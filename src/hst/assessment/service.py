"""Pinned analysis execution, shared by the durable worker and local tools."""

from __future__ import annotations

import copy
import hashlib
import json
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from contextvars import ContextVar
from dataclasses import replace
from typing import Any

from fastapi import HTTPException

from hst import __version__
from hst import path as pathmod
from hst.analysis_model.graph import MAX_SCOPED_LOADS, ScopeExtension
from hst.app import fw_overlay_read
from hst.assessment import evaluation as ev
from hst.assessment.adapters import apply_model_edits, model_changes
from hst.assessment.cost import ScopeCostOracle
from hst.assessment.dependencies import DependencyRecorder
from hst.assessment.evidence import troubleshoot
from hst.assessment.regression import analyze_model_regression, rule_as_add
from hst.assessment.repair import generate_firewall_candidates, search_repairs
from hst.assessment.search import FAILS, HOLDS, UNKNOWN, SearchLimits
from hst.assessment.semantic import read_snapshot_inputs, semantic_change_stream
from hst.assessment.verification import observation_coverage
from hst.core import bgpsource, db, manifest, ospfsource, ribsource, snapshot
from hst.path.addrsets import _intervals, _merge, _ports, _protoset
from hst.path.gates.firewall import _RULEBASE_RULES
from hst.path.verdict import classify_action
from hst.simul.errors import ErrorSink
from hst.simul.fw_overlay import ProposalError

_RULEBASES = """
MATCH (rb:FwRulebase:Obj)
WHERE NOT rb:Retired AND rb.collection_ts = $snap
RETURN rb.uid AS uid ORDER BY uid LIMIT 100001
"""


def _changes(context: Any, intents: list[dict], errors: ErrorSink) -> Any:
    factory = getattr(context, "change_set", None)
    return (
        factory(intents, errors) if factory is not None else ev._change_set(context.session, intents, errors)
    )


def _native_realization(before: Any, actual: Any, changes: Any, budget: Any) -> dict | None:
    if not getattr(before, "uses_symbolic", False):
        return None
    from hst.analysis_model.overlay import apply_overlay
    from hst.assessment.native_verification import compare_configuration
    from hst.simul.fw_overlay import ChangeSet
    from hst.simul.intents import FW_KINDS, NAT_KINDS

    intents = [intent for intent in changes.intents if intent.kind in FW_KINDS | NAT_KINDS]
    targets = {
        "firewall": {str(intent.params["rulebase"]) for intent in intents if intent.kind in FW_KINDS},
        "nat": {str(intent.params["device"]) for intent in intents if intent.kind in NAT_KINDS},
    }
    _, lfw, lnat, _ = before.model_catalogs()
    _, rfw, rnat, _ = actual.model_catalogs()
    if not targets["firewall"] <= lfw & rfw or not targets["nat"] <= lnat & rnat:
        return {
            "state": "not-decided",
            "reason": "Complete policy and object observations are required on both snapshots.",
        }
    projected = apply_overlay(before._symbolic_engine().graph, ChangeSet(intents))
    return compare_configuration(
        projected,
        actual._symbolic_engine().graph,
        targets,
        estate=before.reference["estate"],
        checkpoint=budget.checkpoint,
    )


# `require_retained` raises when retention has removed the graph rows of a run. The
# manifest of such a run can still exist.
_require_graph = snapshot.require_retained


class _BudgetExceeded(RuntimeError):
    pass


class _Budget:
    """Counts full shared request-evaluator invocations, including protections."""

    def __init__(self, limits: SearchLimits, cancelled: Callable[[], bool] | None) -> None:
        self.limits, self.cancelled = limits, cancelled
        self.started = time.monotonic()
        self.count = 0
        self.stop_reason: str | None = None

    def checkpoint(self) -> bool:
        if self.cancelled and self.cancelled():
            self.stop_reason = "cancelled"
        elif time.monotonic() - self.started >= self.limits.max_seconds:
            self.stop_reason = self.stop_reason or "time-limit"
        return self.stop_reason is None

    def stopped(self) -> bool:
        return not self.checkpoint()

    def run(self, call: Callable[[], Any]) -> Any:
        if not self.checkpoint():
            raise _BudgetExceeded(self.stop_reason)
        if self.count >= self.limits.max_evaluations:
            self.stop_reason = "evaluation-limit"
            raise _BudgetExceeded(self.stop_reason)
        self.count += 1
        result = call()
        if not self.checkpoint():
            raise _BudgetExceeded(self.stop_reason)
        return result


def _summary(result: dict) -> dict:
    """Keep whole-region verdicts and bounded evidence pointers."""
    evidence = result.get("evidence", {})
    gaps = result.get("gaps", [])
    digest = hashlib.sha256()
    for chunk in json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False).iterencode(result):
        digest.update(chunk.encode())
    return {
        "outcomes": result.get("outcomes", {}),
        "snapshot": result.get("snapshot"),
        "result_sha256": digest.hexdigest(),
        "evidence_count": evidence.get("count", 0),
        "evidence_sample": evidence.get("items", [])[:2],
        "evidence_detail": "summary",
        "gap_count": len(gaps),
        "gaps": gaps[:5],
        "full_result_retained": False,
        "symbolic": {
            key: value
            for key, value in result.get("symbolic", {}).items()
            if key in {"artifact_ref", "artifact_sha256", "header_schema", "ordering_version"}
        },
        "replay": "Rerun the recorded requirement, snapshot and candidate intents with the recorded engine.",
    }


def _proposal_reason(error: Exception) -> str:
    return str(error.detail) if isinstance(error, HTTPException) else str(error)


def _rule_semantics(rulebase: str, rows: list[dict]) -> list[dict]:
    result = []
    for row in rows:
        params = rule_as_add(rulebase, row)["params"]
        sources, destinations = params["source"], params["destination"]
        protocols = _protoset(params.get("protocols", []))
        result.append(
            {
                "position": params["position"],
                "action": classify_action(params["action"]),
                "source": "any" if sources == ["any"] else _merge(_intervals(sources)),
                "destination": "any" if destinations == ["any"] else _merge(_intervals(destinations)),
                "protocols": sorted(protocols) if protocols is not None else None,
                "ports": _ports(",".join(params["ports"])) if params.get("ports") else None,
                "in_interface": params.get("in_interface"),
                "out_interface": params.get("out_interface"),
            }
        )
    return result


class _NatFamily:
    """A NAT rule's address family in the realization comparison.

    Two stated families compare as values. A rule realized in the other family (`nat66`
    for a `nat` proposal) is a difference. A family that one side does not state (a row
    without `af`, a proposal in a rulebase whose rows state none) equals any family. The
    address columns are compared beside the family and hold every family that the rule
    states."""

    __slots__ = ("value",)
    __hash__ = None  # type: ignore[assignment]

    def __init__(self, value: Any) -> None:
        self.value = value if value in (4, 6) else None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _NatFamily):
            return NotImplemented
        return self.value is None or other.value is None or self.value == other.value

    def __repr__(self) -> str:
        return f"_NatFamily({self.value!r})"


def _nat_semantics(rows: list[dict]) -> list[dict]:
    """Canonical effective NAT stages, ignoring collector-assigned rule identity."""
    from hst.path.gates.nat import _nat_stage_rules

    result = []
    for row in rows:
        if row.get("approximate") or row.get("rule_approximate"):
            raise ValueError("Approximate NAT ownership cannot establish configuration realization.")
        stages = []
        for stage in ("dnat", "snat"):
            iface = row.get("in_if" if stage == "dnat" else "out_if")
            for ingress in ("inside", "outside"):
                for egress in ("inside", "outside"):
                    rules = _nat_stage_rules([row], stage, iface, ingress_role=ingress, egress_role=egress)
                    if any(rule.get("opaque") for rule in rules):
                        raise ValueError(
                            "Opaque NAT predicates or translation prevent realization comparison."
                        )
                    stages.append(
                        {
                            "stage": stage,
                            "iface": iface,
                            "ingress_role": ingress,
                            "egress_role": egress,
                            "rules": [
                                {
                                    k: _NatFamily(v) if k == "af" else v
                                    for k, v in rule.items()
                                    if k not in {"uid", "rb_uid", "rb_name"}
                                }
                                for rule in rules
                            ],
                        }
                    )
        result.append({"position": row.get("pos"), "stages": stages})
    return result


def _extended_realization(settings: Any, inputs: dict, context: Any, budget: _Budget, fresh: bool) -> dict:
    """Check supported projected NAT/firewall rows and administrative BGP shutdowns."""
    base = {"state": "not-decided", "scope": "effective firewall/NAT policy and administrative BGP state"}
    if not fresh:
        return {**base, "reason": "Post-deployment observations are incomplete or too old."}
    intents = inputs["definition"]["intents"]
    supported = {
        "fw_rule.add",
        "fw_rule.modify",
        "fw_rule.remove",
        "nat_rule.add",
        "nat_rule.modify",
        "nat_rule.remove",
        "bgp_session.shut",
    }
    unsupported = sorted({i["kind"] for i in intents} - supported)
    if unsupported:
        return {
            **base,
            "reason": "No collected configuration realization adapter for: " + ", ".join(unsupported),
        }
    predicted_snapshot = inputs["prediction"].get("snapshot")
    reference = next((ref for ref in inputs["snapshot_refs"] if ref["snapshot"] == predicted_snapshot), None)
    if reference is None:
        return {**base, "reason": "The original prediction snapshot reference is unavailable."}
    try:
        factory = getattr(context, "snapshot_session_factory", None)
        extra = {"snapshot_session_factory": factory} if factory is not None else {}
        with EvaluationContext(settings, reference, inputs["definition"]["request"], **extra) as before:
            left, lfw, lnat, lctx = before.model_catalogs()
            right, rfw, rnat, rctx = context.model_catalogs()
            overlay = _changes(before, intents, ErrorSink())
            native_result = _native_realization(before, context, overlay, budget)
            if native_result is not None and native_result["state"] == "not-decided":
                return native_result
            differences = list(native_result.get("differences", ())) if native_result else []
            checked = list(native_result.get("checked", ())) if native_result else []
            families = (
                ()
                if native_result is not None
                else (
                    ("firewall", "rulebase", lfw & rfw, overlay._rewrite_fw_rules, _rule_semantics),
                    (
                        "nat",
                        "device",
                        lnat & rnat,
                        overlay._rewrite_nat_rules,
                        lambda target, rows: _nat_semantics(rows),
                    ),
                )
            )
            for family, target_key, complete, rewrite, semantics in families:
                prefix = "fw_rule." if family == "firewall" else "nat_rule."
                for target in sorted(
                    {i["params"].get(target_key) for i in intents if i["kind"].startswith(prefix)}
                ):
                    if target not in complete:
                        return {
                            **base,
                            "reason": f"Complete {family} ownership observations required for {target}.",
                        }
                    predicted = semantics(target, rewrite(target, left[family][target]))
                    actual = semantics(target, right[family][target])
                    checked.append({"family": family, "target": target})
                    if predicted != actual:
                        differences.append({"family": family, "target": target})
            for intent in intents:
                if intent["kind"] != "bgp_session.shut":
                    continue
                uid = intent["params"]["session"]
                session = next(
                    (
                        s
                        for s in (context.network.routing.bgp.sessions if context.network.routing.bgp else [])
                        if s["uid"] == uid
                    ),
                    None,
                )
                if session is None:
                    return {**base, "reason": f"BGP session {uid} has no collected administrative state."}
                process = next(
                    (p for p in context.network.routing.bgp.processes if p["uid"] == session["process_uid"]),
                    None,
                )
                if process is None or process["context_uid"] not in lctx & rctx:
                    return {
                        **base,
                        "reason": f"BGP process for {uid} lacks complete configuration observations.",
                    }
                state = str(session.get("state", "")).lower()
                if state not in {"shutdown", "admin-down", "administratively-down"}:
                    # Operational down alone is not evidence of configured shutdown.
                    return {
                        **base,
                        "reason": f"BGP state {state!r} does not establish administrative shutdown.",
                    }
                checked.append({"family": "bgp_session.shut", "target": uid})
            if not budget.checkpoint():
                return {**base, "reason": budget.stop_reason}
            return {
                **base,
                "state": "differs" if differences else "matches",
                "checked": checked,
                "differences": differences,
                "reason": "Compared supported configuration semantics; application health remains separate.",
            }
    except (ValueError, ProposalError, HTTPException) as exc:
        return {**base, "reason": _proposal_reason(exc)}


def _configuration_realization(
    settings: Any,
    inputs: dict,
    context: Any,
    budget: _Budget,
    fresh: bool,
) -> dict:
    """Compare supported resolved rule semantics separately from service outcome."""
    intents = inputs["definition"]["intents"]
    base = {"state": "not-decided", "scope": "ordered resolved firewall rules on touched rulebases"}
    if not intents:
        return {**base, "state": "not-applicable", "reason": "No proposed configuration edits were recorded."}
    if not fresh:
        return {**base, "reason": "Post-deployment observations are incomplete or too old."}
    if any(i.get("kind") not in {"fw_rule.add", "fw_rule.modify", "fw_rule.remove"} for i in intents):
        return _extended_realization(settings, inputs, context, budget, fresh)
    if any(not i.get("params", {}).get("rulebase") for i in intents):
        return {**base, "reason": "Configuration realization requires explicit rulebase targets."}
    predicted_snapshot = inputs["prediction"].get("snapshot")
    reference = next((ref for ref in inputs["snapshot_refs"] if ref["snapshot"] == predicted_snapshot), None)
    if reference is None:
        return {**base, "reason": "The original prediction snapshot reference is unavailable."}
    if not budget.checkpoint():
        return {**base, "reason": budget.stop_reason}
    try:
        factory = getattr(context, "snapshot_session_factory", None)
        extra = {"snapshot_session_factory": factory} if factory is not None else {}
        with EvaluationContext(settings, reference, inputs["definition"]["request"], **extra) as before:
            left, lc = before.policies()
            right, rc = context.policies()
            targets = {i["params"]["rulebase"] for i in intents}
            if not targets <= lc & rc:
                return {
                    **base,
                    "reason": "Complete policy/object observations are required on both snapshots.",
                }
            overlay = _changes(before, intents, ErrorSink())
            native_result = _native_realization(before, context, overlay, budget)
            if native_result is not None:
                return native_result
            differences = []
            for target in sorted(targets):
                expected = _rule_semantics(target, overlay._rewrite_fw_rules(target, left[target]))
                actual = _rule_semantics(target, right[target])
                if expected != actual:
                    differences.append(target)
            if not budget.checkpoint():
                return {**base, "reason": budget.stop_reason}
            return {
                **base,
                "state": "differs" if differences else "matches",
                "rulebases": sorted(targets),
                "different_rulebases": differences,
                "reason": (
                    "Compared effective ordered rule semantics; "
                    "object identity and other configuration are outside scope."
                ),
            }
    except (ValueError, ProposalError, HTTPException) as exc:
        return {**base, "reason": _proposal_reason(exc)}


def engine_version(settings: Any) -> str:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    digest.update(getattr(settings, "analysis_engine", "legacy-v1").encode())
    if getattr(settings, "analysis_engine", "legacy-v1") == "symbolic-v2":
        from hst.symbolic.backend import backend_identity

        digest.update(backend_identity().identifier.encode())
    directories = (
        "assessment",
        "impact",
        "path",
        "simul",
        "core",
        "app",
        "symbolic",
        "policy",
        "analysis_model",
    )
    for directory in directories:
        for file in sorted((root / directory).rglob("*.py")):
            digest.update(str(file.relative_to(root)).encode())
            digest.update(file.read_bytes())
    return f"{__version__}:{settings.hst_build_revision or 'host'}:{digest.hexdigest()}"


def snapshot_reference(settings: Any, value: str | None = None) -> dict:
    with db.session(settings) as session:
        snap = snapshot.resolve(session, settings, int(value) if value else None)
        if snap.cts is None or snap.manifest is None:
            raise ValueError("A published snapshot with an evidence manifest is required.")
        _require_graph(session, snap.cts)
        return {
            "snapshot": str(snap.cts),
            "manifest_sha256": manifest.digest_of(settings, snap.cts),
            "estate": snap.manifest.estate,
            "observation_floor_ms": observation_floor(snap.manifest),
        }


def observation_floor(record: Any) -> int | None:
    """Return the oldest observation time of the devices and of their complete tables.

    Return None when the record has no device or when a device or a complete table has
    no time.
    """
    times: list[int] = []
    if not record.devices:
        return None
    for device in record.devices:
        if device.fetch_started_ms is None:
            return None
        times.append(device.fetch_started_ms)
        for table in device.tables.values():
            if table.status in {"complete", "complete-empty", "unchanged"}:
                if table.observed_ms is None:
                    return None
                times.append(table.observed_ms)
    return min(times)


def _incomplete_population(outcome: dict, declaration: dict) -> None:
    """A whole-request outcome over a source population known to be
    incomplete cannot hold or prove isolation for the clients left out."""
    if declaration.get("population_complete") is False:
        if outcome.get("verdict") == HOLDS:
            outcome["verdict"] = UNKNOWN
        outcome["isolated"] = False
        outcome.setdefault("reason", "The source population is incomplete (SOURCE_POPULATION_INCOMPLETE).")


# `_GRAPH_SCOPE` holds the graph scope with which an evaluation context loads the
# symbolic engine. `_REQUEST_SCOPE` selects the devices that the request touches
# (`request_devices`). A set of device uids selects those devices. None selects the
# whole run. `execute` sets the scope when it runs a job again after a read outside the
# loaded scope.
_REQUEST_SCOPE: Any = object()
_GRAPH_SCOPE: ContextVar[Any] = ContextVar("hst_graph_scope", default=_REQUEST_SCOPE)


class EvaluationContext(AbstractContextManager):
    """One recorded graph and observation model reused across candidate overlays.

    The symbolic engine loads the part of the run the request touches. A read
    outside that part raises `ScopeExtension`. A method that calls `_scoped`
    loads the engine again with the devices that the exception names and
    repeats its call. A `ScopeExtension` from another read ends the job.
    `execute` runs the job again with the wider scope.
    """

    def __init__(
        self, settings: Any, reference: dict, request: dict, *, snapshot_session_factory: Any = None
    ) -> None:
        self.settings = settings
        self.reference = reference
        if request.get("population_artifact") is not None:
            from hst.assessment.population_request import replay_bound_request

            request = replay_bound_request(request).request
        self.request_document = request
        self.request = ev._request_from_body(ev.RequestBody(**request))
        self.snapshot_session_factory = snapshot_session_factory
        self._scope = (
            snapshot_session_factory(reference) if snapshot_session_factory else db.session(settings)
        )
        self.dependencies = DependencyRecorder(reference.get("estate", "default"), reference["snapshot"])
        self.session: Any = None
        self.snapshot: Any = None
        self.network: Any = None
        self.symbolic: Any = None
        self._catalog: Any = None
        self.graph_scope: Any = _GRAPH_SCOPE.get()
        self._scoped_loads = 0
        self.errors = ErrorSink()

    def __enter__(self) -> EvaluationContext:
        raw = self._scope.__enter__()
        try:
            self.snapshot = snapshot.resolve(raw, self.settings, int(self.reference["snapshot"]))
            if self.snapshot.manifest is None:
                raise ValueError("The pinned evidence manifest is no longer available.")
            if manifest.digest_of(self.settings, self.snapshot.cts) != self.reference["manifest_sha256"]:
                raise ValueError("The pinned evidence manifest has changed.")
            _require_graph(raw, int(self.reference["snapshot"]))
            self.session = self.dependencies.session(pathmod.pinned(raw, self.snapshot))
            if self.request_document.get("population_artifact") is not None:
                from hst.assessment.population_request import bind_pinned_request

                self.request_document = bind_pinned_request(
                    self.settings, self.session, self.snapshot, self.request_document
                )
            readers = (
                self.dependencies.reader(ribsource.for_snapshot(self.snapshot), section="rib"),
                self.dependencies.reader(bgpsource.for_snapshot(self.snapshot), section="bgp"),
                self.dependencies.reader(ospfsource.for_snapshot(self.snapshot), section="ospf"),
            )
            try:
                self.network = ev.load_network(
                    self.session,
                    self.request,
                    rib_source=readers[0],
                    bgp_source=readers[1],
                    ospf_source=readers[2],
                    errors=self.errors,
                )
            finally:
                for reader in readers:
                    reader.close()
            return self
        except BaseException:
            self._scope.__exit__(None, None, None)
            raise

    def __exit__(self, *args: Any) -> Any:
        try:
            if self.symbolic is not None:
                self.symbolic.close()
        finally:
            result = self._scope.__exit__(*args)
        return result

    def _symbolic_engine(self) -> Any:
        if self.symbolic is None:
            from datetime import datetime

            from hst.analysis_model.evidence import ConsistencyMode, EvidencePolicy
            from hst.analysis_model.graph import load_graph
            from hst.analysis_model.model_cache import CompiledModelCache
            from hst.analysis_model.temporal import manifest_evidence
            from hst.app import crypto
            from hst.assessment.result_artifacts import ResultArtifactStore
            from hst.assessment.symbolic_evaluation import SymbolicEvaluation
            from hst.impact.symbolic_walk import WalkLimits

            def cancelled() -> bool:
                check = self.network.checkpoint
                return check is not None and check() is False

            if self.graph_scope is _REQUEST_SCOPE:
                from hst.analysis_model.network import request_devices

                self.graph_scope = request_devices(self.network, self.request)
            graph = load_graph(
                self.session,
                self.snapshot,
                self.reference["manifest_sha256"],
                memory_mb=int(self.settings.analysis_memory_mb),
                devices=self.graph_scope,
                cancelled=cancelled,
                digest_reader=lambda: manifest.digest_of(self.settings, self.snapshot.cts),
            )
            self.symbolic = SymbolicEvaluation(
                graph,
                self.reference["estate"],
                cancelled=cancelled,
                limits=WalkLimits(max_seconds=self.settings.analysis_timeout_s),
                evidence=manifest_evidence(
                    self.snapshot,
                    analysis_time=datetime.fromisoformat(
                        self.snapshot.manifest.published.replace("Z", "+00:00")
                    ),
                    policy=EvidencePolicy(
                        max_age_s=int(self.settings.analysis_evidence_max_age_s),
                        max_skew_s=int(self.settings.analysis_evidence_max_skew_s),
                        consistency_mode=ConsistencyMode(self.settings.analysis_evidence_consistency_mode),
                        stable_window_assumption=self.settings.analysis_evidence_stable_window_assumption,
                    ),
                    graph=graph,
                ),
                result_store=ResultArtifactStore(
                    self.settings.hst_data_dir,
                    crypto.dek(self.settings),
                    max_bytes=self.settings.analysis_result_mb * 1024 * 1024,
                ),
                model_cache=CompiledModelCache.from_settings(
                    self.settings, semantic_version=engine_version(self.settings)
                ),
            )
        return self.symbolic

    def _scoped(self, call: Callable[[], Any]) -> Any:
        """Run `call`. On a read outside the graph scope of the engine, load the engine
        with the wider scope and run `call` again. After `MAX_SCOPED_LOADS` scoped loads
        the engine loads the whole run."""
        while True:
            try:
                return call()
            except ScopeExtension as extension:
                engine = self.symbolic
                # only a read of this context's own graph is repeated here
                if engine is None or engine.graph.scope is None or extension.scope is not engine.graph.scope:
                    raise
                engine.close()
                self.symbolic = None
                self._catalog = None
                self._scoped_loads += 1
                self.graph_scope = extension.widened() if self._scoped_loads < MAX_SCOPED_LOADS else None

    @property
    def uses_symbolic(self) -> bool:
        return getattr(self.settings, "analysis_engine", "legacy-v1") == "symbolic-v2"

    def answer_network(self, network: Any, request: Any, mode: str) -> Any:
        if self.uses_symbolic:
            return self._scoped(lambda: self._symbolic_engine().answer_network(network, request, mode))
        from hst.impact.evaluate import answer

        return answer(network, request, mode)

    def network_outcome(self, network: Any, request: Any, mode: str) -> dict:
        answer = self.answer_network(network, request, mode)
        if self.uses_symbolic:
            from hst.assessment.symbolic_results import outcome

            result = outcome(answer)
        else:
            result = ev.outcome(answer)
        if request == self.request:
            _incomplete_population(result, self.request_document)
        return result

    def change_set(self, intents: list[dict], errors: ErrorSink) -> Any:
        """Use graph-native policy validation only for symbolic-v2."""
        if self.uses_symbolic:
            from hst.analysis_model.native_changes import native_changes

            return self._scoped(lambda: native_changes(self._symbolic_engine().graph, intents))
        return ev._change_set(self.session, intents, errors)

    def evaluate(self, intents: list[dict], mode: str, request: dict | None = None) -> dict:
        if self.uses_symbolic:
            return self._scoped(lambda: self._evaluate(intents, mode, request))
        return self._evaluate(intents, mode, request)

    def _evaluate(self, intents: list[dict], mode: str, request: dict | None) -> dict:
        selected = self.request if request is None else ev._request_from_body(ev.RequestBody(**request))
        if self.uses_symbolic:
            from hst.impact.evaluate import apply as apply_change

            errors = ErrorSink()
            delta = self.change_set(intents, errors)
            answer = self._symbolic_engine().compare_networks(
                self.network, apply_change(self.network, delta, errors), selected, mode
            )
            answer["intents"] = [intent.as_dict() for intent in delta.intents]
            answer["model_errors"].extend(errors.as_dicts())
        else:
            answer = ev.evaluate_change(
                self.session,
                detail=True,
                intents=intents,
                request=selected,
                mode=mode,
                network=self.network,
            )
        answer["snapshot"] = self.reference["snapshot"]
        answer["model_errors"] = self.errors.as_dicts() + answer["model_errors"]
        self._population_result(answer, self.request_document if request is None else request)
        return answer

    def _population_result(self, answer: dict, declaration: dict) -> None:
        metadata = {key: value for key, value in declaration.items() if key.startswith("population")}
        if metadata:
            answer.setdefault("request", {}).update(metadata)
        if declaration.get("population_complete") is False:
            answer.update(complete=False, completion_status="incomplete")
            gaps = declaration.get("population_gaps") or ["SOURCE_POPULATION_INCOMPLETE"]
            answer["missing_evidence"] = sorted(set(answer.get("missing_evidence", [])) | set(gaps))
            for state in answer.get("outcomes", {}).values():
                if state.get("verdict") == HOLDS:
                    state["verdict"] = UNKNOWN
                state["isolated"] = False

    def policies(self, targets: dict[str, str] | None = None) -> tuple[dict, set[str]]:
        if self.uses_symbolic:
            projection = self._scoped(self._catalog_projection)
            catalogs, complete_catalog, _nat, _contexts = projection.model_catalogs()
            firewall = catalogs["firewall"]
            if targets is not None:
                bindings = catalogs["graph_bindings"]
                for rulebase, owner in targets.items():
                    if rulebase not in firewall or owner not in {
                        item["owner_uid"] for item in bindings.get(rulebase, ())
                    }:
                        raise ValueError(f"Rulebase {rulebase} is not enforced by allowed device {owner}.")
                firewall = {rulebase: rows for rulebase, rows in firewall.items() if rulebase in targets}
            return firewall, complete_catalog
        bases = pathmod._read(self.session, _RULEBASES)
        if len(bases) > 100000:
            raise ValueError("Policy analysis currently supports at most 100000 rulebases per snapshot.")
        rules: dict[str, list[dict]] = {}
        complete: set[str] = set()
        devices = self.snapshot.manifest.devices
        for base in bases:
            uid = base["uid"]
            if targets is not None and uid not in targets:
                continue
            owners = {
                row["uid"] for row in pathmod._read(self.session, fw_overlay_read._RULEBASE_DEVICES, rb=uid)
            }
            if targets is not None and targets[uid] not in owners:
                raise ValueError(f"Rulebase {uid} is not enforced by allowed device {targets[uid]}.")
            rows = pathmod._read(self.session, _RULEBASE_RULES, rb=uid)
            if len(rows) > 10000:
                raise ValueError(f"Rulebase {uid} exceeds the 10000-rule analysis limit.")
            rules[uid] = rows
            observed = [d for d in devices if set(d.device_uids).intersection(owners)]
            # Every owning device must answer, including all declared sections.
            if (
                owners
                and observed
                and owners <= {u for d in observed for u in d.device_uids}
                and all(
                    d.outcome in {"collected", "unchanged"}
                    and not d.carried
                    and d.expected_sections
                    and all(
                        d.sections.get(section) is not None and d.sections[section].status in {"ok", "empty"}
                        for section in d.expected_sections
                    )
                    for d in observed
                )
            ):
                complete.add(uid)
        if targets and set(targets) - set(rules):
            raise ValueError("An allowed rulebase does not exist in the pinned snapshot.")
        return rules, complete

    def complete_devices(self) -> set[str]:
        """All producers of a device must have complete configured observations."""
        observed: dict[str, list[Any]] = {}
        for record in self.snapshot.manifest.devices:
            for uid in record.device_uids:
                observed.setdefault(uid, []).append(record)
        return {
            uid
            for uid, records in observed.items()
            if all(
                record.outcome in {"collected", "unchanged"}
                and not record.carried
                and record.expected_sections
                and all(
                    name in record.sections and record.sections[name].status in {"ok", "empty"}
                    for name in record.expected_sections
                )
                for record in records
            )
        }

    def model_catalogs(self) -> tuple[dict, set[str], set[str], set[str]]:
        if self.uses_symbolic:
            return self._scoped(lambda: self._catalog_projection().model_catalogs())
        from hst.path.gates.nat import _NAT_RULES_QUERY_STRICT

        firewall, complete_fw = self.policies()
        devices = {i.device_uid for i in self.network.interfaces}
        devices.update(row["device_uid"] for row in self.network.routing.contexts if row.get("device_uid"))
        nat = {}
        for uid in sorted(devices):
            rows = pathmod._read(self.session, _NAT_RULES_QUERY_STRICT, dev=uid, in_if=None)
            if len(rows) > 10000:
                raise ValueError(f"Device {uid} exceeds the 10000-NAT-rule analysis bound.")
            nat[uid] = rows
        complete_devices = self.complete_devices()
        complete_contexts = {
            row["uid"] for row in self.network.routing.contexts if row.get("device_uid") in complete_devices
        }
        return {"firewall": firewall, "nat": nat}, complete_fw, devices & complete_devices, complete_contexts

    def _catalog_projection(self, graph: Any = None) -> Any:
        from hst.analysis_model.catalogs import project_catalogs

        if graph is None and self._catalog is not None:
            return self._catalog
        baseline = graph is None
        graph = self._symbolic_engine().graph if baseline else graph
        owners = {
            str(row["uid"]): str(row["device_uid"])
            for row in self.network.routing.contexts
            if row.get("device_uid")
        }
        devices = {interface.device_uid for interface in self.network.interfaces} | set(owners.values())
        result = project_catalogs(
            graph, manifest=self.snapshot.manifest, device_uids=devices, context_owners=owners
        )
        if baseline:
            self._catalog = result
        return result

    def evaluate_model(self, network: Any, mode: str) -> dict:
        if self.uses_symbolic:
            result = self._scoped(
                lambda: self._symbolic_engine().compare_networks(network, network, self.request, mode)
            )
        else:
            result = ev.evaluate_change(
                self.session, detail=True, intents=[], request=self.request, mode=mode, network=network
            )
        result["snapshot"] = self.reference["snapshot"]
        self._population_result(result, self.request_document)
        return result


def execute(
    settings: Any,
    inputs: dict,
    *,
    progress: Callable[[dict], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    snapshot_session_factory: Any = None,
) -> dict:
    """Run a validated assessment input. No network configuration is written.

    `project_engine` writes the result in the result vocabulary. The run record stores
    that form. A replay compares that form."""
    from hst.results.project import project_engine

    definition = inputs.get("definition")
    mode = definition.get("mode") if isinstance(definition, dict) else None
    # A `ScopeExtension` that no context method retried ends the run. The loop runs the
    # job again with the wider scope. The last run loads the whole graph.
    scope: Any = _REQUEST_SCOPE
    for attempt in range(MAX_SCOPED_LOADS + 1):
        token = _GRAPH_SCOPE.set(scope if attempt < MAX_SCOPED_LOADS else None)
        try:
            return project_engine(
                _execute(
                    settings,
                    inputs,
                    progress=progress,
                    cancelled=cancelled,
                    snapshot_session_factory=snapshot_session_factory,
                ),
                mode,
            )
        except ScopeExtension as extension:
            scope = extension.widened()
        finally:
            _GRAPH_SCOPE.reset(token)
    raise RuntimeError("the analysis read outside a whole-run graph")


def _execute(
    settings: Any,
    inputs: dict,
    *,
    progress: Callable[[dict], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    snapshot_session_factory: Any = None,
) -> dict:
    if "analysis_session_simulation" in inputs:
        from hst.app.routes.analysis_sessions import execute_simulation_job

        return execute_simulation_job(
            settings,
            inputs,
            progress=progress,
            cancelled=cancelled,
        )
    if inputs.get("analysis", {}).get("kind") == "symbolic-page":
        from hst.assessment.result_page import execute_page

        return execute_page(settings, inputs)
    if inputs.get("analysis", {}).get("kind") == "symbolic-explain-rule":
        from hst.assessment.rule_explain import execute_explain

        return execute_explain(settings, inputs, cancelled=cancelled)
    if inputs.get("analysis", {}).get("kind") == "symbolic-match-flow":
        from hst.assessment.flow_match import execute_match

        return execute_match(settings, inputs, cancelled=cancelled)
    definition, options = inputs["definition"], inputs["analysis"]
    kind, mode = options["kind"], definition["mode"]
    request = definition["request"]
    limits = SearchLimits(**options["limits"])
    budget = _Budget(limits, cancelled)
    context_options = (
        {"snapshot_session_factory": snapshot_session_factory} if snapshot_session_factory else {}
    )
    with EvaluationContext(settings, inputs["snapshot_refs"][0], request, **context_options) as context:
        context.network = replace(context.network, checkpoint=budget.checkpoint)
        if hasattr(context, "dependencies"):
            context.dependencies.assumptions({"mode": mode, "success": request.get("success")})
            if definition.get("requirement_id"):
                context.dependencies.requirement(
                    definition["requirement_id"], definition["requirement_revision"]
                )

        def evaluated(intents: list[dict], req: dict | None = None, selected_mode: str = mode) -> dict:
            answer = budget.run(lambda: context.evaluate(intents, selected_mode, req))
            if progress:
                progress({"evaluated": budget.count, "phase": kind})
            return answer

        def evaluate_constraints(intents: list[dict], desired: str) -> dict:
            protections = {item["name"]: UNKNOWN for item in options.get("protected", [])}
            outcomes = {}
            reason = None
            try:
                for item in options.get("protected", []):
                    isolated = item["desired"] == "isolated"
                    state = evaluated(intents, item["request"], "possible" if isolated else mode)["outcomes"][
                        "after"
                    ]
                    outcomes[item["name"]] = state
                    protections[item["name"]] = (
                        (HOLDS if state["isolated"] else FAILS if state["holds"] else UNKNOWN)
                        if isolated
                        else state["verdict"]
                    )
            except (ProposalError, ValueError, HTTPException, _BudgetExceeded) as exc:
                reason = _proposal_reason(exc)
            states = [desired, *protections.values()]
            combined = FAILS if FAILS in states else UNKNOWN if UNKNOWN in states else HOLDS
            return {
                "desired": desired,
                "protected": protections,
                "outcomes": outcomes,
                "verdict": combined,
                "verified": combined == HOLDS,
                "reason": reason,
            }

        def finish(result: dict, baseline: dict) -> dict:
            if budget.stop_reason:
                result.update(
                    search_complete=False,
                    scoped_search_complete=False,
                    stop_reason=budget.stop_reason,
                    proved_infeasible=False,
                )
                if result.get("kind") == "repair":
                    for finding in result.get("findings", ()):
                        finding["minimum_cost"] = False
            return {
                **result,
                "kind": kind,
                "snapshot": context.reference["snapshot"],
                "snapshot_refs": inputs["snapshot_refs"],
                "mode": mode,
                "dependencies": (
                    (
                        context.dependencies.references()
                        if hasattr(context, "dependencies")
                        else [{"kind": "estate", "estate": context.snapshot.manifest.estate}]
                    )
                    + result.get("before_dependencies", [])
                ),
                "assumptions": baseline.get("assumptions", []),
                "engine_evaluations": budget.count,
                "evaluation_budget_unit": (
                    "one shared request evaluation or raw whole-region cost evaluation; "
                    "includes baselines, protections and cost"
                ),
                "elapsed_seconds": time.monotonic() - budget.started,
            }

        try:
            baseline = evaluated(definition["intents"] if kind in {"evaluate", "troubleshoot"} else [])
        except _BudgetExceeded:
            return finish({"verdict": UNKNOWN, "findings": [], "trials": []}, {})
        if kind == "evaluate":
            result = baseline
            result["constraints"] = evaluate_constraints(
                definition["intents"], baseline["outcomes"]["after"]["verdict"]
            )
            result["verdict"] = result["constraints"]["verdict"]
        elif kind == "troubleshoot":
            result = troubleshoot(
                baseline,
                context.snapshot.manifest,
                request,
                priority=definition.get("priority", 1),
                device_uids={i.device_uid for i in context.network.interfaces},
            )
        elif kind == "regression":
            with EvaluationContext(
                settings, inputs["snapshot_refs"][1], request, **context_options
            ) as before:
                before.network = replace(before.network, checkpoint=budget.checkpoint)
                try:
                    older = budget.run(lambda: before.evaluate([], mode))
                except _BudgetExceeded:
                    return finish(
                        {"verdict": UNKNOWN, "findings": [], "trials": [], "baseline": _summary(baseline)},
                        baseline,
                    )
                left_inputs = read_snapshot_inputs(
                    before.session, before.snapshot, settings, cancelled=budget.stopped
                )
                right_inputs = read_snapshot_inputs(
                    context.session, context.snapshot, settings, cancelled=budget.stopped
                )
                stream = semantic_change_stream(left_inputs, right_inputs)
                left, lfw, lnat, lctx = before.model_catalogs()
                right, rfw, rnat, rctx = context.model_catalogs()
                difference = model_changes(
                    before.network,
                    context.network,
                    left,
                    right,
                    complete_fw=sorted(lfw & rfw),
                    complete_nat=sorted(lnat & rnat),
                    complete_contexts=sorted(lctx & rctx),
                )
                selectors = {str(value) for edit in difference["edits"] for value in edit["selector"]}
                configured = [change for change in stream["changes"] if change["category"] == "configuration"]
                for change in configured:
                    rows = change["before"] + change["after"]
                    anchors = {
                        str(row[key]) for row in rows for key in ("uid", "start", "end") if row.get(key)
                    }
                    if not anchors & selectors:
                        difference["excluded"].append(
                            {
                                "id": change["id"],
                                "semantic_key": change["key"],
                                "category": "configuration",
                                "reason": "No reversible configured model adapter maps this input change.",
                            }
                        )
                # The reasoner derives RT pairing. The reverse of a derived pairing does
                # not establish a configured edit.
                derived = [edit for edit in difference["edits"] if edit["family"] == "rt_pairs"]
                difference["edits"] = [edit for edit in difference["edits"] if edit["family"] != "rt_pairs"]
                difference["excluded"].extend(
                    {**edit, "reason": "Derived RT pairing requires configured-source inversion."}
                    for edit in derived
                )
                difference["universe_complete"] = not difference["excluded"] and stream["complete"]

                def model_oracle(edits: list[dict], forward: bool = False) -> dict:
                    target, observed = (before, older) if forward else (context, baseline)
                    try:
                        network = apply_model_edits(
                            target.network, edits, direction="forward" if forward else "reverse"
                        )
                        answer = (
                            budget.run(lambda: target.evaluate_model(network, mode)) if edits else observed
                        )
                        if progress:
                            progress(
                                {"evaluated": budget.count, "phase": "forward-replay" if forward else kind}
                            )
                        return {
                            "verdict": answer["outcomes"]["after"]["verdict"],
                            "summary": _summary(answer),
                        }
                    except (ProposalError, ValueError, HTTPException, _BudgetExceeded) as exc:
                        return {"verdict": UNKNOWN, "reason": _proposal_reason(exc)}

                result = analyze_model_regression(
                    difference,
                    model_oracle,
                    limits,
                    before_verdict=older["outcomes"]["after"]["verdict"],
                    after_verdict=baseline["outcomes"]["after"]["verdict"],
                    forward_oracle=lambda edits: model_oracle(edits, True),
                    semantic_stream=stream,
                    cancelled=budget.stopped,
                )
                if hasattr(before, "dependencies"):
                    result["before_dependencies"] = before.dependencies.references()
            result["before_snapshot"] = inputs["snapshot_refs"][1]["snapshot"]
            result["scope"] = (
                "Exact reversible firewall, NAT, interface and routing model inputs; "
                "receiving-snapshot observations remain conditions. Full semantic input changes "
                "and unsupported configured inversions are reported separately."
            )
        elif kind == "repair":
            rules, _complete = context.policies(options["allowed_targets"])
            scope = options.get("scope") or {
                "source": request["sources"],
                "destination": [a for m in request["members"] for a in m["addresses"]],
                # a stated protocol list ('6,17') is one value per protocol
                "protocols": sorted(
                    {
                        p.strip()
                        for m in request["members"]
                        for p in str(m.get("proto") or request.get("proto") or "any").split(",")
                    }
                ),
                "ports": sorted({m.get("port") or request.get("port") or "any" for m in request["members"]}),
            }
            if getattr(context, "uses_symbolic", False):
                from hst.assessment.symbolic_repair import generate_candidates

                generated = generate_candidates(
                    rules,
                    options["allowed_targets"],
                    options["allowed_kinds"],
                    scope,
                    max_candidates=limits.max_candidates,
                    cancelled=budget.stopped,
                )
            else:
                generated = generate_firewall_candidates(
                    rules,
                    options["allowed_targets"],
                    scope,
                    options["allowed_kinds"],
                    max_candidates=limits.max_candidates,
                )

            policy_complete = set(options["allowed_targets"]) <= _complete
            if not policy_complete:
                generated["universe_complete"] = False
                generated["excluded"].extend(
                    {"rulebase": uid, "reason": "Configured policy observations incomplete."}
                    for uid in sorted(set(options["allowed_targets"]) - _complete)
                )

            def proposal_difference(intents: list[dict]) -> dict:
                overlay = _changes(context, intents, ErrorSink())
                projected = None
                if getattr(context, "uses_symbolic", False):
                    from hst.analysis_model.overlay import apply_overlay

                    graph = apply_overlay(context._symbolic_engine().graph, overlay)
                    projected = context._catalog_projection(graph).model_catalogs()[0]["firewall"]
                differences = []
                for rb in sorted({i["params"]["rulebase"] for i in intents}):
                    before_rows = {row["uid"]: row for row in rules[rb]}
                    rows = (
                        projected[rb] if projected is not None else overlay._rewrite_fw_rules(rb, rules[rb])
                    )
                    after_rows = {row["uid"]: row for row in rows}
                    for uid in sorted(before_rows.keys() | after_rows.keys()):
                        if before_rows.get(uid) != after_rows.get(uid):
                            differences.append(
                                {
                                    "rulebase": rb,
                                    "rule": uid,
                                    "before": before_rows.get(uid),
                                    "after": after_rows.get(uid),
                                }
                            )
                digest = hashlib.sha256(json.dumps(differences, sort_keys=True).encode()).hexdigest()
                return {
                    "diff": differences[:50],
                    "diff_count": len(differences),
                    "diff_truncated": len(differences) > 50,
                    "diff_sha256": digest,
                }

            def protected_oracle(intents: list[dict]) -> dict:
                desired_state = UNKNOWN
                protections = {item["name"]: UNKNOWN for item in options["protected"]}
                desired_summary: dict = {}
                if not policy_complete:
                    return {
                        "desired": UNKNOWN,
                        "protected": protections,
                        "reason": "Configured policy observations incomplete on allowed targets.",
                    }
                try:
                    desired = evaluated(intents) if intents else baseline
                    desired_state = desired["outcomes"]["after"]["verdict"]
                    desired_summary = _summary(desired)
                    for item in options["protected"]:
                        isolated = item["desired"] == "isolated"
                        answer = evaluated(intents, item["request"], "possible" if isolated else mode)
                        state = answer["outcomes"]["after"]
                        protections[item["name"]] = (
                            (HOLDS if state["isolated"] else FAILS if state["holds"] else UNKNOWN)
                            if isolated
                            else state["verdict"]
                        )
                    return {
                        "desired": desired_state,
                        "protected": protections,
                        "summary": desired_summary,
                        **proposal_difference(intents),
                    }
                except (ProposalError, ValueError, HTTPException, _BudgetExceeded) as exc:
                    return {
                        "desired": UNKNOWN,
                        "protected": protections,
                        "summary": desired_summary,
                        "reason": _proposal_reason(exc),
                    }

            from hst.impact.evaluate import answer as answer_network
            from hst.impact.evaluate import apply as apply_change

            def cost_evaluate(network: Any, req: Any, selected_mode: str) -> Any:
                if getattr(context, "uses_symbolic", False):
                    return budget.run(lambda: context.answer_network(network, req, selected_mode))
                return budget.run(lambda: answer_network(network, req, selected_mode))

            measured_cost: Callable[[Any], dict]
            if getattr(context, "uses_symbolic", False):
                from hst.assessment.symbolic_cost import SymbolicScopeCostOracle

                measured_cost = SymbolicScopeCostOracle(
                    context.network, context.request, scope, evaluate=cost_evaluate
                )
            else:
                measured_cost = ScopeCostOracle(
                    context.network, context.request, scope, evaluate=cost_evaluate
                )

            def cost_oracle(intents: list[dict]) -> dict:
                if not policy_complete:
                    return {"lower": 0, "upper": None, "reason": "Configured policy observations incomplete."}
                try:
                    overlay = _changes(context, intents, ErrorSink())
                    return measured_cost(apply_change(context.network, overlay))
                except (ProposalError, ValueError, HTTPException, _BudgetExceeded) as exc:
                    return {
                        "lower": 0,
                        "upper": None,
                        "exact": False,
                        "value": None,
                        "reason": _proposal_reason(exc),
                    }

            result = search_repairs(
                generated,
                protected_oracle,
                limits,
                cancelled=budget.stopped,
                cost_oracle=cost_oracle,
                cost_order=options.get("cost_order", ["devices", "newly_permitted_scope", "rule_edits"]),
            )
            result["scope"] = scope
            result["protection_scope"] = [item["name"] for item in options["protected"]]
            result["policy_observations_complete"] = set(options["allowed_targets"]) <= _complete
        elif kind == "resilience":
            from hst.assessment.resilience import apply_failures, search_resilience
            from hst.impact.evaluate import answer as answer_network

            def failure_oracle(effects: list[dict]) -> dict:
                try:
                    if not effects:
                        return baseline["outcomes"]["after"]
                    network = apply_failures(context.network, effects)
                    if getattr(context, "uses_symbolic", False):
                        outcome = budget.run(lambda: context.network_outcome(network, context.request, mode))
                    else:
                        answer = budget.run(lambda: answer_network(network, context.request, mode))
                        outcome = ev.outcome(answer)
                        # the trial is evaluated for the same incomplete
                        # population as the baseline, on either engine
                        _incomplete_population(outcome, getattr(context, "request_document", None) or {})
                    if progress:
                        progress({"evaluated": budget.count, "phase": kind})
                    return outcome
                except (ValueError, HTTPException, _BudgetExceeded) as exc:
                    return {"verdict": UNKNOWN, "reason": _proposal_reason(exc)}

            from hst.assessment.failure_evidence import validate_failure_evidence

            evidence = validate_failure_evidence(
                context.session, context.snapshot.manifest, options["targets"], options["domains"]
            )
            result = search_resilience(
                options["targets"],
                options["domains"],
                failure_oracle,
                limits,
                cancelled=budget.stopped,
                evidence=evidence,
            )
        elif kind == "verify":
            deployment = inputs["deployment"]
            observed_ms = observation_floor(context.snapshot.manifest)
            prediction = inputs["prediction"]
            coverage = observation_coverage(
                context.snapshot.manifest,
                prediction.get("dependencies", []),
                deployment["deployed_at"],
                definition.get("freshness_s"),
                # `as_of` is the submission time. A run recorded without `submitted_at`
                # uses the publication time of the manifest.
                as_of=inputs.get("submitted_at"),
            )
            fresh = coverage["qualifies"]
            # The prediction is a stored run in the result vocabulary. The observation
            # is compared in the same form.
            from hst.results.project import answer_of, engine_value_of, project_engine

            def same_side(left: Any, right: Any) -> bool:
                """Whether two sides state the same answer over the same clients. Only
                the answer of `result` is compared (`answer_of`)."""
                if not isinstance(left, dict) or not isinstance(right, dict):
                    return left == right
                key = lambda side: {k: answer_of(v) if k == "result" else v for k, v in side.items()}  # noqa: E731
                return key(left) == key(right)

            observed_answer = project_engine(copy.deepcopy(baseline), mode)
            actual, expected = observed_answer["outcomes"]["after"], prediction["outcomes"]["after"]
            # Verification observes the deployed model. No proposed intent is applied to
            # the desired observation or to the protected observations.
            observed_constraints = evaluate_constraints([], baseline["outcomes"]["after"]["verdict"])
            baseline["constraints"] = observed_constraints
            observed_projected = project_engine(copy.deepcopy(observed_constraints), mode)
            predicted_constraints = prediction.get("constraints") or {}
            predicted_protections = {
                name: engine_value_of(value)
                for name, value in (predicted_constraints.get("protected") or {}).items()
            }
            observed_protections = observed_constraints["protected"]
            missing_predictions = sorted(set(observed_protections) - set(predicted_protections))
            missing_requests = sorted(set(predicted_protections) - set(observed_protections))
            unresolved = sorted(
                name
                for name in set(predicted_protections) | set(observed_protections)
                if predicted_protections.get(name) not in {HOLDS, FAILS}
                or observed_protections.get(name) not in {HOLDS, FAILS}
            )
            predicted_outcomes = predicted_constraints.get("outcomes", {})
            changed = sorted(
                name
                for name in set(predicted_protections) & set(observed_protections)
                if predicted_protections[name] != observed_protections[name]
                or (
                    name in predicted_outcomes
                    and not same_side(predicted_outcomes[name], observed_projected["outcomes"].get(name))
                )
            )
            protected_comparison = {
                "predicted": predicted_constraints.get("protected") or {},
                "observed": observed_projected["protected"],
                "changed": changed,
                "unresolved": unresolved,
                "missing_predictions": missing_predictions,
                "missing_requests": missing_requests,
                "reason": observed_constraints["reason"],
            }
            # An open answer can have an empty open list. An incomplete population
            # changes the verdict and leaves the client lists unchanged.
            unknown = bool(
                actual["open"]
                or expected["open"]
                or answer_of(actual.get("result")) not in {"true", "false"}
                or answer_of(expected.get("result")) not in {"true", "false"}
                or unresolved
                or missing_predictions
                or missing_requests
                or observed_constraints["reason"]
            )
            state = (
                "insufficient-evidence"
                if not fresh or unknown
                else "agreement"
                if same_side(actual, expected) and not changed
                else "deviation"
            )
            realization = _configuration_realization(settings, inputs, context, budget, fresh)
            result = {
                "state": state,
                "prediction": prediction,
                "observed": baseline,
                "protected_comparison": protected_comparison,
                "deployment": deployment,
                "post_deployment_evidence": fresh,
                "observation_coverage": coverage,
                "observation_floor_ms": observed_ms,
                "configuration_realization": realization["state"],
                "configuration_realization_detail": realization,
                "claim": "Comparison of predicted and collected models; application health was not measured.",
            }
        else:
            raise ValueError(f"Unknown analysis kind {kind}")
        return finish(result, baseline)
