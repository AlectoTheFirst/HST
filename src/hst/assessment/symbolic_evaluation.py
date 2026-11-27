"""Native assessment execution over one immutable, manifest-bound graph.

The manager and compiled models belong to the evaluation context. A caller
serializes results before it closes the context. No native handle enters the
worker IPC.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, replace
from typing import Literal, cast

from hst.analysis_model.compile import AnalysisModel, CompiledNode, compile_model
from hst.analysis_model.counterfactual import (
    apply_policy_counterfactual,
    graph_for_counterfactual,
    project_counterfactual,
)
from hst.analysis_model.evidence import EvidenceEvaluation
from hst.analysis_model.graph import GraphInventory
from hst.analysis_model.incremental import ModelDependencyState, plan_model_incremental
from hst.analysis_model.model import ModelInput, semantic_fingerprint
from hst.analysis_model.model_cache import CompiledModelCache
from hst.analysis_model.network import ROUTE_NOT_OBSERVED, normalize_request_network
from hst.assessment.result_artifacts import MAX_ARTIFACT_BYTES, ResultArtifactStore
from hst.assessment.symbolic_results import (
    SymbolicAnswer,
    aggregate,
    comparison,
    exact_evidence,
    exact_roots,
)
from hst.impact.evaluate import SPREAD_ASSUMPTION, Member, Network, RequestSet, Service
from hst.impact.symbolic_walk import DEFAULT_LIMITS, WalkLimits, walk
from hst.policy.bounds import ChoiceMode
from hst.policy.compile import PolicyCompiler
from hst.policy.ir import ExecutionContext
from hst.symbolic import HeaderSchema, PacketSet, SymbolicManager, header
from hst.symbolic.predicates import ValueRange


def request_identity(request: RequestSet) -> str:
    """Bind a walk to the entire declared question, including assumptions."""

    def encode(value: object) -> object:
        if isinstance(value, frozenset):
            return sorted(value)
        raise TypeError(f"unsupported request identity value: {type(value).__name__}")

    payload = json.dumps(asdict(request), default=encode, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


# The entry of `SymbolicAnswer.assumptions` for a request that states no fragment offset.
INITIAL_FRAGMENTS_ASSUMPTION = (
    "INITIAL_FRAGMENTS_ONLY: the request states no fragment offset, so only initial fragments are evaluated"
)


def _ports_exclude_zero(service: Service) -> bool:
    """Whether a stated port set excludes 0. A packet with a nonzero port is valid only
    as an initial fragment. A request with such a port set holds the fragment offset at
    0."""
    return any(
        intervals and all(low > 0 for _af, low, _high in intervals)
        for intervals in (service.sport, service.dport)
    )


def initial_fragments_assumed(manager: SymbolicManager, request: RequestSet, member: Member) -> bool:
    """Whether `member_packets` assumes the initial fragment for the request. The
    assumption holds when the request states no fragment offset and no port set that
    excludes 0. The answer lists the assumption (`INITIAL_FRAGMENTS_ASSUMPTION`)."""
    stated = {manager.schema.canonical_field(name) for name, _ranges in request.header_constraints}
    return "fragment_offset" not in stated and not _ports_exclude_zero(member.service or request.service)


def computed_routes_assumption(contexts: Iterable[str]) -> str:
    """The entry of `SymbolicAnswer.assumptions` for the forwarding contexts of the
    models of an answer whose routing table the run did not read (`Network.unobserved`).
    The models follow the computed routes of these contexts. A flow of the request
    can pass by none of them."""
    return (
        "COMPUTED_ROUTES: no collected routing table confirms the computed routes of "
        f"{', '.join(sorted(contexts))}"
    )


def answer_assumptions(
    manager: SymbolicManager, request: RequestSet, computed_routes: Iterable[str] = ()
) -> tuple[str, ...]:
    """What an answer to the request assumes beyond the evidence. `computed_routes`
    holds the forwarding contexts of `computed_routes_assumption`."""
    assumed = any(initial_fragments_assumed(manager, request, member) for member in request.members)
    contexts = sorted(set(computed_routes))
    return (
        SPREAD_ASSUMPTION,
        *((INITIAL_FRAGMENTS_ASSUMPTION,) if assumed else ()),
        *((computed_routes_assumption(contexts),) if contexts else ()),
    )


def member_packets(manager: SymbolicManager, request: RequestSet, member: Member) -> PacketSet:
    """Construct the declared set directly, without a FlowRegion conversion."""
    if member not in request.members:
        raise ValueError("member is outside the declared request")
    if any(af != manager.schema.address_family for af, _low, _high in request.sources + member.addresses):
        raise ValueError("request address family differs from the symbolic manager")
    service = member.service or request.service
    constraints: dict[str, object] = {
        "source_address": [ValueRange(low, high) for _af, low, high in request.sources],
        "destination_address": [ValueRange(low, high) for _af, low, high in member.addresses],
    }
    constraints.update(
        {name: [ValueRange(low, high) for low, high in ranges] for name, ranges in request.header_constraints}
    )
    if service.proto is not None:
        constraints["protocol"] = list(service.proto)
    for field, intervals in (("source_port", service.sport), ("destination_port", service.dport)):
        if intervals is not None:
            constraints[field] = [ValueRange(low, high) for _af, low, high in intervals]
    if initial_fragments_assumed(manager, request, member):
        constraints["fragment_offset"] = [ValueRange(0, 0)]
    packets = header(
        manager, constraints, explicitly_all=("fragment_offset",) if _ports_exclude_zero(service) else ()
    )
    if packets.is_empty():
        raise ValueError("request has no valid packets under the declared header constraints")
    return packets


class SymbolicEvaluation:
    """Reuse native managers and compiled models across a job's candidates."""

    def __init__(
        self,
        graph: GraphInventory,
        estate: str,
        *,
        limits: WalkLimits = DEFAULT_LIMITS,
        cancelled: Callable[[], bool] | None = None,
        max_cached_models: int = 32,
        evidence: EvidenceEvaluation | None = None,
        result_store: ResultArtifactStore | None = None,
        model_cache: CompiledModelCache | None = None,
    ) -> None:
        if not estate or max_cached_models < 1:
            raise ValueError("an estate and a positive compiled-model cache bound are required")
        self.graph, self.estate = graph, estate
        self.limits, self.cancelled = limits, cancelled
        self.max_cached_models = max_cached_models
        self.evidence, self.result_store = evidence, result_store
        self.model_cache = model_cache
        self._managers: dict[int, SymbolicManager] = {}
        # The forwarding contexts of `computed_routes_assumption` in the models
        # that `compile` got since `answer_network` started.
        self._computed_routes: set[str] = set()
        self._models: dict[tuple[int, str, frozenset[str]], AnalysisModel] = {}
        self._closed = False
        self.compile_seconds = 0.0
        self.compiled_models = 0
        self._policy_compilers: dict[tuple[int, ExecutionContext, frozenset[str]], PolicyCompiler] = {}
        self._policy_metrics: dict[str, int] = {}
        self._incremental_states: dict[tuple[int, int, frozenset[str], str], ModelDependencyState] = {}
        self._compiled_nodes: dict[tuple[int, int, frozenset[str], str], dict[str, CompiledNode]] = {}
        self._preflight: dict[str, dict] = {}

    def __enter__(self) -> SymbolicEvaluation:
        self._check()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _check(self) -> None:
        if self._closed:
            raise RuntimeError("symbolic evaluation context is closed")
        if self.cancelled is not None and self.cancelled():
            raise RuntimeError("symbolic evaluation cancelled")

    def close(self) -> None:
        self._models.clear()
        self._policy_compilers.clear()
        self._incremental_states.clear()
        self._compiled_nodes.clear()
        for manager in self._managers.values():
            manager.close()
        self._managers.clear()
        self._closed = True
        if self.model_cache is not None:
            self.model_cache.close()

    def compile(
        self, source: ModelInput, manager: SymbolicManager, known_fields: frozenset[str]
    ) -> AnalysisModel:
        self._check()
        self._computed_routes.update(
            str(node.key.context.vrf)
            for node in source.nodes
            if node.key.location.startswith(ROUTE_NOT_OBSERVED)
        )
        key = id(manager), semantic_fingerprint(source), known_fields
        model = self._models.get(key)
        if model is None:
            from hst.analysis_model.preflight import model_preflight

            if len(self._preflight) >= self.max_cached_models:
                del self._preflight[next(iter(self._preflight))]
            self._preflight[key[1]] = model_preflight(source)
            started = time.monotonic()
            model = (
                self._compile_uncached(source, manager, known_fields)
                if self.model_cache is None
                else self.model_cache.compile(
                    source, manager, known_fields, estate=self.estate, compiler=self._compile_uncached
                )
            )
            if len(self._models) >= self.max_cached_models:
                del self._models[next(iter(self._models))]
            self._models[key] = model
            self.compile_seconds += time.monotonic() - started
            self.compiled_models += 1
        return model

    def _compile_uncached(
        self, source: ModelInput, manager: SymbolicManager, known_fields: frozenset[str]
    ) -> AnalysisModel:
        cache_key = (
            id(manager),
            manager.schema.address_family,
            known_fields,
            source.manifest_digest,
        )
        if cache_key not in self._incremental_states:
            while len(self._incremental_states) >= self.max_cached_models:
                evicted = next(iter(self._incremental_states))
                del self._incremental_states[evicted]
                self._compiled_nodes.pop(evicted, None)
        previous = self._incremental_states.get(cache_key)
        current, plan = plan_model_incremental(source, previous)
        self._incremental_states[cache_key] = current
        counters = {
            "incremental_nodes_affected": len(plan.affected),
            "incremental_nodes_reuse_planned": len(plan.reused),
            "incremental_broad_rebuild": int(plan.broad_rebuild),
        }
        for metric, value in counters.items():
            self._policy_metrics[metric] = self._policy_metrics.get(metric, 0) + value
        reusable = frozenset(current.keys[ref] for ref in plan.reused if ref in current.keys)
        cache = self._compiled_nodes.setdefault(cache_key, {})
        model = compile_model(
            source,
            manager,
            known_fields,
            policy_compilers=self._policy_compilers,
            metrics=self._policy_metrics,
            node_cache=cache,
            reusable_nodes=reusable,
        )
        while len(cache) > self.max_cached_models * max(1, len(source.nodes)):
            del cache[next(iter(cache))]
        return model

    def candidate_graph(self, network: Network) -> GraphInventory:
        from hst.analysis_model.overlay import apply_overlay
        from hst.assessment.adapters import _PolicyEdits
        from hst.impact.evaluate import _OverlaySession
        from hst.simul.fw_overlay import ChangeSet
        from hst.simul.rib import INTENT_KINDS

        session = getattr(network.gates, "session", None)
        overlays = []
        while isinstance(session, _OverlaySession):
            overlays.append(session._changes)
            session = session._session
        if network.changes is not None and not any(change is network.changes for change in overlays):
            overlays.insert(0, network.changes)
        graph = self.graph
        for change in reversed(overlays):
            if isinstance(change, _PolicyEdits):
                graph = apply_policy_counterfactual(graph, change)
                continue
            policy = [intent for intent in change.intents if intent.kind not in INTENT_KINDS]
            if policy:
                graph = apply_overlay(graph, ChangeSet(policy, catalog=change.catalog, errors=change.errors))
        return graph_for_counterfactual(graph, network, apply_policy_edits=False)

    def answer_network(
        self,
        network: Network,
        request: RequestSet,
        mode: str,
        *,
        graph: GraphInventory | None = None,
        evidence: EvidenceEvaluation | None = None,
    ) -> SymbolicAnswer:
        self._check()
        if mode not in {"possible", "guaranteed", "unspecified"}:
            raise ValueError("unknown forwarding choice mode")
        selected_graph = self.candidate_graph(network) if graph is None else graph
        if selected_graph.manifest_digest != self.graph.manifest_digest:
            raise ValueError("candidate graph crosses the pinned snapshot manifest")
        family = request.sources[0][0]
        if family not in self._managers:
            self._managers[family] = SymbolicManager(HeaderSchema(cast(Literal[4, 6], family)))
        manager = self._managers[family]
        selected_evidence = self.evidence if evidence is None else evidence
        inputs = normalize_request_network(
            network, selected_graph, request, self.estate, evidence=selected_evidence
        )
        identity = request_identity(request)
        results = {}
        self._computed_routes = set()
        for member in request.members:
            self._check()
            packets = member_packets(manager, request, member)
            source = project_counterfactual(inputs[member.name], network)
            model = self.compile(source, manager, packets.known_fields)
            if request.success == "forward":
                results[member.name] = walk(
                    model,
                    packets,
                    request_id=identity,
                    mode=cast(ChoiceMode, mode),
                    limits=self.limits,
                    cancelled=self.cancelled,
                )
            else:
                from hst.analysis_model.network_session import network_session_walk

                results[member.name] = network_session_walk(
                    network,
                    selected_graph,
                    request,
                    member,
                    manager,
                    model,
                    packets,
                    estate=self.estate,
                    request_id=identity,
                    compiler=self.compile,
                    requires_state=request.success == "session",
                    mode=cast(ChoiceMode, mode),
                    limits=self.limits,
                    cancelled=self.cancelled,
                    evidence=selected_evidence,
                ).reply
        # Equal-cost paths, load balancer members and connectors are the
        # joint choices of this engine.
        answer = aggregate(request, results, mode=cast(ChoiceMode, mode), choice_mode=cast(ChoiceMode, mode))
        answer = replace(answer, assumptions=answer_assumptions(manager, request, self._computed_routes))
        return replace(answer, evidence=selected_evidence)

    def compare_networks(
        self,
        before: Network,
        after: Network,
        request: RequestSet,
        mode: str,
        *,
        after_graph: GraphInventory | None = None,
    ) -> dict:
        left = self.answer_network(before, request, mode)
        right = self.answer_network(after, request, mode, graph=after_graph)
        result = comparison(left, right, include_artifact=self.result_store is None)
        from hst.symbolic.backend import backend_identity

        result["symbolic"]["build"] = asdict(backend_identity())
        result["symbolic"]["preflight"] = {
            "models": list(self._preflight.values()),
            "retained_limit": self.max_cached_models,
        }
        if self.result_store is not None:
            from hst.symbolic.artifacts import ArtifactLimits, encode_packet_sets

            artifact = encode_packet_sets(
                exact_roots(left, right),
                limits=ArtifactLimits(max_bytes=MAX_ARTIFACT_BYTES, max_nodes=1_000_000, max_roots=200_000),
            )
            reference = self.result_store.publish(
                artifact,
                estate=self.estate,
                manifest_sha256=self.graph.manifest_digest,
                request_id=request_identity(request),
                evidence=exact_evidence(left, right),
            )
            result["symbolic"]["artifact_sha256"] = reference["artifact_sha256"]
            result["symbolic"]["artifact_ref"] = reference
        if self.model_cache is not None:
            result["symbolic"]["cache"] = {
                "hits": self.model_cache.hits,
                "misses": self.model_cache.misses,
            }
        result["symbolic"]["metrics"] = {
            **self._policy_metrics,
            "model_load_compile_seconds": self.compile_seconds,
            "models_loaded_or_compiled": self.compiled_models,
            "referenced_bdd_nodes": sum(manager.node_count for manager in self._managers.values()),
            "worklist_states": sum(
                member.states for answer in (left, right) for member in answer.members.values()
            ),
            "worklist_steps": sum(
                member.steps for answer in (left, right) for member in answer.members.values()
            ),
            "database_reads_during_walk": result["symbolic"]["database_reads_during_walk"],
        }
        return result
