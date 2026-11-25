"""Strict accounting for graph gates around an impact forwarding stage."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any, Literal

import hst.path as _path
from hst.core.labels import MATCH_CONTEXTS, RESERVED_LABELS
from hst.core.model import DEGRADING_SECTION_STATUSES

from ..state import Effect, FlowRegion
from . import unevaluated_gates
from .firewall import _other_chain_rulebases
from .pbr import _other_interface_pbr_policies

ImpactStage = Literal["local-input", "local-output", "forward"]

_DETAILS = """
UNWIND $uids AS uid
MATCH (g:Gate {uid: uid})
WHERE NOT g:Retired AND g:Obj AND g.collection_ts = $snap
OPTIONAL MATCH (i:Interface)-[bind:ENFORCES|PROTECTED_BY]->(g)
WHERE bind._retired_at IS NULL AND NOT i:Retired
RETURN g.uid AS uid, labels(g) AS labels, g.kind AS model_kind,
       g.chain AS chain, g.match_context AS match_context,
       collect(DISTINCT i.uid) AS binding_interfaces
ORDER BY uid"""

_DEVICE_EVIDENCE = """
MATCH (d:Device {uid: $device_uid})
WHERE NOT d:Retired AND d:Obj AND d.collection_ts = $snap
RETURN d.hostname AS host, d.source AS source, d._scope AS scope"""

_GOOD_SECTION = {"ok", "empty", "complete", "complete-empty"}
# The statuses of a policy section whose read failed or stopped short.
_DEGRADED_POLICY_SECTION = {*DEGRADING_SECTION_STATUSES, "partial"}
_POLICY_SECTIONS = {
    # Collector section keys that hold flow-gate configuration.
    "iosxe": frozenset({"acl", "interface_config", "nat", "vlan_filter"}),
    "nxos": frozenset({"acl", "interface_config", "nat", "vlan_filter"}),
    # IOS-XR collects no access list body. The bindings place the opaque
    # rulebases. An opaque rulebase makes its bound interface undecided.
    "iosxr": frozenset({"interface_config"}),
    "vyos": frozenset({"config"}),
    "checkpoint": frozenset({"access", "nat"}),
    "unifi": frozenset({"policy"}),
    "apic": frozenset({"policy"}),
}
# The sections a point trace reads beside `_POLICY_SECTIONS`. Only a recorded
# degraded status of these sections is read.
_TRACE_POLICY_SECTIONS = {
    **_POLICY_SECTIONS,
    "velocloud": frozenset({"configuration"}),
    "checkpoint_gateway": frozenset({"installation"}),
}


@dataclass(frozen=True, slots=True)
class CoverageUnknown:
    uid: str
    kind: str
    reason: str


@dataclass(frozen=True, slots=True)
class CoverageTransition:
    """An identity transition that makes unsupported gate evidence explicit."""

    unknowns: tuple[CoverageUnknown, ...]

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        if not self.unknowns:
            return [(region, Effect("pass", "gate-coverage", reason="all applicable gates accounted for"))]
        names = ", ".join(f"{item.kind} {item.uid}" for item in self.unknowns)
        return [
            (
                region,
                Effect(
                    "indeterminate",
                    "gate-coverage",
                    unknown=frozenset({"gate-evidence"}),
                    reason=f"applicable gate(s) were not evaluated: {names}",
                    data={
                        "unknown_gates": tuple(item.uid for item in self.unknowns),
                        "evidence_gaps": tuple(
                            {
                                "code": "policy-observation-incomplete"
                                if item.kind == "ObservationGap"
                                else "gate-semantics-unmodeled",
                                "kind": "not-collected" if item.kind == "ObservationGap" else "not-modeled",
                                "subject": item.uid.removeprefix("evidence:"),
                                "dimension": "policy" if item.kind == "ObservationGap" else item.kind,
                                "detail": item.reason,
                            }
                            for item in self.unknowns
                        ),
                    },
                ),
            )
        ]


@dataclass(slots=True)
class CreditedTransition:
    """Attach the concrete gate IDs a supported transition read."""

    transition: Any
    preflight_credits: frozenset[str] = frozenset()

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        results = self.transition.apply(region)
        credits = set(self.preflight_credits)
        credits.update(str(uid) for uid in getattr(self.transition, "considered", ()) if uid)
        for _out, effect in results:
            credits.update(_effect_credits(effect.data))
        if not credits:
            return results
        return [
            (
                out,
                replace(effect, data={**effect.data, "gate_credits": tuple(sorted(credits))}),
            )
            for out, effect in results
        ]


def stage_gate_credits(
    session: Any,
    device_uid: str,
    stage: ImpactStage,
    in_interface_uid: str | None,
    out_interface_uid: str | None,
    af: int,
    considered_ids: Iterable[str] = (),
) -> frozenset[str]:
    """Concrete gates excluded before a supported stage runs."""
    if af not in {4, 6}:
        raise ValueError("gate coverage address family must be 4 or 6")
    credits = {str(uid) for uid in considered_ids if uid}
    chain = {"local-input": "input", "local-output": "output", "forward": "forward"}[stage]
    credits.update(_other_chain_rulebases(session, device_uid, chain, in_interface_uid))
    if stage == "forward" and in_interface_uid:
        credits.update(_other_interface_pbr_policies(session, device_uid, in_interface_uid))
    return frozenset(credits)


def _effect_credits(data: Mapping[str, Any]) -> set[str]:
    credits: set[str] = set()
    for key in ("rb_uid", "pol_uid", "nat_uid", "rulebase_uid"):
        value = data.get(key)
        if value:
            credits.add(str(value))
    for key in ("rb_uids", "pol_uids", "nat_uids", "gate_credits"):
        values = data.get(key)
        if isinstance(values, (list, tuple, set, frozenset)):
            credits.update(str(value) for value in values if value)
    rule = data.get("rule")
    if isinstance(rule, Mapping):
        for key in ("uid", "rb_uid", "nat_uid"):
            if rule.get(key):
                credits.add(str(rule[key]))
    for key in ("models", "also"):
        for model in data.get(key) or ():
            if isinstance(model, Mapping):
                credits.update(_effect_credits(model))
    return credits


def strict_gate_coverage(
    session: Any,
    device_uid: str,
    *,
    stage: ImpactStage,
    in_interface_uid: str | None,
    out_interface_uid: str | None,
    evaluated_ids: Iterable[str],
    composed_kinds: Iterable[str] = (),
    preflight: bool = False,
) -> CoverageTransition:
    """Return an identity/unknown transition for gates applicable to one stage.

    ``evaluated_ids`` includes gates that decided and gates a reader ruled out.
    A known class is credited only when its concrete uid is read or excluded.
    """
    evaluated = set(evaluated_ids)
    missed = unevaluated_gates(session, [device_uid], evaluated)
    evidence_unknown = _observation_unknown(session, device_uid)
    if not missed and evidence_unknown is None:
        return CoverageTransition(())
    by_uid = {row["uid"]: row for row in missed}
    details = _path._read(session, _DETAILS, uids=sorted(by_uid))
    known_classes = set(composed_kinds)
    unknowns: list[CoverageUnknown] = []
    for row in details:
        uid = row["uid"]
        kind = _primary_kind(row.get("labels"), by_uid[uid].get("kind"))
        if not _applicable(row, kind, stage, in_interface_uid, out_interface_uid):
            continue
        if preflight and _supported_shape(row, kind, known_classes):
            continue
        suffix = ""
        if kind in known_classes:
            suffix = "; its composed evaluator did not account for this gate uid"
        unknowns.append(CoverageUnknown(uid, kind, _reason(row, kind) + suffix))
    detailed = {row["uid"] for row in details}
    for uid in sorted(by_uid.keys() - detailed):
        kind = str(by_uid[uid].get("kind") or "Gate")
        unknowns.append(CoverageUnknown(uid, kind, "gate binding details were not observed"))
    if evidence_unknown is not None:
        unknowns.append(CoverageUnknown(f"evidence:{device_uid}", "ObservationGap", evidence_unknown))
    return CoverageTransition(tuple(sorted(unknowns, key=lambda item: item.uid)))


def _observation_unknown(session: Any, device_uid: str) -> str | None:
    """Why graph absence cannot establish policy absence for this device."""
    snapshot = getattr(session, "snapshot", None)
    if snapshot is None:
        return None
    manifest = snapshot.manifest
    if manifest is None:
        return "no published manifest proves that device policy inputs were collected"
    entry = _manifest_entry(session, manifest, device_uid)
    if entry is None:
        return "device provenance cannot be mapped uniquely to published collection evidence"
    if entry.outcome == "failed" or (entry.carried and not entry.effective_run):
        return f"device collection outcome is {entry.outcome}; policy absence is not observed"
    source_types = {source.name: source.type for source in manifest.sources}
    source_type = source_types.get(entry.source)
    required = _POLICY_SECTIONS.get(str(source_type or "").lower())
    if not required:
        return "collector has no declared policy-section completeness contract"
    relevant = {name: entry.sections[name] for name in required if name in entry.sections}
    degraded = [
        f"{name}={outcome.status}"
        for name, outcome in relevant.items()
        if outcome.status not in _GOOD_SECTION
    ]
    if degraded:
        return "policy input section was not collected completely: " + ", ".join(sorted(degraded))
    missing = sorted(required - entry.sections.keys())
    if missing:
        return "device entry lacks declared policy sections: " + ", ".join(missing)
    return None


def _manifest_entry(session: Any, manifest: Any, device_uid: str) -> Any | None:
    """The manifest's one device entry for this device, or None when its
    provenance does not map to exactly one."""
    identity = _path._read(session, _DEVICE_EVIDENCE, device_uid=device_uid)
    if len(identity) != 1 or not identity[0].get("host"):
        return None
    row = identity[0]
    has_uid_provenance = any(getattr(entry, "device_uids", None) for entry in manifest.devices)
    mapped = [
        entry for entry in manifest.devices if device_uid in (getattr(entry, "device_uids", None) or ())
    ]
    candidates = (
        mapped if has_uid_provenance else [entry for entry in manifest.devices if entry.host == row["host"]]
    )
    source = row.get("source")
    if source and not has_uid_provenance:
        candidates = [entry for entry in candidates if entry.source == source]
    return candidates[0] if len(candidates) == 1 else None


def degraded_policy_sections(session: Any, device_uid: str) -> list[str]:
    """The policy input sections of this device the pinned run's manifest
    records as not collected, as "name=status".

    The list holds each section the run recorded as failed, unauthorized,
    malformed or partial. It holds `device=not collected` for a device no run
    at or before the snapshot collected. It holds `device=load failed` for a
    device whose load in the run failed after it began. The list is empty
    with no manifest, no entry for the device, or no declared policy sections.
    `unknown` (a payload written before outcomes were recorded) and
    `unsupported` (a box without the feature) are not read as gaps.
    """
    return policy_evidence(session, device_uid)[0]


def policy_evidence(session: Any, device_uid: str) -> tuple[list[str], str | None]:
    """`degraded_policy_sections`, and why this device's gates in the graph
    are an earlier run's copy (or None), from one read of the pinned
    manifest's entries for the device.

    A device whose collection failed, or whose source did not run, has the
    state of its effective run. A policy section that failed, was refused or
    did not parse keeps its objects from the run before
    (`Collector.SECTION_LABELS`). In both cases the gate the trace evaluated
    is the last-known copy.

    A section of the source's policy contract that an entry does not record
    is a gap (`name=not recorded`)."""
    snapshot = getattr(session, "snapshot", None)
    manifest = snapshot.manifest if snapshot is not None else None
    if manifest is None:
        return [], None
    entries = _manifest_entries(session, manifest, device_uid)
    source_types = {source.name: str(source.type or "").lower() for source in manifest.sources}
    if len(entries) > 1:
        entries = [
            entry for entry in entries if _TRACE_POLICY_SECTIONS.get(source_types.get(entry.source, ""))
        ]
    named = len(entries) > 1
    gaps: list[str] = []
    notes: list[str] = []
    for entry in entries:
        entry_gaps, entry_note = _entry_policy_evidence(entry, source_types.get(entry.source, ""))
        prefix = f"{entry.source}: " if named else ""
        gaps.extend(prefix + gap for gap in entry_gaps)
        if entry_note:
            notes.append(prefix + entry_note)
    return gaps, "; ".join(notes) or None


def _entry_policy_evidence(entry: Any, source_type: str) -> tuple[list[str], str | None]:
    """`policy_evidence` for one manifest entry of the device.

    A failed entry whose load began (`ingested_ms` set on a failed outcome)
    is a gap, `device=load failed`. A failed fetch stays a note. A later run
    that carries the failed load forward keeps the gap until a full load of
    the device succeeds."""
    load_failed = entry.outcome == "failed" and getattr(entry, "ingested_ms", None) is not None
    if load_failed:
        return ["device=load failed"], (
            "the device's load in this run failed; objects it wrote stand beside objects "
            "carried from the run before"
        )
    mixed_since = getattr(entry, "mixed_since", None)
    if mixed_since:
        return ["device=load failed"], (
            f"the device's load in run {mixed_since} failed and no full load has succeeded since; "
            "its objects are a mix of what that load wrote and what was carried"
        )
    if not entry.effective_run and (entry.carried or entry.outcome == "failed"):
        return ["device=not collected"], None
    required = _TRACE_POLICY_SECTIONS.get(source_type) or frozenset()
    gaps = sorted(
        f"{name}={entry.sections[name].status}"
        for name in required
        if name in entry.sections and entry.sections[name].status in _DEGRADED_POLICY_SECTION
    )
    gaps += sorted(
        f"{name}=not recorded"
        for name in _POLICY_SECTIONS.get(source_type, frozenset()) - entry.sections.keys()
    )
    if entry.outcome in ("failed", "carried"):
        return gaps, f"device outcome {entry.outcome}; policy is the copy from run {entry.effective_run}"
    carried = sorted(
        name
        for name in required
        if name in entry.sections and entry.sections[name].status in DEGRADING_SECTION_STATUSES
    )
    if carried:
        return gaps, f"{', '.join(carried)} carried from the last run that read it"
    return gaps, None


def _manifest_entries(session: Any, manifest: Any, device_uid: str) -> list[Any]:
    """Every manifest entry that may hold this device. These are the entries
    that list its uid, and the entries that list no uids whose host is the
    device's hostname. The entries are not filtered by the Device's `source`.
    On a device that more than one source writes, `source` holds only the
    last writer."""
    identity = _path._read(session, _DEVICE_EVIDENCE, device_uid=device_uid)
    if len(identity) != 1 or not identity[0].get("host"):
        return []
    host = identity[0]["host"]
    return [
        entry
        for entry in manifest.devices
        if (
            device_uid in (getattr(entry, "device_uids", None) or ())
            or (not getattr(entry, "device_uids", None) and entry.host == host)
        )
    ]


def _primary_kind(labels: Any, fallback: Any) -> str:
    if isinstance(labels, list):
        kinds = [label for label in labels if isinstance(label, str) and label not in RESERVED_LABELS]
        if kinds:
            return kinds[0]
    return str(fallback or "Gate")


def _applicable(
    row: Mapping[str, Any],
    kind: str,
    stage: ImpactStage,
    in_if: str | None,
    out_if: str | None,
) -> bool:
    chain = str(row.get("chain") or "").lower()
    if kind == "FwRulebase" and chain in {"input", "output", "forward"}:
        wanted = {"local-input": "input", "local-output": "output", "forward": "forward"}[stage]
        return chain == wanted
    bindings = {uid for uid in row.get("binding_interfaces") or () if uid}
    if kind == "PbrPolicy":
        return stage == "forward" and in_if is not None and (not bindings or in_if in bindings)
    if kind == "VirtualService":
        # Device attachment alone does not establish that this packet targets
        # the VIP. Its address-aware evaluator must supply a concrete credit.
        return False
    if kind == "SdwanBusinessPolicy":
        return stage in {"forward", "local-output"}
    if bindings:
        relevant = {uid for uid in (in_if, out_if) if uid}
        return bool(bindings & relevant)
    return True


def _reason(row: Mapping[str, Any], kind: str) -> str:
    if kind == "FwRulebase" and not row.get("model_kind"):
        return "firewall rulebase kind was not recorded"
    if kind == "FwRulebase" and row.get("model_kind") != "nat" and not row.get("match_context"):
        return "firewall rulebase match context was not recorded"
    return "gate is applicable through a live snapshot binding but produced no evaluated evidence"


def _supported_shape(row: Mapping[str, Any], kind: str, composed_kinds: set[str]) -> bool:
    """Whether preflight may defer this exact schema shape to its evaluator."""
    if kind not in composed_kinds:
        return False
    if kind == "FwRulebase":
        # Each NatRule of a NAT rulebase holds its processing stage. The
        # access-policy match_context field is not part of that schema.
        if row.get("model_kind") == "nat":
            return True
        return (
            str(row.get("chain") or "").lower() in {"", "input", "output", "forward"}
            and row.get("model_kind") in {"access", "zone"}
            and row.get("match_context") in MATCH_CONTEXTS
        )
    return kind in {"PbrPolicy", "VirtualService", "NatRule"}
