"""Exact symbolic assessment results and bounded presentation views."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, cast

from hst.analysis_model.evidence import EvidenceEvaluation
from hst.assessment.symbolic_provenance import ObservationIndex
from hst.impact.evaluate import (
    ANY_ONE,
    CAPACITY,
    EVERY,
    FAILS,
    HOLDS,
    MEMBER,
    NOT_ESTABLISHED,
    Condition,
    RequestSet,
)
from hst.impact.symbolic_walk import WalkResult
from hst.path.trace import _exit_key
from hst.policy.bounds import Bounds, ChoiceMode, at_least, choices, for_all_requested_flows
from hst.symbolic import PacketSet
from hst.symbolic.address_render import address_prefixes
from hst.symbolic.artifacts import encode_packet_sets
from hst.symbolic.predicates import value_range


@dataclass(frozen=True, slots=True)
class SymbolicAnswer:
    request_set: RequestSet
    mode: ChoiceMode
    bounds: Bounds[PacketSet]
    members: Mapping[str, WalkResult]
    complete: bool
    gaps: tuple[str, ...]
    assumptions: tuple[str, ...] = ()
    choice_mode: ChoiceMode | None = None
    evidence: EvidenceEvaluation | None = None

    @property
    def lower(self) -> PacketSet:
        return self.bounds.lower

    @property
    def upper(self) -> PacketSet:
        return self.bounds.upper


def _condition(
    condition: Condition, members: Mapping[str, Bounds[PacketSet]], universe: PacketSet
) -> Bounds[PacketSet]:
    if condition.kind == MEMBER:
        return members[str(condition.member)]
    if condition.kind == CAPACITY:
        return Bounds.terminal(universe, "unknown")
    parts = tuple(_condition(part, members, universe) for part in condition.parts)
    needed = len(parts) if condition.kind == EVERY else 1 if condition.kind == ANY_ONE else condition.n
    if type(needed) is not int:
        raise ValueError("condition has no explicit threshold")
    return at_least(universe, parts, needed)


def aggregate(
    request: RequestSet,
    members: Mapping[str, WalkResult],
    *,
    mode: ChoiceMode,
    choice_mode: ChoiceMode | None = None,
) -> SymbolicAnswer:
    """Quantify each client's flows before aggregating correlated member choices."""
    if set(members) != {member.name for member in request.members}:
        raise ValueError("symbolic results must cover every declared member exactly once")
    first = next(iter(members.values()))
    population = first.bounds.universe.project(("source_address",), bank="original")
    declared = population.manager.empty()
    for af, low, high in request.sources:
        if af != population.manager.schema.address_family:
            raise ValueError("request and result address families differ")
        declared = declared.union(
            value_range(population.manager, "source_address", low, high, bank="original")
        )
    if not declared.project(("source_address",), bank="original").equivalent(population):
        raise ValueError("results do not cover the declared source population")
    assignments = tuple(result.assignment for result in first.by_choice)
    for result in members.values():
        if result.manifest_digest != first.manifest_digest or result.request_id != first.request_id:
            raise ValueError("member results cross snapshot/request identity")
        if tuple(item.assignment for item in result.by_choice) != assignments:
            raise ValueError("members must retain identical joint choice assignments")
        if not result.bounds.universe.project(("source_address",), bank="original").equivalent(population):
            raise ValueError("member results cross source populations")
    per_choice = []
    for index in range(len(assignments)):
        projected = {
            name: for_all_requested_flows(
                result.by_choice[index].bounds,
                population,
                lambda packets: packets.project(("source_address",), bank="original"),
            )
            for name, result in members.items()
        }
        per_choice.append(_condition(request.condition, projected, population))
    # Explicit choices are shared across all members. Unknown correlations are
    # never reconstructed by combining their separately existential marginals.
    bounds = choices(population, per_choice, mode=mode if choice_mode is None else choice_mode)
    if not all(result.choices_complete for result in members.values()):
        bounds = Bounds.terminal(population, "unknown")
    gap_codes = {gap for result in members.values() for gap in result.gap_refs}
    if (
        choice_mode == "unspecified"
        and len(assignments) > 1
        and not choices(population, per_choice, mode="possible").lower.equivalent(
            choices(population, per_choice, mode="guaranteed").lower
        )
    ):
        gap_codes.add("CHOICE_CORRELATION")

    def has_capacity(condition: Condition) -> bool:
        return condition.kind == CAPACITY or any(has_capacity(part) for part in condition.parts)

    if has_capacity(request.condition):
        gap_codes.add("CAPACITY_DEMAND_NOT_MODELED")
    gaps = tuple(sorted(gap_codes))
    return SymbolicAnswer(
        request,
        mode,
        bounds,
        members,
        all(result.complete for result in members.values()),
        gaps,
        choice_mode=choice_mode,
    )


def address_bucket(
    packets: PacketSet, *, limit: int = 250, offset: int = 0, field: str = "source_address"
) -> dict[str, Any]:
    page = address_prefixes(packets, limit=limit, offset=offset, field=field)
    return {
        "count": page.count if page.count <= 2**53 - 1 else None,
        "count_decimal": str(page.count),
        "address_count_decimal": str(page.addresses),
        "items": list(page.items),
        "truncated": page.next_offset is not None or offset > 0,
        "offset": offset if offset <= 2**53 - 1 else None,
        "offset_decimal": str(offset),
        "next_offset": (
            page.next_offset if page.next_offset is None or page.next_offset <= 2**53 - 1 else None
        ),
        "next_offset_decimal": str(page.next_offset) if page.next_offset is not None else None,
    }


def outcome(answer: SymbolicAnswer) -> dict[str, Any]:
    failed = answer.bounds.universe.subtract(answer.upper)
    unknown = answer.upper.subtract(answer.lower)
    held_view, failed_view, unknown_view = (
        address_bucket(value) for value in (answer.lower, failed, unknown)
    )
    return {
        "verdict": FAILS if not failed.is_empty() else NOT_ESTABLISHED if not unknown.is_empty() else HOLDS,
        "isolated": answer.upper.is_empty(),
        "holds": held_view["items"],
        "fails": failed_view["items"],
        "unknown": unknown_view["items"],
        "display_truncated": any(view["truncated"] for view in (held_view, failed_view, unknown_view)),
        "counts": {
            "holds": held_view["address_count_decimal"],
            "fails": failed_view["address_count_decimal"],
            "unknown": unknown_view["address_count_decimal"],
        },
    }


def exact_roots(before: SymbolicAnswer, after: SymbolicAnswer) -> dict[str, PacketSet]:
    if (
        before.request_set != after.request_set
        or before.mode != after.mode
        or before.choice_mode != after.choice_mode
    ):
        raise ValueError("comparison requires the same request and mode")
    if not before.bounds.universe.equivalent(after.bounds.universe):
        raise ValueError("comparison crosses symbolic managers or populations")
    roots = {"population": before.bounds.universe}
    for side, answer in (("before", before), ("after", after)):
        roots[side + "/lower"], roots[side + "/upper"] = answer.lower, answer.upper
        for name, member in answer.members.items():
            roots[f"{side}/member/{name}/request"] = member.bounds.universe
            roots[f"{side}/member/{name}/lower"] = member.bounds.lower
            roots[f"{side}/member/{name}/upper"] = member.bounds.upper
            for index, choice in enumerate(member.by_choice):
                prefix = f"{side}/member/{name}/choice/{index}"
                roots[prefix + "/lower"] = choice.bounds.lower
                roots[prefix + "/upper"] = choice.bounds.upper
                for terminal_index, terminal in enumerate(choice.terminal_reaches):
                    roots[f"{prefix}/terminal/{terminal_index}"] = terminal.packets
                for gap_index, gap in enumerate(choice.scoped_gaps):
                    roots[f"{prefix}/gap/{gap_index}"] = gap.packets
            for root, _choice, terminal, _forward in _forward_edges(f"{side}/member/{name}", member):
                roots[root] = terminal.packets
    return roots


def _forward_edges(prefix: str, result: WalkResult) -> list[tuple[str, Any, Any, WalkResult]]:
    """The forward terminals at the edge of the estate for a reply walk
    (`WalkResult.forward`, set by `session_walk`). Each item is (artifact root, forward
    choice, record, forward walk). The list is empty for a forward walk and for a reply
    whose forward path has no terminal at the edge of the estate."""
    forward = getattr(result, "forward", None)
    if forward is None:
        return []
    return [
        (f"{prefix}/forward/choice/{index}/terminal/{terminal_index}", choice, terminal, forward)
        for index, choice in enumerate(forward.by_choice)
        for terminal_index, terminal in enumerate(choice.terminal_reaches)
        if terminal.left_estate
    ]


def _left_estate(record: Any) -> dict[str, Any]:
    """The row keys of one terminal or gap record whose state ends the model at the edge
    of the estate (`NodeSpec.left_estate`). The keys hold the distinct objects in the
    tracer's order and their sentence. The result is empty for every other record."""
    found = {_exit_key(exit_): exit_ for exit_ in (dict(item) for item in getattr(record, "left_estate", ()))}
    if not found:
        return {}
    from hst.assessment.evaluation import _left_estate_note

    exits = [found[key] for key in sorted(found)]
    return {"left_estate": exits, "left_estate_note": _left_estate_note(exits)}


# A gap row lists at most this many reasons or sections and then "and N more".
_DETAIL_ITEMS = 5
# a result word for each word the result vocabulary leaves out
# (`results.words.FORBIDDEN_WORDS`), for engine texts quoted in a gap row
_PLAIN = {
    "does-not-hold": "fails",
    "not-established": "not decided",
    "indeterminate": "not decided",
    "proven": "shown",
    "possible": "open",
    "holds": "has",
    "mixed": "partly",
    "reachability": "forwarding",
    "reachable": "forwarded to",
    "reached": "arrived at",
    "delivered": "forwarded",
    "leg": "part",
}


def _plain(text: str) -> str:
    import re

    for word, replacement in _PLAIN.items():
        text = re.sub(rf"(?<![\w-]){re.escape(word)}(?![\w-])", replacement, text, flags=re.IGNORECASE)
    return text


def _bounded(items: list[str], separator: str) -> str:
    shown = separator.join(items[:_DETAIL_ITEMS])
    rest = len(items) - _DETAIL_ITEMS
    return f"{shown}{separator}and {rest} more" if rest > 0 else shown


def _family(af: int | None) -> str:
    return {4: "IPv4", 6: "IPv6"}.get(af or 0, "every family")


def _window_fact(code: str, window: Any) -> str:
    """What one observation window lacks, for the gap `code`."""
    if code == "clock-quality-uncertain":
        source = window.clock_source or "no clock source"
        assumption = window.clock_assumption or "no clock assumption"
        return (
            f"the collection clock is not declared trusted (clock quality {window.clock_quality.value}, "
            f"{source}, {assumption}); declare it with COLLECTOR_CLOCK_QUALITY=trusted and "
            "COLLECTOR_CLOCK_ASSUMPTION, or record the device clock"
        )
    if window.capture_start is None:
        return "the fetch start time of the collection is not recorded"
    if window.capture_end is None:
        return "the fetch finish time of the collection is not recorded"
    if window.observation_time is None:
        return "the observation time of the collection is not recorded"
    return "the collection has no capture window"


def _evidence_detail(code: str, evidence: EvidenceEvaluation | None, state: Any) -> str | None:
    """The device and the fact behind one evidence gap of a state. The text lists the
    sections per source and missing fact. The result is None when no gap matches."""
    if evidence is None or state is None:
        return None
    context = state.context
    windows = {(w.source, w.subject, w.section, w.address_family, w.vrf): w for w in evidence.windows}
    facts: dict[tuple[str, str, str], set[str]] = {}
    for gap in evidence.gaps:
        if (
            gap.code.value != code
            or gap.subject != context.firewall_instance
            or gap.address_family not in (None, context.address_family)
            or gap.vrf not in ("", context.vrf)
        ):
            continue
        window = windows.get((gap.source, gap.subject, gap.section, gap.address_family, gap.vrf))
        fact = _window_fact(code, window) if window is not None else (gap.detail or code)
        facts.setdefault((gap.subject, gap.source, fact), set()).add(gap.section)
    if not facts:
        return None
    parts = [
        f"{subject} (collected by {source}): {fact}, for the sections {_bounded(sorted(sections), ', ')}"
        for (subject, source, fact), sections in sorted(facts.items())
    ]
    return _plain(_bounded(parts, "; "))


def _gap_detail(record: Any, evidence: EvidenceEvaluation | None) -> dict[str, Any]:
    """The `gap_detail` key of a gap row, with what the row lacks in words. The result
    is empty for a terminal record and for a gap without detail."""
    code = getattr(record, "code", None)
    state = getattr(record, "state", None)
    text: str | None = None
    if code == "MODEL_SCOPE_INCOMPLETE" and (reasons := tuple(getattr(record, "reasons", ()))):
        where = (
            f"the routing of {state.context.vrf} ({_family(state.context.address_family)}) on "
            f"{state.context.firewall_instance}"
            if state is not None
            else "the routing"
        )
        text = _plain(f"{where} is not decided for this flow: {_bounded(sorted(set(reasons)), '; ')}")
    elif code in ("clock-quality-uncertain", "legacy-metadata-missing"):
        text = _evidence_detail(code, evidence, state)
    return {"gap_detail": text} if text else {}


def _evidence(before: SymbolicAnswer, after: SymbolicAnswer, limit: int = 100) -> dict[str, Any]:
    """One row per terminal and gap record. A record whose state ends at the estate's
    edge also has `left_estate` and its sentence (`left_estate_note`), as a row of
    `assessment.evaluation._evidence` does."""
    items: list[dict[str, Any]] = []
    observations: dict[str, Any] = {}
    count = 0
    for side, answer in (("before", before), ("after", after)):
        observation_index = ObservationIndex(answer.evidence)
        for name, result in answer.members.items():
            listed = [
                (
                    kind,
                    choice,
                    cast(Any, record),
                    f"{side}/member/{name}/choice/{index}/{kind}/{record_index}",
                    result,
                )
                for index, choice in enumerate(result.by_choice)
                for kind, records in (("terminal", choice.terminal_reaches), ("gap", choice.scoped_gaps))
                for record_index, record in enumerate(records)
            ]
            # The forward terminals of a round trip at the edge of the estate. Each row
            # uses the identity of the forward walk.
            listed += [
                ("terminal", choice, record, root, forward)
                for root, choice, record, forward in _forward_edges(f"{side}/member/{name}", result)
            ]
            for kind, choice, record, artifact_root, walked in listed:
                count += 1
                if len(items) >= limit:
                    continue
                observation_refs = observation_index.references(record.state)
                observations.update({key: observation_index.records[key] for key in observation_refs})
                items.append(
                    {
                        "side": side,
                        "member": name,
                        "kind": kind,
                        "choice": asdict(choice.assignment),
                        "state": asdict(record.state) if record.state is not None else None,
                        "outcome": getattr(record, "outcome", "unknown"),
                        "gap_code": getattr(record, "code", None),
                        "packet_scope": (
                            "conservative" if getattr(record, "conservative", False) else "exact"
                        ),
                        "observation_scope": "context",
                        "observation_refs": list(observation_refs),
                        "missing": [record.code] if kind == "gap" else [],
                        **_left_estate(record),
                        **(_gap_detail(record, answer.evidence) if kind == "gap" else {}),
                        "steps": [
                            {
                                "device_uid": (
                                    record.state.context.firewall_instance
                                    if record.state is not None
                                    else None
                                ),
                                "stage": record.state.stage if record.state is not None else "analysis",
                                "kind": kind,
                                "unknown": [record.code] if kind == "gap" else [],
                                "detail": (
                                    getattr(record, "code", None) or f"Recorded {record.outcome} terminal"
                                ),
                            }
                        ],
                        "artifact_root": artifact_root,
                        "manifest_sha256": walked.manifest_digest,
                        "model_fingerprint": walked.model_fingerprint,
                        "request_id": walked.request_id,
                    }
                )
    return {"count": count, "items": items, "truncated": count > len(items), "observations": observations}


def exact_evidence(before: SymbolicAnswer, after: SymbolicAnswer) -> dict[str, Any]:
    """Retain every terminal and gap reference associated with saved exact roots."""
    result = _evidence(before, after, limit=200_000)
    if result["truncated"]:
        raise ValueError("exact result evidence exceeds artifact root limit")
    return result


def _member_bounds(answer: SymbolicAnswer, result: WalkResult) -> Bounds[PacketSet]:
    population = answer.bounds.universe
    if not result.choices_complete:
        return Bounds.terminal(population, "unknown")
    return choices(
        population,
        tuple(
            for_all_requested_flows(
                item.bounds,
                population,
                lambda packets: packets.project(("source_address",), bank="original"),
            )
            for item in result.by_choice
        ),
        mode=answer.mode if answer.choice_mode is None else answer.choice_mode,
    )


def _member_rows(before: SymbolicAnswer, after: SymbolicAnswer) -> list[dict[str, Any]]:
    rows = []
    for name, result in before.members.items():
        left, right = _member_bounds(before, result), _member_bounds(after, after.members[name])
        lb, ub, la, ua = left.lower, left.upper, right.lower, right.upper
        unknown_before, unknown_after = ub.subtract(lb), ua.subtract(la)
        counts = {}
        for side, bounds in (("before", left), ("after", right)):
            counts[side] = {
                state: packets.cardinality(("source_address",), bank="original")
                for state, packets in (
                    (HOLDS, bounds.lower),
                    (FAILS, bounds.universe.subtract(bounds.upper)),
                    (NOT_ESTABLISHED, bounds.upper.subtract(bounds.lower)),
                )
            }
        rows.append(
            {
                "name": name,
                "proven_loss": not lb.subtract(ua).is_empty(),
                "possible_loss": not ub.subtract(la).is_empty(),
                "proven_gain": not la.subtract(ub).is_empty(),
                "possible_gain": not ua.subtract(lb).is_empty(),
                "triage": {
                    key: not value.is_empty()
                    for key, value in {
                        "proven_loss": lb.subtract(ua),
                        "worked_now_unknown": lb.intersect(unknown_after),
                        "unknown_now_broken": unknown_before.subtract(ua),
                        "unknown_throughout": unknown_before.intersect(unknown_after),
                        "proven_gain": la.subtract(ub),
                        "unknown_now_works": unknown_before.intersect(la),
                        "broken_now_unknown": unknown_after.subtract(ub),
                    }.items()
                },
                "count_unit": "client-addresses",
                **{
                    side: {state: value if value <= 2**53 - 1 else None for state, value in values.items()}
                    for side, values in counts.items()
                },
                "counts_decimal": {
                    side: {state: str(value) for state, value in values.items()}
                    for side, values in counts.items()
                },
            }
        )
    return rows


def gap_entries(answer: SymbolicAnswer) -> list[dict[str, Any]]:
    """The gaps of an answer, with each code once per device and context where
    the walk found it.

    The walk records every gap with the state where it found the gap
    (`WalkGap`). The context of the state holds the owning device and the
    forwarding context. A code the walk recorded with no state, or a code of the
    aggregation (`FORWARDING_CHOICES_INCOMPLETE`, `CAPACITY_DEMAND_NOT_MODELED`),
    is one entry with no subject. A device the model could not name
    (`_device_unknown_key`) is no subject either."""
    entries: dict[tuple[str, str | None, str | None], dict[str, Any]] = {}
    for result in answer.members.values():
        by_choice = [gap for choice in result.by_choice for gap in choice.scoped_gaps]
        scoped = by_choice or list(result.scoped_gaps)
        for gap in scoped:
            state = gap.state
            device = state.context.firewall_instance if state is not None else None
            subject = None if device in (None, "unknown") else device
            context_uid = state.context.vrf if state is not None else None
            key = (gap.code, subject, context_uid)
            if key in entries:
                continue
            entries[key] = {
                "kind": gap.code,
                "code": gap.code,
                "subject": subject,
                "context_uid": context_uid,
                "detail": f"{gap.code} at {state.location}" if state is not None else gap.code,
                "scope": "symbolic-set",
            }
    for code in answer.gaps:
        if not any(entry["code"] == code for entry in entries.values()):
            entries[(code, None, None)] = {
                "kind": code,
                "code": code,
                "subject": None,
                "context_uid": None,
                "detail": code,
                "scope": "symbolic-set",
            }
    return sorted(entries.values(), key=lambda e: (e["code"], e["subject"] or "", e["context_uid"] or ""))


def comparison(
    before: SymbolicAnswer, after: SymbolicAnswer, *, include_artifact: bool = True
) -> dict[str, Any]:
    roots = exact_roots(before, after)
    lb, ub, la, ua = before.lower, before.upper, after.lower, after.upper
    unknown_before, unknown_after = ub.subtract(lb), ua.subtract(la)
    triage = {
        "proven_loss": lb.subtract(ua),
        "worked_now_unknown": lb.intersect(unknown_after),
        "unknown_now_broken": unknown_before.subtract(ua),
        "unknown_throughout": unknown_before.intersect(unknown_after),
        "proven_gain": la.subtract(ub),
        "unknown_now_works": unknown_before.intersect(la),
        "broken_now_unknown": unknown_after.subtract(ub),
    }
    request = before.request_set
    from hst.assessment.request_document import service_fields

    result: dict[str, Any] = {
        "semantic_version": "symbolic-v2",
        "result_schema": 2,
        "mode": before.mode,
        "complete": before.complete and after.complete,
        "completion_status": "complete" if before.complete and after.complete else "incomplete",
        "units": {"population": "client-addresses", "display": "CIDR-prefixes"},
        "outcomes": {"before": outcome(before), "after": outcome(after)},
        "proven": {"loss": address_bucket(lb.subtract(ua)), "gain": address_bucket(la.subtract(ub))},
        "possible": {"loss": address_bucket(ub.subtract(la)), "gain": address_bucket(ua.subtract(lb))},
        "not_established": {"before": address_bucket(unknown_before), "after": address_bucket(unknown_after)},
        "condition_holds": {"before": address_bucket(lb), "after": address_bucket(la)},
        "condition_fails": {
            "before": address_bucket(roots["population"].subtract(ub)),
            "after": address_bucket(roots["population"].subtract(ua)),
        },
        "triage": {key: address_bucket(value) for key, value in triage.items()},
        "assumptions": sorted(set(before.assumptions) | set(after.assumptions)),
        "missing_evidence": sorted(set(before.gaps) | set(after.gaps)),
        "gaps": gap_entries(after),
        "model_errors": [],
        "members": _member_rows(before, after),
        "request": {
            "name": request.name,
            "destination": request.destination,
            "sources": address_bucket(before.bounds.universe),
            "members": [
                {
                    "name": member.name,
                    **service_fields(member.service),
                    "addresses": address_bucket(
                        before.members[member.name].bounds.universe, field="destination_address"
                    )["items"],
                    "address_summary": address_bucket(
                        before.members[member.name].bounds.universe, field="destination_address"
                    ),
                }
                for member in request.members
            ],
            "condition": asdict(request.condition),
            **service_fields(request.service),
            "requirement": None,
            "success": request.success,
            "source_context": request.source_context,
            "source_device_uid": request.source_device_uid,
            "identity_uid": request.identity_uid,
            "segment_uid": request.segment_uid,
            "ingress_interface_uid": request.ingress_interface_uid,
            "destination_context": request.destination_context,
            "header_constraints": {name: list(ranges) for name, ranges in request.header_constraints},
            **({"mtu": request.mtu.as_request().model_dump(mode="json")} if request.mtu else {}),
        },
        "evidence": _evidence(before, after),
        "symbolic": {
            "backend": "dd.cudd",
            "header_schema": lb.manager.schema.schema_version,
            "ordering_version": lb.manager.schema.ordering_version,
            "model_fingerprints": {
                side: {name: member.model_fingerprint for name, member in answer.members.items()}
                for side, answer in (("before", before), ("after", after))
            },
            "database_reads_during_walk": sum(
                member.database_reads for answer in (before, after) for member in answer.members.values()
            ),
        },
    }
    if include_artifact:
        artifact = encode_packet_sets(roots)
        result["symbolic"]["artifact_sha256"] = hashlib.sha256(artifact).hexdigest()
        result["symbolic"]["artifact"] = json.loads(artifact)
    return result
