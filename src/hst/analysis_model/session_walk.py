"""Bounded, per-choice forward and reply orchestration for compiled models."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace

from hst.impact.symbolic_walk import (
    DEFAULT_LIMITS,
    ChoiceResult,
    WalkGap,
    WalkLimits,
    WalkResult,
    walk,
    walk_bound,
)
from hst.policy.bounds import Bounds, ChoiceMode, choices
from hst.policy.ir import ExecutionContext
from hst.symbolic import PacketSet
from hst.symbolic.predicates import value_range

from .compile import AnalysisModel
from .model import ChoiceAssignment, StateKey
from .sessions import SessionCatalog


@dataclass(frozen=True, slots=True)
class SessionWalkResult:
    forward: WalkResult
    reply: WalkResult


def session_walk(
    forward_model: AnalysisModel,
    reply_model: AnalysisModel,
    request: PacketSet,
    *,
    request_id: str,
    catalog: SessionCatalog | None = None,
    binding_id: str | None = None,
    reply_context: ExecutionContext | None = None,
    requires_state: bool = False,
    mode: ChoiceMode = "unspecified",
    limits: WalkLimits = DEFAULT_LIMITS,
    cancelled: Callable[[], bool] | None = None,
    forward_result: WalkResult | None = None,
    entry_terminals: tuple[StateKey, ...] | None = None,
    edge_sources: Mapping[str, tuple[tuple[int, int, int], ...]] | None = None,
) -> SessionWalkResult:
    """Evaluate both directions with full fixed-point and joint-choice bounds.

    `entry_terminals` holds, for each entry of `reply_model` in the same
    order, the forward terminal whose packets that entry answers. With it,
    each reply is walked only from the entries of the terminal its forward
    packet ended at (`_reply_groups`). Without it, every reply is walked from
    every entry.

    An estate edge is a forward terminal with `left_estate`. `edge_sources`
    holds the addresses of each uplink interface, by uid. Where the forward
    path did not translate the packets of an estate edge to the address of
    the uplink, the outside decides by which uplink the reply returns. The
    reply is also walked from the entries of every other estate edge of the
    model (`_other_uplinks`, each one walked once per forward choice). The
    reply passes only where it passes from each such uplink. It fails only
    where it is blocked from each. Elsewhere it is not decided
    (`REPLY_RETURN_UPLINK_UNDECIDED`, one gap at each uplink that disagrees
    with its own).

    The result of the reply holds the forward walk in `WalkResult.forward`."""
    if catalog is not None or binding_id is not None or reply_context is not None:
        raise ValueError("session bindings must be installed in the owner-qualified reply model")
    _ = requires_state  # Forward proof establishes ordinary connection state.
    forward = forward_result or walk(
        forward_model,
        request,
        request_id=request_id,
        mode=mode,
        limits=limits,
        cancelled=cancelled,
    )
    if forward.request_id != request_id or forward.model_fingerprint != forward_model.fingerprint:
        raise ValueError("forward result does not belong to this request and model")
    manager = request.manager
    original = request.rename(from_bank="current", to_bank="original")
    results: list[ChoiceResult] = []
    reply_states = reply_steps = 0
    for forward_choice in forward.by_choice:
        permitted = manager.empty()
        for terminal in forward_choice.terminal_reaches:
            if terminal.outcome == "permit":
                permitted = permitted.union(terminal.packets.intersect(forward_choice.bounds.lower))
        assignments = _reply_assignments(reply_model, forward_choice.assignment)
        if permitted.is_empty() or not assignments:
            upper = forward_choice.bounds.upper
            if upper.is_empty():
                results.append(
                    ChoiceResult(
                        forward_choice.assignment,
                        Bounds(original, manager.empty(), manager.empty()),
                        forward_choice.complete,
                        forward_choice.outcomes,
                        forward_choice.gap_refs,
                    )
                )
            else:
                code = "REPLY_CHOICE_SCOPE_MISMATCH" if not assignments else "FORWARD_NOT_PROVEN"
                # The result of a forward part that is not decided holds the gap
                # refs and the scoped gaps of the forward choice beside
                # `FORWARD_NOT_PROVEN`.
                carried = forward_choice if code == "FORWARD_NOT_PROVEN" else None
                results.append(
                    ChoiceResult(
                        forward_choice.assignment,
                        Bounds(original, manager.empty(), upper),
                        False,
                        (("unknown", upper),),
                        tuple(sorted({code, *(carried.gap_refs if carried else ())})),
                        (
                            WalkGap(code, upper, forward_choice.assignment),
                            *(carried.scoped_gaps if carried else ()),
                        ),
                    )
                )
            continue
        groups = _reply_groups(reply_model, forward_choice, entry_terminals)
        originals = [
            forward_choice.bounds.lower
            if model is reply_model and len(groups) == 1
            else part.project(manager.schema.field_names, bank="original").intersect(
                forward_choice.bounds.lower
            )
            for model, part, _state in groups
        ]

        # The reversed tuple is computed once per forward choice.
        reversed_all = _reverse_current(permitted)
        whole = len(groups) == 1 and groups[0][0] is reply_model

        def reply_walk(
            model: AnalysisModel,
            universe: PacketSet,
            assignments: tuple[ChoiceAssignment, ...] = assignments,
            reversed_all: PacketSet = reversed_all,
            whole: bool = whole,
        ) -> WalkResult:
            return walk_bound(
                model,
                reversed_all if whole else reversed_all.intersect(universe),
                universe,
                request_id=f"{request_id}:reply",
                assignments=assignments,
                mode="unspecified",
                limits=limits,
                cancelled=cancelled,
            )

        walked = [
            reply_walk(model, universe)
            for (model, _part, _state), universe in zip(groups, originals, strict=True)
        ]
        reply_lower, reply_upper = manager.empty(), manager.empty()
        return_gaps: list[WalkGap] = []
        # `returns` holds the other uplinks that the reply of each group may
        # return by. Each uplink is walked once per forward choice with the
        # packets of every group that needs it.
        returns = [
            _other_uplinks(reply_model, forward_model, state, part, entry_terminals, edge_sources or {})
            for _model, part, state in groups
        ]
        by_uplink: dict[StateKey, tuple[AnalysisModel, PacketSet]] = {}
        for found, universe in zip(returns, originals, strict=True):
            for other, other_model in found:
                packets = by_uplink[other][1].union(universe) if other in by_uplink else universe
                by_uplink[other] = (other_model, packets)
        elsewhere: dict[StateKey, WalkResult] = {}
        for other, (other_model, packets) in by_uplink.items():
            elsewhere[other] = reply_walk(other_model, packets)
            reply_states += elsewhere[other].states
            reply_steps += elsewhere[other].steps
        for found, universe, reply in zip(returns, originals, walked, strict=True):
            reply_states += reply.states
            reply_steps += reply.steps
            lower, upper = reply.bounds.lower, reply.bounds.upper
            # The outside decides by which of these uplinks the reply returns.
            # The reply passes only where it passes from each uplink. It fails
            # only where it is blocked from each uplink.
            for other, _other_model in found:
                other_lower = elsewhere[other].bounds.lower.intersect(universe)
                other_upper = elsewhere[other].bounds.upper.intersect(universe)
                disagree = (
                    reply.bounds.lower.subtract(other_lower)
                    .union(other_lower.subtract(reply.bounds.lower))
                    .union(reply.bounds.upper.subtract(other_upper))
                    .union(other_upper.subtract(reply.bounds.upper))
                )
                if not disagree.is_empty():
                    return_gaps.append(
                        WalkGap("REPLY_RETURN_UPLINK_UNDECIDED", disagree, forward_choice.assignment, other)
                    )
                lower = lower.intersect(other_lower)
                upper = upper.union(other_upper)
            reply_lower = reply_lower.union(lower)
            reply_upper = reply_upper.union(upper)
        # A forward packet that ended at 2 terminals is decided only by both
        # replies. The union of the lower bounds is sound only where the groups
        # are disjoint. The overlap of the groups is not decided. It leaves the
        # lower bound and stays in the upper bound.
        shared = _overlap(originals, manager.empty())
        reply_lower = reply_lower.subtract(shared)
        reply_upper = reply_upper.union(shared)
        # The reply takes any of its own choices that the forward choice leaves
        # open. `walk_bound` holds the bounds of the reply only where all of
        # these choices agree.
        items = tuple(item for reply in walked for item in reply.by_choice)
        outcomes: dict[str, PacketSet] = {}
        for item in items:
            for name, region in item.outcomes:
                outcomes[name] = outcomes[name].union(region) if name in outcomes else region
        unknown_forward = forward_choice.bounds.upper.subtract(forward_choice.bounds.lower)
        combined = Bounds(
            original,
            forward_choice.bounds.lower.intersect(reply_lower),
            forward_choice.bounds.upper.intersect(reply_upper.union(unknown_forward)),
        )
        results.append(
            ChoiceResult(
                forward_choice.assignment,
                combined,
                all(reply.complete for reply in walked) and not return_gaps,
                tuple(outcomes.items()),
                tuple(
                    sorted(
                        {code for reply in walked for code in reply.gap_refs}
                        | {gap.code for gap in return_gaps}
                    )
                ),
                (*(gap for item in items for gap in item.scoped_gaps), *return_gaps),
                tuple(reach for item in items for reach in item.terminal_reaches),
            )
        )
    reply_result = _aggregate(
        reply_model,
        request_id,
        original,
        tuple(results),
        mode,
        states=reply_states,
        steps=reply_steps,
    )
    return SessionWalkResult(forward, replace(reply_result, forward=forward))


def _reply_groups(
    reply_model: AnalysisModel,
    forward_choice: ChoiceResult,
    entry_terminals: tuple[StateKey, ...] | None,
) -> list[tuple[AnalysisModel, PacketSet, StateKey | None]]:
    """Return the reply walks that one forward choice needs.

    Each item holds the reply model, the forward packets whose reply it walks
    and their forward terminal. The terminal is None for one walk of all
    replies. Each forward permit terminal gets the model restricted to the
    entries of that terminal and the packets that ended there. A missing
    `entry_terminals`, or one that does not match the entries of the model,
    gives one walk of every reply from every entry. A terminal with no entry
    of its own keeps every entry. A terminal that owns every entry walks the
    model itself."""
    lower = forward_choice.bounds.lower
    by_state: dict[StateKey, PacketSet] = {}
    for terminal in forward_choice.terminal_reaches:
        if terminal.outcome == "permit":
            part = terminal.packets.intersect(lower)
            by_state[terminal.state] = (
                by_state[terminal.state].union(part) if terminal.state in by_state else part
            )
    if entry_terminals is None or len(entry_terminals) != len(reply_model.entries):
        permitted = None
        for part in by_state.values():
            permitted = part if permitted is None else permitted.union(part)
        return [(reply_model, permitted, None)] if permitted is not None else []
    groups: list[tuple[AnalysisModel, PacketSet, StateKey | None]] = []
    for state, part in by_state.items():
        if part.is_empty():
            continue
        entries = tuple(
            entry for entry, owner in zip(reply_model.entries, entry_terminals, strict=True) if owner == state
        )
        whole = not entries or len(entries) == len(reply_model.entries)
        groups.append((reply_model if whole else replace(reply_model, entries=entries), part, state))
    return groups


def _uplink_of(state: StateKey) -> str | None:
    """The interface an estate edge terminal leaves by (its `reply-ingress`)."""
    return next(
        (v.removeprefix("reply-ingress:") for v in state.binding_scope if v.startswith("reply-ingress:")),
        None,
    )


def _translated(part: PacketSet, ranges: tuple[tuple[int, int, int], ...]) -> bool:
    """Return whether every packet of `part` leaves with a source in `ranges`,
    the addresses of the uplink.

    A source NAT to the address of the uplink and an interface-bound
    masquerade give True. An empty `ranges` gives False."""
    if not ranges:
        return False
    manager = part.manager
    held = manager.empty()
    for af, low, high in ranges:
        if af == manager.schema.address_family:
            held = held.union(value_range(manager, "source_address", low, high, bank="current"))
    return not held.is_empty() and part.subtract(held).is_empty()


def _other_uplinks(
    reply_model: AnalysisModel,
    forward_model: AnalysisModel,
    state: StateKey | None,
    part: PacketSet,
    entry_terminals: tuple[StateKey, ...] | None,
    edge_sources: Mapping[str, tuple[tuple[int, int, int], ...]],
) -> list[tuple[StateKey, AnalysisModel]]:
    """Return the other estate edges that a reply of `part` may return by.

    `part` left by the edge `state`. The result is empty when `state` is no
    estate edge, when the forward path translated the source to the address
    of the uplink, or when the model has one estate edge. Otherwise the
    result holds each other edge terminal of the model with its own reply
    entries."""
    if state is None or entry_terminals is None or len(entry_terminals) != len(reply_model.entries):
        return []
    edges = {node.key for node in forward_model.nodes if node.left_estate}
    if state not in edges:
        return []
    uplink = _uplink_of(state)
    if uplink is not None and _translated(part, tuple(edge_sources.get(uplink, ()))):
        return []
    others: list[tuple[StateKey, AnalysisModel]] = []
    for other in dict.fromkeys(entry_terminals):
        if other == state or other not in edges or _uplink_of(other) == uplink:
            continue
        entries = tuple(
            entry for entry, owner in zip(reply_model.entries, entry_terminals, strict=True) if owner == other
        )
        others.append((other, replace(reply_model, entries=entries)))
    return others


def _overlap(parts: list[PacketSet], empty: PacketSet) -> PacketSet:
    """Return the packets that 2 or more of `parts` share, or `empty` for fewer than 2 parts."""
    if len(parts) < 2:
        return empty
    seen, shared = parts[0], empty
    for part in parts[1:]:
        shared = shared.union(seen.intersect(part))
        seen = seen.union(part)
    return shared


def _aggregate(
    model: AnalysisModel,
    request_id: str,
    universe: PacketSet,
    results: tuple[ChoiceResult, ...],
    mode: ChoiceMode,
    *,
    states: int,
    steps: int,
) -> WalkResult:
    complete = model.choices_complete and bool(results)
    bounds = choices(universe, tuple(result.bounds for result in results), mode=mode)
    gaps = {gap for result in results for gap in result.gap_refs}
    if not complete:
        bounds = Bounds.terminal(universe, "unknown")
        gaps.add("FORWARDING_CHOICES_INCOMPLETE")
    undecided = bounds.upper.subtract(bounds.lower)
    scoped = tuple(
        replace(gap, packets=scope)
        for result in results
        for gap in result.scoped_gaps
        if not (scope := gap.packets.intersect(undecided)).is_empty()
    )
    return WalkResult(
        model.manifest_digest,
        model.fingerprint,
        f"{request_id}:reply",
        bounds,
        results,
        complete,
        complete and all(result.complete for result in results),
        tuple(sorted(gaps)),
        states,
        steps,
        scoped_gaps=scoped,
    )


def _reply_assignments(model: AnalysisModel, forward: ChoiceAssignment) -> tuple[ChoiceAssignment, ...]:
    """Return the assignments of the reply model that a forward choice allows.

    The result is the one assignment with the same bindings, if it exists.
    Otherwise the result holds every assignment that agrees with the forward
    choice on the scopes that both bind."""
    exact = [candidate for candidate in model.choices if candidate.bindings == forward.bindings]
    if len(exact) == 1:
        return (exact[0],)
    return tuple(candidate for candidate in model.choices if _compatible(forward, candidate))


def _compatible(left: ChoiceAssignment, right: ChoiceAssignment) -> bool:
    values = dict(left.bindings)
    return all(scope not in values or values[scope] == selected for scope, selected in right.bindings)


def _reverse_current(packets: PacketSet) -> PacketSet:
    """Swap the source and the destination address and port in the current bank.

    The original bank is unchanged. The fields `tcp_flags`, `icmp_type`,
    `icmp_code`, `fragment_offset` and `more_fragments` of the current bank
    are forgotten."""
    manager, schema = packets.manager, packets.manager.schema
    generated = {"tcp_flags", "icmp_type", "icmp_code", "fragment_offset", "more_fragments"}
    forgotten = {variable for field in generated for variable in schema.bits("current", field)}
    node = manager._bdd.exist(forgotten, packets._node)
    swapped = {
        "source_address": "destination_address",
        "destination_address": "source_address",
        "source_port": "destination_port",
        "destination_port": "source_port",
    }
    permutation: dict[str, str] = {}
    for field, peer in swapped.items():
        permutation.update(zip(schema.bits("current", field), schema.bits("current", peer), strict=True))
    known = packets.known_fields - generated
    return manager._wrap(manager._bdd.let(permutation, node), known)
