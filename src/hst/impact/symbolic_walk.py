"""A relational worklist with evidence bounds and explicit choices. It reads no database.

Forward reachability retains original/current pairs. Least fixed points establish
possible success and certain terminating success. A greatest fixed point
identifies feasible infinite forwarding. A repeated worklist key alone is not a loop.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace

from hst.analysis_model.compile import AnalysisModel, CompiledEdge
from hst.analysis_model.model import ChoiceAssignment, ExitRecord, StateKey
from hst.policy.bounds import Bounds, ChoiceMode, choices
from hst.symbolic import PacketSet
from hst.symbolic.relations import initial_relation


@dataclass(frozen=True, slots=True)
class WalkLimits:
    max_states: int = 250_000
    max_steps: int = 1_000_000
    max_seconds: float = 600.0

    def __post_init__(self) -> None:
        import math

        if any(
            isinstance(n, bool) or not isinstance(n, int) or n < 1 for n in (self.max_states, self.max_steps)
        ):
            raise ValueError("state and step limits must be positive integers")
        if isinstance(self.max_seconds, bool) or not math.isfinite(self.max_seconds) or self.max_seconds <= 0:
            raise ValueError("time limit must be finite and positive")


@dataclass(frozen=True, slots=True)
class WalkGap:
    code: str
    packets: PacketSet
    assignment: ChoiceAssignment | None
    state: StateKey | None = None
    conservative: bool = True
    # The `left_estate` of the state (`NodeSpec.left_estate`). The walk does not read it.
    left_estate: tuple[ExitRecord, ...] = ()
    # The `incomplete_reasons` of the state, for MODEL_SCOPE_INCOMPLETE. The walk does not read them.
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TerminalReach:
    state: StateKey
    outcome: str
    packets: PacketSet
    # The `left_estate` of the state (`NodeSpec.left_estate`). The walk does not read it.
    left_estate: tuple[ExitRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class ChoiceResult:
    assignment: ChoiceAssignment
    bounds: Bounds[PacketSet]
    complete: bool
    outcomes: tuple[tuple[str, PacketSet], ...]
    gap_refs: tuple[str, ...]
    scoped_gaps: tuple[WalkGap, ...] = ()
    terminal_reaches: tuple[TerminalReach, ...] = ()


@dataclass(frozen=True, slots=True)
class WalkResult:
    manifest_digest: str
    model_fingerprint: str
    request_id: str
    bounds: Bounds[PacketSet]
    by_choice: tuple[ChoiceResult, ...]
    choices_complete: bool
    complete: bool
    gap_refs: tuple[str, ...]
    states: int
    steps: int
    database_reads: int = 0
    scoped_gaps: tuple[WalkGap, ...] = ()
    # The forward walk of a reply walk (`session_walk`). None for a forward walk.
    forward: WalkResult | None = None


DEFAULT_LIMITS = WalkLimits()


class _LimitReached(Exception):
    pass


class _Budget:
    def __init__(self, limits: WalkLimits, cancelled: Callable[[], bool] | None):
        self.limits, self.cancelled = limits, cancelled
        self.deadline = time.monotonic() + limits.max_seconds
        self.steps = self.states = 0

    def check(self, *, state: bool = False) -> None:
        if self.cancelled is not None and self.cancelled():
            raise _LimitReached("ANALYSIS_CANCELLED")
        if time.monotonic() >= self.deadline:
            raise _LimitReached("ANALYSIS_TIME_LIMIT")
        if state:
            if self.states >= self.limits.max_states:
                raise _LimitReached("ANALYSIS_STATE_LIMIT")
            self.states += 1
        else:
            if self.steps >= self.limits.max_steps:
                raise _LimitReached("ANALYSIS_STEP_LIMIT")
            self.steps += 1


def _enabled(requirements: tuple[tuple[str, str], ...], assignment: ChoiceAssignment) -> bool:
    values = dict(assignment.bindings)
    return all(values.get(scope) == selected for scope, selected in requirements)


def _original(packets: PacketSet, request: PacketSet) -> PacketSet:
    return packets.project(packets.manager.schema.field_names, bank="original").intersect(request)


class _Walked:
    """The results of walks already made, by the choice values they read.

    A walk reads an assignment only where an entry or an edge of a state it
    entered names a choice scope. Two assignments that agree on those scopes
    give the same walk."""

    def __init__(self) -> None:
        self.items: list[tuple[tuple[str, ...], tuple[str | None, ...], ChoiceResult]] = []

    def get(self, assignment: ChoiceAssignment) -> ChoiceResult | None:
        values = dict(assignment.bindings)
        for scopes, read, result in self.items:
            if tuple(values.get(scope) for scope in scopes) == read:
                return replace(
                    result,
                    assignment=assignment,
                    scoped_gaps=tuple(replace(gap, assignment=assignment) for gap in result.scoped_gaps),
                )
        return None

    def add(self, scopes: frozenset[str], result: ChoiceResult) -> None:
        ordered = tuple(sorted(scopes))
        values = dict(result.assignment.bindings)
        self.items.append((ordered, tuple(values.get(scope) for scope in ordered), result))


def _one_choice(
    model: AnalysisModel,
    request: PacketSet,
    assignment: ChoiceAssignment,
    budget: _Budget,
    *,
    bound_request: PacketSet | None = None,
    original_request: PacketSet | None = None,
) -> tuple[ChoiceResult, frozenset[str]]:
    """The walk under one assignment, and the choice scopes it read."""
    manager = request.manager
    empty = manager.empty()
    if original_request is None:
        original_request = request.rename(from_bank="current", to_bank="original")
    nodes = {node.key: node for node in model.nodes}
    active: dict[StateKey, tuple[CompiledEdge, ...]] = {}
    terminals: dict[StateKey, dict[str, PacketSet]] = {}
    for node in model.nodes:
        budget.check()
        outgoing = tuple(edge for edge in node.edges if _enabled(edge.choices, assignment))
        active[node.key] = outgoing
        outcomes = dict.fromkeys(("permit", "deny", "no_route", "unknown"), empty)
        for terminal_name, region in node.terminals:
            outcomes[terminal_name] = outcomes[terminal_name].union(region)
        covered = empty
        for region in outcomes.values():
            covered = covered.union(region)
        for edge in outgoing:
            covered = covered.union(edge.guard).union(edge.uncertain)
            outcomes["unknown"] = outcomes["unknown"].union(edge.uncertain)
        missing = model.universe.subtract(covered)
        fallback = "no_route" if node.complete else "unknown"
        outcomes[fallback] = outcomes[fallback].union(missing)
        terminals[node.key] = outcomes
    reached: dict[StateKey, PacketSet] = {}
    pending: deque[tuple[StateKey, PacketSet]] = deque()
    starts: dict[StateKey, PacketSet] = {}
    unknown_attachment = empty
    if bound_request is None:
        bound_request = initial_relation(request)
    gaps: set[str] = set()

    def enqueue(key: StateKey, packets: PacketSet) -> None:
        if packets.is_empty():
            return
        previous = reached.get(key, empty)
        delta = packets.subtract(previous)
        if delta.is_empty():
            return
        if key not in reached:
            budget.check(state=True)
        reached[key] = previous.union(delta)
        pending.append((key, delta))

    for entry in model.entries:
        if _enabled(entry.choices, assignment):
            initial = bound_request.intersect(entry.guard)
            starts[entry.key] = starts.get(entry.key, empty).union(initial)
            unknown_attachment = unknown_attachment.union(bound_request.intersect(entry.uncertain))
            enqueue(entry.key, initial)
    while pending:
        budget.check()
        key, delta = pending.popleft()
        gaps.update(nodes[key].gap_refs)
        for edge in active[key]:
            successor = edge.relation.image(delta.intersect(edge.guard))
            enqueue(edge.target, successor)
    # All calculations below are restricted to the reached relation, the recurrent set included.
    may = {
        key: packets.intersect(terminals[key]["permit"].union(terminals[key]["unknown"]))
        for key, packets in reached.items()
    }
    must = dict.fromkeys(reached, empty)
    recurrent = dict(reached)
    predecessors: dict[StateKey, set[StateKey]] = {key: set() for key in reached}
    for key in reached:
        for edge in active[key]:
            if edge.target in reached:
                predecessors[edge.target].add(key)
    work = deque(reversed(tuple(reached)))
    queued = set(reached)
    while work:
        key = work.popleft()
        queued.remove(key)
        packets = reached[key]
        budget.check()
        outcomes = terminals[key]
        possible = packets.intersect(outcomes["permit"].union(outcomes["unknown"]))
        bad = packets.intersect(outcomes["deny"].union(outcomes["no_route"]).union(outcomes["unknown"]))
        looping = empty
        for edge in active[key]:
            target = reached.get(edge.target, empty)
            scope = packets.intersect(edge.guard)
            possible = possible.union(scope.intersect(edge.relation.preimage(may.get(edge.target, empty))))
            bad = bad.union(
                scope.intersect(edge.relation.preimage(target.subtract(must.get(edge.target, empty))))
            )
            looping = looping.union(
                scope.intersect(edge.relation.preimage(recurrent.get(edge.target, empty)))
            )
        certain = packets.subtract(bad)
        changed = (
            not possible.equivalent(may[key])
            or not certain.equivalent(must[key])
            or not looping.equivalent(recurrent[key])
        )
        may[key], must[key], recurrent[key] = possible, certain, looping
        if changed:
            for predecessor in predecessors[key]:
                if predecessor not in queued:
                    queued.add(predecessor)
                    work.append(predecessor)
    attached, successes, failures = empty, empty, empty
    for key, start in starts.items():
        attached = attached.union(_original(start, original_request))
        successes = successes.union(_original(start.intersect(may.get(key, empty)), original_request))
        failures = failures.union(_original(start.subtract(must.get(key, empty)), original_request))
    missing_attachment = original_request.subtract(attached).union(
        _original(unknown_attachment, original_request)
    )
    if not missing_attachment.is_empty():
        gaps.add("SOURCE_ATTACHMENT_UNKNOWN")
    lower = original_request.subtract(failures).subtract(missing_attachment)
    upper = successes.union(missing_attachment)
    summary = dict.fromkeys(("permit", "deny", "no_route", "unknown", "loop"), empty)
    for key, packets in reached.items():
        for name, region in terminals[key].items():
            summary[name] = summary[name].union(_original(packets.intersect(region), original_request))
        summary["loop"] = summary["loop"].union(_original(recurrent[key], original_request))
    summary["unknown"] = summary["unknown"].union(missing_attachment)
    if not summary["unknown"].is_empty():
        gaps.add("MODEL_OUTCOME_UNKNOWN")
    scoped: list[WalkGap] = []
    terminal_reaches: list[TerminalReach] = []
    for key, packets in reached.items():
        exits = nodes[key].left_estate
        for code in nodes[key].gap_refs:
            scoped.append(
                WalkGap(
                    code,
                    _original(packets, original_request),
                    assignment,
                    key,
                    left_estate=exits,
                    reasons=nodes[key].incomplete_reasons if code == "MODEL_SCOPE_INCOMPLETE" else (),
                )
            )
        unknown_scope = _original(packets.intersect(terminals[key]["unknown"]), original_request)
        if not unknown_scope.is_empty():
            scoped.append(WalkGap("MODEL_OUTCOME_UNKNOWN", unknown_scope, assignment, key, left_estate=exits))
        for outcome, region in terminals[key].items():
            terminal = packets.intersect(region)
            if not terminal.is_empty():
                terminal_reaches.append(TerminalReach(key, outcome, terminal, exits))
    if not missing_attachment.is_empty():
        scoped.append(WalkGap("SOURCE_ATTACHMENT_UNKNOWN", missing_attachment, assignment))
    read = frozenset(
        scope
        for requirements in (
            *(entry.choices for entry in model.entries),
            *(edge.choices for key in reached for edge in nodes[key].edges),
        )
        for scope, _selected in requirements
    )
    return ChoiceResult(
        assignment,
        Bounds(original_request, lower, upper),
        True,
        tuple(summary.items()),
        tuple(sorted(gaps)),
        tuple(scoped),
        tuple(terminal_reaches),
    ), read


def walk(
    model: AnalysisModel,
    request: PacketSet,
    *,
    request_id: str,
    mode: ChoiceMode = "unspecified",
    limits: WalkLimits = DEFAULT_LIMITS,
    cancelled: Callable[[], bool] | None = None,
) -> WalkResult:
    """Evaluate a model. The request has current-bank coordinates.

    The results have original-bank coordinates. `complete` is true when the traversal converged.
    """
    if not request_id:
        raise ValueError("request identity is required")
    manager = model.universe.manager
    manager._assert_sets(request)
    if request.known_fields != model.universe.known_fields:
        raise ValueError("request knowledge mask differs from compiled model")
    if not request.subtract(model.universe).is_empty():
        raise ValueError("request is outside the model's valid header universe")
    # A fresh request may not contain hidden original/next constraints.
    current_only = request.project(manager.schema.field_names)
    if not current_only.equivalent(request):
        raise ValueError("walk expects current-bank request predicates only")
    universe = request.rename(from_bank="current", to_bank="original")
    budget = _Budget(limits, cancelled)
    results: list[ChoiceResult] = []
    gaps: set[str] = set()
    walked = _Walked()
    for assignment in model.choices:
        try:
            if (result := walked.get(assignment)) is None:
                result, read = _one_choice(model, request, assignment, budget)
                walked.add(read, result)
        except _LimitReached as exc:
            code = str(exc)
            result = ChoiceResult(
                assignment,
                Bounds.terminal(universe, "unknown"),
                False,
                (("unknown", universe),),
                (code,),
                (WalkGap(code, universe, assignment),),
            )
        results.append(result)
        gaps.update(result.gap_refs)
    bounds = choices(universe, tuple(result.bounds for result in results), mode=mode)
    if not model.choices_complete or not results:
        bounds = Bounds.terminal(universe, "unknown")
        gaps.add("FORWARDING_CHOICES_INCOMPLETE")
    undecided = bounds.upper.subtract(bounds.lower)
    scoped_gaps = tuple(
        replace(gap, packets=scope)
        for result in results
        for gap in result.scoped_gaps
        if not (scope := gap.packets.intersect(undecided)).is_empty()
    )
    if not model.choices_complete or not results:
        scoped_gaps += (WalkGap("FORWARDING_CHOICES_INCOMPLETE", universe, None),)
    return WalkResult(
        model.manifest_digest,
        model.fingerprint,
        request_id,
        bounds,
        tuple(results),
        model.choices_complete,
        all(result.complete for result in results),
        tuple(sorted(gaps)),
        budget.states,
        budget.steps,
        scoped_gaps=scoped_gaps,
    )


def walk_bound(
    model: AnalysisModel,
    bound_request: PacketSet,
    original_request: PacketSet,
    *,
    request_id: str,
    assignments: tuple[ChoiceAssignment, ...] | None = None,
    mode: ChoiceMode = "unspecified",
    limits: WalkLimits = DEFAULT_LIMITS,
    cancelled: Callable[[], bool] | None = None,
) -> WalkResult:
    """Evaluate a correlated original/current request relation.

    This is the entry point of the reply session. The forward request stays in the original bank.
    """
    if not request_id:
        raise ValueError("request identity is required")
    manager = model.universe.manager
    manager._assert_sets(bound_request, original_request)
    selected = assignments if assignments is not None else model.choices
    if any(assignment not in model.choices for assignment in selected):
        raise ValueError("bound walk assignments must belong to the model")
    budget = _Budget(limits, cancelled)
    results: list[ChoiceResult] = []
    gaps: set[str] = set()
    # `request` supplies the knowledge mask and the manager. `_one_choice`
    # applies the entry guards to `bound_request`.
    request = bound_request.project(manager.schema.field_names, bank="current")
    walked = _Walked()
    for assignment in selected:
        try:
            if (result := walked.get(assignment)) is None:
                result, read = _one_choice(
                    model,
                    request,
                    assignment,
                    budget,
                    bound_request=bound_request,
                    original_request=original_request,
                )
                walked.add(read, result)
        except _LimitReached as exc:
            code = str(exc)
            result = ChoiceResult(
                assignment,
                Bounds.terminal(original_request, "unknown"),
                False,
                (("unknown", original_request),),
                (code,),
                (WalkGap(code, original_request, assignment),),
            )
        results.append(result)
        gaps.update(result.gap_refs)
    bounds = choices(original_request, tuple(item.bounds for item in results), mode=mode)
    complete_choices = model.choices_complete and bool(results)
    if not complete_choices:
        bounds = Bounds.terminal(original_request, "unknown")
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
        request_id,
        bounds,
        tuple(results),
        complete_choices,
        all(result.complete for result in results),
        tuple(sorted(gaps)),
        budget.states,
        budget.steps,
        scoped_gaps=scoped,
    )
