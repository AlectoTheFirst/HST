"""The search of repair proposals in the order of their lexicographic lower cost bounds."""

from __future__ import annotations

import heapq
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict
from math import comb
from typing import Any

from hst.assessment.search import FAILS, HOLDS, UNKNOWN, SearchLimits, verdict

COST_DIMENSIONS = ("devices", "newly_permitted_scope", "rule_edits")


def ordered_repairs(
    generated: Mapping[str, Any],
    oracle: Callable[[list[dict[str, Any]]], Mapping[str, Any]],
    cost_oracle: Callable[[list[dict[str, Any]]], Mapping[str, Any]],
    limits: SearchLimits,
    cost_order: Sequence[str],
    cancelled: Callable[[], bool] | None,
) -> dict[str, Any]:
    """Search the candidate subsets in the order of their lower cost bounds.

    The scope cost is not monotone in the subset. A subset enters the heap with
    the scope lower bound 0. Its parent in the subset tree is the subset without
    its greatest candidate. A popped subset first pushes its children and then
    measures its own scope with `cost_oracle`. The subset enters the heap again
    with the measured lower bound, and `oracle` evaluates its constraints when
    it is popped again. A cost with unequal bounds stays an interval, and its
    finding has no `minimum_cost` claim. Each call of `oracle` and of
    `cost_oracle` counts against `limits.max_evaluations`. The callers bound
    the engine calls and the baseline work of the oracles.
    """
    if len(cost_order) != 3 or set(cost_order) != set(COST_DIMENSIONS):
        raise ValueError("cost_order must be a permutation of devices, newly_permitted_scope, rule_edits")
    by_id = {candidate["id"]: candidate for candidate in generated["candidates"]}
    if len(by_id) != len(generated["candidates"]):
        raise ValueError("candidate identifiers must be unique")
    all_ids = sorted(by_id)
    ids = all_ids[: limits.max_candidates]
    size = min(len(ids), limits.max_combination_size)
    count = sum(comb(len(ids), n) for n in range(size + 1))
    started = time.monotonic()
    calls = 0
    serial = 0
    heap: list[tuple[tuple[int, ...], int, int, tuple[int, ...], dict[str, Any]]] = []
    trials: list[dict[str, Any]] = []
    costs: list[dict[str, Any]] = []
    reason = "complete"
    frontier_truncated = False

    def measure(group: tuple[int, ...], scope: int) -> tuple[int, ...]:
        selected = [by_id[ids[index]] for index in group]
        values = {
            "devices": len({c["device"] for c in selected}),
            "rule_edits": sum(len(c["intents"]) for c in selected),
            "newly_permitted_scope": scope,
        }
        return tuple(values[name] for name in cost_order)

    def push(stage: int, group: tuple[int, ...], payload: dict[str, Any]) -> None:
        nonlocal serial, frontier_truncated
        # The heap holds at most 10000 entries for any count of subsets.
        if len(heap) >= 10000:
            frontier_truncated = True
            return
        serial += 1
        heapq.heappush(heap, (measure(group, payload.get("lower", 0)), stage, serial, group, payload))

    push(0, (), {})
    while heap:
        if cancelled and cancelled():
            reason = "cancelled"
            break
        if time.monotonic() - started >= limits.max_seconds:
            reason = "time-limit"
            break
        if calls >= limits.max_evaluations:
            reason = "evaluation-limit"
            break
        lower_key, stage, _, group, bounds = heapq.heappop(heap)
        selected = [by_id[ids[index]] for index in group]
        intents = [intent for c in selected for intent in c["intents"]]
        candidate_ids = [ids[index] for index in group]
        if stage == 0:
            if len(group) < size:
                for index in range(group[-1] + 1 if group else 0, len(ids)):
                    push(0, (*group, index), {})
            changed: set[tuple[str, str]] = set()
            invalid = None
            for candidate in selected:
                if any(
                    generated["allowed_targets"].get(intent["params"].get("rulebase")) != candidate["device"]
                    for intent in candidate["intents"]
                ):
                    invalid = "candidate-device-does-not-match-allowed-target"
            for intent in intents:
                params = intent["params"]
                if (
                    params.get("rulebase") not in generated["allowed_targets"]
                    or intent["kind"] not in generated["allowed_kinds"]
                ):
                    invalid = "outside-allowed-targets-or-kinds"
                if params.get("rule"):
                    key = (params["rulebase"], params["rule"])
                    if key in changed:
                        invalid = "conflicting-edits-to-one-rule"
                    changed.add(key)
            if invalid:
                trials.append(
                    {
                        "candidates": candidate_ids,
                        "verdict": FAILS,
                        "evaluation": {"verdict": FAILS, "reason": invalid},
                        "cost_lower": list(lower_key),
                        "cost_upper": None,
                    }
                )
                continue
            calls += 1
            bounds = dict(cost_oracle(intents))
            lo, hi = bounds.get("lower"), bounds.get("upper")
            if type(lo) is not int or lo < 0 or (hi is not None and (type(hi) is not int or hi < lo)):
                raise ValueError("cost oracle requires sound nonnegative integer lower/upper bounds")
            bounds["exact"] = hi is not None and lo == hi
            bounds["value"] = lo if bounds["exact"] else None
            costs.append({"candidates": candidate_ids, **bounds})
            push(1, group, bounds)
            continue
        calls += 1
        raw = dict(oracle(intents))
        desired = verdict(raw.get("desired", UNKNOWN))
        protected = raw.get("protected", {})
        if not isinstance(protected, Mapping):
            raise ValueError("protected oracle outcomes must be a requirement-to-verdict mapping")
        states = [desired, *(verdict(value) for value in protected.values())]
        state = FAILS if FAILS in states else UNKNOWN if UNKNOWN in states else HOLDS
        evaluation = {
            **raw,
            "verdict": state,
            "intents": intents,
            "protected_count": len(protected),
            "cost_bounds": bounds,
            "cost": list(lower_key) if bounds["exact"] else None,
            "cost_decimal": [str(value) for value in lower_key] if bounds["exact"] else None,
        }
        trials.append(
            {
                "candidates": candidate_ids,
                "verdict": state,
                "evaluation": evaluation,
                "cost_lower": list(lower_key),
                "cost_lower_decimal": [str(value) for value in lower_key],
                "cost_upper_decimal": (
                    [str(value) for value in measure(group, bounds["upper"])]
                    if bounds["upper"] is not None
                    else None
                ),
                "cost_upper": list(measure(group, bounds["upper"])) if bounds["upper"] is not None else None,
            }
        )
    full_candidates = bool(generated["universe_complete"]) and len(ids) == len(all_ids)
    scoped_complete = not heap and not frontier_truncated
    complete = scoped_complete and full_candidates and size == len(ids)
    if reason == "complete":
        reason = (
            "frontier-limit"
            if frontier_truncated
            else "candidate-limit"
            if len(ids) < len(all_ids)
            else "combination-limit"
            if size < len(ids)
            else "incomplete-universe"
            if not full_candidates
            else "complete"
        )
    verified = sorted(
        (t for t in trials if t["verdict"] == HOLDS),
        key=lambda t: (t["cost_upper"] is None, t["cost_upper"] or t["cost_lower"], t["candidates"]),
    )
    findings = []
    for trial in verified[: limits.max_results]:
        exact = trial["evaluation"]["cost_bounds"]["exact"]
        key = trial["cost_upper"]
        lower_competitor = (
            any(t is not trial and t["verdict"] != FAILS and t["cost_lower"] < key for t in trials)
            if exact
            else True
        )
        findings.append(
            {
                **trial,
                **trial["evaluation"],
                "verified": True,
                "minimum_cost": complete and exact and not lower_competitor,
            }
        )
    return {
        "kind": "repair",
        "candidate_universe": all_ids,
        "evaluated_candidates": ids,
        "universe_complete": generated["universe_complete"],
        "search_complete": complete,
        "scoped_search_complete": scoped_complete,
        "stop_reason": reason,
        "limits": asdict(limits),
        "evaluated": calls,
        "constraint_evaluations": len(trials),
        "cost_evaluations": len(costs),
        "scoped_scenarios": count,
        "elapsed_seconds": time.monotonic() - started,
        "unknown": sum(t["verdict"] == UNKNOWN for t in trials),
        "trials": trials,
        "cost_trials": costs,
        "findings": findings,
        "finding_count": len(verified),
        "findings_truncated": len(verified) > len(findings),
        "candidates": list(by_id.values()),
        "excluded": generated["excluded"],
        "generator_version": generated["generator_version"],
        "cost_order": list(cost_order),
        "scope_cost_measured": all(c["exact"] for c in costs),
        "ordering": "lexicographic sound lower bounds; exact costs when established",
        "proved_infeasible": complete and all(t["verdict"] == FAILS for t in trials),
    }
