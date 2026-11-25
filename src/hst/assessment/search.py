"""A finite subset search over a three-valued oracle.

The oracle evaluates each subset. The verdict of a subset is not inferred from
the verdict of another subset. The evaluation limit counts the trial of the
empty subset.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from itertools import combinations
from math import comb
from typing import Any

HOLDS = "holds"
FAILS = "does-not-hold"
UNKNOWN = "not-established"
VERDICTS = frozenset({HOLDS, FAILS, UNKNOWN})


@dataclass(frozen=True)
class SearchLimits:
    max_candidates: int = 64
    max_evaluations: int = 256
    max_combination_size: int = 2
    max_seconds: float = 30
    max_results: int = 50

    def __post_init__(self) -> None:
        if any(
            type(value) is not int
            for value in (
                self.max_candidates,
                self.max_evaluations,
                self.max_combination_size,
                self.max_results,
            )
        ):
            raise ValueError("candidate, evaluation, combination and result limits must be integers")
        bounds = (
            (self.max_candidates, 1, 256),
            (self.max_evaluations, 1, 10000),
            (self.max_combination_size, 0, 8),
            (self.max_seconds, 0.001, 300),
            (self.max_results, 1, 1000),
        )
        if any(not lo <= value <= hi for value, lo, hi in bounds):
            raise ValueError("search limits exceed the supported bounded range")


def verdict(value: str | Mapping[str, Any]) -> str:
    result = value if isinstance(value, str) else value.get("verdict", UNKNOWN)
    if result not in VERDICTS:
        raise ValueError(f"invalid three-valued oracle verdict: {result!r}")
    return str(result)


def enumerate_subsets(
    candidates: Sequence[str],
    oracle: Callable[[tuple[str, ...]], str | Mapping[str, Any]],
    limits: SearchLimits | None = None,
    *,
    target: str = HOLDS,
    universe_complete: bool = True,
    cancelled: Callable[[], bool] | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Evaluate the subsets of `candidates` in the order of increasing size.

    A trial with an unknown verdict is kept. A finding has the claim
    `minimum_cardinality` when every smaller subset has the opposite verdict,
    and `inclusion_minimal` when every proper subset has the opposite verdict.
    `one_minimal` is the same check for the subsets with one candidate removed.
    The oracle can be non-monotone, and `one_minimal` is a claim of its own.
    `stop_reason` is `candidate-limit` when `limits.max_candidates` cut the
    candidates, and `search_complete` is then false.
    """
    limits = limits or SearchLimits()
    if target not in {HOLDS, FAILS}:
        raise ValueError("search target must be a proven outcome")
    if len(set(candidates)) != len(candidates):
        raise ValueError("candidate identifiers must be unique")
    all_ids = sorted(candidates)
    ids = all_ids[: limits.max_candidates]
    size = min(len(ids), limits.max_combination_size)
    scoped_count = sum(comb(len(ids), n) for n in range(size + 1))
    started = time.monotonic()
    trials: list[dict[str, Any]] = []
    states: dict[tuple[str, ...], str] = {}
    reason = "complete"
    for n in range(size + 1):
        for group in combinations(ids, n):
            if cancelled and cancelled():
                reason = "cancelled"
                break
            if time.monotonic() - started >= limits.max_seconds:
                reason = "time-limit"
                break
            if len(trials) >= limits.max_evaluations:
                reason = "evaluation-limit"
                break
            raw = oracle(group)
            state = verdict(raw)
            trial: dict[str, Any] = {"candidates": list(group), "verdict": state}
            if isinstance(raw, Mapping):
                trial["evaluation"] = dict(raw)
            trials.append(trial)
            states[group] = state
            if progress:
                progress({"evaluated": len(trials), "scoped_scenarios": scoped_count})
        if reason != "complete":
            break
    opposite = FAILS if target == HOLDS else HOLDS
    findings: list[dict[str, Any]] = []
    finding_count = sum(trial["verdict"] == target for trial in trials)
    opposite_by_size = {
        n: sum(len(group) == n and state == opposite for group, state in states.items())
        for n in range(size + 1)
    }
    full_candidates = universe_complete and len(ids) == len(all_ids)
    for trial in trials:
        if trial["verdict"] != target:
            continue
        if len(findings) >= limits.max_results:
            break
        group = tuple(trial["candidates"])
        immediate = list(combinations(group, len(group) - 1)) if group else []
        proper = [subset for n in range(len(group)) for subset in combinations(group, n)]
        claims = {
            "verified": True,
            "one_minimal": all(states.get(s) == opposite for s in immediate),
            "inclusion_minimal": all(states.get(s) == opposite for s in proper),
            "minimum_cardinality": full_candidates
            and all(opposite_by_size[n] == comb(len(ids), n) for n in range(len(group))),
        }
        findings.append({**trial, "minimality": claims})
    complete = reason == "complete" and full_candidates and size == len(ids)
    if reason == "complete" and len(ids) < len(all_ids):
        reason = "candidate-limit"
    elif reason == "complete" and size < len(ids):
        reason = "combination-limit"
    elif reason == "complete" and not universe_complete:
        reason = "incomplete-universe"
    return {
        "candidate_universe": all_ids,
        "evaluated_candidates": ids,
        "universe_complete": universe_complete,
        "search_complete": complete,
        "scoped_search_complete": len(trials) == scoped_count,
        "stop_reason": reason,
        "limits": asdict(limits),
        "evaluated": len(trials),
        "scoped_scenarios": scoped_count,
        "unknown": sum(t["verdict"] == UNKNOWN for t in trials),
        "elapsed_seconds": time.monotonic() - started,
        "trials": trials,
        "findings": findings[: limits.max_results],
        "finding_count": finding_count,
        "findings_truncated": finding_count > len(findings),
    }
