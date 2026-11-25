"""The engine's answers written in the result vocabulary.

The engines answer in their own values and names. `project_engine` projects
every body once, where the body leaves an engine. An HTTP answer, an HST AI
tool result and a stored assessment run hold the result vocabulary and no
engine name.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from hst.results.words import (
    ANSWER_OF_VALUE as _ENGINE_VALUES,
)
from hst.results.words import (
    CONDITION_WORDS,
    QUANTIFIER_OF_MODE,
    Condition,
    Missing,
    Quantifier,
    Result,
    from_engine,
)

# The 3 values of the engine, and `unknown`. The symbolic engine writes
# `unknown` for the open value in its evidence steps and terminals.
ANSWER_OF_VALUE: dict[str, str] = {**_ENGINE_VALUES, "unknown": "not-established"}


def engine_value(raw: Any) -> str | None:
    """The engine value of a verdict or outcome field, or None for a word the
    engines do not use. `unknown` reads as `not-established`."""
    text = str(raw)
    if text not in ANSWER_OF_VALUE:
        return None
    return "not-established" if text == "unknown" else text


def missing_from_gaps(entries: Iterable[Mapping[str, Any]]) -> list[Missing]:
    """The gap entries of an engine as `missing` entries. Each entry has the
    code, the subject if the gap entry has one, and the detail. The result
    has distinct entries, at most 50."""
    seen: dict[tuple[str, str | None], Missing] = {}
    for entry in entries:
        code = str(entry.get("code") or entry.get("kind") or "unclassified")
        subject = entry.get("subject")
        subject_text = None if subject is None else str(subject)[:500]
        key = (code, subject_text)
        if key in seen:
            continue
        detail = entry.get("detail")
        text = None if detail is None else str(detail)[:1000]
        seen[key] = Missing(code=code[:120], subject=subject_text, detail=text)
    return list(seen.values())[:50]


def missing_from_lines(lines: Iterable[Any], *, code: str = "missing-evidence") -> list[Missing]:
    """The engine's free-text missing lines as `missing` entries."""
    return [Missing(code=code, detail=str(line)[:1000]) for line in lines][:50]


def condition_result(
    verdict: str,
    *,
    quantifier: Quantifier | None = None,
    condition: Condition | None = None,
    missing: list[Missing] | tuple[Missing, ...] = (),
    fallback: str = "the evaluation is open",
) -> Result:
    """The connection condition answer for one of the engine's three values.
    An open answer without a `missing` entry gets `fallback` as its one entry."""
    open_on = list(missing) if verdict == "not-established" else []
    if verdict == "not-established" and not open_on:
        open_on = [Missing(code="not-decided", detail=fallback)]
    return from_engine(
        "condition-holds", verdict, quantifier=quantifier, condition=condition, missing=open_on
    )


def explanation_result(
    item: Mapping[str, Any], *, quantifier: Quantifier | None = None, condition: Condition | None = None
) -> dict[str, Any] | None:
    """The condition answer of one engine explanation (`outcome` and
    `missing`), as JSON. None when the outcome is not an engine value."""
    verdict = engine_value(item.get("outcome"))
    if verdict is None:
        return None
    return condition_result(
        verdict,
        quantifier=quantifier,
        condition=condition,
        missing=missing_from_lines(item.get("missing") or []),
        fallback="the calculation did not decide this part",
    ).model_dump(mode="json")


# The bucket names of an evaluation body outside the engine. Every body that
# leaves the engine (an HTTP answer, a tool result, a stored assessment run)
# has these names.
BUCKET_NAMES: dict[str, str] = {
    "proven": "decided_change",
    "possible": "open_change",
    "not_established": "open",
    "condition_holds": "passes",
    "condition_fails": "fails",
}
# A member row's flags of the change.
CHANGE_NAMES: dict[str, str] = {
    "proven_loss": "decided_loss",
    "possible_loss": "open_loss",
    "proven_gain": "decided_gain",
    "possible_gain": "open_gain",
}
# The disjoint parts of the comparison (`triage`).
TRIAGE_NAMES: dict[str, str] = {
    "proven_loss": "decided_loss",
    "worked_now_unknown": "passes_then_open",
    "unknown_now_broken": "open_then_fails",
    "unknown_throughout": "open_throughout",
    "proven_gain": "decided_gain",
    "unknown_now_works": "open_then_passes",
    "broken_now_unknown": "fails_then_open",
}
# The parts of one side. They are the clients for which the condition passes,
# fails or is not decided, as address lists and as counts.
PART_NAMES: dict[str, str] = {
    "holds": "passes",
    "does-not-hold": "fails",
    "fails": "fails",
    "not-established": "open",
    "unknown": "open",
}
_MODES = frozenset(QUANTIFIER_OF_MODE)


def answer_of(value: Any) -> str | None:
    """The `answer` of a result as JSON, or None for anything else."""
    if isinstance(value, Mapping) and value.get("kind", "result") == "result":
        answer = value.get("answer")
        return answer if isinstance(answer, str) else None
    return None


# The engine value of each answer of the condition statement.
VALUE_OF_ANSWER: dict[str, str] = {"true": "holds", "false": "does-not-hold", "open": "not-established"}


def engine_value_of(value: Any) -> str | None:
    """The engine value a condition result as JSON states, or None."""
    return VALUE_OF_ANSWER.get(answer_of(value) or "")


class _Frame:
    """The context for the projection of a result inside a body. It holds the
    quantifier and the condition of the question, and the gaps of the body as
    `missing` entries."""

    def __init__(self, quantifier: Quantifier | None, condition: Condition | None, gaps: list[Missing]):
        self.quantifier = quantifier
        self.condition = condition
        self.gaps = gaps

    def inside(self, body: Mapping[str, Any], *, root: bool = False) -> _Frame:
        mode = body.get("mode")
        quantifier = QUANTIFIER_OF_MODE.get(mode) if isinstance(mode, str) and mode in _MODES else None
        if root and self.quantifier is not None:
            # The mode that the caller states is the mode of the outermost body.
            quantifier = self.quantifier
        request = body.get("request")
        success = request.get("success") if isinstance(request, Mapping) else None
        raw_gaps = body.get("gaps")
        gaps = (
            missing_from_gaps(g for g in raw_gaps if isinstance(g, Mapping))
            if isinstance(raw_gaps, list) and raw_gaps
            else []
        )
        return _Frame(
            quantifier or self.quantifier,
            success if success in CONDITION_WORDS else self.condition,
            gaps or self.gaps,
        )

    def result(self, value: str, *, missing: list[Missing] | None = None, fallback: str) -> dict[str, Any]:
        return condition_result(
            value,
            quantifier=self.quantifier,
            condition=self.condition,
            missing=self.gaps if missing is None else missing,
            fallback=fallback,
        ).model_dump(mode="json")


def _reason(item: Mapping[str, Any]) -> list[Missing] | None:
    """The `missing` entries of an item, from its `missing` lines or from its `reason`."""
    lines = item.get("missing")
    if isinstance(lines, list) and lines and all(isinstance(line, str) for line in lines):
        return missing_from_lines(lines)
    reason = item.get("reason")
    if isinstance(reason, str) and reason:
        return [Missing(code="not-decided", detail=reason[:1000])]
    return None


def _renamed(item: dict[str, Any], names: Mapping[str, str]) -> None:
    """Rename the keys of `item` in place, keeping their order."""
    if not any(key in names for key in item):
        return
    pairs = [(names.get(key, key), value) for key, value in item.items()]
    item.clear()
    item.update(pairs)


def _is_body(item: Mapping[str, Any]) -> bool:
    return all(isinstance(item.get(name), Mapping) for name in ("proven", "possible", "not_established"))


def _is_counts(item: Any) -> bool:
    return (
        isinstance(item, dict)
        and bool(item)
        and set(item) <= set(PART_NAMES)
        and all(value is None or isinstance(value, int | str) for value in item.values())
    )


def _project(value: Any, frame: _Frame, *, root: bool = False) -> None:
    if isinstance(value, list):
        for item in value:
            _project(item, frame, root=root)
        return
    if not isinstance(value, dict):
        return
    if "mode" in value or "request" in value or "gaps" in value:
        frame = frame.inside(value, root=root)
    body = _is_body(value)
    if body:
        _renamed(value, BUCKET_NAMES)
        if isinstance(value.get("triage"), dict):
            _renamed(value["triage"], TRIAGE_NAMES)
        for row in value.get("members") or []:
            if not isinstance(row, dict):
                continue
            _renamed(row, CHANGE_NAMES)
            if isinstance(row.get("triage"), dict):
                _renamed(row["triage"], TRIAGE_NAMES)
            for side in ("before", "after"):
                if _is_counts(row.get(side)):
                    _renamed(row[side], PART_NAMES)
            decimal = row.get("counts_decimal")
            if isinstance(decimal, dict):
                for side in decimal.values():
                    if _is_counts(side):
                        _renamed(side, PART_NAMES)
    if body or isinstance(value.get("outcomes"), dict):
        steps = value.get("evidence")
        for item in steps.get("items") or [] if isinstance(steps, dict) else []:
            verdict = engine_value(item.get("outcome")) if isinstance(item, dict) else None
            if verdict is None:
                continue
            item["outcome"] = frame.result(
                verdict, missing=_reason(item) or [], fallback="the walk did not decide this part"
            )
            _renamed(item, {"outcome": "result"})
    verdict = engine_value(value.get("verdict")) if "verdict" in value else None
    if verdict is not None and "result" not in value:
        # A side of an evaluation has `isolated`, or a client list under `holds` or `unknown`.
        is_side = "isolated" in value or any(isinstance(value.get(key), list) for key in ("holds", "unknown"))
        value["verdict"] = frame.result(
            verdict,
            missing=_reason(value) if not is_side else None,
            fallback="the evaluation is open" if is_side else "the search did not decide this part",
        )
        _renamed(value, {"verdict": "result"})
        if is_side:
            _renamed(value, {key: PART_NAMES[key] for key in ("holds", "unknown") if key in value})
            if _is_counts(value.get("counts")):
                _renamed(value["counts"], PART_NAMES)
    desired, protected = value.get("desired"), value.get("protected")
    if isinstance(desired, str) and engine_value(desired) is not None and isinstance(protected, dict):
        value["desired"] = frame.result(
            engine_value(desired) or "", missing=_reason(value), fallback="the desired requirement is open"
        )
        for name, state in list(protected.items()):
            engine = engine_value(state) if isinstance(state, str) else None
            if engine is not None:
                protected[name] = frame.result(engine, missing=[], fallback="the protection is open")
    for item in value.values():
        _project(item, frame)


def project_engine(value: Any, mode: str | None = None) -> Any:
    """Write the engine's answers inside `value` in the result vocabulary, in
    place, and return it.

    In every evaluation body the address buckets, the member flags, the
    disjoint parts and the counts of each member take the names of
    `BUCKET_NAMES`, `CHANGE_NAMES`, `TRIAGE_NAMES` and `PART_NAMES`. The
    `outcome` of each evidence step becomes `result`.

    Every `verdict` that holds an engine value becomes `result`. On a side of
    an evaluation (an object with `isolated` or client lists), the address
    lists are `passes`, `fails` and `open`, and the `missing` entries are the
    gaps of the body. On any other item, the `missing` entries are the
    `missing` lines or the `reason` of the item. The `desired` and `protected`
    states of a requirement become results.

    The quantifier of the outermost body is `mode`, else the mode of the body.
    The quantifier of a nested body is its own mode, else the quantifier of
    the enclosing body. The condition is the `success` of the nearest request.
    A value that is already projected stays as it is."""
    _project(value, _Frame(QUANTIFIER_OF_MODE.get(mode or ""), None, []), root=True)
    return value


def project_evaluation(body: dict[str, Any], mode: str | None) -> Result | None:
    """Apply `project_engine` to one evaluation body and return the answer of
    the whole evaluation. The answer is the result of the side after the
    change, or None when the body has no outcomes."""
    project_engine(body, mode)
    outcomes = body.get("outcomes")
    after = outcomes.get("after") if isinstance(outcomes, dict) else None
    result = after.get("result") if isinstance(after, dict) else None
    return Result.model_validate(result) if isinstance(result, dict) else None
