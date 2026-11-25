"""A path trace written in the result vocabulary.

The tracer (`hst.path.trace`) describes each leg, carrier and arrival, and
the whole walk, in a prose `verdict`. `project_trace` projects every trace
that leaves the engine once (the `GET /api/path` answer, the site traces, the
change simulation and the `reach_trace` tool). The prose becomes `detail`.
Each leg, carrier and arrival and the whole walk get `result`, the answer of
their statement. The statement of a hop is "the device forwards the flow at
this hop". The statement of the walk is "the flow is forwarded on all
candidate paths". The statement of an SD-WAN business policy rule that the
walk evaluated is that the rule is the first match of the flow.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hst.results.words import Missing, Result, decided, from_engine

# The prose of a leg whose table records no route for its destination.
NO_ROUTE_DETAIL = "no route found"
# The reason of a leg whose L2 walk found no cable path in the graph, found
# more than one, or reached its cap. The tracer drew that stretch as a jump
# (hst.path.trace `_finish_trace`). `leg_result` gives such a leg an open
# answer with the code `l2-path-not-found`.
L2_PATH_NOT_FOUND = "no cable path in the graph for the L2 stretch of this leg; it is drawn as a jump"


def _prose(item: Mapping[str, Any]) -> str:
    """The prose of an item, before or after projection."""
    return str(item.get("verdict") or item.get("detail") or "")


def leg_result(leg: Mapping[str, Any]) -> Result:
    """The statement "the device forwards the flow at this hop" for one leg,
    carrier or arrival.

    A blocked item is false with its prose as the cause. A leg whose table
    has no route for its destination is false with the cause "no route". An
    indeterminate item is open on the cause that it records, or on the gate
    that could not be decided. An L2 stretch drawn as a jump is open with the
    code "l2-path-not-found"."""
    prose = _prose(leg)
    if leg.get("indeterminate"):
        reason = leg.get("indeterminate_reason") or "a gate on this hop could not be decided"
        subject = leg.get("device_uid") or leg.get("fw_uid") or leg.get("egress") or leg.get("next_hop")
        code = "l2-path-not-found" if reason == L2_PATH_NOT_FOUND else "hop-not-decided"
        missing = [Missing(code=code, subject=str(subject) if subject else None, detail=str(reason))]
        return from_engine("hop-forwards", "not-established", missing=missing)
    if leg.get("blocked") or prose.startswith("BLOCKED"):
        cause = "blocked" + prose[len("BLOCKED") :] if prose.startswith("BLOCKED") else "blocked"
        return from_engine("hop-forwards", "does-not-hold", cause=cause)
    if prose == NO_ROUTE_DETAIL:
        return from_engine("hop-forwards", "does-not-hold", cause="no route")
    return from_engine("hop-forwards", "holds")


def walk_result(results: Sequence[Result], legs: Sequence[Mapping[str, Any]], indeterminate: bool) -> Result:
    """The statement "the flow is forwarded on all candidate paths".

    The answer is false at the first false hop, else open at the first open
    hop, else true. A false or open answer holds the device of its hop. A
    false hop decides the walk also when another hop is open. A walk with no
    hop is open. A walk that the tracer marks indeterminate is open when
    every hop forwards."""
    if not results:
        return from_engine(
            "trace-forwards",
            "not-established",
            missing=[Missing(code="no-hop", detail="the trace drew no hop for the flow")],
        )
    for result, leg in zip(results, legs, strict=False):
        if result.answer == "false":
            return from_engine("trace-forwards", "does-not-hold", device=leg.get("device_uid"))
    for result, leg in zip(results, legs, strict=False):
        if result.answer == "open":
            return from_engine(
                "trace-forwards",
                "not-established",
                device=leg.get("device_uid"),
                missing=list(result.missing),
            )
    if indeterminate:
        return from_engine(
            "trace-forwards",
            "not-established",
            missing=[Missing(code="not-decided", detail="the trace could not decide a gate on the path")],
        )
    return from_engine("trace-forwards", "holds")


def _rule_result(rule: Mapping[str, Any]) -> Result:
    """Whether an SD-WAN business policy rule is the first match of the flow.
    The answer is true when every match field is decided. Otherwise it is
    open on the match fields that are not decided."""
    if rule.get("verdict") == "may match":
        undecided = str(rule.get("undecided") or "a match field")
        missing = [
            Missing(code="match-not-decided", subject=rule.get("name"), detail=f"{undecided} not decided")
        ]
        return from_engine("rule-first-match", "not-established", missing=missing)
    return decided("rule-first-match", "true")


def _detail(item: dict[str, Any]) -> None:
    """Rename the key `verdict` of the item to `detail`, in place. The key order stays."""
    if "verdict" not in item:
        return
    pairs = [("detail" if key == "verdict" else key, value) for key, value in item.items()]
    item.clear()
    item.update(pairs)


def _project_leg(leg: dict[str, Any]) -> Result:
    result = leg_result(leg)
    carrier = leg.get("carrier")
    if isinstance(carrier, dict):
        arrival = carrier.get("arrival")
        if isinstance(arrival, dict) and "verdict" in arrival:
            arrival["result"] = leg_result(arrival).model_dump(mode="json")
            _detail(arrival)
        if "verdict" in carrier:
            carrier["result"] = leg_result(carrier).model_dump(mode="json")
            _detail(carrier)
    for rule in leg.get("sdwan_rules") or ():
        if isinstance(rule, dict) and "verdict" in rule:
            rule["result"] = _rule_result(rule).model_dump(mode="json")
            del rule["verdict"]
    if "verdict" in leg:
        leg["result"] = result.model_dump(mode="json")
        _detail(leg)
    return result


def project_walk(walk: dict[str, Any]) -> Result:
    """Project one walk (its legs and its own prose) in place, and return its
    answer.

    The walk's `left_estate` and `reach` (hst.path.trace) are kept as the
    tracer wrote them. `reach` is null on a walk whose answer is not true."""
    legs = [leg for leg in walk.get("legs") or [] if isinstance(leg, dict)]
    results = [_project_leg(leg) for leg in legs]
    answer = walk_result(results, legs, bool(walk.get("indeterminate")))
    if "reach" in walk and answer.answer != "true":
        walk["reach"] = None
    if "verdict" in walk or "result" not in walk:
        walk["result"] = answer.model_dump(mode="json")
        _detail(walk)
    return answer


def project_trace(answer: dict[str, Any]) -> dict[str, Any]:
    """Write one trace answer in the result vocabulary, in place, and return
    it. A reply answer projects its forward walk and each reply walk."""
    if "forward" in answer and isinstance(answer["forward"], dict):
        project_walk(answer["forward"])
        replies = answer.get("reply")
        for walk in replies if isinstance(replies, list) else [replies]:
            if isinstance(walk, dict):
                project_walk(walk)
        return answer
    project_walk(answer)
    return answer


def flow_side_result(side: Mapping[str, Any]) -> Result:
    """The statement "the rulebase permits the flow" for one side of a
    simulated flow.

    The answer is open when a gate could not be decided. It is false for a
    blocked side, with the rule from the prose as the cause. Otherwise it is
    true."""
    prose = _prose(side)
    if side.get("indeterminate"):
        reason = side.get("indeterminate_reason") or "a gate on the path was not decided"
        return from_engine(
            "rule-permits", "not-established", missing=[Missing(code="flow-not-decided", detail=str(reason))]
        )
    if side.get("blocked"):
        cause = prose[len("BLOCKED by ") :] if prose.startswith("BLOCKED by ") else "a rule of the change"
        return from_engine("rule-permits", "does-not-hold", cause=cause)
    return from_engine("rule-permits", "holds")
