"""The answer of a whole trace walk from its hops (results/trace.py)."""

from __future__ import annotations

import pytest

from hst.results.trace import project_trace

BLOCKED = {"verdict": "BLOCKED by rule deny-all", "blocked": True, "device_uid": "dev:fw1"}
UNDECIDED = {"verdict": "may pass", "indeterminate": True, "device_uid": "dev:fw2"}
FORWARDED = {"verdict": "forwarded", "device_uid": "dev:r1"}


def _answer(*legs: dict) -> str:
    walk = project_trace({"verdict": "walk", "legs": [dict(leg) for leg in legs]})
    return walk["result"]["answer"]


@pytest.mark.parametrize("legs", [(BLOCKED, UNDECIDED), (UNDECIDED, BLOCKED)])
def test_a_walk_with_a_hop_that_does_not_forward_is_false_whatever_another_hop_could_not_decide(legs):
    """A blocked lane and a lane the tracer could not decide: the flow is not forwarded on all paths."""
    assert _answer(*legs) == "false"


def test_a_walk_with_an_undecided_hop_and_no_blocked_one_is_open():
    assert _answer(FORWARDED, UNDECIDED) == "open"


def test_a_walk_where_every_hop_forwards_is_true():
    assert _answer(FORWARDED, FORWARDED) == "true"
