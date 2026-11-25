"""Independent counts for native assessment cost bounds and overlap."""

from dataclasses import replace

import pytest

from hst.analysis_model.model import ChoiceAssignment
from hst.assessment.symbolic_cost import permitted_scope_cost
from hst.assessment.symbolic_results import SymbolicAnswer
from hst.impact.evaluate import Member, RequestSet, Service, member
from hst.impact.symbolic_walk import ChoiceResult, WalkResult
from hst.policy.bounds import Bounds
from hst.symbolic import header

from .test_assessment_symbolic_bridge import native as native


def _answer(native, permitted, possible):
    request = RequestSet(
        "cost",
        ((4, 1, 2),),
        "service",
        (Member("one", ((4, 10, 10),)), Member("overlap", ((4, 10, 10),))),
        member("one"),
        Service(frozenset({6}), ((0, 443, 443),), ((0, 40000, 40000),)),
    )
    packets = header(
        native,
        {
            "source_address": (1, 2),
            "destination_address": 10,
            "protocol": 6,
            "source_port": 40000,
            "destination_port": 443,
            "fragment_offset": 0,
        },
        bank="original",
    )
    lower, upper = native.empty(), native.empty()
    for source in permitted:
        lower = lower.union(packets.intersect(header(native, {"source_address": source}, bank="original")))
    for source in possible:
        upper = upper.union(packets.intersect(header(native, {"source_address": source}, bank="original")))
    bounds = Bounds(packets, lower, upper)
    branch = ChoiceResult(ChoiceAssignment("only"), bounds, True, (), ())
    result = WalkResult("a" * 64, "model", "request", bounds, (branch,), True, True, (), 1, 1)
    return SymbolicAnswer(request, "possible", bounds, {"one": result, "overlap": result}, True, ())


def test_scope_cost_counts_overlapping_members_once_and_preserves_uncertainty(native):
    before = _answer(native, (), ())
    after = _answer(native, (1,), (1, 2))
    cost = permitted_scope_cost((before,), (after,))
    assert cost["lower"] == 1 and cost["upper"] == 2
    assert cost["value"] is None and cost["exact"] is False
    assert cost["universe_flows_decimal"] == "2"


def test_one_successful_hidden_header_variant_cannot_prove_whole_cost_tuple(native):
    before = _answer(native, (), ())
    after = _answer(native, (1, 2), (1, 2))
    partial = {}
    for name, result in after.members.items():
        bounds = result.bounds
        flags = header(native, {"tcp_flags": 2}, bank="original")
        limited = Bounds(bounds.universe, bounds.lower.intersect(flags), bounds.upper)
        branch = replace(result.by_choice[0], bounds=limited)
        partial[name] = replace(result, bounds=limited, by_choice=(branch,))
    cost = permitted_scope_cost((before,), (replace(after, members=partial),))
    assert cost["lower"] == 0 and cost["upper"] == 2


def test_cost_rejects_a_changed_request_universe(native):
    before = _answer(native, (), ())
    after = replace(before, request_set=replace(before.request_set, success="round-trip"))
    with pytest.raises(ValueError, match="request"):
        permitted_scope_cost((before,), (after,))
