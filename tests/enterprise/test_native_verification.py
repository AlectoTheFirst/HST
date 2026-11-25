"""Configuration verification compares predicate meaning and retains uncertainty."""

import importlib
import os
from dataclasses import replace
from types import MappingProxyType

import pytest

from hst.analysis_model.overlay import _rebuild
from hst.assessment.native_verification import compare_configuration

from .test_native_changes import added, graph_fixture

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")


def compare(left, right):
    return compare_configuration(
        left, right, {"firewall": {"rb"}}, estate="synthetic", checkpoint=lambda: True
    )


def test_group_membership_change_is_a_configuration_difference():
    before = added(graph_fixture(), protocols=[], ports=[])
    nodes = dict(before.nodes)
    nodes["leaf"] = replace(nodes["leaf"], props=MappingProxyType({"cidr": "10.1.0.0/24"}))
    relations = [relation for rows in before.outgoing.values() for relation in rows]
    after = _rebuild(before, nodes, relations)
    assert compare(before, before)["state"] == "matches"
    assert compare(before, after)["state"] == "differs"


def test_equal_unknown_predicates_do_not_establish_configuration_match():
    graph = added(graph_fixture(), protocols=[], ports=[])
    nodes = dict(graph.nodes)
    nodes["r"] = replace(
        nodes["r"], props=MappingProxyType({**nodes["r"].props, "qualifier_reason": "unsupported"})
    )
    graph = _rebuild(graph, nodes, [relation for rows in graph.outgoing.values() for relation in rows])
    assert compare(graph, graph)["state"] == "not-decided"
