"""Assessment dispatch, request identity and native result lifetime contracts."""

from __future__ import annotations

import os
from dataclasses import replace
from types import MappingProxyType, SimpleNamespace

import pytest

from hst.analysis_model.graph import GraphInventory
from hst.analysis_model.model import ChoiceAssignment, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.assessment import symbolic_evaluation as engine
from hst.impact.evaluate import Member, RequestSet, Service, member
from hst.policy.ir import ExecutionContext
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager


@pytest.fixture
def native():
    try:
        manager = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")
    with manager:
        yield manager


def _request():
    return RequestSet(
        "web",
        ((4, 1, 2),),
        "service",
        (Member("web", ((4, 10, 10),)),),
        member("web"),
        Service(frozenset({6})),
    )


def _graph():
    empty = MappingProxyType({})
    return GraphInventory("a" * 64, "graph", empty, empty, empty, empty, True, (), 0)


def test_request_packets_retain_declared_dimensions_and_omitted_knowledge(native):
    request = _request()
    packets = engine.member_packets(native, request, request.members[0])
    # a request that states no fragment offset is read as initial fragments (4217ace7)
    assert packets.known_fields == {"source_address", "destination_address", "protocol", "fragment_offset"}
    assert packets.cardinality(("source_address", "destination_address", "protocol")) == 2
    assert engine.request_identity(request) != engine.request_identity(replace(request, success="round-trip"))


def test_compiled_assessment_reuses_models_and_serializes_before_manager_close(native, monkeypatch):
    graph = _graph()
    context = ExecutionContext("estate", "authority", "domain", "device", "vrf", 4)
    key = StateKey("terminal", context)

    def normalize(network, selected_graph, request, estate, *, evidence=None):
        assert selected_graph is graph and estate == "estate"
        return {
            "web": ModelInput(
                graph.manifest_digest,
                (NodeSpec(key, terminal=network.verdict),),
                (EntrySpec(key),),
                (ChoiceAssignment("only"),),
                True,
            )
        }

    monkeypatch.setattr(engine, "normalize_request_network", normalize)
    before = SimpleNamespace(gates=SimpleNamespace(), changes=None, verdict="permit")
    after = SimpleNamespace(gates=SimpleNamespace(), changes=None, verdict="deny")
    with engine.SymbolicEvaluation(graph, "estate") as evaluator:
        result = evaluator.compare_networks(before, after, _request(), "possible")
        assert result["proven"]["loss"]["address_count_decimal"] == "2"
        assert result["outcomes"]["before"]["verdict"] == "holds"
        assert result["outcomes"]["after"]["verdict"] == "does-not-hold"
        assert result["symbolic"]["database_reads_during_walk"] == 0
        evaluator.answer_network(before, _request(), "possible")
        assert len(evaluator._models) == 2
    assert result["symbolic"]["artifact"]["complete"] is True
    with pytest.raises(RuntimeError, match="closed"):
        evaluator.answer_network(before, _request(), "possible")


def test_candidate_snapshot_mismatch_is_rejected_before_evaluation(native):
    graph = _graph()
    with (
        engine.SymbolicEvaluation(graph, "estate") as evaluator,
        pytest.raises(ValueError, match="snapshot"),
    ):
        evaluator.answer_network(
            SimpleNamespace(), _request(), "possible", graph=replace(graph, manifest_digest="b" * 64)
        )
