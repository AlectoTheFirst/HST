"""Native models reuse authenticated artifacts across manager lifetimes."""

import logging
from types import MappingProxyType, SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from hst.analysis_model import codec
from hst.analysis_model.cache import ArtifactCache, MemoryCacheIndex
from hst.analysis_model.compile import compile_model
from hst.analysis_model.graph import GraphInventory
from hst.analysis_model.model import ChoiceAssignment, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.analysis_model.model_cache import CompiledModelCache
from hst.assessment import symbolic_evaluation as engine
from hst.impact.evaluate import Member, RequestSet, Service, member
from hst.policy.ir import ExecutionContext
from hst.symbolic import HeaderSchema, SymbolicManager

from .test_assessment_symbolic_bridge import native as native


def test_model_artifact_reuse_preserves_exact_semantics_and_knowledge(native, tmp_path):
    state = StateKey("destination", ExecutionContext("estate", "authority", "domain", "device", "vrf", 4))
    source = ModelInput(
        "a" * 64,
        (NodeSpec(state, terminal="permit"),),
        (EntrySpec(state),),
        (ChoiceAssignment("only"),),
        True,
    )
    cache = CompiledModelCache(
        ArtifactCache(tmp_path, Fernet.generate_key().decode(), MemoryCacheIndex()),
        semantic_version="test-semantics",
    )
    knowledge = frozenset({"source_address"})
    try:
        first = cache.compile(source, native, knowledge, estate="estate", compiler=compile_model)
        assert cache.misses == 1
        with SymbolicManager(HeaderSchema.ipv4()) as other:
            second = cache.compile(source, other, knowledge, estate="estate", compiler=compile_model)
            assert cache.hits == 1
            assert second.fingerprint == first.fingerprint
            assert second.universe.known_fields == knowledge
        cache.compile(source, native, knowledge | {"protocol"}, estate="estate", compiler=compile_model)
        assert cache.misses == 2
    finally:
        cache.close()


def _cache(tmp_path):
    return CompiledModelCache(
        ArtifactCache(tmp_path, Fernet.generate_key().decode(), MemoryCacheIndex()),
        semantic_version="test-semantics",
    )


def _source(terminal="permit"):
    state = StateKey("destination", ExecutionContext("estate", "authority", "domain", "device", "vrf", 4))
    return ModelInput(
        "a" * 64,
        (NodeSpec(state, terminal=terminal),),
        (EntrySpec(state),),
        (ChoiceAssignment("only"),),
        True,
    )


def test_a_model_the_cache_refuses_is_evaluated_from_memory(native, tmp_path, monkeypatch, caplog):
    empty = MappingProxyType({})
    graph = GraphInventory("a" * 64, "graph", empty, empty, empty, empty, True, (), 0)

    def normalize(network, selected_graph, request, estate, *, evidence=None):
        return {"web": _source(network.verdict)}

    monkeypatch.setattr(engine, "normalize_request_network", normalize)
    # Every model now exceeds the metadata limit, so encode_model raises for size.
    monkeypatch.setattr(codec, "MAX_METADATA_BYTES", 1)
    request = RequestSet(
        "web",
        ((4, 1, 2),),
        "service",
        (Member("web", ((4, 10, 10),)),),
        member("web"),
        Service(frozenset({6})),
    )
    before = SimpleNamespace(gates=SimpleNamespace(), changes=None, verdict="permit")
    after = SimpleNamespace(gates=SimpleNamespace(), changes=None, verdict="deny")
    cache = _cache(tmp_path)
    with (
        caplog.at_level(logging.WARNING, logger="hst.analysis_model.model_cache"),
        engine.SymbolicEvaluation(graph, "estate", model_cache=cache) as evaluator,
    ):
        result = evaluator.compare_networks(before, after, request, "possible")
    assert result["outcomes"]["before"]["verdict"] == "holds"
    assert result["outcomes"]["after"]["verdict"] == "does-not-hold"
    assert (cache.misses, cache.hits, cache.store_failures) == (2, 0, 2)
    assert "not stored in the analysis cache" in caplog.text
    assert "model metadata exceeds limit" in caplog.text
    assert not list(tmp_path.glob("*.artifact"))


def test_an_unreadable_cached_model_is_compiled_again(native, tmp_path, caplog):
    source = _source()
    knowledge = frozenset({"source_address"})
    cache = _cache(tmp_path)
    try:
        first = cache.compile(source, native, knowledge, estate="estate", compiler=compile_model)
        (artifact,) = tmp_path.glob("*.artifact")
        artifact.write_bytes(b"x" * artifact.stat().st_size)
        with (
            caplog.at_level(logging.WARNING, logger="hst.analysis_model.model_cache"),
            SymbolicManager(HeaderSchema.ipv4()) as other,
        ):
            second = cache.compile(source, other, knowledge, estate="estate", compiler=compile_model)
            assert second.fingerprint == first.fingerprint
            assert second.universe.manager is other
        assert (cache.misses, cache.hits, cache.read_failures) == (2, 0, 1)
        assert "not read from the analysis cache" in caplog.text
        # The compile after the failed read stored the model again.
        with SymbolicManager(HeaderSchema.ipv4()) as third:
            cache.compile(source, third, knowledge, estate="estate", compiler=compile_model)
        assert cache.hits == 1
    finally:
        cache.close()


def test_a_compile_error_is_not_taken_for_a_cache_failure(native, tmp_path):
    def failing(*_args):
        raise ValueError("policy must be pinned to the model manifest")

    cache = _cache(tmp_path)
    try:
        with pytest.raises(ValueError, match="pinned"):
            cache.compile(_source(), native, frozenset(), estate="estate", compiler=failing)
        assert (cache.misses, cache.read_failures, cache.store_failures) == (1, 0, 0)
    finally:
        cache.close()
