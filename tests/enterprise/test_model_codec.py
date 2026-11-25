import importlib
import json
import os

import pytest

from hst.analysis_model.codec import ModelBinding, ModelCodecError, decode_model, encode_model
from hst.analysis_model.compile import AnalysisModel, CompiledEdge, CompiledEntry, CompiledNode
from hst.analysis_model.model import ChoiceAssignment, StateKey
from hst.policy.ir import ExecutionContext
from hst.symbolic import HeaderSchema, SymbolicManager
from hst.symbolic.relations import PacketRelation

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")

MANIFEST = "a" * 64


def binding(manager, **changes):
    values = {
        "estate": "e",
        "manifest_digest": MANIFEST,
        "semantic_version": "1",
        "header_schema": manager.capabilities.schema_version,
        "ordering_version": manager.capabilities.ordering_version,
        "backend_version": manager.capabilities.backend_version,
    }
    values.update(changes)
    return ModelBinding(**values)


def test_exact_model_roundtrip_including_relation_pipeline():
    with SymbolicManager(HeaderSchema(4)) as source:
        context = ExecutionContext("e", "a", "d", "fw", "vrf", 4)
        key, target = StateKey("in", context), StateKey("out", context)
        packets = source.vector("current", "protocol").equals(6)
        guard = source._wrap(packets)
        relation = PacketRelation.rewrite(source, {"destination_port": 443}).compose(
            PacketRelation.rewrite(source, {"source_port": 1234})
        )
        model = AnalysisModel(
            MANIFEST,
            "f" * 64,
            source.universe(),
            (
                CompiledNode(
                    key,
                    (CompiledEdge("edge", target, guard, source.empty(), relation, (("scope", "choice"),)),),
                    (("deny", source.empty()),),
                    True,
                    (),
                ),
                CompiledNode(target, (), (("permit", source.universe()),), True, ()),
            ),
            (CompiledEntry(key, guard, source.empty(), ()),),
            (ChoiceAssignment("choice", (("scope", "choice"),)),),
            True,
        )
        encoded = encode_model(model, binding(source))
    with SymbolicManager(HeaderSchema(4)) as target_manager:
        decoded = decode_model(encoded, target_manager, binding(target_manager))
        assert decoded.fingerprint == "f" * 64
        assert len(decoded.nodes[0].edges[0].relation._steps) == 2
        assert (
            decoded.nodes[0]
            .edges[0]
            .guard.equivalent(target_manager._wrap(target_manager.vector("current", "protocol").equals(6)))
        )


def test_binding_and_content_corruption_are_rejected_before_replay():
    with SymbolicManager(HeaderSchema(4)) as manager:
        model = AnalysisModel(MANIFEST, "f" * 64, manager.universe(), (), (), (), True)
        expected = binding(manager)
        encoded = encode_model(model, expected)
        with pytest.raises(ModelCodecError, match="binding"):
            decode_model(encoded, manager, binding(manager, estate="other"))
        document = json.loads(encoded)
        document["metadata"]["fingerprint"] = "0" * 64
        with pytest.raises(ModelCodecError, match="digest"):
            decode_model(
                json.dumps(document, sort_keys=True, separators=(",", ":")).encode(), manager, expected
            )
