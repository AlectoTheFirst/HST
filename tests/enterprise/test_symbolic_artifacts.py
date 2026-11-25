"""Portable decision-DAG artifacts use the native CUDD API only after preflight."""

from __future__ import annotations

import hashlib
import importlib
import json
import os

import pytest

from hst.symbolic import HeaderSchema, PacketRelation, SymbolicManager, header, initial_relation
from hst.symbolic.artifacts import (
    ArtifactLimits,
    SymbolicArtifactError,
    decode_packet_sets,
    encode_packet_sets,
)

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for backend qualification")


def _document(data: bytes) -> dict:
    return json.loads(data)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _redigest(document: dict) -> bytes:
    content = {key: value for key, value in document.items() if key != "digest"}
    document["digest"] = hashlib.sha256(_canonical(content)).hexdigest()
    return _canonical(document)


def _roots(manager: SymbolicManager):
    request = header(manager, {"protocol": 6, "source_port": [80, 443], "ecn": [1, 3]})
    paired = PacketRelation.rewrite(manager, {"destination_port": 8443}).image(initial_relation(request))
    all_banks = paired.intersect(paired.rename(from_bank="current", to_bank="next"))
    return {
        "projected": request.project(["ecn"]),
        "request": request,
        "relation": all_banks,
    }


def test_packet_set_artifact_round_trips_all_banks_knowledge_and_projected_roots() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as source:
        roots = _roots(source)
        first = encode_packet_sets(roots)
        second = encode_packet_sets(dict(reversed(tuple(roots.items()))))
        assert first == second
        document = _document(first)
        assert document["complete"] is True
        assert document["family"] == 4
        assert document["schema_version"] == source.schema.schema_version
        assert document["ordering_version"] == source.schema.ordering_version
        assert (
            document["digest"]
            == hashlib.sha256(
                _canonical({key: value for key, value in document.items() if key != "digest"})
            ).hexdigest()
        )

        with SymbolicManager(HeaderSchema.ipv4()) as target:
            decoded = decode_packet_sets(first, target)
            expected = _roots(target)
            assert tuple(decoded) == ("projected", "relation", "request")
            for name, original in roots.items():
                assert decoded[name].known_fields == original.known_fields
                assert decoded[name].equivalent(expected[name])
            assert decoded["relation"].cardinality(["source_port"], bank="original") == 2
            assert decoded["relation"].cardinality(["source_port"], bank="current") == 2
            assert decoded["relation"].cardinality(["source_port"], bank="next") == 2
            assert decoded["projected"].cardinality(["ecn"]) == 2


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda body: body.__setitem__("complete", False), "incomplete"),
        (lambda body: body.__setitem__("family", 6), "address family"),
        (lambda body: body.__setitem__("variables", list(reversed(body["variables"]))), "ordering"),
        (lambda body: body["nodes"][0].__setitem__("variable", "invented_variable"), "unknown variable"),
        (lambda body: body["nodes"][0]["low"].__setitem__("node", 1), "invalid node reference"),
        (lambda body: body["nodes"][1]["low"].__setitem__("node", 1), "variable order"),
        (lambda body: body["nodes"][0]["low"].__setitem__("complement", 0), "boolean"),
        (lambda body: body.__setitem__("complete", 1), "incomplete"),
    ],
)
def test_artifact_preflight_rejects_incompatible_and_malformed_dags_without_native_nodes(
    mutate, message
) -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        data = encode_packet_sets(_roots(manager))
        document = _document(data)
        mutate(document)
        malformed = _redigest(document)
        before = len(manager._bdd)
        with pytest.raises(SymbolicArtifactError, match=message):
            decode_packet_sets(malformed, manager)
        assert len(manager._bdd) == before


def test_artifact_detects_corruption_and_rejects_noncanonical_json() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        data = encode_packet_sets(_roots(manager))
        corrupted = _document(data)
        corrupted["nodes"][0]["variable"] = "corrupted_variable"
        with pytest.raises(SymbolicArtifactError, match="digest mismatch"):
            decode_packet_sets(_canonical(corrupted), manager)
        with pytest.raises(SymbolicArtifactError, match="not canonical"):
            decode_packet_sets(data + b"\n", manager)


def test_artifact_rejects_noncanonical_dag_records() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        data = encode_packet_sets({"current": header(manager, {"protocol": 6})})
        complemented = _document(data)
        complemented["nodes"][0]["high"]["complement"] = True
        with pytest.raises(SymbolicArtifactError, match="complement-normalized"):
            decode_packet_sets(_redigest(complemented), manager)

        duplicate = _document(data)
        copied = dict(duplicate["nodes"][0])
        copied["id"] = len(duplicate["nodes"]) + 1
        duplicate["nodes"].append(copied)
        with pytest.raises(SymbolicArtifactError, match="duplicate"):
            decode_packet_sets(_redigest(duplicate), manager)

        unreachable = _document(data)
        unreachable["nodes"].append(
            {
                "high": {"complement": False, "node": 0},
                "id": len(unreachable["nodes"]) + 1,
                "low": {"complement": True, "node": 0},
                "variable": "o_protocol_0",
            }
        )
        with pytest.raises(SymbolicArtifactError, match="unreachable"):
            decode_packet_sets(_redigest(unreachable), manager)


def test_artifact_limits_apply_to_bytes_nodes_and_roots() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        roots = _roots(manager)
        data = encode_packet_sets(roots)
        with pytest.raises(SymbolicArtifactError, match="root count"):
            encode_packet_sets(roots, limits=ArtifactLimits(max_roots=2))
        with pytest.raises(SymbolicArtifactError, match="node count"):
            encode_packet_sets(roots, limits=ArtifactLimits(max_nodes=1))
        with pytest.raises(SymbolicArtifactError, match="byte length"):
            decode_packet_sets(data, manager, limits=ArtifactLimits(max_bytes=len(data) - 1))
        with pytest.raises(SymbolicArtifactError, match="byte length"):
            decode_packet_sets(
                memoryview(bytearray(data)), manager, limits=ArtifactLimits(max_bytes=len(data) - 1)
            )
        document = _document(data)
        with pytest.raises(SymbolicArtifactError, match="node count"):
            decode_packet_sets(_redigest(document), manager, limits=ArtifactLimits(max_nodes=1))
        with pytest.raises(SymbolicArtifactError, match="root count"):
            decode_packet_sets(_redigest(document), manager, limits=ArtifactLimits(max_roots=2))
        before = len(manager._bdd)
        with pytest.raises(SymbolicArtifactError, match="node count"):
            encode_packet_sets(roots, limits=ArtifactLimits(max_nodes=1))
        assert len(manager._bdd) == before


def test_artifact_rejects_schema_mismatch_and_invalid_public_input() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as source:
        data = encode_packet_sets(_roots(source))
        with (
            SymbolicManager(HeaderSchema.ipv6()) as target,
            pytest.raises(SymbolicArtifactError, match="address family"),
        ):
            decode_packet_sets(data, target)
        with pytest.raises(ValueError, match="max_nodes"):
            ArtifactLimits(max_nodes=True)
        with pytest.raises(TypeError, match="roots"):
            encode_packet_sets([("root", source.empty())])  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="bytes"):
            decode_packet_sets("not bytes", source)  # type: ignore[arg-type]


def test_decoding_keeps_no_construction_roots_after_manager_close() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as source:
        data = encode_packet_sets(_roots(source))
    target = SymbolicManager(HeaderSchema.ipv4())
    decoded = decode_packet_sets(data, target)
    assert decoded
    target.close()
    assert len(target._bdd) == 0


def test_iterative_encoding_handles_an_ipv6_assignment_over_every_bank_bit() -> None:
    with SymbolicManager(HeaderSchema.ipv6()) as source:
        node = source._bdd.true
        for variable in source.schema.variables:
            node &= source._bdd.var(variable)
        all_banks = source._wrap(node, source.schema.field_names)
        data = encode_packet_sets({"all_banks": all_banks})
        assert len(_document(data)["nodes"]) == len(source.schema.variables)

        with SymbolicManager(HeaderSchema.ipv6()) as target:
            decoded = decode_packet_sets(data, target)["all_banks"]
            for bank in ("original", "current", "next"):
                assert decoded.cardinality(["source_address"], bank=bank) == 1


def test_excessively_nested_json_is_an_artifact_error() -> None:
    nested = b"[" * 10_000 + b"0" + b"]" * 10_000
    with (
        SymbolicManager(HeaderSchema.ipv4()) as manager,
        # Python versions differ in whether their JSON decoder accepts this
        # depth. Either parsing or document-shape validation must reject it
        # through the artifact API's typed exception.
        pytest.raises(SymbolicArtifactError),
    ):
        decode_packet_sets(nested, manager)
