from __future__ import annotations

import gc
import os

import pytest
from tests.enterprise.oracle import (
    apply,
    enumerate_headers,
    freeze,
    intersect,
    project,
    select,
    subtract,
    union,
)

from hst.symbolic import (
    BackendUnavailableError,
    CompiledGate,
    HeaderSchema,
    ManagerClosedError,
    ManagerMismatchError,
    MaskedValue,
    PacketRelation,
    RequiredDimensionsUnknownError,
    SymbolicManager,
    SymbolicState,
    header,
    initial_relation,
)


@pytest.fixture
def manager():
    native = _native_manager(HeaderSchema.ipv4())
    yield native
    native.close()


def _native_manager(schema: HeaderSchema) -> SymbolicManager:
    try:
        return SymbolicManager(schema)
    except BackendUnavailableError as exc:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail(str(exc))
        pytest.skip(str(exc))


def _rows(packet_set, fields, *, bank="current", limit=256):
    rendered = packet_set.render(fields, bank=bank, limit=limit)
    assert not rendered.truncated
    return frozenset(freeze(row) for row in rendered.rows)


def test_schema_has_fixed_interleaved_msb_first_order() -> None:
    schema = HeaderSchema.ipv6()
    assert schema.width("src_ip") == 128
    assert schema.field_names == (
        "protocol",
        "source_address",
        "destination_address",
        "source_port",
        "destination_port",
        "tcp_flags",
        "icmp_type",
        "icmp_code",
        "dscp",
        "ecn",
        "fragment_offset",
        "more_fragments",
    )
    assert schema.variables[:6] == (
        "o_protocol_0",
        "c_protocol_0",
        "n_protocol_0",
        "o_protocol_1",
        "c_protocol_1",
        "n_protocol_1",
    )
    with pytest.raises(ValueError):
        HeaderSchema(True)
    with pytest.raises(ValueError):
        HeaderSchema(4.0)


def test_set_algebra_matches_independent_finite_oracle(manager) -> None:
    concrete = enumerate_headers({"protocol": [6, 17, 47], "dscp": [0, 1, 2, 3]})
    concrete_tcp_or_gre = select(concrete, lambda packet: packet["protocol"] in {6, 47})
    concrete_odd_dscp = select(concrete, lambda packet: packet["dscp"] in {1, 3})
    left = header(manager, {"protocol": [6, 47], "dscp": (0, 3)})
    right = header(manager, {"protocol": [6, 17, 47], "dscp": [1, 3]})
    fields = ["protocol", "dscp"]
    assert _rows(left.intersect(right), fields) == intersect(concrete_tcp_or_gre, concrete_odd_dscp)
    assert _rows(left.subtract(right), fields) == subtract(concrete_tcp_or_gre, concrete_odd_dscp)
    assert _rows(left.union(right), fields) == union(concrete_tcp_or_gre, concrete_odd_dscp)


def test_complement_is_relative_to_valid_headers(manager) -> None:
    tcp = header(manager, {"protocol": 6})
    other_protocols = tcp.complement()
    assert other_protocols.cardinality(["protocol"]) == 255
    assert tcp.intersect(other_protocols).is_empty()
    assert tcp.union(other_protocols).equivalent(manager.universe())


def test_exact_count_is_arbitrary_precision_and_ipv6_high_bits_are_exact() -> None:
    manager = _native_manager(HeaderSchema.ipv6())
    high_bit = 1 << 127
    selected = header(
        manager,
        {"source_address": MaskedValue(high_bit, high_bit | 1)},
    )
    assert selected.cardinality(["source_address"]) == 1 << 126
    assert header(manager, {"source_address": high_bit}).cardinality(["source_address"]) == 1
    manager.close()


def test_exact_count_accepts_reversed_fields_and_complemented_roots(manager) -> None:
    six = header(manager, {"protocol": [6, 17], "dscp": [1, 2, 3]})
    assert six.cardinality(["dscp", "protocol"]) == 6
    one_dscp = header(manager, {"dscp": 1})
    assert one_dscp.complement().cardinality(["dscp"]) == 63


def test_non_contiguous_wildcard_and_projection_dedup_match_oracle(manager) -> None:
    packets = header(
        manager,
        {
            "protocol": [6, 17],
            "dscp": MaskedValue(0b100001, 0b100101),
        },
    )
    concrete = enumerate_headers({"protocol": [6, 17], "dscp": list(range(64))})
    expected = select(concrete, lambda packet: packet["dscp"] & 0b100101 == 0b100001)
    assert _rows(packets, ["protocol", "dscp"]) == expected
    assert _rows(packets.project(["dscp"]), ["dscp"]) == project(expected, ["dscp"])
    assert packets.cardinality(["dscp"]) == 8


def test_unstated_and_explicit_all_have_same_set_but_different_knowledge(manager) -> None:
    unknown = header(manager)
    explicit = header(manager, explicitly_all=["destination_port"])
    assert unknown.equivalent(explicit)
    assert "destination_port" not in unknown.known_fields
    assert "destination_port" in explicit.known_fields
    filtered = unknown.intersect(header(manager, {"destination_port": 443}).as_predicate())
    assert filtered.known_fields == frozenset()
    assert manager.empty().union(explicit).known_fields == explicit.known_fields
    assert explicit.union(manager.empty()).known_fields == explicit.known_fields


def test_bounded_rendering_never_silently_claims_completeness(manager) -> None:
    three = header(manager, {"dscp": [1, 2, 3]})
    rendered = three.render(["dscp"], limit=2)
    assert len(rendered.rows) == 2
    assert rendered.truncated
    assert three.cardinality(["dscp"]) == 3


def test_image_preimage_and_composition_preserve_original_request(manager) -> None:
    request = header(manager, {"protocol": 6, "source_port": (10, 12)})
    state = initial_relation(request)
    first = PacketRelation.rewrite(manager, {"source_port": 100})
    second = PacketRelation.rewrite(manager, {"destination_port": 443})
    result = first.compose(second).image(state)
    assert _rows(result, ["source_port"], bank="original") == frozenset(
        freeze({"source_port": port}) for port in (10, 11, 12)
    )
    assert _rows(result, ["source_port", "destination_port"]) == frozenset(
        {freeze({"source_port": 100, "destination_port": 443})}
    )
    target = header(manager, {"protocol": 6, "source_port": 100})
    assert first.preimage(target).cardinality(["source_port"]) == 1 << 16


def test_prefix_rewrite_and_exact_inverse_match_concrete_transition(manager) -> None:
    originals = [0x0A000001, 0x0A0000FE]
    request = initial_relation(header(manager, {"protocol": 6, "source_address": originals}))
    relation = PacketRelation.prefix_rewrite(
        manager,
        "source_address",
        match_value=0x0A000000,
        match_mask=0xFFFFFF00,
        set_value=0xC0000200,
    )
    image = relation.image(request)
    concrete = enumerate_headers({"source_address": originals})
    expected = apply(
        concrete,
        lambda packet: {"source_address": 0xC0000200 | (packet["source_address"] & 0xFF)},
    )
    assert _rows(image, ["source_address"]) == expected
    assert _rows(image, ["source_address"], bank="original") == concrete
    target = header(manager, {"protocol": 6, "source_address": [0xC0000201, 0xC00002FE]})
    assert _rows(relation.preimage(target), ["source_address"]) == concrete

    composed = relation.compose(PacketRelation.rewrite(manager, {"destination_port": 443}))
    expected_composed = apply(expected, lambda packet: {**packet, "destination_port": 443})
    assert _rows(composed.image(request), ["source_address", "destination_port"]) == expected_composed


def test_bank_rename_is_exact(manager) -> None:
    current = header(manager, {"protocol": [6, 17]})
    successor = current.rename(from_bank="current", to_bank="next")
    assert successor.cardinality(["protocol"], bank="next") == 2


def test_explicit_empty_state_knowledge_cannot_inherit_packet_knowledge(manager) -> None:
    packets = header(manager, {"protocol": 6, "destination_port": 443})
    gate = CompiledGate(
        PacketRelation.identity(manager),
        "permit",
        required_dimensions=frozenset({"destination_port"}),
    )
    inherited = SymbolicState(packets, "edge")
    assert gate.apply(inherited)
    explicitly_unknown = SymbolicState(packets, "edge", knowledge_mask=frozenset())
    with pytest.raises(RequiredDimensionsUnknownError):
        gate.apply(explicitly_unknown)


def test_filter_relation_matches_the_oracle(manager) -> None:
    concrete = enumerate_headers({"protocol": [6, 17], "dscp": [0, 1, 2]})
    request = header(manager, {"protocol": [6, 17], "dscp": (0, 2)})
    only_tcp = PacketRelation.filter(header(manager, {"protocol": 6}))
    actual = only_tcp.image(request)
    assert _rows(actual, ["protocol", "dscp"]) == select(concrete, lambda packet: packet["protocol"] == 6)


def test_manager_mismatch_is_rejected_and_close_invalidates_handles() -> None:
    left_manager = _native_manager(HeaderSchema.ipv4())
    right_manager = _native_manager(HeaderSchema.ipv4())
    left = header(left_manager, {"protocol": 6})
    right = header(right_manager, {"protocol": 6})
    with pytest.raises(ManagerMismatchError):
        left.union(right)
    with pytest.raises(ManagerMismatchError):
        PacketRelation.rewrite(left_manager, {}, guard=right)
    left_manager.close()
    assert len(left_manager._bdd) == 0
    with pytest.raises(ManagerClosedError):
        left.is_empty()
    right_manager.close()
    assert len(right_manager._bdd) == 0
    del left, right
    gc.collect()


def test_exact_counter_rejects_an_unprojected_dag(manager) -> None:
    packets = header(manager, {"protocol": 6, "dscp": 1})
    with pytest.raises(ValueError, match="not projected"):
        manager._exact_count(packets._node, manager.schema.bits("current", "protocol"))
