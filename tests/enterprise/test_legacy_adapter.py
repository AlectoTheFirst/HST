from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Literal, cast

import pytest

from hst.path.state import FlowRegion, Rect
from hst.symbolic import (
    BackendUnavailableError,
    Bank,
    HeaderSchema,
    MaskedValue,
    SymbolicManager,
    header,
    initial_relation,
)
from hst.symbolic.legacy_adapter import (
    LegacyAdapterLimits,
    LegacyFamilyError,
    LegacyKnowledgeError,
    LegacyLimitError,
    LegacyOriginError,
    LegacyRepresentationError,
    flow_region_to_packet_set,
    packet_set_to_flow_region,
    partial_flow_region,
)


def _manager(family: Literal[4, 6]) -> SymbolicManager:
    try:
        return SymbolicManager(HeaderSchema(family))
    except BackendUnavailableError as exc:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail(str(exc))
        pytest.skip(str(exc))


@pytest.fixture
def manager() -> Iterator[SymbolicManager]:
    native = _manager(4)
    yield native
    native.close()


def _rect(
    *,
    src: tuple[tuple[int, int, int], ...] = ((4, 1, 1),),
    dst: tuple[tuple[int, int, int], ...] = ((4, 10, 10),),
    proto: frozenset[int] | None = frozenset({6}),
    dport: tuple[tuple[int, int, int], ...] | None = ((0, 80, 80),),
    sport: tuple[tuple[int, int, int], ...] | None = None,
) -> Rect:
    return Rect(4, src, dst, proto, dport, sport)


def _render(packet_set, fields: list[str]) -> set[tuple[int, ...]]:
    rendered = packet_set.render(fields, limit=256)
    assert not rendered.truncated
    return {tuple(row[field] for field in fields) for row in rendered.rows}


def test_finite_overlaps_and_correlations_import_and_roundtrip_exactly(manager) -> None:
    region = FlowRegion(
        (
            _rect(src=((4, 1, 3),)),
            _rect(src=((4, 3, 4),)),
            _rect(src=((4, 1, 1),), dst=((4, 20, 20),), proto=frozenset({17}), dport=((0, 53, 53),)),
        )
    )
    packets = flow_region_to_packet_set(manager, region)
    fields = ["source_address", "destination_address", "protocol", "destination_port"]
    assert _render(packets, fields) == {
        (1, 10, 6, 80),
        (2, 10, 6, 80),
        (3, 10, 6, 80),
        (4, 10, 6, 80),
        (1, 20, 17, 53),
    }

    returned = packet_set_to_flow_region(packets)
    reimported = flow_region_to_packet_set(manager, returned)
    assert reimported.equivalent(packets)
    assert reimported.known_fields == packets.known_fields
    assert len(returned.rects) == 2


def test_none_and_explicit_all_service_dimensions_remain_distinct(manager) -> None:
    unknown = flow_region_to_packet_set(
        manager,
        FlowRegion((_rect(proto=None, dport=None),)),
    )
    assert unknown.known_fields == frozenset({"source_address", "destination_address"})
    unknown_region = packet_set_to_flow_region(unknown)
    assert all(rect.proto is None for rect in unknown_region)

    explicit_cases = (
        (_rect(proto=frozenset(range(256)), dport=None), "protocol", "proto"),
        (_rect(proto=None, dport=((0, 0, 65535),)), "destination_port", "dport"),
        (
            _rect(proto=None, dport=None, sport=((0, 0, 65535),)),
            "source_port",
            "sport",
        ),
    )
    for rect, field, attribute in explicit_cases:
        explicit = flow_region_to_packet_set(manager, FlowRegion((rect,)))
        assert unknown.equivalent(explicit)
        assert explicit.known_fields == unknown.known_fields | {field}
        explicit_region = packet_set_to_flow_region(explicit)
        assert all(getattr(part, attribute) is not None for part in explicit_region)
        assert flow_region_to_packet_set(manager, explicit_region).equivalent(explicit)


def test_import_rejects_fully_and_partly_validity_invalid_explicit_tuples(manager) -> None:
    with pytest.raises(LegacyRepresentationError, match="validity removes explicitly stated"):
        flow_region_to_packet_set(
            manager,
            FlowRegion((_rect(proto=frozenset({47}), dport=((0, 443, 443),)),)),
        )

    with pytest.raises(LegacyRepresentationError, match="validity removes explicitly stated"):
        flow_region_to_packet_set(
            manager,
            FlowRegion((_rect(proto=frozenset({6, 47}), dport=((0, 443, 443),)),)),
        )

    epistemic_protocol = flow_region_to_packet_set(
        manager,
        FlowRegion((_rect(proto=None, dport=((0, 443, 443),)),)),
    )
    assert "protocol" not in epistemic_protocol.known_fields
    assert epistemic_protocol.cardinality(["destination_port"]) == 1


def test_invalid_bank_is_rejected_even_for_empty_inputs(manager) -> None:
    invalid = cast(Bank, "invalid")
    with pytest.raises(ValueError, match="unknown header bank"):
        flow_region_to_packet_set(manager, FlowRegion(), bank=invalid)
    with pytest.raises(ValueError, match="unknown header bank"):
        packet_set_to_flow_region(manager.empty(), bank=invalid)


def test_ipv6_large_intervals_are_not_expanded() -> None:
    manager = _manager(6)
    try:
        lower = 1 << 127
        upper = lower + (1 << 96) - 1
        region = FlowRegion(
            (
                Rect(
                    6,
                    ((6, lower, upper),),
                    ((6, 0, (1 << 128) - 1),),
                    None,
                    None,
                    None,
                ),
            )
        )
        packets = flow_region_to_packet_set(manager, region)
        assert packets.cardinality(["source_address"]) == 1 << 96
        returned = packet_set_to_flow_region(packets)
        assert returned == region
    finally:
        manager.close()


def test_incompatible_address_and_port_families_are_rejected(manager) -> None:
    with pytest.raises(LegacyFamilyError, match="rectangle family"):
        flow_region_to_packet_set(
            manager,
            FlowRegion((Rect(6, ((6, 1, 1),), ((6, 2, 2),), None, None, None),)),
        )
    with pytest.raises(LegacyFamilyError, match="interval family"):
        flow_region_to_packet_set(manager, FlowRegion((_rect(src=((6, 1, 1),)),)))
    with pytest.raises(LegacyFamilyError, match="required family 0"):
        flow_region_to_packet_set(manager, FlowRegion((_rect(dport=((4, 80, 80),)),)))


def test_origin_without_an_exact_relation_is_rejected(manager) -> None:
    original = _rect(src=((4, 1, 2),), dst=((4, 10, 10),))
    rewritten = original.rewrite(src=((4, 100, 101),))
    with pytest.raises(LegacyOriginError, match="without an exact"):
        flow_region_to_packet_set(manager, FlowRegion.single(rewritten))


def test_mixed_rectangle_knowledge_masks_are_rejected(manager) -> None:
    mixed = FlowRegion(
        (
            _rect(src=((4, 1, 1),), proto=frozenset({6})),
            _rect(src=((4, 2, 2),), proto=None),
        )
    )
    with pytest.raises(LegacyKnowledgeError, match="different stated"):
        flow_region_to_packet_set(manager, mixed)


def test_reverse_rejects_extra_predicates_and_original_correlations(manager) -> None:
    addresses = {
        "source_address": (0, (1 << 32) - 1),
        "destination_address": (0, (1 << 32) - 1),
    }
    extra = header(manager, {**addresses, "dscp": 7})
    with pytest.raises(LegacyKnowledgeError, match="dscp"):
        packet_set_to_flow_region(extra)

    hidden_extra = extra.with_knowledge(addresses)
    with pytest.raises(LegacyRepresentationError, match="extra header field"):
        packet_set_to_flow_region(hidden_extra)

    correlated = initial_relation(flow_region_to_packet_set(manager, FlowRegion((_rect(),))))
    with pytest.raises(LegacyRepresentationError, match="another bank"):
        packet_set_to_flow_region(correlated)


def test_reverse_can_prove_a_validity_implied_extra_predicate_safe(manager) -> None:
    maximum = (1 << 32) - 1
    gre_with_canonical_zero_flags = header(
        manager,
        {
            "source_address": (0, maximum),
            "destination_address": (0, maximum),
            "protocol": 47,
            "tcp_flags": 0,
        },
    ).with_knowledge({"source_address", "destination_address", "protocol"})
    returned = packet_set_to_flow_region(gre_with_canonical_zero_flags)
    assert all(rect.proto == frozenset({47}) for rect in returned)
    assert flow_region_to_packet_set(manager, returned).equivalent(gre_with_canonical_zero_flags)


def test_unstated_service_constraint_is_not_silently_dropped(manager) -> None:
    packets = flow_region_to_packet_set(manager, FlowRegion((_rect(proto=None, dport=None),)))
    constrained = packets.intersect(header(manager, {"protocol": 6}).as_predicate())
    assert "protocol" not in constrained.known_fields
    with pytest.raises(LegacyRepresentationError, match="unstated service field"):
        packet_set_to_flow_region(constrained)


def test_reverse_limits_fail_without_returning_partial_regions(manager) -> None:
    correlated = flow_region_to_packet_set(
        manager,
        FlowRegion(
            (
                _rect(src=((4, 1, 1),), dst=((4, 10, 10),)),
                _rect(src=((4, 2, 2),), dst=((4, 20, 20),)),
            )
        ),
    )
    with pytest.raises(LegacyLimitError) as rectangles:
        packet_set_to_flow_region(
            correlated,
            limits=LegacyAdapterLimits(max_rectangles=1),
        )
    assert rectangles.value.limit == "max_rectangles"

    with pytest.raises(LegacyLimitError) as paths:
        packet_set_to_flow_region(
            correlated,
            limits=LegacyAdapterLimits(max_bdd_paths=1),
        )
    assert paths.value.limit == "max_bdd_paths"

    maximum = (1 << 32) - 1
    low_bit_mask = header(
        manager,
        {
            "source_address": MaskedValue(0, 1),
            "destination_address": (0, maximum),
        },
    )
    with pytest.raises(LegacyLimitError) as intervals:
        packet_set_to_flow_region(
            low_bit_mask,
            limits=LegacyAdapterLimits(max_intervals_per_dimension=2),
        )
    assert intervals.value.limit == "max_intervals_per_dimension"

    with pytest.raises(LegacyLimitError) as visits:
        packet_set_to_flow_region(
            correlated,
            limits=LegacyAdapterLimits(max_bdd_visits=1),
        )
    assert visits.value.limit == "max_bdd_visits"

    three_correlations = flow_region_to_packet_set(
        manager,
        FlowRegion(
            (
                _rect(src=((4, 1, 1),), dst=((4, 10, 10),)),
                _rect(src=((4, 2, 2),), dst=((4, 20, 20),)),
                _rect(src=((4, 3, 3),), dst=((4, 30, 30),)),
            )
        ),
    )
    with pytest.raises(LegacyLimitError) as merges:
        packet_set_to_flow_region(
            three_correlations,
            limits=LegacyAdapterLimits(max_merge_attempts=1),
        )
    assert merges.value.limit == "max_merge_attempts"


def test_empty_symbolic_knowledge_cannot_fit_an_empty_flow_region(manager) -> None:
    assert packet_set_to_flow_region(manager.empty()) == FlowRegion()
    assert flow_region_to_packet_set(manager, FlowRegion()).equivalent(manager.empty())
    empty = manager.empty(known_fields={"source_address", "destination_address"})
    with pytest.raises(LegacyKnowledgeError, match="empty FlowRegion"):
        packet_set_to_flow_region(empty)


def test_limits_require_positive_real_integers() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        LegacyAdapterLimits(max_rectangles=0)
    with pytest.raises(ValueError, match="positive integer"):
        LegacyAdapterLimits(max_bdd_paths=True)


def test_a_partial_listing_is_exact_disjoint_pieces_and_counts_them_all(manager) -> None:
    region = FlowRegion(
        (
            _rect(src=((4, 1, 3),)),
            _rect(src=((4, 7, 9),), dst=((4, 20, 21),), proto=frozenset({17}), dport=((0, 53, 54),)),
        )
    )
    packets = flow_region_to_packet_set(manager, region)

    whole, pieces = partial_flow_region(packets, max_rectangles=10_000)
    first, counted = partial_flow_region(packets, max_rectangles=1)

    assert counted == pieces == len(whole.rects) > 1
    assert len(first.rects) == 1
    parts = [flow_region_to_packet_set(manager, FlowRegion((rect,))) for rect in whole.rects]
    union = parts[0]
    for index, part in enumerate(parts):
        assert part.subtract(packets).is_empty()
        for other in parts[index + 1 :]:
            assert part.intersect(other).is_empty()
        union = union.union(part)
    assert union.equivalent(packets)
    assert flow_region_to_packet_set(manager, first).subtract(packets).is_empty()
