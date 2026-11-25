from __future__ import annotations

import importlib
import os

import pytest

from hst.symbolic import HeaderSchema, SymbolicManager, header, initial_relation
from hst.symbolic.transforms import (
    constant_translation,
    exact_range_translation,
    prefix_translation,
    unknown_pool_allocation,
)

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for transformation tests")


@pytest.fixture
def manager():
    owned = SymbolicManager(HeaderSchema.ipv4())
    with owned:
        yield owned
    assert len(owned._bdd) == 0


def _values(packets, field: str, *, bank: str = "current") -> set[int]:
    return {row[field] for row in packets.render([field], bank=bank, limit=64).rows}


def test_constant_and_prefix_translations_preserve_identity_and_untouched_fields(manager) -> None:
    request = initial_relation(
        header(
            manager,
            {
                "protocol": 6,
                "source_address": [0x0A000001, 0x0A0000FE],
                "destination_port": 443,
                "dscp": 7,
            },
        )
    )
    translated = (
        prefix_translation(manager, "source_address", "10.0.0.0/24", "192.0.2.0/24")
        .compose(constant_translation(manager, "destination_port", 8443))
        .image(request)
    )

    assert _values(translated, "source_address") == {0xC0000201, 0xC00002FE}
    assert _values(translated, "source_address", bank="original") == {0x0A000001, 0x0A0000FE}
    assert _values(translated, "destination_port") == {8443}
    assert _values(translated, "dscp") == {7}


def test_range_translation_matches_independent_offset_oracle(manager) -> None:
    relation = exact_range_translation(manager, "source_port", 1000, 1003, 4000)
    request = initial_relation(header(manager, {"protocol": 17, "source_port": (1000, 1003)}))
    image = relation.image(request)
    actual: set[tuple[int, int]] = set()
    for original in range(1000, 1004):
        paired = image.intersect(header(manager, {"source_port": 4000 + original - 1000}))
        if original in _values(paired, "source_port", bank="original"):
            actual.add((original, 4000 + original - 1000))
    assert actual == {(value, 4000 + value - 1000) for value in range(1000, 1004)}


def test_unknown_pool_allocation_and_invalid_prefix_are_explicit(manager) -> None:
    boundary = unknown_pool_allocation()
    assert boundary.status == "unknown"
    assert boundary.alternatives == ()
    assert boundary.gap_code == "NAT_POOL_ALLOCATION_UNKNOWN"
    with pytest.raises(ValueError, match="equal prefix lengths"):
        prefix_translation(manager, "source_address", "10.0.0.0/24", "192.0.2.0/25")


def test_range_translation_supports_negative_delta(manager) -> None:
    relation = exact_range_translation(manager, "source_port", 4000, 4003, 1000)
    request = initial_relation(header(manager, {"protocol": 6, "source_port": (4000, 4003)}))
    image = relation.image(request)
    assert _values(image, "source_port") == {1000, 1001, 1002, 1003}
    for original in range(4000, 4004):
        paired = image.intersect(header(manager, {"source_port": original - 3000}))
        assert _values(paired, "source_port", bank="original") == {original}


def test_huge_range_is_one_exact_relation_without_enumeration(manager) -> None:
    relation = exact_range_translation(manager, "source_address", 0, (1 << 24) - 1, 1 << 24)
    request = initial_relation(header(manager, {"protocol": 17, "source_address": (0, (1 << 24) - 1)}))
    image = relation.image(request)
    assert image.cardinality(["source_address"]) == 1 << 24
    assert _values(
        image.intersect(header(manager, {"source_address": [1 << 24, (1 << 25) - 1]})),
        "source_address",
    ) == {1 << 24, (1 << 25) - 1}


def test_ipv6_high_values_translate_exactly_with_negative_delta() -> None:
    manager = SymbolicManager(HeaderSchema.ipv6())
    with manager:
        source_low = (1 << 128) - 0x100
        relation = exact_range_translation(
            manager, "destination_address", source_low, source_low + 3, source_low - 0x1000
        )
        request = initial_relation(
            header(manager, {"protocol": 17, "destination_address": (source_low, source_low + 3)})
        )
        image = relation.image(request)
        assert image.cardinality(["destination_address"]) == 4
        assert _values(image, "destination_address") == {source_low - 0x1000 + offset for offset in range(4)}
    assert len(manager._bdd) == 0


def test_range_rewrite_rejects_inversion_and_overflow(manager) -> None:
    with pytest.raises(ValueError, match="reversed"):
        exact_range_translation(manager, "source_port", 2, 1, 10)
    with pytest.raises(ValueError, match="exceeds"):
        exact_range_translation(manager, "source_port", 1, 10, 65530)
