"""Exhaust all subsets of a small domain against plain concrete membership."""

from __future__ import annotations

import importlib
import os

import pytest

from hst.symbolic import HeaderSchema, PacketRelation, SymbolicManager, header, initial_relation

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for backend qualification")


def _values(packets):
    rendered = packets.render(["ecn"], limit=4)
    assert not rendered.truncated
    return {row["ecn"] for row in rendered.rows}


def test_every_pair_of_subsets_matches_concrete_set_algebra():
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        concrete = [{value for value in range(4) if mask & (1 << value)} for mask in range(16)]
        symbolic = [header(manager, {"ecn": sorted(values)}) for values in concrete]
        for values, packets in zip(concrete, symbolic, strict=True):
            assert packets.cardinality(["ecn"]) == len(values)
            assert _values(packets.complement()) == set(range(4)) - values
            for other_values, other in zip(concrete, symbolic, strict=True):
                assert _values(packets.union(other)) == values | other_values
                assert _values(packets.intersect(other)) == values & other_values
                assert _values(packets.subtract(other)) == values - other_values


def test_every_subset_matches_concrete_rewrite_image_preimage_and_original_pairs():
    with SymbolicManager(HeaderSchema.ipv6()) as manager:
        # Clear the low bit, retaining the high bit: 0->0, 1->0, 2->2, 3->2.
        rewrite = PacketRelation.prefix_rewrite(
            manager, "ecn", match_value=0, match_mask=0, set_value=0, set_mask=1
        )
        next_rewrite = PacketRelation.rewrite(manager, {"ecn": 3})
        composed = rewrite.compose(next_rewrite)
        for mask in range(16):
            values = {value for value in range(4) if mask & (1 << value)}
            packets = header(manager, {"ecn": sorted(values)})
            assert _values(rewrite.image(packets)) == {value & 2 for value in values}
            assert _values(rewrite.preimage(packets)) == {value for value in range(4) if value & 2 in values}
            assert _values(composed.image(packets)) == ({3} if values else set())
            assert _values(composed.preimage(packets)) == (set(range(4)) if 3 in values else set())
        relation = rewrite.image(initial_relation(header(manager, {"ecn": (0, 3)})))
        for original in range(4):
            original_slice = relation.intersect(header(manager, {"ecn": original}, bank="original"))
            assert _values(original_slice) == {original & 2}
