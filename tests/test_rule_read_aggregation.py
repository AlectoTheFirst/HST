"""The rule reads aggregate each address side before the next is matched."""

from __future__ import annotations

import re
from itertools import pairwise

import pytest

from hst.app import simul_read
from hst.path.gates import firewall, local_zone, nat, pbr
from hst.simul import fw_overlay

_AGGREGATING_WITH = re.compile(r"^WITH\b.*?\bcollect\(", re.M | re.S)


def _sides_aggregated_in_turn(query: str, markers: list[str]) -> bool:
    """Whether an aggregating WITH stands between each side's match and the next."""
    at = [query.index(m) for m in markers]
    assert at == sorted(at), "the sides are matched in the order named"
    return all(_AGGREGATING_WITH.search(query[a:b]) for a, b in pairwise(at))


@pytest.mark.parametrize(
    ("query", "markers"),
    [
        (firewall._RULEBASE_RULES, ["OPTIONAL MATCH (r)-[:SRC]", "OPTIONAL MATCH (r)-[:DST]"]),
        (local_zone._LOCAL_RULES_QUERY, ["OPTIONAL MATCH (r)-[:SRC]", "OPTIONAL MATCH (r)-[:DST]"]),
        (
            pbr._PBR_RULE_ROWS,
            ["OPTIONAL MATCH (r)-[:SRC]", "OPTIONAL MATCH (r)-[:DST]", "OPTIONAL MATCH (r)-[:REDIRECTS_VIA]"],
        ),
        (
            simul_read._PBR_BINDINGS,
            ["OPTIONAL MATCH (r)-[:SRC]", "OPTIONAL MATCH (r)-[:DST]", "OPTIONAL MATCH (r)-[:REDIRECTS_VIA]"],
        ),
        (
            nat._NAT_RULES_QUERY,
            [
                "OPTIONAL MATCH (n)-[os:ORIG_SRC]",
                "OPTIONAL MATCH (n)-[od:ORIG_DST]",
                "OPTIONAL MATCH (n)-[xs:XLATE_SRC]",
                "OPTIONAL MATCH (n)-[xd:XLATE_DST]",
            ],
        ),
    ],
    ids=["firewall", "local-zone", "pbr", "simul-pbr", "nat"],
)
def test_each_address_side_is_aggregated_before_the_next_is_matched(query: str, markers: list[str]) -> None:
    assert _sides_aggregated_in_turn(query, markers)


def test_the_rule_read_keeps_the_header_the_overlay_and_the_local_read_rewrite() -> None:
    """Change simulation recognises the rules reads by their query constants,
    and the strict router-local read is derived from the rules read by
    replacing its header: a read it does not recognise would be answered
    with the unmodified rules."""
    rule_reads, _context = fw_overlay._gate_queries()
    assert {firewall._RULEBASE_RULES, local_zone._LOCAL_RULES_QUERY} <= rule_reads
    assert fw_overlay._Q_NAT_RULES in nat._NAT_RULES_QUERY
    assert local_zone._LOCAL_RULES_QUERY != firewall._RULEBASE_RULES


@pytest.mark.parametrize(
    ("query", "columns"),
    [
        (
            firewall._RULEBASE_RULES,
            [
                "src_cidrs",
                "src_ips",
                "src_ranges",
                "src_obj_count",
                "src_opaque",
                "src_opaque_reasons",
                "dst_cidrs",
                "dst_ips",
                "dst_ranges",
                "dst_obj_count",
                "dst_opaque",
                "dst_opaque_reasons",
            ],
        ),
        (
            pbr._PBR_RULE_ROWS,
            [
                "src_cidrs",
                "src_ips",
                "src_ranges",
                "dst_cidrs",
                "dst_ips",
                "dst_ranges",
                "addr_opaque_reasons",
            ],
        ),
        (
            nat._NAT_RULES_QUERY,
            [
                f"{side}_{column}"
                for side in ("orig_src", "orig_dst", "xlate_src", "xlate_dst")
                for column in ("present", "addrs", "opaque")
            ],
        ),
    ],
    ids=["firewall", "pbr", "nat"],
)
def test_the_rule_read_returns_every_address_column(query: str, columns: list[str]) -> None:
    returned = query[query.rindex("\nRETURN ") :]
    for column in columns:
        assert re.search(rf"\b{column}\b", returned), column


def test_a_rule_sides_addresses_are_parsed_once_however_often_it_is_judged(monkeypatch) -> None:
    """A rule is judged on every hop and lane it governs."""
    from hst.path import addrsets

    parses: list[list[str]] = []
    real = addrsets._intervals

    def counting(specs):
        parses.append(list(specs))
        return real(specs)

    monkeypatch.setattr(addrsets, "_intervals", counting)
    addrsets._parsed_rule_side.cache_clear()
    members = [f"10.1.{i // 256}.{i % 256}" for i in range(1000)]
    first = addrsets._rule_intervals_status(["10.0.0.0/24"], members, [["10.2.0.1-10.2.0.9"]])
    first[0].append((4, 0, 0))
    second = addrsets._rule_intervals_status(["10.0.0.0/24"], members, [["10.2.0.1-10.2.0.9"]])
    assert len(parses) == 1
    assert second == (real(["10.0.0.0/24", *members, "10.2.0.1-10.2.0.9"]), False)
    assert addrsets._rule_intervals_status([], ["not-an-address"], []) == ([], True)
