"""A connected row in the RIB side table is the device's own statement that
it holds a prefix the graph already has as ORIGINATES."""

from __future__ import annotations

from hst.path.addrsets import _intervals, _to_cidrs
from hst.path.gates.routing import _route_partition


def _origin(cidr):
    """An ORIGINATES route as `trace.py` `_ROUTES_QUERY` returns it: no next
    hop, and no egress, because a connected prefix has no VIA edge."""
    return {
        "uid": f"pfx:{cidr}",
        "cidr": cidr,
        "kind": "ORIGINATES",
        "next_hop": None,
        "ifname": None,
        "egress_uid": None,
        "egress_name": None,
        "derived": None,
        "via_rt": None,
        "rib": None,
        "next_hop_vrf": None,
        "discard": None,
    }


def _store_row(prefix, protocol, interface="eth1", next_hop=None):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "interface": interface,
        "protocol": protocol,
        "discard": None,
        "metric": 0,
    }


def _lookup(rows):
    """The `(lpm, overlapping)` pair `_route_partition` reads: every row
    covers the probe here, and no more specific row splits the part."""
    return (lambda probe: rows, lambda lo, hi, minlen, af: [])


def test_a_connected_store_row_folds_onto_the_originates_route_of_its_prefix():
    origin = _origin("192.168.1.0/24")
    parts = _route_partition(
        [origin], _intervals(["192.168.1.7"]), rib_lookup=_lookup([_store_row("192.168.1.0/24", "connected")])
    )
    assert len(parts) == 1
    _part, winners = parts[0]
    assert [w["kind"] for w in winners] == ["ORIGINATES"], "one leg, not a graph route plus a store copy"
    assert origin["rib"] is True, "the device's own row confirms the route"
    assert origin["egress_name"] is None, "the egress stays resolved from GATEWAY_FOR"


def test_the_fold_reads_every_collector_word_for_connected():
    for word in ("connected", "C", "direct", "directly connected"):
        origin = _origin("10.0.0.0/24")
        parts = _route_partition(
            [origin], _intervals(["10.0.0.9"]), rib_lookup=_lookup([_store_row("10.0.0.0/24", word)])
        )
        assert [w["kind"] for w in parts[0][1]] == ["ORIGINATES"], word


def test_a_store_row_that_is_not_connected_still_joins_as_its_own_route():
    """The fold is for connected rows only."""
    origin = _origin("192.168.1.0/24")
    parts = _route_partition(
        [origin],
        _intervals(["192.168.1.7", "10.9.0.5"]),
        rib_lookup=_lookup([_store_row("10.9.0.0/24", "static", interface="eth2", next_hop="192.168.1.254")]),
    )
    by_part = {tuple(_to_cidrs(part)): sorted(w["cidr"] for w in winners) for part, winners in parts}
    assert by_part[("192.168.1.7/32",)] == ["192.168.1.0/24"]
    assert by_part[("10.9.0.5/32",)] == ["10.9.0.0/24"]
    assert origin["rib"] is None
