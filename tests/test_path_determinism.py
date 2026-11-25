"""Determinism and L3-domain containment in the tracer."""

# ruff: noqa: F811

import pytest
from tests.conftest import path_package_strings
from tests.test_path_nat import _nat_row
from tests.test_path_trace import GW, FakeGraph, _route, _src_row, graph  # noqa: F401

from hst import path

# --- L1: unordered LIMIT 1 ---------------------------------------------------------------


def test_every_limit_1_query_in_the_module_is_ordered():
    """Every LIMIT 1 query string of the path package carries an ORDER BY."""
    limited = [s for s in path_package_strings() if "LIMIT 1" in s]
    assert limited, "expected LIMIT 1 queries in the path package"
    unordered = [s for s in limited if "ORDER BY" not in s]
    assert not unordered, f"LIMIT 1 without ORDER BY: {unordered}"


@pytest.fixture()
def recording_graph(monkeypatch):
    """FakeGraph plus a transcript of every query the trace issued."""
    g = FakeGraph()
    seen: list[str] = []

    def read(session, query, **p):
        seen.append(query)
        return g.read(query, **p)

    def read_one(session, query, **p):
        seen.append(query)
        return g.read_one(query, **p)

    monkeypatch.setattr(path, "_read", read)
    monkeypatch.setattr(path, "_read_one", read_one)
    g.seen_all = seen
    return g


def test_a_full_trace_issues_only_ordered_limit_1_reads(recording_graph):
    g = recording_graph
    g.sources = [_src_row()]
    g.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0", next_hop="10.0.0.1")]}
    g.nat = [_nat_row(translation="masquerade", out_if="eth0")]
    g.iface_addrs = {"if:eth0": "203.0.113.1"}
    g.wan = {"uid": "wan:1", "name": "dia"}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    assert result["legs"], "scenario must produce a leg to be representative"

    limited = [q for q in g.seen_all if "LIMIT 1" in q]
    for fragment in (
        "IN_VRF]-(i:Interface {uid: $if_uid})",  # default/PBR-fallback table, no name filter
        "HAS_LINK",  # WAN link for the default route
    ):
        assert any(fragment in q for q in limited), f"scenario did not issue {fragment} lookup"
    # The trace picks a WireGuard peer by its allowed IPs.
    tunnel_reads = [q for q in g.seen_all if "Tunnel:Obj)-[e:ENDPOINT]" in q]
    assert tunnel_reads, "scenario did not issue the tunnel lookup"
    assert all("ORDER BY uid" in q and "LIMIT" not in q for q in tunnel_reads), "tunnel read picks by row"
    # The trunk lookup returns every switch port cabled to the router port in one row.
    trunk_reads = [q for q in g.seen_all if "REALIZED_BY" in q and "AS peers" in q]
    assert trunk_reads, "scenario did not issue the trunk lookup"
    assert all("ORDER BY" in q and "LIMIT" not in q for q in trunk_reads), "trunk read picks by row"
    address_reads = [q for q in g.seen_all if "RETURN addresses[0] AS ip" in q]
    assert address_reads
    assert all("size(addresses) = 1" in q and "$af" in q for q in address_reads)
    unordered = [q for q in limited if "ORDER BY" not in q]
    assert not unordered, f"unordered LIMIT 1 issued during trace: {unordered}"
    # A single-owner pick is the first row of the next-hop device read.
    nh_reads = [q for q in g.seen_all if "AS dev_uid" in q and "HAS_IP" in q]
    assert nh_reads, "scenario did not issue the next-hop device lookup"
    assert all("ORDER BY" in q for q in nh_reads), "unordered next-hop device read"


# --- L2: cross-domain LPM ----------------------------------------------------------------


def test_overlapping_prefixes_in_isolated_domains_fail_closed(graph):
    """Prefix length cannot order isolated domains."""
    gws = [
        GW,  # 10.0.0.0/24 in home
        {
            **GW,
            "cidr": "10.0.0.0/16",
            "l3dom": "lab",
            "if_uid": "if:lab1",
            "if_name": "lab1",
            "dev_uid": "dev:r2",
            "dev_name": "r2",
        },
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.0/24", "8.8.8.8", gateways=gws)

    assert result["legs"] == []
    assert result["indeterminate"] is True
    assert result["ambiguous_domains"] == ["home", "lab"]
    assert "ambiguous" in result["verdict"]
    assert any("isolated" in w for w in result["warnings"])
    # neither domain's gateway was drawn: no arbitrary winner
    assert not any(h["kind"] == "Device" for h in result["hops"])


def test_a_network_trace_is_scoped_when_one_domain_holds_the_prefix(graph):
    gws = [
        GW,  # 10.0.0.0/24 in home
        {
            **GW,
            "cidr": "192.168.0.0/16",
            "l3dom": "lab",
            "if_uid": "if:lab1",
            "if_name": "lab1",
            "dev_uid": "dev:r2",
            "dev_name": "r2",
        },
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.0/24", "8.8.8.8", gateways=gws)

    assert result["legs"][0]["verdict"] == "egress via eth0"
    assert {h["uid"] for h in result["hops"] if h["kind"] == "Device"} == {"dev:r1"}
    assert any("scoped" in n for n in result["notes"])


# --- L3: delivery must not cross an isolation boundary -----------------------------------


def _dst_row(dom, ep, port_uid):
    return {
        **_src_row(dom=dom, ip="10.0.0.9"),
        "ep_uid": ep,
        "ep_name": "host9",
        "att_uid": port_uid,
        "att_name": "9",
        "att_is_port": True,
        "sw_uid": f"dev:sw-{dom}",
        "sw_name": f"sw-{dom}",
    }


def test_the_delivery_leg_does_not_borrow_an_attachment_from_another_domain(graph):
    """10.0.0.9 is attached only in `lab`; the trace runs in `home`. The flow
    must be reported undelivered, not drawn to the lab endpoint."""
    graph.sources_by_ip = {
        "10.0.0.5": [_src_row()],
        "10.0.0.9": [_dst_row("lab", "ep:lab9", "port:lab9")],
    }
    result = path.trace(None, "10.0.0.5", "10.0.0.9", gateways=[GW])

    leg = result["legs"][0]
    assert leg["verdict"] == "switched in 10.0.0.0/24"
    assert leg["delivered"] is False
    uids = {h["uid"] for h in result["hops"]}
    assert "ep:lab9" not in uids and "port:lab9" not in uids
    assert any("no attachment" in w for w in result["warnings"])


def test_a_same_domain_attachment_delivers(graph):
    graph.sources_by_ip = {
        "10.0.0.5": [_src_row()],
        "10.0.0.9": [_dst_row("home", "ep:home9", "port:home9")],
    }
    result = path.trace(None, "10.0.0.5", "10.0.0.9", gateways=[GW])

    leg = result["legs"][0]
    assert leg["delivered"] is True
    uids = {h["uid"] for h in result["hops"]}
    assert {"ep:home9", "port:home9"} <= uids
