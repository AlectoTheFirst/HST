"""Carrier-grade NAT (NAT444) and DS-Lite (IPv4-in-IPv6 to an AFTR) through the engine.

The walker, the RIB, the NAT transition and the tunnel leg builder are the
real ones; only the graph read behind the firewall verdicts is replaced, and
every filter passes. The endpoints of each request share a family (IPv4);
only the DS-Lite carrier differs (IPv6).
"""

from dataclasses import dataclass, replace

import pytest

from hst.collectors.vyos import _TUNNEL_CARRIER_PROTO
from hst.impact import Interface, Member, Network, RequestSet, Service, answer, member
from hst.path.addrsets import _intervals, _ports
from hst.path.gates.nat import NatTransition
from hst.path.gates.tunnel import build_carrier_legs
from hst.path.state import Effect
from hst.simul.rib import RibInput

PUBLIC = "192.0.2.1/32"
POOL = "192.0.2.0/28"
SERVER = "198.51.100.10"


def ips(spec):
    return tuple(_intervals([spec]))


@dataclass
class Verdict:
    kind: str = "pass"

    def apply(self, region):
        return [(region, Effect(self.kind, "firewall", terminal=self.kind == "deny"))]


def source_nat(match_src, xlate):
    """Source NAT of a private range onto public address(es)."""
    return NatTransition(
        [
            {
                "uid": "nat:cgn",
                "match_src": list(ips(match_src)),
                "match_dst": [],
                "rewrite": "src",
                "xlate": list(ips(xlate)),
                "src_port_spec": None,
                "xlate_src_port_spec": None,
                "protos": [],
                "port_spec": None,
            }
        ],
        complete_service=True,
    )


class Gates:
    """Every filter passes; source NAT runs on one named device's egress."""

    def __init__(self, nat_device, nat_egress, match_src, legs=(), xlate=PUBLIC):
        self.nat_device = nat_device
        self.nat_egress = nat_egress
        self.match_src = match_src
        self.legs = legs
        self.xlate = xlate

    def dnat(self, device, ingress):
        return Verdict()

    def filter(self, device, ingress, egress):
        return Verdict()

    def reply_filter(self, device, ingress, egress, established):
        return Verdict()

    def local_filter(self, device, ingress):
        return Verdict()

    def output_filter(self, device, egress):
        return Verdict()

    def load_balancer(self, device, address):
        return None

    def snat(self, device, ingress, egress):
        if device == self.nat_device and egress is not None and egress.name == self.nat_egress:
            return source_nat(self.match_src, self.xlate)
        return Verdict()

    def tunnels(self, egress, inner):
        rows = [row for row in self.legs if row["local_interface_uid"] == egress.uid]
        return build_carrier_legs(rows, inner) if rows else ()


def build(interfaces, static, gates):
    contexts = [
        {"uid": c, "device_uid": d, "platform": "vyos"}
        for d, c in sorted({(i.device_uid, i.context_uid) for i in interfaces})
    ]
    connected = [
        {"context_uid": i.context_uid, "prefix": p, "interface": i.name}
        for i in interfaces
        for p in i.prefixes
    ]
    return Network(
        RibInput(contexts=contexts, connected=connected, static=static),
        tuple(interfaces),
        gates,
        context_domains={i.context_uid: frozenset({"declared:estate"}) for i in interfaces},
    )


def request(client, success="session"):
    return RequestSet(
        "app",
        ips(client),
        "app",
        (Member("server", ips(SERVER)),),
        member("server"),
        Service(frozenset({6}), tuple(_ports("443")), tuple(_ports("40000"))),
        success=success,
    )


def steps(result):
    return [s for e in result.members["server"].explanations for s in e.steps]


# --- CGNAT / NAT444 -------------------------------------------------------------------------


def cgnat_network(xlate=PUBLIC, returns=POOL):
    """client 100.64.1.10 -> cgn (SNAT on its uplink) -> isp -> server.

    The ISP router only knows the public side; 100.64.0.0/10 is not routable
    beyond the CGN, so the reply can only return through the translation.
    """
    interfaces = [
        Interface("cgn", "if:cgn-sub", "sub", "c:cgn", ("100.64.1.0/24",), ("100.64.1.1",)),
        Interface("cgn", "if:cgn-up", "up", "c:cgn", ("203.0.113.0/30",), ("203.0.113.1",)),
        Interface("isp", "if:isp-dn", "dn", "c:isp", ("203.0.113.0/30",), ("203.0.113.2",)),
        Interface("isp", "if:isp-srv", "srv", "c:isp", ("198.51.100.0/24",), ("198.51.100.1",)),
    ]
    static = [
        {"context_uid": "c:cgn", "prefix": "0.0.0.0/0", "next_hop": "203.0.113.2"},
        {"context_uid": "c:isp", "prefix": returns, "next_hop": "203.0.113.1"},
    ]
    return build(interfaces, static, Gates("cgn", "up", "100.64.0.0/10", xlate=xlate))


def test_cgnat_session_is_reachable_through_the_translation():
    req = request("100.64.1.10")
    result = answer(cgnat_network(), req)
    assert result.lower == result.upper == req.sources
    trail = steps(result)
    assert any(s.stage == "snat" and s.kind == "rewrite" and s.device_uid == "cgn" for s in trail)
    assert any(s.stage == "reply-nat" and s.kind == "inverse" and s.device_uid == "cgn" for s in trail)


def test_cgnat_without_the_translation_never_returns():
    class NoNat(Gates):
        def snat(self, device, ingress, egress):
            return Verdict()

    net = replace(cgnat_network(), gates=NoNat("cgn", "up", "100.64.0.0/10"))
    req = request("100.64.1.10")
    assert answer(net, request("100.64.1.10", "forward")).lower == req.sources
    assert not answer(net, req).upper


def test_cgnat_address_pool_is_proven_when_every_pool_address_works():
    # Which pool address a client gets is not collected.
    for client in ("100.64.1.10", "100.64.1.0/24"):
        req = request(client)
        result = answer(cgnat_network(POOL), req)
        assert result.lower == result.upper == req.sources
        trail = steps(result)
        assert any(s.stage == "snat" and s.kind == "rewrite" and s.device_uid == "cgn" for s in trail)
        assert any(s.stage == "reply-nat" and s.kind == "inverse" and s.device_uid == "cgn" for s in trail)


def test_cgnat_address_pool_with_some_addresses_unreachable_is_not_established():
    # Replies reach only half of the pool.
    req = request("100.64.1.10")
    result = answer(cgnat_network(POOL, returns="192.0.2.0/29"), req)
    assert not result.lower
    assert result.upper == req.sources
    assert all(
        "not determined through the translation" in e.missing[0]
        for e in result.members["server"].explanations
    )


# --- DS-Lite: B4 -> IPv6-only core -> AFTR ---------------------------------------------------


def _softwire(local, remote, *, state="up"):
    """One half of the B4/AFTR softwire as the tunnel query returns it, with the
    encap and carrier protocol the VyOS collector writes for `ipip6`."""
    ends = {
        "b4": ("2001:db8:1::2", "if:b4-sw", "c:b4", "if:b4-wan"),
        "aftr": ("2001:db8:2::2", "if:aftr-sw", "c:aftr", "if:aftr-core"),
    }
    l_addr, l_if, l_ctx, l_wan = ends[local]
    r_addr, r_if, r_ctx, r_wan = ends[remote]
    return {
        "tunnel_uid": f"tun:ipip6:{local}",
        "encap": "ipip6",
        "binding_kind": "endpoint",
        "state": state,
        "allowed_ips": None,
        "local_address": l_addr,
        "remote_address": r_addr,
        "carrier_proto": _TUNNEL_CARRIER_PROTO["ipip6"],
        "carrier_port": None,
        "local_device_uid": local,
        "local_interface_uid": l_if,
        "local_context_uid": l_ctx,
        "local_underlay_interface_uid": l_wan,
        "local_underlay_context_uid": l_ctx,
        "remote_device_uid": remote,
        "remote_interface_uid": r_if,
        "remote_context_uid": r_ctx,
        "remote_underlay_interface_uid": r_wan,
        "remote_underlay_context_uid": r_ctx,
        "peer_tunnel_uid": f"tun:ipip6:{remote}",
    }


def dslite_network(*, tunnel=True, drop=(), **leg_options):
    """client 192.168.1.10 -> b4 =ipip6=> (IPv6-only core) => aftr (NAT44) -> isp -> server.

    The two softwire ends are on different segments: the IPv4 softwire exists
    only inside the tunnel, never as a shared link."""
    sw = "192.0.0.0/29"
    interfaces = [
        # B4 (home router): IPv4 LAN, IPv6 WAN, IPv4 softwire; it does no NAT
        Interface("b4", "if:b4-lan", "lan", "c:b4", ("192.168.1.0/24",), ("192.168.1.1",)),
        Interface("b4", "if:b4-wan", "wan", "c:b4", ("2001:db8:1::/64",), ("2001:db8:1::2",)),
        Interface("b4", "if:b4-sw", "sw", "c:b4", (sw,), ("192.0.0.2",), segments=("seg:b4-sw",)),
        # provider core: IPv6 only, no IPv4 address or route anywhere
        Interface("core", "if:core-a", "a", "c:core", ("2001:db8:1::/64",), ("2001:db8:1::1",)),
        Interface("core", "if:core-b", "b", "c:core", ("2001:db8:2::/64",), ("2001:db8:2::1",)),
        # AFTR: IPv6 core side, IPv4 softwire, IPv4 uplink carrying the NAT44
        Interface("aftr", "if:aftr-core", "core", "c:aftr", ("2001:db8:2::/64",), ("2001:db8:2::2",)),
        Interface("aftr", "if:aftr-sw", "sw", "c:aftr", (sw,), ("192.0.0.1",), segments=("seg:aftr-sw",)),
        Interface("aftr", "if:aftr-up", "up", "c:aftr", ("203.0.113.0/30",), ("203.0.113.1",)),
        Interface("isp", "if:isp-dn", "dn", "c:isp", ("203.0.113.0/30",), ("203.0.113.2",)),
        Interface("isp", "if:isp-srv", "srv", "c:isp", ("198.51.100.0/24",), ("198.51.100.1",)),
    ]
    static = [
        {"context_uid": "c:b4", "prefix": "0.0.0.0/0", "next_hop": "192.0.0.1"},
        {"context_uid": "c:b4", "prefix": "::/0", "next_hop": "2001:db8:1::1"},
        {"context_uid": "c:aftr", "prefix": "2001:db8:1::/64", "next_hop": "2001:db8:2::1"},
        {"context_uid": "c:aftr", "prefix": "0.0.0.0/0", "next_hop": "203.0.113.2"},
        {"context_uid": "c:aftr", "prefix": "192.168.1.0/24", "next_hop": "192.0.0.2"},
        {"context_uid": "c:isp", "prefix": POOL, "next_hop": "203.0.113.1"},
    ]
    static = [r for r in static if (r["context_uid"], r["prefix"]) not in drop]
    legs = (_softwire("b4", "aftr", **leg_options), _softwire("aftr", "b4", **leg_options)) if tunnel else ()
    return build(interfaces, static, Gates("aftr", "up", "192.168.1.0/24", legs))


def test_dslite_session_is_reachable_over_the_ipv6_softwire():
    req = request("192.168.1.10")
    result = answer(dslite_network(), req)
    assert result.lower == result.upper == req.sources
    trail = steps(result)
    # one softwire crossing each way, the inner packet resumed at the far end
    decaps = [s.device_uid for s in trail if s.stage == "tunnel" and s.kind == "decapsulate"]
    assert decaps == ["aftr", "b4"]
    # the core forwards only the IPv6 carrier, never the IPv4 inner packet
    core = [s for s in trail if s.device_uid == "core"]
    assert core and all(s.stage.startswith("carrier/") for s in core)
    assert any(s.stage == "carrier/route" and "2001:db8:2::/64" in s.detail for s in core)
    # NAT44 happens at the AFTR, after decapsulation, and the reply undoes it there
    assert any(s.stage == "snat" and s.kind == "rewrite" and s.device_uid == "aftr" for s in trail)
    assert any(s.stage == "reply-nat" and s.kind == "inverse" and s.device_uid == "aftr" for s in trail)
    assert not any(s.stage == "snat" and s.kind == "rewrite" and s.device_uid == "b4" for s in trail)


def test_dslite_ipv4_cannot_cross_without_the_softwire():
    result = answer(dslite_network(tunnel=False), request("192.168.1.10"))
    assert not result.lower
    # the walk stops at the B4: the AFTR's softwire address is not on any link it has
    ends = [e.steps[-1] for e in result.members["server"].explanations]
    assert ends and all(s.device_uid == "b4" and s.kind == "other-scope" for s in ends)


def test_dslite_depends_on_the_ipv6_carrier_in_both_directions():
    req = request("192.168.1.10")
    assert not answer(dslite_network(drop={("c:b4", "::/0")}), req).lower
    no_return = dslite_network(drop={("c:aftr", "2001:db8:1::/64")})
    assert not answer(no_return, req).lower
    # forward delivery alone still holds without the reverse carrier route
    assert answer(no_return, request("192.168.1.10", "forward")).lower == req.sources


def test_dslite_down_softwire_fails():
    assert not answer(dslite_network(state="down"), request("192.168.1.10")).upper


def test_an_ipv6_host_never_reaches_an_ipv4_server_directly():
    with pytest.raises(ValueError, match="address family"):
        replace(request("192.168.1.10"), sources=ips("2001:db8:1::10"))
