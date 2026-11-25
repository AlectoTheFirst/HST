import pytest
from tests.support.query_text import unpinned
from tests.test_path_trace import FakeGraph, _route, _src_row, record_reads

from hst import path

BR = {
    "cidr": "10.0.0.0/24",
    "l3dom": "corp",
    "if_uid": "if:br-lan",
    "if_name": "users",
    "dev_uid": "dev:br",
    "dev_name": "branch-1",
}
CE = {"dev_uid": "dev:ce", "dev_name": "ce-1", "if_uid": "if:ce-in", "if_name": "Gi0/0"}
HUB_WAN = {
    "dev_uid": "dev:hub",
    "dev_name": "hub-1",
    "if_uid": "if:hub-ge1",
    "if_name": "GE1",
    "anchor": "vrf:hub-global",
}
CORE = {"dev_uid": "dev:core", "dev_name": "core-1", "if_uid": "if:core-in", "if_name": "Vlan10"}

MPLS = "tun:br-mpls"
DIA = "tun:br-dia"


class SdwanGraph(FakeGraph):
    """FakeGraph plus the SD-WAN reads, keyed the way the queries ask."""

    def __init__(self):
        super().__init__()
        self.boundaries: dict[tuple[str, str], dict] = {}
        self.candidate_tunnels: dict[tuple[str, str], list[dict]] = {}
        self.bgp_neighbors: dict[tuple[str, str], list[dict]] = {}
        self.far_prefixes: dict[str, list[dict]] = {}
        self.tunnels: dict[str, dict] = {}
        self.tunnel_props_by_uid: dict[str, dict] = {}
        self.local_vrf_by_dev: dict[str, dict] = {}
        self.wan_next_hop: dict[str, dict] = {}
        self.provider_by_if: dict[str, dict] = {}
        self.far_owner: dict[str, dict] = {}
        self.far_owner_by_node: dict[str, dict] = {}
        self.segment_if: dict[tuple[str, str], dict] = {}
        # the tunnels on an interface's ENDPOINT edge, with their far end
        # address, for the egress lookup that names no tunnel
        self.endpoint_tunnels: dict[str, list[dict]] = {}
        # trace._FAR_OVERLAY_QUERY: device uid -> its own Tunnels and the
        # overlay interface each ends on
        self.far_overlay: dict[str, list[dict]] = {}

    def _endpoint_rows(self, query, params):
        # the ENDPOINT arm: a VCMP tunnel only when its far end is the next hop
        return [
            t
            for t in sorted(self.endpoint_tunnels[params["u"]], key=lambda t: t["uid"])
            if "far.ip = $far" not in query
            or t.get("encap") != "velocloud-vcmp"
            or t.get("far_ip") == params.get("far")
        ]

    def read(self, query, **params):
        query = unpinned(query)
        # the egress tunnel lookup returns every candidate
        tunnel_read = "Tunnel {source_ip: ip.ip}" in query and not params.get("tunnel")
        if tunnel_read and params.get("u") in self.endpoint_tunnels:
            return self._endpoint_rows(query, params)
        if "peer.allowed_ips AS allowed_ips" in query:
            return [r for r in self.far_overlay.get(params["dev"], []) if r["peer_uid"] != params["tunnel"]]
        if "CARRIES]->(seg:SdwanSegment" in query:
            return self.candidate_tunnels.get((params["dev"], params["seg"]), [])
        if "HAS]->(s:BgpSession)" in query and "connected" in query:
            return self.bgp_neighbors.get((params["dev"], params["vrf"]), [])
        if "fdev.uid IN $devs" in query:
            return [row for d in params["devs"] for row in self.far_prefixes.get(d, [])]
        return super().read(query, **params)

    def read_one(self, query, **params):
        query = unpinned(query)
        if "HAS_BOUNDARY" in query:
            return self.boundaries.get((params["dev"], params["vrf"]))
        if "Tunnel {source_ip: ip.ip}" in query and params.get("tunnel"):
            return self.tunnels.get(params["tunnel"])
        if "Tunnel {source_ip: ip.ip}" in query and params.get("u") in self.endpoint_tunnels:
            rows = self._endpoint_rows(query, params)
            return rows[0] if rows else None
        if "MATCH (t:Tunnel {uid: $uid})" in query:
            return self.tunnel_props_by_uid.get(params["uid"])
        if "v.is_global = true" in query:
            return self.local_vrf_by_dev.get(params["dev"], self.local_vrf)
        if "i.next_hop AS next_hop" in query:
            return self.wan_next_hop.get(params["u"])
        if "PROVIDED_BY]->(pn:ProviderNetwork)" in query:
            return self.provider_by_if.get(params["u"])
        if "coalesce(ip.l3dom, v.name) AS l3dom" in query:
            # by the far node (its uid ends in the address) or by the address
            if "far" in params:
                if params["far"] in self.far_owner_by_node:
                    return self.far_owner_by_node[params["far"]]
                return self.far_owner.get(params["far"].rsplit(":", 1)[-1])
            return self.far_owner.get(params["ip"])
        if "v.table_id = $segment_id OR v.name = $segment_name" in query:
            return self.segment_if.get((params["dev"], params["segment_name"]))
        return super().read_one(query, **params)


@pytest.fixture()
def graph(monkeypatch):
    g = SdwanGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


def _tunnel_row(uid, egress, far_ip, link_kind, preferred=()):
    return {
        "uid": uid,
        "name": uid,
        "encap": "velocloud-vcmp",
        "state": "STABLE",
        "peer_type": "edge",
        "egress_uid": f"if:{egress}",
        "egress_name": egress,
        "far_uid": f"ip:hub:{far_ip}",
        "far_ip": far_ip,
        "far_name": None,
        "far_kind": "IpAddress",
        "far_dev": "dev:hub",
        "far_dev_name": "hub-1",
        "far_role": "hub",
        "link_uid": f"wan:br:{link_kind}",
        "link_kind": link_kind,
        "link_name": link_kind,
        "preferred_for": list(preferred),
    }


def _overlay(graph):
    """A branch edge with an MPLS and a DIA tunnel to the hub. The MPLS
    carrier crosses the operator's CE; the DIA carrier crosses a third-party
    ISP. The hub hands the inner flow to its BGP neighbor, the DC core, which
    serves the destination."""
    graph.sources = [_src_row(dom="corp")]
    graph.default_tables = {
        "if:br-lan": {"uid": "vrf:br-corp"},
        "if:ce-in": {"uid": "vrf:ce"},
        "if:hub-ge1": {"uid": "vrf:hub-global"},
        "if:hub-lan": {"uid": "vrf:hub-corp"},
        "if:core-in": {"uid": "vrf:core"},
    }
    graph.routes = {
        "vrf:br-corp": [],
        "vrf:br-global": [],
        "vrf:ce": [_route("172.16.9.0/30", egress="ce-out", next_hop="172.16.9.2")],
        "vrf:hub-global": [],
        # the hub's LAN prefix in the segment, as the collector writes it
        "vrf:hub-corp": [_route("10.9.9.0/24", egress="GE3", kind="ORIGINATES")],
        "vrf:core": [_route("10.50.0.0/24", egress="core-eth5")],
    }
    graph.boundaries = {
        ("dev:br", "vrf:br-corp"): {
            "boundary_uid": "fb:br-corp",
            "segment_uid": "seg:corp",
            "segment_name": "corp",
            "segment_id": "1",
            "complete": False,
            "reason": "VeloCloud dynamic path selection is opaque",
            "policy_uids": ["pol:br"],
            "role": None,
        },
        ("dev:hub", "vrf:hub-corp"): {
            "boundary_uid": "fb:hub-corp",
            "segment_uid": "seg:corp",
            "segment_name": "corp",
            "segment_id": "1",
            "complete": False,
            "reason": "VeloCloud dynamic path selection is opaque",
            "policy_uids": ["pol:hub"],
            "role": "hub",
        },
    }
    graph.candidate_tunnels = {
        ("dev:br", "seg:corp"): [
            _tunnel_row(MPLS, "GE1", "172.16.9.2", "mpls", preferred=("voice",)),
            _tunnel_row(DIA, "GE2", "203.0.113.2", "dia"),
        ]
    }
    graph.far_prefixes = {
        "dev:hub": [{"far_dev": "dev:hub", "cidr": "10.20.20.0/24", "prefix_uid": "pfx:hub-lan"}]
    }
    graph.bgp_neighbors = {
        ("dev:hub", "vrf:hub-corp"): [
            {
                "uid": "bgp:hub-core",
                "peer_ip": "10.9.9.2",
                "peer_asn": 65000,
                "connected": [
                    {
                        "if_uid": "if:hub-lan",
                        "if_name": "GE3",
                        "cidr": "10.9.9.0/24",
                        "prefix_uid": "pfx:hub:10.9.9.0/24",
                    }
                ],
            }
        ]
    }
    graph.tunnels = {
        MPLS: {"uid": MPLS, "name": "branch-1 GE1 to hub-1", "encap": "velocloud-vcmp"},
        DIA: {"uid": DIA, "name": "branch-1 GE2 to hub-1", "encap": "velocloud-vcmp"},
    }
    graph.tunnel_props_by_uid = {
        MPLS: {
            "endpoint": "172.16.9.2",
            "endpoint_port": 2426,
            "carrier_proto": "udp",
            "local_address": "172.16.1.2",
            "encap": "velocloud-vcmp",
            "far_ip": "172.16.9.2",
            "far_kind": "IpAddress",
            "far_uid": "ip:hub:172.16.9.2",
        },
        DIA: {
            "endpoint": "203.0.113.2",
            "endpoint_port": 2426,
            "carrier_proto": "udp",
            "local_address": "198.51.100.2",
            "encap": "velocloud-vcmp",
            "far_ip": "203.0.113.2",
            "far_kind": "IpAddress",
            "far_uid": "ip:hub:203.0.113.2",
        },
    }
    graph.local_vrf_by_dev = {"dev:br": {"vrf_uid": "vrf:br-global", "vrf_name": "Global Segment"}}
    graph.wan_next_hop = {
        "if:GE1": {"uid": "if:GE1", "name": "GE1", "next_hop": "172.16.1.1"},
        "if:GE2": {"uid": "if:GE2", "name": "GE2", "next_hop": "198.51.100.1"},
    }
    graph.provider_by_if = {
        "if:GE1": {
            "link_uid": "wan:br:mpls",
            "link_name": "mpls",
            "link_kind": "mpls",
            "provider_uid": "pnet:mpls:ournet",
            "provider_name": "OurNet",
            "provider_kind": "mpls",
        },
        "if:GE2": {
            "link_uid": "wan:br:dia",
            "link_name": "dia",
            "link_kind": "dia",
            "provider_uid": "pnet:internet:isp",
            "provider_name": "ThirdParty ISP",
            "provider_kind": "internet",
        },
    }
    graph.next_hop_devs = {"172.16.1.1": CE, "172.16.9.2": HUB_WAN, "10.9.9.2": CORE}
    # the WAN interfaces hold the carrier's own source: they are the underlay
    graph.iface_addrs = {"if:GE1": "172.16.1.2", "if:GE2": "198.51.100.2"}
    # the DIA carrier's far end: the hub's public address, held by the hub
    graph.far_owner = {
        "203.0.113.2": {**HUB_WAN, "if_uid": "if:hub-ge2", "if_name": "GE2", "l3dom": "global"}
    }
    graph.dev_addrs = {
        "dev:hub": [
            {"ip": "172.16.9.2", "ip_uid": "ip:hub:172.16.9.2", "if_uid": "if:hub-ge1", "if_name": "GE1"},
            {"ip": "203.0.113.2", "ip_uid": "ip:hub:203.0.113.2", "if_uid": "if:hub-ge2", "if_name": "GE2"},
        ]
    }
    graph.default_tables["if:hub-ge2"] = {"uid": "vrf:hub-global"}
    graph.segment_if = {
        ("dev:hub", "corp"): {
            "if_uid": "if:hub-lan",
            "if_name": "GE3",
            "vrf_uid": "vrf:hub-corp",
            "vrf_name": "corp",
        }
    }


def _lane_stages(result, lane):
    return [h["stage"] for h in sorted(result["hops"], key=lambda h: h["rank"]) if h["lane"] == lane]


def test_the_branch_edge_fans_out_over_its_candidate_tunnels(graph):
    _overlay(graph)
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])

    # two legs, one per candidate tunnel, and neither claims to be the decision
    assert len(result["legs"]) == 2
    assert all(leg["candidate_set"] for leg in result["legs"])
    assert all(leg["indeterminate"] for leg in result["legs"])
    boundary = [h for h in result["hops"] if h["kind"] == "ForwardingBoundary"]
    assert boundary and "2 candidate(s)" in boundary[0]["note"]
    assert any("the drawn candidates are not a decision" in n for n in result["notes"])
    # the encap hop names the link kind and the policy preference
    encaps = {h["label"]: h["note"] for h in result["hops"] if h["stage"] == "ENCAP"}
    assert encaps["branch-1 GE1 to hub-1"] == "velocloud-vcmp over mpls · policy prefers for voice"
    assert encaps["branch-1 GE2 to hub-1"] == "velocloud-vcmp over dia"
    # the boundary and the policy count as evaluated: no "not evaluated" gate
    assert not any("not evaluated" in w for w in result["warnings"])


def test_a_tunnel_with_more_than_one_far_end_is_warned(graph):
    _overlay(graph)
    overlay_read_one = graph.read_one

    def read_one(query, **params):
        row = overlay_read_one(query, **params)
        if "AS far_ends" in query and row:
            # the tunnel read itself counts the far ends
            ends = 3 if params["uid"] == MPLS else 1
            return {**row, "far_ends": ends, "far_sample": ["172.16.9.2", "172.16.9.6", "172.16.9.10"][:ends]}
        return row

    graph.read_one = read_one
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    warned = [w for w in result["warnings"] if "far ends" in w]
    assert len(warned) == 1
    assert warned[0].startswith("branch-1 GE1 to hub-1: the tunnel has 3 far ends (172.16.9.2, 172.16.9.6")


def test_a_direct_rule_adds_the_public_link_exit_beside_the_hub_tunnels(graph):
    _overlay(graph)
    overlay_read = graph.read

    def read(query, **params):
        if "sv.route_policy = 'direct'" in query:
            return [
                {
                    "egress_uid": "if:GE2",
                    "egress_name": "GE2",
                    "next_hop": "198.51.100.1",
                    "egress_vrf": "vrf:br-global",
                    "link_uid": "wan:br:dia",
                    "link_kind": "dia",
                    "link_name": "dia",
                    "direct_for": ["saas"],
                }
            ]
        return overlay_read(query, **params)

    graph.read = read
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    assert len(result["legs"]) == 3
    boundary = [h for h in result["hops"] if h["kind"] == "ForwardingBoundary"]
    assert "3 candidate(s)" in boundary[0]["note"]
    assert "the business policy sends some traffic direct" in boundary[0]["note"]
    # two legs encapsulate into the hub tunnels, the direct leg does not
    assert len([h for h in result["hops"] if h["stage"] == "ENCAP"]) == 2


def test_the_mpls_carrier_crosses_the_ce_and_the_inner_flow_resumes_on_the_hub(graph):
    _overlay(graph)
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])

    mpls_leg = next(leg for leg in result["legs"] if leg["carrier"]["endpoint"] == "172.16.9.2")
    carrier = mpls_leg["carrier"]
    # the edge has no route table: the carrier leaves by the WAN next hop
    assert carrier["egress"] == "GE1"
    assert any("toward its WAN next hop 172.16.1.1" in n for n in result["notes"])
    assert carrier["provider"] == "OurNet"
    assert "decapsulated on hub-1" in carrier["verdict"]
    assert carrier["arrival"]["verdict"].startswith("router-local, terminates on hub-1 GE1")
    assert not carrier["arrival"]["blocked"]
    assert mpls_leg["verdict"] == "egress via core-eth5"
    assert any(
        "no route of the hub covers the destination; next hop from the segment's BGP neighbor"
        in (h["note"] or "")
        for h in result["hops"]
    )
    assert any("resumes in segment corp (table corp)" in n for n in result["notes"])

    lane = mpls_leg["lane"]
    stages = _lane_stages(result, lane)
    assert stages.index("ENCAP") < stages.index("CARRIER_ROUTE") < stages.index("DECAP")
    # the carrier's hops are stamped with the tunnel they ride in; the inner
    # flow's hops on either side are not
    by_stage = {h["stage"]: h for h in result["hops"] if h["lane"] == lane}
    devices = [h for h in result["hops"] if h["lane"] == lane and h["kind"] == "Device"]
    assert {(h["label"], h.get("overlay", 0)) for h in devices} == {
        ("branch-1", 0),
        ("ce-1", 1),
        ("hub-1", 1),
        ("core-1", 0),
    }
    assert all(h.get("tunnel") == MPLS for h in devices if h.get("overlay"))
    assert by_stage["DECAP"]["kind"] == "Tunnel" and "hub-1" in by_stage["DECAP"]["note"]


def test_a_tie_on_the_carriers_next_hop_makes_the_leg_indeterminate(graph):
    _overlay(graph)
    graph.next_hop_devs["172.16.1.1"] = [
        {**CE, "anchor": "vrf:ce"},
        {
            "dev_uid": "dev:ce-b",
            "dev_name": "ce-2",
            "if_uid": "if:ce-b-in",
            "if_name": "Gi0/0",
            "anchor": "vrf:ce",
        },
    ]
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])

    mpls_leg = next(leg for leg in result["legs"] if leg["carrier"]["endpoint"] == "172.16.9.2")
    assert result["indeterminate"] and mpls_leg["indeterminate"]
    assert any(
        "carrier next hop 172.16.1.1 is held by ce-1 Gi0/0 and by ce-2 Gi0/0, the carrier is traced "
        "through ce-1 Gi0/0 only, and no record names the device that forwards" in w
        for w in result["warnings"]
    )


def test_the_dia_carrier_crosses_the_provider_cloud_to_the_hub(graph):
    _overlay(graph)
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])

    dia_leg = next(leg for leg in result["legs"] if leg["carrier"]["endpoint"] == "203.0.113.2")
    carrier = dia_leg["carrier"]
    assert carrier["provider"] == "ThirdParty ISP"
    cloud = [h for h in result["hops"] if h["kind"] == "ProviderNetwork"]
    assert cloud and cloud[0]["label"] == "ThirdParty ISP" and "not collected" in cloud[0]["note"]
    assert cloud[0].get("tunnel") == DIA
    # past the cloud the hub holds the far address and decapsulates
    assert "decapsulated on hub-1" in carrier["verdict"]
    assert dia_leg["verdict"] == "egress via core-eth5"
    assert not dia_leg["blocked"]
    # the lane reads as one walk: the client's hops and the core's hops share it
    lane = dia_leg["lane"]
    kinds = [(h["kind"], h["label"]) for h in result["hops"] if h["lane"] == lane]
    assert ("Device", "branch-1") in kinds or any(h["shared"] for h in result["hops"])
    assert ("Device", "core-1") in kinds


def test_a_destination_inside_another_edges_lan_takes_the_tunnel_to_that_edge(graph):
    _overlay(graph)
    result = path.trace(None, "10.0.0.5", "10.20.20.7", port=443, proto="tcp", gateways=[BR])
    assert any("destination is inside a LAN prefix of hub-1" in (h["note"] or "") for h in result["hops"])
    assert len(result["legs"]) == 2


def test_a_far_end_outside_the_twin_is_a_boundary_not_a_verdict(graph):
    _overlay(graph)
    graph.far_owner = {}
    graph.next_hop_devs.pop("172.16.9.2")
    graph.dev_addrs = {}
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    for leg in result["legs"]:
        assert leg["boundary"], leg
        assert "not" in leg["carrier"]["verdict"]
    assert result["boundary"]


def test_the_pure_ranking_prefers_a_lan_holder_then_the_hub_then_every_tunnel():
    from hst.path.gates import sdwan

    hub = _tunnel_row(MPLS, "GE1", "172.16.9.2", "mpls")
    spoke = {
        **_tunnel_row("tun:br-spoke", "GE1", "172.16.5.2", "mpls"),
        "far_dev": "dev:sp",
        "far_role": None,
    }
    dst = [
        (
            4,
            int(__import__("ipaddress").ip_address("10.20.20.7")),
            int(__import__("ipaddress").ip_address("10.20.20.7")),
        )
    ]
    chosen, why = sdwan.rank_candidates(
        [hub, spoke], [], [{"far_dev": "dev:hub", "cidr": "10.20.20.0/24"}], dst, role=None
    )
    assert chosen == [hub] and "LAN prefix" in why
    chosen, why = sdwan.rank_candidates([hub, spoke], [], [], dst, role=None)
    assert chosen == [hub] and "via the hub" in why
    chosen, why = sdwan.rank_candidates([spoke], [], [], dst, role=None)
    assert chosen == [spoke] and "every tunnel is a candidate" in why
    chosen, why = sdwan.rank_candidates([], [{"uid": "bgp:x", "peer_ip": "10.9.9.2"}], [], dst, role="hub")
    assert chosen and "BGP neighbor" in why
    # two edges holding the destination prefix: nothing is guessed
    chosen, why = sdwan.rank_candidates(
        [hub, spoke],
        [],
        [{"far_dev": "dev:hub", "cidr": "10.20.20.0/24"}, {"far_dev": "dev:sp", "cidr": "10.20.20.0/24"}],
        dst,
        role=None,
    )
    assert chosen == [] and "more than one edge" in why
    # a direct exit stands beside the hub tunnels, never in place of a LAN holder
    exit_ = {"egress_uid": "if:GE2", "direct_for": ["saas"]}
    chosen, why = sdwan.rank_candidates([hub, spoke], [], [], dst, role=None, direct=[exit_])
    assert chosen == [hub, exit_] and "sends some traffic direct" in why
    chosen, _ = sdwan.rank_candidates(
        [hub, spoke], [], [{"far_dev": "dev:hub", "cidr": "10.20.20.0/24"}], dst, role=None, direct=[exit_]
    )
    assert chosen == [hub]


# --- the Overlay Flow Control exit: the hub the route table names ----------------------

HUB2 = "tun:br-hub2"


def _hub2_row():
    return {
        **_tunnel_row(HUB2, "GE2", "203.0.113.66", "dia"),
        "far_uid": "ip:hub2:203.0.113.66",
        "far_dev": "dev:hub2",
        "far_dev_name": "hub-2",
    }


def _dst(ip):
    import ipaddress

    value = int(ipaddress.ip_address(ip))
    return [(4, value, value)]


class _SegmentRib:
    """A RibSource stand-in keyed by (device, table), answering the longest
    covering prefix the way `RibSource.lpm` does."""

    def __init__(self, rows):
        self.rows = rows
        self.asked: list[tuple[str, str]] = []

    def lpm(self, device_uid, context_uid, probe_ip, *, legacy_vrf=None):
        import ipaddress

        self.asked.append((device_uid, context_uid))
        probe = ipaddress.ip_address(probe_ip)
        covering = [
            r
            for r in self.rows.get((device_uid, context_uid), [])
            if probe in ipaddress.ip_network(r["prefix"], strict=False)
        ]
        if not covering:
            return []
        longest = max(ipaddress.ip_network(r["prefix"], strict=False).prefixlen for r in covering)
        return [r for r in covering if ipaddress.ip_network(r["prefix"], strict=False).prefixlen == longest]

    def overlapping(self, device_uid, context_uid, lo, hi, min_prefixlen, af, *, legacy_vrf=None):
        # a superset of the overlapping rows: every row of the family that is
        # longer than min_prefixlen; route_exits keeps the covering ones
        import ipaddress

        return [
            r
            for r in self.rows.get((device_uid, context_uid), [])
            if ipaddress.ip_network(r["prefix"], strict=False).version == af
            and ipaddress.ip_network(r["prefix"], strict=False).prefixlen > min_prefixlen
        ]


def _ofc_row(prefix, cost, next_hop="10.9.9.2"):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "interface": "GE3",
        "protocol": "bgp",
        "discard": None,
        "metric": cost,
        "prefixlen": int(prefix.split("/")[1]),
        "af": 4,
    }


def test_the_route_table_names_the_hub_and_the_other_hubs_are_no_candidates():
    """A branch whose segment names two hubs sends a flow to the hub whose
    Overlay Flow Control exit covers the destination at the lowest cost, not
    to every hub. Every transport to that hub stays a candidate."""
    from hst.path.gates import sdwan

    mpls = _tunnel_row(MPLS, "GE1", "172.16.9.2", "mpls")
    dia = _tunnel_row(DIA, "GE2", "203.0.113.2", "dia")
    hub2 = _hub2_row()
    dst = _dst("10.50.0.9")
    exits = [
        {"far_dev": "dev:hub", "cidr": "10.50.0.0/16", "prefixlen": 16, "metric": 32},
        {"far_dev": "dev:hub2", "cidr": "10.50.0.0/16", "prefixlen": 16, "metric": 64},
    ]
    chosen, why = sdwan.rank_candidates([mpls, dia, hub2], [], [], dst, role=None, route_exits=exits)
    assert chosen == [mpls, dia]
    assert why == (
        "the Overlay Flow Control table names hub-1 as the exit for 10.50.0.0/16 at cost 32; "
        "1 other edge(s) hold the destination with a shorter prefix or a higher cost"
    )
    # the longest prefix wins over a lower cost
    longer = [exits[0], {**exits[1], "cidr": "10.50.0.0/24", "prefixlen": 24}]
    chosen, why = sdwan.rank_candidates([mpls, dia, hub2], [], [], dst, role=None, route_exits=longer)
    assert chosen == [hub2] and "names hub-2 as the exit for 10.50.0.0/24" in why
    # an equal prefix at an equal cost keeps both hubs
    tie = [exits[0], {**exits[1], "metric": 32}]
    chosen, why = sdwan.rank_candidates([mpls, dia, hub2], [], [], dst, role=None, route_exits=tie)
    assert chosen == [mpls, dia, hub2] and "names hub-1, hub-2 as the exit" in why
    chosen, why = sdwan.rank_candidates([mpls, dia, hub2], [], [], dst, role=None, route_exits=[])
    assert chosen == [mpls, dia, hub2] and "via the hub" in why


def test_the_route_table_exit_stays_behind_a_lan_holder_and_ahead_of_a_direct_exit():
    from hst.path.gates import sdwan

    mpls = _tunnel_row(MPLS, "GE1", "172.16.9.2", "mpls")
    hub2 = _hub2_row()
    dst = _dst("10.20.20.7")
    exits = [{"far_dev": "dev:hub", "cidr": "10.20.0.0/16", "prefixlen": 16, "metric": 32}]
    # a connected LAN prefix of hub-2 answers first
    chosen, why = sdwan.rank_candidates(
        [mpls, hub2],
        [],
        [{"far_dev": "dev:hub2", "cidr": "10.20.20.0/24"}],
        dst,
        role=None,
        route_exits=exits,
    )
    assert chosen == [hub2] and "LAN prefix" in why
    # the route table names the exit, so a direct rule adds no lane
    exit_ = {"egress_uid": "if:GE2", "direct_for": ["saas"]}
    chosen, why = sdwan.rank_candidates(
        [mpls, hub2], [], [], dst, role=None, direct=[exit_], route_exits=exits
    )
    assert chosen == [mpls] and "direct" not in why
    # an exit on an edge no tunnel ends on selects nothing
    stray = [{"far_dev": "dev:elsewhere", "cidr": "10.20.0.0/16", "prefixlen": 16, "metric": 1}]
    chosen, why = sdwan.rank_candidates([mpls, hub2], [], [], dst, role=None, route_exits=stray)
    assert chosen == [mpls, hub2] and "via the hub" in why
    # a hub takes another edge's exit for a prefix longer than the default
    # before its BGP neighbor, and keeps the neighbor for a default exit
    neighbor = {"uid": "bgp:x", "peer_ip": "10.9.9.2"}
    chosen, why = sdwan.rank_candidates([mpls], [neighbor], [], dst, role="hub", route_exits=exits)
    assert chosen == [mpls] and "Overlay Flow Control" in why
    default = [{**exits[0], "cidr": "0.0.0.0/0", "prefixlen": 0}]
    chosen, why = sdwan.rank_candidates([mpls], [neighbor], [], dst, role="hub", route_exits=default)
    assert chosen == [neighbor] and "BGP neighbor" in why


def test_route_exits_reads_each_far_table_and_keeps_only_a_covering_prefix():
    from hst.path.gates import sdwan

    rib = _SegmentRib(
        {
            ("dev:hub", "vrf:hub-corp"): [_ofc_row("10.50.0.0/16", 32)],
            ("dev:hub2", "vrf:hub2-corp"): [_ofc_row("10.50.0.0/28", 64)],
        }
    )
    tables = [
        {"far_dev": "dev:hub", "vrf_uid": "vrf:hub-corp", "vrf_name": "corp"},
        {"far_dev": "dev:hub2", "vrf_uid": "vrf:hub2-corp", "vrf_name": "corp"},
    ]
    assert sdwan.route_exits(rib, tables, _dst("10.50.0.9")) == [
        {"far_dev": "dev:hub", "cidr": "10.50.0.0/16", "prefixlen": 16, "metric": 32},
        {"far_dev": "dev:hub2", "cidr": "10.50.0.0/28", "prefixlen": 28, "metric": 64},
    ]
    # a destination range wider than the /28 is covered by the /16 only
    import ipaddress

    wide = [(4, int(ipaddress.ip_address("10.50.0.0")), int(ipaddress.ip_address("10.50.0.255")))]
    assert [e["far_dev"] for e in sdwan.route_exits(rib, tables, wide)] == ["dev:hub"]
    # a /28 covers the first address of the range, and a shorter far row on the
    # same edge covers the whole range: that row is the exit
    both = _SegmentRib(
        {("dev:hub2", "vrf:hub2-corp"): [_ofc_row("10.50.0.0/28", 64), _ofc_row("10.50.0.0/20", 70)]}
    )
    assert sdwan.route_exits(both, tables[1:], wide) == [
        {"far_dev": "dev:hub2", "cidr": "10.50.0.0/20", "prefixlen": 20, "metric": 70}
    ]
    assert sdwan.route_exits(None, tables, _dst("10.50.0.9")) == []


@pytest.fixture()
def ofc_graph(monkeypatch):
    """The overlay fixture's graph, answering the far tables query too."""

    class OfcGraph(SdwanGraph):
        far_tables: list[dict] = []

        def read(self, query, **params):
            query = unpinned(query)
            if "AS vrf_uid, v.name AS vrf_name" in query:
                return [t for t in self.far_tables if t["far_dev"] in params["devs"]]
            return super().read(query, **params)

    g = OfcGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


def test_the_trace_draws_only_the_transports_to_the_hub_the_route_table_names(ofc_graph):
    """The branch segment names hub-1 and hub-2. The route table names hub-1
    for the destination, so the boundary offers the two transports to hub-1
    and no lane to hub-2. Without the route table the trace falls back to
    every hub and says so."""
    _overlay(ofc_graph)
    ofc_graph.candidate_tunnels[("dev:br", "seg:corp")].append(_hub2_row())
    ofc_graph.far_tables = [
        {"far_dev": "dev:hub", "vrf_uid": "vrf:hub-corp", "vrf_name": "corp"},
        {"far_dev": "dev:hub2", "vrf_uid": "vrf:hub2-corp", "vrf_name": "corp"},
    ]
    rib = _SegmentRib(
        {
            ("dev:hub", "vrf:hub-corp"): [_ofc_row("10.50.0.0/16", 32)],
            ("dev:hub2", "vrf:hub2-corp"): [_ofc_row("10.50.0.0/16", 64)],
        }
    )

    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR], rib=rib)
    boundary = [h for h in result["hops"] if h["kind"] == "ForwardingBoundary" and h["uid"] == "fb:br-corp"]
    assert boundary and boundary[0]["note"] == (
        "the Overlay Flow Control table names hub-1 as the exit for 10.50.0.0/16 at cost 32; "
        "1 other edge(s) hold the destination with a shorter prefix or a higher cost · 2 candidate(s)"
    )
    encaps = {h["uid"] for h in result["hops"] if h["stage"] == "ENCAP"}
    assert encaps == {MPLS, DIA}

    fallback = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    boundary = [h for h in fallback["hops"] if h["kind"] == "ForwardingBoundary" and h["uid"] == "fb:br-corp"]
    assert boundary and "via the hub" in boundary[0]["note"] and "3 candidate(s)" in boundary[0]["note"]


# --- the transport lane: the recursive next hop under a VPN route ----------------------

PE1 = {
    "cidr": "10.1.1.0/24",
    "l3dom": "cust",
    "if_uid": "if:pe1-cust",
    "if_name": "Gi0/0/0/1",
    "dev_uid": "dev:pe1",
    "dev_name": "pe1",
}
P1 = {"dev_uid": "dev:p1", "dev_name": "p1", "if_uid": "if:p1-w", "if_name": "Hu0/0/0/0"}
P2 = {"dev_uid": "dev:p2", "dev_name": "p2", "if_uid": "if:p2-w", "if_name": "Hu0/0/0/0"}
PE2_LO = {
    "dev_uid": "dev:pe2",
    "dev_name": "pe2",
    "if_uid": "if:pe2-lo",
    "if_name": "Loopback0",
    "anchor": "vrf:pe2-global",
}


class TransportGraph(SdwanGraph):
    def __init__(self):
        super().__init__()
        self.mate_if: dict[tuple[str, str], dict] = {}
        self.te_ifs: dict[str, list[dict]] = {}

    def read(self, query, **params):
        query = unpinned(query)
        if "STARTS WITH 'tunnel-te'" in query:
            return self.te_ifs.get(params["dev"], [])
        return super().read(query, **params)

    def read_one(self, query, **params):
        query = unpinned(query)
        if "MEMBER_OF]->(rd:RoutingDomain)<-[m2:MEMBER_OF]-(v:VrfInstance)" in query and "dev" in params:
            return self.mate_if.get((params["table"], params["dev"]))
        return super().read_one(query, **params)


@pytest.fixture()
def tgraph(monkeypatch):
    g = TransportGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


def _l3vpn(graph):
    """pe1 holds the customer VRF with a VPN route whose next hop is pe2's
    loopback. The loopback is two P routers away in the global table."""
    graph.sources = [_src_row(dom="cust", ip="10.1.1.5")]
    graph.default_tables = {
        "if:pe1-cust": {"uid": "vrf:pe1-cust"},
        "if:pe2-lo": {"uid": "vrf:pe2-global"},
        "if:pe2-cust": {"uid": "vrf:pe2-cust"},
    }
    graph.local_vrf_by_dev = {
        "dev:pe1": {"vrf_uid": "vrf:pe1-global", "vrf_name": "default"},
        "dev:p1": {"vrf_uid": "vrf:p1-global", "vrf_name": "default"},
        "dev:p2": {"vrf_uid": "vrf:p2-global", "vrf_name": "default"},
        "dev:pe2": {"vrf_uid": "vrf:pe2-global", "vrf_name": "default"},
    }
    graph.routes = {
        "vrf:pe1-cust": [
            _route("10.1.1.0/24", egress="Gi0/0/0/1", kind="ORIGINATES"),
            _route("10.99.0.0/24", next_hop="10.255.0.2", kind="LEARNED_ROUTE"),
        ],
        "vrf:pe1-global": [_route("10.255.0.2/32", egress="Hu0/0/0/1", next_hop="10.0.12.2")],
        "vrf:p1-global": [_route("10.255.0.2/32", egress="Hu0/0/0/1", next_hop="10.0.23.2")],
        "vrf:p2-global": [_route("10.255.0.2/32", egress="Hu0/0/0/1", next_hop="10.0.34.2")],
        "vrf:pe2-global": [],
        "vrf:pe2-cust": [_route("10.99.0.0/24", egress="Gi0/0/0/2")],
    }
    graph.next_hop_devs = {"10.255.0.2": PE2_LO, "10.0.12.2": P1, "10.0.23.2": P2, "10.0.34.2": PE2_LO}
    # the global tables are recorded VrfInstances, as every collector writes
    # them (`_single_owner_scope` weighs an unrecorded table as undecided)
    graph.contexts = {
        f"vrf:{d}-global": {"name": "default", "is_global": True} for d in ("pe1", "p1", "p2", "pe2")
    }
    graph.mate_if = {
        ("vrf:pe1-cust", "dev:pe2"): {
            "if_uid": "if:pe2-cust",
            "if_name": "Gi0/0/0/2",
            "vrf_uid": "vrf:pe2-cust",
            "vrf_name": "cust",
        }
    }


def test_a_vpn_routes_next_hop_is_walked_through_the_p_routers(tgraph):
    _l3vpn(tgraph)
    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert leg["verdict"] == "egress via Gi0/0/0/2"
    assert leg["transport"] == ["p1", "p2"]
    assert any("resolved recursively in the global table through p1, p2" in n for n in result["notes"])
    assert any("continues in table cust, the same routing domain as" in n for n in result["notes"])
    assert not any("transit device(s)" in w for w in result["warnings"])
    hops = sorted(result["hops"], key=lambda h: h["rank"])
    devices = [(h["label"], bool(h.get("transport"))) for h in hops if h["kind"] == "Device"]
    assert devices == [("pe1", False), ("p1", True), ("p2", True), ("pe2", False)]
    transport_routes = [h for h in hops if h["stage"] == "TRANSPORT"]
    assert [h["label"] for h in transport_routes] == ["10.255.0.2/32", "10.255.0.2/32"]
    # the P routers sit between the two PEs on the x axis
    rank = {h["label"]: h["rank"] for h in hops if h["kind"] == "Device"}
    assert rank["pe1"] < rank["p1"] < rank["p2"] < rank["pe2"]


def test_the_transport_walk_reads_each_global_table_once(tgraph):
    """The route a P router's transport station is drawn from is the route
    the next pass of the walk forwards by, so each device's global table and
    its routes are read once."""
    _l3vpn(tgraph)
    reads = record_reads(tgraph)

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    assert result["legs"][0]["transport"] == ["p1", "p2"]
    local_tables = [p["dev"] for q, p in reads if "v.is_global = true" in q]
    assert local_tables == ["dev:pe1", "dev:p1", "dev:p2"]
    # the route table reads, keyed by the table they read
    route_reads = [p["vrf"] for q, p in reads if "STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES" in q and "vrf" in p]
    assert route_reads.count("vrf:p1-global") == route_reads.count("vrf:p2-global") == 1


def test_a_te_tunnel_on_the_ingress_pe_stops_the_transport_lane(tgraph):
    _l3vpn(tgraph)
    tgraph.te_ifs = {"dev:pe1": [{"uid": "if:pe1-te10", "name": "tunnel-te10"}]}
    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])
    assert result["indeterminate"]
    assert any("traffic-engineered tunnel(s) tunnel-te10" in w for w in result["warnings"])
    assert not any(h.get("transport") for h in result["hops"])


@pytest.mark.parametrize("reverse", [False, True])
def test_an_equal_cost_transport_takes_the_same_member_in_any_read_order_and_names_the_others(
    tgraph, reverse
):
    _l3vpn(tgraph)
    members = [
        _route("10.255.0.2/32", egress="Hu0/0/0/1", next_hop="10.0.12.2"),
        _route("10.255.0.2/32", egress="Hu0/0/0/1", next_hop="10.0.12.9"),
    ]
    tgraph.routes["vrf:pe1-global"] = members[::-1] if reverse else members
    tgraph.next_hop_devs["10.0.12.9"] = P2

    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])

    assert result["legs"][0]["transport"] == ["p1", "p2"]
    assert any(
        "pe1 holds 2 equal-cost routes 10.255.0.2/32 toward transport next hop 10.255.0.2; "
        "the transport path is drawn via 10.0.12.2 and not via 10.0.12.9" in n
        for n in result["notes"]
    )


def test_equal_cost_members_are_ordered_by_next_hop_then_egress():
    from hst.path.addrsets import _intervals
    from hst.path.gates.routing import _route_partition

    rows = [
        _route("10.0.0.0/8", egress="b", next_hop="192.0.2.10"),
        _route("10.0.0.0/8", egress="a", next_hop="192.0.2.9"),
        _route("10.0.0.0/8", egress="a", next_hop="192.0.2.10"),
    ]
    for order in (rows, rows[::-1]):
        best = _route_partition(list(order), _intervals(["10.1.1.1"]))[0][1]
        assert [(r["next_hop"], r["egress_name"]) for r in best] == [
            ("192.0.2.9", "a"),
            ("192.0.2.10", "a"),
            ("192.0.2.10", "b"),
        ]


def test_a_missing_global_route_leaves_the_non_adjacent_answer(tgraph):
    _l3vpn(tgraph)
    tgraph.routes["vrf:pe1-global"] = []
    result = path.trace(None, "10.1.1.5", "10.99.0.7", port=443, proto="tcp", gateways=[PE1])
    assert result["indeterminate"]
    assert any("has no global route to next hop 10.255.0.2" in w for w in result["warnings"])
    assert any("transit device(s) between here and pe2 are not represented" in w for w in result["warnings"])


R1_LAN = {
    "cidr": "10.0.0.0/24",
    "l3dom": "home",
    "if_uid": "if:r1-lan",
    "if_name": "eth1",
    "dev_uid": "dev:r1",
    "dev_name": "r1",
}
FW_IN = {"dev_uid": "dev:fw", "dev_name": "fw", "if_uid": "if:fw-in", "if_name": "fw-in"}
R3_IN = {"dev_uid": "dev:r3", "dev_name": "r3", "if_uid": "if:r3-in", "if_name": "r3-in"}
R3_LO = {"dev_uid": "dev:r3", "dev_name": "r3", "if_uid": "if:r3-lo", "if_name": "lo"}


def _ibgp_over_igp(graph):
    """r1 learns r3's loopback 10.255.0.3/32 from the IGP via the firewall at
    192.0.2.2, and 172.16.0.0/16 from iBGP with the loopback as its next hop.
    Every table is the device's global one."""
    graph.sources = [_src_row(dom="home", ip="10.0.0.5")]
    graph.default_tables = {"if:r1-lan": {"uid": "vrf:r1"}, "if:r3-lo": {"uid": "vrf:r3"}}
    graph.local_vrf_by_dev = {
        "dev:r1": {"vrf_uid": "vrf:r1", "vrf_name": "default"},
        "dev:fw": {"vrf_uid": "vrf:fw", "vrf_name": "default"},
        "dev:r3": {"vrf_uid": "vrf:r3", "vrf_name": "default"},
    }
    graph.routes = {
        "vrf:r1": [
            _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES"),
            _route("192.0.2.0/30", egress="eth0", kind="ORIGINATES"),
            _route("10.255.0.3/32", egress="eth0", next_hop="192.0.2.2", kind="LEARNED_ROUTE"),
            _route("172.16.0.0/16", next_hop="10.255.0.3", kind="LEARNED_ROUTE"),
        ],
        "vrf:fw": [_route("10.255.0.3/32", egress="fw-out", next_hop="192.0.2.6", kind="LEARNED_ROUTE")],
        "vrf:r3": [_route("172.16.0.0/16", egress="r3-lan", kind="ORIGINATES")],
    }
    graph.next_hop_devs = {"10.255.0.3": R3_LO, "192.0.2.2": FW_IN, "192.0.2.6": R3_IN}


def test_a_learned_host_route_via_a_router_is_not_adjacency(tgraph):
    _ibgp_over_igp(tgraph)

    result = path.trace(None, "10.0.0.5", "172.16.1.1", port=443, proto="tcp", gateways=[R1_LAN])

    leg = result["legs"][0]
    assert leg["verdict"] == "egress via r3-lan"
    assert leg["transport"] == ["fw"]
    assert any("resolved recursively in the global table through fw" in n for n in result["notes"])
    devices = [h["label"] for h in sorted(result["hops"], key=lambda h: h["rank"]) if h["kind"] == "Device"]
    assert devices == ["r1", "fw", "r3"]


def test_a_host_route_naming_itself_as_next_hop_is_adjacency(tgraph):
    """A host route whose next hop is the address itself is the table
    resolving that address on the spot, the same as one with no next hop."""
    _ibgp_over_igp(tgraph)
    tgraph.routes["vrf:r1"][2] = _route("10.255.0.3/32", egress="eth0", next_hop="10.255.0.3")

    result = path.trace(None, "10.0.0.5", "172.16.1.1", port=443, proto="tcp", gateways=[R1_LAN])

    assert "transport" not in result["legs"][0]
    assert not any("resolved recursively" in n for n in result["notes"])


def test_engine_fib_host_routes_with_a_next_hop_are_not_adjacency():
    from hst.app.fw_overlay_read import _fib_route_rows
    from hst.path.gates.routing import _host_prefixes, _next_hop_adjacent

    class _Fib:
        def table(self, uid):
            return [
                {"prefix": "192.0.2.0/30", "protocol": "connected", "interface": "eth0"},
                {"prefix": "10.255.0.3/32", "protocol": "ospf", "next_hop": "192.0.2.2", "interface": "eth0"},
                {"prefix": "172.16.0.0/16", "protocol": "bgp", "next_hop": "10.255.0.3"},
                {"prefix": "192.0.2.9/32", "protocol": "connected", "interface": "eth2"},
            ]

    rows = _fib_route_rows(_Fib())("vrf:r1", [])

    assert _host_prefixes(rows) == ["192.0.2.9/32"]
    assert _next_hop_adjacent("10.255.0.3", ["192.0.2.0/30", *_host_prefixes(rows)]) is False


# --- decapsulation: the interface the inner flow comes out of ---------------------------

WG_R1 = {
    "cidr": "10.0.0.0/24",
    "l3dom": "home",
    "if_uid": "if:r1-lan",
    "if_name": "eth1",
    "dev_uid": "dev:r1",
    "dev_name": "r1",
}
R2_WG_PEER = {
    "peer_uid": "tun:r2-wg",
    "pair": None,
    "local_address": "203.0.113.2",
    "endpoint": "198.51.100.1",
    "allowed_ips": ["10.0.0.0/24"],
    "if_uid": "if:r2-wg0",
    "if_name": "wg0",
    "vrf_uid": "vrf:r2-vpn",
}


def _wireguard(graph):
    """r1 sends 10.2.0.0/16 into WireGuard to r2. r2 holds the tunnel's far
    address on eth0, in its global table, and its wg0 is in vrf:r2-vpn, the
    only table with a route to 10.2.0.0/16."""
    graph.sources = [_src_row(dom="home", ip="10.0.0.5")]
    graph.default_tables = {
        "if:r1-lan": {"uid": "vrf:r1"},
        "if:r2-eth0": {"uid": "vrf:r2-global"},
        "if:r2-wg0": {"uid": "vrf:r2-vpn"},
    }
    graph.local_vrf_by_dev = {
        "dev:r1": {"vrf_uid": "vrf:r1", "vrf_name": "default"},
        "dev:r2": {"vrf_uid": "vrf:r2-global", "vrf_name": "default"},
    }
    graph.routes = {
        "vrf:r1": [_route("10.2.0.0/16", egress="wg0"), _route("203.0.113.0/24", egress="eth0")],
        "vrf:r2-global": [_route("203.0.113.0/24", egress="eth0", kind="ORIGINATES")],
        "vrf:r2-vpn": [_route("10.2.0.0/16", egress="r2-lan", kind="ORIGINATES")],
    }
    graph.endpoint_tunnels = {"if:wg0": [{"uid": "tun:r1-wg", "name": "to-r2", "encap": "wireguard"}]}
    graph.tunnel_props_by_uid = {
        "tun:r1-wg": {
            "endpoint": "203.0.113.2",
            "endpoint_port": "51820",
            "carrier_proto": "udp",
            "local_address": "198.51.100.1",
            "encap": "wireguard",
            "pair": None,
            "far_ip": None,
            "far_uid": None,
            "far_name": None,
            "far_kind": None,
            "far_ends": 0,
        }
    }
    graph.far_owner = {
        "203.0.113.2": {
            "dev_uid": "dev:r2",
            "dev_name": "r2",
            "if_uid": "if:r2-eth0",
            "if_name": "eth0",
            "anchor": "vrf:r2-global",
            "l3dom": "default",
        }
    }
    graph.dev_addrs = {
        "dev:r2": [
            {"ip": "203.0.113.2", "ip_uid": "ip:r2:203.0.113.2", "if_uid": "if:r2-eth0", "if_name": "eth0"}
        ]
    }
    graph.far_overlay = {"dev:r2": [R2_WG_PEER]}


def _inner_leg(result):
    return next(leg for leg in result["legs"] if leg.get("carrier"))


def test_the_inner_flow_comes_out_of_the_far_tunnel_interface(graph):
    _wireguard(graph)

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])

    leg = _inner_leg(result)
    assert "decapsulated on r2" in leg["carrier"]["verdict"]
    assert leg["verdict"] == "egress via r2-lan"
    assert not leg["indeterminate"]
    assert any("the inner flow comes out of wg0" in n for n in result["notes"])


def _two_peers(graph):
    """r1's wg0 ends a second peer, whose uid sorts first, for 10.1.0.0/16;
    the peer to r2 allows 10.2.0.0/16. 10.3.0.0/16 is routed into wg0 too."""
    _wireguard(graph)
    graph.endpoint_tunnels = {
        "if:wg0": [
            {"uid": "tun:r1-aa", "name": "to-hq", "encap": "wireguard", "allowed_ips": ["10.1.0.0/16"]},
            {"uid": "tun:r1-wg", "name": "to-r2", "encap": "wireguard", "allowed_ips": ["10.2.0.0/16"]},
        ]
    }
    graph.routes["vrf:r1"].append(_route("10.3.0.0/16", egress="wg0"))


def test_a_wireguard_interface_sends_the_flow_to_the_peer_whose_allowed_ips_hold_it(graph):
    """One Tunnel per peer ends on wg0, and the flow rides the peer
    whose allowed IPs hold its destination, not the first peer by uid."""
    _two_peers(graph)

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])

    encaps = [h["label"] for h in result["hops"] if h["stage"] == "ENCAP"]
    assert encaps == ["to-r2"]
    assert _inner_leg(result)["verdict"] == "egress via r2-lan"
    assert not result["indeterminate"]


def test_a_destination_no_wireguard_peer_allows_is_dropped(graph):
    _two_peers(graph)

    result = path.trace(None, "10.0.0.5", "10.3.3.3", port=443, proto="tcp", gateways=[WG_R1])

    (leg,) = result["legs"]
    assert leg["blocked"]
    assert leg["verdict"] == "BLOCKED: no WireGuard peer on wg0 allows 10.3.3.3"
    assert not [h for h in result["hops"] if h["stage"] == "ENCAP"]


def test_a_wireguard_peer_with_uncollected_allowed_ips_leaves_the_choice_undecided(graph):
    _two_peers(graph)
    graph.endpoint_tunnels["if:wg0"][0]["allowed_ips"] = None

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])

    assert result["indeterminate"]
    assert any(
        "allowed IPs of WireGuard peer to-hq on wg0 were not collected" in w for w in result["warnings"]
    )


def test_a_hub_peer_with_no_endpoint_is_matched_by_its_allowed_ips(graph):
    """A hub's peer for a dynamic spoke names no endpoint and has no derived
    local address, so the address pair cannot match it; WireGuard accepts the
    inner packet from the peer whose allowed IPs cover its source."""
    _wireguard(graph)
    graph.far_overlay = {"dev:r2": [{**R2_WG_PEER, "local_address": None, "endpoint": None}]}

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])

    assert _inner_leg(result)["verdict"] == "egress via r2-lan"
    assert not result["indeterminate"]


def test_the_pair_identifier_matches_the_far_tunnel_behind_nat(graph):
    _wireguard(graph)
    graph.tunnel_props_by_uid["tun:r1-wg"]["pair"] = "pair:r1-r2"
    graph.far_overlay = {
        "dev:r2": [{**R2_WG_PEER, "pair": "pair:r1-r2", "endpoint": "192.0.2.77", "allowed_ips": []}]
    }

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])

    assert _inner_leg(result)["verdict"] == "egress via r2-lan"


def test_a_decap_with_no_reciprocal_tunnel_is_indeterminate(graph):
    _wireguard(graph)
    graph.far_overlay = {}

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])

    leg = _inner_leg(result)
    assert "decapsulated on r2" in leg["carrier"]["verdict"]
    assert result["indeterminate"] and leg["indeterminate"]
    assert any("no wireguard tunnel of its own is recorded" in w for w in result["warnings"])


def test_two_far_tunnel_interfaces_that_both_match_are_indeterminate(graph):
    _wireguard(graph)
    graph.far_overlay = {
        "dev:r2": [
            R2_WG_PEER,
            {**R2_WG_PEER, "peer_uid": "tun:r2-wg-b", "if_uid": "if:r2-wg1", "if_name": "wg1"},
        ]
    }

    result = path.trace(None, "10.0.0.5", "10.2.3.4", port=443, proto="tcp", gateways=[WG_R1])

    assert result["indeterminate"]
    assert any("2 of its tunnel interfaces match the tunnel (wg0, wg1)" in w for w in result["warnings"])


# --- the business policy, the hub's static routes and the standby link ------------------


def _policy_rule(position, name, policy="auto", hubs=None, **match):
    return {
        "position": position,
        "name": name,
        "segment_id": "1",
        "edge2cloud_route_policy": policy,
        "edge2cloud_backhaul_hubs": hubs,
        **match,
    }


def _flow(dst="8.8.8.8", **over):
    return {
        "af": 4,
        "src": _dst("10.0.0.5"),
        "dst": _dst(dst),
        "port": 443,
        "proto": "tcp",
        "src_port": None,
        "dscp": 0,
        "dscp_stated": False,
        **over,
    }


# The order of the reference profile: DSCP rules first, then a rule that
# matches any flow, then the application rules the trace cannot decide.
_RULES = [
    _policy_rule(1, "Backhaul voice", "backhaul", [" HUB-FRANKFURT", "HUB-PARIS"], match_dscp=46),
    _policy_rule(2, "Internet backhaul", "backhaul", ["HUB-PARIS", " HUB-FRANKFURT"]),
    _policy_rule(3, "Web", "gateway", match_app_class_id=19),
]


def test_the_first_rule_that_matches_decides_and_an_unmarked_flow_skips_the_dscp_rules():
    from hst.path.gates import sdwan

    unmarked = _flow(dscp=0, dscp_stated=True)
    assert [r["position"] for r in sdwan.policy_outcomes(_RULES, unmarked)] == [2]
    assert [r["position"] for r in sdwan.policy_outcomes(_RULES, _flow(dscp=46, dscp_stated=True))] == [1]
    # an unstated DSCP leaves the DSCP rule undecided, as an unstated port does
    unstated = sdwan.policy_outcomes(_RULES, _flow())
    assert [(r["position"], r["maybe"]) for r in unstated] == [(1, True), (2, False)]
    assert unstated[0]["undecided"] == "DSCP"
    rules = [_policy_rule(1, "Web", "gateway", match_app_class_id=19), *_RULES[1:2]]
    outcomes = sdwan.policy_outcomes(rules, _flow())
    assert [(r["position"], r["maybe"]) for r in outcomes] == [(1, True), (2, False)]
    assert outcomes[0]["undecided"] == "application class"


def test_a_rule_is_decided_on_the_address_the_protocol_and_the_port_it_names():
    from hst.path.gates import sdwan

    rule = _policy_rule(1, "dc", match_dst="10.20.0.0/16", match_proto="tcp", match_dst_port="440-450")
    assert sdwan.rule_verdict(rule, _flow("10.20.1.1")) == ("yes", "")
    assert sdwan.rule_verdict(rule, _flow("10.21.1.1"))[0] == "no"
    assert sdwan.rule_verdict(rule, _flow("10.20.1.1", proto="udp"))[0] == "no"
    assert sdwan.rule_verdict(rule, _flow("10.20.1.1", port=80))[0] == "no"
    assert sdwan.rule_verdict(rule, _flow("10.20.1.1", port=None)) == ("maybe", "port")
    # a numbered protocol is the same protocol as its name
    assert sdwan.rule_verdict({**rule, "match_proto": "6"}, _flow("10.20.1.1"))[0] == "yes"
    # a destination range the rule covers only in part is not decided
    wide = {**_flow(), "dst": [(4, int(__import__("ipaddress").ip_address("10.19.255.0")), 169083135)]}
    assert sdwan.rule_verdict(rule, wide) == ("maybe", "destination")


def test_a_port_spec_that_is_neither_a_port_nor_a_range_leaves_the_rule_undecided():
    from hst.path.gates import sdwan

    rule = _policy_rule(1, "web", match_dst_port="80,443", match_src_port="any")
    flow = {**_flow("10.20.1.1", port=22), "src_port": 40000}
    assert sdwan.rule_verdict(rule, flow) == ("maybe", "port, source port")
    # the undecided rule does not end the list
    after = _policy_rule(2, "rest")
    assert [r["name"] for r in sdwan.policy_outcomes([rule, after], flow)] == ["web", "rest"]


def _cluster_row(uid, far_dev, name, cluster, link="GE4", **over):
    return {
        **_tunnel_row(uid, link, "203.0.113.9", "dia"),
        "far_dev": far_dev,
        "far_dev_name": name,
        "far_cluster": cluster,
        **over,
    }


_CLUSTER_TUNNELS = [
    _cluster_row("tun:fra-a", "dev:fra-a", "fra-a", "HUB-FRANKFURT"),
    _cluster_row("tun:fra-b", "dev:fra-b", "fra-b", "HUB-FRANKFURT"),
    _cluster_row("tun:par-a", "dev:par-a", "par-a", "HUB-PARIS"),
    _cluster_row("tun:par-b", "dev:par-b", "par-b", "HUB-PARIS"),
]


def test_a_backhaul_rule_takes_the_tunnels_to_the_first_cluster_it_names():
    from hst.path.gates import sdwan

    flow = _flow(dscp=0, dscp_stated=True)
    chosen, why = sdwan.rank_candidates(
        _CLUSTER_TUNNELS,
        [],
        [],
        flow["dst"],
        role=None,
        policy=sdwan.policy_outcomes(_RULES, flow),
        flow=flow,
    )
    assert [t["uid"] for t in chosen] == ["tun:par-a", "tun:par-b"]
    assert "rule 2 'Internet backhaul' backhauls to HUB-PARIS (then HUB-FRANKFURT if it fails)" in why
    assert "not stated" not in why
    flow = _flow(dscp=46, dscp_stated=True)
    chosen, why = sdwan.rank_candidates(
        _CLUSTER_TUNNELS,
        [],
        [],
        flow["dst"],
        role=None,
        policy=sdwan.policy_outcomes(_RULES, flow),
        flow=flow,
    )
    assert [t["uid"] for t in chosen] == ["tun:fra-a", "tun:fra-b"]
    assert "not stated" not in why


def test_an_undecided_rule_before_the_winner_keeps_its_own_candidates_beside_the_winners():
    from hst.path.gates import sdwan

    gateway = {
        **_tunnel_row("tun:gw", "GE4", "198.51.100.20", "dia"),
        "far_kind": "SdwanGateway",
        "far_role": None,
    }
    rules = [_policy_rule(1, "Web", "gateway", match_app_class_id=19), _RULES[1]]
    flow = _flow()
    chosen, why = sdwan.rank_candidates(
        [*_CLUSTER_TUNNELS, gateway],
        [],
        [],
        flow["dst"],
        role=None,
        policy=sdwan.policy_outcomes(rules, flow),
    )
    assert [t["uid"] for t in chosen] == ["tun:gw", "tun:par-a", "tun:par-b"]
    assert (
        "rule 1 'Web' (may match: application class not decided) sends the flow to the cloud gateways" in why
    )


def test_a_backhaul_to_a_hub_with_no_tunnel_keeps_the_candidates_and_says_why():
    from hst.path.gates import sdwan

    rules = [_policy_rule(1, "elsewhere", "backhaul", ["HUB-LONDON"])]
    flow = _flow()
    chosen, why = sdwan.rank_candidates(
        _CLUSTER_TUNNELS, [], [], flow["dst"], role=None, policy=sdwan.policy_outcomes(rules, flow)
    )
    assert len(chosen) == 4
    assert "backhauls to HUB-LONDON, and no tunnel ends there, so the policy selects no candidate" in why


def test_a_candidate_on_a_standby_link_is_dropped_while_an_active_link_remains():
    from hst.path.gates import sdwan

    active = _cluster_row("tun:par-a", "dev:par-a", "par-a", "HUB-PARIS")
    standby = _cluster_row(
        "tun:par-a-lte",
        "dev:par-a",
        "par-a",
        "HUB-PARIS",
        link="GE3",
        link_name="LTE",
        link_mode="HOTSTANDBY",
    )
    assert sdwan._active_links([active, standby]) == ([active], ["LTE"])
    backup = {**standby, "link_mode": None, "backup_only": True}
    assert sdwan._active_links([active, backup]) == ([active], ["LTE"])
    assert sdwan._active_links([standby]) == ([standby], [])


def test_a_hub_takes_its_static_route_before_its_bgp_neighbors_and_after_a_lan_holder():
    from hst.path.gates import sdwan

    statics = [
        {"uid": "st:default", "cidr": "0.0.0.0/0", "next_hop": "10.9.9.2", "interface": "GE3:801"},
        {"uid": "st:dc", "cidr": "10.0.0.0/8", "next_hop": "10.9.9.6", "interface": "GE3:804"},
    ]
    neighbors = [{"uid": "bgp:x", "peer_ip": "10.9.9.2"}]
    chosen, why = sdwan.rank_candidates([], neighbors, [], _dst("8.8.8.8"), role="hub", statics=statics)
    assert [r["uid"] for r in chosen] == ["st:default"]
    assert why == "the segment's static route 0.0.0.0/0 via 10.9.9.2 on GE3:801 covers the destination"
    chosen, _ = sdwan.rank_candidates([], neighbors, [], _dst("10.50.0.9"), role="hub", statics=statics)
    assert [r["uid"] for r in chosen] == ["st:dc"]
    # a branch LAN the hub reaches over the overlay is not caught by the static default
    spoke = {**_tunnel_row("tun:hub-br", "GE1", "172.16.1.2", "mpls"), "far_dev": "dev:br", "far_role": None}
    chosen, why = sdwan.rank_candidates(
        [spoke],
        neighbors,
        [{"far_dev": "dev:br", "cidr": "10.0.0.0/24"}],
        _dst("10.0.0.5"),
        role="hub",
        statics=statics,
    )
    assert chosen == [spoke] and "LAN prefix" in why


def _policy_overlay(graph, rules, direct=()):
    _overlay(graph)
    overlay_read = graph.read

    def read(query, **params):
        if "HAS_RULE]->(r:SdwanPolicyRule)" in query:
            return [{"rule": r} for r in rules] if params["dev"] == "dev:br" else []
        if "sv.route_policy = 'direct'" in query:
            return list(direct)
        return overlay_read(query, **params)

    graph.read = read


_DIRECT_EXIT = {
    "egress_uid": "if:GE2",
    "egress_name": "GE2",
    "next_hop": "198.51.100.1",
    "egress_vrf": "vrf:br-global",
    "link_uid": "wan:br:dia",
    "link_kind": "dia",
    "link_name": "dia",
    "direct_for": ["internet"],
}


def test_the_trace_draws_what_the_business_policy_selects_for_the_stated_dscp(graph):
    rules = [
        _policy_rule(1, "voice", "backhaul", ["hub-1"], match_dscp=46),
        _policy_rule(2, "internet", "direct"),
    ]
    _policy_overlay(graph, rules, direct=[_DIRECT_EXIT])
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR], dscp=0)
    assert len(result["legs"]) == 1
    boundary = [h for h in result["hops"] if h["kind"] == "ForwardingBoundary"]
    assert "rule 2 'internet' sends the flow direct" in boundary[0]["note"]
    assert "not stated" not in boundary[0]["note"]
    assert not [h for h in result["hops"] if h["stage"] == "ENCAP"]

    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR], dscp=46)
    assert len(result["legs"]) == 2
    boundary = [h for h in result["hops"] if h["kind"] == "ForwardingBoundary"]
    assert "rule 1 'voice' backhauls to hub-1" in boundary[0]["note"]
    assert len([h for h in result["hops"] if h["stage"] == "ENCAP"]) == 2


def test_a_dscp_outside_the_six_bit_field_is_refused(graph):
    _overlay(graph)
    with pytest.raises(ValueError, match=r"outside 0\.\.63"):
        path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR], dscp=64)


def test_the_hub_hands_the_inner_flow_to_the_next_hop_of_its_static_route(graph):
    _overlay(graph)
    overlay_read = graph.read

    def read(query, **params):
        if "HAS_ROUTE]->(r:SdwanStaticRoute)" in query and params["boundary"] == "fb:hub-corp":
            return [
                {
                    "uid": "st:hub-dc",
                    "cidr": "10.50.0.0/16",
                    "next_hop": "10.9.9.2",
                    "interface": "GE3",
                    "cost": 0,
                    "description": "towards the DC",
                    "egress_uid": "if:hub-lan",
                }
            ]
        return overlay_read(query, **params)

    graph.read = read
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    notes = [h["note"] for h in result["hops"] if h["kind"] == "ForwardingBoundary"]
    assert any(
        "the segment's static route 10.50.0.0/16 via 10.9.9.2 on GE3 covers the destination" in n
        for n in notes
    )
    assert not any("BGP neighbor" in n for n in notes)
    assert any(h["label"] == "core-1" for h in result["hops"] if h["kind"] == "Device")


def test_a_fork_behind_the_tunnel_starts_each_new_lane_with_the_hops_before_it(graph):
    _overlay(graph)
    overlay_read = graph.read
    static = {
        "cidr": "10.50.0.0/16",
        "interface": "GE3",
        "cost": 0,
        "description": None,
        "egress_uid": "if:hub-lan",
    }

    def read(query, **params):
        if "HAS_ROUTE]->(r:SdwanStaticRoute)" in query and params["boundary"] == "fb:hub-corp":
            return [
                {**static, "uid": "st:a", "next_hop": "10.9.9.2"},
                {**static, "uid": "st:b", "next_hop": "10.9.9.3"},
            ]
        return overlay_read(query, **params)

    graph.read = read
    graph.next_hop_devs["10.9.9.3"] = CORE
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    encap = {h["rank"] for h in result["hops"] if h["stage"] == "ENCAP"}
    by_lane: dict = {}
    for h in result["hops"]:
        by_lane.setdefault(h["lane"], []).append(h)
    assert len(by_lane) > 2
    for hops in by_lane.values():
        # every lane holds an ENCAP hop, and in the one column
        assert {h["rank"] for h in hops if h["stage"] == "ENCAP"} <= encap
        assert any(h["stage"] == "ENCAP" for h in hops)


def test_a_hub_with_no_route_for_the_flow_leaves_by_its_business_policy_like_a_branch():
    """A hub that serves branches is an edge too. Its own LAN's flow to the
    internet matches no static route of the hub, and the segment has no BGP
    neighbor: the hub's business policy backhauls it to the hub cluster."""
    from hst.path.gates import sdwan

    flow = _flow()
    rules = [_policy_rule(1, "Internet backhaul", "backhaul", ["HUB-PARIS"])]
    chosen, why = sdwan.rank_candidates(
        _CLUSTER_TUNNELS,
        [],
        [],
        flow["dst"],
        role="hub",
        statics=[
            {"uid": "st:dc", "cidr": "10.193.152.0/21", "next_hop": "10.188.254.6", "interface": "SFP1:709"}
        ],
        policy=sdwan.policy_outcomes(rules, flow),
        flow=flow,
    )
    assert [t["uid"] for t in chosen] == ["tun:par-a", "tun:par-b"]
    assert why.startswith(
        "no route of the hub covers the destination and the segment has no BGP neighbor; "
        "destination is not in any edge's LAN; "
        "business policy rule 1 'Internet backhaul' backhauls to HUB-PARIS"
    )
    chosen, _ = sdwan.rank_candidates(
        _CLUSTER_TUNNELS,
        [{"uid": "bgp:x", "peer_ip": "10.9.9.2"}],
        [],
        flow["dst"],
        role="hub",
        policy=sdwan.policy_outcomes(rules, flow),
        flow=flow,
    )
    assert [r["uid"] for r in chosen] == ["bgp:x"]


# --- the hub fallback, the no-match outcome, the candidate cap and the direct link ------


def _spoke_row(uid, far_dev, name):
    return {
        **_tunnel_row(uid, "GE1", "172.16.5.2", "mpls"),
        "far_dev": far_dev,
        "far_dev_name": name,
        "far_role": None,
    }


_SPOKES = [_spoke_row("tun:hub-br1", "dev:br1", "branch-1"), _spoke_row("tun:hub-br2", "dev:br2", "branch-2")]
_HUB_STATICS = [
    {"uid": "st:dc", "cidr": "10.193.152.0/21", "next_hop": "10.188.254.6", "interface": "SFP1:709"}
]
_HUB_LEAD = "no route of the hub covers the destination and the segment has no BGP neighbor"


def test_a_hub_with_tunnels_only_to_branches_selects_no_branch_tunnel():
    from hst.path.gates import sdwan

    flow = _flow()
    chosen, why = sdwan.rank_candidates(_SPOKES, [], [], flow["dst"], role="hub", statics=_HUB_STATICS)
    assert chosen == [] and why == _HUB_LEAD
    for rule in (_policy_rule(1, "any", "auto"), _policy_rule(1, "away", "backhaul", ["HUB-PARIS"])):
        chosen, why = sdwan.rank_candidates(
            _SPOKES,
            [],
            [],
            flow["dst"],
            role="hub",
            statics=_HUB_STATICS,
            policy=sdwan.policy_outcomes([rule], flow),
            flow=flow,
        )
        assert chosen == [], rule
        assert why.startswith(_HUB_LEAD + "; business policy rule 1"), why
    # the direct exits stay
    exit_ = {"egress_uid": "if:GE2", "link_uid": "wan:hub:dia", "direct_for": ["internet"]}
    chosen, why = sdwan.rank_candidates(
        _SPOKES,
        [],
        [],
        flow["dst"],
        role="hub",
        statics=_HUB_STATICS,
        direct=[exit_],
        policy=sdwan.policy_outcomes([_policy_rule(1, "any", "auto")], flow),
        flow=flow,
    )
    assert chosen == [exit_]
    chosen, _ = sdwan.rank_candidates(_SPOKES, [], [], flow["dst"], role=None)
    assert chosen == _SPOKES


def test_the_hub_boundary_draws_no_branch_lane(graph):
    from hst.path.gates import sdwan

    _overlay(graph)
    graph.bgp_neighbors = {}
    graph.candidate_tunnels[("dev:hub", "seg:corp")] = list(_SPOKES)
    hub_gw = {**HUB_WAN, "if_uid": "if:hub-lan", "if_name": "GE3"}
    routes, info = sdwan.candidate_routes(None, hub_gw, "vrf:hub-corp", _dst("8.8.8.8"))
    assert routes == []
    assert info["candidates"] == 0
    assert info["why"] == _HUB_LEAD


def test_one_undecided_backhaul_rule_also_draws_the_no_match_candidates():
    from hst.path.gates import sdwan

    flow = _flow()
    rules = [_policy_rule(1, "Web backhaul", "backhaul", ["HUB-PARIS"], match_app_class_id=19)]
    exit_ = {"egress_uid": "if:GE2", "link_uid": "wan:br:dia", "direct_for": ["internet"]}
    chosen, why = sdwan.rank_candidates(
        _CLUSTER_TUNNELS,
        [],
        [],
        flow["dst"],
        role=None,
        direct=[exit_],
        policy=sdwan.policy_outcomes(rules, flow),
        flow=flow,
    )
    assert [t.get("uid") or t["link_uid"] for t in chosen] == [
        "tun:par-a",
        "tun:par-b",
        "tun:fra-a",
        "tun:fra-b",
        "wan:br:dia",
    ]
    assert "rule 1 'Web backhaul' (may match: application class not decided) backhauls to HUB-PARIS" in why
    assert "when no rule matches: via the hub" in why
    # a decided rule after it closes the gap: the no-match outcome is not added
    decided = [*rules, _policy_rule(2, "Internet backhaul", "backhaul", ["HUB-FRANKFURT"])]
    chosen, why = sdwan.rank_candidates(
        _CLUSTER_TUNNELS,
        [],
        [],
        flow["dst"],
        role=None,
        direct=[exit_],
        policy=sdwan.policy_outcomes(decided, flow),
        flow=flow,
    )
    assert [t["uid"] for t in chosen] == ["tun:par-a", "tun:par-b", "tun:fra-a", "tun:fra-b"]
    assert "when no rule matches" not in why


def test_one_boundary_draws_at_most_sixteen_candidates_with_the_lowest_uids(graph):
    from hst.path.gates import sdwan

    _overlay(graph)
    rows = [_tunnel_row(f"tun:br-{n:02d}", "GE1", "172.16.9.2", "mpls") for n in range(20, 0, -1)]
    graph.candidate_tunnels[("dev:br", "seg:corp")] = rows
    routes, info = sdwan.candidate_routes(None, BR, "vrf:br-corp", _dst("10.50.0.9"))
    assert len(routes) == sdwan.MAX_CANDIDATES == 16
    assert info["candidates"] == 16 and info["not_drawn"] == 4
    assert sorted(r["tunnel_uid"] for r in routes) == [f"tun:br-{n:02d}" for n in range(1, 17)]
    # the kept rows stay in the order the boundary selected them
    assert [r["tunnel_uid"] for r in routes] == [f"tun:br-{n:02d}" for n in range(16, 0, -1)]


def test_the_trace_warns_with_the_candidates_a_boundary_does_not_draw(graph, monkeypatch):
    from hst.path.gates import sdwan

    _overlay(graph)
    monkeypatch.setattr(sdwan, "MAX_CANDIDATES", 1)
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    assert len(result["legs"]) == 1
    assert any(
        "the SD-WAN boundary of branch-1 selects 2 candidates; "
        "the 1 with the lowest uids are drawn and 1 are not" in w
        for w in result["warnings"]
    )


def test_a_direct_row_draws_the_wan_link_it_names(graph):
    """The edge's first WanLink by uid is another link than the one the
    direct row leaves by: the trace draws the row's own link."""
    _policy_overlay(graph, [_policy_rule(1, "internet", "direct")], direct=[_DIRECT_EXIT])
    graph.wan = {"uid": "wan:br:a-mpls", "name": "mpls"}
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    links = [h for h in result["hops"] if h["kind"] == "WanLink"]
    assert [(h["uid"], h["label"]) for h in links] == [("wan:br:dia", "dia")]


def test_a_next_hop_outside_the_twin_reads_no_table_name_for_the_adjacency_note(graph):
    """The direct exit's next hop resolves in the global table, and no
    interface holds it. The global table's name is printed only for a
    resolved owner, so it is not read."""
    _policy_overlay(graph, [_policy_rule(1, "internet", "direct")], direct=[_DIRECT_EXIT])
    reads = record_reads(graph)

    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])

    assert any("198.51.100.1 is not held by any interface" in w for w in result["warnings"])
    assert not [p for q, p in reads if "RETURN v.name AS n" in q and p.get("u") == "vrf:br-global"]


def test_a_rule_with_an_address_group_match_is_undecided_and_names_the_key():
    from hst.path.gates import sdwan

    rule = _policy_rule(1, "grouped", "direct", match_unmapped=["sAddressGroup"])
    assert sdwan.rule_verdict(rule, _flow()) == ("maybe", "sAddressGroup")


def test_the_dscp_clause_shows_only_when_an_evaluated_rule_matches_on_dscp():
    from hst.path.gates import sdwan

    flow = _flow()
    plain = [_policy_rule(1, "internet", "direct")]
    _chosen, why = sdwan.rank_candidates(
        _CLUSTER_TUNNELS, [], [], flow["dst"], role=None, policy=sdwan.policy_outcomes(plain, flow), flow=flow
    )
    assert "read as 0" not in why
    voice = [_policy_rule(1, "voice", "direct", match_dscp=46), _policy_rule(2, "internet", "direct")]
    _chosen, why = sdwan.rank_candidates(
        _CLUSTER_TUNNELS, [], [], flow["dst"], role=None, policy=sdwan.policy_outcomes(voice, flow), flow=flow
    )
    assert "the DSCP is not stated" in why and "rule 1 'voice'" in why


# --- static routes on every edge, ranked against the overlay rules -----------------------------


def _static(uid, cidr, **kw):
    return {"uid": uid, "cidr": cidr, "next_hop": "10.9.9.2", "interface": "GE3", **kw}


def test_a_branch_reads_its_static_route_against_the_overlay_exit():
    from hst.path.gates import sdwan

    tunnel = {**_tunnel_row("tun:br-hub", "GE1", "172.16.1.1", "mpls"), "far_dev": "dev:hub"}
    exit_row = [{"far_dev": "dev:hub", "cidr": "10.40.0.0/16", "prefixlen": 16, "metric": 0}]
    statics = [_static("st:dc", "10.40.1.0/24")]
    chosen, why = sdwan.rank_candidates(
        [tunnel], [], [], _dst("10.40.1.9"), role=None, statics=statics, route_exits=exit_row
    )
    assert [r["uid"] for r in chosen] == ["st:dc"]
    assert why == "the segment's static route 10.40.1.0/24 via 10.9.9.2 on GE3 covers the destination"


def test_a_preferred_static_wins_at_equal_length_and_a_plain_one_yields():
    from hst.path.gates import sdwan

    tunnel = {**_tunnel_row("tun:br-hub", "GE1", "172.16.1.1", "mpls"), "far_dev": "dev:hub"}
    exit_row = [{"far_dev": "dev:hub", "cidr": "10.40.0.0/16", "prefixlen": 16, "metric": 0}]
    for preferred, expect in ((True, "st:dc"), (False, "tun:br-hub"), (None, "tun:br-hub")):
        statics = [_static("st:dc", "10.40.0.0/16", preferred=preferred)]
        chosen, _ = sdwan.rank_candidates(
            [tunnel], [], [], _dst("10.40.1.9"), role=None, statics=statics, route_exits=exit_row
        )
        assert [r["uid"] for r in chosen] == [expect], preferred


def test_the_lowest_cost_static_of_the_longest_length_is_drawn_and_ties_are_kept():
    from hst.path.gates import sdwan

    statics = [
        _static("st:a", "0.0.0.0/0", cost=10),
        _static("st:b", "0.0.0.0/0", cost=2, next_hop="10.9.9.6"),
        _static("st:c", "0.0.0.0/0", cost=2, next_hop="10.9.9.7"),
    ]
    chosen, why = sdwan.rank_candidates([], [], [], _dst("8.8.8.8"), role="hub", statics=statics)
    assert [r["uid"] for r in chosen] == ["st:b", "st:c"]
    assert "10.9.9.6" in why and "10.9.9.7" in why and "static routes" in why


# --- the standby filter at both tunnel ends ---------------------------------------------------


def test_a_hub_reply_drops_the_branch_lte_tunnel_while_an_active_tunnel_remains():
    from hst.path.gates import sdwan

    active = {**_tunnel_row("tun:hub-br-mpls", "GE1", "172.16.1.2", "mpls"), "far_link_mode": "ACTIVE"}
    lte = {
        **_tunnel_row("tun:hub-br-lte", "GE1", "100.64.1.2", "mpls"),
        "link_name": "MPLS",
        "far_link_mode": "HOTSTANDBY",
    }
    assert sdwan._active_links([active, lte])[0] == [active]


def test_the_policy_evaluation_comes_back_as_one_entry_per_rule():
    from hst.path.gates import sdwan

    flow = _flow()
    report: dict = {}
    sdwan.rank_candidates(
        _CLUSTER_TUNNELS,
        [],
        [],
        flow["dst"],
        role=None,
        policy=sdwan.policy_outcomes(_RULES, flow),
        flow=flow,
        report=report,
    )
    assert report["rules"] == [
        {
            "position": 1,
            "name": "Backhaul voice",
            "verdict": "may match",
            "undecided": "DSCP",
            "action": "backhaul",
            "candidates": 2,
        },
        {
            "position": 2,
            "name": "Internet backhaul",
            "verdict": "matches",
            "undecided": "",
            "action": "backhaul",
            "candidates": 2,
        },
    ]
    # a boundary that does not reach the policy reports no rules
    quiet: dict = {}
    sdwan.rank_candidates(_CLUSTER_TUNNELS, [], [], flow["dst"], role=None, report=quiet)
    assert "rules" not in quiet


def test_the_policy_rules_reach_the_leg(graph):
    _policy_overlay(graph, [_policy_rule(1, "internet", "direct")], direct=[_DIRECT_EXIT])
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    rules = [leg.get("sdwan_rules") for leg in result["legs"]]
    assert rules and all(r and r[0]["name"] == "internet" and r[0]["action"] == "direct" for r in rules)


def test_no_trail_note_says_every_candidate_is_drawn_when_one_is_not(graph, monkeypatch):
    from hst.path.gates import sdwan

    _overlay(graph)
    monkeypatch.setattr(sdwan, "MAX_CANDIDATES", 1)
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    assert any("are not" in w for w in result["warnings"])
    assert not any("every candidate is drawn" in n for n in result["notes"])
    assert any("the drawn candidates are not a decision" in n for n in result["notes"])


def test_a_hub_forwards_to_the_edge_that_advertises_the_prefix():
    from hst.path.gates import sdwan

    branch = {
        **_tunnel_row("tun:hub-br7", "GE1", "172.16.9.7", "mpls"),
        "far_dev": "dev:br7",
        "far_dev_name": "br7",
    }
    neighbor = {"uid": "bgp:x", "peer_ip": "10.9.9.2"}
    exits = [{"far_dev": "dev:br7", "cidr": "10.77.0.0/16", "prefixlen": 16, "metric": 10}]
    chosen, why = sdwan.rank_candidates(
        [branch], [neighbor], [], _dst("10.77.1.1"), role="hub", route_exits=exits
    )
    assert chosen == [branch] and "br7" in why
    # route_exits keeps only a covering row, so 8.8.8.8 has no exit
    chosen, why = sdwan.rank_candidates([branch], [neighbor], [], _dst("8.8.8.8"), role="hub", route_exits=[])
    assert chosen == [neighbor] and "BGP neighbor" in why


def test_a_static_route_out_of_the_wan_interface_rides_no_tunnel(graph):
    """A configured static route toward the WAN gateway leaves by the same
    interface the tunnels end on. Its next hop is no tunnel's far end, so
    the flow leaves by the underlay and enters no tunnel."""
    _overlay(graph)
    graph.endpoint_tunnels["if:GE2"] = [
        {"uid": DIA, "name": "branch-1 GE2 to hub-1", "encap": "velocloud-vcmp", "far_ip": "203.0.113.2"}
    ]
    graph.routes["vrf:br-corp"] = [_route("10.70.0.0/24", egress="GE2", next_hop="198.51.100.1")]
    graph.next_hop_devs["198.51.100.1"] = {
        "dev_uid": "dev:isp",
        "dev_name": "isp-1",
        "if_uid": "if:isp-in",
        "if_name": "eth0",
    }
    result = path.trace(None, "10.0.0.5", "10.70.0.9", port=443, proto="tcp", gateways=[BR])
    assert len(result["legs"]) == 1
    assert not result["legs"][0].get("carrier")
    assert [h for h in result["hops"] if h["stage"] == "ENCAP"] == []


def test_a_wan_interface_with_two_vcmp_tunnels_takes_the_tunnel_of_the_next_hop(graph):
    _overlay(graph)
    graph.endpoint_tunnels["if:GE2"] = [
        {"uid": "tun:a", "name": "GE2 to hub-a", "encap": "velocloud-vcmp", "far_ip": "203.0.113.1"},
        {"uid": "tun:b", "name": "GE2 to hub-b", "encap": "velocloud-vcmp", "far_ip": "203.0.113.2"},
    ]
    graph.routes["vrf:br-corp"] = [_route("10.70.0.0/24", egress="GE2", next_hop="203.0.113.2")]
    result = path.trace(None, "10.0.0.5", "10.70.0.9", port=443, proto="tcp", gateways=[BR])
    encap = [h["label"] for h in result["hops"] if h["stage"] == "ENCAP"]
    assert encap == ["GE2 to hub-b"]


def test_an_overlay_lan_prefix_longer_than_the_edges_own_row_wins(graph):
    """The branch has its own /16 toward a local router. The hub's LAN /24 in
    the segment is longer, so the overlay draws the tunnels to the hub. A
    destination only the /16 covers keeps the branch's own next hop."""
    _overlay(graph)
    graph.routes["vrf:br-corp"] = [_route("10.20.0.0/16", egress="GE3", next_hop="10.1.1.1")]
    result = path.trace(None, "10.0.0.5", "10.20.20.7", port=443, proto="tcp", gateways=[BR])
    assert all(leg["candidate_set"] for leg in result["legs"])
    assert any(h["kind"] == "ForwardingBoundary" for h in result["hops"])
    assert any(
        "overlay prefix 10.20.20.0/24 is longer than its own route 10.20.0.0/16" in n for n in result["notes"]
    )

    result = path.trace(None, "10.0.0.5", "10.20.99.7", port=443, proto="tcp", gateways=[BR])
    assert not any(leg.get("candidate_set") for leg in result["legs"])
    assert [leg["next_hop"] for leg in result["legs"]] == ["10.1.1.1"]


HUB_LAN = {
    "cidr": "10.9.9.0/24",
    "l3dom": "corp",
    "if_uid": "if:hub-lan",
    "if_name": "GE3",
    "dev_uid": "dev:hub",
    "dev_name": "hub-1",
}


def test_a_hub_with_a_stored_default_route_draws_the_tunnels_to_the_branch_that_holds_the_lan(graph):
    """hub-1's route store holds only an origin default via 10.9.9.2. The
    branch LAN /24 is longer, so a flow from the hub LAN to a branch host takes
    the tunnels to that branch; a destination only the default covers keeps
    10.9.9.2."""
    _overlay(graph)
    graph.sources = [_src_row(dom="corp", ip="10.9.9.5")]
    graph.bgp_neighbors = {}
    graph.candidate_tunnels[("dev:hub", "seg:corp")] = list(_SPOKES)
    graph.far_prefixes = {
        "dev:br1": [{"far_dev": "dev:br1", "cidr": "10.10.10.0/24", "prefix_uid": "pfx:br1-lan"}]
    }
    rib = _SegmentRib({("dev:hub", "vrf:hub-corp"): [_ofc_row("0.0.0.0/0", 1)]})

    to_branch = path.trace(None, "10.9.9.5", "10.10.10.5", port=443, proto="tcp", gateways=[HUB_LAN], rib=rib)
    boundary = [h["note"] for h in to_branch["hops"] if h["kind"] == "ForwardingBoundary"]
    assert boundary == ["destination is inside a LAN prefix of branch-1 · 1 candidate(s)"]
    assert to_branch["legs"] and all(leg.get("candidate_set") for leg in to_branch["legs"])

    out = path.trace(None, "10.9.9.5", "8.8.8.8", port=443, proto="tcp", gateways=[HUB_LAN], rib=rib)
    assert not any(leg.get("candidate_set") for leg in out["legs"])
    # the hub's own default via 10.9.9.2 forwards to core-1, which holds 10.9.9.2
    assert not [h for h in out["hops"] if h["kind"] == "ForwardingBoundary"]
    assert ("Device", "core-1") in {(h["kind"], h["label"]) for h in out["hops"]}


def test_the_far_edge_a_velocloud_tunnel_uid_names():
    from hst.core import uid as uidmod

    tunnel = "vco:ent-1:path:e-hub:lh~link:e-br1:l1"
    assert uidmod.velocloud_far_edge(tunnel) == "e-br1"
    assert uidmod.names_far_device(tunnel, "vco:ent-1:edge:e-br1")
    assert not uidmod.names_far_device(tunnel, "vco:ent-1:edge:e-br2")
    # a gateway tunnel, or any other uid, names no far edge and rules nothing out
    assert uidmod.velocloud_far_edge("vco:ent-1:path:e-br1:l1~gw:g1") is None
    assert uidmod.names_far_device("tun:x", "dev:anything")


def test_two_branches_behind_one_nat_address_keep_one_row_per_tunnel(graph):
    """Both branches' WAN links hold the shared NAT address, so the read gives
    each hub tunnel a row for each branch. The row of the branch the tunnel uid
    names is kept."""
    from hst.path.gates import sdwan

    _overlay(graph)
    graph.bgp_neighbors = {}

    def row(uid, far_dev, name):
        return {
            **_tunnel_row(uid, "GE2", "198.51.100.9", "dia"),
            "far_dev": far_dev,
            "far_dev_name": name,
            "far_role": None,
        }

    t1, t2 = "vco:ent-1:path:e-hub:lh~link:e-br1:l1", "vco:ent-1:path:e-hub:lh~link:e-br2:l2"
    graph.candidate_tunnels[("dev:hub", "seg:corp")] = [
        row(t1, "vco:ent-1:edge:e-br2", "branch-2"),
        row(t1, "vco:ent-1:edge:e-br1", "branch-1"),
        row(t2, "vco:ent-1:edge:e-br1", "branch-1"),
        row(t2, "vco:ent-1:edge:e-br2", "branch-2"),
    ]
    graph.far_prefixes = {
        "vco:ent-1:edge:e-br2": [
            {"far_dev": "vco:ent-1:edge:e-br2", "cidr": "10.20.2.0/24", "prefix_uid": "p2"}
        ]
    }
    hub_gw = {**HUB_WAN, "if_uid": "if:hub-lan", "if_name": "GE3"}
    routes, info = sdwan.candidate_routes(None, hub_gw, "vrf:hub-corp", _dst("10.20.2.7"))
    assert [r["tunnel_uid"] for r in routes] == [t2]
    assert "branch-2" in info["why"]


def test_a_branch_with_only_a_default_exit_draws_the_business_policy_result_beside_it():
    from hst.path.gates import sdwan

    mpls = _tunnel_row(MPLS, "GE1", "172.16.9.2", "mpls")
    flow = _flow("8.8.8.8")
    default = [{"far_dev": "dev:hub", "cidr": "0.0.0.0/0", "prefixlen": 0, "metric": 10}]
    rules = sdwan.policy_outcomes([_policy_rule(1, "internet", "direct")], flow)
    chosen, why = sdwan.rank_candidates(
        [mpls],
        [],
        [],
        flow["dst"],
        role=None,
        direct=[_DIRECT_EXIT],
        route_exits=default,
        policy=rules,
        flow=flow,
    )
    assert chosen == [mpls, _DIRECT_EXIT]
    assert "Secure Default Route Override" in why and "does not hold" in why
    # a longer exit prefix keeps the route table's answer
    longer = [{**default[0], "cidr": "8.8.8.0/24", "prefixlen": 24}]
    chosen, _ = sdwan.rank_candidates(
        [mpls],
        [],
        [],
        flow["dst"],
        role=None,
        direct=[_DIRECT_EXIT],
        route_exits=longer,
        policy=rules,
        flow=flow,
    )
    assert chosen == [mpls]


def test_the_carrier_finds_its_far_device_by_the_tunnels_own_far_node(graph):
    """Another edge's WAN link holds the same public address and sorts first.
    The tunnel's own far node is the hub's, so the carrier resumes on the hub."""
    _overlay(graph)
    other = {
        "dev_uid": "dev:aaa",
        "dev_name": "aaa-edge",
        "if_uid": "if:aaa-ge2",
        "if_name": "GE2",
        "l3dom": "global",
    }
    hub_owner = graph.far_owner["203.0.113.2"]
    graph.far_owner["203.0.113.2"] = other
    graph.far_owner_by_node["ip:hub:203.0.113.2"] = hub_owner
    result = path.trace(None, "10.0.0.5", "10.50.0.9", port=443, proto="tcp", gateways=[BR])
    dia_leg = next(leg for leg in result["legs"] if leg["carrier"]["endpoint"] == "203.0.113.2")
    assert "decapsulated on hub-1" in dia_leg["carrier"]["verdict"]
    assert not [h for h in result["hops"] if h["label"] == "aaa-edge"]


def test_the_direct_exits_are_read_for_the_boundary_segment_only(graph):
    """A direct exit of a rule in another segment is not an exit of this
    boundary."""
    from hst.path.gates import sdwan

    assert "sv.segment_id = $segment_id" in sdwan._DIRECT_EXITS_QUERY
    _overlay(graph)
    seen: list[dict] = []
    original = graph.read

    def read(query, **params):
        if query == sdwan._DIRECT_EXITS_QUERY:
            seen.append(params)
        return original(query, **params)

    graph.read = read
    sdwan.candidate_routes(None, BR, "vrf:br-corp", _dst("8.8.8.8"))
    assert seen and seen[0]["segment_id"] == "1"


def test_the_tunnel_selection_leaves_a_split_a_tie_and_mixed_kinds_undecided():
    from hst.path.addrsets import _intervals
    from hst.path.trace import _select_tunnel

    hq = {"uid": "tun:a", "name": "to-hq", "encap": "wireguard", "allowed_ips": ["10.1.0.0/16"]}
    r2 = {"uid": "tun:b", "name": "to-r2", "encap": "wireguard", "allowed_ips": ["10.2.0.0/16"]}
    tun, why, drop = _select_tunnel([hq, r2], _intervals(["10.1.0.0-10.2.255.255"]), "wg0")
    assert tun is hq and drop is None and "spans the allowed IPs of WireGuard peers to-hq, to-r2" in why
    twin = {**r2, "uid": "tun:c", "name": "to-r3"}
    tun, why, drop = _select_tunnel([r2, twin], _intervals(["10.2.3.4"]), "wg0")
    assert tun is r2 and "at the same prefix" in why
    tun, why, drop = _select_tunnel([hq], _intervals(["10.0.0.0/15"]), "wg0")
    assert tun is hq and "no peer allows 10.0.0.0/16, which WireGuard drops" in why
    gre = {"uid": "tun:z", "name": "zia", "encap": "gre", "allowed_ips": None}
    tun, why, drop = _select_tunnel([gre, hq], _intervals(["10.1.2.3"]), "eth0")
    assert tun is gre and "2 tunnels end on eth0" in why
    assert _select_tunnel([gre], _intervals(["10.1.2.3"]), "eth0") == (gre, None, None)
