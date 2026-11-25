import importlib
import ipaddress
from importlib import import_module
from types import SimpleNamespace

import pytest
from tests.support.query_text import unpinned

from hst import path
from hst.core import cycle as cyclemod
from hst.core.ipenc import addr_bytes

# `hst.path.trace` the module, not `hst.path.trace` the function the
# package re-exports under the same name.
tracemod = importlib.import_module("hst.path.trace")


class FakeGraph:
    """Answers the tracer's reads by matching fragments of its queries."""

    def __init__(self):
        self.sources: list[dict] = []
        self.sources_by_ip: dict[str, list[dict]] = {}  # per-probe override of `sources`
        # The rows of path._DST_INSTANCES_QUERY are keyed by ip.
        self.dst_instances: dict[str, list[dict]] = {}
        self.pbr: list[dict] = []
        # per-ingress-interface override of `pbr`: the PbrPolicy read is scoped
        # to the interface the flow ingressed, so a policy enforced on another
        # interface of the same device is never in the rows it returns
        self.pbr_by_if: dict[str, list[dict]] = {}
        # The rows of gates.pbr._DEVICE_PBR_POLICIES are keyed by device uid.
        self.pbr_by_dev: dict[str, list[dict]] = {}
        self.nat: list[dict] = []  # rows in the shape of path._NAT_RULES_QUERY
        self.nat_by_dev: dict[str, list[dict]] = {}  # per-device override of `nat`
        # next-hop ip -> owning device/interface row, or a list of candidate
        # rows when the address exists in more than one forwarding context
        self.next_hop_devs: dict[str, dict | list[dict]] = {}
        self.next_hop_lookups: list[str] = []
        # table uid -> context uids sharing a RoutingDomain with it
        # (path._NEXT_HOP_DOMAIN_QUERY)
        self.domain_mates: dict[str, list[str]] = {}
        # VrfInstance uid -> {"name", "is_global"} (routing._NEXT_HOP_CONTEXTS_QUERY);
        # a uid left out is an anchor that is not a recorded forwarding context
        self.contexts: dict[str, dict] = {}
        # trace._GATEWAY_ADDRESSES_QUERY: gateway interface uid -> its addresses
        self.gateway_addresses: dict[str, list[str]] = {}
        self.tunnel: dict | None = None  # the Tunnel on the egress interface's ENDPOINT edge
        # Tunnels found by the other arm of the egress lookup: source_ip ->
        # the Tunnel row, joined against the interface's own address
        self.tunnel_by_source_ip: dict[str, dict] = {}
        # interface uid -> its `kind`, which decides whether a source_ip match
        # is a 'tunnel' binding (a tunnel interface) or a 'source' one
        self.iface_kinds: dict[str, str] = {}
        self.tunnel_props: dict | None = None  # its carrier endpoint row
        self.iface_addrs: dict[str, str] = {}  # interface uid -> its own address
        # firewall._interface_names: interface uid -> the name a rule's
        # in_interface/out_interface scope is compared against
        self.iface_names: dict[str, str] = {}
        # device uid -> the rows of trace._OWN_ADDRS_QUERY: every address the
        # device itself answers for, which a destination is checked against
        # before any route lookup (router-local delivery)
        self.dev_addrs: dict[str, list[dict]] = {}
        self.iface_roles: dict[str, str] = {}  # interface uid -> collected Cisco nat_role
        self.default_tables: dict[str, dict] = {}  # per-ingress-if override of default_table
        self.iface_segments: dict[str, list[str]] = {}  # interface uid -> realized L2 segment uids
        self.segment_reads: list[list[str]] = []  # the interfaces of each batched segment read
        self.trunk_by_ifuid: dict[str, dict | None] = {}  # gw['if_uid'] -> trunk row (rp/swp/...)
        self.trunk_by_name: dict[tuple[str, str], dict | None] = {}  # (parent name, dev) -> trunk row
        # (attach/from_uid, swp/anchor) -> {'chain': [...]}
        self.l2_chains: dict[tuple[str, str], dict | None] = {}
        self.routes: dict[str, list[dict]] = {}  # table uid -> route rows
        self.default_table: dict | None = {"uid": "vrf:main"}
        # _LOCAL_VRF_QUERY's answer (the carrier trace's own routing table),
        # shaped like its RETURN: vrf_uid/vrf_name, not default_table's uid/name
        self.local_vrf: dict | None = {"vrf_uid": "vrf:main", "vrf_name": "default"}
        self.wan: dict | None = None
        self.rb: dict | None = None  # the forward-chain rulebase
        self.rb_by_chain: dict[str, dict] = {}  # per-chain override (output = router-local)
        # A None value answers firewall._ACCESS_VENDOR_QUERY with the vendor of `rb`.
        self.access_vendors: list[str | None] | None = None
        self.rules: list[dict] = []
        self.gates: list[dict] = []
        self.aci_ends: list[dict] = []
        self.aci_contracts: list[dict] = []
        self.zone_pairs: dict[tuple[str, str | None], dict] = {}
        # The rows of firewall._DEVICE_ZONE_RULEBASES are keyed by device uid.
        self.zone_rulebases_by_dev: dict[str, list[dict]] = {}
        self.zone_rules: dict[str, list[dict]] = {}
        # (prefix uid, device uid) -> gateway interface row; device None keys
        # the unpinned lookup, "ingress" keys the ingress-serves-prefix check
        self.gateway_for: dict[tuple[str, str | None], dict] = {}
        self.ingress_zones: dict[str, str] = {}
        # zone name -> the zone's other properties the zone read returns
        # (`intra_zone_filtering`, `intra_zone_action`)
        self.zone_props: dict[str, dict] = {}
        # routing._LINK_PEER_QUERY: (egress interface uid, link-local address)
        # -> the interface rows on that link holding the address
        self.link_peers: dict[tuple[str, str], list[dict]] = {}
        self.seen_queries: list[str] = []
        # gates.lb._vip_bindings: (ip, dev_uid) -> the VirtualService row(s)
        # bound there, one dict or a list of them; absent when nothing is bound
        self.vip: dict[tuple[str, str], dict | list[dict] | None] = {}
        # gates.lb._vip_elsewhere: ip -> the VirtualService rows bound to any
        # device, each with the `on_uid` it is bound to
        self.vip_elsewhere: dict[str, list[dict]] = {}
        # gates.lb._lb_segment_interfaces: the Device or RedundancyGroup uid a
        # VirtualService is ON -> the addressed interface rows of its devices
        self.lb_interfaces: dict[str, list[dict]] = {}
        # gates.lb._pool_members: VirtualService uid -> its pool's member rows
        self.pool_members: dict[str, list[dict]] = {}
        # gates.lb._lb_snat's SNAT_FROM read: VirtualService uid -> the snip row
        self.snat_from: dict[str, dict | None] = {}
        # gates.lb._snip_for: device uid -> its own interface-address/prefix rows
        self.snip_candidates: dict[str, list[dict]] = {}
        # gates.zpa._access_rule_match: (identity, segment) -> candidate rule rows
        self.access_rules: dict[tuple[str | None, str | None], list[dict]] = {}
        # the recorded MEMBER_OF edges: segment uid -> the ZpaSegmentGroup uids
        self.segment_groups: dict[str, list[str]] = {}
        # gates.zpa._segment_resolution: segment uid -> resolved address rows
        self.segment_resolution: dict[str, list[dict]] = {}
        # gates.zpa._connector_selection: segment uid -> candidate connector rows
        self.zpa_connectors: dict[str, list[dict]] = {}
        # gates.zpa._connector_address: connector uid -> host/address rows
        self.connector_address: dict[str, list[dict]] = {}
        # gates.zpa._connector_address's SAME_AS reading: connector uid -> {"ip", "confidence"}
        self.connector_same_as: dict[str, list[dict]] = {}
        # A segment ref is a uid or an FQDN.
        self.segment_ref: dict[str, dict | list[dict] | None] = {}
        # gates.zpa._identity_group: identity uid -> {"uid", "name"} or None
        self.identity_groups: dict[str, dict | None] = {}
        # gates.zpa._segment_port_match: segment uid -> {"tcp": [...], "udp": [...]}
        self.segment_ports: dict[str, dict | None] = {}

    def read(self, query, **params):
        from hst.path import checkpoint_installation, vsx

        query = unpinned(query)

        # gates.zpa._resolve_segment_refs
        if "$ref IN coalesce(seg.domains" in query:
            ref = self.segment_ref.get(params.get("ref"))
            return ref if isinstance(ref, list) else [ref] if ref else []

        if query in (unpinned(vsx.QUERY), unpinned(checkpoint_installation.QUERY)):
            return []
        # the egress tunnel lookup returns every candidate; the fakes
        # script one tunnel per interface through `read_one`
        if "Tunnel {source_ip: ip.ip}" in query:
            row = self.read_one(query, **params)
            return [row] if row else []
        # gates.lb._lb_snat reads every SNAT_FROM address: one dict or a list
        if "SNAT_FROM]->(ip:IpAddress)" in query:
            row = self.snat_from.get(params.get("vs"))
            return [row] if isinstance(row, dict) else list(row or [])
        # the gate safeguard is generated from core/labels.py GATE_BINDINGS and
        # names every gate label, so it must be recognised before any fragment
        # below (PbrPolicy, FROM_ZONE, ENFORCES) can claim it
        if "GATE_BINDINGS" in query or ("RETURN DISTINCT g.uid AS uid" in query and "devs" in params):
            return self.gates
        if "target.uid AS on_uid" in query:
            return list(self.vip_elsewhere.get(params.get("ip"), []))
        if "AS lb_role" in query:
            return list(self.lb_interfaces.get(params.get("on"), []))
        # gates.lb._vip_bindings, ordered before the source-address read below:
        # its own MATCH also carries the `IpAddress {ip: $ip}` inline map
        if "e1:VIP]->" in query:
            row = self.vip.get((params.get("ip"), params.get("dev")))
            if row is None:
                return []
            return [row] if isinstance(row, dict) else list(row)
        if "IpAddress {ip: $ip}" in query:
            if params.get("ip") in self.sources_by_ip:
                return self.sources_by_ip[params["ip"]]
            return self.sources
        # path._NEXT_HOP_DEVICE_QUERY is matched before the projection fragment below.
        if "ipv6_link_local" in query:
            return self.link_peers.get((params["u"], params["ip"]), [])
        if "AS dev_uid" in query and "HAS_IP" in query:
            self.next_hop_lookups.append(params["ip"])
            row = self.next_hop_devs.get(params["ip"])
            if row is None:
                return []
            return [row] if isinstance(row, dict) else list(row)
        if "ip.anchor AS anchor, ip.l3dom AS l3dom" in query:
            return self.dst_instances.get(params.get("ip"), [])
        # ordered before the generic rulebase fragment below: the NAT-rule read
        # also contains "ENFORCES]->(rb:FwRulebase"
        if "kind: 'nat'" in query:
            if self.nat_by_dev:
                return self.nat_by_dev.get(params.get("dev"), [])
            return self.nat
        # gates.pbr._DEVICE_PBR_POLICIES, ordered before the per-interface
        # PbrPolicy read below: every PbrPolicy the device enforces from any
        # interface, which the cross-interface credit reads
        if "AS pol_uid, i.uid AS if_uid" in query:
            return self.pbr_by_dev.get(params.get("dev"), [])
        if "PbrPolicy" in query:
            if self.pbr_by_if:
                return self.pbr_by_if.get(params.get("if_uid"), [])
            return self.pbr
        if "MEMBER_OF]->(rd:RoutingDomain)" in query:
            mates = self.domain_mates.get(params["table"], [])
            return [{"uid": u} for u in mates if u in params["anchors"]]
        if "collect(DISTINCT ip.ip) AS addresses" in query and "interfaces" in params:
            return [
                {"if_uid": u, "addresses": self.gateway_addresses[u]}
                for u in sorted(params["interfaces"])
                if u in self.gateway_addresses
            ]
        if "v.is_global AS is_global" in query:
            return [{"uid": u, **self.contexts[u]} for u in sorted(params["uids"]) if u in self.contexts]
        # path._IFACE_SEGMENT_QUERY: the egress interface's realized broadcast
        # domain(s), EXTENDS-reachable ones included
        if "(v:VlanInstance)-[rz:REALIZES]" in query:
            if "us" in params:
                self.segment_reads.append(list(params["us"]))
                return [
                    {"u": u, "segs": list(self.iface_segments[u])}
                    for u in params["us"]
                    if self.iface_segments.get(u)
                ]
            return [{"uid": u} for u in self.iface_segments.get(params["u"], [])]
        if "STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES" in query:
            return self.routes.get(params["vrf"], [])
        # trace._OWN_ADDRS_QUERY: the device's own interface addresses
        if "ip.uid AS ip_uid, i.uid AS if_uid" in query:
            return self.dev_addrs.get(params.get("dev"), [])
        # firewall._interface_names: the resolved names of this hop's two sides
        if "i.uid IN [$a, $b]" in query:
            return [
                {"uid": u, "name": self.iface_names[u]}
                for u in (params.get("a"), params.get("b"))
                if u in self.iface_names
            ]
        # _connected_egress's remote lookup: every interface serving the prefix
        # on any device, in uid order (the local and ingress lookups stay read_one)
        if "GATEWAY_FOR]->(p:Prefix {uid: $p})" in query:
            self.seen_queries.append(query)
            row = self.gateway_for.get((params["p"], None))
            return [row] if row else []
        if "IN_EPG" in query:
            return self.aci_ends
        if "CONSUMES" in query:
            # the fields apic.py writes on every vzEntry; an entry
            # without them is read as not collected
            return [
                {
                    **row,
                    "entries": [
                        {
                            "s_from_port": "unspecified",
                            "s_to_port": "unspecified",
                            "tcp_rules": "unspecified",
                            "apply_to_frag": "no",
                            **entry,
                        }
                        for entry in row.get("entries") or ()
                    ],
                }
                for row in self.aci_contracts
            ]
        # firewall._ACCESS_VENDOR_QUERY is matched before the generic rulebase fragment below.
        if "DISTINCT rb.vendor AS vendor" in query:
            if self.access_vendors is not None:
                return [{"vendor": v} for v in self.access_vendors]
            rbs = list(self.rb_by_chain.values()) if self.rb_by_chain else [self.rb]
            columns = ("vendor", "match_context")
            return [{column: rb.get(column) for column in columns} for rb in rbs if rb]
        # firewall._DEVICE_CHAINS is matched before the generic fragment below.
        if "DISTINCT rb.chain AS chain" in query:
            if self.rb_by_chain:
                # a row keyed by a chain but carrying chain None models a
                # rulebase that recorded no chain (the candidate read folds
                # it into 'forward'; the chain list does not report it)
                return [
                    {"chain": c}
                    for c, row in sorted(self.rb_by_chain.items())
                    if row.get("chain", c) is not None
                ]
            return [{"chain": "forward"}] if self.rb else []
        if "ENFORCES]->(rb:FwRulebase)" in query:
            chain = params.get("chain", "forward")
            if self.rb_by_chain:
                row = self.rb_by_chain.get(chain)
                return [{**row, "chain": row.get("chain", chain)}] if row else []
            if self.rb and chain == "forward":
                return [{**self.rb, "chain": self.rb.get("chain", "forward")}]
            return []
        # firewall._DEVICE_ZONE_RULEBASES, ordered before the interface-pair
        # read below: every zone-bound rulebase of the device, which the
        # cross-pair credit reads
        if "device_zones" in query:
            return self.zone_rulebases_by_dev.get(params.get("dev"), [])
        if "src_owned:OWNED_BY" in query and "dst_owned:OWNED_BY" in query:
            return []
        if "FROM_ZONE" in query:
            row = self.zone_pairs.get((params["in_if"], params["out_if"]))
            return [row] if row else []
        if "FwRulebase {uid: $rb}" in query:
            if params.get("rb") in self.zone_rules:
                return self.zone_rules[params["rb"]]
            return self.rules
        # gates.lb._pool_members
        if "HAS_MEMBER]->(pm:PoolMember)" in query:
            return self.pool_members.get(params.get("vs"), [])
        # gates.lb._snip_for's candidate read
        if "[e:IN]->(p:Prefix)" in query:
            return self.snip_candidates.get(params.get("dev"), [])
        if "applies_to_all_identities AS applies_to_all_identities" in query:
            identity, segment = params.get("identity"), params.get("segment")
            rows = list(self.access_rules.get((identity, segment), []))
            for group in self.segment_groups.get(segment, []):
                rows.extend(self.access_rules.get((identity, group), []))
            return rows
        # gates.zpa._segment_resolution
        if "RESOLVES_TO*1..5" in query:
            return self.segment_resolution.get(params.get("segment"), [])
        # gates.zpa._connector_selection
        if "conn.health AS health" in query:
            return self.zpa_connectors.get(params.get("segment"), [])
        # gates.zpa._connector_address
        if "host.uid AS host_uid" in query:
            return self.connector_address.get(params.get("connector"), [])
        if "sa.confidence AS confidence" in query:
            return self.connector_same_as.get(params.get("connector"), [])
        return []

    def read_one(self, query, **params):
        query = unpinned(query)
        if "IN_VRF]-(i:Interface {uid: $if_uid})" in query:
            if params.get("if_uid") in self.default_tables:
                return self.default_tables[params["if_uid"]]
            return self.default_table
        if "v.is_global = true" in query:
            return self.local_vrf
        if "RETURN v.name AS n" in query:
            return {"n": "default"}
        if "HAS_LINK" in query:
            return self.wan
        # Each arm of the egress tunnel lookup is answered from its own script.
        if "Tunnel {source_ip: ip.ip}" in query:
            if self.tunnel:
                return self.tunnel
            addr = self.iface_addrs.get(params.get("u", ""))
            row = self.tunnel_by_source_ip.get(addr) if addr else None
            if row is None:
                return None
            tunnel_if = self.iface_kinds.get(params.get("u", "")) in ("tunnel", "vti", "wireguard")
            return {**row, "binding": "tunnel" if tunnel_if else "source"}
        if "t.endpoint AS endpoint" in query:
            return self.tunnel_props
        if "HAS_IP]->(ip:IpAddress)" in query and (
            "RETURN ip.ip AS ip" in query or "RETURN addresses[0] AS ip" in query
        ):
            ip = self.iface_addrs.get(params.get("u", ""))
            if ip and params.get("af") and ipaddress.ip_address(ip).version != params["af"]:
                return None
            return {"ip": ip} if ip else None
        if "RETURN i.nat_role AS nat_role" in query:
            return {"nat_role": self.iface_roles.get(params.get("u", ""))}
        if "GATEWAY_FOR" in query:
            self.seen_queries.append(query)
            if "Device {uid: $dev}" in query:
                row = self.gateway_for.get((params["p"], params["dev"]))
                # emulate the query's own `i.uid <> $in_if` exclusion
                if row and row["uid"] == params["in_if"]:
                    return None
                return row
            if "Interface {uid: $in_if}" in query:
                return self.gateway_for.get((params["p"], "ingress"))
            return self.gateway_for.get((params["p"], None))
        # firewall._DEVICE_STATE_POLICY_QUERY: the device's own state policy,
        # read from the scripted forward-chain rulebase; it names the Zone
        # pattern too, so it must be matched before the ingress-zone read
        if "global_state_policy IS NOT NULL" in query:
            pol = (self.rb or {}).get("global_state_policy")
            return {"global_state_policy": pol} if pol else None
        if "CONTAINS]-(z:Zone)" in query:
            name = self.ingress_zones.get(params["in_if"])
            return {"name": name, **self.zone_props.get(name, {})} if name else None
        # _gateway_walk's trunk lookup (Interface REALIZED_BY Port CONNECTED_TO Port)
        if "REALIZED_BY" in query and "CONNECTED_TO" in query:
            if "i:Interface {uid: $if_uid}" in query:
                return self.trunk_by_ifuid.get(params.get("if_uid"))
            if "i:Interface {name: $name}" in query:
                return self.trunk_by_name.get((params.get("name"), params.get("dev")))
        # _gateway_walk's and _delivery_walk's allShortestPaths chain
        if "allShortestPaths" in query:
            key = (params.get("attach") or params.get("a"), params.get("swp") or params.get("z"))
            return self.l2_chains.get(key)
        # gates.lb._lb_snat's SNAT_FROM read
        if "SNAT_FROM]->(ip:IpAddress)" in query:
            return self.snat_from.get(params.get("vs"))
        # gates.zpa._identity_group
        if "IdentityGroup {uid: $identity}" in query:
            return self.identity_groups.get(params.get("identity"))
        # gates.zpa._segment_port_match
        if "seg.tcp_port_ranges AS tcp" in query:
            return self.segment_ports.get(params.get("segment"))
        return None


@pytest.fixture()
def graph(monkeypatch):
    g = FakeGraph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


GW = {
    "cidr": "10.0.0.0/24",
    "l3dom": "home",
    "if_uid": "if:eth1",
    "if_name": "eth1",
    "dev_uid": "dev:r1",
    "dev_name": "r1",
}


def _src_row(dom="home", ip="10.0.0.5"):
    return {
        "ip_uid": f"ip:{dom}:{ip}",
        "l3dom": dom,
        "ep_uid": None,
        "ep_name": None,
        "att_uid": None,
        "att_name": None,
        "att_is_port": None,
        "ssid": None,
        "sw_uid": None,
        "sw_name": None,
        "seg_uid": None,
    }


def _route(cidr, egress=None, next_hop=None, kind="STATIC_ROUTE", derived=None, via_rt=None, discard=None):
    return {
        "uid": f"pfx:{cidr}",
        "cidr": cidr,
        "kind": kind,
        "next_hop": next_hop,
        "ifname": egress,
        "egress_uid": f"if:{egress}" if egress else None,
        "egress_name": egress,
        "derived": derived,
        "via_rt": via_rt,
        "discard": discard,
    }


def _rule(**kw):
    base = {
        "uid": "cp:r1",
        "pos": 1,
        "action": "accept",
        "name": None,
        "out_if": None,
        "in_if": None,
        "src_any": True,
        "dst_any": True,
        "svc_any": True,
        "src_cidrs": [],
        "src_ips": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "protos": [],
        "ports": [],
        "src_ranges": [],
        "dst_ranges": [],
    }
    return {**base, **kw}


# --- WAN fallback ------------------------------------------------------------------------


def test_a_wan_link_alone_is_not_a_default_route(graph):
    graph.sources = [_src_row()]
    graph.wan = {"uid": "wan:1", "name": "dia"}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    assert result["legs"][0]["verdict"] == "no route found"
    assert not [h for h in result["hops"] if h["kind"] == "WanLink"]
    assert "no route found" in result["verdict"]


def test_a_default_route_of_the_other_family_does_not_reach_the_wan(graph):
    graph.sources = [_src_row()]
    graph.wan = {"uid": "wan:1", "name": "dia"}
    graph.routes = {"vrf:main": [_route("0.0.0.0/0")]}  # v4 default, v6 destination
    result = path.trace(None, "10.0.0.5", "2001:db8::1", gateways=[GW])
    assert result["legs"][0]["verdict"] == "no route found"
    assert not [h for h in result["hops"] if h["kind"] == "WanLink"]


def test_a_real_default_route_names_the_wan_it_leaves_by(graph):
    graph.sources = [_src_row()]
    graph.wan = {"uid": "wan:1", "name": "dia"}
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via eth0"
    wan_hops = [h for h in result["hops"] if h["kind"] == "WanLink"]
    assert [h["label"] for h in wan_hops] == ["dia"]


def test_a_default_route_without_a_wan_link_egresses_plainly(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via eth0"
    assert not [h for h in result["hops"] if h["kind"] == "WanLink"]


# --- PBR partitioning --------------------------------------------------------------------


def test_pbr_partial_destination_leaves_the_rest_to_the_main_table(graph):
    """A rule claiming src x half the destination set must not swallow the other
    half: the sub-flow (claimed sources x unmatched destinations) continues to
    later rules and the main table."""
    graph.sources = [_src_row()]
    graph.pbr = [
        {
            "pol_uid": "pol:1",
            "pol_name": "steer",
            "rule_uid": "rule:10",
            "pos": 10,
            "rule_name": None,
            "src_cidrs": [],
            "src_ips": [],
            "src_ranges": [],
            "dst_cidrs": ["10.9.9.0/25"],
            "dst_ips": [],
            "dst_ranges": [],
            "table_uid": "vrf:100",
            "table_name": "100",
        }
    ]
    graph.routes = {
        "vrf:100": [_route("0.0.0.0/0", egress="wg0")],
        "vrf:main": [_route("0.0.0.0/0", egress="eth0")],
    }
    result = path.trace(None, "10.0.0.5", "10.9.9.0/24", gateways=[GW])
    assert len(result["legs"]) == 2
    by_table = {leg["table"]: leg for leg in result["legs"]}
    assert by_table["100"]["egress"] == "wg0"
    assert by_table["default"]["egress"] == "eth0"
    assert any("part of the destination" in n for n in result["notes"])


def test_pbr_fallback_table_follows_the_interfaces_own_in_vrf_edge(graph):
    graph.default_table = None
    graph.default_tables = {"if:eth1": {"uid": "vrf:CORP"}}
    trail = path._Trail()
    groups = path._pbr_partition(
        None, trail, "if:eth1", path._intervals(["10.0.0.5"]), path._intervals(["8.8.8.8"])
    )
    assert len(groups) == 1
    assert groups[0]["table_uid"] == "vrf:CORP"
    # the "default" label is display-only fallback text for the unclaimed-flow
    # group; it names no VrfInstance and does not have to match one
    assert groups[0]["table_name"] == "default"


def test_a_pbr_rule_with_no_target_table_falls_through_to_main(graph):
    graph.sources = [_src_row()]
    graph.pbr = [
        {
            "pol_uid": "pol:1",
            "pol_name": "steer",
            "rule_uid": "rule:10",
            "pos": 10,
            "rule_name": None,
            "src_cidrs": [],
            "src_ips": [],
            "src_ranges": [],
            "dst_cidrs": [],
            "dst_ips": [],
            "dst_ranges": [],
            "table_uid": None,
            "table_name": None,
        }
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    leg = result["legs"][0]
    assert leg["egress"] == "eth0"
    assert leg["verdict"] != "no route found"
    assert any("falls through" in n for n in result["notes"])
    note = next(n for n in result["notes"] if "falls through" in n)
    assert "no resolvable target table" in note
    assert "neither the graph nor the route store" in note
    rule_hop = next(h for h in result["hops"] if h["uid"] == "rule:10")
    assert rule_hop["note"] == "→ no resolvable target table"
    table_hop = next(h for h in result["hops"] if h["kind"] == "VrfInstance")
    assert table_hop["note"] == "PBR rule 10 fell through to default"


def _pbr_row(pol_uid, pol_name, rule_uid, table_uid, table_name, pos=10, **kw):
    """One row of the PbrPolicy read: a policy, one of its rules, its target
    table. `kw` overrides the address and service columns."""
    return {
        "pol_uid": pol_uid,
        "pol_name": pol_name,
        "rule_uid": rule_uid,
        "pos": pos,
        "rule_name": None,
        "src_cidrs": [],
        "src_ips": [],
        "src_ranges": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "dst_ranges": [],
        "table_uid": table_uid,
        "table_name": table_name,
        **kw,
    }


def test_the_pbr_credit_covers_every_policy_the_stage_read(graph):
    graph.sources = [_src_row()]
    graph.pbr_by_if = {
        "if:eth1": [
            _pbr_row("pol:dc", "DC-PBR", "rule:dc:10", "vrf:t300", "table300", dst_cidrs=["10.0.30.0/24"]),
            _pbr_row(
                "pol:voip",
                "VOIP-PBR",
                "rule:voip:10",
                "vrf:t400",
                "table400",
                svc_obj_count=1,
                svc_protos=["udp"],
                svc_port_specs=["5060"],
            ),
        ]
    }
    graph.routes = {"vrf:t300": [_route("10.0.30.0/24", egress="eth2")]}
    graph.gates = [
        {"uid": "pol:dc", "name": "DC-PBR", "kind": "PbrPolicy"},
        {"uid": "pol:voip", "name": "VOIP-PBR", "kind": "PbrPolicy"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["egress"] == "eth2"
    assert leg["pbr_uids"] == ["pol:dc", "pol:voip"]
    assert not leg["indeterminate"]
    assert "gate(s) not evaluated" not in result["verdict"]


def test_a_pbr_policy_on_another_interface_of_the_device_is_credited(graph):
    graph.sources = [_src_row()]
    graph.pbr_by_if = {
        "if:eth1": [
            _pbr_row("pol:dc", "DC-PBR", "rule:dc:10", "vrf:t300", "table300", dst_cidrs=["10.0.30.0/24"])
        ],
    }
    graph.pbr_by_dev = {
        "dev:r1": [
            {"pol_uid": "pol:dc", "if_uid": "if:eth1"},
            {"pol_uid": "pol:wan", "if_uid": "if:eth0"},
        ]
    }
    graph.routes = {"vrf:t300": [_route("10.0.30.0/24", egress="eth2")]}
    graph.gates = [
        {"uid": "pol:dc", "name": "DC-PBR", "kind": "PbrPolicy"},
        {"uid": "pol:wan", "name": "WAN-PBR", "kind": "PbrPolicy"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert result["legs"][0]["pbr_uids"] == ["pol:dc", "pol:wan"]
    assert "gate(s) not evaluated" not in result["verdict"]
    assert result["warnings"] == []


def test_a_pbr_policy_on_the_ingress_interface_not_read_stays_reported(graph):
    graph.sources = [_src_row()]
    graph.pbr_by_if = {"if:eth1": []}
    graph.pbr_by_dev = {"dev:r1": [{"pol_uid": "pol:dc", "if_uid": "if:eth1"}]}
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2")]}
    graph.gates = [{"uid": "pol:dc", "name": "DC-PBR", "kind": "PbrPolicy"}]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert "pol:dc" not in (result["legs"][0].get("pbr_uids") or [])
    assert "1 gate(s) not evaluated" in result["verdict"]
    assert any("DC-PBR" in w for w in result["warnings"])


def test_a_pbr_policy_with_no_evaluable_rule_is_credited(graph):
    graph.sources = [_src_row()]
    graph.pbr_by_if = {
        "if:eth1": [
            _pbr_row("pol:dc", "DC-PBR", "rule:dc:10", "vrf:t300", "table300", dst_cidrs=["10.0.30.0/24"]),
            _pbr_row("pol:voip", "VOIP-PBR", None, None, None, pos=None),
        ]
    }
    graph.routes = {"vrf:t300": [_route("10.0.30.0/24", egress="eth2")]}
    graph.gates = [
        {"uid": "pol:dc", "name": "DC-PBR", "kind": "PbrPolicy"},
        {"uid": "pol:voip", "name": "VOIP-PBR", "kind": "PbrPolicy"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["egress"] == "eth2"
    assert leg["pbr_uids"] == ["pol:dc", "pol:voip"]
    assert not leg["indeterminate"]
    assert "gate(s) not evaluated" not in result["verdict"]


def test_the_pbr_read_matches_a_policys_rules_optionally():
    import inspect

    from hst.path.gates.pbr import _INTERFACE_POLICY_RULES, _pbr_partition

    assert "_INTERFACE_POLICY_RULES" in inspect.getsource(_pbr_partition)
    src = _INTERFACE_POLICY_RULES
    assert "OPTIONAL MATCH (pol)-[hr:HAS_RULE]->(r:FwRule)" in src
    assert "\nMATCH (pol)-[hr:HAS_RULE]->(r:FwRule)" not in src


def _pbr_rule_to(table_uid, table_name):
    return {
        "pol_uid": "pol:1",
        "pol_name": "steer",
        "rule_uid": "rule:10",
        "pos": 10,
        "rule_name": None,
        "src_cidrs": [],
        "src_ips": [],
        "src_ranges": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "dst_ranges": [],
        "table_uid": table_uid,
        "table_name": table_name,
    }


def test_a_pbr_target_table_answered_only_by_the_route_store_keeps_the_redirect(monkeypatch):
    g = _FakeGraphWithInterfaceLookup({"gi0/2": {"uid": "if:gi0/2", "name": "gi0/2"}})
    g.sources = [_src_row()]
    g.pbr = [_pbr_rule_to("vrf:pbr-100", "pbr-100")]
    # the graph holds the DEFAULT table only; the steered table lives in the store
    g.routes = {"vrf:main": [_route("0.0.0.0/0", egress="gi0/1")]}
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    rib = _TableScopedRib(
        {
            "vrf:pbr-100": [
                {
                    "prefix": "0.0.0.0/0",
                    "next_hop": None,
                    "interface": "gi0/2",
                    "protocol": "static",
                    "metric": None,
                    "prefixlen": 0,
                    "af": 4,
                }
            ]
        }
    )

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW], rib=rib)

    assert result["legs"][0]["egress"] == "gi0/2"
    assert not any("falls through" in n for n in result["notes"])


def test_a_pbr_target_table_empty_in_the_graph_and_the_store_falls_through(monkeypatch):
    g = _FakeGraphWithInterfaceLookup({"gi0/1": {"uid": "if:gi0/1", "name": "gi0/1"}})
    g.sources = [_src_row()]
    g.pbr = [_pbr_rule_to("vrf:pbr-100", "pbr-100")]
    g.routes = {"vrf:main": [_route("0.0.0.0/0", egress="gi0/1")]}
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    rib = _TableScopedRib({})

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW], rib=rib)

    assert result["legs"][0]["egress"] == "gi0/1"
    note = next(n for n in result["notes"] if "falls through" in n)
    assert "table pbr-100" in note


def test_a_pbr_target_table_mirrored_but_covering_nothing_falls_through(monkeypatch):
    g = _FakeGraphWithInterfaceLookup({"gi0/1": {"uid": "if:gi0/1", "name": "gi0/1"}})
    g.sources = [_src_row()]
    g.pbr = [_pbr_rule_to("vrf:pbr-100", "pbr-100")]
    g.routes = {
        "vrf:main": [_route("0.0.0.0/0", egress="gi0/1")],
        # mirrored, but 192.168.50.0/24 does not cover 8.8.8.8
        "vrf:pbr-100": [_route("192.168.50.0/24", egress="gi0/2")],
    }
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    rib = _TableScopedRib({})

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW], rib=rib)

    assert result["legs"][0]["egress"] == "gi0/1"
    note = next(n for n in result["notes"] if "falls through" in n)
    assert "table pbr-100" in note


def test_a_pbr_target_table_mirrored_and_covering_the_destination_keeps_the_redirect(monkeypatch):
    g = _FakeGraphWithInterfaceLookup({"gi0/2": {"uid": "if:gi0/2", "name": "gi0/2"}})
    g.sources = [_src_row()]
    g.pbr = [_pbr_rule_to("vrf:pbr-100", "pbr-100")]
    g.routes = {
        "vrf:main": [_route("0.0.0.0/0", egress="gi0/1")],
        "vrf:pbr-100": [_route("0.0.0.0/0", egress="gi0/2")],
    }
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    rib = _TableScopedRib({})

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW], rib=rib)

    assert result["legs"][0]["egress"] == "gi0/2"
    assert not any("falls through" in n for n in result["notes"])


def _pbr_svc_rule(**svc):
    """A PBR rule redirecting to table 100, with the service columns
    `_pbr_partition` projects (defaults: an SvcObject naming nothing)."""
    return {
        "pol_uid": "pol:1",
        "pol_name": "steer",
        "rule_uid": "rule:10",
        "pos": 10,
        "rule_name": None,
        "src_cidrs": [],
        "src_ips": [],
        "src_ranges": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "dst_ranges": [],
        "table_uid": "vrf:100",
        "table_name": "100",
        "svc_obj_count": 1,
        "svc_protos": [None],
        "svc_port_specs": [None],
        "svc_opaque": False,
        "svc_opaque_reasons": [],
        "svc_src_port": False,
        **svc,
    }


def test_a_pbr_rule_scoped_to_a_protocol_the_flow_lacks_is_indeterminate(graph):
    graph.sources = [_src_row()]
    graph.pbr = [_pbr_svc_rule(svc_protos=["tcp"])]
    graph.routes = {"vrf:100": [_route("0.0.0.0/0", egress="wg0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])  # no proto on this query
    assert result["indeterminate"]
    assert result["legs"][0]["egress"] == "wg0"
    # the reason reaches the leg and the warnings, naming the rule and the
    # dimension that went undecided
    leg = result["legs"][0]
    assert "carries no protocol" in leg["indeterminate_reason"]
    assert any("PBR steer rule 10 claims this flow" in w for w in result["warnings"])


def test_a_pbr_rule_scoped_to_a_source_port_is_indeterminate_not_a_confident_match(graph):
    graph.sources = [_src_row()]
    graph.pbr = [_pbr_svc_rule(svc_src_port=True)]
    graph.routes = {"vrf:100": [_route("0.0.0.0/0", egress="wg0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["egress"] == "wg0"
    assert result["indeterminate"]
    assert "source port" in leg["indeterminate_reason"]


def test_a_pbr_rule_whose_port_name_the_collector_could_not_map_is_undecided_not_skipped(graph):
    graph.sources = [_src_row()]
    graph.pbr = [
        _pbr_svc_rule(
            svc_port_specs=[["myapp"]],
            svc_opaque=True,
            svc_opaque_reasons=["port 'myapp' is not a number or a known service name"],
        )
    ]
    graph.routes = {
        "vrf:100": [_route("0.0.0.0/0", egress="wg0")],
        "vrf:main": [_route("0.0.0.0/0", egress="eth0")],
    }
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["egress"] == "wg0"
    assert result["indeterminate"]
    assert "myapp" in leg["indeterminate_reason"]


# --- destination-set route straddling ----------------------------------------------------


def test_destination_set_straddling_routes_is_partitioned(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.9.0.0/16", egress="eth1"), _route("10.9.9.0/24", egress="eth2")]}
    result = path.trace(None, "10.0.0.5", "10.9.8.0/23", gateways=[GW])
    assert len(result["legs"]) == 2
    assert {leg["cidr"] for leg in result["legs"]} == {"10.9.0.0/16", "10.9.9.0/24"}
    assert {leg["egress"] for leg in result["legs"]} == {"eth1", "eth2"}
    assert {leg.get("dst_label") for leg in result["legs"]} == {"10.9.8.0/24", "10.9.9.0/24"}
    assert any("straddles" in n for n in result["notes"])
    assert "2 paths" in result["verdict"]


class _PrefixTableRib:
    def __init__(self, rows):
        self._rows = [(ipaddress.ip_network(r["prefix"]), r) for r in rows]

    def lpm(self, device_uid, context_uid, probe_ip, *, legacy_vrf=None):
        addr = ipaddress.ip_address(probe_ip)
        hits = [(net, r) for net, r in self._rows if net.version == addr.version and addr in net]
        if not hits:
            return []
        longest = max(net.prefixlen for net, _ in hits)
        return [r for net, r in hits if net.prefixlen == longest]

    def overlapping(self, device_uid, context_uid, lo, hi, min_prefixlen, af, *, legacy_vrf=None):
        return [
            r
            for net, r in self._rows
            if net.version == af
            and net.prefixlen > min_prefixlen
            and addr_bytes(str(net.network_address)) <= hi
            and addr_bytes(str(net.broadcast_address)) >= lo
        ]


def test_a_store_only_prefix_later_in_a_partly_routed_range_is_found_without_a_default_route(graph):
    graph.sources = [_src_row()]
    fake_rib = _PrefixTableRib(
        [
            {
                "prefix": "10.0.2.0/24",
                "next_hop": "10.0.0.9",
                "interface": "eth9",
                "protocol": "bgp",
                "metric": None,
                "prefixlen": 24,
                "af": 4,
            }
        ]
    )
    result = path.trace(None, "10.0.0.5", "10.0.0.0/22", gateways=[GW], rib=fake_rib)

    assert len(result["legs"]) == 2
    routed = [leg for leg in result["legs"] if leg["cidr"] == "10.0.2.0/24"]
    unrouted = [leg for leg in result["legs"] if leg["cidr"] != "10.0.2.0/24"]
    assert len(routed) == 1 and len(unrouted) == 1
    assert unrouted[0]["dst_label"] == "10.0.0.0/23, 10.0.3.0/24"
    assert unrouted[0]["verdict"] == "no route found"


# --- multi-domain sources ----------------------------------------------------------------


def test_an_ambiguous_source_fans_out_per_domain(graph):
    graph.sources = [_src_row("home"), _src_row("lab")]
    gws = [
        GW,
        {**GW, "l3dom": "lab", "if_uid": "if:lab1", "if_name": "lab1", "dev_uid": "dev:r2", "dev_name": "r2"},
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)
    assert {leg["domain"] for leg in result["legs"]} == {"home", "lab"}
    assert {h["domain"] for h in result["hops"]} == {"home", "lab"}
    lanes = [leg["lane"] for leg in result["legs"]]
    assert len(set(lanes)) == len(lanes)
    assert any("2 L3 domains" in n for n in result["notes"])
    assert "[home]" in result["verdict"] and "[lab]" in result["verdict"]
    # each domain rides its own gateway
    assert {h["uid"] for h in result["hops"] if h["domain"] == "home" and h["kind"] == "Device"} == {"dev:r1"}
    assert {h["uid"] for h in result["hops"] if h["domain"] == "lab" and h["kind"] == "Device"} == {"dev:r2"}


def test_an_ambiguous_source_with_a_shared_l3dom_fans_out_by_anchor(graph):
    graph.sources = [
        _src_row("home") | {"anchor": "vrf:dev:r1:home"},
        _src_row("home") | {"anchor": "vrf:dev:r2:home"},
    ]
    gws = [
        {**GW, "anchor": "vrf:dev:r1:home"},
        {
            **GW,
            "anchor": "vrf:dev:r2:home",
            "if_uid": "if:lab1",
            "if_name": "lab1",
            "dev_uid": "dev:r2",
            "dev_name": "r2",
        },
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)

    assert {leg["domain"] for leg in result["legs"]} == {"home"}
    lanes = [leg["lane"] for leg in result["legs"]]
    assert len(set(lanes)) == len(lanes) == 2
    assert {h["uid"] for h in result["hops"] if h["lane"] == 0 and h["kind"] == "Device"} == {"dev:r1"}
    assert {h["uid"] for h in result["hops"] if h["lane"] == 1 and h["kind"] == "Device"} == {"dev:r2"}


def test_gateway_lpm_stays_inside_the_domain_being_traced(graph):
    """A more specific prefix in another domain must not capture the trace."""
    graph.sources = [_src_row("home")]
    gws = [
        GW,  # home /24
        {**GW, "cidr": "10.0.0.0/28", "l3dom": "lab", "dev_uid": "dev:r2", "dev_name": "r2"},
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)
    devices = {h["uid"] for h in result["hops"] if h["kind"] == "Device"}
    assert devices == {"dev:r1"}


# --- gateway LPM ties --------------------------------------------------------------------


def test_a_gateway_tie_is_broken_deterministically_and_noted(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    tied = [
        {**GW, "dev_uid": "dev:zz", "dev_name": "zz", "if_uid": "if:zz", "if_name": "zz1"},
        GW,  # dev:r1 sorts first
    ]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=tied)
    uids = {h["uid"] for h in result["hops"]}
    assert "dev:r1" in uids and "dev:zz" not in uids
    assert any("tie" in n for n in result["notes"])
    reversed_result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=list(reversed(tied)))
    assert [h["uid"] for h in reversed_result["hops"]] == [h["uid"] for h in result["hops"]]


def test_a_gateway_tie_is_a_warning_not_only_a_note(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    tied = [
        {**GW, "dev_uid": "dev:zz", "dev_name": "zz", "if_uid": "if:zz", "if_name": "zz1"},
        GW,
    ]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=tied)
    tie = [w for w in result["warnings"] if "2 gateway candidates tie for 10.0.0.0/24" in w]
    assert tie and "traced via r1 (lowest uid)" in tie[0]
    assert "not evidence of which device forwards" in tie[0]


# --- the source segment is tied to the gateway ---------------------------------------


def _segmented_source(seg="bd:vlan:fab0:10"):
    return _src_row() | {"anchor": seg, "seg_uid": seg}


GW_OTHER_CONTEXT = {
    **GW,
    "anchor": "vrf:dev:r2:lab",
    "l3dom": "lab",
    "if_uid": "if:lab1",
    "if_name": "lab1",
    "dev_uid": "dev:r2",
    "dev_name": "r2",
}


def test_the_source_segment_scopes_the_pick_across_contexts(graph):
    """Two contexts hold a matching gateway prefix, which alone fails closed.
    Only one gateway interface realizes the source's bridge domain, so that
    one is the gateway: scoped by evidence, the other set aside and named."""
    graph.sources = [_segmented_source()]
    graph.iface_segments = {GW["if_uid"]: ["bd:vlan:fab0:10"], "if:lab1": ["bd:vlan:fab0:20"]}
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    gws = [{**GW, "anchor": "vrf:dev:r1:home"}, GW_OTHER_CONTEXT]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)

    assert result["legs"] and not result.get("indeterminate")
    assert {h["uid"] for h in result["hops"] if h["kind"] == "Device"} == {"dev:r1"}
    assert any("lab1 on r2" in n and "not candidates" in n for n in result["notes"])
    assert result["warnings"] == []


def test_the_source_segment_is_read_for_every_candidate_in_one_read(graph):
    graph.sources = [_segmented_source()]
    graph.iface_segments = {GW["if_uid"]: ["bd:vlan:fab0:10"], "if:lab1": ["bd:vlan:fab0:20"]}
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    gws = [{**GW, "anchor": "vrf:dev:r1:home"}, GW_OTHER_CONTEXT]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)

    assert {h["uid"] for h in result["hops"] if h["kind"] == "Device"} == {"dev:r1"}
    assert graph.segment_reads == [sorted([GW["if_uid"], "if:lab1"])]


def test_the_batch_segment_read_reads_the_same_relations_as_the_single_one():
    trace_mod = importlib.import_module("hst.path.trace")
    single, batch = trace_mod._IFACE_SEGMENT_QUERY, trace_mod._IFACE_SEGMENTS_QUERY
    for clause in (
        "OPTIONAL MATCH (i)-[b:BOUND_TO]->(v:VlanInstance)-[rz:REALIZES]->(bound)",
        "OPTIONAL MATCH (i)-[a:ATTACHED_TO]->(attached:BridgeDomain)",
        "collect(DISTINCT bound) + collect(DISTINCT attached) AS held",
        "OPTIONAL MATCH (s)-[x:EXTENDS*..2]-(s2)",
    ):
        assert clause in single and clause in batch


def test_the_source_segment_accepts_an_extended_bridge_domain(graph):
    """`_IFACE_SEGMENT_QUERY` returns the EXTENDS-reachable domains beside the
    interface's own, so a source on a domain one L2 extension away from the
    gateway's is tied to it."""
    graph.sources = [_segmented_source("bd:vlan:fab1:10")]
    graph.iface_segments = {GW["if_uid"]: ["bd:vlan:fab0:10", "bd:vlan:fab1:10"]}
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert result["legs"] and not result.get("indeterminate")
    assert not any("bridge domain" in n for n in result["notes"])


def test_a_gateway_on_an_unrelated_segment_does_not_scope_the_trace(graph):
    graph.sources = [_segmented_source()]
    graph.iface_segments = {GW["if_uid"]: ["bd:vlan:fab0:20"]}
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert result["legs"] == []
    assert result["indeterminate"] is True
    assert result["verdict"].startswith("gateway not established:")
    assert any("bd:vlan:fab0:10" in w and "bd:vlan:fab0:20" in w for w in result["warnings"])
    assert not any(h["uid"] == GW["dev_uid"] for h in result["hops"])


def test_removing_the_tied_gateway_widens_the_answer_never_narrows_it(graph):
    graph.sources = [_segmented_source()]
    graph.iface_segments = {GW["if_uid"]: ["bd:vlan:fab0:10"], "if:lab1": ["bd:vlan:fab0:20"]}
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    both = [{**GW, "anchor": "vrf:dev:r1:home"}, GW_OTHER_CONTEXT]

    with_evidence = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=both)
    without = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW_OTHER_CONTEXT])

    assert not with_evidence.get("indeterminate") and with_evidence["legs"]
    assert without["indeterminate"] is True and without["legs"] == []


def test_a_gateway_with_no_recorded_bridge_domain_is_noted_not_refused(graph):
    graph.sources = [_segmented_source()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert result["legs"] and not result.get("indeterminate")
    assert any("was not checked against the gateway" in n for n in result["notes"])
    assert result["warnings"] == []


def test_two_contexts_on_the_source_segment_fail_closed(graph):
    graph.sources = [_segmented_source()]
    graph.iface_segments = {GW["if_uid"]: ["bd:vlan:fab0:10"], "if:lab1": ["bd:vlan:fab0:10"]}
    gws = [{**GW, "anchor": "vrf:dev:r1:home"}, GW_OTHER_CONTEXT]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)

    assert result["legs"] == [] and result["indeterminate"] is True
    assert result.get("ambiguous_domains") == ["home", "lab"]


# --- rule position 0 ---------------------------------------------------------------------


def test_a_rule_at_position_zero_is_reported_as_a_rule(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": None,
        "approximate": False,
    }
    graph.rules = [_rule(pos=0)]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert "by rule 0" in leg["firewall"]
    assert "default-action" not in leg["firewall"]


# --- contract credit ---------------------------------------------------------------------


def test_a_permitted_contract_is_not_flagged_as_an_unevaluated_gate(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.aci_ends = [
        {"ip": "10.0.0.5", "epg_uid": "epg:web", "epg_name": "web"},
        {"ip": "10.9.9.5", "epg_uid": "epg:db", "epg_name": "db"},
    ]
    graph.aci_contracts = [
        {
            "uid": "k:web-db",
            "name": "web-to-db",
            "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521}],
        }
    ]
    graph.gates = [{"uid": "k:web-db", "name": "web-to-db", "kind": "Contract"}]
    result = path.trace(None, "10.0.0.5", "10.9.9.5", port=1521, proto="tcp", gateways=[GW])
    assert "gate(s) not evaluated" not in result["verdict"]
    assert not any("NOT evaluated" in n for n in result["notes"])
    assert result["indeterminate"] is False


def test_an_aci_deny_draws_a_contract_hop_not_the_permitting_rulebase(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": None,
        "approximate": False,
    }
    graph.rules = [_rule(pos=0)]
    graph.aci_ends = [
        {"ip": "10.0.0.5", "epg_uid": "epg:web", "epg_name": "web"},
        {"ip": "10.9.9.5", "epg_uid": "epg:db", "epg_name": "db"},
    ]
    graph.aci_contracts = [
        {
            "uid": "k:web-db",
            "name": "web-to-db",
            "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521, "action": "deny"}],
        }
    ]
    graph.gates = [{"uid": "k:web-db", "name": "web-to-db", "kind": "Contract"}]
    result = path.trace(None, "10.0.0.5", "10.9.9.5", port=1521, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["blocked"] is True
    assert leg["blocking_uid"] == "k:web-db"
    assert leg["fw_uid"] == "rb:1"
    contract_hops = [h for h in result["hops"] if h["kind"] == "Contract"]
    assert [h["uid"] for h in contract_hops] == ["k:web-db"]
    assert "deny" in contract_hops[0]["note"]
    assert contract_hops[0]["shared"] is True
    assert contract_hops[0]["lane"] == 0


def test_an_aci_deny_over_ecmp_legs_draws_one_shared_contract_hop(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0"), _route("0.0.0.0/0", egress="eth1")]}
    graph.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": None,
        "approximate": False,
    }
    graph.rules = [_rule(pos=0)]
    graph.aci_ends = [
        {"ip": "10.0.0.5", "epg_uid": "epg:web", "epg_name": "web"},
        {"ip": "10.9.9.5", "epg_uid": "epg:db", "epg_name": "db"},
    ]
    graph.aci_contracts = [
        {
            "uid": "k:web-db",
            "name": "web-to-db",
            "entries": [{"proto": "tcp", "from_port": 1521, "to_port": 1521, "action": "deny"}],
        }
    ]
    graph.gates = [{"uid": "k:web-db", "name": "web-to-db", "kind": "Contract"}]

    result = path.trace(None, "10.0.0.5", "10.9.9.5", port=1521, proto="tcp", gateways=[GW])

    assert len({leg["lane"] for leg in result["legs"]}) == 2
    assert all(leg["blocking_uid"] == "k:web-db" for leg in result["legs"])
    contract_hops = [h for h in result["hops"] if h["kind"] == "Contract"]
    assert len(contract_hops) == 1
    assert contract_hops[0]["shared"] is True


# --- zone firewall symmetry --------------------------------------------------------------

GW_LAN = {
    "cidr": "10.0.0.0/24",
    "l3dom": "home",
    "if_uid": "if:eth1",
    "if_name": "eth1",
    "dev_uid": "dev:r1",
    "dev_name": "r1",
}
GW_GUEST = {
    "cidr": "10.0.40.0/24",
    "l3dom": "home",
    "if_uid": "if:eth1.40",
    "if_name": "eth1.40",
    "dev_uid": "dev:r1",
    "dev_name": "r1",
}


def _connected(cidr):
    """An ORIGINATES route row: connected prefixes carry no VIA edge."""
    return {
        "uid": f"pfx:{cidr}",
        "cidr": cidr,
        "kind": "ORIGINATES",
        "next_hop": None,
        "ifname": None,
        "egress_uid": None,
        "egress_name": None,
    }


def _zone_row(rb_uid, rb_name, src_zone, dst_zone):
    return {
        "rb_uid": rb_uid,
        "rb_name": rb_name,
        "default_action": "drop",
        "src_zone": src_zone,
        "dst_zone": dst_zone,
        "zone_default": None,
    }


def _zoned_router(graph):
    """One router, two zoned connected networks, one rulebase per direction."""
    graph.routes = {"vrf:main": [_connected("10.0.0.0/24"), _connected("10.0.40.0/24")]}
    graph.gateway_for = {
        ("pfx:10.0.0.0/24", "dev:r1"): {"uid": "if:eth1", "name": "eth1"},
        ("pfx:10.0.40.0/24", "dev:r1"): {"uid": "if:eth1.40", "name": "eth1.40"},
    }
    graph.zone_pairs = {
        ("if:eth1", "if:eth1.40"): _zone_row("rb:lan-guest", "LAN-GUEST", "lan", "guest"),
        ("if:eth1.40", "if:eth1"): _zone_row("rb:guest-lan", "GUEST-LAN", "guest", "lan"),
    }
    graph.zone_rules = {
        "rb:lan-guest": [_rule(uid="z:l2g", pos=1, action="accept")],
        "rb:guest-lan": [_rule(uid="z:g2l", pos=1, action="drop")],
    }
    graph.ingress_zones = {"if:eth1": "lan", "if:eth1.40": "guest"}


def test_zone_policy_is_consulted_in_both_directions(graph):
    _zoned_router(graph)

    graph.sources = [_src_row(ip="10.0.0.5")]
    fwd = path.trace(None, "10.0.0.5", "10.0.40.9", port=443, proto="tcp", gateways=[GW_LAN, GW_GUEST])
    assert fwd["legs"][0]["firewall"].startswith("LAN-GUEST (lan→guest) accept")
    assert fwd["legs"][0]["verdict"] == "egress via eth1.40"
    assert not fwd["legs"][0]["blocked"]

    graph.sources = [_src_row(ip="10.0.40.9")]
    rev = path.trace(None, "10.0.40.9", "10.0.0.5", port=443, proto="tcp", gateways=[GW_LAN, GW_GUEST])
    assert rev["legs"][0]["firewall"].startswith("GUEST-LAN (guest→lan) drop")
    assert rev["legs"][0]["blocked"] is True
    assert "BLOCKED by GUEST-LAN" in rev["legs"][0]["verdict"]


def _zone_rb_row(rb_uid, src_zone, dst_zone, af=4):
    return {"rb_uid": rb_uid, "af": af, "src_zone": src_zone, "dst_zone": dst_zone, "dst_unbound": False}


def test_a_transit_leg_credits_the_zone_pairs_it_does_not_cross(graph):
    _zoned_router(graph)
    graph.zone_rulebases_by_dev["dev:r1"] = [
        _zone_rb_row("rb:lan-guest", "lan", "guest"),
        _zone_rb_row("rb:guest-lan", "guest", "lan"),
        _zone_rb_row("rb:iot-lan", "iot", "lan"),
    ]
    graph.gates = [
        {"uid": "rb:lan-guest", "name": "LAN-GUEST", "kind": "FwRulebase"},
        {"uid": "rb:guest-lan", "name": "GUEST-LAN", "kind": "FwRulebase"},
        {"uid": "rb:iot-lan", "name": "IOT-LAN", "kind": "FwRulebase"},
    ]
    graph.sources = [_src_row(ip="10.0.0.5")]

    result = path.trace(None, "10.0.0.5", "10.0.40.9", port=443, proto="tcp", gateways=[GW_LAN, GW_GUEST])

    leg = result["legs"][0]
    assert leg["firewall"].startswith("LAN-GUEST (lan→guest) accept")
    assert isinstance(leg["fw_uids"], list)
    assert set(leg["fw_uids"]) >= {"rb:guest-lan", "rb:iot-lan"}
    assert not leg["indeterminate"]
    assert "gate(s) not evaluated" not in result["verdict"]
    assert result["warnings"] == []


def test_a_zone_pair_credits_the_ipv6_ruleset_for_a_v4_flow(graph):
    _zoned_router(graph)
    graph.zone_rulebases_by_dev["dev:r1"] = [
        _zone_rb_row("rb:lan-guest", "lan", "guest", af=4),
        _zone_rb_row("rb:lan-guest-v6", "lan", "guest", af=6),
        _zone_rb_row("rb:guest-lan", "guest", "lan"),
    ]
    graph.gates = [
        {"uid": "rb:lan-guest", "name": "LAN-GUEST", "kind": "FwRulebase"},
        {"uid": "rb:lan-guest-v6", "name": "LAN-GUEST6", "kind": "FwRulebase"},
        {"uid": "rb:guest-lan", "name": "GUEST-LAN", "kind": "FwRulebase"},
    ]
    graph.sources = [_src_row(ip="10.0.0.5")]

    result = path.trace(None, "10.0.0.5", "10.0.40.9", port=443, proto="tcp", gateways=[GW_LAN, GW_GUEST])

    leg = result["legs"][0]
    assert "rb:lan-guest-v6" in leg["fw_uids"]
    assert not leg["indeterminate"]
    assert "gate(s) not evaluated" not in result["verdict"]


def test_a_zone_pair_that_matches_but_was_not_read_stays_reported(graph):
    _zoned_router(graph)
    graph.zone_rulebases_by_dev["dev:r1"] = [
        _zone_rb_row("rb:lan-guest", "lan", "guest"),
        _zone_rb_row("rb:lan-guest-shadow", "lan", "guest"),
        _zone_rb_row("rb:guest-lan", "guest", "lan"),
    ]
    graph.gates = [
        {"uid": "rb:lan-guest", "name": "LAN-GUEST", "kind": "FwRulebase"},
        {"uid": "rb:lan-guest-shadow", "name": "LAN-GUEST-SHADOW", "kind": "FwRulebase"},
        {"uid": "rb:guest-lan", "name": "GUEST-LAN", "kind": "FwRulebase"},
    ]
    graph.sources = [_src_row(ip="10.0.0.5")]

    result = path.trace(None, "10.0.0.5", "10.0.40.9", port=443, proto="tcp", gateways=[GW_LAN, GW_GUEST])

    leg = result["legs"][0]
    assert "rb:lan-guest-shadow" not in (leg.get("fw_uids") or [])
    assert "1 gate(s) not evaluated" in result["verdict"]
    assert any("LAN-GUEST-SHADOW" in w for w in result["warnings"])


def test_connected_egress_lookups_are_ordered(graph):
    """Two interfaces GATEWAY_FOR one prefix must not flip the verdict between
    runs: every GATEWAY_FOR lookup carries an ORDER BY before its LIMIT."""
    _zoned_router(graph)
    graph.sources = [_src_row(ip="10.0.0.5")]
    path.trace(None, "10.0.0.5", "10.0.40.9", port=443, proto="tcp", gateways=[GW_LAN, GW_GUEST])

    gateway_queries = [q for q in graph.seen_queries if "GATEWAY_FOR" in q and "LIMIT" in q]
    assert gateway_queries, "the connected-prefix fallback never ran"
    assert all("ORDER BY i.uid" in q for q in gateway_queries)


def test_unresolved_egress_with_a_zoned_ingress_is_loud_not_clean(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.9.0.0/24", next_hop="10.0.0.2")]}
    graph.ingress_zones = {"if:eth1": "lan"}

    result = path.trace(None, "10.0.0.5", "10.9.0.7", port=443, proto="tcp", gateways=[GW_LAN])

    leg = result["legs"][0]
    assert leg["verdict"] == "next-hop 10.0.0.2"
    assert leg["indeterminate"] is True
    assert any("zone firewall present" in n and "not" in n for n in result["notes"])
    assert "INDETERMINATE" in result["verdict"]


def test_unzoned_unresolved_egress_stays_quietly_unverdicted(graph):
    """No zone anywhere: the next-hop leg keeps its plain verdict with no
    manufactured warning."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.9.0.0/24", next_hop="10.0.0.2")]}

    result = path.trace(None, "10.0.0.5", "10.9.0.7", gateways=[GW_LAN])

    assert result["legs"][0]["verdict"] == "next-hop 10.0.0.2"
    assert not result["legs"][0]["indeterminate"]
    assert not any("zone firewall" in n for n in result["notes"])


def test_intra_segment_destination_never_visits_the_router(graph):
    _zoned_router(graph)
    graph.sources = [_src_row(ip="10.0.0.5")]

    result = path.trace(None, "10.0.0.5", "10.0.0.77", port=443, proto="tcp", gateways=[GW_LAN])

    leg = result["legs"][0]
    assert leg["verdict"] == "switched in 10.0.0.0/24"
    assert leg["egress"] is None and leg["cidr"] is None
    assert not leg["indeterminate"]
    # the router, its VRF and any route match must be absent
    assert not [h for h in result["hops"] if h["kind"] in ("VrfInstance", "Prefix")]
    assert not any(h["uid"] == GW_LAN["dev_uid"] for h in result["hops"])
    assert not any("not evaluated" in n for n in result["notes"])


def test_intra_segment_trace_draws_both_attachments(graph):
    graph.sources = [
        _src_row(ip="10.0.0.5")
        | {
            "ep_uid": "ep:a",
            "ep_name": "laptop-a",
            "att_uid": "port:sw1-p1",
            "att_is_port": True,
            "att_name": "Port 1",
            "sw_uid": "dev:sw1",
            "sw_name": "sw1",
        }
    ]
    graph.sources_by_ip["10.0.0.77"] = [
        _src_row(ip="10.0.0.77")
        | {
            "ep_uid": "ep:b",
            "ep_name": "printer-b",
            "att_uid": "port:sw1-p7",
            "att_is_port": True,
            "att_name": "Port 7",
            "sw_uid": "dev:sw1",
            "sw_name": "sw1",
        }
    ]
    result = path.trace(None, "10.0.0.5", "10.0.0.77", gateways=[GW_LAN])

    labels = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Endpoint", "laptop-a") in labels
    assert ("Port", "Port 1") in labels
    assert ("Port", "Port 7") in labels
    assert ("Endpoint", "printer-b") in labels
    assert not any(h["uid"] == GW_LAN["dev_uid"] for h in result["hops"])


def test_a_remote_gateway_interface_feeds_zone_policy_but_not_the_egress_field(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_connected("10.0.40.0/24")]}
    graph.gateway_for = {
        ("pfx:10.0.40.0/24", None): {"uid": "if:fw2-guest", "name": "fw2-guest"},
    }
    graph.zone_pairs = {
        ("if:eth1", "if:fw2-guest"): _zone_row("rb:lan-guest", "LAN-GUEST", "lan", "guest"),
    }
    graph.zone_rules = {"rb:lan-guest": [_rule(uid="z:l2g", pos=1, action="accept")]}

    result = path.trace(None, "10.0.0.5", "10.0.40.9", port=443, proto="tcp", gateways=[GW_LAN])

    leg = result["legs"][0]
    assert leg["firewall"].startswith("LAN-GUEST (lan→guest) accept")
    assert leg["egress"] is None
    assert leg["verdict"] == "matched 10.0.40.0/24"
    assert any("another" in n and "device" in n for n in result["notes"])


# --- L2 chain carriage gate --------------------------------------------------------------


def _l2_source(ip="10.0.0.5"):
    return _src_row(ip=ip) | {
        "ep_uid": "ep:a",
        "ep_name": "laptop-a",
        "att_uid": "port:sw1-p1",
        "att_is_port": True,
        "att_name": "Port 1",
        "sw_uid": "dev:sw1",
        "sw_name": "sw1",
    }


def _script_l2_trunk(graph, swp="port:sw2-p1", chain=None):
    """A resolved uplink trunk from the gateway interface, plus the chain of
    cables the client's switch (`dev:sw1`) would ride to reach it."""
    graph.trunk_by_ifuid[GW["if_uid"]] = {
        "rp": "port:r1-eth1",
        "rp_name": "eth1",
        "swp": swp,
        "swp_name": "Uplink",
        "swp_dev": "sw2",
    }
    graph.l2_chains[("dev:sw1", swp)] = {"chain": chain or []}


def test_l2_walk_draws_a_matching_vlan_chain_with_no_warning(graph):
    """Every Port on the chain carries the flow's own bridge domain: a plain
    hop chain, no mismatch warning."""
    graph.sources = [_l2_source()]
    graph.iface_segments[GW["if_uid"]] = ["bd:vlan:fab0:10"]
    _script_l2_trunk(
        graph,
        chain=[
            {
                "uid": "port:sw1-p24",
                "is_port": True,
                "label": "Port 24",
                "dev": "sw1",
                "lag": None,
                "bds": ["bd:vlan:fab0:10"],
            },
            {"uid": "dev:sw2", "is_port": False, "label": "sw2", "dev": None, "lag": None, "bds": []},
            {
                "uid": "port:sw2-p1",
                "is_port": True,
                "label": "Uplink",
                "dev": "sw2",
                "lag": None,
                "bds": ["bd:vlan:fab0:10"],
            },
        ],
    )
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    labels = [(h["kind"], h["label"], h["stage"]) for h in result["hops"]]
    assert ("Port", "Port 24", "L2_FABRIC") in labels
    assert ("Device", "sw2", "L2_FABRIC") in labels
    assert ("Port", "Uplink", "L2_FABRIC") in labels
    assert result["warnings"] == []
    assert not any("carries" in n for n in result["notes"])
    assert result["legs"][0]["indeterminate"] is False
    assert not result["legs"][0].get("boundary")


def test_l2_walk_flags_a_vlan_mismatch_on_an_intermediate_port(graph):
    graph.sources = [_l2_source()]
    graph.iface_segments[GW["if_uid"]] = ["bd:vlan:fab0:10"]
    _script_l2_trunk(
        graph,
        chain=[
            {
                "uid": "port:sw1-p24",
                "is_port": True,
                "label": "Port 24",
                "dev": "sw1",
                "lag": None,
                "bds": ["bd:vlan:fab0:10"],
            },
            {"uid": "dev:sw2", "is_port": False, "label": "sw2", "dev": None, "lag": None, "bds": []},
            {
                "uid": "port:sw2-p1",
                "is_port": True,
                "label": "Uplink",
                "dev": "sw2",
                "lag": None,
                "bds": ["bd:vlan:fab0:99"],
            },
        ],
    )
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert any(
        "Uplink" in w and "bd:vlan:fab0:99" in w and "bd:vlan:fab0:10" in w for w in result["warnings"]
    )
    assert result["legs"][0]["indeterminate"] is True
    assert not result["legs"][0].get("boundary")


def test_l2_walk_collapses_lag_members_into_one_hop(graph):
    graph.sources = [_l2_source()]
    _script_l2_trunk(
        graph,
        chain=[
            {
                "uid": "port:sw1-p24a",
                "is_port": True,
                "label": "Port 24a",
                "dev": "sw1",
                "lag": "lag:sw1-po1",
                "bds": [],
            },
            {
                "uid": "port:sw1-p24b",
                "is_port": True,
                "label": "Port 24b",
                "dev": "sw1",
                "lag": "lag:sw1-po1",
                "bds": [],
            },
            {"uid": "dev:sw2", "is_port": False, "label": "sw2", "dev": None, "lag": None, "bds": []},
            {"uid": "port:sw2-p1", "is_port": True, "label": "Uplink", "dev": "sw2", "lag": None, "bds": []},
        ],
    )
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    lag_hops = [h for h in result["hops"] if h["kind"] == "Lag"]
    assert [h["uid"] for h in lag_hops] == ["lag:sw1-po1"]
    assert not any(h["uid"] in ("port:sw1-p24a", "port:sw1-p24b") for h in result["hops"])


def test_l2_walk_with_no_carriage_data_draws_the_hops_and_one_note(graph):
    graph.sources = [_l2_source()]
    _script_l2_trunk(
        graph,
        chain=[
            {"uid": "dev:sw2", "is_port": False, "label": "sw2", "dev": None, "lag": None, "bds": []},
            {"uid": "port:sw2-p1", "is_port": True, "label": "Uplink", "dev": "sw2", "lag": None, "bds": []},
        ],
    )
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert ("Device", "sw2") in [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Port", "Uplink") in [(h["kind"], h["label"]) for h in result["hops"]]
    assert (
        result["notes"].count(
            "VLAN carriage not verified for the L2_FABRIC leg "
            "(no CARRIES/SWITCHES data collected on the path)"
        )
        == 1
    )
    assert result["warnings"] == []
    assert result["legs"][0]["indeterminate"] is False
    assert not result["legs"][0].get("boundary")


# --- more than one cable on the router port: a contradiction, not a pick -------------


def _script_forked_trunk(graph):
    graph.trunk_by_ifuid[GW["if_uid"]] = {
        "rp": "port:r1-eth1",
        "rp_name": "eth1",
        "swp": "port:swa-p5",
        "swp_name": "Port 5",
        "swp_dev": "swa",
        "peers": ["port:swa-p5", "port:swc-p25"],
    }


def test_two_cables_on_the_router_port_draw_no_switch_port_for_a_prefix_source(graph):
    """A subnet source with two cables on the gateway's router port: neither
    switch port is drawn, the router's own port is (that hop is the
    REALIZED_BY fact, not the cable), the warning names both peers, and the
    leg is a boundary. Never the first peer by uid order."""
    _script_forked_trunk(graph)

    result = path.trace(None, "10.0.0.0/24", "8.8.8.8", gateways=[GW])

    uids = [h["uid"] for h in result["hops"]]
    labels = [(h["kind"], h["label"], h["stage"]) for h in result["hops"]]
    assert "port:swa-p5" not in uids
    assert "port:swc-p25" not in uids
    assert ("Port", "eth1", "L2_FABRIC") in labels
    assert ("Interface", "eth1", "INGRESS_IF") in labels
    assert any("2 cables" in w and "port:swa-p5" in w and "port:swc-p25" in w for w in result["warnings"])
    assert all(leg.get("boundary") for leg in result["legs"])


def test_two_cables_on_the_router_port_are_not_walked_for_a_host_source(graph):
    """A host source with a known attachment: the chain is never asked for
    (there is no single far end to walk to), the same warning and boundary
    are raised, and no switch port is drawn."""
    graph.sources = [_l2_source()]
    _script_forked_trunk(graph)
    graph.l2_chains[("dev:sw1", "port:swa-p5")] = {
        "chain": [
            {"uid": "port:swa-p5", "is_port": True, "label": "Port 5", "dev": "swa", "lag": None, "bds": []},
        ]
    }

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    uids = [h["uid"] for h in result["hops"]]
    assert "port:swa-p5" not in uids
    assert "port:swc-p25" not in uids
    assert any("2 cables" in w for w in result["warnings"])
    assert result["legs"][0].get("boundary") is True


def test_one_cable_with_a_peer_list_draws_as_one_cable(graph):
    _script_l2_trunk(graph)
    graph.trunk_by_ifuid[GW["if_uid"]]["peers"] = ["port:sw2-p1"]

    result = path.trace(None, "10.0.0.0/24", "8.8.8.8", gateways=[GW])

    labels = [(h["kind"], h["label"], h["stage"]) for h in result["hops"]]
    assert ("Port", "Uplink", "L2_FABRIC") in labels
    assert ("Port", "eth1", "L2_FABRIC") in labels
    assert result["warnings"] == []
    assert not any(leg.get("boundary") for leg in result["legs"])


def test_trunk_queries_return_every_peer_and_never_limit():
    """The two trunk queries collect the full cabled set into `peers` and
    carry no LIMIT: which cable is real is a fact of the network, never the
    first row."""
    for query in (tracemod._TRUNK_BY_IF_UID_QUERY, tracemod._TRUNK_BY_PARENT_NAME_QUERY):
        assert "LIMIT" not in query
        assert "AS peers" in query
        assert "REALIZED_BY" in query and "CONNECTED_TO" in query
    assert "i:Interface {uid: $if_uid}" in tracemod._TRUNK_BY_IF_UID_QUERY
    assert "i:Interface {name: $name}" in tracemod._TRUNK_BY_PARENT_NAME_QUERY


# --- an SVI gateway: no trunk port, the chain ends on the gateway device --------------


def _svi_chain():
    """The cables from the client's switch to the gateway device: the uplink
    port of `dev:sw1`, the router's own port, then the router itself (the
    chain query returns every node but the start, `z` included)."""
    return [
        {
            "uid": "port:sw1-p24",
            "is_port": True,
            "label": "Port 24",
            "dev": "sw1",
            "lag": None,
            "bds": ["bd:vlan:fab0:10"],
        },
        {
            "uid": "port:r1-eth1-1",
            "is_port": True,
            "label": "Ethernet1/1",
            "dev": "r1",
            "lag": None,
            "bds": ["bd:vlan:fab0:10"],
        },
        {"uid": "dev:r1", "is_port": False, "label": "r1", "dev": None, "lag": None, "bds": []},
    ]


def test_an_svi_gateway_walks_the_chain_to_the_gateway_device(graph):
    """No trunk row resolves a switch port (the FakeGraph scripts none), so the
    chain is anchored on the gateway device: the client's uplink port and the
    router's port are fabric hops, the gateway device is drawn once, at
    `DEVICE`, and nothing is unproven."""
    graph.sources = [_l2_source()]
    graph.iface_segments[GW["if_uid"]] = ["bd:vlan:fab0:10"]
    graph.l2_chains[("dev:sw1", GW["dev_uid"])] = {"chain": _svi_chain()}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    labels = [(h["kind"], h["label"], h["stage"]) for h in result["hops"]]
    assert ("Port", "Port 24", "L2_FABRIC") in labels
    assert ("Port", "Ethernet1/1", "L2_FABRIC") in labels
    assert [h["stage"] for h in result["hops"] if h["uid"] == GW["dev_uid"]] == ["DEVICE"]
    assert result["warnings"] == []
    assert result["legs"][0]["indeterminate"] is False
    assert not result["legs"][0].get("boundary")


def test_an_svi_gateway_with_no_chain_is_drawn_as_a_jump_and_says_so(graph):
    from hst.results.trace import L2_PATH_NOT_FOUND, leg_result

    graph.sources = [_l2_source()]
    # a forwarded leg: a blocked or no-route leg keeps its decided false whatever the L2 marks
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert result["warnings"] == [
        "no cable path from dev:sw1 to dev:r1 in the graph; the L2 leg is drawn as a jump"
    ]
    assert result["legs"][0].get("boundary") is True
    assert result["boundary"] is True
    assert result["legs"][0]["indeterminate"] is True
    assert result["legs"][0]["indeterminate_reason"] == L2_PATH_NOT_FOUND
    (missing,) = leg_result(result["legs"][0]).missing
    assert missing.code == "l2-path-not-found"
    assert not [h for h in result["hops"] if h["stage"] == "L2_FABRIC"]


def test_an_svi_gateway_checks_carriage_against_its_own_bridge_domain(graph):
    graph.sources = [_l2_source()]
    # a forwarded leg: a blocked or no-route leg keeps its decided false whatever the L2 marks
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.iface_segments[GW["if_uid"]] = ["bd:vlan:fab0:10"]
    chain = _svi_chain()
    chain[0]["bds"] = ["bd:vlan:fab0:99"]
    graph.l2_chains[("dev:sw1", GW["dev_uid"])] = {"chain": chain}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert any("Port 24 carries ['bd:vlan:fab0:99']" in w for w in result["warnings"])
    assert result["legs"][0]["indeterminate"] is True


def test_an_svi_gateway_with_an_unknown_source_attachment_stays_silent(graph):
    graph.sources = [_src_row()]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert result["warnings"] == []
    assert not result["legs"][0].get("boundary")


def test_a_source_attached_to_the_gateway_device_itself_has_no_chain_to_walk(graph):
    """The client's port is on the gateway device: there is no cable between
    the attachment and the gateway to prove, so nothing is asked for and
    nothing is reported."""
    graph.sources = [_l2_source() | {"sw_uid": GW["dev_uid"], "sw_name": "r1"}]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert result["warnings"] == []
    assert not result["legs"][0].get("boundary")
    assert [h["stage"] for h in result["hops"] if h["uid"] == GW["dev_uid"]] == ["SRC_ATTACH"]


def _l2_dst(ip="10.0.0.77"):
    return _src_row(ip=ip) | {
        "ep_uid": "ep:b",
        "ep_name": "printer-b",
        "att_uid": "port:sw2-p7",
        "att_is_port": True,
        "att_name": "Port 7",
        "sw_uid": "dev:sw2",
        "sw_name": "sw2",
    }


def test_switched_leg_delivery_chain_flags_a_mid_chain_mismatch(graph):
    graph.sources = [_l2_source(ip="10.0.0.5")]
    graph.sources_by_ip["10.0.0.77"] = [_l2_dst()]
    graph.iface_segments[GW_LAN["if_uid"]] = ["bd:vlan:fab0:10"]
    graph.l2_chains[("dev:sw1", "dev:sw2")] = {
        "chain": [
            {
                "uid": "port:sw1-p2",
                "is_port": True,
                "label": "Uplink1",
                "dev": "sw1",
                "lag": None,
                "bds": ["bd:vlan:fab0:10"],
            },
            {"uid": "dev:core", "is_port": False, "label": "core", "dev": None, "lag": None, "bds": []},
            {
                "uid": "port:sw2-p2",
                "is_port": True,
                "label": "Uplink2",
                "dev": "sw2",
                "lag": None,
                "bds": ["bd:vlan:fab0:99"],
            },
        ]
    }

    result = path.trace(None, "10.0.0.5", "10.0.0.77", gateways=[GW_LAN])

    labels = [(h["kind"], h["label"], h["stage"]) for h in result["hops"]]
    assert ("Port", "Uplink1", "DST_FABRIC") in labels
    assert ("Device", "core", "DST_FABRIC") in labels
    assert ("Port", "Uplink2", "DST_FABRIC") in labels
    assert any(
        "Uplink2" in w and "bd:vlan:fab0:99" in w and "bd:vlan:fab0:10" in w for w in result["warnings"]
    )
    assert result["legs"][0]["indeterminate"] is True
    assert not result["legs"][0].get("boundary")


def test_switched_leg_with_no_scripted_chain_is_drawn_as_a_jump(graph):
    graph.sources = [_l2_source(ip="10.0.0.5")]
    graph.sources_by_ip["10.0.0.77"] = [_l2_dst()]

    result = path.trace(None, "10.0.0.5", "10.0.0.77", gateways=[GW_LAN])

    assert any("no cable path from dev:sw1 to dev:sw2 in the graph" in w for w in result["warnings"])
    assert all(leg.get("boundary") for leg in result["legs"])


# --- kernel RIB (LEARNED_ROUTE / side-store rib=) --------------------------------------


def test_a_learned_route_default_reaches_the_wan(graph):
    graph.sources = [_src_row()]
    graph.wan = {"uid": "wan:1", "name": "dia"}
    graph.routes = {
        "vrf:main": [
            {
                "uid": "pfx:home:0.0.0.0/0",
                "cidr": "0.0.0.0/0",
                "kind": "LEARNED_ROUTE",
                "next_hop": "62.1.2.3",
                "ifname": "pppoe0",
                "egress_uid": "if:pppoe0",
                "egress_name": "pppoe0",
            }
        ]
    }
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via pppoe0"
    wan_hops = [h for h in result["hops"] if h["kind"] == "WanLink"]
    assert [h["label"] for h in wan_hops] == ["dia"]


class _FakeRib:
    def __init__(self, lpm_rows, overlapping_rows=()):
        self._lpm_rows = lpm_rows
        self._overlapping_rows = list(overlapping_rows)

    def lpm(self, device_uid, context_uid, probe_ip, *, legacy_vrf=None):
        return self._lpm_rows

    def overlapping(self, device_uid, context_uid, lo, hi, min_prefixlen, af, *, legacy_vrf=None):
        return self._overlapping_rows


class _TableScopedRib:
    def __init__(self, rows_by_table):
        self._rows_by_table = rows_by_table

    def lpm(self, device_uid, context_uid, probe_ip, *, legacy_vrf=None):
        return self._rows_by_table.get(context_uid, [])

    def overlapping(self, device_uid, context_uid, lo, hi, min_prefixlen, af, *, legacy_vrf=None):
        return []


class _FakeGraphWithInterfaceLookup(FakeGraph):
    """Extends FakeGraph's read_one dispatch with the by-name Interface lookup
    _group_legs issues to resolve a side-store row's bare interface name into a
    graph Interface uid (fragment `Interface {name: $name}`)."""

    def __init__(self, interfaces_by_name):
        super().__init__()
        self._interfaces_by_name = interfaces_by_name

    def read_one(self, query, **params):
        if "Interface {name: $name}" in query:
            return self._interfaces_by_name.get(params["name"])
        return super().read_one(query, **params)


def test_a_side_store_only_route_reaches_a_leg(monkeypatch):
    g = _FakeGraphWithInterfaceLookup({"eth9": {"uid": "if:eth9", "name": "eth9"}})
    g.sources = [_src_row()]
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))

    fake_rib = _FakeRib(
        lpm_rows=[
            {
                "prefix": "8.8.8.0/24",
                "next_hop": "62.1.2.3",
                "interface": "eth9",
                "protocol": "bgp",
                "metric": None,
                "prefixlen": 24,
                "af": 4,
            }
        ],
        overlapping_rows=[],
    )
    result = path.trace(None, "10.0.0.5", "8.8.8.5", gateways=[GW], rib=fake_rib)
    assert result["legs"][0]["verdict"] == "egress via eth9"
    assert any("rib matched 8.8.8.0/24" in n for n in result["notes"])
    route_hops = [h for h in result["hops"] if h["kind"] == "Prefix" and h["stage"] == "ROUTE"]
    assert len(route_hops) == 1
    assert route_hops[0]["uid"] == "rib:dev:r1:vrf:main:8.8.8.0/24"
    assert route_hops[0]["tier"] == "routing"


def test_phantom_ecmp_from_graph_and_store_row_of_the_same_route_collapses_to_one_leg(monkeypatch):
    g = _FakeGraphWithInterfaceLookup({"eth9": {"uid": "if:eth9", "name": "eth9"}})
    g.sources = [_src_row()]
    g.routes = {"vrf:main": [_route("10.99.0.0/24", next_hop="10.99.0.1")]}
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))

    fake_rib = _FakeRib(
        lpm_rows=[
            {
                "prefix": "10.99.0.0/24",
                "next_hop": "10.99.0.1",
                "interface": "eth9",
                "protocol": "static",
                "metric": None,
                "prefixlen": 24,
                "af": 4,
            }
        ],
        overlapping_rows=[],
    )
    result = path.trace(None, "10.0.0.5", "10.99.0.5", gateways=[GW], rib=fake_rib)
    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert leg["verdict"] == "egress via eth9"
    assert not leg["blocked"]
    assert not leg["indeterminate"]
    assert "ECMP over" not in result["verdict"]


def test_a_store_only_leaked_route_resolves_its_next_hop_in_the_exporting_vrf(graph):
    graph.sources = [_src_row()]
    graph.default_tables["if:rx-eth0"] = {"uid": "vrf:rx"}
    graph.routes["vrf:rx"] = [_route("10.99.0.0/24", egress="rx-eth5")]
    graph.next_hop_devs["10.0.12.2"] = [
        {
            "dev_uid": "dev:rx",
            "dev_name": "rx",
            "if_uid": "if:rx-eth0",
            "if_name": "rx-eth0",
            "anchor": "vrf:rx",
        },
        {
            "dev_uid": "dev:r2",
            "dev_name": "r2",
            "if_uid": "if:r2-eth0",
            "if_name": "r2-eth0",
            "anchor": "vrf:main",
        },
    ]
    fake_rib = _TableScopedRib(
        {
            "vrf:main": [
                {
                    "prefix": "10.99.0.0/24",
                    "next_hop": "10.0.12.2",
                    "interface": None,
                    "next_hop_context_uid": "vrf:rx",
                    "protocol": "bgp",
                    "metric": None,
                    "prefixlen": 24,
                    "af": 4,
                }
            ],
            "vrf:rx": [],
        }
    )
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], rib=fake_rib)

    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "rx") in kinds
    assert ("Device", "r2") not in kinds
    assert result["legs"][0]["verdict"] == "egress via rx-eth5"


def test_rib_none_with_no_graph_route_answers_no_route(graph):
    graph.sources = [_src_row()]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["legs"][0]["verdict"] == "no route found"


def test_a_routed_flow_walks_the_far_side_to_the_destination_port(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.7.0.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.sources_by_ip["10.7.0.9"] = [
        _src_row(ip="10.7.0.9")
        | {
            "ep_uid": "ep:cam",
            "ep_name": "cam-1",
            "att_uid": "port:sw2-p3",
            "att_is_port": True,
            "att_name": "Port 3",
            "sw_uid": "dev:sw2",
            "sw_name": "sw2",
        }
    ]
    result = path.trace(None, "10.0.0.5", "10.7.0.9", gateways=[GW_LAN])

    leg = result["legs"][0]
    assert leg["verdict"] == "egress via eth2"
    labels = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "sw2") in labels
    assert ("Port", "Port 3") in labels
    assert ("Endpoint", "cam-1") in labels


def test_equal_cost_legs_of_one_group_read_as_ecmp_not_as_separate_paths(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="wg0"),
            _route("0.0.0.0/0", egress="wg1"),
        ]
    }
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 2
    assert {ll["egress"] for ll in result["legs"]} == {"wg0", "wg1"}
    assert "ECMP over 0.0.0.0/0 · 2 paths" in result["verdict"]
    assert "10.0.0.5 → wg0" not in result["verdict"]
    # the internal grouping key never reaches the response
    assert all("gid" not in ll for ll in result["legs"])


# --- reasoner-derived routes -----------------------------------------------------------


def test_a_derived_route_notes_its_route_target_provenance(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [_route("10.9.9.0/24", kind="LEARNED_ROUTE", derived="rt-import", via_rt="65000:1")]
    }
    result = path.trace(None, "10.0.0.5", "10.9.9.5", gateways=[GW])
    leg = result["legs"][0]
    assert leg["egress"] is None
    assert leg["next_hop"] is None
    assert leg["verdict"] == "matched 10.9.9.0/24"
    assert not leg["blocked"]
    assert "None" not in leg["verdict"]
    assert (
        "10.9.9.0/24 learned via route-target 65000:1 (derived from config, not an observed RIB)"
        in result["notes"]
    )
    assert leg["indeterminate"] is True
    assert result["indeterminate"] is True
    assert any(
        "10.9.9.0/24 is a route the reasoner derived from route-target 65000:1, not a row "
        "read off the device" in w
        for w in result["warnings"]
    )


def test_a_non_derived_route_carries_no_provenance_note(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.9.9.0/24", egress="eth2")]}
    result = path.trace(None, "10.0.0.5", "10.9.9.5", gateways=[GW])
    assert result["legs"][0]["verdict"] == "egress via eth2"
    assert not any("learned via route-target" in n for n in result["notes"])


def test_a_declared_interface_with_no_via_edge_resolves_egress_by_name(monkeypatch):
    g = _FakeGraphWithInterfaceLookup({"eth5": {"uid": "if:eth5", "name": "eth5"}})
    g.sources = [_src_row()]
    g.routes = {
        "vrf:main": [
            {
                "uid": "pfx:10.50.0.0/24",
                "cidr": "10.50.0.0/24",
                "kind": "STATIC_ROUTE",
                "next_hop": None,
                "ifname": "eth5",
                "egress_uid": None,
                "egress_name": None,
                "derived": None,
                "via_rt": None,
                "discard": None,
            }
        ]
    }
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))

    result = path.trace(None, "10.0.0.5", "10.50.0.5", gateways=[GW])
    leg = result["legs"][0]
    assert leg["verdict"] == "egress via eth5"
    assert leg["boundary"] is True
    assert leg["indeterminate"] is False


# --- discard routes ---------------------------------------------------------------------


def test_a_blackhole_route_beats_the_default_and_drops(graph):
    """The LPM winner is a blackhole STATIC_ROUTE, not the /0 default it beats
    on prefix length: the leg ends in a definite drop naming the discard kind
    and the route, drawn to the destination only, with no boundary flag and
    no indeterminate flag."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="eth0"),
            _route("10.0.0.0/8", discard="blackhole", next_hop="10.55.1.254"),
        ]
    }
    graph.next_hop_devs["10.55.1.254"] = {
        "dev_uid": "dev:r9",
        "dev_name": "r9",
        "if_uid": "if:r9-eth0",
        "if_name": "r9-eth0",
    }
    result = path.trace(None, "10.0.0.5", "10.55.1.1", gateways=[GW])

    leg = result["legs"][0]
    assert leg["cidr"] == "10.0.0.0/8"
    assert leg["blocked"] is True
    assert leg["verdict"] == "BLOCKED by blackhole route 10.0.0.0/8"
    assert not leg.get("boundary")
    assert not leg.get("indeterminate")
    assert result["boundary"] is False
    assert result["indeterminate"] is False
    assert graph.next_hop_lookups == []
    assert not any(h.get("label") == "r9" for h in result["hops"])


def test_a_blackhole_static_that_the_rib_also_reports_is_one_blocked_leg(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="eth0"),
            _route("10.0.0.0/8", discard="blackhole"),
        ]
    }
    result = path.trace(None, "10.0.0.5", "10.55.1.1", gateways=[GW])

    assert len(result["legs"]) == 1
    assert result["legs"][0]["blocked"] is True
    assert result["legs"][0]["verdict"] == "BLOCKED by blackhole route 10.0.0.0/8"


def test_a_store_only_discard_route_blocks_like_a_mirrored_one(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    fake_rib = _FakeRib(
        lpm_rows=[
            {
                "prefix": "10.0.0.0/8",
                "next_hop": None,
                "interface": None,
                "discard": "blackhole",
                "protocol": "static",
                "metric": None,
                "prefixlen": 8,
                "af": 4,
            }
        ],
        overlapping_rows=[],
    )
    result = path.trace(None, "10.0.0.5", "10.55.1.1", gateways=[GW], rib=fake_rib)

    assert len(result["legs"]) == 1
    assert result["legs"][0]["blocked"] is True
    assert result["legs"][0]["verdict"] == "BLOCKED by blackhole route 10.0.0.0/8"


@pytest.mark.parametrize("next_hop", [None, "0.0.0.0"])  # noqa: S104 - a next hop
def test_a_stored_null0_route_without_the_discard_column_blocks(graph, next_hop):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    fake_rib = _FakeRib(
        lpm_rows=[
            {
                "prefix": "10.0.0.0/8",
                "next_hop": next_hop,
                "interface": "Null0",
                "protocol": "bgp",
                "metric": None,
                "prefixlen": 8,
                "af": 4,
            }
        ],
        overlapping_rows=[],
    )
    result = path.trace(None, "10.0.0.5", "10.55.1.1", gateways=[GW], rib=fake_rib)

    leg = result["legs"][0]
    assert leg["blocked"] is True and not leg.get("boundary")
    assert leg["verdict"] == "BLOCKED by blackhole route 10.0.0.0/8"


def test_a_reject_route_beats_the_default_and_drops(graph):
    """Same shape as the blackhole case, with the reject discard kind."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("0.0.0.0/0", egress="eth0"),
            _route("10.0.0.0/8", discard="reject", next_hop="10.55.1.254"),
        ]
    }
    graph.next_hop_devs["10.55.1.254"] = {
        "dev_uid": "dev:r9",
        "dev_name": "r9",
        "if_uid": "if:r9-eth0",
        "if_name": "r9-eth0",
    }
    result = path.trace(None, "10.0.0.5", "10.55.1.1", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"] is True
    assert leg["verdict"] == "BLOCKED by reject route 10.0.0.0/8"
    assert not leg.get("boundary")
    assert not leg.get("indeterminate")
    assert graph.next_hop_lookups == []
    assert not any(h.get("label") == "r9" for h in result["hops"])


# --- multi-interpretation trace --------------------------------------------------------


def test_each_lane_carries_its_interpretation(graph):
    graph.sources = [_src_row("home"), _src_row("lab")]
    gws = [
        GW,
        {**GW, "l3dom": "lab", "if_uid": "if:lab1", "if_name": "lab1", "dev_uid": "dev:r2", "dev_name": "r2"},
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)

    by_domain = {leg["domain"]: leg["interpretation"] for leg in result["legs"]}
    assert by_domain["home"] == {"src_ip": "10.0.0.5", "anchor": "home", "display": "home"}
    assert by_domain["lab"] == {"src_ip": "10.0.0.5", "anchor": "lab", "display": "lab"}


def test_src_context_narrows_the_fan_out_to_one_lane(graph):
    graph.sources = [
        _src_row("home") | {"anchor": "vrf:dev:r1:home"},
        _src_row("home") | {"anchor": "vrf:dev:r2:home"},
    ]
    gws = [
        {**GW, "anchor": "vrf:dev:r1:home"},
        {
            **GW,
            "anchor": "vrf:dev:r2:home",
            "if_uid": "if:lab1",
            "if_name": "lab1",
            "dev_uid": "dev:r2",
            "dev_name": "r2",
        },
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws, src_context="vrf:dev:r2:home")

    assert {h["uid"] for h in result["hops"] if h["kind"] == "Device"} == {"dev:r2"}
    assert all(leg["interpretation"]["anchor"] == "vrf:dev:r2:home" for leg in result["legs"])
    assert result["verdict"] == "10.0.0.5 → 8.8.8.8: egress via eth0 (0.0.0.0/0, main table)"


def test_src_context_matching_nothing_lists_the_anchors_that_do_exist(graph):
    graph.sources = [
        _src_row("home") | {"anchor": "vrf:dev:r1:home"},
        _src_row("home") | {"anchor": "vrf:dev:r2:home"},
    ]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW], src_context="vrf:dev:r9:nope")

    assert result == {
        "hops": [],
        "legs": [],
        "notes": [
            "source 10.0.0.5 exists in 2 anchor(s) (vrf:dev:r1:home, vrf:dev:r2:home); "
            "none match src_context 'vrf:dev:r9:nope'"
        ],
        "warnings": [],
        "verdict": "source 10.0.0.5 does not exist in context 'vrf:dev:r9:nope'",
        # every walk carries both keys; one with no leg left nothing and ends nowhere
        "left_estate": [],
        "reach": None,
    }


# --- src_context on the network-scoped branch --------------------------------------------


def test_src_context_scopes_the_gateway_pick_of_a_network_source(graph):
    """Two contexts hold a matching gateway prefix, which unscoped fails
    closed. The stated context picks its own gateway and the trace runs
    there, with the interpretation naming that anchor."""
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    gws = [{**GW, "anchor": "vrf:dev:r1:home"}, GW_OTHER_CONTEXT]

    unscoped = path.trace(None, "10.0.0.5/32", "8.8.8.8", gateways=gws)
    scoped = path.trace(None, "10.0.0.5/32", "8.8.8.8", gateways=gws, src_context="vrf:dev:r2:lab")

    assert unscoped["legs"] == [] and unscoped["indeterminate"] is True
    assert scoped["legs"] and not scoped.get("indeterminate")
    assert {h["uid"] for h in scoped["hops"] if h["kind"] == "Device"} == {"dev:r2"}
    assert scoped["legs"][0]["interpretation"]["anchor"] == "vrf:dev:r2:lab"


def test_src_context_no_gateway_carries_is_answered_not_widened(graph):
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    gws = [{**GW, "anchor": "vrf:dev:r1:home"}, GW_OTHER_CONTEXT]

    result = path.trace(None, "10.0.0.5/32", "8.8.8.8", gateways=gws, src_context="vrf:dev:r9:nope")

    assert result == {
        "hops": [],
        "legs": [],
        "notes": [
            "no gateway prefix is anchored on src_context 'vrf:dev:r9:nope'; the gateway "
            "prefixes containing 10.0.0.5 are anchored on vrf:dev:r1:home, vrf:dev:r2:lab"
        ],
        "warnings": [],
        "verdict": "source 10.0.0.5/32 has no gateway in context 'vrf:dev:r9:nope'",
        # every walk carries both keys; one with no leg left nothing and ends nowhere
        "left_estate": [],
        "reach": None,
    }


def test_more_than_max_interpretations_are_capped_and_the_drop_is_named(graph):
    graph.sources = [_src_row(dom=f"dom{i}", ip="10.0.0.5") | {"anchor": f"anchor{i}"} for i in range(10)]
    gws = [
        {**GW, "anchor": f"anchor{i}", "l3dom": f"dom{i}", "dev_uid": f"dev:r{i}", "if_uid": f"if:r{i}"}
        for i in range(10)
    ]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=gws)

    assert path.MAX_INTERPRETATIONS == 8
    traced = {leg["interpretation"]["anchor"] for leg in result["legs"]}
    assert traced == {f"anchor{i}" for i in range(8)}
    assert (
        "2 more interpretations exist (anchors: anchor8, anchor9); narrow with src_context" in result["notes"]
    )
    assert result["indeterminate"] is True


def _dst_dup_graph(graph):
    """One source, one reached destination instance in 'home', and a second
    live instance of the same address in 'guest' that forwarding never
    touches from this source."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.7.0.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.sources_by_ip["10.7.0.9"] = [
        _src_row(ip="10.7.0.9")
        | {
            "anchor": "home",
            "ep_uid": "ep:cam",
            "ep_name": "cam-1",
            "att_uid": "port:sw2-p3",
            "att_is_port": True,
            "att_name": "Port 3",
            "sw_uid": "dev:sw2",
            "sw_name": "sw2",
        }
    ]
    graph.dst_instances["10.7.0.9"] = [
        {"uid": "ip:home:10.7.0.9", "anchor": "home", "l3dom": "home"},
        {"uid": "ip:guest:10.7.0.9", "anchor": "guest", "l3dom": "guest"},
    ]
    return graph


def test_a_reached_destination_notes_its_unreached_duplicate(graph):
    """Forwarding reaches the 'home' instance; the 'guest' instance of the
    same address is reported as not reached, never traced towards."""
    _dst_dup_graph(graph)
    result = path.trace(None, "10.0.0.5", "10.7.0.9", gateways=[GW_LAN])

    assert "destination 10.7.0.9 also exists in guest (not reached from this source)" in result["notes"]
    assert not any("also exists in home" in n for n in result["notes"])
    assert result["legs"][0]["delivered"] is True


def test_a_host_delivered_outside_dst_context_is_undecided_and_keeps_the_verdict_prose(graph):
    _dst_dup_graph(graph)
    without = path.trace(None, "10.0.0.5", "10.7.0.9", gateways=[GW_LAN])
    result = path.trace(None, "10.0.0.5", "10.7.0.9", gateways=[GW_LAN], dst_context="guest")

    assert result["verdict"].startswith(without["verdict"])
    assert result["legs"][0]["indeterminate"]
    assert (
        "the path to 10.7.0.9 is delivered in context vrf:main, "
        "not in the requested destination context guest" in result["warnings"]
    )
    assert (
        "reached the instance in home; the requested context guest is not reachable from this source"
        in result["notes"]
    )


def test_no_destination_reached_reports_duplicates_elsewhere(graph):
    graph.sources = [_src_row()]
    graph.dst_instances["8.8.8.8"] = [
        {"uid": "ip:home:8.8.8.8", "anchor": "home", "l3dom": "home"},
        {"uid": "ip:guest:8.8.8.8", "anchor": "guest", "l3dom": "guest"},
    ]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert result["legs"][0]["verdict"] == "no route found"
    assert "destination 8.8.8.8 also exists in home (not reached from this source)" in result["notes"]
    assert "destination 8.8.8.8 also exists in guest (not reached from this source)" in result["notes"]


def test_single_candidate_output_keys_and_leg_fields(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert set(result.keys()) == {
        "hops",
        "legs",
        "verdict",
        "notes",
        "warnings",
        "indeterminate",
        "boundary",
        "left_estate",
        "reach",
    }
    assert result["left_estate"] == [] and result["reach"] is None
    assert result["notes"] == [
        "10.0.0.5: 0.0.0.0/0 leaves by eth0 with no next hop in the graph; the path leaves the twin at r1"
    ]
    assert result["warnings"] == []
    assert result["indeterminate"] is False
    assert result["boundary"] is True
    assert result["verdict"] == "10.0.0.5 → 8.8.8.8: egress via eth0 (0.0.0.0/0, main table)"

    leg = result["legs"][0]
    assert leg["interpretation"] == {"src_ip": "10.0.0.5", "anchor": "home", "display": "home"}
    rest = {k: v for k, v in leg.items() if k != "interpretation"}
    assert rest == {
        "context_uid": "vrf:main",
        "device_uid": "dev:r1",
        "lane": 0,
        "sources": ["10.0.0.5/32"],
        "cidr": "0.0.0.0/0",
        "egress": "eth0",
        "next_hop": None,
        "blocked": False,
        "boundary": True,
        "indeterminate": False,
        "table": "default",
        "src_label": "10.0.0.5",
        "verdict": "egress via eth0",
        "nat_uids": [],
    }
    assert all(
        set(h.keys())
        == {"uid", "kind", "label", "note", "stage", "lane", "shared", "rank", "layer", "tier", "gate"}
        for h in result["hops"]
    )


def test_the_destination_endpoint_draws_when_it_anchors_to_the_egress_segment(graph):
    graph.sources = [_src_row()]
    graph.default_tables = {GW["if_uid"]: {"uid": "vrf:core1:default"}}
    graph.routes = {"vrf:core1:default": [_route("192.168.105.0/24", egress="eth0.105", kind="ORIGINATES")]}
    graph.iface_segments = {"if:eth0.105": ["l2seg:home:vlan105"]}
    graph.sources_by_ip["192.168.105.81"] = [
        {
            **_src_row(dom="home", ip="192.168.105.81"),
            "anchor": "l2seg:home:vlan105",
            "ep_uid": "ep:home:0002",
            "ep_name": "thermostat-02",
        }
    ]
    result = path.trace(None, "10.0.0.5", "192.168.105.81", gateways=[{**GW, "anchor": "vrf:core1:default"}])
    leg = result["legs"][0]
    assert leg.get("delivered")
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Endpoint", "thermostat-02") in kinds


def _locally_served_dst(graph):
    """r1 serves 10.7.0.0/24 on eth2; 10.7.0.9 hangs off sw2 port 3."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.7.0.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.sources_by_ip["10.7.0.9"] = [
        _src_row(dom="home", ip="10.7.0.9")
        | {
            "anchor": "home",
            "ep_uid": "ep:cam",
            "ep_name": "cam-1",
            "att_uid": "port:sw2-p3",
            "att_is_port": True,
            "att_name": "Port 3",
            "sw_uid": "dev:sw2",
            "sw_name": "sw2",
        }
    ]
    return graph


def _denying_rulebase(graph):
    graph.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": None,
        "approximate": False,
    }
    graph.rules = [_rule(uid="cp:deny", pos=7, action="drop")]
    return graph


def test_a_permitted_leg_to_a_locally_served_destination_draws_the_same_hops(graph):
    """The permitted baseline the blocked case below is measured against: no
    rulebase, so the leg egresses and the far side is walked to the endpoint."""
    _locally_served_dst(graph)
    result = path.trace(None, "10.0.0.5", "10.7.0.9", port=443, proto="tcp", gateways=[GW])

    assert [(h["uid"], h["kind"], h["label"]) for h in result["hops"]] == [
        ("if:eth1", "Interface", "eth1"),
        ("dev:r1", "Device", "r1"),
        ("vrf:main", "VrfInstance", "default"),
        ("pfx:10.7.0.0/24", "Prefix", "10.7.0.0/24"),
        ("if:eth2", "Interface", "eth2"),
        ("dev:sw2", "Device", "sw2"),
        ("port:sw2-p3", "Port", "Port 3"),
        ("ep:cam", "Endpoint", "cam-1"),
    ]
    leg = result["legs"][0]
    assert leg["blocked"] is False
    assert leg["delivered"] is True
    assert leg["verdict"] == "egress via eth2"
    # the fake scripts no cable chain, so the destination leg is a jump and, as
    # on the source side, the trace says so
    assert result["notes"] == [
        "no cable path from if:eth2 to dev:sw2 in the graph; the destination leg is drawn as a jump"
    ]


def test_a_blocked_leg_ends_on_a_locally_served_destination(graph):
    _locally_served_dst(graph)
    _denying_rulebase(graph)
    result = path.trace(None, "10.0.0.5", "10.7.0.9", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"] is True
    assert leg["verdict"] == "BLOCKED by Standard rule 7"
    assert leg["delivered"] is False

    assert [(h["uid"], h["kind"], h["label"]) for h in result["hops"]] == [
        ("if:eth1", "Interface", "eth1"),
        ("dev:r1", "Device", "r1"),
        ("vrf:main", "VrfInstance", "default"),
        ("pfx:10.7.0.0/24", "Prefix", "10.7.0.0/24"),
        ("rb:1", "FwRulebase", "Standard"),
        ("cp:deny", "FwRule", "rule 7"),
        ("dev:sw2", "Device", "sw2"),
        ("port:sw2-p3", "Port", "Port 3"),
        ("ep:cam", "Endpoint", "cam-1"),
    ]
    by_uid = {h["uid"]: h for h in result["hops"]}
    assert by_uid["ep:cam"]["rank"] > by_uid["rb:1"]["rank"]
    assert by_uid["ep:cam"]["lane"] == by_uid["rb:1"]["lane"] == leg["lane"]
    assert by_uid["ep:cam"]["stage"] == "DST_ENDPOINT"


def test_a_blocked_leg_whose_destination_has_no_attachment_says_so(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.7.0.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.sources_by_ip["10.7.0.9"] = []
    _denying_rulebase(graph)
    result = path.trace(None, "10.0.0.5", "10.7.0.9", port=443, proto="tcp", gateways=[GW])

    assert result["legs"][0]["blocked"] is True
    assert not [h for h in result["hops"] if h["kind"] == "Endpoint"]
    assert "10.0.0.5: destination not drawn past the block: no attachment resolved" in result["notes"]


# --- where an ECMP set forks ------------------------------------------------------------


def unshared_hops(hops, lane):
    return sorted((h for h in hops if h["lane"] == lane and not h["shared"]), key=lambda h: h["rank"])


def test_every_ecmp_lane_walks_from_the_route_lookup_that_forked_it(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.9.0.0/24", egress="eth2", next_hop="10.9.0.1"),
            _route("10.9.0.0/24", egress="eth3", next_hop="10.9.0.2"),
        ]
    }
    result = path.trace(None, "10.0.0.5", "10.9.0.9", gateways=[GW])

    lanes = sorted({leg["lane"] for leg in result["legs"]})
    assert len(lanes) == 2
    hops = result["hops"]

    for kind, uid in (("VrfInstance", "vrf:main"), ("Prefix", "pfx:10.9.0.0/24")):
        drawn = [h for h in hops if h["uid"] == uid and h["kind"] == kind]
        assert sorted(h["lane"] for h in drawn) == lanes
        assert len({h["rank"] for h in drawn}) == 1

    next_hops = [h for h in hops if h["kind"] == "NextHop"]
    assert sorted(h["lane"] for h in next_hops) == lanes
    assert len({h["rank"] for h in next_hops}) == 1
    assert {h["label"] for h in next_hops} == {"10.9.0.1", "10.9.0.2"}

    # each lane opens on the routing context it was looked up in, never on a
    # next hop that would have no lookup in front of it
    for lane in lanes:
        first = unshared_hops(hops, lane)[0]
        assert first["kind"] != "NextHop"
        assert (first["kind"], first["uid"]) == ("VrfInstance", "vrf:main")


# --- zoned device, no ruleset for the pair ---------------------------------------------------------


def test_a_zoned_egress_with_no_pair_ruleset_is_blocked_not_clean(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.ingress_zones = {GW["if_uid"]: "LAN", "if:eth0": "WAN"}
    # the destination zone's default-action, as the VyOS collector records it
    graph.zone_props = {"WAN": {"default_action": "drop"}}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["blocked"]
    assert "default-action" in leg["verdict"]
    assert any(h["kind"] == "FwRulebase" and "no ruleset bound" in h["label"] for h in result["hops"])


def test_a_zoned_ingress_with_an_unzoned_egress_is_indeterminate(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.ingress_zones = {GW["if_uid"]: "LAN"}
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"] and not leg["blocked"]
    assert any("egress interface is in no zone" in w for w in result["warnings"])


def _same_zone(graph, **props):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.9.0.0/24", egress="eth2")]}
    graph.ingress_zones = {GW["if_uid"]: "LAN", "if:eth2": "LAN"}
    graph.zone_props = {"LAN": props}
    graph.zone_rulebases_by_dev["dev:r1"] = [
        _zone_rb_row("rb:lan-wan", "LAN", "WAN"),
        _zone_rb_row("rb:lan-wan-v6", "LAN", "WAN", af=6),
    ]
    graph.gates = [
        {"uid": "rb:lan-wan", "name": "LAN-WAN", "kind": "FwRulebase"},
        {"uid": "rb:lan-wan-v6", "name": "LAN-WAN6", "kind": "FwRulebase"},
    ]


def test_a_same_zone_flow_takes_the_zones_intra_zone_action(graph):
    _same_zone(graph, intra_zone_filtering=True, intra_zone_action="accept")
    result = path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert not leg["indeterminate"] and not leg["blocked"]
    assert leg["firewall"].startswith("LAN intra-zone policy")
    assert {"rb:lan-wan", "rb:lan-wan-v6"} <= set(leg["fw_uids"])
    assert result["warnings"] == []

    _same_zone(graph, intra_zone_filtering=True, intra_zone_action="drop")
    leg = path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])["legs"][0]
    assert leg["blocked"]


def test_a_same_zone_flow_in_a_zone_with_no_intra_zone_filtering_takes_the_default(graph):
    """The VyOS 1.4 and 1.5 zone-based firewall documentation states that
    traffic within a zone passes unless intra-zone-filtering says otherwise."""
    _same_zone(graph, intra_zone_filtering=False)
    result = path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert not leg["indeterminate"] and not leg["blocked"]
    assert leg["firewall"].startswith("LAN intra-zone policy")
    assert not any("not evaluated" in w for w in result["warnings"])


def test_a_same_zone_flow_in_a_zone_filtering_the_other_family_only_is_undecided(graph):
    _same_zone(graph, intra_zone_filtering=True)
    result = path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"] and not leg["blocked"]


def test_a_same_zone_flow_meets_the_intra_zone_ruleset(graph):
    _same_zone(graph, intra_zone_filtering=True)
    graph.zone_pairs = {(GW["if_uid"], "if:eth2"): _zone_row("rb:lan-intra", "LAN-INTRA", "LAN", "LAN")}
    graph.zone_rules = {"rb:lan-intra": [_rule(uid="z:intra", pos=1, action="drop")]}
    leg = path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])["legs"][0]
    assert leg["blocked"] and "LAN-INTRA" in leg["verdict"]


def test_same_zone_egress_is_noted_not_judged(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.9.0.0/24", egress="eth2")]}
    graph.ingress_zones = {GW["if_uid"]: "LAN", "if:eth2": "LAN"}
    result = path.trace(None, "10.0.0.5", "10.9.0.9", gateways=[GW])
    leg = result["legs"][0]
    assert not leg["indeterminate"] and not leg["blocked"]
    assert any("both in zone LAN" in n for n in result["notes"])
    assert result["warnings"] == []


# --- a chain that never recorded its default action --------------------------------------


def test_a_chain_with_no_recorded_default_action_leaves_the_leg_undecided(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.rb = {
        "rb_uid": "vyos:gw:fw:ipv4-forward",
        "rb_name": "ipv4-forward",
        "vendor": "vyos",
        "default_action": None,
        "default_action_unknown": True,
        "approximate": False,
    }
    graph.rules = [_rule(src_any=False, src_cidrs=["192.168.0.0/24"])]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert not leg["blocked"]
    assert any(
        "could not be decided: the chain's default action is not recorded" in w for w in result["warnings"]
    )


def test_a_chain_that_recorded_a_drop_blocks_the_leg(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.rb = {
        "rb_uid": "vyos:gw:fw:ipv4-forward",
        "rb_name": "ipv4-forward",
        "vendor": "vyos",
        "default_action": "drop",
        "default_action_unknown": False,
        "approximate": False,
    }
    graph.rules = [_rule(src_any=False, src_cidrs=["192.168.0.0/24"])]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])
    leg = result["legs"][0]
    assert leg["blocked"] is True
    assert not leg["indeterminate"]


# --- route selection: provenance beats a bare longest-prefix tie -------------------------


def test_an_observed_route_outranks_a_tied_config_static(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.9.0.0/24", egress="eth2", next_hop="10.9.9.1"),
            _route("10.9.0.0/24", egress="eth3", next_hop="10.9.9.2", kind="LEARNED_ROUTE"),
        ]
    }
    result = path.trace(None, "10.0.0.5", "10.9.0.7", gateways=[GW])

    assert len(result["legs"]) == 1
    assert result["legs"][0]["next_hop"] == "10.9.9.2"
    assert any("config-only static route via 10.9.9.1 is outranked" in n for n in result["notes"])
    assert not [h for h in result["hops"] if h["label"] == "eth2"]


def test_a_derived_rt_route_is_dropped_when_an_observed_route_ties(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route(
                "10.9.0.0/24",
                kind="LEARNED_ROUTE",
                derived="rt-import",
                via_rt="65000:100",
            ),
            _route("10.9.0.0/24", egress="eth3", next_hop="10.9.9.2", kind="LEARNED_ROUTE"),
        ]
    }
    result = path.trace(None, "10.0.0.5", "10.9.0.7", gateways=[GW])

    assert len(result["legs"]) == 1
    assert result["legs"][0]["next_hop"] == "10.9.9.2"
    assert any("route-target derived route is outranked" in n for n in result["notes"])


def test_a_table_of_statics_only_keeps_its_ecmp_set(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.9.0.0/24", egress="eth2", next_hop="10.9.9.1"),
            _route("10.9.0.0/24", egress="eth3", next_hop="10.9.9.2"),
        ]
    }
    result = path.trace(None, "10.0.0.5", "10.9.0.7", gateways=[GW])
    assert sorted(ll["next_hop"] for ll in result["legs"]) == ["10.9.9.1", "10.9.9.2"]
    assert not [n for n in result["notes"] if "outranked" in n]


def test_a_blackhole_static_tied_with_an_observed_route_drops(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.9.0.0/24", discard="blackhole"),
            _route("10.9.0.0/24", egress="eth3", next_hop="10.9.9.2", kind="LEARNED_ROUTE"),
        ]
    }
    result = path.trace(None, "10.0.0.5", "10.9.0.7", gateways=[GW])

    blocked = [ll for ll in result["legs"] if ll["blocked"]]
    assert len(blocked) == 1
    assert blocked[0]["verdict"] == "BLOCKED by blackhole route 10.9.0.0/24"
    assert not [n for n in result["notes"] if "outranked" in n]
    assert "1 of 2 blocked" in result["verdict"]


def test_a_blackhole_does_not_outrank_a_sibling_static_in_a_statics_only_table(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.9.0.0/24", discard="blackhole"),
            _route("10.9.0.0/24", egress="eth3", next_hop="10.9.9.2"),
        ]
    }
    result = path.trace(None, "10.0.0.5", "10.9.0.7", gateways=[GW])

    assert len(result["legs"]) == 2
    blocked = [ll for ll in result["legs"] if ll["blocked"]]
    assert len(blocked) == 1
    assert blocked[0]["verdict"] == "BLOCKED by blackhole route 10.9.0.0/24"
    assert [ll["next_hop"] for ll in result["legs"] if not ll["blocked"]] == ["10.9.9.2"]
    assert not [n for n in result["notes"] if "outranked" in n]


def test_a_store_confirmed_static_is_not_outranked_by_a_tied_observed_route(monkeypatch):
    g = _FakeGraphWithInterfaceLookup({"eth9": {"uid": "if:eth9", "name": "eth9"}})
    g.sources = [_src_row()]
    g.routes = {
        "vrf:main": [
            _route("10.99.0.0/24", next_hop="10.99.0.1"),
            _route("10.99.0.0/24", egress="eth3", next_hop="10.99.0.2", kind="LEARNED_ROUTE"),
        ]
    }
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))

    fake_rib = _FakeRib(
        lpm_rows=[
            {
                "prefix": "10.99.0.0/24",
                "next_hop": "10.99.0.1",
                "interface": "eth9",
                "protocol": "static",
                "metric": None,
                "prefixlen": 24,
                "af": 4,
            }
        ],
        overlapping_rows=[],
    )
    result = path.trace(None, "10.0.0.5", "10.99.0.5", gateways=[GW], rib=fake_rib)

    assert sorted(ll["next_hop"] for ll in result["legs"]) == ["10.99.0.1", "10.99.0.2"]
    assert not [n for n in result["notes"] if "outranked" in n]
    # the store row confirmed the graph route; it did not add a second one
    assert len(result["legs"]) == 2


# --- a config-only static the observed RIB does not hold ---------------------------------


def _store_row(prefix, next_hop, interface="eth9", protocol="bgp"):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "interface": interface,
        "protocol": protocol,
        "metric": None,
        "prefixlen": int(prefix.split("/")[1]),
        "af": 4,
    }


def test_a_config_only_static_longer_than_the_observed_route_is_not_confirmed(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1")]}
    fake_rib = _FakeRib(lpm_rows=[_store_row("10.50.0.0/16", "10.50.0.1")])

    result = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=fake_rib)

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert leg["cidr"] == "10.50.60.0/24" and leg["indeterminate"] is True
    assert result["indeterminate"] is True
    warning = next(w for w in result["warnings"] if "config-only static route" in w)
    assert "10.50.60.0/24 is a config-only static route via 10.50.60.1" in warning
    assert "the RIB of table default does not hold" in warning
    assert "the RIB selects 10.50.0.0/16 via 10.50.0.1" in warning
    assert warning.endswith("the forwarding decision on this leg is NOT confirmed")


def test_a_config_only_static_with_no_observed_route_at_all_is_not_confirmed(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1")]}

    result = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=_FakeRib(lpm_rows=[]))

    assert result["legs"][0]["indeterminate"] is True
    assert any("the RIB holds no route for this destination" in w for w in result["warnings"])


def test_a_static_the_store_holds_is_confirmed_and_not_marked(graph):
    """The store's own row for the same route is the device saying it holds
    the static: nothing to contradict, no mark."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1")]}
    fake_rib = _FakeRib(
        lpm_rows=[_store_row("10.50.60.0/24", "10.50.60.1", interface="eth2", protocol="static")]
    )

    result = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=fake_rib)

    assert result["legs"][0]["indeterminate"] is False
    assert not [w for w in result["warnings"] if "config-only" in w]


def test_a_floating_blackhole_the_rib_does_not_hold_is_outranked_by_the_route_it_holds(graph):
    """The graph holds a blackhole static for 10.0.0.0/8 that
    the RIB does not hold (a floating discard below the route it backs up);
    the RIB selects 10.0.0.0/8 via BGP. The store answered for the table, so
    the blackhole is not installed: it is outranked, not drawn as a blocked
    equal-cost lane beside the route the device forwards on."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/8", discard="blackhole")]}
    fake_rib = _FakeRib(lpm_rows=[_store_row("10.0.0.0/8", "192.0.2.2", interface="eth3")])

    result = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=fake_rib)

    assert [ll["next_hop"] for ll in result["legs"]] == ["192.0.2.2"]
    assert not [ll for ll in result["legs"] if ll["blocked"]]
    assert any(
        "10.0.0.0/8: the config-only blackhole static route is outranked" in n for n in result["notes"]
    )


def test_a_blackhole_the_rib_holds_drops(graph):
    """The RIB's own discard row for the prefix confirms the graph blackhole:
    the device installed it, and the leg is blocked."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/8", discard="blackhole")]}
    store = {**_store_row("10.0.0.0/8", None, interface=None, protocol="static"), "discard": "blackhole"}

    result = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=_FakeRib(lpm_rows=[store]))

    assert [ll["blocked"] for ll in result["legs"]] == [True]
    assert not [n for n in result["notes"] if "outranked" in n]


def test_a_collector_confirmed_static_is_not_marked(graph):
    """A static the collector read in the device's own RIB (`rib_confirmed`,
    the VyOS shape) is not config-only whatever the store's own answer is."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1") | {"rib": True}]
    }
    fake_rib = _FakeRib(lpm_rows=[_store_row("10.50.0.0/16", "10.50.0.1")])

    result = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=fake_rib)

    assert result["legs"][0]["indeterminate"] is False
    assert not [w for w in result["warnings"] if "config-only" in w]


def test_without_a_store_a_static_is_not_marked(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1")]}

    result = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW])

    assert result["legs"][0]["indeterminate"] is False
    assert not [w for w in result["warnings"] if "config-only" in w or "not consulted" in w]


def test_removing_the_rib_never_makes_a_static_more_certain(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1")]}
    with_rib = path.trace(
        None,
        "10.0.0.5",
        "10.50.60.8",
        gateways=[GW],
        rib=_FakeRib(lpm_rows=[_store_row("10.50.0.0/16", "10.50.0.1")]),
    )
    without_rib = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=_FailedRib())

    assert with_rib["indeterminate"] is True
    assert without_rib["indeterminate"] is True
    assert without_rib["legs"][0]["cidr"] == with_rib["legs"][0]["cidr"] == "10.50.60.0/24"
    assert any("not consulted" in w for w in without_rib["warnings"])


def test_the_routes_query_pairs_a_route_only_with_its_own_declared_interface(graph):
    from hst.path.trace import _ROUTES_QUERY

    assert "AND egress.name = coalesce(r.interface, r.rib_interface)" in _ROUTES_QUERY
    assert "r.interface IS NULL OR" not in _ROUTES_QUERY


def test_the_routes_query_orders_every_row_of_both_branches():
    from hst.path.trace import _ROUTES_QUERY

    body, tail = _ROUTES_QUERY.strip().rsplit("}", 1)
    assert body.lstrip().startswith("CALL {")
    assert "UNION" in body and "UNION" not in tail
    assert tail.strip().splitlines()[-1] == (
        "ORDER BY cidr, kind, next_hop, egress_uid, ifname, next_hop_vrf, derived, via_rt, rib, discard, uid"
    )


# --- router-local delivery ---------------------------------------------------------------


def _own_addr(ip, if_uid="if:eth0", if_name="eth0", dom="home"):
    return {"ip": ip, "ip_uid": f"ip:{dom}:{ip}", "if_uid": if_uid, "if_name": if_name}


def test_a_trace_to_the_routers_own_address_uses_the_input_chain_not_forward(graph):
    """The destination is one of r1's own interface addresses. Such a flow is
    not forwarded: no egress, no source NAT, no next hop, and the chain that
    judges it is input, not forward. The forward chain here
    would drop it, so a forward verdict is visible in the answer."""
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1")]}
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0", next_hop="10.0.12.254")]}
    graph.rb_by_chain = {
        "forward": {
            "rb_uid": "rb:fwd",
            "rb_name": "ipv4-forward",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        },
        "input": {
            "rb_uid": "rb:in",
            "rb_name": "ipv4-input",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        },
    }
    graph.zone_rules = {"rb:in": [_rule(uid="in:22", pos=22, action="accept")]}

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert leg["router_local"] is True
    assert leg["blocked"] is False
    assert leg["firewall"] == "ipv4-input (input) accept by rule 22"
    assert leg["verdict"] == "router-local, terminates on r1 eth0"
    assert leg["egress"] is None and leg["next_hop"] is None
    assert "snat" not in leg
    # the forward chain never spoke, and no egress interface was drawn
    assert not [h for h in result["hops"] if h["uid"] == "rb:fwd"]
    assert not [h for h in result["hops"] if h["label"] == "eth0" and h["stage"] == "EGRESS_IF"]
    assert any("is judged by the input chain" in n for n in result["notes"])


def test_the_input_chain_can_block_a_router_local_flow(graph):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1")]}
    graph.rb_by_chain = {
        "input": {
            "rb_uid": "rb:in",
            "rb_name": "ipv4-input",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        }
    }
    graph.zone_rules = {"rb:in": []}

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"] is True
    assert leg["verdict"] == "BLOCKED by ipv4-input default-action"


def test_a_router_local_destination_needs_no_route(graph):
    """Nothing routes a packet to the box's own address, so the absence of a
    covering route is not a no-route answer."""
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("172.16.0.1", if_uid="if:lo", if_name="lo")]}
    result = path.trace(None, "10.0.0.5", "172.16.0.1", gateways=[GW])
    leg = result["legs"][0]
    assert leg["router_local"] is True
    assert leg["verdict"] == "router-local, terminates on r1 lo"
    assert "no route found" not in result["verdict"]


def test_a_router_local_address_that_is_a_vip_off_the_path_leaves_the_leg_undecided(graph):
    """The box holds the address, but the VirtualService on it is bound
    to another device, so terminating the flow here as a plain local endpoint
    is not proven."""
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("172.16.0.1", if_uid="if:lo", if_name="lo")]}
    graph.vip_elsewhere["172.16.0.1"] = [_lb_elsewhere(port=None, proto=None)]
    result = path.trace(None, "10.0.0.5", "172.16.0.1", gateways=[GW])
    leg = result["legs"][0]
    assert leg["router_local"] is True
    assert leg["indeterminate"] is True
    assert "172.16.0.1 is the VIP of web-443 on dev:ns1" in leg["indeterminate_reason"]


def test_a_network_scoped_destination_splits_the_routers_own_address_off(graph):
    """A destination range that covers one of the device's own addresses and
    other hosts besides is split by interval: the own address terminates here,
    the rest is routed."""
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.9.0.1", if_uid="if:eth4", if_name="eth4")]}
    graph.routes = {"vrf:main": [_route("10.9.0.0/24", egress="eth3", next_hop="10.9.9.2")]}

    result = path.trace(None, "10.0.0.5", "10.9.0.0/24", gateways=[GW])

    local = [ll for ll in result["legs"] if ll.get("router_local")]
    routed = [ll for ll in result["legs"] if not ll.get("router_local")]
    assert len(local) == 1 and len(routed) == 1
    assert local[0]["verdict"] == "router-local, terminates on r1 eth4"
    assert local[0]["dst_label"] == "10.9.0.1"
    assert routed[0]["next_hop"] == "10.9.9.2"
    assert routed[0]["verdict"] == "egress via eth3"
    assert any("is this device's own address and" in n for n in result["notes"])
    assert routed[0]["dst_label"] and routed[0]["dst_label"] != local[0]["dst_label"]
    assert "terminates on r1 eth4 for 10.9.0.1" in result["verdict"]
    assert "no route" not in result["verdict"]


def test_a_router_local_leg_credits_the_devices_forward_chain(graph):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1")]}
    graph.rb_by_chain = {
        "forward": {
            "rb_uid": "rb:fwd",
            "rb_name": "ipv4-forward",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        },
        "input": {
            "rb_uid": "rb:in",
            "rb_name": "ipv4-input",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        },
    }
    graph.zone_rules = {"rb:in": [_rule(uid="in:22", pos=22, action="accept")]}
    graph.gates = [
        {"uid": "rb:fwd", "name": "ipv4-forward", "kind": "FwRulebase"},
        {"uid": "rb:in", "name": "ipv4-input", "kind": "FwRulebase"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["router_local"] is True
    assert not leg["indeterminate"]
    assert not result["indeterminate"]
    assert "gate(s) not evaluated" not in result["verdict"]
    assert "rb:fwd" in leg["fw_uids"] and "rb:in" in leg["fw_uids"]
    assert not [h for h in result["hops"] if h["uid"] == "rb:fwd"]


def test_a_forwarded_leg_credits_the_devices_input_and_output_chains(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0", next_hop="10.0.12.254")]}
    graph.rb_by_chain = {
        chain: {
            "rb_uid": f"rb:{chain}",
            "rb_name": f"ipv4-{chain}",
            "vendor": "vyos",
            "default_action": "accept",
            "approximate": False,
        }
        for chain in ("forward", "input", "output")
    }
    graph.zone_rules = {"rb:forward": []}
    graph.gates = [
        {"uid": f"rb:{chain}", "name": f"ipv4-{chain}", "kind": "FwRulebase"}
        for chain in ("forward", "input", "output")
    ]

    result = path.trace(None, "10.0.0.5", "198.51.100.7", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert not leg.get("router_local")
    assert leg["firewall"].startswith("ipv4-forward")
    assert not leg["indeterminate"]
    assert "gate(s) not evaluated" not in result["verdict"]
    assert {"rb:input", "rb:output"} <= set(leg["fw_uids"])


def test_an_intra_zone_leg_credits_the_zone_pairs_of_the_device(graph):
    _zoned_router(graph)
    graph.zone_pairs = {}
    graph.ingress_zones = {"if:eth1": "lan", "if:eth1.40": "lan"}
    graph.zone_rulebases_by_dev["dev:r1"] = [
        _zone_rb_row("rb:lan-guest", "lan", "guest"),
        _zone_rb_row("rb:guest-lan", "guest", "lan"),
        _zone_rb_row("rb:lan-guest-v6", "lan", "guest", af=6),
    ]
    graph.gates = [
        {"uid": "rb:lan-guest", "name": "LAN-GUEST", "kind": "FwRulebase"},
        {"uid": "rb:guest-lan", "name": "GUEST-LAN", "kind": "FwRulebase"},
        {"uid": "rb:lan-guest-v6", "name": "LAN-GUEST6", "kind": "FwRulebase"},
    ]
    graph.sources = [_src_row(ip="10.0.0.5")]

    result = path.trace(None, "10.0.0.5", "10.0.40.9", port=443, proto="tcp", gateways=[GW_LAN, GW_GUEST])

    leg = result["legs"][0]
    assert not leg["indeterminate"]
    assert "gate(s) not evaluated" not in result["verdict"]
    assert {"rb:lan-guest", "rb:guest-lan", "rb:lan-guest-v6"} <= set(leg["fw_uids"])
    assert any("both in zone lan" in n for n in result["notes"])


def _acl_rulebase(*, bindings, uid="acl:DENY-SSH", name="DENY-SSH", default_action="permit"):
    """A Cisco interface ACL as cisco_common.py writes it: kind 'access',
    match_context 'interface-acl' and no chain at all, so the chain-keyed
    candidate read offers it under 'forward'. `bindings` is the candidate
    read's `acl_bindings`, one [interface name, direction] pair per
    PROTECTED_BY edge."""
    return {
        "acl_bindings": [list(pair) for pair in bindings],
        "rb_uid": uid,
        "rb_name": name,
        "vendor": "cisco",
        "af": None,
        "default_action": default_action,
        "default_action_unknown": False,
        "global_state_policy": None,
        "match_context": "interface-acl",
        # the candidate read returns `rb.chain`, which a Cisco list never sets
        "chain": None,
        "approximate": False,
    }


def test_an_inbound_interface_acl_blocks_a_trace_to_the_routers_own_address(graph):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1", if_uid="if:eth1", if_name="Gi0/1")]}
    graph.iface_names = {"if:eth1": "Gi0/1"}
    graph.rb_by_chain = {"forward": _acl_rulebase(bindings=[("Gi0/1", "in")])}
    graph.zone_rules = {
        "acl:DENY-SSH": [
            _rule(
                uid="acl:DENY-SSH:10",
                pos=10,
                action="deny",
                svc_any=False,
                protos=["tcp"],
                ports=["22"],
            )
        ]
    }
    graph.gates = [{"uid": "acl:DENY-SSH", "name": "DENY-SSH", "kind": "FwRulebase"}]

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["router_local"] is True
    assert leg["blocked"] is True
    assert leg["verdict"] == "BLOCKED by DENY-SSH (in on Gi0/1) rule 10"
    assert leg["fw_uid"] == "acl:DENY-SSH"
    # evaluated, so credited: the safeguard has nothing left to report
    assert "acl:DENY-SSH" in leg["fw_uids"]
    assert "gate(s) not evaluated" not in result["verdict"]


def test_an_interface_acl_on_another_interface_stays_reported_as_unevaluated(graph):
    """The credit covers what the read looked at and nothing else. An ACL
    scoped to an interface this flow does not enter is excluded per hop and
    credited as excluded; one bound to the device but never offered to either
    read is a gate the engine did not examine, and the leg says so."""
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1", if_uid="if:eth1", if_name="Gi0/1")]}
    graph.iface_names = {"if:eth1": "Gi0/1"}
    graph.rb_by_chain = {"forward": _acl_rulebase(uid="acl:MGMT", name="MGMT-IN", bindings=[("Gi0/9", "in")])}
    graph.zone_rules = {"acl:MGMT": [_rule(uid="acl:MGMT:10", pos=10, action="deny")]}
    graph.gates = [
        {"uid": "acl:MGMT", "name": "MGMT-IN", "kind": "FwRulebase"},
        {"uid": "rb:unread", "name": "UNREAD", "kind": "FwRulebase"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"] is False
    # the ACL was looked at and ruled out by its interface scope
    assert "acl:MGMT" in leg["fw_uids"]
    assert "rb:unread" not in leg["fw_uids"]
    assert leg["indeterminate"] is True
    assert any("UNREAD" in w and "not evaluated" in w for w in result["warnings"])


def test_a_rulebase_with_no_recorded_chain_is_not_credited_on_a_router_local_leg(graph):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1")]}
    graph.rb_by_chain = {
        "forward": {
            "rb_uid": "rb:cp-layer",
            "rb_name": "Network",
            "vendor": "checkpoint",
            "default_action": "drop",
            "approximate": False,
            "chain": None,
        },
    }
    graph.zone_rules = {"rb:cp-layer": [_rule(uid="cp:10", pos=10, action="drop")]}
    graph.gates = [{"uid": "rb:cp-layer", "name": "Network", "kind": "FwRulebase"}]

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["router_local"] is True
    assert "rb:cp-layer" not in leg.get("fw_uids", [])
    assert leg["indeterminate"] is True
    assert any("Network" in w and "not evaluated" in w for w in result["warnings"])


def test_an_egress_only_interface_acl_does_not_judge_a_router_local_flow(graph):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1", if_uid="if:eth1", if_name="Gi0/1")]}
    graph.iface_names = {"if:eth1": "Gi0/1"}
    graph.rb_by_chain = {
        "forward": _acl_rulebase(uid="acl:OUT", name="OUT-ONLY", bindings=[("Gi0/2", "out")])
    }
    graph.zone_rules = {"acl:OUT": [_rule(uid="acl:OUT:10", pos=10, action="deny")]}
    graph.gates = [{"uid": "acl:OUT", "name": "OUT-ONLY", "kind": "FwRulebase"}]

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"] is False
    assert leg["indeterminate"] is False
    assert leg["verdict"] == "router-local, terminates on r1 Gi0/1"


def test_an_unresolvable_ingress_interface_leaves_an_acl_undecided(graph):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1", if_uid="if:eth1", if_name="Gi0/1")]}
    graph.rb_by_chain = {"forward": _acl_rulebase(bindings=[("Gi0/1", "in")])}
    graph.zone_rules = {"acl:DENY-SSH": [_rule(uid="acl:DENY-SSH:10", pos=10, action="deny")]}

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert any("could not be resolved" in w for w in result["warnings"])


def test_the_chains_a_router_local_packet_does_not_cross_are_credited(graph):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1")]}
    graph.rb_by_chain = {
        "forward": {
            "rb_uid": "rb:fwd",
            "rb_name": "ipv4-forward",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        },
        "output": {
            "rb_uid": "rb:out",
            "rb_name": "ipv4-output",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        },
    }
    graph.gates = [
        {"uid": "rb:fwd", "name": "ipv4-forward", "kind": "FwRulebase"},
        {"uid": "rb:out", "name": "ipv4-output", "kind": "FwRulebase"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["fw_uids"] == ["rb:fwd", "rb:out"]
    assert "firewall" not in leg
    assert not leg["indeterminate"]
    assert result["warnings"] == []


def test_each_half_of_a_split_destination_credits_only_its_own_read(graph):
    graph.sources = [_src_row()]
    graph.dev_addrs = {"dev:r1": [_own_addr("10.9.0.1", if_uid="if:eth4", if_name="eth4")]}
    graph.routes = {"vrf:main": [_route("10.9.0.0/24", egress="eth3", next_hop="10.9.9.2")]}
    graph.rb_by_chain = {
        "forward": _acl_rulebase(uid="acl:OUT", name="OUT-ONLY", bindings=[("Gi0/2", "out")])
    }
    graph.zone_rules = {"acl:OUT": [_rule(uid="acl:OUT:10", pos=10, action="deny")]}
    graph.gates = [
        {"uid": "acl:OUT", "name": "OUT-ONLY", "kind": "FwRulebase"},
        {"uid": "rb:unread", "name": "UNREAD", "kind": "FwRulebase"},
    ]

    result = path.trace(None, "10.0.0.5", "10.9.0.0/24", gateways=[GW])

    local = next(ll for ll in result["legs"] if ll.get("router_local"))
    routed = next(ll for ll in result["legs"] if not ll.get("router_local"))
    assert local["fw_uids"] == ["acl:OUT"]
    assert routed.get("fw_uids") == ["acl:OUT"]
    assert any("UNREAD" in w and "not evaluated" in w for w in result["warnings"])


# --- the LOAD_BALANCER stage ------------------------------------------------------------------------


def _lb_vs(**kw):
    base = {
        "uid": "ns:dc1-ns01:lbvs:web-443",
        "name": "web-443",
        "kind": "lb",
        "proto": "tcp",
        "port": 443,
        "snat_mode": "none",
        "ip_uid": "ip:corp:10.0.30.10",
    }
    base.update(kw)
    return base


def _lb_member(**kw):
    base = {
        "uid": "ns:dc1-ns01:sg:web/10.0.10.5:8443",
        "name": "10.0.10.5:8443",
        "pool_uid": "ns:dc1-ns01:sg:web",
        "pool_name": "web",
        "port": 8443,
        "state": "up",
        "ip": "10.0.10.5",
    }
    base.update(kw)
    return base


def test_a_vip_traces_through_to_a_device_beyond_the_lb(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {
        "vrf:main": [
            _route("10.0.30.0/24", egress="eth2", kind="ORIGINATES"),
            _route("10.0.20.0/24", egress="eth3", kind="ORIGINATES"),
            _route("10.0.10.0/24", egress="eth3", next_hop="10.0.20.1"),
        ]
    }
    graph.next_hop_devs["10.0.20.1"] = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
    }
    graph.default_tables["if:fw2-in"] = {"uid": "vrf:fw2"}
    graph.routes["vrf:fw2"] = [_route("10.0.10.0/24", egress="fw2-eth0", kind="ORIGINATES")]
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert not leg["indeterminate"]
    assert leg["dnat"] == [{"to": ["10.0.10.5/32"], "port": 8443, "rule_uid": _lb_member()["uid"]}]
    # snat_mode none rewrites nothing, so the leg records no translation for it
    assert "snat" not in leg
    assert any("web-443" in n and "client source is preserved" in n for n in result["notes"])
    assert leg["lb_uids"] == [_lb_vs()["uid"]]
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("VirtualService", "web-443") in kinds
    assert ("Pool", "web") in kinds
    assert ("PoolMember", "10.0.10.5:8443") in kinds
    assert ("Device", "fw2") in kinds
    # Stage order, not call order: LOAD_BALANCER (145) ranks strictly before
    # the far device's own hops.
    lb_ranks = [h["rank"] for h in result["hops"] if h["stage"] == "LOAD_BALANCER"]
    fw2_ranks = [h["rank"] for h in result["hops"] if h["uid"] == "dev:fw2"]
    assert max(lb_ranks) < min(fw2_ranks)


def _lb_elsewhere(**kw):
    return {
        **{k: v for k, v in _lb_vs().items() if k not in ("snat_mode", "ip_uid")},
        "on_uid": "dev:ns1",
        **kw,
    }


def test_a_vip_bound_to_a_device_off_the_path_leaves_the_leg_undecided(graph):
    """The router delivers the VIP on its server VLAN, and the
    VirtualService is bound to the NetScaler, which the trace never visits.
    The pool and the server-side path are not evaluated, so the leg is
    indeterminate and names the VirtualService and the device."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip_elsewhere["10.0.30.10"] = [_lb_elsewhere()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert "web-443 on dev:ns1" in leg["indeterminate_reason"]
    assert "not on the drawn path" in leg["indeterminate_reason"]
    assert leg["indeterminate_reason"] in result["warnings"]
    assert not any(h["kind"] == "VirtualService" for h in result["hops"])


def test_a_vip_elsewhere_that_misses_the_flows_port_is_not_a_gap(graph):
    """A VirtualService on 8080 does not make a port 443 flow undecided."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip_elsewhere["10.0.30.10"] = [_lb_elsewhere(port=8080)]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert not result["legs"][0]["indeterminate"]
    assert not result["warnings"]


def test_a_vip_elsewhere_undecided_by_an_unstated_port_leaves_the_leg_undecided(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip_elsewhere["10.0.30.10"] = [_lb_elsewhere()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", gateways=[GW])

    assert result["legs"][0]["indeterminate"] is True


def test_a_switched_vip_bound_off_the_path_leaves_the_leg_undecided(graph):
    """The same read on the switched leg: the destination is inside the
    source's own connected prefix and the VirtualService sits on another
    device."""
    _zoned_router(graph)
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.vip_elsewhere["10.0.0.77"] = [_lb_elsewhere()]

    result = path.trace(None, "10.0.0.5", "10.0.0.77", port=443, proto="tcp", gateways=[GW_LAN])

    leg = result["legs"][0]
    assert leg["verdict"] == "switched in 10.0.0.0/24"
    assert leg["indeterminate"] is True
    assert "web-443 on dev:ns1" in leg["indeterminate_reason"]


def test_a_vip_bound_off_the_path_is_named_on_a_blocked_destination(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {
        "vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES", discard="blackhole")]
    }
    graph.vip_elsewhere["10.0.30.10"] = [_lb_elsewhere()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert result["legs"][0]["blocked"]
    assert any("10.0.30.10 is the VIP of web-443 on dev:ns1" in n for n in result["notes"])


def _ns_iface(dev="ns1", ip="10.0.30.5", name="eth0"):
    return {
        "device_uid": f"dev:{dev}",
        "device_name": dev,
        "lb_role": None,
        "if_uid": f"if:{dev}-{name}",
        "if_name": f"{dev}-{name}",
        "ip": ip,
        "vrf_uid": None,
    }


def _one_arm_lb(graph, on_uid="dev:ns1", ifaces=None):
    """r1 delivers the VIP 10.0.30.10 on its server segment 10.0.30.0/24, and
    the VirtualService is ON the NetScaler, whose own table delivers the
    pool member."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {
        "vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")],
        "vrf:ns1": [_route("10.0.10.0/24", egress="ns1-eth1", kind="ORIGINATES")],
    }
    graph.vip_elsewhere["10.0.30.10"] = [_lb_elsewhere(on_uid=on_uid)]
    graph.lb_interfaces[on_uid] = [_ns_iface()] if ifaces is None else ifaces
    graph.default_tables["if:ns1-eth0"] = {"uid": "vrf:ns1"}
    graph.vip[("10.0.30.10", "dev:ns1")] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]


def test_a_vip_bound_to_the_load_balancer_on_the_segment_runs_the_stage_there(graph):
    """The router holds no binding for the VIP it delivers; the
    VirtualService is ON the NetScaler, whose interface on the server segment
    the flow arrives on, and the LOAD_BALANCER stage runs on it: the pool,
    the member and the server-side path are evaluated."""
    _one_arm_lb(graph)

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert not leg["indeterminate"], leg
    assert leg["lb_uids"] == [_lb_vs()["uid"]]
    assert leg["dnat"] == [{"to": ["10.0.10.5/32"], "port": 8443, "rule_uid": _lb_member()["uid"]}]
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Interface", "ns1-eth0") in kinds and ("Device", "ns1") in kinds
    assert ("VirtualService", "web-443") in kinds and ("PoolMember", "10.0.10.5:8443") in kinds
    assert not any("not on the drawn path" in w for w in result["warnings"])
    # the NetScaler's own pipeline ranks after the router's
    r1 = max(h["rank"] for h in result["hops"] if h["uid"] == "dev:r1")
    assert r1 < min(h["rank"] for h in result["hops"] if h["stage"] == "LOAD_BALANCER")


def test_a_vip_bound_to_a_redundancy_group_runs_the_stage_on_a_member(graph):
    """The VirtualService is ON the HA group: the member with an interface on
    the segment is the load balancer, the lowest uid of two, and a note says
    no member is recorded as the active one."""
    _one_arm_lb(
        graph,
        on_uid="rgrp:ns-ha:dc1:ns01",
        ifaces=[_ns_iface(), _ns_iface(dev="ns2", ip="10.0.30.6"), _ns_iface(ip="192.168.9.5", name="mgmt")],
    )
    graph.lb_interfaces["rgrp:ns-ha:dc1:ns01"].sort(key=lambda r: (r["device_uid"], r["if_uid"]))

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["lb_uids"] == [_lb_vs()["uid"]]
    devices = [h["uid"] for h in result["hops"] if h["kind"] == "Device"]
    assert "dev:ns1" in devices and "dev:ns2" not in devices
    assert any("ns1, ns2 of rgrp:ns-ha:dc1:ns01" in n and "(lowest uid)" in n for n in result["notes"])


def test_a_load_balancer_with_no_interface_on_the_segment_leaves_the_leg_undecided(graph):
    """The load balancer holds no address on the segment the VIP is delivered
    on, so the device the flow enters cannot be named."""
    _one_arm_lb(graph, ifaces=[_ns_iface(ip="192.168.9.5", name="mgmt")])

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"] is True
    assert "no interface of dev:ns1 holds an address in 10.0.30.0/24" in leg["indeterminate_reason"]
    assert not any(h["kind"] == "VirtualService" for h in result["hops"])


def test_a_switched_vip_bound_to_the_load_balancer_on_the_prefix_runs_the_stage_there(graph):
    """The same hand-off on a switched leg: the client and the VIP share a
    prefix, and the NetScaler's interface on it is where the flow arrives."""
    _zoned_router(graph)
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.vip_elsewhere["10.0.0.77"] = [_lb_elsewhere()]
    graph.lb_interfaces["dev:ns1"] = [_ns_iface(ip="10.0.0.6")]
    graph.default_tables["if:ns1-eth0"] = {"uid": "vrf:ns1"}
    graph.routes["vrf:ns1"] = [_route("10.0.10.0/24", egress="ns1-eth1", kind="ORIGINATES")]
    graph.vip[("10.0.0.77", "dev:ns1")] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]

    result = path.trace(None, "10.0.0.5", "10.0.0.77", port=443, proto="tcp", gateways=[GW_LAN])

    leg = result["legs"][0]
    assert not leg["indeterminate"], leg
    assert leg["lb_uids"] == [_lb_vs()["uid"]]
    assert ("Device", "ns1") in [(h["kind"], h["label"]) for h in result["hops"]]


def test_a_vip_with_a_down_member_produces_one_leg_naming_the_skipped_member(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    down = _lb_member(uid="m:down", ip="10.0.10.6", name="10.0.10.6:8443", state="down")
    up = _lb_member()
    graph.pool_members[_lb_vs()["uid"]] = [down, up]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 1
    assert result["legs"][0]["dnat"][0]["to"] == ["10.0.10.5/32"]
    assert any("10.0.10.6:8443" in n and "skipped as down" in n for n in result["notes"])


def test_a_vip_with_only_down_members_is_indeterminate_naming_every_member(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member(state="down")]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert result["legs"][0]["indeterminate"]
    assert not result["legs"][0].get("dnat")
    assert any("web-443" in w and "down" in w for w in result["warnings"])


def test_a_vip_whose_port_does_not_match_is_blocked_naming_the_vs(graph):
    """Every VirtualService on the VIP definitely misses the flow's port: no
    service on the VIP serves it, which is a decided block, not a gap."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs(port=8080)
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"]
    assert not leg["indeterminate"]
    assert "BLOCKED at VIP 10.0.30.10" in result["verdict"]
    assert not leg.get("dnat")
    assert any("web-443" in n for n in result["notes"])
    assert not result["warnings"]
    assert not any(h["kind"] == "PoolMember" for h in result["hops"])


def test_a_vip_claim_the_flow_leaves_undecided_stays_indeterminate(graph):
    """A flow that states no port cannot be matched against a VirtualService
    scoped to one: the claim is undecided, not a miss."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs(port=8080)

    result = path.trace(None, "10.0.0.5", "10.0.30.10", proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert not leg["blocked"]
    assert any("does not carry" in w for w in result["warnings"])


def test_a_vip_miss_beside_an_unsupported_vs_kind_stays_indeterminate(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = [
        _lb_vs(port=8080),
        _lb_vs(uid="ns:vs:cs", name="cs-9000", kind="cs", port=9000),
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert not leg["blocked"]
    assert any("does not evaluate" in w for w in result["warnings"])


def test_the_part_of_a_range_no_vs_serves_is_blocked_beside_the_served_part(graph):
    """A range that one VirtualService claims part of: the claimed part
    reaches the pool, and the part every VirtualService on the VIP definitely
    misses is a blocked leg, not an indeterminate one."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port="440-450", proto="tcp", gateways=[GW])

    blocked = [ll for ll in result["legs"] if ll["blocked"]]
    assert len(blocked) == 1
    assert not blocked[0]["indeterminate"]
    assert blocked[0]["verdict"].startswith("BLOCKED at VIP 10.0.30.10")
    assert any(h["kind"] == "PoolMember" for h in result["hops"])
    assert not any("marked INDETERMINATE" in w for w in result["warnings"])


def test_a_non_vip_destination_is_unaffected_by_the_lb_stage(graph):
    _locally_served_dst(graph)
    result = path.trace(None, "10.0.0.5", "10.7.0.9", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg.get("delivered")
    assert not leg.get("dnat")
    assert not leg.get("lb_uids")
    assert not any(h["kind"] in ("VirtualService", "Pool", "PoolMember") for h in result["hops"])


def test_a_vip_past_a_denying_rule_is_named_but_not_evaluated(graph):
    _locally_served_dst(graph)
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    _denying_rulebase(graph)
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"]
    kinds = [(h["kind"], h["label"], h["note"]) for h in result["hops"]]
    assert ("VirtualService", "web-443", "past the block, not evaluated") in kinds
    assert not any(h["kind"] == "PoolMember" for h in result["hops"])


def test_an_unsupported_vs_kind_is_named_and_flagged_unevaluated_by_the_safeguard(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs(kind="gslb")
    graph.gates = [{"uid": _lb_vs()["uid"], "name": "web-443", "kind": "VirtualService"}]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert not leg.get("lb_uids")
    assert any("web-443" in w and "not evaluated" in w for w in result["warnings"])


def test_a_successfully_evaluated_vip_credits_lb_uids_and_is_not_double_flagged(graph):
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]
    graph.gates = [{"uid": _lb_vs()["uid"], "name": "web-443", "kind": "VirtualService"}]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["lb_uids"] == [_lb_vs()["uid"]]
    assert not leg["indeterminate"]
    assert not any("not evaluated" in w for w in result["warnings"])


def _sibling_vs(graph, vips):
    """web-443 decides the flow on VIP 10.0.30.10, and ldap-636 sits on the
    same load balancer. `vips` is what the VIP read records for ldap-636."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]
    graph.gates = [
        {"uid": _lb_vs()["uid"], "name": "web-443", "kind": "VirtualService"},
        {"uid": "ns:vs:ldap-636", "name": "ldap-636", "kind": "VirtualService"},
    ]
    read = graph.read
    rows = [{"uid": "ns:vs:ldap-636", "vips": vips}] if vips else []
    graph.read = lambda q, **p: rows if "[ev:VIP]->" in q else read(q, **p)


def test_a_vs_on_another_vip_is_not_reported_as_not_evaluated(graph):
    """A VirtualService acts only on a packet addressed to its VIP. One on a
    VIP no device on the path handled cannot claim the flow, so it is a
    definite non-match, not an unevaluated gate."""
    _sibling_vs(graph, ["10.0.40.10"])

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert not result["legs"][0]["indeterminate"]
    assert not any("not evaluated" in w for w in result["warnings"])


def test_a_vs_with_no_recorded_vip_stays_reported_as_not_evaluated(graph):
    _sibling_vs(graph, [])

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert result["legs"][0]["indeterminate"]
    assert any("ldap-636" in w and "not evaluated" in w for w in result["warnings"])


def test_a_vs_whose_vip_is_inside_a_handled_destination_stays_reported(graph):
    """A destination range that holds the VIP can carry a packet the
    VirtualService serves, so it is not a definite non-match."""
    _sibling_vs(graph, ["10.0.30.20"])
    graph.vip.clear()

    result = path.trace(None, "10.0.0.5", "10.0.30.0/27", port=443, proto="tcp", gateways=[GW])

    assert any("ldap-636" in w and "not evaluated" in w for w in result["warnings"])


def _lb_beyond(graph):
    """r1 terminates the VIP on 10.0.30.10 and routes the pool member's
    network on to fw2, so the member flow crosses r1's table a second time."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {
        "vrf:main": [
            _route("10.0.30.0/24", egress="eth2", kind="ORIGINATES"),
            _route("10.0.20.0/24", egress="eth3", kind="ORIGINATES"),
            _route("10.0.10.0/24", egress="eth3", next_hop="10.0.20.1"),
        ]
    }
    graph.next_hop_devs["10.0.20.1"] = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
    }
    graph.default_tables["if:fw2-in"] = {"uid": "vrf:fw2"}
    graph.routes["vrf:fw2"] = [_route("10.0.10.0/24", egress="fw2-eth0", kind="ORIGINATES")]
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]
    return graph


def test_a_dnat_before_the_lb_keeps_both_translations(graph):
    """The device dNATs a public address to the VIP and then load-balances it.
    Both translations stay on the leg: a flow can be destination-translated
    more than once on a path and every translation is reported, so the LB entry
    is appended to the device's own, not put in its place."""
    from tests.test_path_nat import _dnat_row  # the shared dNAT row shape

    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {
        "vrf:main": [
            _route("10.0.30.0/24", egress="eth2", kind="ORIGINATES"),
            _route("10.0.10.0/24", egress="eth3", kind="ORIGINATES"),
        ]
    }
    graph.nat = [_dnat_row(translation="10.0.30.10", xlate_dst_addrs=["10.0.30.10"])]
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert [d["rule_uid"] for d in leg["dnat"]] == ["dnat:r10", _lb_member()["uid"]]
    assert leg["dnat"][0]["to"] == ["10.0.30.10/32"]
    assert leg["dnat"][1]["to"] == ["10.0.10.5/32"]


def test_the_vserver_that_claims_the_flow_is_chosen_over_the_first_uid(graph):
    """Two vservers on one VIP is the ordinary appliance shape. The flow's own
    port picks which one claims it, so a lower-sorting uid on another port does
    not answer for it."""
    _lb_beyond(graph)
    web80 = _lb_vs(uid="ns:dc1-ns01:lbvs:web-080", name="web-80", port=80)
    graph.vip[("10.0.30.10", GW["dev_uid"])] = [web80, _lb_vs()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert not leg["indeterminate"]
    assert leg["lb_uids"] == [_lb_vs()["uid"]]
    assert not any(h["uid"] == web80["uid"] for h in result["hops"])
    assert ("PoolMember", "10.0.10.5:8443") in [(h["kind"], h["label"]) for h in result["hops"]]


def test_two_vservers_claiming_one_flow_are_indeterminate_naming_them(graph):
    """Two vservers on one VIP that both claim the flow's protocol and port is
    a collected configuration this engine cannot resolve into one pool: both
    are named and the leg is INDETERMINATE, never answered by sort order."""
    _lb_beyond(graph)
    graph.vip[("10.0.30.10", GW["dev_uid"])] = [
        _lb_vs(uid="ns:vs:a", name="web-a"),
        _lb_vs(uid="ns:vs:b", name="web-b"),
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert leg["lb_uids"] == ["ns:vs:a", "ns:vs:b"]
    assert not any(h["kind"] == "PoolMember" for h in result["hops"])
    assert any("web-a" in w and "web-b" in w and "2 virtual services" in w for w in result["warnings"])


def test_an_own_address_vip_is_taken_by_the_lb_stage_not_by_local_delivery(graph):
    _lb_beyond(graph)
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.30.10", if_uid="if:vip0", if_name="vip0")]}
    graph.gates = [{"uid": _lb_vs()["uid"], "name": "web-443", "kind": "VirtualService"}]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["lb_uids"] == [_lb_vs()["uid"]]
    assert leg["dnat"][-1]["to"] == ["10.0.10.5/32"]
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("PoolMember", "10.0.10.5:8443") in kinds
    assert ("Device", "fw2") in kinds
    # the leg records both: the router-local termination and the pool
    assert any("terminates on vip0" in n for n in result["notes"])
    assert not any("not evaluated" in w for w in result["warnings"])


def test_an_own_address_vip_denied_by_the_input_chain_is_named_not_evaluated(graph):
    """The input chain denies the packet, so nothing crosses to the virtual
    service: it is named on the path and never evaluated, the same posture a
    flow denied further upstream gets."""
    _lb_beyond(graph)
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.30.10", if_uid="if:vip0", if_name="vip0")]}
    graph.rb_by_chain = {
        "input": {
            "rb_uid": "rb:in",
            "rb_name": "ipv4-input",
            "vendor": "vyos",
            "default_action": "drop",
            "approximate": False,
        }
    }
    graph.zone_rules = {"rb:in": []}

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["blocked"]
    assert not leg.get("lb_uids")
    assert ("VirtualService", "web-443", "past the block, not evaluated") in [
        (h["kind"], h["label"], h["note"]) for h in result["hops"]
    ]
    assert not any(h["kind"] == "PoolMember" for h in result["hops"])


def test_a_member_that_targets_the_vip_itself_is_named_not_followed(graph):
    _lb_beyond(graph)
    loop = _lb_member(uid="m:loop", ip="10.0.30.10", name="10.0.30.10:8443")
    graph.pool_members[_lb_vs()["uid"]] = [loop, _lb_member()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert leg["dnat"][-1]["to"] == ["10.0.10.5/32"]
    assert not any(h["uid"] == "m:loop" for h in result["hops"])
    assert any(
        "10.0.30.10:8443" in w and "dispatches back into the same virtual service" in w
        for w in result["warnings"]
    )


def test_a_pool_of_nothing_but_self_targeting_members_draws_no_fan_out(graph):
    _lb_beyond(graph)
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member(uid="m:loop", ip="10.0.30.10")]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert not leg.get("dnat")
    assert not any(h["kind"] in ("Pool", "PoolMember") for h in result["hops"])
    assert any("dispatches back into the same virtual service" in w for w in result["warnings"])


def test_a_pool_over_the_region_cap_reports_the_surplus_as_one_leg(graph, monkeypatch):
    """The fan-out is capped by lb_member_cap. The members past the cap are
    not dropped: they are one further indeterminate leg naming the cap."""
    monkeypatch.setenv("LB_MEMBER_CAP", "2")
    _lb_beyond(graph)
    graph.pool_members[_lb_vs()["uid"]] = [
        _lb_member(uid=f"m:{i}", ip=f"10.0.10.{i}", name=f"10.0.10.{i}:8443") for i in (5, 6, 7)
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    followed = [ll for ll in result["legs"] if ll.get("dnat")]
    surplus = [ll for ll in result["legs"] if not ll.get("dnat")]
    assert len(followed) == 2
    assert len(surplus) == 1
    assert surplus[0]["indeterminate"]
    assert any("2-member cap" in w and "10.0.10.7" in w for w in result["warnings"])


def test_the_lb_devices_second_pass_keeps_its_own_table_and_filter_hops(graph):
    _lb_beyond(graph)
    graph.rb = {
        "rb_uid": "rb:fwd",
        "rb_name": "ipv4-forward",
        "vendor": "vyos",
        "default_action": "accept",
        "approximate": False,
    }
    graph.rules = []

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    vrf_ranks = sorted(h["rank"] for h in result["hops"] if h["uid"] == "vrf:main")
    assert len(vrf_ranks) == 2
    assert vrf_ranks[0] < vrf_ranks[1]
    # r1's own pass to the VIP, r1's second pass from the pool member, and fw2
    # (this FakeGraph answers the same rulebase row for every device)
    rb_ranks = sorted(h["rank"] for h in result["hops"] if h["uid"] == "rb:fwd")
    assert len(rb_ranks) == 3
    lb_ranks = [h["rank"] for h in result["hops"] if h["stage"] == "LOAD_BALANCER"]
    assert max(lb_ranks) < rb_ranks[1]


def test_two_members_fan_out_onto_consecutive_lanes(graph):
    _lb_beyond(graph)
    graph.pool_members[_lb_vs()["uid"]] = [
        _lb_member(),
        _lb_member(uid="m:b", ip="10.0.10.6", name="10.0.10.6:8443"),
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 2
    assert sorted(ll["lane"] for ll in result["legs"]) == [0, 1]
    assert sorted({h["lane"] for h in result["hops"]}) == [0, 1]


def test_a_further_member_lane_replays_only_the_pools_own_pre_fork_hops(graph):
    """The members fork at the VirtualService, so that is what a further lane
    replays. The shared source chain stays shared and on its own lane, and the
    hops of the devices upstream of the load balancer are not copied into it
    at the load balancer's own depth."""
    graph.sources = [_src_row(ip="10.0.0.5")]
    graph.routes = {
        "vrf:main": [
            _route("10.0.20.0/24", egress="eth3", kind="ORIGINATES"),
            _route("10.0.30.0/24", egress="eth3", next_hop="10.0.20.1"),
        ],
        "vrf:ns01": [
            _route("10.0.30.0/24", egress="ns-eth1", kind="ORIGINATES"),
            _route("10.0.10.0/24", egress="ns-eth2", kind="ORIGINATES"),
        ],
    }
    graph.next_hop_devs["10.0.20.1"] = {
        "dev_uid": "dev:ns01",
        "dev_name": "ns01",
        "if_uid": "if:ns-in",
        "if_name": "ns-in",
    }
    graph.default_tables["if:ns-in"] = {"uid": "vrf:ns01"}
    graph.vip[("10.0.30.10", "dev:ns01")] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [
        _lb_member(),
        _lb_member(uid="m:b", ip="10.0.10.6", name="10.0.10.6:8443"),
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    lanes = {
        h["uid"]: sorted({h2["lane"] for h2 in result["hops"] if h2["uid"] == h["uid"]})
        for h in result["hops"]
    }
    # the load balancer sits behind r1, so r1's own hops belong to lane 0 only
    assert lanes["dev:r1"] == [0]
    assert lanes["vrf:main"] == [0]
    # the shared source chain is never re-recorded as an unshared hop
    assert all(h["shared"] for h in result["hops"] if h["stage"] in ("SRC_ENDPOINT", "SRC_ATTACH"))
    # what the further lane does replay is the pool's own fork point
    assert lanes[_lb_vs()["uid"]] == [0, 1]
    assert lanes["m:b"] == [1]


def test_a_duplicated_vip_address_reports_only_the_other_instance(graph):
    """The LOAD_BALANCER stage terminates the flow on the VIP's own address, so
    that instance is the one this lane landed on, and only the other instance
    of the address is reported as one this source does not land on."""
    _lb_beyond(graph)
    graph.dst_instances["10.0.30.10"] = [
        {"uid": "ip:corp:10.0.30.10", "anchor": "corp", "l3dom": "corp"},
        {"uid": "ip:guest:10.0.30.10", "anchor": "guest", "l3dom": "guest"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert "destination 10.0.30.10 also exists in guest (not reached from this source)" in result["notes"]
    assert not any("also exists in corp" in n for n in result["notes"])


def test_the_instance_pinned_is_the_one_the_claiming_vserver_holds(graph):
    """Two vservers on one VIP can hold two IpAddress nodes of the same
    address. The instance this lane terminated on is the one the vserver that
    claimed the flow is VIP'd to, not the first binding row in uid order."""
    _lb_beyond(graph)
    web80 = _lb_vs(uid="ns:dc1-ns01:lbvs:web-080", name="web-80", port=80, ip_uid="ip:guest:10.0.30.10")
    graph.vip[("10.0.30.10", GW["dev_uid"])] = [web80, _lb_vs()]
    graph.dst_instances["10.0.30.10"] = [
        {"uid": "ip:corp:10.0.30.10", "anchor": "corp", "l3dom": "corp"},
        {"uid": "ip:guest:10.0.30.10", "anchor": "guest", "l3dom": "guest"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert result["legs"][0]["lb_uids"] == [_lb_vs()["uid"]]
    assert "destination 10.0.30.10 also exists in guest (not reached from this source)" in result["notes"]
    assert not any("also exists in corp" in n for n in result["notes"])


def test_an_undecided_vip_pins_the_instance_of_the_candidates_it_names(graph):
    _lb_beyond(graph)
    graph.vip[("10.0.30.10", GW["dev_uid"])] = [
        _lb_vs(uid="ns:vs:a", name="web-a", port=8080, ip_uid="ip:corp:10.0.30.10")
    ]
    graph.dst_instances["10.0.30.10"] = [
        {"uid": "ip:corp:10.0.30.10", "anchor": "corp", "l3dom": "corp"},
        {"uid": "ip:guest:10.0.30.10", "anchor": "guest", "l3dom": "guest"},
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", proto="tcp", gateways=[GW])

    assert result["legs"][0]["indeterminate"]
    assert "destination 10.0.30.10 also exists in guest (not reached from this source)" in result["notes"]


def test_a_snip_rewrite_records_the_address_not_a_sentence(graph):
    """The snat entry is the same shape every other source translation has:
    the addresses in `sources` and `to`, plus which snat_mode resolved it. The
    explanation rides in the note stream."""
    _lb_beyond(graph)
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs(snat_mode="snip")
    graph.snip_candidates[GW["dev_uid"]] = [
        {"ip": "10.0.10.1", "if_uid": "if:snip0", "if_name": "snip0", "cidr": "10.0.10.0/24"}
    ]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["snat"] == [
        {
            "sources": ["10.0.0.5/32"],
            "to": "10.0.10.1",
            "mode": "snip",
            "rule_uid": _lb_vs()["uid"],
        }
    ]
    assert any("SNAT to 10.0.10.1 (SNIP)" in n for n in result["notes"])


def test_a_second_own_address_vip_is_drawn_in_the_load_balancers_own_column(graph):
    _lb_beyond(graph)
    graph.dev_addrs = {
        "dev:r1": [
            _own_addr("10.0.30.10", if_uid="if:vip0", if_name="vip0"),
            _own_addr("10.0.30.11", if_uid="if:vip1", if_name="vip1"),
        ]
    }
    second = _lb_vs(uid="ns:dc1-ns01:lbvs:web-444", name="web-444", ip_uid="ip:corp:10.0.30.11")
    graph.vip[("10.0.30.11", GW["dev_uid"])] = second
    graph.pool_members[second["uid"]] = [_lb_member(uid="m:b", ip="10.0.10.6", name="10.0.10.6:8443")]

    result = path.trace(None, "10.0.0.5", "10.0.30.10/31", port=443, proto="tcp", gateways=[GW])

    first = [h["rank"] for h in result["hops"] if h["uid"] == "if:vip0"]
    later = [h["rank"] for h in result["hops"] if h["uid"] == "if:vip1"]
    assert first and later
    assert later == first
    by_uid = {h["uid"]: h["rank"] for h in result["hops"]}
    assert by_uid[second["uid"]] == by_uid[_lb_vs()["uid"]]
    assert by_uid["m:b"] == by_uid[_lb_member()["uid"]]


# --- the ZPA brokered entry point ------------------------------------------------------------------

ZPA_IDENTITY = "idg:scim:sales"
ZPA_SEGMENT = "zpa:acme:seg:2001"
ZPA_CONNECTOR = "zpa:acme:connector:dc1-01"
_BROKERED_STAGES = ("IDENTITY", "BROKER", "ACCESS_RULE", "CONNECTOR")


def _zpa_rule(**kw):
    base = {
        "uid": "zpa:acme:rule:100",
        "name": "sales-to-webshop",
        "position": 1,
        "action": "allow",
        "applies_to_all_identities": None,
        "conditions": None,
        "identity_named": True,
    }
    base.update(kw)
    return base


def _zpa_connector_row(**kw):
    base = {"uid": ZPA_CONNECTOR, "name": "dc1-conn-01", "health": "healthy"}
    base.update(kw)
    return base


def _zpa_prelude(graph):
    """The three reads every brokered trace makes before a rule is consulted:
    the identity group has to be in the graph, the segment reference has to
    resolve, and the segment has to publish the requested port."""
    graph.identity_groups[ZPA_IDENTITY] = {"uid": ZPA_IDENTITY, "name": "sales"}
    graph.segment_ref[ZPA_SEGMENT] = {"uid": ZPA_SEGMENT}
    graph.segment_ports[ZPA_SEGMENT] = {"tcp": ["443", "443"], "udp": None}


def _zpa_allow_graph(graph):
    _zpa_prelude(graph)
    graph.access_rules[(ZPA_IDENTITY, ZPA_SEGMENT)] = [_zpa_rule()]
    graph.segment_resolution[ZPA_SEGMENT] = [{"addr": "10.0.30.10"}]
    graph.zpa_connectors[ZPA_SEGMENT] = [_zpa_connector_row()]
    graph.connector_address[ZPA_CONNECTOR] = [{"host_uid": "vc:vc01:vm-201", "ip": "10.0.0.6"}]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]


def test_brokered_allow_draws_identity_access_rule_connector_then_continues(graph):
    _zpa_allow_graph(graph)

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    kinds = [(h["kind"], h["label"], h["stage"]) for h in result["hops"]]
    # the hop is labelled with the group's collected name, falling back to the uid
    assert ("IdentityGroup", "sales", "IDENTITY") in kinds
    assert ("ZpaAccessRule", "sales-to-webshop", "ACCESS_RULE") in kinds
    assert ("ZpaAppConnector", "dc1-conn-01", "CONNECTOR") in kinds
    # Stage order, not call order: the four brokered stages rank strictly
    # before every ordinary pipeline hop that follows them.
    brokered_ranks = [h["rank"] for h in result["hops"] if h["stage"] in _BROKERED_STAGES]
    other_ranks = [h["rank"] for h in result["hops"] if h["stage"] not in _BROKERED_STAGES]
    assert brokered_ranks and other_ranks
    assert max(brokered_ranks) < min(other_ranks)
    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert not leg["indeterminate"]
    assert leg["dnat"] == [{"to": ["10.0.10.5/32"], "port": 8443, "rule_uid": _lb_member()["uid"]}]
    assert leg["lb_uids"] == [_lb_vs()["uid"]]


def test_brokered_deny_stops_at_access_rule_with_no_further_hops(graph):
    _zpa_prelude(graph)
    deny_rule = _zpa_rule(uid="zpa:acme:rule:200", name="contractors-deny-corp", action="deny")
    graph.access_rules[(ZPA_IDENTITY, ZPA_SEGMENT)] = [deny_rule]

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    kinds = [(h["kind"], h["stage"]) for h in result["hops"]]
    assert ("IdentityGroup", "IDENTITY") in kinds
    assert ("ZpaAccessRule", "ACCESS_RULE") in kinds
    assert not any(h["stage"] == "CONNECTOR" for h in result["hops"])
    assert result["legs"] == [{"indeterminate": False, "blocked": True, "blocking_uid": "zpa:acme:rule:200"}]
    assert "denied" in result["verdict"]
    assert not result["indeterminate"]


def test_brokered_unresolved_segment_is_indeterminate_with_no_hops_past_it(graph):
    _zpa_prelude(graph)
    graph.access_rules[(ZPA_IDENTITY, ZPA_SEGMENT)] = [_zpa_rule()]
    graph.segment_resolution[ZPA_SEGMENT] = []

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert result["indeterminate"]
    assert not any(h["stage"] == "CONNECTOR" for h in result["hops"])
    assert ZPA_SEGMENT in result["verdict"]


def test_brokered_no_healthy_connector_is_indeterminate_with_no_hops_past_it(graph):
    _zpa_prelude(graph)
    graph.access_rules[(ZPA_IDENTITY, ZPA_SEGMENT)] = [_zpa_rule()]
    graph.segment_resolution[ZPA_SEGMENT] = [{"addr": "10.0.30.10"}]
    graph.zpa_connectors[ZPA_SEGMENT] = []

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert result["indeterminate"]
    assert not any(h["stage"] == "CONNECTOR" for h in result["hops"])


def test_brokered_connector_with_no_collected_address_is_indeterminate(graph):
    _zpa_prelude(graph)
    graph.access_rules[(ZPA_IDENTITY, ZPA_SEGMENT)] = [_zpa_rule()]
    graph.segment_resolution[ZPA_SEGMENT] = [{"addr": "10.0.30.10"}]
    graph.zpa_connectors[ZPA_SEGMENT] = [_zpa_connector_row()]
    graph.connector_address[ZPA_CONNECTOR] = []

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert result["indeterminate"]
    # the CONNECTOR hop IS drawn (a connector was chosen); nothing beyond it is.
    assert any(h["stage"] == "CONNECTOR" for h in result["hops"])
    assert not any(h["stage"] not in _BROKERED_STAGES for h in result["hops"])


def test_brokered_connector_without_runs_on_does_not_follow_same_as_by_default(graph):
    _zpa_prelude(graph)
    graph.access_rules[(ZPA_IDENTITY, ZPA_SEGMENT)] = [_zpa_rule()]
    graph.segment_resolution[ZPA_SEGMENT] = [{"addr": "10.0.30.10"}]
    graph.zpa_connectors[ZPA_SEGMENT] = [_zpa_connector_row()]
    graph.connector_address[ZPA_CONNECTOR] = []
    graph.connector_same_as[ZPA_CONNECTOR] = [{"ip": "10.0.0.6", "confidence": 0.6}]

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert result["indeterminate"]
    assert not any(h["stage"] not in _BROKERED_STAGES for h in result["hops"])


def test_brokered_connector_follows_same_as_when_asked_and_names_the_basis(graph):
    _zpa_allow_graph(graph)
    graph.connector_address[ZPA_CONNECTOR] = []
    graph.connector_same_as[ZPA_CONNECTOR] = [{"ip": "10.0.0.6", "confidence": 0.6}]

    result = path.trace_from_identity(
        None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW], follow_same_as=True
    )

    assert len(result["legs"]) == 1 and not result["legs"][0]["indeterminate"]
    notes = " ".join(result["notes"])
    assert "SAME_AS" in notes and "10.0.0.6" in notes and "0.6" in notes


def test_brokered_trace_pins_a_bare_session_to_the_current_run(monkeypatch):
    pinned_with = []

    class _BareSession:
        pass

    session = _BareSession()
    monkeypatch.setattr(path, "load_gateways", lambda s: [GW])
    monkeypatch.setattr(cyclemod, "current_ts_or_none", lambda s: 1_735_689_600_000)

    def _pinned(s, snap):
        pinned_with.append((s, snap.cts))
        return s

    monkeypatch.setattr(path, "pinned", _pinned)
    monkeypatch.setattr(path, "_read", lambda s, query, **p: [])
    monkeypatch.setattr(path, "_read_one", lambda s, query, **p: None)

    path.trace_from_identity(session, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp")

    assert pinned_with == [(session, 1_735_689_600_000)]


def test_brokered_trace_loads_gateways_when_the_caller_supplies_none(graph, monkeypatch):
    _zpa_allow_graph(graph)
    loaded = []

    def _load(session):
        loaded.append(session)
        return [GW]

    monkeypatch.setattr(path, "load_gateways", _load)

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp")

    assert loaded
    assert len(result["legs"]) == 1
    assert not result["legs"][0]["indeterminate"]


def test_brokered_unknown_identity_group_is_indeterminate_before_any_rule_is_read(graph):
    """An allow-all rule must not answer for a uid the twin does not hold:
    the identity is a dimension of the match, so an IdentityGroup the graph
    does not contain is named, and no IDENTITY hop is drawn for it."""
    _zpa_allow_graph(graph)
    graph.identity_groups[ZPA_IDENTITY] = None
    graph.access_rules[(ZPA_IDENTITY, ZPA_SEGMENT)] = [
        _zpa_rule(identity_named=False, applies_to_all_identities=True)
    ]

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert result["indeterminate"]
    assert result["hops"] == []
    assert ZPA_IDENTITY in result["verdict"]


def test_brokered_port_inside_the_segments_collected_ranges_is_brokered(graph):
    _zpa_allow_graph(graph)
    graph.segment_ports[ZPA_SEGMENT] = {"tcp": ["440", "445"], "udp": None}

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert any(h["stage"] == "ACCESS_RULE" for h in result["hops"])
    assert not result["indeterminate"]


def test_brokered_port_outside_every_collected_range_is_a_named_no_match(graph):
    """A broker does not intercept a port the segment does not publish, so
    the flow stops at the segment and no rule is consulted."""
    _zpa_allow_graph(graph)

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=22, proto="tcp", gateways=[GW])

    assert not result["indeterminate"]
    assert result["legs"] == [{"indeterminate": False, "blocked": True, "blocking_uid": ZPA_SEGMENT}]
    assert "443-443" in result["verdict"] and "22" in result["verdict"]
    assert not any(h["stage"] == "ACCESS_RULE" for h in result["hops"])


def test_brokered_uncollected_port_ranges_are_indeterminate_naming_the_segment(graph):
    _zpa_allow_graph(graph)
    graph.segment_ports[ZPA_SEGMENT] = {"tcp": None, "udp": None}

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert result["indeterminate"]
    assert ZPA_SEGMENT in result["verdict"]
    assert not any(h["stage"] == "ACCESS_RULE" for h in result["hops"])


def test_brokered_connector_address_in_two_contexts_is_named_not_picked(graph):
    _zpa_allow_graph(graph)
    graph.sources_by_ip["10.0.0.6"] = [_src_row(dom="home"), _src_row(dom="dev")]

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert result["indeterminate"]
    assert "home" in result["verdict"] and "dev" in result["verdict"]
    assert not any(h["stage"] not in _BROKERED_STAGES for h in result["hops"])


def test_brokered_same_as_address_in_two_contexts_is_named_not_picked(graph):
    """A SAME_AS address that the campus holds in two forwarding
    contexts is named, as a RUNS_ON address is, not picked."""
    _zpa_allow_graph(graph)
    graph.connector_address[ZPA_CONNECTOR] = []
    graph.connector_same_as[ZPA_CONNECTOR] = [{"ip": "10.0.0.6", "confidence": 0.6}]
    graph.sources_by_ip["10.0.0.6"] = [_src_row(dom="home"), _src_row(dom="dev")]

    result = path.trace_from_identity(
        None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW], follow_same_as=True
    )

    assert result["indeterminate"]
    assert "home" in result["verdict"] and "dev" in result["verdict"]
    assert any("SAME_AS" in n and "10.0.0.6" in n for n in result["notes"])
    assert not any(h["stage"] not in _BROKERED_STAGES for h in result["hops"])


def test_brokered_alternate_connectors_and_addresses_are_noted_not_dropped(graph):
    _zpa_allow_graph(graph)
    graph.zpa_connectors[ZPA_SEGMENT] = [
        _zpa_connector_row(),
        _zpa_connector_row(uid="zpa:acme:connector:dc1-02", name="dc1-conn-02"),
        _zpa_connector_row(uid="zpa:acme:connector:dc1-03", name="dc1-conn-03", health=None),
    ]
    graph.connector_address[ZPA_CONNECTOR] = [
        {"host_uid": "vc:vc01:vm-201", "ip": "10.0.0.6"},
        {"host_uid": "vc:vc01:vm-201", "ip": "10.9.9.9"},
    ]

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    notes = " ".join(result["notes"])
    assert "dc1-conn-02" in notes
    assert "dc1-conn-03" in notes and "no collected health" in notes
    assert "10.9.9.9" in notes


def test_brokered_legs_carry_the_l2_walk_flags_from_the_trail(graph, monkeypatch):
    _zpa_allow_graph(graph)
    graph.routes["vrf:main"].append(_route("0.0.0.0/0", egress="eth0"))
    real_walk = tracemod._gateway_walk

    def _walk(session, trail, gw, attach, src_set, **kwargs):
        trail.l2_boundary = True
        trail.l2_mismatch = True
        return real_walk(session, trail, gw, attach, src_set, **kwargs)

    monkeypatch.setattr(tracemod, "_gateway_walk", _walk)

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert result["boundary"]
    assert result["indeterminate"]
    assert all(ll["boundary"] and ll["indeterminate"] for ll in result["legs"])


def test_brokered_same_connected_prefix_is_switched_not_routed(graph):
    _zpa_prelude(graph)
    graph.access_rules[(ZPA_IDENTITY, ZPA_SEGMENT)] = [_zpa_rule()]
    graph.segment_resolution[ZPA_SEGMENT] = [{"addr": "10.0.0.9"}]
    graph.zpa_connectors[ZPA_SEGMENT] = [_zpa_connector_row()]
    graph.connector_address[ZPA_CONNECTOR] = [{"host_uid": "vc:vc01:vm-201", "ip": "10.0.0.6"}]

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert len(result["legs"]) == 1
    leg = result["legs"][0]
    assert "switched in 10.0.0.0/24" in leg["verdict"]
    assert leg["cidr"] is None
    assert not any(h["uid"] == GW["dev_uid"] for h in result["hops"])


def test_brokered_legs_carry_the_interpretation_key(graph):
    """Every other trace result states the interpretation each leg rests on;
    a brokered leg is read by the same viewers."""
    _zpa_allow_graph(graph)

    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])

    assert all(ll["interpretation"]["src_ip"] == "10.0.0.6" for ll in result["legs"])
    assert all(ll["interpretation"]["display"] == "home" for ll in result["legs"])


# --- header space: service fan-out -------------------------------------------------------


def test_a_ranged_port_query_fans_a_firewall_rule_into_sibling_legs(graph):
    """A single firewall rule scoped to part of the query's port range
    produces one leg per region: the sub-range it decides and the remainder
    that falls to the default action, each carrying its own `service` field
    naming its own narrowed range."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "accept",
        "approximate": False,
    }
    graph.rules = [_rule(uid="cp:deny", pos=1, action="drop", svc_any=False, protos=["tcp"], ports=["1-100"])]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port="50-150", proto="tcp", gateways=[GW])

    legs = result["legs"]
    assert len(legs) == 2
    blocked = next(ll for ll in legs if ll["blocked"])
    permitted = next(ll for ll in legs if not ll["blocked"])
    assert blocked["service"] == {"proto": ["tcp"], "ports": [[50, 100]]}
    assert permitted["service"] == {"proto": ["tcp"], "ports": [[101, 150]]}
    assert blocked["lane"] != permitted["lane"]
    assert "by rule 1" in blocked["firewall"]
    assert "default-action" in permitted["firewall"]


def test_a_service_fan_out_replays_shared_hops_like_an_ecmp_fork(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "accept",
        "approximate": False,
    }
    graph.rules = [_rule(uid="cp:deny", pos=1, action="drop", svc_any=False, protos=["tcp"], ports=["1-100"])]
    result = path.trace(None, "10.0.0.5", "8.8.8.8", port="50-150", proto="tcp", gateways=[GW])

    lanes = sorted({leg["lane"] for leg in result["legs"]})
    assert len(lanes) == 2
    hops = result["hops"]
    for kind, uid in (("VrfInstance", "vrf:main"), ("Prefix", "pfx:0.0.0.0/0")):
        drawn = [h for h in hops if h["uid"] == uid and h["kind"] == kind]
        assert sorted(h["lane"] for h in drawn) == lanes
        assert len({h["rank"] for h in drawn}) == 1
    # and the source spine in front of that lookup is drawn once and shared,
    # not copied into the sibling: an ECMP fork leaves it alone the same way
    for kind, uid in (("Interface", "if:eth1"), ("Device", "dev:r1")):
        drawn = [h for h in hops if h["uid"] == uid and h["kind"] == kind]
        assert [(h["lane"], h["shared"]) for h in drawn] == [(0, True)]
    # each lane opens on the routing context the fork came out of
    for lane in lanes:
        assert (unshared_hops(hops, lane)[0]["kind"]) == "VrfInstance"
    rb_hops = [h for h in hops if h["kind"] == "FwRulebase"]
    assert sorted(h["lane"] for h in rb_hops) == lanes
    assert len({h["rank"] for h in rb_hops}) == 1
    assert {h["note"] for h in rb_hops} == {
        "checkpoint · drop (rule)",
        "checkpoint · accept (default-action)",
    }


def test_a_ranged_port_query_fans_a_dnat_pat_rule_into_sibling_legs(graph):
    from tests.test_path_nat import _dnat_row

    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.0.0.0/24", egress="eth2"),
            _route("203.0.113.0/24", egress="eth3"),
        ]
    }
    graph.nat = [_dnat_row(orig_dst_port="1-100", translation_port="2000-2099")]
    result = path.trace(None, "10.0.0.5", "203.0.113.10", port="1-150", proto="tcp", gateways=[GW])

    legs = result["legs"]
    assert len(legs) == 2
    translated = next(ll for ll in legs if ll.get("dnat"))
    remainder = next(ll for ll in legs if not ll.get("dnat"))
    assert translated["dnat"] == [{"to": ["10.0.0.99/32"], "port": None, "rule_uid": "dnat:r10"}]
    assert translated["cidr"] == "10.0.0.0/24"
    # the region the translated sibling carries onward is the pool it was
    # rewritten to, not the ports the query named before the rewrite
    assert translated["service"] == {"proto": ["tcp"], "ports": [[2000, 2099]]}
    assert remainder["cidr"] == "203.0.113.0/24"
    assert remainder["service"] == {"proto": ["tcp"], "ports": [[101, 150]]}
    dnat_hops = [h for h in result["hops"] if h["kind"] == "NatRule"]
    assert any("2000-2099" in h["note"] for h in dnat_hops)


def _service_rb(vendor="checkpoint", default_action="accept"):
    return {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": vendor,
        "default_action": default_action,
        "approximate": False,
    }


def test_a_dnat_pat_sibling_is_judged_downstream_on_the_translated_ports(graph):
    from tests.test_path_nat import _dnat_row

    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.0.20.0/24", egress="eth2", next_hop="10.0.30.1"),
            _route("10.0.30.0/24", egress="eth2", kind="ORIGINATES"),
            _route("203.0.113.0/24", egress="eth3"),
        ]
    }
    graph.nat = [
        _dnat_row(
            orig_dst_port="1-100",
            translation="10.0.20.5",
            xlate_dst_addrs=["10.0.20.5"],
            translation_port="2000-2099",
        )
    ]
    graph.next_hop_devs["10.0.30.1"] = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
    }
    graph.default_tables["if:fw2-in"] = {"uid": "vrf:fw2"}
    graph.routes["vrf:fw2"] = [_route("10.0.20.0/24", egress="fw2-eth0", kind="ORIGINATES")]
    graph.rb = _service_rb(vendor="vyos", default_action="accept")
    graph.rules = [_rule(uid="cp:deny", pos=1, action="drop", svc_any=False, protos=["tcp"], ports=["1-100"])]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port="1-150", proto="tcp", gateways=[GW])

    legs = result["legs"]
    translated = [ll for ll in legs if ll.get("dnat")]
    assert len(translated) == 1
    far = translated[0]
    assert not far["blocked"]
    assert far["service"] == {"proto": ["tcp"], "ports": [[2000, 2099]]}
    assert ("Device", "fw2") in [(h["kind"], h["label"]) for h in result["hops"]]


GW6 = {**GW, "cidr": "2001:db8::/64"}
R2_ON_THE_LINK = {"dev_uid": "dev:r2", "dev_name": "r2", "if_uid": "if:r2-eth0", "if_name": "r2-eth0"}


def _link_local_route(graph):
    """r1 routes 2001:db8:99::/64 to the link-local next hop fe80::2 out of
    eth2, where r2 serves the destination."""
    graph.sources = [_src_row(ip="2001:db8::5")]
    graph.routes = {
        "vrf:main": [
            _route("2001:db8:99::/64", egress="eth2", next_hop="fe80::2"),
            _route("2001:db8:12::/64", egress="eth2", kind="ORIGINATES"),
        ],
        "vrf:r2": [_route("2001:db8:99::/64", egress="r2-lan", kind="ORIGINATES")],
    }
    graph.default_tables["if:r2-eth0"] = {"uid": "vrf:r2"}


def test_a_link_local_next_hop_is_found_on_the_egress_link(graph):
    """An OSPFv3 or BGP route names its next hop by its link-local
    address, which no IpAddress holds; the neighbour holding it on the link
    out of eth2 is the next hop, and the trace continues there."""
    _link_local_route(graph)
    graph.link_peers[("if:eth2", "fe80::2")] = [R2_ON_THE_LINK]

    result = path.trace(None, "2001:db8::5", "2001:db8:99::7", port=443, proto="tcp", gateways=[GW6])

    assert ("Device", "r2") in [(h["kind"], h["label"]) for h in result["hops"]]
    assert not any(leg.get("boundary") for leg in result["legs"])
    assert not any("leaves the twin" in w for w in result["warnings"])
    assert "fe80::2" not in graph.next_hop_lookups  # not looked up by its literal address


def test_a_link_local_next_hop_no_interface_on_the_link_holds_is_undecided(graph):
    _link_local_route(graph)

    result = path.trace(None, "2001:db8::5", "2001:db8:99::7", port=443, proto="tcp", gateways=[GW6])

    (leg,) = result["legs"]
    assert leg["indeterminate"] and not leg.get("boundary")
    assert any("no collected interface on the egress link holds" in w for w in result["warnings"])
    assert not any("leaves the twin" in w for w in result["warnings"])


def test_a_link_local_next_hop_held_twice_on_the_link_fails_closed(graph):
    _link_local_route(graph)
    r3 = {"dev_uid": "dev:r3", "dev_name": "r3", "if_uid": "if:r3-eth0", "if_name": "r3-eth0"}
    graph.link_peers[("if:eth2", "fe80::2")] = [R2_ON_THE_LINK, r3]

    result = path.trace(None, "2001:db8::5", "2001:db8:99::7", port=443, proto="tcp", gateways=[GW6])

    assert result["legs"][0]["indeterminate"]
    assert any("held on the egress link by more than one interface" in w for w in result["warnings"])


@pytest.mark.parametrize("spec", ["8443", "8000-9000"])
def test_a_region_narrowed_to_one_port_crosses_a_next_hop_as_a_port_number(graph, spec):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.0.10.0/24", egress="eth2", next_hop="10.0.20.1"),
            _route("10.0.20.0/24", egress="eth2", kind="ORIGINATES"),
        ]
    }
    graph.next_hop_devs["10.0.20.1"] = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
    }
    graph.default_tables["if:fw2-in"] = {"uid": "vrf:fw2"}
    graph.routes["vrf:fw2"] = [_route("10.0.10.0/24", egress="fw2-eth0", kind="ORIGINATES")]
    graph.rb = _service_rb(default_action="drop")
    graph.rules = [_rule(uid="cp:ok", pos=1, action="accept", svc_any=False, ports=[spec])]

    result = path.trace(None, "10.0.0.5", "10.0.10.5", port="80,8443", gateways=[GW])

    legs = result["legs"]
    assert len(legs) == 2
    permitted = [ll for ll in legs if not ll["blocked"]]
    assert len(permitted) == 1
    assert permitted[0]["service"] == {"proto": [], "ports": [[8443, 8443]]}
    assert "by rule 1" in permitted[0]["firewall"]
    assert ("Device", "fw2") in [(h["kind"], h["label"]) for h in result["hops"]]


def test_a_check_point_gateway_decides_a_ranged_query_on_the_original_destination(graph):
    from tests.test_path_nat import _dnat_row

    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]
    graph.rb = _service_rb(vendor="checkpoint", default_action="drop")
    graph.rules = [
        _rule(
            uid="cp:pub",
            pos=1,
            action="accept",
            dst_any=False,
            dst_cidrs=["203.0.113.10/32"],
            svc_any=False,
            protos=["tcp"],
            ports=["443"],
        )
    ]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port="80,443", proto="tcp", gateways=[GW])

    legs = result["legs"]
    assert len(legs) == 2
    by_ports = {tuple(map(tuple, ll["service"]["ports"])): ll for ll in legs}
    permitted = by_ports[((443, 443),)]
    assert not permitted["blocked"]
    assert "by rule 1" in permitted["firewall"]
    assert by_ports[((80, 80),)]["blocked"]
    assert permitted["filter_view"] == "original"


def test_a_ranged_query_on_a_device_with_no_derivable_filter_view_is_indeterminate(graph):
    from tests.test_path_nat import _dnat_row

    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.0.0/24", egress="eth2")]}
    graph.nat = [_dnat_row()]
    graph.rb = _service_rb(vendor="nsx", default_action="accept")
    graph.access_vendors = ["nsx"]
    graph.rules = [_rule(uid="x:1", pos=1, action="accept", svc_any=False, protos=["tcp"], ports=["443"])]

    result = path.trace(None, "10.0.0.5", "203.0.113.10", port="80,443", proto="tcp", gateways=[GW])

    assert all(ll["indeterminate"] for ll in result["legs"])
    assert any("could not be derived" in w for w in result["warnings"])


def test_the_load_balancer_stage_reads_a_ranged_query_as_not_stated(graph):
    """A stated port range the VirtualService's port lies outside is a
    definite miss on that dimension, whatever the unstated protocol: tcp/443
    serves no port in 80-100, so the VIP serves nothing of the flow and the
    leg is blocked there, with the VirtualService named."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.30.0/24", egress="eth2", kind="ORIGINATES")]}
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs()
    graph.pool_members[_lb_vs()["uid"]] = [_lb_member()]

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port="80-100", gateways=[GW])

    assert all(ll["blocked"] and not ll["indeterminate"] for ll in result["legs"])
    assert any("web-443" in n for n in result["notes"])


def _pbr_tcp_443_into_table_100(graph):
    """One PBR rule scoped to TCP 443 toward 10.9.9.0/24 into table 100, with
    table 100 egressing via wg0 and the main table via eth0."""
    graph.sources = [_src_row()]
    graph.pbr = [
        {
            "pol_uid": "pol:1",
            "pol_name": "steer",
            "rule_uid": "rule:10",
            "pos": 10,
            "rule_name": None,
            "src_cidrs": [],
            "src_ips": [],
            "src_ranges": [],
            "dst_cidrs": ["10.9.9.0/24"],
            "dst_ips": [],
            "dst_ranges": [],
            "table_uid": "vrf:100",
            "table_name": "100",
            "svc_obj_count": 1,
            "svc_protos": ["tcp"],
            "svc_port_specs": ["443"],
        }
    ]
    graph.routes = {
        "vrf:100": [_route("0.0.0.0/0", egress="wg0")],
        "vrf:main": [_route("0.0.0.0/0", egress="eth0")],
    }


def test_pbr_decides_a_ranged_query_on_the_part_its_service_covers(graph):
    _pbr_tcp_443_into_table_100(graph)

    result = path.trace(None, "10.0.0.5", "10.9.9.9", port="1-1024", proto="tcp", gateways=[GW])

    legs = result["legs"]
    assert len(legs) == 2
    by_table = {leg["table"]: leg for leg in legs}
    steered = by_table["100"]
    assert steered["egress"] == "wg0"
    assert not steered["indeterminate"]
    assert steered["service"] == {"proto": ["tcp"], "ports": [[443, 443]]}
    rest = by_table["default"]
    assert rest["egress"] == "eth0"
    assert not rest["indeterminate"]
    assert rest["service"] == {"proto": ["tcp"], "ports": [[1, 442], [444, 1024]]}
    assert ("PbrPolicy", "steer") in [(h["kind"], h["label"]) for h in result["hops"]]
    # the policy was read once for the device and is credited on both legs
    assert all(leg["pbr_uids"] == ["pol:1"] for leg in legs)


def test_pbr_leaves_a_ranged_query_its_service_misses_to_the_main_table(graph):
    _pbr_tcp_443_into_table_100(graph)

    result = path.trace(None, "10.0.0.5", "10.9.9.9", port="1-400", proto="tcp", gateways=[GW])

    legs = result["legs"]
    assert len(legs) == 1
    assert legs[0]["table"] == "default"
    assert legs[0]["egress"] == "eth0"
    assert not legs[0]["indeterminate"]
    assert legs[0]["service"] == {"proto": ["tcp"], "ports": [[1, 400]]}
    assert not any(h["kind"] in ("PbrPolicy", "FwRule") for h in result["hops"])
    assert legs[0]["pbr_uids"] == ["pol:1"]


def _two_device_graph(graph, *, rule_out_if):
    """r1 routes to fw2, and only the far device's egress carries the rules."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.0.10.0/24", egress="eth2", next_hop="10.0.20.1"),
            _route("10.0.20.0/24", egress="eth2", kind="ORIGINATES"),
        ]
    }
    graph.next_hop_devs["10.0.20.1"] = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
    }
    graph.default_tables["if:fw2-in"] = {"uid": "vrf:fw2"}
    graph.routes["vrf:fw2"] = [_route("10.0.10.0/24", egress="fw2-eth0", kind="ORIGINATES")]
    graph.iface_names = {
        "if:eth1": "eth1",
        "if:eth2": "eth2",
        "if:fw2-in": "fw2-in",
        "if:fw2-eth0": "fw2-eth0",
    }
    graph.rb = _service_rb(vendor="vyos", default_action="accept")
    graph.rules = [
        _rule(
            uid="cp:deny",
            pos=1,
            action="drop",
            out_if=rule_out_if,
            svc_any=False,
            protos=["tcp"],
            ports=["1-100"],
        )
    ]


def test_a_fan_out_at_the_second_device_replays_no_hop_of_the_first(graph):
    _two_device_graph(graph, rule_out_if="fw2-eth0")

    result = path.trace(None, "10.0.0.5", "10.0.10.5", port="50-150", proto="tcp", gateways=[GW])

    lanes = sorted({leg["lane"] for leg in result["legs"]})
    assert len(lanes) == 2
    sibling = max(lanes)
    # the far device draws its own Prefix for the same route, so the uids that
    # belong to the first device alone are the ones that must not appear
    first_device = {"dev:r1", "if:eth1", "if:eth2", "vrf:main"}
    assert not [h for h in result["hops"] if h["lane"] == sibling and h["uid"] in first_device]
    # and every hop the sibling does carry is ranked after the first device's
    # own hops, so a replayed hop is never re-stamped at the wrong depth
    sibling_ranks = [h["rank"] for h in result["hops"] if h["lane"] == sibling]
    first_ranks = [h["rank"] for h in result["hops"] if h["uid"] in first_device]
    assert min(sibling_ranks) > max(first_ranks)


def test_a_fan_out_at_every_hop_stops_at_the_per_trace_region_budget(graph, monkeypatch):
    """The region ceiling is on the whole trace, not on one rulebase walk:
    a leg that forks again at every device multiplies the per-device caps. Once
    the budget is spent the remaining regions are reported as one indeterminate
    region naming the setting, never dropped and never fanned out further."""
    # `hst.path` re-exports `trace` as the function, so the module the
    # setting is read in is fetched by name
    tracemod = import_module("hst.path.trace")

    _two_device_graph(graph, rule_out_if=None)
    # one rule per device, cutting the range at a different port, so the
    # regions the first device decided are each split again by the second
    graph.rules = [
        _rule(
            uid="fw:a",
            pos=1,
            action="accept",
            out_if="eth2",
            svc_any=False,
            protos=["tcp"],
            ports=["1-100"],
        ),
        _rule(
            uid="fw:b",
            pos=2,
            action="accept",
            out_if="fw2-eth0",
            svc_any=False,
            protos=["tcp"],
            ports=["1-60"],
        ),
    ]
    monkeypatch.setattr(
        tracemod, "Settings", lambda: SimpleNamespace(path_region_cap=3, path_lane_cap=64, max_l3_hops=8)
    )

    result = path.trace(None, "10.0.0.5", "10.0.10.5", port="50-150", proto="tcp", gateways=[GW])

    # without the budget the second device splits the first device's two
    # regions into three legs; with it the surplus is one undecided leg
    legs = result["legs"]
    assert len(legs) == 2
    truncated = [ll for ll in legs if ll["indeterminate"]]
    assert len(truncated) == 1
    # the leg names the truncation, not a rulebase called None, and the
    # setting's own value (3), never the budget left over at this device
    assert truncated[0]["firewall"] == "partition truncated at the path_region_cap setting (3 regions)"
    assert any("path_region_cap" in n for n in result["notes"] + result["warnings"])


# --- the RIB coverage gap ----------------------------------------------------------------


class _FailedRib:
    """A RibSource stand-in bound to a run whose manifest recorded the device's
    RIB table as failed: no rows to answer, and the reason on record."""

    available = True

    def lpm(self, device_uid, context_uid, probe_ip, *, legacy_vrf=None):
        return []

    def overlapping(self, device_uid, context_uid, lo, hi, min_prefixlen, af, *, legacy_vrf=None):
        return []

    def has_rows(self, device_uid):
        return False

    def coverage(self, device_uid):
        return "failed"


def test_a_rib_outcome_beyond_the_manifest_walk_is_a_recorded_gap():
    """Past the bounded manifest walk the device's outcome is
    `unknown`; held rows must not read as confirmed, nor an absent table as
    "no RIB rows"."""
    from hst.path.trace import _rib_gap

    for rows in (True, False):
        rib = type(
            "UnknownRib",
            (_FailedRib,),
            {"has_rows": lambda self, uid, rows=rows: rows, "coverage": lambda self, uid: "unknown"},
        )()
        why, recorded = _rib_gap(rib, "r1")
        assert recorded is True
        assert "beyond the manifests read" in why


def test_a_failed_rib_outcome_makes_the_trace_note_name_the_coverage_gap(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW], rib=_FailedRib())

    note = next(n for n in result["warnings"] if "not consulted" in n)
    assert "RIB of r1" in note
    assert "recorded this device's RIB table as failed" in note
    assert result["legs"][0]["indeterminate"]
    # the verdict names the routing cause, not the default policy wording
    assert "INDETERMINATE, RIB of r1" in result["verdict"]
    assert "policy on this path was not evaluated" not in result["verdict"]
    assert result["legs"][0]["indeterminate_reason"].startswith("RIB of r1 table")
    # every leg names the device whose table it leaves
    assert result["legs"][0]["device_uid"] == GW["dev_uid"]


class _UnrecordedRib(_FailedRib):
    def coverage(self, device_uid):
        return None


def test_a_recorded_but_unusable_rib_marks_every_routed_leg(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1")]}

    result = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=_FailedRib())

    assert result["legs"][0]["cidr"] == "10.50.60.0/24"
    assert result["legs"][0]["indeterminate"] is True
    assert any("not consulted" in w and "as failed" in w for w in result["warnings"])


def test_a_device_with_no_recorded_rib_keeps_its_specific_graph_routes_settled(graph):
    """Nothing records a RIB for the device (no outcome, no rows) and no
    dynamic routing process runs in the table's VRF: the graph is the whole
    answer such a device gives, so a specific graph route and a default route
    both stay settled. No more specific route is the evidence, not a gap."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1")]}
    specific = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=_UnrecordedRib())
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    default = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=_UnrecordedRib())

    assert specific["legs"][0]["indeterminate"] is False
    assert not any("not consulted" in w for w in specific["warnings"])
    assert default["legs"][0]["indeterminate"] is False
    assert not any("not consulted" in w for w in default["warnings"])


def test_a_device_with_no_recorded_rib_and_dynamic_routing_marks_its_default_route(graph):
    """Nothing records a RIB for the device, but a BGP process runs in the
    table's VRF: a learned route the graph does not hold can be more specific
    than the default route, so the default-route part reports the gap and a
    specific graph route stays settled."""
    read_one = graph.read_one
    graph.read_one = lambda q, **p: {"proto": "bgp"} if "RoutingProcess" in q else read_one(q, **p)
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.50.60.0/24", egress="eth2", next_hop="10.50.60.1")]}
    specific = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=_UnrecordedRib())
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    default = path.trace(None, "10.0.0.5", "10.50.60.8", gateways=[GW], rib=_UnrecordedRib())

    assert specific["legs"][0]["indeterminate"] is False
    assert default["legs"][0]["indeterminate"] is True
    assert any("no RIB rows for this device" in w for w in default["warnings"])


@pytest.mark.parametrize("port", [443, "80-81"])
def test_routed_path_crosses_distinct_vsids_on_one_member(graph, port):
    graph.sources = [_src_row()]
    vs7 = {
        "dev_uid": "dev:vsx",
        "dev_name": "vsx",
        "if_uid": "vs7:in",
        "if_name": "eth1",
        "firewall_instance_uid": "fi:vs7",
        "vsid": 7,
        "vsx_kind": "virtual-system",
    }
    vs8 = dict(vs7, if_uid="vs8:in", firewall_instance_uid="fi:vs8", vsid=8)
    graph.default_tables = {
        GW["if_uid"]: {"uid": "vrf:nxos"},
        vs7["if_uid"]: {"uid": "vrf:vs7"},
        vs8["if_uid"]: {"uid": "vrf:vs8"},
    }
    graph.routes = {
        "vrf:nxos": [_route("203.0.113.0/24", egress="nx-out", next_hop="192.0.2.7")],
        "vrf:vs7": [_route("203.0.113.0/24", egress="vs7-out", next_hop="192.0.2.8")],
        "vrf:vs8": [_route("203.0.113.0/24", egress="vs8-out")],
    }
    graph.next_hop_devs = {"192.0.2.7": vs7, "192.0.2.8": vs8}
    result = path.trace(None, "10.0.0.5", "203.0.113.5", port=port, proto="tcp", gateways=[GW])
    assert {h["uid"] for h in result["hops"] if h["kind"] == "FirewallInstance"} == {"fi:vs7", "fi:vs8"}
    assert not any("routing loop" in warning for warning in result["warnings"])
    assert result["legs"][0]["egress"] == "vs8-out"
    # Topological reachability without captured VS policies is not a permit.
    assert result["indeterminate"]


def test_hide_nat_does_not_use_ipv6_address_for_ipv4_flow(graph):
    from tests.test_path_nat import _nat_row

    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    graph.nat = [_nat_row(translation="masquerade")]
    graph.iface_addrs["if:eth0"] = "2001:db8::1"
    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])
    assert result["indeterminate"]
    assert not result["legs"][0].get("nat_chain")


# --- segment state before the rule match -------------------------------------------------------


def test_brokered_disabled_segment_is_a_blocked_leg_that_names_the_segment(graph, monkeypatch):
    _zpa_allow_graph(graph)
    monkeypatch.setattr(
        __import__("sys").modules["hst.path.trace"], "_segment_state", lambda session, uid: "disabled"
    )
    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])
    assert result["legs"] == [{"indeterminate": False, "blocked": True, "blocking_uid": ZPA_SEGMENT}]
    assert "disabled" in result["verdict"]
    assert not any(h["stage"] in ("ACCESS_RULE", "CONNECTOR") for h in result["hops"])


def test_brokered_always_bypass_is_not_brokered_and_undecided(graph, monkeypatch):
    _zpa_allow_graph(graph)
    monkeypatch.setattr(
        __import__("sys").modules["hst.path.trace"], "_segment_state", lambda session, uid: "bypass"
    )
    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])
    assert result["indeterminate"]
    assert "bypass_type ALWAYS" in result["verdict"]


# --- one FQDN listed by several segments -------------------------------------------------------

SHARED_FQDN = "app.corp.example"


def _shared_fqdn_graph(graph, monkeypatch, *, states=None, ports=None):
    """seg:a publishes tcp/22, seg:b tcp/443, and both list the same domain."""
    _zpa_allow_graph(graph)
    graph.segment_ref[SHARED_FQDN] = [{"uid": "zpa:seg:a"}, {"uid": "zpa:seg:b"}]
    ports = ports or {"zpa:seg:a": ["22", "22"], "zpa:seg:b": ["443", "443"]}
    for uid, tcp in ports.items():
        graph.segment_ports[uid] = {"tcp": tcp, "udp": None}
    states = states or {}
    monkeypatch.setattr(
        __import__("sys").modules["hst.path.gates.zpa"],
        "_segment_state",
        lambda session, uid: states.get(uid, "active"),
    )


def test_a_domain_two_segments_list_is_undecided_not_blocked_by_the_lower_uid(graph, monkeypatch):
    _shared_fqdn_graph(graph, monkeypatch)
    result = path.trace_from_identity(None, ZPA_IDENTITY, SHARED_FQDN, port=443, proto="tcp", gateways=[GW])
    assert result["indeterminate"]
    assert not any(leg.get("blocked") for leg in result["legs"])
    assert "zpa:seg:a" in result["verdict"] and "zpa:seg:b" in result["verdict"]
    assert not any(h["stage"] in ("ACCESS_RULE", "CONNECTOR") for h in result["hops"])


def test_a_disabled_segment_beside_an_active_one_for_the_domain_is_undecided(graph, monkeypatch):
    _shared_fqdn_graph(
        graph,
        monkeypatch,
        states={"zpa:seg:a": "disabled"},
        ports={"zpa:seg:a": ["443", "443"], "zpa:seg:b": ["443", "443"]},
    )
    result = path.trace_from_identity(None, ZPA_IDENTITY, SHARED_FQDN, port=443, proto="tcp", gateways=[GW])
    assert result["indeterminate"]
    assert "disabled" in result["verdict"] and "zpa:seg:b" in result["verdict"]


def test_a_domain_no_listing_segment_can_carry_is_blocked_naming_every_segment(graph, monkeypatch):
    _shared_fqdn_graph(graph, monkeypatch, states={"zpa:seg:b": "disabled"})
    result = path.trace_from_identity(None, ZPA_IDENTITY, SHARED_FQDN, port=443, proto="tcp", gateways=[GW])
    assert result["legs"] == [{"indeterminate": False, "blocked": True, "blocking_uid": "zpa:seg:a"}]
    assert "none of which carries this flow" in result["verdict"]
    assert "zpa:seg:a does not publish tcp/443" in result["verdict"]
    assert "zpa:seg:b: the segment or its segment group is disabled" in result["verdict"]


def test_brokered_every_connector_disabled_is_a_blocked_leg(graph):
    _zpa_allow_graph(graph)
    graph.zpa_connectors[ZPA_SEGMENT] = [_zpa_connector_row(enabled=False)]
    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])
    assert result["legs"] == [{"indeterminate": False, "blocked": True, "blocking_uid": ZPA_SEGMENT}]
    assert "disabled" in result["verdict"]


def test_brokered_bypass_forwarding_rule_is_not_brokered_and_names_the_rule(graph, monkeypatch):
    from hst.core.zpa_policy import forwarding_decision

    _zpa_allow_graph(graph)
    bypass = {"uid": "f:1", "name": "bypass-crm", "position": 1, "action": "bypass", "identity_named": True}
    monkeypatch.setattr(
        __import__("sys").modules["hst.path.trace"],
        "_forwarding_match",
        lambda session, identity, segment: forwarding_decision([bypass], identity, segment),
    )
    result = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])
    assert result["indeterminate"] and "bypass-crm" in result["verdict"]
    assert not any(h["stage"] == "ACCESS_RULE" for h in result["hops"])


def test_two_pbr_groups_on_a_device_at_depth_two_both_start_with_the_hops_before_it(graph):
    """Every later source group of a device starts on a new lane. That lane
    carries the hops of the devices before it and of this device's ingress,
    as the first group's lane does."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.0.20.0/24", egress="eth3", kind="ORIGINATES"),
            _route("10.9.9.0/24", egress="eth3", next_hop="10.0.20.1"),
        ]
    }
    graph.next_hop_devs["10.0.20.1"] = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
    }
    graph.default_tables["if:fw2-in"] = {"uid": "vrf:fw2"}
    graph.pbr_by_if["if:fw2-in"] = [
        {
            "pol_uid": "pol:fw2",
            "pol_name": "steer",
            "rule_uid": "rule:10",
            "pos": 10,
            "rule_name": None,
            "src_cidrs": [],
            "src_ips": [],
            "src_ranges": [],
            "dst_cidrs": ["10.9.9.0/25"],
            "dst_ips": [],
            "dst_ranges": [],
            "table_uid": "vrf:100",
            "table_name": "100",
        }
    ]
    graph.routes["vrf:100"] = [_route("0.0.0.0/0", egress="wg0")]
    graph.routes["vrf:fw2"] = [_route("10.9.9.0/24", egress="fw2-eth0", kind="ORIGINATES")]
    result = path.trace(None, "10.0.0.5", "10.9.9.0/24", gateways=[GW])
    lanes = sorted(
        {h["lane"] for h in result["hops"] if h["kind"] == "Interface" and h["label"] in ("wg0", "fw2-eth0")}
    )
    assert len(lanes) == 2, [(h["kind"], h["label"], h["lane"]) for h in result["hops"]]
    for lane in lanes:
        on_lane = {(h["kind"], h["label"]) for h in result["hops"] if h["lane"] == lane or h["shared"]}
        assert ("Device", "fw2") in on_lane, lane


def test_a_hop_carries_the_gate_flag_from_the_label_registry():
    from hst.path.gates import is_gate_kind

    assert is_gate_kind("ForwardingBoundary") and is_gate_kind("FwRulebase")
    # a NAT rule is evaluated as a translation, not a permit or a deny
    assert not is_gate_kind("NatRule")
    assert not is_gate_kind("Interface") and not is_gate_kind("NextHop")


# --- the reads a trace sends ----------------------------------------------------------------


def record_reads(graph):
    """Every read the fake answers from here on, in call order, as (query, params)."""
    calls: list[tuple[str, dict]] = []
    read, read_one = graph.read, graph.read_one

    def recorded_read(query, **params):
        calls.append((query, params))
        return read(query, **params)

    def recorded_read_one(query, **params):
        calls.append((query, params))
        return read_one(query, **params)

    graph.read, graph.read_one = recorded_read, recorded_read_one
    return calls


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def data(self):
        return self._rows


class _GraphTx:
    """One transaction on `_GraphSession`: the fake's list answer to a query,
    or its one-row answer when it has no list answer."""

    def __init__(self, graph):
        self.graph = graph

    def run(self, query, **params):
        rows = self.graph.read(query, **params)
        if not rows:
            row = self.graph.read_one(query, **params)
            rows = [row] if row else []
        return _Rows(rows)


class _GraphSession:
    """The session a `CycleSession` wraps, answering from a FakeGraph and
    counting every `execute_read` round trip."""

    def __init__(self, graph):
        self.graph = graph
        self.round_trips = 0

    def execute_read(self, work):
        self.round_trips += 1
        return work(_GraphTx(self.graph))


def test_a_second_trace_on_one_session_sends_no_reads():
    """The read cache of one pinned session answers every read of a repeated
    trace: the second run sends no round trip and gives the same answer."""
    inner = _GraphSession(_lb_beyond(FakeGraph()))
    session = path.CycleSession(inner, 42)

    first = path.trace(session, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])
    sent = inner.round_trips
    second = path.trace(session, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert sent > 0
    assert inner.round_trips == sent
    assert second == first
    assert [leg["verdict"] for leg in first["legs"]] == ["egress via fw2-eth0"]


def _two_member_pool(graph, **vs):
    _lb_beyond(graph)
    graph.vip[("10.0.30.10", GW["dev_uid"])] = _lb_vs(**vs)
    graph.pool_members[_lb_vs()["uid"]] = [
        _lb_member(),
        _lb_member(uid="ns:dc1-ns01:sg:web/10.0.10.6:8443", name="10.0.10.6:8443", ip="10.0.10.6"),
    ]


def test_a_pool_reads_the_snip_candidates_once_for_all_its_members(graph):
    """The SNIP read names the device only, and each member's subnet filters
    the same rows, so the second member does not read them again."""
    _two_member_pool(graph, snat_mode="snip")
    graph.snip_candidates[GW["dev_uid"]] = [
        {"ip": "10.0.10.1", "if_uid": "if:snip0", "if_name": "snip0", "cidr": "10.0.10.0/24"}
    ]
    reads = record_reads(graph)

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert [leg["snat"][0]["to"] for leg in result["legs"]] == ["10.0.10.1", "10.0.10.1"]
    assert [p for q, p in reads if "[e:IN]->(p:Prefix)" in q] == [{"dev": GW["dev_uid"]}]


def test_a_pool_reads_its_snat_from_address_once_for_all_its_members(graph):
    _two_member_pool(graph, snat_mode="snat_from")
    graph.snat_from[_lb_vs()["uid"]] = {"ip": "10.0.10.2"}
    reads = record_reads(graph)

    result = path.trace(None, "10.0.0.5", "10.0.30.10", port=443, proto="tcp", gateways=[GW])

    assert [leg["snat"][0]["to"] for leg in result["legs"]] == ["10.0.10.2", "10.0.10.2"]
    assert len([q for q, _p in reads if "SNAT_FROM]->(ip:IpAddress)" in q]) == 1


def test_an_interface_trunk_with_a_switch_port_skips_the_parent_trunk_read(graph):
    """The parent interface's trunk is read only when the interface's own
    trunk names no switch port."""
    trace_mod = import_module("hst.path.trace")
    graph.sources = [_l2_source()]
    _script_l2_trunk(graph)
    reads = record_reads(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert ("Port", "Uplink") in [(h["kind"], h["label"]) for h in result["hops"]]
    assert [q for q, _p in reads if q == trace_mod._TRUNK_BY_IF_UID_QUERY]
    assert not [q for q, _p in reads if q == trace_mod._TRUNK_BY_PARENT_NAME_QUERY]


def test_an_interface_trunk_with_no_switch_port_reads_the_parent_trunk(graph):
    trace_mod = import_module("hst.path.trace")
    graph.sources = [_l2_source()]
    _script_l2_trunk(graph, swp=None)
    reads = record_reads(graph)

    path.trace(None, "10.0.0.5", "8.8.8.8", gateways=[GW])

    assert [p for q, p in reads if q == trace_mod._TRUNK_BY_PARENT_NAME_QUERY] == [
        {"name": "eth1", "dev": GW["dev_uid"]}
    ]


def test_an_explicit_vsx_target_skips_the_owner_and_adjacency_reads(graph):
    """A target the VSX crossings walk hands down is the next hop already and
    one hop away by definition: no owner lookup, no adjacency evidence, and
    no table name read for a note that is never printed."""
    trace_mod = import_module("hst.path.trace")
    graph.default_tables["if:fw2-in"] = {"uid": "vrf:fw2"}
    graph.routes["vrf:fw2"] = [_route("10.9.0.0/24", egress="fw2-eth0", kind="ORIGINATES")]
    target = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
        "anchor": None,
    }
    route = {**_route("10.9.0.0/24", egress="eth3", next_hop="10.0.20.1"), "next_hop_vrf": "vrf:leak"}
    grp = {"table_uid": "vrf:main", "table_name": "main"}
    trail = path._Trail()
    reads = record_reads(graph)

    inner, _lane = trace_mod._next_hop_stage(
        None,
        trail,
        {"lane": 0, "indeterminate": False, "blocked": False},
        grp,
        GW,
        route,
        path._intervals(["10.9.0.5"]),
        path._intervals(["10.0.0.5"]),
        None,
        None,
        "10.0.0.5",
        0,
        None,
        0,
        frozenset({GW["dev_uid"]}),
        False,
        max_hops=8,
        _vsx_target=target,
    )

    assert inner and inner[0]["verdict"] == "egress via fw2-eth0"
    assert any(h["uid"] == "dev:fw2" for h in trail.hops)
    assert graph.next_hop_lookups == []
    assert not [
        p for q, p in reads if "ip.uid AS ip_uid, i.uid AS if_uid" in q and p.get("dev") == GW["dev_uid"]
    ]
    assert not [p for q, p in reads if "RETURN v.name AS n" in q and p.get("u") == "vrf:leak"]


def _two_service_rects(src, dst):
    """Two decided rectangles of one transparent part: tcp/443 and tcp/444."""
    return [
        rect
        for port in (443, 444)
        for rect in tracemod._query_region(path._intervals([src]), path._intervals([dst]), port, "tcp", None)
    ]


def test_each_vsx_crossing_rectangle_starts_from_its_own_part(graph, monkeypatch):
    """A field the walk of one rectangle writes into its leg stays on that
    leg: the next rectangle of the same part starts from the part again and
    is walked to the explicit next hop."""
    graph.default_tables["if:fw2-in"] = {"uid": "vrf:fw2"}
    graph.routes["vrf:fw2"] = [_route("10.9.0.0/24", egress="fw2-eth0", kind="ORIGINATES")]
    target = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
        "anchor": None,
    }
    route = _route("10.9.0.0/24", egress="eth3", next_hop="10.0.20.1")
    grp = {"table_uid": "vrf:main", "table_name": "main"}
    part = {"lane": 0, "indeterminate": False, "blocked": False, "src_label": "10.0.0.5"}
    monkeypatch.setattr(
        tracemod,
        "_transparent_parts",
        lambda *_a, **_k: [(part, _two_service_rects("10.0.0.5", "10.9.0.5"))],
    )
    walked = []
    real_stage = tracemod._next_hop_stage

    def first_rect_blocked(session, trail, leg, *args, **kwargs):
        if kwargs.get("_vsx_target") is not target:
            # the far device's own next-hop resolution
            return real_stage(session, trail, leg, *args, **kwargs)
        walked.append(leg)
        if len(walked) == 1:
            leg["blocked"] = True
            leg["verdict"] = "BLOCKED by fw2-policy rule 1"
            return None, args[8]
        return real_stage(session, trail, leg, *args, **kwargs)

    monkeypatch.setattr(tracemod, "_next_hop_stage", first_rect_blocked)

    legs, lane = tracemod._vsx_crossing_legs(
        None,
        path._Trail(),
        part,
        grp,
        GW,
        route,
        path._intervals(["10.9.0.5"]),
        path._intervals(["10.0.0.5"]),
        "443-444",
        "tcp",
        "10.0.0.5",
        0,
        None,
        0,
        frozenset({GW["dev_uid"]}),
        False,
        max_hops=8,
        conn_state="new",
        src_port=None,
        explicit_target=target,
        crossings=[({"uid": "if:br-in"}, {"uid": "if:br-out"})],
    )

    assert len(walked) == 2
    assert not walked[1].get("blocked")
    assert not part.get("blocked")
    assert [leg.get("blocked") for leg in legs] == [True, False]
    assert legs[1]["verdict"] == "egress via fw2-eth0"
    assert [leg["lane"] for leg in legs] == [0, 1]
    assert lane == 2


def test_a_blocked_reply_part_gets_one_leg_and_lane_per_rectangle(graph, monkeypatch):
    """A reply crossing a transparent gate that blocks a part over two
    rectangles answers with two legs, each its own object on its own lane
    and not delivered, the same form the forward walk gives."""
    blocked = {
        "lane": 0,
        "blocked": True,
        "indeterminate": False,
        "sources": ["10.9.0.5/32"],
        "src_label": "10.9.0.5",
        "verdict": "BLOCKED by bridge rule 1",
        "cidr": None,
        "egress": None,
        "next_hop": None,
    }
    monkeypatch.setattr(
        tracemod.vsx,
        "resolve",
        lambda *_a, **_k: (None, [({"uid": "if:br-in"}, {"uid": "if:br-out"})], None),
    )
    monkeypatch.setattr(
        tracemod,
        "_transparent_parts",
        lambda *_a, **_k: [(blocked, _two_service_rects("10.9.0.5", "10.0.0.5"))],
    )
    terminal = {
        "dev_uid": "dev:fw2",
        "dev_name": "fw2",
        "if_uid": "if:fw2-in",
        "if_name": "fw2-in",
        "attachment_uid": "port:fw2-in",
    }

    reply = tracemod._walk_reply_leg(
        None,
        {"sources": ["10.0.0.5/32"]},
        terminal,
        [],
        {},
        path._intervals(["10.0.0.5"]),
        path._intervals(["10.9.0.5"]),
        None,
        max_hops=8,
    )

    legs = reply["legs"]
    assert len(legs) == 2
    assert legs[0] is not legs[1]
    assert legs[0] is not blocked and legs[1] is not blocked
    assert [leg["lane"] for leg in legs] == [0, 1]
    assert [leg["delivered"] for leg in legs] == [False, False]
    assert all(leg["blocked"] for leg in legs)
    assert "2 of 2 blocked" in reply["verdict"]


# --- a permit that covers only part of a network-scoped query ----------------------------


def _partial_permit_rulebase(graph, chain="forward"):
    """Rule 1 accepts one host of the source /24; rule 2 drops the rest."""
    graph.sources = [_src_row()]
    graph.rb_by_chain = {
        chain: {
            "rb_uid": "rb:cp",
            "rb_name": "Network",
            "vendor": "vyos",
            "default_action": "accept",
            "approximate": False,
        }
    }
    graph.zone_rules = {
        "rb:cp": [
            _rule(uid="cp:r1", pos=1, src_any=False, src_cidrs=["10.0.0.5/32"]),
            _rule(uid="cp:r2", pos=2, action="drop"),
        ]
    }


def test_a_partial_permit_on_a_network_scoped_query_is_indeterminate(graph):
    _partial_permit_rulebase(graph)
    graph.routes = {"vrf:main": [_route("10.9.9.0/24", egress="eth2")]}

    result = path.trace(None, "10.0.0.0/24", "10.9.9.9", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert result["indeterminate"] and leg["indeterminate"]
    assert not leg["blocked"]
    assert "matches part of the range only" in leg["firewall"]
    assert "permits only part of the flow's address range" in leg["indeterminate_reason"]


def test_a_partial_permit_records_no_confirmed_permit_for_the_reply(graph):
    """The gate state a reply reads must not record a confirmed permit for a
    forward leg that was not one."""
    from hst.path.gates.firewall import _apply_firewall

    _partial_permit_rulebase(graph)
    leg: dict = {"lane": 0, "next_hop": None}

    outcome = _apply_firewall(
        None,
        path._Trail(),
        leg,
        GW,
        "if:eth2",
        path._intervals(["10.0.0.0/24"]),
        path._intervals(["10.9.9.9"]),
        443,
        "tcp",
        "10.0.0.0/24",
        "eth2",
    )

    assert outcome == path.INDETERMINATE
    assert leg["gate_state"]["dev:r1"]["permit"] is False


def test_a_partial_permit_on_a_ranged_query_is_indeterminate(graph):
    """The region renderer reads the partial flag the same way."""
    _partial_permit_rulebase(graph)
    graph.routes = {"vrf:main": [_route("10.9.9.0/24", egress="eth2")]}

    result = path.trace(None, "10.0.0.0/24", "10.9.9.9", port="440-450", proto="tcp", gateways=[GW])

    assert result["indeterminate"]
    assert all(leg["indeterminate"] and not leg["blocked"] for leg in result["legs"])


def test_a_partial_permit_on_a_router_local_flow_is_indeterminate(graph):
    _partial_permit_rulebase(graph, chain="input")
    graph.dev_addrs = {"dev:r1": [_own_addr("10.0.12.1")]}

    result = path.trace(None, "10.0.0.0/24", "10.0.12.1", port=22, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["router_local"] is True
    assert result["indeterminate"] and leg["indeterminate"] and not leg["blocked"]
    assert leg["firewall"] == "Network (input) accept by rule 1 (matches part of the range only)"
    assert any("covers only part of the flow" in w for w in result["warnings"])


def test_a_partial_deny_stays_a_deny():
    from hst.path.gates.firewall import _partial_permit

    leg: dict = {}
    fw = {"action": "drop", "partial": True, "rb_name": "Network"}
    assert _partial_permit(leg, fw, path.DENY, "rule 2") == path.DENY
    assert "indeterminate" not in leg


def _candidate(rb, action="accept", partial=False):
    return {"rb_uid": rb, "rb_name": rb, "action": action, "partial": partial}


def test_the_candidate_fold_keeps_a_partial_permit_that_sorts_second():
    from hst.path.gates.firewall import _both_rulebase_models, _fold_point, _pick_winner

    full, part = _candidate("Application"), _candidate("Network", partial=True)

    assert _fold_point([full, part]) is part
    assert _pick_winner(full, part) is part
    assert _both_rulebase_models(part, full, None)["rb_uid"] == "Network"
    deny = _candidate("Network", action="drop")
    assert _fold_point([part, deny]) is deny


def test_no_gateway_names_the_interfaces_held_by_devices_that_do_not_route(graph):
    """A routed-access switch whose role is not a gateway role holds the source
    prefix; the verdict names those interfaces, not an absent interface."""
    asked: list[dict] = []
    answer = graph.read

    def read(query, **params):
        if "MATCH (p:Prefix:Obj {kind: 'connected'})" in query:
            asked.append(params)
            return [{"dev": "ber1-swa-07", "role": "switch", "iface": "Vlan20"}]
        return answer(query, **params)

    graph.read = read
    graph.sources = [_src_row(ip="10.20.7.50")]

    result = path.trace(None, "10.20.7.50", "10.20.9.9", gateways=[])

    assert result["verdict"] == (
        "no gateway found for the source prefix; the interfaces recorded on it are on devices "
        "whose role is not a gateway role: ber1-swa-07 Vlan20 (role switch)"
    )
    assert asked and asked[0]["key"] and "router" in asked[0]["gateway_roles"]


def test_no_gateway_keeps_its_text_when_no_such_interface_is_recorded(graph):
    graph.sources = [_src_row(ip="10.20.7.50")]

    result = path.trace(None, "10.20.7.50", "10.20.9.9", gateways=[])

    assert result["verdict"] == (
        "no gateway found for the source prefix; no router, gateway or firewall interface is recorded on it"
    )


def _five_equal_cost_routes():
    return {
        "vrf:main": [_route("10.9.0.0/24", egress=f"eth{i}", next_hop=f"10.9.{i}.1") for i in range(2, 7)]
    }


def test_equal_cost_routes_past_the_lane_cap_are_named_and_the_legs_indeterminate(graph, monkeypatch):
    monkeypatch.setenv("PATH_LANE_CAP", "3")
    graph.sources = [_src_row()]
    graph.routes = _five_equal_cost_routes()

    result = path.trace(None, "10.0.0.5", "10.9.0.9", gateways=[GW])

    # the three routes that sort first are walked; the other two are named, never dropped
    assert [leg["egress"] for leg in result["legs"]] == ["eth2", "eth3", "eth4"]
    assert result["indeterminate"] is True
    assert all(leg["indeterminate"] for leg in result["legs"])
    reason = result["legs"][0]["indeterminate_reason"]
    assert reason.startswith("2 equal-cost next hops not walked (10.9.5.1, 10.9.6.1)")
    assert "path_lane_cap setting (3 lanes)" in reason
    assert any("path_lane_cap" in w for w in result["warnings"])


def test_equal_cost_routes_within_the_lane_cap_are_all_walked(graph):
    graph.sources = [_src_row()]
    graph.routes = _five_equal_cost_routes()

    result = path.trace(None, "10.0.0.5", "10.9.0.9", gateways=[GW])

    assert len(result["legs"]) == 5
    assert not any("path_lane_cap" in w for w in result["warnings"])


def test_the_hop_index_dedupes_as_the_scan_did():
    from hst.path.gates import Stage, _Trail

    trail = _Trail()
    trail.depth = 0
    trail.hop("a", "Device", "a", stage=Stage.DEVICE)
    trail.hop("a", "Device", "a", stage=Stage.DEVICE)
    trail.depth = 1
    trail.hop("a", "Device", "a", stage=Stage.DEVICE)  # a second crossing of one node at another depth
    trail.at(1)
    trail.hop("a", "Device", "a", stage=Stage.DEVICE)  # another lane
    assert [(h["uid"], h["lane"], h["_pos"][0]) for h in trail.hops] == [
        ("a", 0, 0),
        ("a", 0, 1),
        ("a", 1, 1),
    ]
    # replaying the upstream hops of lane 0 adds only the ones lane 1 does not hold at their own position
    tracemod._replay_upstream(trail, [dict(h) for h in trail.hops if h["lane"] == 0])
    assert sorted((h["lane"], h["_pos"][0]) for h in trail.hops if h["lane"] == 1) == [(1, 0), (1, 1)]
    tracemod._replay_upstream(trail, [dict(h) for h in trail.hops if h["lane"] == 0])
    assert len([h for h in trail.hops if h["lane"] == 1]) == 2
    # after ranking a hop is matched on uid and lane alone, at any depth
    trail.rank_hops()
    trail.depth = 5
    trail.hop("a", "Device", "a", stage=Stage.DEVICE)
    assert len(trail.hops) == 4


def test_the_hop_index_keeps_a_trace_of_400_lanes_linear():
    from tests.support.cputime import cpu_time

    from hst.path.gates import Stage, _Trail

    trail = _Trail()
    with cpu_time() as spent:
        for lane in range(400):
            trail.at(lane)
            for depth in range(40):
                trail.depth = depth
                trail.hop(f"dev:{depth}", "Device", "d", stage=Stage.DEVICE)
    assert len(trail.hops) == 400 * 40
    assert spent.seconds < 2.0


def _two_stage_fabric(graph):
    """r1 forks two ways, each next hop forks two ways again: four lanes without a cap."""
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("10.9.0.0/24", egress="eth2", next_hop="10.0.20.1"),
            _route("10.9.0.0/24", egress="eth3", next_hop="10.0.21.1"),
        ]
    }
    for name, addr in (("r2a", "10.0.20.1"), ("r2b", "10.0.21.1")):
        graph.next_hop_devs[addr] = {
            "dev_uid": f"dev:{name}",
            "dev_name": name,
            "if_uid": f"if:{name}-in",
            "if_name": f"{name}-in",
        }
        graph.default_tables[f"if:{name}-in"] = {"uid": f"vrf:{name}"}
        graph.routes[f"vrf:{name}"] = [
            _route("10.9.0.0/24", egress=f"{name}-e{i}", next_hop=f"10.8.{i}.1") for i in (0, 1)
        ]


def test_the_lane_budget_is_one_for_the_whole_trace_not_one_per_fork(graph, monkeypatch):
    _two_stage_fabric(graph)
    assert len(path.trace(None, "10.0.0.5", "10.9.0.9", gateways=[GW])["legs"]) == 4

    monkeypatch.setenv("PATH_LANE_CAP", "3")
    result = path.trace(None, "10.0.0.5", "10.9.0.9", gateways=[GW])

    assert len(result["legs"]) == 3
    assert all(leg["indeterminate"] for leg in result["legs"][-1:])
    assert any("1 equal-cost next hops not walked" in w for w in result["warnings"])


def _reconverging_fabric(graph, width=2, stages=3):
    """r1 forks over `width` equal-cost next hops, and every device of a stage
    routes the destination over the same `width` next hops of the stage after
    it, on one shared segment, so every lane into a device enters it on the
    same interface. The last stage delivers on a connected route."""
    graph.sources = [_src_row()]

    def hops_to(k):
        return [_route("10.9.0.0/24", egress=f"to{k}", next_hop=f"10.{k}.0.{i + 1}") for i in range(width)]

    graph.routes = {"vrf:main": hops_to(1)}
    for k in range(1, stages + 1):
        for i in range(width):
            name = f"s{k}{chr(97 + i)}"
            graph.next_hop_devs[f"10.{k}.0.{i + 1}"] = {
                "dev_uid": f"dev:{name}",
                "dev_name": name,
                "if_uid": f"if:{name}-in",
                "if_name": f"{name}-in",
            }
            graph.default_tables[f"if:{name}-in"] = {"uid": f"vrf:{name}"}
            graph.routes[f"vrf:{name}"] = (
                hops_to(k + 1) if k < stages else [_route("10.9.0.0/24", egress=f"{name}-lan")]
            )


def _device_walks(monkeypatch):
    """The devices `_walk_device` walks, in order."""
    walked: list[str] = []
    real = tracemod._walk_device

    def spy(ctx, gw, *args, **kwargs):
        walked.append(gw["dev_uid"])
        return real(ctx, gw, *args, **kwargs)

    monkeypatch.setattr(tracemod, "_walk_device", spy)
    return walked


def _without_reuse(monkeypatch):
    from hst.path import walk_memo

    monkeypatch.setattr(walk_memo, "walk", lambda trail, gw, flow, depth, cs, visited, lane, run: run())


def test_reconverging_lanes_walk_each_device_once_and_answer_as_the_repeated_walks(graph, monkeypatch):
    _reconverging_fabric(graph)
    walked = _device_walks(monkeypatch)
    reused = path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])
    assert len(reused["legs"]) == 8
    assert sorted(walked) == sorted(["dev:r1", *(f"dev:s{k}{c}" for k in (1, 2, 3) for c in "ab")])

    walked.clear()
    _without_reuse(monkeypatch)
    repeated = path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])
    assert len(walked) == 1 + 2 + 4 + 8
    assert reused == repeated


@pytest.mark.parametrize(
    "options", [{"port": 443, "proto": "tcp", "reply": True}, {"port": "440-450", "proto": "tcp"}]
)
def test_a_reply_and_a_service_range_answer_as_the_repeated_walks_did(graph, monkeypatch, options):
    _reconverging_fabric(graph, width=3)
    reused = path.trace(None, "10.0.0.5", "10.9.0.9", gateways=[GW], **options)
    _without_reuse(monkeypatch)
    assert reused == path.trace(None, "10.0.0.5", "10.9.0.9", gateways=[GW], **options)


def test_a_lane_cap_that_cuts_the_fabric_answers_as_the_repeated_walks_did(graph, monkeypatch):
    """A copy spends the lanes the walk spent; where the budget left has no
    room for them, the device is walked, so the cap cuts the same lanes."""
    _reconverging_fabric(graph)
    monkeypatch.setenv("PATH_LANE_CAP", "5")
    reused = path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])
    assert len(reused["legs"]) == 5
    _without_reuse(monkeypatch)
    assert reused == path.trace(None, "10.0.0.5", "10.9.0.9", port=443, proto="tcp", gateways=[GW])


def _enter(trail, lane):
    """Put the trail on `lane` at the far device's depth, its arrival drawn."""
    from hst.path.gates import Stage

    trail.at(lane)
    trail.depth = 1
    trail.hop("if:x-in", "Interface", "x-in", stage=Stage.INGRESS_IF)


def _counted_walk(trail, calls, probe=None):
    from hst.path.gates import Stage

    def run():
        calls.append(trail.lane)
        if probe:
            trail.probe_visit(probe)
        trail.hop("dev:x", "Device", "x", stage=Stage.DEVICE)
        return [{"lane": trail.lane, "verdict": "egress via x-lan", "gate_state": {}}], trail.lane + 1

    return run


def test_a_lane_whose_gate_state_differs_walks_the_device_itself():
    """The key holds the gate state a walk reads (`device_gate_state`), so a
    lane reading another one never takes over the recorded walk; one reading
    the same takes it over, onto its own lane."""
    from hst.path import walk_memo
    from hst.path.gates import _Trail

    trail, calls = _Trail(), []
    gw = {"dev_uid": "dev:x", "if_uid": "if:x-in"}
    flow = ((), (), 443, "tcp", None)
    for lane in (1, 2):
        _enter(trail, lane)
        legs, next_lane = walk_memo.walk(
            trail, gw, flow, 1, "new", frozenset(), lane, _counted_walk(trail, calls)
        )
        assert legs[0]["lane"] == lane and next_lane == lane + 1
    assert calls == [1]
    assert [h["lane"] for h in trail.hops if h["uid"] == "dev:x"] == [1, 2]

    trail.device_gate_state = {"dev:x": {"policy": ["established=accept"], "permit": True}}
    _enter(trail, 3)
    walk_memo.walk(trail, gw, flow, 1, "new", frozenset(), 3, _counted_walk(trail, calls))
    assert calls == [1, 3]


def test_a_lane_whose_visited_set_answers_a_loop_check_otherwise_walks_the_device_itself():
    """The visited set is compared on the visits the walk tested only: a lane
    that visited other devices takes the walk over, one that visited the
    device the walk's loop check names walks it."""
    from hst.path import walk_memo
    from hst.path.gates import _Trail

    trail, calls = _Trail(), []
    gw = {"dev_uid": "dev:x", "if_uid": "if:x-in"}
    for lane, visited in ((1, {"dev:r1"}), (2, {"dev:q"}), (3, {"dev:y|vrf:y"})):
        _enter(trail, lane)
        walk_memo.walk(
            trail, gw, ((),), 1, "new", frozenset(visited), lane, _counted_walk(trail, calls, "dev:y|vrf:y")
        )
    assert calls == [1, 3]
