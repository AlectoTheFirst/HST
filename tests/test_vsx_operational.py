"""VSX operational reads over synthetic captures."""

import asyncio
import importlib

from tests.enterprise.test_checkpoint_gateway_integration import _config
from tests.test_path_nat import _nat_row

from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.checkpoint_gateway import CpGatewayCollector, normalize_checkpoint_gateway
from hst.collectors.checkpoint_operational import cluster_state, installed_policy, virtual_devices
from hst.path.gates import _Trail
from hst.path.gates.nat import _nat_stage_rules, _nat_step

trace = importlib.import_module("hst.path.trace")


def capture(kind="S"):
    return {
        "vsx stat -v": f"7 | {kind} customer | policy | 12Sep2026 | Trust",
        "contexts": {
            "7": {
                "vsid": 7,
                "interfaces": [
                    {"ifname": "eth1", "address": "00:11:22:33:44:55", "operstate": "UP", "flags": ["UP"]},
                    {"ifname": "eth1.100", "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]},
                ],
                "links": [
                    {"ifindex": 2, "ifname": "eth1", "link_type": "ether", "address": "00:11:22:33:44:55"},
                    {
                        "ifindex": 3,
                        "ifname": "eth1.100",
                        "link_index": 2,
                        "linkinfo": {"info_kind": "vlan", "info_data": {"id": 100}},
                    },
                ],
                "routes4": [
                    {"dst": "203.0.113.0/24", "gateway": "192.0.2.2", "dev": "eth1.100", "protocol": "bgp"}
                ],
                "routes6": [],
                "neighbors": [
                    {
                        "dst": "192.0.2.2",
                        "dev": "eth1.100",
                        "lladdr": "00:aa:bb:cc:dd:ee",
                        "state": ["STALE"],
                    },
                    {
                        "dst": "2001:db8::2",
                        "dev": "eth1.100",
                        "lladdr": "00:aa:bb:cc:dd:ee",
                        "state": ["REACHABLE"],
                    },
                    {"dst": "192.0.2.3", "dev": "eth1.100", "state": ["INCOMPLETE"]},
                ],
                "bgp_as": "65001",
                "bgp_peers": "Peer AS MsgRcvd MsgSent State\n192.0.2.2 65002 10 10 Established",
                "cluster": "Cluster Mode: High Availability\n1 (local) 10.0.0.1 100% ACTIVE member-a",
                "installation": "HOST IF POLICY DATE\nlocalhost <eth1.100 customer 12Sep2026 10:20:30 :",
            }
        },
    }


def test_member_observations_do_not_merge_interfaces_routes_or_neighbors():
    first = _config()
    second = first.model_copy(update={"appliance_uid": "member-b", "host": "gaia-b"})
    a = normalize_checkpoint_gateway(capture(), first)
    b = normalize_checkpoint_gateway(capture(), second)
    for label in ("Interface", "VrfInstance", "Port", "Endpoint", "BgpSession"):
        assert {n.uid for n in a.nodes if n.label == label}.isdisjoint(
            {n.uid for n in b.nodes if n.label == label}
        )
    assert {n.uid for n in a.nodes if n.label == "FirewallInstance"} == {
        n.uid for n in b.nodes if n.label == "FirewallInstance"
    }
    ca, cb = CpGatewayCollector(first, None), CpGatewayCollector(second, None)
    assert (
        ca.side_tables(capture())["rib"][0]["context_uid"]
        != cb.side_tables(capture())["rib"][0]["context_uid"]
    )


def test_collected_vlan_realization_bgp_and_arp_share_the_same_context():
    config = _config()
    collector = CpGatewayCollector(config, None)
    batch = collector.normalize(capture())
    batch.validate_registry()
    tables = collector.side_tables(capture())
    assert {r["af"] for r in tables["arp"]} == {4, 6}
    assert len(tables["arp"]) == 2
    assert {r["context_uid"] for r in tables["arp"]} == {tables["rib"][0]["context_uid"]}
    assert tables["rib"][0]["protocol"] == "bgp"
    assert {"REALIZED_BY", "BOUND_TO", "CARRIES"} <= {r.rel_type for r in batch.rels}
    peer = next(n for n in batch.nodes if n.label == "BgpSession")
    assert peer.props["context_uid"] == tables["rib"][0]["context_uid"]
    assert peer.props["local_asn"] == 65001 and peer.props["peer_asn"] == 65002
    assert peer.props["state"] == "established"
    assert batch.sections["installation"].status == "unknown"
    assert batch.sections["bgp"].status == "partial"
    assert any(n.props.get("installed_policy_in") == "customer" for n in batch.nodes)


def test_virtual_switch_and_bridge_do_not_become_routed_gateways():
    for kind in ("W", "B"):
        collector = CpGatewayCollector(_config(), None)
        batch = collector.normalize(capture(kind))
        assert not [r for r in batch.rels if r.rel_type in {"GATEWAY_FOR", "LEARNED_ROUTE"}]
        assert collector.side_tables(capture(kind))["rib"] == []
        if kind == "W":
            assert not [n for n in batch.nodes if n.label == "FirewallInstance"]


def test_empty_failed_discovery_cannot_report_complete_tables():
    collector = CpGatewayCollector(_config(), None)
    raw = {"contexts": {}, "_outcomes": {"vsx stat -v": {"status": "failed"}}}
    batch = collector.normalize(raw)
    assert batch.sections["interfaces"].status == "failed"
    assert batch.sections["routes"].status == "failed"
    assert collector.table_outcomes(raw)["rib"].status == "partial"
    assert collector.table_outcomes(raw)["arp"].status == "partial"


def test_device_types_and_local_member_state_are_not_flattened():
    devices = virtual_devices(
        "1 | S routed | p | d\n2 | B bridged | p | d\n3 | R router | p | d\n4 | W sw | p | d"
    )
    assert [d["kind"] for d in devices.values()] == [
        "virtual-system",
        "bridge",
        "virtual-router",
        "virtual-switch",
    ]
    assert cluster_state("1 10.0.0.1 100% ACTIVE a\n2 (local) 10.0.0.2 0% STANDBY b") == "standby"
    assert cluster_state("1 (local) 10.0.0.1 100% ACTIVE(!) a") == "unknown"
    assert installed_policy("Policy installed") == []


def test_egress_lookup_binds_the_selected_table(monkeypatch):
    calls = []

    def read(_session, query, **params):
        calls.append(params)
        return {"uid": "vs7-out", "name": "eth1"} if params["vrf"] == "vs7-table" else None

    monkeypatch.setattr(trace._path, "_read_one", read)
    route = {"egress_uid": None, "egress_name": "eth1", "ifname": "eth1", "uid": None}
    result, _, _, _ = trace._resolve_route_egress(
        None, _Trail(), route, {"dev_uid": "member-a", "if_uid": "vs7-in"}, "source", "vs7-table"
    )
    assert result["egress_uid"] == "vs7-out"
    assert calls == [{"name": "eth1", "dev": "member-a", "vrf": "vs7-table"}]


def test_hide_nat_does_not_turn_original_or_unresolved_objects_into_masquerade():
    original = _nat_row(method="hide", xlate_src_original=True)
    rules = _nat_stage_rules([original], "snat", "eth1")
    assert rules[0]["exclude"] and not rules[0]["masquerade"]
    unresolved = _nat_row(method="hide", xlate_src_present=True, xlate_src_addrs=[])
    rules = _nat_stage_rules([unresolved], "snat", "eth1")
    assert rules[0]["opaque"] and not rules[0]["masquerade"]


def test_nat_observation_keeps_the_vs_context():
    step = _nat_step(
        "member-a", "snat", {"sources": [], "dst": [], "new_src": [], "new_dst": []}, context_uid="vs7-table"
    )
    assert step["context_uid"] == "vs7-table"


def test_malformed_json_and_failed_neighbor_capture_stay_incomplete():
    class Session:
        async def run(self, command):
            if command == "vsx stat -v":
                return "7 | S customer | p | d"
            if "neigh show" in command:
                raise RuntimeError("permission denied")
            if "ip " in command:
                return "{}"
            return ""

    collector = CpGatewayCollector(_config(), None)
    raw = asyncio.run(collector._afetch_over(Session()))
    assert raw[RAW_OUTCOMES_KEY]["vs:7:interfaces"]["status"] == "failed"
    assert raw[RAW_OUTCOMES_KEY]["vs:7:neighbors4"]["status"] == "unauthorized"
    assert collector.table_outcomes(raw)["arp"].status == "partial"


def test_reply_gateway_preserves_virtual_system_identity():
    terminal = {
        "dev_uid": "member-a",
        "dev_name": "vsx",
        "if_uid": "vs7-out",
        "if_name": "eth1",
        "firewall_instance_uid": "vs7",
        "vsid": 7,
        "vsx_kind": "virtual-system",
        "context_uid": "member-a-vs7",
    }
    gateway = trace._reply_gw(terminal)
    assert gateway["firewall_instance_uid"] == "vs7"
    assert trace._forwarding_visit(gateway) != trace._forwarding_visit(
        dict(gateway, firewall_instance_uid="vs8")
    )


def test_upstream_virtual_system_session_decisions_survive_leg_merge():
    upstream = {"gate_state": {"member-a|vs7": {"permit": True}}, "indeterminate": False}
    downstream = {"gate_state": {"member-a|vs8": {"permit": False}}, "indeterminate": False}
    trace._merge_upstream_leg(downstream, upstream)
    assert downstream["gate_state"] == {
        "member-a|vs7": {"permit": True},
        "member-a|vs8": {"permit": False},
    }


def test_hide_interface_lookup_requires_unique_same_family_address():
    from hst.path.gates.nat import _NAT_IFACE_ADDR_QUERY

    assert "$af = 4" in _NAT_IFACE_ADDR_QUERY and "$af = 6" in _NAT_IFACE_ADDR_QUERY
    assert "size(addresses) = 1" in _NAT_IFACE_ADDR_QUERY
    assert "LIMIT 1" not in _NAT_IFACE_ADDR_QUERY


def test_vsls_next_hop_requires_one_active_member_even_after_context_narrowing(monkeypatch):
    from hst.path.gates import routing

    base = {
        "if_name": "eth1",
        "dev_name": "vsx",
        "l3dom": "vs7",
        "vsx_cluster": True,
        "firewall_instance_uid": "vs7",
        "vsid": 7,
        "vsx_kind": "virtual-system",
    }
    a = dict(base, dev_uid="member-a", if_uid="a:if", anchor="a:vrf", vsx_state="active")
    b = dict(base, dev_uid="member-b", if_uid="b:if", anchor="b:vrf", vsx_state="standby")
    rows = [a, b]
    monkeypatch.setattr(
        routing._path, "_read", lambda _s, q, **kw: rows if q == routing._NEXT_HOP_DEVICE_QUERY else []
    )
    winner, why = routing._next_hop_device(None, "192.0.2.1", "a:vrf", a)
    assert winner["dev_uid"] == "member-a" and why is None
    b["vsx_state"] = "active"
    winner, why = routing._next_hop_device(None, "192.0.2.1", "a:vrf", a)
    assert winner is None and why
    a["vsx_state"] = b["vsx_state"] = "unknown"
    winner, why = routing._next_hop_device(None, "192.0.2.1", "a:vrf", a)
    assert winner is None and why


def test_missing_vs_policy_is_not_a_confirmed_permit(monkeypatch):
    from hst.path.gates import firewall

    monkeypatch.setattr(firewall, "_firewall_verdict", lambda *a, **kw: None)
    trail = _Trail()
    leg = {"indeterminate": False}
    gateway = {
        "dev_uid": "member-a",
        "dev_name": "vsx",
        "if_uid": "vs7-in",
        "firewall_instance_uid": "vs7",
        "vsid": 7,
        "vsx_kind": "virtual-system",
    }
    result = firewall._apply_firewall(
        None, trail, leg, gateway, "vs7-out", [], [], 443, "tcp", "source", "eth1"
    )
    assert result == "indeterminate"
    assert leg["indeterminate"]
    assert leg["gate_state"]["member-a|vs7"]["permit"] is False
