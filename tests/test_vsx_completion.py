"""VSX completion: explicit evidence, partitions and vendor policies."""

import importlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from tests.enterprise.test_checkpoint_gateway_integration import _config
from tests.test_path_trace import _rule, graph  # noqa: F401
from tests.test_vsx_operational import capture

from hst import path
from hst.collectors.checkpoint_bgp import peers
from hst.collectors.checkpoint_evidence import Session, installations_for, read_evidence
from hst.collectors.checkpoint_gateway import normalize_checkpoint_gateway
from hst.path import reply_nat, vsx
from hst.simul.compile import compile_policies
from hst.simul.errors import ErrorSink
from hst.simul.policy import Environment, call
from hst.simul.route import Route

trace = importlib.import_module("hst.path.trace")


def envelope(**kw):
    return {"version": 1, "appliance_uid": "member-a", "observation_uid": "snapshot-a", **kw}


def topology_capture():
    return {
        "contexts": {
            "7": {
                "vsid": 7,
                "kind": "virtual-system",
                "interfaces": [{"ifname": "wrp10"}],
                "links": [{"ifname": "wrp10"}],
            },
            "8": {
                "vsid": 8,
                "kind": "virtual-switch",
                "interfaces": [{"ifname": "wrpj10"}, {"ifname": "eth1"}],
                "links": [{"ifname": "wrpj10"}, {"ifname": "eth1", "link_type": "ether"}],
            },
        }
    }


def pair(a=7, b=8):
    return {
        "a": {"vsid": a, "interface": "wrp10"},
        "b": {"vsid": b, "interface": "wrpj10"},
        "evidence_uid": "mgmt-export:10",
    }


def test_warp_suffix_never_connects_without_evidence():
    batch = normalize_checkpoint_gateway(topology_capture(), _config())
    assert not [r for r in batch.rels if r.props.get("source") == "vsx-warp"]
    assert batch.sections["topology"].status == "partial"


def test_explicit_warp_and_virtual_switch_membership_survive_normalization():
    raw = topology_capture()
    raw["vsx_evidence"] = envelope(warp_links=[pair()])
    batch = normalize_checkpoint_gateway(raw, _config())
    batch.validate_registry()
    warp = [r for r in batch.rels if r.props.get("source") == "vsx-warp"]
    bridges = [r for r in batch.rels if r.rel_type == "BRIDGED_TO"]
    assert len(warp) == len(bridges) == 1
    assert warp[0].props["evidence_uid"] == "mgmt-export:10"
    assert bridges[0].props["policy_required"] is False
    assert all(n.props.get("vsx_topology_complete") for n in batch.nodes if n.props.get("kind") == "warp")


def test_reciprocal_netlink_names_connect_once():
    raw = topology_capture()
    raw["contexts"]["7"]["links"][0]["link"] = "wrpj10"
    raw["contexts"]["8"]["links"][0]["link"] = "wrp10"
    batch = normalize_checkpoint_gateway(raw, _config())
    assert len([r for r in batch.rels if r.props.get("source") == "vsx-warp"]) == 1


def test_bridge_membership_and_contradictions():
    raw = topology_capture()
    raw["contexts"]["8"]["kind"] = "bridge"
    raw["contexts"]["8"]["bridge_members"] = (
        "bridge name bridge id STP enabled interfaces\nbr0 8000.001122334455 no wrpj10\n\teth1\n"
    )
    batch = normalize_checkpoint_gateway(raw, _config())
    assert any(r.rel_type == "BRIDGED_TO" and r.props["policy_required"] for r in batch.rels)
    raw["vsx_evidence"] = envelope(
        bridge_groups=[
            {"vsid": 8, "name": "br0", "interfaces": ["eth1", "missing"], "evidence_uid": "conflict"}
        ]
    )
    batch = normalize_checkpoint_gateway(raw, _config())
    assert not [r for r in batch.rels if r.rel_type == "BRIDGED_TO"]
    assert "conflicting" in batch.sections["topology"].detail


def test_evidence_is_bound_to_appliance_and_observation(tmp_path):
    file = tmp_path / "vsx.json"
    file.write_text(json.dumps(envelope()))
    assert read_evidence(str(file), "member-a", "snapshot-a")["sha256"]
    with pytest.raises(ValueError, match="another appliance"):
        read_evidence(str(file), "member-b", "snapshot-a")


def installation(**kw):
    return {
        "vsid": 7,
        "gateway_object_uid": "vs-object-7",
        "authority": "manager",
        "rulebase_uid": "rb:1",
        "configured_revision": "r1",
        "installed_revision": "r1",
        "complete": True,
        "policy_name": "customer",
        "installed_at_raw": "12Sep2026 10:20:30",
        "evidence_uid": "install:1",
        "address_family": 4,
        "ingress_interface": "eth1",
        "egress_interface": "*",
        **kw,
    }


@pytest.mark.parametrize(
    "changes,complete", [({}, True), ({"complete": False}, False), ({"installed_revision": "r0"}, False)]
)
def test_installed_revision_is_correlated_with_observation_and_coverage(changes, complete):
    results, gaps = installations_for(
        envelope(installations=[installation(**changes)]),
        vsid=7,
        authority="manager",
        gateway="vs-object-7",
        observed=[{"policy_name": "customer", "installed_at_raw": "12Sep2026 10:20:30"}],
        interfaces={"eth1": "if:vs7:eth1"},
    )
    assert results[0]["complete"] is complete
    assert results[0]["ingress_interface_uid"] == "if:vs7:eth1"
    assert bool(gaps) is not complete


def test_wrong_management_target_never_creates_installation():
    rows, gaps = installations_for(
        envelope(installations=[installation()]),
        vsid=7,
        authority="wrong",
        gateway="vs-object-7",
        observed=[],
        interfaces={},
    )
    assert rows == [] and gaps


def session_record(**kw):
    now = datetime.now(UTC)
    return {
        "vsid": 7,
        "binding_uid": "conn:1",
        "protocol": "tcp",
        "evidence_uid": "runtime:1",
        "observed_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
        "original_source": "10.0.0.5",
        "original_destination": "203.0.113.8",
        "translated_source": "192.0.2.1",
        "translated_destination": "203.0.113.8",
        "original_source_port": 50123,
        "original_destination_port": 443,
        "translated_source_port": 62001,
        "translated_destination_port": 443,
        **kw,
    }


def test_runtime_evidence_retains_pat_ports_and_rejects_expired_rows():
    raw = capture()
    raw["vsx_evidence"] = envelope(sessions=[session_record()])
    batch = normalize_checkpoint_gateway(raw, _config())
    node = next(n for n in batch.nodes if n.label == "VrfInstance")
    assert json.loads(node.props["vsx_runtime_sessions"])[0]["translated_source_port"] == 62001
    raw["vsx_evidence"]["sessions"][0] = session_record(
        observed_at=(datetime.now(UTC) - timedelta(hours=2)).isoformat(),
        expires_at=(datetime.now(UTC) - timedelta(hours=1)).isoformat(),
    )
    batch = normalize_checkpoint_gateway(raw, _config())
    assert next(n for n in batch.nodes if n.label == "VrfInstance").props["vsx_runtime_sessions"] == "[]"
    with pytest.raises(ValueError, match="mixed address"):
        Session.model_validate(session_record(translated_source="2001:db8::1"))


def step(pre, translated, direction="snat", **kw):
    return {
        "device": "dev:cp",
        "context_uid": "vrf:vs7",
        "direction": direction,
        "pre": {"src": [pre], "dst": ["203.0.113.8"]},
        "post": {"src": [translated], "dst": ["203.0.113.8"]},
        **kw,
    }


def test_return_nat_maps_subranges_and_preserves_untranslated_clients():
    chain = [step("10.0.0.0/24", "192.0.2.0/24")]
    result, used = reply_nat.undo(
        chain,
        device="dev:cp",
        context="vrf:vs7",
        stage="ingress",
        addresses=path._intervals(["192.0.2.128/25", "198.51.100.1"]),
    )
    assert result == path._intervals(["10.0.0.128/25", "198.51.100.1"])
    assert used == [0]
    assert reply_nat.valid_chain(chain) and not reply_nat.point_chain(chain)


def test_return_nat_parallel_partitions_do_not_feed_each_other():
    chain = [step("10.0.0.1", "10.0.0.2"), step("10.0.0.2", "10.0.0.3")]
    src, dst = reply_nat.wire_reply(
        chain, path._intervals(["10.0.0.1", "10.0.0.2"]), path._intervals(["203.0.113.8"])
    )
    assert dst == path._intervals(["10.0.0.2", "10.0.0.3"])
    restored, indices = reply_nat.undo(
        chain, device="dev:cp", context="vrf:vs7", stage="ingress", addresses=dst
    )
    assert restored == path._intervals(["10.0.0.1", "10.0.0.2"]) and len(indices) == 2
    assert src == path._intervals(["203.0.113.8"])


def test_load_balancer_inverse_runs_at_both_stages_only_in_own_context():
    chain = [step("10.0.0.5", "192.0.2.1", "lb", post={"src": ["192.0.2.1"], "dst": ["10.1.0.5"]})]
    assert reply_nat.valid_chain(chain)
    unchanged, used = reply_nat.undo(
        chain, device="dev:cp", context="vrf:vs8", stage="ingress", addresses=path._intervals(["192.0.2.1"])
    )
    assert not used and unchanged == path._intervals(["192.0.2.1"])
    restored, _ = reply_nat.undo(
        chain, device="dev:cp", context="vrf:vs7", stage="egress", addresses=path._intervals(["10.1.0.5"])
    )
    assert restored == path._intervals(["203.0.113.8"])


def test_gaia_config_binding_order_family_and_disable():
    rows, gaps = peers(
        "\n".join(
            [
                "set bgp external remote-as 65002 export-routemap base preference 20 on",
                "set bgp external remote-as 65002 peer 192.0.2.2 on",
                "set bgp external remote-as 65002 peer 192.0.2.2 "
                "export-routemap v6 preference 10 family inet6 on",
                "set bgp external remote-as 65002 peer 192.0.2.2 export-routemap base off",
            ]
        ),
        65001,
    )
    assert not gaps
    assert rows["192.0.2.2"]["bindings"] == [("out", 10, "v6", (6,))]


def test_normalized_gaia_route_map_compiles_with_peer_as_and_family():
    raw = capture()
    value = raw["contexts"]["7"]
    value["bgp_config"] = (
        "set bgp external remote-as 65002 peer 192.0.2.2 export-routemap out preference 10 on"
    )
    value["bgp_routemaps"] = "\n".join(
        [
            "set routemap out id 10 on",
            "set routemap out id 10 allow",
            "set routemap out id 10 match as 65002 on",
            "set routemap out id 10 match protocol static",
            "set routemap out id 10 action localpref 150",
        ]
    )
    batch = normalize_checkpoint_gateway(raw, _config())
    nodes = {n.uid: n for n in batch.nodes}
    policies = [
        {
            **n.props,
            "entries": [
                nodes[r.end_uid].props
                for r in batch.rels
                if r.start_uid == n.uid and r.rel_type == "HAS_RULE"
            ],
        }
        for n in batch.nodes
        if n.label == "RoutePolicy"
    ]
    errors = ErrorSink()
    compiled, _ = compile_policies(policies, "checkpoint-gaia", errors)
    for prefix, peer, accepted in [
        ("10.0.0.0/24", 65002, True),
        ("10.0.0.0/24", 65003, False),
        ("2001:db8::/64", 65002, False),
    ]:
        route = Route(prefix, src_protocol="static", as_path=(65003,))
        env = Environment(route, route, policies=compiled, peer_as=peer)
        assert call(compiled["192.0.2.2:out"], env).boolean_value is accepted
        if accepted:
            assert env.output_route.local_pref == 150
    assert not errors.errors


def test_bridge_range_keeps_permitted_and_denied_partitions_separate(graph):  # noqa: F811
    graph.rb = {
        "rb_uid": "rb:bridge",
        "rb_name": "bridge",
        "vendor": "checkpoint",
        "default_action": "drop",
        "approximate": False,
    }
    graph.rules = [_rule(svc_any=False, protos=["tcp"], ports=["443"])]
    ingress = {
        "uid": "if:in",
        "name": "in",
        "device": "dev:bridge",
        "instance": "fi:bridge",
        "kind": "bridge",
        "vsid": 9,
    }
    egress = {**ingress, "uid": "if:out", "name": "out"}
    parts = trace._transparent_parts(
        None,
        path._Trail(),
        [(ingress, egress)],
        {"blocked": False, "src_label": "client"},
        trace._query_region(
            path._intervals(["10.0.0.5"]), path._intervals(["10.1.0.5"]), "443-444", "tcp", None
        ),
    )
    assert len(parts) == 2
    assert sorted(bool(leg.get("blocked")) for leg, _ in parts) == [False, True]
    assert {rect.dport for _, region in parts for rect in region} == {((0, 443, 443),), ((0, 444, 444),)}


def inventory(*batches, extra=()):
    from hst.analysis_model.graph import GraphInventory
    from hst.analysis_model.read import MaterializedTable

    nodes = {n.uid: {"id": n.uid, "labels": [n.label], "props": n.props} for b in batches for n in b.nodes}
    rels = [
        {
            "id": f"rel:{i}",
            "kind": r.rel_type,
            "start": r.start_uid,
            "end": r.end_uid,
            "props": {**r.key, **r.props},
        }
        for i, r in enumerate([r for b in batches for r in b.rels])
    ]
    rels.extend(extra)
    return GraphInventory.from_tables(
        MaterializedTable("a" * 64, "nodes", tuple(nodes.values()), len(nodes), True, "b" * 64),
        MaterializedTable("a" * 64, "relationships", tuple(rels), len(rels), True, "c" * 64),
    )


def test_normalized_nxos_vsx_iosxe_context_path_in_both_directions():
    from tests import test_iosxe, test_nxos

    from hst.analysis_model.vsx_topology import resolve

    nx = test_nxos._collector().normalize(test_nxos.RAW)
    xe = test_iosxe._collector().normalize(test_iosxe.RAW)
    raw = topology_capture()
    raw["vsx_evidence"] = envelope(warp_links=[pair()])
    raw["contexts"]["7"]["interfaces"].append({"ifname": "eth2"})
    raw["contexts"]["7"]["links"].append({"ifname": "eth2", "link_type": "ether"})
    cp = normalize_checkpoint_gateway(raw, _config().model_copy(update={"cluster_mode": "standalone"}))
    for batch in (nx, cp, xe):
        batch.validate_registry()

    def physical(batch):
        return next(
            r
            for r in batch.rels
            if r.rel_type == "REALIZED_BY" and r.start_label == "Interface" and r.end_label == "Port"
        )

    nx_port, xe_port = physical(nx), physical(xe)
    cp_ports = {n.props["name"]: n.uid for n in cp.nodes if n.label == "Port"}
    cables = [
        {"id": name, "kind": "CONNECTED_TO", "start": a, "end": b, "props": {"source": "cable-inventory"}}
        for name, a, b in [
            ("nx-cp", nx_port.end_uid, cp_ports["eth1"]),
            ("cp-xe", cp_ports["eth2"], xe_port.end_uid),
        ]
    ]
    g = inventory(nx, cp, xe, extra=cables)
    assert g.complete
    vs_in = next(n for n in cp.nodes if n.label == "Interface" and n.props["name"] == "wrp10")
    target, crossings, gap = resolve(g, nx_port.start_uid, None)
    assert target[0] == vs_in.uid and len(crossings) == 1 and gap is None
    target, crossings, gap = resolve(g, vs_in.uid, None)
    assert target[0] == nx_port.start_uid and len(crossings) == 1 and gap is None
    # Egress is physically connected to the IOS-XE interface, without
    # treating the physical VSX chassis as an inter-VSID forwarding edge.
    assert any(r["end"] == xe_port.end_uid for r in cables)
    assert {n.uid for n in cp.nodes if n.label == "VrfInstance"}.isdisjoint(
        n.uid for n in nx.nodes + xe.nodes if n.label == "VrfInstance"
    )


def test_runtime_catalog_keeps_binding_owner_and_explicit_sync_only():
    from hst.analysis_model.checkpoint_sessions import catalog_from_graph

    raw = capture()
    first = normalize_checkpoint_gateway(raw, _config())
    other_config = _config().model_copy(update={"appliance_uid": "member-b"})
    second = normalize_checkpoint_gateway(raw, other_config)
    other_device = next(n.uid for n in second.nodes if n.label == "Device")
    raw["vsx_evidence"] = envelope(sessions=[session_record(synchronized_members=[other_device])])
    first = normalize_checkpoint_gateway(raw, _config())
    catalog = catalog_from_graph(
        inventory(first, second), estate="estate", request_id="request:1", choice_scope=()
    )
    assert len(catalog.bindings) == 1 and len(catalog.synchronization) == 1
    binding = catalog.bindings[0]
    assert binding.original_forward.source_port == 50123
    assert binding.translated_forward.source_port == 62001
    sync = catalog.synchronization[0]
    assert sync.owner_context.vrf != sync.reply_context.vrf
    assert sync.owner_context.firewall_instance == sync.reply_context.firewall_instance
    assert not catalog.complete


def test_a_runtime_catalog_for_one_binding_reads_no_whole_vrf_label():
    """The reply of one named binding reads the contexts that binding
    names and their firewall instance's peers, not every VrfInstance of the
    run, which on a scoped inventory reloads the whole run."""
    from collections.abc import Mapping
    from dataclasses import replace

    from hst.analysis_model.checkpoint_sessions import catalog_from_graph

    raw = capture()
    other_config = _config().model_copy(update={"appliance_uid": "member-b"})
    second = normalize_checkpoint_gateway(raw, other_config)
    other_device = next(n.uid for n in second.nodes if n.label == "Device")
    raw["vsx_evidence"] = envelope(sessions=[session_record(synchronized_members=[other_device])])
    first = normalize_checkpoint_gateway(raw, _config())
    run = inventory(first, second)
    whole = catalog_from_graph(run, estate="estate", request_id="request:1", choice_scope=())
    (binding,) = whole.bindings

    class NoVrfLabel(Mapping):
        def __init__(self, items):
            self.items = items

        def __getitem__(self, label):
            assert label != "VrfInstance", "read every VrfInstance"
            return self.items[label]

        def __iter__(self):
            raise AssertionError("read every label")

        def __len__(self):
            raise AssertionError("counted the labels")

    scoped = catalog_from_graph(
        replace(run, labels=NoVrfLabel(run.labels)),
        estate="estate",
        request_id="request:1",
        choice_scope=(),
        binding_id=binding.binding_id,
    )
    assert scoped.bindings == whole.bindings and scoped.synchronization == whole.synchronization
    assert not scoped.complete
    unknown = catalog_from_graph(
        run, estate="estate", request_id="request:1", choice_scope=(), binding_id="nowhere:b1"
    )
    assert unknown.binding("nowhere:b1") is None and not unknown.complete


def test_text_fallback_preserves_ipv6_neighbors_unnumbered_and_multipath():
    from hst.collectors.checkpoint_iproute import parse

    assert (
        parse("links", "9: wrp10: <BROADCAST,UP> mtu 1500 state UP link/ether 00:11:22:33:44:55")[0]["ifname"]
        == "wrp10"
    )
    assert parse("neighbors6", "2001:db8::2 dev eth1 lladdr 00:11:22:33:44:55 STALE")[0]["state"] == ["STALE"]
    route = parse(
        "routes4",
        "default proto bgp metric 20 nexthop via 192.0.2.1 dev eth1 weight 1 "
        "nexthop via 192.0.2.2 dev eth2 weight 1",
    )[0]
    assert route["protocol"] == "bgp" and len(route["nexthops"]) == 2
    with pytest.raises(ValueError):
        parse("routes4", "Error: unknown option")


def test_transit_selection_reports_ambiguity_and_budget(monkeypatch):
    def row(target):
        return {
            "target": {"if_uid": target},
            "nodes": [{"uid": "start"}, {"uid": target}],
            "edges": [{"type": "CONNECTED_TO", "source": "vsx-warp"}],
        }

    monkeypatch.setattr(path, "_read", lambda *a, **kw: [row("vs7"), row("vs8")])
    assert "multiple" in vsx.resolve(None, "start", None)[2]
    monkeypatch.setattr(path, "_read", lambda *a, **kw: [row(str(i)) for i in range(33)])
    assert "budget" in vsx.resolve(None, "start", None)[2]


def test_compiled_model_inserts_bridge_policy_before_next_routing_context():
    from tests.enterprise.test_network_compile import _graph, _ivals, _network

    from hst.analysis_model.graph import GraphNode, GraphRelation
    from hst.analysis_model.network import normalize_network
    from hst.analysis_model.overlay import _rebuild
    from hst.impact.evaluate import Member, RequestSet, member

    nodes = {
        uid: GraphNode(uid, frozenset({label}), props)
        for uid, label, props in [
            ("if:r1:wan", "Interface", {}),
            ("if:r2:lan", "Interface", {}),
            ("b-in", "Interface", {"vsx_kind": "bridge"}),
            ("b-out", "Interface", {"vsx_kind": "bridge"}),
            (
                "b-vrf",
                "VrfInstance",
                {"firewall_instance_uid": "b-vs", "authority": "manager", "domain": "domain"},
            ),
            ("b-vs", "FirewallInstance", {}),
            ("b-member", "Device", {"role": "firewall"}),
            ("c2", "VrfInstance", {}),
            ("peer", "IpAddress", {"ip": "192.0.2.2"}),
        ]
    }
    links = [
        GraphRelation(str(i), kind, a, b, props)
        for i, (kind, a, b, props) in enumerate(
            [
                ("CONNECTED_TO", "if:r1:wan", "b-in", {}),
                ("BRIDGED_TO", "b-in", "b-out", {"source": "vsx-bridge"}),
                ("CONNECTED_TO", "b-out", "if:r2:lan", {}),
                ("IN_VRF", "if:r2:lan", "c2", {}),
                ("HAS_IP", "if:r2:lan", "peer", {}),
                ("IN_VRF", "b-in", "b-vrf", {}),
                ("ON", "b-in", "b-member", {}),
            ]
        )
    ]
    g = _rebuild(_graph(), nodes, links)
    network = _network()
    for row in network.routes.rib:
        if row.get("next_hop") == "192.0.2.2":
            row["interface"] = "wan"
    request = RequestSet(
        "flow",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
    )
    model = normalize_network(network, g, request, request.members[0], "estate")
    bridges = [n for n in model.nodes if n.key.location.startswith("vsx-bridge:")]
    assert bridges and all(n.policy is not None for n in bridges)
    assert all(n.key.context.firewall_instance == "b-vs" for n in bridges)


def test_vsx_access_keeps_original_destination_even_without_chassis_rulebase(monkeypatch):
    monkeypatch.setattr(
        trace,
        "_device_filter_view",
        lambda *a: (_ for _ in ()).throw(AssertionError("chassis policy lookup")),
    )
    original = path._intervals(["203.0.113.8"])
    translated = path._intervals(["10.1.0.5"])
    leg = {}
    result = trace._filter_dst(
        None,
        path._Trail(),
        leg,
        {"dev_uid": "member-a", "vsx_kind": "virtual-system"},
        {"nat_dst": translated, "dst": translated, "orig_dst": original, "orig_port": 443},
        translated,
        8443,
        "client",
    )
    assert result == (original, 443)
    assert leg["filter_view"] == "original"


def test_gaia_default_id_and_reenable_are_not_cisco_sequence_defaults():
    from hst.collectors.checkpoint_bgp import route_maps

    maps = route_maps(
        "set routemap policy id default allow\nset routemap policy id 10 inactive\n"
        "set routemap policy id 10 restrict"
    )
    assert len(maps["policy"]) == 1
    entry = maps["policy"][0]
    assert entry["seq"] == 10 and entry["enabled"] and entry["action"] == "deny"


def test_virtual_router_cannot_acquire_firewall_policy_from_installation_rows():
    raw = capture("R")
    raw["contexts"]["7"]["installations"] = [
        {"rulebase_uid": "rb:1", "installed_revision": "r1", "complete": True}
    ]
    batch = normalize_checkpoint_gateway(raw, _config())
    assert not [r for r in batch.rels if r.rel_type == "ENFORCES"]
    assert not [n for n in batch.nodes if n.label == "FirewallInstance"]
