"""A UniFi classic ruleset judges only the traffic the gateway applies it to.

LAN_IN filters what enters the gateway from a LAN network, WAN_IN what enters
from the WAN, and a LOCAL ruleset what a family sends to the gateway itself,
each with the default the gateway applies when no listed rule matches. Each
test runs the normalized batch through the gate's own candidate and verdict
code, with the graph reads answered from the batch.
"""

from __future__ import annotations

from typing import Any

from tests.test_firewall_rule_scope import _inventory, _rows
from tests.test_unifi import RAW, UDM

import hst.path as path
from hst.analysis_model.network import _bindings
from hst.assessment.flow_match import receives
from hst.collectors.unifi import normalize_unifi
from hst.path.gates import firewall as fw
from hst.path.verdict import DENY, INDETERMINATE, PERMIT, classify_action
from hst.policy.graph import LOCAL_INTERFACE
from hst.policy.ir import ExecutionContext

BR1, BR30, BR40 = "dev:gateway/if/br1", "dev:gateway/if/br30", "dev:gateway/if/br40"


def _rule(rid: str, ruleset: str, index: int, action: str, **sides: Any) -> dict[str, Any]:
    return {
        "_id": rid,
        "ruleset": ruleset,
        "rule_index": index,
        "name": rid,
        "action": action,
        "enabled": True,
        "protocol": sides.pop("protocol", "all"),
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": [],
        **sides,
    }


RULES = [
    _rule("iot-to-lan", "LAN_IN", 2000, "drop", src_address="192.168.30.0/24", dst_address="192.168.1.0/24"),
    _rule("web-in", "WAN_IN", 3000, "accept", protocol="tcp", dst_address="192.168.1.20", dst_port="443"),
    _rule("v6-drop", "LANv6_IN", 2000, "drop", src_address="fd00:30::/64"),
    _rule("guest-web", "GUEST_IN", 2000, "accept", protocol="tcp", dst_port="80"),
    _rule("lan-ssh", "LAN_LOCAL", 2000, "accept", protocol="tcp", dst_port="22"),
]


def _batch(rules=RULES, networks=None):
    raw = {**RAW, "devices": RAW["devices"] + [UDM], "firewall_rules": rules}
    if networks is not None:
        raw["networks"] = networks
    return normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")


def _reader(batch):
    """A `_read` answering the gate's candidate, chain, rule and interface
    name queries from `batch`."""
    props = {n.uid: n.props for n in batch.nodes}
    names = {n.uid: n.props.get("name") for n in batch.nodes if n.label == "Interface"}
    rows = []
    for e in (r for r in batch.rels if r.rel_type == "ENFORCES"):
        p = props[e.end_uid]
        rows.append(
            {
                "rb_uid": e.end_uid,
                "rb_name": p.get("name"),
                "vendor": p.get("vendor"),
                "af": p.get("af"),
                "default_action": p.get("default_action"),
                "default_action_unknown": p.get("default_action_unknown"),
                "global_state_policy": None,
                "state_policy_basis": None,
                "established_default_unknown": p.get("established_default_unknown"),
                "match_context": p.get("match_context"),
                "chain": p.get("chain"),
                "approximate": e.props.get("approximate", False),
                "owner_raw_uid": None,
                "acl_bindings": [
                    [names[r.start_uid], r.props["direction"]]
                    for r in batch.rels
                    if r.rel_type == "PROTECTED_BY" and r.end_uid == e.end_uid
                ],
                "acl_unreported": p.get("unreported_bindings"),
            }
        )

    def read(session, query, **params):
        if query == fw._RULEBASE_CANDIDATES:
            chain, strict = params["chain"], params["strict_local"]
            return [
                r
                for r in rows
                if (r["chain"] or "forward") == chain
                or (strict and r["chain"] is None and chain in ("input", "output"))
            ]
        if query == fw._DEVICE_CHAINS:
            return [{"chain": c} for c in sorted({r["chain"] for r in rows if r["chain"]})]
        if query == fw._RULEBASE_RULES:
            return _rows(batch, params["rb"])
        if "i.uid IN [$a, $b]" in query:
            return [{"uid": u, "name": n} for u, n in names.items() if u in (params["a"], params["b"])]
        return []

    return read


def _verdict(monkeypatch, batch, in_if, out_if, src, dst, port=443, proto="tcp", af=4, considered=None):
    monkeypatch.setattr(path, "_read", _reader(batch))
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    v = path._device_rulebase_verdict(
        None,
        "dev:gateway",
        in_if,
        out_if,
        path._intervals([src]),
        path._intervals([dst]),
        port,
        proto,
        af,
        considered=considered,
    )
    return v, classify_action(v["action"]) if v else None


def _rulebases(batch):
    return {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}


def test_classic_rulesets_record_their_family_chain_and_default():
    rbs = _rulebases(_batch())
    lan_in = rbs["unifi:default:fw:lan_in"]
    assert (lan_in["match_context"], lan_in["chain"], lan_in["af"]) == ("interface-acl", "forward", 4)
    assert lan_in["default_action"] == "accept" and lan_in["default_action_unknown"] is False
    assert rbs["unifi:default:fw:lanv6_in"]["af"] == 6
    # the controller places port forward and service accepts ahead of the
    # WAN drop, and guest isolation rules in the GUEST rulesets
    for name in ("wan_in", "guest_in"):
        assert rbs[f"unifi:default:fw:{name}"].get("default_action") is None
        assert rbs[f"unifi:default:fw:{name}"]["default_action_unknown"] is True
    local = rbs["unifi:default:fw:lan_local"]
    assert (local["match_context"], local["chain"], local["default_action"]) == ("device", "input", "accept")
    odd = _rulebases(_batch([_rule("odd", "CUSTOM_RULESET", 2000, "drop")]))[
        "unifi:default:fw:custom_ruleset"
    ]
    assert odd.get("chain") is None and odd["default_action_unknown"] is True


def test_in_rulesets_bind_the_interfaces_of_their_network_family():
    batch = _batch()
    bound = {
        (r.start_uid, r.end_uid, r.props["direction"]) for r in batch.rels if r.rel_type == "PROTECTED_BY"
    }
    assert {b for b in bound if b[1] == "unifi:default:fw:lan_in"} == {
        (BR1, "unifi:default:fw:lan_in", "in"),
        (BR30, "unifi:default:fw:lan_in", "in"),
    }
    assert {b for b in bound if b[1] == "unifi:default:fw:guest_in"} == {
        (BR40, "unifi:default:fw:guest_in", "in")
    }
    rbs = _rulebases(batch)
    # the WAN interface is not collected: the binding is kept by name
    assert rbs["unifi:default:fw:wan_in"]["unreported_bindings"] == ["wan in"]
    enforces = {r.end_uid: r.props for r in batch.rels if r.rel_type == "ENFORCES"}
    assert enforces["unifi:default:fw:lan_in"]["approximate"] is False
    assert enforces["unifi:default:fw:lan_in"]["coverage"] == "complete"
    assert enforces["unifi:default:fw:wan_in"]["coverage"] == "partial"
    # which ingress a LOCAL ruleset judges is not modeled
    assert enforces["unifi:default:fw:lan_local"]["approximate"] is True


def test_a_lan_flow_to_the_internet_is_not_dropped_by_a_lan_in_default(monkeypatch):
    v, outcome = _verdict(monkeypatch, _batch(), BR1, None, "192.168.1.20/32", "8.8.8.8/32")
    assert outcome == PERMIT, v


def test_a_lan_flow_to_another_lan_network_takes_the_lan_in_default(monkeypatch):
    v, outcome = _verdict(monkeypatch, _batch(), BR1, BR30, "192.168.1.20/32", "192.168.30.50/32", 80)
    assert outcome == PERMIT, v
    assert v["rb_uid"] == "unifi:default:fw:lan_in" and v["by"] == "default-action"


def test_a_lan_in_rule_drops_what_enters_from_its_network(monkeypatch):
    v, outcome = _verdict(monkeypatch, _batch(), BR30, BR1, "192.168.30.50/32", "192.168.1.20/32", 22)
    assert outcome == DENY and v["rule_name"] == "iot-to-lan"


def test_a_guest_flow_with_no_matching_rule_is_undecided(monkeypatch):
    v, outcome = _verdict(monkeypatch, _batch(), BR40, None, "192.168.40.9/32", "8.8.8.8/32", 22)
    assert outcome == INDETERMINATE and v["rb_uid"] == "unifi:default:fw:guest_in"


def test_a_ruleset_of_no_known_scope_is_undecided_not_a_drop(monkeypatch):
    rules = [_rule("odd", "CUSTOM_RULESET", 2000, "drop")]
    v, outcome = _verdict(monkeypatch, _batch(rules), BR1, BR30, "192.168.1.20/32", "192.168.30.50/32")
    assert outcome == INDETERMINATE and v["approximate_binding"] is True


def test_predefined_isolation_makes_the_lan_default_unknown(monkeypatch):
    networks = [dict(n) for n in RAW["networks"]]
    networks[1]["network_isolation_enabled"] = True
    batch = _batch(networks=networks)
    assert _rulebases(batch)["unifi:default:fw:lan_in"].get("default_action") is None
    v, outcome = _verdict(monkeypatch, batch, BR1, None, "192.168.1.20/32", "8.8.8.8/32")
    assert outcome == INDETERMINATE, v


def test_lan_in_is_not_read_for_traffic_to_the_gateway_and_is_credited(monkeypatch):
    rules = [_rule("drop-all", "LAN_IN", 2000, "drop")]
    batch = _batch(rules)
    monkeypatch.setattr(path, "_read", _reader(batch))
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    considered: list[str] = []
    v = fw._firewall_verdict_local(
        None,
        "dev:gateway",
        None,
        path._intervals(["192.168.1.20/32"]),
        path._intervals(["192.168.1.1/32"]),
        53,
        "udp",
        chain="input",
        in_if=BR1,
        considered=considered,
    )
    assert v is None
    assert "unifi:default:fw:lan_in" in considered


def test_a_local_ruleset_is_credited_on_a_forwarded_leg(monkeypatch):
    rules = [_rule("lan-ssh", "LAN_LOCAL", 2000, "accept", protocol="tcp", dst_port="22")]
    batch = _batch(rules)
    monkeypatch.setattr(path, "_read", _reader(batch))
    assert fw._other_chain_rulebases(None, "dev:gateway", "forward", BR1) == ["unifi:default:fw:lan_local"]


def test_lan_in_is_credited_on_an_output_leg(monkeypatch):
    rules = [_rule("drop-all", "LAN_IN", 2000, "drop")]
    monkeypatch.setattr(path, "_read", _reader(_batch(rules)))
    assert fw._other_chain_rulebases(None, "dev:gateway", "output") == ["unifi:default:fw:lan_in"]


def test_a_forward_chain_acl_does_not_receive_a_packet_to_the_device():
    batch = _batch([_rule("drop-all", "LAN_IN", 2000, "drop")])
    graph = _inventory(batch)
    assert receives(graph, "unifi:default:fw:lan_in", "Default", "IoT") is True
    assert receives(graph, "unifi:default:fw:lan_in", "Default", LOCAL_INTERFACE) is False


def test_the_analysis_model_binds_no_local_ruleset_to_a_forwarded_flow():
    batch = _batch([_rule("lan-ssh", "LAN_LOCAL", 2000, "accept", protocol="tcp", dst_port="22")])
    graph = _inventory(batch)
    context = ExecutionContext("estate", "unifi", "home", "dev:gateway", "vrf:dev:gateway:default", 4)
    bound, _installation = _bindings(graph, context, BR1, BR30, 4)
    assert "unifi:default:fw:lan_local" not in bound


def test_a_local_ruleset_receives_a_packet_to_the_device_and_not_a_forwarded_one():
    """The input chain of a UniFi LOCAL ruleset is read like a VyOS input chain:
    not_applicable for a forwarded leg, received by a packet the gateway
    terminates, undecided while an interface is unnamed."""
    graph = _inventory(_batch([_rule("lan-ssh", "LAN_LOCAL", 2000, "accept", protocol="tcp", dst_port="22")]))
    local = "unifi:default:fw:lan_local"
    assert receives(graph, local, "Default", "IoT") is False
    assert receives(graph, local, "Default", LOCAL_INTERFACE) is True
    assert receives(graph, local, "Default", None) is None
    assert receives(graph, local, None, "IoT") is False


def test_the_explanation_scope_of_a_local_ruleset_ends_at_the_gateway():
    from hst.assessment.rule_scope import scope_space

    graph = _inventory(_batch([_rule("lan-ssh", "LAN_LOCAL", 2000, "accept", protocol="tcp", dst_port="22")]))
    local = "unifi:default:fw:lan_local"
    (rule,) = graph.targets(local, "HAS_RULE")
    space = scope_space(graph, local, rule.uid)
    assert space.entry["kind"] == "chain" and space.entry["chain"] == "input"
    assert [member for side in space.egress for member in side.members] == [LOCAL_INTERFACE]


def test_a_wan_ruleset_unreported_binding_leaves_a_lan_to_lan_flow_installed():
    """The binding of WAN_IN is unreported ("wan in"), and its ENFORCES row is
    partial. A flow that enters by a reported LAN interface does not enter by
    the WAN. WAN_IN is not bound to it, and its installation is proven. A
    flow with no known ingress keeps WAN_IN bound, and its installation is
    not proven."""
    from hst.policy.ir import Constant

    graph = _inventory(_batch())
    context = ExecutionContext("estate", "unifi", "home", "dev:gateway", "vrf:dev:gateway:default", 4)
    lan_in, wan_in = "unifi:default:fw:lan_in", "unifi:default:fw:wan_in"
    bound, installation = _bindings(graph, context, BR1, BR30, 4)
    assert lan_in in bound and wan_in not in bound
    assert installation == Constant(True)
    bound, installation = _bindings(graph, context, None, BR30, 4)
    assert {lan_in, wan_in} <= set(bound)
    assert installation != Constant(True)
