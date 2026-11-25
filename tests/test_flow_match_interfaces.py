from __future__ import annotations

from ipaddress import ip_address

from tests.support import policy_route_graph as vyos
from tests.support.batch_inventory import inventory
from tests.test_cisco_common import _PERMIT_ANY_ACE, DEV, _acl_batch
from tests.test_rule_explain_scope import LAN_WAN, RULE_10, _backend, _lan_wan

from hst.assessment import flow_match


def _flow(source: str, destination: str = "198.51.100.7") -> dict:
    def point(text: str) -> list[list[int]]:
        return [[int(ip_address(text)), int(ip_address(text))]]

    return {
        "sources": point(source),
        "destinations": point(destination),
        "protocols": [6],
        "destination_ports": [[443, 443]],
        "source_ports": None,
    }


def _acl():
    acl = {
        "lists": {"EDGE": [{**_PERMIT_ANY_ACE, "action": "deny"}]},
        "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE"}],
    }
    graph = inventory(_acl_batch(acl))
    (rulebase,) = [
        uid
        for uid in graph.labels["FwRulebase"]
        if graph.nodes[uid].props.get("match_context") == "interface-acl"
    ]
    return graph, rulebase


def test_a_zone_pair_receives_a_flow_only_from_its_source_zone_to_its_destination_zone():
    graph = _lan_wan()

    assert flow_match.receives(graph, LAN_WAN, "eth1", "eth2") is True
    assert flow_match.receives(graph, LAN_WAN, "eth2", "eth1") is False
    assert flow_match.receives(graph, LAN_WAN, "eth1", None) is None


def test_an_acl_receives_a_flow_through_its_bindings_only():
    graph, rulebase = _acl()

    assert flow_match.receives(graph, rulebase, "Ethernet1/1", None) is True
    assert flow_match.receives(graph, rulebase, "Vlan10", None) is False
    assert flow_match.receives(graph, rulebase, None, "Vlan10") is None


def test_a_vyos_input_chain_does_not_receive_a_forwarded_flow():
    def patch(cfg):
        cfg["firewall"] = {"ipv4": {"input": {"filter": {"default-action": "drop"}}}}

    graph = inventory(vyos.batch(patch))
    chain = f"vyos:{vyos.HOST}:fw:ipv4-input"

    assert flow_match.receives(graph, chain, "eth0", "eth1") is False
    assert flow_match.receives(graph, chain, "eth0", None) is None


def test_an_interface_the_device_does_not_have_is_refused():
    document = flow_match.match(
        _lan_wan(), "test", vyos.DEV, LAN_WAN, _flow("192.168.2.45"), 4, ingress="eth9"
    )

    assert document["error"]["code"] == "not_found" and document["error"]["field"] == "ingress_interface"


def test_the_reported_rule_drops_the_flow_that_leaves_through_eth2_and_not_through_eth0():
    _backend()
    graph = _lan_wan()

    def decided(egress: str) -> dict:
        document = flow_match.match(
            graph, "test", vyos.DEV, LAN_WAN, _flow("192.168.2.45"), 4, ingress="eth1", egress=egress
        )
        (rulebase,) = document["rulebases"]
        return rulebase

    through_eth2, through_eth0 = decided("eth2"), decided(f"{vyos.DEV}/if/eth0")

    assert through_eth2["receives"] is True and through_eth2["gaps"] == []
    assert through_eth2["decision"] == "deny" and through_eth2["deciding_rule"]["uid"] == RULE_10
    # rule 10 is scoped to eth2: through eth0 the default accept decides the flow
    assert through_eth0["decision"] == "permit" and through_eth0["gaps"] == []


def test_a_flow_from_the_wrong_zone_is_not_applicable():
    _backend()

    document = flow_match.match(
        _lan_wan(), "test", vyos.DEV, LAN_WAN, _flow("192.168.2.45"), 4, ingress="eth2", egress="eth1"
    )

    (rulebase,) = document["rulebases"]
    assert rulebase["receives"] is False and rulebase["decision"] == "not_applicable"


def test_an_acl_not_bound_to_the_flow_interfaces_does_not_deny_it():
    _backend()
    graph, rulebase = _acl()

    def decided(ingress: str) -> dict:
        document = flow_match.match(graph, "test", DEV, rulebase, _flow("10.0.0.5"), 4, ingress=ingress)
        return document["rulebases"][0]

    assert decided("Ethernet1/1")["decision"] == "deny"
    assert decided("Vlan10")["decision"] == "not_applicable"


def test_a_rulebase_of_the_other_family_is_not_applicable_to_the_flow():
    from tests.test_rule_explain_scope import LAN_WAN6, _dual_family

    graph = _dual_family()

    for rulebase, family in ((LAN_WAN, 6), (LAN_WAN6, 4)):
        # returned before any policy is built or compiled
        entry = flow_match._rulebase(graph, "test", "dev:gw", rulebase, family, None, None, "eth1", "eth2")

        assert entry["decision"] == "not_applicable" and entry["receives"] is False
        assert entry["deciding_rule"] is None and entry["candidate_rules"] == []


def test_an_ipv6_flow_is_decided_by_the_ipv6_ruleset_only():
    _backend()
    from tests.test_rule_explain_scope import LAN_WAN6, _dual_family

    graph = _dual_family()
    flow = {
        "sources": [[int(ip_address("2001:db8::5"))] * 2],
        "destinations": [[int(ip_address("2001:db8:1::7"))] * 2],
        "protocols": [6],
        "destination_ports": [[22, 22]],
        "source_ports": None,
    }

    document = flow_match.match(graph, "test", "dev:gw", None, flow, 6, ingress="eth1", egress="eth2")

    decisions = {entry["uid"]: entry["decision"] for entry in document["rulebases"]}
    assert decisions[LAN_WAN] == "not_applicable"
    assert decisions[LAN_WAN6] == "permit"
