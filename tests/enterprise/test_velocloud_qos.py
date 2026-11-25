"""The effective business policy: one enterprise-wide profile read plus the
edge's own override delta. No operation answers a per-edge QOS body."""

import json

import httpx
import pytest

from hst.collectors.velocloud import PORTAL_READ_PATHS, normalize_velocloud

from .test_velocloud import ENT, _qos, _rule
from .test_velocloud_poll import Fleet


def _policy(eid: str) -> str:
    return f"vco:{ENT}:edge-{eid}-policy:edge"


def _classes(batch, eid: str) -> set[str]:
    return {
        rel.props["application_class"]
        for rel in batch.rels
        if rel.rel_type == "STEERS_VIA" and rel.start_uid == _policy(eid) and "-link:" in rel.end_uid
    }


@pytest.fixture
def fleet(monkeypatch):
    return Fleet(monkeypatch)


def test_the_policy_steers_without_a_per_edge_qos_request(fleet, monkeypatch):
    paths = []

    def watch(request):
        paths.append(request.url.path)
        return fleet.reply(request)

    monkeypatch.setattr("hst.collectors.velocloud._transport", lambda _: httpx.MockTransport(watch))
    batch = normalize_velocloud(fleet.poll(), private_carriers={"ournet"})
    assert not [path for path in paths if "qos" in path.lower()]
    assert PORTAL_READ_PATHS["enterprise_configurations"] in paths
    # the profile rules apply to both edges, each through its own links
    assert _classes(batch, "e-br") == {"voice", "web", "backup"}
    assert _classes(batch, "e-hub") == {"web", "backup"}
    policy = next(n for n in batch.nodes if n.uid == _policy("e-br"))
    assert "capability_gap" not in policy.props
    rules = sorted(
        (
            n
            for n in batch.nodes
            if n.label == "SdwanPolicyRule" and n.uid.startswith(f"vco:{ENT}:edge-e-br-rule:")
        ),
        key=lambda n: n.props["position"],
    )
    assert [rule.props["name"] for rule in rules] == ["voice", "web", "backup"]
    assert policy.props["rule_count"] == 3


def test_the_edge_override_replaces_the_profile_rules_of_the_same_segment(fleet):
    """`edgeSpecificData` is the override delta. Its `rules` go ahead of the
    profile's for the segment it names, and the other edges keep the profile."""
    modules = fleet.enterprises[0]["edges"][0]["configuration"]["enterprise"]["modules"]
    qos = next(module for module in modules if module["name"] == "QOS")
    qos["isEdgeSpecific"] = True
    qos["edgeSpecificData"] = _qos([_rule("mgmt", linkPolicy="internet")])
    batch = normalize_velocloud(fleet.poll(), private_carriers={"ournet"})
    assert _classes(batch, "e-br") == {"mgmt", "voice", "web", "backup"}
    assert _classes(batch, "e-hub") == {"web", "backup"}
    steer = next(
        rel
        for rel in batch.rels
        if rel.rel_type == "STEERS_VIA"
        and rel.start_uid == _policy("e-br")
        and "-link:" in rel.end_uid
        and rel.props["application_class"] == "mgmt"
    )
    assert steer.end_uid == f"vco:{ENT}:edge-e-br-link:l-br-dia"
    assert steer.props["preference"] == "internet"


def test_a_refused_profile_read_leaves_every_policy_unknown_and_keeps_the_edges(fleet):
    fleet.fail["getEnterpriseConfigurations"] = 403
    raw = fleet.poll()
    gap = raw["enterprises"][0]["gaps"][0]["_capability"]
    assert gap["operation"] == PORTAL_READ_PATHS["enterprise_configurations"]
    assert gap["http_status"] == 403
    batch = normalize_velocloud(raw)
    assert len([n for n in batch.nodes if n.label == "Device"]) == 2
    policies = [n for n in batch.nodes if n.label == "SdwanBusinessPolicy"]
    assert len(policies) == 2
    for policy in policies:
        assert json.loads(policy.props["capability_gap"])["status"] == "unavailable"
    assert not _classes(batch, "e-br")
    assert any("getEnterpriseConfigurations" in str(n.props.get("gaps")) for n in batch.nodes)


def test_a_refused_profile_read_writes_no_rule_count(fleet):
    fleet.fail["getEnterpriseConfigurations"] = 403
    batch = normalize_velocloud(fleet.poll())
    policies = [n for n in batch.nodes if n.label == "SdwanBusinessPolicy"]
    assert len(policies) == 2
    for policy in policies:
        assert "capability_gap" in policy.props
        assert "rule_count" not in policy.props
    assert not [n for n in batch.nodes if n.label == "SdwanPolicyRule"]


def test_a_rule_keeps_its_match_and_its_action_as_flat_properties():
    """The values are the shape a production QOS body carries: -1, "" and
    "any" leave a field open, and the backhaul hubs are named by cluster."""
    from hst.collectors.velocloud import _rule_action, _rule_match

    match = {
        "appid": -1,
        "classid": -1,
        "dscp": 46,
        "proto": 17,
        "sip": "any",
        "ssm": "255.255.255.255",
        "dip": "10.20.0.0",
        "dsm": "255.255.0.0",
        "dport_low": 5060,
        "dport_high": 5061,
        "sport_low": -1,
        "sport_high": -1,
        "hostname": "",
        "ipVersion": "IPv4",
    }
    assert _rule_match(match) == {
        "match_app_id": None,
        "match_app_class_id": None,
        "match_dscp": 46,
        "match_proto": "udp",
        "match_src": None,
        "match_dst": "10.20.0.0/16",
        "match_src_port": None,
        "match_dst_port": "5060-5061",
        "match_hostname": None,
        "match_src_interface": None,
        "match_dst_interface": None,
        "match_src_vlan": None,
        "match_dst_vlan": None,
        "match_ip_version": "IPv4",
        "match_summary": "dscp 46 udp dst 10.20.0.0/16 dport 5060-5061",
    }
    assert _rule_match({"appid": -1, "sip": "any", "dip": "any"})["match_summary"] == "any"
    action = {
        "QoS": {
            "type": "realtime",
            "txScheduler": {"priority": "high", "bandwidthCapPct": -1},
            "rxScheduler": {"priority": "high", "bandwidthCapPct": 20},
        },
        "routeType": "edge2Cloud",
        "sla": {"jitterMs": "0", "latencyMs": "150", "lossPct": "0.0"},
        "nat": {"destIp": "no", "sourceIp": "no"},
        "edge2CloudRouteAction": {
            "routePolicy": "backhaul",
            "linkPolicy": "auto",
            "wanlink": "auto",
            "linkOuterDscpTag": "CS0",
            "routeCfg": {
                "backhaulEdges": [
                    {"name": " HUB-FRANKFURT", "type": "edgeHubCluster"},
                    {"name": "HUB-PARIS", "type": "edgeHubCluster"},
                ]
            },
        },
        "edge2EdgeRouteAction": {
            "routePolicy": "gateway",
            "linkPolicy": "auto",
            "wanlink": "auto",
            "routeCfg": {},
        },
    }
    props = _rule_action(action)
    assert props["qos_class"] == "realtime"
    assert (props["priority_tx"], props["priority_rx"]) == ("high", "high")
    assert (props["bandwidth_cap_pct_tx"], props["bandwidth_cap_pct_rx"]) == (None, 20)
    assert props["route_type"] == "edge2Cloud"
    assert (props["sla_latency_ms"], props["sla_jitter_ms"], props["sla_loss_pct"]) == ("150", None, None)
    assert (props["nat_source"], props["nat_dest"]) == (None, None)
    assert props["edge2cloud_route_policy"] == "backhaul"
    assert props["edge2cloud_wanlink"] is None
    assert props["edge2cloud_outer_dscp"] == "CS0"
    # the orchestrator keeps the leading space an operator typed; the hub name does not
    assert props["edge2cloud_backhaul_hubs"] == ["HUB-FRANKFURT", "HUB-PARIS"]
    assert props["edge2edge_route_policy"] == "gateway"
    assert props["edge2edge_backhaul_hubs"] is None
    assert "edge2datacenter_route_policy" not in props


def test_the_segment_defaults_follow_its_rules_in_position():
    from hst.collectors.util import GraphBuilder
    from hst.collectors.velocloud import _policy_rules

    class _Ent:
        segment_uids = {"0": "seg-0"}

    class _E:
        b = GraphBuilder()
        ent = _Ent()
        enterprise = ENT
        eid = "e-br"

    qos = {
        "segments": [
            {
                "segment": {"segmentId": 0, "name": "Global Segment"},
                "rules": [{"name": "voice", "ruleLogicalId": "r1", "match": {"dscp": 46}, "action": {}}],
                "defaults": [{"name": "Default-Any-Other", "ruleLogicalId": "d1", "match": {}, "action": {}}],
            }
        ]
    }
    edge = _E()
    assert _policy_rules(edge, "pol", qos) == 2
    rules = {n.props["name"]: n.props for n in edge.b._nodes.values()}
    assert (rules["voice"]["position"], rules["voice"]["default"]) == (1, False)
    assert (rules["Default-Any-Other"]["position"], rules["Default-Any-Other"]["default"]) == (2, True)


def test_an_override_that_repeats_a_rule_logical_id_replaces_only_that_rule(fleet):
    modules = fleet.enterprises[0]["edges"][0]["configuration"]["enterprise"]["modules"]
    qos = next(module for module in modules if module["name"] == "QOS")
    qos["isEdgeSpecific"] = True
    qos["edgeSpecificData"] = _qos([{**_rule("web", linkPolicy="internet"), "name": "web-edge"}])
    batch = normalize_velocloud(fleet.poll(), private_carriers={"ournet"})
    rules = sorted(
        (n for n in batch.nodes if n.label == "SdwanPolicyRule" and "-e-br-rule:" in n.uid),
        key=lambda n: n.props["position"],
    )
    names = [n.props["name"] for n in rules if not n.props.get("default")]
    assert names[0] == "web-edge"
    assert "web" not in names
    assert rules[0].props["override"] is True
    assert all("override" not in n.props for n in rules[1:])


def test_a_match_key_the_collector_does_not_map_is_named():
    from hst.collectors.velocloud import _unmapped_match

    assert _unmapped_match({"sAddressGroup": "grp-1", "dip": "10.0.0.0", "sPortGroup": "", "x": -1}) == [
        "sAddressGroup"
    ]
    assert _unmapped_match({"appid": 7}) is None


def _rule_uids(qos: dict) -> dict[str, str]:
    from hst.collectors.util import GraphBuilder
    from hst.collectors.velocloud import _policy_rules

    class _Ent:
        segment_uids = {"0": "seg-0"}

    class _E:
        b = GraphBuilder()
        ent = _Ent()
        enterprise = ENT
        eid = "e-br"

    edge = _E()
    _policy_rules(edge, "pol", qos)
    return {n.props["name"]: n.uid for n in edge.b._nodes.values() if n.label == "SdwanPolicyRule"}


def test_a_rule_inserted_without_a_logical_id_keeps_the_default_rule_uids():
    def qos(rules: list[str]) -> dict:
        return {
            "segments": [
                {
                    "segment": {"segmentId": 0, "name": "Global Segment"},
                    "rules": [{"name": n, "match": {}, "action": {}} for n in rules],
                    "defaults": [{"name": "Default-Any-Other", "match": {}, "action": {}}],
                }
            ]
        }

    before = _rule_uids(qos(["voice", "web"]))
    after = _rule_uids(qos(["voice", "backup", "web"]))
    assert after["Default-Any-Other"] == before["Default-Any-Other"]
    assert after["voice"] == before["voice"]
    assert len(set(after.values())) == 4
