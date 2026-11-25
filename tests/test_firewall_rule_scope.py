"""A firewall rule must not match more than the device would."""

from __future__ import annotations

from types import MappingProxyType
from typing import Any

from tests.support import checkpoint_batch
from tests.test_unifi import RAW, UDM, ZONES

import hst.path as path
from hst.analysis_model.checkpoint_graph import checkpoint_policy
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.overlay import _rebuild
from hst.collectors.checkpoint import normalize_checkpoint
from hst.collectors.unifi import normalize_unifi
from hst.path.gates import firewall as fw
from hst.path.gates.nat import _nat_stage_rules
from hst.path.verdict import DENY, INDETERMINATE, PERMIT, classify_action
from hst.policy.ir import AllOf, AnyOf, Constant, ExecutionContext, Not, Unknown
from hst.policy.nat import normalize_nat_rules

# --- batch to gate rows -------------------------------------------------------------


def _rows(batch, rb_uid: str) -> list[dict[str, Any]]:
    """The rules of one rulebase of `batch` as `_RULEBASE_RULES` rows."""
    props = {n.uid: n.props for n in batch.nodes}
    rels = batch.rels
    rows = []
    for hr in (r for r in rels if r.rel_type == "HAS_RULE" and r.start_uid == rb_uid):
        p = props[hr.end_uid]
        row: dict[str, Any] = {
            "uid": hr.end_uid,
            "pos": p.get("position"),
            "action": p.get("action"),
            "name": p.get("name"),
            "out_if": None,
            "in_if": None,
            "out_if_group": None,
            "in_if_group": None,
            "states": p.get("states") or [],
            "states_opaque": bool(p.get("states_opaque")),
            "states_opaque_reason": p.get("states_opaque_reason"),
            "install_on": p.get("install_on") or [],
            "install_on_unresolved": bool(p.get("install_on_unresolved")),
            "src_any": bool(p.get("src_any")),
            "dst_any": bool(p.get("dst_any")),
            "svc_any": bool(p.get("svc_any")),
            "src_negate": bool(p.get("src_negate")),
            "dst_negate": bool(p.get("dst_negate")),
            "svc_negate": bool(p.get("svc_negate")),
            "src_ranges": [],
            "dst_ranges": [],
        }
        for side in ("src", "dst"):
            objs = [r.end_uid for r in rels if r.rel_type == side.upper() and r.start_uid == hr.end_uid]
            targets = [props[r.end_uid] for r in rels if r.rel_type == "RESOLVES_TO" and r.start_uid in objs]
            row[f"{side}_cidrs"] = [t["cidr"] for t in targets if "cidr" in t]
            row[f"{side}_ips"] = [t["ip"] for t in targets if "ip" in t]
            row[f"{side}_obj_count"] = len(objs)
            row[f"{side}_opaque"] = any(props[o].get("opaque") for o in objs)
            row[f"{side}_opaque_reasons"] = [
                props[o]["opaque_reason"] for o in objs if props[o].get("opaque")
            ]
        svcs = [props[r.end_uid] for r in rels if r.rel_type == "SVC" and r.start_uid == hr.end_uid]
        row["svc_obj_count"] = len(svcs)
        row["protos"] = [s.get("proto") for s in svcs]
        row["ports"] = [s.get("ports") for s in svcs]
        row["src_ports"] = [s.get("src_port") for s in svcs]
        row["svc_src_port"] = any(s.get("src_port") for s in svcs)
        row["svc_opaque"] = any(s.get("opaque") for s in svcs)
        row["svc_opaque_reasons"] = [s["opaque_reason"] for s in svcs if s.get("opaque")]
        rows.append(row)
    return sorted(rows, key=lambda r: r["pos"])


def _first(rows, src: str, dst: str, port: int | None = 22, proto: str | None = "tcp"):
    """The deciding rule's (name, action class), or None when no rule matched."""
    m = fw._first_match_point(rows, None, None, path._intervals([src]), path._intervals([dst]), port, proto)
    return (m[0]["name"], classify_action(m[0]["action"])) if m else None


def _gw_batch(**extra):
    raw = {**RAW, "devices": RAW["devices"] + [UDM], **extra}
    return normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")


# --- UniFi classic rest/firewallrule ------------------------------------------------

RFC1918 = {
    "_id": "g-rfc",
    "name": "RFC1918",
    "group_type": "address-group",
    "group_members": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
}
SSH_SRC = {"_id": "g-ssh", "name": "ssh-src", "group_type": "port-group", "group_members": ["2222"]}
ISOLATE = {
    "_id": "r-iso",
    "ruleset": "LAN_IN",
    "rule_index": 2001,
    "name": "drop inter-vlan",
    "action": "drop",
    "enabled": True,
    "protocol": "all",
    "src_firewallgroup_ids": ["g-rfc"],
    "dst_firewallgroup_ids": ["g-rfc"],
}


def _classic(first: dict[str, Any]):
    rule = {
        "_id": "r-first",
        "ruleset": "LAN_IN",
        "rule_index": 2000,
        "name": "first",
        "action": "accept",
        "enabled": True,
        "protocol": "all",
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": [],
        **first,
    }
    batch = _gw_batch(firewall_rules=[rule, ISOLATE], firewall_groups=[RFC1918, SSH_SRC])
    return _rows(batch, "unifi:default:fw:lan_in")


def test_a_classic_established_related_accept_does_not_admit_a_new_flow():
    """The standard isolation recipe: allow established/related, then drop
    inter-VLAN. A new IoT to LAN flow is dropped by the second rule."""
    rows = _classic({"state_established": True, "state_related": True, "state_new": False})
    assert rows[0]["states"] == ["established", "related"]
    assert _first(rows, "192.168.30.50/32", "192.168.1.20/32") == ("drop inter-vlan", DENY)


def test_a_classic_mac_qualifier_leaves_a_matching_rule_undecided():
    rows = _classic({"src_mac_address": "aa:bb:cc:dd:ee:ff"})
    assert _first(rows, "192.168.30.50/32", "192.168.1.20/32") == ("first", INDETERMINATE)
    assert "source MAC address" in rows[0]["states_opaque_reason"]


def test_a_classic_source_port_group_scopes_the_rule():
    """A source port group is not an address and not nothing: a flow that
    states no source port cannot be decided by the rule."""
    rows = _classic({"protocol": "tcp", "src_firewallgroup_ids": ["g-ssh"]})
    assert rows[0]["src_any"] is True
    assert rows[0]["src_ports"] == ["2222"] and rows[0]["protos"] == ["tcp"]
    assert _first(rows, "192.168.30.50/32", "192.168.1.20/32") == ("first", INDETERMINATE)


def test_a_classic_excepted_protocol_does_not_match_that_protocol():
    rows = _classic({"protocol": "tcp", "protocol_match_excepted": True})
    assert rows[0]["protos"] == ["!tcp"]
    assert _first(rows, "192.168.30.50/32", "192.168.1.20/32", 22, "tcp") == ("drop inter-vlan", DENY)
    assert _first(rows, "192.168.30.50/32", "192.168.1.20/32", 53, "udp") == ("first", PERMIT)


# --- UniFi 9.x zone policies --------------------------------------------------------

BLOCK_ALL = {
    "_id": "blk",
    "name": "block all",
    "index": 30001,
    "action": "BLOCK",
    "enabled": True,
    "protocol": "all",
    "source": {"zone_id": "z2", "matching_target": "ANY"},
    "destination": {"zone_id": "z1", "matching_target": "ANY"},
}
ALLOW_ALL = {**BLOCK_ALL, "_id": "all", "name": "allow all", "action": "ALLOW"}


def _zone(first: dict[str, Any], last: dict[str, Any] = BLOCK_ALL, rb="unifi:default:fw:zone:z2:z1"):
    policy = {
        "_id": "first",
        "name": "first",
        "index": 30000,
        "action": "ALLOW",
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": "z2", "matching_target": "ANY"},
        "destination": {"zone_id": "z1", "matching_target": "ANY"},
        **first,
    }
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=[policy, last])
    return batch, _rows(batch, rb)


def test_a_respond_only_allow_does_not_admit_a_new_flow():
    _, rows = _zone({"connection_state_type": "RESPOND_ONLY", "connection_states": []})
    assert rows[0]["states"] == ["established", "related"]
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("block all", DENY)


def test_custom_connection_states_are_kept():
    _, rows = _zone({"connection_state_type": "CUSTOM", "connection_states": ["ESTABLISHED"]})
    assert rows[0]["states"] == ["established"]


def test_a_port_group_destination_is_not_every_port():
    _, rows = _zone(
        {
            "protocol": "tcp",
            "destination": {
                "zone_id": "z1",
                "matching_target": "ANY",
                "port_matching_type": "OBJECT",
                "port_group_id": "pg-web",
            },
        }
    )
    assert rows[0]["svc_opaque"] is True
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("first", INDETERMINATE)


def test_a_negated_destination_block_excludes_only_the_named_address():
    first = {
        "action": "BLOCK",
        "destination": {
            "zone_id": "z1",
            "matching_target": "IP",
            "ips": ["192.168.1.5"],
            "match_opposite_ips": True,
        },
    }
    _, rows = _zone(first, ALLOW_ALL)
    assert rows[0]["dst_negate"] is True
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("first", DENY)
    assert _first(rows, "192.168.40.9/32", "192.168.1.5/32") == ("allow all", PERMIT)


def test_a_source_port_scopes_the_policy():
    _, rows = _zone(
        {
            "protocol": "tcp",
            "source": {"zone_id": "z2", "matching_target": "ANY", "port": "2222"},
            "destination": {"zone_id": "z1", "matching_target": "ANY", "port": "22"},
        }
    )
    assert rows[0]["src_ports"] == ["2222"]
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("first", INDETERMINATE)


def _first_by_sport(rows, src: str, dst: str, sport: int, port: int = 22):
    """The deciding rule's (name, action class) for a tcp flow stating a source port."""
    sport_ivals, _ = fw._sport_query(sport)
    port_ivals, _ = fw._as_portset(port)
    sliced = fw._first_match_by_sport(
        rows,
        None,
        None,
        path._intervals([src]),
        path._intervals([dst]),
        frozenset({6}),
        port_ivals,
        sport_ivals,
    )
    ((_, regions),) = sliced
    r = regions[0][0]
    return (r["name"], classify_action(r["action"])) if r else None


def test_a_negated_source_port_is_not_a_positive_source_port():
    """Source port 53 with match_opposite_ports means every source port but 53."""
    first = {
        "action": "BLOCK",
        "protocol": "tcp",
        "source": {"zone_id": "z2", "matching_target": "ANY", "port": "53", "match_opposite_ports": True},
        "destination": {"zone_id": "z1", "matching_target": "ANY", "port": "22"},
    }
    _, rows = _zone(first, ALLOW_ALL)
    assert rows[0]["svc_opaque"] is True and rows[0]["src_ports"] == [None]
    assert _first_by_sport(rows, "192.168.40.9/32", "192.168.1.20/32", 1234) == ("first", INDETERMINATE)
    assert _first_by_sport(rows, "192.168.40.9/32", "192.168.1.20/32", 53) == ("first", INDETERMINATE)


def test_a_port_group_id_without_a_matching_type_is_not_every_port():
    _, rows = _zone(
        {
            "protocol": "tcp",
            "destination": {"zone_id": "z1", "matching_target": "ANY", "port_group_id": "pg-web"},
        }
    )
    assert rows[0]["svc_opaque"] is True
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("first", INDETERMINATE)


def test_a_scheduled_policy_is_undecided():
    _, rows = _zone({"schedule": {"mode": "EVERY_DAY", "time_range_start": "08:00"}})
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("first", INDETERMINATE)


def test_a_family_scoped_policy_lands_in_that_familys_rulebase_only():
    batch, v4 = _zone({"ip_version": "IPV6"})
    v6 = _rows(batch, "unifi:default:fw:zone:z2:z1:ipv6")
    assert [r["name"] for r in v4] == ["block all"]
    assert [r["name"] for r in v6] == ["first", "block all"]
    rbs = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}
    assert rbs["unifi:default:fw:zone:z2:z1:ipv6"]["af"] == 6
    assert "af" not in rbs["unifi:default:fw:zone:z2:z1"]


def test_an_ipv4_only_policy_does_not_judge_ipv6_flows():
    """Every policy of the pair is IPv4-only."""
    batch, v4 = _zone({"ip_version": "IPV4"}, {**BLOCK_ALL, "ip_version": "IPV4"})
    assert [r["name"] for r in v4] == ["first", "block all"]
    assert _rows(batch, "unifi:default:fw:zone:z2:z1:ipv6") == []
    rbs = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}
    assert rbs["unifi:default:fw:zone:z2:z1:ipv6"]["af"] == 6


def test_a_block_on_an_ip_group_is_undecided_not_skipped():
    """An IP side that references an IP group carries no inline ips."""
    first = {
        "action": "BLOCK",
        "source": {
            "zone_id": "z2",
            "matching_target": "IP",
            "matching_target_type": "OBJECT",
            "ip_group_id": "grp-blocklist",
        },
    }
    _, rows = _zone(first, ALLOW_ALL)
    assert rows[0]["src_obj_count"] == 1 and rows[0]["src_opaque"] is True
    assert "IP group" in rows[0]["src_opaque_reasons"][0]
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("first", INDETERMINATE)


def test_an_ip_side_with_inline_ips_beside_an_ip_group_is_undecided():
    first = {
        "action": "BLOCK",
        "source": {"zone_id": "z2", "matching_target": "IP", "ips": ["192.168.40.5"], "ip_group_id": "grp"},
    }
    _, rows = _zone(first, ALLOW_ALL)
    assert rows[0]["src_opaque"] is True
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("first", INDETERMINATE)


def test_an_ip_side_with_no_inline_ips_is_undecided():
    first = {"action": "BLOCK", "destination": {"zone_id": "z1", "matching_target": "IP", "ips": []}}
    _, rows = _zone(first, ALLOW_ALL)
    assert rows[0]["dst_opaque"] is True
    assert "no inline ips" in rows[0]["dst_opaque_reasons"][0]
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32") == ("first", INDETERMINATE)


def test_a_specific_ip_side_matches_its_addresses():
    first = {
        "action": "BLOCK",
        "source": {
            "zone_id": "z2",
            "matching_target": "IP",
            "matching_target_type": "SPECIFIC",
            "ips": ["192.168.40.9"],
        },
    }
    _, rows = _zone(first, ALLOW_ALL)
    assert rows[0]["src_opaque"] is False
    assert _first(rows, "192.168.40.9/32", "192.168.1.20/32")[0] == "first"
    assert _first(rows, "192.168.40.10/32", "192.168.1.20/32") == ("allow all", PERMIT)


def test_a_side_that_is_not_any_is_never_written_empty():
    """The guard behind every target: a side `side_ips` returns with no
    address and no reason is written opaque, never as no object."""
    from hst.collectors.unifi import _zone_policy_rule
    from hst.collectors.util import GraphBuilder

    b = GraphBuilder()
    policy = {"_id": "p", "index": 1, "action": "BLOCK", "source": {}, "destination": {}}
    _zone_policy_rule(b, "default", "home", "rb", policy, (False, [], None, False), (True, [], None, False))
    batch = b.batch("unifi", "unifi:default")
    rows = _rows(batch, "rb")
    assert rows[0]["src_obj_count"] == 1 and rows[0]["src_opaque"] is True
    assert rows[0]["dst_obj_count"] == 0 and rows[0]["dst_any"] is True


# --- Check Point rule columns -------------------------------------------------------

DOMAIN = {"uid": "domain"}
ANY = {"uid": "any", "name": "Any", "type": "CpmiAnyObject", "domain": DOMAIN}
ACCEPT = {"uid": "accept", "name": "Accept", "type": "RulebaseAction", "domain": DOMAIN}
DROP = {"uid": "drop", "name": "Drop", "type": "RulebaseAction", "domain": DOMAIN}
TARGETS = {"uid": "policy-targets", "name": "Policy Targets", "type": "Global", "domain": DOMAIN}
O365 = {"uid": "o365", "name": "Office365", "type": "application-site", "domain": DOMAIN}


def _cp_rule(uid: str, number: int, action: str, **columns: Any) -> dict[str, Any]:
    return {
        "uid": uid,
        "type": "access-rule",
        "domain": DOMAIN,
        "rule-number": number,
        "enabled": True,
        "action": action,
        "source": ["any"],
        "destination": ["any"],
        "service": ["any"],
        "install-on": ["policy-targets"],
        "source-negate": False,
        "destination-negate": False,
        "service-negate": False,
        "time": ["any"],
        "vpn": ["any"],
        "content": ["any"],
        **columns,
    }


def _cp_raw(rules: list[dict[str, Any]], nat: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    layer = {"uid": "layer", "name": "Network", "type": "access-layer", "domain": DOMAIN}
    package = {
        "uid": "package",
        "name": "Policy",
        "type": "package",
        "domain": DOMAIN,
        "access-layers": ["layer"],
        "installation-targets": ["gw-a", "gw-b"],
    }
    objects = [ANY, ACCEPT, DROP, TARGETS, O365]
    return {
        "gateways": [
            {"uid": "gw-a", "name": "fw-a", "type": "simple-gateway"},
            {"uid": "gw-b", "name": "fw-b", "type": "simple-gateway"},
        ],
        "layers": [layer],
        "packages": [package],
        "package_details": {"package": package},
        "package_revisions": {"package": "revision"},
        "rulebases": {"layer": [{"rulebase": rules, "objects-dictionary": objects}]},
        "nat": {"Policy": [{"rulebase": nat, "objects-dictionary": objects}]} if nat else {},
        "policy_section_errors": [],
        "management_release": "R81.20",
        "gateway_release": "R81.20",
        "api_version": "1.9",
        "implied_rules_complete": True,
    }


def _cp_rows(raw):
    batch = normalize_checkpoint(raw, mgmt="manager", domain="domain")
    rb = next(n.uid for n in batch.nodes if n.label == "FwRulebase" and n.props.get("kind") == "access")
    return batch, _rows(batch, rb)


def test_checkpoint_rules_record_install_on_and_scoping_columns():
    raw = _cp_raw(
        [
            _cp_rule("r1", 1, "accept", **{"install-on": ["gw-a"]}),
            _cp_rule("r2", 2, "accept", vpn=["remote-access"]),
            _cp_rule("r3", 3, "accept", **{"install-on": ["gw-group"]}),
            _cp_rule("r4", 4, "drop"),
        ]
    )
    _, rows = _cp_rows(raw)
    by_uid = {r["uid"].rsplit(":", 1)[-1]: r for r in rows}
    assert by_uid["r1"]["install_on"] == ["gw-a"] and not by_uid["r1"]["install_on_unresolved"]
    assert by_uid["r2"]["states_opaque"] and "vpn" in by_uid["r2"]["states_opaque_reason"]
    assert by_uid["r3"]["install_on_unresolved"] is True
    # Policy Targets is every target of the package: no scope of its own
    assert by_uid["r4"]["install_on"] == [] and not by_uid["r4"]["install_on_unresolved"]


def test_a_rule_installed_on_another_gateway_does_not_decide_this_one():
    raw = _cp_raw([_cp_rule("r1", 1, "accept", **{"install-on": ["gw-a"]}), _cp_rule("r2", 2, "drop")])
    _, rows = _cp_rows(raw)
    on_b = fw._installed_rules(rows, "gw-b")
    assert _first(on_b, "10.1.1.1/32", "10.2.2.2/32")[1] == DENY
    on_a = fw._installed_rules(rows, "gw-a")
    assert _first(on_a, "10.1.1.1/32", "10.2.2.2/32")[1] == PERMIT


def test_an_install_on_the_gate_cannot_place_is_undecided():
    raw = _cp_raw([_cp_rule("r1", 1, "accept", **{"install-on": ["gw-group"]}), _cp_rule("r2", 2, "drop")])
    _, rows = _cp_rows(raw)
    assert _first(fw._installed_rules(rows, "gw-b"), "10.1.1.1/32", "10.2.2.2/32")[1] == INDETERMINATE
    raw = _cp_raw([_cp_rule("r1", 1, "accept", **{"install-on": ["gw-a"]}), _cp_rule("r2", 2, "drop")])
    _, rows = _cp_rows(raw)
    # read without the binding's gateway (another caller of the matcher)
    assert _first(rows, "10.1.1.1/32", "10.2.2.2/32")[1] == INDETERMINATE


def test_a_vpn_scoped_accept_is_undecided_for_a_matching_flow():
    raw = _cp_raw([_cp_rule("r1", 1, "accept", vpn=["remote-access"]), _cp_rule("r2", 2, "drop")])
    _, rows = _cp_rows(raw)
    assert _first(fw._installed_rules(rows, "gw-a"), "10.1.1.1/32", "10.2.2.2/32")[1] == INDETERMINATE


def test_an_application_in_the_service_column_is_an_opaque_service():
    raw = _cp_raw([_cp_rule("r1", 1, "accept", service=["o365"]), _cp_rule("r2", 2, "drop")])
    batch, rows = _cp_rows(raw)
    labels = {n.uid.rsplit(":", 1)[-1]: n.label for n in batch.nodes}
    assert labels["o365"] == "SvcObject"
    assert rows[0]["svc_opaque"] is True
    assert _first(rows, "10.1.1.1/32", "10.2.2.2/32")[1] == INDETERMINATE


def test_the_rules_query_counts_a_service_object_that_is_not_a_svcobject():
    """The query reads an application held as a NetObject on the SVC edge as an
    opaque service member."""
    assert "NOT x:SvcObject" in fw._RULEBASE_RULES
    assert "size(svc_foreign) > 0 OR" in fw._RULEBASE_RULES
    assert "count(DISTINCT sv0) + size(svc_foreign) AS svc_obj_count" in fw._RULEBASE_RULES


def test_the_device_verdict_compares_install_on_with_the_binding_gateway(monkeypatch):
    raw = _cp_raw([_cp_rule("r1", 1, "accept", **{"install-on": ["gw-a"]}), _cp_rule("r2", 2, "drop")])
    _, rows = _cp_rows(raw)
    rb_row = {
        "rb_uid": "cp:layer",
        "rb_name": "Network",
        "vendor": "checkpoint",
        "af": None,
        "default_action": None,
        "default_action_unknown": None,
        "global_state_policy": None,
        "match_context": "device",
        "chain": None,
        "approximate": False,
        "owner_raw_uid": "gw-b",
    }

    def fake_read(session, query, **params):
        if "ENFORCES" in query and "owner_raw_uid" in query:
            return [rb_row]
        if "HAS_RULE" in query:
            return rows
        return []

    monkeypatch.setattr(path, "_read", fake_read)
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: None)
    v = path._device_rulebase_verdict(
        None,
        "dev:b",
        "if:in",
        "if:out",
        path._intervals(["10.1.1.1/32"]),
        path._intervals(["10.2.2.2/32"]),
        22,
        "tcp",
        4,
    )
    assert classify_action(v["action"]) == DENY


# --- Check Point NAT install-on, gate and analysis model ----------------------------


def _nat_row(**kw):
    base = {
        "rb_uid": "cp:nat",
        "rb_name": "NAT:Policy",
        "approximate": False,
        "owners": ["gw-b"],
        "install_on": [],
        "install_on_unresolved": False,
        "auto_generated": False,
        "orig_src_present": True,
        "orig_dst_present": False,
        "xlate_src_present": True,
        "xlate_dst_present": False,
        "uid": "cp:n1",
        "pos": 1,
        "kind": None,
        "method": "hide",
        "enabled": True,
        "exclude": False,
        "translation": None,
        "translation_port": None,
        "direction": None,
        "static_flag": False,
        "orig_src_raw": None,
        "orig_dst_raw": None,
        "orig_src_port": None,
        "orig_dst_port": None,
        "orig_port": None,
        "xlate_port": None,
        "protocol": None,
        "in_if": None,
        "out_if": None,
        "translation_interface": None,
        "xlate_src_original": False,
        "xlate_dst_original": False,
        "rule_approximate": False,
        "orig_src_addrs": ["10.1.0.0/16"],
        "orig_dst_addrs": [],
        "xlate_src_addrs": ["198.51.100.1"],
        "xlate_dst_addrs": [],
    }
    return {**base, **kw}


def test_a_nat_rule_installed_on_another_gateway_is_not_applied():
    assert _nat_stage_rules([_nat_row(install_on=["gw-a"])], "snat", None) == []
    kept = _nat_stage_rules([_nat_row(install_on=["gw-b"])], "snat", None)
    assert len(kept) == 1 and not kept[0]["opaque"]


def test_a_nat_rule_whose_install_on_cannot_be_placed_is_opaque():
    kept = _nat_stage_rules([_nat_row(install_on=["gw-a"], install_on_unresolved=True)], "snat", None)
    assert len(kept) == 1 and kept[0]["opaque"] is True
    kept = _nat_stage_rules([_nat_row(install_on=["gw-a"], owners=[])], "snat", None)
    assert len(kept) == 1 and kept[0]["opaque"] is True


def _inventory(batch) -> GraphInventory:
    nodes = {n.uid: GraphNode(n.uid, frozenset({n.label}), MappingProxyType(n.props)) for n in batch.nodes}
    relations = [
        GraphRelation(
            f"relation:{i}", r.rel_type, r.start_uid, r.end_uid, MappingProxyType({**r.key, **r.props})
        )
        for i, r in enumerate(batch.rels)
    ]
    return _rebuild(GraphInventory("a" * 64, "seed", {}, {}, {}, {}, True, (), 0), nodes, relations)


def _nat_rule(install_on: list[str]) -> dict[str, Any]:
    host = {"uid": "lan", "name": "lan", "type": "network", "subnet4": "10.1.0.0", "mask-length4": 16}
    return {
        "uid": "n1",
        "type": "nat-rule",
        "rule-number": 1,
        "enabled": True,
        "method": "hide",
        "original-source": host["uid"],
        "original-destination": "any",
        "original-service": "any",
        "translated-source": "any",
        "translated-destination": "any",
        "translated-service": "any",
        "install-on": install_on,
    }


def test_the_analysis_model_reads_nat_install_on_as_the_gate_does():
    raw = _cp_raw([_cp_rule("r1", 1, "drop")], nat=[_nat_rule(["gw-a"])])
    graph = _inventory(checkpoint_batch.normalize(raw, mgmt="manager", domain="domain"))
    device_b = next(u for u in graph.labels["Device"] if graph.nodes[u].props.get("cp_raw_uid") == "gw-b")
    device_a = next(u for u in graph.labels["Device"] if graph.nodes[u].props.get("cp_raw_uid") == "gw-a")
    kw = {"ingress_interface_uid": None, "egress_interface_uid": None, "address_family": 4}
    assert normalize_nat_rules(graph, device_b, **kw) == ()
    on_a = normalize_nat_rules(graph, device_a, **kw)
    assert on_a
    assert all(s.predicate != Constant(False) and s.gap_code != "NAT_INSTALL_ON_UNKNOWN" for s in on_a)


def _terms(predicate) -> list[Any]:
    if isinstance(predicate, (AllOf, AnyOf)):
        return [t for term in predicate.terms for t in _terms(term)]
    if isinstance(predicate, Not):
        return _terms(predicate.term)
    return [predicate]


def test_the_analysis_model_reads_policy_targets_as_every_package_target():
    """Policy Targets is the package's own targets."""
    raw = _cp_raw([_cp_rule("r1", 1, "accept")])
    graph = _inventory(checkpoint_batch.normalize(raw, mgmt="manager", domain="domain"))
    rulebase = next(uid for uid in graph.labels["FwRulebase"] if graph.nodes[uid].props["kind"] == "access")
    device = next(u for u in graph.labels["Device"] if graph.nodes[u].props.get("cp_raw_uid") == "gw-a")
    context = ExecutionContext("estate", "manager", "domain", device, "vrf", 4)
    policy = checkpoint_policy(graph, (rulebase,), context, Constant(True))
    assert policy is not None
    (rule,) = [r for layer in policy.layers for r in layer.rules if r.uid.endswith("r1")]
    codes = {t.code for t in _terms(rule.predicate) if isinstance(t, Unknown)}
    assert "CP_INSTALL_TARGET_UNRESOLVED" not in codes
