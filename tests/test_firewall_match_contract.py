"""The first rule of each case comes back INDETERMINATE for a flow its known fields match."""

from __future__ import annotations

import importlib
import re
from types import SimpleNamespace
from typing import Any

import pytest
from tests.test_cisco_common import _PERMIT_ANY_ACE, _acl_batch
from tests.test_cisco_common import DEV as CISCO_DEV
from tests.test_cisco_common import SCOPE as CISCO_SCOPE
from tests.test_firewall_rule_scope import ALLOW_ALL, RFC1918, _cp_raw, _cp_rule, _gw_batch, _inventory, _zone
from tests.test_firewall_rule_scope import _rows as _unifi_cp_rows
from tests.test_vyos_match_clauses import _batch as _vyos_batch
from tests.test_vyos_match_clauses import _forward
from tests.test_vyos_match_clauses import _rows as _vyos_rows

from hst.analysis_model.catalogs import project_catalogs
from hst.collectors import iosxe, nxos
from hst.collectors.checkpoint import normalize_checkpoint
from hst.collectors.cisco_common import parse_access_groups, parse_vlan_filters
from hst.core import uid
from hst.path.addrsets import _intervals
from hst.path.gates.firewall import _RULEBASE_RULES, _first_match_point
from hst.path.verdict import INDETERMINATE
from hst.policy.acl import _rule as _acl_rule
from hst.policy.graph import GraphPolicyNormalizer
from hst.policy.ir import Constant, ExecutionContext, Unknown

_VYOS_RB = "vyos:gw:fw:ipv4-forward"
_CLASSIC_RB = "unifi:default:fw:lan_in"
_ZONE_RB = "unifi:default:fw:zone:z2:z1"


def _without(batch, rel_type: str):
    """The batch as the gate reads it once the loader dropped every `rel_type`
    edge, the shape an edge to a node that was never written leaves."""
    return SimpleNamespace(nodes=batch.nodes, rels=[r for r in batch.rels if r.rel_type != rel_type])


def _decide(rows: list[dict[str, Any]], src: str, dst: str, port: int, proto: str) -> tuple[str, str] | None:
    hit = _first_match_point(rows, None, None, _intervals([src]), _intervals([dst]), port, proto)
    return None if hit is None else (hit[0]["uid"], hit[0]["action"])


# --- VyOS -----------------------------------------------------------------------------


def _vyos(first: dict[str, Any], last_action: str, groups: dict | None = None, drop: str | None = None):
    batch = _vyos_batch(_forward({"10": first, "20": {"action": last_action}}, groups=groups))
    rows = _vyos_rows(_without(batch, drop) if drop else batch, _VYOS_RB)
    return rows, f"{_VYOS_RB}:10"


def vyos_unknown_rule_key():
    return _vyos({"action": "accept", "future-match": {"value": "x"}}, "drop")


def vyos_unmodelled_side_key():
    return _vyos({"action": "accept", "source": {"geoip": {"country-code": ["us"]}}}, "drop")


def vyos_dropped_source_edge():
    groups = {"address-group": {"BLOCKED": {"address": ["192.168.30.0/24"]}}}
    return _vyos(
        {"action": "drop", "source": {"group": {"address-group": "BLOCKED"}}}, "accept", groups, "SRC"
    )


# --- UniFi classic rules --------------------------------------------------------------


def _classic(first: dict[str, Any], last_action: str, drop: str | None = None):
    def rule(rid: str, index: int, action: str, **extra: Any) -> dict[str, Any]:
        return {
            "_id": rid,
            "ruleset": "LAN_IN",
            "rule_index": index,
            "name": rid,
            "action": action,
            "enabled": True,
            "protocol": "all",
            "src_firewallgroup_ids": [],
            "dst_firewallgroup_ids": [],
            **extra,
        }

    batch = _gw_batch(
        firewall_rules=[rule("r-first", 2000, **first), rule("r-last", 2001, last_action)],
        firewall_groups=[RFC1918],
    )
    rows = _unifi_cp_rows(_without(batch, drop) if drop else batch, _CLASSIC_RB)
    return rows, f"{_CLASSIC_RB}:r-first"


def unifi_classic_unmodelled_qualifier():
    return _classic({"action": "accept", "src_mac_address": "aa:bb:cc:dd:ee:ff"}, "drop")


def unifi_classic_dropped_source_edge():
    return _classic({"action": "drop", "src_firewallgroup_ids": ["g-rfc"]}, "accept", "SRC")


# --- UniFi zone policies --------------------------------------------------------------


def unifi_zone_unmodelled_schedule():
    _, rows = _zone({"schedule": {"mode": "EVERY_DAY", "time_range_start": "08:00"}})
    return rows, f"{_ZONE_RB}:first"


def unifi_zone_dropped_source_edge():
    """An IP-target side whose SRC edge the loader dropped carries no object
    and is not Any. The collector writes an IP group side opaque."""
    first = {
        "action": "BLOCK",
        "source": {"zone_id": "z2", "matching_target": "IP", "ips": ["192.168.40.0/24"]},
    }
    batch, _ = _zone(first, ALLOW_ALL)
    return _unifi_cp_rows(_without(batch, "SRC"), _ZONE_RB), f"{_ZONE_RB}:first"


# --- Check Point ----------------------------------------------------------------------


def _checkpoint(first: dict[str, Any], last_action: str):
    raw = _cp_raw([_cp_rule("r1", 1, **first), _cp_rule("r2", 2, last_action)])
    batch = normalize_checkpoint(raw, mgmt="manager", domain="domain")
    rb = next(n.uid for n in batch.nodes if n.label == "FwRulebase" and n.props.get("kind") == "access")
    rows = _unifi_cp_rows(batch, rb)
    return rows, next(r["uid"] for r in rows if r["uid"].endswith(":r1"))


def checkpoint_unmodelled_time_column():
    return _checkpoint({"action": "accept", "time": ["office-hours"]}, "drop")


def checkpoint_source_object_missing_from_the_dictionary():
    """The collector writes an opaque object for a uid the objects
    dictionary does not carry."""
    return _checkpoint({"action": "drop", "source": ["host-not-collected"]}, "accept")


# --- a field outside the normalizer's allow-list ----------------------------------------
#
# UniFi and Check Point keep an allow-list of the rule fields they model, as VyOS
# does: a field a controller or management release adds is not read as absent.


def unifi_classic_unknown_field():
    return _classic({"action": "accept", "match_device_fingerprint": "camera"}, "drop")


def unifi_zone_unknown_field():
    _, rows = _zone({"match_web_domains": ["example.com"]})
    return rows, f"{_ZONE_RB}:first"


def unifi_zone_unknown_side_field():
    _, rows = _zone({"source": {"zone_id": "z2", "matching_target": "ANY", "match_mac": "aa:bb:cc:dd:ee:ff"}})
    return rows, f"{_ZONE_RB}:first"


def checkpoint_unknown_field():
    return _checkpoint({"action": "accept", "custom-fields": {"field-1": "x"}}, "drop")


# --- Cisco interface ACLs ---------------------------------------------------------------

_CISCO_DENY_ANY = {**_PERMIT_ANY_ACE, "action": "deny"}


def _cisco(aces: list[dict[str, Any]], drop: str | None = None):
    """An access list bound inbound on Ethernet1/1, its first ACE under test
    and a deny of everything after it."""
    acl = {
        "lists": {"EDGE": [*aces, _CISCO_DENY_ANY]},
        "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE"}],
    }
    batch = _acl_batch(acl)
    rb = f"{CISCO_SCOPE}:acl:{uid.exact_slug('EDGE')}"
    rows = _unifi_cp_rows(_without(batch, drop) if drop else batch, rb)
    return rows, f"{rb}:1"


def iosxe_unknown_template_value():
    """A template value the IOS-XE ACE conversion does not read (a later
    template's DSCP column)."""
    record = {
        "acl_type": "Extended",
        "acl_name": "EDGE",
        "line_num": "10",
        "action": "permit",
        "protocol": "ip",
        "src_any": "any",
        "dst_any": "any",
        "log": "",
        "dscp": "ef",
    }
    (ace,) = iosxe._acl_filter_records([record])["EDGE"]
    return _cisco([ace])


def nxos_unknown_column():
    """An NX-OS `seqno` column the ACE conversion does not read."""
    seq = {
        "seqno": 10,
        "permitdeny": "permit",
        "proto_str": "ip",
        "src_any": "any",
        "dest_any": "any",
        "dscp": "ef",
    }
    payload = {
        "TABLE_ip_ipv6_mac": {"ROW_ip_ipv6_mac": [{"acl_name": "EDGE", "TABLE_seqno": {"ROW_seqno": [seq]}}]}
    }
    (ace,) = nxos._acl_filter_records(payload)["EDGE"]
    return _cisco([ace])


def cisco_dropped_source_edge():
    ace = {**_CISCO_DENY_ANY, "src_any": False, "src": "192.168.30.0/24"}
    rows, first = _cisco([ace], "SRC")
    return [rows[0], {**rows[-1], "action": "permit"}], first


_FLOWS = {
    "vyos": ("192.168.30.50/32", "10.20.30.40/32"),
    "unifi-classic": ("192.168.30.50/32", "192.168.1.20/32"),
    "unifi-zone": ("192.168.40.9/32", "192.168.1.20/32"),
    "checkpoint": ("10.1.1.1/32", "10.2.2.2/32"),
    "cisco": ("192.168.30.50/32", "10.20.30.40/32"),
}

_UNMODELLED = [
    ("vyos", vyos_unknown_rule_key),
    ("vyos", vyos_unmodelled_side_key),
    ("unifi-classic", unifi_classic_unmodelled_qualifier),
    ("unifi-classic", unifi_classic_unknown_field),
    ("unifi-zone", unifi_zone_unmodelled_schedule),
    ("unifi-zone", unifi_zone_unknown_field),
    ("unifi-zone", unifi_zone_unknown_side_field),
    ("checkpoint", checkpoint_unmodelled_time_column),
    ("checkpoint", checkpoint_unknown_field),
    ("checkpoint", checkpoint_source_object_missing_from_the_dictionary),
    ("cisco", iosxe_unknown_template_value),
    ("cisco", nxos_unknown_column),
]

_EMPTY_SIDE = [
    ("vyos", vyos_dropped_source_edge),
    ("unifi-classic", unifi_classic_dropped_source_edge),
    ("unifi-zone", unifi_zone_dropped_source_edge),
    ("cisco", cisco_dropped_source_edge),
]


@pytest.mark.parametrize(("vendor", "build"), _UNMODELLED, ids=[b.__name__ for _, b in _UNMODELLED])
def test_a_match_criterion_the_normalizer_does_not_model_leaves_the_rule_undecided(vendor, build):
    """An accept rule that also matches on a criterion its normalizer does not
    model is neither applied to a flow its addresses and service match nor
    skipped past to the drop rule after it."""
    rows, first_uid = build()
    src, dst = _FLOWS[vendor]
    assert _decide(rows, src, dst, 22, "tcp") == (first_uid, INDETERMINATE)


@pytest.mark.parametrize(("vendor", "build"), _EMPTY_SIDE, ids=[b.__name__ for _, b in _EMPTY_SIDE])
def test_a_side_with_no_object_that_is_not_any_leaves_the_rule_undecided(vendor, build):
    """A drop rule whose source carries no object and is not flagged Any is not
    a rule that matches nothing: the accept rule after it does not decide the
    flow in its place."""
    rows, first_uid = build()
    first = next(r for r in rows if r["uid"] == first_uid)
    assert first["src_any"] is False and first["src_obj_count"] == 0
    src, dst = _FLOWS[vendor]
    assert _decide(rows, src, dst, 22, "tcp") == (first_uid, INDETERMINATE)


def test_a_protocol_name_outside_the_gate_table_leaves_a_deny_rule_undecided():
    """VyOS writes a protocol name from /etc/protocols verbatim. A drop rule for
    one the gate's table does not carry is not a confident miss for a flow that
    names the protocol by number."""
    rows, first_uid = _vyos({"action": "drop", "protocol": "igrp"}, "accept")
    src, dst = _FLOWS["vyos"]
    assert _decide(rows, src, dst, 22, "9") == (first_uid, INDETERMINATE)
    assert _decide(rows, src, dst, 22, "tcp") == (first_uid, INDETERMINATE)


# --- the names of the fields a normalizer does not model ------------------------------


def _classic_batch(**extra: Any):
    rule = {
        "_id": "r-first",
        "ruleset": "LAN_IN",
        "rule_index": 2000,
        "name": "r-first",
        "action": "accept",
        "enabled": True,
        "protocol": "all",
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": [],
        **extra,
    }
    return _gw_batch(firewall_rules=[rule], firewall_groups=[RFC1918]), f"{_CLASSIC_RB}:r-first"


def _zone_batch(**extra: Any):
    batch, _rows = _zone(extra)
    return batch, f"{_ZONE_RB}:first"


def _checkpoint_batch(**columns: Any):
    raw = _cp_raw([_cp_rule("r1", 1, "accept", **columns)])
    batch = normalize_checkpoint(raw, mgmt="manager", domain="domain")
    return batch, next(n.uid for n in batch.nodes if n.label == "FwRule" and n.uid.endswith(":r1"))


def _cisco_batch(**extra: Any):
    seq = {
        "seqno": 10,
        "permitdeny": "permit",
        "proto_str": "ip",
        "src_any": "any",
        "dest_any": "any",
        **extra,
    }
    payload = {
        "TABLE_ip_ipv6_mac": {"ROW_ip_ipv6_mac": [{"acl_name": "EDGE", "TABLE_seqno": {"ROW_seqno": [seq]}}]}
    }
    acl = {
        "lists": nxos._acl_filter_records(payload),
        "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE"}],
    }
    return _acl_batch(acl), f"{CISCO_SCOPE}:acl:{uid.exact_slug('EDGE')}:1"


@pytest.mark.parametrize(
    ("build", "extra", "names"),
    [
        (_classic_batch, {}, []),
        (
            _classic_batch,
            {"match_device_fingerprint": "camera", "zz_future": 1},
            ["match_device_fingerprint", "zz_future"],
        ),
        (_zone_batch, {}, []),
        (
            _zone_batch,
            {"source": {"zone_id": "z2", "matching_target": "ANY", "match_mac": "aa:bb:cc:dd:ee:ff"}},
            ["source match_mac"],
        ),
        (_checkpoint_batch, {}, []),
        (_checkpoint_batch, {"custom-fields": {"field-1": "x"}}, ["custom-fields"]),
        (_cisco_batch, {}, []),
        (_cisco_batch, {"dscp": "ef", "ttl": ""}, ["dscp"]),
    ],
)
def test_every_field_outside_the_allow_list_is_recorded_on_the_rule(build, extra, names):
    """An explicit empty list says every field was modeled."""
    batch, rule_uid = build(**extra)
    props = next(n.props for n in batch.nodes if n.uid == rule_uid)
    assert props["unmodeled_fields"] == names
    if names and "states_opaque" in props:
        assert props["states_opaque"] is True
        assert all(repr(name) in props["states_opaque_reason"] for name in names)


def test_a_cisco_ace_names_its_unmodeled_field_on_its_service_side():
    batch, rule_uid = _cisco_batch(dscp="ef")
    svc = next(n.props for n in batch.nodes if n.uid == f"{rule_uid}:svc")
    assert svc["opaque"] is True and "'dscp'" in svc["opaque_reason"]
    assert svc["opaque_note"] == "field dscp"


# --- Cisco filter bindings --------------------------------------------------------------


def test_every_interface_filter_binding_form_is_read():
    lines = [
        "interface Ethernet1/1",
        "  ip access-group V4-IN in",
        "  ip port access-group PACL-IN in",
        "  ipv6 traffic-filter V6-IN in",
        "  ipv6 port traffic-filter V6-PACL in",
        "  mac access-group MAC-IN in",
        "  mac port access-group MAC-PACL",
        "interface GigabitEthernet0/0/0/0",
        " ipv4 access-group XR-IN ingress hardware-count",
        " ipv6 access-group XR6-OUT egress",
        " ipv4 access-group common C1 XR-C ingress",
        " ipv4 access-group XR-ODD ingress compress level 3 extra",
    ]
    odd = "ipv4 access-group XR-ODD ingress compress level 3 extra"
    assert parse_access_groups(lines) == [
        {"interface": "Ethernet1/1", "direction": "in", "acl": "V4-IN"},
        {"interface": "Ethernet1/1", "direction": "in", "acl": "PACL-IN"},
        {"interface": "Ethernet1/1", "direction": "in", "acl": "V6-IN", "family": "ipv6"},
        {"interface": "Ethernet1/1", "direction": "in", "acl": "V6-PACL", "family": "ipv6"},
        {"interface": "Ethernet1/1", "direction": "in", "acl": "MAC-IN", "family": "mac"},
        {"interface": "Ethernet1/1", "direction": "in", "acl": "MAC-PACL", "family": "mac"},
        {"interface": "GigabitEthernet0/0/0/0", "direction": "in", "acl": "XR-IN"},
        {"interface": "GigabitEthernet0/0/0/0", "direction": "out", "acl": "XR6-OUT", "family": "ipv6"},
        {"interface": "GigabitEthernet0/0/0/0", "direction": "in", "acl": "C1 XR-C", "family": "common"},
        {"interface": "GigabitEthernet0/0/0/0", "direction": "in", "acl": odd, "family": "unparsed"},
        {"interface": "GigabitEthernet0/0/0/0", "direction": "out", "acl": odd, "family": "unparsed"},
    ]


def test_a_vlan_filter_binds_each_vlan_interface_in_both_directions():
    bindings = parse_vlan_filters(
        ["vlan filter GUEST-MAP vlan-list 10, 20-21", "vlan filter BAD vlan-list 5000"]
    )
    assert [(b["interface"], b["direction"]) for b in bindings] == [
        (f"Vlan{vid}", side) for vid in (10, 20, 21) for side in ("in", "out")
    ]
    assert {(b["acl"], b["family"]) for b in bindings} == {("GUEST-MAP", "vlan-map")}


def test_a_vlan_filter_line_with_4000_items_and_a_trailing_word_binds_nothing():
    line = "vlan filter M vlan-list " + ",".join(["1"] * 4000) + " x"
    assert parse_vlan_filters([line]) == []


_CISCO_FAMILIES = [
    (
        ["interface Ethernet1/1", "  ipv6 traffic-filter EDGE in"],
        "acl6",
        6,
        "Ethernet1/1",
        "IPv6 access lists",
    ),
    (
        ["interface Ethernet1/1", "  mac access-group EDGE in"],
        "macacl",
        None,
        "Ethernet1/1",
        "MAC access lists",
    ),
    (
        ["interface Ethernet1/1", "  ipv4 access-group common C1 EDGE ingress"],
        "aclcommon",
        None,
        "Ethernet1/1",
        "common access list",
    ),
    (
        ["interface Ethernet1/1", "  ip access-group EDGE in extra"],
        "aclline",
        None,
        "Ethernet1/1",
        "could not be read",
    ),
    (["vlan filter EDGE vlan-list 10"], "vacl", None, "Vlan10", "VLAN access maps"),
]


@pytest.mark.parametrize(
    ("lines", "segment", "af", "interface", "reason"), _CISCO_FAMILIES, ids=[f[1] for f in _CISCO_FAMILIES]
)
def test_a_filter_binding_of_an_unread_family_leaves_its_interface_undecided(
    lines, segment, af, interface, reason
):
    """Each binding is a rulebase of its family bound to the interface."""
    bindings = parse_access_groups(lines) + parse_vlan_filters(lines)
    # an IPv4 list of the same name is collected; only the IPv4 family reads it
    batch = _acl_batch({"lists": {"EDGE": [_PERMIT_ANY_ACE]}, "bindings": bindings})
    rulebases = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}
    (rb,) = [u for u in rulebases if u.startswith(f"{CISCO_SCOPE}:{segment}:")]
    assert rulebases[rb].get("af") == af and rulebases[rb]["match_context"] == "interface-acl"
    edges = {
        (r.start_uid, r.props.get("direction"))
        for r in batch.rels
        if r.rel_type == "PROTECTED_BY" and r.end_uid == rb
    }
    assert (uid.interface(CISCO_DEV, interface), "in") in edges
    rows = _unifi_cp_rows(batch, rb)
    assert [r["uid"] for r in rows] == [f"{rb}:1"]
    assert reason in rows[0]["src_opaque_reasons"][0]
    src, dst = _FLOWS["cisco"]
    assert _decide(rows, src, dst, 22, "tcp") == (f"{rb}:1", INDETERMINATE)


def test_a_port_acl_is_judged_by_its_ipv4_entries():
    bindings = parse_access_groups(["interface Ethernet1/1", "  ip port access-group EDGE in"])
    batch = _acl_batch({"lists": {"EDGE": [_PERMIT_ANY_ACE]}, "bindings": bindings})
    rb = f"{CISCO_SCOPE}:acl:{uid.exact_slug('EDGE')}"
    src, dst = _FLOWS["cisco"]
    assert _decide(_unifi_cp_rows(batch, rb), src, dst, 22, "tcp") == (f"{rb}:1", "permit")


def test_an_ipv4_and_an_ipv6_list_of_one_name_are_two_rulebases():
    lines = ["interface Ethernet1/1", "  ip access-group EDGE in", "  ipv6 traffic-filter EDGE in"]
    batch = _acl_batch({"lists": {"EDGE": [_PERMIT_ANY_ACE]}, "bindings": parse_access_groups(lines)})
    afs = {n.uid.split(":")[-2]: n.props.get("af") for n in batch.nodes if n.label == "FwRulebase"}
    assert afs == {"acl": 4, "acl6": 6}


@pytest.mark.parametrize("family", ["iosxe", "nxos"])
def test_the_ios_and_nxos_parse_reads_ipv6_port_and_vlan_filter_bindings(family):
    module = {"iosxe": iosxe, "nxos": nxos}[family]
    raw = importlib.import_module(f"tests.test_{family}").RAW
    config = "interface Vlan10\n ipv6 traffic-filter V6-IN in\n ip port access-group PACL-IN in\n"
    vlan_filter = "vlan filter MAP vlan-list 30\n"
    inter = module.parse({**raw, module.CMD_INTERFACE_CONFIG: config, module.CMD_VLAN_FILTER: vlan_filter})
    assert {(b["interface"], b["acl"], b.get("family")) for b in inter["acl"]["bindings"]} == {
        ("Vlan10", "V6-IN", "ipv6"),
        ("Vlan10", "PACL-IN", None),
        ("Vlan30", "MAP", "vlan-map"),
    }


# --- the analysis model and policy readers of FwRule ----------------------------------

# the columns the gate's rules query returns, which the analysis model's catalog
# row stands in for when policy analysis runs on the symbolic engine
_GATE_COLUMNS = set(re.findall(r"\bAS (\w+)", _RULEBASE_RULES.rsplit("RETURN r.uid", 1)[1])) | {"uid"}


def _cp_catalog(rules: list[dict[str, Any]]):
    batch = normalize_checkpoint(_cp_raw(rules), mgmt="manager", domain="domain")
    rb = next(n.uid for n in batch.nodes if n.label == "FwRulebase" and n.props.get("kind") == "access")
    projected = project_catalogs(_inventory(batch), manifest=None)
    return batch, rb, projected.model_catalogs()[0]["firewall"][rb]


def test_the_catalog_row_carries_every_column_of_the_gate_rules_query():
    _batch, _rb, rows = _cp_catalog([_cp_rule("r1", 1, "accept")])
    assert {"install_on", "install_on_unresolved", "unmodeled_fields"} <= _GATE_COLUMNS
    assert sorted(_GATE_COLUMNS - set(rows[0])) == []


def test_the_catalog_reads_an_install_on_it_cannot_place_as_the_gate_does():
    rules = [_cp_rule("r1", 1, "accept", **{"install-on": ["gw-group"]}), _cp_rule("r2", 2, "drop")]
    batch, rb, rows = _cp_catalog(rules)
    first = next(r["uid"] for r in rows if r["uid"].endswith(":r1"))
    src, dst = _FLOWS["checkpoint"]
    assert _decide(rows, src, dst, 22, "tcp") == (first, INDETERMINATE)
    assert _decide(_unifi_cp_rows(batch, rb), src, dst, 22, "tcp") == (first, INDETERMINATE)


def test_the_gate_reads_unmodeled_fields_on_their_own():
    rows, first_uid = unifi_classic_unknown_field()
    rows = [{**rows[0], "states_opaque": False, "unmodeled_fields": ["zz_future"]}, *rows[1:]]
    src, dst = _FLOWS["unifi-classic"]
    hit = _first_match_point(rows, None, None, _intervals([src]), _intervals([dst]), 22, "tcp")
    assert hit is not None and (hit[0]["uid"], hit[0]["action"]) == (first_uid, INDETERMINATE)
    assert "zz_future" in hit[0]["indeterminate_reason"]


def _unknown_codes(predicate: Any) -> set[str]:
    if isinstance(predicate, Unknown):
        return {predicate.code}
    terms = list(getattr(predicate, "terms", ()) or ())
    if hasattr(predicate, "term"):
        terms.append(predicate.term)
    return {code for term in terms for code in _unknown_codes(term)}


def test_the_policy_reader_reads_unmodeled_fields_as_the_gate_does():
    """The symbolic engine's reader of FwRule makes a rule carrying an unmodeled
    field unknown, and reads an empty list as no field at all."""
    context = ExecutionContext("estate", "graph", "graph", "dev:gw", "vrf", 4)
    for extra, expected in (({"match_device_fingerprint": "camera"}, True), ({}, False)):
        batch, rule_uid = _classic_batch(**extra)
        policy = GraphPolicyNormalizer(_inventory(batch), context).policy(
            (_CLASSIC_RB,), installation=Constant(True)
        )
        (rule,) = [r for layer in policy.layers for r in layer.rules if r.uid == rule_uid]
        codes = _unknown_codes(rule.predicate)
        assert ("GRAPH_RULE_UNMODELED_FIELD" in codes) is expected
        assert "GRAPH_RULE_UNSUPPORTED_FIELD" not in codes


def test_the_cisco_policy_adapter_reads_unmodeled_fields():
    base = {"uid": "r1", "position": 1, "action": "permit", "enabled": True}
    base |= {"src_any": True, "dst_any": True, "svc_any": True}
    flagged = _acl_rule({**base, "unmodeled_fields": ["dscp"]}, "rb", 0, 4)
    assert "UNMODELED_ACL_FIELD" in _unknown_codes(flagged.predicate)
    plain = _acl_rule({**base, "unmodeled_fields": []}, "rb", 0, 4)
    assert plain.action == "permit" and not _unknown_codes(plain.predicate)
