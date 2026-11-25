"""The original and translated service of a Check Point NAT rule.

The collector records what an original service matches, or marks the rule's
service match unknown with a reason.
"""

from __future__ import annotations

from typing import Any

from tests.test_checkpoint_policy_facts import (
    DOMAIN,
    OBJECTS,
    _batch,
    _device,
    _estate,
    _nat_graph,
    _packet,
    _truth,
)

import hst.path as path
from hst.path.gates.nat import _NAT_RULES_QUERY_STRICT, _nat_partition, _nat_stage_rules
from hst.policy.nat import _row as nat_row
from hst.policy.nat import normalize_nat_rules

VIP = {"uid": "vip", "name": "vip", "type": "host", "domain": DOMAIN, "ipv4-address": "203.0.113.10"}
WEBSRV = {"uid": "websrv", "name": "websrv", "type": "host", "domain": DOMAIN, "ipv4-address": "10.1.1.10"}


def _svc(uid: str, kind: str, **extra: Any) -> dict[str, Any]:
    return {"uid": uid, "name": uid, "type": kind, "domain": DOMAIN, **extra}


HTTP = _svc("http", "service-tcp", port="80")
HTTPS = _svc("https", "service-tcp", port="443")
DNS = _svc("dns", "service-udp", port="53")
WEB_GROUP = {**_svc("web-grp", "service-group"), "name": "Web", "members": ["http", "https"]}
MIXED = {**_svc("mixed", "service-group"), "members": ["http", "dns"]}
ECHO = _svc("echo-request", "service-icmp", **{"icmp-type": 8})
OTHER = _svc("other", "service-other", **{"ip-protocol": 47})
TCP_NOPORT = _svc("tcp-noport", "service-tcp")
SERVICES = [VIP, WEBSRV, HTTP, HTTPS, DNS, WEB_GROUP, MIXED, ECHO, OTHER, TCP_NOPORT]


def _raw(original_service: str, translated_service: str = "any") -> dict[str, Any]:
    """A manual static rule: the VIP is translated to the web server for
    `original_service` only."""
    rule = {
        "uid": "n1",
        "type": "nat-rule",
        "rule-number": 1,
        "enabled": True,
        "method": "static",
        "original-source": "any",
        "original-destination": "vip",
        "original-service": original_service,
        "translated-source": "any",
        "translated-destination": "websrv",
        "translated-service": translated_service,
        "install-on": ["policy-targets"],
    }
    return _estate(nat={"Policy": [{"rulebase": [rule], "objects-dictionary": [*OBJECTS, *SERVICES]}]})


def _rule_props(raw: dict[str, Any]) -> dict[str, Any]:
    (rule,) = [n for n in _batch(raw).nodes if n.label == "NatRule"]
    return dict(rule.props)


def _dnat_spec(raw: dict[str, Any]):
    graph, _rulebase, _rule = _nat_graph(raw)
    specs = normalize_nat_rules(
        graph, _device(graph, "gw-a"), ingress_interface_uid=None, egress_interface_uid=None, address_family=4
    )
    (spec,) = [s for s in specs if s.stage == "dnat"]
    return spec


def _dnat_rule(raw: dict[str, Any]) -> dict[str, Any]:
    graph, rulebase, rule = _nat_graph(raw)
    (resolved,) = _nat_stage_rules([nat_row(graph, rulebase, rule, False, {"gw-a"})], "dnat", None)
    return resolved


def _tracer_parts(raw: dict[str, Any], port: int, proto: str) -> list[dict[str, Any]]:
    """The tracer's dNAT partition of one flow to the VIP."""
    rule = _dnat_rule(raw)
    return _nat_partition(
        [rule], path._intervals(["10.9.9.1"]), path._intervals(["203.0.113.10"]), port, proto
    )


def test_a_service_group_records_the_protocol_and_ports_of_its_members():
    props = _rule_props(_raw("web-grp"))
    assert props["orig_service"] == "Web"
    assert props["protocol"] == "tcp" and props["orig_port"] == "443,80"
    assert props["service_unknown"] is False and props.get("approximate") is None


def test_ssh_to_a_web_vip_is_not_translated_by_the_web_rule():
    raw = _raw("web-grp")
    ssh = _tracer_parts(raw, 22, "tcp")
    assert [part["rule"] for part in ssh] == [None]
    (https,) = _tracer_parts(raw, 443, "tcp")
    assert https["rule"] is not None and not https["rule"]["opaque"]
    assert https["new_dst"] == path._intervals(["10.1.1.10"])
    spec = _dnat_spec(raw)
    assert spec.gap_code is None
    assert _truth(spec.predicate, _packet("10.9.9.1", "203.0.113.10", 6, 22)) is False
    assert _truth(spec.predicate, _packet("10.9.9.1", "203.0.113.10", 6, 443)) is True


def test_an_icmp_service_claims_icmp_only_and_leaves_it_undecided():
    props = _rule_props(_raw("echo-request"))
    assert props["protocol"] == "icmp" and props["approximate"] is True and props["service_unknown"] is True
    assert "ICMP type" in props["approximate_reason"]
    raw = _raw("echo-request")
    assert [part["rule"] for part in _tracer_parts(raw, 22, "tcp")] == [None]
    (icmp,) = _tracer_parts(raw, None, "icmp")  # type: ignore[arg-type]
    assert icmp["rule"]["opaque"] and "ICMP type" in icmp["rule"]["role_note"]
    spec = _dnat_spec(raw)
    assert spec.gap_code == "NAT_SERVICE_UNKNOWN"
    assert _truth(spec.predicate, _packet("10.9.9.1", "203.0.113.10", 6, 22)) is False
    assert _truth(spec.predicate, _packet("10.9.9.1", "203.0.113.10", 1, 0)) is None


def test_a_service_without_a_protocol_or_port_makes_the_translation_undecided():
    for service, protocol in (("other", None), ("tcp-noport", "tcp")):
        props = _rule_props(_raw(service))
        assert props.get("protocol") == protocol, service
        assert props["approximate"] is True and props["service_unknown"] is True, service
        spec = _dnat_spec(_raw(service))
        assert spec.gap_code == "NAT_SERVICE_UNKNOWN", service
        assert _truth(spec.predicate, _packet("10.9.9.1", "203.0.113.10", 6, 22)) is None, service


def test_a_group_pairing_different_ports_with_different_protocols_is_a_superset():
    props = _rule_props(_raw("mixed"))
    assert props["protocol"] == "tcp_udp" and props["orig_port"] == "53,80"
    assert props["service_unknown"] is True and "different ports" in props["approximate_reason"]
    spec = _dnat_spec(_raw("mixed"))
    assert _truth(spec.predicate, _packet("10.9.9.1", "203.0.113.10", 6, 22)) is False
    assert _truth(spec.predicate, _packet("10.9.9.1", "203.0.113.10", 6, 53)) is None


def test_an_unknown_or_group_translated_service_leaves_the_port_rewrite_undecided():
    for translated in ("web-grp", "missing"):
        props = _rule_props(_raw("http", translated))
        assert props["approximate"] is True and props["service_unknown"] is True, translated
        assert "xlate_port" not in props, translated
        spec = _dnat_spec(_raw("http", translated))
        assert spec.gap_code == "NAT_SERVICE_UNKNOWN", translated
        assert _truth(spec.predicate, _packet("10.9.9.1", "203.0.113.10", 6, 22)) is False, translated


def test_a_rule_without_the_service_flag_is_read_as_unknown():
    graph, rulebase, rule = _nat_graph(_raw("web-grp"))
    row = nat_row(graph, rulebase, rule, False, {"gw-a"})
    row.update(protocol=None, orig_port=None, service_unknown=None)
    (resolved,) = _nat_stage_rules([row], "dnat", None)
    assert resolved["opaque"] and "'Web'" in resolved["role_note"]
    assert "n.service_unknown AS service_unknown" in _NAT_RULES_QUERY_STRICT
    assert "n.orig_service AS orig_service" in _NAT_RULES_QUERY_STRICT


# --- a failed package read whose layers a captured package also holds --------------


def test_a_failed_package_sharing_every_layer_binds_them_to_the_unclaimed_firewalls():
    """Package Second fails to read and shares every layer with Policy on
    gw-a. gw-b, where Second may be installed, binds those layers
    approximately."""
    from tests.test_checkpoint_policy_facts import _enforces, _nat_rule

    raw = _estate()
    second = {"uid": "second", "name": "Second", "type": "package", "domain": DOMAIN}
    raw["packages"] = [raw["packages"][0], second]
    raw["package_details"]["package"] = {
        **raw["package_details"]["package"],
        "installation-targets": ["gw-a"],
    }
    raw["nat"]["Second"] = [{"rulebase": [{**_nat_rule(), "uid": "n2"}], "objects-dictionary": OBJECTS}]
    raw["policy_section_errors"] = ["show-package second: HTTP 500"]
    edges = _enforces(_batch(raw))
    for name in ("Network", "Application"):
        assert edges["gw-a", name].get("configured") is True, name
        assert edges["gw-b", name].get("approximate") is True, name
    assert ("mgmt", "Network") not in edges
    raw["policy_section_errors"] = []
    assert ("gw-b", "Network") not in _enforces(_batch(raw))


# --- a column entry the objects dictionary does not hold -----------------------------


def _missing_service_estate(service: list[str], extra: list[dict[str, Any]] = ()) -> dict[str, Any]:  # type: ignore[assignment]
    from tests.test_firewall_rule_scope import _cp_rule

    raw = _estate()
    objects = [*OBJECTS, *extra]
    rule = _cp_rule("r1", 1, "accept", destination=["web"], service=service, **{"install-on": ["gw-a"]})
    raw["rulebases"]["net"] = [{"rulebase": [rule], "objects-dictionary": objects}]
    return raw


def test_a_service_entry_missing_from_the_dictionary_leaves_the_rule_undecided(monkeypatch):
    """The service entry is an opaque SvcObject."""
    from tests.test_checkpoint_policy_facts import _tracer

    from hst.path.verdict import INDETERMINATE

    batch = _batch(_missing_service_estate(["gone"]))
    (node,) = [n for n in batch.nodes if n.label == "SvcObject" and n.uid.endswith("gone")]
    assert node.props["opaque"] is True and "objects dictionary" in node.props["opaque_reason"]
    assert _tracer(monkeypatch, batch, "gw-a", "10.1.0.5", "10.9.1.1", 443) == INDETERMINATE


def test_a_service_group_with_a_member_missing_from_the_dictionary_is_opaque(monkeypatch):
    from tests.test_checkpoint_policy_facts import _tracer

    from hst.path.verdict import INDETERMINATE

    group = {**_svc("grp", "service-group"), "members": ["ssh", "gone"]}
    batch = _batch(_missing_service_estate(["grp"], [group]))
    (node,) = [n for n in batch.nodes if n.label == "SvcObject" and n.uid.endswith(":grp")]
    assert node.props["opaque"] is True and "gone" in node.props["opaque_reason"]
    assert _tracer(monkeypatch, batch, "gw-a", "10.1.0.5", "10.9.1.1", 443) == INDETERMINATE


def test_a_destination_entry_missing_from_the_dictionary_leaves_the_rule_undecided(monkeypatch):
    from tests.test_checkpoint_policy_facts import _tracer
    from tests.test_firewall_rule_scope import _cp_rule

    from hst.path.verdict import INDETERMINATE

    raw = _estate()
    rule = _cp_rule("r1", 1, "drop", destination=["gone"], service=["ssh"])
    raw["rulebases"]["net"] = [{"rulebase": [rule], "objects-dictionary": OBJECTS}]
    raw["layers"] = [{**raw["layers"][0], "implicit-cleanup-action": "accept"}, raw["layers"][1]]
    batch = _batch(raw)
    assert _tracer(monkeypatch, batch, "gw-a", "10.1.0.5", "10.9.1.1", 22) == INDETERMINATE


# --- two packages that name the same gateway ----------------------------------------


def test_two_packages_with_explicit_targets_on_one_gateway_bind_it_approximately():
    from tests.test_checkpoint_policy_facts import _enforces

    raw = _estate()
    other = {
        "uid": "other",
        "name": "Other",
        "type": "package",
        "domain": DOMAIN,
        "access-layers": ["app"],
        "installation-targets": ["gw-a"],
    }
    raw["packages"] = [raw["packages"][0], other]
    raw["package_details"] = {
        "package": {**raw["package_details"]["package"], "access-layers": ["net"]},
        "other": other,
    }
    edges = _enforces(_batch(raw))
    assert edges["gw-a", "Network"].get("approximate") is True
    assert edges["gw-a", "Application"].get("approximate") is True
    assert edges["gw-a", "NAT:Policy"].get("approximate") is True
    assert edges["gw-b", "Network"].get("configured") is True
