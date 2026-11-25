from __future__ import annotations

from tests.test_iosxe import RAW, _sections
from tests.test_path_section_gaps import _flow, _install, _session

from hst.collectors.cisco_common import parse_access_groups
from hst.collectors.iosxe import CMD_INTERFACE_CONFIG

ZBFW_CONFIG_TEXT = """\
interface GigabitEthernet1/0/1
 description uplink
 ip address 10.0.0.1 255.255.255.0
 zone-member security OUTSIDE
!
interface GigabitEthernet1/0/2
 no ip address
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
 zone-member security INSIDE
!
"""

ZBFW_RAW = {**RAW, CMD_INTERFACE_CONFIG: ZBFW_CONFIG_TEXT}


def test_a_zone_member_line_is_a_binding_in_both_directions():
    bindings = parse_access_groups(ZBFW_CONFIG_TEXT.splitlines())
    assert bindings == [
        {"interface": "GigabitEthernet1/0/1", "direction": "in", "acl": "OUTSIDE", "family": "zone"},
        {"interface": "GigabitEthernet1/0/1", "direction": "out", "acl": "OUTSIDE", "family": "zone"},
        {"interface": "Vlan10", "direction": "in", "acl": "INSIDE", "family": "zone"},
        {"interface": "Vlan10", "direction": "out", "acl": "INSIDE", "family": "zone"},
    ]


def test_a_zone_member_interface_binds_an_opaque_rulebase(monkeypatch):
    from tests.conftest import FakeSshSession
    from tests.test_iosxe import _collector

    FakeSshSession(ZBFW_RAW).install(monkeypatch)
    c = _collector()
    batch = c.normalize(c.fetch())
    rulebases = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase" and ":zbfw:" in n.uid}
    assert {p["name"] for p in rulebases.values()} == {"INSIDE", "OUTSIDE"}
    bound = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "PROTECTED_BY"}
    assert any(end in rulebases and "vlan10" in start.lower() for start, end in bound)
    opaque = [n.props for n in batch.nodes if n.label == "NetObject" and n.props.get("opaque")]
    assert any("zone-based firewall" in (p.get("opaque_reason") or "") for p in opaque)


def test_a_zone_based_firewall_makes_the_interface_config_section_partial(monkeypatch):
    sections = _sections(monkeypatch, ZBFW_RAW)
    section = sections["interface_config"]
    assert section.status == "partial"
    assert "INSIDE, OUTSIDE" in section.detail and "zone-pair" in section.detail
    assert _sections(monkeypatch, RAW)["interface_config"].status == "ok"


def test_a_trace_across_a_zone_based_firewall_is_undecided(monkeypatch):
    statuses = {name: outcome.status for name, outcome in _sections(monkeypatch, ZBFW_RAW).items()}
    _install(monkeypatch)
    _trail, legs, _verdict = _flow(_session(statuses))
    assert legs[0]["indeterminate"] is True
    assert "interface_config=partial" in legs[0]["indeterminate_reason"]
