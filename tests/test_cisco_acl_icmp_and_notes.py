"""The ICMP type and the short notes of a Cisco interface ACL rule (collectors/cisco_common.py
acl_stage): an ICMP type is data on the rule's SvcObject and in its name, and every reason the
trace prints has a short `opaque_note` beside it, which the Firewall rules table lists."""

import json

from tests import test_iosxe, test_nxos
from tests.test_cisco_common import _PERMIT_ANY_ACE, _acl_batch

from hst.collectors import iosxe, nxos

# The rows of ACL-PEER-INTERNET-IN and ACL-DNS-INTERNET-OUT as IOS-XE prints them
# (dev:xe-edge-rtr-07), and one row for each reason a rule can carry.
IOSXE_ACL_TEXT = """\
Extended IP access list EDGE-IN
    10 permit tcp host 203.0.113.15 host 203.0.113.14 eq bgp (179492 matches)
    20 permit tcp host 203.0.113.14 eq bgp host 203.0.113.15
    30 permit icmp any host 203.0.113.138 echo-reply
    40 deny icmp any any timestamp-request (225 matches)
    50 permit udp any eq domain host 198.51.100.36 (9387 matches)
    60 permit tcp object-group PARTNERS any eq 443
    70 permit tcp any any neq www
    80 permit tcp any any eq 443 time-range WORK (active)
    90 permit tcp any any ack syn
    100 permit tcp any any eq foo
    110 permit tcp any any eq www 443
"""

IOSXE_BINDING_TEXT = """\
interface GigabitEthernet1/0/1
 description uplink
 ip address 10.0.0.1 255.255.255.0
 ip access-group EDGE-IN in
!
"""

IOSXE_RB = "iosxe:sw1x:acl:edge-in~f89b1a37"


def _iosxe_batch():
    raw = {**test_iosxe.RAW, iosxe.CMD_ACL: IOSXE_ACL_TEXT, iosxe.CMD_INTERFACE_CONFIG: IOSXE_BINDING_TEXT}
    return test_iosxe._collector().normalize(raw)


def _props(batch, uid_):
    return next(n.props for n in batch.nodes if n.uid == uid_)


def test_iosxe_port_keywords_become_port_numbers_and_a_decidable_service():
    batch = _iosxe_batch()
    bgp = _props(batch, f"{IOSXE_RB}:1:svc")
    assert (bgp["name"], bgp["proto"], bgp["ports"]) == ("tcp/179", "tcp", "179")
    assert "opaque" not in bgp and "opaque_reason" not in bgp and "opaque_note" not in bgp
    reply = _props(batch, f"{IOSXE_RB}:2:svc")
    assert (reply["name"], reply["src_port"]) == ("tcp/any src 179", "179")
    assert "ports" not in reply and "opaque" not in reply
    dns = _props(batch, f"{IOSXE_RB}:5:svc")
    assert (dns["name"], dns["proto"], dns["src_port"]) == ("udp/any src 53", "udp", "53")


def test_iosxe_icmp_type_is_on_the_service_and_the_gate_reason_names_it():
    batch = _iosxe_batch()
    echo_reply = _props(batch, f"{IOSXE_RB}:3:svc")
    assert echo_reply["name"] == "icmp echo-reply"
    assert echo_reply["icmp_type"] == "echo-reply"
    assert echo_reply["opaque"] is True
    assert echo_reply["opaque_reason"] == (
        "the rule matches on the ICMP type 'echo-reply', which the traced flow does not state"
    )
    # the table shows the type in the service column, so nothing is left unresolved
    assert echo_reply["opaque_note"] == ""
    timestamp = _props(batch, f"{IOSXE_RB}:4:svc")
    assert (timestamp["name"], timestamp["icmp_type"]) == ("icmp timestamp-request", "timestamp-request")


def test_iosxe_every_reason_has_a_short_note_beside_it():
    batch = _iosxe_batch()
    partners = _props(batch, f"{IOSXE_RB}:6:src")
    assert partners["opaque_reason"] == "the ACE matches object-group 'PARTNERS', which is not collected"
    assert partners["opaque_note"] == "src object-group PARTNERS not collected"
    neq = _props(batch, f"{IOSXE_RB}:7:svc")
    assert neq["opaque_reason"] == "the port operator 'neq' does not express a port set"
    assert neq["opaque_note"] == "neq 80"
    work = _props(batch, f"{IOSXE_RB}:8:svc")
    assert work["name"] == "tcp/443" and work["opaque_note"] == "time-range WORK"
    assert "time-range 'WORK'" in work["opaque_reason"]
    flags = _props(batch, f"{IOSXE_RB}:9:svc")
    assert flags["opaque_note"] == "tcp flags ack syn"
    assert "the TCP flags 'ack syn'" in flags["opaque_reason"]
    foo = _props(batch, f"{IOSXE_RB}:10:svc")
    assert foo["opaque_reason"] == "the port keyword 'foo' was not resolved to a port number"
    assert foo["opaque_note"] == "port keyword foo unknown"


def test_iosxe_an_icmp_type_on_a_tcp_rule_is_listed_not_shown_as_a_type():
    """The template reads the second port of `eq www 443` as an ICMP type. The rule
    stays indeterminate, the service is named by its TCP port, and the note lists the type."""
    batch = _iosxe_batch()
    svc = _props(batch, f"{IOSXE_RB}:11:svc")
    assert svc["name"] == "tcp/80" and "icmp_type" not in svc
    assert svc["opaque"] is True and svc["opaque_note"] == "icmp type 443"


# NX-OS `show ip access-lists | json` rows: the ICMP type is in `icmp_str` (dev:nx-core-sw-03)
NXOS_ACL_PAYLOAD = {
    "TABLE_ip_ipv6_mac": {
        "ROW_ip_ipv6_mac": [
            {
                "op_ip_ipv6_mac": "ip",
                "acl_name": "EDGE-IN",
                "TABLE_seqno": {
                    "ROW_seqno": [
                        {
                            "seqno": 10,
                            "permitdeny": "permit",
                            "proto_str": "icmp",
                            "src_any": "any",
                            "dest_any": "any",
                            "icmp_str": "echo",
                        },
                        {
                            "seqno": 20,
                            "permitdeny": "permit",
                            "proto_str": "icmp",
                            "src_any": "any",
                            "dest_any": "any",
                            "icmp_type": "echo-reply",
                        },
                        {
                            "seqno": 30,
                            "permitdeny": "permit",
                            "proto_str": "tcp",
                            "src_any": "any",
                            "dest_any": "any",
                            "dest_port_op": "eq",
                            "dest_port1_str": "bgp",
                        },
                        {
                            "seqno": 40,
                            "permitdeny": "permit",
                            "proto_str": "tcp",
                            "src_any": "any",
                            "dest_any": "any",
                            "dest_port_op": "eq",
                            "dest_port1_str": "snmp",
                        },
                        {
                            "seqno": 50,
                            "permitdeny": "permit",
                            "proto_str": "udp",
                            "src_any": "any",
                            "dest_any": "any",
                            "src_port_op": "neq",
                            "src_port1_num": 1023,
                        },
                        {
                            "seqno": 60,
                            "permitdeny": "permit",
                            "proto_str": "tcp",
                            "src_addrgrp": "PARTNERS",
                            "dest_any": "any",
                            "port_grp": "WEB",
                        },
                    ]
                },
            },
        ]
    }
}

NXOS_BINDING_TEXT = """\
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/24
  ip access-group EDGE-IN in
"""

NXOS_RB = "nxos:n9k1:acl:edge-in~f89b1a37"


def _nxos_batch():
    raw = {
        **test_nxos.RAW,
        nxos.CMD_ACL: json.dumps(NXOS_ACL_PAYLOAD),
        nxos.CMD_INTERFACE_CONFIG: NXOS_BINDING_TEXT,
    }
    return test_nxos._collector().normalize(raw)


def test_nxos_icmp_str_names_the_icmp_type():
    aces = nxos.parse(
        {
            **test_nxos.RAW,
            nxos.CMD_ACL: json.dumps(NXOS_ACL_PAYLOAD),
            nxos.CMD_INTERFACE_CONFIG: NXOS_BINDING_TEXT,
        }
    )["acl"]["lists"]["EDGE-IN"]
    assert aces[0]["icmp_type"] == "echo"
    assert aces[0]["qualifier_reason"] == (
        "the rule matches on the ICMP type 'echo', which the traced flow does not state"
    )
    batch = _nxos_batch()
    echo = _props(batch, f"{NXOS_RB}:1:svc")
    assert (echo["name"], echo["icmp_type"], echo["opaque"], echo["opaque_note"]) == (
        "icmp echo",
        "echo",
        True,
        "",
    )
    rule = _props(batch, f"{NXOS_RB}:1")
    assert rule["svc_any"] is False


def test_nxos_the_icmp_type_column_is_read():
    echo_reply = _props(_nxos_batch(), f"{NXOS_RB}:2:svc")
    assert (echo_reply["name"], echo_reply["icmp_type"]) == ("icmp echo-reply", "echo-reply")


def test_nxos_two_icmp_types_keep_two_services():
    batch = _nxos_batch()
    assert _props(batch, f"{NXOS_RB}:1:svc")["icmp_type"] != _props(batch, f"{NXOS_RB}:2:svc")["icmp_type"]


def test_nxos_a_keyword_with_no_number_reads_through_the_protocol():
    batch = _nxos_batch()
    bgp = _props(batch, f"{NXOS_RB}:3:svc")
    assert (bgp["name"], bgp["ports"]) == ("tcp/179", "179") and "opaque" not in bgp
    snmp = _props(batch, f"{NXOS_RB}:4:svc")
    assert snmp["opaque"] is True and snmp["opaque_note"] == "port keyword snmp unknown"


def test_nxos_every_reason_has_a_short_note_beside_it():
    batch = _nxos_batch()
    assert _props(batch, f"{NXOS_RB}:5:svc")["opaque_note"] == "src neq 1023"
    assert _props(batch, f"{NXOS_RB}:6:src")["opaque_note"] == "src address-group PARTNERS not collected"
    assert _props(batch, f"{NXOS_RB}:6:svc")["opaque_note"] == "port-group WEB not collected"


def test_the_placeholder_rules_carry_short_notes():
    binding = {"interface": "Ethernet1/1", "direction": "in", "acl": "X"}
    empty = _acl_batch({"lists": {"X": []}, "bindings": [binding]})
    assert next(n for n in empty.nodes if n.label == "NetObject").props["opaque_note"] == "ACL empty"
    ghost = _acl_batch({"lists": {}, "bindings": [binding]})
    assert next(n for n in ghost.nodes if n.label == "NetObject").props["opaque_note"] == "ACL not collected"


def test_a_reason_with_no_note_beside_it_stands_for_itself():
    ace = {
        **_PERMIT_ANY_ACE,
        "src_any": False,
        "src_opaque_reason": "the ACE matches a thing",
        "proto": "tcp",
        "svc_opaque_reason": "a service reason",
    }
    batch = _acl_batch(
        {"lists": {"X": [ace]}, "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "X"}]}
    )
    src = next(n for n in batch.nodes if n.label == "NetObject")
    assert src.props["opaque_note"] == "src the ACE matches a thing"
    svc = next(n for n in batch.nodes if n.label == "SvcObject")
    assert svc.props["opaque_note"] == "a service reason"
