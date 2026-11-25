"""Cisco ACE port keywords (`eq bgp`, `eq domain`) read as port numbers under the
ACE's protocol (collectors/cisco_common.py `ace_port_keyword`, `ace_port_clause`)."""

import pytest

from hst.collectors.cisco_common import ace_port_clause, ace_port_keyword, ace_port_spec


@pytest.mark.parametrize(
    ("keyword", "proto", "number"),
    [
        ("bgp", "tcp", 179),
        ("domain", "tcp", 53),
        ("domain", "udp", 53),
        ("www", "tcp", 80),
        ("ftp-data", "tcp", 20),
        ("telnet", "tcp", 23),
        ("tacacs", "tcp", 49),
        ("ntp", "udp", 123),
        ("snmp", "udp", 161),
        ("snmptrap", "udp", 162),
        ("bootps", "udp", 67),
        ("bootpc", "udp", 68),
        ("pim-auto-rp", "udp", 496),
        ("rip", "udp", 520),
        ("tftp", "udp", 69),
        ("non500-isakmp", "udp", 4500),
        ("BGP", "TCP", 179),
    ],
)
def test_a_keyword_reads_as_its_number_under_its_protocol(keyword, proto, number):
    assert ace_port_keyword(keyword, proto) == number


def test_the_numbers_named_per_protocol_resolve_only_under_their_own_protocol():
    # 512, 513 and 514 are exec, login and cmd on TCP, and biff, who and syslog on UDP
    pairs = {512: ("exec", "biff"), 513: ("login", "who"), 514: ("cmd", "syslog")}
    for number, (tcp_name, udp_name) in pairs.items():
        assert ace_port_keyword(tcp_name, "tcp") == number
        assert ace_port_keyword(udp_name, "udp") == number
        assert ace_port_keyword(tcp_name, "udp") is None
        assert ace_port_keyword(udp_name, "tcp") is None


def test_a_keyword_of_one_protocol_does_not_resolve_under_the_other():
    assert ace_port_keyword("www", "udp") is None
    # NX-OS prints tcp 161 as a bare number: snmp is a UDP name only
    assert ace_port_keyword("snmp", "tcp") is None


def test_without_a_protocol_only_a_keyword_both_tables_agree_on_resolves():
    assert ace_port_keyword("domain") == 53
    assert ace_port_keyword("www") is None


def test_a_keyword_in_neither_table_stays_unresolved():
    # NX-OS prints tcp 443 as a number, not https
    assert ace_port_keyword("https", "tcp") is None
    assert ace_port_keyword("foo", "udp") is None


def test_every_operator_reads_a_keyword_through_the_protocol():
    assert ace_port_clause("eq", "bgp", proto="tcp") == ("179", None, None)
    assert ace_port_clause("range", "ftp-data", "ftp", proto="tcp") == ("20-21", None, None)
    assert ace_port_clause("gt", "www", proto="tcp") == ("81-65535", None, None)
    assert ace_port_clause("lt", "domain", proto="udp") == ("0-52", None, None)
    assert ace_port_spec("eq", "domain", proto="udp") == ("53", None)


def test_a_number_is_read_as_its_port_with_no_note():
    assert ace_port_clause("eq", 443, proto="tcp") == ("443", None, None)
    assert ace_port_clause(None, None) == (None, None, None)


def test_an_unknown_keyword_keeps_the_trace_reason_and_gets_a_short_note():
    assert ace_port_clause("eq", "foo", proto="tcp") == (
        None,
        "the port keyword 'foo' was not resolved to a port number",
        "port keyword foo unknown",
    )
    # a keyword of the other protocol is unknown under this one
    assert ace_port_clause("eq", "www", proto="udp")[2] == "port keyword www unknown"


def test_neq_stays_opaque_and_its_note_names_the_port_number():
    assert ace_port_clause("neq", "www", proto="tcp") == (
        None,
        "the port operator 'neq' does not express a port set",
        "neq 80",
    )
    assert ace_port_clause("neq", 80)[2] == "neq 80"


def test_the_other_opaque_clauses_carry_short_notes():
    assert ace_port_clause("precedence", "routine")[2] == "precedence routine"
    assert ace_port_clause("tos", "max-reliability")[2] == "tos max-reliability"
    assert ace_port_clause("range", 20, None)[2] == "port range 20 unknown"
    assert ace_port_clause("range", "foo", "ftp", proto="tcp")[2] == "port range foo ftp unknown"
    assert ace_port_clause("lt", 0) == (None, "'lt 0' names no port", "lt 0")
    assert ace_port_clause("gt", 65535) == (None, "'gt 65535' names no port", "gt 65535")
