"""BGP AS numbers in asdot notation (RFC 5396) in the NX-OS and IOS-XE BGP
config parsers, and the NX-OS warning for a neighbor that is dropped."""

import pytest
from tests.test_nxos import RAW, RPM_CONFIG_TEXT, _collector

from hst.collectors import iosxe
from hst.collectors.nxos import CMD_BGP, CMD_RPM
from hst.collectors.util import parse_asn


@pytest.mark.parametrize(
    ("text", "asn"),
    [
        ("65001", 65001),
        ("4200000001", 4200000001),
        ("1.10", 65546),
        ("64086.59904", 64086 * 65536 + 59904),
        ("0.65535", 65535),
        ("65536.0", None),
        ("1.65536", None),
        ("4294967296", None),
        ("route-map", None),
        ("", None),
    ],
)
def test_parse_asn(text, asn):
    assert parse_asn(text) == asn


def _nxos_sessions(bgp_text):
    raw = dict(RAW)
    raw[CMD_BGP] = bgp_text
    raw[CMD_RPM] = RPM_CONFIG_TEXT
    batch = _collector().normalize(raw)
    return [n for n in batch.nodes if n.label == "BgpSession"]


def test_nxos_reads_an_asdot_process_and_remote_as():
    sessions = _nxos_sessions(
        "router bgp 1.10\n"
        "  vrf CUST-A\n"
        "    neighbor 192.0.2.50\n"
        "      remote-as 2.20\n"
        "      address-family ipv4 unicast\n"
    )
    assert [s.props["peer_asn"] for s in sessions] == [2 * 65536 + 20]


def test_nxos_names_an_unreadable_remote_as_in_the_warning(caplog):
    sessions = _nxos_sessions(
        "router bgp 65001\n"
        "  vrf CUST-A\n"
        "    neighbor 192.0.2.50\n"
        "      remote-as 70000.1\n"
        "      address-family ipv4 unicast\n"
    )
    assert sessions == []
    assert "192.0.2.50 remote-as '70000.1' is not an AS number" in caplog.text


def test_iosxe_reads_an_asdot_process_and_remote_as():
    parsed = iosxe.parse_bgp_config(
        "router bgp 1.10\n"
        " neighbor 192.0.2.1 remote-as 64086.59904\n"
        " address-family ipv4\n"
        "  neighbor 192.0.2.1 activate\n"
        " exit-address-family\n"
    )
    assert parsed is not None
    assert parsed["asn"] == 65546
    assert [n["remote_as"] for n in parsed["neighbors"]] == [64086 * 65536 + 59904]


def test_iosxe_an_unreadable_remote_as_does_not_stop_the_parse():
    parsed = iosxe.parse_bgp_config(
        "router bgp 65001\n neighbor 192.0.2.1 remote-as 70000.1\n neighbor 192.0.2.2 remote-as 65002\n"
    )
    assert parsed is not None
    assert {n["peer_ip"]: n.get("remote_as") for n in parsed["neighbors"]} == {
        "192.0.2.1": None,
        "192.0.2.2": 65002,
    }
