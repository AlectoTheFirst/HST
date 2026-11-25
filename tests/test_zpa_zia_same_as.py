"""The reasoner's `zpa-zia-ip-same-as` rule: `resolve_zpa_zia_ip_links` joins a ZPA/ZIA
address to every campus `IpAddress` with the same value. Every address and uid here is
made up.
"""

from __future__ import annotations

from hst.reasoner import (
    GLOBAL_ADDRESS_CONFIDENCE,
    PRIVATE_ADDRESS_CONFIDENCE,
    resolve_zpa_zia_ip_links,
)

CONNECTOR = {"uid": "zpa:acme:conn:6001", "basis": "private_ip", "ip": "10.1.1.6"}
APP_SERVER = {"uid": "zpa:acme:appsrv:4101", "basis": "address", "ip": "10.1.1.10"}
APP_SERVER_BY_NAME = {"uid": "zpa:acme:appsrv:4102", "basis": "address", "ip": "web.corp.example"}
# Python's ipaddress reads the RFC 5737 documentation ranges as not global.
TUNNEL = {"uid": "zia:acme:gre:5001", "basis": "source_ip", "ip": "8.8.8.8"}

CAMPUS_CONNECTOR = {"uid": "ip:vrf-main:10.1.1.6", "ip": "10.1.1.6"}
CAMPUS_SERVER = {"uid": "ip:vrf-main:10.1.1.10", "ip": "10.1.1.10"}
CAMPUS_WAN = {"uid": "ip:vrf-wan:8.8.8.8", "ip": "8.8.8.8"}


def test_a_private_address_links_at_the_private_confidence():
    rows = resolve_zpa_zia_ip_links([CONNECTOR], [CAMPUS_CONNECTOR])
    assert rows == [
        {
            "a": CONNECTOR["uid"],
            "b": CAMPUS_CONNECTOR["uid"],
            "basis": "private_ip",
            "confidence": PRIVATE_ADDRESS_CONFIDENCE,
        }
    ]


def test_a_globally_routable_address_links_at_the_higher_confidence():
    rows = resolve_zpa_zia_ip_links([TUNNEL], [CAMPUS_WAN])
    assert rows == [
        {
            "a": TUNNEL["uid"],
            "b": CAMPUS_WAN["uid"],
            "basis": "source_ip",
            "confidence": GLOBAL_ADDRESS_CONFIDENCE,
        }
    ]
    assert GLOBAL_ADDRESS_CONFIDENCE > PRIVATE_ADDRESS_CONFIDENCE


def test_an_app_server_address_links_and_a_host_name_does_not():
    rows = resolve_zpa_zia_ip_links([APP_SERVER, APP_SERVER_BY_NAME], [CAMPUS_SERVER])
    assert [(r["a"], r["basis"]) for r in rows] == [(APP_SERVER["uid"], "address")]


def test_no_match_writes_nothing():
    assert resolve_zpa_zia_ip_links([CONNECTOR, APP_SERVER, TUNNEL], []) == []


def test_one_address_in_two_forwarding_contexts_links_to_both():
    other_vrf = {"uid": "ip:vrf-other:10.1.1.6", "ip": "10.1.1.6"}
    rows = resolve_zpa_zia_ip_links([CONNECTOR], [CAMPUS_CONNECTOR, other_vrf])
    assert {r["b"] for r in rows} == {CAMPUS_CONNECTOR["uid"], other_vrf["uid"]}


def test_addresses_compare_in_canonical_form():
    spaced = {**CONNECTOR, "ip": " 10.1.1.6 "}
    v6 = {"uid": "zpa:acme:conn:6002", "basis": "private_ip", "ip": "fd00:0:0:0::5"}
    campus_v6 = {"uid": "ip:vrf-main:fd00::5", "ip": "fd00::5"}
    rows = resolve_zpa_zia_ip_links([spaced, v6], [CAMPUS_CONNECTOR, campus_v6])
    assert {(r["a"], r["b"]) for r in rows} == {
        (CONNECTOR["uid"], CAMPUS_CONNECTOR["uid"]),
        (v6["uid"], campus_v6["uid"]),
    }


def test_rows_are_sorted_for_determinism():
    second = {"uid": "zpa:acme:conn:zzz", "basis": "private_ip", "ip": "10.1.1.10"}
    rows = resolve_zpa_zia_ip_links([second, CONNECTOR], [CAMPUS_SERVER, CAMPUS_CONNECTOR])
    assert rows == sorted(rows, key=lambda r: (r["a"], r["b"]))


def test_a_special_use_value_draws_no_link():
    from hst.reasoner import resolve_zpa_zia_ip_links

    zscaler = [
        {"uid": f"z:{ip}", "basis": "private_ip", "ip": ip}
        for ip in ("0.0.0.0", "127.0.0.1", "169.254.10.10")  # noqa: S104 - addresses, not a bind
    ]
    campus = [{"uid": f"ip:{row['ip']}", "ip": row["ip"]} for row in zscaler]
    assert resolve_zpa_zia_ip_links(zscaler, campus) == []
