"""The device sections of a raw payload: version, routing, ACLs and NAT (`interface_text.device_sections`),
and their redacted read for one device at a run (`tier3.device_text`)."""

import json
from typing import Any

from tests.support.synthetic_payloads import case_payload
from tests.support.synthetic_vyos import CASES as VYOS_CASES
from tests.support.synthetic_vyos import answers, base_raw

from hst.map import interface_text, tier3


def _commands(sections: list[dict[str, Any]]) -> dict[str, list[str]]:
    return {s["key"]: [p["command"] for p in s["parts"]] for s in sections}


def test_an_nxos_payload_has_its_version_routing_acl_and_nat_sections() -> None:
    sections = interface_text.device_sections(case_payload("nxos/fixture/plain"))

    assert [s["title"] for s in sections] == ["Version", "Routing", "ACLs", "NAT"]
    assert _commands(sections) == {
        "version": ["show version | json"],
        "routing": ["show running-config bgp", "show running-config ospf", "show running-config rpm"],
        "acls": ["show ip access-lists | json"],
        "nat": ["show running-config nat"],
    }


def test_an_iosxe_payload_files_its_running_config_sections() -> None:
    commands = _commands(interface_text.device_sections(case_payload("iosxe/fixture/plain")))

    assert commands["version"] == ["show version"]
    assert commands["routing"] == [
        "show running-config | include ^ip prefix-list",
        "show running-config | section ^route-map",
        "show running-config | section ^router bgp",
    ]
    assert commands["acls"] == ["show ip access-lists"]
    assert "show running-config | include ^ip nat" in commands["nat"]


def test_a_json_answer_is_indented_and_a_failed_command_has_no_part() -> None:
    version = {"host_name": "sw1", "nxos_ver_str": "10.6(4)"}
    payload = {
        "show version | json": json.dumps(version),
        "show running-config bgp": {"status": "failed", "detail": "not sent"},
    }

    sections = interface_text.device_sections(payload)

    assert [s["key"] for s in sections] == ["version"]
    assert sections[0]["parts"][0]["text"] == json.dumps(version, indent=2, sort_keys=True)


def test_the_interface_stanzas_and_the_rib_are_no_device_section() -> None:
    payload = {
        "show running-config interface": "interface Ethernet1/1\n  no shutdown\n",
        "show ip route vrf all | json": "{}",
    }

    assert interface_text.device_sections(payload) == []


def test_a_vyos_configuration_is_cut_at_its_top_level_nodes() -> None:
    commands = _commands(interface_text.device_sections(base_raw(answers(VYOS_CASES[0]))))

    assert commands == {
        "routing": ["show configuration json protocols", "show configuration json policy"],
        "acls": ["show configuration json firewall"],
        "nat": ["show configuration json nat"],
    }


def test_a_unifi_payload_has_no_device_section() -> None:
    assert interface_text.device_sections({"devices": [], "networks": [], "show version": "x"}) == []


class _Record:
    def __init__(self, devices: list[Any], files: list[Any]) -> None:
        self.devices, self.files = devices, files


class _Entry:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


def test_the_sections_come_from_the_effective_run_and_are_redacted(monkeypatch: Any, tmp_path: Any) -> None:
    from hst.core import manifest, rawstore
    from hst.core.config import Settings

    device = _Entry(device_uids=["dev:edge1"], effective_run="1700000000000-aaaaaaaa")
    files = [
        _Entry(kind="raw", run_id="1699999999999-bbbbbbbb", path="old.json.gz"),
        _Entry(kind="raw", run_id="1700000000000-aaaaaaaa", path="raw.json.gz"),
    ]
    payload = {"show running-config bgp": "router bgp 65000\n  neighbor 10.0.0.1\n    password 3 s3cret\n"}
    read_paths: list[str] = []
    monkeypatch.setattr(manifest, "read", lambda settings, key: _Record([device], files))
    monkeypatch.setattr(rawstore, "read", lambda path, key: read_paths.append(path.name) or payload)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)  # type: ignore[call-arg]

    found = tier3.device_text(settings, "k", "dev:edge1", 1)

    assert read_paths == ["raw.json.gz"]
    assert found is not None and found["fetched_ts"] == 1_700_000_000_000
    [routing] = found["sections"]
    assert routing["key"] == "routing" and routing["parts"][0]["command"] == "show running-config bgp"
    assert routing["parts"][0]["text"].startswith("router bgp 65000\n  neighbor 10.0.0.1")
    assert "s3cret" not in routing["parts"][0]["text"]
    assert tier3.device_text(settings, "k", "dev:other", 1) is None


def test_nxos_access_lists_show_as_their_own_lines() -> None:
    sections = {s["key"]: s for s in interface_text.device_sections(case_payload("nxos/fixture/plain"))}

    assert sections["acls"]["parts"][0]["text"].split("\n") == [
        "ip access-list ACL-NAT",
        "  10 permit ip 10.10.10.0/24 any",
        "  20 permit ip 10.10.10.7/32 any",
        "ip access-list EDGE-IN",
        "  10 permit tcp 10.0.0.0/24 203.0.113.10/32 eq 443",
        "  20 permit tcp any 203.0.113.10/32 established",
        "  30 permit ip addrgroup PARTNERS any",
        "  40 deny ip any any",
        "ip access-list MGMT-OUT",
        "  10 permit ip 10.10.10.0/24 any",
    ]


def test_an_access_list_line_keeps_remarks_ranges_log_and_unknown_columns() -> None:
    aces = [
        {"seqno": 5, "remark": "web servers"},
        {
            "seqno": 10,
            "permitdeny": "permit",
            "proto": "udp",
            "src_any": "any",
            "src_port_op": "range",
            "src_port1_num": 1024,
            "src_port2_num": 2048,
            "dest_ip_prefix": "10.0.0.1/32",
            "dest_port_op": "eq",
            "dest_port1_str": "domain",
            "log": True,
            "dscp": "ef",
        },
    ]
    one_list = {"op": "ip", "acl_name": "A", "TABLE_seqno": {"ROW_seqno": aces}}
    payload = {
        "show ip access-lists | json": json.dumps({"TABLE_ip_ipv6_mac": {"ROW_ip_ipv6_mac": one_list}})
    }

    [acls] = interface_text.device_sections(payload)

    assert acls["parts"][0]["text"].split("\n") == [
        "ip access-list A",
        "  5 remark web servers",
        "  10 permit udp any range 1024 2048 10.0.0.1/32 eq domain log [dscp=ef]",
    ]


def test_an_access_list_line_reads_the_columns_a_real_nxos_answer_has() -> None:
    aces = [
        {"seqno": 2, "permitdeny": "permit", "ip": "ip", "src_ip_prefix": "10.174.242.0/24",
         "dest_any": "any", "match_count": 0},
        {"seqno": 3, "permitdeny": "permit", "proto_str": "tcp", "src_any": "any", "dest_any": "any",
         "dest_port_op": "eq", "dest_port1_num": 443, "dest_port1_str": "https"},
        {"seqno": 4, "permitdeny": "permit", "proto_str": "icmp", "src_any": "any", "dest_any": "any",
         "icmp_str": "echo"},
    ]  # fmt: skip
    one_list = {"op": "ip", "acl_name": "VTY", "TABLE_seqno": {"ROW_seqno": aces}}
    payload = {
        "show ip access-lists | json": json.dumps({"TABLE_ip_ipv6_mac": {"ROW_ip_ipv6_mac": [one_list]}})
    }

    [acls] = interface_text.device_sections(payload)

    assert acls["parts"][0]["text"].split("\n") == [
        "ip access-list VTY",
        "  2 permit ip 10.174.242.0/24 any [match=0]",
        "  3 permit tcp any any eq https",
        "  4 permit icmp any any echo",
    ]


def test_an_access_list_answer_of_another_shape_stays_indented_json() -> None:
    payload = {"show ip access-lists | json": json.dumps({"other": [1]})}

    [acls] = interface_text.device_sections(payload)

    assert acls["parts"][0]["text"] == json.dumps({"other": [1]}, indent=2, sort_keys=True)
