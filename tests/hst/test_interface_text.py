"""The interface configuration section, cut from the payloads behind the parser goldens."""

import copy
import json
from typing import Any

import pytest
from tests.support.synthetic_payloads import CASES, case_payload
from tests.support.synthetic_vyos import CASES as VYOS_CASES
from tests.support.synthetic_vyos import answers, base_raw

from hst.map import interface_text, tier3


@pytest.mark.parametrize(
    ("case", "name", "command", "lines"),
    [
        (
            "iosxe/fixture/plain",
            "GigabitEthernet1/0/1",
            "show running-config | section ^interface",
            ["interface GigabitEthernet1/0/1", " description uplink", " ip address 10.0.0.1 255.255.255.0"],
        ),
        (
            "nxos/fixture/plain",
            "Ethernet1/1",
            "show running-config interface",
            ["interface Ethernet1/1", "  no switchport", "  ip address 10.0.0.1/24"],
        ),
    ],
)
def test_the_stanza_of_one_interface_and_nothing_of_the_next(
    case: str, name: str, command: str, lines: list[str]
) -> None:
    assert interface_text.section(case_payload(case), name) == (command, "\n".join(lines))


# IOS-XR collects no interface configuration, so it has no stanza to read.
@pytest.mark.parametrize("case", [c for c in CASES if "/fixture/" in c and not c.startswith("iosxr/")])
def test_every_configured_interface_has_its_own_stanza(case: str) -> None:
    payload = case_payload(case)
    texts = [payload[c] for c in interface_text.STANZA_COMMANDS if c in payload]
    text = texts[0] if texts else ""
    names = [line.split(" ", 1)[1] for line in text.split("\n") if line.startswith("interface ")]
    assert names
    for name in names:
        found = interface_text.section(payload, name)
        assert found is not None and found[1].split("\n")[0] == f"interface {name}", name
        assert all(line.startswith(" ") for line in found[1].split("\n")[1:]), name


def test_iosxr_collects_no_interface_configuration() -> None:
    assert interface_text.section(case_payload("iosxr/fixture/plain"), "GigabitEthernet0/0/0/0") is None


def test_vyos_answers_with_the_interface_node_of_its_configuration() -> None:
    command, text = interface_text.section(base_raw(answers(VYOS_CASES[0])), "eth1") or ("", "")
    assert command == "show configuration json interfaces ethernet eth1"
    assert '"description": "LAN trunk"' in text and '"vif"' in text


def test_vyos_interface_text_clears_macsec_keys_and_the_snmp_community() -> None:
    config = {
        "interfaces": {
            "macsec": {"macsec0": {"security": {"mka": {"cak": "0123456789abcdef", "ckn": "fedcba98"}}}}
        },
        "service": {"snmp": {"community": {"S3CRETCOMM": {"authorization": "ro"}}}},
    }
    _, text = interface_text.section({"config": config}, "macsec0") or ("", "")
    assert "0123456789abcdef" not in text and "fedcba98" not in text and '"mka"' in text
    sections = interface_text.device_sections({"config": {**config, "protocols": config["service"]}})
    assert "S3CRETCOMM" not in json.dumps(sections)


def test_an_unknown_interface_has_no_section() -> None:
    assert interface_text.section(case_payload("iosxe/fixture/plain"), "GigabitEthernet9/9/9") is None


class _Record:
    def __init__(self, devices: list[Any], files: list[Any]) -> None:
        self.devices, self.files = devices, files


class _Entry:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


def test_the_section_comes_from_the_effective_run_and_is_redacted(monkeypatch: Any, tmp_path: Any) -> None:
    from hst.core import manifest, rawstore
    from hst.core.config import Settings

    device = _Entry(device_uids=["dev:edge1"], effective_run="1700000000000-aaaaaaaa")
    files = [
        _Entry(kind="raw", run_id="1699999999999-bbbbbbbb", path="old.json.gz"),
        _Entry(kind="raw", run_id="1700000000000-aaaaaaaa", path="raw.json.gz"),
    ]
    payload = {
        "show running-config | section ^interface": "interface Gi1\n description uplink\n"
        " snmp-server community s3cret RO\n"
    }
    read_paths: list[str] = []
    monkeypatch.setattr(manifest, "read", lambda settings, key: _Record([device], files))
    monkeypatch.setattr(rawstore, "read", lambda path, key: read_paths.append(path.name) or payload)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)  # type: ignore[call-arg]
    found = tier3.interface_text(settings, "k", "dev:edge1", 1, "Gi1")
    assert read_paths == ["raw.json.gz"]
    assert found is not None
    assert found["command"] == "show running-config | section ^interface"
    assert found["fetched_ts"] == 1_700_000_000_000
    assert found["text"].startswith("interface Gi1\n description uplink")
    assert "s3cret" not in found["text"]
    assert tier3.interface_text(settings, "k", "dev:other", 1, "Gi1") is None


def _unifi() -> dict[str, Any]:
    from tests.test_unifi import RAW

    raw = copy.deepcopy(RAW)
    switch, ap = raw["devices"]
    switch["port_table"][0]["name"] = "UPPER_LAN"
    switch["port_overrides"] = [
        {
            "port_idx": 1,
            "name": "UPPER_LAN",
            "portconf_id": "prof-trunk",
            "native_networkconf_id": "n1",
            "tagged_networkconf_ids": ["n30"],
            "poe_mode": "off",
            "autoneg": False,
            "speed": 1000,
            "full_duplex": True,
            "isolation": False,
            "stp_port_mode": True,
            "x_secret": "s3cret",
        },
        {"port_idx": 2, "portconf_id": "prof-unknown"},
    ]
    ap["port_table"] = [
        {"port_idx": 1, "name": "Port 1", "up": True, "speed": 1000, "portconf_id": "prof-all"}
    ]
    raw["port_profiles"] = [
        {
            "_id": "prof-trunk",
            "site_id": "site1",
            "attr_no_delete": True,
            "name": "Trunk",
            "forward": "customize",
            "native_networkconf_id": "n1",
            "excluded_networkconf_ids": ["n40", "n50"],
            "dot1x_ctrl": "force_authorized",
            "radius_secret": "r4dius",
            "x_passphrase": "hunter2",
        },
        {"_id": "prof-all", "name": "All", "forward": "all"},
    ]
    return raw


SWITCH = {"mac": "aabbcc000001", "serial": "SW1234567"}
AP = {"mac": "aabbcc000002", "serial": "AP7654321"}


def test_a_unifi_switch_port_shows_its_override_and_profile_with_network_names() -> None:
    found = interface_text.section(_unifi(), "UPPER_LAN", SWITCH)
    assert found is not None
    command, text = found
    assert command == "unifi port_overrides + portconf"
    assert json.loads(text) == {
        "device": "Rack-Switch",
        "name": "UPPER_LAN",
        "port_idx": 1,
        "port_overrides": {
            "name": "UPPER_LAN",
            "portconf": "Trunk",
            "native_network": "Default",
            "tagged_networks": ["IoT (vlan 30)"],
            "poe_mode": "off",
            "autoneg": False,
            "speed": 1000,
            "full_duplex": True,
            "isolation": False,
            "stp_port_mode": True,
        },
        "portconf": {
            "name": "Trunk",
            "forward": "customize",
            "native_network": "Default",
            "excluded_networks": ["Guest (vlan 40)", "VL_50_CAM (vlan 50)"],
            "dot1x_ctrl": "force_authorized",
        },
    }
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True)
    assert all(s not in text for s in ("s3cret", "r4dius", "hunter2", "site1", "prof-trunk"))
    assert interface_text.section(_unifi(), "port1", {"serial": "SW1234567"}) == found


def test_a_unifi_ap_port_without_overrides_shows_its_port_table_profile() -> None:
    command, text = interface_text.section(_unifi(), "Port 1", AP) or ("", "")
    assert command == "unifi port_table + portconf"
    assert json.loads(text) == {
        "device": "Living-Room-AP",
        "name": "Port 1",
        "port_idx": 1,
        "port_table": {"portconf": "All"},
        "portconf": {"name": "All", "forward": "all"},
    }
    raw = _unifi()
    del raw["devices"][1]["port_table"]
    command, text = interface_text.section(raw, "eth0", AP) or ("", "")
    assert command == "unifi stat/device"
    assert json.loads(text) == {"device": "Living-Room-AP", "name": "eth0", "port_idx": 0}


def test_an_unknown_unifi_port_or_device_has_no_section() -> None:
    raw = _unifi()
    assert interface_text.section(raw, "Port 9", SWITCH) is None
    assert interface_text.section(raw, "UPPER_LAN", AP) is None
    assert interface_text.section(raw, "UPPER_LAN", {"mac": "aabbcc0000ff"}) is None
    assert interface_text.section(raw, "UPPER_LAN") is None
    raw["devices"][0]["port_table"][1]["name"] = "UPPER_LAN"
    assert interface_text.section(raw, "UPPER_LAN", SWITCH) is None


def test_a_unifi_section_picks_the_device_through_the_graph_and_is_redacted(
    monkeypatch: Any, tmp_path: Any
) -> None:
    from hst.core import manifest, rawstore
    from hst.core.config import Settings

    device = _Entry(
        device_uids=["dev:rack-switch", "dev:living-room-ap"], effective_run="1700000000000-cccccccc"
    )
    files = [_Entry(kind="raw", run_id="1700000000000-cccccccc", path="unifi.json.gz")]
    raw = _unifi()
    raw["devices"][0]["port_overrides"][0]["name"] = "UPPER_LAN key s3cret"
    lookups: list[tuple[str, int]] = []
    monkeypatch.setattr(manifest, "read", lambda settings, key: _Record([device], files))
    monkeypatch.setattr(rawstore, "read", lambda path, key: raw)
    monkeypatch.setattr(tier3, "device_ids", lambda settings, uid, cts: lookups.append((uid, cts)) or SWITCH)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)  # type: ignore[call-arg]
    found = tier3.interface_text(settings, "k", "dev:rack-switch", 7, "UPPER_LAN")
    assert lookups == [("dev:rack-switch", 7)]
    assert found is not None and found["command"] == "unifi port_overrides + portconf"
    assert '"portconf": "Trunk"' in found["text"] and "s3cret" not in found["text"]
