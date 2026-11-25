"""The interface description of the IOS-XE, IOS-XR and NX-OS parse, kept on
the `Interface` and on the `Port`.

NX-OS reads `desc` on a physical or port-channel row and `svi_desc` on a VLAN
interface; IOS-XE and IOS-XR read the `Description:` line of `show
interfaces`. The
reasoner's fabric-port-from-description rule reads the Equinix port name and
the cable id from the `Port` text. The overlay
`tests/support/port_description_golden.json` replaces the `inter` digest of
the cases whose payload describes an interface; the last two tests hold it to
the digest without the overlay once the descriptions are taken out again, so
the overlay can carry no other change."""

from __future__ import annotations

import importlib
import json
from typing import Any

import pytest
from tests import test_iosxe, test_iosxr, test_nxos
from tests.support.synthetic_payloads import (
    CASES,
    PORT_DESCRIPTION_GOLDEN_PATH,
    canonical_neighbor_names,
    case_payload,
    load_golden,
    route_session_change_taken_out,
    split_case,
    without_rpl_passes,
)
from tests.test_family_stream_parity import inter_digest
from tests.test_nxos_stream_parity import _golden_inter_digest

from hst.collectors import iosxe, iosxr, nxos

FABRIC_TEXT = "TO EQUINIX FABRIC - ACME-FR2-EXT-PRI-01 - CABLE ID : 21000001 - 10 GBPS"


# --- NX-OS ------------------------------------------------------------------------------


def _nxos_raw(rows: list[dict[str, Any]]) -> dict[str, str]:
    return {**test_nxos.RAW, nxos.CMD_INTERFACE: json.dumps({"TABLE_interface": {"ROW_interface": rows}})}


NXOS_ROWS = [
    {"interface": "Ethernet1/3", "state": "up", "admin_state": "up", "desc": f"  {FABRIC_TEXT} "},
    {"interface": "port-channel10", "state": "up", "admin_state": "up", "desc": "TO FABRIC PRI"},
    {"interface": "Vlan599", "svi_admin_state": "up", "svi_desc": "GLOBAL BACKBONE", "desc": "not this"},
    {"interface": "Ethernet1/4", "state": "up", "admin_state": "up", "desc": "   "},
    {"interface": "Ethernet1/5", "state": "up", "admin_state": "up"},
]


def test_nxos_reads_desc_and_svi_desc_on_a_vlan_interface():
    parsed = {i["name"]: i for i in nxos.parse(_nxos_raw(NXOS_ROWS))["interfaces"]}
    assert parsed["Ethernet1/3"]["description"] == FABRIC_TEXT
    assert parsed["port-channel10"]["description"] == "TO FABRIC PRI"
    assert parsed["Vlan599"]["description"] == "GLOBAL BACKBONE"
    # an absent or blank description adds no key
    assert "description" not in parsed["Ethernet1/4"]
    assert "description" not in parsed["Ethernet1/5"]


def test_nxos_port_and_interface_carry_the_description():
    batch = test_nxos._collector().normalize(_nxos_raw(NXOS_ROWS))
    ports = {n.props["name"]: n.props for n in batch.nodes if n.label == "Port"}
    interfaces = {n.props["name"]: n.props for n in batch.nodes if n.label == "Interface"}
    assert ports["Ethernet1/3"]["description"] == FABRIC_TEXT
    assert ports["port-channel10"]["description"] == "TO FABRIC PRI"
    assert "description" not in ports["Ethernet1/5"]
    assert interfaces["Vlan599"]["description"] == "GLOBAL BACKBONE"


# --- IOS-XE -----------------------------------------------------------------------------

IOSXE_INTERFACES_TEXT = f"""\
TenGigabitEthernet0/1/0 is up, line protocol is up
  Hardware is SFP-10GBase-LR, address is aabb.ccdd.ff00 (bia aabb.ccdd.ff00)
  Description: {FABRIC_TEXT}
  MTU 1500 bytes, BW 10000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full Duplex, 10000Mbps, link type is force-up, media type is SFP-LR
  Last input 00:00:01, output 00:00:02, output hang never
     1000 packets input, 100000 bytes, 0 no buffer
     1000 packets output, 100000 bytes, 0 underruns
TenGigabitEthernet0/1/1 is up, line protocol is up
  Hardware is SFP-10GBase-LR, address is aabb.ccdd.ff01 (bia aabb.ccdd.ff01)
  MTU 1500 bytes, BW 10000000 Kbit/sec, DLY 10 usec,
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Full Duplex, 10000Mbps, link type is force-up, media type is SFP-LR
  Last input 00:00:01, output 00:00:02, output hang never
     1000 packets input, 100000 bytes, 0 no buffer
     1000 packets output, 100000 bytes, 0 underruns
"""


def _iosxe_raw() -> dict[str, str]:
    return {**test_iosxe.RAW, iosxe.CMD_INTERFACES: IOSXE_INTERFACES_TEXT}


def test_iosxe_reads_the_description_line():
    parsed = {i["name"]: i for i in iosxe.parse(_iosxe_raw())["interfaces"]}
    assert parsed["TenGigabitEthernet0/1/0"]["description"] == FABRIC_TEXT
    assert "description" not in parsed["TenGigabitEthernet0/1/1"]


def test_iosxe_port_and_interface_carry_the_description():
    batch = test_iosxe._collector().normalize(_iosxe_raw())
    ports = {n.props["name"]: n.props for n in batch.nodes if n.label == "Port"}
    interfaces = {n.props["name"]: n.props for n in batch.nodes if n.label == "Interface"}
    assert ports["TenGigabitEthernet0/1/0"]["description"] == FABRIC_TEXT
    assert interfaces["TenGigabitEthernet0/1/0"]["description"] == FABRIC_TEXT
    assert "description" not in ports["TenGigabitEthernet0/1/1"]


# --- IOS-XR -----------------------------------------------------------------------------

IOSXR_INTERFACES_TEXT = f"""\
TenGigE0/0/0/1 is up, line protocol is up
  Interface state transitions: 1
  Hardware is TenGigE, address is aabb.ccdd.ff10 (bia aabb.ccdd.ff10)
  Description: {FABRIC_TEXT}
  Internet address is Unknown
  MTU 1514 bytes, BW 10000000 Kbit
  reliability 255/255, txload 0/255, rxload 0/255
  Encapsulation ARPA,
  Full-duplex, 10000Mb/s, LR, link type is force-up
  Last input never, output never
  Last clearing of "show interface" counters never
TenGigE0/0/0/2 is up, line protocol is up
  Interface state transitions: 1
  Hardware is TenGigE, address is aabb.ccdd.ff11 (bia aabb.ccdd.ff11)
  Internet address is Unknown
  MTU 1514 bytes, BW 10000000 Kbit
  reliability 255/255, txload 0/255, rxload 0/255
  Encapsulation ARPA,
  Full-duplex, 10000Mb/s, LR, link type is force-up
  Last input never, output never
  Last clearing of "show interface" counters never
"""


def _iosxr_raw() -> dict[str, str]:
    return {**test_iosxr.RAW, iosxr.CMD_INTERFACES: IOSXR_INTERFACES_TEXT}


def test_iosxr_reads_the_description_line():
    parsed = {i["name"]: i for i in iosxr.parse(_iosxr_raw())["interfaces"]}
    assert parsed["TenGigE0/0/0/1"]["description"] == FABRIC_TEXT
    assert "description" not in parsed["TenGigE0/0/0/2"]


def test_iosxr_port_and_interface_carry_the_description():
    batch = test_iosxr._collector().normalize(_iosxr_raw())
    ports = {n.props["name"]: n.props for n in batch.nodes if n.label == "Port"}
    interfaces = {n.props["name"]: n.props for n in batch.nodes if n.label == "Interface"}
    assert ports["TenGigE0/0/0/1"]["description"] == FABRIC_TEXT
    assert interfaces["TenGigE0/0/0/1"]["description"] == FABRIC_TEXT
    assert "description" not in ports["TenGigE0/0/0/2"]


# --- the golden overlay ----------------------------------------------------------------


def _overlay_cases() -> dict[str, Any]:
    return json.loads(PORT_DESCRIPTION_GOLDEN_PATH.read_text(encoding="utf-8"))["cases"]


def _parse(key: str) -> dict[str, Any]:
    # The rpl-pass and route-session overlays (tests/test_rpl_pass_golden.py,
    # tests/test_route_session_golden.py) are recorded over this one.
    with route_session_change_taken_out():
        return without_rpl_passes(
            importlib.import_module(f"hst.collectors.{split_case(key)[0]}").parse(case_payload(key))
        )


def _digest(key: str, inter: dict[str, Any]) -> str:
    # each family's parity test reads the digest its own way
    return _golden_inter_digest(inter) if split_case(key)[0] == "nxos" else inter_digest(inter)


def test_the_overlay_names_exactly_the_cases_whose_payload_describes_an_interface():
    described = {
        key
        for key in CASES
        if split_case(key)[0] in ("iosxe", "iosxr", "nxos")
        and any("description" in i for i in _parse(key)["interfaces"])
    }
    assert set(_overlay_cases()) == described
    assert all(set(fields) == {"inter"} for fields in _overlay_cases().values())


@pytest.mark.parametrize("key", sorted(_overlay_cases()))
def test_an_overlay_digest_is_the_one_without_it_once_the_descriptions_are_taken_out(key):
    inter = canonical_neighbor_names(split_case(key)[0], _parse(key))
    assert _digest(key, inter) == _overlay_cases()[key]["inter"]
    stripped = {
        **inter,
        "interfaces": [{k: v for k, v in i.items() if k != "description"} for i in inter["interfaces"]],
    }
    assert _digest(key, stripped) == load_golden(port_description=False, ifname=False)["cases"][key]["inter"]
