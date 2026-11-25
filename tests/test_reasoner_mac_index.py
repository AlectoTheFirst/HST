"""The vlan-stretch check's MAC corroboration reads its rows through one index
(hst/reasoner.py `MacIndex`). Its counts equal those of the unindexed scan,
which reads every `mac` row four times per observation (`_scan_count`, below),
over a grid of rows and observations that covers each condition the scan
tests.
"""

from __future__ import annotations

import itertools
from typing import Any

from tests.test_reasoner import _carriage, _circuit, _stretch_rows, _StretchSession

from hst import reasoner as rules
from hst.core.normalize import iface_slug


def _scan_count(observation: dict[str, Any], mac_rows: list[dict[str, Any]]) -> int:
    """`observed_mac_count` as the unindexed scan of every row."""

    def macs(device: Any, vid: int, port_uid: str, *, on_circuit_port: bool) -> set[str]:
        slug = port_uid.rsplit("/port/", 1)[-1]
        out: set[str] = set()
        for row in mac_rows:
            if row.get("device_uid") != device or row.get("vlan") != vid or not row.get("mac"):
                continue
            name = row.get("port_name")
            same = bool(name) and iface_slug(str(name)) == slug
            if same == on_circuit_port:
                out.add(str(row["mac"]).lower())
        return out

    dev_a, dev_z = observation.get("device_a"), observation.get("device_z")
    vid, vid_z = int(observation["vid"]), int(observation["vid_z"])
    through_a = macs(dev_a, vid, observation["port_a"], on_circuit_port=True)
    local_z = macs(dev_z, vid_z, observation["port_z"], on_circuit_port=False)
    through_z = macs(dev_z, vid_z, observation["port_z"], on_circuit_port=True)
    local_a = macs(dev_a, vid, observation["port_a"], on_circuit_port=False)
    return len((through_a & local_z) | (through_z & local_a))


DEVICES = ("dev:fr2", "dev:pa3", None)
VLANS = (100, 200, None)
PORTS = ("Ethernet1/49", "Eth1/49", "ethernet1/49", "Ethernet1/7", "Po10", "", None)
MACS = ("AABB.CCDD.EE01", "aabb.ccdd.ee01", "aabbccddee02", "", None)


def _rows() -> list[dict[str, Any]]:
    """One row for every combination of device, VLAN, port name and MAC, plus
    rows that leave keys out entirely."""
    rows = [
        {"device_uid": device, "vlan": vlan, "port_name": port, "mac": mac}
        for device, vlan, port, mac in itertools.product(DEVICES, VLANS, PORTS, MACS)
    ]
    rows += [{"device_uid": "dev:fr2", "vlan": 100, "mac": "aabbccddee03"}, {"mac": "aabbccddee04"}]
    return rows


def _observations() -> list[dict[str, Any]]:
    """Every pairing of the row devices and a device no row names, over
    stretched and translated VLAN pairs, with the far end's circuit port and
    a local port as its circuit port."""
    devices = (*DEVICES, "dev:absent")
    out = []
    for device_a, device_z, (vid, vid_z), port_z in itertools.product(
        devices,
        devices,
        ((100, 100), (100, 200), (200, 100)),
        ("dev:pa3/port/eth1-49", "dev:pa3/port/eth1-7"),
    ):
        out.append(
            {
                "vid": vid,
                "vid_z": vid_z,
                "port_a": "dev:fr2/port/eth1-49",
                "port_z": port_z,
                "device_a": device_a,
                "device_z": device_z,
            }
        )
    return out


def test_the_index_counts_what_the_scan_counted():
    rows = _rows()
    index = rules.MacIndex(rows)
    counts = []
    for observation in _observations():
        expected = _scan_count(observation, rows)
        assert rules.observed_mac_count(observation, index) == expected, observation
        assert rules.observed_mac_count(observation, rows) == expected, observation
        counts.append(expected)
    # the grid is not trivially zero: it holds observations with and without corroboration
    assert min(counts) == 0 and max(counts) > 0


def test_every_subset_of_one_devices_rows_counts_what_the_scan_counted():
    """Each port and MAC combination of one device and VLAN, on its own and
    beside the far end's rows, against a stretched observation."""
    far = [{"device_uid": "dev:pa3", "vlan": 100, "port_name": "Ethernet1/7", "mac": "AABB.CCDD.EE01"}]
    observation = {
        "vid": 100,
        "vid_z": 100,
        "port_a": "dev:fr2/port/eth1-49",
        "port_z": "dev:pa3/port/eth1-49",
        "device_a": "dev:fr2",
        "device_z": "dev:pa3",
    }
    for port, mac in itertools.product(PORTS, MACS):
        near = [{"device_uid": "dev:fr2", "vlan": 100, "port_name": port, "mac": mac}]
        for rows in (near, near + far):
            assert rules.observed_mac_count(observation, rows) == _scan_count(observation, rows), rows


def test_a_run_builds_the_index_once(tmp_path, monkeypatch):
    built: list[int] = []
    index_type = rules.MacIndex

    class CountingIndex(index_type):
        def __init__(self, mac_rows: list[dict[str, Any]]) -> None:
            built.append(len(mac_rows))
            super().__init__(mac_rows)

    rows = [
        {"device_uid": "dev:fr2", "vlan": 100, "mac": "aabbccddee01", "port_name": "Ethernet1/49"},
        {"device_uid": "dev:pa3", "vlan": 100, "mac": "aabbccddee01", "port_name": "Ethernet1/7"},
    ]
    monkeypatch.setattr("hst.reasoner.vlan_stretch.MacIndex", CountingIndex)
    monkeypatch.setattr(
        "hst.reasoner.vlan_stretch.read_mac_rows", lambda sidestore_dir, devices, cts: list(rows)
    )
    circuits = [_circuit(f"eqx:connection:c{n}") for n in range(5)]
    session = _StretchSession(_stretch_rows(circuits, _carriage()))

    report = rules.check_vlan_stretch(session, collection_ts=4242, sidestore_dir=tmp_path)

    assert built == [2]
    assert [o["observed_macs"] for o in report["observations"]] == [1] * 5
