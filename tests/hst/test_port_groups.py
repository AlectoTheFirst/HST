"""Port groups: one row per device and module or name range."""

from typing import Any

import pytest

from hst.map import port_groups


def _port(device: str, name: str, **status: Any) -> dict[str, Any]:
    return {"uid": f"{device}/port/{name}", "device_uid": device, "tile": "block:b", "name": name, **status}


@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("Ethernet1/12", "Ethernet1/"),
        ("eth0", "eth"),
        ("Port 17", "Port "),
        ("ge-0/0/3", "ge-0/0/"),
        ("mgmt", "mgmt"),
    ],
)
def test_the_group_key_strips_the_trailing_port_number(name: str, key: str) -> None:
    assert port_groups.group_key(name) == key


def test_first_and_last_follow_the_natural_order() -> None:
    names = ["Ethernet1/10", "Ethernet1/2", "Ethernet1/1", "Ethernet1/48", "Ethernet1/9"]
    [row] = port_groups.groups([_port("dev:a", n) for n in names], [])
    assert (row["first_name"], row["last_name"], row["port_count"]) == ("Ethernet1/1", "Ethernet1/48", 5)
    assert sorted(names, key=port_groups.natural) == [
        "Ethernet1/1",
        "Ethernet1/2",
        "Ethernet1/9",
        "Ethernet1/10",
        "Ethernet1/48",
    ]


def test_groups_are_ordered_by_device_then_group_key_in_natural_order() -> None:
    ports = [
        _port("dev:b", "eth0"),
        _port("dev:a", "Ethernet10/1"),
        _port("dev:a", "Ethernet2/1"),
        _port("dev:a", "Ethernet1/1"),
    ]
    rows = port_groups.groups(ports, [])
    assert [(r["device_uid"], r["group_key"]) for r in rows] == [
        ("dev:a", "Ethernet1/"),
        ("dev:a", "Ethernet2/"),
        ("dev:a", "Ethernet10/"),
        ("dev:b", "eth"),
    ]
    assert port_groups.groups(list(reversed(ports)), []) == rows
    assert all(list(r) == list(port_groups.COLUMNS) for r in rows)


def test_state_counts_put_each_port_in_at_most_one_state() -> None:
    ports = [
        _port("dev:a", "eth0", admin_status="up", oper_status="up"),
        _port("dev:a", "eth1", admin_status="up", oper_status="down"),
        _port("dev:a", "eth2", admin_status="down", oper_status="down"),
        _port("dev:a", "eth3", oper_status="administratively down"),
        _port("dev:a", "eth4", oper_status="lowerLayerDown"),
        _port("dev:a", "eth5"),
        _port("dev:a", "eth6", oper_status="unknown"),
    ]
    [row] = port_groups.groups(ports, [])
    assert (row["port_count"], row["up"], row["down"], row["admin_down"]) == (7, 1, 2, 2)


def test_connected_counts_the_ports_at_either_end_of_a_cable() -> None:
    ports = [_port("dev:a", f"eth{i}") for i in range(4)] + [_port("dev:b", "eth0")]
    cables: list[dict[str, Any]] = [
        {"a_port": "dev:a/port/eth0", "b_port": "dev:b/port/eth0"},
        {"a_port": "dev:c/port/eth9", "b_port": "dev:a/port/eth2"},
        {"a_port": "dev:a/port/eth3", "b_port": None},
    ]
    rows = {r["device_uid"]: r for r in port_groups.groups(ports, cables)}
    assert (rows["dev:a"]["connected"], rows["dev:b"]["connected"]) == (3, 1)


def test_a_device_with_2000_ports_gives_few_groups() -> None:
    ports = [_port("leaf:1", f"Ethernet{m}/{p}") for m in range(1, 43) for p in range(1, 49)][:2000]
    ports.append(_port("leaf:1", "mgmt0"))
    rows = port_groups.groups(ports, [])
    assert len(rows) == 43
    assert sum(r["port_count"] for r in rows) == 2001
    assert (rows[0]["group_key"], rows[0]["first_name"], rows[0]["last_name"]) == (
        "Ethernet1/",
        "Ethernet1/1",
        "Ethernet1/48",
    )
    assert rows[-1]["group_key"] == "mgmt"
