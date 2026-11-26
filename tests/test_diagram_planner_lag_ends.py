"""Where a LAG member port with no cable in the drawing ends (hst/diagram/planner.py): at
its exit, at the CDP or LLDP neighbor no collector reached, at a stub with the
neighbor that is a device of the drawing, or at a stub with no neighbor."""

from __future__ import annotations

from hst.diagram import planner


def _dev(uid: str, tier: str = "core") -> dict:
    return {"uid": uid, "name": uid, "role": "switch", "tier": tier, "role_basis": "hostname", "site": "fr2"}


def _lag(ports: list[str], neighbors: list[dict] | None = None) -> dict:
    return {"uid": "lag:sw1:po51", "dev": "sw1", "name": "Po51", "ports": ports, "neighbors": neighbors or []}


def _plan(cables: list[dict], lag: dict) -> dict:
    return planner.plan([_dev("sw1"), _dev("rt1", "internet-edge")], cables, [lag])


def _cdp(port: str, name: str, far_port: str) -> dict:
    return {"port": port, "name": name, "far_port": far_port, "proto": "cdp"}


def test_a_member_cabled_to_a_device_outside_the_drawing_is_an_exit_and_no_loose_end():
    out = {"a_dev": "sw1", "a_port": "Eth1/101", "b_dev": "sw9", "b_port": "Eth1/101", "b_name": "SW9"}
    model = _plan([{**out, "source": "cdp"}], _lag(["Eth1/101", "Eth1/102"]))

    [lag] = model["lags"]
    assert lag["ports_without_cable"] == ["Eth1/102"]
    assert [(e["port"], e["far_name"]) for e in model["exits"]] == [("Eth1/101", "SW9")]


def test_a_member_whose_neighbor_no_collector_reached_is_an_exit_to_that_neighbor():
    neighbors = [_cdp("Eth1/107", "SWA-01(FDO12345678)", "Ethernet1/107")]
    model = _plan([], _lag(["Eth1/107", "Eth1/108"], neighbors))

    [lag] = model["lags"]
    assert lag["ports_without_cable"] == ["Eth1/108"]
    assert model["exits"] == [
        {
            "dev": "sw1",
            "port": "Eth1/107",
            "far_dev": "",
            "far_port": "Ethernet1/107",
            "far_name": "SWA-01",
            "source": "cdp, no cable",
        }
    ]


def test_a_neighbor_hint_on_a_cabled_member_adds_nothing():
    cable = {"a_dev": "sw1", "a_port": "Eth1/1", "b_dev": "rt1", "b_port": "Gi1", "source": "cdp"}
    model = _plan([cable], _lag(["Eth1/1"], [_cdp("Eth1/1", "rt1", "Gi1")]))

    assert model["exits"] == []
    assert model["lags"][0]["ports_without_cable"] == []


def test_a_neighbor_no_collector_reached_is_no_way_out_of_the_site():
    model = _plan([], _lag(["Eth1/107"], [_cdp("Eth1/107", "SWA-01", "Ethernet1/107")]))

    sw1 = next(n for n in model["nodes"] if n["id"] == "sw1")
    assert sw1["anchor"] is None


def test_a_neighbor_that_is_a_drawn_device_is_no_exit_and_the_lag_lists_it():
    # the neighbor is rt1, in this drawing, and the reasoner wrote no cable to it
    neighbors = [
        _cdp("Eth1/107", "RT1.corp.example(FDO12345678)", "Gi0/1"),
        {"port": "Eth1/108", "name": "rt1", "far_port": None, "proto": "lldp"},
    ]
    model = _plan([], _lag(["Eth1/107", "Eth1/108", "Eth1/109"], neighbors))

    assert model["exits"] == []
    [lag] = model["lags"]
    assert lag["ports_without_cable"] == ["Eth1/107", "Eth1/108", "Eth1/109"]
    assert lag["neighbors_without_cable"] == [
        {"port": "Eth1/107", "far_name": "RT1.corp.example", "far_port": "Gi0/1", "source": "cdp, no cable"},
        {"port": "Eth1/108", "far_name": "rt1", "far_port": None, "source": "lldp, no cable"},
    ]


def test_a_member_at_an_exit_has_no_row_in_the_neighbors_without_cable():
    neighbors = [_cdp("Eth1/107", "SWA-01", "Ethernet1/107")]
    model = _plan([], _lag(["Eth1/107"], neighbors))

    assert model["lags"][0]["neighbors_without_cable"] == []
