"""Traces through the internet edge of the demo estate.

fr5-inet-01 (zone `internet`) and fr5-inet-02 (zone `external`) are two IOS-XE routers with the
same configuration: a static default of each family to a provider gateway no collected interface
holds, and no WAN link (tests/test_demo_enterprise_internet_edge.py). Each jump host sits on its
core, which routes the default to its router. The run stamps the zone on each router's Device;
here the stamp is set on the Batch before `TraceGraph` reads it, from the demo loader's blocks.

The tracer runs on the generated estate of each version with no database (tests/support/
demo_trace_graph.py). Every read is answered (`refused == []`).
"""

from __future__ import annotations

import copy
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from tests.support.demo_trace_graph import TraceGraph

from hst import path
from hst.app import demo_estate, runs_exec
from hst.core.fixtures import load_fixture
from hst.core.model import Batch
from hst.map import site_config

DEMO_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "demo-enterprise"
VERSIONS = (1, 2, 3)
INTERNET = "Internet edge"
# 192.0.2.200: an internet address no device of the estate routes. The generator's
# 192.0.2.77 is inside osl01-vyos-01's static 192.0.2.0/25, so the estate routes it
# (`test_an_address_another_device_routes_is_no_exit_at_the_internet_router`).
V4 = ("10.72.101.10", "192.0.2.200", "0.0.0.0/0", "203.0.113.17", "10.72.101.0/24")
V6 = ("2001:db8:72:101::10", "2001:db8:ffff::77", "::/0", "2001:db8:72:e1::1", "2001:db8:72:101::/64")
ZONE = '(the operator\'s site zone "internet" of block Internet edge)'


@cache
def _raw(version: int) -> Batch:
    return load_fixture(DEMO_DIR / f"estate-v{version}.yaml")


@cache
def _blocks() -> dict[str, tuple[str, str]]:
    """The stamp a demo run writes: device uid -> (block, zone), from the loader's blocks."""
    estate = demo_estate.read(DEMO_DIR)
    config = site_config.from_params(
        (s.code, {"lat": s.lat, "lon": s.lon, "blocks": [dict(b) for b in s.blocks]}) for s in estate.sites
    )
    return runs_exec._site_blocks(config)


def _trace(version: int, src: str, dst: str, stamp: dict[str, tuple[str, str]] | None = None) -> Any:
    """`path.trace(..., reply=True)` on the estate with `stamp` (the demo run's by default)."""
    batch = copy.deepcopy(_raw(version))
    for node in batch.nodes:
        if node.uid in (_blocks() if stamp is None else stamp):
            node.props["site_block"], node.props["site_zone"] = (_blocks() if stamp is None else stamp)[
                node.uid
            ]
    graph = TraceGraph(batch)
    result = path.trace(graph, src, dst, port=443, proto="tcp", reply=True)
    assert graph.refused == []
    return result


def _devices(walk: dict[str, Any]) -> list[str]:
    return [h["uid"] for h in sorted(walk["hops"], key=lambda h: h["rank"]) if h["kind"] == "Device"]


def test_the_demo_run_stamps_the_internet_router_internet_and_the_other_external() -> None:
    assert _blocks() == {
        "dev:fr5-inet-01": (INTERNET, "internet"),
        "dev:fr5-inet-02": ("Carrier edge", "external"),
    }


# --- cases 1 and 2: zone internet ---------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("flow", [V4, V6], ids=["ipv4", "ipv6"])
def test_a_jump_host_leaves_the_estate_by_the_internet_routers_zone(
    version: int, flow: tuple[str, ...]
) -> None:
    src, dst, default, gateway, lan = flow
    result = _trace(version, src, dst)

    forward = result["forward"]
    exit_ = {
        "basis": "site-zone",
        "device_uid": "dev:fr5-inet-01",
        "device": "fr5-inet-01",
        "interface_uid": "dev:fr5-inet-01/if/gi0-0-1",
        "interface": "GigabitEthernet0/0/1",
        "next_hop": gateway,
        "wan_link_uid": None,
        "wan_link": None,
        "site_block": INTERNET,
    }
    assert _devices(forward) == ["dev:fr5-core-01", "dev:fr5-inet-01"]
    (leg,) = forward["legs"]
    assert leg["left_estate"] == exit_
    assert forward["left_estate"] == [exit_]
    assert forward["reach"] == "left_estate"
    assert forward["boundary"] is True and forward["indeterminate"] is False
    assert forward["warnings"] == []
    assert forward["verdict"] == (
        f"{src} → {dst}:443/tcp: egress via GigabitEthernet0/0/1 ({default}, main table) · leaves the estate "
        f"at fr5-inet-01 GigabitEthernet0/0/1 to next hop {gateway} {ZONE}"
    )

    reply = result["reply"]
    first = reply["hops"][0]
    assert (first["stage"], first["uid"]) == ("SRC_ENDPOINT", "dev:fr5-inet-01/if/gi0-0-1")
    assert reply["verdict"] == f"reply: egress via ethernet1/10 ({lan}, main table)"
    assert reply["reach"] == "destination" and reply["left_estate"] == []
    # the reply retraces the forward path reversed: no asymmetry is reported
    assert result["asymmetric"] is False
    assert result["notes"] == []


# --- cases 3 and 4: zone external ----------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize(
    ("src", "default"), [("10.72.102.10", "0.0.0.0/0"), ("2001:db8:72:102::10", "::/0")], ids=["ipv4", "ipv6"]
)
def test_the_external_router_keeps_todays_answer(version: int, src: str, default: str) -> None:
    dst = "192.0.2.77" if ":" not in src else "2001:db8:ffff::77"
    result = _trace(version, src, dst)

    forward = result["forward"]
    assert _devices(forward) == ["dev:fr5-core-02", "dev:fr5-inet-02"]
    assert (
        forward["verdict"]
        == f"{src} → {dst}:443/tcp: egress via GigabitEthernet0/0/1 ({default}, main table)"
    )
    assert forward["reach"] is None and forward["left_estate"] == []
    assert forward["boundary"] is True
    assert "left_estate" not in forward["legs"][0]
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"
    assert result["reply"]["reach"] is None and result["reply"]["left_estate"] == []
    # byte for byte the same trace with no stamp at all
    assert result == _trace(version, src, dst, stamp={})


# --- case 5: the control ------------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("flow", [V4, V6], ids=["ipv4", "ipv6"])
@pytest.mark.parametrize("zone", [None, "external", "internal"])
def test_the_internet_router_with_no_internet_zone_reads_as_today(
    version: int, flow: tuple[str, ...], zone: str | None
) -> None:
    src, dst, default, _gateway, _lan = flow
    stamp = {} if zone is None else {"dev:fr5-inet-01": (INTERNET, zone)}
    result = _trace(version, src, dst, stamp=stamp)

    assert result == _trace(version, src, dst, stamp={})
    forward = result["forward"]
    assert (
        forward["verdict"]
        == f"{src} → {dst}:443/tcp: egress via GigabitEthernet0/0/1 ({default}, main table)"
    )
    assert forward["reach"] is None and forward["left_estate"] == []
    assert any("is not held by any interface in the graph" in w for w in forward["warnings"])
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"
    assert result["reply"]["reach"] is None and result["reply"]["left_estate"] == []


# --- an address the estate routes elsewhere ------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_an_address_another_device_routes_is_no_exit_at_the_internet_router(version: int) -> None:
    """osl01-vyos-01 has a static 192.0.2.0/25 to 10.18.99.1: another device of the estate has
    a route to 192.0.2.77, so fr5-inet-01's default route to it is a route missing there, not
    the internet. The walk reads as an edge with no basis, and the warning names the route."""
    result = _trace(version, "10.72.101.10", "192.0.2.77")

    forward = result["forward"]
    assert _devices(forward) == ["dev:fr5-core-01", "dev:fr5-inet-01"]
    assert "left_estate" not in forward["legs"][0]
    assert forward["left_estate"] == [] and forward["reach"] is None
    assert forward["warnings"] == [
        "10.72.101.10: next hop 203.0.113.17 is not held by any interface in the graph; "
        "the path leaves the twin at fr5-inet-01",
        "10.72.101.10: another device of the estate has a route to the destination 192.0.2.77, and "
        "fr5-inet-01 has no route to it other than the default route 0.0.0.0/0 by GigabitEthernet0/0/1",
    ]
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"


# --- the owner's shape: the Oslo VyOS router with a collected WAN link --------------------------


@pytest.mark.parametrize("version", VERSIONS)
def test_the_wan_link_router_to_a_public_address_leaves_the_estate(version: int) -> None:
    result = _trace(version, "10.18.10.21", "192.0.2.180", stamp={})

    forward = result["forward"]
    assert [e["basis"] for e in forward["left_estate"]] == ["wan-link"]
    assert forward["reach"] == "left_estate" and forward["warnings"] == []
    assert result["reply"]["verdict"] == "reply: egress via eth1.10 (10.18.10.0/24, main table)"


@pytest.mark.parametrize("version", VERSIONS)
def test_the_wan_link_router_to_an_unknown_private_address_is_no_exit(version: int) -> None:
    """A private address is never on the internet."""
    result = _trace(version, "10.18.10.21", "172.31.99.9", stamp={})

    forward = result["forward"]
    assert forward["left_estate"] == [] and forward["reach"] is None
    assert forward["warnings"][-1] == (
        "10.18.10.21: the destination 172.31.99.9 is a private address that no device of the estate "
        "serves, and osl01-vyos-01 has no route to it other than the default route 0.0.0.0/0 by eth0"
    )
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"
