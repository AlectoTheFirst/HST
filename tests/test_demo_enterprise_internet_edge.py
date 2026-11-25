"""The internet edge of the demo estate: two IOS-XE internet routers at Equinix FR5.

fr5-inet-01 and fr5-inet-02 (tools/gen_demo_enterprise.py `fr5_internet_edges`) carry the same
configuration: an uplink on a provider /30 and /64, static default routes of both families to the
provider's gateway, which no collected interface holds, and no WAN link. The demo loader puts
fr5-inet-01 in a block of zone `internet` and fr5-inet-02 in a block of zone `external`
(fixtures/demo-enterprise/sites.yaml), and each run stamps the zone on the router
(`Device.site_zone`, `runs_exec._site_blocks`), so the two answer differently.

These tests hold the generated files and the demo loader's blocks to that, with no database.
"""

from __future__ import annotations

import importlib.util
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from hst.app import demo_estate, runs_exec
from hst.core.fixtures import load_fixture
from hst.core.model import Batch
from hst.map import site_config

ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = ROOT / "fixtures" / "demo-enterprise"
VERSIONS = (1, 2, 3)
ROUTERS = {
    "dev:fr5-inet-01": ("203.0.113.17", "2001:db8:72:e1::1", "Internet edge", "internet"),
    "dev:fr5-inet-02": ("203.0.113.21", "2001:db8:72:e2::1", "Carrier edge", "external"),
}


@cache
def _estate(version: int) -> Batch:
    return load_fixture(DEMO_DIR / f"estate-v{version}.yaml")


@cache
def _generator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "gen_demo_enterprise", ROOT / "tools" / "gen_demo_enterprise.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _nodes(batch: Batch) -> dict[str, Any]:
    return {n.uid: n for n in batch.nodes}


@pytest.mark.parametrize("version", VERSIONS)
def test_each_internet_router_is_an_ios_xe_device_with_a_default_route_of_each_family_to_an_outside_gateway(
    version: int,
) -> None:
    batch = _estate(version)
    nodes = _nodes(batch)
    held = {n.props["ip"] for n in batch.nodes if n.label == "IpAddress"}
    for dev, (gw4, gw6, _block, _zone) in ROUTERS.items():
        assert nodes[dev].label == "Device"
        assert (nodes[dev].props["platform"], nodes[dev].props["vendor"]) == ("iosxe", "cisco")
        # no WAN link: the edge is the operator's declaration alone
        assert not [r for r in batch.rels if r.rel_type == "HAS_LINK" and r.start_uid == dev]
        table = f"vrf:{dev}:default"
        defaults = {
            nodes[r.end_uid].props["cidr"]: r.props["next_hop"]
            for r in batch.rels
            if r.rel_type == "STATIC_ROUTE"
            and r.start_uid == table
            and nodes[r.end_uid].props["cidr"] in ("0.0.0.0/0", "::/0")
        }
        assert defaults == {"0.0.0.0/0": gw4, "::/0": gw6}
        # the provider's gateway is held by no collected interface
        assert gw4 not in held and gw6 not in held


def test_the_internet_routers_add_to_the_estate_and_change_no_line_of_it() -> None:
    """The routers and hosts come last in each file (`fr5_internet_edges` runs after the Oslo office)."""
    for version in VERSIONS:
        text = (DEMO_DIR / f"estate-v{version}.yaml").read_text(encoding="utf-8")
        nodes, rels = text.split("\nrels:\n")
        assert (
            nodes.rstrip().splitlines()[-1].startswith("  - ")
            and "  # --- eqx-fr5 internet routers and jump hosts" in nodes
        )
        assert rels.index("  # --- eqx-fr5 internet routers and jump hosts") > rels.index(
            "  # --- osl01 site and endpoints"
        )


def test_the_demo_loader_gives_the_routers_the_generators_blocks() -> None:
    estate = demo_estate.read(DEMO_DIR)
    (fr5,) = [s for s in estate.sites if s.code == "eqx-fr5"]
    assert [dict(b) for b in fr5.blocks] == [dict(b) for b in _generator().FR5_BLOCKS]
    # every other site has none, so a demo load stamps nothing else
    assert not [s.code for s in estate.sites if s.blocks and s.code != "eqx-fr5"]


@pytest.mark.parametrize("version", VERSIONS)
def test_the_stamp_a_demo_run_writes_names_the_routers_by_their_graph_uid(version: int) -> None:
    """The blocks the run reads after the demo loader seeded the sites, as `_write_site_config`
    reads them, become the stamp (contract A); every uid is a Device of the estate."""
    estate = demo_estate.read(DEMO_DIR)
    config = site_config.from_params(
        (s.code, {"lat": s.lat, "lon": s.lon, "blocks": [dict(b) for b in s.blocks]}) for s in estate.sites
    )
    blocks = runs_exec._site_blocks(config)
    assert blocks == {dev: (block, zone) for dev, (_g4, _g6, block, zone) in ROUTERS.items()}
    nodes = _nodes(_estate(version))
    assert all(nodes[uid].label == "Device" for uid in blocks)
