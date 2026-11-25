"""The layout over 4 projected runs against a scratch Neo4j: two devices without a site, then with their
site, then two unchanged runs."""

from typing import Any

import pytest
from tests.hst.conftest import drop_runs, fixture_batches, load_runs

from hst.core import manifest as manifestmod
from hst.core.model import Batch
from hst.map import layout, layout_read, markers
from hst.map.project import Projection

RUNS = (4_600_000_000_000, 4_600_000_060_000, 4_600_000_120_000, 4_600_000_180_000)
# The two devices of site fra01 in the "other" layer: no row of the plate takes them, so they are annexed.
MOVED = ("dev:fra01-ips-01", "dev:fra01-wlc-01")
SITE = "site:fra01"

pytestmark = pytest.mark.db


def _unsited(batch: Batch) -> None:
    batch.rels = [r for r in batch.rels if not (r.rel_type == "LOCATED_IN" and r.start_uid in MOVED)]


@pytest.fixture(scope="module")
def runs(neo4j_session: Any, tmp_path_factory: pytest.TempPathFactory) -> Any:
    session = neo4j_session
    base = tmp_path_factory.mktemp("layout")
    markers_dir, sidestore = base / "manifests", base / "sidestore"
    load_runs(session, RUNS, lambda run: fixture_batches(_unsited if run == 0 else None))
    parent = None
    for key in RUNS:
        projection = Projection(sidestore, markers_dir, key, parent, "full")
        if parent is not None:
            manifestmod.graph_delta(session, parent, key, observer=projection.observe)
        projection.prepare(session)
        projection.publish(None)
        assert projection.failed is None, projection.failed
        parent = key
    yield markers_dir, sidestore
    drop_runs(session, RUNS)


def _inside(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    return (
        parent["u"] <= child["u"]
        and child["u"] + child["w"] <= parent["u"] + parent["w"]
        and parent["v"] <= child["v"]
        and child["v"] + child["h"] <= parent["v"] + parent["h"]
    )


def test_a_device_that_gets_its_site_moves_once_and_its_old_blocks_leave(runs: Any) -> None:
    _markers_dir, sidestore = runs
    before = layout_read.rows_at(sidestore, RUNS[0])
    old_blocks = {before[d]["parent_uid"] for d in MOVED}
    assert all(b.startswith("block:unassigned:") for b in old_blocks)
    at = layout_read.rows_at(sidestore, RUNS[1])
    for device in MOVED:
        assert at[device]["valid_from_ts"] == RUNS[1]
        assert at[device]["parent_uid"].startswith("block:fra01:")
    assert not old_blocks & set(at)
    delta = {r["uid"]: r for r in layout_read.delta_at(sidestore, RUNS[1])}
    assert {delta[b]["reason"] for b in old_blocks} == {layout.REMOVED}


def test_the_blocks_of_the_site_lie_inside_its_plate_and_the_plate_inside_the_site(runs: Any) -> None:
    _markers_dir, sidestore = runs
    for key in RUNS[1:]:
        at = layout_read.rows_at(sidestore, key)
        plate = at[layout.plate_uid(SITE)]
        assert _inside(plate, at[SITE]), key
        blocks = [r for r in at.values() if r["kind"] == "block" and r["parent_uid"] == plate["uid"]]
        assert blocks
        for block in blocks:
            assert _inside(block, plate), (key, block["uid"])


def test_the_unchanged_runs_write_no_layout_row_and_keep_every_position(runs: Any) -> None:
    markers_dir, sidestore = runs
    placed = layout_read.rows_at(sidestore, RUNS[1])
    for key in RUNS[2:]:
        assert layout_read.delta_at(sidestore, key) == [], key
        assert layout_read.rows_at(sidestore, key) == placed, key
        marker = markers.read(markers_dir, key)
        assert marker is not None and marker["replan_recommended"] is False, key
