"""The publish-time projection on the fixtures loaded as 3 runs, against a scratch Neo4j."""

from pathlib import Path
from typing import Any

import pytest
from tests.hst.conftest import drop_runs, fixture_batches, load_runs
from tests.hst.test_fold_db import _edit

from hst.core import manifest as manifestmod
from hst.map import events, layout, layout_read, markers, store, timeline
from hst.map.project import Projection, reconcile
from hst.map.tiers import read
from hst.map.tiers.fold import TIER_TABLES

RUNS = (4_400_000_000_000, 4_400_000_060_000, 4_400_000_120_000)

pytestmark = pytest.mark.db


def _project(session: Any, dirs: tuple[Path, Path], key: int, parent: int | None) -> Projection:
    markers_dir, sidestore = dirs
    projection = Projection(sidestore, markers_dir, key, parent, "full")
    if parent is not None:
        manifestmod.graph_delta(session, parent, key, observer=projection.observe)
    projection.prepare(session)
    return projection


class RecordingBus(events.LocalBus):
    def __init__(self, *args: Any) -> None:
        super().__init__(*args)
        self.live: list[events.Event] = []

    def publish(self, event: events.Event) -> None:
        super().publish(event)
        self.live.append(event)


@pytest.fixture(scope="module")
def published(neo4j_session: Any, tmp_path_factory: pytest.TempPathFactory) -> Any:
    session = neo4j_session
    base = tmp_path_factory.mktemp("project")
    dirs = (base / "manifests", base / "sidestore")
    load_runs(session, RUNS, lambda run: fixture_batches(_edit if run == 1 else None))
    bus = RecordingBus(*dirs)
    projections = []
    parent = None
    for key in RUNS:
        projection = _project(session, dirs, key, parent)
        projection.publish(bus)
        projections.append(projection)
        parent = key
    yield dirs, projections, bus
    drop_runs(session, RUNS)


def test_every_run_publishes_its_tiers_layout_and_marker(published: Any) -> None:
    (markers_dir, sidestore), projections, _bus = published
    for key, projection in zip(RUNS, projections, strict=True):
        assert projection.failed is None, projection.failed
        marker = markers.read(markers_dir, key)
        assert marker is not None and marker["tiers_ready"] is True and marker["state"] == "warm"
        assert set(marker["durations_ms"]) == {"delta", "attribution", "fold", "layout", "write"}
        assert marker["peak_memory_bytes"] > 0
        for name in TIER_TABLES:
            assert store.table_path(sidestore, name, key).exists(), name
        assert not store.staging_dir(sidestore, key).exists()
    assert not store.table_path(sidestore, "graph_delta", RUNS[0]).exists()
    assert store.table_path(sidestore, "graph_delta", RUNS[1]).exists()
    assert markers.read(markers_dir, RUNS[1])["counts"]["removed"] == 1


def test_the_parent_of_each_run_is_its_predecessor(published: Any) -> None:
    (markers_dir, _sidestore), _p, _bus = published
    assert timeline.chain(markers_dir) == list(RUNS)
    assert [r["parent"] for r in timeline.timeline(markers_dir)["runs"]] == [None, RUNS[0], RUNS[1]]


def test_the_layout_places_every_element_once_and_only_new_ones_later(published: Any) -> None:
    (_markers_dir, sidestore), projections, _bus = published
    first = layout_read.delta_at(sidestore, RUNS[0])
    assert {r["reason"] for r in first} == {layout.FIRST_SEEN}
    assert len(layout_read.rows_at(sidestore, RUNS[2])) >= len(first)
    before = layout_read.rows_at(sidestore, RUNS[0])
    # A block, plate or site that holds no device in the run leaves the layout with a `removed` row:
    # in run 1 the edit deletes the only device of its block.
    second = projections[1].folded
    assert second is not None
    occupied = set(layout.hierarchy(second.estate).device_block.values())
    for row in layout_read.delta_at(sidestore, RUNS[1]):
        new_uid = row["uid"] not in before
        if row["reason"] == layout.REMOVED:
            assert row["kind"] in ("block", "plate", "site") and row["uid"] not in occupied, row
            continue
        assert new_uid or row["reason"] in (layout.RELATION_RESOLVED, layout.ANNEX), row
    folded = projections[2].folded
    assert folded is not None
    every = {*layout.hierarchy(folded.estate).device_block}
    assert every <= set(layout_read.rows_at(sidestore, RUNS[2]))


def test_replay_equals_the_live_sequence(published: Any) -> None:
    (markers_dir, sidestore), _p, bus = published
    for key in RUNS:
        live = [e for e in bus.live if e.run_key == key]
        replay = events.LocalBus(markers_dir, sidestore).replay(key)
        assert replay == live
        assert replay[0].type == events.RUN_PUBLISHED and replay[-1].type == events.RUN_TIERS_READY
        assert [e.seq for e in replay] == list(range(len(replay)))
    assert any(e.type == events.DELTA_RECORD for e in bus.live)
    assert any(e.type == events.LAYOUT_CHANGED for e in bus.live)


def test_the_tier_at_a_run_reads_back_what_the_fold_wrote(published: Any) -> None:
    (markers_dir, sidestore), projections, _bus = published
    folded = projections[1].folded
    assert folded is not None
    table = read.tier_at(sidestore, "render_t1", RUNS[1], timeline.chain(markers_dir))
    assert table.to_pylist() == folded.tables["render_t1"]


def test_the_marker_heals_after_a_crash_between_the_pointer_move_and_the_marker_write(
    neo4j_session: Any, published: Any, tmp_path: Path
) -> None:
    healing = (tmp_path / "manifests", tmp_path / "sidestore")
    _project(neo4j_session, healing, RUNS[0], None)
    assert markers.read(healing[0], RUNS[0]) is None
    assert reconcile(healing[1], healing[0], RUNS[0], lambda key: {})
    healed = markers.read(healing[0], RUNS[0])
    assert healed is not None and healed["tiers_ready"] is True
    assert store.table_path(healing[1], "render_t1", RUNS[0]).exists()
