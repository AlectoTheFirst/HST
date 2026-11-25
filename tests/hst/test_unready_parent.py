"""A run whose parent has no tiers."""

from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from hst.map import markers, store, sweep, timeline
from hst.map.project import Projection
from hst.map.tiers import delta, read
from hst.map.tiers.fold import TIER_TABLES
from hst.map.tiers.schemas import SCHEMAS


def _marker(key: int, parent: int | None, *, ready: bool = True, state: str = "warm") -> dict[str, Any]:
    return {
        "key": key,
        "kind": "full",
        "parent": parent,
        "published_ts": key,
        "state": state,
        "tiers_ready": ready,
    }


def _write(sidestore: Path, name: str, key: int, rows: list[dict[str, Any]]) -> None:
    path = store.table_path(sidestore, name, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows, schema=SCHEMAS[name]), path)


def _t1(uid: str, ports: int, ts: int) -> dict[str, Any]:
    return {"uid": uid, "label": uid, "n_ports": ports, "snapshot_ts": ts}


def _write_delta(
    sidestore: Path, key: int, parent: int, before: list[dict[str, Any]], after: list[dict[str, Any]]
) -> None:
    old = {r["uid"]: r for r in before}
    new = {r["uid"]: r for r in after}
    rows = [{**r, "snapshot_ts": key, "parent_ts": parent} for r in delta.changes("render_t1", old, new)]
    _write(sidestore, "render_t1_delta", key, rows)


def _gap(markers_dir: Path) -> None:
    """Runs 10 and 20 are ready, 30 failed, 40 and 50 are ready."""
    for key, parent, ready in (
        (10, None, True),
        (20, 10, True),
        (30, 20, False),
        (40, 30, True),
        (50, 40, True),
    ):
        markers.write(markers_dir, _marker(key, parent, ready=ready))


def test_the_chain_names_the_runs_whose_parent_has_no_tiers(tmp_path: Path) -> None:
    _gap(tmp_path)
    chain = timeline.chain(tmp_path)
    assert chain == [10, 20, 30, 40, 50]
    assert chain.rebased == {40}


def test_a_marker_without_the_field_is_not_a_failed_run(tmp_path: Path) -> None:
    markers.write(tmp_path, {"key": 1, "kind": "full", "parent": None, "published_ts": 1, "state": "warm"})
    markers.write(tmp_path, {"key": 2, "kind": "full", "parent": 1, "published_ts": 2, "state": "warm"})
    assert timeline.chain(tmp_path).rebased == frozenset()


def test_the_ready_ancestor_skips_the_failed_runs(tmp_path: Path) -> None:
    _gap(tmp_path)
    markers.write(tmp_path, _marker(35, 30, ready=False))
    assert timeline.ready_ancestor(tmp_path, 35) == 20
    assert timeline.ready_ancestor(tmp_path, 20) == 20
    assert timeline.ready_ancestor(tmp_path, 99) is None


def test_the_fold_diffs_against_the_newest_run_with_tiers_when_the_parent_failed(tmp_path: Path) -> None:
    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    _gap(markers_dir)
    _write(sidestore, "render_t1", 20, [_t1("a", 1, 20), _t1("b", 1, 20)])
    projection = Projection(sidestore, markers_dir, 40, 30, "full")
    assert projection.parent_key == 30
    assert projection._parent is not None
    assert projection._parent.key == 20 and projection._parent.ready
    assert projection._rebased


def test_the_fold_keeps_the_parent_when_it_has_tiers(tmp_path: Path) -> None:
    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    _gap(markers_dir)
    _write(sidestore, "render_t1", 50, [_t1("a", 1, 50)])
    projection = Projection(sidestore, markers_dir, 60, 50, "full")
    assert projection._parent is not None and projection._parent.key == 50
    assert not projection._rebased


def test_the_fold_falls_back_to_the_failed_parent_when_no_earlier_run_has_tiers(tmp_path: Path) -> None:
    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    _gap(markers_dir)
    projection = Projection(sidestore, markers_dir, 40, 30, "full")
    assert projection._parent is not None and projection._parent.key == 30 and not projection._parent.ready
    assert projection._rebased


def _history(sidestore: Path, *, keep_own_file: bool) -> None:
    """Run 3 failed."""
    run1, run2 = [_t1("a", 1, 1), _t1("b", 1, 1)], [_t1("a", 1, 2), _t1("b", 1, 2)]
    run4 = [_t1("a", 1, 4)]
    _write(sidestore, "render_t1", 1, run1)
    _write_delta(sidestore, 2, 1, run1, run2)
    _write_delta(sidestore, 4, 3, [], run4)
    if keep_own_file:
        _write(sidestore, "render_t1", 4, run4)
    _write_delta(sidestore, 5, 4, run4, [_t1("a", 2, 5)])


def test_a_cold_read_after_a_run_without_tiers_starts_at_the_run_after_the_gap(tmp_path: Path) -> None:
    _history(tmp_path, keep_own_file=True)
    chain = timeline.Chain([1, 2, 3, 4, 5], rebased=[4])
    got = {r["uid"]: r["n_ports"] for r in read.tier_at(tmp_path, "render_t1", 5, chain).to_pylist()}
    assert got == {"a": 2}


def test_a_cold_read_never_composes_across_the_gap_from_an_earlier_base(tmp_path: Path) -> None:
    _history(tmp_path, keep_own_file=False)
    chain = timeline.Chain([1, 2, 3, 4, 5], rebased=[4])
    with pytest.raises(read.NotFound):
        read.tier_at(tmp_path, "render_t1", 5, chain)
    with pytest.raises(read.NotFound):
        read.tier_at(tmp_path, "render_t1", 4, chain)
    assert {r["uid"] for r in read.tier_at(tmp_path, "render_t1", 2, chain).to_pylist()} == {"a", "b"}


def test_a_chain_without_the_gap_marks_composes_across_the_failed_run(tmp_path: Path) -> None:
    _history(tmp_path, keep_own_file=False)
    got = read.tier_at(tmp_path, "render_t1", 5, [1, 2, 3, 4, 5])
    assert {r["uid"] for r in got.to_pylist()} == {"a", "b"}


def test_a_tier_prune_keeps_the_files_of_a_cold_run_whose_parent_has_no_tiers(tmp_path: Path) -> None:
    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    for key, parent, ready in ((1, None, True), (2, 1, False), (3, 2, True), (4, 3, True), (5, 4, True)):
        markers.write(markers_dir, _marker(key, parent, ready=ready, state="cold"))
        if ready:
            for name in TIER_TABLES:
                path = store.table_path(sidestore, name, key)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"PAR1")
    sweep.prune_tiers(sidestore, markers_dir, checkpoint_every=100)
    held = {k for k in range(1, 6) if store.table_path(sidestore, "render_t1", k).exists()}
    assert held == {1, 3}
