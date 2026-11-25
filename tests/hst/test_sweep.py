from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hst.core.config import Settings
from hst.map import layout, layout_read, markers, store, sweep
from hst.map.tiers.fold import TIER_TABLES
from hst.worker import maintenance

DAY_MS = 86_400_000
NOW = datetime(2026, 10, 10, tzinfo=UTC)
NOW_MS = int(NOW.timestamp() * 1000)


def _run(dirs: tuple[Path, Path], key: int, parent: int | None, *, state: str = "warm") -> None:
    markers_dir, sidestore = dirs
    markers.write(
        markers_dir, {"key": key, "kind": "full", "parent": parent, "published_ts": key, "state": state}
    )
    for name in (*TIER_TABLES, *sweep.HISTORY_TABLES):
        path = store.table_path(sidestore, name, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"PAR1")


def _chain(dirs: tuple[Path, Path], keys: list[int], *, cold_below: int) -> None:
    parent = None
    for key in keys:
        _run(dirs, key, parent, state="cold" if key < cold_below else "warm")
        parent = key


def _has_tiers(sidestore: Path, key: int) -> bool:
    return store.table_path(sidestore, "render_t1", key).exists()


def test_mark_cold_sets_the_state_of_the_pruned_runs_only(tmp_path: Path) -> None:
    dirs = (tmp_path / "m", tmp_path / "s")
    _chain(dirs, [1, 2, 3], cold_below=0)
    assert sweep.mark_cold(dirs[0], [1, 2, 9]) == [1, 2]
    assert [markers.read(dirs[0], k)["state"] for k in (1, 2, 3)] == ["cold", "cold", "warm"]
    assert sweep.mark_cold(dirs[0], [1]) == []


def test_cold_runs_keep_one_tier_checkpoint_every_n_runs_and_warm_runs_keep_all(tmp_path: Path) -> None:
    dirs = (tmp_path / "m", tmp_path / "s")
    keys = list(range(1, 13))
    _chain(dirs, keys, cold_below=10)
    deleted = sweep.prune_tiers(dirs[1], dirs[0], checkpoint_every=4)
    assert {k for k in keys if _has_tiers(dirs[1], k)} == {1, 5, 9, 10, 11, 12}
    assert len(deleted) == 6 * len(TIER_TABLES)
    assert all(store.table_path(dirs[1], "graph_delta", k).exists() for k in keys)


def test_history_retention_deletes_the_old_cold_runs_and_keeps_the_layout_in_force(tmp_path: Path) -> None:
    dirs = (tmp_path / "m", tmp_path / "s")
    old = NOW_MS - 40 * DAY_MS
    keys = [old, old + 1, NOW_MS - DAY_MS]
    _chain(dirs, keys, cold_below=NOW_MS - 2 * DAY_MS)
    layout.write(
        store.table_path(dirs[1], layout.TABLE, old),
        [layout.Placement("site:a", "site", None, 0, 0, 1, 1, valid_from_ts=old)],
    )
    layout.write(
        store.table_path(dirs[1], layout.TABLE, old + 1),
        [layout.Placement("site:b", "site", None, 5, 0, 1, 1, valid_from_ts=old + 1)],
    )
    files, gone = sweep.prune_history(dirs[1], dirs[0], 30, NOW)
    assert gone == [old, old + 1]
    assert markers.keys(dirs[0]) == [keys[-1]]
    assert not store.table_path(dirs[1], "graph_delta", old).exists()
    assert store.table_path(dirs[1], layout.TABLE, old).exists()
    assert store.table_path(dirs[1], "graph_delta", keys[-1]).exists()
    assert files


def test_history_retention_unset_keeps_every_delta(tmp_path: Path) -> None:
    dirs = (tmp_path / "m", tmp_path / "s")
    _chain(dirs, [1, 2, 3], cold_below=3)
    swept = sweep.sweep(dirs[1], dirs[0], [], checkpoint_every=30, history_days=None, now=NOW)
    assert swept.markers == []
    assert all(store.table_path(dirs[1], "render_t1_delta", k).exists() for k in (1, 2, 3))


def test_the_hst_family_is_outside_the_side_store_prune() -> None:
    assert store.FAMILY not in maintenance.SIDESTORE_TABLES


def test_the_graph_prune_turn_heals_the_pointer_marker_and_marks_the_pruned_runs_cold(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    dirs = (settings.manifests_dir, settings.sidestore_dir)
    _chain(dirs, [1, 2, 3], cold_below=0)
    maintenance._sweep_hst(settings, [1, 2], 4)
    assert [markers.read(settings.manifests_dir, k)["state"] for k in (1, 2, 3)] == ["cold", "cold", "warm"]
    healed: dict[str, Any] | None = markers.read(settings.manifests_dir, 4)
    assert healed is not None and healed["tiers_ready"] is False


def test_history_retention_keeps_the_layout_file_of_a_removed_row_in_force(tmp_path: Path) -> None:
    dirs = (tmp_path / "m", tmp_path / "s")
    old = NOW_MS - 40 * DAY_MS
    keys = [old, old + 1, NOW_MS - DAY_MS]
    _chain(dirs, keys, cold_below=NOW_MS - 2 * DAY_MS)
    site_a = layout.Placement("site:a", "site", None, 0, 0, 1, 1, valid_from_ts=old)
    site_b = layout.Placement("site:b", "site", None, 5, 0, 1, 1, valid_from_ts=old)
    layout.write(store.table_path(dirs[1], layout.TABLE, old), [site_a, site_b])
    gone = layout.Placement("site:a", "site", None, 0, 0, 1, 1, valid_from_ts=old + 1, reason=layout.REMOVED)
    layout.write(store.table_path(dirs[1], layout.TABLE, old + 1), [gone])
    sweep.prune_history(dirs[1], dirs[0], 30, NOW)
    assert store.table_path(dirs[1], layout.TABLE, old + 1).exists()
    assert set(layout_read.rows_at(dirs[1], keys[-1])) == {"site:b"}


def test_history_retention_keeps_the_checkpoint_in_force_and_drops_the_layout_files_older_than_it(
    tmp_path: Path,
) -> None:
    dirs = (tmp_path / "m", tmp_path / "s")
    old = NOW_MS - 40 * DAY_MS
    keys = [old, old + 1, old + 2, old + 3, NOW_MS - DAY_MS]
    _chain(dirs, keys, cold_below=NOW_MS - 2 * DAY_MS)

    def site(name: str, key: int) -> layout.Placement:
        return layout.Placement(f"site:{name}", "site", None, 0, 0, 1, 1, valid_from_ts=key)

    for i, key in enumerate(keys[:4]):
        layout.write(store.table_path(dirs[1], layout.TABLE, key), [site("abcd"[i], key)])
    layout.write(store.table_path(dirs[1], layout_read.FULL_TABLE, old), [site("a", old)])
    layout.write(
        store.table_path(dirs[1], layout_read.FULL_TABLE, old + 1), [site("a", old), site("b", old + 1)]
    )
    before = set(layout_read.rows_at(dirs[1], keys[-1]))
    sweep.prune_history(dirs[1], dirs[0], 30, NOW)
    assert [layout_read.keys(dirs[1], t) for t in (layout.TABLE, layout_read.FULL_TABLE)] == [
        [old + 2, old + 3],
        [old + 1],
    ]
    assert set(layout_read.rows_at(dirs[1], keys[-1])) == before == {"site:a", "site:b", "site:c", "site:d"}


def test_a_leased_cold_run_defers_the_file_deletion_of_the_turn(tmp_path: Path) -> None:
    """A map read of a cold run holds a lease; the sweep marks runs cold but
    deletes no file while it is held."""
    dirs = (tmp_path / "m", tmp_path / "s")
    _chain(dirs, [1, 2, 3], cold_below=3)
    swept = sweep.sweep(dirs[1], dirs[0], [], checkpoint_every=2, history_days=0, now=NOW, leased=[1])
    assert swept.files == [] and swept.markers == []
    assert markers.keys(dirs[0]) == [1, 2, 3]
    # a lease on a warm run does not hold the sweep back
    swept = sweep.sweep(dirs[1], dirs[0], [], checkpoint_every=2, history_days=0, now=NOW, leased=[3])
    assert swept.markers
