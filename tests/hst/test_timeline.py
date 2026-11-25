from pathlib import Path
from typing import Any

from hst.map import markers, store, timeline


def _marker(key: int, parent: int | None, **extra: Any) -> dict[str, Any]:
    return {
        "key": key,
        "kind": "full",
        "parent": parent,
        "published_ts": key,
        "state": "warm",
        "tiers_ready": True,
        **extra,
    }


def test_the_timeline_lists_the_runs_oldest_first_with_the_route_fields(tmp_path: Path) -> None:
    for key, parent in ((10, None), (20, 10), (30, 20)):
        markers.write(tmp_path, _marker(key, parent, counts={"added": 1, "removed": 0, "changed": 2}))
    answer = timeline.timeline(tmp_path)
    assert answer["current"] == 30
    assert [r["key"] for r in answer["runs"]] == [10, 20, 30]
    assert set(answer["runs"][0]) == {
        "key",
        "kind",
        "parent",
        "published_ts",
        "state",
        "tiers_ready",
        "counts",
        "replan_recommended",
    }
    assert timeline.timeline(tmp_path, current=20)["current"] == 20


def test_the_parent_of_each_run_is_its_predecessor_and_a_run_that_breaks_it_is_refused(
    tmp_path: Path,
) -> None:
    for key, parent in ((10, None), (20, 10), (30, 10), (40, 20)):
        markers.write(tmp_path, _marker(key, parent))
    assert timeline.chain(tmp_path) == [10, 20, 40]


def test_a_run_without_a_parent_after_a_purge_starts_a_new_timeline(tmp_path: Path) -> None:
    for key, parent in ((10, None), (20, 10), (30, None), (40, 30), (50, 20)):
        markers.write(tmp_path, _marker(key, parent))
    assert timeline.chain(tmp_path) == [30, 40]
    assert timeline.timeline(tmp_path)["current"] == 40


def test_the_first_remaining_run_may_name_a_parent_the_sweep_removed(tmp_path: Path) -> None:
    for key, parent in ((20, 10), (30, 20)):
        markers.write(tmp_path, _marker(key, parent))
    assert timeline.chain(tmp_path) == [20, 30]


def test_the_marker_heals_from_the_staged_projection_after_a_crash(tmp_path: Path) -> None:
    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    staging = store.staging_dir(sidestore, 50)
    staged_table = store.staged_path(sidestore, 50, "render_t1")
    staged_table.parent.mkdir(parents=True)
    staged_table.write_bytes(b"PAR1")
    markers.write_staged(staging, _marker(50, 40))

    assert timeline.reconcile(markers_dir, sidestore, 50, lambda key: {})
    assert markers.read(markers_dir, 50)["tiers_ready"] is True
    assert store.table_path(sidestore, "render_t1", 50).exists()
    assert not staging.exists()
    assert not timeline.reconcile(markers_dir, sidestore, 50, lambda key: {})


def test_the_marker_heals_without_tiers_when_nothing_was_staged(tmp_path: Path) -> None:
    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    assert timeline.reconcile(markers_dir, sidestore, 60, lambda key: {"kind": "device", "parent": 50})
    healed = markers.read(markers_dir, 60)
    assert (healed["kind"], healed["parent"], healed["tiers_ready"], healed["state"]) == (
        "device",
        50,
        False,
        "warm",
    )
    assert not timeline.reconcile(markers_dir, sidestore, None, lambda key: {})
