import json
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq

from hst.map import events, markers, store
from hst.map.graph_delta import TABLE, GraphDeltaWriter
from hst.map.tiers import schemas


def _record(i: int, change: str = "added") -> dict[str, Any]:
    return {
        "kind": "node",
        "change": change,
        "uid": f"dev:d{i:02d}",
        "label": "Device",
        "start": None,
        "end": None,
        "before": None if change == "added" else {"role": "leaf"},
        "after": {"role": "spine", "name": f"d{i:02d}"} if change != "removed" else None,
    }


def test_the_writer_writes_row_groups_of_the_given_size(tmp_path: Path) -> None:
    path = tmp_path / "g.parquet"
    writer = GraphDeltaWriter(path, snapshot_ts=200, parent_ts=100, row_group_rows=3)
    for i in range(7):
        writer.add(_record(i))
    assert writer.close() == 7
    meta = pq.read_metadata(path)
    assert (meta.num_rows, meta.num_row_groups) == (7, 3)
    assert pq.read_schema(path).equals(schemas.GRAPH_DELTA)


def test_a_run_without_changes_writes_an_empty_table(tmp_path: Path) -> None:
    path = tmp_path / "g.parquet"
    assert GraphDeltaWriter(path, snapshot_ts=200, parent_ts=100).close() == 0
    assert pq.read_metadata(path).num_rows == 0
    assert pq.read_schema(path).equals(schemas.GRAPH_DELTA)


def test_a_row_holds_the_record_its_run_and_its_device(tmp_path: Path) -> None:
    writer = GraphDeltaWriter(tmp_path / "g.parquet", snapshot_ts=200, parent_ts=100)
    row = writer.add(_record(1, "changed"), device_uid="dev:d01")
    writer.close()
    assert row["snapshot_ts"] == 200
    assert row["parent_ts"] == 100
    assert row["run_id"] == "200"
    assert row["device_uid"] == "dev:d01"
    assert json.loads(row["props_before"]) == {"role": "leaf"}
    assert row["props_after"] == '{"name":"d01","role":"spine"}'
    assert (
        GraphDeltaWriter(tmp_path / "h.parquet", snapshot_ts=1, parent_ts=None).add(_record(2))[
            "props_before"
        ]
        is None
    )


def test_a_staged_table_is_invisible_until_published(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    staged = store.staged_path(sidestore, 200, TABLE)
    writer = GraphDeltaWriter(staged, snapshot_ts=200, parent_ts=100)
    writer.add(_record(1))
    writer.close()
    assert not store.table_path(sidestore, TABLE, 200).exists()
    assert store.publish_staged(sidestore, 200) == [TABLE]
    assert store.table_path(sidestore, TABLE, 200).exists()
    assert not store.staging_dir(sidestore, 200).exists()


def test_a_published_table_has_mode_0600_in_a_directory_with_mode_0700(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    writer = GraphDeltaWriter(store.staged_path(sidestore, 200, TABLE), snapshot_ts=200, parent_ts=100)
    writer.add(_record(1))
    writer.close()
    store.publish_staged(sidestore, 200)

    published = store.table_path(sidestore, TABLE, 200)
    assert published.stat().st_mode & 0o777 == 0o600
    assert published.parent.stat().st_mode & 0o777 == 0o700


def test_a_marker_has_mode_0600(tmp_path: Path) -> None:
    markers.write(tmp_path, {"key": 200})
    markers.write_staged(tmp_path / "stage", {"key": 200})

    assert markers.path_for(tmp_path, 200).stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "stage" / markers.STAGED_MARKER).stat().st_mode & 0o777 == 0o600


def test_a_discarded_stage_leaves_nothing(tmp_path: Path) -> None:
    sidestore = tmp_path / "sidestore"
    writer = GraphDeltaWriter(store.staged_path(sidestore, 200, TABLE), snapshot_ts=200, parent_ts=100)
    writer.add(_record(1))
    writer.close()
    store.discard_staged(sidestore, 200)
    assert store.publish_staged(sidestore, 200) == []
    assert not store.table_path(sidestore, TABLE, 200).exists()


def test_replay_returns_the_rows_in_the_order_the_writer_took_them(tmp_path: Path) -> None:
    markers_dir, sidestore = tmp_path / "manifests", tmp_path / "sidestore"
    writer = GraphDeltaWriter(
        store.staged_path(sidestore, 200, TABLE), snapshot_ts=200, parent_ts=100, row_group_rows=2
    )
    live = [
        writer.add(_record(i, change))
        for i, change in enumerate(["added", "changed", "removed", "added", "changed"])
    ]
    writer.close()
    store.publish_staged(sidestore, 200)
    markers.write(
        markers_dir, {"key": 200, "kind": "full", "parent": 100, "published_ts": 200, "tiers_ready": False}
    )
    replayed = events.LocalBus(markers_dir, sidestore).replay(200, [events.DELTA_RECORD])
    assert [e.payload for e in replayed] == live
    assert [e.seq for e in replayed] == [1, 2, 3, 4, 5]
    assert events.GRAPH_DELTA_TABLE == TABLE


def test_every_hst_table_states_its_schema_version() -> None:
    assert set(schemas.SCHEMA_VERSIONS) == set(schemas.SCHEMAS)
