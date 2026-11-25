"""The `graph_delta` writer. It writes every record of the diff of a run against its parent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from . import store
from .tiers.schemas import GRAPH_DELTA

TABLE = "graph_delta"
ROW_GROUP_ROWS = 10_000

_JSON = json.JSONEncoder(sort_keys=True, default=str, separators=(",", ":"))


def _props(value: dict[str, Any] | None) -> str | None:
    return None if value is None else _JSON.encode(value)


class GraphDeltaWriter:
    """Writes `core/diff.py Observer` records to one parquet file in row groups of `row_group_rows`."""

    def __init__(
        self,
        path: Path,
        *,
        snapshot_ts: int,
        parent_ts: int | None,
        row_group_rows: int = ROW_GROUP_ROWS,
    ) -> None:
        self._path = path
        self._snapshot_ts = snapshot_ts
        self._parent_ts = parent_ts
        self._row_group_rows = row_group_rows
        self._batch: list[dict[str, Any]] = []
        self._writer: pq.ParquetWriter | None = None
        self.rows = 0

    def add(self, record: dict[str, Any], device_uid: str | None = None) -> dict[str, Any]:
        row = {
            "snapshot_ts": self._snapshot_ts,
            "parent_ts": self._parent_ts,
            "kind": record["kind"],
            "change": record["change"],
            "uid": record["uid"],
            "label": record["label"],
            "start_uid": record["start"],
            "end_uid": record["end"],
            "device_uid": device_uid,
            "props_before": _props(record["before"]),
            "props_after": _props(record["after"]),
            "run_id": str(self._snapshot_ts),
        }
        self._batch.append(row)
        self.rows += 1
        if len(self._batch) >= self._row_group_rows:
            self._flush()
        return row

    def _flush(self) -> pq.ParquetWriter:
        if self._writer is None:
            store.private_file(self._path)
            self._writer = pq.ParquetWriter(self._path, GRAPH_DELTA)
        self._writer.write_table(pa.Table.from_pylist(self._batch, schema=GRAPH_DELTA))
        self._batch = []
        return self._writer

    def close(self) -> int:
        writer = self._flush() if self._batch or self._writer is None else self._writer
        writer.close()
        return self.rows


def fill_devices(path: Path, devices: dict[str, str]) -> None:
    """Set `device_uid` on the rows whose uid, or start or end, resolved after the row was written."""
    if not devices or not path.exists():
        return
    source = pq.ParquetFile(path)
    tmp = path.with_name(path.name + ".fill")
    store.private_file(tmp)
    with pq.ParquetWriter(tmp, GRAPH_DELTA) as writer:
        for group in range(source.num_row_groups):
            rows = source.read_row_group(group).to_pylist()
            for row in rows:
                if row["device_uid"] is None:
                    for uid in (row["uid"], row["start_uid"], row["end_uid"]):
                        if uid is not None and uid in devices:
                            row["device_uid"] = devices[uid]
                            break
            writer.write_table(pa.Table.from_pylist(rows, schema=GRAPH_DELTA))
    tmp.replace(path)
