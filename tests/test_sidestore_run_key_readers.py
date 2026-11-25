"""The side-store prune reads a file's run key from its own `snapshot_ts` column
(worker/maintenance.py `_file_snapshot_ts`)."""

from __future__ import annotations

from pathlib import Path

import pytest

pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")

from hst.worker import maintenance  # noqa: E402


def _files(tmp_path: Path) -> dict[str, Path]:
    files = {
        "one run": {"snapshot_ts": [7, 7, None], "prefix": ["a", "b", "c"]},
        "two runs": {"snapshot_ts": [7, 8], "prefix": ["a", "b"]},
        "no value": {"snapshot_ts": pa.array([None, None], type=pa.int64()), "prefix": ["a", "b"]},
        "no column": {"prefix": ["a"]},
    }
    paths = {}
    for name, columns in files.items():
        path = tmp_path / f"{name.replace(' ', '-')}.parquet"
        pq.write_table(pa.table(columns), path)
        paths[name] = path
    garbage = tmp_path / "not-parquet.parquet"
    garbage.write_bytes(b"not a parquet file")
    paths["not parquet"] = garbage
    paths["missing"] = tmp_path / "gone.parquet"
    return paths


def test_the_reader_tells_one_run_or_none(tmp_path: Path) -> None:
    read = {name: maintenance._file_snapshot_ts(path) for name, path in _files(tmp_path).items()}

    assert read == {
        "one run": 7,
        "two runs": None,
        "no value": None,
        "no column": None,
        "not parquet": None,
        "missing": None,
    }


def test_the_command_has_no_reader_of_its_own() -> None:
    import hst.cli as cli

    assert not hasattr(cli, "_prune_file_snapshot_ts")
    assert not hasattr(cli, "_prune_sort_key")
