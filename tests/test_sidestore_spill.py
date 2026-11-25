"""Where a side-store reader's DuckDB database spills (`sidestore.spill_dir`),
and how the catalog it attaches to is created (`sidestore._create_catalog`)."""

from __future__ import annotations

import errno
import logging
import os
import subprocess
import sys
import textwrap
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("pyarrow")
duckdb = pytest.importorskip("duckdb")

from hst.core import sidestore  # noqa: E402
from hst.worker import maintenance as maint  # noqa: E402

RUN = "1700000000000-aaaaaaaa"
TEMP_SQL = "SELECT current_setting('temp_directory') AS spill"
READ_SQL = "SELECT prefix FROM rib"
# A query that needs more than 32 MiB plus an 8 MiB spill (see
# tests/test_sidestore_reader_bounds.py), so at a 32 MiB memory limit it spills.
HEAVY_SQL = (
    "SELECT count(*) AS n FROM (SELECT i % 800000 AS k, count(*), max(i::VARCHAR) "
    "FROM range(8000000) t(i) GROUP BY k)"
)
REPO = Path(__file__).parents[1]


def _store(base: Path) -> Path:
    row = {"device_uid": "dev:r1", "vrf": "default", "prefix": "10.0.0.0/8", "protocol": "static"}
    sidestore.write_table(base, "rib", "src", "h1", RUN, [row], 7)
    return base


def _children(script: str, count: int) -> list[str]:
    """Run `script` in `count` child processes at once and return their
    output. Each child imports first and then waits for a line on its
    standard input, which every child is sent together, so the children start
    their work at the same moment."""
    children = [
        subprocess.Popen(
            [sys.executable, "-c", script],
            cwd=REPO,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(count)
    ]
    for child in children:
        assert child.stdin is not None
        child.stdin.write("\n")
        child.stdin.flush()
    outputs = []
    for child in children:
        out, err = child.communicate(timeout=600)
        assert child.returncode == 0, err
        outputs.append(out)
    return outputs


# --- one spill directory per process ------------------------------------------------------


def test_a_reader_spills_to_this_processes_own_directory(tmp_path):
    base = _store(tmp_path / "sidestore")
    spill = sidestore.spill_dir(base)

    assert sidestore.query(base, TEMP_SQL) == [{"spill": spill.as_posix()}]
    assert spill.parent == base / sidestore.QUERY_SPILL
    assert spill.is_dir()
    assert spill.name.startswith(f"{os.getpid()}-")
    assert sidestore.spill_dir(base) == spill


def test_two_processes_spill_to_two_directories(tmp_path):
    base = _store(tmp_path / "sidestore")
    script = textwrap.dedent(
        f"""
        import sys
        from pathlib import Path
        from hst.core import sidestore

        sys.stdin.readline()
        print(sidestore.query(Path({str(base)!r}), {TEMP_SQL!r})[0]["spill"])
        """
    )

    spills = [out.strip() for out in _children(script, 2)]

    assert len(set(spills)) == 2
    assert sidestore.spill_dir(base).as_posix() not in spills
    assert all(Path(spill).parent == base / sidestore.QUERY_SPILL for spill in spills)


def test_processes_spilling_at_once_all_read(tmp_path):
    """Three processes each run a query past the memory limit twice, all at
    once. Each spills to its own directory, so none reads or removes the
    others' spill files, and every query returns its full answer."""
    base = _store(tmp_path / "sidestore")
    script = textwrap.dedent(
        f"""
        import sys
        from pathlib import Path
        from hst.core import sidestore

        sidestore.DUCKDB_MEMORY_LIMIT_MB = 32
        sys.stdin.readline()
        for _ in range(2):
            print(sidestore.query(Path({str(base)!r}), {HEAVY_SQL!r})[0]["n"])
        """
    )

    outputs = _children(script, 3)

    assert [out.split() for out in outputs] == [["800000", "800000"]] * 3
    assert not (base / f"{sidestore.QUERY_CATALOG}.tmp").exists()
    spills = sorted((base / sidestore.QUERY_SPILL).iterdir())
    assert len(spills) == 3
    # DuckDB removes its files when each database closes, and leaves the
    # directory, which the reader created
    assert [list(spill.iterdir()) for spill in spills] == [[]] * 3


def test_every_connection_marks_the_spill_directory_in_use(tmp_path):
    base = _store(tmp_path / "sidestore")
    sidestore.connect_reader(base).close()
    spill = sidestore.spill_dir(base)
    day_ago = time.time() - 86400
    os.utime(spill, (day_ago, day_ago))

    sidestore.connect_reader(base).close()

    assert spill.stat().st_mtime > day_ago + 3600


def test_a_spill_directory_removed_while_idle_is_made_again_by_the_next_connection(tmp_path, monkeypatch):
    monkeypatch.setattr(sidestore, "DUCKDB_MEMORY_LIMIT_MB", 32)
    base = _store(tmp_path / "sidestore")
    sidestore.connect_reader(base).close()
    spill = sidestore.spill_dir(base)
    spill.rmdir()

    assert sidestore.query(base, HEAVY_SQL) == [{"n": 800000}]
    assert spill.is_dir()


def test_a_process_killed_while_spilling_leaves_files_the_sweep_removes(tmp_path):
    """A real kill: a child process runs a query that spills and exits while
    its spill files are on disk. They stay until the prune's spill sweep
    finds the directory unused for long enough."""
    base = _store(tmp_path / "sidestore")
    script = textwrap.dedent(
        f"""
        import os
        import threading
        import time
        from pathlib import Path
        from hst.core import sidestore

        base = Path({str(base)!r})
        sidestore.DUCKDB_MEMORY_LIMIT_MB = 32
        spill = sidestore.spill_dir(base)
        query = threading.Thread(target=sidestore.query, args=(base, {HEAVY_SQL!r}), daemon=True)
        query.start()
        while query.is_alive():
            if spill.is_dir() and any(p.name.startswith("duckdb_temp_") for p in spill.iterdir()):
                os._exit(3)
            time.sleep(0.001)
        os._exit(4)
        """
    )
    done = subprocess.run([sys.executable, "-c", script], cwd=REPO, check=False)
    assert done.returncode == 3, "the query ended before any of its spill files was seen"

    (spill,) = (base / sidestore.QUERY_SPILL).iterdir()
    assert any(p.name.startswith("duckdb_temp_") for p in spill.iterdir())
    now = datetime.now(UTC)
    assert maint.sweep_sidestore_spills(base, now) == []
    assert spill.is_dir()

    later = now + maint.SIDESTORE_TMP_MIN_AGE + timedelta(minutes=1)
    assert maint.sweep_sidestore_spills(base, later) == [spill]
    assert list((base / sidestore.QUERY_SPILL).iterdir()) == []
    assert sidestore.query(base, READ_SQL) == [{"prefix": "10.0.0.0/8"}]


# --- no store, and no spill directory ------------------------------------------------------


def test_a_query_over_no_store_does_not_spill(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sidestore, "DUCKDB_MEMORY_LIMIT_MB", 32)
    missing = tmp_path / "missing"

    assert sidestore.query(missing, TEMP_SQL) == [{"spill": ""}]
    with pytest.raises(duckdb.OutOfMemoryException):
        sidestore.query(missing, HEAVY_SQL)
    assert sorted(tmp_path.iterdir()) == []


def test_a_store_without_room_for_a_spill_directory_reads_without_spilling(tmp_path, caplog):
    base = _store(tmp_path / "sidestore")
    (base / sidestore.QUERY_SPILL).write_bytes(b"")  # a file where the directory belongs

    with caplog.at_level(logging.WARNING, logger=sidestore.logger.name):
        rows = sidestore.query(base, READ_SQL)
        spill = sidestore.query(base, TEMP_SQL)

    assert rows == [{"prefix": "10.0.0.0/8"}]
    assert spill == [{"spill": ""}]
    assert (base / sidestore.QUERY_CATALOG).is_file()
    assert any("cannot be created" in r.getMessage() for r in caplog.records)


# --- the catalog ---------------------------------------------------------------------------


def test_6_processes_reading_a_new_store_at_once_all_read(tmp_path):
    """No catalog yet: every child creates one in its spill directory and
    links it into place, and the first link wins."""
    base = _store(tmp_path / "sidestore")
    assert not (base / sidestore.QUERY_CATALOG).exists()
    script = textwrap.dedent(
        f"""
        import sys
        from pathlib import Path
        from hst.core import sidestore

        sys.stdin.readline()
        print(sidestore.query(Path({str(base)!r}), {READ_SQL!r})[0]["prefix"])
        """
    )

    outputs = _children(script, 6)

    assert [out.strip() for out in outputs] == ["10.0.0.0/8"] * 6
    assert (base / sidestore.QUERY_CATALOG).is_file()
    assert [list(spill.iterdir()) for spill in (base / sidestore.QUERY_SPILL).iterdir()] == [[]] * 6


def test_a_catalog_already_in_place_is_kept(tmp_path):
    base = tmp_path / "sidestore"
    base.mkdir()
    catalog = base / sidestore.QUERY_CATALOG
    duckdb.connect(str(catalog)).close()
    inode = catalog.stat().st_ino
    spill = base / "spill"
    spill.mkdir()

    sidestore._create_catalog(duckdb, catalog, spill)

    assert catalog.stat().st_ino == inode
    assert list(spill.iterdir()) == []


def test_a_file_system_without_hard_links_gets_the_catalog_moved_into_place(tmp_path, monkeypatch):
    def no_links(src, dst, *args, **kwargs):
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(sidestore.os, "link", no_links)
    base = _store(tmp_path / "sidestore")

    assert sidestore.query(base, READ_SQL) == [{"prefix": "10.0.0.0/8"}]
    assert (base / sidestore.QUERY_CATALOG).is_file()
    assert list(sidestore.spill_dir(base).iterdir()) == []


# --- names read off disk -------------------------------------------------------------------


def test_a_store_whose_path_holds_a_quote_reads(tmp_path):
    base = _store(tmp_path / "it's the sidestore")

    assert sidestore.query(base, READ_SQL) == [{"prefix": "10.0.0.0/8"}]
    assert sidestore.query(base, TEMP_SQL) == [{"spill": sidestore.spill_dir(base).as_posix()}]


def test_a_table_directory_of_any_name_is_read_as_itself(tmp_path):
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    base = _store(tmp_path / "sidestore")
    odd = base / 'rib-copy "b"' / "src"
    odd.mkdir(parents=True)
    pq.write_table(pa.table({"x": [1, 2]}), odd / f"{RUN}.parquet")

    assert sidestore.query(base, 'SELECT sum(x) AS total FROM "rib-copy ""b"""') == [{"total": 3}]
    assert sidestore.query(base, READ_SQL) == [{"prefix": "10.0.0.0/8"}]
