"""`maintenance.sweep_sidestore_tmp`: the temporary files of side-store writes
that never finished are removed by the hourly side-store prune."""

from __future__ import annotations

import contextlib
import logging
import os
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tests.app.fakes import FakeStore

from hst.core import manifest as manifestmod
from hst.core.config import Settings
from hst.worker import maintenance as maint

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
RUN = "1700000000000-aaaaaaaa"


def _settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path)


def _tmp_file(directory: Path, run_id: str, modified: datetime) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run_id}{maint.SIDESTORE_TMP_SUFFIX}"
    path.write_bytes(b"PAR1 half a table")
    os.utime(path, (modified.timestamp(), modified.timestamp()))
    return path


@contextlib.contextmanager
def _fake_session(settings):
    yield object()


@pytest.fixture(autouse=True)
def _no_earlier_sweep(monkeypatch):
    """Every test starts as a process that has not swept yet, with no graph
    history (so the prune under the lock deletes nothing)."""
    monkeypatch.setattr(maint, "_sidestore_tmp_swept_at", None)
    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [])


class _LockRecordingStore(FakeStore):
    """Records, in order, the prune taking the cycle lock and each sweep,
    noting whether the lock was held when the sweep ran."""

    def __init__(self) -> None:
        super().__init__()
        self.held = False
        self.events: list[str] = []

    @contextlib.asynccontextmanager
    async def try_cycle_lock(self):
        async with super().try_cycle_lock() as locked:
            if locked:
                self.held = True
                self.events.append("lock taken")
            try:
                yield locked
            finally:
                self.held = False


def _record_sweeps(monkeypatch, store: _LockRecordingStore) -> None:
    sweep = maint.sweep_sidestore_tmp

    def recording(sidestore_dir: Path, now: datetime, *args, **kwargs) -> list[Path]:
        store.events.append("sweep under the lock" if store.held else "sweep")
        return sweep(sidestore_dir, now, *args, **kwargs)

    monkeypatch.setattr(maint, "sweep_sidestore_tmp", recording)


# --- the sweep itself -------------------------------------------------------------------


def test_the_suffix_is_the_writers():
    sidestore = pytest.importorskip("hst.core.sidestore")
    assert maint.SIDESTORE_TMP_SUFFIX == sidestore.TMP_SUFFIX


def test_an_old_temporary_file_is_removed_and_a_fresh_one_kept(tmp_path):
    base = tmp_path / "sidestore"
    old = _tmp_file(base / "rib" / "edge" / "r1", RUN, NOW - timedelta(hours=7))
    fresh = _tmp_file(base / "rib" / "edge" / "r1", "1700000000001-aaaaaaaa", NOW - timedelta(hours=1))
    controller = _tmp_file(base / "bgp_sessions" / "vco", RUN, NOW - timedelta(days=30))

    swept = maint.sweep_sidestore_tmp(base, NOW)

    assert sorted(swept) == sorted([old, controller])
    assert not old.exists() and not controller.exists()
    assert fresh.exists()


def test_the_age_threshold_is_the_callers(tmp_path):
    base = tmp_path / "sidestore"
    path = _tmp_file(base / "rib" / "edge" / "r1", RUN, NOW - timedelta(minutes=30))

    assert maint.sweep_sidestore_tmp(base, NOW) == []
    assert maint.sweep_sidestore_tmp(base, NOW, older_than=timedelta(minutes=10)) == [path]


def test_only_temporary_files_are_swept(tmp_path):
    """A published table and anything else in the store stay, however old."""
    base = tmp_path / "sidestore"
    leaf = base / "rib" / "edge" / "r1"
    leaf.mkdir(parents=True)
    kept = [leaf / f"{RUN}.parquet", leaf / "notes.tmp", base / ".query-catalog.duckdb"]
    for path in kept:
        path.write_bytes(b"x")
        os.utime(path, ((NOW - timedelta(days=400)).timestamp(),) * 2)

    assert maint.sweep_sidestore_tmp(base, NOW) == []
    assert all(path.exists() for path in kept)


def test_a_missing_store_sweeps_nothing(tmp_path):
    assert maint.sweep_sidestore_tmp(tmp_path / "sidestore", NOW) == []


def test_a_file_that_cannot_be_removed_is_logged_and_left(tmp_path, monkeypatch, caplog):
    base = tmp_path / "sidestore"
    stuck = _tmp_file(base / "rib" / "edge" / "r1", RUN, NOW - timedelta(days=1))
    gone = _tmp_file(base / "rib" / "edge" / "r2", RUN, NOW - timedelta(days=1))
    unlink = Path.unlink

    def refuse(self: Path, missing_ok: bool = False) -> None:
        if self == stuck:
            raise PermissionError(13, "Permission denied", str(self))
        unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse)
    with caplog.at_level(logging.WARNING, logger=maint.log.name):
        swept = maint.sweep_sidestore_tmp(base, NOW)

    assert swept == [gone]
    assert stuck.exists()
    assert any(
        "sidestore tmp sweep: could not remove" in r.getMessage() and str(stuck) in r.getMessage()
        for r in caplog.records
    )


def test_a_write_killed_mid_table_leaves_the_file_the_sweep_removes(tmp_path):
    """A real kill: a child process writes a table and exits in the middle of
    the parquet write, before the rename. What it leaves is exactly one
    temporary file under the writer's name, which no reader matches."""
    pytest.importorskip("pyarrow")
    base = tmp_path / "sidestore"
    child = textwrap.dedent(
        f"""
        import os
        from pathlib import Path
        from hst.core import sidestore

        class Killed(sidestore.pq.ParquetWriter):
            def write_batch(self, batch, *args, **kwargs):
                super().write_batch(batch, *args, **kwargs)
                os._exit(3)

        sidestore.pq.ParquetWriter = Killed
        rows = [{{"device_uid": "dev:r1", "prefix": f"10.{{n}}.0.0/16"}} for n in range(10)]
        sidestore.write_table(Path({str(base)!r}), "rib", "edge", "r1", {RUN!r}, rows, 7, 2)
        """
    )
    done = subprocess.run([sys.executable, "-c", child], cwd=Path(__file__).parents[1], check=False)
    assert done.returncode == 3

    left = sorted(p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file())
    assert left == [f"rib/edge/r1/{RUN}{maint.SIDESTORE_TMP_SUFFIX}"]
    assert list(base.rglob("*.parquet")) == []

    # in flight for the sweep until it is older than SIDESTORE_TMP_MIN_AGE
    assert maint.sweep_sidestore_tmp(base, datetime.now(UTC)) == []
    assert maint.sweep_sidestore_tmp(
        base, datetime.now(UTC) + maint.SIDESTORE_TMP_MIN_AGE + timedelta(minutes=1)
    )
    assert [p for p in base.rglob("*") if p.is_file()] == []


# --- inside the hourly prune --------------------------------------------------------------


async def test_the_prune_sweeps_before_it_takes_the_cycle_lock(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    old = _tmp_file(settings.sidestore_dir / "rib" / "edge" / "r1", RUN, NOW - timedelta(hours=7))
    store = _LockRecordingStore()
    _record_sweeps(monkeypatch, store)

    victims = await maint.prune_sidestore(settings, store, keep=2, now=NOW)

    assert victims == []
    assert store.events == ["sweep", "lock taken"]
    assert not old.exists()


async def test_a_collection_holding_the_cycle_lock_does_not_stop_the_sweep(tmp_path):
    settings = _settings(tmp_path)
    old = _tmp_file(settings.sidestore_dir / "rib" / "edge" / "r1", RUN, NOW - timedelta(hours=7))
    store = FakeStore()

    async with store.cycle_lock():  # a collection in flight
        victims = await maint.prune_sidestore(settings, store, keep=2, now=NOW)

    assert victims is None
    assert not old.exists()


async def test_a_second_sweep_within_six_hours_is_skipped_and_runs_after(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    leaf = settings.sidestore_dir / "rib" / "edge" / "r1"
    store = _LockRecordingStore()
    _record_sweeps(monkeypatch, store)
    first = _tmp_file(leaf, RUN, NOW - timedelta(hours=7))

    await maint.prune_sidestore(settings, store, keep=2, now=NOW)
    assert not first.exists()

    within = NOW + maint.SIDESTORE_TMP_SWEEP_INTERVAL - timedelta(minutes=1)
    second = _tmp_file(leaf, "1700000000002-aaaaaaaa", within - timedelta(hours=7))
    await maint.prune_sidestore(settings, store, keep=2, now=within)
    assert second.exists()

    after = NOW + maint.SIDESTORE_TMP_SWEEP_INTERVAL
    await maint.prune_sidestore(settings, store, keep=2, now=after)
    assert not second.exists()
    assert store.events == ["sweep", "lock taken", "lock taken", "sweep", "lock taken"]


async def test_a_wall_clock_stepped_back_sweeps_at_the_next_turn(tmp_path):
    settings = _settings(tmp_path)
    store = FakeStore()
    await maint.prune_sidestore(settings, store, keep=2, now=NOW + timedelta(days=1))
    leftover = _tmp_file(settings.sidestore_dir / "rib" / "edge" / "r1", RUN, NOW - timedelta(hours=7))

    await maint.prune_sidestore(settings, store, keep=2, now=NOW)

    assert not leftover.exists()
    assert maint._sidestore_tmp_swept_at == NOW


async def test_the_sweep_logs_how_many_files_it_removed(tmp_path, caplog):
    settings = _settings(tmp_path)
    for n in range(3):
        _tmp_file(settings.sidestore_dir / "rib" / "edge" / f"r{n}", RUN, NOW - timedelta(days=1))

    with caplog.at_level(logging.INFO, logger=maint.log.name):
        await maint.prune_sidestore(settings, FakeStore(), keep=2, now=NOW)

    assert any(
        "removed 3 temporary file(s) of unfinished side-store writes" in r.getMessage()
        for r in caplog.records
    )


# --- the DuckDB spill directories ----------------------------------------------------------


def _spill(base: Path, name: str, modified: datetime, files: dict[str, datetime] | None = None) -> Path:
    """A reader's spill directory holding `files` (name to modification
    time), itself last modified at `modified`."""
    directory = base / maint.SIDESTORE_SPILL_DIR / name
    directory.mkdir(parents=True, exist_ok=True)
    for file_name, file_modified in (files or {}).items():
        path = directory / file_name
        path.write_bytes(b"a spilled block")
        os.utime(path, (file_modified.timestamp(),) * 2)
    os.utime(directory, (modified.timestamp(),) * 2)
    return directory


def _catalog_spill(base: Path, files: dict[str, datetime]) -> Path:
    directory = base / f"{maint.SIDESTORE_CATALOG}.tmp"
    directory.mkdir(parents=True, exist_ok=True)
    for file_name, file_modified in files.items():
        path = directory / file_name
        path.write_bytes(b"a spilled block")
        os.utime(path, (file_modified.timestamp(),) * 2)
    return directory


STALE = NOW - timedelta(hours=7)
FRESH = NOW - timedelta(hours=1)
SPILL_FILE = "duckdb_temp_storage_S32K-0.tmp"


def test_the_spill_names_are_the_readers():
    sidestore = pytest.importorskip("hst.core.sidestore")
    assert maint.SIDESTORE_SPILL_DIR == sidestore.QUERY_SPILL
    assert maint.SIDESTORE_CATALOG == sidestore.QUERY_CATALOG


def test_an_unused_spill_directory_is_removed_with_its_files(tmp_path):
    base = tmp_path / "sidestore"
    killed = _spill(base, "101-aa", STALE, {SPILL_FILE: STALE, "duckdb_temp_block-4.block": STALE})
    ended = _spill(base, "102-bb", STALE)

    swept = maint.sweep_sidestore_spills(base, NOW)

    assert swept == [killed, ended]
    assert not killed.exists() and not ended.exists()
    assert (base / maint.SIDESTORE_SPILL_DIR).is_dir()


def test_a_spill_directory_in_use_is_kept(tmp_path):
    """Opened by a connection within the age (its own time is fresh), or
    holding a file written within it."""
    base = tmp_path / "sidestore"
    opened = _spill(base, "101-aa", FRESH, {SPILL_FILE: STALE})
    writing = _spill(base, "102-bb", STALE, {SPILL_FILE: STALE, "duckdb_temp_storage_S64K-0.tmp": FRESH})

    assert maint.sweep_sidestore_spills(base, NOW) == []
    assert sorted(p.name for p in opened.iterdir()) == [SPILL_FILE]
    assert len(list(writing.iterdir())) == 2


def test_the_age_of_a_spill_is_the_callers(tmp_path):
    base = tmp_path / "sidestore"
    spill = _spill(base, "101-aa", FRESH)

    assert maint.sweep_sidestore_spills(base, NOW) == []
    assert maint.sweep_sidestore_spills(base, NOW, older_than=timedelta(minutes=30)) == [spill]


def test_a_spill_directory_holding_anything_but_files_is_kept(tmp_path):
    base = tmp_path / "sidestore"
    nested = _spill(base, "101-aa", STALE)
    (nested / "inner").mkdir()
    os.utime(nested / "inner", (STALE.timestamp(),) * 2)
    os.utime(nested, (STALE.timestamp(),) * 2)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "kept").write_bytes(b"x")
    link = base / maint.SIDESTORE_SPILL_DIR / "102-bb"
    link.symlink_to(elsewhere, target_is_directory=True)
    stray = base / maint.SIDESTORE_SPILL_DIR / "notes"
    stray.write_bytes(b"x")
    for path in (link, stray):
        os.utime(path, (STALE.timestamp(),) * 2, follow_symlinks=False)

    assert maint.sweep_sidestore_spills(base, NOW) == []
    assert (nested / "inner").is_dir()
    assert link.is_symlink() and (elsewhere / "kept").exists()
    assert stray.exists()


def test_the_catalogs_default_spill_directory_loses_only_old_spill_files(tmp_path):
    base = tmp_path / "sidestore"
    directory = _catalog_spill(
        base, {SPILL_FILE: STALE, "duckdb_temp_storage_S64K-0.tmp": FRESH, "notes.tmp": STALE}
    )

    assert maint.sweep_sidestore_spills(base, NOW) == [directory / SPILL_FILE]
    assert sorted(p.name for p in directory.iterdir()) == ["duckdb_temp_storage_S64K-0.tmp", "notes.tmp"]


def test_a_store_with_no_spills_sweeps_nothing(tmp_path):
    base = tmp_path / "sidestore"
    assert maint.sweep_sidestore_spills(base, NOW) == []
    (base / "rib").mkdir(parents=True)
    assert maint.sweep_sidestore_spills(base, NOW) == []


def test_a_spill_that_cannot_be_removed_is_logged_and_left(tmp_path, monkeypatch, caplog):
    base = tmp_path / "sidestore"
    stuck = _spill(base, "101-aa", STALE, {SPILL_FILE: STALE})
    gone = _spill(base, "102-bb", STALE, {SPILL_FILE: STALE})
    unlink = Path.unlink

    def refuse(self: Path, missing_ok: bool = False) -> None:
        if self.parent == stuck:
            raise PermissionError(13, "Permission denied", str(self))
        unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse)
    with caplog.at_level(logging.WARNING, logger=maint.log.name):
        swept = maint.sweep_sidestore_spills(base, NOW)

    assert swept == [gone]
    assert (stuck / SPILL_FILE).exists()
    assert any(
        "sidestore spill sweep: could not remove" in r.getMessage() and str(stuck) in r.getMessage()
        for r in caplog.records
    )


def test_a_spill_directory_that_cannot_be_listed_is_logged_and_left(tmp_path, monkeypatch, caplog):
    base = tmp_path / "sidestore"
    spill = _spill(base, "101-aa", STALE)
    iterdir = Path.iterdir

    def refuse(self: Path):
        if self == base / maint.SIDESTORE_SPILL_DIR:
            raise PermissionError(13, "Permission denied", str(self))
        return iterdir(self)

    monkeypatch.setattr(Path, "iterdir", refuse)
    with caplog.at_level(logging.WARNING, logger=maint.log.name):
        assert maint.sweep_sidestore_spills(base, NOW) == []

    assert spill.is_dir()
    assert any("sidestore spill sweep: could not list" in r.getMessage() for r in caplog.records)


async def test_the_prune_sweeps_spills_on_every_turn_while_a_collection_holds_the_lock(tmp_path):
    settings = _settings(tmp_path)
    first = _spill(settings.sidestore_dir, "101-aa", STALE, {SPILL_FILE: STALE})
    store = FakeStore()

    async with store.cycle_lock():  # a collection in flight
        assert await maint.prune_sidestore(settings, store, keep=2, now=NOW) is None
        assert not first.exists()

        within = NOW + timedelta(hours=1)
        second = _spill(settings.sidestore_dir, "102-bb", within - timedelta(hours=7))
        assert await maint.prune_sidestore(settings, store, keep=2, now=within) is None
        assert not second.exists()


async def test_the_spill_sweep_logs_how_much_it_removed(tmp_path, caplog):
    settings = _settings(tmp_path)
    _spill(settings.sidestore_dir, "101-aa", STALE)
    _catalog_spill(settings.sidestore_dir, {SPILL_FILE: STALE})

    with caplog.at_level(logging.INFO, logger=maint.log.name):
        await maint.prune_sidestore(settings, FakeStore(), keep=2, now=NOW)

    assert any(
        "removed 2 DuckDB spill path(s) no reader has used for more than 6 h" in r.getMessage()
        for r in caplog.records
    )


# --- the tables the prune covers, and the run key it reads -------------------------------


def test_the_prune_covers_every_side_store_table():
    sidestore = pytest.importorskip("hst.core.sidestore")
    assert set(maint.SIDESTORE_TABLES) == set(sidestore.SCHEMAS)


async def test_an_ospf_database_of_a_pruned_run_is_pruned(tmp_path, monkeypatch):
    sidestore = pytest.importorskip("hst.core.sidestore")
    settings = _settings(tmp_path)
    lsa = {
        "device_uid": "dev:r1",
        "process": "1",
        "area": "0.0.0.0",  # noqa: S104 - an OSPF area id, not a bind address
        "lsa_type": "router",
        "lsid": "10.0.0.1",
    }
    pruned = sidestore.write_table(
        settings.sidestore_dir, "ospf_lsdb", "nxos", "r1", "1000-aaaaaaaa", [lsa], 1000
    )
    kept = sidestore.write_table(
        settings.sidestore_dir, "ospf_lsdb", "nxos", "r1", "2000-bbbbbbbb", [lsa], 2000
    )
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [2000])
    # a kept run with no manifest protects every file up to its key
    manifestmod.write(
        settings,
        manifestmod.SnapshotManifest(
            snapshot_key=2000, kind="full", opened=manifestmod.iso(2000), published=manifestmod.now_iso()
        ),
    )

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=1, now=NOW)

    assert victims == [pruned]
    assert kept is not None and kept.exists()


def _parquet(path: Path, columns: dict[str, list[object]], types: dict[str, object] | None = None) -> Path:
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    arrays = {name: pa.array(values, type=(types or {}).get(name)) for name, values in columns.items()}
    pq.write_table(pa.table(arrays), path)
    return path


def test_the_run_key_is_the_files_one_snapshot_ts(tmp_path):
    path = _parquet(tmp_path / "a.parquet", {"snapshot_ts": [1000, None, 1000], "x": [1, 2, 3]})
    assert maint._file_snapshot_ts(path) == 1000


def test_a_run_key_given_as_text_reads_as_its_number(tmp_path):
    path = _parquet(tmp_path / "a.parquet", {"snapshot_ts": ["1000", "1000"]})
    assert maint._file_snapshot_ts(path) == 1000


@pytest.mark.parametrize(
    "columns",
    [
        {"snapshot_ts": [1000, 2000]},
        {"snapshot_ts": [None, None]},
        {"run_id": ["1000-aaaaaaaa"]},
        {"snapshot_ts": ["not a number"]},
    ],
    ids=["two-runs", "all-null", "no-column", "not-a-number"],
)
def test_a_file_without_exactly_one_run_key_has_none(tmp_path, columns):
    path = _parquet(tmp_path / "a.parquet", columns, {"snapshot_ts": None})
    assert maint._file_snapshot_ts(path) is None


def test_a_timestamp_column_has_no_run_key(tmp_path):
    pa = pytest.importorskip("pyarrow")
    path = _parquet(
        tmp_path / "a.parquet",
        {"snapshot_ts": [datetime(2026, 1, 1, tzinfo=UTC)]},
        {"snapshot_ts": pa.timestamp("ms", tz="UTC")},
    )
    assert maint._file_snapshot_ts(path) is None


def test_a_file_that_is_not_parquet_has_no_run_key(tmp_path):
    path = tmp_path / "a.parquet"
    path.write_bytes(b"not parquet at all")
    assert maint._file_snapshot_ts(path) is None


# --- a dry run ----------------------------------------------------------------------------


async def test_a_dry_run_leaves_an_old_spill_and_temporary_file_in_place(tmp_path):
    """`hst sidestore prune` without --yes only reports."""
    settings = _settings(tmp_path)
    tmp = _tmp_file(settings.sidestore_dir / "rib" / "edge" / "r1", RUN, STALE)
    spill = _spill(settings.sidestore_dir, "101-aa", STALE, {SPILL_FILE: STALE})
    catalog = _catalog_spill(settings.sidestore_dir, {SPILL_FILE: STALE})

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=2, now=NOW, dry_run=True)

    assert victims == []
    assert tmp.exists() and spill.exists() and (catalog / SPILL_FILE).exists()
    assert maint._sidestore_tmp_swept_at is None

    await maint.prune_sidestore(settings, FakeStore(), keep=2, now=NOW)

    assert not tmp.exists() and not spill.exists() and not (catalog / SPILL_FILE).exists()
