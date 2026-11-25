"""`maintenance.sweep_raw_tmp`: the temporary files of raw writes that never
finished are removed by the hourly raw-store prune, whatever the retention
setting."""

from __future__ import annotations

import contextlib
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tests.app.fakes import FakeStore

from hst.app.crypto import dek, generate_key
from hst.core import rawstore
from hst.core.config import Settings
from hst.worker import maintenance as maint

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)


def _settings(tmp_path, **kw) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key(), **kw)


def _tmp_file(directory: Path, run_id: str, modified: datetime) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run_id}{rawstore.TMP_SUFFIX}"
    path.write_bytes(b"a partly written token")
    os.utime(path, (modified.timestamp(), modified.timestamp()))
    return path


@contextlib.contextmanager
def _fake_session(settings):
    yield object()


def _no_retained(monkeypatch) -> None:
    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [])


@pytest.fixture(autouse=True)
def _no_earlier_sweep(monkeypatch):
    """Every test starts as a process that has not swept yet."""
    monkeypatch.setattr(maint, "_raw_tmp_swept_at", None)


class _LockRecordingStore(FakeStore):
    """A FakeStore that records, in order, the prune taking the cycle lock and
    each standalone sweep, noting whether the lock was held when it ran."""

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
    sweep = maint.sweep_raw_tmp

    def recording(raw_dir: Path, now: datetime, *args, **kwargs) -> list[Path]:
        store.events.append("sweep under the lock" if store.held else "sweep")
        return sweep(raw_dir, now, *args, **kwargs)

    monkeypatch.setattr(maint, "sweep_raw_tmp", recording)


# --- the sweep itself -------------------------------------------------------------------


def test_an_old_temporary_file_is_removed_and_a_fresh_one_kept(tmp_path):
    raw_dir = tmp_path / "raw"
    old = _tmp_file(raw_dir / "edge" / "r1", "1700000000000-aaaaaaaa", NOW - timedelta(hours=7))
    fresh = _tmp_file(raw_dir / "edge" / "r1", "1700000000001-aaaaaaaa", NOW - timedelta(hours=1))
    controller = _tmp_file(raw_dir / "nautobot", "1700000000002-aaaaaaaa", NOW - timedelta(days=30))
    cache = _tmp_file(raw_dir / "checkpoint" / "replay-cache", "policy-layer", NOW - timedelta(days=2))

    swept = maint.sweep_raw_tmp(raw_dir, NOW)

    assert sorted(swept) == sorted([old, controller, cache])
    assert not old.exists() and not controller.exists() and not cache.exists()
    assert fresh.exists()


def test_the_age_threshold_is_the_callers(tmp_path):
    raw_dir = tmp_path / "raw"
    path = _tmp_file(raw_dir / "edge" / "r1", "1700000000000-aaaaaaaa", NOW - timedelta(minutes=30))

    assert maint.sweep_raw_tmp(raw_dir, NOW) == []
    assert maint.sweep_raw_tmp(raw_dir, NOW, older_than=timedelta(minutes=10)) == [path]
    assert not path.exists()


def test_only_temporary_files_are_swept(tmp_path):
    """A sealed raw file, its sidecars and its trace are evidence or its
    bookkeeping, however old."""
    settings = _settings(tmp_path)
    raw = rawstore.write(
        settings.raw_dir, "edge", "1600000000000-aaaaaaaa", {"x": 1}, host="r1", key=dek(settings)
    )
    rawstore.mark_joined(raw, snapshot_ts=1)
    sidecar = rawstore.sibling(raw, rawstore.META_SUFFIX)
    trace = rawstore.trace_path(raw)
    trace.write_bytes(b"sealed trace")
    long_ago = (NOW - timedelta(days=4000)).timestamp()
    for path in (raw, sidecar, trace):
        os.utime(path, (long_ago, long_ago))

    assert maint.sweep_raw_tmp(settings.raw_dir, NOW) == []
    assert raw.exists() and sidecar.exists() and trace.exists()


def test_a_missing_raw_directory_sweeps_nothing(tmp_path):
    assert maint.sweep_raw_tmp(tmp_path / "raw", NOW) == []


def test_a_file_that_cannot_be_removed_is_logged_and_left(tmp_path, monkeypatch, caplog):
    raw_dir = tmp_path / "raw"
    stuck = _tmp_file(raw_dir / "edge" / "r1", "1700000000000-aaaaaaaa", NOW - timedelta(days=1))
    gone = _tmp_file(raw_dir / "edge" / "r2", "1700000000001-aaaaaaaa", NOW - timedelta(days=1))
    unlink = Path.unlink

    def refuse(self: Path, missing_ok: bool = False) -> None:
        if self == stuck:
            raise PermissionError(13, "Permission denied", str(self))
        unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse)
    with caplog.at_level(logging.WARNING, logger=maint.log.name):
        swept = maint.sweep_raw_tmp(raw_dir, NOW)

    assert swept == [gone]
    assert stuck.exists()
    assert any("could not remove" in r.getMessage() and str(stuck) in r.getMessage() for r in caplog.records)


# --- inside the hourly prune, period tier off -------------------------------------------


async def test_the_prune_sweeps_with_the_period_tier_off(tmp_path):
    settings = _settings(tmp_path)
    assert settings.evidence_retention_days is None
    raw = rawstore.write(
        settings.raw_dir, "edge", "1700000000000-aaaaaaaa", {"x": 1}, host="r1", key=dek(settings)
    )
    old = _tmp_file(raw.parent, "1700000000001-aaaaaaaa", NOW - timedelta(hours=7))
    fresh = _tmp_file(raw.parent, "1700000000002-aaaaaaaa", NOW - timedelta(minutes=5))

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2, now=NOW)

    assert victims == []
    assert not old.exists()
    assert fresh.exists()
    assert raw.exists()


async def test_the_sweep_runs_before_the_cycle_lock_is_taken_and_not_under_it(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    old = _tmp_file(settings.raw_dir / "edge" / "r1", "1700000000001-aaaaaaaa", NOW - timedelta(hours=7))
    store = _LockRecordingStore()
    _record_sweeps(monkeypatch, store)

    victims = await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert victims == []
    assert store.events == ["sweep", "lock taken"]
    assert not old.exists()


async def test_a_collection_holding_the_cycle_lock_does_not_stop_the_sweep(tmp_path):
    settings = _settings(tmp_path)
    old = _tmp_file(settings.raw_dir / "edge" / "r1", "1700000000001-aaaaaaaa", NOW - timedelta(hours=7))
    store = FakeStore()

    async with store.cycle_lock():  # a collection in flight
        victims = await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert victims is None
    assert not old.exists()


async def test_a_second_sweep_within_six_hours_is_skipped_and_runs_after(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    directory = settings.raw_dir / "edge" / "r1"
    store = _LockRecordingStore()
    _record_sweeps(monkeypatch, store)
    first = _tmp_file(directory, "1700000000001-aaaaaaaa", NOW - timedelta(hours=7))

    await maint.prune_rawstore(settings, store, keep=2, now=NOW)
    assert not first.exists()

    within = NOW + maint.RAW_TMP_SWEEP_INTERVAL - timedelta(minutes=1)
    second = _tmp_file(directory, "1700000000002-aaaaaaaa", within - timedelta(hours=7))
    await maint.prune_rawstore(settings, store, keep=2, now=within)
    assert second.exists()

    after = NOW + maint.RAW_TMP_SWEEP_INTERVAL
    await maint.prune_rawstore(settings, store, keep=2, now=after)
    assert not second.exists()
    assert store.events == ["sweep", "lock taken", "lock taken", "sweep", "lock taken"]


async def test_the_sweep_logs_how_many_files_it_removed(tmp_path, caplog):
    settings = _settings(tmp_path)
    for n in range(3):
        _tmp_file(settings.raw_dir / "edge" / f"r{n}", f"170000000000{n}-aaaaaaaa", NOW - timedelta(days=1))

    with caplog.at_level(logging.INFO, logger=maint.log.name):
        await maint.prune_rawstore(settings, FakeStore(), keep=2, now=NOW)

    assert any("removed 3 temporary file(s)" in r.getMessage() for r in caplog.records)


# --- inside the hourly prune, period tier on --------------------------------------------


async def test_with_the_period_tier_on_its_own_walk_sweeps(tmp_path, monkeypatch):
    """No standalone sweep: the tier's walk of the store matches the temporary
    files too, so the store is walked once."""
    settings = _settings(tmp_path, evidence_retention_days=30)
    _no_retained(monkeypatch)
    store = _LockRecordingStore()
    _record_sweeps(monkeypatch, store)
    raw = rawstore.write(
        settings.raw_dir, "edge", "1700000000000-aaaaaaaa", {"x": 1}, host="r1", key=dek(settings)
    )
    rawstore.mark_superseded(raw, superseded_by=9999)
    old = _tmp_file(raw.parent, "1700000000001-aaaaaaaa", NOW - timedelta(hours=7))
    fresh = _tmp_file(raw.parent, "1700000000002-aaaaaaaa", NOW - timedelta(minutes=5))
    walks: list[str] = []
    rglob = Path.rglob

    def counting_rglob(self: Path, pattern: str, *args, **kwargs):
        if self == settings.raw_dir:
            walks.append(pattern)
        return rglob(self, pattern, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", counting_rglob)

    victims = await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert victims == [raw]
    assert not raw.exists()
    assert not old.exists()
    assert fresh.exists()
    assert len(walks) == 1
    assert store.events == ["lock taken"]


async def test_swept_files_are_not_reported_as_pruned_raw_files(tmp_path, monkeypatch, caplog):
    settings = _settings(tmp_path, evidence_retention_days=0)
    _no_retained(monkeypatch)
    old = _tmp_file(settings.raw_dir / "edge" / "r1", "1700000000001-aaaaaaaa", NOW - timedelta(days=1))

    with caplog.at_level(logging.INFO, logger=maint.log.name):
        victims = await maint.prune_rawstore(settings, FakeStore(), keep=2, now=NOW)

    assert victims == []
    assert not old.exists()
    assert any("removed 1 temporary file(s)" in r.getMessage() for r in caplog.records)
