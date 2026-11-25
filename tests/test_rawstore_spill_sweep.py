"""The raw-store prune removes spill files a day old
(`maintenance.RAW_SPILL_MIN_AGE`).

A cycle removes every spill file it made before it ends, and the next cycle's
start removes what a killed one left (tests/app/test_fetch_spill.py). An
install where no cycle runs after the kill has only the hourly prune: with the
period tier off it clears `<raw_dir>/.spill` on the throttled turn of the
temporary-file sweep, and with the tier on it clears it after the tier's own
walk, once the decision is taken and the lock is released. Neither walks
the store a second time.
"""

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


def _settings(tmp_path: Path, **kw) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key(), **kw)


def _spill_file(raw_dir: Path, run_id: str, modified: datetime, suffix: str = rawstore.SPILL_SUFFIX) -> Path:
    path = raw_dir / rawstore.SPILL_DIR / f"{run_id}{suffix}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"a sealed payload")
    os.utime(path, (modified.timestamp(), modified.timestamp()))
    return path


@contextlib.contextmanager
def _fake_session(settings):
    yield object()


@pytest.fixture(autouse=True)
def _no_earlier_sweep(monkeypatch):
    """Every test starts as a process that has not swept yet."""
    monkeypatch.setattr(maint, "_raw_tmp_swept_at", None)


class _LockRecordingStore(FakeStore):
    """A FakeStore that records when the prune holds the cycle lock."""

    def __init__(self) -> None:
        super().__init__()
        self.held = False

    @contextlib.asynccontextmanager
    async def try_cycle_lock(self):
        async with super().try_cycle_lock() as locked:
            self.held = bool(locked)
            try:
                yield locked
            finally:
                self.held = False


def _record_clears(monkeypatch, store: _LockRecordingStore) -> list[str]:
    events: list[str] = []
    clear = rawstore.clear_spills

    def recording(raw_dir: Path, **kw) -> list[Path]:
        events.append("clear under the lock" if store.held else "clear")
        return clear(raw_dir, **kw)

    monkeypatch.setattr(maint.rawstoremod, "clear_spills", recording)
    return events


async def test_with_the_period_tier_off_a_day_old_spill_is_removed(tmp_path, monkeypatch, caplog):
    settings = _settings(tmp_path)
    store = _LockRecordingStore()
    events = _record_clears(monkeypatch, store)
    old = _spill_file(settings.raw_dir, "1700000000000-aaaaaaaa", NOW - timedelta(hours=25))
    old_tmp = _spill_file(
        settings.raw_dir, "1700000000001-aaaaaaaa", NOW - timedelta(hours=25), suffix=rawstore.TMP_SUFFIX
    )
    young = _spill_file(settings.raw_dir, "1700000000002-aaaaaaaa", NOW - timedelta(hours=23))

    with caplog.at_level(logging.INFO, logger=maint.log.name):
        victims = await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert victims == []
    assert not old.exists() and not old_tmp.exists()
    assert young.exists()
    assert events == ["clear"], "cleared before the lock is tried, as the tmp sweep is"
    assert any(
        "removed 1 spill file(s) last modified more than 24 h ago" in r.getMessage() for r in caplog.records
    )


async def test_the_spill_clear_shares_the_tmp_sweeps_throttle(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    store = _LockRecordingStore()
    events = _record_clears(monkeypatch, store)

    await maint.prune_rawstore(settings, store, keep=2, now=NOW)
    within = NOW + maint.RAW_TMP_SWEEP_INTERVAL - timedelta(minutes=1)
    stale = _spill_file(settings.raw_dir, "1700000000000-aaaaaaaa", within - timedelta(days=2))
    await maint.prune_rawstore(settings, store, keep=2, now=within)
    assert stale.exists()

    await maint.prune_rawstore(settings, store, keep=2, now=NOW + maint.RAW_TMP_SWEEP_INTERVAL)
    assert not stale.exists()
    assert events == ["clear", "clear"]


async def test_nothing_is_logged_when_no_spill_is_old_enough(tmp_path, caplog):
    settings = _settings(tmp_path)
    _spill_file(settings.raw_dir, "1700000000000-aaaaaaaa", NOW - timedelta(hours=1))

    with caplog.at_level(logging.INFO, logger=maint.log.name):
        await maint.prune_rawstore(settings, FakeStore(), keep=2, now=NOW)

    assert not any("spill file" in r.getMessage() for r in caplog.records)


async def test_with_the_period_tier_on_a_day_old_spill_is_removed_after_the_lock_is_released(
    tmp_path, monkeypatch, caplog
):
    settings = _settings(tmp_path, evidence_retention_days=30)
    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [])
    store = _LockRecordingStore()
    events = _record_clears(monkeypatch, store)
    raw = rawstore.write(
        settings.raw_dir, "edge", "1700000000000-aaaaaaaa", {"x": 1}, host="r1", key=dek(settings)
    )
    rawstore.mark_superseded(raw, superseded_by=9999)
    old = _spill_file(settings.raw_dir, "1700000000001-aaaaaaaa", NOW - timedelta(hours=25))
    young = _spill_file(settings.raw_dir, "1700000000002-aaaaaaaa", NOW - timedelta(minutes=5))
    walks: list[str] = []
    rglob = Path.rglob

    def counting_rglob(self: Path, pattern: str, *args, **kwargs):
        if self == settings.raw_dir:
            walks.append(pattern)
        return rglob(self, pattern, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", counting_rglob)

    with caplog.at_level(logging.INFO, logger=maint.log.name):
        victims = await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert victims == [raw]
    assert not old.exists() and young.exists()
    assert events == ["clear"], "the walk and the clear run with the lock released"
    assert len(walks) == 1, "the spill directory is listed, not walked"
    assert any(
        "removed 1 spill file(s) last modified more than 24 h ago" in r.getMessage() for r in caplog.records
    )
