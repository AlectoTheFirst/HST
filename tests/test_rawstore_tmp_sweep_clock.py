"""The throttle of the standalone raw tmp sweep across a wall-clock step
(`maintenance._sweep_raw_tmp_throttled`).

With the period tier off, the hourly raw-store prune sweeps the temporary
files of unfinished raw writes at most once every `RAW_TMP_SWEEP_INTERVAL` in
a process, measured by the `now` of each turn. A `now` earlier than the one
the last sweep recorded, as after the wall clock was stepped back, is not
within the interval: the turn sweeps. An elapsed time of zero is.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tests.app.fakes import FakeStore

from hst.app.crypto import generate_key
from hst.core import rawstore
from hst.core.config import Settings
from hst.worker import maintenance as maint

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)


def _settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _tmp_file(directory: Path, run_id: str, modified: datetime) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{run_id}{rawstore.TMP_SUFFIX}"
    path.write_bytes(b"a partly written token")
    os.utime(path, (modified.timestamp(), modified.timestamp()))
    return path


@pytest.fixture(autouse=True)
def _no_earlier_sweep(monkeypatch):
    """Every test starts as a process that has not swept yet."""
    monkeypatch.setattr(maint, "_raw_tmp_swept_at", None)


async def test_a_wall_clock_stepped_back_sweeps_at_the_next_turn(tmp_path):
    settings = _settings(tmp_path)
    store = FakeStore()
    await maint.prune_rawstore(settings, store, keep=2, now=NOW + timedelta(days=1))
    leftover = _tmp_file(settings.raw_dir / "edge" / "r1", "1700000000001-aaaaaaaa", NOW - timedelta(hours=7))

    await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert not leftover.exists()
    assert maint._raw_tmp_swept_at == NOW


async def test_a_second_turn_at_the_same_time_is_skipped(tmp_path):
    settings = _settings(tmp_path)
    store = FakeStore()
    await maint.prune_rawstore(settings, store, keep=2, now=NOW)
    leftover = _tmp_file(settings.raw_dir / "edge" / "r1", "1700000000001-aaaaaaaa", NOW - timedelta(hours=7))

    await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert leftover.exists()
