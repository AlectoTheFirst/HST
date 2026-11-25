"""The hourly raw-store prune removes a spool last modified more than a day ago."""

from __future__ import annotations

import contextlib
import gzip
import json
import logging
import os
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tests.app.fakes import FakeStore

from hst.app.crypto import dek, generate_key
from hst.collectors import http_trace
from hst.core import Settings, rawstore
from hst.worker import maintenance as maint

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
OLD = NOW - maint.HTTP_TRACE_SPOOL_MIN_AGE - timedelta(minutes=1)


def _settings(tmp_path: Path, **kw) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key(), **kw)


def _age(path: Path, modified: datetime) -> Path:
    os.utime(path, (modified.timestamp(), modified.timestamp()), follow_symlinks=False)
    return path


def _spool(directory: Path, name: str, modified: datetime) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{http_trace.SPOOL_PREFIX}{name}{http_trace.SPOOL_SUFFIX}"
    path.write_bytes(gzip.compress(b'{"url": "https://vco/portal/rest/login"}\n'))
    return _age(path, modified)


@contextlib.contextmanager
def _fake_session(settings):
    yield object()


@pytest.fixture(autouse=True)
def _no_graph_history(monkeypatch):
    monkeypatch.setattr(maint, "_raw_tmp_swept_at", None)
    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [])


# --- the sweep itself -------------------------------------------------------------------


def test_an_old_spool_is_removed_and_a_fresh_one_kept(tmp_path):
    old = _spool(tmp_path, "abc123", OLD)
    fresh = _spool(tmp_path, "def456", NOW - timedelta(hours=1))

    removed = http_trace.sweep_spools(tmp_path, before=(NOW - maint.HTTP_TRACE_SPOOL_MIN_AGE).timestamp())

    assert removed == [old]
    assert not old.exists()
    assert fresh.exists()


def test_only_spools_directly_in_the_directory_are_removed(tmp_path):
    """A sealed trace, a raw file, a spool-named directory, a spool-named link
    and a spool-named file one level down all stay, however old."""
    settings = _settings(tmp_path)
    raw = rawstore.write(
        settings.raw_dir, "edge", "1600000000000-aaaaaaaa", {"x": 1}, host="r1", key=dek(settings)
    )
    sealed = rawstore.write_trace(raw, gzip.compress(b"{}\n"), key=dek(settings))
    below = _spool(raw.parent, "below", OLD)
    directory = settings.raw_dir / f"{http_trace.SPOOL_PREFIX}dir{http_trace.SPOOL_SUFFIX}"
    directory.mkdir()
    target = _spool(tmp_path / "elsewhere", "target", OLD)
    link = settings.raw_dir / f"{http_trace.SPOOL_PREFIX}link{http_trace.SPOOL_SUFFIX}"
    link.symlink_to(target)
    for path in (raw, sealed, directory, link):
        _age(path, OLD)

    assert http_trace.sweep_spools(settings.raw_dir, before=NOW.timestamp()) == []
    assert all(path.exists() for path in (raw, sealed, below, directory, target))
    assert link.is_symlink()


def test_a_missing_directory_sweeps_nothing(tmp_path):
    assert http_trace.sweep_spools(tmp_path / "raw", before=NOW.timestamp()) == []


def test_a_spool_that_cannot_be_removed_is_logged_and_left(tmp_path, monkeypatch, caplog):
    stuck = _spool(tmp_path, "stuck", OLD)
    gone = _spool(tmp_path, "gone", OLD)
    unlink = Path.unlink

    def refuse(self: Path, missing_ok: bool = False) -> None:
        if self == stuck:
            raise PermissionError(13, "Permission denied", str(self))
        unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse)
    with caplog.at_level(logging.WARNING, logger=http_trace.logger.name):
        removed = http_trace.sweep_spools(tmp_path, before=NOW.timestamp())

    assert removed == [gone]
    assert stuck.exists()
    assert any(
        "could not remove the spool" in r.getMessage() and str(stuck) in r.getMessage()
        for r in caplog.records
    )


def test_a_trace_whose_process_was_killed_leaves_the_spool_the_sweep_removes(tmp_path):
    """A real kill: a child process opens a trace, records an exchange and
    exits without sealing or discarding it."""
    raw_dir = tmp_path / "raw"
    child = textwrap.dedent(
        f"""
        import os
        from pathlib import Path
        from hst.collectors import http_trace

        trace = http_trace.HttpTrace("vco", Path({str(raw_dir)!r}))
        trace.record({{"url": "https://vco/portal/rest/login", "status": 200}})
        os._exit(3)
        """
    )
    done = subprocess.run([sys.executable, "-c", child], cwd=Path(__file__).parents[1], check=False)
    assert done.returncode == 3

    left = [p for p in raw_dir.iterdir() if p.is_file()]
    assert len(left) == 1
    assert left[0].name.startswith(http_trace.SPOOL_PREFIX) and left[0].name.endswith(http_trace.SPOOL_SUFFIX)

    now = datetime.now(UTC)
    assert http_trace.sweep_spools(raw_dir, before=(now - maint.HTTP_TRACE_SPOOL_MIN_AGE).timestamp()) == []
    later = now + maint.HTTP_TRACE_SPOOL_MIN_AGE + timedelta(minutes=1)
    assert (
        http_trace.sweep_spools(raw_dir, before=(later - maint.HTTP_TRACE_SPOOL_MIN_AGE).timestamp()) == left
    )
    assert not left[0].exists()


def test_a_spool_that_cannot_be_opened_is_not_left_behind(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(http_trace.gzip, "GzipFile", refuse)
    with pytest.raises(OSError, match="No space"):
        http_trace.HttpTrace("vco", tmp_path)

    assert list(tmp_path.iterdir()) == []


# --- inside the hourly raw-store prune ----------------------------------------------------


class _LockRecordingStore(FakeStore):
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


@pytest.mark.parametrize("days", [None, 30], ids=["period-off", "period-on"])
async def test_the_prune_removes_an_old_spool_before_it_takes_the_lock(tmp_path, monkeypatch, days):
    settings = _settings(tmp_path, evidence_retention_days=days)
    old = _spool(settings.raw_dir, "old", OLD)
    fresh = _spool(settings.raw_dir, "fresh", NOW - timedelta(hours=1))
    store = _LockRecordingStore()
    sweep = http_trace.sweep_spools

    def recording(spool_dir: Path, *, before: float) -> list[Path]:
        store.events.append("spool sweep under the lock" if store.held else "spool sweep")
        return sweep(spool_dir, before=before)

    monkeypatch.setattr(maint.http_trace, "sweep_spools", recording)

    victims = await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert victims == []
    assert store.events == ["spool sweep", "lock taken"]
    assert not old.exists()
    assert fresh.exists()


async def test_a_collection_holding_the_cycle_lock_does_not_stop_the_spool_sweep(tmp_path, caplog):
    settings = _settings(tmp_path)
    old = _spool(settings.raw_dir, "old", OLD)
    store = FakeStore()

    with caplog.at_level(logging.INFO, logger=maint.log.name):
        async with store.cycle_lock():  # a collection in flight
            victims = await maint.prune_rawstore(settings, store, keep=2, now=NOW)

    assert victims is None
    assert not old.exists()
    assert any(
        "removed 1 HTTP trace spool file(s) last modified more than 24 h ago" in r.getMessage()
        for r in caplog.records
    )


async def test_the_spool_sweep_runs_on_every_turn_and_walks_nothing(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    store = FakeStore()
    await maint.prune_rawstore(settings, store, keep=2, now=NOW)
    walks: list[str] = []
    rglob = Path.rglob

    def counting_rglob(self: Path, pattern: str, *args, **kwargs):
        walks.append(pattern)
        return rglob(self, pattern, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", counting_rglob)
    second = _spool(settings.raw_dir, "second", OLD)

    await maint.prune_rawstore(settings, store, keep=2, now=NOW + timedelta(minutes=5))

    assert not second.exists()
    assert walks == []


def test_a_live_trace_is_kept_and_seals(tmp_path):
    settings = _settings(tmp_path)
    trace = http_trace.HttpTrace("vco", settings.raw_dir)
    trace.record({"url": "https://vco/portal/rest/x", "status": 200})

    assert (
        http_trace.sweep_spools(
            settings.raw_dir, before=(datetime.now(UTC) - timedelta(hours=24)).timestamp()
        )
        == []
    )
    raw = rawstore.write(settings.raw_dir, "vco", "1700000000000-aaaaaaaa", {"x": 1}, key=dek(settings))
    sealed = trace.seal(raw, dek(settings))
    lines = rawstore.read_trace(sealed, dek(settings)).decode().splitlines()
    assert [json.loads(line)["url"] for line in lines] == ["https://vco/portal/rest/x"]
