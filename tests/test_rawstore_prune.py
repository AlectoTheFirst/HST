"""`maintenance.prune_rawstore` sweeps the raw store."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta

from tests.app.fakes import FakeStore

from hst.app.crypto import dek, generate_key
from hst.core import manifest as manifestmod
from hst.core import rawstore
from hst.core.config import Settings
from hst.worker import maintenance as maint


def _settings(tmp_path, **kw) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key(), **kw)


def _key(settings: Settings) -> str:
    return dek(settings)


@contextlib.contextmanager
def _fake_session(settings):
    yield object()


def _run_id(at: datetime, nonce: str = "aaaaaaaa") -> str:
    return f"{int(at.timestamp() * 1000)}-{nonce}"


def _write_raw(settings: Settings, key: str, source: str, host: str, run_id: str):
    return rawstore.write(settings.raw_dir, source, run_id, {"x": 1}, host=host, key=key)


def _manifest(
    settings: Settings,
    snapshot_key: int,
    *,
    devices: list[manifestmod.DeviceEntry] = (),
    files: list[manifestmod.FileEntry] = (),
) -> None:
    record = manifestmod.SnapshotManifest(
        snapshot_key=snapshot_key,
        kind="full",
        opened=manifestmod.iso(snapshot_key),
        published=manifestmod.now_iso(),
        devices=list(devices),
        files=list(files),
    )
    manifestmod.write(settings, record)


def _no_retained(monkeypatch) -> None:
    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [])


def _retained(monkeypatch, keys: list[int]) -> None:
    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: keys)


# --- the period tier is off by default -------------------------------------------------


async def test_evidence_retention_days_unset_prunes_nothing(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    assert settings.evidence_retention_days is None
    key = _key(settings)
    old = datetime.now(UTC) - timedelta(days=4000)
    run_id = _run_id(old)
    path = _write_raw(settings, key, "nxos", "h1", run_id)
    rawstore.mark_joined(path, snapshot_ts=1000)
    _manifest(settings, 1000)
    _no_retained(monkeypatch)

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == []
    assert path.exists()


# --- still parked: never touched -------------------------------------------------------


async def test_a_parked_raw_file_is_left_alone(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=0)
    key = _key(settings)
    old = datetime.now(UTC) - timedelta(days=4000)
    path = _write_raw(settings, key, "nxos", "h1", _run_id(old))
    _no_retained(monkeypatch)

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == []
    assert path.exists()


# --- no manifest for its own run: no-migration, left alone -----------------------------


async def test_a_raw_file_whose_own_run_has_no_manifest_is_left_alone(tmp_path, monkeypatch):
    """A run with no manifest keeps its file."""
    settings = _settings(tmp_path, evidence_retention_days=30)
    key = _key(settings)
    old = datetime.now(UTC) - timedelta(days=400)
    path = _write_raw(settings, key, "nxos", "h1", _run_id(old))
    rawstore.mark_joined(path, snapshot_ts=1000)  # no manifest ever written for 1000
    _retained(monkeypatch, [5000])  # some other run is retained; 1000 is not

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == []
    assert path.exists()


# --- graph-count tier: retained, with or without a manifest -----------------------------


async def test_a_raw_file_of_a_graph_retained_run_is_kept_however_old(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=1)
    key = _key(settings)
    old = datetime.now(UTC) - timedelta(days=400)
    path = _write_raw(settings, key, "nxos", "h1", _run_id(old))
    rawstore.mark_joined(path, snapshot_ts=2000)
    _retained(monkeypatch, [2000])  # graph-retained, and no manifest exists for it either

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == []
    assert path.exists()


# --- manifest membership survives the run falling out -----------------------------------


async def test_a_raw_file_is_kept_via_manifest_membership_after_its_run_falls_out(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=1)
    key = _key(settings)
    old = datetime.now(UTC) - timedelta(days=400)
    run_id = _run_id(old)
    path = _write_raw(settings, key, "nxos", "h1", run_id)
    rawstore.mark_joined(path, snapshot_ts=1000)
    _manifest(settings, 1000)  # its own run has a manifest, but is not retained
    device = manifestmod.DeviceEntry(
        source="nxos", host="h1", outcome="carried", effective_run=run_id, carried=True
    )
    _manifest(settings, 5000, devices=[device])
    _retained(monkeypatch, [5000])

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == []
    assert path.exists()


# --- the AND predicate ------------------------------------------------------------------


async def test_a_raw_file_past_graph_retention_and_past_the_period_is_deleted(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=30)
    key = _key(settings)
    old = datetime.now(UTC) - timedelta(days=400)
    run_id = _run_id(old)
    path = _write_raw(settings, key, "nxos", "h1", run_id)
    rawstore.mark_joined(path, snapshot_ts=1000)
    _manifest(settings, 1000)  # a manifest exists, and names nothing that protects this file
    _manifest(settings, 5000)
    _retained(monkeypatch, [5000])

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == [path]
    assert not path.exists()


async def test_a_raw_file_past_graph_retention_but_within_the_period_is_kept(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=30)
    key = _key(settings)
    recent = datetime.now(UTC) - timedelta(days=5)
    run_id = _run_id(recent)
    path = _write_raw(settings, key, "nxos", "h1", run_id)
    rawstore.mark_joined(path, snapshot_ts=1000)
    _manifest(settings, 1000)
    _manifest(settings, 5000)
    _retained(monkeypatch, [5000])

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == []
    assert path.exists()


# --- superseded payloads: period alone, no graph tier to consult ------------------------


async def test_a_superseded_raw_file_past_the_period_is_deleted(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=30)
    key = _key(settings)
    old = datetime.now(UTC) - timedelta(days=400)
    path = _write_raw(settings, key, "nxos", "h1", _run_id(old))
    rawstore.mark_superseded(path, superseded_by=9999)
    _retained(monkeypatch, [5000])

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == [path]
    assert not path.exists()


async def test_a_superseded_raw_file_within_the_period_is_kept(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=30)
    key = _key(settings)
    recent = datetime.now(UTC) - timedelta(days=5)
    path = _write_raw(settings, key, "nxos", "h1", _run_id(recent))
    rawstore.mark_superseded(path, superseded_by=9999)
    _retained(monkeypatch, [5000])

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == []
    assert path.exists()


# --- no graph history at all: leave joined files alone -----------------------------------


async def test_no_graph_history_leaves_a_joined_file_alone(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=1)
    key = _key(settings)
    old = datetime.now(UTC) - timedelta(days=400)
    path = _write_raw(settings, key, "nxos", "h1", _run_id(old))
    rawstore.mark_joined(path, snapshot_ts=1000)
    _manifest(settings, 1000)
    _no_retained(monkeypatch)  # bootstrap state: nothing graph-retained yet

    victims = await maint.prune_rawstore(settings, FakeStore(), keep=2)

    assert victims == []
    assert path.exists()


# --- the cross-pod cycle lock ------------------------------------------------------------


async def test_prune_rawstore_is_skipped_rather_than_queued_behind_a_running_cycle(tmp_path, monkeypatch):
    settings = _settings(tmp_path, evidence_retention_days=30)
    calls: list[int] = []

    def retained_runs(session, keep):
        calls.append(keep)
        return []

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", retained_runs)

    store = FakeStore()
    async with store.cycle_lock():  # a collection in flight
        victims = await maint.prune_rawstore(settings, store, keep=2)
    assert victims is None
    assert calls == []


def test_prune_rawstore_is_scheduled_hourly_and_unguarded():
    from hst.worker import scheduler as sched_mod

    schedule = next(s for s in sched_mod.SYSTEM_SCHEDULES if s.kind == maint.PRUNE_RAWSTORE)
    assert schedule.interval == sched_mod.HOURLY
    assert schedule.guard is sched_mod.always
