from __future__ import annotations

import asyncio
import contextlib
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from tests.app.fakes import FakeStore

from hst.app import retention
from hst.app.store import AiEvent
from hst.core import Settings
from hst.core import manifest as manifestmod
from hst.worker import maintenance as maint
from hst.worker import scheduler as sched_mod
from hst.worker.scheduler import Schedule, Scheduler, jitter

NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
DSN = os.environ.get("HST_TEST_PG_DSN")


class Clock:
    """A clock a test moves by hand."""

    def __init__(self, at: datetime = NOW) -> None:
        self.at = at

    def __call__(self) -> datetime:
        return self.at

    def advance(self, seconds: float) -> datetime:
        self.at += timedelta(seconds=seconds)
        return self.at


# `_scheduler` pins the device-run schedule to an interval no test here reaches
# (the longest clock advance in this file is a day).
_NEVER_DUE_S = 10**9


def _scheduler(store, schedules, clock, **overrides) -> Scheduler:
    if not any(s.kind == maint.BUILD_DEVICE_RUN for s in schedules):
        schedules = (*schedules, Schedule(maint.BUILD_DEVICE_RUN, _NEVER_DUE_S))
    return Scheduler(
        store,
        Settings(_env_file=None, **overrides),
        schedules=schedules,
        clock=clock,
    )


# --- the registry ----------------------------------------------------------------


def test_the_system_registry_covers_every_maintenance_body():
    assert set(sched_mod.kinds()) == set(maint.BODIES) - {maint.BUILD_DEVICE_RUN}
    scheduler = Scheduler(FakeStore(), Settings(_env_file=None))
    assert set(scheduler.kinds()) == set(maint.BODIES)


def test_the_session_sweep_runs_on_the_session_purge_interval():
    session = next(s for s in sched_mod.SYSTEM_SCHEDULES if s.kind == maint.PURGE_SESSIONS)
    assert session.interval == sched_mod.SESSION_PURGE_INTERVAL_S == 3600.0
    hourly = {s.kind for s in sched_mod.SYSTEM_SCHEDULES if s.interval == sched_mod.HOURLY}
    assert hourly == {
        maint.PRUNE_GRAPH,
        maint.PRUNE_SIDESTORE,
        maint.PRUNE_RAWSTORE,
        maint.PRUNE_MANIFESTS,
        maint.PURGE_LOGIN_EVENTS,
        maint.PURGE_CYPHER_EVENTS,
        maint.PURGE_AI_CONVERSATIONS,
        maint.COMPACT_AI_STEPS,
        maint.PURGE_AI_EPHEMERAL,
        maint.PURGE_AI_EVENTS,
        maint.PURGE_SESSIONS,
    }
    history = next(s for s in sched_mod.SYSTEM_SCHEDULES if s.kind == maint.PURGE_JOB_HISTORY)
    assert history.interval == sched_mod.DAILY


# --- the device-run schedule -------------------------------------------------------


def test_the_device_run_schedule_is_added_from_settings_at_construction():
    scheduler = Scheduler(FakeStore(), Settings(_env_file=None, device_run_interval_s=321))
    schedule = next(s for s in scheduler._schedules if s.kind == maint.BUILD_DEVICE_RUN)
    assert schedule.interval == 321
    assert maint.BUILD_DEVICE_RUN not in sched_mod.kinds()  # not in the static registry


def test_a_caller_supplied_device_run_schedule_is_not_doubled_up():
    mine = Schedule(maint.BUILD_DEVICE_RUN, 5.0)
    scheduler = Scheduler(
        FakeStore(),
        Settings(_env_file=None, device_run_interval_s=600),
        schedules=(mine,),
    )
    matches = [s for s in scheduler._schedules if s.kind == maint.BUILD_DEVICE_RUN]
    assert matches == [mine]


async def test_the_device_run_schedule_queues_its_own_kind_when_due():
    store = FakeStore()
    clock = Clock()
    scheduler = Scheduler(
        store,
        Settings(_env_file=None, device_run_interval_s=100),
        schedules=(),
        clock=clock,
    )
    scheduler.arm()

    clock.advance(200)
    assert await scheduler.tick() == [maint.BUILD_DEVICE_RUN]
    assert [j.kind for j in store.jobs.values()] == [maint.BUILD_DEVICE_RUN]


# --- jitter ----------------------------------------------------------------------


def test_jitter_is_stable_per_kind_and_within_bounds():
    for kind in sched_mod.kinds():
        first = jitter(kind, sched_mod.HOURLY)
        assert first == jitter(kind, sched_mod.HOURLY)
        assert 0 <= first < sched_mod.MAX_JITTER_S


def test_jitter_spreads_the_schedules_that_share_an_interval():
    offsets = [jitter(s.kind, s.interval) for s in sched_mod.SYSTEM_SCHEDULES]
    assert len(set(offsets)) == len(offsets)


def test_jitter_of_a_zero_interval_is_zero():
    assert jitter("maintenance.prune_graph", 0.0) == 0.0


# --- due-ness --------------------------------------------------------------------


async def test_nothing_is_due_before_one_full_interval_has_passed():
    store = FakeStore()
    clock = Clock()
    schedules = (Schedule("maintenance.purge_sessions", 3600.0),)
    scheduler = _scheduler(store, schedules, clock)
    scheduler.arm()

    assert await scheduler.tick() == []
    clock.advance(3599)
    assert await scheduler.tick() == []
    clock.advance(2 + jitter("maintenance.purge_sessions", 3600.0))
    assert await scheduler.tick() == ["maintenance.purge_sessions"]
    assert [j.kind for j in store.jobs.values()] == ["maintenance.purge_sessions"]


async def test_a_due_schedule_queues_once_per_interval():
    store = FakeStore()
    clock = Clock()
    schedules = (Schedule("maintenance.purge_sessions", 100.0),)
    scheduler = _scheduler(store, schedules, clock)
    scheduler.arm()

    clock.advance(200)
    assert await scheduler.tick() == ["maintenance.purge_sessions"]
    clock.advance(100)
    assert await scheduler.tick() == []

    # once it completes, the following turn queues again
    (claimed,) = await store.claim_jobs("w", 1, clock.at, timedelta(minutes=5))
    await store.finish_job(claimed.id, "ok", "done", clock.at)
    clock.advance(100)
    assert await scheduler.tick() == ["maintenance.purge_sessions"]


async def test_a_long_outage_queues_one_turn_not_one_per_missed_interval():
    """The next due time is measured from now, so a process stopped for a day
    comes back and runs each schedule once."""
    store = FakeStore()
    clock = Clock()
    schedules = (Schedule("maintenance.purge_sessions", 3600.0),)
    scheduler = _scheduler(store, schedules, clock)
    scheduler.arm()

    clock.advance(86_400)
    assert await scheduler.tick() == ["maintenance.purge_sessions"]
    (claimed,) = await store.claim_jobs("w", 1, clock.at, timedelta(minutes=5))
    await store.finish_job(claimed.id, "ok", "done", clock.at)

    clock.advance(60)
    assert await scheduler.tick() == []  # not owed 23 more turns
    clock.advance(3600)
    assert await scheduler.tick() == ["maintenance.purge_sessions"]


async def test_a_refused_enqueue_advances_the_next_due_time():
    store = FakeStore()
    clock = Clock()
    schedules = (Schedule("maintenance.prune_graph", 100.0),)
    scheduler = _scheduler(store, schedules, clock)
    scheduler.arm()

    clock.advance(200)
    assert await scheduler.tick() == ["maintenance.prune_graph"]
    await store.claim_jobs("w", 1, clock.at, timedelta(minutes=5))

    clock.advance(100)
    assert await scheduler.tick() == []
    assert await scheduler.tick() == []
    assert len(store.jobs) == 1


async def test_a_kind_whose_enqueue_raises_stays_due_for_the_next_tick(monkeypatch):
    store = FakeStore()
    clock = Clock()
    schedules = (Schedule("maintenance.prune_graph", 3600.0),)
    scheduler = _scheduler(store, schedules, clock)
    scheduler.arm()
    enqueue = store.enqueue_job
    calls = 0

    async def flaky(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ConnectionError("postgres went away")
        return await enqueue(*args, **kwargs)

    monkeypatch.setattr(store, "enqueue_job", flaky)
    clock.advance(7200)
    with pytest.raises(ConnectionError):
        await scheduler.tick()
    clock.advance(30)
    assert await scheduler.tick() == ["maintenance.prune_graph"]


# --- guards ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "setting"),
    [
        (maint.PURGE_LOGIN_EVENTS, "login_event_retention_days"),
        (maint.PURGE_CYPHER_EVENTS, "cypher_event_retention_days"),
        (maint.PURGE_JOB_HISTORY, "job_history_retention_days"),
    ],
)
async def test_a_retention_of_zero_queues_no_job_at_all(kind, setting):
    store = FakeStore()
    clock = Clock()
    schedules = tuple(replace(s, interval=100.0) for s in sched_mod.SYSTEM_SCHEDULES)
    scheduler = _scheduler(store, schedules, clock, **{setting: 0})
    scheduler.arm()

    clock.advance(200)
    queued = await scheduler.tick()
    assert kind not in queued
    assert maint.PURGE_SESSIONS in queued


async def test_a_guard_reads_the_stored_limit_over_the_environment():
    store = FakeStore()
    await store.put_setting(retention.SETTINGS_KEY, {"login_event_retention_days": 0}, b"")
    clock = Clock()
    schedules = tuple(replace(s, interval=100.0) for s in sched_mod.SYSTEM_SCHEDULES)
    scheduler = _scheduler(store, schedules, clock, login_event_retention_days=90)
    scheduler.arm()

    clock.advance(200)
    assert maint.PURGE_LOGIN_EVENTS not in await scheduler.tick()


async def test_queued_jobs_are_attributed_to_the_scheduler():
    store = FakeStore()
    clock = Clock()
    scheduler = _scheduler(store, (Schedule(maint.PURGE_SESSIONS, 100.0),), clock)
    scheduler.arm()
    clock.advance(200)
    await scheduler.tick()

    (job,) = store.jobs.values()
    assert job.triggered_by == "scheduler"
    assert (job.source, job.device) == (None, None)  # maintenance scopes nothing


# --- leadership ------------------------------------------------------------------


async def test_a_non_leader_stands_by_and_queues_nothing():
    store = FakeStore()
    asks: list[float] = []

    async def sleep(seconds):
        asks.append(seconds)
        if len(asks) >= 3:
            raise asyncio.CancelledError
        await asyncio.sleep(0)

    scheduler = Scheduler(
        store,
        Settings(_env_file=None),
        schedules=(Schedule(maint.PURGE_SESSIONS, 0.0),),
        standby_s=7.0,
        sleep=sleep,
    )
    async with store.try_scheduler_lock() as leader:  # a peer replica holds it
        assert leader is True
        with pytest.raises(asyncio.CancelledError):
            await scheduler.run()

    assert asks == [7.0, 7.0, 7.0]  # stood by and kept asking
    assert store.jobs == {}


async def test_the_leader_schedules_once_it_holds_the_lock():
    store = FakeStore()
    ticks = 0

    async def sleep(seconds):
        nonlocal ticks
        ticks += 1
        if ticks > 3:
            raise asyncio.CancelledError
        await asyncio.sleep(0)

    scheduler = Scheduler(
        store,
        Settings(_env_file=None),
        schedules=(Schedule(maint.PURGE_SESSIONS, 0.0),),
        tick_s=0.0,
        sleep=sleep,
    )
    with pytest.raises(asyncio.CancelledError):
        await scheduler.run()
    assert [j.kind for j in store.jobs.values()] == [maint.PURGE_SESSIONS]
    # leadership was released with the loop, so a standby can take over
    assert not store._scheduler_lock.locked()


async def test_a_failing_tick_does_not_cost_leadership():
    class BrokenStore(FakeStore):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        async def enqueue_job(self, *a, **kw):
            self.attempts += 1
            if self.attempts <= 2:
                raise RuntimeError("connection reset")
            return await super().enqueue_job(*a, **kw)

    store = BrokenStore()
    ticks = 0

    async def sleep(seconds):
        nonlocal ticks
        ticks += 1
        if ticks > 4:
            raise asyncio.CancelledError
        await asyncio.sleep(0)

    scheduler = Scheduler(
        store,
        Settings(_env_file=None),
        schedules=(Schedule(maint.PURGE_SESSIONS, 0.0),),
        tick_s=0.0,
        sleep=sleep,
    )
    with pytest.raises(asyncio.CancelledError):
        await scheduler.run()
    assert store.attempts >= 3
    assert [j.kind for j in store.jobs.values()] == [maint.PURGE_SESSIONS]


async def test_a_leader_whose_lock_is_lost_stops_scheduling_and_stands_by():
    class Store(FakeStore):
        def __init__(self):
            super().__init__()
            self.lose = []
            self.peer_leads = False

        @contextlib.asynccontextmanager
        async def try_scheduler_lock(self, on_lost=None):
            if self.peer_leads:
                yield False
                return
            self.lose.append(on_lost)
            yield True

    store = Store()
    asks: list[float] = []

    async def sleep(seconds):
        asks.append(seconds)
        if len(asks) == 2:
            # the lock connection of the leader drops, and a peer takes the lock
            store.peer_leads = True
            store.lose[0]()
        if len(asks) >= 4:
            raise asyncio.CancelledError
        await asyncio.sleep(0)

    scheduler = Scheduler(
        store,
        Settings(_env_file=None),
        schedules=(Schedule(maint.PURGE_SESSIONS, 0.0),),
        tick_s=1.0,
        standby_s=7.0,
        sleep=sleep,
    )
    with pytest.raises(asyncio.CancelledError):
        await scheduler.run()
    # 1 tick as the leader, then the loss, then the standby waits
    assert asks == [1.0, 1.0, 7.0, 7.0]
    assert [j.kind for j in store.jobs.values()] == [maint.PURGE_SESSIONS]


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_only_one_process_can_lead_at_a_time():
    from hst.app.store.pg import PgStore, upgrade_to_head

    await asyncio.to_thread(upgrade_to_head, DSN)
    first, second = PgStore(DSN), PgStore(DSN)
    try:
        async with first.try_scheduler_lock() as leader:
            assert leader is True
            async with second.try_scheduler_lock() as standby:
                assert standby is False
        # the lock is released with its connection, so the standby takes over
        async with second.try_scheduler_lock() as promoted:
            assert promoted is True
    finally:
        await first.dispose()
        await second.dispose()


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_the_leader_is_told_when_its_lock_connection_is_gone(monkeypatch):
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store import pg as pgmod

    monkeypatch.setattr(pgmod, "LOCK_PING_S", 0.05)
    await asyncio.to_thread(pgmod.upgrade_to_head, DSN)
    leader_store, standby_store = pgmod.PgStore(DSN), pgmod.PgStore(DSN)
    engine = create_async_engine(DSN)
    lost = asyncio.Event()
    try:
        async with leader_store.try_scheduler_lock(on_lost=lost.set) as leader:
            assert leader is True
            async with engine.connect() as c:
                await c.execute(
                    sa.text(
                        "SELECT pg_terminate_backend(pid) FROM pg_locks "
                        "WHERE locktype = 'advisory' AND pid <> pg_backend_pid()"
                    )
                )
            await asyncio.wait_for(lost.wait(), 10)
            async with standby_store.try_scheduler_lock() as promoted:
                assert promoted is True
    finally:
        await engine.dispose()
        await leader_store.dispose()
        await standby_store.dispose()


# --- prune_sidestore ---------------------------------------------------------------


def _rib_row() -> dict:
    return {
        "device_uid": "dev:r1",
        "vrf": "default",
        "context_uid": None,
        "prefix": "0.0.0.0/0",
        "next_hop": "10.0.0.1",
        "interface": "eth0",
        "protocol": "static",
        "metric": 1,
        "af": 4,
        "prefixlen": 0,
        "lo": b"\x00" * 16,
        "hi": b"\xff" * 16,
    }


@contextlib.contextmanager
def _fake_session(settings):
    yield object()


async def test_prune_sidestore_removes_rib_files_older_than_the_oldest_kept_cycle(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    for ts, hexid in [(1000, "aaaaaaaa"), (2000, "bbbbbbbb"), (3000, "cccccccc")]:
        sidestore.write_table(settings.sidestore_dir, "rib", "nxos", "h1", f"{ts}-{hexid}", [_rib_row()], ts)
    rib_dir = settings.sidestore_dir / "rib"
    assert len(list(rib_dir.rglob("*.parquet"))) == 3

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [3000, 2000])
    # a kept run with no manifest protects every file up to its key, so
    # the kept runs have theirs, binding nothing of the oldest file
    _manifest(settings, 3000)
    _manifest(settings, 2000)

    store = FakeStore()
    victims = await maint.prune_sidestore(settings, store, keep=2)

    assert victims is not None
    assert [p.name for p in victims] == ["1000-aaaaaaaa.parquet"]
    remaining = sorted(p.name for p in rib_dir.rglob("*.parquet"))
    assert remaining == ["2000-bbbbbbbb.parquet", "3000-cccccccc.parquet"]


class _RunsGraph:
    """The two reads `cycle.retained_runs` makes: the pointer, and every run with
    its kind and parent."""

    def __init__(self, rows: list[dict], current: int) -> None:
        self.rows = rows
        self.current = current

    def run(self, query: str, **params):
        rows = [{"current": self.current}] if "CyclePointer" in query else self.rows

        class _Result:
            def data(self) -> list[dict]:
                return rows

        return _Result()

    def execute_read(self, work):
        return work(self)


async def test_prune_sidestore_keeps_the_files_of_a_kept_cycle_behind_a_burst_of_device_runs(
    tmp_path, monkeypatch
):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    for ts, hexid in [(1000, "aaaaaaaa"), (2000, "bbbbbbbb"), (2100, "cccccccc")]:
        sidestore.write_table(settings.sidestore_dir, "rib", "nxos", "h1", f"{ts}-{hexid}", [_rib_row()], ts)

    graph = _RunsGraph(
        [
            {"cts": 2200, "kind": "device", "parent": 2100},
            {"cts": 2100, "kind": "device", "parent": 2000},
            {"cts": 2000, "kind": "full", "parent": 1000},
            {"cts": 1000, "kind": "full", "parent": None},
        ],
        current=2200,
    )
    monkeypatch.setattr(maint, "_session", contextlib.contextmanager(lambda settings: iter([graph])))

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=2)

    assert victims == []
    remaining = sorted(p.name for p in (settings.sidestore_dir / "rib").rglob("*.parquet"))
    assert remaining == ["1000-aaaaaaaa.parquet", "2000-bbbbbbbb.parquet", "2100-cccccccc.parquet"]


async def test_prune_sidestore_leaves_a_file_with_no_parseable_run_timestamp(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    rib_dir = settings.sidestore_dir / "rib"
    rib_dir.mkdir(parents=True)
    stray = rib_dir / "not-a-run-id.parquet"
    stray.write_bytes(b"")

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [3000])

    store = FakeStore()
    victims = await maint.prune_sidestore(settings, store, keep=2)

    assert victims == []
    assert stray.exists()


def _mac_row() -> dict:
    return {"device_uid": "dev:m1", "vlan": 10, "mac": "00:11:22:33:44:55", "port_name": "eth0"}


def _arp_row() -> dict:
    return {
        "device_uid": "dev:a1",
        "vrf": "default",
        "ip": "10.0.0.9",
        "mac": "aa:bb:cc:dd:ee:ff",
        "interface_name": "eth0",
    }


async def test_prune_sidestore_sweeps_mac_and_arp_tables_too(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    base = settings.sidestore_dir
    for table, row in (("rib", _rib_row()), ("mac", _mac_row()), ("arp", _arp_row())):
        for ts, hexid in [(1000, "aaaaaaaa"), (2000, "bbbbbbbb")]:
            sidestore.write_table(base, table, "nxos", "h1", f"{ts}-{hexid}", [row], ts)

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [2000])
    _manifest(settings, 2000)

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=1)

    assert sorted(p.parent.parent.parent.name for p in victims) == ["arp", "mac", "rib"]
    for table in ("rib", "mac", "arp"):
        remaining = sorted(p.name for p in (base / table).rglob("*.parquet"))
        assert remaining == ["2000-bbbbbbbb.parquet"]


async def test_prune_sidestore_reads_the_snapshot_ts_column_not_the_file_name(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    base = settings.sidestore_dir
    # named "2000-..." (a kept run, by name) but joined the pruned run 500
    named_kept_actually_pruned = sidestore.write_table(
        base, "rib", "nxos", "h1", "2000-aaaaaaaa", [_rib_row()], 500
    )
    # named "500-..." (a pruned run, by name) but joined the kept run 2000
    named_pruned_actually_kept = sidestore.write_table(
        base, "rib", "nxos", "h1", "500-bbbbbbbb", [_rib_row()], 2000
    )

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [2000])
    _manifest(settings, 2000)

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=1)

    assert victims == [named_kept_actually_pruned]
    assert not named_kept_actually_pruned.exists()
    assert named_pruned_actually_kept.exists()


async def test_prune_sidestore_holds_the_cycle_lock_while_it_runs(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    store = FakeStore()
    held: list[bool] = []

    def retained_runs(session, keep):
        held.append(store._cycle_lock.locked())
        return []

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", retained_runs)

    await maint.prune_sidestore(settings, store, keep=2)
    assert held == [True]


async def test_prune_sidestore_is_skipped_rather_than_queued_behind_a_running_cycle(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    calls: list[int] = []

    def retained_runs(session, keep):
        calls.append(keep)
        return []

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", retained_runs)

    store = FakeStore()
    async with store.cycle_lock():  # a collection in flight
        victims = await maint.prune_sidestore(settings, store, keep=2)
    assert victims is None
    assert calls == []


def test_prune_sidestore_is_scheduled_hourly_and_unguarded():
    schedule = next(s for s in sched_mod.SYSTEM_SCHEDULES if s.kind == maint.PRUNE_SIDESTORE)
    assert schedule.interval == sched_mod.HOURLY
    assert schedule.guard is sched_mod.always


# --- prune_sidestore: manifest membership and the period tier ---------------------------


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


def _rib_file_entry(source: str, host: str, run_id: str) -> manifestmod.FileEntry:
    return manifestmod.FileEntry(
        kind="sidestore", path="x", sha256="0" * 64, bytes=1, source=source, host=host, run_id=run_id
    )


async def test_prune_sidestore_keeps_a_carried_devices_file_via_manifest_membership(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    run_id = "1000-aaaaaaaa"
    sidestore.write_table(settings.sidestore_dir, "rib", "nxos", "h1", run_id, [_rib_row()], 1000)

    device = manifestmod.DeviceEntry(
        source="nxos", host="h1", outcome="carried", effective_run=run_id, carried=True
    )
    _manifest(settings, 2000, devices=[device])
    _manifest(settings, 3000, devices=[device])
    # 1000 itself has no manifest read here: it is not in `retained_runs`'s
    # result, so `_manifest_protected_identities` never looks for one.

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [3000, 2000])

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=2)

    assert victims == []
    assert (settings.sidestore_dir / "rib" / "nxos" / "h1" / f"{run_id}.parquet").exists()


async def test_prune_sidestore_deletes_an_unretained_uncarried_file_once_it_predates_manifests(
    tmp_path, monkeypatch
):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    run_id = "1000-aaaaaaaa"
    path = sidestore.write_table(settings.sidestore_dir, "rib", "nxos", "h1", run_id, [_rib_row()], 1000)
    _manifest(settings, 3000)  # names nothing of this device

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [3000])

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=1)

    assert victims == [path]
    assert not path.exists()


async def test_prune_sidestore_period_tier_off_follows_the_graph_tier_alone(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    assert settings.evidence_retention_days is None
    path = sidestore.write_table(
        settings.sidestore_dir, "rib", "nxos", "h1", "1000-aaaaaaaa", [_rib_row()], 1000
    )

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [2000])
    _manifest(settings, 2000)

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=1)

    assert victims == [path]
    assert not path.exists()


async def test_prune_sidestore_past_graph_retention_but_within_the_period_is_kept(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30)
    # prune_sidestore measures the period against the real clock.
    recent_ts = int((datetime.now(UTC) - timedelta(days=5)).timestamp() * 1000)
    path = sidestore.write_table(
        settings.sidestore_dir, "rib", "nxos", "h1", f"{recent_ts}-aaaaaaaa", [_rib_row()], recent_ts
    )
    _manifest(settings, 9_999_999_999_999)

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [9_999_999_999_999])

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=1)

    assert victims == []
    assert path.exists()


async def test_prune_sidestore_past_graph_retention_and_past_the_period_is_deleted(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30)
    old_ts = int((NOW - timedelta(days=400)).timestamp() * 1000)
    path = sidestore.write_table(
        settings.sidestore_dir, "rib", "nxos", "h1", f"{old_ts}-aaaaaaaa", [_rib_row()], old_ts
    )
    _manifest(settings, 9_999_999_999_999)

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [9_999_999_999_999])

    victims = await maint.prune_sidestore(settings, FakeStore(), keep=1)

    assert victims == [path]
    assert not path.exists()


async def test_prune_sidestore_a_graph_retained_run_with_no_manifest_is_protected_and_logged(
    tmp_path, monkeypatch, caplog
):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=1)
    old_ts = 2000
    path = sidestore.write_table(
        settings.sidestore_dir, "rib", "nxos", "h1", f"{old_ts}-aaaaaaaa", [_rib_row()], old_ts
    )
    # 2000 is graph-retained but never got a manifest written for it

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [2000])

    with caplog.at_level("INFO", logger=maint.log.name):
        victims = await maint.prune_sidestore(settings, FakeStore(), keep=1)

    assert victims == []
    assert path.exists()
    assert any("no manifest" in r.message for r in caplog.records)


# --- prune_rawstore: scheduling -----------------------------------------------------

# `maint.prune_rawstore`'s own behavior is covered by tests/test_rawstore_prune.py;
# only the schedule wiring belongs beside its siblings here.


def test_prune_rawstore_is_scheduled_hourly_and_unguarded():
    schedule = next(s for s in sched_mod.SYSTEM_SCHEDULES if s.kind == maint.PRUNE_RAWSTORE)
    assert schedule.interval == sched_mod.HOURLY
    assert schedule.guard is sched_mod.always


async def test_prune_rawstore_body_reports_the_period_tier_being_off():
    ctx = maint.Context(store=FakeStore(), settings=Settings(_env_file=None))
    detail = await maint._prune_rawstore_body(ctx, None)
    assert "period tier is off" in detail


# --- prune_manifests ---------------------------------------------------------------------


def test_prune_manifests_is_scheduled_hourly_and_unguarded():
    schedule = next(s for s in sched_mod.SYSTEM_SCHEDULES if s.kind == maint.PRUNE_MANIFESTS)
    assert schedule.interval == sched_mod.HOURLY
    assert schedule.guard is sched_mod.always


async def test_prune_manifests_period_tier_off_prunes_nothing(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    assert settings.evidence_retention_days is None
    _manifest(settings, 1000)
    _manifest(settings, 2000)

    victims = await maint.prune_manifests(settings, FakeStore())

    assert victims == []
    assert manifestmod.path_for(settings, 1000).exists()


async def test_prune_manifests_never_deletes_the_newest(tmp_path):
    old_ts = int((NOW - timedelta(days=400)).timestamp() * 1000)
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30)
    _manifest(settings, old_ts)

    victims = await maint.prune_manifests(settings, FakeStore())

    assert victims == []
    assert manifestmod.path_for(settings, old_ts).exists()


@pytest.fixture
def graph_keeps_nothing(monkeypatch):
    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [])


async def test_prune_manifests_deletes_a_manifest_past_the_period_nothing_needs(
    tmp_path, graph_keeps_nothing
):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30)
    old_ts = int((NOW - timedelta(days=400)).timestamp() * 1000)
    older_ts = int((NOW - timedelta(days=500)).timestamp() * 1000)
    _manifest(settings, older_ts)
    _manifest(settings, old_ts)  # no `previous` link recorded here: an isolated older manifest
    newest_ts = int(NOW.timestamp() * 1000)
    _manifest(settings, newest_ts)

    victims = await maint.prune_manifests(settings, FakeStore())

    assert sorted(victims) == sorted([old_ts, older_ts])
    assert not manifestmod.path_for(settings, old_ts).exists()
    assert not manifestmod.path_for(settings, older_ts).exists()
    assert manifestmod.path_for(settings, newest_ts).exists()


async def test_prune_manifests_keeps_the_manifest_of_a_run_a_reader_holds_open(tmp_path, graph_keeps_nothing):
    """A run that fell out of the graph window while a trace holds a lease on it keeps
    its manifest, and loses it on the first sweep after the lease ends."""
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30)
    old_ts = int((NOW - timedelta(days=400)).timestamp() * 1000)
    other_ts = int((NOW - timedelta(days=401)).timestamp() * 1000)
    _manifest(settings, other_ts)
    _manifest(settings, old_ts)
    _manifest(settings, int(NOW.timestamp() * 1000))
    store = FakeStore()

    async with store.lease_run([old_ts]):
        held = await maint.prune_manifests(settings, store)

    assert held == [other_ts]
    assert manifestmod.path_for(settings, old_ts).exists()

    assert await maint.prune_manifests(settings, store) == [old_ts]
    assert not manifestmod.path_for(settings, old_ts).exists()


async def test_prune_manifests_never_breaks_the_chain(tmp_path, graph_keeps_nothing):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30)
    old_ts = int((NOW - timedelta(days=400)).timestamp() * 1000)
    _manifest(settings, old_ts)
    old_record = manifestmod.read(settings, old_ts)
    old_sha, _ = manifestmod.file_facts(manifestmod.path_for(settings, old_ts))

    # a recent (within-period) manifest whose own `previous` link names old_ts
    recent_ts = int((NOW - timedelta(days=5)).timestamp() * 1000)
    recent_record = manifestmod.SnapshotManifest(
        snapshot_key=recent_ts,
        kind="full",
        opened=manifestmod.iso(recent_ts),
        published=manifestmod.now_iso(),
        previous=manifestmod.PreviousLink(
            snapshot_key=old_ts, sha256=old_sha, chain_index=old_record.chain_index + 1
        ),
    )
    manifestmod.write(settings, recent_record)

    victims = await maint.prune_manifests(settings, FakeStore())

    assert victims == []
    assert manifestmod.path_for(settings, old_ts).exists()
    assert manifestmod.path_for(settings, recent_ts).exists()


async def test_prune_manifests_keeps_the_manifest_of_a_run_the_graph_keeps(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30)
    old_ts = int((NOW - timedelta(days=400)).timestamp() * 1000)
    older_ts = int((NOW - timedelta(days=500)).timestamp() * 1000)
    _manifest(settings, older_ts)
    _manifest(settings, old_ts)
    _manifest(settings, int(NOW.timestamp() * 1000))
    seen = []

    def retained_runs(session, keep):
        seen.append(keep)
        return [old_ts]

    monkeypatch.setattr(maint, "_session", _fake_session)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", retained_runs)

    victims = await maint.prune_manifests(settings, FakeStore())

    assert victims == [older_ts]
    assert manifestmod.path_for(settings, old_ts).exists()
    assert seen == [maint.cyclemod.Keep(settings.cycle_keep_runs, settings.cycle_keep_device_runs)]


async def test_prune_manifests_is_skipped_rather_than_queued_behind_a_running_cycle(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30)
    store = FakeStore()
    async with store.cycle_lock():  # a collection in flight
        victims = await maint.prune_manifests(settings, store)
    assert victims is None


async def test_prune_manifests_body_reports_nothing_to_prune(tmp_path):
    ctx = maint.Context(
        store=FakeStore(),
        settings=Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=30),
    )
    detail = await maint._prune_manifests_body(ctx, None)
    assert "nothing to prune" in detail


# --- build_device_run job body ------------------------------------------------------


async def test_the_build_device_run_body_reports_the_run_and_the_shed_case(monkeypatch):
    ctx = maint.Context(store=FakeStore(), settings=Settings(_env_file=None))

    async def held(store, settings, source, triggered_by=None):
        assert source == maint.runs_exec.DEVICE_RUN
        return None

    monkeypatch.setattr(maint.runs_exec, "run_blocking", held)
    assert "skipped" in await maint._build_device_run_body(ctx, None)

    async def done(store, settings, source, triggered_by=None):
        from hst.app.store import Run

        detail = "device run 4200: 3 nodes, 5 rels · nxos/h1"
        return Run(9, maint.runs_exec.DEVICE_RUN, "ok", NOW, NOW, detail)

    monkeypatch.setattr(maint.runs_exec, "run_blocking", done)
    detail = await maint._build_device_run_body(ctx, None)
    assert detail.startswith("run 9 ok")
    assert "device run 4200" in detail


# --- AI retention bodies ------------------------------------------------------------------

AI_BODIES = (
    maint.PURGE_AI_CONVERSATIONS,
    maint.COMPACT_AI_STEPS,
    maint.PURGE_AI_EPHEMERAL,
    maint.PURGE_AI_EVENTS,
)


def test_the_ai_bodies_are_registered_and_scheduled_hourly_under_a_guard():
    """`hst worker` and the embedded executor both run what BODIES names."""
    assert set(AI_BODIES) <= set(maint.BODIES)
    for kind in AI_BODIES:
        schedule = next(s for s in sched_mod.SYSTEM_SCHEDULES if s.kind == kind)
        assert schedule.interval == sched_mod.HOURLY
        assert schedule.guard is not sched_mod.always


@pytest.mark.parametrize(
    ("setting", "skipped"),
    [
        ("ai_conversation_retention_days", {maint.PURGE_AI_CONVERSATIONS, maint.PURGE_AI_EPHEMERAL}),
        ("ai_step_result_days", {maint.COMPACT_AI_STEPS}),
        ("ai_event_retention_days", {maint.PURGE_AI_EVENTS}),
    ],
)
async def test_an_ai_limit_of_zero_queues_no_job(setting, skipped):
    store = FakeStore()
    clock = Clock()
    schedules = tuple(replace(s, interval=100.0) for s in sched_mod.SYSTEM_SCHEDULES)
    scheduler = _scheduler(store, schedules, clock, **{setting: 0})
    scheduler.arm()

    clock.advance(200)
    queued = set(await scheduler.tick())
    assert not skipped & queued
    assert set(AI_BODIES) - skipped <= queued


async def _ai_turn(store, at, *, ephemeral=False):
    """One conversation with a claimed assistant turn, last active at `at`."""
    user = await store.create_user(f"u{len(store.ai_conversations)}", "h", "operator")
    conversation = await store.create_conversation(user.id, "drawer", at, ephemeral=ephemeral)
    reply = await store.start_turn(user.id, conversation.id, "q", None, at, per_user_cap=2, global_cap=16)
    assert await store.claim_turn(reply.id, "proc-a", 60, at)
    return user, reply


def _ai_event(at):
    return AiEvent(at=at, origin="web", event="tool.call", outcome="ok")


@pytest.mark.parametrize("kind", AI_BODIES)
async def test_an_ai_body_at_zero_keeps_everything(kind):
    store = FakeStore()
    old = datetime.now(UTC) - timedelta(days=400)
    user, reply = await _ai_turn(store, old, ephemeral=True)
    await store.append_step(reply.id, "trace_path", 1, {}, False, "result", old, 5)
    await store.record_ai_event(_ai_event(old))
    settings = Settings(
        _env_file=None, ai_conversation_retention_days=0, ai_step_result_days=0, ai_event_retention_days=0
    )

    detail = await maint.BODIES[kind](maint.Context(store=store, settings=settings), None)

    assert detail.startswith("retention is 0")
    conversation = await store.get_conversation(user.id, reply.conversation_id)
    assert conversation.steps[0].result == "result"
    assert len(store.ai_events) == 1


async def test_compaction_nulls_old_results_and_keeps_digests_and_summaries():
    store = FakeStore()
    now = datetime.now(UTC)
    user, reply = await _ai_turn(store, now)
    old = await store.append_step(
        reply.id,
        "trace_path",
        1,
        {},
        False,
        "old result",
        now - timedelta(days=15),
        5,
        result_summary="2 paths",
    )
    new = await store.append_step(reply.id, "trace_path", 1, {}, False, "new result", now, 5)
    ctx = maint.Context(store=store, settings=Settings(_env_file=None, ai_step_result_days=14))

    assert await maint.BODIES[maint.COMPACT_AI_STEPS](ctx, None) == (
        "compacted 1 AI tool result(s) older than 14 day(s)"
    )

    steps = {s.id: s for s in (await store.get_conversation(user.id, reply.conversation_id)).steps}
    assert steps[old.id].result is None
    assert steps[old.id].compacted_at is not None
    assert (steps[old.id].result_sha256, steps[old.id].result_chars, steps[old.id].result_summary) == (
        old.result_sha256,
        10,
        "2 paths",
    )
    assert (steps[new.id].result, steps[new.id].compacted_at) == ("new result", None)


async def test_conversations_purge_by_their_limit_and_ephemeral_ones_after_a_day():
    store = FakeStore()
    now = datetime.now(UTC)
    stale_user, stale = await _ai_turn(store, now - timedelta(days=91))
    kept_user, kept = await _ai_turn(store, now - timedelta(days=89))
    shim_user, shim = await _ai_turn(store, now - timedelta(hours=25), ephemeral=True)
    fresh_user, fresh = await _ai_turn(store, now - timedelta(hours=23), ephemeral=True)
    ctx = maint.Context(store=store, settings=Settings(_env_file=None, ai_conversation_retention_days=90))

    assert await maint.BODIES[maint.PURGE_AI_EPHEMERAL](ctx, None) == (
        "deleted 1 ephemeral AI conversation(s) older than 24 h"
    )
    assert await maint.BODIES[maint.PURGE_AI_CONVERSATIONS](ctx, None) == (
        "deleted 1 AI conversation(s) with no message in 90 day(s)"
    )
    present = [
        await store.get_conversation(user.id, reply.conversation_id) is not None
        for user, reply in ((stale_user, stale), (kept_user, kept), (shim_user, shim), (fresh_user, fresh))
    ]
    assert present == [False, True, False, True]


async def test_ai_events_purge_by_their_limit():
    store = FakeStore()
    now = datetime.now(UTC)
    for age in (181, 179):
        await store.record_ai_event(_ai_event(now - timedelta(days=age)))
    ctx = maint.Context(store=store, settings=Settings(_env_file=None, ai_event_retention_days=180))

    assert (
        await maint.BODIES[maint.PURGE_AI_EVENTS](ctx, None) == "deleted 1 AI event(s) older than 180 day(s)"
    )
    assert [e.at for e in store.ai_events] == [now - timedelta(days=179)]
