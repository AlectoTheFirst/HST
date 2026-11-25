"""The periodic maintenance sweep: sessions, auth state, audit rows, graph history."""

from __future__ import annotations

import asyncio
import contextlib
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

import pytest
from tests.app.fakes import FakeStore

from hst.app import retention
from hst.app.main import create_app
from hst.core import Settings
from hst.core.cycle import Keep
from hst.worker import maintenance as maint
from hst.worker import queue
from hst.worker import scheduler as sched_mod
from hst.worker.executor import Executor

# Short enough that a schedule comes due immediately, long enough that a job
# body has room to run before the next turn is queued.
FAST_INTERVAL_S = 0.02


def _app(store, **overrides):
    return create_app(settings=Settings(_env_file=None, **overrides), store=store)


@dataclass
class PruneSpy:
    """Stands in for a Neo4j session plus `cycle.prune`, recording the keep count
    each sweep asked for."""

    keeps: list[Keep] = field(default_factory=list)
    victims: list[int] = field(default_factory=list)
    error: Exception | None = None

    def prune(self, session, keep, protected=frozenset(), max_victims=None, orphans=True):
        self.keeps.append(keep)
        if self.error is not None:
            raise self.error
        return list(self.victims)


@pytest.fixture(autouse=True)
def prune_spy(monkeypatch):
    spy = PruneSpy()

    @contextlib.contextmanager
    def fake_session(settings):
        yield object()

    monkeypatch.setattr(maint, "_session", fake_session)
    monkeypatch.setattr(maint.cyclemod, "prune", spy.prune)
    monkeypatch.setattr(maint.cyclemod, "retained_runs", lambda session, keep: [])
    # A failed job's next attempt is a minute out in production. These tests
    # assert that a retry happens at all, not when.
    monkeypatch.setattr(queue, "BACKOFF_BASE_S", 0.01)
    monkeypatch.setattr(queue, "BACKOFF_CAP_S", 0.01)
    return spy


@asynccontextmanager
async def sweeping(store, **overrides):
    """Run the real scheduler and executor against `store`, at test speed."""
    settings = Settings(_env_file=None, **overrides)
    schedules = tuple(replace(s, interval=FAST_INTERVAL_S) for s in sched_mod.SYSTEM_SCHEDULES)
    scheduler = sched_mod.Scheduler(store, settings, schedules=schedules, tick_s=0.005, standby_s=0.005)
    executor = Executor(store, settings, poll_s=0.005)
    loop = asyncio.get_running_loop()
    tasks = [loop.create_task(scheduler.run()), loop.create_task(executor.run())]
    try:
        yield scheduler, executor
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task


async def _wait_for(predicate):
    """Poll until the store shows the effect."""
    try:
        async with asyncio.timeout(2.0):
            while not predicate():  # noqa: ASYNC110 - no event exists to wait on
                await asyncio.sleep(0.005)
    except TimeoutError:
        return False
    return True


async def test_expired_sessions_are_purged_while_the_app_runs():
    store = FakeStore()
    now = datetime.now(UTC)
    await store.create_session("dead", 1, now - timedelta(hours=1))
    await store.create_session("live", 1, now + timedelta(hours=1))

    async with sweeping(store):
        assert await _wait_for(lambda: "dead" not in store.sessions), "expired session never purged"
        assert "live" in store.sessions


async def test_the_lifespan_starts_the_sweep_and_shutdown_cancels_it():
    store = FakeStore()
    app = _app(store)
    async with app.router.lifespan_context(app):
        assert len(app.state.worker_tasks) == 2
        assert not any(t.done() for t in app.state.worker_tasks)
    assert all(t.done() for t in app.state.worker_tasks)


async def test_the_embedded_scheduler_is_entered_again_after_an_error(monkeypatch):
    from hst.worker import runtime

    entered = asyncio.Event()

    class Flaky:
        runs = 0

        async def run(self):
            self.runs += 1
            if self.runs == 1:
                raise ConnectionError("postgres went away")
            entered.set()
            await asyncio.Event().wait()

    class Idle:
        async def run(self):
            await asyncio.Event().wait()

    flaky = Flaky()
    monkeypatch.setattr(runtime, "build_loops", lambda store, settings: (flaky, Idle()))
    keep = runtime.keep_scheduling
    monkeypatch.setattr(runtime, "keep_scheduling", lambda scheduler: keep(scheduler, restart_s=0.0))
    app = _app(FakeStore())
    async with app.router.lifespan_context(app):
        await asyncio.wait_for(entered.wait(), 5)
        assert not app.state.worker_tasks[0].done()
    assert flaky.runs == 2


async def test_shutdown_disposes_the_store_when_a_worker_task_ended_with_an_exception(monkeypatch, caplog):
    import logging

    from hst.worker import runtime

    disposed: list[bool] = []

    class Store(FakeStore):
        async def dispose(self) -> None:
            disposed.append(True)

    class Idle:
        async def run(self):
            await asyncio.Event().wait()

    class Broken:
        async def run(self):
            raise RuntimeError("no claim connection")

    async def open_store(settings):
        return Store()

    monkeypatch.setattr(runtime, "open_store", open_store)
    monkeypatch.setattr(runtime, "build_loops", lambda store, settings: (Idle(), Broken()))
    app = create_app(settings=Settings(_env_file=None))
    with caplog.at_level(logging.ERROR, logger="hst.app.main"):
        async with app.router.lifespan_context(app):
            await _wait_for(lambda: app.state.worker_tasks[1].done())
    assert disposed == [True]
    assert "the executor task ended: RuntimeError: no claim connection" in caplog.text


async def test_the_sweep_does_not_start_when_the_scheduler_is_disabled():
    """A process meant to serve requests only starts neither loop."""
    store = FakeStore()
    app = _app(store, scheduler_enabled=False)
    async with app.router.lifespan_context(app):
        assert app.state.worker_tasks == []
        assert app.state.scheduler is None


async def test_expired_auth_state_is_purged_alongside_sessions():
    store = FakeStore()
    now = datetime.now(UTC)
    await store.create_auth_state("dead", 1, "oidc", {}, now - timedelta(minutes=1))
    await store.create_auth_state("live", 1, "oidc", {}, now + timedelta(minutes=5))

    async with sweeping(store):
        assert await _wait_for(lambda: "dead" not in store.auth_state), "expired auth_state never purged"
        assert "live" in store.auth_state


async def test_idle_sessions_are_purged_alongside_expired_ones():
    store = FakeStore()
    now = datetime.now(UTC)
    far = now + timedelta(days=6)  # both are far from their absolute expiry
    await store.create_session("idle", 1, far, now - timedelta(hours=9))
    await store.create_session("active", 1, far, now - timedelta(minutes=5))

    async with sweeping(store):
        assert await _wait_for(lambda: "idle" not in store.sessions), "idle session never purged"
        assert "active" in store.sessions


async def test_old_audit_rows_are_purged_on_the_same_sweep():
    store = FakeStore()
    now = datetime.now(UTC)
    for age, name in ((100, "ancient"), (10, "recent")):
        await store.record_login_event(
            username=name,
            user_id=None,
            provider="local",
            outcome="bad_credentials",
            source="",
            at=now - timedelta(days=age),
        )
    for age, query in ((200, "MATCH (old) RETURN old"), (10, "MATCH (new) RETURN new")):
        await store.record_cypher_event(
            user_id=1, query=query, outcome="ok", row_count=1, byte_count=1, at=now - timedelta(days=age)
        )

    async with sweeping(store):
        assert await _wait_for(lambda: len(store.login_events) == 1), "old login event never purged"
        assert await _wait_for(lambda: len(store.cypher_events) == 1), "old cypher event never purged"
    assert store.login_events[0].username == "recent"
    assert "new" in store.cypher_events[0].query


async def test_retention_of_zero_keeps_everything():
    store = FakeStore()
    old = datetime.now(UTC) - timedelta(days=5000)
    await store.record_login_event(
        username="ancient", user_id=None, provider="local", outcome="ok", source="", at=old
    )
    await store.record_cypher_event(
        user_id=1, query="MATCH (n) RETURN n", outcome="ok", row_count=0, byte_count=0, at=old
    )
    # something else on the same sweep, to know the mechanism ran at all
    await store.create_session("dead", 1, datetime.now(UTC) - timedelta(hours=1))

    async with sweeping(store, login_event_retention_days=0, cypher_event_retention_days=0):
        assert await _wait_for(lambda: "dead" not in store.sessions), "the sweep never ran"
        assert len(store.login_events) == 1
        assert len(store.cypher_events) == 1
        assert not any(
            j.kind in (maint.PURGE_LOGIN_EVENTS, maint.PURGE_CYPHER_EVENTS) for j in store.jobs.values()
        )


async def test_a_failing_purge_retries():
    class FlakyStore(FakeStore):
        def __init__(self):
            super().__init__()
            self.failures_left = 1

        async def purge_expired_sessions(self, now, idle_after=None):
            if self.failures_left:
                self.failures_left -= 1
                raise RuntimeError("connection reset")
            return await super().purge_expired_sessions(now, idle_after)

    store = FlakyStore()
    await store.create_session("dead", 1, datetime.now(UTC) - timedelta(hours=1))

    async with sweeping(store):
        assert await _wait_for(lambda: "dead" not in store.sessions), "sweep died on the first error"
    assert any(j.kind == maint.PURGE_SESSIONS and j.attempt >= 2 for j in store.jobs.values()), (
        "the failed sweep was never retried"
    )


async def test_the_sweep_prunes_the_graph_to_the_configured_keep_count(prune_spy):
    prune_spy.victims = [1710000000000, 1720000000000]
    store = FakeStore()

    async with sweeping(store, cycle_keep_runs=12):
        assert await _wait_for(lambda: prune_spy.keeps), "the graph was never pruned"
    assert prune_spy.keeps[0].cycles == 12


async def test_the_prune_follows_the_stored_keep_count_over_the_environment(prune_spy):
    store = FakeStore()
    await store.put_setting(retention.SETTINGS_KEY, {"cycle_keep_runs": 4}, b"")

    async with sweeping(store, cycle_keep_runs=30):
        assert await _wait_for(lambda: prune_spy.keeps), "the graph was never pruned"
    assert prune_spy.keeps[0].cycles == 4


async def test_the_prune_holds_the_cycle_lock_while_it_runs(monkeypatch, prune_spy):
    store = FakeStore()
    held: list[bool] = []

    def prune(session, keep, protected=frozenset(), max_victims=None, orphans=True):
        held.append(store._cycle_lock.locked())
        return []

    monkeypatch.setattr(maint.cyclemod, "prune", prune)

    async with sweeping(store):
        assert await _wait_for(lambda: held), "the graph was never pruned"
    assert held[0] is True


async def test_the_prune_is_skipped_while_a_cycle_runs(prune_spy):
    store = FakeStore()
    await store.create_session("dead", 1, datetime.now(UTC) - timedelta(hours=1))

    # the cycle lock stands in for a collection in flight
    async with store.cycle_lock(), sweeping(store):
        assert await _wait_for(lambda: "dead" not in store.sessions), "the sweep never ran"
        assert prune_spy.keeps == []
    assert any(
        j.kind == maint.PRUNE_GRAPH and "cycle lock" in (j.detail or "") for j in store.jobs.values()
    ), "the skipped turn left no record"


async def test_a_failing_prune_does_not_end_the_sweep(prune_spy):
    prune_spy.error = RuntimeError("twin unreachable")
    store = FakeStore()
    await store.create_session("dead", 1, datetime.now(UTC) - timedelta(hours=1))

    async with sweeping(store):
        assert await _wait_for(lambda: len(prune_spy.keeps) >= 2), "the sweep stopped at the first error"
        assert await _wait_for(lambda: "dead" not in store.sessions)
    assert any(
        j.kind == maint.PRUNE_GRAPH and "twin unreachable" in (j.detail or "") for j in store.jobs.values()
    ), "the prune failure was never recorded"
