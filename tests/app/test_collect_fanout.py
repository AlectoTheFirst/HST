"""The scheduler's per-device fan-out (`Scheduler.fanout_collect`): one
`collect.fetch` job per due enabled device of every group whose `interval_s`
is set, per-device backoff, and high-water backpressure that sheds jobs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tests.app.fakes import FakeStore

from hst.app.store import DeviceSpec
from hst.core import Settings
from hst.worker.collect import FETCH_KIND
from hst.worker.scheduler import Scheduler

NOW = datetime(2026, 8, 28, 12, 0, 0, tzinfo=UTC)


def _scheduler(store, **settings_kw):
    # Arming at construction puts the due time of the maintenance.build_device_run
    # schedule past every clock offset this file uses.
    scheduler = Scheduler(store, Settings(**settings_kw), schedules=(), collect_fanout=True)
    scheduler.arm(NOW)
    return scheduler


def _fetch_jobs(store):
    return [j for j in store.jobs.values() if j.kind == FETCH_KIND]


async def test_every_enabled_device_of_a_cadenced_group_gets_a_job():
    store = FakeStore()
    await store.create_source("grp", "vyos", {"interval_s": 60}, {})
    await store.replace_devices(
        "grp",
        [DeviceSpec(host="r1"), DeviceSpec(host="r2"), DeviceSpec(host="r3", enabled=False)],
    )
    queued = await _scheduler(store).tick(NOW)
    jobs = _fetch_jobs(store)
    assert sorted(j.device for j in jobs) == ["r1", "r2"]
    assert all(j.source == "grp" for j in jobs)
    assert sorted(queued) == [f"{FETCH_KIND}:grp/r1", f"{FETCH_KIND}:grp/r2"]


async def test_a_group_without_a_cadence_queues_nothing():
    store = FakeStore()
    await store.create_source("grp", "vyos", {}, {})
    await store.replace_devices("grp", [DeviceSpec(host="r1")])
    await store.create_source("off", "vyos", {"interval_s": 60}, {}, enabled=False)
    assert await _scheduler(store).tick(NOW) == []


async def test_the_implicit_single_host_source_is_one_device():
    store = FakeStore()
    await store.create_source("ctrl", "apic", {"host": "apic1", "interval_s": 300}, {})
    await _scheduler(store).tick(NOW)
    jobs = _fetch_jobs(store)
    assert len(jobs) == 1 and jobs[0].source == "ctrl" and jobs[0].device == "apic1"


async def test_a_wholly_disabled_fleet_does_not_fall_back_to_the_config_host():
    store = FakeStore()
    await store.create_source("grp", "vyos", {"host": "spare", "interval_s": 60}, {})
    await store.replace_devices("grp", [DeviceSpec(host="r1", enabled=False)])
    await _scheduler(store).tick(NOW)
    assert _fetch_jobs(store) == []


async def test_a_recently_attempted_device_is_not_due_until_its_interval_passes():
    store = FakeStore()
    await store.create_source("grp", "vyos", {"interval_s": 60}, {})
    await store.replace_devices("grp", [DeviceSpec(host="r1")])
    await store.upsert_device_status("grp", "r1", now=NOW - timedelta(seconds=30), ok=True)
    sched = _scheduler(store)
    await sched.tick(NOW)
    assert _fetch_jobs(store) == []
    await sched.tick(NOW + timedelta(seconds=31))
    assert len(_fetch_jobs(store)) == 1


async def test_a_failing_device_backs_off_alone_and_its_mates_keep_cadence():
    store = FakeStore()
    await store.create_source("grp", "vyos", {"interval_s": 60}, {})
    await store.replace_devices("grp", [DeviceSpec(host="flappy"), DeviceSpec(host="steady")])
    last = NOW - timedelta(seconds=90)
    await store.upsert_device_status("grp", "steady", now=last, ok=True)
    for _ in range(2):  # two consecutive failures: due after 60 * 2**2 = 240 s
        await store.upsert_device_status("grp", "flappy", now=last, ok=False, error="down")
    await _scheduler(store).tick(NOW)
    assert [j.device for j in _fetch_jobs(store)] == ["steady"]
    await _scheduler(store).tick(last + timedelta(seconds=241))
    assert sorted(j.device for j in _fetch_jobs(store)) == ["flappy", "steady"]


async def test_the_backoff_is_capped():
    store = FakeStore()
    await store.create_source("grp", "vyos", {"interval_s": 60}, {})
    await store.replace_devices("grp", [DeviceSpec(host="r1")])
    last = NOW - timedelta(seconds=901)
    for _ in range(10):  # uncapped this would be 60 * 2**10 s, far past the cap
        await store.upsert_device_status("grp", "r1", now=last, ok=False, error="down")
    await _scheduler(store, collect_backoff_cap_s=900).tick(NOW)
    assert len(_fetch_jobs(store)) == 1


async def test_high_water_sheds_the_whole_tick():
    store = FakeStore()
    await store.create_source("grp", "vyos", {"interval_s": 60}, {})
    await store.replace_devices("grp", [DeviceSpec(host="r1")])
    sched = _scheduler(store, collect_queue_high_water=2)
    await store.enqueue_job(
        "x.a", source=None, device=None, priority=0, not_before=NOW, max_attempts=1, triggered_by="t", now=NOW
    )
    await store.enqueue_job(
        "x.b", source=None, device=None, priority=0, not_before=NOW, max_attempts=1, triggered_by="t", now=NOW
    )
    assert await sched.tick(NOW) == []
    assert _fetch_jobs(store) == []


async def test_the_budget_caps_one_ticks_enqueues_below_high_water():
    store = FakeStore()
    await store.create_source("grp", "vyos", {"interval_s": 60}, {})
    await store.replace_devices("grp", [DeviceSpec(host=f"r{i}") for i in range(5)])
    await _scheduler(store, collect_queue_high_water=3).tick(NOW)
    assert len(_fetch_jobs(store)) == 3  # the other two stay due for the next tick


async def test_a_devices_pending_job_is_not_duplicated():
    store = FakeStore()
    await store.create_source("grp", "vyos", {"interval_s": 60}, {})
    await store.replace_devices("grp", [DeviceSpec(host="r1")])
    sched = _scheduler(store)
    assert len(await sched.tick(NOW)) == 1
    # the pending-jobs index refuses the duplicate
    assert await sched.tick(NOW + timedelta(seconds=5)) == []
    assert len(_fetch_jobs(store)) == 1
