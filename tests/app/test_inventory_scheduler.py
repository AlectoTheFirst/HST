"""Scheduler cadence under resolver v2: the target's resolved profile interval drives the fan-out,
disabled and archived targets never queue, the empty direct source is not
invented as a target, a controller is one job however many devices it reports,
and the dedup key, backoff and queue bound are the legacy ones.
"""

from __future__ import annotations

from datetime import timedelta

from tests.app.test_inventory_collection import (
    NOW,
    VYOS_SECRETS,
    VYOS_SETTINGS,
    activate,
    make_store,
    seed_credential,
    seed_direct_connection,
    seed_profile,
    settings_for,
)

from hst.app.inventory.contracts import TargetKind
from hst.app.store import DeviceSpec
from hst.worker.collect import FETCH_KIND
from hst.worker.scheduler import Scheduler


def _scheduler(store, settings=None, **kw):
    scheduler = Scheduler(store, settings or settings_for(**kw), schedules=(), collect_fanout=True)
    scheduler.arm(NOW)
    return scheduler


def _fetch_jobs(store):
    return sorted((j.source, j.device) for j in store.jobs.values() if j.kind == FETCH_KIND)


async def test_v2_cadence_is_the_resolved_profile_interval_not_the_row_interval():
    store = await make_store()
    settings = settings_for()
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)  # interval 120
    _, targets = await seed_direct_connection(store, settings, hosts=("r1", "r2"), profile=profile)
    no_cadence = await seed_profile(store, "manual", "vyos", {**VYOS_SETTINGS, "interval_s": 0}, cred)
    async with store.inventory().transaction() as tx:
        t = targets["r2"]
        await tx.update_target(t.id, expected_revision=t.revision, now=NOW, profile_id=no_cadence.id)
    queued = await _scheduler(store, settings).tick(NOW)
    assert queued == [f"{FETCH_KIND}:lab/r1"]
    assert _fetch_jobs(store) == [("lab", "r1")]
    # due again only after the profile's 120 s, not the row's 60 s
    await store.upsert_device_status("lab", "r1", now=NOW, ok=True, raw_sha="x", full=True)
    assert await _scheduler(store, settings).tick(NOW + timedelta(seconds=90)) == []
    store.jobs.clear()
    assert await _scheduler(store, settings).tick(NOW + timedelta(seconds=121)) == [f"{FETCH_KIND}:lab/r1"]


async def test_a_disabled_or_archived_inventory_target_is_not_queued():
    store = await make_store()
    settings = settings_for()
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    _, targets = await seed_direct_connection(store, settings, hosts=("r1", "r2", "r3"), profile=profile)
    async with store.inventory().transaction() as tx:
        t2, t3 = targets["r2"], targets["r3"]
        await tx.update_target(t2.id, expected_revision=t2.revision, now=NOW, enabled=False)
        await tx.archive_target(t3.id, expected_revision=t3.revision, now=NOW)
    await _scheduler(store, settings).tick(NOW)
    assert _fetch_jobs(store) == [("lab", "r1")]


async def test_a_connection_without_a_profile_queues_nothing_under_v2():
    store = await make_store()
    settings = settings_for()
    await activate(store)
    await seed_direct_connection(store, settings, hosts=("r1",))  # row interval_s 60, no profile
    assert await _scheduler(store, settings).tick(NOW) == []


async def test_the_empty_direct_source_is_not_invented_as_a_target():
    store = await make_store()
    settings = settings_for()
    await store.create_source("empty", "vyos", {"interval_s": 60}, b"")
    assert await _scheduler(store, settings).tick(NOW) == []
    await activate(store)
    assert await _scheduler(store, settings).tick(NOW) == []
    assert _fetch_jobs(store) == []


async def test_a_controller_is_one_job_however_many_devices_it_reports():
    store = await make_store()
    settings = settings_for()
    await activate(store)
    cred = await seed_credential(store, settings, {"auth.key": "k"})
    profile = await seed_profile(
        store, "vco-p", "velocloud", {"interval_s": 300, "auth": {"method": "api_key"}}, cred
    )
    row = await store.create_source("vco", "velocloud", {"url": "https://vco.example"}, b"")
    async with store.inventory().transaction() as tx:
        inventory = await tx.get_source_inventory(row.id)
        await tx.update_source_inventory(
            row.id, expected_revision=inventory.inventory_revision, now=NOW, default_profile_id=profile.id
        )
        await tx.create_target(
            source_id=row.id, source_key="vco", host="", kind=TargetKind.CONTROLLER.value, now=NOW
        )
    await store.record_target_devices("vco", "", [f"velocloud:e{i}" for i in range(25)], {})
    queued = await _scheduler(store, settings).tick(NOW)
    assert queued == [f"{FETCH_KIND}:vco"]
    assert _fetch_jobs(store) == [("vco", None)]
    # a second tick sheds against the same pending job: the dedup key is unchanged
    assert await _scheduler(store, settings).tick(NOW) == []


async def test_backoff_and_the_queue_bound_are_unchanged_under_v2():
    store = await make_store()
    settings = settings_for(collect_queue_high_water=1)
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    await seed_direct_connection(store, settings, hosts=("r1", "r2"), profile=profile)
    queued = await _scheduler(store, settings).tick(NOW)
    assert len(queued) == 1, "the high-water mark bounds the fan-out"
    store.jobs.clear()
    # r1 failed twice: due after 120 * 4 seconds, not after 120
    await store.upsert_device_status("lab", "r1", now=NOW, ok=False, error="x")
    await store.upsert_device_status("lab", "r1", now=NOW, ok=False, error="x")
    settings = settings_for(collect_queue_high_water=10)
    assert _fetch_jobs(store) == []
    queued = await _scheduler(store, settings).tick(NOW + timedelta(seconds=200))
    assert queued == [f"{FETCH_KIND}:lab/r2"]
    store.jobs.clear()
    queued = await _scheduler(store, settings).tick(NOW + timedelta(seconds=481))
    assert f"{FETCH_KIND}:lab/r1" in queued


async def test_v1_fan_out_is_untouched_by_an_unactivated_inventory():
    store = await make_store()
    settings = settings_for()
    await store.create_source("grp", "vyos", {"interval_s": 60}, b"")
    await store.replace_devices("grp", [DeviceSpec(host="r1"), DeviceSpec(host="r2", enabled=False)])
    await store.create_source("ctrl", "apic", {"host": "apic1", "interval_s": 300}, b"")
    assert sorted(await _scheduler(store, settings).tick(NOW)) == [
        f"{FETCH_KIND}:ctrl/apic1",
        f"{FETCH_KIND}:grp/r1",
    ]
