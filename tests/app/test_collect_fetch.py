"""The per-device job pipeline (`runs_exec.run_device_fetch` and the
`collect.fetch` body): fetch over the right lane, skip on an unchanged hash,
park the payload otherwise, record `device_status`, pin on first contact, and
never raise for a device failure."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from tests.app.fakes import FakeStore

from hst import collectors as coll
from hst.app import runs_exec
from hst.app.store import DeviceSpec, Job
from hst.core import Settings
from hst.worker import collect as collect_worker
from hst.worker.maintenance import Context

PAYLOAD = {"config": "x", "uptime": 1}


class FakeCollector:
    """Records which fetch lane ran; config carries the transport field."""

    VOLATILE_RAW_KEYS = ("uptime",)

    def __init__(self, transport="asyncssh", payload=PAYLOAD, boom: Exception | None = None):
        self.config = SimpleNamespace(transport=transport)
        self.payload = payload
        self.boom = boom
        self.lanes: list[str] = []
        self.observed_host_key = "ssh-ed25519 OBSERVED"
        self.observed_jump_key = ""

    async def afetch(self):
        self.lanes.append("loop")
        if self.boom:
            raise self.boom
        return self.payload

    def fetch(self):
        self.lanes.append("thread")
        if self.boom:
            raise self.boom
        return self.payload


@pytest.fixture
def rig(monkeypatch, tmp_path):
    """A FakeStore with one fleet source, plus the pipeline's seams patched:
    secrets resolve to nothing, collector builds are recorded, and the raw
    store write is a recorder returning a plausible path."""
    store = FakeStore()
    # the raw store the parked-payload check reads is the test's own
    settings = Settings(hst_data_dir=tmp_path)
    parked: list[tuple] = []
    fetch_ts: list[int | None] = []
    built = {"collector": FakeCollector()}

    monkeypatch.setattr(runs_exec, "crypto", SimpleNamespace(dek=lambda s: b""))
    monkeypatch.setattr(runs_exec, "FernetResolver", lambda key: SimpleNamespace(resolve=lambda row: {}))
    monkeypatch.setattr(
        runs_exec.sources_glue, "build_device_collector", lambda row, d, s, **kw: built["collector"]
    )
    monkeypatch.setattr(runs_exec.sources_glue, "build_collector", lambda row, s, **kw: built["collector"])

    def park(collector, raw, *, source_name=None, fetch_ts_ms=None, **kw):
        parked.append((source_name, raw))
        fetch_ts.append(fetch_ts_ms)
        return tmp_path / "1780000000000-abcd1234.json.gz.enc"

    monkeypatch.setattr(runs_exec.coll, "park", park)
    return SimpleNamespace(store=store, settings=settings, parked=parked, built=built, fetch_ts=fetch_ts)


async def _fleet_source(store, *, hosts=("r1",), enabled=True):
    await store.create_source("grp", "vyos", {"interval_s": 60}, {}, enabled=enabled)
    await store.replace_devices("grp", [DeviceSpec(host=h) for h in hosts])


async def test_a_changed_device_parks_its_payload_and_records_no_basis(rig):
    """The skip basis (raw hash, observation hash, `last_full_at`) describes
    what the graph holds, and the graph holds the payload only once a device
    run loads it: the park records none, and clears the raw hash, so
    no lane skips against the old one until that run records the new one."""
    await _fleet_source(rig.store)
    before = datetime.now(UTC) - timedelta(seconds=30)
    await rig.store.upsert_device_status(
        "grp", "r1", now=before, ok=True, raw_sha="OLD", obs_sha="OLDOBS", full=True
    )
    detail = await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    assert rig.built["collector"].lanes == ["loop"]  # asyncssh fetches on the loop
    assert len(rig.parked) == 1 and rig.parked[0] == ("grp", PAYLOAD)
    st = (await rig.store.list_device_status("grp"))[0]
    assert (st.last_raw_sha, st.last_obs_sha, st.last_full_at) == ("", "OLDOBS", before)
    # the attempt itself is recorded; the load happens in the next device run
    assert st.last_attempt_at > before and st.last_success_at > before and st.consecutive_failures == 0
    assert st.load_ms is None
    assert "grp/r1" in detail and "parked" in detail


async def test_first_contact_pins_the_device_host_key(rig):
    await _fleet_source(rig.store)
    await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    device = (await rig.store.list_devices("grp"))[0]
    assert device.host_key == "ssh-ed25519 OBSERVED"


async def test_an_unchanged_device_is_not_parked(rig):
    await _fleet_source(rig.store)
    sha = coll.raw_sha(rig.built["collector"], PAYLOAD)
    await rig.store.upsert_device_status("grp", "r1", now=datetime.now(UTC), ok=True, raw_sha=sha, full=True)
    detail = await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    assert rig.parked == []
    assert "unchanged" in detail
    st = (await rig.store.list_device_status("grp"))[0]
    assert st.last_raw_sha == sha


async def test_a_parked_payload_is_named_by_its_fetch_start(rig):
    """The device run reads the payload's run id back as when it was
    observed, so the id is the fetch's start, not the later park time."""
    await _fleet_source(rig.store)
    before = int(time.time() * 1000)
    await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    (started,) = rig.fetch_ts
    assert started is not None and before <= started <= int(time.time() * 1000)


async def test_an_unchanged_device_records_its_fetch_window(rig, monkeypatch):
    """A fetch that found the device unchanged observed it; its outcome
    says when."""
    recorded: list[runs_exec.DeviceOutcome] = []
    real = runs_exec._record_outcomes

    async def record(store, outcomes, secrets=None):
        recorded.extend(outcomes)
        await real(store, outcomes, secrets)

    monkeypatch.setattr(runs_exec, "_record_outcomes", record)
    await _fleet_source(rig.store)
    sha = coll.raw_sha(rig.built["collector"], PAYLOAD)
    await rig.store.upsert_device_status("grp", "r1", now=datetime.now(UTC), ok=True, raw_sha=sha, full=True)
    before = int(time.time() * 1000)
    await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    (outcome,) = recorded
    assert outcome.skipped
    assert outcome.fetch_started_ms is not None and outcome.fetch_finished_ms is not None
    assert before <= outcome.fetch_started_ms <= outcome.fetch_finished_ms <= int(time.time() * 1000)


async def test_a_stale_full_forces_the_park_despite_a_matching_hash(rig):
    await _fleet_source(rig.store)
    sha = coll.raw_sha(rig.built["collector"], PAYLOAD)
    old = datetime.now(UTC) - timedelta(seconds=rig.settings.collect_full_interval_s + 1)
    await rig.store.upsert_device_status("grp", "r1", now=old, ok=True, raw_sha=sha, full=True)
    await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    assert len(rig.parked) == 1


async def test_a_fetch_failure_is_recorded_not_raised(rig):
    await _fleet_source(rig.store)
    rig.built["collector"] = FakeCollector(boom=RuntimeError("wedged"))
    detail = await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    assert detail.startswith("failed: grp/r1")
    assert rig.parked == []
    st = (await rig.store.list_device_status("grp"))[0]
    assert st.consecutive_failures == 1 and "wedged" in st.last_error


async def test_a_paramiko_device_fetches_on_the_thread_lane(rig):
    await _fleet_source(rig.store)
    rig.built["collector"] = FakeCollector(transport="paramiko")
    await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    assert rig.built["collector"].lanes == ["thread"]
    assert len(rig.parked) == 1


async def test_a_gone_or_disabled_source_is_skipped(rig):
    assert (await runs_exec.run_device_fetch(rig.store, rig.settings, "ghost", "r1")).startswith("skipped")
    await _fleet_source(rig.store, enabled=False)
    assert (await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")).startswith("skipped")
    assert rig.parked == []


async def test_a_disabled_device_is_skipped(rig):
    await rig.store.create_source("grp", "vyos", {"interval_s": 60}, {})
    await rig.store.replace_devices("grp", [DeviceSpec(host="r1", enabled=False)])
    detail = await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    assert detail == "skipped: grp/r1 is disabled"
    assert rig.parked == []


async def test_an_unknown_host_is_skipped_without_a_status_row(rig):
    await _fleet_source(rig.store)
    detail = await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r9")
    assert detail.startswith("skipped")
    assert len(await rig.store.list_device_status("grp")) == 0


async def test_the_implicit_single_host_source_builds_from_its_config(rig):
    await rig.store.create_source("ctrl", "apic", {"host": "apic1", "interval_s": 60}, {})
    detail = await runs_exec.run_device_fetch(rig.store, rig.settings, "ctrl", "apic1")
    assert len(rig.parked) == 1
    assert "parked" in detail
    assert (await rig.store.list_device_status("ctrl"))[0].host == "apic1"


async def test_a_raw_store_failure_is_recorded_not_raised(rig, monkeypatch):
    """A fetch that cannot be stored is a failed attempt, not a lost one: the
    device_status row carries the reason and the scheduler retries on backoff."""
    await _fleet_source(rig.store)

    def boom(collector, raw, *, source_name=None, fetch_ts_ms=None, **kw):
        raise OSError("read-only file system")

    monkeypatch.setattr(runs_exec.coll, "park", boom)
    detail = await runs_exec.run_device_fetch(rig.store, rig.settings, "grp", "r1")
    assert detail.startswith("failed: grp/r1") and "read-only file system" in detail
    st = (await rig.store.list_device_status("grp"))[0]
    assert st.consecutive_failures == 1


async def test_the_job_body_delegates_and_guards_an_empty_source(monkeypatch):
    calls = []

    async def record(store, settings, source, host):
        calls.append((source, host))
        return "done"

    monkeypatch.setattr(runs_exec, "run_device_fetch", record)
    ctx = Context(store=FakeStore(), settings=Settings())
    job = Job(
        id=1,
        kind=collect_worker.FETCH_KIND,
        source="grp",
        device="r1",
        state="running",
        priority=0,
        attempt=1,
        max_attempts=4,
        not_before=datetime.now(UTC),
        lease_expires_at=None,
        claimed_by=None,
        enqueued_at=datetime.now(UTC),
        started_at=None,
        finished_at=None,
        detail="",
        triggered_by="scheduler",
    )
    assert await collect_worker.collect_fetch_body(ctx, job) == "done"
    assert calls == [("grp", "r1")]
    empty = Job(
        id=2,
        kind=collect_worker.FETCH_KIND,
        source=None,
        device=None,
        state="running",
        priority=0,
        attempt=1,
        max_attempts=4,
        not_before=datetime.now(UTC),
        lease_expires_at=None,
        claimed_by=None,
        enqueued_at=datetime.now(UTC),
        started_at=None,
        finished_at=None,
        detail="",
        triggered_by="scheduler",
    )
    assert (await collect_worker.collect_fetch_body(ctx, empty)).startswith("skipped")
