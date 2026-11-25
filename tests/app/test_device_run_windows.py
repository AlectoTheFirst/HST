"""The fetch window a device run publishes for each device, and the
`legacy-metadata-missing` gap."""

from __future__ import annotations

import asyncio
import itertools
from types import SimpleNamespace
from typing import Any

import pytest
from tests.app import test_device_run
from tests.app.fakes import FakeStore
from tests.app.test_device_run import NOW, _HostCfg
from tests.app.test_skip_basis_at_load import _Router

from hst import collectors as coll
from hst.app import runs_exec
from hst.app.store import Device, DeviceSpec, Source
from hst.core import Settings, rawstore
from hst.core import manifest as manifestmod

rig = test_device_run.rig  # real settings and raw store, the graph stubbed


@pytest.fixture
def fleet(rig, monkeypatch):
    """Two devices `edge/r1` and `edge/r2` in a FakeStore, the job lane
    building the collector the device run joins with, and a device run that
    publishes under a new key each time, records what it loaded, and returns
    the manifest it wrote."""
    settings, cycle = rig()
    keys = itertools.count(10_000)
    monkeypatch.setattr(cycle, "new_collection_ts", lambda: next(keys))
    store = FakeStore()
    row = Source(1, "edge", "vyos", {}, b"", True, NOW, NOW)
    collectors = {h: _Router(_HostCfg(host=h, source_name="edge"), settings) for h in ("r1", "r2")}
    units = [
        runs_exec.PreparedDevice(Device(1, "edge", h, None, True, "", NOW, NOW), c, None)
        for h, c in collectors.items()
    ]
    prepared = runs_exec.PreparedSource(row, units)
    monkeypatch.setattr(runs_exec, "FernetResolver", lambda key: SimpleNamespace(resolve=lambda row: {}))
    monkeypatch.setattr(
        runs_exec.sources_glue, "build_device_collector", lambda row, d, s, **kw: collectors[d.host]
    )

    async def fetch(host: str) -> str:
        return await runs_exec.run_device_fetch(store, settings, "edge", host)

    async def device_run() -> manifestmod.SnapshotManifest | None:
        prior = {(st.source, st.host): st for st in await store.list_device_status()}
        outcomes: list[runs_exec.DeviceOutcome] = []
        _detail, _ran, key, _ = runs_exec.build_device_run(
            settings, [prepared], outcomes=outcomes, prior=prior
        )
        if key is None:
            return None
        await runs_exec._record_graphs(store, outcomes)  # as `launch` records a published run
        return manifestmod.read(settings, key)

    async def status(host: str) -> Any:
        return next(st for st in await store.list_device_status("edge") if st.host == host)

    async def setup() -> None:
        await store.create_source("edge", "vyos", {}, b"")
        await store.replace_devices("edge", [DeviceSpec(host="r1"), DeviceSpec(host="r2")])

    return SimpleNamespace(
        settings=settings,
        store=store,
        collectors=collectors,
        units={u.device.host: u for u in units},
        fetch=fetch,
        device_run=device_run,
        status=status,
        setup=setup,
    )


async def _store_check(store: Any, host: str, start_ms: int, end_ms: int) -> None:
    """A status row with a basis and a check offered against that basis."""
    await store.upsert_device_status("edge", host, now=NOW, ok=True, raw_sha="RAW", obs_sha="OBS", full=True)
    await store.upsert_device_status(
        "edge",
        host,
        now=NOW,
        ok=True,
        verified_started_at=runs_exec._at_ms(start_ms),
        verified_at=runs_exec._at_ms(end_ms),
        verified_raw_sha="RAW",
        verified_obs_sha="OBS",
    )


def _entry(record: manifestmod.SnapshotManifest | None, host: str) -> manifestmod.DeviceEntry:
    assert record is not None
    return next(d for d in record.devices if d.host == host)


async def _both_loaded(fleet: Any) -> manifestmod.SnapshotManifest | None:
    await fleet.setup()
    await fleet.fetch("r1")
    await fleet.fetch("r2")
    return await fleet.device_run()


# -- the end of a parked payload's fetch -----------------------------------------


async def test_a_parked_payload_publishes_the_whole_window_of_its_fetch(fleet):
    record = await _both_loaded(fleet)

    for host in ("r1", "r2"):
        entry = _entry(record, host)
        assert entry.carried is False
        assert entry.fetch_started_ms is not None and entry.fetch_finished_ms is not None
        assert entry.fetch_started_ms <= entry.fetch_finished_ms
        # the start is the run id the payload was parked under
        assert entry.fetch_ts_ms == entry.fetch_started_ms


async def test_the_park_sidecar_records_the_end_of_the_fetch(fleet, tmp_path):
    await fleet.setup()
    await fleet.fetch("r1")

    (payload,) = rawstore.parked(fleet.settings.raw_dir)
    assert payload.fetch_finished_ms is not None and payload.fetch_finished_ms >= payload.fetch_ts_ms


async def test_a_payload_parked_without_its_end_publishes_no_invented_one(fleet):
    await fleet.setup()
    unit = fleet.units["r1"]
    coll.park(unit.collector, unit.collector.fetch(), source_name="edge", fetch_ts_ms=1_700_000_000_000)

    record = await fleet.device_run()

    entry = _entry(record, "r1")
    assert (entry.fetch_started_ms, entry.fetch_finished_ms) == (1_700_000_000_000, None)


def test_an_end_before_the_start_is_not_read(tmp_path):
    """A sidecar end that does not follow its run id's start is no window."""
    path = tmp_path / "edge" / "r1" / f"1700000000000-abcd1234{rawstore.SUFFIX}"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"")
    rawstore.mark_kind(path, rawstore.KIND_FULL, fetch_finished_ms=1_699_999_999_999)

    assert rawstore.read_park_finished(path, 1_700_000_000_000) is None
    assert rawstore.read_park_finished(path, 1_699_999_999_000) == 1_699_999_999_999


# -- an unchanged per-device fetch is a check of the carried device ---------------


async def test_a_carried_device_found_unchanged_is_published_as_checked_then(fleet):
    loaded = _entry(await _both_loaded(fleet), "r1")
    assert await fleet.fetch("r1") == "edge/r1: unchanged, not parked"
    checked = await fleet.status("r1")
    fleet.collectors["r2"].payload["version"] = "B"  # r2 changed, so a device run publishes
    await fleet.fetch("r2")

    entry = _entry(await fleet.device_run(), "r1")

    assert entry.carried is True
    # the data's own collection window is the fetch it came from
    assert (entry.fetch_started_ms, entry.fetch_finished_ms) == (
        loaded.fetch_started_ms,
        loaded.fetch_finished_ms,
    )
    # and the device was last checked by the unchanged fetch
    assert checked.last_verified_at is not None and checked.last_verified_started_at is not None
    assert (entry.verified_started_ms, entry.verified_ms) == (
        runs_exec._ms_of(checked.last_verified_started_at),
        runs_exec._ms_of(checked.last_verified_at),
    )
    assert loaded.fetch_finished_ms is not None and entry.verified_ms is not None
    assert entry.verified_ms >= loaded.fetch_finished_ms


async def test_a_later_run_does_not_repeat_a_check_it_already_published(fleet):
    await _both_loaded(fleet)
    await fleet.fetch("r1")
    fleet.collectors["r2"].payload["version"] = "B"
    await fleet.fetch("r2")
    first = _entry(await fleet.device_run(), "r1")
    fleet.collectors["r2"].payload["version"] = "C"
    await fleet.fetch("r2")

    second = _entry(await fleet.device_run(), "r1")

    assert (second.verified_started_ms, second.verified_ms) == (first.verified_started_ms, first.verified_ms)


async def test_a_carried_device_never_checked_keeps_no_check(fleet):
    await _both_loaded(fleet)
    fleet.collectors["r2"].payload["version"] = "B"
    await fleet.fetch("r2")

    entry = _entry(await fleet.device_run(), "r1")

    assert entry.carried is True
    assert (entry.verified_started_ms, entry.verified_ms) == (None, None)


async def test_a_failed_fetch_after_a_check_withdraws_the_check(fleet):
    await _both_loaded(fleet)
    await fleet.fetch("r1")
    assert (await fleet.status("r1")).last_verified_at is not None
    fleet.collectors["r1"].fetch = lambda: (_ for _ in ()).throw(RuntimeError("wedged"))  # type: ignore[method-assign]
    assert (await fleet.fetch("r1")).startswith("failed: edge/r1")
    fleet.collectors["r2"].payload["version"] = "B"
    await fleet.fetch("r2")

    entry = _entry(await fleet.device_run(), "r1")

    st = await fleet.status("r1")
    assert (st.last_verified_started_at, st.last_verified_at) == (None, None)
    assert (entry.verified_started_ms, entry.verified_ms) == (None, None)


async def test_a_skip_that_did_not_compare_the_observations_is_no_check(fleet):
    """A row whose observation hash is empty skips on the configuration hash
    alone."""
    await _both_loaded(fleet)
    await fleet.store.record_device_basis("edge", "r1", now=NOW, obs_sha="")
    assert await fleet.fetch("r1") == "edge/r1: unchanged, not parked"

    st = await fleet.status("r1")
    assert (st.last_verified_started_at, st.last_verified_at) == (None, None)


async def test_a_fetch_equal_to_a_parked_payload_is_no_check(fleet):
    await fleet.setup()
    assert (await fleet.fetch("r1")).startswith("edge/r1: parked ")
    assert (await fleet.fetch("r1")).endswith(", not parked again")

    st = await fleet.status("r1")
    assert (st.last_verified_started_at, st.last_verified_at) == (None, None)


async def test_a_check_older_than_the_data_it_would_describe_is_not_published(fleet):
    """A check that ends before the payload the run carries was fetched says
    nothing about that payload: the store refuses it, though it names the
    basis on record."""
    record = await _both_loaded(fleet)
    loaded = _entry(record, "r1")
    assert loaded.fetch_started_ms is not None
    early = loaded.fetch_started_ms - 10_000
    row = await fleet.status("r1")
    await fleet.store.upsert_device_status(
        "edge",
        "r1",
        now=NOW,
        ok=True,
        verified_started_at=runs_exec._at_ms(early - 500),
        verified_at=runs_exec._at_ms(early),
        verified_raw_sha=row.last_raw_sha,
        verified_obs_sha=row.last_obs_sha,
    )
    assert (await fleet.status("r1")).last_verified_at is None
    fleet.collectors["r2"].payload["version"] = "B"
    await fleet.fetch("r2")

    entry = _entry(await fleet.device_run(), "r1")

    assert (entry.verified_started_ms, entry.verified_ms) == (None, None)


# -- the cycle path counts the same checks ----------------------------------------


async def test_the_cycle_counts_an_unchanged_fetch_as_a_check_only_when_both_hashes_matched(fleet):
    await _both_loaded(fleet)
    unit = fleet.units["r1"]

    async def cycle_fetch() -> Any:
        st = await fleet.status("r1")
        fetched = await asyncio.to_thread(
            runs_exec._fetch_phase, fleet.settings, [("edge", unit)], {("edge", "r1"): st}, True
        )
        return fetched[id(unit)]

    compared = await cycle_fetch()
    assert compared.skipped and compared.verified
    await fleet.store.record_device_basis("edge", "r1", now=NOW, obs_sha="")
    uncompared = await cycle_fetch()
    assert uncompared.skipped and not uncompared.verified


async def test_the_cycle_records_its_check_in_the_status_row(fleet):
    await fleet.setup()
    for host in ("r1", "r2"):
        await fleet.store.upsert_device_status(
            "edge", host, now=NOW, ok=True, raw_sha="RAW", obs_sha="OBS", full=True
        )
    checked = runs_exec.DeviceOutcome(
        "edge",
        "r1",
        True,
        skipped=True,
        verified=True,
        checked_basis=("RAW", "OBS"),
        fetch_started_ms=5_000,
        fetch_finished_ms=6_000,
    )
    unverified = runs_exec.DeviceOutcome(
        "edge", "r2", True, skipped=True, fetch_started_ms=5_000, fetch_finished_ms=6_000
    )

    await runs_exec._record_outcomes(fleet.store, [checked, unverified])

    one, two = await fleet.status("r1"), await fleet.status("r2")
    assert (runs_exec._ms_of(one.last_verified_started_at), runs_exec._ms_of(one.last_verified_at)) == (
        5_000,
        6_000,
    )
    assert (two.last_verified_started_at, two.last_verified_at) == (None, None)


async def test_a_run_reads_stored_checks_only_for_devices_it_has_no_outcome_for(fleet):
    """`_note_rechecks`, which a device run and a cycle both call: a device the
    run fetched itself is described by its own outcome, not by the row."""
    await fleet.setup()
    for host in ("r1", "r2"):
        await _store_check(fleet.store, host, 5_000, 6_000)
    prior = {(st.source, st.host): st for st in await fleet.store.list_device_status()}
    evidence = runs_exec.RunEvidence(fleet.settings)
    evidence.devices.append(runs_exec.DeviceOutcome("edge", "r2", True, full=True))
    prepared = [
        runs_exec.PreparedSource(
            Source(1, "edge", "vyos", {}, b"", True, NOW, NOW), list(fleet.units.values())
        )
    ]

    runs_exec._note_rechecks(evidence, prepared, prior)

    assert evidence.rechecked == {("edge", "r1"): (5_000, 6_000)}


async def test_a_load_cut_short_after_it_wrote_publishes_no_stored_check(fleet, monkeypatch):
    """A cycle load cancelled after it wrote has no outcome, and its device
    carries a mix of that write and the parent's objects: a check stored
    before describes neither. Through `_device_entries`, as a cycle builds it."""
    await fleet.setup()
    for host in ("r1", "r2"):
        await _store_check(fleet.store, host, 5_000, 6_000)
    prior_rows = {(st.source, st.host): st for st in await fleet.store.list_device_status()}
    previous = manifestmod.SnapshotManifest(
        snapshot_key=3_000,
        kind="full",
        opened=manifestmod.iso(3_000),
        published=manifestmod.iso(3_000),
        devices=[
            manifestmod.DeviceEntry(
                source="edge", host=h, outcome="collected", fetch_started_ms=1_000, fetch_finished_ms=2_000
            )
            for h in ("r1", "r2")
        ],
    )
    monkeypatch.setattr(manifestmod, "read", lambda *_: previous)
    monkeypatch.setattr(manifestmod, "effective_runs", lambda *_: {})
    evidence = runs_exec.RunEvidence(fleet.settings)
    evidence.mixed_loads.add(("edge", "r1"))
    prepared = [
        runs_exec.PreparedSource(
            Source(1, "edge", "vyos", {}, b"", True, NOW, NOW), list(fleet.units.values())
        )
    ]

    runs_exec._note_rechecks(evidence, prepared, prior_rows)
    entries = runs_exec._device_entries(fleet.settings, 7_000, 3_000, prepared, {}, evidence)

    by_host = {e.host: e for e in entries}
    assert (by_host["r1"].verified_started_ms, by_host["r1"].verified_ms) == (None, None)
    assert (by_host["r2"].verified_started_ms, by_host["r2"].verified_ms) == (5_000, 6_000)
    assert (by_host["r2"].fetch_started_ms, by_host["r2"].fetch_finished_ms) == (1_000, 2_000)


def test_a_skipped_outcome_without_a_check_does_not_refresh_a_carried_entry(monkeypatch):
    """`_device_entries` reads the check, not the skip: a skip on the
    configuration hash alone leaves the carried entry's last check as it was."""
    prior = manifestmod.DeviceEntry(
        source="edge",
        host="r1",
        outcome="collected",
        fetch_started_ms=1_000,
        fetch_finished_ms=2_000,
        verified_started_ms=3_000,
        verified_ms=4_000,
    )
    previous = manifestmod.SnapshotManifest(
        snapshot_key=5_000,
        kind="full",
        opened=manifestmod.iso(5_000),
        published=manifestmod.iso(5_000),
        devices=[prior],
    )
    monkeypatch.setattr(manifestmod, "read", lambda *_: previous)
    monkeypatch.setattr(manifestmod, "effective_runs", lambda *_: {})
    unit = runs_exec.PreparedDevice(
        Device(1, "edge", "r1", None, True, "", NOW, NOW),
        SimpleNamespace(config=SimpleNamespace(), scope="vyos:r1"),
        None,
    )
    prepared = [runs_exec.PreparedSource(Source(1, "edge", "vyos", {}, b"", True, NOW, NOW), [unit])]
    skipped = runs_exec.DeviceOutcome(
        "edge", "r1", True, skipped=True, fetch_started_ms=9_000, fetch_finished_ms=9_500
    )

    [entry] = runs_exec._device_entries(
        Settings(_env_file=None),
        10_000,
        5_000,
        prepared,
        {},
        SimpleNamespace(files=[], devices=[skipped]),
    )

    assert (entry.verified_started_ms, entry.verified_ms) == (3_000, 4_000)


def _carried_entries(
    monkeypatch: Any, evidence: Any, prior: manifestmod.DeviceEntry
) -> manifestmod.DeviceEntry:
    previous = manifestmod.SnapshotManifest(
        snapshot_key=5_000,
        kind="full",
        opened=manifestmod.iso(5_000),
        published=manifestmod.iso(5_000),
        devices=[prior],
    )
    monkeypatch.setattr(manifestmod, "read", lambda *_: previous)
    monkeypatch.setattr(manifestmod, "effective_runs", lambda *_: {})
    unit = runs_exec.PreparedDevice(
        Device(1, "edge", "r1", None, True, "", NOW, NOW),
        SimpleNamespace(config=SimpleNamespace(), scope="vyos:r1"),
        None,
    )
    prepared = [runs_exec.PreparedSource(Source(1, "edge", "vyos", {}, b"", True, NOW, NOW), [unit])]
    [entry] = runs_exec._device_entries(Settings(_env_file=None), 10_000, 5_000, prepared, {}, evidence)
    return entry


def test_a_stored_check_no_later_than_the_carried_data_is_not_published(monkeypatch):
    """`_device_entries` guards on its own as well: a check that ends at or
    before the times the carried entry records keeps the entry's values."""
    prior = manifestmod.DeviceEntry(
        source="edge", host="r1", outcome="collected", fetch_started_ms=1_000, fetch_finished_ms=2_000
    )
    evidence = SimpleNamespace(files=[], devices=[], rechecked={("edge", "r1"): (1_500, 2_000)})
    entry = _carried_entries(monkeypatch, evidence, prior)
    assert (entry.verified_started_ms, entry.verified_ms) == (None, None)

    evidence.rechecked = {("edge", "r1"): (2_500, 3_000)}
    entry = _carried_entries(monkeypatch, evidence, prior)
    assert (entry.verified_started_ms, entry.verified_ms) == (2_500, 3_000)


def test_a_skip_that_is_no_check_does_not_stamp_the_carried_tables(monkeypatch):
    """A cycle skip that did not compare the observation hash did not compare
    what feeds the side tables (for VyOS, `neigh` feeds `arp` and only the
    observation hash covers it): the tables keep their own observation time.
    A skip that is a check stamps them with its fetch."""
    prior = manifestmod.DeviceEntry(
        source="edge",
        host="r1",
        outcome="collected",
        fetch_started_ms=1_000,
        fetch_finished_ms=2_000,
        tables={"arp": manifestmod.TableOutcome(status="complete", observed_ms=1_000)},
    )
    tables = {"arp": manifestmod.TableOutcome(status="unchanged")}
    unchecked = runs_exec.DeviceOutcome(
        "edge", "r1", True, skipped=True, fetch_started_ms=9_000, fetch_finished_ms=9_500, tables=tables
    )
    entry = _carried_entries(monkeypatch, SimpleNamespace(files=[], devices=[unchecked]), prior)
    assert entry.tables["arp"].observed_ms == 1_000

    checked = runs_exec.DeviceOutcome(
        "edge",
        "r1",
        True,
        skipped=True,
        verified=True,
        fetch_started_ms=9_000,
        fetch_finished_ms=9_500,
        tables=tables,
    )
    entry = _carried_entries(monkeypatch, SimpleNamespace(files=[], devices=[checked]), prior)
    assert (entry.tables["arp"].status, entry.tables["arp"].observed_ms) == ("unchanged", 9_000)
