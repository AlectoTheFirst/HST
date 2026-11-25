"""The skip basis of a per-device fetch is recorded when a
device run loads its payload, not when the fetch parks it.

The basis (`device_status.last_raw_sha`, `last_obs_sha`, `last_full_at`) is
what the next fetch and the next cycle compare to decide that the graph
already holds a device's payload. The graph holds a parked payload only once a
device run has loaded it, so the park records the attempt alone and the run's
`_record_graphs` records the basis, under the cycle lock.

Real collector, real raw store, real park, real `build_device_run` and
`_record_graphs` against the fake store; the graph is stubbed as in
test_device_run.py.
"""

from __future__ import annotations

import asyncio
import itertools
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from tests.app import test_device_run
from tests.app.fakes import FakeStore
from tests.app.test_device_run import NOW, _DevCollector, _HostCfg

from hst import collectors as coll
from hst.app import runs_exec
from hst.app.store import Device, DeviceSpec, Source
from hst.collectors.util import GraphBuilder
from hst.core import rawstore

rig = test_device_run.rig  # real settings and raw store, the graph stubbed


class _Router(_DevCollector):
    """A device whose payload the test sets: `version` is configuration (it
    reaches the graph), `arp` an observation."""

    VOLATILE_RAW_KEYS = ("arp",)

    def __init__(self, config: _HostCfg, settings: Any) -> None:
        super().__init__(config, settings)
        self.payload: dict[str, Any] = {"host": config.host, "version": "A"}

    def fetch(self) -> Any:
        return dict(self.payload)

    def normalize(self, raw: Any) -> Any:
        b = GraphBuilder()
        b.node("Device", f"dev:{raw['host']}", hostname=raw["host"], role="router", version=raw["version"])
        return b.batch(self.config.source_name or self.name, self.scope)


@pytest.fixture
def lanes(rig, monkeypatch):
    """One device `edge/r1` in a FakeStore, the job lane building the same
    collector the device run joins with, and a device run that publishes
    under a new key each time and records what it loaded."""
    settings, cycle = rig()
    keys = itertools.count(10_000)
    monkeypatch.setattr(cycle, "new_collection_ts", lambda: next(keys))
    store = FakeStore()
    collector = _Router(_HostCfg(host="r1", source_name="edge"), settings)
    row = Source(1, "edge", "vyos", {}, b"", True, NOW, NOW)
    unit = runs_exec.PreparedDevice(Device(1, "edge", "r1", None, True, "", NOW, NOW), collector, None)
    prepared = runs_exec.PreparedSource(row, [unit])
    monkeypatch.setattr(runs_exec, "FernetResolver", lambda key: SimpleNamespace(resolve=lambda row: {}))
    monkeypatch.setattr(runs_exec.sources_glue, "build_device_collector", lambda *a, **kw: collector)

    async def fetch() -> str:
        return await runs_exec.run_device_fetch(store, settings, "edge", "r1")

    async def device_run(*, record: bool = True) -> str:
        prior = {(st.source, st.host): st for st in await store.list_device_status()}
        outcomes: list[runs_exec.DeviceOutcome] = []
        detail, _ran, key, _ = runs_exec.build_device_run(
            settings, [prepared], outcomes=outcomes, prior=prior
        )
        lanes.pending_outcomes = outcomes
        if record and key is not None:  # as `launch` records it: only for a run that published
            await runs_exec._record_graphs(store, outcomes)
        return detail

    async def status() -> Any:
        (st,) = await store.list_device_status("edge")
        return st

    async def cycle_skips() -> bool:
        st = await status()
        # the cycle's fetch phase runs a loop of its own, so off this one
        fetched = await asyncio.to_thread(
            runs_exec._fetch_phase, settings, [("edge", unit)], {("edge", "r1"): st}, True
        )
        return fetched[id(unit)].skipped

    async def setup() -> None:
        await store.create_source("edge", "vyos", {}, b"")
        await store.replace_devices("edge", [DeviceSpec(host="r1")])

    lanes = SimpleNamespace(
        settings=settings,
        store=store,
        collector=collector,
        unit=unit,
        fetch=fetch,
        device_run=device_run,
        status=status,
        cycle_skips=cycle_skips,
        setup=setup,
    )
    return lanes


async def test_a_parked_payload_that_was_never_loaded_is_no_skip_basis(lanes):
    await lanes.setup()

    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    st = await lanes.status()
    # the attempt is recorded, the basis is not
    assert st.last_success_at is not None and st.consecutive_failures == 0
    assert (st.last_raw_sha, st.last_obs_sha, st.last_full_at) == ("", "", None)
    # the same payload again: no run has loaded the first one, so neither lane skips;
    # it defers to the parked payload the next window applies
    assert (await lanes.fetch()).endswith(", not parked again") and _parked_count(lanes) == 1
    assert await lanes.cycle_skips() is False


async def test_an_unchanged_device_is_skipped_once_its_payload_is_loaded(lanes):
    await lanes.setup()
    await lanes.fetch()

    detail = await lanes.device_run()

    assert "edge/r1" in detail and rawstore.parked(lanes.settings.raw_dir) == []
    st = await lanes.status()
    assert st.last_raw_sha == coll.raw_sha(lanes.collector, lanes.collector.fetch())
    assert st.last_full_at is not None
    assert await lanes.fetch() == "edge/r1: unchanged, not parked"
    assert await lanes.cycle_skips() is True


async def test_a_device_back_on_its_loaded_configuration_is_not_skipped_while_a_change_is_parked(lanes):
    await lanes.setup()
    await lanes.fetch()
    await lanes.device_run()  # A is loaded and is the basis
    lanes.collector.payload["version"] = "B"
    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    lanes.collector.payload["version"] = "A"

    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    assert await lanes.cycle_skips() is False
    await lanes.device_run()  # the newest payload, A, wins the window

    st = await lanes.status()
    assert st.last_raw_sha == coll.raw_sha(lanes.collector, lanes.collector.fetch())
    assert await lanes.fetch() == "edge/r1: unchanged, not parked"


async def test_an_observation_payload_records_its_observation_hash_when_loaded(lanes):
    await lanes.setup()
    lanes.collector.payload["arp"] = [["10.0.0.9", "aa:bb:cc:dd:ee:01"]]
    await lanes.fetch()
    await lanes.device_run()
    loaded = await lanes.status()
    lanes.collector.payload["arp"] = [["10.0.0.9", "aa:bb:cc:dd:ee:02"]]

    assert (await lanes.fetch()).startswith("edge/r1: parked observations ")
    assert (await lanes.status()).last_obs_sha == loaded.last_obs_sha  # parked, not loaded
    await lanes.device_run()

    st = await lanes.status()
    assert st.last_obs_sha == coll.obs_sha(lanes.collector, lanes.collector.fetch()) != loaded.last_obs_sha
    # the configuration hash and the full cadence are the loaded payload's
    assert (st.last_raw_sha, st.last_full_at) == (loaded.last_raw_sha, loaded.last_full_at)
    assert await lanes.fetch() == "edge/r1: unchanged, not parked"


async def test_a_join_that_failed_records_no_basis(lanes, monkeypatch):
    await lanes.setup()
    await lanes.fetch()

    def boom(raw: Any) -> Any:
        raise ValueError("payload from a schema this build cannot read")

    monkeypatch.setattr(lanes.collector, "normalize", boom)
    detail = await lanes.device_run()

    assert "left parked" in detail
    st = await lanes.status()
    assert (st.last_raw_sha, st.last_full_at) == ("", None)
    # it defers to the parked payload the next window applies
    assert (await lanes.fetch()).endswith(", not parked again") and _parked_count(lanes) == 1


async def test_a_payload_parked_under_another_placement_clears_the_raw_basis(lanes):
    """The join normalizes under the park-time context; a basis bound to the
    unit's current resolution would name a normalization the load did not
    make, so the next fetch parks and the next run loads under the current
    one."""
    await lanes.setup()
    await lanes.fetch()
    await lanes.device_run()
    lanes.collector.payload["version"] = "B"
    await lanes.fetch()  # parked under site "home"
    lanes.collector.config = lanes.collector.config.model_copy(update={"site_code": "branch"})

    await lanes.device_run()

    st = await lanes.status()
    assert st.last_raw_sha == ""
    assert (await lanes.fetch()).startswith("edge/r1: parked ")


async def test_a_row_naming_a_parked_payloads_hash_is_no_skip_basis(lanes):
    await lanes.setup()
    await lanes.fetch()
    sha = coll.raw_sha(lanes.collector, lanes.collector.fetch())
    await lanes.store.upsert_device_status(
        "edge", "r1", now=datetime.now(UTC), ok=True, raw_sha=sha, full=True
    )

    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    assert await lanes.cycle_skips() is False


async def test_a_skip_does_not_write_back_the_basis_it_read(lanes, monkeypatch):
    await lanes.setup()
    await lanes.fetch()
    await lanes.device_run()
    store = lanes.store
    real = store.list_device_status

    async def read_then_a_run_records(source=None):
        rows = await real(source)
        await store.record_device_basis("edge", "r1", now=datetime.now(UTC), raw_sha="LATER")
        return rows

    monkeypatch.setattr(store, "list_device_status", read_then_a_run_records)
    assert await lanes.fetch() == "edge/r1: unchanged, not parked"
    monkeypatch.setattr(store, "list_device_status", real)

    assert (await lanes.status()).last_raw_sha == "LATER"


def _parked_count(lanes: Any) -> int:
    return len(rawstore.parked(lanes.settings.raw_dir))


async def test_a_payload_whose_join_keeps_failing_is_parked_once(lanes, monkeypatch):
    await lanes.setup()

    def boom(raw: Any) -> Any:
        raise ValueError("payload from a schema this build cannot read")

    monkeypatch.setattr(lanes.collector, "normalize", boom)
    for _ in range(5):
        await lanes.fetch()
        assert "left parked" in await lanes.device_run()

    assert _parked_count(lanes) == 1
    st = await lanes.status()
    assert (st.last_raw_sha, st.consecutive_failures) == ("", 0)
    lanes.collector.payload["version"] = "B"
    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    assert _parked_count(lanes) == 2


async def test_no_lane_skips_between_the_settle_and_the_basis_write(lanes):
    """A loaded, B parked; the device run loads and settles B, and before its
    basis is recorded the device is back on A."""
    await lanes.setup()
    await lanes.fetch()
    await lanes.device_run()  # A loaded and recorded
    lanes.collector.payload["version"] = "B"
    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    await lanes.device_run(record=False)  # B published and settled, basis not yet written
    assert _parked_count(lanes) == 0
    lanes.collector.payload["version"] = "A"

    assert await lanes.cycle_skips() is False
    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    await runs_exec._record_graphs(lanes.store, lanes.pending_outcomes)


async def test_a_crash_before_the_basis_write_leaves_no_lane_skipping(lanes):
    """The same gap, never closed: the process died after the run published."""
    await lanes.setup()
    await lanes.fetch()
    await lanes.device_run()
    lanes.collector.payload["version"] = "B"
    await lanes.fetch()
    await lanes.device_run(record=False)  # and nothing after it
    lanes.collector.payload["version"] = "A"

    assert await lanes.cycle_skips() is False
    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    await lanes.device_run()
    assert await lanes.fetch() == "edge/r1: unchanged, not parked"


async def test_a_basis_with_no_status_row_is_logged(caplog):
    store = FakeStore()
    outcome = runs_exec.DeviceOutcome("edge", "r9", True, fingerprint="F", basis_full=True)

    with caplog.at_level("WARNING", logger=runs_exec.logger.name):
        await runs_exec._record_graphs(store, [outcome])

    assert any(
        "edge/r9" in r.getMessage() and "no device_status row" in r.getMessage() for r in caplog.records
    )


async def test_a_parked_payload_a_later_load_made_stale_is_no_reason_not_to_park(lanes):
    await lanes.setup()
    await lanes.fetch()
    await lanes.device_run()  # A loaded
    lanes.collector.payload["version"] = "B"
    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    # the cycle's load of C, as `_record_outcomes` records it
    lanes.collector.payload["version"] = "C"
    c = coll.raw_sha(lanes.collector, lanes.collector.fetch())
    await lanes.store.upsert_device_status(
        "edge",
        "r1",
        now=datetime.now(UTC),
        ok=True,
        raw_sha=c,
        graph_sha="GC",
        graph_fetch_at=datetime.now(UTC) - timedelta(seconds=1),
        full=True,
    )
    lanes.collector.payload["version"] = "B"

    assert (await lanes.fetch()).startswith("edge/r1: parked ")
    await lanes.device_run()
    assert (await lanes.status()).last_raw_sha == coll.raw_sha(lanes.collector, lanes.collector.fetch())


async def test_the_identical_check_reads_the_park_sidecar_not_the_payload(lanes, monkeypatch):
    """The comparison costs no decrypt: the park stored the hashes beside the
    payload, and a payload parked without them (an older build) is not
    identical."""
    await lanes.setup()
    await lanes.fetch()
    (parked,) = rawstore.parked(lanes.settings.raw_dir)
    assert set(rawstore.read_park_hashes(parked.path)) == {"fingerprint", "obs"}

    def no_read(*a: Any, **kw: Any) -> Any:
        raise AssertionError("the parked payload was decrypted")

    monkeypatch.setattr(runs_exec.rawstore, "read", no_read)
    assert (await lanes.fetch()).endswith(", not parked again")
    # an older build's sidecar: kind and context only
    kind = parked.path.with_name(parked.path.name[: -len(rawstore.SUFFIX)] + rawstore.KIND_SUFFIX)
    body = json.loads(kind.read_text())
    del body["hashes"]
    kind.write_text(json.dumps(body))
    assert rawstore.read_park_hashes(parked.path) == {}
    assert (await lanes.fetch()).startswith("edge/r1: parked ")
