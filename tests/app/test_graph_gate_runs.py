"""The graph change detection in the run builders (app/runs_exec.py).

A payload that reaches the load is normalized, and its batch digest is
compared with the one the device's `device_status` row records
(`_recorded_graph`). When they match, the raw file and the side tables are
written, of the graph only the objects other writers share and the ones that
carry an anchor (`collectors/base.py _shared_part`), and the device's other
objects come forward from the parent run marked `unchanged`: the device is
recorded as an observation-only publication. The run records each digest and
the fetch time of its payload (`_record_outcomes`, `_record_graphs`) while it
still holds the cycle lock, and a device run applies a parked payload only
when it was fetched after the device's last graph check (`_last_observed`).

The graph is stubbed as in tests/app/test_device_run.py; the raw store, the
side store, the loads above the graph and the snapshot manifest are real.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from tests.app.fakes import FakeStore
from tests.app.test_device_run import NEW, PREV, _DevCollector, _HostCfg, _park, _prepared, _Session
from tests.app.test_device_run import rig as rig  # the stubbed graph, real stores

from hst import collectors as coll
from hst.app import runs_exec
from hst.app.inventory import collection as inventory_collection
from hst.app.store import Device, DeviceStatus, Source
from hst.collectors import base as collectors_base
from hst.collectors.base import Collector, graph_sha
from hst.collectors.util import GraphBuilder
from hst.core import Settings, rawstore
from hst.core import manifest as manifestmod
from hst.core.model import SectionOutcome

pytest.importorskip("pyarrow")

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


class _Router(Collector):
    """One device whose every fetch moves its uptime and nothing else: the
    change hash differs on every fetch, the batch does not. `hostname` is
    graph content; `sections` is what the payload reports per section."""

    name = "vyos"
    KIND = "group"
    ConfigModel = _HostCfg
    SIDE_TABLES = ("arp",)
    OBSERVATION_RAW_KEYS = ("arp",)
    AUTHORITATIVE_SECTIONS = ("config",)

    def __init__(
        self,
        config: _HostCfg,
        settings: Settings,
        hostname: str = "r1",
        sections: dict[str, str] | None = None,
    ) -> None:
        super().__init__(config, settings)
        self.scope = f"vyos:{config.host}"
        self.hostname = hostname
        self.sections = {"config": "ok", **(sections or {})}
        self.fetches = 0

    def fetch(self) -> Any:
        self.fetches += 1
        return {
            "host": self.config.host,
            "hostname": self.hostname,
            "uptime": self.fetches,
            "arp": [["10.0.0.9", "aa:bb:cc:dd:ee:ff"]],
            "sections": self.sections,
        }

    def normalize(self, raw: Any) -> Any:
        b = GraphBuilder()
        b.node("Device", f"dev:{raw['host']}", hostname=raw["hostname"], role="router")
        batch = b.batch(self.config.source_name or self.name, self.scope)
        batch.sections = {name: SectionOutcome(status=status) for name, status in raw["sections"].items()}
        batch.warnings.append(f"dev:{raw['host']}: one thing the payload could not settle")
        return batch

    def side_tables(self, raw: Any) -> dict[str, list[dict[str, Any]]]:
        return {"arp": [{"device_uid": f"dev:{raw['host']}", "ip": ip, "mac": mac} for ip, mac in raw["arp"]]}

    def probe(self) -> str:
        return "ok"


def _router(settings: Settings, hostname: str = "r1", sections: dict[str, str] | None = None) -> _Router:
    return _Router(_HostCfg(host="r1", source_name="edge"), settings, hostname, sections)


def _edge(collector: Collector, effective: Any = None) -> runs_exec.PreparedSource:
    row = Source(1, "edge", "vyos", {}, b"", True, NOW, NOW)
    device = Device(1, "edge", "r1", None, True, "", NOW, NOW)
    return runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(device, collector, None, effective)])


def _digest(collector: Collector, raw: Any) -> str:
    """The digest a load of `raw` from source row `edge` computes."""
    return graph_sha(collector, collector.normalize(raw).model_copy(update={"source": "edge"}))


def _status(
    digest: str,
    graph_at: datetime | None,
    raw: str = "A-PAYLOAD-BEFORE",
    fetch_at: datetime | None = None,
) -> DeviceStatus:
    return DeviceStatus(
        id=1,
        source="edge",
        host="r1",
        last_raw_sha=raw,
        last_obs_sha="",
        last_attempt_at=graph_at,
        last_success_at=graph_at,
        last_full_at=graph_at,
        consecutive_failures=0,
        last_error="",
        fetch_ms=None,
        normalize_ms=None,
        load_ms=None,
        updated_at=graph_at or NOW,
        last_graph_sha=digest,
        last_graph_at=graph_at,
        last_graph_fetch_at=fetch_at,
    )


@pytest.fixture
def loads(monkeypatch) -> list[str]:
    """The batches the graph loader is handed, by source."""
    handed: list[str] = []
    real = collectors_base.load

    def load(session, batch, **kw):
        handed.append(batch.source)
        return real(session, batch, **kw)

    monkeypatch.setattr(collectors_base, "load", load)
    return handed


def _cycle(settings: Settings, source: runs_exec.PreparedSource, prior: Any) -> tuple[str, Any, list[Any]]:
    outs: list[runs_exec.DeviceOutcome] = []
    summary, ran, _, _ = runs_exec.execute_cycle(settings, [source], {"edge"}, None, prior, outs)
    return summary, ran, outs


# --- a cycle ---------------------------------------------------------------------------------


def test_a_payload_whose_batch_digests_as_the_record_writes_its_tables_and_no_graph(rig, loads):
    settings, cycle = rig()
    collector = _router(settings)
    recorded = _digest(collector, collector.fetch())
    prior = {("edge", "r1"): _status(recorded, datetime.now(UTC))}

    summary, ran, outs = _cycle(settings, _edge(collector), prior)

    assert loads == []
    (out,) = outs
    assert out.ok and out.observations_only and not out.full and not out.skipped
    assert out.graph_sha == recorded
    assert out.raw_sha not in ("", "A-PAYLOAD-BEFORE")
    assert out.tables["arp"].row_count == 1
    assert "edge/r1: graph unchanged, observations written: arp=1" in summary
    assert "warning: dev:r1: one thing the payload could not settle" in summary
    # the objects come forward from the parent run, and the run is not degraded
    assert cycle.scopes == {"vyos:r1": "unchanged"}
    assert cycle.collected == set()
    assert cycle.carried is not None and "edge" in cycle.carried
    assert cycle.meta["statuses"] == {"edge": "fresh"} and cycle.meta["degraded"] is False
    assert [d.host for _, d, _ in ran] == ["r1"]
    # the payload itself is this run's: its raw file joined, its rows written
    record = manifestmod.read(settings, NEW)
    assert sorted(f.kind for f in record.files) == ["raw", "sidestore"]
    (entry,) = record.devices
    assert (entry.outcome, entry.carried) == ("unchanged", False)
    assert entry.sections["config"].status == "ok"


def test_a_batch_that_digests_otherwise_is_written(rig, loads):
    settings, cycle = rig()
    collector = _router(settings, hostname="r1-renamed")
    before = _router(settings)
    prior = {("edge", "r1"): _status(_digest(before, before.fetch()), datetime.now(UTC))}

    summary, _ran, outs = _cycle(settings, _edge(collector), prior)

    assert loads == ["edge"]
    (out,) = outs
    assert out.ok and out.full and not out.observations_only
    assert out.graph_sha == _digest(collector, collector.fetch())
    # the device answered for its own scope, so nothing of it carries
    assert cycle.carried is None
    assert "graph unchanged" not in summary


def test_a_digest_written_longer_ago_than_the_forced_interval_is_not_compared(rig, loads):
    settings, cycle = rig()
    collector = _router(settings)
    old = datetime.now(UTC) - timedelta(seconds=settings.collect_full_interval_s + 1)
    prior = {("edge", "r1"): _status(_digest(collector, collector.fetch()), old)}

    _summary, _ran, outs = _cycle(settings, _edge(collector), prior)

    assert loads == ["edge"]
    assert outs[0].full and outs[0].graph_sha == prior[("edge", "r1")].last_graph_sha
    assert cycle.carried is None


def test_a_row_without_a_digest_loads_in_full(rig, loads):
    settings, _cycle_stub = rig()
    collector = _router(settings)

    _summary, _ran, outs = _cycle(
        settings, _edge(collector), {("edge", "r1"): _status("", datetime.now(UTC))}
    )

    assert loads == ["edge"] and outs[0].full


def test_no_digest_is_compared_on_a_cold_start(rig, loads):
    settings, _cycle_stub = rig(pointer=None)
    collector = _router(settings)
    prior = {("edge", "r1"): _status(_digest(collector, collector.fetch()), datetime.now(UTC))}

    _summary, _ran, outs = _cycle(settings, _edge(collector), prior)

    assert loads == ["edge"] and outs[0].full


def test_a_press_writes_every_device_it_fetches(rig, loads):
    settings, cycle = rig()
    collector = _router(settings)
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.execute_refresh(settings, [_edge(collector)], "edge", outcomes=outs, concurrent=True)

    assert loads == ["edge"]
    assert outs[0].full and outs[0].graph_sha == _digest(collector, collector.fetch())
    assert cycle.carried is None


def test_a_kept_graph_whose_authoritative_section_failed_fails_the_device(rig, loads):
    """The digest leaves sections out, so the batch matches; the device is
    judged by the rule a full load is judged by, and its objects carry as a
    failed device's do."""
    settings, cycle = rig()
    collector = _router(settings, sections={"config": "malformed"})
    prior = {("edge", "r1"): _status(_digest(collector, collector.fetch()), datetime.now(UTC))}

    summary, ran, outs = _cycle(settings, _edge(collector), prior)

    assert loads == []
    (out,) = outs
    assert not out.ok and out.observations_only
    assert out.error == "sections not collected: config=malformed"
    assert cycle.scopes == {"vyos:r1": "failed"}
    assert cycle.meta["statuses"] == {"edge": "failed"}
    assert "graph unchanged, observations written: arp=1 · failed: config=malformed" in summary
    assert ran == []


def test_a_kept_graph_whose_optional_section_failed_is_partial(rig, loads):
    settings, cycle = rig()
    collector = _router(settings, sections={"lldp": "failed"})
    prior = {("edge", "r1"): _status(_digest(collector, collector.fetch()), datetime.now(UTC))}

    summary, _ran, outs = _cycle(settings, _edge(collector), prior)

    assert loads == []
    (out,) = outs
    assert out.ok and out.completeness == "partial"
    assert cycle.scopes == {"vyos:r1": "unchanged"}
    assert cycle.meta["statuses"] == {"edge": "partial"} and cycle.meta["degraded"] is True
    assert "· partial: lldp=failed" in summary


def _resolved(generation: int) -> Any:
    """A resolver v2 resolution, as far as the skip fingerprint reads one."""
    return SimpleNamespace(
        effective=SimpleNamespace(resolver_version=inventory_collection.RESOLVER_V2),
        normalization_revision="rev-1",
        placement_generation=generation,
        evidence=lambda: {},
    )


@pytest.mark.parametrize(("generation", "written"), [(3, False), (4, True)])
def test_the_digest_is_bound_to_the_normalization_and_placement_as_the_raw_hash_is(
    rig, loads, generation, written
):
    """Recorded under placement generation 3: the same batch under
    generation 4, a placement-only change, is written again."""
    settings, _cycle_stub = rig()
    collector = _router(settings)
    digest = _digest(collector, collector.fetch())
    prior = {
        ("edge", "r1"): _status(inventory_collection.skip_fingerprint(digest, "rev-1", 3), datetime.now(UTC))
    }

    _summary, _ran, outs = _cycle(settings, _edge(collector, _resolved(generation)), prior)

    assert loads == (["edge"] if written else [])
    assert outs[0].graph_sha == inventory_collection.skip_fingerprint(digest, "rev-1", generation)


# --- a device run ----------------------------------------------------------------------------


def _parked_digest(settings: Settings) -> str:
    collector = _DevCollector(_HostCfg(host="r1", source_name="edge"), settings)
    return _digest(collector, {"host": "r1"})


def test_a_device_run_payload_whose_batch_digests_as_the_record_writes_no_graph(rig, loads):
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")
    recorded = _parked_digest(settings)
    outs: list[runs_exec.DeviceOutcome] = []

    detail, ran, key, _ = runs_exec.build_device_run(
        settings, [edge], outcomes=outs, prior={("edge", "r1"): _status(recorded, datetime.now(UTC))}
    )

    assert key == NEW and loads == []
    assert "graph unchanged, observations written: arp=0" in detail
    assert cycle.scopes == {"vyos:r1": "unchanged"} and cycle.collected == set()
    (out,) = outs
    assert out.ok and out.observations_only and not out.full and out.graph_sha == recorded
    assert [d.host for _, d, _ in ran] == ["r1"]
    # applied, so it settles like any other applied payload
    assert rawstore.parked(settings.raw_dir) == []


def test_a_device_run_payload_whose_batch_digests_otherwise_is_written(rig, loads):
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.build_device_run(
        settings, [edge], outcomes=outs, prior={("edge", "r1"): _status("ANOTHER", datetime.now(UTC))}
    )

    assert loads == ["edge"]
    assert cycle.collected == {"vyos:r1"}
    assert outs[0].full and outs[0].graph_sha == _parked_digest(settings)


def test_a_device_run_observation_payload_normalizes_nothing(rig, loads):
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    (unit,) = edge.units
    coll.park(unit.collector, {"host": "r1"}, source_name="edge", kind=rawstore.KIND_OBSERVATION)
    outs: list[runs_exec.DeviceOutcome] = []

    detail, _ran, _key, _ = runs_exec.build_device_run(
        settings,
        [edge],
        outcomes=outs,
        prior={("edge", "r1"): _status(_parked_digest(settings), datetime.now(UTC))},
    )

    assert loads == []
    assert "configuration unchanged, observations written" in detail
    assert outs[0].observations_only and outs[0].graph_sha is None
    assert cycle.scopes == {"vyos:r1": "unchanged"}


# --- what a run records ----------------------------------------------------------------------


async def _seeded() -> FakeStore:
    store = FakeStore()
    await store.create_source("edge", "vyos", {}, b"")
    for host in ("r1", "r2", "r3", "r4"):
        await store.upsert_device_status(
            "edge", host, now=NOW, ok=True, raw_sha="RAW", obs_sha="OBS", graph_sha="G0", full=True
        )
    return store


async def test_a_cycle_records_each_digest_and_clears_a_failed_devices(monkeypatch):
    store = await _seeded()
    later = NOW + timedelta(minutes=1)
    monkeypatch.setattr(runs_exec, "_now", lambda: later)
    outcomes = [
        runs_exec.DeviceOutcome("edge", "r1", True, raw_sha="RAW1", full=True, graph_sha="G1"),
        runs_exec.DeviceOutcome("edge", "r2", True, raw_sha="RAW2", observations_only=True, graph_sha="G0"),
        runs_exec.DeviceOutcome("edge", "r3", True, raw_sha="RAW", skipped=True),
        runs_exec.DeviceOutcome("edge", "r4", False, error="sections not collected: config=malformed"),
    ]

    await runs_exec._record_outcomes(store, outcomes)

    rows = {st.host: st for st in await store.list_device_status("edge")}
    assert (rows["r1"].last_graph_sha, rows["r1"].last_graph_at) == ("G1", later)
    assert (rows["r2"].last_graph_sha, rows["r2"].last_graph_at, rows["r2"].last_raw_sha) == (
        "G0",
        NOW,
        "RAW2",
    )
    assert (rows["r3"].last_graph_sha, rows["r3"].last_graph_at) == ("G0", NOW)
    assert (rows["r4"].last_graph_sha, rows["r4"].last_raw_sha) == ("", "")


async def test_a_device_run_records_each_digest_and_clears_a_failed_load(monkeypatch):
    store = await _seeded()
    later = NOW + timedelta(minutes=1)
    monkeypatch.setattr(runs_exec, "_now", lambda: later)
    outcomes = [
        runs_exec.DeviceOutcome("edge", "r1", True, full=True, graph_sha="G1"),
        runs_exec.DeviceOutcome("edge", "r2", True, observations_only=True, graph_sha="G0"),
        runs_exec.DeviceOutcome("edge", "r3", True, observations_only=True),
        runs_exec.DeviceOutcome("edge", "r4", False, error="ValueError: payload from a schema"),
    ]

    await runs_exec._record_graphs(store, outcomes)

    rows = {st.host: st for st in await store.list_device_status("edge")}
    assert (rows["r1"].last_graph_sha, rows["r1"].last_graph_at, rows["r1"].last_raw_sha) == (
        "G1",
        later,
        "RAW",
    )
    assert (rows["r2"].last_graph_sha, rows["r2"].last_graph_at) == ("G0", NOW)
    assert rows["r3"].updated_at == NOW  # an observation payload records nothing
    assert (rows["r4"].last_graph_sha, rows["r4"].last_raw_sha, rows["r4"].consecutive_failures) == (
        "",
        "",
        0,
    )


class _OrderedStore(FakeStore):
    """A FakeStore that notes when the cycle lock is taken and released, and
    when the device statuses are read and written."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[str] = []

    @asynccontextmanager
    async def cycle_lock(self, on_lost=None):
        async with super().cycle_lock(on_lost) as fence:
            self.events.append("lock")
            yield fence
            self.events.append("unlock")

    async def list_device_status(self, source=None):
        self.events.append("read")
        return await super().list_device_status(source)

    async def upsert_device_status(self, *args, **kw):
        self.events.append("write")
        return await super().upsert_device_status(*args, **kw)

    async def record_device_graph(self, *args, **kw):
        self.events.append("graph")
        return await super().record_device_graph(*args, **kw)


async def _launch(store: _OrderedStore, settings: Settings, source: str, monkeypatch) -> Any:
    async def prepare(store, settings):
        rows = [r for r in await store.list_sources() if r.enabled]
        return [runs_exec.PreparedSource(r, [], None) for r in rows], {}

    monkeypatch.setattr(runs_exec, "_prepare_all", prepare)
    monkeypatch.setattr(runs_exec, "_RUNS", {})
    run = await runs_exec.launch(store, settings, source)
    assert run is not None
    return await asyncio.wait_for(runs_exec.wait_for_run(store, run), 30)


async def test_a_cycle_decides_and_records_under_the_lock(tmp_path, monkeypatch):
    """A run queued behind this one decides its skips against what this one
    published, not against the record from before it."""
    store = _OrderedStore()
    await store.create_source("edge", "vyos", {}, b"")
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    seen: dict[str, Any] = {}

    def cycle(settings, prepared, fresh, assigned, prior, outcomes, **kw):
        seen["prior"] = prior
        store.events.append("build")
        outcomes.append(runs_exec.DeviceOutcome("edge", "r1", True, raw_sha="RAW", full=True, graph_sha="G1"))
        return runs_exec.RunOutcome("cycle", [], NEW)

    monkeypatch.setattr(runs_exec, "execute_cycle", cycle)

    finished = await _launch(store, settings, "cycle", monkeypatch)

    assert finished.status == "ok"
    assert store.events == ["lock", "read", "build", "write", "unlock"]
    assert seen["prior"] == {}
    (row,) = await store.list_device_status("edge")
    assert row.last_graph_sha == "G1" and row.last_graph_at is not None


async def test_a_cycle_that_collected_no_source_ends_its_run_in_error(tmp_path, monkeypatch):
    store = _OrderedStore()
    await store.create_source("edge", "vyos", {}, b"")
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)

    def cycle(settings, prepared, fresh, assigned, prior, outcomes, **kw):
        outcomes.append(runs_exec.DeviceOutcome("edge", "r1", False, error="RuntimeError: r1 unreachable"))
        return runs_exec.RunOutcome("cycle · edge: r1: RuntimeError: r1 unreachable", [], NEW, "error")

    monkeypatch.setattr(runs_exec, "execute_cycle", cycle)

    finished = await _launch(store, settings, "cycle", monkeypatch)

    assert (finished.status, finished.snapshot_key) == ("error", str(NEW))
    assert "r1 unreachable" in finished.detail


async def test_a_device_run_decides_and_records_under_the_lock(tmp_path, monkeypatch):
    store = _OrderedStore()
    await store.create_source("edge", "vyos", {}, b"")
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="RAW", graph_sha="G0", full=True)
    store.events.clear()
    settings = Settings(
        _env_file=None, hst_data_dir=tmp_path, hst_secret_key=collectors_base.crypto.generate_key()
    )
    coll.park(
        _DevCollector(_HostCfg(host="r1", source_name="edge"), settings), {"host": "r1"}, source_name="edge"
    )
    seen: dict[str, Any] = {}

    def device_run(settings, prepared, assigned=None, *, prior=None, outcomes=None, **kw):
        seen["prior"] = prior
        store.events.append("build")
        outcomes.append(runs_exec.DeviceOutcome("edge", "r1", True, full=True, graph_sha="G1"))
        return runs_exec.RunOutcome("device run", [], NEW)

    monkeypatch.setattr(runs_exec, "build_device_run", device_run)

    finished = await _launch(store, settings, runs_exec.DEVICE_RUN, monkeypatch)

    assert finished.status == "ok"
    # the first hold claims the run; the second builds it
    assert store.events == ["lock", "unlock", "lock", "read", "build", "graph", "unlock"]
    assert seen["prior"][("edge", "r1")].last_graph_sha == "G0"
    (row,) = await store.list_device_status("edge")
    assert row.last_graph_sha == "G1" and row.last_graph_at is not None and row.last_graph_at > NOW


async def test_a_device_run_that_publishes_nothing_records_nothing(tmp_path, monkeypatch):
    store = _OrderedStore()
    await store.create_source("edge", "vyos", {}, b"")
    await store.upsert_device_status("edge", "r1", now=NOW, ok=True, raw_sha="RAW", graph_sha="G0", full=True)
    store.events.clear()
    settings = Settings(
        _env_file=None, hst_data_dir=tmp_path, hst_secret_key=collectors_base.crypto.generate_key()
    )
    coll.park(
        _DevCollector(_HostCfg(host="r1", source_name="edge"), settings), {"host": "r1"}, source_name="edge"
    )

    def device_run(settings, prepared, assigned=None, *, prior=None, outcomes=None, **kw):
        outcomes.append(runs_exec.DeviceOutcome("edge", "r1", False, error="ValueError: unreadable"))
        return runs_exec.RunOutcome("skipped: no parked payload this window could apply", [], None)

    monkeypatch.setattr(runs_exec, "build_device_run", device_run)

    await _launch(store, settings, runs_exec.DEVICE_RUN, monkeypatch)

    assert "graph" not in store.events
    (row,) = await store.list_device_status("edge")
    assert (row.last_graph_sha, row.last_raw_sha) == ("G0", "RAW")


def test_the_run_builders_pass_on_what_the_fetch_phase_learned(rig, loads):
    """The recorded digest reaches the load only for a result that loads: a
    skipped result carries none, so nothing compares for it."""
    settings, cycle = rig()
    collector = _router(settings)
    raw = collector.fetch()
    recorded = _digest(collector, raw)
    status = _status(recorded, datetime.now(UTC), raw=collectors_base.raw_sha(collector, raw))
    collector.fetches = 0  # the next fetch answers the same payload

    _summary, _ran, outs = _cycle(settings, _edge(collector), {("edge", "r1"): status})

    assert loads == []
    assert outs[0].skipped and outs[0].graph_sha is None
    assert cycle.scopes == {"vyos:r1": "unchanged"}
    assert PREV != NEW


# --- what a kept batch writes, and what it is compared against -------------------------------


class _Shares(_Session):
    """The stubbed graph, in which another writer shares `shared`; `asked`
    collects the parameters of every read of the shared objects."""

    def __init__(self, shared: set[str], asked: list[dict[str, Any]]) -> None:
        self.shared = shared
        self.asked = asked

    def run(self, q: str, **p: Any) -> Any:
        if q != collectors_base.SHARED_OBJECTS:
            return super().run(q, **p)
        self.asked.append(p)
        rows = [{"uid": u} for u in p["uids"] if u in self.shared]

        class _Result:
            def data(self_inner) -> list[dict[str, Any]]:
                return rows

        return _Result()


def test_a_kept_batch_writes_what_it_shares_and_the_run_says_so(rig, loads, monkeypatch):
    settings, cycle = rig()
    asked: list[dict[str, Any]] = []
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda s: _Shares({"dev:r1"}, asked))
    collector = _router(settings)
    prior = {("edge", "r1"): _status(_digest(collector, collector.fetch()), datetime.now(UTC))}

    summary, _ran, outs = _cycle(settings, _edge(collector), prior)

    assert loads == ["edge"]
    (params,) = asked
    assert (params["prev"], params["cts"], params["uids"]) == (PREV, NEW, ["dev:r1"])
    assert (
        "edge/r1: graph unchanged, shared objects written: 1 nodes, 0 rels, observations written: arp=1"
        in summary
    )
    (out,) = outs
    assert out.ok and out.observations_only and not out.full
    assert cycle.scopes == {"vyos:r1": "unchanged"} and cycle.collected == set()


def test_a_cycle_records_when_the_payload_it_checked_was_fetched(rig, loads):
    """Written or kept, a normalized payload's fetch time is the time its run
    id carries, which is what a parked payload's fetch time is compared with."""
    settings, _cycle_stub = rig()
    collector = _router(settings)
    prior = {("edge", "r1"): _status(_digest(collector, collector.fetch()), datetime.now(UTC))}

    _summary, _ran, outs = _cycle(settings, _edge(collector), prior)

    (out,) = outs
    (raw,) = settings.raw_dir.rglob(f"*{rawstore.SUFFIX}")
    assert out.graph_fetch_ms == manifestmod.run_ts(raw.name.removesuffix(rawstore.SUFFIX))
    assert out.graph_fetch_ms == out.fetch_started_ms


def test_a_device_run_records_the_parked_payloads_fetch_time(rig, loads):
    settings, _cycle_stub = rig()
    edge = _prepared(settings, "edge", "r1")
    (unit,) = edge.units
    coll.park(unit.collector, {"host": "r1"}, source_name="edge", fetch_ts_ms=1_500)
    outs: list[runs_exec.DeviceOutcome] = []

    runs_exec.build_device_run(
        settings,
        [edge],
        outcomes=outs,
        prior={("edge", "r1"): _status(_parked_digest(settings), datetime.now(UTC))},
    )

    (out,) = outs
    assert out.observations_only and out.graph_fetch_ms == 1_500


@pytest.mark.parametrize(("checked", "applied"), [(1_600, False), (1_400, True), (None, True)])
def test_a_device_run_applies_a_payload_only_when_it_was_fetched_after_the_last_graph_check(
    rig, loads, checked, applied
):
    """A cycle whose batch digested as the one on record wrote no object that
    dates its fetch, so the parent run's objects still say 1_100. The row says
    when the payload the graph was last checked against was fetched: a payload
    parked before that is older than the picture it would overwrite."""
    settings, _cycle_stub = rig(observed={"vyos:r1": 1_100})
    edge = _prepared(settings, "edge", "r1")
    (unit,) = edge.units
    coll.park(unit.collector, {"host": "r1"}, source_name="edge", fetch_ts_ms=1_500)
    status = _status("", None, fetch_at=None if checked is None else runs_exec._at_ms(checked))

    detail, _ran, key, _ = runs_exec.build_device_run(settings, [edge], prior={("edge", "r1"): status})

    if applied:
        assert key == NEW and loads == ["edge"]
    else:
        assert key is None and loads == []
        assert f"run {PREV} holds a newer observation of this device (1600 vs 1500)" in detail
        assert rawstore.parked(settings.raw_dir) == []  # settled as superseded


@pytest.mark.parametrize(("observed", "full"), [(None, True), (1_450, False)])
def test_an_observation_payload_over_a_full_one_it_supersedes_is_applied_in_full(rig, loads, observed, full):
    """Its configuration hash matched the record the full payload's fetch left,
    so that payload's graph change is its own too. A full payload the parent
    run is newer than changes nothing, and the observation payload is applied
    as one."""
    settings, cycle = rig(observed={} if observed is None else {"vyos:r1": observed})
    edge = _prepared(settings, "edge", "r1")
    (unit,) = edge.units
    coll.park(unit.collector, {"host": "r1"}, source_name="edge", fetch_ts_ms=1_400)
    coll.park(
        unit.collector,
        {"host": "r1", "arp": [["10.0.0.9", "aa:bb:cc:dd:ee:ff"]]},
        source_name="edge",
        fetch_ts_ms=1_500,
        kind=rawstore.KIND_OBSERVATION,
    )
    outs: list[runs_exec.DeviceOutcome] = []

    detail, _ran, key, _ = runs_exec.build_device_run(settings, [edge], outcomes=outs)

    assert key == NEW
    (out,) = outs
    if full:
        assert loads == ["edge"] and out.full and out.graph_sha is not None
        assert cycle.collected == {"vyos:r1"}
    else:
        assert loads == [] and out.observations_only and out.graph_sha is None
        assert "configuration unchanged, observations written: arp=1" in detail
    assert "superseded by" in detail


def test_a_fetch_time_survives_the_store_to_the_millisecond():
    for ms in (0, 1_727_000_000_123, 1_727_000_000_999):
        assert runs_exec._ms_of(runs_exec._at_ms(ms)) == ms
    assert runs_exec._at_ms(None) is None and runs_exec._ms_of(None) is None


async def test_the_run_records_the_fetch_time_with_the_digest(monkeypatch):
    store = await _seeded()
    later = NOW + timedelta(minutes=1)
    monkeypatch.setattr(runs_exec, "_now", lambda: later)

    await runs_exec._record_outcomes(
        store,
        [
            runs_exec.DeviceOutcome("edge", "r1", True, full=True, graph_sha="G1", graph_fetch_ms=1_500),
            runs_exec.DeviceOutcome("edge", "r2", True, raw_sha="RAW", skipped=True),
        ],
    )
    await runs_exec._record_graphs(
        store,
        [
            runs_exec.DeviceOutcome(
                "edge", "r3", True, observations_only=True, graph_sha="G0", graph_fetch_ms=1_600
            ),
            runs_exec.DeviceOutcome("edge", "r4", False, error="ValueError: unreadable"),
        ],
    )

    rows = {st.host: st for st in await store.list_device_status("edge")}
    assert runs_exec._ms_of(rows["r1"].last_graph_fetch_at) == 1_500
    assert rows["r2"].last_graph_fetch_at is None
    assert runs_exec._ms_of(rows["r3"].last_graph_fetch_at) == 1_600
    assert rows["r4"].last_graph_fetch_at is None
