"""`runs_exec.build_device_run`: the payloads parked by per-device fetch jobs
folded into one run."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from hst import collectors as coll
from hst.app import runs_exec
from hst.app.crypto import generate_key
from hst.app.store import Device, Source
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import Settings, rawstore
from hst.core import manifest as manifestmod

PREV, NEW = 1_000, 2_000
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def _settings(tmp_path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


class _HostCfg(SourceConfig):
    host: str = ""


class _DevCollector(Collector):
    """One device of a fleet. `boom` makes normalize raise, which is how a
    payload that cannot be folded in is left parked.
    """

    name = "vyos"
    ConfigModel = _HostCfg
    SIDE_TABLES = ("arp",)
    OBSERVATION_RAW_KEYS = ("arp",)

    def __init__(self, config: _HostCfg, settings: Settings, boom: bool = False) -> None:
        super().__init__(config, settings)
        self.scope = f"vyos:{config.host}"
        self.boom = boom

    def fetch(self) -> Any:
        return {"host": self.config.host}

    def normalize(self, raw: Any) -> Any:
        if self.boom:
            raise ValueError("payload from a schema this build cannot read")
        b = GraphBuilder()
        b.node("Device", f"dev:{raw['host']}", hostname=raw["host"], role="router")
        return b.batch(self.config.source_name or self.name, self.scope)

    def side_tables(self, raw: Any) -> dict[str, list[dict]]:
        arp = raw.get("arp") or []
        return {"arp": [{"device_uid": f"dev:{raw['host']}", "ip": ip, "mac": mac} for ip, mac in arp]}

    def probe(self) -> str:
        return "ok"


class _Session:
    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *a: Any) -> bool:
        return False

    def execute_write(self, work: Any) -> Any:
        return work(self)

    def execute_read(self, work: Any) -> Any:
        return work(self)

    def run(self, q: str, **p: Any) -> Any:
        class _Result:
            def data(self_inner) -> list[dict[str, Any]]:
                if "UNWIND $rows" in q and "MERGE (n" in q:
                    return [{"uid": r["uid"], "before": {}, "after": {**r["props"]}} for r in p["rows"]]
                return []

        return _Result()


class _Cycle:
    """Stands in for `core.cycle`. `observed` is what the parent run holds per
    collector scope, the comparison a parked payload has to beat to be applied;
    an absent scope means the run never observed that device."""

    def __init__(self, pointer: int | None, observed: dict[str, int] | None = None) -> None:
        self.pointer = pointer
        self.carried: tuple[str, ...] | None = None
        self.scopes: dict[str, str] = {}
        self.collected: set[str] = set()
        self.unasked: tuple[str, ...] = ()
        self.section_labels: dict[str, list[str]] = {}
        self.meta: dict[str, Any] | None = None
        self.steps: list[str] = []
        self.observed = observed or {}

    def current_ts(self, s: Any) -> int | None:
        return self.pointer

    def new_collection_ts(self) -> int:
        return NEW

    def carry_forward(
        self,
        s: Any,
        prev: int,
        cts: int,
        sources: list[str],
        *,
        scopes: dict[str, str] | None = None,
        collected: Any = (),
        unasked: Any = None,
        section_labels: Any = None,
    ) -> dict[str, int]:
        self.carried = tuple(sources)
        self.scopes = dict(scopes or {})
        self.collected = set(collected)
        self.unasked = tuple(sources if unasked is None else unasked)
        self.section_labels = {k: list(v) for k, v in (section_labels or {}).items()}
        return {"nodes": 3, "rels": 1}

    def cycle_counts(self, s: Any, cts: int) -> dict[str, int]:
        return {"nodes": 7, "rels": 9}

    def scope_collected_at(self, s: Any, cts: int, scope: str) -> int | None:
        return self.observed.get(scope)

    def set_pointer(self, s: Any, cts: int) -> None:
        self.steps.append("set_pointer")
        self.pointer = cts

    def apply_site_assignments(self, s: Any, assigned: Any, cts: int | None = None) -> int:
        self.steps.append("apply_site_assignments")
        return 0

    def write_cycle_meta(self, s: Any, cts: int, **kw: Any) -> None:
        self.steps.append("write_cycle_meta")
        self.meta = kw


class _Rules:
    def run(self, s: Any, ts_ms: int | None = None, collection_ts: int | None = None) -> list[dict]:
        return []


class _Rt:
    def execute(self, session: Any, settings: Settings, collection_ts: int | None = None) -> Any:
        from hst.core.model import RunManifest

        return RunManifest(run_id="rt-i", source="reasoner", scope="rt-imports")

    def execute_rt_domains(self, session: Any, settings: Settings, collection_ts: int | None = None) -> Any:
        from hst.core.model import RunManifest

        return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

    def execute_link_speed(self, session: Any, settings: Settings, collection_ts: int | None = None) -> Any:
        from hst.core.model import RunManifest

        return RunManifest(run_id="ls", source="reasoner", scope="link-speed")


@pytest.fixture
def rig(monkeypatch, tmp_path):
    """Real settings and a real raw store; the graph side stubbed."""

    def build(
        *, pointer: int | None = PREV, observed: dict[str, int] | None = None
    ) -> tuple[Settings, _Cycle]:
        settings = _settings(tmp_path)
        cycle = _Cycle(pointer, observed)
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda s: _Session())
        return settings, cycle

    return build


def _prepared(settings: Settings, name: str, *hosts: str, bad: str = "") -> runs_exec.PreparedSource:
    row = Source(1, name, "vyos", {}, b"", True, NOW, NOW)
    units = [
        runs_exec.PreparedDevice(
            Device(1, name, host, None, True, "", NOW, NOW),
            _DevCollector(_HostCfg(host=host, source_name=name), settings, boom=host == bad),
            None,
        )
        for host in hosts
    ]
    return runs_exec.PreparedSource(row, units)


def _park(source: runs_exec.PreparedSource, host: str) -> None:
    unit = next(u for u in source.units if u.device.host == host)
    coll.park(unit.collector, {"host": host}, source_name=source.row.name)


def test_a_device_run_joins_every_parked_payload_and_carries_the_rest(rig, tmp_path):
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2")
    other = _prepared(settings, "ctrl", "c1")
    _park(edge, "r1")  # only r1 was fetched in this window

    detail, ran, key, _ = runs_exec.build_device_run(settings, [edge, other])

    assert key == NEW and cycle.pointer == NEW
    assert cycle.meta["kind"] == "device"
    assert cycle.meta["parent"] == PREV
    assert cycle.meta["statuses"] == {"edge": "fresh", "ctrl": "carried"}
    # both the untouched source and the fetched source carry: r2 of the edge
    # fleet was not in this window and has to come forward
    assert cycle.carried is not None and set(cycle.carried) == {"edge", "ctrl", "vyos"}
    assert [d.host for _, d, _ in ran] == ["r1"]
    assert detail.startswith(f"device run {NEW}:")
    assert rawstore.parked(settings.raw_dir) == []  # joined, so no longer parked


def test_the_parent_runs_observation_times_are_read_once_for_the_whole_window(rig, tmp_path):
    """Each parked payload is compared with the parent run's observation of its
    device. The run is read once for every device in the window, not once per
    payload."""
    settings, cycle = rig()
    asked: list[set[str]] = []

    def scopes_collected_at(s: Any, cts: int, scopes: Any) -> dict[str, int]:
        asked.append(set(scopes))
        return {}

    def one_scope(s: Any, cts: int, scope: str) -> int | None:
        raise AssertionError("read scope by scope")

    cycle.scopes_collected_at = scopes_collected_at  # type: ignore[attr-defined]
    cycle.scope_collected_at = one_scope  # type: ignore[method-assign]
    edge = _prepared(settings, "edge", "r1", "r2")
    _park(edge, "r1")
    _park(edge, "r2")

    runs_exec.build_device_run(settings, [edge])

    assert asked == [{"vyos:r1", "vyos:r2"}]


def test_an_observation_only_payload_writes_side_tables_and_carries_the_graph(rig, tmp_path):
    """The per-device half of the observation-only rule.

    r1's fetch matched the configuration already loaded and differed only in
    its ARP table, so `run_device_fetch` parked the payload with the kind
    sidecar `observation`. The device run applies it as side tables only: a
    real parquet lands under this run, the manifest names it, and r1's graph
    objects come forward marked `unchanged`; the run holds no new picture of
    the device, only newer rows for the table the graph does not hold.
    """
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2")
    unit = next(u for u in edge.units if u.device.host == "r1")
    coll.park(
        unit.collector,
        {"host": "r1", "arp": [["10.0.0.9", "aa:bb:cc:dd:ee:ff"]]},
        source_name="edge",
        kind=rawstore.KIND_OBSERVATION,
    )
    (parked,) = rawstore.parked(settings.raw_dir)
    assert parked.kind == rawstore.KIND_OBSERVATION

    detail, ran, key, _ = runs_exec.build_device_run(settings, [edge])

    # the run published, and r1 contributed to it
    assert key == NEW and cycle.pointer == NEW
    assert [d.host for _, d, _ in ran] == ["r1"]
    assert "observations written: arp=1" in detail
    # the graph was not rewritten: r1's objects come forward as unchanged,
    # r2 was not in the window at all
    assert cycle.collected == set()
    assert cycle.scopes == {"vyos:r1": "unchanged", "vyos:r2": "not-run"}
    # a real side-store file, and the manifest names it
    written = sorted(p.name for p in (settings.sidestore_dir / "arp").rglob("*.parquet"))
    assert written == [f"{parked.run_id}.parquet"]
    record = manifestmod.read(settings, NEW)
    assert sorted(f.table for f in record.files if f.kind == "sidestore") == ["arp"]
    # and the device's entry states that its tables are this run's
    (entry,) = [d for d in record.devices if d.host == "r1"]
    assert entry.outcome == "unchanged"
    assert entry.tables["arp"].status == "complete" and entry.tables["arp"].row_count == 1
    # the payload settles like any other applied payload
    assert rawstore.parked(settings.raw_dir) == []


def test_a_full_payload_is_normalized_and_loaded(rig, tmp_path):
    """The other kind, unchanged: a payload parked without an observation
    sidecar is applied in full, so its device answers for its own scope and
    its absent objects read as removals."""
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")

    runs_exec.build_device_run(settings, [edge])

    assert cycle.collected == {"vyos:r1"}
    assert cycle.scopes == {}


def test_a_device_run_does_not_resurrect_an_interface_the_device_stopped_reporting(rig, tmp_path):
    """The absence a device run has to read two ways.

    r1's payload was applied, so r1 answered for its own scope in this run: an
    interface its payload does not report is absent from the new run. r2 was not
    in this window, so its objects come forward marked `not-run`.
    """
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2")
    _park(edge, "r1")

    runs_exec.build_device_run(settings, [edge])

    assert cycle.collected == {"vyos:r1"}
    assert cycle.scopes == {"vyos:r2": "not-run"}


def test_a_payload_left_parked_keeps_its_device_in_the_carry_set(rig, tmp_path):
    """A payload that could not be normalized applied nothing, so the run holds
    no observation of that device."""
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2", bad="r2")
    _park(edge, "r1")
    _park(edge, "r2")

    runs_exec.build_device_run(settings, [edge])

    assert cycle.collected == {"vyos:r1"}
    assert cycle.scopes == {"vyos:r2": "failed"}


def test_a_joined_payload_records_the_run_it_joined(rig, tmp_path):
    """The run key is a sidecar beside the raw file, never part of its name: the
    file keeps its fetch-time identity."""
    settings, _ = rig()
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")
    (payload,) = rawstore.parked(settings.raw_dir)

    runs_exec.build_device_run(settings, [edge])

    meta = payload.path.with_name(payload.run_id + rawstore.META_SUFFIX)
    assert meta.is_file()
    import json

    assert json.loads(meta.read_text()) == {"snapshot_ts": NEW}


def test_a_payload_that_cannot_be_normalized_stays_parked_and_is_named(rig, tmp_path):
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2", bad="r2")
    _park(edge, "r1")
    _park(edge, "r2")

    detail, ran, key, _ = runs_exec.build_device_run(settings, [edge])

    assert key == NEW
    assert cycle.meta["statuses"] == {"edge": "partial"}
    assert cycle.meta["degraded"] is True
    assert "left parked" in detail and "this build cannot read" in detail
    assert [d.host for _, d, _ in ran] == ["r1"]
    still = rawstore.parked(settings.raw_dir)
    assert [p.host for p in still] == ["r2"]


def test_a_payload_whose_source_is_gone_stays_parked(rig, tmp_path):
    """A source deleted or disabled between the fetch and the device run has no
    collector to normalize with. No run is published."""
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")

    detail, ran, key, _ = runs_exec.build_device_run(settings, [])

    assert (key, ran) == (None, [])
    assert cycle.meta is None and cycle.pointer == PREV
    assert "no enabled source or device for this payload" in detail
    assert [p.host for p in rawstore.parked(settings.raw_dir)] == ["r1"]


def test_nothing_parked_publishes_no_run(rig, tmp_path):
    settings, cycle = rig()

    detail, ran, key, _ = runs_exec.build_device_run(settings, [_prepared(settings, "edge", "r1")])

    assert (key, ran) == (None, [])
    assert cycle.meta is None and cycle.pointer == PREV
    assert "no device payloads parked" in detail


def test_no_pointer_yet_leaves_the_payloads_parked(rig, tmp_path):
    settings, cycle = rig(pointer=None)
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")

    detail, ran, key, _ = runs_exec.build_device_run(settings, [edge])

    assert (key, ran) == (None, [])
    assert cycle.meta is None
    assert "no snapshot yet" in detail
    assert len(rawstore.parked(settings.raw_dir)) == 1


def _sidecar(payload: rawstore.ParkedPayload) -> dict[str, Any]:
    import json

    return json.loads(payload.path.with_name(payload.run_id + rawstore.META_SUFFIX).read_text())


def test_the_newest_payload_of_a_device_wins_and_supersedes_the_older_ones(rig, tmp_path):
    """Two payloads of one device in one window are two observations of the same
    objects. The older one is settled against the run the newer one publishes."""
    settings, _ = rig()
    edge = _prepared(settings, "edge", "r1")
    unit = edge.units[0]
    coll.park(unit.collector, {"host": "r1"}, source_name="edge", fetch_ts_ms=200)
    coll.park(unit.collector, {"host": "r1"}, source_name="edge", fetch_ts_ms=100)
    older, newer = sorted(rawstore.parked(settings.raw_dir), key=lambda p: p.fetch_ts_ms)

    detail, ran, key, _ = runs_exec.build_device_run(settings, [edge])

    assert key == NEW
    assert [d.host for _, d, _ in ran] == ["r1"]  # one load, not two
    assert _sidecar(newer) == {"snapshot_ts": NEW}
    assert _sidecar(older) == {"snapshot_ts": None, "superseded_by": NEW}
    assert rawstore.parked(settings.raw_dir) == []
    assert f"{older.run_id}: superseded by " in detail


def test_a_payload_older_than_the_parent_runs_view_of_the_device_is_not_applied(rig, tmp_path):
    """A payload that sat parked across a cycle which collected the same device is
    older than the picture it would overwrite. It is settled against the run that
    superseded it, its raw file kept, and named in the detail."""
    settings, cycle = rig(observed={"vyos:r1": 500})
    edge = _prepared(settings, "edge", "r1")
    coll.park(edge.units[0].collector, {"host": "r1"}, source_name="edge", fetch_ts_ms=100)
    (payload,) = rawstore.parked(settings.raw_dir)

    detail, ran, key, _ = runs_exec.build_device_run(settings, [edge])

    assert (key, ran) == (None, [])  # nothing left to apply, so no run
    assert cycle.meta is None and cycle.pointer == PREV
    assert "superseded, not applied" in detail
    assert _sidecar(payload) == {"snapshot_ts": None, "superseded_by": PREV}
    assert payload.path.is_file() and rawstore.parked(settings.raw_dir) == []


def test_a_payload_newer_than_the_parent_runs_view_is_applied(rig, tmp_path):
    """The other side of the comparison: the parent run observed this device
    before the payload was fetched, so the payload is the newer truth."""
    settings, cycle = rig(observed={"vyos:r1": 100})
    edge = _prepared(settings, "edge", "r1")
    coll.park(edge.units[0].collector, {"host": "r1"}, source_name="edge", fetch_ts_ms=500)

    _, ran, key, _ = runs_exec.build_device_run(settings, [edge])

    assert key == NEW and [d.host for _, d, _ in ran] == ["r1"]
    assert cycle.meta["statuses"] == {"edge": "fresh"}


def test_a_failed_run_leaves_its_whole_window_parked(rig, tmp_path, monkeypatch):
    """The join sidecars are written after the run publishes. A run that raises in
    a derivation published nothing."""
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")

    def boom(s: Any, cts: int, scope: str = "") -> dict[str, int]:
        raise RuntimeError("route-target derivation blew up")

    monkeypatch.setattr(cycle, "cycle_counts", boom)

    with pytest.raises(RuntimeError, match="route-target derivation blew up"):
        runs_exec.build_device_run(settings, [edge])

    assert cycle.pointer == PREV
    assert [p.host for p in rawstore.parked(settings.raw_dir)] == ["r1"]


def test_a_device_run_moves_the_pointer_last(rig, tmp_path):
    """The same order every builder runs (core/cycle.py): the run is complete,
    meta node and site edges included, before the pointer names it."""
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")

    runs_exec.build_device_run(settings, [edge])

    assert cycle.steps == ["apply_site_assignments", "write_cycle_meta", "set_pointer"]


# --- a controller source's parked payloads -----------------------------------------------

FETCHED = 1_700_000_000_000


def _controller(settings: Settings, name: str) -> runs_exec.PreparedSource:
    """An orchestrator row with no host and no device rows: its one unit is the
    controller itself, and its payloads sit directly under `<source>/`."""
    row = Source(1, name, "vyos", {}, b"", True, NOW, NOW)
    unit = runs_exec.PreparedDevice(None, _DevCollector(_HostCfg(host="", source_name=name), settings), None)
    return runs_exec.PreparedSource(row, [unit])


def _park_controller(source: runs_exec.PreparedSource, fetched: int) -> None:
    coll.park(source.units[0].collector, {"host": ""}, source_name=source.row.name, fetch_ts_ms=fetched)


def test_a_parked_controller_payload_joins_the_next_device_run(rig, tmp_path):
    """A scheduled fetch of an orchestrator parks its payload under the source
    directory; the device run picks it up like a device's."""
    settings, cycle = rig()
    ctrl = _controller(settings, "ctrl")
    _park_controller(ctrl, FETCHED)
    (payload,) = rawstore.parked(settings.raw_dir)
    assert (payload.source, payload.host) == ("ctrl", "")

    detail, ran, key, _ = runs_exec.build_device_run(settings, [ctrl])

    assert key == NEW and cycle.pointer == NEW
    assert [row.name for row, _device, _collector in ran] == ["ctrl"]
    assert cycle.collected == {"vyos:"}
    assert cycle.meta["statuses"] == {"ctrl": "fresh"}
    assert f"ctrl {payload.run_id}:" in detail
    assert rawstore.parked(settings.raw_dir) == []
    meta = payload.path.with_name(payload.run_id + rawstore.META_SUFFIX)
    assert json.loads(meta.read_text()) == {"snapshot_ts": NEW}


def test_the_newest_parked_controller_payload_is_applied_and_older_ones_are_superseded(rig, tmp_path):
    settings, _cycle = rig()
    ctrl = _controller(settings, "ctrl")
    for offset in (0, 1_000, 2_000):
        _park_controller(ctrl, FETCHED + offset)
    oldest, middle, newest = sorted(rawstore.parked(settings.raw_dir), key=lambda p: p.fetch_ts_ms)

    detail, _ran, key, _ = runs_exec.build_device_run(settings, [ctrl])

    assert key == NEW
    assert json.loads(newest.path.with_name(newest.run_id + rawstore.META_SUFFIX).read_text()) == {
        "snapshot_ts": NEW
    }
    for older in (oldest, middle):
        settled = json.loads(older.path.with_name(older.run_id + rawstore.META_SUFFIX).read_text())
        assert settled == {"snapshot_ts": None, "superseded_by": NEW}
        assert f"ctrl {older.run_id}: superseded by {newest.run_id} in this window" in detail
    assert rawstore.parked(settings.raw_dir) == []


def test_payloads_older_than_the_runs_observation_are_all_settled_not_one_per_window(rig, tmp_path):
    """Payloads stranded before the parent run's observation (a cycle collected
    the controller after them) are superseded by the parent run together: the
    newest is older than the observation, and so are those it won against."""
    settings, _cycle = rig(observed={"vyos:": FETCHED + 10_000})
    ctrl = _controller(settings, "ctrl")
    for offset in (0, 1_000, 2_000):
        _park_controller(ctrl, FETCHED + offset)
    stranded = rawstore.parked(settings.raw_dir)

    detail, ran, key, _ = runs_exec.build_device_run(settings, [ctrl])

    assert (key, ran) == (None, [])
    assert "skipped: no parked payload this window could apply" in detail
    for payload in stranded:
        settled = json.loads(payload.path.with_name(payload.run_id + rawstore.META_SUFFIX).read_text())
        assert settled == {"snapshot_ts": None, "superseded_by": PREV}
    assert rawstore.parked(settings.raw_dir) == []
