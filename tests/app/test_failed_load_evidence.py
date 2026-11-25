"""A device load that fails part way, and a parked payload as a skip basis."""

from __future__ import annotations

import contextlib
import importlib
from datetime import UTC, datetime
from types import SimpleNamespace

from tests.app import test_device_run
from tests.app.test_device_run import _DevCollector, _HostCfg, _park, _prepared

from hst import collectors as coll
from hst.app import runs_exec
from hst.collectors import base as collbase
from hst.core import loader, rawstore
from hst.core import manifest as manifestmod
from hst.core.model import SectionOutcome, TableOutcome
from hst.path.gates import Stage, _Trail
from hst.path.gates.coverage import policy_evidence

trace = importlib.import_module("hst.path.trace")
rig = test_device_run.rig  # the shared fixture: real settings and raw store, the graph stubbed
NEW = 2_000


def _write_then_fail(session, exc: Exception):
    """One node chunk commits, then the next statement fails after its
    retries: a transaction memory limit, a lock timeout, a constraint error."""
    session.execute_write(
        lambda tx: tx.run("UNWIND $rows AS r MERGE (n:Device {uid: r.uid})", rows=[]).data()
    )
    raise exc


def _graph_write_fails(monkeypatch) -> None:
    def load(session, batch, **kwargs):
        _write_then_fail(session, RuntimeError("transaction memory limit reached"))

    monkeypatch.setattr(collbase, "load", load)


class _Unreachable(_DevCollector):
    def fetch(self):
        raise ConnectionError("no route to host")


# --- the failure paths record that the load began ---------------------------------------


def test_a_cycle_load_that_raised_after_its_raw_write_records_that_it_began(rig, monkeypatch):
    settings, _cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2", "r3", bad="r3")
    edge.units[1] = runs_exec.PreparedDevice(
        edge.units[1].device, _Unreachable(_HostCfg(host="r2", source_name="edge"), settings), None
    )
    _graph_write_fails(monkeypatch)
    outcomes: list[runs_exec.DeviceOutcome] = []
    evidence = runs_exec.RunEvidence(settings)

    statuses, _details, _ran, _carry, scopes = runs_exec._collect_sources(
        test_device_run._Session(), [edge], {"edge"}, {}, NEW, outcomes.append, evidence
    )

    assert statuses == {"edge": "failed"}
    assert scopes.reasons == {"vyos:r1": "failed", "vyos:r2": "failed", "vyos:r3": "failed"}
    by_host = {o.host: o for o in outcomes}
    # r1's graph write raised after one chunk committed
    assert by_host["r1"].ok is False and by_host["r1"].ingested_ms is not None
    assert "transaction memory limit" in by_host["r1"].error
    # r2's fetch failed: nothing was written, the carry brings it whole
    assert by_host["r2"].ok is False and by_host["r2"].ingested_ms is None
    # r3 got past its raw write and failed in normalize: no graph write
    assert by_host["r3"].ok is False and by_host["r3"].ingested_ms is None


def test_a_device_run_join_that_raised_reaches_the_trace_as_a_failed_load(rig, monkeypatch):
    """r1 joins, r2's graph write raises: the published run's entry for r2
    reads failed with `ingested_ms`, maps the device's uid, and the
    coverage check reads it as a failed load."""
    settings, _cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2")
    _park(edge, "r1")
    _park(edge, "r2")
    real = collbase.load

    def load(session, batch, **kwargs):
        if any(n.uid == "dev:r2" for n in batch.nodes):
            _write_then_fail(session, RuntimeError("transaction memory limit reached"))
        return real(session, batch, **kwargs)

    monkeypatch.setattr(collbase, "load", load)
    outcomes: list[runs_exec.DeviceOutcome] = []

    detail, _ran, key, _ = runs_exec.build_device_run(settings, [edge], outcomes=outcomes)

    assert key == NEW, detail
    assert "transaction memory limit" in detail
    failed = next(o for o in outcomes if o.host == "r2")
    assert failed.ok is False and failed.ingested_ms is not None
    entry = next(d for d in manifestmod.read(settings, NEW).devices if d.host == "r2")
    assert entry.outcome == "failed" and entry.ingested_ms is not None
    assert "dev:r2" in entry.device_uids
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="edge", type="vyos")])
    session = SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))
    monkeypatch.setattr(
        "hst.path._read",
        lambda _session, query, **_params: [{"host": "r2", "source": "edge", "scope": "vyos:r2"}],
    )
    gaps, note = policy_evidence(session, "dev:r2")
    assert gaps == ["device=load failed"]
    assert note is not None and "load in this run failed" in note


def test_a_device_run_join_that_landed_records_when_it_loaded(rig):
    settings, _cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    _park(edge, "r1")
    outcomes: list[runs_exec.DeviceOutcome] = []

    runs_exec.build_device_run(settings, [edge], outcomes=outcomes)

    (outcome,) = outcomes
    assert outcome.ok is True and outcome.ingested_ms is not None
    entry = next(d for d in manifestmod.read(settings, NEW).devices if d.host == "r1")
    assert entry.outcome == "collected" and entry.ingested_ms is not None


# --- the trace reads a failed load as undecided -----------------------------------------


def _entry(**overrides) -> manifestmod.DeviceEntry:
    fields = {
        "source": "edge",
        "host": "router-1",
        "outcome": "failed",
        "effective_run": "900-abcdef12",
        "carried": True,
        "sections": {"config": SectionOutcome(status="ok")},
        "device_uids": ["dev:1"],
    }
    fields.update(overrides)
    return manifestmod.DeviceEntry(**fields)


def _session(entry: manifestmod.DeviceEntry) -> SimpleNamespace:
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="edge", type="vyos")])
    return SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))


def _install(monkeypatch) -> None:
    monkeypatch.setattr(trace, "aci_contract_verdict", lambda *_args: None)
    monkeypatch.setattr(trace, "unevaluated_gates", lambda *_args: [])
    monkeypatch.setattr(
        "hst.path._read",
        lambda _session, query, **_params: (
            [{"host": "router-1", "source": "edge", "scope": "vyos:router-1"}]
            if "RETURN d.hostname AS host" in query
            else []
        ),
    )


def _flow(session):
    trail = _Trail()
    trail.hop("dev:1", "Device", "router-1", stage=Stage.DEVICE)
    legs = [{"verdict": "forwarded", "blocked": False}]
    verdict = trace._flow_gates(
        session, trail, legs, "10.0.0.1 → 10.0.0.2: forwarded", "10.0.0.1", "10.0.0.2", 443, "tcp"
    )
    return trail, legs, verdict


def test_a_failed_load_makes_the_leg_undecided_and_names_the_failed_load(monkeypatch):
    """The device run's failed join: its raw file is not this run's, so the
    entry reads carried, with the prior run's clean sections copied in."""
    _install(monkeypatch)
    trail, legs, verdict = _flow(_session(_entry(ingested_ms=1_234)))
    assert legs[0]["indeterminate"] is True
    assert "device=load failed" in legs[0]["indeterminate_reason"]
    assert any("load in this run failed" in w for w in trail.warnings)
    assert "policy of 1 device(s) not collected completely" in verdict


def test_a_cycle_load_that_failed_after_its_raw_write_is_undecided(monkeypatch):
    _install(monkeypatch)
    entry = _entry(carried=False, effective_run="2000-abcdef12", sections={}, ingested_ms=1_234)
    _trail, legs, _verdict = _flow(_session(entry))
    assert legs[0]["indeterminate"] is True
    assert "device=load failed" in legs[0]["indeterminate_reason"]


def test_a_landed_load_judged_failed_is_undecided(monkeypatch):
    """An authoritative section that did not come back fails a load that
    landed: the carry fills what it left absent, the same mix."""
    _install(monkeypatch)
    entry = _entry(carried=False, sections={"config": SectionOutcome(status="ok")}, ingested_ms=1_234)
    gaps, _note = policy_evidence(_session(entry), "dev:1")
    assert gaps == ["device=load failed"]


def test_a_failed_fetch_with_the_device_carried_whole_stays_a_note(monkeypatch):
    _install(monkeypatch)
    trail, legs, _verdict = _flow(_session(_entry()))
    assert not legs[0].get("indeterminate")
    assert any("policy is the copy from run 900-abcdef12" in note for note in trail.notes)


def test_a_collected_or_carried_device_gets_no_new_warning(monkeypatch):
    _install(monkeypatch)
    for entry in (
        _entry(outcome="collected", carried=False, ingested_ms=1_234),
        _entry(outcome="unchanged", carried=True),
        _entry(outcome="carried", carried=True),
    ):
        trail, legs, _verdict = _flow(_session(entry))
        assert not legs[0].get("indeterminate"), entry.outcome
        assert trail.warnings == [], entry.outcome


# --- a parked payload is no skip basis --------------------------------------------------


def _decide(settings, unit, status) -> runs_exec._Fetched:
    fetched = runs_exec._fetch_phase(settings, [("edge", unit)], {("edge", "r1"): status}, True)
    return fetched[id(unit)]


def _status(sha: str) -> SimpleNamespace:
    return SimpleNamespace(
        last_raw_sha=sha,
        last_obs_sha="",
        last_full_at=datetime.now(UTC),
        last_graph_sha="",
        last_graph_at=None,
    )


def test_a_cycle_does_not_skip_a_device_whose_payload_is_parked(rig):
    settings, _cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    unit = edge.units[0]
    sha = coll.raw_sha(unit.collector, {"host": "r1"})
    # a device job parked this payload and recorded its hash; no device run
    # has loaded it, so the graph still holds the device's older load
    _park(edge, "r1")
    assert _decide(settings, unit, _status(sha)).skipped is False


def test_a_cycle_skips_an_unchanged_device_with_nothing_parked(rig):
    settings, _cycle = rig()
    edge = _prepared(settings, "edge", "r1")
    unit = edge.units[0]
    sha = coll.raw_sha(unit.collector, {"host": "r1"})
    assert _decide(settings, unit, _status(sha)).skipped is True


# --- the mark outlives the run whose load failed ----------------------------------------


def _trace_across(record, uid: str, host: str, monkeypatch):
    monkeypatch.setattr(trace, "aci_contract_verdict", lambda *_args: None)
    monkeypatch.setattr(trace, "unevaluated_gates", lambda *_args: [])
    monkeypatch.setattr(
        "hst.path._read",
        lambda _session, query, **_params: (
            [{"host": host, "source": "edge", "scope": f"vyos:{host}"}]
            if "RETURN d.hostname AS host" in query
            else []
        ),
    )
    # the test collector records no sections, so its source is read as one
    # with no policy-section contract: what is left is the device's outcome
    manifest = SimpleNamespace(devices=record.devices, sources=[SimpleNamespace(name="edge", type="test")])
    session = SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))
    trail = _Trail()
    trail.hop(uid, "Device", host, stage=Stage.DEVICE)
    legs = [{"verdict": "forwarded", "blocked": False}]
    trace._flow_gates(session, trail, legs, "a → b: forwarded", "10.0.0.1", "10.0.0.2", 443, "tcp")
    return trail, legs


def test_the_failed_load_mark_carries_until_a_full_load_succeeds(rig, monkeypatch):
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2", "r3")
    real = collbase.load

    def r2_fails(session, batch, **kwargs):
        if any(n.uid == "dev:r2" for n in batch.nodes):
            _write_then_fail(session, RuntimeError("lock timeout"))
        return real(session, batch, **kwargs)

    # run A: r2's load raises part way
    _park(edge, "r1")
    _park(edge, "r2")
    _park(edge, "r3")
    monkeypatch.setattr(collbase, "load", r2_fails)
    runs_exec.build_device_run(settings, [edge])
    run_a = manifestmod.read(settings, NEW)
    assert {d.host: d.mixed_since for d in run_a.devices} == {"r1": None, "r2": str(NEW), "r3": None}

    # run B: r2 is not reloaded (its payload settled elsewhere), only r1 joins;
    # r2 carries the mixed state and its entry reads 'carried'
    for payload in rawstore.parked(settings.raw_dir):
        rawstore.mark_joined(payload.path, snapshot_ts=NEW)
    _park(edge, "r1")
    monkeypatch.setattr(cycle, "new_collection_ts", lambda: 3_000)
    runs_exec.build_device_run(settings, [edge])
    run_b = manifestmod.read(settings, 3_000)
    r2 = next(d for d in run_b.devices if d.host == "r2")
    assert r2.outcome == "carried" and r2.ingested_ms is None
    assert r2.mixed_since == str(NEW)
    trail, legs = _trace_across(run_b, "dev:r2", "r2", monkeypatch)
    assert legs[0]["indeterminate"] is True
    assert "device=load failed" in legs[0]["indeterminate_reason"]
    assert any(f"load in run {NEW} failed" in w for w in trail.warnings)
    # r3 loaded in run A and is carried whole: no warning
    trail, legs = _trace_across(run_b, "dev:r3", "r3", monkeypatch)
    assert not legs[0].get("indeterminate") and trail.warnings == []

    # run C: a full load of r2 succeeds and clears the mark
    monkeypatch.setattr(collbase, "load", real)
    _park(edge, "r2")
    monkeypatch.setattr(cycle, "new_collection_ts", lambda: 4_000)
    runs_exec.build_device_run(settings, [edge])
    r2 = next(d for d in manifestmod.read(settings, 4_000).devices if d.host == "r2")
    assert r2.outcome == "collected" and r2.mixed_since is None
    trail, legs = _trace_across(manifestmod.read(settings, 4_000), "dev:r2", "r2", monkeypatch)
    assert not legs[0].get("indeterminate") and trail.warnings == []


def _outcome(**kw) -> runs_exec.DeviceOutcome:
    return runs_exec.DeviceOutcome("edge", "r1", kw.pop("ok", True), **kw)


def test_only_a_whole_successful_full_load_clears_the_mark():
    prior = _entry(mixed_since="2000")
    keep = [
        None,  # no outcome: carried
        _outcome(ok=False, error="fetch failed"),  # failed fetch
        _outcome(skipped=True),  # unchanged against a basis that may predate the failure
        _outcome(observations_only=True),
    ]
    for outcome in keep:
        assert runs_exec._mixed_since(outcome, prior, 3_000) == "2000"
    assert runs_exec._mixed_since(_outcome(full=True), prior, 3_000) is None
    assert runs_exec._mixed_since(_outcome(ok=False, ingested_ms=5), prior, 3_000) == "3000"
    assert runs_exec._mixed_since(_outcome(skipped=True), None, 3_000) is None


def test_an_entry_without_the_mark_serializes_without_the_field():
    plain = _entry()
    dumped = plain.model_dump(mode="json")
    assert "mixed_since" not in dumped
    assert manifestmod.canonical_json(dumped) == manifestmod.canonical_json(
        {k: v for k, v in _entry(mixed_since="2000").model_dump(mode="json").items() if k != "mixed_since"}
    )
    marked = _entry(mixed_since="2000")
    assert manifestmod.DeviceEntry.model_validate_json(marked.model_dump_json()).mixed_since == "2000"
    # a manifest entry without the field reads with no mark
    assert manifestmod.DeviceEntry.model_validate_json(plain.model_dump_json()).mixed_since is None


# --- a mark only after a write, cleared by a full load, a cancel after a write ---------


def test_a_join_that_fails_before_any_graph_write_stays_a_note(rig, monkeypatch):
    """r2's payload cannot be normalized, so nothing of r2 was written and
    the carry brings it whole: no load-failed mark."""
    settings, _cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2", bad="r2")
    _park(edge, "r1")
    _park(edge, "r2")
    outcomes: list[runs_exec.DeviceOutcome] = []

    runs_exec.build_device_run(settings, [edge], outcomes=outcomes)

    failed = next(o for o in outcomes if o.host == "r2")
    assert failed.ok is False and failed.ingested_ms is None
    record = manifestmod.read(settings, NEW)
    assert next(d for d in record.devices if d.host == "r2").mixed_since is None
    trail, legs = _trace_across(record, "dev:r2", "r2", monkeypatch)
    assert "device=load failed" not in str(legs[0].get("indeterminate_reason"))
    assert not any("load" in w and "failed" in w for w in trail.warnings)


class _CountingSession(test_device_run._Session):
    """A stand-in graph that reports update counters as the server does:
    the loader's reads (anchor check, shared objects) change nothing."""

    def __init__(self, shared: tuple[str, ...] = ()) -> None:
        self.shared = shared

    def run(self, q: str, **p):
        inner = super().run(q, **p)
        reads = (loader.CYCLE_ANCHOR_CHECK, collbase.SHARED_OBJECTS)
        shared = self.shared

        class _Result:
            def data(self_inner):
                if q == collbase.SHARED_OBJECTS:
                    return [{"uid": uid} for uid in shared]
                return inner.data()

            def consume(self_inner):
                return SimpleNamespace(counters=SimpleNamespace(contains_updates=q not in reads))

        return _Result()


def test_a_read_through_a_write_transaction_is_not_a_graph_write():
    ws = runs_exec._GraphWrites(_CountingSession())
    ws.execute_write(lambda tx: tx.run(loader.CYCLE_ANCHOR_CHECK, rows=[], cts=1).data())
    ws.execute_write(lambda tx: tx.run(collbase.SHARED_OBJECTS, uids=["dev:r1"], prev=1, cts=2).data())
    assert ws.began is False
    ws.execute_write(lambda tx: tx.run("UNWIND $rows AS r MERGE (n:X {uid: r.uid})", rows=[]).data())
    assert ws.began is True


def _kept_load(settings, monkeypatch, shared: tuple[str, ...]):
    """A kept-path load (the batch digests as the one on record) whose side
    tables then fail, as a later failure or cancel cuts it."""
    collector = _DevCollector(_HostCfg(host="r1", source_name="edge"), settings)

    def side_tables_fail(*_a, **_k):
        raise RuntimeError("side store unavailable")

    monkeypatch.setattr(collbase, "_write_side_tables", side_tables_fail)
    ws = runs_exec._GraphWrites(_CountingSession(shared))
    with contextlib.suppress(RuntimeError):
        coll.load_payload(
            collector,
            ws,
            {"host": "r1"},
            collection_ts=NEW,
            run_id="1999-abcdef12",
            ts_ms=1_999,
            source_name="edge",
            graph_gate=collbase.GraphGate(matches=lambda _digest: True, parent_ts=1_000),
        )
    return ws


def test_a_kept_load_that_then_fails_wrote_nothing(rig, monkeypatch):
    """The shared-objects read ran in a write transaction and the shared
    part was empty, so nothing of the device was written."""
    settings, _cycle = rig()
    assert _kept_load(settings, monkeypatch, shared=()).began is False


def test_a_kept_load_that_wrote_its_shared_part_then_failed_marks(rig, monkeypatch):
    settings, _cycle = rig()
    assert _kept_load(settings, monkeypatch, shared=("dev:r1",)).began is True


def test_a_write_transaction_that_raised_is_not_a_committed_write():
    class _Raising(test_device_run._Session):
        def execute_write(self, work):
            work(self)
            raise RuntimeError("rolled back")

    ws = runs_exec._GraphWrites(_Raising())
    with contextlib.suppress(RuntimeError):
        ws.execute_write(lambda tx: tx.run("MERGE (n:X)").data())
    assert ws.began is False


class _Labelled(_DevCollector):
    SECTION_LABELS = {"lldp": ("LldpNeighbor",)}


def test_a_successful_full_load_clears_the_mark_unless_a_section_carries_from_the_mix(rig):
    settings, _cycle = rig()
    collector = _Labelled(_HostCfg(host="r1", source_name="edge"), settings)
    prior = _entry(mixed_since="2000")
    ok = SectionOutcome(status="ok")
    # a side table that did not land does not touch the graph: cleared
    partial_tables = _outcome(
        full=True, sections={"config": ok}, tables={"arp": TableOutcome(status="failed")}
    )
    assert partial_tables.completeness == "partial"
    assert runs_exec._mixed_since(partial_tables, prior, 3_000, collector) is None
    # a failed section with no labels of its own carries nothing: cleared
    no_labels = _outcome(full=True, sections={"config": ok, "bgp": SectionOutcome(status="failed")})
    assert runs_exec._mixed_since(no_labels, prior, 3_000, collector) is None
    # a failed section whose labels carry from the parent (the mixed state): kept
    lldp = _outcome(full=True, sections={"config": ok, "lldp": SectionOutcome(status="failed")})
    assert runs_exec._mixed_since(lldp, prior, 3_000, collector) == "2000"


def test_a_source_cancel_after_the_load_wrote_marks_the_device(rig, monkeypatch):
    """A per-source cancel cuts the load after its batch committed; the run
    publishes with that source's devices carried, so the write and the
    carry mix, and the entry is marked as a failed load's is."""
    settings, _cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2", bad="r2")
    real = collbase.load

    def load(session, batch, **kwargs):
        real(session, batch, **kwargs)
        raise collbase.CollectionStopped("source edge cancelled")

    monkeypatch.setattr(collbase, "load", load)
    monkeypatch.setattr(
        runs_exec, "_cut_by_cancel", lambda exc, stop, name: isinstance(exc, collbase.CollectionStopped)
    )
    outcomes: list[runs_exec.DeviceOutcome] = []
    evidence = runs_exec.RunEvidence(settings)

    statuses, *_ = runs_exec._collect_sources(
        test_device_run._Session(), [edge], {"edge"}, {}, NEW, outcomes.append, evidence
    )

    assert statuses == {"edge": runs_exec.CANCELLED}
    assert evidence.mixed_loads == {("edge", "r1")}
    entries = {e.host: e for e in runs_exec._device_entries(settings, NEW, None, [edge], statuses, evidence)}
    assert entries["r1"].mixed_since == str(NEW)
    assert entries["r2"].mixed_since is None
