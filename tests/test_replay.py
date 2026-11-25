"""Point-in-time reconstruction by replaying raw snapshots."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import pytest

from hst.app.crypto import dek, generate_key
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import manifest, rawstore, replay, uid
from hst.core.config import Settings
from hst.core.model import Batch

KEY = generate_key()

MARCH = 1_772_000_000_000  # ~2026-02-25
APRIL = 1_775_000_000_000  # ~2026-03-31
MAY = 1_778_000_000_000  # ~2026-05-05


def _settings(tmp_path):
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=KEY)


def _write(settings, source, ts, payload, host="", nonce="abc12345"):
    # A run id carries no source segment.
    return rawstore.write(settings.raw_dir, source, f"{ts}-{nonce}", payload, host=host, key=dek(settings))


# --- run id parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expect",
    [
        ("1784527461005-b3054969", 1784527461005),
        ("1784527461005-b305496900", 1784527461005),  # a longer nonce still parses
        # an id with a collector-name or source segment does not parse
        ("vyos-1784527461005-b3054969", None),
        ("check-point-1784527461005-b3054969", None),
        ("fixture-mini-dc-1784527461", None),  # no hex nonce: not a collector run
        ("garbage", None),
    ],
)
def test_parse_run_id(name, expect):
    assert replay.parse_run_id(name) == expect


# --- listing and selection --------------------------------------------------------


def test_snapshots_are_grouped_by_source_newest_first(tmp_path):
    s = _settings(tmp_path)
    for ts in (MARCH, MAY, APRIL):
        _write(s, "vyos", ts, {"n": ts})
    _write(s, "unifi", APRIL, {"n": 1})

    found = replay.list_snapshots(s.raw_dir)
    assert sorted(found) == ["unifi", "vyos"]
    assert [x.ts_ms for x in found["vyos"]] == [MAY, APRIL, MARCH]


def test_the_source_comes_from_the_directory_not_the_parsed_name(tmp_path):
    s = _settings(tmp_path)
    _write(s, "check-point", APRIL, {"n": 1})
    assert list(replay.list_snapshots(s.raw_dir)) == ["check-point"]


def test_plan_picks_the_newest_snapshot_at_or_before_the_target(tmp_path):
    s = _settings(tmp_path)
    for ts in (MARCH, APRIL, MAY):
        _write(s, "vyos", ts, {"n": ts})

    selected, missing = replay.plan(s.raw_dir, APRIL)
    assert [x.ts_ms for x in selected] == [APRIL]
    assert missing == []

    # exactly on the boundary counts as at-or-before
    selected, _ = replay.plan(s.raw_dir, APRIL - 1)
    assert [x.ts_ms for x in selected] == [MARCH]


def test_a_source_with_nothing_old_enough_is_reported_not_dropped(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"n": 1})
    _write(s, "zscaler", MAY, {"n": 1})

    selected, missing = replay.plan(s.raw_dir, APRIL)
    assert [x.source for x in selected] == ["vyos"]
    assert missing == ["zscaler"]


def test_plan_orders_oldest_first(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", APRIL, {"n": 1})
    _write(s, "unifi", MARCH, {"n": 1})
    selected, _ = replay.plan(s.raw_dir, MAY)
    assert [x.source for x in selected] == ["unifi", "vyos"]


def test_an_empty_raw_dir_is_not_an_error(tmp_path):
    s = _settings(tmp_path)
    assert replay.plan(s.raw_dir, APRIL) == ([], [])


# --- per-(source, host) selection --------------------------------------------------


def test_list_snapshots_records_the_host_each_file_was_found_under(tmp_path):
    s = _settings(tmp_path)
    _write(s, "fleet", APRIL, {"n": 1}, host="r1")
    _write(s, "fleet", MARCH, {"n": 1}, host="r2")
    found = replay.list_snapshots(s.raw_dir)
    assert sorted((x.host, x.ts_ms) for x in found["fleet"]) == [("r1", APRIL), ("r2", MARCH)]


def test_a_host_less_write_records_an_empty_host(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", APRIL, {"n": 1})
    (snap,) = replay.list_snapshots(s.raw_dir)["vyos"]
    assert snap.host == ""


def test_plan_selects_one_per_source_and_host_not_one_per_source_directory(tmp_path):
    """`plan` picks one file per (source, host)."""
    s = _settings(tmp_path)
    _write(s, "vyos1", APRIL, {"n": 1})  # two sources of one collector type
    _write(s, "vyos2", APRIL, {"n": 1})
    _write(s, "fleet", APRIL, {"n": 1}, host="r1")  # one source, two hosts
    _write(s, "fleet", MARCH, {"n": 1}, host="r2")

    selected, missing = replay.plan(s.raw_dir, MAY)
    assert missing == []
    assert sorted((x.source, x.host) for x in selected) == [
        ("fleet", "r1"),
        ("fleet", "r2"),
        ("vyos1", ""),
        ("vyos2", ""),
    ]


def test_plan_picks_the_newest_eligible_snapshot_independently_per_host(tmp_path):
    s = _settings(tmp_path)
    _write(s, "fleet", MARCH, {"gen": "old"}, host="r1")
    _write(s, "fleet", APRIL, {"gen": "new"}, host="r1")
    _write(s, "fleet", MARCH, {"gen": "only"}, host="r2")

    selected, _ = replay.plan(s.raw_dir, MAY)
    by_host = {snap.host: snap.path for snap in selected}
    assert len(selected) == 2
    assert rawstore.read(by_host["r1"], dek(s)) == {"gen": "new"}
    assert rawstore.read(by_host["r2"], dek(s)) == {"gen": "only"}


def test_missing_reports_the_bare_source_name_for_a_host_less_source(tmp_path):
    s = _settings(tmp_path)
    _write(s, "zscaler", MAY, {"n": 1})
    _, missing = replay.plan(s.raw_dir, APRIL)
    assert missing == ["zscaler"]


def test_missing_names_the_host_for_a_per_device_source(tmp_path):
    s = _settings(tmp_path)
    _write(s, "fleet", MAY, {"n": 1}, host="r1")  # too new for the target
    selected, missing = replay.plan(s.raw_dir, APRIL)
    assert selected == []
    assert missing == ["fleet/r1"]


def test_one_hosts_missing_snapshot_does_not_hide_another_hosts_hit(tmp_path):
    s = _settings(tmp_path)
    _write(s, "fleet", MARCH, {"n": 1}, host="r1")
    _write(s, "fleet", MAY, {"n": 1}, host="r2")  # too new
    selected, missing = replay.plan(s.raw_dir, APRIL)
    assert [(x.source, x.host) for x in selected] == [("fleet", "r1")]
    assert missing == ["fleet/r2"]


# --- rebuild ----------------------------------------------------------------------


class FakeCollector:
    """Stands in for a real collector: normalize is a pure function of the payload."""

    def __init__(self, source):
        self.source = source
        self.seen = []

    def normalize(self, payload):
        self.seen.append(payload)
        return Batch(source=self.source, scope=f"{self.source}:test", nodes=[], rels=[])

    def side_tables(self, raw):
        return {}  # matches Collector's own default: no side tables


class RecordingSession:
    def __init__(self):
        self.loads = []

    def execute_write(self, work, *args, **kw):
        # loader.load runs each statement in a managed transaction; the fake session
        # doubles as its own tx.
        return work(self, *args, **kw)

    def execute_read(self, work, *args, **kw):
        # `core.reasoner._read_cycle` passes the query and its parameters through the session.
        return work(self, *args, **kw)

    def run(self, q, **p):
        self.loads.append((q, p))
        return _Result()


class _Result:
    def data(self):
        return []

    def consume(self):
        return None


def test_rebuild_replays_the_historical_payload_not_the_current_one(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"rule": "accept"})
    _write(s, "vyos", MAY, {"rule": "drop"})  # today's state

    collector = FakeCollector("vyos")
    report = replay.rebuild(s, RecordingSession(), APRIL, collector_for=lambda src: collector)

    assert report.ok
    assert [x.ts_ms for x in report.replayed] == [MARCH]
    assert collector.seen == [{"rule": "accept"}]


def test_rebuild_stamps_the_snapshots_own_timestamp(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"n": 1})
    session = RecordingSession()
    report = replay.rebuild(s, session, APRIL, collector_for=lambda src: FakeCollector(src))

    assert report.manifests[0].run_id == f"{MARCH}-abc12345"  # no source segment
    timestamps = {p.get("ts") for _, p in session.loads if "ts" in p}
    assert timestamps == {MARCH}


def test_rebuild_does_not_retire(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"n": 1})
    session = RecordingSession()
    replay.rebuild(s, session, APRIL, collector_for=lambda src: FakeCollector(src))
    assert not any("_retired_at = $ts" in q for q, _ in session.loads)


def test_a_source_that_no_longer_exists_is_a_failure_not_a_silent_skip(tmp_path):
    s = _settings(tmp_path)
    _write(s, "retired-collector", MARCH, {"n": 1})
    report = replay.rebuild(s, RecordingSession(), APRIL, collector_for=lambda src: None)
    assert not report.ok
    assert report.failed[0][0] == "retired-collector"
    assert "cannot normalize" in report.failed[0][1]


def test_a_normalize_failure_does_not_abort_the_other_sources(tmp_path):
    s = _settings(tmp_path)
    _write(s, "good", MARCH, {"n": 1})
    _write(s, "bad", MARCH, {"n": 1})

    class Exploding(FakeCollector):
        def normalize(self, payload):
            raise ValueError("vendor payload changed shape")

    report = replay.rebuild(
        s,
        RecordingSession(),
        APRIL,
        collector_for=lambda src: Exploding(src) if src == "bad" else FakeCollector(src),
    )
    assert [x.source for x in report.replayed] == ["good"]
    assert report.failed == [("bad", "ValueError: vendor payload changed shape")]
    assert not report.ok


def test_dry_run_reads_and_normalizes_but_writes_nothing(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"n": 1})
    session = RecordingSession()
    report = replay.rebuild(s, session, APRIL, collector_for=lambda src: FakeCollector(src), dry_run=True)
    assert [x.source for x in report.replayed] == ["vyos"]
    assert session.loads == []


class _CountResult:
    def __init__(self, c):
        self._c = c

    def data(self):
        return [{"c": self._c}]

    def consume(self):
        return None


class ClearingSession(RecordingSession):
    """Reports a non-empty first delete batch, then empty ones."""

    def __init__(self, to_delete=3):
        super().__init__()
        self._remaining = to_delete

    def run(self, q, **p):
        self.loads.append((q, p))
        if "DETACH DELETE" in q:
            n = min(self._remaining, p["batch"])
            self._remaining -= n
            return _CountResult(n)
        return _Result()


def test_rebuild_clears_the_target_before_replaying(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"n": 1})
    session = ClearingSession(to_delete=3)
    report = replay.rebuild(s, session, APRIL, collector_for=lambda src: FakeCollector(src))
    assert report.cleared == 3
    assert "DETACH DELETE" in session.loads[0][0]


def test_dry_run_does_not_clear_the_target(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"n": 1})
    session = ClearingSession(to_delete=5)
    report = replay.rebuild(s, session, APRIL, collector_for=lambda src: FakeCollector(src), dry_run=True)
    assert report.cleared == 0
    assert not any("DETACH DELETE" in q for q, _ in session.loads)


def test_missing_sources_make_the_report_not_ok(tmp_path):
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"n": 1})
    _write(s, "zscaler", MAY, {"n": 1})
    report = replay.rebuild(s, RecordingSession(), APRIL, collector_for=lambda src: FakeCollector(src))
    assert report.missing == ["zscaler"]
    assert not report.ok


# --- manifest-driven replay -------------------------------------------------------


class _RibCollector(FakeCollector):
    """A FakeCollector whose side_tables produces one row, for the
    kept-file-missing-or-altered regeneration path."""

    def side_tables(self, raw):
        return {"rib": [{"device_uid": "dev:r1", "prefix": "0.0.0.0/0"}]}


def _snapshot_manifest(key, sources, devices, files, *, parent=None, site_assignments=None):
    return manifest.SnapshotManifest(
        snapshot_key=key,
        kind="full",
        parent=parent,
        opened=manifest.iso(key),
        published=manifest.iso(key),
        sources=sources,
        devices=devices,
        files=files,
        site_assignments=site_assignments or {},
    )


def _one_device_manifest(s, source, host, run_id, ts, files, *, config=None, carried=False, parent=None):
    """Write a two-entry manifest (one source, one device) naming `run_id` as
    the device's effective run."""
    digest = manifest.source_config_digest(source, source, True, config or {})
    status = "carried" if carried else "fresh"
    entry = manifest.SourceEntry(name=source, type=source, status=status, config_sha256=digest)
    device = manifest.DeviceEntry(
        source=source,
        host=host,
        outcome=status if carried else "collected",
        effective_run=run_id,
        fetch_ts_ms=ts,
        carried=carried,
    )
    record = _snapshot_manifest(2_000, [entry], [device], files, parent=parent)
    manifest.write(s, record)
    return record


def test_rebuild_from_manifest_replays_the_exact_recorded_file_even_when_a_newer_one_exists(tmp_path):
    s = _settings(tmp_path)
    old_path = _write(s, "vyos", MARCH, {"rule": "accept"})
    _write(s, "vyos", APRIL, {"rule": "drop"})  # newer, never named by the manifest
    run_id = f"{MARCH}-abc12345"
    _one_device_manifest(s, "vyos", "", run_id, MARCH, [manifest.file_entry(s, old_path)])

    collector = FakeCollector("vyos")
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={})
    report = replay.rebuild_from_manifest(s, RecordingSession(), 2_000, source_for=lambda name: lookup)

    assert report.ok
    assert collector.seen == [{"rule": "accept"}]
    assert [d.host for d in report.replayed] == [""]


def test_config_drift_refuses_replay_by_default(tmp_path):
    s = _settings(tmp_path)
    path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    record = _one_device_manifest(
        s, "vyos", "", run_id, MARCH, [manifest.file_entry(s, path)], config={"a": 1}
    )
    recorded_digest = record.sources[0].config_sha256

    collector = FakeCollector("vyos")
    # today's configuration differs ({"a": 2}), so its digest cannot match the recorded one
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={"a": 2})
    report = replay.rebuild_from_manifest(s, RecordingSession(), 2_000, source_for=lambda name: lookup)

    assert not report.ok
    assert collector.seen == []  # never normalized under a configuration the manifest never saw
    assert report.drift == []
    assert any("vyos" in why and recorded_digest in why for _source, why in report.failed)


def test_config_drift_allowed_replays_and_records_the_drift(tmp_path):
    s = _settings(tmp_path)
    path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    record = _one_device_manifest(
        s, "vyos", "", run_id, MARCH, [manifest.file_entry(s, path)], config={"a": 1}
    )
    recorded_digest = record.sources[0].config_sha256

    collector = FakeCollector("vyos")
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={"a": 2})
    report = replay.rebuild_from_manifest(
        s, RecordingSession(), 2_000, source_for=lambda name: lookup, allow_config_drift=True
    )

    assert report.ok
    assert collector.seen == [{"n": 1}]
    assert len(report.drift) == 1
    assert "vyos" in report.drift[0] and recorded_digest in report.drift[0]


def test_a_device_with_no_effective_run_is_reported_missing_not_replayed(tmp_path):
    """A device carried forward with no payload in any run at or before the
    snapshot has nothing to replay (manifest.py's DeviceEntry docstring)."""
    s = _settings(tmp_path)
    entry = manifest.SourceEntry(name="ctrl", type="ctrl", status="carried", config_sha256="x")
    device = manifest.DeviceEntry(source="ctrl", host="", outcome="carried", effective_run=None, carried=True)
    manifest.write(s, _snapshot_manifest(2_000, [entry], [device], []))

    report = replay.rebuild_from_manifest(s, RecordingSession(), 2_000, source_for=lambda name: None)
    assert report.missing == ["ctrl"]
    assert report.replayed == []
    assert not report.ok


def test_a_source_not_configured_today_fails_its_devices(tmp_path):
    s = _settings(tmp_path)
    path = _write(s, "retired", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    _one_device_manifest(s, "retired", "", run_id, MARCH, [manifest.file_entry(s, path)])

    report = replay.rebuild_from_manifest(s, RecordingSession(), 2_000, source_for=lambda name: None)
    assert not report.ok
    assert report.failed == [("retired", "no such source configured; cannot normalize")]


def test_dry_run_manifest_replay_writes_nothing(tmp_path):
    s = _settings(tmp_path)
    path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    _one_device_manifest(s, "vyos", "", run_id, MARCH, [manifest.file_entry(s, path)])

    collector = FakeCollector("vyos")
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={})
    session = RecordingSession()
    report = replay.rebuild_from_manifest(s, session, 2_000, source_for=lambda name: lookup, dry_run=True)

    assert [d.source for d in report.replayed] == ["vyos"]
    assert session.loads == []
    assert report.cleared == 0


def test_rebuild_from_manifest_clears_the_target_before_replaying(tmp_path):
    s = _settings(tmp_path)
    path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    _one_device_manifest(s, "vyos", "", run_id, MARCH, [manifest.file_entry(s, path)])

    collector = FakeCollector("vyos")
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={})
    session = ClearingSession(to_delete=2)
    report = replay.rebuild_from_manifest(s, session, 2_000, source_for=lambda name: lookup)
    assert report.cleared == 2


def test_rebuild_from_manifest_raises_when_there_is_no_manifest(tmp_path):
    s = _settings(tmp_path)
    with pytest.raises(FileNotFoundError):
        replay.rebuild_from_manifest(s, RecordingSession(), 999, source_for=lambda name: None)


def test_a_kept_side_store_file_that_verifies_is_read_in_place(tmp_path):
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    s = _settings(tmp_path)
    raw_path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    rib_path = sidestore.write_table(
        s.sidestore_dir, "rib", "vyos", "", run_id, [{"device_uid": "dev:r1", "prefix": "0.0.0.0/0"}], MARCH
    )
    files = [manifest.file_entry(s, raw_path), manifest.file_entry(s, rib_path)]
    _one_device_manifest(s, "vyos", "", run_id, MARCH, files)

    collector = FakeCollector("vyos")  # side_tables -> {}; must never be called
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={})
    scratch = tmp_path / "scratch"
    report = replay.rebuild_from_manifest(
        s, RecordingSession(), 2_000, source_for=lambda name: lookup, sidestore_scratch_dir=scratch
    )

    assert report.side_table_notes == []
    assert not scratch.exists()


def test_a_missing_side_store_file_is_regenerated_into_the_scratch_directory(tmp_path):
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    s = _settings(tmp_path)
    raw_path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    rib_path = sidestore.write_table(
        s.sidestore_dir, "rib", "vyos", "", run_id, [{"device_uid": "dev:r1", "prefix": "0.0.0.0/0"}], MARCH
    )
    rib_entry = manifest.file_entry(s, rib_path)
    rib_path.unlink()  # the kept file is gone

    files = [manifest.file_entry(s, raw_path), rib_entry]
    _one_device_manifest(s, "vyos", "", run_id, MARCH, files)

    collector = _RibCollector("vyos")
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={})
    scratch = tmp_path / "scratch"
    report = replay.rebuild_from_manifest(
        s, RecordingSession(), 2_000, source_for=lambda name: lookup, sidestore_scratch_dir=scratch
    )

    assert len(report.side_table_notes) == 1
    assert "regenerated" in report.side_table_notes[0]
    assert (scratch / "rib" / "vyos" / f"{run_id}.parquet").exists()


def test_a_missing_side_store_file_with_no_scratch_dir_is_left_unresolved(tmp_path):
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    s = _settings(tmp_path)
    raw_path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    rib_path = sidestore.write_table(
        s.sidestore_dir, "rib", "vyos", "", run_id, [{"device_uid": "dev:r1", "prefix": "0.0.0.0/0"}], MARCH
    )
    rib_entry = manifest.file_entry(s, rib_path)
    rib_path.unlink()

    files = [manifest.file_entry(s, raw_path), rib_entry]
    _one_device_manifest(s, "vyos", "", run_id, MARCH, files)

    collector = _RibCollector("vyos")
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={})
    report = replay.rebuild_from_manifest(s, RecordingSession(), 2_000, source_for=lambda name: lookup)

    assert len(report.side_table_notes) == 1
    assert "no scratch directory" in report.side_table_notes[0]


def test_rebuild_from_manifest_replays_a_device_carried_from_an_earlier_snapshot(tmp_path):
    """A carried device stands on a run its own snapshot wrote no file for."""
    s = _settings(tmp_path)
    path = _write(s, "vyos", MARCH, {"rule": "accept"})
    run_id = f"{MARCH}-abc12345"
    digest = manifest.source_config_digest("vyos", "vyos", True, {})
    source = manifest.SourceEntry(name="vyos", type="vyos", status="fresh", config_sha256=digest)

    collected = manifest.DeviceEntry(
        source="vyos", host="", outcome="collected", effective_run=run_id, fetch_ts_ms=MARCH
    )
    written = manifest.file_entry(s, path)
    manifest.write(s, _snapshot_manifest(1_000, [source], [collected], [written]))

    carried = manifest.DeviceEntry(
        source="vyos",
        host="",
        outcome="carried",
        effective_run=run_id,
        fetch_ts_ms=MARCH,
        carried=True,
    )
    copies = manifest.carried_entries(s, 1_000, [carried], [])
    assert [(f.path, f.sha256, f.carried) for f in copies] == [(written.path, written.sha256, True)]
    manifest.write(s, _snapshot_manifest(2_000, [source], [carried], copies, parent=1_000))
    manifest.path_for(s, 1_000).unlink()  # the collecting run's manifest is gone

    collector = FakeCollector("vyos")
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={})
    report = replay.rebuild_from_manifest(s, RecordingSession(), 2_000, source_for=lambda name: lookup)

    assert report.ok, report.failed
    assert collector.seen == [{"rule": "accept"}]
    assert [(d.host, d.carried) for d in report.replayed] == [("", True)]


def test_a_replay_runs_the_derivations_and_re_applies_the_site_assignments(tmp_path):
    """Both replay paths finish a reconstructed run the way a collection run
    finishes one (`core/finalize.py`)."""
    s = _settings(tmp_path)
    _write(s, "vyos", MARCH, {"n": 1})
    session = RecordingSession()

    report = replay.rebuild(s, session, APRIL, collector_for=lambda src: FakeCollector(src))

    assert [line.split(":")[0] for line in report.derived] == [
        "reasoner",
        "rt-domains",
        "link-speed",
        "device-roles",
    ]
    # the derived objects carry the replayed payload's own time
    assert {p.get("ts") for _, p in session.loads if "ts" in p} == {MARCH}
    # the pointer is the last write of a replay, after everything derived
    pointer = next(i for i, (q, _) in enumerate(session.loads) if "CyclePointer" in q)
    assert pointer == len(session.loads) - 1


def test_an_altered_side_store_file_is_regenerated_not_trusted(tmp_path):
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    s = _settings(tmp_path)
    raw_path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    rib_path = sidestore.write_table(
        s.sidestore_dir, "rib", "vyos", "", run_id, [{"device_uid": "dev:r1", "prefix": "0.0.0.0/0"}], MARCH
    )
    rib_entry = manifest.file_entry(s, rib_path)
    rib_path.write_bytes(b"tampered-bytes-not-parquet")  # the bytes on disk no longer match

    files = [manifest.file_entry(s, raw_path), rib_entry]
    _one_device_manifest(s, "vyos", "", run_id, MARCH, files)

    collector = _RibCollector("vyos")
    lookup = replay.SourceLookup(collector=collector, type="vyos", enabled=True, config={})
    scratch = tmp_path / "scratch"
    report = replay.rebuild_from_manifest(
        s, RecordingSession(), 2_000, source_for=lambda name: lookup, sidestore_scratch_dir=scratch
    )

    assert len(report.side_table_notes) == 1
    assert "regenerated" in report.side_table_notes[0]


# --- the finalization a replay owes, against a real graph --------------------------

URI = os.environ.get("NEO4J_TEST_URI")
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)


class _HostCfg(SourceConfig):
    host: str = ""


class _RtCollector(Collector):
    """Two VRFs paired by one route target, and a prefix the exporter originates."""

    name = "vyos"
    ConfigModel = _HostCfg

    def fetch(self) -> Any:
        return {"host": self.config.host}

    def probe(self) -> str:
        return "ok"

    def normalize(self, raw: Any) -> Any:
        b = GraphBuilder()
        host = raw["host"]
        device = f"dev:{host}"
        b.node("Device", device, hostname=host, role="router")
        exporter = b.node("VrfInstance", uid.vrf(device, "blue"), name="blue", anchor=device)
        importer = b.node("VrfInstance", uid.vrf(device, "red"), name="red", anchor=device)
        rt = b.node("RouteTarget", uid.route_target("65000:1"), value="65000:1")
        b.rel("EXPORTS", "VrfInstance", exporter, "RouteTarget", rt)
        b.rel("IMPORTS", "VrfInstance", importer, "RouteTarget", rt)
        prefix = b.node(
            "Prefix", uid.prefix(exporter, "10.0.0.0/24"), cidr="10.0.0.0/24", af=4, anchor=exporter
        )
        b.rel("ORIGINATES", "VrfInstance", exporter, "Prefix", prefix, proto="connected")
        return b.batch(self.config.source_name or self.name, f"vyos:{host}")


_RT_COMPONENT = "MATCH (d:RoutingDomain {collection_ts: $cts, basis: 'rt-component'}) RETURN d.uid AS uid"
_LEARNED = "MATCH ()-[r:LEARNED_ROUTE {collection_ts: $cts}]->() RETURN count(r) AS n"
_SITE_EDGE = (
    "MATCH (d:Device {collection_ts: $cts})-[:LOCATED_IN]->(s:Site) RETURN d.uid AS device, s.uid AS site"
)


def _rows(session, query, **params):
    return session.run(query, **params).data()


def _imported_routes(session, cts):
    """The rt-import routes the tracer's route read resolves for the importing
    VRF of `_RtCollector`, pinned to the run `cts`."""
    import importlib

    from hst import path as pathmod
    from hst.path.session import CycleSession

    trace = importlib.import_module("hst.path.trace")
    rows = pathmod._read(CycleSession(session, cts), trace._ROUTES_QUERY, vrf=uid.vrf("dev:r1", "red"))
    return [(r["cidr"], r["kind"], r["derived"], r["via_rt"]) for r in rows]


_IMPORTED = [("10.0.0.0/24", "LEARNED_ROUTE", "rt-import", "65000:1")]


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_an_exact_manifest_replay_restores_derivations_and_site_assignments(tmp_path):
    """An archive-backed rebuild reproduces the published graph without
    running the derivations again."""
    from neo4j import GraphDatabase

    from hst.app import runs_exec
    from hst.app.store import Device, Source
    from hst.core import cycle as cyclemod
    from hst.core import db as dbmod

    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This test wipes its target. "
            f"Point it at a scratch database.",
            returncode=2,
        )

    settings = Settings(
        _env_file=None,
        hst_data_dir=tmp_path,
        hst_secret_key=KEY,
        neo4j_uri=URI,
        neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
        neo4j_database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"),
    )
    driver = GraphDatabase.driver(URI, auth=(settings.neo4j_user, settings.neo4j_password))
    try:
        with driver.session(database=settings.neo4j_database) as session:
            dbmod.init_db(session)
            replay._clear_target(session)  # a cold start: no pointer, nothing to carry

            row = Source(1, "edge", "vyos", {"host": "r1"}, b"", True, NOW, NOW)
            device_row = Device(1, "edge", "r1", None, True, "", NOW, NOW)
            collector = _RtCollector(_HostCfg(host="r1", source_name="edge"), settings)
            prepared = [
                runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(device_row, collector, None)])
            ]

            _summary, _ran, cts, _ = runs_exec.execute_cycle(
                settings, prepared, {"edge"}, {"dev:r1": "DEU-FRA-1"}
            )
            assert cts is not None

            record = manifest.read(settings, cts)
            assert record.schema_version == manifest.SCHEMA_VERSION
            assert record.site_assignments == {"dev:r1": "DEU-FRA-1"}
            assert record.checkpoint is not None and record.checkpoint.sha256
            published = record.checkpoint.sha256
            assert [r["uid"] for r in _rows(session, _RT_COMPONENT, cts=cts)] == ["rdom:rt-65000-1"]
            # the route into the importer is resolved where it is read, never
            # written as an edge
            assert _rows(session, _LEARNED, cts=cts)[0]["n"] == 0
            assert _imported_routes(session, cts) == _IMPORTED
            site = {"device": "dev:r1", "site": uid.site("DEU-FRA-1")}
            assert _rows(session, _SITE_EDGE, cts=cts) == [site]

            lookup = replay.SourceLookup(
                collector=_RtCollector(_HostCfg(host="r1", source_name="edge"), settings),
                type=row.type,
                enabled=row.enabled,
                config=row.config,
            )
            report = replay.rebuild_from_manifest(settings, session, cts, source_for=lambda name: lookup)

            assert report.ok, report.failed
            assert report.cleared  # the published run was wiped, then rebuilt from its manifest
            assert report.exact is True
            assert report.derived == []
            assert manifest.checkpoint(session, cts).sha256 == published
            assert cyclemod.current_ts(session) == cts
            assert [r["uid"] for r in _rows(session, _RT_COMPONENT, cts=cts)] == ["rdom:rt-65000-1"]
            assert _rows(session, _LEARNED, cts=cts)[0]["n"] == 0
            assert _imported_routes(session, cts) == _IMPORTED
            assert _rows(session, _SITE_EDGE, cts=cts) == [site]
    finally:
        with driver.session(database=settings.neo4j_database) as session:
            replay._clear_target(session)
        driver.close()
        dbmod.close_drivers()


class _RtCollectorPlus(_RtCollector):
    """`_RtCollector` with one more originated prefix."""

    def fetch(self) -> Any:
        return {"host": self.config.host, "second": True}

    def normalize(self, raw: Any) -> Any:
        batch = super().normalize(raw)
        b = GraphBuilder()
        exporter = uid.vrf(f"dev:{raw['host']}", "blue")
        prefix = b.node(
            "Prefix", uid.prefix(exporter, "10.0.1.0/24"), cidr="10.0.1.0/24", af=4, anchor=exporter
        )
        b.rel("ORIGINATES", "VrfInstance", exporter, "Prefix", prefix, proto="connected")
        extra = b.batch(batch.source, batch.scope)
        return Batch(
            source=batch.source,
            scope=batch.scope,
            nodes=[*batch.nodes, *extra.nodes],
            rels=[*batch.rels, *extra.rels],
        )


_REBUILT_RUN = """
MATCH (c:CycleRun {uid: $uid})
RETURN c.reprocessed_from AS reprocessed_from, c.app_version AS app_version,
       c.build_revision AS build_revision, c.degraded AS degraded, c.kind AS kind
"""


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_an_exact_rebuilt_snapshot_answers_as_the_original_did(tmp_path):
    """With two snapshots on disk, replaying the
    older one reproduces that snapshot and not the newer one."""
    from neo4j import GraphDatabase

    from hst.app import runs_exec
    from hst.app.store import Device, Source
    from hst.core import cycle as cyclemod
    from hst.core import db as dbmod

    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This test wipes its target. "
            f"Point it at a scratch database.",
            returncode=2,
        )

    settings = Settings(
        _env_file=None,
        hst_data_dir=tmp_path,
        hst_secret_key=KEY,
        neo4j_uri=URI,
        neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
        neo4j_database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"),
    )
    row = Source(1, "edge", "vyos", {"host": "r1"}, b"", True, NOW, NOW)
    device_row = Device(1, "edge", "r1", None, True, "", NOW, NOW)

    def cycle_with(collector_cls):
        collector = collector_cls(_HostCfg(host="r1", source_name="edge"), settings)
        prepared = [runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(device_row, collector, None)])]
        _summary, _ran, cts, _ = runs_exec.execute_cycle(settings, prepared, {"edge"})
        assert cts is not None
        return cts

    driver = GraphDatabase.driver(URI, auth=(settings.neo4j_user, settings.neo4j_password))
    try:
        with driver.session(database=settings.neo4j_database) as session:
            dbmod.init_db(session)
            replay._clear_target(session)  # a cold start: no pointer, nothing to carry

            first = cycle_with(_RtCollector)
            second = cycle_with(_RtCollectorPlus)
            assert second > first

            published = manifest.read(settings, first).checkpoint
            assert published is not None and published.sha256
            assert manifest.checkpoint(session, second).sha256 != published.sha256

            lookup = replay.SourceLookup(
                collector=_RtCollector(_HostCfg(host="r1", source_name="edge"), settings),
                type=row.type,
                enabled=row.enabled,
                config=row.config,
            )
            report = replay.rebuild_from_manifest(settings, session, first, source_for=lambda name: lookup)

            assert report.ok, report.failed
            assert report.exact is True
            assert report.derived == []
            assert manifest.checkpoint(session, first).sha256 == published.sha256
            assert cyclemod.current_ts(session) == first
            rebuilt = _rows(session, _REBUILT_RUN, uid=f"cycle:{first}")[0]
            assert rebuilt["reprocessed_from"] is None
            assert rebuilt["app_version"] is None
            assert rebuilt["build_revision"] is None
            assert rebuilt["degraded"] is False
            assert rebuilt["kind"] == "full"
    finally:
        with driver.session(database=settings.neo4j_database) as session:
            replay._clear_target(session)
        driver.close()
        dbmod.close_drivers()


# --- the side-store files a date-based rebuild derives from -----------------------


def test_a_date_based_rebuild_reads_the_side_store_files_of_its_replayed_runs_only(tmp_path):
    from hst.core import sidestore

    settings = _settings(tmp_path)
    wanted = replay.Snapshot(
        source="unifi", host="ckey-1", run_id=f"{APRIL}-abc12345", ts_ms=APRIL, path=tmp_path / "x"
    )
    rows = [{"device_uid": "dev:a", "vrf": "default", "ip": "10.0.0.1", "mac": "aa"}]
    base = settings.sidestore_dir
    kept = sidestore.write_table(base, "arp", "unifi", "ckey-1", wanted.run_id, rows, APRIL)
    # another run of the same device, and the same run id under another host
    other = sidestore.write_table(base, "arp", "unifi", "ckey-1", f"{MARCH}-abc12345", rows, MARCH)
    foreign = sidestore.write_table(base, "arp", "unifi", "ckey-2", wanted.run_id, rows, APRIL)
    assert kept is not None and other is not None and foreign is not None

    files = replay._snapshot_sidestore_files(settings, [wanted])

    assert files.files("arp", ["dev:a"]) == [kept]
    assert files.files("mac", ["dev:a"]) == []


def test_a_date_based_rebuild_with_no_side_store_reads_no_file(tmp_path):
    settings = _settings(tmp_path)
    snap = replay.Snapshot(
        source="vyos", host="", run_id=f"{APRIL}-abc12345", ts_ms=APRIL, path=tmp_path / "x"
    )

    assert replay._snapshot_sidestore_files(settings, [snap]).files("arp", ["dev:a"]) == []
