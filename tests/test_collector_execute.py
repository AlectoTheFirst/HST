"""collectors.base.execute: fetch-time run identity and the per-source/host raw
and side-store file layout."""

from __future__ import annotations

import json

from hst import collectors as coll
from hst.app.crypto import dek, generate_key
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import Settings, manifest, rawstore


def _settings(tmp_path):
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


class FakeSession:
    """Minimal SessionLike: MERGE-shaped node upserts answered inline, every
    other statement (the rel pass, the run-meta write) counted but ignored,
    the same seam test_sidestore.py's execute() tests use."""

    def execute_write(self, work):
        return work(self)

    def run(self, q, **p):
        class _Result:
            def data(self_inner):
                if "UNWIND $rows" in q and "MERGE (n" in q:
                    return [{"uid": r["uid"], "before": {}, "after": {**r["props"]}} for r in p["rows"]]
                return []

        return _Result()


class HostCfg(SourceConfig):
    host: str = ""


class DevCollector(Collector):
    """One device fetch. `name` is the collector TYPE (fixed); `config.host`
    and `config.source_name` vary per instance the way a real fleet's
    per-device collectors do (app/sources.py build_device_collector)."""

    name = "nxos"
    ConfigModel = HostCfg

    def __init__(self, config: HostCfg, settings: Settings):
        super().__init__(config, settings)
        self.scope = f"nxos:{config.host or config.source_name}"

    def fetch(self):
        return {"seen": 1}

    def normalize(self, raw):
        b = GraphBuilder()
        b.node("Device", f"dev:{self.config.host or self.config.source_name}", hostname="h", role="router")
        return b.batch(self.config.source_name or self.name, self.scope)

    def probe(self) -> str:
        return "ok"

    def side_tables(self, raw):
        return {}


def _collector(settings: Settings, *, host: str = "", source_name: str = "") -> DevCollector:
    return DevCollector(HostCfg(host=host, source_name=source_name), settings)


def test_raw_sha_ignores_the_reserved_outcomes_key(tmp_path):
    """The outcomes describe the fetch, not the device: two fetches that
    captured the same output are the same payload whether or not one of them
    also recorded that a command was refused."""
    c = _collector(_settings(tmp_path), source_name="row1")
    bare = {"show version": "V", "show arp": ""}
    with_outcomes = {
        **bare,
        coll.RAW_OUTCOMES_KEY: {"show version": {"status": "ok"}, "show arp": {"status": "failed"}},
    }
    assert coll.raw_sha(c, with_outcomes) == coll.raw_sha(c, bare)


def test_run_id_is_built_from_fetch_time_not_from_collection_ts_or_collector_type(tmp_path):
    """Two calls under two different collection_ts values (a cycle, then a
    same-tick refresh) each mint their own run_id from when they ran."""
    c = _collector(_settings(tmp_path), source_name="row1")
    m1 = coll.execute(c, FakeSession(), collection_ts=100)
    m2 = coll.execute(c, FakeSession(), collection_ts=200)

    assert m1.run_id != m2.run_id
    for run_id, cts in ((m1.run_id, 100), (m2.run_id, 200)):
        assert "nxos" not in run_id  # no collector-type segment
        ts_part, _, nonce = run_id.partition("-")
        assert ts_part.isdigit() and len(nonce) >= 6
        assert int(ts_part) != cts  # the fetch time, not the joined collection_ts


def test_execute_stamps_the_fetch_time_not_the_load_time_for_a_prefetched_payload(tmp_path):
    """`execute` stamps `ts` from `fetch_window`'s start."""
    c = _collector(_settings(tmp_path), source_name="row1")
    long_ago = 1_000  # far earlier than "now" in epoch ms, and than collection_ts

    m = coll.execute(
        c, FakeSession(), collection_ts=999_999_999, raw={"seen": 1}, fetch_window=(long_ago, long_ago + 50)
    )

    ts_part, _, nonce = m.run_id.partition("-")
    assert int(ts_part) == long_ago
    assert nonce
    assert m.started == manifest.iso(long_ago)


def test_two_devices_of_one_source_write_raw_files_under_different_host_directories(tmp_path):
    settings = _settings(tmp_path)
    a = _collector(settings, host="10.0.0.1", source_name="row1")
    b = _collector(settings, host="10.0.0.2", source_name="row1")

    ma = coll.execute(a, FakeSession(), collection_ts=1, source_name="row1")
    mb = coll.execute(b, FakeSession(), collection_ts=1, source_name="row1")

    raw_a = settings.raw_dir / "row1" / "10.0.0.1" / f"{ma.run_id}{rawstore.SUFFIX}"
    raw_b = settings.raw_dir / "row1" / "10.0.0.2" / f"{mb.run_id}{rawstore.SUFFIX}"
    assert raw_a.is_file()
    assert raw_b.is_file()
    assert raw_a.parent != raw_b.parent


def test_two_sources_of_one_collector_type_write_raw_files_under_different_source_directories(tmp_path):
    settings = _settings(tmp_path)
    a = _collector(settings, source_name="vyos-hq")
    b = _collector(settings, source_name="vyos-branch")

    ma = coll.execute(a, FakeSession(), collection_ts=1, source_name="vyos-hq")
    mb = coll.execute(b, FakeSession(), collection_ts=1, source_name="vyos-branch")

    raw_a = settings.raw_dir / "vyos-hq" / f"{ma.run_id}{rawstore.SUFFIX}"
    raw_b = settings.raw_dir / "vyos-branch" / f"{mb.run_id}{rawstore.SUFFIX}"
    assert raw_a.is_file()
    assert raw_b.is_file()
    assert raw_a.parent != raw_b.parent


def test_execute_joins_its_own_raw_file_immediately(tmp_path):
    """A cycle or an in-tick refresh already knows its collection_ts, so
    execute() marks its raw file joined at once."""
    settings = _settings(tmp_path)
    c = _collector(settings, host="10.0.0.5", source_name="row1")
    m = coll.execute(c, FakeSession(), collection_ts=555, source_name="row1")

    raw_path = settings.raw_dir / "row1" / "10.0.0.5" / f"{m.run_id}{rawstore.SUFFIX}"
    assert raw_path.is_file()
    assert rawstore.parked(settings.raw_dir) == []  # nothing left unjoined

    meta = raw_path.with_name(f"{m.run_id}.meta.json")
    assert json.loads(meta.read_text()) == {"snapshot_ts": 555}


# --- park and load_payload: the two halves a parked per-device payload uses --------------


def test_park_writes_the_raw_file_without_joining_it_to_a_run(tmp_path):
    """A device fetch does not know the run its payload will join, so it stores
    the payload and returns; the sidecar that names the run is written later, by
    the device-run builder."""
    settings = _settings(tmp_path)
    c = _collector(settings, host="10.0.0.7", source_name="row1")

    path = coll.park(c, {"seen": 1}, source_name="row1")

    assert path.is_file()
    assert path.parent == settings.raw_dir / "row1" / "10.0.0.7"
    assert not path.with_name(path.name[: -len(rawstore.SUFFIX)] + ".meta.json").exists()
    (found,) = rawstore.parked(settings.raw_dir)
    assert (found.source, found.host, found.path) == ("row1", "10.0.0.7", path)


def test_park_writes_no_side_store_rows(tmp_path):
    """The side-store rows carry the joining run's snapshot_ts as a column, and a
    parked payload has no run yet: they are written when it joins one."""

    class WithTables(DevCollector):
        def side_tables(self, raw):
            return {"rib": [{"device_uid": "dev:x", "prefix": "10.0.0.0/8"}]}

    settings = _settings(tmp_path)
    c = WithTables(HostCfg(host="10.0.0.8", source_name="row1"), settings)

    coll.park(c, {"seen": 1}, source_name="row1")

    assert list(settings.sidestore_dir.rglob("*.parquet")) == []


def test_load_payload_joins_a_parked_payload_under_the_run_that_claims_it(tmp_path):
    """The payload keeps its own fetch-time run id and fetch time; only the
    collection_ts is the joining run's."""
    settings = _settings(tmp_path)
    c = _collector(settings, host="10.0.0.9", source_name="row1")
    path = coll.park(c, {"seen": 1}, source_name="row1", fetch_ts_ms=111)
    (found,) = rawstore.parked(settings.raw_dir)
    assert found.fetch_ts_ms == 111

    raw = rawstore.read(path, dek(settings))
    manifest = coll.load_payload(
        c, FakeSession(), raw, collection_ts=999, run_id=found.run_id, ts_ms=found.fetch_ts_ms
    )

    assert manifest.run_id == found.run_id
    assert manifest.nodes_upserted == 1
