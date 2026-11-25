"""The snapshot manifest (core/manifest.py)."""

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
from hst.core import Settings, manifest, rawstore

PREV = 1_000
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def _settings(tmp_path, **kw: Any) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key(), **kw)


# --- digests ------------------------------------------------------------------------------


def test_the_canonical_form_ignores_key_order_and_renders_what_json_cannot():
    a = {"b": 1, "a": {"d": 4, "c": 3}}
    b = {"a": {"c": 3, "d": 4}, "b": 1}
    assert manifest.canonical_digest(a) == manifest.canonical_digest(b)
    # a payload JSON cannot render hashes and does not fail the run
    assert manifest.canonical_digest({"x": {1, 2}})


def test_a_row_digest_is_the_same_whatever_order_the_rows_arrive_in():
    """A regenerated table digests identically to the file it came from."""
    rows = [{"prefix": "10.0.0.0/8", "nh": "a"}, {"prefix": "0.0.0.0/0", "nh": "b"}]
    assert manifest.rows_digest(rows) == manifest.rows_digest(list(reversed(rows)))
    assert manifest.rows_digest(rows) != manifest.rows_digest(rows[:1])


def test_bucketing_the_digests_does_not_change_the_digest():
    """The per-item digests are sorted and combined in bounded buckets."""
    items = [manifest.digest_bytes(f"row-{i}".encode()) for i in range(50)]
    whole = manifest._combine(items)

    for bucket in (1, 2, 7, 49, 50, 51, 1000):
        with manifest._Buckets(bucket) as buckets:
            for item in items:
                buckets.add(item)
            assert buckets.count == 50
            assert buckets.digest() == whole, f"bucket size {bucket} changed the digest"

    with manifest._Buckets(3) as buckets:
        for item in reversed(items):
            buckets.add(item)
        assert buckets.digest() == whole


def test_a_file_digest_covers_the_bytes_on_disk(tmp_path):
    """The check needs no data key."""
    path = tmp_path / "raw.bin"
    path.write_bytes(b"sealed")
    assert manifest.file_facts(path) == (manifest.digest_bytes(b"sealed"), 6)


def test_a_source_configuration_digest_carries_no_credential(tmp_path):
    config = {"host": "r1", "password": "hunter2", "jump_host": {"host": "b1", "api_key": "k"}}
    redacted = manifest.redact_config(config)
    assert redacted == {
        "host": "r1",
        "password": manifest.REDACTED,
        "jump_host": {"host": "b1", "api_key": manifest.REDACTED},
    }
    assert "hunter2" not in json.dumps(redacted)
    with_secret = manifest.source_config_digest("vyos1", "vyos", True, config)
    other_secret = manifest.source_config_digest("vyos1", "vyos", True, {**config, "password": "different"})
    no_secret = manifest.source_config_digest("vyos1", "vyos", True, {"host": "r1"})
    assert with_secret == other_secret  # the value never enters the digest
    assert with_secret != no_secret  # its presence does


def test_a_short_credential_field_is_redacted_wherever_it_nests():
    config = {
        "snmp": {"community": "public"},
        "tunnel": {"psk": "s3cret", "preshared_key": "s3cret"},
        "tls": {"private_bytes": "-----BEGIN"},
        "mfa": {"otp_seed": "JBSWY3DP"},
        "api": {"bearer_value": "abc.def"},
    }
    redacted = manifest.redact_config(config)

    assert redacted == {
        "snmp": {"community": manifest.REDACTED},
        "tunnel": {"psk": manifest.REDACTED, "preshared_key": manifest.REDACTED},
        "tls": {"private_bytes": manifest.REDACTED},
        "mfa": {"otp_seed": manifest.REDACTED},
        "api": {"bearer_value": manifest.REDACTED},
    }
    dumped = json.dumps(redacted)
    assert not any(v in dumped for v in ("public", "s3cret", "BEGIN", "JBSWY3DP", "abc.def"))


# --- the store, the chain and the signature -----------------------------------------------


def _record(key: int, **kw: Any) -> manifest.SnapshotManifest:
    return manifest.SnapshotManifest(
        snapshot_key=key, kind="full", opened=manifest.iso(key), published=manifest.iso(key), **kw
    )


def test_a_written_manifest_reads_back_and_its_digest_is_the_file(tmp_path):
    settings = _settings(tmp_path)
    digest = manifest.write(settings, _record(2_000))

    assert manifest.read(settings, 2_000).snapshot_key == 2_000
    assert manifest.digest_of(settings, 2_000) == digest
    body = manifest.path_for(settings, 2_000).read_bytes()
    assert manifest.digest_bytes(body) == digest
    # the file holds the manifest body and nothing else, so the digest that is
    # signed, chained and checked is one value
    assert body == manifest.canonical_json(manifest.read(settings, 2_000).model_dump(mode="json"))


def test_each_manifest_chains_to_the_digest_of_the_one_before_it(tmp_path):
    settings = _settings(tmp_path)
    first = manifest.write(settings, manifest.build(**_build_args(settings, 2_000)))
    second = manifest.build(**_build_args(settings, 3_000))
    manifest.write(settings, second)

    assert second.previous is not None
    assert second.previous.snapshot_key == 2_000
    assert second.previous.sha256 == first == manifest.digest_of(settings, 2_000)
    assert (second.chain_index, manifest.read(settings, 2_000).chain_index) == (1, 0)


def test_the_first_manifest_of_a_chain_carries_no_link(tmp_path):
    settings = _settings(tmp_path)
    record = manifest.build(**_build_args(settings, 2_000))
    assert record.previous is None and record.chain_index == 0


def test_a_built_manifest_carries_the_settings_estate_name(tmp_path):
    """`SnapshotManifest.estate` comes from `Settings.estate_name`,
    which defaults to "default" for a single-estate deployment, and a
    deployment that declares one gets it verbatim."""
    default_settings = _settings(tmp_path)
    assert manifest.build(**_build_args(default_settings, 2_000)).estate == "default"

    named_settings = _settings(tmp_path, estate_name="west")
    assert manifest.build(**_build_args(named_settings, 2_000)).estate == "west"


def _build_args(settings: Settings, key: int) -> dict[str, Any]:
    return {
        "settings": settings,
        "snapshot_key": key,
        "kind": "full",
        "parent": None,
        "sources": [],
        "devices": [],
        "files": [],
        "delta": manifest.GraphDelta(),
    }


def test_a_tampered_manifest_breaks_the_chain_it_is_named_in(tmp_path):
    """The recorded digest is of the bytes."""
    settings = _settings(tmp_path)
    manifest.write(settings, manifest.build(**_build_args(settings, 2_000)))
    second = manifest.build(**_build_args(settings, 3_000))

    path = manifest.path_for(settings, 2_000)
    path.write_bytes(path.read_bytes().replace(b'"kind":"full"', b'"kind":"idle"'))

    assert second.previous is not None
    assert second.previous.sha256 != manifest.digest_of(settings, 2_000)


def test_with_no_signing_key_the_manifest_is_written_unsigned(tmp_path):
    settings = _settings(tmp_path)
    assert manifest.signer_for(settings) is None

    manifest.write(settings, _record(2_000), manifest.signer_for(settings))

    assert manifest.read_signature(settings, 2_000) is None
    assert not manifest.sig_path_for(settings, 2_000).exists()


def test_a_configured_signer_signs_the_manifest_digest(tmp_path):
    settings = _settings(tmp_path, evidence_signing_key=generate_key())
    signer = manifest.signer_for(settings)
    assert signer is not None

    digest = manifest.write(settings, _record(2_000), signer)
    signature = manifest.read_signature(settings, 2_000)

    assert signature is not None
    assert signature.algorithm == "ed25519" and signature.key_id == signer.key_id
    assert signature.digest == digest
    assert manifest.verify(signature, bytes.fromhex(digest))
    # verification needs the public key only, which the .sig carries
    assert not manifest.verify(signature, bytes.fromhex(manifest.digest_bytes(b"another manifest")))


def test_a_signature_with_the_key_id_of_another_key_does_not_verify(tmp_path):
    settings = _settings(tmp_path, evidence_signing_key=generate_key())
    digest = manifest.write(settings, _record(2_000), manifest.signer_for(settings))
    signature = manifest.read_signature(settings, 2_000)
    other = manifest.AppKeySigner(generate_key().encode())

    forged = signature.model_copy(update={"key_id": other.key_id})

    assert not manifest.verify(forged, bytes.fromhex(digest))


def test_a_signing_key_from_a_file_wins_over_the_value(tmp_path):
    key_file = tmp_path / "signing.key"
    key_file.write_text(generate_key())
    settings = _settings(
        tmp_path, evidence_signing_key=generate_key(), evidence_signing_key_file=str(key_file)
    )
    from_file = _settings(tmp_path, evidence_signing_key_file=str(key_file))

    signer = manifest.signer_for(settings)
    assert signer is not None
    other = manifest.signer_for(from_file)
    assert other is not None
    assert signer.key_id == other.key_id


def test_a_signing_key_too_short_to_sign_with_is_refused(tmp_path):
    settings = _settings(tmp_path, evidence_signing_key="short")
    with pytest.raises(manifest.SignerError):
        manifest.signer_for(settings)


# --- observation metadata: every field defaults null and reads --------------------------


def test_new_observation_fields_default_null_and_versions_1_to_3_all_read(tmp_path):
    """Every observation metadata field has a default."""
    settings = _settings(tmp_path)
    for version in (1, 2, 3):
        path = manifest.path_for(settings, 4_000)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "schema_version": version,
                    "snapshot_key": 4_000,
                    "kind": "full",
                    "opened": manifest.iso(4_000),
                    "published": manifest.now_iso(),
                }
            )
        )
        record = manifest.read(settings, 4_000)
        assert record.schema_version == version
        assert record.devices == [] and record.files == []

    device = manifest.DeviceEntry(source="edge", host="r1", outcome="collected")
    assert (device.fetch_started_ms, device.fetch_finished_ms) == (None, None)
    assert (device.source_clock_ms, device.ingested_ms) == (None, None)
    assert device.expected_sections == []

    table = manifest.TableOutcome(status="complete")
    assert (table.observed_ms, table.parser_version) == (None, None)

    raw_file = manifest.FileEntry(
        kind="raw",
        path="edge/r1/1-aa.json.gz.enc",
        sha256="a" * 64,
        bytes=1,
        source="edge",
        host="r1",
        run_id="1-aa",
    )
    assert raw_file.schema_version is None


# --- the capped side-store table ----------------------------------------------------------


def _rib_rows(n: int) -> list[dict]:
    return [{"device_uid": "dev:r1", "vrf": "default", "prefix": f"10.0.{i}.0/24"} for i in range(n)]


def _write_rib(settings: Settings, rows: list[dict], run_id: str = "1700000000000-aa11bb22"):
    from hst.core import sidestore

    return sidestore.write_table(settings.sidestore_dir, "rib", "vyos1", "r1", run_id, rows, 2_000)


def test_a_vyos_rib_under_the_cap_is_recorded_as_mirrored(tmp_path):
    pytest.importorskip("pyarrow")
    from hst.collectors.vyos import VyosCollector

    settings = _settings(tmp_path, rib_graph_max_routes=10)
    path = _write_rib(settings, _rib_rows(3))
    entry = manifest.file_entry(settings, path, mirrored_tables=VyosCollector.GRAPH_MIRRORED_TABLES)

    assert (entry.kind, entry.table, entry.source, entry.host) == ("sidestore", "rib", "vyos1", "r1")
    assert (entry.row_count, entry.cap) == (3, 10)
    assert entry.graph_mirrored is True and entry.truncated is False
    assert entry.rows_sha256 is not None


def test_a_vyos_rib_over_the_cap_is_recorded_with_its_rows_but_not_mirrored(tmp_path):
    """The parquet file is never truncated."""
    pytest.importorskip("pyarrow")
    from hst.collectors.vyos import VyosCollector

    settings = _settings(tmp_path, rib_graph_max_routes=2)
    path = _write_rib(settings, _rib_rows(5))
    entry = manifest.file_entry(settings, path, mirrored_tables=VyosCollector.GRAPH_MIRRORED_TABLES)

    assert entry.row_count == 5
    assert entry.graph_mirrored is False and entry.truncated is True


def test_a_cisco_rib_is_never_mirrored_whatever_its_size(tmp_path):
    """Cisco collectors write no LEARNED_ROUTE edges."""
    pytest.importorskip("pyarrow")
    from hst.collectors.cli_collector import CiscoCliCollector

    settings = _settings(tmp_path, rib_graph_max_routes=1_000)
    path = _write_rib(settings, _rib_rows(3))
    entry = manifest.file_entry(settings, path, mirrored_tables=CiscoCliCollector.GRAPH_MIRRORED_TABLES)

    assert entry.row_count == 3
    assert entry.graph_mirrored is False and entry.truncated is False
    assert entry.cap is None  # no cap governs a table this collector never mirrors


def test_a_side_store_files_row_digest_is_the_digest_of_the_rows_it_holds(tmp_path):
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    settings = _settings(tmp_path)
    rows = _rib_rows(4)
    path = _write_rib(settings, rows)
    count, digest = manifest.sidestore_row_facts(path)

    assert count == 4
    # the same rows written again, in another order, digest the same. Same run
    # id: `write_table` stamps it into every row, so it is part of the rows.
    other = sidestore.write_table(
        settings.sidestore_dir, "rib", "vyos1", "r2", "1700000000000-aa11bb22", rows[::-1], 2_000
    )
    assert manifest.sidestore_row_facts(other)[1] == digest


def test_a_side_store_files_manifest_entry_records_its_own_schema_version(tmp_path):
    """`FileEntry.schema_version` comes from `sidestore.SCHEMA_VERSIONS`."""
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    settings = _settings(tmp_path)
    path = _write_rib(settings, _rib_rows(2))

    entry = manifest.file_entry(settings, path)

    assert entry.schema_version == sidestore.SCHEMA_VERSIONS["rib"]


# --- the three run builders ---------------------------------------------------------------


class _HostCfg(SourceConfig):
    host: str = ""


class _DevCollector(Collector):
    name = "vyos"
    ConfigModel = _HostCfg

    def __init__(self, config: _HostCfg, settings: Settings) -> None:
        super().__init__(config, settings)
        self.scope = f"vyos:{config.host}"

    def fetch(self) -> Any:
        return {"host": self.config.host}

    def normalize(self, raw: Any) -> Any:
        b = GraphBuilder()
        b.node("Device", f"dev:{raw['host']}", hostname=raw["host"], role="router")
        return b.batch(self.config.source_name or self.name, self.scope)

    def probe(self) -> str:
        return "ok"


class _RibCollector(_DevCollector):
    """A collector with a side-store table, and one that mirrors it into the
    graph under the cap, as VyosCollector does. It declares a second table it
    has no rows for, which is the case the file list cannot state on its own."""

    GRAPH_MIRRORED_TABLES = ("rib",)
    SIDE_TABLES = ("rib", "mac")

    def side_tables(self, raw: Any) -> dict[str, list[dict]]:
        return {"rib": _rib_rows(2), "mac": []}


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
    """Stands in for `core.cycle`; `keys` are the run keys it mints in turn."""

    def __init__(self, pointer: int | None, keys: list[int]) -> None:
        self.pointer = pointer
        self.keys = list(keys)
        self.meta: dict[str, Any] | None = None
        self.steps: list[str] = []

    def current_ts(self, s: Any) -> int | None:
        return self.pointer

    def new_collection_ts(self) -> int:
        return self.keys.pop(0)

    def carry_forward(self, s: Any, prev: int, cts: int, sources: list[str], **kw: Any) -> dict[str, int]:
        return {"nodes": 1, "rels": 0}

    def cycle_counts(self, s: Any, cts: int) -> dict[str, int]:
        return {"nodes": 7, "rels": 9}

    def scope_collected_at(self, s: Any, cts: int, scope: str) -> int | None:
        return None

    def set_pointer(self, s: Any, cts: int) -> None:
        self.steps.append("set_pointer")
        self.pointer = cts

    def apply_site_assignments(self, s: Any, assigned: Any, cts: int | None = None) -> int:
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
    """Real settings, a real raw store and a real manifest writer; the graph
    stubbed, as in tests/app/test_device_run.py."""

    def build(
        *,
        pointer: int | None = PREV,
        keys: list[int] | None = None,
        session: type[_Session] = _Session,
        **kw: Any,
    ):
        settings = _settings(tmp_path, **kw)
        cycle = _Cycle(pointer, keys or [2_000])
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda s: session())
        return settings, cycle

    return build


def _prepared(settings: Settings, name: str, *hosts: str) -> runs_exec.PreparedSource:
    config = {"host": hosts[0] if hosts else "", "password": "hunter2"}
    row = Source(1, name, "vyos", config, b"", True, NOW, NOW)
    units = [
        runs_exec.PreparedDevice(
            Device(1, name, host, None, True, "", NOW, NOW),
            _DevCollector(_HostCfg(host=host, source_name=name), settings),
            None,
        )
        for host in hosts
    ]
    return runs_exec.PreparedSource(row, units)


def _rehash(settings: Settings, record: manifest.SnapshotManifest) -> None:
    """Every recorded digest matches the file it names, re-read from disk."""
    assert record.files, "the run wrote no files, so nothing was digested"
    for entry in record.files:
        path = settings.hst_data_dir / entry.path
        sha, size = manifest.file_facts(path)
        assert (sha, size) == (entry.sha256, entry.bytes), entry.path


def test_a_full_cycle_publishes_a_manifest_the_run_meta_node_names(rig):
    settings, cycle = rig()
    edge = _prepared(settings, "edge", "r1", "r2")

    runs_exec.execute_cycle(settings, [edge], {"edge"})

    record = manifest.read(settings, 2_000)
    assert record.kind == "full" and record.parent == PREV
    assert cycle.meta["manifest_digest"] == manifest.digest_of(settings, 2_000)
    assert [s.name for s in record.sources] == ["edge"]
    assert [(d.host, d.outcome, d.carried) for d in record.devices] == [
        ("r1", "collected", False),
        ("r2", "collected", False),
    ]
    # the source configuration is recorded as a digest, never as text
    assert "hunter2" not in manifest.path_for(settings, 2_000).read_text()
    _rehash(settings, record)


def test_a_full_cycle_records_the_fetch_window_and_observation_metadata(rig):
    """`prior={}` turns on the concurrent fetch phase."""
    pytest.importorskip("pyarrow")
    settings, _ = rig()
    edge = _prepared(settings, "edge", "r1")
    edge.units[0].collector = _RibCollector(_HostCfg(host="r1", source_name="edge"), settings)

    runs_exec.execute_cycle(settings, [edge], {"edge"}, None, {})

    (device,) = manifest.read(settings, 2_000).devices
    assert device.fetch_started_ms is not None and device.fetch_finished_ms is not None
    assert device.fetch_finished_ms >= device.fetch_started_ms
    assert device.ingested_ms is not None and device.ingested_ms >= device.fetch_finished_ms
    assert device.source_clock_ms is None  # no collector reads the device clock
    assert device.expected_sections == []  # this collector reports no per-section outcomes
    rib = device.tables["rib"]
    assert rib.observed_ms == device.fetch_started_ms
    assert rib.parser_version == "1"


def test_the_manifest_is_written_before_the_pointer_moves(rig):
    """A crash between the two must never leave a reader-visible run with no
    evidence behind it."""
    settings, cycle = rig()
    calls: list[str] = []

    def watch(s: Any, cts: int) -> None:
        calls.append("set_pointer")
        assert manifest.path_for(settings, cts).is_file(), "the pointer moved before the manifest"

    cycle.set_pointer = watch
    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})
    assert calls == ["set_pointer"]


def test_a_refresh_publishes_its_own_manifest(rig):
    settings, _ = rig(keys=[2_000])
    edge = _prepared(settings, "edge", "r1")
    other = _prepared(settings, "ctrl", "c1")

    runs_exec.execute_refresh(settings, [edge, other], "edge")

    record = manifest.read(settings, 2_000)
    assert record.kind == "refresh"
    assert {s.name: s.status for s in record.sources} == {"edge": "fresh", "ctrl": "carried"}
    _rehash(settings, record)


def test_a_device_run_publishes_a_manifest_naming_the_payload_it_joined(rig):
    settings, _ = rig(keys=[2_000])
    edge = _prepared(settings, "edge", "r1")
    unit = edge.units[0]
    coll.park(unit.collector, {"host": "r1"}, source_name="edge")
    (parked,) = rawstore.parked(settings.raw_dir)

    runs_exec.build_device_run(settings, [edge])

    record = manifest.read(settings, 2_000)
    assert record.kind == "device"
    assert [f.run_id for f in record.files] == [parked.run_id]
    device = record.devices[0]
    assert (device.effective_run, device.carried) == (parked.run_id, False)
    _rehash(settings, record)


def test_a_device_run_entry_is_observed_when_its_parked_payload_was_fetched(rig):
    """The entry carries the parked payload's fetch time."""
    from types import SimpleNamespace

    from hst.analysis_model.evidence import EvidencePolicy
    from hst.analysis_model.temporal import manifest_evidence
    from hst.core.model import SectionOutcome

    settings, _ = rig(keys=[2_000])
    edge = _prepared(settings, "edge", "r1")
    coll.park(edge.units[0].collector, {"host": "r1"}, source_name="edge", fetch_ts_ms=1_700_000_000_000)
    (parked,) = rawstore.parked(settings.raw_dir)

    runs_exec.build_device_run(settings, [edge])

    (device,) = manifest.read(settings, 2_000).devices
    assert device.fetch_started_ms == parked.fetch_ts_ms == 1_700_000_000_000
    # the parked file does not record when the fetch finished
    assert device.fetch_finished_ms is None
    entry = device.model_copy(update={"sections": {"routes": SectionOutcome(status="ok")}})
    evaluated = manifest_evidence(
        SimpleNamespace(manifest=SimpleNamespace(devices=(entry,))),
        analysis_time=datetime.fromtimestamp(1_700_000_060, UTC),
        policy=EvidencePolicy(),
    )
    assert evaluated is not None


def test_a_cycle_records_every_side_store_file_it_writes(rig):
    """The accumulator is filled by the writers themselves, so a
    table written during the load is in the file list with its own row digest."""
    pytest.importorskip("pyarrow")
    settings, _ = rig(rib_graph_max_routes=10)
    edge = _prepared(settings, "edge", "r1")
    edge.units[0].collector = _RibCollector(_HostCfg(host="r1", source_name="edge"), settings)

    runs_exec.execute_cycle(settings, [edge], {"edge"})

    record = manifest.read(settings, 2_000)
    kinds = {f.kind: f for f in record.files}
    assert set(kinds) == {"raw", "sidestore"}
    rib = kinds["sidestore"]
    assert (rib.table, rib.row_count, rib.graph_mirrored) == ("rib", 2, True)
    assert rib.rows_sha256 == manifest.sidestore_row_facts(settings.hst_data_dir / rib.path)[1]
    assert rib.run_id == kinds["raw"].run_id  # one fetch, both files

    # A zero-row table is absent from the file list.
    (device,) = record.devices
    assert device.outcome == "collected"
    assert {n: o.status for n, o in device.tables.items()} == {
        "rib": "complete",
        "mac": "complete-empty",
    }
    assert device.tables["rib"].row_count == 2
    assert device.tables["rib"].path == rib.path
    assert device.tables["mac"].row_count == 0 and device.tables["mac"].path == ""
    _rehash(settings, record)


def test_a_device_that_never_collected_stands_on_no_run_at_all(rig):
    """The manifest records the providing run per device, including a device this
    run did not collect; with no payload in any run there is none to name."""
    settings, _ = rig()
    prepared = [_prepared(settings, "edge", "r1"), _prepared(settings, "old", "r9")]
    runs_exec.execute_cycle(settings, prepared, {"edge"})

    record = manifest.read(settings, 2_000)
    by_host = {d.host: d for d in record.devices}
    assert (by_host["r9"].effective_run, by_host["r9"].carried) == (None, True)
    assert by_host["r9"].outcome == "carried"
    assert by_host["r1"].effective_run is not None and by_host["r1"].carried is False


def test_the_carried_device_of_a_later_run_stands_on_the_run_that_collected_it(rig):
    """The join sidecars answer which run provides a device's payload."""
    settings, _cycle = rig(keys=[2_000, 3_000])
    edge = _prepared(settings, "edge", "r1")
    other = _prepared(settings, "ctrl", "c1")

    runs_exec.execute_cycle(settings, [edge, other], {"edge"})
    first = manifest.read(settings, 2_000)
    runs_exec.execute_cycle(settings, [edge, other], {"ctrl"})
    second = manifest.read(settings, 3_000)

    r1_first = next(d for d in first.devices if d.host == "r1")
    r1_second = next(d for d in second.devices if d.host == "r1")
    assert r1_second.effective_run == r1_first.effective_run
    assert r1_second.carried is True and r1_second.outcome == "carried"

    written = next(f for f in first.files if f.run_id == r1_first.effective_run)
    assert written.carried is False
    copied = next(f for f in second.files if f.run_id == r1_second.effective_run)
    assert copied.carried is True
    # A's own digest, byte count and path, copied and not recomputed
    assert (copied.path, copied.sha256, copied.bytes) == (written.path, written.sha256, written.bytes)
    assert [f.carried for f in second.files if f.run_id != copied.run_id] == [False]
    _rehash(settings, second)


def test_consecutive_runs_chain_and_the_meta_node_records_each_digest(rig):
    settings, cycle = rig(keys=[2_000, 3_000])
    edge = _prepared(settings, "edge", "r1")

    runs_exec.execute_cycle(settings, [edge], {"edge"})
    first_digest = manifest.digest_of(settings, 2_000)
    runs_exec.execute_cycle(settings, [edge], {"edge"})

    second = manifest.read(settings, 3_000)
    assert second.previous is not None
    assert (second.previous.snapshot_key, second.previous.sha256) == (2_000, first_digest)
    assert cycle.meta["manifest_digest"] == manifest.digest_of(settings, 3_000)


def test_a_signed_run_writes_a_signature_beside_its_manifest(rig):
    settings, _ = rig(evidence_signing_key=generate_key())

    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    signature = manifest.read_signature(settings, 2_000)
    assert signature is not None
    assert manifest.verify(signature, bytes.fromhex(manifest.digest_of(settings, 2_000)))


def test_a_run_whose_manifest_cannot_be_written_does_not_publish(monkeypatch, rig):
    """The pointer is what makes a run visible; a run with no evidence must not
    reach it."""
    settings, cycle = rig()
    monkeypatch.setattr(manifest, "write", _boom)

    with pytest.raises(RuntimeError):
        runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    assert cycle.pointer == PREV and "set_pointer" not in cycle.steps


def _boom(*a: Any, **kw: Any) -> str:
    raise RuntimeError("manifests directory is read-only")


class _BlindSession(_Session):
    """A session that cannot read: what the graph-derived digests meet when the
    database refuses a read."""

    def execute_read(self, work: Any) -> Any:
        raise RuntimeError("no read access")


def test_a_graph_read_that_cannot_build_the_archive_prevents_publication(rig):
    """The authenticated graph archive is required publication evidence.

    Delta and checkpoint read failures remain diagnostic, but an archive read
    failure cannot publish a snapshot whose exact graph state was never sealed.
    """
    settings, cycle = rig(session=_BlindSession)

    with pytest.raises(RuntimeError, match="no read access"):
        runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    assert cycle.pointer == PREV
    assert "set_pointer" not in cycle.steps
    assert not manifest.path_for(settings, 2_000).exists()


class _RouteCollector(_DevCollector):
    """A collector whose one RIB row carries the LPM columns, so a reader can
    answer a lookup from the file it wrote; `next_hop` tells two runs apart."""

    GRAPH_MIRRORED_TABLES = ("rib",)
    SIDE_TABLES = ("rib",)
    next_hop = "10.0.0.1"

    def side_tables(self, raw: Any) -> dict[str, list[dict]]:
        from hst.core import ipenc

        lo, hi, prefixlen, af = ipenc.prefix_bounds("0.0.0.0/0")
        return {
            "rib": [
                {
                    "device_uid": "dev:r1",
                    "vrf": "default",
                    "prefix": "0.0.0.0/0",
                    "next_hop": self.next_hop,
                    "interface": "eth0",
                    "protocol": "static",
                    "metric": 1,
                    "af": af,
                    "prefixlen": prefixlen,
                    "lo": lo,
                    "hi": hi,
                }
            ]
        }


def test_a_failure_between_the_parquet_write_and_the_manifest_leaves_the_reader_at_the_previous_snapshot(
    monkeypatch, rig
):
    """The parquet file of a run that never published is on disk under its
    final name, stamped with a snapshot key the pointer never reached. The
    reader bound to the published snapshot opens the files its manifest
    lists and nothing else, so the unpublished file answers no lookup."""
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from hst.core import ribsource
    from hst.core import snapshot as snapshotmod

    settings, cycle = rig(keys=[2_000, 3_000], rib_graph_max_routes=10)
    edge = _prepared(settings, "edge", "r1")
    collector = _RouteCollector(_HostCfg(host="r1", source_name="edge"), settings)
    edge.units[0].collector = collector
    runs_exec.execute_cycle(settings, [edge], {"edge"})
    assert cycle.pointer == 2_000

    collector.next_hop = "10.9.9.9"
    monkeypatch.setattr(manifest, "write", _boom)
    with pytest.raises(RuntimeError):
        runs_exec.execute_cycle(settings, [edge], {"edge"})

    assert cycle.pointer == 2_000
    # the failed run's file is on disk under its final name, beside the published one
    assert len(list((settings.sidestore_dir / "rib").rglob("*.parquet"))) == 2
    rib = ribsource.for_snapshot(snapshotmod.Snapshot(cycle.pointer, settings))
    assert rib.approximate is False
    assert [r["next_hop"] for r in rib.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")] == ["10.0.0.1"]
    assert rib.coverage("dev:r1") == "complete"


def test_a_built_manifest_carries_the_stretch_observations_and_warnings(tmp_path):
    """Schema version 5: the reasoner's vlan-stretch findings ride in the
    manifest (`stretch_observations`, `warnings`) and read back typed; a
    manifest built without them, and every earlier version, reads empty."""
    settings = _settings(tmp_path)
    observation = {
        "circuit": "eqx:connection:c1",
        "kind": "stretched",
        "vid": 100,
        "vid_z": 100,
        "tag_a": 100,
        "tag_z": 100,
        "port_a": "dev:fr2/port/eth1-49",
        "port_z": "dev:pa3/port/eth1-49",
        "device_a": "dev:fr2",
        "device_z": "dev:pa3",
        "site_a": "fr2",
        "site_z": "pa3",
        "observed_macs": 3,
    }
    record = manifest.build(
        **_build_args(settings, 2_000),
        stretch_observations=[observation],
        warnings=["vlan 200 exists at fr2, pa3 in one bridge domain but no circuit carries it"],
    )
    # The stretch fields are in version 5 and later.
    assert record.schema_version == manifest.SCHEMA_VERSION >= 5
    assert record.stretch_observations[0].kind == "stretched"
    assert record.stretch_observations[0].observed_macs == 3
    manifest.write(settings, record)
    back = manifest.read(settings, 2_000)
    assert back.stretch_observations[0].model_dump() == observation
    assert back.warnings == ["vlan 200 exists at fr2, pa3 in one bridge domain but no circuit carries it"]

    assert manifest.build(**_build_args(settings, 3_000)).stretch_observations == []
    assert manifest.build(**_build_args(settings, 3_000)).warnings == []
    path = manifest.path_for(settings, 4_000)
    path.write_text(
        json.dumps(
            {
                "schema_version": 4,
                "snapshot_key": 4_000,
                "kind": "full",
                "opened": manifest.iso(4_000),
                "published": manifest.now_iso(),
            }
        )
    )
    old = manifest.read(settings, 4_000)
    assert old.stretch_observations == [] and old.warnings == []
