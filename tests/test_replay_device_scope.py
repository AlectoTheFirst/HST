"""Each device of a fleet replays under its own scope (core/replay.py
`device_collector`, and `rebuild`'s `device_collector_for`)."""

from __future__ import annotations

import gc
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.test_payload_release import _collector, _count_parses, _released, _two_hosts, _watch_replay_reads
from tests.test_replay import RecordingSession, _snapshot_manifest

import hst.app.sources as glue
from hst.app.crypto import dek, encrypt_secrets, generate_key
from hst.app.store import Device, Source
from hst.collectors.base import Collector, SourceConfig
from hst.core import manifest, rawstore, replay
from hst.core.config import Settings
from hst.core.model import Batch
from hst.core.uid import slug

MARCH = 1_772_000_000_000
APRIL = 1_775_000_000_000
NOW = datetime(2026, 9, 27, tzinfo=UTC)
SOURCE = "edge"


def _settings(tmp_path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


class _HostCfg(SourceConfig):
    host: str = ""
    port: int = 22
    host_key: str = ""


class _Scoped(Collector):
    """Scoped by its host, as `SshCliCollector` is. `normalized` and `tabled`
    record, across every instance, which host each payload was handled
    under and by which instance, named by the order it was built in."""

    name = "scoped"
    ConfigModel = _HostCfg
    normalized: list[tuple[int, str, str, Any]] = []
    tabled: list[tuple[int, str]] = []

    built = 0

    def __init__(self, config: _HostCfg, settings: Any) -> None:
        super().__init__(config, settings)
        self.scope = f"scoped:{config.host}"
        _Scoped.built += 1
        self.serial = _Scoped.built

    def fetch(self) -> Any:
        return {}

    def probe(self) -> str:
        return "ok"

    def normalize(self, raw: Any) -> Batch:
        _Scoped.normalized.append((self.serial, self.config.host, self.scope, raw))
        return Batch(source=SOURCE, scope=self.scope, nodes=[], rels=[])

    def side_tables(self, raw: Any) -> dict[str, list[dict[str, Any]]]:
        _Scoped.tabled.append((self.serial, self.config.host))
        return {"rib": [{"device_uid": f"dev:{self.scope}", "prefix": "0.0.0.0/0"}]}


class _NoHostCfg(SourceConfig):
    tenant: str = "t1"


class _Controller(_Scoped):
    """A controller type: its configuration has no host to scope by."""

    ConfigModel = _NoHostCfg

    def __init__(self, config: Any, settings: Any) -> None:
        Collector.__init__(self, config, settings)
        self.scope = f"controller:{config.tenant}"
        _Scoped.built += 1
        self.serial = _Scoped.built

    def normalize(self, raw: Any) -> Batch:
        _Scoped.normalized.append((self.serial, "", self.scope, raw))
        return Batch(source=SOURCE, scope=self.scope, nodes=[], rels=[])


@pytest.fixture(autouse=True)
def _fresh_records():
    _Scoped.normalized = []
    _Scoped.tabled = []


def _fleet_manifest(settings: Settings, hosts: list[str], *, tables: bool = False) -> None:
    """A published snapshot of one group source whose devices are `hosts`,
    each with a raw file of its own and, with `tables`, a side-store file the
    disk no longer holds."""
    files = []
    devices = []
    for i, host in enumerate(hosts):
        run_id = f"{MARCH + i}-abc1234{i}"
        path = rawstore.write(settings.raw_dir, SOURCE, run_id, {"host": host}, host=host, key=dek(settings))
        files.append(manifest.file_entry(settings, path))
        if tables:
            from hst.core import sidestore

            rib = sidestore.write_table(
                settings.sidestore_dir,
                "rib",
                SOURCE,
                host,
                run_id,
                [{"device_uid": "x", "prefix": "p"}],
                MARCH,
            )
            files.append(manifest.file_entry(settings, rib))
            rib.unlink()
        devices.append(
            manifest.DeviceEntry(
                source=SOURCE, host=host, outcome="collected", effective_run=run_id, fetch_ts_ms=MARCH + i
            )
        )
    digest = manifest.source_config_digest(SOURCE, "scoped", True, {})
    entry = manifest.SourceEntry(name=SOURCE, type="scoped", status="fresh", config_sha256=digest)
    manifest.write(settings, _snapshot_manifest(2_000, [entry], devices, files))


def _lookup(collector: Any) -> replay.SourceLookup:
    return replay.SourceLookup(collector=collector, type="scoped", enabled=True, config={})


# --- manifest-driven replay -------------------------------------------------------------


@pytest.mark.parametrize("dry_run", [False, True])
def test_each_fleet_device_of_a_manifest_replays_under_its_own_host(tmp_path, dry_run):
    settings = _settings(tmp_path)
    hosts = ["10.0.0.1", "Core-2.example.net", "2001:db8::2"]
    _fleet_manifest(settings, hosts)
    group = _Scoped(_HostCfg(host="", source_name=SOURCE), settings)

    report = replay.rebuild_from_manifest(
        settings, RecordingSession(), 2_000, source_for=lambda name: _lookup(group), dry_run=dry_run
    )

    assert report.ok, report.failed
    assert [(host, scope, raw) for _, host, scope, raw in _Scoped.normalized] == [
        (host, f"scoped:{host}", {"host": host}) for host in hosts
    ]
    instances = {instance for instance, *_ in _Scoped.normalized}
    assert len(instances) == len(hosts) and group.serial not in instances


def test_a_regenerated_side_table_comes_from_the_devices_own_collector(tmp_path):
    pytest.importorskip("pyarrow")
    settings = _settings(tmp_path)
    hosts = ["10.0.0.1", "10.0.0.2"]
    _fleet_manifest(settings, hosts, tables=True)
    group = _Scoped(_HostCfg(host="", source_name=SOURCE), settings)

    report = replay.rebuild_from_manifest(
        settings,
        RecordingSession(),
        2_000,
        source_for=lambda name: _lookup(group),
        sidestore_scratch_dir=tmp_path / "scratch",
    )

    assert report.ok, report.failed
    assert [host for _, host in _Scoped.tabled] == hosts
    # each device's rows come from the collector that normalized it
    assert [instance for instance, _ in _Scoped.tabled] == [instance for instance, *_ in _Scoped.normalized]
    assert all("regenerated" in note for note in report.side_table_notes)


def test_the_single_device_of_a_source_with_a_host_replays_under_the_sources_collector(tmp_path):
    settings = _settings(tmp_path)
    _fleet_manifest(settings, ["r1"])
    own = _Scoped(_HostCfg(host="r1", source_name=SOURCE), settings)

    report = replay.rebuild_from_manifest(
        settings, RecordingSession(), 2_000, source_for=lambda name: _lookup(own)
    )

    assert report.ok, report.failed
    assert [(instance, host) for instance, host, _, _ in _Scoped.normalized] == [(own.serial, "r1")]


def test_a_collector_whose_configuration_has_no_host_replays_as_it_is(tmp_path):
    settings = _settings(tmp_path)
    _fleet_manifest(settings, ["ctrl.example.net"])
    controller = _Controller(_NoHostCfg(source_name=SOURCE), settings)

    report = replay.rebuild_from_manifest(
        settings, RecordingSession(), 2_000, source_for=lambda name: _lookup(controller)
    )

    assert report.ok, report.failed
    assert [(instance, scope) for instance, _, scope, _ in _Scoped.normalized] == [
        (controller.serial, "controller:t1")
    ]


def test_a_device_collector_that_cannot_be_built_fails_that_device_only(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    _fleet_manifest(settings, ["r1", "r2"])
    group = _Scoped(_HostCfg(host="", source_name=SOURCE), settings)
    real = _Scoped.__init__

    def refusing(self: _Scoped, config: _HostCfg, settings: Any) -> None:
        if config.host == "r1":
            raise ValueError("r1 cannot be built")
        real(self, config, settings)

    monkeypatch.setattr(_Scoped, "__init__", refusing)
    report = replay.rebuild_from_manifest(
        settings, RecordingSession(), 2_000, source_for=lambda name: _lookup(group)
    )

    assert report.failed == [(f"{SOURCE}/r1", "ValueError: r1 cannot be built")]
    assert [host for _, host, _, _ in _Scoped.normalized] == ["r2"]


# --- date-based replay ------------------------------------------------------------------


def test_each_host_directory_of_a_date_based_rebuild_replays_under_its_own_host(tmp_path):
    settings = _settings(tmp_path)
    for i, host in enumerate(["10.0.0.1", "r2"]):
        rawstore.write(
            settings.raw_dir, SOURCE, f"{MARCH + i}-abc1234{i}", {"host": host}, host=host, key=dek(settings)
        )
    group = _Scoped(_HostCfg(host="", source_name=SOURCE), settings)

    report = replay.rebuild(settings, RecordingSession(), APRIL, collector_for=lambda source: group)

    assert report.ok, report.failed
    assert sorted((host, scope) for _, host, scope, _ in _Scoped.normalized) == [
        ("10.0.0.1", "scoped:10.0.0.1"),
        ("r2", "scoped:r2"),
    ]
    assert group.serial not in {instance for instance, *_ in _Scoped.normalized}


def test_a_source_whose_host_names_its_directory_keeps_its_collector_in_a_date_based_rebuild(tmp_path):
    """The directory holds the slugged host; a source whose own host slugs to
    it is that device, and keeps the host as configured."""
    settings = _settings(tmp_path)
    rawstore.write(
        settings.raw_dir, SOURCE, f"{MARCH}-abc12345", {"host": "R1"}, host="R1", key=dek(settings)
    )
    own = _Scoped(_HostCfg(host="R1", source_name=SOURCE), settings)

    report = replay.rebuild(settings, RecordingSession(), APRIL, collector_for=lambda source: own)

    assert report.ok, report.failed
    assert [(instance, host) for instance, host, _, _ in _Scoped.normalized] == [(own.serial, "R1")]


def _write_hosts(settings: Settings, hosts: list[str]) -> None:
    for i, host in enumerate(hosts):
        rawstore.write(
            settings.raw_dir, SOURCE, f"{MARCH + i}-abc1234{i}", {"host": host}, host=host, key=dek(settings)
        )


def test_a_date_based_rebuild_takes_the_collector_of_the_device_configured_under_a_host_directory(tmp_path):
    """A host directory holds the slugged host, which upper case and an IPv6
    address's colons do not survive. The caller's collector of the device
    configured under the directory carries the host as configured; a
    directory no device is configured under falls back to the source's
    collector, built for the directory's name."""
    settings = _settings(tmp_path)
    hosts = ["Core-2.example.net", "2001:db8::2", "10.0.0.3"]
    _write_hosts(settings, hosts)
    group = _Scoped(_HostCfg(host="", source_name=SOURCE), settings)
    configured = {slug(host): host for host in hosts[:2]}
    asked: list[tuple[str, str]] = []

    def device_collector_for(source: str, host: str) -> Any:
        asked.append((source, host))
        if host not in configured:
            return None
        return _Scoped(_HostCfg(host=configured[host], source_name=SOURCE), settings)

    report = replay.rebuild(
        settings,
        RecordingSession(),
        APRIL,
        collector_for=lambda source: group,
        device_collector_for=device_collector_for,
    )

    assert report.ok, report.failed
    assert asked == [(SOURCE, "core-2.example.net"), (SOURCE, "2001-db8-2"), (SOURCE, "10.0.0.3")]
    assert [(host, scope, raw) for _, host, scope, raw in _Scoped.normalized] == [
        (host, f"scoped:{host}", {"host": host}) for host in hosts
    ]


def test_a_date_based_device_collector_that_cannot_be_built_fails_that_device_only(tmp_path):
    settings = _settings(tmp_path)
    _write_hosts(settings, ["r1", "r2"])
    group = _Scoped(_HostCfg(host="", source_name=SOURCE), settings)

    def device_collector_for(source: str, host: str) -> Any:
        if host == "r1":
            raise ValueError("r1 cannot be built")
        return None

    report = replay.rebuild(
        settings,
        RecordingSession(),
        APRIL,
        collector_for=lambda source: group,
        device_collector_for=device_collector_for,
    )

    assert report.failed == [(f"{SOURCE}/r1", "ValueError: r1 cannot be built")]
    assert [host for _, host, _, _ in _Scoped.normalized] == ["r2"]
    assert [s.host for s in report.replayed] == ["r2"]


def test_a_date_based_failure_names_the_host_directory_as_missing_does(tmp_path):
    settings = _settings(tmp_path)
    _write_hosts(settings, ["r1"])
    rawstore.write(settings.raw_dir, "ctl", f"{MARCH}-abc12349", {"host": ""}, key=dek(settings))

    report = replay.rebuild(settings, RecordingSession(), APRIL, collector_for=lambda source: None)

    assert sorted(label for label, _ in report.failed) == ["ctl", f"{SOURCE}/r1"]


# --- the cycle's own build --------------------------------------------------------------


def _row(settings: Settings, type_: str) -> Source:
    config, secrets = glue.validate_source(
        type_,
        {
            "host": "",
            "auth": {"method": "password", "username": "ro", "password": "pw"},
            "site_code": "dc1",
            "routing_scope": "corp",
        },
    )
    return Source(1, SOURCE, type_, config, encrypt_secrets(dek(settings), secrets), True, NOW, NOW)


@pytest.mark.parametrize("type_", ["iosxe", "iosxr", "nxos", "vyos"])
def test_the_device_collector_is_the_one_the_cycle_builds(type_, tmp_path):
    settings = _settings(tmp_path)
    row = _row(settings, type_)
    rows = {row.name: row}
    for device in (
        Device(1, SOURCE, "10.0.0.1", 2222, True, "ssh-ed25519 PIN", NOW, NOW),
        Device(2, SOURCE, "Core-2.example.net", None, True, "", NOW, NOW),
    ):
        cycle = glue.build_device_collector(row, device, settings, sources=rows)
        built = replay.device_collector(glue.build_collector(row, settings, sources=rows), device.host)

        assert type(built) is type(cycle)
        assert built.scope == cycle.scope == f"{type_}:{device.host}"
        # the port and the pinned host key are the fetch's alone
        fields = {"port", "host_key"}
        assert built.config.model_dump(exclude=fields) == cycle.config.model_dump(exclude=fields)
        assert built.config.resolved_origins == cycle.config.resolved_origins


def test_the_device_collector_normalizes_as_the_cycles_does(tmp_path):
    from tests.test_iosxe import RAW

    settings = _settings(tmp_path)
    row = _row(settings, "iosxe")
    device = Device(1, SOURCE, "10.0.0.9", None, True, "", NOW, NOW)
    cycle = glue.build_device_collector(row, device, settings, sources={row.name: row})
    group = glue.build_collector(row, settings, sources={row.name: row})

    built = replay.device_collector(group, device.host)

    assert built.normalize(dict(RAW)) == cycle.normalize(dict(RAW))
    assert group.normalize(dict(RAW)).scope != cycle.normalize(dict(RAW)).scope


def test_a_date_based_rebuild_loads_each_configured_device_under_the_cycles_scope(tmp_path):
    """A group whose devices are addressed by a mixed-case name and an IPv6
    address, both of which slugging changes. Built by the caller from the
    device rows, as the CLI builds them, each device loads under the scope
    the cycle gives it; without them, under its directory's name."""
    from tests.test_iosxe import RAW

    settings = _settings(tmp_path)
    row = _row(settings, "iosxe")
    rows = {row.name: row}
    devices = [
        Device(1, SOURCE, "Core-2.example.net", None, True, "", NOW, NOW),
        Device(2, SOURCE, "2001:db8::2", 830, True, "ssh-ed25519 PIN", NOW, NOW),
    ]
    for i, device in enumerate(devices):
        rawstore.write(
            settings.raw_dir,
            SOURCE,
            f"{MARCH + i}-abc1234{i}",
            dict(RAW),
            host=device.host,
            key=dek(settings),
        )
    by_directory = {(slug(d.source), slug(d.host)): d for d in devices}

    def collector_for(source: str) -> Any:
        return glue.build_collector(rows[source], settings, sources=rows)

    def device_collector_for(source: str, host: str) -> Any:
        device = by_directory.get((source, host))
        if device is None:
            return None
        return glue.build_device_collector(rows[source], device, settings, sources=rows)

    report = replay.rebuild(
        settings,
        RecordingSession(),
        APRIL,
        collector_for=collector_for,
        device_collector_for=device_collector_for,
    )
    fallback = replay.rebuild(settings, RecordingSession(), APRIL, collector_for=collector_for)

    cycle = [glue.build_device_collector(row, d, settings, sources=rows).scope for d in devices]
    assert report.ok, report.failed
    assert [m.scope for m in report.manifests] == cycle == ["iosxe:Core-2.example.net", "iosxe:2001:db8::2"]
    assert [m.scope for m in fallback.manifests] == ["iosxe:core-2.example.net", "iosxe:2001-db8-2"]


# --- payload release --------------------------------------------------------------------
#
# `sw1` is the host of the source's own collector, so its device is normalized
# by that collector, which the caller keeps; `sw2` has a collector of its own.


def _iosxe_manifest(settings: Settings, written: list[tuple[str, str, Any]]) -> None:
    files = [manifest.file_entry(settings, path) for _, _, path in written]
    devices = [
        manifest.DeviceEntry(
            source=SOURCE, host=host, outcome="collected", effective_run=run_id, fetch_ts_ms=MARCH
        )
        for host, run_id, _ in written
    ]
    digest = manifest.source_config_digest(SOURCE, "iosxe", True, {})
    entry = manifest.SourceEntry(name=SOURCE, type="iosxe", status="fresh", config_sha256=digest)
    manifest.write(settings, _snapshot_manifest(2_000, [entry], devices, files))


def _replay(path: str, settings: Settings, collector: Any, *, dry_run: bool = False) -> Any:
    if path == "rebuild":
        return replay.rebuild(
            settings, RecordingSession(), APRIL, collector_for=lambda source: collector, dry_run=dry_run
        )
    lookup = replay.SourceLookup(collector=collector, type="iosxe", enabled=True, config={})
    return replay.rebuild_from_manifest(
        settings, RecordingSession(), 2_000, source_for=lambda name: lookup, dry_run=dry_run
    )


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("path", ["rebuild", "rebuild_from_manifest"])
def test_a_source_collector_a_device_is_normalized_by_holds_no_payload_after_the_replay(
    tmp_path, monkeypatch, path, dry_run
):
    settings = _settings(tmp_path)
    _iosxe_manifest(settings, _two_hosts(settings))
    collector = _collector(settings, host="sw1")
    parses = _count_parses(monkeypatch)

    report = _replay(path, settings, collector, dry_run=dry_run)

    assert report.ok, report.failed
    assert len(parses) == 2
    assert collector._parsed_for is None, "the source's collector normalized sw1 and still holds its payload"
    assert _released(collector)


@pytest.mark.parametrize("path", ["rebuild", "rebuild_from_manifest"])
def test_no_payload_is_alive_while_a_replay_loads(tmp_path, monkeypatch, path):
    """The load reads the Batch alone: the payload and its parse are released
    before it, by the source's own collector and by a device's own alike."""
    settings = _settings(tmp_path)
    _iosxe_manifest(settings, _two_hosts(settings))
    collector = _collector(settings, host="sw1")
    payloads = _watch_replay_reads(monkeypatch)
    alive_at_load: list[int] = []
    real_load = replay.load

    def load(*args: Any, **kwargs: Any) -> Any:
        gc.collect()
        alive_at_load.append(sum(ref() is not None for ref in payloads))
        return real_load(*args, **kwargs)

    monkeypatch.setattr(replay, "load", load)
    report = _replay(path, settings, collector)

    assert report.ok, report.failed
    assert len(payloads) == 2
    assert alive_at_load == [0, 0]
    assert _released(collector)
