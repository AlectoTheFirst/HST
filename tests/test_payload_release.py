"""A load leaves no payload behind the collector that loaded it."""

from __future__ import annotations

import gc
import weakref
from typing import Any

import pytest
from tests.test_collector_execute import FakeSession
from tests.test_iosxe import RAW
from tests.test_replay import RecordingSession, _snapshot_manifest

from hst import collectors as coll
from hst.app.crypto import dek, generate_key
from hst.collectors import cli_collector, iosxe
from hst.collectors.auth import SshPassword
from hst.collectors.base import new_run_id
from hst.collectors.iosxe import IosxeCollector, IosxeConfig
from hst.core import manifest, rawstore, replay
from hst.core.config import Settings

MARCH = 1_772_000_000_000
APRIL = 1_775_000_000_000
SOURCE = "edge"


class _Payload(dict):
    """A payload a weak reference can watch: a plain dict cannot be one's
    referent, a subclass can."""


def _settings(tmp_path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _collector(settings: Settings | None, host: str = "sw1x") -> IosxeCollector:
    config = IosxeConfig(
        host=host,
        auth=SshPassword(username="ro", password="pw"),
        site_code="hq",
        l3dom="corp",
        source_name=SOURCE,
    )
    return IosxeCollector(config, settings)


def _count_parses(monkeypatch) -> list[int]:
    """Every parse the family runs from here on, one entry per payload."""
    parses: list[int] = []

    def counting(raw: dict[str, str]) -> dict[str, Any]:
        parses.append(id(raw))
        return iosxe.parse(raw)

    monkeypatch.setattr(IosxeCollector, "_parse", staticmethod(counting))
    return parses


def _released(collector: IosxeCollector) -> bool:
    return collector._parsed_for is None and collector._parsed is None


def _load(collector: IosxeCollector, raw: dict[str, Any]) -> Any:
    return coll.load_payload(
        collector,
        FakeSession(),
        raw,
        collection_ts=MARCH,
        run_id=new_run_id(MARCH),
        ts_ms=MARCH,
        source_name=SOURCE,
    )


def _observe(collector: IosxeCollector, raw: dict[str, Any]) -> Any:
    return coll.load_observations(
        collector,
        raw,
        collection_ts=MARCH,
        run_id=new_run_id(MARCH),
        ts_ms=MARCH,
        source_name=SOURCE,
    )


# --- the load functions ------------------------------------------------------------


def test_load_payload_parses_once_and_releases_the_parse_when_it_returns(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    collector = _collector(_settings(tmp_path))
    parses = _count_parses(monkeypatch)

    loaded = _load(collector, dict(RAW))

    assert loaded.nodes_upserted, "the payload normalized and loaded"
    assert {loaded.tables[t].status for t in ("rib", "arp")} == {"complete"}
    assert len(parses) == 1, "normalize, sections and side_tables still share one parse"
    assert _released(collector)


def test_load_observations_releases_the_parse_when_it_returns(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    collector = _collector(_settings(tmp_path))
    parses = _count_parses(monkeypatch)

    written = _observe(collector, dict(RAW))

    assert written.tables["arp"].status == "complete"
    assert len(parses) == 1
    assert _released(collector)


@pytest.mark.parametrize("run", [_load, _observe], ids=["load_payload", "load_observations"])
def test_a_load_whose_parse_raises_releases_the_parse_it_held(tmp_path, monkeypatch, run):
    """The cache is warm from an earlier payload when the next one fails to
    parse. The failed load must not leave the earlier one pinned."""
    collector = _collector(_settings(tmp_path))
    earlier = dict(RAW)
    collector.sections(earlier)
    assert collector._parsed_for is earlier

    def unreadable(raw: dict[str, str]) -> dict[str, Any]:
        raise RuntimeError("unreadable answer")

    monkeypatch.setattr(IosxeCollector, "_parse", staticmethod(unreadable))
    with pytest.raises(RuntimeError, match="unreadable answer"):
        run(collector, dict(RAW))

    assert _released(collector)


def test_a_load_whose_normalize_raises_after_the_parse_releases_it(tmp_path, monkeypatch):
    """The parse succeeded and filled the cache; normalize failed after it."""
    collector = _collector(_settings(tmp_path))
    parses = _count_parses(monkeypatch)

    def failing(inter: dict[str, Any], **kw: Any) -> Any:
        raise ValueError("normalize failed")

    monkeypatch.setattr(cli_collector, "normalize_cisco", failing)
    with pytest.raises(ValueError, match="normalize failed"):
        _load(collector, dict(RAW))

    assert len(parses) == 1, "the parse ran and filled the cache before normalize raised"
    assert _released(collector)


def test_a_payload_handed_to_execute_is_freed_once_execute_returns(tmp_path):
    """The whole invariant, from the outside: once `execute` has stored,
    normalized, loaded and written the side tables, nothing but the caller
    holds the payload, and a caller that drops it frees it."""
    pytest.importorskip("pyarrow")
    collector = _collector(_settings(tmp_path))
    raw = _Payload(RAW)
    watch = weakref.ref(raw)

    loaded = coll.execute(collector, FakeSession(), collection_ts=MARCH, source_name=SOURCE, raw=raw)
    assert loaded.nodes_upserted

    del raw
    gc.collect()
    assert watch() is None, "the collector, or something the load left behind, still holds the payload"

    again = coll.execute(collector, FakeSession(), collection_ts=MARCH, source_name=SOURCE, raw=dict(RAW))
    assert again.nodes_upserted == loaded.nodes_upserted
    assert _released(collector)


def test_the_default_release_is_a_no_op_every_load_can_call(tmp_path):
    """A collector with no per-payload cache inherits a release that does
    nothing, so the load functions call it on every collector."""
    from tests.test_collector_execute import DevCollector, HostCfg

    collector = DevCollector(HostCfg(host="r1", source_name=SOURCE), _settings(tmp_path))
    assert collector.release_payload() is None
    assert _load(collector, {"seen": 1}).nodes_upserted == 1


# --- replay ------------------------------------------------------------------------


def _two_hosts(settings: Settings) -> list[tuple[str, str, Any]]:
    """Two devices of one source, one raw file each: (host, run id, path)."""
    out = []
    for host, nonce in (("sw1", "aaaa0001"), ("sw2", "aaaa0002")):
        run_id = f"{MARCH}-{nonce}"
        path = rawstore.write(settings.raw_dir, SOURCE, run_id, dict(RAW), host=host, key=dek(settings))
        out.append((host, run_id, path))
    return out


def _watch_replay_reads(monkeypatch) -> list[weakref.ref]:
    """A weak reference to every payload replay reads from here on."""
    read = replay.read
    seen: list[weakref.ref] = []

    def watched(path: Any, key: str) -> Any:
        payload = _Payload(read(path, key))
        seen.append(weakref.ref(payload))
        return payload

    monkeypatch.setattr(replay, "read", watched)
    return seen


@pytest.mark.parametrize("dry_run", [False, True])
def test_rebuild_leaves_no_payload_behind_the_collectors_of_its_snapshots(tmp_path, monkeypatch, dry_run):
    settings = _settings(tmp_path)
    _two_hosts(settings)
    collector = _collector(settings)
    parses = _count_parses(monkeypatch)
    payloads = _watch_replay_reads(monkeypatch)

    report = replay.rebuild(
        settings, RecordingSession(), APRIL, collector_for=lambda src: collector, dry_run=dry_run
    )

    assert report.ok, report.failed
    assert sorted(s.host for s in report.replayed) == ["sw1", "sw2"]
    assert len(parses) == 2
    gc.collect()
    assert len(payloads) == 2 and all(ref() is None for ref in payloads)


@pytest.mark.parametrize("dry_run", [False, True])
def test_rebuild_from_manifest_leaves_no_payload_behind_and_parses_each_device_once(
    tmp_path, monkeypatch, dry_run
):
    """Each device is normalized by its own collector, built from its
    source's. Each device's missing side-store file is regenerated from the
    parse its normalize already made, so the release does not cost a second
    parse; after the replay neither payload is alive."""
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    settings = _settings(tmp_path)
    files = []
    devices = []
    for host, run_id, path in _two_hosts(settings):
        files.append(manifest.file_entry(settings, path))
        # a side-store file the manifest names and the disk no longer holds
        arp = sidestore.write_table(
            settings.sidestore_dir, "arp", SOURCE, host, run_id, [{"device_uid": "d", "ip": "x"}], MARCH
        )
        files.append(manifest.file_entry(settings, arp))
        arp.unlink()
        devices.append(
            manifest.DeviceEntry(
                source=SOURCE, host=host, outcome="collected", effective_run=run_id, fetch_ts_ms=MARCH
            )
        )
    digest = manifest.source_config_digest(SOURCE, "iosxe", True, {})
    entry = manifest.SourceEntry(name=SOURCE, type="iosxe", status="fresh", config_sha256=digest)
    manifest.write(settings, _snapshot_manifest(2_000, [entry], devices, files))

    collector = _collector(settings)
    lookup = replay.SourceLookup(collector=collector, type="iosxe", enabled=True, config={})
    parses = _count_parses(monkeypatch)
    payloads = _watch_replay_reads(monkeypatch)
    scratch = tmp_path / "scratch"
    report = replay.rebuild_from_manifest(
        settings,
        RecordingSession(),
        2_000,
        source_for=lambda name: lookup,
        sidestore_scratch_dir=scratch,
        dry_run=dry_run,
    )

    assert report.ok, report.failed
    assert sorted(d.host for d in report.replayed) == ["sw1", "sw2"]
    assert len(parses) == 2, "one parse per device, shared by normalize and the side-table regeneration"
    if not dry_run:
        assert sorted(n.split(":")[0] for n in report.side_table_notes) == [f"{SOURCE}/sw1", f"{SOURCE}/sw2"]
        assert all("regenerated" in n for n in report.side_table_notes)
    gc.collect()
    assert len(payloads) == 2 and all(ref() is None for ref in payloads)
