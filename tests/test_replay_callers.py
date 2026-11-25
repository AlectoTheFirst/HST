"""The collectors the replay callers hand `core/replay.py`: built as the cycle
builds them, with every site (a group that inherits its routing scope from its
site replays under that scope) and every source row (a collector that links
another source finds it), and one per configured device of a fleet.

The callers are `hst rebuild --as-of`, `hst rebuild --snapshot`, the
side-store repair (`hst reconcile --repair`) and POST
/api/snapshots/{key}/rebuild. The collectors themselves are stand-ins: what
is checked is what each caller builds them from."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import hst.cli as cli
from hst.app import sources as glue
from hst.core import manifest, replay
from hst.core.config import Settings

runner = CliRunner()
SCRATCH = "bolt://scratch:7999"
TS = 1_772_000_000_000
ROWS = {"edge": SimpleNamespace(name="edge", type="iosxe", enabled=True, config={"site_code": "hq"})}
SITES = {"hq": SimpleNamespace(code="hq")}
DEVICES = {("edge", "r1"): SimpleNamespace(source="edge", host="R1")}
# the device identity registry as the callers read it (`cli._registry_snapshot`)
REGISTRY = SimpleNamespace(name="registry")


@pytest.fixture
def built(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any, dict[str, Any]]]:
    """Every collector the callers build: which builder, for what, and with
    which keyword arguments."""
    calls: list[tuple[str, Any, dict[str, Any]]] = []

    def build_collector(row: Any, settings: Any, resolver: Any = None, **kw: Any) -> Any:
        calls.append(("group", row.name, kw))
        return SimpleNamespace(built_for=row.name)

    def build_device_collector(row: Any, device: Any, settings: Any, resolver: Any = None, **kw: Any) -> Any:
        calls.append(("device", (row.name, device.host), kw))
        return SimpleNamespace(built_for=(row.name, device.host))

    monkeypatch.setattr(glue, "build_collector", build_collector)
    monkeypatch.setattr(glue, "build_device_collector", build_device_collector)
    monkeypatch.setattr(cli, "_registry_snapshot", lambda: REGISTRY)
    return calls


def _settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Settings:
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, neo4j_uri="bolt://twin:7687")
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    return settings


@contextmanager
def _session(target: Any) -> Any:
    yield object()


def test_a_rebuild_by_date_builds_one_collector_per_configured_device(monkeypatch, tmp_path, built):
    _settings(monkeypatch, tmp_path)
    snapshots = [
        replay.Snapshot(source="edge", host="r1", run_id="x", ts_ms=TS - 1000, path=tmp_path / "a"),
        replay.Snapshot(source="edge", host="r9", run_id="y", ts_ms=TS - 1000, path=tmp_path / "b"),
    ]
    monkeypatch.setattr(replay, "plan", lambda raw_dir, as_of_ms: (snapshots, []))
    monkeypatch.setattr(cli, "_replay_inventory", lambda: (ROWS, DEVICES, SITES))
    monkeypatch.setattr(cli.dbmod, "session", _session)
    seen: dict[str, Any] = {}

    def fake_rebuild(settings: Any, target: Any, as_of_ms: int, **kw: Any) -> Any:
        seen["group"] = kw["collector_for"]("edge")
        seen["unknown"] = kw["collector_for"]("vco")
        seen["device"] = kw["device_collector_for"]("edge", "r1")
        seen["no_device"] = kw["device_collector_for"]("edge", "r9")
        return replay.RebuildReport(as_of_ms=as_of_ms, replayed=snapshots)

    monkeypatch.setattr(replay, "rebuild", fake_rebuild)
    r = runner.invoke(cli.app, ["rebuild", "--as-of", "2026-03-31", "--into", SCRATCH])

    assert r.exit_code == 0, r.output
    assert "edge/r1" in r.stdout and "edge/r9" in r.stdout
    assert seen["group"].built_for == "edge"
    assert seen["unknown"] is None
    assert seen["device"].built_for == ("edge", "R1")
    assert seen["no_device"] is None
    assert built == [
        ("group", "edge", {"sites": SITES, "sources": ROWS, "identity": REGISTRY}),
        ("device", ("edge", "R1"), {"sites": SITES, "sources": ROWS, "identity": REGISTRY}),
    ]


def test_a_rebuild_by_date_finds_no_row_by_its_collector_type(monkeypatch, tmp_path, built):
    """A raw directory is named after its source row; another row of the same
    type is not that source."""
    _settings(monkeypatch, tmp_path)
    snapshot = replay.Snapshot(source="iosxe", host="r1", run_id="x", ts_ms=TS - 1000, path=tmp_path / "a")
    monkeypatch.setattr(replay, "plan", lambda raw_dir, as_of_ms: ([snapshot], []))
    monkeypatch.setattr(cli, "_replay_inventory", lambda: (ROWS, {}, SITES))
    monkeypatch.setattr(cli.dbmod, "session", _session)
    seen: dict[str, Any] = {}

    def fake_rebuild(settings: Any, target: Any, as_of_ms: int, **kw: Any) -> Any:
        seen["collector"] = kw["collector_for"]("iosxe")
        return replay.RebuildReport(as_of_ms=as_of_ms)

    monkeypatch.setattr(replay, "rebuild", fake_rebuild)
    r = runner.invoke(cli.app, ["rebuild", "--as-of", "2026-03-31", "--into", SCRATCH])

    assert r.exit_code == 0, r.output
    assert seen["collector"] is None
    assert built == []


def test_a_rebuild_by_snapshot_builds_its_collectors_with_the_sites(monkeypatch, tmp_path, built):
    settings = _settings(monkeypatch, tmp_path)
    manifest.write(
        settings,
        manifest.SnapshotManifest(
            snapshot_key=TS,
            kind="full",
            opened=manifest.iso(TS),
            published=manifest.iso(TS + 60_000),
            devices=[manifest.DeviceEntry(source="edge", host="r1", outcome="collected")],
        ),
    )
    monkeypatch.setattr(cli, "_source_rows", lambda: ROWS)
    monkeypatch.setattr(cli, "_sites", lambda: SITES)
    monkeypatch.setattr(cli.dbmod, "session", _session)
    seen: dict[str, Any] = {}

    def fake_rebuild(settings: Any, target: Any, key: int, **kw: Any) -> Any:
        seen["lookup"] = kw["source_for"]("edge")
        return replay.ManifestRebuildReport(snapshot_key=key)

    monkeypatch.setattr(replay, "rebuild_from_manifest", fake_rebuild)
    r = runner.invoke(cli.app, ["rebuild", "--snapshot", str(TS), "--into", SCRATCH])

    assert r.exit_code == 0, r.output
    assert seen["lookup"].collector.built_for == "edge"
    assert built == [("group", "edge", {"sites": SITES, "sources": ROWS, "identity": REGISTRY})]


def test_the_repair_builds_a_device_collector_for_a_host_no_device_is_configured_with(
    monkeypatch, tmp_path, built
):
    """The group's own collector names the group's host; a device without a
    serial would derive its uid, and the regenerated rows theirs, from that."""
    monkeypatch.setattr(cli, "_replay_inventory", lambda: (ROWS, DEVICES, SITES))
    placed: list[tuple[Any, str, bool]] = []

    def device_collector(collector: Any, host: str, *, slugged: bool = False) -> Any:
        placed.append((collector.built_for, host, slugged))
        return SimpleNamespace(built_for=("edge", host))

    monkeypatch.setattr(replay, "device_collector", device_collector)
    collector_for = cli._repair_collector_for(Settings(_env_file=None, hst_data_dir=tmp_path), glue)

    assert collector_for("edge", "r1").built_for == ("edge", "R1")
    assert collector_for("edge", "r9").built_for == ("edge", "r9")
    assert collector_for("vco", "r1") is None
    assert placed == [("edge", "r9", True)]
    assert built == [
        ("device", ("edge", "R1"), {"sites": SITES, "sources": ROWS, "identity": REGISTRY}),
        ("group", "edge", {"sites": SITES, "sources": ROWS, "identity": REGISTRY}),
    ]
