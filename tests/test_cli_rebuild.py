"""`hst rebuild --snapshot`: the manifest-driven replay behind the CLI
(core/replay.py rebuild_from_manifest).

The date path (`--as-of`) and the guards both paths share are covered in
tests/test_destructive_guards.py; this covers naming a published snapshot
and the two flags that only the manifest path has.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

import hst.cli as cli
from hst.core import manifest, replay
from hst.core.config import Settings

runner = CliRunner()

SNAPSHOT = 1_772_000_000_000
SCRATCH = "bolt://scratch:7999"


def _settings(monkeypatch, tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, neo4j_uri="bolt://twin:7687")
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    return settings


def _publish(settings, devices=()):
    record = manifest.SnapshotManifest(
        snapshot_key=SNAPSHOT,
        kind="full",
        opened=manifest.iso(SNAPSHOT),
        published=manifest.iso(SNAPSHOT + 60_000),
        devices=list(devices),
    )
    manifest.write(settings, record)
    return record


def test_exactly_one_past_must_be_named(monkeypatch, tmp_path):
    """A date and a snapshot key are two different reconstructions."""
    _settings(monkeypatch, tmp_path)
    both = runner.invoke(cli.app, ["rebuild", "--as-of", "2026-03-31", "--snapshot", str(SNAPSHOT)])
    assert both.exit_code == 2
    assert "name exactly one past" in both.stdout
    neither = runner.invoke(cli.app, ["rebuild", "--into", SCRATCH])
    assert neither.exit_code == 2
    assert "name exactly one past" in neither.stdout


def test_the_manifest_flags_are_refused_on_the_date_path(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    r = runner.invoke(cli.app, ["rebuild", "--as-of", "2026-03-31", "--allow-config-drift"])
    assert r.exit_code == 2
    assert "--allow-config-drift applies to --snapshot only" in r.stdout


def test_a_snapshot_with_no_manifest_is_reported_not_replayed(monkeypatch, tmp_path):
    """The date path is the only option for a snapshot without a manifest."""
    _settings(monkeypatch, tmp_path)
    r = runner.invoke(cli.app, ["rebuild", "--snapshot", str(SNAPSHOT), "--into", SCRATCH])
    assert r.exit_code == 1
    assert f"no manifest for snapshot {SNAPSHOT}" in r.stdout


def test_the_live_twin_is_refused_for_a_snapshot_rebuild_too(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    _publish(settings)
    r = runner.invoke(cli.app, ["rebuild", "--snapshot", str(SNAPSHOT), "--into", "bolt://twin:7687"])
    assert r.exit_code == 2
    assert "is the live twin" in r.stdout


def test_a_dry_run_reports_the_snapshots_devices_and_writes_nothing(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    _publish(
        settings,
        [
            manifest.DeviceEntry(source="edge", host="r1", outcome="collected", effective_run="900-ab12cd"),
            manifest.DeviceEntry(source="edge", host="r2", outcome="failed"),
        ],
    )

    def refuse(*args, **kw):
        raise AssertionError("a dry run must not open the target")

    monkeypatch.setattr(cli.dbmod, "session", refuse)
    r = runner.invoke(cli.app, ["rebuild", "--snapshot", str(SNAPSHOT), "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "edge/r1" in r.stdout and "collected" in r.stdout
    assert "edge/r2" in r.stdout and "failed" in r.stdout


def test_the_snapshot_path_replays_the_manifest_with_both_flags(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    _publish(settings, [manifest.DeviceEntry(source="edge", host="r1", outcome="collected")])
    scratch_dir = tmp_path / "regenerated"
    seen: dict = {}
    opened: list[str] = []

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_session(target):
        opened.append(target.neo4j_uri)
        return _Session()

    def fake_rebuild(passed_settings, target, key, **kw):
        seen.update(key=key, **kw)
        return replay.ManifestRebuildReport(
            snapshot_key=key,
            replayed=[manifest.DeviceEntry(source="edge", host="r1", outcome="collected")],
            cleared=4,
            drift=["edge: replayed under today's configuration"],
        )

    monkeypatch.setattr(cli, "_source_rows", dict)
    monkeypatch.setattr(cli.dbmod, "session", fake_session)
    monkeypatch.setattr(replay, "rebuild_from_manifest", fake_rebuild)

    r = runner.invoke(
        cli.app,
        [
            "rebuild",
            "--snapshot",
            str(SNAPSHOT),
            "--into",
            SCRATCH,
            "--allow-config-drift",
            "--sidestore-scratch",
            str(scratch_dir),
        ],
    )
    assert r.exit_code == 0, r.output
    assert seen["key"] == SNAPSHOT
    assert seen["allow_config_drift"] is True
    assert seen["sidestore_scratch_dir"] == Path(scratch_dir)
    assert opened == [SCRATCH]
    assert "cleared 4 existing node(s)" in r.stdout
    assert "replayed 1 device(s)" in r.stdout


def test_an_incomplete_rebuild_exits_non_zero(monkeypatch, tmp_path):
    """A rebuild missing a device is partial evidence."""
    settings = _settings(monkeypatch, tmp_path)
    _publish(settings, [manifest.DeviceEntry(source="edge", host="r1", outcome="collected")])

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(cli, "_source_rows", dict)
    monkeypatch.setattr(cli.dbmod, "session", lambda target: _Session())
    monkeypatch.setattr(
        replay,
        "rebuild_from_manifest",
        lambda *a, **kw: replay.ManifestRebuildReport(
            snapshot_key=SNAPSHOT, failed=[("edge/r1", "no such source configured; cannot normalize")]
        ),
    )

    r = runner.invoke(cli.app, ["rebuild", "--snapshot", str(SNAPSHOT), "--into", SCRATCH])
    assert r.exit_code == 1
    assert "no such source configured" in r.stdout
    assert "partial evidence" in r.stdout
