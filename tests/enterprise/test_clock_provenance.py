"""Collector clock trust is explicit, durable and stable across carried state."""

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from hst.analysis_model.evidence import ClockQuality, EvidencePolicy
from hst.analysis_model.temporal import manifest_evidence
from hst.app import runs_exec, sources
from hst.collectors.base import SourceConfig
from hst.core import Settings, manifest
from hst.core.model import SectionOutcome

ASSUMPTION = "collector host is synchronized to the analysis clock"


def _settings(**clock: str) -> Settings:
    return Settings(_env_file=None, hst_data_dir=Path("unused"), **clock)


def _prepared():
    collector = SimpleNamespace(config=SourceConfig(), last_device_uids=["device:one"])
    return [
        runs_exec.PreparedSource(
            SimpleNamespace(name="source"),
            [runs_exec.PreparedDevice(SimpleNamespace(host="edge"), collector, None)],
        )
    ]


def test_settings_couple_clock_quality_and_assumption(monkeypatch):
    with pytest.raises(ValidationError, match="nonempty assumption"):
        _settings(collector_clock_quality="trusted")
    with pytest.raises(ValidationError, match="nonempty assumption"):
        _settings(collector_clock_quality="trusted", collector_clock_assumption="   ")
    with pytest.raises(ValidationError, match="requires trusted quality"):
        _settings(collector_clock_assumption=ASSUMPTION)
    with pytest.raises(ValidationError):
        _settings(collector_clock_quality="uncertain", collector_clock_assumption=ASSUMPTION)

    declared = _settings(collector_clock_quality="trusted", collector_clock_assumption=ASSUMPTION)
    assert (declared.collector_clock_quality, declared.collector_clock_assumption) == ("trusted", ASSUMPTION)

    monkeypatch.setenv("COLLECTOR_CLOCK_QUALITY", "trusted")
    monkeypatch.setenv("COLLECTOR_CLOCK_ASSUMPTION", ASSUMPTION)
    from_env = Settings(_env_file=None)
    assert (from_env.collector_clock_quality, from_env.collector_clock_assumption) == ("trusted", ASSUMPTION)


def test_stored_source_config_with_clock_keys_validates_and_drops_them():
    stored = {
        "site_code": "dc1",
        "collector_clock_quality": "trusted",
        "collector_clock_assumption": ASSUMPTION,
    }
    config = SourceConfig.model_validate(stored)
    assert config.site_code == "dc1"
    assert not hasattr(config, "collector_clock_quality")
    assert not hasattr(config, "collector_clock_assumption")
    dumped = config.model_dump()
    assert "collector_clock_quality" not in dumped
    assert "collector_clock_assumption" not in dumped
    persisted, _ = sources.split_secrets(config)
    assert "collector_clock_quality" not in persisted
    assert "collector_clock_assumption" not in persisted
    assert SourceConfig.model_validate({"collector_clock_quality": "trusted"}).site_code == "home"


def test_clock_assumption_is_explicit_and_manifest_serializable(monkeypatch):
    settings = _settings(collector_clock_quality="trusted", collector_clock_assumption=ASSUMPTION)
    monkeypatch.setattr(manifest, "effective_runs", lambda *_: {})
    evidence = SimpleNamespace(
        files=[SimpleNamespace(kind="raw", source="source", host="edge", run_id="2000-abcdef")],
        devices=[
            runs_exec.DeviceOutcome(
                "source",
                "edge",
                True,
                fetch_started_ms=1_000,
                fetch_finished_ms=2_000,
                sections={"config": SectionOutcome(status="ok")},
            )
        ],
    )
    [entry] = runs_exec._device_entries(
        settings,
        3_000,
        None,
        _prepared(),
        {},
        evidence,
    )
    replay = manifest.DeviceEntry.model_validate_json(entry.model_dump_json())
    snapshot = SimpleNamespace(manifest=SimpleNamespace(devices=(replay,)))
    evaluated = manifest_evidence(
        snapshot,
        analysis_time=datetime.fromtimestamp(2, UTC),
        policy=EvidencePolicy(),
    )

    assert replay.clock_source == "collector-fetch-window"
    assert evaluated.windows[0].observation_time == datetime.fromtimestamp(2, UTC)
    assert evaluated.windows[0].clock_quality is ClockQuality.TRUSTED
    assert evaluated.windows[0].clock_source == "collector-fetch-window"
    assert evaluated.windows[0].clock_assumption == ASSUMPTION


def test_default_and_arbitrary_source_clock_remain_untrusted(monkeypatch):
    settings = _settings()
    assert settings.collector_clock_quality == "unknown"
    assert settings.collector_clock_assumption == ""
    monkeypatch.setattr(manifest, "effective_runs", lambda *_: {})
    evidence = SimpleNamespace(
        files=[SimpleNamespace(kind="raw", source="source", host="edge", run_id="2000-abcdef")],
        devices=[
            runs_exec.DeviceOutcome(
                "source",
                "edge",
                True,
                fetch_started_ms=1_000,
                fetch_finished_ms=2_000,
                sections={"config": SectionOutcome(status="ok")},
            )
        ],
    )
    [entry] = runs_exec._device_entries(settings, 3_000, None, _prepared(), {}, evidence)
    assert (entry.clock_quality, entry.clock_source, entry.clock_assumption) == ("unknown", "", "")

    device = manifest.DeviceEntry(
        source="source",
        host="edge",
        outcome="collected",
        source_clock_ms=2_000,
        clock_source="device",
        sections={"config": SectionOutcome(status="ok")},
    )
    evaluated = manifest_evidence(
        SimpleNamespace(manifest=SimpleNamespace(devices=(device,))),
        analysis_time=datetime.fromtimestamp(2, UTC),
        policy=EvidencePolicy(),
    )
    assert evaluated.windows[0].clock_quality is ClockQuality.UNKNOWN


def test_carried_failed_fetch_retains_prior_clock_provenance(monkeypatch):
    prior = manifest.DeviceEntry(
        source="source",
        host="edge",
        outcome="collected",
        fetch_started_ms=1_000,
        fetch_finished_ms=2_000,
        source_clock_ms=1_500,
        clock_quality="trusted",
        clock_source="device",
        clock_assumption="device clock is monitored",
        sections={"config": SectionOutcome(status="ok")},
    )
    previous = manifest.SnapshotManifest(
        snapshot_key=3_000,
        kind="full",
        opened=manifest.iso(3_000),
        published=manifest.iso(3_000),
        devices=[prior],
    )
    monkeypatch.setattr(manifest, "read", lambda *_: previous)
    monkeypatch.setattr(manifest, "effective_runs", lambda *_: {})
    failed = runs_exec.DeviceOutcome(
        "source",
        "edge",
        False,
        fetch_started_ms=9_000,
        fetch_finished_ms=10_000,
        error="timeout",
    )
    [entry] = runs_exec._device_entries(
        _settings(),
        11_000,
        3_000,
        _prepared(),
        {},
        SimpleNamespace(files=[], devices=[failed]),
    )

    assert entry.carried is True
    assert (entry.fetch_started_ms, entry.fetch_finished_ms, entry.source_clock_ms) == (
        1_000,
        2_000,
        1_500,
    )
    assert (entry.clock_quality, entry.clock_source, entry.clock_assumption) == (
        "trusted",
        "device",
        "device clock is monitored",
    )
    assert (entry.verified_started_ms, entry.verified_ms) == (None, None)


def _previous(prior: manifest.DeviceEntry) -> manifest.SnapshotManifest:
    return manifest.SnapshotManifest(
        snapshot_key=3_000,
        kind="full",
        opened=manifest.iso(3_000),
        published=manifest.iso(3_000),
        devices=[prior],
    )


def test_an_unchanged_fetch_is_the_carried_devices_observation(monkeypatch):
    prior = manifest.DeviceEntry(
        source="source",
        host="edge",
        outcome="collected",
        fetch_started_ms=1_000,
        fetch_finished_ms=2_000,
        sections={"config": SectionOutcome(status="ok")},
    )
    monkeypatch.setattr(manifest, "read", lambda *_: _previous(prior))
    monkeypatch.setattr(manifest, "effective_runs", lambda *_: {})
    settings = _settings(collector_clock_quality="trusted", collector_clock_assumption=ASSUMPTION)
    unchanged = runs_exec.DeviceOutcome(
        "source",
        "edge",
        True,
        skipped=True,
        verified=True,
        fetch_started_ms=7_200_000,
        fetch_finished_ms=7_201_000,
    )
    [entry] = runs_exec._device_entries(
        settings, 7_300_000, 3_000, _prepared(), {}, SimpleNamespace(files=[], devices=[unchanged])
    )

    assert entry.carried is True
    assert (entry.fetch_started_ms, entry.fetch_finished_ms) == (1_000, 2_000)
    assert (entry.verified_started_ms, entry.verified_ms) == (7_200_000, 7_201_000)
    assert (entry.clock_quality, entry.clock_source) == ("trusted", "collector-fetch-window")
    replay = manifest.DeviceEntry.model_validate_json(entry.model_dump_json())
    evaluated = manifest_evidence(
        SimpleNamespace(manifest=SimpleNamespace(devices=(replay,))),
        analysis_time=datetime.fromtimestamp(7_300, UTC),
        policy=EvidencePolicy(),
    )
    window = evaluated.windows[0]
    assert window.observation_time == datetime.fromtimestamp(7_201, UTC)
    assert window.capture_start == datetime.fromtimestamp(7_200, UTC)
    assert evaluated.gaps == ()

    # a later run that does not fetch it keeps that verification
    monkeypatch.setattr(manifest, "read", lambda *_: _previous(entry))
    [later] = runs_exec._device_entries(
        settings, 7_400_000, 3_000, _prepared(), {}, SimpleNamespace(files=[], devices=[])
    )
    assert (later.verified_started_ms, later.verified_ms) == (7_200_000, 7_201_000)


def test_the_evidence_policy_is_a_setting():
    settings = _settings(analysis_evidence_max_age_s=60, analysis_evidence_max_skew_s=5)
    assert (settings.analysis_evidence_max_age_s, settings.analysis_evidence_max_skew_s) == (60, 5)
    assert settings.analysis_evidence_consistency_mode == "bounded-window"
    with pytest.raises(ValidationError, match="requires a nonempty assumption"):
        _settings(analysis_evidence_consistency_mode="stable-window-assumption")
    with pytest.raises(ValidationError, match="requires stable-window-assumption"):
        _settings(analysis_evidence_stable_window_assumption="nothing changed")
    stable = _settings(
        analysis_evidence_consistency_mode="stable-window-assumption",
        analysis_evidence_stable_window_assumption="changes are frozen during collection",
    )
    assert stable.analysis_evidence_stable_window_assumption == "changes are frozen during collection"
