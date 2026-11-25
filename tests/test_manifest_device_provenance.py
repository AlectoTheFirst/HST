"""Published manifests retain the exact Device nodes produced by each source unit."""

from pathlib import Path
from types import SimpleNamespace

from pydantic import BaseModel, SecretStr

from hst.app import runs_exec
from hst.core import Settings, manifest
from hst.core.model import SectionOutcome, TableOutcome


def _source(name: str, host: str, device_uids: list[str] | None, *, fleet_host: str | None = None):
    collector = SimpleNamespace(
        config=SimpleNamespace(host=host),
        last_device_uids=device_uids,
    )
    device = SimpleNamespace(host=fleet_host) if fleet_host is not None else None
    return runs_exec.PreparedSource(
        SimpleNamespace(name=name),
        [runs_exec.PreparedDevice(device, collector, None)],
    )


def test_manifest_records_fleet_and_controller_device_uids(monkeypatch):
    settings = Settings(_env_file=None, hst_data_dir=Path("unused"))
    monkeypatch.setattr(manifest, "effective_runs", lambda *_: {})
    prepared = [
        _source("fleet", "ignored", ["device:b", "device:a", "device:a"], fleet_host="edge-1"),
        _source("controller", "controller.example", ["device:leaf-1", "device:leaf-2"]),
    ]
    evidence = SimpleNamespace(
        files=[],
        devices=[
            runs_exec.DeviceOutcome("fleet", "edge-1", True),
            runs_exec.DeviceOutcome("controller", "controller.example", True),
        ],
    )

    entries = runs_exec._device_entries(settings, 2_000, None, prepared, {}, evidence)

    assert {(entry.source, entry.host): entry.device_uids for entry in entries} == {
        ("fleet", "edge-1"): ["device:a", "device:b"],
        ("controller", "controller.example"): ["device:leaf-1", "device:leaf-2"],
    }


def test_carried_entry_preserves_historical_device_uids(monkeypatch):
    settings = Settings(_env_file=None, hst_data_dir=Path("unused"))
    monkeypatch.setattr(manifest, "effective_runs", lambda *_: {})
    previous = manifest.SnapshotManifest(
        snapshot_key=1_000,
        kind="full",
        opened=manifest.iso(1_000),
        published=manifest.iso(1_000),
        devices=[
            manifest.DeviceEntry(
                source="controller",
                host="controller.example",
                outcome="collected",
                device_uids=["device:historical-leaf"],
                sections={"config": SectionOutcome(status="ok")},
                expected_sections=["config"],
                tables={"rib": TableOutcome(status="complete-empty")},
            )
        ],
    )
    monkeypatch.setattr(manifest, "read", lambda *_: previous)
    prepared = [_source("controller", "controller.example", None)]
    evidence = SimpleNamespace(files=[], devices=[])

    [entry] = runs_exec._device_entries(settings, 2_000, 1_000, prepared, {}, evidence)

    assert entry.carried is True
    assert entry.device_uids == ["device:historical-leaf"]
    assert entry.sections == previous.devices[0].sections
    assert entry.expected_sections == ["config"]
    assert entry.tables == previous.devices[0].tables


def test_a_failed_devices_error_loses_the_credential_values_its_source_is_configured_with(monkeypatch):
    """The manifest is signed and kept: the error text it records for a device
    must not hold the device's credential."""

    class Config(BaseModel):
        host: str = "edge-1"
        password: SecretStr = SecretStr("opaque-pw-8812")

    settings = Settings(_env_file=None, hst_data_dir=Path("unused"))
    monkeypatch.setattr(manifest, "effective_runs", lambda *_: {})
    collector = SimpleNamespace(config=Config(), last_device_uids=None)
    prepared = [
        runs_exec.PreparedSource(
            SimpleNamespace(name="fleet"), [runs_exec.PreparedDevice(None, collector, None)]
        )
    ]
    outcome = runs_exec.DeviceOutcome(
        "fleet", "edge-1", False, error="ConnectError: edge-1 refused opaque-pw-8812"
    )
    evidence = SimpleNamespace(files=[], devices=[outcome])

    [entry] = runs_exec._device_entries(settings, 2_000, None, prepared, {}, evidence)

    assert "opaque-pw-8812" not in entry.error
    assert entry.error.startswith("ConnectError: edge-1 refused")
