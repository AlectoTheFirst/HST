"""The sample collector of `docs/new-collector.md` as code."""

from __future__ import annotations

import sys
import types
from pathlib import Path

import httpx
import pytest

import hst.collectors as collectors
import hst.collectors.base as base
from hst.core.config import Settings
from hst.core.identity import MemoryResolver
from hst.core.labels import DEVICE_ROLES

DOC = Path(__file__).resolve().parents[1] / "docs" / "new-collector.md"
MARKER = "<!-- example: collector -->\n```python\n"
MODULE = "hst.collectors.docs_example"

RAW = {
    "devices": [
        {
            "id": "d-1",
            "hostname": "edge-1.example.net",
            "serial": "SN0001",
            "model": "EX-200",
            "type": "router",
            "location_id": "loc-7",
            "location_name": "Hall 7",
            "interfaces": [{"name": "GigabitEthernet0/0", "mac": "AA:BB:CC:00:00:01"}],
        },
        {"id": "d-2", "hostname": "core-2", "serial": "N/A", "type": "appliance"},
    ]
}


@pytest.fixture
def sample(monkeypatch: pytest.MonkeyPatch) -> tuple[types.ModuleType, dict[str, type[base.Collector]]]:
    """The module of the block after the marker, and the copy of `REGISTRY` that holds its collector."""
    text = DOC.read_text()
    assert text.count(MARKER) == 1
    code = text.split(MARKER)[1].split("\n```\n")[0] + "\n"
    registry = dict(base.REGISTRY)
    monkeypatch.setattr(base, "REGISTRY", registry)
    module = types.ModuleType(MODULE)
    module.__package__ = "hst.collectors"
    monkeypatch.setitem(sys.modules, MODULE, module)
    exec(compile(code, str(DOC), "exec"), module.__dict__)  # noqa: S102
    return module, registry


def _collector(registry: dict[str, type[base.Collector]]) -> base.Collector:
    cls = registry["example"]
    config = cls.ConfigModel(url="https://ctl.example", auth={"method": "api_key", "key": "k1"})
    return cls(config, Settings(_env_file=None))


def test_the_sample_collector_registers_and_normalizes(sample):
    _module, registry = sample
    assert "example" in registry
    assert "example" not in collectors.REGISTRY
    assert registry["example"].KIND == "orchestrator"

    collector = _collector(registry)
    batch = collector.normalize(RAW)
    batch.validate_registry()

    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert batch.scope == collector.scope == "example:ctl.example"
    assert nodes["dev:edge-1"].label == "Device"
    assert {n.props["role"] for n in batch.nodes if n.label == "Device"} <= DEVICE_ROLES
    assert nodes["dev:edge-1"].props["role"] == "router"
    assert nodes["dev:edge-1"].props["serial"] == "SN0001"
    assert nodes["dev:core-2"].props["role"] == "unknown"
    assert "serial" not in nodes["dev:core-2"].props
    assert rels == {
        ("ON", "dev:edge-1/if/gi0-0", "dev:edge-1"),
        ("ON", "dev:edge-1/port/gi0-0", "dev:edge-1"),
        ("REALIZED_BY", "dev:edge-1/if/gi0-0", "dev:edge-1/port/gi0-0"),
    }
    assert batch.sections["devices"].row_count == 2


def test_the_sample_collector_gets_each_device_uid_from_the_identity_registry(sample):
    _module, registry = sample
    collector = _collector(registry)
    collector.identity = MemoryResolver([("dev:kept", "serial", "sn0001")])

    batch = collector.normalize(RAW)

    assert {n.uid for n in batch.nodes if n.label == "Device"} == {"dev:kept", "dev:core-2"}
    assert collector.identity.resolve_device("ref", "example:ctl.example:d-2", None) == "dev:core-2"


def test_the_sample_collector_probes_and_fetches(sample, monkeypatch: pytest.MonkeyPatch):
    module, registry = sample
    calls: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, request.headers.get("authorization")))
        if request.url.path == "/api/v1/version":
            return httpx.Response(200, json={"version": "1.2"})
        return httpx.Response(200, json=RAW)

    monkeypatch.setattr(module, "_transport", lambda config: httpx.MockTransport(handler))
    collector = _collector(registry)

    assert collector.probe() == "login ok: Example 1.2 at https://ctl.example"
    assert collector.fetch() == RAW
    assert calls == [("/api/v1/version", "Bearer k1"), ("/api/v1/devices", "Bearer k1")]


def test_the_sample_fixture_leaves_the_registry_as_it_was(sample, monkeypatch: pytest.MonkeyPatch):
    _module, registry = sample
    assert base.REGISTRY is registry
    assert MODULE in sys.modules

    monkeypatch.undo()

    assert base.REGISTRY is collectors.REGISTRY
    assert "example" not in base.REGISTRY
    assert MODULE not in sys.modules
