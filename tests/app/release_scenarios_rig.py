"""Shared rig of the release scenario tests.

The store is the in-memory assessment store under the app fake store, so every
application revision, resolution, session, assessment and run the API writes is
a real store record. Snapshots pin through a reference table keyed by the
snapshot named, and the graph is a `GraphReferenceSession` holding only the
synthetic inventory objects a test names.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from tests.app.fakes import FakeStore
from tests.test_business_applications import GraphReferenceSession

from hst.assessment import service as assessment_service
from hst.assessment.store import MemoryAssessmentStore
from hst.core import db

CHECKOUT_YAML = (
    Path(__file__).resolve().parents[2] / "docs" / "examples" / "business-application.yaml"
).read_text(encoding="utf-8")
CHECKOUT_ID = "checkout-production"
CHECKOUT_SERVICE = "checkout-frontend"
CHECKOUT_CONNECTIONS = {
    "clients-to-frontend": ("branch-clients", "frontend"),
    "frontend-to-api": ("frontend", "api"),
    "api-to-database": ("api", "database"),
}
API_INTERFACE = "interface:api-primary"


class ScenarioStore(MemoryAssessmentStore, FakeStore):
    pass


def reference(snapshot: str) -> dict:
    return {
        "snapshot": snapshot,
        "manifest_sha256": f"manifest-{snapshot}",
        "estate": "synthetic",
        "observation_floor_ms": None,
    }


class Inventory:
    """The pinned snapshots and the graph objects of each one.

    `latest` is the snapshot an unpinned read answers from; `objects` maps a
    snapshot to the `GraphReferenceSession` nodes it holds."""

    def __init__(self, latest: str, objects: dict[str, dict]) -> None:
        self.latest = latest
        self.objects = objects

    def snapshot_reference(self, settings, value=None):
        snapshot = str(value or self.latest)
        if snapshot not in self.objects:
            raise ValueError("A published snapshot with an evidence manifest is required.")
        return reference(snapshot)

    @contextmanager
    def session(self, settings, **kwargs):
        yield _InventorySession(self.objects)


class _InventorySession(GraphReferenceSession):
    """The reference read of `GraphInventoryReader` at the snapshot it names,
    and no rows for the inventory neighbourhood read of the application graph."""

    def __init__(self, objects: dict[str, dict]) -> None:
        super().__init__({})
        self.objects = objects

    def run(self, query, **params):
        if "uid" not in params:
            self.params.append(params)
            return SimpleNamespace(data=lambda: [])
        self.nodes = self.objects[str(params["snap"])]
        return super().run(query, **params)


def api_interface(address: str) -> dict:
    return {API_INTERFACE: {"labels": ["Obj", "Interface"], "rows": [(address, "vrf:production")]}}


def install(monkeypatch, inventory: Inventory) -> None:
    monkeypatch.setattr(assessment_service, "snapshot_reference", inventory.snapshot_reference)
    monkeypatch.setattr(assessment_service, "engine_version", lambda settings: "engine-release-test")
    monkeypatch.setattr(db, "session", inventory.session)


async def commit_yaml(client, text: str, *, mode: str = "merge", removals: dict | None = None, **extra):
    body = {"yaml": text, "mode": mode, **({"removals": removals} if removals else {})}
    preview = await client.post("/api/business-applications/import/preview", json=body)
    assert preview.status_code == 200, preview.text
    token = {key: preview.json()[key] for key in ("base_revision", "base_digest", "preview_digest")}
    return await client.post("/api/business-applications/import/commit", json={**body, **token, **extra})
