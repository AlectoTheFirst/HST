"""A failure inside `commit_import` during a change of a service, a group and
two connections, on the memory store."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from hst.applications.models import RemovalSet
from hst.applications.service import commit_import, export_revision, preview_import
from hst.assessment.store import MemoryAssessmentStore

CHECKOUT = (
    Path(__file__).resolve().parents[2] / "docs" / "examples" / "business-application.yaml"
).read_text()
APP = "checkout-production"

# The patch updates the service checkout-frontend, adds the member web-secondary
# to the group frontend, updates the connection clients-to-frontend and, with
# REMOVALS, removes the connection api-to-database.
PATCH = """\
schema_version: 1
kind: BusinessApplication
id: checkout-production
services:
  - id: checkout-frontend
    name: Checkout frontend
    connection_ids: [clients-to-frontend, frontend-to-api]
    component_roles:
      - group_id: frontend
        role: endpoint
groups:
  - id: frontend
    name: Frontend
    members:
      - id: web-primary
        address: 198.51.100.10
      - id: web-secondary
        address: 198.51.100.11
connections:
  - id: clients-to-frontend
    name: Branch clients to frontend
    source: branch-clients
    destination: frontend
    protocol: tcp
    destination_ports: [443, 8443]
    source_ports: [1024-65535]
    success: session
    source_context:
      vrf: vrf:branch
    destination_condition:
      kind: member
      member: web-primary
"""
REMOVALS = RemovalSet(connections=["api-to-database"])


class _FailingPut:
    """A transaction whose `put` of an application record writes and then raises."""

    def __init__(self, tx) -> None:
        self.tx = tx

    def __getattr__(self, name):
        return getattr(self.tx, name)

    async def put(self, kind: str, document: dict) -> None:
        await self.tx.put(kind, document)
        if kind == "application":
            raise RuntimeError("failure after the application write")


def _fail_application_writes(store: MemoryAssessmentStore) -> None:
    real = store.assessment_transaction

    @asynccontextmanager
    async def failing():
        async with real() as tx:
            yield _FailingPut(tx)

    store.assessment_transaction = failing


async def _first_revision(store: MemoryAssessmentStore):
    preview = await preview_import(store, CHECKOUT, RemovalSet(), "replace")
    return await commit_import(
        store,
        CHECKOUT,
        RemovalSet(),
        base_revision=preview.base_revision,
        base_digest=preview.base_digest,
        preview_digest=preview.preview_digest,
        actor=1,
        mode="replace",
    )


async def test_a_failure_inside_commit_import_leaves_every_entity_of_the_revision_unchanged():
    store = MemoryAssessmentStore()
    first = await _first_revision(store)
    before = await store.get_application(APP)
    preview = await preview_import(store, PATCH, REMOVALS)
    assert preview.changes["services_updated"] == ["checkout-frontend"]
    assert preview.changes["groups_updated"] == ["frontend"]
    assert preview.changes["connections_updated"] == ["clients-to-frontend"]
    assert preview.changes["connections_removed"] == ["api-to-database"]

    _fail_application_writes(store)
    with pytest.raises(RuntimeError, match="failure after the application write"):
        await commit_import(
            store,
            PATCH,
            REMOVALS,
            base_revision=preview.base_revision,
            base_digest=preview.base_digest,
            preview_digest=preview.preview_digest,
            actor=1,
        )

    latest = await store.get_application(APP)
    assert latest == before
    assert [item.revision for item in await store.list_application_revisions(APP)] == [1]
    assert export_revision(latest) == export_revision(first)
    frontend = next(group for group in latest.definition["groups"] if group["id"] == "frontend")
    assert [member["id"] for member in frontend["members"]] == ["web-primary"]
    assert [item["id"] for item in latest.definition["connections"]] == [
        "clients-to-frontend",
        "frontend-to-api",
        "api-to-database",
    ]


async def test_the_preview_of_a_failed_commit_commits_once_the_store_writes_again():
    store = MemoryAssessmentStore()
    await _first_revision(store)
    preview = await preview_import(store, PATCH, REMOVALS)
    real = store.assessment_transaction
    _fail_application_writes(store)
    with pytest.raises(RuntimeError):
        await commit_import(
            store,
            PATCH,
            REMOVALS,
            base_revision=preview.base_revision,
            base_digest=preview.base_digest,
            preview_digest=preview.preview_digest,
            actor=1,
        )

    store.assessment_transaction = real
    saved = await commit_import(
        store,
        PATCH,
        REMOVALS,
        base_revision=preview.base_revision,
        base_digest=preview.base_digest,
        preview_digest=preview.preview_digest,
        actor=1,
    )

    assert saved.revision == 2
    assert saved.digest == preview.result_digest
    assert [item["id"] for item in saved.definition["connections"]] == [
        "clients-to-frontend",
        "frontend-to-api",
    ]
    assert [item.revision for item in await store.list_application_revisions(APP)] == [2, 1]
