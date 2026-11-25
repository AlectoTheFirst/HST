"""The Business Application and Analysis session store contract.

Each test takes a `store` fixture. This module runs them on the memory store;
`test_application_store_contract_pg.py` runs the same tests on a disposable
Postgres, so both adapters are held to one contract.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from hst.applications.models import RemovalSet
from hst.applications.service import commit_import, export_revision, preview_import
from hst.assessment.store import MemoryAssessmentStore, RevisionConflict

EXAMPLES = Path(__file__).resolve().parents[2] / "docs" / "examples"
CHECKOUT = (EXAMPLES / "business-application.yaml").read_text()
PATCH = (EXAMPLES / "business-application-partial.yaml").read_text()
APP = "checkout-production"
NO_REMOVALS = RemovalSet()


@pytest.fixture
def store():
    return MemoryAssessmentStore()


async def _commit(store, yaml_text: str, removals: RemovalSet = NO_REMOVALS, mode: str = "merge"):
    preview = await preview_import(store, yaml_text, removals, mode)
    return await commit_import(
        store,
        yaml_text,
        removals,
        base_revision=preview.base_revision,
        base_digest=preview.base_digest,
        preview_digest=preview.preview_digest,
        actor=1,
        mode=mode,
    )


async def test_preview_writes_nothing(store):
    preview = await preview_import(store, CHECKOUT, RemovalSet(), "replace")
    assert preview.base_revision == 0 and not preview.no_op
    assert await store.get_application(APP) is None
    assert await store.list_applications() == []


async def test_import_commits_once_and_an_unchanged_import_is_a_no_op(store):
    first = await _commit(store, CHECKOUT, mode="replace")
    assert first.revision == 1
    again = await preview_import(store, CHECKOUT, RemovalSet(), "replace")
    assert again.no_op
    same = await _commit(store, CHECKOUT, mode="replace")
    assert same.revision == 1
    assert [item.revision for item in await store.list_application_revisions(APP)] == [1]


async def test_a_stale_preview_conflicts_and_writes_nothing(store):
    await _commit(store, CHECKOUT, mode="replace")
    stale = await preview_import(store, PATCH, RemovalSet())
    await _commit(store, PATCH.replace("network-platform", "checkout-team"))
    with pytest.raises(RevisionConflict):
        await commit_import(
            store,
            PATCH,
            RemovalSet(),
            base_revision=stale.base_revision,
            base_digest=stale.base_digest,
            preview_digest=stale.preview_digest,
            actor=1,
        )
    latest = await store.get_application(APP)
    assert latest.revision == 2 and latest.definition["owner"] == "checkout-team"


async def test_concurrent_commits_of_one_preview_write_one_revision(store):
    await _commit(store, CHECKOUT, mode="replace")
    preview = await preview_import(store, PATCH, RemovalSet())

    async def commit(actor: int):
        return await commit_import(
            store,
            PATCH,
            RemovalSet(),
            base_revision=preview.base_revision,
            base_digest=preview.base_digest,
            preview_digest=preview.preview_digest,
            actor=actor,
        )

    attempts = await asyncio.gather(commit(1), commit(2), return_exceptions=True)
    revisions = [item.revision for item in await store.list_application_revisions(APP)]
    assert revisions == [2, 1]
    # the second commit either conflicts or finds its result already stored
    assert all(isinstance(value, RevisionConflict) or value.revision == 2 for value in attempts)


async def test_an_explicit_removal_is_previewed_and_committed(store):
    await _commit(store, CHECKOUT, mode="replace")
    removals = RemovalSet(connections=["api-to-database"])
    patch = (
        "schema_version: 1\nkind: BusinessApplication\nid: checkout-production\n"
        "services:\n  - id: checkout-frontend\n    name: Checkout frontend\n"
        "    connection_ids: [clients-to-frontend, frontend-to-api]\n"
        "    component_roles:\n      - group_id: frontend\n        role: endpoint\n"
    )
    preview = await preview_import(store, patch, removals)
    assert "api-to-database" in preview.changes["connections_removed"]
    saved = await _commit(store, patch, removals)
    assert saved.revision == 2
    assert [c["id"] for c in saved.definition["connections"]] == ["clients-to-frontend", "frontend-to-api"]


async def test_an_old_revision_exports_exactly_after_a_newer_one(store):
    first = await _commit(store, CHECKOUT, mode="replace")
    exported = export_revision(first)
    await _commit(store, PATCH)
    old = await store.get_application(APP, 1)
    assert export_revision(old) == exported
    assert (await store.get_application(APP)).revision == 2


async def test_a_failed_transaction_leaves_no_partial_write(store):
    first = await _commit(store, CHECKOUT, mode="replace")
    row = {**first.as_dict(), "revision": 2, "name": "Half written"}
    with pytest.raises(RuntimeError):
        async with store.assessment_transaction() as tx:
            await tx.put("application", row)
            raise RuntimeError("failure after the first write")
    latest = await store.get_application(APP)
    assert latest.revision == 1 and latest.name == "Checkout"


async def test_analysis_session_revisions_are_immutable_fenced_and_listed_newest(store):
    first = await store.create_analysis_session(
        title="Checkout", definition={"id": "s1", "revision": 1}, results={}, created_by=1, session_id="s1"
    )
    attempts = await asyncio.gather(
        *(
            store.create_analysis_session(
                title="Checkout",
                definition={"id": "s1", "revision": 2, "value": value},
                results={},
                created_by=1,
                session_id="s1",
                expected_revision=1,
            )
            for value in ("one", "two")
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(value, RevisionConflict) for value in attempts) == 1
    await store.create_analysis_session(
        title="Other", definition={"id": "s2", "revision": 1}, results={}, created_by=1, session_id="s2"
    )
    assert (await store.get_analysis_session(first.id, 1)).definition == {"id": "s1", "revision": 1}
    assert [item.revision for item in await store.list_analysis_session_revisions("s1")] == [2, 1]
    listed = {item.id: item.revision for item in await store.list_analysis_sessions()}
    assert listed == {"s1": 2, "s2": 1}


async def test_resolutions_are_keyed_by_digest_and_never_overwritten(store):
    resolution = {"digest": "a" * 64, "application_id": APP, "groups": {}}
    saved = await store.save_application_resolution(resolution)
    assert await store.save_application_resolution(resolution) == saved
    assert await store.get_application_resolution("a" * 64) == saved
    with pytest.raises(ValueError, match="collision"):
        await store.save_application_resolution({**resolution, "groups": {"api": {}}})
    assert await store.get_application_resolution("a" * 64) == saved
    assert await store.get_application_resolution("b" * 64) is None


async def test_generations_are_stored_once(store):
    saved = await store.save_application_generation(
        {"id": "gen-1", "created_by": 1, "definition_digest": "c" * 64}
    )
    assert await store.get_application_generation("gen-1") == saved
    with pytest.raises(ValueError, match="already exists"):
        await store.save_application_generation({"id": "gen-1", "created_by": 2})
    assert (await store.get_application_generation("gen-1"))["created_by"] == 1
    assert await store.get_application_generation("gen-2") is None
