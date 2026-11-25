import asyncio

import pytest

from hst.applications.models import BusinessApplicationDefinition
from hst.applications.service import revision_origin, save_definition
from hst.applications.yaml_format import definition_digest, normalized_document
from hst.assessment.store import MemoryAssessmentStore, RevisionConflict


@pytest.fixture
def store():
    return MemoryAssessmentStore()


def definition(name: str = "Checkout") -> BusinessApplicationDefinition:
    return BusinessApplicationDefinition(id="checkout-production", name=name)


async def test_application_revisions_are_immutable_noop_and_concurrency_fenced(store):
    first = await save_definition(store, definition(), expected_revision=0, actor=1)
    same = await save_definition(store, definition(), expected_revision=1, actor=1)
    assert same.revision == 1
    attempts = await asyncio.gather(
        save_definition(store, definition("One"), expected_revision=1, actor=1),
        save_definition(store, definition("Two"), expected_revision=1, actor=2),
        return_exceptions=True,
    )
    assert sum(isinstance(value, RevisionConflict) for value in attempts) == 1
    latest = await store.get_application(first.id)
    assert latest.revision == 2
    assert (await store.get_application(first.id, 1)).definition["name"] == "Checkout"
    assert [item.revision for item in await store.list_application_revisions(first.id)] == [2, 1]


async def test_application_rows_with_an_origin_key_load(store):
    first = await save_definition(store, definition(), expected_revision=0, actor=1)
    row = {**first.as_dict(), "revision": 2, "origin": {"source": "import", "generation_id": None}}
    async with store.assessment_transaction() as tx:
        await tx.put("application", row)
    latest = await store.get_application(first.id)
    assert latest.revision == 2
    assert latest.origin == {"source": "import", "generation_id": None}
    assert (await store.get_application(first.id, 1)).origin is None
    assert {item.revision: item.origin for item in await store.list_application_revisions(first.id)} == {
        2: {"source": "import", "generation_id": None},
        1: None,
    }
    assert (await store.list_applications())[0].origin == {"source": "import", "generation_id": None}
    same = await save_definition(store, definition(), expected_revision=2, actor=1)
    assert same.revision == 2
    assert same.origin == {"source": "import", "generation_id": None}


def validation(digest: str, snapshot: str = "4000") -> dict:
    return {
        "schema_version": 1,
        "application_id": "checkout-production",
        "definition_digest": digest,
        "base_revision": 0,
        "snapshot": {"snapshot": snapshot, "manifest_sha256": "a" * 64, "estate": "test"},
        "resolution": {"ready": True, "issues": []},
        "flows": None,
        "warnings": [],
        "blocking": [],
        "ready": True,
    }


async def test_validation_records_are_keyed_by_the_digest_of_their_content(store):
    digest = definition_digest(normalized_document(definition()))
    first = await store.save_application_validation(validation(digest))
    assert len(first["digest"]) == 64
    assert first["id"] == first["digest"]
    # the store computes the key, so a supplied digest does not name the record
    again = await store.save_application_validation({**validation(digest), "digest": "f" * 64})
    assert again == first
    assert await store.get_application_validation(first["digest"]) == first
    assert await store.get_application_validation("f" * 64) is None
    other = await store.save_application_validation(validation(digest, snapshot="4001"))
    assert other["digest"] != first["digest"]
    with pytest.raises(ValueError, match="definition digest"):
        await store.save_application_validation(validation("short"))
    with pytest.raises(ValueError, match="snapshot reference"):
        await store.save_application_validation({**validation(digest), "snapshot": {}})


async def test_revisions_record_their_origin_and_a_validation_for_another_definition_is_rejected(store):
    checkout = definition()
    digest = definition_digest(normalized_document(checkout))
    record = await store.save_application_validation(validation(digest))
    origin = await revision_origin(store, "import", validation_digest=record["digest"])
    assert origin == {
        "source": "import",
        "generation_id": None,
        "generated_digest": None,
        "validation": {
            "validation_digest": record["digest"],
            "snapshot": {"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test"},
            "definition_digest": digest,
            "ready": True,
            "blocking_count": 0,
        },
    }

    saved = await save_definition(store, checkout, expected_revision=0, actor=1, origin=origin)
    assert saved.origin == origin
    assert saved.definition == normalized_document(checkout)
    assert (await store.get_application(saved.id)).origin == origin
    assert [item.origin for item in await store.list_application_revisions(saved.id)] == [origin]

    renamed = definition("Renamed")
    with pytest.raises(ValueError, match="for another definition"):
        await save_definition(store, renamed, expected_revision=1, actor=1, origin=origin)
    # an unchanged definition is a no-op, and its validation is still checked
    forged = {**origin, "validation": {**origin["validation"], "validation_digest": "e" * 64}}
    with pytest.raises(ValueError, match="unknown application validation"):
        await save_definition(store, checkout, expected_revision=1, actor=1, origin=forged)
    assert [item.revision for item in await store.list_application_revisions(saved.id)] == [1]

    edited = await save_definition(
        store, renamed, expected_revision=1, actor=2, origin=await revision_origin(store, "editor")
    )
    assert edited.revision == 2
    assert edited.origin == {
        "source": "editor",
        "generation_id": None,
        "generated_digest": None,
        "validation": None,
    }
    generated = await revision_origin(store, "import", generation_id="generation-1")
    assert (generated["source"], generated["generation_id"]) == ("generator", "generation-1")
    with pytest.raises(ValueError, match="unknown application validation"):
        await revision_origin(store, "import", validation_digest="e" * 64)


def _connection_session(application_id: str, connection_id: str = "web") -> dict:
    """A connection session definition that selects one application connection."""
    return {
        "id": f"session-{application_id}",
        "revision": 1,
        "input": {
            "kind": "connection",
            "snapshot": {"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test"},
            "connections": [
                {"id": "first", "name": "First", "source": {"kind": "inline", "request": {}}},
                {
                    "id": connection_id,
                    "name": "Web",
                    "source": {
                        "kind": "application_connection",
                        "reference": {
                            "application": {"id": application_id, "revision": 1},
                            "service_id": "shop",
                            "connection_id": connection_id,
                        },
                        "request": {},
                        "resolved_scope_digest": "d" * 64,
                    },
                },
            ],
        },
        "runs": [],
    }


async def test_application_analysis_sessions_are_found_by_application_id(store):
    """The lookup matches a session by an application connection nested in its
    selection list, takes each session's newest revision, and leaves out the
    sessions of other applications."""
    first = await store.create_analysis_session(
        title="Checkout",
        definition=_connection_session("checkout-production"),
        results={},
        created_by=1,
        session_id="session-checkout",
    )
    await store.create_analysis_session(
        title="Checkout",
        definition={**_connection_session("checkout-production"), "revision": 2, "runs": [{"id": "run-1"}]},
        results={},
        created_by=1,
        session_id=first.id,
        expected_revision=1,
    )
    await store.create_analysis_session(
        title="Billing",
        definition=_connection_session("billing"),
        results={},
        created_by=1,
        session_id="session-billing",
    )

    found = await store.list_application_analysis_sessions("checkout-production")

    assert [(item.id, item.revision) for item in found] == [("session-checkout", 2)]
    assert await store.list_application_analysis_sessions("inventory") == []
