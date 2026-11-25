import asyncio

from hst.assessment.store import MemoryAssessmentStore, RevisionConflict


async def test_analysis_session_revisions_are_immutable_and_concurrency_fenced():
    store = MemoryAssessmentStore()
    first = await store.create_analysis_session(
        title="Checkout",
        definition={"id": "session-1", "revision": 1},
        results={},
        created_by=1,
        session_id="session-1",
    )
    attempts = await asyncio.gather(
        store.create_analysis_session(
            title="Checkout",
            definition={"id": "session-1", "revision": 2, "value": "one"},
            results={},
            created_by=1,
            session_id="session-1",
            expected_revision=1,
        ),
        store.create_analysis_session(
            title="Checkout",
            definition={"id": "session-1", "revision": 2, "value": "two"},
            results={},
            created_by=2,
            session_id="session-1",
            expected_revision=1,
        ),
        return_exceptions=True,
    )
    assert sum(isinstance(value, RevisionConflict) for value in attempts) == 1
    assert (await store.get_analysis_session(first.id, 1)).definition == {
        "id": "session-1",
        "revision": 1,
    }
    assert [item.revision for item in await store.list_analysis_session_revisions(first.id)] == [2, 1]
