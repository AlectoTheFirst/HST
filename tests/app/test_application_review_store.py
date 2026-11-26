"""Review flags of Business Applications and the Analysis sessions bound to an application."""

import asyncio

import pytest

from hst.assessment.store import MemoryAssessmentStore

APPLICATION = "checkout-production"
SNAPSHOT = {"snapshot": "100", "manifest_sha256": "manifest-100", "estate": "synthetic"}


@pytest.fixture
def store():
    return MemoryAssessmentStore()


@pytest.fixture
def users():
    """The ids of 2 users."""
    return 1, 2


def _reference(application_id: str, revision: int, connection_id: str = "web") -> dict:
    return {
        "application": {"id": application_id, "revision": revision},
        "service_id": "frontend",
        "connection_id": connection_id,
    }


def connection_session(
    session_id: str, bindings: list[tuple[str, int]], runs: list[dict] | None = None
) -> dict:
    """A stored connection session definition with 1 application connection
    per (application id, revision) of `bindings`."""
    return {
        "schema_version": 1,
        "id": session_id,
        "revision": 1,
        "title": session_id,
        "input": {
            "kind": "connection",
            "snapshot": SNAPSHOT,
            "connections": [
                {
                    "id": f"item-{index}",
                    "name": f"Item {index}",
                    "source": {
                        "kind": "application_connection",
                        "reference": _reference(application_id, revision),
                        "request": {"src": "192.0.2.1", "dst": "198.51.100.10"},
                        "resolved_scope_digest": "0" * 64,
                    },
                }
                for index, (application_id, revision) in enumerate(bindings)
            ],
            "changes": [],
            "mode": "possible",
        },
        "runs": runs or [],
    }


def simulation_session(session_id: str, application_id: str, revision: int) -> dict:
    """A stored simulation session definition with 1 application protection."""
    return {
        "schema_version": 1,
        "id": session_id,
        "revision": 1,
        "title": session_id,
        "input": {
            "kind": "simulation",
            "snapshot": SNAPSHOT,
            "changes": [{"kind": "shutdown_interface", "params": {}}],
            "protected": [
                {
                    "kind": "application_connection",
                    "reference": _reference(application_id, revision),
                    "resolved_scope_digest": "0" * 64,
                    "desired": "holds",
                }
            ],
        },
        "runs": [],
    }


async def save_session(store, definition: dict):
    return await store.create_analysis_session(
        title=definition["title"],
        definition=definition,
        results={},
        created_by=None,
        session_id=definition["id"],
    )


async def test_a_flag_opens_once_and_closes_once(store, users):
    ada, _ = users
    opened = await store.open_application_review(
        APPLICATION, reason="revision 2 saved", revision=2, opened_by=None
    )
    assert opened is not None
    assert (opened.state, opened.reason, opened.revision, opened.opened_by) == (
        "open",
        "revision 2 saved",
        2,
        None,
    )
    assert (opened.closed_at, opened.closed_by) == (None, None)
    assert await store.open_application_review(APPLICATION, reason="again", revision=2, opened_by=ada) is None
    assert await store.open_application_review("other", reason="other", revision=1, opened_by=ada) is not None

    closed = await store.close_application_review(APPLICATION, closed_by=ada)
    assert closed is not None
    assert (closed.id, closed.state, closed.closed_by) == (opened.id, "closed", ada)
    assert closed.closed_at is not None
    assert await store.close_application_review(APPLICATION, closed_by=ada) is None


async def test_concurrent_opens_leave_one_open_flag(store, users):
    opened = await asyncio.gather(
        *(
            store.open_application_review(
                APPLICATION, reason=f"reason {index}", revision=1, opened_by=users[0]
            )
            for index in range(4)
        )
    )
    assert sum(review is not None for review in opened) == 1
    assert list(await store.open_application_reviews([APPLICATION])) == [APPLICATION]


async def test_the_history_lists_the_flags_of_an_application_newest_first(store, users):
    ada, bob = users
    first = await store.open_application_review(APPLICATION, reason="one", revision=1, opened_by=ada)
    await store.close_application_review(APPLICATION, closed_by=bob)
    await asyncio.sleep(0.01)
    second = await store.open_application_review(APPLICATION, reason="two", revision=2, opened_by=None)
    await store.open_application_review("other", reason="other", revision=1, opened_by=ada)

    history = await store.list_application_reviews(APPLICATION)
    assert [(review.id, review.state) for review in history] == [(second.id, "open"), (first.id, "closed")]
    assert [review.id for review in await store.list_application_reviews(APPLICATION, 1)] == [second.id]
    flagged = await store.open_application_reviews([APPLICATION, "missing"])
    assert {key: review.id for key, review in flagged.items()} == {APPLICATION: second.id}
    assert await store.open_application_reviews([]) == {}


async def test_bound_sessions_hold_connection_and_simulation_sessions_of_the_application(store):
    await save_session(store, connection_session("connection", [(APPLICATION, 1)]))
    await save_session(store, simulation_session("simulation", APPLICATION, 2))
    await save_session(store, connection_session("other", [("other", 1)]))
    await save_session(store, connection_session("both", [("other", 1), (APPLICATION, 3)]))

    bound = await store.list_application_bound_sessions(APPLICATION)
    assert sorted(record.id for record in bound) == ["both", "connection", "simulation"]
    assert [record.created_at for record in bound] == sorted(
        (record.created_at for record in bound), reverse=True
    )
    every = await store.list_application_bound_sessions(None)
    assert sorted(record.id for record in every) == ["both", "connection", "other", "simulation"]
    assert await store.list_application_bound_sessions("missing") == []


async def test_bound_sessions_hold_the_newest_session_revision(store):
    first = await save_session(store, connection_session("session", [(APPLICATION, 1)]))
    await store.create_analysis_session(
        title="session",
        definition={**connection_session("session", [(APPLICATION, 2)]), "revision": 2},
        results={},
        created_by=None,
        session_id="session",
        expected_revision=first.revision,
    )
    [record] = await store.list_application_bound_sessions(APPLICATION)
    assert record.revision == 2
