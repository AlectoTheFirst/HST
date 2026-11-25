"""Service clue parameters and saved revision identities cross the API intact."""

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.app.routes import assessment_discovery
from hst.assessment.store import MemoryAssessmentStore


class AssessmentFake(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return AssessmentFake()


async def test_clues_and_saved_requirement_revisions_are_forwarded(client, store, monkeypatch):
    saved = await store.create_requirement(
        title="Payments", definition={"request": {"name": "Payments"}}, created_by=1
    )
    calls = []

    def search(settings, snapshot, kind, q, uid, **kwargs):
        calls.append((snapshot, kind, kwargs))
        return {
            "snapshot": snapshot,
            "items": [],
            "facets": {"locations": [], "applications": []},
            "questions": [],
        }

    monkeypatch.setattr(assessment_discovery, "search_options", search)
    await login(client, "vera")
    response = await client.get(
        "/api/assessment-options",
        params={
            "snapshot": "300",
            "kind": "service",
            "destination": "https://checkout.example/pay",
            "client": "10.0.0.23",
            "location": "Frankfurt",
            "application": "Checkout",
        },
    )
    assert response.status_code == 200, response.text
    assert calls[0][:2] == ("300", "service")
    assert calls[0][2]["destination"] == "https://checkout.example/pay"
    assert calls[0][2]["client"] == "10.0.0.23"
    assert calls[0][2]["location"] == "Frankfurt"
    assert calls[0][2]["application"] == "Checkout"
    assert calls[0][2]["saved_requirements"] == [saved.as_dict()]
    assert (
        await client.get(
            "/api/assessment-options", params={"snapshot": "300", "kind": "service", "destination": "x" * 501}
        )
    ).status_code == 422


async def test_saved_lookup_is_available_for_explicit_uid(client, store, monkeypatch):
    saved = await store.create_requirement(
        title="Payments", definition={"request": {"name": "Payments"}}, created_by=1
    )

    def search(settings, snapshot, kind, q, uid, **kwargs):
        assert uid == saved.id
        assert kwargs["saved_requirements"] == [saved.as_dict()]
        return {"snapshot": snapshot, "items": []}

    monkeypatch.setattr(assessment_discovery, "search_options", search)
    await login(client, "vera")
    assert (
        await client.get(
            "/api/assessment-options", params={"snapshot": "300", "kind": "service", "uid": saved.id}
        )
    ).status_code == 200
