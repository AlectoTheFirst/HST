"""A Coverage resolve leaves the authored definition of the application unchanged."""

from __future__ import annotations

import pytest
from tests.app.conftest import login
from tests.app.release_scenarios_rig import (
    CHECKOUT_ID,
    CHECKOUT_YAML,
    Inventory,
    ScenarioStore,
    api_interface,
    commit_yaml,
    install,
)


@pytest.fixture
def store():
    return ScenarioStore()


async def test_resolving_coverage_at_two_snapshots_writes_no_revision(client, store, monkeypatch):
    install(
        monkeypatch,
        Inventory("4000", {"4000": api_interface("10.20.0.10"), "4001": api_interface("10.20.0.99")}),
    )
    await login(client, "otto")
    assert (await commit_yaml(client, CHECKOUT_YAML)).status_code == 201

    def read_all():
        return (
            client.get(f"/api/business-applications/{CHECKOUT_ID}"),
            client.get(f"/api/business-applications/{CHECKOUT_ID}/history"),
            client.get(f"/api/business-applications/{CHECKOUT_ID}/export"),
            client.get("/api/business-applications"),
        )

    before = [await request for request in read_all()]
    assert all(response.status_code == 200 for response in before)

    for snapshot in ("4000", "4001"):
        resolved = await client.post(
            f"/api/business-applications/{CHECKOUT_ID}/resolve", json={"snapshot": snapshot}
        )
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["application"]["revision"] == 1

    after = [await request for request in read_all()]
    assert [response.content for response in after] == [response.content for response in before]
    assert [item.revision for item in await store.list_application_revisions(CHECKOUT_ID)] == [1]
