"""Resolution diagnostics of a wrong-kind or unsupported inventory object, and
the resolved scope of one revision at two snapshots."""

from __future__ import annotations

import pytest
from tests.app.conftest import login
from tests.app.release_scenarios_rig import (
    API_INTERFACE,
    CHECKOUT_ID,
    CHECKOUT_YAML,
    Inventory,
    ScenarioStore,
    api_interface,
    commit_yaml,
    install,
)
from tests.test_business_applications import (
    COMPLETE,
    GraphReferenceSession,
    one_connection_definition,
)

from hst.applications.resolution import (
    AddressBinding,
    GraphInventoryReader,
    InventoryCandidate,
    StaticInventoryReader,
    resolve_application,
)
from hst.applications.yaml_format import ApplicationFormatError, parse_application_yaml

SNAPSHOT = {"snapshot": "100", "manifest_sha256": "a", "estate": "test"}


@pytest.fixture
def store():
    return ScenarioStore()


def test_an_inventory_object_of_another_kind_reports_inventory_kind_mismatch():
    reader = StaticInventoryReader(
        {
            "interface:api-1": [
                InventoryCandidate(
                    "interface:api-1",
                    "device",
                    (AddressBinding("203.0.113.10", "vrf:production", "interface:api-1"),),
                )
            ]
        }
    )

    result = resolve_application(
        parse_application_yaml(COMPLETE),
        revision=1,
        snapshot=SNAPSHOT,
        reader=reader,
        connection_ids=["frontend-to-api"],
    )

    assert result["ready"] is False
    assert result["issues"] == [
        {
            "code": "inventory-kind-mismatch",
            "path": "groups.api.members.api-primary",
            "detail": "expected interface, found device",
            "severity": "error",
        }
    ]
    (connection,) = result["connections"]
    assert connection["readiness"] == "unresolved"
    assert [issue["code"] for issue in connection["issues"]] == ["inventory-kind-mismatch"]


def test_a_device_reference_to_a_site_object_reports_inventory_kind_mismatch():
    session = GraphReferenceSession({"site:fra01": {"labels": ["Obj", "Site"]}})

    result = resolve_application(
        one_connection_definition("device", "site:fra01"),
        revision=1,
        snapshot={"snapshot": "4000"},
        reader=GraphInventoryReader(session, 4000),
    )

    assert result["ready"] is False
    issues = {issue["code"]: issue for issue in result["issues"]}
    assert issues["inventory-kind-mismatch"]["detail"] == "expected device, found unsupported"
    assert issues["inventory-kind-mismatch"]["path"] == "groups.servers.members.web"
    assert "inventory-address-unavailable" in issues
    assert result["groups"]["servers"]["web"]["bindings"] == []
    assert result["connections"][0]["request"] is None


def test_an_inventory_reference_of_kind_site_is_refused():
    text = COMPLETE.replace(
        "kind: interface\n          uid: interface:api-1", "kind: site\n          uid: site:fra01"
    )
    assert text != COMPLETE

    with pytest.raises(ApplicationFormatError, match=r"groups\.2\.members\.0\.inventory\.kind"):
        parse_application_yaml(text)


async def test_one_revision_resolved_at_two_snapshots_holds_the_scope_of_each_snapshot(
    client, store, monkeypatch
):
    inventory = Inventory("4000", {"4000": api_interface("10.20.0.10"), "4001": api_interface("10.20.0.99")})
    install(monkeypatch, inventory)
    await login(client, "otto")
    assert (await commit_yaml(client, CHECKOUT_YAML)).status_code == 201

    async def resolve(snapshot: str) -> dict:
        response = await client.post(
            f"/api/business-applications/{CHECKOUT_ID}/resolve", json={"snapshot": snapshot}
        )
        assert response.status_code == 200, response.text
        return response.json()

    old, new = await resolve("4000"), await resolve("4001")

    assert old["application"] == new["application"]
    assert old["snapshot"]["snapshot"] == "4000" and new["snapshot"]["snapshot"] == "4001"
    assert old["digest"] != new["digest"]
    assert old["groups"]["api"]["api-primary"]["bindings"] == [
        {"address": "10.20.0.10", "context": "vrf:production", "object_uid": API_INTERFACE}
    ]
    assert new["groups"]["api"]["api-primary"]["bindings"] == [
        {"address": "10.20.0.99", "context": "vrf:production", "object_uid": API_INTERFACE}
    ]
    requests = {
        snapshot: {item["id"]: item["request"] for item in value["connections"]}
        for snapshot, value in (("4000", old), ("4001", new))
    }
    assert requests["4000"]["frontend-to-api"]["members"][0]["addresses"] == ["10.20.0.10"]
    assert requests["4001"]["frontend-to-api"]["members"][0]["addresses"] == ["10.20.0.99"]
    assert requests["4000"]["api-to-database"]["sources"] == ["10.20.0.10"]
    assert requests["4001"]["api-to-database"]["sources"] == ["10.20.0.99"]
    assert requests["4000"]["clients-to-frontend"] == requests["4001"]["clients-to-frontend"]
    for value in (old, new):
        stored = await store.get_application_resolution(value["digest"])
        assert stored["groups"] == value["groups"]
        assert stored["snapshot"] == value["snapshot"]
