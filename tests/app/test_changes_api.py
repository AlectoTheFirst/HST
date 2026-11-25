"""The change entity API under /api/changes:
CRUD, intent-kind validation, and the whole-list replace on PATCH."""

from __future__ import annotations

from tests.app.conftest import login

from hst.app.changes_delta import INTENT_KINDS


async def test_viewers_can_read_but_not_write(client):
    await login(client, "vera")
    assert (await client.get("/api/changes")).status_code == 200
    assert (await client.post("/api/changes", json={"title": "x"})).status_code == 403
    assert (await client.patch("/api/changes/1", json={"title": "y"})).status_code == 403
    assert (await client.delete("/api/changes/1")).status_code == 403


async def test_create_list_get_delete_round_trip(client, seeded):
    await login(client, "otto")
    otto = await seeded.get_user_by_username("otto")

    r = await client.post(
        "/api/changes",
        json={
            "title": "decommission edge1",
            "description": "reload edge1 for the firmware bump",
            "snapshot_cts": 1234567890123,
            "intents": [{"kind": "device.exclude", "params": {"device_uid": "dev:edge1"}}],
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["title"] == "decommission edge1"
    assert body["description"] == "reload edge1 for the firmware bump"
    assert body["snapshot_cts"] == 1234567890123
    assert body["status"] == "draft"
    assert body["created_by"] == otto.id
    assert len(body["intents"]) == 1
    assert body["intents"][0] == {
        "id": body["intents"][0]["id"],
        "position": 0,
        "kind": "device.exclude",
        "params": {"device_uid": "dev:edge1"},
        "simulatable": False,
    }
    change_id = body["id"]

    listed = (await client.get("/api/changes")).json()["changes"]
    assert [c["id"] for c in listed] == [change_id]

    got = await client.get(f"/api/changes/{change_id}")
    assert got.status_code == 200
    assert got.json() == body

    assert (await client.delete(f"/api/changes/{change_id}")).status_code == 204
    assert (await client.get(f"/api/changes/{change_id}")).status_code == 404
    assert (await client.get("/api/changes")).json()["changes"] == []


async def test_get_patch_delete_of_an_unknown_change_is_404(client):
    await login(client, "otto")
    assert (await client.get("/api/changes/999999")).status_code == 404
    assert (await client.patch("/api/changes/999999", json={"title": "x"})).status_code == 404
    assert (await client.delete("/api/changes/999999")).status_code == 404


async def test_create_rejects_an_unknown_intent_kind_with_the_known_list(client):
    await login(client, "otto")
    r = await client.post(
        "/api/changes",
        json={"title": "x", "intents": [{"kind": "reticulate.splines", "params": {}}]},
    )
    assert r.status_code == 422
    detail = r.json()["error"]
    assert "reticulate.splines" in detail
    for kind in sorted(INTENT_KINDS):
        assert kind in detail


async def test_a_stage_3_kind_is_stored_but_flagged_not_simulatable(client):
    await login(client, "otto")
    r = await client.post(
        "/api/changes",
        json={
            "title": "shut a peering",
            "intents": [{"kind": "bgp_session.shut", "params": {"session_uid": "sess:1"}}],
        },
    )
    assert r.status_code == 201, r.text
    (intent,) = r.json()["intents"]
    assert intent["kind"] == "bgp_session.shut"
    assert intent["simulatable"] is False


async def test_patch_updates_fields_without_touching_intents(client):
    await login(client, "otto")
    created = await client.post(
        "/api/changes",
        json={"title": "x", "intents": [{"kind": "static_route.add", "params": {"prefix": "10.0.0.0/24"}}]},
    )
    change_id = created.json()["id"]

    r = await client.patch(f"/api/changes/{change_id}", json={"title": "y", "status": "simulated"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["title"] == "y"
    assert body["status"] == "simulated"
    assert len(body["intents"]) == 1  # untouched


async def test_patch_replaces_the_intent_list_as_a_whole(client):
    await login(client, "otto")
    created = await client.post(
        "/api/changes",
        json={
            "title": "x",
            "intents": [
                {"kind": "static_route.add", "params": {"prefix": "10.0.0.0/24"}},
                {"kind": "static_route.remove", "params": {"prefix": "10.1.0.0/24"}},
            ],
        },
    )
    change_id = created.json()["id"]

    r = await client.patch(
        f"/api/changes/{change_id}",
        json={"intents": [{"kind": "device.exclude", "params": {"device_uid": "dev:x"}}]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["intents"]) == 1
    assert body["intents"][0]["kind"] == "device.exclude"
    assert body["intents"][0]["position"] == 0

    r = await client.patch(f"/api/changes/{change_id}", json={"intents": []})
    assert r.json()["intents"] == []


async def test_patch_rejects_an_unknown_intent_kind(client):
    await login(client, "otto")
    created = await client.post("/api/changes", json={"title": "x"})
    change_id = created.json()["id"]
    r = await client.patch(
        f"/api/changes/{change_id}",
        json={"intents": [{"kind": "not.a.kind", "params": {}}]},
    )
    assert r.status_code == 422


async def test_patch_rejects_an_unknown_status(client):
    await login(client, "otto")
    created = await client.post("/api/changes", json={"title": "x"})
    change_id = created.json()["id"]
    r = await client.patch(f"/api/changes/{change_id}", json={"status": "not-a-status"})
    assert r.status_code == 422


async def test_snapshot_cts_can_be_explicitly_cleared(client):
    await login(client, "otto")
    created = await client.post("/api/changes", json={"title": "x", "snapshot_cts": 111})
    change_id = created.json()["id"]

    # omitted entirely: unchanged
    r = await client.patch(f"/api/changes/{change_id}", json={"title": "still x"})
    assert r.json()["snapshot_cts"] == 111

    # explicit null: cleared
    r = await client.patch(f"/api/changes/{change_id}", json={"snapshot_cts": None})
    assert r.json()["snapshot_cts"] is None
