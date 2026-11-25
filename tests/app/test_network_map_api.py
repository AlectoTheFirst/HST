"""/api/network-map: the shared layouts and views, on the FakeStore."""

from tests.app.conftest import login

SCOPE = "/api/network-map/layouts/site/ber1"


async def test_an_unsaved_scope_reads_as_revision_zero(client):
    await login(client, "vera")
    r = await client.get(SCOPE)
    assert r.status_code == 200
    assert r.json() == {
        "scope": "site/ber1",
        "positions": {},
        "revision": 0,
        "updated_by": None,
        "updated_at": None,
    }


async def test_a_saved_layout_is_read_back_and_a_stale_write_is_refused(client):
    await login(client, "otto")
    first = await client.put(SCOPE, json={"positions": {"dev:b": {"x": 1, "y": 2}}, "expected_revision": 0})
    assert first.status_code == 200 and first.json()["revision"] == 1
    second = await client.put(SCOPE, json={"positions": {"dev:b": {"x": 5, "y": 2}}, "expected_revision": 1})
    assert second.json()["revision"] == 2
    stale = await client.put(SCOPE, json={"positions": {}, "expected_revision": 1})
    assert stale.status_code == 409
    assert (await client.get(SCOPE)).json()["positions"] == {"dev:b": {"x": 5.0, "y": 2.0}}


async def test_a_reset_removes_the_layout(client):
    await login(client, "otto")
    await client.put(SCOPE, json={"positions": {"dev:b": {"x": 1, "y": 2}}, "expected_revision": 0})
    assert (await client.delete(f"{SCOPE}?expected_revision=2")).status_code == 409
    assert (await client.delete(f"{SCOPE}?expected_revision=1")).status_code == 204
    assert (await client.get(SCOPE)).json()["revision"] == 0


async def test_a_viewer_reads_but_does_not_write(client):
    await login(client, "vera")
    r = await client.put(SCOPE, json={"positions": {}, "expected_revision": 0})
    assert r.status_code == 403


async def test_a_scope_must_name_a_site(client):
    await login(client, "vera")
    assert (await client.get("/api/network-map/layouts/estate")).status_code == 422


async def test_a_coordinate_out_of_range_is_refused(client):
    await login(client, "otto")
    r = await client.put(SCOPE, json={"positions": {"dev:b": {"x": 1e12, "y": 0}}, "expected_revision": 0})
    assert r.status_code == 422


async def test_views_are_shared_named_and_revised(client):
    await login(client, "otto")
    made = await client.post(
        "/api/network-map/views", json={"name": "Berlin core", "state": {"site": "ber1"}}
    )
    assert made.status_code == 201
    view = made.json()
    assert (
        await client.post("/api/network-map/views", json={"name": "Berlin core", "state": {}})
    ).status_code == 409

    patched = await client.patch(
        f"/api/network-map/views/{view['id']}", json={"state": {"site": "ham2"}, "expected_revision": 1}
    )
    assert patched.json()["revision"] == 2 and patched.json()["state"] == {"site": "ham2"}
    stale = await client.patch(
        f"/api/network-map/views/{view['id']}", json={"name": "x", "expected_revision": 1}
    )
    assert stale.status_code == 409

    await login(client, "vera")
    listed = (await client.get("/api/network-map/views")).json()["views"]
    assert [v["name"] for v in listed] == ["Berlin core"]

    await login(client, "otto")
    assert (
        await client.delete(f"/api/network-map/views/{view['id']}?expected_revision=2")
    ).status_code == 204
    assert (
        await client.delete(f"/api/network-map/views/{view['id']}?expected_revision=2")
    ).status_code == 404


async def test_a_view_state_is_capped(client):
    await login(client, "otto")
    r = await client.post("/api/network-map/views", json={"name": "big", "state": {"x": "a" * 20000}})
    assert r.status_code == 422
