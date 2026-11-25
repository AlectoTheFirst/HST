"""Personal saved views and the built-in views.

A view filters and organizes; it never assigns. The list shows the four
built-in views and the caller's own; a foreign or unknown id is 404; every
change carries an expected revision; a built-in view cannot be changed.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.inventory_rig import Rig, device, fake_rig

from hst.app.inventory import inventory_routes, views
from hst.app.inventory.contracts import API_PREFIX
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.core import Settings

VIEWS = f"{API_PREFIX}/views"


@pytest.fixture
async def rig() -> Rig:
    r = fake_rig()
    for name, role in (("vera", "viewer"), ("otto", "operator")):
        await r.store.create_user(name, hash_password(PASSWORD), role)
    await r.seed_source("vyos-lab", "vyos")
    await r.seed_site("fra")
    return r


@pytest.fixture
async def client(rig: Rig):
    from hst.app.crypto import generate_key

    application = create_app(
        settings=Settings(_env_file=None, hst_secret_key=generate_key()),
        store=rig.store,
        register_inventory=False,
    )
    application.state.inventory_context = rig.ctx
    inventory_routes.register(application)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        yield c


def test_builtin_views_have_stable_ids_and_the_four_required_names():
    names = [v.name for v in views.BUILTIN_VIEWS.values()]
    assert names == ["All devices", "Unplaced", "Collection issues", "Archived"]
    assert views.builtin_id("all") == views.builtin_id("all")
    assert all(v.revision == 0 and v.owner_id == "" for v in views.BUILTIN_VIEWS.values())
    archived = views.BUILTIN_VIEWS[views.builtin_id("archived")]
    assert [x.value for x in archived.filter.lifecycle] == ["archived"]


async def test_a_viewer_creates_lists_updates_and_deletes_their_own_views(client):
    await login(client, "vera")
    r = await client.get(VIEWS)
    assert r.status_code == 200 and [v["name"] for v in r.json()] == [
        "All devices",
        "Unplaced",
        "Collection issues",
        "Archived",
    ]
    r = await client.post(
        VIEWS,
        json={
            "name": "mine",
            "filter": {"platform": ["vyos"], "q": "r"},
            "sort": "platform",
            "columns": ["name"],
        },
    )
    assert r.status_code == 201, r.text
    view = r.json()
    assert view["revision"] == 1 and view["filter"]["platform"] == ["vyos"] and view["filter"]["version"] == 1
    assert view["sort"] == "platform" and view["columns"] == ["name"]
    assert (await client.post(VIEWS, json={"name": "mine"})).status_code == 409
    assert (await client.post(VIEWS, json={"name": "x", "filter": {"site": ["1"]}})).status_code == 422
    assert (await client.post(VIEWS, json={"name": "x", "columns": ["c"] * 21})).status_code == 422
    r = await client.get(f"{VIEWS}/{view['id']}")
    assert r.status_code == 200 and r.json()["name"] == "mine"
    r = await client.patch(f"{VIEWS}/{view['id']}", json={"name": "renamed", "expected_revision": 1})
    assert r.status_code == 200 and r.json()["revision"] == 2 and r.json()["name"] == "renamed"
    assert r.json()["filter"]["platform"] == ["vyos"], "omitted means unchanged"
    r = await client.patch(f"{VIEWS}/{view['id']}", json={"filter": {}, "expected_revision": 2})
    assert r.json()["filter"]["platform"] == [] and r.json()["revision"] == 3
    r = await client.patch(f"{VIEWS}/{view['id']}", json={"name": "late", "expected_revision": 1})
    assert r.status_code == 409 and r.json()["code"] == "stale_revision" and r.json()["current_revision"] == 3
    assert [v["name"] for v in (await client.get(VIEWS)).json()][-1] == "renamed"
    r = await client.delete(f"{VIEWS}/{view['id']}?expected_revision=1")
    assert r.status_code == 409
    r = await client.delete(f"{VIEWS}/{view['id']}?expected_revision=3")
    assert r.status_code == 204
    assert (await client.get(f"{VIEWS}/{view['id']}")).status_code == 404
    assert len((await client.get(VIEWS)).json()) == 4


async def test_views_are_owned_and_foreign_ones_read_as_absent(client):
    await login(client, "vera")
    r = await client.post(VIEWS, json={"name": "vera's"})
    view_id = r.json()["id"]
    await login(client, "otto")
    assert [v["name"] for v in (await client.get(VIEWS)).json()] == [
        "All devices",
        "Unplaced",
        "Collection issues",
        "Archived",
    ]
    assert (await client.get(f"{VIEWS}/{view_id}")).status_code == 404
    assert (
        await client.patch(f"{VIEWS}/{view_id}", json={"name": "x", "expected_revision": 1})
    ).status_code == 404
    assert (await client.delete(f"{VIEWS}/{view_id}")).status_code == 404
    r = await client.post(VIEWS, json={"name": "vera's"})
    assert r.status_code == 201, "names are unique per owner, not globally"
    assert (await client.get(f"{VIEWS}/{uuid.uuid4()}")).status_code == 404


async def test_builtin_views_are_readable_usable_and_immutable(client, rig):
    await rig.run("100", {("vyos-lab", "r1"): ("complete", [device("dev:a", "a"), device("dev:b", "b")])})
    await login(client, "vera")
    devices = {d["graph_uid"]: d for d in (await client.get(f"{API_PREFIX}/devices")).json()["items"]}
    async with rig.repo.transaction() as tx:
        from hst.app.inventory.contracts import Lifecycle

        await tx.set_lifecycle(
            uuid.UUID(devices["dev:b"]["id"]), Lifecycle.ARCHIVED, expected_revision=1, now=rig.clock()
        )
    archived = views.builtin_id("archived")
    r = await client.get(f"{VIEWS}/{archived}")
    assert r.status_code == 200 and r.json()["name"] == "Archived"
    r = await client.get(f"{API_PREFIX}/devices?view_id={archived}")
    assert [d["graph_uid"] for d in r.json()["items"]] == ["dev:b"]
    r = await client.get(f"{API_PREFIX}/devices?view_id={views.builtin_id('unplaced')}")
    assert [d["graph_uid"] for d in r.json()["items"]] == ["dev:a"]
    r = await client.get(f"{API_PREFIX}/devices?view_id={views.builtin_id('all')}")
    assert [d["graph_uid"] for d in r.json()["items"]] == ["dev:a"], "the default view hides archived devices"
    assert (
        await client.patch(f"{VIEWS}/{archived}", json={"name": "x", "expected_revision": 1})
    ).status_code == 404
    assert (await client.delete(f"{VIEWS}/{archived}")).status_code == 404


async def test_view_writes_are_recorded_as_events(client, rig):
    await login(client, "vera")
    r = await client.post(VIEWS, json={"name": "audited"})
    view_id = r.json()["id"]
    await client.patch(f"{VIEWS}/{view_id}", json={"name": "audited 2", "expected_revision": 1})
    await client.delete(f"{VIEWS}/{view_id}")
    async with rig.repo.transaction() as tx:
        events, _ = await tx.page_events(entity_type="view", entity_id=view_id)
    assert [e.action for e in events] == ["view.delete", "view.update", "view.create"]
    assert all(e.actor_id is not None for e in events)
