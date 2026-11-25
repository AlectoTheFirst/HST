"""A source save names the other controller rows on its routing scope."""

from tests.app.conftest import login
from tests.app.test_sources_api import make_app_client


def _unifi(name: str, **config) -> dict:
    return {
        "name": name,
        "type": "unifi",
        "config": {
            "url": f"https://{name}",
            "auth": {"method": "user_password", "username": "ro", "password": "pw"},
            **config,
        },
    }


async def test_a_controller_row_saved_onto_another_rows_scope_is_warned(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        first = await client.post("/api/sources", json=_unifi("branch-a", routing_scope="corp"))
        assert first.status_code == 201, first.text
        assert "warnings" not in first.json()

        second = await client.post("/api/sources", json=_unifi("branch-b", routing_scope="corp"))
        assert second.status_code == 201, second.text
        (warning,) = second.json()["warnings"]
        assert "'corp'" in warning and "branch-a" in warning

        moved = await client.patch("/api/sources/branch-b", json={"config": {"routing_scope": "branch-b"}})
        assert moved.status_code == 200, moved.text
        assert "warnings" not in moved.json()


async def test_a_connection_saved_on_another_connections_frozen_scope_is_warned(tmp_path):
    """Under resolver v2 a new connection gets `inventory:<name>`, so creates
    do not collide. Two migrated connections whose frozen routing scope is one
    stated value are warned on the next edit of either."""
    from datetime import UTC, datetime

    from tests.app.test_inventory_collection import activate, make_client, make_store, settings_for

    from hst.app.inventory.connection_routes import API_PREFIX

    store = await make_store()
    await activate(store)
    async with make_client(store, settings_for(tmp_path)) as client:
        await login(client, "ada")
        views = {}
        for name in ("branch-a", "branch-b", "branch-c"):
            response = await client.post(
                f"{API_PREFIX}/connections",
                json={"name": name, "collector_type": "unifi", "config": {"url": f"https://{name}"}},
            )
            assert response.status_code == 201, response.text
            views[name] = response.json()
            assert views[name]["warnings"] == []

        frozen = {
            "values": {"site_code": "home", "routing_scope": "corp", "l2fabric": "fab0"},
            "origins": {"site_code": "implicit", "routing_scope": "group", "l2fabric": "application"},
        }
        async with store.inventory().transaction() as tx:
            for name in ("branch-a", "branch-b"):
                await tx.set_frozen_normalization(int(views[name]["id"]), frozen, datetime.now(UTC))

        edited = {}
        for name in ("branch-b", "branch-c"):
            response = await client.patch(
                f"{API_PREFIX}/connections/{views[name]['id']}",
                json={"display_name": name.upper(), "expected_revision": views[name]["revision"]},
            )
            assert response.status_code == 200, response.text
            edited[name] = response.json()
        (warning,) = edited["branch-b"]["warnings"]
        assert "'corp'" in warning and "branch-a" in warning
        assert edited["branch-c"]["warnings"] == []


async def test_controller_rows_that_state_no_scope_are_not_warned(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=_unifi("branch-a"))
        second = await client.post("/api/sources", json=_unifi("branch-b"))
        assert second.status_code == 201, second.text
        assert "warnings" not in second.json()
