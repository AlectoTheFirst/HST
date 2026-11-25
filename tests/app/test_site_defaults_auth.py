"""Site network defaults require the same permission as source identity edits."""

from tests.app.conftest import login


async def test_operator_can_create_and_edit_plain_site_but_not_network_defaults(client):
    await login(client, "otto")
    assert (await client.post("/api/sites", json={"code": "fra", "name": "Frankfurt"})).status_code == 201
    assert (await client.patch("/api/sites/fra", json={"location": "Main"})).status_code == 200

    create = await client.post("/api/sites", json={"code": "ber", "params": {"routing_scope": "wan"}})
    patch = await client.patch("/api/sites/fra", json={"params": {"routing_scope": "wan"}})
    reset = await client.patch("/api/sites/fra", json={"params": None})
    assert create.status_code == patch.status_code == reset.status_code == 403


async def test_operator_create_with_omitted_or_all_null_params_does_not_change_identity(client):
    await login(client, "otto")
    omitted = await client.post("/api/sites", json={"code": "fra"})
    nulls = await client.post(
        "/api/sites",
        json={"code": "ber", "params": {"routing_scope": None}},
    )
    assert omitted.status_code == nulls.status_code == 201


async def test_admin_can_set_and_reset_site_network_defaults(client):
    await login(client, "ada")
    created = await client.post(
        "/api/sites",
        json={"code": "fra", "params": {"routing_scope": "wan"}},
    )
    assert created.status_code == 201
    reset = await client.patch("/api/sites/fra", json={"params": {"routing_scope": None}})
    assert reset.status_code == 200
    assert reset.json()["params"] == {"routing_scope": None}


async def test_operator_can_place_a_site_on_the_map_without_touching_the_network_default(client):
    """Coordinates are site data, not a collection parameter: sites.write is
    enough. A patch of the coordinates keeps the routing scope an admin set,
    and a patch of the scope keeps the coordinates."""
    await login(client, "ada")
    assert (
        await client.post("/api/sites", json={"code": "FR2", "params": {"routing_scope": "ACME-EMEA"}})
    ).status_code == 201

    await login(client, "otto")
    placed = await client.patch("/api/sites/FR2", json={"params": {"lat": 50.12, "lon": 8.74}})
    assert placed.status_code == 200
    assert placed.json()["params"] == {"routing_scope": "ACME-EMEA", "lat": 50.12, "lon": 8.74}
    assert (await client.patch("/api/sites/FR2", json={"params": {"routing_scope": "x"}})).status_code == 403

    await login(client, "ada")
    rescoped = await client.patch("/api/sites/FR2", json={"params": {"routing_scope": "EMEA"}})
    assert rescoped.json()["params"] == {"routing_scope": "EMEA", "lat": 50.12, "lon": 8.74}
    cleared = await client.patch("/api/sites/FR2", json={"params": {"lat": None, "lon": None}})
    assert cleared.json()["params"] == {"routing_scope": "EMEA", "lat": None, "lon": None}


async def test_coordinates_come_as_a_pair_within_range(client):
    await login(client, "otto")
    assert (await client.post("/api/sites", json={"code": "FR6"})).status_code == 201
    for params in ({"lat": 50.1}, {"lon": 8.7}, {"lat": 91, "lon": 0}, {"lat": 0, "lon": -181}):
        r = await client.patch("/api/sites/FR6", json={"params": params})
        assert r.status_code == 422, params
    # a patch of one coordinate over a stored pair is validated as the merged pair
    assert (
        await client.patch("/api/sites/FR6", json={"params": {"lat": 50.1, "lon": 8.7}})
    ).status_code == 200
    assert (await client.patch("/api/sites/FR6", json={"params": {"lat": None}})).status_code == 422
    assert (await client.patch("/api/sites/FR6", json={"params": {"lon": 8.8}})).status_code == 200
    assert (await client.get("/api/sites")).json()["sites"][0]["params"] == {"lat": 50.1, "lon": 8.8}
