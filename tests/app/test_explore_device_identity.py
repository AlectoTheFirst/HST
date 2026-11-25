"""GET /api/explore/device-identity: the device uids that do not read as the
hostname their device reported last."""

from tests.app.conftest import login


async def test_the_report_lists_the_suffixed_and_the_renamed_uids(client, store):
    await store.resolve_device("serial", "FOC1111AAAA", "core1", 1)
    await store.resolve_device("serial", "FOC2222BBBB", "core1", 1)
    await store.resolve_device("serial", "FOC3333CCCC", "edge1", 1)
    await store.resolve_device("serial", "FOC3333CCCC", "edge2", 2)
    await login(client, "vera")

    r = await client.get("/api/explore/device-identity")

    assert r.status_code == 200
    assert r.json() == {
        "items": [
            {
                "uid": "dev:core1-bbbb",
                "hostname": "core1",
                "last_hostname": "core1",
                "first_run_id": 1,
                "identifiers": [{"kind": "serial", "value": "foc2222bbbb"}],
            },
            {
                "uid": "dev:edge1",
                "hostname": "edge1",
                "last_hostname": "edge2",
                "first_run_id": 1,
                "identifiers": [{"kind": "serial", "value": "foc3333cccc"}],
            },
        ]
    }


async def test_the_report_needs_a_login(client):
    assert (await client.get("/api/explore/device-identity")).status_code == 401
