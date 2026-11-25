"""GET /api/explore/device-names: uid -> hostname for the UI."""

from tests.app.conftest import login
from tests.app.test_explore_api import install, table


async def test_device_names_map_each_uid_to_its_latest_hostname(client, monkeypatch):
    await login(client, "vera")
    fake = install(
        monkeypatch,
        [
            (
                "RETURN d.uid AS uid, d.hostname AS hostname",
                lambda params: table(
                    ["uid", "hostname", "ts"],
                    [
                        ["dev:fdo2335abc", "fw-fra-02", 2000],
                        ["dev:fdo2335abc", "fw-fra-02-old", 1000],
                        ["dev:fdo2335xyz", "fw-fra-01", 2000],
                    ],
                ),
            )
        ],
    )

    r = await client.get("/api/explore/device-names")

    assert r.status_code == 200
    assert r.json() == {"names": {"dev:fdo2335abc": "fw-fra-02", "dev:fdo2335xyz": "fw-fra-01"}}
    assert "ORDER BY uid, ts DESC" in fake.calls[0][0]


async def test_device_names_need_a_login(client):
    assert (await client.get("/api/explore/device-names")).status_code == 401
