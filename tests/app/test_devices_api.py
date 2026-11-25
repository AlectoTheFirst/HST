"""The device-fleet API under /api/sources/{name}/devices: PUT replaces, pins
survive, a row states nothing but its address, and the per-device probe pins
the device row."""

from unittest.mock import ANY

from tests.app.conftest import login
from tests.app.test_sources_api import make_app_client

import hst.app.routes.sources as sources_route

VYOS_GROUP = {
    "name": "edge",
    "type": "vyos",
    # no host: a pure device group; the fleet holds the hosts
    "config": {
        "auth": {"method": "password", "username": "vyos", "password": "grouppw1"},
        "site_code": "dc1",
        "l3dom": "dc1",
    },
}


async def _group(client) -> None:
    await login(client, "ada")
    r = await client.post("/api/sources", json=VYOS_GROUP)
    assert r.status_code == 201, r.text


async def test_put_replaces_the_fleet_and_get_reads_it_back(seeded):
    async with await make_app_client(seeded) as client:
        await _group(client)
        r = await client.put(
            "/api/sources/edge/devices",
            json={
                "devices": [
                    {"host": "r1"},
                    {"host": "r2", "port": 2222, "overrides": {"site_code": "dc2"}},
                ]
            },
        )
        assert r.status_code == 200, r.text
        assert [d["host"] for d in r.json()["devices"]] == ["r1", "r2"]

        r = await client.put("/api/sources/edge/devices", json={"devices": [{"host": "r2"}]})
        assert [d["host"] for d in r.json()["devices"]] == ["r2"]

        await login(client, "otto")  # operators read
        r = await client.get("/api/sources/edge/devices")
        (row,) = r.json()["devices"]
        assert row["host"] == "r2"
        assert row["pinned"] is False


async def test_put_ignores_anything_but_an_address_and_refuses_duplicates(seeded):
    async with await make_app_client(seeded) as client:
        await _group(client)
        # a device states an address and a switch; everything a caller adds
        # beyond that belongs to the group and is dropped
        r = await client.put(
            "/api/sources/edge/devices",
            json={"devices": [{"host": "r1", "overrides": {"auth": {"password": "evil"}}}]},
        )
        assert r.status_code == 200
        assert r.json()["devices"] == [
            {"host": "r1", "port": None, "enabled": True, "pinned": False, "updated_at": ANY}
        ]

        r = await client.put(
            "/api/sources/edge/devices",
            json={"devices": [{"host": "r1"}, {"host": "r1"}]},
        )
        assert r.status_code == 422
        assert "duplicate" in r.json()["error"]


async def test_get_devices_carries_the_status_row_once_one_exists(seeded):
    from datetime import UTC, datetime

    async with await make_app_client(seeded) as client:
        await _group(client)
        await client.put("/api/sources/edge/devices", json={"devices": [{"host": "r1"}]})
        await login(client, "otto")
        (before,) = (await client.get("/api/sources/edge/devices")).json()["devices"]
        assert before["status"] is None  # no attempt yet

        now = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
        await seeded.upsert_device_status(
            "edge", "r1", now=now, ok=True, raw_sha="SHA", full=True, fetch_ms=120, load_ms=45
        )
        (after,) = (await client.get("/api/sources/edge/devices")).json()["devices"]
        assert after["status"]["consecutive_failures"] == 0
        assert after["status"]["last_success_at"] == now.isoformat()
        assert after["status"]["fetch_ms"] == 120
        assert "last_raw_sha" not in after["status"]


async def test_a_controller_type_takes_no_devices(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        r = await client.post(
            "/api/sources",
            json={
                "name": "ctrl",
                "type": "unifi",
                "config": {
                    "url": "https://c",
                    "auth": {"method": "user_password", "username": "ro", "password": "pw1"},
                },
            },
        )
        assert r.status_code == 201, r.text
        r = await client.put("/api/sources/ctrl/devices", json={"devices": [{"host": "r1"}]})
        assert r.status_code == 400
        r = await client.get("/api/sources/ctrl/devices")
        assert r.status_code == 400


async def test_device_probe_pins_the_device_row(seeded, monkeypatch):
    class FakeCollector:
        observed_host_key = "ssh-ed25519 OBSERVED"
        observed_jump_key = ""

        def probe(self):
            return "VyOS 1.5"

    captured = {}

    def fake_build(row, device, settings, **kwargs):
        captured["host"] = device.host
        return FakeCollector()

    monkeypatch.setattr(sources_route.glue, "build_device_collector", fake_build)
    async with await make_app_client(seeded) as client:
        await _group(client)
        await client.put("/api/sources/edge/devices", json={"devices": [{"host": "r1"}]})
        await login(client, "otto")
        r = await client.post("/api/sources/edge/devices/r1/test")
        assert r.json() == {"ok": True, "detail": "VyOS 1.5"}
        assert captured["host"] == "r1"
        (device,) = await seeded.list_devices("edge")
        assert device.host_key == "ssh-ed25519 OBSERVED"
        # the pin stays off the group config
        assert not (await seeded.get_source("edge")).config.get("host_key")

        r = await client.post("/api/sources/edge/devices/ghost/test")
        assert r.status_code == 404


async def test_source_probe_uses_the_first_enabled_device(seeded, monkeypatch):
    class FakeCollector:
        observed_host_key = ""
        observed_jump_key = ""

        def probe(self):
            return "ok"

    captured = {}

    def fake_build(row, device, settings, **kwargs):
        captured["host"] = device.host
        return FakeCollector()

    monkeypatch.setattr(sources_route.glue, "build_device_collector", fake_build)
    async with await make_app_client(seeded) as client:
        await _group(client)
        await client.put(
            "/api/sources/edge/devices",
            json={"devices": [{"host": "r1", "enabled": False}, {"host": "r2"}]},
        )
        await login(client, "otto")
        r = await client.post("/api/sources/edge/test")
        assert r.json()["ok"] is True
        assert captured["host"] == "r2"
