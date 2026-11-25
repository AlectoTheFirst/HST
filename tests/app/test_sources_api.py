"""Source CRUD: write-only secrets, merge PATCH, probe, RBAC."""

from tests.app.conftest import login

import hst.app.routes.sources as sources_route
from hst.app.crypto import SecretKeyError, decrypt_secrets, dek, generate_key
from hst.core import Settings

KEY = generate_key()


def _dk() -> str:
    """The data key of the app under test (HST_DATA_DIR is pinned per test)."""
    return dek(Settings(_env_file=None, hst_secret_key=KEY))


async def make_app_client(seeded):
    import httpx

    from hst.app.main import create_app
    from hst.core import Settings

    app = create_app(settings=Settings(_env_file=None, hst_secret_key=KEY), store=seeded)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"})


UNIFI_BODY = {
    "name": "home-unifi",
    "type": "unifi",
    "config": {
        "url": "https://c",
        "auth": {"method": "user_password", "username": "ro", "password": "pw1"},
        "site_code": "home",
        "l3dom": "home",
    },
}

# vyos + a configured jump_host: the one registry type with two required secret
# fields at once.
VYOS_JUMP_BODY = {
    "name": "edge-vyos",
    "type": "vyos",
    "config": {
        "host": "gw1",
        "auth": {"method": "password", "username": "vyos", "password": "devpw1"},
        "jump_host": {
            "host": "bastion1",
            "auth": {"method": "password", "username": "jump", "password": "jumppw1"},
        },
    },
}


async def test_admin_creates_secrets_never_echoed(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        r = await client.post("/api/sources", json=UNIFI_BODY)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["secrets"] == {"auth.password": True, "tls.client_cert.key": False}
        assert "password" not in body["config"]["auth"] and "pw1" not in r.text
        row = await seeded.get_source("home-unifi")
        assert decrypt_secrets(_dk(), row.secrets) == {"auth.password": "pw1"}
        assert (await client.post("/api/sources", json=UNIFI_BODY)).status_code == 409


async def test_operator_reads_admin_writes(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)
        await login(client, "otto")
        types = (await client.get("/api/source-types")).json()["types"]
        assert any(t["type"] == "manual" for t in types)
        rows = (await client.get("/api/sources")).json()["sources"]
        assert rows[0]["name"] == "home-unifi" and rows[0]["secrets"] == {
            "auth.password": True,
            "tls.client_cert.key": False,
        }
        assert (await client.post("/api/sources", json=UNIFI_BODY)).status_code == 403
        assert (await client.delete("/api/sources/home-unifi")).status_code == 403


async def test_patch_merges_and_keeps_omitted_secrets(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)
        r = await client.patch("/api/sources/home-unifi", json={"config": {"site": "dc2"}, "enabled": False})
        assert r.status_code == 200
        body = r.json()
        assert body["config"]["site"] == "dc2" and body["config"]["url"] == "https://c"
        assert body["enabled"] is False
        row = await seeded.get_source("home-unifi")
        assert decrypt_secrets(_dk(), row.secrets) == {"auth.password": "pw1"}  # kept
        r = await client.patch("/api/sources/home-unifi", json={"config": {"auth": {"password": "pw2"}}})
        row = await seeded.get_source("home-unifi")
        assert decrypt_secrets(_dk(), row.secrets) == {"auth.password": "pw2"}  # replaced
        assert (await client.patch("/api/sources/ghost", json={})).status_code == 404


async def test_patch_racing_a_delete_is_404_not_500(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)

        real_get = seeded.get_source

        async def get_then_delete(name):
            row = await real_get(name)
            seeded.sources.pop(name, None)  # deleted between pre-check and write
            return row

        seeded.get_source = get_then_delete
        r = await client.patch("/api/sources/home-unifi", json={"enabled": False})
        assert r.status_code == 404
        assert "no source" in r.json()["error"]


async def test_patch_full_secrets_heals_an_unreadable_row(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)
        row = await seeded.get_source("home-unifi")
        row.secrets = b"garbage-not-a-fernet-token"

        r = await client.patch("/api/sources/home-unifi", json={"config": {"auth": {"password": "newpw"}}})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["secrets"] == {"auth.password": True, "tls.client_cert.key": False}
        assert "secrets_unreadable" not in body

        row = await seeded.get_source("home-unifi")
        assert decrypt_secrets(_dk(), row.secrets) == {"auth.password": "newpw"}

        r = await client.get("/api/sources")
        listed = next(s for s in r.json()["sources"] if s["name"] == "home-unifi")
        assert listed["secrets"] == {"auth.password": True, "tls.client_cert.key": False}
        assert "secrets_unreadable" not in listed


async def test_patch_partial_secrets_on_unreadable_row_names_whats_missing(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=VYOS_JUMP_BODY)
        row = await seeded.get_source("edge-vyos")
        row.secrets = b"garbage-not-a-fernet-token"

        # supplies the device credential but not the jump host's
        r = await client.patch("/api/sources/edge-vyos", json={"config": {"auth": {"password": "newdevpw"}}})
        assert r.status_code == 422
        detail = r.json()["error"]
        assert detail == (
            "stored credentials cannot be decrypted; missing secret fields: jump_host.auth.password"
        )

        row = await seeded.get_source("edge-vyos")
        assert row.secrets == b"garbage-not-a-fernet-token"


async def test_validation_and_unknown_type(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        bad_type = {"name": "x1", "type": "nope", "config": {}}
        assert (await client.post("/api/sources", json=bad_type)).status_code == 400
        bad_cfg = {"name": "x1", "type": "unifi", "config": {"user": "ro"}}
        r = await client.post("/api/sources", json=bad_cfg)
        assert r.status_code == 422 and "error" in r.json()
        bad_name = {"name": "Bad Name!", "type": "manual", "config": {"devices": ""}}
        assert (await client.post("/api/sources", json=bad_name)).status_code == 422


async def test_reserved_name_is_422(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        body = {"name": "reasoner", "type": "manual", "config": {"devices": ""}}
        r = await client.post("/api/sources", json=body)
        assert r.status_code == 422
        assert "reserved" in r.json()["error"]


async def test_broken_kek_on_list_is_500(seeded, monkeypatch):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)

        def boom(settings):
            raise SecretKeyError("bad key")

        monkeypatch.setattr(sources_route.crypto, "dek", boom)
        r = await client.get("/api/sources")
        assert r.status_code == 500
        assert "error" in r.json()


async def test_list_degrades_the_unreadable_row_not_the_whole_response(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)
        await client.post("/api/sources", json={**UNIFI_BODY, "name": "office-unifi"})
        stale = await seeded.get_source("office-unifi")
        stale.secrets = b"garbage-not-a-fernet-token"

        r = await client.get("/api/sources")
        assert r.status_code == 200
        by_name = {s["name"]: s for s in r.json()["sources"]}

        healthy = by_name["home-unifi"]
        assert healthy["secrets"] == {"auth.password": True, "tls.client_cert.key": False}
        assert "secrets_unreadable" not in healthy

        bad = by_name["office-unifi"]
        assert bad["secrets"] == {"auth.password": False, "tls.client_cert.key": False}
        assert bad["secrets_unreadable"] is True


async def test_delete_refuses_while_running(seeded):
    from datetime import UTC, datetime

    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)
        run = await seeded.start_run("home-unifi", datetime.now(UTC))
        assert (await client.delete("/api/sources/home-unifi")).status_code == 409
        await seeded.finish_run(run.id, "ok", datetime.now(UTC), "d")
        assert (await client.delete("/api/sources/home-unifi")).status_code == 200
        assert await seeded.get_source("home-unifi") is None


async def test_probe_endpoint(seeded, monkeypatch):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post(
            "/api/sources", json={"name": "seed", "type": "manual", "config": {"devices": "r1, 10.0.0.1"}}
        )
        await login(client, "otto")
        r = await client.post("/api/sources/seed/test")
        assert r.status_code == 200
        assert r.json() == {"ok": True, "detail": "1 device(s) parsed"}

        def boom(row, settings, **kwargs):
            raise RuntimeError("unreachable")

        monkeypatch.setattr(sources_route.glue, "build_collector", boom)
        r = await client.post("/api/sources/seed/test")
        assert r.status_code == 200
        assert r.json() == {"ok": False, "detail": "RuntimeError: unreachable"}


async def test_probe_on_unreadable_row_is_409_not_500(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)
        row = await seeded.get_source("home-unifi")
        row.secrets = b"garbage-not-a-fernet-token"
        await login(client, "otto")

        r = await client.post("/api/sources/home-unifi/test")
        assert r.status_code == 409
        assert r.json()["error"] == "stored credentials cannot be decrypted"


async def test_probe_failure_never_echoes_secrets(seeded, monkeypatch):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        await client.post("/api/sources", json=UNIFI_BODY)
        await login(client, "otto")

        def boom(row, settings, **kwargs):
            raise RuntimeError("login failed for pw1 at https://c")

        monkeypatch.setattr(sources_route.glue, "build_collector", boom)
        r = await client.post("/api/sources/home-unifi/test")
        assert r.status_code == 200
        assert r.json()["ok"] is False
        assert "pw1" not in r.text
        assert "***" in r.json()["detail"]


async def test_create_strips_client_source_name(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        body = {
            "name": "seed",
            "type": "manual",
            "config": {"devices": "r1, 10.0.0.1", "source_name": "evil"},
        }
        r = await client.post("/api/sources", json=body)
        assert r.status_code == 201, r.text
        row = await seeded.get_source("seed")
        assert row.config["source_name"] == ""
