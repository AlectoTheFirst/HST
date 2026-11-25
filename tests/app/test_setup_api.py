"""First-run setup of a fresh deployment."""

from __future__ import annotations

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.fakes import FakeStore

from hst.app.main import create_app
from hst.app.security import hash_password
from hst.core import Settings

GOOD_PASSWORD = "a-long-enough-admin-pw"


@pytest.fixture
def fresh_store() -> FakeStore:
    return FakeStore()


@pytest.fixture
def fresh_app(fresh_store):
    return create_app(settings=Settings(_env_file=None), store=fresh_store)


@pytest.fixture
async def fresh_client(fresh_app):
    transport = httpx.ASGITransport(app=fresh_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        yield c


async def test_a_fresh_deployment_reports_setup_required(fresh_client):
    r = await fresh_client.get("/api/setup")
    assert r.status_code == 200
    body = r.json()
    assert body["required"] is True
    assert body["min_password_length"] >= 12


async def test_setup_creates_an_admin_and_signs_them_in(fresh_client, fresh_store):
    r = await fresh_client.post("/api/setup", json={"username": "ada", "password": GOOD_PASSWORD})
    assert r.status_code == 201, r.text
    assert r.json() == {"username": "ada", "role": "admin"}
    # ends in a usable session, not a login form
    assert "hst_session=" in r.headers["set-cookie"]

    me = await fresh_client.get("/api/me")
    assert me.status_code == 200
    assert me.json()["role"] == "admin"

    user = await fresh_store.get_user_by_username("ada")
    assert user.role == "admin"


async def test_setup_closes_permanently_once_it_has_been_used(fresh_client):
    first = await fresh_client.post("/api/setup", json={"username": "ada", "password": GOOD_PASSWORD})
    assert first.status_code == 201

    status = await fresh_client.get("/api/setup")
    assert status.json()["required"] is False

    second = await fresh_client.post("/api/setup", json={"username": "mallory", "password": GOOD_PASSWORD})
    assert second.status_code == 409
    assert "already been completed" in second.json()["error"]


async def test_setup_is_closed_when_any_account_exists_even_a_viewer(client, store):
    r = await client.get("/api/setup")
    assert r.json()["required"] is False

    r = await client.post("/api/setup", json={"username": "mallory", "password": GOOD_PASSWORD})
    assert r.status_code == 409
    assert await store.get_user_by_username("mallory") is None


async def test_a_non_admin_account_alone_closes_setup():
    store = FakeStore()
    await store.create_user("vera", hash_password(PASSWORD), "viewer")
    app = create_app(settings=Settings(_env_file=None), store=store)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        assert (await c.get("/api/setup")).json()["required"] is False
        r = await c.post("/api/setup", json={"username": "m", "password": GOOD_PASSWORD})
        assert r.status_code == 409


async def test_a_short_password_is_refused(fresh_client, fresh_store):
    r = await fresh_client.post("/api/setup", json={"username": "ada", "password": "short"})
    assert r.status_code == 422
    assert await fresh_store.list_users() == []
    assert (await fresh_client.get("/api/setup")).json()["required"] is True


async def test_a_blank_username_is_refused(fresh_client, fresh_store):
    r = await fresh_client.post("/api/setup", json={"username": "   ", "password": GOOD_PASSWORD})
    assert r.status_code == 422
    assert await fresh_store.list_users() == []


async def test_setup_requires_the_csrf_header_like_every_other_mutation(fresh_app):
    transport = httpx.ASGITransport(app=fresh_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as bare:
        r = await bare.post("/api/setup", json={"username": "ada", "password": GOOD_PASSWORD})
        assert r.status_code == 403


async def test_the_created_admin_can_then_log_in_normally(fresh_client, fresh_app):
    await fresh_client.post("/api/setup", json={"username": "ada", "password": GOOD_PASSWORD})
    transport = httpx.ASGITransport(app=fresh_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        r = await c.post("/api/login", json={"username": "ada", "password": GOOD_PASSWORD})
        assert r.status_code == 200
        assert r.json()["role"] == "admin"


async def test_login_works_for_the_seeded_users(client):
    r = await login(client, "ada")
    assert r.status_code == 200
    assert "hst_session=" in r.headers["set-cookie"]
