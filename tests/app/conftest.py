"""App test rig: FakeStore-backed app, pre-created users, cookie-carrying client."""

from __future__ import annotations

import httpx
import pytest
from argon2 import PasswordHasher
from tests.app.fakes import FakeStore

from hst.app import security
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.core import Settings

PASSWORD = "correct-horse-9"
PUBLIC_URL = "http://t"

security._hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)


@pytest.fixture
def store() -> FakeStore:
    return FakeStore()


@pytest.fixture
async def seeded(store):
    for name, role in (("vera", "viewer"), ("otto", "operator"), ("ada", "admin")):
        await store.create_user(name, hash_password(PASSWORD), role)
    return store


@pytest.fixture
def app(seeded):
    from hst.app.crypto import generate_key

    settings = Settings(_env_file=None, hst_secret_key=generate_key(), HST_PUBLIC_URL=PUBLIC_URL)
    return create_app(settings=settings, store=seeded)


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        yield c


async def login(client, username):
    r = await client.post("/api/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r
