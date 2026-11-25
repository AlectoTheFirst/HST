"""The personal access token methods of the store, on both backends.

Parametrized over `FakeStore` and `PgStore` as `test_store_contract.py` is. The
`pg` leg carries the `pg` marker and skips without `HST_TEST_PG_DSN`.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError
from tests.app.fakes import FakeStore

from hst.app.store import SESSION_TOUCH_INTERVAL, SSO_TOKEN_LOGIN_MAX_AGE
from hst.app.store.pg import PgStore, metadata, upgrade_to_head

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=90)
DSN = os.environ.get("HST_TEST_PG_DSN")

BACKENDS = [
    pytest.param("fake", id="fake"),
    pytest.param(
        "pg",
        id="pg",
        marks=[pytest.mark.pg, pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")],
    ),
]


@pytest.fixture(params=BACKENDS)
async def store(request):
    if request.param == "fake":
        yield FakeStore()
        return

    from sqlalchemy.ext.asyncio import create_async_engine

    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:  # clean slate per test
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    await engine.dispose()
    st = PgStore(DSN)
    yield st
    await st.dispose()


async def test_a_token_is_created_listed_and_revoked_by_its_owner_only(store):
    a = await store.create_user("a", None, "viewer")
    b = await store.create_user("b", None, "operator")
    first = await store.create_access_token("h1", a.id, "laptop", "read", LATER, NOW)
    second = await store.create_access_token(
        "h2", a.id, "ci", "read-write", LATER, NOW + timedelta(seconds=1)
    )
    await store.create_access_token("h3", b.id, "other", "read", LATER, NOW)

    listed = await store.list_access_tokens(a.id)

    assert [(t.name, t.scope) for t in listed] == [("ci", "read-write"), ("laptop", "read")]
    assert (first.user_id, first.created_at, first.expires_at, first.last_used_at) == (a.id, NOW, LATER, None)
    assert await store.delete_access_token(b.id, first.id) is False
    assert await store.delete_access_token(a.id, first.id) is True
    assert await store.delete_access_token(a.id, first.id) is False
    assert [t.id for t in await store.list_access_tokens(a.id)] == [second.id]
    assert len(await store.list_access_tokens(b.id)) == 1


async def test_a_lookup_returns_the_token_and_its_user(store):
    u = await store.create_user("a", None, "operator")
    await store.create_access_token("h", u.id, "laptop", "read-write", LATER, NOW)

    found = await store.get_access_token_user("h", NOW)

    assert found is not None
    token, user = found
    assert (token.name, token.scope, user.id, user.role) == ("laptop", "read-write", u.id, "operator")
    assert await store.get_access_token_user("unknown", NOW) is None


async def test_an_expired_or_revoked_token_does_not_authenticate(store):
    u = await store.create_user("a", None, "viewer")
    token = await store.create_access_token("h", u.id, "laptop", "read", NOW + timedelta(hours=1), NOW)

    assert await store.get_access_token_user("h", NOW + timedelta(hours=1)) is None
    assert await store.get_access_token_user("h", NOW) is not None
    await store.delete_access_token(u.id, token.id)
    assert await store.get_access_token_user("h", NOW) is None


async def test_a_lookup_moves_last_used_forward_throttled(store):
    u = await store.create_user("a", None, "viewer")
    await store.create_access_token("h", u.id, "laptop", "read", LATER, NOW)

    await store.get_access_token_user("h", NOW)
    await store.get_access_token_user("h", NOW + SESSION_TOUCH_INTERVAL / 2)
    (token,) = await store.list_access_tokens(u.id)
    assert token.last_used_at == NOW

    later = NOW + SESSION_TOUCH_INTERVAL
    found = await store.get_access_token_user("h", later)
    assert found is not None and found[0].last_used_at == later
    (token,) = await store.list_access_tokens(u.id)
    assert token.last_used_at == later


async def test_a_token_hash_is_unique(store):
    u = await store.create_user("a", None, "viewer")
    await store.create_access_token("h", u.id, "one", "read", LATER, NOW)

    with pytest.raises((ValueError, IntegrityError)):
        await store.create_access_token("h", u.id, "two", "read", LATER, NOW)


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_postgres_refuses_a_scope_other_than_read_or_read_write():
    await asyncio.to_thread(upgrade_to_head, DSN)
    st = PgStore(DSN)
    try:
        u = await st.create_user(f"scope-{datetime.now(UTC).timestamp()}", None, "viewer")
        with pytest.raises(IntegrityError):
            await st.create_access_token(f"h-{u.id}", u.id, "x", "admin", LATER, NOW)
    finally:
        await st.dispose()


async def test_a_password_reset_revokes_the_users_tokens_only(store):
    a = await store.create_user("a", "old", "viewer")
    b = await store.create_user("b", None, "viewer")
    await store.create_access_token("h1", a.id, "laptop", "read", LATER, NOW)
    await store.create_access_token("h2", b.id, "other", "read", LATER, NOW)

    await store.update_user(a.id, password_hash="new")

    assert await store.list_access_tokens(a.id) == []
    assert await store.get_access_token_user("h1", NOW) is None
    assert [t.name for t in await store.list_access_tokens(b.id)] == ["other"]


async def test_deleting_a_users_tokens_counts_them(store):
    a = await store.create_user("a", None, "viewer")
    await store.create_access_token("h1", a.id, "one", "read", LATER, NOW)
    await store.create_access_token("h2", a.id, "two", "read", LATER, NOW)

    assert await store.delete_user_access_tokens(a.id) == 2
    assert await store.delete_user_access_tokens(a.id) == 0


async def test_an_sso_accounts_token_needs_an_sso_login_within_30_days(store):
    provider = await store.create_auth_provider("okta", "oidc", {"issuer": "https://okta"}, None)
    sso = await store.create_user("sso", None, "viewer")
    identity = await store.create_identity(sso.id, provider.id, "sub-1")
    local = await store.create_user("local", "hash", "viewer")
    await store.create_access_token("h-sso", sso.id, "laptop", "read", LATER, NOW)
    await store.create_access_token("h-local", local.id, "laptop", "read", LATER, NOW)

    # never logged in through SSO since the identity was linked
    assert await store.get_access_token_user("h-sso", NOW) is None

    await store.touch_last_login(identity.id, NOW)
    assert (await store.get_access_token_user("h-sso", NOW))[1].id == sso.id
    edge = NOW + SSO_TOKEN_LOGIN_MAX_AGE
    assert await store.get_access_token_user("h-sso", edge - timedelta(seconds=1)) is not None
    assert await store.get_access_token_user("h-sso", edge) is None
    # a local account has no SSO login to need
    assert await store.get_access_token_user("h-local", edge) is not None
