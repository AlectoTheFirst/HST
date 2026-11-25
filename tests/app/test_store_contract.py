"""The storage contract of `FakeStore` and `PgStore`."""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from tests.app.fakes import FakeStore

from hst.app.store import LIST_TITLE_CHARS, AiEvent, DeviceSpec, IdentityOwnerMissing, TurnCapExceeded
from hst.app.store.pg import PgStore, metadata, upgrade_to_head, users

NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
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


async def crash(store) -> None:
    """Simulate the store's holder dying without releasing its claims."""
    if isinstance(store, FakeStore):
        store.crash()
        return
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import RUN_CLAIM_CLASS

    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as c:
            await c.execute(
                sa.text(
                    "SELECT pg_terminate_backend(pid) FROM pg_locks "
                    "WHERE locktype = 'advisory' AND classid = :cls AND pid <> pg_backend_pid()"
                ),
                {"cls": RUN_CLAIM_CLASS},
            )
    finally:
        await engine.dispose()


async def _start_run_eventually(store, source: str, ts: datetime):
    """PgStore's claim release after a killed backend is async on Postgres' side
    (it must reap the terminated connection first); FakeStore's is immediate."""
    for _ in range(50 if isinstance(store, PgStore) else 1):
        run = await store.start_run(source, ts)
        if run is not None:
            return run
        await asyncio.sleep(0.1)
    return None


async def test_user_crud_and_duplicate(store):
    u = await store.create_user("ada", "h1", "admin")
    assert (u.username, u.role, u.disabled) == ("ada", "admin", False)
    assert (await store.get_user_by_username("ada")).id == u.id
    with pytest.raises(ValueError):
        await store.create_user("ada", "h2", "viewer")
    patched = await store.update_user(u.id, role="operator", disabled=True)
    assert (patched.role, patched.disabled) == ("operator", True)
    assert await store.update_user(999_999, role="viewer") is None
    assert [x.username for x in await store.list_users()] == ["ada"]


async def test_create_first_user_admits_exactly_one(store):
    u = await store.create_first_user("ada", "h1", "admin")
    assert (u.username, u.role) == ("ada", "admin")
    with pytest.raises(ValueError):
        await store.create_first_user("mallory", "h2", "admin")
    assert [x.username for x in await store.list_users()] == ["ada"]


async def test_sessions_expire_and_purge(store):
    u = await store.create_user("a", "h", "viewer")
    await store.create_session("tok", u.id, NOW + timedelta(hours=1))
    assert (await store.get_session_user("tok", NOW)).id == u.id
    assert await store.get_session_user("tok", NOW + timedelta(hours=2)) is None
    assert await store.get_session_user("tok", NOW) is None  # expiry deleted it

    await store.create_session("dead", u.id, NOW - timedelta(seconds=1))
    await store.create_session("alive", u.id, NOW + timedelta(hours=1))
    count = await store.purge_expired_sessions(NOW)
    assert count == 1
    assert await store.get_session_user("dead", NOW) is None
    assert (await store.get_session_user("alive", NOW)).id == u.id


async def test_sessions_expire_when_idle_even_inside_the_absolute_ttl(store):
    u = await store.create_user("idler", "h", "viewer")
    week = NOW + timedelta(hours=168)
    await store.create_session("stale", u.id, week, NOW - timedelta(hours=9))
    await store.create_session("fresh", u.id, week, NOW - timedelta(hours=7))
    idle = timedelta(hours=8)

    assert await store.get_session_user("stale", NOW, idle) is None
    assert await store.get_session_user("stale", NOW) is None  # the lookup deleted it
    assert (await store.get_session_user("fresh", NOW, idle)).id == u.id
    # no idle window asked for means absolute expiry only
    await store.create_session("ancient", u.id, week, NOW - timedelta(days=30))
    assert (await store.get_session_user("ancient", NOW)).id == u.id


async def test_a_disable_deletes_the_sessions_and_the_access_tokens_of_the_account(store):
    u = await store.create_user("leaver", "h", "viewer")
    other = await store.create_user("stayer", "h", "viewer")
    later = NOW + timedelta(days=30)
    for name, user in (("leaver", u), ("stayer", other)):
        await store.create_session(f"session-{name}", user.id, later, NOW)
        await store.create_access_token(f"token-{name}", user.id, "laptop", "read", later, NOW)

    assert (await store.update_user(u.id, disabled=True)).disabled is True
    assert await store.get_session_user("session-leaver", NOW) is None
    assert await store.get_access_token_user("token-leaver", NOW) is None
    assert (await store.get_session_user("session-stayer", NOW)).id == other.id
    assert (await store.get_access_token_user("token-stayer", NOW))[1].id == other.id

    await store.update_user(u.id, disabled=False)
    assert await store.get_session_user("session-leaver", NOW) is None
    assert await store.get_access_token_user("token-leaver", NOW) is None


async def test_the_session_of_a_disabled_account_keeps_its_last_use(store):
    u = await store.create_user("sleeper", "h", "viewer")
    await store.update_user(u.id, disabled=True)
    await store.create_session("kept", u.id, NOW + timedelta(hours=168), NOW)
    idle = timedelta(hours=8)

    assert (await store.get_session_user("kept", NOW + timedelta(hours=7), idle)).disabled is True
    # a read at hour 7 that moved the last use forward would keep the session alive at hour 9
    assert await store.get_session_user("kept", NOW + timedelta(hours=9), idle) is None


async def test_a_session_in_use_moves_its_idle_clock_forward_but_not_per_request(store):
    u = await store.create_user("worker", "h", "viewer")
    week = NOW + timedelta(hours=168)
    await store.create_session("tok", u.id, week, NOW - timedelta(hours=7))
    idle = timedelta(hours=8)

    assert (await store.get_session_user("tok", NOW, idle)).id == u.id
    # the write landed: eight hours on from NOW it is still inside the window
    later = NOW + timedelta(hours=7)
    assert (await store.get_session_user("tok", later, idle)).id == u.id
    assert (await store.get_session_user("tok", later + timedelta(seconds=30), idle)).id == u.id
    assert (await store.get_session_user("tok", NOW + timedelta(hours=15), idle)) is None


async def test_purge_takes_the_same_two_expiries_the_lookup_does(store):
    u = await store.create_user("purged", "h", "viewer")
    week = NOW + timedelta(hours=168)
    await store.create_session("idle", u.id, week, NOW - timedelta(hours=9))
    await store.create_session("active", u.id, week, NOW - timedelta(minutes=1))
    await store.create_session("expired", u.id, NOW - timedelta(seconds=1), NOW)

    assert await store.purge_expired_sessions(NOW, timedelta(hours=8)) == 2
    assert (await store.get_session_user("active", NOW)).id == u.id


async def test_session_lookup_returns_the_whole_account(store):
    u = await store.create_user("themed", "h", "viewer")
    await store.update_user(u.id, role_source="mapped")
    await store.set_user_theme(u.id, "dracula")
    await store.create_session("tok", u.id, NOW + timedelta(hours=1), NOW)

    got = await store.get_session_user("tok", NOW)
    assert (got.theme, got.role_source) == ("dracula", "mapped")


async def test_delete_user_sessions_revokes_one_account_only(store):
    a = await store.create_user("revoked", "h", "viewer")
    b = await store.create_user("bystander", "h", "viewer")
    later = NOW + timedelta(hours=1)
    await store.create_session("a1", a.id, later, NOW)
    await store.create_session("a2", a.id, later, NOW)
    await store.create_session("b1", b.id, later, NOW)

    assert await store.delete_user_sessions(a.id) == 2
    assert await store.get_session_user("a1", NOW) is None
    assert (await store.get_session_user("b1", NOW)).id == b.id
    assert await store.delete_user_sessions(a.id) == 0  # idempotent


async def test_cycle_lock_excludes_a_second_holder_and_releases(store):
    held = asyncio.Event()
    release = asyncio.Event()
    order: list[str] = []

    async def first():
        async with store.cycle_lock():
            order.append("first in")
            held.set()
            await release.wait()
            order.append("first out")

    async def second():
        async with store.cycle_lock():
            order.append("second in")

    one = asyncio.create_task(first())
    await held.wait()
    two = asyncio.create_task(second())
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(asyncio.shield(two), 0.2)

    release.set()
    await asyncio.gather(one, two)
    assert order == ["first in", "first out", "second in"]


async def test_try_cycle_lock_reports_a_busy_lock_without_waiting(store):
    held = asyncio.Event()
    release = asyncio.Event()

    async def holder():
        async with store.cycle_lock():
            held.set()
            await release.wait()

    one = asyncio.create_task(holder())
    await held.wait()
    async with store.try_cycle_lock() as locked:
        assert locked is False
    release.set()
    await one

    # and it hands the lock over once the holder is gone
    async with store.try_cycle_lock() as locked:
        assert locked is True


async def test_try_cycle_lock_releases_what_it_took(store):
    async with store.try_cycle_lock() as locked:
        assert locked is True
    async with store.try_cycle_lock() as locked:
        assert locked is True

    # the blocking form takes it too, without waiting on anything
    async def blocking():
        async with store.cycle_lock():
            return True

    assert await asyncio.wait_for(blocking(), 1.0) is True


async def test_a_run_lease_is_listed_for_the_length_of_its_block(store):
    """A pinned trace leases the run it reads, and graph retention keeps every leased run."""
    assert await store.leased_runs() == set()
    async with store.lease_run(2000):
        assert await store.leased_runs() == {2000}
        async with store.lease_run([2000, 3000]):
            assert await store.leased_runs() == {2000, 3000}
        # the inner block ends its own leases only
        assert await store.leased_runs() == {2000}
    assert await store.leased_runs() == set()


async def test_a_run_lease_is_released_when_its_block_raises(store):
    with pytest.raises(RuntimeError):
        async with store.lease_run(2000):
            raise RuntimeError("the trace failed")
    assert await store.leased_runs() == set()


async def test_a_lease_nobody_released_expires_on_its_own(store):
    async with store.lease_run(2000, ttl_s=0.2):
        assert await store.leased_runs() == {2000}
        await asyncio.sleep(0.4)
        assert await store.leased_runs() == set()


async def test_run_lock_is_per_source_and_releases_on_finish(store):
    r = await store.start_run("unifi", NOW)
    assert r.status == "running"
    assert (await store.running_run("unifi")).id == r.id
    assert await store.start_run("unifi", NOW) is None  # locked
    assert (await store.start_run("vyos", NOW)).source == "vyos"  # other source fine
    await store.finish_run(r.id, "ok", NOW, "done")
    assert await store.running_run("unifi") is None
    r2 = await store.start_run("unifi", NOW)
    assert r2.id != r.id  # lock released
    await store.finish_run(r2.id, "ok", NOW, "done")


async def test_claim_after_crash_reconciles_the_orphaned_row(store):
    orphan = await store.start_run("unifi", NOW)
    await crash(store)

    later = NOW + timedelta(minutes=1)
    fresh = await _start_run_eventually(store, "unifi", later)
    assert fresh is not None and fresh.id != orphan.id

    runs = {r.id: r for r in await store.list_runs()}
    assert runs[orphan.id].status == "error"
    assert runs[orphan.id].detail == "orphaned by crash"
    assert runs[fresh.id].status == "running"

    # the dead holder's late finish must not resurrect the reconciled row
    await store.finish_run(orphan.id, "ok", later, "late result")
    runs = {r.id: r for r in await store.list_runs()}
    assert runs[orphan.id].status == "error"
    await store.finish_run(fresh.id, "ok", later, "done")


async def test_reconcile_orphaned_runs_spares_live_claims(store):
    live = await store.start_run("unifi", NOW)
    dead = await store.start_run("vyos", NOW)
    if isinstance(store, FakeStore):
        store._claims.discard("vyos")  # vyos's holder died; unifi's claim is live
    else:
        from tests.app.test_store_pg import _kill_claim_holders

        await _kill_claim_holders(spare="unifi")

    reaped = None
    for _ in range(50 if not isinstance(store, FakeStore) else 1):
        reaped = await store.reconcile_orphaned_runs(NOW + timedelta(minutes=1))
        if reaped:
            break
        await asyncio.sleep(0.1)

    assert reaped == 1
    runs = {r.id: r for r in await store.list_runs()}
    assert runs[dead.id].status == "error"
    assert runs[dead.id].detail == "orphaned by crash"
    assert runs[live.id].status == "running"
    await store.finish_run(live.id, "ok", NOW, "done")


async def test_source_crud_and_run_lifecycle(store):
    s = await store.create_source("apic-dc1", "apic", {"url": "https://apic"}, b"blob")
    assert s.id and s.enabled is True
    with pytest.raises(ValueError):
        await store.create_source("apic-dc1", "apic", {}, b"")
    got = await store.get_source("apic-dc1")
    assert (got.config, got.secrets) == ({"url": "https://apic"}, b"blob")
    patched = await store.update_source("apic-dc1", enabled=False, secrets=b"new")
    assert (patched.enabled, patched.secrets, patched.config) == (False, b"new", {"url": "https://apic"})
    assert await store.update_source("ghost", enabled=True) is None
    assert [x.name for x in await store.list_sources()] == ["apic-dc1"]

    run = await store.start_run("apic-dc1", NOW)
    assert (await store.running_run("apic-dc1")).id == run.id
    await store.finish_run(run.id, "ok", NOW, "d")
    assert await store.running_run("apic-dc1") is None

    assert await store.delete_source("apic-dc1") is True
    assert await store.delete_source("apic-dc1") is False


# --- SSO: auth providers, identities, group mappings, auth state -----------------


async def test_auth_provider_crud_and_duplicate(store):
    p = await store.create_auth_provider("okta", "oidc", {"issuer": "https://okta"}, b"blob")
    assert (p.name, p.kind, p.enabled) == ("okta", "oidc", False)  # disabled by default
    with pytest.raises(ValueError):
        await store.create_auth_provider("okta", "oidc", {}, None)
    got = await store.get_auth_provider("okta")
    assert (got.config, got.secrets) == ({"issuer": "https://okta"}, b"blob")
    patched = await store.update_auth_provider("okta", enabled=True, secrets=b"new")
    assert (patched.enabled, patched.secrets, patched.config) == (True, b"new", {"issuer": "https://okta"})
    assert await store.update_auth_provider("ghost", enabled=True) is None
    assert [x.name for x in await store.list_auth_providers()] == ["okta"]
    assert await store.get_auth_provider("ghost") is None


async def test_auth_provider_secrets_may_be_absent(store):
    p = await store.create_auth_provider("adfs", "saml", {}, None)
    assert p.secrets is None


async def test_identity_crud_unique_and_touch_last_login(store):
    u = await store.create_user("ident-user", None, "viewer")
    p = await store.create_auth_provider("okta", "oidc", {}, None)
    assert await store.get_identity(p.id, "sub-1") is None

    ident = await store.create_identity(u.id, p.id, "sub-1", email="a@b.example")
    assert (ident.subject, ident.email, ident.last_login_at) == ("sub-1", "a@b.example", None)
    with pytest.raises(ValueError):
        await store.create_identity(u.id, p.id, "sub-1")  # UNIQUE(provider_id, subject)

    got = await store.get_identity(p.id, "sub-1")
    assert got.id == ident.id

    await store.touch_last_login(ident.id, NOW)
    assert (await store.get_identity(p.id, "sub-1")).last_login_at == NOW


async def test_list_identities_for_users(store):
    u1 = await store.create_user("multi-1", None, "viewer")
    u2 = await store.create_user("multi-2", "h", "viewer")
    p = await store.create_auth_provider("okta", "oidc", {}, None)
    i1 = await store.create_identity(u1.id, p.id, "sub-1")

    assert [i.id for i in await store.list_identities_for_users([u1.id, u2.id])] == [i1.id]
    assert await store.list_identities_for_users([u2.id]) == []  # u2 is local-only
    assert await store.list_identities_for_users([]) == []


async def test_group_mapping_upsert_and_delete(store):
    p = await store.create_auth_provider("okta", "oidc", {}, None)
    gm = await store.put_group_mapping(p.id, "engineers", "operator")
    assert (gm.group_name, gm.role) == ("engineers", "operator")

    updated = await store.put_group_mapping(p.id, "engineers", "admin")  # upsert by provider+group
    assert updated.id == gm.id
    assert updated.role == "admin"
    assert [g.group_name for g in await store.list_group_mappings(p.id)] == ["engineers"]

    assert await store.delete_group_mapping(p.id, "engineers") is True
    assert await store.delete_group_mapping(p.id, "engineers") is False
    assert await store.list_group_mappings(p.id) == []


async def test_deleting_provider_cascades_identities_mappings_and_auth_state(store):
    u = await store.create_user("cascade-user", None, "viewer")
    p = await store.create_auth_provider("okta", "oidc", {}, None)
    await store.create_identity(u.id, p.id, "sub-1")
    await store.put_group_mapping(p.id, "engineers", "operator")
    await store.create_auth_state("state-1", p.id, "oidc_state", {"nonce": "n"}, NOW + timedelta(minutes=5))

    assert await store.delete_auth_provider("okta") is True
    assert await store.delete_auth_provider("okta") is False
    assert await store.get_auth_provider("okta") is None
    assert await store.get_identity(p.id, "sub-1") is None
    assert await store.list_group_mappings(p.id) == []
    assert await store.consume_auth_state("state-1", "oidc_state", p.id, NOW) is None
    assert await store.get_user(u.id) is not None


async def test_deleting_provider_deletes_the_sessions_and_tokens_of_its_users_only(store):
    okta = await store.create_auth_provider("okta", "oidc", {}, None)
    auth0 = await store.create_auth_provider("auth0", "oidc", {}, None)
    later = NOW + timedelta(hours=1)
    users_by_name = {}
    for username, provider in (("okta-user", okta), ("auth0-user", auth0), ("local-user", None)):
        u = await store.create_user(username, None if provider else "h", "viewer")
        if provider is not None:
            identity = await store.create_identity(u.id, provider.id, "sub-1")
            await store.touch_last_login(identity.id, NOW)
        await store.create_session(f"session-{username}", u.id, later, NOW)
        await store.create_access_token(f"token-{username}", u.id, "laptop", "read", later, NOW)
        users_by_name[username] = u
    assert await store.get_session_user("session-okta-user", NOW) is not None
    assert await store.get_access_token_user("token-okta-user", NOW) is not None

    assert await store.delete_auth_provider("okta") is True

    okta_user = users_by_name["okta-user"]
    assert await store.get_session_user("session-okta-user", NOW) is None
    assert await store.get_access_token_user("token-okta-user", NOW) is None
    assert await store.list_access_tokens(okta_user.id) == []
    assert (await store.get_user(okta_user.id)).disabled is False
    for username in ("auth0-user", "local-user"):
        u = users_by_name[username]
        assert (await store.get_session_user(f"session-{username}", NOW)).id == u.id
        assert (await store.get_access_token_user(f"token-{username}", NOW))[1].id == u.id


async def _users_with_a_session_and_a_token(store, okta, auth0):
    """-> the users `okta-user`, `auth0-user` and `local-user` by name.

    The session of a user is `session-<username>`, the token is `token-<username>`.
    """
    later = NOW + timedelta(hours=1)
    users_by_name = {}
    for username, provider in (("okta-user", okta), ("auth0-user", auth0), ("local-user", None)):
        u = await store.create_user(username, None if provider else "h", "viewer")
        if provider is not None:
            identity = await store.create_identity(u.id, provider.id, "sub-1")
            await store.touch_last_login(identity.id, NOW)
        await store.create_session(f"session-{username}", u.id, later, NOW)
        await store.create_access_token(f"token-{username}", u.id, "laptop", "read", later, NOW)
        users_by_name[username] = u
    return users_by_name


async def test_disabling_provider_deletes_the_sessions_and_tokens_of_its_users_only(store):
    okta = await store.create_auth_provider("okta", "oidc", {}, None, enabled=True)
    auth0 = await store.create_auth_provider("auth0", "oidc", {}, None, enabled=True)
    users_by_name = await _users_with_a_session_and_a_token(store, okta, auth0)
    assert await store.get_session_user("session-okta-user", NOW) is not None
    assert await store.get_access_token_user("token-okta-user", NOW) is not None

    updated = await store.update_auth_provider("okta", enabled=False)

    assert updated.enabled is False
    okta_user = users_by_name["okta-user"]
    assert await store.get_session_user("session-okta-user", NOW) is None
    assert await store.get_access_token_user("token-okta-user", NOW) is None
    assert await store.list_access_tokens(okta_user.id) == []
    assert (await store.get_identity(okta.id, "sub-1")).user_id == okta_user.id
    assert (await store.get_user(okta_user.id)).disabled is False
    for username in ("auth0-user", "local-user"):
        u = users_by_name[username]
        assert (await store.get_session_user(f"session-{username}", NOW)).id == u.id
        assert (await store.get_access_token_user(f"token-{username}", NOW))[1].id == u.id


async def test_provider_update_that_does_not_disable_deletes_no_session_and_no_token(store):
    okta = await store.create_auth_provider("okta", "oidc", {}, None, enabled=True)
    auth0 = await store.create_auth_provider("auth0", "oidc", {}, None, enabled=False)
    users_by_name = await _users_with_a_session_and_a_token(store, okta, auth0)

    await store.update_auth_provider("okta", config={"issuer": "https://okta"})
    await store.update_auth_provider("okta", secrets=b"new")
    await store.update_auth_provider("okta", enabled=True)
    await store.update_auth_provider("auth0", enabled=False)
    await store.update_auth_provider("auth0", enabled=True)

    for username, u in users_by_name.items():
        assert (await store.get_session_user(f"session-{username}", NOW)).id == u.id
        assert (await store.get_access_token_user(f"token-{username}", NOW))[1].id == u.id


async def test_auth_state_one_time_consume_and_expiry_and_purge(store):
    p = await store.create_auth_provider("okta", "oidc", {}, None)
    created = await store.create_auth_state(
        "state-1", p.id, "oidc_state", {"nonce": "abc"}, NOW + timedelta(minutes=5)
    )
    assert (created.kind, created.payload) == ("oidc_state", {"nonce": "abc"})

    consumed = await store.consume_auth_state("state-1", "oidc_state", p.id, NOW)
    assert consumed is not None and consumed.id == "state-1"
    assert await store.consume_auth_state("state-1", "oidc_state", p.id, NOW) is None  # one-time

    await store.create_auth_state("state-2", p.id, "oidc_state", {}, NOW - timedelta(seconds=1))
    assert await store.consume_auth_state("state-2", "oidc_state", p.id, NOW) is None  # expired, not deleted

    await store.create_auth_state("state-3", p.id, "oidc_state", {}, NOW - timedelta(seconds=1))
    await store.create_auth_state("state-4", p.id, "oidc_state", {}, NOW + timedelta(minutes=5))
    purged = await store.purge_expired_auth_state(NOW)
    assert purged == 2  # state-2 (left behind by the refused consume above) and state-3
    assert await store.consume_auth_state("state-4", "oidc_state", p.id, NOW) is not None  # not purged


async def test_consume_auth_state_deletes_only_a_row_of_the_kind_and_the_provider(store):
    okta = await store.create_auth_provider("okta", "oidc", {}, None)
    adfs = await store.create_auth_provider("adfs", "saml", {}, None)
    await store.create_auth_state("id-1", adfs.id, "saml_seen", {}, NOW + timedelta(minutes=5))

    assert await store.consume_auth_state("id-1", "saml_request", adfs.id, NOW) is None
    assert await store.consume_auth_state("id-1", "saml_seen", okta.id, NOW) is None

    with pytest.raises(ValueError):
        await store.create_auth_state("id-1", adfs.id, "saml_seen", {}, NOW + timedelta(minutes=5))
    consumed = await store.consume_auth_state("id-1", "saml_seen", adfs.id, NOW)
    assert (consumed.kind, consumed.provider_id) == ("saml_seen", adfs.id)


async def test_identity_of_a_missing_user_or_provider_raises_identity_owner_missing(store):
    u = await store.create_user("ident-user", None, "viewer")
    p = await store.create_auth_provider("okta", "oidc", {}, None)
    await store.delete_auth_provider("okta")

    with pytest.raises(IdentityOwnerMissing):
        await store.create_identity(u.id, p.id, "sub-1")
    with pytest.raises(IdentityOwnerMissing):
        await store.create_identity(999_999, p.id, "sub-1")


async def test_create_user_with_identity_creates_both_or_neither(store):
    p = await store.create_auth_provider("okta", "oidc", {}, None)

    user, identity = await store.create_user_with_identity(
        "alice", "viewer", p.id, "sub-1", email="a@b.example"
    )

    assert (user.username, user.role, user.password_hash) == ("alice", "viewer", None)
    assert (identity.user_id, identity.provider_id, identity.subject) == (user.id, p.id, "sub-1")
    assert identity.email == "a@b.example"
    assert (await store.get_identity(p.id, "sub-1")).id == identity.id

    with pytest.raises(ValueError):
        await store.create_user_with_identity("alice", "viewer", p.id, "sub-2")
    with pytest.raises(ValueError):
        await store.create_user_with_identity("bob", "viewer", p.id, "sub-1")
    with pytest.raises(IdentityOwnerMissing):
        await store.create_user_with_identity("carol", "viewer", 999_999, "sub-3")
    assert [u.username for u in await store.list_users()] == ["alice"]
    assert await store.get_identity(p.id, "sub-2") is None


async def test_provider_session_needs_an_enabled_provider(store):
    okta = await store.create_auth_provider("okta", "oidc", {}, None, enabled=True)
    adfs = await store.create_auth_provider("adfs", "saml", {}, None, enabled=False)
    u = await store.create_user("sso-user", None, "viewer")
    later = NOW + timedelta(hours=1)

    assert await store.create_provider_session("tok-okta", u.id, okta.id, later, NOW) is True
    assert await store.create_provider_session("tok-adfs", u.id, adfs.id, later, NOW) is False
    assert await store.create_provider_session("tok-none", u.id, 999_999, later, NOW) is False

    assert (await store.get_session_user("tok-okta", NOW)).id == u.id
    assert await store.get_session_user("tok-adfs", NOW) is None
    assert await store.get_session_user("tok-none", NOW) is None


@pytest.mark.parametrize("change", ["delete", "disable"])
async def test_provider_change_and_a_concurrent_provider_session_leave_no_session(store, change):
    later = NOW + timedelta(hours=1)
    for i in range(10):
        name = f"okta-{i}"
        p = await store.create_auth_provider(name, "oidc", {}, None, enabled=True)
        user, _ = await store.create_user_with_identity(f"user-{i}", "viewer", p.id, "sub-1")
        changed = (
            store.delete_auth_provider(name)
            if change == "delete"
            else store.update_auth_provider(name, enabled=False)
        )

        await asyncio.gather(changed, store.create_provider_session(f"tok-{i}", user.id, p.id, later, NOW))

        assert await store.get_session_user(f"tok-{i}", NOW) is None


@pytest.mark.parametrize("change", ["delete", "disable"])
async def test_provider_session_waits_for_a_provider_change_and_creates_no_session(store, change):
    if not isinstance(store, PgStore):
        pytest.skip("FakeStore has no row lock")
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import auth_providers

    p = await store.create_auth_provider("okta", "oidc", {}, None, enabled=True)
    user, _ = await store.create_user_with_identity("sso-user", "viewer", p.id, "sub-1")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as c:
            # The row lock that `delete_auth_provider` and a disabling `update_auth_provider` take.
            await c.execute(
                sa.select(auth_providers.c.id).where(auth_providers.c.id == p.id).with_for_update()
            )
            login = asyncio.create_task(
                store.create_provider_session("tok", user.id, p.id, NOW + timedelta(hours=1), NOW)
            )
            done, _ = await asyncio.wait({login}, timeout=0.5)
            assert not done
            if change == "delete":
                await c.execute(auth_providers.delete().where(auth_providers.c.id == p.id))
            else:
                await c.execute(
                    auth_providers.update().where(auth_providers.c.id == p.id).values(enabled=False)
                )
            await c.commit()
        assert await login is False
    finally:
        await engine.dispose()
    assert await store.get_session_user("tok", NOW) is None


# --- login events ---------------------------------------------------------------


async def test_login_events_record_and_list_newest_first(store):
    u = await store.create_user("audit-user", "h", "viewer")
    e1 = await store.record_login_event(
        username="audit-user", user_id=u.id, provider="local", outcome="ok", source="10.0.0.1", at=NOW
    )
    assert (e1.username, e1.user_id, e1.provider, e1.outcome, e1.source) == (
        "audit-user",
        u.id,
        "local",
        "ok",
        "10.0.0.1",
    )
    e2 = await store.record_login_event(
        username="ghost",
        user_id=None,
        provider="local",
        outcome="bad_credentials",
        source="",
        at=NOW + timedelta(seconds=1),
    )
    e3 = await store.record_login_event(
        username="alice",
        user_id=None,
        provider="okta",
        outcome="ok",
        source="10.0.0.2",
        at=NOW + timedelta(seconds=2),
    )

    events = await store.list_login_events()
    assert [e.id for e in events] == [e3.id, e2.id, e1.id]  # newest first


async def test_login_events_limit(store):
    for i in range(5):
        await store.record_login_event(
            username=f"u{i}",
            user_id=None,
            provider="local",
            outcome="bad_credentials",
            source="",
            at=NOW + timedelta(seconds=i),
        )
    events = await store.list_login_events(limit=2)
    assert len(events) == 2
    assert [e.username for e in events] == ["u4", "u3"]  # newest two


async def test_login_event_user_id_set_null_when_user_deleted(store):
    if not isinstance(store, PgStore):
        pytest.skip("FK ON DELETE SET NULL cannot be expressed by FakeStore")
    from sqlalchemy.ext.asyncio import create_async_engine

    u = await store.create_user("about-to-be-deleted", "h", "viewer")
    e = await store.record_login_event(
        username="about-to-be-deleted", user_id=u.id, provider="local", outcome="ok", source="", at=NOW
    )
    engine = create_async_engine(DSN)
    try:
        async with engine.begin() as c:
            await c.execute(users.delete().where(users.c.id == u.id))
    finally:
        await engine.dispose()

    events = {row.id: row for row in await store.list_login_events()}
    assert events[e.id].user_id is None
    assert events[e.id].username == "about-to-be-deleted"  # the name survives independently


async def test_login_events_are_purged_by_age(store):
    for age, name in ((100, "ancient"), (89, "kept"), (1, "recent")):
        await store.record_login_event(
            username=name,
            user_id=None,
            provider="local",
            outcome="bad_credentials",
            source="",
            at=NOW - timedelta(days=age),
        )
    assert await store.purge_login_events(NOW - timedelta(days=90)) == 1
    assert sorted(e.username for e in await store.list_login_events()) == ["kept", "recent"]
    assert await store.purge_login_events(NOW - timedelta(days=90)) == 0


# --- cypher events ---------------------------------------------------------------


async def test_cypher_events_record_and_list_newest_first(store):
    u = await store.create_user("cypher-user", "h", "operator")
    e1 = await store.record_cypher_event(
        user_id=u.id, query="MATCH (n) RETURN n", outcome="ok", row_count=7, byte_count=512, at=NOW
    )
    assert (e1.user_id, e1.query, e1.outcome, e1.row_count, e1.byte_count) == (
        u.id,
        "MATCH (n) RETURN n",
        "ok",
        7,
        512,
    )
    e2 = await store.record_cypher_event(
        user_id=u.id,
        query="LOAD CSV FROM 'http://x' AS r RETURN r",
        outcome="rejected",
        row_count=0,
        byte_count=0,
        at=NOW + timedelta(seconds=1),
    )
    events = await store.list_cypher_events()
    assert [e.id for e in events] == [e2.id, e1.id]  # newest first
    assert len(await store.list_cypher_events(limit=1)) == 1


async def test_cypher_events_are_purged_by_age(store):
    for age in (200, 179, 1):
        await store.record_cypher_event(
            user_id=None,
            query=f"RETURN {age}",
            outcome="ok",
            row_count=1,
            byte_count=1,
            at=NOW - timedelta(days=age),
        )
    assert await store.purge_cypher_events(NOW - timedelta(days=180)) == 1
    assert sorted(e.query for e in await store.list_cypher_events()) == ["RETURN 1", "RETURN 179"]


async def test_cypher_event_user_id_set_null_when_user_deleted(store):
    if not isinstance(store, PgStore):
        pytest.skip("FK ON DELETE SET NULL cannot be expressed by FakeStore")
    from sqlalchemy.ext.asyncio import create_async_engine

    u = await store.create_user("ran-then-deleted", "h", "operator")
    e = await store.record_cypher_event(
        user_id=u.id, query="MATCH (n) RETURN n", outcome="ok", row_count=1, byte_count=2, at=NOW
    )
    engine = create_async_engine(DSN)
    try:
        async with engine.begin() as c:
            await c.execute(users.delete().where(users.c.id == u.id))
    finally:
        await engine.dispose()

    events = {row.id: row for row in await store.list_cypher_events()}
    assert events[e.id].user_id is None
    assert events[e.id].query == "MATCH (n) RETURN n"  # the evidence survives


async def test_evidence_exports_are_listed_newest_first(store):
    u = await store.create_user("exporter", "h", "operator")
    rows = [
        await store.record_evidence_export(
            user_id=u.id,
            username="exporter",
            kind="payload_bundle",
            raw_mode="full",
            source="edge",
            host="r1",
            run_id=f"run-{i}",
            payloads=1,
            at=NOW + timedelta(seconds=i),
        )
        for i in range(3)
    ]
    listed = await store.list_evidence_exports()
    assert [e.id for e in listed] == [r.id for r in reversed(rows)]
    assert (listed[0].username, listed[0].kind, listed[0].raw_mode, listed[0].run_id) == (
        "exporter",
        "payload_bundle",
        "full",
        "run-2",
    )
    assert [e.id for e in await store.list_evidence_exports(limit=1)] == [rows[-1].id]


async def test_evidence_export_user_id_set_null_when_user_deleted(store):
    if not isinstance(store, PgStore):
        pytest.skip("FK ON DELETE SET NULL cannot be expressed by FakeStore")
    from sqlalchemy.ext.asyncio import create_async_engine

    u = await store.create_user("exported-then-deleted", "h", "operator")
    e = await store.record_evidence_export(
        user_id=u.id,
        username="exported-then-deleted",
        kind="http_trace",
        raw_mode=None,
        source="vco-1",
        host="",
        run_id="1790000000000-abcdef12",
        payloads=1,
        at=NOW,
    )
    engine = create_async_engine(DSN)
    try:
        async with engine.begin() as c:
            await c.execute(users.delete().where(users.c.id == u.id))
    finally:
        await engine.dispose()
    [row] = [r for r in await store.list_evidence_exports() if r.id == e.id]
    assert row.user_id is None
    assert row.username == "exported-then-deleted"


async def test_cypher_events_keep_the_origin_and_the_step_id(store):
    step_id = str(uuid.uuid4())
    await store.record_cypher_event(
        user_id=None, query="RETURN 1", outcome="ok", row_count=1, byte_count=1, at=NOW
    )
    await store.record_cypher_event(
        user_id=None,
        query="RETURN 2",
        outcome="ok",
        row_count=1,
        byte_count=1,
        at=NOW + timedelta(seconds=1),
        origin="web",
        ai_step_id=step_id,
    )
    events = await store.list_cypher_events()
    assert [(e.query, e.origin, e.ai_step_id) for e in events] == [
        ("RETURN 2", "web", step_id),
        ("RETURN 1", None, None),
    ]


# --- AI events -------------------------------------------------------------------


async def test_ai_events_record_and_list_newest_first(store):
    u = await store.create_user("ai-user", "h", "operator")
    step_id = str(uuid.uuid4())
    first = await store.record_ai_event(
        AiEvent(
            at=NOW,
            origin="web",
            event="tool.call",
            outcome="ok",
            user_id=u.id,
            step_id=step_id,
            provider="anthropic",
            model_requested="claude-opus-5",
            tool="trace_path",
            tool_version=1,
            snapshot="3000",
            latency_ms=41,
        )
    )
    second = await store.record_ai_event(
        AiEvent(
            at=NOW + timedelta(seconds=1),
            origin="mcp",
            event="turn.error",
            outcome="error",
            tokens_in=10,
            tokens_out=2,
            error_class="APIError",
            detail={"status": 529},
        )
    )
    assert first.id and second.id and first.id != second.id

    events = await store.list_ai_events()
    assert [e.id for e in events] == [second.id, first.id]
    stored = events[1]
    assert (stored.user_id, stored.step_id, stored.tool, stored.tool_version, stored.latency_ms) == (
        u.id,
        step_id,
        "trace_path",
        1,
        41,
    )
    assert (stored.conversation_id, stored.message_id, stored.detail) == (None, None, None)
    assert (events[0].tokens_in, events[0].tokens_out, events[0].detail) == (10, 2, {"status": 529})
    assert len(await store.list_ai_events(limit=1)) == 1


async def test_ai_events_are_purged_by_age(store):
    for age in (200, 179, 1):
        await store.record_ai_event(
            AiEvent(
                at=NOW - timedelta(days=age), origin="web", event="tool.call", outcome="ok", tool=str(age)
            )
        )
    assert await store.purge_ai_events(NOW - timedelta(days=180)) == 1
    assert sorted(e.tool for e in await store.list_ai_events()) == ["1", "179"]


async def test_ai_token_usage_sums_per_user_and_utc_day(store):
    ada = await store.create_user("ada-tokens", "h", "operator")
    bob = await store.create_user("bob-tokens", "h", "operator")
    day = NOW.replace(hour=0)
    rows = [
        (day + timedelta(hours=1), ada.id, 100, 10),
        (day + timedelta(hours=23), ada.id, 50, None),
        (day + timedelta(hours=2), bob.id, 7, 3),
        (day + timedelta(hours=3), None, 1, 1),
        (day + timedelta(hours=4), ada.id, None, None),  # no tokens: not counted
        (day - timedelta(hours=1), ada.id, 5, 5),  # the previous UTC day
        (day - timedelta(days=3), ada.id, 9, 9),  # before `since`
    ]
    for at, user_id, tokens_in, tokens_out in rows:
        await store.record_ai_event(
            AiEvent(
                at=at,
                origin="web",
                event="provider.round",
                outcome="ok",
                user_id=user_id,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
            )
        )

    usage = await store.ai_token_usage(day - timedelta(days=1))
    assert [(u.day, u.user_id, u.tokens_in, u.tokens_out) for u in usage] == [
        (day.date(), ada.id, 150, 10),
        (day.date(), bob.id, 7, 3),
        (day.date(), None, 1, 1),
        ((day - timedelta(days=1)).date(), ada.id, 5, 5),
    ]
    assert await store.ai_token_usage(day + timedelta(days=1)) == []


async def test_a_prompt_version_is_stored_once_per_hash(store):
    assert await store.put_prompt_version("a" * 64, "base prompt", NOW) is True
    assert await store.put_prompt_version("a" * 64, "base prompt", NOW + timedelta(seconds=1)) is False
    assert await store.put_prompt_version("b" * 64, "other prompt", NOW) is True


async def test_user_nullable_password_hash_and_role_source(store):
    u = await store.create_user("nullpass-user", None, "viewer")
    assert u.password_hash is None
    assert u.role_source == "local"  # the default for every account, local or SSO

    patched = await store.update_user(u.id, role="operator", role_source="mapped")
    assert (patched.role, patched.role_source) == ("operator", "mapped")

    # a role edit with no explicit role_source leaves it as it was
    patched2 = await store.update_user(u.id, role="admin")
    assert (patched2.role, patched2.role_source) == ("admin", "mapped")

    patched3 = await store.update_user(u.id, role_source="local")
    assert patched3.role_source == "local"


# --- job queue -------------------------------------------------------------------
#

LEASE = timedelta(minutes=5)


async def _queue(store, kind, *, source=None, device=None, priority=0, at=NOW, max_attempts=3):
    return await store.enqueue_job(
        kind,
        source=source,
        device=device,
        priority=priority,
        not_before=at,
        max_attempts=max_attempts,
        triggered_by="scheduler",
        now=at,
    )


async def test_enqueue_is_idempotent_while_one_is_pending(store):
    """The `one_pending_per_kind` index is the pile-up guard: a scheduler that
    ticks while the previous turn is still queued cannot stack a second one."""
    first = await _queue(store, "maintenance.prune_graph")
    assert first is not None
    assert (first.state, first.attempt, first.claimed_by) == ("queued", 0, None)

    assert await _queue(store, "maintenance.prune_graph") is None  # still queued

    claimed = await store.claim_jobs("worker-a", 5, NOW, LEASE)
    assert [j.id for j in claimed] == [first.id]
    assert await _queue(store, "maintenance.prune_graph") is None  # now running

    await store.finish_job(first.id, "ok", "done", NOW)
    again = await _queue(store, "maintenance.prune_graph")
    assert again is not None and again.id != first.id  # the finished row frees the scope


async def test_an_enqueue_that_breaks_another_constraint_is_raised(store):
    if isinstance(store, FakeStore):
        pytest.skip("FakeStore has no NOT NULL constraint")
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        await _queue(store, None)
    assert await _queue(store, "maintenance.prune_graph") is not None


async def test_the_pending_scope_is_kind_plus_source_and_device(store):
    assert await _queue(store, "collect.fetch", source="vyos", device="edge-1") is not None
    assert await _queue(store, "collect.fetch", source="vyos", device="edge-2") is not None
    assert await _queue(store, "collect.fetch", source="vyos", device="edge-1") is None
    assert await _queue(store, "collect.fetch", source="vyos") is not None  # no device is its own scope
    assert await _queue(store, "collect.fetch", source="vyos") is None


async def test_two_claimants_never_take_the_same_job(store):
    ids = set()
    for i in range(4):
        job = await _queue(store, f"maintenance.k{i}")
        ids.add(job.id)

    a = await store.claim_jobs("worker-a", 2, NOW, LEASE)
    b = await store.claim_jobs("worker-b", 2, NOW, LEASE)
    c = await store.claim_jobs("worker-c", 2, NOW, LEASE)

    assert len(a) == len(b) == 2
    assert c == []  # nothing left
    assert {j.id for j in a} | {j.id for j in b} == ids
    assert not ({j.id for j in a} & {j.id for j in b})
    assert all(j.state == "running" and j.attempt == 1 for j in a + b)
    assert {j.claimed_by for j in a} == {"worker-a"}
    assert {j.claimed_by for j in b} == {"worker-b"}


async def test_a_job_is_not_claimed_before_its_not_before(store):
    later = await _queue(store, "maintenance.later", at=NOW + timedelta(minutes=10))
    assert await store.claim_jobs("worker-a", 5, NOW, LEASE) == []
    claimed = await store.claim_jobs("worker-a", 5, NOW + timedelta(minutes=11), LEASE)
    assert [j.id for j in claimed] == [later.id]


async def test_higher_priority_is_claimed_first(store):
    low = await _queue(store, "maintenance.low", priority=0)
    high = await _queue(store, "maintenance.high", priority=10)
    claimed = await store.claim_jobs("worker-a", 1, NOW, LEASE)
    assert [j.id for j in claimed] == [high.id]
    assert (await store.claim_jobs("worker-a", 1, NOW, LEASE))[0].id == low.id


async def test_an_expired_lease_is_requeued(store):
    job = await _queue(store, "maintenance.prune_graph", max_attempts=3)
    await store.claim_jobs("worker-gone", 1, NOW, LEASE)

    assert await store.reap_jobs(NOW + timedelta(minutes=1)) == 0  # lease still good
    assert await store.reap_jobs(NOW + timedelta(minutes=6)) == 1

    (requeued,) = await store.list_jobs(limit=1)
    assert requeued.id == job.id
    assert (requeued.state, requeued.claimed_by, requeued.lease_expires_at) == ("queued", None, None)
    assert requeued.attempt == 1
    assert "lease expired" in requeued.detail

    retaken = await store.claim_jobs("worker-b", 1, NOW + timedelta(minutes=6), LEASE)
    assert [j.attempt for j in retaken] == [2]


async def test_a_reaped_job_with_no_attempts_left_is_dead_not_requeued(store):
    await _queue(store, "maintenance.prune_graph", max_attempts=1)
    await store.claim_jobs("worker-gone", 1, NOW, LEASE)
    assert await store.reap_jobs(NOW + timedelta(minutes=6)) == 1

    (reaped,) = await store.list_jobs(limit=1)
    assert reaped.state == "dead"
    assert reaped.finished_at is not None
    assert await _queue(store, "maintenance.prune_graph") is not None


async def test_a_heartbeat_extends_only_this_workers_claims(store):
    mine = await _queue(store, "maintenance.mine")
    await store.claim_jobs("worker-a", 1, NOW, LEASE)

    assert await store.heartbeat_jobs([mine.id], "worker-b", NOW + timedelta(minutes=1), LEASE) == []
    assert await store.heartbeat_jobs([mine.id], "worker-a", NOW + timedelta(minutes=4), LEASE) == [mine.id]
    # the extension moved the lease past the point that would have reaped it
    assert await store.reap_jobs(NOW + timedelta(minutes=6)) == 0
    assert await store.heartbeat_jobs([], "worker-a", NOW, LEASE) == []


async def test_a_failed_attempt_is_requeued_with_its_reason(store):
    job = await _queue(store, "maintenance.prune_graph", max_attempts=3)
    (claimed,) = await store.claim_jobs("worker-a", 1, NOW, LEASE)

    retry_at = NOW + timedelta(minutes=1)
    requeued = await store.finish_job(
        claimed.id, "error", "RuntimeError: twin unreachable", NOW, retry_at=retry_at
    )
    assert (requeued.state, requeued.not_before, requeued.finished_at) == ("queued", retry_at, None)
    assert requeued.detail == "RuntimeError: twin unreachable"
    assert (requeued.claimed_by, requeued.lease_expires_at) == (None, None)
    assert requeued.attempt == 1  # attempts accrue at claim time, not here

    assert await store.claim_jobs("worker-a", 1, NOW, LEASE) == []  # backoff respected
    assert len(await store.claim_jobs("worker-a", 1, retry_at, LEASE)) == 1
    assert job.id == requeued.id  # one row throughout, never a fresh one per attempt


async def test_a_terminal_failure_records_a_dead_row(store):
    job = await _queue(store, "maintenance.prune_graph", max_attempts=2)
    (claimed,) = await store.claim_jobs("worker-a", 1, NOW, LEASE)
    dead = await store.finish_job(claimed.id, "dead", "gave up", NOW + timedelta(seconds=5))
    assert (dead.state, dead.detail) == ("dead", "gave up")
    assert dead.finished_at == NOW + timedelta(seconds=5)
    assert (dead.claimed_by, dead.lease_expires_at) == (None, None)
    assert dead.id == job.id


async def test_a_late_finish_from_a_reclaimed_attempt_is_refused(store):
    job = await _queue(store, "maintenance.prune_graph")
    (first,) = await store.claim_jobs("worker-a", 1, NOW, LEASE)

    assert await store.reap_jobs(NOW + timedelta(minutes=6)) == 1
    (second,) = await store.claim_jobs("worker-b", 1, NOW + timedelta(minutes=6), LEASE)
    assert (second.id, second.attempt, second.claimed_by) == (job.id, 2, "worker-b")

    late = await store.finish_job(
        first.id,
        "ok",
        "worker-a, long after it lost the job",
        NOW + timedelta(minutes=7),
        claimed_by=first.claimed_by,
        attempt=first.attempt,
    )
    assert late is None
    row = next(j for j in await store.list_jobs() if j.id == job.id)
    assert (row.state, row.claimed_by, row.attempt) == ("running", "worker-b", 2)
    assert row.finished_at is None
    assert row.detail != "worker-a, long after it lost the job"

    done = await store.finish_job(
        second.id,
        "ok",
        "done",
        NOW + timedelta(minutes=8),
        claimed_by=second.claimed_by,
        attempt=second.attempt,
    )
    assert done is not None and (done.state, done.detail) == ("ok", "done")


async def test_finishing_a_reaped_job_does_not_resurrect_it(store):
    job = await _queue(store, "maintenance.prune_graph", max_attempts=3)
    await store.claim_jobs("worker-gone", 1, NOW, LEASE)
    await store.reap_jobs(NOW + timedelta(minutes=6))

    assert await store.finish_job(job.id, "ok", "too late", NOW + timedelta(minutes=7)) is None
    (row,) = await store.list_jobs(limit=1)
    assert row.state == "queued"


async def test_completed_jobs_are_kept_and_bounded_by_their_own_retention(store):
    old = await _queue(store, "maintenance.old")
    (claimed,) = await store.claim_jobs("worker-a", 1, NOW, LEASE)
    await store.finish_job(claimed.id, "ok", "done", NOW - timedelta(days=40))

    recent = await _queue(store, "maintenance.recent")
    (claimed2,) = await store.claim_jobs("worker-a", 1, NOW, LEASE)
    await store.finish_job(claimed2.id, "ok", "done", NOW - timedelta(days=1))

    pending = await _queue(store, "maintenance.pending", at=NOW - timedelta(days=100))

    assert {j.id for j in await store.list_jobs()} == {old.id, recent.id, pending.id}

    assert await store.purge_jobs(NOW - timedelta(days=30)) == 1
    remaining = {j.id for j in await store.list_jobs()}
    assert old.id not in remaining
    # a queued row is never purged however old it is: it has not run yet
    assert remaining == {recent.id, pending.id}


async def test_job_depth_counts_by_state(store):
    await _queue(store, "maintenance.a")
    await _queue(store, "maintenance.b")
    queued = await _queue(store, "maintenance.c")
    (claimed,) = await store.claim_jobs("worker-a", 1, NOW, LEASE)
    await store.finish_job(claimed.id, "ok", "done", NOW)

    depth = await store.job_depth()
    assert depth.get("ok") == 1
    assert depth.get("queued") == 2
    assert depth.get("running") is None
    assert queued.state == "queued"


async def test_jobs_list_newest_first_and_bounded(store):
    ids = [(await _queue(store, f"maintenance.k{i}")).id for i in range(5)]
    assert [j.id for j in await store.list_jobs()] == list(reversed(ids))
    assert [j.id for j in await store.list_jobs(limit=2)] == list(reversed(ids))[:2]


# --- device fleets ----------------------------------------------------------------


async def test_replace_devices_upserts_deletes_and_keeps_pins(store):
    await store.create_source("vyos1", "vyos", {}, b"")
    rows = await store.replace_devices("vyos1", [DeviceSpec("r1"), DeviceSpec("r2", port=2222)])
    assert [d.host for d in rows] == ["r1", "r2"]
    assert rows[1].port == 2222

    assert await store.set_device_host_key("vyos1", "r1", "ssh-ed25519 K")
    rows = await store.replace_devices(
        "vyos1",
        [DeviceSpec("r1", enabled=False), DeviceSpec("r3")],
    )
    by = {d.host: d for d in rows}
    assert set(by) == {"r1", "r3"}
    # the rewrite must never unpin: r1 keeps its key through the upsert
    assert by["r1"].host_key == "ssh-ed25519 K"
    assert by["r1"].enabled is False
    assert by["r3"].host_key == ""


async def test_replace_devices_refuses_unknown_source_and_duplicate_hosts(store):
    with pytest.raises(ValueError):
        await store.replace_devices("nope", [])
    with pytest.raises(ValueError):
        await store.replace_devices("nope", [DeviceSpec("r1")])
    await store.create_source("vyos1", "vyos", {}, b"")
    with pytest.raises(ValueError):
        await store.replace_devices("vyos1", [DeviceSpec("r1"), DeviceSpec("r1")])


async def test_device_pin_is_empty_only_and_unpin_clears_it(store):
    await store.create_source("vyos1", "vyos", {}, b"")
    await store.replace_devices("vyos1", [DeviceSpec("r1")])
    assert await store.set_device_host_key("vyos1", "r1", "ssh-ed25519 A") is True
    assert await store.set_device_host_key("vyos1", "r1", "ssh-ed25519 B") is False
    (row,) = await store.list_devices("vyos1")
    assert row.host_key == "ssh-ed25519 A"
    assert await store.set_device_host_key("vyos1", "ghost", "ssh-ed25519 C") is False

    assert await store.clear_device_host_key("vyos1", "r1") is True
    assert await store.clear_device_host_key("vyos1", "r1") is False
    (row,) = await store.list_devices("vyos1")
    assert row.host_key == ""


async def test_list_devices_scopes_by_source_and_deleting_a_source_takes_its_fleet(store):
    await store.create_source("vyos1", "vyos", {}, b"")
    await store.create_source("vyos2", "vyos", {}, b"")
    await store.replace_devices("vyos1", [DeviceSpec("a")])
    await store.replace_devices("vyos2", [DeviceSpec("b")])
    assert [d.host for d in await store.list_devices("vyos1")] == ["a"]
    assert [(d.source, d.host) for d in await store.list_devices()] == [("vyos1", "a"), ("vyos2", "b")]

    await store.delete_source("vyos1")
    assert [(d.source, d.host) for d in await store.list_devices()] == [("vyos2", "b")]


async def test_a_host_that_leaves_the_fleet_takes_its_observations_with_it(store):
    await store.create_source("fr6", "vyos", {"site_code": "fr6"}, b"")
    await store.replace_devices("fr6", [DeviceSpec("r1"), DeviceSpec("r2")])
    await store.record_target_devices("fr6", "r1", ["dev:r1"])
    await store.record_target_devices("fr6", "r2", ["dev:r2"])
    await store.upsert_device_status("fr6", "r1", now=NOW, ok=True, raw_sha="a", full=True)
    await store.upsert_device_status("fr6", "r2", now=NOW, ok=True, raw_sha="b", full=True)

    await store.replace_devices("fr6", [DeviceSpec("r2")])

    assert [(m.host, m.device_uid) for m in await store.target_devices("fr6")] == [("r2", "dev:r2")]
    assert [s.host for s in await store.list_device_status("fr6")] == ["r2"]


async def test_replace_devices_with_an_empty_list_empties_the_fleet(store):
    await store.create_source("vyos1", "vyos", {}, b"")
    await store.replace_devices("vyos1", [DeviceSpec("a")])
    assert await store.replace_devices("vyos1", []) == []
    assert await store.list_devices("vyos1") == []


# --- device status ------------------------------------------------------------------


async def test_upsert_device_status_creates_then_a_partial_update_keeps_stale_fields(store):
    await store.create_source("vyos1", "vyos", {}, b"")
    row = await store.upsert_device_status(
        "vyos1",
        "r1",
        now=NOW,
        ok=True,
        raw_sha="sha1",
        full=True,
        fetch_ms=100,
        normalize_ms=50,
        load_ms=20,
    )
    assert row.last_attempt_at == NOW
    assert row.last_success_at == NOW
    assert row.last_full_at == NOW
    assert row.last_raw_sha == "sha1"
    assert row.consecutive_failures == 0
    assert row.last_error == ""
    assert (row.fetch_ms, row.normalize_ms, row.load_ms) == (100, 50, 20)

    # a second ok call with no sha and only load_ms set must not clobber what
    # the first call recorded for the fields it didn't pass
    later = NOW + timedelta(minutes=1)
    row2 = await store.upsert_device_status("vyos1", "r1", now=later, ok=True, load_ms=30)
    assert row2.last_raw_sha == "sha1"
    assert row2.fetch_ms == 100
    assert row2.load_ms == 30
    assert row2.last_attempt_at == later
    assert row2.last_success_at == later
    assert row2.last_full_at == NOW  # full=False this time, so it doesn't advance


async def test_upsert_device_status_failure_path_increments_then_resets_on_success(store):
    await store.create_source("vyos1", "vyos", {}, b"")
    row = await store.upsert_device_status("vyos1", "r1", now=NOW, ok=False, error="timeout")
    assert row.consecutive_failures == 1
    assert row.last_error == "timeout"
    assert row.last_success_at is None
    assert row.last_raw_sha == ""

    later = NOW + timedelta(minutes=1)
    row2 = await store.upsert_device_status("vyos1", "r1", now=later, ok=False, error="timeout again")
    assert row2.consecutive_failures == 2
    assert row2.last_error == "timeout again"
    assert row2.last_success_at is None
    assert row2.last_raw_sha == ""

    even_later = later + timedelta(minutes=1)
    row3 = await store.upsert_device_status("vyos1", "r1", now=even_later, ok=True, raw_sha="sha2")
    assert row3.consecutive_failures == 0
    assert row3.last_error == ""
    assert row3.last_success_at == even_later
    assert row3.last_raw_sha == "sha2"


async def test_upsert_device_status_unknown_source_raises(store):
    with pytest.raises(ValueError):
        await store.upsert_device_status("nope", "r1", now=NOW, ok=True)
    with pytest.raises(ValueError):
        await store.upsert_device_status("nope", "r1", now=NOW, ok=False, error="boom")


async def test_list_device_status_scopes_by_source_and_deleting_a_source_cascades(store):
    await store.create_source("vyos1", "vyos", {}, b"")
    await store.create_source("vyos2", "vyos", {}, b"")
    await store.upsert_device_status("vyos1", "b", now=NOW, ok=True)
    await store.upsert_device_status("vyos1", "a", now=NOW, ok=True)
    await store.upsert_device_status("vyos2", "c", now=NOW, ok=True)
    assert [d.host for d in await store.list_device_status("vyos1")] == ["a", "b"]
    assert [(d.source, d.host) for d in await store.list_device_status()] == [
        ("vyos1", "a"),
        ("vyos1", "b"),
        ("vyos2", "c"),
    ]

    await store.delete_source("vyos1")
    assert [(d.source, d.host) for d in await store.list_device_status()] == [("vyos2", "c")]


async def test_one_location_named_twice_in_a_call_settles_on_one_name(store):
    await store.create_source("unifi1", "unifi", {}, b"")
    await store.record_target_devices(
        "unifi1",
        "controller",
        ["dev:a", "dev:b"],
        {"dev:a": ("default", "Head office"), "dev:b": ("default", "Head Office")},
    )

    rows = await store.list_reported_locations("unifi1")
    assert [(r.location_id, r.name, r.device_count) for r in rows] == [("default", "Head Office", 2)]


async def test_a_location_reported_without_a_name_keeps_the_one_it_has(store):
    await store.create_source("unifi1", "unifi", {}, b"")
    await store.record_target_devices(
        "unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Head office")}
    )
    await store.record_target_devices(
        "unifi1",
        "controller",
        ["dev:a", "dev:b"],
        {"dev:a": ("default", "Head office"), "dev:b": ("default", "")},
    )

    rows = await store.list_reported_locations("unifi1")
    assert [(r.location_id, r.name) for r in rows] == [("default", "Head office")]


async def test_resolve_device_mints_once_and_keeps_the_uid(store):
    """The device identity registry: the first sight mints `dev:<short hostname>`,
    and the identifier keeps that uid whatever hostname it reports later."""
    uid = await store.resolve_device("serial", "FOC1234ABCD", "core1.corp.example", 7)
    assert uid == "dev:core1"
    assert await store.resolve_device("serial", "foc1234abcd", "core9", 8) == uid
    assert await store.resolve_device("serial", "FDO5555QRST", "core1", 8) == "dev:core1-qrst"
    rows = [r for r in await store.device_identities() if r.uid == uid]
    assert [(r.kind, r.value, r.hostname, r.last_hostname, r.first_run_id) for r in rows] == [
        ("serial", "foc1234abcd", "core1.corp.example", "core9", 7)
    ]


async def test_bind_device_adds_a_stack_member_and_keeps_a_held_identifier(store):
    uid = await store.resolve_device("serial", "FOC1111AAAA", "stack1", 1)
    other = await store.resolve_device("serial", "FOC3333CCCC", "other1", 1)
    await store.bind_device(uid, "serial", "FOC2222BBBB", 1)
    # an identifier the registry holds already keeps its uid
    await store.bind_device(uid, "serial", "FOC3333CCCC", 1)
    assert await store.resolve_device("serial", "FOC2222BBBB", None, 2) == uid
    assert await store.resolve_device("serial", "FOC3333CCCC", None, 2) == other
    with pytest.raises(LookupError):
        await store.bind_device("dev:nobody", "serial", "FOC4444DDDD", 1)


async def test_rekey_device_refuses_a_taken_uid_and_increments_the_generation(store):
    uid = await store.resolve_device("serial", "FOC1111AAAA", "switch", 1)
    assert uid == "dev:switch-aaaa"  # a default name always gets a suffix
    await store.bind_device(uid, "serial", "FOC2222BBBB", 1)
    taken = await store.resolve_device("ref", "vyos:edge", "edge", 1)
    assert await store.identity_generation() == 0

    with pytest.raises(ValueError, match="taken"):
        await store.rekey_device(uid, taken)
    with pytest.raises(LookupError):
        await store.rekey_device("dev:nobody", "dev:somebody")
    assert await store.identity_generation() == 0

    assert await store.rekey_device(uid, "dev:access3") == 2
    assert await store.identity_generation() == 1
    assert await store.resolve_device("serial", "FOC2222BBBB", None, 2) == "dev:access3"
    assert await store.resolve_device("serial", "FOC1111AAAA", None, 2) == "dev:access3"


async def test_a_rename_moves_the_hand_placement_and_the_observed_target_devices(store):
    await store.create_source("unifi1", "unifi", {}, b"")
    await store.create_site("dc1", "DC 1", "")
    uid = await store.resolve_device("serial", "FOC1111AAAA", "core1", 1)
    await store.record_target_devices("unifi1", "controller", [uid], {})
    assert await store.assign_device(uid, "dc1")

    await store.rekey_device(uid, "dev:core9")

    assert await store.device_sites() == {"dev:core9": "dc1"}
    assert [t.device_uid for t in await store.target_devices("unifi1")] == ["dev:core9"]


async def test_a_merge_moves_a_replaced_chassis_into_the_uid_and_keeps_its_placement(store):
    await store.create_site("dc1", "DC 1", "")
    await store.create_site("dc2", "DC 2", "")
    old = await store.resolve_device("serial", "FOC1111AAAA", "core1", 1)
    new = await store.resolve_device("serial", "FOC2222BBBB", "core1", 2)
    assert new == "dev:core1-bbbb"
    await store.assign_device(old, "dc1")
    await store.assign_device(new, "dc2")

    with pytest.raises(LookupError):
        await store.rekey_device(new, "dev:nobody", merge=True)
    assert await store.rekey_device(new, old, merge=True) == 1

    assert await store.resolve_device("serial", "FOC2222BBBB", None, 3) == old
    assert await store.device_sites() == {old: "dc1"}
    assert await store.identity_generation() == 1


async def test_the_first_mint_takes_over_the_placement_of_the_uid_before_the_registry(store):
    """A device placed by hand under its serial-based uid, or under its by-ref
    uid, keeps the placement when the registry mints its new uid."""
    await store.create_site("dc1", "DC 1", "")
    await store.assign_device("dev:foc1111aaaa", "dc1")
    await store.assign_device("dev:x:manual-dc1-seed:edge-r2", "dc1")

    serial = await store.resolve_device("serial", "FOC1111AAAA", "core1", 1)
    ref = await store.resolve_device("ref", "manual:dc1-seed:edge-r2", "edge-r2", 1)

    assert await store.device_sites() == {serial: "dc1", ref: "dc1"}


async def test_the_identity_report_lists_the_uids_that_do_not_read_as_the_hostname(store):
    plain = await store.resolve_device("serial", "FOC1111AAAA", "core1", 1)
    suffixed = await store.resolve_device("serial", "FOC2222BBBB", "core1", 1)
    renamed = await store.resolve_device("serial", "FOC3333CCCC", "edge1", 1)
    await store.resolve_device("serial", "FOC3333CCCC", "edge2", 2)

    report = {r.uid: r for r in await store.device_identity_report()}
    assert set(report) == {suffixed, renamed}
    assert plain == "dev:core1"
    assert (report[suffixed].hostname, report[suffixed].last_hostname) == ("core1", "core1")
    assert (report[renamed].hostname, report[renamed].last_hostname) == ("edge1", "edge2")
    assert report[renamed].identifiers == [("serial", "foc3333cccc")]
    assert report[renamed].first_run_id == 1


async def test_delete_site_releases_every_reference_and_reports_them(store):
    await store.create_site("dcber1", "Berlin", "")
    await store.create_source("edge", "vyos", {"site_code": "dcber1"}, b"")
    await store.create_source("unifi1", "unifi", {}, b"")
    await store.record_target_devices(
        "unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Head office")}
    )
    await store.bind_location("unifi1", "default", "dcber1")
    await store.assign_device("dev:a", "dcber1")

    released = await store.delete_site("dcber1")
    assert released.groups == ["edge"]
    assert released.locations == [("unifi1", "default")]
    assert released.devices == ["dev:a"]

    assert await store.get_site("dcber1") is None
    assert (await store.get_source("edge")).config["site_code"] == ""
    assert [loc.site for loc in await store.list_reported_locations()] == [None]
    assert await store.device_sites() == {}
    assert await store.delete_site("dcber1") is None


# --- AI conversations ----------------------------------------------------------------


async def _turn(store, user_id, conversation_id=None, *, owner="proc-a", at=NOW):
    """Start a turn and claim it, as the runner does at acceptance."""
    reply = await store.start_turn(
        user_id, conversation_id, "which path?", {"route": "/trace"}, at, per_user_cap=2, global_cap=16
    )
    assert await store.claim_turn(reply.id, owner, 60, at)
    return reply


async def _step(store, message_id, result="3 paths", at=NOW):
    return await store.append_step(message_id, "trace_path", 1, {"src": "10.0.0.1"}, False, result, at, 12)


async def _rows(store, table: str, conversation_id: str) -> int:
    """Rows of one conversation table that belong to `conversation_id`."""
    if isinstance(store, FakeStore):
        rows = {
            "ai_conversations": [c.id for c in store.ai_conversations.values()],
            "ai_messages": [m.conversation_id for m in store.ai_messages.values()],
            "ai_steps": [s.conversation_id for s in store.ai_steps.values()],
            "ai_links": [link.conversation_id for link in store.ai_links],
        }[table]
        return rows.count(conversation_id)
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine

    t = metadata.tables[table]
    column = t.c.id if table == "ai_conversations" else t.c.conversation_id
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as c:
            return await c.scalar(sa.select(sa.func.count()).select_from(t).where(column == conversation_id))
    finally:
        await engine.dispose()


async def test_a_conversation_is_invisible_to_another_user(store):
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    c = await store.create_conversation(ada.id, "drawer", NOW, title="paths")

    assert (await store.get_conversation(ada.id, c.id)).title == "paths"
    assert await store.get_conversation(bob.id, c.id) is None
    assert await store.get_conversation(ada.id, str(uuid.uuid4())) is None
    assert await store.get_conversation(ada.id, "not-a-uuid") is None
    assert await store.delete_conversation(bob.id, c.id) is False
    assert await store.start_turn(bob.id, c.id, "q", None, NOW, per_user_cap=2, global_cap=16) is None
    reply = await store.start_turn(ada.id, c.id, "q", None, NOW, per_user_cap=2, global_cap=16)
    assert await store.request_cancel(bob.id, reply.id) is False
    assert await store.request_cancel(ada.id, reply.id) is True
    assert (await store.get_conversation(ada.id, c.id)).messages[-1].cancel_requested is True


async def test_get_message_answers_only_the_owner_and_the_surface(store):
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    reply = await store.start_turn(
        ada.id, None, "q", None, NOW, per_user_cap=2, global_cap=16, surface="assessment_draft"
    )

    message = await store.get_message(ada.id, reply.id)
    assert (message.id, message.role, message.status) == (reply.id, "assistant", "pending")
    assert (await store.get_message(ada.id, reply.id, surface="assessment_draft")).id == reply.id
    assert await store.get_message(ada.id, reply.id, surface="drawer") is None
    assert await store.get_message(bob.id, reply.id) is None
    assert await store.get_message(ada.id, str(uuid.uuid4())) is None
    assert await store.get_message(ada.id, "not-a-uuid") is None

    assert await store.claim_turn(reply.id, "p1", 60, NOW)
    assert await store.finish_turn(reply.id, "p1", "done", NOW, envelope={"payload": {"ready": False}})
    done = await store.get_message(ada.id, reply.id)
    assert (done.status, done.envelope) == ("done", {"payload": {"ready": False}})


async def test_list_conversations_excludes_ephemeral_rows_and_filters(store):
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    older = await store.create_conversation(ada.id, "drawer", NOW)
    newer = await store.create_conversation(ada.id, "changesim", NOW + timedelta(minutes=1))
    await store.create_conversation(ada.id, "drawer", NOW + timedelta(minutes=2), ephemeral=True)
    await store.create_conversation(bob.id, "drawer", NOW)
    shim = await store.start_turn(ada.id, None, "legacy ask", None, NOW, per_user_cap=2, global_cap=16)
    await store.add_link(older.id, "assessment", "as-1", "from", NOW, ref_revision=3)

    assert [c.id for c in await store.list_conversations(ada.id)] == [newer.id, older.id]
    assert [c.id for c in await store.list_conversations(ada.id, surface="changesim")] == [newer.id]
    linked = await store.list_conversations(ada.id, link_kind="assessment", link_id="as-1")
    assert [c.id for c in linked] == [older.id]
    assert await store.list_conversations(ada.id, link_kind="assessment", link_id="as-2") == []
    assert [c.id for c in await store.list_conversations(ada.id, limit=1)] == [newer.id]

    # the shim turn made an ephemeral drawer conversation holding both messages
    ephemeral = await store.get_conversation(ada.id, shim.conversation_id)
    assert (ephemeral.ephemeral, ephemeral.surface, ephemeral.message_count) == (True, "drawer", 2)
    assert [(m.seq, m.role, m.status) for m in ephemeral.messages] == [
        (1, "user", "done"),
        (2, "assistant", "pending"),
    ]
    assert ephemeral.messages[0].content == "legacy ask"


async def test_list_conversations_titles_an_untitled_conversation_and_names_its_last_run(store):
    ada = await store.create_user("ada", "h", "operator")
    untitled = await store.create_conversation(ada.id, "drawer", NOW)
    titled = await store.create_conversation(ada.id, "drawer", NOW, title="paths")
    empty = await store.create_conversation(ada.id, "drawer", NOW)
    first = await store.start_turn(ada.id, untitled.id, "x" * 250, None, NOW, per_user_cap=4, global_cap=16)
    assert await store.claim_turn(first.id, "proc-a", 60, NOW)
    assert await store.finish_turn(first.id, "proc-a", "done", NOW, content="a", snapshot_id="1759")
    second = await store.start_turn(
        ada.id, untitled.id, "and then?", None, NOW + timedelta(seconds=1), per_user_cap=4, global_cap=16
    )
    assert await store.claim_turn(second.id, "proc-a", 60, NOW)
    assert await store.finish_turn(second.id, "proc-a", "error", NOW, error="failed")
    await store.start_turn(ada.id, titled.id, "which path?", None, NOW, per_user_cap=4, global_cap=16)

    listed = {c.id: c for c in await store.list_conversations(ada.id)}
    # the run of the newest answer that names one
    assert (listed[untitled.id].title, listed[untitled.id].last_run) == ("x" * LIST_TITLE_CHARS, "1759")
    assert (listed[titled.id].title, listed[titled.id].last_run) == ("paths", None)
    assert (listed[empty.id].title, listed[empty.id].last_run) == ("", None)
    # the stored title is unchanged
    assert (await store.get_conversation(ada.id, untitled.id)).title == ""


async def test_step_labels_run_per_conversation_and_never_repeat(store):
    ada = await store.create_user("ada", "h", "operator")
    first = await store.create_conversation(ada.id, "drawer", NOW)
    second = await store.create_conversation(ada.id, "drawer", NOW)

    turn1 = await _turn(store, ada.id, first.id)
    other = await _turn(store, ada.id, second.id)
    assert [(await _step(store, turn1.id)).label for _ in range(3)] == [1, 2, 3]
    assert (await _step(store, other.id)).label == 1
    assert await store.finish_turn(turn1.id, "proc-a", "done", NOW, content="answer")

    turn2 = await _turn(store, ada.id, first.id)
    assert (await _step(store, turn2.id)).label == 4
    assert await store.compact_steps(NOW + timedelta(seconds=1), NOW) == 5
    assert (await _step(store, turn2.id)).label == 5

    conversation = await store.get_conversation(ada.id, first.id)
    assert [s.label for s in conversation.steps] == [1, 2, 3, 4, 5]
    assert conversation.step_count == 5
    assert [m.seq for m in conversation.messages] == [1, 2, 3, 4]
    with pytest.raises(KeyError):
        await _step(store, str(uuid.uuid4()))


async def test_a_turn_runs_through_its_lease_and_finishes_once(store):
    ada = await store.create_user("ada", "h", "operator")
    reply = await store.start_turn(ada.id, None, "q", None, NOW, per_user_cap=2, global_cap=16)
    assert reply.status == "pending"
    assert await store.heartbeat_turn(reply.id, "proc-a", 60, NOW) is False
    assert await store.claim_turn(reply.id, "proc-a", 60, NOW) is True
    assert await store.claim_turn(reply.id, "proc-b", 60, NOW) is False
    assert await store.heartbeat_turn(reply.id, "proc-b", 60, NOW) is False
    assert await store.heartbeat_turn(reply.id, "proc-a", 60, NOW + timedelta(seconds=20)) is True
    assert await store.finish_turn(reply.id, "proc-b", "done", NOW) is False
    with pytest.raises(ValueError):
        await store.finish_turn(reply.id, "proc-a", "interrupted", NOW)

    done_at = NOW + timedelta(seconds=30)
    assert await store.finish_turn(
        reply.id,
        "proc-a",
        "done",
        done_at,
        content="two paths",
        envelope={"claims": []},
        snapshot_id="1759000000",
        provider="anthropic",
        model_served="m-1",
        usage={"input_tokens": 10, "output_tokens": 2},
    )
    assert await store.finish_turn(reply.id, "proc-a", "error", done_at) is False
    assert await store.request_cancel(ada.id, reply.id) is False

    conversation = await store.get_conversation(ada.id, reply.conversation_id)
    answer = conversation.messages[1]
    assert (answer.status, answer.content, answer.lease_expires_at, answer.finished_at) == (
        "done",
        "two paths",
        None,
        done_at,
    )
    assert (answer.envelope, answer.usage, answer.snapshot_id, answer.lease_owner) == (
        {"claims": []},
        {"input_tokens": 10, "output_tokens": 2},
        "1759000000",
        "proc-a",
    )
    assert conversation.last_message_at == done_at


async def test_start_turn_refuses_at_the_per_user_cap_then_the_global_cap(store):
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    for _ in range(2):
        await store.start_turn(ada.id, None, "q", None, NOW, per_user_cap=2, global_cap=3)
    with pytest.raises(TurnCapExceeded) as refused:
        await store.start_turn(ada.id, None, "q", None, NOW, per_user_cap=2, global_cap=3)
    assert refused.value.scope == "user"

    await store.start_turn(bob.id, None, "q", None, NOW, per_user_cap=2, global_cap=3)
    with pytest.raises(TurnCapExceeded) as refused:
        await store.start_turn(bob.id, None, "q", None, NOW, per_user_cap=2, global_cap=3)
    assert refused.value.scope == "global"


async def test_stale_turns_are_marked_interrupted_and_keep_their_steps(store):
    ada = await store.create_user("ada", "h", "operator")
    lapsed = await _turn(store, ada.id)
    await _step(store, lapsed.id)
    live = await _turn(store, ada.id)
    assert await store.heartbeat_turn(live.id, "proc-a", 60, NOW + timedelta(seconds=50))
    assert await store.finish_turn(live.id, "proc-a", "done", NOW + timedelta(seconds=55))
    unclaimed = await store.start_turn(ada.id, None, "q", None, NOW, per_user_cap=16, global_cap=16)
    later = NOW + timedelta(seconds=30)
    fresh = await store.start_turn(ada.id, None, "q", None, later, per_user_cap=16, global_cap=16)

    assert await store.expire_stale_turns(NOW + timedelta(seconds=61)) == 2
    assert await store.expire_stale_turns(NOW + timedelta(seconds=61)) == 0

    turns = [
        await store.get_conversation(ada.id, m.conversation_id) for m in (lapsed, live, unclaimed, fresh)
    ]
    assert [t.messages[-1].status for t in turns] == ["interrupted", "done", "interrupted", "pending"]
    assert len(turns[0].steps) == 1
    assert await store.finish_turn(lapsed.id, "proc-a", "done", NOW + timedelta(seconds=62)) is False


async def test_compact_steps_drops_the_result_and_keeps_the_digest(store):
    ada = await store.create_user("ada", "h", "operator")
    reply = await _turn(store, ada.id)
    old = await store.append_step(
        reply.id,
        "trace_path",
        1,
        {},
        False,
        "old result",
        NOW - timedelta(days=15),
        5,
        result_summary="2 paths",
    )
    new = await _step(store, reply.id, "new result", NOW)
    assert (old.result_sha256, old.result_chars) == (hashlib.sha256(b"old result").hexdigest(), 10)

    assert await store.compact_steps(NOW - timedelta(days=14), NOW) == 1
    assert await store.compact_steps(NOW - timedelta(days=14), NOW) == 0
    steps = {s.id: s for s in (await store.get_conversation(ada.id, reply.conversation_id)).steps}
    assert (steps[old.id].result, steps[old.id].result_sha256, steps[old.id].result_chars) == (
        None,
        old.result_sha256,
        10,
    )
    assert (steps[old.id].result_summary, steps[old.id].compacted_at) == ("2 paths", NOW)
    assert (steps[new.id].result, steps[new.id].compacted_at) == ("new result", None)


async def test_get_turn_and_get_step_answer_only_the_owner(store):
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    reply = await _turn(store, ada.id)
    first = await _step(store, reply.id, "one")
    second = await _step(store, reply.id, "two")

    turn = await store.get_turn(ada.id, reply.id)
    assert (turn.message.id, turn.question.role, turn.question.content) == (reply.id, "user", "which path?")
    assert turn.question.context == {"route": "/trace"}
    assert [s.id for s in turn.steps] == [first.id, second.id]
    assert await store.get_turn(ada.id, turn.question.id) is None
    assert await store.get_turn(bob.id, reply.id) is None
    assert await store.get_turn(ada.id, "not-a-uuid") is None

    assert (await store.get_step(ada.id, second.id)).result == "two"
    assert await store.get_step(bob.id, second.id) is None
    assert await store.get_step(ada.id, str(uuid.uuid4())) is None


async def test_set_question_context_writes_the_user_row_of_the_turn(store):
    ada = await store.create_user("ada", "h", "operator")
    reply = await _turn(store, ada.id)
    stored = {"page_context": {"version": 1}, "block": "<page_context/>", "snapshot": "1759"}

    assert await store.set_question_context(reply.id, stored) is True
    turn = await store.get_turn(ada.id, reply.id)
    assert turn.question.context == stored
    assert turn.message.context is None
    assert await store.set_question_context(turn.question.id, {"x": 1}) is False
    assert await store.set_question_context(str(uuid.uuid4()), {"x": 1}) is False
    assert await store.set_question_context("not-a-uuid", {"x": 1}) is False


async def test_set_summary_moves_forward_only_for_the_owner(store):
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    c = await store.create_conversation(ada.id, "drawer", NOW)

    assert await store.set_summary(ada.id, c.id, "turns 1 to 2", 4) is True
    assert await store.set_summary(ada.id, c.id, "turn 1", 2) is False
    assert await store.set_summary(bob.id, c.id, "theirs", 6) is False
    stored = await store.get_conversation(ada.id, c.id)
    assert (stored.summary, stored.summary_through) == ("turns 1 to 2", 4)


async def test_deleting_a_conversation_takes_its_messages_steps_and_links(store):
    ada = await store.create_user("ada", "h", "operator")
    kept = await store.create_conversation(ada.id, "drawer", NOW)
    await store.add_link(kept.id, "change", "7", "to", NOW)
    reply = await _turn(store, ada.id)
    step = await _step(store, reply.id)
    await store.add_link(
        reply.conversation_id, "step", step.id, "to", NOW, message_id=reply.id, step_id=step.id
    )

    assert await store.delete_conversation(ada.id, reply.conversation_id) is True
    assert await store.delete_conversation(ada.id, reply.conversation_id) is False
    assert await store.get_conversation(ada.id, reply.conversation_id) is None
    assert (await store.get_conversation(ada.id, kept.id)).links[0].ref_id == "7"
    for table in ("ai_conversations", "ai_messages", "ai_steps", "ai_links"):
        assert await _rows(store, table, reply.conversation_id) == 0


async def test_conversations_are_purged_by_last_message_and_ephemeral_ones_sooner(store):
    ada = await store.create_user("ada", "h", "operator")
    stale = await store.create_conversation(ada.id, "drawer", NOW - timedelta(days=91))
    kept = await store.create_conversation(ada.id, "drawer", NOW - timedelta(days=2))
    shim_old = await store.create_conversation(ada.id, "drawer", NOW - timedelta(hours=25), ephemeral=True)
    shim_new = await store.create_conversation(ada.id, "drawer", NOW - timedelta(hours=1), ephemeral=True)

    assert await store.purge_ephemeral(NOW - timedelta(hours=24)) == 1
    assert await store.purge_conversations(NOW - timedelta(days=90)) == 1
    present = [await store.get_conversation(ada.id, c.id) for c in (stale, kept, shim_old, shim_new)]
    assert [c is not None for c in present] == [False, True, False, True]


async def test_deleting_a_user_deletes_their_conversations(store):
    if not isinstance(store, PgStore):
        pytest.skip("FK ON DELETE CASCADE on users cannot be expressed by FakeStore")
    from sqlalchemy.ext.asyncio import create_async_engine

    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    reply = await _turn(store, ada.id)
    await _step(store, reply.id)
    theirs = await store.create_conversation(bob.id, "drawer", NOW)
    # the app never deletes users; this reaches around the store as the
    # login_events test above does
    engine = create_async_engine(DSN)
    try:
        async with engine.begin() as c:
            await c.execute(users.delete().where(users.c.id == ada.id))
    finally:
        await engine.dispose()

    for table in ("ai_conversations", "ai_messages", "ai_steps"):
        assert await _rows(store, table, reply.conversation_id) == 0
    assert await store.get_conversation(bob.id, theirs.id) is not None


async def test_get_turn_progress_reads_the_status_and_the_steps_above_a_label(store):
    ada = await store.create_user("ada", "h", "operator")
    bob = await store.create_user("bob", "h", "operator")
    reply = await _turn(store, ada.id)
    first = await _step(store, reply.id, "one")
    second = await _step(store, reply.id, "two")

    progress = await store.get_turn_progress(ada.id, reply.id, 0)
    assert (progress.status, [s.id for s in progress.steps]) == ("running", [first.id, second.id])
    progress = await store.get_turn_progress(ada.id, reply.id, first.label)
    assert [(s.id, s.result) for s in progress.steps] == [(second.id, "two")]
    assert (await store.get_turn_progress(ada.id, reply.id, second.label)).steps == []

    assert await store.finish_turn(reply.id, "proc-a", "done", NOW, content="answer")
    assert (await store.get_turn_progress(ada.id, reply.id, second.label)).status == "done"
    question = (await store.get_turn(ada.id, reply.id)).question
    assert await store.get_turn_progress(ada.id, question.id, 0) is None
    assert await store.get_turn_progress(bob.id, reply.id, 0) is None
    assert await store.get_turn_progress(ada.id, "not-a-uuid", 0) is None


async def test_add_link_treats_a_bad_or_foreign_id_as_missing(store):
    ada = await store.create_user("ada", "h", "operator")
    reply = await _turn(store, ada.id)
    step = await _step(store, reply.id)
    other = await _turn(store, ada.id)
    other_step = await _step(store, other.id)
    cid = reply.conversation_id

    link = await store.add_link(cid.upper(), "step", step.id, "to", NOW, message_id=reply.id, step_id=step.id)
    assert (link.conversation_id, link.message_id, link.step_id) == (cid, reply.id, step.id)
    assert await store.add_link("not-a-uuid", "change", "7", "to", NOW) is None
    assert await store.add_link(str(uuid.uuid4()), "change", "7", "to", NOW) is None
    assert await store.add_link(cid, "change", "7", "to", NOW, message_id="not-a-uuid") is None
    assert await store.add_link(cid, "change", "7", "to", NOW, message_id=other.id) is None
    assert await store.add_link(cid, "change", "7", "to", NOW, step_id=other_step.id) is None
    assert await store.add_link(cid, "change", "7", "to", NOW, step_id=str(uuid.uuid4())) is None
    assert [link.ref_id for link in (await store.get_conversation(ada.id, cid)).links] == [step.id]


async def test_an_ai_event_without_detail_stores_sql_null(store):
    if not isinstance(store, PgStore):
        pytest.skip("SQL NULL and JSON null differ only in Postgres")
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import ai_events

    await store.record_ai_event(AiEvent(at=NOW, origin="web", event="tool.call", outcome="ok"))
    await store.record_ai_event(
        AiEvent(at=NOW, origin="web", event="tool.call", outcome="ok", detail={"n": 1})
    )
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as c:
            empty = await c.scalar(
                sa.select(sa.func.count()).select_from(ai_events).where(ai_events.c.detail.is_(None))
            )
    finally:
        await engine.dispose()
    assert empty == 1
    assert sorted(str(e.detail) for e in await store.list_ai_events()) == ["None", "{'n': 1}"]


async def test_a_network_map_layout_saves_by_revision(store):
    from hst.app.store import StaleMapRevision

    assert await store.get_network_map_layout("site/ber1") is None
    first = await store.save_network_map_layout(
        "site/ber1", {"dev:a": {"x": 1.0, "y": 2.0}}, expected_revision=0, user_id=None, now=NOW
    )
    assert first.revision == 1
    with pytest.raises(StaleMapRevision):
        await store.save_network_map_layout("site/ber1", {}, expected_revision=0, user_id=None, now=NOW)
    second = await store.save_network_map_layout(
        "site/ber1", {"dev:a": {"x": 3.0, "y": 2.0}}, expected_revision=1, user_id=None, now=NOW
    )
    assert second.revision == 2
    got = await store.get_network_map_layout("site/ber1")
    assert got is not None and got.positions == {"dev:a": {"x": 3.0, "y": 2.0}}
    with pytest.raises(StaleMapRevision):
        await store.delete_network_map_layout("site/ber1", expected_revision=1)
    assert await store.delete_network_map_layout("site/ber1", expected_revision=2) is True
    assert await store.delete_network_map_layout("site/ber1", expected_revision=2) is False


async def test_network_map_views_are_unique_by_name_and_revised(store):
    from hst.app.store import MapViewNameTaken, StaleMapRevision

    u = await store.create_user("mapper", "h", "operator")
    a = await store.create_network_map_view("core", {"site": "ber1"}, owner_id=u.id, now=NOW)
    b = await store.create_network_map_view("edge", {}, owner_id=None, now=NOW)
    with pytest.raises(MapViewNameTaken):
        await store.create_network_map_view("core", {}, owner_id=None, now=NOW)
    with pytest.raises(MapViewNameTaken):
        await store.update_network_map_view(b.id, expected_revision=1, now=NOW, name="core")
    updated = await store.update_network_map_view(a.id, expected_revision=1, now=NOW, state={"site": "ham2"})
    assert updated is not None and (updated.revision, updated.state, updated.name) == (
        2,
        {"site": "ham2"},
        "core",
    )
    with pytest.raises(StaleMapRevision):
        await store.update_network_map_view(a.id, expected_revision=1, now=NOW, name="x")
    assert [v.name for v in await store.list_network_map_views()] == ["core", "edge"]
    assert await store.update_network_map_view(uuid.uuid4(), expected_revision=1, now=NOW) is None
    assert await store.delete_network_map_view(a.id, expected_revision=2) is True
    assert await store.delete_network_map_view(a.id, expected_revision=2) is False


def _add_key(key: str, value: object):
    def change(row):
        row.config[key] = value
        return row

    return change


async def test_modify_source_writes_the_change_and_skips_a_none_change(store):
    await store.create_source("lab", "vyos", {"host": "r1"}, b"blob")
    row = await store.modify_source("lab", _add_key("host_key", "k1"))
    assert (row.config, row.secrets, row.enabled) == ({"host": "r1", "host_key": "k1"}, b"blob", True)
    kept = await store.modify_source("lab", lambda row: None)
    assert kept.config == {"host": "r1", "host_key": "k1"}
    assert await store.modify_source("ghost", _add_key("a", 1)) is None


async def test_modify_source_rolls_back_when_the_change_raises(store):
    await store.create_source("lab", "vyos", {"host": "r1"}, b"")

    def fail(row):
        row.config["host"] = "r2"
        raise ValueError("refused")

    with pytest.raises(ValueError, match="refused"):
        await store.modify_source("lab", fail)
    assert (await store.get_source("lab")).config == {"host": "r1"}


async def test_concurrent_modify_source_calls_keep_every_key(store):
    await store.create_source("lab", "vyos", {}, b"")
    await asyncio.gather(*(store.modify_source("lab", _add_key(f"k{i}", i)) for i in range(8)))
    assert (await store.get_source("lab")).config == {f"k{i}": i for i in range(8)}


async def test_update_site_change_params_merges_into_the_stored_params(store):
    await store.create_site("fra", "Frankfurt", "DE", {"lat": 50.0})
    site = await store.update_site("fra", name="FRA", change_params=lambda p: {**p, "lon": 8.0})
    assert (site.name, site.params) == ("FRA", {"lat": 50.0, "lon": 8.0})
    assert await store.update_site("ghost", change_params=lambda p: p) is None


async def test_concurrent_update_site_change_params_calls_keep_every_key(store):
    await store.create_site("fra", "Frankfurt", "DE", {})

    def add(i: int):
        return lambda p: {**p, f"k{i}": i}

    await asyncio.gather(*(store.update_site("fra", change_params=add(i)) for i in range(8)))
    assert (await store.get_site("fra")).params == {f"k{i}": i for i in range(8)}


async def test_modify_setting_creates_merges_and_skips_a_none_change(store):
    created = await store.modify_setting("retention", lambda row: ({"a": 1}, b"s") if row is None else None)
    assert (created.value, created.secrets) == ({"a": 1}, b"s")
    merged = await store.modify_setting("retention", lambda row: ({**row.value, "b": 2}, row.secrets))
    assert (merged.value, merged.secrets) == ({"a": 1, "b": 2}, b"s")
    kept = await store.modify_setting("retention", lambda row: None)
    assert kept.value == {"a": 1, "b": 2}
    assert await store.modify_setting("absent", lambda row: None) is None


async def test_concurrent_modify_setting_calls_keep_every_key_from_no_row(store):
    def add(i: int):
        return lambda row: ({**(row.value if row else {}), f"k{i}": i}, b"")

    await asyncio.gather(*(store.modify_setting("retention", add(i)) for i in range(8)))
    assert (await store.get_setting("retention")).value == {f"k{i}": i for i in range(8)}


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_pg_modify_source_waits_for_a_row_lock_and_reads_the_committed_config():
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import sources

    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    st = PgStore(DSN)
    try:
        await st.create_source("lab", "vyos", {"host": "r1", "host_key": ""}, b"")
        async with engine.begin() as other:
            await other.execute(
                sa.select(sources.c.id).where(sources.c.name == "lab").with_for_update(key_share=True)
            )
            pin = asyncio.create_task(st.modify_source("lab", _add_key("host_key", "k1")))
            await asyncio.sleep(0.5)
            assert not pin.done()
            await other.execute(
                sources.update().where(sources.c.name == "lab").values(config={"host": "r2", "host_key": ""})
            )
        row = await pin
        assert row.config == {"host": "r2", "host_key": "k1"}
    finally:
        await st.dispose()
        await engine.dispose()


@pytest.mark.pg
@pytest.mark.skipif(not DSN, reason="HST_TEST_PG_DSN not set")
async def test_pg_modify_setting_waits_for_an_insert_of_the_same_key():
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import create_async_engine

    from hst.app.store.pg import SETTING_LOCK_CLASS, app_settings

    await asyncio.to_thread(upgrade_to_head, DSN)
    engine = create_async_engine(DSN)
    async with engine.begin() as conn:
        for table in reversed(metadata.sorted_tables):
            await conn.execute(table.delete())
    st = PgStore(DSN)
    try:
        async with engine.begin() as other:
            await other.execute(
                sa.text("SELECT pg_advisory_xact_lock(:c, hashtext(:k))"),
                {"c": SETTING_LOCK_CLASS, "k": "retention"},
            )
            task = asyncio.create_task(
                st.modify_setting("retention", lambda row: ({**(row.value if row else {}), "b": 2}, b""))
            )
            await asyncio.sleep(0.5)
            assert not task.done()
            await other.execute(
                app_settings.insert().values(key="retention", value={"a": 1}, secrets=b"", updated_at=NOW)
            )
        saved = await task
        assert saved.value == {"a": 1, "b": 2}
    finally:
        await st.dispose()
        await engine.dispose()
