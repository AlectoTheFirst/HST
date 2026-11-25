"""Login, sessions, CSRF and roles of the auth surface, against the in-memory store."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from tests.app.conftest import PASSWORD, login

from hst import __version__


async def test_login_sets_cookie_and_me_reports_role(client):
    r = await login(client, "otto")
    assert r.json() == {"username": "otto", "role": "operator"}
    cookie = r.headers["set-cookie"]
    assert "hst_session=" in cookie
    assert "httponly" in cookie.lower() and "samesite=lax" in cookie.lower()
    me = await client.get("/api/me")
    assert me.status_code == 200 and me.json()["role"] == "operator"


async def test_bad_password_unknown_user_and_disabled_are_all_401(client, seeded):
    r = await client.post("/api/login", json={"username": "otto", "password": "wrong"})
    assert r.status_code == 401
    r = await client.post("/api/login", json={"username": "ghost", "password": PASSWORD})
    assert r.status_code == 401
    u = await seeded.get_user_by_username("vera")
    await seeded.update_user(u.id, disabled=True)
    r = await client.post("/api/login", json={"username": "vera", "password": PASSWORD})
    assert r.status_code == 401


async def test_login_rate_limited(client):
    for _ in range(5):
        await client.post("/api/login", json={"username": "otto", "password": "wrong"})
    r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    assert r.status_code == 429


async def test_login_rate_limited_per_ip_across_usernames(client):
    # same client (same IP), five different unknown usernames: no per-user bucket trips,
    # but the shared per-IP bucket does
    for i in range(5):
        await client.post("/api/login", json={"username": f"ghost{i}", "password": "wrong"})
    r = await client.post("/api/login", json={"username": "ghost5", "password": "wrong"})
    assert r.status_code == 429


async def test_csrf_header_required_on_posts(app):
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as bare:
        r = await bare.post("/api/login", json={"username": "otto", "password": PASSWORD})
        assert r.status_code == 403 and "CSRF" in r.json()["error"]
        assert (await bare.get("/api/health")).status_code in (200, 401)  # GETs pass through


async def test_logout_kills_the_session(client):
    await login(client, "vera")
    assert (await client.get("/api/me")).status_code == 200
    assert (await client.post("/api/logout")).status_code == 204
    assert (await client.get("/api/me")).status_code == 401


async def test_logout_is_idempotent_without_a_session(client, seeded):
    assert (await client.post("/api/logout")).status_code == 204  # never logged in

    await login(client, "vera")
    seeded.sessions.clear()  # the row expired, or an admin revoked it
    r = await client.post("/api/logout")
    assert r.status_code == 204
    assert "hst_session=" in r.headers["set-cookie"]  # cleared regardless
    assert (await client.post("/api/logout")).status_code == 204  # and again


async def test_disabled_mid_session_is_locked_out(client, seeded):
    await login(client, "vera")
    u = await seeded.get_user_by_username("vera")
    await seeded.update_user(u.id, disabled=True)
    assert (await client.get("/api/me")).status_code == 401


# --- idle session expiry ----------------------------------------------------


def _session_key(client):
    """The store key for the cookie this client is carrying."""
    from hst.app import security

    return security.token_hash(client.cookies["hst_session"])


async def test_a_session_idle_past_the_timeout_stops_authenticating(client, seeded):
    await login(client, "vera")
    tok = _session_key(client)
    user_id, expires_at, _ = seeded.sessions[tok]
    assert expires_at > datetime.now(UTC) + timedelta(hours=100)  # absolute TTL untouched

    seeded.sessions[tok] = (user_id, expires_at, datetime.now(UTC) - timedelta(hours=9))
    assert (await client.get("/api/me")).status_code == 401
    assert tok not in seeded.sessions  # the lookup deleted the dead row on sight


async def test_a_session_used_inside_the_window_stays_alive(client, seeded):
    await login(client, "vera")
    tok = _session_key(client)
    user_id, expires_at, _ = seeded.sessions[tok]

    seeded.sessions[tok] = (user_id, expires_at, datetime.now(UTC) - timedelta(hours=7))
    assert (await client.get("/api/me")).status_code == 200
    # accepted, and the idle clock moved forward: the next seven hours start now
    assert seeded.sessions[tok][2] > datetime.now(UTC) - timedelta(minutes=1)


async def test_the_last_use_mark_is_not_written_on_every_request(client, seeded):
    await login(client, "vera")
    tok = _session_key(client)
    before = seeded.sessions[tok][2]

    for _ in range(5):
        assert (await client.get("/api/me")).status_code == 200
    assert seeded.sessions[tok][2] == before


async def test_health_reports_backends_and_requires_auth(client, monkeypatch):
    assert (await client.get("/api/health")).status_code == 401
    await login(client, "vera")
    import hst.app.routes.health as health

    monkeypatch.setattr(health, "_neo4j_ok", lambda settings: False)
    body = (await client.get("/api/health")).json()
    # `agent` is false until a provider is configured
    assert {k: body[k] for k in ("path", "neo4j", "postgres", "agent")} == {
        "path": True,
        "neo4j": False,
        "postgres": True,
        "agent": False,
    }
    # The build identity is "unknown" outside a container and the git SHA inside one.
    assert body["version"] == __version__
    assert body["revision"] == "unknown"


async def test_unknown_user_login_does_no_fresh_hashing(client, monkeypatch):
    import hst.app.auth as auth

    def boom(password):
        raise AssertionError("hash_password should not run per unknown-user attempt")

    monkeypatch.setattr(auth.security, "hash_password", boom)
    r = await client.post("/api/login", json={"username": "ghost", "password": "whatever"})
    assert r.status_code == 401


async def test_null_hash_user_cannot_authenticate_by_password(client, seeded, monkeypatch):
    """An SSO-provisioned account (password_hash IS NULL) must never authenticate by
    password, and the refusal must be indistinguishable from a wrong password: same
    401, same limiter behavior and the same burner-hash verify as an unknown user."""
    import hst.app.auth as auth

    # a JIT-provisioned SSO account: password_hash is NULL from creation
    await seeded.create_user("sso-otto", None, "operator")
    assert (await seeded.get_user_by_username("sso-otto")).password_hash is None

    calls = []
    real_verify = auth.security.verify_password

    def spy(hashed, password):
        calls.append(hashed)
        return real_verify(hashed, password)

    monkeypatch.setattr(auth.security, "verify_password", spy)
    r = await client.post("/api/login", json={"username": "sso-otto", "password": "anything-goes-9"})

    assert r.status_code == 401
    # the burner hash ran
    assert calls == [auth._BURNER_HASH]


async def test_login_disabled_never_looks_up_the_username(client, app, monkeypatch):
    """The toggle check runs before the store lookup."""
    import hst.app.auth as auth

    async def local_login_off(store):
        return False

    monkeypatch.setattr(auth.sso_flow, "local_login_enabled", local_login_off)

    async def boom(username):
        raise AssertionError("get_user_by_username must not run while local login is off")

    monkeypatch.setattr(app.state.store, "get_user_by_username", boom)

    r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    assert r.status_code == 401


async def test_login_disabled_keeps_the_unknown_user_timing_path(client, monkeypatch):
    """Same burner-hash verify as an unknown username: no branch on the
    toggle past the initial check."""
    import hst.app.auth as auth

    async def local_login_off(store):
        return False

    monkeypatch.setattr(auth.sso_flow, "local_login_enabled", local_login_off)

    calls = []
    real_verify = auth.security.verify_password

    def verify_spy(hashed, password):
        calls.append(hashed)
        return real_verify(hashed, password)

    monkeypatch.setattr(auth.security, "verify_password", verify_spy)

    r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    assert r.status_code == 401
    assert calls == [auth._BURNER_HASH]


async def test_login_disabled_consumes_rate_limit_budget_on_failure(client, monkeypatch):
    """The toggle-off refusal must not consume rate-limit budget differently
    than a wrong password: same buckets, same accounting."""
    import hst.app.auth as auth

    async def local_login_off(store):
        return False

    monkeypatch.setattr(auth.sso_flow, "local_login_enabled", local_login_off)

    for _ in range(5):
        r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
        assert r.status_code == 401
    r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    assert r.status_code == 429


async def test_validation_errors_use_the_error_shape(client):
    r = await client.post("/api/login", json={"username": "x"})
    assert r.status_code == 422
    body = r.json()
    assert "error" in body
    assert "detail" not in body


async def test_successful_logins_do_not_consume_the_failure_budget(client):
    for _ in range(10):
        r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
        assert r.status_code == 200
    final = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    assert final.status_code == 200


async def test_one_ip_cannot_lock_a_known_account_out_of_another_ip(app):
    """The strict bucket is keyed on the username and the client address."""
    import httpx

    async def attempt(ip: str, password: str) -> int:
        transport = httpx.ASGITransport(app=app, client=(ip, 12345))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}
        ) as c:
            r = await c.post("/api/login", json={"username": "otto", "password": password})
            return r.status_code

    for _ in range(6):
        await attempt("10.0.0.9", "wrong")
    assert await attempt("10.0.0.9", "wrong") == 429  # the attacker is stopped
    assert await attempt("10.0.0.1", PASSWORD) == 200  # the real user is not


async def test_a_username_that_holds_an_address_does_not_fill_the_bucket_of_that_user_and_address(app):
    import httpx

    async def attempt(address: str, username: str, password: str) -> int:
        transport = httpx.ASGITransport(app=app, client=(address, 12345))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}
        ) as c:
            r = await c.post("/api/login", json={"username": username, "password": password})
            return r.status_code

    for i in range(app.state.limiter.limit):
        assert await attempt(f"10.0.9.{i}", "otto:10.0.0.1", "wrong") == 401

    assert await attempt("10.0.0.1", "otto", PASSWORD) == 200


async def test_limiter_keys_are_tuples_of_the_bucket_name_and_the_raw_values(app):
    import httpx

    transport = httpx.ASGITransport(app=app, client=("10.0.0.1", 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        await c.post("/api/login", json={"username": "a:b", "password": "wrong"})

    assert set(app.state.limiter._hits) == {
        ("user-ip", "a:b", "10.0.0.1"),
        ("ip", "10.0.0.1"),
        ("user", "a:b"),
    }


@pytest.mark.parametrize(
    "body",
    [
        {"username": "o" * 65, "password": PASSWORD},
        {"username": "", "password": PASSWORD},
        {"username": "otto", "password": "p" * 1025},
    ],
    ids=["long-username", "empty-username", "long-password"],
)
async def test_login_refuses_a_field_outside_its_bounds_before_the_verification(
    client, app, seeded, monkeypatch, body
):
    calls = _count_verifications(monkeypatch)

    r = await client.post("/api/login", json=body)

    assert r.status_code == 422
    assert calls == []
    assert app.state.limiter._hits == {}
    assert await seeded.list_login_events() == []


async def test_login_verifies_a_username_and_a_password_at_their_bounds(client, monkeypatch):
    calls = _count_verifications(monkeypatch)

    r = await client.post("/api/login", json={"username": "o" * 64, "password": "p" * 1024})

    assert r.status_code == 401
    assert len(calls) == 1


async def test_user_create_and_patch_refuse_a_password_above_the_bound(client, seeded, monkeypatch):
    import hst.app.routes.users as users_routes

    hashed: list[str] = []
    monkeypatch.setattr(users_routes, "hash_password", lambda password: hashed.append(password) or "h")
    await login(client, "ada")
    vera = await seeded.get_user_by_username("vera")

    created = await client.post(
        "/api/users", json={"username": "nora", "password": "p" * 1025, "role": "viewer"}
    )
    patched = await client.patch(f"/api/users/{vera.id}", json={"password": "p" * 1025})

    assert (created.status_code, patched.status_code) == (422, 422)
    assert hashed == []
    assert await seeded.get_user_by_username("nora") is None


async def test_readyz_is_unauthenticated_and_reports_postgres(client):
    r = await client.get("/api/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_readyz_goes_503_when_the_store_is_unreachable(client, app):
    async def down():
        return False

    app.state.store.ping = down
    r = await client.get("/api/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "unavailable"}


# --- login events -----------------------------------------------------------


async def test_successful_login_records_an_ok_event(client, seeded):
    await login(client, "otto")
    events = await seeded.list_login_events()
    assert len(events) == 1
    e = events[0]
    user = await seeded.get_user_by_username("otto")
    assert (e.username, e.user_id, e.provider, e.outcome) == ("otto", user.id, "local", "ok")


async def test_bad_password_unknown_user_and_disabled_events(client, seeded):
    await client.post("/api/login", json={"username": "otto", "password": "wrong"})
    await client.post("/api/login", json={"username": "ghost", "password": PASSWORD})
    u = await seeded.get_user_by_username("vera")
    await seeded.update_user(u.id, disabled=True)
    await client.post("/api/login", json={"username": "vera", "password": PASSWORD})

    events = await seeded.list_login_events()
    assert len(events) == 3
    by_username = {e.username: e for e in events}
    # a failed attempt records user_id None also for an existing, disabled account:
    # the FK never leaks whether a username exists
    assert (by_username["otto"].outcome, by_username["otto"].user_id) == ("bad_credentials", None)
    assert (by_username["ghost"].outcome, by_username["ghost"].user_id) == ("bad_credentials", None)
    assert (by_username["vera"].outcome, by_username["vera"].user_id) == ("disabled", None)
    assert all(e.provider == "local" for e in events)


async def test_rate_limited_login_records_an_event(client, seeded):
    for _ in range(5):
        await client.post("/api/login", json={"username": "otto", "password": "wrong"})
    await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    events = await seeded.list_login_events()
    assert events[0].outcome == "rate_limited"  # newest first, the 429 attempt


async def test_rate_limited_attempts_record_one_event_per_window(client, seeded):
    for _ in range(5):
        await client.post("/api/login", json={"username": "otto", "password": "wrong"})
    for _ in range(25):
        r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
        assert r.status_code == 429

    events = await seeded.list_login_events()
    assert [e.outcome for e in events].count("rate_limited") == 1
    assert [e.outcome for e in events].count("bad_credentials") == 5


def _count_verifications(monkeypatch) -> list[str]:
    """Replace `verify_password` with a spy and return the list of the hashes it verified."""
    import hst.app.auth as auth

    calls: list[str] = []
    real_verify = auth.security.verify_password

    def spy(hashed, password):
        calls.append(hashed)
        return real_verify(hashed, password)

    monkeypatch.setattr(auth.security, "verify_password", spy)
    return calls


async def test_parallel_failed_logins_verify_at_most_the_limit(client, app, seeded, monkeypatch):
    calls = _count_verifications(monkeypatch)
    limit = app.state.limiter.limit

    responses = await asyncio.gather(
        *(client.post("/api/login", json={"username": "otto", "password": f"wrong-{i}"}) for i in range(50))
    )

    statuses = [r.status_code for r in responses]
    assert len(calls) == limit
    assert statuses.count(401) == limit
    assert statuses.count(429) == 50 - limit
    events = await seeded.list_login_events()
    assert [e.outcome for e in events].count("rate_limited") == 1


async def test_successful_logins_use_no_budget(client, app, monkeypatch):
    limiter = app.state.limiter
    for _ in range(limiter.limit * 3):
        await login(client, "otto")
    assert limiter._hits == {}

    calls = _count_verifications(monkeypatch)
    for _ in range(limiter.limit):
        r = await client.post("/api/login", json={"username": "otto", "password": "wrong"})
        assert r.status_code == 401
    r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    assert r.status_code == 429
    assert len(calls) == limiter.limit


async def test_username_bucket_holds_ten_times_the_limit_across_addresses(app, monkeypatch):
    import httpx

    calls = _count_verifications(monkeypatch)
    limit = app.state.limiter.limit

    async def attempt(address: str) -> int:
        transport = httpx.ASGITransport(app=app, client=(address, 4000))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}
        ) as c:
            r = await c.post("/api/login", json={"username": "otto", "password": "wrong"})
            return r.status_code

    for i in range(10):
        statuses = await asyncio.gather(*(attempt(f"10.0.0.{i}") for _ in range(limit)))
        assert statuses == [401] * limit
    assert await attempt("10.0.0.10") == 429
    assert len(calls) == limit * 10


async def test_store_error_before_the_verification_uses_no_budget(client, app, monkeypatch):
    calls = _count_verifications(monkeypatch)

    async def boom(username):
        raise RuntimeError("store is down")

    monkeypatch.setattr(app.state.store, "get_user_by_username", boom)
    for _ in range(app.state.limiter.limit * 2):
        with pytest.raises(RuntimeError, match="store is down"):
            await client.post("/api/login", json={"username": "otto", "password": PASSWORD})

    assert calls == []
    assert app.state.limiter._hits == {}


async def test_error_in_the_verification_keeps_the_budget(client, app, monkeypatch):
    import hst.app.auth as auth

    calls = []

    def boom(hashed, password):
        calls.append(hashed)
        raise RuntimeError("verification failed to run")

    monkeypatch.setattr(auth.security, "verify_password", boom)
    limit = app.state.limiter.limit
    for _ in range(limit):
        with pytest.raises(RuntimeError, match="verification failed to run"):
            await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})

    assert r.status_code == 429
    assert len(calls) == limit


async def test_local_login_disabled_toggle_records_its_own_outcome(client, seeded, monkeypatch):
    import hst.app.auth as auth

    async def local_login_off(store):
        return False

    monkeypatch.setattr(auth.sso_flow, "local_login_enabled", local_login_off)
    await client.post("/api/login", json={"username": "otto", "password": PASSWORD})

    events = await seeded.list_login_events()
    assert len(events) == 1
    assert events[0].outcome == "local_login_disabled"
    assert events[0].user_id is None
    assert events[0].username == "otto"  # the name as presented, even though it exists


async def test_null_hash_account_login_failure_is_recorded_as_bad_credentials(client, seeded):
    await seeded.create_user("sso-otto", None, "operator")
    await client.post("/api/login", json={"username": "sso-otto", "password": "anything-goes-9"})
    events = await seeded.list_login_events()
    assert len(events) == 1
    assert (events[0].outcome, events[0].user_id) == ("bad_credentials", None)


async def test_login_event_recording_failure_does_not_break_login(client, app, monkeypatch):
    """An audit-trail write failure must never lock anyone out."""

    async def boom(*a, **k):
        raise RuntimeError("store is down")

    monkeypatch.setattr(app.state.store, "record_login_event", boom)
    r = await client.post("/api/login", json={"username": "otto", "password": PASSWORD})
    assert r.status_code == 200
    assert r.json() == {"username": "otto", "role": "operator"}


async def test_livez_stays_backend_blind(client, app):
    async def down():
        return False

    app.state.store.ping = down
    assert (await client.get("/api/livez")).status_code == 200


async def test_me_theme_roundtrip(client):
    await login(client, "vera")
    assert (await client.get("/api/me")).json()["theme"] is None

    r = await client.patch("/api/me", json={"theme": "dracula"})
    assert r.status_code == 200 and r.json()["theme"] == "dracula"
    assert (await client.get("/api/me")).json()["theme"] == "dracula"


async def test_me_theme_rejects_unknown_palette(client):
    await login(client, "vera")
    r = await client.patch("/api/me", json={"theme": "hotdog-stand"})
    assert r.status_code == 400
    r = await client.patch("/api/me", json={})
    assert r.status_code == 400


async def test_me_rejects_a_malformed_body_with_422_not_500(client):
    await login(client, "vera")
    r = await client.patch("/api/me", content=b"{not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 422
    assert "error" in r.json()

    r = await client.patch("/api/me", json={"theme": 7})  # right shape, wrong type
    assert r.status_code == 422


async def test_me_theme_cannot_touch_other_fields(client, seeded):
    """The self-service surface is the theme and nothing else."""
    await login(client, "vera")
    r = await client.patch("/api/me", json={"theme": "nord", "role": "admin", "disabled": True})
    assert r.status_code == 200
    me = (await client.get("/api/me")).json()
    assert me["role"] == "viewer" and me["theme"] == "nord"
