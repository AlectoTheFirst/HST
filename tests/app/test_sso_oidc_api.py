"""OIDC login end to end: authorization redirect, callback, provisioning, and
role resolution, driven through a fake IdP
(oidc_fixtures.py) over httpx.MockTransport. No test here touches the network.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from tests.app.conftest import login
from tests.app.oidc_fixtures import FakeIdp

from hst.app import sso_flow
from hst.app.routes import sso as sso_routes


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


async def _register_provider(client, idp: FakeIdp, monkeypatch, **config_overrides) -> None:
    monkeypatch.setattr(sso_flow, "_transport", lambda: idp.transport())
    await login(client, "ada")
    config = {"issuer": idp.issuer, "client_id": idp.client_id, "groups_claim": "groups"}
    config.update(config_overrides)
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": config, "secret": idp.client_secret},
    )
    assert r.status_code == 201, r.text
    r = await client.patch("/api/settings/auth/providers/okta", json={"enabled": True})
    assert r.status_code == 200, r.text
    await client.post("/api/logout")


async def _start_login(client) -> tuple[str, str]:
    """-> (state, nonce), read off the authorization redirect's query string.
    The state cookie itself is picked up automatically by the client's cookie
    jar (httpx persists Set-Cookie across requests on the same client)."""
    r = await client.get("/api/auth/okta/login")
    assert r.status_code == 302, r.text
    qs = parse_qs(urlsplit(r.headers["location"]).query)
    return qs["state"][0], qs["nonce"][0]


async def _callback(client, state: str, *, code: str = "test-code"):
    return await client.get(f"/api/auth/okta/callback?state={state}&code={code}")


async def test_happy_path_provisions_maps_role_and_stamps_last_login(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch, default_role="viewer")
    provider = await store.get_auth_provider("okta")
    await store.put_group_mapping(provider.id, "engineers", "operator")

    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(
        idp.claims(nonce=nonce, sub="sub-1", email="alice@example.com", groups=["engineers"])
    )
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert "hst_session=" in r.headers["set-cookie"]
    # the transient state cookie is always cleared, success or not
    assert "hst_sso_state=" in r.headers["set-cookie"]

    me = await client.get("/api/me")
    assert me.status_code == 200
    assert me.json() == {
        "username": "alice",
        "role": "operator",
        "permissions": sorted(me.json()["permissions"]),
        "theme": None,
    }
    user = await store.get_user_by_username("alice")
    assert user is not None
    assert user.role == "operator" and user.role_source == "mapped" and user.password_hash is None
    identity = await store.get_identity(provider.id, "sub-1")
    assert identity is not None and identity.email == "alice@example.com"
    assert identity.last_login_at is not None


async def test_username_collision_is_suffixed(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    await store.create_user("alice", None, "viewer")  # occupies the preferred name

    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-2", preferred_username="alice"))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert await store.get_user_by_username("alice2") is not None


async def test_no_email_linking_to_an_existing_local_account(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    local = await store.create_user("carol", "somehash", "operator")

    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(
        idp.claims(nonce=nonce, sub="sub-3", email="carol@example.com", preferred_username="carol-sso")
    )
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/"

    original = await store.get_user_by_username("carol")
    assert original is not None and original.id == local.id and original.password_hash == "somehash"
    new_user = await store.get_user_by_username("carol-sso")
    assert new_user is not None and new_user.id != local.id


async def test_group_mapping_miss_uses_default_role(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch, default_role="viewer")
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, groups=["nobody-maps-this"]))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/"
    user = await store.get_user_by_username("user-1")
    assert user is not None and user.role == "viewer" and user.disabled is False


async def test_default_role_none_creates_a_disabled_account_and_refuses_login(
    client, store, monkeypatch, idp
):
    await _register_provider(client, idp, monkeypatch, default_role="none")
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-locked"))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert "hst_session=" not in r.headers.get("set-cookie", "")
    user = await store.get_user_by_username("sub-locked")
    assert user is not None and user.disabled is True


async def test_disabled_account_is_always_refused_even_with_a_matching_group(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch, default_role="viewer")
    provider = await store.get_auth_provider("okta")
    await store.put_group_mapping(provider.id, "engineers", "operator")

    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-4", groups=["engineers"]))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/"
    user = await store.get_user_by_username("sub-4")
    assert user is not None
    await store.update_user(user.id, disabled=True)  # an admin disables it after provisioning

    state2, nonce2 = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce2, sub="sub-4", groups=["engineers"]))
    r2 = await _callback(client, state2)
    assert r2.status_code == 302 and r2.headers["location"] == "/login?error=sso"


async def test_local_role_source_override_survives_sso_login(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch, default_role="viewer")
    provider = await store.get_auth_provider("okta")
    await store.put_group_mapping(provider.id, "engineers", "operator")

    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-5", groups=["engineers"]))
    await _callback(client, state)
    user = await store.get_user_by_username("sub-5")
    assert user is not None and user.role == "operator"

    # an admin pins the role locally
    await login(client, "ada")
    await client.patch(f"/api/users/{user.id}", json={"role": "admin"})
    await client.post("/api/logout")

    state2, nonce2 = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce2, sub="sub-5", groups=["engineers"]))
    r2 = await _callback(client, state2)
    assert r2.status_code == 302 and r2.headers["location"] == "/"
    unchanged = await store.get_user_by_username("sub-5")
    assert unchanged is not None and unchanged.role == "admin" and unchanged.role_source == "local"


async def test_state_mismatch_is_refused(client, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    _state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce))
    r = await _callback(client, "not-the-real-state")
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_replayed_callback_is_refused(client, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce))
    first = await _callback(client, state)
    assert first.status_code == 302 and first.headers["location"] == "/"
    second = await _callback(client, state)
    assert second.status_code == 302 and second.headers["location"] == "/login?error=sso"


async def test_a_callback_with_the_state_of_another_kind_keeps_the_row(client, store, monkeypatch, idp):
    from datetime import UTC, datetime, timedelta

    await _register_provider(client, idp, monkeypatch)
    provider = await store.get_auth_provider("okta")
    seen = await store.create_auth_state(
        "assertion-1", provider.id, "saml_seen", {}, datetime.now(UTC) + timedelta(minutes=5)
    )

    r = await client.get(
        "/api/auth/okta/callback?state=assertion-1&code=test-code",
        headers={"Cookie": "hst_sso_state=assertion-1"},
    )

    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert store.auth_state["assertion-1"] == seen


@pytest.mark.parametrize("change", ["delete", "disable"])
async def test_a_provider_change_during_the_callback_leaves_no_session(
    client, store, monkeypatch, idp, change
):
    await _register_provider(client, idp, monkeypatch)
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-race"))
    touch_last_login = store.touch_last_login

    async def touch_then_change(identity_id, when):
        """The provider changes after the validation of the ID token and before the session insert."""
        await touch_last_login(identity_id, when)
        if change == "delete":
            await store.delete_auth_provider("okta")
        else:
            await store.update_auth_provider("okta", enabled=False)

    monkeypatch.setattr(store, "touch_last_login", touch_then_change)

    r = await _callback(client, state)

    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert "hst_session=" not in r.headers.get("set-cookie", "")
    assert store.sessions == {}
    assert (await client.get("/api/me")).status_code == 401
    events = [e for e in await store.list_login_events() if e.provider == "okta"]
    assert [(e.username, e.outcome) for e in events] == [("", "failed")]


async def test_a_provider_delete_before_the_account_is_created_refuses_the_login(
    client, store, monkeypatch, idp
):
    await _register_provider(client, idp, monkeypatch)
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-gone"))
    get_identity = store.get_identity

    async def get_then_delete(provider_id, subject):
        found = await get_identity(provider_id, subject)
        await store.delete_auth_provider("okta")
        return found

    monkeypatch.setattr(store, "get_identity", get_then_delete)

    r = await _callback(client, state)

    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert "hst_session=" not in r.headers.get("set-cookie", "")
    assert await store.get_user_by_username("sub-gone") is None
    assert store.sessions == {}


async def test_bad_nonce_is_refused(client, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    state, _nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce="not-the-real-nonce"))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_wrong_audience_is_refused(client, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, aud="someone-elses-client"))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_expired_token_is_refused(client, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, exp=0))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_jwks_key_rotation_is_refreshed_and_retried(client, store, monkeypatch, idp):
    """A kid the cached JWKS doesn't carry (the IdP rotated its signing key
    since the provider was saved) is refetched once and the validation
    retried against the fresh JWKS."""
    await _register_provider(client, idp, monkeypatch)
    idp.rotate_key()

    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-rotated"))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert await store.get_user_by_username("sub-rotated") is not None
    provider = await store.get_auth_provider("okta")
    assert provider.config[sso_flow.JWKS_KEY] == idp.jwks()  # the refresh persisted


async def test_userinfo_supplies_groups_absent_from_the_id_token(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch, default_role="viewer")
    provider = await store.get_auth_provider("okta")
    await store.put_group_mapping(provider.id, "engineers", "operator")
    idp.userinfo_body = {"groups": ["engineers"]}

    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-6"))  # no groups claim
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/"
    user = await store.get_user_by_username("sub-6")
    assert user is not None and user.role == "operator"


async def test_disabled_provider_login_is_not_found(client, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    await login(client, "ada")
    await client.patch("/api/settings/auth/providers/okta", json={"enabled": False})
    await client.post("/api/logout")
    r = await client.get("/api/auth/okta/login")
    assert r.status_code == 404


async def test_unknown_provider_login_is_not_found(client):
    r = await client.get("/api/auth/no-such-provider/login")
    assert r.status_code == 404


# --- login events -----------------------------------------------------------


async def test_login_start_is_429_above_the_limit_of_the_client_address(client, app, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    limit = app.state.limiter.limit * sso_routes.LOGIN_START_LIMIT_FACTOR
    for _ in range(limit):
        assert (await client.get("/api/auth/okta/login")).status_code == 302

    r = await client.get("/api/auth/okta/login")

    assert (r.status_code, r.json()) == (429, {"error": "too many attempts"})
    assert len(store.auth_state) == limit


async def test_a_full_login_start_bucket_leaves_the_password_login_and_other_addresses_alone(
    client, app, monkeypatch, idp
):
    await _register_provider(client, idp, monkeypatch)
    for _ in range(app.state.limiter.limit * sso_routes.LOGIN_START_LIMIT_FACTOR):
        await client.get("/api/auth/no-such-provider/login")
    assert (await client.get("/api/auth/okta/login")).status_code == 429

    await login(client, "ada")
    transport = httpx.ASGITransport(app=app, client=("10.0.0.2", 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as other:
        assert (await other.get("/api/auth/okta/login")).status_code == 302


async def test_successful_oidc_login_records_an_ok_event(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch, default_role="viewer")
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-audit"))
    r = await _callback(client, state)
    assert r.status_code == 302 and r.headers["location"] == "/"

    user = await store.get_user_by_username("sub-audit")
    events = [e for e in await store.list_login_events() if e.provider == "okta"]
    assert len(events) == 1
    assert (events[0].username, events[0].user_id, events[0].outcome) == ("sub-audit", user.id, "ok")


async def test_failed_oidc_callback_records_a_failed_event(client, store, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    _state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce))
    r = await _callback(client, "not-the-real-state")
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"

    events = [e for e in await store.list_login_events() if e.provider == "okta"]
    assert len(events) == 1
    assert (events[0].username, events[0].user_id, events[0].outcome) == ("", None, "failed")


async def test_unknown_provider_callback_records_an_unknown_provider_event(client, store):
    r = await client.get("/api/auth/no-such-provider/callback")
    assert r.status_code == 302

    events = await store.list_login_events()
    assert len(events) == 1
    e = events[0]
    assert (e.username, e.user_id, e.provider, e.outcome) == (
        "",
        None,
        "no-such-provider",
        "unknown_provider",
    )


async def test_saml_provider_login_redirects_with_a_signed_authn_request(client, monkeypatch, idp):
    from tests.app.saml_fixtures import FakeSamlIdp

    monkeypatch.setattr(sso_flow, "_transport", lambda: idp.transport())
    await login(client, "ada")
    saml_idp = FakeSamlIdp()
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": saml_idp.metadata_xml()}},
    )
    assert r.status_code == 201, r.text
    r = await client.patch("/api/settings/auth/providers/adfs", json={"enabled": True})
    assert r.status_code == 200, r.text
    await client.post("/api/logout")
    r = await client.get("/api/auth/adfs/login")
    assert r.status_code == 302
    assert "SAMLRequest=" in r.headers["location"]


async def test_public_providers_list_reports_only_enabled_ones(client, monkeypatch, idp):
    monkeypatch.setattr(sso_flow, "_transport", lambda: idp.transport())
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "okta",
            "kind": "oidc",
            "config": {"issuer": idp.issuer, "client_id": idp.client_id, "label": "Okta SSO"},
            "secret": idp.client_secret,
        },
    )
    await client.post("/api/settings/auth/providers", json={"name": "adfs", "kind": "saml", "config": {}})
    await client.patch("/api/settings/auth/providers/okta", json={"enabled": True})
    await client.post("/api/logout")

    r = await client.get("/api/auth/providers")
    assert r.status_code == 200
    body = r.json()
    assert body["providers"] == [{"name": "okta", "kind": "oidc", "label": "Okta SSO"}]
    assert body["local_login_enabled"] is True


# --- the public URL -----------------------------------------------------------

REDIRECT_URI = "http://t/api/auth/okta/callback"
OTHER_HOST = "sp.other.example"


async def test_the_authorization_redirect_uri_ignores_the_host_header(client, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    r = await client.get("/api/auth/okta/login", headers={"Host": OTHER_HOST})
    assert r.status_code == 302, r.text
    assert parse_qs(urlsplit(r.headers["location"]).query)["redirect_uri"] == [REDIRECT_URI]


async def test_the_token_request_redirect_uri_ignores_the_host_header(client, monkeypatch, idp):
    await _register_provider(client, idp, monkeypatch)
    token_requests: list[dict[str, list[str]]] = []

    def _recording(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            token_requests.append(parse_qs(request.content.decode()))
        return idp.handler(request)

    monkeypatch.setattr(sso_flow, "_transport", lambda: httpx.MockTransport(_recording))
    state, nonce = await _start_login(client)
    idp.pending_id_token = idp.sign_id_token(idp.claims(nonce=nonce, sub="sub-host"))
    r = await client.get(
        f"/api/auth/okta/callback?state={state}&code=test-code", headers={"Host": OTHER_HOST}
    )
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert [t["redirect_uri"] for t in token_requests] == [[REDIRECT_URI]]
