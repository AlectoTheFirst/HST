"""Admin auth settings: the local-login toggle, provider CRUD, secrets
write-only/has_secret, discovery-gated enabling, break-glass invariants, and
group mappings.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from tests.app.conftest import PASSWORD, PUBLIC_URL, login
from tests.app.oidc_fixtures import FakeIdp
from tests.app.saml_fixtures import FakeSamlIdp

from hst.app import crypto, sso_flow
from hst.app.crypto import decrypt_secrets, generate_key
from hst.app.main import create_app
from hst.app.routes import auth_settings
from hst.app.saml_flow import generate_sp_keypair
from hst.core import Settings

SP_URL_FIELDS = ("sp_entity_id", "sp_acs_url", "redirect_uri")


@pytest.fixture
def idp(monkeypatch) -> FakeIdp:
    fake = FakeIdp()
    monkeypatch.setattr(sso_flow, "_transport", lambda: fake.transport())
    return fake


@pytest.fixture
def saml_idp(monkeypatch) -> FakeSamlIdp:
    # app/saml_flow.py fetches SAML metadata URLs through the injectable transport
    # of OIDC discovery (sso_flow._client/_transport)
    fake = FakeSamlIdp()
    monkeypatch.setattr(sso_flow, "_transport", lambda: fake.transport())
    return fake


async def test_admin_only(client):
    await login(client, "otto")
    assert (await client.get("/api/settings/auth")).status_code == 403
    assert (await client.get("/api/settings/auth/providers")).status_code == 403


async def test_provider_crud_secrets_are_write_only(client, idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "okta",
            "kind": "oidc",
            "config": {"issuer": idp.issuer, "client_id": idp.client_id},
            "secret": idp.client_secret,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["has_secret"] is True
    assert "secret" not in body and "secrets" not in body
    assert body["enabled"] is False
    assert "issuer" in body["config"]
    assert not any(k.startswith("_") for k in body["config"])  # discovery cache stays private

    listed = (await client.get("/api/settings/auth/providers")).json()
    assert [p["name"] for p in listed] == ["okta"]

    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "x"}},
    )
    assert r.status_code == 409


async def test_name_must_be_a_slug(client, idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "Not A Slug!", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    assert r.status_code == 422


async def test_oidc_config_requires_issuer_and_client_id(client):
    await login(client, "ada")
    r = await client.post("/api/settings/auth/providers", json={"name": "okta", "kind": "oidc", "config": {}})
    assert r.status_code == 422


async def test_saml_provider_needs_no_oidc_fields(client, saml_idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": saml_idp.metadata_xml()}},
    )
    assert r.status_code == 201, r.text


# --- SAML provider save, keypair, and metadata ------------------------------


async def test_saml_config_requires_exactly_one_of_url_or_xml(client, saml_idp):
    await login(client, "ada")
    neither = await client.post(
        "/api/settings/auth/providers", json={"name": "adfs", "kind": "saml", "config": {}}
    )
    assert neither.status_code == 422

    both = await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "adfs",
            "kind": "saml",
            "config": {
                "idp_metadata_url": "https://idp.example/saml/metadata",
                "idp_metadata_xml": saml_idp.metadata_xml(),
            },
        },
    )
    assert both.status_code == 422


async def test_saml_config_rejects_a_bad_default_role(client, saml_idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "adfs",
            "kind": "saml",
            "config": {"idp_metadata_xml": saml_idp.metadata_xml(), "default_role": "superuser"},
        },
    )
    assert r.status_code == 422


async def test_saml_provider_gets_a_generated_sp_keypair_never_returned(client, saml_idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": saml_idp.metadata_xml()}},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["has_secret"] is True
    assert "secret" not in body and "secrets" not in body
    cert = body["config"]["sp_certificate_pem"]
    assert "BEGIN CERTIFICATE" in cert
    assert "PRIVATE KEY" not in str(body)  # the private key never appears anywhere in the response
    assert not any(k.startswith("_") for k in body["config"])  # parsed metadata cache stays private


async def test_saml_metadata_url_is_fetched_through_the_injectable_transport(client, saml_idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "adfs",
            "kind": "saml",
            "config": {"idp_metadata_url": saml_idp.metadata_url},
        },
    )
    assert r.status_code == 201, r.text
    r2 = await client.patch("/api/settings/auth/providers/adfs", json={"enabled": True})
    assert r2.status_code == 200, r2.text
    assert any("metadata" in c for c in saml_idp.calls)


async def test_provider_ca_bundle_must_be_pem(client, idp, saml_idp):
    """Both provider kinds carry tls_skip_verify / tls_ca_bundle; a bundle
    that does not load is refused at save time, and a good one saves."""
    from hst.app.saml_flow import generate_sp_keypair

    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "okta",
            "kind": "oidc",
            "config": {"issuer": idp.issuer, "client_id": "c", "tls_ca_bundle": "garbage"},
        },
    )
    assert r.status_code == 422
    assert "tls_ca_bundle" in r.json()["error"]
    r = await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "okta",
            "kind": "oidc",
            "config": {
                "issuer": idp.issuer,
                "client_id": "c",
                "tls_skip_verify": True,
                "tls_ca_bundle": generate_sp_keypair()[1],
            },
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["config"]["tls_skip_verify"] is True

    r = await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "adfs",
            "kind": "saml",
            "config": {"idp_metadata_url": saml_idp.metadata_url, "tls_ca_bundle": "garbage"},
        },
    )
    assert r.status_code == 422
    assert "tls_ca_bundle" in r.json()["error"]


async def test_enabling_saml_requires_successfully_parsed_metadata(client, saml_idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": "not valid metadata"}},
    )
    assert r.status_code == 201, r.text
    assert r.json()["enabled"] is False

    r2 = await client.patch("/api/settings/auth/providers/adfs", json={"enabled": True})
    assert r2.status_code == 409

    # a config re-save with valid metadata makes enabling succeed
    r3 = await client.patch(
        "/api/settings/auth/providers/adfs",
        json={"config": {"idp_metadata_xml": saml_idp.metadata_xml()}, "enabled": True},
    )
    assert r3.status_code == 200, r3.text
    assert r3.json()["enabled"] is True


async def test_saml_sp_certificate_survives_a_config_patch(client, saml_idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": saml_idp.metadata_xml()}},
    )
    original_cert = r.json()["config"]["sp_certificate_pem"]

    # a PATCH that only edits an attribute name never mentions the cert:
    # the admin UI's SAML form has no field for it
    r2 = await client.patch(
        "/api/settings/auth/providers/adfs",
        json={"config": {"idp_metadata_xml": saml_idp.metadata_xml(), "username_attr": "email"}},
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["config"]["sp_certificate_pem"] == original_cert


async def test_saml_test_endpoint_reports_certificate_validity(client, saml_idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": saml_idp.metadata_xml()}},
    )
    r = await client.post("/api/settings/auth/providers/adfs/test")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "valid" in body["detail"]


async def test_saml_test_endpoint_reports_unreachable_url_without_ever_500ing(client, saml_idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "adfs",
            "kind": "saml",
            "config": {"idp_metadata_url": "https://idp.example/saml/nowhere"},
        },
    )
    r = await client.post("/api/settings/auth/providers/adfs/test")
    assert r.status_code == 200
    assert r.json()["ok"] is False


async def test_saml_metadata_route_requires_an_enabled_saml_provider(client, saml_idp):
    r = await client.get("/api/auth/no-such-provider/metadata")
    assert r.status_code == 404

    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": saml_idp.metadata_xml()}},
    )
    await client.post("/api/logout")
    r2 = await client.get("/api/auth/adfs/metadata")  # created, not yet enabled
    assert r2.status_code == 404


async def test_enabling_oidc_requires_successful_discovery(client, idp):
    await login(client, "ada")
    idp.token_status = 500  # irrelevant here; discovery itself must fail
    # an issuer with no working discovery endpoint: MockTransport 404s anything
    # outside the fixed paths, so pointing at a path discovery won't find works
    bad_issuer = idp.issuer + "/nowhere"
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "broken", "kind": "oidc", "config": {"issuer": bad_issuer, "client_id": "c"}},
    )
    assert r.status_code == 201, r.text
    assert r.json()["enabled"] is False

    r = await client.patch("/api/settings/auth/providers/broken", json={"enabled": True})
    assert r.status_code == 409


async def test_enabling_succeeds_once_discovery_is_fixed(client, idp):
    await login(client, "ada")
    r = await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "broken",
            "kind": "oidc",
            "config": {"issuer": idp.issuer + "/nowhere", "client_id": "c"},
        },
    )
    assert r.status_code == 201, r.text
    r = await client.patch("/api/settings/auth/providers/broken", json={"enabled": True})
    assert r.status_code == 409

    # a config re-save against the real issuer refreshes discovery
    r = await client.patch(
        "/api/settings/auth/providers/broken",
        json={"config": {"issuer": idp.issuer, "client_id": "c"}, "enabled": True},
    )
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True


async def test_test_endpoint_reports_discovery_without_ever_500ing(client, idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    r = await client.post("/api/settings/auth/providers/okta/test")
    assert r.status_code == 200 and r.json()["ok"] is True

    await client.post(
        "/api/settings/auth/providers",
        json={
            "name": "broken",
            "kind": "oidc",
            "config": {"issuer": idp.issuer + "/nowhere", "client_id": "c"},
        },
    )
    r2 = await client.post("/api/settings/auth/providers/broken/test")
    assert r2.status_code == 200 and r2.json()["ok"] is False

    await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": "not valid metadata"}},
    )
    r3 = await client.post("/api/settings/auth/providers/adfs/test")
    assert r3.status_code == 200 and r3.json()["ok"] is False


async def test_group_mappings_crud(client, idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    r = await client.post(
        "/api/settings/auth/providers/okta/mappings", json={"group_name": "engineers", "role": "operator"}
    )
    assert r.status_code == 201 and r.json() == {"group_name": "engineers", "role": "operator"}

    # upsert
    r = await client.post(
        "/api/settings/auth/providers/okta/mappings", json={"group_name": "engineers", "role": "admin"}
    )
    assert r.status_code == 201 and r.json()["role"] == "admin"

    listed = await client.get("/api/settings/auth/providers/okta/mappings")
    assert listed.json() == [{"group_name": "engineers", "role": "admin"}]

    r = await client.delete("/api/settings/auth/providers/okta/mappings/engineers")
    assert r.status_code == 204
    assert (await client.get("/api/settings/auth/providers/okta/mappings")).json() == []
    assert (await client.delete("/api/settings/auth/providers/okta/mappings/engineers")).status_code == 404


async def test_delete_provider(client, idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    r = await client.delete("/api/settings/auth/providers/okta")
    assert r.status_code == 204
    assert (await client.get("/api/settings/auth/providers")).json() == []
    assert (await client.delete("/api/settings/auth/providers/okta")).status_code == 404


async def test_delete_provider_deletes_the_sessions_and_tokens_of_its_users_only(client, store, idp):
    await login(client, "ada")
    now = datetime.now(UTC)
    later = now + timedelta(hours=1)
    for name in ("okta", "auth0"):
        await client.post(
            "/api/settings/auth/providers",
            json={"name": name, "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
        )
        provider = await store.get_auth_provider(name)
        u = await store.create_user(f"{name}-user", None, "viewer")
        identity = await store.create_identity(u.id, provider.id, "sub-1")
        await store.touch_last_login(identity.id, now)
        await store.create_session(f"session-{name}", u.id, later, now)
        await store.create_access_token(f"token-{name}", u.id, "laptop", "read", later, now)
    vera = await store.get_user_by_username("vera")
    await store.create_session("session-local", vera.id, later, now)
    await store.create_access_token("token-local", vera.id, "laptop", "read", later, now)

    r = await client.delete("/api/settings/auth/providers/okta")

    assert r.status_code == 204
    assert await store.get_session_user("session-okta", now) is None
    assert await store.get_access_token_user("token-okta", now) is None
    assert (await store.get_user_by_username("okta-user")).disabled is False
    for name in ("auth0", "local"):
        assert await store.get_session_user(f"session-{name}", now) is not None
        assert await store.get_access_token_user(f"token-{name}", now) is not None
    assert (await client.get("/api/me")).status_code == 200


async def _enabled_providers_with_logged_in_users(client, store, idp, now):
    """The enabled providers `okta` and `auth0`, each with one user, and the
    local user `vera`.

    The session of a user is `session-<okta|auth0|local>`, the token is
    `token-<okta|auth0|local>`.
    """
    later = now + timedelta(hours=1)
    for name in ("okta", "auth0"):
        await client.post(
            "/api/settings/auth/providers",
            json={"name": name, "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
        )
        r = await client.patch(f"/api/settings/auth/providers/{name}", json={"enabled": True})
        assert r.status_code == 200, r.text
        provider = await store.get_auth_provider(name)
        u = await store.create_user(f"{name}-user", None, "viewer")
        identity = await store.create_identity(u.id, provider.id, "sub-1")
        await store.touch_last_login(identity.id, now)
        await store.create_session(f"session-{name}", u.id, later, now)
        await store.create_access_token(f"token-{name}", u.id, "laptop", "read", later, now)
    vera = await store.get_user_by_username("vera")
    await store.create_session("session-local", vera.id, later, now)
    await store.create_access_token("token-local", vera.id, "laptop", "read", later, now)


async def test_disabling_provider_deletes_the_sessions_and_tokens_of_its_users_only(client, store, idp):
    await login(client, "ada")
    now = datetime.now(UTC)
    await _enabled_providers_with_logged_in_users(client, store, idp, now)

    r = await client.patch("/api/settings/auth/providers/okta", json={"enabled": False})

    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False
    assert await store.get_session_user("session-okta", now) is None
    assert await store.get_access_token_user("token-okta", now) is None
    okta_user = await store.get_user_by_username("okta-user")
    assert okta_user.disabled is False
    assert [i.subject for i in await store.list_identities_for_users([okta_user.id])] == ["sub-1"]
    for name in ("auth0", "local"):
        assert await store.get_session_user(f"session-{name}", now) is not None
        assert await store.get_access_token_user(f"token-{name}", now) is not None
    assert (await client.get("/api/me")).status_code == 200


@pytest.mark.parametrize("extra", [{}, {"enabled": True}], ids=["config", "config-and-enabled"])
async def test_patch_that_does_not_disable_deletes_no_session_and_no_token(client, store, idp, extra):
    await login(client, "ada")
    now = datetime.now(UTC)
    await _enabled_providers_with_logged_in_users(client, store, idp, now)

    r = await client.patch(
        "/api/settings/auth/providers/okta",
        json={"config": {"issuer": idp.issuer, "client_id": "c", "groups_claim": "roles"}, **extra},
    )

    assert r.status_code == 200, r.text
    assert r.json()["config"]["groups_claim"] == "roles"
    for name in ("okta", "auth0", "local"):
        assert await store.get_session_user(f"session-{name}", now) is not None
        assert await store.get_access_token_user(f"token-{name}", now) is not None


async def _create_okta_with_a_secret(client, idp) -> dict:
    config = {"issuer": idp.issuer, "client_id": idp.client_id}
    r = await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": config, "secret": idp.client_secret},
    )
    assert r.status_code == 201, r.text
    return config


@pytest.mark.parametrize(
    ("change", "detail"),
    [
        ({"issuer": "https://idp.example/other"}, auth_settings.OTHER_ISSUER_DETAIL),
        ({"tls_skip_verify": True}, auth_settings.WEAKER_TLS_DETAIL),
        ({"tls_ca_bundle": "new"}, auth_settings.WEAKER_TLS_DETAIL),
    ],
    ids=["issuer", "skip on", "bundle"],
)
async def test_a_patch_with_another_issuer_or_a_weaker_tls_check_needs_a_client_secret_in_the_request(
    client, app, store, idp, change, detail
):
    await login(client, "ada")
    config = await _create_okta_with_a_secret(client, idp)
    before = await store.get_auth_provider("okta")
    if "tls_ca_bundle" in change:
        change = {"tls_ca_bundle": generate_sp_keypair()[1]}
    changed = {**config, **change}

    r = await client.patch("/api/settings/auth/providers/okta", json={"config": changed})
    assert (r.status_code, r.json()) == (400, {"error": detail})
    assert await store.get_auth_provider("okta") == before

    r = await client.patch(
        "/api/settings/auth/providers/okta", json={"config": changed, "secret": "own-secret"}
    )
    assert r.status_code == 200, r.text
    after = await store.get_auth_provider("okta")
    assert decrypt_secrets(crypto.dek(app.state.settings), after.secrets) == {"client_secret": "own-secret"}


async def test_a_patch_that_keeps_the_issuer_and_the_tls_check_keeps_the_stored_client_secret(
    client, store, idp
):
    await login(client, "ada")
    config = await _create_okta_with_a_secret(client, idp)
    before = await store.get_auth_provider("okta")

    r = await client.patch(
        "/api/settings/auth/providers/okta", json={"config": {**config, "groups_claim": "roles"}}
    )

    assert r.status_code == 200, r.text
    assert (await store.get_auth_provider("okta")).secrets == before.secrets


# --- the URLs of the service provider ------------------------------------------


def _sp_urls(body: dict) -> dict:
    return {k: v for k, v in body.items() if k in SP_URL_FIELDS}


async def _create_okta_and_adfs(client, idp) -> tuple[dict, dict]:
    """-> (the create response of the OIDC provider `okta`, that of the SAML provider `adfs`)"""
    okta = await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    adfs = await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": FakeSamlIdp().metadata_xml()}},
    )
    assert (okta.status_code, adfs.status_code) == (201, 201), (okta.text, adfs.text)
    return okta.json(), adfs.json()


async def test_provider_json_holds_the_urls_under_the_public_url(client, idp):
    await login(client, "ada")
    okta_urls = {"redirect_uri": f"{PUBLIC_URL}/api/auth/okta/callback"}
    adfs_urls = {
        "sp_entity_id": f"{PUBLIC_URL}/api/auth/adfs/metadata",
        "sp_acs_url": f"{PUBLIC_URL}/api/auth/adfs/acs",
    }

    okta, adfs = await _create_okta_and_adfs(client, idp)

    assert _sp_urls(okta) == okta_urls
    assert _sp_urls(adfs) == adfs_urls
    listed = {p["name"]: p for p in (await client.get("/api/settings/auth/providers")).json()}
    assert _sp_urls(listed["okta"]) == okta_urls
    assert _sp_urls(listed["adfs"]) == adfs_urls
    patched = (await client.patch("/api/settings/auth/providers/adfs", json={"enabled": True})).json()
    assert _sp_urls(patched) == adfs_urls


async def test_provider_json_urls_are_null_without_the_public_url(seeded, idp):
    app = create_app(settings=Settings(_env_file=None, hst_secret_key=generate_key()), store=seeded)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        await login(c, "ada")

        okta, adfs = await _create_okta_and_adfs(c, idp)

        listed = {p["name"]: p for p in (await c.get("/api/settings/auth/providers")).json()}
    for body in (okta, listed["okta"]):
        assert _sp_urls(body) == {"redirect_uri": None}
    for body in (adfs, listed["adfs"]):
        assert _sp_urls(body) == {
            "sp_entity_id": None,
            "sp_acs_url": None,
        }


# --- break-glass invariants --------------------------------------------------


async def test_local_login_toggle_refuses_off_with_no_enabled_provider(client):
    await login(client, "ada")
    r = await client.put("/api/settings/auth", json={"local_login_enabled": False})
    assert r.status_code == 409
    assert (await client.get("/api/settings/auth")).json() == {"local_login_enabled": True}


async def test_local_login_toggle_refuses_off_with_no_admin_password_remaining(client, store, idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    await client.patch("/api/settings/auth/providers/okta", json={"enabled": True})
    ada = await store.get_user_by_username("ada")
    # store.update_user reads password_hash=None as "leave unchanged"
    store.users[ada.id] = replace(ada, password_hash=None)

    r = await client.put("/api/settings/auth", json={"local_login_enabled": False})
    assert r.status_code == 409


async def test_local_login_toggle_succeeds_with_a_provider_and_survives(client, idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    await client.patch("/api/settings/auth/providers/okta", json={"enabled": True})

    r = await client.put("/api/settings/auth", json={"local_login_enabled": False})
    assert r.status_code == 200 and r.json() == {"local_login_enabled": False}
    assert (await client.get("/api/settings/auth")).json() == {"local_login_enabled": False}

    # can be turned back on freely
    r = await client.put("/api/settings/auth", json={"local_login_enabled": True})
    assert r.status_code == 200


async def test_cannot_disable_the_last_enabled_provider_while_local_login_is_off(client, idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    await client.patch("/api/settings/auth/providers/okta", json={"enabled": True})
    await client.put("/api/settings/auth", json={"local_login_enabled": False})

    r = await client.patch("/api/settings/auth/providers/okta", json={"enabled": False})
    assert r.status_code == 409

    r = await client.delete("/api/settings/auth/providers/okta")
    assert r.status_code == 409


async def test_disabling_one_of_two_enabled_providers_is_fine(client, idp):
    await login(client, "ada")
    for name in ("okta", "auth0"):
        await client.post(
            "/api/settings/auth/providers",
            json={"name": name, "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
        )
        await client.patch(f"/api/settings/auth/providers/{name}", json={"enabled": True})
    await client.put("/api/settings/auth", json={"local_login_enabled": False})

    r = await client.patch("/api/settings/auth/providers/okta", json={"enabled": False})
    assert r.status_code == 200


async def _enable_providers_and_turn_local_login_off(client, idp, *names: str) -> None:
    for name in names:
        await client.post(
            "/api/settings/auth/providers",
            json={"name": name, "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
        )
        r = await client.patch(f"/api/settings/auth/providers/{name}", json={"enabled": True})
        assert r.status_code == 200, r.text
    r = await client.put("/api/settings/auth", json={"local_login_enabled": False})
    assert r.status_code == 200, r.text


async def test_config_without_discovery_is_refused_for_the_last_login_path(client, store, idp):
    await login(client, "ada")
    await _enable_providers_and_turn_local_login_off(client, idp, "okta")
    before = await store.get_auth_provider("okta")

    r = await client.patch(
        "/api/settings/auth/providers/okta",
        json={"config": {"issuer": idp.issuer + "/nowhere", "client_id": "c"}},
    )

    assert r.status_code == 409
    assert r.json() == {
        "error": "the new config of okta has no usable discovery, and okta is the last identity "
        "provider while local login is off"
    }
    assert await store.get_auth_provider("okta") == before


async def test_config_without_idp_metadata_is_refused_for_the_last_login_path(client, store, saml_idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": saml_idp.metadata_xml()}},
    )
    await client.patch("/api/settings/auth/providers/adfs", json={"enabled": True})
    r = await client.put("/api/settings/auth", json={"local_login_enabled": False})
    assert r.status_code == 200, r.text
    before = await store.get_auth_provider("adfs")

    r = await client.patch(
        "/api/settings/auth/providers/adfs", json={"config": {"idp_metadata_xml": "not valid metadata"}}
    )

    assert r.status_code == 409
    assert "has no usable IdP metadata" in r.json()["error"]
    assert await store.get_auth_provider("adfs") == before


async def test_config_with_discovery_is_saved_for_the_last_login_path(client, idp):
    await login(client, "ada")
    await _enable_providers_and_turn_local_login_off(client, idp, "okta")

    r = await client.patch(
        "/api/settings/auth/providers/okta",
        json={"config": {"issuer": idp.issuer, "client_id": "c", "groups_claim": "roles"}},
    )

    assert r.status_code == 200, r.text
    assert (r.json()["enabled"], r.json()["config"]["groups_claim"]) == (True, "roles")


async def test_config_without_discovery_is_saved_while_another_provider_is_a_login_path(client, store, idp):
    await login(client, "ada")
    await _enable_providers_and_turn_local_login_off(client, idp, "okta", "auth0")
    broken = {"issuer": idp.issuer + "/nowhere", "client_id": "c"}

    first = await client.patch("/api/settings/auth/providers/okta", json={"config": broken})
    second = await client.patch("/api/settings/auth/providers/auth0", json={"config": broken})
    disabled = await client.patch("/api/settings/auth/providers/auth0", json={"enabled": False})
    deleted = await client.delete("/api/settings/auth/providers/auth0")

    assert (first.status_code, second.status_code) == (200, 409)
    assert (disabled.status_code, deleted.status_code) == (409, 409)
    assert sso_flow.discovery_ok((await store.get_auth_provider("auth0")).config)


async def test_local_login_stays_on_while_no_enabled_provider_has_discovery(client, idp):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    await client.patch("/api/settings/auth/providers/okta", json={"enabled": True})
    r = await client.patch(
        "/api/settings/auth/providers/okta",
        json={"config": {"issuer": idp.issuer + "/nowhere", "client_id": "c"}},
    )
    assert r.status_code == 200 and r.json()["enabled"] is True

    r = await client.put("/api/settings/auth", json={"local_login_enabled": False})

    assert r.status_code == 409
    assert (await client.get("/api/settings/auth")).json() == {"local_login_enabled": True}


async def test_local_login_disabled_endpoint_short_circuits_before_the_store_lookup(client, idp, monkeypatch):
    await login(client, "ada")
    await client.post(
        "/api/settings/auth/providers",
        json={"name": "okta", "kind": "oidc", "config": {"issuer": idp.issuer, "client_id": "c"}},
    )
    await client.patch("/api/settings/auth/providers/okta", json={"enabled": True})
    await client.put("/api/settings/auth", json={"local_login_enabled": False})
    await client.post("/api/logout")

    r = await client.post("/api/login", json={"username": "ada", "password": PASSWORD})
    assert r.status_code == 401


# --- login events -----------------------------------------------------------


async def test_login_events_requires_users_manage_not_settings_auth(client):
    await login(client, "otto")  # operator: holds neither permission
    assert (await client.get("/api/settings/auth/events")).status_code == 403


async def test_login_events_admin_can_read(client):
    await login(client, "ada")
    assert (await client.get("/api/settings/auth/events")).status_code == 200


async def test_login_events_shape_and_default_ordering(client, store):
    await login(client, "ada")  # this login itself is the first recorded event
    r = await client.get("/api/settings/auth/events")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert set(body[0]) == {"at", "username", "user_id", "provider", "outcome", "source"}
    admin = await store.get_user_by_username("ada")
    assert body[0]["username"] == "ada"
    assert body[0]["user_id"] == admin.id
    assert body[0]["provider"] == "local"
    assert body[0]["outcome"] == "ok"


async def test_login_events_limit_is_capped_at_1000(client):
    await login(client, "ada")
    r = await client.get("/api/settings/auth/events", params={"limit": 5000})
    assert r.status_code == 422  # over the ge/le bound, same shape as any other Query validation


async def test_login_events_limit_is_respected(client, store):
    await login(client, "ada")
    for i in range(3):
        await store.record_login_event(
            username=f"extra{i}",
            user_id=None,
            provider="local",
            outcome="bad_credentials",
            source="",
            at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    r = await client.get("/api/settings/auth/events", params={"limit": 2})
    assert r.status_code == 200
    assert len(r.json()) == 2
