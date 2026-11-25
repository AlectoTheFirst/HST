"""The setting `public_url`: its validation, the URL helper, and the SSO routes
of an app that has no value for it."""

from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError
from tests.app.conftest import PUBLIC_URL, login
from tests.app.oidc_fixtures import FakeIdp
from tests.app.saml_fixtures import FakeSamlIdp

from hst.app import sso_flow
from hst.app.crypto import generate_key
from hst.app.main import create_app, warn_if_no_proxy_is_trusted
from hst.core import Settings


def _settings(public_url: str) -> Settings:
    return Settings(_env_file=None, HST_PUBLIC_URL=public_url)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", ""),
        ("https://hst.example.net", "https://hst.example.net"),
        ("https://hst.example.net/", "https://hst.example.net"),
        ("http://hst.example.net:8080", "http://hst.example.net:8080"),
        ("HTTPS://hst.example.net", "https://hst.example.net"),
        ("https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
    ],
)
def test_public_url_is_stored_as_an_origin(value, expected):
    assert _settings(value).public_url == expected


def test_public_url_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("HST_PUBLIC_URL", "https://hst.example.net/")
    assert Settings(_env_file=None).public_url == "https://hst.example.net"


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("hst.example.net", "must start with http:// or https://"),
        ("ftp://hst.example.net", "must start with http:// or https://"),
        ("javascript:alert(1)", "must start with http:// or https://"),
        ("https://", "has no host"),
        ("https://:8443", "has no host"),
        ("https://hst.example.net/app", "must not have a path, a query or a fragment"),
        ("https://hst.example.net//", "must not have a path, a query or a fragment"),
        ("https://hst.example.net/?next=1", "must not have a path, a query or a fragment"),
        ("https://hst.example.net?", "must not have a path, a query or a fragment"),
        ("https://hst.example.net#top", "must not have a path, a query or a fragment"),
        ("https://user:secret@hst.example.net", "must not have a user or a password"),
        ("https://hst.example.net:port", "is not a URL"),
        ("https://[2001:db8::1", "is not a URL"),
    ],
)
def test_public_url_refuses_a_value_that_is_not_an_origin(value, message):
    with pytest.raises(ValidationError, match="HST_PUBLIC_URL") as raised:
        _settings(value)
    assert message in str(raised.value)


def test_external_url_joins_the_public_url_and_the_route_path(app):
    assert sso_flow.external_url(app, "saml_acs", name="adfs") == f"{PUBLIC_URL}/api/auth/adfs/acs"
    assert sso_flow.external_url(app, "sso_callback", name="okta") == f"{PUBLIC_URL}/api/auth/okta/callback"


@pytest.fixture
def bare_app(seeded):
    """An app with no value for `public_url`."""
    return create_app(settings=Settings(_env_file=None, hst_secret_key=generate_key()), store=seeded)


@pytest.fixture
async def bare_client(bare_app, monkeypatch):
    """A client of `bare_app` with the enabled providers `okta` (OIDC) and
    `adfs` (SAML)."""
    idp = FakeIdp()
    monkeypatch.setattr(sso_flow, "_transport", lambda: idp.transport())
    transport = httpx.ASGITransport(app=bare_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        await login(c, "ada")
        for body in (
            {
                "name": "okta",
                "kind": "oidc",
                "config": {"issuer": idp.issuer, "client_id": idp.client_id},
                "secret": idp.client_secret,
            },
            {"name": "adfs", "kind": "saml", "config": {"idp_metadata_xml": FakeSamlIdp().metadata_xml()}},
        ):
            r = await c.post("/api/settings/auth/providers", json=body)
            assert r.status_code == 201, r.text
            r = await c.patch(f"/api/settings/auth/providers/{body['name']}", json={"enabled": True})
            assert r.status_code == 200, r.text
        await c.post("/api/logout")
        yield c


def test_external_url_raises_without_the_public_url(bare_app):
    with pytest.raises(sso_flow.PublicUrlNotSet, match="HST_PUBLIC_URL"):
        sso_flow.external_url(bare_app, "saml_acs", name="adfs")


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/auth/adfs/login"),
        ("POST", "/api/auth/adfs/acs"),
        ("GET", "/api/auth/adfs/metadata"),
        ("GET", "/api/auth/okta/login"),
        ("GET", "/api/auth/okta/callback?state=s&code=c"),
    ],
)
async def test_an_sso_route_refuses_without_the_public_url(bare_client, seeded, caplog, method, path):
    with caplog.at_level("WARNING", logger="hst.sso"):
        r = await bare_client.request(method, path, data={"SAMLResponse": "x"} if method == "POST" else None)
    assert r.status_code == 503
    assert r.json() == {"error": "HST_PUBLIC_URL is not set"}
    assert "set-cookie" not in r.headers
    assert seeded.auth_state == {}
    warnings = [rec.getMessage() for rec in caplog.records if rec.levelname == "WARNING"]
    assert len(warnings) == 1 and "HST_PUBLIC_URL is not set" in warnings[0]


PUBLIC_URL_WARNING = "HST_PUBLIC_URL is not set. The SSO routes of adfs, okta answer 503."


def _warnings(caplog) -> list[str]:
    return [rec.getMessage() for rec in caplog.records if rec.levelname == "WARNING"]


async def _two_enabled_providers_and_one_disabled(store) -> None:
    await store.create_auth_provider("okta", "oidc", {}, None, enabled=True)
    await store.create_auth_provider("adfs", "saml", {}, None, enabled=True)
    await store.create_auth_provider("auth0", "oidc", {}, None, enabled=False)


async def test_the_start_up_check_warns_about_enabled_providers_without_the_public_url(seeded, caplog):
    await _two_enabled_providers_and_one_disabled(seeded)

    with caplog.at_level("WARNING", logger="hst.sso"):
        await sso_flow.warn_if_public_url_missing(seeded, _settings(""))

    assert _warnings(caplog) == [PUBLIC_URL_WARNING]


async def test_the_start_up_check_is_silent_with_the_public_url_or_without_an_enabled_provider(
    seeded, caplog
):
    await seeded.create_auth_provider("auth0", "oidc", {}, None, enabled=False)
    with caplog.at_level("WARNING", logger="hst.sso"):
        await sso_flow.warn_if_public_url_missing(seeded, _settings(""))
        await seeded.update_auth_provider("auth0", enabled=True)
        await sso_flow.warn_if_public_url_missing(seeded, _settings(PUBLIC_URL))

    assert _warnings(caplog) == []


async def test_the_lifespan_runs_the_start_up_check_once(seeded, caplog):
    await _two_enabled_providers_and_one_disabled(seeded)
    settings = Settings(_env_file=None, hst_secret_key=generate_key(), scheduler_enabled=False)
    app = create_app(settings=settings, store=seeded)

    with caplog.at_level("WARNING", logger="hst.sso"):
        async with app.router.lifespan_context(app):
            pass

    assert _warnings(caplog) == [PUBLIC_URL_WARNING]


async def test_local_login_works_without_the_public_url(bare_client):
    await login(bare_client, "otto")
    assert (await bare_client.get("/api/me")).status_code == 200


def test_the_start_up_check_warns_about_an_https_public_url_without_a_trusted_proxy(caplog):
    with caplog.at_level("WARNING", logger="hst.app.main"):
        warn_if_no_proxy_is_trusted(Settings(_env_file=None, HST_PUBLIC_URL="https://hst.example.net"))

    assert [r.getMessage() for r in caplog.records] == [
        "HST_PUBLIC_URL is HTTPS and HST_FORWARDED_ALLOW_IPS is empty"
    ]


@pytest.mark.parametrize(
    "overrides",
    [
        {"HST_PUBLIC_URL": ""},
        {"HST_FORWARDED_ALLOW_IPS": "10.0.0.1"},
        {"tls_cert_file": "/etc/hst/tls.crt"},
    ],
)
def test_the_start_up_check_logs_no_warning_without_a_tls_terminator_or_with_a_trusted_proxy(
    overrides, caplog
):
    with caplog.at_level("WARNING", logger="hst.app.main"):
        warn_if_no_proxy_is_trusted(
            Settings(_env_file=None, **{"HST_PUBLIC_URL": "https://hst.example.net", **overrides})
        )

    assert caplog.records == []
