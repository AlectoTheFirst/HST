"""app/main.py's csrf_guard exempts exactly one path from the X-HST-CSRF
header check: POST /api/auth/{name}/acs, the SAML assertion consumer, which
is a cross-site POST from an IdP."""

from __future__ import annotations

import httpx
import pytest
from tests.app.conftest import PASSWORD
from tests.app.test_authz_matrix import ROUTES

_BEARER = {"Authorization": "Bearer some-token"}


async def _bare_client(app) -> httpx.AsyncClient:
    """A client with no default X-HST-CSRF header."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_acs_passes_without_the_csrf_header(app):
    async with await _bare_client(app) as bare:
        r = await bare.post("/api/auth/some-provider/acs", data={"SAMLResponse": "not-real"})
    # rejected for a SAML reason (no such provider / bad assertion), never
    # for a missing CSRF header
    assert r.status_code != 403
    assert r.status_code == 302
    assert r.headers["location"] == "/login?error=sso"


@pytest.mark.parametrize(
    "path",
    [
        "/api/auth/some-provider/acs2",
        "/api/auth/some-provider/acs/y",
        "/api/auth/UPPER/acs",
        "/api/auth//acs",
        "/api/auth/some-provider/acsx",
    ],
)
async def test_near_misses_require_the_csrf_header(app, path):
    async with await _bare_client(app) as bare:
        r = await bare.post(path, data={"SAMLResponse": "not-real"})
    assert r.status_code == 403
    assert r.json()["error"] == "missing CSRF header"


async def test_every_other_mutating_route_requires_the_csrf_header(app):
    """Walks the route table test_authz_matrix.py enumerates from the live
    OpenAPI schema."""
    exempt = {("POST", "/api/auth/{name}/acs")}
    mutating = {"POST", "PUT", "PATCH", "DELETE"}
    checked = 0
    async with await _bare_client(app) as bare:
        for method, path_template, _min_role, kwargs in ROUTES:
            if method not in mutating or (method, path_template) in exempt:
                continue
            url = kwargs.get("url", path_template)
            request_kwargs = {k: v for k, v in kwargs.items() if k != "url"}
            for headers in ({}, _BEARER):
                r = await bare.request(method, url, headers=headers, **request_kwargs)
                assert r.status_code == 403, (
                    f"{method} {url} was not CSRF-guarded ({headers}): {r.status_code} {r.text}"
                )
                assert r.json()["error"] == "missing CSRF header"
            checked += 1
    assert checked > 0


async def test_a_bearer_post_to_api_mcp_passes_without_the_csrf_header(app):
    async with await _bare_client(app) as bare:
        r = await bare.post("/api/mcp", json={}, headers=_BEARER)
    # the transport is off by default, so the endpoint itself answers 404:
    # the guard was not why this failed
    assert r.status_code == 404


async def test_a_cookie_session_post_to_api_mcp_without_the_csrf_header_is_rejected(app):
    async with await _bare_client(app) as bare:
        login = await bare.post(
            "/api/login", json={"username": "otto", "password": PASSWORD}, headers={"X-HST-CSRF": "1"}
        )
        assert login.status_code == 200, login.text
        r = await bare.post("/api/mcp", json={})
    assert r.status_code == 403
    assert r.json()["error"] == "missing CSRF header"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/mcp/"),
        ("POST", "/api/mcp/x"),
        ("POST", "/api/mcpx"),
        ("POST", "/api/MCP"),
        ("DELETE", "/api/mcp"),
        ("PUT", "/api/mcp"),
    ],
)
async def test_a_bearer_token_exempts_no_other_path_or_method(app, method, path):
    async with await _bare_client(app) as bare:
        r = await bare.request(method, path, json={}, headers=_BEARER)
    assert r.status_code == 403
    assert r.json()["error"] == "missing CSRF header"
