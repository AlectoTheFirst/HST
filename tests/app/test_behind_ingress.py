"""The app behind the chart's ingress, with the chart's default proxy trust (GS-06).

`hst serve` hands HST_FORWARDED_ALLOW_IPS to uvicorn, which wraps the app in
its ProxyHeadersMiddleware. Here the same middleware wraps the test app with the
default of `app.forwardedAllowIps` read from the chart's values.yaml, and the
transport's peer address stands in for the ingress controller's pod.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import yaml
from tests.app.conftest import PASSWORD, PUBLIC_URL, login
from tests.app.oidc_fixtures import FakeIdp
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from hst.app import sso_flow

VALUES = Path(__file__).resolve().parents[2] / "deploy/helm/hst/values.yaml"
INGRESS_POD = "10.244.2.244"  # a Traefik pod address
HOST = "http://hst.example.lan"


def _chart_default() -> str:
    return yaml.safe_load(VALUES.read_text())["app"]["forwardedAllowIps"]


def _proxied(app, peer: str, trusted: str | None = None) -> httpx.AsyncClient:
    wrapped = ProxyHeadersMiddleware(app, trusted_hosts=_chart_default() if trusted is None else trusted)
    transport = httpx.ASGITransport(app=wrapped, client=(peer, 40000))
    return httpx.AsyncClient(transport=transport, base_url=HOST, headers={"X-HST-CSRF": "1"})


async def _bad_logins(c: httpx.AsyncClient, forwarded_for: str, n: int) -> list[int]:
    codes = []
    for _ in range(n):
        r = await c.post(
            "/api/login",
            json={"username": "otto", "password": "wrong"},
            headers={"X-Forwarded-For": forwarded_for, "X-Forwarded-Proto": "https"},
        )
        codes.append(r.status_code)
    return codes


def test_every_default_entry_is_an_address_or_a_network():
    """uvicorn turns an entry it cannot parse into a literal that no peer address
    matches."""
    entries = [e.strip() for e in _chart_default().split(",")]
    assert entries
    for entry in entries:
        if "/" in entry:
            ipaddress.ip_network(entry)
        else:
            ipaddress.ip_address(entry)


def test_the_default_trusts_the_ingress_pod_and_not_a_public_peer():
    trusted = _chart_default().split(",")
    wrapped = ProxyHeadersMiddleware(lambda *a: None, trusted_hosts=trusted)
    for pod in (INGRESS_POD, "10.42.0.17", "172.20.1.4", "192.168.5.9", "100.64.3.2", "fd00:10:244::5"):
        assert pod in wrapped.trusted_hosts, pod
    for public in ("203.0.113.50", "2001:db8::1"):
        assert public not in wrapped.trusted_hosts, public


async def test_two_users_behind_one_ingress_have_their_own_login_buckets(app, seeded):
    """Without the trust, every request has the ingress pod's address, and five
    wrong passwords from anyone lock every local login. With it, one user's
    failures leave the other's login alone, and the audit row names each user."""
    async with _proxied(app, INGRESS_POD) as c:
        assert await _bad_logins(c, "192.168.1.66", 6) == [401] * 5 + [429]
        r = await c.post(
            "/api/login",
            json={"username": "otto", "password": PASSWORD},
            headers={"X-Forwarded-For": "192.168.1.50", "X-Forwarded-Proto": "https"},
        )
    assert r.status_code == 200, r.text
    sources = {e.source for e in await seeded.list_login_events()}
    assert sources == {"192.168.1.66", "192.168.1.50"}


async def test_without_the_trust_one_user_locks_out_the_other(app):
    async with _proxied(app, INGRESS_POD, trusted="127.0.0.1,::1") as c:
        assert await _bad_logins(c, "192.168.1.66", 5) == [401] * 5
        r = await c.post(
            "/api/login",
            json={"username": "otto", "password": PASSWORD},
            headers={"X-Forwarded-For": "192.168.1.50", "X-Forwarded-Proto": "https"},
        )
    assert r.status_code == 429


async def test_hsts_and_a_secure_cookie_follow_the_forwarded_scheme(app):
    async with _proxied(app, INGRESS_POD) as c:
        r = await c.get("/api/livez", headers={"X-Forwarded-Proto": "https"})
        assert r.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
        plain = await c.get("/api/livez", headers={"X-Forwarded-Proto": "http"})
        assert "strict-transport-security" not in plain.headers
        r = await c.post(
            "/api/login",
            json={"username": "ada", "password": PASSWORD},
            headers={"X-Forwarded-For": "192.168.1.50", "X-Forwarded-Proto": "https"},
        )
    assert r.status_code == 200, r.text
    assert "secure" in r.headers["set-cookie"].lower()


async def test_the_oidc_redirect_uri_ignores_the_forwarded_scheme_and_the_host(app, client, monkeypatch):
    idp = FakeIdp()
    monkeypatch.setattr(sso_flow, "_transport", lambda: idp.transport())
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
    assert (
        await client.patch("/api/settings/auth/providers/okta", json={"enabled": True})
    ).status_code == 200

    async with _proxied(app, INGRESS_POD) as c:
        r = await c.get(
            "/api/auth/okta/login", headers={"X-Forwarded-For": "192.168.1.50", "X-Forwarded-Proto": "https"}
        )
    assert r.status_code == 302, r.text
    redirect_uri = parse_qs(urlsplit(r.headers["location"]).query)["redirect_uri"][0]
    assert redirect_uri == f"{PUBLIC_URL}/api/auth/okta/callback"


async def test_a_peer_outside_the_list_cannot_name_its_own_address(app):
    """A public peer that reaches the pod directly (a LoadBalancer or NodePort that
    keeps the client address) is not a proxy: its forwarded headers are ignored,
    and a new X-Forwarded-For per attempt does not buy a new bucket."""
    async with _proxied(app, "203.0.113.50") as c:
        codes = []
        for i in range(6):
            r = await c.post(
                "/api/login",
                json={"username": "otto", "password": "wrong"},
                headers={"X-Forwarded-For": f"198.51.100.{i}", "X-Forwarded-Proto": "https"},
            )
            codes.append(r.status_code)
            assert "strict-transport-security" not in r.headers
    assert codes == [401] * 5 + [429]


@pytest.mark.parametrize(
    ("forwarded_for", "expected"),
    [
        # The ingress replaces the header: the one entry is the client.
        ("192.168.1.50", "192.168.1.50"),
        # The ingress appends a public client to a forged entry: the walk from the
        # right stops at the first address outside the list, the real client.
        ("10.9.9.9, 203.0.113.7", "203.0.113.7"),
        # The ingress appends a client inside the list to a forged entry: every entry
        # is trusted and uvicorn takes the leftmost, which the client wrote. This is
        # the condition the default rests on (values.yaml app.forwardedAllowIps): the
        # ingress must replace the header, or the list must be narrowed to the
        # ingress controller's pod network.
        ("10.9.9.9, 192.168.1.50", "10.9.9.9"),
    ],
)
async def test_which_entry_of_x_forwarded_for_is_the_client(app, seeded, forwarded_for, expected):
    async with _proxied(app, INGRESS_POD) as c:
        await _bad_logins(c, forwarded_for, 1)
    assert [e.source for e in await seeded.list_login_events()] == [expected]
