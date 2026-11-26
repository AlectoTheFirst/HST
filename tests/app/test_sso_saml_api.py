"""SAML login end to end: the signed AuthnRequest, ACS verification and
provisioning, the assertion-replay cache, and SP metadata, driven through a
fake IdP (saml_fixtures.py) with real xmlsec1-backed signatures. No test here
touches the network, and no signature check is mocked: every negative case is a
pysaml2/xmlsec1 rejection.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from tests.app.conftest import login
from tests.app.saml_fixtures import FakeSamlIdp, authn_request, extract_authn_request_id

from hst.app import saml_flow
from hst.app.routes.sso import SAML_REQUEST_COOKIE

BASE_URL = "http://t"
ENTITY_ID = f"{BASE_URL}/api/auth/adfs/metadata"
ACS_URL = f"{BASE_URL}/api/auth/adfs/acs"
OTHER_HOST = "sp.other.example"
OTHER_SP = f"http://{OTHER_HOST}"
FOREIGN_SP = "https://someone-elses-sp.example"


@pytest.fixture
def idp() -> FakeSamlIdp:
    return FakeSamlIdp()


async def _register_provider(client, idp: FakeSamlIdp, **config_overrides) -> None:
    await login(client, "ada")
    config = {"idp_metadata_xml": idp.metadata_xml(), "username_attr": "uid", "groups_attr": "groups"}
    config.update(config_overrides)
    r = await client.post(
        "/api/settings/auth/providers", json={"name": "adfs", "kind": "saml", "config": config}
    )
    assert r.status_code == 201, r.text
    r = await client.patch("/api/settings/auth/providers/adfs", json={"enabled": True})
    assert r.status_code == 200, r.text
    await client.post("/api/logout")


async def _start_login(client) -> str:
    """-> request_id, read off the AuthnRequest the app itself signed and
    sent in the redirect's SAMLRequest query parameter."""
    r = await client.get("/api/auth/adfs/login")
    assert r.status_code == 302, r.text
    return extract_authn_request_id(r.headers["location"])


async def _acs(client, saml_response_b64: str):
    return await client.post("/api/auth/adfs/acs", data={"SAMLResponse": saml_response_b64})


async def test_happy_path_provisions_maps_role_and_stamps_last_login(client, store, idp):
    await _register_provider(client, idp, default_role="viewer")
    provider = await store.get_auth_provider("adfs")
    await store.put_group_mapping(provider.id, "engineers", "operator")

    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="alice@example.com",
        attributes={"uid": ["alice"], "groups": ["engineers"], "email": ["alice@example.com"]},
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert "hst_session=" in r.headers["set-cookie"]

    me = await client.get("/api/me")
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "alice" and body["role"] == "operator"

    user = await store.get_user_by_username("alice")
    assert user is not None
    assert user.role == "operator" and user.role_source == "mapped" and user.password_hash is None
    identity = await store.get_identity(provider.id, "alice@example.com")
    assert identity is not None and identity.email == "alice@example.com"
    assert identity.last_login_at is not None


async def test_username_collision_is_suffixed(client, store, idp):
    await _register_provider(client, idp)
    await store.create_user("bob", None, "viewer")  # occupies the preferred name

    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="bob-subject",
        attributes={"uid": ["bob"]},
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert await store.get_user_by_username("bob2") is not None


async def test_group_mapping_miss_uses_default_role(client, store, idp):
    await _register_provider(client, idp, default_role="viewer")
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="carol@example.com",
        attributes={"uid": ["carol"], "groups": ["nobody-maps-this"]},
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/"
    user = await store.get_user_by_username("carol")
    assert user is not None and user.role == "viewer" and user.disabled is False


async def test_default_role_none_creates_a_disabled_account_and_refuses_login(client, store, idp):
    await _register_provider(client, idp, default_role="none")
    provider = await store.get_auth_provider("adfs")
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID, acs_url=ACS_URL, in_response_to=request_id, name_id="locked-subject"
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert "hst_session=" not in r.headers.get("set-cookie", "")
    identity = await store.get_identity(provider.id, "locked-subject")
    assert identity is not None
    user = await store.get_user(identity.user_id)
    assert user is not None and user.disabled is True


async def test_wrong_audience_is_refused(client, idp):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=FOREIGN_SP,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="eve@example.com",
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


@pytest.mark.parametrize(
    ("audiences", "location"),
    [
        ([ENTITY_ID], "/"),
        ([], "/login?error=sso"),
        ([FOREIGN_SP], "/login?error=sso"),
        ([ENTITY_ID, FOREIGN_SP], "/login?error=sso"),
    ],
    ids=["own", "none", "foreign", "own-and-foreign"],
)
async def test_each_audience_restriction_must_hold_the_sp_entity_id(
    client, store, idp, caplog, audiences, location
):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="aud@example.com",
        attributes={"uid": ["aud"]},
        audiences=audiences,
    )

    with caplog.at_level("WARNING", logger="hst.sso"):
        r = await _acs(client, saml_response)

    assert r.status_code == 302 and r.headers["location"] == location
    signed_in = location == "/"
    assert ("hst_session=" in r.headers.get("set-cookie", "")) == signed_in
    assert (await store.get_user_by_username("aud") is not None) == signed_in
    refusals = [rec for rec in caplog.records if rec.name == "hst.sso" and "Audience" in rec.getMessage()]
    assert len(refusals) == (0 if signed_in else 1)


async def test_expired_assertion_is_refused(client, idp):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="dana@example.com",
        lifetime_seconds=-30,
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_unsolicited_response_is_refused(client, idp):
    await _register_provider(client, idp)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to="id-never-issued-by-this-app",
        name_id="mallory@example.com",
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_unsigned_response_is_refused(client, idp):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="plain@example.com",
        sign_assertion=False,
        sign_response=False,
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_tampered_signature_is_refused(client, idp):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="tamper@example.com",
        attributes={"uid": ["tamperer"]},
    )
    raw = base64.b64decode(saml_response).decode()
    tampered = raw.replace("tamperer", "admin-tamperer")
    assert tampered != raw
    tampered_b64 = base64.b64encode(tampered.encode()).decode()

    r = await _acs(client, tampered_b64)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_replayed_response_cannot_be_resubmitted(client, idp):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID, acs_url=ACS_URL, in_response_to=request_id, name_id="rex@example.com"
    )
    first = await _acs(client, saml_response)
    assert first.status_code == 302 and first.headers["location"] == "/"

    second = await _acs(client, saml_response)
    assert second.status_code == 302 and second.headers["location"] == "/login?error=sso"


async def test_replayed_assertion_id_is_refused_even_with_a_fresh_pending_request(client, store, idp):
    await _register_provider(client, idp)
    provider = await store.get_auth_provider("adfs")
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID, acs_url=ACS_URL, in_response_to=request_id, name_id="quinn@example.com"
    )
    first = await _acs(client, saml_response)
    assert first.status_code == 302 and first.headers["location"] == "/"

    await store.create_auth_state(
        request_id, provider.id, saml_flow.REQUEST_KIND, {}, datetime.now(UTC) + timedelta(minutes=5)
    )
    second = await _acs(client, saml_response)
    assert second.status_code == 302 and second.headers["location"] == "/login?error=sso"


async def test_an_acs_post_bound_to_a_used_assertion_id_keeps_the_replay_row(app, client, store, idp):
    import httpx

    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID, acs_url=ACS_URL, in_response_to=request_id, name_id="rita@example.com"
    )
    first = await _acs(client, saml_response)
    assert first.status_code == 302 and first.headers["location"] == "/"
    (seen,) = [s for s in store.auth_state.values() if s.kind == saml_flow.SEEN_KIND]
    forged = f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="{seen.id}"/>'

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as other:
        r = await other.post(
            "/api/auth/adfs/acs",
            data={"SAMLResponse": base64.b64encode(forged.encode()).decode()},
            headers={"Cookie": f"{SAML_REQUEST_COOKIE}={seen.id}"},
        )

    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert store.auth_state[seen.id] == seen


@pytest.mark.parametrize("change", ["delete", "disable"])
async def test_a_provider_change_during_the_acs_request_leaves_no_session(
    client, store, idp, monkeypatch, change
):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="race@example.com",
        attributes={"uid": ["race"]},
    )
    touch_last_login = store.touch_last_login

    async def touch_then_change(identity_id, when):
        """The provider changes after the validation of the assertion and before the session insert."""
        await touch_last_login(identity_id, when)
        if change == "delete":
            await store.delete_auth_provider("adfs")
        else:
            await store.update_auth_provider("adfs", enabled=False)

    monkeypatch.setattr(store, "touch_last_login", touch_then_change)

    r = await _acs(client, saml_response)

    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert "hst_session=" not in r.headers.get("set-cookie", "")
    assert store.sessions == {}
    assert (await client.get("/api/me")).status_code == 401
    events = [e for e in await store.list_login_events() if e.provider == "adfs"]
    assert [(e.username, e.outcome) for e in events] == [("", "failed")]


async def test_unknown_provider_acs_is_refused(client):
    r = await _acs(client, "irrelevant")
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_disabled_provider_acs_is_refused(client, store, idp):
    await _register_provider(client, idp)
    await login(client, "ada")
    await client.patch("/api/settings/auth/providers/adfs", json={"enabled": False})
    await client.post("/api/logout")
    r = await _acs(client, "irrelevant")
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"


async def test_unknown_provider_login_is_not_found(client):
    r = await client.get("/api/auth/no-such-provider/login")
    assert r.status_code == 404


async def test_saml_metadata_endpoint_parses_and_carries_the_cert(client, idp):
    from defusedxml import ElementTree as DET

    await _register_provider(client, idp)
    r = await client.get("/api/auth/adfs/metadata")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/xml")

    root = DET.fromstring(r.content)
    assert root.get("entityID") == ENTITY_ID
    xml_text = r.text
    assert ACS_URL in xml_text
    assert "X509Certificate" in xml_text


# --- login events -----------------------------------------------------------


async def test_successful_saml_login_records_an_ok_event(client, store, idp):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="audit@example.com",
        attributes={"uid": ["audituser"]},
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/"

    user = await store.get_user_by_username("audituser")
    events = [e for e in await store.list_login_events() if e.provider == "adfs"]
    assert len(events) == 1
    assert (events[0].username, events[0].user_id, events[0].outcome) == ("audituser", user.id, "ok")


async def test_failed_saml_acs_records_a_failed_event(client, store, idp):
    await _register_provider(client, idp)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to="id-never-issued-by-this-app",
        name_id="mallory@example.com",
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"

    events = [e for e in await store.list_login_events() if e.provider == "adfs"]
    assert len(events) == 1
    assert (events[0].username, events[0].user_id, events[0].outcome) == ("", None, "failed")


async def test_unknown_provider_acs_records_an_unknown_provider_event(client, store):
    # _acs always posts to /api/auth/adfs/acs; no provider named "adfs" is
    # registered in this test, so it is unknown from the route's point of view
    r = await _acs(client, "irrelevant")
    assert r.status_code == 302

    events = await store.list_login_events()
    assert len(events) == 1
    e = events[0]
    assert (e.username, e.user_id, e.provider, e.outcome) == ("", None, "adfs", "unknown_provider")


async def test_saml_metadata_endpoint_is_not_found_for_unknown_or_disabled(client, store, idp):
    r = await client.get("/api/auth/no-such-provider/metadata")
    assert r.status_code == 404

    await _register_provider(client, idp)
    await login(client, "ada")
    await client.patch("/api/settings/auth/providers/adfs", json={"enabled": False})
    await client.post("/api/logout")
    r2 = await client.get("/api/auth/adfs/metadata")
    assert r2.status_code == 404


async def test_the_login_cookie_is_bound_to_the_acs_path_and_crosses_sites(client, idp):
    await _register_provider(client, idp)
    r = await client.get("/api/auth/adfs/login")
    cookie = r.headers["set-cookie"]
    request_id = extract_authn_request_id(r.headers["location"])

    assert cookie.startswith(f"hst_saml_req={request_id};")
    assert "Path=/api/auth/adfs/acs" in cookie and "SameSite=none" in cookie and "HttpOnly" in cookie


async def test_a_response_posted_from_another_browser_is_refused(app, client, store, idp):
    """Login CSRF: the attacker starts a login, gets their own signed
    response and posts it from a page the victim opens. The victim's browser
    holds no cookie for that request, so no session is issued, and the
    pending request is not burned."""
    import httpx

    await _register_provider(client, idp)
    request_id = await _start_login(client)  # the attacker's own browser
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="mallory@example.com",
        attributes={"uid": ["mallory"]},
    )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as victim:
        r = await _acs(victim, saml_response)
        assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
        assert "hst_session=" not in r.headers.get("set-cookie", "")
        assert (await victim.get("/api/me")).status_code == 401
    assert await store.get_user_by_username("mallory") is None

    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/"


# --- the cost of an unauthenticated request ---------------------------------------


async def test_an_acs_post_without_the_request_cookie_fails_before_the_response_is_read(
    app, client, store, idp, monkeypatch
):
    import httpx

    await _register_provider(client, idp)

    async def unreachable(**kwargs):
        raise AssertionError("the response was read")

    monkeypatch.setattr(saml_flow, "complete_saml_login", unreachable)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as other:
        r = await _acs(other, "irrelevant")

    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    events = [e for e in await store.list_login_events() if e.provider == "adfs"]
    assert [e.outcome for e in events] == ["failed"]


async def test_the_saml_response_is_parsed_off_the_event_loop(client, idp, monkeypatch):
    import threading

    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID, acs_url=ACS_URL, in_response_to=request_id, name_id="quinn@example.com"
    )
    threads: list[int] = []
    reject_dtd = saml_flow.reject_dtd

    def recording(xml, *, what):
        if what == "SAMLResponse":
            threads.append(threading.get_ident())
        reject_dtd(xml, what=what)

    monkeypatch.setattr(saml_flow, "reject_dtd", recording)
    r = await _acs(client, saml_response)

    assert r.status_code == 302 and r.headers["location"] == "/"
    assert threads and threading.get_ident() not in threads


async def test_the_acs_refuses_a_client_address_over_its_limit(app, client):
    limiter = app.state.limiter
    for _ in range(limiter.limit * 10):
        assert (await _acs(client, "irrelevant")).status_code == 302

    assert (await _acs(client, "irrelevant")).status_code == 429


async def test_a_successful_saml_login_gives_its_acs_unit_back(app, client, idp):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID, acs_url=ACS_URL, in_response_to=request_id, name_id="rita@example.com"
    )

    r = await _acs(client, saml_response)

    assert r.status_code == 302 and r.headers["location"] == "/"
    assert not [key for key in app.state.limiter._hits if key[0] == "saml-acs"]


async def test_the_sp_metadata_refuses_a_client_address_over_its_limit(app, client, idp):
    await _register_provider(client, idp)
    limiter = app.state.limiter
    for _ in range(limiter.limit * 10):
        assert (await client.get("/api/auth/adfs/metadata")).status_code == 200

    assert (await client.get("/api/auth/adfs/metadata")).status_code == 429


# --- the public URL -----------------------------------------------------------


async def test_a_response_for_another_service_provider_is_refused_under_its_host(client, store, idp):
    """A second service provider at the same IdP gets a signed response for
    the request id of a login this browser started, and posts it with its own
    Host header and the login cookie."""
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=f"{OTHER_SP}/api/auth/adfs/metadata",
        acs_url=f"{OTHER_SP}/api/auth/adfs/acs",
        in_response_to=request_id,
        name_id="victim@example.com",
        attributes={"uid": ["victim"]},
    )
    r = await client.post(
        "/api/auth/adfs/acs", data={"SAMLResponse": saml_response}, headers={"Host": OTHER_HOST}
    )
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert "hst_session=" not in r.headers.get("set-cookie", "")
    assert await store.get_user_by_username("victim") is None


async def test_a_response_for_the_public_url_is_accepted_under_another_host(client, store, idp):
    await _register_provider(client, idp)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="uma@example.com",
        attributes={"uid": ["uma"]},
    )
    r = await client.post(
        "/api/auth/adfs/acs", data={"SAMLResponse": saml_response}, headers={"Host": OTHER_HOST}
    )
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert await store.get_user_by_username("uma") is not None


async def test_the_acs_verifies_against_the_public_url_under_another_host(client, idp, monkeypatch):
    await _register_provider(client, idp)
    calls: list[dict] = []
    real = saml_flow._sp_client

    def _recording(**kwargs):
        calls.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(saml_flow, "_sp_client", _recording)
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID, acs_url=ACS_URL, in_response_to=request_id, name_id="ivo@example.com"
    )
    await client.post(
        "/api/auth/adfs/acs", data={"SAMLResponse": saml_response}, headers={"Host": OTHER_HOST}
    )
    assert [(c["entity_id"], c["acs_url"]) for c in calls] == [(ENTITY_ID, ACS_URL)] * 2


async def test_the_authn_request_ignores_the_host_header(client, idp):
    await _register_provider(client, idp)
    r = await client.get("/api/auth/adfs/login", headers={"Host": OTHER_HOST})
    assert r.status_code == 302, r.text
    root = authn_request(r.headers["location"])
    assert root.get("AssertionConsumerServiceURL") == ACS_URL
    assert root.findtext("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer") == ENTITY_ID


async def test_the_sp_metadata_ignores_the_host_header(client, idp):
    from defusedxml import ElementTree as DET

    await _register_provider(client, idp)
    r = await client.get("/api/auth/adfs/metadata", headers={"Host": OTHER_HOST})
    assert r.status_code == 200
    assert DET.fromstring(r.content).get("entityID") == ENTITY_ID
    assert ACS_URL in r.text and OTHER_HOST not in r.text


# --- required group ------------------------------------------------------------


async def test_a_login_with_the_required_group_signs_in(client, store, idp):
    await _register_provider(client, idp, required_group="hst-users")
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="gina@example.com",
        attributes={"uid": ["gina"], "groups": ["hst-users"]},
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert await store.get_user_by_username("gina") is not None


async def test_a_login_without_the_required_group_creates_no_account(client, store, idp):
    await _register_provider(client, idp, required_group="hst-users")
    provider = await store.get_auth_provider("adfs")
    request_id = await _start_login(client)
    saml_response = idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="hugo@example.com",
        attributes={"uid": ["hugo"], "groups": ["engineers"]},
    )
    r = await _acs(client, saml_response)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert "hst_session=" not in r.headers.get("set-cookie", "")
    assert await store.get_user_by_username("hugo") is None
    assert await store.get_identity(provider.id, "hugo@example.com") is None
