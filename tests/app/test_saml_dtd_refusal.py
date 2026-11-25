"""SAML documents with a DTD are refused before any XML library past expat
reads them (CVE-2026-6653 in xmlsec1's libxml2)."""

from __future__ import annotations

import base64

import pytest
from tests.app.conftest import login
from tests.app.saml_fixtures import FakeSamlIdp
from tests.app.test_sso_saml_api import ACS_URL, ENTITY_ID, _acs, _register_provider, _start_login

from hst.app import saml_flow

DOCTYPE = "<!DOCTYPE Response [<!ELEMENT Response ANY>]>"
ENTITY = '<!DOCTYPE Response [<!ENTITY e "x">]>'
LOWER = "<!doctype Response>"


@pytest.fixture
def idp() -> FakeSamlIdp:
    return FakeSamlIdp()


def _with_prolog(xml: str, prolog: str) -> str:
    if xml.startswith("<?xml"):
        end = xml.index("?>") + 2
        return xml[:end] + prolog + xml[end:]
    return prolog + xml


@pytest.mark.parametrize("prolog", [DOCTYPE, ENTITY, LOWER])
def test_reject_dtd_refuses_a_declaration(prolog):
    with pytest.raises(ValueError, match="DTD"):
        saml_flow.reject_dtd(_with_prolog("<Response/>", prolog), what="SAMLResponse")


def test_reject_dtd_refuses_a_declaration_in_utf16():
    xml = '<?xml version="1.0" encoding="UTF-16"?>' + DOCTYPE + "<Response/>"
    data = xml.encode("utf-16")
    assert b"<!doctype" not in data.lower()
    with pytest.raises(ValueError, match="DTD"):
        saml_flow.reject_dtd(data, what="SAMLResponse")


def test_reject_dtd_passes_a_plain_document():
    saml_flow.reject_dtd('<?xml version="1.0"?><Response ID="a"/>', what="SAMLResponse")


def test_reject_dtd_leaves_malformed_xml_to_the_caller():
    saml_flow.reject_dtd(b"<Response", what="SAMLResponse")


async def _signed_response(client, idp: FakeSamlIdp) -> str:
    request_id = await _start_login(client)
    return idp.create_signed_response(
        sp_entity_id=ENTITY_ID,
        acs_url=ACS_URL,
        in_response_to=request_id,
        name_id="dtd@example.com",
        attributes={"uid": ["dtd"]},
    )


@pytest.mark.parametrize("prolog", [DOCTYPE, ENTITY, LOWER])
async def test_a_response_with_a_dtd_is_refused_before_verification(client, idp, monkeypatch, caplog, prolog):
    await _register_provider(client, idp, default_role="viewer")
    signed = await _signed_response(client, idp)
    raw = base64.b64decode(signed).decode()
    with_dtd = base64.b64encode(_with_prolog(raw, prolog).encode()).decode()

    calls: list[dict] = []
    real = saml_flow._sp_client

    def _recording(**kwargs):
        calls.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(saml_flow, "_sp_client", _recording)
    with caplog.at_level("WARNING", logger="hst.sso"):
        r = await _acs(client, with_dtd)
    assert r.status_code == 302 and r.headers["location"] == "/login?error=sso"
    assert calls == [], "pysaml2 and xmlsec1 must not see a response with a DTD"
    assert any("SAMLResponse declares a DTD" in rec.getMessage() for rec in caplog.records)


async def test_a_normal_response_signs_in(client, idp):
    await _register_provider(client, idp, default_role="viewer")
    r = await _acs(client, await _signed_response(client, idp))
    assert r.status_code == 302 and r.headers["location"] == "/"


def test_metadata_with_a_dtd_is_refused(idp):
    with pytest.raises(ValueError, match="DTD"):
        saml_flow._parse_metadata(_with_prolog(idp.metadata_xml(), ENTITY))


def test_metadata_without_a_dtd_parses(idp):
    entity_id, certs = saml_flow._parse_metadata(idp.metadata_xml())
    assert entity_id == idp.entity_id and certs


async def test_a_provider_saved_with_dtd_metadata_cannot_be_enabled(client, store, idp):
    await login(client, "ada")
    config = {"idp_metadata_xml": _with_prolog(idp.metadata_xml(), DOCTYPE), "username_attr": "uid"}
    r = await client.post(
        "/api/settings/auth/providers", json={"name": "adfs", "kind": "saml", "config": config}
    )
    assert r.status_code == 201, r.text
    provider = await store.get_auth_provider("adfs")
    assert not saml_flow.saml_metadata_ok(provider.config)
    r = await client.patch("/api/settings/auth/providers/adfs", json={"enabled": True})
    assert r.status_code == 409, r.text


async def test_cached_metadata_with_a_dtd_is_refused_at_use(client, store, idp):
    await _register_provider(client, idp)
    provider = await store.get_auth_provider("adfs")
    config = dict(provider.config)
    config[saml_flow.IDP_METADATA_XML_KEY] = _with_prolog(config[saml_flow.IDP_METADATA_XML_KEY], DOCTYPE)
    provider.config.clear()
    provider.config.update(config)
    with pytest.raises(saml_flow.SsoLoginError, match="DTD"):
        saml_flow._cached_idp_metadata(provider)
