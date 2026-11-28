"""SAML 2.0 protocol: SP keypair generation, IdP metadata parsing, the signed
AuthnRequest, and assertion verification and provisioning at the ACS."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import logging
import tempfile
import warnings
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from defusedxml import DefusedXmlException
from defusedxml import ElementTree as _DET

from hst.app import crypto, egress, sso_flow, tls
from hst.app.crypto import SecretKeyError, decrypt_secrets
from hst.app.saml_resources import saml_tempfiles
from hst.app.sso_flow import SsoLoginError
from hst.app.store import ROLES
from hst.app.tls import Trust

# pysaml2's import chain emits CryptographyDeprecationWarning at import time.
with warnings.catch_warnings():
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.simplefilter("ignore", CryptographyDeprecationWarning)
    # xmlschema<3 calls the deprecated PurePath.as_uri on Python 3.14.
    warnings.filterwarnings(
        "ignore",
        message=(
            r"pathlib\.PurePath\.as_uri\(\) is deprecated and scheduled for removal in Python 3\.19\. "
            r"Use pathlib\.Path\.as_uri\(\)\."
        ),
        category=DeprecationWarning,
        module=r"xmlschema\.resources",
    )
    import saml2
    from saml2 import time_util
    from saml2.client import Saml2Client
    from saml2.config import SPConfig
    from saml2.metadata import entity_descriptor

if TYPE_CHECKING:
    from hst.app.store import AuthProvider, Store, User
    from hst.core import Settings

log = logging.getLogger("hst.sso")

# app/sso_flow.py's public_config strips the keys with the `_` prefix.
IDP_METADATA_XML_KEY = "_idp_metadata_xml"
IDP_ENTITY_ID_KEY = "_idp_entity_id"

# routes/auth_settings.py re-asserts the SP certificate from the existing row on every PATCH.
SP_CERT_CONFIG_KEY = "sp_certificate_pem"

SP_PRIVATE_KEY_SECRET = "sp_private_key"  # noqa: S105

# The auth_state.kind values of SAML. A REQUEST_KIND row holds the id of a
# pending AuthnRequest, and the ACS consumes it as the InResponseTo match. A
# SEEN_KIND row holds the id of an accepted assertion until the assertion
# expires.
REQUEST_KIND = "saml_request"
SEEN_KIND = "saml_seen"


# --- DTD refusal ----------------------------------------------------------------

# xmlsec1's libxml2 has a DTD parser fault (CVE-2026-6653).
_DTD_MARKERS = (b"<!doctype", b"<!entity")


def reject_dtd(xml: bytes | str, *, what: str) -> None:
    """Raise ValueError when `xml` declares a DTD or an entity.

    The byte check finds the declaration in each ASCII-compatible encoding.
    The expat parse with `forbid_dtd` finds it in each other encoding that
    expat reads. The function does not raise for a document that expat cannot
    parse. The parse of the caller refuses that document.
    """
    data = xml.encode() if isinstance(xml, str) else xml
    if any(marker in data.lower() for marker in _DTD_MARKERS):
        raise ValueError(f"{what} declares a DTD")
    try:
        _DET.fromstring(data, forbid_dtd=True)
    except DefusedXmlException as exc:
        raise ValueError(f"{what} declares a DTD") from exc
    except Exception:  # noqa: S110 -- the parse of the caller refuses malformed XML
        pass


# --- SP keypair ---------------------------------------------------------------


def generate_sp_keypair() -> tuple[str, str]:
    """Return the PEM texts of a new RSA key and of a self-signed certificate
    for the SP role of one provider.

    The certificate is valid for 3650 days. The key signs the AuthnRequests.
    The certificate identifies the SP to the IdP.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hst-sp")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


# --- config validation, metadata fetch/parse/cache -----------------------------


def validate_saml_config(config: dict[str, Any]) -> None:
    """Shape check before a save fetches and parses metadata."""
    url = config.get("idp_metadata_url") or ""
    xml = config.get("idp_metadata_xml") or ""
    if bool(url) == bool(xml):  # both set, or neither
        raise ValueError("config must set exactly one of idp_metadata_url or idp_metadata_xml")
    default_role = config.get("default_role", "viewer")
    allowed = (*ROLES, "none")
    if default_role not in allowed:
        raise ValueError(f"config.default_role must be one of {', '.join(allowed)}")
    sso_flow.validate_required_group(config)
    if config.get(tls.CA_BUNDLE):
        tls.validate_ca_bundle(config[tls.CA_BUNDLE], what=f"config.{tls.CA_BUNDLE}")


async def _fetch_metadata_xml(url: str, *, trust: Trust) -> str:
    """Fetch with the https check and the `sso_flow._transport` of OIDC discovery."""
    egress.check_https_url(url, what="idp_metadata_url")
    async with sso_flow._client(trust) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.text


def _parse_metadata(xml_text: str) -> tuple[str, list[tuple[str | None, str]]]:
    """Return the IdP entity id and the signing certificates as
    (key_name, base64_der_cert) pairs.

    Raises ValueError when the metadata has no IdP entity, no
    redirect-binding SSO endpoint or no signing certificate.
    """
    reject_dtd(xml_text, what="IdP metadata")
    mds_config = SPConfig().load({"entityid": "urn:hst:metadata-parse", "metadata": {"inline": [xml_text]}})
    mds = mds_config.metadata
    idps = mds.identity_providers()
    if not idps:
        raise ValueError("metadata carries no IDPSSODescriptor")
    if len(idps) > 1:
        log.info("IdP metadata names %d entities; using the first (%s)", len(idps), idps[0])
    idp_entity_id = idps[0]
    sso = mds.single_sign_on_service(idp_entity_id, binding=saml2.BINDING_HTTP_REDIRECT)
    if not sso:
        raise ValueError("metadata carries no redirect-binding SingleSignOnService")
    certs = mds.certs(idp_entity_id, "idpsso", "signing")
    if not certs:
        raise ValueError("metadata carries no IdP signing certificate")
    return idp_entity_id, certs


async def refresh_saml_metadata(config: dict[str, Any], *, trust: Trust) -> tuple[dict[str, Any], bool]:
    """Fetch (for a URL) and parse SAML IdP metadata. Returns the config to
    store and whether fetch and parse succeeded. A scheme violation raises
    ValueError. Any other failure drops the cache.
    """
    url = config.get("idp_metadata_url") or ""
    pasted = config.get("idp_metadata_xml") or ""
    try:
        xml_text = await _fetch_metadata_xml(url, trust=trust) if url else pasted
    except ValueError:
        raise
    except Exception as exc:
        log.info("SAML metadata fetch failed for %r: %s: %s", url, type(exc).__name__, exc)
        return _without_metadata_cache(config), False

    try:
        idp_entity_id, _certs = _parse_metadata(xml_text)
    except Exception as exc:
        log.info("SAML metadata parse failed: %s: %s", type(exc).__name__, exc)
        return _without_metadata_cache(config), False

    new_config = dict(config)
    new_config[IDP_METADATA_XML_KEY] = xml_text
    new_config[IDP_ENTITY_ID_KEY] = idp_entity_id
    return new_config, True


def _without_metadata_cache(config: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in config.items() if k not in (IDP_METADATA_XML_KEY, IDP_ENTITY_ID_KEY)}


def saml_metadata_ok(config: dict[str, Any]) -> bool:
    return bool(config.get(IDP_METADATA_XML_KEY)) and bool(config.get(IDP_ENTITY_ID_KEY))


async def test_saml_metadata(config: dict[str, Any], *, trust: Trust) -> dict[str, object]:
    """/api/settings/auth/providers/{name}/test for kind=saml. The metadata is
    read without the cache. A failure returns "ok": False with the reason.
    """
    url = config.get("idp_metadata_url") or ""
    pasted = config.get("idp_metadata_xml") or ""
    try:
        xml_text = await _fetch_metadata_xml(url, trust=trust) if url else pasted
    except ValueError as exc:
        return {"ok": False, "detail": str(exc)}
    except Exception as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}

    try:
        _idp_entity_id, certs = _parse_metadata(xml_text)
    except Exception as exc:
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}

    windows: list[str] = []
    for _name, cert_b64 in certs:
        try:
            cert = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
        except Exception as exc:
            log.info("could not parse a signing certificate from metadata: %s", exc)
            continue
        windows.append(f"{cert.not_valid_before_utc.date()} to {cert.not_valid_after_utc.date()}")

    if not windows:
        return {"ok": False, "detail": "IdP metadata has no readable signing certificate"}
    return {"ok": True, "detail": "IdP metadata parsed; signing certificate valid " + "; ".join(windows)}


# --- SP metadata (the public /metadata route) -----------------------------------


def build_sp_metadata_xml(*, entity_id: str, acs_url: str, sp_cert_pem: str) -> str:
    """SP metadata for IdP-side setup: entity id, ACS endpoint, SP
    certificate. The function reads no private key.
    """
    with saml_tempfiles(), tempfile.TemporaryDirectory() as tmp:
        cert_path = Path(tmp) / "sp-cert.pem"
        cert_path.write_text(sp_cert_pem)
        cnf = {
            "entityid": entity_id,
            "service": {
                "sp": {
                    "endpoints": {"assertion_consumer_service": [(acs_url, saml2.BINDING_HTTP_POST)]},
                    "authn_requests_signed": True,
                    "want_assertions_or_response_signed": True,
                }
            },
            "cert_file": str(cert_path),
        }
        config = SPConfig().load(cnf)
        return str(entity_descriptor(config))


# --- SP runtime config, shared by login and the ACS -----------------------------


@contextmanager
def _sp_client(
    *,
    entity_id: str,
    acs_url: str,
    sp_key_pem: str,
    sp_cert_pem: str,
    idp_metadata_xml: str,
    idp_entity_id: str,
):
    """A Saml2Client with this provider's SP keypair and only the entity
    `idp_entity_id` of the cached IdP metadata. An unsigned response is
    rejected. Raises SsoLoginError when the metadata has no IdP entity
    `idp_entity_id`.
    """
    with saml_tempfiles(), tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "sp-key.pem"
        cert_path = Path(tmp) / "sp-cert.pem"
        key_path.write_text(sp_key_pem)
        key_path.chmod(0o600)
        cert_path.write_text(sp_cert_pem)
        cnf = {
            "entityid": entity_id,
            "service": {
                "sp": {
                    "endpoints": {"assertion_consumer_service": [(acs_url, saml2.BINDING_HTTP_POST)]},
                    "authn_requests_signed": True,
                    "want_assertions_signed": False,
                    "want_response_signed": False,
                    "want_assertions_or_response_signed": True,
                    "allow_unsolicited": False,
                }
            },
            # Without this key, pysaml2 drops an attribute that is absent from its bundled maps.
            "allow_unknown_attributes": True,
            "key_file": str(key_path),
            "cert_file": str(cert_path),
            "metadata": {"inline": [idp_metadata_xml]},
        }
        config = SPConfig().load(cnf)
        _keep_only_entity(config.metadata, idp_entity_id)
        yield Saml2Client(config=config)


def _keep_only_entity(mds: Any, idp_entity_id: str) -> None:
    """Delete each entity except `idp_entity_id` from the pysaml2 MetadataStore `mds`."""
    for loaded in mds.metadata.values():
        for other in [eid for eid, _entity in loaded.items() if eid != idp_entity_id]:
            del loaded[other]
    if mds.identity_providers() != [idp_entity_id]:
        raise SsoLoginError(
            f"IdP metadata has no EntityDescriptor with an IDPSSODescriptor for {idp_entity_id!r}"
        )


def _provider_secret(settings: Settings, provider: AuthProvider) -> str:
    key = crypto.dek(settings)
    try:
        provider_secrets = decrypt_secrets(key, provider.secrets) if provider.secrets else {}
    except SecretKeyError as exc:
        raise SsoLoginError(f"provider secret cannot be decrypted: {exc}") from exc
    sp_key_pem = provider_secrets.get(SP_PRIVATE_KEY_SECRET, "")
    if not sp_key_pem:
        raise SsoLoginError(f"provider {provider.name!r} has no SP private key")
    return sp_key_pem


def _cached_idp_metadata(provider: AuthProvider) -> tuple[str, str]:
    idp_metadata_xml = provider.config.get(IDP_METADATA_XML_KEY)
    idp_entity_id = provider.config.get(IDP_ENTITY_ID_KEY)
    if not idp_metadata_xml or not idp_entity_id:
        raise SsoLoginError(f"provider {provider.name!r} has no cached IdP metadata")
    try:
        reject_dtd(idp_metadata_xml, what="cached IdP metadata")
    except ValueError as exc:
        raise SsoLoginError(f"provider {provider.name!r}: {exc}") from exc
    return idp_metadata_xml, idp_entity_id


# --- SP-initiated login: the signed AuthnRequest --------------------------------


async def start_login(
    *, provider: AuthProvider, settings: Settings, entity_id: str, acs_url: str
) -> tuple[str, str]:
    """Build a signed AuthnRequest for the redirect binding.

    Returns (redirect_url, request_id). The caller (app/routes/sso.py) stores
    request_id as a pending auth_state row with kind REQUEST_KIND and an
    expiry of 5 minutes. The ACS consumes the row as the InResponseTo match.
    """
    idp_metadata_xml, idp_entity_id = _cached_idp_metadata(provider)
    sp_key_pem = _provider_secret(settings, provider)
    sp_cert_pem = provider.config.get(SP_CERT_CONFIG_KEY, "")
    if not sp_cert_pem:
        raise SsoLoginError(f"provider {provider.name!r} has no SP certificate")

    def _build() -> tuple[str, str]:
        with _sp_client(
            entity_id=entity_id,
            acs_url=acs_url,
            sp_key_pem=sp_key_pem,
            sp_cert_pem=sp_cert_pem,
            idp_metadata_xml=idp_metadata_xml,
            idp_entity_id=idp_entity_id,
        ) as client:
            request_id, info = client.prepare_for_authenticate(
                entityid=idp_entity_id, binding=saml2.BINDING_HTTP_REDIRECT, sign=True
            )
            redirect_url = dict(info["headers"])["Location"]
            return redirect_url, request_id

    try:
        return await asyncio.to_thread(_build)
    except SsoLoginError:
        raise
    except Exception as exc:
        raise SsoLoginError(f"could not build AuthnRequest: {type(exc).__name__}: {exc}") from exc


# --- the ACS: verify, then provision through the shared path --------------------


def _first(values: object) -> str | None:
    if isinstance(values, list) and values:
        return str(values[0])
    return None


def _parse_saml_time(value: str) -> datetime:
    t = time_util.str_to_time(value)
    return datetime(t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, tzinfo=UTC)


def _audience_is(assertion: Any, entity_id: str) -> bool:
    """True when the assertion has at least 1 AudienceRestriction and each one
    holds `entity_id` as an Audience.

    pysaml2 accepts an assertion that has no AudienceRestriction.
    """
    conditions = getattr(assertion, "conditions", None)
    restrictions = conditions.audience_restriction if conditions else None
    if not restrictions:
        return False
    return all(
        any(audience.text and audience.text.strip() == entity_id for audience in restriction.audience or [])
        for restriction in restrictions
    )


def _check_issuers(authn_resp: Any, idp_entity_id: str) -> None:
    """Raise SsoLoginError unless the Issuer of the Response and the Issuer of
    each assertion of the pysaml2 AuthnResponse `authn_resp` are `idp_entity_id`.

    pysaml2 verifies a signature with the certificates of the Issuer in the
    message.
    """
    response_issuer = authn_resp.issuer()
    if response_issuer != idp_entity_id:
        raise SsoLoginError(
            f"the Issuer of the SAML response is {response_issuer!r}, expected {idp_entity_id!r}"
        )
    if not authn_resp.assertions:
        raise SsoLoginError("the SAML response has no assertion")
    for assertion in authn_resp.assertions:
        issuer = (
            assertion.issuer.text.strip() if assertion.issuer is not None and assertion.issuer.text else ""
        )
        if issuer != idp_entity_id:
            raise SsoLoginError(f"the Issuer of an assertion is {issuer!r}, expected {idp_entity_id!r}")


def _in_response_to(saml_response_b64: str) -> str:
    """The InResponseTo of a base64 SAML response. Raises SsoLoginError for a
    response that is not base64, declares a DTD, is not well-formed XML or has
    no InResponseTo."""
    try:
        raw_xml = base64.b64decode(saml_response_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SsoLoginError(f"SAMLResponse is not valid base64: {exc}") from exc
    try:
        reject_dtd(raw_xml, what="SAMLResponse")
    except ValueError as exc:
        raise SsoLoginError(str(exc)) from exc
    try:
        root = _DET.fromstring(raw_xml)
    except Exception as exc:
        raise SsoLoginError(f"SAMLResponse is not well-formed XML: {exc}") from exc
    in_response_to = root.get("InResponseTo")
    if not in_response_to:
        raise SsoLoginError("SAML response carried no InResponseTo (unsolicited)")
    return str(in_response_to)


async def complete_saml_login(
    *,
    store: Store,
    settings: Settings,
    provider: AuthProvider,
    entity_id: str,
    acs_url: str,
    saml_response_b64: str,
    bound: str | None,
) -> User:
    """Validate the SAML response at the ACS, provision the account
    and return the user to sign in. Raises SsoLoginError for every rejection.

    `bound` is the request id that the SAML cookie of the browser holds. The
    response must answer that request. pysaml2 checks the destination and the
    recipient against `acs_url`. Each assertion must have an
    AudienceRestriction that holds `entity_id`.
    """
    # InResponseTo is read before the signature check.
    in_response_to = await asyncio.to_thread(_in_response_to, saml_response_b64)
    # The check runs before the pending row is consumed.
    if not bound or not hmac.compare_digest(bound, in_response_to):
        raise SsoLoginError("SAML response does not answer a login this browser started")

    now = datetime.now(UTC)
    pending = await store.consume_auth_state(in_response_to, REQUEST_KIND, provider.id, now)
    if pending is None:
        raise SsoLoginError("no matching pending SAML request (unsolicited, expired, or already used)")

    idp_metadata_xml, idp_entity_id = _cached_idp_metadata(provider)
    sp_key_pem = _provider_secret(settings, provider)
    sp_cert_pem = provider.config.get(SP_CERT_CONFIG_KEY, "")
    if not sp_cert_pem:
        raise SsoLoginError(f"provider {provider.name!r} has no SP certificate")

    def _verify():
        with _sp_client(
            entity_id=entity_id,
            acs_url=acs_url,
            sp_key_pem=sp_key_pem,
            sp_cert_pem=sp_cert_pem,
            idp_metadata_xml=idp_metadata_xml,
            idp_entity_id=idp_entity_id,
        ) as client:
            return client.parse_authn_request_response(
                saml_response_b64, saml2.BINDING_HTTP_POST, outstanding={in_response_to: "/"}
            )

    try:
        authn_resp = await asyncio.to_thread(_verify)
    except SsoLoginError:
        raise
    except Exception as exc:
        raise SsoLoginError(f"assertion validation failed: {type(exc).__name__}: {exc}") from exc

    if authn_resp is None or not authn_resp.name_id or not authn_resp.name_id.text:
        raise SsoLoginError("SAML response carried no usable assertion or NameID")
    _check_issuers(authn_resp, idp_entity_id)
    assertions = authn_resp.assertions or [authn_resp.assertion]
    if not all(_audience_is(assertion, entity_id) for assertion in assertions):
        raise SsoLoginError(f"an assertion has no AudienceRestriction that holds {entity_id!r}")

    try:
        replay_expiry = _parse_saml_time(authn_resp.assertion.conditions.not_on_or_after)
    except Exception as exc:
        raise SsoLoginError(f"assertion NotOnOrAfter is not a usable timestamp: {exc}") from exc

    # A second write of one assertion id raises ValueError.
    try:
        await store.create_auth_state(authn_resp.assertion.id, provider.id, SEEN_KIND, {}, replay_expiry)
    except ValueError as exc:
        raise SsoLoginError(f"assertion {authn_resp.assertion.id!r} already used (replay)") from exc

    subject = authn_resp.name_id.text
    ava = authn_resp.ava or {}
    username_attr = provider.config.get("username_attr") or "uid"
    groups_attr = provider.config.get("groups_attr") or "groups"
    preferred_username = _first(ava.get(username_attr))
    groups = set(ava.get(groups_attr) or [])
    email = _first(ava.get("email")) or ""

    user, identity = await sso_flow.provision_and_authorize(
        store=store,
        provider=provider,
        subject=subject,
        email=email,
        preferred_username=preferred_username,
        groups=groups,
    )
    await store.touch_last_login(identity.id, now)
    return user
