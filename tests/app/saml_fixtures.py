"""Fake SAML IdP for the SAML test files."""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import functools
import os
import tempfile
import warnings
import weakref
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from defusedxml import ElementTree as _DET

from hst.app.saml_resources import saml_tempfiles

with warnings.catch_warnings():
    from cryptography.utils import CryptographyDeprecationWarning

    # the import-time warning that app/saml_flow.py also filters by name
    warnings.simplefilter("ignore", CryptographyDeprecationWarning)
    # Match the application's narrow xmlschema import compatibility on Python 3.14.
    warnings.filterwarnings(
        "ignore",
        message=(
            r"pathlib\.PurePath\.as_uri\(\) is deprecated and scheduled for removal in Python 3\.19\. "
            r"Use pathlib\.Path\.as_uri\(\)\."
        ),
        category=DeprecationWarning,
        module=r"xmlschema\.resources",
    )
    from saml2 import BINDING_HTTP_REDIRECT
    from saml2.assertion import Policy
    from saml2.config import IdPConfig
    from saml2.s_utils import decode_base64_and_inflate
    from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, Audience, AudienceRestriction, NameID
    from saml2.server import Server

IDP_ENTITY_ID = "https://idp.example/saml"
IDP_SSO_URL = "https://idp.example/saml/sso"
IDP_METADATA_URL = "https://idp.example/saml/metadata"


# Fixed inputs for the fixture's signing certificate
_FIXED_SERIAL_NUMBER = 0x4A5A5A6172656E6B6F  # under the 20-octet cap of RFC 5280
_FIXED_NOT_VALID_BEFORE = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
_FIXED_NOT_VALID_AFTER = dt.datetime(2099, 1, 1, tzinfo=dt.UTC)


@functools.cache
def _generate_keypair(cn: str) -> tuple[str, str]:
    """Built once per CN for the whole test session (see the cache)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_FIXED_SERIAL_NUMBER)
        .not_valid_before(_FIXED_NOT_VALID_BEFORE)
        .not_valid_after(_FIXED_NOT_VALID_AFTER)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def _strip_pem(pem: str) -> str:
    return "".join(line for line in pem.strip().splitlines() if "BEGIN" not in line and "END" not in line)


def _write_temp_pem(content: str) -> str:
    if not content.endswith("\n"):
        content += "\n"
    fd, path = tempfile.mkstemp(suffix=".pem")
    # the `with` block closes fh before `path` is returned
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


def _remove_temp_pem(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        Path(path).unlink()


def authn_request(redirect_url: str):
    """The root element of the app's AuthnRequest, read from the SAMLRequest
    query parameter of the redirect binding."""
    qs = parse_qs(urlsplit(redirect_url).query)
    return _DET.fromstring(decode_base64_and_inflate(qs["SAMLRequest"][0]))


def extract_authn_request_id(redirect_url: str) -> str:
    request_id = authn_request(redirect_url).get("ID")
    assert request_id is not None
    return request_id


@dataclass
class FakeSamlIdp:
    entity_id: str = IDP_ENTITY_ID
    sso_url: str = IDP_SSO_URL
    metadata_url: str = IDP_METADATA_URL
    key_cn: str = "idp.example"
    calls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._key_pem, self._cert_pem = _generate_keypair(self.key_cn)
        # the temp files are removed when the instance is garbage collected
        self._key_path = _write_temp_pem(self._key_pem)
        self._cert_path = _write_temp_pem(self._cert_pem)
        weakref.finalize(self, _remove_temp_pem, self._key_path)
        weakref.finalize(self, _remove_temp_pem, self._cert_path)

    def metadata_xml(self) -> str:
        cert_b64 = _strip_pem(self._cert_pem)
        return (
            '<?xml version="1.0"?>'
            f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{self.entity_id}">'
            '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f"<ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>"
            "</ds:KeyInfo></KeyDescriptor>"
            '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            f'Location="{self.sso_url}"/>'
            "</IDPSSODescriptor></EntityDescriptor>"
        )

    def entity_descriptor_xml(self) -> str:
        """The EntityDescriptor of metadata_xml, without the XML declaration."""
        return self.metadata_xml().removeprefix('<?xml version="1.0"?>')

    def generate_other_keypair(self) -> tuple[str, str]:
        """A second keypair, for the tampered and wrong-signer test."""
        return _generate_keypair("attacker.example")

    @staticmethod
    def _trivial_sp_metadata(sp_entity_id: str, acs_url: str) -> str:
        """A minimal SPSSODescriptor for the SP entity id."""
        return (
            '<?xml version="1.0"?>'
            f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{sp_entity_id}">'
            '<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f'Location="{acs_url}" index="0"/>'
            "</SPSSODescriptor></EntityDescriptor>"
        )

    def _server(self, *, sp_entity_id: str, acs_url: str, lifetime_seconds: int) -> Server:
        cnf = {
            "entityid": self.entity_id,
            "service": {
                "idp": {
                    "endpoints": {"single_sign_on_service": [(self.sso_url, BINDING_HTTP_REDIRECT)]},
                    "policy": {"default": {"lifetime": {"seconds": lifetime_seconds}}},
                }
            },
            "key_file": self._key_path,
            "cert_file": self._cert_path,
            "metadata": {"inline": [self._trivial_sp_metadata(sp_entity_id, acs_url)]},
        }
        return Server(config=IdPConfig().load(cnf))

    @saml_tempfiles()
    def create_signed_response(
        self,
        *,
        sp_entity_id: str,
        acs_url: str,
        in_response_to: str,
        name_id: str,
        attributes: dict[str, list[str]] | None = None,
        sign_assertion: bool = True,
        sign_response: bool = False,
        lifetime_seconds: int = 3600,
        audiences: Sequence[str] | None = None,
    ) -> str:
        """An xmlsec1-signed SAML Response, base64-encoded, for the
        SAMLResponse form field of an ACS POST. A negative `lifetime_seconds`
        gives an expired assertion.

        The assertion has 1 AudienceRestriction per entry of `audiences`, and
        none for an empty sequence. None gives 1 AudienceRestriction that
        holds `sp_entity_id`."""
        server = self._server(sp_entity_id=sp_entity_id, acs_url=acs_url, lifetime_seconds=lifetime_seconds)
        nid = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=name_id)
        build_conditions = Policy.conditions

        def conditions(policy: Policy, entity_id: str):
            built = build_conditions(policy, entity_id)
            if audiences is not None:
                built.audience_restriction = [
                    AudienceRestriction(audience=[Audience(text=audience)]) for audience in audiences
                ]
            return built

        with patch.object(Policy, "conditions", conditions):
            resp = server.create_authn_response(
                identity=attributes or {},
                in_response_to=in_response_to,
                destination=acs_url,
                sp_entity_id=sp_entity_id,
                userid=name_id,
                name_id=nid,
                sign_response=sign_response,
                sign_assertion=sign_assertion,
                authn={
                    "class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
                    "authn_auth": self.entity_id,
                },
            )
        return base64.b64encode(str(resp).encode()).decode()

    @saml_tempfiles()
    def create_signed_response_with_key(
        self,
        *,
        sp_entity_id: str,
        acs_url: str,
        in_response_to: str,
        name_id: str,
        signing_key_pem: str,
        signing_cert_pem: str,
        attributes: dict[str, list[str]] | None = None,
    ) -> str:
        """create_signed_response, signed by an arbitrary keypair."""
        key_path = _write_temp_pem(signing_key_pem)
        cert_path = _write_temp_pem(signing_cert_pem)
        try:
            cnf = {
                "entityid": self.entity_id,
                "service": {
                    "idp": {"endpoints": {"single_sign_on_service": [(self.sso_url, BINDING_HTTP_REDIRECT)]}}
                },
                "key_file": key_path,
                "cert_file": cert_path,
                "metadata": {"inline": [self._trivial_sp_metadata(sp_entity_id, acs_url)]},
            }
            server = Server(config=IdPConfig().load(cnf))
            nid = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=name_id)
            resp = server.create_authn_response(
                identity=attributes or {},
                in_response_to=in_response_to,
                destination=acs_url,
                sp_entity_id=sp_entity_id,
                userid=name_id,
                name_id=nid,
                sign_response=False,
                sign_assertion=True,
                authn={
                    "class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
                    "authn_auth": self.entity_id,
                },
            )
            return base64.b64encode(str(resp).encode()).decode()
        finally:
            _remove_temp_pem(key_path)
            _remove_temp_pem(cert_path)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(f"{request.method} {request.url.path}")
        if request.url.path == urlsplit(self.metadata_url).path:
            return httpx.Response(200, text=self.metadata_xml(), headers={"content-type": "application/xml"})
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
