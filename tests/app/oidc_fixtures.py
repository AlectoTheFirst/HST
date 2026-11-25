"""Fake OIDC IdP for the OIDC test files: an RSA key, its JWKS, and an
httpx.MockTransport handler serving discovery, token and userinfo."""

from __future__ import annotations

import json
import time
import warnings
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from authlib.jose import JsonWebKey, jwt

ISSUER = "https://idp.example"
CLIENT_ID = "hst-client"
CLIENT_SECRET = "s3cr3t-client-secret"
KID = "test-key-1"


@dataclass
class FakeIdp:
    issuer: str = ISSUER
    client_id: str = CLIENT_ID
    client_secret: str = CLIENT_SECRET
    kid: str = KID
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=lambda: ["client_secret_basic"])
    token_status: int = 200
    userinfo_status: int = 200
    userinfo_body: dict[str, Any] = field(default_factory=dict)
    # set by the test before it drives the callback
    pending_id_token: str = ""
    calls: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            self._jwk = JsonWebKey.import_key(pem, {"kid": self.kid, "alg": "RS256"})
        self._jwks = {"keys": [json.loads(self._jwk.as_json(is_private=False))]}

    def discovery_document(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/jwks",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "token_endpoint_auth_methods_supported": self.token_endpoint_auth_methods_supported,
        }

    def jwks(self) -> dict[str, Any]:
        return self._jwks

    def rotate_key(self, *, new_kid: str = "test-key-2") -> None:
        """A new key and kid replace the current ones in the published JWKS."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            self._jwk = JsonWebKey.import_key(pem, {"kid": new_kid, "alg": "RS256"})
        self.kid = new_kid
        self._jwks = {"keys": [json.loads(self._jwk.as_json(is_private=False))]}

    def sign_id_token(self, claims: dict[str, Any], *, kid: str | None = None) -> str:
        header = {"alg": "RS256", "kid": kid if kid is not None else self.kid}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            token = jwt.encode(header, claims, self._jwk)
        return token.decode() if isinstance(token, bytes) else token

    def claims(self, *, nonce: str, sub: str = "user-1", **extra: Any) -> dict[str, Any]:
        now = int(time.time())
        base = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": sub,
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
        }
        base.update(extra)
        return base

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(f"{request.method} {request.url.path}")
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=self.discovery_document())
        if path == "/jwks":
            return httpx.Response(200, json=self.jwks())
        if path == "/token":
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "server_error"})
            return httpx.Response(
                200,
                json={"access_token": "at-1", "token_type": "Bearer", "id_token": self.pending_id_token},
            )
        if path == "/userinfo":
            return httpx.Response(self.userinfo_status, json=self.userinfo_body)
        return httpx.Response(404, json={"error": "not found"})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
