"""Credential vocabulary shared by every collector."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field, SecretStr


def _nonempty(value: SecretStr) -> SecretStr:
    if not value.get_secret_value():
        raise ValueError("must not be empty")
    return value


RequiredSecret = Annotated[SecretStr, AfterValidator(_nonempty)]
NonEmptyStr = Annotated[str, Field(min_length=1)]


class SshPassword(BaseModel):
    method: Literal["password"] = "password"
    username: NonEmptyStr
    password: RequiredSecret


class SshPrivateKey(BaseModel):
    method: Literal["private_key"] = "private_key"
    username: NonEmptyStr
    private_key: RequiredSecret  # PEM text of the key
    passphrase: SecretStr = SecretStr("")


class SshAgent(BaseModel):
    method: Literal["agent"] = "agent"
    username: NonEmptyStr


SshAuth = Annotated[SshPassword | SshPrivateKey | SshAgent, Field(discriminator="method")]


class SshJumpHost(BaseModel):
    """A bastion with its own address, port, credentials and pinned host key.

    The credentials of the device are never sent to the bastion. The host key
    is pinned at the first contact.
    """

    host: NonEmptyStr
    port: int = 22
    auth: SshAuth
    host_key: str = ""  # empty before the first contact, then the pinned key


class UserPassword(BaseModel):
    method: Literal["user_password"] = "user_password"
    username: NonEmptyStr
    password: RequiredSecret


class ApiKeyCredential(BaseModel):
    method: Literal["api_key"] = "api_key"
    key: RequiredSecret


class OAuthClientCredentials(BaseModel):
    method: Literal["oauth_client"] = "oauth_client"
    client_id: NonEmptyStr
    client_secret: RequiredSecret


class ClientCert(BaseModel):
    """A client certificate and its key for mutual TLS, both as PEM text.

    The two fields are required together. `key` is sealed as a source secret.
    """

    cert: NonEmptyStr  # public PEM certificate chain
    key: RequiredSecret  # PEM private key, sealed as a secret


class TlsConfig(BaseModel):
    """Trust material for an HTTPS backend.

    `verify=False` turns off the check of the server certificate.

    `client_cert` adds mutual TLS, for example for APIC and Check Point. It is
    an optional block. `secret_paths_for_payload` in `app/sources.py` skips an
    absent block, so a source without mutual TLS asks for no key.
    """

    verify: bool = True
    ca_bundle: str = ""  # public PEM trust anchor
    client_cert: ClientCert | None = None
