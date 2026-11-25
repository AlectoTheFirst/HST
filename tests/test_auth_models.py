"""The shared credential vocabulary: what validates, what does not."""

import pytest
from pydantic import SecretStr, TypeAdapter, ValidationError

from hst.collectors.auth import (
    ApiKeyCredential,
    ClientCert,
    OAuthClientCredentials,
    SshAgent,
    SshAuth,
    SshJumpHost,
    SshPassword,
    SshPrivateKey,
    TlsConfig,
    UserPassword,
)


def test_ssh_password_roundtrips():
    a = SshPassword(username="admin", password="pw")
    assert a.method == "password" and a.password.get_secret_value() == "pw"


def test_ssh_private_key_passphrase_defaults_empty():
    a = SshPrivateKey(username="admin", private_key="-----BEGIN-----")
    assert a.passphrase.get_secret_value() == ""


def test_ssh_agent_needs_only_a_username():
    assert SshAgent(username="admin").method == "agent"


def test_jump_host_carries_its_own_credentials():
    """The bastion is a peer of the device: its own auth, port and pinned key.
    The device's credentials are never offered to it."""
    j = SshJumpHost(host="bastion", auth={"method": "password", "username": "hop", "password": "pw"})
    assert j.port == 22 and j.host_key == ""
    assert isinstance(j.auth, SshPassword)
    with pytest.raises(ValidationError):
        SshJumpHost(host="bastion")  # a bastion with no credentials of its own


@pytest.mark.parametrize(
    "payload",
    [
        {"method": "password", "username": "admin"},  # no password
        {"method": "password", "username": "", "password": "pw"},  # blank username
        {"method": "password", "username": "admin", "password": ""},  # blank password
        {"method": "private_key", "private_key": "pem"},  # no username
    ],
)
def test_partial_ssh_credentials_are_rejected(payload):
    with pytest.raises(ValidationError):
        TypeAdapter(SshAuth).validate_python(payload)


def test_ssh_auth_union_selects_by_method():
    a = TypeAdapter(SshAuth).validate_python(
        {"method": "private_key", "username": "admin", "private_key": "pem"}
    )
    assert isinstance(a, SshPrivateKey)


def test_http_credentials_reject_blank_secrets():
    for model, payload in [
        (UserPassword, {"username": "u", "password": ""}),
        (ApiKeyCredential, {"key": ""}),
        (OAuthClientCredentials, {"client_id": "id", "client_secret": ""}),
    ]:
        with pytest.raises(ValidationError):
            model(**payload)


def test_tls_defaults_to_verifying():
    t = TlsConfig()
    assert t.verify is True and t.ca_bundle == ""


def test_tls_verify_false_is_allowed():
    assert TlsConfig(verify=False).verify is False


def test_the_ca_bundle_is_not_a_secret():
    assert TlsConfig.model_fields["ca_bundle"].annotation is str


def test_the_client_cert_pem_is_not_a_secret():
    """The certificate is public material, same rule as ca_bundle."""
    assert ClientCert.model_fields["cert"].annotation is str


def test_the_client_key_is_sealed_like_any_other_secret():
    """app/sources.py:secret_paths seals each `SecretStr` field."""
    assert ClientCert.model_fields["key"].annotation is SecretStr


def test_tls_client_cert_defaults_absent():
    """app/sources.py's secret-path walk treats a set value as mTLS configured."""
    assert TlsConfig().client_cert is None


def test_client_cert_needs_both_cert_and_key():
    # tools/check_no_run_data.py's key scan rejects a literal PEM header.
    with pytest.raises(ValidationError):
        ClientCert(cert="cert-pem")
    with pytest.raises(ValidationError):
        ClientCert(key="key-pem")
