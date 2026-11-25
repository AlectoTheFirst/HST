from __future__ import annotations

import ssl
from pathlib import Path
from types import SimpleNamespace

import pytest

from hst.app import tls
from hst.app.agent.anthropic_ import AnthropicAdapter
from hst.app.agent.openrouter import OpenRouterAdapter
from hst.app.saml_flow import generate_sp_keypair
from hst.app.tls import Trust

_SERVER_DEFAULT = SimpleNamespace(tls_verify=True, tls_ca_bundle="")


def _self_signed_pem() -> str:
    """A well-formed certificate; what it certifies does not matter here."""
    return generate_sp_keypair()[1]


def test_default_trust_leaves_the_sdk_alone():
    trust = tls.resolve(_SERVER_DEFAULT, {})
    assert trust.is_default
    assert trust.ssl_verify() is True
    with trust.ca_file_path() as verify:
        assert verify is None


def test_server_wide_skip_applies_when_the_row_says_nothing():
    trust = tls.resolve(SimpleNamespace(tls_verify=False, tls_ca_bundle=""), {})
    assert trust.verify is False
    assert trust.ssl_verify() is False
    with trust.ca_file_path() as verify:
        assert verify is False


def test_row_skip_overrides_a_verifying_server():
    for value in ("true", "True", "1", "on", True):
        trust = tls.resolve(_SERVER_DEFAULT, {tls.SKIP_VERIFY: value})
        assert trust.verify is False, value
    for value in ("", "false", "0", None, False):
        assert tls.resolve(_SERVER_DEFAULT, {tls.SKIP_VERIFY: value}).verify is True, value


def test_server_bundle_path_becomes_an_ssl_context(tmp_path: Path):
    bundle = tmp_path / "proxy-ca.pem"
    bundle.write_text(_self_signed_pem())
    trust = tls.resolve(SimpleNamespace(tls_verify=True, tls_ca_bundle=str(bundle)), {})
    assert not trust.is_default
    assert isinstance(trust.ssl_verify(), ssl.SSLContext)
    with trust.ca_file_path() as verify:
        assert verify == str(bundle)


def test_row_pem_wins_over_the_server_bundle_and_is_written_for_boto_only_briefly(tmp_path: Path):
    bundle = tmp_path / "proxy-ca.pem"
    bundle.write_text("not read")
    pem = _self_signed_pem().strip()
    trust = tls.resolve(SimpleNamespace(tls_verify=True, tls_ca_bundle=str(bundle)), {tls.CA_BUNDLE: pem})
    assert trust.ca_pem == pem
    assert isinstance(trust.ssl_verify(), ssl.SSLContext)
    with trust.ca_file_path() as verify:
        assert isinstance(verify, str) and verify != str(bundle)
        assert Path(verify).read_text() == pem
        written = Path(verify)
    assert not written.exists()


def test_a_skip_beats_any_bundle():
    trust = tls.resolve(_SERVER_DEFAULT, {tls.SKIP_VERIFY: "true", tls.CA_BUNDLE: _self_signed_pem()})
    assert trust.ssl_verify() is False
    with trust.ca_file_path() as verify:
        assert verify is False


def test_validate_ca_bundle_rejects_text_that_is_not_a_certificate():
    with pytest.raises(ValueError, match="tls_ca_bundle"):
        tls.validate_ca_bundle("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
    tls.validate_ca_bundle(_self_signed_pem())


# --- how the trust reaches each SDK ----------------------------------------------


class _FakeAnthropic:
    """Records what each client constructor received."""

    def __init__(self) -> None:
        self.calls: dict[str, dict] = {}

    def DefaultHttpxClient(self, **kwargs):
        self.calls["http"] = kwargs
        return "http-client"

    def AnthropicBedrock(self, **kwargs):
        self.calls["bedrock"] = kwargs
        return object()


def test_bedrock_client_gets_an_http_client_only_when_trust_is_not_default():
    fake = _FakeAnthropic()
    AnthropicAdapter("bedrock", {}, {"aws_region": "eu-central-1"}, Trust())._bedrock_client(fake)
    assert "http_client" not in fake.calls["bedrock"]

    fake = _FakeAnthropic()
    AnthropicAdapter("bedrock", {}, {"aws_region": "eu-central-1"}, Trust(verify=False))._bedrock_client(fake)
    assert fake.calls["http"] == {"verify": False}
    assert fake.calls["bedrock"]["http_client"] == "http-client"


def test_assume_role_passes_the_ca_to_sts(monkeypatch):
    seen: dict = {}

    class _Sts:
        def assume_role(self, **kwargs):
            return {"Credentials": {"AccessKeyId": "A", "SecretAccessKey": "S", "SessionToken": "T"}}

    def fake_client(service, **kwargs):
        seen.update(service=service, **kwargs)
        return _Sts()

    import boto3

    monkeypatch.setattr(boto3, "client", fake_client)
    pem = _self_signed_pem()
    adapter = AnthropicAdapter(
        "bedrock", {}, {"aws_region": "us-east-1", "aws_role_arn": "arn:aws:iam::1:role/r"}, Trust(ca_pem=pem)
    )
    adapter._assume_role("us-east-1")
    assert seen["service"] == "sts"
    assert isinstance(seen["verify"], str)  # a path, gone again after the call
    assert not Path(seen["verify"]).exists()

    seen.clear()
    AnthropicAdapter("bedrock", {}, {"aws_role_arn": "arn:x"}, Trust(verify=False))._assume_role("us-east-1")
    assert seen["verify"] is False


def test_openrouter_client_gets_an_http_client_only_when_trust_is_not_default(monkeypatch):
    import openai

    seen: dict = {}
    monkeypatch.setattr(openai, "DefaultHttpxClient", lambda **kw: seen.update(http=kw) or "http-client")
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: seen.update(client=kw) or object())

    OpenRouterAdapter({"api_key": "k"}, {}, Trust())._client()
    assert "http_client" not in seen["client"] and "http" not in seen

    seen.clear()
    OpenRouterAdapter({"api_key": "k"}, {}, Trust(verify=False))._client()
    assert seen["http"] == {"verify": False}
    assert seen["client"]["http_client"] == "http-client"
