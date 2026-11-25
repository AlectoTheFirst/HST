"""Exercise the real SDK's Runtime URL, payload and authentication offline."""

import json
from urllib.parse import unquote

import anthropic
import httpx2
import pytest

from hst.app.agent.anthropic_ import AnthropicAdapter, probe
from hst.app.agent.base import AgentError
from hst.app.agent.registry import HOST_CREDENTIALS_DETAIL


@pytest.mark.parametrize(
    "model",
    [
        "eu.anthropic.claude-opus-5-5",
        "arn:aws:bedrock:eu-central-1:123456789012:inference-profile/eu.anthropic.claude-opus-5-5",
        "arn:aws:bedrock:eu-central-1:123456789012:application-inference-profile/example",
    ],
)
@pytest.mark.parametrize("mode", ["api_key", "keys", "assume", "ambient"])
@pytest.mark.parametrize("operation", ["probe", "ask"])
def test_runtime_request_preserves_profile_and_auth(monkeypatch, model, mode, operation):
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.delenv("ANTHROPIC_BEDROCK_BASE_URL", raising=False)
    options = {"aws_region": "eu-central-1"}
    credentials = {}
    if mode == "api_key":
        credentials = {"aws_bedrock_api_key": "ABSK-test"}
    elif mode == "keys":
        credentials = {
            "aws_access_key_id": "AKIA-test",
            "aws_secret_access_key": "test-secret",
            "aws_session_token": "test-session",
        }
    elif mode == "assume":
        options["aws_role_arn"] = "arn:aws:iam::123456789012:role/test"
        monkeypatch.setattr(
            AnthropicAdapter,
            "_assume_role",
            lambda self, region: {
                "AccessKeyId": "ASIA-test",
                "SecretAccessKey": "test-secret",
                "SessionToken": "test-session",
            },
        )
    else:
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-ambient")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
        monkeypatch.setenv("AWS_SESSION_TOKEN", "test-session")

    requests = []

    def respond(request):
        requests.append(request)
        return httpx2.Response(
            200,
            json={
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    with anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(respond)) as http:
        monkeypatch.setattr(AnthropicAdapter, "_http_client", lambda *args: {"http_client": http})
        if operation == "probe":
            probe("bedrock", credentials, options, model)
        else:
            answer = AnthropicAdapter("bedrock", credentials, options).ask(
                "test", system="test", tools=[], model=model, effort="high"
            )
            assert answer.answer == "ok"

    assert len(requests) == 1
    request = requests[0]
    assert request.url.host == "bedrock-runtime.eu-central-1.amazonaws.com"
    assert unquote(request.url.path) == f"/model/{model}/invoke"
    if model.startswith("arn:"):
        assert b"%2F" in request.url.raw_path
    body = json.loads(request.content)
    assert body["anthropic_version"] == "2026-10-21"
    assert "model" not in body
    assert "fallbacks" not in body
    assert body["messages"][0]["role"] == "user"
    if operation == "ask":
        assert body["output_config"] == {"effort": "high"}
    auth = request.headers["Authorization"]
    if mode == "api_key":
        assert auth == "Bearer ABSK-test"
        assert "X-Amz-Security-Token" not in request.headers
    else:
        assert auth.startswith("AWS4-HMAC-SHA256 ")
        assert "/eu-central-1/bedrock/aws4_request" in auth
        assert request.headers["X-Amz-Security-Token"] == "test-session"
        key = {"keys": "AKIA-test", "assume": "ASIA-test", "ambient": "AKIA-ambient"}[mode]
        assert f"Credential={key}/" in auth


_MESSAGE = {
    "id": "msg_test",
    "type": "message",
    "role": "assistant",
    "model": "m",
    "content": [{"type": "text", "text": "ok"}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 1, "output_tokens": 1},
}
_KEYS = {"aws_access_key_id": "AKIA-own", "aws_secret_access_key": "own-secret"}
_VPC_ENDPOINT = "https://vpce-0abc.bedrock-runtime.eu-central-1.vpce.amazonaws.com"
_ROLE = "arn:aws:iam::123456789012:role/test"


@pytest.fixture
def runtime(monkeypatch):
    """The requests of the Bedrock SDK client. Each one gets a message.

    The environment holds the credentials of the host. `_assume_role` fails the test.
    """
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    monkeypatch.delenv("ANTHROPIC_BEDROCK_BASE_URL", raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA-ambient")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "test-session")
    monkeypatch.setattr(AnthropicAdapter, "_assume_role", lambda *args: pytest.fail("STS was called"))
    requests: list[httpx2.Request] = []

    def respond(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        return httpx2.Response(200, json=_MESSAGE)

    with anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(respond)) as http:
        monkeypatch.setattr(AnthropicAdapter, "_http_client", lambda *args: {"http_client": http})
        yield requests


@pytest.mark.parametrize("region", ["eu-central-1", "us-gov-west-1"])
def test_the_request_goes_to_the_runtime_host_of_the_region(runtime, region):
    probe("bedrock", {}, {"aws_region": region}, "m")

    assert [request.url.host for request in runtime] == [f"bedrock-runtime.{region}.amazonaws.com"]
    assert f"/{region}/bedrock/aws4_request" in runtime[0].headers["Authorization"]


@pytest.mark.parametrize(
    "base_url",
    [_VPC_ENDPOINT, "https://bedrock-runtime-fips.eu-central-1.amazonaws.com"],
    ids=["vpc endpoint", "fips"],
)
def test_host_credentials_sign_a_request_to_a_runtime_endpoint_base_url(runtime, base_url):
    probe("bedrock", {}, {"aws_region": "eu-central-1", "base_url": base_url}, "m")

    assert [str(request.url) for request in runtime] == [f"{base_url}/model/m/invoke"]
    auth = runtime[0].headers["Authorization"]
    assert "Credential=AKIA-ambient/" in auth
    assert "/eu-central-1/bedrock/aws4_request" in auth
    assert "host;" in auth.partition("SignedHeaders=")[2]


@pytest.mark.parametrize(
    ("credentials", "authorization"),
    [
        (_KEYS, "AWS4-HMAC-SHA256 Credential=AKIA-own/"),
        ({"aws_bedrock_api_key": "ABSK-own"}, "Bearer ABSK-own"),
    ],
    ids=["keys", "api key"],
)
def test_a_stored_credential_goes_to_a_gateway_base_url(runtime, credentials, authorization):
    options = {"aws_region": "eu-central-1", "base_url": "https://gw.example/bedrock"}
    probe("bedrock", credentials, options, "m")

    assert [str(request.url) for request in runtime] == ["https://gw.example/bedrock/model/m/invoke"]
    assert runtime[0].headers["Authorization"].startswith(authorization)


@pytest.mark.parametrize(
    "options",
    [
        {"base_url": "https://gw.example"},
        {"base_url": "https://bedrock-runtime.eu-west-1.amazonaws.com"},
        {"base_url": "https://bedrock-runtime.eu-central-1.amazonaws.com.gw.example"},
        {"base_url": "https://gw.example", "aws_role_arn": _ROLE},
    ],
    ids=["gateway", "other region", "suffix", "assumed role"],
)
@pytest.mark.parametrize("bearer_token", [None, "ABSK-host"], ids=["sigv4", "bearer token of the host"])
@pytest.mark.parametrize("operation", ["probe", "ask"])
def test_host_credentials_send_no_request_to_another_base_url(
    runtime, monkeypatch, options, bearer_token, operation
):
    if bearer_token:
        monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", bearer_token)
    options = {"aws_region": "eu-central-1", **options}

    with pytest.raises(AgentError, match=HOST_CREDENTIALS_DETAIL):
        if operation == "probe":
            probe("bedrock", {}, options, "m")
        else:
            AnthropicAdapter("bedrock", {}, options).ask("q", system="s", tools=[], model="m", effort="high")
    assert runtime == []


@pytest.mark.parametrize("region", ["x.evil.example/", "eu-central-1.evil.example", "eu-central-1/"])
@pytest.mark.parametrize("credentials", [{}, _KEYS, {"aws_bedrock_api_key": "ABSK-own"}])
def test_a_region_that_is_no_region_name_sends_no_request(runtime, region, credentials):
    with pytest.raises(AgentError, match="aws_region must be an AWS region name"):
        probe("bedrock", credentials, {"aws_region": region}, "m")
    assert runtime == []


@pytest.mark.parametrize(
    "base_url",
    [
        "https://bedrock-runtime.eu-central-1.amazonaws.com@gw.example",
        "https://user:password@gw.example",
        "http://bedrock-runtime.eu-central-1.amazonaws.com",
    ],
)
def test_a_base_url_with_a_user_part_or_without_https_sends_no_request(runtime, base_url):
    with pytest.raises(AgentError, match="base_url must"):
        probe("bedrock", _KEYS, {"aws_region": "eu-central-1", "base_url": base_url}, "m")
    assert runtime == []


def test_a_probe_fails_for_a_reply_with_status_200_that_is_no_message(monkeypatch):
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    page = httpx2.Response(200, text="<html>sign in</html>", headers={"content-type": "text/html"})
    with anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(lambda request: page)) as http:
        monkeypatch.setattr(AnthropicAdapter, "_http_client", lambda *args: {"http_client": http})
        with pytest.raises(AgentError, match="the provider reply is not a message"):
            probe("bedrock", {"aws_bedrock_api_key": "ABSK-own"}, {"aws_region": "eu-central-1"}, "m")
