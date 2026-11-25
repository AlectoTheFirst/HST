"""Ask-AI agent: settings, credential handling, role gating, and the ask loop.

No test here reaches a provider. The adapters are exercised against stub clients
that mimic the two wire shapes, so the tool loop, the refusal path and the role
gate are all covered without an API key or a network.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.twin_tools_fakes import FakeGraph, install
from tests.twin_tools_fakes import settings as fake_settings

import hst.app.routes.ai as ai_routes
from hst.app.agent import base as agent_base
from hst.app.agent import context as agent_context
from hst.app.agent import registry
from hst.app.agent import tools as tools_mod
from hst.app.agent.anthropic_ import AnthropicAdapter
from hst.app.agent.openrouter import OpenRouterAdapter
from hst.app.agent.tools import Tool
from hst.app.ai.registry import Principal, ToolContext
from hst.app.crypto import SecretKeyError, generate_key
from hst.app.main import create_app
from hst.core import Settings
from hst.core import db as db_mod
from hst.core import snapshot as snapshot_mod


@pytest.fixture
def app(seeded):
    # a real Fernet key: the settings route seals credentials the same way
    # source credentials are sealed
    return create_app(settings=Settings(_env_file=None, hst_secret_key=generate_key()), store=seeded)


# --- settings API -------------------------------------------------------------


async def test_settings_are_admin_only(client):
    await login(client, "otto")
    assert (await client.get("/api/settings/ai")).status_code == 403
    assert (await client.get("/api/settings/ai/providers")).status_code == 403
    assert (
        await client.put(
            "/api/settings/ai", json={"enabled": True, "provider": "anthropic", "model": "claude-opus-5"}
        )
    ).status_code == 403


async def test_defaults_before_anything_is_stored(client):
    await login(client, "ada")
    body = (await client.get("/api/settings/ai")).json()
    assert body["enabled"] is False
    assert body["configured"] is False
    assert body["stored_credentials"] == []
    # no site instructions: the fixed prompt layers apply on their own
    assert body["system_prompt"] == ""
    assert body["prompt_mode"] == "append"


async def test_provider_descriptors_drive_the_form(client):
    await login(client, "ada")
    body = (await client.get("/api/settings/ai/providers")).json()
    ids = [p["id"] for p in body["providers"]]
    assert ids == ["anthropic", "bedrock", "openrouter"]
    # effort is an Anthropic-family control; OpenRouter has no equivalent
    by_id = {p["id"]: p for p in body["providers"]}
    assert by_id["anthropic"]["supports_effort"] is True
    assert by_id["openrouter"]["supports_effort"] is False
    # Runtime suggestions use cross-region inference profiles.
    assert by_id["bedrock"]["models"] == [
        "eu.anthropic.claude-opus-5-5",
        "global.anthropic.claude-sonnet-5-5",
    ]


async def test_api_key_is_write_only(client):
    await login(client, "ada")
    await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "credentials": {"api_key": "sk-ant-secret"},
        },
    )

    body = (await client.get("/api/settings/ai")).json()
    assert body["stored_credentials"] == ["api_key"]
    assert body["configured"] is True
    # the value itself must never come back out
    assert "sk-ant-secret" not in json.dumps(body)


async def test_omitting_credentials_keeps_the_stored_one(client):
    """Editing the model or the prompt must not require re-entering the key."""
    await login(client, "ada")
    await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "credentials": {"api_key": "sk-ant-secret"},
        },
    )

    r = await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-sonnet-5",
            "system_prompt": "be terse",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["model"] == "claude-sonnet-5"
    assert body["system_prompt"] == "be terse"
    # a save without a mode stores the text as site instructions
    assert body["prompt_mode"] == "append"
    assert body["configured"] is True, "the stored key was dropped"


async def test_unknown_provider_is_rejected(client):
    await login(client, "ada")
    r = await client.put("/api/settings/ai", json={"enabled": True, "provider": "skynet", "model": "x"})
    assert r.status_code == 400


async def test_a_null_credential_clears_the_stored_secret(client):
    """Blank means keep; an explicit null is the only way to delete a key
    without replacing it."""
    await login(client, "ada")
    base = {"enabled": True, "provider": "anthropic", "model": "claude-opus-5"}
    await client.put("/api/settings/ai", json={**base, "credentials": {"api_key": "sk-ant-secret"}})

    r = await client.put("/api/settings/ai", json={**base, "credentials": {"api_key": ""}})
    assert r.json()["stored_credentials"] == ["api_key"]  # blank kept it

    r = await client.put("/api/settings/ai", json={**base, "credentials": {"api_key": None}})
    assert r.status_code == 200
    body = r.json()
    assert body["stored_credentials"] == []
    assert body["configured"] is False
    assert (await client.get("/api/settings/ai")).json()["stored_credentials"] == []


# --- unreadable stored credentials ---------------------------------------------
#


async def test_get_degrades_on_unreadable_secrets(client, seeded):
    await login(client, "ada")
    await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "effort": "low",
            "system_prompt": "be terse",
            "credentials": {"api_key": "sk-ant-secret"},
        },
    )
    row = await seeded.get_setting(registry.SETTINGS_KEY)
    row.secrets = b"garbage-not-a-fernet-token"

    r = await client.get("/api/settings/ai")
    assert r.status_code == 200
    body = r.json()
    assert body["secrets_unreadable"] is True
    assert body["stored_credentials"] == []
    assert body["configured"] is False
    # everything else survives the degrade
    assert body["provider"] == "anthropic"
    assert body["model"] == "claude-opus-5"
    assert body["effort"] == "low"
    assert body["system_prompt"] == "be terse"
    assert body["prompt_mode"] == "append"
    assert body["enabled"] is True


async def test_put_full_secrets_heals_an_unreadable_row(client, seeded):
    await login(client, "ada")
    await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "credentials": {"api_key": "sk-ant-secret"},
        },
    )
    row = await seeded.get_setting(registry.SETTINGS_KEY)
    row.secrets = b"garbage-not-a-fernet-token"

    r = await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-sonnet-5",
            "credentials": {"api_key": "sk-ant-fresh"},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "secrets_unreadable" not in body
    assert body["stored_credentials"] == ["api_key"]
    assert body["configured"] is True

    r = await client.get("/api/settings/ai")
    body = r.json()
    assert "secrets_unreadable" not in body
    assert body["stored_credentials"] == ["api_key"]


async def test_put_missing_a_required_secret_on_an_unreadable_row_is_422(client, seeded):
    await login(client, "ada")
    await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "credentials": {"api_key": "sk-ant-secret"},
        },
    )
    row = await seeded.get_setting(registry.SETTINGS_KEY)
    row.secrets = b"garbage-not-a-fernet-token"

    r = await client.put(
        "/api/settings/ai", json={"enabled": True, "provider": "anthropic", "model": "claude-sonnet-5"}
    )
    assert r.status_code == 422
    assert r.json()["error"] == "stored credentials cannot be decrypted; missing secret fields: api_key"

    row = await seeded.get_setting(registry.SETTINGS_KEY)
    assert row.secrets == b"garbage-not-a-fernet-token"


async def test_broken_kek_on_get_is_500(client, monkeypatch):
    await login(client, "ada")
    await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "credentials": {"api_key": "sk-ant-secret"},
        },
    )

    def boom(settings):
        raise SecretKeyError("bad key")

    monkeypatch.setattr(ai_routes.crypto, "dek", boom)
    r = await client.get("/api/settings/ai")
    assert r.status_code == 500
    assert "error" in r.json()


_BAD_BASE_URLS = (
    "http://plain.example/api/v1",
    "https://",
    "not-a-url",
    "https://user:password@gw.example/api/v1",
    "https://bedrock-runtime.eu-central-1.amazonaws.com@gw.example",
    "https://gw.example\\@other.example/api/v1",
    " https://gw.example/api/v1",
    "https://gw.example/api\t/v1",
    "https://gw.example:port/api/v1",
)


async def test_openrouter_base_url_is_validated_on_save(client):
    await login(client, "ada")
    base = {"enabled": False, "provider": "openrouter", "model": "openai/gpt-5"}
    for bad in _BAD_BASE_URLS:
        r = await client.put("/api/settings/ai", json={**base, "options": {"base_url": bad}})
        assert r.status_code == 400, bad
        assert "base_url" in r.json()["error"]
    good = await client.put(
        "/api/settings/ai", json={**base, "options": {"base_url": "https://gw.example/api/v1"}}
    )
    assert good.status_code == 200


def test_base_url_is_a_declared_openrouter_option():
    openrouter = registry.BY_ID["openrouter"]
    assert [o.name for o in openrouter.options] == ["base_url", "tls_skip_verify", "tls_ca_bundle"]


async def test_a_ca_bundle_that_is_not_pem_is_refused_on_save(client):
    await login(client, "ada")
    base = {"enabled": False, "provider": "anthropic", "model": "claude-opus-5"}
    r = await client.put("/api/settings/ai", json={**base, "options": {"tls_ca_bundle": "garbage"}})
    assert r.status_code == 400
    assert "tls_ca_bundle" in r.json()["error"]
    from hst.app.saml_flow import generate_sp_keypair

    good = await client.put(
        "/api/settings/ai",
        json={**base, "options": {"tls_skip_verify": "", "tls_ca_bundle": generate_sp_keypair()[1]}},
    )
    assert good.status_code == 200


def test_every_provider_declares_the_tls_options():
    """One proxy CA or a verification skip must be settable per provider, the
    same pair the HTTP collectors carry; the form renders them by `kind`."""
    for p in registry.PROVIDERS:
        by_name = {o.name: o for o in p.options}
        assert by_name["tls_skip_verify"].kind == "checkbox", p.id
        assert by_name["tls_ca_bundle"].kind == "textarea", p.id
        assert not by_name["tls_ca_bundle"].secret, p.id


def test_base_url_is_a_declared_bedrock_option():
    """A VPC endpoint or a gateway in front of Bedrock replaces the SDK's
    regional default host; the option is non-secret and optional."""
    bedrock = registry.BY_ID["bedrock"]
    endpoint = next(o for o in bedrock.options if o.name == "base_url")
    assert endpoint.secret is False
    assert "optional" in endpoint.label.lower()


async def test_bedrock_base_url_is_validated_on_save(client):
    """The Bedrock API key or the SigV4 signature goes to whatever host the
    endpoint names, so a save applies the same check as OpenRouter's base_url."""
    await login(client, "ada")
    base = {
        "enabled": False,
        "provider": "bedrock",
        "model": "anthropic.claude-opus-5",
        "credentials": {"aws_bedrock_api_key": "ABSK-own"},
    }
    for bad in _BAD_BASE_URLS:
        r = await client.put(
            "/api/settings/ai", json={**base, "options": {"aws_region": "eu-central-1", "base_url": bad}}
        )
        assert r.status_code == 400, bad
        assert "base_url" in r.json()["error"]
    good = await client.put(
        "/api/settings/ai",
        json={
            **base,
            "options": {"aws_region": "eu-central-1", "base_url": "https://gw.example/anthropic"},
        },
    )
    assert good.status_code == 200


@pytest.mark.parametrize("region", ["eu-central-1", "us-gov-west-1", "ap-southeast-2"])
async def test_an_aws_region_name_is_accepted_on_save(client, region):
    await login(client, "ada")
    r = await client.put("/api/settings/ai", json={**_BEDROCK, "options": {"aws_region": region}})
    assert r.status_code == 200
    assert r.json()["options"] == {"aws_region": region}


@pytest.mark.parametrize(
    "region",
    ["x.evil.example/", "eu-central-1.evil.example", "eu-central-1/", "EU-CENTRAL-1", " eu-central-1", "eu"],
)
async def test_an_aws_region_that_is_no_region_name_is_refused_on_save_and_on_test(
    client, monkeypatch, region
):
    monkeypatch.setattr(ai_routes, "_probe", lambda *args: pytest.fail("the probe ran"))
    await login(client, "ada")
    expected = "aws_region must be an AWS region name, for example eu-central-1"

    r = await client.put("/api/settings/ai", json={**_BEDROCK, "options": {"aws_region": region}})
    assert (r.status_code, r.json()["error"]) == (400, expected)

    r = await client.post(
        "/api/settings/ai/test",
        json={
            "provider": "bedrock",
            "options": {"aws_region": region},
            "secrets": {"aws_bedrock_api_key": "ABSK-own"},
        },
    )
    assert (r.status_code, r.json()["error"]) == (400, expected)


_VPC_ENDPOINT = "https://vpce-0abc.bedrock-runtime.eu-central-1.vpce.amazonaws.com"
_HOST_CREDENTIALS = registry.HOST_CREDENTIALS_DETAIL
_ROLE = "arn:aws:iam::123456789012:role/hst-bedrock"


@pytest.mark.parametrize(
    "base_url",
    [
        "https://bedrock-runtime.eu-central-1.amazonaws.com",
        "https://bedrock-runtime-fips.eu-central-1.amazonaws.com",
        _VPC_ENDPOINT,
        "https://vpce-0abc-1a2b3c4d-eu-central-1a.bedrock-runtime.eu-central-1.vpce.amazonaws.com",
    ],
)
async def test_bedrock_with_host_credentials_accepts_a_runtime_endpoint_of_the_region(client, base_url):
    await login(client, "ada")
    options = {"aws_region": "eu-central-1", "base_url": base_url}
    r = await client.put(
        "/api/settings/ai", json={"enabled": True, "provider": "bedrock", "model": "m", "options": options}
    )
    assert r.status_code == 200
    assert r.json()["options"] == options


@pytest.mark.parametrize(
    "options",
    [
        {"base_url": "https://gw.example/anthropic"},
        {"base_url": "https://bedrock-runtime.eu-west-1.amazonaws.com"},
        {"base_url": "https://bedrock-runtime.eu-central-1.amazonaws.com.gw.example"},
        {"base_url": "https://vpce-0abc.bedrock-runtime.eu-central-1.vpce.amazonaws.com.gw.example"},
        {"base_url": "https://gw.example/bedrock-runtime.eu-central-1.amazonaws.com"},
        {"base_url": "https://gw.example", "aws_role_arn": _ROLE},
    ],
    ids=["gateway", "other region", "suffix", "vpc endpoint suffix", "path", "assumed role"],
)
async def test_bedrock_with_host_credentials_refuses_any_other_base_url(client, monkeypatch, options):
    monkeypatch.setattr(ai_routes, "_probe", lambda *args: pytest.fail("the probe ran"))
    await login(client, "ada")
    options = {"aws_region": "eu-central-1", **options}

    r = await client.put(
        "/api/settings/ai", json={"enabled": True, "provider": "bedrock", "model": "m", "options": options}
    )
    assert (r.status_code, r.json()["error"]) == (400, _HOST_CREDENTIALS)

    r = await client.post("/api/settings/ai/test", json={"provider": "bedrock", "options": options})
    assert (r.status_code, r.json()["error"]) == (400, _HOST_CREDENTIALS)


async def test_bedrock_refuses_the_deletion_of_the_keys_that_sign_for_a_gateway(client):
    await login(client, "ada")
    gateway = {
        "enabled": True,
        "provider": "bedrock",
        "model": "m",
        "options": {"aws_region": "eu-central-1", "base_url": "https://gw.example"},
    }
    keys = {"aws_access_key_id": "AKIA-own", "aws_secret_access_key": "own-secret"}
    assert (await client.put("/api/settings/ai", json={**gateway, "credentials": keys})).status_code == 200

    r = await client.put("/api/settings/ai", json={**gateway, "credentials": dict.fromkeys(keys)})
    assert (r.status_code, r.json()["error"]) == (400, _HOST_CREDENTIALS)
    assert (await client.get("/api/settings/ai")).json()["stored_credentials"] == sorted(keys)


async def test_test_endpoint_names_missing_credentials(client):
    await login(client, "ada")
    await client.put(
        "/api/settings/ai", json={"enabled": True, "provider": "anthropic", "model": "claude-opus-5"}
    )
    body = (await client.post("/api/settings/ai/test")).json()
    assert body["ok"] is False
    assert "api_key" in body["error"]


async def test_test_endpoint_overrides_probe_only_and_persists_nothing(client, monkeypatch):
    import hst.app.routes.ai as ai_routes

    seen = {}
    monkeypatch.setattr(
        ai_routes, "_probe", lambda settings, secrets, trust: seen.update(settings=settings, secrets=secrets)
    )
    await login(client, "ada")
    await client.put(
        "/api/settings/ai", json={"enabled": False, "provider": "anthropic", "model": "claude-opus-5"}
    )

    r = await client.post(
        "/api/settings/ai/test",
        json={"provider": "openrouter", "model": "openai/gpt-5", "secrets": {"api_key": "sk-or-x"}},
    )
    body = r.json()
    assert body["ok"] is True
    assert (body["provider"], body["model"]) == ("openrouter", "openai/gpt-5")
    assert seen["settings"]["provider"] == "openrouter"
    assert seen["secrets"]["api_key"] == "sk-or-x"

    stored = (await client.get("/api/settings/ai")).json()
    assert stored["provider"] == "anthropic"
    assert stored["stored_credentials"] == []


async def test_test_endpoint_blank_secret_falls_back_to_the_stored_one(client, monkeypatch):
    import hst.app.routes.ai as ai_routes

    seen = {}
    monkeypatch.setattr(
        ai_routes, "_probe", lambda settings, secrets, trust: seen.update(settings=settings, secrets=secrets)
    )
    await login(client, "ada")
    await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "credentials": {"api_key": "sk-ant-stored"},
        },
    )

    r = await client.post(
        "/api/settings/ai/test", json={"model": "claude-sonnet-5", "secrets": {"api_key": ""}}
    )
    assert r.json()["ok"] is True
    assert r.json()["model"] == "claude-sonnet-5"
    assert seen["secrets"]["api_key"] == "sk-ant-stored"


async def test_test_endpoint_rejects_an_unknown_provider_override(client):
    await login(client, "ada")
    r = await client.post("/api/settings/ai/test", json={"provider": "skynet"})
    assert r.status_code == 400


_OPENROUTER = {"enabled": True, "provider": "openrouter", "model": "openai/gpt-5"}
_BEDROCK = {
    "enabled": True,
    "provider": "bedrock",
    "model": "anthropic.claude-opus-5",
    "options": {"aws_region": "eu-central-1"},
    "credentials": {"aws_bedrock_api_key": "ABSK-stored"},
}
_OTHER_ENDPOINT = ai_routes.OTHER_ENDPOINT_DETAIL


def _openrouter_transport(monkeypatch, reply=None) -> list:
    """The requests of the OpenRouter SDK client. Each one gets `reply`, or a completion."""
    import httpx
    import openai

    seen: list[httpx.Request] = []
    completion = {
        "id": "c1",
        "object": "chat.completion",
        "created": 0,
        "model": "openai/gpt-5",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return reply or httpx.Response(200, json=completion)

    real = openai.OpenAI
    monkeypatch.setattr(
        openai,
        "OpenAI",
        lambda **kwargs: real(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(handler))),
    )
    return seen


async def _store_openrouter_key(client, options=None) -> None:
    await login(client, "ada")
    r = await client.put(
        "/api/settings/ai",
        json={**_OPENROUTER, "options": options or {}, "credentials": {"api_key": "sk-or-stored"}},
    )
    assert r.status_code == 200


async def test_a_test_of_another_base_url_without_a_secret_sends_no_request(client, monkeypatch):
    seen = _openrouter_transport(monkeypatch)
    await _store_openrouter_key(client)

    r = await client.post(
        "/api/settings/ai/test", json={"options": {"base_url": "https://other.example/api/v1"}}
    )
    assert [(q.url.host, q.headers["authorization"]) for q in seen] == []
    assert r.status_code == 400
    assert r.json()["error"] == _OTHER_ENDPOINT + "api_key"


async def test_a_test_of_another_base_url_sends_the_secret_of_the_request(client, monkeypatch):
    seen = _openrouter_transport(monkeypatch)
    await _store_openrouter_key(client)

    r = await client.post(
        "/api/settings/ai/test",
        json={"options": {"base_url": "https://other.example/api/v1"}, "secrets": {"api_key": "sk-or-own"}},
    )
    assert r.json()["ok"] is True
    assert [(q.url.host, q.headers["authorization"]) for q in seen] == [("other.example", "Bearer sk-or-own")]


async def test_a_test_of_another_model_sends_the_stored_key_to_the_stored_endpoint(client, monkeypatch):
    seen = _openrouter_transport(monkeypatch)
    options = {"base_url": "https://gw.example/api/v1"}
    await _store_openrouter_key(client, options)

    r = await client.post("/api/settings/ai/test", json={"model": "openai/other", "options": options})
    assert r.json()["ok"] is True
    assert [(q.url.host, q.headers["authorization"]) for q in seen] == [("gw.example", "Bearer sk-or-stored")]
    assert json.loads(seen[0].content)["model"] == "openai/other"


@pytest.mark.parametrize(
    ("stored", "probe", "kept"),
    [
        (
            {"enabled": True, "provider": "anthropic", "model": "m", "credentials": {"api_key": "sk-ant-s"}},
            {"provider": "openrouter"},
            "api_key",
        ),
        (_BEDROCK, {"options": {"aws_region": "eu-west-1"}}, "aws_bedrock_api_key"),
        (
            _BEDROCK,
            {"options": {"aws_region": "eu-central-1", "base_url": "https://other.example"}},
            "aws_bedrock_api_key",
        ),
    ],
    ids=["provider", "aws_region", "bedrock base_url"],
)
async def test_a_test_refuses_each_option_that_selects_another_host(client, monkeypatch, stored, probe, kept):
    monkeypatch.setattr(ai_routes, "_probe", lambda *args: pytest.fail("the probe ran"))
    await login(client, "ada")
    assert (await client.put("/api/settings/ai", json=stored)).status_code == 200

    r = await client.post("/api/settings/ai/test", json=probe)
    assert r.status_code == 400
    assert r.json()["error"] == _OTHER_ENDPOINT + kept


def _ca_pem() -> str:
    from hst.app.saml_flow import generate_sp_keypair

    return generate_sp_keypair()[1]


_REGION = {"aws_region": "eu-central-1"}


@pytest.mark.parametrize(
    ("stored", "weaker"),
    [
        ({}, {"tls_skip_verify": "true"}),
        ({"tls_skip_verify": ""}, {"tls_skip_verify": "true"}),
        ({}, {"tls_ca_bundle": "new"}),
        ({"tls_ca_bundle": "stored"}, {"tls_ca_bundle": "new"}),
    ],
    ids=["skip on", "skip from blank to on", "first bundle", "other bundle"],
)
async def test_a_weaker_tls_check_takes_the_key_of_the_request(client, monkeypatch, stored, weaker):
    seen = {}
    monkeypatch.setattr(ai_routes, "_probe", lambda settings, secrets, trust: seen.update(secrets))
    pems = {"stored": _ca_pem(), "new": _ca_pem()}
    stored, weaker = (
        {**_REGION, **{name: pems.get(value, value) for name, value in options.items()}}
        for options in (stored, weaker)
    )
    refused = ai_routes.WEAKER_TLS_DETAIL + "aws_bedrock_api_key"
    await login(client, "ada")
    assert (await client.put("/api/settings/ai", json={**_BEDROCK, "options": stored})).status_code == 200

    r = await client.post("/api/settings/ai/test", json={"options": weaker})
    assert (r.status_code, r.json()["error"]) == (400, refused)
    r = await client.put("/api/settings/ai", json={**_BEDROCK, "options": weaker, "credentials": {}})
    assert (r.status_code, r.json()["error"]) == (400, refused)
    assert seen == {}

    own = {"aws_bedrock_api_key": "ABSK-own"}
    r = await client.post("/api/settings/ai/test", json={"options": weaker, "secrets": own})
    assert r.json()["ok"] is True
    assert seen == own
    r = await client.put("/api/settings/ai", json={**_BEDROCK, "options": weaker, "credentials": own})
    assert r.status_code == 200


@pytest.mark.parametrize(
    ("stored", "options"),
    [
        ({}, {"aws_role_arn": "arn:aws:iam::123456789012:role/probe"}),
        ({"tls_skip_verify": "true"}, {}),
        ({"tls_skip_verify": "true"}, {"tls_skip_verify": "true"}),
        ({"tls_ca_bundle": "stored"}, {}),
        ({"tls_ca_bundle": "stored"}, {"tls_ca_bundle": "stored"}),
    ],
    ids=["aws_role_arn", "skip off", "skip kept", "bundle removed", "bundle kept"],
)
async def test_a_test_keeps_the_stored_key_for_options_that_keep_the_host_and_the_tls_check(
    client, monkeypatch, stored, options
):
    seen = {}
    monkeypatch.setattr(ai_routes, "_probe", lambda settings, secrets, trust: seen.update(secrets))
    pem = _ca_pem()
    stored, options = (
        {**_REGION, **{name: pem if value == "stored" else value for name, value in given.items()}}
        for given in (stored, options)
    )
    await login(client, "ada")
    assert (await client.put("/api/settings/ai", json={**_BEDROCK, "options": stored})).status_code == 200

    r = await client.post("/api/settings/ai/test", json={"options": options})
    assert r.json()["ok"] is True
    assert seen == {"aws_bedrock_api_key": "ABSK-stored"}


async def test_a_null_secret_leaves_the_stored_key_out_of_a_test_of_another_endpoint(client, monkeypatch):
    seen = {}
    monkeypatch.setattr(ai_routes, "_probe", lambda settings, secrets, trust: seen.update(secrets))
    await login(client, "ada")
    assert (await client.put("/api/settings/ai", json=_BEDROCK)).status_code == 200
    keys = {"aws_access_key_id": "AKIA-own", "aws_secret_access_key": "own-secret"}

    r = await client.post(
        "/api/settings/ai/test",
        json={"options": {"aws_region": "eu-west-1"}, "secrets": {**keys, "aws_bedrock_api_key": None}},
    )
    assert r.json()["ok"] is True
    assert seen == keys
    assert (await client.get("/api/settings/ai")).json()["stored_credentials"] == ["aws_bedrock_api_key"]


async def test_a_failed_test_returns_a_redacted_error_of_bounded_length(client, monkeypatch):
    import httpx

    message = "Authorization: Bearer abcdef123456 " + "x" * 10_000
    _openrouter_transport(monkeypatch, httpx.Response(500, json={"error": {"message": message}}))
    await _store_openrouter_key(client)

    body = (await client.post("/api/settings/ai/test")).json()
    assert body["ok"] is False
    assert "abcdef123456" not in body["error"]
    text, status, _ = body["error"].partition(" (HTTP 500 from openrouter.ai)")
    assert status
    assert "Authorization: [redacted]" in text
    assert len(text) == ai_routes.MAX_PROBE_ERROR_CHARS


_PAGE = "<html>Authorization: Bearer abcdef123456 " + "x" * 5000 + " end-of-page</html>"


async def test_a_failed_test_returns_the_status_and_the_host_of_a_reply_that_is_not_json(
    client, monkeypatch, caplog
):
    import httpx

    _openrouter_transport(monkeypatch, httpx.Response(502, text=_PAGE))
    await _store_openrouter_key(client)

    with caplog.at_level("WARNING", logger="hst.ai"):
        body = (await client.post("/api/settings/ai/test")).json()
    assert body["ok"] is False
    assert body["error"] == "HTTP 502 from openrouter.ai: the reply is not JSON"
    assert "abcdef123456" not in caplog.text


async def test_the_whole_reply_of_a_failed_anthropic_test_goes_to_the_log_redacted(
    client, monkeypatch, caplog
):
    import anthropic
    import httpx2

    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    http = anthropic.DefaultHttpxClient(
        transport=httpx2.MockTransport(lambda request: httpx2.Response(502, text=_PAGE))
    )
    monkeypatch.setattr(AnthropicAdapter, "_http_client", lambda *args: {"http_client": http})
    await login(client, "ada")
    stored = {"enabled": True, "provider": "anthropic", "model": "m", "credentials": {"api_key": "sk-ant-s"}}
    assert (await client.put("/api/settings/ai", json=stored)).status_code == 200

    with caplog.at_level("WARNING", logger="hst.ai"):
        body = (await client.post("/api/settings/ai/test")).json()
    assert body["error"] == "HTTP 502 from api.anthropic.com: the reply is not JSON"
    assert "end-of-page" in caplog.text
    assert "abcdef123456" not in caplog.text


async def test_a_test_fails_for_a_reply_with_status_200_that_is_no_completion(client, monkeypatch):
    import httpx

    _openrouter_transport(monkeypatch, httpx.Response(200, text="<html>sign in</html>"))
    await _store_openrouter_key(client)

    body = (await client.post("/api/settings/ai/test")).json()
    assert body["ok"] is False
    assert body["error"] == "AgentError: the provider returned no answer: no error detail given"


async def test_a_save_of_another_endpoint_takes_the_key_of_the_request(client, monkeypatch):
    seen = _openrouter_transport(monkeypatch)
    await _store_openrouter_key(client)
    moved = {**_OPENROUTER, "options": {"base_url": "https://other.example/api/v1"}}

    r = await client.put("/api/settings/ai", json=moved)
    assert r.status_code == 400
    assert r.json()["error"] == _OTHER_ENDPOINT + "api_key"
    assert (await client.get("/api/settings/ai")).json()["options"] == {}

    r = await client.put("/api/settings/ai", json={**moved, "credentials": {"api_key": "sk-or-own"}})
    assert r.status_code == 200
    assert (await client.post("/api/settings/ai/test")).json()["ok"] is True
    assert [(q.url.host, q.headers["authorization"]) for q in seen] == [("other.example", "Bearer sk-or-own")]


async def test_a_save_of_another_endpoint_accepts_the_deletion_of_the_stored_key(client):
    await _store_openrouter_key(client)

    r = await client.put(
        "/api/settings/ai",
        json={
            **_OPENROUTER,
            "options": {"base_url": "https://other.example/api/v1"},
            "credentials": {"api_key": None},
        },
    )
    assert r.status_code == 200
    assert r.json()["stored_credentials"] == []


async def test_a_save_of_another_provider_does_not_keep_a_key_that_the_provider_uses(client):
    await _store_openrouter_key(client)

    r = await client.put(
        "/api/settings/ai", json={"enabled": True, "provider": "anthropic", "model": "claude-opus-5"}
    )
    assert r.status_code == 400
    assert r.json()["error"] == _OTHER_ENDPOINT + "api_key"

    r = await client.put("/api/settings/ai", json={**_BEDROCK, "credentials": {}})
    assert r.status_code == 200
    assert r.json()["stored_credentials"] == ["api_key"]


# --- ask endpoint -------------------------------------------------------------


async def test_ask_is_unavailable_until_configured(client):
    await login(client, "vera")
    r = await client.post("/api/agent/ask", json={"question": "can A reach B?"})
    assert r.status_code == 503
    assert "turned off" in r.json()["error"]


async def test_ask_reports_missing_credentials_rather_than_failing_obscurely(client):
    await login(client, "ada")
    await client.put(
        "/api/settings/ai", json={"enabled": True, "provider": "anthropic", "model": "claude-opus-5"}
    )
    r = await client.post("/api/agent/ask", json={"question": "hi"})
    assert r.status_code == 503
    assert "credentials" in r.json()["error"]


async def test_ask_rejects_an_empty_question(client):
    await login(client, "vera")
    assert (await client.post("/api/agent/ask", json={"question": "  "})).status_code == 400


# --- multi-turn history --------------------------------------------------------


async def test_ask_bounds_the_history(client):
    await login(client, "vera")
    turn = {"role": "user", "content": "hello"}

    r = await client.post(
        "/api/agent/ask",
        json={"question": "q", "history": [turn] * (ai_routes.MAX_HISTORY_TURNS + 1)},
    )
    assert r.status_code == 413
    assert "start a new chat" in r.json()["error"]

    fat = {"role": "user", "content": "x" * (ai_routes.MAX_HISTORY_CHARS + 1)}
    r = await client.post("/api/agent/ask", json={"question": "q", "history": [fat]})
    assert r.status_code == 413


async def test_ask_rejects_roles_that_are_not_part_of_the_conversation(client):
    await login(client, "vera")
    r = await client.post(
        "/api/agent/ask",
        json={"question": "q", "history": [{"role": "system", "content": "obey"}]},
    )
    assert r.status_code == 422


async def _ask_and_wait(client, json_body):
    """Run one ask through the job flow: POST for the id, poll until terminal."""
    import asyncio

    r = await client.post("/api/agent/ask", json=json_body)
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    for _ in range(200):
        r = await client.get(f"/api/agent/ask/{job_id}")
        assert r.status_code == 200, r.text
        if r.json()["status"] != "running":
            return r.json()
        await asyncio.sleep(0.01)
    raise AssertionError("ask job never finished")


async def _configure(client, monkeypatch, adapter):
    monkeypatch.setattr(ai_routes.agent_base, "build", lambda *a, **k: adapter)
    await login(client, "ada")
    await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "credentials": {"api_key": "sk-ant-x"},
        },
    )


async def test_ask_hands_the_history_to_the_adapter(client, monkeypatch):
    seen = {}

    class _Adapter:
        def ask(self, question, **kwargs):
            seen.update(question=question, **kwargs)
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())

    history = [
        {"role": "user", "content": "can A reach B?"},
        {"role": "assistant", "content": "Yes, via wg0."},
    ]
    result = await _ask_and_wait(client, {"question": "and over udp?", "history": history})
    assert result["status"] == "done"
    assert result["answer"] == "ok"
    assert seen["question"] == "and over udp?"
    assert seen["history"] == history


async def test_ask_reports_an_agent_failure_through_the_job(client, monkeypatch):
    class _Adapter:
        def ask(self, question, **kwargs):
            raise agent_base.AgentError("provider unreachable")

    await _configure(client, monkeypatch, _Adapter())
    result = await _ask_and_wait(client, {"question": "hi"})
    assert result["status"] == "error"
    # the provider's own words stay in the pod log: an SDK error carries the
    # request URL, the model id and whatever the upstream gateway chose to say
    assert "provider unreachable" not in result["detail"]
    assert "see the server log" in result["detail"]


_GUARDED_DEVICES = "MATCH (n:Device) WHERE coalesce(n.collection_ts, $snap) = $snap RETURN n"
_GUARDED_ANY = "MATCH (n) WHERE coalesce(n.collection_ts, $snap) = $snap RETURN n"


async def test_the_agents_cypher_calls_land_in_the_same_audit_trail(client, app, monkeypatch):
    import hst.twin_tools.query as query_mod

    table = {"columns": ["n"], "data": [{"row": [1]}, {"row": [2]}], "truncated": False}
    monkeypatch.setattr(query_mod, "run_readonly", lambda s, q, p, graph=False: table)
    monkeypatch.setattr(db_mod, "session", _db_seam(_FakeGraphSession(lambda query: [], current=4000)))

    class _Adapter:
        def ask(self, question, *, tools, **kwargs):
            call = tools_mod.dispatch(tools, "query_cypher", {"query": _GUARDED_DEVICES})
            assert call.is_error is False, call.result
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())
    assert (await _ask_and_wait(client, {"question": "hi"}))["status"] == "done"

    ada = await app.state.store.get_user_by_username("ada")
    events = await app.state.store.list_cypher_events()
    assert len(events) == 1
    e = events[0]
    assert (e.user_id, e.query, e.outcome, e.row_count) == (ada.id, _GUARDED_DEVICES, "ok", 2)
    assert e.byte_count > 0


async def test_a_rejected_agent_query_is_recorded_with_its_verdict(client, app, monkeypatch):
    class _Adapter:
        def ask(self, question, *, tools, **kwargs):
            # the adapters call dispatch
            tools_mod.dispatch(tools, "query_cypher", {"query": "RETURN dbms.components() AS v"})
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())
    assert (await _ask_and_wait(client, {"question": "hi"}))["status"] == "done"

    events = await app.state.store.list_cypher_events()
    assert [(e.outcome, e.row_count) for e in events] == [("rejected", 0)]


async def test_an_unguarded_agent_query_is_refused_before_any_read_and_recorded(client, app, monkeypatch):
    """A query that never references $snap reads every retained run. The model gets
    the guard form in an error step, nothing is read, and the attempt is audited."""
    import hst.twin_tools.query as query_mod

    reads: list[str] = []
    monkeypatch.setattr(query_mod, "run_readonly", lambda s, q, p, graph=False: reads.append(q))
    steps: list[tools_mod.ToolCall] = []

    class _Adapter:
        def ask(self, question, *, tools, **kwargs):
            steps.append(tools_mod.dispatch(tools, "query_cypher", {"query": "MATCH (n:Device) RETURN n"}))
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())
    assert (await _ask_and_wait(client, {"question": "hi"}))["status"] == "done"

    assert steps[0].is_error is True
    assert "x.collection_ts = $snap" in steps[0].result
    assert "coalesce(x.collection_ts" not in steps[0].result
    assert reads == []
    events = await app.state.store.list_cypher_events()
    assert [(e.query, e.outcome, e.row_count) for e in events] == [
        ("MATCH (n:Device) RETURN n", "rejected", 0)
    ]


async def test_an_abandoned_ask_records_the_queries_it_ran(client, app, monkeypatch):
    import time

    import hst.twin_tools.query as query_mod

    monkeypatch.setattr(
        query_mod, "run_readonly", lambda s, q, p, graph=False: {"data": [], "truncated": False}
    )
    monkeypatch.setattr(db_mod, "session", _db_seam(_FakeGraphSession(lambda query: [], current=4000)))

    class _Adapter:
        def ask(self, question, *, tools, **kwargs):
            tools_mod.dispatch(tools, "query_cypher", {"query": _GUARDED_ANY})
            time.sleep(0.5)
            return agent_base.AgentAnswer(answer="too late")

    monkeypatch.setattr(ai_routes, "ASK_DEADLINE_S", 0.05)
    await _configure(client, monkeypatch, _Adapter())
    assert (await _ask_and_wait(client, {"question": "slow"}))["status"] == "error"

    events = await app.state.store.list_cypher_events()
    assert [e.query for e in events] == [_GUARDED_ANY]


async def test_ask_job_is_invisible_to_other_users(client, monkeypatch):
    class _Adapter:
        def ask(self, question, **kwargs):
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())
    r = await client.post("/api/agent/ask", json={"question": "hi"})
    assert r.status_code == 202
    job_id = r.json()["job_id"]

    await login(client, "vera")
    r = await client.get(f"/api/agent/ask/{job_id}")
    assert r.status_code == 404
    assert (await client.get("/api/agent/ask/no-such-job")).status_code == 404


def test_seed_history_normalizes_client_transcripts():
    """Anthropic requires user-first alternating roles."""
    assert agent_base.seed_history(
        [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}], "c"
    ) == [
        {"role": "user", "content": "a"},
        {"role": "assistant", "content": "b"},
        {"role": "user", "content": "c"},
    ]
    assert agent_base.seed_history([{"role": "assistant", "content": "orphan"}], "q") == [
        {"role": "user", "content": "q"}
    ]
    # consecutive same-role turns coalesce, including into the new question
    assert agent_base.seed_history(
        [{"role": "user", "content": "first"}, {"role": "user", "content": "again"}], "q"
    ) == [{"role": "user", "content": "first\n\nagain\n\nq"}]
    assert agent_base.seed_history([{"role": "user", "content": "  "}], "q") == [
        {"role": "user", "content": "q"}
    ]


def test_anthropic_adapter_seeds_the_conversation_from_history(monkeypatch):
    stub = _StubAnthropic([SimpleNamespace(stop_reason="end_turn", content=[_block(type="text", text="hi")])])
    adapter = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)

    adapter.ask(
        "and over udp?",
        system="s",
        tools=[],
        model="claude-opus-5",
        effort="high",
        history=[
            {"role": "user", "content": "can A reach B?"},
            {"role": "assistant", "content": "Yes, via wg0."},
        ],
    )
    assert stub.requests[0]["messages"] == [
        {"role": "user", "content": "can A reach B?"},
        {"role": "assistant", "content": "Yes, via wg0."},
        {"role": "user", "content": "and over udp?"},
    ]


def test_openrouter_adapter_keeps_the_system_message_ahead_of_history(monkeypatch):
    stub = _StubOpenAI([_openai_turn(content="hi")])
    adapter = OpenRouterAdapter({"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)

    adapter.ask(
        "and over udp?",
        system="s",
        tools=[],
        model="openai/gpt-5",
        effort="high",
        history=[
            {"role": "user", "content": "can A reach B?"},
            {"role": "assistant", "content": "Yes, via wg0."},
        ],
    )
    assert stub.requests[0]["messages"] == [
        {"role": "system", "content": "s"},
        {"role": "user", "content": "can A reach B?"},
        {"role": "assistant", "content": "Yes, via wg0."},
        {"role": "user", "content": "and over udp?"},
    ]


# --- tool exposure ------------------------------------------------------------


# The read tools of the catalogue that need only graph.read, in catalogue order.
_GRAPH_READ_TOOLS = [
    "snapshot_list",
    "snapshot_resolve",
    "snapshot_diff",
    "inventory_search",
    "inventory_get",
    "inventory_list",
    "inventory_resolve",
    "routing_routes",
    "routing_bgp",
    "routing_evaluate_policy",
    "routing_predict_routes",
    "policy_evaluate",
    "policy_lookup_nat",
    "lb_lookup_vip",
    "reach_trace",
    "reach_audit_mtu",
    "impact_evaluate_service",
    "impact_assess",
    "change_simulate",
    "change_get_simulation",
    "app_applications",
    "app_find_affected",
    "assessment_read",
    "evidence_get_gaps",
    "query_catalog",
    "query_run_named",
]


def _roster(role: str) -> list[str]:
    ctx = ToolContext(settings=None, principal=Principal.for_role(role), surface="drawer")
    return [t.name for t in tools_mod.offered_tools(ctx)]


def test_viewers_are_never_offered_the_cypher_tool():
    assert _roster("viewer") == _GRAPH_READ_TOOLS


@pytest.mark.parametrize("role", ["operator", "admin"])
def test_operators_and_admins_are_offered_every_read_tool_of_the_catalogue(role):
    assert _roster(role) == [
        *_GRAPH_READ_TOOLS[:-2],
        "ops_list_collection_runs",
        *_GRAPH_READ_TOOLS[-2:],
        "query_cypher",
    ]


def test_a_role_without_graph_read_is_offered_nothing():
    assert _roster("no-such-role") == []


# Arguments that take each tool an admin is offered on the drawer to its first
# graph read, in catalogue order.
_FIRST_READ_ARGUMENTS: dict[str, dict] = {
    "snapshot_list": {},
    "snapshot_resolve": {},
    "snapshot_diff": {"base": "3000"},
    "inventory_search": {"q": "leaf"},
    "inventory_get": {"kind": "device", "device": "dev:leaf1"},
    "inventory_list": {"kind": "zones"},
    "inventory_resolve": {"kind": "address", "address": "10.0.0.1"},
    "routing_routes": {"mode": "table", "device": "dev:leaf1"},
    "routing_bgp": {"mode": "sessions"},
    "routing_evaluate_policy": {
        "device": "dev:leaf1",
        "direction": "import",
        "route": {"prefix": "10.0.0.0/24"},
        "policy_name": "RM-IN",
    },
    "routing_predict_routes": {"scope": "dev:leaf1"},
    "policy_evaluate": {"mode": "explain_rule", "rulebase": "rb:1", "rule": "r1"},
    "policy_lookup_nat": {"address": "10.0.0.1"},
    "lb_lookup_vip": {"address": "10.0.0.1", "direction": "vip_to_members"},
    "reach_trace": {"mode": "path", "flow": {"src": "10.0.0.1", "dst": "10.0.0.2"}},
    "reach_audit_mtu": {},
    "impact_evaluate_service": {"form": "request", "request": {}},
    "impact_assess": {"subject": "device", "device": "dev:leaf1"},
    "change_simulate": {"intents": [{"kind": "acl.rule.add", "params": {}}]},
    "change_get_simulation": {"session_id": "1", "run_id": "1"},
    "app_applications": {"mode": "list"},
    "app_find_affected": {"inventory_uids": ["dev:leaf1"]},
    "assessment_read": {"mode": "list"},
    "evidence_get_gaps": {"subject": {"kind": "device", "id": "dev:leaf1"}},
    "ops_list_collection_runs": {},
    "query_catalog": {"mode": "schema"},
    "query_run_named": {"key": "devices"},
    "query_cypher": {"query": _GUARDED_DEVICES},
}


def _admin_drawer_tools() -> list[Tool]:
    ctx = ToolContext(
        settings=fake_settings(),
        principal=Principal.for_role("admin"),
        surface="drawer",
        snapshot=snapshot_mod.Snapshot(4000, None),
        cypher_log=[],
    )
    return tools_mod.offered_tools(ctx)


def test_the_first_read_arguments_cover_every_tool_an_admin_is_offered():
    assert list(_FIRST_READ_ARGUMENTS) == [t.name for t in _admin_drawer_tools()]


@pytest.mark.parametrize("name", list(_FIRST_READ_ARGUMENTS))
def test_every_agent_graph_session_is_opened_in_read_mode(monkeypatch, name):
    graph = install(monkeypatch, FakeGraph())

    tools_mod.dispatch(_admin_drawer_tools(), name, _FIRST_READ_ARGUMENTS[name])

    assert graph.session_kwargs
    assert all(kwargs == {"access_mode": "READ"} for kwargs in graph.session_kwargs)


def test_a_failing_tool_is_reported_to_the_model_not_raised():
    def boom() -> str:
        raise RuntimeError("neo4j is down")

    tools = [Tool("boom", "", {"type": "object", "properties": {}}, "viewer", boom)]
    outcome = tools_mod.dispatch(tools, "boom", {})
    assert outcome.is_error and "neo4j is down" in outcome.result


def test_an_unknown_tool_name_is_reported_not_raised():
    outcome = tools_mod.dispatch([], "nope", {})
    assert outcome.is_error and "No such tool" in outcome.result


# --- adapters, against stub clients -------------------------------------------


def _echo_tool(calls: list) -> Tool:
    def run(**kwargs):
        calls.append(kwargs)
        return "PERMITTED via wg0"

    return Tool("trace_path", "trace", {"type": "object", "properties": {}}, "viewer", run)


class _StubAnthropic:
    """Mimics the Messages API: one tool-use turn, then a text answer."""

    def __init__(self, turns):
        self._turns = list(turns)
        self.requests = []
        self.messages = SimpleNamespace(create=self._create)
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        return self._turns.pop(0)


def _block(**kw):
    return SimpleNamespace(**kw)


def test_anthropic_adapter_runs_the_tool_then_answers(monkeypatch):
    calls: list = []
    stub = _StubAnthropic(
        [
            SimpleNamespace(
                stop_reason="tool_use",
                content=[
                    _block(
                        type="tool_use",
                        id="tu_1",
                        name="trace_path",
                        input={"src": "10.0.0.1", "dst": "8.8.8.8"},
                    )
                ],
            ),
            SimpleNamespace(
                stop_reason="end_turn", content=[_block(type="text", text="Yes, it egresses via wg0.")]
            ),
        ]
    )
    adapter = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)

    answer = adapter.ask(
        "can 10.0.0.1 reach 8.8.8.8?",
        system="sys",
        tools=[_echo_tool(calls)],
        model="claude-opus-5",
        effort="high",
    )

    assert answer.answer == "Yes, it egresses via wg0."
    assert [s.name for s in answer.steps] == ["trace_path"]
    assert calls == [{"src": "10.0.0.1", "dst": "8.8.8.8"}]
    # current models answer these parameters with 400
    for req in stub.requests:
        assert "temperature" not in req and "top_p" not in req and "top_k" not in req
        assert "budget_tokens" not in json.dumps(req.get("thinking", {}))


def test_anthropic_direct_opts_into_server_side_fallbacks(monkeypatch):
    stub = _StubAnthropic([SimpleNamespace(stop_reason="end_turn", content=[_block(type="text", text="hi")])])
    adapter = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)
    adapter.ask("q", system="s", tools=[], model="claude-opus-5", effort="high")
    assert stub.requests[0]["fallbacks"] == "default"


def test_bedrock_does_not_send_fallbacks(monkeypatch):
    """The parameter is Claude-API only; Bedrock rejects it."""
    stub = _StubAnthropic([SimpleNamespace(stop_reason="end_turn", content=[_block(type="text", text="hi")])])
    adapter = AnthropicAdapter("bedrock", {"aws_access_key_id": "a"}, {"aws_region": "eu-west-1"})
    monkeypatch.setattr(adapter, "_client", lambda: stub)
    adapter.ask("q", system="s", tools=[], model="anthropic.claude-opus-5", effort="high")
    assert "fallbacks" not in stub.requests[0]


def test_a_refusal_is_reported(monkeypatch):
    """Classifiers return HTTP 200 with `stop_reason: refusal` and no content."""
    stub = _StubAnthropic(
        [
            SimpleNamespace(
                stop_reason="refusal", content=[], stop_details=SimpleNamespace(explanation="declined: cyber")
            )
        ]
    )
    adapter = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)

    answer = adapter.ask("q", system="s", tools=[], model="claude-opus-5", effort="high")
    assert answer.declined is True
    assert "cyber" in answer.answer


def test_anthropic_adapter_stops_rather_than_looping_forever(monkeypatch):
    forever = [
        SimpleNamespace(
            stop_reason="tool_use",
            content=[_block(type="tool_use", id=f"tu_{i}", name="trace_path", input={})],
        )
        for i in range(50)
    ]
    adapter = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: _StubAnthropic(forever))
    answer = adapter.ask("q", system="s", tools=[_echo_tool([])], model="claude-opus-5", effort="high")
    assert "Gave up" in answer.answer


def test_anthropic_adapter_concludes_from_gathered_results_when_out_of_turns(monkeypatch):
    turns = [
        SimpleNamespace(
            stop_reason="tool_use",
            content=[_block(type="tool_use", id=f"tu_{i}", name="trace_path", input={})],
        )
        for i in range(agent_base.MAX_TURNS)
    ]
    turns.append(
        SimpleNamespace(
            stop_reason="end_turn",
            content=[_block(type="text", text="Best-effort: core1 enforces two rulebases.")],
        )
    )
    stub = _StubAnthropic(turns)
    adapter = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)

    answer = adapter.ask("q", system="s", tools=[_echo_tool([])], model="claude-opus-5", effort="high")

    assert answer.answer == "Best-effort: core1 enforces two rulebases."
    assert len(answer.steps) == agent_base.MAX_TURNS
    final = stub.requests[-1]
    assert final["tool_choice"] == {"type": "none"}
    assert final["messages"][-1]["role"] == "user"
    assert "exhausted" in final["messages"][-1]["content"]


class _StubOpenAI:
    def __init__(self, turns):
        self._turns = list(turns)
        self.requests = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        return self._turns.pop(0)


def _openai_turn(content=None, tool_calls=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=tool_calls or []))]
    )


def test_openrouter_adapter_parses_json_string_arguments(monkeypatch):
    calls: list = []
    stub = _StubOpenAI(
        [
            _openai_turn(
                tool_calls=[
                    SimpleNamespace(
                        id="c1",
                        function=SimpleNamespace(
                            name="trace_path", arguments='{"src": "10.0.0.1", "dst": "8.8.8.8"}'
                        ),
                    )
                ]
            ),
            _openai_turn(content="Yes, via wg0."),
        ]
    )
    adapter = OpenRouterAdapter({"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)

    answer = adapter.ask(
        "q", system="s", tools=[_echo_tool(calls)], model="anthropic/claude-opus-5", effort="high"
    )
    assert answer.answer == "Yes, via wg0."
    assert calls == [{"src": "10.0.0.1", "dst": "8.8.8.8"}]


def test_openrouter_malformed_tool_arguments_do_not_kill_the_request(monkeypatch):
    stub = _StubOpenAI(
        [
            _openai_turn(
                tool_calls=[
                    SimpleNamespace(
                        id="c1", function=SimpleNamespace(name="trace_path", arguments="{not json")
                    )
                ]
            ),
            _openai_turn(content="Let me try again differently."),
        ]
    )
    adapter = OpenRouterAdapter({"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)

    answer = adapter.ask(
        "q", system="s", tools=[_echo_tool([])], model="anthropic/claude-opus-5", effort="high"
    )
    assert answer.steps[0].is_error
    assert answer.answer == "Let me try again differently."


def test_openrouter_adapter_concludes_from_gathered_results_when_out_of_turns(monkeypatch):
    turns = [
        _openai_turn(
            tool_calls=[
                SimpleNamespace(id=f"c{i}", function=SimpleNamespace(name="trace_path", arguments="{}"))
            ]
        )
        for i in range(agent_base.MAX_TURNS)
    ]
    turns.append(_openai_turn(content="Best-effort: two rulebases found."))
    stub = _StubOpenAI(turns)
    adapter = OpenRouterAdapter({"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)

    answer = adapter.ask(
        "q", system="s", tools=[_echo_tool([])], model="anthropic/claude-opus-5", effort="high"
    )

    assert answer.answer == "Best-effort: two rulebases found."
    assert stub.requests[-1]["tool_choice"] == "none"


def test_openrouter_sends_no_anthropic_only_parameters(monkeypatch):
    stub = _StubOpenAI([_openai_turn(content="hi")])
    adapter = OpenRouterAdapter({"api_key": "k"}, {})
    monkeypatch.setattr(adapter, "_client", lambda: stub)
    adapter.ask("q", system="s", tools=[], model="openai/gpt-5", effort="high")
    req = stub.requests[0]
    assert "output_config" not in req and "fallbacks" not in req and "betas" not in req
    assert req["messages"][0] == {"role": "system", "content": "s"}


# --- store round-trip ---------------------------------------------------------


async def test_settings_survive_a_round_trip_through_the_store():
    store = FakeStore()
    await store.put_setting("ai", {"provider": "openrouter"}, b"sealed")
    row = await store.get_setting("ai")
    assert row.value == {"provider": "openrouter"} and row.secrets == b"sealed"
    assert await store.get_setting("nope") is None


def test_required_credentials_treat_optional_fields_as_optional():
    assert registry.required_credentials("bedrock") == []
    assert registry.required_credentials("anthropic") == ["api_key"]


# --- Bedrock authentication paths ---------------------------------------------
#
# An empty credential form is a valid configuration.


def test_bedrock_needs_only_a_region():
    from hst.app.agent.registry import is_configured

    settings = {"provider": "bedrock", "options": {"aws_region": "eu-central-1"}}
    assert is_configured(settings, {}) is True, "an instance profile is a valid setup"
    assert is_configured({"provider": "bedrock", "options": {}}, {}) is False


def test_bedrock_auth_mode_prefers_explicit_over_ambient():
    from hst.app.agent.registry import bedrock_auth_mode

    region = {"aws_region": "eu-central-1"}
    keys = {"aws_access_key_id": "A", "aws_secret_access_key": "B"}
    assert (
        bedrock_auth_mode({"aws_bedrock_api_key": "ABSK", **keys}, {**region, "aws_role_arn": "arn:x"})
        == "api_key"
    )
    assert bedrock_auth_mode(keys, {**region, "aws_role_arn": "arn:x"}) == "assume"
    assert bedrock_auth_mode(keys, region) == "keys"
    assert bedrock_auth_mode({}, region) == "ambient"


# every Bedrock client is built with the adapter's own timeout and retry policy
_BEDROCK_CALL = {"timeout": 90.0, "max_retries": 0}


def test_bedrock_api_key_builds_a_bearer_client(monkeypatch):
    seen = {}

    class _FakeAnthropic:
        @staticmethod
        def AnthropicBedrock(**kwargs):
            seen.update(kwargs)
            return object()

    adapter = AnthropicAdapter("bedrock", {"aws_bedrock_api_key": "ABSK1"}, {"aws_region": "eu-central-1"})
    adapter._bedrock_client(_FakeAnthropic)
    assert seen == {"aws_region": "eu-central-1", **_BEDROCK_CALL, "api_key": "ABSK1"}


def test_bedrock_ambient_passes_no_credentials(monkeypatch):
    seen = {}

    class _FakeAnthropic:
        @staticmethod
        def AnthropicBedrock(**kwargs):
            seen.update(kwargs)
            return object()

    adapter = AnthropicAdapter("bedrock", {}, {"aws_region": "eu-west-1"})
    adapter._bedrock_client(_FakeAnthropic)
    assert seen == {"aws_region": "eu-west-1", **_BEDROCK_CALL}


def test_bedrock_assume_role_uses_the_sts_credentials(monkeypatch):
    seen = {}

    class _FakeAnthropic:
        @staticmethod
        def AnthropicBedrock(**kwargs):
            seen.update(kwargs)
            return object()

    adapter = AnthropicAdapter(
        "bedrock", {}, {"aws_region": "us-east-1", "aws_role_arn": "arn:aws:iam::1:role/r"}
    )
    monkeypatch.setattr(
        adapter,
        "_assume_role",
        lambda region: {"AccessKeyId": "ASIA", "SecretAccessKey": "S", "SessionToken": "T"},
    )

    adapter._bedrock_client(_FakeAnthropic)
    assert seen == {
        "aws_region": "us-east-1",
        **_BEDROCK_CALL,
        "aws_access_key": "ASIA",
        "aws_secret_key": "S",
        "aws_session_token": "T",
    }


def test_bedrock_endpoint_is_passed_to_the_client():
    """An explicit endpoint reaches the SDK in every auth mode; a blank one is
    not passed at all, so the SDK's own regional default applies."""
    seen = {}

    class _FakeAnthropic:
        @staticmethod
        def AnthropicBedrock(**kwargs):
            seen.update(kwargs)
            return object()

    endpoint = "https://vpce-0abc.bedrock-runtime.eu-central-1.vpce.amazonaws.com"
    options = {"aws_region": "eu-central-1", "base_url": endpoint}

    AnthropicAdapter("bedrock", {}, options)._bedrock_client(_FakeAnthropic)
    assert seen == {"aws_region": "eu-central-1", **_BEDROCK_CALL, "base_url": endpoint}

    seen.clear()
    AnthropicAdapter("bedrock", {"aws_bedrock_api_key": "ABSK1"}, options)._bedrock_client(_FakeAnthropic)
    assert seen == {"aws_region": "eu-central-1", **_BEDROCK_CALL, "base_url": endpoint, "api_key": "ABSK1"}

    seen.clear()
    AnthropicAdapter(
        "bedrock", {"aws_access_key_id": "AKIA", "aws_secret_access_key": "S"}, options
    )._bedrock_client(_FakeAnthropic)
    assert seen["base_url"] == endpoint and seen["aws_access_key"] == "AKIA"

    seen.clear()
    AnthropicAdapter("bedrock", {}, {"aws_region": "eu-central-1", "base_url": ""})._bedrock_client(
        _FakeAnthropic
    )
    assert "base_url" not in seen


def test_bedrock_client_keeps_the_tls_trust(monkeypatch):
    """A CA bundle or skip-verify must reach the Runtime client used for calls."""
    import anthropic

    from hst.app.tls import Trust

    built = []
    real = anthropic.DefaultHttpxClient

    def _tracking(**kwargs):
        built.append(real(**kwargs))
        return built[-1]

    monkeypatch.setattr(anthropic, "DefaultHttpxClient", _tracking)
    trust = Trust(verify=False, ca_pem="", ca_file="")
    for credentials in ({"aws_bedrock_api_key": "ABSK1"}, {}):
        client = AnthropicAdapter("bedrock", credentials, {"aws_region": "eu-central-1"}, trust)._client()
        assert client._client is built[-1]
        assert client.max_retries == 0
        assert client.timeout == 90.0


def test_bedrock_without_a_region_is_refused():
    from hst.app.agent.base import AgentError

    adapter = AnthropicAdapter("bedrock", {"aws_bedrock_api_key": "k"}, {})
    with pytest.raises(AgentError, match="region"):
        adapter._bedrock_client(object())


def test_the_default_prompt_is_never_pinned_by_a_save():
    assert registry.merged({"system_prompt": ""})["system_prompt"] == registry.DEFAULT_SYSTEM_PROMPT
    assert (
        registry.merged({"system_prompt": registry.DEFAULT_SYSTEM_PROMPT})["system_prompt"]
        == registry.DEFAULT_SYSTEM_PROMPT
    )
    custom = "You are a terse network oracle."
    assert registry.merged({"system_prompt": custom})["system_prompt"] == custom
    # a default reads as no site instructions; a custom row saved without a
    blank = registry.merged({"system_prompt": ""})
    assert (blank["site_instructions"], blank["prompt_mode"]) == ("", "append")
    legacy = registry.merged({"system_prompt": custom})
    assert (legacy["site_instructions"], legacy["prompt_mode"]) == (custom, "replace")
    added = registry.merged({"system_prompt": custom, "prompt_mode": "append"})
    assert (added["site_instructions"], added["prompt_mode"]) == (custom, "append")


def test_default_prompt_instructs_the_model_to_state_a_degraded_run():
    assert "degraded" in registry.DEFAULT_SYSTEM_PROMPT
    sentence = next(line for line in registry.DEFAULT_SYSTEM_PROMPT.split("\n\n") if "run.degraded" in line)
    assert "state" in sentence.lower()


async def test_saving_the_default_prompt_stores_blank(client, seeded, monkeypatch):
    await login(client, "ada")
    r = await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "system_prompt": registry.DEFAULT_SYSTEM_PROMPT,
        },
    )
    assert r.status_code == 200
    # the default is no site instructions, so the public payload shows none
    assert (r.json()["system_prompt"], r.json()["prompt_mode"]) == ("", "append")
    row = await client.get("/api/settings/ai")
    assert (row.json()["system_prompt"], row.json()["prompt_mode"]) == ("", "append")
    stored = await seeded.get_setting(registry.SETTINGS_KEY)
    assert stored.value["system_prompt"] == ""


_CHANGE_PARAGRAPH_START = "A question about a planned change"
_CHANGE_PARAGRAPH_END = "Never call a recorded dependency incidental"


def _change_paragraph() -> str:
    prompt = registry.DEFAULT_SYSTEM_PROMPT
    return prompt[prompt.index(_CHANGE_PARAGRAPH_START) : prompt.index(_CHANGE_PARAGRAPH_END)]


def test_the_change_paragraph_orders_no_tool_first_and_claims_no_change_is_unmodelled():
    """The change paragraph does not send every change question to one tool
    ahead of the other, and the prompt does not say that interface or
    routing-protocol changes have no model."""
    assert "first" not in _change_paragraph().lower()
    assert "nothing models" not in registry.DEFAULT_SYSTEM_PROMPT.lower()


def test_the_change_paragraph_names_both_change_tools_with_their_scopes():
    """A named requirement or flow set goes to the bounded evaluator. A change
    set with derived flows goes to the simulator, whose derived flow list is
    capped by the same constant the overlay read applies."""
    from hst.app.fw_overlay_read import _MAX_DERIVED_FLOWS

    paragraph = " ".join(_change_paragraph().split())
    assert "`impact_evaluate_service` is the bounded tool for a named requirement or flow set" in paragraph
    assert "`change_simulate` is the tool for a change set whose flows are derived" in paragraph
    assert "a derived flow list holds at most 8 flows" in paragraph
    assert f"at most {_MAX_DERIVED_FLOWS} flows" in paragraph


# --- per-user ask cap -----------------------------------------------------------


async def test_one_user_cannot_monopolize_the_ask_queue(client, app, monkeypatch):
    import threading

    release = threading.Event()

    class _Adapter:
        def ask(self, question, **kwargs):
            release.wait(timeout=30)
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())
    try:
        await login(client, "vera")
        for _ in range(ai_routes.MAX_ASKS_PER_USER):
            assert (await client.post("/api/agent/ask", json={"question": "q"})).status_code == 202
        r = await client.post("/api/agent/ask", json={"question": "q"})
        assert r.status_code == 429
        assert "too many questions of this user in progress" in r.json()["error"]
        await login(client, "otto")
        assert (await client.post("/api/agent/ask", json={"question": "q"})).status_code == 202
    finally:
        release.set()
        for task in list(getattr(app.state, "ask_tasks", ())):
            await task


async def test_ask_ends_at_the_deadline(client, monkeypatch):
    import time

    class _Adapter:
        def ask(self, question, **kwargs):
            time.sleep(0.5)
            return agent_base.AgentAnswer(answer="too late")

    monkeypatch.setattr(ai_routes, "ASK_DEADLINE_S", 0.05)
    await _configure(client, monkeypatch, _Adapter())
    result = await _ask_and_wait(client, {"question": "slow"})
    assert result["status"] == "error"
    assert "exceeded" in result["detail"]


# --- the graph fake ----------------------------------------------------------------
#
# Neo4j faked at the hst.core.db.session seam, same idiom as
# tests/app/test_impact_api.py: session.run answers the cycle-pointer read,
# execute_read answers every path._read/_read_one, both routed by query text.


def _device_row(**overrides: object) -> dict:
    row = {
        "uid": "dev:leaf101",
        "hostname": "leaf101",
        "role": "switch",
        "software_version": "10.2(5)",
        "platform": "nxos",
        "vendor": "cisco",
        "model": "N9K-C93180YC-EX",
    }
    row.update(overrides)
    return row


class _FakeGraphSession:
    def __init__(self, rows_for, current: int | None = 4000, retained: bool = True) -> None:
        self.calls: list[dict] = []
        self.retained_checks: list[object] = []
        self._rows_for = rows_for
        self._current = current
        self._retained = retained

    def run(self, query: str, **params: object):
        current = self._current
        rows = [{"current": current}] if "CyclePointer" in query and current is not None else []
        return SimpleNamespace(data=lambda: rows)

    def execute_read(self, work, *args: object):
        sink, rows_for = self.calls, self._rows_for
        checks, retained = self.retained_checks, self._retained

        class _Tx:
            def run(self, query: str, **params: object):
                if query == snapshot_mod._RETAINED_GRAPH:
                    # the run-existence check a named snapshot passes before any read
                    checks.append(params["snap"])
                    data = [{"uid": "dev:leaf101"}] if retained else []
                    return SimpleNamespace(data=lambda: data)
                sink.append({"query": query, "params": params})
                data = rows_for(query)
                return SimpleNamespace(data=lambda: data)

        return work(_Tx(), *args)


def _db_seam(session):
    @contextmanager
    def cm(settings, **kwargs):
        yield session

    return cm


def _tool_context(role: str = "viewer", settings=None, **fields) -> ToolContext:
    """The context of one turn's tool calls on the drawer surface."""
    if settings is None:
        settings = Settings(_env_file=None, hst_secret_key=generate_key())
    return ToolContext(settings=settings, principal=Principal.for_role(role), surface="drawer", **fields)


def _reach_trace_tool(settings=None) -> Tool:
    return next(
        t for t in tools_mod.offered_tools(_tool_context(settings=settings)) if t.name == "reach_trace"
    )


def _address_rows(query: str) -> list[dict]:
    if "MATCH (n:IpAddress:Obj)" in query:
        return [
            {"uid": "ip:bd-vlan20:192.168.2.35", "anchor": "bd:site1:20", "l3dom": "site1", "af": 4},
            {"uid": "ip:site1-core:192.168.2.35", "anchor": "site1-core", "l3dom": "site1-core", "af": 4},
        ]
    if "(e:Endpoint:Obj)-[h:HAS_IP]" in query:
        return [
            {
                "uid": "ep:site1:aa-bb-cc-dd-ee-ff",
                "mac": "aa:bb:cc:dd:ee:ff",
                "kind": "client",
                "name": "printer-2",
                "ip_uid": "ip:bd-vlan20:192.168.2.35",
                "anchor": "bd:site1:20",
                "attached": [{"uid": "port:sw1:ge-0/0/3", "name": "ge-0/0/3", "kind": "Port", "ssid": None}],
                "bridge_domains": [{"uid": "bd:site1:20", "name": "users"}],
            }
        ]
    if "(i:Interface:Obj)-[h:HAS_IP]" in query:
        return []
    if "(s:BgpSession:Obj)" in query:
        return [
            {
                "uid": "bgp:rp:vyos1:default:bgp:192.168.2.35",
                "peer_ip": "192.168.2.35",
                "local_asn": 65001,
                "peer_asn": 65002,
                "import_policy_name": "FROM-PEER",
                "import_policy_kind": "route-map",
                "export_policy_name": None,
                "export_policy_kind": None,
                "process_uid": "rp:vyos1:default:bgp",
                "process_proto": "bgp",
                "process_asn": 65001,
                "vrf_uid": "vrf:vyos1:default",
                "vrf_name": "default",
            }
        ]
    if "LEARNED_ROUTE|STATIC_ROUTE" in query:
        return [
            {
                "kind": "LEARNED_ROUTE",
                "prefix": "10.9.0.0/16",
                "prefix_uid": "pfx:vrf-vyos1-default:10.9.0.0/16",
                "protocol": "bgp",
                "metric": 20,
                "interface": "eth0",
                "vrf_uid": "vrf:vyos1:default",
                "vrf_name": "default",
            }
        ]
    return []


# --- the route prediction ----------------------------------------------------------
#
# `route_prediction` is the engine behind routing_predict_routes. The whole of
# simul_read's read is answered here by query text.

_LEAF_PROC = "rp:leaf101:default:bgp"
_SPINE_PROC = "rp:spine1:default:bgp"


def _route_rows(*, originated=None, extra_sessions=()):
    """A two-process eBGP peering: leaf101 and spine1, one prefix each."""
    origin = (
        originated
        if originated is not None
        else [
            {"process_uid": _LEAF_PROC, "prefix": "10.10.0.0/24", "proto": "connected"},
            {"process_uid": _SPINE_PROC, "prefix": "10.20.0.0/24", "proto": "connected"},
        ]
    )

    def rows_for(query: str) -> list[dict]:
        if "toLower(d.hostname)" in query:  # match_devices
            return [_device_row()]
        if "(d:Device:Obj {uid: $dev, collection_ts: $snap})" in query:  # seed by device scope
            return [{"uid": _LEAF_PROC}]
        if "(v:VrfInstance:Obj {uid: $vrf, collection_ts: $snap})" in query:  # seed by VRF scope
            return [{"uid": _LEAF_PROC}]
        if "-[e:ENDPOINT]->" in query:  # one peering hop out of the seed
            return [{"uid": _SPINE_PROC}]
        if "properties(rp) AS props" in query:
            return [
                {
                    "uid": _LEAF_PROC,
                    "props": {"uid": _LEAF_PROC, "proto": "bgp", "asn": 65001, "router_id": "10.0.0.1"},
                    "context_uid": "vrf:leaf101:default",
                    "platforms": ["iosxe"],
                    "vendors": ["cisco"],
                },
                {
                    "uid": _SPINE_PROC,
                    "props": {"uid": _SPINE_PROC, "proto": "bgp", "asn": 65002, "router_id": "10.0.0.2"},
                    "context_uid": "vrf:spine1:default",
                    "platforms": ["iosxe"],
                    "vendors": ["cisco"],
                },
            ]
        if "properties(b) AS props" in query:
            return [
                {
                    "uid": "bgp:leaf101:10.1.0.2",
                    "process_uid": _LEAF_PROC,
                    "props": {
                        "uid": "bgp:leaf101:10.1.0.2",
                        "peer_ip": "10.1.0.2",
                        "local_asn": 65001,
                        "peer_asn": 65002,
                    },
                },
                {
                    "uid": "bgp:spine1:10.1.0.1",
                    "process_uid": _SPINE_PROC,
                    "props": {
                        "uid": "bgp:spine1:10.1.0.1",
                        "peer_ip": "10.1.0.1",
                        "local_asn": 65002,
                        "peer_asn": 65001,
                    },
                },
                *extra_sessions,
            ]
        if "ip.ip AS ip" in query:
            return [
                {"process_uid": _LEAF_PROC, "ip": "10.1.0.1"},
                {"process_uid": _SPINE_PROC, "ip": "10.1.0.2"},
            ]
        if "ORIGINATES" in query:
            return origin
        return []  # no FILTERED_BY policy attachments in this estate

    return rows_for


def _predict(rows_for, scope: str, intents=()) -> tools_mod.RoutePrediction:
    from hst import path as path_engine

    session = _FakeGraphSession(rows_for)
    pinned = path_engine.pinned(session, snapshot_mod.Snapshot(4000, None))
    return tools_mod.route_prediction(pinned, scope, list(intents))


def _prefixes(prediction: tools_mod.RoutePrediction, context_uid: str) -> list[str]:
    return sorted(str(r["prefix"]) for r in prediction.delta.rib if r.get("context_uid") == context_uid)


def test_the_route_prediction_carries_each_peers_prefix_across_the_peering():
    prediction = _predict(_route_rows(), "dev:leaf101")

    assert (prediction.scope, prediction.scope_kind) == ("dev:leaf101", "device")
    assert _prefixes(prediction, "vrf:leaf101:default") == ["10.10.0.0/24", "10.20.0.0/24"]
    learned = next(
        r
        for r in prediction.delta.rib
        if r.get("context_uid") == "vrf:leaf101:default" and r["prefix"] == "10.20.0.0/24"
    )
    assert learned["as_path"] == [65002], "the sending ASN was prepended on export"


def test_the_route_prediction_resolves_a_hostname_and_accepts_a_vrf_scope():
    by_name = _predict(_route_rows(), "leaf101")
    by_vrf = _predict(_route_rows(), "vrf:leaf101:default")

    assert (by_name.scope, by_name.scope_kind) == ("dev:leaf101", "device")
    assert (by_vrf.scope, by_vrf.scope_kind) == ("vrf:leaf101:default", "vrf")


def test_the_route_prediction_refuses_an_ambiguous_hostname():
    def rows_for(query: str) -> list[dict]:
        if "toLower(d.hostname)" in query:
            return [_device_row(), _device_row(uid="dev:leaf101b", hostname="leaf101b")]
        return _route_rows()(query)

    with pytest.raises(ValueError, match=r"ambiguous device name 'leaf'.*dev:leaf101b"):
        _predict(rows_for, "leaf")


def test_the_route_prediction_returns_every_model_error_whole():
    orphan = {
        "uid": "bgp:leaf101:198.51.100.7",
        "process_uid": _LEAF_PROC,
        "props": {
            "uid": "bgp:leaf101:198.51.100.7",
            "peer_ip": "198.51.100.7",
            "local_asn": 65001,
            "peer_asn": 64512,
        },
    }
    errors = _predict(_route_rows(extra_sessions=(orphan,)), "dev:leaf101").delta.model_errors

    kinds = [e["kind"] for e in errors]
    assert "origination-not-recorded" in kinds
    unpaired = next(e for e in errors if e["kind"] == "unpaired-bgp-session")
    assert unpaired["subject"] == "bgp:leaf101:198.51.100.7"
    assert unpaired["detail"], "the prose caveat travels with the kind"


def test_a_bgp_session_shut_intent_removes_the_routes_learned_across_it():
    intents = [{"kind": "bgp_session.shut", "params": {"session": "bgp:leaf101:10.1.0.2"}}]
    prediction = _predict(_route_rows(), "dev:leaf101", intents)

    assert _prefixes(prediction, "vrf:leaf101:default") == ["10.10.0.0/24"]
    assert "unpaired-bgp-session" in [e["kind"] for e in prediction.delta.model_errors]


def test_a_static_route_add_intent_appears_in_the_rib():
    params = {"context_uid": "vrf:leaf101:default", "prefix": "198.51.100.0/24"}
    prediction = _predict(_route_rows(), "dev:leaf101", [{"kind": "static_route.add", "params": params}])

    assert "198.51.100.0/24" in _prefixes(prediction, "vrf:leaf101:default")


@pytest.mark.parametrize(
    "intent",
    [
        {"kind": "route_policy.attach", "params": {"session": "bgp:leaf101:10.1.0.2", "policy": "x"}},
        {"kind": "fw_rule.add", "params": {"rulebase": "fw:LAN"}},
    ],
)
def test_a_simulator_kind_the_prediction_does_not_apply_is_named_not_modeled(intent):
    baseline = _predict(_route_rows(), "dev:leaf101")
    prediction = _predict(_route_rows(), "dev:leaf101", [intent])

    assert prediction.delta.rib == baseline.delta.rib, "not modeled yet: the prediction must not change"
    entry = next(e for e in prediction.delta.model_errors if e["kind"] == "not-modeled-yet")
    assert entry["subject"] == intent["kind"]


def test_the_route_prediction_rejects_a_kind_outside_the_simulator_catalog():
    with pytest.raises(ValueError, match=r"vlan\.add"):
        _predict(_route_rows(), "dev:leaf101", [{"kind": "vlan.add", "params": {}}])


# --- question context -----------------------------------------------------------
#
# The panes of the change-simulation workspace read what the pinned snapshot
# records about the entities a question names.


def _context_ctx(role: str = "operator", settings=None) -> ToolContext:
    return _tool_context(role, settings if settings is not None else object())


def _context_rows(query: str) -> list[dict]:
    """Both reads the context can run, off one fake session: the address
    sections inventory_resolve reads and the device identity assess reads."""
    if "software_version" in query:
        return [_device_row()]
    if "toLower(d.hostname) = toLower($name)" in query:
        return [{"uid": "dev:leaf101", "hostname": "leaf101", "role": "switch", "vendor": "cisco"}]
    return _address_rows(query)


def test_context_names_the_addresses_and_hostnames_a_question_holds():
    addresses, names = agent_context.extract_entities(
        "can 192.168.2.35 reach 2001:db8::1 through leaf101 or dc1-spine2 after the reload?"
    )
    assert addresses == ["192.168.2.35", "2001:db8::1"]
    assert names == ["leaf101", "dc1-spine2"]


def test_context_names_nothing_in_a_question_that_holds_nothing():
    assert agent_context.extract_entities("what does this snapshot record about the estate?") == ([], [])


def test_context_leaves_a_prefix_and_a_time_of_day_alone():
    addresses, _ = agent_context.extract_entities("was 10.0.0.0/24 withdrawn at 10:30 on version 4.2.1?")
    assert addresses == []


def test_context_reads_an_address_the_model_was_never_asked_to_resolve(monkeypatch):
    session = _FakeGraphSession(_context_rows)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    entries = agent_context.build(_context_ctx(), "is 192.168.2.35 a peer or a client host?")

    assert [(e["kind"], e["tool"], e["subject"]) for e in entries] == [
        ("address", "inventory_resolve", "192.168.2.35")
    ]
    envelope = entries[0]["result"]
    assert envelope["snapshot"]["id"] == "4000"
    assert envelope["result"]["address"] == "192.168.2.35"
    assert [n["anchor"] for n in envelope["result"]["sections"]["ip_nodes"]["rows"]] == [
        "bd:site1:20",
        "site1-core",
    ]


def test_context_assesses_the_device_a_hostname_resolves_to(monkeypatch):
    session = _FakeGraphSession(_context_rows)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    entries = agent_context.build(_context_ctx(), "what breaks if leaf101 is reloaded tonight?")

    assert [(e["kind"], e["tool"], e["subject"]) for e in entries] == [
        ("device", "impact_assess", "dev:leaf101")
    ]
    # the buckets impact_assess returns to the model, through the same tool
    result = entries[0]["result"]["result"]
    assert result["device"]["uid"] == "dev:leaf101"
    assert result["buckets"]["single_homed_prefixes"] == {"count": 0, "items": [], "truncated": False}


def test_context_leaves_an_ambiguous_hostname_alone(monkeypatch):
    def rows_for(query: str) -> list[dict]:
        if "toLower(d.hostname) = toLower($name)" in query:
            return []
        if "STARTS WITH toLower($name)" in query:
            return [
                {"uid": "dev:leaf101", "hostname": "leaf101", "role": "switch", "vendor": "cisco"},
                {"uid": "dev:leaf102", "hostname": "leaf102", "role": "switch", "vendor": "cisco"},
            ]
        if "software_version" in query:
            raise AssertionError("an ambiguous name must not reach assess")
        return []

    session = _FakeGraphSession(rows_for)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    assert agent_context.build(_context_ctx(), "what if leaf-1 reloads?") == []


def test_a_question_naming_no_entity_reads_nothing(monkeypatch):
    session = _FakeGraphSession(_context_rows)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    assert agent_context.build(_context_ctx(), "what does the snapshot record?") == []
    assert session.calls == [], "no entity named, no graph read"


def test_context_is_bounded_per_question(monkeypatch):
    session = _FakeGraphSession(_context_rows)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    question = " ".join(f"10.0.0.{n}" for n in range(1, 9))
    entries = agent_context.build(_context_ctx(), question)

    assert len(entries) == agent_context.MAX_ENTITIES


def test_context_passes_the_same_permission_gate_the_tools_do(monkeypatch):
    """A caller without graph.read is refused every read by invoke's own check,
    so the context is empty."""
    session = _FakeGraphSession(_context_rows)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    assert agent_context.build(_context_ctx(role="no-such-role"), "what about 192.168.2.35?") == []
    assert session.calls == []


def test_a_failing_context_read_degrades_to_no_context(monkeypatch):
    @contextmanager
    def broken(settings):
        raise RuntimeError("the driver is down")
        yield  # pragma: no cover

    monkeypatch.setattr(db_mod, "session", broken)

    assert agent_context.build(_context_ctx(), "what about 192.168.2.35 and leaf101?") == []


async def test_ask_returns_the_question_context_beside_the_answer(client, monkeypatch):
    """This adapter calls no tool."""
    session = _FakeGraphSession(_context_rows)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    class _Adapter:
        def ask(self, question, **kwargs):
            return agent_base.AgentAnswer(answer="that address is a printer")

    await _configure(client, monkeypatch, _Adapter())
    result = await _ask_and_wait(
        client,
        {"question": "what is 192.168.2.35?", "include_context": True},
    )

    assert result["status"] == "done"
    assert result["steps"] == []
    assert [(e["kind"], e["subject"]) for e in result["context"]] == [("address", "192.168.2.35")]
    assert result["context"][0]["result"]["result"]["address"] == "192.168.2.35"


async def test_an_ask_that_did_not_request_context_carries_none(client, monkeypatch):
    """The drawer asks the same endpoint and is charged nothing for the reads."""
    session = _FakeGraphSession(_context_rows)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    class _Adapter:
        def ask(self, question, **kwargs):
            return agent_base.AgentAnswer(answer="ok")

    await _configure(client, monkeypatch, _Adapter())
    result = await _ask_and_wait(client, {"question": "what is 192.168.2.35?"})

    assert result["context"] == []
    assert session.calls == []


async def test_a_broken_context_read_answers_the_question(client, monkeypatch):
    """A failure in the context reads is never the ask's failure."""

    def explode(tools, question):
        raise RuntimeError("context is broken")

    monkeypatch.setattr(agent_context, "build", explode)

    class _Adapter:
        def ask(self, question, **kwargs):
            return agent_base.AgentAnswer(answer="answered anyway")

    await _configure(client, monkeypatch, _Adapter())
    result = await _ask_and_wait(client, {"question": "what is 192.168.2.35?", "include_context": True})

    assert result["status"] == "done"
    assert result["answer"] == "answered anyway"
    assert result["context"] == []


def test_step_results_reach_the_ui_without_the_untrusted_envelope() -> None:
    """The UI parses a step's `result` as JSON to fill the workspace panes."""
    from hst.app.agent import tools as tools_mod

    payload = '{"flows": [], "model_errors": [], "flow_count": 0}'
    framed = tools_mod.frame_untrusted(payload)
    assert framed != payload
    assert tools_mod.unframe(framed) == payload
    # a tool error is framed too, and unframes to its text
    error = tools_mod.frame_untrusted("ValueError: no such rulebase")
    assert error != "ValueError: no such rulebase"
    assert tools_mod.unframe(error) == "ValueError: no such rulebase"
    # text with no frame is returned untouched
    assert tools_mod.unframe("ValueError: no such rulebase") == "ValueError: no such rulebase"


# --- side-store reader lifecycle and the model copy's cap -----------------------


class _CountingReader:
    """A side-store reader double that counts how often it is closed."""

    def __init__(self, opened: list) -> None:
        self.closes = 0
        opened.append(self)

    def close(self) -> None:
        self.closes += 1


def _count_readers(monkeypatch) -> list:
    """Route every `for_snapshot` factory to a counting reader."""
    from hst.core import bgpsource, ospfsource, ribsource

    opened: list[_CountingReader] = []
    for module in (ribsource, bgpsource, ospfsource):
        monkeypatch.setattr(module, "for_snapshot", lambda snap: _CountingReader(opened))
    return opened


def test_reader_pool_closes_what_it_built_when_a_later_reader_fails(monkeypatch):
    from hst.app.agent.readers import ReaderPool
    from hst.core import ospfsource

    opened = _count_readers(monkeypatch)

    def unreadable(snap):
        raise OSError("side store unreadable")

    monkeypatch.setattr(ospfsource, "for_snapshot", unreadable)
    with pytest.raises(OSError, match="side store unreadable"), ReaderPool() as readers:
        readers.rib(SimpleNamespace(cts=4000))
        readers.bgp(SimpleNamespace(cts=4000))
        readers.ospf(SimpleNamespace(cts=4000))
    assert [reader.closes for reader in opened] == [1, 1]


def test_reader_pool_closes_the_rest_when_one_close_fails(monkeypatch, caplog):
    from hst.app.agent.readers import ReaderPool

    opened = _count_readers(monkeypatch)

    def broken_close() -> None:
        raise RuntimeError("close failed")

    with ReaderPool() as readers:
        readers.rib(SimpleNamespace(cts=4000)).close = broken_close
        readers.bgp(SimpleNamespace(cts=4000))
    assert opened[1].closes == 1
    assert "closing a side-store reader failed" in caplog.text


def _large_cypher_table() -> dict:
    """500 rows, the executor's row cap, whose envelope stays under the 4 MiB
    result cap."""
    rows = [{"row": [f"dev:{i:06d}", "x" * 8200]} for i in range(500)]
    return {"columns": ["uid", "pad"], "data": rows, "truncated": False}


def _compact(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _large_cypher_step(monkeypatch) -> tools_mod.ToolCall:
    """One query_cypher call as the drawer offers it, over `_large_cypher_table`."""
    import hst.twin_tools.query as query_mod

    table = _large_cypher_table()
    monkeypatch.setattr(query_mod, "run_readonly", lambda s, q, p, graph=False: table)
    monkeypatch.setattr(db_mod, "session", _db_seam(_FakeGraphSession(lambda query: [], current=4000)))
    tools = tools_mod.offered_tools(_tool_context("operator"))
    return tools_mod.dispatch(tools, "query_cypher", {"query": _GUARDED_ANY})


def test_a_4_mib_cypher_result_reaches_the_model_capped_and_flagged(monkeypatch):
    """The model copy drops trailing rows of the result until the envelope fits
    in 100,000 characters, and says so. The UI copy is the envelope as the tool
    returned it."""
    from hst.app.agent import traffic
    from hst.app.tables import MAX_RESULT_BYTES

    table = _large_cypher_table()
    outcome = _large_cypher_step(monkeypatch)

    assert outcome.is_error is False, outcome.result
    assert outcome.result.startswith('<tool_result untrusted="true">')
    assert outcome.ui_result is not None
    assert 4_000_000 < len(outcome.ui_result.encode()) <= MAX_RESULT_BYTES
    envelope = json.loads(outcome.ui_result)
    assert envelope["result"]["data"] == table["data"]
    model_copy = tools_mod.unframe(outcome.result)
    assert len(model_copy) <= traffic.MAX_RESULT_CHARS == 100_000
    body = json.loads(model_copy)
    assert body["output_truncated"] is True
    assert body["result"]["columns"] == table["columns"]
    assert body["result"]["truncated"] is False
    kept = len(body["result"]["data"])
    assert 0 < kept < len(table["data"])
    assert body["result"]["data"] == table["data"][:kept]
    # only trailing rows that could not fit were dropped
    assert len(model_copy) + 1 + len(_compact(table["data"][kept])) > traffic.MAX_RESULT_CHARS
    assert body["warnings"] == [
        f"result.data lists {kept} of 500 items in this copy, cut to fit 100000 characters; "
        "narrow the request to read the rest"
    ]
    for key in ("snapshot", "provenance", "evidence", "page"):
        assert body[key] == envelope[key]


async def test_a_step_keeps_the_ui_cap_when_the_model_copy_is_capped(client, monkeypatch):
    """The UI copy of a step is cut at MAX_STEP_RESULT_CHARS, independent of
    the smaller cap on the model copy."""
    import hst.twin_tools.query as query_mod
    from hst.app.agent import traffic

    table = _large_cypher_table()
    monkeypatch.setattr(query_mod, "run_readonly", lambda s, q, p, graph=False: table)
    monkeypatch.setattr(db_mod, "session", _db_seam(_FakeGraphSession(lambda query: [], current=4000)))
    calls: list[tools_mod.ToolCall] = []

    class _Adapter:
        def ask(self, question, *, tools, **kwargs):
            calls.append(tools_mod.dispatch(tools, "query_cypher", {"query": _GUARDED_ANY}))
            return agent_base.AgentAnswer(answer="ok", steps=list(calls))

    await _configure(client, monkeypatch, _Adapter())
    result = await _ask_and_wait(client, {"question": "every device"})

    assert result["status"] == "done"
    [step] = result["steps"]
    [call] = calls
    assert step["is_error"] is False
    assert call.ui_result is not None and len(call.ui_result) > ai_routes.MAX_STEP_RESULT_CHARS
    assert step["result"] == call.ui_result[: ai_routes.MAX_STEP_RESULT_CHARS]
    assert len(step["result"]) == ai_routes.MAX_STEP_RESULT_CHARS == 200_000
    assert len(tools_mod.unframe(call.result)) <= traffic.MAX_RESULT_CHARS


def test_a_result_with_no_list_to_shorten_becomes_an_error_step():
    from hst.app.agent import traffic

    def oversize() -> str:
        return json.dumps({"summary": "x" * (traffic.MAX_RESULT_CHARS + 1), "rows": ["a", "b"]})

    tools = [Tool("oversize", "", {"type": "object", "properties": {}}, "viewer", oversize)]
    outcome = tools_mod.dispatch(tools, "oversize", {})

    assert outcome.is_error is True
    assert "exceeds the 100000-character limit" in outcome.result
    assert len(outcome.result) <= traffic.MAX_RESULT_CHARS


def test_reach_trace_groups_reaches_the_model_bounded_with_its_counts(monkeypatch):
    """A groups page larger than the model copy keeps its first rectangles in
    the model copy, with the counts, the page and the run the tool computed."""
    import copy

    from hst.app.agent import traffic

    items = [
        {
            "sources": [f"10.{i}.{j}.0/24" for j in range(150)],
            "destinations": ["192.0.2.0/24"],
            "protocols": ["tcp"],
            "destination_ports": "443",
            "source_ports": "any",
        }
        for i in range(traffic.RESULT_CAP)
    ]

    def bucket(rows: list, count: int) -> dict:
        return {"count": count, "items": rows, "truncated": count > len(rows)}

    body = {
        "status": "complete",
        "allowed": bucket(items, 4000),
        "denied": bucket([], 0),
        "not_established": bucket([], 0),
        "evidence": bucket([], 0),
        "coverage": {
            "entire_request_evaluated": True,
            "entire_request_decided": True,
            "output_truncated": False,
        },
    }
    _count_readers(monkeypatch)
    monkeypatch.setattr(db_mod, "session", _db_seam(_FakeGraphSession(lambda query: [], current=4000)))
    monkeypatch.setattr(traffic, "query", lambda pinned, **kwargs: copy.deepcopy(body))

    outcome = tools_mod.dispatch(
        [_reach_trace_tool()],
        "reach_trace",
        {"mode": "groups", "source": {"kind": "non-rfc1918"}, "destination": {"kind": "vlan", "value": "10"}},
    )

    assert outcome.is_error is False, outcome.result
    assert outcome.ui_result is not None
    envelope = json.loads(outcome.ui_result)
    page = envelope["result"]["passes"]["items"]
    # one page of the default limit
    assert page == items[:50]
    model_copy = tools_mod.unframe(outcome.result)
    assert len(model_copy) <= traffic.MAX_RESULT_CHARS
    capped = json.loads(model_copy)
    assert capped["output_truncated"] is True
    kept = len(capped["result"]["passes"]["items"])
    assert 0 < kept < len(page)
    assert capped["result"]["passes"]["items"] == page[:kept]
    assert len(model_copy) + 1 + len(_compact(page[kept])) > traffic.MAX_RESULT_CHARS
    assert capped["result"]["passes"]["count"] == 4000
    assert capped["warnings"] == [
        *envelope["warnings"],
        f"result.passes.items lists {kept} of 50 items in this copy, cut to fit 100000 characters; "
        "narrow the request or lower limit to read the rest",
        "page.truncated is true because this copy leaves items of the page out; page.next_cursor "
        "continues after the whole page and does not return them",
    ]
    for key in ("snapshot", "evidence", "page"):
        assert capped[key] == envelope[key]
    assert capped["page"]["truncated"] is True


def test_an_error_step_is_capped_like_a_result():
    """An exception message can echo model input. The model copy of the error
    is cut to MAX_RESULT_CHARS and ends with a note that it was cut. The UI
    copy keeps the full text."""
    from hst.app.agent import traffic

    message = "x" * (4 * 1024 * 1024)

    def fails() -> str:
        raise ValueError(message)

    tools = [Tool("fails", "", {"type": "object", "properties": {}}, "viewer", fails)]
    outcome = tools_mod.dispatch(tools, "fails", {})

    assert outcome.is_error is True
    model_copy = tools_mod.unframe(outcome.result)
    assert model_copy.startswith("ValueError: xxx")
    assert len(model_copy) == traffic.MAX_RESULT_CHARS
    assert model_copy.endswith(f"\n[error text cut to {traffic.MAX_RESULT_CHARS} characters]")
    assert outcome.ui_result == f"ValueError: {message}"


# --- one evaluate_request, tool-contract parity ----------------------------


_OVERSIZE_INTENTS = [{"kind": "fw_rule.add", "params": {"rulebase": "fw:LAN"}}] * 51


async def test_51_intents_are_refused_by_the_route_and_the_agent_tool(client, monkeypatch):
    from hst.app.routes import impact as impact_route

    def no_engine(*args, **kwargs):
        raise AssertionError("the engine ran on an oversize change set")

    monkeypatch.setattr(impact_route, "evaluate_change", no_engine)
    monkeypatch.setattr(db_mod, "session", _db_seam(_FakeGraphSession(lambda query: [], current=4000)))
    await login(client, "vera")

    r = await client.post(
        "/api/impact/evaluate", json={"requirement": "sreq:app", "intents": _OVERSIZE_INTENTS}
    )
    assert r.status_code == 422

    settings = Settings(_env_file=None, hst_secret_key=generate_key(), analysis_engine="legacy-v1")
    call = tools_mod.dispatch(
        tools_mod.offered_tools(_tool_context(settings=settings)),
        "impact_evaluate_service",
        {"form": "requirement", "requirement": "sreq:app", "intents": _OVERSIZE_INTENTS},
    )
    assert call.is_error is True
    assert "intents" in tools_mod.unframe(call.result)
    assert "at most 50 items" in tools_mod.unframe(call.result)


@pytest.mark.parametrize("engine", ["legacy-v1", "symbolic-v2"])
def test_evaluate_request_refuses_51_intents_before_any_engine_read(monkeypatch, engine):
    from fastapi import HTTPException

    from hst.app.routes import impact as impact_route
    from hst.assessment import direct

    def no_engine(*args, **kwargs):
        raise AssertionError("the engine ran on an oversize change set")

    monkeypatch.setattr(impact_route, "evaluate_change", no_engine)
    monkeypatch.setattr(direct, "evaluate_pinned", no_engine)
    opened = _count_readers(monkeypatch)

    with pytest.raises(HTTPException) as caught:
        direct.evaluate_request(
            SimpleNamespace(analysis_engine=engine),
            object(),
            SimpleNamespace(cts=4000),
            intents=_OVERSIZE_INTENTS,
            requirement="sreq:app",
            request=None,
            mode="possible",
        )

    assert caught.value.status_code == 422
    assert caught.value.detail == "a change set states at most 50 intents"
    assert opened == []


def test_evaluate_request_opens_no_reader_in_this_process_for_either_engine(monkeypatch):
    """The question runs in the isolated child, which builds its own readers."""
    from hst.assessment import direct

    opened = _count_readers(monkeypatch)
    asked: list[dict] = []

    def pinned(settings, session, snap, **kwargs):
        asked.append(kwargs)
        return {"verdict": "computed"}

    monkeypatch.setattr(direct, "evaluate_pinned", pinned)

    for engine in ("legacy-v1", "symbolic-v2"):
        answer = direct.evaluate_request(
            SimpleNamespace(analysis_engine=engine),
            object(),
            SimpleNamespace(cts=4000),
            intents=[],
            requirement="sreq:app",
            request=None,
            mode="possible",
        )
        assert answer == {"verdict": "computed"}

    assert len(asked) == 2
    assert opened == []


@pytest.mark.parametrize(
    ("field", "value", "cap"),
    [
        ("intents", _OVERSIZE_INTENTS, 50),
        ("flows", [{"src": "a", "dst": "b"}] * 51, 50),
        ("sites", ["site:a"] * 21, 20),
    ],
)
@pytest.mark.parametrize("validation", ["warn", "enforce"])
def test_the_agent_refuses_an_oversize_simulation(monkeypatch, field, value, cap, validation):
    from hst.app import fw_overlay_read

    def no_engine(*args, **kwargs):
        raise AssertionError("the simulation ran on an oversize argument")

    def no_session(*args, **kwargs):
        raise AssertionError("an oversize simulation opens no session")

    monkeypatch.setattr(fw_overlay_read, "simulate_change", no_engine)
    monkeypatch.setattr(db_mod, "session", no_session)
    settings = Settings(_env_file=None, hst_secret_key=generate_key(), hst_ai_tool_validation=validation)
    arguments = {"intents": _OVERSIZE_INTENTS[:1], field: value}

    call = tools_mod.dispatch(
        tools_mod.offered_tools(_tool_context(settings=settings)), "change_simulate", arguments
    )

    assert call.is_error is True
    text = tools_mod.unframe(call.result)
    assert field in text
    assert f"at most {cap} items" in text


def test_the_simulation_caps_are_the_change_simulation_export_bounds():
    from hst.app.routes import changesim
    from hst.twin_tools import change, selectors

    assert (selectors.MAX_INTENTS, change.MAX_FLOWS, change.MAX_SITES) == (
        changesim.MAX_INTENTS,
        changesim.MAX_FLOWS,
        changesim.MAX_SITES,
    )


def test_the_question_context_of_an_unpinned_ask_reads_under_the_default_validation(monkeypatch):
    """With no turn snapshot the context's reads name no run, so each read
    resolves the pointer under the enforce default."""
    settings = Settings(_env_file=None, hst_secret_key=generate_key())
    assert settings.hst_ai_tool_validation == "enforce"
    session = _FakeGraphSession(_context_rows)
    monkeypatch.setattr(db_mod, "session", _db_seam(session))

    entries = agent_context.build(_context_ctx(settings=settings), "what about 192.168.2.35 and leaf101?")

    assert [(e["kind"], e["tool"], e["subject"]) for e in entries] == [
        ("address", "inventory_resolve", "192.168.2.35"),
        ("device", "impact_assess", "dev:leaf101"),
    ]
    assert entries[0]["result"]["snapshot"]["id"] == "4000"
