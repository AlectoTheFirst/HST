"""The real catalogue must be usable by Claude, including through OpenRouter."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from hst.app.agent.anthropic_ import AnthropicAdapter
from hst.app.agent.openrouter import OpenRouterAdapter
from hst.app.agent.tools import offered_tools
from hst.app.ai.registry import Principal, ToolContext, to_anthropic, to_openai
from hst.app.ai.schema import provider_input_schema
from hst.twin_tools import catalogue_registry


@pytest.mark.parametrize("provider", ["openrouter", "anthropic", "bedrock"])
def test_catalogue_requests_have_object_schemas_and_reject_invalid_mode_arguments(monkeypatch, provider):
    registry = catalogue_registry()
    ctx = ToolContext(settings=None, principal=Principal.for_role("admin"), surface="drawer")
    available = offered_tools(ctx, registry)
    originals = {tool.name: deepcopy(tool.schema) for tool in available}
    requests = []

    def create(**kwargs):
        requests.append(kwargs)
        for tool in kwargs["tools"]:
            schema = tool["function"]["parameters"] if provider == "openrouter" else tool["input_schema"]
            assert schema["type"] == "object"
            assert not {"oneOf", "allOf", "anyOf"}.intersection(schema)
        if provider == "openrouter":
            calls = (
                [
                    SimpleNamespace(
                        id="call1",
                        function=SimpleNamespace(name="inventory_get", arguments='{"kind":"device"}'),
                    )
                ]
                if len(requests) == 1
                else None
            )
            message = SimpleNamespace(content="done" if calls is None else None, tool_calls=calls)
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])
        content = (
            [SimpleNamespace(type="tool_use", id="call1", name="inventory_get", input={"kind": "device"})]
            if len(requests) == 1
            else [SimpleNamespace(type="text", text="done")]
        )
        return SimpleNamespace(stop_reason="tool_use" if len(requests) == 1 else "end_turn", content=content)

    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
        messages=SimpleNamespace(create=create),
        beta=SimpleNamespace(messages=SimpleNamespace(create=create)),
    )
    adapter = OpenRouterAdapter({}, {}) if provider == "openrouter" else AnthropicAdapter(provider, {}, {})
    monkeypatch.setattr(adapter, "_client", lambda: client)
    answer = adapter.ask("get the device", system="s", tools=available, model="m", effort="medium")

    assert answer.answer == "done"
    assert len(answer.steps) == 1
    assert answer.steps[0].is_error
    assert answer.steps[0].ui_result == "ToolError: invalid arguments: device: Field required"
    serializer = to_openai if provider == "openrouter" else to_anthropic
    assert requests[0]["tools"] == [serializer(spec) for spec in registry.offered(ctx.principal, ctx.surface)]
    assert {tool.name: tool.schema for tool in available} == originals
    assert {spec.name: spec.input_schema() for spec in registry.specs()} == originals


def test_mode_projection_preserves_fields_constraints_and_explains_required_arguments():
    schema = catalogue_registry().get("inventory_get").input_schema()
    original = deepcopy(schema)
    projected = provider_input_schema(schema)

    assert projected["required"] == ["kind"]
    assert projected["properties"]["kind"]["enum"] == ["device", "site"]
    assert "kind=device: required fields: device;" in projected["properties"]["kind"]["description"]
    assert "kind=site: required fields: none;" in projected["properties"]["kind"]["description"]
    for name, field in schema["properties"].items():
        if name != "kind":
            assert projected["properties"][name] == field
    assert projected["$defs"] == schema["$defs"]
    assert schema == original
    assert provider_input_schema(projected) == projected


def test_shared_fields_keep_each_modes_constraints():
    schema = catalogue_registry().get("inventory_get").input_schema()
    schema["$defs"]["SiteGetInput"]["properties"]["device"] = {"type": "integer"}
    projected = provider_input_schema(schema)

    assert projected["properties"]["device"]["anyOf"] == [
        schema["$defs"]["DeviceGetInput"]["properties"]["device"],
        {"type": "integer"},
    ]


def test_ordinary_schemas_keep_nested_unions_and_references():
    schema = catalogue_registry().get("reach_audit_mtu").input_schema()
    assert provider_input_schema(schema) == schema
