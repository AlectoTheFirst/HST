"""The tool registry: specs, offered lists, the invoke pipeline, input models.

`tests/golden/agent_catalogue_schemas.json` holds the tool definitions the
conversational surfaces offer a principal with every permission, in catalogue
order: under `anthropic` in the Anthropic Messages format and under `openai`
in the OpenAI function format.
"""

import json
import logging
import os
import pathlib
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

from hst.app.agent import context as agent_context
from hst.app.agent import tools as tools_mod
from hst.app.agent.anthropic_ import AnthropicAdapter
from hst.app.agent.openrouter import OpenRouterAdapter
from hst.app.ai.registry import (
    Principal,
    ToolContext,
    ToolLimits,
    ToolRegistry,
    ToolSpec,
    to_anthropic,
    to_openai,
)

GOLDEN = pathlib.Path(__file__).resolve().parents[1] / "golden" / "agent_catalogue_schemas.json"
ROLES = ("viewer", "operator", "admin")
AGENT_SURFACES = ("drawer", "changesim", "assessment_qa")
# Tool names the catalogue does not offer.
OLD_AGENT_TOOLS = (
    "saved_assessments",
    "mtu_audit",
    "trace_path",
    "allowed_traffic",
    "find_device",
    "assess_impact",
    "resolve_address",
    "predict_routes",
    "simulate_policy_change",
    "evaluate_service_impact",
    "run_cypher",
)
# The read tools a viewer holds the permission for, in catalogue order.
VIEWER_TOOLS = [
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


def _golden() -> dict[str, list[dict[str, Any]]]:
    return json.loads(GOLDEN.read_text())


def _every_permission() -> list[ToolSpec]:
    return tools_mod.agent_registry().offered(Principal.for_role("admin"), "drawer")


class _ProbeInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    name: str


class _AnyInput(BaseModel):
    model_config = ConfigDict(extra="allow")


def _spec(run, *, name="probe", permission="graph.read", limits: ToolLimits | None = None) -> ToolSpec:
    return ToolSpec(
        name=name,
        version=1,
        description="a test tool",
        input_model=_ProbeInput,
        permission=permission,
        kind="read",
        snapshot="none",
        run=run,
        surfaces=frozenset({"drawer"}),
        limits=limits or ToolLimits(),
    )


def _registry(*specs: ToolSpec) -> ToolRegistry:
    registry = ToolRegistry()
    for spec in specs:
        registry.register(spec)
    return registry


def _ctx(role="viewer", settings=None) -> ToolContext:
    return ToolContext(settings=settings, principal=Principal.for_role(role), surface="drawer")


# --- wire schemas ------------------------------------------------------------------------


def test_the_agent_catalogue_publishes_the_golden_schemas_in_both_provider_formats():
    specs = _every_permission()
    assert [to_anthropic(spec) for spec in specs] == _golden()["anthropic"]
    assert [to_openai(spec) for spec in specs] == _golden()["openai"]
    offered = tools_mod.offered_tools(_ctx("admin"))
    # The provider projection is applied at serialization; catalogue/MCP
    # schemas and the inputs used for local validation retain their unions.
    assert [{"name": t.name, "description": t.description, "input_schema": t.schema} for t in offered] == [
        {"name": spec.name, "description": spec.description, "input_schema": spec.input_schema()}
        for spec in specs
    ]


def test_the_golden_holds_the_28_read_tools_of_the_catalogue():
    golden = _golden()
    names = [tool["name"] for tool in golden["anthropic"]]
    assert len(names) == 28
    assert names == [tool["function"]["name"] for tool in golden["openai"]]
    assert names == [spec.name for spec in tools_mod.agent_registry().specs() if spec.kind == "read"]


def test_the_adapters_send_what_to_anthropic_and_to_openai_build(monkeypatch):
    """The adapters build their wire tools from the offered `Tool` objects;
    what they send equals the registry's own adapters."""
    specs = _every_permission()
    offered = tools_mod.offered_tools(_ctx("admin"))

    anthropic_requests: list[dict[str, Any]] = []

    def anthropic_create(**kwargs):
        anthropic_requests.append(kwargs)
        return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text="done")])

    stub = SimpleNamespace(
        messages=SimpleNamespace(create=anthropic_create),
        beta=SimpleNamespace(messages=SimpleNamespace(create=anthropic_create)),
    )
    anthropic = AnthropicAdapter("anthropic", {"api_key": "k"}, {})
    monkeypatch.setattr(anthropic, "_client", lambda: stub)
    anthropic.ask("q", system="s", tools=offered, model="m", effort="high")
    assert anthropic_requests[0]["tools"] == [to_anthropic(spec) for spec in specs]

    openai_requests: list[dict[str, Any]] = []

    def openai_create(**kwargs):
        openai_requests.append(kwargs)
        message = SimpleNamespace(content="done", tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=openai_create)))
    openrouter = OpenRouterAdapter({"api_key": "k"}, {})
    monkeypatch.setattr(openrouter, "_client", lambda: client)
    openrouter.ask("q", system="s", tools=offered, model="m", effort="medium")
    assert openai_requests[0]["tools"] == [to_openai(spec) for spec in specs]


# --- offered -----------------------------------------------------------------------------


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("surface", AGENT_SURFACES)
def test_each_conversational_surface_offers_the_read_tools_the_role_holds(role, surface):
    principal = Principal.for_role(role)
    offered = tools_mod.agent_registry().offered(principal, surface)
    assert [spec.name for spec in offered] == [
        spec.name
        for spec in tools_mod.agent_registry().specs()
        if spec.kind == "read" and spec.permission in principal.permissions
    ]
    assert all(spec.kind == "read" for spec in offered)
    assert not {spec.name for spec in offered} & set(OLD_AGENT_TOOLS)


def test_offered_for_a_viewer_is_the_viewer_roster():
    offered = tools_mod.agent_registry().offered(Principal.for_role("viewer"), "drawer")
    assert [spec.name for spec in offered] == VIEWER_TOOLS
    assert "query_cypher" not in VIEWER_TOOLS and "ops_list_collection_runs" not in VIEWER_TOOLS


@pytest.mark.parametrize("role", ["operator", "admin"])
def test_an_operator_is_offered_query_cypher_and_the_collection_runs(role):
    names = [spec.name for spec in tools_mod.agent_registry().offered(Principal.for_role(role), "drawer")]
    assert names == [*VIEWER_TOOLS[:-2], "ops_list_collection_runs", *VIEWER_TOOLS[-2:], "query_cypher"]


@pytest.mark.parametrize("role", ROLES)
def test_offered_is_empty_for_assessment_drafts(role):
    assert tools_mod.agent_registry().offered(Principal.for_role(role), "assessment_draft") == []


def test_offered_tools_follow_the_context_principal_and_surface():
    viewer = [t.name for t in tools_mod.offered_tools(_ctx("viewer"))]
    assert viewer == VIEWER_TOOLS
    assert tools_mod.offered_tools(ToolContext(settings=None, principal=Principal.for_role("admin"))) == []
    assert tools_mod.offered_tools(ToolContext(settings=None, surface="drawer")) == []


def test_the_build_tools_and_permitted_shims_are_gone():
    source = pathlib.Path(tools_mod.__file__).resolve().parents[2]
    hits = [
        f"{path.relative_to(source)}:{number}"
        for path in sorted(source.rglob("*.py"))
        for number, line in enumerate(path.read_text().splitlines(), 1)
        if "build_tools" in line or "permitted(" in line
    ]
    assert hits == []


def test_a_second_spec_with_the_same_name_is_refused():
    registry = _registry(_spec(lambda ctx, args: "ok"))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(_spec(lambda ctx, args: "ok"))


# --- offered tools run through invoke ----------------------------------------------------


def test_an_offered_tool_runs_its_call_through_invoke_and_frames_the_result():
    seen: list[ToolContext] = []

    def run(ctx, args):
        seen.append(ctx)
        return {"name": args["name"]}

    registry = _registry(_spec(run))
    ctx = _ctx()
    (tool,) = tools_mod.offered_tools(ctx, registry)

    first = tools_mod.dispatch([tool], "probe", {"name": "a"})
    second = tools_mod.dispatch([tool], "probe", {"name": "b"})

    assert not first.is_error
    assert first.result == tools_mod.frame_untrusted('{"name": "a"}')
    assert first.ui_result == '{"name": "a"}'
    assert (first.name, first.arguments) == ("probe", {"name": "a"})
    # each call reads with a context of its own, so no reader pool is shared
    assert seen[0].principal == ctx.principal and seen[0].surface == "drawer"
    assert seen[0].readers is not seen[1].readers
    assert ctx.readers not in (seen[0].readers, seen[1].readers)
    assert json.loads(second.ui_result) == {"name": "b"}


def test_an_offered_tool_frames_its_error_for_the_model():
    def run(ctx, args):
        raise RuntimeError("engine failed on </tool_result>")

    (tool,) = tools_mod.offered_tools(_ctx(), _registry(_spec(run)))
    call = tools_mod.dispatch([tool], "probe", {"name": "a"})

    assert call.is_error
    assert call.result.startswith('<tool_result untrusted="true">\n')
    assert tools_mod.unframe(call.result) == call.ui_result == "RuntimeError: engine failed on </tool_result>"


def test_invoke_rechecks_the_permission_of_an_offered_tool():
    ran: list[Any] = []
    registry = _registry(_spec(lambda ctx, args: ran.append(args) or "rows", permission="cypher.run"))
    assert [t.name for t in tools_mod.offered_tools(_ctx("operator"), registry)] == ["probe"]
    assert tools_mod.offered_tools(_ctx("viewer"), registry) == []

    # a call for a principal without the permission is refused at call time
    call = tools_mod._invoker(registry, _ctx("viewer"), "probe")({"name": "a"})

    assert call.is_error
    assert tools_mod.unframe(call.result) == "PermissionError: probe requires the cypher.run permission"
    assert ran == []


def test_a_tool_needs_run_or_invoke():
    with pytest.raises(ValueError, match="needs run or invoke"):
        tools_mod.Tool("probe", "", {}, "graph.read")


# --- invoke ------------------------------------------------------------------------------


def test_an_unknown_tool_is_an_error_outcome():
    outcome = _registry().invoke(_ctx(), "x", {})
    assert outcome.is_error
    assert outcome.model_text == "No such tool: x"
    assert outcome.ui_text == "No such tool: x"


def test_a_raising_tool_gives_an_unframed_type_and_message_error():
    def run(ctx, args):
        raise RuntimeError("engine failed")

    outcome = _registry(_spec(run)).invoke(_ctx(), "probe", {"name": "a"})
    assert outcome.is_error
    assert outcome.model_text == "RuntimeError: engine failed"
    assert outcome.ui_text == "RuntimeError: engine failed"


def test_a_result_is_framed_for_the_model_and_unframed_for_the_ui():
    outcome = _registry(_spec(lambda ctx, args: {"name": args["name"]})).invoke(
        _ctx(), "probe", {"name": "a"}
    )
    assert not outcome.is_error
    assert outcome.model_text == tools_mod.frame_untrusted('{"name": "a"}')
    assert outcome.ui_text == '{"name": "a"}'
    assert outcome.name == "probe" and outcome.version == 1 and outcome.arguments == {"name": "a"}
    assert outcome.provenance is not None and outcome.provenance.snapshot is None


def test_the_permission_is_checked_again_at_call_time():
    ran: list[dict[str, Any]] = []

    def run(ctx, args):
        ran.append(args)
        return "rows"

    registry = _registry(_spec(run, name="run_cypher", permission="cypher.run"))
    outcome = registry.invoke(_ctx("viewer"), "run_cypher", {"name": "a"})
    assert outcome.is_error
    assert outcome.model_text == "PermissionError: run_cypher requires the cypher.run permission"
    assert not ran
    assert not registry.invoke(_ctx("operator"), "run_cypher", {"name": "a"}).is_error


def test_invoke_caps_the_model_copy_and_the_ui_copy_at_the_spec_limits():
    rows = [{"n": i} for i in range(100)]
    spec = _spec(lambda ctx, args: {"rows": rows}, limits=ToolLimits(max_model_chars=200, max_ui_chars=50))
    outcome = _registry(spec).invoke(_ctx(), "probe", {"name": "a"})
    assert not outcome.is_error
    model_copy = tools_mod.unframe(outcome.model_text)
    assert len(model_copy) <= 200
    assert json.loads(model_copy)["output_truncated"] is True
    assert outcome.ui_text == json.dumps({"rows": rows})[:50]


def _envelope(rows: list[Any]) -> dict[str, Any]:
    return {
        "snapshot": {"id": "4000", "run": None},
        "provenance": {"tool": "probe"},
        "evidence": {"status": "proven", "gaps": []},
        "page": {"next_cursor": None, "truncated": False, "limit": None},
        "result": {"buckets": {"hosts": {"count": len(rows), "items": rows}}},
        "warnings": [],
    }


def test_the_conversational_surfaces_bound_the_model_copy_at_100000_characters():
    from hst.app.agent import traffic
    from hst.app.ai import registry as registry_mod

    rows = [{"uid": f"dev:{i:06d}", "pad": "x" * 1000} for i in range(500)]
    limits = ToolLimits(max_model_chars=4 * 1024 * 1024, max_ui_chars=4 * 1024 * 1024)
    registry = _registry(_spec(lambda ctx, args: _envelope(rows), limits=limits))
    full = json.dumps(_envelope(rows))
    assert registry_mod.AGENT_MODEL_CHARS == traffic.MAX_RESULT_CHARS == 100_000

    for surface in AGENT_SURFACES:
        ctx = ToolContext(settings=None, principal=Principal.for_role("viewer"), surface=surface)
        outcome = registry.invoke(ctx, "probe", {"name": "a"})
        model_copy = tools_mod.unframe(outcome.model_text)
        assert len(model_copy) <= 100_000
        body = json.loads(model_copy)
        assert body["output_truncated"] is True
        kept = body["result"]["buckets"]["hosts"]["items"]
        assert kept == rows[: len(kept)] and 0 < len(kept) < len(rows)
        assert body["result"]["buckets"]["hosts"]["count"] == 500
        assert body["warnings"] == [
            f"result.buckets.hosts.items lists {len(kept)} of 500 items in this copy, cut to fit "
            "100000 characters; narrow the request to read the rest"
        ]
        assert outcome.ui_text == full

    # MCP keeps the spec's own bound
    mcp = ToolContext(settings=None, principal=Principal.for_role("viewer"), surface="mcp")
    outcome = registry.invoke(mcp, "probe", {"name": "a"})
    assert tools_mod.unframe(outcome.model_text) == outcome.ui_text == full


def test_the_conversational_surfaces_cut_an_error_text_at_100000_characters():
    message = "x" * 300_000

    def run(ctx, args):
        raise ValueError(message)

    limits = ToolLimits(max_model_chars=4 * 1024 * 1024, max_ui_chars=4 * 1024 * 1024)
    registry = _registry(_spec(run, limits=limits))

    outcome = registry.invoke(_ctx(), "probe", {"name": "a"})

    assert outcome.is_error
    assert len(outcome.model_text) == 100_000
    assert outcome.model_text.endswith("\n[error text cut to 100000 characters]")
    assert outcome.ui_text == f"ValueError: {message}"
    mcp = ToolContext(settings=None, principal=Principal.for_role("viewer"), surface="mcp")
    assert registry.invoke(mcp, "probe", {"name": "a"}).model_text == f"ValueError: {message}"


class _CountingReader:
    def __init__(self, opened: list["_CountingReader"]) -> None:
        self.closes = 0
        opened.append(self)

    def close(self) -> None:
        self.closes += 1


@pytest.mark.parametrize("fails", [False, True], ids=["success", "exception"])
def test_invoke_closes_the_readers_the_call_opened(monkeypatch, fails):
    from hst.core import bgpsource, ribsource

    opened: list[_CountingReader] = []
    monkeypatch.setattr(ribsource, "for_snapshot", lambda snap: _CountingReader(opened))
    monkeypatch.setattr(bgpsource, "for_snapshot", lambda snap: _CountingReader(opened))

    def run(ctx, args):
        ctx.readers.rib(SimpleNamespace(cts=1))
        ctx.readers.bgp(SimpleNamespace(cts=1))
        if fails:
            raise OSError("side store unreadable")
        return "ok"

    outcome = _registry(_spec(run)).invoke(_ctx(), "probe", {"name": "a"})
    assert outcome.is_error is fails
    assert [reader.closes for reader in opened] == [1, 1]


# --- validation --------------------------------------------------------------------------


def test_warn_mode_logs_one_warning_naming_the_tool_and_field_and_runs_the_call(caplog):
    ran: list[dict[str, Any]] = []

    def run(ctx, args):
        ran.append(args)
        return "ok"

    caplog.set_level(logging.WARNING, logger="hst.ai")
    outcome = _registry(_spec(run)).invoke(_ctx(), "probe", {"name": 5, "extra": True})
    assert not outcome.is_error
    assert ran == [{"name": 5, "extra": True}]
    records = [r for r in caplog.records if r.name == "hst.ai" and r.levelno == logging.WARNING]
    assert len(records) == 1
    message = records[0].getMessage()
    assert "probe" in message and "name:" in message and "extra:" in message


def test_enforce_mode_returns_the_mismatch_and_does_not_run_the_call(monkeypatch):
    from hst.core import db as dbmod

    def no_session(*args, **kwargs):
        raise AssertionError("a refused call opens no session")

    monkeypatch.setattr(dbmod, "session", no_session)
    settings = SimpleNamespace(hst_ai_tool_validation="enforce")
    tools = tools_mod.offered_tools(_ctx(settings=settings))

    call = tools_mod.dispatch(tools, "snapshot_list", {"limit": 500})

    assert call.is_error
    assert tools_mod.unframe(call.result).startswith(
        "ValueError: invalid arguments for snapshot_list: limit:"
    )


def test_the_setting_defaults_to_enforce_and_warn_stays_available():
    from hst.core.config import Settings

    assert Settings.model_fields["hst_ai_tool_validation"].default == "enforce"
    assert Settings(_env_file=None, hst_ai_tool_validation="warn").hst_ai_tool_validation == "warn"


# --- the question context reads through invoke ------------------------------------------


def test_context_build_reads_each_entity_through_registry_invoke():
    calls: list[tuple[str, dict[str, Any], Any]] = []

    class _Recording(ToolRegistry):
        def invoke(self, ctx, name, raw_args, *, label=0):
            calls.append((name, raw_args, ctx))
            return super().invoke(ctx, name, raw_args, label=label)

    def envelope(result: dict[str, Any]) -> str:
        return json.dumps({"snapshot": {"id": "3000"}, "provenance": {}, "result": result})

    registry = _Recording()
    for name, result in (
        ("inventory_resolve", {"kind": "address"}),
        ("impact_assess", {"device_uid": "dev:leaf101"}),
    ):
        registry.register(
            ToolSpec(
                name=name,
                version=1,
                description="a test tool",
                input_model=_AnyInput,
                permission="graph.read",
                kind="read",
                snapshot="graph",
                run=lambda ctx, args, result=result: envelope(result),
                surfaces=frozenset({"drawer"}),
            )
        )
    ctx = _ctx()

    entries = agent_context.build(ctx, "what is 10.0.0.1 behind leaf101?", registry)

    assert [(name, arguments) for name, arguments, _ in calls] == [
        ("inventory_resolve", {"kind": "address", "address": "10.0.0.1"}),
        ("impact_assess", {"subject": "device", "device": "leaf101"}),
    ]
    assert all(call_ctx.principal == ctx.principal for _, _, call_ctx in calls)
    assert [(e["kind"], e["subject"], e["tool"]) for e in entries] == [
        ("address", "10.0.0.1", "inventory_resolve"),
        ("device", "dev:leaf101", "impact_assess"),
    ]
    assert entries[0]["result"]["snapshot"]["id"] == "3000"


def test_the_registry_and_the_agent_tools_import_without_fastapi():
    code = (
        "import sys\n"
        "import hst.app.ai.registry\n"
        "import hst.app.agent.tools\n"
        "print('fastapi' in sys.modules)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=dict(os.environ), check=True
    )
    assert result.stdout.strip() == "False"


# --- item caps and the app store bridge ------------------------------------------------


class _ListInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    items: list[str]


@pytest.mark.parametrize("validation", ["warn", "enforce"])
def test_invoke_refuses_a_list_longer_than_its_cap_and_does_not_run_the_call(validation):
    ran: list[Any] = []
    spec = ToolSpec(
        name="probe",
        version=1,
        description="a test tool",
        input_model=_ListInput,
        permission="graph.read",
        kind="read",
        snapshot="none",
        run=lambda ctx, arguments: ran.append(arguments) or "ok",
        surfaces=frozenset({"drawer"}),
        limits=ToolLimits(max_items={"items": 2}),
    )
    ctx = _ctx(settings=SimpleNamespace(hst_ai_tool_validation=validation))

    refused = _registry(spec).invoke(ctx, "probe", {"items": ["a", "b", "c"]})
    accepted = _registry(spec).invoke(ctx, "probe", {"items": ["a", "b"]})

    assert refused.is_error
    assert refused.model_text == "ValueError: invalid arguments for probe: items: at most 2 items, got 3"
    assert not accepted.is_error
    assert ran == [{"items": ["a", "b"]}]


def test_call_async_without_a_loop_runs_the_coroutine_on_a_new_loop():
    async def answer() -> int:
        return 42

    assert ToolContext(settings=None).call_async(answer()) == 42


async def test_call_async_runs_the_coroutine_on_the_given_loop():
    import asyncio
    import threading

    owner = threading.get_ident()
    ran_on: list[int] = []

    async def answer() -> int:
        ran_on.append(threading.get_ident())
        return 42

    ctx = ToolContext(settings=None, loop=asyncio.get_running_loop())

    assert await asyncio.to_thread(ctx.call_async, answer()) == 42
    assert ran_on == [owner]


def test_call_async_without_a_loop_gives_up_after_its_timeout():
    import asyncio

    cancelled: list[bool] = []

    async def slow() -> int:
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        return 42

    with pytest.raises(TimeoutError):
        ToolContext(settings=None).call_async(slow(), timeout_s=0.05)
    assert cancelled == [True]


async def test_call_async_on_a_loop_gives_up_after_its_timeout_and_cancels_the_coroutine():
    import asyncio

    cancelled = asyncio.Event()

    async def slow() -> int:
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return 42

    ctx = ToolContext(settings=None, loop=asyncio.get_running_loop())

    with pytest.raises(TimeoutError):
        await asyncio.to_thread(ctx.call_async, slow(), 0.05)
    await asyncio.wait_for(cancelled.wait(), 2)


# --- argument normalization and the enforce refusals ---------------------------------


class _RunInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    name: str
    snapshot: str = Field(default=None)
    port: str = Field(default=None)
    limit: int = Field(default=None)


class _FlowInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    port: int


def _recording_spec(ran: list[dict[str, Any]], input_model: type[BaseModel] = _RunInput) -> ToolSpec:
    return ToolSpec(
        name="probe",
        version=1,
        description="a test tool",
        input_model=input_model,
        permission="graph.read",
        kind="read",
        snapshot="none",
        run=lambda ctx, arguments: ran.append(arguments) or "ok",
        surfaces=frozenset({"drawer"}),
    )


_ENFORCE = SimpleNamespace(hst_ai_tool_validation="enforce")


@pytest.mark.parametrize("validation", ["warn", "enforce"])
def test_a_null_argument_counts_as_omitted(validation):
    ran: list[dict[str, Any]] = []
    ctx = _ctx(settings=SimpleNamespace(hst_ai_tool_validation=validation))
    arguments = {"name": "leaf1", "snapshot": None, "limit": None}

    outcome = _registry(_recording_spec(ran)).invoke(ctx, "probe", arguments)

    assert not outcome.is_error
    assert ran == [{"name": "leaf1"}]
    assert outcome.arguments == arguments


def test_a_run_id_or_a_port_sent_as_a_number_reaches_the_body_as_digits():
    ran: list[dict[str, Any]] = []
    arguments = {"name": "leaf1", "snapshot": 3000, "port": 443, "limit": 5}

    outcome = _registry(_recording_spec(ran)).invoke(_ctx(settings=_ENFORCE), "probe", arguments)

    assert not outcome.is_error
    assert ran == [{"name": "leaf1", "snapshot": "3000", "port": "443", "limit": 5}]


@pytest.mark.parametrize("snapshot", [-1, True, 1.5])
def test_enforce_mode_refuses_a_run_id_that_is_not_a_whole_number(snapshot):
    ran: list[dict[str, Any]] = []
    arguments = {"name": "leaf1", "snapshot": snapshot}

    outcome = _registry(_recording_spec(ran)).invoke(_ctx(settings=_ENFORCE), "probe", arguments)

    assert outcome.is_error
    assert outcome.model_text.startswith("ValueError: invalid arguments for probe: snapshot:")
    assert ran == []


def test_a_port_the_input_model_types_as_an_integer_stays_an_integer():
    ran: list[dict[str, Any]] = []

    outcome = _registry(_recording_spec(ran, _FlowInput)).invoke(
        _ctx(settings=_ENFORCE), "probe", {"port": 443}
    )

    assert not outcome.is_error
    assert ran == [{"port": 443}]


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({}, "TypeError: invalid arguments for probe: name: Field required"),
        (
            {"name": "leaf1", "other": 1},
            "TypeError: invalid arguments for probe: other: Extra inputs are not permitted",
        ),
        ({"name": 1}, "ValueError: invalid arguments for probe: name: Input should be a valid string"),
    ],
)
def test_enforce_mode_refuses_a_call_python_would_refuse_as_a_type_error(arguments, expected):
    ran: list[dict[str, Any]] = []

    outcome = _registry(_recording_spec(ran)).invoke(_ctx(settings=_ENFORCE), "probe", arguments)

    assert outcome.is_error
    assert outcome.model_text == expected
    assert ran == []


def test_an_argument_refused_in_enforce_mode_is_an_invalid_argument_error():
    ran: list[dict[str, Any]] = []

    missing = _registry(_recording_spec(ran)).invoke(_ctx(settings=_ENFORCE), "probe", {})
    wrong = _registry(_recording_spec(ran)).invoke(_ctx(settings=_ENFORCE), "probe", {"name": 1})

    assert missing.error == {
        "error": {
            "code": "invalid_argument",
            "message": "TypeError: invalid arguments for probe: name: Field required",
            "retryable": False,
            "field": "name",
        }
    }
    assert wrong.error is not None
    assert (wrong.error["error"]["code"], wrong.error["error"]["field"]) == ("invalid_argument", "name")
    assert ran == []


def test_a_list_over_its_cap_is_an_invalid_argument_error_that_names_the_list():
    spec = ToolSpec(
        name="probe",
        version=1,
        description="a test tool",
        input_model=_ListInput,
        permission="graph.read",
        kind="read",
        snapshot="none",
        run=lambda ctx, arguments: "ok",
        surfaces=frozenset({"drawer"}),
        limits=ToolLimits(max_items={"items": 2}),
    )

    refused = _registry(spec).invoke(_ctx(), "probe", {"items": ["a", "b", "c"]})

    assert refused.error is not None
    assert (refused.error["error"]["code"], refused.error["error"]["field"]) == ("invalid_argument", "items")


def test_a_provenance_function_that_raises_is_an_error_outcome():
    def broken(ctx, arguments, result):
        raise KeyError("run")

    spec = ToolSpec(
        name="probe",
        version=1,
        description="a test tool",
        input_model=_ProbeInput,
        permission="graph.read",
        kind="read",
        snapshot="none",
        run=lambda ctx, arguments: "ok",
        surfaces=frozenset({"drawer"}),
        provenance=broken,
    )

    outcome = _registry(spec).invoke(_ctx(), "probe", {"name": "a"})

    assert outcome.is_error
    assert outcome.model_text == "KeyError: 'run'"
    assert outcome.error is not None and outcome.error["error"]["code"] == "internal"


def test_a_cut_paged_envelope_marks_its_page_truncated_and_says_where_the_cursor_continues():
    rows = [{"uid": f"dev:{i:06d}", "pad": "x" * 1000} for i in range(200)]
    envelope = {**_envelope(rows), "page": {"next_cursor": None, "truncated": False, "limit": 200}}

    model_copy = tools_mod.cap_model_copy(json.dumps(envelope), limit=100_000)

    assert len(model_copy) <= 100_000
    body = json.loads(model_copy)
    kept = body["result"]["buckets"]["hosts"]["items"]
    assert 0 < len(kept) < len(rows)
    assert body["page"] == {"next_cursor": None, "truncated": True, "limit": 200}
    assert body["warnings"] == [
        f"result.buckets.hosts.items lists {len(kept)} of 200 items in this copy, cut to fit 100000 "
        "characters; narrow the request or lower limit to read the rest",
        "page.truncated is true because this copy leaves items of the page out; page.next_cursor "
        "continues after the whole page and does not return them",
    ]
