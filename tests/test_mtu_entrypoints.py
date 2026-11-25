"""MTU entrypoint parity, pagination binding and bounded evidence reads."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from hst import cli, path
from hst.app.agent.tools import dispatch, offered_tools
from hst.app.ai.registry import Principal, ToolContext
from hst.core.mtu import MtuRequest
from hst.core.mtu_audit_read import audit_mtu
from hst.core.mtu_read import MtuEvidenceSet


def test_audit_keyset_cursor_and_snapshot_binding(monkeypatch):
    calls = []
    rows = [{"subject_uid": "a", "peer_uid": "b"}, {"subject_uid": "b", "peer_uid": "c"}]

    def read(session, query, **params):
        calls.append((query, params))
        return rows if not params["after_a"] else rows[1:]

    monkeypatch.setattr(path, "_read", read)
    monkeypatch.setattr("hst.core.mtu_audit_read.read_mtu", lambda *a, **k: MtuEvidenceSet())
    page = audit_mtu(SimpleNamespace(cts=10), limit=1)
    assert page.truncated and page.next_cursor and not page.coverage_complete
    assert calls[0][1]["row_limit"] == 2
    assert "all(n IN nodes(p)" in calls[0][0] and "all(r IN relationships(p)" in calls[0][0]
    next_page = audit_mtu(SimpleNamespace(cts=10), limit=1, cursor=page.next_cursor)
    assert next_page.items[0].subject_uid == "b"
    assert not next_page.truncated and next_page.next_cursor is None
    assert calls[-1][1]["after_a"] == "a"
    for kw in ({"af": 6}, {"subject_uid": "x"}, {"scope": "fabric", "subject_uid": "x"}):
        with pytest.raises(ValueError, match="cursor"):
            audit_mtu(SimpleNamespace(cts=10), cursor=page.next_cursor, **kw)
    with pytest.raises(ValueError, match="cursor"):
        audit_mtu(SimpleNamespace(cts=11), cursor=page.next_cursor)


@pytest.mark.parametrize(
    "kwargs", [{"limit": 0}, {"limit": 201}, {"scope": "fabric"}, {"af": 5}, {"cursor": "malformed"}]
)
def test_audit_bad_request_does_not_read(monkeypatch, kwargs):
    monkeypatch.setattr(path, "_read", lambda *a, **k: pytest.fail("unexpected graph read"))
    with pytest.raises(ValueError):
        audit_mtu(SimpleNamespace(cts=10), **kwargs)


def test_unpinned_audit_cannot_fall_back_to_current():
    with pytest.raises(ValueError, match="pinned"):
        audit_mtu(SimpleNamespace())


def test_absent_evidence_reports_gap_not_default_mtu(monkeypatch):
    monkeypatch.setattr(path, "_read", lambda *a, **k: [{"subject_uid": "a", "peer_uid": "b"}])
    monkeypatch.setattr("hst.core.mtu_audit_read.read_mtu", lambda *a, **k: MtuEvidenceSet())
    page = audit_mtu(SimpleNamespace(cts=10))
    assert {f.code for f in page.items[0].findings} == {"MTU_NOT_CAPTURED"}
    assert all(not r.constraints for r in page.items[0].resolutions)


def _mtu_tools(role: str = "viewer") -> dict:
    ctx = ToolContext(settings=SimpleNamespace(), principal=Principal.for_role(role), surface="drawer")
    return {t.name: t for t in offered_tools(ctx)}


def test_ask_ai_schema_permissions_and_validation(monkeypatch):
    monkeypatch.setattr("hst.core.db.session", lambda *a, **k: pytest.fail("unexpected DB session"))
    tools = _mtu_tools()
    trace = tools["reach_trace"]
    assert trace.permission == tools["reach_audit_mtu"].permission == "graph.read"
    assert trace.schema["properties"]["mtu"]["anyOf"][0]["$ref"].endswith("/MtuRequest")
    assert set(MtuRequest.model_fields) <= set(trace.schema["$defs"]["MtuRequest"]["properties"])
    flow = {"src": "192.0.2.1", "dst": "192.0.2.2"}
    missing_size = dispatch([trace], "reach_trace", {"mode": "path", "flow": flow, "mtu": {"mode": "packet"}})
    assert missing_size.is_error
    reply = dispatch(
        [trace],
        "reach_trace",
        {
            "mode": "path",
            "flow": flow,
            "mtu": {"mode": "packet", "ip_packet_bytes": 1500, "reply_ip_packet_bytes": 1000},
        },
    )
    assert reply.is_error and "reply" in reply.ui_result


def test_cli_size_validation_precedes_session(monkeypatch):
    monkeypatch.setattr(cli.dbmod, "session", lambda *a, **k: pytest.fail("unexpected DB session"))
    result = CliRunner().invoke(cli.app, ["path", "192.0.2.1", "192.0.2.2", "--mtu-mode", "packet"])
    assert result.exit_code != 0 and "complete IP packet" in result.output


def test_cli_preserves_off_and_transmits_typed_request(monkeypatch):
    from hst.core import ribsource, snapshot

    calls = []
    monkeypatch.setattr(cli.dbmod, "session", lambda *a: nullcontext(object()))
    monkeypatch.setattr(snapshot, "resolve", lambda *a: SimpleNamespace(cts=10))
    monkeypatch.setattr(ribsource, "for_snapshot", lambda *a: None)
    monkeypatch.setattr(path, "pinned", lambda s, snap: s)
    monkeypatch.setattr(
        path, "trace", lambda *a, **k: calls.append(k) or {"verdict": "allow", "hops": [], "legs": []}
    )
    monkeypatch.setattr(cli, "_render_trace_block", lambda *a: None)
    runner = CliRunner()
    base = ["path", "192.0.2.1", "192.0.2.2"]
    assert runner.invoke(cli.app, base).exit_code == 0
    assert "mtu" not in calls[-1]
    result = runner.invoke(
        cli.app, [*base, "--mtu-mode", "packet", "--mtu-ip-packet-bytes", "1500", "--mtu-no-ipv4-df"]
    )
    assert result.exit_code == 0, result.output
    assert calls[-1]["mtu"] == MtuRequest(mode="packet", ip_packet_bytes=1500, ipv4_df=False)


def test_mcp_typed_schema_registers_without_device_contact(monkeypatch):
    from mcp import server

    from hst import mcp_server
    from hst.core import db as dbmod

    captured = {}

    class Registry:
        def __init__(self, *a, **kw):
            pass

        def tool(self):
            def register(fn):
                captured[fn.__name__] = fn
                return fn

            return register

    monkeypatch.setattr(server, "MCPServer", Registry)
    monkeypatch.setattr(dbmod, "session", lambda *a, **k: pytest.fail("unexpected DB session"))
    mcp_server.build_server()
    assert {"reach_trace", "reach_audit_mtu"} <= captured.keys()
    refused = captured["reach_trace"](
        mode="path", flow={"src": "192.0.2.1", "dst": "192.0.2.2"}, mtu={"mode": "packet"}
    )
    assert refused.is_error is True
    assert refused.structured_content["error"]["code"] == "invalid_argument"


@pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
def test_all_graph_reader_roles_receive_mtu_tools(role):
    assert {"reach_trace", "reach_audit_mtu"} <= set(_mtu_tools(role))


def test_domain_page_compares_only_known_members_without_policy_inheritance(monkeypatch):
    from hst.core.mtu_profiles import observation_from_raw

    observations = {}
    for uid, value in (("a", 1500), ("b", 9000)):
        observations[uid] = [
            observation_from_raw(
                subject_uid=uid,
                source="synthetic",
                source_target=uid,
                source_field="mtu",
                raw_value=value,
                profile_id="ip_packet",
                af=4,
                direction="tx",
                metric="ipv4_mtu_bytes",
                bound_kind="ceiling",
                enforcement="l3",
                enforcement_key="ip",
                assertion_kind="operational",
            )
        ]
    monkeypatch.setattr(
        path,
        "_read",
        lambda *a, **k: [{"subject_uid": "a", "peer_uid": "bd"}, {"subject_uid": "b", "peer_uid": "bd"}],
    )
    monkeypatch.setattr(
        "hst.core.mtu_audit_read.read_mtu", lambda *a, **k: MtuEvidenceSet(by_subject=observations)
    )
    page = audit_mtu(SimpleNamespace(cts=10), scope="bridge-domain", subject_uid="bd")
    assert "MTU_POLICY_UNRESOLVED" in page.gaps
    assert page.findings[0].code == "MTU_NORMALIZED_DIFFERENCE"
    assert page.findings[0].severity == "info" and page.findings[0].scope == "page_members"
    assert not page.coverage_complete


async def test_real_mcp_registration_exposes_typed_request_contract():
    from hst.mcp_server import build_server

    tools = {tool.name: tool for tool in await build_server().list_tools()}
    assert {"reach_trace", "reach_audit_mtu"} <= tools.keys()
    schema = tools["reach_trace"].input_schema
    assert schema["$defs"]["MtuRequest"] == MtuRequest.model_json_schema()
    assert "mtu" in schema["properties"]
