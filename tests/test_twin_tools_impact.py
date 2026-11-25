"""The impact and change tools: service evaluation, device and link
assessment, synchronous change simulation and durable simulation reads."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from tests.twin_tools_fakes import FakeGraph, call, context, install

from hst.app import fw_overlay_read
from hst.app.routes import impact as impact_route
from hst.assessment import direct
from hst.results.project import condition_result
from hst.results.trace import flow_side_result
from hst.simul.fw_overlay import ProposalError
from hst.twin_tools import catalogue_registry, change

_DEVICE = ("MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})", [{"uid": "dev:r1"}])


def _bucket(*items):
    return {"count": len(items), "items": list(items), "truncated": False}


# --- impact_evaluate_service ---------------------------------------------------------------


def _engine_evaluation(**parts):
    """An evaluation body as the engine returns it, before projection."""
    body = {
        "mode": "possible",
        "proven": {"loss": _bucket(), "gain": _bucket()},
        "possible": {"loss": _bucket(), "gain": _bucket()},
        "not_established": {"before": _bucket(), "after": _bucket()},
        "condition_holds": {"before": _bucket(), "after": _bucket()},
        "condition_fails": {"before": _bucket(), "after": _bucket()},
        "evidence": {"count": 3, "items": [{"step": 1}, {"step": 2}, {"step": 3}], "truncated": False},
        "missing_evidence": [],
        "gaps": [],
        "model_errors": [],
    }
    body.update(parts)
    return body


def _evaluation(**parts):
    """An evaluation body as `evaluate_request` returns it, in the result vocabulary."""
    body = {
        "mode": "possible",
        "decided_change": {"loss": _bucket(), "gain": _bucket()},
        "open_change": {"loss": _bucket(), "gain": _bucket()},
        "open": {"before": _bucket(), "after": _bucket()},
        "passes": {"before": _bucket(), "after": _bucket()},
        "fails": {"before": _bucket(), "after": _bucket()},
        "evidence": {"count": 3, "items": [{"step": 1}, {"step": 2}, {"step": 3}], "truncated": False},
        "missing_evidence": [],
        "gaps": [],
        "model_errors": [],
    }
    body.update(parts)
    return body


def test_an_evaluation_writes_the_condition_answer_beside_the_engine_fields():
    from hst.results.project import project_evaluation

    body = _engine_evaluation(
        request={"success": "round-trip"},
        outcomes={"before": {"verdict": "holds"}, "after": {"verdict": "not-established"}},
        gaps=[
            {
                "code": "routing-context-missing",
                "kind": "not-collected",
                "subject": "dev:r1",
                "detail": "no context",
            }
        ],
        evidence={
            "count": 2,
            "items": [
                {"outcome": "does-not-hold", "missing": []},
                {"outcome": "not-established", "missing": ["the zones of eth2 were not collected"]},
            ],
        },
    )
    answer = project_evaluation(body, "guaranteed")
    assert answer is not None and answer.word == "not decided"
    assert (answer.quantifier, answer.condition) == ("every", "round-trip")
    assert answer.missing[0].subject == "dev:r1"
    assert body["outcomes"]["before"]["result"]["word"] == "passes"
    assert body["outcomes"]["after"]["result"] == answer.model_dump(mode="json")
    # the result replaces the engine's own fields
    assert "verdict" not in body["outcomes"]["after"]
    items = body["evidence"]["items"]
    assert items[0]["result"]["word"] == "fails" and "outcome" not in items[0]
    assert items[1]["result"]["missing"][0]["detail"] == "the zones of eth2 were not collected"
    assert project_evaluation(_engine_evaluation(), "possible") is None


def test_an_evaluation_maps_each_part_of_the_answer_and_pages_its_evidence(monkeypatch):
    install(monkeypatch, FakeGraph())
    gap = {
        "code": "routing-context-missing",
        "kind": "not-collected",
        "dimension": "routing-context",
        "subject": "dev:r1",
        "detail": "no context",
        "producer": {"stage": "route", "kind": "no-context"},
        "recipe_id": None,
        "unknown_dimensions": [],
    }
    body = _evaluation(
        decided_change={"loss": _bucket("10.0.0.0/25"), "gain": _bucket()},
        open_change={"loss": _bucket("10.0.0.0/25", "10.0.1.0/25"), "gain": _bucket()},
        open={"before": _bucket(), "after": _bucket("10.0.2.0/24")},
        gaps=[gap],
    )
    seen = {}

    def evaluate(settings, session, snap, **kwargs):
        seen.update(kwargs, cts=session.cts)
        return body

    monkeypatch.setattr(direct, "evaluate_request", evaluate)
    arguments = {
        "form": "requirement",
        "requirement": "sreq:app",
        "intents": [{"kind": "fw_rule.add", "params": {"rulebase": "fw:LAN"}}],
        "limit": 2,
    }

    failed, first = call("impact_evaluate_service", arguments)
    _, second = call("impact_evaluate_service", {**arguments, "cursor": first["page"]["next_cursor"]})

    assert not failed, first
    assert seen["requirement"] == "sreq:app" and seen["request"] is None and seen["mode"] == "possible"
    assert seen["intents"] == [{"kind": "fw_rule.add", "params": {"rulebase": "fw:LAN"}}]
    assert first["evidence"]["result"]["answer"] == "open"
    assert first["result"]["evidence"]["items"] == [{"step": 1}, {"step": 2}]
    assert second["result"]["evidence"]["items"] == [{"step": 3}]
    assert first["page"]["total"] == 3
    (mapped,) = first["evidence"]["gaps"]
    assert mapped["code"] == "routing-context-missing" and mapped["kind"] == "not-collected"
    assert "unknown_dimensions" not in mapped
    assert first["provenance"]["engine"] == "legacy-v1"


@pytest.mark.parametrize(
    ("parts", "status"),
    [
        ({"passes": {"before": _bucket("10.0.0.0/24"), "after": _bucket("10.0.0.0/24")}}, "passes"),
        (
            {"open": {"before": _bucket("10.0.0.0/24"), "after": _bucket("10.0.0.0/24")}},
            "not decided",
        ),
        ({"fails": {"before": _bucket(), "after": _bucket("10.0.0.0/24")}}, "fails"),
    ],
)
def test_each_part_of_the_answer_has_its_own_status(monkeypatch, parts, status):
    install(monkeypatch, FakeGraph())
    monkeypatch.setattr(direct, "evaluate_request", lambda *a, **k: _evaluation(**parts))

    failed, envelope = call(
        "impact_evaluate_service",
        {"form": "request", "request": {"name": "app", "destination": "10.9.0.1"}},
    )

    assert not failed
    assert envelope["evidence"]["result"]["word"] == status


def test_a_change_with_no_effect_answers_from_its_buckets():
    from hst.twin_tools.impact import whole_answer

    unchanged = _evaluation(
        passes={"before": _bucket("10.0.0.0/25"), "after": _bucket("10.0.0.0/25")},
        fails={"before": _bucket("10.0.0.128/25"), "after": _bucket("10.0.0.128/25")},
    )

    assert whole_answer(unchanged, "possible").word == "fails"


def test_an_engine_refusal_keeps_its_reason(monkeypatch):
    install(monkeypatch, FakeGraph())

    def refuse(*a, **k):
        raise HTTPException(404, "no requirement sreq:gone in this snapshot")

    monkeypatch.setattr(direct, "evaluate_request", refuse)

    failed, error = call("impact_evaluate_service", {"form": "requirement", "requirement": "sreq:gone"})

    assert failed
    assert error["error"] == {
        "code": "not_found",
        "message": "no requirement sreq:gone in this snapshot",
        "retryable": False,
        "field": "requirement",
    }


def test_the_application_connection_form_is_served_and_listed_in_the_schema():
    schema = catalogue_registry().get("impact_evaluate_service").input_schema()

    assert schema["properties"]["form"]["enum"] == ["requirement", "request", "application_connection"]
    assert "application_connection" in schema["properties"]


# --- impact_assess -------------------------------------------------------------------------

_ASSESS = {
    "device": {"uid": "dev:r1", "hostname": "r1"},
    "run": {"snapshot": "4000"},
    **{
        name: _bucket()
        for name in (
            "single_homed_prefixes",
            "single_homed_endpoints",
            "gateway_prefixes",
            "attached_endpoints",
            "redundancy_groups",
            "interfaces",
            "tunnels",
            "bgp_sessions",
            "fhrp_groups",
        )
    },
    "gateway_prefixes": _bucket({"cidr": "10.0.0.0/24"}),
}


def test_a_device_assessment_is_possible_and_moves_the_run_to_the_envelope(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    seen = []
    monkeypatch.setattr(
        impact_route, "assess", lambda session, uid: seen.append((session.cts, uid)) or _ASSESS
    )

    failed, envelope = call("impact_assess", {"subject": "device", "device": "dev:r1"})

    assert not failed
    assert seen == [(4000, "dev:r1")]
    result = envelope["result"]
    assert result["device_uid"] == "dev:r1"
    assert "run" not in result
    assert result["buckets"]["gateway_prefixes"]["count"] == 1
    assert len(result["buckets"]) == 9
    assert envelope["evidence"]["result"]["word"] == "recorded in the snapshot"
    assert any("is not evaluated" in u for u in envelope["evidence"]["unknowns"])


def test_a_link_that_is_not_in_the_run_is_not_found(monkeypatch):
    install(monkeypatch, FakeGraph())

    def missing(session, link):
        raise HTTPException(404, detail=f"no link or tunnel {link} in this snapshot")

    monkeypatch.setattr(impact_route, "assess_link", missing)

    failed, error = call("impact_assess", {"subject": "link", "link": "wan:gone"})

    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == "link"


def test_a_link_assessment_names_the_device_and_its_other_circuits(monkeypatch):
    install(monkeypatch, FakeGraph())
    body = {
        "device": "dev:r1",
        "link": "wan:1",
        "circuit": None,
        "other_circuits": ["wan:2"],
        "parallel_circuits": [],
        "parallel_path": "not established",
        "not_parallel": [
            {"uid": "wan:2", "reason": "leaves the device by the same interface as the lost circuit"}
        ],
        "run": None,
        "single_homed_prefixes": _bucket(),
        "single_homed_endpoints": _bucket(),
    }
    monkeypatch.setattr(impact_route, "assess_link", lambda session, link: body)

    failed, envelope = call("impact_assess", {"subject": "link", "link": "wan:1"})

    assert not failed
    assert envelope["result"]["device_uid"] == "dev:r1"
    assert envelope["result"]["other_circuits"] == ["wan:2"]
    assert envelope["result"]["parallel_path"] == "not established"
    # the reason per circuit reaches the caller, and the unknown points at it
    assert envelope["result"]["not_parallel"] == body["not_parallel"]
    unknown = next(u for u in envelope["evidence"]["unknowns"] if "no parallel path is established" in u)
    assert "not_parallel" in unknown and "lead away" not in unknown
    assert set(envelope["result"]["buckets"]) == {"single_homed_prefixes", "single_homed_endpoints"}


# --- change_simulate -----------------------------------------------------------------------


def _side(detail, *, blocked=False, indeterminate=False):
    """One side of a simulated flow as the change simulation writes it."""
    side = {"detail": detail, "blocked": blocked, "indeterminate": indeterminate}
    return {**side, "result": flow_side_result(side).model_dump(mode="json")}


def _flow(src, *, blocked=False, indeterminate=False):
    return {
        "flow": {"src": src, "dst": "0.0.0.0/0"},
        "before": _side("egress"),
        "after": _side("after", blocked=blocked, indeterminate=indeterminate),
        "result_changed": blocked,
        "blocked_changed": blocked,
        "paths": {},
    }


def _simulation(flows, **extra):
    return {"flow_count": len(flows), "flows": flows, "model_errors": [], **extra}


def _simulate(tmp_path, arguments):
    """One change_simulate call, with a side store for the readers to bind to."""
    return call("change_simulate", arguments, context(sidestore_dir=tmp_path))


def test_derived_flows_never_make_the_answer_proven_and_say_how_many_there_are_at_most(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    seen = {}

    def simulate(session, **kwargs):
        seen.update(kwargs)
        return _simulation(
            [_flow("10.0.0.5", blocked=True), _flow("10.0.0.6", blocked=True)],
            flows_derived_count=2,
            flows_derived_not_traced=3,
        )

    monkeypatch.setattr(fw_overlay_read, "simulate_change", simulate)

    failed, envelope = _simulate(
        tmp_path, {"intents": [{"kind": "fw_rule.add", "params": {"device": "fw1"}}]}
    )

    assert not failed, envelope
    assert seen["flows"] is None
    assert [f["evidence"]["result"]["answer"] for f in envelope["result"]["flows"]] == ["false", "false"]
    assert envelope["evidence"]["result"]["word"] == "each item states its own result"
    assert any("at most 8 derived flows" in u for u in envelope["evidence"]["unknowns"])
    assert any("3 more derived candidate flows" in u for u in envelope["evidence"]["unknowns"])


def test_supplied_flows_that_are_all_decided_are_proven(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    seen = {}

    def simulate(session, **kwargs):
        seen.update(kwargs)
        return _simulation([_flow("10.0.0.5"), _flow("10.0.0.6", blocked=True)])

    monkeypatch.setattr(fw_overlay_read, "simulate_change", simulate)

    failed, envelope = _simulate(
        tmp_path,
        {
            "intents": [{"kind": "fw_rule.add", "params": {"rulebase": "fw:LAN"}}],
            "flows": [{"src": "10.0.0.5", "dst": "10.0.1.1", "port": 443, "proto": "tcp"}],
            "depth": 2,
        },
    )

    assert not failed
    assert seen["flows"] == [{"src": "10.0.0.5", "dst": "10.0.1.1", "port": 443, "proto": "tcp"}]
    assert seen["depth"] == 2
    assert envelope["evidence"]["result"]["word"] == "each item states its own result"
    assert envelope["evidence"]["unknowns"] == []
    assert [f["evidence"]["result"]["answer"] for f in envelope["result"]["flows"]] == ["true", "false"]


def test_an_indeterminate_or_uncrossed_flow_is_not_established(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    uncrossed = {**_flow("10.0.0.7"), "model_error": {"kind": "flow-does-not-cross-the-changed-device"}}
    monkeypatch.setattr(
        fw_overlay_read,
        "simulate_change",
        lambda session, **k: _simulation([_flow("10.0.0.5", indeterminate=True), uncrossed]),
    )

    failed, envelope = _simulate(
        tmp_path, {"intents": [{"kind": "fw_rule.add"}], "flows": [{"src": "10.0.0.5", "dst": "10.0.1.1"}]}
    )

    assert not failed
    evidence = [f["evidence"] for f in envelope["result"]["flows"]]
    assert [e["result"]["answer"] for e in evidence] == ["open", "open"]
    assert [m["code"] for m in evidence[1]["result"]["missing"]] == ["flow-does-not-cross-the-changed-device"]
    assert envelope["evidence"]["result"]["answer"] == "open"


def test_a_change_set_that_cannot_be_applied_is_invalid_argument(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())

    def refuse(session, **kwargs):
        raise ProposalError("intent 0 (fw_rule.add) names no rulebase")

    monkeypatch.setattr(fw_overlay_read, "simulate_change", refuse)

    failed, error = _simulate(tmp_path, {"intents": [{"kind": "fw_rule.add"}]})

    assert failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "intents"


def test_the_depth_bound_is_the_engine_withdrawal_cap():
    assert change.MAX_DEPTH == fw_overlay_read._MAX_WITHDRAWAL_DEPTH
    assert catalogue_registry().get("change_simulate").permission == "graph.read"


# --- change_get_simulation -----------------------------------------------------------------


class _Store:
    """An app store holding one analysis session with one simulation run."""

    def __init__(self, run):
        self.run = run

    async def get_analysis_session(self, session_id, revision=None):
        if session_id != "s1":
            return None
        return SimpleNamespace(definition=_definition())

    async def get_analysis_run(self, run_id):
        return self.run if run_id == self.run.id else None


def _definition():
    return {
        "id": "s1",
        "revision": 2,
        "title": "block telnet",
        "input": {
            "kind": "simulation",
            "snapshot": {"snapshot": "4000", "manifest_sha256": "0" * 64, "estate": "e"},
            "changes": [{"kind": "fw_rule.add", "params": {}}],
        },
        "runs": [
            {
                "id": "r1",
                "item_id": "simulation",
                "execution": "completed",
                "result": condition_result("not-established").model_dump(mode="json"),
                "coverage": "complete",
            }
        ],
    }


def _run(snapshot="4000", state="completed"):
    simulation = _simulation(
        [_flow("10.0.0.5", blocked=True), _flow("10.0.0.6"), _flow("10.0.0.7")],
        flows_derived_count=3,
        routing_prediction={"gaps_after": [{"kind": "not-observed", "context_uid": "vrf:a", "detail": "x"}]},
    )
    return SimpleNamespace(
        id="r1",
        state=state,
        result={"snapshot": {"snapshot": snapshot}, "simulation": simulation, "protected": []},
        snapshot_refs=[{"snapshot": snapshot}],
        error=None,
    )


def _store_context(run):
    ctx = context()
    ctx.store = _Store(run)
    return ctx


def test_a_durable_run_pages_its_flows_with_the_derived_flow_rule(monkeypatch):
    install(monkeypatch, FakeGraph())
    ctx = _store_context(_run())

    failed, first = call(
        "change_get_simulation", {"session_id": "s1", "run_id": "r1", "section": "flows", "limit": 2}, ctx
    )
    _, second = call(
        "change_get_simulation",
        {
            "session_id": "s1",
            "run_id": "r1",
            "section": "flows",
            "limit": 2,
            "cursor": first["page"]["next_cursor"],
        },
        ctx,
    )

    assert not failed, first
    assert first["result"]["execution"] == "completed"
    assert first["result"]["snapshot_matches"] is True
    assert [f["flow"]["src"] for f in first["result"]["items"]] == ["10.0.0.5", "10.0.0.6"]
    assert [f["flow"]["src"] for f in second["result"]["items"]] == ["10.0.0.7"]
    assert first["evidence"]["result"]["word"] == "each item states its own result"
    assert any("at most 8 derived flows" in u for u in first["evidence"]["unknowns"])
    (gap,) = first["evidence"]["gaps"]
    assert (gap["code"], gap["kind"], gap["context_uid"]) == ("not-observed", "not-collected", "vrf:a")


def test_a_durable_run_of_another_snapshot_says_so(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, envelope = call(
        "change_get_simulation", {"session_id": "s1", "run_id": "r1"}, _store_context(_run("3000"))
    )

    assert not failed
    assert envelope["result"]["snapshot_matches"] is False
    assert envelope["result"]["summary"]["flow_count"] == 3
    assert any("computed from run 3000" in u for u in envelope["evidence"]["unknowns"])


@pytest.mark.parametrize(
    ("session_id", "run_id", "field"), [("s9", "r1", "session_id"), ("s1", "r9", "run_id")]
)
def test_an_unknown_session_or_run_is_not_found(monkeypatch, session_id, run_id, field):
    install(monkeypatch, FakeGraph())

    failed, error = call(
        "change_get_simulation", {"session_id": session_id, "run_id": run_id}, _store_context(_run())
    )

    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == field
