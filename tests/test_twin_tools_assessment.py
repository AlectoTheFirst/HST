"""The assessment, evidence, operations and policy tools: stored assessment
reads and result buckets, evidence gaps per subject, collection runs, and one
firewall rule explained by the symbolic-v2 engine."""

from __future__ import annotations

import asyncio
import json
import os
from collections import defaultdict
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from types import MappingProxyType, SimpleNamespace

import pytest
from fastapi import HTTPException
from tests.app.fakes import FakeStore
from tests.support import checkpoint_batch
from tests.test_business_applications import one_connection_definition
from tests.twin_tools_fakes import FakeGraph, call, context, install

from hst import symbolic
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.overlay import _rebuild
from hst.app.ai.registry import Principal
from hst.applications.service import save_definition
from hst.assessment import direct, rule_explain
from hst.assessment import service as assessment_service
from hst.assessment.result_page import BUCKETS
from hst.assessment.store import AnalysisRun, AnalysisSessionRevision, MemoryAssessmentStore
from hst.collectors.checkpoint import scope_of
from hst.core import uid as uidmod
from hst.results.project import condition_result
from hst.twin_tools import assessment as assessment_tool
from hst.twin_tools import catalogue_registry

REFERENCE = {"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test", "observation_floor_ms": None}
_DEVICE = ("MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})", [{"uid": "dev:r1"}])


# The answers a stored run records, in the result vocabulary.
_PASSES = condition_result("holds").model_dump(mode="json")
_FAILS = condition_result("does-not-hold").model_dump(mode="json")
_OPEN = condition_result("not-established").model_dump(mode="json")


def _context(store=None, **overrides):
    ctx = context(**overrides)
    ctx.store = store
    return ctx


def _published(monkeypatch):
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: dict(REFERENCE))


def _run(
    run_id="run-1", *, assessment_id="a-1", snapshot="4000", result=None, state="completed", kind="evaluate"
):
    return AnalysisRun(
        id=run_id,
        assessment_id=assessment_id,
        assessment_revision=1,
        kind=kind,
        inputs={},
        input_digest="d" * 64,
        snapshot_refs=[{"snapshot": snapshot, "manifest_sha256": "a" * 64, "estate": "test"}],
        engine_version="build",
        created_by=1,
        created_at="2026-09-28T00:00:00+00:00",
        state=state,
        result=result,
    )


class RunStore:
    """An app store holding recorded assessment runs."""

    def __init__(self, *runs):
        self.runs = {run.id: run for run in runs}

    async def get_analysis_run(self, run_id):
        return self.runs.get(run_id)


# --- assessment_read -----------------------------------------------------------------------


def _assessments() -> MemoryAssessmentStore:
    store = MemoryAssessmentStore()

    async def fill():
        assessment = await store.create_assessment(
            title="Checkout", purpose="evaluation", definition={}, created_by=1
        )
        await store.enqueue_analysis(
            assessment_id=assessment.id,
            assessment_revision=1,
            kind="evaluate",
            inputs={},
            snapshot_refs=[{"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test"}],
            engine_version="build",
            created_by=1,
        )

    asyncio.run(fill())
    return store


def test_list_mode_flags_whether_each_run_was_computed_from_the_selected_snapshot(monkeypatch):
    install(monkeypatch, FakeGraph())
    store = _assessments()

    failed, latest = call("assessment_read", {"mode": "list"}, _context(store))
    _, older = call("assessment_read", {"mode": "list", "snapshot": "3000"}, _context(store))

    assert not failed, latest
    (item,) = latest["result"]["items"]
    assert item["title"] == "Checkout"
    (run,) = item["runs"]
    assert run["snapshot_matches"] is True
    assert "snapshot_refs" not in run
    assert older["result"]["items"][0]["runs"][0]["snapshot_matches"] is False
    assert latest["evidence"]["result"]["word"] == "stored record"
    assert latest["page"]["truncated"] is False


async def _mcp_call(monkeypatch, name, arguments):
    pytest.importorskip("mcp")
    from tests.twin_tools_fakes import settings

    from hst.app.ai import mcp as ai_mcp
    from hst.mcp_server import build_server

    monkeypatch.setattr(ai_mcp, "Settings", lambda: settings())
    return await build_server().call_tool(name, arguments)


async def test_list_mode_caps_limit_at_100(monkeypatch):
    install(monkeypatch, FakeGraph())

    res = await _mcp_call(monkeypatch, "assessment_read", {"mode": "list", "limit": 150})

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "invalid_argument"
    assert res.structured_content["error"]["field"] == "limit"


def test_run_mode_reads_one_recorded_run_without_its_lease(monkeypatch):
    install(monkeypatch, FakeGraph())
    store = _assessments()
    run_id = asyncio.run(store.list_assessments(10))[0].id
    (listed,) = asyncio.run(store.list_analysis_runs(run_id, limit=5))
    asyncio.run(store.claim_analysis("worker-private"))

    failed, envelope = call("assessment_read", {"mode": "run", "run_id": listed.id}, _context(store))
    missing_failed, missing = call("assessment_read", {"mode": "run", "run_id": "none"}, _context(store))

    assert not failed, envelope
    run = envelope["result"]["run"]
    assert run["id"] == listed.id
    assert not {"lease_token", "claimed_by", "checkpoint"} & run.keys()
    assert envelope["result"]["snapshot_matches"] is True
    assert envelope["evidence"]["result"]["answer"] == "open"
    assert any("records no complete result" in u for u in envelope["evidence"]["unknowns"])
    assert missing_failed and missing["error"]["code"] == "not_found"


@pytest.mark.parametrize(
    ("result", "word"),
    [
        ({"result": _PASSES}, "passes"),
        ({"outcomes": {"after": {"result": _FAILS}}}, "fails"),
        ({"result": _OPEN}, "not decided"),
        ({}, "stored record"),
    ],
)
def test_a_completed_run_takes_its_status_from_its_verdict(result, word):
    assert assessment_tool.run_result("completed", result).word == word
    assert assessment_tool.run_result("running", result).answer == "open"


def test_findings_on_a_run_without_a_symbolic_artifact_is_conflict(monkeypatch):
    install(monkeypatch, FakeGraph())

    def isolated(*args, **kwargs):
        raise AssertionError("no child is started for a run without an artifact")

    monkeypatch.setattr(direct, "run_isolated", isolated)
    store = RunStore(_run(result={"result": _PASSES}))

    failed, error = call(
        "assessment_read",
        {"mode": "findings", "assessment_id": "a-1", "run_id": "run-1", "bucket": "decided_change.loss"},
        _context(store),
    )

    assert failed and error["error"]["code"] == "conflict"
    assert error["error"]["field"] == "run_id"


def test_findings_pages_a_bucket_through_the_analysis_child(monkeypatch):
    install(monkeypatch, FakeGraph())
    reference = {"estate": "test", "manifest_sha256": "a" * 64, "artifact_sha256": "b" * 64}
    store = RunStore(_run(result={"symbolic": {"artifact_ref": reference}}))
    sent = []

    def isolated(settings, inputs):
        sent.append(inputs)
        offset, limit = inputs["offset"], inputs["limit"]
        prefixes = [f"10.0.{i}.0/24" for i in range(5)]
        end = offset + limit
        return {
            "bucket": inputs["bucket"],
            "artifact_sha256": "b" * 64,
            "count": 5,
            "count_decimal": "5",
            "items": prefixes[offset:end],
            "next_offset": end if end < 5 else None,
        }

    monkeypatch.setattr(direct, "run_isolated", isolated)
    arguments = {
        "mode": "findings",
        "assessment_id": "a-1",
        "run_id": "run-1",
        "bucket": "decided_change.loss",
        "limit": 2,
    }

    failed, first = call("assessment_read", arguments, _context(store))
    _, second = call(
        "assessment_read", {**arguments, "cursor": first["page"]["next_cursor"]}, _context(store)
    )

    assert not failed, first
    assert sent[0]["analysis"] == {"kind": "symbolic-page"}
    assert sent[0]["artifact_ref"] == reference
    assert (sent[0]["offset"], sent[1]["offset"]) == (0, 2)
    assert [i["item"] for i in first["result"]["items"]] == ["10.0.0.0/24", "10.0.1.0/24"]
    assert [i["item"] for i in second["result"]["items"]] == ["10.0.2.0/24", "10.0.3.0/24"]
    assert first["result"]["items"][0]["evidence"]["result"]["answer"] == "false"
    assert first["page"]["total"] == 5 and first["page"]["truncated"] is True
    assert first["provenance"]["engine"] == "symbolic-v2"


def test_findings_on_a_busy_analysis_slot_is_engine_unavailable(monkeypatch):
    install(monkeypatch, FakeGraph())
    reference = {"estate": "test", "manifest_sha256": "a" * 64, "artifact_sha256": "b" * 64}

    def busy(settings, inputs):
        raise HTTPException(503, "Analysis capacity is busy; retry or submit a queued assessment.")

    monkeypatch.setattr(direct, "run_isolated", busy)

    failed, error = call(
        "assessment_read",
        {"mode": "findings", "assessment_id": "a-1", "run_id": "run-1", "bucket": "evidence"},
        _context(RunStore(_run(result={"symbolic": {"artifact_ref": reference}}))),
    )

    assert failed and error["error"]["code"] == "engine_unavailable" and error["error"]["retryable"] is True


def test_the_bucket_names_are_the_result_page_buckets():
    schema = catalogue_registry().get("assessment_read").input_schema()
    findings = schema["$defs"]["AssessmentFindingsInput"]

    assert set(findings["properties"]["bucket"]["enum"]) == BUCKETS
    assert assessment_tool.bucket_evidence("fails.after").result.answer == "false"
    assert assessment_tool.bucket_evidence("triage.open_then_fails").result.answer == "open"
    # an address open on one side of the change is an open answer, with the reason named
    open_gain = assessment_tool.bucket_evidence("open_change.gain")
    assert open_gain.result.answer == "open" and open_gain.result.word == "not decided"
    assert open_gain.result.missing[0].code == "side-not-decided"
    assert assessment_tool.bucket_evidence("decided_change.loss").result.word == "fails"
    assert assessment_tool.bucket_evidence("decided_change.gain").result.word == "passes"
    assert assessment_tool.bucket_evidence("evidence") is None


# --- assessment_read, mode: finding and mode: analysis_session ------------------------------

_RESULT = {
    "findings": [
        {"id": "f-1", "candidates": ["rule-a"], "result": _PASSES},
        {"candidates": ["rule-b"], "result": _FAILS},
    ],
    "gaps": [{"code": "rib-missing", "kind": "not-collected", "detail": "no routing table on fw1"}],
}


def _finding(finding_id, store, **arguments):
    return call(
        "assessment_read",
        {"mode": "finding", "run_id": "run-1", "finding_id": finding_id, **arguments},
        _context(store),
    )


def test_finding_mode_reads_one_entry_by_its_own_id_or_its_position(monkeypatch):
    install(monkeypatch, FakeGraph())
    store = RunStore(_run(result=_RESULT))

    failed, by_id = _finding("finding:f-1", store, assessment_id="a-1")
    _, by_position = _finding("finding:@1", store)
    _, gap = _finding("gap:@0", store)

    assert not failed, by_id
    finding = by_id["result"]["finding"]
    assert (finding["reference"], finding["kind"], finding["index"]) == ("finding:f-1", "finding", 0)
    assert finding["record"] == _RESULT["findings"][0]
    assert finding["record_truncated"] is False
    assert by_id["result"]["run"]["assessment_id"] == "a-1"
    assert by_id["result"]["snapshot_matches"] is True
    assert by_id["evidence"]["result"]["word"] == "passes"
    assert by_id["provenance"]["engine_function"] == "hst.assessment.findings.locate"
    assert by_position["result"]["finding"]["reference"] == "finding:@1"
    assert by_position["result"]["finding"]["record"]["candidates"] == ["rule-b"]
    assert gap["result"]["finding"]["kind"] == "gap"
    assert gap["evidence"]["result"]["missing"][0]["code"] == "rib-missing"
    assert gap["evidence"]["gaps"]


def test_a_finding_id_is_verified_against_the_run(monkeypatch):
    install(monkeypatch, FakeGraph())
    store = RunStore(_run(result=_RESULT), _run("run-2", result=None, state="running"))

    unknown_failed, unknown = _finding("finding:f-9", store)
    beyond_failed, beyond = _finding("finding:@2", store)
    other_failed, other = _finding("finding:f-1", store, assessment_id="a-2")
    missing_failed, missing = call(
        "assessment_read", {"mode": "finding", "run_id": "none", "finding_id": "finding:f-1"}, _context(store)
    )
    pending_failed, pending = call(
        "assessment_read", {"mode": "finding", "run_id": "run-2", "finding_id": "finding:@0"}, _context(store)
    )

    assert unknown_failed and unknown["error"]["code"] == "not_found"
    assert unknown["error"]["field"] == "finding_id"
    assert beyond_failed and beyond["error"]["code"] == "not_found"
    # a run of another assessment
    assert other_failed and other["error"]["code"] == "not_found" and other["error"]["field"] == "run_id"
    assert missing_failed and missing["error"]["field"] == "run_id"
    assert pending_failed and pending["error"]["code"] == "conflict"


def test_finding_mode_returns_one_finding_within_the_model_bound(monkeypatch):
    from hst.app.ai.registry import AGENT_MODEL_CHARS

    install(monkeypatch, FakeGraph())
    huge = {
        "id": "f-big",
        "result": _PASSES,
        "trials": [{"candidates": [f"rule-{n}"], "detail": "x" * 200} for n in range(5000)],
        "note": "y" * 300_000,
    }
    ctx = _context(RunStore(_run(result={"findings": [huge]})), principal=Principal.for_role("viewer"))
    ctx.surface = "drawer"

    outcome = catalogue_registry().invoke(
        ctx, "assessment_read", {"mode": "finding", "run_id": "run-1", "finding_id": "finding:f-big"}
    )

    assert not outcome.is_error, outcome.ui_text
    assert len(outcome.ui_text) <= AGENT_MODEL_CHARS
    # the tool bounds the record itself, so the model copy is the whole answer
    assert "output_truncated" not in outcome.model_text
    finding = json.loads(outcome.ui_text)["result"]["finding"]
    assert finding["record_truncated"] is True
    assert finding["record_chars"] > assessment_tool.MAX_RECORD_CHARS
    assert finding["record"]["id"] == "f-big"
    assert finding["record"]["trials"][0]["candidates"] == ["rule-0"]


def test_a_gap_in_finding_mode_stays_within_the_model_bound_with_its_evidence_gap(monkeypatch):
    from hst.app.ai.registry import AGENT_MODEL_CHARS

    install(monkeypatch, FakeGraph())
    gap = {
        "code": "rib-missing",
        "kind": "not-collected",
        "subject": "s" * 200_000,
        "dimension": "d" * 50_000,
        "producer": {f"field-{n}": "p" * 2000 for n in range(100)},
    }
    ctx = _context(RunStore(_run(result={"gaps": [gap]})), principal=Principal.for_role("viewer"))
    ctx.surface = "drawer"

    outcome = catalogue_registry().invoke(
        ctx, "assessment_read", {"mode": "finding", "run_id": "run-1", "finding_id": "gap:@0"}
    )

    assert not outcome.is_error, outcome.ui_text
    assert len(outcome.ui_text) <= AGENT_MODEL_CHARS
    assert "output_truncated" not in outcome.model_text
    envelope = json.loads(outcome.ui_text)
    finding = envelope["result"]["finding"]
    assert (finding["kind"], finding["record_truncated"]) == ("gap", True)
    # the evidence gap is built from the cut record
    (listed,) = envelope["evidence"]["gaps"]
    assert (listed["code"], listed["kind"]) == ("rib-missing", "not-collected")
    assert listed["subject"] == finding["record"]["subject"]
    assert len(listed["subject"]) < len(gap["subject"])


class SessionStore(RunStore):
    """An app store holding analysis session revisions and their runs."""

    def __init__(self, sessions, *runs):
        super().__init__(*runs)
        self.sessions = {(s.id, s.revision): s for s in sessions}

    async def get_analysis_session(self, session_id, revision=None):
        if revision is not None:
            return self.sessions.get((session_id, revision))
        revisions = [s for (sid, _), s in self.sessions.items() if sid == session_id]
        return max(revisions, key=lambda s: s.revision) if revisions else None


def _session(revision, title):
    definition = {
        "schema_version": 1,
        "id": "sess-1",
        "revision": revision,
        "title": title,
        "input": {
            "kind": "simulation",
            "snapshot": REFERENCE,
            "changes": [{"kind": "fw_rule.add", "params": {"rulebase": "fw:core1:LAN"}}],
        },
        "runs": [{"id": "run-1", "item_id": "simulation", "execution": "queued", "coverage": "not_started"}]
        if revision > 1
        else [],
    }
    origin = {"conversation_id": "c-1", "message_id": "m-1", "step_id": "st-1", "step": "s1"}
    return AnalysisSessionRevision(
        id="sess-1",
        revision=revision,
        title=title,
        definition=definition,
        results={"review": {"origin": origin}},
        created_by=1,
        created_at="2026-09-28T00:00:00+00:00",
    )


def test_analysis_session_mode_reads_the_session_with_its_runs_and_review(monkeypatch):
    install(monkeypatch, FakeGraph())
    store = SessionStore(
        [_session(1, "Draft"), _session(2, "Block web")], _run("run-1", result={"result": _PASSES})
    )

    failed, newest = call(
        "assessment_read", {"mode": "analysis_session", "session_id": "sess-1"}, _context(store)
    )
    _, first = call(
        "assessment_read",
        {"mode": "analysis_session", "session_id": "sess-1", "revision": 1},
        _context(store),
    )
    missing_failed, missing = call(
        "assessment_read", {"mode": "analysis_session", "session_id": "none"}, _context(store)
    )

    assert not failed, newest
    session = newest["result"]["session"]
    assert (session["id"], session["revision"], session["title"], session["kind"]) == (
        "sess-1",
        2,
        "Block web",
        "simulation",
    )
    # the run's answer is its result
    run_result = session["runs"][0].pop("result")
    assert (run_result["statement"], run_result["word"]) == ("condition-holds", "passes")
    assert session["runs"] == [
        {
            "id": "run-1",
            "item_id": "simulation",
            "execution": "completed",
            "coverage": "complete",
        }
    ]
    assert session["review"]["origin"]["conversation_id"] == "c-1"
    assert newest["result"]["snapshot_matches"] is True
    assert newest["evidence"]["result"]["word"] == "passes"
    assert (first["result"]["session"]["title"], first["result"]["session"]["runs"]) == ("Draft", [])
    assert first["evidence"]["result"]["word"] == "stored record"
    assert missing_failed and missing["error"]["code"] == "not_found"
    assert missing["error"]["field"] == "session_id"


def test_analysis_session_mode_reads_an_old_stored_session_as_the_session_routes_do(monkeypatch):
    """A session stored by older builds: an inline request with `choice_scope`
    (89dd667b), a run summary with `outcome: null` (a2e950f5) and a completed
    run with an `outcome` and no result (before 376fd2b3). The tool reads it
    through `stored_session`: no error, and the older run is left out as the
    session routes leave it out."""
    install(monkeypatch, FakeGraph())
    request = {
        "name": "Client to API",
        "destination": "API",
        "sources": ["10.0.0.1"],
        "members": [{"name": "api", "addresses": ["192.0.2.1"]}],
        "condition": {"kind": "member", "member": "api"},
        "success": "forward",
        "choice_scope": "unspecified",
    }
    summary = {"item_id": "c-1", "result": None, "result_ref": None}
    definition = {
        "schema_version": 1,
        "id": "sess-old",
        "revision": 1,
        "title": "Old",
        "input": {
            "kind": "connection",
            "snapshot": REFERENCE,
            "connections": [{"id": "c-1", "name": "C", "source": {"kind": "inline", "request": request}}],
        },
        "runs": [
            {
                **summary,
                "id": "run-old",
                "execution": "completed",
                "outcome": "holds",
                "coverage": "complete",
            },
            {**summary, "id": "run-2", "execution": "queued", "outcome": None, "coverage": "not_started"},
        ],
    }
    old = AnalysisSessionRevision(
        id="sess-old",
        revision=1,
        title="Old",
        definition=definition,
        results={},
        created_by=1,
        created_at="2026-09-28T00:00:00+00:00",
    )
    store = SessionStore([old], _run("run-old", result={"result": _PASSES}))

    failed, answer = call(
        "assessment_read", {"mode": "analysis_session", "session_id": "sess-old"}, _context(store)
    )

    assert not failed, answer
    session = answer["result"]["session"]
    assert [row["id"] for row in session["runs"]] == ["run-2"]
    assert "1 run stored with an outcome and no result is not shown" in answer["evidence"]["unknowns"]
    assert "choice_scope" not in json.dumps(session)
    assert answer["evidence"]["result"]["word"] != "passes"
    # the stored row is not changed
    assert [run["id"] for run in old.definition["runs"]] == ["run-old", "run-2"]


def test_analysis_session_mode_names_a_stored_session_it_cannot_read(monkeypatch):
    install(monkeypatch, FakeGraph())
    broken = _session(2, "Block web")
    del broken.definition["title"]
    store = SessionStore([broken], _run("run-1", result={"result": _PASSES}))

    failed, answer = call(
        "assessment_read", {"mode": "analysis_session", "session_id": "sess-1"}, _context(store)
    )

    assert failed and answer["error"]["code"] == "internal"
    assert "stored analysis session sess-1 revision 2 cannot be read" in answer["error"]["message"]
    assert answer["error"]["field"] == "session_id"


def test_the_finding_and_session_modes_publish_their_inputs():
    schema = catalogue_registry().get("assessment_read").input_schema()

    assert set(schema["$defs"]["AssessmentFindingInput"]["required"]) == {"mode", "run_id", "finding_id"}
    assert set(schema["$defs"]["AssessmentSessionInput"]["required"]) == {"mode", "session_id"}


# --- evidence_get_gaps ---------------------------------------------------------------------


class _Readers:
    """A reader pool whose readers report fixed table outcomes."""

    def __init__(self, outcomes, approximate=False):
        self.outcomes = outcomes
        self.approximate = approximate

    def _source(self, table):
        return SimpleNamespace(coverage=lambda uid: self.outcomes[table], approximate=self.approximate)

    def rib(self, snap):
        return self._source("rib")

    def bgp(self, snap):
        return self._source("bgp_routes")

    def ospf(self, snap):
        return self._source("ospf_lsdb")

    def close(self):
        return None


def test_a_device_with_an_incomplete_table_has_a_gap_for_it(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    ctx = _context()
    ctx.readers = _Readers({"rib": "complete", "bgp_routes": "failed", "ospf_lsdb": "complete-empty"})

    failed, envelope = call("evidence_get_gaps", {"subject": {"kind": "device", "id": "dev:r1"}}, ctx)

    assert not failed, envelope
    assert envelope["result"]["tables"] == {
        "rib": "complete",
        "bgp_routes": "failed",
        "ospf_lsdb": "complete-empty",
    }
    (gap,) = envelope["result"]["gaps"]
    assert (gap["code"], gap["kind"], gap["subject"]) == ("bgp_routes-failed", "not-collected", "dev:r1")
    assert envelope["evidence"]["result"]["word"] == "recorded from an incomplete table"
    assert envelope["evidence"]["complete"] is False


def test_a_device_with_every_table_complete_is_proven(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    ctx = _context()
    ctx.readers = _Readers({"rib": "complete", "bgp_routes": "complete", "ospf_lsdb": "complete-empty"})

    failed, envelope = call("evidence_get_gaps", {"subject": {"kind": "device", "id": "dev:r1"}}, ctx)

    assert not failed
    assert envelope["result"]["gaps"] == []
    assert envelope["evidence"]["result"]["word"] == "recorded from a complete table"


def test_an_assessment_run_reports_its_gaps_and_collection_actions(monkeypatch):
    install(monkeypatch, FakeGraph())
    result = {
        "gaps": [{"code": "rib-missing", "kind": "not-collected", "subject": "dev:r1"}],
        "missing_evidence": ["routing evidence for dev:r1"],
        "actions": [
            {"id": "act-1", "recipe_id": "rib.show", "source": "lab", "host": "r1", "state": "available"}
        ],
    }
    store = RunStore(_run(result=result, kind="troubleshoot"))

    failed, envelope = call(
        "evidence_get_gaps", {"subject": {"kind": "assessment_run", "id": "run-1"}}, _context(store)
    )

    assert not failed, envelope
    codes = [gap["code"] for gap in envelope["result"]["gaps"]]
    assert codes == ["rib-missing", "missing-evidence"]
    assert envelope["result"]["collection_actions"] == [
        {"rank": 1, "recipe_id": "rib.show", "target": "lab/r1", "state": "available", "id": "act-1"}
    ]
    assert envelope["evidence"]["result"]["word"] == "recorded from an incomplete table"


def test_an_application_connection_reports_its_resolution_issues(monkeypatch):
    def reference_rows(params):
        if params.get("uid") != "dev:core1":
            return []
        return [
            {
                "uid": "dev:core1",
                "labels": ["Obj", "Device"],
                "bindings": [],
                "binding_count": 0,
                "evidence": None,
            }
        ]

    install(monkeypatch, FakeGraph([("binding_count", reference_rows)]))
    _published(monkeypatch)
    store = MemoryAssessmentStore()
    asyncio.run(
        save_definition(store, one_connection_definition("device", "dev:core1"), expected_revision=0, actor=1)
    )

    failed, envelope = call(
        "evidence_get_gaps",
        {"subject": {"kind": "application_connection", "id": "web", "application_id": "webshop"}},
        _context(store),
    )

    assert not failed, envelope
    codes = {gap["code"] for gap in envelope["result"]["gaps"]}
    assert "inventory-address-unavailable" in codes
    assert "inventory-read-incomplete" not in codes
    assert envelope["result"]["subject"]["readiness"] == "unresolved"
    assert asyncio.run(store.list_application_revisions("webshop")) != []


async def test_an_application_connection_subject_needs_an_application(monkeypatch):
    pytest.importorskip("mcp")
    from mcp.server.mcpserver.exceptions import ToolError as McpToolError

    graph = install(monkeypatch, FakeGraph())
    schema = catalogue_registry().get("evidence_get_gaps").input_schema()

    with pytest.raises(McpToolError, match="application_id"):
        await _mcp_call(
            monkeypatch, "evidence_get_gaps", {"subject": {"kind": "application_connection", "id": "web"}}
        )

    assert graph.session_kwargs == []
    assert schema["$defs"]["ConnectionGapsSubject"]["required"] == ["id", "kind", "application_id"]


def test_a_service_requirement_reports_the_gaps_of_its_evaluation(monkeypatch):
    install(monkeypatch, FakeGraph())
    seen = {}

    def evaluate(settings, session, snap, **kwargs):
        seen.update(kwargs)
        return {
            "gaps": [{"code": "routing-context-missing", "kind": "not-collected", "subject": "dev:r1"}],
            "missing_evidence": ["routing context of dev:r1"],
        }

    monkeypatch.setattr(direct, "evaluate_request", evaluate)

    failed, envelope = call(
        "evidence_get_gaps", {"subject": {"kind": "service_requirement", "id": "sreq:web"}}
    )

    assert not failed, envelope
    assert seen["requirement"] == "sreq:web" and seen["intents"] == []
    assert [gap["code"] for gap in envelope["result"]["gaps"]] == [
        "routing-context-missing",
        "missing-evidence",
    ]


# --- ops_list_collection_runs --------------------------------------------------------------


def _runs_store() -> FakeStore:
    store = FakeStore()
    started = datetime(2026, 9, 28, 8, 0, tzinfo=UTC)
    finished = datetime(2026, 9, 28, 8, 5, tzinfo=UTC)

    async def fill():
        published = await store.start_run("lab", started, triggered_by=1)
        await store.finish_run(published.id, "ok", finished, "cycle 4000: ok", snapshot_key="4000")
        failed = await store.start_run("lab", started)
        await store.finish_run(failed.id, "error", finished, "login refused")
        await store.enqueue_job(
            "collect.run",
            source="lab",
            not_before=started,
            max_attempts=1,
            triggered_by="runs:1",
            now=started,
        )

    asyncio.run(fill())
    return store


def test_ops_returns_the_pending_runs_of_get_api_runs(monkeypatch):
    from hst.app.routes import runs as runs_route

    install(monkeypatch, FakeGraph())
    store = _runs_store()
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(store=store, settings=None)))
    route = asyncio.run(runs_route.history(request, limit=50))
    ctx = _context(store, principal=Principal.local(store=True))

    failed, envelope = call("ops_list_collection_runs", {}, ctx)

    assert not failed, envelope
    result = envelope["result"]
    assert result["pending_runs"] == route["pending_runs"]
    assert len(result["pending_runs"]) == 1
    assert [
        {k: v for k, v in run.items() if k not in ("snapshot_key", "snapshot_matches", "evidence")}
        for run in result["runs"]
    ] == route["runs"]
    assert [(run["snapshot_key"], run["snapshot_matches"]) for run in result["runs"]] == [
        (None, None),
        ("4000", True),
    ]


def test_ops_filters_runs_by_status_and_source(monkeypatch):
    install(monkeypatch, FakeGraph())
    ctx = _context(_runs_store(), principal=Principal.local(store=True))

    _, errors = call("ops_list_collection_runs", {"status": "error"}, ctx)
    _, other = call("ops_list_collection_runs", {"source": "other"}, ctx)

    assert [run["detail"] for run in errors["result"]["runs"]] == ["login refused"]
    assert other["result"]["runs"] == []
    assert len(other["result"]["pending_runs"]) == 1


def test_ops_needs_runs_manage(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, error = call("ops_list_collection_runs", {}, _context(_runs_store()))

    assert failed and error["error"]["code"] == "permission_denied"
    assert catalogue_registry().get("ops_list_collection_runs").permission == "runs.manage"


async def test_ops_is_offered_on_local_stdio_only_with_an_app_store():
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    bare = {tool.name for tool in await build_server().list_tools()}
    with_store = {tool.name for tool in await build_server(Principal.local(store=True)).list_tools()}

    assert "ops_list_collection_runs" not in bare
    assert "ops_list_collection_runs" in with_store
    assert with_store - bare == {"ops_list_collection_runs"}


# --- policy_evaluate -----------------------------------------------------------------------

_EXPLAIN = {"mode": "explain_rule", "rulebase": "fw:rb", "rule": "fw:rb/r1"}


def test_explain_rule_needs_the_symbolic_engine(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, error = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="legacy-v1"))

    assert failed and error["error"]["code"] == "engine_unavailable"
    assert "symbolic-v2" in error["error"]["message"]


def test_explain_rule_needs_the_native_backend(monkeypatch):
    install(monkeypatch, FakeGraph())
    monkeypatch.setattr(symbolic, "backend_available", lambda: False)

    failed, error = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

    assert failed and error["error"]["code"] == "engine_unavailable"


def _explained(**overrides):
    document = {
        "rulebase": "fw:rb",
        "rule": "fw:rb/r1",
        "address_family": 4,
        "vendor": None,
        "qualified": True,
        "action": "permit",
        "called_layer": None,
        "enabled": True,
        "lower_empty": False,
        "possible_empty": False,
        "gaps": [{"code": "GRAPH_RULE_QUALIFIER_UNKNOWN", "subject": "fw:rb/r1/in_interface_group"}],
        "items": [
            {"match": "definite", "sources": ["10.0.0.0/24"], "destinations": ["0.0.0.0/0"]},
            {"match": "possible", "sources": ["10.0.1.0/24"], "destinations": ["0.0.0.0/0"]},
        ],
        "definite_count": 1,
        "possible_count": 2,
        "next_offset": 2,
    }
    document.update(overrides)
    return document


def test_explain_rule_maps_the_child_answer_to_the_envelope(monkeypatch):
    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    sent = []

    def isolated(settings, inputs):
        sent.append(inputs)
        return _explained()

    monkeypatch.setattr(direct, "run_isolated", isolated)

    failed, envelope = call(
        "policy_evaluate", {**_EXPLAIN, "limit": 2}, _context(analysis_engine="symbolic-v2")
    )

    assert not failed, envelope
    assert sent[0] == {
        "analysis": {"kind": "symbolic-explain-rule"},
        "snapshot": REFERENCE,
        "rulebase": "fw:rb",
        "rule": "fw:rb/r1",
        "offset": 0,
        "limit": 2,
    }
    result = envelope["result"]
    assert result["action"] == "permit"
    assert result["first_match"][0]["sources"] == ["10.0.0.0/24"]
    assert result["first_match"][0]["evidence"]["result"]["answer"] == "true"
    possible_only = result["not_decided"][0]["evidence"]
    assert possible_only["result"]["answer"] == "open"
    assert possible_only["result"]["statement"] == "rule-first-match"
    assert possible_only["result"]["word"] == "not decided"
    assert possible_only["result"]["missing"][0]["code"] == "GRAPH_RULE_QUALIFIER_UNKNOWN"
    assert result["first_match"][0]["evidence"]["result"]["word"] == "first match"
    assert envelope["evidence"]["result"]["answer"] == "open"
    assert envelope["evidence"]["bounds"]["unit"] == "flow-rectangles"
    assert (envelope["evidence"]["bounds"]["lower_count"], envelope["evidence"]["bounds"]["upper_count"]) == (
        1,
        3,
    )
    assert envelope["evidence"]["gaps"][0]["code"] == "GRAPH_RULE_QUALIFIER_UNKNOWN"
    assert envelope["page"]["truncated"] is True and envelope["page"]["total"] == 3
    assert envelope["provenance"]["engine"] == "symbolic-v2"


def test_explain_rule_carries_the_leak_guards_of_the_rule(monkeypatch):
    from hst.path import leak_guard

    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: _explained(action="drop"))
    asked = []
    guard = {"status": "definite", "effect": "Rule 10 is not on the tunnel path because ..."}

    def guards(session, rulebase, rule, af, rib=None):
        asked.append((rulebase, rule, af, session.cts, callable(rib)))
        return {"leak_guards": [guard], "guard_gaps": [], "notes": []}

    monkeypatch.setattr(leak_guard, "leak_guards", guards)

    failed, envelope = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

    assert not failed, envelope
    assert asked == [("fw:rb", "fw:rb/r1", 4, 4000, True)]
    assert envelope["result"]["intent"] == {"leak_guards": [guard], "guard_gaps": [], "notes": []}
    assert any("leak guards" in unknown for unknown in envelope["evidence"]["unknowns"])


def test_explain_rule_without_a_family_uses_the_family_the_child_explained_the_rule_in(monkeypatch):
    from hst.path import leak_guard

    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    asked = []
    monkeypatch.setattr(
        leak_guard,
        "leak_guards",
        lambda session, rulebase, rule, af, rib=None: (
            asked.append(af) or {"leak_guards": [], "guard_gaps": [], "notes": []}
        ),
    )

    for family in (4, 6):
        sent = []

        def isolated(settings, inputs, family=family, sent=sent):
            sent.append(inputs)
            return _explained(address_family=family)

        monkeypatch.setattr(direct, "run_isolated", isolated)

        failed, envelope = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

        assert not failed, envelope
        # no family asked for: the child takes the family the rulebase records
        assert "address_family" not in sent[0]
        assert envelope["result"]["address_family"] == family
        assert asked[-1] == family

    sent.clear()
    call("policy_evaluate", {**_EXPLAIN, "address_family": 4}, _context(analysis_engine="symbolic-v2"))
    assert sent[0]["address_family"] == 4


def test_explain_rule_returns_the_child_refusal_as_a_tool_error(monkeypatch):
    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    monkeypatch.setattr(
        direct,
        "run_isolated",
        lambda settings, inputs: {"error": {"code": "not_found", "message": "no rule x", "field": "rule"}},
    )

    failed, error = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

    assert failed and error["error"] == {
        "code": "not_found",
        "message": "no rule x",
        "retryable": False,
        "field": "rule",
    }


def test_explain_rule_names_the_gateway_candidates_when_several_enforce_the_rulebase(monkeypatch):
    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    sent = []
    candidates = [{"uid": "dev:gw1", "hostname": "gw1"}, {"uid": "dev:gw2", "hostname": "gw2"}]

    def isolated(settings, inputs):
        sent.append(inputs)
        if "firewall" not in inputs:
            return {
                "error": {
                    "code": "ambiguous",
                    "message": "2 gateways enforce rulebase fw:rb",
                    "field": "firewall",
                    "candidates": candidates,
                }
            }
        return _explained(firewall=inputs["firewall"])

    monkeypatch.setattr(direct, "run_isolated", isolated)
    ctx = _context(analysis_engine="symbolic-v2")

    failed, error = call("policy_evaluate", _EXPLAIN, ctx)
    bound_failed, envelope = call("policy_evaluate", {**_EXPLAIN, "firewall": "dev:gw2"}, ctx)

    assert failed and error["error"]["code"] == "ambiguous" and error["error"]["field"] == "firewall"
    assert error["error"]["candidates"] == candidates
    assert not bound_failed, envelope
    assert sent[1]["firewall"] == "dev:gw2"
    assert envelope["result"]["firewall"] == "dev:gw2"
    assert (
        "the install-on column of each rule is bound to gateway dev:gw2" in envelope["evidence"]["unknowns"]
    )


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"enabled": False, "matches_nothing": True}, "the rule is disabled and matches no flow"),
        (
            {"matches_nothing": True, "firewall": "dev:gw2"},
            "the rule matches no flow of this address family on gateway dev:gw2",
        ),
        ({"matches_nothing": False}, "earlier rules take every flow it matches"),
    ],
)
def test_a_rule_that_nothing_arrives_at_names_the_reason(monkeypatch, overrides, reason):
    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    document = _explained(
        lower_empty=True, possible_empty=True, items=[], definite_count=0, possible_count=0, next_offset=None
    )
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: {**document, **overrides})

    failed, envelope = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

    assert not failed, envelope
    assert envelope["evidence"]["result"]["answer"] == "true"
    assert sum(reason in unknown for unknown in envelope["evidence"]["unknowns"]) == 1


def test_a_check_point_rulebase_no_gateway_enforces_is_not_established(monkeypatch):
    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    document = _explained(
        vendor="checkpoint",
        installation_unknown=True,
        gaps=[{"code": "INSTALLATION_UNKNOWN", "subject": "fw:rb"}],
        items=[],
        definite_count=None,
        possible_count=None,
        next_offset=None,
    )
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: document)

    failed, envelope = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

    assert not failed, envelope
    assert envelope["evidence"]["result"]["answer"] == "open"
    assert envelope["evidence"]["bounds"] is None
    assert envelope["evidence"]["gaps"][0]["code"] == "INSTALLATION_UNKNOWN"
    assert any("no gateway in this snapshot enforces" in u for u in envelope["evidence"]["unknowns"])


def test_an_explain_rule_page_stays_within_the_page_budget(monkeypatch):
    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    wide = ["10.0.0.0/24"] * 12000
    document = _explained(
        items=[{"match": "definite", "sources": wide, "destinations": ["0.0.0.0/0"]} for _ in range(3)],
        definite_count=3,
        possible_count=0,
        next_offset=None,
    )
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: document)

    failed, envelope = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

    assert not failed
    assert len(envelope["result"]["first_match"]) == 1
    assert envelope["page"]["truncated"] is True and envelope["page"]["next_cursor"] is not None
    assert envelope["page"]["total"] == 3


def test_a_findings_page_stays_within_the_page_budget(monkeypatch):
    install(monkeypatch, FakeGraph())
    reference = {"estate": "test", "manifest_sha256": "a" * 64, "artifact_sha256": "b" * 64}
    store = RunStore(_run(result={"symbolic": {"artifact_ref": reference}}))
    wide = {"sources": ["10.0.0.0/24"] * 12000}
    monkeypatch.setattr(
        direct,
        "run_isolated",
        lambda settings, inputs: {"count": 3, "items": [wide, wide, wide], "next_offset": None},
    )
    arguments = {
        "mode": "findings",
        "assessment_id": "a-1",
        "run_id": "run-1",
        "bucket": "decided_change.loss",
    }

    failed, envelope = call("assessment_read", arguments, _context(store))

    assert not failed, envelope
    assert len(envelope["result"]["items"]) == 1
    assert envelope["page"]["truncated"] is True and envelope["page"]["next_cursor"] is not None


def test_explain_rule_on_a_run_without_a_manifest_is_snapshot_not_published(monkeypatch):
    install(monkeypatch, FakeGraph())
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)

    def unpublished(settings, value):
        raise ValueError("A published snapshot with an evidence manifest is required.")

    monkeypatch.setattr(assessment_service, "snapshot_reference", unpublished)

    failed, error = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

    assert failed and error["error"]["code"] == "snapshot_not_published"


def test_the_child_dispatches_the_explain_kind(monkeypatch):
    seen = []
    monkeypatch.setattr(
        rule_explain, "execute_explain", lambda settings, inputs, cancelled=None: seen.append(inputs) or {}
    )

    assessment_service.execute(None, {"analysis": {"kind": "symbolic-explain-rule"}})

    assert seen == [{"analysis": {"kind": "symbolic-explain-rule"}}]


# --- the rule explanation in the child -----------------------------------------------------


def _graph(rules, objects=()):
    """A rulebase `rb` with default deny, its rules, and address objects.

    `rules` holds (uid, props, source object uids); `objects` holds (uid, cidr).
    """
    nodes = {"rb": GraphNode("rb", frozenset({"FwRulebase"}), MappingProxyType({"default_action": "deny"}))}
    for uid, cidr in objects:
        nodes[uid] = GraphNode(uid, frozenset({"NetObject"}), MappingProxyType({"cidr": cidr}))
    outgoing, incoming = defaultdict(list), defaultdict(list)

    def relate(kind, start, end):
        relation = GraphRelation(f"{start}>{kind}>{end}", kind, start, end, MappingProxyType({}))
        outgoing[start, kind].append(relation)
        incoming[end, kind].append(relation)

    for uid, props, sources in rules:
        nodes[uid] = GraphNode(uid, frozenset({"FwRule"}), MappingProxyType(props))
        relate("HAS_RULE", "rb", uid)
        for target in sources:
            relate("SRC", uid, target)
    labels = defaultdict(list)
    for uid, node in nodes.items():
        for label in node.labels:
            labels[label].append(uid)
    return GraphInventory(
        "a" * 64,
        "fingerprint",
        MappingProxyType(nodes),
        MappingProxyType({key: tuple(value) for key, value in labels.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )


_ANY = {"enabled": True, "dst_any": True, "svc_any": True}
_FIRST_MATCHES_A = _graph(
    [
        ("r1", {"position": 1, "action": "accept", **_ANY}, ["net:a"]),
        ("r2", {"position": 2, "action": "accept", "src_any": True, **_ANY}, []),
    ],
    [("net:a", "10.0.0.0/24")],
)
_FIRST_IS_OPAQUE = _graph(
    [
        ("r1", {"position": 1, "action": "accept", "src_any": True, "vendor_qualifier": "x", **_ANY}, []),
        ("r2", {"position": 2, "action": "accept", "src_any": True, **_ANY}, []),
    ]
)


def test_an_unknown_rulebase_or_rule_is_not_found():
    assert rule_explain.explain(_FIRST_MATCHES_A, "test", "nothing", "r1", 4)["error"]["field"] == "rulebase"
    assert rule_explain.explain(_FIRST_MATCHES_A, "test", "rb", "r9", 4)["error"]["field"] == "rule"


def _backend():
    if not symbolic.backend_available():
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")


def test_a_rule_that_decides_its_sources_is_definite_for_them():
    _backend()

    first = rule_explain.explain(_FIRST_MATCHES_A, "test", "rb", "r1", 4, limit=1000)
    second = rule_explain.explain(_FIRST_MATCHES_A, "test", "rb", "r2", 4, limit=1000)

    assert first["action"] == "permit"
    assert first["lower_empty"] is False and first["possible_empty"] is True
    assert "render_error" not in first
    assert first["definite_count"] >= 1 and first["possible_count"] == 0
    assert all(item["sources"] == ["10.0.0.0/24"] for item in first["items"])
    # every source the first rule does not take arrives at the second one
    assert second["lower_empty"] is False and second["possible_empty"] is True
    assert second["definite_count"] >= 1
    assert all("10.0.0.0/24" not in item["sources"] for item in second["items"])


def test_an_opaque_rule_possibly_matches_and_names_its_gap():
    _backend()

    first = rule_explain.explain(_FIRST_IS_OPAQUE, "test", "rb", "r1", 4, limit=1)
    second = rule_explain.explain(_FIRST_IS_OPAQUE, "test", "rb", "r2", 4)

    assert first["lower_empty"] is True and first["possible_empty"] is False
    assert "GRAPH_RULE_UNSUPPORTED_FIELD" in {gap["code"] for gap in first["gaps"]}
    assert len(first["items"]) == 1 and all(item["match"] == "possible" for item in first["items"])
    # no flow is certain to pass the opaque rule, so no flow must arrive at the second one
    assert second["lower_empty"] is True and second["possible_empty"] is False


# --- a Check Point rulebase: install-on binds to the enforcing gateway ---------------------

_CP_SCOPE = scope_of("manager", "domain")
# minted by the in-memory registry from the gateway names in `_checkpoint_graph`
_GW1, _GW2 = "dev:fw1", "dev:fw2"
_CP_RULEBASE = uidmod.checkpoint("manager", "domain", "layer")
_CP_R1, _CP_R2 = uidmod.checkpoint("manager", "domain", "r1"), uidmod.checkpoint("manager", "domain", "r2")


def _checkpoint_graph(installation_targets):
    """A Check Point package with one layer: r1 accepts https from 192.0.2.1
    and is installed on gw1 only; r2 accepts https from any source on gw1 and
    gw2. The package is installed on `installation_targets`."""
    domain = {"uid": "domain"}
    any_object = {"uid": "any", "name": "Any", "type": "CpmiAnyObject", "domain": domain}
    action = {"uid": "accept", "name": "Accept", "type": "RulebaseAction", "domain": domain}
    host = {"uid": "host", "name": "client", "type": "host", "domain": domain, "ipv4-address": "192.0.2.1"}
    service = {
        "uid": "https",
        "name": "https",
        "type": "service-tcp",
        "domain": domain,
        "port": "443",
        "source-port": "",
        "protocol": "",
        "match-by-protocol-signature": False,
    }

    def rule(uid, number, source, install_on):
        return {
            "uid": uid,
            "type": "access-rule",
            "domain": domain,
            "rule-number": number,
            "enabled": True,
            "action": "accept",
            "source": [source],
            "destination": ["any"],
            "service": ["https"],
            "install-on": install_on,
            "source-negate": False,
            "destination-negate": False,
            "service-negate": False,
            "time": ["any"],
            "vpn": ["any"],
            "content": ["any"],
        }

    layer = {
        "uid": "layer",
        "name": "Network",
        "type": "access-layer",
        "domain": domain,
        "implicit-cleanup-action": "drop",
    }
    package = {
        "uid": "package",
        "name": "Policy",
        "type": "package",
        "domain": domain,
        "access-layers": ["layer"],
        "installation-targets": installation_targets,
    }
    raw = {
        "gateways": [
            {"uid": "gw1", "name": "fw1", "type": "simple-gateway"},
            {"uid": "gw2", "name": "fw2", "type": "simple-gateway"},
        ],
        "layers": [layer],
        "packages": [package],
        "package_details": {"package": package},
        "package_revisions": {"package": "revision"},
        "rulebases": {
            "layer": [
                {
                    "rulebase": [rule("r1", 1, "host", ["gw1"]), rule("r2", 2, "any", ["gw1", "gw2"])],
                    "objects-dictionary": [any_object, action, host, service],
                }
            ]
        },
        "nat": {},
        "policy_section_errors": [],
        "management_release": "R81.20",
        "gateway_release": "R81.20",
        "api_version": "1.9",
        "implied_rules_complete": True,
    }
    batch = checkpoint_batch.normalize(raw, mgmt="manager", domain="domain")
    nodes = {
        item.uid: GraphNode(item.uid, frozenset({item.label}), MappingProxyType(item.props))
        for item in batch.nodes
    }
    relations = [
        GraphRelation(
            f"relation:{index}",
            item.rel_type,
            item.start_uid,
            item.end_uid,
            MappingProxyType({**item.key, **item.props}),
        )
        for index, item in enumerate(batch.rels)
    ]
    return _rebuild(GraphInventory("a" * 64, "seed", {}, {}, {}, {}, True, (), 0), nodes, relations)


def _covers(items, address):
    return any(ip_address(address) in ip_network(cidr) for item in items for cidr in item["sources"])


def test_a_check_point_rulebase_on_several_gateways_needs_the_firewall():
    graph = _checkpoint_graph(["gw1", "gw2"])

    ambiguous = rule_explain.explain(graph, "test", _CP_RULEBASE, _CP_R1, 4)
    unknown = rule_explain.explain(graph, "test", _CP_RULEBASE, _CP_R1, 4, firewall="dev:x:other")

    assert ambiguous["error"]["code"] == "ambiguous" and ambiguous["error"]["field"] == "firewall"
    assert [item["uid"] for item in ambiguous["error"]["candidates"]] == sorted([_GW1, _GW2])
    assert unknown["error"]["code"] == "not_found" and unknown["error"]["field"] == "firewall"


def test_a_check_point_rulebase_no_gateway_enforces_settles_nothing():
    document = rule_explain.explain(_checkpoint_graph([]), "test", _CP_RULEBASE, _CP_R1, 4)

    assert document["qualified"] is True and document["installation_unknown"] is True
    assert document["firewall"] is None and document["action"] == "permit"
    assert document["items"] == [] and document["definite_count"] is None
    assert document["gaps"] == [{"code": "INSTALLATION_UNKNOWN", "subject": _CP_RULEBASE}]


def test_a_check_point_rule_installed_on_one_gateway_is_explained_for_that_gateway():
    _backend()
    graph = _checkpoint_graph(["gw1", "gw2"])

    def explained(rule, firewall):
        return rule_explain.explain(graph, "test", _CP_RULEBASE, rule, 4, firewall=firewall, limit=1000)

    first_on_gw1, second_on_gw1 = explained(_CP_R1, _GW1), explained(_CP_R2, _GW1)
    first_on_gw2, second_on_gw2 = explained(_CP_R1, _GW2), explained(_CP_R2, _GW2)

    assert first_on_gw1["firewall"] == _GW1 and first_on_gw1["qualified"] is True
    assert first_on_gw1["lower_empty"] is False
    definite = [item for item in first_on_gw1["items"] if item["match"] == "definite"]
    assert definite and all(item["sources"] == ["192.0.2.1/32"] for item in definite)
    # on gw1 the first rule takes the https flows of 192.0.2.1, so they never arrive at the second
    assert second_on_gw1["lower_empty"] is False
    assert not _covers(second_on_gw1["items"], "192.0.2.1")
    # the first rule is not installed on gw2, so it matches nothing there and the second
    # rule receives the https flows of 192.0.2.1
    assert first_on_gw2["lower_empty"] is True and first_on_gw2["possible_empty"] is True
    assert first_on_gw2["matches_nothing"] is True
    assert second_on_gw2["lower_empty"] is False
    assert _covers([i for i in second_on_gw2["items"] if i["match"] == "definite"], "192.0.2.1")


def _relations(graph):
    return [relation for relations in graph.outgoing.values() for relation in relations]


def test_an_unqualified_rulebase_on_several_gateways_is_answered_without_asking_for_the_firewall():
    built = _checkpoint_graph(["gw1", "gw2"])
    # no package lists the layer, so the capture cannot be qualified
    graph = _rebuild(built, dict(built.nodes), [r for r in _relations(built) if r.kind != "HAS_LAYER"])

    document = rule_explain.explain(graph, "test", _CP_RULEBASE, _CP_R1, 4)

    assert "error" not in document
    assert document["qualified"] is False and document["firewall"] is None
    assert document["items"] == [] and document["definite_count"] is None
    assert document["gaps"] == [{"code": "CHECKPOINT_CAPTURE_UNQUALIFIED", "subject": _CP_RULEBASE}]


_CP_INLINE = uidmod.checkpoint("manager", "domain", "inline")
_CP_R3 = uidmod.checkpoint("manager", "domain", "r3")
_CP_CALLER = uidmod.checkpoint("manager", "domain", "caller")


def _with_inline_layer(graph):
    """`graph` with an inline layer holding r3, called by a rule of the
    package's ordered layer. As the collector records it, no package lists
    the inline layer and no gateway enforces it."""
    nodes = dict(graph.nodes)

    def add(uid, label, envelope):
        props = {"uid": uid, "vendor": "checkpoint", "checkpoint_envelope": json.dumps(envelope)}
        nodes[uid] = GraphNode(uid, frozenset({label}), MappingProxyType(props))

    add(_CP_INLINE, "FwRulebase", {"uid": "inline", "name": "Inline", "type": "access-layer"})
    add(_CP_R3, "FwRule", {"uid": "r3", "type": "access-rule", "rule-number": 1})
    add(_CP_CALLER, "FwRule", {"uid": "caller", "type": "access-rule", "inline-layer": "inline"})
    relations = [
        *_relations(graph),
        GraphRelation("relation:inline", "HAS_RULE", _CP_INLINE, _CP_R3, MappingProxyType({})),
        GraphRelation("relation:caller", "HAS_RULE", _CP_RULEBASE, _CP_CALLER, MappingProxyType({})),
    ]
    return _rebuild(graph, nodes, relations)


def test_a_rule_of_an_inline_layer_names_the_rules_that_call_the_layer():
    graph = _with_inline_layer(_checkpoint_graph(["gw1"]))

    document = rule_explain.explain(graph, "test", _CP_INLINE, _CP_R3, 4)

    assert document["qualified"] is False
    assert document["inline_layer_callers"] == [_CP_CALLER]
    assert document["gaps"] == [{"code": "CHECKPOINT_INLINE_LAYER", "subject": _CP_INLINE}]
    assert document["items"] == [] and document["definite_count"] is None


def test_explain_rule_on_an_inline_layer_names_the_calling_rules_in_the_envelope(monkeypatch):
    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    document = _explained(
        vendor="checkpoint",
        qualified=False,
        action="unknown",
        items=[],
        definite_count=None,
        possible_count=None,
        next_offset=None,
        inline_layer_callers=["cp:manager:domain:caller"],
        gaps=[{"code": "CHECKPOINT_INLINE_LAYER", "subject": "fw:rb"}],
    )
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: document)

    failed, envelope = call("policy_evaluate", _EXPLAIN, _context(analysis_engine="symbolic-v2"))

    assert not failed, envelope
    assert envelope["evidence"]["result"]["answer"] == "open"
    assert envelope["evidence"]["gaps"][0]["code"] == "CHECKPOINT_INLINE_LAYER"
    assert any(
        "inline layer" in unknown and "cp:manager:domain:caller" in unknown
        for unknown in envelope["evidence"]["unknowns"]
    )
