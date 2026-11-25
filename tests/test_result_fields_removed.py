"""The tool and HTTP bodies and their schemas hold none of these engine
fields: `status`, `polarity` and `gap_codes` of
each item's evidence, the whole answer's `evidence.status`, the engine's
bucket and member names, `verdict` and `outcome` beside `result`, the
`definite` and `possible` lists of `policy_evaluate`, and `choice_scope`."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from tests.test_application_flows import WALK, part, step
from tests.test_twin_tools_policy import _GROUPS, _paged_query
from tests.test_twin_tools_reach import _BLOCK, _PERMIT, _answer, _fake_trace, _trace
from tests.twin_tools_fakes import FakeGraph, call, context, install

from hst.analysis.contracts import AnalysisRunSummary
from hst.applications import flows
from hst.applications.models import Connection
from hst.applications.validation import _flow_outcome
from hst.assessment import direct
from hst.assessment.evaluation import RequestBody
from hst.assessment.resilience import search_resilience
from hst.assessment.search import FAILS, HOLDS
from hst.assessment.store import verified_answer
from hst.results.project import project_engine, project_evaluation
from hst.results.words import from_engine
from hst.twin_tools import catalogue_registry, write_registry
from hst.twin_tools.envelope import Evidence, ItemEvidence, whole_result
from hst.twin_tools.policy import PolicyEvaluateResult

# Names the engines use that no body or schema that leaves them carries.
_ENGINE_NAMES = {
    "proven",
    "possible",
    "not_established",
    "condition_holds",
    "condition_fails",
    "proven_loss",
    "possible_loss",
    "proven_gain",
    "possible_gain",
    "worked_now_unknown",
    "unknown_now_broken",
    "unknown_throughout",
    "unknown_now_works",
    "broken_now_unknown",
    "verdict",
    "holds",
    "not-established",
    "does-not-hold",
}
_REMOVED_FIELDS = {
    "polarity",
    "gap_codes",
    "definite",
    "possible_only",
    "definite_count",
    "possible_count",
    "not_established_count",
    "choice_scope",
}


def _keys(value: Any) -> set[str]:
    """Every key of a JSON body, at any depth."""
    out: set[str] = set()
    if isinstance(value, dict):
        for name, item in value.items():
            out.add(name)
            out |= _keys(item)
    elif isinstance(value, list):
        for item in value:
            out |= _keys(item)
    return out


def _values(value: Any) -> set[str]:
    """Every string value of a JSON body, at any depth."""
    if isinstance(value, dict):
        return set().union(*(_values(item) for item in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(_values(item) for item in value)) if value else set()
    return {value} if isinstance(value, str) else set()


def _properties(schema: Any) -> set[str]:
    """Every property name a JSON Schema declares, at any depth."""
    out: set[str] = set()
    if isinstance(schema, dict):
        for name, item in schema.items():
            if name == "properties" and isinstance(item, dict):
                out |= set(item)
            out |= _properties(item)
    elif isinstance(schema, list):
        for item in schema:
            out |= _properties(item)
    return out


def _engine_body(**parts: Any) -> dict[str, Any]:
    """An evaluation body as the engine returns it, before projection."""

    def bucket(*items: str) -> dict[str, Any]:
        return {"count": len(items), "items": list(items), "truncated": False}

    body = {
        "mode": "possible",
        "request": {"success": "forward"},
        "outcomes": {
            "before": {
                "verdict": "holds",
                "isolated": False,
                "holds": ["10.0.0.0/24"],
                "fails": [],
                "unknown": [],
            },
            "after": {
                "verdict": "does-not-hold",
                "isolated": False,
                "holds": [],
                "fails": ["10.0.0.0/24"],
                "unknown": [],
                "counts": {"holds": "0", "fails": "256", "unknown": "0"},
            },
        },
        "proven": {"loss": bucket("10.0.0.0/24"), "gain": bucket()},
        "possible": {"loss": bucket("10.0.0.0/24"), "gain": bucket()},
        "not_established": {"before": bucket(), "after": bucket()},
        "condition_holds": {"before": bucket("10.0.0.0/24"), "after": bucket()},
        "condition_fails": {"before": bucket(), "after": bucket("10.0.0.0/24")},
        "triage": {
            "proven_loss": bucket("10.0.0.0/24"),
            "worked_now_unknown": bucket(),
            "unknown_now_broken": bucket(),
            "unknown_throughout": bucket(),
            "proven_gain": bucket(),
            "unknown_now_works": bucket(),
            "broken_now_unknown": bucket(),
        },
        "members": [
            {
                "name": "app",
                "proven_loss": True,
                "possible_loss": True,
                "proven_gain": False,
                "possible_gain": False,
                "triage": {"proven_loss": True, "unknown_throughout": False},
                "before": {"holds": 1, "does-not-hold": 0, "not-established": 0},
                "after": {"holds": 0, "does-not-hold": 1, "not-established": 0},
            }
        ],
        "evidence": {
            "count": 1,
            "items": [{"side": "after", "outcome": "does-not-hold", "missing": [], "steps": []}],
            "truncated": False,
        },
        "missing_evidence": [],
        "gaps": [],
    }
    body.update(parts)
    return body


# --- the envelope ------------------------------------------------------------------------------


def test_item_evidence_has_only_result_and_basis():
    evidence = ItemEvidence.of(
        from_engine("hop-forwards", "does-not-hold", cause="no route"), basis="derived"
    )
    assert set(evidence.model_dump(mode="json")) == {"result", "basis"}
    assert set(ItemEvidence.model_json_schema()["properties"]) == {"result", "basis"}


def test_the_whole_answer_states_a_result_and_no_status():
    schema = Evidence.model_json_schema()
    assert "status" not in schema["properties"]
    assert "result" in schema["required"]
    assert "not_established_count" not in _properties(schema) and "open_count" in _properties(schema)
    # a list states the completeness its items share, or that each states its own
    decided = from_engine("condition-holds", "holds")
    assert whole_result([decided, decided]).word == "passes"
    assert whole_result([decided, from_engine("condition-holds", "does-not-hold")]).word == (
        "each item states its own result"
    )
    assert whole_result([], unknowns=["the read stopped"]).missing[0].detail == "the read stopped"


def test_no_tool_schema_declares_a_removed_field():
    for registry in (catalogue_registry(), write_registry()):
        for spec in registry.specs():
            output = spec.output_model.model_json_schema() if spec.output_model is not None else {}
            declared = _properties(output) | _properties(spec.input_schema())
            assert not _REMOVED_FIELDS & declared, spec.name
            assert "status" not in output["$defs"]["Evidence"]["properties"], spec.name
    assert not {"definite", "possible_only", "definite_count", "possible_count"} & set(
        PolicyEvaluateResult.model_fields
    )


def test_every_tool_body_changed_by_the_vocabulary_carries_a_new_version():
    versions = {
        spec.name: spec.version for r in (catalogue_registry(), write_registry()) for spec in r.specs()
    }
    # a trace and a simulated flow answer in result with their prose as detail; an
    # analysis session's run states no outcome
    for name in (
        "policy_evaluate",
        "reach_trace",
        "change_simulate",
        "change_get_simulation",
        "assessment_read",
    ):
        assert versions.pop(name) == 4, name
    assert set(versions.values()) == {3}


# --- evaluation bodies -------------------------------------------------------------------------


def test_an_engine_body_leaves_with_the_result_names_only():
    body = _engine_body()
    answer = project_evaluation(body, "possible")

    assert answer is not None and answer.word == "fails"
    assert not _ENGINE_NAMES & _keys(body)
    assert {"decided_change", "open_change", "open", "passes", "fails"} <= set(body)
    assert set(body["triage"]) == {
        "decided_loss",
        "passes_then_open",
        "open_then_fails",
        "open_throughout",
        "decided_gain",
        "open_then_passes",
        "fails_then_open",
    }
    (member,) = body["members"]
    assert {"decided_loss", "open_loss", "decided_gain", "open_gain"} <= set(member)
    assert member["after"] == {"passes": 0, "fails": 1, "open": 0}
    after = body["outcomes"]["after"]
    assert (after["passes"], after["fails"], after["open"]) == ([], ["10.0.0.0/24"], [])
    assert after["counts"] == {"passes": "0", "fails": "256", "open": "0"}
    assert body["evidence"]["items"][0]["result"]["word"] == "fails"
    # projecting a projected body changes nothing
    again = project_engine(dict(body), "possible")
    assert again == body


def test_an_evaluation_over_http_and_the_tool_leaves_projected(monkeypatch):
    install(monkeypatch, FakeGraph())
    # both engines answer through the isolated child, so its answer is the seam
    monkeypatch.setattr(direct, "evaluate_pinned", lambda *a, **k: _engine_body())

    body = direct.evaluate_request(
        SimpleNamespace(analysis_engine="legacy-v1"),
        None,
        None,
        intents=[],
        requirement=None,
        request={
            "name": "app",
            "destination": "app",
            "sources": ["10.0.0.0/24"],
            "members": [{"name": "app", "addresses": ["10.1.0.0/24"]}],
            "condition": {"kind": "member", "member": "app"},
        },
        mode="possible",
    )
    assert not _ENGINE_NAMES & _keys(body)
    assert body["outcomes"]["after"]["result"]["word"] == "fails"


def test_a_stored_assessment_run_is_written_in_the_result_vocabulary():
    result = project_engine(
        {
            "kind": "repair",
            "mode": "guaranteed",
            "verdict": "does-not-hold",
            "findings": [
                {
                    "candidates": ["a"],
                    "verdict": "holds",
                    "verified": True,
                    "desired": "holds",
                    "protected": {"web": "holds"},
                    "summary": {"outcomes": {"after": {"verdict": "holds", "isolated": False}}},
                }
            ],
            "trials": [{"candidates": ["b"], "verdict": "not-established", "reason": "the budget ran out"}],
            "constraints": {
                "desired": "holds",
                "protected": {"web": "does-not-hold"},
                "verdict": "does-not-hold",
            },
        },
        "guaranteed",
    )

    assert not _ENGINE_NAMES & _keys(result)
    assert not {"holds", "does-not-hold", "not-established"} & _values(result)
    (finding,) = result["findings"]
    assert verified_answer(finding)
    assert finding["result"]["quantifier"] == "every"
    assert result["trials"][0]["result"]["missing"][0]["detail"] == "the budget ran out"
    assert result["constraints"]["protected"]["web"]["word"] == "fails"


def test_the_groups_buckets_are_passes_fails_and_open(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    _paged_query(monkeypatch, unknown=1)

    failed, envelope = call("reach_trace", _GROUPS, context(sidestore_dir=tmp_path))

    assert not failed, envelope
    result = envelope["result"]
    assert not {"allowed", "denied", "not_established"} & set(result)
    assert all("outcome" not in item for item in result["explanations"]["items"])
    assert "status" not in envelope["evidence"]


def test_trace_legs_carry_no_removed_evidence_fields(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    _fake_trace(monkeypatch, lambda: _answer(_PERMIT, _BLOCK))

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.1", "dst": "10.0.0.2"})

    assert not failed
    assert not {"status", "polarity", "gap_codes"} & _keys(envelope["result"])
    assert "status" not in envelope["evidence"]


# --- the web's application bodies --------------------------------------------------------------


def test_a_flow_check_names_its_clients_by_their_answer():
    result = from_engine("condition-holds", "does-not-hold").model_dump(mode="json")
    checked = _flow_outcome({"outcomes": {"after": {"result": result, "fails": ["10.0.0.0/24"]}}})
    assert "verdict" not in checked and not {"holds", "unknown"} & set(checked)
    assert (checked["passes"], checked["fails"], checked["open"]) == ([], ["10.0.0.0/24"], [])


def test_netmap_paths_count_and_draw_in_the_result_vocabulary():
    body = flows.connection_paths("web", [part("holds", [step("a"), step("b")]), part("unknown", WALK)])
    assert set(body["counts"]) == {"passes", "fails", "open"}
    states = {segment["state"] for path in body["paths"] for segment in path["segments"]}
    assert states <= {"passes", "fails", "decided", "open"}
    assert all("outcome" not in path for path in body["paths"])


def test_a_run_summary_states_its_answer_only_as_result():
    properties = AnalysisRunSummary.model_json_schema()["properties"]
    assert "outcome" not in properties and "result" in properties


def test_choice_scope_is_no_request_or_connection_field():
    assert "choice_scope" not in RequestBody.model_fields
    assert "choice_scope" not in Connection.model_fields


def test_a_resilience_body_states_its_baseline_as_a_result():
    targets = [{"id": "a", "kind": "device", "uid": "dev:a"}]
    body = project_engine(search_resilience(targets, [], lambda effects: FAILS if effects else HOLDS))
    assert "baseline_verdict" not in body
    assert body["baseline"]["result"]["answer"] == "true"
    assert all("verdict" not in trial for trial in body["trials"])
