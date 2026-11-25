"""`hst.results.project`: the HTTP bodies carry the result vocabulary
beside the engine's own fields."""

from __future__ import annotations

from hst.analysis.contracts import AnalysisRunSummary
from hst.app.routes.analysis_sessions import _result
from hst.applications.flows import path_result
from hst.applications.validation import _flow_outcome
from hst.results.project import missing_from_gaps, project_evaluation


def test_the_evaluation_body_gets_the_condition_answer_on_both_sides():
    body = {
        "mode": "guaranteed",
        "request": {"success": "session"},
        "outcomes": {"before": {"verdict": "holds"}, "after": {"verdict": "does-not-hold"}},
        "gaps": [],
        "evidence": {"items": [{"outcome": "holds", "missing": []}]},
    }
    answer = project_evaluation(body, None)
    assert answer is not None and answer.word == "fails"
    assert (answer.quantifier, answer.condition) == ("every", "session")
    assert body["outcomes"]["before"]["result"]["word"] == "passes"
    assert "verdict" not in body["outcomes"]["after"]
    assert body["evidence"]["items"][0]["result"]["word"] == "passes"


def test_the_symbolic_engines_unknown_reads_as_not_decided():
    body = {
        "mode": "possible",
        "outcomes": {"after": {"verdict": "unknown"}},
        "gaps": [{"code": "MODEL_SCOPE_INCOMPLETE", "subject": "dev:vie01-core-01"}],
        "evidence": {"items": [{"outcome": "unknown", "missing": []}]},
    }
    answer = project_evaluation(body, None)
    assert answer is not None and answer.word == "not decided"
    assert answer.missing[0].subject == "dev:vie01-core-01"
    assert body["evidence"]["items"][0]["result"]["word"] == "not decided"


def test_gap_entries_become_missing_once_per_code_and_subject():
    entries = [
        {"code": "MODEL_SCOPE_INCOMPLETE", "subject": "dev:leaf101", "detail": "x"},
        {"code": "MODEL_SCOPE_INCOMPLETE", "subject": "dev:leaf101", "detail": "x again"},
        {"kind": "not-collected", "detail": "no code"},
    ]
    missing = missing_from_gaps(entries)
    assert [(m.code, m.subject, m.detail) for m in missing] == [
        ("MODEL_SCOPE_INCOMPLETE", "dev:leaf101", "x"),
        ("not-collected", None, "no code"),
    ]


def test_a_flow_check_carries_the_projected_result_or_builds_one_from_the_verdict():
    projected = {
        "kind": "result",
        "statement": "condition-holds",
        "answer": "true",
        "word": "passes",
        "missing": [],
    }
    with_result = _flow_outcome({"outcomes": {"after": {"result": projected}}})
    assert with_result["result"] == projected


def test_a_netmap_path_and_connection_state_have_a_result_word():
    assert path_result("true", [])["word"] == "passes"
    assert path_result("false", [])["word"] == "fails"
    assert path_result("open", [])["missing"][0]["code"] == "not-decided"
    assert path_result("unresolved", []) is None
    assert path_result("not-evaluated", []) is None


def test_an_analysis_run_summary_carries_the_result_of_its_run():
    projected = {
        "kind": "result",
        "statement": "condition-holds",
        "answer": "false",
        "word": "fails",
        "missing": [],
    }
    assert _result({"outcomes": {"after": {"result": projected}}}) == projected
    built = _result({"missing_evidence": ["routing evidence for dev:r1"]})
    assert built["word"] == "not decided" and built["missing"][0]["detail"] == "routing evidence for dev:r1"
    assert _result(None) is None
    summary = AnalysisRunSummary(
        id="r1", item_id="i1", execution="completed", result=built, coverage="complete"
    )
    assert summary.result == built
