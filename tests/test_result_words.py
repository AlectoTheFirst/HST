"""`hst.results.words`: the one word table every surface reads."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hst.results import words as w


def test_the_engine_values_map_onto_the_statements_words():
    assert w.from_engine("rule-permits", "holds").word == "permitted"
    assert w.from_engine("rule-permits", "does-not-hold", cause="rule 10 of LAN-WAN on core1").word == (
        "blocked by rule 10 of LAN-WAN on core1"
    )
    assert w.from_engine("hop-forwards", "does-not-hold", cause="no route").word == "no route"
    assert w.from_engine("trace-forwards", "holds").word == "forwarded, all candidate paths"
    assert w.from_engine("trace-forwards", "does-not-hold", device="core1").word == "blocked at core1"
    assert w.from_engine("condition-holds", "holds", condition="session", quantifier="every").word == "passes"
    assert w.from_engine("route-policy-accepts", "does-not-hold").word == "rejected"
    assert w.from_engine("object-exists", "does-not-hold").word == "removed"
    with pytest.raises(ValueError, match="not an engine value"):
        w.from_engine("rule-permits", "mixed")


def test_an_open_answer_always_names_what_is_missing_and_a_decided_one_never_does():
    missing = [w.Missing(code="not-collected", subject="eth2 on core1", detail="zones not collected")]

    result = w.from_engine("rule-permits", "not-established", missing=missing)
    assert result.answer == "open" and result.word == "not decided"
    with pytest.raises(ValidationError, match="open answer names what is missing"):
        w.from_engine("rule-permits", "not-established")
    with pytest.raises(ValidationError, match="open answer names what is missing"):
        w.from_engine("rule-permits", "holds", missing=missing)
    with pytest.raises(ValueError, match="comes from"):
        w.decided("rule-permits", "open")


def test_the_split_and_part_answers_are_stated_by_the_caller():
    split = w.decided("condition-holds", "split", device="core1", quantifier="some", condition="forward")
    assert split.word == "split by path at core1"
    assert w.decided("rule-permits", "partly").word == "partly permitted"
    assert w.decided("route-policy-accepts", "default").word == "platform default"
    assert w.decided("object-exists", "added").word == "added"
    with pytest.raises(ValueError, match="not an answer of"):
        w.decided("hop-forwards", "split")


def test_a_record_has_a_completeness_and_no_answer():
    row = w.record("incomplete")
    assert row.kind == "record" and row.answer is None and row.word == "recorded from an incomplete table"
    assert w.record("declared").kind == "declared"
    with pytest.raises(ValidationError, match="has no statement"):
        w.Result(kind="record", statement="rule-permits", answer="true", word="permitted")
    short = w.record("incomplete", missing=[w.Missing(code="table-partial", subject="dev:r1")])
    assert short.missing[0].subject == "dev:r1"


def test_no_result_word_is_an_engine_term():
    for statement, answers in w.WORDS.items():
        for answer in answers:
            rendered = w.word(statement, answer, cause="rule 1", device="d1")  # type: ignore[arg-type]
            assert not any(w._contains_word(rendered.lower(), bad) for bad in w.FORBIDDEN_WORDS), rendered
    for table in (w.QUANTIFIER_WORDS, w.CONDITION_WORDS, w.FIXED_REASONS, w.RECORD_WORDS):
        for text in table.values():
            assert not any(w._contains_word(text.lower(), bad) for bad in w.FORBIDDEN_WORDS), text
    with pytest.raises(ValidationError, match="not a result word"):
        w.Result(statement="rule-permits", answer="true", word="proven")


def test_the_three_lines_for_the_engineer():
    result = w.from_engine(
        "rule-permits",
        "does-not-hold",
        cause="rule 10 of LAN-WAN on core1",
        condition="forward",
        quantifier="every",
    )
    assert w.lines(result, subject="tcp/443 from 10.1.1.0/24 to 10.2.2.10", run="1759") == [
        "tcp/443 from 10.1.1.0/24 to 10.2.2.10: blocked by rule 10 of LAN-WAN on core1.",
        "Tested: the forward flow, counts as passing only if every path and member works.",
        "All data on the path is in run 1759.",
    ]
    open_result = w.from_engine(
        "condition-holds",
        "not-established",
        condition="forward",
        missing=[
            w.Missing(code="MODEL_SCOPE_INCOMPLETE", subject="dev:leaf101", detail="policy not collected"),
            w.Missing(code="capacity-not-modelled"),
        ],
    )
    assert w.lines(open_result, subject="Webshop: clients to web")[-1] == (
        "Not decided: dev:leaf101: policy not collected; the capacity condition is declared, not calculated."
    )
    assert w.lines(w.record("stored"), subject="Webshop") == ["Webshop: stored record."]


def test_the_web_table_equals_the_source():
    assert w.WEB_FILE.read_text() == w.typescript(), "run `python -m hst.results.words`"
