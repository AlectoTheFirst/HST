"""The answer envelope, the claim splitter and the citation check.

The per-turn graph pin is stubbed with run 1759, so no test opens a Neo4j
session. The tools are stubs that the adapter calls through the ask budget,
as the provider adapters do.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.app.test_ai_api import _ask_and_wait, _configure
from tests.app.test_ai_conversations_api import _create, _until_finished

from hst.app.agent import base as agent_base
from hst.app.agent.budget import INCOMPLETE_ANSWER
from hst.app.agent.tools import Tool
from hst.app.ai import envelope as envelope_mod
from hst.app.ai import prompt
from hst.app.ai.registry import Principal
from hst.app.routes import ai as ai_routes
from hst.app.store import AiStep
from hst.core.snapshot import Snapshot

NOW = datetime(2026, 9, 1, tzinfo=UTC)
MESSAGE = str(uuid.uuid4())
CONVERSATION = str(uuid.uuid4())


def _claims(markdown: str) -> list[tuple[str, tuple[str, ...]]]:
    return [(markdown[c.start : c.end], c.citations) for c in envelope_mod.split_claims(markdown)]


def _step(
    label: int,
    *,
    run: str | None = "1759",
    is_error: bool = False,
    result: str | None = '{"status": "complete", "verdict": "deny"}',
    summary: str | None = None,
    tool: str = "reach_trace",
) -> AiStep:
    return AiStep(
        id=str(uuid.uuid4()),
        conversation_id=CONVERSATION,
        message_id=MESSAGE,
        label=label,
        tool=tool,
        tool_version=1,
        arguments={},
        is_error=is_error,
        result=result,
        result_sha256="0" * 64,
        result_chars=len(result or ""),
        started_at=NOW,
        elapsed_ms=5,
        result_summary=summary,
        provenance={
            "snapshot": run,
            "degraded": False,
            "manifest_sha256": "ab" * 32,
            "engine": "path",
            "queries": [{"kind": "fixed", "id": "TRACE"}],
        },
    )


def _envelope(
    answer: str,
    steps: list[AiStep],
    earlier: list[AiStep] | None = None,
    *,
    kind: envelope_mod.EnvelopeKind = "answer",
    snapshot: str | None = "1759",
) -> dict[str, Any]:
    return envelope_mod.build_envelope(
        answer,
        message_id=MESSAGE,
        conversation_id=CONVERSATION,
        kind=kind,
        snapshot=snapshot,
        origin="pointer",
        provider="anthropic",
        model_requested="claude-opus-5",
        model_served="claude-opus-5",
        prompt_hash="f" * 64,
        steps=steps,
        earlier=earlier or [],
    )


def _statuses(envelope: dict[str, Any]) -> list[str]:
    return [claim["citation_status"] for claim in envelope["claims"]]


# --- the claim splitter ---------------------------------------------------------------------


def test_the_splitter_reads_sentences_list_items_and_table_rows():
    answer = (
        "Rule 10 on fw1 denies the flow [s1]. The address 10.0.0.1 sits on vlan20 [s2].\n"
        "\n"
        "- fw1 permits tcp/443 [s1, s3]\n"
        "1. sw2 holds no rule\n"
        "\n"
        "| Hop | Device |\n"
        "|---|---|\n"
        "| 1 | fw1 [s1] |"
    )
    assert _claims(answer) == [
        ("Rule 10 on fw1 denies the flow [s1].", ("s1",)),
        ("The address 10.0.0.1 sits on vlan20 [s2].", ("s2",)),
        ("fw1 permits tcp/443 [s1, s3]", ("s1", "s3")),
        ("sw2 holds no rule", ()),
        ("1 | fw1 [s1]", ("s1",)),
    ]


def test_headings_code_blocks_and_lead_ins_are_not_claims():
    answer = (
        "## Verdict [s4]\n"
        "The trace records these hops:\n"
        "```\n"
        "MATCH (n) RETURN n. [s9]\n"
        "```\n"
        "fw1 denies it [s1]."
    )
    assert _claims(answer) == [("fw1 denies it [s1].", ("s1",))]


def test_a_marker_after_the_full_stop_belongs_to_the_sentence_before_it():
    answer = "fw1 denies the flow. [s1][s2]\n[s3] sw2 forwards it! Nothing else."
    assert _claims(answer) == [
        ("fw1 denies the flow. [s1][s2]\n[s3]", ("s1", "s2", "s3")),
        ("sw2 forwards it!", ()),
        ("Nothing else.", ()),
    ]


def test_a_marker_inside_inline_code_is_text():
    assert _claims("The query was `MATCH (n) [s9]. RETURN n` [s1].") == [
        ("The query was `MATCH (n) [s9]. RETURN n` [s1].", ("s1",))
    ]


def test_inline_code_that_wraps_across_a_paragraph_line_is_text():
    answer = "The query was `MATCH (n)\nWHERE n.name = 'fw1'. RETURN n` [s1]. It found fw1 [s2]."
    assert _claims(answer) == [
        ("The query was `MATCH (n)\nWHERE n.name = 'fw1'. RETURN n` [s1].", ("s1",)),
        ("It found fw1 [s2].", ("s2",)),
    ]


def test_addresses_decimals_and_abbreviations_do_not_end_a_sentence():
    answer = "Traffic to 192.168.2.35 uses 1.5 links, e.g. the uplink on fw1.example.net [s1]. Done [s2]."
    assert [citations for _, citations in _claims(answer)] == [("s1",), ("s2",)]


def test_a_claim_span_is_a_code_point_range_of_the_answer():
    answer = "Zone ü is denied [s1]. Rule \U0001f600 is unknown."
    first, second = envelope_mod.split_claims(answer)
    assert answer[first.start : first.end] == "Zone ü is denied [s1]."
    assert answer[second.start : second.end] == "Rule \U0001f600 is unknown."


# --- citation statuses ----------------------------------------------------------------------


def test_a_marker_that_names_no_step_is_citation_invalid():
    trace = _step(1)
    failed = _step(2, is_error=True, result="ValueError: unknown run 3000")
    other = _step(3, run="1760")
    envelope = _envelope(
        "fw1 denies it [s1][s7]. sw2 denies it [s2]. The route exists [s3][s9].",
        [trace, failed, other],
    )
    # an unknown step and an error step make a claim invalid, before any
    # cross-snapshot check
    assert _statuses(envelope) == ["citation-invalid", "citation-invalid", "citation-invalid"]
    assert envelope["grounding"] == {
        "status": "no-evidence",
        "cited": 0,
        "uncited": 0,
        "invalid": 3,
        "cross_snapshot": 0,
        "matched": 0,
        "process": 0,
    }
    assert all(claim["evidence_status"] is None for claim in envelope["claims"])


def test_a_step_on_another_run_is_cross_snapshot():
    envelope = _envelope("fw1 denies it [s1]. The route exists [s2].", [_step(1), _step(2, run="1760")])
    assert _statuses(envelope) == ["cited", "cross-snapshot"]
    assert envelope["snapshot"]["id"] == "1759"
    assert envelope["snapshot"]["others_used"] == ["1760"]
    assert envelope["grounding"]["status"] == "partially-grounded"
    assert envelope["grounding"]["cross_snapshot"] == 1


def test_markers_of_earlier_turns_only_are_prior_turn():
    earlier = _step(1)
    envelope = _envelope("fw1 denies it [s1]. It still does [s1][s2].", [_step(2)], [earlier])
    assert _statuses(envelope) == ["prior-turn", "cited"]
    assert envelope["grounding"]["status"] == "grounded"
    assert envelope["grounding"]["cited"] == 2


def test_a_marker_outside_the_history_window_is_citation_invalid():
    # s1 belongs to a turn folded into the summary, so it is not passed as earlier
    envelope = _envelope("fw1 denies it [s1]. It still does [s2].", [_step(2)])
    assert _statuses(envelope) == ["citation-invalid", "cited"]


def test_a_claim_without_a_marker_is_uncited():
    envelope = _envelope("fw1 denies it [s1]. The graph holds two rulebases.", [_step(1)])
    assert _statuses(envelope) == ["cited", "uncited"]
    assert envelope["grounding"] == {
        "status": "partially-grounded",
        "cited": 1,
        "uncited": 1,
        "invalid": 0,
        "cross_snapshot": 0,
        "matched": 0,
        "process": 0,
    }


def test_an_answer_with_no_tool_call_is_no_evidence():
    assert _envelope("fw1 denies the flow.", [])["grounding"]["status"] == "no-evidence"
    cited = _envelope("fw1 denies the flow [s1].", [], [_step(1)])
    assert _statuses(cited) == ["prior-turn"]
    assert cited["grounding"]["status"] == "no-evidence"
    assert cited["tools_used"] == []


def test_a_declined_or_an_incomplete_answer_carries_no_claims():
    for kind in ("declined", "incomplete"):
        envelope = _envelope("I cannot answer that.", [_step(1)], kind=kind)
        assert envelope["kind"] == kind
        assert envelope["claims"] == []
        assert envelope["grounding"]["status"] == "no-evidence"
    answer = agent_base.AgentAnswer(answer=INCOMPLETE_ANSWER)
    assert envelope_mod.answer_kind(answer) == "incomplete"
    assert envelope_mod.answer_kind(agent_base.AgentAnswer(answer="no", declined=True)) == "declined"


# --- the splitter: section titles, nested items --------------------------------------------


def test_a_section_title_written_as_a_plain_line_is_not_a_claim():
    answer = (
        "What the rule says\n"
        "\n"
        "Rule 10 drops the flow [s1].\n"
        "\n"
        "**Verdict:**\n"
        "- fw1 drops it [s1]\n"
        "**The rule drops the flow.**\n"
        "\n"
        "Rule 10 on fw1 drops it\n"
        "and logs it [s1]."
    )
    # a bold sentence that ends with a full stop is a claim, and a short
    # plain line the paragraph goes on from is the start of a sentence
    assert _claims(answer) == [
        ("Rule 10 drops the flow [s1].", ("s1",)),
        ("fw1 drops it [s1]", ("s1",)),
        ("**The rule drops the flow.**", ()),
        ("Rule 10 on fw1 drops it\nand logs it [s1].", ("s1",)),
    ]


def test_a_short_line_at_the_end_or_before_a_heading_stays_a_claim():
    assert _claims("fw1 drops it [s1].\n\nNo other rule matches") == [
        ("fw1 drops it [s1].", ("s1",)),
        ("No other rule matches", ()),
    ]
    assert _claims("No other rule matches\n\n## Details") == [("No other rule matches", ())]


def test_a_nested_list_item_takes_the_markers_of_its_parent():
    answer = (
        "- Rules of LAN-WAN on core1 [s2]\n"
        "  - rule 10 drops\n"
        "    - logged\n"
        "  - rule 20 accepts [s3]\n"
        "    - for tcp/443\n"
        "- rule 30 rejects\n"
        "\n"
        "Done.\n"
        "  - not nested"
    )
    assert _claims(answer) == [
        ("Rules of LAN-WAN on core1 [s2]", ("s2",)),
        ("rule 10 drops", ("s2",)),
        ("logged", ("s2",)),
        ("rule 20 accepts [s3]", ("s3",)),
        ("for tcp/443", ("s3",)),
        ("rule 30 rejects", ()),
        ("Done.", ()),
        ("not nested", ()),
    ]


# --- matching a claim without a marker to a step result -------------------------------------

_RULE_ROWS = json.dumps(
    {
        "snapshot": {"id": "1759"},
        "provenance": {"tool": "query_cypher"},
        "result": {
            "columns": ["rb.uid", "rb.name", "type(r)", "rule.uid", "rule.position", "rule.action"],
            "data": [
                {
                    "row": [
                        "vyos:core1:fw:LAN-WAN",
                        "LAN-WAN",
                        "HAS_RULE",
                        "vyos:core1:fw:LAN-WAN:10",
                        10,
                        "drop",
                    ]
                },
                {
                    "row": [
                        "vyos:core1:fw:LAN-WAN",
                        "LAN-WAN",
                        "HAS_RULE",
                        "vyos:core1:fw:LAN-WAN:20",
                        20,
                        "accept",
                    ]
                },
            ],
            "truncated": False,
            "pinned": True,
        },
    }
)


def test_a_claim_without_a_marker_is_matched_to_the_row_that_holds_it():
    rows = _step(2, tool="query_cypher", result=_RULE_ROWS)
    envelope = _envelope(
        "LAN-WAN rule 10 on core1 is a drop rule. Rule 20 of LAN-WAN on core1 accepts it.",
        [_step(1, tool="snapshot_list", result='{"runs": [1759]}'), rows],
    )
    first, second = envelope["claims"]
    assert (first["citation_status"], first["citations"]) == ("matched", [])
    assert first["support"] == [{"step": "s2", "pointer": "/result/data/0"}]
    assert second["support"] == [{"step": "s2", "pointer": "/result/data/1"}]
    assert envelope["grounding"] == {
        "status": "grounded",
        "cited": 0,
        "uncited": 0,
        "invalid": 0,
        "cross_snapshot": 0,
        "matched": 2,
        "process": 0,
    }
    # the matched step is linked as a cited one is
    assert envelope["links"] == [{"kind": "step", "ref_id": rows.id, "ref_revision": None, "step": "s2"}]
    assert envelope_mod.AnswerEnvelope.model_validate(envelope)


def test_a_claim_is_not_matched_on_a_common_word_or_half_of_what_it_names():
    rows = _step(1, tool="query_cypher", result=_RULE_ROWS)
    envelope = _envelope(
        "The firewall drops traffic it does not permit. "  # value words, no identifier
        "Rule 10 is a drop rule. "  # a number and a value word, no identifier
        "LAN-WAN rule 10 on core2 is a drop rule. "  # core2 is in no row
        "LAN-WAN holds many rules. "  # one identifier and no value
        "LAN-WAN rule 30 on core1 rejects it. "  # neither 30 nor reject is in a row
        "Rule 10 of LAN-WAN on core1 accepts it. "  # 10 and accept are in two rows
        "Rule 20 of LAN-WAN on core1 accepts it.",
        [rows],
    )
    assert _statuses(envelope) == ["uncited"] * 6 + ["matched"]
    assert [claim["support"] for claim in envelope["claims"]][-2:] == [
        [],
        [{"step": "s1", "pointer": "/result/data/1"}],
    ]
    assert envelope["grounding"]["status"] == "partially-grounded"


def test_a_claim_is_matched_to_the_object_that_holds_it():
    result = json.dumps(
        {
            "snapshot": {"id": "1759"},
            "provenance": {"tool": "inventory_get"},
            "result": {
                "kind": "device",
                "device": {"uid": "dev:SN1", "hostname": "core1.example.net"},
                "interfaces": [
                    {"name": "eth0", "address": "10.0.0.1/24", "vlan": "vlan20"},
                    {"name": "eth1", "address": "10.0.1.1/24", "vlan": "vlan30"},
                ],
            },
        }
    )
    envelope = _envelope(
        "The address 10.0.0.1/24 sits on vlan20. eth1 is in vlan20.", [_step(1, result=result)]
    )
    # two identifiers in one object are a relation; eth1 and vlan20 are in two
    assert _statuses(envelope) == ["matched", "uncited"]
    assert envelope["claims"][0]["support"] == [{"step": "s1", "pointer": "/result/interfaces/0"}]


def test_after_compaction_a_claim_is_matched_to_the_result_summary():
    compacted = _step(1, result=None, summary="status=complete; verdict=deny; snapshot=1759; items: fw1, fw2")
    envelope = _envelope("fw1 would deny the flow. fw3 would deny it.", [compacted])
    assert _statuses(envelope) == ["matched", "uncited"]
    assert envelope["claims"][0]["support"] == [{"step": "s1", "pointer": None}]
    assert envelope["claims"][0]["evidence_status"] == "deny"


def test_an_error_step_or_an_earlier_turn_is_never_matched():
    failed = _step(2, is_error=True, result="ToolError: LAN-WAN rule 10 on core1 drop")
    earlier = _step(1, tool="query_cypher", result=_RULE_ROWS)
    envelope = _envelope("LAN-WAN rule 10 on core1 is a drop rule.", [failed], [earlier])
    assert _statuses(envelope) == ["uncited"]
    assert envelope["claims"][0]["support"] == []


def test_a_cited_claim_records_the_rows_of_its_steps_that_hold_it():
    envelope = _envelope(
        "LAN-WAN rule 10 on core1 drops it [s1]. The rulebase has two rules [s1].",
        [_step(1, tool="query_cypher", result=_RULE_ROWS)],
    )
    assert _statuses(envelope) == ["cited", "cited"]
    assert [claim["support"] for claim in envelope["claims"]] == [
        [{"step": "s1", "pointer": "/result/data/0"}],
        [],
    ]


def test_a_statement_of_the_assistants_own_process_is_process():
    envelope = _envelope(
        "I traced only 192.168.2.45. I did not check the NAT rules. I've read run 1759 [s1]. "
        "Ignoring the reply direction, fw1 denies it.",
        [_step(1)],
    )
    assert _statuses(envelope) == ["process", "process", "cited", "uncited"]
    assert envelope["claims"][0]["evidence_status"] is None
    # a process claim counts neither way
    assert envelope["grounding"]["process"] == 2
    assert envelope["grounding"]["status"] == "partially-grounded"
    grounded = _envelope("I traced the flow. fw1 denies it [s1].", [_step(1)])
    assert grounded["grounding"]["status"] == "grounded"
    assert _envelope("I traced the flow.", [_step(1)])["grounding"]["status"] == "no-evidence"


# --- the vocabulary check -------------------------------------------------------------------


def test_the_evidence_status_is_a_vocabulary_word_the_cited_result_holds():
    step = _step(1, result=json.dumps({"verdict": "deny", "passes": [], "note": "blocked outage"}))
    envelope = _envelope(
        "fw1 would Deny the flow [s1]. The passes bucket is empty [s1]. "
        "The flow is blocked [s1]. The flow is removed [s1].",
        [step],
    )
    # the result holds deny as a value and passes as a key; blocked appears
    # only inside a longer string
    assert [claim["evidence_status"] for claim in envelope["claims"]] == ["deny", "passes", None, None]


def test_after_compaction_the_vocabulary_check_uses_the_result_summary():
    compacted = _step(1, result=None, summary="status=complete; snapshot=1759; evidence=passes")
    envelope = _envelope("The flow set passes [s1]. The flow set is removed [s1].", [], [compacted])
    assert [claim["evidence_status"] for claim in envelope["claims"]] == ["passes", None]


def test_an_uncited_claim_has_no_evidence_status():
    envelope = _envelope("fw1 would deny the flow.", [_step(1)])
    assert envelope["claims"][0]["evidence_status"] is None


# --- the envelope ---------------------------------------------------------------------------


def test_the_envelope_matches_the_schema_and_names_the_steps():
    trace, other = _step(1), _step(2, run="1760")
    envelope = _envelope("fw1 would deny the flow [s1]. The route exists [s2]. Nothing else.", [trace, other])
    assert envelope_mod.AnswerEnvelope.model_validate(envelope)
    schema = envelope_mod.schema()
    assert schema["$id"] == "strata/ai/answer-envelope/v2"
    assert set(schema["required"]) == {
        "version",
        "message_id",
        "conversation_id",
        "kind",
        "snapshot",
        "model",
        "prompt_hash",
        "tools_used",
        "answer_markdown",
        "claims",
        "grounding",
    }
    assert envelope["snapshot"] == {
        "id": "1759",
        "origin": "pointer",
        "manifest_sha256": "ab" * 32,
        "degraded": False,
        "others_used": ["1760"],
    }
    assert envelope["tools_used"][0] == {
        "step": "s1",
        "step_id": trace.id,
        "tool": "reach_trace",
        "version": 1,
        "is_error": False,
        "snapshot": "1759",
        "engine": "path",
        "queries": [{"kind": "fixed", "id": "TRACE"}],
    }
    assert envelope["links"] == [
        {"kind": "step", "ref_id": trace.id, "ref_revision": None, "step": "s1"},
        {"kind": "step", "ref_id": other.id, "ref_revision": None, "step": "s2"},
    ]
    assert envelope["answer_markdown"].startswith("fw1 would deny")
    assert [claim["span"] for claim in envelope["claims"]] == [[0, 29], [30, 52], [53, 66]]


def test_the_links_name_the_stored_objects_the_steps_read():
    def catalogue(result: dict[str, Any]) -> str:
        return json.dumps({"result": result})

    finding = _step(
        1,
        tool="assessment_read",
        result=catalogue(
            {
                "mode": "finding",
                "run": {"id": "run-1", "assessment_id": "a-1", "assessment_revision": 3},
                "finding": {"reference": "finding:@1"},
            }
        ),
    )
    simulation = _step(2, tool="change_get_simulation", result=catalogue({"session_id": "sess-1"}))
    session = _step(
        3, tool="assessment_read", result=catalogue({"mode": "analysis_session", "session": {"id": "sess-1"}})
    )
    buckets = replace(
        _step(4, tool="assessment_read", result=catalogue({"mode": "findings"})),
        arguments={"assessment_id": "a-1", "run_id": "run-1"},
    )
    failed = _step(5, tool="assessment_read", is_error=True, result="ToolError: no run")

    envelope = _envelope("The finding holds [s1].", [finding, simulation, session, buckets, failed])

    assert envelope["links"] == [
        {"kind": "step", "ref_id": finding.id, "ref_revision": None, "step": "s1"},
        {"kind": "assessment", "ref_id": "a-1", "ref_revision": 3, "step": "s1"},
        {"kind": "assessment_run", "ref_id": "run-1", "ref_revision": None, "step": "s1"},
        {"kind": "finding", "ref_id": "finding:@1", "ref_revision": None, "step": "s1"},
        {"kind": "analysis_session", "ref_id": "sess-1", "ref_revision": None, "step": "s2"},
        {"kind": "assessment", "ref_id": "a-1", "ref_revision": None, "step": "s4"},
    ]


def test_every_new_run_or_finding_link_comes_with_the_assessment_and_run_of_its_step():
    def read(label: int, mode: str, run: str, finding: str | None = None) -> AiStep:
        result: dict[str, Any] = {
            "mode": mode,
            "run": {"id": run, "assessment_id": "a-1", "assessment_revision": 3},
        }
        if finding is not None:
            result["finding"] = {"reference": finding}
        return _step(label, tool="assessment_read", result=json.dumps({"result": result}))

    steps = [
        read(1, "finding", "run-1", "finding:@0"),
        read(2, "finding", "run-1", "finding:@1"),
        read(3, "finding", "run-2", "finding:@0"),
        read(4, "run", "run-2"),
        read(5, "run", "run-3"),
        read(6, "finding", "run-1", "finding:@1"),
    ]

    envelope = _envelope("The findings hold.", steps)

    def link(kind: str, ref_id: str, step: str) -> dict[str, Any]:
        return {
            "kind": kind,
            "ref_id": ref_id,
            "ref_revision": 3 if kind == "assessment" else None,
            "step": step,
        }

    assert envelope["links"] == [
        link("assessment", "a-1", "s1"),
        link("assessment_run", "run-1", "s1"),
        link("finding", "finding:@0", "s1"),
        # a second finding of the same run
        link("assessment", "a-1", "s2"),
        link("assessment_run", "run-1", "s2"),
        link("finding", "finding:@1", "s2"),
        # the entry at the same position of another run
        link("assessment", "a-1", "s3"),
        link("assessment_run", "run-2", "s3"),
        link("finding", "finding:@0", "s3"),
        # a second run of the same assessment; s4 and s6 name nothing new
        link("assessment", "a-1", "s5"),
        link("assessment_run", "run-3", "s5"),
    ]


def test_the_stored_envelope_is_returned_without_its_payload():
    stored = {**_envelope("fw1 denies it [s1].", [_step(1)]), "payload": {"declined": False}}
    public = envelope_mod.stored_answer(stored)
    assert public is not None
    assert "payload" not in public
    assert public["version"] == 2
    assert envelope_mod.stored_answer({"payload": {"answer": "Text"}}) is None
    assert envelope_mod.stored_answer(None) is None


# --- the citation rule ----------------------------------------------------------------------


def test_the_conversational_base_layer_carries_the_citation_rule():
    assert prompt.CITATION_RULE in prompt.BASE_CONVERSATIONAL
    assert prompt.CITATION_RULE not in prompt.BASE_STRUCTURED
    assembled = prompt.assemble("changesim", prompt.SiteInstructions(), [], Principal.for_role("viewer"))
    assert prompt.CITATION_RULE in assembled.system
    assert "[s3]" in prompt.CITATION_RULE


# --- the routes -----------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _pinned(monkeypatch):
    async def pinned(settings, requested):
        return Snapshot(1759, settings)

    monkeypatch.setattr(ai_routes, "_pin_turn", pinned)


def _catalogue_result(run: str) -> str:
    return json.dumps(
        {
            "snapshot": {"id": run, "run": {"degraded": True}, "manifest_sha256": "cd" * 32},
            "provenance": {
                "tool": "reach_trace",
                "engine": "path",
                "queries": [{"kind": "fixed", "id": "T"}],
            },
            "evidence": {"status": "proven"},
            "page": {"truncated": False},
            "result": {"status": "complete", "verdict": "deny"},
        }
    )


def _returning(text: str):
    return lambda **kwargs: text


class _Answers:
    """Answers each turn with the next text. A turn whose entry names runs
    first calls `reach_trace` once per run. A call with no tools is the
    summary update."""

    def __init__(self, turns: list[tuple[list[str], str]]) -> None:
        self.turns = list(turns)

    def ask(self, question, *, budget, on_step, **kwargs):
        if not kwargs.get("tools"):
            return agent_base.AgentAnswer(answer="the summary")
        runs, answer = self.turns.pop(0)
        steps = []
        for run in runs:
            tool = Tool("reach_trace", "", {}, "graph.read", _returning(_catalogue_result(run)))
            step = budget.invoke([tool], "reach_trace", {"mode": "path"})
            on_step(step)
            steps.append(step)
        return agent_base.AgentAnswer(answer=answer, steps=steps, provider="anthropic")


async def _turn(client, conversation_id: str, question: str) -> dict[str, Any]:
    r = await client.post(f"/api/ai/conversations/{conversation_id}/messages", json={"question": question})
    assert r.status_code == 202, r.text
    return await _until_finished(client, r.json()["message_id"])


async def test_a_turn_stores_its_answer_envelope_and_the_poll_returns_it(client, seeded, monkeypatch):
    answer = "fw1 would deny the flow [s1]. The graph holds two rulebases."
    await _configure(client, monkeypatch, _Answers([(["1759"], answer)]))
    conversation = await _create(client)

    polled = await _turn(client, conversation["id"], "is it denied?")

    assert polled["status"] == "done"
    assert polled["answer"] == answer
    envelope = polled["envelope"]
    assert "payload" not in envelope
    assert (envelope["message_id"], envelope["conversation_id"]) == (polled["message_id"], conversation["id"])
    assert (envelope["kind"], envelope["snapshot"]["id"], envelope["snapshot"]["origin"]) == (
        "answer",
        "1759",
        "pointer",
    )
    assert (envelope["snapshot"]["degraded"], envelope["snapshot"]["manifest_sha256"]) == (True, "cd" * 32)
    assert envelope["prompt_hash"] == polled["prompt_hash"]
    assert envelope["model"]["provider"] == "anthropic"
    [used] = envelope["tools_used"]
    assert (used["step"], used["step_id"], used["snapshot"], used["engine"]) == (
        "s1",
        polled["steps"][0]["id"],
        "1759",
        "path",
    )
    assert [c["citation_status"] for c in envelope["claims"]] == ["cited", "uncited"]
    assert envelope["claims"][0]["evidence_status"] == "deny"
    assert envelope["grounding"]["status"] == "partially-grounded"

    # the row holds the envelope beside the poll fields, and the step its provenance
    user = await seeded.get_user_by_username("ada")
    message = await seeded.get_message(user.id, polled["message_id"])
    assert message.envelope["version"] == 2
    assert message.envelope["payload"]["prompt_hash"] == polled["prompt_hash"]
    [step] = seeded.ai_steps.values()
    assert step.provenance["snapshot"] == "1759"
    assert step.provenance["queries"] == [{"kind": "fixed", "id": "T"}]


async def test_a_later_turn_may_cite_a_step_of_an_earlier_turn(client, seeded, monkeypatch):
    await _configure(
        client,
        monkeypatch,
        _Answers([(["1759"], "fw1 would deny the flow [s1]."), ([], "As before, fw1 would deny it [s1].")]),
    )
    conversation = await _create(client)
    first = await _turn(client, conversation["id"], "is it denied?")
    second = await _turn(client, conversation["id"], "still?")

    envelope = second["envelope"]
    assert [c["citation_status"] for c in envelope["claims"]] == ["prior-turn"]
    # the turn called no tool
    assert envelope["grounding"]["status"] == "no-evidence"
    assert envelope["links"] == [
        {"kind": "step", "ref_id": first["steps"][0]["id"], "ref_revision": None, "step": "s1"}
    ]


async def test_a_step_on_another_run_makes_its_claim_cross_snapshot(client, monkeypatch):
    answer = "fw1 would deny the flow [s1]. The route exists [s2]."
    await _configure(client, monkeypatch, _Answers([(["1759", "1760"], answer)]))
    conversation = await _create(client)

    envelope = (await _turn(client, conversation["id"], "is it denied?"))["envelope"]

    assert [c["citation_status"] for c in envelope["claims"]] == ["cited", "cross-snapshot"]
    assert envelope["snapshot"]["others_used"] == ["1760"]


async def test_an_ask_turn_stores_its_envelope_and_its_poll_keeps_its_fields(client, seeded, monkeypatch):
    await _configure(client, monkeypatch, _Answers([([], "fw1 would deny the flow.")]))

    result = await _ask_and_wait(client, {"question": "is it denied?"})

    assert result["status"] == "done"
    assert result["answer"] == "fw1 would deny the flow."
    assert "envelope" not in result
    user = await seeded.get_user_by_username("ada")
    [message] = [m for m in seeded.ai_messages.values() if m.role == "assistant"]
    envelope = envelope_mod.stored_answer((await seeded.get_message(user.id, message.id)).envelope)
    assert envelope is not None
    assert envelope["kind"] == "answer"
    assert [c["citation_status"] for c in envelope["claims"]] == ["uncited"]
    assert envelope["grounding"]["status"] == "no-evidence"
    assert envelope["snapshot"] == {
        "id": "1759",
        "origin": "pointer",
        "manifest_sha256": None,
        "degraded": None,
        "others_used": [],
    }


async def test_a_turn_whose_envelope_cannot_be_built_keeps_its_answer(client, monkeypatch):
    def broken(*args, **kwargs):
        raise ValueError("no envelope")

    monkeypatch.setattr(envelope_mod, "build_envelope", broken)
    await _configure(client, monkeypatch, _Answers([(["1759"], "fw1 would deny the flow [s1].")]))
    conversation = await _create(client)

    polled = await _turn(client, conversation["id"], "is it denied?")

    assert (polled["status"], polled["answer"], polled["envelope"]) == (
        "done",
        "fw1 would deny the flow [s1].",
        None,
    )


async def test_the_conversation_read_returns_the_stored_envelope(client, monkeypatch):
    await _configure(client, monkeypatch, _Answers([(["1759"], "fw1 would deny the flow [s1].")]))
    conversation = await _create(client)
    polled = await _turn(client, conversation["id"], "is it denied?")

    detail = (await client.get(f"/api/ai/conversations/{conversation['id']}")).json()
    stored = detail["messages"][1]["envelope"]
    assert stored["version"] == 2
    assert stored["claims"] == polled["envelope"]["claims"]
    assert stored["payload"]["declined"] is False
