"""Draft assistance cannot turn provider guesses into graph identities or actions."""

from copy import deepcopy

import pytest
from pydantic import ValidationError

from hst.assessment.assistant import DraftBody, IntentPlan, parse_plan, prepare_draft

REQUEST = {
    "name": "Checkout",
    "destination": "API",
    "sources": ["10.0.0.0/24"],
    "members": [
        {
            "name": "api",
            "addresses": ["192.0.2.10"],
            "proto": "tcp",
            "port": "443",
            "source_port": "1024-65535",
        }
    ],
    "condition": {"kind": "member", "member": "api"},
    "success": "session",
    "source_context": "context-1",
    "source_device_uid": "source-device",
}
SERVICE = {
    "kind": "service",
    "uid": "service-1",
    "name": "Checkout",
    "selectable": True,
    "definition": REQUEST,
}
LINK = {
    "kind": "link",
    "uid": "link-1",
    "name": "Frankfurt uplink",
    "selectable": True,
    "interfaces": ["interface-a", "interface-b"],
}


def searcher(items, *, snapshot="1000", truncated=False):
    def search(**kw):
        selected = [
            deepcopy(v)
            for v in items
            if v["kind"] == kw["kind"] and (not kw.get("uid") or v["uid"] == kw["uid"])
        ]
        return {"snapshot": snapshot, "items": selected, "truncated": truncated}

    return search


def plan(kind="resilience"):
    return IntentPlan(
        title="Frankfurt continuity", kind=kind, searches=[{"kind": "link", "query": "Frankfurt uplink"}]
    )


def test_no_match_is_selected_even_if_only_one_exists():
    result = prepare_draft(
        DraftBody(snapshot="1000", question="Can we survive losing Frankfurt?"),
        plan(),
        searcher([SERVICE, LINK]),
    )
    assert len(result["candidates"]) == 2
    assert result["selections"] == []
    assert result["ready"] is False
    assert result["definition"] is None
    assert result["analysis"]["targets"] == []


def test_explicit_selection_preserves_exact_service_and_resolved_link_endpoints():
    body = DraftBody(
        snapshot="1000",
        question="Can checkout survive?",
        selections=[{"kind": "service", "uid": "service-1"}, {"kind": "link", "uid": "link-1"}],
    )
    result = prepare_draft(body, plan(), searcher([SERVICE, LINK]))
    assert result["ready"] and result["analysis_valid"]
    assert result["definition"]["request"]["source_context"] == "context-1"
    assert result["definition"]["request"]["members"][0]["source_port"] == "1024-65535"
    assert result["definition"]["request"]["success"] == "session"
    assert result["definition"]["intents"] == []
    assert result["analysis"]["targets"][0]["interfaces"] == ["interface-a", "interface-b"]
    assert result["snapshot"] == "1000"


@pytest.mark.parametrize(
    "field,value",
    [("definition", {}), ("targets", [{"uid": "invented"}]), ("intents", [{"kind": "fw_rule.remove"}])],
)
def test_model_cannot_supply_definition_or_executable_fields(field, value):
    import json

    with pytest.raises(ValidationError):
        parse_plan(json.dumps({"title": "Unsafe", "kind": "repair", field: value}))


def test_unknown_or_disabled_identity_is_not_accepted():
    disabled = {**SERVICE, "selectable": False}
    body = DraftBody(snapshot="1000", question="Test", selections=[{"kind": "service", "uid": "service-1"}])
    result = prepare_draft(body, plan(), searcher([disabled]))
    assert result["ready"] is False
    assert any("unavailable" in q for q in result["questions"])


def test_multiple_services_require_clarification_not_first_match():
    other = {**SERVICE, "uid": "service-2"}
    body = DraftBody(
        snapshot="1000",
        question="Test",
        selections=[{"kind": "service", "uid": "service-1"}, {"kind": "service", "uid": "service-2"}],
    )
    result = prepare_draft(body, plan(), searcher([SERVICE, other]))
    assert result["definition"] is None
    assert any("exactly one" in q for q in result["questions"])


def test_rulebase_owner_is_explicit_and_revalidated():
    rb = {
        "kind": "rulebase",
        "uid": "rb-1",
        "name": "Edge",
        "selectable": True,
        "devices": [{"uid": "d-1", "name": "Paris"}, {"uid": "d-2", "name": "Frankfurt"}],
    }
    for owner, expected in [(None, {}), ("invented", {}), ("d-2", {"rb-1": "d-2"})]:
        body = DraftBody(
            snapshot="1000",
            question="Repair",
            selections=[
                {"kind": "service", "uid": "service-1"},
                {"kind": "rulebase", "uid": "rb-1", "device_uid": owner},
            ],
        )
        result = prepare_draft(body, plan("repair"), searcher([SERVICE, rb]))
        assert result["analysis"]["allowed_targets"] == expected
        assert "scope" not in result["analysis"]


def test_resolution_cannot_drift_to_a_different_snapshot():
    count = 0

    def search(**kw):
        nonlocal count
        count += 1
        return searcher([SERVICE, LINK], snapshot=str(count * 1000))(**kw)

    body = DraftBody(snapshot="1000", question="Test", selections=[{"kind": "service", "uid": "service-1"}])
    with pytest.raises(ValueError, match="Snapshot changed"):
        prepare_draft(body, plan(), search)


def test_truncation_is_visible_and_verification_requires_existing_deployment():
    body = DraftBody(snapshot="1000", question="Verify", selections=[{"kind": "service", "uid": "service-1"}])
    result = prepare_draft(body, plan("verify"), searcher([SERVICE], truncated=True))
    assert result["truncated"]
    assert not result["ready"]
    assert any("deployment record" in q for q in result["questions"])


def test_selected_domain_identity_is_carried_to_guided_member_review():
    domain = {
        "kind": "domain",
        "uid": "domain-1",
        "name": "Frankfurt power",
        "selectable": True,
        "members": [{"uid": "link-1", "kind": "link", "name": "Frankfurt uplink"}],
        "source": "observed-source",
        "provenance_validated": False,
    }
    body = DraftBody(
        snapshot="1000",
        question="Test power loss",
        selections=[{"kind": "service", "uid": "service-1"}, {"kind": "domain", "uid": "domain-1"}],
    )
    result = prepare_draft(body, plan(), searcher([SERVICE, domain]))
    assert result["analysis"]["domains"] == [{"uid": "domain-1"}]
    assert result["ready"]
    assert not result["analysis_valid"]
    assert any("provenance" in q for q in result["questions"])
    assert result["definition"]["origin_requirement"] == "service-1"


def test_symptom_clues_are_separate_search_inputs_and_missing_evidence_is_a_question():
    calls = []

    def search(**kwargs):
        calls.append(kwargs)
        return {
            "snapshot": "1000",
            "items": [],
            "questions": ["No recorded DNS address. Supply the destination IP."],
            "truncated": False,
        }

    intent = IntentPlan(
        title="Checkout from Berlin",
        kind="troubleshoot",
        searches=[
            {
                "kind": "service",
                "destination": "https://shop.example/checkout",
                "client": "10.0.0.8",
                "location": "Berlin",
                "application": "checkout",
            }
        ],
    )
    result = prepare_draft(DraftBody(snapshot="1000", question="Checkout fails from Berlin"), intent, search)
    assert calls == [
        {
            "kind": "service",
            "q": "",
            "limit": 30,
            "destination": "https://shop.example/checkout",
            "client": "10.0.0.8",
            "location": "Berlin",
            "application": "checkout",
        }
    ]
    assert result["clues"][0]["destination"] == "https://shop.example/checkout"
    assert "No recorded DNS address. Supply the destination IP." in result["questions"]
    assert result["definition"] is None and not result["ready"]


def test_destination_match_requires_explicit_service_selection():
    intent = IntentPlan(
        title="Unknown service",
        kind="evaluate",
        searches=[
            {
                "kind": "service",
                "destination": "192.0.2.10",
                "client": "10.0.0.8",
            }
        ],
    )
    result = prepare_draft(
        DraftBody(snapshot="1000", question="This destination fails"), intent, searcher([SERVICE])
    )
    assert result["candidates"] == [SERVICE]
    assert not result["ready"] and result["selections"] == []
    assert result["definition"] is None


def test_traffic_clues_cannot_be_attached_to_a_non_service_search():
    with pytest.raises(ValidationError, match="service search"):
        IntentPlan(
            title="Invalid",
            kind="evaluate",
            searches=[
                {
                    "kind": "device",
                    "destination": "192.0.2.10",
                }
            ],
        )


def test_saved_service_selection_preserves_the_revision_and_disambiguates_origin():
    from hst.assessment.models import Definition

    exact = Definition.model_validate({"request": REQUEST}).model_dump(mode="json")["request"]
    saved = {
        **SERVICE,
        "origin": "saved",
        "requirement_id": "service-1",
        "requirement_revision": 3,
        "definition": exact,
    }
    intent = IntentPlan(title="Saved service", kind="evaluate")
    body = DraftBody(
        snapshot="1000",
        question="Check this destination",
        selections=[
            {
                "kind": "service",
                "uid": "service-1",
                "origin": "saved",
                "requirement_revision": 3,
            }
        ],
    )
    result = prepare_draft(body, intent, searcher([SERVICE, saved]))
    assert result["ready"]
    assert len(result["candidates"]) == 2
    assert result["definition"]["request"] == exact
    assert result["definition"]["requirement_id"] == "service-1"
    assert result["definition"]["requirement_revision"] == 3
    assert result["definition"]["origin_requirement"] is None
    unavailable = prepare_draft(body, intent, searcher([{**saved, "requirement_revision": 4}]))
    assert not unavailable["ready"]
