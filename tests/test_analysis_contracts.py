from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from hst.analysis.contracts import (
    AnalysisInput,
    AnalysisSession,
    ConnectionAnalysisInput,
    SnapshotReference,
    adapt_legacy_assessment,
)
from hst.assessment.models import Definition

SNAPSHOT = {
    "snapshot": "1700000000000",
    "manifest_sha256": "fixture-manifest",
    "estate": "fixture",
}
REQUEST = {
    "name": "Clients to frontend",
    "destination": "frontend",
    "sources": ["192.0.2.0/24"],
    "members": [{"name": "frontend", "addresses": ["198.51.100.10"]}],
    "condition": {"kind": "member", "member": "frontend"},
    "proto": "tcp",
    "port": "443",
    "success": "session",
}
OPEN_RESULT = {
    "kind": "result",
    "statement": "condition-holds",
    "answer": "open",
    "word": "not decided",
    "missing": [{"code": "not-decided", "detail": "routing evidence for dev:r1"}],
}


def application_connection(identifier: str, service: str = "checkout-frontend") -> dict:
    return {
        "id": identifier,
        "name": identifier.replace("-", " "),
        "source": {
            "kind": "application_connection",
            "reference": {
                "application": {"id": "checkout-production", "revision": 4, "digest": "app-v4"},
                "service_id": service,
                "connection_id": identifier,
            },
            "request": REQUEST,
            "resolved_scope_digest": f"scope-{identifier}",
        },
    }


def test_connection_contract_groups_explicit_service_connections_without_implied_edges():
    value = TypeAdapter(AnalysisInput).validate_python(
        {
            "kind": "connection",
            "snapshot": SNAPSHOT,
            "connections": [
                application_connection("clients-to-frontend"),
                application_connection("frontend-to-api"),
            ],
            "changes": [],
            "mode": "possible",
        }
    )
    assert isinstance(value, ConnectionAnalysisInput)
    assert [item.source.reference.service_id for item in value.connections] == [
        "checkout-frontend",
        "checkout-frontend",
    ]
    assert [item.id for item in value.connections] == ["clients-to-frontend", "frontend-to-api"]


def test_application_connection_requires_explicit_service_association():
    connection = application_connection("clients-to-frontend")
    del connection["source"]["reference"]["service_id"]
    with pytest.raises(ValidationError, match="service_id"):
        TypeAdapter(AnalysisInput).validate_python(
            {
                "kind": "connection",
                "snapshot": SNAPSHOT,
                "connections": [connection],
            }
        )


def test_change_only_simulation_needs_no_service_or_traffic_scope():
    value = TypeAdapter(AnalysisInput).validate_python(
        {
            "kind": "simulation",
            "snapshot": SNAPSHOT,
            "changes": [{"kind": "fw_rule.modify", "params": {"rule_uid": "rule-7"}}],
        }
    )
    assert value.kind == "simulation"
    assert value.scope is None
    assert value.protected == []
    assert value.model_dump()["changes"][0]["kind"] == "fw_rule.modify"


def test_input_discriminator_does_not_make_legacy_definition_nullable():
    with pytest.raises(ValidationError, match="State exactly one request or graph requirement"):
        Definition()
    with pytest.raises(ValidationError):
        TypeAdapter(AnalysisInput).validate_python(
            {"kind": "simulation", "snapshot": SNAPSHOT, "changes": []}
        )


def test_legacy_adapter_preserves_order_and_does_not_infer_catalog_ownership():
    definition = Definition(
        request=REQUEST,
        snapshot=SNAPSHOT["snapshot"],
        intents=[
            {"kind": "fw_rule.add", "params": {"rule_uid": "first"}},
            {"kind": "fw_rule.remove", "params": {"rule_uid": "second"}},
        ],
    )
    value = adapt_legacy_assessment(
        assessment_id="assessment-1",
        assessment_revision=3,
        title="Clients to frontend",
        definition=definition,
        snapshot=SnapshotReference.model_validate(SNAPSHOT),
    )
    assert value.input.kind == "connection"
    assert value.input.connections[0].source.kind == "inline"
    assert [change.params["rule_uid"] for change in value.input.changes] == ["first", "second"]
    assert value.legacy_assessment.assessment_id == "assessment-1"
    assert "application" not in value.model_dump_json()
    assert "service" not in value.model_dump_json()


def test_legacy_adapter_distinguishes_graph_and_saved_requirements():
    snapshot = SnapshotReference.model_validate(SNAPSHOT)
    graph = adapt_legacy_assessment(
        assessment_id="graph-assessment",
        assessment_revision=1,
        title="Graph service",
        definition=Definition(requirement="requirement:graph-service"),
        snapshot=snapshot,
    )
    saved = adapt_legacy_assessment(
        assessment_id="saved-assessment",
        assessment_revision=2,
        title="Saved service",
        definition=Definition(
            request=REQUEST,
            requirement_id="saved-requirement",
            requirement_revision=3,
        ),
        snapshot=snapshot,
    )
    assert graph.input.connections[0].source.kind == "graph_requirement"
    assert graph.input.connections[0].source.requirement_uid == "requirement:graph-service"
    assert saved.input.connections[0].source.kind == "saved_requirement"
    assert saved.input.connections[0].source.requirement.revision == 3


def test_session_keeps_execution_outcome_and_coverage_distinct():
    session = AnalysisSession.model_validate(
        {
            "schema_version": 1,
            "id": "analysis-1",
            "revision": 1,
            "title": "Checkout connections",
            "input": {
                "kind": "connection",
                "snapshot": SNAPSHOT,
                "connections": [application_connection("clients-to-frontend")],
            },
            "runs": [
                {
                    "id": "run-1",
                    "item_id": "clients-to-frontend",
                    "execution": "completed",
                    "result": OPEN_RESULT,
                    "coverage": "partial",
                    "result_ref": "run:run-1",
                }
            ],
        }
    )
    assert session.runs[0].execution == "completed"
    assert session.runs[0].result == OPEN_RESULT
    assert session.runs[0].coverage == "partial"
    with pytest.raises(ValidationError, match="only a completed run may state a result"):
        session.runs[0].model_validate(
            {
                "id": "run-2",
                "item_id": "clients-to-frontend",
                "execution": "failed",
                "result": OPEN_RESULT,
                "coverage": "partial",
            }
        )


def test_session_rejects_duplicate_or_unrelated_run_identities():
    base = {
        "schema_version": 1,
        "id": "analysis-1",
        "revision": 1,
        "title": "Checkout connections",
        "input": {
            "kind": "connection",
            "snapshot": SNAPSHOT,
            "connections": [application_connection("clients-to-frontend")],
        },
    }
    with pytest.raises(ValidationError, match="input item"):
        AnalysisSession.model_validate(
            {
                **base,
                "runs": [{"id": "run-1", "item_id": "other", "execution": "failed", "coverage": "partial"}],
            }
        )
