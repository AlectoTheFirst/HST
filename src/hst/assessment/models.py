"""Versioned HTTP/worker inputs for durable assessments."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from hst.assessment.evaluation import RequestBody, _request_from_body


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Definition(StrictModel):
    request: RequestBody | None = None
    requirement: str | None = None
    intents: list[dict] = Field(default_factory=list, max_length=50)
    mode: Literal["possible", "guaranteed"] = "possible"
    snapshot: str | None = None
    freshness_s: int = Field(default=3600, ge=60, le=31_536_000)
    priority: int = Field(default=1, ge=1, le=100)
    requirement_id: str | None = None
    requirement_revision: int | None = None
    change_id: str | None = None
    change_revision: int | None = None
    origin_requirement: str | None = None
    origin_snapshot: str | None = None
    deployments: list[dict] = Field(default_factory=list, max_length=200)
    collection_actions: list[dict] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def valid_request(self) -> Definition:
        if (self.request is None) == (self.requirement is None):
            raise ValueError("State exactly one request or graph requirement.")
        if self.request is not None and self.request.sources:
            _request_from_body(self.request)
        if (self.requirement_id is None) != (self.requirement_revision is None):
            raise ValueError("A saved requirement reference needs both its ID and revision.")
        if self.requirement_revision is not None and self.requirement_revision < 1:
            raise ValueError("Requirement revision must be positive.")
        if (self.change_id is None) != (self.change_revision is None):
            raise ValueError("A saved change reference needs both its ID and revision.")
        if self.change_revision is not None and self.change_revision < 1:
            raise ValueError("Change revision must be positive.")
        return self


class CreateAssessment(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    purpose: str = Field(default="evaluation", max_length=100)
    definition: Definition


class ReviseAssessment(CreateAssessment):
    expected_revision: int = Field(ge=1)


class Limits(StrictModel):
    max_candidates: int = Field(default=64, ge=1, le=256)
    max_evaluations: int = Field(default=256, ge=1, le=10000)
    max_combination_size: int = Field(default=2, ge=0, le=8)
    max_seconds: float = Field(default=30, ge=0.1, le=300)
    max_results: int = Field(default=50, ge=1, le=1000)


class ProtectedRequirement(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    request: RequestBody
    desired: Literal["holds", "isolated"] = "holds"


class FailureTarget(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    kind: Literal["device", "interface", "link", "tunnel"]
    uid: str = Field(min_length=1, max_length=500)
    interfaces: list[str] = Field(default_factory=list, max_length=100)


class FailureDomain(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    members: list[str] = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=500)
    evidence_status: Literal["declared", "observed", "unknown"] = "declared"
    uid: str | None = Field(default=None, max_length=500)
    valid_from_ms: int | None = Field(default=None, ge=0)
    valid_until_ms: int | None = Field(default=None, ge=0)
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def valid_window(self) -> FailureDomain:
        if (
            self.valid_from_ms is not None
            and self.valid_until_ms is not None
            and self.valid_from_ms >= self.valid_until_ms
        ):
            raise ValueError("Failure-domain validity must end after it starts.")
        return self


class Analyze(StrictModel):
    kind: Literal["evaluate", "troubleshoot", "regression", "repair", "resilience", "verify"] = "evaluate"
    snapshot: str | None = None
    before_snapshot: str | None = None
    limits: Limits = Field(default_factory=Limits)
    allowed_targets: dict[str, str] = Field(default_factory=dict, max_length=50)
    allowed_kinds: list[Literal["fw_rule.add", "fw_rule.modify", "fw_rule.remove"]] = Field(
        default=["fw_rule.add", "fw_rule.modify", "fw_rule.remove"], max_length=3
    )
    protected: list[ProtectedRequirement] = Field(default_factory=list, max_length=50)
    targets: list[FailureTarget] = Field(default_factory=list, max_length=100)
    domains: list[FailureDomain] = Field(default_factory=list, max_length=100)
    retry_of: str | None = None
    scope: dict[str, list[str]] | None = None
    cost_order: list[Literal["devices", "newly_permitted_scope", "rule_edits"]] = Field(
        default=["devices", "newly_permitted_scope", "rule_edits"], min_length=3, max_length=3
    )

    @model_validator(mode="after")
    def valid_analysis(self) -> Analyze:
        if self.kind == "regression" and not self.before_snapshot:
            raise ValueError("regression analysis requires before_snapshot")
        if self.kind == "repair" and not self.allowed_targets:
            raise ValueError("repair search requires allowed rulebase targets")
        if self.kind == "resilience" and not self.targets:
            raise ValueError("resilience analysis requires failure targets")
        if len(set(self.cost_order)) != 3:
            raise ValueError("Cost order must include each cost dimension exactly once.")
        names = [p.name for p in self.protected]
        if len(set(names)) != len(names):
            raise ValueError("protected requirement names must be unique")
        for protection in self.protected:
            _request_from_body(protection.request)
        if self.scope is not None:
            if set(self.scope) - {"source_ports"} != {"source", "destination", "protocols", "ports"}:
                raise ValueError("Repair scope needs source, destination, protocols and ports.")
            if any(
                not values or len(values) > 100 or any(len(v) > 200 for v in values)
                for values in self.scope.values()
            ):
                raise ValueError("Each repair scope field needs 1 to 100 bounded values.")
        return self


class Deployment(StrictModel):
    reference: str = Field(min_length=1, max_length=500)
    deployed_at: str
    assessment_revision: int = Field(ge=1)


class CollectionActions(StrictModel):
    run_id: str
    action_ids: list[str] = Field(min_length=1, max_length=50)
