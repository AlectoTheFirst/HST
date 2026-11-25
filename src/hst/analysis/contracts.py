"""Versioned contracts shared by Analysis UI and backend packages."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from hst.assessment.evaluation import RequestBody
from hst.assessment.models import Definition

ANALYSIS_SESSION_SCHEMA_VERSION: Literal[1] = 1
MAX_CONNECTIONS = 200
MAX_CHANGES = 50
MAX_PROTECTIONS = 50


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SnapshotReference(ContractModel):
    """One immutable inventory/model identity."""

    snapshot: str = Field(min_length=1, max_length=200)
    manifest_sha256: str = Field(min_length=1, max_length=128)
    estate: str = Field(min_length=1, max_length=200)
    observation_floor_ms: int | None = Field(default=None, ge=0)


class RevisionReference(ContractModel):
    id: str = Field(min_length=1, max_length=200)
    revision: int = Field(ge=1)
    digest: str | None = Field(default=None, min_length=1, max_length=128)


class ApplicationConnectionReference(ContractModel):
    """Explicit catalog ownership for one selected connection."""

    application: RevisionReference
    service_id: str = Field(min_length=1, max_length=200)
    connection_id: str = Field(min_length=1, max_length=200)


class InlineConnection(ContractModel):
    kind: Literal["inline"] = "inline"
    request: RequestBody


class SavedRequirementConnection(ContractModel):
    kind: Literal["saved_requirement"] = "saved_requirement"
    requirement: RevisionReference
    request: RequestBody


class GraphRequirementConnection(ContractModel):
    kind: Literal["graph_requirement"] = "graph_requirement"
    requirement_uid: str = Field(min_length=1, max_length=500)


class ApplicationConnection(ContractModel):
    kind: Literal["application_connection"] = "application_connection"
    reference: ApplicationConnectionReference
    request: RequestBody
    resolved_scope_digest: str = Field(min_length=1, max_length=128)


ConnectionSource = Annotated[
    InlineConnection | SavedRequirementConnection | GraphRequirementConnection | ApplicationConnection,
    Field(discriminator="kind"),
]


class ConnectionSelection(ContractModel):
    """One independently reported connection in a grouped session."""

    id: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    source: ConnectionSource


class ChangeIntent(ContractModel):
    """The engine decides admission."""

    kind: str = Field(min_length=1, max_length=100)
    params: dict[str, Any] = Field(default_factory=dict, max_length=100)


class ConnectionAnalysisInput(ContractModel):
    kind: Literal["connection"] = "connection"
    snapshot: SnapshotReference
    connections: list[ConnectionSelection] = Field(min_length=1, max_length=MAX_CONNECTIONS)
    changes: list[ChangeIntent] = Field(default_factory=list, max_length=MAX_CHANGES)
    mode: Literal["possible", "guaranteed"] = "possible"

    @model_validator(mode="after")
    def unique_connections(self) -> ConnectionAnalysisInput:
        ids = [connection.id for connection in self.connections]
        if len(ids) != len(set(ids)):
            raise ValueError("connection selection IDs must be unique")
        return self


class SimulationFlow(ContractModel):
    src: str = Field(min_length=1, max_length=500)
    dst: str = Field(min_length=1, max_length=500)
    port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = Field(default=None, min_length=1, max_length=40)


class SimulationScope(ContractModel):
    flows: list[SimulationFlow] = Field(default_factory=list, max_length=50)
    sites: list[str] = Field(default_factory=list, max_length=20)


class SimulationBounds(ContractModel):
    depth: int | None = Field(default=None, ge=1, le=64)
    max_flows: int = Field(default=50, ge=1, le=200)
    max_seconds: float = Field(default=30, gt=0, le=300)


class InlineProtection(ContractModel):
    kind: Literal["inline"] = "inline"
    name: str = Field(min_length=1, max_length=200)
    request: RequestBody
    desired: Literal["holds", "isolated"] = "holds"


class ApplicationProtection(ContractModel):
    kind: Literal["application_connection"] = "application_connection"
    reference: ApplicationConnectionReference
    resolved_scope_digest: str = Field(min_length=1, max_length=128)
    desired: Literal["holds", "isolated"] = "holds"


Protection = Annotated[InlineProtection | ApplicationProtection, Field(discriminator="kind")]


class SimulationAnalysisInput(ContractModel):
    kind: Literal["simulation"] = "simulation"
    snapshot: SnapshotReference
    changes: list[ChangeIntent] = Field(min_length=1, max_length=MAX_CHANGES)
    change_revision: RevisionReference | None = None
    scope: SimulationScope | None = None
    bounds: SimulationBounds = Field(default_factory=SimulationBounds)
    protected: list[Protection] = Field(default_factory=list, max_length=MAX_PROTECTIONS)


AnalysisInput = Annotated[
    ConnectionAnalysisInput | SimulationAnalysisInput,
    Field(discriminator="kind"),
]

ExecutionState = Literal["queued", "running", "completed", "failed", "cancelled"]
CoverageState = Literal["not_started", "partial", "complete"]


class AnalysisRunSummary(ContractModel):
    id: str = Field(min_length=1, max_length=200)
    item_id: str = Field(min_length=1, max_length=200)
    execution: ExecutionState
    # the run's answer in the result vocabulary: passes, fails, or not decided
    # with what is missing (hst.results.words)
    result: dict[str, Any] | None = None
    coverage: CoverageState
    result_ref: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def valid_result_state(self) -> AnalysisRunSummary:
        stated = self.result is not None
        if self.execution != "completed" and stated:
            raise ValueError("only a completed run may state a result")
        if self.execution == "completed" and not stated:
            raise ValueError("a completed run must state a result")
        return self


class LegacyAssessmentReference(ContractModel):
    assessment_id: str = Field(min_length=1, max_length=200)
    assessment_revision: int = Field(ge=1)


class AnalysisSession(ContractModel):
    schema_version: Literal[1] = ANALYSIS_SESSION_SCHEMA_VERSION
    id: str = Field(min_length=1, max_length=200)
    revision: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=200)
    input: AnalysisInput
    runs: list[AnalysisRunSummary] = Field(default_factory=list, max_length=MAX_CONNECTIONS)
    legacy_assessment: LegacyAssessmentReference | None = None

    @model_validator(mode="after")
    def run_items_belong_to_input(self) -> AnalysisSession:
        expected = (
            {connection.id for connection in self.input.connections}
            if self.input.kind == "connection"
            else {"simulation"}
        )
        if any(run.item_id not in expected for run in self.runs):
            raise ValueError("run item IDs must identify an input item")
        if len({run.id for run in self.runs}) != len(self.runs):
            raise ValueError("run IDs must be unique within a session")
        return self


class AnalysisLocation(ContractModel):
    """Shareable state. The producer issues the finding and evidence IDs."""

    section: Literal["results", "scope", "history", "verification"] = "results"
    session_id: str | None = Field(default=None, min_length=1, max_length=200)
    run_id: str | None = Field(default=None, min_length=1, max_length=200)
    finding_id: str | None = Field(default=None, min_length=1, max_length=500)
    evidence_id: str | None = Field(default=None, min_length=1, max_length=500)


def adapt_legacy_assessment(
    *,
    assessment_id: str,
    assessment_revision: int,
    title: str,
    definition: Definition,
    snapshot: SnapshotReference,
) -> AnalysisSession:
    """Read an existing assessment as one connection without rewriting it."""

    source: ConnectionSource
    if definition.requirement_id is not None:
        if definition.request is None:
            raise ValueError("a saved requirement reference must retain its inline request")
        source = SavedRequirementConnection(
            requirement=RevisionReference(
                id=definition.requirement_id,
                revision=definition.requirement_revision or 1,
            ),
            request=definition.request,
        )
        name = definition.request.name
    elif definition.request is not None:
        source = InlineConnection(request=definition.request)
        name = definition.request.name
    else:
        source = GraphRequirementConnection(requirement_uid=definition.requirement or "")
        name = definition.requirement or "Graph requirement"
    return AnalysisSession(
        id=f"legacy-assessment:{assessment_id}",
        revision=assessment_revision,
        title=title,
        input=ConnectionAnalysisInput(
            snapshot=snapshot,
            connections=[ConnectionSelection(id="legacy-connection", name=name, source=source)],
            changes=[ChangeIntent.model_validate(intent) for intent in definition.intents],
            mode=definition.mode,
        ),
        legacy_assessment=LegacyAssessmentReference(
            assessment_id=assessment_id,
            assessment_revision=assessment_revision,
        ),
    )
