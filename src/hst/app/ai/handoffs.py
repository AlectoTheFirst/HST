"""Handoffs from a stored AI step to a durable record.

A handoff names one step by id. The tool, the arguments and the run come from
the stored `ai_steps` row.

A `change_simulate` step becomes the input of an analysis session of
kind simulation. The intents of the step are the changes, its flows and sites
are the scope and its depth is the bound. The run in the provenance of the
step is the pinned snapshot.

An `impact_evaluate_service` step becomes the assessment draft that the
change-simulation workspace opens. The draft has the shape that `serviceDraft`
builds in the web client (web/src/assessments/context.ts). The draft of a
request form holds the request set. The draft of a requirement form holds the
requirement uid. A step of the application_connection form has no draft.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from hst.analysis.contracts import SimulationAnalysisInput
from hst.app.ai.envelope import step_run
from hst.app.store import AiStep
from hst.assessment.evaluation import ConditionBody, RequestBody

# The tool whose steps save as an analysis session.
SIMULATION_TOOL = "change_simulate"
# The tool whose steps have an assessment draft.
SERVICE_TOOL = "impact_evaluate_service"
# The evidence age a drafted assessment accepts, as `serviceDraft` sets it.
DRAFT_FRESHNESS_S = 86400
# The request set `serviceDraft` starts from before the stored request
# overrides it (`emptyRequirement` in web/src/assessments/types.ts).
_EMPTY_REQUEST: dict[str, Any] = {
    "name": "",
    "destination": "",
    "sources": [],
    "members": [{"name": "member-1", "addresses": []}],
    "condition": {"kind": "member", "member": "member-1"},
    "success": "forward",
}
# The condition kinds the assessment editor names differently.
_CONDITION_KINDS = {"every": "and", "any-one": "or", "n-of-m": "threshold"}


class HandoffError(ValueError):
    """The step cannot be handed off. The message holds the reason."""


def _label(step: AiStep) -> str:
    return f"s{step.label}"


def _run(step: AiStep) -> str:
    run = step_run(step)
    if run is None:
        raise HandoffError(f"step {_label(step)} records no run")
    return run


def _require(step: AiStep, tool: str, what: str) -> None:
    if step.tool != tool:
        raise HandoffError(f"step {_label(step)} calls {step.tool} and is not {what}")
    if step.is_error:
        raise HandoffError(f"step {_label(step)} ended with an error")


def _first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    where = ".".join(str(part) for part in error["loc"])
    return f"{where}: {error['msg']}" if where else str(error["msg"])


def simulation_run(step: AiStep) -> str:
    """The run a simulation step read. Raises HandoffError for a step of
    another tool, an error step and a step that records no run."""
    _require(step, SIMULATION_TOOL, "a change simulation")
    return _run(step)


def simulation_input(step: AiStep, reference: Mapping[str, Any]) -> SimulationAnalysisInput:
    """The simulation input of `step`, pinned to `reference`, the snapshot
    reference of the run the step read. Raises HandoffError when the stored
    manifest digest differs from the reference's or the arguments do not form
    a simulation input."""
    _require(step, SIMULATION_TOOL, "a change simulation")
    stored = (step.provenance or {}).get("manifest_sha256")
    if stored and stored != reference.get("manifest_sha256"):
        raise HandoffError(
            f"the evidence manifest of run {reference.get('snapshot')} differs from the step's"
        )
    arguments = step.arguments
    flows = arguments.get("flows") or []
    sites = arguments.get("sites") or []
    document: dict[str, Any] = {
        "snapshot": dict(reference),
        "changes": arguments.get("intents") or [],
        "scope": {"flows": flows, "sites": sites} if flows or sites else None,
    }
    if arguments.get("depth") is not None:
        document["bounds"] = {"depth": arguments["depth"]}
    try:
        return SimulationAnalysisInput.model_validate(document)
    except ValidationError as exc:
        raise HandoffError(
            f"step {_label(step)} does not form a simulation input: {_first_error(exc)}"
        ) from None


def session_title(step: AiStep) -> str:
    return f"Simulation from chat step {_label(step)}"


def review_origin(step: AiStep) -> dict[str, Any]:
    """The `review` of a session saved from `step`. Its origin holds the ids of
    the conversation, the message and the step, and the step label."""
    return {
        "origin": {
            "conversation_id": step.conversation_id,
            "message_id": step.message_id,
            "step_id": step.id,
            "step": _label(step),
        }
    }


def _editor_condition(condition: Any) -> Any:
    """`condition` with the kind names the assessment editor uses, as
    `conditionForEditor` in web/src/assessments/context.ts renames them."""
    if not isinstance(condition, Mapping):
        return condition
    renamed = dict(condition)
    kind = renamed.get("kind")
    if isinstance(kind, str):
        renamed["kind"] = _CONDITION_KINDS.get(kind, kind)
    if isinstance(renamed.get("parts"), list):
        renamed["parts"] = [_editor_condition(part) for part in renamed["parts"]]
    return renamed


def _requirement_name(step: AiStep) -> str | None:
    """The request set name the stored result reports for a requirement, or
    None when the result is gone or is not an evaluation."""
    if step.result is None:
        return None
    try:
        parsed = json.loads(step.result)
    except ValueError:
        return None
    result = parsed.get("result") if isinstance(parsed, dict) else None
    request = result.get("request") if isinstance(result, dict) else None
    name = request.get("name") if isinstance(request, dict) else None
    return name if isinstance(name, str) and name else None


def _condition_complete(condition: ConditionBody, names: set[str]) -> bool:
    if condition.kind == "member":
        return condition.member in names
    if not condition.parts or not all(_condition_complete(part, names) for part in condition.parts):
        return False
    return condition.kind != "threshold" or (
        condition.n is not None and 0 < condition.n <= len(condition.parts)
    )


def _request_error(body: RequestBody) -> str | None:
    """Why the assessment editor refuses `body`, or None. The checks are those
    of `requirementError` in web/src/assessments/types.ts."""
    if body.mtu is not None and body.mtu.mode != "off":
        try:
            body.mtu.validate_af(6 if any(":" in source for source in body.sources) else 4)
        except ValueError as exc:
            return str(exc)
    if not body.name.strip() or not body.destination.strip():
        return "it has no name or no destination"
    if not body.sources:
        return "it has no client address or prefix"
    if any(not member.name.strip() for member in body.members):
        return "a destination member has no name"
    names = {member.name for member in body.members}
    if len(names) != len(body.members):
        return "the destination member names are not unique"
    if not _condition_complete(body.condition, names):
        return "the success condition names a missing member or a threshold outside its parts"
    return None


def assessment_draft(step: AiStep) -> dict[str, Any]:
    """The assessment draft of a service evaluation step. Raises HandoffError
    for a step of another tool, an error step, a step that records no run and
    a step that names neither a requirement nor a complete request set."""
    _require(step, SERVICE_TOOL, "a service evaluation")
    run = _run(step)
    arguments = step.arguments
    intents = arguments.get("intents")
    definition: dict[str, Any] = {
        "intents": copy.deepcopy(intents) if isinstance(intents, list) else [],
        "snapshot": run,
        "mode": arguments.get("mode") or "possible",
        "freshness_s": DRAFT_FRESHNESS_S,
    }
    requirement = arguments.get("requirement")
    if isinstance(requirement, str) and requirement:
        title = _requirement_name(step) or requirement
        return {
            "title": title,
            "kind": "troubleshoot",
            "definition": {**definition, "requirement": requirement},
        }
    stored = arguments.get("request")
    if not isinstance(stored, Mapping):
        raise HandoffError(f"step {_label(step)} names no requirement and no request set")
    request = {**copy.deepcopy(_EMPTY_REQUEST), **copy.deepcopy(dict(stored))}
    request["condition"] = _editor_condition(request["condition"])
    try:
        body = RequestBody.model_validate(request)
    except ValidationError as exc:
        raise HandoffError(
            f"the request set of step {_label(step)} is not complete: {_first_error(exc)}"
        ) from None
    error = _request_error(body)
    if error is not None:
        raise HandoffError(f"the request set of step {_label(step)} is not complete: {error}")
    return {
        "title": request["name"],
        "kind": "troubleshoot",
        "definition": {**definition, "request": request},
    }
