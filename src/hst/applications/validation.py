"""Validation of an unsaved Business Application definition at a pinned snapshot.

Validation has 5 stages.

1. The YAML syntax and the bounds.
2. The schema and its internal references. `parse_application_source` runs
   stages 1 and 2, and its errors have a line and a column.
3. The inventory references at the snapshot. A resolver that the caller
   supplies resolves the complete definition for the base revision.
4. On request, the flow evaluation of each ready connection in
   `evaluate_flows`, through an evaluator that the caller supplies.
5. The warnings `address-normalized` and `engine-limit`. They block nothing.

Validation writes nothing. The resolution document is returned and is not
saved. `record_validation` stores a result as an `application-validation`
record for a caller who may commit. A commit names that record by its digest.

Stage 1 and 2 errors block both a save and the ready state. Every stage 3
resolution issue blocks the ready state. `blocking` lists the paths of both.
A stage 4 result blocks nothing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any, Literal

from pydantic import ValidationError

from hst.applications import service as application_service
from hst.applications.merge import merge_application
from hst.applications.models import (
    BusinessApplicationDefinition,
    BusinessApplicationPatch,
    RemovalSet,
    stored_definition,
)
from hst.applications.service import ImportMode
from hst.applications.yaml_format import (
    ApplicationFormatError,
    FormatIssue,
    definition_digest,
    normalized_document,
    parse_application_source,
)
from hst.assessment.evaluation import MAX_MEMBERS, MAX_SOURCES

log = logging.getLogger(__name__)

# A stage 3 resolver resolves a complete definition at the snapshot for the given
# revision number and returns the `resolve_application` document.
Resolver = Callable[[BusinessApplicationDefinition, int], Awaitable[dict]]

# A stage 4 evaluator evaluates the compiled request of one connection at the
# snapshot and returns the evaluate result. It raises `FlowNotEvaluated` when it
# does not evaluate the connection, for example when no process slot is free. It
# is called from a worker thread.
FlowEvaluator = Callable[[dict], dict]

# Stage 4 evaluates at most MAX_EVALUATED_CONNECTIONS ready connections, one at a
# time, and starts none after FLOW_DEADLINE_S seconds.
MAX_EVALUATED_CONNECTIONS = 20
FLOW_DEADLINE_S = 300.0


class FlowNotEvaluated(Exception):
    """A `FlowEvaluator` did not evaluate one connection. `reason` is the
    flow record's `not_evaluated_reason` and `detail` its message."""

    def __init__(
        self, reason: Literal["capacity-busy", "evaluation-failed"], detail: str | None = None
    ) -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class ValidationWarning:
    code: str
    path: str
    message: str


async def validate_application(
    store: Any,
    yaml_text: str,
    *,
    mode: ImportMode,
    snapshot: dict,
    resolve: Resolver,
    application_id: str | None = None,
    include_preview: bool = False,
    evaluate: FlowEvaluator | None = None,
) -> dict:
    """The validation result of `yaml_text` at `snapshot`.

    `mode` is the import mode. `merge` validates a partial document merged
    onto the current revision of its application. `replace` validates a
    complete document on its own. The base revision passed to `resolve` is the
    current revision of the application, or 0 for a new one.

    With `application_id`, the document must name that application. With
    `application_id` and `include_preview`, the result also holds the import
    preview. The mapping issues of the preview are the resolution issues of
    the inventory members at `snapshot`. With `evaluate`, `flows` holds the
    stage 4 record of each connection. `flows` is None without `evaluate` or
    when stage 1 or 2 fails. The store is only read.
    """
    result: dict[str, Any] = {
        "errors": [],
        "warnings": [],
        "definition": None,
        "preview": None,
        "resolution": None,
        "flows": None,
        "blocking": [],
        "snapshot": snapshot,
    }
    try:
        parsed = parse_application_source(yaml_text, partial=mode == "merge")
    except ApplicationFormatError as exc:
        return _with_errors(result, exc.errors)
    document = parsed.document
    if application_id is not None and document.id != application_id:
        message = f"the document names application {document.id}; the request names {application_id}"
        return _with_errors(result, [parsed.issue(("id",), message)])
    current_record = await store.get_application(document.id)
    base_revision = current_record.revision if current_record is not None else 0
    if isinstance(document, BusinessApplicationPatch):
        current = stored_definition(current_record.definition) if current_record is not None else None
        try:
            definition = merge_application(current, document)
        except ValueError as exc:
            return _with_errors(result, _merge_errors(exc))
    else:
        definition = document
    result["definition"] = normalized_document(definition)
    result["warnings"] = [
        asdict(warning)
        for warning in (
            *_address_warnings(parsed.source, document),
            *_engine_limit_warnings(definition),
        )
    ]
    resolution = await resolve(definition, base_revision)
    result["resolution"] = resolution
    result["blocking"] = list(dict.fromkeys(issue["path"] for issue in resolution["issues"]))
    if evaluate is not None:
        result["flows"] = await asyncio.to_thread(evaluate_flows, resolution, evaluate)
    if include_preview and application_id is not None:
        preview = await application_service.preview_import(
            store, yaml_text, RemovalSet(), mode, resolution=resolution
        )
        result["preview"] = preview.as_dict()
    return result


def evaluate_flows(resolution: dict, evaluate: FlowEvaluator) -> list[dict]:
    """Return one stage 4 flow record per connection of `resolution`, in its order.

    The compiled request of each ready connection goes to `evaluate`, one at a
    time. `result` is the connection condition in the result vocabulary.
    `result` and the `passes`, `fails` and `open` source prefixes come from
    `outcomes.after` of the evaluate result. The change set is empty, and
    `outcomes.after` equals `outcomes.before`. `display_truncated` is true
    when the outcome cut one of the 3 lists to its display bound. A connection
    that is not evaluated has a null result and one `not_evaluated_reason`.

    - `not-ready`: stage 3 left the connection unresolved.
    - `over-cap`: the connection comes after the first
      MAX_EVALUATED_CONNECTIONS ready connections.
    - `deadline`: FLOW_DEADLINE_S had passed before its turn.
    - `capacity-busy`: no process slot was free.
    - `evaluation-failed`: the evaluation raised an error, stopped without
      outcomes or answered an outcome without a result. `detail` holds the
      message. An error other than `FlowNotEvaluated` or `ValueError` is
      logged, and `detail` holds only its type.

    After an error of one connection, the results computed before it are kept
    and the next connection is evaluated.
    """
    started = time.monotonic()
    ready = 0
    flows = []
    for connection in resolution["connections"]:
        flow: dict[str, Any] = {
            "connection_id": connection["id"],
            "readiness": connection["readiness"],
            "result": None,
            "passes": [],
            "fails": [],
            "open": [],
            "missing_evidence": [],
            "display_truncated": False,
            "not_evaluated_reason": None,
            "detail": None,
        }
        flows.append(flow)
        if connection["readiness"] != "ready" or connection.get("request") is None:
            flow["not_evaluated_reason"] = "not-ready"
            continue
        ready += 1
        if ready > MAX_EVALUATED_CONNECTIONS:
            flow["not_evaluated_reason"] = "over-cap"
            continue
        if time.monotonic() - started >= FLOW_DEADLINE_S:
            flow["not_evaluated_reason"] = "deadline"
            continue
        try:
            flow.update(_flow_outcome(evaluate(connection["request"])))
        except FlowNotEvaluated as exc:
            flow.update(not_evaluated_reason=exc.reason, detail=exc.detail)
        except ValueError as exc:
            flow.update(not_evaluated_reason="evaluation-failed", detail=str(exc))
        except Exception as exc:
            log.warning("stage 4 evaluation of connection %s failed", connection["id"], exc_info=True)
            flow.update(
                not_evaluated_reason="evaluation-failed",
                detail=f"the evaluation raised {type(exc).__name__}; see the server log",
            )
    return flows


def _flow_outcome(answer: dict) -> dict[str, Any]:
    """The flow record fields of one evaluate result."""
    after = (answer.get("outcomes") or {}).get("after")
    if after is None:
        stop = answer.get("stop_reason") or "no reason recorded"
        raise FlowNotEvaluated("evaluation-failed", f"the evaluation stopped without outcomes: {stop}")
    result = after.get("result")
    if not isinstance(result, dict):
        raise FlowNotEvaluated("evaluation-failed", "the evaluation answered an outcome without a result")
    return {
        "result": result,
        "passes": list(after.get("passes") or []),
        "fails": list(after.get("fails") or []),
        "open": list(after.get("open") or []),
        "missing_evidence": list(answer.get("missing_evidence") or []),
        "display_truncated": bool(after.get("display_truncated")),
    }


def validation_record(result: dict) -> dict | None:
    """The `application-validation` record of a validation result, or None
    when stage 1 or 2 failed and there is no definition to record.

    The record holds the definition digest, the snapshot reference, the stage 3
    resolution document, the stage 4 flow results when they ran, and the
    warnings and blocking paths. `ready` is true when nothing blocks the ready
    state at the snapshot.
    """
    definition, resolution = result["definition"], result["resolution"]
    if definition is None or resolution is None:
        return None
    return {
        "schema_version": 1,
        "application_id": definition["id"],
        "definition_digest": definition_digest(definition),
        "base_revision": resolution["application"]["revision"],
        "snapshot": result["snapshot"],
        "resolution": resolution,
        "flows": result.get("flows"),
        "warnings": result["warnings"],
        "blocking": result["blocking"],
        "ready": bool(resolution["ready"]) and not result["blocking"],
    }


async def record_validation(store: Any, result: dict) -> str | None:
    """Store the record of a validation result and return its digest, or
    return None when there is nothing to record."""
    record = validation_record(result)
    if record is None:
        return None
    return str((await store.save_application_validation(record))["digest"])


def _with_errors(result: dict[str, Any], errors: list[FormatIssue]) -> dict[str, Any]:
    result["errors"] = [error.as_dict() for error in errors]
    result["blocking"] = list(dict.fromkeys(error.path for error in errors))
    return result


def _merge_errors(exc: ValueError) -> list[FormatIssue]:
    """Errors of the merged definition. Their paths index the merged document.
    The errors have no line and no column."""
    if isinstance(exc, ValidationError):
        return [
            FormatIssue(".".join(str(part) for part in error["loc"]) or "$", error["msg"])
            for error in exc.errors(include_url=False)
        ]
    return [FormatIssue("$", str(exc))]


def _address_warnings(
    source: dict, document: BusinessApplicationDefinition | BusinessApplicationPatch
) -> list[ValidationWarning]:
    """A literal member address whose stored form differs from the text, for
    example a host address with a mask that is stored as its network."""
    warnings = []
    written_groups = source.get("groups")
    for written_group, group in zip(
        written_groups if isinstance(written_groups, list) else [], document.groups or [], strict=False
    ):
        written_members = written_group.get("members") if isinstance(written_group, dict) else None
        for written_member, member in zip(
            written_members if isinstance(written_members, list) else [], group.members, strict=False
        ):
            written = written_member.get("address") if isinstance(written_member, dict) else None
            if member.address is not None and written != member.address:
                warnings.append(
                    ValidationWarning(
                        "address-normalized",
                        f"groups.{group.id}.members.{member.id}.address",
                        f"address {written} is stored as {member.address}",
                    )
                )
    return warnings


def _engine_limit_warnings(definition: BusinessApplicationDefinition) -> list[ValidationWarning]:
    """A group with more members than one evaluation request accepts on the side
    a connection uses it. A request accepts MAX_SOURCES source addresses and
    MAX_MEMBERS destination members."""
    groups = {group.id: group for group in definition.groups}
    warnings: dict[tuple[str, str], ValidationWarning] = {}
    for connection in definition.connections:
        for group_id, side, limit, noun in (
            (connection.source, "source", MAX_SOURCES, "source addresses"),
            (connection.destination, "destination", MAX_MEMBERS, "destination members"),
        ):
            count = len(groups[group_id].members)
            if count > limit and (group_id, side) not in warnings:
                warnings[(group_id, side)] = ValidationWarning(
                    "engine-limit",
                    f"groups.{group_id}",
                    f"group {group_id} has {count} members and is the {side} of connection "
                    f"{connection.id}; one evaluation request accepts at most {limit} {noun}",
                )
    return list(warnings.values())
