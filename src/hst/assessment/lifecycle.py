"""The invalidation of saved assessments after a publication, and the follow-up of collection actions.

A poll is idempotent across replicas and restarts. The poll reads all
assessments with an ID cursor. A finished fetch job moves its collection action
to `awaiting_publication`.

A publication marks saved assessments as needing reassessment and queues no
evaluation. The operator decides when an assessment runs.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any, Literal

from hst.app.permissions import permissions_for
from hst.assessment import service
from hst.assessment.dependencies import manifest_changes
from hst.assessment.models import Analyze
from hst.assessment.store import AnalysisCapacityError, AssessmentRevision, RevisionConflict, input_digest
from hst.core import manifest

log = logging.getLogger(__name__)
POLL_SECONDS = 5
PAGE_SIZE = 100


def _publication(settings: Any) -> tuple[dict, Any]:
    reference = service.snapshot_reference(settings)
    return reference, manifest.read(settings, int(reference["snapshot"]))


async def _permission(store: Any, actor: int | None, permission: str) -> bool:
    if actor is None:
        return False
    user = await store.get_user(actor)
    return bool(user and not user.disabled and permission in permissions_for(user.role))


async def _save_actions(store: Any, item: AssessmentRevision, actions: list[dict]) -> AssessmentRevision:
    if actions == item.definition.get("collection_actions", []):
        return item
    return await store.create_assessment(
        title=item.title,
        purpose=item.purpose,
        definition={**item.definition, "collection_actions": actions},
        created_by=item.created_by,
        assessment_id=item.id,
        expected_revision=item.revision,
    )


async def _enqueue(
    store: Any,
    settings: Any,
    item: AssessmentRevision,
    reference: dict,
    engine: str,
    kind: Literal["evaluate", "troubleshoot"],
    actor: int | None,
) -> Any:
    # The reference is resolved again inside the retention and publication fence.
    async with store.cycle_lock():
        pinned = await asyncio.to_thread(service.snapshot_reference, settings, reference["snapshot"])
        if pinned != reference:
            raise ValueError("publication identity changed during reassessment")
        current = await store.get_assessment(item.id)
        if current is None or current.revision != item.revision:
            raise RevisionConflict("assessment changed while reassessment was queued")
        if not await _permission(store, actor, "changes.write"):
            raise ValueError("analysis permission is no longer available")
        protected = []
        if item.definition.get("change_id"):
            change = await store.get_change_revision(
                item.definition["change_id"], item.definition["change_revision"]
            )
            if change is None or change.definition["intents"] != item.definition.get("intents"):
                raise ValueError("the immutable change reference is unavailable or inconsistent")
            protected = change.definition.get("protected", [])
        body = Analyze(kind=kind, snapshot=reference["snapshot"], protected=protected)
        analysis = body.model_dump(mode="json")
        return await store.enqueue_analysis(
            assessment_id=item.id,
            assessment_revision=item.revision,
            kind=kind,
            inputs={"definition": item.definition, "analysis": analysis, "snapshot_refs": [reference]},
            snapshot_refs=[reference],
            engine_version=engine,
            created_by=actor,
            limits=analysis["limits"],
        )


def _observation(action: dict, published: Any, freshness_s: int) -> tuple[str, str]:
    """The status `ready`, `waiting` or `failed` of a collection action at the
    published snapshot, with its reason. The status is read from the devices of
    the requested source and host."""
    try:
        requested = datetime.fromisoformat(action["requested_at"])
        if requested.tzinfo is None:
            raise ValueError("request time has no timezone")
        requested_ms = requested.timestamp() * 1000
    except (KeyError, TypeError, ValueError):
        return "failed", "The collection request has no valid observation time."
    devices = [
        device
        for device in published.devices
        if device.source == action.get("source") and device.host == action.get("host")
    ]
    if not devices:
        return "waiting", "The committed snapshot does not contain the requested source and host."
    sections = action.get("sections") or [action.get("section")]
    if not sections or any(not section for section in sections):
        return "failed", "The collection request does not identify its required sections."
    for device in devices:
        observed = device.fetch_started_ms
        if observed is None or observed < requested_ms or device.carried:
            continue
        if device.outcome not in {"collected", "unchanged"}:
            return "failed", "The published collection was failed or partial; its gap remains open."
        if any(
            section not in device.sections or device.sections[section].status not in {"ok", "empty"}
            for section in sections
        ):
            return "failed", "A required observation section is incomplete in the published snapshot."
        if any(
            value.status not in {"ok", "empty"}
            for key, value in device.sections.items()
            if any(key.startswith(f"{section}_table_") for section in sections)
        ):
            return "failed", "A required VRF observation is incomplete in the published snapshot."
        tables = action.get("tables")
        if tables is None:
            tables = (
                ["rib"]
                if any(
                    ".rib." in recipe for recipe in action.get("recipe_ids", [action.get("recipe_id", "")])
                )
                else []
            )
        observation_times = [observed]
        for name in tables:
            table = device.tables.get(name)
            if not table or table.status not in {"complete", "complete-empty", "unchanged"}:
                return "failed", f"The required {name} side table was not completely published."
            if table.observed_ms is None or table.observed_ms < requested_ms:
                return "waiting", "A required side table still contains evidence from before this request."
            observation_times.append(table.observed_ms)
        oldest = min(observation_times)
        if datetime.now(UTC).timestamp() * 1000 >= oldest + freshness_s * 1000:
            return "failed", "The collected observations expired before reevaluation."
        return "ready", "Required observations are complete in the committed snapshot."
    return "waiting", "The committed snapshot still carries evidence from before this collection request."


def _same_gap(action: dict, gap: dict) -> bool:
    recipes = action.get("recipe_ids") or [action.get("recipe_id")]
    dimensions = {f"{recipe.rsplit('.', 1)[-1]}-rib" for recipe in recipes if recipe}
    if gap.get("id") in action.get("gap_ids", []):
        return True
    if gap.get("source") != action.get("source") or gap.get("host") != action.get("host"):
        return False
    if gap.get("recipe_id") and gap["recipe_id"] in recipes:
        return True
    if gap.get("code") == "routing-observation-missing" and gap.get("dimension") in dimensions:
        return True
    codes = set(action.get("gap_codes", []))
    sections = set(action.get("sections", [action.get("section")]))
    subjects = set(action.get("subjects", []))
    gap_subjects = gap.get("subject", [])
    gap_subjects = [gap_subjects] if isinstance(gap_subjects, str) else gap_subjects
    return bool(
        (not codes or gap.get("code") in codes)
        and (gap.get("section") or gap.get("dimension")) in sections
        and (not subjects or subjects.intersection(gap_subjects))
    )


async def _actions(
    store: Any, settings: Any, item: AssessmentRevision, reference: dict, published: Any, engine: str
) -> tuple[AssessmentRevision, int]:
    actions = [dict(action) for action in item.definition.get("collection_actions", [])]
    ready: list[int] = []
    actors: dict[int, int] = {}
    for index, action in enumerate(actions):
        if action.get("state") in {"reevaluated", "failed"}:
            continue
        original = await store.get_analysis_run(action.get("run_id", ""))
        actor = action.get("requested_by", original.created_by if original else None)
        if (
            actor is None
            or original is None
            or original.assessment_id != item.id
            or not await _permission(store, actor, "runs.manage")
        ):
            action.update(
                state="failed", reason="The original collection authorization is no longer available."
            )
            continue
        if action.get("reevaluation_run_id"):
            result = await store.get_analysis_run(action["reevaluation_run_id"])
            if result is None or result.assessment_id != item.id or result.kind != "troubleshoot":
                action.update(state="failed", reason="The recorded reevaluation is unavailable.")
            elif result.state in {"failed", "cancelled"}:
                action.update(
                    state="failed",
                    reason="The reevaluation did not complete; the original result is preserved.",
                )
            elif result.state == "completed" and result.result is not None:
                remaining = any(_same_gap(action, gap) for gap in result.result.get("gaps", []))
                action.update(
                    state="reevaluated",
                    gap_closed=not remaining,
                    reason="Reevaluated against the committed collection snapshot; inspect the new result.",
                    completed_at=result.finished_at,
                )
            continue
        job = await store.get_job(action["job_id"]) if action.get("job_id") is not None else None
        if job and (job.source != action.get("source") or job.device != action.get("host")):
            action.update(
                state="failed", reason="The collection job does not match the requested source and host."
            )
            continue
        if job and job.state in {"error", "dead"}:
            action.update(state="failed", reason="The collection job failed; its gap remains open.")
            continue
        if job and job.state in {"queued", "running"}:
            action["state"] = "collecting" if job.state == "running" else "queued"
            continue
        action["state"] = "awaiting_publication"
        status, reason = _observation(action, published, item.definition.get("freshness_s", 3600))
        action["reason"] = reason
        if status == "failed":
            action["state"] = "failed"
        elif status == "ready":
            action["published_snapshot"] = reference["snapshot"]
            ready.append(index)
            actors[index] = actor
    item = await _save_actions(store, item, actions)
    queued = 0
    # `_enqueue` checks the current permission of each requesting actor. The ready
    # actions of one actor share one run.
    for actor in sorted({actors[index] for index in ready}):
        run = await _enqueue(store, settings, item, reference, engine, "troubleshoot", actor)
        queued += 1
        for index in ready:
            if actors[index] == actor:
                actions[index]["reevaluation_run_id"] = run.id
    item = await _save_actions(store, item, actions)
    return item, queued


async def reconcile_once(store: Any, settings: Any) -> dict:
    async with store.cycle_lock():
        reference, published = await asyncio.to_thread(_publication, settings)
        previous = None
        if getattr(published, "previous", None) is not None:
            with suppress(OSError, ValueError):
                previous = await asyncio.to_thread(manifest.read, settings, published.previous.snapshot_key)
    engine = await asyncio.to_thread(service.engine_version, settings)
    event = "publication:" + input_digest({"reference": reference, "engine": engine})
    # Without a previous manifest the scope is the whole estate. Otherwise the scopes
    # are the source, device and observation changes between the 2 manifests.
    scopes = (
        manifest_changes(previous, published)
        if hasattr(published, "estate")
        else [{"estate": reference["estate"], "scope_complete": False}]
    )
    if previous is not None:
        scopes = [{**scope, "from_snapshot": str(previous.snapshot_key)} for scope in scopes]
    invalidated = await store.invalidate_assessments(event, reference, scopes, engine)
    stats = {"assessments": 0, "invalidated": len(invalidated), "queued": 0, "conflicts": 0}
    cursor = ""
    while True:
        batch = await store.list_assessment_batch(after_id=cursor, limit=PAGE_SIZE)
        if not batch:
            break
        for item in batch:
            cursor = item.id
            stats["assessments"] += 1
            try:
                # This loop queues one kind of run. It is the follow-up of a
                # collection action that the operator requested, after the evidence
                # of the action is published. A publication or an expired
                # observation marks the saved assessment as needing reassessment,
                # and the operator queues the evaluation.
                item, queued = await _actions(store, settings, item, reference, published, engine)
                stats["queued"] += queued
            except RevisionConflict:
                stats["conflicts"] += 1
            except AnalysisCapacityError:
                continue
            except ValueError:
                log.warning("Assessment reconciliation needs updated evidence or authorization")
        if len(batch) < PAGE_SIZE:
            break
    return stats


async def watch_assessments(store: Any, settings: Any) -> None:
    while True:
        try:
            await reconcile_once(store, settings)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("Assessment lifecycle reconciliation failed; retrying after poll interval")
        await asyncio.sleep(POLL_SECONDS)
