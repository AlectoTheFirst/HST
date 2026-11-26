"""The Analysis sessions that reference a Business Application, and its review flag."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

log = logging.getLogger(__name__)

# The `limit` of each call of `list_application_bound_sessions`.
MAX_SESSIONS = 1000


def _application_references(definition: dict) -> list[dict]:
    """The `reference` of each application connection and application
    protection of a stored session definition."""
    value = (definition or {}).get("input") or {}
    if value.get("kind") == "connection":
        sources = [item.get("source") or {} for item in value.get("connections") or []]
    elif value.get("kind") == "simulation":
        sources = list(value.get("protected") or [])
    else:
        return []
    return [
        source.get("reference") or {}
        for source in sources
        if isinstance(source, dict) and source.get("kind") == "application_connection"
    ]


def bound_revisions(definition: dict, application_id: str) -> list[int]:
    """The revisions of `application_id` that the session binds, in ascending order."""
    return sorted(
        {
            int(reference["application"]["revision"])
            for reference in _application_references(definition)
            if (reference.get("application") or {}).get("id") == application_id
        }
    )


async def session_counts(store: Any) -> Counter[str]:
    """The number of Analysis sessions that reference each Business Application."""
    counts: Counter[str] = Counter()
    for record in await store.list_application_bound_sessions(None, MAX_SESSIONS):
        counts.update(
            {
                str((reference.get("application") or {}).get("id"))
                for reference in _application_references(record.definition)
            }
        )
    return counts


async def analyses(store: Any, application_id: str, current_revision: int) -> list[dict]:
    """The Analysis sessions that reference `application_id`, newest first, with
    the bound revisions and the runs of the newest session revision. The
    execution state of a run is the state of its stored run, or else the
    state of its summary in the session."""
    from hst.app.routes.analysis_sessions import older_run

    items = []
    for record in await store.list_application_bound_sessions(application_id, MAX_SESSIONS):
        bound = bound_revisions(record.definition, application_id)
        runs = []
        for summary in record.definition.get("runs") or []:
            if not isinstance(summary, dict) or older_run(summary):
                continue
            run = await store.get_analysis_run(str(summary.get("id")))
            runs.append(
                {"id": summary.get("id"), "execution": run.state if run else summary.get("execution")}
            )
        items.append(
            {
                "session_id": record.id,
                "title": record.title,
                "kind": (record.definition.get("input") or {}).get("kind"),
                "session_revision": record.revision,
                "bound_revisions": bound,
                "current_revision": current_revision,
                "stale": any(revision < current_revision for revision in bound),
                "runs": runs,
            }
        )
    return items


async def flag_stale_bindings(store: Any, application_id: str, revision: int) -> Any:
    """Open a review flag of `application_id` after revision `revision` is
    saved, when an Analysis session binds an older revision. The function
    returns the opened flag, or None. An open flag stays as it is. A store
    error is logged, and the function returns None."""
    try:
        sessions = await store.list_application_bound_sessions(application_id, MAX_SESSIONS)
        if not any(
            bound < revision
            for record in sessions
            for bound in bound_revisions(record.definition, application_id)
        ):
            return None
        return await store.open_application_review(
            application_id, reason=f"revision {revision} saved", revision=revision, opened_by=None
        )
    except Exception:
        log.warning(
            "the review flag of application %s revision %s could not be opened",
            application_id,
            revision,
            exc_info=True,
        )
        return None
