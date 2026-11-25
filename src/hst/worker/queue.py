"""The policy of the job queue for leases, backoff and the final failure of a job."""

from __future__ import annotations

import logging
from collections.abc import Collection
from datetime import UTC, datetime, timedelta

from hst.app.store import Job, Store

log = logging.getLogger(__name__)

# How long a claim is good for without a heartbeat.
LEASE = timedelta(minutes=5)

# The retry backoff starts at 60 s, doubles per attempt and is capped at BACKOFF_CAP_S.
BACKOFF_BASE_S = 60.0
BACKOFF_CAP_S = 1800.0

# The kinds whose lapsed claims are requeued with the backoff delay. The
# strings equal `KIND`, `FETCH_KIND` and `RUN_KIND` of worker/collect.py and
# `BUILD_DEVICE_RUN` of worker/maintenance.py. This module does not import the
# job bodies.
LEASE_BACKOFF_KINDS = (
    "collect.cycle",
    "collect.fetch",
    "collect.run",
    "maintenance.build_device_run",
)

DEFAULT_MAX_ATTEMPTS = 4


def backoff(attempt: int) -> timedelta:
    """How long after a failed attempt the next one becomes due."""
    return timedelta(seconds=min(BACKOFF_CAP_S, BACKOFF_BASE_S * 2 ** max(0, attempt - 1)))


def _now(now: datetime | None) -> datetime:
    return now if now is not None else datetime.now(UTC)


async def enqueue(
    store: Store,
    kind: str,
    *,
    source: str | None = None,
    device: str | None = None,
    priority: int = 0,
    not_before: datetime | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    triggered_by: str,
    now: datetime | None = None,
) -> Job | None:
    """Queue one job, or return None when an identical one is already pending.

    A job is identical when it has the same (kind, source, device) and is
    queued or running.
    """
    when = _now(now)
    return await store.enqueue_job(
        kind,
        source=source,
        device=device,
        priority=priority,
        not_before=not_before if not_before is not None else when,
        max_attempts=max_attempts,
        triggered_by=triggered_by,
        now=when,
    )


async def claim(
    store: Store,
    worker_id: str,
    batch: int = 1,
    *,
    now: datetime | None = None,
    lease: timedelta = LEASE,
    skip_kinds: Collection[str] = (),
) -> list[Job]:
    """Take up to `batch` due jobs for this worker, leaving a job of a kind in
    `skip_kinds` queued."""
    return await store.claim_jobs(worker_id, batch, _now(now), lease, skip_kinds=skip_kinds)


async def heartbeat(
    store: Store,
    job_ids: list[int],
    worker_id: str,
    *,
    now: datetime | None = None,
    lease: timedelta = LEASE,
) -> list[int]:
    """Extend the lease of the jobs that this worker is running.

    The result is the list of ids whose lease was extended.
    """
    return await store.heartbeat_jobs(job_ids, worker_id, _now(now), lease)


async def finish(
    store: Store,
    job: Job,
    ok: bool,
    detail: str = "",
    *,
    now: datetime | None = None,
) -> Job | None:
    """Record an attempt's outcome and decide what happens next.

    Success is terminal. A failure with attempts left goes back to 'queued' with
    `not_before` delayed by the backoff and the failure text kept in
    `detail`. A failure with no attempts left is 'dead', or 'error' for a job
    of one attempt.

    Every write passes `claimed_by` and `attempt` of the job. The store
    returns None when the row no longer belongs to this attempt.
    """
    when = _now(now)
    if ok:
        return await store.finish_job(
            job.id, "ok", detail, when, claimed_by=job.claimed_by, attempt=job.attempt
        )
    if job.attempt < job.max_attempts:
        retry_at = when + backoff(job.attempt)
        log.warning(
            "job %s (%s) failed on attempt %d of %d; retrying at %s: %s",
            job.id,
            job.kind,
            job.attempt,
            job.max_attempts,
            retry_at.isoformat(),
            detail,
        )
        return await store.finish_job(
            job.id,
            "error",
            detail,
            when,
            retry_at=retry_at,
            claimed_by=job.claimed_by,
            attempt=job.attempt,
        )
    state = "dead" if job.max_attempts > 1 else "error"
    log.error(
        "job %s (%s) failed on attempt %d of %d and will not be retried: %s",
        job.id,
        job.kind,
        job.attempt,
        job.max_attempts,
        detail,
    )
    return await store.finish_job(job.id, state, detail, when, claimed_by=job.claimed_by, attempt=job.attempt)


async def reap(store: Store, now: datetime | None = None) -> int:
    """Requeue every claim whose lease has passed.

    A lapsed claim of a kind in `LEASE_BACKOFF_KINDS` is due again after
    `backoff(attempt)`. A lapsed claim of any other kind is due at once. The
    lapsed attempt counts against `max_attempts` for every kind.
    """
    return await store.reap_jobs(
        _now(now),
        backoff_kinds=LEASE_BACKOFF_KINDS,
        backoff_base_s=BACKOFF_BASE_S,
        backoff_cap_s=BACKOFF_CAP_S,
    )


async def depth(store: Store) -> dict[str, int]:
    """How many jobs sit in each state."""
    return await store.job_depth()
