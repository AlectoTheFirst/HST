"""The scheduler decides which jobs are due. One process, the leader, schedules them."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from hst.app import retention
from hst.app import sources as glue
from hst.app.inventory import collection as inventory_collection
from hst.app.retention import Retention
from hst.app.store import Device, DeviceStatus, Source, Store
from hst.core import Settings
from hst.worker import maintenance, queue
from hst.worker.collect import FETCH_KIND

log = logging.getLogger(__name__)

HOURLY = 3600.0
DAILY = 86400.0

# Expired sessions are purged at boot. Between restarts this schedule purges
# them.
SESSION_PURGE_INTERVAL_S = 3600.0

# How often the loop wakes to look for due work.
TICK_S = 15.0

# How long a standby waits before asking whether it leads yet.
STANDBY_S = 30.0

# The cap of the spread applied to first due times.
MAX_JITTER_S = 300.0


def jitter(kind: str, interval: float) -> float:
    """A stable per-kind offset in [0, min(interval/2, MAX_JITTER_S)).

    The offset is derived from the name of the kind. It is the same on every
    replica and in every test run.
    """
    span = min(interval / 2, MAX_JITTER_S)
    if span <= 0:
        return 0.0
    digest = hashlib.blake2b(kind.encode(), digest_size=8).digest()
    return (int.from_bytes(digest, "big") % 1_000_000) / 1_000_000 * span


def always(limits: Retention) -> bool:
    """The default guard. It returns True for every retention setting."""
    return True


@dataclass(frozen=True)
class Schedule:
    """One system schedule.

    `guard` is called before every enqueue. The job is queued only when
    `guard` returns True.
    """

    kind: str
    interval: float
    guard: Callable[[Retention], bool] = always


SYSTEM_SCHEDULES: tuple[Schedule, ...] = (
    Schedule(maintenance.PRUNE_GRAPH, HOURLY),
    Schedule(maintenance.PRUNE_SIDESTORE, HOURLY),
    # Each body decides whether the period tier is off (worker/maintenance.py).
    Schedule(maintenance.PRUNE_RAWSTORE, HOURLY),
    Schedule(maintenance.PRUNE_MANIFESTS, HOURLY),
    Schedule(
        maintenance.PURGE_LOGIN_EVENTS,
        HOURLY,
        guard=lambda limits: limits.login_event_retention_days > 0,
    ),
    Schedule(
        maintenance.PURGE_CYPHER_EVENTS,
        HOURLY,
        guard=lambda limits: limits.cypher_event_retention_days > 0,
    ),
    # The schedules of the AI tables. The ephemeral purge has the guard of the
    # conversation purge. A conversation limit of 0 keeps every conversation.
    Schedule(
        maintenance.PURGE_AI_CONVERSATIONS,
        HOURLY,
        guard=lambda limits: limits.ai_conversation_retention_days > 0,
    ),
    Schedule(
        maintenance.COMPACT_AI_STEPS,
        HOURLY,
        guard=lambda limits: limits.ai_step_result_days > 0,
    ),
    Schedule(
        maintenance.PURGE_AI_EPHEMERAL,
        HOURLY,
        guard=lambda limits: limits.ai_conversation_retention_days > 0,
    ),
    Schedule(
        maintenance.PURGE_AI_EVENTS,
        HOURLY,
        guard=lambda limits: limits.ai_event_retention_days > 0,
    ),
    Schedule(maintenance.PURGE_SESSIONS, SESSION_PURGE_INTERVAL_S),
    Schedule(
        maintenance.PURGE_JOB_HISTORY,
        DAILY,
        guard=lambda limits: limits.job_history_retention_days > 0,
    ),
)

# The `triggered_by` of the job rows that this scheduler creates.
TRIGGERED_BY = "scheduler"


class Scheduler:
    """The due-work loop. A test passes `clock` and `sleep` to drive it."""

    def __init__(
        self,
        store: Store,
        settings: Settings,
        *,
        schedules: Sequence[Schedule] = SYSTEM_SCHEDULES,
        collect_fanout: bool = False,
        tick_s: float = TICK_S,
        standby_s: float = STANDBY_S,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        schedules = tuple(schedules)
        # The interval of the device-run schedule is the setting
        # `device_run_interval_s`. The schedule is added here when `schedules`
        # does not have it.
        if not any(s.kind == maintenance.BUILD_DEVICE_RUN for s in schedules):
            schedules = (
                *schedules,
                Schedule(maintenance.BUILD_DEVICE_RUN, settings.device_run_interval_s),
            )
        self._schedules = schedules
        self._collect_fanout = collect_fanout
        self._tick_s = tick_s
        self._standby_s = standby_s
        self._clock = clock or (lambda: datetime.now(UTC))
        self._sleep = sleep or asyncio.sleep
        self._due: dict[str, datetime] = {}

    def kinds(self) -> list[str]:
        """The kinds this instance schedules, the device-run schedule included."""
        return [s.kind for s in self._schedules]

    def arm(self, now: datetime | None = None) -> None:
        """Set the first due time for every schedule.

        The first due time is the start time plus one interval plus the jitter
        of the kind.
        """
        start = now if now is not None else self._clock()
        for schedule in self._schedules:
            self._due[schedule.kind] = start + timedelta(
                seconds=schedule.interval + jitter(schedule.kind, schedule.interval)
            )

    def due(self, now: datetime) -> list[Schedule]:
        return [s for s in self._schedules if self._due.get(s.kind, now) <= now]

    async def tick(self, now: datetime | None = None) -> list[str]:
        """Enqueue everything due, and report the kinds that were queued.

        A due kind whose guard returns False, or whose previous job is pending,
        is not queued. The next due time of a due kind is `now` plus one
        interval. A kind whose enqueue raises stays due, and the next tick
        queues it.
        """
        moment = now if now is not None else self._clock()
        queued: list[str] = []
        ready = self.due(moment)
        if ready:
            limits = await retention.resolve(self._store, self._settings)
            for schedule in ready:
                following = moment + timedelta(seconds=schedule.interval)
                if not schedule.guard(limits):
                    self._due[schedule.kind] = following
                    continue
                job = await queue.enqueue(
                    self._store,
                    schedule.kind,
                    not_before=moment,
                    triggered_by=TRIGGERED_BY,
                    now=moment,
                )
                self._due[schedule.kind] = following
                if job is None:
                    log.info(
                        "%s not queued: the previous one has not finished; skipping this turn",
                        schedule.kind,
                    )
                    continue
                queued.append(schedule.kind)
        if self._collect_fanout:
            queued.extend(await self.fanout_collect(moment))
        return queued

    def _device_due(self, interval: int, status: DeviceStatus | None, now: datetime) -> bool:
        """Whether a device is due. A device with no status row is due
        immediately. Any other device is due at the last attempt plus the
        interval. The interval doubles per consecutive failure of the device,
        up to `collect_backoff_cap_s`."""
        if status is None or status.last_attempt_at is None:
            return True
        cap = max(interval, self._settings.collect_backoff_cap_s)
        delay = min(interval * (2 ** min(status.consecutive_failures, 16)), cap)
        return status.last_attempt_at + timedelta(seconds=delay) <= now

    async def _due_targets(
        self, rows: list[Source], fleets: dict[str, list[Device]]
    ) -> list[tuple[Source, str, int]]:
        """The (source, host, interval) triples that are eligible for a fetch
        job in this tick, before the due check. Each enabled target of every
        enabled source gives one triple. A controller source is one target. A
        group source with no fleet row and no `host` gives no triple.

        Under resolver v1 the interval is `interval_s` of the group. Under v2
        the interval is the resolved profile interval of the target from
        `EffectiveCollection`. A target that the inventory has disabled or
        archived is not eligible.
        """
        context = await inventory_collection.execution_context(self._store)
        eligible: list[tuple[Source, str, int]] = []

        def legacy_interval(row: Source) -> int:
            try:
                return int(row.config.get("interval_s") or 0)
            except (TypeError, ValueError):
                return 0

        def hosts_of(row: Source) -> tuple[list[Device], list[str]] | None:
            fleet = fleets.get(row.name, [])
            enabled = [d for d in fleet if d.enabled]
            if fleet and not enabled:
                return None  # a wholly disabled fleet collects nothing
            if not fleet and glue.is_group(row.type) and not row.config.get("host"):
                return None  # The source has no fleet row and no implicit host.
            return enabled, [d.host for d in enabled] or [str(row.config.get("host") or "")]

        if not context.v2:
            for row in rows:
                interval = legacy_interval(row)
                if not row.enabled or interval <= 0:
                    continue
                found = hosts_of(row)
                if found is None:
                    continue
                eligible.extend((row, host, interval) for host in found[1])
            return eligible
        async with self._store.inventory().transaction() as tx:
            resolver = inventory_collection.Resolver(tx, self._settings, context=context)
            for row in rows:
                if not row.enabled:
                    continue
                found = hosts_of(row)
                if found is None:
                    continue
                devices, hosts = found
                by_host = {d.host: d for d in devices}
                for host in hosts:
                    try:
                        resolved = await resolver.resolve(row, device=by_host.get(host), host=host)
                    except inventory_collection.ResolutionError as exc:
                        log.info("%s/%s not scheduled: %s", row.name, host, exc)
                        continue
                    if not resolved.enabled or resolved.interval_s <= 0:
                        continue
                    eligible.append((row, host, resolved.interval_s))
        return eligible

    async def fanout_collect(self, now: datetime) -> list[str]:
        """Queue the per-device collection jobs of this tick.

        Every enabled source whose group config sets `interval_s` gets one
        `collect.fetch` job per due enabled device, or one for its implicit
        single host when it has no fleet. The `one_pending_per_kind` index
        refuses a job for a device whose previous job has not finished.

        The setting `collect_queue_high_water` bounds the total queue depth. At
        or above it this tick enqueues nothing, and the devices stay due.

        Under resolver v2 the interval is the resolved profile interval of the
        target (`_due_targets`). The dedup key, the per-device backoff and the
        queue bound are the same under both resolvers."""
        depth = await queue.depth(self._store)
        pending = depth.get("queued", 0) + depth.get("running", 0)
        budget = self._settings.collect_queue_high_water - pending
        if budget <= 0:
            log.info(
                "collect fan-out shed: %d jobs pending, high water %d",
                pending,
                self._settings.collect_queue_high_water,
            )
            return []
        fleets: dict[str, list[Device]] = {}
        for device in await self._store.list_devices():
            fleets.setdefault(device.source, []).append(device)
        statuses = {(st.source, st.host): st for st in await self._store.list_device_status()}
        queued: list[str] = []
        seen: set[tuple[str, str]] = set()
        for row, host, interval in await self._due_targets(await self._store.list_sources(), fleets):
            if budget <= 0:
                break
            if (row.name, host) in seen:
                continue  # One job is queued per eligible target.
            seen.add((row.name, host))
            if not self._device_due(interval, statuses.get((row.name, host)), now):
                continue
            job = await queue.enqueue(
                self._store,
                FETCH_KIND,
                source=row.name,
                device=host or None,
                not_before=now,
                triggered_by=TRIGGERED_BY,
                now=now,
            )
            if job is not None:
                queued.append(f"{FETCH_KIND}:{row.name}/{host}" if host else f"{FETCH_KIND}:{row.name}")
                budget -= 1
        return queued

    async def run(self) -> None:
        """Stand by until this process leads, then schedule until cancelled.

        The leader holds the advisory lock during the whole inner loop. Leaving
        the loop releases the lock.

        A new leader first reconciles the latest inventory publication
        (`collection.reconcile_on_startup`). A publication whose pointer moved
        and whose read-model apply did not complete is retried before any job
        of this leader stages a newer publication.

        A leader whose lock connection stops answering leaves the inner loop
        and stands by again.
        """
        while True:
            lost = asyncio.Event()
            async with self._store.try_scheduler_lock(on_lost=lost.set) as leader:
                if not leader:
                    await self._sleep(self._standby_s)
                    continue
                log.info("scheduler: this process is the leader")
                try:
                    await inventory_collection.reconcile_on_startup(self._store)
                except Exception as exc:
                    log.warning(
                        "inventory reconcile at leadership failed (%s: %s); continuing",
                        type(exc).__name__,
                        exc,
                    )
                self.arm()
                while True:
                    await self._sleep(self._tick_s)
                    if lost.is_set():
                        log.warning("scheduler: the leader lock is lost; this process stands by")
                        break
                    try:
                        queued = await self.tick()
                    except Exception as exc:
                        # A tick that cannot reach the database keeps leadership.
                        log.warning(
                            "scheduler tick failed (%s: %s); retrying next tick",
                            type(exc).__name__,
                            exc,
                        )
                        continue
                    if queued:
                        log.info("scheduler queued: %s", ", ".join(queued))


def kinds(schedules: Iterable[Schedule] = SYSTEM_SCHEDULES) -> list[str]:
    return [s.kind for s in schedules]
