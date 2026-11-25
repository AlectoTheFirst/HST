"""The retention limits of the deployment."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from hst.app.store import Store
from hst.core import Settings
from hst.core import manifest as manifestmod
from hst.core.uid import slug

SETTINGS_KEY = "retention"

MAX_KEEP_RUNS = 10_000
MAX_RETENTION_DAYS = 36_500


@dataclass(frozen=True)
class Retention:
    """The effective limits. Stored values override the environment defaults.

    `cycle_keep_runs` is a count of collection cycles and is at least 1.
    `cycle_keep_device_runs` counts device and refresh runs apart from the
    cycles (`core/cycle.py` `_partition`). A value of 0 keeps none beyond the
    current run. The 3 day counts are ages in days, and 0 keeps everything.
    The 3 AI limits follow the same rule. Conversations age by their last
    message, step results by the start of the step and AI events by their
    time. Compaction of a step result keeps the digest and the summary.
    """

    cycle_keep_runs: int
    login_event_retention_days: int
    cypher_event_retention_days: int
    job_history_retention_days: int
    ai_conversation_retention_days: int
    ai_step_result_days: int
    ai_event_retention_days: int
    cycle_keep_device_runs: int


def defaults(settings: Settings) -> Retention:
    return Retention(
        cycle_keep_runs=settings.cycle_keep_runs,
        login_event_retention_days=settings.login_event_retention_days,
        cypher_event_retention_days=settings.cypher_event_retention_days,
        job_history_retention_days=settings.job_history_retention_days,
        ai_conversation_retention_days=settings.ai_conversation_retention_days,
        ai_step_result_days=settings.ai_step_result_days,
        ai_event_retention_days=settings.ai_event_retention_days,
        cycle_keep_device_runs=settings.cycle_keep_device_runs,
    )


def merged(stored: dict | None, settings: Settings) -> Retention:
    """Stored values over the environment, field by field."""
    env = defaults(settings)
    row = stored or {}

    def pick(name: str, fallback: int) -> int:
        value = row.get(name)
        return value if isinstance(value, int) and not isinstance(value, bool) else fallback

    return Retention(
        cycle_keep_runs=max(1, pick("cycle_keep_runs", env.cycle_keep_runs)),
        login_event_retention_days=max(0, pick("login_event_retention_days", env.login_event_retention_days)),
        cypher_event_retention_days=max(
            0, pick("cypher_event_retention_days", env.cypher_event_retention_days)
        ),
        job_history_retention_days=max(0, pick("job_history_retention_days", env.job_history_retention_days)),
        ai_conversation_retention_days=max(
            0, pick("ai_conversation_retention_days", env.ai_conversation_retention_days)
        ),
        ai_step_result_days=max(0, pick("ai_step_result_days", env.ai_step_result_days)),
        ai_event_retention_days=max(0, pick("ai_event_retention_days", env.ai_event_retention_days)),
        cycle_keep_device_runs=max(0, pick("cycle_keep_device_runs", env.cycle_keep_device_runs)),
    )


async def resolve(store: Store, settings: Settings) -> Retention:
    row = await store.get_setting(SETTINGS_KEY)
    return merged(row.value if row else None, settings)


# A manifest `FileEntry` identifies a raw or side-store file by (source, host, run_id).
Identity = tuple[str, str, str]


def manifest_protected_identities(settings: Settings, kept: Iterable[int]) -> tuple[set[Identity], list[int]]:
    """Return the (source, host, run_id) identities that the manifests of the
    runs in `kept` need, and the runs of `kept` with no manifest to read.

    Each manifest adds the identity of every file that it lists and the
    effective run of every device in it, also of a carried device. A listed
    file is a raw or side-store file that the run wrote or joined.
    `DeviceEntry.source` and `DeviceEntry.host` are the row name and the host
    as configured. They are slugged here to match the directory form of
    `FileEntry`.

    A run in `kept` with no manifest on disk adds nothing to the protected set.
    """
    protected: set[Identity] = set()
    unmanifested: list[int] = []
    for cts in sorted(kept):
        try:
            record = manifestmod.read(settings, cts)
        except (FileNotFoundError, ValueError):
            unmanifested.append(cts)
            continue
        for f in record.files:
            protected.add((f.source, f.host, f.run_id))
        for d in record.devices:
            if d.effective_run:
                protected.add((slug(d.source), slug(d.host), d.effective_run))
    return protected, unmanifested


@dataclass(frozen=True)
class Plan:
    """The runs and the file identities that retention keeps at one moment.

    Every prune path reads one `Plan`. It is built once per turn under the
    cycle lock.

    `window` is the retention of the graph (`core/cycle.py` `retained_runs`).
    It holds the newest cycles, a bounded window of device and refresh runs,
    and any run that is being built. `refs` holds the runs that assessments
    reference. `leased` holds the runs that a reader holds open. The runs of
    `refs` and `leased` are kept whole, and their manifest chains are not
    added to the kept set. `protected` holds the file identities that the
    manifests of every kept run bind. `unmanifested` holds the kept runs with
    no manifest.
    """

    window: frozenset[int]
    refs: frozenset[int]
    leased: frozenset[int]
    protected: frozenset[Identity]
    unmanifested: tuple[int, ...]

    @property
    def kept(self) -> frozenset[int]:
        """Every run key a prune path leaves whole."""
        return self.window | self.refs | self.leased

    @property
    def ceiling(self) -> int | None:
        """The newest run key retention has named. A file stamped above it
        belongs to a run in flight."""
        return max(self.window) if self.window else None

    @property
    def floor(self) -> int | None:
        """The newest kept run with no manifest. The files that it carried forward
        are not known. No file stamped at or below its key is deleted this turn."""
        return max(self.unmanifested) if self.unmanifested else None

    def keeps(self, run_key: int, identity: Identity) -> bool:
        """Return whether a raw or side-store file with the stamp `run_key` and
        the path identity `identity` is kept."""
        if run_key in self.kept or identity in self.protected:
            return True
        if self.floor is not None and run_key <= self.floor:
            return True
        return self.ceiling is not None and run_key > self.ceiling


def plan(
    settings: Settings,
    window: Iterable[int],
    refs: Iterable[int] = (),
    leased: Iterable[int] = (),
) -> Plan:
    """Build the `Plan` for the retained `window` of the graph, the assessment
    `refs` and the `leased` runs.

    The call reads the manifest of every kept run. The caller runs it in a
    worker thread."""
    win, ref, lease = frozenset(window), frozenset(refs), frozenset(leased)
    protected, unmanifested = manifest_protected_identities(settings, win | ref | lease)
    return Plan(win, ref, lease, frozenset(protected), tuple(unmanifested))
