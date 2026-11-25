"""One snapshot resolved per request and shared by every reader of one answer.

A request resolves one snapshot once. All readers use the graph version and
the exact table references of that snapshot.

`resolve` returns a `Snapshot` that every reader of the answer shares. The
graph session pins to `snapshot.cts` through `path.pinned`. The side store
binds to the same run through `ribsource.for_snapshot`. `Snapshot.manifest`
reads the published record of the run at most once.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import cycle as cyclemod

# The `$snap` binding of an unpinned read, when no run exists. No versioned
# node has this value as its collection_ts. A read pinned with
# `x.collection_ts = $snap` returns no rows.
LIVE_SNAP = "live"


class NoRun(LookupError):
    """No run is published, and a read pinned to a run has no graph.

    Raised where a reader needs an integer `$snap`. The anchors of such a
    reader seek on obj_uid_cts at an exact collection_ts, and LIVE_SNAP
    matches none.
    """

    def __init__(self) -> None:
        super().__init__("no run is published yet")


def snap_param(cts: int | None) -> Any:
    """The `$snap` binding of a resolved snapshot. It is the collection_ts, or
    LIVE_SNAP when nothing is pinned."""
    return cts if cts is not None else LIVE_SNAP


@dataclass(frozen=True)
class DeviceCompleteness:
    """What the snapshot's manifest records about one device's collection.

    `outcome` is the `DeviceEntry` verdict: "collected", "partial",
    "unchanged", "failed" or "carried". `sections` maps each section of the
    device's collection to the status it produced, and `tables` does the same
    for the side-store tables the device's collector declares.
    `effective_run` is the run whose payload provides the device's state in
    this snapshot. `carried` is true when the source did not run in this
    snapshot.
    """

    source: str
    host: str
    outcome: str
    effective_run: str | None
    carried: bool
    sections: dict[str, str]
    tables: dict[str, str]


@dataclass
class Snapshot:
    """The run one answer is computed from, resolved once and shared.

    `cts` is the collection_ts of the run. It is the current run of the
    pointer, the run that a caller named, or None when no run is pinned.

    `manifest` is the published record of the run, read from disk on first
    use and kept. It is None when no run is pinned, when the settings have no
    manifests directory (a fixture store), and when the run has no manifest.
    """

    cts: int | None
    settings: Any
    _manifest: Any = field(default=None, init=False, repr=False, compare=False)
    _manifest_read: bool = field(default=False, init=False, repr=False, compare=False)
    _evidence: dict[Any, Any] = field(default_factory=dict, init=False, repr=False, compare=False)
    _completeness: dict[str, DeviceCompleteness] | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def evidence(self, key: Any, build: Callable[[], Any]) -> Any:
        """What `build` returns for `key`, built once per `Snapshot`."""
        if key not in self._evidence:
            self._evidence[key] = build()
        return self._evidence[key]

    @property
    def manifest(self) -> Any:
        """The run's `SnapshotManifest`, or None when nothing published
        governs it. Read once per `Snapshot`."""
        if not self._manifest_read:
            self._manifest_read = True
            self._manifest = self._read_manifest()
        return self._manifest

    def _read_manifest(self) -> Any:
        if self.cts is None or getattr(self.settings, "manifests_dir", None) is None:
            return None
        # The import is deferred because core/manifest.py imports run_ts from core/ribsource.py.
        from . import manifest as manifestmod

        try:
            return manifestmod.read(self.settings, self.cts)
        except (OSError, ValueError):
            return None

    @property
    def approximate(self) -> bool:
        """Whether readers work from what the run published or from file age.

        True when no manifest governs the run. A `RibSource` is then
        approximate. The newest file at or before the bound answers for each
        device, whether or not the run that wrote it published.
        """
        return self.manifest is None

    @property
    def snapshot_id(self) -> str | None:
        """The run id as a string for an API response, or None when unpinned."""
        return None if self.cts is None else str(self.cts)

    def completeness(self) -> dict[str, DeviceCompleteness]:
        """Per-device completeness from the manifest, keyed by "source/host".

        Empty when no manifest governs the run.
        """
        if self._completeness is not None:
            return self._completeness
        record = self.manifest
        if record is None:
            return {}
        self._completeness = {
            f"{entry.source}/{entry.host}": DeviceCompleteness(
                source=entry.source,
                host=entry.host,
                outcome=entry.outcome,
                effective_run=entry.effective_run,
                carried=entry.carried,
                sections={name: outcome.status for name, outcome in sorted(entry.sections.items())},
                tables={name: outcome.status for name, outcome in sorted(entry.tables.items())},
            )
            for entry in record.devices
        }
        return self._completeness

    def device_completeness(self, source: str, host: str) -> DeviceCompleteness | None:
        """What the manifest records for one device, or None when the run's
        manifest does not hold it (or no manifest governs the run)."""
        return self.completeness().get(f"{source}/{host}")


def resolve(session: Any, settings: Any, cts: int | None = None) -> Snapshot:
    """The snapshot one request answers from.

    With `cts` given, that run is the snapshot and no pointer is read.
    Without one, the pointer is read once.
    """
    return Snapshot(cts if cts is not None else cyclemod.current_ts_or_none(session), settings)


# One node stamped with the run's collection_ts is enough to show the run's
# graph is retained. It is the same version key `grapharchive` reads.
_RETAINED_GRAPH = "MATCH (n:Obj {collection_ts: $snap}) RETURN n.uid AS uid LIMIT 1"

_MAX_RUN_ID = 2**63 - 1


def parse_snapshot_id(value: str | int | None) -> int | None:
    """The run id a request names, or None when it names none.

    None and the empty string mean the caller named no run, and the caller
    resolves the pointer. Any other value must be a run id written in ASCII
    digits, and a value that is not raises `ValueError`. A route maps the
    error to 400, the agent to an error step and MCP to an error payload.
    """
    if value is None or value == "":
        return None
    text = str(value)
    if not (text.isascii() and text.isdigit()):
        raise ValueError(f"snapshot {text!r} is not a run id; a run id is written in digits only")
    cts = int(text)
    if cts > _MAX_RUN_ID:
        # The graph stores run ids as 64-bit integers, and the driver cannot send a larger one.
        raise ValueError(f"snapshot {text!r} is not a run id; it exceeds the 64-bit integer range")
    return cts


def require_retained(session: Any, cts: int) -> None:
    """Raise `ValueError` unless the graph still holds objects of run `cts`."""
    # The import is deferred because hst.path imports core modules at load
    # time. The read goes through `hst.path._read`, which tests replace.
    from hst import path as pathmod

    if not pathmod._read(session, _RETAINED_GRAPH, snap=cts):
        raise ValueError(f"unknown run {cts}: no retained graph objects")
