"""Reader for the BGP session and path observations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .ribsource import holds_parquet, run_ts
from .uid import slug

if TYPE_CHECKING:
    from .snapshot import Snapshot

# The two tables this reader answers from, and the columns each read returns.
ROUTES = "bgp_session_routes"
SESSIONS = "bgp_sessions"
TABLES: tuple[str, ...] = (ROUTES, SESSIONS)

_ROUTE_COLUMNS = (
    "device_uid, context_uid, session_uid, peer_ip, af, safi, direction, rib_type, policy_stage, "
    "path_id, prefix, prefixlen, next_hop, next_hop_context_uid, as_path, local_pref, med, origin, "
    "communities, best"
)
_SESSION_COLUMNS = (
    "device_uid, context_uid, session_uid, peer_ip, af, safi, state, established_since_ms, "
    "prefixes_received, prefixes_advertised, capabilities"
)


# --- the evidence of a published snapshot for each device -------------------------------


@dataclass(frozen=True)
class DeviceEvidence:
    """The run and the outcome that the manifest of the pinned snapshot records
    for one device and one of the 2 tables.

    `source` and `host` are the slugged directory names of the store layout.
    `outcome` is the recorded `TableOutcome` status, `missing` when a recorded
    file is not on disk, or None when no manifest records an outcome. Only
    `complete` selects a file, in `path`.
    """

    source: str
    host: str
    run_id: str | None
    outcome: str | None
    path: Path | None = None
    detail: str = ""


@dataclass
class SnapshotEvidence:
    """The BGP evidence of one published snapshot.

    `devices` holds, for each table, the `DeviceEvidence` of each device in the
    manifest. `directions` holds the outcome status of each session direction,
    keyed (session_uid, direction).
    """

    snapshot_key: int
    data_dir: Path
    devices: dict[str, list[DeviceEvidence]]
    directions: dict[tuple[str, str], str]
    _by_run: dict[tuple[str, str], DeviceEvidence] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        for table, entries in self.devices.items():
            for device in entries:
                if device.run_id is not None:
                    self._by_run.setdefault((table, device.run_id), device)

    def files(self, table: str) -> list[Path]:
        """Every file the snapshot selects for one table, each once, in path order."""
        return sorted({d.path for d in self.devices.get(table, ()) if d.path is not None})

    def by_run(self, table: str, run_id: str) -> DeviceEvidence | None:
        """Return the evidence of the device whose run for `table` is `run_id`, or None."""
        return self._by_run.get((table, run_id))


def snapshot_evidence(settings: Any, cts: int | None, *, manifest: Any = None) -> SnapshotEvidence | None:
    """Return the BGP evidence of the snapshot pinned at `cts`.

    The result is None when `cts` is None, when the settings have no manifests
    directory (a fixture store), or when the manifest of the key cannot be read.
    """
    if cts is None:
        return None
    # The import is local. core/manifest.py imports `run_ts` from core/ribsource.py.
    from . import manifest as manifestmod

    record = manifest
    if record is None:
        if getattr(settings, "manifests_dir", None) is None:
            return None
        try:
            record = manifestmod.read(settings, cts)
        except (OSError, ValueError):
            return None
    data_dir = Path(settings.hst_data_dir)
    store_dir = Path(settings.sidestore_dir)
    devices: dict[str, list[DeviceEvidence]] = {table: [] for table in TABLES}
    directions: dict[tuple[str, str], str] = {}
    # `published` holds the first published sidestore file of each (table, run).
    published: dict[tuple[str, str | None], Any] = {}
    for f in record.files:
        if f.kind == "sidestore":
            published.setdefault((f.table, f.run_id), f)
    for entry in record.devices:
        for key, outcome in manifestmod.bgp_direction_outcomes(entry.tables).items():
            directions[key] = outcome.status
        for table in TABLES:
            evidence = _device_evidence(entry, published, table, data_dir, store_dir)
            if evidence is not None:
                devices[table].append(evidence)
    return SnapshotEvidence(cts, data_dir, devices, directions)


def _device_evidence(
    entry: Any, published: dict[tuple[str, str | None], Any], table: str, data_dir: Path, store_dir: Path
) -> DeviceEvidence | None:
    """Resolve one `DeviceEntry` to the run and the outcome for one table.

    A device that the run collected has its recorded outcome and the file that
    the run published for it. A carried or unchanged device uses the run in
    `effective_run`. Its outcome is `complete` when the snapshot publishes a
    file of the table for that run.
    """
    source, host = slug(entry.source), slug(entry.host)
    run_id = entry.effective_run
    recorded = entry.tables.get(table)
    file = published.get((table, run_id))
    if recorded is not None and recorded.status != "unchanged":
        return _resolve(source, host, run_id, recorded.status, file, data_dir, store_dir)
    if run_id is None:
        return None
    if file is None:
        return DeviceEvidence(
            source, host, run_id, None, detail=f"this snapshot publishes no {table} file for run {run_id}"
        )
    return _resolve(source, host, run_id, "complete", file, data_dir, store_dir)


def _resolve(
    source: str,
    host: str,
    run_id: str | None,
    status: str | None,
    entry: Any,
    data_dir: Path,
    store_dir: Path,
) -> DeviceEvidence:
    """Return the evidence of a device whose run is `run_id`, from the status
    recorded for the table and the file entry published for it."""
    if status != "complete":
        return DeviceEvidence(source, host, run_id, status)
    if entry is None:
        return DeviceEvidence(source, host, run_id, "missing", detail=f"run {run_id} published no file")
    path = data_dir / entry.path
    if not _under(path, store_dir):
        return DeviceEvidence(source, host, run_id, "missing", detail=f"{entry.path} is outside the store")
    if not path.is_file():
        return DeviceEvidence(source, host, run_id, "missing", detail=f"{entry.path} is not on disk")
    return DeviceEvidence(source, host, run_id, "complete", path)


def _under(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


def _sql_str(value: str) -> str:
    """Return a SQL string literal. DuckDB binds no parameter into a file list."""
    return "'" + value.replace("'", "''") + "'"


def compare(before: Iterable[str], after: Iterable[str]) -> dict[str, list[str]]:
    """Return the prefixes added and removed between 2 readings of one session and direction.

    The result is the set difference of 2 prefix lists, each read from its own
    snapshot. Both result lists are sorted.
    """
    old, new = set(before), set(after)
    return {"added": sorted(new - old), "removed": sorted(old - new)}


# --- the reader -------------------------------------------------------------------------


class BgpSource:
    """Read-only queries over one snapshot's BGP session and path observations.

    Each table has its own view. The view reads the published file list when
    the instance has snapshot evidence. Without evidence the view reads a glob
    of the table directory.
    """

    def __init__(
        self, base_dir: Path, *, as_of_ms: int | None = None, evidence: SnapshotEvidence | None = None
    ) -> None:
        self._base_dir = Path(base_dir)
        self._as_of_ms = as_of_ms
        self._evidence = evidence
        self._con: Any = None
        self._unavailable = False
        self._views: set[str] = set()
        self._run_cache: dict[tuple[str, str, str], str | None] = {}

    def _connect(self) -> Any:
        if self._con is not None:
            return self._con
        if self._unavailable:
            return None
        if not self._base_dir.is_dir():
            self._unavailable = True
            return None
        try:
            # sidestore raises RuntimeError without pyarrow
            from hst.core import sidestore
        except (ImportError, RuntimeError):
            self._unavailable = True
            return None
        try:
            # The read-only catalog rejects CREATE of a view that is not TEMP.
            con = sidestore.connect_reader(self._base_dir)
        except ImportError:
            self._unavailable = True
            return None
        for table in TABLES:
            source = self._view_source(table)
            if source is None:
                continue
            # Both interpolations are paths this process read off disk or out of a manifest.
            con.execute(f"CREATE TEMP VIEW {table} AS SELECT * FROM {source}")  # noqa: S608
            self._views.add(table)
        self._con = con
        return con

    def _view_source(self, table: str) -> str | None:
        """Return the `read_parquet(...)` expression that the view of one table
        scans, or None when this snapshot has no file for the table."""
        if self._evidence is None:
            directory = self._base_dir / table
            if not holds_parquet(directory):
                return None
            glob = _sql_str(f"{directory.as_posix()}/**/*.parquet")
            return f"read_parquet({glob}, union_by_name=true)"
        files = self._evidence.files(table)
        if not files:
            return None
        return f"read_parquet([{', '.join(_sql_str(p.as_posix()) for p in files)}], union_by_name=true)"

    def close(self) -> None:
        """Release the connection. Another reader of the same store may be
        open beside it (`sidestore.connect_reader`)."""
        if self._con is not None:
            self._con.close()
            self._con = None
        self._unavailable = False
        self._views = set()
        self._run_cache = {}

    @property
    def available(self) -> bool:
        """Whether duckdb is importable and the store directory exists."""
        return self._connect() is not None

    @property
    def approximate(self) -> bool:
        """Whether files are selected by age, with no published manifest."""
        return self._evidence is None

    def coverage(self, device_uid: str, table: str = ROUTES) -> str | None:
        """Return the `DeviceEvidence.outcome` that the pinned snapshot recorded
        for one device and one table.

        The result is None in approximate mode and when the snapshot selects no
        file of the table for the device.
        """
        if self._evidence is None:
            return None
        con = self._connect()
        if con is None:
            return None
        run_id = self._pick_run(con, table, "device_uid", device_uid)
        if run_id is None:
            return None
        found = self._evidence.by_run(table, run_id)
        return found.outcome if found is not None else None

    def direction_status(self, session_uid: str, direction: str) -> str | None:
        """Return the status that the pinned snapshot recorded for one direction
        of one session.

        The status is `complete`, `complete-empty`, `not-captured`, `failed` or
        `partial`. The result is None when the snapshot records nothing for the
        direction (a run that captured no BGP observations, or an approximate
        pin).

        `not-captured` is the status of a direction that the platform does not
        expose (a received table with no soft reconfiguration inbound) and of a
        direction that the capture setting of the source left out.
        """
        if self._evidence is None:
            return None
        return self._evidence.directions.get((session_uid, direction))

    def paths(
        self,
        device_uid: str,
        context_uid: str | None = None,
        prefix: str | None = None,
        *,
        direction: str | None = None,
        session_uid: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return the observed BGP paths of one device from the newest run within the bound.

        `context_uid` (the owning VrfInstance uid), `prefix`, `direction` and
        `session_uid` each narrow the result. None applies no filter. `prefix`
        matches the text form exactly.

        The rows are ordered by session, direction, prefix and path id. The
        result is [] when the store is not queryable, when the device has no run
        within the bound, or when no row matches.
        """
        con = self._connect()
        if con is None:
            return []
        run_id = self._pick_run(con, ROUTES, "device_uid", device_uid)
        if run_id is None:
            return []
        where = ["device_uid = ?", "run_id = ?"]
        params: list[Any] = [device_uid, run_id]
        for column, value in (
            ("context_uid", context_uid),
            ("prefix", prefix),
            ("direction", direction),
            ("session_uid", session_uid),
        ):
            if value is not None:
                where.append(f"{column} = ?")
                params.append(value)
        return self._rows(
            con,
            f"SELECT {_ROUTE_COLUMNS} FROM {ROUTES} WHERE {' AND '.join(where)} "  # noqa: S608
            "ORDER BY session_uid, direction, prefix, path_id",
            params,
        )

    def next_hop_context_consumers(self, context_uids: Iterable[str]) -> list[tuple[str, str | None]]:
        """Return (device_uid, context_uid) of every context that has an observed
        path with a next-hop context in `context_uids`.

        Only the paths of the picked run of each device count. The result is []
        when the store is not queryable or `context_uids` is empty."""
        wanted = sorted({str(c) for c in context_uids})
        con = self._connect()
        if con is None or ROUTES not in self._views or not wanted:
            return []
        rows = con.execute(
            f"SELECT DISTINCT device_uid, run_id, context_uid FROM {ROUTES} "  # noqa: S608
            "WHERE device_uid IS NOT NULL AND list_contains(?, next_hop_context_uid)",
            [wanted],
        ).fetchall()
        return sorted(
            {(r[0], r[2]) for r in rows if self._pick_run(con, ROUTES, "device_uid", r[0]) == r[1]},
            key=lambda t: (str(t[0]), str(t[1])),
        )

    def prefixes(self, session_uid: str, direction: str) -> list[str]:
        """Return the distinct prefixes of one direction of one session at this
        snapshot, sorted.

        The result is [] for a direction without prefixes and for a direction
        that this run did not capture.
        """
        con = self._connect()
        if con is None:
            return []
        run_id = self._pick_run(con, ROUTES, "session_uid", session_uid)
        if run_id is None:
            return []
        rows = self._rows(
            con,
            f"SELECT DISTINCT prefix FROM {ROUTES} "  # noqa: S608
            "WHERE session_uid = ? AND direction = ? AND run_id = ? ORDER BY prefix",
            [session_uid, direction, run_id],
        )
        return [r["prefix"] for r in rows if r["prefix"] is not None]

    def session_state(self, session_uid: str) -> dict[str, Any] | None:
        """Return the observed state of one session at this snapshot, or None when
        the snapshot holds no session row for it.

        A session whose state was not captured has no row. A session that the
        device reported down has a row.

        The result for a session with 2 or more families is the row of the first
        family in ascending order.
        """
        rows = self.sessions_for(session_uid)
        return rows[0] if rows else None

    def sessions_for(self, session_uid: str) -> list[dict[str, Any]]:
        """Every observed session row for one session uid at this snapshot, one
        per address family, ordered by family."""
        con = self._connect()
        if con is None:
            return []
        run_id = self._pick_run(con, SESSIONS, "session_uid", session_uid)
        if run_id is None:
            return []
        return self._rows(
            con,
            f"SELECT {_SESSION_COLUMNS} FROM {SESSIONS} "  # noqa: S608
            "WHERE session_uid = ? AND run_id = ? ORDER BY af, safi",
            [session_uid, run_id],
        )

    def _pick_run(self, con: Any, table: str, column: str, value: str) -> str | None:
        """Return the run for one key of one table.

        The run has the newest `snapshot_ts` at or before the bound. The fetch
        time in the run id breaks a tie. The instance caches the result for each
        (table, column, value).
        """
        cache_key = (table, column, value)
        if cache_key in self._run_cache:
            return self._run_cache[cache_key]
        if table not in self._views:
            self._run_cache[cache_key] = None
            return None
        rows = con.execute(
            f"SELECT run_id, max(snapshot_ts) FROM {table} WHERE {column} = ? GROUP BY run_id",  # noqa: S608
            [value],
        ).fetchall()
        snapshot_ts_by_run = {r[0]: r[1] for r in rows if r[0] is not None}
        run_ids = list(snapshot_ts_by_run)
        if self._as_of_ms is not None:
            # A lookup with a bound keeps only the runs that have a snapshot_ts
            # at or before the bound.
            run_ids = [
                rid
                for rid in run_ids
                if (snap := snapshot_ts_by_run[rid]) is not None and snap <= self._as_of_ms
            ]

        def _key(rid: str) -> tuple[int, int, int, str]:
            snap = snapshot_ts_by_run.get(rid)
            if snap is None:
                return (0, 0, 0, rid)
            fetch_ts = run_ts(rid)
            return (1, snap, fetch_ts if fetch_ts is not None else -1, rid)

        picked = max(run_ids, key=_key) if run_ids else None
        self._run_cache[cache_key] = picked
        return picked

    def _rows(self, con: Any, sql: str, params: list) -> list[dict[str, Any]]:
        cur = con.execute(sql, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]


def for_snapshot(snapshot: Snapshot) -> BgpSource:
    """Return the BgpSource of the side store, bounded to the `cts` of the pinned snapshot."""
    record = snapshot.manifest
    evidence = (
        None
        if record is None
        else snapshot.evidence(
            "bgp", lambda: snapshot_evidence(snapshot.settings, snapshot.cts, manifest=record)
        )
    )
    return BgpSource(snapshot.settings.sidestore_dir, as_of_ms=snapshot.cts, evidence=evidence)
