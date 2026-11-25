"""Reader of the OSPF link-state database rows in the side store."""

from __future__ import annotations

from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .ribsource import (
    ORPHAN_WALK_MAX,
    DeviceEvidence,
    SnapshotEvidence,
    holds_parquet,
    pick_run,
    recorded_orphans,
    run_ts,
    snapshot_evidence,
    time_limit,
)

if TYPE_CHECKING:
    from .snapshot import Snapshot

# The name of the side-store table and of the TEMP view over it.
TABLE = "ospf_lsdb"

_COLUMNS = (
    "process, area, lsa_type, lsid, adv_router, seq, age, metric, "
    "links, attached_routers, mask, forwarding_address, metric_type"
)
# The columns that identify one LSA within a database. `OspfSource.lsdb`
# returns its rows in this order.
_ORDER = "area, lsa_type, lsid, adv_router"

# `_PREFIX_SEARCH` selects the prefixes that the LSAs of the selected runs
# hold, as integer intervals (`OspfSource.search_prefixes`). A prefix is the
# link state id and the mask of an LSA that is not a router LSA and has a
# mask, or the link id and the link data of a stub link of a router LSA.
# `_DOTTED` converts a dotted quad to an integer. A dotted quad that does not
# parse gives no prefix. `{marks}` is the placeholder list of the (device,
# run) keys. `OspfSource.search_prefixes` fills `{where}`, `{order}`,
# `{id_expr}` and `{mask_expr}` with fixed SQL text.
_DOTTED = (
    "(try_cast(split_part({v}, '.', 1) AS BIGINT) << 24)"
    " | (try_cast(split_part({v}, '.', 2) AS BIGINT) << 16)"
    " | (try_cast(split_part({v}, '.', 3) AS BIGINT) << 8)"
    " | try_cast(split_part({v}, '.', 4) AS BIGINT)"
)
_PREFIX_SEARCH = (
    "WITH cur AS (SELECT * FROM {table} WHERE device_uid || chr(31) || run_id IN ({marks})), "
    "held AS ("
    "SELECT device_uid, context_uid, process, area, lsa_type, lsid, adv_router, metric, run_id, "
    "lsid AS p_id, mask AS p_mask FROM cur WHERE lsa_type <> 'router' AND mask IS NOT NULL "
    "UNION ALL "
    "SELECT device_uid, context_uid, process, area, lsa_type, lsid, adv_router, lk.metric AS metric, run_id, "
    "lk.link_id AS p_id, lk.link_data AS p_mask "
    "FROM (SELECT *, unnest(links) AS lk FROM cur WHERE lsa_type = 'router') WHERE lk.link_type = 'stub'"
    "), "
    "num AS (SELECT *, {id_expr} AS id_int, {mask_expr} AS mask_int FROM held), "
    "nets AS (SELECT *, id_int & mask_int AS net_lo, "
    "(id_int & mask_int) | (~mask_int & 4294967295) AS net_hi, "
    "bit_count(mask_int) AS prefixlen FROM num WHERE id_int IS NOT NULL AND mask_int IS NOT NULL) "
    "SELECT device_uid, context_uid, process, area, lsa_type, lsid, adv_router, metric, run_id, "
    "net_lo AS net, prefixlen FROM nets WHERE {where} "
    "ORDER BY {order}, device_uid, context_uid, area, lsa_type, lsid, adv_router LIMIT ?"
)


def _sql_str(value: str) -> str:
    """Return `value` as a SQL string literal. DuckDB binds no parameter into a file list."""
    return "'" + value.replace("'", "''") + "'"


class OspfSource:
    """Read-only queries over a device's OSPF link-state database runs.

    One instance is bound to one `as_of_ms`. The instance caches the run that
    it picks for each device. The instance writes no parquet file.
    """

    def __init__(
        self, base_dir: Path, *, as_of_ms: int | None = None, evidence: SnapshotEvidence | None = None
    ) -> None:
        # With `as_of_ms`, only a run whose `snapshot_ts` is at or before
        # `as_of_ms` is selected. With None, the newest run is selected.
        # With `evidence`, the reader reads only the files that the manifest of
        # the pinned snapshot publishes for this table. Without `evidence`, the
        # reader reads every file under ospf_lsdb/.
        self._base_dir = Path(base_dir)
        self._as_of_ms = as_of_ms
        self._evidence = evidence
        self._con: Any = None
        self._unavailable = False
        self._has_view = False
        self._run_id_cache: dict[str, str | None] = {}
        self._orphans: dict[str, DeviceEvidence] | None = None

    def _connect(self) -> Any:
        if self._con is not None:
            return self._con
        if self._unavailable:
            return None

        table_dir = self._base_dir / TABLE
        files = None if self._evidence is None else self._evidence.files
        # DuckDB resolves the glob when the view is created, and the glob needs
        # a parquet file under the table directory. With `evidence`, the reader
        # opens the files that the manifest lists, and a manifest that lists no
        # file gives a connection with no view. `base_dir` holds the catalog
        # file and is the only directory that the connection can read under.
        present = holds_parquet(table_dir) if files is None else self._base_dir.is_dir()
        if not present:
            self._unavailable = True
            return None

        try:
            # sidestore raises RuntimeError when pyarrow is not installed.
            from hst.core import sidestore
        except (ImportError, RuntimeError):
            self._unavailable = True
            return None
        try:
            # The connection is read-only, reads only under base_dir and has
            # limits on memory, threads and spill. The read-only catalog
            # rejects the CREATE of a view that is not TEMP.
            con = sidestore.connect_reader(self._base_dir)
        except ImportError:
            self._unavailable = True
            return None
        # union_by_name fills NULL for a column a file lacks. Files nest under
        # <source>/<host>/.
        if files is None:
            glob = _sql_str(f"{table_dir.as_posix()}/**/*.parquet")
            source = f"read_parquet({glob}, union_by_name=true)"
        else:
            source = f"read_parquet([{', '.join(_sql_str(p.as_posix()) for p in files)}], union_by_name=true)"
        if files is None or files:
            con.execute(f"CREATE TEMP VIEW {TABLE} AS SELECT * FROM {source}")  # noqa: S608 - paths off disk
            self._has_view = True
        self._con = con
        return con

    def close(self) -> None:
        """Release the connection. Another reader of the same store may be
        open beside it (`sidestore.connect_reader`)."""
        if self._con is not None:
            self._con.close()
            self._con = None
        self._unavailable = False
        self._has_view = False
        self._run_id_cache = {}
        self._orphans = None

    @property
    def available(self) -> bool:
        """Whether DuckDB is importable and the store is present."""
        return self._connect() is not None

    @property
    def approximate(self) -> bool:
        """Whether the reader selects files by age, without a published manifest.

        True for a pin with no manifest, for a fixture store and for a read
        with no pin. The newest run at or before the bound answers for each
        device, including a run that did not publish."""
        return self._evidence is None

    def has_rows(self, device_uid: str) -> bool:
        """Whether the store holds any run for this device within the bound."""
        con = self._connect()
        return con is not None and self._latest_run_id(con, device_uid) is not None

    def coverage(self, device_uid: str) -> str | None:
        """Return the outcome that the pinned snapshot recorded for the
        `ospf_lsdb` table of this device. The value is a
        `DeviceEvidence.outcome` value: `complete`, `complete-empty`,
        `unsupported`, `failed`, `partial` or `missing`. The value is None
        when no published manifest records the device, and in approximate
        mode.
        """
        if self._evidence is None:
            return None
        con = self._connect()
        if con is not None:
            run_id = self._latest_run_id(con, device_uid)
            if run_id is not None:
                selected = self._evidence.by_run(run_id)
                if selected is not None:
                    return selected.outcome
        found = self._orphans_by_device_uid().get(device_uid)
        return found.outcome if found is not None else None

    def context_coverage(self, context_uid: str) -> str | None:
        """Return the outcome that the pinned snapshot recorded for the
        link-state database of one forwarding context
        (`manifest.ospf_context_key`). The value is `complete`,
        `complete-empty`, or `not-captured` for a context whose process the
        run did not read. The value is None when the snapshot records nothing
        for the context (a device that did not state the context, an
        unchanged device, an approximate pin). `coverage` returns the outcome
        of the whole device."""
        if self._evidence is None:
            return None
        return self._evidence.contexts.get(context_uid)

    def contexts_with_rows(self, device_uid: str) -> set[str]:
        """The contexts the device's selected run holds LSAs for."""
        con = self._connect()
        if con is None:
            return set()
        run_id = self._latest_run_id(con, device_uid)
        if run_id is None:
            return set()
        rows = con.execute(
            f"SELECT DISTINCT context_uid FROM {TABLE} "  # noqa: S608 - a module constant
            "WHERE device_uid = ? AND run_id = ? AND context_uid IS NOT NULL",
            [device_uid, run_id],
        ).fetchall()
        return {str(r[0]) for r in rows}

    def _orphans_by_device_uid(self) -> dict[str, DeviceEvidence]:
        """Map each device uid to the evidence of a device that the snapshot
        selects no file for.

        A manifest entry that records `device_uids` gives the device uids
        (`recorded_orphans`). For an entry that records none, the device uids
        come from the newest `ospf_lsdb` file that the source and host of the
        entry published in the first `ORPHAN_WALK_MAX` manifests of the chain.
        Only the `device_uid` column of that file is read. The map is built
        once per instance."""
        if self._orphans is not None:
            return self._orphans
        evidence = self._evidence
        if evidence is None:
            self._orphans = {}
            return self._orphans
        index, legacy = recorded_orphans(evidence.devices)
        con = self._connect() if legacy else None
        if con is not None:
            pending = {(d.source, d.host): d for d in legacy}
            for held in islice(evidence.chain.walk(evidence.snapshot_key), ORPHAN_WALK_MAX):
                if not pending:
                    break
                for f in held.files:
                    if f.kind != "sidestore" or f.table != TABLE:
                        continue
                    device = pending.get((f.source, f.host))
                    if device is None:
                        continue
                    path = evidence.data_dir / f.path
                    if not _under(path, self._base_dir) or not path.is_file():
                        continue
                    for device_uid in self._device_uids(con, path):
                        index.setdefault(device_uid, device)
                    del pending[(f.source, f.host)]
        self._orphans = index
        return index

    def _device_uids(self, con: Any, path: Path) -> list[str]:
        rows = con.execute(
            f"SELECT DISTINCT device_uid FROM read_parquet({_sql_str(path.as_posix())})"  # noqa: S608
        ).fetchall()
        return [r[0] for r in rows if r[0] is not None]

    def _latest_run_id(self, con: Any, device_uid: str) -> str | None:
        """Return the run that answers for this device, by the rule of
        `ribsource.pick_run`.

        The run with the newest `snapshot_ts` at or before the bound is
        picked. Among runs with the same `snapshot_ts`, the run with the
        latest fetch timestamp in its run id is picked. The result is cached
        per device."""
        if device_uid in self._run_id_cache:
            return self._run_id_cache[device_uid]
        if not self._has_view:
            # the pinned snapshot publishes no file for this table at all
            self._run_id_cache[device_uid] = None
            return None

        rows = con.execute(
            f"SELECT run_id, max(snapshot_ts) FROM {TABLE} "  # noqa: S608 - a module constant
            "WHERE device_uid = ? GROUP BY run_id",
            [device_uid],
        ).fetchall()
        snapshot_ts_by_run = {r[0]: r[1] for r in rows if r[0] is not None}
        run_ids = list(snapshot_ts_by_run)
        if self._as_of_ms is not None:
            # A read with a bound keeps only the runs that have a snapshot_ts
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
        self._run_id_cache[device_uid] = picked
        return picked

    def _rows(self, con: Any, sql: str, params: list) -> list[dict[str, Any]]:
        cur = con.execute(sql, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    def lsdb(
        self,
        device_uid: str,
        context_uid: str | None = None,
        process: str | None = None,
        area: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return the LSAs of the link-state database of one device, in LSA order.

        `context_uid` is the uid of the owning VrfInstance. `process` is the
        name that the platform gives the process. `area` is the dotted area
        id. Each argument filters the rows, and None applies no filter. An LSA
        that belongs to no area has no area value (an AS-external LSA is
        flooded in the whole domain). A filter on `area` excludes such an LSA.

        The result is [] when the store is not queryable, when the device has
        no run within the bound, or when the selected run holds no rows for
        the device. `coverage` returns the recorded outcome of the device.
        """
        con = self._connect()
        if con is None:
            return []
        run_id = self._latest_run_id(con, device_uid)
        if run_id is None:
            return []
        return self._rows(
            con,
            f"SELECT {_COLUMNS} FROM {TABLE} "  # noqa: S608 - module constants, no caller input
            "WHERE device_uid = ? AND run_id = ? "
            "AND (? IS NULL OR context_uid = ?) "
            "AND (? IS NULL OR process = ?) "
            "AND (? IS NULL OR area = ?) "
            f"ORDER BY {_ORDER}",
            [device_uid, run_id, context_uid, context_uid, process, process, area, area],
        )

    def _latest_run_ids(self, con: Any) -> dict[str, str]:
        """Return the run that answers for each device in the view, from one
        query. The rule is `ribsource.pick_run`."""
        if not self._has_view:
            return {}
        rows = con.execute(
            f"SELECT device_uid, run_id, max(snapshot_ts) FROM {TABLE} "  # noqa: S608 - a module constant
            "WHERE device_uid IS NOT NULL AND run_id IS NOT NULL GROUP BY device_uid, run_id"
        ).fetchall()
        by_device: dict[str, dict[str, Any]] = {}
        for device_uid, run_id, snapshot_ts in rows:
            by_device.setdefault(device_uid, {})[run_id] = snapshot_ts
        picked: dict[str, str] = {}
        for device_uid, snapshot_ts_by_run in by_device.items():
            run_id = pick_run(snapshot_ts_by_run, self._as_of_ms)
            self._run_id_cache[device_uid] = run_id
            if run_id is not None:
                picked[device_uid] = run_id
        return picked

    def search_prefixes(
        self,
        lo: int,
        hi: int,
        *,
        covering: bool,
        row_cap: int = 200,
        timeout_s: float | None = None,
    ) -> list[dict[str, Any]]:
        """Return the LSAs of every device that hold an IPv4 prefix related to
        [`lo`, `hi`] (integer addresses). Each device answers from the run
        that the snapshot selects for it.

        With `covering`, the result holds the prefixes that contain the whole
        interval, longest prefix first. An address is an interval of one
        address. Without `covering`, the result holds the prefixes inside the
        interval, in address order.

        The prefix of an LSA is its link state id and mask for an LSA type
        that has a mask (network, summary, external, NSSA external), and the
        link id and link data of each stub link of a router LSA. Each row
        holds the prefix as `net` (integer) and `prefixlen`, the LSA header
        fields, the metric and the `run_id`. The result has at most `row_cap`
        rows. `timeout_s` bounds the run time of the lookup (`time_limit`).
        The result is [] when the store is not queryable.
        """
        con = self._connect()
        if con is None:
            return []
        with time_limit(con, timeout_s):
            picked = self._latest_run_ids(con)
            if not picked:
                return []
            keys = [f"{device}\x1f{run}" for device, run in picked.items()]
            marks = ",".join("?" * len(keys))
            if covering:
                where, order = "net_lo <= ? AND ? <= net_hi", "prefixlen DESC, net_lo"
            else:
                where, order = "net_lo >= ? AND net_hi <= ?", "net_lo, prefixlen"
            return self._rows(
                con,
                _PREFIX_SEARCH.format(
                    table=TABLE,
                    marks=marks,
                    where=where,
                    order=order,
                    id_expr=_DOTTED.format(v="p_id"),
                    mask_expr=_DOTTED.format(v="p_mask"),
                ),
                [*keys, int(lo), int(hi), int(row_cap)],
            )


def _under(path: Path, base: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        return False
    return True


def for_snapshot(snapshot: Snapshot) -> OspfSource:
    """Return the OspfSource of a pinned snapshot, bounded to the collection
    timestamp of the snapshot.

    With a manifest, the source reads the files that the manifest publishes
    for the `ospf_lsdb` table. Without a manifest, the source reads the newest
    run at or before the bound (`approximate`).
    """
    record = snapshot.manifest
    evidence = (
        None
        if record is None
        else snapshot.evidence(
            TABLE, lambda: snapshot_evidence(snapshot.settings, snapshot.cts, manifest=record, table=TABLE)
        )
    )
    return OspfSource(snapshot.settings.sidestore_dir, as_of_ms=snapshot.cts, evidence=evidence)
