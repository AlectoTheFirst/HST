"""Pinned reader for the `arp` and `mac` side-store tables.

A lookup returns the rows of the ARP tables and the MAC tables of every device
that hold an address or a MAC. The rows of a device come from the run that the
snapshot selects for that device.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from .ribsource import SnapshotEvidence, holds_parquet, pick_run, snapshot_evidence, time_limit

if TYPE_CHECKING:
    from .snapshot import Snapshot

TABLES = ("arp", "mac")

# The MAC of a row as twelve lowercase hex digits.
_MAC_HEX = "lower(regexp_replace(mac, '[^0-9A-Fa-f]', '', 'g'))"

_COLUMNS = {
    "arp": "device_uid, vrf, context_uid, ip, mac, interface_name, run_id",
    "mac": "device_uid, vlan, mac, port_name, bridge_domain_uid, run_id",
}
_ORDER = {
    "arp": "device_uid, coalesce(context_uid, vrf, ''), ip, mac, interface_name",
    "mac": "device_uid, vlan, mac, port_name",
}


def _sql_str(value: str) -> str:
    """Return `value` as a SQL string literal. DuckDB binds no parameter into a file list."""
    return "'" + value.replace("'", "''") + "'"


class NeighborSource:
    """Read-only lookups over one of the `arp` and `mac` tables, bound to one
    `as_of_ms` and one file list for its whole life."""

    def __init__(
        self,
        base_dir: Path,
        table: str,
        *,
        as_of_ms: int | None = None,
        evidence: SnapshotEvidence | None = None,
    ) -> None:
        if table not in TABLES:
            raise ValueError(f"not a neighbor table: {table!r}")
        self._base_dir = Path(base_dir)
        self._table = table
        self._as_of_ms = as_of_ms
        self._evidence = evidence
        self._con: Any = None
        self._unavailable = False
        self._has_view = False

    def _connect(self) -> Any:
        if self._con is not None:
            return self._con
        if self._unavailable:
            return None
        table_dir = self._base_dir / self._table
        files = None if self._evidence is None else self._evidence.files
        present = holds_parquet(table_dir) if files is None else self._base_dir.is_dir()
        if not present:
            self._unavailable = True
            return None
        try:
            # sidestore raises RuntimeError when pyarrow is missing.
            from hst.core import sidestore
        except (ImportError, RuntimeError):
            self._unavailable = True
            return None
        try:
            con = sidestore.connect_reader(self._base_dir)
        except ImportError:
            self._unavailable = True
            return None
        if files is None:
            glob = _sql_str(f"{table_dir.as_posix()}/**/*.parquet")
            source = f"read_parquet({glob}, union_by_name=true)"
        else:
            source = f"read_parquet([{', '.join(_sql_str(p.as_posix()) for p in files)}], union_by_name=true)"
        if files is None or files:
            # The table name is one of TABLES. The paths come from the store
            # directory and the manifest.
            con.execute(f"CREATE TEMP VIEW {self._table} AS SELECT * FROM {source}")  # noqa: S608
            self._has_view = True
        self._con = con
        return con

    def close(self) -> None:
        """Release the connection. A repeated close is safe."""
        if self._con is not None:
            self._con.close()
            self._con = None
        self._has_view = False

    @property
    def available(self) -> bool:
        """Whether lookups can answer. DuckDB must be importable and the table must be present."""
        return self._connect() is not None

    @property
    def approximate(self) -> bool:
        """Whether files are selected by age, with no published manifest."""
        return self._evidence is None

    def _latest_run_ids(self, con: Any) -> dict[str, str]:
        """Return the run that each device answers from (`ribsource.pick_run`).

        One query reads all devices.
        """
        if not self._has_view:
            return {}
        rows = con.execute(
            f"SELECT device_uid, run_id, max(snapshot_ts) FROM {self._table} "  # noqa: S608 - one of TABLES
            "WHERE device_uid IS NOT NULL AND run_id IS NOT NULL GROUP BY device_uid, run_id"
        ).fetchall()
        by_device: dict[str, dict[str, Any]] = {}
        for device_uid, run_id, snapshot_ts in rows:
            by_device.setdefault(device_uid, {})[run_id] = snapshot_ts
        picked: dict[str, str] = {}
        for device_uid, snapshot_ts_by_run in by_device.items():
            run_id = pick_run(snapshot_ts_by_run, self._as_of_ms)
            if run_id is not None:
                picked[device_uid] = run_id
        return picked

    def _find(
        self, where: str, params: list[Any], *, row_cap: int, timeout_s: float | None
    ) -> list[dict[str, Any]]:
        con = self._connect()
        if con is None:
            return []
        with time_limit(con, timeout_s):
            picked = self._latest_run_ids(con)
            if not picked:
                return []
            keys = [f"{device}\x1f{run}" for device, run in picked.items()]
            marks = ",".join("?" * len(keys))
            cur = con.execute(
                f"SELECT {_COLUMNS[self._table]} FROM {self._table} "  # noqa: S608 - module constants
                f"WHERE device_uid || chr(31) || run_id IN ({marks}) AND {where} "
                f"ORDER BY {_ORDER[self._table]} LIMIT ?",
                [*keys, *params, int(row_cap)],
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]

    def by_ip(self, ip: str, *, row_cap: int = 200, timeout_s: float | None = None) -> list[dict[str, Any]]:
        """Return the ARP rows that hold the address `ip`, in the text form of
        `ipaddress`. The `mac` table gives []."""
        if self._table != "arp":
            return []
        return self._find("lower(ip) = ?", [ip.lower()], row_cap=row_cap, timeout_s=timeout_s)

    def by_mac(
        self, macs: list[str], *, row_cap: int = 200, timeout_s: float | None = None
    ) -> list[dict[str, Any]]:
        """The rows that hold one of `macs`, each given as twelve lowercase
        hex digits."""
        if not macs:
            return []
        marks = ",".join("?" * len(macs))
        return self._find(f"{_MAC_HEX} IN ({marks})", list(macs), row_cap=row_cap, timeout_s=timeout_s)


def for_snapshot(snapshot: Snapshot, table: str) -> NeighborSource:
    """Return the reader of `table` for the run of the pinned graph session of
    the caller.

    The reader uses the files that the manifest of the run publishes for the
    table. Without a manifest it uses the newest file at or before the snapshot
    key (`approximate`). `snapshot` is the `Snapshot` that the request resolved.
    """
    record = snapshot.manifest
    evidence = (
        None
        if record is None
        else snapshot.evidence(
            table, lambda: snapshot_evidence(snapshot.settings, snapshot.cts, manifest=record, table=table)
        )
    )
    return NeighborSource(snapshot.settings.sidestore_dir, table, as_of_ms=snapshot.cts, evidence=evidence)
