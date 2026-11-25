"""`hst ipam import` seals one IPAdmin network-list export into the raw store at
`<raw_dir>/ipadmin/<run_id>.json.gz.enc`."""

from __future__ import annotations

import csv
import io
import ipaddress
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import rawstore
from .config import Settings

# No collector has this name.
SOURCE = "ipadmin"
FORMAT = "ipadmin-networklist-csv"
COLUMNS = ("address", "description", "location", "vlan")
# Every property the step writes.
PROPS = ("ipam_cidr", "ipam_match", "ipam_description", "ipam_location", "ipam_vlan", "ipam_import")
WRITE_CHUNK = 5000

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Entry:
    network: Net
    description: str
    location: str
    vlan: int | None

    @property
    def informative(self) -> bool:
        return bool(self.description or self.location or self.vlan is not None)


def parse(text: str) -> list[Entry]:
    """The entries of one export.

    A leading byte order mark is dropped. The lines before the header that are
    empty or start with `#` are skipped. The first other line is the header.
    The header must have each name of `COLUMNS`, in any case and with any white
    space around a name. Every later line is read as CSV. A quoted field keeps
    its continuation lines, also a line that starts with `#`. A row whose
    fields are all empty adds no entry. A row whose address starts with `#` (a
    comment row) adds no entry. A missing trailing field reads as empty. A
    VLAN that is not a number is left out of its entry. Raises ValueError with
    the physical line number on a bad address or a repeated address."""
    text = text.removeprefix("\ufeff")
    lines = text.splitlines(keepends=True)
    skipped = 0
    while skipped < len(lines) and (not lines[skipped].strip() or lines[skipped].startswith("#")):
        skipped += 1
    reader = csv.reader(io.StringIO("".join(lines[skipped:])))
    header = next(reader, [])
    index = {name.strip().lower(): i for i, name in enumerate(header)}
    missing = [c for c in COLUMNS if c not in index]
    if missing:
        raise ValueError(f"the export has no column {', '.join(missing)}")

    def field(row: list[str], name: str) -> str:
        i = index[name]
        return row[i].strip() if i < len(row) else ""

    entries: dict[Net, Entry] = {}
    for row in reader:
        line = skipped + reader.line_num
        if not any(value.strip() for value in row):
            continue
        address = field(row, "address")
        if address.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(address, strict=True)
        except ValueError as exc:
            raise ValueError(f"line {line}: bad address {address!r}") from exc
        if network in entries:
            raise ValueError(f"line {line}: {network} is in the export twice")
        vlan = field(row, "vlan")
        entries[network] = Entry(
            network=network,
            description=field(row, "description"),
            location=field(row, "location"),
            vlan=int(vlan) if vlan.isdigit() else None,
        )
    return list(entries.values())


def import_export(settings: Settings, path: Path, text: str) -> tuple[Path, int]:
    from hst.app.crypto import dek
    from hst.collectors.base import new_run_id

    count = len(parse(text))
    payload = {"format": FORMAT, "file_name": path.name, "csv": text}
    raw = rawstore.write(settings.raw_dir, SOURCE, new_run_id(), payload, key=dek(settings))
    return raw, count


def import_for(raw_dir: Path, ts_ms: int) -> Path | None:
    """The newest import fetched at or before `ts_ms`, or None."""
    # raw_files lists newest first
    for f in rawstore.raw_files(raw_dir, SOURCE, limit=1_000_000):
        if f.host == "" and f.fetch_ts_ms <= ts_ms:
            return f.path
    return None


def match(cidrs: Iterable[str], entries: Iterable[Entry]) -> dict[str, tuple[Entry, str]]:
    """CIDR -> (entry, "exact" | "covering") for each CIDR that has a match.

    An exact match is the entry of the same network. A covering match is the
    longest covering entry that is `informative`. A CIDR that does not parse
    has no match."""
    by_len: dict[tuple[int, int], dict[Net, Entry]] = {}
    for e in entries:
        by_len.setdefault((e.network.version, e.network.prefixlen), {})[e.network] = e
    out: dict[str, tuple[Entry, str]] = {}
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        exact = by_len.get((net.version, net.prefixlen), {}).get(net)
        if exact is not None:
            out[cidr] = (exact, "exact")
            continue
        for length in range(net.prefixlen - 1, 0, -1):
            parent = by_len.get((net.version, length), {}).get(net.supernet(new_prefix=length))
            if parent is not None and parent.informative:
                out[cidr] = (parent, "covering")
                break
    return out


def props_of(entry: Entry, kind: str, import_id: str) -> dict[str, Any]:
    props: dict[str, Any] = {
        "ipam_cidr": str(entry.network),
        "ipam_match": kind,
        "ipam_import": import_id,
    }
    if entry.description:
        props["ipam_description"] = entry.description
    if entry.location:
        props["ipam_location"] = entry.location
    if entry.vlan is not None:
        props["ipam_vlan"] = entry.vlan
    return props


FETCH_PREFIXES = """
MATCH (p:Prefix:Obj) WHERE p.collection_ts = $cts AND NOT p:Retired AND p.cidr IS NOT NULL
RETURN p.uid AS uid, p.cidr AS cidr
"""

CLEAR = "MATCH (p:Prefix:Obj) WHERE p.collection_ts = $cts AND p.ipam_cidr IS NOT NULL REMOVE " + ", ".join(
    f"p.{k}" for k in PROPS
)

WRITE = """
UNWIND $rows AS row
MATCH (p:Prefix:Obj {uid: row.uid, collection_ts: $cts}) WHERE p.collection_ts = $cts
SET p += row.props
RETURN count(p) AS n
"""


def annotate(
    session: Any, settings: Settings, *, collection_ts: int, ts_ms: int | None = None
) -> dict[str, Any] | None:
    from hst.app.crypto import dek

    path = import_for(settings.raw_dir, ts_ms if ts_ms is not None else int(time.time() * 1000))
    if path is None:
        return None
    import_id = path.name[: -len(rawstore.SUFFIX)]
    try:
        payload = rawstore.read(path, dek(settings))
        entries = parse(payload["csv"])
    except Exception:
        # no prefix of this run keeps register data of an earlier run
        session.run(CLEAR, cts=collection_ts).consume()
        raise
    prefixes = session.run(FETCH_PREFIXES, cts=collection_ts).data()
    found = match({str(p["cidr"]) for p in prefixes}, entries)
    rows = [
        {"uid": p["uid"], "props": props_of(*found[str(p["cidr"])], import_id)}
        for p in prefixes
        if str(p["cidr"]) in found
    ]
    session.run(CLEAR, cts=collection_ts).consume()
    written = 0
    try:
        for start in range(0, len(rows), WRITE_CHUNK):
            result = session.run(WRITE, rows=rows[start : start + WRITE_CHUNK], cts=collection_ts).data()
            written += result[0]["n"] if result else 0
    except Exception:
        # a failed write leaves no partial annotation
        session.run(CLEAR, cts=collection_ts).consume()
        raise
    exact = sum(1 for r in rows if r["props"]["ipam_match"] == "exact")
    return {
        "import": import_id,
        "prefixes": len(prefixes),
        "exact": exact,
        "covering": len(rows) - exact,
        "written": written,
    }


def detail_line(report: Mapping[str, Any]) -> str:
    return (
        f"ipam: {report['written']} of {report['prefixes']} prefix(es) annotated "
        f"(exact {report['exact']}, covering {report['covering']}; import {report['import']})"
    )
