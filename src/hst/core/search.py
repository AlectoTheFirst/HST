"""The typed object search. One query text is searched in the graph and in the
side store of one run. The answer has typed hits grouped by kind, a count per
kind and cursor pages per kind.

Query grammar (`detect`). The text is read as the first of these modes that
matches.

- `regex` is `/pattern/`. The regex guard of core/filters.py (`check_regex`)
  checks the pattern. The pattern is matched over names, case-insensitive and
  whole-value, as in the list filters.
- `ip` is one IPv4 or IPv6 address.
- `prefix` is an address with a prefix length (`10.1.0.0/16`, host bits
  ignored).
- `range` is 2 addresses of one family joined by `-` (`10.0.0.5-10.0.0.9`),
  both included.
- `mac` is a MAC in any common notation (`aa:bb:cc:dd:ee:ff`,
  `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`, `aabbccddeeff`), in any case.
- `text` is any other text. Text that is the exact uid of an object of a
  searched kind in the run is the `uid` mode and answers that object alone.

core/filters.py (`parse_filter`) parses the address modes and the regex. They
compile to the same Cypher as the list filters.

The graph kinds (`GRAPH_KINDS`) are device, interface, site, prefix,
ip_address, endpoint, vrf, segment (BridgeDomain, with its VLAN id) and
application (BusinessService). An address matches the object that is the
address or holds it, through the integer address keys (`ip_key`, `lo_key`,
`hi_key`, core/ipenc.py). The prefix kind answers the prefixes that hold an
address and the prefixes inside a prefix or a range. Text is searched in the
full-text index `obj_names` (name, description, hostname) for devices,
interfaces, endpoints, VRFs and applications. Sites are matched on their code
and name. Segments are matched on their name, uid and VLAN id. Addresses and
prefixes are matched on the start of their text when the query text can be the
start of an address. A MAC matches the `mac` of devices, interfaces and
endpoints.

The side-store kinds (`SIDE_KINDS`) are read from the run of the request.

- `arp` has the ARP rows that hold the address (ip mode) or the MAC (mac mode).
- `mac` has the MAC-table rows that hold the MAC. In ip mode it has the rows of
  the MACs of the ARP rows for the address (at most `MAC_CHAIN_MAX` MACs).
- `route` has the longest-prefix match of each routing table for an address
  and the routes for the address as a network, or the routes for exactly one
  prefix (`RibSource.search_routes`).
- `ospf_lsa` has the LSAs that hold a prefix that covers the address, or a
  prefix inside the prefix or the range of the query (IPv4,
  `OspfSource.search_prefixes`).

Each side-store lookup returns at most `SIDE_ROW_CAP` rows and runs for at
most `SIDE_TIMEOUT_S` seconds before DuckDB interrupts it. A row is returned
as a typed hit that holds its source table.

Pinning. Every graph query filters the node that it lists with
`collection_ts = $snap` and every relationship that it follows with
`_retired_at IS NULL`. The side-store readers are built from the same resolved
`Snapshot` (`ribsource.for_snapshot`, `ospfsource.for_snapshot`,
`neighborsource.for_snapshot`). One answer reads one run.

Cursors follow core/filters.py. A page of one kind is ordered by a sort key
and then by uid. The cursor holds the key and the uid of the last row, the
run, the kind and a fingerprint of the query. The side-store kinds page in the
same way over their bounded row list (`filters.after`).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field, replace
from typing import Any

from . import entity_read, neighborsource, ospfsource, ribsource
from . import filters as filtermod
from .snapshot import Snapshot, snap_param

log = logging.getLogger(__name__)

GRAPH_KINDS = (
    "device",
    "interface",
    "site",
    "prefix",
    "ip_address",
    "endpoint",
    "vrf",
    "segment",
    "application",
)
SIDE_KINDS = ("arp", "mac", "route", "ospf_lsa")
KINDS = GRAPH_KINDS + SIDE_KINDS

# The graph label of each graph kind, and the kind of each label.
KIND_LABEL = {
    "device": "Device",
    "interface": "Interface",
    "site": "Site",
    "prefix": "Prefix",
    "ip_address": "IpAddress",
    "endpoint": "Endpoint",
    "vrf": "VrfInstance",
    "segment": "BridgeDomain",
    "application": "BusinessService",
}
LABEL_KIND = {label: kind for kind, label in KIND_LABEL.items()}

# The side-store table each side kind reads.
SIDE_SOURCE = {"arp": "arp", "mac": "mac", "route": "rib", "ospf_lsa": "ospf_lsdb"}

QUERY_MAX_LEN = 200
SIDE_ROW_CAP = 200
SIDE_TIMEOUT_S = 5.0
MAC_CHAIN_MAX = 20

Mode = str  # "uid" | "ip" | "prefix" | "range" | "mac" | "regex" | "text"

_MAC = re.compile(
    r"^(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}"
    r"|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12})$",
    re.IGNORECASE,
)
_RANGE = re.compile(r"^\s*([0-9A-Fa-f:.]+)\s*-\s*([0-9A-Fa-f:.]+)\s*$")
_ADDRESS_START = re.compile(r"^(?:[0-9]+\.[0-9.]*|[0-9a-f]*:[0-9a-f:]*)$", re.IGNORECASE)
_VLAN = re.compile(r"^(?:vlan\s*)?([0-9]{1,4})$", re.IGNORECASE)
# The characters of the Lucene query syntax. `lucene` escapes them in each word.
_LUCENE_SPECIAL = re.compile(r'([+\-&|!(){}\[\]^"~*?:\\/])')


def lucene(text: str) -> str:
    """Every word of the text as a prefix term, all required. The full-text
    analyzer splits names on punctuation. The text is split in the same way."""
    words = [w for w in re.split(r"[^\w.]+", text) if w]
    return " AND ".join(f"{_LUCENE_SPECIAL.sub(r'\\\1', w)}*" for w in words)


# --- the query ------------------------------------------------------------------------


@dataclass(frozen=True)
class Query:
    """One search text read as one mode (see the module docstring).

    `filter` is the address or regex filter of the ip, prefix, range and regex
    modes. `mac` is the 12 hex digits of the mac mode. `vid` is the VLAN id of
    a text of the form `vlan 10` or `10`, if any."""

    text: str
    mode: Mode
    filter: filtermod.EntityFilter | None = None
    mac: str | None = None
    vid: int | None = None

    @property
    def fingerprint(self) -> str:
        """A short digest of the mode and the text, to tie a cursor to its query."""
        canon = json.dumps([self.mode, self.text], separators=(",", ":"))
        return hashlib.sha256(canon.encode()).hexdigest()[:16]

    @property
    def lucene(self) -> str:
        return lucene(self.text)

    @property
    def mac_forms(self) -> list[str]:
        """The notations a graph `mac` property may hold for this MAC."""
        if self.mac is None:
            return []
        h = self.mac
        pairs = [h[i : i + 2] for i in range(0, 12, 2)]
        forms = [h, ":".join(pairs), "-".join(pairs), ".".join(h[i : i + 4] for i in range(0, 12, 4))]
        return forms + [f.upper() for f in forms]


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def detect(text: str) -> Query:
    """The mode of `text` and its parsed parts. An empty text, a text longer
    than `QUERY_MAX_LEN`, a regex that the guard refuses, and a range whose
    bounds are out of order or of 2 families raise `filters.FilterError`."""
    t = text.strip()
    if not t:
        raise filtermod.FilterError("empty query")
    if len(t) > QUERY_MAX_LEN:
        raise filtermod.FilterError(f"longer than {QUERY_MAX_LEN} characters")
    if len(t) >= 3 and t.startswith("/") and t.endswith("/"):
        return Query(t, "regex", filter=filtermod.parse_filter({"regex": t[1:-1]}))
    if _address(t) is not None:
        return Query(t, "ip", filter=filtermod.parse_filter({"ip": t}))
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
        except ValueError:
            pass
        else:
            return Query(t, "prefix", filter=filtermod.parse_filter({"subnet": t}))
    m = _RANGE.match(t)
    if m and _address(m.group(1)) is not None and _address(m.group(2)) is not None:
        return Query(
            t, "range", filter=filtermod.parse_filter({"range_start": m.group(1), "range_end": m.group(2)})
        )
    if _MAC.match(t):
        return Query(t, "mac", mac=re.sub(r"[^0-9a-f]", "", t.lower()))
    vlan = _VLAN.match(t)
    return Query(t, "text", vid=int(vlan.group(1)) if vlan else None)


# --- graph kinds ----------------------------------------------------------------------


@dataclass(frozen=True)
class GraphKind:
    """The listing of one graph kind. It holds the match variable (the variable
    of the filter target), the sort key, the name and the detail of a hit, the
    text match, and the property that holds the MAC.

    `text` is "fulltext" for the full-text index, a Cypher predicate over the
    variable that binds `$t_text` (the lowercased text) and `$t_vid`, or None
    when text does not search the kind. With `address_text`, the predicate
    applies only to text that can be the start of an address."""

    kind: str
    var: str
    sort: str
    name: str
    detail: str
    text: str | None
    address_text: bool = False
    mac: str | None = None

    @property
    def label(self) -> str:
        return KIND_LABEL[self.kind]


GRAPH: dict[str, GraphKind] = {
    g.kind: g
    for g in (
        GraphKind(
            kind="device",
            var="d",
            sort="coalesce(d.hostname, d.name, d.uid)",
            name="coalesce(d.hostname, d.name, d.uid)",
            detail="coalesce(d.platform, d.role, d.vendor, '')",
            text="fulltext",
            mac="d.mac",
        ),
        GraphKind(
            kind="interface",
            var="i",
            sort="coalesce(i.name, i.uid)",
            name="coalesce(i.name, i.uid)",
            detail=(
                "coalesce(head([(i)-[o:ON]->(od:Device) WHERE o._retired_at IS NULL"
                " | coalesce(od.hostname, od.uid)]), '')"
            ),
            text="fulltext",
            mac="i.mac",
        ),
        GraphKind(
            kind="site",
            var="s",
            sort="coalesce(s.code, s.uid)",
            name="coalesce(s.name, s.code, s.uid)",
            detail="coalesce(s.code, '')",
            text=(
                "(toLower(coalesce(s.code, '')) CONTAINS $t_text"
                " OR toLower(coalesce(s.name, '')) CONTAINS $t_text)"
            ),
        ),
        GraphKind(
            kind="prefix",
            var="p",
            sort="coalesce(p.hi_key, p.cidr, p.uid)",
            name="coalesce(p.cidr, p.uid)",
            detail=(
                "coalesce(head([(p)<-[o:ORIGINATES]-(v:VrfInstance) WHERE o._retired_at IS NULL"
                " | v.name]), p.anchor, '')"
            ),
            text="p.cidr STARTS WITH $t_text",
            address_text=True,
        ),
        GraphKind(
            kind="ip_address",
            var="a",
            sort="coalesce(a.ip_key, a.ip, a.uid)",
            name="coalesce(a.ip, a.uid)",
            detail=(
                "coalesce(head([(a)<-[h:HAS_IP]-(x) WHERE h._retired_at IS NULL AND NOT x:Retired"
                " | coalesce(x.hostname, x.name, x.uid)]), '')"
            ),
            text="a.ip STARTS WITH $t_text",
            address_text=True,
        ),
        GraphKind(
            kind="endpoint",
            var="e",
            sort="coalesce(e.hostname, e.name, e.mac, e.uid)",
            name="coalesce(e.hostname, e.name, e.mac, e.uid)",
            detail="coalesce(e.ip, e.oui, '')",
            text="fulltext",
            mac="e.mac",
        ),
        GraphKind(
            kind="vrf",
            var="v",
            sort="coalesce(v.name, v.uid)",
            name="coalesce(v.name, v.uid)",
            detail="coalesce(v.hostname, v.anchor, '')",
            text="fulltext",
        ),
        GraphKind(
            kind="segment",
            var="b",
            sort="coalesce(b.name, b.uid)",
            name="coalesce(b.name, b.uid)",
            detail=(
                "coalesce('VLAN ' + toString(head([(b)<-[rz:REALIZES]-(vl:VlanInstance)"
                " WHERE rz._retired_at IS NULL | vl.vid])), '')"
            ),
            text="""(toLower(coalesce(b.name, '')) CONTAINS $t_text OR toLower(b.uid) CONTAINS $t_text
  OR ($t_vid IS NOT NULL AND EXISTS {
    MATCH (b)<-[rz:REALIZES]-(vl:VlanInstance) WHERE rz._retired_at IS NULL AND vl.vid = $t_vid }))""",
        ),
        GraphKind(
            kind="application",
            var="x",
            sort="coalesce(x.name, x.uid)",
            name="coalesce(x.name, x.uid)",
            detail="coalesce(x.description, '')",
            text="fulltext",
        ),
    )
}

# The page and count queries of a graph kind. `{v}`, `{label}`, `{sort}`,
# `{name}` and `{detail}` are fields of the `GraphKind`. After formatting, the
# predicate of the query replaces the `/*filter*/` marker and the cursor seek
# replaces the `/*seek*/` marker, as in core/entity_read.py.
GRAPH_PAGE = """
MATCH ({v}:{label})
WHERE (({v}:Meta AND {v}.collection_ts IS NULL) OR {v}.collection_ts = $snap)
  AND NOT {v}:Retired
WITH {v}, {sort} AS sort_key
WHERE /*filter*/ AND /*seek*/
WITH {v}, sort_key
ORDER BY sort_key, {v}.uid
LIMIT $limit
RETURN {v}.uid AS uid, sort_key, {name} AS name, {detail} AS detail
ORDER BY sort_key, uid
"""

GRAPH_PAGE_FULLTEXT = """
CALL db.index.fulltext.queryNodes('obj_names', $lucene) YIELD node AS {v}
WITH {v}
WHERE {v}:{label} AND (({v}:Meta AND {v}.collection_ts IS NULL) OR {v}.collection_ts = $snap)
  AND NOT {v}:Retired
WITH {v}, {sort} AS sort_key
WHERE /*filter*/ AND /*seek*/
WITH {v}, sort_key
ORDER BY sort_key, {v}.uid
LIMIT $limit
RETURN {v}.uid AS uid, sort_key, {name} AS name, {detail} AS detail
ORDER BY sort_key, uid
"""

GRAPH_COUNT = """
MATCH ({v}:{label})
WHERE (({v}:Meta AND {v}.collection_ts IS NULL) OR {v}.collection_ts = $snap)
  AND NOT {v}:Retired
WITH {v}
WHERE /*filter*/
WITH {v} LIMIT $cap
RETURN count({v}) AS n
"""

GRAPH_COUNT_FULLTEXT = """
CALL db.index.fulltext.queryNodes('obj_names', $lucene) YIELD node AS {v}
WITH {v}
WHERE {v}:{label} AND (({v}:Meta AND {v}.collection_ts IS NULL) OR {v}.collection_ts = $snap)
  AND NOT {v}:Retired
WITH {v}
WHERE /*filter*/
WITH {v} LIMIT $cap
RETURN count({v}) AS n
"""

# The object of the run whose uid is the text. `exact_kind` reads its kind from its labels.
EXACT_UID = """
MATCH (n:Obj {uid: $u_uid, collection_ts: $snap})
WHERE NOT n:Retired
RETURN labels(n) AS labels
LIMIT 1
"""

# The hostnames, in the run, of the devices of the side-store rows.
DEVICE_NAMES = """
MATCH (d:Device:Obj)
WHERE d.uid IN $uids AND d.collection_ts = $snap AND NOT d:Retired
RETURN d.uid AS uid, coalesce(d.hostname, d.uid) AS name
"""


@dataclass(frozen=True)
class Predicate:
    """The match of one query in one graph kind. It holds a Cypher predicate
    over the variable of the kind, its parameters, and whether the listing
    reads the full-text index."""

    where: str
    params: dict[str, Any]
    fulltext: bool = False


def graph_predicate(kind: str, q: Query) -> Predicate | None:
    """The predicate of `q` on `kind`, or None when the query does not search
    that kind (a filter that the kind does not support, a MAC on a kind with
    no MAC property, text on a kind that text does not search)."""
    g = GRAPH[kind]
    if q.mode == "uid":
        return Predicate(f"{g.var}.uid = $u_uid", {"u_uid": q.text})
    if q.filter is not None:
        try:
            compiled = filtermod.compile_filter(q.filter, kind)
        except filtermod.FilterError:
            return None
        return Predicate(compiled.where, compiled.params)
    if q.mode == "mac":
        if g.mac is None:
            return None
        return Predicate(f"{g.mac} IN $m_macs", {"m_macs": q.mac_forms})
    if g.text == "fulltext":
        return Predicate("true", {"lucene": q.lucene}, fulltext=True) if q.lucene else None
    if g.text is None or (g.address_text and not _ADDRESS_START.match(q.text)):
        return None
    return Predicate(g.text, {"t_text": q.text.lower(), "t_vid": q.vid})


def page_query(kind: str, pred: Predicate, *, seek: bool) -> str:
    g = GRAPH[kind]
    template = GRAPH_PAGE_FULLTEXT if pred.fulltext else GRAPH_PAGE
    text = template.format(v=g.var, label=g.label, sort=g.sort, name=g.name, detail=g.detail)
    return text.replace("/*filter*/", pred.where).replace(
        "/*seek*/", filtermod.seek_clause(g.var) if seek else "true"
    )


def count_query(kind: str, pred: Predicate) -> str:
    g = GRAPH[kind]
    template = GRAPH_COUNT_FULLTEXT if pred.fulltext else GRAPH_COUNT
    return template.format(v=g.var, label=g.label).replace("/*filter*/", pred.where)


# --- results --------------------------------------------------------------------------


@dataclass
class Group:
    """The page of one kind. It holds the hits, the cursor of the next page
    (None on the last page) and the count of the kind. The count is exact when
    `count_exact` is true."""

    items: list[dict[str, Any]]
    next_cursor: str | None
    count: int
    count_exact: bool


@dataclass
class Result:
    """A typed search answer. It holds the query with its mode, the run, the
    groups by kind, and the state of the side-store lookups."""

    query: Query
    snapshot: int | None
    groups: dict[str, Group] = field(default_factory=dict)
    side_available: bool = False
    side_approximate: bool = False
    side_capped: list[str] = field(default_factory=list)
    side_timed_out: list[str] = field(default_factory=list)

    def body(self) -> dict[str, Any]:
        """The typed fields of the route's answer."""
        return {
            "mode": self.query.mode,
            "snapshot": self.snapshot,
            "kinds": [
                {"kind": k, "count": g.count, "count_exact": g.count_exact}
                for k in KINDS
                if (g := self.groups.get(k)) is not None and g.count > 0
            ],
            "groups": {
                k: {"items": g.items, "next_cursor": g.next_cursor}
                for k in KINDS
                if (g := self.groups.get(k)) is not None and (g.items or g.next_cursor)
            },
            "side_store": {
                "available": self.side_available,
                "approximate": self.side_approximate,
                "capped": self.side_capped,
                "timed_out": self.side_timed_out,
            },
        }

    def legacy(self, limit: int) -> dict[str, Any]:
        """The fields of the untyped answer, from the graph groups. They are the
        hits as `{uid, label, name, detail, matched}`, the total, and the label
        counts."""
        items = [
            {
                "uid": h["uid"],
                "label": KIND_LABEL[k],
                "name": h["name"],
                "detail": h["detail"],
                "matched": h["matched"],
            }
            for k in GRAPH_KINDS
            if (g := self.groups.get(k)) is not None
            for h in g.items
        ]
        counts = [
            (KIND_LABEL[k], g.count) for k in GRAPH_KINDS if (g := self.groups.get(k)) is not None and g.count
        ]
        counts.sort(key=lambda c: -c[1])
        return {
            "items": items[:limit],
            "total": sum(c for _, c in counts),
            "labels": [{"label": label, "count": n} for label, n in counts],
        }


def _graph_hit(kind: str, row: dict[str, Any], q: Query, run: int | None) -> dict[str, Any]:
    uid = str(row["uid"])
    return {
        "kind": kind,
        "key": uid,
        "uid": uid,
        "name": str(row.get("name") or uid),
        "detail": str(row.get("detail") or ""),
        "source": "graph",
        "matched": q.mode,
        "run": run,
        "source_run": None,
        "target": {"kind": kind, "uid": uid},
        "fields": {},
    }


def graph_group(
    session: Any,
    kind: str,
    q: Query,
    *,
    snap: Any,
    run: int | None,
    cursor: filtermod.Cursor | None,
    limit: int,
) -> Group | None:
    """One page of `kind` for `q` in the run of `snap`, after `cursor`. The
    result is None when the query does not search the kind. The count query
    runs only when the first page does not hold every match."""
    pred = graph_predicate(kind, q)
    if pred is None:
        return None
    params: dict[str, Any] = {**pred.params, "snap": snap, "limit": limit + 1}
    if cursor is not None:
        params |= {"c_key": cursor.key, "c_uid": cursor.uid}
    rows = session.run(entity_read.timed(page_query(kind, pred, seek=cursor is not None)), **params).data()
    more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if more and rows:
        last = rows[-1]
        next_cursor = filtermod.Cursor(
            kind=kind, run=run, key=str(last["sort_key"]), uid=str(last["uid"]), filter=q.fingerprint
        ).encode()
    if cursor is not None:
        count, exact = 0, False
    elif not more:
        count, exact = len(rows), True
    else:
        counted = session.run(
            entity_read.timed(count_query(kind, pred)),
            **pred.params,
            snap=snap,
            cap=filtermod.COUNT_CAP + 1,
        ).data()
        n = int(counted[0]["n"]) if counted else 0
        count, exact = min(n, filtermod.COUNT_CAP), n <= filtermod.COUNT_CAP
    return Group([_graph_hit(kind, r, q, run) for r in rows], next_cursor, count, exact)


def exact_kind(session: Any, text: str, *, snap: Any) -> str | None:
    """The kind of the object whose uid is `text` in the run, or None when no
    object of a graph kind has that uid."""
    rows = session.run(entity_read.timed(EXACT_UID), u_uid=text, snap=snap).data()
    for label in rows[0]["labels"] if rows else []:
        if label in LABEL_KIND:
            return LABEL_KIND[label]
    return None


# --- side-store kinds -----------------------------------------------------------------


def _mac_hex(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def mac_text(value: Any) -> str:
    """A MAC as colon-separated lowercase pairs, or the value as written when
    it does not hold 12 hex digits."""
    text = str(value or "")
    h = _mac_hex(text)
    return ":".join(h[i : i + 2] for i in range(0, 12, 2)) if len(h) == 12 else text


def _joined(*parts: Any) -> str:
    return " ".join(str(p) for p in parts if p not in (None, ""))


def _is_interrupt(exc: BaseException) -> bool:
    return type(exc).__name__ == "InterruptException"


@dataclass
class SideRows:
    """The bounded rows of each side kind, before shaping, and the kinds that
    reached the row cap or the timeout."""

    rows: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    available: bool = False
    approximate: bool = False
    capped: list[str] = field(default_factory=list)
    timed_out: list[str] = field(default_factory=list)


def _lookup(out: SideRows, kind: str, read: Any) -> list[dict[str, Any]]:
    """The rows of `read()`. The kind is added to `out.capped` when `read()`
    returned at least `SIDE_ROW_CAP` rows. The kind is added to `out.timed_out`
    and the result is [] when DuckDB interrupted the read."""
    try:
        rows = list(read())
    except Exception as exc:
        if _is_interrupt(exc):
            out.timed_out.append(kind)
            return []
        raise
    if len(rows) >= SIDE_ROW_CAP and kind not in out.capped:
        out.capped.append(kind)
    return rows


def side_rows(snapshot: Snapshot, q: Query, kinds: tuple[str, ...]) -> SideRows:
    """The side-store rows of `kinds` for `q`, read from the run of `snapshot`.
    Only ip, prefix, range and mac queries search the side store."""
    out = SideRows()
    ip = q.filter.ip if q.filter is not None else None
    wanted = set(kinds)
    if q.mode in ("ip", "mac") and wanted & {"arp", "mac"}:
        arp = neighborsource.for_snapshot(snapshot, "arp")
        mac = neighborsource.for_snapshot(snapshot, "mac")
        try:
            out.available |= arp.available or mac.available
            out.approximate |= arp.approximate
            if q.mode == "ip" and ip is not None:
                arp_rows = _lookup(
                    out, "arp", lambda: arp.by_ip(ip, row_cap=SIDE_ROW_CAP, timeout_s=SIDE_TIMEOUT_S)
                )
                macs = sorted({h for r in arp_rows if len(h := _mac_hex(r.get("mac"))) == 12})[:MAC_CHAIN_MAX]
            else:
                macs = [q.mac] if q.mac else []
                arp_rows = (
                    _lookup(
                        out, "arp", lambda: arp.by_mac(macs, row_cap=SIDE_ROW_CAP, timeout_s=SIDE_TIMEOUT_S)
                    )
                    if "arp" in wanted
                    else []
                )
            if "arp" in wanted:
                out.rows["arp"] = arp_rows
            if "mac" in wanted:
                out.rows["mac"] = (
                    _lookup(
                        out, "mac", lambda: mac.by_mac(macs, row_cap=SIDE_ROW_CAP, timeout_s=SIDE_TIMEOUT_S)
                    )
                    if macs
                    else []
                )
        finally:
            arp.close()
            mac.close()
    if "route" in wanted and q.mode in ("ip", "prefix") and q.filter is not None:
        text = q.filter.ip or q.filter.subnet or ""
        rib = ribsource.for_snapshot(snapshot)
        try:
            out.available |= rib.available
            out.approximate |= rib.approximate
            out.rows["route"] = _lookup(
                out,
                "route",
                lambda: (
                    rib.search_routes(
                        text, limit=SIDE_ROW_CAP, row_cap=SIDE_ROW_CAP, timeout_s=SIDE_TIMEOUT_S
                    ).rows
                ),
            )
        finally:
            rib.close()
    if "ospf_lsa" in wanted and q.filter is not None and q.mode in ("ip", "prefix", "range"):
        bounds = _v4_bounds(q.filter)
        if bounds is not None:
            lo, hi = bounds
            ospf = ospfsource.for_snapshot(snapshot)
            try:
                out.available |= ospf.available
                out.approximate |= ospf.approximate
                out.rows["ospf_lsa"] = _lookup(
                    out,
                    "ospf_lsa",
                    lambda: ospf.search_prefixes(
                        lo, hi, covering=q.mode == "ip", row_cap=SIDE_ROW_CAP, timeout_s=SIDE_TIMEOUT_S
                    ),
                )
            finally:
                ospf.close()
    return out


def _v4_bounds(f: filtermod.EntityFilter) -> tuple[int, int] | None:
    """The IPv4 interval of an address, prefix or range filter, as integers.
    The result is None for IPv6. The OSPFv2 database holds no IPv6 prefix."""
    if f.ip is not None:
        a = ipaddress.ip_address(f.ip)
        return (int(a), int(a)) if a.version == 4 else None
    if f.subnet is not None:
        n = ipaddress.ip_network(f.subnet, strict=False)
        return (int(n.network_address), int(n.broadcast_address)) if n.version == 4 else None
    if f.range_start is not None and f.range_end is not None:
        lo, hi = ipaddress.ip_address(f.range_start), ipaddress.ip_address(f.range_end)
        return (int(lo), int(hi)) if lo.version == 4 else None
    return None


def _side_hit(
    kind: str, row: dict[str, Any], names: dict[str, str], q: Query, run: int | None
) -> dict[str, Any]:
    """One side-store row as a typed hit with a name, a detail, the fields of
    the row and the device as the target. The result also holds the `sort` and
    `uid` keys for paging."""
    device_uid = str(row.get("device_uid") or "")
    device = names.get(device_uid, device_uid)
    source = SIDE_SOURCE[kind]
    if kind == "arp":
        mac = mac_text(row.get("mac"))
        ctx = row.get("context_uid") or row.get("vrf") or ""
        name = str(row.get("ip") or "")
        detail = _joined(
            device, row.get("interface_name"), f"VRF {row['vrf']}" if row.get("vrf") else "", mac
        )
        fields = {
            "device": device,
            "device_uid": device_uid,
            "vrf": row.get("vrf"),
            "interface": row.get("interface_name"),
            "ip": row.get("ip"),
            "mac": mac,
        }
        sort, key = device, f"arp|{device_uid}|{ctx}|{name}|{mac}|{row.get('interface_name') or ''}"
    elif kind == "mac":
        mac = mac_text(row.get("mac"))
        vlan = row.get("vlan")
        name = mac
        detail = _joined(device, row.get("port_name"), f"VLAN {vlan}" if vlan is not None else "")
        fields = {
            "device": device,
            "device_uid": device_uid,
            "vlan": vlan,
            "interface": row.get("port_name"),
            "mac": mac,
            "segment_uid": row.get("bridge_domain_uid"),
        }
        sort, key = device, f"mac|{device_uid}|{vlan}|{mac}|{row.get('port_name') or ''}"
    elif kind == "route":
        prefixlen = int(row.get("prefixlen") or 0)
        name = str(row.get("prefix") or "")
        via = f"via {row['next_hop']}" if row.get("next_hop") else ""
        detail = _joined(
            device,
            f"VRF {row['vrf']}" if row.get("vrf") else "",
            via,
            row.get("interface"),
            row.get("protocol"),
        )
        fields = {
            "device": device,
            "device_uid": device_uid,
            "vrf": row.get("vrf"),
            "prefix": name,
            "next_hop": row.get("next_hop"),
            "interface": row.get("interface"),
            "protocol": row.get("protocol"),
            "metric": row.get("metric"),
        }
        ctx = row.get("context_uid") or row.get("vrf") or ""
        sort = f"{128 - prefixlen:03d}|{device}"
        key = f"route|{device_uid}|{ctx}|{name}|{row.get('next_hop') or ''}|{row.get('interface') or ''}"
    else:  # ospf_lsa
        net = ipaddress.IPv4Network((int(row["net"]), int(row["prefixlen"])), strict=False)
        name = str(net)
        detail = _joined(
            device,
            f"area {row['area']}" if row.get("area") else "",
            f"{row.get('lsa_type')} LSA {row.get('lsid')}",
            f"from {row['adv_router']}" if row.get("adv_router") else "",
        )
        fields = {
            "device": device,
            "device_uid": device_uid,
            "prefix": name,
            "area": row.get("area"),
            "lsa_type": row.get("lsa_type"),
            "lsid": row.get("lsid"),
            "adv_router": row.get("adv_router"),
            "metric": row.get("metric"),
        }
        sort = (
            f"{32 - net.prefixlen:02d}"
            if q.mode == "ip"
            else f"{int(net.network_address):010d}|{net.prefixlen:02d}"
        )
        key = (
            f"ospf|{device_uid}|{row.get('context_uid') or ''}|{row.get('process') or ''}"
            f"|{row.get('area') or ''}"
            f"|{row.get('lsa_type')}|{row.get('lsid')}|{row.get('adv_router')}|{name}"
        )
    return {
        "sort": sort,
        "uid": key,
        "hit": {
            "kind": kind,
            "key": key,
            "uid": None,
            "name": name,
            "detail": detail,
            "source": source,
            "matched": q.mode,
            "run": run,
            "source_run": row.get("run_id"),
            "target": {"kind": "device", "uid": device_uid} if device_uid else None,
            "fields": fields,
        },
    }


def side_group(
    kind: str,
    rows: list[dict[str, Any]],
    names: dict[str, str],
    q: Query,
    *,
    run: int | None,
    cursor: filtermod.Cursor | None,
    limit: int,
    exact: bool,
) -> Group:
    """One page of the bounded rows of a side kind, after `cursor`, ordered by
    sort key and then by key, with one hit per distinct key."""
    shaped: dict[str, dict[str, Any]] = {}
    for row in rows:
        s = _side_hit(kind, row, names, q, run)
        shaped.setdefault(s["uid"], s)
    ordered = sorted(shaped.values(), key=lambda s: (s["sort"], s["uid"]))
    rest = filtermod.after(ordered, cursor, key="sort")
    page = rest[:limit]
    next_cursor = None
    if len(rest) > limit and page:
        last = page[-1]
        next_cursor = filtermod.Cursor(
            kind=kind, run=run, key=last["sort"], uid=last["uid"], filter=q.fingerprint
        ).encode()
    count = 0 if cursor is not None else len(ordered)
    return Group([s["hit"] for s in page], next_cursor, count, exact and cursor is None)


def device_names(session: Any, uids: list[str], *, snap: Any) -> dict[str, str]:
    """The hostname of each device uid in the run, where the graph holds one."""
    if not uids:
        return {}
    rows = session.run(entity_read.timed(DEVICE_NAMES), uids=uids, snap=snap).data()
    return {str(r["uid"]): str(r["name"]) for r in rows}


# --- the search -----------------------------------------------------------------------


def search(
    session: Any,
    snapshot: Snapshot,
    q: Query,
    *,
    kinds: tuple[str, ...] = KINDS,
    cursor: filtermod.Cursor | None = None,
    limit: int = 25,
) -> Result:
    """The typed search of `q` in the run of `snapshot`. The result has the
    first page of each kind in `kinds`. With `cursor`, it has the next page of
    the kind of the cursor, and no count is read."""
    run = snapshot.cts
    snap = snap_param(run)
    if cursor is not None:
        kinds = (cursor.kind,)
    if q.mode == "text" and cursor is None:
        found = exact_kind(session, q.text, snap=snap)
        if found is not None and found in kinds:
            q = replace(q, mode="uid")
            kinds = (found,)
    result = Result(query=q, snapshot=run)
    for kind in kinds:
        if kind in GRAPH:
            group = graph_group(session, kind, q, snap=snap, run=run, cursor=cursor, limit=limit)
            if group is not None:
                result.groups[kind] = group
    side = tuple(k for k in kinds if k in SIDE_KINDS)
    if side and q.mode in ("ip", "prefix", "range", "mac"):
        found_rows = side_rows(snapshot, q, side)
        result.side_available = found_rows.available
        result.side_approximate = found_rows.approximate
        result.side_capped = found_rows.capped
        result.side_timed_out = found_rows.timed_out
        uids = sorted(
            {str(r["device_uid"]) for rows in found_rows.rows.values() for r in rows if r.get("device_uid")}
        )
        names = device_names(session, uids, snap=snap)
        for kind, rows in found_rows.rows.items():
            exact = kind not in found_rows.capped and kind not in found_rows.timed_out
            result.groups[kind] = side_group(
                kind, rows, names, q, run=run, cursor=cursor, limit=limit, exact=exact
            )
    return result
