"""The `/*filter*/` and `/*seek*/` markers in the page and count queries are
replaced by the compiled filter (core/filters.py) and the cursor seek."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from neo4j import Query

from . import filters as filtermod

ENDPOINT_PAGE = """
MATCH (e:Endpoint:Obj)
WHERE e.collection_ts = $snap AND NOT e:Retired
WITH e, coalesce(e.hostname, e.name, e.mac, e.uid) AS sort_key
WHERE /*filter*/ AND /*seek*/
RETURN e.uid AS uid, sort_key
ORDER BY sort_key, uid
LIMIT $limit
"""

ENDPOINT_COUNT = """
MATCH (e:Endpoint:Obj)
WHERE e.collection_ts = $snap AND NOT e:Retired
WITH e
WHERE /*filter*/
WITH e LIMIT $cap
RETURN count(e) AS n
"""

# One row for each listed endpoint. The row has the fields of the endpoint, its
# addresses, and one entry for each attachment with the owning device, the port
# or interface, the SSID of a wireless attachment and the sites of the device.
# `bd` is the first segment that the endpoint is IN. `last_seen` is the time
# when the source last saw the endpoint, else the time when a run last
# collected it (epoch ms).
ENDPOINT_ROWS = """
UNWIND $uids AS want
MATCH (e:Endpoint:Obj {uid: want, collection_ts: $snap})
WHERE NOT e:Retired
OPTIONAL MATCH (e)-[h:HAS_IP]->(ia:IpAddress) WHERE h._retired_at IS NULL AND NOT ia:Retired
WITH e, collect(DISTINCT ia.ip) AS ips
OPTIONAL MATCH (e)-[a:ATTACHED]->(at) WHERE a._retired_at IS NULL AND NOT at:Retired
OPTIONAL MATCH (at)-[o:ON]->(od:Device) WHERE o._retired_at IS NULL
WITH e, ips, a, at, coalesce(od, CASE WHEN at:Device THEN at END) AS owner
WITH e, ips, a, at, CASE WHEN owner:Retired THEN null ELSE owner END AS dev
OPTIONAL MATCH (dev)-[li:LOCATED_IN]->(s:Site) WHERE li._retired_at IS NULL
WITH e, ips, a, at, dev, collect(DISTINCT s.code) AS sites
WITH e, ips, collect(CASE WHEN at IS NULL THEN null ELSE {
       device: dev.uid, device_name: coalesce(dev.hostname, dev.uid),
       port: CASE WHEN at:Port OR at:Interface THEN at.name END,
       ssid: a.ssid, sites: sites} END) AS attachments
RETURN e.uid AS uid, coalesce(e.hostname, e.name, e.mac, e.uid) AS name,
       e.name AS label, e.hostname AS hostname, e.mac AS mac, e.oui AS vendor,
       e.kind AS kind, e.wired AS wired, e.ip AS ip,
       coalesce(e.last_seen, e.last_seen_ts) AS last_seen, ips, attachments,
       head([(e)-[ib:IN]->(bd) WHERE (bd:BridgeDomain OR bd:L2Segment) AND ib._retired_at IS NULL
             AND NOT bd:Retired | bd.uid]) AS bd
"""


# --- the other entity kinds (the GraphQL connections) ---------------------------------

DEVICE_PAGE = """
MATCH (d:Device:Obj)
WHERE d.collection_ts = $snap AND NOT d:Retired
WITH d, coalesce(d.hostname, d.uid) AS sort_key
WHERE /*filter*/ AND /*seek*/
RETURN d.uid AS uid, sort_key
ORDER BY sort_key, uid
LIMIT $limit
"""

DEVICE_COUNT = """
MATCH (d:Device:Obj)
WHERE d.collection_ts = $snap AND NOT d:Retired
WITH d
WHERE /*filter*/
WITH d LIMIT $cap
RETURN count(d) AS n
"""

SITE_PAGE = """
MATCH (s:Site:Obj)
WHERE (s:Meta OR s.collection_ts = $snap) AND NOT s:Retired
WITH s, coalesce(s.code, s.uid) AS sort_key
WHERE /*filter*/ AND /*seek*/
RETURN s.uid AS uid, sort_key
ORDER BY sort_key, uid
LIMIT $limit
"""

SITE_COUNT = """
MATCH (s:Site:Obj)
WHERE (s:Meta OR s.collection_ts = $snap) AND NOT s:Retired
WITH s
WHERE /*filter*/
WITH s LIMIT $cap
RETURN count(s) AS n
"""

SEGMENT_PAGE = """
CALL {
  MATCH (b:BridgeDomain:Obj) WHERE b.collection_ts = $snap RETURN b
  UNION
  MATCH (b:L2Segment:Obj) WHERE b.collection_ts = $snap RETURN b
}
WITH b WHERE NOT b:Retired
WITH b, coalesce(b.name, b.uid) AS sort_key
WHERE /*filter*/ AND /*seek*/
RETURN b.uid AS uid, sort_key
ORDER BY sort_key, uid
LIMIT $limit
"""

SEGMENT_COUNT = """
CALL {
  MATCH (b:BridgeDomain:Obj) WHERE b.collection_ts = $snap RETURN b
  UNION
  MATCH (b:L2Segment:Obj) WHERE b.collection_ts = $snap RETURN b
}
WITH b WHERE NOT b:Retired
WITH b
WHERE /*filter*/
WITH b LIMIT $cap
RETURN count(b) AS n
"""

# A prefix with no key sorts by its cidr text after the keyed prefixes.
PREFIX_PAGE = """
MATCH (p:Prefix:Obj)
WHERE p.collection_ts = $snap AND NOT p:Retired
WITH p, coalesce(p.lo_key, '~' + p.cidr, p.uid) AS sort_key
WHERE /*filter*/ AND /*seek*/
RETURN p.uid AS uid, sort_key
ORDER BY sort_key, uid
LIMIT $limit
"""

PREFIX_COUNT = """
MATCH (p:Prefix:Obj)
WHERE p.collection_ts = $snap AND NOT p:Retired
WITH p
WHERE /*filter*/
WITH p LIMIT $cap
RETURN count(p) AS n
"""

IP_ADDRESS_PAGE = """
MATCH (a:IpAddress:Obj)
WHERE a.collection_ts = $snap AND NOT a:Retired
WITH a, coalesce(a.ip_key, '~' + a.ip, a.uid) AS sort_key
WHERE /*filter*/ AND /*seek*/
RETURN a.uid AS uid, sort_key
ORDER BY sort_key, uid
LIMIT $limit
"""

IP_ADDRESS_COUNT = """
MATCH (a:IpAddress:Obj)
WHERE a.collection_ts = $snap AND NOT a:Retired
WITH a
WHERE /*filter*/
WITH a LIMIT $cap
RETURN count(a) AS n
"""

# The rows of each kind by uid. The site of a device is the first site of its
# LOCATED_IN edges.
DEVICE_ROWS = """
UNWIND $uids AS want
MATCH (d:Device:Obj {uid: want, collection_ts: $snap})
WHERE NOT d:Retired
RETURN d.uid AS uid, coalesce(d.hostname, d.uid) AS name, d.hostname AS hostname, d.role AS role,
       d.tier AS tier, d.vendor AS vendor, d.model AS model, d.mgmt_ip AS mgmt_ip, d.mac AS mac,
       coalesce(d.last_seen_ts, d.collected_at) AS last_seen,
       head([(d)-[li:LOCATED_IN]->(s:Site) WHERE li._retired_at IS NULL | s.uid]) AS site
"""

SITE_ROWS = """
UNWIND $uids AS want
MATCH (s:Site:Obj {uid: want})
WHERE (s:Meta OR s.collection_ts = $snap) AND NOT s:Retired
RETURN s.uid AS uid, s.code AS code, s.kind AS kind
"""

SEGMENT_ROWS = """
UNWIND $uids AS want
MATCH (b:Obj {uid: want, collection_ts: $snap})
WHERE (b:BridgeDomain OR b:L2Segment) AND NOT b:Retired
RETURN b.uid AS uid, b.name AS name, b.security_class AS security_class
"""

PREFIX_ROWS = """
UNWIND $uids AS want
MATCH (p:Prefix:Obj {uid: want, collection_ts: $snap})
WHERE NOT p:Retired
RETURN p.uid AS uid, p.cidr AS cidr, p.af AS af, p.kind AS kind, p.anchor AS anchor,
       head([(p)<-[og:ORIGINATES]-(v:VrfInstance) WHERE og._retired_at IS NULL | v.name]) AS vrf
"""

IP_ADDRESS_ROWS = """
UNWIND $uids AS want
MATCH (a:IpAddress:Obj {uid: want, collection_ts: $snap})
WHERE NOT a:Retired
RETURN a.uid AS uid, a.ip AS ip, a.af AS af, a.anchor AS anchor,
       head([(a)-[n:IN]->(p:Prefix) WHERE n._retired_at IS NULL AND NOT p:Retired | p.uid]) AS prefix
"""

# The child lists have one row for each parent. A row holds the uids of the
# first `$first` children in the list order of the child kind. Each parent is
# matched under the run guard.
DEVICE_ENDPOINTS = """
UNWIND $uids AS want
MATCH (d:Device:Obj {uid: want, collection_ts: $snap})
WHERE NOT d:Retired
CALL (d) {
  CALL (d) {
    MATCH (d)<-[a:ATTACHED]-(e:Endpoint) WHERE a._retired_at IS NULL AND NOT e:Retired
    RETURN e
    UNION
    MATCH (d)<-[o:ON]-(x)<-[a:ATTACHED]-(e:Endpoint)
    WHERE o._retired_at IS NULL AND a._retired_at IS NULL AND NOT x:Retired AND NOT e:Retired
    RETURN e
  }
  WITH e ORDER BY coalesce(e.hostname, e.name, e.mac, e.uid), e.uid LIMIT $first
  RETURN collect(e.uid) AS children
}
RETURN want AS parent, children
"""

SITE_DEVICES = """
UNWIND $uids AS want
MATCH (s:Site:Obj {uid: want})
WHERE (s:Meta OR s.collection_ts = $snap) AND NOT s:Retired
CALL (s) {
  MATCH (s)<-[li:LOCATED_IN]-(d:Device)
  WHERE li._retired_at IS NULL AND NOT d:Retired AND d.collection_ts = $snap
  WITH DISTINCT d ORDER BY coalesce(d.hostname, d.uid), d.uid LIMIT $first
  RETURN collect(d.uid) AS children
}
RETURN want AS parent, children
"""

SEGMENT_ENDPOINTS = """
UNWIND $uids AS want
MATCH (b:Obj {uid: want, collection_ts: $snap})
WHERE (b:BridgeDomain OR b:L2Segment) AND NOT b:Retired
CALL (b) {
  MATCH (b)<-[ib:IN]-(e:Endpoint) WHERE ib._retired_at IS NULL AND NOT e:Retired
  WITH e ORDER BY coalesce(e.hostname, e.name, e.mac, e.uid), e.uid LIMIT $first
  RETURN collect(e.uid) AS children
}
RETURN want AS parent, children
"""

PREFIX_ADDRESSES = """
UNWIND $uids AS want
MATCH (p:Prefix:Obj {uid: want, collection_ts: $snap})
WHERE NOT p:Retired
CALL (p) {
  MATCH (p)<-[n:IN]-(a:IpAddress) WHERE n._retired_at IS NULL AND NOT a:Retired
  WITH DISTINCT a ORDER BY coalesce(a.ip_key, '~' + a.ip, a.uid), a.uid LIMIT $first
  RETURN collect(a.uid) AS children
}
RETURN want AS parent, children
"""

IP_ADDRESS_ENDPOINTS = """
UNWIND $uids AS want
MATCH (a:IpAddress:Obj {uid: want, collection_ts: $snap})
WHERE NOT a:Retired
CALL (a) {
  MATCH (a)<-[h:HAS_IP]-(e:Endpoint) WHERE h._retired_at IS NULL AND NOT e:Retired
  WITH e ORDER BY coalesce(e.hostname, e.name, e.mac, e.uid), e.uid LIMIT $first
  RETURN collect(e.uid) AS children
}
RETURN want AS parent, children
"""

ENDPOINT_ADDRESSES = """
UNWIND $uids AS want
MATCH (e:Endpoint:Obj {uid: want, collection_ts: $snap})
WHERE NOT e:Retired
CALL (e) {
  MATCH (e)-[h:HAS_IP]->(a:IpAddress) WHERE h._retired_at IS NULL AND NOT a:Retired
  WITH DISTINCT a ORDER BY coalesce(a.ip_key, '~' + a.ip, a.uid), a.uid LIMIT $first
  RETURN collect(a.uid) AS children
}
RETURN want AS parent, children
"""


@dataclass(frozen=True)
class ListQueries:
    """The page and the count query of one entity kind."""

    page: str
    count: str


LISTS: dict[str, ListQueries] = {
    "endpoint": ListQueries(ENDPOINT_PAGE, ENDPOINT_COUNT),
    "device": ListQueries(DEVICE_PAGE, DEVICE_COUNT),
    "site": ListQueries(SITE_PAGE, SITE_COUNT),
    "segment": ListQueries(SEGMENT_PAGE, SEGMENT_COUNT),
    "prefix": ListQueries(PREFIX_PAGE, PREFIX_COUNT),
    "ip_address": ListQueries(IP_ADDRESS_PAGE, IP_ADDRESS_COUNT),
}

# The row read of each kind by uid.
ROWS: dict[str, str] = {
    "endpoint": ENDPOINT_ROWS,
    "device": DEVICE_ROWS,
    "site": SITE_ROWS,
    "segment": SEGMENT_ROWS,
    "prefix": PREFIX_ROWS,
    "ip_address": IP_ADDRESS_ROWS,
}

# The batched read of the child list of each (parent kind, child kind).
CHILDREN: dict[tuple[str, str], str] = {
    ("device", "endpoint"): DEVICE_ENDPOINTS,
    ("site", "device"): SITE_DEVICES,
    ("segment", "endpoint"): SEGMENT_ENDPOINTS,
    ("prefix", "ip_address"): PREFIX_ADDRESSES,
    ("ip_address", "endpoint"): IP_ADDRESS_ENDPOINTS,
    ("endpoint", "ip_address"): ENDPOINT_ADDRESSES,
}


@dataclass(frozen=True)
class Page:
    """One page of uids with their sort keys, the cursor after it (None on the
    last page), and the matching row count, exact when `total_exact`, else at
    least `total_capped`."""

    uids: list[str]
    next_cursor: str | None
    total_capped: int
    total_exact: bool
    keys: list[str] = field(default_factory=list)


def timed(text: str) -> Query:
    """`text` as a query that runs under the filtered-read timeout."""
    return Query(text, timeout=filtermod.QUERY_TIMEOUT_S)


def page_query(kind: str, compiled: filtermod.Compiled, *, seek: bool) -> str:
    """The page query of `kind` with `compiled` and, when `seek`, the cursor
    seek put in."""
    target = filtermod.TARGETS[kind]
    return (
        LISTS[kind]
        .page.replace("/*filter*/", compiled.where)
        .replace("/*seek*/", filtermod.seek_clause(target.var) if seek else "true")
    )


def count_query(kind: str, compiled: filtermod.Compiled) -> str:
    return LISTS[kind].count.replace("/*filter*/", compiled.where)


def read_page(
    session: Any,
    kind: str,
    f: filtermod.EntityFilter,
    *,
    snap: Any,
    run: int | None,
    cursor: filtermod.Cursor | None,
    limit: int,
    count: bool = True,
) -> Page:
    """Return one page of `kind` that matches `f` in the run of `snap`, after `cursor`.

    `run` is the run id that the next cursor records. With `count` false the
    count query is skipped, the total is 0 and `total_exact` is False."""
    compiled = filtermod.compile_filter(f, kind)
    params: dict[str, Any] = {**compiled.params, "snap": snap, "limit": limit + 1}
    if cursor is not None:
        params |= {"c_key": cursor.key, "c_uid": cursor.uid}
    rows = session.run(timed(page_query(kind, compiled, seek=cursor is not None)), **params).data()
    more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = None
    if more and rows:
        last = rows[-1]
        next_cursor = filtermod.Cursor(
            kind=kind, run=run, key=last["sort_key"], uid=last["uid"], filter=f.fingerprint()
        ).encode()
    total, exact = 0, False
    if count:
        counted = session.run(
            timed(count_query(kind, compiled)),
            **compiled.params,
            snap=snap,
            cap=filtermod.COUNT_CAP + 1,
        ).data()
        n = int(counted[0]["n"]) if counted else 0
        total, exact = min(n, filtermod.COUNT_CAP), n <= filtermod.COUNT_CAP
    return Page([r["uid"] for r in rows], next_cursor, total, exact, [r["sort_key"] for r in rows])


def endpoint_item(row: dict[str, Any]) -> dict[str, Any]:
    """Return one endpoint of a list response.

    It is the `ENDPOINT_ROWS` row with the display address `ip` added to `ips`."""
    ips = sorted(set(row.get("ips") or []) | ({row["ip"]} if isinstance(row.get("ip"), str) else set()))
    attachments = sorted(
        row.get("attachments") or [],
        key=lambda a: (a.get("device") or "", a.get("port") or "", a.get("ssid") or ""),
    )
    return {
        "uid": row["uid"],
        "name": row["name"],
        "label": row.get("label"),
        "hostname": row.get("hostname"),
        "mac": row.get("mac"),
        "vendor": row.get("vendor"),
        "kind": row.get("kind"),
        "wired": row.get("wired"),
        "last_seen": row.get("last_seen"),
        "ips": ips,
        "bd": row.get("bd"),
        "attachments": [{**a, "sites": sorted(a.get("sites") or [])} for a in attachments],
    }


def read_endpoints(session: Any, uids: list[str], *, snap: Any) -> list[dict[str, Any]]:
    """The list items of the endpoints `uids`, in that order."""
    if not uids:
        return []
    rows = session.run(timed(ENDPOINT_ROWS), uids=uids, snap=snap).data()
    by_uid = {r["uid"]: endpoint_item(r) for r in rows}
    return [by_uid[u] for u in uids if u in by_uid]


def read_rows(session: Any, kind: str, uids: list[str], *, snap: Any) -> dict[str, dict[str, Any]]:
    """The rows of the `kind` objects `uids` in the run `snap` binds, by uid.
    An endpoint row is shaped by `endpoint_item`."""
    if not uids:
        return {}
    rows = session.run(timed(ROWS[kind]), uids=uids, snap=snap).data()
    shape = endpoint_item if kind == "endpoint" else dict
    return {r["uid"]: shape(r) for r in rows}


def read_children(
    session: Any, parent: str, child: str, uids: list[str], *, first: int, snap: Any
) -> dict[str, list[str]]:
    """The first `first` child uids of each `parent` object `uids`, in the
    child kind's list order, by parent uid."""
    if not uids:
        return {}
    rows = session.run(timed(CHILDREN[(parent, child)]), uids=uids, first=first, snap=snap).data()
    return {r["parent"]: list(r["children"] or []) for r in rows}
