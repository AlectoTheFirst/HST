"""GET /api/explore/* serves graph search, node browsing, schema and statistics."""

from __future__ import annotations

import ipaddress
import logging
import re
import threading
from collections import Counter
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from hst.app.auth import require_permission
from hst.app.routes.endpoints import pinned_run
from hst.app.routes.run_lease import reading
from hst.app.tables import run_readonly
from hst.core import db as dbmod
from hst.core import filters as filtermod
from hst.core import ribsource
from hst.core import search as searchmod
from hst.core import snapshot as snapshotmod
from hst.core.labels import LABELS, RELS, RESERVED_LABELS
from hst.path import LIVE_SNAP

log = logging.getLogger(__name__)

router = APIRouter(prefix="/explore", dependencies=[Depends(require_permission("graph.read"))])

_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_RESERVED = sorted(RESERVED_LABELS)
SAMPLE_NODES = 2000
PROPERTY_SAMPLE = 200


def _primary(var: str) -> str:
    """The one domain label of a node, as a Cypher expression over `var`."""
    reserved = ",".join(f"'{label}'" for label in _RESERVED)
    return f"[l IN labels({var}) WHERE NOT l IN [{reserved}]][0]"


def _name(var: str) -> str:
    return (
        f"coalesce({var}.name, {var}.hostname, {var}.cidr, {var}.ip, {var}.mac, "
        f"toString({var}.vid), {var}.uid)"
    )


def _pinned(var: str) -> str:
    """The run pin of a node the query starts from."""
    return f"{var}.collection_ts = $snap AND NOT {var}:Retired"


def _at_run(var: str) -> str:
    """The run pin of a node reached from a pinned one. A :Meta node without a
    collection_ts, such as an operator-invented Site, belongs to no run and
    passes the pin."""
    runless = f"{var}:Meta AND {var}.collection_ts IS NULL"
    return f"(({runless}) OR {var}.collection_ts = $snap) AND NOT {var}:Retired"


def _of_label(name: str | None) -> str:
    """The nodes of one label in the run, as `n`. They are the nodes of the label
    at the run and the :Meta nodes of the label without a collection_ts, such as
    an operator-invented Site."""
    return (
        f"CALL {{ MATCH (n:`{name}`:Obj) WHERE {_pinned('n')} RETURN n "
        f"UNION MATCH (n:`{name}`:Meta) WHERE n.collection_ts IS NULL AND NOT n:Retired RETURN n }} "
    )


def _by_uid(param: str) -> str:
    """The node whose uid is `$param` in the run, as `n`. It is the node at the
    run or the :Meta node of that uid without a collection_ts. Both branches seek
    an index."""
    return (
        f"CALL {{ MATCH (n:Obj {{uid: ${param}, collection_ts: $snap}}) "
        "USING INDEX n:Obj(uid, collection_ts) RETURN n "
        f"UNION MATCH (n:Obj:Meta {{uid: ${param}}}) WHERE n.collection_ts IS NULL RETURN n }} "
        "WITH n WHERE NOT n:Retired "
    )


def _label(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if value not in LABELS:
        raise HTTPException(422, detail=f"unknown label {value!r}")
    return value


def _rel_type(value: str) -> str:
    if value not in RELS:
        raise HTTPException(422, detail=f"unknown relationship type {value!r}")
    return value


def _property(value: str) -> str:
    if not _IDENT.match(value):
        raise HTTPException(422, detail=f"invalid property name {value!r}")
    return value


def _snapshot(request: Request) -> snapshotmod.Snapshot:
    """The snapshot that this request answers from. A route resolves it once.
    Every query of one response then reads the same run, in the graph and in the
    side store."""
    settings = request.app.state.settings
    with dbmod.session(settings) as s:
        return snapshotmod.resolve(s, settings)


def _snap(request: Request) -> Any:
    """The `$snap` binding of the resolved snapshot."""
    cts = _snapshot(request).cts
    return snapshotmod.snap_param(cts)


def _run(request: Request, cypher: str, params: dict[str, Any], *, graph: bool = False) -> dict[str, Any]:
    return run_readonly(request.app.state.settings, cypher, params, trusted=True, graph=graph)


def _rows(table: dict[str, Any]) -> list[dict[str, Any]]:
    columns = table["columns"]
    return [dict(zip(columns, row["row"], strict=True)) for row in table["data"]]


def _node_view(node: dict[str, Any]) -> dict[str, Any]:
    """A graph-payload node as the Explore views show it. `bookkeeping` holds the
    loader properties, which start with `_`. `properties` holds the others."""
    props = node["properties"]
    labels = node["labels"]
    return {
        "id": node["id"],
        "uid": props.get("uid"),
        "label": labels[0] if labels else None,
        "labels": labels,
        "name": next(
            (
                str(props[k])
                for k in ("name", "hostname", "cidr", "ip", "mac", "vid", "uid")
                if props.get(k) is not None
            ),
            "",
        ),
        "properties": {k: v for k, v in props.items() if not k.startswith("_")},
        "bookkeeping": {k: v for k, v in props.items() if k.startswith("_")},
    }


# --- statistics -----------------------------------------------------------------------------


_STATS_CACHE: dict[Any, dict[str, Any]] = {}
_STATS_LOCK = threading.Lock()


_PRESENCE_CACHE: dict[Any, frozenset[str]] = {}


def products_present(request: Request) -> frozenset[str] | None:
    """The vendor products that hold data in the pinned run, or None when that
    is not known. It is not known before the first published run, after a failed
    read and for an empty answer. A known answer is cached per snapshot."""
    from hst.queries import presence_cypher

    try:
        snap = _snap(request)
        with _STATS_LOCK:
            cached = _PRESENCE_CACHE.get(snap)
        if cached is not None:
            return cached
        rows = _rows(_run(request, presence_cypher(), {"snap": snap}))
    except Exception:
        log.warning("product presence read failed", exc_info=True)
        return None
    if not rows or snap == LIVE_SNAP:
        return None
    present = frozenset(product for product, held in rows[0].items() if held)
    with _STATS_LOCK:
        _PRESENCE_CACHE.clear()
        _PRESENCE_CACHE[snap] = present
    return present


@router.get("/stats")
def stats(request: Request) -> dict[str, Any]:
    """Node counts by label and layer, and the device fleet by vendor, platform
    and role, for the current snapshot."""
    snap = _snap(request)
    with _STATS_LOCK:
        cached = _STATS_CACHE.get(snap)
    if cached is not None:
        return cached
    labels = _rows(
        _run(
            request,
            f"CALL {{ MATCH (n:Obj) WHERE {_pinned('n')} RETURN n "
            "UNION ALL MATCH (n:Obj:Meta) WHERE n.collection_ts IS NULL AND NOT n:Retired RETURN n } "
            f"WITH {_primary('n')} AS label WHERE label IS NOT NULL "
            "RETURN label, count(*) AS count ORDER BY count DESC",
            {"snap": snap},
        )
    )
    devices = _rows(
        _run(
            request,
            f"MATCH (d:Device:Obj) WHERE {_pinned('d')} "
            "RETURN coalesce(d.vendor, '') AS vendor, coalesce(d.platform, '') AS platform, "
            "coalesce(d.role, '') AS role, count(*) AS count",
            {"snap": snap},
        )
    )
    layers: Counter[str] = Counter()
    label_rows = []
    for row in labels:
        spec = LABELS.get(row["label"])
        for layer in spec.layers if spec else ("Unregistered",):
            layers[layer] += row["count"]
        label_rows.append(
            {
                "label": row["label"],
                "count": row["count"],
                "layers": list(spec.layers) if spec else [],
                "doc": spec.doc if spec else "",
            }
        )

    def facet(key: str) -> list[dict[str, Any]]:
        counts: Counter[str] = Counter()
        for row in devices:
            counts[row[key] or "unknown"] += row["count"]
        return [{"value": v, "count": n} for v, n in counts.most_common()]

    result = {
        "snapshot": snap,
        "total_nodes": sum(r["count"] for r in labels),
        "labels": label_rows,
        "layers": [{"layer": layer, "count": n} for layer, n in layers.most_common()],
        "devices": {
            "total": sum(r["count"] for r in devices),
            "by_vendor": facet("vendor"),
            "by_platform": facet("platform"),
            "by_role": facet("role"),
        },
    }
    # Nothing is cached before the first published run.
    if snap != LIVE_SNAP:
        with _STATS_LOCK:
            _STATS_CACHE.clear()
            _STATS_CACHE[snap] = result
    return result


# --- schema: one label --------------------------------------------------------------------


@router.get("/labels/{label}")
def label_detail(request: Request, label: str) -> dict[str, Any]:
    """The content of a label in this snapshot. The answer has the count, the
    properties of the nodes with the share of nodes that have each one, the
    relationships of the nodes, and example nodes. Properties and relationships
    are read from a sample of the label's nodes. `sampled` is true when the label
    has more nodes than the sample."""
    name = _label(label)
    if name is None:
        raise HTTPException(422, detail="a label is required")
    snap = _snap(request)
    params = {"snap": snap}
    count = _rows(_run(request, f"{_of_label(name)}RETURN count(n) AS count", params))[0]["count"]
    properties = _rows(
        _run(
            request,
            f"{_of_label(name)}WITH n LIMIT {PROPERTY_SAMPLE} "
            "UNWIND keys(n) AS key WITH key WHERE NOT key STARTS WITH '_' "
            "RETURN key, count(*) AS filled ORDER BY filled DESC, key",
            params,
        )
    )
    relationships = _rows(
        _run(
            request,
            f"{_of_label(name)}WITH n LIMIT {SAMPLE_NODES} "
            f"MATCH (n)-[r]-(m) WHERE r._retired_at IS NULL AND {_at_run('m')} "
            f"WITH type(r) AS type, CASE WHEN startNode(r) = n THEN 'out' ELSE 'in' END AS direction, "
            f"{_primary('m')} AS other "
            "RETURN type, direction, other, count(*) AS count ORDER BY count DESC LIMIT 100",
            params,
        )
    )
    examples = _rows(
        _run(
            request,
            f"{_of_label(name)}RETURN n.uid AS uid, {_name('n')} AS name ORDER BY name LIMIT 25",
            params,
        )
    )
    spec = LABELS[name]
    sample = min(count, PROPERTY_SAMPLE)
    return {
        "label": name,
        "layers": list(spec.layers),
        "doc": spec.doc,
        "count": count,
        "sampled": count > SAMPLE_NODES,
        "properties": [
            {"name": p["key"], "share": round(p["filled"] / sample, 3) if sample else 0} for p in properties
        ],
        "relationships": relationships,
        "examples": examples,
        "cypher": (
            f"MATCH (n:{name}:Obj)\nWHERE n.collection_ts = $snap AND NOT n:Retired\nRETURN n\nLIMIT 25"
        ),
    }


# --- search ---------------------------------------------------------------------------------


# Every word of the text as a prefix term, all required (core/search.py).
_lucene = searchmod.lucene


def _address_query(text: str) -> tuple[str, str] | None:
    """An IP address or prefix is matched exactly on its indexed property.
    The full-text index covers names and descriptions only."""
    try:
        if "/" in text:
            ipaddress.ip_network(text, strict=False)
            return "Prefix", "cidr"
        ipaddress.ip_address(text)
        return "IpAddress", "ip"
    except ValueError:
        return None


@router.get("/search")
def search(
    request: Request,
    q: str = Query(min_length=1, max_length=200),
    label: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    typed: bool = False,
    kind: Annotated[list[str] | None, Query()] = None,
    cursor: str | None = None,
    snapshot: str | None = None,
) -> dict[str, Any]:
    """Nodes that match the text. The matches are an exact uid, an exact IP
    address or prefix, and then the hits of the full-text index over name,
    hostname and description. The label counts cover the first 200 matches, for
    filter chips.

    With `typed`, the route runs the typed search of core/search.py. It returns
    the hits of each kind in `kind` (all kinds when none is named), with the
    first page of `limit` hits and the count of each kind. With `cursor` and
    exactly one `kind` it returns the next page of that kind. `snapshot` names
    the run. Without it the run of the cursor is read, or else the current run.
    The answer keeps `items`, `total` and `labels` (the graph hits) beside the
    typed fields."""
    text = q.strip()
    if typed:
        return _typed_search(request, text, kind, cursor, snapshot, limit)
    wanted = _label(label)
    unique = search_hits(request.app.state.settings, _snap(request), text, wanted)
    counts = Counter(h["label"] for h in unique if h["label"])
    return {
        "query": text,
        "items": unique[:limit],
        "total": len(unique),
        "labels": [{"label": k, "count": v} for k, v in counts.most_common()],
    }


_session = dbmod.session  # Tests replace this name.


def _typed_search(
    request: Request,
    text: str,
    kinds: list[str] | None,
    cursor: str | None,
    snapshot: str | None,
    limit: int,
) -> dict[str, Any]:
    """The typed answer of `search`. A regex the guard refuses, an unknown
    kind, a cursor without exactly one kind or of another query is a 400."""
    try:
        query = searchmod.detect(text)
    except filtermod.FilterError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
    wanted = tuple(dict.fromkeys(kinds)) if kinds else searchmod.KINDS
    unknown = [k for k in wanted if k not in searchmod.KINDS]
    if unknown:
        raise HTTPException(400, detail=f"unknown kind: {', '.join(unknown)}")
    after = None
    if cursor:
        if len(wanted) != 1:
            raise HTTPException(400, detail="a cursor pages one kind: name exactly one kind")
        try:
            after = filtermod.decode_cursor(cursor, kind=wanted[0], filter_print=query.fingerprint)
        except filtermod.FilterError as exc:
            raise HTTPException(400, detail=str(exc)) from exc
    settings = request.app.state.settings
    with _session(settings) as s:
        resolved = snapshotmod.resolve(s, settings, pinned_run(s, snapshot, after))
        with reading(request, s, resolved):
            result = searchmod.search(s, resolved, query, kinds=wanted, cursor=after, limit=limit)
    return {"query": text, **result.legacy(limit), **result.body()}


def search_hits(settings: Any, snap: Any, text: str, wanted: str | None) -> list[dict[str, Any]]:
    """Nodes of one run that match `text`, each uid once, in match order. The
    order is an exact uid, an exact IP address or prefix, then the full-text index.

    `snap` is the `$snap` binding of the run. It is the run id, or the live
    sentinel when no run is published. `wanted` is a registered label or None.
    The caller checks it.
    """
    params: dict[str, Any] = {"snap": snap, "q": text}
    only = f" AND n:`{wanted}`" if wanted else ""
    returning = (
        f"RETURN n.uid AS uid, {_primary('n')} AS label, {_name('n')} AS name, "
        "coalesce(n.description, n.platform, n.role, n.kind, '') AS detail"
    )
    hits: list[dict[str, Any]] = []
    for row in _rows(
        run_readonly(
            settings,
            f"{_by_uid('q')}{only} {returning}, 'uid' AS matched",
            params,
            trusted=True,
        )
    ):
        hits.append(row)
    address = _address_query(text)
    if address:
        addr_label, prop = address
        if not wanted or wanted == addr_label:
            hits += _rows(
                run_readonly(
                    settings,
                    f"MATCH (n:{addr_label}:Obj) WHERE n.{prop} STARTS WITH $q AND {_pinned('n')} "
                    f"{returning}, 'address' AS matched LIMIT 50",
                    params,
                    trusted=True,
                )
            )
        if addr_label == "IpAddress" and (not wanted or wanted == "Prefix"):
            # an address is also the network of the prefixes that start at it
            hits += _rows(
                run_readonly(
                    settings,
                    f"MATCH (n:Prefix:Obj) WHERE n.cidr STARTS WITH $q + '/' AND {_pinned('n')} "
                    f"{returning}, 'address' AS matched LIMIT 50",
                    params,
                    trusted=True,
                )
            )
    lucene = _lucene(text)
    if lucene:
        hits += _rows(
            run_readonly(
                settings,
                "CALL db.index.fulltext.queryNodes('obj_names', $lucene) YIELD node AS n, score "
                f"WITH n, score WHERE {_at_run('n')}{only} "
                f"{returning}, 'text' AS matched ORDER BY score DESC LIMIT 200",
                {**params, "lucene": lucene},
                trusted=True,
            )
        )
    seen: set[str] = set()
    unique = []
    for hit in hits:
        if hit["uid"] in seen:
            continue
        seen.add(hit["uid"])
        unique.append(hit)
    return unique


@router.get("/route-search")
def route_search(
    request: Request,
    q: str = Query(min_length=1, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """An address or prefix looked up in the route table of every device, from
    the side store of the resolved snapshot (`RibSource.search_routes`). A large
    route table is only in the side store. The node search cannot find its
    routes. Each row names its device by hostname where one is recorded."""
    text = q.strip()
    if _address_query(text) is None:
        return {"query": text, "total": 0, "items": []}
    snapshot = _snapshot(request)
    rib = ribsource.for_snapshot(snapshot)
    try:
        page = rib.search_routes(text, limit=limit)
    finally:
        rib.close()
    uids = sorted({str(r["device_uid"]) for r in page.rows})
    names: dict[str, str] = {}
    if uids:
        # The graph keeps one copy of a device per retained run. The hostnames
        # come from the run that the routes were read for.
        snap = snapshotmod.snap_param(snapshot.cts)
        for row in _rows(
            _run(
                request,
                f"MATCH (d:Device:Obj) WHERE d.uid IN $uids AND d.hostname IS NOT NULL AND {_pinned('d')} "
                "RETURN d.uid AS uid, d.hostname AS hostname",
                {"uids": uids, "snap": snap},
            )
        ):
            names[str(row["uid"])] = str(row["hostname"])
    items = [
        {
            "device_uid": r["device_uid"],
            "device": names.get(str(r["device_uid"]), r["device_uid"]),
            "vrf": r["vrf"],
            "context_uid": r["context_uid"],
            "prefix": r["prefix"],
            "next_hop": r["next_hop"],
            "interface": r["interface"],
            "protocol": r["protocol"],
            "metric": r["metric"],
        }
        for r in page.rows
    ]
    return {"query": text, "total": page.total, "items": items}


# --- one node and its neighbors -------------------------------------------------------------


@router.get("/node")
def node(request: Request, uid: str = Query(min_length=1, max_length=512)) -> dict[str, Any]:
    """One node, and its relationships grouped by type, direction and the label
    at the other end, with a count for each group."""
    snap = _snap(request)
    params = {"snap": snap, "uid": uid}
    table = _run(
        request,
        f"{_by_uid('uid')}RETURN n AS _n LIMIT 1",
        params,
        graph=True,
    )
    nodes = table.get("graph", {}).get("nodes", [])
    if not nodes:
        raise HTTPException(404, detail=f"no node {uid!r} in this snapshot")
    groups = _rows(
        _run(
            request,
            f"{_by_uid('uid')}"
            f"MATCH (n)-[r]-(m) WHERE r._retired_at IS NULL AND {_at_run('m')} "
            "WITH type(r) AS type, CASE WHEN startNode(r) = n THEN 'out' ELSE 'in' END AS direction, "
            f"{_primary('m')} AS label "
            "RETURN type, direction, label, count(*) AS count ORDER BY count DESC, type LIMIT 200",
            params,
        )
    )
    return {"snapshot": snap, "node": _node_view(nodes[0]), "neighbors": groups}


@router.get("/neighbors")
def neighbors(
    request: Request,
    uid: str = Query(min_length=1, max_length=512),
    rel_type: str = Query(alias="type", min_length=1, max_length=64),
    direction: str = Query(pattern="^(out|in)$"),
    label: str | None = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """One page of the neighbors in one relationship group, with the matched
    nodes and relationships as a graph payload for the canvas."""
    rel = _rel_type(rel_type)
    other = _label(label)
    snap = _snap(request)
    pattern = f"(n)-[r:`{rel}`]->(m)" if direction == "out" else f"(n)<-[r:`{rel}`]-(m)"
    only = f" AND m:`{other}`" if other else ""
    where = f"{_by_uid('uid')}MATCH {pattern} WHERE r._retired_at IS NULL AND {_at_run('m')}{only} "
    params = {"snap": snap, "uid": uid, "offset": offset, "limit": limit}
    total = _rows(_run(request, where + "RETURN count(m) AS total", params))[0]["total"]
    table = _run(
        request,
        where + f"WITH n, r, m, {_name('m')} AS name ORDER BY name SKIP $offset LIMIT $limit "
        f"RETURN m.uid AS uid, {_primary('m')} AS label, name, n AS _n, r AS _r, m AS _m",
        params,
        graph=True,
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": _rows(table),
        "graph": table.get("graph"),
    }


# --- values, for pickers --------------------------------------------------------------------


@router.get("/values")
def values(
    request: Request,
    label: str,
    prop_name: str = Query(alias="property"),
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    """The distinct values one property of one label takes in this snapshot,
    that contain the text, most common first."""
    name = _label(label)
    prop = _property(prop_name)
    snap = _snap(request)
    # a ZIA sublocation is left out
    extra = " AND NOT (n)-[:PART_OF]->(:ZiaLocation)" if name == "ZiaLocation" else ""
    # `id_only` is true when the value is the name of an identity group whose name is its group id.
    id_only = (
        ", sum(CASE WHEN n.name_is_id THEN 1 ELSE 0 END) > 0 AS id_only"
        if name == "IdentityGroup" and prop == "name"
        else ""
    )
    rows = _rows(
        _run(
            request,
            f"{_of_label(name)}WITH n WHERE n.`{prop}` IS NOT NULL{extra} "
            f"WITH n, toString(n.`{prop}`) AS value "
            "WHERE $q = '' OR toLower(value) CONTAINS toLower($q) "
            f"RETURN value, count(*) AS count{id_only} ORDER BY count DESC, value LIMIT $limit",
            {"snap": snap, "q": q.strip(), "limit": limit},
        )
    )
    return {"items": rows}


@router.get("/device-names")
def device_names(request: Request) -> dict[str, Any]:
    """A map from uid to hostname for every device that has a hostname, retired
    devices included. The UI shows the hostname where a result has the uid. A
    uid is `dev:<name>`, where the name is the short hostname at the time the
    device identity registry first saw the device. The uid can differ from the
    hostname that the device reports. Such a uid is a uid with a suffix, a uid of
    a device renamed after the uid was minted, a uid that the rename command set,
    or a serial-based uid of a run from before the registry. The map is not
    pinned to one run. A result read from an earlier run can name a device that
    is retired."""
    rows = _rows(
        _run(
            request,
            "MATCH (d:Device) WHERE d.hostname IS NOT NULL AND d.hostname <> '' "
            "RETURN d.uid AS uid, d.hostname AS hostname, coalesce(d.collection_ts, 0) AS ts "
            "ORDER BY uid, ts DESC",
            {},
        )
    )
    names: dict[str, str] = {}
    for row in rows:
        names.setdefault(str(row["uid"]), str(row["hostname"]))
    return {"names": names}


@router.get("/device-identity")
async def device_identity(request: Request) -> dict[str, Any]:
    """The device uids that differ from the hostname that their device reported
    last. Such a uid is a uid with a suffix, a uid of a device renamed after the
    uid was minted, or a uid that the rename command set. The route reads the
    device identity registry. `hst device rekey` gives a device a new uid."""
    report = await request.app.state.store.device_identity_report()
    return {
        "items": [
            {
                "uid": entry.uid,
                "hostname": entry.hostname,
                "last_hostname": entry.last_hostname,
                "first_run_id": entry.first_run_id,
                "identifiers": [{"kind": kind, "value": value} for kind, value in entry.identifiers],
            }
            for entry in report
        ]
    }


# --- routes from the side store --------------------------------------------------------------

# The device that a VrfInstance belongs to. The expression follows the 2 ties of
# `_VRF_DEVICE` in queries.py (OWNED_BY from the BGP stage, else interface membership).
_VRF_DEVICE = (
    "coalesce(head([(n)-[:OWNED_BY]->(od:Device) WHERE NOT od:Retired | od.uid]), "
    "head([(n)<-[x:IN_VRF]-(:Interface)-[:ON]->(dd:Device) "
    "WHERE x._retired_at IS NULL AND NOT dd:Retired | dd.uid]))"
)


@router.get("/routes")
def routes(
    request: Request,
    uid: str = Query(min_length=1, max_length=512),
    address: str | None = Query(default=None, max_length=64),
    prefix: str | None = Query(default=None, max_length=64),
    protocol: str | None = Query(default=None, max_length=32),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, Any]:
    """One page of the route table of a Device, or of one VrfInstance, from the
    run the snapshot selects for the device. `address` keeps the routes that
    cover it, longest prefix first. `available` is false when the side store
    is not installed or holds no route table. `coverage` is the outcome that the
    snapshot recorded for the route table of the device. `approximate` is true
    when the files were chosen by age, for a snapshot without a manifest.
    `snapshot` is the collection time of the run the page was read from, null
    before the first run."""
    if address:
        try:
            ipaddress.ip_address(address.strip())
        except ValueError as exc:
            raise HTTPException(422, detail=f"{address!r} is not an IP address") from exc
    return route_table(
        request.app.state.settings,
        _snapshot(request),
        uid,
        address=address,
        prefix=prefix,
        protocol=protocol,
        offset=offset,
        limit=limit,
    )


def route_table(
    settings: Any,
    snapshot: snapshotmod.Snapshot,
    uid: str,
    *,
    address: str | None = None,
    prefix: str | None = None,
    protocol: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """One page of the route table of the Device or VrfInstance `uid` in the
    run `snapshot` resolved, as `GET /explore/routes` answers it.

    The side-store reader is bound to `snapshot` and closed before the
    function returns. A uid with no node in the run is a 404. A node of
    another label is a 422. The caller checks that `address` is an IP address.
    """
    snap = snapshotmod.snap_param(snapshot.cts)
    found = _rows(
        run_readonly(
            settings,
            f"{_by_uid('uid')}"
            f"RETURN {_primary('n')} AS label, n.name AS name, "
            f"CASE WHEN n:VrfInstance THEN {_VRF_DEVICE} END AS device_uid LIMIT 1",
            {"snap": snap, "uid": uid},
            trusted=True,
        )
    )
    if not found:
        raise HTTPException(404, detail=f"no node {uid!r} in this snapshot")
    node = found[0]
    if node["label"] == "Device":
        device_uid, context_uid, legacy_vrf = uid, None, None
    elif node["label"] == "VrfInstance":
        if not node["device_uid"]:
            raise HTTPException(404, detail=f"no device owns the VRF {uid!r} in this snapshot")
        device_uid, context_uid, legacy_vrf = node["device_uid"], uid, node["name"]
    else:
        raise HTTPException(422, detail="routes are kept for Device and VrfInstance nodes")
    source = ribsource.for_snapshot(snapshot)
    try:
        available = source.available
        page = source.route_page(
            device_uid,
            context_uid,
            legacy_vrf=legacy_vrf,
            address=address.strip() if address else None,
            prefix_text=prefix.strip() if prefix else None,
            protocol=protocol,
            offset=offset,
            limit=limit,
        )
        coverage = source.coverage(device_uid) if available else None
        approximate = source.approximate
    finally:
        source.close()
    return {
        "available": available,
        "approximate": approximate,
        "coverage": coverage,
        "snapshot": snapshot.cts,
        "device_uid": device_uid,
        "context_uid": context_uid,
        "run_id": page.run_id,
        "total": page.total,
        "offset": offset,
        "limit": limit,
        "protocols": page.protocols,
        "items": page.rows,
    }
