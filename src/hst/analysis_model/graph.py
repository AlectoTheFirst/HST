"""Bounded production reads and immutable indexes for one published graph.

Rules, objects and references are separate keyed tables. No group traversal or
source/destination/service cross-product occurs in the database or the walker.

A load reads either the whole run or the part of it one request can touch
(`load_graph(devices=...)`). A scoped load reads every node of the run except
the per-device bulk (`SCOPED_LABELS`) of devices outside the scope, and the
inventory it returns raises `ScopeExtension` on any read that the omitted part
could answer differently. The caller then loads again with the devices of the
exception. No answer is computed from a partial graph.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, NoReturn

from hst import path as pathmod
from hst.core import manifest as manifestmod

from . import checkpoint_envelopes
from .read import BoundedTableReader, MaterializedTable, ReadError, ReadPage, TableBudgetExceeded

# The worker memory of the default table budgets. The budgets are 1,000,000
# rows and 256 MiB of row JSON per table at the default `analysis_memory_mb`.
DEFAULT_MEMORY_MB = 1024

# Labels whose nodes belong to one device. A scoped load
# reads them for the devices in its scope only. A node of these labels with no
# owner is always read.
SCOPED_LABELS = frozenset({"Interface", "Port", "VrfInstance", "Prefix", "IpAddress"})

# The policy binding types. A scoped load keeps every such relationship of a
# node it reads, also when the other end is outside the scope. The list of
# bindings of a rulebase is whole. A read that follows a binding to the
# omitted end raises.
BOUNDARY_KINDS = ("ENFORCES", "PROTECTED_BY")

# The `source` of a relationship that VSX transit discovery follows.
VSX_TRANSIT_SOURCES = frozenset({"vsx-warp", "vsx-bridge"})

# The properties by which a consumer finds nodes across the whole run
# (`GraphInventory.nodes_carrying`). A scoped load reads every node of any
# label that has one of them, and `nodes_carrying` stays whole for them.
WHOLE_RUN_PROPERTIES = ("cp_uid",)


def graph_budget(memory_mb: int) -> tuple[int, int]:
    """The row and byte budgets of one graph table for an analysis worker of
    `memory_mb` MiB. Both scale linearly from 1,000,000 rows and 256 MiB at
    `DEFAULT_MEMORY_MB`."""
    if type(memory_mb) is not int or memory_mb <= 0:
        raise ValueError("the analysis worker memory must be a positive number of MiB")
    return memory_mb * 1_000_000 // DEFAULT_MEMORY_MB, memory_mb * 1024 * 1024 // 4


class GraphTooLarge(ReadError):
    """SCOPE_TOO_LARGE. The part of the run that an analysis needs holds more than
    the table budgets of its worker memory (`graph_budget`)."""

    code = "SCOPE_TOO_LARGE"


class ScopeExtension(BaseException):
    """A read of a scoped inventory that the omitted part of the run could
    answer differently. `scope` is the scope of that inventory. `devices`
    holds the devices to add to the scope, or is None when only the whole run
    answers the read.

    It is a BaseException that no `except Exception` handler catches."""

    def __init__(self, devices: frozenset[str] | None, reason: str, scope: frozenset[str]) -> None:
        super().__init__(reason)
        self.devices = devices
        self.reason = reason
        self.scope = scope

    def widened(self) -> frozenset[str] | None:
        """The scope to load next. The result is None (the whole run) when the read
        needs the whole run, or when `devices` adds nothing to the scope."""
        if self.devices is None:
            return None
        grown = self.scope | self.devices
        return None if grown == self.scope else grown


def _run(variable: str) -> str:
    """The condition for a relationship of the run. The relationship is not retired
    and is stamped with the run or unstamped."""
    return (
        f"{variable}._retired_at IS NULL"
        f" AND ({variable}.collection_ts = $snap OR {variable}.collection_ts IS NULL)"
    )


def _owners(variable: str) -> str:
    """The uids of the Devices that own a node of `SCOPED_LABELS`, or an empty
    list for any other node."""
    return (
        f"CASE WHEN {variable}:Interface OR {variable}:Port THEN COLLECT {{"
        f" MATCH ({variable})-[:ON]->(o:Device:Obj) WHERE o.collection_ts = $snap RETURN o.uid }}"
        f" WHEN {variable}:VrfInstance THEN COLLECT {{"
        f" MATCH ({variable})-[:OWNED_BY]->(o:Device:Obj) WHERE o.collection_ts = $snap RETURN o.uid }}"
        f" WHEN {variable}:Prefix OR {variable}:IpAddress THEN COLLECT {{"
        f" MATCH (v:VrfInstance:Obj {{uid: {variable}.anchor, collection_ts: $snap}})-[:OWNED_BY]->(o:Device)"
        f" WHERE o.collection_ts = $snap RETURN o.uid }}"
        f" ELSE [] END"
    )


def _loaded(variable: str) -> str:
    """True for a node that a scoped load reads. Such a node has a property of
    `WHOLE_RUN_PROPERTIES`, has no owner, or has an owner in `$devices`."""
    owners = _owners(variable)
    carried = " OR ".join(f"{variable}.{name} IS NOT NULL" for name in WHOLE_RUN_PROPERTIES)
    return f"({carried} OR size({owners}) = 0 OR any(owner IN {owners} WHERE owner IN $devices))"


# Every read is a keyset page on the obj_uid_cts index, (uid, collection_ts).
# The index serves `x.uid > $after AND x.collection_ts = $snap` in uid order,
# and a page reads the next LIMIT nodes of the run and stops. Without the hint
# the planner seeks obj_cts on the equality and sorts every node of the run on
# each page. Nodes are paged on their uid. Relationships and attached nodes
# are paged on an anchor node of the run, a window of $window anchors in uid
# order. Only the relationships of that window are sorted, by the anchor and
# then elementId, and the page continues after the last (anchor, key) read.
# An anchor with nothing to return returns one row with a null key, and
# the cursor moves past it.
_ANCHOR = """MATCH (x:Obj)
USING INDEX x:Obj(uid, collection_ts)
WHERE x.uid >= $after_node AND x.collection_ts = $snap
  AND (x.uid > $after_node OR $after_key IS NOT NULL)"""
_WINDOW = "WITH x ORDER BY x.uid LIMIT $window"
_AFTER = "WHERE x.uid > $after_node OR key > $after_key"


def _nodes(scoped: bool) -> str:
    return f"""// graph-load:nodes
MATCH (n:Obj)
USING INDEX n:Obj(uid, collection_ts)
WHERE n.uid > $after AND n.collection_ts = $snap AND NOT n:Retired{" AND " + _loaded("n") if scoped else ""}
RETURN n.uid AS id, labels(n) AS labels, properties(n) AS props
ORDER BY id LIMIT $limit
"""


# Unstamped nodes attached to a node of the run. A scoped load reads all
# of them, and a label read stays whole for them.
_ATTACHED = f"""// graph-load:attached-nodes
{_ANCHOR}
{_WINDOW}
OPTIONAL MATCH (x)-[attached]-(n:Obj)
WHERE n.collection_ts IS NULL AND NOT n:Retired AND {_run("attached")}
WITH x, n, elementId(attached) AS key
{_AFTER}
RETURN x.uid AS anchor, key, n.uid AS id, labels(n) AS labels, properties(n) AS props
ORDER BY anchor, key LIMIT $limit
"""


def _from_run(scoped: bool) -> str:
    """Relationships that start at a node of the run."""
    anchor = " AND NOT x:Retired" + (" AND " + _loaded("x") if scoped else "")
    end = f" AND ({_loaded('y')} OR type(r) IN $boundary)" if scoped else ""
    outside = (
        f",\n       CASE WHEN r IS NULL OR {_loaded('y')} THEN null ELSE {_owners('y')} END AS outside"
        if scoped
        else ""
    )
    return f"""// graph-load:relationships-from-run
{_ANCHOR}{anchor}
{_WINDOW}
OPTIONAL MATCH (x)-[r]->(y:Obj)
WHERE (y.collection_ts = $snap OR y.collection_ts IS NULL) AND NOT y:Retired AND {_run("r")}{end}
WITH x, r, y, elementId(r) AS key
{_AFTER}
RETURN x.uid AS anchor, key, type(r) AS kind, x.uid AS start, y.uid AS end, properties(r) AS props{outside}
ORDER BY anchor, key LIMIT $limit
"""


def _from_unstamped(scoped: bool) -> str:
    """Relationships from an unstamped node to a node of the run."""
    anchor = " AND NOT x:Retired" + (" AND " + _loaded("x") if scoped else "")
    return f"""// graph-load:relationships-from-unstamped
{_ANCHOR}{anchor}
{_WINDOW}
OPTIONAL MATCH (y:Obj)-[r]->(x)
WHERE y.collection_ts IS NULL AND NOT y:Retired AND {_run("r")}
WITH x, r, y, elementId(r) AS key
{_AFTER}
RETURN x.uid AS anchor, key, type(r) AS kind, y.uid AS start, x.uid AS end, properties(r) AS props
ORDER BY anchor, key LIMIT $limit
"""


# The policy bindings into a node that a scoped load reads from a node that it
# omits, with the owners of the omitted start. Only a scoped load sends this query.
_BOUNDARY_RELATIONSHIPS = f"""// graph-load:boundary-relationships
{_ANCHOR} AND NOT x:Retired AND {_loaded("x")}
{_WINDOW}
OPTIONAL MATCH (y:Obj)-[r]->(x)
WHERE type(r) IN $boundary AND y.collection_ts = $snap AND NOT y:Retired AND {_run("r")}
  AND NOT {_loaded("y")}
WITH x, r, y, elementId(r) AS key
{_AFTER}
RETURN x.uid AS anchor, key, type(r) AS kind, y.uid AS start, x.uid AS end, properties(r) AS props,
       CASE WHEN r IS NULL THEN null ELSE {_owners("y")} END AS outside
ORDER BY anchor, key LIMIT $limit
"""

# For each node that a scoped load reads, the relationship types and
# directions that it omits because the other end is outside the scope, with the
# devices that own those ends. A read of such a list raises. Only a scoped load
# sends this query.
_SCOPE_BOUNDARY = f"""// graph-load:scope-boundary
{_ANCHOR} AND NOT x:Retired AND {_loaded("x")}
{_WINDOW}
OPTIONAL MATCH (x)-[r]-(y:Obj)
WHERE y.collection_ts = $snap AND NOT y:Retired AND {_run("r")} AND NOT type(r) IN $boundary
  AND NOT {_loaded("y")}
WITH x, type(r) AS kind,
     CASE WHEN r IS NULL THEN null WHEN startNode(r) = x THEN 'out' ELSE 'in' END AS direction,
     collect({_owners("y")}) AS owner_lists
WITH x, kind, direction, kind + '|' + direction AS key,
     reduce(found = [], owners IN owner_lists | found + owners) AS owners
{_AFTER}
RETURN x.uid AS anchor, key, kind, direction, owners
ORDER BY anchor, key LIMIT $limit
"""

# One node by uid, for a uid that no read returned. Only a scoped load sends this query.
_SCOPE_LOOKUP = f"""// graph-load:scope-lookup
MATCH (n:Obj {{uid: $uid, collection_ts: $snap}})
WHERE NOT n:Retired
RETURN {_loaded("n")} AS loaded, {_owners("n")} AS owners
"""

# Whether any relationship of the run is a VSX transit link. Only a scoped
# load sends this query. A whole-run inventory answers from its relationships.
_VSX_TRANSIT = f"""// graph-load:vsx-transit
RETURN EXISTS {{
  MATCH (x:Obj {{collection_ts: $snap}})-[r]-(y:Obj)
  USING INDEX x:Obj(collection_ts)
  WHERE r.source IN $sources AND NOT x:Retired AND NOT y:Retired AND {_run("r")}
    AND (y.collection_ts = $snap OR y.collection_ts IS NULL)
}} AS present
"""

_PRESENT = "MATCH (n:Obj {collection_ts: $snap}) RETURN count(n) AS count"


@dataclass(frozen=True, slots=True)
class _Segment:
    """One read of a table. A keyed segment pages on (anchor, key). The node
    segment pages on the node uid. `outside` is the column of the end of a
    boundary relationship that the scope omits."""

    query: str
    keyed: bool
    shape: str
    outside: str | None = None


def _segments(scoped: bool) -> dict[str, tuple[_Segment, ...]]:
    tables: dict[str, tuple[_Segment, ...]] = {
        "nodes": (_Segment(_nodes(scoped), False, "node"), _Segment(_ATTACHED, True, "node")),
        "relationships": (
            _Segment(_from_run(scoped), True, "relationship", "end" if scoped else None),
            _Segment(_from_unstamped(scoped), True, "relationship"),
        ),
    }
    if scoped:
        tables["relationships"] += (_Segment(_BOUNDARY_RELATIONSHIPS, True, "relationship", "start"),)
        tables["boundary"] = (_Segment(_SCOPE_BOUNDARY, True, "boundary"),)
    return tables


# The queries a load can send, by name, for plan checks.
LOAD_QUERIES: Mapping[str, str] = MappingProxyType(
    {
        "nodes": _nodes(False),
        "scoped-nodes": _nodes(True),
        "attached-nodes": _ATTACHED,
        "relationships-from-run": _from_run(False),
        "scoped-relationships-from-run": _from_run(True),
        "relationships-from-unstamped": _from_unstamped(False),
        "scoped-relationships-from-unstamped": _from_unstamped(True),
        "boundary-relationships": _BOUNDARY_RELATIONSHIPS,
        "scope-boundary": _SCOPE_BOUNDARY,
        "scope-lookup": _SCOPE_LOOKUP,
        "vsx-transit": _VSX_TRANSIT,
    }
)


@dataclass(slots=True)
class _TableState:
    segment: int = 0
    after: tuple[str, str | None] = ("", None)
    delivered: int = 0
    rows: deque[dict[str, Any]] = field(default_factory=deque)
    seen: set[str] = field(default_factory=set)


class SnapshotGraphProvider:
    """A fixed-table provider bound to the existing snapshot/manifest authority."""

    def __init__(
        self,
        session: Any,
        snapshot: Any,
        manifest_digest: str,
        *,
        cancelled: Callable[[], bool] | None = None,
        digest_reader: Callable[[], str] | None = None,
        devices: Iterable[str] | None = None,
    ):
        if snapshot.cts is None or snapshot.manifest is None:
            raise ReadError("a published snapshot manifest is required")
        if len(manifest_digest) != 64 or any(c not in "0123456789abcdef" for c in manifest_digest):
            raise ReadError("a pinned SHA-256 manifest digest is required")
        self.session = session
        self.snapshot = snapshot
        self.manifest_digest = manifest_digest
        self.cancelled = cancelled
        self.digest_reader = digest_reader or (lambda: manifestmod.digest_of(snapshot.settings, snapshot.cts))
        self.devices = None if devices is None else frozenset(devices)
        self.calls = 0
        # The owning devices per uid of the omitted ends of boundary relationships.
        self.outside: dict[str, frozenset[str]] = {}
        self._tables = _segments(self.devices is not None)
        self._state: dict[str, _TableState] = {}
        self._check()
        present = pathmod._read(session, _PRESENT, snap=snapshot.cts)
        if len(present) != 1 or type(present[0].get("count")) is not int or present[0]["count"] < 1:
            raise ReadError("the pinned graph is unavailable")

    def _check(self) -> None:
        if self.cancelled and self.cancelled():
            raise ReadError("analysis model read cancelled")
        if self.digest_reader() != self.manifest_digest:
            raise ReadError("the pinned manifest changed during model loading")

    def _params(self) -> dict[str, Any]:
        params: dict[str, Any] = {"snap": self.snapshot.cts}
        if self.devices is not None:
            params.update(devices=sorted(self.devices), boundary=list(BOUNDARY_KINDS))
        return params

    def __call__(self, manifest_digest: str, table: str, offset: int, limit: int) -> ReadPage:
        if manifest_digest != self.manifest_digest:
            raise ReadError("provider cannot read another manifest")
        if type(offset) is not int or offset < 0 or type(limit) is not int or limit <= 0:
            raise ReadError("invalid graph page bounds")
        segments = self._tables.get(table)
        if segments is None:
            raise ReadError("unknown graph table")
        # The reader asks for each page at the count of rows that it has read,
        # in order. The cursor of a table continues from the page before.
        state = self._state.get(table)
        if offset == 0:
            state = self._state[table] = _TableState()
        elif state is None or offset != state.delivered:
            raise ReadError("graph pages are read in order")
        while len(state.rows) <= limit and state.segment < len(segments):
            self._fetch(segments[state.segment], state, limit)
        rows = tuple(state.rows.popleft() for _ in range(min(limit, len(state.rows))))
        state.delivered += len(rows)
        terminal = not state.rows and state.segment >= len(segments)
        return ReadPage(
            manifest_digest, table, offset, None, None if terminal else offset + len(rows), terminal, rows
        )

    def _fetch(self, segment: _Segment, state: _TableState, limit: int) -> None:
        self._check()
        params = self._params()
        params["limit"] = limit
        if segment.keyed:
            params.update(after_node=state.after[0], after_key=state.after[1], window=limit + 1)
        else:
            params["after"] = state.after[0]
        rows = pathmod._read(self.session, segment.query, **params)
        self.calls += 1
        self._check()
        if len(rows) > limit:
            raise ReadError("graph provider exceeded requested page size")
        before = state.after
        for row in rows:
            if segment.keyed:
                anchor, key = row.get("anchor"), row.get("key")
                if not isinstance(anchor, str) or (key is not None and not isinstance(key, str)):
                    raise ReadError("graph page row lacks its anchor and key")
                state.after = (anchor, key)
                if key is None:
                    continue
            else:
                state.after = (_text(row.get("id"), "node"), None)
            converted = self._convert(segment, row, state)
            if converted is not None:
                state.rows.append(converted)
        if rows and state.after == before:
            raise ReadError("graph page did not advance")
        # A keyed page can return fewer rows than the limit while anchors
        # remain past its window. Only an empty page ends a keyed segment.
        if not rows or (not segment.keyed and len(rows) < limit):
            state.segment += 1
            state.after = ("", None)

    def _convert(
        self, segment: _Segment, row: Mapping[str, Any], state: _TableState
    ) -> dict[str, Any] | None:
        if segment.shape == "node":
            uid = _text(row.get("id"), "node")
            if uid in state.seen:
                return None
            if segment.keyed:
                state.seen.add(uid)
            return {"id": uid, "labels": row.get("labels"), "props": row.get("props")}
        if segment.shape == "boundary":
            owners = row.get("owners")
            if not isinstance(owners, (list, tuple)):
                raise ReadError("malformed scope boundary row")
            return {
                "id": f"{row['anchor']}|{row['key']}",
                "node": row["anchor"],
                "kind": row.get("kind"),
                "direction": row.get("direction"),
                "owners": sorted({_text(owner, "device") for owner in owners}),
            }
        relationship = {key: row.get(key) for key in ("kind", "start", "end", "props")}
        relationship["id"] = row["key"]
        owners = row.get("outside") if segment.outside else None
        if owners is not None and segment.outside is not None:
            if not isinstance(owners, (list, tuple)) or not owners:
                raise ReadError("malformed boundary relationship owners")
            self.outside[_text(row.get(segment.outside), "relationship end")] = frozenset(
                _text(owner, "device") for owner in owners
            )
        return relationship

    def vsx_transit(self) -> bool:
        """Whether any relationship of the run is a VSX transit link."""
        self._check()
        rows = pathmod._read(
            self.session, _VSX_TRANSIT, snap=self.snapshot.cts, sources=sorted(VSX_TRANSIT_SOURCES)
        )
        self.calls += 1
        self._check()
        if len(rows) != 1 or type(rows[0].get("present")) is not bool:
            raise ReadError("malformed VSX transit read")
        return rows[0]["present"]

    def lookup(self, uid: str) -> frozenset[str] | None:
        """For a scoped load, the owners of `uid` when the scope omits that
        node of the run, None when the run has no such node, and an empty set
        when the node should have been read (only the whole run answers)."""
        if self.devices is None:
            raise ReadError("only a scoped load looks nodes up")
        self._check()
        rows = pathmod._read(self.session, _SCOPE_LOOKUP, uid=uid, **self._params())
        self.calls += 1
        self._check()
        if not rows:
            return None
        if rows[0].get("loaded") is not False:
            return frozenset()
        return frozenset(_text(owner, "device") for owner in rows[0].get("owners") or ())


def _text(value: Any, subject: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ReadError(f"{subject} requires a canonical string identity")
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class GraphNode:
    uid: str
    labels: frozenset[str]
    props: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class GraphRelation:
    uid: str
    kind: str
    start: str
    end: str
    props: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class GraphInventory:
    manifest_digest: str
    fingerprint: str
    nodes: Mapping[str, GraphNode]
    labels: Mapping[str, tuple[str, ...]]
    outgoing: Mapping[tuple[str, str], tuple[GraphRelation, ...]]
    incoming: Mapping[tuple[str, str], tuple[GraphRelation, ...]]
    complete: bool
    gaps: tuple[str, ...]
    database_reads: int
    # Indexes derived from this inventory once and reused by every model built
    # on it (the EPG index of the ACI contract gate). The field is no
    # `__init__` argument. A copy made with dataclasses.replace starts empty.
    derived: dict[Any, Any] = field(default_factory=dict, init=False, repr=False, compare=False)
    # The devices whose bulk a scoped load read, or None for the whole run.
    scope: frozenset[str] | None = None
    # Whether the run holds a VSX transit link. With None, `has_vsx_transit` reads the relationships.
    vsx_transit: bool | None = None

    def has_vsx_transit(self) -> bool:
        """Whether any relationship of the run is a VSX transit link
        (`VSX_TRANSIT_SOURCES`). The load of a scoped inventory sets `vsx_transit`."""
        if self.vsx_transit is not None:
            return self.vsx_transit
        return any(
            rel.props.get("source") in VSX_TRANSIT_SOURCES for rels in self.outgoing.values() for rel in rels
        )

    def nodes_carrying(self, name: str) -> Iterator[GraphNode]:
        """Every node with the property `name`, in load order. A scoped
        inventory answers for `WHOLE_RUN_PROPERTIES` only."""
        nodes = self.nodes
        if isinstance(nodes, _ScopedNodes):
            if name not in WHOLE_RUN_PROPERTIES:
                nodes._guard.whole(f"a read of every node with {name}")
            nodes = nodes._items
        return (node for node in nodes.values() if node.props.get(name) is not None)

    def targets(self, uid: str, kind: str) -> tuple[GraphNode, ...]:
        return tuple(
            self.nodes[rel.end] for rel in self.outgoing.get((uid, kind), ()) if rel.end in self.nodes
        )

    def sources(self, uid: str, kind: str) -> tuple[GraphNode, ...]:
        return tuple(
            self.nodes[rel.start] for rel in self.incoming.get((uid, kind), ()) if rel.start in self.nodes
        )

    @classmethod
    def from_tables(
        cls,
        nodes: MaterializedTable,
        relationships: MaterializedTable,
        *,
        database_reads: int = 0,
        ordered: bool = False,
        outside: Iterable[str] = (),
    ) -> GraphInventory:
        """Index the two tables. `ordered` sorts the relationships by start
        node and then uid, and every adjacency list has one order for any reads
        that produced the table. `outside` holds the relationship ends that a
        scoped load omits. These ends do not count as missing endpoints."""
        if nodes.manifest_digest != relationships.manifest_digest:
            raise ReadError("graph tables belong to different manifests")
        catalog: dict[str, GraphNode] = {}
        labels: dict[str, list[str]] = defaultdict(list)
        outgoing: dict[tuple[str, str], list[GraphRelation]] = defaultdict(list)
        incoming: dict[tuple[str, str], list[GraphRelation]] = defaultdict(list)
        gaps: set[str] = set()
        if not nodes.complete or not relationships.complete:
            gaps.add("GRAPH_TABLE_INCOMPLETE")
        for row in nodes.rows:
            uid = _text(row.get("id"), "node")
            raw_labels, props = row.get("labels"), row.get("props")
            if not isinstance(raw_labels, (tuple, list)) or not raw_labels or not isinstance(props, Mapping):
                raise ReadError("malformed graph node")
            if uid in catalog or props.get("uid", uid) != uid:
                raise ReadError("duplicate or inconsistent graph node identity")
            kinds = frozenset(_text(label, "label") for label in raw_labels)
            if "Retired" in kinds:
                raise ReadError("retired node in active graph input")
            catalog[uid] = GraphNode(uid, kinds, _freeze(props))
            for label in kinds:
                labels[label].append(uid)
        seen: set[str] = set()
        omitted = frozenset(outside)
        rows = relationships.rows
        if ordered:
            rows = tuple(sorted(rows, key=lambda row: (str(row.get("start")), str(row.get("id")))))
        for row in rows:
            uid = _text(row.get("id"), "relationship")
            kind, start, end = (_text(row.get(key), key) for key in ("kind", "start", "end"))
            props = row.get("props")
            if uid in seen or not isinstance(props, Mapping) or props.get("_retired_at") is not None:
                raise ReadError("duplicate, retired or malformed graph relationship")
            seen.add(uid)
            if (start not in catalog and start not in omitted) or (end not in catalog and end not in omitted):
                gaps.add("GRAPH_RELATIONSHIP_ENDPOINT_MISSING")
            relation = GraphRelation(uid, kind, start, end, _freeze(props))
            outgoing[start, kind].append(relation)
            incoming[end, kind].append(relation)
        fingerprint = hashlib.sha256(
            json.dumps((nodes.fingerprint, relationships.fingerprint), separators=(",", ":")).encode()
        ).hexdigest()
        return cls(
            nodes.manifest_digest,
            fingerprint,
            MappingProxyType(catalog),
            MappingProxyType({key: tuple(sorted(value)) for key, value in labels.items()}),
            MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
            MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
            not gaps,
            tuple(sorted(gaps)),
            database_reads,
        )


class _ScopeGuard:
    """The data of a scoped inventory about the part of the run that it omits."""

    def __init__(
        self,
        devices: frozenset[str],
        nodes: Mapping[str, GraphNode],
        outside: dict[str, frozenset[str]],
        truncated: Mapping[tuple[str, str, str], frozenset[str]],
        lookup: Callable[[str], frozenset[str] | None],
    ) -> None:
        self.devices, self.nodes, self.outside = devices, nodes, outside
        self.truncated, self.lookup = truncated, lookup
        self.absent: set[str] = set()

    def whole(self, read: str) -> NoReturn:
        raise ScopeExtension(None, f"{read} needs the whole run", self.devices)

    def node(self, uid: Any) -> bool:
        """True for a node that the load read, False for a uid that the run does
        not hold. `node` raises `ScopeExtension` for a node of the run that the
        scope omits."""
        if not isinstance(uid, str):
            return False
        if uid in self.nodes:
            return True
        owners = self.outside.get(uid)
        if owners is None:
            if uid in self.absent:
                return False
            owners = self.lookup(uid)
            if owners is None:
                self.absent.add(uid)
                return False
            self.outside[uid] = owners
        if not owners:
            self.whole(f"node {uid}")
        raise ScopeExtension(owners, f"node {uid} belongs to a device outside the scope", self.devices)

    def relations(self, uid: str, kind: str, direction: str) -> None:
        owners = self.truncated.get((uid, kind, direction))
        if owners is not None:
            if not owners:
                self.whole(f"the {direction} {kind} relationships of {uid}")
            raise ScopeExtension(
                owners, f"{uid} has {direction} {kind} relationships outside the scope", self.devices
            )


class _ScopedNodes(Mapping[str, GraphNode]):
    __slots__ = ("_guard", "_items")

    def __init__(self, items: Mapping[str, GraphNode], guard: _ScopeGuard) -> None:
        self._items, self._guard = items, guard

    def __getitem__(self, uid: str) -> GraphNode:
        if self._guard.node(uid):
            return self._items[uid]
        raise KeyError(uid)

    def __contains__(self, uid: object) -> bool:
        return self._guard.node(uid)

    def get(self, uid: str, default: Any = None) -> Any:
        return self._items[uid] if self._guard.node(uid) else default

    def __iter__(self) -> Iterator[str]:
        self._guard.whole("a read of every node")

    def __len__(self) -> int:
        self._guard.whole("a count of the nodes")


class _ScopedLabels(Mapping[str, tuple[str, ...]]):
    __slots__ = ("_guard", "_items")

    def __init__(self, items: Mapping[str, tuple[str, ...]], guard: _ScopeGuard) -> None:
        self._items, self._guard = items, guard

    def _known(self, label: object) -> None:
        if label in SCOPED_LABELS:
            self._guard.whole(f"a read of every {label} node")

    def __getitem__(self, label: str) -> tuple[str, ...]:
        self._known(label)
        return self._items[label]

    def __contains__(self, label: object) -> bool:
        self._known(label)
        return label in self._items

    def get(self, label: str, default: Any = None) -> Any:
        self._known(label)
        return self._items.get(label, default)

    def __iter__(self) -> Iterator[str]:
        self._guard.whole("a read of every label")

    def __len__(self) -> int:
        self._guard.whole("a count of the labels")


class _ScopedRelations(Mapping[tuple[str, str], tuple[GraphRelation, ...]]):
    __slots__ = ("_direction", "_guard", "_items")

    def __init__(
        self, items: Mapping[tuple[str, str], tuple[GraphRelation, ...]], guard: _ScopeGuard, direction: str
    ) -> None:
        self._items, self._guard, self._direction = items, guard, direction

    def _known(self, key: object) -> bool:
        if not isinstance(key, tuple) or len(key) != 2:
            return False
        uid, kind = key
        if not self._guard.node(uid):
            return False
        self._guard.relations(uid, kind, self._direction)
        return True

    def __getitem__(self, key: tuple[str, str]) -> tuple[GraphRelation, ...]:
        if self._known(key):
            return self._items[key]
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        return self._known(key) and key in self._items

    def get(self, key: tuple[str, str], default: Any = None) -> Any:
        return self._items.get(key, default) if self._known(key) else default

    def __iter__(self) -> Iterator[tuple[str, str]]:
        self._guard.whole("a read of every relationship")

    def __len__(self) -> int:
        self._guard.whole("a count of the relationships")


def scoped_inventory(
    nodes: MaterializedTable,
    relationships: MaterializedTable,
    boundary: MaterializedTable,
    devices: frozenset[str],
    outside: Mapping[str, frozenset[str]],
    lookup: Callable[[str], frozenset[str] | None],
    *,
    vsx_transit: bool,
    database_reads: int = 0,
) -> GraphInventory:
    """The inventory of a scoped load. A read that it holds whole returns what a
    whole-run inventory returns. Any other read raises `ScopeExtension`.

    `boundary` holds, per node read, the relationship types and directions
    that end outside the scope and the devices that own those ends. `outside`
    holds the omitted ends of policy bindings (`BOUNDARY_KINDS`) with their
    owners. `lookup` answers for a uid that no read returned."""
    if boundary.manifest_digest != nodes.manifest_digest:
        raise ReadError("graph tables belong to different manifests")
    base = GraphInventory.from_tables(
        nodes, relationships, database_reads=database_reads, ordered=True, outside=outside
    )
    truncated: dict[tuple[str, str, str], frozenset[str]] = {}
    for row in boundary.rows:
        node, kind, direction = (_text(row.get(key), key) for key in ("node", "kind", "direction"))
        owners = row.get("owners")
        if direction not in ("in", "out") or not isinstance(owners, (list, tuple)):
            raise ReadError("malformed scope boundary row")
        truncated[node, kind, direction] = frozenset(_text(owner, "device") for owner in owners)
    guard = _ScopeGuard(devices, base.nodes, dict(outside), MappingProxyType(truncated), lookup)
    fingerprint = hashlib.sha256(
        json.dumps((base.fingerprint, boundary.fingerprint, sorted(devices)), separators=(",", ":")).encode()
    ).hexdigest()
    return GraphInventory(
        base.manifest_digest,
        fingerprint,
        _ScopedNodes(base.nodes, guard),
        _ScopedLabels(base.labels, guard),
        _ScopedRelations(base.outgoing, guard, "out"),
        _ScopedRelations(base.incoming, guard, "in"),
        base.complete,
        base.gaps,
        base.database_reads,
        devices,
        vsx_transit,
    )


def load_graph(
    session: Any,
    snapshot: Any,
    manifest_digest: str,
    *,
    memory_mb: int = DEFAULT_MEMORY_MB,
    max_rows: int | None = None,
    max_bytes: int | None = None,
    page_size: int = 1000,
    devices: Iterable[str] | None = None,
    cancelled: Callable[[], bool] | None = None,
    digest_reader: Callable[[], str] | None = None,
) -> GraphInventory:
    """Read the run, or with `devices` the part of it those devices hold.

    The row and byte budgets of each table follow the analysis worker memory
    (`graph_budget(memory_mb)`) unless `max_rows` or `max_bytes` set them. A
    budget failure rejects loading with `GraphTooLarge` (SCOPE_TOO_LARGE). A
    scoped load returns an inventory that raises `ScopeExtension` on a read it
    cannot answer as the whole run would (`scoped_inventory`). All table reads
    finish before the inventory is returned. A scoped inventory may look single
    nodes up by uid later, through the same session and manifest checks.
    """
    rows_budget, bytes_budget = graph_budget(memory_mb)
    max_rows = rows_budget if max_rows is None else max_rows
    max_bytes = bytes_budget if max_bytes is None else max_bytes
    provider = SnapshotGraphProvider(
        session, snapshot, manifest_digest, cancelled=cancelled, digest_reader=digest_reader, devices=devices
    )
    reader = BoundedTableReader(
        provider,
        manifest_digest,
        max_rows=max_rows,
        max_bytes=max_bytes,
        page_size=page_size,
        max_page_rows=page_size,
        max_pages=max(100_000, max_rows // page_size + 2),
    )

    def read(table: str) -> MaterializedTable:
        try:
            return reader.read(table)
        except TableBudgetExceeded as exc:
            part = (
                "the whole run"
                if provider.devices is None
                else f"the objects of {len(provider.devices)} devices"
            )
            raise GraphTooLarge(
                f"SCOPE_TOO_LARGE: the {table} of {part} exceed the {max_rows} rows and {max_bytes} bytes"
                f" a table may hold in a {memory_mb} MiB analysis worker ({exc})"
            ) from exc

    # The Check Point envelopes are side-store rows of the pinned run. The
    # nodes hold their digests (checkpoint_envelopes.py).
    nodes = checkpoint_envelopes.hydrate(read("nodes"), snapshot)
    relationships = read("relationships")
    if provider.devices is None:
        provider._check()
        return GraphInventory.from_tables(
            nodes, relationships, database_reads=provider.calls + 1, ordered=True
        )
    boundary = read("boundary")
    vsx_transit = provider.vsx_transit()
    provider._check()
    return scoped_inventory(
        nodes,
        relationships,
        boundary,
        provider.devices,
        provider.outside,
        provider.lookup,
        vsx_transit=vsx_transit,
        database_reads=provider.calls + 1,
    )


# Scoped loads one analysis tries before it loads the whole run.
MAX_SCOPED_LOADS = 4


def load_scoped(
    load: Callable[[frozenset[str] | None], GraphInventory],
    use: Callable[[GraphInventory], Any],
    scope: frozenset[str] | None,
    *,
    attempts: int = MAX_SCOPED_LOADS,
) -> Any:
    """Run `use` on the inventory `load(scope)` returns, widening the scope
    and loading again each time a read raises `ScopeExtension`. After
    `attempts` scoped loads the whole run is loaded."""
    for _attempt in range(attempts):
        if scope is None:
            break
        try:
            return use(load(scope))
        except ScopeExtension as extension:
            scope = extension.widened()
    return use(load(None))
