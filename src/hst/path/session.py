"""CycleSession, the timed read helpers, and the load of every gateway
interface and prefix pair for longest-prefix match.
"""

from __future__ import annotations

import copy
import ipaddress
import threading
from collections import OrderedDict
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from neo4j import unit_of_work

import hst.path as _path

if TYPE_CHECKING:
    from hst.core.snapshot import Snapshot

READ_TIMEOUT_S = 30.0

# The most read-cache entries one CycleSession keeps.
READ_CACHE_MAX = 4096

# LIVE_SNAP is bound to $snap when no run is pinned. No versioned node has this value.
from hst.core.snapshot import LIVE_SNAP, NoRun  # noqa: E402, F401 - re-exported


class CycleSession:
    """A duck-typed session that pins every tracer read to one run.

    `cts` is the collection_ts that `_read` binds to $snap.

    `snapshot` is the `Snapshot` the request resolved (`core/snapshot.py`)
    when `pinned` built the session, else None.

    `_read_cache` holds the raw rows of each read `_read` has run on this
    session, keyed by query text and parameters. A caller that writes to the
    graph and then reads the same run again needs a new session.
    """

    def __init__(self, session: Any, cts: int, snapshot: Snapshot | None = None) -> None:
        self._session = session
        self.cts = cts
        self.snapshot = snapshot
        self._read_cache: dict[Any, Any] = {}

    def execute_read(self, work: Any, /) -> Any:
        return self._session.execute_read(work)

    def run(self, query: str, **params: Any) -> Any:
        """Autocommit passthrough for the one-row meta reads of a request
        (`cycle.run_status`)."""
        return self._session.run(query, **params)


def pinned(session: Any, snapshot: Snapshot) -> Any:
    """The session, pinned to the run of `snapshot` when it has one.

    A snapshot with no run (a pre-migration graph, a session that cannot answer
    the pointer read) returns the session unpinned.
    """
    return CycleSession(session, snapshot.cts, snapshot) if snapshot.cts is not None else session


def _read(session: Any, query: str, **params: Any) -> Any:
    """Run one read of the tracer inside a managed transaction with the
    timeout READ_TIMEOUT_S.

    $snap is bound to the `cts` of the session when it has one (CycleSession)
    and to LIVE_SNAP otherwise.

    A session can have `overlay`, a callable `(query, params, rows) -> rows`
    that rewrites the rows of a read.

    A session can have `_read_cache`, a dict (`CycleSession` sets one). The
    cache stores the raw rows, and the overlay runs on every read. Rows are
    deep-copied on store and on hit. A read whose parameters cannot be frozen
    into a key is not cached.
    """
    params.setdefault("snap", getattr(session, "cts", LIVE_SNAP))

    @unit_of_work(timeout=READ_TIMEOUT_S)
    def work(tx: Any) -> Any:
        return tx.run(query, **params).data()

    cache: dict[Any, Any] | None = getattr(session, "_read_cache", None)
    key = None
    if cache is not None:
        try:
            key = _freeze((query, params))
        except TypeError:
            cache = None
    if cache is not None and key in cache:
        rows = copy.deepcopy(cache[key])
    else:
        rows = session.execute_read(work)
        if cache is not None:
            if len(cache) >= READ_CACHE_MAX:
                del cache[next(iter(cache))]
            cache[key] = copy.deepcopy(rows)
    overlay = getattr(session, "overlay", None)
    return rows if overlay is None else overlay(query, params, rows)


def _freeze(value: Any) -> Any:
    """A hashable form of the query and parameters of a read, for the cache key.

    A dict becomes a sorted tuple of its items. A list or tuple becomes a
    tagged tuple. A set becomes a frozenset. Raises TypeError when a value
    cannot be made hashable or keys cannot be sorted.
    """
    if isinstance(value, dict):
        return ("dict", tuple(sorted((k, _freeze(v)) for k, v in value.items())))
    if isinstance(value, (list, tuple)):
        return ("seq", tuple(_freeze(v) for v in value))
    if isinstance(value, (set, frozenset)):
        return ("set", frozenset(_freeze(v) for v in value))
    hash(value)
    return value


# gateway_for_cts indexes GATEWAY_FOR on the run of the edge.
GATEWAYS = """
MATCH (i:Interface:Obj)-[g:GATEWAY_FOR {collection_ts: $snap}]->(p:Prefix)
WHERE i.collection_ts = $snap AND NOT i:Retired AND NOT p:Retired AND g._retired_at IS NULL
MATCH (i)-[:ON]->(d:Device)
RETURN p.cidr AS cidr, p.l3dom AS l3dom, p.anchor AS anchor, i.uid AS if_uid, i.name AS if_name,
       d.uid AS dev_uid, d.hostname AS dev_name, coalesce(d.carried, false) AS dev_carried,
       d.carried_reason AS dev_carried_reason,
       i.vsx_cluster AS vsx_cluster, i.vsx_state AS vsx_state,
       i.firewall_instance_uid AS firewall_instance_uid, i.vsid AS vsid, i.vsx_kind AS vsx_kind"""


def _read_one(session: Any, query: str, **params: Any) -> Any:
    rows = _path._read(session, query, **params)
    return rows[0] if rows else None


def prefix_index(rows: Iterable[dict[str, Any]]) -> dict[tuple[int, int, int], list[int]]:
    """The positions of `rows` by (IP version, prefix length, network as an
    integer). A row whose cidr does not parse as a network is left out."""
    index: dict[tuple[int, int, int], list[int]] = {}
    for pos, row in enumerate(rows):
        try:
            net = ipaddress.ip_network(row["cidr"])
        except (KeyError, TypeError, ValueError):
            continue
        index.setdefault((net.version, net.prefixlen, int(net.network_address)), []).append(pos)
    return index


class GatewayRows(list[dict[str, Any]]):
    """The gateway rows of one run with an index of their prefixes, built once."""

    def __init__(
        self, rows: Iterable[dict[str, Any]] = (), index: dict[tuple[int, int, int], list[int]] | None = None
    ) -> None:
        super().__init__(rows)
        self._index = index

    def prefix_index(self) -> dict[tuple[int, int, int], list[int]]:
        if self._index is None:
            self._index = prefix_index(self)
        return self._index


# A process keeps the gateway rows of its last GATEWAY_CACHE_RUNS runs. The key
# is the run and the digest, node count, relationship count and
# `reprocessed_from` of its meta node. A run with no meta node, an unpinned
# session or a session with a simulation overlay is not cached.
GATEWAY_CACHE_RUNS = 4
_RUN_IDENTITY = """
MATCH (c:CycleRun {uid: $uid})
RETURN c.manifest_digest AS digest, c.nodes AS nodes, c.rels AS rels,
       c.reprocessed_from AS reprocessed_from"""
_GATEWAY_CACHE: OrderedDict[tuple[Any, ...], GatewayRows] = OrderedDict()
_GATEWAY_LOCK = threading.Lock()


def load_gateways(session: Any) -> GatewayRows:
    """Every gateway interface/prefix pair in the estate.

    Longest-prefix match and per-domain filtering run in Python over the whole
    set. The rows of a pinned run are kept per process (`_GATEWAY_CACHE`) and
    handed out as shallow copies.
    """
    cts = getattr(session, "cts", None)
    if not isinstance(cts, int) or getattr(session, "overlay", None) is not None:
        return GatewayRows(_path._read(session, GATEWAYS))
    meta = _read_one(session, _RUN_IDENTITY, uid=f"cycle:{cts}")
    if meta is None:
        return GatewayRows(_path._read(session, GATEWAYS))
    key = (cts, meta["digest"], meta["nodes"], meta["rels"], meta["reprocessed_from"])
    with _GATEWAY_LOCK:
        held = _GATEWAY_CACHE.get(key)
        if held is not None:
            _GATEWAY_CACHE.move_to_end(key)
    if held is None:
        held = GatewayRows(_path._read(session, GATEWAYS))
        held.prefix_index()
        with _GATEWAY_LOCK:
            _GATEWAY_CACHE[key] = held
            while len(_GATEWAY_CACHE) > GATEWAY_CACHE_RUNS:
                _GATEWAY_CACHE.popitem(last=False)
    return GatewayRows((dict(row) for row in held), held.prefix_index())
