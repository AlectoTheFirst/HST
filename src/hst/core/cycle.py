"""There are four kinds of run, recorded as `kind` on the `:CycleRun` node:

full     a cycle over every source
partial  a cycle over a subset of the sources
refresh  an operator press of one source
device   one window of per-device fetch jobs, folded in together
"""

from __future__ import annotations

import heapq
import itertools
import logging
import pickle
import re
import tempfile
import time
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from operator import itemgetter
from typing import IO, TYPE_CHECKING, Any

from neo4j import Session, unit_of_work
from neo4j.exceptions import DriverError, Neo4jError

from . import ipenc
from . import loader as loadermod
from . import uid as uidmod
from .config import KEEP_DEVICE_RUNS_DEFAULT
from .labels import LABELS, CycleIdentityCollision

if TYPE_CHECKING:
    from .snapshot import Snapshot

log = logging.getLogger(__name__)

BATCH = 5000

POINTER_UID = "meta:cycle-pointer"

# Loads never touch the :Meta pointer node.
_SET_POINTER = (
    "MERGE (p:Obj:CyclePointer:Meta {uid: $uid}) "
    "SET p.current = $cts, p._scope = 'meta:cycle', p.updated = $iso"
)
_GET_POINTER = "MATCH (p:CyclePointer {uid: $uid}) RETURN p.current AS current"

# The pointer keeps the highest fence it has been moved with.
_SET_POINTER_FENCED = (
    "MERGE (p:Obj:CyclePointer:Meta {uid: $uid}) "
    "WITH p, coalesce(p.fence, -1) AS held "
    "WHERE held <= $fence "
    "SET p.current = $cts, p.fence = $fence, p._scope = 'meta:cycle', p.updated = $iso "
    "RETURN p.current AS current"
)


class StaleFence(RuntimeError):
    """`set_pointer` refused a publication.

    `set_pointer` raises it when the pointer has a fence above the offered
    fence. The writes of the run stay in the graph under their collection_ts,
    and retention removes them. The run row records the refusal as its failure.
    """


def new_collection_ts() -> int:
    return int(time.time() * 1000)


def _iso(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000, tz=UTC).isoformat(timespec="seconds")


def _write(session: Session, query: str, **params: Any) -> list[dict[str, Any]]:
    return session.execute_write(lambda tx: tx.run(query, **params).data())


def _read(session: Session, query: str, **params: Any) -> list[dict[str, Any]]:
    return session.execute_read(lambda tx: tx.run(query, **params).data())


def device_scopes(session: Session, prev: int, uids: list[str], source: str) -> list[str]:
    if not uids:
        return []
    rows = _read(
        session,
        "MATCH (d:Device:Obj {collection_ts: $prev}) "
        "WHERE d.uid IN $uids AND $source IN d._sources AND d._scope IS NOT NULL "
        "RETURN DISTINCT d._scope AS scope",
        prev=prev,
        uids=uids,
        source=source,
    )
    return [row["scope"] for row in rows]


# The scopes of the Device nodes of each unit in the parent run that differ
# from the scope of the unit (`written_scopes`). One statement reads every
# unit. The MATCH uses the (uid, collection_ts) pair of the uniqueness
# constraint.
_WRITTEN_SCOPES = """
UNWIND $units AS unit
UNWIND unit.uids AS device
MATCH (d:Obj {uid: device, collection_ts: $prev})
WHERE d:Device AND unit.source IN coalesce(d._sources, [])
  AND d._scope IS NOT NULL AND d._scope <> unit.scope
RETURN DISTINCT unit.scope AS scope, d._scope AS written
"""


def written_scopes(
    session: Session, prev: int, units: Iterable[tuple[str, str, Iterable[str]]]
) -> dict[str, list[str]]:
    """Return, for each unit scope, the sorted scopes of the Device nodes of the
    unit in run `prev` that differ from the unit scope.

    `units` holds `(source, scope, device uids)` for each unit. The uids come
    from the manifest of the parent run. A unit without uids is not read. Only
    a Device whose `_sources` holds the source of the unit is read.
    """
    rows = [
        {"source": source, "scope": scope, "uids": sorted(set(uids))}
        for source, scope, uids in units
        if scope and uids
    ]
    if not rows:
        return {}
    found: dict[str, set[str]] = defaultdict(set)
    for row in _read(session, _WRITTEN_SCOPES, prev=prev, units=rows):
        found[str(row["scope"])].add(str(row["written"]))
    return {scope: sorted(written) for scope, written in found.items()}


def current_ts(session: Session) -> int | None:
    """The pointer's current collection_ts, or None before the first cycle."""
    rows = session.run(_GET_POINTER, uid=POINTER_UID).data()
    return rows[0]["current"] if rows else None


def current_ts_or_none(session: Any) -> int | None:
    try:
        return current_ts(session)
    except (Neo4jError, DriverError):
        raise
    except Exception:
        log.warning("could not resolve the current cycle pointer; continuing unpinned", exc_info=True)
        return None


def set_pointer(session: Session, cts: int, fence: int | None = None) -> None:
    """A reader resolving the pointer sees either the old run or the new one."""
    if fence is None:
        _write(session, _SET_POINTER, uid=POINTER_UID, cts=cts, iso=_iso(cts))
        return
    if not _write(session, _SET_POINTER_FENCED, uid=POINTER_UID, cts=cts, iso=_iso(cts), fence=fence):
        raise StaleFence(
            f"run {cts} was built under cycle lock fence {fence} and the pointer has since "
            f"been moved by a later one; not publishing it"
        )


# The 2 prune statements use CALL IN TRANSACTIONS, which requires an implicit
# (autocommit) transaction. `session.run` opens one.


def _run_batched(session: Session, query: str, **params: Any) -> None:
    session.run(query, **params).consume()


# --- streamed reads ---------------------------------------------------------------------

# One read holds about 2 times SPILL_ROWS rows in memory.
SPILL_ROWS = 20_000
SPILL_RUNS = 32


def stream_rows(tx: Any, query: str, **params: Any) -> Iterable[Mapping[str, Any]]:
    """Return the records of `query`. A result that is not iterable is read with `data()`."""
    result = tx.run(query, **params)
    if isinstance(result, Iterable):
        return result
    return result.data()


class SortedRows:
    """Rows added one at a time with a key and read back in key order.

    The object holds up to `bucket` rows. A full bucket is sorted and written
    to a temporary file as one sorted run. Iteration merges the runs and the
    held rows into one sequence of `(key, row)` pairs (`heapq.merge`). Rows
    with equal keys come back in the order of their addition. The sequence
    equals a stable sort of every row.

    Runs are merged by level. The run of a bucket has level 0. When `fan_in`
    runs of one level exist, they are merged into one run of the next level.
    A row is rewritten once for each level, about log_fan_in(rows / bucket)
    times. At most `fan_in - 1` runs of each level are open between merges.
    At the defaults 3 levels hold about 650 million rows. Before the rows are
    read back, the levels below the top are merged upward until at most
    `fan_in` runs remain. Runs are written and read in blocks of
    `bucket // fan_in` rows. The object holds about 2 buckets of rows in
    memory. They are the rows not yet written and one block of each of at
    most `fan_in` runs in a merge or a read.

    Keys must be comparable with each other. The callers use strings and
    tuples of strings and integers. The rows are driver values (strings,
    numbers, lists, temporal and spatial types). pickle round-trips them
    exactly. Only this object writes and reads the files. The files have no
    name (`tempfile.TemporaryFile`), and a crash leaves no file behind.

    The rows can be iterated once. `close` or the context manager releases
    the files.
    """

    def __init__(self, bucket: int | None = None, fan_in: int | None = None) -> None:
        self._bucket = max(1, SPILL_ROWS if bucket is None else bucket)
        self._fan_in = max(2, SPILL_RUNS if fan_in is None else fan_in)
        self._block = max(1, self._bucket // self._fan_in)
        self._held: list[tuple[Any, int, Any]] = []
        # The open runs by level. A run of level n holds about
        # bucket * fan_in ** n rows.
        self._levels: list[list[IO[bytes]]] = []
        self._seq = 0

    def add(self, key: Any, row: Any) -> None:
        # The sequence number orders equal keys by arrival. It is unique, and
        # no comparison of 2 entries reaches the row.
        self._held.append((key, self._seq, row))
        self._seq += 1
        if len(self._held) < self._bucket:
            return
        self._held.sort()
        run = self._write(self._held)
        self._held = []
        self._push(0, run)

    def _push(self, level: int, run: IO[bytes]) -> None:
        """Add `run` to `level`.

        A level that reaches `fan_in` runs is merged into one run, and that run
        is added to the next level in the same way."""
        while True:
            if level == len(self._levels):
                self._levels.append([])
            self._levels[level].append(run)
            if len(self._levels[level]) < self._fan_in:
                return
            runs, self._levels[level] = self._levels[level], []
            run = self._merge(runs)
            level += 1

    def _merge(self, runs: list[IO[bytes]]) -> IO[bytes]:
        """Return one run with the entries of `runs`. `runs` are closed also when the merge fails."""
        try:
            return self._write(heapq.merge(*map(self._read, runs)))
        finally:
            for run in runs:
                run.close()

    def _write(self, entries: Iterable[tuple[Any, int, Any]]) -> IO[bytes]:
        run: IO[bytes] = tempfile.TemporaryFile()  # noqa: SIM115 - closed by close() or the merge
        try:
            for block in itertools.batched(entries, self._block, strict=False):
                pickle.dump(block, run, protocol=pickle.HIGHEST_PROTOCOL)
        except BaseException:
            run.close()
            raise
        return run

    @staticmethod
    def _read(run: IO[bytes]) -> Iterator[tuple[Any, int, Any]]:
        run.seek(0)
        while True:
            try:
                block = pickle.load(run)  # noqa: S301 - this object wrote the file
            except EOFError:
                return
            yield from block

    def _open_runs(self) -> list[IO[bytes]]:
        """Return the open runs.

        The levels below the top are merged upward, lowest first, until at most
        `fan_in` runs remain. Every level holds fewer than `fan_in` runs. The
        merge of the lower levels adds at most one run to the top level."""
        for level in range(len(self._levels) - 1):
            if sum(map(len, self._levels)) <= self._fan_in:
                break
            runs, self._levels[level] = self._levels[level], []
            if runs:
                self._push(level + 1, runs[0] if len(runs) == 1 else self._merge(runs))
        return [run for runs in self._levels for run in runs]

    def __iter__(self) -> Iterator[tuple[Any, Any]]:
        self._held.sort()
        runs = self._open_runs()
        entries: Iterable[tuple[Any, int, Any]] = self._held
        if runs:
            entries = heapq.merge(*map(self._read, runs), self._held)
        return ((key, row) for key, _seq, row in entries)

    def close(self) -> None:
        for runs in self._levels:
            for run in runs:
                run.close()
        self._levels = []
        self._held = []

    def __enter__(self) -> SortedRows:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def read_sorted(
    session: Session,
    query: str,
    entry: Callable[[Mapping[str, Any]], tuple[Any, Any]],
    /,
    *,
    timeout_s: float | None = None,
    **params: Any,
) -> SortedRows:
    """Return the rows of one read in a `SortedRows`.

    `entry` turns one record into its `(key, row)`. The records are consumed
    inside the read transaction as the driver fetches them. The read holds
    only the rows that `SortedRows` holds. A read that the driver retries
    starts with a new `SortedRows`. A failed read releases its files.
    `timeout_s` is the timeout of the read transaction. With None, the timeout
    of the server applies.
    """

    def work(tx: Any) -> SortedRows:
        rows = SortedRows()
        try:
            for record in stream_rows(tx, query, **params):
                rows.add(*entry(record))
        except BaseException:
            rows.close()
            raise
        return rows

    return session.execute_read(work if timeout_s is None else unit_of_work(timeout=timeout_s)(work))


# --- carry-forward ----------------------------------------------------------------------

# The carry rules for one object of the previous run:
#   1. An object without `_sources` (no recorded producer) is carried.
#   2. An object whose `_scope` is in $scopes is carried with the reason of
#      that unit. $scopes holds the units that failed, did not run, were
#      cancelled or skipped their load as unchanged.
#   3. An object whose `_scope` is in $named and outside $scopes is not carried.
#   4. An object whose `_scope` is set and outside $named is carried only when
#      a source in $unasked wrote it. Its device left the inventory of its source.
#   5. An object without `_scope` and with `_sources` is carried when one of
#      its sources is in $sources.
_READ_CARRY_NODES = """
MATCH (old:Obj {collection_ts: $prev})
WHERE (old._sources IS NULL
       OR old._scope IN $scopes
       OR (old._scope IS NULL AND any(s IN old._sources WHERE s IN $sources))
       OR (old._scope IS NOT NULL
           AND NOT old._scope IN $named
           AND any(s IN old._sources WHERE s IN $unasked)))
  AND NOT EXISTS { MATCH (n:Obj {uid: old.uid, collection_ts: $cts}) }
RETURN labels(old) AS labels, properties(old) AS props
"""

_READ_CARRY_RELS = """
MATCH (a0:Obj {collection_ts: $prev})-[r]->(b0:Obj {collection_ts: $prev})
WHERE coalesce(r._scope, '') <> 'reasoner' AND NOT coalesce(r._scope, '') STARTS WITH 'derived:'
MATCH (a:Obj {uid: a0.uid, collection_ts: $cts}), (b:Obj {uid: b0.uid, collection_ts: $cts})
WHERE (a.carried = true OR b.carried = true OR r._scope IN $scopes)
  AND NOT EXISTS { MATCH (a)-[r2]->(b) WHERE type(r2) = type(r) }
RETURN a.uid AS start, b.uid AS end, type(r) AS t, properties(r) AS props,
       CASE WHEN a.carried = true THEN a.carried_reason ELSE b.carried_reason END AS reason,
       coalesce(a.carried, false) OR coalesce(b.carried, false) AS by_end
"""

# One statement per partial device runs after the scope-level objects are written.
_READ_CARRY_SECTION_NODES = """
MATCH (old:Obj {collection_ts: $prev})
WHERE old._scope = $scope
  AND any(l IN labels(old) WHERE l IN $labels)
  AND NOT EXISTS { MATCH (n:Obj {uid: old.uid, collection_ts: $cts}) }
RETURN labels(old) AS labels, properties(old) AS props
"""

# A source row name holds no `/` (app/sources.py NAME_PATTERN).
CARRIED_SCOPES = "_carried_scopes"

# The read runs before any object is copied.
_READ_CARRY_CONTRIBUTIONS = """
MATCH (n:Obj {collection_ts: $cts}) WHERE coalesce(n.carried, false) = false
MATCH (old:Obj {uid: n.uid, collection_ts: $prev})
WHERE any(s IN coalesce(old._sources, []) WHERE NOT s IN coalesce(n._sources, []))
RETURN labels(old) AS labels, properties(old) AS prior, properties(n) AS fresh,
       [(old)-[r]-(o) WHERE r._scope IN $scopes AND o._scope = r._scope | o._sources[0] + '/' + r._scope]
         AS touched
"""

_WRITE_CARRY_CONTRIBUTIONS = """
UNWIND $rows AS row
MATCH (n:Obj {uid: row.uid, collection_ts: $cts})
SET n += row.props, n._sources = coalesce(n._sources, []) + row.sources
"""

# A carried scope meets the anchor check of core/loader.py `_check_cycle_anchors`.
_CHECK_CARRY_ANCHORS = """
MATCH (old:Obj {collection_ts: $prev})
WHERE old.anchor IS NOT NULL AND (old._scope IN $kept OR old._carried_scopes IS NOT NULL)
MATCH (n:Obj {uid: old.uid, collection_ts: $cts})
WHERE coalesce(n.carried, false) = false AND n.anchor IS NOT NULL AND n.anchor <> old.anchor
RETURN old.uid AS uid, old._scope AS scope, old._carried_scopes AS laid, old.anchor AS carried,
       n.anchor AS written
"""

# The properties that `_stamp` writes on a carried copy. No source asserts them.
_STAMPS = frozenset({"carried_reason", "last_seen_ts"})

# The values of `carried_reason` on a carried object. `cancelled`, `failed`,
# `not-run` and `unchanged` are the reasons of a unit of this run. `not-run` is
# also the reason of an object for which no unit of this run has a reason, for
# example a source-level carry or an object with no recorded producer.
# `section-failed` is the reason of a section. The device answered, and one
# section of it did not.
CARRY_REASONS = ("cancelled", "failed", "not-run", "section-failed", "unchanged")
NOT_RUN = "not-run"
# A unit whose load this run skipped because nothing it would write changed.
UNCHANGED = "unchanged"
# A source an operator stopped mid-cycle, whose devices carry.
CANCELLED = "cancelled"
SECTION_FAILED = "section-failed"


def _label_clause(labels: list[str]) -> str:
    for label in labels:
        if not re.match(r"^[A-Za-z][A-Za-z0-9_]*$", label):
            raise ValueError(f"label {label!r} is not a bare identifier; refusing to carry")
    return ":" + ":".join(labels)


def _stamp(props: dict[str, Any], reason: str) -> dict[str, Any]:
    """`last_seen_ts` is the previous run's `collected_at`."""
    props["carried_reason"] = reason
    if props.get("collected_at") is not None:
        props["last_seen_ts"] = props["collected_at"]
    return props


def _carried_node(record: Mapping[str, Any], reason: str) -> tuple[tuple[str, ...], dict[str, Any]]:
    """Return (label signature, row) of one object that carry-forward copies."""
    labels = tuple(sorted(set(record["labels"]) - {"Latest", "Retired"}))
    # The row must not hold collection_ts. `SET n = row` would write the old
    # value before the new one, and the uniqueness constraint validates each
    # write. The copy would collide with the source node.
    props = {k: v for k, v in record["props"].items() if k != "collection_ts"}
    props.update(ipenc.graph_address_props(labels, props))
    return labels, _stamp(props, reason)


def _carried_rel(record: Mapping[str, Any], reasons: Mapping[str, str]) -> tuple[str, dict[str, Any]]:
    """Return (type, row) of one relationship that carry-forward copies.

    The reason is the `carried_reason` of its carried endpoint. When no
    endpoint is carried, the reason is the entry of `reasons` for the scope of
    the relationship (`_READ_CARRY_RELS`)."""
    props = {k: v for k, v in record["props"].items() if k != "collection_ts"}
    if record["by_end"]:
        reason = record["reason"] or NOT_RUN
    else:
        reason = reasons.get(str(props.get("_scope") or ""), NOT_RUN)
    _stamp(props, reason)
    return record["t"], {"start": record["start"], "end": record["end"], "props": props}


def _create_nodes(labels: tuple[str, ...]) -> str:
    return (
        f"UNWIND $rows AS row CREATE (n{_label_clause(list(labels))}) "
        "SET n = row, n.collection_ts = $cts, n.carried = true"
    )


def _create_rels(rel_type: str) -> str:
    _label_clause([rel_type])  # A type that is not a bare identifier raises ValueError.
    return (
        "UNWIND $rows AS row "
        "MATCH (a:Obj {uid: row.start, collection_ts: $cts}), "
        "(b:Obj {uid: row.end, collection_ts: $cts}) "
        f"CREATE (a)-[r:{rel_type}]->(b) "
        "SET r = row.props, r.collection_ts = $cts, r.carried = true"
    )


def _write_groups(session: Session, rows: SortedRows, statement: Callable[[Any], str], cts: int) -> int:
    """Write `rows` one key at a time, in chunks of BATCH, with the statement
    `statement` builds for that key. Returns how many rows were written."""
    written = 0
    with rows:
        for key, group in itertools.groupby(rows, key=itemgetter(0)):
            query = statement(key)
            for chunk in itertools.batched((row for _key, row in group), BATCH, strict=False):
                _write(session, query, rows=list(chunk), cts=cts)
                written += len(chunk)
    return written


def _pairs(entries: Iterable[str] | None) -> list[tuple[str, str]]:
    """The `(source, scope)` of each `<source>/<scope>` pair (CARRIED_SCOPES)."""
    return [(source, scope) for source, _, scope in (str(e).partition("/") for e in entries or [])]


def _check_carry_anchors(session: Session, prev: int, cts: int, kept: list[str]) -> None:
    wanted = set(kept)

    def kept_writer(row: Mapping[str, Any]) -> str | None:
        if row["scope"] in wanted:
            return str(row["scope"])
        return next((scope for _source, scope in _pairs(row["laid"]) if scope in wanted), None)

    def first(tx: Any) -> dict[str, Any] | None:
        for row in stream_rows(tx, _CHECK_CARRY_ANCHORS, prev=prev, cts=cts, kept=kept):
            scope = kept_writer(row)
            if scope is not None:
                return {**dict(row), "scope": scope}
        return None

    rec = session.execute_read(first)
    if rec is not None:
        raise CycleIdentityCollision(
            f"uid {rec['uid']!r} was written in this run with anchor={rec['written']!r}, and the unchanged "
            f"scope {rec['scope']} holds it with anchor={rec['carried']!r}: one uid cannot name two objects"
        )


def _registered_label(labels: Iterable[str]) -> str:
    """Return the first label of the object that the registry holds, or the empty string."""
    return next((label for label in labels if label in LABELS), "")


def _writers(
    old: Mapping[str, Any], touched: Iterable[str | None], reasons: Mapping[str, str]
) -> dict[str, list[str]]:
    """Return the `<source>/<scope>` pairs, by source, of the scopes in `reasons`
    that wrote one object or one of its relationships in the parent run.

    The pairs come from the first writer of the object, from the CARRIED_SCOPES
    of an earlier carry, and from `touched` (`_READ_CARRY_CONTRIBUTIONS`)."""
    pairs = {pair for pair in touched if pair} | set(old.get(CARRIED_SCOPES) or [])
    sources = old.get("_sources") or []
    if old.get("_scope") and sources:
        pairs.add(f"{sources[0]}/{old['_scope']}")
    by_source: dict[str, list[str]] = {}
    for pair in sorted(pairs):
        source, _, scope = pair.partition("/")
        if scope in reasons:
            by_source.setdefault(source, []).append(pair)
    return by_source


def _contribution(old: Mapping[str, Any], source: str, scope: str) -> tuple[str, dict[str, Any]]:
    """Return (collector type, fields) that `source` asserted on one object of
    the parent run.

    When the object has assertion entries (core/loader.py `encode_assertion`),
    the fields are the entries of `source`. When the object has none, the
    fields are the whole payload for the first writer and empty for any other
    source. `scope` is a scope of the source that wrote the object, or the
    empty string. The collector type of `scope` is used when no entry of
    `source` has one. A property in `_STAMPS` is not a field."""
    recorded = {k: v for k, v in old.items() if k.startswith(loadermod.ASSERT_PREFIX)}
    fallback = loadermod.collector_type(scope)
    if not recorded:
        if source != next(iter(old.get("_sources") or []), None):
            return fallback, {}
        payload = loadermod._payload_of(dict(old))
        collector = loadermod.collector_type(str(old.get("_scope") or scope))
        return collector, {k: v for k, v in payload.items() if k not in _STAMPS}
    collector = ""
    fields: dict[str, Any] = {}
    for key, entries in sorted(recorded.items()):
        field = key[len(loadermod.ASSERT_PREFIX) :]
        if field in _STAMPS:
            continue
        for entry in entries or []:
            asserted_by, asserting_source, value = loadermod.decode_assertion(entry)
            if asserting_source == source:
                collector = collector or asserted_by
                fields[field] = value
    return collector or fallback, fields


def _carry_contributions(
    session: Session, prev: int, cts: int, reasons: Mapping[str, str], unasked: Iterable[str]
) -> int:
    """Write the assertions of the sources that did not collect on the objects
    that this run wrote without them (`_READ_CARRY_CONTRIBUTIONS`)."""
    asked_nothing = set(unasked)

    def entry(record: Mapping[str, Any]) -> tuple[str, dict[str, Any] | None]:
        old, new = record["prior"], dict(record["fresh"])
        if old.get("anchor") is not None and new.get("anchor") is not None and old["anchor"] != new["anchor"]:
            return "", None
        writers = _writers(old, record["touched"] or [], reasons)
        label = _registered_label(record["labels"])
        props: dict[str, Any] = {}
        taken: list[str] = []
        laid: set[str] = set()
        for source in dict.fromkeys(old.get("_sources") or []):
            pairs = writers.get(source, [])
            if source in (new.get("_sources") or []) or not (pairs or source in asked_nothing):
                continue
            collector, fields = _contribution(old, source, pairs[0].partition("/")[2] if pairs else "")
            merged = {k: v for k, v in fields.items() if v is not None}
            merged |= loadermod.assertion_props(label, collector, source, new, fields)
            props |= merged
            new |= merged
            new["_sources"] = [*(new.get("_sources") or []), source]
            taken.append(source)
            laid.update(pairs)
        if not taken:
            return "", None
        if laid:
            props[CARRIED_SCOPES] = sorted(laid)
        return "", {"uid": new["uid"], "props": props, "sources": taken}

    rows = read_sorted(session, _READ_CARRY_CONTRIBUTIONS, entry, prev=prev, cts=cts, scopes=sorted(reasons))
    written = 0
    with rows:
        taken = (row for _key, row in rows if row is not None)
        for chunk in itertools.batched(taken, BATCH, strict=False):
            _write(session, _WRITE_CARRY_CONTRIBUTIONS, rows=list(chunk), cts=cts)
            written += len(chunk)
    return written


def carry_forward(
    session: Session,
    prev: int,
    cts: int,
    sources: list[str],
    *,
    scopes: Mapping[str, str] | None = None,
    collected: Iterable[str] = (),
    unasked: Iterable[str] | None = None,
    section_labels: Mapping[str, Iterable[str]] | None = None,
) -> dict[str, int]:
    """Every relationship is read before any is written."""
    if prev == cts:
        return {"nodes": 0, "rels": 0}
    reasons = dict(scopes or {})
    per_section = {s: sorted(set(labels)) for s, labels in (section_labels or {}).items() if labels}
    whole = sorted(set(sources) if unasked is None else set(unasked))
    if not (sources or reasons or whole or per_section):
        return {"nodes": 0, "rels": 0}
    named = sorted(set(reasons) | set(collected))

    def by_scope(record: Mapping[str, Any]) -> tuple[tuple[str, ...], dict[str, Any]]:
        return _carried_node(record, reasons.get(record["props"].get("_scope") or "", NOT_RUN))

    def by_section(record: Mapping[str, Any]) -> tuple[tuple[str, ...], dict[str, Any]]:
        return _carried_node(record, SECTION_FAILED)

    def by_rel(record: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        return _carried_rel(record, reasons)

    kept = sorted(scope for scope, reason in reasons.items() if reason == UNCHANGED)
    if kept:
        _check_carry_anchors(session, prev, cts, kept)
    if reasons or whole:
        _carry_contributions(session, prev, cts, reasons, whole)
    scope_rows = read_sorted(
        session,
        _READ_CARRY_NODES,
        by_scope,
        prev=prev,
        cts=cts,
        sources=sources,
        scopes=sorted(reasons),
        named=named,
        unasked=whole,
    )
    nodes = _write_groups(session, scope_rows, _create_nodes, cts)
    for scope, labels_wanted in sorted(per_section.items()):
        section_rows = read_sorted(
            session,
            _READ_CARRY_SECTION_NODES,
            by_section,
            prev=prev,
            cts=cts,
            scope=scope,
            labels=labels_wanted,
        )
        nodes += _write_groups(session, section_rows, _create_nodes, cts)
    rel_rows = read_sorted(session, _READ_CARRY_RELS, by_rel, prev=prev, cts=cts, scopes=sorted(reasons))
    rels = _write_groups(session, rel_rows, _create_rels, cts)
    return {"nodes": nodes, "rels": rels}


# --- the run meta node ------------------------------------------------------------------

WRITE_CYCLE = """
MERGE (c:Obj:CycleRun:Meta {uid: $uid})
SET c += $props, c._scope = 'meta:cycles'
"""


KINDS = ("full", "partial", "refresh", "device")
# A node with no state is read as built.
STATE_BUILDING = "building"
STATE_BUILT = "built"
# The kinds retention counts against `keep`.
CYCLE_KINDS = ("full", "partial")


def write_cycle_meta(
    session: Session,
    cts: int,
    *,
    statuses: dict[str, str],
    carried_from: int | None,
    nodes: int,
    rels: int,
    degraded: bool,
    kind: str = "full",
    parent: int | None = None,
    manifest_digest: str | None = None,
    reprocessed_from: int | None = None,
    app_version: str | None = None,
    build_revision: str | None = None,
) -> None:
    """Write the meta node of run `cts`.

    `statuses` maps each source name to "fresh", "carried", "failed", "partial" or `CANCELLED`.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown run kind {kind!r}; known kinds: {sorted(KINDS)}")
    _write(
        session,
        WRITE_CYCLE,
        uid=f"cycle:{cts}",
        props={
            "collection_ts": None,  # The meta node belongs to no snapshot.
            "cts": cts,
            "created": _iso(cts),
            "kind": kind,
            "parent": parent,
            "state": STATE_BUILT,
            "sources_fresh": sorted(k for k, v in statuses.items() if v == "fresh"),
            "sources_carried": sorted(k for k, v in statuses.items() if v == "carried"),
            "sources_failed": sorted(k for k, v in statuses.items() if v == "failed"),
            "sources_partial": sorted(k for k, v in statuses.items() if v == "partial"),
            "sources_cancelled": sorted(k for k, v in statuses.items() if v == CANCELLED),
            "carried_from": carried_from,
            "nodes": nodes,
            "rels": rels,
            "degraded": degraded,
            "manifest_digest": manifest_digest,
            # None removes the property under `c += $props`.
            "reprocessed_from": reprocessed_from,
            "app_version": app_version,
            "build_revision": build_revision,
        },
    )


def begin_run(session: Session, cts: int, kind: str, parent: int | None) -> None:
    """Record run `cts` as being built, before the build writes anything."""
    if kind not in KINDS:
        raise ValueError(f"unknown run kind {kind!r}; known kinds: {sorted(KINDS)}")
    _write(
        session,
        WRITE_CYCLE,
        uid=f"cycle:{cts}",
        props={
            "collection_ts": None,
            "cts": cts,
            "created": _iso(cts),
            "kind": kind,
            "parent": parent,
            "state": STATE_BUILDING,
        },
    )


def discard_run(session: Session, cts: int) -> None:
    """Delete everything that run `cts` wrote, for a build that failed before
    the pointer named it (`delete_run`)."""
    delete_run(session, cts)


LIST_CYCLES = """
MATCH (c:CycleRun) WHERE coalesce(c.state, 'built') <> 'building'
RETURN c.cts AS id, c.cts AS ts_ms, c.created AS created, c.nodes AS nodes, c.rels AS rels,
       coalesce(c.kind, 'full') AS kind, c.parent AS parent,
       c.sources_fresh AS sources_fresh, c.sources_carried AS sources_carried,
       c.sources_failed AS sources_failed, c.sources_partial AS sources_partial,
       c.sources_cancelled AS sources_cancelled, c.degraded AS degraded
ORDER BY c.cts DESC SKIP $offset LIMIT $limit
"""


def list_cycles(session: Session, limit: int = 200, offset: int = 0) -> tuple[list[dict[str, Any]], bool]:
    """One page of runs, newest first, and whether more exist beyond it."""
    limit = max(1, limit)
    rows = _read(session, LIST_CYCLES, limit=limit + 1, offset=max(0, offset))
    truncated = len(rows) > limit
    rows = rows[:limit]
    for row in rows:
        row["id"] = str(row["id"])
    return rows, truncated


RUN_STATUS = """
MATCH (c:CycleRun {uid: $uid})
RETURN c.cts AS cts, c.created AS created, c.degraded AS degraded,
       c.sources_carried AS sources_carried, c.sources_failed AS sources_failed,
       c.sources_partial AS sources_partial, c.sources_cancelled AS sources_cancelled
"""


# How many devices the freshness summary reports, in the manifest's order of source and host.
FRESHNESS_CAP = 200

# A collected device has no carry reason.
_OUTCOME_REASONS = {
    "failed": "failed",
    "carried": NOT_RUN,
    "unchanged": "unchanged",
    "partial": SECTION_FAILED,
}


def _device_freshness(entry: Any, cts: int) -> dict[str, Any]:
    """`last_seen` is the start of the device's last fetch that landed."""
    observed = entry.fetch_started_ms if entry.fetch_started_ms is not None else entry.fetch_ts_ms
    return {
        "source": entry.source,
        "host": entry.host,
        "outcome": entry.outcome,
        "carried": bool(entry.carried),
        "carried_reason": _OUTCOME_REASONS.get(entry.outcome),
        "last_seen": observed,
        "tables": {
            name: {
                "status": table.status,
                "observed_ms": table.observed_ms,
                "age_ms": None if table.observed_ms is None else cts - table.observed_ms,
            }
            for name, table in sorted(entry.tables.items())
        },
    }


def freshness(snapshot: Snapshot | None, *, cap: int = FRESHNESS_CAP) -> dict[str, Any]:
    """`truncated` is true when the cap cut the list."""
    record = None if snapshot is None else snapshot.manifest
    cts = None if snapshot is None else snapshot.cts
    if record is None or cts is None:
        return {"devices": [], "truncated": False, "approximate": True}
    entries = list(record.devices)
    return {
        "devices": [_device_freshness(e, cts) for e in entries[: max(0, cap)]],
        "truncated": len(entries) > max(0, cap),
        "approximate": False,
    }


class DeviceIndex:
    def __init__(self, devices: Iterable[Any]) -> None:
        self.by_scope: dict[tuple[str, str], list[Any]] = defaultdict(list)
        self.by_host: dict[tuple[str, str], list[Any]] = defaultdict(list)
        for device in devices:
            if device.scope:
                self.by_scope[(device.source, device.scope)].append(device)
            else:
                self.by_host[(device.source, device.host or "")].append(device)


def device_index(devices: Iterable[Any]) -> DeviceIndex:
    """Index `devices` by source and scope and by source and host for `device_owner`."""
    return DeviceIndex(devices)


def device_owner(props: Mapping[str, Any], index: DeviceIndex) -> Any | None:
    """None when no entry or more than one entry matches."""
    scope = str(props.get("_scope") or "")
    sources = props.get("_sources") or []
    if not scope or not sources:
        return None
    hosts = dict.fromkeys(["", *scope.split(":")[1:]])
    matches: list[Any] = []
    for source in dict.fromkeys(sources):
        matches.extend(index.by_scope.get((source, scope), ()))
        for host in hosts:
            matches.extend(index.by_host.get((source, host), ()))
    return matches[0] if len(matches) == 1 else None


def freshness_for(
    snapshot: Snapshot | None,
    props: Mapping[str, Any],
    index: DeviceIndex | None = None,
) -> dict[str, Any] | None:
    """Return the freshness of the device that produced one graph object, or None.

    The device is the one that `device_owner` returns. core/diff.py uses the
    same rule for a removal.

    `index` is the `device_index` of the manifest entries of the snapshot.
    Without `index`, the call indexes the entries of the sources of the object.
    """
    record = None if snapshot is None else snapshot.manifest
    cts = None if snapshot is None else snapshot.cts
    if record is None or cts is None:
        return None
    if index is None:
        sources = props.get("_sources") or []
        index = device_index(d for d in record.devices if d.source in sources)
    owner = device_owner(props, index)
    return None if owner is None else _device_freshness(owner, cts)


def run_present(session: Any, cts: int) -> bool:
    """Return whether the `:CycleRun` node of run `cts` exists.

    A reader repeats this read inside its lease to tell a pruned run from a whole run.
    """
    return bool(session.run(RUN_STATUS, uid=f"cycle:{cts}").data())


def run_status(session: Any, snapshot: Snapshot | None) -> dict[str, Any] | None:
    """None when there is no snapshot, the snapshot names no run, or the meta node is absent."""
    cts = None if snapshot is None else snapshot.cts
    if cts is None:
        return None
    rows = session.run(RUN_STATUS, uid=f"cycle:{cts}").data()
    if not rows:
        return None
    row = rows[0]
    return {
        "snapshot": str(cts),
        "created": row.get("created"),
        "degraded": bool(row.get("degraded")),
        "sources_carried": sorted(row.get("sources_carried") or []),
        "sources_failed": sorted(row.get("sources_failed") or []),
        "sources_partial": sorted(row.get("sources_partial") or []),
        "sources_cancelled": sorted(row.get("sources_cancelled") or []),
        "freshness": freshness(snapshot),
    }


def cycle_counts(session: Session, cts: int) -> dict[str, int]:
    nodes = _read(session, "MATCH (n:Obj {collection_ts: $cts}) RETURN count(n) AS c", cts=cts)[0]["c"]
    rels = _read(
        session,
        "MATCH (:Obj {collection_ts: $cts})-[r]->(:Obj) WHERE r.collection_ts = $cts RETURN count(r) AS c",
        cts=cts,
    )[0]["c"]
    return {"nodes": nodes, "rels": rels}


_SCOPE_COLLECTED_AT = """
MATCH (n:Obj {collection_ts: $cts})
WHERE n._scope = $scope
RETURN max(n.collected_at) AS collected_at
"""


def scope_collected_at(session: Session, cts: int, scope: str) -> int | None:
    """The newest observation time run `cts` holds for the objects `scope` owns.

    None when the run holds no object of that scope.
    """
    rows = _read(session, _SCOPE_COLLECTED_AT, cts=cts, scope=scope)
    value = rows[0]["collected_at"] if rows else None
    return int(value) if value is not None else None


_SCOPES_COLLECTED_AT = """
MATCH (n:Obj {collection_ts: $cts})
WHERE n._scope IN $scopes
RETURN n._scope AS scope, max(n.collected_at) AS collected_at
"""


def scopes_collected_at(session: Session, cts: int, scopes: Iterable[str]) -> dict[str, int]:
    """A scope the run holds nothing of is absent from the answer."""
    wanted = sorted(set(scopes))
    if not wanted:
        return {}
    rows = _read(session, _SCOPES_COLLECTED_AT, cts=cts, scopes=wanted)
    return {str(r["scope"]): int(r["collected_at"]) for r in rows if r["collected_at"] is not None}


# --- operator site assignments ----------------------------------------------------------

# A site the operator invented is made only while no collector-reported Site with the
# same uid exists in the run.
_ENSURE_META_SITES = """
UNWIND $sites AS row
OPTIONAL MATCH (ls:Site:Obj {uid: row.uid, collection_ts: $snap})
WITH row, ls WHERE ls IS NULL
MERGE (m:Site:Obj {uid: row.uid, collection_ts: $snap})
  ON CREATE SET m.code = row.code, m._scope = 'app:sites', m._sources = ['app:sites']
"""
# A device with an operator site loses every LOCATED_IN edge before the
# operator edge is made. A device that the operator left without a site loses
# only an operator edge, which the carry copied. The site edge that a collector
# reports for such a device (an Equinix Network Edge, a ZIA location) stays.
_CLEAR_ASSIGNMENTS = """
UNWIND $rows AS row
MATCH (d:Device:Obj {uid: row.uid, collection_ts: $snap})-[r:LOCATED_IN]->(:Site)
WHERE row.site IS NOT NULL OR r._scope = 'app:sites'
DELETE r
"""
# The run holds one Site per uid (obj_uid_cts), a collected Site or the copy
# that `_ENSURE_META_SITES` made. A device gets at most one edge.
_APPLY_ASSIGNMENTS = """
UNWIND $rows AS row
MATCH (d:Device:Obj {uid: row.uid, collection_ts: $snap})
MATCH (s:Site:Obj {uid: row.site_uid, collection_ts: $snap})
MERGE (d)-[li:LOCATED_IN]->(s)
SET li._scope = 'app:sites', li.collection_ts = $snap
RETURN count(d) AS n
"""


def apply_site_assignments(session: Session, assigned: Mapping[str, str | None], cts: int) -> int:
    """In `assigned`, None clears the operator's site and leaves the one a collector reported."""
    if not assigned:
        return 0
    _write(
        session,
        _CLEAR_ASSIGNMENTS,
        rows=[{"uid": uid, "site": code or None} for uid, code in sorted(assigned.items())],
        snap=cts,
    )
    # The Site uid is minted through uid.site(), as every collector mints it.
    rows = [
        {"uid": uid, "site_uid": uidmod.site(code), "code": code}
        for uid, code in sorted(assigned.items())
        if code
    ]
    if not rows:
        return 0
    sites = {r["site_uid"]: r["code"] for r in rows}
    _write(
        session,
        _ENSURE_META_SITES,
        sites=[{"uid": uid, "code": code} for uid, code in sorted(sites.items())],
        snap=cts,
    )
    out = _write(session, _APPLY_ASSIGNMENTS, rows=rows, snap=cts)
    return out[0]["n"] if out else 0


# A run that carries a device forward keeps the site of its copy in `$parent`, unless the run
# resolved the device.
_CARRY_META_SITES = """
MATCH (d:Device:Obj {collection_ts: $snap}) WHERE coalesce(d.carried, false)
  AND NOT d.uid IN $resolved AND NOT (d)-[:LOCATED_IN]->(:Site)
MATCH (p:Device:Obj {uid: d.uid, collection_ts: $parent})-[pl:LOCATED_IN]->(ps:Site)
WHERE pl._retired_at IS NULL AND (ps:Meta OR ps._scope = 'app:sites')
WITH DISTINCT ps
OPTIONAL MATCH (ls:Site:Obj {uid: ps.uid, collection_ts: $snap})
WITH ps, ls WHERE ls IS NULL
MERGE (m:Site:Obj {uid: ps.uid, collection_ts: $snap})
  ON CREATE SET m.code = ps.code, m._scope = 'app:sites', m._sources = ['app:sites']
"""
_CARRY_SITES = """
MATCH (d:Device:Obj {collection_ts: $snap}) WHERE coalesce(d.carried, false)
  AND NOT d.uid IN $resolved AND NOT (d)-[:LOCATED_IN]->(:Site)
MATCH (p:Device:Obj {uid: d.uid, collection_ts: $parent})-[pl:LOCATED_IN]->(ps:Site)
WHERE pl._retired_at IS NULL
MATCH (s:Site:Obj {uid: ps.uid, collection_ts: $snap})
MERGE (d)-[li:LOCATED_IN]->(s)
SET li._scope = 'app:sites', li.collection_ts = $snap
RETURN count(DISTINCT d) AS n
"""


_PREVIOUS_RUN = "MATCH (c:CycleRun) WHERE c.cts < $snap RETURN max(c.cts) AS prev"


# The named block of a device (site parameter `blocks`) is stamped on the Device
# nodes of the run. _CLEAR_SITE_BLOCKS removes the stamp from every Device of the
# run first, including a carried copy that holds the stamp of its parent.
_CLEAR_SITE_BLOCKS = """
MATCH (d:Device:Obj {collection_ts: $snap})
WHERE d.site_zone IS NOT NULL OR d.site_block IS NOT NULL
REMOVE d.site_zone, d.site_block
"""
_APPLY_SITE_BLOCKS = """
UNWIND $rows AS row
MATCH (d:Device:Obj {uid: row.uid, collection_ts: $snap})
SET d.site_block = row.block, d.site_zone = row.zone
RETURN count(d) AS n
"""


def site_block_rows(blocks: Mapping[str, tuple[str, str | None]]) -> list[dict[str, Any]]:
    """Return the rows that `apply_site_blocks` writes, sorted by uid.

    `block` is the block name. `zone` is the zone of the block, or None for a
    block with no zone.
    """
    return [{"uid": uid, "block": name, "zone": zone} for uid, (name, zone) in sorted(blocks.items())]


def apply_site_blocks(session: Session, blocks: Mapping[str, tuple[str, str | None]], cts: int) -> int:
    """Write `site_block` and `site_zone` on the Device nodes of run `cts` from
    `blocks` (device uid to block name and zone).

    The function first removes both properties from every Device of the run.
    An empty map clears every stamp. The callers write only into a run being
    built. Return the count of devices that got a stamp."""
    _write(session, _CLEAR_SITE_BLOCKS, snap=cts)
    rows = site_block_rows(blocks)
    if not rows:
        return 0
    out = _write(session, _APPLY_SITE_BLOCKS, rows=rows, snap=cts)
    return out[0]["n"] if out else 0


def carry_site_assignments(
    session: Session, resolved: Mapping[str, str | None], cts: int, parent: int | None = None
) -> int:
    """Give each device that run `cts` carried and did not resolve the site of
    its previous copy.

    `resolved` is the map that apply_site_assignments got. A uid in `resolved`
    is not touched. `parent` is the run that the carried copies came from. When
    `parent` is None (a replay), the newest run before `cts` is used. Return the
    count of devices that got an edge."""
    if parent is None:
        rows = _read(session, _PREVIOUS_RUN, snap=cts)
        parent = rows[0]["prev"] if rows else None
        if parent is None:
            return 0
    _write(session, _CARRY_META_SITES, resolved=sorted(resolved), snap=cts, parent=parent)
    out = _write(session, _CARRY_SITES, resolved=sorted(resolved), snap=cts, parent=parent)
    return out[0]["n"] if out else 0


# --- retention and migration ------------------------------------------------------------


_LIST_RUNS_FOR_PRUNE = """
MATCH (c:CycleRun)
RETURN c.cts AS cts, coalesce(c.kind, 'full') AS kind, coalesce(c.state, 'built') AS state
ORDER BY c.cts DESC
"""

# The run keys of objects and of per-load meta nodes below `$below`. A key with
# no `:CycleRun` node is a run that `begin_run` did not record, or a run whose
# node a prune deleted (`delete_run`) before the prune stopped.
_OBJECT_KEYS_BELOW = "MATCH (n:Obj) WHERE n.collection_ts < $below RETURN DISTINCT n.collection_ts AS cts"
_LOAD_KEYS_BELOW = "MATCH (r:CollectionRun) WHERE r.snapshot_ts < $below RETURN DISTINCT r.snapshot_ts AS cts"

# The age after which retention deletes a BUILDING run or the objects of a run
# key with no run node. A build under the cycle lock is the only writer of such
# a run, and prune holds the same lock. The blocking path of the CLI, a replay
# and the bootstrap migration publish without the lock.
ORPHAN_GRACE_MS = 24 * 3600 * 1000

# Rows one delete transaction holds. Relationships are deleted in their own
# transactions before their nodes. A hub node (a VRF instance with 10^5
# route-target edges, a bridge domain with every endpoint) is not deleted with
# all its edges in one transaction.
DELETE_BATCH = 10_000

# The default count of device and refresh runs that retention keeps beside the
# counted cycles. 48 runs are eight hours of device runs at the default
# device_run_interval_s of 600 seconds. `Settings` has the same default.
KEEP_DEVICE_RUNS = KEEP_DEVICE_RUNS_DEFAULT


@dataclass(frozen=True)
class Keep:
    """The runs that graph retention keeps.

    Retention keeps the newest `cycles` cycles (kind full and partial) and the
    newest `device_runs` device and refresh runs that are newer than the oldest
    kept cycle. A bare int means `Keep(n)`."""

    cycles: int
    device_runs: int = KEEP_DEVICE_RUNS


def _keep(keep: int | Keep) -> Keep:
    if isinstance(keep, Keep):
        return Keep(max(1, keep.cycles), max(0, keep.device_runs))
    return Keep(max(1, keep))


def _now_ms() -> int:
    return int(time.time() * 1000)


def _partition(session: Session, keep: int | Keep) -> tuple[list[int], list[int]]:
    """The pointer's run is kept whatever its kind or age."""
    limits = _keep(keep)
    cur = current_ts(session)
    rows = _read(session, _LIST_RUNS_FOR_PRUNE)
    built = [r for r in rows if r.get("state", STATE_BUILT) != STATE_BUILDING]
    cycles = [r["cts"] for r in built if r["kind"] in CYCLE_KINDS][: limits.cycles]
    floor = min(cycles) if cycles else None
    others = [r["cts"] for r in built if r["kind"] not in CYCLE_KINDS and (floor is None or r["cts"] > floor)]
    held = {cur, *cycles, *others[: limits.device_runs]}
    now = _now_ms()
    kept: list[int] = []
    victims: list[int] = []
    for row in rows:
        cts = row["cts"]
        if row.get("state", STATE_BUILT) == STATE_BUILDING and cts != cur:
            abandoned = cur is not None and cts < cur and now - cts > ORPHAN_GRACE_MS
            (victims if abandoned else kept).append(cts)
        else:
            (kept if cts in held else victims).append(cts)
    return kept, victims


def retained_runs(session: Session, keep: int | Keep) -> list[int]:
    """The run keys retention keeps under `keep`, newest first."""
    return _partition(session, keep)[0]


def orphan_runs(session: Session) -> list[int]:
    """Run keys that hold objects or load meta nodes in the graph and have no
    `:CycleRun` node, older than the pointer and than `ORPHAN_GRACE_MS`, newest first."""
    cur = current_ts(session)
    if cur is None:
        return []
    below = min(cur, _now_ms() - ORPHAN_GRACE_MS)
    named = {r["cts"] for r in _read(session, _LIST_RUNS_FOR_PRUNE)}
    found = {r["cts"] for r in _read(session, _OBJECT_KEYS_BELOW, below=below)}
    found |= {r["cts"] for r in _read(session, _LOAD_KEYS_BELOW, below=below)}
    return sorted((c for c in found - named if c is not None), reverse=True)


def delete_run(session: Session, cts: int) -> None:
    """Delete run `cts` from the graph, its `:CycleRun` node first.

    After the first statement, no listing, `run_status` or retention count
    names the run. A delete that stops between statements leaves objects that
    `orphan_runs` finds on the next prune. Relationships are deleted before the
    nodes, in batches of `DELETE_BATCH`.
    """
    _write(session, "MATCH (c:CycleRun {uid: $uid}) DELETE c", uid=f"cycle:{cts}")
    _run_batched(
        session,
        "MATCH (n:Obj {collection_ts: $cts})-[r]->() CALL (r) { DELETE r } IN TRANSACTIONS OF $batch ROWS",
        cts=cts,
        batch=DELETE_BATCH,
    )
    _run_batched(
        session,
        "MATCH (n:Obj {collection_ts: $cts}) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF $batch ROWS",
        cts=cts,
        batch=DELETE_BATCH,
    )
    # The loader's per-load meta node records the run it joined as
    # `snapshot_ts` (core/loader.py WRITE_RUN).
    _run_batched(
        session,
        "MATCH (r:CollectionRun {snapshot_ts: $cts}) "
        "CALL (r) { DETACH DELETE r } IN TRANSACTIONS OF $batch ROWS",
        cts=cts,
        batch=DELETE_BATCH,
    )


def prune(
    session: Session,
    keep: int | Keep,
    protected: frozenset[int] = frozenset(),
    max_victims: int | None = None,
    orphans: bool = True,
) -> list[int]:
    """Delete graph data of the runs retention does not keep, except the current run."""
    _, victims = _partition(session, keep)
    found = {cts for cts in victims if cts not in protected}
    if orphans:
        found |= {cts for cts in orphan_runs(session) if cts not in protected}
    ordered = sorted(found)
    if max_victims is not None:
        ordered = ordered[: max(0, max_victims)]
    for cts in ordered:
        delete_run(session, cts)
    return sorted(ordered, reverse=True)


def sweep_unversioned_reasoner_edges(session: Session) -> None:
    """Delete the reasoner edges that have no collection_ts."""
    _run_batched(
        session,
        "MATCH ()-[r]->() WHERE r._scope = 'reasoner' AND r.collection_ts IS NULL "
        "CALL (r) { DELETE r } IN TRANSACTIONS OF $batch ROWS",
        batch=BATCH,
    )


# The split statement only adds. A repeat after a failure adds nothing.
_COUNT_META_SITES = "MATCH (m:Site:Meta) WHERE m.collection_ts IS NULL RETURN count(m) AS n"
_SPLIT_META_SITES = """
MATCH (m:Site:Meta)<-[l:LOCATED_IN]-(d:Device:Obj)
WHERE m.collection_ts IS NULL AND d.collection_ts IS NOT NULL
CALL (m, l, d) {
  MERGE (c:Site:Obj {uid: m.uid, collection_ts: d.collection_ts})
    ON CREATE SET c.code = m.code, c._scope = 'app:sites', c._sources = ['app:sites']
  MERGE (d)-[n:LOCATED_IN]->(c)
  SET n += properties(l), n.collection_ts = d.collection_ts
} IN TRANSACTIONS OF $batch ROWS
"""
# A shared Site is deleted once every device edge has a copy. A Site with another
# relationship, or with an edge from a Device that has no run, stays.
_DROP_META_SITES = """
MATCH (m:Site:Meta)
WHERE m.collection_ts IS NULL
  AND NOT EXISTS {
    MATCH (m)-[r]-(x)
    WHERE NOT (type(r) = 'LOCATED_IN' AND x:Device AND x.collection_ts IS NOT NULL)
  }
CALL (m) { DETACH DELETE m } IN TRANSACTIONS OF $batch ROWS
"""


def migrate_meta_sites(session: Session) -> int:
    """Split each unversioned operator Site into one copy per run that has a
    device at it.

    A graph with no unversioned Site does not change. Return the count of
    unversioned Sites found."""
    rows = _read(session, _COUNT_META_SITES)
    found = int(rows[0]["n"]) if rows else 0
    if found:
        _run_batched(session, _SPLIT_META_SITES, batch=BATCH)
        _run_batched(session, _DROP_META_SITES, batch=BATCH)
    return found


def migrate_bootstrap(session: Session) -> dict[str, Any]:
    """Stamp a graph with no pointer as the first run."""
    if current_ts(session) is not None:
        return {"migrated": False}
    cts = new_collection_ts()
    _run_batched(
        session,
        "MATCH (n:Obj) WHERE n.collection_ts IS NULL AND NOT n:Meta AND NOT n:Retired "
        "CALL (n) { SET n.collection_ts = $cts, n.collected_at = coalesce(n._last_seen, $cts) } "
        "IN TRANSACTIONS OF $batch ROWS",
        cts=cts,
        batch=BATCH,
    )
    _run_batched(
        session,
        "MATCH (a:Obj {collection_ts: $cts})-[r]->(b:Obj {collection_ts: $cts}) "
        "WHERE r.collection_ts IS NULL AND r._retired_at IS NULL "
        "CALL (r) { SET r.collection_ts = $cts } IN TRANSACTIONS OF $batch ROWS",
        cts=cts,
        batch=BATCH,
    )
    counts = cycle_counts(session, cts)
    write_cycle_meta(
        session,
        cts,
        statuses={},
        carried_from=None,
        nodes=counts["nodes"],
        rels=counts["rels"],
        degraded=False,
        kind="full",
        parent=None,
    )
    # The pointer is set last. A reader that resolves the pointer gets a
    # complete run with its meta node.
    set_pointer(session, cts)
    return {"migrated": True, "collection_ts": cts, **counts}
