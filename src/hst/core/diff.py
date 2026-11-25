"""The comparison joins two runs on the stable uid."""

from __future__ import annotations

import bisect
import hashlib
import itertools
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from operator import itemgetter
from typing import Any

from neo4j import Session
from neo4j.exceptions import ClientError

from .cycle import DeviceIndex, device_index, device_owner, read_sorted
from .labels import RESERVED_LABELS
from .loader import ASSERT_PREFIX, decode_assertion

# Each bucket keeps at most DETAIL_CAP detail records. The counts cover every record.
DETAIL_CAP = 500

_EXCLUDED_PROPS = {
    "collection_ts",
    "collected_at",
    "carried",
    "carried_reason",
    "last_seen_ts",
    # The run sets the named block of the operator (core/cycle.py apply_site_blocks).
    "site_zone",
    "site_block",
}
# A node row keeps these `_`-prefixed properties and its `_assert.` lists.
# `device_owner` reads them. A row holds no other `_`-prefixed property.
_ROW_INTERNALS = frozenset({"_scope", "_sources"})

# A node with no domain label is compared as a last group.
_ALL_NODES = (
    "MATCH (n:Obj {collection_ts: $snap}) RETURN n.uid AS uid, labels(n) AS labels, properties(n) AS props"
)
_ALL_RELS = (
    "MATCH (a:Obj {collection_ts: $snap})-[r]->(b:Obj) WHERE r.collection_ts = $snap "
    "RETURN a.uid AS start, b.uid AS end, type(r) AS t, properties(r) AS props"
)

INTERACTIVE_READ_TIMEOUT_S = 120.0


# The properties of each label that the comparison of a changed node skips. The
# `last_seen` of an Endpoint is the time when its source last saw it
# (collectors/unifi.py, the stat/sta time of the controller). It changes in
# every run for every client on the network. `last_seen` on any other label is
# compared. An added or removed object shows the property.
_UNCOMPARED_PROPS: dict[str, frozenset[str]] = {"Endpoint": frozenset({"last_seen"})}


def _payload(props: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in props.items() if not k.startswith("_") and k not in _EXCLUDED_PROPS}


def _compared(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return the payload of a node row that the change comparison uses.

    It is `_payload` without the uncompared properties of the labels of the row."""
    skip = frozenset().union(*(_UNCOMPARED_PROPS.get(label, frozenset()) for label in row["labels"]))
    return {k: v for k, v in _payload(row["props"]).items() if k not in skip}


def _primary_label(labels: list[str]) -> str:
    named = [label for label in labels if label not in RESERVED_LABELS]
    return named[0] if named else (labels[0] if labels else "")


def _assertion_conflicts(uid: str, labels: list[str], props: dict[str, Any]) -> list[dict[str, Any]]:
    """`effective` is the value that precedence materialized on the field."""
    out: list[dict[str, Any]] = []
    for key, raw in props.items():
        if not key.startswith(ASSERT_PREFIX):
            continue
        entries = list(raw or [])
        if len({e.partition("=")[2] for e in entries}) < 2:
            continue
        field = key[len(ASSERT_PREFIX) :]
        assertions = [decode_assertion(e) for e in entries]
        out.append(
            {
                "uid": uid,
                "label": _primary_label(labels),
                "name": props.get("name"),
                "field": field,
                "assertions": [{"collector": c, "source": s, "value": v} for c, s, v in assertions],
                "effective": props.get(field),
            }
        )
    return out


def _prop_changes(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[Any]]:
    keys = set(before) | set(after)
    return {k: [before.get(k), after.get(k)] for k in keys if before.get(k) != after.get(k)}


# --- the streamed join ------------------------------------------------------------------


def _order(value: Any) -> tuple[int, str]:
    """Return the sort key of one uid or type. None and each string have a key of their own."""
    if value is None:
        return (0, "")
    if isinstance(value, str):
        return (1, value)
    return (2, repr(value))


def _node_entry(record: Mapping[str, Any]) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Return (key, row) of one node read.

    The row keeps every property except the `_`-prefixed properties that are
    neither in `_ROW_INTERNALS` nor `_assert.` lists. The key is the domain
    label of the node and then its uid. A node with no domain label sorts after
    every label."""
    props = {
        k: v
        for k, v in record["props"].items()
        if not k.startswith("_") or k in _ROW_INTERNALS or k.startswith(ASSERT_PREFIX)
    }
    labels = list(record["labels"])
    domain = any(label not in RESERVED_LABELS for label in labels)
    key = (0, _primary_label(labels), *_order(record["uid"])) if domain else (1, "", *_order(record["uid"]))
    return key, {"uid": record["uid"], "labels": labels, "props": props}


def _rel_entry(record: Mapping[str, Any]) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Return (key, row) of one relationship read.

    The row keeps the type, the start, the end and the payload."""
    t, start, end = record["t"], record["start"], record["end"]
    row = {"type": t, "start": start, "end": end, "payload": _payload(record["props"])}
    return (_order(t), _order(start), _order(end)), row


def _payload_order(payload: dict[str, Any]) -> str:
    """Return the order key of a payload, the repr of its items in key order.

    The key is the same in every process."""
    return repr(sorted(payload.items()))


def _one_node(entries: Iterable[tuple[Any, dict[str, Any]]]) -> Iterator[tuple[Any, dict[str, Any]]]:
    """Yield one row for each key. Of 2 or more rows with one key, the row whose
    payload sorts last is kept."""
    for key, group in itertools.groupby(entries, key=itemgetter(0)):
        rows = [row for _key, row in group]
        yield (
            key,
            rows[0] if len(rows) == 1 else max(rows, key=lambda row: _payload_order(_payload(row["props"]))),
        )


def _edges(entries: Iterable[tuple[Any, dict[str, Any]]]) -> Iterator[tuple[Any, list[dict[str, Any]]]]:
    """Yield the edges of each (type, start, end) of a key-sorted sequence in payload order.

    The match of the edges is independent of the order in which the database
    returned them."""
    for key, group in itertools.groupby(entries, key=itemgetter(0)):
        yield key, sorted((row for _key, row in group), key=lambda row: _payload_order(row["payload"]))


def _shared(before: dict[str, Any], after: dict[str, Any]) -> int:
    """How many property values two payloads hold in common."""
    return sum(1 for k, v in before.items() if k in after and after[k] == v)


def _edge_pairs(
    rows_a: list[dict[str, Any]], rows_b: list[dict[str, Any]]
) -> Iterator[tuple[dict[str, Any] | None, dict[str, Any] | None]]:
    """Yield the edges of one (type, start, end) that differ between A and B.

    A pair is `(a, b)` for a changed edge, `(a, None)` for a removed edge and
    `(None, b)` for an added edge.

    An edge of A matches the first edge of B, in payload order, with an equal
    payload. When the counts of the remaining edges of A and of B differ, every
    remaining edge of A is removed and every remaining edge of B is added. With
    equal counts, each remaining edge of A, in payload order, pairs with the
    remaining edge of B that shares the most values with it. The first edge of
    B in payload order wins a tie.
    """
    left_b = list(rows_b)
    left_a: list[dict[str, Any]] = []
    for a in rows_a:
        for i, b in enumerate(left_b):
            if b["payload"] == a["payload"]:
                del left_b[i]
                break
        else:
            left_a.append(a)
    if len(left_a) != len(left_b):
        yield from ((a, None) for a in left_a)
        yield from ((None, b) for b in left_b)
        return
    for a in left_a:
        shared = [_shared(a["payload"], b["payload"]) for b in left_b]
        yield a, left_b.pop(shared.index(max(shared)))


def _joined[T](
    side_a: Iterator[tuple[Any, T]], side_b: Iterator[tuple[Any, T]]
) -> Iterator[tuple[T | None, T | None]]:
    """Yield the values of 2 sequences sorted by the same unique key, paired by key.

    A pair is `(a, b)` for a key in both sequences, and `(a, None)` or
    `(None, b)` for a key in one sequence."""
    left, right = next(side_a, None), next(side_b, None)
    while left is not None and right is not None:
        if left[0] < right[0]:
            yield left[1], None
            left = next(side_a, None)
        elif right[0] < left[0]:
            yield None, right[1]
            right = next(side_b, None)
        else:
            yield left[1], right[1]
            left, right = next(side_a, None), next(side_b, None)
    if left is not None:
        yield left[1], None
        yield from ((row, None) for _key, row in side_a)
    if right is not None:
        yield None, right[1]
        yield from ((None, row) for _key, row in side_b)


class _Detail:
    """One bucket of the result.

    The bucket counts every record and keeps the first DETAIL_CAP records in
    sort order. `rows` equals `sorted(records, key=...)[:DETAIL_CAP]` of the
    whole bucket. The sort key is the key fields as strings, with the empty
    string for a missing field. Records with equal keys stay in arrival order.
    """

    def __init__(self, *keys: str) -> None:
        self._keys = keys
        self._kept: list[tuple[tuple[str, ...], int, dict[str, Any]]] = []
        self.count = 0

    def add(self, record: dict[str, Any]) -> None:
        # The count is the arrival number of the record. It is unique, and no
        # comparison of 2 entries reaches the record.
        entry = (tuple(str(record.get(k) or "") for k in self._keys), self.count, record)
        self.count += 1
        if len(self._kept) < DETAIL_CAP:
            bisect.insort(self._kept, entry)
        elif self._kept and entry < self._kept[-1]:
            bisect.insort(self._kept, entry)
            self._kept.pop()

    @property
    def rows(self) -> list[dict[str, Any]]:
        return [record for _key, _seq, record in self._kept]

    @property
    def truncated(self) -> bool:
        return self.count > DETAIL_CAP


# --- removal records --------------------------------------------------------------------

# A device with one of these outcomes did not answer for its own scope in B.
UNANSWERED_OUTCOMES = ("failed", "carried")
REMOVED = "removed"
UNKNOWN = "unknown"


def _removal_record(uid: str, row: dict[str, Any], devices: DeviceIndex | None) -> dict[str, Any]:
    """`status` is `removed` only when the owning device answered for its own scope
    in B."""
    props = row["props"]
    record = {"uid": uid, "label": _primary_label(row["labels"]), "name": props.get("name")}
    if devices is None:
        return record
    owner = device_owner(props, devices)
    absence = None
    if owner is not None:
        absence = owner.fetch_started_ms if owner.fetch_started_ms is not None else owner.fetch_ts_ms
    return {
        **record,
        "last_seen": props.get("collected_at"),
        "absence_detected": absence,
        "device": (
            None if owner is None else {"source": owner.source, "host": owner.host, "outcome": owner.outcome}
        ),
        "status": UNKNOWN if owner is not None and owner.outcome in UNANSWERED_OUTCOMES else REMOVED,
    }


def _rel_record(row: dict[str, Any]) -> dict[str, Any]:
    return {"type": row["type"], "start": row["start"], "end": row["end"]}


# An Observer receives every record of the comparison, without the detail cap.
# The order is nodes by label and uid, then relationships by type, start and
# end. `before` and `after` hold the full payload of an added or removed object,
# and the changed properties of a changed object.
Observer = Callable[[dict[str, Any]], None]


def _observed(
    kind: str,
    change: str,
    label: str,
    *,
    uid: Any = None,
    start: Any = None,
    end: Any = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "change": change,
        "uid": uid,
        "label": label,
        "start": start,
        "end": end,
        "before": before,
        "after": after,
    }


def diff_snapshots(
    archive: Session,
    snap_a: int | str,
    snap_b: int | str,
    *,
    devices_b: Sequence[Any] | None = None,
    observer: Observer | None = None,
    timeout_s: float | None = None,
) -> dict[str, Any]:
    """Added means "in B, not in A"."""
    devices = None if devices_b is None else device_index(devices_b)

    node_added = _Detail("label", "uid")
    node_removed = _Detail("label", "uid")
    node_changed = _Detail("label", "uid")
    conflicts_a = _Detail("label", "uid", "field")
    conflicts_b = _Detail("label", "uid", "field")

    def compare_nodes() -> None:
        with (
            read_sorted(archive, _ALL_NODES, _node_entry, snap=snap_a, timeout_s=timeout_s) as rows_a,
            read_sorted(archive, _ALL_NODES, _node_entry, snap=snap_b, timeout_s=timeout_s) as rows_b,
        ):
            pairs = _joined(_one_node(rows_a), _one_node(rows_b))
            for a, b in pairs:
                if a is not None:
                    for conflict in _assertion_conflicts(a["uid"], a["labels"], a["props"]):
                        conflicts_a.add(conflict)
                if b is not None:
                    for conflict in _assertion_conflicts(b["uid"], b["labels"], b["props"]):
                        conflicts_b.add(conflict)
                if b is None:
                    if a is not None:
                        node_removed.add(_removal_record(a["uid"], a, devices))
                        if observer is not None:
                            observer(
                                _observed(
                                    "node",
                                    REMOVED,
                                    _primary_label(a["labels"]),
                                    uid=a["uid"],
                                    before=_payload(a["props"]),
                                )
                            )
                    continue
                named = {
                    "uid": b["uid"],
                    "label": _primary_label(b["labels"]),
                    "name": b["props"].get("name"),
                }
                if a is None:
                    node_added.add(named)
                    if observer is not None:
                        observer(
                            _observed(
                                "node", "added", named["label"], uid=b["uid"], after=_payload(b["props"])
                            )
                        )
                    continue
                changes = _prop_changes(_compared(a), _compared(b))
                if changes:
                    node_changed.add({**named, "changes": changes})
                    if observer is not None:
                        observer(
                            _observed(
                                "node",
                                "changed",
                                named["label"],
                                uid=b["uid"],
                                before={k: v[0] for k, v in changes.items()},
                                after={k: v[1] for k, v in changes.items()},
                            )
                        )

    compare_nodes()

    rel_added = _Detail("type", "start", "end")
    rel_removed = _Detail("type", "start", "end")
    rel_changed = _Detail("type", "start", "end")
    with (
        read_sorted(archive, _ALL_RELS, _rel_entry, snap=snap_a, timeout_s=timeout_s) as rels_a,
        read_sorted(archive, _ALL_RELS, _rel_entry, snap=snap_b, timeout_s=timeout_s) as rels_b,
    ):
        for edges_a, edges_b in _joined(_edges(rels_a), _edges(rels_b)):
            for a, b in _edge_pairs(edges_a or [], edges_b or []):
                if b is None:
                    if a is not None:
                        rel_removed.add(_rel_record(a))
                        if observer is not None:
                            observer(
                                _observed(
                                    "rel",
                                    REMOVED,
                                    a["type"],
                                    start=a["start"],
                                    end=a["end"],
                                    before=a["payload"],
                                )
                            )
                elif a is None:
                    rel_added.add(_rel_record(b))
                    if observer is not None:
                        observer(
                            _observed(
                                "rel",
                                "added",
                                b["type"],
                                start=b["start"],
                                end=b["end"],
                                after=b["payload"],
                            )
                        )
                else:
                    changes = _prop_changes(a["payload"], b["payload"])
                    if changes:
                        rel_changed.add({**_rel_record(b), "changes": changes})
                        if observer is not None:
                            observer(
                                _observed(
                                    "rel",
                                    "changed",
                                    b["type"],
                                    start=b["start"],
                                    end=b["end"],
                                    before={k: v[0] for k, v in changes.items()},
                                    after={k: v[1] for k, v in changes.items()},
                                )
                            )

    buckets = (
        node_added,
        node_removed,
        node_changed,
        rel_added,
        rel_removed,
        rel_changed,
        conflicts_a,
        conflicts_b,
    )
    return {
        "a": snap_a,
        "b": snap_b,
        "counts": {
            "nodes": {
                "added": node_added.count,
                "removed": node_removed.count,
                "changed": node_changed.count,
            },
            "rels": {"added": rel_added.count, "removed": rel_removed.count, "changed": rel_changed.count},
        },
        "nodes": {"added": node_added.rows, "removed": node_removed.rows, "changed": node_changed.rows},
        "rels": {"added": rel_added.rows, "removed": rel_removed.rows, "changed": rel_changed.rows},
        "conflicts": {
            "a": conflicts_a.rows,
            "b": conflicts_b.rows,
            "counts": {"a": conflicts_a.count, "b": conflicts_b.count},
        },
        "truncated": any(bucket.truncated for bucket in buckets),
    }


# --- the comparison of a request --------------------------------------------------------


class DiffTimeout(Exception):
    """A comparison that answers a request ran past `INTERACTIVE_READ_TIMEOUT_S`."""


# The key holds a digest of B's device entries.
_RESULTS: OrderedDict[tuple[int | str, int | str, str], dict[str, Any]] = OrderedDict()
_RESULTS_KEPT = 16
_RESULTS_LOCK = threading.Lock()


def request_diff(
    archive: Session, snap_a: int | str, snap_b: int | str, *, devices_b: Sequence[Any]
) -> dict[str, Any]:
    """Run `diff_snapshots` for a request.

    Each read has the timeout `INTERACTIVE_READ_TIMEOUT_S`, and a read over it
    raises `DiffTimeout`. The result is cached for each run pair and device
    list. The caller has checked that both runs exist and are not being built.
    The caller must not change the result.
    """
    key = (snap_a, snap_b, hashlib.sha256(repr(list(devices_b)).encode()).hexdigest())
    with _RESULTS_LOCK:
        if key in _RESULTS:
            _RESULTS.move_to_end(key)
            return _RESULTS[key]
    try:
        result = diff_snapshots(
            archive, snap_a, snap_b, devices_b=devices_b, timeout_s=INTERACTIVE_READ_TIMEOUT_S
        )
    except ClientError as exc:
        if "TransactionTimedOut" not in (exc.code or ""):
            raise
        raise DiffTimeout(
            f"comparing runs {snap_a} and {snap_b} took longer than {INTERACTIVE_READ_TIMEOUT_S:g} s"
        ) from exc
    with _RESULTS_LOCK:
        _RESULTS[key] = result
        while len(_RESULTS) > _RESULTS_KEPT:
            _RESULTS.popitem(last=False)
    return result
