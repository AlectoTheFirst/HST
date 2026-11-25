"""Invertible tier deltas: one row per changed element."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any

ADD, REMOVE, SET = "add", "remove", "set"
# Every row of a run holds the run key in `snapshot_ts`. The comparison leaves the column out.
UNCOMPARED = frozenset({"snapshot_ts"})

_JSON = json.JSONEncoder(sort_keys=True, separators=(",", ":"))


def _encode(row: Mapping[str, Any] | None) -> str | None:
    return None if row is None else _JSON.encode(dict(row))


def _compared(row: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in UNCOMPARED}


def changes(
    table: str,
    before: Mapping[str, Mapping[str, Any]],
    after: Mapping[str, Mapping[str, Any]],
    tile_of: Callable[[Mapping[str, Any]], str | None] = lambda _row: None,
) -> Iterator[dict[str, Any]]:
    """The delta rows that turn `before` into `after`, both keyed by the table's key, in key order."""
    for uid in sorted(set(before) | set(after)):
        old, new = before.get(uid), after.get(uid)
        if old is None and new is not None:
            yield {
                "table": table,
                "tile": tile_of(new),
                "uid": uid,
                "op": ADD,
                "before": None,
                "after": _encode(_compared(new)),
            }
        elif new is None and old is not None:
            yield {
                "table": table,
                "tile": tile_of(old),
                "uid": uid,
                "op": REMOVE,
                "before": _encode(_compared(old)),
                "after": None,
            }
        elif old is not None and new is not None:
            cols = sorted(k for k in _compared(new) if new[k] != old.get(k))
            if cols:
                yield {
                    "table": table,
                    "tile": tile_of(new),
                    "uid": uid,
                    "op": SET,
                    "before": _encode({k: old.get(k) for k in cols}),
                    "after": _encode({k: new[k] for k in cols}),
                }


def apply(
    rows: dict[str, dict[str, Any]], delta: Iterable[Mapping[str, Any]], *, inverse: bool = False
) -> None:
    """Apply `delta` to `rows` in place, or unapply it with `inverse`."""
    for d in delta:
        uid, op = d["uid"], d["op"]
        before = json.loads(d["before"]) if d["before"] else None
        after = json.loads(d["after"]) if d["after"] else None
        if inverse:
            op = {ADD: REMOVE, REMOVE: ADD, SET: SET}[op]
            before, after = after, before
        if op == ADD:
            rows[uid] = dict(after or {})
        elif op == REMOVE:
            rows.pop(uid, None)
        else:
            rows.setdefault(uid, {}).update(after or {})
