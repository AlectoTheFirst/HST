"""A carry-forward and a snapshot comparison that hold every read in memory, the
reference of the parity tests of `core/cycle.py carry_forward` and
`core/diff.py diff_snapshots`.

The parity tests hold no case of the two rules below. The comparison here keeps
one edge per type and pair of objects, the row the database returns last. And `_owner_of` here
matches a device entry by its host alone, the rule `core/cycle.py
device_owner` applies only to an entry that records no scope.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from hst.core import cycle as cyclemod
from hst.core import diff as diffmod
from hst.core.labels import RESERVED_LABELS

# The relationship read of `reference_carry_forward`.
READ_CARRY_RELS = """
MATCH (a0:Obj {collection_ts: $prev})-[r]->(b0:Obj {collection_ts: $prev})
WHERE coalesce(r._scope, '') <> 'reasoner'
MATCH (a:Obj {uid: a0.uid, collection_ts: $cts}), (b:Obj {uid: b0.uid, collection_ts: $cts})
WHERE (a.carried = true OR b.carried = true)
  AND NOT EXISTS { MATCH (a)-[r2]->(b) WHERE type(r2) = type(r) }
RETURN a.uid AS start, b.uid AS end, type(r) AS t, properties(r) AS props,
       CASE WHEN a.carried = true THEN a.carried_reason ELSE b.carried_reason END AS reason
"""


# The reads of `reference_diff`: the label sets and types in play, then one
# read of the run per label and per type.
NODE_LABEL_SETS = "MATCH (n:Obj {collection_ts: $snap}) RETURN DISTINCT labels(n) AS labels"
NODES_FOR_LABEL = (
    "MATCH (n:Obj {collection_ts: $snap}) WHERE $label IN labels(n) "
    "RETURN n.uid AS uid, labels(n) AS labels, properties(n) AS props"
)
NODES_NO_DOMAIN_LABEL = (
    "MATCH (n:Obj {collection_ts: $snap}) WHERE none(l IN labels(n) WHERE NOT l IN $reserved) "
    "RETURN n.uid AS uid, labels(n) AS labels, properties(n) AS props"
)
REL_TYPES = (
    "MATCH (a:Obj {collection_ts: $snap})-[r]->(b:Obj) WHERE r.collection_ts = $snap "
    "RETURN DISTINCT type(r) AS t"
)
RELS_FOR_TYPE = (
    "MATCH (a:Obj {collection_ts: $snap})-[r]->(b:Obj) WHERE r.collection_ts = $snap AND type(r) = $type "
    "RETURN a.uid AS start, b.uid AS end, type(r) AS t, properties(r) AS props"
)
RESERVED = list(RESERVED_LABELS)


def _read(session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    return session.execute_read(lambda tx: tx.run(query, **params).data())


def _domain_labels(session: Any, snap: int | str) -> tuple[set[str], bool]:
    """Domain labels present at `snap`, and whether any node there carries none."""
    labels: set[str] = set()
    no_domain = False
    for row in _read(session, NODE_LABEL_SETS, snap=snap):
        named = [label for label in row["labels"] if label not in RESERVED_LABELS]
        if named:
            labels.add(named[0])
        else:
            no_domain = True
    return labels, no_domain


def _rel_types(session: Any, snap: int | str) -> set[str]:
    return {row["t"] for row in _read(session, REL_TYPES, snap=snap)}


def _write(session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    return session.execute_write(lambda tx: tx.run(query, **params).data())


def reference_carry_forward(
    session: Any,
    prev: int,
    cts: int,
    sources: list[str],
    *,
    scopes: Mapping[str, str] | None = None,
    collected: Iterable[str] = (),
    unasked: Iterable[str] | None = None,
    section_labels: Mapping[str, Iterable[str]] | None = None,
    batch: int = cyclemod.BATCH,
) -> dict[str, int]:
    """The reference of `core/cycle.py carry_forward`. It holds each read whole
    in memory and writes it back in batches of `batch`."""
    if prev == cts:
        return {"nodes": 0, "rels": 0}
    reasons = dict(scopes or {})
    per_section = {s: sorted(set(labels)) for s, labels in (section_labels or {}).items() if labels}
    whole = sorted(set(sources) if unasked is None else set(unasked))
    if not (sources or reasons or whole or per_section):
        return {"nodes": 0, "rels": 0}
    named = sorted(set(reasons) | set(collected))
    nodes = 0
    grouped: dict[tuple[str, ...], list[dict]] = {}
    seen: set[str] = set()

    def collect_row(rec: dict[str, Any], reason: str) -> None:
        labels = tuple(sorted(set(rec["labels"]) - {"Latest", "Retired"}))
        props = {k: v for k, v in rec["props"].items() if k != "collection_ts"}
        uid = str(props.get("uid") or "")
        if uid and uid in seen:
            return
        seen.add(uid)
        grouped.setdefault(labels, []).append(cyclemod._stamp(props, reason))

    for rec in _read(
        session,
        cyclemod._READ_CARRY_NODES,
        prev=prev,
        cts=cts,
        sources=sources,
        scopes=sorted(reasons),
        named=named,
        unasked=whole,
    ):
        collect_row(rec, reasons.get(rec["props"].get("_scope") or "", cyclemod.NOT_RUN))
    for scope, labels_wanted in sorted(per_section.items()):
        for rec in _read(
            session, cyclemod._READ_CARRY_SECTION_NODES, prev=prev, cts=cts, scope=scope, labels=labels_wanted
        ):
            collect_row(rec, cyclemod.SECTION_FAILED)
    for labels, rows in grouped.items():
        for i in range(0, len(rows), batch):
            chunk = rows[i : i + batch]
            _write(
                session,
                f"UNWIND $rows AS row CREATE (n{cyclemod._label_clause(list(labels))}) "
                "SET n = row, n.collection_ts = $cts, n.carried = true",
                rows=chunk,
                cts=cts,
            )
            nodes += len(chunk)

    rels = 0
    rel_rows = _read(session, READ_CARRY_RELS, prev=prev, cts=cts)
    by_type: dict[str, list[dict]] = {}
    for rec in rel_rows:
        props = {k: v for k, v in rec["props"].items() if k != "collection_ts"}
        cyclemod._stamp(props, rec["reason"] or cyclemod.NOT_RUN)
        by_type.setdefault(rec["t"], []).append({"start": rec["start"], "end": rec["end"], "props": props})
    for rel_type, rows in by_type.items():
        cyclemod._label_clause([rel_type])
        for i in range(0, len(rows), batch):
            chunk = rows[i : i + batch]
            _write(
                session,
                "UNWIND $rows AS row "
                "MATCH (a:Obj {uid: row.start, collection_ts: $cts}), "
                "(b:Obj {uid: row.end, collection_ts: $cts}) "
                f"CREATE (a)-[r:{rel_type}]->(b) "
                "SET r = row.props, r.collection_ts = $cts, r.carried = true",
                rows=chunk,
                cts=cts,
            )
            rels += len(chunk)
    return {"nodes": nodes, "rels": rels}


def _conflicts_in(nodes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for uid, row in nodes.items():
        out.extend(diffmod._assertion_conflicts(uid, row["labels"], row["props"]))
    return out


def _owner_of(props: dict[str, Any], devices: Sequence[Any]) -> Any | None:
    scope = str(props.get("_scope") or "")
    sources = props.get("_sources") or []
    if not scope or not sources:
        return None
    segments = scope.split(":")[1:]
    matches = [d for d in devices if d.source in sources and (not d.host or d.host in segments)]
    return matches[0] if len(matches) == 1 else None


def _removal_record(uid: str, row: dict[str, Any], devices: Sequence[Any] | None) -> dict[str, Any]:
    props = row["props"]
    record = {"uid": uid, "label": diffmod._primary_label(row["labels"]), "name": props.get("name")}
    if devices is None:
        return record
    owner = _owner_of(props, devices)
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
        "status": (
            diffmod.UNKNOWN
            if owner is not None and owner.outcome in diffmod.UNANSWERED_OUTCOMES
            else diffmod.REMOVED
        ),
    }


def _diff_nodes(
    nodes_a: dict[str, dict[str, Any]],
    nodes_b: dict[str, dict[str, Any]],
    devices_b: Sequence[Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    added = [
        {
            "uid": uid,
            "label": diffmod._primary_label(nodes_b[uid]["labels"]),
            "name": nodes_b[uid]["props"].get("name"),
        }
        for uid in nodes_b.keys() - nodes_a.keys()
    ]
    removed = [_removal_record(uid, nodes_a[uid], devices_b) for uid in nodes_a.keys() - nodes_b.keys()]
    changed = []
    for uid in nodes_a.keys() & nodes_b.keys():
        changes = diffmod._prop_changes(
            diffmod._payload(nodes_a[uid]["props"]), diffmod._payload(nodes_b[uid]["props"])
        )
        if changes:
            changed.append(
                {
                    "uid": uid,
                    "label": diffmod._primary_label(nodes_b[uid]["labels"]),
                    "name": nodes_b[uid]["props"].get("name"),
                    "changes": changes,
                }
            )
    return added, removed, changed


def reference_diff(
    archive: Any,
    snap_a: int | str,
    snap_b: int | str,
    *,
    devices_b: Sequence[Any] | None = None,
    cap: int = diffmod.DETAIL_CAP,
) -> dict[str, Any]:
    """The reference of `core/diff.py diff_snapshots`. It reads each label and
    type of a run whole into memory. `cap` is its DETAIL_CAP."""
    labels_a, no_domain_a = _domain_labels(archive, snap_a)
    labels_b, no_domain_b = _domain_labels(archive, snap_b)

    node_added: list[dict[str, Any]] = []
    node_removed: list[dict[str, Any]] = []
    node_changed: list[dict[str, Any]] = []
    conflicts_a: list[dict[str, Any]] = []
    conflicts_b: list[dict[str, Any]] = []
    for label in labels_a | labels_b:
        nodes_a = {r["uid"]: r for r in _read(archive, NODES_FOR_LABEL, snap=snap_a, label=label)}
        nodes_b = {r["uid"]: r for r in _read(archive, NODES_FOR_LABEL, snap=snap_b, label=label)}
        added, removed, changed = _diff_nodes(nodes_a, nodes_b, devices_b)
        node_added.extend(added)
        node_removed.extend(removed)
        node_changed.extend(changed)
        conflicts_a.extend(_conflicts_in(nodes_a))
        conflicts_b.extend(_conflicts_in(nodes_b))

    if no_domain_a or no_domain_b:
        rows_a = _read(archive, NODES_NO_DOMAIN_LABEL, snap=snap_a, reserved=RESERVED)
        rows_b = _read(archive, NODES_NO_DOMAIN_LABEL, snap=snap_b, reserved=RESERVED)
        nodes_a = {r["uid"]: r for r in rows_a}
        nodes_b = {r["uid"]: r for r in rows_b}
        added, removed, changed = _diff_nodes(nodes_a, nodes_b, devices_b)
        node_added.extend(added)
        node_removed.extend(removed)
        node_changed.extend(changed)
        conflicts_a.extend(_conflicts_in(nodes_a))
        conflicts_b.extend(_conflicts_in(nodes_b))

    def _rel_row(key: tuple[str, str, str]) -> dict[str, Any]:
        t, start, end = key
        return {"type": t, "start": start, "end": end}

    rel_added: list[dict[str, Any]] = []
    rel_removed: list[dict[str, Any]] = []
    rel_changed: list[dict[str, Any]] = []
    for rel_type in _rel_types(archive, snap_a) | _rel_types(archive, snap_b):
        rels_a = {
            (r["t"], r["start"], r["end"]): r["props"]
            for r in _read(archive, RELS_FOR_TYPE, snap=snap_a, type=rel_type)
        }
        rels_b = {
            (r["t"], r["start"], r["end"]): r["props"]
            for r in _read(archive, RELS_FOR_TYPE, snap=snap_b, type=rel_type)
        }
        rel_added.extend(_rel_row(k) for k in rels_b.keys() - rels_a.keys())
        rel_removed.extend(_rel_row(k) for k in rels_a.keys() - rels_b.keys())
        for k in rels_a.keys() & rels_b.keys():
            changes = diffmod._prop_changes(diffmod._payload(rels_a[k]), diffmod._payload(rels_b[k]))
            if changes:
                rel_changed.append({**_rel_row(k), "changes": changes})

    def _sorted(rows: list[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
        return sorted(rows, key=lambda r: tuple(str(r.get(k) or "") for k in keys))

    node_added = _sorted(node_added, "label", "uid")
    node_removed = _sorted(node_removed, "label", "uid")
    node_changed = _sorted(node_changed, "label", "uid")
    rel_added = _sorted(rel_added, "type", "start", "end")
    rel_removed = _sorted(rel_removed, "type", "start", "end")
    rel_changed = _sorted(rel_changed, "type", "start", "end")
    conflicts_a = _sorted(conflicts_a, "label", "uid", "field")
    conflicts_b = _sorted(conflicts_b, "label", "uid", "field")

    return {
        "a": snap_a,
        "b": snap_b,
        "counts": {
            "nodes": {"added": len(node_added), "removed": len(node_removed), "changed": len(node_changed)},
            "rels": {"added": len(rel_added), "removed": len(rel_removed), "changed": len(rel_changed)},
        },
        "nodes": {
            "added": node_added[:cap],
            "removed": node_removed[:cap],
            "changed": node_changed[:cap],
        },
        "rels": {
            "added": rel_added[:cap],
            "removed": rel_removed[:cap],
            "changed": rel_changed[:cap],
        },
        "conflicts": {
            "a": conflicts_a[:cap],
            "b": conflicts_b[:cap],
            "counts": {"a": len(conflicts_a), "b": len(conflicts_b)},
        },
        "truncated": any(
            len(rows) > cap
            for rows in (
                node_added,
                node_removed,
                node_changed,
                rel_added,
                rel_removed,
                rel_changed,
                conflicts_a,
                conflicts_b,
            )
        ),
    }
