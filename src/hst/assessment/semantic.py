"""The bounded read of the semantic inputs of a snapshot, and their change stream."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from hst import path as pathmod
from hst.core import grapharchive
from hst.core import manifest as manifestmod
from hst.core.diff import _assertion_conflicts, _payload

_OBSERVED_LABELS = {"ArpEntry", "MacEntry", "LearnedRoute", "Endpoint", "BgpSessionObservation"}
_OBSERVED_PROPS = {"state", "status", "oper_state", "oper_status", "link_state", "uptime", "adjacency_state"}


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _category(row: Mapping[str, Any], *, relationship: bool = False) -> str:
    props = row.get("props", {})
    if props.get("derived") or str(props.get("_scope", "")).startswith("derived:"):
        return "derived"
    if "MtuObservation" in row.get("labels", ()):
        return "configuration" if props.get("assertion_kind") in {"configured", "intent"} else "observation"
    if set(row.get("labels", ())) & _OBSERVED_LABELS or (
        relationship and row.get("type") in {"LEARNED_ROUTE", "ARP_ENTRY", "MAC_ENTRY"}
    ):
        return "observation"
    return "configuration"


def read_snapshot_inputs(
    session: Any,
    snapshot: Any,
    settings: Any,
    *,
    max_records: int = 100000,
    max_bytes: int = 32 * 1024 * 1024,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Read the pinned graph and every side-table file that the manifest references.

    The digest of a file is checked before the file is read. A bound that stops
    the read sets `stop_reason`, and `complete` is then false. Raw credentials
    and raw configuration payloads are not read.
    """
    if not 1 <= max_records <= 1000000 or not 1024 <= max_bytes <= 256 * 1024 * 1024:
        raise ValueError("semantic input read bounds are outside supported limits")
    record = snapshot.manifest
    if record is None or snapshot.cts is None:
        raise ValueError("semantic differences require a pinned evidence manifest")
    records: list[dict[str, Any]] = []
    coverage: dict[str, bool] = {}
    used_bytes = 0
    stop_reason: str | None = None

    def add(item: dict[str, Any]) -> bool:
        nonlocal used_bytes, stop_reason
        if cancelled and cancelled():
            stop_reason = "cancelled"
            return False
        size = len(json.dumps(item, sort_keys=True, default=str).encode())
        if len(records) >= max_records or used_bytes + size > max_bytes:
            stop_reason = "record-limit" if len(records) >= max_records else "byte-limit"
            return False
        records.append(item)
        used_bytes += size
        return True

    for device in record.devices:
        key = f"{device.source}/{device.host}"
        coverage[key] = bool(
            not device.carried
            and device.outcome in {"collected", "unchanged"}
            and device.expected_sections
            and all(
                name in device.sections and device.sections[name].status in {"ok", "empty"}
                for name in device.expected_sections
            )
        )
        values = {
            "source": device.source,
            "host": device.host,
            "outcome": device.outcome,
            "carried": device.carried,
            "effective_run": device.effective_run,
            "sections": {k: v.model_dump(mode="json") for k, v in device.sections.items()},
            "tables": {k: v.model_dump(mode="json") for k, v in device.tables.items()},
            "device_uids": list(device.device_uids),
        }
        add(
            {
                "key": f"collection:{key}",
                "category": "observation" if coverage[key] else "collection-failure",
                "value": values,
                "owners": [key],
                "complete": coverage[key],
            }
        )
    # Each page runs the query again. The rows have one total order, and no page
    # repeats or skips a row. The endpoints and the type of a relationship are not
    # unique. Parallel edges are ordered by their element id.
    pages = (
        (grapharchive._NODES + ", elementId(n) AS element_id ORDER BY uid, element_id", False),
        (
            grapharchive._RELS + ", elementId(r) AS element_id ORDER BY `start`, `type`, `end`, element_id",
            True,
        ),
    )
    for query, relationship in pages:
        offset = 0
        while stop_reason is None:
            rows = pathmod._read(
                session,
                query + " SKIP $offset LIMIT $limit",
                snap=snapshot.cts,
                offset=offset,
                limit=min(1000, max_records + 1),
            )
            for row in rows:
                props = row.get("props", {})
                sources = set(props.get("_sources", ()))
                scope = str(props.get("_scope", ""))
                owners = sorted(
                    f"{d.source}/{d.host}"
                    for d in record.devices
                    if d.source in sources and (not d.host or d.host in scope.split(":"))
                )
                if relationship:
                    key = "rel:" + digest([row["type"], row["start"], row["end"]])
                    identity = {"type": row["type"], "start": row["start"], "end": row["end"]}
                else:
                    key, identity = f"node:{row['uid']}", {"uid": row["uid"], "labels": sorted(row["labels"])}
                conflicts = _assertion_conflicts(key, row.get("labels", []), props)
                if conflicts and not add(
                    {
                        "key": f"conflict:{key}",
                        "category": "collection-failure",
                        "value": conflicts,
                        "owners": owners,
                        "complete": False,
                    }
                ):
                    break
                category = _category(row, relationship=relationship)
                if relationship and row.get("snapshot_valid") is False:
                    category = "collection-failure"
                payload = _payload(props)
                observed_props = {
                    k: payload.pop(k)
                    for k in tuple(payload)
                    if category == "configuration" and k in _OBSERVED_PROPS
                }
                if not add(
                    {
                        "key": key,
                        "category": category,
                        "value": {**identity, "props": payload},
                        "owners": owners,
                        "complete": bool(owners) and all(coverage.get(owner, False) for owner in owners),
                    }
                ):
                    break
                if observed_props and not add(
                    {
                        "key": f"observation:{key}",
                        "category": "observation",
                        "value": {**identity, "props": observed_props},
                        "owners": owners,
                        "complete": all(coverage.get(o) for o in owners),
                    }
                ):
                    break
            if len(rows) < min(1000, max_records + 1):
                break
            offset += len(rows)
    # The manifest lists the observation files to read.
    for entry in record.files:
        if stop_reason or entry.kind != "sidestore":
            continue
        owner = f"{entry.source}/{entry.host}"
        target = (Path(settings.hst_data_dir) / entry.path).resolve()
        if not target.is_relative_to(Path(settings.hst_data_dir).resolve()):
            raise ValueError("manifest side-table path escapes the evidence directory")
        if target.is_file() and target.stat().st_size > max_bytes:
            stop_reason = "input-byte-limit"
            break
        if not target.is_file() or manifestmod.file_facts(target)[0] != entry.sha256:
            add(
                {
                    "key": f"missing-file:{entry.path}",
                    "category": "collection-failure",
                    "value": {"path": entry.path, "reason": "missing-or-changed-evidence"},
                    "owners": [owner],
                    "complete": False,
                }
            )
            coverage[owner] = False
            continue
        import pyarrow.parquet as pq

        file = pq.ParquetFile(target)
        for batch in file.iter_batches(batch_size=1000):
            for row in batch.to_pylist():
                # The changes are a multiset of observed rows.
                value = {
                    k: v for k, v in row.items() if k not in {"collection_ts", "observed_ms", "fetch_ts_ms"}
                }
                if not add(
                    {
                        "key": f"table:{owner}:{entry.table}:{digest(value)}",
                        "category": "observation",
                        "value": value,
                        "owners": [owner],
                        "table": entry.table,
                        "complete": not entry.truncated and coverage.get(owner, False),
                    }
                ):
                    break
            if stop_reason:
                break
    return {
        "snapshot": str(snapshot.cts),
        "records": records,
        "coverage": coverage,
        "complete": stop_reason is None,
        "evidence_complete": bool(records) and all(r.get("complete") for r in records),
        "stop_reason": stop_reason or "complete",
        "record_count": len(records),
        "bytes": used_bytes,
        "counts": dict(Counter(r["category"] for r in records)),
        "limits": {"max_records": max_records, "max_bytes": max_bytes},
    }


def semantic_change_stream(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Compare the records of 2 snapshot input reads and return the changes of every category."""

    def index(snapshot: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {}
        for row in snapshot["records"]:
            out.setdefault(row["key"], []).append(row)
        return out

    left, right = index(before), index(after)
    changes = []
    for key in sorted(left.keys() | right.keys()):
        old, new = left.get(key, []), right.get(key, [])
        old_values = sorted((r["value"] for r in old), key=digest)
        new_values = sorted((r["value"] for r in new), key=digest)
        if old_values == new_values:
            continue
        category = (new or old)[0]["category"]
        owners = sorted({owner for r in old + new for owner in r["owners"]})
        observed_edit = bool(
            before["complete"]
            and after["complete"]
            and owners
            and all(before["coverage"].get(o) and after["coverage"].get(o) for o in owners)
            and all(row.get("complete") for row in old + new)
        )
        reason = None
        if category == "configuration" and not observed_edit:
            category = "collection-failure"
            reason = "Configuration change is unconfirmed because owning-source completeness is missing."
        changes.append(
            {
                "id": "semantic:" + digest(key)[:24],
                "key": key,
                "category": category,
                "before": old_values,
                "after": new_values,
                "owners": owners,
                "observed_edit": observed_edit,
                "reason": reason,
                "precondition": {"before_sha256": digest(old_values), "after_sha256": digest(new_values)},
            }
        )
    return {
        "changes": changes,
        "complete": bool(before["complete"] and after["complete"]),
        "before_snapshot": before["snapshot"],
        "after_snapshot": after["snapshot"],
        "counts": dict(Counter(c["category"] for c in changes)),
        "input_read_limits": {"before": before.get("limits"), "after": after.get("limits")},
        "input_stop_reasons": {"before": before["stop_reason"], "after": after["stop_reason"]},
    }
