"""The batch loader writes one collector batch into a cycle of the graph."""

from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Sequence
from typing import Any, Protocol

from .ipenc import graph_address_props
from .labels import CycleIdentityCollision, labels_clause
from .model import Batch, NodeRecord, RelRecord, RunManifest, SectionOutcome

CHUNK = 5000


class SessionLike(Protocol):
    def run(self, query: str, **params: Any) -> Any: ...

    # `work` is positional-only. The Neo4j driver has the name `transaction_function`
    # for this parameter. A Protocol with another name for a keyword parameter does
    # not match the driver.
    def execute_write(self, work: Callable[[Any], Any], /) -> Any: ...


# --- query builders ---------------------------------------------------------------------


def node_upsert_query(label: str) -> str:
    return f"""
UNWIND $rows AS row
MERGE (n{labels_clause(label)} {{uid: row.uid, collection_ts: $cts}})
WITH n, row, properties(n) AS before
SET n += row.props,
    n.collected_at = $ts,
    n.carried = false,
    n.carried_reason = null,
    n.last_seen_ts = null,
    n._run_id = $run_id,
    n._scope = coalesce(n._scope, $scope),
    n._sources = CASE WHEN $source IN coalesce(n._sources, []) THEN n._sources
                      ELSE coalesce(n._sources, []) + $source END
RETURN row.uid AS uid, before
"""


def rel_upsert_query(rel_type: str, key_fields: tuple[str, ...]) -> str:
    # Batch.validate_registry allows only bare identifiers in key_fields.
    key_map = ", ".join(f"{k}: row.key.{k}" for k in key_fields)
    pattern = f"[r:{rel_type}" + (f" {{{key_map}}}" if key_fields else "") + "]"
    return f"""
UNWIND $rows AS row
MATCH (a:Obj {{uid: row.start, collection_ts: $cts}}), (b:Obj {{uid: row.end, collection_ts: $cts}})
MERGE (a)-{pattern}->(b)
WITH r, row, r {{.collected_at}} AS before
SET r += row.props,
    r.collection_ts = $cts,
    r.collected_at = $ts,
    r.carried = false,
    r.carried_reason = null,
    r.last_seen_ts = null,
    r._run_id = $run_id,
    r._scope = coalesce(r._scope, $scope)
RETURN row.start AS start, row.end AS end, before
"""


# --- source assertions and materialization precedence -----------------------------------
#
# 2 collectors can write one uid in one cycle. APIC and NX-OS both resolve the
# serial of a fabric leaf to one device uid in the identity registry
# (core/identity.py). Every device collector declares the same
# `bd:vlan:<fabric>:<vid>` broadcast domain.
#
# A node that more than one source wrote in a cycle has the property
# `_assert.<field>` for each payload field. The property is the sorted list of
# the assertions of the field, one `<collector>/<source>=<json value>` string
# per source. The field holds the effective value. The precedence table chooses
# the effective value from the assertions. A node that one source wrote has no
# `_assert.` property.

ASSERT_PREFIX = "_assert."


def collector_type(scope: str) -> str:
    """The collector type of a batch scope, the part before the first colon.

    Every collector builds its scope as `<collector type>:<partition>`
    (`nxos:leaf1`, `iosxe:r1`, `apic:fab1`, `vyos:gw1`, `cp:fw.example.net`,
    `derived:rt-domains`). The prefix does not depend on the name of the source
    row. A scope with no colon is its own collector type.
    """
    return scope.partition(":")[0]


# No source asserts these properties or a `_`-prefixed property.
_NOT_PAYLOAD = frozenset({"uid", "collection_ts", "collected_at", "carried"})

# The authority class of each collector type.
#   observed    read from the device, by CLI or device API
#   configured  read from a controller or a manager, or declared by hand
#   derived     computed from the facts of other sources
# The key is the scope prefix that `collector_type` returns. The Check Point
# collector has the prefix `cp`. core/reasoner.py has the prefix `derived`.
COLLECTOR_CLASSES: dict[str, str] = {
    "apic": "configured",
    "cp": "observed",  # collectors/checkpoint.py
    "derived": "derived",  # core/reasoner.py
    "iosxe": "observed",
    "iosxr": "observed",
    "manual": "configured",
    "nautobot": "configured",
    "ndo": "configured",
    "netscaler": "observed",
    "nxos": "observed",
    "unifi": "configured",
    "vyos": "observed",
    "zia": "configured",
    "zpa": "configured",
}
UNCLASSIFIED_COLLECTOR_CLASS = "configured"

# Highest authority first.
DEFAULT_PRECEDENCE = ("observed", "configured", "derived")

# A label missing from this table uses DEFAULT_PRECEDENCE.
LABEL_PRECEDENCE: dict[str, tuple[str, ...]] = {
    "BridgeDomain": DEFAULT_PRECEDENCE,
    "Device": DEFAULT_PRECEDENCE,
    "IpAddress": DEFAULT_PRECEDENCE,
    "Port": DEFAULT_PRECEDENCE,
    "Prefix": DEFAULT_PRECEDENCE,
    "Site": DEFAULT_PRECEDENCE,
}

# The assertion pass writes the `_assert.<field>` keys after the upsert.
ASSERT_UPDATE = """
UNWIND $rows AS row
MATCH (n:Obj {uid: row.uid, collection_ts: $cts})
SET n += row.props
"""

CYCLE_ANCHOR_CHECK = """
UNWIND $rows AS row
MATCH (n:Obj) WHERE n.uid = row.uid AND n.collection_ts = $cts
  AND n.anchor IS NOT NULL AND n.anchor <> row.anchor AND coalesce(n.carried, false) = false
RETURN row.uid AS uid, n.anchor AS prior, row.anchor AS anchor
"""


def _check_cycle_anchors(write: Callable[..., list[dict[str, Any]]], batch: Batch, cts: int) -> None:
    """Raise CycleIdentityCollision when a node of `batch` has an `anchor` that
    differs from the one an earlier batch of this run wrote under the same uid.
    """
    rows = [
        {"uid": n.uid, "anchor": n.props["anchor"]} for n in batch.nodes if n.props.get("anchor") is not None
    ]
    for chunk in _chunks(rows):
        for rec in write(CYCLE_ANCHOR_CHECK, rows=chunk, cts=cts):
            raise CycleIdentityCollision(
                f"uid {rec['uid']!r} was written in this run with anchor={rec['prior']!r} and is "
                f"declared again with anchor={rec['anchor']!r}: one uid cannot name two objects"
            )


# --- two source rows on one source-local uid --------------------------------------------
#
# A collector mints the uid of these labels from names that are unique only
# within one device or one controller. When 2 source rows of one collector type
# write one of these uids in one run, one node holds 2 objects, with the
# properties of the second writer on top. Examples are 2 VyOS routers with the
# host name `edge` and 2 UniFi consoles with a site `default`. The set leaves
# out the labels that 2 sources share by design: Device through the identity
# registry, Port, Prefix and IpAddress in a declared routing domain,
# BridgeDomain, VrfInstance and Site.
SOURCE_LOCAL_LABELS = frozenset(
    {
        "FwRulebase",
        "FwRule",
        "Zone",
        "NatRulebase",
        "NatRule",
        "NetObject",
        "SvcObject",
        "PbrPolicy",
        "WanLink",
        "Rack",
    }
)


def rival_writers(label: str, collector: str, source: str, before: dict[str, Any]) -> list[str]:
    """The earlier writers of a node of a SOURCE_LOCAL_LABELS label, as
    `<collector>/<source>`. An earlier writer is another source row of the same
    collector type that wrote the uid in this run. The list is empty for any
    other label, for a node that this write created and for a carried copy.
    """
    if label not in SOURCE_LOCAL_LABELS or "collected_at" not in before or before.get("carried") is True:
        return []
    writers = [str(s) for s in before.get("_sources") or []]
    prior = [s for s in writers if s != source]
    if not prior:
        return []
    kinds: dict[str, str] = {}
    for key, entries in before.items():
        if key.startswith(ASSERT_PREFIX):
            for entry in entries or []:
                kind, row, _ = decode_assertion(str(entry))
                if kind:
                    kinds.setdefault(row, kind)
    kinds.setdefault(writers[0], collector_type(str(before.get("_scope") or "")))
    return [f"{kinds.get(s, '?')}/{s}" for s in prior if kinds.get(s, collector) == collector]


def rival_warnings(
    collector: str, source: str, found: dict[tuple[str, tuple[str, ...]], list[str]]
) -> list[str]:
    """One load warning per label and set of earlier writers. The warning has
    both writers and up to 5 of the uids."""
    out = []
    for (label, rivals), uids in sorted(found.items()):
        sample = ", ".join(uids[:5])
        out.append(
            f"{label}: {len(uids)} uid(s) that {collector}/{source} wrote were already written in this run "
            f"by {', '.join(rivals)}, so each is one node for two objects (e.g. {sample})"
        )
    return out


def encode_assertion(collector: str, source: str, value: Any) -> str:
    """One assertion as `<collector>/<source>=<json value>`.

    A collector type is a bare identifier. A source row name matches
    app/sources.py NAME_PATTERN (lowercase letters, digits, hyphens). Neither
    part of the head has a `/` or a `=`.
    """
    return f"{collector}/{source}={json.dumps(value, sort_keys=True, separators=(',', ':'))}"


def decode_assertion(entry: str) -> tuple[str, str, Any]:
    """The `(collector, source, value)` of an `encode_assertion` string.

    A head with no `/` is read as a source row whose collector type is unknown.
    """
    head, _, raw = entry.partition("=")
    collector, _, source = head.partition("/")
    if not source:
        collector, source = "", head
    try:
        return collector, source, json.loads(raw)
    except ValueError:
        return collector, source, raw


def effective_value(label: str, assertions: Sequence[str]) -> Any:
    """The value of the assertion whose collector class is first in the precedence
    of `label`. The collector type and the source name decide a tie."""
    order = LABEL_PRECEDENCE.get(label, DEFAULT_PRECEDENCE)

    def rank(entry: str) -> tuple[int, str, str]:
        collector, source, _ = decode_assertion(entry)
        cls = COLLECTOR_CLASSES.get(collector, UNCLASSIFIED_COLLECTOR_CLASS)
        return (order.index(cls) if cls in order else len(order), collector, source)

    return decode_assertion(min(assertions, key=rank))[2]


def _payload_of(before: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in before.items() if not k.startswith("_") and k not in _NOT_PAYLOAD}


def assertion_props(
    label: str, collector: str, source: str, before: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    """The properties to write on a node after a second source wrote it.

    `collector` is the collector type of the write (`collector_type` of the
    batch scope). `source` is the source row of the write. `before` holds the
    properties of the node before the `SET n += row.props` of this source.
    `incoming` holds the properties that this source asserted. The result has
    the `_assert.<field>` lists. For each field whose sources disagree, it also
    has the effective value of the field.
    """
    if before.get("carried") is True:
        return {}
    prior_sources = [s for s in (before.get("_sources") or []) if s != source]
    if not prior_sources:
        return {}

    payload = _payload_of(before)
    recorded = {k[len(ASSERT_PREFIX) :]: v for k, v in before.items() if k.startswith(ASSERT_PREFIX)}
    # The upsert appends to `_sources` in first-write order.
    first_collector = collector_type(str(before.get("_scope") or ""))
    first_source = prior_sources[0]

    def prior_for(field: str) -> list[str]:
        if field in recorded:
            return list(recorded[field] or [])
        if field in payload:
            return [encode_assertion(first_collector, first_source, payload[field])]
        return []

    props: dict[str, Any] = {}
    fields = set(payload) | {k for k, v in incoming.items() if v is not None}
    for field in sorted(fields):
        prior = prior_for(field)
        if field in incoming and incoming[field] is not None:
            mine = encode_assertion(collector, source, incoming[field])
            assertions = sorted({e for e in prior if decode_assertion(e)[1] != source} | {mine})
        else:
            assertions = sorted(set(prior))
        if not assertions:
            continue
        props[ASSERT_PREFIX + field] = assertions
        if len({e.partition("=")[2] for e in assertions}) > 1:
            props[field] = effective_value(label, assertions)
    return props


WRITE_RUN = """
MERGE (r:Obj:CollectionRun:Meta {uid: $uid})
SET r += $props, r._scope = 'meta:runs', r.snapshot_ts = $cts,
    r._first_seen = coalesce(r._first_seen, $ts), r._last_seen = $ts
"""
# A meta node with `collection_ts` would match the label-less object queries.


def section_props(sections: dict[str, SectionOutcome]) -> list[str]:
    """`Batch.sections` as a CollectionRun property."""
    return [f"{name}={outcome.status}" for name, outcome in sorted(sections.items())]


def _chunks(rows: list[Any], size: int = CHUNK):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def _group_nodes(nodes: list[NodeRecord]) -> dict[str, list[NodeRecord]]:
    grouped: dict[str, list[NodeRecord]] = defaultdict(list)
    for n in nodes:
        grouped[n.label].append(n)
    return grouped


def _group_rels(rels: list[RelRecord]) -> dict[tuple[str, tuple[str, ...]], list[RelRecord]]:
    grouped: dict[tuple[str, tuple[str, ...]], list[RelRecord]] = defaultdict(list)
    for r in rels:
        grouped[(r.rel_type, tuple(sorted(r.key)))].append(r)
    return grouped


# --- loader -----------------------------------------------------------------------------


def load(
    session: SessionLike,
    batch: Batch,
    *,
    run_id: str | None = None,
    ts_ms: int | None = None,
    collection_ts: int | None = None,
) -> RunManifest:
    """Load one collector batch into the cycle `collection_ts`.

    `collection_ts` is the version key of the cycle of this load. The
    orchestration passes it. Without it, the time of the load is the key, and a
    standalone load (fixtures, tests) is a cycle of one source. Returns the
    manifest. The manifest is also written as a CollectionRun node.
    """
    batch.validate_registry()

    ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    cts = collection_ts if collection_ts is not None else ts
    rid = run_id or f"{batch.source}-{ts}-{uuid.uuid4().hex[:8]}"
    manifest = RunManifest(
        run_id=rid,
        source=batch.source,
        scope=batch.scope,
        started=_iso(ts),
        sections=batch.sections,
    )
    common = {"ts": ts, "cts": cts, "run_id": rid, "scope": batch.scope, "source": batch.source}
    collector = collector_type(batch.scope)

    def write(query: str, **params: Any) -> list[dict[str, Any]]:
        """`execute_write` retries a statement on Neo.TransientError."""
        return session.execute_write(lambda tx: tx.run(query, **params).data())

    _check_cycle_anchors(write, batch, cts)
    # (label, earlier writers) -> uids, for nodes of a source-local label that
    # another source row of this collector type already wrote in this run
    rivals: dict[tuple[str, tuple[str, ...]], list[str]] = defaultdict(list)

    # Nodes are written per label. Cypher takes no label as a parameter.
    for label, records in _group_nodes(batch.nodes).items():
        q = node_upsert_query(label)
        for chunk in _chunks(records):
            # `graph_address_props` (core/ipenc.py) adds the address keys of the `ip`
            # or the `cidr` of the node. The filters compare ranges on these keys.
            rows = [{"uid": r.uid, "props": r.props | graph_address_props(label, r.props)} for r in chunk]
            incoming = {row["uid"]: row["props"] for row in rows}
            assert_rows: list[dict[str, Any]] = []
            for rec in write(q, rows=rows, **common):
                manifest.nodes_upserted += 1
                before = rec["before"] or {}
                # The `before` of a node that the MERGE created holds only the MERGE key.
                if "collected_at" not in before:
                    manifest.nodes_created += 1
                    continue
                earlier = rival_writers(label, collector, batch.source, before)
                if earlier:
                    rivals[(label, tuple(earlier))].append(rec["uid"])
                props = assertion_props(
                    label, collector, batch.source, before, incoming.get(rec["uid"]) or {}
                )
                if props:
                    assert_rows.append({"uid": rec["uid"], "props": props})
            for assert_chunk in _chunks(assert_rows):
                write(ASSERT_UPDATE, rows=assert_chunk, **common)
    manifest.warnings.extend(rival_warnings(collector, batch.source, rivals))

    # Relationships are written per (type, key signature). The ends match on :Obj(uid)
    # and `collection_ts`. The node phase binds `records` and `rows` to other types.
    for (rel_type, key_fields), rel_records in _group_rels(batch.rels).items():
        q = rel_upsert_query(rel_type, key_fields)
        for chunk in _chunks(rel_records):
            rel_rows = [
                {"start": r.start_uid, "end": r.end_uid, "key": r.key, "props": r.props} for r in chunk
            ]
            result = write(q, rows=rel_rows, **common)
            returned = {(rec["start"], rec["end"]) for rec in result}
            for rec in result:
                manifest.rels_upserted += 1
                # `before` holds only `collected_at`. It is null on a relationship
                # that this MERGE created (`rel_upsert_query`).
                if (rec["before"] or {}).get("collected_at") is None:
                    manifest.rels_created += 1
            # MATCH skips a row whose end is missing. The manifest counts these rows and
            # has an error for them.
            missing = [(r["start"], r["end"]) for r in rel_rows if (r["start"], r["end"]) not in returned]
            if missing:
                manifest.rels_dropped_missing_endpoint += len(missing)
                sample = ", ".join(f"{a}->{b}" for a, b in missing[:5])
                manifest.errors.append(
                    f"{rel_type}: {len(missing)} rel(s) dropped, endpoint missing (e.g. {sample})"
                )

    manifest.finished_ms = int(time.time() * 1000) if ts_ms is None else ts
    manifest.finished = _iso(manifest.finished_ms)

    write(
        WRITE_RUN,
        uid=f"run:{rid}",
        ts=ts,
        cts=cts,
        # The side store is written after this load returns.
        props=manifest.model_dump(exclude={"errors", "sections", "tables", "warnings"})
        | {"errors": manifest.errors[:20], "sections": section_props(manifest.sections)},
    )
    return manifest


def _iso(ts_ms: int) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(ts_ms / 1000, tz=UTC).isoformat(timespec="seconds")
