"""Check Point policy envelopes read back from the side store.

The Check Point collector stores the full API envelope of every rule, layer,
package and policy object as a row of the `checkpoint_envelopes` side-store
table, and the node keeps only the envelope's SHA-256 as
`checkpoint_envelope_sha`. A graph load puts the envelope back on the node as
`checkpoint_envelope`, the property the strict Check Point readers take it
from (checkpoint_graph.py, overlay.py), for the run the load is pinned to.

The rows are found through the files the pinned manifest selects for the
table (`ribsource.snapshot_evidence`). For a carried source, these are the
files of the run that collected the source. A row is taken only when its
envelope hashes to the digest the node holds. When any envelope the graph asks
for is not found that way, none is put back.

A node that already holds `checkpoint_envelope` (a run collected before the
table existed, a fixture) is left as it is.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .read import MaterializedTable

logger = logging.getLogger(__name__)

TABLE = "checkpoint_envelopes"
SHA_PROPERTY = "checkpoint_envelope_sha"
ENVELOPE_PROPERTY = "checkpoint_envelope"


def envelope_sha(envelope: str) -> str:
    """The digest that a node holds for its envelope text."""
    return hashlib.sha256(envelope.encode()).hexdigest()


def _sql_str(value: str) -> str:
    """`value` as a SQL string literal. DuckDB binds no parameter into a file list."""
    return "'" + value.replace("'", "''") + "'"


def read_envelopes(snapshot: Any, wanted: Mapping[str, str]) -> dict[str, str]:
    """The envelope text per uid, for every uid of `wanted` (digest per uid)
    whose row in the files the snapshot selects for the table holds an envelope
    that hashes to that digest. The result is empty when the snapshot has no
    manifest, the manifest selects no file, or the side store cannot be read."""
    if not wanted:
        return {}
    record = getattr(snapshot, "manifest", None)
    if record is None:
        return {}
    from hst.core.ribsource import snapshot_evidence

    evidence = snapshot_evidence(snapshot.settings, snapshot.cts, manifest=record, table=TABLE)
    files = [] if evidence is None else evidence.files
    if not files:
        return {}
    try:
        # sidestore raises RuntimeError when pyarrow is missing.
        from hst.core import sidestore
    except (ImportError, RuntimeError):
        return {}
    try:
        con = sidestore.connect_reader(Path(snapshot.settings.sidestore_dir))
    except ImportError:
        return {}
    try:
        listed = ", ".join(_sql_str(path.as_posix()) for path in files)
        rows = con.execute(
            "SELECT uid, envelope_sha, envelope "  # noqa: S608 - paths off disk
            f"FROM read_parquet([{listed}], union_by_name=true) WHERE list_contains(?, envelope_sha)",
            [sorted(set(wanted.values()))],
        ).fetchall()
    finally:
        con.close()
    found: dict[str, str] = {}
    for uid, sha, envelope in rows:
        if wanted.get(uid) == sha and isinstance(envelope, str) and envelope_sha(envelope) == sha:
            found[uid] = envelope
    return found


def hydrate(nodes: MaterializedTable, snapshot: Any) -> MaterializedTable:
    """`nodes` with `checkpoint_envelope` put back on every node that holds
    only its digest, or `nodes` unchanged when none does or when any of them
    is not found (logged)."""
    wanted: dict[str, str] = {}
    for row in nodes.rows:
        props = row.get("props")
        if not isinstance(props, Mapping) or ENVELOPE_PROPERTY in props:
            continue
        sha = props.get(SHA_PROPERTY)
        if isinstance(sha, str) and isinstance(row.get("id"), str):
            wanted[row["id"]] = sha
    if not wanted:
        return nodes
    try:
        found = read_envelopes(snapshot, wanted)
    except Exception as exc:  # a side-store failure leaves the policy unqualified
        logger.warning("checkpoint envelopes: side-store read failed: %s: %s", type(exc).__name__, exc)
        return nodes
    if len(found) != len(wanted):
        logger.warning(
            "checkpoint envelopes: %d of %d envelopes of snapshot %s are not in the side store; "
            "the Check Point policy reads as unqualified",
            len(wanted) - len(found),
            len(wanted),
            getattr(snapshot, "cts", None),
        )
        return nodes
    rows = tuple(
        {**row, "props": {**row["props"], ENVELOPE_PROPERTY: found[row["id"]]}}
        if row.get("id") in found
        else row
        for row in nodes.rows
    )
    return dataclasses.replace(nodes, rows=rows)
