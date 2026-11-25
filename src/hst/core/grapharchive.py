"""Encrypted, chunk-authenticated archives of a published graph state."""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import uuid
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.fernet import Fernet, InvalidToken

from .config import Settings

MAGIC = b"STRATA-GRAPH-ARCHIVE\x00\x01"
FORMAT_VERSION = 1
GRAPH_SCHEMA_VERSION = 1
CHUNK_RECORDS = 2_000
MAX_FRAME_BYTES = 64 * 1024 * 1024
_FRAME = struct.Struct(">I")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_NODES = (
    "CALL { "
    "MATCH (n:Obj {collection_ts: $snap}) RETURN n "
    "UNION ALL "
    "MATCH (:Obj {collection_ts: $snap})-[r]-(n:Obj) "
    "WHERE n.collection_ts IS NULL AND (r.collection_ts = $snap OR r.collection_ts IS NULL) "
    "RETURN DISTINCT n "
    "} "
    "RETURN n.uid AS uid, labels(n) AS labels, properties(n) AS props"
)
_RELS = (
    "CALL { "
    "MATCH (a:Obj {collection_ts: $snap})-[r]->(b:Obj) "
    "WHERE r.collection_ts = $snap OR r.collection_ts IS NULL RETURN a, r, b "
    "UNION ALL "
    "MATCH (a:Obj)-[r]->(b:Obj {collection_ts: $snap}) "
    "WHERE (r.collection_ts = $snap OR r.collection_ts IS NULL) "
    "AND (a.collection_ts IS NULL OR a.collection_ts <> $snap) RETURN a, r, b "
    "} "
    "RETURN type(r) AS type, a.uid AS start, b.uid AS end, "
    "coalesce(a.collection_ts = $snap, false) AS start_versioned, "
    "coalesce(b.collection_ts = $snap, false) AS end_versioned, "
    "(a.collection_ts = $snap OR a.collection_ts IS NULL) AND "
    "(b.collection_ts = $snap OR b.collection_ts IS NULL) AS snapshot_valid, "
    "properties(r) AS props"
)


class ArchiveError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    # An unsupported Neo4j value raises.
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _rows(result: Any) -> Iterable[Mapping[str, Any]]:
    return result if isinstance(result, Iterable) else result.data()


def path_for(settings: Settings, snapshot_key: int) -> Path:
    return settings.graph_archives_dir / f"{snapshot_key}.graph.enc"


def _write_frame(fh: BinaryIO, token: bytes) -> None:
    fh.write(_FRAME.pack(len(token)))
    fh.write(token)


def _validate_record(record: Any, snapshot_key: int) -> str:
    if not isinstance(record, dict) or not isinstance(record.get("props"), dict):
        raise ArchiveError("graph archive contains a malformed record")
    kind = record.get("kind")
    if kind == "node":
        labels = record.get("labels")
        if (
            not isinstance(record.get("uid"), str)
            or not isinstance(labels, list)
            or not labels
            or any(not isinstance(label, str) or not _IDENT.fullmatch(label) for label in labels)
        ):
            raise ArchiveError("graph archive contains an invalid node record")
        if "Obj" not in labels or record["props"].get("uid") != record["uid"]:
            raise ArchiveError("graph archive node identity is inconsistent")
        versioned = record.get("versioned")
        if not isinstance(versioned, bool):
            raise ArchiveError("graph archive node has no versioning marker")
    elif kind == "rel":
        if (
            not isinstance(record.get("start"), str)
            or not isinstance(record.get("end"), str)
            or not isinstance(record.get("type"), str)
            or not isinstance(record.get("start_versioned"), bool)
            or not isinstance(record.get("end_versioned"), bool)
            or not isinstance(record.get("versioned"), bool)
            or not _IDENT.fullmatch(record["type"])
        ):
            raise ArchiveError("graph archive contains an invalid relationship record")
    else:
        raise ArchiveError("graph archive contains an unknown record kind")
    if kind == "node" and not record["versioned"]:
        if "collection_ts" in record["props"]:
            raise ArchiveError("unversioned graph archive node has a collection timestamp")
    elif kind == "rel" and not record["versioned"]:
        if "collection_ts" in record["props"]:
            raise ArchiveError("unversioned graph archive relationship has a collection timestamp")
    elif record["props"].get("collection_ts") != snapshot_key:
        raise ArchiveError("graph archive record belongs to a different snapshot")
    return kind


def write(
    session: Any,
    settings: Settings,
    snapshot_key: int,
    key: str,
    *,
    normalization_context: Mapping[str, Any] | None = None,
    chunk_records: int = CHUNK_RECORDS,
) -> dict[str, Any]:
    """Write the graph at ``snapshot_key`` to a new archive file.

    The file is written under a temporary name and renamed when it is complete."""
    directory = settings.graph_archives_dir
    directory.mkdir(parents=True, exist_ok=True)
    path = path_for(settings, snapshot_key)
    if path.exists():
        raise FileExistsError(f"graph archive already exists: {path}")
    tmp = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    archive_id = f"{snapshot_key}:{uuid.uuid4().hex}"
    cipher = Fernet(key.encode())
    digest = hashlib.sha256()
    counts = {"nodes": 0, "rels": 0}
    sequence = 0
    mtu_versions: set[str] = set()

    def records(tx: Any) -> Iterator[dict[str, Any]]:
        for row in _rows(tx.run(_NODES, snap=snapshot_key)):
            counts["nodes"] += 1
            if "MtuObservation" in row["labels"]:
                mtu_versions.add(str(row["props"].get("normalization_version", "unknown")))
            yield {
                "kind": "node",
                "uid": row["uid"],
                "labels": sorted(row["labels"]),
                "props": dict(row["props"]),
                "versioned": row["props"].get("collection_ts") == snapshot_key,
            }
        for row in _rows(tx.run(_RELS, snap=snapshot_key)):
            if row.get("snapshot_valid") is not True:
                raise ArchiveError("current graph relationship reaches an endpoint from a different snapshot")
            counts["rels"] += 1
            yield {
                "kind": "rel",
                "type": row["type"],
                "start": row["start"],
                "end": row["end"],
                "start_versioned": row["start_versioned"],
                "end_versioned": row["end_versioned"],
                "props": dict(row["props"]),
                "versioned": row["props"].get("collection_ts") == snapshot_key,
            }

    try:
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as fh:
            fh.write(MAGIC)
            held: list[dict[str, Any]] = []

            def flush() -> None:
                nonlocal sequence, held
                if not held:
                    return
                body = {"archive_id": archive_id, "sequence": sequence, "records": held}
                raw = _canonical(body)
                digest.update(raw)
                _write_frame(fh, cipher.encrypt(raw))
                sequence += 1
                held = []

            def consume(tx: Any) -> None:
                nonlocal sequence, held, digest, counts
                mtu_versions.clear()
                # Each attempt of the read callback starts from an empty file, digest and count.
                fh.seek(len(MAGIC))
                fh.truncate()
                held = []
                sequence = 0
                digest = hashlib.sha256()
                counts = {"nodes": 0, "rels": 0}
                for record in records(tx):
                    held.append(record)
                    if len(held) >= max(1, chunk_records):
                        flush()
                flush()

            session.execute_read(consume)
            final = {
                "archive_id": archive_id,
                "sequence": sequence,
                "final": True,
                "chunks": sequence,
                "counts": counts,
                "records_sha256": digest.hexdigest(),
                "snapshot_key": snapshot_key,
                "format_version": FORMAT_VERSION,
                "graph_schema_version": GRAPH_SCHEMA_VERSION,
            }
            _write_frame(fh, cipher.encrypt(_canonical(final)))
            fh.flush()
            os.fsync(fh.fileno())
        tmp.replace(path)
        with suppress(OSError):
            _fsync(directory)
    except Exception:
        with suppress(OSError):
            tmp.unlink()
        raise
    ciphertext_sha256, size = _file_facts(path)
    context = dict(normalization_context or {})
    if mtu_versions:
        context["mtu_normalization_versions"] = sorted(mtu_versions)
    return {
        "path": path.resolve().relative_to(settings.hst_data_dir.resolve()).as_posix(),
        "sha256": ciphertext_sha256,
        "bytes": size,
        "snapshot_key": snapshot_key,
        "format_version": FORMAT_VERSION,
        "graph_schema_version": GRAPH_SCHEMA_VERSION,
        "chunks": sequence,
        "nodes": counts["nodes"],
        "rels": counts["rels"],
        "normalization_context": context,
        "normalization_context_sha256": hashlib.sha256(_canonical(context)).hexdigest(),
    }


def _file_facts(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while block := fh.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def _fsync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _frames(path: Path, key: str, expected: Mapping[str, Any]) -> Iterator[list[dict[str, Any]]]:
    actual_sha, actual_size = _file_facts(path)
    if (actual_sha, actual_size) != (expected["sha256"], expected["bytes"]):
        raise ArchiveError("graph archive ciphertext digest or size does not match its manifest")
    cipher = Fernet(key.encode())
    archive_id: str | None = None
    sequence = 0
    digest = hashlib.sha256()
    counts = {"nodes": 0, "rels": 0}
    final_seen = False
    try:
        with path.open("rb") as fh:
            if fh.read(len(MAGIC)) != MAGIC:
                raise ArchiveError("not a HST graph archive")
            while raw_len := fh.read(_FRAME.size):
                if len(raw_len) != _FRAME.size:
                    raise ArchiveError("truncated graph archive frame length")
                length = _FRAME.unpack(raw_len)[0]
                if not 0 < length <= MAX_FRAME_BYTES:
                    raise ArchiveError("invalid graph archive frame length")
                token = fh.read(length)
                if len(token) != length:
                    raise ArchiveError("truncated graph archive frame")
                raw = cipher.decrypt(token)
                body = json.loads(raw)
                if body.get("sequence") != sequence:
                    raise ArchiveError("graph archive frames are missing, duplicated, or reordered")
                if archive_id is None:
                    archive_id = body.get("archive_id")
                if not archive_id or body.get("archive_id") != archive_id:
                    raise ArchiveError("graph archive frame identity mismatch")
                if body.get("final"):
                    final_seen = True
                    if fh.read(1):
                        raise ArchiveError("data follows the graph archive final frame")
                    required = {
                        "chunks": sequence,
                        "counts": counts,
                        "records_sha256": digest.hexdigest(),
                        "snapshot_key": expected["snapshot_key"],
                        "format_version": expected["format_version"],
                        "graph_schema_version": expected["graph_schema_version"],
                    }
                    if any(body.get(k) != v for k, v in required.items()):
                        raise ArchiveError("graph archive final authentication record does not match")
                    break
                records = body.get("records")
                if not isinstance(records, list):
                    raise ArchiveError("graph archive data frame has no record list")
                digest.update(raw)
                for record in records:
                    kind = _validate_record(record, expected["snapshot_key"])
                    counts["nodes" if kind == "node" else "rels"] += 1
                sequence += 1
                yield records
    except (InvalidToken, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ArchiveError("graph archive authentication or structure is invalid") from exc
    if not final_seen:
        raise ArchiveError("graph archive has no authenticated final frame")
    actual_counts = (sequence, counts["nodes"], counts["rels"])
    expected_counts = (expected["chunks"], expected["nodes"], expected["rels"])
    if actual_counts != expected_counts:
        raise ArchiveError("graph archive counts do not match its manifest")


def verify(settings: Settings, entry: Any, key: str) -> None:
    expected = entry.model_dump() if hasattr(entry, "model_dump") else dict(entry)
    for _ in _frames(_resolved_path(settings, expected["path"]), key, expected):
        pass


def reseal(settings: Settings, entry: Any, key: str, new_key: str, target: Path) -> tuple[str, int]:
    """Copy the archive of `entry` to the new file `target`, each frame
    decrypted under `key` and encrypted under `new_key`. Return the SHA-256 and
    the size of `target`.

    The bytes read must have the digest and the size of `entry`."""
    expected = entry.model_dump() if hasattr(entry, "model_dump") else dict(entry)
    old, new = Fernet(key.encode()), Fernet(new_key.encode())
    digest = hashlib.sha256()
    size = 0
    try:
        with (
            _resolved_path(settings, expected["path"]).open("rb") as source,
            os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as fh,
        ):
            magic = source.read(len(MAGIC))
            if magic != MAGIC:
                raise ArchiveError("not a HST graph archive")
            digest.update(magic)
            size += len(magic)
            fh.write(MAGIC)
            while raw_len := source.read(_FRAME.size):
                if len(raw_len) != _FRAME.size:
                    raise ArchiveError("truncated graph archive frame length")
                length = _FRAME.unpack(raw_len)[0]
                if not 0 < length <= MAX_FRAME_BYTES:
                    raise ArchiveError("invalid graph archive frame length")
                token = source.read(length)
                if len(token) != length:
                    raise ArchiveError("truncated graph archive frame")
                digest.update(raw_len)
                digest.update(token)
                size += len(raw_len) + length
                _write_frame(fh, new.encrypt(old.decrypt(token)))
    except InvalidToken as exc:
        raise ArchiveError("graph archive authentication or structure is invalid") from exc
    if (digest.hexdigest(), size) != (expected["sha256"], expected["bytes"]):
        raise ArchiveError("graph archive ciphertext digest or size does not match its manifest")
    return _file_facts(target)


def _resolved_path(settings: Settings, relative: str) -> Path:
    path = (settings.hst_data_dir / relative).resolve()
    try:
        path.relative_to(settings.graph_archives_dir.resolve())
    except ValueError as exc:
        raise ArchiveError("graph archive path escapes the archive directory") from exc
    return path


def restore(
    session: Any,
    settings: Settings,
    entry: Any,
    key: str,
    target_collection_ts: int,
) -> tuple[int, int]:
    """Restore the archive of `entry`. The versioned records get
    `target_collection_ts` as their `collection_ts`.

    Return the counts of the versioned nodes and relationships."""
    expected = entry.model_dump() if hasattr(entry, "model_dump") else dict(entry)
    archive_path = _resolved_path(settings, expected["path"])
    # The whole archive is verified before the first write.
    for _ in _frames(archive_path, key, expected):
        pass
    node_count = rel_count = 0
    for records in _frames(archive_path, key, expected):
        nodes = [r for r in records if r["kind"] == "node"]
        rels = [r for r in records if r["kind"] == "rel"]
        node_groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
        for record in nodes:
            labels = tuple(record["labels"])
            if not labels or any(not _IDENT.fullmatch(label) for label in labels):
                raise ArchiveError("graph archive contains an invalid node label")
            props = dict(record["props"])
            if record["versioned"]:
                props["collection_ts"] = target_collection_ts
            node_groups[labels].append(props)
        for labels, rows in node_groups.items():
            clause = ":" + ":".join(labels)
            result = session.execute_write(
                lambda tx, q=f"UNWIND $rows AS row CREATE (n{clause}) SET n = row", batch=rows: tx.run(
                    q + " RETURN count(n) AS created", rows=batch
                ).data()
            )
            _require_created(result, len(rows), "nodes")
            node_count += sum(1 for row in nodes if row["versioned"] and tuple(row["labels"]) == labels)
        rel_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in rels:
            type_ = record["type"]
            if not _IDENT.fullmatch(type_):
                raise ArchiveError("graph archive contains an invalid relationship type")
            props = dict(record["props"])
            if record["versioned"]:
                props["collection_ts"] = target_collection_ts
            rel_groups[type_].append(
                {
                    "start": record["start"],
                    "end": record["end"],
                    "start_versioned": record["start_versioned"],
                    "end_versioned": record["end_versioned"],
                    "props": props,
                }
            )
        # A versioned end matches the node with its uid and `collection_ts = $cts`
        # (constraint obj_uid_cts). An unversioned end matches the :Meta node with
        # its uid and no `collection_ts`.
        for type_, rows in rel_groups.items():
            query = (
                "UNWIND $rows AS row "
                "CALL { WITH row CALL { "
                "WITH row WITH row WHERE row.start_versioned "
                "MATCH (a:Obj {uid: row.start, collection_ts: $cts}) RETURN a "
                "UNION WITH row WITH row WHERE NOT row.start_versioned "
                "MATCH (a:Obj:Meta {uid: row.start}) WHERE a.collection_ts IS NULL RETURN a "
                "} RETURN collect(a) AS starts } "
                "CALL { WITH row CALL { "
                "WITH row WITH row WHERE row.end_versioned "
                "MATCH (b:Obj {uid: row.end, collection_ts: $cts}) RETURN b "
                "UNION WITH row WITH row WHERE NOT row.end_versioned "
                "MATCH (b:Obj:Meta {uid: row.end}) WHERE b.collection_ts IS NULL RETURN b "
                "} RETURN collect(b) AS ends } "
                "WITH collect({row: row, starts: starts, ends: ends}) AS matches "
                "WHERE all(x IN matches WHERE size(x.starts) = 1 AND size(x.ends) = 1) "
                "UNWIND matches AS x WITH x.row AS row, x.starts[0] AS a, x.ends[0] AS b "
                f"CREATE (a)-[r:{type_}]->(b) SET r = row.props"
            )
            result = session.execute_write(
                lambda tx, q=query, rs=rows: tx.run(
                    q + " RETURN count(r) AS created", rows=rs, cts=target_collection_ts
                ).data()
            )
            _require_created(result, len(rows), "relationships")
            rel_count += sum(1 for row in rels if row["versioned"] and row["type"] == type_)
    return node_count, rel_count


def _require_created(result: Any, expected: int, kind: str) -> None:
    try:
        created = result[0]["created"]
    except (IndexError, KeyError, TypeError) as exc:
        raise ArchiveError(f"graph archive restore did not report created {kind}") from exc
    if created != expected:
        raise ArchiveError(f"graph archive restore created {created} {kind}; expected exactly {expected}")
