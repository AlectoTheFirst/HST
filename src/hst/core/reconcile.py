"""Reconciliation of the committed runs, the manifests and the files on disk,
and the recovery set of a backup."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from hst.map import store as map_store

from . import manifest as manifestmod
from . import rawstore
from .config import Settings

# The schema version of the recovery set. It is independent of the manifest
# schema version.
SET_SCHEMA_VERSION = 2
READABLE_SET_SCHEMA_VERSIONS = (1, SET_SCHEMA_VERSION)

QUARANTINE_DIR = "quarantine"
DIR_MODE = 0o700
FILE_MODE = 0o600

# The file names of the Postgres dump of a set. pg_dump writes `POSTGRES_DUMP`,
# and the set stores `SEALED_POSTGRES_DUMP`.
POSTGRES_DUMP = "postgres.dump"
SEALED_POSTGRES_DUMP = "postgres.dump.enc"
_DUMP_PIECE_BYTES = 1 << 20

_RAW_SUFFIX = rawstore.SUFFIX
_META_SUFFIX = rawstore.META_SUFFIX
_PARQUET_SUFFIX = ".parquet"


def _stamp() -> str:
    """Return a quarantine directory name, the current UTC time as `YYYYMMDDTHHMMSSZ`."""
    return datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")


# --- the recovery set --------------------------------------------------------------------


class RecoveryObject(BaseModel):
    """One immutable object required to restore a recovery set.

    ``key`` is unique to the set, or ``version_id`` pins a retained object
    version. ``restore_path`` is the path of a data object under
    ``HST_DATA_DIR``. Database and configuration objects have no
    ``restore_path``. The digest and length are checked before a set is
    published and again after its data objects are restored.
    """

    role: str
    key: str
    sha256: str
    bytes: int
    restore_path: str = ""
    version_id: str = ""


class RecoverySet(BaseModel):
    """The record of one completed backup. A restore is checked against it.

    Schema 2 lists every required object with an immutable per-set key (or a
    retained version id), a digest and a length. The snapshot is selected from
    the committed pointer under the cycle lock. The Postgres dump is taken after
    that selection, and ``boundary`` states this order. The record is published
    only after every referenced object is uploaded and checked. A schema-1 set
    is readable.
    """

    schema_version: int = SET_SCHEMA_VERSION
    created: str = ""
    estate: str = ""
    # The object key in the bucket of the Postgres dump of this set.
    postgres_dump_key: str = ""
    # The committed snapshot at the head of the manifest chain, and the digest of
    # its manifest file. `evidence check` recomputes the digest from disk.
    snapshot_key: int
    manifest_sha256: str
    chain_index: int | None = None
    # Schema-1 fields.
    data_prefix: str = ""
    data_object_list_sha256: str = ""
    # Maps a role to the name of the Kubernetes Secret that holds it, for example
    # {"operatorKey": "hst-secrets", "objectStore": "hst-backup-s3"}.
    secrets: dict[str, str] = Field(default_factory=dict)
    # The names of the settings that a restore needs. The values are not stored.
    settings: list[str] = Field(default_factory=list)
    # Only a schema-2 record has `objects` and `boundary`.
    objects: list[RecoveryObject] = Field(default_factory=list)
    boundary: str = ""

    @model_validator(mode="before")
    @classmethod
    def infer_omitted_legacy_version(cls, value: Any) -> Any:
        """A record with no `schema_version`, no `objects`, no `boundary` and a
        `data_prefix` or a `data_object_list_sha256` is schema 1."""
        if isinstance(value, Mapping) and "schema_version" not in value:
            held = dict(value)
            if (
                not held.get("objects")
                and not held.get("boundary")
                and (held.get("data_prefix") or held.get("data_object_list_sha256"))
            ):
                held["schema_version"] = 1
            return held
        return value

    @property
    def label(self) -> str:
        return f"snapshot {self.snapshot_key}" + (f" of {self.created}" if self.created else "")


@dataclass(frozen=True)
class MaterializedRecovery:
    """The verified restore inputs. `configuration`, `operator_key` and `dek` are
    plaintext secrets and are held in memory only."""

    data_dir: Path
    postgres_dump: Path
    configuration: bytes
    operator_key: bytes
    dek: str


def _set_relative_key(obj: RecoveryObject) -> Path:
    parts = Path(obj.key).parts
    try:
        marker = parts.index("sets")
        relative = Path(*parts[marker + 2 :])
    except (ValueError, IndexError):
        raise ValueError(f"object {obj.key!r} is not beneath an immutable set key") from None
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"object {obj.key!r} has an unsafe immutable key")
    return relative


def materialize_recovery_bundle(
    recovery_set: RecoverySet,
    object_root: Path,
    target: Path,
    recovery_key: str,
) -> MaterializedRecovery:
    """Verify every downloaded object and cryptographic dependency, then publish a restore tree.

    ``object_root`` is the downloaded ``sets/<id>`` directory. No target path is
    created until all object bytes, envelopes, wrapped DEK and graph archive have
    authenticated successfully. The Postgres dump is decrypted under
    ``recovery_key`` to ``.recovery/postgres.dump`` in the restore tree.
    """
    from hst.app import crypto
    from hst.core import grapharchive

    if recovery_set.schema_version < 2:
        raise ValueError("only immutable schema-2 recovery sets can be materialized")
    by_role: dict[str, list[tuple[RecoveryObject, Path]]] = {}
    object_keys: set[Path] = set()
    restore_paths: set[str] = set()
    for obj in recovery_set.objects:
        relative_key = _set_relative_key(obj)
        if relative_key in object_keys:
            raise ValueError(f"duplicate recovery object key: {obj.key}")
        object_keys.add(relative_key)
        if obj.restore_path:
            relative = Path(obj.restore_path)
            if relative.is_absolute() or ".." in relative.parts or str(relative) in {"", "."}:
                raise ValueError(f"object {obj.key!r} has unsafe restore path")
            if relative.parts[0] == ".recovery" or relative.as_posix() in restore_paths:
                raise ValueError(f"duplicate or reserved recovery restore path: {obj.restore_path}")
            restore_paths.add(relative.as_posix())
        source = (object_root / _set_relative_key(obj)).resolve()
        try:
            source.relative_to(object_root.resolve())
        except ValueError as exc:
            raise ValueError(f"object {obj.key!r} escapes the downloaded set") from exc
        if not source.is_file():
            raise FileNotFoundError(f"recovery object is absent: {obj.key}")
        if manifestmod.file_facts(source) != (obj.sha256, obj.bytes):
            raise ValueError(f"recovery object digest/size mismatch: {obj.key}")
        by_role.setdefault(obj.role, []).append((obj, source))
    for role in ("postgres", "manifest", "graph-archive", "wrapped-key", "configuration", "operator-key"):
        if not by_role.get(role):
            raise ValueError(f"the recovery set has no immutable {role} object")
    for role in ("postgres", "wrapped-key", "configuration", "operator-key"):
        if len(by_role[role]) != 1:
            raise ValueError(f"the recovery set has ambiguous {role} objects")

    operator_key = crypto.decrypt(recovery_key, by_role["operator-key"][0][1].read_bytes())
    configuration = crypto.decrypt(recovery_key, by_role["configuration"][0][1].read_bytes())
    dek = crypto.unwrap_dek(by_role["wrapped-key"][0][1].read_bytes(), operator_key)
    heads = [
        obj
        for obj, _ in by_role["manifest"]
        if obj.restore_path == f"manifests/{recovery_set.snapshot_key}.json"
    ]
    if len(heads) != 1:
        raise ValueError("the recovery set must identify exactly one head manifest")
    manifest_obj = heads[0]
    if manifest_obj.sha256 != recovery_set.manifest_sha256:
        raise ValueError("head manifest digest differs from the recovery set")

    verify_root = object_root / "data"
    verify_settings = Settings(_env_file=None, hst_data_dir=verify_root)  # type: ignore[call-arg]
    head = manifestmod.read(verify_settings, recovery_set.snapshot_key)
    if head.graph_archive is None:
        raise ValueError("head manifest has no graph archive")
    grapharchive.verify(verify_settings, head.graph_archive, dek)
    evidence = verify_evidence(verify_settings, recovery_set.snapshot_key)
    if not evidence.ok:
        raise ValueError("recovery evidence does not verify: " + "; ".join(evidence.problems))

    if target.exists():
        raise FileExistsError(f"recovery target already exists: {target}")
    partial = target.with_name(target.name + f".{os.getpid()}.partial")
    _private_dir(partial, partial)
    try:
        for obj, source in ((obj, source) for items in by_role.values() for obj, source in items):
            if obj.role == "postgres":
                continue
            if obj.restore_path:
                relative = Path(obj.restore_path)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"object {obj.key!r} has unsafe restore path")
                destination = partial / relative
            else:
                destination = partial / ".recovery" / _set_relative_key(obj)
            _private_dir(destination.parent, partial)
            shutil.copyfile(source, destination)
            destination.chmod(FILE_MODE)
            if manifestmod.file_facts(destination) != (obj.sha256, obj.bytes):
                raise ValueError(f"recovery object changed during materialization: {obj.key}")
        _private_dir(partial / ".recovery", partial)
        _open_postgres_dump(by_role["postgres"][0][1], partial / ".recovery" / POSTGRES_DUMP, recovery_key)
        partial.replace(target)
    except Exception:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    postgres = target / ".recovery" / POSTGRES_DUMP
    return MaterializedRecovery(target, postgres, configuration, operator_key, dek)


def seal_postgres_dump(root: Path, recovery_key: str) -> Path:
    """Encrypt ``root/postgres.dump`` under ``recovery_key`` and delete the plain dump.

    The sealed file ``root/postgres.dump.enc`` is one Fernet token, written a
    piece at a time (``crypto.TokenWriter``). Returns its path.
    """
    from hst.app import crypto

    plain = root / POSTGRES_DUMP
    sealed = root / SEALED_POSTGRES_DUMP
    with plain.open("rb") as source:
        fd = os.open(sealed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        try:
            with os.fdopen(fd, "wb") as fh:
                token = crypto.TokenWriter(recovery_key, fh)
                while piece := source.read(_DUMP_PIECE_BYTES):
                    token.write(piece)
                token.finish()
        except BaseException:
            sealed.unlink(missing_ok=True)
            raise
    plain.unlink()
    return sealed


def _open_postgres_dump(sealed: Path, destination: Path, recovery_key: str) -> None:
    """Decrypt the sealed dump to the new file ``destination``, a piece at a time.

    ``crypto.TokenReader`` authenticates the whole token before the first byte
    is written.
    """
    from hst.app import crypto

    try:
        with sealed.open("rb") as fh, crypto.TokenReader(recovery_key, fh) as token:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(token, out, _DUMP_PIECE_BYTES)
    except crypto.SecretKeyError as exc:
        raise ValueError("the Postgres dump does not open under the recovery key") from exc


def read_set(path: Path) -> RecoverySet:
    """The recovery set at `path`. Raises ValueError on a version this build does
    not read, as `manifest.read` does."""
    record = RecoverySet.model_validate_json(path.read_bytes())
    if record.schema_version not in READABLE_SET_SCHEMA_VERSIONS:
        raise ValueError(
            f"{path} is recovery-set schema version {record.schema_version}; "
            f"this build reads {', '.join(str(v) for v in READABLE_SET_SCHEMA_VERSIONS)}"
        )
    return record


def stage_recovery_data(
    settings: Settings,
    snapshot_key: int,
    target: Path,
    *,
    set_id: str,
    key_prefix: str = "",
    encrypted_configuration: bytes,
    encrypted_operator_key: bytes,
    operator_key: bytes,
) -> list[RecoveryObject]:
    """Copy the exact data-side restore inputs into a private immutable set.

    The caller selects ``snapshot_key`` from the graph's committed pointer while
    holding the cycle lock. Files are copied to a new set directory and checked
    against their recorded digests before this function returns. A caller must
    upload these files under the same per-set keys and must not publish the set
    record until the object store reports matching lengths and checksums.
    """
    from hst.app import crypto
    from hst.core import grapharchive

    report = verify_evidence(settings, snapshot_key)
    if not report.ok:
        raise ValueError("committed snapshot evidence does not verify: " + "; ".join(report.problems))
    record = manifestmod.read(settings, snapshot_key)
    root = target / "sets" / set_id
    object_root = "/".join(part for part in (key_prefix.strip("/"), "sets", set_id) if part)
    _private_dir(root, target)
    objects: list[RecoveryObject] = []

    paths: list[tuple[str, Path, str]] = []
    current = record
    while True:
        key = current.snapshot_key
        paths.append(("manifest", manifestmod.path_for(settings, key), f"manifests/{key}.json"))
        sig = manifestmod.sig_path_for(settings, key)
        if sig.is_file():
            paths.append(("manifest-signature", sig, f"manifests/{key}.sig"))
        if current.previous is None:
            break
        current = manifestmod.read(settings, current.previous.snapshot_key)
    for entry in record.files:
        paths.append((entry.kind, settings.hst_data_dir / entry.path, entry.path))
    archive = getattr(record, "graph_archive", None)
    if archive is None:
        raise ValueError("the committed manifest has no graph archive; it is not independently recoverable")
    relative = getattr(archive, "path", "")
    if not relative:
        raise ValueError("the committed manifest's graph archive has no path")
    paths.append(("graph-archive", settings.hst_data_dir / relative, relative))
    wrapped = settings.hst_data_dir / "dek.wrapped"
    if not wrapped.is_file():
        raise FileNotFoundError("dek.wrapped is absent; the recovery set cannot decrypt sealed data")
    paths.append(("wrapped-key", wrapped, "dek.wrapped"))

    seen: set[str] = set()
    for role, source, relative in paths:
        if relative in seen:
            continue
        seen.add(relative)
        if not source.is_file():
            raise FileNotFoundError(f"required recovery input is absent: {relative}")
        destination = root / "data" / relative
        _private_dir(destination.parent, root)
        shutil.copyfile(source, destination)
        destination.chmod(FILE_MODE)
        sha, size = manifestmod.file_facts(destination)
        if role not in {"manifest", "manifest-signature", "wrapped-key", "graph-archive"}:
            entry = next(item for item in record.files if item.path == relative)
            if (sha, size) != (entry.sha256, entry.bytes):
                raise ValueError(f"{relative}: source bytes do not match the committed manifest")
        if role == "graph-archive":
            expected = (getattr(archive, "sha256", ""), getattr(archive, "bytes", -1))
            if expected != (sha, size):
                raise ValueError("the graph archive does not match its committed manifest reference")
        objects.append(
            RecoveryObject(
                role=role,
                key=f"{object_root}/data/{relative}",
                sha256=sha,
                bytes=size,
                restore_path=relative,
            )
        )

    copied_wrapped = (root / "data" / "dek.wrapped").read_bytes()
    dek = crypto.unwrap_dek(copied_wrapped, operator_key)
    archive_settings = settings.model_copy(update={"hst_data_dir": root / "data"})
    grapharchive.verify(archive_settings, archive, dek)

    for role, name, body in (
        ("configuration", "configuration.enc", encrypted_configuration),
        ("operator-key", "operator-key.enc", encrypted_operator_key),
    ):
        if not body:
            raise ValueError(f"the encrypted {role} material is empty")
        destination = root / name
        with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE), "wb") as fh:
            fh.write(body)
        sha, size = manifestmod.file_facts(destination)
        objects.append(RecoveryObject(role=role, key=f"{object_root}/{name}", sha256=sha, bytes=size))
    return objects


# --- evidence verification, shared by `evidence check` and `recovery check` --------------


@dataclass
class EvidenceReport:
    """The result of the verification of the evidence of one snapshot. `signature`
    is "unsigned", "verified" or "invalid". An invalid signature also adds an entry
    to `problems`."""

    snapshot_key: int
    files: int = 0
    chain_len: int = 1
    signature: str = "unsigned"
    signature_key_id: str = ""
    signature_key_configured: bool | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def verify_evidence(settings: Settings, snapshot_key: int) -> EvidenceReport:
    """Verify the evidence of one snapshot from the files on disk. The checks are
    every file digest, the row digest of every side-store file, the signature when
    one exists, the digest of the graph archive, and the manifest chain back to the
    first manifest on disk or to the first missing manifest.

    Each mismatch is added to `problems`. Raises `FileNotFoundError` when the
    snapshot has no manifest.
    """
    record = manifestmod.read(settings, snapshot_key)
    report = EvidenceReport(snapshot_key=snapshot_key, files=len(record.files))

    for entry in record.files:
        path = settings.hst_data_dir / entry.path
        if not path.is_file():
            report.problems.append(f"{entry.path}: file missing")
            continue
        sha, size = manifestmod.file_facts(path)
        if (sha, size) != (entry.sha256, entry.bytes):
            report.problems.append(f"{entry.path}: digest mismatch (manifest {entry.sha256}, on disk {sha})")
        if entry.kind == "sidestore" and entry.rows_sha256 is not None:
            try:
                count, rows_sha = manifestmod.sidestore_row_facts(path)
            except Exception as exc:  # A parquet reader failure is recorded as a problem.
                report.problems.append(f"{entry.path}: could not verify row digest ({exc})")
            else:
                if (count, rows_sha) != (entry.row_count, entry.rows_sha256):
                    report.problems.append(
                        f"{entry.path}: row digest mismatch (manifest {entry.row_count} rows / "
                        f"{entry.rows_sha256}, on disk {count} rows / {rows_sha})"
                    )

    signature = manifestmod.read_signature(settings, snapshot_key)
    if signature is not None:
        digest = bytes.fromhex(manifestmod.digest_of(settings, snapshot_key))
        if manifestmod.verify(signature, digest):
            report.signature = "verified"
            report.signature_key_id = signature.key_id
            try:
                signer = manifestmod.signer_for(settings)
            except manifestmod.SignerError:
                signer = None
            if signer is not None:
                report.signature_key_configured = signer.public_key == signature.public_key
        else:
            report.signature = "invalid"
            report.problems.append(
                "signature does not verify against the manifest and its recorded public key"
            )

    archive = getattr(record, "graph_archive", None)
    if archive is not None:
        archive_path = settings.hst_data_dir / archive.path
        if not archive_path.is_file():
            report.problems.append(f"{archive.path}: graph archive missing")
        else:
            sha, size = manifestmod.file_facts(archive_path)
            if (sha, size) != (archive.sha256, archive.bytes):
                report.problems.append(f"{archive.path}: graph archive digest mismatch")

    current = record
    visited = {snapshot_key}
    while current.previous is not None:
        prev_key = current.previous.snapshot_key
        if prev_key in visited:
            report.problems.append(f"chain: cycle detected revisiting snapshot {prev_key}")
            break
        visited.add(prev_key)
        if not manifestmod.path_for(settings, prev_key).is_file():
            report.problems.append(f"chain: manifest for snapshot {prev_key} is missing")
            break
        actual_sha = manifestmod.digest_of(settings, prev_key)
        if actual_sha != current.previous.sha256:
            report.problems.append(
                f"chain: snapshot {current.snapshot_key} recorded snapshot {prev_key}'s digest as "
                f"{current.previous.sha256}, but it is {actual_sha} now"
            )
        try:
            current = manifestmod.read(settings, prev_key)
        except Exception as exc:  # An unreadable manifest is recorded as a problem.
            report.problems.append(f"chain: snapshot {prev_key}'s manifest could not be read ({exc})")
            break
        previous_signature = manifestmod.read_signature(settings, prev_key)
        if previous_signature is not None and not manifestmod.verify(
            previous_signature, bytes.fromhex(actual_sha)
        ):
            report.problems.append(f"chain: snapshot {prev_key}'s signature is invalid")
        report.chain_len += 1
    return report


# --- reconcile: runs against manifests against files ------------------------------------


@dataclass(frozen=True)
class Orphan:
    """A file on disk no retained manifest accounts for. `path` is relative to
    the data directory, as a manifest entry's path is."""

    path: str
    reason: str


@dataclass(frozen=True)
class NamedFile:
    """One file that a retained manifest lists. `snapshot_key` is the oldest
    snapshot whose manifest lists the file with `FileEntry.carried` false. When no
    retained manifest does, `snapshot_key` is the oldest snapshot that carries the
    file."""

    entry: manifestmod.FileEntry
    snapshot_key: int


@dataclass
class ReconcileReport:
    """The findings of one reconciliation, one list per kind of finding.

    A `--apply` run keeps `orphans` and `repairable_metadata` as found and
    records the resolutions in `quarantined` and `repaired_metadata`.
    """

    manifests: list[int] = field(default_factory=list)
    unreadable_manifests: list[str] = field(default_factory=list)
    # The count of files that a manifest lists and whose bytes on disk match the
    # recorded digest and size.
    verified: int = 0
    # Files that a manifest lists and that are on disk with another digest or size.
    tampered: list[str] = field(default_factory=list)
    # Files that a manifest lists and that are not on disk. `missing_raw` holds
    # raw payloads. `missing_derived` holds side-store files, which
    # `repair_derived` can rebuild.
    missing_raw: list[str] = field(default_factory=list)
    missing_derived: list[str] = field(default_factory=list)
    # Files on disk that no manifest lists and that are not pending.
    orphans: list[Orphan] = field(default_factory=list)
    # Raw files that are fetched and not joined to a run. They are not quarantined.
    parked: list[str] = field(default_factory=list)
    # Raw files whose sidecar holds a snapshot newer than every manifest on disk.
    # The run loaded the file and has not written its manifest.
    pending: list[str] = field(default_factory=list)
    # Raw files that are settled without a join to a run
    # (`rawstore.mark_superseded`). They are not moved.
    unjoined: list[str] = field(default_factory=list)
    # Raw files whose sidecar holds a snapshot whose manifest is on disk and does
    # not list the file. They are reported only. No function of this module
    # rewrites a manifest.
    unlisted: list[str] = field(default_factory=list)
    # Committed raw files with no join sidecar, each with the snapshot key of the
    # manifest that lists the file. `repair_metadata` writes the sidecar from
    # this key.
    repairable_metadata: list[tuple[str, int]] = field(default_factory=list)
    # The manifest entry of each missing derived file. `repair_derived` rebuilds
    # from this entry.
    derived_named: dict[str, NamedFile] = field(default_factory=dict)
    quarantined: list[str] = field(default_factory=list)
    quarantine_dir: Path | None = None
    repaired_metadata: list[str] = field(default_factory=list)
    # `rebuilt` holds one line per attempted rebuild. `rebuilt_paths` holds the
    # paths whose rebuild matches the recorded row digest.
    rebuilt: list[str] = field(default_factory=list)
    rebuilt_paths: list[str] = field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        """The findings that an operator must resolve after this run: tampered or
        missing files, a file that no manifest lists, an orphan that was not
        quarantined, a missing derived file that was not rebuilt, and an
        unreadable manifest."""
        out = [f"{p}: digest mismatch against the manifest that names it" for p in self.tampered]
        out += [f"{p}: named by a manifest and not on disk" for p in self.missing_raw]
        out += [
            f"{p}: derived dataset named by a manifest and not on disk"
            for p in self.missing_derived
            if p not in self.rebuilt_paths
        ]
        out += [f"{p}: its run joined a snapshot whose manifest does not list it" for p in self.unlisted]
        out += [f"{o.path}: {o.reason}" for o in self.orphans if o.path not in self.quarantined]
        out += self.unreadable_manifests
        return out

    @property
    def ok(self) -> bool:
        return not self.problems


def _named_files(settings: Settings, report: ReconcileReport) -> dict[str, NamedFile]:
    """Return every file that the retained manifests list, keyed by its path
    relative to the data directory.

    A carried entry lists a file that an earlier run wrote (`FileEntry.carried`,
    schema version 2). More than one manifest can list one path. The oldest
    manifest that lists the path with `carried` false is kept. When every entry
    is carried, the oldest manifest is kept.
    """
    named: dict[str, NamedFile] = {}
    for key in report.manifests:
        try:
            record = manifestmod.read(settings, key)
        except (OSError, ValueError) as exc:
            report.unreadable_manifests.append(f"manifest for snapshot {key} could not be read ({exc})")
            continue
        for entry in record.files:
            held = named.get(entry.path)
            if held is None or (held.entry.carried and not entry.carried):
                named[entry.path] = NamedFile(entry=entry, snapshot_key=key)
    return named


def _sidecar_state(path: Path) -> tuple[str, int | None]:
    """Return ("parked" | "joined" | "unjoined" | "unreadable", snapshot_ts) for a
    raw file, from the settle sidecar beside it (`core/rawstore.py`)."""
    sidecar = path.with_name(path.name[: -len(_RAW_SUFFIX)] + _META_SUFFIX)
    if not sidecar.is_file():
        return "parked", None
    try:
        body = json.loads(sidecar.read_text())
    except (OSError, ValueError):
        return "unreadable", None
    joined = body.get("snapshot_ts")
    if isinstance(joined, int):
        return "joined", joined
    return "unjoined", None


def _on_disk(settings: Settings) -> list[Path]:
    """Return every raw payload and side-store file under the data directory, in
    sorted order. Sidecars, manifests and other files in the tree are not
    returned. The HST map tables under `map_store.FAMILY` are not returned. No
    manifest lists them, and the HST sweep (`hst/map/sweep.py`) manages their
    retention."""
    found: list[Path] = []
    if settings.raw_dir.is_dir():
        found += sorted(settings.raw_dir.rglob(f"*{_RAW_SUFFIX}"))
    if settings.sidestore_dir.is_dir():
        hst = settings.sidestore_dir / map_store.FAMILY
        found += sorted(
            p for p in settings.sidestore_dir.rglob(f"*{_PARQUET_SUFFIX}") if not p.is_relative_to(hst)
        )
    return found


def scan(settings: Settings) -> ReconcileReport:
    """Reconcile the committed runs, the manifests and the files on disk.

    The scan reads files only. The manifests are plain JSON, and a digest is
    computed from the bytes. The scan needs no data key and no graph.

    A raw file that no retained manifest lists is classified by its settle
    sidecar (`core/rawstore.py`). A file with no sidecar is fetched and not
    joined to a run, and it is reported as parked. A file whose sidecar has a
    null `snapshot_ts` was superseded by a newer collection of the same device,
    and it is reported as unjoined. A file whose sidecar holds a snapshot joined
    that run. Such a file is reported as unlisted when the manifest of that
    snapshot is on disk, and as pending when the snapshot is newer than every
    manifest on disk. Otherwise the file is an orphan. A file whose sidecar
    cannot be read is an orphan. A side-store file that no retained manifest
    lists is an orphan.

    A scan takes no lock. `settle_since_scan` checks each orphan again under the
    cycle lock before a file moves.
    """
    report = ReconcileReport(manifests=manifestmod.keys(settings))
    named = _named_files(settings, report)

    for path in _on_disk(settings):
        relative = path.resolve().relative_to(settings.hst_data_dir.resolve()).as_posix()
        held = named.pop(relative, None)
        is_raw = path.name.endswith(_RAW_SUFFIX)
        if held is not None:
            sha, size = manifestmod.file_facts(path)
            if (sha, size) == (held.entry.sha256, held.entry.bytes):
                report.verified += 1
            else:
                report.tampered.append(relative)
            if is_raw and _sidecar_state(path)[0] == "parked":
                report.repairable_metadata.append((relative, held.snapshot_key))
            continue
        if not is_raw:
            report.orphans.append(Orphan(relative, "no retained manifest names this side-store file"))
            continue
        state, joined = _sidecar_state(path)
        if state == "parked":
            report.parked.append(relative)
        elif state == "unjoined":
            report.unjoined.append(relative)
        elif state == "unreadable":
            report.orphans.append(Orphan(relative, "its join sidecar cannot be read"))
        elif joined in report.manifests:
            report.unlisted.append(relative)
        elif report.manifests and joined is not None and joined > max(report.manifests):
            report.pending.append(relative)
        else:
            report.orphans.append(
                Orphan(relative, f"it joined snapshot {joined}, whose manifest is not on disk")
            )

    for relative, held in sorted(named.items()):
        if held.entry.kind == "sidestore":
            report.missing_derived.append(relative)
            report.derived_named[relative] = held
        else:
            report.missing_raw.append(relative)
    return report


class ScanSuperseded(RuntimeError):
    """A manifest that was published after the scan cannot be read. The orphans
    that it lists are not known, and no file is moved."""


def settle_since_scan(settings: Settings, report: ReconcileReport) -> None:
    """Remove from `report.orphans` each orphan that a manifest published after
    the scan accounts for.

    The caller holds the cycle lock, and no run is between the load of its files
    and the write of its manifest. A run that was in flight during the scan has
    published or failed. An orphan is removed when a manifest that is not in
    `report.manifests` lists it, or when its raw sidecar holds the snapshot of
    such a manifest. An orphan that stays belongs to a run that failed or to a
    manifest that was pruned. A new manifest that cannot be read raises
    `ScanSuperseded`.
    """
    fresh = sorted(set(manifestmod.keys(settings)) - set(report.manifests))
    named: set[str] = set()
    for key in fresh:
        try:
            named.update(entry.path for entry in manifestmod.read(settings, key).files)
        except (OSError, ValueError) as exc:
            raise ScanSuperseded(
                f"the manifest for snapshot {key} was published after the scan and cannot be read ({exc})"
            ) from exc
    report.manifests = sorted({*report.manifests, *fresh})
    kept: list[Orphan] = []
    for orphan in report.orphans:
        if orphan.path in named:
            continue
        if orphan.path.endswith(_RAW_SUFFIX):
            joined = _sidecar_state(settings.hst_data_dir / orphan.path)[1]
            if joined in fresh:
                continue
        kept.append(orphan)
    report.orphans = kept


# --- quarantine --------------------------------------------------------------------------


def _private_dir(path: Path, base: Path) -> None:
    """Create `path` and its parents, and apply the evidence directory mode to
    every level from `path` up to and including `base`.

    The mode argument of `mkdir` is masked by the umask and has no effect on a
    directory that exists. No directory above `base` is changed.
    """
    path.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
    stop = base.resolve()
    current = path.resolve()
    while True:
        with contextlib.suppress(OSError):  # chmod raises OSError on a mount without unix modes.
            current.chmod(DIR_MODE)
        if current == stop or current == current.parent:
            return
        current = current.parent


def quarantine(settings: Settings, report: ReconcileReport, stamp: str | None = None) -> Path:
    """Move every orphan under `data/quarantine/<ts>/`, with its relative path
    kept below that root, and write `report.json` with the moved paths and their
    reasons.

    No file is deleted. The quarantine root has mode 0o700 and the report file
    has mode 0o600.

    The moved paths are recorded in `report.quarantined`. Returns the quarantine
    root, which exists also when no file moved.
    """
    quarantine_root = settings.hst_data_dir / QUARANTINE_DIR
    root = quarantine_root / (stamp or _stamp())
    _private_dir(root, quarantine_root)
    moved: list[dict[str, str]] = []
    for orphan in report.orphans:
        source = settings.hst_data_dir / orphan.path
        if not source.exists():
            continue
        destination = root / orphan.path
        _private_dir(destination.parent, root)
        shutil.move(str(source), str(destination))
        moved.append({"path": orphan.path, "reason": orphan.reason})
        report.quarantined.append(orphan.path)
        # The settle sidecar of a raw file moves with the file.
        sidecar = source.with_name(source.name[: -len(_RAW_SUFFIX)] + _META_SUFFIX)
        if source.name.endswith(_RAW_SUFFIX) and sidecar.is_file():
            shutil.move(str(sidecar), str(destination.parent / sidecar.name))
    body = {
        "created": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "estate": settings.estate_name,
        "manifests": report.manifests,
        "moved": moved,
    }
    path = root / "report.json"
    path.write_text(json.dumps(body, indent=2, sort_keys=True))
    with contextlib.suppress(OSError):
        path.chmod(FILE_MODE)
    report.quarantine_dir = root
    return root


def repair_metadata(settings: Settings, report: ReconcileReport) -> list[str]:
    """Write the join sidecar of every committed raw file that has none.

    `rawstore.mark_joined` writes the sidecar and does not overwrite an existing
    sidecar.
    """
    for relative, snapshot_key in report.repairable_metadata:
        path = settings.hst_data_dir / relative
        try:
            rawstore.mark_joined(path, snapshot_key)
        except OSError as exc:
            report.unreadable_manifests.append(f"{relative}: join sidecar could not be written ({exc})")
            continue
        report.repaired_metadata.append(f"{relative}: join sidecar recorded snapshot {snapshot_key}")
    return report.repaired_metadata


# --- rebuilding a derived dataset, only into a named repair target -----------------------


class RepairTargetRefused(Exception):
    """The repair target is a directory that a rebuild must not write into."""


def check_repair_target(settings: Settings, target: Path) -> None:
    """Refuse a repair target inside the evidence directories of the estate.

    Raises RepairTargetRefused when the target is, or is under, the side store,
    the raw store, the manifest directory or the data directory.
    """
    resolved = target.resolve()
    for name, directory in (
        ("the side store", settings.sidestore_dir),
        ("the raw store", settings.raw_dir),
        ("the manifest directory", settings.manifests_dir),
        ("the data directory", settings.hst_data_dir),
    ):
        base = directory.resolve()
        if resolved == base or base in resolved.parents:
            raise RepairTargetRefused(
                f"{target} is {name} ({directory}); rebuild derived data into a directory "
                "outside the estate's own evidence"
            )


def repair_derived(
    settings: Settings,
    report: ReconcileReport,
    target: Path,
    *,
    collector_for: Callable[[str, str], Any | None],
    key: str,
) -> list[str]:
    """Rebuild the missing side-store files into `target`, and record whether each
    rebuild reproduced the row digest in the manifest.

    A side-store table is derived data. `collector.side_tables` is a pure
    function of the raw payload. A rebuild reproduced the file when its row
    digest equals the `rows_sha256` of the manifest entry. A digest that does not
    match is reported, and the file stays in the target.

    `collector_for(source, host)` returns the collector for the rebuild, or None
    when the source is not configured. No file is written outside `target`.
    """
    from hst.collectors import streams
    from hst.core import sidestore

    check_repair_target(settings, target)
    _private_dir(target, target)
    for relative in report.missing_derived:
        collector = None
        try:
            held = report.derived_named.get(relative)
            table = None if held is None else held.entry.table
            if held is None or table is None:
                report.rebuilt.append(f"{relative}: no manifest entry to rebuild from")
                continue
            entry = held.entry
            try:
                record = manifestmod.read(settings, held.snapshot_key)
            except (OSError, ValueError) as exc:
                report.rebuilt.append(f"{relative}: snapshot {held.snapshot_key}'s manifest ({exc})")
                continue
            raw_entry = next((f for f in record.files if f.kind == "raw" and f.run_id == entry.run_id), None)
            if raw_entry is None:
                report.rebuilt.append(f"{relative}: the manifest names no raw payload for run {entry.run_id}")
                continue
            raw_path = settings.hst_data_dir / raw_entry.path
            if not raw_path.is_file():
                report.rebuilt.append(f"{relative}: the raw payload {raw_entry.path} is not on disk either")
                continue
            collector = collector_for(entry.source, entry.host)
            if collector is None:
                report.rebuilt.append(f"{relative}: no such source configured; cannot regenerate")
                continue
            try:
                payload = rawstore.read(raw_path, key)
                rows = collector.side_tables(payload).get(table, [])
            except Exception as exc:  # A failure on a vendor payload is recorded in the report.
                report.rebuilt.append(f"{relative}: could not regenerate ({type(exc).__name__}: {exc})")
                continue
            if not rows:
                report.rebuilt.append(f"{relative}: side_tables produced no rows to regenerate it from")
                continue
            # `write_table` gets the snapshot key of the manifest as `snapshot_ts`.
            # The column is written into the rows, and the row digest matches the
            # recorded digest only with this value. The rows can be a view that
            # builds each row while the write reads it. A row that the collector
            # cannot build raises `RowMappingError` in `write_table`.
            try:
                written = sidestore.write_table(
                    target,
                    table,
                    entry.source,
                    entry.host,
                    entry.run_id,
                    rows,
                    record.snapshot_key,
                )
            except streams.RowMappingError as exc:
                # `exc` is unbound when the handler ends. A local alias of
                # `exc.original` keeps its traceback, and with it the rows and
                # the payload of this file, alive during the read of the next
                # file.
                report.rebuilt.append(
                    f"{relative}: could not regenerate ({type(exc.original).__name__}: {exc.original})"
                )
                continue
            if written is None:
                report.rebuilt.append(f"{relative}: the regenerated table held no rows to write")
                continue
            # `sidestore.written_row_facts` returns the digest that `write_table`
            # recorded while it wrote the rows. It equals the digest of a read of
            # the file.
            _count, digest = sidestore.written_row_facts(written) or manifestmod.sidestore_row_facts(written)
            if digest == entry.rows_sha256:
                report.rebuilt_paths.append(relative)
                report.rebuilt.append(f"{relative}: rebuilt into {written}, the recorded row digest matches")
            else:
                report.rebuilt.append(
                    f"{relative}: rebuilt into {written}, and the row digest differs "
                    f"(manifest {entry.rows_sha256}, rebuilt {digest})"
                )
        finally:
            # The payload of one file, its rows and the parse of the payload by
            # the collector are released here. Otherwise they stay in memory
            # while the payload of the next file is read.
            release = getattr(collector, "release_payload", None)
            if callable(release):
                release()
            payload = rows = collector = None
    return report.rebuilt


# --- recovery check ----------------------------------------------------------------------


@dataclass
class RecoveryCheck:
    """The result of the check of a restored tree against a recovery set."""

    recovery_set: RecoverySet
    evidence: EvidenceReport | None = None
    sources_checked: int = 0
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def check_recovery_set(
    settings: Settings,
    recovery_set: RecoverySet,
    source_rows: Mapping[str, tuple[str, bool, Mapping[str, Any]]] | None,
) -> RecoveryCheck:
    """Verify a restored tree against the recovery set of the backup.

    For a schema-2 set, the set must state its boundary and hold an object of
    each required role. Each object with a `restore_path` must be present in the
    restored tree with the recorded digest and length.

    The manifest of the snapshot of the set must be present, and its file digest
    must equal the `manifest_sha256` of the set. The evidence of that snapshot
    must verify (`verify_evidence`).

    For a schema-1 set, the restored Postgres must hold every source of the
    manifest, and the redacted configuration of each row must have the
    `config_sha256` that the manifest recorded. `source_rows` maps a source name
    to its (type, enabled, stored config), the 3 arguments of
    `manifest.source_config_digest` at publish time. `source_rows` None means
    that the rows could not be read, and it is recorded as a problem. A source in
    Postgres that the manifest does not list is recorded as a note.
    """
    check = RecoveryCheck(recovery_set=recovery_set)
    if recovery_set.schema_version >= 2:
        if not recovery_set.boundary:
            check.problems.append("the recovery set does not state its catalog/snapshot boundary")
        roles = {obj.role for obj in recovery_set.objects}
        for required in (
            "postgres",
            "manifest",
            "graph-archive",
            "wrapped-key",
            "configuration",
            "operator-key",
        ):
            if required not in roles:
                check.problems.append(f"the recovery set has no immutable {required} object")
        seen: set[tuple[str, str]] = set()
        for obj in recovery_set.objects:
            identity = (obj.key, obj.version_id)
            if identity in seen:
                check.problems.append(f"the recovery set repeats object {obj.key!r}")
            seen.add(identity)
            if not obj.key or not obj.sha256 or obj.bytes < 0:
                check.problems.append(f"object role {obj.role!r} has incomplete identity or digest facts")
            if "/sets/" not in f"/{obj.key}" and not obj.version_id:
                check.problems.append(
                    f"object {obj.key!r} is mutable: use a per-set key or retain its exact version id"
                )
            if obj.restore_path:
                relative = Path(obj.restore_path)
                if relative.is_absolute() or ".." in relative.parts:
                    check.problems.append(f"object {obj.key!r} has unsafe restore path {obj.restore_path!r}")
                    continue
                restored = settings.hst_data_dir / relative
                if not restored.is_file():
                    check.problems.append(
                        f"object {obj.key!r}: restored file {obj.restore_path!r} is missing"
                    )
                    continue
                sha, size = manifestmod.file_facts(restored)
                if (sha, size) != (obj.sha256, obj.bytes):
                    check.problems.append(
                        f"object {obj.key!r}: restored file digest/size differs from the recovery set"
                    )
    key = recovery_set.snapshot_key
    if recovery_set.estate and recovery_set.estate != settings.estate_name:
        check.notes.append(
            f"the set was written for estate {recovery_set.estate!r} and this install is "
            f"{settings.estate_name!r}"
        )
    if not manifestmod.path_for(settings, key).is_file():
        check.problems.append(f"the restored tree holds no manifest for snapshot {key}")
        return check
    digest = manifestmod.digest_of(settings, key)
    if digest != recovery_set.manifest_sha256:
        check.problems.append(
            f"snapshot {key}'s manifest digests {digest}; the set recorded {recovery_set.manifest_sha256}"
        )
    try:
        record = manifestmod.read(settings, key)
    except ValueError as exc:
        check.problems.append(str(exc))
        return check
    if recovery_set.chain_index is not None and record.chain_index != recovery_set.chain_index:
        check.problems.append(
            f"snapshot {key} is chain index {record.chain_index}; the set recorded {recovery_set.chain_index}"
        )
    check.evidence = verify_evidence(settings, key)
    check.problems += check.evidence.problems

    if recovery_set.schema_version >= 2:
        check.notes.append(
            "schema-2 graph recovery is pinned to its archived normalization context; "
            "the following Postgres dump is an explicit identity-store boundary"
        )
        return check

    if source_rows is None:
        check.problems.append(
            "the source rows could not be read from Postgres, so the configuration digests the "
            "manifest recorded were not checked"
        )
        return check
    for entry in record.sources:
        row = source_rows.get(entry.name)
        if row is None:
            check.problems.append(
                f"source {entry.name!r}: named by the manifest and not in the restored Postgres"
            )
            continue
        type_, enabled, config = row
        today = manifestmod.source_config_digest(entry.name, type_, enabled, config)
        if today != entry.config_sha256:
            check.problems.append(
                f"source {entry.name!r}: the manifest recorded configuration digest "
                f"{entry.config_sha256}, the restored Postgres digests {today}"
            )
        check.sources_checked += 1
    extra = sorted(set(source_rows) - {e.name for e in record.sources})
    if extra:
        check.notes.append("configured now and not named by this snapshot: " + ", ".join(extra))
    return check
