"""Assessment exports and portable replay packages.

A checksum establishes the byte integrity of a file. A portable file contains
no decryption key. A replay against retained evidence writes nothing. The
restoration of archives requires an empty graph that the caller selects.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import tempfile
import zipfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any

from hst.assessment.store import AnalysisRun, input_digest
from hst.core import Settings, grapharchive, manifest, reconcile

MAX_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 32 * 1024 * 1024
MAX_FILES = 10000
FORMAT = "strata-assessment"
_INPUT_FIELDS = (
    "assessment_id",
    "assessment_revision",
    "kind",
    "inputs",
    "snapshot_refs",
    "engine_version",
    "limits",
    "input_schema_version",
)


class PackageError(ValueError):
    """An export is incomplete, incompatible, or unsafe to interpret."""


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(value: Any) -> str:
    return hashlib.sha256(_json(value)).hexdigest()


def export_document(run: AnalysisRun | Mapping[str, Any]) -> dict:
    """Return the export document of the recorded result of a run."""
    value = run.as_dict() if isinstance(run, AnalysisRun) else dict(run)
    for key in ("lease_token", "claimed_by", "checkpoint"):
        value.pop(key, None)
    value = json.loads(_json(value))
    if value.get("result") is None:
        raise PackageError("The run has no recorded result to export.")
    document = {
        "format": FORMAT,
        "version": 1,
        "run": value,
        "replay": {
            "available": False,
            "reason": (
                "Replay requires the recorded engine and retained snapshot evidence; "
                "run assessments replay to check and execute."
            ),
            "command": "hst assessments replay FILE",
        },
    }
    document["sha256"] = _sha(document)
    _validate_document(document)
    return document


def _validate_document(document: Any) -> dict:
    if not isinstance(document, dict) or document.get("format") != FORMAT or document.get("version") != 1:
        raise PackageError("Unsupported assessment package format or version.")
    if len(_json(document)) > MAX_METADATA_BYTES:
        raise PackageError("Assessment metadata exceeds 32 MiB.")
    claimed = document.get("sha256")
    if claimed != _sha({k: v for k, v in document.items() if k != "sha256"}):
        raise PackageError("Assessment package checksum mismatch.")
    run = document.get("run")
    if not isinstance(run, dict) or run.get("result") is None:
        raise PackageError("Assessment package has no recorded run result.")
    if any(key not in run for key in _INPUT_FIELDS):
        raise PackageError("Assessment package is missing normalized run inputs.")
    if not isinstance(run["inputs"], dict) or not isinstance(run["result"], dict):
        raise PackageError("Normalized inputs and result must be objects.")
    if run.get("input_schema_version") != 1:
        raise PackageError("Unsupported assessment input schema version.")
    if run.get("input_digest") != input_digest({key: run[key] for key in _INPUT_FIELDS}):
        raise PackageError("Recorded analysis input digest mismatch.")
    refs = run["snapshot_refs"]
    if not isinstance(refs, list) or not 1 <= len(refs) <= 16:
        raise PackageError("Assessment package needs 1 to 16 pinned snapshot references.")
    if run["inputs"].get("snapshot_refs") != refs:
        raise PackageError("Run and normalized input snapshot references differ.")
    for ref in refs:
        if (
            not isinstance(ref, dict)
            or not str(ref.get("snapshot", "")).isdigit()
            or not ref.get("manifest_sha256")
        ):
            raise PackageError("A pinned snapshot or manifest identity is missing.")
    return document


def _relative(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or path.is_absolute()
        or path.as_posix() != name
        or any(part in {".", ".."} for part in path.parts)
        or path.parts[0] not in {"raw", "sidestore", "manifests", "graph-archives", "analysis-results"}
    ):
        raise PackageError("Evidence path is outside the permitted evidence directories.")
    return name


def _path(settings: Settings, name: str) -> Path:
    _relative(name)
    root = settings.hst_data_dir.resolve()
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise PackageError(f"Required evidence is absent or outside the data directory: {name}")
    return path


def _data_key(settings: Settings) -> str:
    from hst.app import crypto

    wrapped = settings.hst_data_dir / crypto.DEK_FILENAME
    if not wrapped.is_file():
        raise PackageError("Archive authentication requires the existing wrapped data key.")
    return crypto.unwrap_dek(wrapped.read_bytes(), crypto._kek_bytes(settings))


def _package_id(document: dict) -> str:
    from hst.app import crypto

    identity = document.get("package_id")
    if not isinstance(identity, str) or not crypto.PACKAGE_ID.fullmatch(identity):
        raise PackageError("The package is not sealed under a package key. Export the run again.")
    return identity


def _archive(settings: Settings, ref: Mapping[str, Any]) -> manifest.GraphArchiveEntry:
    archive = manifest.read(settings, int(ref["snapshot"])).graph_archive
    if archive is None:
        raise PackageError("Exact portable replay unavailable: snapshot has no graph archive.")
    return archive


def _inventory(
    settings: Settings, document: dict, *, max_bytes: int, packaged: bool = False
) -> dict[str, dict]:
    """Return the digest and the size of each evidence file of every pinned snapshot.

    The files are the evidence files of the manifest, the graph archive, the
    manifest chain and the result artifacts.

    With `packaged`, the data directory is an unpacked package. Its graph
    archives and its side-store files are sealed under the package key. Their
    digests differ from the manifest. Its result artifacts are not opened.
    """
    entries: dict[str, dict] = {}
    size = 0

    def add(name: str, expected_sha: str | None = None, expected_size: int | None = None) -> None:
        nonlocal size
        path = _path(settings, name)
        file_size = path.stat().st_size
        if len(entries) >= MAX_FILES and name not in entries:
            raise PackageError("Evidence closure exceeds 10000 files.")
        if size + (0 if name in entries else file_size) > max_bytes:
            raise PackageError("Evidence closure exceeds the package byte limit.")
        sha, actual_size = manifest.file_facts(path)
        if (expected_sha is not None and sha != expected_sha) or (
            expected_size is not None and actual_size != expected_size
        ):
            raise PackageError(f"Evidence digest or size mismatch: {name}")
        entry = {"sha256": sha, "bytes": actual_size}
        if name in entries and entries[name] != entry:
            raise PackageError("Evidence changed while preparing the package.")
        if name not in entries:
            size += actual_size
        entries[name] = entry

    for ref in document["run"]["snapshot_refs"]:
        key = int(ref["snapshot"])
        current = manifest.read(settings, key)
        if current.estate != ref.get("estate"):
            raise PackageError("Pinned snapshot estate differs from the recorded manifest.")
        if current.graph_archive is None:
            raise PackageError("Exact portable replay unavailable: snapshot has no graph archive.")
        current_files = current.files
        for entry in current_files:
            expected_top = "raw" if entry.kind == "raw" else "sidestore" if entry.kind == "sidestore" else ""
            if not expected_top or not entry.path or PurePosixPath(entry.path).parts[0] != expected_top:
                raise PackageError("Unsupported or inconsistent evidence file kind.")
            if packaged and entry.kind == "sidestore":
                add(entry.path)
            else:
                add(entry.path, entry.sha256, entry.bytes)
        archive = current.graph_archive
        if not archive.path.startswith("graph-archives/"):
            raise PackageError("Graph archive is outside its required evidence directory.")
        if packaged:
            add(archive.path)
        else:
            add(archive.path, archive.sha256, archive.bytes)
        seen: set[int] = set()
        expected = ref["manifest_sha256"]
        while True:
            if current.snapshot_key in seen:
                raise PackageError("Cyclic manifest chain.")
            seen.add(current.snapshot_key)
            add(f"manifests/{current.snapshot_key}.json", expected)
            signature = manifest.sig_path_for(settings, current.snapshot_key)
            if signature.exists():
                add(f"manifests/{current.snapshot_key}.sig")
            if current.previous is None:
                break
            expected = current.previous.sha256
            current = manifest.read(settings, current.previous.snapshot_key)
        problems = reconcile.verify_evidence(settings, key).problems
        if packaged:
            # A problem of `reconcile.verify_evidence` starts with the path of its file.
            sealed = tuple(f"{entry.path}: " for entry in current_files if entry.kind == "sidestore")
            problems = [
                p
                for p in problems
                if p != f"{archive.path}: graph archive digest mismatch" and not p.startswith(sealed)
            ]
        if problems:
            raise PackageError("Evidence verification failed: " + "; ".join(problems))
    from hst.app import crypto
    from hst.assessment.result_artifacts import ResultArtifactStore, references

    result_refs = references(document["run"]["result"])
    if result_refs:
        store = None if packaged else ResultArtifactStore(settings.hst_data_dir, crypto.dek(settings))
        allowed = {(ref["estate"], ref["manifest_sha256"]) for ref in document["run"]["snapshot_refs"]}
        for reference in result_refs:
            if (reference["estate"], reference["manifest_sha256"]) not in allowed:
                raise PackageError("Result artifact crosses the run's pinned evidence scope.")
            identity = reference["identity"]
            if reference.get("path") != f"analysis-results/{identity}.artifact":
                raise PackageError("Result artifact path differs from its saved identity.")
            if store is not None:
                store.load(reference)
            add(reference["path"])
    return entries


def _reseal(settings: Settings, document: dict, data_key: str, key: str, root: Path) -> dict[str, Path]:
    """Return each copy by its evidence name."""
    from hst.app import crypto
    from hst.assessment.result_artifacts import references

    copies: dict[str, Path] = {}
    packaged = Settings(hst_data_dir=root)
    for ref in document["run"]["snapshot_refs"]:
        archive = _archive(settings, ref)
        if archive.path in copies:
            continue
        target = root / archive.path
        target.parent.mkdir(parents=True, exist_ok=True)
        sha, size = grapharchive.reseal(settings, archive, data_key, key, target)
        grapharchive.verify(packaged, {**archive.model_dump(), "sha256": sha, "bytes": size}, key)
        copies[archive.path] = target
        for entry in manifest.read(settings, int(ref["snapshot"])).files:
            if entry.kind != "sidestore" or entry.path in copies:
                continue
            target = root / entry.path
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with (
                _path(settings, entry.path).open("rb") as source,
                os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as sealed,
            ):
                writer = crypto.TokenWriter(key, sealed)
                while block := source.read(1024 * 1024):
                    digest.update(block)
                    writer.write(block)
                writer.finish()
            if digest.hexdigest() != entry.sha256:
                raise PackageError("Evidence changed during packaging.")
            copies[entry.path] = target
    for reference in references(document["run"]["result"]):
        envelope = crypto.decrypt(data_key, _path(settings, reference["path"]).read_bytes())
        if hashlib.sha256(envelope).hexdigest() != reference["identity"]:
            raise PackageError("Evidence changed during packaging.")
        target = root / reference["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(crypto.encrypt(key, envelope))
        copies[reference["path"]] = target
    return copies


def _unseal(root: Path, document: dict, key: str) -> None:
    from hst.app import crypto

    packaged = Settings(hst_data_dir=root)
    done: set[str] = set()
    for ref in document["run"]["snapshot_refs"]:
        for entry in manifest.read(packaged, int(ref["snapshot"])).files:
            if entry.kind != "sidestore" or entry.path in done:
                continue
            done.add(entry.path)
            path = _path(packaged, entry.path)
            plain = path.with_name(path.name + ".plain")
            digest, size = hashlib.sha256(), 0
            try:
                with (
                    path.open("rb") as sealed,
                    os.fdopen(os.open(plain, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as target,
                ):
                    reader = crypto.TokenReader(key, sealed)
                    while block := reader.read(1024 * 1024):
                        digest.update(block)
                        size += len(block)
                        target.write(block)
            except crypto.SecretKeyError as exc:
                raise PackageError("The package key does not open the side-store files.") from exc
            if (digest.hexdigest(), size) != (entry.sha256, entry.bytes):
                raise PackageError(f"Evidence digest or size mismatch: {entry.path}")
            plain.replace(path)


def build_portable(
    settings: Settings,
    run: AnalysisRun | Mapping[str, Any],
    destination: Path,
    *,
    max_bytes: int = MAX_BYTES,
    key_file: Path | None = None,
) -> dict:
    """Write a new ZIP with the mode 0600 that holds the evidence and no key.

    The graph archives, the side-store files and the result artifacts are
    sealed under the package key. The other evidence files have the bytes of
    the data directory. With `key_file`, the package key is written to that new
    private file.
    """
    from hst.app import crypto

    document = export_document(run)
    entries = _inventory(settings, document, max_bytes=max_bytes)
    data_key = _data_key(settings)
    package_id = secrets.token_hex(16)
    key = crypto.package_key(data_key, package_id)
    with tempfile.TemporaryDirectory(prefix="hst-assessment-export-") as temporary:
        copies = _reseal(settings, document, data_key, key, Path(temporary))
        for name, copy in copies.items():
            sha, size = manifest.file_facts(copy)
            entries[name] = {"sha256": sha, "bytes": size}
        if sum(facts["bytes"] for facts in entries.values()) > max_bytes:
            raise PackageError("Evidence closure exceeds the package byte limit.")
        document.update(
            evidence=entries,
            package_id=package_id,
            replay={
                "available": False,
                "reason": (
                    "Execution requires the exact engine, an empty isolated Neo4j target, "
                    "and the package key supplied separately."
                ),
                "engine_version": document["run"]["engine_version"],
                "key_included": False,
                "command": "hst assessments replay FILE --into URI --package-key-file PATH",
            },
        )
        document["sha256"] = _sha({k: v for k, v in document.items() if k != "sha256"})
        _validate_document(document)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with (
                os.fdopen(fd, "wb") as output,
                zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle,
            ):
                bundle.writestr("assessment.json", _json(document))
                for name, facts in sorted(entries.items()):
                    info = zipfile.ZipInfo(f"evidence/{name}")
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    digest, count = hashlib.sha256(), 0
                    with (
                        (copies.get(name) or _path(settings, name)).open("rb") as source,
                        bundle.open(info, "w") as target,
                    ):
                        while block := source.read(1024 * 1024):
                            count += len(block)
                            if count > facts["bytes"]:
                                raise PackageError("Evidence changed during packaging.")
                            digest.update(block)
                            target.write(block)
                    if (digest.hexdigest(), count) != (facts["sha256"], facts["bytes"]):
                        raise PackageError("Evidence changed during packaging.")
            if key_file is not None:
                with os.fdopen(os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
                    stream.write(key + "\n")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    return {
        "path": str(destination),
        "files": len(entries),
        "bytes": destination.stat().st_size,
        "sha256": document["sha256"],
    }


def _read_document(path: Path) -> dict:
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise PackageError("Assessment JSON exceeds 32 MiB.")
    return _validate_document(json.loads(path.read_bytes()))


def _unpack(path: Path, root: Path, *, max_bytes: int) -> dict:
    """Extract only indexed regular evidence files after validating every ZIP name."""
    if path.stat().st_size > max_bytes + MAX_METADATA_BYTES:
        raise PackageError("Package file exceeds its byte limit.")
    with zipfile.ZipFile(path) as bundle:
        infos = bundle.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)) or len(names) > MAX_FILES + 1:
            raise PackageError("Duplicate or excessive package entries.")
        if sum(info.file_size for info in infos) > max_bytes + MAX_METADATA_BYTES:
            raise PackageError("Uncompressed package exceeds its byte limit.")
        for info in infos:
            kind = stat.S_IFMT(info.external_attr >> 16)
            if info.is_dir() or kind not in {0, stat.S_IFREG}:
                raise PackageError("Package contains a directory, symlink or special file.")
            if info.filename != "assessment.json":
                if not info.filename.startswith("evidence/"):
                    raise PackageError("Package contains an unexpected file.")
                _relative(info.filename.removeprefix("evidence/"))
        if "assessment.json" not in names or bundle.getinfo("assessment.json").file_size > MAX_METADATA_BYTES:
            raise PackageError("Package has no bounded assessment descriptor.")
        document = _validate_document(json.loads(bundle.read("assessment.json")))
        _package_id(document)
        entries = document.get("evidence")
        if not isinstance(entries, dict) or set(names) != {
            "assessment.json",
            *(f"evidence/{name}" for name in entries),
        }:
            raise PackageError("Package evidence index differs from its file set.")
        count_total = 0
        for name, facts in entries.items():
            _relative(name)
            if (
                not isinstance(facts, dict)
                or not isinstance(facts.get("bytes"), int)
                or facts["bytes"] < 0
                or not isinstance(facts.get("sha256"), str)
            ):
                raise PackageError("Malformed evidence size or digest.")
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest, count = hashlib.sha256(), 0
            with bundle.open(f"evidence/{name}") as source, destination.open("xb") as target:
                destination.chmod(0o600)
                while block := source.read(1024 * 1024):
                    count += len(block)
                    count_total += len(block)
                    if count > facts["bytes"] or count_total > max_bytes:
                        raise PackageError("Evidence exceeds its declared size or package limit.")
                    digest.update(block)
                    target.write(block)
            if (digest.hexdigest(), count) != (facts["sha256"], facts["bytes"]):
                raise PackageError(f"Packaged evidence digest mismatch: {name}")
    settings = Settings(hst_data_dir=root)
    if _inventory(settings, document, max_bytes=max_bytes, packaged=True) != entries:
        raise PackageError("Package does not contain exactly its required evidence closure.")
    return document


def check_package(path: Path, *, max_bytes: int = MAX_BYTES) -> dict:
    """Verify integrity and portable evidence closure without graph access or keys."""
    with tempfile.TemporaryDirectory(prefix="hst-assessment-check-") as temporary:
        portable = zipfile.is_zipfile(path)
        document = _unpack(path, Path(temporary), max_bytes=max_bytes) if portable else _read_document(path)
    return {
        "valid": True,
        "format": "portable" if portable else "reference",
        "run_id": document["run"].get("id"),
        "sha256": document["sha256"],
        "replay": document["replay"],
        "claim": "Byte integrity verified; semantic replay and trusted authorship are separate checks.",
    }


def _semantic(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _semantic(entry) for key, entry in value.items() if key != "elapsed_seconds"}
    return [_semantic(entry) for entry in value] if isinstance(value, list) else value


# A row without one of these evidence keys states the same answer.
_ADDITIVE_KEYS = frozenset({"left_estate", "left_estate_note", "gap_detail"})


def _align(expected: Any, actual: Any) -> tuple[Any, Any]:
    """`expected` and `actual` with each additive key left out of a pair of
    dicts where only one of the two has it."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        drop = {key for key in _ADDITIVE_KEYS if (key in expected) != (key in actual)}
        pairs = {key: _align(expected[key], actual[key]) for key in expected.keys() & actual.keys()}
        return (
            {
                key: pairs[key][0] if key in pairs else value
                for key, value in expected.items()
                if key not in drop
            },
            {
                key: pairs[key][1] if key in pairs else value
                for key, value in actual.items()
                if key not in drop
            },
        )
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        aligned = [_align(left, right) for left, right in zip(expected, actual, strict=True)]
        return [left for left, _ in aligned], [right for _, right in aligned]
    return expected, actual


def replay_status(settings: Settings, run: AnalysisRun | Mapping[str, Any]) -> dict:
    """Inspect retained evidence, actual storage use and required replay runtime."""
    from hst.app import crypto
    from hst.assessment import service

    try:
        document = export_document(run)
        entries = _inventory(settings, document, max_bytes=MAX_BYTES)
    except (OSError, ValueError) as exc:
        return {
            "available": False,
            "portable_available": False,
            "bytes": None,
            "reason": str(exc),
            "evidence_complete": False,
        }
    compatible = document["run"]["engine_version"] == service.engine_version(settings)
    portable_reason = None
    try:
        key = _data_key(settings)
        for ref in document["run"]["snapshot_refs"]:
            record = manifest.read(settings, int(ref["snapshot"]))
            grapharchive.verify(settings, record.graph_archive, key)
    except (grapharchive.ArchiveError, crypto.SecretKeyError):
        portable_reason = "The retained graph archives could not be authenticated with the configured key."
    except Exception as exc:
        portable_reason = f"The retained graph archives could not be read. {type(exc).__name__}: {exc}"
    return {
        "available": compatible,
        "portable_available": portable_reason is None,
        "portable_reason": portable_reason,
        "evidence_complete": True,
        "files": len(entries),
        "bytes": sum(v["bytes"] for v in entries.values()),
        "reason": None if compatible else "The recorded engine build is not currently available.",
        "required_engine": document["run"]["engine_version"],
        "snapshot_refs": document["run"]["snapshot_refs"],
        "claim": "Availability preflight; successful semantic replay is a separate check.",
    }


def package_key(settings: Settings, path: Path) -> str:
    """The key of the portable package at `path`, derived from the data key of
    `settings`. A package that the key does not open is refused."""
    from hst.app import crypto

    if not zipfile.is_zipfile(path):
        raise PackageError("A reference export has no package key.")
    with tempfile.TemporaryDirectory(prefix="hst-assessment-key-") as temporary:
        document = _unpack(path, Path(temporary), max_bytes=MAX_BYTES)
        key = crypto.package_key(_data_key(settings), _package_id(document))
        packaged = Settings(hst_data_dir=Path(temporary))
        try:
            for ref in document["run"]["snapshot_refs"]:
                archive = _archive(packaged, ref)
                facts = document["evidence"][archive.path]
                expected = {**archive.model_dump(), "sha256": facts["sha256"], "bytes": facts["bytes"]}
                grapharchive.verify(packaged, expected, key)
        except grapharchive.ArchiveError as exc:
            raise PackageError("The data key of this deployment does not open the package.") from exc
    return key


def replay_package(
    settings: Settings, path: Path, *, into: str | None = None, package_key_file: Path | None = None
) -> dict:
    """Replay the run of an export and compare its result with the recorded result.

    Without `into`, the replay reads the configured graph and writes nothing.
    With `into`, the archives of a portable package are restored into that
    empty graph.
    """
    from hst.app import crypto
    from hst.assessment import service
    from hst.core import db

    with tempfile.TemporaryDirectory(prefix="hst-assessment-replay-") as temporary:
        portable = zipfile.is_zipfile(path)
        root = Path(temporary)
        document = _unpack(path, root, max_bytes=MAX_BYTES) if portable else _read_document(path)
        run = document["run"]
        if run["engine_version"] != service.engine_version(settings):
            return {"available": False, "reason": "The current engine differs from the recorded engine."}
        selected = settings
        if into is not None:
            if not portable or package_key_file is None:
                raise PackageError("Isolated restoration requires a portable package and --package-key-file.")
            if db.same_endpoint(into, settings.neo4j_uri):
                raise PackageError("Refusing to restore into the configured live twin.")
            selected = settings.model_copy(update={"neo4j_uri": into, "hst_data_dir": root})
            key = package_key_file.read_text().strip()
            # `crypto.dek(selected)` returns the package key. A host without an operator key gets no data key.
            with suppress(crypto.SecretKeyError):
                crypto.install_dek(selected, key)
        else:
            if package_key_file is not None:
                raise PackageError("--package-key-file is only used with an isolated --into target.")
            try:
                _inventory(settings, document, max_bytes=MAX_BYTES)
            except (OSError, ValueError) as exc:
                return {"available": False, "reason": f"Retained evidence unavailable: {exc}"}
        replay_scope: dict = {}
        try:
            if into is not None:
                from hst.assessment.archive_sessions import ArchiveSessions

                _unseal(root, document, key)
                with db.session(selected) as target:
                    router = ArchiveSessions(
                        selected, target, run["snapshot_refs"], key, evidence=document["evidence"]
                    )
                    if len(run["snapshot_refs"]) == 1:
                        router._select(int(run["snapshot_refs"][0]["snapshot"]))
                        actual = service.execute(selected, run["inputs"])
                    else:
                        actual = service.execute(
                            selected, run["inputs"], snapshot_session_factory=router.session
                        )
                    replay_scope = {
                        "restored_snapshots": sorted(router.restored),
                        "archive_switches": router.switches,
                        "isolation": "complete-archive-per-read-boundary",
                    }
            else:
                actual = service.execute(selected, run["inputs"])
        except Exception as exc:
            return {
                "available": False,
                "reason": f"Replay runtime or evidence unavailable: {type(exc).__name__}: {exc}",
            }
        expected_semantic = _semantic(
            {key: value for key, value in run["result"].items() if key != "execution"}
        )
        actual_semantic = _semantic({key: value for key, value in actual.items() if key != "execution"})
        expected_semantic, actual_semantic = _align(expected_semantic, actual_semantic)
        return {
            "available": True,
            "matches": expected_semantic == actual_semantic,
            "run_id": run.get("id"),
            "expected_sha256": _sha(expected_semantic),
            "actual_sha256": _sha(actual_semantic),
            "ignored_fields": ["elapsed_seconds", "execution"],
            "result": actual,
            **replay_scope,
        }
