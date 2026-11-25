"""The store of the encrypted result artifacts under `analysis-results`."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from hst.app import crypto

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
FORMAT = "strata-result-artifact"


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


class ResultArtifactStore:
    def __init__(self, data_dir: Path, key: str, *, max_bytes: int = 10 * 1024**3):
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("result storage quota must be positive")
        self.root, self.key = Path(data_dir) / "analysis-results", key
        self.max_bytes = max_bytes

    @contextmanager
    def _publication_quota(self, target: Path, size: int) -> Iterator[bool]:
        """Hold the lock of the store directory and check the quota for a new file of `size` bytes.

        The quota counts every file in the directory, including the temporary
        file of an interrupted write. The context yields False when `target` exists.
        """
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            if target.exists():
                yield False
                return
            used = 0
            with os.scandir(self.root) as entries:
                for index, entry in enumerate(entries):
                    if index >= 100_000 or entry.is_symlink():
                        raise ValueError("result storage has too many entries or contains a symlink")
                    facts = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(facts.st_mode):
                        raise ValueError("result storage contains a non-regular entry")
                    used += facts.st_size
            if used + size > self.max_bytes:
                raise ValueError("saved-result storage quota exceeded; retained results were preserved")
            yield True
        finally:
            os.close(descriptor)

    def _path(self, digest: str) -> Path:
        if not _sha(digest):
            raise ValueError("invalid result artifact identity")
        if self.root.is_symlink():
            raise ValueError("result artifact directory cannot be a symlink")
        return self.root / f"{digest}.artifact"

    def publish(
        self,
        artifact: bytes,
        *,
        estate: str,
        manifest_sha256: str,
        request_id: str,
        evidence: Mapping[str, Any] | None = None,
    ) -> dict:
        if not estate or not _sha(manifest_sha256) or not _sha(request_id):
            raise ValueError("exact results require estate, snapshot and request identities")
        if len(artifact) > MAX_ARTIFACT_BYTES:
            raise ValueError("result artifact exceeds byte limit")
        binding = {
            "format": FORMAT,
            "version": 1,
            "estate": estate,
            "manifest_sha256": manifest_sha256,
            "request_id": request_id,
            "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        }
        content: dict[str, Any] = {"binding": binding, "artifact": json.loads(artifact)}
        if evidence is not None:
            content["evidence"] = dict(evidence)
        envelope = _json(content)
        if len(envelope) > MAX_ARTIFACT_BYTES:
            raise ValueError("result packet sets and evidence exceed byte limit")
        identity = hashlib.sha256(envelope).hexdigest()
        target = self._path(identity)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.root / f".{identity}.{secrets.token_hex(16)}.tmp"
        token = crypto.encrypt(self.key, envelope)
        try:
            with self._publication_quota(target, len(token)) as publish:
                if publish:
                    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(token)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.link(temporary, target)
                    temporary.unlink()
                    directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        reference = {
            **binding,
            "identity": identity,
            "path": f"analysis-results/{identity}.artifact",
        }
        # `load` authenticates the stored file. A concurrent publication can have written it.
        self.load(reference)
        return reference

    def load(self, reference: Mapping[str, Any]) -> bytes:
        return _json(self._load_envelope(reference)["artifact"])

    def load_evidence(self, reference: Mapping[str, Any]) -> dict[str, Any]:
        """Return the `evidence` of the authenticated envelope, or an empty dict."""
        return self._load_envelope(reference).get("evidence", {})

    def _load_envelope(self, reference: Mapping[str, Any]) -> dict[str, Any]:
        identity = reference.get("identity")
        if not isinstance(identity, str):
            raise ValueError("missing result artifact identity")
        path = self._path(identity)
        if reference.get("path") != f"analysis-results/{identity}.artifact":
            raise ValueError("result artifact path does not match its identity")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            facts = os.fstat(stream.fileno())
            if not stat.S_ISREG(facts.st_mode) or facts.st_size > 2 * MAX_ARTIFACT_BYTES:
                raise ValueError("result artifact file exceeds limits or is not regular")
            token = stream.read(2 * MAX_ARTIFACT_BYTES + 1)
        envelope = crypto.decrypt(self.key, token)
        if len(envelope) > MAX_ARTIFACT_BYTES + 4096 or hashlib.sha256(envelope).hexdigest() != identity:
            raise ValueError("result artifact integrity mismatch")
        decoded = json.loads(envelope)
        binding = decoded.get("binding", {})
        if binding.get("format") != FORMAT or binding.get("version") != 1:
            raise ValueError("unsupported result artifact format")
        if any(reference.get(name) != value for name, value in binding.items()):
            raise ValueError("result artifact scope does not match its saved reference")
        artifact = _json(decoded["artifact"])
        if hashlib.sha256(artifact).hexdigest() != binding["artifact_sha256"]:
            raise ValueError("result packet sets differ from their saved digest")
        return decoded


def references(result: Mapping[str, Any]) -> tuple[dict, ...]:
    """Return the result artifact references in `result`, in identity order.

    A document that nests deeper than 64 levels is refused.
    """
    found: dict[str, dict] = {}

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 64:
            raise ValueError("result document nesting exceeds limit")
        if isinstance(value, Mapping):
            if value.get("format") == FORMAT:
                identity = value.get("identity")
                if not isinstance(identity, str) or not _sha(identity):
                    raise ValueError("invalid result artifact reference")
                found[identity] = dict(value)
            else:
                for item in value.values():
                    visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, depth + 1)

    visit(result)
    return tuple(found[key] for key in sorted(found))
