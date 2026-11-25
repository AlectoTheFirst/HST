"""Native-backend identity checks that do not construct a BDD manager."""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_STAMP = Path("/usr/share/hst/symbolic-build.json")


@dataclass(frozen=True)
class BackendIdentity:
    available: bool
    verified: bool
    status: str
    backend: str
    backend_version: str
    cudd_version: str
    python_abi: str
    platform: str
    wheel_sha256: str
    source_identity: str

    @property
    def identifier(self) -> str:
        return ":".join(
            (
                self.backend,
                self.backend_version,
                self.cudd_version,
                self.python_abi,
                self.platform,
                self.status,
                self.wheel_sha256,
                self.source_identity,
            )
        )


def _stamp(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return value if isinstance(value, dict) and value.get("format_version") == 1 else None


@lru_cache(maxsize=4)
def backend_identity(stamp_path: Path | None = None) -> BackendIdentity:
    """Describe the installed extension and its locked build without importing it."""
    path = stamp_path or Path(os.environ.get("HST_SYMBOLIC_BUILD_STAMP", DEFAULT_STAMP))
    stamp = _stamp(path)
    try:
        version = importlib.metadata.version("dd")
    except importlib.metadata.PackageNotFoundError:
        version = "missing"
    try:
        spec = importlib.util.find_spec("dd.cudd")
    except (ImportError, AttributeError, ValueError):
        spec = None
    available = version != "missing" and spec is not None and bool(spec.origin)
    expected_version = str(stamp.get("dd_version", "")) if stamp else ""
    wheel_sha = str(stamp.get("wheel_sha256", "")) if stamp else ""
    extension_sha = str(stamp.get("extension_sha256", "")) if stamp else ""
    digest_fields = (wheel_sha, extension_sha) + (
        tuple(str(stamp.get(key, "")) for key in ("dd_source_sha256", "cudd_source_sha256")) if stamp else ()
    )
    digests_valid = all(re.fullmatch(r"[0-9a-f]{64}", value) for value in digest_fields)
    source_fields = (
        {key: stamp.get(key) for key in ("dd_source_sha256", "cudd_source_sha256", "patches")}
        if stamp
        else {}
    )
    source_identity = (
        hashlib.sha256(json.dumps(source_fields, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if stamp
        else "unstamped"
    )
    running_abi = sys.implementation.cache_tag or "unknown"
    running_platform = f"{sys.platform}-{platform.machine().lower()}"
    extension_matches = False
    if spec is not None and spec.origin and extension_sha and digests_valid:
        try:
            extension_matches = hashlib.sha256(Path(spec.origin).read_bytes()).hexdigest() == extension_sha
        except OSError:
            extension_matches = False
    verified = (
        available
        and stamp is not None
        and version == expected_version
        and digests_valid
        and stamp.get("python_abi") == running_abi
        and stamp.get("platform") == running_platform
        and extension_matches
    )
    if not available:
        status = "missing-backend"
    elif stamp is None:
        status = "missing-build-stamp"
    elif version != expected_version:
        status = "backend-version-mismatch"
    elif not digests_valid:
        status = "invalid-build-stamp"
    elif stamp.get("python_abi") != running_abi or stamp.get("platform") != running_platform:
        status = "runtime-abi-mismatch"
    elif not extension_matches:
        status = "extension-hash-mismatch"
    else:
        status = "ready"
    return BackendIdentity(
        available=available,
        verified=verified,
        status=status,
        backend="dd.cudd",
        backend_version=version,
        cudd_version=str(stamp.get("cudd_version", "unknown")) if stamp else "unknown",
        python_abi=running_abi,
        platform=running_platform,
        wheel_sha256=wheel_sha,
        source_identity=source_identity,
    )
