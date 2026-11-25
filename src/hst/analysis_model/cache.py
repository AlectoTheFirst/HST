"""Encrypted durable analysis artifacts with fenced publication and leases."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import os
import secrets
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from hst.app import crypto


class CacheError(RuntimeError):
    pass


class CacheCorruptionError(CacheError):
    pass


@dataclass(frozen=True, slots=True)
class CacheRecord:
    key: str
    artifact_sha256: str
    path: str
    encrypted_bytes: int
    created_at: float
    accessed_at: float
    lease_count: int = 0
    pinned: bool = False


@dataclass(frozen=True, slots=True)
class CacheLease:
    record: CacheRecord
    token: str


class CacheIndex(Protocol):
    async def publish(self, record: CacheRecord) -> CacheRecord: ...
    async def get(self, key: str) -> CacheRecord | None: ...
    async def acquire(self, key: str) -> CacheLease | None: ...
    async def release(self, key: str, token: str) -> None: ...
    async def eviction_candidates(self) -> list[CacheRecord]: ...
    async def delete(self, key: str, artifact_sha256: str) -> bool: ...
    async def total_bytes(self) -> int: ...
    async def artifact_referenced(self, artifact_sha256: str) -> bool: ...


class MemoryCacheIndex:
    def __init__(self) -> None:
        self.records: dict[str, CacheRecord] = {}
        self.leases: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def publish(self, record: CacheRecord) -> CacheRecord:
        async with self._lock:
            old = self.records.get(record.key)
            if old and old.artifact_sha256 != record.artifact_sha256:
                raise CacheError("a cache key cannot identify two artifacts")
            self.records[record.key] = old or record
            return self.records[record.key]

    async def get(self, key: str) -> CacheRecord | None:
        async with self._lock:
            record = self.records.get(key)
            if record:
                record = replace(record, accessed_at=time.time())
                self.records[key] = record
            return record

    async def acquire(self, key: str) -> CacheLease | None:
        async with self._lock:
            record = self.records.get(key)
            if record:
                token = secrets.token_hex(24)
                self.leases[token] = key
                count = sum(candidate == key for candidate in self.leases.values())
                record = replace(record, lease_count=count, accessed_at=time.time())
                self.records[key] = record
                return CacheLease(record, token)
            return None

    async def release(self, key: str, token: str) -> None:
        async with self._lock:
            record = self.records.get(key)
            if not record or self.leases.get(token) != key:
                raise CacheError("cache lease is not held")
            del self.leases[token]
            count = sum(candidate == key for candidate in self.leases.values())
            self.records[key] = replace(record, lease_count=count)

    async def eviction_candidates(self) -> list[CacheRecord]:
        async with self._lock:
            return sorted(
                (r for r in self.records.values() if not r.pinned and r.lease_count == 0),
                key=lambda r: (r.accessed_at, r.key),
            )

    async def delete(self, key: str, artifact_sha256: str) -> bool:
        async with self._lock:
            record = self.records.get(key)
            if not record or record.artifact_sha256 != artifact_sha256 or record.lease_count or record.pinned:
                return False
            del self.records[key]
            return True

    async def total_bytes(self) -> int:
        async with self._lock:
            blobs: dict[str, int] = {}
            for record in self.records.values():
                blobs.setdefault(record.artifact_sha256, record.encrypted_bytes)
            return sum(blobs.values())

    async def artifact_referenced(self, artifact_sha256: str) -> bool:
        async with self._lock:
            return any(record.artifact_sha256 == artifact_sha256 for record in self.records.values())


class ArtifactCache:
    def __init__(
        self,
        root: Path,
        encryption_key: str,
        index: CacheIndex,
        *,
        max_bytes: int = 100 * 1024**3,
        max_artifact_bytes: int = 512 * 1024**2,
    ) -> None:
        if max_bytes <= 0 or max_artifact_bytes <= 0:
            raise ValueError("cache limits must be positive")
        self.root, self.key, self.index = Path(root), encryption_key, index
        self.max_bytes, self.max_artifact_bytes = max_bytes, max_artifact_bytes

    async def publish(self, key: str, plaintext: bytes) -> CacheRecord:
        _cache_key(key)
        if len(plaintext) > self.max_artifact_bytes:
            raise CacheError("artifact exceeds byte limit")
        digest = hashlib.sha256(plaintext).hexdigest()
        target = self._path(digest)
        self.root.mkdir(parents=True, exist_ok=True)
        token = crypto.encrypt(self.key, plaintext)
        if len(token) > self.max_artifact_bytes * 2:
            raise CacheError("encrypted artifact exceeds byte limit")
        temporary = self.root / f".{digest}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(token)
                stream.flush()
                os.fsync(stream.fileno())
            async with self._blob_lock(digest):
                temporary.replace(target)
                dirfd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(dirfd)
                finally:
                    os.close(dirfd)
                now = time.time()
                record = await self.index.publish(CacheRecord(key, digest, target.name, len(token), now, now))
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
        await self.evict()
        return record

    async def load(self, key: str) -> bytes | None:
        async with self.lease(key) as data:
            return data

    @asynccontextmanager
    async def lease(self, key: str) -> AsyncIterator[bytes | None]:
        lease = await self.index.acquire(key)
        if lease is None:
            yield None
            return
        try:
            yield self._read(lease.record)
        finally:
            await self.index.release(key, lease.token)

    async def materialize(self, key: str, destination: Path) -> str:
        """Copy authenticated plaintext to an immutable saved-result location."""
        async with self.lease(key) as data:
            if data is None:
                raise CacheError("cache artifact is absent")
            digest = hashlib.sha256(data).hexdigest()
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            return digest

    async def evict(self) -> int:
        candidates = await self.index.eviction_candidates()
        total = await self.index.total_bytes()
        removed = 0
        for record in candidates:
            if total <= self.max_bytes:
                break
            async with self._blob_lock(record.artifact_sha256):
                if await self.index.delete(record.key, record.artifact_sha256):
                    if not await self.index.artifact_referenced(record.artifact_sha256):
                        with contextlib.suppress(FileNotFoundError):
                            self._path(record.artifact_sha256).unlink()
                        total -= record.encrypted_bytes
                    removed += 1
        return removed

    def _path(self, digest: str) -> Path:
        return self.root / f"{digest}.artifact"

    @asynccontextmanager
    async def _blob_lock(self, digest: str) -> AsyncIterator[None]:
        path = self.root / f".{digest}.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            await asyncio.to_thread(fcntl.flock, descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read(self, record: CacheRecord) -> bytes:
        expected = self._path(record.artifact_sha256)
        if record.path != expected.name:
            raise CacheCorruptionError("artifact index path is invalid")
        path = self.root / record.path
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                if size != record.encrypted_bytes or size > self.max_artifact_bytes * 2:
                    raise CacheCorruptionError("artifact size differs from cache index")
                token = stream.read(record.encrypted_bytes + 1)
        except OSError as exc:
            raise CacheCorruptionError("indexed artifact is unavailable") from exc
        if len(token) != record.encrypted_bytes or len(token) > self.max_artifact_bytes * 2:
            raise CacheCorruptionError("artifact size differs from cache index")
        try:
            data = crypto.decrypt(self.key, token)
        except crypto.SecretKeyError as exc:
            raise CacheCorruptionError("artifact authentication failed") from exc
        if len(data) > self.max_artifact_bytes or hashlib.sha256(data).hexdigest() != record.artifact_sha256:
            raise CacheCorruptionError("artifact content digest mismatch")
        return data


def _cache_key(value: str) -> None:
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("cache key must be lowercase SHA-256")


class PgCacheIndex:
    """Transactional index using an existing SQLAlchemy async engine."""

    def __init__(self, engine: object) -> None:
        self.engine = engine

    async def publish(self, record: CacheRecord) -> CacheRecord:
        import sqlalchemy as sa

        async with self.engine.begin() as conn:  # type: ignore[attr-defined]
            row = (
                await conn.execute(
                    sa.text("""
                INSERT INTO analysis_cache_artifacts
                  (cache_key, artifact_sha256, path, encrypted_bytes, created_at, accessed_at)
                VALUES (:key, :sha, :path, :size, to_timestamp(:created), to_timestamp(:accessed))
                ON CONFLICT (cache_key) DO UPDATE SET accessed_at = EXCLUDED.accessed_at
                RETURNING cache_key, artifact_sha256, path, encrypted_bytes,
                          extract(epoch from created_at), extract(epoch from accessed_at), lease_count, pinned
            """),
                    {
                        "key": record.key,
                        "sha": record.artifact_sha256,
                        "path": record.path,
                        "size": record.encrypted_bytes,
                        "created": record.created_at,
                        "accessed": record.accessed_at,
                    },
                )
            ).one()
            if row[1] != record.artifact_sha256:
                raise CacheError("a cache key cannot identify two artifacts")
            return _pg_record(row)

    async def get(self, key: str) -> CacheRecord | None:
        import sqlalchemy as sa

        async with self.engine.begin() as conn:  # type: ignore[attr-defined]
            row = (
                await conn.execute(
                    sa.text("""UPDATE analysis_cache_artifacts SET accessed_at=now()
                WHERE cache_key=:key RETURNING cache_key, artifact_sha256, path, encrypted_bytes,
                extract(epoch from created_at), extract(epoch from accessed_at), lease_count, pinned"""),
                    {"key": key},
                )
            ).first()
            return _pg_record(row) if row else None

    async def acquire(self, key: str) -> CacheLease | None:
        import sqlalchemy as sa

        token = secrets.token_hex(24)
        async with self.engine.begin() as conn:  # type: ignore[attr-defined]
            await conn.execute(sa.text("DELETE FROM analysis_cache_leases WHERE expires_at < now()"))
            inserted = await conn.execute(
                sa.text("""INSERT INTO analysis_cache_leases (lease_token, cache_key, expires_at)
                    SELECT :token, cache_key, now() + interval '5 minutes'
                    FROM analysis_cache_artifacts WHERE cache_key=:key
                    RETURNING cache_key"""),
                {"key": key, "token": token},
            )
            if inserted.first() is None:
                return None
            row = (
                await conn.execute(
                    sa.text("""UPDATE analysis_cache_artifacts
                SET accessed_at=now(),
                    lease_count=(SELECT count(*) FROM analysis_cache_leases WHERE cache_key=:key),
                    lease_expires_at=now() + interval '5 minutes'
                WHERE cache_key=:key
                RETURNING cache_key, artifact_sha256, path, encrypted_bytes,
                extract(epoch from created_at), extract(epoch from accessed_at), lease_count, pinned"""),
                    {"key": key},
                )
            ).first()
            return CacheLease(_pg_record(row), token) if row else None

    async def release(self, key: str, token: str) -> None:
        import sqlalchemy as sa

        async with self.engine.begin() as conn:  # type: ignore[attr-defined]
            result = await conn.execute(
                sa.text(
                    """DELETE FROM analysis_cache_leases
                    WHERE cache_key=:key AND lease_token=:token"""
                ),
                {"key": key, "token": token},
            )
            if result.rowcount != 1:
                raise CacheError("cache lease is not held")
            await conn.execute(
                sa.text("""UPDATE analysis_cache_artifacts
                    SET lease_count=(SELECT count(*) FROM analysis_cache_leases WHERE cache_key=:key),
                        lease_expires_at=(SELECT max(expires_at) FROM analysis_cache_leases
                                          WHERE cache_key=:key)
                    WHERE cache_key=:key"""),
                {"key": key},
            )

    async def eviction_candidates(self) -> list[CacheRecord]:
        import sqlalchemy as sa

        async with self.engine.begin() as conn:  # type: ignore[attr-defined]
            await conn.execute(sa.text("DELETE FROM analysis_cache_leases WHERE expires_at < now()"))
            await conn.execute(
                sa.text("""UPDATE analysis_cache_artifacts a
                    SET lease_count=(SELECT count(*) FROM analysis_cache_leases l
                                     WHERE l.cache_key=a.cache_key),
                        lease_expires_at=(SELECT max(expires_at) FROM analysis_cache_leases l
                                          WHERE l.cache_key=a.cache_key)""")
            )
            rows = (
                await conn.execute(
                    sa.text("""SELECT cache_key, artifact_sha256, path, encrypted_bytes,
                    extract(epoch from created_at), extract(epoch from accessed_at), lease_count, pinned
                    FROM analysis_cache_artifacts WHERE lease_count=0 AND NOT pinned
                    ORDER BY accessed_at, cache_key""")
                )
            ).all()
            return [_pg_record(row) for row in rows]

    async def delete(self, key: str, artifact_sha256: str) -> bool:
        import sqlalchemy as sa

        async with self.engine.begin() as conn:  # type: ignore[attr-defined]
            result = await conn.execute(
                sa.text(
                    """DELETE FROM analysis_cache_artifacts
                    WHERE cache_key=:key AND artifact_sha256=:sha
                      AND NOT pinned AND NOT EXISTS (
                        SELECT 1 FROM analysis_cache_leases
                        WHERE analysis_cache_leases.cache_key=analysis_cache_artifacts.cache_key
                          AND expires_at >= now())"""
                ),
                {"key": key, "sha": artifact_sha256},
            )
            return result.rowcount == 1

    async def total_bytes(self) -> int:
        import sqlalchemy as sa

        async with self.engine.begin() as conn:  # type: ignore[attr-defined]
            value = await conn.scalar(
                sa.text("""SELECT coalesce(sum(encrypted_bytes), 0) FROM (
                    SELECT artifact_sha256, max(encrypted_bytes) AS encrypted_bytes
                    FROM analysis_cache_artifacts GROUP BY artifact_sha256) AS blobs""")
            )
            return int(value or 0)

    async def artifact_referenced(self, artifact_sha256: str) -> bool:
        import sqlalchemy as sa

        async with self.engine.begin() as conn:  # type: ignore[attr-defined]
            value = await conn.scalar(
                sa.text("""SELECT EXISTS (SELECT 1 FROM analysis_cache_artifacts
                    WHERE artifact_sha256=:sha)"""),
                {"sha": artifact_sha256},
            )
            return bool(value)


def _pg_record(row: Sequence[Any]) -> CacheRecord:
    return CacheRecord(
        str(row[0]),
        str(row[1]),
        str(row[2]),
        int(row[3]),
        float(row[4]),
        float(row[5]),
        int(row[6]),
        bool(row[7]),
    )
