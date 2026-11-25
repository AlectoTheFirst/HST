"""Reads of several archived snapshots through one empty replay target."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import contextmanager
from typing import Any

from hst.core import grapharchive, manifest, replay


class ArchiveSessionError(ValueError):
    pass


class ArchiveSessions:
    def __init__(
        self,
        settings: Any,
        target: Any,
        references: list[dict],
        key: str,
        *,
        evidence: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        """`evidence` is the evidence index of a package. It holds the digest
        and the size of each graph archive as the package stores it."""
        self.settings, self.target, self.key = settings, target, key
        self.records = {}
        self.archives: dict[int, dict[str, Any]] = {}
        self.references = {}
        self.current: int | None = None
        self.restored: set[int] = set()
        self.switches = 0
        self.active_transactions = 0
        occupied = target.run("MATCH (n) RETURN count(n) AS count").single()
        if occupied is None or occupied["count"]:
            raise ArchiveSessionError("The explicitly selected replay target must be empty.")
        # Authenticate every complete archive before making the first mutation.
        for reference in references:
            snapshot = int(reference["snapshot"])
            record = manifest.read(settings, snapshot)
            if record.graph_archive is None:
                raise ArchiveSessionError("A required snapshot has no exact graph archive.")
            if manifest.digest_of(settings, snapshot) != reference["manifest_sha256"]:
                raise ArchiveSessionError("A recorded replay manifest changed.")
            archive = record.graph_archive.model_dump()
            if evidence is not None:
                facts = evidence[archive["path"]]
                archive.update(sha256=facts["sha256"], bytes=facts["bytes"])
            grapharchive.verify(settings, archive, key)
            self.records[snapshot], self.references[snapshot] = record, reference
            self.archives[snapshot] = archive

    def _select(self, snapshot: int) -> None:
        if snapshot == self.current:
            return
        if snapshot not in self.records:
            raise ArchiveSessionError("Read requested a snapshot outside the recorded replay package.")
        if self.active_transactions:
            raise ArchiveSessionError("Cannot switch archived snapshots inside an active transaction.")
        if self.current is not None:
            # The target was empty at construction, and this replay created all of
            # its content. A live target must not be passed to `ArchiveSessions`.
            replay._clear_target(self.target)
        record = self.records[snapshot]
        counts = grapharchive.restore(self.target, self.settings, self.archives[snapshot], self.key, snapshot)
        replay._publish(
            self.settings,
            self.target,
            snapshot,
            reprocessed_from=None,
            manifests=[],
            ok=True,
            exact_counts=counts,
            exact_record=record,
        )
        self.current = snapshot
        self.restored.add(snapshot)
        self.switches += 1

    @contextmanager
    def session(self, reference: dict):
        snapshot = int(reference["snapshot"])
        if self.references.get(snapshot) != reference:
            raise ArchiveSessionError("Read reference differs from the exact replay input.")
        self._select(snapshot)
        yield _SnapshotSession(self, snapshot)


class _BufferedResult:
    def __init__(self, result: Any) -> None:
        self.rows = result.data()

    def data(self, *keys: Any) -> list[dict]:
        if not keys:
            return self.rows
        return [{key: row[key] for key in keys if key in row} for row in self.rows]

    def single(self, strict: bool = False) -> Any:
        if strict and len(self.rows) != 1:
            raise ArchiveSessionError("Expected exactly one replay query result.")
        return self.rows[0] if self.rows else None

    def values(self, *keys: Any) -> list[list]:
        return [[row[key] for key in keys] if keys else list(row.values()) for row in self.rows]

    def value(self, key: Any = 0, default: Any = None) -> list:
        return [
            list(row.values())[key] if isinstance(key, int) and len(row) > key else row.get(key, default)
            for row in self.rows
        ]

    def __iter__(self):
        return iter(self.rows)


class _Transaction:
    def __init__(self, transaction: Any) -> None:
        self.transaction = transaction

    def run(self, query: Any, parameters: dict | None = None, **kwargs: Any) -> _BufferedResult:
        return _BufferedResult(self.transaction.run(query, **{**(parameters or {}), **kwargs}))


class _SnapshotSession:
    def __init__(self, router: ArchiveSessions, snapshot: int) -> None:
        self.router, self.snapshot = router, snapshot

    def run(self, query: Any, parameters: dict | None = None, **kwargs: Any) -> _BufferedResult:
        self.router._select(self.snapshot)
        return _BufferedResult(self.router.target.run(query, **{**(parameters or {}), **kwargs}))

    def execute_read(self, callback: Any, *args: Any, **kwargs: Any) -> Any:
        self.router._select(self.snapshot)
        self.router.active_transactions += 1
        try:
            return self.router.target.execute_read(lambda tx: callback(_Transaction(tx), *args, **kwargs))
        finally:
            self.router.active_transactions -= 1

    def execute_write(self, *args: Any, **kwargs: Any) -> Any:
        raise ArchiveSessionError("Assessment replay evaluators may only read their archived snapshot.")
