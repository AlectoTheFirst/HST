"""Strict bounded reads from a caller supplied, manifest-pinned provider."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol


class ReadError(ValueError):
    """A page or row violated the pinned read contract."""


class TableBudgetExceeded(ReadError):
    """A table holds more rows, bytes or pages than its read budget."""


class PageProvider(Protocol):
    def __call__(self, manifest_digest: str, table: str, offset: int, limit: int) -> ReadPage: ...


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _normalize(
    value: Any, depth: int, fields: list[int], max_depth: int, max_fields: int, max_field_bytes: int
) -> Any:
    if depth > max_depth:
        raise ReadError("row nesting depth budget exceeded")
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and len(value.encode()) > max_field_bytes:
            raise ReadError("field byte budget exceeded")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ReadError("non-finite JSON number")
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReadError("JSON object keys must be strings")
            if len(key.encode()) > max_field_bytes:
                raise ReadError("field byte budget exceeded")
            fields[0] += 1
            if fields[0] > max_fields:
                raise ReadError("field count budget exceeded")
            result[key] = _normalize(item, depth + 1, fields, max_depth, max_fields, max_field_bytes)
        return result
    if isinstance(value, (list, tuple)):
        sequence: list[Any] = []
        for item in value:
            fields[0] += 1
            if fields[0] > max_fields:
                raise ReadError("field count budget exceeded")
            sequence.append(_normalize(item, depth + 1, fields, max_depth, max_fields, max_field_bytes))
        return sequence
    raise ReadError("row contains unsupported JSON value")


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ReadPage:
    manifest_digest: str
    table: str
    offset: int
    total: int | None
    next_offset: int | None
    complete: bool
    rows: tuple[Mapping[str, Any], ...]
    outcome: str = "complete"

    def __post_init__(self) -> None:
        if not isinstance(self.manifest_digest, str) or not self.manifest_digest.strip() or not self.table:
            raise ValueError("manifest_digest and table are required")
        if (
            type(self.offset) is not int
            or (self.total is not None and type(self.total) is not int)
            or (self.next_offset is not None and type(self.next_offset) is not int)
        ):
            raise ValueError("offset and total must be integers")
        if type(self.complete) is not bool:
            raise ValueError("complete must be boolean")
        if self.offset < 0 or (self.total is not None and self.total < 0):
            raise ValueError("offset and total must be nonnegative")
        if self.next_offset is not None and self.next_offset <= self.offset:
            raise ValueError("next_offset must advance the offset")
        if self.outcome not in {"complete", "missing"}:
            raise ValueError("outcome must be complete or missing")
        if self.outcome == "missing" and self.complete:
            raise ValueError("missing page cannot be complete")
        object.__setattr__(self, "rows", tuple(dict(row) for row in self.rows))


@dataclass(frozen=True, slots=True)
class MaterializedTable:
    manifest_digest: str
    table: str
    rows: tuple[Mapping[str, Any], ...]
    total: int
    complete: bool
    fingerprint: str
    outcome: str = "complete"

    def __post_init__(self) -> None:
        if type(self.total) is not int or type(self.complete) is not bool:
            raise ValueError("total must be an integer and complete must be boolean")
        if self.total < 0 or self.total < len(self.rows):
            raise ValueError("total cannot be less than rows")
        normalized = tuple(_normalize(dict(row), 0, [0], 32, 100_000, 1_000_000) for row in self.rows)
        object.__setattr__(self, "rows", tuple(_freeze(row) for row in normalized))

    @property
    def status(self) -> str:
        if self.outcome == "missing":
            return "missing"
        return (
            "complete-empty"
            if self.complete and not self.rows
            else "complete"
            if self.complete
            else "partial"
        )


class BoundedTableReader:
    def __init__(
        self,
        provider: PageProvider | Callable[[str, str, int, int], ReadPage],
        manifest_digest: str,
        *,
        max_rows: int = 1_000_000,
        max_page_rows: int = 10_000,
        max_bytes: int = 256 * 1024 * 1024,
        page_size: int = 1_000,
        row_id_key: str = "id",
        max_pages: int = 100_000,
        max_depth: int = 32,
        max_fields: int = 100_000,
        max_field_bytes: int = 1_000_000,
    ) -> None:
        budgets = (
            max_rows,
            max_page_rows,
            max_bytes,
            page_size,
            max_pages,
            max_depth,
            max_fields,
            max_field_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in budgets):
            raise ValueError("read budgets must be positive integers")
        self.provider, self.manifest_digest = provider, manifest_digest
        self.max_rows, self.max_page_rows, self.max_bytes = max_rows, max_page_rows, max_bytes
        self.page_size, self.row_id_key, self.max_pages = page_size, row_id_key, max_pages
        self.max_depth, self.max_fields, self.max_field_bytes = max_depth, max_fields, max_field_bytes

    def read(self, table: str) -> MaterializedTable:
        offset, expected_total, complete, outcome = 0, _MISSING, False, "complete"
        rows: list[Mapping[str, Any]] = []
        seen: set[str] = set()
        used_bytes = 0
        for _ in range(self.max_pages):
            if callable(self.provider):
                page = self.provider(self.manifest_digest, table, offset, self.page_size)
            else:
                page = self.provider.read_page(self.manifest_digest, table, offset, self.page_size)
            if page.manifest_digest != self.manifest_digest or page.table != table or page.offset != offset:
                raise ReadError("manifest, table, or offset drift")
            if expected_total is _MISSING:
                expected_total = page.total
            elif page.total != expected_total:
                raise ReadError("mismatched totals across pages")
            if page.total is not None and page.total > self.max_rows:
                raise TableBudgetExceeded("advertised total exceeds row budget")
            if len(page.rows) > self.max_page_rows:
                raise ReadError("page or table row budget exceeded")
            if len(rows) + len(page.rows) > self.max_rows:
                raise TableBudgetExceeded("page or table row budget exceeded")
            normalized = [
                _normalize(dict(row), 0, [0], self.max_depth, self.max_fields, self.max_field_bytes)
                for row in page.rows
            ]
            page_bytes = sum(len(_json(row)) for row in normalized)
            if used_bytes + page_bytes > self.max_bytes:
                raise TableBudgetExceeded("table byte budget exceeded")
            for row in normalized:
                if (
                    self.row_id_key not in row
                    or not isinstance(row[self.row_id_key], str)
                    or not row[self.row_id_key].strip()
                ):
                    raise ReadError("row is missing a stable string identifier")
                key = row[self.row_id_key]
                if key in seen:
                    raise ReadError("duplicate row identifier")
                seen.add(key)
            rows.extend(_freeze(row) for row in normalized)
            used_bytes += page_bytes
            if page.next_offset is None:
                complete, outcome = page.complete, page.outcome
                break
            if page.complete or page.next_offset != offset + len(page.rows):
                raise ReadError("page offset discontinuity")
            offset = page.next_offset
        else:
            raise TableBudgetExceeded("page count budget exceeded")
        total = expected_total if expected_total is not _MISSING and expected_total is not None else len(rows)
        if outcome == "missing" and rows:
            raise ReadError("missing table cannot contain rows")
        if total < len(rows):
            raise ReadError("table total is less than rows")
        if complete and total != len(rows):
            raise ReadError("complete table has mismatched total")
        keyed = sorted(((row[self.row_id_key], _thaw(row)) for row in rows), key=lambda item: item[0])
        payload = _json(
            {
                "manifest_digest": self.manifest_digest,
                "table": table,
                "complete": complete,
                "outcome": outcome,
                "total": total,
                "rows": keyed,
            }
        )
        return MaterializedTable(
            self.manifest_digest,
            table,
            tuple(rows),
            total,
            complete,
            hashlib.sha256(payload).hexdigest(),
            outcome,
        )

    read_table = read


PinnedTableReader = BoundedTableReader
Page = ReadPage
SnapshotTable = MaterializedTable
_MISSING = object()
