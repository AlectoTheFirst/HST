"""The record of the reads of an evaluation, with their selectors and with failed reads.

The selector of a recorded query is its parameter set. The Cypher text is not
parsed. A read without a complete scope adds a dependency on the whole estate.
A narrower invalidation applies where the reader supplies a complete source scope.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Iterator, Mapping
from typing import Any

from hst.assessment.store import bounded_json, input_digest

MAX_REFERENCES = 4096
MAX_REFERENCE_BYTES = 512 * 1024


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(entry) for key, entry in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((_plain(entry) for entry in value), key=lambda entry: json.dumps(entry, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_plain(entry) for entry in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return {"type": type(value).__name__}


class DependencyRecorder:
    def __init__(self, estate: str, snapshot: str, *, max_references: int = MAX_REFERENCES) -> None:
        if not 1 <= max_references <= MAX_REFERENCES:
            raise ValueError("dependency reference limit must be between 1 and 4096")
        self.estate, self.snapshot = estate, snapshot
        self.max_references = max_references
        self._references: dict[str, dict] = {}
        self._bytes = 0
        self.complete = True
        self.truncated = False

    def record(self, kind: str, *, scope_complete: bool = True, **values: Any) -> None:
        try:
            reference = bounded_json(
                {
                    "kind": kind,
                    "estate": self.estate,
                    "snapshot": self.snapshot,
                    "scope_complete": scope_complete,
                    **_plain(values),
                }
            )
            key = input_digest(reference)
            size = len(json.dumps(reference).encode())
        except (TypeError, ValueError):
            self.truncated = True
            self.complete = False
            return
        if key not in self._references:
            if len(self._references) >= self.max_references or self._bytes + size > MAX_REFERENCE_BYTES:
                self.truncated = True
                self.complete = False
                return
            self._bytes += size
        self.complete = self.complete and scope_complete
        self._references[key] = reference

    def references(self) -> list[dict]:
        refs = list(self._references.values())
        if not self.complete or not refs:
            refs.append(
                {
                    "kind": "estate",
                    "estate": self.estate,
                    "snapshot": self.snapshot,
                    "scope_complete": False,
                    "reason": "dependency-cap" if self.truncated else "unattributed-read",
                }
            )
        return bounded_json(refs)

    def requirement(self, identifier: str, revision: int) -> None:
        self.record("requirement", requirement_id=identifier, revision=revision)

    def assumptions(self, value: dict) -> None:
        self.record("assumptions", value=value, digest=input_digest(value))

    def session(self, session: Any, *, scope: dict | None = None) -> Any:
        return _Session(self, session, scope or {})

    def reader(
        self,
        reader: Any,
        *,
        source: str | None = None,
        device: str | None = None,
        section: str | None = None,
        observed_ms: int | None = None,
        scope: dict | None = None,
    ) -> Any:
        values = {
            key: value
            for key, value in {
                "source": source,
                "device": device,
                "section": section,
                "observed_ms": observed_ms,
                **(scope or {}),
            }.items()
            if value is not None
        }
        return _Reader(self, reader, values)


class _Result:
    def __init__(self, recorder: DependencyRecorder, result: Any, dependency: dict) -> None:
        self.recorder, self.result, self.dependency = recorder, result, dependency
        self.count = 0
        # A result that is not consumed is recorded as a selector dependency.
        # `absence` is recorded only after the result stream is exhausted.
        self._record(False)

    def _record(self, exhausted: bool) -> None:
        self.recorder.record(
            "graph-query",
            **self.dependency,
            rows_observed=self.count,
            absence=self.count == 0 and exhausted,
            exhausted=exhausted,
        )

    def _observe(self, row: Any) -> Any:
        self.count += 1
        value = _plain(row)
        self._objects(value)
        return row

    def _objects(self, value: Any) -> None:
        if isinstance(value, dict):
            uid = value.get("uid")
            if isinstance(uid, str):
                self.recorder.record(
                    "graph-object",
                    uid=uid,
                    properties=sorted(value),
                    property_digest=input_digest(value),
                    **{
                        k: v
                        for k, v in self.dependency.items()
                        if k in {"source", "device", "host", "vrf", "section", "scope_complete"}
                    },
                )
            for nested in value.values():
                if isinstance(nested, (dict, list)):
                    self._objects(nested)
        elif isinstance(value, list):
            for nested in value:
                self._objects(nested)

    def data(self, *args: Any, **kwargs: Any) -> list:
        values = self.result.data(*args, **kwargs)
        for value in values:
            self._observe(value)
        self._record(True)
        return values

    def single(self, *args: Any, **kwargs: Any) -> Any:
        value = self.result.single(*args, **kwargs)
        if value is not None:
            self._observe(value)
        self._record(True)
        return value

    def __iter__(self) -> Iterator:
        for row in self.result:
            yield self._observe(row)
        self._record(True)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.result, name)


class _Session:
    def __init__(self, recorder: DependencyRecorder, session: Any, scope: dict) -> None:
        self.recorder, self.session, self.scope = recorder, session, scope

    def run(self, query: Any, parameters: dict | None = None, **kwargs: Any) -> Any:
        params = {**(parameters or {}), **kwargs}
        dependency = {
            "query_sha256": hashlib.sha256(str(query).encode()).hexdigest(),
            "selector": _plain(params),
            "properties_read": ["*"],
            "scope_complete": bool(self.scope),
            **self.scope,
        }
        try:
            result = self.session.run(query, **params)
        except BaseException:
            self.recorder.record("graph-query", **dependency, failed=True, absence=False)
            raise
        return _Result(self.recorder, result, dependency)

    def execute_read(self, callback: Any, *args: Any, **kwargs: Any) -> Any:
        return self.session.execute_read(
            lambda tx: callback(_Session(self.recorder, tx, self.scope), *args, **kwargs)
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self.session, name)


class _Reader:
    def __init__(self, recorder: DependencyRecorder, reader: Any, scope: dict) -> None:
        self.recorder, self.reader, self.scope = recorder, reader, scope

    def __getattr__(self, name: str) -> Any:
        value = getattr(self.reader, name)
        if name.startswith("_") or name == "close":
            return value
        if not callable(value):
            self.recorder.record(
                "observation", method=name, scope_complete=bool(self.scope), value=_plain(value), **self.scope
            )
            return value

        def read(*args: Any, **kwargs: Any) -> Any:
            try:
                selector = dict(inspect.signature(value).bind(*args, **kwargs).arguments)
            except (TypeError, ValueError):
                selector = {"args": list(args), **kwargs}
            scope = dict(self.scope)
            for key in ("device_uid", "vrf", "af", "table", "session_uid", "direction"):
                if key in selector:
                    scope["device" if key == "device_uid" else key] = selector[key]
            try:
                result = value(*args, **kwargs)
            except BaseException:
                self.recorder.record(
                    "observation",
                    method=name,
                    selector=selector,
                    failed=True,
                    scope_complete=bool(scope.get("source") or scope.get("device")),
                    **scope,
                    absence=False,
                )
                raise
            self.recorder.record(
                "observation",
                method=name,
                selector=selector,
                scope_complete=bool(scope.get("source") or scope.get("device")),
                **scope,
                absence=result is None
                or result is False
                or (isinstance(result, (list, tuple, dict)) and not result),
            )
            return result

        return read


def manifest_changes(before: Any | None, after: Any) -> list[dict]:
    """The source and device scopes that differ between 2 manifests.

    An added or removed source or device is a changed scope. A manifest of
    another estate changes the whole estate.
    """
    estate = after.estate
    if before is None or before.estate != estate:
        return [{"kind": "estate", "estate": estate, "scope_complete": False}]
    changed: dict[str, dict] = {}

    def add(**scope: Any) -> None:
        value = {"estate": estate, **scope}
        changed[input_digest(value)] = value

    sources_before = {source.name: source for source in before.sources}
    sources_after = {source.name: source for source in after.sources}
    for source in sources_before.keys() | sources_after.keys():
        left, right = sources_before.get(source), sources_after.get(source)
        if (
            left is None
            or right is None
            or left.config_sha256 != right.config_sha256
            or left.status != right.status
        ):
            add(source=source)
    old = {(device.source, device.host): device for device in before.devices}
    new = {(device.source, device.host): device for device in after.devices}
    for source, host in old.keys() | new.keys():
        left, right = old.get((source, host)), new.get((source, host))
        if left is None or right is None:
            add(source=source, host=host, change="membership")
            continue
        if any(
            getattr(left, key) != getattr(right, key)
            for key in ("raw_sha256", "outcome", "carried", "device_uids", "expected_sections")
        ):
            add(source=source, host=host, change="configuration-or-coverage")
        if left.fetch_started_ms != right.fetch_started_ms:
            add(source=source, host=host, change="observation-time")
        for section in left.sections.keys() | right.sections.keys():
            if left.sections.get(section) != right.sections.get(section):
                add(source=source, host=host, section=section)
        for table in left.tables.keys() | right.tables.keys():
            if left.tables.get(table) != right.tables.get(table):
                add(source=source, host=host, table=table)
    return list(changed.values())
