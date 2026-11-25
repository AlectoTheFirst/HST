"""A fake graph session for the catalogue tool tests.

One object answers every read seam the tools use: the autocommit pointer and
run-status reads (`session.run`), the managed reads of `path._read` and
`cycle._read` (`tx.run(query, **params)`), and `run_readonly`
(`tx.run(query, parameters=...)`, iterated record by record). Rows come from
responders matched by a marker in the query text.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

from hst.app.ai.registry import Principal, ToolContext
from hst.core import db as dbmod
from hst.core import snapshot as snapshotmod

Rows = list[dict[str, Any]]
Answer = Rows | Callable[[dict[str, Any]], Rows]


class FakeRecord:
    def __init__(self, row: dict[str, Any]) -> None:
        self._row = row

    def data(self) -> dict[str, Any]:
        return dict(self._row)

    def values(self) -> list[Any]:
        return list(self._row.values())


class FakeResult:
    def __init__(self, rows: Rows) -> None:
        self._rows = rows

    def data(self) -> Rows:
        return [dict(r) for r in self._rows]

    def __iter__(self):
        return iter([FakeRecord(r) for r in self._rows])

    def keys(self) -> list[str]:
        return list(self._rows[0]) if self._rows else []

    def consume(self) -> None:
        return None


class FakeGraph:
    """A graph session. `current` is the pointer's run, `retained` the runs
    whose graph is retained, and `responders` pairs a query marker with rows
    or with a function of the query parameters."""

    def __init__(
        self,
        responders: Iterable[tuple[str, Answer]] = (),
        *,
        current: int | None = 4000,
        retained: Iterable[int] = (3000, 4000),
    ) -> None:
        self.responders = list(responders)
        self.current = current
        self.retained = set(retained)
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.session_kwargs: list[dict[str, Any]] = []

    def rows(self, query: str, params: dict[str, Any]) -> Rows:
        if query == snapshotmod._RETAINED_GRAPH:
            return [{"uid": "dev:a"}] if params.get("snap") in self.retained else []
        self.calls.append((query, params))
        for marker, answer in self.responders:
            if marker in query:
                return answer(params) if callable(answer) else answer
        return []

    def reads(self, marker: str) -> list[dict[str, Any]]:
        """The parameters of every read whose text holds `marker`."""
        return [params for query, params in self.calls if marker in query]

    def __enter__(self) -> FakeGraph:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def run(self, query: str, **params: Any) -> FakeResult:
        if "CyclePointer" in query:
            return FakeResult([{"current": self.current}] if self.current is not None else [])
        return FakeResult(self.rows(query, params))

    def execute_read(self, work: Any, *args: Any) -> Any:
        graph = self

        class _Tx:
            def run(self, query: str, parameters: dict[str, Any] | None = None, **params: Any) -> FakeResult:
                return FakeResult(graph.rows(query, {**(parameters or {}), **params}))

        return work(_Tx())


def install(monkeypatch: Any, graph: FakeGraph) -> FakeGraph:
    """Every `dbmod.session` opens `graph`."""

    @contextmanager
    def session(settings: Any, **kwargs: Any):
        graph.session_kwargs.append(kwargs)
        yield graph

    monkeypatch.setattr(dbmod, "session", session)
    return graph


def settings(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "neo4j_database": "neo4j",
        "manifests_dir": None,
        "hst_ai_cypher_pinning": "refuse",
        "hst_ai_tool_validation": "enforce",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def context(principal: Principal | None = None, **overrides: Any) -> ToolContext:
    return ToolContext(
        settings=settings(**overrides),
        principal=principal if principal is not None else Principal.local(),
        surface="mcp",
        cypher_log=[],
    )


def call(name: str, arguments: dict[str, Any], ctx: ToolContext | None = None) -> tuple[bool, dict[str, Any]]:
    """Run one catalogue tool through the registry pipeline.

    Returns whether the call failed, and the envelope or the error payload.
    """
    from hst.twin_tools import catalogue_registry

    registry = catalogue_registry()
    outcome = registry.invoke(ctx if ctx is not None else context(), name, arguments)
    if outcome.is_error:
        assert outcome.error is not None
        return True, outcome.error
    envelope = json.loads(outcome.ui_text)
    spec = registry.get(name)
    assert spec is not None and spec.output_model is not None
    # the envelope a client receives validates against the published output model
    spec.output_model.model_validate(envelope)
    return False, envelope
