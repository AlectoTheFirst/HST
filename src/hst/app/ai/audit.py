"""The audit rows of one ask, written while the ask runs.

The adapters and the tool bodies run on a worker thread with no event loop.
`AuditSink.on_step` takes each tool step from the adapter on that thread and
schedules the store writes on the event loop that started the ask. Each call
writes one `tool.call` row in `ai_events` and the `cypher_events` rows of its
`query_cypher` calls. The `cypher_events` rows hold the step id. `close` is
the flush at the end of the turn. It writes the rows that were queued while
the loop was closed and the `query_cypher` rows of a step that the adapter
did not report.

`McpAudit` is the audit trail of the MCP transports. With the app store it is
an `AuditSink` with origin `mcp`. The user is None on local stdio and the
token user on the HTTP transport. Without a store it writes one `hst.ai` log
line per call.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import uuid
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from hst.app.agent.tools import CypherAudit, ToolCall
from hst.app.store import AiEvent

log = logging.getLogger("hst.ai")

# `ExceptionName: message`, the form `dispatch` gives a failed call's text
_ERROR_CLASS = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*):\s")


@dataclass
class _CypherRow:
    entry: CypherAudit
    step_id: str | None
    at: datetime


class AuditSink:
    """Collects and writes the audit rows of one ask for one user.

    `cypher` is the turn's `ToolContext.cypher_log`. Construct the sink on the
    event loop that serves the ask.
    """

    def __init__(
        self,
        store: Any,
        *,
        user_id: int | None,
        origin: str = "web",
        surface: str | None = None,
        provider: str | None = None,
        model_requested: str | None = None,
        snapshot: str | None = None,
    ) -> None:
        self.store = store
        self.user_id = user_id
        self.origin = origin
        self.surface = surface
        self.provider = provider
        self.model_requested = model_requested
        self.snapshot = snapshot
        self.cypher: list[CypherAudit] = []
        self._rows: list[_CypherRow | AiEvent] = []
        self._loop = asyncio.get_running_loop()
        self._scheduled: list[Future[None]] = []

    def on_step(
        self, step: ToolCall, cypher: list[CypherAudit] | None = None, step_id: str | None = None
    ) -> None:
        """Queue the rows of one finished tool call and schedule their write.

        `cypher` holds the Cypher entries of this call alone. Without it the
        call takes every entry in the sink's `cypher` buffer. `step_id` is the
        id of the rows. A None value is replaced by a new uuid4. The method
        runs on the thread of the adapter and does not raise.
        """
        try:
            step_id = step_id or str(uuid.uuid4())
            now = datetime.now(UTC)
            entries = _drain(self.cypher if cypher is None else cypher)
            rows: list[_CypherRow | AiEvent] = [_CypherRow(e, step_id, now) for e in entries]
            rows.append(self._tool_event(step, step_id, now))
            self._rows.extend(rows)
            self._schedule()
        except Exception:
            log.warning("could not queue the audit rows of tool %s", step.name, exc_info=True)

    async def flush(self) -> None:
        """Write every queued row, oldest first."""
        while self._rows:
            await self._write(self._rows.pop(0))

    async def close(self) -> None:
        """The flush at the end of the turn. It waits for the scheduled writes,
        then writes the `query_cypher` rows that no step took and the rows
        still queued."""
        for future in list(self._scheduled):
            with contextlib.suppress(Exception):
                await asyncio.wrap_future(future)
        now = datetime.now(UTC)
        self._rows.extend(_CypherRow(e, None, now) for e in _drain(self.cypher))
        await self.flush()

    def _schedule(self) -> None:
        if self._loop.is_closed():
            return
        flush = self.flush()
        try:
            self._scheduled.append(asyncio.run_coroutine_threadsafe(flush, self._loop))
        except RuntimeError:
            # The loop closed after the check. The rows stay queued.
            flush.close()

    def _tool_event(self, step: ToolCall, step_id: str, at: datetime) -> AiEvent:
        return AiEvent(
            at=at,
            origin=self.origin,
            event="tool.call",
            outcome="error" if step.is_error else "ok",
            user_id=self.user_id,
            surface=self.surface,
            step_id=step_id,
            provider=self.provider,
            model_requested=self.model_requested,
            tool=step.name,
            snapshot=self.snapshot,
            latency_ms=step.elapsed_ms,
            error_class=_error_class(step),
        )

    async def _write(self, row: _CypherRow | AiEvent) -> None:
        try:
            if isinstance(row, AiEvent):
                await self.store.record_ai_event(row)
            else:
                await self.store.record_cypher_event(
                    user_id=self.user_id,
                    query=row.entry.query,
                    outcome=row.entry.outcome,
                    row_count=row.entry.row_count,
                    byte_count=row.entry.byte_count,
                    at=row.at,
                    origin=self.origin,
                    ai_step_id=row.step_id,
                )
        except Exception:
            kind = row.event if isinstance(row, AiEvent) else f"cypher {row.entry.outcome}"
            log.warning("failed to record an agent audit row (%s)", kind, exc_info=True)


class McpAudit:
    """The audit trail of the MCP transports.

    With the app store, each tool call writes one `tool.call` row in
    `ai_events` with origin `mcp` and surface `mcp`, and each Cypher query
    the call ran writes one `cypher_events` row with origin `mcp`. Both rows
    hold `user_id`, which is the token user on the HTTP transport and None on
    local stdio. With a store, construct it on the event loop of the server.
    Without a store, each call writes one `hst.ai` log line.
    """

    def __init__(self, store: Any = None, *, user_id: int | None = None) -> None:
        self._sink = (
            AuditSink(store, user_id=user_id, origin="mcp", surface="mcp") if store is not None else None
        )

    def record(self, tool: str, elapsed_ms: int, cypher: list[CypherAudit], error: str | None = None) -> None:
        """Record one finished call. The method runs on any thread and does not raise.

        `error` is the error text of a failed call, in the form
        `ExceptionName: message` when an exception ended it. It is None for a
        call that succeeded.
        """
        step = ToolCall(tool, {}, error or "", is_error=error is not None, elapsed_ms=elapsed_ms)
        if self._sink is not None:
            self._sink.on_step(step, cypher)
            return
        outcome = "error" if step.is_error else "ok"
        log.info(
            "mcp tool %s: %s",
            tool,
            outcome,
            extra={
                "surface": "mcp",
                "tool": tool,
                "outcome": outcome,
                "error_class": _error_class(step),
                "latency_ms": elapsed_ms,
            },
        )

    async def close(self) -> None:
        """Write every row still queued. Call it before the store is disposed."""
        if self._sink is not None:
            await self._sink.close()


def _error_class(step: ToolCall) -> str | None:
    """The exception name at the start of a failed call's text, or None."""
    if not step.is_error:
        return None
    text = step.ui_result if step.ui_result is not None else step.result
    match = _ERROR_CLASS.match(text)
    return match.group(1) if match else None


def _drain(buffer: list[CypherAudit]) -> list[CypherAudit]:
    """Take every entry from `buffer`. `list.pop` is atomic. A tool thread can
    append and another drain can take entries during the call."""
    taken = []
    while True:
        try:
            taken.append(buffer.pop(0))
        except IndexError:
            return taken
