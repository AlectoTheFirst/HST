"""Durable turns. A turn holds the state of an ask or of an assessment draft in
`ai_messages`.

A turn starts through `Store.start_turn`. `start_turn` writes the question
and a 'pending' assistant row under the caps. Without a conversation id it
writes them to a new ephemeral conversation. The process that accepts the turn
claims the row with a lease before it waits on the execution gate, renews the
lease while the turn waits and runs, writes each tool step to `ai_steps` as
the tool returns, and finishes the row with the result. A poll reads the row.
Any app process answers a poll, also after a restart. The sweeper in every app
process marks a turn whose lease lapsed, or that was never claimed, as
'interrupted'. An interrupted turn is not run again.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import uuid
from collections.abc import Mapping
from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from fastapi.encoders import jsonable_encoder

from hst.app.agent.tools import unframe
from hst.app.ai.envelope import provenance_json
from hst.app.ai.history import result_summary
from hst.app.store import TURN_ACTIVE_STATES, AiMessage, AiStep

if TYPE_CHECKING:
    from hst.app.agent.budget import AskBudget
    from hst.app.agent.tools import ToolCall
    from hst.app.ai.registry import Provenance

log = logging.getLogger("hst.ai")

# The lease a claim or a heartbeat grants. A turn whose process stops renewing
# it is marked 'interrupted' by the next sweep after it lapses.
LEASE_S = 60.0
HEARTBEAT_S = 20.0
SWEEP_INTERVAL_S = 20.0
# A 'pending' row with no lease is marked 'interrupted' after this many seconds.
# Its process stopped between the insert and the claim.
PENDING_GRACE_S = 60.0
# How long the cancel check on the worker thread waits for the row.
CANCEL_READ_S = 5.0
# How long the step callback waits for the `ai_steps` write that gives the
# step its label.
STEP_WRITE_S = 5.0


def owner(app: Any) -> str:
    """The lease owner of this app instance. It is the host name, the process
    id and a random suffix. 2 apps in one process get different owners."""
    value = getattr(app.state, "turn_owner", None)
    if value is None:
        value = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        app.state.turn_owner = value
    return value


def poll_result(message: AiMessage, interrupted: str) -> dict[str, Any]:
    """The poll answer for one assistant row. The status is 'running' while the
    turn waits or runs, 'done' with the stored payload for a finished turn, and
    'error' with a detail otherwise. `interrupted` is the detail of an
    interrupted turn."""
    if message.status in TURN_ACTIVE_STATES:
        return {"status": "running"}
    if message.status == "done":
        return {"status": "done", **((message.envelope or {}).get("payload") or {})}
    if message.status == "interrupted":
        return {"status": "error", "detail": interrupted}
    return {"status": "error", "detail": message.error}


class TurnRunner:
    """The handle of the accepting process for one durable turn.

    `start` inserts the rows and claims the lease. A heartbeat task then
    renews the lease every `HEARTBEAT_S` seconds. `attach` gives a budget the
    cancel check. `stop_requested` runs the same check on the event loop
    before the budget exists. `on_step` runs on the thread of the adapter,
    writes the `ai_steps` row on the event loop and returns the label of the
    step. `finish` waits for those writes, stops the heartbeat and ends the
    row. The constructor must run on the event loop that serves the turn.
    """

    def __init__(
        self,
        store: Any,
        message_id: str,
        user_id: int,
        owner: str,
        *,
        tool_versions: Mapping[str, int] | None = None,
        conversation_id: str | None = None,
    ) -> None:
        self.store = store
        self.id = message_id
        self.conversation_id = conversation_id
        self.user_id = user_id
        self.owner = owner
        self.tool_versions = dict(tool_versions or {})
        self.cancelled = False
        self.lost = False
        self._loop = asyncio.get_running_loop()
        self._budget: AskBudget | None = None
        self._heartbeat: asyncio.Task[None] | None = None
        self._writes: list[Future[AiStep | None]] = []
        self._order = asyncio.Lock()
        self._finished = False

    @classmethod
    async def start(
        cls,
        store: Any,
        user_id: int,
        question: str,
        *,
        owner: str,
        surface: str,
        per_user_cap: int,
        global_cap: int,
        tool_versions: Mapping[str, int] | None = None,
        conversation_id: str | None = None,
    ) -> TurnRunner:
        """Insert the turn under the caps and claim it. With no
        `conversation_id` the turn gets an ephemeral conversation of
        `surface`. Raises `TurnCapExceeded` when a cap is reached, and
        `LookupError` when the conversation is not the user's."""
        message = await store.start_turn(
            user_id,
            conversation_id,
            question,
            None,
            datetime.now(UTC),
            per_user_cap=per_user_cap,
            global_cap=global_cap,
            surface=surface,
        )
        if message is None:
            raise LookupError(conversation_id)
        runner = cls(
            store,
            message.id,
            user_id,
            owner,
            tool_versions=tool_versions,
            conversation_id=message.conversation_id,
        )
        await runner.claim()
        return runner

    async def claim(self) -> None:
        if not await self.store.claim_turn(self.id, self.owner, LEASE_S, datetime.now(UTC)):
            log.warning("turn %s could not be claimed; it runs without a lease", self.id)
            self.lost = True
            return
        self._heartbeat = self._loop.create_task(self._beat())

    async def _beat(self) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_S)
            try:
                alive = await self.store.heartbeat_turn(self.id, self.owner, LEASE_S, datetime.now(UTC))
            except Exception:
                log.warning("the lease of turn %s could not be renewed", self.id, exc_info=True)
                continue
            if not alive:
                log.warning("turn %s lost its lease and stops", self.id)
                self.lost = True
                if self._budget is not None:
                    self._budget.stopped.set()
                return

    def attach(self, budget: AskBudget) -> AskBudget:
        """Give `budget` the cancel check and keep the budget. A lost lease sets
        `budget.stopped`."""
        budget.cancelled = self.should_stop
        self._budget = budget
        if self.lost:
            budget.stopped.set()
        return budget

    def should_stop(self) -> bool:
        """Whether the turn was cancelled or lost its lease. It reads the row
        from the worker thread. On the event loop that serves the turn it does
        not read the row."""
        if self.cancelled or self.lost:
            return True
        with contextlib.suppress(RuntimeError):
            if asyncio.get_running_loop() is self._loop:
                return False
        try:
            read = asyncio.run_coroutine_threadsafe(self.store.get_message(self.user_id, self.id), self._loop)
            message = read.result(timeout=CANCEL_READ_S)
        except Exception:
            log.warning("the cancel flag of turn %s could not be read", self.id, exc_info=True)
            return False
        return self._note_cancel(message)

    async def stop_requested(self) -> bool:
        """The check of `should_stop` for the event loop that serves the turn.
        It reads the row with an await."""
        if self.cancelled or self.lost:
            return True
        try:
            message = await self.store.get_message(self.user_id, self.id)
        except Exception:
            log.warning("the cancel flag of turn %s could not be read", self.id, exc_info=True)
            return False
        return self._note_cancel(message)

    def _note_cancel(self, message: AiMessage | None) -> bool:
        if message is not None and message.cancel_requested and not self.cancelled:
            log.info("turn %s was cancelled", self.id)
            self.cancelled = True
        return self.cancelled

    def on_step(
        self, step: ToolCall, step_id: str | None = None, provenance: Provenance | None = None
    ) -> int | None:
        """Write the `ai_steps` row of one finished tool call and return its
        label. Runs on the adapter's thread, waits up to `STEP_WRITE_S` for the
        write and never raises. The stored result is the unframed text the UI
        shows, stored with its deterministic summary and with `provenance`.
        Returns None when the row was not written in time. On the event loop
        that serves the turn it returns None without a wait."""
        try:
            now = datetime.now(UTC)
            elapsed_ms = step.elapsed_ms or 0
            result = step.ui_result if step.ui_result is not None else unframe(step.result)
            row = {
                "tool": step.name,
                "tool_version": self.tool_versions.get(step.name, 0),
                "arguments": step.arguments,
                "is_error": step.is_error,
                "result": result,
                "result_summary": result_summary(step.name, step.is_error, result),
                "provenance": provenance_json(provenance),
                "started_at": now - timedelta(milliseconds=elapsed_ms),
                "elapsed_ms": elapsed_ms,
                "step_id": step_id,
            }
            write = asyncio.run_coroutine_threadsafe(self._append(row), self._loop)
            self._writes.append(write)
        except Exception:
            log.warning("could not schedule step %s of turn %s", step.name, self.id, exc_info=True)
            return None
        with contextlib.suppress(RuntimeError):
            if asyncio.get_running_loop() is self._loop:
                return None
        try:
            stored = write.result(timeout=STEP_WRITE_S)
        except Exception:
            log.warning("step %s of turn %s has no label", step.name, self.id, exc_info=True)
            return None
        return stored.label if stored is not None else None

    async def _append(self, row: dict[str, Any]) -> AiStep | None:
        # The writes run one at a time in call order. The labels follow the call order.
        async with self._order:
            try:
                return await self.store.append_step(
                    self.id,
                    row["tool"],
                    row["tool_version"],
                    row["arguments"],
                    row["is_error"],
                    row["result"],
                    row["started_at"],
                    row["elapsed_ms"],
                    result_summary=row["result_summary"],
                    provenance=row["provenance"],
                    step_id=row["step_id"],
                )
            except Exception:
                log.warning("could not store step %s of turn %s", row["tool"], self.id, exc_info=True)
                return None

    async def stored_steps(self) -> list[AiStep]:
        """The `ai_steps` rows of the turn written so far, by label. Waits for
        the scheduled writes. A failed write is left out."""
        steps: list[AiStep] = []
        for write in list(self._writes):
            with contextlib.suppress(Exception):
                stored = await asyncio.wrap_future(write)
                if stored is not None:
                    steps.append(stored)
        return sorted(steps, key=lambda step: step.label)

    async def finish(
        self,
        status: str,
        *,
        content: str = "",
        payload: dict[str, Any] | None = None,
        envelope: Mapping[str, Any] | None = None,
        error: str | None = None,
        snapshot_id: str | None = None,
        provider: str | None = None,
        model_requested: str | None = None,
        model_served: str | None = None,
        usage: dict[str, Any] | None = None,
    ) -> None:
        """End the turn. Waits for the scheduled step writes first. A poll that
        reads 'done' then finds every step. The envelope of the row is
        `envelope`, the answer envelope of a finished answer, with `payload`
        under the key `payload`. A turn without a payload stores no envelope.
        Never raises."""
        if self._finished:
            return
        self._finished = True
        for write in list(self._writes):
            with contextlib.suppress(Exception):
                await asyncio.wrap_future(write)
        if self._heartbeat is not None:
            self._heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._heartbeat
        try:
            # `jsonable_encoder` encodes the payload as the poll response does.
            stored = None if payload is None else {**(envelope or {}), "payload": jsonable_encoder(payload)}
            ended = await self.store.finish_turn(
                self.id,
                self.owner,
                status,
                datetime.now(UTC),
                content=content,
                envelope=stored,
                error=error,
                snapshot_id=snapshot_id,
                provider=provider,
                model_requested=model_requested,
                model_served=model_served,
                usage=usage,
            )
        except Exception:
            log.warning("turn %s could not be finished", self.id, exc_info=True)
            return
        if not ended:
            log.warning("turn %s was no longer held by this process; its result is dropped", self.id)


async def sweep_forever(store: Any) -> None:
    """Mark stale turns 'interrupted' every `SWEEP_INTERVAL_S` seconds until
    cancelled. Every app process runs one sweep task. The update is idempotent."""
    while True:
        try:
            marked = await store.expire_stale_turns(datetime.now(UTC), PENDING_GRACE_S)
        except Exception:
            log.warning("the interrupted-turn sweep failed", exc_info=True)
        else:
            if marked:
                log.warning("marked %d AI turns interrupted", marked)
        await asyncio.sleep(SWEEP_INTERVAL_S)


def start_sweeper(store: Any) -> asyncio.Task[None] | None:
    """The sweeper task for this app process, or None when the store has no
    turn rows. The task does not depend on `SCHEDULER_ENABLED`."""
    if not hasattr(store, "expire_stale_turns"):
        return None
    return asyncio.get_running_loop().create_task(sweep_forever(store))
