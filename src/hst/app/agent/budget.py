"""Wall-clock budget shared by the HTTP runner and its synchronous worker.

Cancelling ``to_thread`` does not stop its worker. After the runner abandons
the ask, the event `stopped` prevents another provider call or tool call. A
call that is in flight runs to its end.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Event
from typing import TYPE_CHECKING

from hst.app.agent.tools import Tool, ToolCall, dispatch

if TYPE_CHECKING:
    from hst.app.agent.base import Usage

log = logging.getLogger("hst.ai")
ASK_TIMEOUT_S = 300.0
ROUND_TIMEOUT_S = 90.0
FINAL_RESERVE_S = 90.0


def _usage() -> Usage:
    # hst.app.agent.base imports this module. The import of Usage runs when a budget is built.
    from hst.app.agent.base import Usage

    return Usage()


@dataclass
class AskBudget:
    timeout: float = ASK_TIMEOUT_S
    started: float = field(default_factory=time.monotonic)
    stopped: Event = field(default_factory=Event)
    steps: list[ToolCall] = field(default_factory=list)
    # The tokens and the round latencies of the provider rounds so far.
    usage: Usage = field(default_factory=_usage)
    rounds: list[int] = field(default_factory=list)
    phase: str = "starting"
    # `poll_cancel` calls it before each provider round and before each tool
    # call. A True result sets `stopped`, and `check` then raises TimeoutError.
    cancelled: Callable[[], bool] | None = None

    def poll_cancel(self) -> None:
        if self.cancelled is not None and not self.stopped.is_set() and self.cancelled():
            self.stopped.set()

    def remaining(self) -> float:
        return max(0.0, self.started + self.timeout - time.monotonic())

    def check(self) -> None:
        if self.stopped.is_set() or self.remaining() <= 0:
            raise TimeoutError("ask budget exhausted")

    def exploring(self) -> bool:
        self.check()
        return self.remaining() > FINAL_RESERVE_S

    def request_timeout(self, *, final: bool = False) -> float:
        self.poll_cancel()
        self.check()
        self.phase = "final answer" if final else "provider"
        available = self.remaining() - (5.0 if final else FINAL_RESERVE_S)
        if available <= 0:
            raise TimeoutError("ask budget exhausted")
        return min(ROUND_TIMEOUT_S, available)

    def invoke(self, tools: list[Tool], name: str, arguments: dict) -> ToolCall:
        self.poll_cancel()
        self.check()
        if not self.exploring():
            return ToolCall(name, arguments, "Time budget exhausted; tool was not run.", is_error=True)
        self.phase = f"tool {name}"
        started = time.monotonic()
        token = current_budget.set(self)
        try:
            outcome = dispatch(tools, name, arguments)
        finally:
            current_budget.reset(token)
        elapsed = time.monotonic() - started
        outcome.elapsed_ms = int(elapsed * 1000)
        self.steps.append(outcome)
        log.info(
            "agent tool %s finished in %.1fs (error=%s)",
            name,
            elapsed,
            outcome.is_error,
            extra={
                "tool": name,
                "latency_ms": outcome.elapsed_ms,
                "outcome": "error" if outcome.is_error else "ok",
            },
        )
        return outcome


current_budget: ContextVar[AskBudget | None] = ContextVar("agent_ask_budget", default=None)


FINAL_INSTRUCTION = (
    "The tool-call or time budget for this question is exhausted. Answer now from "
    "the results already gathered, and state plainly anything that could not be "
    "determined. Do not treat a sample of flows as a complete traffic-policy answer."
)

INCOMPLETE_ANSWER = (
    "The agent could not complete its answer. Completed tool results "
    "are available in the steps below, but they do not establish a complete answer "
    "to the question."
)
