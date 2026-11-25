"""Analysis execution in child processes under a lease and a process capacity.

The async app supervises the pipe and the lease. The model load and the search
run in a spawned process. On Linux the child has an address-space limit. On
macOS the supervisor samples the RSS of the child. Each result holds the method
in `execution.memory_limit_method`. A persisted job supplies no command and no
evaluator path. The production entry is `service.execute`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import multiprocessing
import os
import sys
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from hst.assessment.store import MAX_DOCUMENT_BYTES, AnalysisRun, AssessmentStore, bounded_json

log = logging.getLogger(__name__)
MAX_PROGRESS_BYTES = 64 * 1024
PROCESS_CAPACITY = threading.BoundedSemaphore(1)


def _send(connection: Connection, kind: str, value: dict) -> None:
    payload = json.dumps({"kind": kind, "value": value}, allow_nan=False, separators=(",", ":")).encode()
    limit = MAX_PROGRESS_BYTES if kind == "progress" else MAX_DOCUMENT_BYTES
    if len(payload) > limit:
        raise ValueError("analysis IPC document exceeds its limit")
    connection.send_bytes(payload)


def _runtime_error_signature(exc: BaseException) -> dict[str, Any]:
    tb = traceback.extract_tb(exc.__traceback__)
    if not tb:
        return {"kind": type(exc).__name__}
    frame = tb[-1]
    return {
        "kind": type(exc).__name__,
        "file": Path(frame.filename).name,
        "line": frame.lineno,
        "function": frame.name,
    }


def _execute_child(
    settings: Any,
    inputs: dict,
    connection: Connection,
    cancellation: Any,
    memory_mb: int,
    execute: Callable | None,
    expected_engine: str,
) -> None:
    """The entry point of the spawned process.

    Credentials stay in the memory of the process. An IPC error holds no credential.
    """
    from hst.analysis_model.graph import GraphTooLarge

    try:
        if sys.platform.startswith("linux"):
            import resource

            ceiling = memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
        elif sys.platform != "darwin":
            _send(
                connection, "error", {"error": "Analysis memory supervision is unavailable on this platform."}
            )
            return
        selected: Callable
        if execute is None:
            from hst.assessment.service import engine_version
            from hst.assessment.service import execute as default_execute

            selected = default_execute

            if engine_version(settings) != expected_engine:
                _send(
                    connection,
                    "error",
                    {
                        "error": "The queued analysis engine is unavailable; submit a new run.",
                        "stop_reason": "engine-incompatible",
                    },
                )
                return
        else:
            selected = execute
        last_sent = 0.0

        def progress(value: dict) -> None:
            nonlocal last_sent
            now = time.monotonic()
            if now - last_sent >= 0.2:
                _send(connection, "progress", bounded_json(value))
                last_sent = now

        result = selected(settings, inputs, progress=progress, cancelled=cancellation.is_set)
        _send(connection, "result", bounded_json(result))
    except MemoryError:
        with contextlib.suppress(Exception):
            _send(
                connection,
                "error",
                {"error": "Analysis memory limit reached.", "stop_reason": "memory-limit"},
            )
    except GraphTooLarge as exc:
        with contextlib.suppress(Exception):
            _send(connection, "error", {"error": str(exc), "stop_reason": "scope-too-large"})
    except HTTPException as exc:
        with contextlib.suppress(Exception):
            if 400 <= exc.status_code < 500:
                # A 400 or a 422 refuses the saved definition. Another 4xx refuses
                # the inputs, for example a 404 for an object that is absent from
                # the pinned snapshot.
                reason = "invalid-definition" if exc.status_code in {400, 422} else "input-unavailable"
                _send(connection, "error", {"error": str(exc.detail)[:1000], "stop_reason": reason})
            else:
                _send(connection, "error", _execution_failed(exc))
    except BaseException as exc:
        # Driver exceptions can contain credentials or connection URLs.
        with contextlib.suppress(Exception):
            _send(connection, "error", _execution_failed(exc))
    finally:
        connection.close()


def _execution_failed(exc: BaseException) -> dict:
    return {
        "error": "Analysis execution failed. Review pinned inputs and runtime compatibility.",
        "stop_reason": "execution-failed",
        "runtime_exception": _runtime_error_signature(exc),
    }


async def _resident_mb(pid: int) -> float | None:
    """Return the RSS of `pid` in MiB, from the KiB value of `ps` on Darwin."""
    try:
        process = await asyncio.create_subprocess_exec(
            "ps",
            "-o",
            "rss=",
            "-p",
            str(pid),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        output, _ = await asyncio.wait_for(process.communicate(), timeout=1)
        return int(output.strip()) / 1024 if output.strip() else None
    except (OSError, ValueError, TimeoutError):
        return None


class AnalysisWorker:
    """A worker that claims analysis runs and runs one child process at a time."""

    def __init__(
        self,
        store: AssessmentStore,
        settings: Any,
        *,
        execute: Callable | None = None,
        poll_s: float | None = None,
        lease_seconds: int = 60,
    ) -> None:
        self.store = store
        self.settings = settings
        self.execute = execute
        self.poll_s = float(poll_s if poll_s is not None else getattr(settings, "analysis_poll_s", 1.0))
        self.lease_seconds = lease_seconds
        self.memory_mb = int(getattr(settings, "analysis_memory_mb", 1024))
        self.timeout_s = float(getattr(settings, "analysis_timeout_s", 120))
        if not 0.01 <= self.poll_s <= 60 or not 1 <= lease_seconds <= 3600:
            raise ValueError("invalid analysis polling or lease interval")
        if not 64 <= self.memory_mb <= 65536 or not 0.01 <= self.timeout_s <= 3600:
            raise ValueError("invalid analysis memory or wall-time budget")
        self.name = f"analysis:{os.getpid()}:{uuid.uuid4().hex[:12]}"
        self._context = multiprocessing.get_context("spawn")
        self._active = asyncio.Lock()

    async def run_forever(self) -> None:
        while True:
            try:
                worked = await self.run_once()
                if not worked:
                    await asyncio.sleep(self.poll_s)
            except asyncio.CancelledError:
                raise
            except Exception:
                # The exception text can include a database DSN.
                log.warning("Analysis supervisor operation failed; retrying after poll interval")
                await asyncio.sleep(self.poll_s)

    async def run_once(self) -> bool:
        async with self._active:
            if not PROCESS_CAPACITY.acquire(blocking=False):
                return False
            try:
                run = await self.store.claim_analysis(self.name, lease_seconds=self.lease_seconds)
                if run is None:
                    return False
                await self._run(run)
                return True
            finally:
                PROCESS_CAPACITY.release()

    async def _run(self, run: AnalysisRun) -> None:
        if not run.lease_token:
            raise ValueError("claimed analysis has no lease token")
        requested = run.limits.get("max_seconds", self.timeout_s)
        deadline_s = min(self.timeout_s, float(requested))
        if not 0 < deadline_s <= 3600:
            await self.store.finish_analysis(
                run.id, run.lease_token, state="failed", result={}, error="Invalid analysis deadline."
            )
            return
        receiver, sender = self._context.Pipe(duplex=False)
        cancellation = self._context.Event()
        process = self._context.Process(
            target=_execute_child,
            args=(
                self.settings,
                run.inputs,
                sender,
                cancellation,
                self.memory_mb,
                self.execute,
                run.engine_version,
            ),
            daemon=True,
        )
        started = time.monotonic()
        progress = dict(run.progress)
        result: dict | None = None
        runtime_exception: dict[str, Any] | None = None
        error: str | None = None
        state = "completed"
        stop_reason: str | None = None
        lease_lost = False
        next_heartbeat = started
        next_memory_check = started
        stopping_at: float | None = None
        started_process = False
        try:
            process.start()
            started_process = True
            sender.close()
            while True:
                now = time.monotonic()
                if now >= next_heartbeat:
                    current = await self.store.get_analysis_run(run.id)
                    if current and current.cancel_requested:
                        state, stop_reason = "cancelled", "cancelled"
                        cancellation.set()
                        stopping_at = stopping_at or now
                    elif not await self.store.heartbeat_analysis(
                        run.id, run.lease_token, progress=progress, lease_seconds=self.lease_seconds
                    ):
                        lease_lost = True
                        break
                    next_heartbeat = now + min(self.poll_s, self.lease_seconds / 3)
                if now - started >= deadline_s and stopping_at is None:
                    state, stop_reason = "failed", "time-limit"
                    error = "Analysis wall-time limit reached."
                    cancellation.set()
                    stopping_at = now
                if sys.platform == "darwin" and now >= next_memory_check:
                    resident = await _resident_mb(process.pid) if process.pid else None
                    if resident is not None and resident > self.memory_mb:
                        state, stop_reason = "failed", "memory-limit"
                        error = "Analysis memory limit reached."
                        cancellation.set()
                        stopping_at = now - 1
                    next_memory_check = now + min(self.poll_s, 1.0)
                if receiver.poll():
                    try:
                        # The read of a pipe frame can block on the writer. It runs
                        # in a thread, and the async loop stays free.
                        raw = await asyncio.to_thread(receiver.recv_bytes, MAX_DOCUMENT_BYTES)
                    except (EOFError, OSError):
                        break
                    message = json.loads(raw)
                    if message.get("kind") == "progress":
                        progress = bounded_json(message["value"])
                    elif message.get("kind") == "result":
                        result = bounded_json(message["value"])
                        break
                    elif message.get("kind") == "error":
                        state = "cancelled" if stop_reason == "cancelled" else "failed"
                        error = message["value"]["error"]
                        stop_reason = stop_reason or message["value"].get("stop_reason", "execution-failed")
                        if "runtime_exception" in message["value"]:
                            runtime_exception = message["value"]["runtime_exception"]
                            log.warning(
                                "Analysis run %s failed in subprocess with %s at %s:%s in %s",
                                run.id,
                                runtime_exception.get("kind", "UnknownError"),
                                runtime_exception.get("file", "unknown"),
                                runtime_exception.get("line", "unknown"),
                                runtime_exception.get("function", "unknown"),
                            )
                        else:
                            log.warning(
                                "Analysis run %s failed in subprocess. stop_reason=%s",
                                run.id,
                                stop_reason,
                            )
                        break
                if not process.is_alive() and not receiver.poll():
                    break
                if stopping_at is not None and now - stopping_at >= 0.5:
                    break
                await asyncio.sleep(min(self.poll_s, 0.05))
            if lease_lost:
                return
            if result is None and stop_reason is None:
                state, stop_reason, error = (
                    "failed",
                    "worker-exited",
                    "Analysis process exited without a result.",
                )
            result = result or {}
            if stop_reason:
                result.update(
                    search_complete=False,
                    scoped_search_complete=False,
                    stop_reason=stop_reason,
                    progress=progress,
                )
                if runtime_exception is not None:
                    result["runtime_exception"] = runtime_exception
            result["execution"] = {
                "elapsed_seconds": time.monotonic() - started,
                "deadline_seconds": deadline_s,
                "memory_mb": self.memory_mb,
                "memory_limit_method": "address-space" if sys.platform.startswith("linux") else "rss-monitor",
                "attempt": run.attempt,
            }
            await self.store.heartbeat_analysis(
                run.id, run.lease_token, progress=progress, lease_seconds=self.lease_seconds
            )
            await self.store.finish_analysis(
                run.id,
                run.lease_token,
                result=result,
                state=state,
                dependencies=result.get("dependencies", []),
                error=error,
            )
        except asyncio.CancelledError:
            # Server shutdown leaves the row leased for another worker to reclaim.
            cancellation.set()
            raise
        except Exception:
            cancellation.set()
            await self.store.finish_analysis(
                run.id,
                run.lease_token,
                state="failed",
                result={"search_complete": False, "stop_reason": "supervision-failed"},
                error="Analysis supervision failed.",
            )
        finally:
            if started_process:
                if process.is_alive():
                    process.terminate()
                await asyncio.to_thread(process.join, 1.0)
                if process.is_alive():
                    process.kill()
                    await asyncio.to_thread(process.join, 1.0)
                process.close()
            sender.close()
            receiver.close()
