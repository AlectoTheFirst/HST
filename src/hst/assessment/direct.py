"""Bounded synchronous evaluations using the assessment worker's child entry."""

from __future__ import annotations

import contextlib
import json
import multiprocessing
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException

from hst.assessment.jobs import PROCESS_CAPACITY, _execute_child
from hst.assessment.store import MAX_DOCUMENT_BYTES, bounded_json

if TYPE_CHECKING:
    from hst.assessment.evaluation import RequestBody


def _run_owned(settings: Any, inputs: dict, *, execute: Callable | None = None) -> dict:
    """Run `inputs` in one child process and return its result.

    The child is ended before the function returns. `execute` is a test seam.
    Without it the child runs `assessment.service.execute`.
    """
    from hst.assessment.service import engine_version

    if not getattr(settings, "analysis_enabled", True):
        raise HTTPException(503, "Analysis execution is disabled.")
    memory = int(settings.analysis_memory_mb)
    timeout = float(settings.analysis_timeout_s)
    if not 64 <= memory <= 65536 or not 0 < timeout <= 3600:
        raise ValueError("invalid analysis process budget")
    document = bounded_json(inputs)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    cancellation = context.Event()
    process = context.Process(
        target=_execute_child,
        args=(settings, document, sender, cancellation, memory, execute, engine_version(settings)),
        daemon=True,
    )
    messages: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
    stopped = threading.Event()

    def receive() -> None:
        # The pipe is read in this thread. A read of an incomplete frame does not
        # block the deadline of the supervising thread or the termination of the child.
        try:
            while not stopped.is_set():
                payload = receiver.recv_bytes(MAX_DOCUMENT_BYTES)
                while not stopped.is_set():
                    try:
                        messages.put(payload, timeout=0.1)
                        break
                    except queue.Full:
                        continue
        except (EOFError, OSError):
            with contextlib.suppress(queue.Full):
                messages.put_nowait(None)

    started = False
    reader: threading.Thread | None = None
    try:
        process.start()
        started = True
        sender.close()
        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        next_memory_check = 0.0
        while True:
            now = time.monotonic()
            if now >= deadline:
                raise HTTPException(503, "Analysis time limit reached; no complete result is available.")
            if sys.platform == "darwin" and now >= next_memory_check:
                next_memory_check = now + 1
                measured = subprocess.run(  # noqa: S603 - fixed executable and numeric child PID
                    ["/bin/ps", "-o", "rss=", "-p", str(process.pid)],
                    capture_output=True,
                    text=True,
                    timeout=1,
                    check=False,
                ).stdout.strip()
                if measured and int(measured) > memory * 1024:
                    raise HTTPException(503, "Analysis memory limit reached.")
            try:
                payload = messages.get(timeout=min(0.1, max(0.001, deadline - now)))
            except queue.Empty:
                if not process.is_alive() and reader is not None and not reader.is_alive():
                    raise HTTPException(503, "Analysis process exited without a result.") from None
                continue
            if payload is None:
                raise HTTPException(503, "Analysis process exited without a result.")
            message = json.loads(payload)
            if message.get("kind") == "result":
                return bounded_json(message["value"])
            if message.get("kind") == "error":
                # Child diagnostics contain no exception messages or credentials.
                raise HTTPException(503, message["value"]["error"])
    finally:
        cancellation.set()
        stopped.set()
        if started:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
        receiver.close()
        sender.close()
        if reader is not None:
            reader.join(timeout=1)
        if started and not process.is_alive():
            process.close()


class CapacityBusy(HTTPException):
    """No process slot is free. The status is 503, as for any other analysis
    failure. A caller that records the busy slot catches this class."""

    def __init__(self) -> None:
        super().__init__(503, "Analysis capacity is busy; retry or submit a queued assessment.")


def run_isolated(settings: Any, inputs: dict, *, execute: Callable | None = None) -> dict:
    """Run `inputs` in a child process that holds the process slot of `PROCESS_CAPACITY`.

    The durable jobs use the same slot. `CapacityBusy` is raised when the slot is taken.
    """
    if not PROCESS_CAPACITY.acquire(blocking=False):
        raise CapacityBusy()
    try:
        return _run_owned(settings, inputs, execute=execute)
    finally:
        PROCESS_CAPACITY.release()


def evaluate_pinned(
    settings: Any,
    session: Any,
    snap: Any,
    *,
    intents: list[dict],
    requirement: str | None,
    request: dict | None,
    mode: str,
) -> dict:
    """Validate one question at the pinned snapshot and evaluate it in a child process."""
    from hst.assessment import evaluation as ev
    from hst.assessment.models import Analyze
    from hst.assessment.population_request import PopulationBindingError, bind_pinned_request
    from hst.assessment.request_document import request_document
    from hst.assessment.service import observation_floor
    from hst.core import manifest

    if (requirement is None) == (request is None):
        raise HTTPException(400, "State exactly one request or graph requirement.")
    if mode not in {"possible", "guaranteed"}:
        raise HTTPException(400, "Mode must be possible or guaranteed.")
    if snap.cts is None or snap.manifest is None:
        raise HTTPException(409, "A published snapshot with an evidence manifest is required.")
    if request is not None:
        try:
            request = bind_pinned_request(settings, session, snap, request)
        except PopulationBindingError as exc:
            raise HTTPException(422, str(exc)) from exc
    body = ev.EvaluateBody(
        intents=intents,
        requirement=requirement,
        request=ev.RequestBody.model_validate(request) if request is not None else None,
        mode=mode,
    )
    if body.request is None:
        req = ev._request_from_requirement(session, str(body.requirement))
        declaration = request_document(req)
    else:
        ev._request_from_body(body.request)
        declaration = body.request.model_dump(mode="json")
    options = Analyze(kind="evaluate").model_dump(mode="json")
    options["limits"]["max_seconds"] = min(float(settings.analysis_timeout_s), 300)
    result = run_isolated(
        settings,
        {
            "definition": {"request": declaration, "mode": mode, "intents": intents},
            "analysis": options,
            "snapshot_refs": [
                {
                    "snapshot": str(snap.cts),
                    "manifest_sha256": manifest.digest_of(settings, snap.cts),
                    "estate": snap.manifest.estate,
                    "observation_floor_ms": observation_floor(snap.manifest),
                }
            ],
        },
    )
    if requirement and "request" in result:
        result["request"]["requirement"] = requirement
    return result


def evaluate_request(
    settings: Any,
    session: Any,
    snap: Any,
    *,
    intents: list[dict],
    requirement: str | None,
    request: RequestBody | dict[str, Any] | None,
    mode: str,
) -> dict:
    """Answer one service-impact question over a pinned session.

    `POST /api/impact/evaluate`, the agent tool and the MCP tool call this
    function, and each adds its own `snapshot` and `run` keys. A change set
    above `MAX_INTENTS` is refused before any engine read. Both engines run
    through `evaluate_pinned` in a child process. The child holds the process
    slot and is ended at `min(analysis_timeout_s, 300)` seconds. `request` is
    an inline request set as a `RequestBody` or as its JSON form. Errors are
    raised as `HTTPException`, and each caller maps them to its own error form.
    """
    from pydantic import BaseModel

    from hst.assessment.evaluation import MAX_INTENTS
    from hst.results.project import project_evaluation

    if len(intents) > MAX_INTENTS:
        raise HTTPException(422, f"a change set states at most {MAX_INTENTS} intents")
    body = evaluate_pinned(
        settings,
        session,
        snap,
        intents=intents,
        requirement=requirement,
        request=request.model_dump(mode="json") if isinstance(request, BaseModel) else request,
        mode=mode,
    )
    # `project_evaluation` adds the condition answer in the result vocabulary to
    # the fields of the engine.
    if isinstance(body, dict):
        project_evaluation(body, mode)
    return body
