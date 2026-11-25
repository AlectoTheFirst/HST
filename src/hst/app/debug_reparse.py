"""Re-parse one stored payload in a child process, from the UI.

The re-parse runs the parse of `hst parse-raw` (`collectors/offline.py parse_report`) in a
child process that the server spawns.

- An address-space limit (Linux) turns runaway memory, in the read of the
  payload or in its parse, into a `MemoryError` that the child reports. The
  limit is the address space that the child mapped before it reads the
  payload plus `hst_debug_reparse_memory_mb`.
- A wall-clock limit (`hst_debug_reparse_timeout_s`) ends the child with
  SIGABRT. `faulthandler` in the child writes the stack of every thread to
  the re-parse stack file before the child exits, also while a regex holds
  the GIL.
- The child records the parse under a forced debug capture
  (core/debug_capture.py). The step that was running is on disk for every
  way the child ends.
- A process runs one child at a time (`MAX_CHILDREN`). A re-parse that is
  asked for while a child runs waits for that child.

The collector is built with the stand-in configuration that `parse-raw` uses
without `--config`. The parse reads the payload and opens no session. The
result is sealed beside the raw file (core/rawstore.py
`REPARSE_RESULT_SUFFIX`). If the payload left the raw store while the child
ran, every re-parse file of the payload is removed (`_seal`).

RUN_EXECUTION selects the process of the re-parse. With "inline" the re-parse
runs in the process that answered the request (`start`). With "queue" it is a
`debug.reparse` job (`enqueue`). The process whose executor claims the job
runs it (`reparse_body`). In a split deployment this process is `hst worker`.
The result file of a queued re-parse holds the id of the job until the job
seals its result over the id. Every process reads the same state from the
file (`state`, `resolve`).
"""

from __future__ import annotations

import asyncio
import contextlib
import faulthandler
import logging
import multiprocessing
import os
import signal
import sys
import threading
import time
import traceback
import weakref
from multiprocessing.connection import Connection
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hst.app.crypto import dek
from hst.app.store import JOB_PENDING_STATES
from hst.core import debug_capture, rawstore
from hst.worker import queue

if TYPE_CHECKING:
    from hst.app.store import Job, Store
    from hst.worker.maintenance import Context

logger = logging.getLogger(__name__)

RUNNING = "running"
KIND = "debug.reparse"
# The `triggered_by` of a queued re-parse is this prefix and the id of the
# account that asked for it.
TRIGGER = "debug:"
# This priority is ahead of maintenance and the per-device fan-out, as the
# priority of a queued run is.
PRIORITY = 1
# The count of re-parse children that one process runs at once.
MAX_CHILDREN = 1
_ABORT_GRACE_S = 10.0
_TRACEBACK_LIMIT = 8000
# The interval at which the wait for a child reads its stop flag.
_STOP_POLL_S = 0.5
# The keys of a stored result the payload listing shows.
_SHOWN = ("state", "error", "started_ms", "finished_ms", "exit_code", "peak_rss_kb")
_STOPPED = "the process running the re-parse stopped before the parse finished"

# The task that runs each capture id on this process.
_TASKS: dict[str, asyncio.Task] = {}

# The child slots of the process, per event loop. A process serves from one
# loop, and a semaphore belongs to the loop it first waited on.
_SLOTS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = weakref.WeakKeyDictionary()


def _slot() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    slot = _SLOTS.get(loop)
    if slot is None:
        slot = _SLOTS[loop] = asyncio.Semaphore(MAX_CHILDREN)
    return slot


def _files(raw_path: Path) -> list[Path]:
    return [
        rawstore.sibling(raw_path, rawstore.REPARSE_PREFIX + rawstore.DEBUG_SUFFIX),
        rawstore.sibling(raw_path, rawstore.REPARSE_PREFIX + rawstore.DEBUG_STACK_SUFFIX),
        rawstore.sibling(raw_path, rawstore.REPARSE_RESULT_SUFFIX),
    ]


def _seal(raw_path: Path, result: dict[str, Any], key: str) -> None:
    """Seal `result` as the payload's re-parse result, or remove every
    re-parse file of the payload when it is no longer in the raw store.

    The retention sweep removes a raw file and then the files beside it
    (worker/maintenance.py `_unlink_raw`), and a child that runs meanwhile
    writes its records and stack again. The raw file is looked for after the
    write. A result written while the sweep runs is removed by the sweep, or
    it is found here without its payload and removed."""
    debug_capture.write_reparse(raw_path, result, key)
    if not raw_path.is_file():
        for path in _files(raw_path):
            path.unlink(missing_ok=True)


def _limit_address_space(memory_mb: int) -> None:
    """On Linux, cap this process's address space at what it has mapped now
    plus `memory_mb`."""
    baseline = debug_capture.address_space_kb()
    if sys.platform.startswith("linux") and baseline is not None:
        import resource

        ceiling = baseline * 1024 + memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))


def _child(
    settings: Any,
    collector_type: str,
    source: str,
    host: str,
    run_id: str,
    connection: Connection,
    memory_mb: int,
) -> None:
    """The spawn entry point. It parses one payload and sends the result."""
    raw_path = rawstore.raw_path_of(settings.raw_dir, source, host, run_id)
    stack = rawstore.sibling(raw_path, rawstore.REPARSE_PREFIX + rawstore.DEBUG_STACK_SUFFIX)
    stack_fd = os.open(stack, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    # SIGABRT from the parent at the wall-clock limit dumps every thread here
    faulthandler.enable(file=stack_fd, all_threads=True)
    try:
        from hst.collectors import offline

        collector = offline.build_collector(collector_type, settings, None)
        key = dek(settings)
        # The limit is set before the read. It covers the read of the payload and its parse.
        _limit_address_space(memory_mb)
        raw = rawstore.read(raw_path, key)
        with debug_capture.capture(
            settings,
            source=source,
            host=host,
            run_id=run_id,
            collector=collector.name,
            raw=raw,
            kind="reparse",
            force=True,
        ):
            report = offline.parse_report(collector, raw, path=raw_path.name)
        connection.send({"state": "ok", "report": report.as_dict(), **debug_capture.memory_facts()})
    except MemoryError:
        # The address-space limit was hit.
        with contextlib.suppress(Exception):
            connection.send(
                {
                    "state": "memory",
                    "error": f"reading and parsing the payload needed more than {memory_mb} MiB",
                }
            )
    except Exception as exc:
        with contextlib.suppress(Exception):
            connection.send(
                {
                    "state": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc()[-_TRACEBACK_LIMIT:],
                    **debug_capture.memory_facts(),
                }
            )
    finally:
        connection.close()


def run_isolated(
    settings: Any,
    collector_type: str,
    source: str,
    host: str,
    run_id: str,
    *,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """Run the child to its end and return how it ended. The call blocks.

    `stop`, once set, kills the child and ends the wait."""
    memory_mb = int(settings.hst_debug_reparse_memory_mb)
    timeout_s = float(settings.hst_debug_reparse_timeout_s)
    started = int(time.time() * 1000)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_child,
        args=(settings, collector_type, source, host, run_id, sender, memory_mb),
        name="hst-reparse",
        daemon=True,
    )
    process.start()
    sender.close()
    message: dict[str, Any] | None = None
    timed_out = False
    stopped = False
    deadline = time.monotonic() + timeout_s
    while True:
        # `poll` returns True for data and for the end of the pipe. A child that
        # dies closes its end.
        if receiver.poll(min(max(deadline - time.monotonic(), 0.0), _STOP_POLL_S)):
            with contextlib.suppress(EOFError, OSError):
                message = receiver.recv()
            break
        if stop is not None and stop.is_set():
            stopped = True
            process.kill()
            break
        if time.monotonic() >= deadline:
            if process.is_alive() and process.pid is not None:
                timed_out = True
                with contextlib.suppress(ProcessLookupError):
                    os.kill(process.pid, signal.SIGABRT)
            break
    process.join(_ABORT_GRACE_S)
    if process.is_alive():
        process.kill()
        process.join()
    receiver.close()
    result: dict[str, Any] = {
        "collector": collector_type,
        "started_ms": started,
        "finished_ms": int(time.time() * 1000),
        "exit_code": process.exitcode,
        "limits": {"memory_mb": memory_mb, "timeout_s": timeout_s},
    }
    if message is not None:
        result.update(message)
    elif stopped:
        result.update(state="error", error=_STOPPED)
    elif timed_out:
        result.update(
            state="timeout",
            error=f"the parse did not finish within {timeout_s:.0f} s; the stack file holds where it was",
        )
    else:
        code = process.exitcode
        signal_name = ""
        if code is not None and code < 0:
            with contextlib.suppress(ValueError):
                signal_name = signal.Signals(-code).name
        ended = f"exit code {code} ({signal_name})" if signal_name else f"exit code {code}"
        result.update(state="killed", error=f"the child ended with {ended} and sent no result")
    return result


async def _reparse(settings: Any, collector_type: str, source: str, host: str, run_id: str) -> dict[str, Any]:
    """Run `run_isolated` in a worker thread, once a child slot of this
    process is free.

    On a cancellation while the child runs, the child is killed and waited
    for before the cancellation goes on."""
    stop = threading.Event()
    async with _slot():
        running = asyncio.ensure_future(
            asyncio.to_thread(run_isolated, settings, collector_type, source, host, run_id, stop=stop)
        )
        try:
            return await asyncio.shield(running)
        except asyncio.CancelledError:
            stop.set()
            with contextlib.suppress(Exception):
                await running
            raise


def state(settings: Any, source: str, host: str, run_id: str) -> dict[str, Any] | None:
    """Return the re-parse of one payload, or None.

    The result is the running state for a re-parse that runs in this process,
    and the stored result otherwise. The result file of a queued re-parse
    holds the id of its job (`job_id`) until the job seals its result.
    `resolve` reads the job."""
    if debug_capture.capture_id(source, host, run_id) in _TASKS:
        return {"state": RUNNING}
    raw_path = rawstore.raw_path_of(settings.raw_dir, source, host, run_id)
    result = debug_capture.read_reparse(raw_path, dek(settings))
    if result is None:
        return None
    return {k: result.get(k) for k in (*_SHOWN, "job_id")}


async def resolve(store: Store, stored: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return what `state` read, as the payload listing shows it.

    A queued re-parse is running while its job is queued or running. A job
    that ended and left its id in the result file ended without a sealed
    result. A process that is killed while it runs the job leaves this state."""
    if stored is None:
        return None
    job_id = stored.get("job_id")
    if stored.get("state") != RUNNING or not isinstance(job_id, int):
        return {k: v for k, v in stored.items() if k != "job_id"}
    job = await store.get_job(job_id)
    if job is not None and job.state in JOB_PENDING_STATES:
        return {"state": RUNNING}
    if job is None:
        error = f"the re-parse job {job_id} is no longer recorded and left no result"
    else:
        error = f"the re-parse job {job_id} ended {job.state} and left no result"
        if job.detail:
            error += f": {job.detail}"
    return {"state": "killed", "error": error}


def start(settings: Any, collector_type: str, source: str, host: str, run_id: str) -> bool:
    """Start a re-parse in the background, in this process.

    The result is False when a re-parse of this payload already runs here.
    The files of the previous re-parse are removed first."""
    key_id = debug_capture.capture_id(source, host, run_id)
    if key_id in _TASKS:
        return False
    raw_path = rawstore.raw_path_of(settings.raw_dir, source, host, run_id)
    for path in _files(raw_path):
        path.unlink(missing_ok=True)

    async def work() -> None:
        key = dek(settings)
        try:
            result = await _reparse(settings, collector_type, source, host, run_id)
            await asyncio.to_thread(_seal, raw_path, result, key)
            logger.info("re-parse of %s/%s/%s: %s", source, host, run_id, result.get("state"))
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                _seal(raw_path, {"state": "error", "error": _STOPPED}, key)
            raise
        except Exception as exc:
            logger.exception("re-parse of %s/%s/%s failed to run", source, host, run_id)
            with contextlib.suppress(Exception):
                failed = {
                    "state": "error",
                    "error": f"the re-parse could not run: {type(exc).__name__}: {exc}",
                }
                await asyncio.to_thread(_seal, raw_path, failed, key)
        finally:
            _TASKS.pop(key_id, None)

    _TASKS[key_id] = asyncio.get_running_loop().create_task(work())
    return True


# --- the queued re-parse (RUN_EXECUTION=queue) ----------------------------------


def job_device(source: str, host: str, run_id: str) -> str:
    """Return the `device` of the job row for one stored payload, its path in
    the raw store.

    A source name, a host segment and a run id hold no '/'. `_payload_of`
    splits the path back into the 3 parts."""
    return f"{source}/{host}/{run_id}"


def _payload_of(job: Job) -> tuple[str, str, str] | None:
    parts = (job.device or "").split("/")
    if len(parts) != 3 or not parts[0] or not rawstore._RUN_ID.match(parts[2]):
        return None
    return parts[0], parts[1], parts[2]


async def enqueue(
    store: Store, settings: Any, source: str, host: str, run_id: str, user_id: int
) -> Job | None:
    """Queue a re-parse of one stored payload for the account `user_id`.
    The result is None when a re-parse of that payload is already queued or
    running.

    The id of the job is sealed in the result file of the payload right after
    the insert returns, with no await between the two. An executor in another
    process can claim the job and seal its outcome before that write. A
    refusal at the claim does this without starting a child. Each write
    replaces the whole file, and the id then replaces the outcome. `resolve`
    then lists the job as one that left no result, with the detail of the
    job. The detail holds the refusal or the state in which the parse ended."""
    raw_path = rawstore.raw_path_of(settings.raw_dir, source, host, run_id)
    key = dek(settings)
    job = await queue.enqueue(
        store,
        KIND,
        device=job_device(source, host, run_id),
        priority=PRIORITY,
        max_attempts=1,
        triggered_by=f"{TRIGGER}{user_id}",
    )
    if job is not None:
        marker = {"state": RUNNING, "job_id": job.id, "queued_ms": int(time.time() * 1000)}
        try:
            _seal(raw_path, marker, key)
        except OSError as exc:
            logger.warning(
                "re-parse job %s: the result file of %s could not be written: %s", job.id, raw_path, exc
            )
    return job


async def _collector_type(ctx: Context, job: Job, source: str, raw_path: Path) -> tuple[str | None, str]:
    """The collector type to parse with, or None and why the job is refused.
    The account, the source and the payload are checked again."""
    from hst.app.permissions import permissions_for
    from hst.collectors import REGISTRY

    user_id = job.triggered_by.removeprefix(TRIGGER)
    actor = None
    if user_id != job.triggered_by and user_id.isdecimal():
        actor = await ctx.store.get_user(int(user_id))
    if actor is None or actor.disabled or "runs.manage" not in permissions_for(actor.role):
        return None, "the account that asked for the re-parse no longer holds runs.manage"
    row = await ctx.store.get_source(source)
    if row is None:
        return None, f"source {source} no longer exists"
    if row.type not in REGISTRY:
        return None, f"{source} has no collector type {row.type!r}"
    if not await asyncio.to_thread(raw_path.is_file):
        return None, "the payload is no longer in the raw store"
    return row.type, ""


async def reparse_body(ctx: Context, job: Job) -> str:
    """Run the `debug.reparse` job. It re-parses one stored payload in a child
    of this process and seals the result beside the payload.

    Every way the job ends leaves a result in the result file of the payload
    in place of the id of the job. The result is the result of the child, a
    refusal, a failure to run or a stopped result. A stopped result is
    written when the job is cancelled because the executor is stopping or
    lost the lease. The cancelled job is finished with that result before the
    cancellation goes on. If the payload has left the raw store before the
    job starts or while its child runs, every re-parse file of the payload is
    removed (`_seal`). The detail of the job holds only the state of the
    result."""
    payload = _payload_of(job)
    if payload is None:
        return "skipped: the job names no stored payload"
    source, host, run_id = payload
    raw_path = rawstore.raw_path_of(ctx.settings.raw_dir, source, host, run_id)
    key = dek(ctx.settings)
    sealed = False

    async def seal(result: dict[str, Any]) -> None:
        nonlocal sealed
        # `sealed` is set before the write. A write that is under way finishes
        # in its thread even when this task is cancelled, and the cancel path
        # does not write over it.
        sealed = True
        await asyncio.to_thread(_seal, raw_path, {**result, "job_id": job.id}, key)

    try:
        collector_type, refused = await _collector_type(ctx, job, source, raw_path)
        if collector_type is None:
            await seal({"state": "error", "error": refused})
            return f"skipped: {refused}"
        # The records and the stack of the previous re-parse are removed
        # before the child appends its own. The result file holds the id of
        # this job until `seal`.
        for path in _files(raw_path)[:2]:
            await asyncio.to_thread(path.unlink, missing_ok=True)
        result = await _reparse(ctx.settings, collector_type, source, host, run_id)
        await seal(result)
        logger.info("re-parse of %s: %s", job.device, result.get("state"))
        return f"re-parse {result.get('state')}"
    except asyncio.CancelledError:
        if not sealed:
            with contextlib.suppress(Exception):
                _seal(raw_path, {"state": "error", "error": _STOPPED, "job_id": job.id}, key)
        with contextlib.suppress(Exception):
            await queue.finish(ctx.store, job, ok=True, detail=f"re-parse error: {_STOPPED}")
        raise
    except Exception as exc:
        if not sealed:
            with contextlib.suppress(Exception):
                await seal(
                    {"state": "error", "error": f"the re-parse could not run: {type(exc).__name__}: {exc}"}
                )
        raise
