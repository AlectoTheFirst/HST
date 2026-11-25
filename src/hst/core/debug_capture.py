"""Debug capture of collector loads, and the debug bundle.

Each record is written to the record file before the next step starts.
"""

from __future__ import annotations

import contextlib
import faulthandler
import functools
import hashlib
import io
import json
import logging
import os
import platform
import re
import sys
import tempfile
import threading
import time
import zipfile
from collections.abc import Buffer, Callable, Iterable, Iterator, Sequence, Sized
from contextvars import ContextVar
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, TextIO

from cryptography.fernet import Fernet, InvalidToken

from . import rawstore, redaction
from .uid import slug

logger = logging.getLogger(__name__)

SWITCH_FILE = "switches.json"
_RAW_OUTCOMES_KEY = "_strata_outcomes"  # collectors/base.py RAW_OUTCOMES_KEY
_SAMPLE_INTERVAL_S = 1.0
_MESSAGE_LIMIT = 4000


def _now_ms() -> int:
    return int(time.time() * 1000)


# --- the per-source switch -----------------------------------------------------


def _switch_path(settings: Any) -> Path:
    return settings.hst_data_dir / "debug-capture" / SWITCH_FILE


def switches(settings: Any) -> dict[str, dict[str, Any]]:
    """Return the switches that are still on, by source row name, as {"until_ms", "by"}."""
    try:
        data = json.loads(_switch_path(settings).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    now = _now_ms()
    return {
        str(name): value
        for name, value in data.items()
        if isinstance(value, dict) and int(value.get("until_ms") or 0) > now
    }


def enabled(settings: Any, source: str) -> bool:
    """Return whether loads of `source` are captured now.

    `source` is the row name or its slug. The raw store uses the slug.
    """
    on = switches(settings)
    return source in on or any(slug(name) == slug(source) for name in on)


def set_switch(settings: Any, source: str, *, until_ms: int | None, by: str) -> None:
    """Turn capture on for `source` until `until_ms`, or off with None."""
    path = _switch_path(settings)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = switches(settings)
    if until_ms is None:
        data.pop(source, None)
    else:
        data[source] = {"until_ms": until_ms, "by": by}
    fd, name = tempfile.mkstemp(prefix="switches-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle)
        Path(name).replace(path)
    finally:
        Path(name).unlink(missing_ok=True)


# --- process facts -------------------------------------------------------------


def _proc_status() -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        with Path("/proc/self/status").open() as handle:
            for line in handle:
                key, _, value = line.partition(":")
                if key in ("VmRSS", "VmHWM", "VmSize"):
                    out[key] = int(value.split()[0])
    except (OSError, ValueError):
        pass
    return out


def rss_kb() -> int | None:
    """Resident memory of this process now, in KiB. None where /proc is absent."""
    return _proc_status().get("VmRSS")


def address_space_kb() -> int | None:
    """Virtual size of this process now, in KiB. None where /proc is absent."""
    return _proc_status().get("VmSize")


def _read_cgroup(name: str) -> str | None:
    try:
        return Path("/sys/fs/cgroup", name).read_text().strip()
    except OSError:
        return None


def memory_facts() -> dict[str, Any]:
    """Return the resident and peak memory of this process and the memory usage of its cgroup."""
    status = _proc_status()
    facts: dict[str, Any] = {"rss_kb": status.get("VmRSS"), "peak_rss_kb": status.get("VmHWM")}
    if facts["peak_rss_kb"] is None:
        with contextlib.suppress(Exception):
            import resource

            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            facts["peak_rss_kb"] = peak // 1024 if sys.platform == "darwin" else peak
    current = _read_cgroup("memory.current")
    if current is not None:
        facts["cgroup_current_bytes"] = int(current) if current.isdigit() else current
    return facts


def oom_kills() -> int | None:
    """The cgroup's `oom_kill` counter. A rise across a restart is an OOM kill."""
    events = _read_cgroup("memory.events")
    if events is None:
        return None
    for line in events.splitlines():
        key, _, value = line.partition(" ")
        if key == "oom_kill" and value.strip().isdigit():
            return int(value)
    return None


def _version(package: str) -> str | None:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def environment() -> dict[str, Any]:
    """The facts about this process a parse fault depends on."""
    from hst import __version__

    return {
        "pid": os.getpid(),
        "hst": __version__,
        "commit": os.environ.get("HST_GIT_SHA") or os.environ.get("GIT_SHA"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "textfsm": _version("textfsm"),
        "ntc_templates": _version("ntc-templates"),
        "cgroup_memory_max": _read_cgroup("memory.max"),
        "oom_kill": oom_kills(),
        **memory_facts(),
    }


def payload_summary(raw: Any) -> dict[str, Any]:
    """Return the size and the outcome of each command of the payload, without content."""
    if not isinstance(raw, dict):
        return {"type": type(raw).__name__}
    outcomes = raw.get(_RAW_OUTCOMES_KEY)
    outcomes = outcomes if isinstance(outcomes, dict) else {}
    commands: dict[str, Any] = {}
    for key, value in raw.items():
        if key == _RAW_OUTCOMES_KEY:
            continue
        entry: dict[str, Any] = _size(value) or {"type": type(value).__name__}
        if key in outcomes:
            entry["outcome"] = outcomes[key]
        commands[str(key)] = entry
    return {"commands": commands}


def _size(value: Any) -> dict[str, int] | None:
    if isinstance(value, str):
        return {"chars": len(value), "lines": value.count("\n") + 1 if value else 0}
    if isinstance(value, (list, tuple, dict, set)):
        return {"items": len(value)}
    # Any other sized container, such as a lazy row view, is counted by its
    # length. Iterating it would build every row.
    if isinstance(value, Sized) and not isinstance(value, (bytes, bytearray)):
        return {"items": len(value)}
    return None


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:_MESSAGE_LIMIT]


# --- the record file -----------------------------------------------------------


def _open_append(path: Path) -> int:
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)


class Capture:
    """One load's record file and stack file, open for appending.

    `record` encrypts one JSON record and writes it with one `os.write` on an
    O_APPEND descriptor. No buffer lies between a record and the page cache. A
    SIGKILL after `record` returns loses no record.
    """

    def __init__(self, path: Path, stack_path: Path, key: str, *, stack_after_s: float) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.stack_path = stack_path
        self.stack_after_s = stack_after_s
        self.thread = threading.get_ident()
        self.depth = 0
        self._fernet = Fernet(key.encode())
        self._lock = threading.Lock()
        self._fd = _open_append(path)
        try:
            self.stack_fd = _open_append(stack_path)
        except OSError:
            os.close(self._fd)
            raise

    def record(self, event: str, **fields: Any) -> None:
        body = {"ts_ms": _now_ms(), "event": event, **fields}
        line = self._fernet.encrypt(json.dumps(body, default=str).encode()) + b"\n"
        with self._lock:
            view = memoryview(line)
            while view:
                view = view[os.write(self._fd, view) :]

    def close(self) -> None:
        for fd in (self._fd, self.stack_fd):
            with contextlib.suppress(OSError):
                os.close(fd)
        # An empty stack file is deleted.
        with contextlib.suppress(OSError):
            if self.stack_path.stat().st_size == 0:
                self.stack_path.unlink()


_current: ContextVar[Capture | None] = ContextVar("hst_debug_capture", default=None)


def active() -> bool:
    return _current.get() is not None


class _Watchdog:
    """One `faulthandler` timer for the process.

    `faulthandler.dump_traceback_later` keeps one timer per process. The timer
    is armed for the earliest deadline of the open steps that are not dumped.
    A step is dumped once. At a re-arm, a step whose deadline has passed is
    marked and dumped at once.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._steps: dict[int, list[Any]] = {}  # token: [deadline, fd, dumped]
        self._next = 0

    def enter(self, capture: Capture) -> int:
        with self._lock:
            self._next += 1
            token = self._next
            self._steps[token] = [time.monotonic() + capture.stack_after_s, capture.stack_fd, False]
            self._rearm()
            return token

    def leave(self, token: int) -> None:
        with self._lock:
            self._steps.pop(token, None)
            self._rearm()

    def _rearm(self) -> None:
        faulthandler.cancel_dump_traceback_later()
        pending = [s for s in self._steps.values() if not s[2]]
        if not pending:
            return
        step = min(pending, key=lambda s: s[0])
        remaining = step[0] - time.monotonic()
        if remaining <= 0:
            step[2] = True
            remaining = 0.01
        try:
            faulthandler.dump_traceback_later(remaining, repeat=False, file=step[1], exit=False)
        except (OSError, ValueError, RuntimeError):
            logger.warning("debug capture: the stack watchdog could not be armed", exc_info=True)


_WATCHDOG = _Watchdog()


class _ThreadLogHandler(logging.Handler):
    """Every record the capturing thread emits, into its record file."""

    def __init__(self, capture: Capture) -> None:
        super().__init__()
        self.capture = capture

    def emit(self, record: logging.LogRecord) -> None:
        if record.thread != self.capture.thread:
            return
        try:
            fields: dict[str, Any] = {
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage()[:_MESSAGE_LIMIT],
            }
            if record.exc_info and record.exc_info[1] is not None:
                fields["exception"] = _describe(record.exc_info[1])
            self.capture.record("log", **fields)
        except Exception:
            # A log call here would emit a record back into this handler.
            self.handleError(record)


def _sample(capture: Capture, stop: threading.Event) -> None:
    while not stop.wait(_SAMPLE_INTERVAL_S):
        with contextlib.suppress(Exception):
            capture.record("memory", **memory_facts())


@contextlib.contextmanager
def capture(
    settings: Any,
    *,
    source: str,
    host: str,
    run_id: str,
    collector: str,
    raw: Any,
    kind: str = "run",
    force: bool = False,
) -> Iterator[Capture | None]:
    if settings is None or _current.get() is not None or not (force or enabled(settings, source)):
        yield None
        return
    raw_path = rawstore.raw_path_of(settings.raw_dir, source, host, run_id)
    prefix = rawstore.REPARSE_PREFIX if kind == "reparse" else ""
    try:
        from hst.app.crypto import dek

        cap = Capture(
            rawstore.sibling(raw_path, prefix + rawstore.DEBUG_SUFFIX),
            rawstore.sibling(raw_path, prefix + rawstore.DEBUG_STACK_SUFFIX),
            dek(settings),
            stack_after_s=float(settings.hst_debug_stack_after_s),
        )
    except Exception:
        logger.warning(
            "debug capture: cannot open the capture files of %s/%s/%s", source, host, run_id, exc_info=True
        )
        yield None
        return
    token = _current.set(cap)
    handler = _ThreadLogHandler(cap)
    stop = threading.Event()
    sampler = threading.Thread(target=_sample, args=(cap, stop), name="debug-capture-memory", daemon=True)
    try:
        cap.record(
            "begin",
            kind=kind,
            source=source,
            host=host,
            run_id=run_id,
            collector=collector,
            stack_after_s=cap.stack_after_s,
            environment=environment(),
            payload=payload_summary(raw),
        )
        logging.getLogger().addHandler(handler)
        sampler.start()
        try:
            yield cap
        except BaseException as exc:
            cap.record("finish", status="error", error=_describe(exc), **memory_facts())
            raise
        cap.record("finish", status="ok", **memory_facts())
    finally:
        stop.set()
        # The sampler stops before the record file descriptor closes.
        if sampler.is_alive():
            sampler.join()
        logging.getLogger().removeHandler(handler)
        _current.reset(token)
        cap.close()


@contextlib.contextmanager
def step(name: str, **detail: Any) -> Iterator[dict[str, Any]]:
    """Record one parse step.

    The yielded dict is merged into the `end` record. Outside a capture, the
    step records nothing.
    """
    cap = _current.get()
    if cap is None:
        yield {}
        return
    out: dict[str, Any] = {}
    cap.depth += 1
    depth = cap.depth
    started = time.monotonic()
    cap.record("start", step=name, depth=depth, rss_kb=rss_kb(), **detail)
    token = _WATCHDOG.enter(cap)
    try:
        yield out
    except BaseException as exc:
        elapsed = round((time.monotonic() - started) * 1000, 1)
        cap.record("end", step=name, depth=depth, ms=elapsed, rss_kb=rss_kb(), error=_describe(exc))
        raise
    else:
        elapsed = round((time.monotonic() - started) * 1000, 1)
        cap.record("end", step=name, depth=depth, ms=elapsed, rss_kb=rss_kb(), **out)
    finally:
        _WATCHDOG.leave(token)
        cap.depth -= 1


def traced[F: Callable[..., Any]](fn: F) -> F:
    name = f"{fn.__module__.rsplit('.', 1)[-1]}.{fn.__name__}"

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if _current.get() is None:
            return fn(*args, **kwargs)
        with step(name, input=_size(args[0]) if args else None) as out:
            result = fn(*args, **kwargs)
            out["output"] = _size(result)
            return result

    return wrapper  # type: ignore[return-value]


# --- reading captures back -----------------------------------------------------


class RecordReader:
    """The records of one file, read a line at a time each time it is iterated.

    `unreadable` is how many lines of the last pass did not open. A line cut
    short by a kill is the one expected case. A file that cannot be opened
    reads as no records.
    """

    def __init__(self, path: Path, key: str) -> None:
        self.path = path
        self.unreadable = 0
        self._fernet = Fernet(key.encode())

    def __iter__(self) -> Iterator[dict[str, Any]]:
        self.unreadable = 0
        try:
            handle = self.path.open("rb")
        except OSError:
            return
        with handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    body = json.loads(self._fernet.decrypt(line.rstrip(b"\r\n")))
                except (InvalidToken, ValueError):
                    self.unreadable += 1
                    continue
                if isinstance(body, dict):
                    yield body


def read_records(path: Path, key: str) -> tuple[list[dict[str, Any]], int]:
    """Return the records of one file and the count of lines that did not open."""
    reader = RecordReader(path, key)
    records = list(reader)
    return records, reader.unreadable


class LoadSummary:
    """`summarize` with one record added at a time (`add`).

    A reader that writes the records as it reads them needs no second pass.
    """

    def __init__(self) -> None:
        self.loads: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None
        self._open_steps: list[dict[str, Any]] = []

    def add(self, r: dict[str, Any]) -> None:
        event = r.get("event")
        if event == "begin":
            if self._current is not None:
                self._current["open_steps"] = list(self._open_steps)
            self._open_steps = []
            env = r.get("environment") or {}
            self._current = {
                "kind": r.get("kind"),
                "collector": r.get("collector"),
                "begin_ms": r.get("ts_ms"),
                "last_ms": r.get("ts_ms"),
                "finished": False,
                "status": None,
                "error": None,
                "peak_rss_kb": env.get("peak_rss_kb") or env.get("rss_kb"),
                "cgroup_memory_max": env.get("cgroup_memory_max"),
                "oom_kill_at_begin": env.get("oom_kill"),
                "slowest_steps": [],
                "warnings": 0,
                "errors": 0,
            }
            self.loads.append(self._current)
            return
        current = self._current
        if current is None:
            return
        current["last_ms"] = r.get("ts_ms") or current["last_ms"]
        for key in ("rss_kb", "peak_rss_kb"):
            value = r.get(key)
            if isinstance(value, int) and value > (current["peak_rss_kb"] or 0):
                current["peak_rss_kb"] = value
        if event == "start":
            self._open_steps.append({k: v for k, v in r.items() if k != "event"})
        elif event == "end":
            open_steps = self._open_steps
            for i in range(len(open_steps) - 1, -1, -1):
                if open_steps[i].get("step") == r.get("step") and open_steps[i].get("depth") == r.get(
                    "depth"
                ):
                    del open_steps[i]
                    break
            current["slowest_steps"].append(
                {
                    "step": r.get("step"),
                    "ms": r.get("ms"),
                    **({"error": r["error"]} if r.get("error") else {}),
                }
            )
        elif event == "log":
            level = r.get("level")
            if level == "WARNING":
                current["warnings"] += 1
            elif level in ("ERROR", "CRITICAL"):
                current["errors"] += 1
        elif event == "finish":
            current["finished"] = True
            current["status"] = r.get("status")
            current["error"] = r.get("error")

    def result(self) -> list[dict[str, Any]]:
        """The summaries of every load added so far."""
        loads = [dict(load) for load in self.loads]
        if loads:
            loads[-1]["open_steps"] = list(self._open_steps)
        for load in loads:
            load["slowest_steps"] = sorted(load["slowest_steps"], key=lambda s: -(s.get("ms") or 0))[:10]
        return loads


def summarize(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one summary per load in the file.

    A file holds more than one load when the same payload was loaded again.
    `open_steps` are the steps with a `start` and no `end`, outermost first.
    For a load with no `finish`, they show where the process stopped."""
    summary = LoadSummary()
    for r in records:
        summary.add(r)
    return summary.result()


@dataclass(frozen=True)
class CaptureFile:
    source: str
    host: str
    run_id: str
    raw_path: Path
    path: Path
    size: int
    has_stack: bool


def capture_files(raw_dir: Path) -> list[CaptureFile]:
    """Every run capture under `raw_dir`. A re-parse capture belongs to its
    raw file's bundle and is not listed on its own."""
    found: list[CaptureFile] = []
    if not raw_dir.is_dir():
        return found
    for path in raw_dir.rglob(f"*{rawstore.DEBUG_SUFFIX}"):
        stem = path.name[: -len(rawstore.DEBUG_SUFFIX)]
        if stem.endswith(rawstore.REPARSE_PREFIX):
            continue
        relative = path.parent.relative_to(raw_dir).parts
        source = relative[0] if relative else ""
        host = relative[1] if len(relative) > 1 else ""
        raw_path = path.with_name(stem + rawstore.SUFFIX)
        stack = rawstore.sibling(raw_path, rawstore.DEBUG_STACK_SUFFIX)
        try:
            size = path.stat().st_size
        except OSError:
            # The file was removed after the walk found it. The retention
            # sweep removes a capture with its raw file.
            continue
        found.append(CaptureFile(source, host, stem, raw_path, path, size, stack.is_file()))
    return found


# --- the bundle ----------------------------------------------------------------

# The keyword of a credential line stays, and the text after it is removed.
_SECRET = re.compile(
    r"(?i)(?<![^\W_])(password|secret|key-string|pre-shared-key|community|key|md5|"
    r"authentication-key|auth-key|authkey|authentication|auth|priv|localizedkey|passphrase|psk|private-key|"
    r"token)\b.*$"
)
REDACTED = "<removed>"

# The bundle is handed out in pieces of about this many bytes (`iter_bundle`),
# and the text of an entry is compressed in batches of about this many
# characters.
_BUNDLE_CHUNK = 256 * 1024
_TEXT_BATCH = 64 * 1024

# A JSON container that holds more values than this, counted through every
# level, is written a member at a time (`_json_pieces`). A smaller container is
# encoded whole.
_JSON_WHOLE_VALUES = 512


def _redact_line(line: str, known: Sequence[str] = ()) -> str:
    line = redaction.redact_cli(line)
    return redaction.redact_known(_SECRET.sub(lambda m: f"{m.group(1)} {REDACTED}", line), known)


def redact(text: str, known: Sequence[str] = ()) -> str:
    """Return `text` with every line that holds a credential keyword cut after
    the keyword, and with each of the `known` credential values removed."""
    known = redaction.line_forms(known)
    return "\n".join(_redact_line(line, known) for line in text.split("\n"))


def _redact_structured(value: Any, mode: str) -> Any:
    """`value` is changed in place."""
    if mode != "redacted":
        return value
    return redaction.redact_in_place(value)


def _text_pieces(text: str, mode: str, known: Sequence[str] = ()) -> Iterator[str]:
    """Yield `text`, or `redact(text)` for the redacted mode, in pieces.

    In the redacted mode, each piece is one whole line.
    """
    if mode != "redacted":
        for start in range(0, len(text), _TEXT_BATCH):
            yield text[start : start + _TEXT_BATCH]
        return
    start = 0
    while (end := text.find("\n", start)) >= 0:
        yield _redact_line(text[start:end], known) + "\n"
        start = end + 1
    yield _redact_line(text[start:], known)


def _redacted_pieces(pieces: Iterable[str], known: Sequence[str] = ()) -> Iterator[str]:
    """Apply `redact` to text that arrives in pieces.

    A line is redacted once it is whole.
    """
    pending: list[str] = []
    for piece in pieces:
        if "\n" not in piece:
            pending.append(piece)
            continue
        lines = ("".join(pending) + piece).split("\n")
        pending = [lines.pop()]
        yield "".join(_redact_line(line, known) + "\n" for line in lines)
    yield _redact_line("".join(pending), known)


def _holds_more_than(value: Any, limit: int) -> bool:
    """Whether `value` holds more than `limit` JSON values, counted through
    every level and never past the limit."""
    budget = limit
    stack: list[Iterator[Any]] = [iter((value,))]
    while stack:
        for item in stack[-1]:
            budget -= 1
            if budget < 0:
                return True
            if isinstance(item, dict):
                stack.append(iter(item.values()))
                break
            if isinstance(item, (list, tuple)):
                stack.append(iter(item))
                break
        else:
            stack.pop()
    return False


def _json_pieces(value: Any, level: int = 0) -> Iterator[str]:
    """Yield `json.dumps(value, indent=1, default=str)` in pieces.

    A container that holds more than `_JSON_WHOLE_VALUES` values, counted
    through every level, is written a member at a time. The text of a large
    answer (an NX-OS route table, a list inside a few small objects) is never
    held whole. Every other value is encoded whole by `json.dumps`. A member
    encoded whole is indented to its level by adding `level` spaces after every
    line break of its dump. A line break in JSON text is always structure. A
    dict with a key that is not a string is encoded whole.
    """
    if isinstance(value, (dict, list, tuple)) and _holds_more_than(value, _JSON_WHOLE_VALUES):
        inner = "\n" + " " * (level + 1)
        if isinstance(value, dict):
            if all(isinstance(k, str) for k in value):
                for i, (key, member) in enumerate(value.items()):
                    yield ("{" if i == 0 else ",") + inner + json.dumps(key) + ": "
                    yield from _json_pieces(member, level + 1)
                yield "\n" + " " * level + "}"
                return
        else:
            for i, member in enumerate(value):
                yield ("[" if i == 0 else ",") + inner
                yield from _json_pieces(member, level + 1)
            yield "\n" + " " * level + "]"
            return
    text = json.dumps(value, indent=1, default=str)
    yield text.replace("\n", "\n" + " " * level) if level else text


class _Sink(io.RawIOBase):
    """The bytes that the zip writer writes, held until `take`. The sink cannot seek."""

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[bytes] = []
        self.size = 0

    def writable(self) -> bool:
        return True

    def write(self, data: Buffer) -> int:
        part = bytes(data)
        self._parts.append(part)
        self.size += len(part)
        return len(part)

    def take(self) -> bytes:
        data = b"".join(self._parts)
        self._parts.clear()
        self.size = 0
        return data


# The date and time of a zip entry, to the second.
_DateTime = tuple[int, int, int, int, int, int]


def _now() -> _DateTime:
    now = time.localtime()
    return (now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)


def _info(name: str, stamp: _DateTime) -> zipfile.ZipInfo:
    """Return the header of one entry of the bundle.

    The entry is compressed and readable by its owner alone. Its date is
    `stamp`, the time the build of the bundle started.
    """
    info = zipfile.ZipInfo(name, date_time=stamp)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    return info


def _entry(
    bundle: zipfile.ZipFile, sink: _Sink, name: str, pieces: Iterable[str], *, stamp: _DateTime
) -> Iterator[bytes]:
    """Write one entry of the bundle from its text in pieces, as UTF-8.

    The zip bytes are yielded whenever `_BUNDLE_CHUNK` of them are ready. Every
    entry is written with ZIP64 sizes (`force_zip64`).
    """
    with bundle.open(_info(name, stamp), "w", force_zip64=True) as out:
        batch: list[str] = []
        size = 0
        for piece in pieces:
            batch.append(piece)
            size += len(piece)
            if size < _TEXT_BATCH:
                continue
            out.write("".join(batch).encode())
            batch.clear()
            size = 0
            if sink.size >= _BUNDLE_CHUNK:
                yield sink.take()
        if batch:
            out.write("".join(batch).encode())
    if sink.size >= _BUNDLE_CHUNK:
        yield sink.take()


def _file_pieces(handle: TextIO) -> Iterator[str]:
    """Read a text file opened with `encoding="utf-8", errors="replace"` in
    pieces of `_TEXT_BATCH` characters."""
    while piece := handle.read(_TEXT_BATCH):
        yield piece


def _record_pieces(
    reader: RecordReader, summary: LoadSummary, *, redacted: bool = False, known: Sequence[str] = ()
) -> Iterator[str]:
    """Yield each record as one JSON line and add it to `summary`.

    A redacted record has its credential keys, the credentials in its messages
    and the `known` values removed before it is added and written.
    """
    for record in reader:
        if redacted:
            record = redaction.redact_value(record, known)
        summary.add(record)
        line = json.dumps(record, default=str)
        yield (redaction.redact_known(line, known) if redacted else line) + "\n"


def _message(text: str, redacted: bool, known: Sequence[str]) -> str:
    """Return the text of an exception or of a stack for a reader.

    With `redacted`, each line loses the credentials of the shapes that
    `core/redaction.py` knows, the text after a credential keyword and the
    `known` values.
    """
    if not redacted:
        return text
    return "\n".join(_redact_line(redaction.redact_text(line, known), known) for line in text.split("\n"))


def _described(exc: BaseException, redacted: bool, known: Sequence[str]) -> str:
    """Return `_describe(exc)` for a reader.

    The message passes through `_message`. The name of the exception stays unchanged.
    """
    text = _describe(exc)
    if not redacted:
        return text
    head = f"{type(exc).__name__}: "
    return head + _message(text[len(head) :], True, known)


def _stack_pieces(handle: TextIO, redacted: bool, known: Sequence[str]) -> Iterator[str]:
    """Yield `_file_pieces(handle)`, or for a redacted bundle each line of the
    file through `_message`."""
    if not redacted:
        yield from _file_pieces(handle)
        return
    for line in handle:
        body = line.removesuffix("\n")
        yield _message(body, True, known) + line[len(body) :]


def _json_text(value: Any, redacted: bool, known: Sequence[str]) -> str:
    """Return `json.dumps(value, indent=1, default=str)` for a small entry.

    With `redacted`, the text is redacted by key, by message and by the `known` values.
    """
    if redacted:
        return redaction.redact_known(
            json.dumps(redaction.redact_value(value, known), indent=1, default=str), known
        )
    return json.dumps(value, indent=1, default=str)


def _raw_entries(
    bundle: zipfile.ZipFile,
    sink: _Sink,
    raw: Any,
    *,
    prefix: str,
    mode: str,
    stamp: _DateTime,
    known: Sequence[str] = (),
) -> Iterator[bytes]:
    """Write the commands of the payload, one entry each.

    A payload that is not a dict is one entry, `raw/payload.json`. The entry
    names are the names by which `hst parse-raw` reads a directory capture.
    When 2 commands have the same name, the entry sits at the position of the
    first command and holds the output of the last command. The output of each
    command is removed from `raw` once it is written. The output of a command
    that another command replaces is removed before the first entry."""
    from hst.collectors.offline import raw_file_name

    if not isinstance(raw, dict):
        pieces = _json_pieces(_redact_structured(raw, mode))
        yield from _entry(
            bundle,
            sink,
            f"{prefix}raw/payload.json",
            _redacted_pieces(pieces, known) if mode == "redacted" else pieces,
            stamp=stamp,
        )
        return
    names: dict[str, Any] = {}
    for key, value in raw.items():
        if key == _RAW_OUTCOMES_KEY:
            names["_outcomes.json"] = key
        elif isinstance(value, str):
            names[raw_file_name(str(key))] = key
        else:
            names[f"{raw_file_name(str(key)).rsplit('.', 1)[0]}.json"] = key
    written = set(names.values())
    for key in [k for k in raw if k not in written]:
        del raw[key]
    for name, key in names.items():
        value = raw.pop(key)
        if key == _RAW_OUTCOMES_KEY:
            # The detail of an outcome holds the text that the device answered.
            pieces = _json_pieces(redaction.redact_value(value, known) if mode == "redacted" else value)
        elif isinstance(value, str):
            pieces = _text_pieces(value, mode, known)
        else:
            pieces = _json_pieces(_redact_structured(value, mode))
            if mode == "redacted":
                pieces = _redacted_pieces(pieces, known)
        yield from _entry(bundle, sink, f"{prefix}raw/{name}", pieces, stamp=stamp)
        del value, pieces


def _raw_file_entries(
    bundle: zipfile.ZipFile,
    sink: _Sink,
    raw_path: Path,
    key: str,
    *,
    prefix: str,
    raw_mode: str,
    stamp: _DateTime,
    known: Sequence[str] = (),
) -> Iterator[bytes]:
    """Write every entry that the store holds about one raw file under `prefix`.

    Unless `raw_mode` is `full`, the records, the summary, the stack, the
    re-parse result, the error text and the payload are redacted.
    """
    redacted = raw_mode != "full"
    for kind, record_suffix, stack_suffix in (
        ("", rawstore.DEBUG_SUFFIX, rawstore.DEBUG_STACK_SUFFIX),
        (
            "reparse-",
            rawstore.REPARSE_PREFIX + rawstore.DEBUG_SUFFIX,
            rawstore.REPARSE_PREFIX + rawstore.DEBUG_STACK_SUFFIX,
        ),
    ):
        records_path = rawstore.sibling(raw_path, record_suffix)
        if records_path.is_file():
            # The file is read once. The summary covers the records that the
            # bundle holds, also while a load still appends to the file.
            reader = RecordReader(records_path, key)
            summary = LoadSummary()
            yield from _entry(
                bundle,
                sink,
                f"{prefix}{kind}debug.jsonl",
                _record_pieces(reader, summary, redacted=redacted, known=known),
                stamp=stamp,
            )
            bundle.writestr(
                _info(f"{prefix}{kind}summary.json", stamp),
                _json_text(
                    {"loads": summary.result(), "unreadable_lines": reader.unreadable}, redacted, known
                ),
            )
        # The stack file is opened before its entry starts. The retention prune
        # and the start of an inline re-parse remove this file. A file removed
        # after the entry header is written would end the zip there, after the
        # response went out as a success. A file removed before the open is
        # skipped. An open handle reads the file to its end.
        stack_path = rawstore.sibling(raw_path, stack_suffix)
        if not stack_path.is_file():
            continue
        try:
            handle = stack_path.open(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        except OSError as exc:
            bundle.writestr(_info(f"{prefix}{kind}stack_error.txt", stamp), _described(exc, redacted, known))
            continue
        with handle:
            yield from _entry(
                bundle, sink, f"{prefix}{kind}stack.txt", _stack_pieces(handle, redacted, known), stamp=stamp
            )
    result = read_reparse(raw_path, key)
    if result is not None:
        pieces = _json_pieces(redaction.redact_value(result, known) if redacted else result)
        if redacted:
            pieces = _redacted_pieces(pieces, known)
        yield from _entry(bundle, sink, f"{prefix}reparse.json", pieces, stamp=stamp)
    if raw_mode != "none" and raw_path.is_file():
        try:
            raw = rawstore.read(raw_path, key)
        except Exception as exc:
            bundle.writestr(_info(f"{prefix}raw/_error.txt", stamp), _described(exc, redacted, known))
        else:
            yield from _raw_entries(bundle, sink, raw, prefix=prefix, mode=raw_mode, stamp=stamp, known=known)


def iter_bundle(
    raw_dir: Path,
    key: str,
    raw_paths: list[Path],
    *,
    raw_mode: str,
    extra: dict[str, Any] | None = None,
    known: Sequence[str] = (),
) -> Iterator[bytes]:
    """Yield a zip of the captures, the re-parse result and the payload of every
    raw file, in pieces of about `_BUNDLE_CHUNK` bytes.

    `extra` and the environment of this process are top-level JSON files. In
    every mode except `full`, each entry is redacted. The payload and the
    re-parse result lose their credential keys, and every line passes the
    keyword pass. The records, the summary, the stack, `extra`, the outcomes and
    the error text lose the credential keys and the credentials in their
    messages. Each entry loses each of the `known` credential values, which are
    the values that the sources are configured with.

    The zip is never held whole. The text of an entry is held one batch, one
    line or one small JSON member at a time. The bundle holds one payload at a
    time, and the output of each command leaves memory once its entry is
    written. The zip is written front to back, with the sizes of each entry
    after its data. Every entry is dated with the time the build started.
    """
    sink = _Sink()
    stamp = _now()
    known = redaction.line_forms(known)
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as bundle:
        redacted = raw_mode != "full"
        bundle.writestr(_info("environment.json", stamp), _json_text(environment(), redacted, known))
        for name, value in (extra or {}).items():
            bundle.writestr(_info(name, stamp), _json_text(value, redacted, known))
        root = raw_dir.resolve()
        for raw_path in raw_paths:
            relative = raw_path.resolve().relative_to(root)
            stem = relative.name[: -len(rawstore.SUFFIX)]
            prefix = "captures/" + "/".join((*relative.parent.parts, stem)) + "/"
            yield from _raw_file_entries(
                bundle, sink, raw_path, key, prefix=prefix, raw_mode=raw_mode, stamp=stamp, known=known
            )
    if data := sink.take():
        yield data


# --- re-parse results ----------------------------------------------------------


def write_reparse(raw_path: Path, result: dict[str, Any], key: str) -> None:
    """Encrypt `result` and write it beside the raw file as its re-parse
    result, in place of the one there.

    The result is written to a temporary file and renamed over the result
    file. A reader reads a whole result. Of 2 concurrent writes, one stands
    whole. The name of the temporary file ends in `rawstore.TMP_SUFFIX`.
    worker/maintenance.py `sweep_raw_tmp` removes a temporary file that a
    killed process leaves behind."""
    from hst.app.crypto import encrypt

    path = rawstore.sibling(raw_path, rawstore.REPARSE_RESULT_SUFFIX)
    blob = encrypt(key, json.dumps(result, default=str).encode())
    tmp = rawstore.sibling(raw_path, f"{rawstore.REPARSE_PREFIX}-{os.urandom(4).hex()}{rawstore.TMP_SUFFIX}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
        tmp.replace(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def read_reparse(raw_path: Path, key: str) -> dict[str, Any] | None:
    from hst.app.crypto import decrypt

    path = rawstore.sibling(raw_path, rawstore.REPARSE_RESULT_SUFFIX)
    try:
        body = json.loads(decrypt(key, path.read_bytes()))
    except Exception:
        return None
    return body if isinstance(body, dict) else None


def capture_id(source: str, host: str, run_id: str) -> str:
    """A stable key for one raw file, for the UI's lists."""
    return hashlib.sha256(f"{source}/{host}/{run_id}".encode()).hexdigest()[:16]
