"""The HTTP exchange trace of one fetch holds every request of a collector
and the response of the management plane.

The trace is off by default. `Settings.hst_http_trace` lists the sources to
trace, or holds `*` for all sources (`Settings.http_trace_enabled`). For a
traced source, `collectors.base.fetch_traced` activates a trace around the
fetch. `collectors.http.client` attaches the event hooks of the active trace
to every client that it builds. The trace spools to a private gzip file during
the fetch. `seal` writes the trace beside the raw file as
`<run_id>.http.jsonl.gz.enc` when the run id is known. The trace file has the
same data key and directory modes as the raw snapshot (core/rawstore.py). Only
clients from `collectors.http.client` are traced. A collector with its own
async client records nothing.

Each exchange is one JSON line.

    {"ts": <epoch ms>, "method": "POST", "url": "https://vco/portal/rest/...",
     "status": 200, "elapsed_ms": 112, "request": {"headers": {...}, "body": ...},
     "response": {"headers": {...}, "body": ...}}

Each body is bounded by `BODY_LIMIT` bytes. A body over the bound is cut and
marked `truncated`. A body is JSON-decoded when the content type contains
`json` or the body starts with `{` or `[`. A form-encoded body is written as
`form`, a list of `[name, value]` pairs in wire order. A form body over the
bound drops its last pair. Any other body is text. Only the headers in
`REQUEST_HEADERS` and `RESPONSE_HEADERS` are written. `Authorization`,
`Cookie` and `Set-Cookie` are in neither list.

The credential keys are those of `core/redaction.py`. The value of a
credential key is replaced by `[redacted]` in a JSON body at any depth, on
both sides, and in a form body. A JSON body over the bound is redacted before
it is cut. A JSON body that starts with a byte order mark is read as JSON.
`redaction.redact_text` replaces the credentials that it recognizes in a text
body. The URL is written without the user name and the password, and with the
value of a credential-named query parameter replaced. `redaction.redact_known`
then removes the credential values of the source configuration
(`HttpTrace.secrets`) from each line.
"""

from __future__ import annotations

import contextlib
import contextvars
import gzip
import json
import logging
import os
import stat
import tempfile
import threading
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

import httpx

from hst.core.redaction import REDACTED, is_secret_key, redact, redact_known, redact_text

logger = logging.getLogger(__name__)

BODY_LIMIT = 1_048_576  # bytes per request or response body
# The spool file of an open trace is `<spool_dir>/<SPOOL_PREFIX><random><SPOOL_SUFFIX>`
# (`HttpTrace`). The name starts with a dot. No source directory name starts
# with a dot (app/sources.py `NAME_PATTERN`). No raw-store reader matches the name.
SPOOL_PREFIX = ".http-trace-"
SPOOL_SUFFIX = ".jsonl.gz"
REQUEST_HEADERS = ("content-type", "accept")
RESPONSE_HEADERS = (
    "content-type",
    "content-length",
    "retry-after",
    "x-request-id",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
)
_STARTED = "hst_trace_started"

_current: contextvars.ContextVar[HttpTrace | None] = contextvars.ContextVar("hst_http_trace", default=None)


def current() -> HttpTrace | None:
    """The trace active for this fetch, or None when nothing is traced."""
    return _current.get()


@contextlib.contextmanager
def activate(trace: HttpTrace | None) -> Iterator[None]:
    """Make `trace` the active trace for the calls inside the block, in this
    thread or task. `asyncio.to_thread` copies the context. A plain thread
    pool does not copy it. The block belongs in the thread that calls
    `fetch()`."""
    token = _current.set(trace)
    try:
        yield
    finally:
        _current.reset(token)


def _url(url: httpx.URL) -> str:
    """Return the URL for the trace, without the user name and the password,
    and with the value of a credential-named query parameter replaced. A URL
    with none of them is returned unchanged."""
    items = url.params.multi_items()
    if not url.userinfo and not any(is_secret_key(name) for name, _ in items):
        return str(url)
    clean = url.copy_with(username=None, password=None)
    if any(is_secret_key(name) for name, _ in items):
        clean = clean.copy_with(
            params=[(name, REDACTED if is_secret_key(name) else value) for name, value in items]
        )
    return str(clean)


_BOM = b"\xef\xbb\xbf"


def _looks_like_json(raw: bytes) -> bool:
    head = raw[:64].removeprefix(_BOM).lstrip()
    return head[:1] in (b"{", b"[")


def _body(raw: bytes, content_type: str) -> dict[str, Any]:
    """Return a bounded, decoded body record. A form body is parsed into
    pairs and a JSON body is decoded, and both are redacted. Any other body is
    text redacted by `redact_text`."""
    record: dict[str, Any] = {"bytes": len(raw)}
    cut = raw[:BODY_LIMIT]
    if len(raw) > BODY_LIMIT:
        record["truncated"] = True
    kind = content_type.lower()
    if "x-www-form-urlencoded" in kind:
        pairs = parse_qsl(cut.decode("utf-8", errors="replace"), keep_blank_values=True)
        if "truncated" in record and pairs:
            pairs = pairs[:-1]  # the cut can split the last pair
        record["form"] = [[name, REDACTED if is_secret_key(name) else value] for name, value in pairs]
        return record
    if "json" in kind or _looks_like_json(raw):
        try:
            value = redact(json.loads(raw.decode("utf-8-sig", errors="replace")))
        except ValueError:
            pass
        else:
            if "truncated" in record:
                record["text"] = json.dumps(value)[:BODY_LIMIT]
            else:
                record["json"] = value
            return record
    record["text"] = redact_text(cut.decode("utf-8-sig", errors="replace"))
    return record


def _headers(headers: httpx.Headers, keep: tuple[str, ...]) -> dict[str, str]:
    return {name: headers[name] for name in keep if name in headers}


class HttpTrace:
    """The exchanges of one fetch, spooled to a private gzip file.

    `seal()` moves the spool beside the raw file. `discard()` removes the
    spool after a failed fetch. Each of them ends the trace.
    """

    def __init__(self, source: str, spool_dir: Path, secrets: Iterable[str] = ()) -> None:
        self.source = source
        # The credential values of the source configuration. `record` removes
        # them from every line.
        self.secrets = tuple(secrets)
        self.exchanges = 0
        spool_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=SPOOL_PREFIX, suffix=SPOOL_SUFFIX, dir=spool_dir)
        self._path = Path(name)
        # GzipFile does not close a fileobj that it was given. `_close` closes both.
        try:
            self._raw = os.fdopen(fd, "wb")
        except BaseException:
            # `fdopen` can close the descriptor when it raises.
            with contextlib.suppress(OSError):
                os.close(fd)
            self._path.unlink(missing_ok=True)
            raise
        try:
            self._fh: gzip.GzipFile | None = gzip.GzipFile(fileobj=self._raw, mode="wb")
        except BaseException:
            self._raw.close()
            self._path.unlink(missing_ok=True)
            raise
        self._lock = threading.Lock()

    @property
    def spool_path(self) -> Path:
        return self._path

    def hooks(self) -> dict[str, list[Any]]:
        return {"request": [self._on_request], "response": [self._on_response]}

    def _on_request(self, request: httpx.Request) -> None:
        request.extensions[_STARTED] = time.monotonic()

    def _on_response(self, response: httpx.Response) -> None:
        request = response.request
        started = request.extensions.get(_STARTED)
        response.read()
        try:
            sent = request.content
        except httpx.RequestNotRead:  # No collector sends a streamed upload.
            sent = b""
        line = {
            "ts": int(time.time() * 1000),
            "method": request.method,
            "url": _url(request.url),
            "status": response.status_code,
            "elapsed_ms": int((time.monotonic() - started) * 1000) if started is not None else None,
            "request": {
                "headers": _headers(request.headers, REQUEST_HEADERS),
                "body": _body(sent, request.headers.get("content-type", "")) if sent else None,
            },
            "response": {
                "headers": _headers(response.headers, RESPONSE_HEADERS),
                "body": _body(response.content, response.headers.get("content-type", "")),
            },
        }
        self.record(line)

    def record(self, line: dict[str, Any]) -> None:
        data = (redact_known(json.dumps(line, default=str), self.secrets) + "\n").encode()
        with self._lock:
            if self._fh is None:
                return  # The trace was sealed or discarded while a request was in flight.
            self._fh.write(data)
            self.exchanges += 1

    def _close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._raw.close()
                self._fh = None

    def seal(self, raw_path: Path, key: str) -> Path:
        """Seal the spool beside the raw file at `raw_path`, under `key`, and
        remove the spool. Returns the trace file's path."""
        from hst.core import rawstore

        self._close()
        try:
            return rawstore.write_trace(raw_path, self._path.read_bytes(), key=key)
        finally:
            self._path.unlink(missing_ok=True)

    def discard(self) -> None:
        self._close()
        self._path.unlink(missing_ok=True)


def sweep_spools(spool_dir: Path, *, before: float) -> list[Path]:
    """Remove the trace spools directly under `spool_dir` last modified before
    `before`, an epoch time in seconds, and return what was removed.

    Only a regular file with the spool prefix and suffix is removed.
    """
    removed: list[Path] = []
    try:
        entries = sorted(spool_dir.iterdir())
    except FileNotFoundError:
        return removed
    except OSError as exc:
        logger.warning("http trace: could not list the spool directory %s: %s", spool_dir, exc)
        return removed
    for path in entries:
        if not (path.name.startswith(SPOOL_PREFIX) and path.name.endswith(SPOOL_SUFFIX)):
            continue
        try:
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_mtime >= before:
                continue
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            logger.warning("http trace: could not remove the spool %s: %s", path, exc)
            continue
        removed.append(path)
    return removed
