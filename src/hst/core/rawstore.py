"""Append-only raw snapshot store with one file per (source, host, run)."""

from __future__ import annotations

import codecs
import contextlib
import gzip
import io
import json
import logging
import os
import re
import secrets
import stat
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hst.app.crypto import TokenReader, TokenWriter, encrypt

from . import jsonstream
from .uid import slug

SUFFIX = ".json.gz.enc"
# `write` writes the sealed payload to a name with this suffix and renames the
# file to its final name. core/debug_capture.py `write_reparse` writes a
# re-parse result to a name with this suffix beside the raw file. Each reader
# matches the exact `SUFFIX` and reads no file with this suffix.
# worker/maintenance.py `sweep_raw_tmp` removes a file that a killed process
# left.
TMP_SUFFIX = SUFFIX + ".tmp"
# The directory under `raw_dir` that holds spill files, and the suffix of a
# spill file (`spill`). A spill is sealed to `<run_id>-<random>` + `TMP_SUFFIX`
# in the same directory and renamed to `<run_id>-<random>` + `SPILL_SUFFIX`.
# A source row name does not start with a dot (app/sources.py `NAME_PATTERN`).
# No reader matches `TMP_SUFFIX` or `SPILL_SUFFIX`.
SPILL_DIR = ".spill"
SPILL_SUFFIX = SUFFIX + ".spill"
# The gzip level of a raw file when the caller gives none. It equals the
# default of `Settings.raw_compress_level`. `read` reads a file of any level.
DEFAULT_COMPRESS_LEVEL = 6
# The index of the raw files that no run has joined (`parked`). The index
# holds one empty marker per such file under `<raw_dir>/.pending/`. The marker
# has the path of the file below `raw_dir`, with `PENDING_SUFFIX` in place of
# `SUFFIX`. `write` and `adopt` create the marker before the file takes its
# name. The write of the settle sidecar (`mark_joined`, `mark_superseded`)
# removes the marker. `.built` marks an index that covers every file that
# existed when the index was built. `parked` reads the whole store and creates
# the markers when `.built` is absent.
PENDING_DIR = ".pending"
PENDING_SUFFIX = ".pending"
PENDING_BUILT = ".built"
META_SUFFIX = ".meta.json"
KIND_SUFFIX = ".kind.json"
# The suffix of the HTTP exchange trace of the fetch that produced a raw file
# (collectors/http_trace.py). The trace is beside the raw file. Its content is
# gzip JSON lines, sealed under the same key. The trace exists only for a run
# whose source had tracing on. worker/maintenance.py `prune_rawstore` prunes
# the trace with its raw file.
TRACE_SUFFIX = ".http.jsonl.gz.enc"
# The suffixes of the collection debug capture of a load of a raw file
# (core/debug_capture.py). The capture files are beside the raw file. The
# record file holds one sealed JSON record per line, appended while the parse
# runs. The stack file is the plain text that faulthandler writes. It holds
# file names, line numbers and function names, and no value. A re-parse in
# isolation writes the same 2 files under `REPARSE_PREFIX` and a sealed
# result. worker/maintenance.py `prune_rawstore` prunes all of them with their
# raw file.
DEBUG_SUFFIX = ".debug.jsonl"
DEBUG_STACK_SUFFIX = ".debug-stack.txt"
REPARSE_PREFIX = ".reparse"
REPARSE_RESULT_SUFFIX = ".reparse.json.enc"
DEBUG_SUFFIXES = (
    DEBUG_SUFFIX,
    DEBUG_STACK_SUFFIX,
    REPARSE_PREFIX + DEBUG_SUFFIX,
    REPARSE_PREFIX + DEBUG_STACK_SUFFIX,
    REPARSE_RESULT_SUFFIX,
)

# How a parked payload must be applied by the device run that picks it up.
# `full` is normalize, load and side tables, and `observation` is side tables only.
# `full` is never written to disk.
KIND_FULL = "full"
KIND_OBSERVATION = "observation"

# A run id is "<fetch_ts_ms>-<nonce>".
_RUN_ID = re.compile(r"^(?P<ts>\d+)-(?P<nonce>[0-9a-fA-F]{6,})$")

logger = logging.getLogger(__name__)


def _open_private(path: Path):
    """Create the file at `path` with mode 0600 and open it for binary write."""
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb")


def _directory(raw_dir: Path, source: str, host: str) -> tuple[Path, Path]:
    """Return (source_dir, leaf_dir). The leaf is source_dir/host, or source_dir
    when host is empty (a controller-type source)."""
    source_dir = raw_dir / slug(source)
    return source_dir, (source_dir / slug(host) if host else source_dir)


def write(
    raw_dir: Path,
    source: str,
    run_id: str,
    payload: Any,
    *,
    host: str = "",
    key: str,
    level: int | None = None,
) -> Path:
    """Write the payload of one fetch, sealed under `key`. Returns the file path.

    `source` is the name of the source row. `host` is the device host. Both
    are path segments under `raw_dir`. `host` is "" for a caller with no
    device.

    The file is one Fernet token over the gzip of `json.dumps(payload,
    default=str)`, compressed at `level` (1 to 9, and None takes
    `DEFAULT_COMPRESS_LEVEL`). The JSON is compressed while it is encoded
    (`jsonstream.iter_json_bytes`). Each piece from the compressor is
    encrypted and written at once (`crypto.TokenWriter`). The JSON text, the
    compressed bytes and the token are never held whole in memory. The gzip
    header holds no modification time.

    The token is written to `<run_id>` + `TMP_SUFFIX` and renamed to the final
    name. A file with the final name is complete. A write that fails removes
    its temporary file. A killed write leaves the temporary file for
    worker/maintenance.py `sweep_raw_tmp`. No reader lists a temporary file.

    A written payload is not joined to a run.
    """
    directory = _prepare(raw_dir, source, host)
    path = directory / f"{run_id}{SUFFIX}"
    _mark_pending(raw_dir, path)
    _seal(payload, directory / f"{run_id}{TMP_SUFFIX}", path, key=key, level=level)
    return path


def _pending_path(raw_dir: Path, path: Path) -> Path:
    """The index marker (`PENDING_DIR`) of the raw file `path` under `raw_dir`."""
    relative = path.relative_to(raw_dir)
    return raw_dir / PENDING_DIR / relative.with_name(relative.name[: -len(SUFFIX)] + PENDING_SUFFIX)


def _mark_pending(raw_dir: Path, path: Path) -> None:
    """Create the index marker of the raw file `path`, before the file takes
    its name.

    The next `parked` drops a marker that has no file. `parked` does not list
    a file that has no marker. A file whose name is not a run id gets no
    marker. Errors propagate, and the caller then does not write the
    payload."""
    if not _RUN_ID.match(path.name[: -len(SUFFIX)]):
        return
    _touch_marker(raw_dir, _pending_path(raw_dir, path))


def _touch_marker(raw_dir: Path, marker: Path) -> None:
    """Create `marker` and the directories above it. `_drop_marker` removes
    the directory of a device with no marker. The creation is tried a second
    time when the directory is removed between `mkdir` and `touch`."""
    for attempt in (0, 1):
        marker.parent.mkdir(parents=True, exist_ok=True)
        _private_dirs(raw_dir / PENDING_DIR, marker.parent)
        try:
            marker.touch(exist_ok=True)
        except FileNotFoundError:
            if attempt:
                raise
        else:
            return


def _drop_marker(marker: Path) -> None:
    """Remove an index marker. Remove the marker directory of a device when
    that directory is empty. An OSError is suppressed."""
    with contextlib.suppress(OSError):
        marker.unlink(missing_ok=True)
    if marker.parent.parent.name != PENDING_DIR:
        with contextlib.suppress(OSError):
            marker.parent.rmdir()


def _clear_pending(path: Path) -> None:
    """Remove the index marker of the settled raw file `path`. The raw
    directory is the nearest of the first 3 ancestors that holds the index. A
    path with no such ancestor has no marker. An OSError is suppressed. The
    next `parked` drops a marker that stays."""
    for ancestor in path.parents[:3]:
        if (ancestor / PENDING_DIR).is_dir():
            _drop_marker(_pending_path(ancestor, path))
            return


def _private_dirs(*directories: Path) -> None:
    """Apply 0700 to each directory. The mode argument of mkdir is masked by
    the umask and has no effect on a directory that exists."""
    for d in directories:
        # chmod raises OSError on a mount without unix modes. The file mode
        # still applies.
        with contextlib.suppress(OSError):
            d.chmod(0o700)


def _prepare(raw_dir: Path, source: str, host: str) -> Path:
    """Create the leaf directory a payload of (source, host) is stored in,
    private at every level, and return it."""
    source_dir, directory = _directory(raw_dir, source, host)
    directory.mkdir(parents=True, exist_ok=True)
    _private_dirs(raw_dir, source_dir, directory)
    return directory


def _seal(payload: Any, tmp: Path, dest: Path, *, key: str, level: int | None) -> None:
    """Seal `payload` to `tmp` and rename it to `dest` (see `write`). A seal
    that fails removes `tmp` and raises."""
    try:
        with _open_private(tmp) as fh:
            token = TokenWriter(key, fh)
            for piece in _gzip_json(payload, DEFAULT_COMPRESS_LEVEL if level is None else level):
                token.write(piece)
            token.finish()
        tmp.replace(dest)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


@dataclass(frozen=True)
class Spilled:
    """A payload sealed under `<raw_dir>/.spill/` before its load (`spill`).

    `path` is the spill file. `raw_dir`, `source`, `host` and `run_id`
    identify the raw file that `write` stores the payload under. `final` is
    the path of that raw file. `adopt` renames the spill file to `final`.
    `fetch_ts_ms` is the fetch start in the run id."""

    path: Path
    raw_dir: Path
    source: str
    host: str
    run_id: str
    fetch_ts_ms: int

    @property
    def final(self) -> Path:
        return raw_path_of(self.raw_dir, self.source, self.host, self.run_id)


def spill(
    raw_dir: Path,
    source: str,
    run_id: str,
    payload: Any,
    *,
    host: str = "",
    key: str,
    level: int | None = None,
) -> Spilled:
    """Seal the payload of one fetch to a spill file, in the format of
    `write`, and return its handle.

    The file is `<raw_dir>/.spill/<run_id>-<random>` + `SPILL_SUFFIX`. It is
    sealed to the same name + `TMP_SUFFIX` in the same directory and renamed.
    The payloads of every source and host share this directory. The random
    part has 128 bits and makes the name of each spill unique. No source or
    host directory is created. `adopt` creates the leaf directory when the
    payload is loaded. Raises ValueError for a run id that is not in the
    format of `new_run_id`.
    """
    m = _RUN_ID.match(run_id)
    if not m:
        raise ValueError(f"not a run id: {run_id!r}")
    spill_dir = raw_dir / SPILL_DIR
    spill_dir.mkdir(parents=True, exist_ok=True)
    _private_dirs(raw_dir, spill_dir)
    name = f"{run_id}-{secrets.token_hex(16)}"
    path = spill_dir / f"{name}{SPILL_SUFFIX}"
    _seal(payload, spill_dir / f"{name}{TMP_SUFFIX}", path, key=key, level=level)
    return Spilled(path, raw_dir, source, host, run_id, int(m["ts"]))


def adopt(spilled: Spilled) -> Path:
    """Rename a spill file to the raw file path that `write` uses for the same
    payload, and return that path.

    The leaf directory is created as `write` creates it. The file keeps the
    bytes that were sealed at fetch time. Errors propagate, and the spill file
    then stays in place.
    """
    _prepare(spilled.raw_dir, spilled.source, spilled.host)
    final = spilled.final
    _mark_pending(spilled.raw_dir, final)
    spilled.path.replace(final)
    return final


def drop_spill(spilled: Spilled) -> None:
    """Remove a spill file that will not be loaded. The call does nothing
    after `adopt` has moved the file. An OSError is logged, and the file stays
    for the `clear_spills` of the next cycle or refresh."""
    try:
        spilled.path.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("could not remove raw spill file %s: %s", spilled.path, exc)


def clear_spills(raw_dir: Path, *, before: float | None = None) -> list[Path]:
    """Remove the spill files under `<raw_dir>/.spill/` and the temporary
    files of unfinished spills, and return the removed paths.

    With `before`, an epoch time in seconds, only a file with an earlier
    modification time is removed. A file that vanishes first is skipped. A
    file that cannot be removed is logged and stays. A directory that cannot
    be listed is logged. No OSError is raised. The directory `.spill` is
    neither removed nor created. Other readers iterate the children of
    `raw_dir` at the same time.
    """
    removed: list[Path] = []
    spill_dir = raw_dir / SPILL_DIR
    try:
        entries = sorted(spill_dir.iterdir())
    except FileNotFoundError:
        return removed
    except OSError as exc:
        logger.warning("could not list raw spill directory %s: %s", spill_dir, exc)
        return removed
    for path in entries:
        if not path.name.endswith((SPILL_SUFFIX, TMP_SUFFIX)):
            continue
        try:
            st = path.lstat()
            if not stat.S_ISREG(st.st_mode):
                continue
            if before is not None and st.st_mtime >= before:
                continue
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as exc:
            logger.warning("could not remove raw spill file %s: %s", path, exc)
            continue
        removed.append(path)
    return removed


def _gzip_json(payload: Any, level: int) -> Iterator[bytes]:
    """Yield the pieces of a gzip member whose content is `json.dumps(payload,
    default=str)` in UTF-8. The JSON is compressed one chunk at a time. wbits
    31 selects the gzip container that `gzip.decompress` reads."""
    comp = zlib.compressobj(level, zlib.DEFLATED, 31)
    for chunk in jsonstream.iter_json_bytes(payload, sort_keys=False, separators=(", ", ": "), max_depth=1):
        if out := comp.compress(chunk):
            yield out
    yield comp.flush()


def read(path: Path, key: str) -> Any:
    """Return the payload sealed at `path`. The payload equals `json.loads` of
    the gzip content of the Fernet token under `key`.

    The token is authenticated in full before any of it is decrypted. It is
    then decrypted, decompressed and decoded one piece at a time (`_opened`,
    `_JsonReader`). Besides the payload, a read holds buffers of a fixed size,
    the text of the one member that is being decoded when that member is not
    a string, and the decoded pieces of a long string member while they are
    joined.

    The errors equal the errors of a read of the whole token. A token that
    does not authenticate under `key` raises SecretKeyError. Content that is
    not gzip raises the errors of `gzip.decompress`. Text that is not JSON
    raises the UnicodeDecodeError or JSONDecodeError of `json.loads`. Text
    that is nested deeper than `json.loads` decodes raises its RecursionError.
    Content with more than one fault raises the error that a read of the
    whole token meets first. A read that fails reads on to the end of the
    token, and to the end of the content or of its text when the fault
    requires it, before it raises (`_opened`, `_JsonReader.rest`). The
    position in a JSONDecodeError counts from the start of the text held.
    """
    with _opened(path, key) as content:
        reader = _JsonReader(content)
        try:
            return reader.document()
        except (ValueError, RecursionError) as exc:
            reader.rest(exc)
            raise


@contextlib.contextmanager
def _opened(path: Path, key: str) -> Iterator[gzip.GzipFile]:
    """Yield the decompressed content of the token sealed at `path`, as a stream.

    The token authenticates before the stream is yielded. The second pass
    checks the same tag at the end of the token (`crypto.TokenReader`). A file
    that changes in place between the 2 passes gives other bytes to the gzip
    and JSON readers, and these readers can fail before the end of the token
    is read. A failure while the stream is read therefore reads on to the end
    of the token. When the rest of the token does not authenticate, its
    SecretKeyError replaces the error that the changed bytes caused.
    """
    with path.open("rb") as fh, TokenReader(key, fh) as token:
        try:
            with gzip.GzipFile(fileobj=token, mode="rb") as content:
                yield content
        except Exception:
            while token.read(_JSON_READ):
                pass
            raise


# `_JsonReader` reads `_JSON_READ` bytes of the decompressed stream at a time.
# When a member that is decoded whole extends past the text held, the decode
# is tried again with `_JSON_WINDOW` characters from the start of the member,
# and then with twice the text each time.
_JSON_READ = 1 << 20
_JSON_WINDOW = 16 << 20
# The characters an escape sequence of a JSON string can still be open at:
# its backslash, and the `u` and the hex digits of a `\uXXXX`.
_ESCAPE_OPEN = "\\u0123456789abcdefABCDEF"
# The characters of a JSON number.
_NUMBER_CHARS = "0123456789.eE+-"
_WHITESPACE = re.compile(r"[ \t\n\r]*")
_DECODER = json.JSONDecoder()


class _JsonReader:
    """Decode the bytes of a binary stream as `json.loads` does, one piece at
    a time.

    The text is decoded from the bytes as `json.loads` decodes bytes, in the
    encoding that `json.detect_encoding` returns, with the `surrogatepass`
    error handler. The object or array of the payload is walked member by
    member. A string member that extends past the text held is decoded in
    pieces (`_long_string`). Any other member is decoded by the C decoder in
    one call when its text is held (`_whole`). The text held is a window of
    fixed size and the text of one member that is not a string.

    The value equals the value that `json.loads` returns for the whole text.
    Every member is decoded by the same C decoder. The members of an object
    are set in order, and a repeated key keeps its first place and its last
    value. A malformed text raises a JSONDecodeError or a UnicodeDecodeError
    for the first fault in reading order, with positions counted in the text
    held. `rest` then finds a fault that a read of the whole text meets
    earlier.
    """

    def __init__(self, stream: io.BufferedIOBase) -> None:
        self._stream = stream
        self._decoder: codecs.IncrementalDecoder | None = None
        self._head = b""
        self._eof = False
        self._buf = ""
        self._pos = 0

    def document(self) -> Any:
        first = self._skip()
        if first == "{":
            value: Any = self._object()
        elif first == "[":
            value = self._array()
        elif first:
            value = self._member()
        else:
            raise json.JSONDecodeError("Expecting value", self._buf, self._pos)
        if self._skip():
            raise json.JSONDecodeError("Extra data", self._buf, self._pos)
        return value

    def rest(self, error: Exception) -> None:
        """Read the rest of the stream after `document` raised `error`, and
        hold none of it.

        `json.loads` of the whole decompressed content meets its faults in
        another order. All of the content is decompressed before any of it is
        decoded, and all of the text is decoded before any of it is parsed.
        After a parse error, `rest` decodes the rest of the text. After a
        decoding error, `rest` reads the rest of the stream. A fault met on
        the way is raised in place of `error`. The fault is a
        UnicodeDecodeError or an error of an incomplete gzip stream.
        """
        if isinstance(error, UnicodeDecodeError):
            self._drain()
            return
        try:
            while self._read() is not None:
                pass
        except UnicodeDecodeError:
            self._drain()
            raise

    def _drain(self) -> None:
        while self._stream.read(_JSON_READ):
            pass

    def _read(self) -> str | None:
        """The next piece of text, or None at the end of the stream."""
        while not self._eof:
            data = self._stream.read(_JSON_READ)
            self._eof = not data
            if self._decoder is None:
                # json.detect_encoding reads the first 4 bytes.
                self._head += data
                if len(self._head) < 4 and not self._eof:
                    continue
                encoding = json.detect_encoding(self._head)
                self._decoder = codecs.getincrementaldecoder(encoding)("surrogatepass")
                data, self._head = self._head, b""
            if text := self._decoder.decode(data, self._eof):
                return text
        return None

    def _fill(self, want: int) -> None:
        """Hold at least `want` characters from the position on, or the rest
        of the text when less remains."""
        have = len(self._buf) - self._pos
        if have >= want or self._eof:
            return
        parts = [self._buf[self._pos :]]
        while have < want and (text := self._read()) is not None:
            parts.append(text)
            have += len(text)
        if len(parts) > 1:
            self._buf, self._pos = "".join(parts), 0

    def _skip(self) -> str:
        """Move past whitespace and return the next character, or "" at the
        end of the text."""
        while True:
            if match := _WHITESPACE.match(self._buf, self._pos):
                self._pos = match.end()
            if self._pos < len(self._buf):
                return self._buf[self._pos]
            text = self._read()
            if text is None:
                return ""
            self._buf, self._pos = text, 0

    def _object(self) -> dict[str, Any]:
        """The payload's object, walked member by member."""
        members: dict[str, Any] = {}
        self._pos += 1
        char = self._skip()
        if char == "}":
            self._pos += 1
            return members
        while True:
            if char != '"':
                raise json.JSONDecodeError(
                    "Expecting property name enclosed in double quotes", self._buf, self._pos
                )
            key = self._string()
            if self._skip() != ":":
                raise json.JSONDecodeError("Expecting ':' delimiter", self._buf, self._pos)
            self._pos += 1
            if not self._skip():
                raise json.JSONDecodeError("Expecting value", self._buf, self._pos)
            members[key] = self._member()
            char = self._skip()
            if char == "}":
                self._pos += 1
                return members
            if char != ",":
                raise json.JSONDecodeError("Expecting ',' delimiter", self._buf, self._pos)
            self._pos += 1
            char = self._skip()

    def _array(self) -> list[Any]:
        """The payload's array, walked item by item."""
        items: list[Any] = []
        self._pos += 1
        char = self._skip()
        if char == "]":
            self._pos += 1
            return items
        while True:
            if not char:
                raise json.JSONDecodeError("Expecting value", self._buf, self._pos)
            items.append(self._member())
            char = self._skip()
            if char == "]":
                self._pos += 1
                return items
            if char != ",":
                raise json.JSONDecodeError("Expecting ',' delimiter", self._buf, self._pos)
            self._pos += 1
            char = self._skip()

    def _member(self) -> Any:
        """The value that starts at the position."""
        if self._buf[self._pos] == '"':
            return self._string()
        return self._whole()

    def _whole(self) -> Any:
        """Return the value at the position, decoded by the C decoder in one call.

        The decode runs on the text held. A failure before the end of the
        stream can be caused by the end of the text held. The decode is then
        tried again with at least `_JSON_WINDOW` characters from the start of
        the value, and then with twice the text each time, until the value
        decodes or the stream ends."""
        while True:
            try:
                value, end = _DECODER.raw_decode(self._buf, self._pos)
            except json.JSONDecodeError:
                if self._eof:
                    raise
            else:
                # A number can continue in the text that is not held yet (`1`
                # of `1.5`, `1.5` of `1.5e3`). A value that does not start
                # with a bracket is accepted when the next character is held
                # and is not a number character, or at the end of the stream.
                if (
                    self._eof
                    or self._buf[self._pos] in "{["
                    or (end < len(self._buf) and self._buf[end] not in _NUMBER_CHARS)
                ):
                    self._pos = end
                    return value
            self._fill(max(2 * (len(self._buf) - self._pos), _JSON_WINDOW))

    def _string(self) -> str:
        """The string at the position."""
        try:
            value, end = _DECODER.raw_decode(self._buf, self._pos)
        except json.JSONDecodeError:
            if self._eof:
                raise
            return self._long_string()
        self._pos = end
        return value

    def _long_string(self) -> str:
        """Return the string at the position, decoded one piece at a time. The
        closing quote of the string is past the text held.

        Each piece is decoded as a separate string. The text is cut after its
        last character that is not in `_ESCAPE_OPEN`. An escape is a backslash
        and one character, or `\\u` and 4 hex digits. A text that does not end
        in a backslash, a `u` or a hex digit ends between 2 escapes. The cut
        does not fall between the 2 escapes of a surrogate pair. `json.loads`
        decodes such a pair as one character. The text after the cut is
        prepended to the next text. The piece that holds the closing quote
        ends the string. The text after that quote stays in the buffer.
        """
        pieces: list[str] = []
        carry = ""
        text: str | None = self._buf[self._pos + 1 :]
        self._buf, self._pos = "", 0
        while text is not None:
            cut = len(text.rstrip(_ESCAPE_OPEN))
            if not cut:
                carry += text
            else:
                quoted = "".join(('"', carry, text[:cut], '"'))
                piece, end = _DECODER.raw_decode(quoted)
                pieces.append(piece)
                if end < len(quoted):
                    self._buf = quoted[end:-1] + text[cut:]
                    return "".join(pieces)
                carry = text[cut:]
            text = self._read()
        raise json.JSONDecodeError("Unterminated string starting at", '"' + carry, 0)


def trace_path(raw_path: Path) -> Path:
    """The path of the HTTP trace of the fetch that produced `raw_path`. The
    file exists only when a trace was taken."""
    return raw_path.with_name(raw_path.name[: -len(SUFFIX)] + TRACE_SUFFIX)


def write_trace(raw_path: Path, blob: bytes, *, key: str) -> Path:
    """Seal an HTTP trace (gzip JSON lines, already compressed) beside its raw file."""
    path = trace_path(raw_path)
    with _open_private(path) as fh:
        fh.write(encrypt(key, blob))
    return path


def read_trace(path: Path, key: str) -> bytes:
    """Return the decompressed JSON lines of a sealed trace. The token is read
    through `_opened`, as `read` reads a raw file. The lines are held whole in
    memory."""
    with _opened(path, key) as content:
        return content.read()


def sibling(raw_path: Path, suffix: str) -> Path:
    """The file with `suffix` beside the raw file at `raw_path`."""
    return raw_path.with_name(raw_path.name[: -len(SUFFIX)] + suffix)


def raw_path_of(raw_dir: Path, source: str, host: str, run_id: str) -> Path:
    """Where `write` puts the payload of (source, host, run_id)."""
    _source_dir, directory = _directory(raw_dir, source, host)
    return directory / f"{run_id}{SUFFIX}"


@dataclass(frozen=True)
class RawFile:
    source: str
    host: str
    run_id: str
    fetch_ts_ms: int
    path: Path
    size: int


def _size(path: Path) -> int | None:
    """The size of a listed file, or None when retention removed it after the
    listing (worker/maintenance.py `prune_rawstore`)."""
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return None


def raw_files(raw_dir: Path, source: str, limit: int) -> list[RawFile]:
    """Return the newest `limit` raw files of one source, over every host,
    newest first. `source` is the directory segment that `write` creates. A
    file that is removed during the listing is left out."""
    source_dir = raw_dir / slug(source)
    found: list[RawFile] = []
    if not source_dir.is_dir():
        return found
    for path in source_dir.rglob(f"*{SUFFIX}"):
        run_id = path.name[: -len(SUFFIX)]
        m = _RUN_ID.match(run_id)
        if not m or (size := _size(path)) is None:
            continue
        relative = path.parent.relative_to(source_dir).parts
        host = relative[0] if relative else ""
        found.append(RawFile(source_dir.name, host, run_id, int(m.group("ts")), path, size))
    found.sort(key=lambda f: (f.fetch_ts_ms, f.run_id), reverse=True)
    return found[:limit]


@dataclass(frozen=True)
class TraceFile:
    source: str
    host: str
    run_id: str
    fetch_ts_ms: int
    path: Path
    size: int


def traces(raw_dir: Path) -> list[TraceFile]:
    """Return every sealed HTTP trace under `raw_dir`, newest first. The
    source and the host are the path segments that `write` creates. A trace
    that is removed during the listing is left out."""
    found: list[TraceFile] = []
    if not raw_dir.is_dir():
        return found
    for path in raw_dir.rglob(f"*{TRACE_SUFFIX}"):
        run_id = path.name[: -len(TRACE_SUFFIX)]
        m = _RUN_ID.match(run_id)
        if not m or (size := _size(path)) is None:
            continue
        relative = path.parent.relative_to(raw_dir).parts
        source = relative[0] if relative else ""
        host = relative[1] if len(relative) > 1 else ""
        found.append(TraceFile(source, host, run_id, int(m.group("ts")), path, size))
    found.sort(key=lambda t: (t.fetch_ts_ms, t.run_id), reverse=True)
    return found


def latest_path(raw_dir: Path, source: str, host: str = "") -> Path | None:
    """Return the newest raw file of one source (and host, for a device of a
    fleet), or None when the source has no raw file.

    The newest file has the latest fetch time in its run id. The file stem is
    the run id (`new_run_id`). A file whose stem does not parse as a run id is
    skipped. Joined files and parked files both count.
    """
    _source_dir, directory = _directory(raw_dir, source, host)
    if not directory.is_dir():
        return None
    newest: tuple[int, str, Path] | None = None
    for path in directory.iterdir():
        if not path.name.endswith(SUFFIX):
            continue
        run_id = path.name[: -len(SUFFIX)]
        m = _RUN_ID.match(run_id)
        if not m:
            continue
        candidate = (int(m.group("ts")), run_id, path)
        if newest is None or candidate > newest:
            newest = candidate
    return None if newest is None else newest[2]


def _meta_path(path: Path) -> Path:
    return path.with_name(path.name[: -len(SUFFIX)] + META_SUFFIX)


def _kind_path(path: Path) -> Path:
    return path.with_name(path.name[: -len(SUFFIX)] + KIND_SUFFIX)


def mark_kind(
    path: Path,
    kind: str,
    normalization_context: dict[str, Any] | None = None,
    hashes: dict[str, str] | None = None,
    fetch_finished_ms: int | None = None,
) -> None:
    """Record how a parked payload must be applied, in the kind sidecar beside
    the raw file.

    The sidecar is created with O_EXCL.

    `hashes` are the content hashes of the payload, computed by the fetch that
    parked it (app/runs_exec.py `run_device_fetch`). The sidecar has no
    `hashes` key when `hashes` is empty or None. `fetch_finished_ms` is the
    time when that fetch finished, on the collector host clock that also gives
    the fetch start in the run id. The sidecar has no `fetch_finished_ms` key
    when the argument is None.
    """
    body: dict[str, Any] = {"kind": kind, "normalization_context": normalization_context or {}}
    if hashes:
        body["hashes"] = dict(hashes)
    if fetch_finished_ms is not None:
        body["fetch_finished_ms"] = int(fetch_finished_ms)
    _write_sidecar_at(_kind_path(path), body)


def read_kind(path: Path) -> str:
    """Return how a parked payload must be applied. The result is `KIND_FULL`
    when the kind sidecar is absent, cannot be read or holds no kind."""
    try:
        kind = json.loads(_kind_path(path).read_text()).get("kind")
    except (OSError, ValueError):
        return KIND_FULL
    return str(kind) if kind else KIND_FULL


def read_park_hashes(path: Path) -> dict[str, str]:
    """The content hashes stored at park time (`mark_kind`), or {} when the
    sidecar holds none or cannot be read."""
    try:
        value = json.loads(_kind_path(path).read_text()).get("hashes", {})
    except (OSError, ValueError, AttributeError):
        return {}
    if not isinstance(value, dict):
        return {}
    return {str(k): v for k, v in value.items() if isinstance(v, str)}


def read_park_finished(path: Path, fetch_ts_ms: int) -> int | None:
    """When the fetch that parked `path` finished (`mark_kind`), or None when
    the sidecar holds no such time, cannot be read, or holds one before the
    fetch's start `fetch_ts_ms`."""
    try:
        value = json.loads(_kind_path(path).read_text()).get("fetch_finished_ms")
    except (OSError, ValueError, AttributeError):
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < fetch_ts_ms:
        return None
    return value


def read_normalization_context(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_kind_path(path).read_text()).get("normalization_context", {})
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_sidecar(path: Path, body: dict[str, Any]) -> None:
    """Write the settle sidecar beside a raw file, once.

    A second call for the same file raises FileExistsError. The index marker
    of the file (`PENDING_DIR`) is removed when the sidecar exists after the
    call.
    """
    try:
        _write_sidecar_at(_meta_path(path), body)
    finally:
        if _meta_path(path).exists():
            _clear_pending(path)


def _write_sidecar_at(meta: Path, body: dict[str, Any]) -> None:
    fd = os.open(meta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(body, fh)
    except BaseException:
        with contextlib.suppress(OSError):
            meta.unlink()
        raise


def mark_joined(path: Path, snapshot_ts: int) -> None:
    """Record the run's joined collection_ts in a sidecar beside the raw file,
    once. `path` is a raw file's own path, as returned by `write`."""
    _write_sidecar(path, {"snapshot_ts": snapshot_ts})


def mark_superseded(path: Path, superseded_by: int) -> None:
    """Settle a payload that no run will apply. Run `superseded_by` holds a
    newer observation of the same device.

    `parked` stops returning it. The raw file stays on disk until retention
    removes it (app/runs_exec.py `build_device_run`).
    """
    _write_sidecar(path, {"snapshot_ts": None, "superseded_by": superseded_by})


@dataclass(frozen=True)
class ParkedPayload:
    """One raw file that is fetched and not joined to a run. The file has no
    `<run_id>.meta.json` sidecar. `source` and `host` are the names of the
    directories that hold the file.

    `kind` is how the device run must apply the payload, `KIND_FULL` or
    `KIND_OBSERVATION`, read from the kind sidecar (`read_kind`).
    `fetch_finished_ms` is the time when the fetch finished, read from the
    same sidecar (`read_park_finished`). It is None when the sidecar holds no
    such time."""

    path: Path
    source: str
    host: str
    run_id: str
    fetch_ts_ms: int
    kind: str = KIND_FULL
    normalization_context: dict[str, Any] = field(default_factory=dict)
    fetch_finished_ms: int | None = None


def parked(raw_dir: Path, source: str | None = None) -> list[ParkedPayload]:
    """Return every raw file under `raw_dir`, or under the directory of one
    `source`, that has no join sidecar.

    The function reads the index of those files (`PENDING_DIR`), which holds
    one marker per file. When the store has no index, `_build_pending` reads
    the whole store once and builds the index (`_scan_parked`). A marker whose
    file is gone or settled is removed.

    A file has the `<source>/<host>/<run_id>` path of a device fetch, or the
    `<source>/<run_id>` path of a controller fetch, which is listed with host
    "". A cycle joins its controller payload when it loads the payload. A
    file without a host counts as parked only when it has the kind sidecar
    that `mark_kind` writes. Other files without a host (the IPAdmin import,
    a cycle that failed before it joined its payload) have no kind sidecar. A
    file whose stem does not parse as a run id is skipped.
    """
    if not raw_dir.is_dir():
        return []
    index = raw_dir / PENDING_DIR
    if not (index / PENDING_BUILT).is_file():
        _build_pending(raw_dir)
    roots = [index / slug(source)] if source else sorted(p for p in index.iterdir() if p.is_dir())
    out: list[ParkedPayload] = []
    for source_dir in roots:
        if not source_dir.is_dir():
            continue
        entries = sorted(source_dir.iterdir())
        found = [("", p) for p in entries if p.is_file()]
        for host_dir in (p for p in entries if p.is_dir()):
            found += [(host_dir.name, p) for p in sorted(host_dir.iterdir())]
        for host, marker in found:
            if not marker.name.endswith(PENDING_SUFFIX):
                continue
            run_id = marker.name[: -len(PENDING_SUFFIX)]
            leaf = raw_dir / source_dir.name / host if host else raw_dir / source_dir.name
            path = leaf / f"{run_id}{SUFFIX}"
            if not path.is_file() or _meta_path(path).exists():
                _drop_marker(marker)
                continue
            if not host and not _kind_path(path).is_file():
                continue
            payload = _parked_payload(path, source_dir.name, host, run_id)
            if payload is not None:
                out.append(payload)
    return out


def _parked_payload(path: Path, source: str, host: str, run_id: str) -> ParkedPayload | None:
    m = _RUN_ID.match(run_id)
    if not m:
        return None
    fetch_ts_ms = int(m["ts"])
    return ParkedPayload(
        path=path,
        source=source,
        host=host,
        run_id=run_id,
        fetch_ts_ms=fetch_ts_ms,
        kind=read_kind(path),
        normalization_context=read_normalization_context(path),
        fetch_finished_ms=read_park_finished(path, fetch_ts_ms),
    )


def _build_pending(raw_dir: Path) -> None:
    """Build the index of the parked payloads of a store that has none. The
    function creates one marker for each raw file without a join sidecar
    (`_scan_parked`), and then `PENDING_BUILT`. A payload that is written
    during the build creates its own marker."""
    for payload in _scan_parked(raw_dir):
        _touch_marker(raw_dir, _pending_path(raw_dir, payload.path))
    (raw_dir / PENDING_DIR).mkdir(exist_ok=True)
    _private_dirs(raw_dir / PENDING_DIR)
    (raw_dir / PENDING_DIR / PENDING_BUILT).touch()


def _scan_parked(raw_dir: Path) -> list[ParkedPayload]:
    """Return the parked payloads from a read of every directory and every
    file of the store."""
    out: list[ParkedPayload] = []
    for source_dir in sorted(p for p in raw_dir.iterdir() if p.is_dir() and p.name != PENDING_DIR):
        entries = sorted(source_dir.iterdir())
        found = [("", p) for p in entries if p.name.endswith(SUFFIX) and _kind_path(p).is_file()]
        for host_dir in (p for p in entries if p.is_dir()):
            found += [(host_dir.name, p) for p in sorted(host_dir.iterdir())]
        for host, path in found:
            if not path.name.endswith(SUFFIX) or _meta_path(path).exists():
                continue
            payload = _parked_payload(path, source_dir.name, host, path.name[: -len(SUFFIX)])
            if payload is not None:
                out.append(payload)
    return out
