"""This module writes no private key to disk."""

from __future__ import annotations

import codecs
import contextlib
import logging
import re
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from io import StringIO
from typing import NamedTuple

import paramiko

from .auth import SshAgent, SshJumpHost, SshPassword, SshPrivateKey

logger = logging.getLogger(__name__)

# The read timeout is in seconds.
DEFAULT_READ_TIMEOUT = 300

# The keepalive interval is in seconds.
KEEPALIVE_INTERVAL = 30

# The patterns match the terminal control bytes that a device, a console server or a
# bastion writes into the output stream. `ESC [ ... <letter>` is a CSI sequence.
# `ESC ] ... BEL` is an OS command. The bytes below 0x20 are the other controls.
_CSI = re.compile(r"\x1b\[([0-9;?]*)[ -/]*([@-~])")
_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")
_ESC_OTHER = re.compile(r"\x1b[@-Z\\-_]")
# The pattern matches DEL and every byte below 0x20 except tab, newline and CR. Each CR
# is a newline before this pattern runs.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _expand_csi(m: re.Match[str]) -> str:
    params, final = m.group(1), m.group(2)
    if final == "C":
        return " " * (min(int(params), SHELL_WIDTH) if params.isdigit() else 1)
    return ""


def sanitize_cli_text(text: str) -> str:
    text = _CSI.sub(_expand_csi, text)
    text = _OSC.sub("", text)
    text = _ESC_OTHER.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", text)
    return "\n".join(line.rstrip() for line in text.split("\n"))


def _sanitize_after_osc(text: str) -> str:
    """The steps of `sanitize_cli_text` that follow the CSI and OSC passes, in
    the same order and with the same patterns."""
    text = _ESC_OTHER.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL.sub("", text)
    return "\n".join(line.rstrip() for line in text.split("\n"))


# The last stage holds back a partial line up to this length. It cuts a longer
# partial line in the middle. This bounds the hold of a single-line answer
# (NX-OS `| json`).
_STREAM_LINE_LIMIT = 1 << 16

# The pattern matches an unfinished CSI sequence at the end of the text. The
# sequence is an ESC, or an ESC `[` with parameters and intermediates and no
# final byte.
_CSI_UNDECIDED = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*)?\Z")

# The match ends at the last character that is neither whitespace nor a control byte.
_LAST_KEPT = re.compile(r".*[^\s\x00-\x1f\x7f]", re.DOTALL)


class StreamSanitizer:
    """For any split of an answer, `"".join(feed(piece) for piece in pieces) + finish()`
    equals `sanitize_cli_text` of the whole answer."""

    def __init__(self) -> None:
        self._start()

    def _start(self) -> None:
        self._csi: list[str] = []
        self._csi_len = 0
        self._csi_retry = 0
        self._osc = ""
        self._rest: list[str] = []
        self._rest_len = 0
        self._rest_retry = _STREAM_LINE_LIMIT

    def feed(self, data: str) -> str:
        return self._feed_rest(self._feed_osc(self._feed_csi(data)))

    def finish(self) -> str:
        text = self._osc + _CSI.sub(_expand_csi, "".join(self._csi))
        text = "".join(self._rest) + _OSC.sub("", text)
        self._start()
        return _sanitize_after_osc(text)

    def _feed_csi(self, data: str) -> str:
        if data:
            self._csi.append(data)
            self._csi_len += len(data)
        if self._csi_len < self._csi_retry:
            return ""
        text = "".join(self._csi)
        esc = text.rfind("\x1b")
        held = ""
        if esc >= 0 and _CSI_UNDECIDED.match(text, esc):
            text, held = text[:esc], text[esc:]
        self._csi = [held] if held else []
        self._csi_len = len(held)
        self._csi_retry = 2 * len(held) if len(held) >= _STREAM_LINE_LIMIT else 0
        return _CSI.sub(_expand_csi, text)

    def _feed_osc(self, data: str) -> str:
        text = self._osc + data
        self._osc = ""
        esc = text.rfind("\x1b")
        if esc < 0:
            return _OSC.sub("", text)
        if esc == len(text) - 1:
            # A trailing ESC after an open OSC can start the `ESC \` terminator.
            start = text.rfind("\x1b", 0, esc)
            if start >= 0 and text.startswith("\x1b]", start) and text.find("\x07", start, esc) < 0:
                text, self._osc = text[:start], "\x1b]\x1b"
            else:
                text, self._osc = text[:esc], "\x1b"
        elif text.startswith("\x1b]", esc) and text.find("\x07", esc) < 0:
            # The introducer of an open OSC is held back. `_OSC` deletes the
            # body.
            text, self._osc = text[:esc], "\x1b]"
        return _OSC.sub("", text)

    def _feed_rest(self, data: str) -> str:
        if data:
            self._rest.append(data)
            self._rest_len += len(data)
        if self._rest_len < self._rest_retry and "\n" not in data:
            return ""
        text = "".join(self._rest)
        cut = text.rfind("\n") + 1
        if cut:
            self._hold_rest(text[cut:], _STREAM_LINE_LIMIT)
            return _sanitize_after_osc(text[:cut])
        end = len(text)
        while (m := _LAST_KEPT.match(text, 0, end)) is not None:
            end = m.end()
            # The second byte of an ESC sequence is deleted with its ESC.
            if not (end > 1 and text[end - 2] == "\x1b" and _ESC_OTHER.match(text, end - 2)):
                break
            end -= 2
        else:
            self._hold_rest(text, 2 * len(text))
            return ""
        # The line continues after the cut. The last character before the cut
        # is kept and is not whitespace. The right-strip of the complete line
        # removes no character before the cut.
        self._hold_rest(text[end:], _STREAM_LINE_LIMIT)
        return _sanitize_after_osc(text[:end])

    def _hold_rest(self, text: str, retry: int) -> None:
        self._rest = [text] if text else []
        self._rest_len = len(text)
        self._rest_retry = retry


# A prompt line is a name followed by `>` or `#`. The pattern is matched against a
# stripped line.
_PROMPT_LINE = re.compile(r"^\S{1,63}[>#]$")

# `SHELL_IDLE_READ` is the quiet time in seconds that ends a burst without a prompt.
# The PTY is wide enough that no show output wraps.
SHELL_IDLE_READ = 1.0
SHELL_WIDTH = 511
SHELL_HEIGHT = 1000

# The login fails after this many newlines without a settled prompt.
SHELL_PROMPT_ATTEMPTS = 3

# The prompt check reads this many trailing characters of a read.
_PROMPT_TAIL = 4096

# The echo search covers this many first lines. A later line that equals the command
# is output.
_ECHO_SEARCH_LINES = 20


def shell_prompt_of(text: str) -> str:
    """The prompt at the end of `text`, or "" if there is none.

    `text` is the output of `sanitize_cli_text`. A prompt that a device paints
    with cursor moves matches like a plain prompt.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    return lines[-1] if _PROMPT_LINE.match(lines[-1]) else ""


def shell_at_prompt(text: str, prompt: str) -> bool:
    """True if `prompt` is alone on the last line of `text`."""
    lines = text.split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    return bool(lines) and lines[-1].strip() == prompt


def shell_output_of(text: str, command: str, prompt: str) -> str:
    """The search covers the first `_ECHO_SEARCH_LINES` lines and stops at the first echo."""
    wanted = command.strip()
    start = 0
    pos = 0
    for _ in range(_ECHO_SEARCH_LINES):
        end = text.find("\n", pos)
        if _line_reads_as(text, pos, len(text) if end < 0 else end, wanted):
            start = len(text) if end < 0 else end + 1
            break
        if end < 0:
            break
        pos = end + 1
    end = len(text)
    while True:
        end = _rstripped_end(text, start, end)
        if end == start:
            return ""
        line = max(text.rfind("\n", start, end) + 1, start)
        if not _line_reads_as(text, line, end, prompt):
            break
        end = line
    if end < len(text) and text[end] == "\n":
        return text[start : end + 1]
    return text[start:end] + "\n"


def _line_reads_as(text: str, start: int, end: int, wanted: str) -> bool:
    """True if `text[start:end]`, one line, equals `wanted` once stripped."""
    if wanted != wanted.strip():
        # A stripped line has no whitespace at either edge.
        return False
    pattern = re.compile(r"\s*" + re.escape(wanted) + r"\s*")
    return pattern.fullmatch(text, start, end) is not None


def _rstripped_end(text: str, start: int, end: int) -> int:
    """The end of `text[start:end]` without trailing whitespace.

    Each step strips a window of 256 characters and copies at most the window.
    """
    while end > start:
        window = max(start, end - 256)
        kept = len(text[window:end].rstrip())
        if kept:
            return window + kept
        end = window
    return start


# The rejection lines of IOS/IOS-XE/IOS-XR/NX-OS and vtysh, matched at the start of a line.
_CLI_ERROR_MARKERS = (
    "% Invalid input",
    "% Incomplete command",
    "% Ambiguous command",
    "% Invalid command",
    "% Unknown command",
    "% Unrecognized command",
    "% Bad IP address",
    # IOS/IOS-XE runs a command sent on the exec channel as the autocommand of
    # the line. For a command that the parser does not accept at the privilege
    # level of the session, the device prints this line, with no `%`, in place
    # of the output.
    "Line has invalid autocommand",
    # AAA command authorization (TACACS+) refuses a command for the account
    # with these lines. IOS/IOS-XE prints the first line, with no `%` and exit
    # 0, in place of the output. IOS-XR and NX-OS print the `%` forms.
    # `classify_command_failure` reads all of them as `unauthorized`.
    "Command authorization failed",
    "% Authorization failed",
    "% Permission denied",
    "% This command is not authorized",
    # NX-OS's `| json` pipe prints this line, with exit 0, in place of a table past a size limit.
    "JSONScripterror",
)


# The line breaks of `str.splitlines` other than "\n". Text without any of
# them has "\n" as its only line break. One regex search over such text finds
# the same line as a loop over its lines.
_EXOTIC_BREAKS = "\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"

# The patterns match a rejection line at the start of the text and after a
# newline. For a str pattern, `\s` matches the characters that `str.strip`
# removes.
_CLI_MARKER_ALTERNATION = "|".join(re.escape(m) for m in _CLI_ERROR_MARKERS)
_CLI_REJECTION_FIRST_LINE = re.compile(rf"[^\S\n]*(?:{_CLI_MARKER_ALTERNATION})[^\n]*")
_CLI_REJECTION_LATER_LINE = re.compile(rf"\n[^\S\n]*(?:{_CLI_MARKER_ALTERNATION})[^\n]*")


def _cli_rejection(stdout: str) -> str | None:
    """The first device-rejection banner line in `stdout`, or None.

    A regex search finds the line in text whose only line break is "\n".
    Other text is split into lines.
    """
    if not any(brk in stdout for brk in _EXOTIC_BREAKS):
        m = _CLI_REJECTION_FIRST_LINE.match(stdout) or _CLI_REJECTION_LATER_LINE.search(stdout)
        return m.group(0).strip() if m else None
    for line in stdout.splitlines():
        s = line.strip()
        if any(s.startswith(m) for m in _CLI_ERROR_MARKERS):
            return s
    return None


# The whitespace in front of an answer's first line.
_LEADING_SPACE = re.compile(r"\s*")


def opening_rejection(text: str) -> str | None:
    """The device-rejection banner `text` opens with, or None."""
    m = _CLI_REJECTION_FIRST_LINE.match(text, _LEADING_SPACE.match(text).end())
    if m is None:
        return None
    return m.group(0).splitlines()[0].strip()


# The first character that is not whitespace. For a str pattern, `\S` matches
# the characters that `str.strip` keeps.
_FIRST_WORD = re.compile(r"\S")


# The most characters of stderr that a failure reason holds.
_STDERR_REASON_MAX = 2000


def _failure_reason(stdout: str, stderr: str) -> str:
    """The text that the device gave for a command that exited non-zero."""
    err = stderr.strip()
    if err:
        return err[:_STDERR_REASON_MAX]
    rejection = _cli_rejection(stdout)
    if rejection is not None:
        return rejection
    if any(brk in stdout for brk in _EXOTIC_BREAKS):
        return next((line.strip() for line in stdout.splitlines() if line.strip()), "")[:200]
    first = _FIRST_WORD.search(stdout)
    if first is None:
        return ""
    # The stripped line starts at `first` and ends at the last character of
    # the line that is not whitespace.
    line_end = stdout.find("\n", first.start())
    end = _rstripped_end(stdout, first.start(), len(stdout) if line_end < 0 else line_end)
    return stdout[first.start() : min(end, first.start() + 200)]


class SshError(RuntimeError):
    """Base for every failure this module raises."""


class SshUnreachable(SshError):
    """No TCP session was established. The causes are DNS, routing, a filtered
    port and a timeout."""


class SshRefused(SshError):
    """The transport closed before authentication could be attempted."""


class SshRejected(SshError):
    """The credential was offered and refused."""


class HostKeyMismatch(SshError):
    """The device presented a different host key than the pinned one."""


class CommandFailed(SshError):
    """The session ran and the command gave no usable answer. The command
    exited non-zero, the device rejected it, or one of the subclasses applies.

    A collector records a failed section for an optional command that raises
    it. A collector fails the device for a required command that raises it.
    """


class AnswerTooLarge(CommandFailed):
    """The answer exceeded the answer limit (`COLLECT_MAX_ANSWER_MB`).

    The read stops at the first piece that exceeds the limit and closes the
    channel. No part of the answer is returned.
    """


class AnswerIncomplete(CommandFailed):
    """The connection ended inside the answer. It ended before the device
    closed its channel or sent an exit status, or after a part of the output
    was lost on the way to the reader. No part of the answer is returned."""


class SshTimeout(SshError):
    """The session stays usable for the next command."""


# One MiB, the unit of the answer limit.
_MIB = 1 << 20


class _AnswerBudget:
    """A limit of 0 is no limit."""

    def __init__(self, what: str, limit_mb: int) -> None:
        self._what = what
        self._limit_mb = limit_mb
        self.size = 0

    def take(self, size: int) -> None:
        self.size += size
        if self._limit_mb and self.size > self._limit_mb * _MIB:
            raise AnswerTooLarge(
                f"{self._what} is larger than the answer limit of {self._limit_mb} MiB: "
                f"the read stopped after {self.size} bytes"
            )


class SshResult(NamedTuple):
    stdout: str
    host_key: str  # The host key that the device presented.
    jump_host_key: str  # The host key that the bastion presented, or "" without a jump host.


_KEY_CLASSES = (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey)


# The size of one recv on an exec channel.
_EXEC_RECV = 65536
_EXEC_FEED = 1 << 18

# The longest wait in seconds for standard output before the next read of
# standard error.
_EXEC_STDERR_POLL = 0.1


def _answer_decoder() -> codecs.IncrementalDecoder:
    """`assh.py` has asyncssh decode with the same codec and error handler."""
    return codecs.getincrementaldecoder("utf-8")(errors="replace")


def _read_exec_streams(
    channel: paramiko.Channel, read_timeout: float, answer: _AnswerBudget
) -> tuple[str, str]:
    """`read_timeout` bounds the wait for standard output alone, from the last
    standard output that arrived."""
    decoder = _answer_decoder()
    sanitizer = StreamSanitizer()
    out: list[str] = []
    err: list[bytes] = []
    pending: list[str] = []
    pending_len = 0
    deadline = time.monotonic() + read_timeout
    while True:
        while channel.recv_stderr_ready():
            data = channel.recv_stderr(_EXEC_RECV)
            answer.take(len(data))
            err.append(data)
        wait = min(deadline - time.monotonic(), _EXEC_STDERR_POLL)
        # A timeout of zero takes what has already arrived and does not wait.
        channel.settimeout(max(wait, 0.0))
        try:
            data = channel.recv(_EXEC_RECV)
        except TimeoutError:
            if wait > 0:
                continue
            raise
        if not data:
            break
        answer.take(len(data))
        deadline = time.monotonic() + read_timeout
        text = decoder.decode(data)
        pending.append(text)
        pending_len += len(text)
        if pending_len >= _EXEC_FEED:
            out.append(sanitizer.feed("".join(pending)))
            pending.clear()
            pending_len = 0
    channel.settimeout(read_timeout)
    pending.append(decoder.decode(b"", final=True))
    out.append(sanitizer.feed("".join(pending)))
    out.append(sanitizer.finish())
    while data := channel.recv_stderr(_EXEC_RECV):
        answer.take(len(data))
        err.append(data)
    return "".join(out), sanitize_cli_text(b"".join(err).decode(errors="replace"))


def _ended_by_the_connection(channel: paramiko.Channel) -> bool:
    """True when the streams of an exec channel ended because the connection
    ended.

    paramiko ends the streams the same way for an end of file of the device,
    a close of the device and an end of the connection. The flags of the
    channel record the case. The end of file of the device sets
    `eof_received`. paramiko answers the close of the device with an end of
    file and a close, and this sets `eof_sent`. `SshSession.run` writes
    nothing to an exec channel, and no other code sends an end of file on it.
    A channel that the transport ended with the connection has neither flag.
    A stand-in without the flags counts as ended at an end of file.
    """
    return not getattr(channel, "eof_received", True) and not getattr(channel, "eof_sent", True)


# paramiko raises these from a channel call that writes to an ended
# connection. EOFError comes from the socket write, OSError from a closed
# socket and SSHException from an inactive transport.
_CONNECTION_ERRORS = (EOFError, OSError, paramiko.SSHException)

# paramiko raises these from a channel request (exec, pty, shell) that the
# device refuses ("Channel closed.") or that meets an ended connection.
_REQUEST_ERRORS = (EOFError, paramiko.SSHException)


def _close_quietly(channel) -> None:
    """Closes `channel` in every state of its connection.

    The close of paramiko sends an end of file and a close to the device.
    This write raises on an ended connection. The channel is closed on this
    side in both cases. No code after a close depends on its delivery to the
    device.
    """
    with contextlib.suppress(*_CONNECTION_ERRORS):
        channel.close()


def _answered_within(channel, seconds: float, request: Callable[[], object]) -> bool:
    """Runs `request()`, one channel request, with a bound of `seconds`.
    Returns False when the device did not answer in time.

    paramiko waits for the answer of the device to a channel request (exec,
    pty, shell) without a timeout. After `seconds` the function closes the
    channel, and the close ends the wait. The function then returns False
    for every result of the request. The channel is unusable after the close.
    """
    lock = threading.Lock()
    state = {"done": False, "expired": False}

    def expire() -> None:
        with lock:
            if state["done"]:
                return
            state["expired"] = True
        _close_quietly(channel)

    def stop() -> bool:
        with lock:
            state["done"] = True
        timer.cancel()
        return state["expired"]

    timer = threading.Timer(seconds, expire)
    timer.daemon = True
    timer.start()
    try:
        request()
    except Exception:
        # The close of an expired request makes paramiko raise
        # "Channel closed.".
        if stop():
            return False
        raise
    except BaseException:
        stop()
        raise
    return not stop()


def _open_socket(host: str, port: int, timeout: int):
    """A test replaces this function."""
    return socket.create_connection((host, port), timeout=timeout)


def _transport_factory(sock) -> paramiko.Transport:
    """A test replaces this function, like `_transport` of `zia.py`."""
    return paramiko.Transport(sock)


def _agent_keys() -> list[paramiko.PKey]:
    return list(paramiko.Agent().get_keys())


def load_key(pem: str, passphrase: str) -> paramiko.PKey:
    """Loads PEM material from memory. The material does not declare the key
    type. Each class of `_KEY_CLASSES` is tried in order."""
    password = passphrase or None
    saw_passphrase_error = False
    for cls in _KEY_CLASSES:
        try:
            return cls.from_private_key(StringIO(pem), password=password)
        except paramiko.PasswordRequiredException:
            saw_passphrase_error = True
        except paramiko.SSHException:
            continue
    if saw_passphrase_error:
        raise SshError("private key needs a passphrase, or the passphrase is wrong")
    if password is not None:
        raise SshError("could not load the private key: wrong passphrase, or unsupported format")
    raise SshError("could not load the private key: unsupported or corrupt material")


def _host_key_of(transport: paramiko.Transport) -> str:
    key = transport.get_remote_server_key()
    return f"{key.get_name()} {key.get_base64()}"


def _authenticate(transport: paramiko.Transport, auth, where: str) -> None:
    """`where` is the hop, such as "device r1" or "bastion bhost"."""
    try:
        if isinstance(auth, SshPassword):
            # fallback=True (paramiko's default) retries a rejected "password"
            # attempt as single-prompt keyboard-interactive.
            transport.auth_password(auth.username, auth.password.get_secret_value())
        elif isinstance(auth, SshPrivateKey):
            key = load_key(auth.private_key.get_secret_value(), auth.passphrase.get_secret_value())
            transport.auth_publickey(auth.username, key)
        elif isinstance(auth, SshAgent):
            keys = _agent_keys()
            if not keys:
                raise SshRejected(f"no keys available from the SSH agent for {where}")
            last: Exception | None = None
            for key in keys:
                try:
                    transport.auth_publickey(auth.username, key)
                    return
                except paramiko.AuthenticationException as exc:
                    last = exc
            raise SshRejected(f"every agent key was refused by {where}: {last}")
        else:  # pragma: no cover (the union is closed)
            raise SshError(f"unsupported auth method: {auth!r}")
    except paramiko.AuthenticationException as exc:
        raise SshRejected(f"credentials refused: {auth.username}@{where}: {exc}") from exc
    except paramiko.SSHException as exc:
        raise SshRefused(f"{where} closed the transport before authentication completed: {exc}") from exc


def _connect(
    host: str,
    port: int,
    auth,
    known_host_key: str,
    timeout: int,
    connect_timeout: int,
    opener=None,
    hop: str = "device",
) -> tuple[paramiko.Transport, str]:
    """`opener` defaults to a plain TCP socket."""
    where = f"{hop} {host}"
    try:
        sock = (opener or _open_socket)(host, port, connect_timeout)
    except (OSError, TimeoutError, paramiko.SSHException) as exc:
        # SSHException here means the bastion could not open the tunnel
        raise SshUnreachable(f"cannot reach {where}:{port}: {exc}") from exc

    transport = _transport_factory(sock)
    try:
        transport.start_client(timeout=timeout)
    except paramiko.SSHException as exc:
        transport.close()
        raise SshRefused(f"{where}:{port} closed the session before authentication: {exc}") from exc

    observed = _host_key_of(transport)
    if known_host_key and observed != known_host_key:
        transport.close()
        raise HostKeyMismatch(f"{where} presented host key {observed}, pinned key is {known_host_key}")

    try:
        _authenticate(transport, auth, where)
    except BaseException:
        transport.close()
        raise
    return transport, observed


class SshSession:
    """Each command gets its own SSH exec channel."""

    def __init__(
        self,
        transport: paramiko.Transport,
        host_key: str,
        jump_host_key: str,
        *,
        open_timeout: int,
        read_timeout: int,
        max_answer_mb: int = 0,
    ) -> None:
        self._transport = transport
        self.host_key = host_key
        self.jump_host_key = jump_host_key
        self._open_timeout = open_timeout
        self._read_timeout = read_timeout
        self._max_answer_mb = max_answer_mb

    def _open_channel(self, command: str) -> paramiko.Channel:
        """A new session channel for `command`.

        A refused channel and an ended connection raise `SshTimeout` with the
        message text of `assh.AsyncSshSession.run`. The session continues
        with the next command.
        """
        try:
            return self._transport.open_session(timeout=self._open_timeout)
        except _CONNECTION_ERRORS as exc:
            raise SshTimeout(f"{command!r} could not open an exec channel: {_detail(exc)}") from exc

    def _exec(self, channel: paramiko.Channel, command: str) -> None:
        """Sends the exec request for `command` on `channel`.

        A request that the device refuses or does not answer within
        `open_timeout` raises `SshTimeout`.
        """
        try:
            answered = _answered_within(channel, self._open_timeout, lambda: channel.exec_command(command))
        except _REQUEST_ERRORS as exc:
            raise SshTimeout(f"{command!r} could not open an exec channel: {_detail(exc)}") from exc
        if not answered:
            raise SshTimeout(
                f"{command!r} could not open an exec channel: the device did not answer within "
                f"{self._open_timeout}s"
            )

    def run(self, command: str) -> str:
        channel = self._open_channel(command)
        # Without this timeout a paramiko read waits forever.
        channel.settimeout(self._read_timeout)
        answer = _AnswerBudget(f"the answer to {command!r}", self._max_answer_mb)
        try:
            self._exec(channel, command)
            stdout, stderr = _read_exec_streams(channel, self._read_timeout, answer)
            # recv_exit_status() waits on the channel's status event with no timeout of its own.
            status_event = getattr(channel, "status_event", None)
            if status_event is not None and not status_event.wait(self._read_timeout):
                raise SshTimeout(
                    f"{command!r} produced output but sent no exit status within {self._read_timeout}s"
                )
            status = channel.recv_exit_status()
            # The flags are read before the close. The close sends an end of file.
            cut_short = status < 0 and _ended_by_the_connection(channel)
        except TimeoutError as exc:
            raise SshTimeout(f"{command!r} produced no further output within {self._read_timeout}s") from exc
        except _CONNECTION_ERRORS as exc:
            # The recv that raised had taken data from the channel
            # (`_read_exec_streams`).
            raise AnswerIncomplete(
                f"{command!r} was cut short: the read failed after {answer.size} bytes of its answer, "
                f"and data that had arrived after them was lost ({_cause(exc)})"
            ) from exc
        finally:
            _close_quietly(channel)
        # The end of file, the close and the exit status of the device each
        # follow the last byte of the answer on the connection. A channel that
        # ended with the connection before any of the 3 arrived holds a part
        # of an answer.
        if cut_short:
            raise AnswerIncomplete(
                f"{command!r} was cut short: the connection ended after {answer.size} bytes of its "
                "answer, before the device ended the channel or sent an exit status"
            )
        # -1 means that the device sent no exit status.
        if status > 0:
            raise CommandFailed(f"{command!r} exited {status}: {_failure_reason(stdout, stderr)}")
        rejection = _cli_rejection(stdout)
        if rejection is not None:
            raise CommandFailed(f"{command!r} rejected by device: {rejection}")
        return stdout


def _shell_stopped(command: str, exc: BaseException) -> str:
    """The reason text of a shell session that sends no command after
    `command`. The write or the read of `command` ended in `exc` before the
    prompt of the device returned.

    The session keeps this text and drops `exc`. The traceback of `exc` holds
    the frames of the read with the part of the answer that was read.
    """
    what = "timed out" if isinstance(exc, SshTimeout) else f"ended before its prompt ({_cause(exc)})"
    return f"the shell session stopped after {command!r} {what}; no later command was sent"


def _cause(exc: BaseException) -> str:
    """The type of `exc`, followed by its message when it has one."""
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


def _detail(exc: BaseException) -> str:
    """The message of `exc`, or its type when it has no message. The bare
    `EOFError` of a write to an ended connection has no message."""
    return str(exc) or type(exc).__name__


def _not_reopened(command: str, exc: BaseException) -> str:
    """The reason text of a shell session that sends no command after
    `command`. The answer of `command` exceeded the answer limit, and the
    replacement shell did not open."""
    return (
        f"the shell session stopped after {command!r}: the new shell that replaces the one closed "
        f"at the answer limit did not open ({_cause(exc)}); no later command was sent"
    )


class ShellSession:
    """A command whose write or read ends anywhere but at the prompt stops the
    session (`run`)."""

    def __init__(
        self,
        channel,
        host_key: str,
        jump_host_key: str,
        *,
        read_timeout: int,
        setup: tuple[str, ...] = (),
        max_answer_mb: int = 0,
        reopen: Callable[[], object] | None = None,
    ) -> None:
        self._channel = channel
        self.host_key = host_key
        self.jump_host_key = jump_host_key
        self._read_timeout = read_timeout
        self._setup_commands = setup
        self._max_answer_mb = max_answer_mb
        self._reopen = reopen
        # The text is empty while the reader is at a prompt. Otherwise it
        # holds the reason that `run` sends no further command.
        self._stopped = ""
        # The command whose answer exceeded the answer limit. It is set from
        # the close of its shell until the next `run` opens a new shell.
        self._closed_after = ""
        self._start()

    def _start(self) -> None:
        """Learns the prompt of the current channel and runs the setup commands."""
        self._decoder = _answer_decoder()
        self.prompt = self._learn_prompt()
        for command in self._setup_commands:
            self._setup(command)

    def _learn_prompt(self) -> str:
        """The answer to a bare newline has to be the same twice."""
        login = self._read_burst()
        logger.debug("shell: login burst %d chars, last line %r", len(login), login.rstrip()[-80:])
        seen = ""
        for _ in range(SHELL_PROMPT_ATTEMPTS):
            self._channel.sendall(b"\n")
            prompt = shell_prompt_of(sanitize_cli_text(self._read_burst()))
            logger.debug("shell: newline answered with prompt %r", prompt)
            if prompt and prompt == seen:
                logger.info("shell: prompt %r settled after a login burst of %d chars", prompt, len(login))
                return prompt
            seen = prompt
        raise SshError(
            f"the device's prompt did not settle within {SHELL_PROMPT_ATTEMPTS} newlines, "
            f"so a shell read cannot be delimited; its last line was {seen[-120:]!r}"
        )

    def _setup(self, command: str) -> None:
        """A setup command whose read does not end at the prompt stops the opening
        of the shell."""
        try:
            self.run(command)
        except CommandFailed as exc:
            if self._stopped or self._closed_after:
                raise
            logger.warning("shell setup %r refused: %s", command, exc)

    def _recv(self, seconds: float, during: str) -> bytes:
        """The next output of the shell, or b"" after the device closed the shell.

        A recv on an ended connection raises `SshError` with `during` in its
        message, like `assh.AsyncShellSession`.
        """
        self._channel.settimeout(seconds)
        try:
            return self._channel.recv(65536)
        except TimeoutError:
            raise
        except _CONNECTION_ERRORS as exc:
            raise SshError(f"the connection ended {during} ({_cause(exc)})") from exc

    def _read_burst(self) -> str:
        """Everything the device sends, to the first prompt-shaped line or to
        the first quiet of `SHELL_IDLE_READ`.
        """
        deadline = time.monotonic() + self._read_timeout
        answer = _AnswerBudget("the device's output before its prompt", self._max_answer_mb)
        buffer = ""
        while not shell_prompt_of(sanitize_cli_text(buffer[-_PROMPT_TAIL:])):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SshTimeout(f"the device sent no prompt within {self._read_timeout}s")
            try:
                data = self._recv(min(remaining, SHELL_IDLE_READ), "before the device sent a prompt")
            except TimeoutError:
                if buffer:
                    return buffer
                continue
            if not data:
                raise SshError("the device closed the shell before sending a prompt")
            answer.take(len(data))
            buffer += self._decoder.decode(data)
        return buffer

    def _read_to_prompt(self, command: str) -> str:
        """Sanitized output, read to the prompt on its own line."""
        deadline = time.monotonic() + self._read_timeout
        answer = _AnswerBudget(f"the answer to {command!r}", self._max_answer_mb)
        # The prompt check reads only the tail.
        sanitizer = StreamSanitizer()
        parts: list[str] = []
        tail = ""
        while not shell_at_prompt(sanitize_cli_text(tail), self.prompt):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SshTimeout(f"{command!r} produced no further output within {self._read_timeout}s")
            try:
                data = self._recv(remaining, f"during {command!r}")
            except TimeoutError as exc:
                raise SshTimeout(
                    f"{command!r} produced no further output within {self._read_timeout}s"
                ) from exc
            if not data:
                raise SshError(f"the device closed the shell during {command!r}")
            answer.take(len(data))
            text = self._decoder.decode(data)
            parts.append(sanitizer.feed(text))
            tail = (tail + text)[-_PROMPT_TAIL:]
        parts.append(sanitizer.finish())
        return "".join(parts)

    def _open_again(self, reopen: Callable[[], object]) -> None:
        """Opens a new shell with `reopen` in place of the shell closed after
        `_closed_after`. A failure to open it stops the session."""
        after, self._closed_after = self._closed_after, ""
        try:
            self._channel = reopen()
            self._start()
        except BaseException as exc:
            self._stopped = _not_reopened(after, exc)
            self._closed_after = ""
            _close_quietly(self._channel)
            if not isinstance(exc, Exception):
                raise
            raise SshError(self._stopped) from exc
        logger.info("shell: a new shell opened after %r passed the answer limit", after)

    def run(self, command: str) -> str:
        """After a write or a read that ends anywhere but at the prompt, every
        later `run` raises `SshError` without a write."""
        if self._stopped:
            raise SshError(self._stopped)
        if self._closed_after and self._reopen is not None:
            self._open_again(self._reopen)
        logger.debug("shell: send %r", command)
        started = time.monotonic()
        try:
            self._channel.sendall(f"{command}\n".encode())
            text = self._read_to_prompt(command)
        except BaseException as exc:
            if not isinstance(exc, AnswerTooLarge):
                self._stopped = _shell_stopped(command, exc)
                raise
            _close_quietly(self._channel)
            if self._reopen is None:
                self._stopped = _shell_stopped(command, exc)
            else:
                self._closed_after = command
            raise
        logger.debug("shell: %r read %d chars in %.1fs", command, len(text), time.monotonic() - started)
        stdout = shell_output_of(text, command, self.prompt)
        rejection = _cli_rejection(stdout)
        if rejection is not None:
            raise CommandFailed(f"{command!r} rejected by device: {rejection}")
        return stdout

    def close(self) -> None:
        _close_quietly(self._channel)


def _open_shell(transport: paramiko.Transport, timeout: int) -> paramiko.Channel:
    """A new interactive shell on `transport` with a PTY of `SHELL_WIDTH`
    columns.

    `timeout` bounds the channel open, and bounds the pty request and the
    shell request together. The error messages match those of
    `assh.AsyncShellSession`.
    """
    try:
        shell = transport.open_session(timeout=timeout)
    except _CONNECTION_ERRORS as exc:
        raise SshError(f"the device refused an interactive shell: {_detail(exc)}") from exc

    def requests() -> None:
        shell.get_pty(width=SHELL_WIDTH, height=SHELL_HEIGHT)
        shell.invoke_shell()

    try:
        answered = _answered_within(shell, timeout, requests)
    except _REQUEST_ERRORS as exc:
        # The device refused the pty-req or the shell request.
        _close_quietly(shell)
        raise SshError(f"the device refused an interactive shell: {_detail(exc)}") from exc
    if not answered:
        raise SshTimeout(f"the device did not open a shell within {timeout}s")
    return shell


@contextmanager
def session(
    host: str,
    auth,
    *,
    port: int = 22,
    jump: SshJumpHost | None = None,
    known_host_key: str = "",
    timeout: int = 120,
    connect_timeout: int = 10,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
    channel: str = "exec",
    shell_setup: tuple[str, ...] = (),
    max_answer_mb: int = 0,
) -> Iterator[SshSession | ShellSession]:
    """Observed keys are attributes of the session."""
    jump_transport: paramiko.Transport | None = None
    jump_key = ""
    if jump is not None:
        jump_transport, jump_key = _connect(
            jump.host, jump.port, jump.auth, jump.host_key, timeout, connect_timeout, hop="bastion"
        )
    try:
        if jump_transport is None:
            transport, observed = _connect(host, port, auth, known_host_key, timeout, connect_timeout)
        else:

            def _via_bastion(h, p, t):
                # The paramiko default timeout of a channel open is 3600s.
                return jump_transport.open_channel("direct-tcpip", (h, p), ("127.0.0.1", 0), timeout=t)

            transport, observed = _connect(
                host, port, auth, known_host_key, timeout, connect_timeout, opener=_via_bastion
            )
        try:
            transport.set_keepalive(KEEPALIVE_INTERVAL)
            if channel == "shell":
                first = _open_shell(transport, timeout)
                try:
                    shell = ShellSession(
                        first,
                        observed,
                        jump_key,
                        read_timeout=read_timeout,
                        setup=shell_setup,
                        max_answer_mb=max_answer_mb,
                        reopen=lambda: _open_shell(transport, timeout),
                    )
                except BaseException:
                    _close_quietly(first)
                    raise
                try:
                    yield shell
                finally:
                    shell.close()
            else:
                yield SshSession(
                    transport,
                    observed,
                    jump_key,
                    open_timeout=timeout,
                    read_timeout=read_timeout,
                    max_answer_mb=max_answer_mb,
                )
        finally:
            transport.close()
    finally:
        if jump_transport is not None:
            jump_transport.close()


def run(
    host: str,
    auth,
    command: str,
    *,
    port: int = 22,
    jump: SshJumpHost | None = None,
    known_host_key: str = "",
    timeout: int = 120,
    connect_timeout: int = 10,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
    channel: str = "exec",
    shell_setup: tuple[str, ...] = (),
    max_answer_mb: int = 0,
) -> SshResult:
    """Returns (stdout, device key, bastion key)."""
    with session(
        host,
        auth,
        port=port,
        jump=jump,
        known_host_key=known_host_key,
        timeout=timeout,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        channel=channel,
        shell_setup=shell_setup,
        max_answer_mb=max_answer_mb,
    ) as s:
        return SshResult(s.run(command), s.host_key, s.jump_host_key)
