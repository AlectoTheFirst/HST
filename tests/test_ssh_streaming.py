"""The paramiko transport's reads stream through `ssh.StreamSanitizer`."""

from __future__ import annotations

import contextlib
import logging
import random
import socket
import threading
from collections.abc import Callable

import paramiko
import pytest
from tests.test_cli_text_sanitize import ESC, SHAPES
from tests.test_ssh_transport import FakeChannel
from tests.test_stream_sanitize import reference_shell_output_of

from hst.collectors import ssh
from hst.collectors.auth import SshPassword
from hst.collectors.ssh import sanitize_cli_text

AUTH = SshPassword(username="ro", password="pw")
PROMPT = "r1#"

Answer = Callable[[paramiko.Channel], None]


def _raw_table(size: int) -> bytes:
    """About `size` bytes of route table, with characters of two, three and
    four bytes in UTF-8, colour codes, CRLF line ends, and byte sequences that
    are not UTF-8 at all."""
    parts, total, i = [], 0, 0
    while total < size:
        row = (
            f"\x1b[32m*>\x1b[0m 10.{i // 256 % 256}.{i % 256}.0/24 \u2500 caf\xe9 \U0001f600 65000 {i} i\r\n"
        ).encode()
        if i % 101 == 0:
            row = b"bad \xff \xe2\x94( \xed\xa0\x80 \xc3" + row
        parts.append(row)
        total += len(row)
        i += 1
    return b"".join(parts)


def _odd_writes(data: bytes) -> list[bytes]:
    """`data` cut into writes of sizes that land inside multi-byte characters."""
    sizes = (1, 2, 3, 5, 7, 11, 4093, 65537)
    pieces, pos, k = [], 0, 0
    while pos < len(data):
        n = sizes[k % len(sizes)]
        pieces.append(data[pos : pos + n])
        pos += n
        k += 1
    return pieces


# --- a real paramiko device ---------------------------------------------------


class _Device(paramiko.ServerInterface):
    """Accepts any password and answers each exec request on a thread of its own."""

    def __init__(self, answers: dict[str, Answer]) -> None:
        self._answers = answers
        self.threads: list[threading.Thread] = []

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        thread = threading.Thread(target=self._answer, args=(channel, self._answers[command.decode()]))
        thread.start()
        self.threads.append(thread)
        return True

    @staticmethod
    def _answer(channel: paramiko.Channel, answer: Answer) -> None:
        # A client that has already gone, after a timeout, closes the channel
        # under the answer; that is the test's outcome, not a failure.
        with contextlib.suppress(OSError, EOFError, paramiko.SSHException):
            try:
                answer(channel)
                # EOF, and the close is left to the client. This thread starts
                # before paramiko replies to the exec request, and a channel
                # closed ahead of that reply fails the request itself.
                channel.shutdown_write()
                channel.recv(1)
            finally:
                channel.close()


@pytest.fixture
def device(monkeypatch, caplog):
    """Points `ssh._open_socket` at a device that gives a set of answers, one
    socket pair and one server transport per connection.

    Returns the event a stalled answer waits on; it is set at teardown so
    every device thread ends.

    A transport logs the peer's close of the socket pair at ERROR from its own
    thread, which can run after the test's log capture has closed; paramiko's
    logger stays at CRITICAL until every transport thread has been joined.
    """
    caplog.set_level(logging.CRITICAL, logger="paramiko")
    started: list[tuple[paramiko.Transport, _Device, socket.socket]] = []
    release = threading.Event()
    host_key = paramiko.ECDSAKey.generate()

    def serve(answers: dict[str, Answer]) -> threading.Event:
        def connect(host: str, port: int, timeout: int) -> socket.socket:
            client, server = socket.socketpair()
            dev = _Device(answers)
            transport = paramiko.Transport(server)
            transport.add_server_key(host_key)
            transport.start_server(event=threading.Event(), server=dev)
            started.append((transport, dev, client))
            return client

        monkeypatch.setattr(ssh, "_open_socket", connect)
        return release

    yield serve
    release.set()
    for transport, dev, client in started:
        transport.close()
        for thread in dev.threads:
            thread.join(10)
        transport.join(10)
        client.close()


def _sends(stdout: bytes, stderr: bytes = b"", status: int = 0) -> Answer:
    def answer(channel: paramiko.Channel) -> None:
        for piece in _odd_writes(stdout):
            channel.sendall(piece)
        if stderr:
            channel.sendall_stderr(stderr)
        channel.send_exit_status(status)

    return answer


def _run(command: str, *, read_timeout: int = 30) -> str:
    with ssh.session("r1", AUTH, read_timeout=read_timeout) as s:
        return s.run(command)


# --- exec: the answer ----------------------------------------------------------


def test_a_multi_mb_answer_over_a_real_channel_decodes_as_the_whole(device):
    raw = _raw_table(4 * 2**20)
    device({"show ip bgp": _sends(raw)})
    assert _run("show ip bgp") == sanitize_cli_text(raw.decode(errors="replace"))


class _ScriptedExec:
    """A paramiko exec channel whose standard output arrives in given byte chunks."""

    def __init__(self, chunks: list[bytes], err: bytes = b"", status: int = 0) -> None:
        self._out = list(chunks)
        self._err = [err] if err else []
        self._status = status
        self.closed = False

    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds

    def exec_command(self, command: str) -> None:
        self.command = command

    def recv(self, size: int) -> bytes:
        return self._out.pop(0) if self._out else b""

    def recv_stderr_ready(self) -> bool:
        return False

    def recv_stderr(self, size: int) -> bytes:
        return self._err.pop(0) if self._err else b""

    def recv_exit_status(self) -> int:
        return self._status

    def close(self) -> None:
        self.closed = True


def _exec_run(channel: object, command: str = "show ip bgp") -> str:
    class _Transport:
        def open_session(self, timeout=None):
            return channel

    return ssh.SshSession(_Transport(), "", "", open_timeout=1, read_timeout=1).run(command)


@pytest.mark.parametrize("size", [1, 2, 3, 5, 7])
def test_every_recv_boundary_inside_a_character_decodes_as_the_whole(size):
    raw = _raw_table(20_000)
    chunks = [raw[i : i + size] for i in range(0, len(raw), size)]
    channel = _ScriptedExec(chunks)
    assert _exec_run(channel) == sanitize_cli_text(raw.decode(errors="replace"))
    assert channel.closed


def test_random_recv_boundaries_decode_as_the_whole():
    raw = _raw_table(3 * 2**20)
    rng = random.Random(31)
    chunks, pos = [], 0
    while pos < len(raw):
        n = rng.randint(1, 65536)
        chunks.append(raw[pos : pos + n])
        pos += n
    assert _exec_run(_ScriptedExec(chunks)) == sanitize_cli_text(raw.decode(errors="replace"))


class _NoStatusEvent:
    """A status event that never fires: the device ends its streams and sends
    no exit status."""

    def wait(self, timeout: float) -> bool:
        return False


def _outcome(channel: object) -> tuple[str, str]:
    try:
        return "returned", _exec_run(channel)
    except ssh.SshError as exc:
        return type(exc).__name__, str(exc)


_AGREEMENT_CASES = {
    "clean": (b"OUT", b"", 0),
    "empty": (b"", b"", 0),
    "rejected at exit 0": (b"% Invalid input detected at '^' marker.", b"", 0),
    "banner on stdout at exit 16": (b"% Invalid command at '^' marker.\n", b"", 16),
    "stderr at exit 1": (b"partial\r\n", b"\x1b[31minvalid command\x1b[0m\r\n", 1),
    "no exit status": (b"OUT", b"OUTPUT", -1),
    "console-server bytes": (SHAPES["all of them together"].encode(), f"{ESC}[1;31m\x07".encode(), 0),
    "console-server bytes at exit 1": (
        SHAPES["all of them together"].encode(),
        f"{ESC}[1;31m\x07".encode(),
        1,
    ),
    "not utf-8 at exit 3": (_raw_table(20_000), b"\xff\xfe err \xe2\x94\r\n", 3),
}


def _whole_read_outcome(out: bytes, err: bytes, status: int, sends_status: bool) -> tuple[str, str]:
    """What `SshSession.run` gives for these streams when each is decoded and
    sanitized as one text: the answer, or the exception and its message."""
    stdout = sanitize_cli_text(out.decode(errors="replace"))
    stderr = sanitize_cli_text(err.decode(errors="replace"))
    if not sends_status:
        return "SshTimeout", "'show ip bgp' produced output but sent no exit status within 1s"
    if status > 0:
        return "CommandFailed", f"'show ip bgp' exited {status}: {ssh._failure_reason(stdout, stderr)}"
    rejection = ssh._cli_rejection(stdout)
    if rejection is not None:
        return "CommandFailed", f"'show ip bgp' rejected by device: {rejection}"
    return "returned", stdout


@pytest.mark.parametrize("sends_status", [True, False], ids=["status", "no-status-event"])
@pytest.mark.parametrize("case", list(_AGREEMENT_CASES))
def test_the_outcome_does_not_depend_on_where_recv_cuts_the_streams(case, sends_status):
    out, err, status = _AGREEMENT_CASES[case]
    streamed = _ScriptedExec([out[i : i + 3] for i in range(0, len(out), 3)], err, status)
    whole = FakeChannel(out=out, err=err, status=status)
    if not sends_status:
        streamed.status_event = whole.status_event = _NoStatusEvent()
    expected = _whole_read_outcome(out, err, status, sends_status)
    assert _outcome(streamed) == expected
    assert _outcome(whole) == expected
    assert streamed.closed and whole.closed
    # The read leaves the channel's timeout where the session set it.
    assert streamed.timeout == whole.timeout == 1


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("stderr at exit 1", "'show ip bgp' exited 1: invalid command"),
        ("not utf-8 at exit 3", "'show ip bgp' exited 3: �� err �"),
    ],
)
def test_standard_error_in_a_failure_message_is_decoded_with_replacement_and_sanitized(case, message):
    out, err, status = _AGREEMENT_CASES[case]
    assert _whole_read_outcome(out, err, status, True) == ("CommandFailed", message)
    streamed = _ScriptedExec([out[i : i + 3] for i in range(0, len(out), 3)], err, status)
    assert _outcome(streamed) == ("CommandFailed", message)


# --- exec: standard error ------------------------------------------------------


def _interleaved(stdout: bytes, stderr: bytes, status: int) -> Answer:
    def answer(channel: paramiko.Channel) -> None:
        step = 1 << 16
        for start in range(0, max(len(stdout), len(stderr)), step):
            channel.sendall(stdout[start : start + step])
            channel.sendall_stderr(stderr[start : start + step])
        channel.send_exit_status(status)

    return answer


def test_stderr_is_drained_while_stdout_streams(device):
    """Both streams share the channel's receive window."""
    out = b"".join(f" 10.{i % 256}.0.0/16 via 192.0.2.1\n".encode() for i in range(100_000))
    err = b"warning: a line the device wrote to standard error\n" * 60_000
    device({"noisy": _interleaved(out, err, 0), "noisy-fail": _interleaved(out, err, 2)})
    assert _run("noisy", read_timeout=10) == sanitize_cli_text(out.decode())
    with pytest.raises(ssh.CommandFailed) as caught:
        _run("noisy-fail", read_timeout=10)
    reason = sanitize_cli_text(err.decode()).strip()[: ssh._STDERR_REASON_MAX]
    assert str(caught.value) == f"'noisy-fail' exited 2: {reason}"


def _stderr_first(stdout: bytes, stderr: bytes, status: int) -> Answer:
    def answer(channel: paramiko.Channel) -> None:
        channel.sendall_stderr(stderr)
        channel.sendall(stdout)
        channel.send_exit_status(status)

    return answer


def test_stderr_past_the_window_before_any_stdout_does_not_stall(device):
    """3 MB of standard error, more than the receive window, before the first
    byte of standard output. A read that waits on standard output alone never
    frees the window, and the device never gets to its answer."""
    out = b"payload\r\n"
    err = b"warning: something the device wrote to standard error\n" * 60_000
    device({"noisy": _stderr_first(out, err, 0), "noisy-fail": _stderr_first(out, err, 2)})
    assert _run("noisy", read_timeout=10) == "payload\n"
    with pytest.raises(ssh.CommandFailed) as caught:
        _run("noisy-fail", read_timeout=10)
    reason = sanitize_cli_text(err.decode()).strip()[: ssh._STDERR_REASON_MAX]
    assert str(caught.value) == f"'noisy-fail' exited 2: {reason}"


def test_stderr_alone_does_not_extend_the_read_timeout(device):
    """The read timeout bounds the wait for standard output. A device that
    writes only to standard error runs into it as one that writes nothing
    does."""

    def chatters(channel: paramiko.Channel) -> None:
        for _ in range(100):
            channel.sendall_stderr(b"still working\n")
            if release.wait(0.05):
                break
        channel.send_exit_status(0)

    # The device writes to standard error for 5 s and then exits with status 0.
    # A read that standard error extends ends with that exit and raises nothing.
    release = device({"chatty": chatters})
    with pytest.raises(ssh.SshTimeout) as caught:
        _run("chatty", read_timeout=1)
    assert str(caught.value) == "'chatty' produced no further output within 1s"


# --- exec: the read timeout ----------------------------------------------------


def test_an_exec_read_that_stops_is_ssh_timeout(device):
    def stalls(channel: paramiko.Channel) -> None:
        channel.sendall(_raw_table(100_000))
        release.wait(30)

    release = device({"slow": stalls})
    with pytest.raises(ssh.SshTimeout) as caught:
        _run("slow", read_timeout=1)
    assert str(caught.value) == "'slow' produced no further output within 1s"


# --- the shell twin ------------------------------------------------------------


class _ByteShell:
    """A paramiko shell channel that answers a command with given byte chunks.

    The login burst ends in the prompt, and a bare newline is answered with
    the prompt alone, as a device at an exec prompt answers it. `recv` raises
    `TimeoutError` once nothing is queued, as a quiet channel does.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self._queue = [f"banner\r\n{PROMPT}".encode()]

    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds

    def recv(self, size: int) -> bytes:
        if not self._queue:
            raise TimeoutError
        return self._queue.pop(0)

    def sendall(self, data: bytes) -> None:
        if data.strip():
            self._queue.extend(self._chunks)
        else:
            self._queue.append(f"\r\n{PROMPT}".encode())


def test_the_shell_reads_a_multi_mb_answer_as_one_decode_of_the_whole():
    """A character cut by a recv boundary reads as the character, and the
    answer is the whole stream decoded and sanitized as one text."""
    raw = b"show ip bgp\r\n" + _raw_table(3 * 2**20) + PROMPT.encode()
    rng = random.Random(41)
    chunks, pos = [], 0
    while pos < len(raw):
        n = rng.choice((1, 2, 3, 7, 4096, 65536))
        chunks.append(raw[pos : pos + n])
        pos += n
    shell = ssh.ShellSession(_ByteShell(chunks), "k", "", read_timeout=30)
    expected = reference_shell_output_of(
        sanitize_cli_text(raw.decode(errors="replace")), "show ip bgp", PROMPT
    )
    assert shell.run("show ip bgp") == expected
    assert "\ufffd" in expected


def test_a_shell_read_that_stops_is_ssh_timeout():
    """An answer that never reaches the prompt: the channel goes quiet."""
    shell = ssh.ShellSession(_ByteShell([b"show ip bgp\r\n", _raw_table(100_000)]), "k", "", read_timeout=5)
    with pytest.raises(ssh.SshTimeout) as caught:
        shell.run("show ip bgp")
    assert str(caught.value) == "'show ip bgp' produced no further output within 5s"
