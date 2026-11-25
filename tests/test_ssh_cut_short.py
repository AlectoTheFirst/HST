"""An exec answer the connection cut short fails its command."""

from __future__ import annotations

import asyncio
import re
import threading

import asyncssh
import paramiko
import pytest
from tests.conftest import FakeSshSession
from tests.support.ssh_device import joined_paramiko_transports, outcomes, serve, write_all
from tests.test_assh_transport import _Recorder, _Server
from tests.test_cli_collector import AUTH, DemoCollector, DemoConfig
from tests.test_ssh_streaming import _ScriptedExec

from hst.collectors import assh, ssh
from hst.collectors.base import RAW_OUTCOMES_KEY

# Plain text, larger than either client's receive window, so the device's
# writes wait on the client's reads: by the time the last one is queued the
# client is reading the answer.
TABLE = "".join(f"*> 10.{i // 256 % 256}.{i % 256}.0/24 192.0.2.1 0 65000 {i} i\n" for i in range(80_000))

# The two ways a transport words an answer the connection cut short, each
# with the byte count it read, and the cause when there is one.
CUT_SHORT = re.compile(
    r"'show ip bgp' was cut short: (?:"
    r"the connection ended after (?P<ended>\d+) bytes of its answer, before the device ended the "
    r"channel or sent an exit status"
    r"|the read failed after (?P<failed>\d+) bytes of its answer, and data that had arrived after them "
    r"was lost"
    r")(?P<cause> \(.+\))?"
)


async def _ends_the_connection_inside_the_answer(process: asyncssh.SSHServerProcess) -> None:
    await write_all(process, TABLE)
    process.get_extra_info("connection").abort()


async def _disconnects_inside_the_answer(process: asyncssh.SSHServerProcess) -> None:
    # The server's `close()` closes the channel first.
    await write_all(process, TABLE[: 1 << 16])
    conn = process.get_extra_info("connection")
    conn._send_disconnect(asyncssh.DISC_BY_APPLICATION, "idle timeout", "en-US")
    conn._force_close(None)


async def _closes_the_channel(process: asyncssh.SSHServerProcess) -> None:
    # A close with no end of file and no exit status before it.
    process.stdout.write("payload\r\n")
    process.close()


async def _closes_the_channel_and_the_connection(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write("payload\r\n")
    process.close()
    process.get_extra_info("connection").close()


async def _closes_after_a_large_answer_and_ends_the_connection(process: asyncssh.SSHServerProcess) -> None:
    # The close is sent after the last of the answer, and the client's close
    # in reply arrives once the client has received all of it; only then does
    # the device end the connection.
    await write_all(process, TABLE)
    process.close()
    await process.wait_closed()
    process.get_extra_info("connection").close()


async def _exits_after_a_large_answer_and_ends_the_connection(process: asyncssh.SSHServerProcess) -> None:
    await write_all(process, TABLE)
    process.exit(0)
    await process.wait_closed()
    process.get_extra_info("connection").close()


async def _answers(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write("ok\n")
    process.exit(0)


BEHAVIOURS = {
    "show ip bgp": _ends_the_connection_inside_the_answer,
    "show disconnect": _disconnects_inside_the_answer,
    "show closed": _closes_the_channel,
    "show once": _closes_the_channel_and_the_connection,
    "show table closed": _closes_after_a_large_answer_and_ends_the_connection,
    "show table exited": _exits_after_a_large_answer_and_ends_the_connection,
    "show version": _answers,
}


@pytest.fixture
def paramiko_transports(monkeypatch):
    with joined_paramiko_transports(monkeypatch) as made:
        yield made


TRANSPORTS = pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])


# --- over a real connection ------------------------------------------------------


@TRANSPORTS
async def test_a_connection_that_ends_inside_the_answer_fails_the_command(transport, paramiko_transports):
    async with serve(BEHAVIOURS) as port:
        (kind, message), (next_kind, next_message) = await outcomes(
            transport, port, ["show ip bgp", "show version"]
        )
    assert kind == "AnswerIncomplete"
    match = CUT_SHORT.fullmatch(message)
    assert match is not None, message
    assert 0 < int(match.group("ended") or match.group("failed")) <= len(TABLE)
    if match.group("failed") is not None:
        # A paramiko recv whose window adjust met the ended connection. The
        # detail names the exception paramiko raised.
        assert transport == "paramiko"
        assert match.group("cause") is not None
    # The session has no connection left, and the next command says so on
    # both transports alike.
    assert next_kind == "SshTimeout"
    assert next_message.startswith("'show version' could not open an exec channel: ")


@TRANSPORTS
async def test_a_device_that_disconnects_inside_the_answer_fails_the_command(transport, paramiko_transports):
    """The device ends the connection with a disconnect message, with the
    channel open."""
    async with serve(BEHAVIOURS) as port:
        [(kind, message)] = await outcomes(transport, port, ["show disconnect"])
    assert kind == "AnswerIncomplete"
    assert message.startswith("'show disconnect' was cut short: ")


@TRANSPORTS
async def test_a_channel_closed_with_neither_eof_nor_exit_status_is_a_whole_answer(
    transport, paramiko_transports
):
    async with serve(BEHAVIOURS) as port:
        got = await outcomes(transport, port, ["show closed", "show version"])
    assert got == [("returned", "payload\n"), ("returned", "ok\n")]


@TRANSPORTS
async def test_a_device_that_closes_the_channel_and_the_connection_at_once_gives_its_answer(
    transport, paramiko_transports
):
    """A device that allows one command per connection answers, closes the
    channel and ends the connection in one burst. asyncssh drops the data it
    holds for a channel whose connection ends before it starts delivering
    that channel's data, so the read starts the delivery itself
    (`AsyncSshSession._open`). Every run reads the whole answer, on both
    transports."""
    async with serve(BEHAVIOURS) as port:
        for _ in range(20):
            assert await outcomes(transport, port, ["show once"]) == [("returned", "payload\n")]


@TRANSPORTS
@pytest.mark.parametrize("command", ["show table closed", "show table exited"])
async def test_a_large_answer_is_whole_when_the_device_ends_the_connection_right_after_it(
    transport, command, paramiko_transports, monkeypatch
):
    real = assh._read_stream

    async def behind(reader, answer, *, sanitize):
        class _Behind:
            async def read(self, n: int) -> str:
                await asyncio.sleep(0.001)
                return await reader.read(min(n, 1 << 14))

        return await real(_Behind(), answer, sanitize=sanitize)

    monkeypatch.setattr(assh, "_read_stream", behind)
    async with serve(BEHAVIOURS) as port:
        for _ in range(3):
            assert await outcomes(transport, port, [command]) == [("returned", TABLE)]


class _RefusesOneExec(asyncssh.SSHServerSession):
    """A session that refuses the exec request for 'show refused' and
    answers any other command with "ok"."""

    def connection_made(self, chan) -> None:
        self._chan = chan

    def exec_requested(self, command: str) -> bool:
        return command != "show refused"

    def session_started(self) -> None:
        self._chan.write("ok\n")
        self._chan.exit(0)


class _RefusingServer(_Server):
    def session_requested(self):
        return _RefusesOneExec()


@TRANSPORTS
async def test_a_refused_exec_request_is_named_alike_and_the_session_goes_on(transport, paramiko_transports):
    key = asyncssh.generate_private_key("ssh-ed25519")
    listener = await asyncssh.listen(
        "127.0.0.1", 0, server_factory=lambda: _RefusingServer(_Recorder()), server_host_keys=[key]
    )
    try:
        (kind, message), after = await outcomes(
            transport, listener.get_port(), ["show refused", "show version"]
        )
    finally:
        listener.close()
        await listener.wait_closed()
    assert kind == "SshTimeout"
    assert message.startswith("'show refused' could not open an exec channel: ")
    assert after == ("returned", "ok\n")


# --- paramiko: where the answer ended --------------------------------------------


def _exec_run(channel, *, open_timeout: float = 1) -> str:
    class _Transport:
        def open_session(self, timeout=None):
            return channel

    return ssh.SshSession(_Transport(), "", "", open_timeout=open_timeout, read_timeout=1).run("show ip bgp")


@pytest.mark.parametrize(
    ("eof_received", "eof_sent", "status", "whole"),
    [
        # The device's end of file.
        (True, False, -1, True),
        # The device's close, which paramiko answers with an end of file.
        (False, True, -1, True),
        # The exit status, with the channel ended by the connection after it.
        (False, False, 0, True),
        # None of them: the connection ended the channel.
        (False, False, -1, False),
    ],
)
def test_paramiko_reads_where_the_answer_ended_from_the_channel(eof_received, eof_sent, status, whole):
    channel = _ScriptedExec([b"part of a ", b"table\r\n"], status=status)
    channel.eof_received = eof_received
    channel.eof_sent = eof_sent
    if whole:
        assert _exec_run(channel) == "part of a table\n"
    else:
        with pytest.raises(ssh.AnswerIncomplete) as caught:
            _exec_run(channel)
        assert str(caught.value) == (
            "'show ip bgp' was cut short: the connection ended after 17 bytes of its answer, "
            "before the device ended the channel or sent an exit status"
        )
    assert channel.closed


def test_a_paramiko_answer_cut_short_with_an_exit_status_above_zero_fails_on_the_status():
    channel = _ScriptedExec([b"partial\r\n"], err=b"boom\r\n", status=2)
    channel.eof_received = channel.eof_sent = False
    with pytest.raises(ssh.CommandFailed) as caught:
        _exec_run(channel)
    assert type(caught.value) is ssh.CommandFailed
    assert str(caught.value) == "'show ip bgp' exited 2: boom"


class _EndedConnection(_ScriptedExec):
    """An exec channel whose connection has ended under it, as paramiko sees
    it before its transport thread notices: the given pieces, then a recv
    whose window adjust raises `fails` after it took a piece, and a close
    whose end of file and close raise it too."""

    def __init__(self, pieces: list[bytes], fails: BaseException, *, taken: bytes = b"") -> None:
        super().__init__(pieces)
        self._fails = fails
        self._taken = taken
        self.eof_received = self.eof_sent = False

    def recv(self, size: int) -> bytes:
        if self._out:
            return self._out.pop(0)
        if self._taken:
            raise self._fails
        return b""

    def close(self) -> None:
        self.closed = True
        raise self._fails


@pytest.mark.parametrize(
    "fails",
    [EOFError(), OSError("Socket is closed"), paramiko.SSHException("Key-exchange timed out")],
    ids=["eof", "socket", "rekey"],
)
def test_a_paramiko_recv_that_fails_fails_the_command(fails):
    """The recv had taken data from the channel before its window adjust
    raised, so that data is lost whatever the device sent after it."""
    channel = _EndedConnection([b"part of a ", b"table\r\n"], fails, taken=b"more")
    with pytest.raises(ssh.AnswerIncomplete) as caught:
        _exec_run(channel)
    cause = f"{type(fails).__name__}: {fails}" if str(fails) else type(fails).__name__
    assert str(caught.value) == (
        "'show ip bgp' was cut short: the read failed after 17 bytes of its answer, and data that had "
        f"arrived after them was lost ({cause})"
    )
    assert caught.value.__cause__ is fails
    assert channel.closed


def test_a_paramiko_close_that_fails_after_a_whole_answer_keeps_the_answer():
    channel = _EndedConnection([b"payload\r\n"], EOFError())
    channel.eof_sent = True
    assert _exec_run(channel) == "payload\n"
    assert channel.closed


@pytest.mark.parametrize(
    "error",
    [
        paramiko.SSHException("SSH session not active"),
        paramiko.ChannelException(2, "Connect failed"),
        EOFError(),
    ],
    ids=["session-not-active", "open-refused", "eof"],
)
def test_a_paramiko_channel_that_cannot_open_is_named_as_asyncssh_names_it(error):
    class _Transport:
        def open_session(self, timeout=None):
            raise error

    with pytest.raises(ssh.SshTimeout) as caught:
        ssh.SshSession(_Transport(), "", "", open_timeout=1, read_timeout=1).run("show version")
    assert (
        str(caught.value)
        == f"'show version' could not open an exec channel: {str(error) or type(error).__name__}"
    )
    assert caught.value.__cause__ is error


@pytest.mark.parametrize(
    "error", [paramiko.SSHException("Channel closed."), EOFError()], ids=["refused", "eof"]
)
def test_a_paramiko_exec_request_that_fails_is_named_as_a_channel_that_does_not_open(error):
    class _Refused(_ScriptedExec):
        def exec_command(self, command: str) -> None:
            raise error

    channel = _Refused([b"never read\r\n"])
    with pytest.raises(ssh.SshTimeout) as caught:
        _exec_run(channel)
    assert (
        str(caught.value)
        == f"'show ip bgp' could not open an exec channel: {str(error) or type(error).__name__}"
    )
    assert caught.value.__cause__ is error
    assert channel.closed


def test_a_paramiko_exec_request_left_unanswered_is_a_timeout_not_a_hang():
    """paramiko waits for the answer to an exec request with no timeout of
    its own. The close at the open timeout ends the wait, as paramiko's own
    close does: the waiter sees the channel closed."""

    class _Unanswered(_ScriptedExec):
        def __init__(self) -> None:
            super().__init__([b"never read\r\n"])
            self._closed = threading.Event()

        def exec_command(self, command: str) -> None:
            self._closed.wait(30)
            raise paramiko.SSHException("Channel closed.")

        def close(self) -> None:
            self.closed = True
            self._closed.set()

    channel = _Unanswered()
    with pytest.raises(ssh.SshTimeout) as caught:
        _exec_run(channel, open_timeout=0.05)
    assert (
        str(caught.value)
        == "'show ip bgp' could not open an exec channel: the device did not answer within 0.05s"
    )
    assert channel.closed


# --- asyncssh: where the answer ended ----------------------------------------------


class _Reader:
    """An asyncssh stream: the given pieces, then `ends` raised, or the end."""

    def __init__(self, pieces: list[str], ends: Exception | None = None) -> None:
        self._pieces = list(pieces)
        self._ends = ends

    async def read(self, n: int = -1) -> str:
        if self._pieces:
            return self._pieces.pop(0)
        if self._ends is not None:
            raise self._ends
        return ""


class _Process:
    def __init__(self, stdout: _Reader, stderr: _Reader, exit_status: int | None) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status
        self.closed = False

    async def wait_closed(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class _Conn:
    def __init__(self, process: _Process) -> None:
        self.process = process

    async def create_process(self, command, **kwargs):
        return self.process


async def _arun(process: _Process, *, open_timeout: float = 120) -> str:
    session = assh.AsyncSshSession(_Conn(process), "", "", read_timeout=5, open_timeout=open_timeout)
    return await session.run("show ip bgp")


async def test_asyncssh_accepts_an_answer_whose_exit_status_arrived_before_the_connection_ended():
    lost = asyncssh.ConnectionLost("Connection lost")
    process = _Process(_Reader(["part of a ", "table\r\n"], lost), _Reader([], lost), 0)
    assert await _arun(process) == "part of a table\n"
    assert process.closed


async def test_asyncssh_fails_an_answer_the_connection_ended_without_an_exit_status():
    lost = asyncssh.ConnectionLost("Connection lost")
    process = _Process(_Reader(["part of a ", "täble\r\n"], lost), _Reader([], lost), None)
    with pytest.raises(ssh.AnswerIncomplete) as caught:
        await _arun(process)
    assert str(caught.value) == (
        "'show ip bgp' was cut short: the connection ended after 18 bytes of its answer, "
        "before the device ended the channel or sent an exit status (ConnectionLost: Connection lost)"
    )
    assert caught.value.__cause__ is lost
    assert process.closed


async def test_asyncssh_fails_an_answer_when_only_standard_error_saw_the_connection_end():
    lost = ConnectionResetError(54, "Connection reset by peer")
    process = _Process(_Reader(["part"]), _Reader(["warn"], lost), None)
    with pytest.raises(ssh.AnswerIncomplete, match=r"after 8 bytes .* \(ConnectionResetError: "):
        await _arun(process)


class _Channel:
    """The parts of an asyncssh channel the read looks at: its receive state,
    and delivery, which a paused channel holds back until it is resumed."""

    def __init__(self, recv_state: str = "closed") -> None:
        self._recv_state = recv_state
        self.resumed = 0

    def resume_reading(self) -> None:
        self.resumed += 1


@pytest.mark.parametrize(
    ("recv_state", "ended", "whole"),
    [
        # The device's close or end of file was received.
        ("closed", None, True),
        ("eof", None, True),
        # A close received, with the connection's exception queued behind it.
        ("closed", asyncssh.ConnectionLost("bye"), True),
        # Neither: a disconnect "by application" queues no exception.
        ("open", None, False),
        ("open", asyncssh.ConnectionLost("bye"), False),
    ],
)
async def test_asyncssh_reads_where_the_answer_ended_from_the_channel(recv_state, ended, whole):
    process = _Process(_Reader(["part of a table\r\n"], ended), _Reader([]), None)
    process.channel = _Channel(recv_state)
    if whole:
        assert await _arun(process) == "part of a table\n"
        return
    with pytest.raises(ssh.AnswerIncomplete) as caught:
        await _arun(process)
    cause = f" (ConnectionLost: {ended})" if ended is not None else ""
    assert str(caught.value) == (
        "'show ip bgp' was cut short: the connection ended after 17 bytes of its answer, "
        f"before the device ended the channel or sent an exit status{cause}"
    )


async def test_asyncssh_starts_the_channels_delivery_before_the_read_yields():
    """Asyncssh drops the data a channel holds when its connection ends
    before delivery started."""

    class _Stdout(_Reader):
        def __init__(self, channel: _Channel) -> None:
            super().__init__([])
            self._channel = channel
            self._held = ["payload\r\n"]
            asyncio.get_running_loop().call_soon(self._connection_ends)

        def _connection_ends(self) -> None:
            if not self._channel.resumed:
                self._held.clear()
            self._pieces.extend(self._held)

        async def read(self, n: int = -1) -> str:
            await asyncio.sleep(0)
            return await super().read(n)

    channel = _Channel()
    process = _Process(_Stdout(channel), _Reader([]), None)
    process.channel = channel
    assert await _arun(process) == "payload\n"
    assert channel.resumed == 1


async def test_asyncssh_delivers_what_the_channel_holds_before_the_streams_end():
    """Delivery resumes inside `connection_lost`."""

    class _Stdout(_Reader):
        def __init__(self) -> None:
            super().__init__(["head of the table\r\n"])
            self.ended = asyncio.Event()

        async def read(self, n: int = -1) -> str:
            if not self._pieces:
                await self.ended.wait()
            return await super().read(n)

    class _HoldingChannel(_Channel):
        def __init__(self, process: _HoldingProcess) -> None:
            super().__init__("open")
            self._process: _HoldingProcess | None = process
            self._held: list[str] = []

        def resume_reading(self) -> None:
            super().resume_reading()
            if self._process is not None and self._held:
                self._process.stdout._pieces.extend(self._held)
                self._recv_state = "closed"
            self._held = []

        def connection_ends(self) -> None:
            # The tail and the device's close arrived while delivery was
            # paused, and the connection ended right after.
            self._held = ["tail of the table\r\n"]
            self._recv_state = "close_pending"
            assert self._process is not None
            self._process.connection_lost(None)
            self._process = None

    class _HoldingProcess(_Process):
        def __init__(self) -> None:
            super().__init__(_Stdout(), _Reader([]), None)
            self.channel = _HoldingChannel(self)

        def connection_lost(self, exc: Exception | None) -> None:
            self.stdout.ended.set()

    process = _HoldingProcess()
    asyncio.get_running_loop().call_soon(process.channel.connection_ends)
    assert await _arun(process) == "head of the table\ntail of the table\n"


async def test_an_asyncssh_exec_request_left_unanswered_is_a_timeout_not_a_hang():
    class _Unanswered:
        async def create_process(self, command, **kwargs):
            await asyncio.Event().wait()

    session = assh.AsyncSshSession(_Unanswered(), "", "", read_timeout=5, open_timeout=0.05)
    with pytest.raises(ssh.SshTimeout) as caught:
        await session.run("show ip bgp")
    assert (
        str(caught.value)
        == "'show ip bgp' could not open an exec channel: the device did not answer within 0.05s"
    )


# --- the shells ---------------------------------------------------------------


async def test_an_async_shell_whose_connection_ends_raises_ssh_error_and_stops():
    lost = asyncssh.ConnectionLost("Connection lost")
    prompt = "r1#"

    class _ShellStdout:
        def __init__(self) -> None:
            self.queue: list[str] = [f"banner\r\n{prompt}"]
            self.lost = False

        async def read(self, n: int) -> str:
            if self.queue:
                return self.queue.pop(0)
            if self.lost:
                raise lost
            await asyncio.sleep(3600)
            return ""

    stdout = _ShellStdout()

    class _Stdin:
        def write(self, data: str) -> None:
            if data.strip():
                stdout.queue.append(f"{data.strip()}\r\npart of a table\r\n")
                stdout.lost = True
            else:
                stdout.queue.append(f"\r\n{prompt}")

    class _ShellProcess:
        def __init__(self) -> None:
            self.stdout = stdout
            self.stdin = _Stdin()

        def close(self) -> None:
            pass

    class _ShellConn:
        async def create_process(self, **kwargs):
            return _ShellProcess()

    shell = await assh.AsyncShellSession.open(_ShellConn(), "k", "", read_timeout=5)
    with pytest.raises(ssh.SshError) as caught:
        await shell.run("show ip bgp")
    assert type(caught.value) is ssh.SshError
    assert str(caught.value) == "the connection ended during 'show ip bgp' (ConnectionLost: Connection lost)"
    assert caught.value.__cause__ is lost
    with pytest.raises(ssh.SshError, match="no later command was sent"):
        await shell.run("show version")


class _EndingShell:
    """A paramiko shell channel whose connection ends under a read: the
    login, a prompt for each bare newline, and for a command its echo and
    part of an answer, after which a recv raises `fails`, as a window adjust
    on the ended connection does. `at_login` ends it during the login."""

    def __init__(self, fails: BaseException, *, at_login: bool = False) -> None:
        self._fails = fails
        self._queue = [b"banner\r\n"] if at_login else [b"banner\r\nr1#"]
        self._ending = at_login
        self.closed = False

    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds

    def recv(self, size: int) -> bytes:
        if self._queue:
            return self._queue.pop(0)
        if self._ending:
            raise self._fails
        raise TimeoutError

    def sendall(self, data: bytes) -> None:
        command = data.decode().strip()
        if not command:
            self._queue.append(b"\r\nr1#")
            return
        self._queue.append(f"{command}\r\npart of a table\r\n".encode())
        self._ending = True

    def close(self) -> None:
        self.closed = True


def test_a_paramiko_shell_whose_connection_ends_raises_ssh_error_and_stops():
    fails = EOFError()
    shell = ssh.ShellSession(_EndingShell(fails), "k", "", read_timeout=5)
    with pytest.raises(ssh.SshError) as caught:
        shell.run("show ip bgp")
    assert type(caught.value) is ssh.SshError
    assert str(caught.value) == "the connection ended during 'show ip bgp' (EOFError)"
    assert caught.value.__cause__ is fails
    with pytest.raises(ssh.SshError) as later:
        shell.run("show version")
    assert str(later.value) == (
        "the shell session stopped after 'show ip bgp' ended before its prompt "
        "(SshError: the connection ended during 'show ip bgp' (EOFError)); no later command was sent"
    )


def test_a_paramiko_shell_whose_connection_ends_at_login_is_an_ssh_error():
    with pytest.raises(ssh.SshError) as caught:
        ssh.ShellSession(_EndingShell(OSError("Socket is closed"), at_login=True), "k", "", read_timeout=5)
    assert type(caught.value) is ssh.SshError
    assert str(caught.value) == (
        "the connection ended before the device sent a prompt (OSError: Socket is closed)"
    )


# --- the collector ---------------------------------------------------------------


def _cut_short(command: str) -> ssh.AnswerIncomplete:
    return ssh.AnswerIncomplete(
        f"{command!r} was cut short: the connection ended after 5 bytes of its answer, "
        "before the device ended the channel or sent an exit status"
    )


@TRANSPORTS
def test_an_optional_command_cut_short_is_a_failed_section(monkeypatch, transport):
    def answer(command: str) -> str:
        if command == "show inventory":
            raise _cut_short(command)
        return "V"

    FakeSshSession(answer).install(monkeypatch)
    raw = DemoCollector(DemoConfig(host="r1", auth=AUTH, transport=transport), None).fetch()
    assert raw["show inventory"] == "STANDIN"
    assert raw[RAW_OUTCOMES_KEY]["show inventory"] == {
        "status": "failed",
        "detail": str(_cut_short("show inventory")),
    }


@TRANSPORTS
def test_a_required_command_cut_short_fails_the_device(monkeypatch, transport):
    def answer(command: str) -> str:
        raise _cut_short(command)

    FakeSshSession(answer).install(monkeypatch)
    with pytest.raises(ssh.AnswerIncomplete, match="'show version' was cut short"):
        DemoCollector(DemoConfig(host="r1", auth=AUTH, transport=transport), None).fetch()
