"""The answer limit, `COLLECT_MAX_ANSWER_MB`, on every SSH session type.

An answer larger than the limit fails its command with `ssh.AnswerTooLarge`,
a `CommandFailed`. The read stops at the first piece that passes the limit
and closes the channel or process, and nothing of the answer is returned. An
optional command is then a failed section whose detail states the limit and
the size read, and a required one fails the device. On a shell session the
next command runs on a new shell of the same connection. An answer at the
limit is read whole, and 0 is no limit.
"""

from __future__ import annotations

import asyncio
import contextlib
from types import SimpleNamespace

import asyncssh
import pytest
from pydantic import ValidationError
from tests.conftest import FakeSshSession
from tests.support.ssh_device import joined_paramiko_transports, outcomes, serve, write_all
from tests.test_assh_transport import PW
from tests.test_cli_collector import AUTH, DemoCollector, DemoConfig
from tests.test_ssh_streaming import _ScriptedExec

from hst.collectors import assh, ssh
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.core import Settings

MIB = 1 << 20
PIECE = 1 << 16
PROMPT = "r1#"


def _too_large(what: str, size: int, limit_mb: int = 1) -> str:
    return f"{what} is larger than the answer limit of {limit_mb} MiB: the read stopped after {size} bytes"


@pytest.fixture
def paramiko_transports(monkeypatch):
    with joined_paramiko_transports(monkeypatch) as made:
        yield made


# --- the count -----------------------------------------------------------------


def test_the_budget_takes_up_to_the_limit_and_raises_past_it():
    answer = ssh._AnswerBudget("the answer to 'show x'", 1)
    answer.take(MIB - 1)
    answer.take(1)
    assert answer.size == MIB
    with pytest.raises(ssh.AnswerTooLarge) as caught:
        answer.take(1)
    assert str(caught.value) == _too_large("the answer to 'show x'", MIB + 1)
    assert isinstance(caught.value, ssh.CommandFailed)


def test_a_limit_of_zero_is_no_limit():
    answer = ssh._AnswerBudget("the answer to 'show x'", 0)
    answer.take(64 * MIB)
    assert answer.size == 64 * MIB


# --- paramiko exec ---------------------------------------------------------------


def _exec_run(channel, *, limit_mb: int = 1) -> str:
    class _Transport:
        def open_session(self, timeout=None):
            return channel

    session = ssh.SshSession(_Transport(), "", "", open_timeout=1, read_timeout=1, max_answer_mb=limit_mb)
    return session.run("show ip bgp")


def test_paramiko_exec_stops_at_the_first_recv_past_the_limit():
    channel = _ScriptedExec([b"x" * PIECE] * 20)
    with pytest.raises(ssh.AnswerTooLarge) as caught:
        _exec_run(channel)
    assert str(caught.value) == _too_large("the answer to 'show ip bgp'", 17 * PIECE)
    # Three pieces were never read, and the channel is closed.
    assert len(channel._out) == 3
    assert channel.closed


def test_paramiko_exec_reads_an_answer_at_the_limit_whole():
    channel = _ScriptedExec([b"x" * PIECE] * 16)
    assert _exec_run(channel) == "x" * MIB


def test_paramiko_exec_counts_standard_error_too():
    channel = _ScriptedExec([b"o" * (600 * 1024)], err=b"e" * (600 * 1024))
    with pytest.raises(ssh.AnswerTooLarge) as caught:
        _exec_run(channel)
    assert str(caught.value) == _too_large("the answer to 'show ip bgp'", 1200 * 1024)


def test_paramiko_exec_without_a_limit_reads_any_answer():
    channel = _ScriptedExec([b"x" * PIECE] * 40)
    assert _exec_run(channel, limit_mb=0) == "x" * (40 * PIECE)


# --- asyncssh exec ---------------------------------------------------------------


class _Reader:
    def __init__(self, pieces: list[str]) -> None:
        self.pieces = list(pieces)

    async def read(self, n: int = -1) -> str:
        return self.pieces.pop(0) if self.pieces else ""


class _Process:
    def __init__(self, stdout: list[str], stderr: tuple[str, ...] = ()) -> None:
        self.stdout = _Reader(stdout)
        self.stderr = _Reader(list(stderr))
        self.exit_status = 0
        self.closed = False

    async def wait_closed(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _Conn:
    def __init__(self, process: _Process) -> None:
        self.process = process

    async def create_process(self, command, **kwargs):
        return self.process


async def _arun(process: _Process, *, limit_mb: int = 1) -> str:
    session = assh.AsyncSshSession(_Conn(process), "", "", read_timeout=5, max_answer_mb=limit_mb)
    return await session.run("show ip bgp")


async def test_asyncssh_exec_stops_at_the_first_read_past_the_limit():
    process = _Process(["x" * PIECE] * 20)
    with pytest.raises(ssh.AnswerTooLarge) as caught:
        await _arun(process)
    assert str(caught.value) == _too_large("the answer to 'show ip bgp'", 17 * PIECE)
    assert len(process.stdout.pieces) == 3
    assert process.closed


async def test_asyncssh_exec_counts_the_answer_in_utf8_and_standard_error_too():
    # 256 KiB of a two-byte character is 512 KiB, and standard error adds
    # the 512 KiB and one byte that pass the limit.
    process = _Process(["\u00e9" * (256 * 1024)], ("e" * (512 * 1024 + 1),))
    with pytest.raises(ssh.AnswerTooLarge) as caught:
        await _arun(process)
    assert str(caught.value) == _too_large("the answer to 'show ip bgp'", MIB + 1)


async def test_asyncssh_exec_reads_an_answer_at_the_limit_whole():
    process = _Process(["x" * PIECE] * 16)
    assert await _arun(process) == "x" * MIB


# --- both exec paths over a real connection -------------------------------------


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
async def test_an_exec_answer_past_the_limit_fails_and_the_session_goes_on(transport, paramiko_transports):
    table = "*> 10.0.0.0/24 192.0.2.1 0 65000 i\n" * (8 * MIB // 35)
    finished: list[bool] = []

    async def floods(process: asyncssh.SSHServerProcess) -> None:
        # The client closes the channel under the writes.
        with contextlib.suppress(OSError, asyncssh.Error):
            await write_all(process, table)
            finished.append(True)
            process.exit(0)

    async def answers(process: asyncssh.SSHServerProcess) -> None:
        process.stdout.write("ok\n")
        process.exit(0)

    async with serve({"show ip bgp": floods, "show version": answers}) as port:
        (kind, message), after = await outcomes(
            transport, port, ["show ip bgp", "show version"], max_answer_mb=1
        )
    assert kind == "AnswerTooLarge"
    prefix = "the answer to 'show ip bgp' is larger than the answer limit of 1 MiB: the read stopped after "
    assert message.startswith(prefix)
    assert MIB < int(message.removeprefix(prefix).removesuffix(" bytes")) <= MIB + (1 << 18)
    assert after == ("returned", "ok\n")
    assert finished == []


# --- the shells ----------------------------------------------------------------


class _ShellChannel:
    """A paramiko shell channel: the login, a prompt for each bare newline,
    and for a command its echo followed by the byte pieces `answers` holds
    for it, or by the prompt alone."""

    def __init__(self, answers: dict[str, list[bytes]], login: bytes) -> None:
        self.answers = answers
        self.queue = [login]
        self.sent: list[str] = []
        self.closed = False

    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds

    def recv(self, size: int) -> bytes:
        if not self.queue:
            raise TimeoutError
        return self.queue.pop(0)

    def sendall(self, data: bytes) -> None:
        command = data.decode().strip()
        if not command:
            self.queue.append(f"\r\n{PROMPT}".encode())
            return
        self.sent.append(command)
        self.queue.append(f"{command}\r\n".encode())
        self.queue.extend(self.answers.get(command, [PROMPT.encode()]))

    def close(self) -> None:
        self.closed = True


class _Shells:
    """One device's shells: each open is a new `_ShellChannel`, with the
    answers of `later` from the second open on when it is given."""

    def __init__(
        self,
        answers: dict[str, list[bytes]],
        *,
        login: bytes = f"banner\r\n{PROMPT}".encode(),
        later: dict[str, list[bytes]] | None = None,
    ) -> None:
        self._answers = answers
        self._later = later
        self._login = login
        self.opened: list[_ShellChannel] = []

    def open(self) -> _ShellChannel:
        answers = self._later if self.opened and self._later is not None else self._answers
        channel = _ShellChannel(answers, self._login)
        self.opened.append(channel)
        return channel


class _ShellStdout:
    def __init__(self, channel: _ShellChannel) -> None:
        self._channel = channel

    async def read(self, n: int) -> str:
        return self._channel.recv(n).decode()


class _ShellStdin:
    def __init__(self, channel: _ShellChannel) -> None:
        self._channel = channel

    def write(self, data: str) -> None:
        self._channel.sendall(data.encode())


class _ShellProcess:
    def __init__(self, channel: _ShellChannel) -> None:
        self.stdout = _ShellStdout(channel)
        self.stdin = _ShellStdin(channel)
        self.channel = channel

    def close(self) -> None:
        self.channel.close()


class _ShellConn:
    def __init__(self, shells: _Shells) -> None:
        self._shells = shells

    async def create_process(self, **kwargs):
        return _ShellProcess(self._shells.open())


async def _open_shell(kind: str, shells: _Shells, *, limit_mb: int = 1, setup=()):
    if kind == "paramiko":
        return ssh.ShellSession(
            shells.open(), "k", "", read_timeout=5, setup=setup, max_answer_mb=limit_mb, reopen=shells.open
        )
    return await assh.AsyncShellSession.open(
        _ShellConn(shells), "k", "", read_timeout=5, setup=setup, max_answer_mb=limit_mb
    )


async def _shell_run(shell, command: str) -> str:
    answer = shell.run(command)
    return await answer if asyncio.iscoroutine(answer) else answer


SHELLS = pytest.mark.parametrize("kind", ["paramiko", "asyncssh"])

TOO_LARGE = [b"x" * PIECE] * 20 + [PROMPT.encode()]
VERSION = [f"V\r\n{PROMPT}".encode()]
ECHO = len(b"show ip bgp\r\n")


@SHELLS
async def test_a_shell_answer_past_the_limit_fails_alone_and_the_next_command_runs_on_a_new_shell(kind):
    shells = _Shells({"show ip bgp": TOO_LARGE, "show version": VERSION})
    shell = await _open_shell(kind, shells, setup=("terminal length 0",))
    with pytest.raises(ssh.AnswerTooLarge) as caught:
        await _shell_run(shell, "show ip bgp")
    # The echo line counts: it is part of what the device sent.
    assert str(caught.value) == _too_large("the answer to 'show ip bgp'", ECHO + 16 * PIECE)
    first = shells.opened[0]
    assert first.closed
    # The rest of the answer and its prompt were never read.
    assert len(first.queue) == 5
    assert await _shell_run(shell, "show version") == "V\n"
    assert await _shell_run(shell, "show version") == "V\n"
    assert len(shells.opened) == 2
    second = shells.opened[1]
    assert second.sent == ["terminal length 0", "show version", "show version"]
    assert not second.closed
    assert first.sent == ["terminal length 0", "show ip bgp"]


async def test_a_paramiko_shell_that_cannot_open_another_stops_after_an_answer_past_the_limit():
    shells = _Shells({"show ip bgp": TOO_LARGE})
    shell = ssh.ShellSession(shells.open(), "k", "", read_timeout=5, max_answer_mb=1)
    with pytest.raises(ssh.AnswerTooLarge) as caught:
        shell.run("show ip bgp")
    assert shells.opened[0].closed
    with pytest.raises(ssh.SshError) as later:
        shell.run("show version")
    assert str(later.value) == (
        "the shell session stopped after 'show ip bgp' ended before its prompt "
        f"(AnswerTooLarge: {caught.value}); no later command was sent"
    )
    assert shells.opened[0].sent == ["show ip bgp"]


@SHELLS
async def test_a_new_shell_that_does_not_open_stops_the_session(kind):
    shells = _Shells({"show ip bgp": TOO_LARGE, "show version": VERSION})
    refused = ssh.SshError("the device refused an interactive shell: Channel closed.")
    if kind == "paramiko":

        def reopen():
            raise refused

        shell = ssh.ShellSession(shells.open(), "k", "", read_timeout=5, max_answer_mb=1, reopen=reopen)
    else:

        class _RefusesAgain(_ShellConn):
            async def create_process(self, **kwargs):
                if shells.opened:
                    raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "SSH connection closed")
                return await super().create_process(**kwargs)

        shell = await assh.AsyncShellSession.open(
            _RefusesAgain(shells), "k", "", read_timeout=5, max_answer_mb=1
        )
    with pytest.raises(ssh.AnswerTooLarge):
        await _shell_run(shell, "show ip bgp")
    cause = (
        "SshError: the device refused an interactive shell: Channel closed."
        if kind == "paramiko"
        else "SshError: the device refused an interactive shell: SSH connection closed"
    )
    stopped = (
        "the shell session stopped after 'show ip bgp': the new shell that replaces the one closed at the "
        f"answer limit did not open ({cause}); no later command was sent"
    )
    for _ in range(2):
        with pytest.raises(ssh.SshError) as caught:
            await _shell_run(shell, "show version")
        assert type(caught.value) is ssh.SshError
        assert str(caught.value) == stopped
    assert len(shells.opened) == 1


@SHELLS
async def test_a_setup_command_past_the_limit_on_the_new_shell_stops_the_session(kind):
    setup = ("terminal length 0",)
    shells = _Shells(
        {"show ip bgp": TOO_LARGE, "show version": VERSION},
        later={"terminal length 0": [b"x" * (MIB + 1), PROMPT.encode()], "show version": VERSION},
    )
    shell = await _open_shell(kind, shells, setup=setup)
    with pytest.raises(ssh.AnswerTooLarge):
        await _shell_run(shell, "show ip bgp")
    with pytest.raises(ssh.SshError) as caught:
        await _shell_run(shell, "show version")
    assert str(caught.value).startswith(
        "the shell session stopped after 'show ip bgp': the new shell that replaces the one closed at the "
        "answer limit did not open (AnswerTooLarge: the answer to 'terminal length 0' is larger than "
    )
    assert [channel.closed for channel in shells.opened] == [True, True]
    assert shells.opened[1].sent == ["terminal length 0"]


@SHELLS
async def test_a_shell_answer_at_the_limit_is_read_whole(kind):
    body = b"x" * (MIB - ECHO - len(b"\r\n" + PROMPT.encode()))
    shells = _Shells({"show ip bgp": [body + b"\r\n" + PROMPT.encode()]})
    shell = await _open_shell(kind, shells)
    assert await _shell_run(shell, "show ip bgp") == body.decode() + "\n"
    assert not shells.opened[0].closed


@SHELLS
async def test_a_login_past_the_limit_opens_no_shell(kind):
    shells = _Shells({}, login=b"x" * (MIB + 1))
    with pytest.raises(ssh.AnswerTooLarge) as caught:
        await _open_shell(kind, shells)
    assert str(caught.value) == _too_large("the device's output before its prompt", MIB + 1)


@SHELLS
async def test_a_setup_command_past_the_limit_opens_no_shell(kind):
    """A refused setup command is logged and the shell opens. One whose read
    stopped leaves no shell to send the collected commands on."""
    shells = _Shells({"terminal length 0": [b"x" * (MIB + 1), PROMPT.encode()]})
    with pytest.raises(ssh.AnswerTooLarge, match="the answer to 'terminal length 0' is larger"):
        await _open_shell(kind, shells, setup=("terminal length 0",))
    assert [channel.closed for channel in shells.opened] == [True]


class _CloseFails:
    """A close whose end of file and close meet a connection that has ended."""

    def close(self) -> None:
        self.closed = True
        raise EOFError


def test_a_paramiko_close_that_fails_keeps_the_answer_too_large():
    class _Channel(_CloseFails, _ScriptedExec):
        pass

    channel = _Channel([b"x" * PIECE] * 20)
    with pytest.raises(ssh.AnswerTooLarge):
        _exec_run(channel)
    assert channel.closed

    class _Shell(_CloseFails, _ShellChannel):
        pass

    channel = _Shell({"show ip bgp": TOO_LARGE}, f"banner\r\n{PROMPT}".encode())
    shell = ssh.ShellSession(channel, "k", "", read_timeout=5, max_answer_mb=1)
    with pytest.raises(ssh.AnswerTooLarge):
        shell.run("show ip bgp")
    assert channel.closed


# --- the collector ---------------------------------------------------------------


def test_the_setting_defaults_to_1024_mib_and_zero_turns_it_off(monkeypatch):
    monkeypatch.delenv("COLLECT_MAX_ANSWER_MB", raising=False)
    assert Settings(_env_file=None).collect_max_answer_mb == 1024
    assert Settings(_env_file=None, collect_max_answer_mb=0).collect_max_answer_mb == 0
    with pytest.raises(ValidationError):
        Settings(_env_file=None, collect_max_answer_mb=-1)


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (None, 1024),
        (SimpleNamespace(), 1024),
        (SimpleNamespace(collect_max_answer_mb=7), 7),
        (SimpleNamespace(collect_max_answer_mb=0), 0),
    ],
    ids=["no-settings", "settings-without-it", "set", "off"],
)
@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
@pytest.mark.parametrize("fresh", [False, True], ids=["one-connection", "fresh-connections"])
def test_every_session_of_a_fetch_carries_the_limit(monkeypatch, settings, expected, transport, fresh):
    fake = FakeSshSession({"show version": "V", "show inventory": "I"}).install(monkeypatch)
    config = DemoConfig(host="r1", auth=AUTH, transport=transport, fresh_connection_per_command=fresh)
    DemoCollector(config, settings).fetch()
    assert fake.connections
    assert all(connection["max_answer_mb"] == expected for connection in fake.connections)


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
async def test_an_optional_answer_past_the_limit_is_a_failed_section(transport, paramiko_transports):
    big = "x" * (MIB + 1)

    async def version(process: asyncssh.SSHServerProcess) -> None:
        process.stdout.write("V\n")
        process.exit(0)

    async def inventory(process: asyncssh.SSHServerProcess) -> None:
        with contextlib.suppress(OSError, asyncssh.Error):
            await write_all(process, big)
            process.exit(0)

    async with serve({"show version": version, "show inventory": inventory}) as port:
        config = DemoConfig(host="127.0.0.1", port=port, auth=PW, transport=transport)
        raw = await DemoCollector(config, SimpleNamespace(collect_max_answer_mb=1)).afetch()
    assert raw["show version"] == "V\n"
    assert raw["show inventory"] == "STANDIN"
    outcome = raw[RAW_OUTCOMES_KEY]["show inventory"]
    assert outcome["status"] == "failed"
    assert outcome["detail"].startswith(
        "the answer to 'show inventory' is larger than the answer limit of 1 MiB: the read stopped after "
    )


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
async def test_a_required_answer_past_the_limit_fails_the_device(transport, paramiko_transports):
    async def version(process: asyncssh.SSHServerProcess) -> None:
        with contextlib.suppress(OSError, asyncssh.Error):
            await write_all(process, "x" * (2 * MIB))
            process.exit(0)

    async with serve({"show version": version}) as port:
        config = DemoConfig(host="127.0.0.1", port=port, auth=PW, transport=transport)
        with pytest.raises(ssh.AnswerTooLarge, match="the answer to 'show version' is larger"):
            await DemoCollector(config, SimpleNamespace(collect_max_answer_mb=1)).afetch()


class _OptionalFirst(DemoCollector):
    COMMANDS = ("show inventory", "show version")
    SHELL_SETUP = ("terminal length 0",)


async def _shell_device(process: asyncssh.SSHServerProcess) -> None:
    """A shell that answers `show inventory` with 2 MiB and `show version`
    with one line, each followed by the prompt."""
    process.stdout.write(f"banner\r\n{PROMPT}")
    # The client closes the first shell under the large answer.
    with contextlib.suppress(OSError, asyncssh.Error):
        while line := await process.stdin.readline():
            command = line.strip()
            if command == "show inventory":
                await write_all(process, "x" * (2 * MIB) + "\n")
            elif command == "show version":
                process.stdout.write("V\n")
            process.stdout.write(PROMPT)
    process.exit(0)


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
async def test_an_optional_answer_past_the_limit_on_a_shell_costs_only_its_section(
    transport, paramiko_transports
):
    """The first shell is closed under the large answer, and the required
    command after it is read on a new shell of the same connection."""
    async with serve({"": _shell_device}) as port:
        config = DemoConfig(host="127.0.0.1", port=port, auth=PW, transport=transport, channel="shell")
        raw = await _OptionalFirst(config, SimpleNamespace(collect_max_answer_mb=1)).afetch()
    assert raw["show inventory"] == "STANDIN"
    assert raw["show version"] == "V\n"
    outcome = raw[RAW_OUTCOMES_KEY]["show inventory"]
    assert outcome["status"] == "failed"
    assert outcome["detail"].startswith(
        "the answer to 'show inventory' is larger than the answer limit of 1 MiB: the read stopped after "
    )
