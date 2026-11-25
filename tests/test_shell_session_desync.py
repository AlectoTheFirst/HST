"""A shell session that has lost its place in the stream sends no further command."""

from __future__ import annotations

import asyncio
import contextlib
import gc
import inspect
import json
import logging
import socket
import threading
import warnings
from contextlib import asynccontextmanager, contextmanager

import asyncssh
import paramiko
import pytest
from tests.test_assh_transport import PW, _Recorder, _Server

from hst.collectors import assh, ssh, vyos
from hst.collectors.auth import SshPassword
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cli_collector import classify_command_failure

PROMPT = "r1#"
LOGIN = "banner\r\n" + PROMPT

ROUTE = "show ip route"
# The first part of the answer arrives before the reader gives up; the rest,
# with its prompt, arrives after.
ROUTE_LATE = ("S*   0.0.0.0/0 [1/0] via 192.0.2.1\r\n", "C    192.0.2.0/24 is directly connected\r\n")
STOPPED = f"the shell session stopped after {ROUTE!r} timed out; no later command was sent"


class Device:
    """A shell device that answers from a script, behind either fake below.

    `read` hands out one queued chunk per call and raises `TimeoutError` when
    nothing is queued, as a quiet channel does; once the device has closed
    the shell it returns "". A bare newline is answered with the prompt
    alone, as a device at an exec prompt answers it.

    A command in `late` is echoed with the first part of its answer. The rest
    of that answer, with its prompt, is queued only when the device next
    receives input, after the reader gave up. A
    command in `closes` is echoed and the device then closes the shell. A
    command in `refuses_write` fails its write, as a write to a closed
    channel does.
    """

    def __init__(
        self,
        answers: dict[str, str] | None = None,
        *,
        late: dict[str, tuple[str, str]] | None = None,
        closes: tuple[str, ...] = (),
        refuses_write: tuple[str, ...] = (),
    ) -> None:
        self._answers = answers or {}
        self._late = late or {}
        self._closes = closes
        self._refuses_write = refuses_write
        self._queue: list[str | None] = [LOGIN]
        self._held: list[str] = []
        self._closed = False
        self.sent: list[str] = []
        self.writes = 0

    @property
    def quiet(self) -> bool:
        return not self._closed and not self._queue

    def read(self) -> str:
        if self._closed:
            return ""
        if not self._queue:
            raise TimeoutError
        chunk = self._queue.pop(0)
        if chunk is None:
            self._closed = True
            return ""
        return chunk

    def write(self, data: str) -> None:
        self.writes += 1
        command = data.strip()
        if self._closed or command in self._refuses_write:
            raise OSError("Socket is closed")
        self._queue.extend(self._held)
        self._held.clear()
        if not command:
            self._queue.append(f"\r\n{PROMPT}")
            return
        self.sent.append(command)
        if command in self._closes:
            self._queue.extend([f"{command}\r\n", None])
        elif command in self._late:
            first, rest = self._late[command]
            self._queue.append(f"{command}\r\n{first}")
            self._held.append(f"{rest}{PROMPT}")
        else:
            self._queue.append(f"{command}\r\n{self._answers.get(command, '')}{PROMPT}")


class Channel:
    """The paramiko `Channel` face of a `Device`."""

    def __init__(self, device: Device) -> None:
        self._device = device
        self.closed = False

    def settimeout(self, seconds: float) -> None:
        self.timeout = seconds

    def recv(self, size: int) -> bytes:
        return self._device.read().encode()

    def sendall(self, data: bytes) -> None:
        self._device.write(data.decode())

    def close(self) -> None:
        self.closed = True


class _Stdin:
    def __init__(self, device: Device) -> None:
        self._device = device

    def write(self, data: str) -> None:
        self._device.write(data)


class _Stdout:
    def __init__(self, device: Device, wait: bool) -> None:
        self._device = device
        self._wait = wait
        self.waiting = asyncio.Event()

    async def read(self, size: int) -> str:
        if self._wait and self._device.quiet:
            self.waiting.set()
            # Never set: the read waits until its task is cancelled.
            await asyncio.Event().wait()
        return self._device.read()


class Process:
    """The asyncssh process face of a `Device`. With `wait`, a quiet device
    is waited on and raises no `TimeoutError`."""

    def __init__(self, device: Device, *, wait: bool = False) -> None:
        self.stdin = _Stdin(device)
        self.stdout = _Stdout(device, wait)
        self.closed = False

    def close(self) -> None:
        self.closed = True


class Connection:
    def __init__(self, process: Process) -> None:
        self.process = process

    async def create_process(self, **kwargs) -> Process:
        return self.process


async def _open(kind: str, device: Device, *, wait: bool = False):
    if kind == "paramiko":
        return ssh.ShellSession(Channel(device), "k", "", read_timeout=5)
    return await assh.AsyncShellSession.open(Connection(Process(device, wait=wait)), "k", "", read_timeout=5)


async def _run(shell, command: str) -> str:
    answer = shell.run(command)
    return await answer if inspect.isawaitable(answer) else answer


KINDS = pytest.mark.parametrize("kind", ["paramiko", "asyncssh"])


# --- the scripted device ------------------------------------------------------


@KINDS
async def test_a_command_that_times_out_stops_the_session(kind):
    device = Device({"show version": "Version: 1.5\r\n"}, late={ROUTE: ROUTE_LATE})
    shell = await _open(kind, device)
    with pytest.raises(ssh.SshTimeout) as timed_out:
        await _run(shell, ROUTE)
    assert str(timed_out.value) == f"{ROUTE!r} produced no further output within 5s"
    writes = device.writes
    for _ in range(2):
        with pytest.raises(ssh.SshError) as caught:
            await _run(shell, "show version")
        assert type(caught.value) is ssh.SshError
        assert str(caught.value) == STOPPED
        # What a collector records for it: a failed read, not an unsupported
        # or unauthorized one.
        assert classify_command_failure(caught.value) == ("failed", STOPPED)
    assert device.writes == writes
    assert device.sent == [ROUTE]


@KINDS
async def test_a_session_whose_commands_end_at_the_prompt_goes_on(kind):
    """A rejection is raised after the prompt was read, so the reader is in
    step and the next command runs."""
    device = Device(
        {
            "show version": "Version: 1.5\r\n",
            "show nonsense": "% Invalid input detected at '^' marker.\r\n",
            "show clock": "12:00:00.000 UTC\r\n",
        }
    )
    shell = await _open(kind, device)
    assert await _run(shell, "show version") == "Version: 1.5\n"
    with pytest.raises(ssh.CommandFailed, match="rejected by device"):
        await _run(shell, "show nonsense")
    assert await _run(shell, "show clock") == "12:00:00.000 UTC\n"
    assert device.sent == ["show version", "show nonsense", "show clock"]


@KINDS
async def test_a_device_that_closes_the_shell_keeps_its_error(kind):
    device = Device(closes=(ROUTE,))
    shell = await _open(kind, device)
    with pytest.raises(ssh.SshError) as caught:
        await _run(shell, ROUTE)
    assert type(caught.value) is ssh.SshError
    assert str(caught.value) == f"the device closed the shell during {ROUTE!r}"
    writes = device.writes
    with pytest.raises(ssh.SshError) as later:
        await _run(shell, "show version")
    assert str(later.value) == (
        f"the shell session stopped after {ROUTE!r} ended before its prompt "
        f"(SshError: the device closed the shell during {ROUTE!r}); no later command was sent"
    )
    assert device.writes == writes


@KINDS
async def test_a_write_that_fails_stops_the_session(kind):
    device = Device(refuses_write=(ROUTE,))
    shell = await _open(kind, device)
    with pytest.raises(OSError, match="Socket is closed"):
        await _run(shell, ROUTE)
    writes = device.writes
    with pytest.raises(ssh.SshError) as caught:
        await _run(shell, "show version")
    assert str(caught.value) == (
        f"the shell session stopped after {ROUTE!r} ended before its prompt "
        "(OSError: Socket is closed); no later command was sent"
    )
    assert device.writes == writes


async def test_a_read_cancelled_while_it_waits_stops_the_async_session():
    device = Device(late={ROUTE: ROUTE_LATE})
    process = Process(device, wait=True)
    shell = await assh.AsyncShellSession.open(Connection(process), "k", "", read_timeout=5)
    task = asyncio.create_task(shell.run(ROUTE))
    await asyncio.wait_for(process.stdout.waiting.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    writes = device.writes
    with pytest.raises(ssh.SshError) as caught:
        await shell.run("show version")
    assert str(caught.value) == (
        f"the shell session stopped after {ROUTE!r} ended before its prompt (CancelledError); "
        "no later command was sent"
    )
    assert device.writes == writes


async def test_a_stopped_async_session_still_closes():
    device = Device(late={ROUTE: ROUTE_LATE})
    process = Process(device)
    shell = await assh.AsyncShellSession.open(Connection(process), "k", "", read_timeout=5)
    with pytest.raises(ssh.SshTimeout):
        await shell.run(ROUTE)
    shell.close()
    assert process.closed


# --- real servers ---------------------------------------------------------------

SLOW = "show ip bgp"
SLOW_STOPPED = f"the shell session stopped after {SLOW!r} timed out; no later command was sent"


def _shell_lines(command: str, held: str) -> tuple[str, str]:
    """What the real servers send for one line of input, and what they hold
    back until the next: the `Device` rules, on a real channel."""
    if not command:
        return f"{held}\r\n{PROMPT}", ""
    if command == SLOW:
        return f"{held}{command}\r\npart of the answer\r\n", f"the rest of the answer\r\n{PROMPT}"
    return f"{held}{command}\r\nanswer to {command}\r\n{PROMPT}", ""


@asynccontextmanager
async def _asyncssh_device():
    """A real asyncssh server with an interactive shell. Yields its port and
    the commands the shell received."""
    received: list[str] = []
    finished = asyncio.Event()
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def shell(process: asyncssh.SSHServerProcess) -> None:
        held = ""
        try:
            process.stdout.write(LOGIN)
            while line := await process.stdin.readline():
                command = line.strip()
                if command:
                    received.append(command)
                out, held = _shell_lines(command, held)
                process.stdout.write(out)
        except (OSError, asyncssh.Error):
            # The client closed the shell under the answer.
            pass
        finally:
            with contextlib.suppress(OSError, asyncssh.Error):
                process.exit(0)
            finished.set()

    listener = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_factory=lambda: _Server(_Recorder()),
        server_host_keys=[key],
        process_factory=shell,
        # Raw input: the shell above echoes each command itself, as a device does.
        line_editor=False,
    )
    try:
        yield listener.get_port(), received
        await asyncio.wait_for(finished.wait(), 10)
    finally:
        listener.close()
        await listener.wait_closed()


async def test_a_stopped_asyncssh_shell_closes_without_resource_warnings():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        async with (
            _asyncssh_device() as (port, received),
            assh.session("127.0.0.1", PW, port=port, channel="shell", read_timeout=1) as s,
        ):
            with pytest.raises(ssh.SshTimeout):
                await s.run(SLOW)
            with pytest.raises(ssh.SshError) as refused:
                await s.run("show version")
        gc.collect()
    assert str(refused.value) == SLOW_STOPPED
    assert received == [SLOW]
    assert [w for w in caught if issubclass(w.category, ResourceWarning)] == []


class _ShellDevice(paramiko.ServerInterface):
    """A real paramiko server whose shell answers each line on a thread of its own."""

    def __init__(self) -> None:
        self.received: list[str] = []
        self.threads: list[threading.Thread] = []

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        thread = threading.Thread(target=self._serve, args=(channel,))
        thread.start()
        self.threads.append(thread)
        return True

    def _serve(self, channel: paramiko.Channel) -> None:
        # A client that has gone after its timeout closes the channel under
        # the answer; that is the test's outcome, not a failure.
        with contextlib.suppress(OSError, EOFError, paramiko.SSHException):
            try:
                channel.sendall(LOGIN.encode())
                held, pending = "", b""
                while data := channel.recv(1024):
                    pending += data
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        command = line.decode().strip()
                        if command:
                            self.received.append(command)
                        out, held = _shell_lines(command, held)
                        channel.sendall(out.encode())
            finally:
                channel.close()


@contextmanager
def _paramiko_device(monkeypatch):
    """Points `ssh._open_socket` at a `_ShellDevice` over a socket pair."""
    device = _ShellDevice()
    host_key = paramiko.ECDSAKey.generate()
    started: list[tuple[paramiko.Transport, socket.socket]] = []

    def connect(host: str, port: int, timeout: int) -> socket.socket:
        client, server = socket.socketpair()
        transport = paramiko.Transport(server)
        transport.add_server_key(host_key)
        transport.start_server(event=threading.Event(), server=device)
        started.append((transport, client))
        return client

    monkeypatch.setattr(ssh, "_open_socket", connect)
    # A transport logs the peer's close of the socket pair at ERROR from its
    # own thread, which can run after the test's log capture has closed.
    paramiko_log = logging.getLogger("paramiko")
    level = paramiko_log.level
    paramiko_log.setLevel(logging.CRITICAL)
    try:
        yield device
    finally:
        for transport, client in started:
            transport.close()
            for thread in device.threads:
                thread.join(10)
            transport.join(10)
            client.close()
        paramiko_log.setLevel(level)


def test_a_stopped_paramiko_shell_closes_without_resource_warnings(monkeypatch):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with (
            _paramiko_device(monkeypatch) as device,
            ssh.session("r1", PW, channel="shell", read_timeout=1) as s,
        ):
            with pytest.raises(ssh.SshTimeout):
                s.run(SLOW)
            with pytest.raises(ssh.SshError) as refused:
                s.run("show version")
        gc.collect()
    assert str(refused.value) == SLOW_STOPPED
    assert device.received == [SLOW]
    assert [w for w in caught if issubclass(w.category, ResourceWarning)] == []


# --- a collector that goes on after a failed read -----------------------------

VERSION = "Version:          VyOS 1.5-rolling-202607150020\r\nHardware S/N:     QEMU1234\r\n"
LINKS = [{"ifname": "eth0", "address": "52:54:00:12:34:56"}]
# Text only the timed-out `addrs` answer carries.
LATE_ADDRESS = "198.51.100.7"


def _install_shell(monkeypatch, device: Device) -> None:
    """Both transports' `session` entries, opening a real shell session of
    that transport over `device`."""

    @contextmanager
    def paramiko_session(host, auth, **kwargs):
        assert kwargs["channel"] == "shell"
        channel = Channel(device)
        try:
            yield ssh.ShellSession(
                channel, "k", "", read_timeout=kwargs["read_timeout"], setup=kwargs["shell_setup"]
            )
        finally:
            channel.close()

    @asynccontextmanager
    async def asyncssh_session(host, auth, **kwargs):
        assert kwargs["channel"] == "shell"
        shell = await assh.AsyncShellSession.open(
            Connection(Process(device)),
            "k",
            "",
            read_timeout=kwargs["read_timeout"],
            setup=kwargs["shell_setup"],
        )
        try:
            yield shell
        finally:
            shell.close()

    monkeypatch.setattr(ssh, "session", paramiko_session)
    monkeypatch.setattr(assh, "session", asyncssh_session)


@pytest.mark.parametrize("transport", ["asyncssh", "paramiko"])
def test_vyos_records_every_read_after_a_timed_out_read_as_failed(monkeypatch, transport):
    op = vyos.VyosCollector._op_mode
    addrs = vyos.READ_COMMANDS["addrs"]
    device = Device(
        {
            op(vyos.READ_COMMANDS["config"]): "{}\r\n",
            op(vyos.READ_COMMANDS["version"]): VERSION,
            op(vyos.READ_COMMANDS["links"]): json.dumps(LINKS) + "\r\n",
        },
        late={
            addrs: (
                '[{"ifname": "eth0", "addr_info": [\r\n',
                f'{{"local": "{LATE_ADDRESS}", "prefixlen": 24}}]}}]\r\n',
            )
        },
    )
    _install_shell(monkeypatch, device)
    config = vyos.VyosConfig(
        host="gw1",
        auth=SshPassword(username="vyos", password="pw"),
        site_code="dc1",
        l3dom="dc1",
        channel="shell",
        transport=transport,
    )
    raw = vyos.VyosCollector(config, None).fetch()

    outcomes = raw[RAW_OUTCOMES_KEY]
    assert raw["links"] == LINKS
    assert outcomes["addrs"]["status"] == "failed"
    assert outcomes["addrs"]["detail"].startswith(f"{addrs!r} produced no further output")
    stopped = f"the shell session stopped after {addrs!r} timed out; no later command was sent"
    earlier = {"config", "version", "links", "addrs"}
    later = {key: value for key, value in outcomes.items() if key not in earlier}
    assert {"link_speeds", "routes", "routes6", vyos.BGP_SUMMARY_COMMAND} <= later.keys()
    assert all(value == {"status": "failed", "detail": stopped} for value in later.values()), later
    # Nothing was sent after the read that timed out, and the rest of its
    # answer is under no other command.
    assert device.sent[-1] == addrs
    assert LATE_ADDRESS not in json.dumps(raw, default=str)
