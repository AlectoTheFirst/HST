"""A real SSH device for the transport tests: the asyncssh server of
`tests/test_assh_transport.py`, answering each exec command with a behaviour.

Both transports reach it over loopback, the paramiko client from a thread.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager

import asyncssh
import paramiko
import pytest
from tests.test_assh_transport import PW, _Recorder, _Server

from hst.collectors import assh, ssh

Behaviour = Callable[[asyncssh.SSHServerProcess], Awaitable[None]]

# What a command gave: ("returned", answer), or the exception's type name
# and message.
Outcome = tuple[str, str]


async def write_all(process: asyncssh.SSHServerProcess, text: str) -> None:
    """`text` on standard output in 64 KiB writes, each drained, so the
    writes wait on the client's reads once the channel window is full."""
    step = 1 << 16
    for start in range(0, len(text), step):
        process.stdout.write(text[start : start + step])
        await process.stdout.drain()


@asynccontextmanager
async def serve(behaviours: dict[str, Behaviour]):
    """A listening device. Yields its port."""
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def handler(process: asyncssh.SSHServerProcess) -> None:
        await behaviours[process.command or ""](process)

    listener = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_factory=lambda: _Server(_Recorder()),
        server_host_keys=[key],
        process_factory=handler,
    )
    try:
        yield listener.get_port()
    finally:
        listener.close()
        await listener.wait_closed()


@contextmanager
def joined_paramiko_transports(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[paramiko.Transport]]:
    """Every client transport `ssh.session` makes, each joined on exit.

    A transport whose connection the device ended logs that from its own
    thread, which can run after the test's log capture has closed, so
    paramiko's logger stays at CRITICAL until every transport thread has
    been joined.
    """
    made: list[paramiko.Transport] = []
    real = ssh._transport_factory

    def factory(sock) -> paramiko.Transport:
        transport = real(sock)
        made.append(transport)
        return transport

    monkeypatch.setattr(ssh, "_transport_factory", factory)
    paramiko_log = logging.getLogger("paramiko")
    level = paramiko_log.level
    paramiko_log.setLevel(logging.CRITICAL)
    try:
        yield made
    finally:
        for transport in made:
            transport.close()
            transport.join(10)
        paramiko_log.setLevel(level)


async def outcomes(transport: str, port: int, commands: list[str], **session_kwargs) -> list[Outcome]:
    """What each command gives over one session of `transport` to the device
    at `port`. An `SshError` is an outcome; anything else fails the test."""

    def failed(exc: ssh.SshError) -> Outcome:
        return type(exc).__name__, str(exc)

    if transport == "asyncssh":
        results: list[Outcome] = []
        async with assh.session("127.0.0.1", PW, port=port, **session_kwargs) as s:
            for command in commands:
                try:
                    results.append(("returned", await s.run(command)))
                except ssh.SshError as exc:
                    results.append(failed(exc))
        return results

    def run() -> list[Outcome]:
        results: list[Outcome] = []
        with ssh.session("127.0.0.1", PW, port=port, **session_kwargs) as s:
            for command in commands:
                try:
                    results.append(("returned", s.run(command)))
                except ssh.SshError as exc:
                    results.append(failed(exc))
        return results

    return await asyncio.to_thread(run)
