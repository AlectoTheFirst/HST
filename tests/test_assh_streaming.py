"""The asyncssh exec read streams its answer through `ssh.StreamSanitizer`.

Against the real in-process asyncssh server of `test_assh_transport.py`: the
answer arrives in whatever packets the server's writes become, and the read
has to give exactly what `conn.run` collects for the whole answer, sanitized
as one text. Every expectation here is computed that way, in the test,
against the same server.
"""

from __future__ import annotations

import asyncio
import random
import sys
import tracemalloc
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

import asyncssh
import pytest
from tests.test_assh_transport import PASSWORD, PW, USER, _Recorder, _Server
from tests.test_cli_shell_session import LOGIN, PROMPT, FakeConnection, ScriptedChannel
from tests.test_stream_sanitize import reference_shell_output_of

from hst.collectors import assh, ssh
from hst.collectors.ssh import sanitize_cli_text

Behaviour = Callable[[asyncssh.SSHServerProcess], Awaitable[None]]

# A login banner, as the device writes it in front of every exec answer.
BANNER = (
    "CCCC\r\n"
    "**********************************************************\r\n"
    "*  Authorised access only. All activity is recorded.     *\r\n"
    "**********************************************************\r\n"
    "\r\n"
)


def _route_table(size: int, *, plain: bool = False) -> str:
    """A BGP table of about `size` characters. Unless `plain`, it carries CRLF
    line ends, colour codes, cursor-forward columns, OSC titles, erase codes
    and a character outside Latin-1, behind the banner."""
    parts = [] if plain else [BANNER]
    total = 0
    i = 0
    while total < size:
        prefix = f"10.{i // 256 % 256}.{i % 256}.0/24"
        if plain:
            row = f"*> {prefix:<18} 192.0.2.{i % 250 + 1:<3}      0 65000 {i} i\n"
        else:
            row = f"\x1b[1;32m*>\x1b[0m {prefix}\x1b[5C192.0.2.{i % 250 + 1} \u2500 0 65000 {i} i   \r\n"
            if i % 997 == 0:
                row = "\x1b]0;r1: show ip bgp\x07" + row + "\x1b[K\r\n"
        parts.append(row)
        total += len(row)
        i += 1
    return "".join(parts)


async def _write(stream: asyncssh.SSHWriter[str], text: str, sizes: list[int]) -> None:
    """`text` written in pieces of `sizes` and then the rest, draining after
    each write so every write goes out as its own packets."""
    pos = 0
    for n in sizes:
        if pos >= len(text):
            break
        stream.write(text[pos : pos + n])
        await stream.drain()
        pos += n
    step = 1 << 16
    for start in range(pos, len(text), step):
        stream.write(text[start : start + step])
        await stream.drain()


def _sizes(delivery: str, total: int) -> list[int]:
    rng = random.Random(11)
    if delivery == "one-byte":
        # About a second of single-byte packets; the rest follows in 64 KiB writes.
        return [1] * 16_384
    if delivery == "64k":
        return []
    sizes, covered = [], 0
    while covered < total:
        sizes.append(rng.randint(1, 200_000))
        covered += sizes[-1]
    return sizes


def _answering(stdout: str = "", stderr: str = "", status: int | None = 0, sizes=()) -> Behaviour:
    async def behaviour(process: asyncssh.SSHServerProcess) -> None:
        await _write(process.stdout, stdout, list(sizes))
        if stderr:
            process.stderr.write(stderr)
        if status is None:
            process.close()
        else:
            process.exit(status)

    return behaviour


@asynccontextmanager
async def _serve(behaviours: dict[str, Behaviour]):
    """The `test_assh_transport` server, answering each command with a
    behaviour. Yields the port."""
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


async def _collected(port: int, command: str) -> asyncssh.SSHCompletedProcess:
    """The answer as `conn.run` collects it, whole. Sanitized as one text,
    it is what the streamed read has to return."""
    async with asyncssh.connect(
        "127.0.0.1",
        port,
        username=USER,
        password=PASSWORD,
        known_hosts=None,
        config=None,
        client_keys=None,
        agent_path=None,
    ) as conn:
        return await conn.run(command, encoding="utf-8", errors="replace")


async def _run(port: int, command: str, *, read_timeout: int = 30) -> str:
    async with assh.session("127.0.0.1", PW, port=port, read_timeout=read_timeout) as s:
        return await s.run(command)


# --- the answer --------------------------------------------------------------


@pytest.fixture(scope="module")
def table_20mb() -> str:
    return _route_table(20 * 2**20)


@pytest.mark.parametrize("delivery", ["one-byte", "64k", "random"])
async def test_a_20_mb_answer_reads_as_the_collected_answer_sanitized(table_20mb, delivery):
    behaviour = _answering(table_20mb, sizes=_sizes(delivery, len(table_20mb)))
    async with _serve({"show ip bgp": behaviour}) as port:
        collected = await _collected(port, "show ip bgp")
        out = await _run(port, "show ip bgp")
    assert collected.stdout == table_20mb
    assert out == sanitize_cli_text(collected.stdout)


async def test_crlf_split_across_packets_colour_codes_and_a_banner():
    answer = (
        BANNER + "\x1b]0;r1\x07Name   \x1b[1mDefault RD\x1b[0m\x1b[5CInterfaces\r\n"
        "\x1b[32mmgmt\x1b[0m   <not set>\x1b[8CGi0\r\n"
        "vrf-a  65000:1\x1b[11CGi1.10\r\n"
    )
    # Cut inside every CRLF, inside an OSC, inside a CSI and after a bare ESC.
    cuts = sorted({i + 1 for i, ch in enumerate(answer) if ch in "\r\x1b["} | {len(BANNER) + 3})
    sizes = [b - a for a, b in zip([0, *cuts], cuts, strict=False)]
    async with _serve({"show vrf": _answering(answer, sizes=sizes)}) as port:
        collected = await _collected(port, "show vrf")
        out = await _run(port, "show vrf")
    assert out == sanitize_cli_text(collected.stdout)
    assert out.splitlines()[5:] == [
        "Name   Default RD     Interfaces",
        "mgmt   <not set>        Gi0",
        "vrf-a  65000:1           Gi1.10",
    ]


# --- exit status, rejection, stderr ------------------------------------------


async def test_a_nonzero_exit_with_stderr_fails_with_the_same_text():
    behaviour = _answering("partial\r\n", "\x1b[31mboom\x1b[0m\r\n", 3)
    async with _serve({"bad": behaviour}) as port:
        collected = await _collected(port, "bad")
        with pytest.raises(ssh.CommandFailed) as caught:
            await _run(port, "bad")
    reason = ssh._failure_reason(sanitize_cli_text(collected.stdout), sanitize_cli_text(collected.stderr))
    assert str(caught.value) == f"'bad' exited {collected.exit_status}: {reason}" == "'bad' exited 3: boom"


async def test_a_rejection_at_exit_zero_fails():
    answer = "some header\r\n\x1b[1;31m% Invalid input detected at '^' marker.\x1b[0m\r\n"
    async with _serve({"show foo": _answering(answer)}) as port:
        with pytest.raises(ssh.CommandFailed) as caught:
            await _run(port, "show foo")
    assert str(caught.value) == "'show foo' rejected by device: % Invalid input detected at '^' marker."


async def test_a_missing_exit_status_returns_stdout():
    async with _serve({"show x": _answering("payload\r\n", status=None)}) as port:
        collected = await _collected(port, "show x")
        out = await _run(port, "show x")
    assert collected.exit_status is None
    assert out == sanitize_cli_text(collected.stdout) == "payload\n"


async def test_megabytes_of_stderr_while_stdout_streams_do_not_stall():
    """Both streams share the channel's receive window. Read only after
    standard output ends, 3 MB of standard error would fill the window and
    stop standard output; the read would end in a timeout."""
    out_text = _route_table(3 * 2**20, plain=True)
    err_text = "warning: a line the device wrote to standard error\n" * 60_000

    def interleaved(status: int) -> Behaviour:
        async def behaviour(process: asyncssh.SSHServerProcess) -> None:
            step = 1 << 16
            for start in range(0, max(len(out_text), len(err_text)), step):
                process.stdout.write(out_text[start : start + step])
                process.stderr.write(err_text[start : start + step])
                await process.stdout.drain()
                await process.stderr.drain()
            process.exit(status)

        return behaviour

    async with _serve({"noisy": interleaved(0), "noisy-fail": interleaved(2)}) as port:
        collected = await _collected(port, "noisy-fail")
        assert await _run(port, "noisy", read_timeout=10) == sanitize_cli_text(out_text)
        with pytest.raises(ssh.CommandFailed) as caught:
            await _run(port, "noisy-fail", read_timeout=10)
    reason = ssh._failure_reason(sanitize_cli_text(collected.stdout), sanitize_cli_text(collected.stderr))
    assert str(caught.value) == f"'noisy-fail' exited 2: {reason}"
    assert len(collected.stderr) > 3_000_000
    assert len(reason) == ssh._STDERR_REASON_MAX


# --- the read ends early -------------------------------------------------------


async def test_a_timeout_mid_stream_is_ssh_timeout_with_the_same_message():
    async def stalls(process: asyncssh.SSHServerProcess) -> None:
        await _write(process.stdout, _route_table(200_000), [])
        await asyncio.sleep(30)
        process.exit(0)

    async with _serve({"slow": stalls}) as port:
        with pytest.raises(ssh.SshTimeout) as caught:
            await _run(port, "slow", read_timeout=1)
    assert str(caught.value) == "'slow' did not complete within 1s"


async def test_a_connection_dropped_mid_answer_fails_the_command():
    """asyncssh queues the lost connection behind the data that arrived before
    it. `conn.run` returns that data, with no exit status, as if it were the
    answer."""
    partial = _route_table(100_000) + "a line cut o"

    async def drops(process: asyncssh.SSHServerProcess) -> None:
        await _write(process.stdout, partial, [])
        await asyncio.sleep(0.2)
        process.get_extra_info("connection").abort()

    async with _serve({"show ip bgp": drops}) as port:
        collected = await _collected(port, "show ip bgp")
        with pytest.raises(ssh.AnswerIncomplete) as caught:
            await _run(port, "show ip bgp")
    assert collected.stdout == partial
    assert collected.exit_status is None
    assert isinstance(caught.value, ssh.CommandFailed)
    assert str(caught.value).startswith(
        f"'show ip bgp' was cut short: the connection ended after {len(partial.encode())} bytes of "
        "its answer, before the device ended the channel or sent an exit status ("
    )


# --- memory --------------------------------------------------------------------


async def test_the_peak_of_a_50_mb_answer_is_at_most_2_4_times_the_answer():
    """The answer's pieces and their join are the whole cost: about twice the
    answer. Collected whole and then sanitized, the peak is about five times
    the answer."""
    table = _route_table(50 * 2**20, plain=True)
    async with (
        _serve({"show ip route": _answering(table)}) as port,
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            out = await s.run("show ip route")
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert out == sanitize_cli_text(table)
    assert peak <= 2.4 * sys.getsizeof(out), peak / sys.getsizeof(out)


# --- the async shell -----------------------------------------------------------


async def test_the_async_shell_reads_a_large_answer_split_anywhere():
    """The shell read sanitizes chunk by chunk and keeps the prompt logic on
    the raw tail. Chunks cut through CRLF pairs and escape sequences."""
    body = _route_table(2 * 2**20)
    text = f"show ip bgp\r\n{body}{PROMPT}"
    rng = random.Random(21)
    chunks, pos = [], 0
    while pos < len(text):
        n = rng.choice((1, 2, 7, 4096, 65536))
        chunks.append(text[pos : pos + n])
        pos += n
    channel = ScriptedChannel(LOGIN, chunks)
    shell = await assh.AsyncShellSession.open(FakeConnection(channel), "k", "", read_timeout=30)
    out = await shell.run("show ip bgp")
    assert out == reference_shell_output_of(sanitize_cli_text(text), "show ip bgp", PROMPT)
