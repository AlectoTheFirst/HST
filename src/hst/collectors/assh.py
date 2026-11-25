"""The asyncssh transport of the SSH collectors is the async twin of `ssh.py`."""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import asyncssh

from .auth import SshAgent, SshJumpHost, SshPassword, SshPrivateKey
from .ssh import (
    _PROMPT_TAIL,
    DEFAULT_READ_TIMEOUT,
    KEEPALIVE_INTERVAL,
    SHELL_HEIGHT,
    SHELL_IDLE_READ,
    SHELL_PROMPT_ATTEMPTS,
    SHELL_WIDTH,
    AnswerIncomplete,
    AnswerTooLarge,
    CommandFailed,
    HostKeyMismatch,
    SshError,
    SshRefused,
    SshRejected,
    SshResult,
    SshTimeout,
    SshUnreachable,
    StreamSanitizer,
    _AnswerBudget,
    _cause,
    _cli_rejection,
    _failure_reason,
    _not_reopened,
    _shell_stopped,
    sanitize_cli_text,
    shell_at_prompt,
    shell_output_of,
    shell_prompt_of,
)

logger = logging.getLogger(__name__)

__all__ = [
    "AsyncShellSession",
    "AsyncSshSession",
    "load_key",
    "run",
    "session",
]


def _pin_of(key: asyncssh.SSHKey) -> str:
    """Return the pin string for a host key, byte-identical to `ssh._host_key_of`."""
    return f"{key.algorithm.decode()} {base64.b64encode(key.public_data).decode()}"


def _no_known_hosts(host: str, addr: str, port: int):
    return ([], [], [])


class _PinningClient(asyncssh.SSHClient):
    """Holds the pinned host key for the host key callback that asyncssh calls during
    key exchange, and records the observed key.

    The callback rejects a key that differs from the pin before authentication. With no
    pin, the callback accepts the key (trust on first use)."""

    def __init__(self, known_host_key: str) -> None:
        self._pin = known_host_key
        self.observed = ""

    def validate_host_public_key(self, host, addr, port, key) -> bool:
        self.observed = _pin_of(key)
        return not self._pin or self.observed == self._pin


def load_key(pem: str, passphrase: str) -> asyncssh.SSHKey:
    password = passphrase or None
    try:
        return asyncssh.import_private_key(pem, password)
    except asyncssh.KeyEncryptionError as exc:
        if password is None:
            raise SshError("private key needs a passphrase, or the passphrase is wrong") from exc
        raise SshError("could not load the private key: wrong passphrase, or unsupported format") from exc
    except asyncssh.KeyImportError as exc:
        if password is None and "passphrase" in str(exc).lower():
            raise SshError("private key needs a passphrase, or the passphrase is wrong") from exc
        if password is not None:
            raise SshError("could not load the private key: wrong passphrase, or unsupported format") from exc
        raise SshError("could not load the private key: unsupported or corrupt material") from exc


async def _agent_keys() -> list:
    try:
        agent = await asyncssh.connect_agent()
    except (OSError, ValueError):
        return []
    try:
        return list(await agent.get_keys())
    finally:
        agent.close()


async def _auth_options(auth, where: str) -> dict:
    """Return the asyncssh connect kwargs that authenticate with exactly one method."""
    if isinstance(auth, SshPassword):
        # `client_keys=None` disables public key auth. asyncssh offers the password as
        # password auth and as the answer to a single-prompt keyboard-interactive
        # challenge. paramiko does the same with `fallback=True`.
        return {
            "username": auth.username,
            "password": auth.password.get_secret_value(),
            "client_keys": None,
            "agent_path": None,
        }
    if isinstance(auth, SshPrivateKey):
        key = load_key(auth.private_key.get_secret_value(), auth.passphrase.get_secret_value())
        return {"username": auth.username, "client_keys": [key], "agent_path": None}
    if isinstance(auth, SshAgent):
        keys = await _agent_keys()
        if not keys:
            raise SshRejected(f"no keys available from the SSH agent for {where}")
        return {"username": auth.username, "client_keys": keys, "agent_path": None}
    raise SshError(f"unsupported auth method: {auth!r}")  # pragma: no cover (the union is closed)


# The delay in seconds before the second connection attempt to a hop that accepts the
# TCP connection and closes it before the key exchange completes. Such a close can be
# transient. A second close raises `SshRefused`.
PRE_AUTH_RETRY_DELAY = 2.0


async def _connect(
    host: str,
    port: int,
    auth,
    known_host_key: str,
    timeout: int,  # noqa: ASYNC109 - the handshake+auth budget, mirroring ssh.py
    connect_timeout: int,
    tunnel: asyncssh.SSHClientConnection | None = None,
    hop: str = "device",
) -> tuple[asyncssh.SSHClientConnection, str]:
    """One authenticated connection to one hop. The device hop behind a bastion passes
    the bastion connection as `tunnel`. Both hops use the error classification and the
    pinning of this function. A hop that closes the connection before authentication
    gets a second attempt after `PRE_AUTH_RETRY_DELAY`."""
    where = f"{hop} {host}"
    auth_opts = await _auth_options(auth, where)
    client = _PinningClient(known_host_key)
    kwargs: dict = {
        "client_factory": lambda: client,
        "known_hosts": _no_known_hosts,
        "config": None,
        "login_timeout": timeout,
        "connect_timeout": connect_timeout,
        **auth_opts,
    }
    if tunnel is not None:
        kwargs["tunnel"] = tunnel
    if hop == "device":
        kwargs["keepalive_interval"] = KEEPALIVE_INTERVAL
    try:
        try:
            conn = await asyncssh.connect(host, port, **kwargs)
        except (ConnectionResetError, asyncssh.ConnectionLost) as exc:
            logger.warning(
                "%s:%s closed the session before authentication (%s); one more try in %ss",
                where,
                port,
                exc,
                PRE_AUTH_RETRY_DELAY,
            )
            await asyncio.sleep(PRE_AUTH_RETRY_DELAY)
            conn = await asyncssh.connect(host, port, **kwargs)
    except asyncssh.HostKeyNotVerifiable as exc:
        raise HostKeyMismatch(
            f"{where} presented host key {client.observed}, pinned key is {known_host_key}"
        ) from exc
    except asyncssh.PermissionDenied as exc:
        raise SshRejected(f"credentials refused: {auth.username}@{where}: {exc}") from exc
    except asyncssh.ChannelOpenError as exc:
        # the bastion could not open the tunnel
        raise SshUnreachable(f"cannot reach {where}:{port}: {exc}") from exc
    except ConnectionResetError as exc:
        raise SshRefused(f"{where}:{port} closed the session before authentication: {exc}") from exc
    except (OSError, TimeoutError) as exc:
        raise SshUnreachable(f"cannot reach {where}:{port}: {exc}") from exc
    except asyncssh.Error as exc:
        raise SshRefused(f"{where}:{port} closed the session before authentication: {exc}") from exc
    return conn, client.observed


class AsyncSshSession:
    def __init__(
        self,
        conn: asyncssh.SSHClientConnection,
        host_key: str,
        jump_host_key: str,
        *,
        read_timeout: int,
        open_timeout: int = 120,
        max_answer_mb: int = 0,
    ) -> None:
        self._conn = conn
        self.host_key = host_key
        self.jump_host_key = jump_host_key
        self._read_timeout = read_timeout
        self._open_timeout = open_timeout
        self._max_answer_mb = max_answer_mb

    async def run(self, command: str) -> str:
        answer = _AnswerBudget(f"the answer to {command!r}", self._max_answer_mb)
        try:
            stdout, stderr, status = await self._exec(command, answer)
        except TimeoutError as exc:
            raise SshTimeout(f"{command!r} did not complete within {self._read_timeout}s") from exc
        # A status of None means that the device sent no exit status.
        if status is not None and status > 0:
            reason = _failure_reason(stdout, sanitize_cli_text(stderr))
            raise CommandFailed(f"{command!r} exited {status}: {reason}")
        rejection = _cli_rejection(stdout)
        if rejection is not None:
            raise CommandFailed(f"{command!r} rejected by device: {rejection}")
        return stdout

    async def _open(self, command: str) -> asyncssh.SSHClientProcess:
        """Open a new exec channel that runs `command`. The channel delivers its data
        from the start (`resume_reading`) and when the connection ends
        (`_deliver_before_the_end`).

        A channel or an exec request that the device refuses, or leaves unanswered for
        `open_timeout`, raises `SshTimeout`. The session goes on to the next command.
        """
        try:
            async with asyncio.timeout(self._open_timeout):
                process = await self._conn.create_process(command, encoding="utf-8", errors="replace")
        except TimeoutError as exc:
            raise SshTimeout(
                f"{command!r} could not open an exec channel: the device did not answer within "
                f"{self._open_timeout}s"
            ) from exc
        except asyncssh.ChannelOpenError as exc:
            raise SshTimeout(f"{command!r} could not open an exec channel: {exc}") from exc
        # Both calls run before this task yields. asyncssh processes nothing more for
        # the channel before them. A stand-in process without a channel delivers its own
        # data.
        channel = getattr(process, "channel", None)
        if channel is not None:
            _deliver_before_the_end(process, channel)
            # asyncssh delivers the data of a new channel from a task that it starts one
            # loop step after the command is accepted. It drops the held data of a
            # channel whose connection ends before that step. Without `resume_reading`,
            # a device that answers, closes the channel and ends the connection at once
            # gives an empty answer. A device that allows one command per connection
            # does that.
            channel.resume_reading()
        return process

    async def _exec(self, command: str, answer: _AnswerBudget) -> tuple[str, str, int | None]:
        """The sanitized standard output of one command, its standard error and its exit
        status.

        `read_timeout` bounds the whole read. Both streams count against `answer`. The
        read that passes the limit of `answer` raises `AnswerTooLarge`, and the process
        is closed.

        A read that the connection ended raises `AnswerIncomplete` (`_cut_short`).
        """
        process = await self._open(command)
        try:
            async with asyncio.timeout(self._read_timeout):
                # Both streams share the receive window. Standard error is read
                # alongside standard output. Unread standard error that fills the window
                # stops standard output.
                reads = (
                    asyncio.ensure_future(_read_stream(process.stdout, answer, sanitize=True)),
                    asyncio.ensure_future(_read_stream(process.stderr, answer, sanitize=False)),
                )
                try:
                    (stdout, out_ended), (stderr, err_ended) = await asyncio.gather(*reads)
                finally:
                    # A read that raised leaves the other one waiting on the
                    # channel.
                    for read in reads:
                        read.cancel()
                await process.wait_closed()
            _cut_short(command, answer, process, out_ended or err_ended)
        finally:
            process.close()
        return stdout, stderr, process.exit_status


def _deliver_before_the_end(process: asyncssh.SSHClientProcess, channel: asyncssh.SSHClientChannel) -> None:
    """Have asyncssh deliver what `channel` holds before it ends the streams of the
    channel for a connection that ended.

    asyncssh holds what arrives while flow control has paused delivery. When the
    connection ends, asyncssh ends the streams of the channel at once, and the held data
    never reaches the reader. The streams then end without the tail of the answer. A
    large answer loses its tail when a device closes the channel or sends its exit
    status and ends the connection right after.

    asyncssh ends the streams with a call to `connection_lost` of the process, while the
    channel can still deliver to the process. The replaced `connection_lost` resumes
    delivery first. The held data reaches the streams before their end. The held data is
    at most the receive window of the channel.
    """
    ended = process.connection_lost

    def connection_lost(exc: Exception | None) -> None:
        try:
            channel.resume_reading()
        finally:
            ended(exc)

    process.connection_lost = connection_lost


def _cut_short(
    command: str, answer: _AnswerBudget, process: asyncssh.SSHClientProcess, ended: Exception | None
) -> None:
    """Raise `AnswerIncomplete` when the connection ended the answer before the device
    did.

    The end of file, the close and the exit status of the device each follow the last
    data of its answer on the connection. A channel that received none of them before
    the connection ended holds part of an answer (see `ssh.SshSession.run`). asyncssh
    records the end of file and the close in the receive state of the channel
    (`_recv_state`), an undocumented attribute. The state stays "open" without them. A
    lost connection also queues an exception behind the data (`ended`). A disconnect
    message with the reason "by application" queues no exception, and only the state
    shows it. A close that the device sent is a whole answer even when an exception is
    queued behind it. asyncssh can end the streams for the connection before it ends
    them for the close.

    Without that state, as on a stand-in process, the answer is judged on `ended` alone.
    """
    if process.exit_status is not None:
        return
    state = getattr(getattr(process, "channel", None), "_recv_state", None)
    if (ended is not None) if state is None else (state == "open"):
        cause = f" ({_cause(ended)})" if ended is not None else ""
        raise AnswerIncomplete(
            f"{command!r} was cut short: the connection ended after {answer.size} bytes of its answer, "
            f"before the device ended the channel or sent an exit status{cause}"
        ) from ended


_EXEC_READ = 1 << 18


def _size_of(text: str) -> int:
    """The size of `text` in UTF-8. It equals the size that the device sent, with one
    exception. asyncssh replaces a run of bytes that are not UTF-8 with one U+FFFD, and
    the run counts as the 3 bytes of U+FFFD."""
    return len(text) if text.isascii() else len(text.encode("utf-8", "surrogatepass"))


async def _read_stream(
    reader: asyncssh.SSHReader[str], answer: _AnswerBudget, *, sanitize: bool
) -> tuple[str, Exception | None]:
    """Read a stream to its end. Return the text, sanitized on arrival when `sanitize`
    is set, and the exception that ended the read early, or None.

    asyncssh reports a lost connection as an exception queued behind the data that
    arrived before it. The read ends at the exception. `_cut_short` decides whether the
    data is a whole answer.
    """
    sanitizer = StreamSanitizer() if sanitize else None
    parts: list[str] = []
    ended: Exception | None = None
    while True:
        try:
            data = await reader.read(_EXEC_READ)
        except Exception as exc:
            ended = exc
            break
        if not data:
            break
        answer.take(_size_of(data))
        parts.append(sanitizer.feed(data) if sanitizer is not None else data)
    if sanitizer is not None:
        parts.append(sanitizer.finish())
    return "".join(parts), ended


class AsyncShellSession:
    """The async form of `ssh.ShellSession`, one interactive shell whose reads end at
    the prompt.

    A command whose answer passes the answer limit fails alone. The next command runs on
    a new shell of the same connection (`run`).
    """

    def __init__(
        self,
        conn: asyncssh.SSHClientConnection,
        host_key: str,
        jump_host_key: str,
        *,
        read_timeout: int,
        open_timeout: int = 120,
        setup: tuple[str, ...] = (),
        max_answer_mb: int = 0,
    ) -> None:
        self._conn = conn
        # The current shell, or None before `_start` opens it.
        self._process: Any = None
        self.host_key = host_key
        self.jump_host_key = jump_host_key
        self._read_timeout = read_timeout
        self._open_timeout = open_timeout
        self._setup_commands = setup
        self._max_answer_mb = max_answer_mb
        self.prompt = ""
        # The reason why `run` sends no further command, or empty while the reader is at
        # a prompt.
        self._stopped = ""
        # The command whose answer passed the answer limit, once its shell is
        # closed and until the next `run` opens another one.
        self._closed_after = ""

    @classmethod
    async def open(
        cls,
        conn: asyncssh.SSHClientConnection,
        host_key: str,
        jump_host_key: str,
        *,
        read_timeout: int,
        open_timeout: int = 120,
        setup: tuple[str, ...] = (),
        max_answer_mb: int = 0,
    ) -> AsyncShellSession:
        self = cls(
            conn,
            host_key,
            jump_host_key,
            read_timeout=read_timeout,
            open_timeout=open_timeout,
            setup=setup,
            max_answer_mb=max_answer_mb,
        )
        try:
            await self._start()
        except BaseException:
            self.close()
            raise
        return self

    async def _start(self) -> None:
        """Open a shell, learn its prompt and run the setup commands."""
        try:
            self._process = await asyncio.wait_for(
                self._conn.create_process(
                    term_type="vt100",
                    term_size=(SHELL_WIDTH, SHELL_HEIGHT),
                    encoding="utf-8",
                    errors="replace",
                ),
                self._open_timeout,
            )
        except TimeoutError as exc:
            raise SshTimeout(f"the device did not open a shell within {self._open_timeout}s") from exc
        except asyncssh.ChannelOpenError as exc:
            raise SshError(f"the device refused an interactive shell: {exc}") from exc
        self.prompt = await self._learn_prompt()
        for command in self._setup_commands:
            await self._setup(command)

    async def _learn_prompt(self) -> str:
        """Return the prompt of the device after 2 equal answers to a newline. See
        `ssh.ShellSession._learn_prompt`.
        """
        login = await self._read_burst()
        logger.debug("shell: login burst %d chars, last line %r", len(login), login.rstrip()[-80:])
        seen = ""
        for _ in range(SHELL_PROMPT_ATTEMPTS):
            self._process.stdin.write("\n")
            prompt = shell_prompt_of(sanitize_cli_text(await self._read_burst()))
            logger.debug("shell: newline answered with prompt %r", prompt)
            if prompt and prompt == seen:
                logger.info("shell: prompt %r settled after a login burst of %d chars", prompt, len(login))
                return prompt
            seen = prompt
        raise SshError(
            f"the device's prompt did not settle within {SHELL_PROMPT_ATTEMPTS} newlines, "
            f"so a shell read cannot be delimited; its last line was {seen[-120:]!r}"
        )

    async def _setup(self, command: str) -> None:
        """Run one setup command and log a refusal as a warning. See
        `ssh.ShellSession._setup`.
        """
        try:
            await self.run(command)
        except CommandFailed as exc:
            if self._stopped or self._closed_after:
                raise
            logger.warning("shell setup %r refused: %s", command, exc)

    async def _recv(self, seconds: float, during: str) -> str:
        """The shell's next output, or "" once the device closed the shell.

        asyncssh reports a lost connection as an exception queued behind the
        data that arrived before it. `_recv` raises it as `SshError` with
        `during` in the message. The paramiko shell ends a read on a closed
        channel in the same way.
        """
        try:
            return await asyncio.wait_for(self._process.stdout.read(65536), seconds)
        except TimeoutError:
            raise
        except Exception as exc:
            raise SshError(f"the connection ended {during} ({_cause(exc)})") from exc

    async def _read_burst(self) -> str:
        deadline = time.monotonic() + self._read_timeout
        answer = _AnswerBudget("the device's output before its prompt", self._max_answer_mb)
        buffer = ""
        while not shell_prompt_of(sanitize_cli_text(buffer[-_PROMPT_TAIL:])):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SshTimeout(f"the device sent no prompt within {self._read_timeout}s")
            try:
                data = await self._recv(min(remaining, SHELL_IDLE_READ), "before the device sent a prompt")
            except TimeoutError:
                if buffer:
                    return buffer
                continue
            if not data:
                raise SshError("the device closed the shell before sending a prompt")
            answer.take(_size_of(data))
            buffer += data
        return buffer

    async def _read_to_prompt(self, command: str) -> str:
        """Sanitized output, read to the prompt on its own line."""
        deadline = time.monotonic() + self._read_timeout
        answer = _AnswerBudget(f"the answer to {command!r}", self._max_answer_mb)
        # The output is sanitized chunk by chunk and joined once at the end. See
        # `ssh.ShellSession._read_to_prompt`.
        sanitizer = StreamSanitizer()
        parts: list[str] = []
        tail = ""
        while not shell_at_prompt(sanitize_cli_text(tail), self.prompt):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SshTimeout(f"{command!r} produced no further output within {self._read_timeout}s")
            try:
                data = await self._recv(remaining, f"during {command!r}")
            except TimeoutError as exc:
                raise SshTimeout(
                    f"{command!r} produced no further output within {self._read_timeout}s"
                ) from exc
            if not data:
                raise SshError(f"the device closed the shell during {command!r}")
            answer.take(_size_of(data))
            parts.append(sanitizer.feed(data))
            tail = (tail + data)[-_PROMPT_TAIL:]
        parts.append(sanitizer.finish())
        return "".join(parts)

    async def _open_again(self) -> None:
        """Open a new shell on the same connection after the shell of `_closed_after`
        closed. See `ssh.ShellSession._open_again`."""
        after, self._closed_after = self._closed_after, ""
        try:
            await self._start()
        except BaseException as exc:
            self._stopped = _not_reopened(after, exc)
            self._closed_after = ""
            self.close()
            if not isinstance(exc, Exception):
                raise
            raise SshError(self._stopped) from exc
        logger.info("shell: a new shell opened after %r passed the answer limit", after)

    async def run(self, command: str) -> str:
        """One command's output, read to the prompt that follows it.

        Once a command's write or read ends anywhere but at the prompt, the
        rest of its answer may still arrive, and a later command would read
        it as its own output. The session then sends nothing more, and every
        later `run` raises `SshError` without a write.

        An `AnswerTooLarge` closes the process, and the next `run` first
        opens a new shell on the same connection, as the paramiko session
        does with its `reopen`.
        """
        if self._stopped:
            raise SshError(self._stopped)
        if self._closed_after:
            await self._open_again()
        logger.debug("shell: send %r", command)
        started = time.monotonic()
        try:
            self._process.stdin.write(f"{command}\n")
            text = await self._read_to_prompt(command)
        except BaseException as exc:
            if isinstance(exc, AnswerTooLarge):
                self.close()
                self._closed_after = command
            else:
                self._stopped = _shell_stopped(command, exc)
            raise
        logger.debug("shell: %r read %d chars in %.1fs", command, len(text), time.monotonic() - started)
        stdout = shell_output_of(text, command, self.prompt)
        rejection = _cli_rejection(stdout)
        if rejection is not None:
            raise CommandFailed(f"{command!r} rejected by device: {rejection}")
        return stdout

    def close(self) -> None:
        if self._process is not None:
            self._process.close()


@asynccontextmanager
async def session(
    host: str,
    auth,
    *,
    port: int = 22,
    jump: SshJumpHost | None = None,
    known_host_key: str = "",
    timeout: int = 120,  # noqa: ASYNC109 - the handshake+auth budget, mirroring ssh.py
    connect_timeout: int = 10,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
    channel: str = "exec",
    shell_setup: tuple[str, ...] = (),
    max_answer_mb: int = 0,
) -> AsyncIterator[AsyncSshSession | AsyncShellSession]:
    """One authenticated session to one device, reused across commands.

    The session exposes the observed keys and stores none, as `ssh.session`
    does. The module has no database handle. The platform decides whether to
    pin the keys (see runs_exec). `channel` and `max_answer_mb` are as in
    `ssh.session`."""
    jump_conn: asyncssh.SSHClientConnection | None = None
    jump_key = ""
    if jump is not None:
        jump_conn, jump_key = await _connect(
            jump.host, jump.port, jump.auth, jump.host_key, timeout, connect_timeout, hop="bastion"
        )
    try:
        conn, observed = await _connect(
            host, port, auth, known_host_key, timeout, connect_timeout, tunnel=jump_conn
        )
        try:
            if channel == "shell":
                shell = await AsyncShellSession.open(
                    conn,
                    observed,
                    jump_key,
                    open_timeout=timeout,
                    read_timeout=read_timeout,
                    setup=shell_setup,
                    max_answer_mb=max_answer_mb,
                )
                try:
                    yield shell
                finally:
                    shell.close()
            else:
                yield AsyncSshSession(
                    conn,
                    observed,
                    jump_key,
                    read_timeout=read_timeout,
                    open_timeout=timeout,
                    max_answer_mb=max_answer_mb,
                )
        finally:
            conn.close()
            await conn.wait_closed()
    finally:
        if jump_conn is not None:
            jump_conn.close()
            await jump_conn.wait_closed()


async def run(
    host: str,
    auth,
    command: str,
    *,
    port: int = 22,
    jump: SshJumpHost | None = None,
    known_host_key: str = "",
    timeout: int = 120,  # noqa: ASYNC109 - the handshake+auth budget, mirroring ssh.py
    connect_timeout: int = 10,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
    channel: str = "exec",
    shell_setup: tuple[str, ...] = (),
    max_answer_mb: int = 0,
) -> SshResult:
    """Run one command in its own session. Returns (stdout, device key, bastion key)."""
    async with session(
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
        return SshResult(await s.run(command), s.host_key, s.jump_host_key)
