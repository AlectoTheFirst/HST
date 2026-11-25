"""Contract tests for the asyncssh transport (`collectors/assh.py`).

The tests run against a real in-process asyncssh server on loopback.
"""

from __future__ import annotations

import asyncio
import base64
import re
import socket
from contextlib import asynccontextmanager

import asyncssh
import paramiko
import pytest

from hst.collectors import assh, ssh
from hst.collectors.auth import SshAgent, SshJumpHost, SshPassword, SshPrivateKey

USER = "collector"
PASSWORD = "s3cret"

PW = SshPassword(username=USER, password=PASSWORD)


def _pw(password: str) -> SshPassword:
    return SshPassword(username=USER, password=password)


class _Recorder:
    """What the server saw: auth attempts and connection count."""

    def __init__(self) -> None:
        self.auth: list[tuple] = []
        self.connections = 0


class _Server(asyncssh.SSHServer):
    def __init__(self, rec: _Recorder, *, authorized_key=None, kbdint_only=False, forward=False):
        self._rec = rec
        self._authorized_key = authorized_key
        self._kbdint_only = kbdint_only
        self._forward = forward

    def connection_made(self, conn) -> None:
        self._rec.connections += 1

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return not self._kbdint_only

    def validate_password(self, username: str, password: str) -> bool:
        self._rec.auth.append(("password", username, password))
        return username == USER and password == PASSWORD

    def public_key_auth_supported(self) -> bool:
        return self._authorized_key is not None

    def validate_public_key(self, username: str, key) -> bool:
        self._rec.auth.append(("publickey", username))
        return username == USER and key == self._authorized_key

    def kbdint_auth_supported(self) -> bool:
        return self._kbdint_only

    def get_kbdint_challenge(self, username: str, lang: str, submethods: str):
        return ("", "", "", [("Password:", False)])

    def validate_kbdint_response(self, username: str, responses) -> bool:
        self._rec.auth.append(("kbdint", username, list(responses)))
        return username == USER and responses == [PASSWORD]

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        # direct-tcpip, i.e. acting as a bastion
        return self._forward


def _handle(outputs: dict):
    """A process factory: command -> (stdout, stderr, exit_status)."""

    async def handler(process: asyncssh.SSHServerProcess) -> None:
        spec = outputs.get(process.command or "")
        if spec is None:
            process.exit(127)
            return
        if spec == "hang":
            await asyncio.sleep(30)
            process.exit(0)
            return
        stdout, stderr, status = spec
        process.stdout.write(stdout)
        process.stderr.write(stderr)
        process.exit(status)

    return handler


@asynccontextmanager
async def _server(outputs: dict | None = None, **server_kwargs):
    """One listening server. Yields (rec, port, pin)."""
    rec = _Recorder()
    key = asyncssh.generate_private_key("ssh-ed25519")
    pub = key.convert_to_public()
    pin = f"{pub.algorithm.decode()} {base64.b64encode(pub.public_data).decode()}"
    listener = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_factory=lambda: _Server(rec, **server_kwargs),
        server_host_keys=[key],
        process_factory=_handle(outputs or {}),
    )
    try:
        yield rec, listener.get_port(), pin
    finally:
        listener.close()
        await listener.wait_closed()


# --- pin format ---


async def test_observed_pin_is_byte_identical_to_paramikos():
    async with (
        _server({"show x": ("out\n", "", 0)}) as (_rec, port, pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        observed = s.host_key
    _name, b64 = pin.split()
    p = paramiko.Ed25519Key(data=base64.b64decode(b64))
    assert observed == f"{p.get_name()} {p.get_base64()}" == pin


# --- TOFU / pinning ---


async def test_first_contact_captures_the_key_and_a_matching_pin_passes():
    async with _server({"c": ("ok", "", 0)}) as (_rec, port, pin):
        async with assh.session("127.0.0.1", PW, port=port) as s:
            assert s.host_key == pin
            assert s.jump_host_key == ""
        async with assh.session("127.0.0.1", PW, port=port, known_host_key=pin) as s:
            assert await s.run("c") == "ok"


async def test_a_mismatched_pin_fails_before_the_credential_is_offered():
    wrong = "ssh-ed25519 " + base64.b64encode(b"\x00" * 51).decode()
    async with _server() as (rec, port, _pin):
        with pytest.raises(ssh.HostKeyMismatch, match=re.escape("device 127.0.0.1")):
            async with assh.session("127.0.0.1", PW, port=port, known_host_key=wrong):
                pass
        assert rec.auth == []


# --- error taxonomy ---


async def test_a_closed_port_is_unreachable():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    with pytest.raises(ssh.SshUnreachable, match=f"device 127.0.0.1:{port}"):
        async with assh.session("127.0.0.1", PW, port=port, connect_timeout=1):
            pass


async def test_a_transport_that_closes_before_auth_is_refused():
    async def slam(reader, writer):
        writer.close()

    server = await asyncio.start_server(slam, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        with pytest.raises(ssh.SshRefused, match="before authentication"):
            async with assh.session("127.0.0.1", PW, port=port):
                pass
    finally:
        server.close()
        await server.wait_closed()


@asynccontextmanager
async def _closes_first(upstream_port: int, closes: int = 1):
    """A TCP front that closes its first `closes` connections at once and pipes
    every later one to `upstream_port`. Yields (port, accepted), `accepted`
    a one-element list with the connection count."""
    accepted = [0]

    async def pipe(src, dst):
        try:
            while data := await src.read(65536):
                dst.write(data)
                await dst.drain()
        finally:
            dst.close()

    async def handle(reader, writer):
        accepted[0] += 1
        if accepted[0] <= closes:
            writer.close()
            return
        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", upstream_port)
        await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer), return_exceptions=True)

    front = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield front.sockets[0].getsockname()[1], accepted
    finally:
        front.close()
        await front.wait_closed()


async def test_a_hop_that_closes_once_before_auth_gets_one_more_try(monkeypatch):
    """A close before the key exchange completes can clear by itself: the
    second try reaches the server, and the session runs."""
    monkeypatch.setattr(assh, "PRE_AUTH_RETRY_DELAY", 0)
    async with (
        _server({"c": ("ok", "", 0)}) as (rec, port, _pin),
        _closes_first(port) as (front, accepted),
        assh.session("127.0.0.1", PW, port=front) as s,
    ):
        assert await s.run("c") == "ok"
    assert accepted == [2]
    assert rec.connections == 1


async def test_a_second_close_before_auth_stands(monkeypatch):
    monkeypatch.setattr(assh, "PRE_AUTH_RETRY_DELAY", 0)
    async with _server() as (rec, port, _pin), _closes_first(port, closes=2) as (front, accepted):
        with pytest.raises(ssh.SshRefused, match="before authentication"):
            async with assh.session("127.0.0.1", PW, port=front):
                pass
    assert accepted == [2]
    assert rec.connections == 0


async def test_wrong_credentials_are_rejected_and_name_the_hop():
    async with _server() as (rec, port, _pin):
        with pytest.raises(ssh.SshRejected, match=f"credentials refused: {USER}@device 127.0.0.1"):
            async with assh.session("127.0.0.1", _pw("wrong"), port=port):
                pass
    assert ("password", USER, "wrong") in rec.auth


async def test_a_nonzero_exit_is_command_failed_with_stderr():
    async with (
        _server({"bad": ("", "boom\n", 3)}) as (_rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        with pytest.raises(ssh.CommandFailed, match=r"'bad' exited 3: boom"):
            await s.run("bad")


async def test_a_nonzero_exit_with_the_banner_on_stdout_carries_the_banner():
    """The NX-OS shape: non-zero exit, banner on stdout, nothing on stderr."""
    out = "% Invalid command at '^' marker.\n"
    async with (
        _server({"show vpc | json": (out, "", 16)}) as (_rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        with pytest.raises(ssh.CommandFailed, match=r"exited 16: % Invalid command at"):
            await s.run("show vpc | json")


async def test_a_cli_rejection_banner_is_command_failed_despite_exit_zero():
    out = "some header\n% Invalid input detected at '^' marker.\n"
    async with (
        _server({"show foo": (out, "", 0)}) as (_rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        with pytest.raises(ssh.CommandFailed, match="rejected by device"):
            await s.run("show foo")


async def test_a_command_authorization_refusal_is_command_failed_despite_exit_zero():
    """IOS's TACACS+ refusal has no `%`."""
    async with (
        _server({"show running-config": ("Command authorization failed.\n", "", 0)}) as (_rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        with pytest.raises(ssh.CommandFailed, match="rejected by device: Command authorization failed"):
            await s.run("show running-config")


async def test_a_command_that_never_finishes_is_a_timeout():
    async with (
        _server({"slow": "hang"}) as (_rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port, read_timeout=1) as s,
    ):
        with pytest.raises(ssh.SshTimeout, match=r"'slow' did not complete within 1s"):
            await s.run("slow")


# --- auth methods ---


async def test_keyboard_interactive_only_devices_accept_the_password():
    async with (
        _server({"c": ("ok", "", 0)}, kbdint_only=True) as (rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        assert await s.run("c") == "ok"
    assert ("kbdint", USER, [PASSWORD]) in rec.auth


async def test_private_key_auth_offers_exactly_that_key():
    key = asyncssh.generate_private_key("ssh-ed25519")
    auth = SshPrivateKey(
        method="private_key", username=USER, private_key=key.export_private_key("openssh").decode()
    )
    async with (
        _server({"c": ("ok", "", 0)}, authorized_key=key.convert_to_public()) as (
            rec,
            port,
            _pin,
        ),
        assh.session("127.0.0.1", auth, port=port) as s,
    ):
        assert await s.run("c") == "ok"
    assert ("publickey", USER) in rec.auth


async def test_an_empty_agent_is_rejected_before_connecting(monkeypatch):
    async def none():
        return []

    monkeypatch.setattr(assh, "_agent_keys", none)
    with pytest.raises(ssh.SshRejected, match="no keys available from the SSH agent for device r1"):
        async with assh.session("r1", SshAgent(method="agent", username=USER)):
            pass


async def test_agent_keys_are_offered_explicitly(monkeypatch):
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def keys():
        return [key]

    monkeypatch.setattr(assh, "_agent_keys", keys)
    async with (
        _server({"c": ("ok", "", 0)}, authorized_key=key.convert_to_public()) as (
            _rec,
            port,
            _pin,
        ),
        assh.session("127.0.0.1", SshAgent(method="agent", username=USER), port=port) as s,
    ):
        assert await s.run("c") == "ok"


# --- key loading ---


def test_load_key_loads_each_supported_type():
    for alg in ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"):
        pem = asyncssh.generate_private_key(alg).export_private_key("openssh").decode()
        assert assh.load_key(pem, "")


def test_load_key_failures_match_the_paramiko_messages():
    key = asyncssh.generate_private_key("ssh-ed25519")
    encrypted = key.export_private_key("openssh", passphrase="right").decode()
    with pytest.raises(ssh.SshError, match="needs a passphrase, or the passphrase is wrong"):
        assh.load_key(encrypted, "")
    with pytest.raises(ssh.SshError, match="wrong passphrase, or unsupported format"):
        assh.load_key(encrypted, "wrong")
    with pytest.raises(ssh.SshError, match="unsupported or corrupt material"):
        assh.load_key("not a key", "")


# --- session reuse ---


async def test_one_connection_serves_many_commands():
    outputs = {f"cmd{i}": (f"out{i}", "", 0) for i in range(3)}
    async with _server(outputs) as (rec, port, _pin), assh.session("127.0.0.1", PW, port=port) as s:
        for i in range(3):
            assert await s.run(f"cmd{i}") == f"out{i}"
    assert rec.connections == 1


async def test_no_exit_status_at_all_is_not_a_failure():
    class _Result:
        exit_status = None
        stdout = "payload"
        stderr = ""

    class _Reader:
        def __init__(self, text):
            self._text = text

        async def read(self, n=-1):
            if n < 0:
                n = len(self._text)
            data, self._text = self._text[:n], self._text[n:]
            return data

    class _Process:
        """The exec channel `create_process` opens, answering as `run` does."""

        def __init__(self, result):
            self.stdout = _Reader(result.stdout)
            self.stderr = _Reader(result.stderr)
            self.exit_status = result.exit_status

        async def wait_closed(self):
            pass

        def close(self):
            pass

    class _Conn:
        async def run(self, command, **kwargs):
            return _Result()

        async def create_process(self, command, **kwargs):
            return _Process(await self.run(command, **kwargs))

    s = assh.AsyncSshSession(_Conn(), "", "", read_timeout=1)
    assert await s.run("show x") == "payload"


# --- bastion ---


async def test_the_bastion_authenticates_separately_and_tunnels_the_device():
    async with (
        _server({"c": ("via-tunnel", "", 0)}) as (dev_rec, dev_port, dev_pin),
        _server(forward=True) as (jump_rec, jump_port, jump_pin),
    ):
        jump = SshJumpHost(host="127.0.0.1", port=jump_port, auth=PW)
        async with assh.session("127.0.0.1", PW, port=dev_port, jump=jump) as s:
            assert await s.run("c") == "via-tunnel"
            assert s.host_key == dev_pin
            assert s.jump_host_key == jump_pin
    assert jump_rec.connections == 1
    assert dev_rec.connections == 1


async def test_a_mismatched_bastion_pin_fails_before_any_hop_authenticates():
    wrong = "ssh-ed25519 " + base64.b64encode(b"\x01" * 51).decode()
    async with (
        _server() as (dev_rec, dev_port, _dev_pin),
        _server(forward=True) as (jump_rec, jump_port, _jump_pin),
    ):
        jump = SshJumpHost(host="127.0.0.1", port=jump_port, auth=PW, host_key=wrong)
        with pytest.raises(ssh.HostKeyMismatch, match=re.escape("bastion 127.0.0.1")):
            async with assh.session("127.0.0.1", PW, port=dev_port, jump=jump):
                pass
    assert jump_rec.auth == []
    assert dev_rec.connections == 0


async def test_a_device_the_bastion_cannot_reach_is_unreachable():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    dead_port = sock.getsockname()[1]
    sock.close()
    async with _server(forward=True) as (_jump_rec, jump_port, _jump_pin):
        jump = SshJumpHost(host="127.0.0.1", port=jump_port, auth=PW)
        with pytest.raises(ssh.SshUnreachable, match=f"device 127.0.0.1:{dead_port}"):
            async with assh.session("127.0.0.1", PW, port=dead_port, jump=jump, connect_timeout=2):
                pass


# --- run() ---


async def test_run_returns_stdout_and_both_observed_keys():
    async with _server({"show version": ("v1\n", "", 0)}) as (_rec, port, pin):
        result = await assh.run("127.0.0.1", PW, "show version", port=port)
    assert result == ssh.SshResult("v1\n", pin, "")


# --- terminal control bytes ---


async def test_control_bytes_never_reach_the_caller():
    from tests.test_cli_text_sanitize import SHAPES, VRF_NAMES

    from hst.collectors import iosxe
    from hst.collectors.cli_parse import parse

    dirty = SHAPES["all of them together"]
    async with (
        _server({iosxe.CMD_VRF: (dirty, "", 0)}) as (_rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        out = await s.run(iosxe.CMD_VRF)
    assert "\x1b" not in out
    assert [r["name"] for r in parse("iosxe", iosxe.CMD_VRF, out)] == VRF_NAMES


async def test_a_columns_by_cursor_capture_keeps_its_columns():
    # `ESC [ n C` becomes n spaces, so a member interface stays under
    # `Interfaces`.
    from tests.test_cli_text_sanitize import COLUMNS_BY_CURSOR

    async with (
        _server({"show vrf": (COLUMNS_BY_CURSOR, "", 0)}) as (_rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        out = await s.run("show vrf")
    assert "  Name  " in out.splitlines()[0]
    assert out.splitlines()[3].startswith(" " * 69)


async def test_a_rejection_banner_behind_a_colour_code_is_caught():
    # The sanitize runs before `_cli_rejection`, so a banner the device wrote
    # in colour is a refused command.
    dirty = "\x1b[1;31m% Invalid input detected at '^' marker.\x1b[0m\r\n"
    async with (
        _server({"show frobnicate": (dirty, "", 0)}) as (_rec, port, _pin),
        assh.session("127.0.0.1", PW, port=port) as s,
    ):
        with pytest.raises(ssh.CommandFailed, match="rejected by device"):
            await s.run("show frobnicate")
