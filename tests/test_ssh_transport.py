"""Paramiko transport: auth wiring, host-key pinning, error classification."""

import io

import paramiko
import pytest

from hst.collectors import ssh
from hst.collectors.auth import SshAgent, SshJumpHost, SshPassword


class FakeChannel:
    def __init__(self, out=b"OUT", err=b"", status=0, read_error=None):
        self._out, self._err, self._status = out, err, status
        self._read_error = read_error
        self.timeout = None
        self.closed = False
        # What `recv` and `recv_stderr` hand out: the bytes the file objects serve.
        self._stdout, self._stderr = io.BytesIO(out), io.BytesIO(err)

    def settimeout(self, value):
        self.timeout = value

    def exec_command(self, command):
        self.command = command
        if self._read_error is not None:
            raise self._read_error

    def makefile(self, *_):
        return io.BytesIO(self._out)

    def makefile_stderr(self, *_):
        return io.BytesIO(self._err)

    def recv(self, size):
        return self._stdout.read(size)

    def recv_stderr_ready(self):
        return self._stderr.tell() < len(self._err)

    def recv_stderr(self, size):
        return self._stderr.read(size)

    def recv_exit_status(self):
        return self._status

    def close(self):
        self.closed = True


class FakeTransport:
    def __init__(
        self, host_key="AAAAKEY", status=0, err=b"", auth_error=None, read_error=None, open_channel_error=None
    ):
        self.calls = []
        self.channels = []
        self.keepalive = None
        self._host_key, self._status, self._err = host_key, status, err
        self._auth_error = auth_error
        self._read_error = read_error
        self._open_channel_error = open_channel_error

    def set_keepalive(self, interval):
        self.keepalive = interval

    def start_client(self, timeout=None):
        self.calls.append(("start_client", timeout))

    def get_remote_server_key(self):
        return type("K", (), {"get_name": lambda s: "ssh-ed25519", "get_base64": lambda s: self._host_key})()

    def auth_password(self, username, password):
        self.calls.append(("auth_password", username, password))
        if self._auth_error:
            raise self._auth_error

    def auth_publickey(self, username, key):
        self.calls.append(("auth_publickey", username, key))
        if self._auth_error:
            raise self._auth_error

    def open_session(self, timeout=None):
        ch = FakeChannel(err=self._err, status=self._status, read_error=self._read_error)
        self.channels.append(ch)
        return ch

    def open_channel(self, kind, dest, src, timeout=None):
        self.calls.append(("open_channel", kind, dest, timeout))
        if self._open_channel_error:
            raise self._open_channel_error
        return object()  # stands in for the tunnelled socket

    def close(self):
        self.calls.append(("close",))


@pytest.fixture
def fake(monkeypatch):
    made = {}

    def factory(sock):
        made["transport"] = made.get("transport") or FakeTransport()
        return made["transport"]

    monkeypatch.setattr(ssh, "_transport_factory", factory)
    monkeypatch.setattr(ssh, "_open_socket", lambda host, port, timeout: object())
    return made


def test_password_auth_runs_the_command(fake):
    res = ssh.run("r1", SshPassword(username="admin", password="pw"), "show version")
    assert res.stdout == "OUT" and res.host_key == "ssh-ed25519 AAAAKEY"
    assert res.jump_host_key == ""
    assert ("auth_password", "admin", "pw") in fake["transport"].calls


def test_agent_auth_uses_publickey(fake, monkeypatch):
    monkeypatch.setattr(ssh, "_agent_keys", lambda: ["AGENTKEY"])
    ssh.run("r1", SshAgent(username="admin"), "show version")
    assert ("auth_publickey", "admin", "AGENTKEY") in fake["transport"].calls


def test_matching_host_key_is_accepted(fake):
    res = ssh.run("r1", SshPassword(username="a", password="p"), "cmd", known_host_key="ssh-ed25519 AAAAKEY")
    assert res.stdout == "OUT"


def test_changed_host_key_fails_before_authenticating(fake):
    with pytest.raises(ssh.HostKeyMismatch):
        ssh.run("r1", SshPassword(username="a", password="p"), "cmd", known_host_key="ssh-ed25519 DIFFERENT")
    # the credential must never be offered to an unverified host
    assert not any(c[0] == "auth_password" for c in fake["transport"].calls)


def test_rejected_credentials_raise_ssh_rejected(monkeypatch):
    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())
    monkeypatch.setattr(
        ssh, "_transport_factory", lambda sock: FakeTransport(auth_error=paramiko.AuthenticationException())
    )
    with pytest.raises(ssh.SshRejected):
        ssh.run("r1", SshPassword(username="a", password="bad"), "cmd")


def test_transport_closed_before_auth_raises_ssh_refused(monkeypatch):
    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())
    monkeypatch.setattr(
        ssh, "_transport_factory", lambda sock: FakeTransport(auth_error=paramiko.SSHException("closed"))
    )
    with pytest.raises(ssh.SshRefused):
        ssh.run("r1", SshPassword(username="a", password="p"), "cmd")


def test_unreachable_host_raises_ssh_unreachable(monkeypatch):
    def refuse(host, port, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(ssh, "_open_socket", refuse)
    with pytest.raises(ssh.SshUnreachable):
        ssh.run("r1", SshPassword(username="a", password="p"), "cmd")


def test_nonzero_exit_status_raises_command_failed(monkeypatch):
    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())
    monkeypatch.setattr(
        ssh, "_transport_factory", lambda sock: FakeTransport(status=1, err=b"invalid command")
    )
    with pytest.raises(ssh.CommandFailed, match="invalid command"):
        ssh.run("r1", SshPassword(username="a", password="p"), "bogus")


def test_nonzero_exit_with_the_banner_on_stdout_carries_the_banner(monkeypatch):
    class NxosRefusal(FakeTransport):
        def open_session(self, timeout=None):
            ch = FakeChannel(out=b"% Invalid command at '^' marker.\n", err=b"", status=16)
            self.channels.append(ch)
            return ch

    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())
    monkeypatch.setattr(ssh, "_transport_factory", lambda sock: NxosRefusal())
    with pytest.raises(ssh.CommandFailed, match=r"exited 16: % Invalid command at"):
        ssh.run("r1", SshPassword(username="a", password="p"), "show vpc | json")


def test_absent_exit_status_with_valid_output_is_not_a_failure(monkeypatch):
    """paramiko returns -1 when the device sends no exit status."""
    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())
    monkeypatch.setattr(ssh, "_transport_factory", lambda sock: FakeTransport(status=-1, err=b"OUTPUT"))
    res = ssh.run("r1", SshPassword(username="a", password="p"), "show version")
    assert res.stdout == "OUT"


def test_error_banner_on_stdout_with_zero_status_is_a_failure(monkeypatch):
    """Classic IOS rejects a command with exit 0 and '% Invalid input' on stdout."""

    class RejectingTransport(FakeTransport):
        def open_session(self, timeout=None):
            ch = FakeChannel(out=b"% Invalid input detected at '^' marker.", status=0)
            self.channels.append(ch)
            return ch

    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())
    monkeypatch.setattr(ssh, "_transport_factory", lambda sock: RejectingTransport())
    with pytest.raises(ssh.CommandFailed, match="Invalid input"):
        ssh.run("r1", SshPassword(username="a", password="p"), "show frobnicate")


def test_channel_that_never_sends_exit_status_times_out(monkeypatch):
    class NoStatusEvent:
        def wait(self, timeout):
            return False  # the status event never fires

    class StuckChannel(FakeChannel):
        status_event = NoStatusEvent()

    class StuckTransport(FakeTransport):
        def open_session(self, timeout=None):
            ch = StuckChannel()
            self.channels.append(ch)
            return ch

    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())
    monkeypatch.setattr(ssh, "_transport_factory", lambda sock: StuckTransport())
    with pytest.raises(ssh.SshTimeout, match="no exit status"):
        ssh.run("r1", SshPassword(username="a", password="p"), "show version")


def test_load_key_accepts_an_unencrypted_ed25519_pem():
    """paramiko's Ed25519Key cannot generate keys."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pem = (
        Ed25519PrivateKey.generate()
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
        .decode()
    )
    assert ssh.load_key(pem, "").get_name() == "ssh-ed25519"


def test_load_key_accepts_an_unencrypted_ecdsa_pem():
    buf = io.StringIO()
    paramiko.ECDSAKey.generate().write_private_key(buf)
    assert ssh.load_key(buf.getvalue(), "").get_name().startswith("ecdsa-")


def test_load_key_accepts_an_encrypted_rsa_pem_with_the_right_passphrase():
    buf = io.StringIO()
    paramiko.RSAKey.generate(2048).write_private_key(buf, password="right")
    assert ssh.load_key(buf.getvalue(), "right").get_name() == "ssh-rsa"


def test_load_key_rejects_garbage():
    with pytest.raises(ssh.SshError, match="private key"):
        ssh.load_key("not a key", "")


def test_load_key_reports_a_wrong_passphrase():
    rsa = paramiko.RSAKey.generate(2048)
    buf = io.StringIO()
    rsa.write_private_key(buf, password="right")
    with pytest.raises(ssh.SshError, match="passphrase"):
        ssh.load_key(buf.getvalue(), "wrong")


# --- jump host ---------------------------------------------------------------

JUMP = SshJumpHost(host="bhost", port=2222, auth={"method": "password", "username": "hop", "password": "hp"})


def _two_transports(monkeypatch, bastion, device):
    """With a jump, _transport_factory is called twice: bastion first."""
    made = iter([bastion, device])
    monkeypatch.setattr(ssh, "_transport_factory", lambda sock: next(made))
    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())


def test_jump_host_receives_its_own_credentials_never_the_devices(monkeypatch):
    bastion, device = FakeTransport(host_key="BKEY"), FakeTransport()
    _two_transports(monkeypatch, bastion, device)
    res = ssh.run("r1", SshPassword(username="admin", password="pw"), "cmd", jump=JUMP)
    assert ("auth_password", "hop", "hp") in bastion.calls
    assert ("auth_password", "admin", "pw") in device.calls
    # the device's credential must never be offered to the bastion
    assert not any(c[0].startswith("auth") and "admin" in c for c in bastion.calls)
    # the tunnel targets the device on the device's port, not the bastion's, and the
    # channel open carries the connect timeout (paramiko's default is 3600s)
    assert ("open_channel", "direct-tcpip", ("r1", 22), 10) in bastion.calls
    assert res.host_key == "ssh-ed25519 AAAAKEY"
    assert res.jump_host_key == "ssh-ed25519 BKEY"


def test_a_pinned_bastion_key_is_enforced_before_any_credential(monkeypatch):
    bastion, device = FakeTransport(host_key="BKEY"), FakeTransport()
    _two_transports(monkeypatch, bastion, device)
    pinned = JUMP.model_copy(update={"host_key": "ssh-ed25519 OLD"})
    with pytest.raises(ssh.HostKeyMismatch, match="bastion"):
        ssh.run("r1", SshPassword(username="a", password="p"), "cmd", jump=pinned)
    assert not any(c[0].startswith("auth") for c in bastion.calls)
    assert device.calls == []  # the device hop was never reached


def test_a_bastion_failure_is_classified_and_names_the_hop(monkeypatch):
    bastion = FakeTransport(auth_error=paramiko.AuthenticationException())
    _two_transports(monkeypatch, bastion, FakeTransport())
    with pytest.raises(ssh.SshRejected, match="bastion"):
        ssh.run("r1", SshPassword(username="a", password="p"), "cmd", jump=JUMP)


def test_jump_channel_open_carries_the_connect_timeout(monkeypatch):
    """`open_channel` waits paramiko's default of 3600s unless given a timeout."""
    bastion, device = FakeTransport(host_key="BKEY"), FakeTransport()
    _two_transports(monkeypatch, bastion, device)
    ssh.run("r1", SshPassword(username="admin", password="pw"), "cmd", jump=JUMP, connect_timeout=7)
    assert ("open_channel", "direct-tcpip", ("r1", 22), 7) in bastion.calls


def test_unreachable_device_behind_bastion_is_classified_unreachable(monkeypatch):
    bastion = FakeTransport(
        host_key="BKEY", open_channel_error=paramiko.SSHException("Timeout opening channel")
    )
    _two_transports(monkeypatch, bastion, FakeTransport())
    with pytest.raises(ssh.SshUnreachable, match="device r1"):
        ssh.run("r1", SshPassword(username="a", password="p"), "cmd", jump=JUMP)


def test_one_session_reuses_one_transport_across_commands(fake):
    with ssh.session("r1", SshPassword(username="admin", password="pw")) as s:
        outputs = [s.run(c) for c in ("show version", "show interface", "show ip route")]
    assert outputs == ["OUT", "OUT", "OUT"]
    transport = fake["transport"]
    # one authentication, three channels
    assert [c[0] for c in transport.calls].count("auth_password") == 1
    assert len(transport.channels) == 3
    assert all(ch.closed for ch in transport.channels)


def test_session_sets_a_read_timeout_and_a_keepalive(fake):
    with ssh.session("r1", SshPassword(username="a", password="p"), read_timeout=42) as s:
        s.run("show version")
    transport = fake["transport"]
    assert transport.keepalive == ssh.KEEPALIVE_INTERVAL
    assert transport.channels[0].timeout == 42


def test_read_timeout_is_classified_as_ssh_timeout(monkeypatch):
    """paramiko leaves Channel.timeout at None by default."""
    monkeypatch.setattr(ssh, "_open_socket", lambda h, p, t: object())
    monkeypatch.setattr(ssh, "_transport_factory", lambda sock: FakeTransport(read_error=TimeoutError()))
    with pytest.raises(ssh.SshTimeout, match="no further output"):
        ssh.run("r1", SshPassword(username="a", password="p"), "show tech-support")


def test_run_returns_the_observed_keys(fake):
    res = ssh.run("r1", SshPassword(username="a", password="p"), "cmd")
    assert res.stdout == "OUT"
    assert res.host_key == "ssh-ed25519 AAAAKEY"
    assert res.jump_host_key == ""
