"""Real TLS and HTTP through socket-like SSH channels, without external hosts."""

import json
import select
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace

import httpx
import paramiko
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from hst.collectors import http, ssh
from hst.collectors.auth import TlsConfig
from hst.collectors.velocloud import (
    EDGE_MODULES,
    EDGE_WITH,
    PORTAL_READ_PATHS,
    VeloCloudCollector,
    VeloCloudConfig,
    VeloCloudJumpHost,
)
from hst.core import Settings


def jump(**changes):
    return VeloCloudJumpHost(
        **{
            "host": "bastion.invalid",
            "port": 2222,
            "host_key": "ssh-ed25519 test-pin",
            "auth": {"method": "password", "username": "jump-user", "password": "jump-secret"},
            **changes,
        }
    )


class Channel:
    """Only the socket-like operations offered by a Paramiko channel."""

    def __init__(self, sock):
        self.sock = sock
        self.closed = False
        self.eof_received = False

    def settimeout(self, timeout):
        self.sock.settimeout(timeout)

    def recv(self, size):
        data = self.sock.recv(size)
        self.eof_received = not data
        return data

    def sendall(self, data):
        self.sock.sendall(data)

    def recv_ready(self):
        return bool(select.select([self.sock], [], [], 0)[0])

    def close(self):
        self.closed = True
        self.sock.close()


@pytest.fixture
def bastion(monkeypatch, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vco.invalid")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("vco.invalid")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_text(pem)
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    state = SimpleNamespace(
        calls=[],
        requests=[],
        posts=[],
        # One answer per allowed Portal read, so a whole poll runs over the jump
        # transport. A test that asserts on one read overrides its entry.
        responses={
            PORTAL_READ_PATHS["aggregates"]: b'{"enterprises":[{"id":34,"logicalId":"ent-1"}]}',
            PORTAL_READ_PATHS["enterprise_edges"]: b'[{"id":12,"logicalId":"edge-1"}]',
            PORTAL_READ_PATHS["enterprise_configurations"]: b'[{"id":77,"name":"profile-1"}]',
            PORTAL_READ_PATHS["route_table"]: b'{"subnets":[]}',
            PORTAL_READ_PATHS["configuration_modules"]: b"{}",
        },
        channels=[],
        closed=False,
        sni=[],
        reject=False,
        pem=pem,
    )
    context.set_servername_callback(lambda sock, name, ctx: state.sni.append(name))

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            state.requests.append((self.path, dict(self.headers)))
            body = (
                b'{"data": [{"logicalId": "ent-1"}]}'
                if "enterprises?" in self.path or self.path.endswith("/enterprises")
                else b'{"data": []}'
            )
            self.reply(state.responses.get(self.path.split("?")[0], body))

        def do_POST(self):
            state.requests.append((self.path, dict(self.headers)))
            state.posts.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.reply(state.responses[self.path])

        def reply(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    def serve(sock):
        with sock:
            try:
                with context.wrap_socket(sock, server_side=True) as tls:
                    Handler(tls, ("127.0.0.1", 0), None)
            except (ssl.SSLError, ConnectionError):
                pass  # Certificate rejection and client shutdown are tested below.

    with ThreadPoolExecutor(max_workers=4) as executor:

        class Transport:
            def open_channel(self, kind, destination, source, timeout):
                state.calls.append((kind, destination))
                if state.reject:
                    raise paramiko.ChannelException(1, "administratively prohibited")
                client_sock, server_sock = socket.socketpair()
                server_sock.settimeout(5)
                executor.submit(serve, server_sock)
                channel = Channel(client_sock)
                state.channels.append(channel)
                return channel

            def set_keepalive(self, interval):
                pass

            def close(self):
                state.closed = True
                for channel in state.channels:
                    channel.close()

        def connect(host, port, auth, known_host_key, timeout, connect_timeout, hop):
            assert (host, port, hop) == ("bastion.invalid", 2222, "bastion")
            assert auth.password.get_secret_value() == "jump-secret"
            assert known_host_key == "ssh-ed25519 test-pin"
            return Transport(), known_host_key

        monkeypatch.setattr(ssh, "_connect", connect)
        monkeypatch.setenv("HTTPS_PROXY", "http://unreachable-proxy.invalid:9999")
        yield state


def test_vco_portal_posts_and_the_scoped_get_share_the_jump_transport(bastion):
    config = VeloCloudConfig(
        url="https://vco.invalid:8443",
        orchestrator_release="6.4.0",
        auth={"key": "api-secret"},
        tls=TlsConfig(ca_bundle=bastion.pem),
        jump_host=jump(),
    )
    collector = VeloCloudCollector(config, Settings(_env_file=None))
    with collector._client() as client:
        assert collector._enterprise_id(client, "ent-1") == (34, None)
        edges, gap = collector._portal_edges(client, 34)
        assert gap is None
        assert [edge["logicalId"] for edge in edges] == ["edge-1"]
        assert collector._edge_modules(client, 34, 12) == {}
        assert collector._bgp_sessions(client, "ent-1") == []
    assert bastion.posts == [
        (PORTAL_READ_PATHS["aggregates"], {}),
        (PORTAL_READ_PATHS["enterprise_edges"], {"enterpriseId": 34, "with": list(EDGE_WITH)}),
        (
            PORTAL_READ_PATHS["configuration_modules"],
            {"enterpriseId": 34, "edgeId": 12, "modules": list(EDGE_MODULES)},
        ),
    ]
    assert bastion.requests[-1][0] == "/api/sdwan/v2/enterprises/ent-1/bgpSessions?state%5Bis%5D=ESTABLISHED"
    assert len(bastion.calls) == 1
    assert bastion.calls[0] == ("direct-tcpip", ("vco.invalid", 8443))
    assert bastion.sni == ["vco.invalid"]
    assert all(headers["Authorization"] == "Token api-secret" for _, headers in bastion.requests)
    assert bastion.closed


@pytest.mark.parametrize("operation", ["probe", "fetch"])
def test_vco_requests_use_jump_host_with_original_tls_identity(bastion, operation):
    config = VeloCloudConfig(
        url="https://vco.invalid:8443",
        orchestrator_release="6.4.0",
        auth={"key": "api-secret"},
        tls=TlsConfig(ca_bundle=bastion.pem),
        jump_host=jump(),
    )
    collector = VeloCloudCollector(config, Settings(_env_file=None))
    result = getattr(collector, operation)()
    if operation == "probe":
        assert result.startswith("login ok")
    else:
        assert result["enterprises"][0]["logicalId"] == "ent-1"
        # the whole cold poll of one enterprise with one edge: the discovery
        # page, four enterprise-wide Portal reads, one module read, one BGP page
        assert len(bastion.requests) == 7
    assert set(bastion.calls) == {("direct-tcpip", ("vco.invalid", 8443))}
    assert set(bastion.sni) == {"vco.invalid"}
    for _, headers in bastion.requests:
        assert headers["Host"] == "vco.invalid:8443"
        assert headers["Authorization"] == "Token api-secret"
        assert "jump-secret" not in str(headers)
    assert bastion.closed and all(channel.closed for channel in bastion.channels)


def test_jump_keeps_certificate_verification_and_closes_on_failure(bastion):
    with (
        http.client("https://vco.invalid", TlsConfig(), jump_host=jump()) as client,
        pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"),
    ):
        client.get("/")
    assert bastion.closed and all(channel.closed for channel in bastion.channels)


def test_jump_verify_false_is_explicit_and_origin_cannot_change(bastion):
    with http.client("https://vco.invalid", TlsConfig(verify=False), jump_host=jump()) as client:
        assert client.get("/").status_code == 200
        with pytest.raises(httpx.ConnectError, match="different VCO origin"):
            client.get("https://other.invalid/")
    assert all(destination[0] == "vco.invalid" for _, destination in bastion.calls)


def test_a_body_larger_than_the_answer_limit_raises_answer_too_large_over_the_jump_host(bastion):
    bastion.responses["/big"] = b"x" * ((1 << 20) + 1)
    with (
        http.fetching("vco-1", 1),
        http.client("https://vco.invalid", TlsConfig(verify=False), jump_host=jump()) as client,
        pytest.raises(ssh.AnswerTooLarge, match="answer limit of 1 MiB"),
    ):
        client.get("/big")
    assert bastion.closed and all(channel.closed for channel in bastion.channels)


def test_refused_forwarding_has_no_direct_fallback(bastion):
    bastion.reject = True
    with (
        http.client("https://vco.invalid", TlsConfig(), jump_host=jump()) as client,
        pytest.raises(httpx.ConnectError, match=r"bastion could not reach vco\.invalid"),
    ):
        client.get("/")
    assert bastion.closed
    assert not bastion.requests


def test_vco_jump_requires_a_trusted_host_key():
    with pytest.raises(ValidationError):
        jump(host_key="")


def test_jump_checks_the_original_hostname_even_with_trusted_ca(bastion):
    with (
        http.client("https://wrong.invalid", TlsConfig(ca_bundle=bastion.pem), jump_host=jump()) as client,
        pytest.raises(httpx.ConnectError, match=r"[Hh]ostname mismatch"),
    ):
        client.get("/")
    assert bastion.closed


def test_tls_handshake_timeout_closes_channel_and_ssh(bastion, monkeypatch):
    def timeout(self, size):
        raise TimeoutError("stalled VCO handshake")

    monkeypatch.setattr(Channel, "recv", timeout)
    with (
        http.client("https://vco.invalid", TlsConfig(), jump_host=jump()) as client,
        pytest.raises(httpx.ConnectTimeout, match="stalled VCO handshake"),
    ):
        client.get("/")
    assert bastion.closed and all(channel.closed for channel in bastion.channels)
