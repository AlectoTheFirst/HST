"""A UniFi source can pin the console certificate by its SHA-256 fingerprint.
Real TLS over a socket pair, without external hosts: the pin is
checked on the connection that carries the login and the reads, and a
different certificate fails the source before the login is sent."""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from hst.collectors import http
from hst.collectors import unifi as unifi_mod
from hst.collectors.unifi import CertificatePinMismatch, UnifiCollector, UnifiConfig
from hst.core import Settings

AUTH = {"method": "user_password", "username": "ro", "password": "pw-secret"}


class _PairSocket(socket.socket):
    """One end of a socket pair standing in for a TCP connection; the TCP
    options httpcore sets on a new connection do not apply to it."""

    def setsockopt(self, *args, **kwargs):
        pass


@pytest.fixture
def console(monkeypatch, tmp_path):
    """A UniFi OS console with a self-signed certificate for its own name,
    answering at any address."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("unifi.local")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    state = SimpleNamespace(
        requests=[],
        posts=[],
        connections=0,
        fingerprint=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
    )

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            state.requests.append(("GET", self.path))
            self.reply(b'{"data": []}')

        def do_POST(self):
            state.requests.append(("POST", self.path))
            state.posts.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.reply(b"{}")

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
            except (ssl.SSLError, ConnectionError, OSError):
                pass  # the client refusing the certificate is tested below

    with ThreadPoolExecutor(max_workers=4) as executor:

        def create_connection(address, timeout=None, source_address=None):
            state.connections += 1
            client_sock, server_sock = socket.socketpair()
            server_sock.settimeout(5)
            executor.submit(serve, server_sock)
            client = _PairSocket(fileno=client_sock.detach())
            client.settimeout(timeout)
            return client

        monkeypatch.setattr(socket, "create_connection", create_connection)
        yield state


def _collector(**config):
    return UnifiCollector(
        UnifiConfig(url="https://192.0.2.8", auth=AUTH, **config),
        Settings(_env_file=None),
    )


def test_the_pinned_certificate_carries_login_and_reads_at_an_ip_url(console):
    collector = _collector(tls_fingerprint_sha256=console.fingerprint)
    assert "login ok" in collector.probe()
    raw = collector.fetch()
    assert raw["devices"] == [] and raw["refused_reads"] == []
    assert ("POST", "/api/auth/login") in console.requests
    assert ("GET", "/proxy/network/api/s/default/stat/device") in console.requests
    assert console.posts[0]["password"] == "pw-secret"


def test_the_pin_also_holds_with_verify_false(console):
    collector = _collector(tls_fingerprint_sha256=console.fingerprint, tls={"verify": False})
    assert "login ok" in collector.probe()


@pytest.mark.parametrize("operation", ["probe", "fetch"])
def test_another_certificate_fails_the_source_before_the_login_is_sent(console, operation):
    other = hashlib.sha256(b"another console").hexdigest()
    collector = _collector(tls_fingerprint_sha256=other, tls={"verify": False})
    with pytest.raises(CertificatePinMismatch) as caught:
        getattr(collector, operation)()
    text = f"{type(caught.value).__name__}: {caught.value}"
    assert text.startswith("CertificatePinMismatch: https://192.0.2.8: ")
    assert console.fingerprint in text and other in text
    assert console.connections >= 1
    assert console.requests == [] and console.posts == []


def test_without_a_pin_the_client_applies_the_stated_tls(monkeypatch):
    seen = {}

    def logged_in_client(base_url, tls, login, *, timeout, transport):
        seen.update(base_url=base_url, tls=tls, timeout=timeout, transport=transport)
        raise RuntimeError("stop")

    monkeypatch.setattr(http, "logged_in_client", logged_in_client)
    collector = _collector(tls={"verify": False})
    with pytest.raises(RuntimeError):
        collector.probe()
    assert seen["transport"] is None and seen["tls"].verify is False and seen["timeout"] == 30


def test_the_test_seam_transport_is_kept_when_a_pin_is_stated(monkeypatch):
    marker = object()
    monkeypatch.setattr(unifi_mod, "_transport", lambda config: marker)
    seen = {}

    def logged_in_client(base_url, tls, login, *, timeout, transport):
        seen["transport"] = transport
        raise RuntimeError("stop")

    monkeypatch.setattr(http, "logged_in_client", logged_in_client)
    with pytest.raises(RuntimeError):
        _collector(tls_fingerprint_sha256="ab" * 32).probe()
    assert seen["transport"] is marker


def test_the_fingerprint_is_stored_as_lowercase_hex():
    colons = ":".join(["AB"] * 32)
    assert (
        UnifiConfig(url="https://c", auth=AUTH, tls_fingerprint_sha256=colons).tls_fingerprint_sha256
        == "ab" * 32
    )
    assert UnifiConfig(url="https://c", auth=AUTH).tls_fingerprint_sha256 == ""
    for bad in ("ab" * 31, "zz" * 32, "ab" * 33, "sha256:" + "ab" * 32):
        with pytest.raises(ValidationError):
            UnifiConfig(url="https://c", auth=AUTH, tls_fingerprint_sha256=bad)
