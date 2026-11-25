"""Construction kwargs are captured by monkeypatching `httpx.Client`."""

import logging
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from hst import collectors as coll
from hst.collectors import http as http_client
from hst.collectors.auth import ClientCert, TlsConfig
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.ssh import AnswerTooLarge
from hst.core import Settings


def _test_ca_pem() -> str:
    """A self-signed CA certificate, PEM."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hst-test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2020, 1, 1, tzinfo=UTC) + timedelta(days=365 * 30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _test_client_cert_and_key() -> tuple[str, str]:
    """`load_cert_chain` checks that the key signs the certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hst-test-client")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2020, 1, 1, tzinfo=UTC) + timedelta(days=365 * 30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, None)
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


@pytest.fixture
def captured(monkeypatch):
    """httpx.Client construction kwargs, without constructing a client."""
    seen = {}

    class FakeClient:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(http_client.httpx, "Client", FakeClient)
    return seen


def test_default_verifies(captured):
    http_client.client("https://x", TlsConfig()).close()
    assert captured["verify"] is True


def test_verify_false_is_honoured(captured):
    http_client.client("https://x", TlsConfig(verify=False)).close()
    assert captured["verify"] is False


def test_ca_bundle_becomes_a_context_holding_exactly_that_anchor(captured):
    http_client.client("https://x", TlsConfig(ca_bundle=_test_ca_pem())).close()
    context = captured["verify"]
    assert isinstance(context, ssl.SSLContext)
    assert context.cert_store_stats()["x509_ca"] == 1


def test_client_cert_requires_both_cert_and_key_to_construct():
    """`ClientCert` has no partial state."""
    cert_pem, key_pem = _test_client_cert_and_key()
    with pytest.raises(ValidationError):
        ClientCert(cert=cert_pem)
    with pytest.raises(ValidationError):
        ClientCert(key=key_pem)


def test_client_cert_and_key_load_a_real_chain_into_the_ssl_context(captured):
    """`load_cert_chain` runs unmocked."""
    cert_pem, key_pem = _test_client_cert_and_key()
    tls = TlsConfig(client_cert=ClientCert(cert=cert_pem, key=key_pem))
    http_client.client("https://x", tls).close()
    assert isinstance(captured["verify"], ssl.SSLContext)


def test_client_cert_is_layered_onto_the_ca_bundle_context(captured):
    cert_pem, key_pem = _test_client_cert_and_key()
    tls = TlsConfig(ca_bundle=_test_ca_pem(), client_cert=ClientCert(cert=cert_pem, key=key_pem))
    http_client.client("https://x", tls).close()
    context = captured["verify"]
    assert isinstance(context, ssl.SSLContext)
    assert context.cert_store_stats()["x509_ca"] == 1


def test_client_cert_survives_verify_false(captured):
    cert_pem, key_pem = _test_client_cert_and_key()
    tls = TlsConfig(verify=False, client_cert=ClientCert(cert=cert_pem, key=key_pem))
    http_client.client("https://x", tls).close()
    context = captured["verify"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_client_cert_temp_files_do_not_survive_construction(monkeypatch, captured):
    """The PEM material is written to disk only for the width of `load_cert_chain`."""
    seen_paths: list[str] = []
    real_load_cert_chain = ssl.SSLContext.load_cert_chain

    def spy(self, certfile=None, keyfile=None, password=None):
        seen_paths.extend([certfile, keyfile])
        assert Path(certfile).exists()
        assert Path(keyfile).exists()
        return real_load_cert_chain(self, certfile=certfile, keyfile=keyfile, password=password)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", spy)

    cert_pem, key_pem = _test_client_cert_and_key()
    tls = TlsConfig(client_cert=ClientCert(cert=cert_pem, key=key_pem))
    http_client.client("https://x", tls).close()

    assert len(seen_paths) == 2
    assert not any(Path(p).exists() for p in seen_paths)


def test_client_cert_temp_files_are_removed_even_if_load_cert_chain_fails(monkeypatch, captured):
    """Cleanup runs in `finally`."""
    seen_paths: list[str] = []

    def failing(self, certfile=None, keyfile=None, password=None):
        seen_paths.extend([certfile, keyfile])
        raise ssl.SSLError("simulated failure")

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", failing)

    cert_pem, key_pem = _test_client_cert_and_key()
    tls = TlsConfig(client_cert=ClientCert(cert=cert_pem, key=key_pem))
    with pytest.raises(ssl.SSLError):
        http_client.client("https://x", tls)

    assert len(seen_paths) == 2
    assert not any(Path(p).exists() for p in seen_paths)


def test_the_client_key_file_is_removed_when_the_certificate_file_cannot_be_removed(monkeypatch, caplog):
    seen_paths: list[str] = []
    real_load_cert_chain = ssl.SSLContext.load_cert_chain
    real_unlink = Path.unlink

    def spy(self, certfile=None, keyfile=None, password=None):
        seen_paths.extend([certfile, keyfile])
        return real_load_cert_chain(self, certfile=certfile, keyfile=keyfile, password=password)

    def unlink(self, missing_ok=False):
        if "hst-tls-cert-" in self.name:
            raise PermissionError("simulated failure")
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", spy)
    monkeypatch.setattr(Path, "unlink", unlink)
    cert_pem, key_pem = _test_client_cert_and_key()
    try:
        with caplog.at_level(logging.ERROR, logger="hst.collectors.http"):
            http_client._load_client_cert(ssl.create_default_context(), cert_pem, key_pem)
    finally:
        monkeypatch.undo()
        cert_path, key_path = seen_paths
        key_left = Path(key_path).exists()
        Path(cert_path).unlink(missing_ok=True)
        Path(key_path).unlink(missing_ok=True)

    assert not key_left
    assert "hst-tls-cert-" in caplog.text


MIB = 1 << 20


class _Body(httpx.SyncByteStream):
    def __init__(self, pieces: int):
        self.pieces = pieces
        self.read = 0
        self.closed = False

    def __iter__(self):
        for _ in range(self.pieces):
            self.read += 1
            yield b"x" * MIB

    def close(self):
        self.closed = True


def _client(body: _Body, limit_mb: int) -> httpx.Client:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=body))
    with http_client.fetching("vco-1", limit_mb):
        return http_client.client("https://api.example", TlsConfig(), transport=transport)


def test_a_body_larger_than_the_answer_limit_stops_the_read_and_raises_answer_too_large():
    body = _Body(pieces=5)
    with _client(body, limit_mb=2) as client, pytest.raises(AnswerTooLarge) as raised:
        client.get("/big")
    assert str(raised.value) == (
        "the answer to GET api.example/big is larger than the answer limit of 2 MiB: "
        f"the read stopped after {3 * MIB} bytes"
    )
    assert body.read == 3
    assert body.closed


def test_a_body_as_large_as_the_answer_limit_is_read_whole():
    body = _Body(pieces=2)
    with _client(body, limit_mb=2) as client:
        assert len(client.get("/big").content) == 2 * MIB


def test_a_client_with_an_answer_limit_of_zero_reads_each_body_whole():
    body = _Body(pieces=3)
    with _client(body, limit_mb=0) as client:
        assert len(client.get("/big").content) == 3 * MIB


class _PlainCfg(SourceConfig):
    url: str


class _PlainCollector(Collector):
    name = "plain"
    ConfigModel = _PlainCfg

    def fetch(self):
        for _ in range(2):
            http_client.client(self.config.url, TlsConfig()).close()
        return {}

    def normalize(self, raw):
        raise NotImplementedError

    def probe(self) -> str:
        return "ok"


def _fetch_log(url: str, caplog) -> list[str]:
    collector = _PlainCollector(_PlainCfg(url=url, source_name="adc-1"), Settings(_env_file=None))
    with caplog.at_level(logging.WARNING, logger=http_client.logger.name):
        coll.fetch_traced(collector)
    return [record.getMessage() for record in caplog.records]


def test_a_fetch_over_plain_http_logs_one_warning_with_the_name_of_the_source(caplog):
    assert _fetch_log("http://192.0.2.10", caplog) == [
        "source adc-1: the credentials go to 192.0.2.10 over HTTP without TLS"
    ]


def test_a_fetch_over_https_logs_no_warning(caplog):
    assert _fetch_log("https://192.0.2.10", caplog) == []
