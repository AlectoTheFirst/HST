"""Postgres TLS engine wiring: connect_args through pg.py, with no live
database."""

from __future__ import annotations

import ssl
from datetime import UTC, datetime, timedelta

import pytest

from hst.app.store import pg as pgmod
from hst.app.store.pg import PgStore, pg_ssl_engine_kwargs

DSN = "postgresql+asyncpg://u:p@localhost:5432/db"


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


@pytest.fixture
def ca_file(tmp_path) -> str:
    p = tmp_path / "ca.pem"
    p.write_text(_test_ca_pem())
    return str(p)


# --- pg_ssl_engine_kwargs ---------------------------------------------------


def test_no_ca_file_yields_no_ssl_connect_arg():
    assert pg_ssl_engine_kwargs("") == {}


def test_ca_file_yields_a_verified_ssl_context_with_exactly_that_anchor(ca_file):
    kwargs = pg_ssl_engine_kwargs(ca_file)
    ctx = kwargs["connect_args"]["ssl"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.cert_store_stats()["x509_ca"] == 1


# --- PgStore: both engines share the same kwargs ---------------------------


@pytest.fixture
def captured_engine_kwargs(monkeypatch):
    """create_async_engine calls in pg.py, without constructing a real engine."""
    seen: list[dict] = []

    def fake(url, **kwargs):
        seen.append(kwargs)
        return object()

    monkeypatch.setattr(pgmod, "create_async_engine", fake)
    return seen


def test_pgstore_default_has_no_ssl_connect_arg(captured_engine_kwargs):
    PgStore(DSN)
    assert len(captured_engine_kwargs) == 2  # pool engine + claims engine
    assert all("connect_args" not in kw for kw in captured_engine_kwargs)


def test_pgstore_threads_ca_file_into_both_engines(captured_engine_kwargs, ca_file):
    PgStore(DSN, ca_file)
    assert len(captured_engine_kwargs) == 2
    for kw in captured_engine_kwargs:
        assert isinstance(kw["connect_args"]["ssl"], ssl.SSLContext)


# --- schema_is_current -------------------------------------------------------


def test_schema_is_current_threads_ca_file(monkeypatch, ca_file):
    class _Boom(Exception):
        pass

    seen: list[dict] = []

    def fake(url, **kwargs):
        seen.append(kwargs)
        raise _Boom

    monkeypatch.setattr(pgmod, "create_async_engine", fake)
    with pytest.raises(_Boom):
        pgmod.schema_is_current(DSN, ca_file)
    assert isinstance(seen[0]["connect_args"]["ssl"], ssl.SSLContext)


def test_schema_is_current_default_has_no_ssl_connect_arg(monkeypatch):
    class _Boom(Exception):
        pass

    seen: list[dict] = []

    def fake(url, **kwargs):
        seen.append(kwargs)
        raise _Boom

    monkeypatch.setattr(pgmod, "create_async_engine", fake)
    with pytest.raises(_Boom):
        pgmod.schema_is_current(DSN)
    assert "connect_args" not in seen[0]


# --- upgrade_to_head: the Alembic path shares the helper via config.attributes


def test_upgrade_to_head_threads_ca_file_via_alembic_attributes(monkeypatch, ca_file):
    seen = {}

    def fake_upgrade(cfg, rev):
        seen["ca_file"] = cfg.attributes.get("postgres_ca_file")

    monkeypatch.setattr(pgmod.command, "upgrade", fake_upgrade)
    pgmod.upgrade_to_head(DSN, ca_file)
    assert seen["ca_file"] == ca_file


def test_upgrade_to_head_default_ca_file_is_empty(monkeypatch):
    seen = {}

    def fake_upgrade(cfg, rev):
        seen["ca_file"] = cfg.attributes.get("postgres_ca_file")

    monkeypatch.setattr(pgmod.command, "upgrade", fake_upgrade)
    pgmod.upgrade_to_head(DSN)
    assert seen["ca_file"] == ""
