"""`hst serve` TLS validation."""

from __future__ import annotations

import pytest
import typer

from hst.cli import TlsFiles, _tls_kwargs_or_die
from hst.core import Settings


def test_neither_cert_nor_key_is_plaintext():
    settings = Settings(_env_file=None)
    assert _tls_kwargs_or_die(settings) == TlsFiles()


def test_cert_and_key_yield_ssl_kwargs(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    settings = Settings(_env_file=None, tls_cert_file=str(cert), tls_key_file=str(key))
    assert _tls_kwargs_or_die(settings) == TlsFiles(certfile=str(cert), keyfile=str(key))


def test_key_password_file_is_read_and_stripped(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    password_file = tmp_path / "key-pass"
    password_file.write_text("hunter2\n")
    settings = Settings(
        _env_file=None,
        tls_cert_file=str(cert),
        tls_key_file=str(key),
        tls_key_password_file=str(password_file),
    )
    tls = _tls_kwargs_or_die(settings)
    assert tls.keyfile_password == "hunter2"


def test_cert_without_key_fails_fast(tmp_path):
    cert = tmp_path / "cert.pem"
    cert.write_text("cert")
    settings = Settings(_env_file=None, tls_cert_file=str(cert))
    with pytest.raises(typer.Exit):
        _tls_kwargs_or_die(settings)


def test_key_without_cert_fails_fast(tmp_path):
    key = tmp_path / "key.pem"
    key.write_text("key")
    settings = Settings(_env_file=None, tls_key_file=str(key))
    with pytest.raises(typer.Exit):
        _tls_kwargs_or_die(settings)
