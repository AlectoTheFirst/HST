"""Fernet round-trip for source secrets; wrong key must fail with guidance."""

import base64
import hashlib
import hmac

import pytest
from cryptography.fernet import Fernet

from hst.app.crypto import (
    SecretKeyError,
    decrypt_secrets,
    dek,
    encrypt_secrets,
    install_dek,
    package_key,
)
from hst.core import Settings


def _data_key() -> str:
    """A data key (DEK) as crypto.dek() would hand out."""
    return Fernet.generate_key().decode()


def test_round_trip():
    key = _data_key()
    blob = encrypt_secrets(key, {"password": "hunter22", "token": "abc"})
    assert isinstance(blob, bytes) and b"hunter22" not in blob
    assert decrypt_secrets(key, blob) == {"password": "hunter22", "token": "abc"}


def test_empty_blob_is_no_secrets():
    assert decrypt_secrets(_data_key(), b"") == {}


def test_wrong_or_missing_key_names_the_fix():
    blob = encrypt_secrets(_data_key(), {"password": "x"})
    for bad in (_data_key(), ""):
        with pytest.raises(SecretKeyError, match="HST_SECRET_KEY"):
            decrypt_secrets(bad, blob)


def test_tampered_blob_fails():
    key = _data_key()
    blob = bytearray(encrypt_secrets(key, {"password": "x"}))
    blob[-1] ^= 0xFF
    with pytest.raises(SecretKeyError):
        decrypt_secrets(key, bytes(blob))


def test_package_key_is_hkdf_sha256_of_the_data_key_with_the_package_identity():
    key = _data_key()
    identity = "0123456789abcdef0123456789abcdef"
    extracted = hmac.new(b"strata-reticulum", base64.urlsafe_b64decode(key), hashlib.sha256).digest()
    info = b"assessment-package-v1:" + identity.encode()
    expanded = hmac.new(extracted, info + b"\x01", hashlib.sha256).digest()
    assert package_key(key, identity) == base64.urlsafe_b64encode(expanded).decode()


def test_package_key_opens_only_what_it_sealed():
    key = _data_key()
    first, second = package_key(key, "0" * 32), package_key(key, "1" * 32)
    assert len({key, first, second}) == 3
    blob = encrypt_secrets(first, {"password": "x"})
    assert decrypt_secrets(first, blob) == {"password": "x"}
    for other in (second, key):
        with pytest.raises(SecretKeyError):
            decrypt_secrets(other, blob)
    with pytest.raises(SecretKeyError):
        decrypt_secrets(first, encrypt_secrets(key, {"password": "x"}))


@pytest.mark.parametrize("identity", ["", "0" * 31, "A" * 32, "0" * 32 + "\n", "../" + "0" * 29])
def test_package_key_refuses_a_malformed_package_identity(identity):
    with pytest.raises(ValueError, match="package identity"):
        package_key(_data_key(), identity)


def test_package_key_refuses_a_malformed_data_key():
    with pytest.raises(SecretKeyError):
        package_key("short", "0" * 32)


def test_install_dek_writes_the_key_once_and_keeps_an_existing_dek(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key="k" * 40)
    key = _data_key()
    install_dek(settings, key)
    assert dek(settings) == key
    assert (tmp_path / "dek.wrapped").stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        install_dek(settings, _data_key())
    assert dek(settings) == key


def test_install_dek_refuses_a_malformed_key_and_a_missing_operator_key(tmp_path):
    with pytest.raises(SecretKeyError):
        install_dek(Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key="k" * 40), "short")
    with pytest.raises(SecretKeyError):
        install_dek(Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=""), _data_key())
    assert not (tmp_path / "dek.wrapped").exists()
