"""`hst rotate-secret-key`: re-wraps the data key under a new operator key."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from hst.app.crypto import (
    SecretKeyError,
    decrypt_secrets,
    dek,
    encrypt_secrets,
    generate_key,
)
from hst.cli import app
from hst.core import Settings

runner = CliRunner()

KEY = generate_key()


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("HST_SECRET_KEY", KEY)
    monkeypatch.setenv("HST_DATA_DIR", str(tmp_path))
    return tmp_path


def _settings(tmp_path, key) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=key)


def test_rotation_prints_the_generated_key_and_rewraps(env):
    original = dek(_settings(env, KEY))
    blob = encrypt_secrets(original, {"password": "s3cret"})

    result = runner.invoke(app, ["rotate-secret-key"])
    assert result.exit_code == 0, result.stdout
    assert "re-wrapped" in result.stdout

    new_key = result.stdout.strip().splitlines()[0].strip()
    assert new_key and new_key != KEY
    # same data key under the new operator key: stored data needs no rewrite
    assert dek(_settings(env, new_key)) == original
    assert decrypt_secrets(dek(_settings(env, new_key)), blob) == {"password": "s3cret"}
    # the old operator key is dead immediately
    with pytest.raises(SecretKeyError):
        dek(_settings(env, KEY))


def test_rotation_from_a_file_does_not_print_the_key(env, tmp_path):
    original = dek(_settings(env, KEY))
    new_key = generate_key()
    key_file = tmp_path / "new-kek"
    key_file.write_text(new_key + "\n")

    result = runner.invoke(app, ["rotate-secret-key", "--new-key-file", str(key_file)])
    assert result.exit_code == 0, result.stdout
    assert new_key not in result.stdout
    assert dek(_settings(env, new_key)) == original


def test_rotation_without_a_current_key_is_a_clean_error(env, monkeypatch):
    monkeypatch.delenv("HST_SECRET_KEY")
    result = runner.invoke(app, ["rotate-secret-key"])
    assert result.exit_code == 1
    assert "HST_SECRET_KEY" in result.stdout
    assert "Traceback" not in result.stdout
