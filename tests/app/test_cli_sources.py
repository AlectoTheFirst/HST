"""CLI source management against the fake store (PgStore monkeypatched away)."""

import asyncio

import pytest
from tests.app.fakes import FakeStore
from typer.testing import CliRunner

import hst.cli as cli
from hst.app.crypto import decrypt_secrets, dek, generate_key
from hst.core import Settings

runner = CliRunner()
KEY = generate_key()


@pytest.fixture
def fake(monkeypatch, tmp_path):
    store = FakeStore()
    monkeypatch.setattr(cli, "_open_store", lambda settings, **_: store)
    monkeypatch.setenv("HST_SECRET_KEY", KEY)
    # the CLI unwraps (or creates) the data key under HST_DATA_DIR, here tmp_path
    monkeypatch.setenv("HST_DATA_DIR", str(tmp_path))
    return store


def _dek(tmp_path) -> str:
    """The same data key the CLI under test created in tmp_path."""
    return dek(Settings(_env_file=None, hst_secret_key=KEY, hst_data_dir=tmp_path))


def test_add_list_test_remove(fake):
    r = runner.invoke(
        cli.app, ["sources", "add", "seed1", "--type", "manual", "--config", '{"devices": "r1, 10.0.0.1"}']
    )
    assert r.exit_code == 0, r.output
    assert fake.sources["seed1"].type == "manual"
    r = runner.invoke(cli.app, ["sources", "list"])
    assert "seed1" in r.output and "manual" in r.output
    r = runner.invoke(cli.app, ["sources", "test", "seed1"])
    assert r.exit_code == 0 and "1 device" in r.output
    r = runner.invoke(cli.app, ["sources", "remove", "seed1"])
    assert r.exit_code == 0 and not fake.sources


def test_add_prompts_hidden_for_secrets(fake, tmp_path):
    r = runner.invoke(
        cli.app,
        [
            "sources",
            "add",
            "home",
            "--type",
            "unifi",
            "--config",
            '{"url": "https://c", "auth": {"username": "ro"}}',
        ],
        input="pw1\npw1\n",
    )
    assert r.exit_code == 0, r.output
    row = fake.sources["home"]
    assert "password" not in row.config
    assert decrypt_secrets(_dek(tmp_path), row.secrets) == {"auth.password": "pw1"}


def test_bad_config_is_a_clean_error(fake):
    r = runner.invoke(
        cli.app, ["sources", "add", "x1", "--type", "unifi", "--config", '{"user": "ro"}'], input="pw\npw\n"
    )
    assert r.exit_code == 1
    assert "url" in r.output and "Traceback" not in r.output


def test_short_secret_key_is_a_clean_error(fake, monkeypatch):
    monkeypatch.setenv("HST_SECRET_KEY", "too-short")
    r = runner.invoke(cli.app, ["sources", "add", "seed2", "--type", "manual", "--config", '{"devices": ""}'])
    assert r.exit_code == 1
    assert "HST_SECRET_KEY" in r.output
    assert "Traceback" not in r.output


def test_wrong_secret_key_on_set_is_a_clean_error(fake, monkeypatch, tmp_path):
    _dek(tmp_path)  # creates dek.wrapped under KEY
    asyncio.run(fake.create_source("seed3", "manual", {"devices": ""}, b""))
    monkeypatch.setenv("HST_SECRET_KEY", generate_key())  # valid length, wrong key
    r = runner.invoke(cli.app, ["sources", "set", "seed3", "--config", '{"devices": "x, 10.0.0.1"}'])
    assert r.exit_code == 1
    assert "HST_SECRET_KEY" in r.output
    assert "Traceback" not in r.output


def test_add_reasoner_is_reserved(fake):
    r = runner.invoke(
        cli.app, ["sources", "add", "reasoner", "--type", "manual", "--config", '{"devices": ""}']
    )
    assert r.exit_code == 1
    assert "reserved" in r.output
    assert "reasoner" not in fake.sources


def test_add_bad_name_is_a_clean_error_no_prompt(fake):
    r = runner.invoke(
        cli.app, ["sources", "add", "Bad Name!", "--type", "manual", "--config", '{"devices": ""}'], input=""
    )
    assert r.exit_code == 1
    assert "Bad Name!" not in fake.sources
    assert not fake.sources


def test_unpin_clears_device_and_bastion_pins(fake):
    asyncio.run(
        fake.create_source(
            "r1",
            "nxos",
            {
                "host": "h",
                "host_key": "ssh-ed25519 DEV",
                "jump_host": {"host": "b", "host_key": "ssh-ed25519 BAST"},
            },
            b"",
        )
    )
    r = runner.invoke(cli.app, ["sources", "unpin", "r1"])
    assert r.exit_code == 0, r.output
    config = fake.sources["r1"].config
    assert config["host_key"] == "" and config["jump_host"]["host_key"] == ""


def test_unpin_without_pins_says_so(fake):
    asyncio.run(fake.create_source("r2", "manual", {"devices": ""}, b""))
    r = runner.invoke(cli.app, ["sources", "unpin", "r2"])
    assert r.exit_code == 0 and "nothing pinned" in r.output
