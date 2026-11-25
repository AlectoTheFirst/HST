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
    monkeypatch.setenv("HST_DATA_DIR", str(tmp_path))
    return store


def _secrets(tmp_path, row) -> dict:
    key = dek(Settings(_env_file=None, hst_secret_key=KEY, hst_data_dir=tmp_path))
    return decrypt_secrets(key, row.secrets)


def test_add_and_set_read_the_config_from_standard_input(fake, tmp_path):
    r = runner.invoke(
        cli.app,
        ["sources", "add", "home", "--type", "unifi", "--config", "-"],
        input='{"url": "https://c", "auth": {"username": "ro", "password": "pw1"}}',
    )
    assert r.exit_code == 0, r.output
    assert fake.sources["home"].config["url"] == "https://c"
    assert _secrets(tmp_path, fake.sources["home"]) == {"auth.password": "pw1"}

    r = runner.invoke(
        cli.app, ["sources", "set", "home", "--config", "-"], input='{"auth": {"password": "pw2"}}'
    )
    assert r.exit_code == 0, r.output
    assert _secrets(tmp_path, fake.sources["home"]) == {"auth.password": "pw2"}
