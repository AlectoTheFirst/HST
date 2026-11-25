"""`hst worker`: the command that runs the scheduler and the executor without
the HTTP server."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from hst.app.crypto import generate_key
from hst.cli import app
from hst.core import Settings
from hst.worker import runtime

runner = CliRunner()


@pytest.fixture
def env(monkeypatch, tmp_path):
    # No .env from the working directory: the environment below is all there is.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HST_SECRET_KEY", generate_key())
    monkeypatch.setenv("HST_DATA_DIR", str(tmp_path / "data"))
    started: list[Settings] = []
    monkeypatch.setattr(runtime, "main", started.append)
    return started


def test_the_command_runs_the_worker_with_the_settings(env, tmp_path):
    result = runner.invoke(app, ["worker"])
    assert result.exit_code == 0, result.stdout
    (settings,) = env
    assert isinstance(settings, Settings)
    assert settings.hst_data_dir == tmp_path / "data"
    assert "scheduler and executor, no HTTP server" in result.stdout
    # the operator key unwrapped (here: created) the data key before the loops started
    assert (tmp_path / "data" / "dek.wrapped").is_file()


def test_the_command_refuses_to_start_without_an_operator_key(env, monkeypatch):
    monkeypatch.delenv("HST_SECRET_KEY")
    result = runner.invoke(app, ["worker"])
    assert result.exit_code == 1
    assert "HST_SECRET_KEY" in result.stdout
    assert env == []


def test_the_command_is_listed():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "worker" in result.stdout
