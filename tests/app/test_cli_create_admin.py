"""Bootstrapping the first admin account."""

from __future__ import annotations

import asyncio

import pytest
from tests.app.fakes import FakeStore
from typer.testing import CliRunner

from hst.app.security import hash_password, verify_password
from hst.cli import app

runner = CliRunner()
PASSWORD = "bootstrap-pw-99"


def run(coro):
    """`_with_store` calls asyncio.run(), which cannot nest, so these are sync tests."""
    return asyncio.run(coro)


@pytest.fixture
def store(monkeypatch):
    st = FakeStore()
    monkeypatch.setattr("hst.cli._open_store", lambda settings, **_: st)
    monkeypatch.delenv("HST_ADMIN_PASSWORD", raising=False)
    return st


def test_there_is_no_password_option(store):
    result = runner.invoke(app, ["user", "create-admin", "--password", PASSWORD])
    # 2 is click's usage error.
    assert result.exit_code == 2
    assert run(store.list_users()) == []


def test_non_interactive_creation(store, monkeypatch):
    monkeypatch.setenv("HST_ADMIN_PASSWORD", PASSWORD)
    result = runner.invoke(app, ["user", "create-admin", "--username", "ops"])
    assert result.exit_code == 0, result.stdout
    assert "admin ops created" in result.stdout

    user = run(store.get_user_by_username("ops"))
    assert user.role == "admin"
    assert verify_password(user.password_hash, PASSWORD)


def test_username_is_required_when_the_password_is_in_the_environment(store, monkeypatch):
    monkeypatch.setenv("HST_ADMIN_PASSWORD", PASSWORD)
    result = runner.invoke(app, ["user", "create-admin"])
    assert result.exit_code == 2
    assert "--username is required" in result.stdout


def test_a_short_password_is_refused_non_interactively_too(store, monkeypatch):
    """Both paths share MIN_PASSWORD_LENGTH."""
    monkeypatch.setenv("HST_ADMIN_PASSWORD", "elevenchars")
    result = runner.invoke(app, ["user", "create-admin", "--username", "ops"])
    assert result.exit_code == 2
    assert "must have 12 to 1024 characters" in result.stdout
    assert run(store.get_user_by_username("ops")) is None


def test_if_not_exists_leaves_an_existing_admin_completely_alone(store, monkeypatch):
    original = hash_password("the-real-admin-pw")
    run(store.create_user("ada", original, "admin"))

    monkeypatch.setenv("HST_ADMIN_PASSWORD", PASSWORD)
    result = runner.invoke(app, ["user", "create-admin", "--username", "ops", "--if-not-exists"])
    assert result.exit_code == 0
    assert "already exists" in result.stdout

    assert run(store.get_user_by_username("ops")) is None
    ada = run(store.get_user_by_username("ada"))
    assert ada.password_hash == original


def test_if_not_exists_creates_when_there_is_no_admin(store, monkeypatch):
    # a non-admin account must not count as one
    run(store.create_user("vera", hash_password("viewer-pw"), "viewer"))
    monkeypatch.setenv("HST_ADMIN_PASSWORD", PASSWORD)
    result = runner.invoke(app, ["user", "create-admin", "--username", "ops", "--if-not-exists"])
    assert result.exit_code == 0
    assert "admin ops created" in result.stdout
    assert run(store.get_user_by_username("ops")).role == "admin"


def test_a_duplicate_username_without_the_flag_fails(store, monkeypatch):
    run(store.create_user("ops", hash_password("x" * 10), "viewer"))
    monkeypatch.setenv("HST_ADMIN_PASSWORD", PASSWORD)
    result = runner.invoke(app, ["user", "create-admin", "--username", "ops"])
    assert result.exit_code == 1
