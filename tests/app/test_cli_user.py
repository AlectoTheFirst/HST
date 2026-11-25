"""CLI user commands against the fake store (PgStore construction is monkeypatched)."""

import pytest
from tests.app.fakes import FakeStore
from typer.testing import CliRunner

import hst.cli as cli

runner = CliRunner()


@pytest.fixture
def fake(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(cli, "_open_store", lambda settings, **_: store)
    return store


def test_create_admin_and_duplicate(fake):
    r = runner.invoke(cli.app, ["user", "create-admin"], input="ada\nhunter22-long\nhunter22-long\n")
    assert r.exit_code == 0, r.output
    u = fake.users[1]
    assert (u.username, u.role) == ("ada", "admin") and u.password_hash != "hunter22-long"
    r = runner.invoke(cli.app, ["user", "create-admin"], input="ada\nhunter22-long\nhunter22-long\n")
    assert r.exit_code == 1


def test_add_role_disable(fake):
    runner.invoke(cli.app, ["user", "create-admin"], input="root\nhunter22-long\nhunter22-long\n")
    r = runner.invoke(
        cli.app, ["user", "add", "vera", "--role", "viewer"], input="viewerpass-12\nviewerpass-12\n"
    )
    assert r.exit_code == 0, r.output
    r = runner.invoke(cli.app, ["user", "role", "vera", "operator"])
    assert r.exit_code == 0
    r = runner.invoke(cli.app, ["user", "disable", "vera"])
    assert r.exit_code == 0
    vera = next(u for u in fake.users.values() if u.username == "vera")
    assert (vera.role, vera.disabled) == ("operator", True)
    assert runner.invoke(cli.app, ["user", "role", "ghost", "admin"]).exit_code == 1


def test_enable_local_login_turns_the_setting_on(fake):
    import asyncio

    from hst.app import sso_flow

    asyncio.run(fake.put_setting(sso_flow.LOCAL_LOGIN_KEY, {"enabled": False}, b""))
    r = runner.invoke(cli.app, ["user", "enable-local-login"])
    assert r.exit_code == 0, r.output
    assert asyncio.run(sso_flow.local_login_enabled(fake)) is True


def test_add_refuses_a_username_or_a_password_above_the_login_bounds(fake):
    from hst.app.security import MAX_PASSWORD_LENGTH, MAX_USERNAME_LENGTH

    r = runner.invoke(cli.app, ["user", "add", "u" * (MAX_USERNAME_LENGTH + 1)], input="viewerpass-12\n" * 2)
    assert r.exit_code == 1
    long_password = "p" * (MAX_PASSWORD_LENGTH + 1)
    r = runner.invoke(cli.app, ["user", "add", "vera"], input=f"{long_password}\n{long_password}\n")
    assert r.exit_code == 1
    assert fake.users == {}
