"""`hst device rekey`: the rename command of the device identity registry.
`_with_store` calls asyncio.run(), which cannot nest, so these are sync tests."""

import asyncio

from tests.app.fakes import FakeStore
from typer.testing import CliRunner

import hst.cli as cli

runner = CliRunner()


def _store(monkeypatch) -> FakeStore:
    store = FakeStore()
    asyncio.run(store.resolve_device("serial", "FOC1111AAAA", "switch", 1))
    monkeypatch.setattr(cli, "_with_store", lambda fn: asyncio.run(fn(store)))
    return store


def test_rekey_moves_the_uid_and_says_when_it_lands(monkeypatch):
    store = _store(monkeypatch)

    r = runner.invoke(cli.app, ["device", "rekey", "dev:switch-aaaa", "dev:access3"])

    assert r.exit_code == 0, r.output
    assert "The next run writes the new uid." in r.output
    assert asyncio.run(store.resolve_device("serial", "FOC1111AAAA", None, 2)) == "dev:access3"
    assert asyncio.run(store.identity_generation()) == 1


def test_rekey_refuses_a_uid_that_is_not_slugged(monkeypatch):
    store = _store(monkeypatch)

    for bad in ("access3", "dev:Access3", "dev:"):
        r = runner.invoke(cli.app, ["device", "rekey", "dev:switch-aaaa", bad])
        assert r.exit_code == 2, (bad, r.output)
    assert asyncio.run(store.identity_generation()) == 0


def test_rekey_refuses_an_unknown_or_a_taken_uid(monkeypatch):
    store = _store(monkeypatch)
    asyncio.run(store.resolve_device("serial", "FOC2222BBBB", "access3", 1))

    taken = runner.invoke(cli.app, ["device", "rekey", "dev:switch-aaaa", "dev:access3"])
    unknown = runner.invoke(cli.app, ["device", "rekey", "dev:nobody", "dev:somebody"])

    assert taken.exit_code == 1 and "taken" in taken.output
    assert unknown.exit_code == 1 and "no device has the uid" in unknown.output
    assert asyncio.run(store.identity_generation()) == 0


def test_rekey_merges_a_replaced_chassis_into_an_existing_uid(monkeypatch):
    store = _store(monkeypatch)
    asyncio.run(store.resolve_device("serial", "FOC2222BBBB", "switch", 2))

    plain = runner.invoke(cli.app, ["device", "rekey", "dev:switch-bbbb", "dev:switch-aaaa"])
    merged = runner.invoke(cli.app, ["device", "rekey", "dev:switch-bbbb", "dev:switch-aaaa", "--merge"])

    assert plain.exit_code == 1 and "taken" in plain.output
    assert merged.exit_code == 0, merged.output
    assert asyncio.run(store.resolve_device("serial", "FOC2222BBBB", None, 3)) == "dev:switch-aaaa"
