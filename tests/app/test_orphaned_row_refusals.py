"""A source's deletion refuses while a run of it is in flight, and a
'running' row whose claim no process holds is no run in flight: the
orphaned-run sweep closes it first (`store.live_run`), so the deletion goes
through, from the API and from `hst sources remove` alike."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from typer.testing import CliRunner

import hst.cli as cli
from hst.app.crypto import generate_key
from hst.app.main import create_app
from hst.core import Settings

KEY = generate_key()


async def _orphan(store: FakeStore, source: str) -> int:
    run = await store.start_run(source, datetime.now(UTC) - timedelta(minutes=30))
    assert run is not None
    store.crash()
    return run.id


async def test_the_api_deletes_a_source_whose_running_row_has_no_run(seeded):
    await seeded.create_source("unifi", "unifi", {}, b"")
    stale = await _orphan(seeded, "unifi")
    app = create_app(settings=Settings(_env_file=None, hst_secret_key=KEY), store=seeded)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "ada")
        r = await client.delete("/api/sources/unifi")

    assert r.status_code == 200, r.text
    assert await seeded.get_source("unifi") is None
    row = await seeded.get_run(stale)
    assert row is not None and row.status != "running"


async def test_the_api_refuses_while_a_run_holds_its_claim(seeded):
    await seeded.create_source("unifi", "unifi", {}, b"")
    run = await seeded.start_run("unifi", datetime.now(UTC))
    assert run is not None
    app = create_app(settings=Settings(_env_file=None, hst_secret_key=KEY), store=seeded)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "ada")
        r = await client.delete("/api/sources/unifi")

    assert r.status_code == 409
    assert await seeded.get_source("unifi") is not None


def test_the_cli_removes_a_source_whose_running_row_has_no_run(monkeypatch, tmp_path):
    import asyncio

    store = FakeStore()
    monkeypatch.setattr(cli, "_open_store", lambda settings, **_: store)
    monkeypatch.setenv("HST_SECRET_KEY", KEY)
    monkeypatch.setenv("HST_DATA_DIR", str(tmp_path))

    async def seed() -> int:
        await store.create_source("unifi", "unifi", {}, b"")
        return await _orphan(store, "unifi")

    stale = asyncio.run(seed())
    r = CliRunner().invoke(cli.app, ["sources", "remove", "unifi"])

    assert r.exit_code == 0, r.output
    assert "unifi" not in store.sources
    assert store.runs[stale].status != "running"
