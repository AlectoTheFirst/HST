"""The compatibility CLI uses revisioned inventory intent."""

import asyncio

from tests.app.test_inventory_legacy_api import activated
from typer.testing import CliRunner

from hst import cli


async def test_activated_sources_set_cli_creates_profile_revision(tmp_path, monkeypatch):
    rig, settings = await activated(tmp_path)
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    monkeypatch.setattr(cli, "_open_store", lambda settings, **_: rig.store)
    result = await asyncio.to_thread(
        CliRunner().invoke, cli.app, ["sources", "set", "lab", "--config", '{"interval_s": 180}']
    )
    assert result.exit_code == 0, result.output
    async with rig.repo.transaction() as tx:
        source = await tx.get_source_inventory_by_key("lab")
        profile = await tx.get_profile(source.default_profile_id)
        version = await tx.get_profile_version(profile.id, profile.current_revision)
        assert version.settings["interval_s"] == 180
    assert "interval_s" not in (await rig.store.get_source("lab")).config
