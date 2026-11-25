"""`hst prune`: the scheduled graph prune, run by hand.

The command calls `worker.maintenance.prune_graph` with the Keep the scheduled
sweep would use (the stored Lifecycle values over the environment), takes the
cycle lock inside that function, and exits 1 when a
collection holds the lock. `prune_graph` itself is replaced by a recorder here;
tests/test_retention_sequence.py runs the real sweeps.
"""

import asyncio

import pytest
from typer.testing import CliRunner

pytest.importorskip("sqlalchemy")

import hst.cli as cli
from hst.app import retention
from hst.app.store import AppSetting
from hst.core import Settings
from hst.core import cycle as cyclemod
from hst.worker import maintenance

runner = CliRunner()


class _Store:
    def __init__(self, stored=None):
        self.stored = stored

    async def retained_snapshot_refs(self):
        return []

    async def get_setting(self, key):
        assert key == retention.SETTINGS_KEY
        if self.stored is None:
            return None
        from datetime import UTC, datetime

        return AppSetting(key=key, value=self.stored, secrets=b"", updated_at=datetime.now(UTC))


@pytest.fixture
def prune(monkeypatch, tmp_path):
    class State:
        settings = Settings(
            _env_file=None, hst_data_dir=tmp_path, cycle_keep_runs=30, cycle_keep_device_runs=48
        )
        store = _Store()
        result: list[int] | None = []
        keeps: list = []
        hold_lock: list = []

    state = State()
    state.keeps = []
    state.hold_lock = []
    monkeypatch.setattr(cli, "Settings", lambda: state.settings)

    def store_read(settings, callback, *, hold_lock=True):
        state.hold_lock.append(hold_lock)
        return asyncio.run(callback(state.store))

    async def prune_graph(settings, store, keep):
        state.keeps.append(keep)
        return state.result

    monkeypatch.setattr(cli, "_assessment_store_read", store_read)
    monkeypatch.setattr(maintenance, "prune_graph", prune_graph)
    return state


def test_the_keep_is_the_environment_when_nothing_is_stored(prune):
    r = runner.invoke(cli.app, ["prune"])

    assert r.exit_code == 0, r.output
    assert prune.keeps == [cyclemod.Keep(30, 48)]


def test_the_keep_is_the_stored_lifecycle_value_over_the_environment(prune):
    prune.store = _Store({"cycle_keep_runs": 7, "cycle_keep_device_runs": 9})

    r = runner.invoke(cli.app, ["prune"])

    assert r.exit_code == 0, r.output
    assert prune.keeps == [cyclemod.Keep(7, 9)]


def test_keep_replaces_only_the_cycle_count(prune):
    prune.store = _Store({"cycle_keep_runs": 7, "cycle_keep_device_runs": 9})

    r = runner.invoke(cli.app, ["prune", "--keep", "3"])

    assert r.exit_code == 0, r.output
    assert prune.keeps == [cyclemod.Keep(3, 9)]


def test_the_prune_takes_the_cycle_lock_itself(prune):
    runner.invoke(cli.app, ["prune"])

    assert prune.hold_lock == [False]


def test_the_deleted_runs_are_listed(prune):
    prune.result = [5, 3]

    r = runner.invoke(cli.app, ["prune"])

    assert r.exit_code == 0, r.output
    assert "deleted 2 run(s)" in r.output
    assert "5, 3" in r.output


def test_nothing_deleted_says_so(prune):
    prune.result = []

    r = runner.invoke(cli.app, ["prune"])

    assert r.exit_code == 0, r.output
    assert "nothing to delete" in r.output


def test_a_collection_holding_the_cycle_lock_ends_the_command_with_exit_1(prune):
    prune.result = None

    r = runner.invoke(cli.app, ["prune"])

    assert r.exit_code == 1
    assert "A collection holds the cycle lock; nothing was pruned" in r.output
    assert "deleted" not in r.output


def test_a_store_that_cannot_be_read_stops_the_command(prune, monkeypatch):
    def down(settings, callback, *, hold_lock=True):
        raise RuntimeError("missing store")

    monkeypatch.setattr(cli, "_assessment_store_read", down)

    r = runner.invoke(cli.app, ["prune"])

    assert r.exit_code == 1
    assert "retention state" in r.output
    assert "RuntimeError" in r.output
    assert prune.keeps == []
