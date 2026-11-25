"""`hst sidestore prune`: the scheduled side-store prune, run by hand."""

import asyncio
import contextlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

pytest.importorskip("pyarrow")
pytest.importorskip("sqlalchemy")

import hst.cli as cli
from hst.core import Settings, sidestore
from hst.core import manifest as manifestmod
from hst.worker import maintenance

runner = CliRunner()


def _rib_row() -> dict:
    return {
        "device_uid": "dev:r1",
        "vrf": "default",
        "context_uid": None,
        "prefix": "0.0.0.0/0",
        "next_hop": "10.0.0.1",
        "interface": "eth0",
        "protocol": "static",
        "metric": 1,
        "af": 4,
        "prefixlen": 0,
        "lo": b"\x00" * 16,
        "hi": b"\xff" * 16,
    }


def _mac_row() -> dict:
    return {"device_uid": "dev:m1", "vlan": 10, "mac": "00:11:22:33:44:55", "port_name": "eth0"}


def _write(base, table, source, host, run_id, snapshot_ts):
    """One realistic parquet file at the nested layout, stamped with a real
    `snapshot_ts`."""
    row = _rib_row() if table == "rib" else _mac_row()
    path = sidestore.write_table(base, table, source, host, run_id, [row], snapshot_ts)
    assert path is not None
    return path


def _manifest(settings, key, devices=()):
    manifestmod.write(
        settings,
        manifestmod.SnapshotManifest(
            snapshot_key=key,
            kind="full",
            opened=manifestmod.iso(key),
            published=manifestmod.now_iso(),
            devices=list(devices),
        ),
    )


class _Store:
    """The slice of the Postgres store the sweep reads."""

    def __init__(self, refs=(), leased=(), locked=False, stored=None):
        self.stored = stored
        self.refs = list(refs)
        self.leased = set(leased)
        self.locked = locked

    async def retained_snapshot_refs(self):
        return self.refs

    async def leased_runs(self):
        return self.leased

    async def get_setting(self, key):
        """The Settings -> Lifecycle document, when `stored` is set."""
        if self.stored is None:
            return None
        from hst.app.store import AppSetting

        return AppSetting(key=key, value=self.stored, secrets=b"", updated_at=datetime.now(UTC))

    @asynccontextmanager
    async def try_cycle_lock(self):
        yield not self.locked


@pytest.fixture
def estate(monkeypatch, tmp_path):
    """Settings under tmp_path, with `retained_runs` answering `estate.kept` and
    recording the limits it is asked for."""

    class Estate:
        settings = Settings(_env_file=None, hst_data_dir=tmp_path)
        kept: list[int] = []
        store = _Store()
        asked: list = []
        down: Exception | None = None

    state = Estate()
    monkeypatch.setattr(cli, "Settings", lambda: state.settings)

    def retained_runs(session, keep):
        state.asked.append(keep)
        return list(state.kept)

    monkeypatch.setattr(maintenance, "_session", contextlib.contextmanager(lambda settings: iter([object()])))
    monkeypatch.setattr(maintenance.cyclemod, "retained_runs", retained_runs)

    def store_read(settings, callback, *, hold_lock=True):
        # the prune takes the cycle lock itself, on a connection of its own
        assert hold_lock is False
        if state.down is not None:
            raise state.down
        return asyncio.run(callback(state.store))

    monkeypatch.setattr(cli, "_assessment_store_read", store_read)
    return state


def test_missing_store_prints_nothing_to_prune(estate, tmp_path):
    estate.settings = Settings(_env_file=None, hst_data_dir=tmp_path / "absent")
    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "2"])
    assert r.exit_code == 0, r.output
    assert "nothing to prune" in r.output


def test_empty_store_prints_nothing_to_prune(estate):
    estate.settings.sidestore_dir.mkdir(parents=True, exist_ok=True)
    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "2"])
    assert r.exit_code == 0, r.output
    assert "nothing to prune" in r.output


def test_dry_run_reports_what_the_scheduled_prune_would_delete_and_deletes_nothing(estate):
    pytest.importorskip("duckdb")
    base = estate.settings.sidestore_dir
    for ts, hexid in [(1000, "aaaaaaaa"), (2000, "bbbbbbbb"), (3000, "cccccccc")]:
        _write(base, "rib", "nxos", "h1", f"{ts}-{hexid}", ts)
    estate.kept = [3000, 2000]
    _manifest(estate.settings, 3000)
    _manifest(estate.settings, 2000)

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "2"])

    assert r.exit_code == 0, r.output
    assert "would delete rib/nxos/h1/1000-aaaaaaaa.parquet" in r.output
    assert "2000-bbbbbbbb" not in r.output
    assert "3000-cccccccc" not in r.output
    assert "would delete 1 file(s)" in r.output
    assert "--yes" in r.output
    assert len(list(base.rglob("*.parquet"))) == 3


def test_yes_keeps_every_file_a_retained_run_reads_not_the_newest_n_per_directory(estate):
    pytest.importorskip("duckdb")
    base = estate.settings.sidestore_dir
    for ts, hexid in [(1000, "aaaaaaaa"), (2000, "bbbbbbbb"), (3000, "cccccccc")]:
        _write(base, "rib", "nxos", "h1", f"{ts}-{hexid}", ts)
    _write(base, "mac", "nxos", "h1", "1000-ffffffff", 1000)
    (base / ".query-catalog.duckdb").touch()
    estate.kept = [3000, 2000]
    _manifest(estate.settings, 3000)
    _manifest(estate.settings, 2000)

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "1", "--yes"])

    assert r.exit_code == 0, r.output
    assert "deleting mac/nxos/h1/1000-ffffffff.parquet" in r.output
    assert "deleting rib/nxos/h1/1000-aaaaaaaa.parquet" in r.output
    assert "deleted 2 file(s)" in r.output
    assert not (base / "rib" / "nxos" / "h1" / "1000-aaaaaaaa.parquet").exists()
    assert (base / "rib" / "nxos" / "h1" / "2000-bbbbbbbb.parquet").exists()
    assert (base / "rib" / "nxos" / "h1" / "3000-cccccccc.parquet").exists()
    assert (base / ".query-catalog.duckdb").exists()


def test_a_file_a_retained_manifest_binds_is_kept_whatever_its_age(estate):
    """A device carried forward through the whole window is never rewritten: only
    the `devices` list of a retained run's manifest says its file is still read."""
    pytest.importorskip("duckdb")
    base = estate.settings.sidestore_dir
    bound = _write(base, "rib", "nxos", "h1", "1000-aaaaaaaa", 1000)
    loose = _write(base, "rib", "nxos", "h2", "1000-bbbbbbbb", 1000)
    estate.kept = [3000]
    _manifest(
        estate.settings,
        3000,
        devices=[
            manifestmod.DeviceEntry(
                source="nxos", host="h1", outcome="carried", effective_run="1000-aaaaaaaa", carried=True
            )
        ],
    )

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "1", "--yes"])

    assert r.exit_code == 0, r.output
    assert bound.exists()
    assert not loose.exists()


def test_the_run_of_a_retained_assessment_and_a_run_a_reader_holds_are_kept(estate):
    pytest.importorskip("duckdb")
    base = estate.settings.sidestore_dir
    pinned = _write(base, "rib", "nxos", "h1", "1000-aaaaaaaa", 1000)
    leased = _write(base, "rib", "nxos", "h1", "2000-bbbbbbbb", 2000)
    loose = _write(base, "rib", "nxos", "h1", "1500-cccccccc", 1500)
    estate.kept = [3000]
    estate.store = _Store(refs=[{"snapshot": "1000"}], leased=[2000])
    for key in (1000, 2000, 3000):
        _manifest(estate.settings, key)

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "1", "--yes"])

    assert r.exit_code == 0, r.output
    assert pinned.exists() and leased.exists()
    assert not loose.exists()


def test_a_run_without_a_manifest_protects_the_files_up_to_its_key(estate):
    """What its carried devices stand on cannot be named, so nothing older goes."""
    pytest.importorskip("duckdb")
    base = estate.settings.sidestore_dir
    old = _write(base, "rib", "nxos", "h1", "1000-aaaaaaaa", 1000)
    estate.kept = [3000]

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "1", "--yes"])

    assert r.exit_code == 0, r.output
    assert old.exists()
    assert "nothing to prune" in r.output


def test_a_collection_holding_the_cycle_lock_stops_the_command_without_deleting(estate):
    pytest.importorskip("duckdb")
    base = estate.settings.sidestore_dir
    old = _write(base, "rib", "nxos", "h1", "1000-aaaaaaaa", 1000)
    estate.kept = [3000]
    estate.store = _Store(locked=True)
    _manifest(estate.settings, 3000)

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "1", "--yes"])

    assert r.exit_code == 1
    assert "holds the cycle lock" in r.output
    assert old.exists()


def test_the_graph_retention_is_the_one_the_scheduled_prune_applies(estate):
    pytest.importorskip("duckdb")
    base = estate.settings.sidestore_dir
    _write(base, "rib", "nxos", "h1", "1000-aaaaaaaa", 1000)
    estate.kept = [1000]
    runner.invoke(cli.app, ["sidestore", "prune", "--keep", "5"])
    runner.invoke(cli.app, ["sidestore", "prune"])

    device_runs = estate.settings.cycle_keep_device_runs
    cycles = estate.settings.cycle_keep_runs
    assert [(k.cycles, k.device_runs) for k in estate.asked] == [(5, device_runs), (cycles, device_runs)]


def test_the_stored_lifecycle_counts_are_the_default_and_keep_replaces_the_cycle_count(estate):
    pytest.importorskip("duckdb")
    estate.settings.sidestore_dir.mkdir(parents=True, exist_ok=True)
    estate.store = _Store(stored={"cycle_keep_runs": 7, "cycle_keep_device_runs": 9})
    runner.invoke(cli.app, ["sidestore", "prune"])
    runner.invoke(cli.app, ["sidestore", "prune", "--keep", "3"])

    assert [(k.cycles, k.device_runs) for k in estate.asked] == [(7, 9), (3, 9)]


def test_the_period_tier_keeps_a_file_still_inside_the_regulatory_period(estate):
    pytest.importorskip("duckdb")
    from datetime import UTC, datetime, timedelta

    estate.settings = Settings(
        _env_file=None, hst_data_dir=estate.settings.hst_data_dir, evidence_retention_days=30
    )
    recent = int((datetime.now(UTC) - timedelta(days=5)).timestamp() * 1000)
    path = _write(estate.settings.sidestore_dir, "rib", "nxos", "h1", f"{recent}-aaaaaaaa", recent)
    estate.kept = [9_999_999_999_999]
    _manifest(estate.settings, 9_999_999_999_999)

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "1", "--yes"])

    assert r.exit_code == 0, r.output
    assert path.exists()


def test_a_file_with_no_readable_run_key_is_left_in_place(estate):
    rib_dir = estate.settings.sidestore_dir / "rib" / "nxos" / "h1"
    rib_dir.mkdir(parents=True)
    stray = rib_dir / "not-a-real-file.parquet"
    stray.write_bytes(b"")
    estate.kept = [3000]
    _manifest(estate.settings, 3000)

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "1", "--yes"])

    assert r.exit_code == 0, r.output
    assert "nothing to prune" in r.output
    assert stray.exists()


def test_an_unavailable_store_stops_the_command_and_deletes_nothing(estate):
    pytest.importorskip("duckdb")
    old = _write(estate.settings.sidestore_dir, "rib", "nxos", "h1", "1000-aaaaaaaa", 1000)
    estate.kept = [3000]
    estate.down = ConnectionError("no database")

    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "1", "--yes"])

    assert r.exit_code == 1
    assert "could not be verified" in r.output
    assert old.exists()


def test_keep_zero_or_negative_is_rejected(estate):
    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "0"])
    assert r.exit_code == 2, r.output
    r = runner.invoke(cli.app, ["sidestore", "prune", "--keep", "-1"])
    assert r.exit_code == 2, r.output
