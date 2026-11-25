"""Every prune path, run in sequence on one history, leaves every kept run readable."""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
from contextlib import asynccontextmanager

import pytest

pytest.importorskip("pyarrow")
pytest.importorskip("duckdb")
pytest.importorskip("sqlalchemy")

from tests.test_cycle_retention import _Session

from hst.core import Settings, rawstore, sidestore
from hst.core import cycle as cyclemod
from hst.core import manifest as manifestmod
from hst.map import markers as hstmarkers
from hst.map import store as hststore
from hst.map import sweep as hstsweep
from hst.map import timeline as hsttimeline
from hst.map.tiers.fold import TIER_TABLES
from hst.map.tiers.read import MAX_COMPOSE
from hst.worker import maintenance

BASE = 1_700_000_000_000
STEP = 600_000
DEVICES = 3
RUNS = 60
PINNED = BASE + 20 * STEP
LEASED = BASE + 40 * STEP
KEEP = cyclemod.Keep(2, device_runs=5)


def _key(i: int) -> int:
    return BASE + i * STEP


def _run_id(key: int, device: int) -> str:
    return f"{key}-{'a' * 7}{device}"


class _Store:
    def __init__(self, refs, leased=()):
        self.refs = refs
        self.leased = set(leased)

    async def retained_snapshot_refs(self):
        return self.refs

    async def leased_runs(self):
        return self.leased

    async def get_setting(self, key):
        """Settings -> Lifecycle: the graph window `KEEP` names, over the environment's 30 and 48."""
        from datetime import UTC, datetime

        from hst.app.store import AppSetting

        value = {"cycle_keep_runs": KEEP.cycles, "cycle_keep_device_runs": KEEP.device_runs}
        return AppSetting(key=key, value=value, secrets=b"", updated_at=datetime.now(UTC))

    @asynccontextmanager
    async def try_cycle_lock(self):
        yield True


def _history(settings):
    """60 runs: full cycles at 0 and 30, device runs between. Device d fetches every
    d+2 runs and is carried in between, so a carried device's file is named only by
    the `devices` list of the manifests that stand on it."""
    runs = []
    effective: dict[int, str] = {}
    previous = None
    for i in range(RUNS):
        key = _key(i)
        files, devices = [], []
        for d in range(DEVICES):
            fetched = i % (d + 2) == 0
            if fetched:
                run_id = _run_id(key, d)
                raw = settings.raw_dir / "src" / f"h{d}" / (run_id + rawstore.SUFFIX)
                raw.parent.mkdir(parents=True, exist_ok=True)
                raw.write_bytes(b"synthetic sealed payload")
                raw.with_name(run_id + rawstore.META_SUFFIX).write_text(json.dumps({"snapshot_ts": key}))
                sidestore.write_table(
                    settings.sidestore_dir,
                    "rib",
                    "src",
                    f"h{d}",
                    run_id,
                    [
                        {
                            "device_uid": f"dev:h{d}",
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
                    ],
                    key,
                )
                effective[d] = run_id
                for kind in ("raw", "sidestore"):
                    files.append(
                        manifestmod.FileEntry(
                            kind=kind,
                            path="x",
                            sha256="0" * 64,
                            bytes=1,
                            source="src",
                            host=f"h{d}",
                            run_id=run_id,
                        )
                    )
            devices.append(
                manifestmod.DeviceEntry(
                    source="src",
                    host=f"h{d}",
                    outcome="collected" if fetched else "carried",
                    effective_run=effective[d],
                    carried=not fetched,
                )
            )
        manifestmod.write(
            settings,
            manifestmod.SnapshotManifest(
                snapshot_key=key,
                kind="full",
                opened=manifestmod.iso(key),
                published=manifestmod.iso(key + 1000),
                previous=manifestmod.PreviousLink(
                    snapshot_key=previous, sha256=manifestmod.digest_of(settings, previous), chain_index=i
                )
                if previous
                else None,
                files=files,
                devices=devices,
            ),
        )
        runs.append({"cts": key, "kind": "full" if i in (0, 30) else "device", "parent": previous})
        previous = key
    return runs


def _identities(record):
    """Every (kind, source, host, run_id) a run's manifest says it reads."""
    wanted = {(f.kind, f.source, f.host, f.run_id) for f in record.files}
    for d in record.devices:
        if d.effective_run:
            wanted.add(("raw", d.source, d.host, d.effective_run))
            wanted.add(("sidestore", d.source, d.host, d.effective_run))
    return wanted


def _exists(settings, kind, source, host, run_id):
    if kind == "raw":
        return (settings.raw_dir / source / host / (run_id + rawstore.SUFFIX)).is_file()
    return (settings.sidestore_dir / "rib" / source / host / f"{run_id}.parquet").is_file()


SWEEPS = {
    "graph": lambda s, store: maintenance.prune_graph(s, store, KEEP),
    "side": lambda s, store: maintenance.prune_sidestore(s, store, KEEP),
    "raw": lambda s, store: maintenance.prune_rawstore(s, store, KEEP),
    "manifests": lambda s, store: maintenance.prune_manifests(s, store, KEEP),
}


def _hst_history(settings):
    """The HST projection of the same runs: a warm marker chained to its parent and the tier
    and delta files of every run (map/sweep.py)."""
    previous = None
    for i in range(RUNS):
        key = _key(i)
        hstmarkers.write(
            settings.manifests_dir,
            {"key": key, "kind": "full", "parent": previous, "published_ts": key, "state": "warm"},
        )
        for name in (*TIER_TABLES, *hstsweep.HISTORY_TABLES):
            path = hststore.table_path(settings.sidestore_dir, name, key)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"PAR1")
        previous = key


def _estate(tmp_path, monkeypatch, refs, leased=(), hst=False):
    settings = Settings(
        _env_file=None,
        hst_data_dir=tmp_path,
        evidence_retention_days=1,
        hst_tier_checkpoint_every=10,
        hst_history_days=1,
    )
    runs = _history(settings)
    if hst:
        _hst_history(settings)
        monkeypatch.setattr(hstsweep, "_layout_in_force", lambda _sidestore, _newest: set())
    graph = _Session(runs, runs[-1]["cts"])
    monkeypatch.setattr(maintenance, "_session", contextlib.contextmanager(lambda settings: iter([graph])))
    return settings, graph, _Store(refs, leased)


@pytest.mark.parametrize("order", [o for o in itertools.permutations(SWEEPS) if o[0] == "graph"])
async def test_every_kept_run_still_reads_completely_after_every_sweep(tmp_path, monkeypatch, order):
    settings, graph, store = _estate(tmp_path, monkeypatch, [{"snapshot": str(PINNED)}])

    for name in order:
        assert await SWEEPS[name](settings, store) is not None

    # the graph window: two cycles, the newest five device runs and the pointer
    kept = {_key(0), _key(30), *(_key(i) for i in range(RUNS - 5, RUNS))}
    assert set(cyclemod.retained_runs(graph, KEEP)) == kept
    assert {r["cts"] for r in graph.runs} == kept | {PINNED}  # and the run an assessment retains

    for key in kept | {PINNED}:
        record = manifestmod.read(settings, key)  # raises when the manifest is gone
        for identity in _identities(record):
            assert _exists(settings, *identity), f"run {key} lost {identity}"

    # and the rest went: a file that no kept or pinned manifest binds is gone
    bound = {i for key in kept | {PINNED} for i in _identities(manifestmod.read(settings, key))}
    checked = 0
    for i in range(RUNS):
        for d in range(DEVICES):
            if i % (d + 2) == 0:
                for kind in ("raw", "sidestore"):
                    identity = (kind, "src", f"h{d}", _run_id(_key(i), d))
                    assert _exists(settings, *identity) == (identity in bound), identity
                    checked += 1
    assert checked > 100
    # manifests keep the chain behind a retained assessment (the evidence trail), the
    # manifest each kept one names as `previous`, and nothing else
    left = set(manifestmod.keys(settings))
    assert {_key(i) for i in range(0, 21)} | {_key(29), _key(54)} <= left
    assert not left & {_key(21), _key(31), _key(40), _key(53)}


async def test_a_second_pass_of_every_sweep_deletes_nothing_more(tmp_path, monkeypatch):
    settings, _graph, store = _estate(tmp_path, monkeypatch, [{"snapshot": str(PINNED)}])
    for name in SWEEPS:
        await SWEEPS[name](settings, store)

    again = [await SWEEPS[name](settings, store) for name in SWEEPS]

    assert again == [[], [], [], []]


async def test_the_retained_assessment_is_the_only_reason_its_run_and_files_stay(tmp_path, monkeypatch):
    settings, graph, store = _estate(tmp_path, monkeypatch, [])

    for name in SWEEPS:
        await SWEEPS[name](settings, store)

    assert PINNED not in {r["cts"] for r in graph.runs}
    assert not manifestmod.path_for(settings, PINNED).exists()
    assert not _exists(settings, "sidestore", "src", "h0", _run_id(PINNED, 0))


async def test_a_raw_file_of_a_run_whose_manifest_the_period_sweep_removed_is_not_kept_forever(
    tmp_path, monkeypatch
):
    """The manifest sweep runs first and removes the manifest of run 21."""
    settings, _graph, store = _estate(tmp_path, monkeypatch, [])
    for name in ("graph", "manifests", "raw"):
        await SWEEPS[name](settings, store)

    assert not manifestmod.path_for(settings, _key(21)).exists()
    assert not _exists(settings, "raw", "src", "h1", _run_id(_key(21), 1))


async def test_a_raw_file_that_predates_manifests_is_left_alone(tmp_path, monkeypatch):
    """The oldest surviving manifest is the first ever written (it links to no predecessor),
    so a run older than it was published before manifests existed (no-migration)."""
    settings, _graph, store = _estate(tmp_path, monkeypatch, [])
    legacy_key = _key(0) - 10 * STEP
    legacy = settings.raw_dir / "src" / "h0" / (_run_id(legacy_key, 0) + rawstore.SUFFIX)
    legacy.write_bytes(b"synthetic sealed payload")
    legacy.with_name(_run_id(legacy_key, 0) + rawstore.META_SUFFIX).write_text(
        json.dumps({"snapshot_ts": legacy_key})
    )

    for name in SWEEPS:
        await SWEEPS[name](settings, store)

    assert legacy.exists()


def _assert_kept_runs_read_completely(settings, keys):
    for key in keys:
        record = manifestmod.read(settings, key)  # raises when the manifest is gone
        for identity in _identities(record):
            assert _exists(settings, *identity), f"run {key} lost {identity}"


def _composable(settings):
    """Every run left in the HST timeline composes its tiers from its own files or from a
    base at most MAX_COMPOSE runs back."""
    chain = hsttimeline.chain(settings.manifests_dir)
    held = [hststore.table_path(settings.sidestore_dir, "render_t1", key).exists() for key in chain]
    return chain, [any(held[max(0, i - MAX_COMPOSE) : i + 1]) for i in range(len(chain))]


@pytest.mark.parametrize("order", [o for o in itertools.permutations(SWEEPS) if o[0] == "graph"])
async def test_a_leased_run_stays_whole_through_every_sweep_until_its_lease_ends(
    tmp_path, monkeypatch, order
):
    """A trace holds a lease on run 40, which is outside the graph window and not in an
    assessment's chain: no sweep takes its graph data, its manifest or any file it reads."""
    settings, graph, store = _estate(tmp_path, monkeypatch, [{"snapshot": str(PINNED)}], leased=[LEASED])

    for name in order:
        assert await SWEEPS[name](settings, store) is not None

    kept = {_key(0), _key(30), *(_key(i) for i in range(RUNS - 5, RUNS))}
    assert {r["cts"] for r in graph.runs} == kept | {PINNED, LEASED}
    _assert_kept_runs_read_completely(settings, kept | {PINNED, LEASED})
    assert manifestmod.path_for(settings, LEASED).exists()

    store.leased = set()
    for name in SWEEPS:
        await SWEEPS[name](settings, store)

    assert LEASED not in {r["cts"] for r in graph.runs}
    assert not manifestmod.path_for(settings, LEASED).exists()
    assert not _exists(settings, "sidestore", "src", "h0", _run_id(LEASED, 0))
    _assert_kept_runs_read_completely(settings, kept | {PINNED})


async def test_the_hst_sweep_keeps_every_run_left_in_the_timeline_composable(tmp_path, monkeypatch):
    """The HST sweep rides on the graph prune's turn: the runs the prune deleted go cold, their
    tier files go but for a base at most every `hst_tier_checkpoint_every` runs, and the runs
    the graph still keeps stay warm with their own files."""
    settings, graph, store = _estate(
        tmp_path, monkeypatch, [{"snapshot": str(PINNED)}], leased=[LEASED], hst=True
    )

    for name in ("graph", "side", "raw", "manifests"):
        assert await SWEEPS[name](settings, store) is not None

    kept = {r["cts"] for r in graph.runs}
    assert kept == {_key(0), _key(30), PINNED, LEASED, *(_key(i) for i in range(RUNS - 5, RUNS))}
    chain, composable = _composable(settings)
    assert chain == [_key(i) for i in range(RUNS)]
    assert all(composable)
    for key in chain:
        state = hstmarkers.read(settings.manifests_dir, key)["state"]
        assert state == ("warm" if key in kept else "cold"), key
        if key in kept:
            assert hststore.table_path(settings.sidestore_dir, "render_t1", key).exists()
    # the tier files of cold runs went, but for the bases the gap rule keeps
    held_cold = [
        k
        for k in chain
        if k not in kept and hststore.table_path(settings.sidestore_dir, "render_t1", k).exists()
    ]
    assert 0 < len(held_cold) < RUNS - len(kept)
    _assert_kept_runs_read_completely(settings, kept)


async def test_hst_prune_then_every_other_sweep_leaves_every_kept_run_readable(tmp_path, monkeypatch):
    """The graph step is `hst prune`, not the scheduled job: its keep comes from the stored
    Lifecycle values (the environment says 30 and 48), it passes through `prune_graph` with the
    leases and the assessment references, and the HST sweep follows it."""
    from typer.testing import CliRunner

    import hst.cli as cli

    settings, graph, store = _estate(
        tmp_path, monkeypatch, [{"snapshot": str(PINNED)}], leased=[LEASED], hst=True
    )
    assert settings.cycle_keep_runs == 30 and settings.cycle_keep_device_runs == 48
    monkeypatch.setattr(cli, "Settings", lambda: settings)

    def store_read(_settings, callback, *, hold_lock=True):
        assert hold_lock is False
        return asyncio.run(callback(store))

    monkeypatch.setattr(cli, "_assessment_store_read", store_read)

    result = await asyncio.to_thread(CliRunner().invoke, cli.app, ["prune"])

    assert result.exit_code == 0, result.output
    assert "deleted" in result.output
    for name in ("side", "raw", "manifests"):
        assert await SWEEPS[name](settings, store) is not None

    kept = {_key(0), _key(30), PINNED, LEASED, *(_key(i) for i in range(RUNS - 5, RUNS))}
    assert {r["cts"] for r in graph.runs} == kept
    _assert_kept_runs_read_completely(settings, kept)
    chain, composable = _composable(settings)
    assert chain == [_key(i) for i in range(RUNS)] and all(composable)
    assert hstmarkers.read(settings.manifests_dir, _key(21))["state"] == "cold"
