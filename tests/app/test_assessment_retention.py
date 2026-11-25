"""Saved assessment evidence survives every retention tier and broken chains fail closed."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from hst.core import Settings, cycle, manifest, rawstore
from hst.worker import maintenance


class Store:
    def __init__(self, refs):
        self.refs = refs
        self.locked = False
        self.leased: set[int] = set()

    async def leased_runs(self):
        return self.leased

    async def retained_snapshot_refs(self):
        return self.refs

    @asynccontextmanager
    async def try_cycle_lock(self):
        self.locked = True
        try:
            yield True
        finally:
            self.locked = False


@pytest.fixture
def estate(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, evidence_retention_days=1)
    records = {}
    files = {}
    for key, parent in ((5, None), (10, None), (20, 10), (30, 20), (40, None), (100, None)):
        run = f"{key}-abcdef"
        raw = settings.raw_dir / "source" / "device" / (run + rawstore.SUFFIX)
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_bytes(b"synthetic encrypted evidence")
        raw.with_name(run + rawstore.META_SUFFIX).write_text(json.dumps({"snapshot_ts": key}))
        side = settings.sidestore_dir / "rib" / "source" / "device" / (run + ".parquet")
        side.parent.mkdir(parents=True, exist_ok=True)
        side.write_bytes(b"synthetic side-table fixture")
        archive = settings.graph_archives_dir / f"{key}.enc"
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(b"synthetic graph archive")
        record = manifest.SnapshotManifest(
            snapshot_key=key,
            kind="cycle",
            opened="2000-01-01T00:00:00+00:00",
            published="2000-01-01T00:00:01+00:00",
            previous=manifest.PreviousLink(
                snapshot_key=parent, sha256=manifest.digest_of(settings, parent), chain_index=0
            )
            if parent
            else None,
            files=[
                manifest.FileEntry(
                    kind="raw",
                    path=str(raw.relative_to(tmp_path)),
                    sha256="synthetic",
                    bytes=raw.stat().st_size,
                    source="source",
                    host="device",
                    run_id=run,
                )
            ],
            graph_archive=manifest.GraphArchiveEntry(
                path=str(archive.relative_to(tmp_path)),
                sha256="synthetic",
                bytes=archive.stat().st_size,
                snapshot_key=key,
                format_version=1,
                graph_schema_version=1,
                chunks=1,
                nodes=1,
                rels=0,
                normalization_context_sha256="synthetic",
            ),
        )
        if key == 10:
            # A retained manifest needs evidence fetched in a run outside
            # both the count window and its predecessor-manifest chain.
            record.files.append(
                manifest.FileEntry(
                    kind="raw",
                    path="raw/source/device/5-abcdef.json.gz.enc",
                    sha256="synthetic",
                    bytes=1,
                    source="source",
                    host="device",
                    run_id="5-abcdef",
                )
            )
        manifest.write(settings, record)
        manifest.sig_path_for(settings, key).write_text("synthetic signature")
        records[key] = record
        files[key] = {
            "raw": raw,
            "side": side,
            "archive": archive,
            "manifest": manifest.path_for(settings, key),
            "signature": manifest.sig_path_for(settings, key),
        }

    @contextmanager
    def session(settings):
        yield object()

    monkeypatch.setattr(maintenance, "_session", session)
    monkeypatch.setattr(cycle, "retained_runs", lambda session, keep: [100])
    monkeypatch.setattr(maintenance, "_file_snapshot_ts", lambda path: int(path.name.split("-", 1)[0]))
    return SimpleNamespace(settings=settings, records=records, files=files, store=Store([{"snapshot": "30"}]))


async def test_exact_snapshot_and_transitive_manifest_ancestors_are_pinned(estate):
    estate.store.refs.extend([{"collection_ts": 20}, {"snapshot_key": "10"}])
    assert await maintenance._assessment_pins(estate.store, estate.settings) == {10, 20, 30}


@pytest.mark.parametrize(
    "reference",
    [
        {},
        {"snapshot": "latest"},
        {"snapshot": True},
        {"snapshot": 30.5},
        {"snapshot": "30", "collection_ts": 20},
        {"snapshot_key": -1},
    ],
)
async def test_invalid_retained_reference_fails_closed(estate, reference):
    estate.store.refs = [reference]
    with pytest.raises(ValueError, match="retention stopped"):
        await maintenance._assessment_pins(estate.store, estate.settings)


class _Graph:
    """The graph's runs as a list that `cycle.prune` reads and deletes from, so the
    sweep's one-run-at-a-time loop sees each delete."""

    def __init__(self, monkeypatch, estate, window, runs):
        self.runs = list(runs)  # newest first
        self.deleted: list[int] = []
        self.window = window
        self.estate = estate
        monkeypatch.setattr(cycle, "_partition", lambda session, keep: (list(window), list(self.runs)))
        monkeypatch.setattr(cycle, "orphan_runs", lambda session: [])
        monkeypatch.setattr(cycle, "current_ts_or_none", lambda session: window[0])
        monkeypatch.setattr(cycle, "delete_run", self.delete_run)

    def delete_run(self, session, cts):
        assert self.estate.store.locked
        self.deleted.append(cts)
        self.runs.remove(cts)


async def test_graph_sweep_keeps_the_pinned_run_and_not_the_manifest_chain_behind_it(estate, monkeypatch):
    graph = _Graph(monkeypatch, estate, [100], [40, 30, 20, 10, 5])
    assert await maintenance.prune_graph(estate.settings, estate.store, 1) == [40, 20, 10, 5]
    assert graph.deleted == [5, 10, 20, 40]  # oldest first, the pinned 30 stays


async def test_graph_sweep_keeps_a_run_a_reader_holds_open(estate, monkeypatch):
    estate.store.leased = {20}
    graph = _Graph(monkeypatch, estate, [100], [40, 30, 20, 10, 5])
    assert await maintenance.prune_graph(estate.settings, estate.store, 1) == [40, 10, 5]
    assert 20 not in graph.deleted and 30 not in graph.deleted


async def test_graph_sweep_takes_the_cycle_lock_once_per_run_and_lets_a_collection_in_between(
    estate, monkeypatch
):
    graph = _Graph(monkeypatch, estate, [100], [40, 30, 20, 10, 5])
    holds: list[int] = []
    take = estate.store.try_cycle_lock

    def counted():
        holds.append(len(graph.deleted))
        return take()

    estate.store.try_cycle_lock = counted
    await maintenance.prune_graph(estate.settings, estate.store, 1)
    # a hold per deleted run, plus the one that found nothing more to delete
    assert holds == [0, 1, 2, 3, 4]


async def test_graph_sweep_ends_with_what_it_deleted_when_a_collection_takes_the_lock(estate, monkeypatch):
    graph = _Graph(monkeypatch, estate, [100], [40, 30, 20, 10, 5])
    take = estate.store.try_cycle_lock
    turns = 0

    @asynccontextmanager
    async def busy_after_two():
        nonlocal turns
        turns += 1
        if turns > 2:
            yield False
            return
        async with take() as locked:
            yield locked

    estate.store.try_cycle_lock = busy_after_two
    assert await maintenance.prune_graph(estate.settings, estate.store, 1) == [10, 5]
    assert graph.deleted == [5, 10]
    turns = 2
    assert await maintenance.prune_graph(estate.settings, estate.store, 1) is None


@pytest.mark.parametrize("tier", ["raw", "side"])
async def test_raw_and_side_tables_keep_pinned_runs_and_manifest_dependencies(estate, tier):
    """Runs 30 and 10 are the retained assessments' runs: each keeps its own files and
    every file its manifest binds (10 binds run 5's). Run 20, the manifest ancestor of 30,
    is not pinned."""
    estate.store.refs.append({"snapshot": "10"})
    prune = maintenance.prune_rawstore if tier == "raw" else maintenance.prune_sidestore
    victims = await prune(estate.settings, estate.store, 1)
    assert sorted(victims) == sorted([estate.files[20][tier], estate.files[40][tier]])
    for key in (5, 10, 30, 100):
        assert estate.files[key][tier].exists()
    for key in (20, 40):
        assert not estate.files[key][tier].exists()


@pytest.mark.parametrize("tier", ["raw", "side"])
async def test_file_sweeps_leave_the_files_of_a_run_in_flight_and_a_leased_run(estate, tier):
    """A run being built writes under keys above the newest kept run, and the lock is not
    held while the files are walked."""
    estate.store.leased = {20}
    ahead = estate.files[40][tier].with_name(estate.files[40][tier].name.replace("40-", "200-"))
    estate.files[40][tier].rename(ahead)
    if tier == "raw":
        ahead.with_name(ahead.name.replace(rawstore.SUFFIX, rawstore.META_SUFFIX)).write_text(
            json.dumps({"snapshot_ts": 200})
        )
    prune = maintenance.prune_rawstore if tier == "raw" else maintenance.prune_sidestore
    await prune(estate.settings, estate.store, 1)
    assert ahead.exists()
    assert estate.files[20][tier].exists()
    assert not estate.files[5][tier].exists()


async def test_the_decision_is_taken_under_the_lock_and_the_files_are_walked_after_it(estate, monkeypatch):
    seen = []
    real = maintenance._file_snapshot_ts

    def walk(path):
        seen.append(estate.store.locked)
        return real(path)

    monkeypatch.setattr(maintenance, "_file_snapshot_ts", walk)
    await maintenance.prune_sidestore(estate.settings, estate.store, 1)
    assert seen and not any(seen)


async def test_manifest_sweep_preserves_pinned_chain_signatures_and_graph_archives(estate):
    victims = await maintenance.prune_manifests(estate.settings, estate.store)
    assert 40 in victims
    assert not set(victims).intersection({10, 20, 30, 100})
    for key in (10, 20, 30, 100):
        for kind in ("manifest", "signature", "archive"):
            assert estate.files[key][kind].exists()
    for kind in ("manifest", "signature", "archive"):
        assert not estate.files[40][kind].exists()


@pytest.mark.parametrize("tier", ["graph", "raw", "side", "manifest"])
async def test_a_missing_manifest_ancestor_of_a_pin_ends_the_chain_and_stops_nothing(
    estate, monkeypatch, tier
):
    """With the period sweep on, old manifests are removed, so a pinned run's chain runs
    into a missing file."""
    estate.files[20]["manifest"].unlink()
    graph = _Graph(monkeypatch, estate, [100], [40, 30, 20, 10, 5])
    if tier == "graph":
        assert await maintenance.prune_graph(estate.settings, estate.store, 1) == [40, 20, 10, 5]
    elif tier == "raw":
        assert estate.files[40]["raw"] in await maintenance.prune_rawstore(estate.settings, estate.store, 1)
    elif tier == "side":
        assert estate.files[40]["side"] in await maintenance.prune_sidestore(estate.settings, estate.store, 1)
    else:
        victims = await maintenance.prune_manifests(estate.settings, estate.store)
        assert 40 in victims and 30 not in victims and 100 not in victims
    assert 30 not in graph.deleted


async def test_an_assessment_reference_naming_no_run_stops_every_sweep(estate, monkeypatch):
    estate.store.refs = [{"snapshot": "latest"}]
    graph = _Graph(monkeypatch, estate, [100], [40, 30, 20, 10, 5])
    for sweep in (
        maintenance.prune_graph,
        maintenance.prune_rawstore,
        maintenance.prune_sidestore,
        maintenance.prune_manifests,
    ):
        with pytest.raises(ValueError, match="retention stopped"):
            await sweep(
                estate.settings, estate.store, 1
            ) if sweep is not maintenance.prune_manifests else await sweep(estate.settings, estate.store)
    assert graph.deleted == []


async def test_a_missing_ancestor_named_by_a_manifest_inside_the_period_is_a_broken_chain(estate):
    recent = estate.records[30].model_copy(update={"opened": datetime.now(UTC).isoformat()})
    manifest.write(estate.settings, recent)
    estate.files[20]["manifest"].unlink()
    with pytest.raises(FileNotFoundError):
        await maintenance._assessment_pins(estate.store, estate.settings)


async def test_a_missing_ancestor_is_a_broken_chain_while_the_period_sweep_is_off(estate):
    estate.files[20]["manifest"].unlink()
    estate.settings.evidence_retention_days = None
    with pytest.raises(FileNotFoundError):
        await maintenance._assessment_pins(estate.store, estate.settings)


async def test_the_missing_manifest_of_a_retained_run_itself_is_a_broken_chain(estate):
    estate.files[30]["manifest"].unlink()
    with pytest.raises(FileNotFoundError):
        await maintenance._assessment_pins(estate.store, estate.settings)
