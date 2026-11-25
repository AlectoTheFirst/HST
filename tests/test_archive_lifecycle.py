"""Archive replay and retention lifecycle."""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

import hst.cli as cli
from hst.core import manifest, replay
from hst.core.config import Settings
from hst.worker import maintenance


def test_cli_exact_replay_does_not_read_current_source_rows(monkeypatch, tmp_path):
    entry = SimpleNamespace(normalization_context={})
    record = SimpleNamespace(
        opened="then",
        published="then",
        devices=[],
        files=[],
        graph_archive=entry,
    )
    monkeypatch.setattr(manifest, "read", lambda settings, snapshot: record)
    monkeypatch.setattr(
        cli,
        "_source_rows",
        lambda: (_ for _ in ()).throw(AssertionError("exact replay consulted Postgres")),
    )

    @contextmanager
    def session(_settings):
        yield object()

    monkeypatch.setattr(cli.dbmod, "session", session)
    seen = {}

    def rebuild(settings, target, snapshot, **kwargs):
        seen["source"] = kwargs["source_for"]("anything")
        return replay.ManifestRebuildReport(snapshot_key=snapshot, exact=True)

    monkeypatch.setattr(replay, "rebuild_from_manifest", rebuild)
    cli._rebuild_from_manifest(
        Settings(_env_file=None, hst_data_dir=tmp_path),
        1000,
        into="bolt://scratch",
        dry_run=False,
        allow_config_drift=False,
        sidestore_scratch=None,
    )
    assert seen["source"] is None


def test_sequential_fixture_copies_parent_into_a_fresh_unpublished_key(monkeypatch, tmp_path):
    settings = Settings(
        _env_file=None,
        hst_data_dir=tmp_path,
        hst_secret_key="x" * 32,
    )
    batch = SimpleNamespace(source="second", scope="fixture:second", nodes=[], rels=[])
    prior = SimpleNamespace(
        graph_archive=object(),
        devices=[],
        files=[],
        site_assignments={},
        sources=[
            manifest.SourceEntry(
                name="first",
                type="fixture",
                status="fresh",
                config_sha256="a" * 64,
            )
        ],
    )
    session_object = object()

    @contextmanager
    def session(_settings):
        yield session_object

    monkeypatch.setattr(cli, "Settings", lambda: settings)
    monkeypatch.setattr(cli, "load_fixture", lambda path: batch)
    monkeypatch.setattr(cli.dbmod, "session", session)
    published = {}
    monkeypatch.setattr("hst.core.cycle.current_ts", lambda session: published.get("pointer", 1000))
    monkeypatch.setattr("hst.core.cycle.new_collection_ts", lambda: 1001)
    monkeypatch.setattr(
        "hst.core.cycle.begin_run",
        lambda session, cts, kind, parent: published.update(begun=(cts, kind, parent)),
    )
    monkeypatch.setattr("hst.core.cycle.discard_run", lambda session, cts: published.update(discarded=cts))
    monkeypatch.setattr("hst.core.cycle.cycle_counts", lambda session, cts: {"nodes": 2, "rels": 1})
    monkeypatch.setattr(
        "hst.core.cycle.write_cycle_meta",
        lambda session, cts, **kwargs: published.update(meta=cts, meta_args=kwargs),
    )
    monkeypatch.setattr(
        "hst.core.cycle.set_pointer",
        lambda session, cts: published.update(pointer=cts),
    )
    monkeypatch.setattr(manifest, "read", lambda settings, key: prior)
    monkeypatch.setattr("hst.core.grapharchive.verify", lambda settings, entry, key: None)
    monkeypatch.setattr(
        "hst.core.cycle.carry_forward",
        lambda session, previous, target, sources: published.update(carried=(previous, target, sources)),
    )
    monkeypatch.setattr(
        "hst.core.grapharchive.write",
        lambda *args, **kwargs: {
            "path": "graph-archives/1001.graph.enc",
            "sha256": "b" * 64,
            "bytes": 1,
            "snapshot_key": 1001,
            "format_version": 1,
            "graph_schema_version": 1,
            "chunks": 1,
            "nodes": 2,
            "rels": 1,
            "normalization_context": kwargs["normalization_context"],
            "normalization_context_sha256": "c" * 64,
        },
    )
    monkeypatch.setattr("hst.app.crypto.dek", lambda settings: "key")
    monkeypatch.setattr(cli, "load", lambda *args, **kwargs: SimpleNamespace(counts={}, errors=[]))
    monkeypatch.setattr(
        "hst.core.finalize.finalize_derivations",
        lambda session, settings, cts, sites, **kwargs: published.update(finalize=kwargs) or [],
    )
    monkeypatch.setattr(manifest, "graph_delta", lambda *args: manifest.GraphDelta())
    built = {}
    monkeypatch.setattr(
        manifest,
        "build",
        lambda **kwargs: built.update(kwargs) or SimpleNamespace(),
    )
    monkeypatch.setattr(manifest, "write", lambda *args: "d" * 64)
    monkeypatch.setattr(manifest, "signer_for", lambda settings: None)
    monkeypatch.setattr(cli, "_print_manifest", lambda loaded: None)

    cli.load_fixture_cmd(tmp_path / "second.yaml", dry_run=False, new_run=False)

    assert published["begun"] == (1001, "full", 1000)  # recorded before the first write
    assert "discarded" not in published  # the pointer names the run, so it stays
    assert published["finalize"]["parent"] == 1000
    # the fixture writes no side-store file; the derivations read the carried devices' files only
    assert set(published["finalize"]) == {"parent", "sidestore_files"}
    assert published["carried"] == (1000, 1001, ["first"])
    assert built["snapshot_key"] == 1001
    assert built["parent"] == 1000
    assert published["meta"] == published["pointer"] == 1001
    assert {entry.name: entry.status for entry in built["sources"]} == {
        "first": "carried",
        "second": "fresh",
    }


class _LockingStore:
    @asynccontextmanager
    async def try_cycle_lock(self):
        yield True


@pytest.mark.asyncio
async def test_manifest_retention_removes_only_its_linked_archive(tmp_path, monkeypatch):
    settings = Settings(
        _env_file=None,
        hst_data_dir=tmp_path,
        evidence_retention_days=1,
    )
    old_key = 1_600_000_000_000
    current_key = 1_800_000_000_000
    entries = {}
    for key, opened in (
        (old_key, "2020-09-13T12:26:40+00:00"),
        (current_key, datetime.now(UTC).isoformat()),
    ):
        archive_path = settings.graph_archives_dir / f"{key}.graph.enc"
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path.write_bytes(str(key).encode())
        sha, size = manifest.file_facts(archive_path)
        archive = manifest.GraphArchiveEntry(
            path=str(archive_path.relative_to(settings.hst_data_dir)),
            sha256=sha,
            bytes=size,
            snapshot_key=key,
            format_version=1,
            graph_schema_version=1,
            chunks=1,
            nodes=1,
            rels=0,
            normalization_context={},
            normalization_context_sha256=manifest.canonical_digest({}),
        )
        entries[key] = archive_path
        manifest.write(
            settings,
            manifest.SnapshotManifest(
                snapshot_key=key,
                kind="full",
                opened=opened,
                published=opened,
                graph_archive=archive,
            ),
        )

    @contextmanager
    def session(_settings):
        yield object()

    # the period sweep also asks the graph which runs it still keeps
    monkeypatch.setattr(maintenance, "_session", session)
    monkeypatch.setattr(maintenance.cyclemod, "retained_runs", lambda session, keep: [current_key])

    victims = await maintenance.prune_manifests(settings, _LockingStore())
    assert victims == [old_key]
    assert not entries[old_key].exists()
    assert entries[current_key].is_file()
    assert manifest.path_for(settings, current_key).is_file()
