"""Real encrypted archives replay multiple snapshots without merging unversioned objects."""

from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager

import pytest
from typer.testing import CliRunner

from hst.app import crypto
from hst.assessment import package, service
from hst.assessment.archive_sessions import ArchiveSessionError, ArchiveSessions
from hst.assessment.store import MemoryAssessmentStore, input_digest
from hst.core import Settings, db, grapharchive, manifest, replay


class Result:
    def __init__(self, rows):
        self.rows = rows

    def data(self):
        return self.rows

    def single(self):
        return self.rows[0] if self.rows else None


class ArchivedGraph:
    def __init__(self, snapshot, shared_value):
        self.snapshot, self.shared_value = snapshot, shared_value

    def execute_read(self, callback):
        return callback(self)

    def run(self, query, **params):
        if query == grapharchive._NODES:
            return [
                {
                    "uid": "shared",
                    "labels": ["Obj", "Service"],
                    "props": {"uid": "shared", "value": self.shared_value},
                },
                {
                    "uid": "device",
                    "labels": ["Obj", "Device"],
                    "props": {"uid": "device", "collection_ts": self.snapshot},
                },
            ]
        assert query == grapharchive._RELS
        return []


class Target:
    def __init__(self):
        self.nodes = []
        self.restores = []
        self.clears = 0

    def execute_read(self, callback):
        return callback(self)

    def execute_write(self, callback):
        return callback(self)

    def run(self, query, **params):
        if query == "MATCH (n) RETURN count(n) AS count":
            return Result([{"count": len(self.nodes)}])
        if query.startswith("UNWIND $rows AS row CREATE"):
            self.nodes.extend(params["rows"])
            return Result([{"created": len(params["rows"])}])
        if query == replay._CLEAR_BATCH:
            count = len(self.nodes)
            self.nodes.clear()
            self.clears += 1
            return Result([{"c": count}])
        if query == "READ_SHARED":
            return Result([dict(node) for node in self.nodes if node["uid"] == "shared"])
        raise AssertionError(query)


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path / "estate", hst_secret_key="fixture" * 8)
    key = crypto.dek(settings)
    refs = []
    previous = None
    for snapshot, value in ((1000, "old"), (2000, "new")):
        archive = grapharchive.write(ArchivedGraph(snapshot, value), settings, snapshot, key)
        record = manifest.SnapshotManifest(
            snapshot_key=snapshot,
            kind="full",
            opened="2026-09-08T00:00:00Z",
            published="2026-09-08T00:01:00Z",
            graph_archive=manifest.GraphArchiveEntry(**archive),
            previous=previous,
        )
        digest = manifest.write(settings, record)
        refs.append({"snapshot": str(snapshot), "manifest_sha256": digest, "estate": "default"})
        previous = manifest.PreviousLink(snapshot_key=snapshot, sha256=digest, chain_index=0)
    refs.reverse()
    inputs = {"definition": {}, "analysis": {"kind": "regression"}, "snapshot_refs": refs}
    fields = {
        "assessment_id": "assessment",
        "assessment_revision": 1,
        "kind": "regression",
        "inputs": inputs,
        "snapshot_refs": refs,
        "engine_version": "fixture",
        "limits": {},
        "input_schema_version": 1,
    }
    run = {
        **fields,
        "id": "run",
        "input_digest": input_digest(fields),
        "state": "completed",
        "result": {"before": "old", "after": "new", "execution": {"elapsed_seconds": 123, "attempt": 1}},
    }
    target = Target()

    @contextmanager
    def session(selected):
        assert selected.neo4j_uri == "bolt://localhost:19999"
        yield target

    monkeypatch.setattr(db, "session", session)
    monkeypatch.setattr(service, "engine_version", lambda settings: "fixture")
    monkeypatch.setattr(
        replay, "_publish", lambda settings, target, snapshot, **kwargs: target.restores.append(snapshot)
    )
    return settings, run, key, target


def test_portable_multi_snapshot_replay_switches_complete_archives_for_nested_late_reads(
    fixture, tmp_path, monkeypatch
):
    settings, run, _key, target = fixture
    path, key_file = tmp_path / "portable.zip", tmp_path / "key"
    package.build_portable(settings, run, path, key_file=key_file)

    def execute(selected, inputs, *, snapshot_session_factory):
        with snapshot_session_factory(inputs["snapshot_refs"][0]) as newer:
            buffered = newer.run("READ_SHARED")
            with snapshot_session_factory(inputs["snapshot_refs"][1]) as older:
                before = older.execute_read(lambda tx: tx.run("READ_SHARED").single())["value"]
            # The graph gate restores the newer archive before this read.
            after = newer.execute_read(lambda tx: tx.run("READ_SHARED").single())["value"]
            assert buffered.single()["value"] == "new"
        return {"before": before, "after": after}

    monkeypatch.setattr(service, "execute", execute)
    result = package.replay_package(settings, path, into="bolt://localhost:19999", package_key_file=key_file)
    assert result["available"] and result["matches"]
    assert result["restored_snapshots"] == [1000, 2000]
    assert target.restores == [2000, 1000, 2000]
    assert target.clears == 2
    assert len([node for node in target.nodes if node["uid"] == "shared"]) == 1
    assert result["ignored_fields"] == ["elapsed_seconds", "execution"]


def test_router_refuses_snapshot_switch_with_live_transaction(fixture):
    settings, run, key, target = fixture
    router = ArchiveSessions(settings, target, run["snapshot_refs"], key)
    with router.session(run["snapshot_refs"][0]) as newer:

        def illegal_switch(tx):
            with router.session(run["snapshot_refs"][1]):
                pass

        with pytest.raises(ArchiveSessionError, match="active transaction"):
            newer.execute_read(illegal_switch)
    assert target.restores == [2000]
    assert target.clears == 0


def test_all_archives_authenticate_before_first_graph_mutation(fixture):
    settings, run, key, target = fixture
    record = manifest.read(settings, 1000)
    (settings.hst_data_dir / record.graph_archive.path).write_bytes(b"corrupted archive")
    with pytest.raises(ValueError):
        ArchiveSessions(settings, target, run["snapshot_refs"], key)
    assert target.nodes == [] and target.restores == [] and target.clears == 0


def test_replay_storage_preflight_reports_actual_deduplicated_bytes(fixture):
    settings, run, _key, _target = fixture
    result = package.replay_status(settings, run)
    assert result["available"] and result["evidence_complete"]
    assert result["files"] == 4
    expected = sum(
        path.stat().st_size
        for path in settings.hst_data_dir.rglob("*")
        if path.is_file() and path.parent.name in {"manifests", "graph-archives"}
    )
    assert result["bytes"] == expected


def test_cli_job_inspection_reads_saved_progress_without_exposing_leases(monkeypatch):
    import hst.cli as cli

    store = MemoryAssessmentStore()

    async def prepare():
        saved = await store.create_assessment(title="CLI", purpose="evaluation", definition={}, created_by=1)
        run = await store.enqueue_analysis(
            assessment_id=saved.id,
            assessment_revision=1,
            kind="evaluate",
            inputs={},
            snapshot_refs=[{"snapshot": "100"}],
            engine_version="fixture",
            created_by=1,
        )
        lease = await store.claim_analysis("worker")
        await store.heartbeat_analysis(run.id, lease.lease_token, progress={"evaluated": 4})
        return saved, run

    saved, run = asyncio.run(prepare())
    monkeypatch.setattr(
        cli, "_assessment_store_read", lambda settings, callback: asyncio.run(callback(store))
    )
    response = CliRunner().invoke(cli.app, ["assessments", "jobs", "--assessment", saved.id])
    assert response.exit_code == 0, response.output
    jobs = json.loads(response.output)["jobs"]
    assert jobs[0]["progress"] == {"evaluated": 4}
    assert "lease_token" not in jobs[0] and "checkpoint" not in jobs[0]
    response = CliRunner().invoke(cli.app, ["assessments", "job", run.id])
    assert response.exit_code == 0
    assert json.loads(response.output)["state"] == "running"


def test_portable_preflight_needs_authentication_but_not_matching_local_engine(fixture, monkeypatch):
    settings, run, _key, _target = fixture
    monkeypatch.setattr(service, "engine_version", lambda settings: "different-engine")
    status = package.replay_status(settings, run)
    assert not status["available"] and status["portable_available"]
    (settings.hst_data_dir / crypto.DEK_FILENAME).write_bytes(b"invalid wrapped key")
    status = package.replay_status(settings, run)
    assert not status["portable_available"]
    assert status["evidence_complete"]
    assert (
        status["portable_reason"]
        == "The retained graph archives could not be authenticated with the configured key."
    )
