"""Portable exports keep exact evidence and separate checksums from replay."""

from __future__ import annotations

import hashlib
import json
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hst.app import crypto
from hst.assessment import package, service
from hst.assessment.store import input_digest
from hst.cli import app
from hst.core import Settings, db, grapharchive, manifest, replay


class EmptyGraph:
    def execute_read(self, callback):
        return callback(self)

    def run(self, _query, **_params):
        return []


SIDE_STORE_PATH = "sidestore/rib/synthetic/1000-abcdef.parquet"
SIDE_STORE_BYTES = b"synthetic side-store rows " * 100_000


def fixture(tmp_path: Path, *, side_store: bool = False):
    settings = Settings(hst_data_dir=tmp_path / "estate", hst_secret_key="x" * 40)
    key = crypto.dek(settings)
    archive = grapharchive.write(EmptyGraph(), settings, 1000, key)
    raw = settings.raw_dir / "synthetic" / "host" / "1000-abcdef.json.gz.enc"
    raw.parent.mkdir(parents=True)
    raw.write_bytes(crypto.encrypt(key, b"synthetic payload"))
    sha, size = manifest.file_facts(raw)
    files = [
        manifest.FileEntry(
            kind="raw",
            path=raw.relative_to(settings.hst_data_dir).as_posix(),
            sha256=sha,
            bytes=size,
            source="synthetic",
            host="host",
            run_id="1000-abcdef",
        )
    ]
    if side_store:
        table = settings.hst_data_dir / SIDE_STORE_PATH
        table.parent.mkdir(parents=True)
        table.write_bytes(SIDE_STORE_BYTES)
        sha, size = manifest.file_facts(table)
        files.append(
            manifest.FileEntry(
                kind="sidestore",
                path=SIDE_STORE_PATH,
                sha256=sha,
                bytes=size,
                source="synthetic",
                host="",
                run_id="1000-abcdef",
                table="rib",
            )
        )
    record = manifest.SnapshotManifest(
        snapshot_key=1000,
        kind="full",
        opened="2026-09-08T00:00:00Z",
        published="2026-09-08T00:01:00Z",
        graph_archive=manifest.GraphArchiveEntry(**archive),
        files=files,
    )
    digest = manifest.write(settings, record)
    refs = [{"snapshot": "1000", "manifest_sha256": digest, "estate": "default"}]
    values = {
        "assessment_id": "a1",
        "assessment_revision": 1,
        "kind": "evaluate",
        "inputs": {
            "definition": {"request": {"name": "synthetic"}},
            "analysis": {"kind": "evaluate"},
            "snapshot_refs": refs,
        },
        "snapshot_refs": refs,
        "engine_version": "test-engine",
        "limits": {},
        "input_schema_version": 1,
    }
    run = {
        **values,
        "id": "run-1",
        "input_digest": input_digest(values),
        "state": "completed",
        "result": {"verdict": "not-established", "elapsed_seconds": 1.2},
        "lease_token": "not-exportable",
    }
    return settings, run, raw, key


def test_reference_export_is_exact_and_sanitized(tmp_path):
    _settings, run, _raw, _key = fixture(tmp_path)
    exported = package.export_document(run)
    assert "lease_token" not in exported["run"]
    assert exported["run"]["result"] == run["result"]
    assert exported == package.export_document(run)
    path = tmp_path / "run.json"
    path.write_text(json.dumps(exported))
    assert package.check_package(path)["valid"]
    exported["run"]["inputs"]["analysis"]["kind"] = "repair"
    exported["sha256"] = package._sha({k: v for k, v in exported.items() if k != "sha256"})
    path.write_text(json.dumps(exported))
    with pytest.raises(package.PackageError, match="input digest"):
        package.check_package(path)


def test_portable_contains_closure_and_no_keys(tmp_path):
    settings, run, raw, key = fixture(tmp_path)
    path, key_file = tmp_path / "run.zip", tmp_path / "run.key"
    package.build_portable(settings, run, path, key_file=key_file)
    assert path.stat().st_mode & 0o777 == 0o600
    assert key_file.stat().st_mode & 0o777 == 0o600
    package_key = key_file.read_text().strip()
    with zipfile.ZipFile(path) as bundle:
        names = bundle.namelist()
        assert "evidence/manifests/1000.json" in names
        assert "evidence/graph-archives/1000.graph.enc" in names
        assert f"evidence/{raw.relative_to(settings.hst_data_dir)}" in names
        assert not any("dek" in name or "secret" in name for name in names)
        descriptor = bundle.read("assessment.json")
        assert key.encode() not in descriptor and package_key.encode() not in descriptor
        assert package_key == crypto.package_key(key, json.loads(descriptor)["package_id"])
        assert bundle.read(f"evidence/{raw.relative_to(settings.hst_data_dir)}") == raw.read_bytes()
        archive = settings.hst_data_dir / "graph-archives" / "1000.graph.enc"
        assert bundle.read("evidence/graph-archives/1000.graph.enc") != archive.read_bytes()
    report = package.check_package(path)
    assert report["valid"] and report["format"] == "portable"
    assert report["replay"]["key_included"] is False
    assert report["replay"]["available"] is False


def test_portable_rejects_missing_or_modified_bytes_and_limits(tmp_path):
    settings, run, raw, _key = fixture(tmp_path)
    with pytest.raises(package.PackageError, match="byte limit"):
        package.build_portable(settings, run, tmp_path / "small.zip", max_bytes=1)
    raw.write_bytes(b"changed")
    with pytest.raises(package.PackageError, match="digest or size"):
        package.build_portable(settings, run, tmp_path / "changed.zip")
    raw.unlink()
    with pytest.raises(package.PackageError, match="absent"):
        package.build_portable(settings, run, tmp_path / "missing.zip")


@pytest.mark.parametrize(
    "name", ["evidence/../escape", "/absolute", "evidence/raw/../../escape", "evidence/raw\\escape"]
)
def test_zip_path_traversal_refused_before_extraction(tmp_path, name):
    _settings, run, _raw, _key = fixture(tmp_path)
    path = tmp_path / "hostile.zip"
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("assessment.json", json.dumps(package.export_document(run)))
        bundle.writestr(name, "untrusted")
    with pytest.raises(package.PackageError):
        package.check_package(path)
    assert not (tmp_path / "escape").exists()


def test_zip_symlink_refused(tmp_path):
    _settings, run, _raw, _key = fixture(tmp_path)
    path = tmp_path / "symlink.zip"
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("assessment.json", json.dumps(package.export_document(run)))
        info = zipfile.ZipInfo("evidence/raw/link")
        info.external_attr = 0o120777 << 16
        bundle.writestr(info, "/etc/passwd")
    with pytest.raises(package.PackageError, match="symlink"):
        package.check_package(path)


def test_manifest_external_file_refused_without_reading(tmp_path):
    settings, run, _raw, _key = fixture(tmp_path)
    record = manifest.read(settings, 1000)
    record.files[0].path = "raw/../../outside"
    path = manifest.path_for(settings, 1000)
    path.write_bytes(manifest.canonical_json(record.model_dump(mode="json")))
    new_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    run["snapshot_refs"][0]["manifest_sha256"] = new_sha
    run["input_digest"] = input_digest({k: run[k] for k in package._INPUT_FIELDS})
    with pytest.raises(package.PackageError, match="outside"):
        package.build_portable(settings, run, tmp_path / "outside.zip")


def test_replay_executes_normalized_input_and_detects_semantic_change(tmp_path, monkeypatch):
    settings, run, _raw, _key = fixture(tmp_path)
    path = tmp_path / "run.json"
    path.write_text(json.dumps(package.export_document(run)))
    monkeypatch.setattr(service, "engine_version", lambda _settings: "test-engine")
    called = []

    def execute(_settings, inputs):
        called.append(inputs)
        return {"verdict": "not-established", "elapsed_seconds": 99}

    monkeypatch.setattr(service, "execute", execute)
    result = package.replay_package(settings, path)
    assert called == [run["inputs"]]
    assert result["available"] and result["matches"]
    monkeypatch.setattr(service, "execute", lambda *_: {"verdict": "holds", "elapsed_seconds": 99})
    assert package.replay_package(settings, path)["matches"] is False
    monkeypatch.setattr(service, "engine_version", lambda _: "different-engine")
    assert package.replay_package(settings, path)["available"] is False


def test_retained_replay_missing_evidence_is_unavailable(tmp_path, monkeypatch):
    settings, run, raw, _key = fixture(tmp_path)
    path = tmp_path / "run.json"
    path.write_text(json.dumps(package.export_document(run)))
    monkeypatch.setattr(service, "engine_version", lambda _: "test-engine")
    raw.unlink()
    result = package.replay_package(settings, path)
    assert result["available"] is False
    assert "evidence unavailable" in result["reason"]


def test_cli_check_is_read_only_and_reports_invalid_checksum(tmp_path):
    _settings, run, _raw, _key = fixture(tmp_path)
    path = tmp_path / "run.json"
    exported = package.export_document(run)
    path.write_text(json.dumps(exported))
    runner = CliRunner()
    assert runner.invoke(app, ["assessments", "check", str(path)]).exit_code == 0
    exported["sha256"] = "wrong"
    path.write_text(json.dumps(exported))
    result = runner.invoke(app, ["assessments", "check", str(path)])
    assert result.exit_code == 1
    assert "checksum mismatch" in result.output


def isolated_target(monkeypatch, settings, run):
    """Patch the replay target, the publication and the engine. Return the list of their events."""
    monkeypatch.setattr(service, "engine_version", lambda _: "test-engine")
    events = []

    class Target:
        def run(self, query):
            assert query == "MATCH (n) RETURN count(n) AS count"
            return self

        def single(self):
            return {"count": 0}

    @contextmanager
    def session(selected):
        assert selected.neo4j_uri == "bolt://localhost:19999"
        events.append("empty-target-check")
        yield Target()

    def published(*_args, **kwargs):
        assert kwargs["exact_counts"] == (0, 0)
        assert kwargs["exact_record"].snapshot_key == 1000
        events.append("exact-archive-restored")

    def execute(selected, inputs):
        assert selected.hst_data_dir != settings.hst_data_dir
        assert manifest.digest_of(selected, 1000) == inputs["snapshot_refs"][0]["manifest_sha256"]
        events.append("model-executed")
        return run["result"]

    monkeypatch.setattr(db, "session", session)
    monkeypatch.setattr(replay, "_publish", published)
    monkeypatch.setattr(service, "execute", execute)
    return events


def test_portable_replay_uses_empty_isolated_target_and_real_archives(tmp_path, monkeypatch):
    settings, run, _raw, _key = fixture(tmp_path)
    path, key_file = tmp_path / "portable.zip", tmp_path / "portable.key"
    package.build_portable(settings, run, path, key_file=key_file)
    events = isolated_target(monkeypatch, settings, run)
    report = package.replay_package(settings, path, into="bolt://localhost:19999", package_key_file=key_file)
    assert report["available"] and report["matches"]
    assert events == ["empty-target-check", "exact-archive-restored", "model-executed"]


def test_portable_replay_uses_the_package_key_as_the_data_key_of_the_unpacked_package(tmp_path, monkeypatch):
    settings, run, _raw, _key = fixture(tmp_path)
    path, key_file = tmp_path / "portable.zip", tmp_path / "portable.key"
    package.build_portable(settings, run, path, key_file=key_file)
    isolated_target(monkeypatch, settings, run)
    seen = []

    def execute(selected, _inputs):
        seen.append(crypto.dek(selected))
        return run["result"]

    monkeypatch.setattr(service, "execute", execute)
    report = package.replay_package(settings, path, into="bolt://localhost:19999", package_key_file=key_file)
    assert report["available"] and report["matches"]
    assert seen == [key_file.read_text().strip()]


def test_portable_replay_runs_on_a_host_without_an_operator_key(tmp_path, monkeypatch):
    settings, run, _raw, _key = fixture(tmp_path)
    path, key_file = tmp_path / "portable.zip", tmp_path / "portable.key"
    package.build_portable(settings, run, path, key_file=key_file)
    isolated_target(monkeypatch, settings, run)
    host = settings.model_copy(update={"hst_secret_key": ""})
    report = package.replay_package(host, path, into="bolt://localhost:19999", package_key_file=key_file)
    assert report["available"] and report["matches"]


def test_portable_seals_the_side_store_files_under_the_package_key(tmp_path):
    settings, run, _raw, _key = fixture(tmp_path, side_store=True)
    path, key_file = tmp_path / "portable.zip", tmp_path / "portable.key"
    package.build_portable(settings, run, path, key_file=key_file)
    with zipfile.ZipFile(path) as bundle:
        sealed = bundle.read(f"evidence/{SIDE_STORE_PATH}")
    assert SIDE_STORE_BYTES[:26] not in sealed
    assert crypto.decrypt(key_file.read_text().strip(), sealed) == SIDE_STORE_BYTES
    assert package.check_package(path)["valid"]


def test_portable_replay_reads_the_side_store_files_as_the_manifest_records_them(tmp_path, monkeypatch):
    settings, run, _raw, _key = fixture(tmp_path, side_store=True)
    path, key_file = tmp_path / "portable.zip", tmp_path / "portable.key"
    package.build_portable(settings, run, path, key_file=key_file)
    isolated_target(monkeypatch, settings, run)
    seen = []

    def execute(selected, _inputs):
        seen.append((selected.hst_data_dir / SIDE_STORE_PATH).read_bytes())
        return run["result"]

    monkeypatch.setattr(service, "execute", execute)
    report = package.replay_package(settings, path, into="bolt://localhost:19999", package_key_file=key_file)
    assert report["available"] and report["matches"]
    assert seen == [SIDE_STORE_BYTES]


def test_portable_replay_with_another_key_does_not_open_the_side_store_files(tmp_path, monkeypatch):
    settings, run, _raw, key = fixture(tmp_path, side_store=True)
    path, key_file = tmp_path / "portable.zip", tmp_path / "wrong.key"
    package.build_portable(settings, run, path)
    key_file.write_text(key)
    events = isolated_target(monkeypatch, settings, run)
    report = package.replay_package(settings, path, into="bolt://localhost:19999", package_key_file=key_file)
    assert report["available"] is False
    assert "does not open the side-store files" in report["reason"]
    assert events == []


def test_two_packages_of_one_run_have_different_package_keys(tmp_path):
    settings, run, _raw, key = fixture(tmp_path)
    keys = []
    for name in ("first", "second"):
        key_file = tmp_path / f"{name}.key"
        package.build_portable(settings, run, tmp_path / f"{name}.zip", key_file=key_file)
        keys.append(key_file.read_text().strip())
    assert len({*keys, key}) == 3


@pytest.mark.parametrize("wrong", ["key of another package", "data key"])
def test_portable_replay_refuses_a_key_that_is_not_the_package_key(tmp_path, monkeypatch, wrong):
    settings, run, _raw, key = fixture(tmp_path)
    path, key_file = tmp_path / "portable.zip", tmp_path / "wrong.key"
    package.build_portable(settings, run, path)
    if wrong == "data key":
        key_file.write_text(key)
    else:
        package.build_portable(settings, run, tmp_path / "other.zip", key_file=key_file)
    events = isolated_target(monkeypatch, settings, run)
    report = package.replay_package(settings, path, into="bolt://localhost:19999", package_key_file=key_file)
    assert report["available"] is False
    assert "graph archive authentication" in report["reason"]
    assert events == ["empty-target-check"]


def test_package_sealed_under_the_data_key_is_refused(tmp_path, monkeypatch):
    settings, run, _raw, key = fixture(tmp_path)
    path, key_file = tmp_path / "portable.zip", tmp_path / "data-key"
    key_file.write_text(key)
    document = package.export_document(run)
    document["evidence"] = package._inventory(settings, document, max_bytes=package.MAX_BYTES)
    document["sha256"] = package._sha({k: v for k, v in document.items() if k != "sha256"})
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("assessment.json", json.dumps(document))
        for name in document["evidence"]:
            bundle.write(settings.hst_data_dir / name, f"evidence/{name}")
    monkeypatch.setattr(db, "session", lambda _: pytest.fail("the replay target was accessed"))
    with pytest.raises(package.PackageError, match="not sealed under a package key"):
        package.check_package(path)
    with pytest.raises(package.PackageError, match="not sealed under a package key"):
        package.replay_package(settings, path, into="bolt://localhost:19999", package_key_file=key_file)


def test_package_key_is_derived_again_only_by_the_exporting_deployment(tmp_path):
    settings, run, _raw, _key = fixture(tmp_path / "first")
    path, key_file = tmp_path / "portable.zip", tmp_path / "portable.key"
    package.build_portable(settings, run, path, key_file=key_file)
    assert package.package_key(settings, path) == key_file.read_text().strip()
    other, _run, _raw, _key = fixture(tmp_path / "second")
    with pytest.raises(package.PackageError, match="does not open the package"):
        package.package_key(other, path)
    reference = tmp_path / "run.json"
    reference.write_text(json.dumps(package.export_document(run)))
    with pytest.raises(package.PackageError, match="no package key"):
        package.package_key(settings, reference)


def test_portable_export_keeps_an_existing_key_file_and_removes_the_package(tmp_path):
    settings, run, _raw, _key = fixture(tmp_path)
    path, key_file = tmp_path / "portable.zip", tmp_path / "portable.key"
    key_file.write_text("existing")
    with pytest.raises(FileExistsError):
        package.build_portable(settings, run, path, key_file=key_file)
    assert key_file.read_text() == "existing"
    assert not path.exists()


def test_cli_export_writes_the_package_key_that_the_replay_reads(tmp_path, monkeypatch):
    import asyncio

    import hst.cli as cli

    settings, run, _raw, _key = fixture(tmp_path)
    monkeypatch.setenv("HST_DATA_DIR", str(settings.hst_data_dir))
    monkeypatch.setenv("HST_SECRET_KEY", "x" * 40)

    class Store:
        async def get_analysis_run(self, _run_id):
            return run

    monkeypatch.setattr(
        cli, "_assessment_store_read", lambda _settings, callback: asyncio.run(callback(Store()))
    )
    path, key_file, derived = tmp_path / "portable.zip", tmp_path / "portable.key", tmp_path / "derived.key"
    runner = CliRunner()
    refused = runner.invoke(
        app, ["assessments", "export", "run-1", "--output", str(path), "--package-key-file", str(key_file)]
    )
    assert refused.exit_code == 1 and not path.exists() and not key_file.exists()
    exported = runner.invoke(
        app,
        [
            "assessments",
            "export",
            "run-1",
            "--output",
            str(path),
            "--portable",
            "--package-key-file",
            str(key_file),
        ],
    )
    assert exported.exit_code == 0, exported.output
    assert key_file.read_text().strip() not in exported.output
    assert (
        runner.invoke(app, ["assessments", "package-key", str(path), "--output", str(derived)]).exit_code == 0
    )
    assert derived.read_text() == key_file.read_text()
    assert derived.stat().st_mode & 0o777 == 0o600
    events = isolated_target(monkeypatch, settings, run)
    replayed = runner.invoke(
        app,
        [
            "assessments",
            "replay",
            str(path),
            "--into",
            "bolt://localhost:19999",
            "--package-key-file",
            str(derived),
        ],
    )
    assert replayed.exit_code == 0, replayed.output
    assert events == ["empty-target-check", "exact-archive-restored", "model-executed"]


def test_portable_restore_refuses_live_target_before_graph_access(tmp_path, monkeypatch):
    settings, run, _raw, _key = fixture(tmp_path)
    path, key_file = tmp_path / "portable.zip", tmp_path / "key"
    package.build_portable(settings, run, path, key_file=key_file)
    monkeypatch.setattr(service, "engine_version", lambda _: "test-engine")
    monkeypatch.setattr(db, "session", lambda _: pytest.fail("live database was accessed"))
    with pytest.raises(package.PackageError, match="live twin"):
        package.replay_package(settings, path, into=settings.neo4j_uri, package_key_file=key_file)


def test_cli_prune_stops_when_retention_state_unavailable(monkeypatch):
    import hst.cli as cli

    def unavailable(*_args, **_kwargs):
        raise RuntimeError("missing store")

    monkeypatch.setattr(cli, "_assessment_store_read", unavailable)
    monkeypatch.setattr(db, "session", lambda _: pytest.fail("pruning touched graph without retention state"))
    result = CliRunner().invoke(app, ["prune", "--keep", "2"])
    assert result.exit_code == 1
    assert "retention state" in result.output
