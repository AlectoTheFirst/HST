"""Portable symbolic results preserve exact encrypted proofs without shipping keys."""

import zipfile

import pytest

from hst.app import crypto
from hst.assessment import package
from hst.assessment.result_artifacts import ResultArtifactStore
from hst.assessment.store import input_digest
from hst.core import Settings, grapharchive, manifest


class EmptyGraph:
    def execute_read(self, callback):
        return callback(self)

    def run(self, _query, **_params):
        return []


def test_portable_exact_result_is_verifiable_without_decryption_key(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path / "estate", hst_secret_key="x" * 40)
    key = crypto.dek(settings)
    archive = grapharchive.write(EmptyGraph(), settings, 1000, key)
    record = manifest.SnapshotManifest(
        snapshot_key=1000,
        kind="full",
        opened="2026-09-08T00:00:00Z",
        published="2026-09-08T00:01:00Z",
        graph_archive=manifest.GraphArchiveEntry(**archive),
    )
    digest = manifest.write(settings, record)
    refs = [{"snapshot": "1000", "manifest_sha256": digest, "estate": "default"}]
    reference = ResultArtifactStore(settings.hst_data_dir, key).publish(
        b'{"exact_count":"340282366920938463463374607431768211456"}',
        estate="default",
        manifest_sha256=digest,
        request_id="b" * 64,
        evidence={"items": [{"artifact_root": "before/lower"}]},
    )
    values = {
        "assessment_id": "a1",
        "assessment_revision": 1,
        "kind": "evaluate",
        "inputs": {"definition": {}, "analysis": {"kind": "evaluate"}, "snapshot_refs": refs},
        "snapshot_refs": refs,
        "engine_version": "synthetic-symbolic",
        "limits": {},
        "input_schema_version": 1,
    }
    run = {
        **values,
        "id": "run-1",
        "input_digest": input_digest(values),
        "state": "completed",
        "result": {"symbolic": {"artifact_ref": reference}, "result_schema": 2},
    }
    target, key_file = tmp_path / "run.zip", tmp_path / "run.key"
    package.build_portable(settings, run, target, key_file=key_file)
    assert package.check_package(target)["valid"]
    restored = tmp_path / "restored"
    restored.mkdir()
    package._unpack(target, restored, max_bytes=package.MAX_BYTES)
    restored_store = ResultArtifactStore(restored, key_file.read_text().strip())
    assert restored_store.load_evidence(reference)["items"] == [{"artifact_root": "before/lower"}]
    with pytest.raises(crypto.SecretKeyError):
        ResultArtifactStore(restored, key).load(reference)
    with zipfile.ZipFile(target) as bundle:
        assert f"evidence/{reference['path']}" in bundle.namelist()
        assert key.encode() not in bundle.read("assessment.json")
        assert not any("dek" in name for name in bundle.namelist())
