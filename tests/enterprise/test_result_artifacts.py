"""Exact saved results survive cache eviction and enforce their recorded scope."""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.fernet import Fernet

from hst.assessment.result_artifacts import ResultArtifactStore, references


def test_durable_result_round_trip_and_idempotent_publication(tmp_path):
    store = ResultArtifactStore(tmp_path, Fernet.generate_key().decode())
    artifact = json.dumps(
        {"complete": True, "exact_count": str(2**128)}, sort_keys=True, separators=(",", ":")
    ).encode()
    scope = {"estate": "synthetic", "manifest_sha256": "a" * 64, "request_id": "b" * 64}
    ref = store.publish(artifact, **scope)
    assert store.load(ref) == artifact
    assert store.publish(artifact, **scope) == ref
    assert ref["artifact_sha256"] == hashlib.sha256(artifact).hexdigest()
    assert references({"trials": [{"symbolic": {"artifact_ref": ref}}, {"artifact": ref}]}) == (ref,)
    assert len(list((tmp_path / "analysis-results").iterdir())) == 1


def test_result_scope_and_path_cannot_be_substituted(tmp_path):
    store = ResultArtifactStore(tmp_path, Fernet.generate_key().decode())
    ref = store.publish(b"{}", estate="synthetic", manifest_sha256="a" * 64, request_id="b" * 64)
    for replacement in ({"estate": "another"}, {"manifest_sha256": "c" * 64}, {"path": "../outside"}):
        with pytest.raises(ValueError):
            store.load({**ref, **replacement})


def test_result_directory_symlink_is_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "analysis-results").symlink_to(outside, target_is_directory=True)
    store = ResultArtifactStore(tmp_path, Fernet.generate_key().decode())
    with pytest.raises(ValueError, match="symlink"):
        store.publish(b"{}", estate="synthetic", manifest_sha256="a" * 64, request_id="b" * 64)
