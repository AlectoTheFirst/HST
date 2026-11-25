"""Saved proof metadata survives display truncation and shares artifact integrity."""

from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from hst.assessment.result_artifacts import ResultArtifactStore


def test_complete_proof_index_is_authenticated_with_exact_sets(tmp_path):
    store = ResultArtifactStore(tmp_path, Fernet.generate_key().decode())
    scope = {"estate": "synthetic", "manifest_sha256": "a" * 64, "request_id": "b" * 64}
    evidence = {
        "count": 101,
        "truncated": False,
        "items": [{"artifact_root": f"before/member/service/choice/0/terminal/{i}"} for i in range(101)],
    }
    reference = store.publish(b"{}", **scope, evidence=evidence)
    assert store.load_evidence(reference) == evidence
    assert store.load(reference) == b"{}"
    changed = store.publish(b"{}", **scope, evidence={**evidence, "count": 102})
    assert changed["artifact_sha256"] == reference["artifact_sha256"]
    assert changed["identity"] != reference["identity"]
    with pytest.raises(ValueError, match="scope"):
        store.load_evidence({**reference, "request_id": "c" * 64})


def test_proof_page_can_read_beyond_the_display_limit(tmp_path, monkeypatch):
    from hst.app import crypto
    from hst.assessment.result_page import execute_page

    key = Fernet.generate_key().decode()
    monkeypatch.setattr(crypto, "dek", lambda _settings: key)
    store = ResultArtifactStore(tmp_path, key)
    reference = store.publish(
        b"{}",
        estate="synthetic",
        manifest_sha256="a" * 64,
        request_id="b" * 64,
        evidence={"items": [{"artifact_root": str(i)} for i in range(101)]},
    )
    result = execute_page(
        SimpleNamespace(hst_data_dir=tmp_path),
        {
            "artifact_ref": reference,
            "snapshot_refs": [{"estate": "synthetic", "manifest_sha256": "a" * 64}],
            "bucket": "evidence",
            "offset": 100,
            "limit": 1,
        },
    )
    assert result["count"] == 101
    assert result["items"] == [{"artifact_root": "100"}]
    assert result["next_offset"] is None
