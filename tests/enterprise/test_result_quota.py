"""A full result store preserves saved proofs and rejects further growth."""

import pytest
from cryptography.fernet import Fernet

from hst.assessment.result_artifacts import ResultArtifactStore


def test_result_quota_preserves_existing_artifact_and_allows_idempotent_publish(tmp_path):
    key = Fernet.generate_key().decode()
    scope = {"estate": "synthetic", "manifest_sha256": "a" * 64, "request_id": "b" * 64}
    store = ResultArtifactStore(tmp_path, key)
    reference = store.publish(b"{}", **scope)
    size = (tmp_path / reference["path"]).stat().st_size
    full = ResultArtifactStore(tmp_path, key, max_bytes=size)
    assert full.publish(b"{}", **scope) == reference
    with pytest.raises(ValueError, match="quota exceeded"):
        full.publish(b'{"different":true}', **scope)
    assert full.load(reference) == b"{}"
    assert len(list((tmp_path / "analysis-results").iterdir())) == 1
