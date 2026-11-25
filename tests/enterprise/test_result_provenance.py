"""Raw observation provenance survives retained proof pagination."""

import json
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from hst.analysis_model.evidence import (
    CaptureOutcome,
    ClockQuality,
    EvidencePolicy,
    EvidenceWindow,
    RevisionEvidence,
    evaluate_evidence,
)
from hst.analysis_model.model import ChoiceAssignment, StateKey
from hst.assessment.result_artifacts import ResultArtifactStore
from hst.assessment.result_page import execute_page
from hst.assessment.symbolic_provenance import page_observations
from hst.assessment.symbolic_results import exact_evidence
from hst.policy.ir import ExecutionContext


def test_observation_producers_are_scoped_deduplicated_and_retained(tmp_path, monkeypatch):
    from hst.app import crypto

    instant = datetime(2026, 9, 13, tzinfo=UTC)
    window = EvidenceWindow(
        subject="fw:one",
        source="gateway",
        section="installation",
        capture_start=instant,
        capture_end=instant,
        observation_time=instant,
        outcome=CaptureOutcome.PARTIAL,
        clock_quality=ClockQuality.TRUSTED,
        revision=RevisionEvidence("configured", "installed", ("raw:revision",)),
        producer_ids=("raw:gateway",),
    )
    evidence = evaluate_evidence(
        (window, replace(window, subject="fw:other", producer_ids=("raw:unrelated",))),
        EvidencePolicy(),
        analysis_time=instant,
    )
    state = StateKey("routing", ExecutionContext("estate", "manager", "domain", "fw:one", "vrf", 4))
    gap = SimpleNamespace(state=state, code="partial-evidence", conservative=True)
    result = SimpleNamespace(
        by_choice=(
            SimpleNamespace(
                assignment=ChoiceAssignment("only"),
                terminal_reaches=(),
                scoped_gaps=(gap,),
            ),
        ),
        manifest_digest="a" * 64,
        model_fingerprint="model",
        request_id="b" * 64,
    )
    answer = SimpleNamespace(evidence=evidence, members={"service": result})
    proof = exact_evidence(answer, answer)
    assert proof["count"] == 2
    assert len(proof["observations"]) == 1
    [identity] = proof["observations"]
    assert all(item["observation_refs"] == [identity] for item in proof["items"])
    assert all(item["observation_scope"] == "context" for item in proof["items"])
    assert all(item["packet_scope"] == "conservative" for item in proof["items"])
    observation = proof["observations"][identity]
    assert observation["producer_ids"] == ["raw:gateway"]
    assert observation["revision"]["producer_ids"] == ["raw:revision"]
    assert observation["observation_time"] == instant.isoformat()

    key = Fernet.generate_key().decode()
    monkeypatch.setattr(crypto, "dek", lambda _: key)
    store = ResultArtifactStore(tmp_path, key)
    reference = store.publish(
        b"{}",
        estate="estate",
        manifest_sha256="a" * 64,
        request_id="b" * 64,
        evidence=proof,
    )
    page = execute_page(
        SimpleNamespace(hst_data_dir=tmp_path),
        {
            "artifact_ref": reference,
            "snapshot_refs": [{"estate": "estate", "manifest_sha256": "a" * 64}],
            "bucket": "evidence",
            "offset": 1,
            "limit": 1,
        },
    )
    assert page["observations"] == proof["observations"]
    assert page["items"] == json.loads(json.dumps(proof["items"][1:]))
    assert page["next_offset"] is None


def test_page_rejects_a_dangling_observation_reference():
    with pytest.raises(ValueError, match="missing observation"):
        page_observations({"observations": {}}, [{"observation_refs": ["missing"]}])
