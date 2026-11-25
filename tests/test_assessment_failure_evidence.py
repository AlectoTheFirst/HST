"""Independent graph/manifest joins authenticate domain evidence, not request labels."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from hst import path
from hst.assessment.failure_evidence import validate_failure_evidence
from hst.core.manifest import SnapshotManifest


@pytest.fixture
def evidence(monkeypatch):
    manifest = SnapshotManifest.model_validate(
        {
            "snapshot_key": 1000,
            "kind": "full",
            "opened": "then",
            "published": "now",
            "sources": [{"name": "inventory", "type": "nautobot", "status": "ok", "config_sha256": "a"}],
            "devices": [
                {
                    "source": "inventory",
                    "host": "controller",
                    "outcome": "collected",
                    "effective_run": "900-abcdef",
                    "fetch_started_ms": 900,
                    "fetch_finished_ms": 950,
                    "device_uids": ["dev:a"],
                    "sections": {"domains": {"status": "ok"}},
                }
            ],
            "files": [
                {
                    "kind": "raw",
                    "path": "raw/evidence",
                    "sha256": "d",
                    "bytes": 10,
                    "source": "inventory",
                    "host": "controller",
                    "run_id": "900-abcdef",
                }
            ],
        }
    )
    props = {
        "source": "inventory",
        "collector": "nautobot",
        "origin": "observed",
        "_sources": ["inventory"],
        "_run_id": "900-abcdef",
        "evidence_host": "controller",
        "evidence_section": "domains",
        "evidence_reference": "raw/evidence",
        "observed_ms": 920,
        "valid_from_ms": 900,
        "valid_until_ms": 1100,
    }
    rows = [
        {"uid": "dev:a", "labels": ["Device"], "props": deepcopy(props)},
        {
            "uid": "domain:power",
            "labels": ["FailureDomain"],
            "props": props,
            "members": [{"uid": "dev:a", "props": {"_run_id": "900-abcdef"}}],
        },
    ]
    monkeypatch.setattr(path, "_read", lambda *args, **kwargs: rows)
    target = [{"id": "a", "uid": "dev:a", "kind": "device"}]
    domain = [
        {
            "id": "power",
            "uid": "domain:power",
            "members": ["a"],
            "source": "ignored claim",
            "evidence_status": "observed",
        }
    ]
    return SimpleNamespace(cts=1000), manifest, target, domain, rows


def test_real_recorded_membership_is_authenticated(evidence):
    session, manifest, target, domain, _ = evidence
    result = validate_failure_evidence(session, manifest, target, domain)
    assert result["power"]["evidence_complete"] and result["a"]["evidence_complete"]
    assert result["power"]["evidence_refs"][0]["collector"] == "nautobot"
    assert not result["_summary"]["independent_diversity_established"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("origin", "operator"),
        ("collector", "invented"),
        ("valid_until_ms", 999),
        ("valid_until_ms", 1000),
        ("evidence_reference", "invented"),
        ("observed_ms", 800),
        ("evidence_section", "absent"),
    ],
)
def test_claimed_observation_cannot_override_missing_recorded_evidence(evidence, field, value):
    session, manifest, target, domain, rows = evidence
    rows[1]["props"][field] = value
    assert not validate_failure_evidence(session, manifest, target, domain)["power"]["evidence_complete"]


def test_manual_source_is_not_an_independent_observation(evidence):
    session, manifest, target, domain, rows = evidence
    manifest.sources[0].type = "manual"
    rows[1]["props"]["collector"] = "manual"
    result = validate_failure_evidence(session, manifest, target, domain)
    assert not result["power"]["provenance_validated"]


def test_hidden_member_or_mismatched_edge_run_prevents_membership_proof(evidence):
    session, manifest, target, domain, rows = evidence
    rows[1]["members"].append({"uid": "dev:unreported", "props": {"_run_id": "other"}})
    result = validate_failure_evidence(session, manifest, target, domain)
    assert not result["power"]["evidence_complete"]
    assert len(result["power"]["missing"]) == 2


def test_manifest_graph_snapshot_mismatch_is_rejected(evidence):
    _, manifest, target, domain, _ = evidence
    with pytest.raises(ValueError, match="same pinned snapshot"):
        validate_failure_evidence(SimpleNamespace(cts=999), manifest, target, domain)


@pytest.mark.parametrize("outcome", ["carried", "failed"])
def test_target_on_a_carried_device_is_not_validated(evidence, outcome):
    session, manifest, target, domain, _ = evidence
    manifest.devices[0].carried = True
    manifest.devices[0].outcome = outcome
    result = validate_failure_evidence(session, manifest, target, domain)
    assert not result["a"]["provenance_validated"]
    assert not result["a"]["evidence_complete"]
    assert any("carried from an earlier run" in m for m in result["a"]["missing"])


def test_target_on_a_device_fetched_and_found_unchanged_is_validated(evidence):
    # this run fetched the device and the payload hash matched: no new raw file,
    # so the manifest marks it carried, but it was observed in this snapshot
    session, manifest, target, domain, _ = evidence
    manifest.devices[0].carried = True
    manifest.devices[0].outcome = "unchanged"
    manifest.devices[0].verified_started_ms = 900
    manifest.devices[0].verified_ms = 950
    result = validate_failure_evidence(session, manifest, target, domain)
    assert result["a"]["provenance_validated"] and result["a"]["evidence_complete"]
    assert result["a"]["missing"] == []
