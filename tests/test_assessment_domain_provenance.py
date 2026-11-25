"""Operator provenance labels cannot authenticate independent failure domains."""

from hst.assessment.resilience import search_resilience
from hst.assessment.search import HOLDS, UNKNOWN


def test_forged_observed_source_is_retained_but_not_validated():
    targets = [{"id": "router", "kind": "device", "uid": "device:router"}]
    domains = [
        {
            "id": "power",
            "members": ["router"],
            "source": "claimed-independent-power-survey",
            "evidence_status": "observed",
        }
    ]
    result = search_resilience(targets, domains, lambda _: HOLDS)
    domain = result["expanded_domains"]["power"]
    assert domain["supplied_provenance"] == {
        "source": "claimed-independent-power-survey",
        "evidence_status": "observed",
    }
    assert not domain["provenance_validated"] and not domain["evidence_complete"]
    assert not result["domain_coverage_established"]
    assert not result["independent_diversity_established"]
    assert result["evidence_validation"]["verdict"] == UNKNOWN
    assert all(not t["evaluation"]["domain_evidence_complete"] for t in result["trials"])
    assert result["survives_all_single_failures"]


def test_empty_domains_do_not_vacuously_establish_diversity():
    targets = [{"id": "router", "kind": "device", "uid": "device:router"}]
    result = search_resilience(targets, [], lambda _: HOLDS)
    assert not result["domain_coverage_established"]
    assert not result["independent_diversity_established"]
    assert result["evidence_validation"]["verdict"] == UNKNOWN
    assert "declared failure universe" in result["scope"]
