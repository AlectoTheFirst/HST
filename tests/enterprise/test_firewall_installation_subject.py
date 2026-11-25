"""An observation envelope cannot relabel evidence about another policy."""

from dataclasses import replace

from tests.enterprise.test_vsx import NOW, _expectation, _instance, _observation, _window

from hst.analysis_model.evidence import EvidencePolicy
from hst.core.firewall_read import installation_predicate
from hst.policy.ir import Unknown


def test_evidence_subject_must_match_installed_policy():
    instance = _instance()
    observation = _observation(instance, replace(_window(), subject="other-policy"))
    result = installation_predicate(
        _expectation(instance), (observation,), analysis_time=NOW, evidence_policy=EvidencePolicy()
    )
    assert isinstance(result, Unknown)
    assert result.code == "INSTALLATION_SUBJECT_MISMATCH"
