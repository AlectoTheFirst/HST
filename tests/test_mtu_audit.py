"""Neighbor and aggregate differences do not assert an outage."""

from tests.test_mtu_budget import request, stage

from hst.assessment.mtu import audit_adjacency, audit_members, audit_neighbors, audit_stages
from hst.core.mtu import MtuResolution


def resolution(value):
    return MtuResolution(constraints=stage(value).constraints)


def test_difference_is_informational_and_lower_bounds_not_compared_as_ceilings():
    a, b = resolution(1500), resolution(9000)
    findings = audit_neighbors(a, b)
    assert findings[0].severity == "info"
    b.constraints[0].bound_kind = "acceptance_lower_bound"
    assert audit_neighbors(a, b) == []


def test_inactive_member_difference_is_readiness_only():
    findings = audit_members([("a", True, resolution(9000)), ("b", False, resolution(1500))])
    assert findings[0].scope == "member_readiness"
    assert findings[0].code == "MTU_LAG_INCONSISTENCY"


def test_target_audit_uses_path_size_semantics():
    assert audit_stages([stage()], request()) == []
    findings = audit_stages([stage()], request(1501))
    assert findings[0].code == "MTU_CAPACITY_DEFICIT"


def test_missing_neighbor_evidence_is_not_a_clean_empty_audit():
    unknown = MtuResolution(gaps=["MTU_NOT_CAPTURED"])
    findings = audit_neighbors(resolution(1500), unknown)
    assert findings[0].code == "MTU_NOT_CAPTURED"


def test_adjacency_discrepancy_is_risk_not_session_failure():
    findings = audit_adjacency(resolution(1500), resolution(9000))
    assert findings[0].code == "MTU_ADJACENCY_DISCREPANCY"
    assert findings[0].severity == "risk"
