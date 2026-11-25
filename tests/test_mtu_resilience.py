"""Failure scenarios reevaluate the surviving egress's own MTU."""

from tests.test_mtu_assessment import network, request, wire

from hst.assessment.resilience import apply_failures
from hst.impact.evaluate import answer


def test_failure_reroutes_to_different_mtu_without_inventing_positive_proof(monkeypatch):
    wire(monkeypatch)
    before = network({"if:r1-eth1": 9000, "if:r1-eth2": 1500})
    requirement = request(1600)
    baseline = answer(before, requirement)
    assert baseline.upper and not baseline.lower
    changed = apply_failures(before, [{"kind": "interface", "uid": "if:r1-eth1"}])
    result = answer(changed, requirement)
    assert not result.upper
    assert any(
        s.kind == "packet-exceeds-limit"
        for m in result.members.values()
        for e in m.explanations
        for s in e.steps
    )
    assert changed.interfaces == before.interfaces
