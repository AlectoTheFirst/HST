"""A simulation run's coverage includes its protections: a protection
evaluated with missing evidence or gaps leaves the run partial."""

from hst.app.routes.analysis_sessions import _coverage


def _run(*protections: dict) -> dict:
    return {
        "snapshot": {"snapshot": "4000"},
        "simulation": {"changed_devices": ["r1"]},
        "protected": [{"desired": "holds", "reference": {}, "result": item} for item in protections],
    }


DECIDED = {"missing_evidence": [], "gaps": [], "model_errors": []}


def test_a_simulation_whose_protections_are_decided_is_complete():
    assert _coverage(_run()) == "complete"
    assert _coverage(_run(DECIDED, DECIDED)) == "complete"


def test_a_protection_with_missing_evidence_leaves_the_simulation_partial():
    unserved = {**DECIDED, "missing_evidence": ["no interface in the model serves the source addresses"]}
    assert _coverage(_run(DECIDED, unserved)) == "partial"


def test_a_protection_with_gaps_leaves_the_simulation_partial():
    gapped = {**DECIDED, "gaps": [{"device": "r1", "reason": "no rulebase"}]}
    assert _coverage(_run(gapped)) == "partial"
