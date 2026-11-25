"""Candidate budgeting does not reject large rule-position universes."""

from hst.assessment.symbolic_repair import generate_candidates
from hst.path.addrsets import _intervals

SCOPE = {
    "source": ["192.0.2.0/24"],
    "destination": ["198.51.100.1"],
    "protocols": ["tcp"],
    "ports": ["443"],
}


def test_candidate_generation_caps_work_without_claiming_complete_search():
    rows = [
        {
            "uid": f"r:{index}",
            "pos": index,
            "action": "accept",
            "src_any": True,
            "dst_any": True,
            "svc_any": True,
        }
        for index in range(6000)
    ]
    result = generate_candidates(
        {"rb": rows},
        {"rb": "device"},
        ["fw_rule.add"],
        SCOPE,
        max_candidates=3,
    )
    assert len(result["candidates"]) == 3
    assert result["generated_count"] == 12002
    assert result["generation_truncated"] and not result["universe_complete"]
    assert all(
        _intervals(item["intents"][0]["params"]["source"]) == _intervals(SCOPE["source"])
        for item in result["candidates"]
    )


def test_cancelled_generation_does_not_claim_complete_universe():
    result = generate_candidates(
        {"rb": []},
        {"rb": "device"},
        ["fw_rule.add"],
        SCOPE,
        max_candidates=3,
        cancelled=lambda: True,
    )
    assert result["candidates"] == []
    assert not result["generated_count_complete"] and not result["universe_complete"]
