"""The walk and the evidence row of a router whose BGP peers' routes are not collected and
whose collected routing table is complete (tests/test_bgp_peer_supply_calibrated.py).

A flow to the internet passes with no MODEL_SCOPE_INCOMPLETE gap. A flow into a prefix
the router learned from a peer, while no path is collected, is not decided, and the row's
`gap_detail` names the prefix; it is not answered by the default route.
"""

from __future__ import annotations

import importlib
import os
from types import SimpleNamespace

import pytest

from hst.analysis_model.compile import compile_model
from hst.analysis_model.network import normalize_network
from hst.assessment import symbolic_results
from hst.assessment.symbolic_evaluation import member_packets
from hst.impact.symbolic_walk import walk
from hst.results.words import FORBIDDEN_WORDS, _contains_word
from hst.symbolic import HeaderSchema, SymbolicManager

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")


def _row(net, destination):
    """(passes, not decided, gap codes, the before-side gap rows) of one flow from the LAN."""
    from tests.test_demo_enterprise_vyos import _estate
    from tests.test_symbolic_masquerade import oslo_request
    from tests.test_symbolic_vyos_service_ports import _inventory

    request = oslo_request(destination=destination)
    model = normalize_network(net, _inventory(_estate(1)), request, request.members[0], "estate")
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        packets = member_packets(manager, request, request.members[0])
        compiled = compile_model(model, manager, packets.known_fields)
        result = walk(compiled, packets, request_id="core1")
        passes = result.bounds.upper.subtract(
            result.bounds.lower
        ).is_empty() and result.bounds.lower.equivalent(result.bounds.universe)
        undecided = not result.bounds.upper.subtract(result.bounds.lower).is_empty()
        answer = SimpleNamespace(members={"web": result}, evidence=None)
        rows = symbolic_results._evidence(answer, answer)["items"]  # type: ignore[arg-type]
        gaps = [row for row in rows if row["side"] == "before" and row["kind"] == "gap"]
        return passes, undecided, set(result.gap_refs), gaps


@pytest.mark.parametrize("case", ["none", "accepted", "received"])
def test_a_flow_to_the_internet_passes_with_no_scope_gap(case):
    from tests.test_bgp_peer_supply_calibrated import INTERNET, core1

    passes, undecided, codes, rows = _row(core1(case), INTERNET)
    assert passes and not undecided
    assert "MODEL_SCOPE_INCOMPLETE" not in codes
    assert not [row for row in rows if row["gap_code"] == "MODEL_SCOPE_INCOMPLETE"]


def test_a_flow_into_a_learned_prefix_with_no_path_collected_is_not_decided_and_names_it():
    from tests.test_bgp_peer_supply_calibrated import INSIDE_LEARNED, core1

    passes, undecided, codes, rows = _row(core1("none"), INSIDE_LEARNED)
    assert not passes and undecided
    assert "MODEL_SCOPE_INCOMPLETE" in codes
    # the routing state names the prefix; the hop the default route leaves by is a gap of
    # its own (a private address sent out by the default route), with no text
    details = [
        row["gap_detail"]
        for row in rows
        if row["gap_code"] == "MODEL_SCOPE_INCOMPLETE" and "gap_detail" in row
    ]
    assert details
    for detail in details:
        assert "10.96.0.0/12" in detail
        assert "BGP peer" not in detail
        assert not [word for word in FORBIDDEN_WORDS if _contains_word(detail.lower(), word)], detail


def test_with_the_table_not_complete_the_flow_to_the_internet_stays_not_decided():
    from tests.test_bgp_peer_supply_calibrated import INTERNET, core1

    passes, undecided, codes, rows = _row(core1("none", coverage="partial"), INTERNET)
    assert not passes and undecided
    assert "MODEL_SCOPE_INCOMPLETE" in codes
    assert any("BGP peer" in row.get("gap_detail", "") for row in rows)
