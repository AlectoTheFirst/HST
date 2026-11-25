"""The path call and the impact call on one snapshot whose computed and
observed RIB disagree.

The snapshot is expressed once, as data, and handed to both engines: the
static as the graph's STATIC_ROUTE edge and as `RibInput.static`, the observed
row as the side store's lpm answer and as `RibInput.observed_rib`.
"""

from dataclasses import replace

import pytest
from tests import test_impact_evaluate as estate
from tests.test_path_trace import FakeGraph, _FakeRib, _route, _src_row

from hst import path
from hst.simul import rib

PREFIX = "203.0.113.0/24"
CONFIGURED_NEXT_HOP = "10.0.1.2"  # the static's next hop, from config
OBSERVED_NEXT_HOP = "10.0.2.2"  # what the device's RIB holds for the prefix

GW = {
    "cidr": "10.0.0.0/24",
    "l3dom": "home",
    "if_uid": "if:r1-eth0",
    "if_name": "eth0",
    "dev_uid": estate.R1,
    "dev_name": "r1",
}


def _observed_rib_row():
    return {
        "prefix": PREFIX,
        "next_hop": OBSERVED_NEXT_HOP,
        "interface": "eth2",
        "protocol": "static",
        "metric": None,
        "prefixlen": 24,
        "af": 4,
    }


def _impact_input():
    """The observed RIB differs from the computed one in the prefix's next hop."""
    inp = estate._routing(bgp=False, static=[estate._static(PREFIX, CONFIGURED_NEXT_HOP)])
    observed: dict[str, list[dict]] = {}
    for row in rib.compute(inp).rib:
        observed.setdefault(str(row["context_uid"]), []).append(dict(row))
    for row in observed[estate.VRF_R1]:
        if row["prefix"] == PREFIX:
            row["next_hop"] = OBSERVED_NEXT_HOP
    return replace(inp, observed_rib=observed, rib_coverage=dict.fromkeys(observed, "complete"))


@pytest.fixture()
def graph(monkeypatch):
    g = FakeGraph()
    g.sources = [_src_row()]
    g.default_table = {"uid": estate.VRF_R1}
    g.routes = {estate.VRF_R1: [_route(PREFIX, egress="eth1", next_hop=CONFIGURED_NEXT_HOP)]}
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


def test_the_impact_call_reports_the_disagreement_as_a_model_error():
    result = rib.compute(_impact_input())

    mismatches = [e for e in result.model_errors if e["kind"] == "rib-route-mismatch"]
    assert mismatches
    assert all(str(e["subject"]).endswith(f"/{PREFIX}") for e in mismatches)
    assert any(
        CONFIGURED_NEXT_HOP in str(e["detail"]) and OBSERVED_NEXT_HOP in str(e["detail"]) for e in mismatches
    )


def test_the_path_call_reports_the_disagreement_beside_its_answer(graph):
    """An observed row outranks a config-only static."""
    result = path.trace(
        None, "10.0.0.5", "203.0.113.10", gateways=[GW], rib=_FakeRib(lpm_rows=[_observed_rib_row()])
    )

    assert len(result["legs"]) == 1
    assert result["legs"][0]["next_hop"] == OBSERVED_NEXT_HOP
    assert any(
        f"{PREFIX}: the config-only static route via {CONFIGURED_NEXT_HOP} is outranked" in n
        for n in result["notes"]
    )


def test_the_path_call_reports_a_static_the_rib_does_not_hold_at_all(graph):
    """The leg that follows the static is indeterminate."""
    shorter = _observed_rib_row() | {"prefix": "203.0.113.0/23", "prefixlen": 23}

    result = path.trace(None, "10.0.0.5", "203.0.113.10", gateways=[GW], rib=_FakeRib(lpm_rows=[shorter]))

    assert result["legs"][0]["cidr"] == PREFIX
    assert result["legs"][0]["indeterminate"] is True
    assert any(
        f"{PREFIX} is a config-only static route via {CONFIGURED_NEXT_HOP}" in w
        and f"the RIB selects 203.0.113.0/23 via {OBSERVED_NEXT_HOP}" in w
        for w in result["warnings"]
    )
