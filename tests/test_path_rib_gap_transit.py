# ruff: noqa: F811

import pytest
from tests.test_path_multihop import _two_routers
from tests.test_path_trace import GW, _FailedRib, _route, graph  # noqa: F401

from hst import path


class _OneDeviceRib(_FailedRib):
    """r1's RIB table carries `outcome`; r2 records no RIB at all."""

    def __init__(self, outcome):
        self.outcome = outcome

    def coverage(self, device_uid):
        return self.outcome if device_uid == "dev:r1" else None

    def has_rows(self, device_uid):
        return device_uid == "dev:r1" and self.outcome == "complete"


def _r1_routes_to_r2(graph):
    _two_routers(graph)
    graph.routes["vrf:r1"] = [
        _route("10.0.12.0/30", egress="eth0", kind="ORIGINATES"),
        _route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2"),
    ]


@pytest.mark.parametrize("outcome", ["failed", "partial", "unknown"])
def test_a_recorded_rib_gap_on_a_transit_device_marks_the_path(graph, outcome):
    _r1_routes_to_r2(graph)

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], rib=_OneDeviceRib(outcome))

    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert all(leg["indeterminate"] for leg in result["legs"])
    gaps = [w for w in result["warnings"] if "RIB of r1" in w]
    assert len(gaps) == 1
    assert "routed on graph edges only" in gaps[0]


def test_a_complete_rib_on_a_transit_device_adds_no_warning(graph):
    _r1_routes_to_r2(graph)

    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW], rib=_OneDeviceRib("complete"))

    # the stand-in holds no row for the static route, which the routing gate
    # reports on its own; a complete outcome is no RIB gap
    assert result["legs"][0]["verdict"] == "egress via r2-eth5"
    assert not [w for w in result["warnings"] if "not consulted" in w]
    assert not any("not consulted" in (leg.get("indeterminate_reason") or "") for leg in result["legs"])
