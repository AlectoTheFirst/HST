"""An exclude rule on the carrier packet whose match is not decided marks the leg."""

# ruff: noqa: F811

from tests.test_path_nat import _carrier_graph, _carrier_snat_rule
from tests.test_path_trace import GW, _FakeRib, _route, _src_row, _store_row, graph  # noqa: F401

from hst import path


def test_an_undecided_exclude_rule_on_the_carrier_marks_the_leg(graph):
    """The tunnel's endpoint port was not collected, so the port-scoped
    exclude rule cannot be decided for the carrier packet."""
    _carrier_graph(graph, endpoint_port=None)
    graph.nat = [_carrier_snat_rule(orig_dst_port="51820", exclude=True)]

    result = path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])

    leg = result["legs"][0]
    assert leg["indeterminate"]
    assert "snat" not in leg["carrier"]
    assert any("carrier sNAT rule 20 not determinable" in w for w in result["warnings"])


def _rib():
    return _FakeRib(lpm_rows=[_store_row("0.0.0.0/0", "192.0.2.2", interface="eth3")])


def test_an_unheld_aggregate_leg_is_worded_as_an_aggregate(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.20.0.0/16", kind="AGGREGATE", discard="blackhole")]}

    result = path.trace(None, "10.0.0.5", "10.20.5.5", gateways=[GW], rib=_rib())

    leg = result["legs"][0]
    assert leg["indeterminate_reason"] == (
        "10.20.0.0/16 is a BGP aggregate (no contributing route may be present) "
        "that the RIB of table default does not hold"
    )
    assert not [w for w in result["warnings"] if "config-only static" in w]
    assert any(
        "10.20.0.0/16 is a BGP aggregate (no contributing route may be present)" in w
        for w in result["warnings"]
    )


def test_an_unheld_connected_leg_is_worded_as_a_connected_prefix(graph):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [
            _route("192.168.50.0/24", kind="ORIGINATES"),
            _route("192.168.10.0/24", kind="ORIGINATES"),
            _route("0.0.0.0/0", next_hop="192.0.2.2"),
        ]
    }
    # the store holds the connected row of an up LAN: its writer records
    # connected routes for the table, so the absent row is evidence
    rib = _FakeRib(
        lpm_rows=[_store_row("0.0.0.0/0", "192.0.2.2", interface="eth3")],
        overlapping_rows=[_store_row("192.168.10.0/24", None, interface="eth1.10", protocol="connected")],
    )

    result = path.trace(None, "10.0.0.5", "192.168.50.20", gateways=[GW], rib=rib)

    leg = next(leg for leg in result["legs"] if leg["cidr"] == "192.168.50.0/24")
    assert leg["indeterminate_reason"].startswith(
        "192.168.50.0/24 is a connected prefix (its interface may be down or disabled) that the RIB of table"
    )
    assert not [w for w in result["warnings"] if "config-only static" in w]
