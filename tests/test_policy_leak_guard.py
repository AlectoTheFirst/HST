"""The leak guard analysis of a drop rule (`path/leak_guard.py`) on the VyOS
router of `tests/support/policy_route_graph.py`: policy route VPN-PBR rule 30
sends the tunnel-b-download sources on eth1.10 into table 144, whose default
route leaves through wg44, and LAN-WAN rule 10 drops the same sources leaving
by eth0, the interface of the main table's default route.

The router is the collector's own batch, answered by `BatchGraph`;
tests/test_policy_leak_guard_db.py runs the same analysis on the batch loaded
into Neo4j.
"""

from __future__ import annotations

from typing import Any

from tests.support import policy_route_graph as fixture

from hst.path import leak_guard
from hst.path.session import CycleSession

RULE = fixture.CONFIG["firewall"]["ipv4"]["name"]["LAN-WAN"]["rule"]


def analyse(patch=None) -> dict[str, Any]:
    graph = fixture.BatchGraph(fixture.batch(patch))
    return leak_guard.leak_guards(
        CycleSession(graph, fixture.BatchGraph.cts), fixture.LAN_WAN, fixture.GUARD, 4
    )


def _rule(cfg: dict[str, Any]) -> dict[str, Any]:
    return cfg["firewall"]["ipv4"]["name"]["LAN-WAN"]["rule"]["10"]


def test_the_drop_rule_guards_the_tunnel_the_policy_route_sends_its_sources_into():
    found = analyse()

    assert found["guard_gaps"] == [] and found["notes"] == []
    (guard,) = found["leak_guards"]
    assert guard["decided"] is True and "missing" not in guard
    assert guard["tunnel"] == {"interface": "wg44", "description": "peer b tunnel", "uid": fixture.WG44}
    assert guard["policy_routes"] == [f"{fixture.POLICY}:30"]
    assert guard["hosts"] == ["10.20.10.60", "10.20.10.70/31", "10.20.10.72"]
    assert guard["host_objects"] == ["tunnel-b-download"]
    assert (guard["rule_exits"], guard["exits_covered"], guard["exits_not_covered"]) == (
        ["eth0"],
        ["eth0"],
        [],
    )
    detail = guard["detail"]
    assert [t["uid"] for t in detail["tunnels"]] == [fixture.TUNNEL_B]
    (route,) = detail["policy_routes"]
    assert (route["policy"]["uid"], route["rule"]["position"]) == (fixture.POLICY, 30)
    assert route["ingress_interface"]["uid"] == fixture.VLAN10
    assert route["table"]["uid"] == fixture.TABLE_B
    assert [item["address"] for item in detail["sources"]] == ["10.20.10.60", "10.20.10.70/31", "10.20.10.72"]
    assert detail["source_objects"] == [{"uid": fixture.GROUP_B, "name": "tunnel-b-download"}]
    # rule 10 of the policy keeps the local destinations in the main table
    assert detail["destinations"] == fixture.NOT_LOCAL
    assert detail["normal_tables"] == [{"uid": fixture.MAIN, "name": "default"}]
    assert detail["breakout"] == [
        {
            "interface": {"uid": fixture.ETH0, "name": "eth0"},
            "zones": ["WAN"],
            "route": "0.0.0.0/0",
            "next_hop": None,
        }
    ]
    assert (
        guard["line"]
        == "Without the policy routes the sources leave through eth0, where rule 10 blocks them."
    )


def test_a_rule_whose_sources_no_policy_route_steers_guards_nothing():
    def patch(cfg):
        _rule(cfg)["source"] = {"address": "10.20.10.99"}

    assert analyse(patch) == {"leak_guards": [], "guard_gaps": [], "notes": []}


def test_a_rule_that_also_drops_the_tunnel_path_is_not_a_guard():
    def patch(cfg):
        # scoped to the zone pair alone, the rule drops LAN to wg44 as well
        del _rule(cfg)["outbound-interface"]

    found = analyse(patch)

    assert found["leak_guards"] == [] and found["guard_gaps"] == []
    assert found["notes"] == [
        "rule 10 also drops these flows on the tunnel path out wg44, so it does not back up policy route "
        "VPN-PBR rule 30"
    ]


def test_a_normal_route_the_rule_does_not_match_is_a_guard_gap():
    def patch(cfg):
        cfg["interfaces"]["ethernet"]["eth2"] = {"address": ["192.0.2.2/24"], "description": "second WAN"}
        cfg["firewall"]["zone"]["WAN"]["member"]["interface"].append("eth2")
        cfg["protocols"]["static"]["route"] = {"0.0.0.0/0": {"interface": {"eth2": {}}}}

    found = analyse(patch)

    assert found["leak_guards"] == []
    (gap,) = found["guard_gaps"]
    assert gap["decided"] is True
    assert gap["tunnel"]["uid"] == fixture.WG44
    assert [out["interface"]["name"] for out in gap["detail"]["breakout"]] == ["eth2"]
    assert gap["exits_not_covered"] == ["eth2"]
    assert (
        gap["line"]
        == "It does not cover eth2, so without the policy routes the sources still get out through it."
    )


def test_a_normal_route_that_does_not_resolve_to_an_interface_leaves_the_guard_not_decided():
    def patch(cfg):
        # eth0 takes its address by DHCP, so nothing resolves the next hop
        cfg["protocols"]["static"]["route"] = {"0.0.0.0/0": {"next-hop": {"198.51.100.1": {}}}}

    found = analyse(patch)

    assert found["guard_gaps"] == []
    (guard,) = found["leak_guards"]
    assert guard["decided"] is False
    assert [out["interface"]["name"] for out in guard["detail"]["breakout"]] == ["eth0"]
    assert guard["missing"] == [
        {
            "code": "egress-not-resolved",
            "subject": "route 0.0.0.0/0 via next hop 198.51.100.1 in table default",
            "detail": (
                "the route does not resolve to an interface; rule 10 drops these flows if they leave by eth0"
            ),
        }
    ]


def test_a_rule_that_does_not_drop_has_no_leak_guard():
    def patch(cfg):
        _rule(cfg)["action"] = "accept"

    assert analyse(patch) == {"leak_guards": [], "guard_gaps": [], "notes": []}


def test_the_fixture_rule_is_the_one_the_tests_name():
    assert RULE["10"]["action"] == "drop"
    assert fixture.GUARD in fixture.BatchGraph(fixture.batch()).nodes


def test_a_connected_destination_leaves_by_the_interface_that_serves_it():
    def patch(cfg):
        cfg["interfaces"]["ethernet"]["eth0"]["address"] = ["203.0.113.2/24"]
        del cfg["protocols"]["static"]["route"]

    found = analyse(patch)

    (guard,) = found["leak_guards"]
    assert guard["decided"] is True
    assert guard["detail"]["destinations"] == ["203.0.113.0/24"]
    assert [(out["interface"]["name"], out["route"]) for out in guard["detail"]["breakout"]] == [
        ("eth0", "203.0.113.0/24")
    ]
    # the main table holds no default route now
    assert len(found["notes"]) == 1 and "holds no route for" in found["notes"][0]


def test_an_earlier_rule_that_decides_the_breakout_flows_leaves_a_guard_gap():
    def patch(cfg):
        rules = cfg["firewall"]["ipv4"]["name"]["LAN-WAN"]["rule"]
        rules["5"] = {"action": "accept", "source": {"address": "10.20.10.0/24"}}

    found = analyse(patch)

    assert found["leak_guards"] == []
    (gap,) = found["guard_gaps"]
    assert gap["detail"]["breakout"][0]["decided_by"] == "rule 5"
    assert gap["exits_decided_first"] == [{"rule": "rule 5", "exits": ["eth0"]}]
    assert gap["line"] == "Rule 5 decides this traffic first on eth0."
