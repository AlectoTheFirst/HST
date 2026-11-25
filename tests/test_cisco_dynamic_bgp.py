"""Replay the same dynamic-neighbor network through all Cisco collectors."""

import importlib
import json
from pathlib import Path

import pytest
from tests.conftest import FakeSshSession

from hst.collectors.base import raw_sha
from hst.collectors.cisco_bgp import expand_dynamic_neighbors
from hst.core import manifest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures/network/cisco-dynamic-bgp"
PEERS = {"10.252.32.10", "10.252.33.20"}


@pytest.fixture(params=["nxos", "iosxe", "iosxr"])
def network(request, monkeypatch):
    family = request.param
    mod = importlib.import_module(f"hst.collectors.{family}")
    base = importlib.import_module(f"tests.test_{family}")
    outputs = dict(base.RAW)
    outputs[mod.CMD_BGP] = (FIXTURES / f"{family}.cfg").read_text()
    summary = mod.CMD_BGP_SESSIONS if family == "nxos" else mod.bgp_summary_command("WAN")
    suffix = "json" if family == "nxos" else "txt"
    outputs[summary] = (FIXTURES / f"{family}-sessions.{suffix}").read_text()
    if family == "nxos":
        outputs[mod.CMD_RPM] = "route-map RM-IN permit 10\nroute-map RM-OUT permit 10\n"
    elif family == "iosxe":
        outputs[mod.CMD_ROUTE_MAP] = "route-map RM-IN permit 10\nroute-map RM-OUT permit 10\n"
    else:
        outputs[mod.CMD_ROUTE_POLICY] = (
            "route-policy RM-IN\n pass\nend-policy\nroute-policy RM-OUT\n pass\nend-policy\n"
        )
    # the neighbor detail commands state no router id in this network
    for name in ("CMD_BGP_NEIGHBORS", "CMD_BGP_VRF_NEIGHBORS"):
        if hasattr(mod, name):
            outputs[getattr(mod, name)] = ""
    route_commands = []
    for peer in sorted(PEERS):
        for direction in mod.BGP_DIRECTION_KEYWORDS:
            command = (
                mod.bgp_route_command("WAN", peer, direction)
                if family == "nxos"
                else mod.bgp_route_command(peer, direction, "WAN")
            )
            route_commands.append(command)
            if family == "nxos":
                prefix = {
                    "ipprefix": "203.0.113.0/24",
                    "TABLE_path": {
                        "ROW_path": {
                            "ipnexthop": peer,
                            "aspath": "65099",
                            "localpref": "100",
                            "metric": "0",
                            "origin": "i",
                        }
                    },
                }
                payload = {"TABLE_prefix": {"ROW_prefix": prefix}}
                for table in ("safi", "afi", "vrf"):
                    payload = {f"TABLE_{table}": {f"ROW_{table}": payload}}
                outputs[command] = json.dumps(payload)
            elif family == "iosxe":
                outputs[command] = (
                    "     Network          Next Hop            Metric LocPrf Weight Path\n"
                    f" *>  203.0.113.0/24   {peer:<15}          0    100      0 65099 i\n"
                )
            else:
                outputs[command] = (
                    "   Network            Next Hop            Metric LocPrf Weight Path\n"
                    f"*> 203.0.113.0/24     {peer:<15}          0    100      0 65099 i\n"
                )
    fake = FakeSshSession(lambda command: outputs[command]).install(monkeypatch)
    return family, mod, base, outputs, summary, route_commands, fake


def collect(network, capture="all"):
    collector = network[2]._bgp_collector(capture)
    raw = collector.fetch()
    return collector, raw, collector.normalize(raw)


def test_range_is_preserved_and_only_observed_members_become_sessions(network):
    collector, raw, batch = collect(network)
    ranges = [n for n in batch.nodes if n.label == "BgpPeerRange"]
    sessions = [n for n in batch.nodes if n.label == "BgpSession"]
    assert len(ranges) == 1
    assert ranges[0].props["prefix"] == "10.252.32.0/23"
    assert {s.props["peer_ip"] for s in sessions} == PEERS
    assert {s.props["peer_asn"] for s in sessions} == {65099}
    assert {s.props["local_asn"] for s in sessions} == {65001}
    assert {s.props["observed_state"] for s in sessions} == {"Established", "Idle"}
    for peer in [*ranges, *sessions]:
        assert peer.props["import_policy_name"] == "RM-IN"
        assert peer.props["export_policy_name"] == "RM-OUT"
        assert len([r for r in batch.rels if r.rel_type == "FILTERED_BY" and r.start_uid == peer.uid]) == 2
    assert {r.start_uid for r in batch.rels if r.rel_type == "MEMBER_OF" and r.end_uid == ranges[0].uid} == {
        s.uid for s in sessions
    }
    batch.validate_registry()
    session_uids = {s.uid for s in sessions}
    routes = collector.side_tables(raw)["bgp_session_routes"]
    assert routes and {r["session_uid"] for r in routes} == session_uids
    assert {r["prefix"] for r in routes} == {"203.0.113.0/24"}
    outcomes = manifest.bgp_direction_outcomes(collector.table_outcomes(raw))
    assert len(outcomes) == 6
    assert all(o.status == "complete" for o in outcomes.values())


def test_capture_discovers_dynamic_peers_before_querying_their_routes(network):
    collect(network)
    _, _, _, _, summary, routes, fake = network
    assert all(fake.commands.index(summary) < fake.commands.index(command) for command in routes)
    assert all(fake.commands.count(command) == 1 for command in routes)
    assert not any(
        "neighbors 10.252.32.0/23" in cmd or "neighbors 192.0.2.99" in cmd for cmd in fake.commands
    )


@pytest.mark.parametrize("capture", ["none", "sessions"])
def test_capture_modes_preserve_range_without_inventing_route_observations(network, capture):
    collector, raw, batch = collect(network, capture)
    assert len([n for n in batch.nodes if n.label == "BgpPeerRange"]) == 1
    assert len([n for n in batch.nodes if n.label == "BgpSession"]) == (0 if capture == "none" else 2)
    assert not set(network[5]) & set(network[6].commands)
    assert collector.side_tables(raw).get("bgp_session_routes", []) == []


def test_disappearing_peer_changes_fingerprint_and_graph(network):
    collector, first, _ = collect(network, "sessions")
    family, _, _, outputs, summary, _, _ = network
    if family == "nxos":
        payload = json.loads(outputs[summary])
        rows = payload["TABLE_vrf"]["ROW_vrf"]["TABLE_neighbor"]["ROW_neighbor"]
        rows[:] = [r for r in rows if r["neighbor-id"] != "10.252.32.10"]
        outputs[summary] = json.dumps(payload)
    else:
        outputs[summary] = "\n".join(
            line for line in outputs[summary].splitlines() if "10.252.32.10" not in line
        )
    second = collector.fetch()
    assert raw_sha(collector, first) != raw_sha(collector, second)
    batch = collector.normalize(second)
    assert {n.props["peer_ip"] for n in batch.nodes if n.label == "BgpSession"} == {"10.252.33.20"}


def test_default_vrf_volatile_summary_refreshes_dynamic_graph(network):
    family, mod, _, outputs, summary, _, _ = network
    config = outputs[mod.CMD_BGP]
    if family == "nxos":
        outputs[mod.CMD_BGP] = config.replace("  vrf WAN\n", "").replace("    ", "  ")
        payload = json.loads(outputs[summary])
        payload["TABLE_vrf"]["ROW_vrf"]["vrf-name-out"] = "default"
        outputs[summary] = json.dumps(payload)
    elif family == "iosxe":
        outputs[mod.CMD_BGP] = config.replace("address-family ipv4 vrf WAN", "address-family ipv4")
        outputs[mod.CMD_BGP_SESSIONS] = outputs[summary]
    else:
        outputs[mod.CMD_BGP] = (
            config.replace(" vrf WAN\n", "")
            .replace("  neighbor ", " neighbor ")
            .replace("   use neighbor-group", "  use neighbor-group")
        )
        outputs[mod.CMD_BGP_SESSIONS] = outputs[summary]
    collector, before, batch = collect(network, "sessions")
    assert len([n for n in batch.nodes if n.label == "BgpSession"]) == 2
    outputs[mod.CMD_BGP_SESSIONS] = "{}" if family == "nxos" else ""
    after = collector.fetch()
    assert raw_sha(collector, before) != raw_sha(collector, after)
    assert after["_strata_dynamic_bgp"] == []
    assert not [n for n in collector.normalize(after).nodes if n.label == "BgpSession"]


def test_failed_summary_does_not_invent_dynamic_sessions_or_query_range(network):
    from hst.collectors import ssh

    _, _, base, outputs, summary, commands, fake = network

    def answer(command):
        if command == summary:
            raise ssh.CommandFailed(f"{command!r} exited 1: Permission denied")
        return outputs[command]

    fake._outputs = answer
    collector = base._bgp_collector("all")
    raw = collector.fetch()
    assert not set(commands) & set(fake.commands)
    assert not [n for n in collector.normalize(raw).nodes if n.label == "BgpSession"]
    assert collector.table_outcomes(raw)["bgp_sessions"].status == "failed"


def test_observed_peer_in_other_vrf_does_not_instantiate_range():
    neighbors = [{"peer_ip": "10.252.32.0/23", "remote_as": 65099}]
    observed = [{"vrf": "OTHER", "peer_ip": "10.252.32.10", "state": "Established"}]
    assert expand_dynamic_neighbors(neighbors, observed, "WAN") == neighbors


def test_explicit_neighbor_keeps_its_own_policies():
    neighbors = [
        {"peer_ip": "10.252.32.0/23", "remote_as": 65099, "route_map_in": "RANGE"},
        {"peer_ip": "10.252.32.10", "remote_as": 65099, "route_map_in": "EXPLICIT"},
    ]
    observed = [{"vrf": "WAN", "peer_ip": "10.252.32.10", "state": "Established"}]
    assert expand_dynamic_neighbors(neighbors, observed, "WAN") == neighbors


def test_overlapping_ranges_do_not_guess_inherited_policy(caplog):
    neighbors = [{"peer_ip": "10.252.32.0/23"}, {"peer_ip": "10.252.32.0/24"}]
    observed = [{"vrf": "WAN", "peer_ip": "10.252.32.10", "state": "Established"}]
    assert expand_dynamic_neighbors(neighbors, observed, "WAN") == neighbors
    assert "matches multiple ranges" in caplog.text


def test_range_without_fixed_as_uses_observed_as_without_enumerating_prefix():
    neighbors = [{"peer_ip": "10.252.32.0/23", "remote_as_route_map": "ALLOWED-AS"}]
    observed = [{"vrf": "WAN", "peer_ip": "10.252.32.10", "state": "Established", "peer_asn": 65099}]
    result = expand_dynamic_neighbors(neighbors, observed, "WAN")
    assert len(result) == 2
    assert result[-1]["remote_as"] == 65099
    assert result[-1]["remote_as_route_map"] == "ALLOWED-AS"


@pytest.mark.parametrize("peer", ["10.252.32.0/23", "invalid", "2001:db8::1"])
def test_observations_must_be_single_addresses_in_the_range(peer):
    neighbors = [{"peer_ip": "10.252.32.0/23"}]
    assert expand_dynamic_neighbors(neighbors, [{"peer_ip": peer}], "default") == neighbors


def test_conflicting_observations_are_not_resolved_by_row_order():
    neighbors = [{"peer_ip": "10.252.32.0/23", "remote_as": 65099}]
    observed = [{"peer_ip": "10.252.32.10", "state": state} for state in ("Established", "Idle")]
    assert expand_dynamic_neighbors(neighbors, observed, "default") == neighbors


def test_missing_template_is_not_treated_as_an_unfiltered_dynamic_peer(network):
    family, mod, _, outputs, _, _, _ = network
    if family == "nxos":
        outputs[mod.CMD_BGP] = outputs[mod.CMD_BGP].replace("remote-as 65099", "inherit peer MISSING")
    else:
        outputs[mod.CMD_BGP] = outputs[mod.CMD_BGP].replace(
            "peer-group DYNAMIC" if family == "iosxe" else "use neighbor-group DYNAMIC",
            "peer-group MISSING" if family == "iosxe" else "use neighbor-group MISSING",
        )
    _, _, batch = collect(network)
    assert not [n for n in batch.nodes if n.label == "BgpSession"]
    ranges = [n for n in batch.nodes if n.label == "BgpPeerRange"]
    assert len(ranges) == 1 and ranges[0].props["inheritance_gaps"]


def test_nxos_dynamic_range_inherits_captured_peer_templates():
    from tests.test_nxos import RAW, _collector

    from hst.collectors import nxos

    config = """router bgp 65001
  template peer-session SESSION
    remote-as 65099
  template peer-policy POLICY
    route-map RM-IN in
  template peer DYNAMIC
    inherit peer-session SESSION
    address-family ipv4 unicast
      inherit peer-policy POLICY 10
      route-map RM-OUT out
  vrf WAN
    neighbor 10.252.32.0/23
      inherit peer DYNAMIC
"""
    raw = {**RAW, nxos.CMD_BGP: config, nxos.CMD_BGP_SESSIONS: (FIXTURES / "nxos-sessions.json").read_text()}
    batch = _collector().normalize(raw)
    sessions = [n for n in batch.nodes if n.label == "BgpSession"]
    assert {n.props["peer_ip"] for n in sessions} == PEERS
    assert all(n.props["import_policy_name"] == "RM-IN" for n in sessions)
    assert all(n.props["export_policy_name"] == "RM-OUT" for n in sessions)


def test_nxos_remote_as_route_map_keeps_definition_and_uses_observed_as():
    from tests.test_nxos import RAW, _collector

    from hst.collectors import nxos

    raw = {
        **RAW,
        nxos.CMD_BGP: (FIXTURES / "nxos.cfg")
        .read_text()
        .replace("remote-as 65099", "remote-as route-map AS-POOL"),
        nxos.CMD_BGP_SESSIONS: (FIXTURES / "nxos-sessions.json").read_text(),
    }
    batch = _collector().normalize(raw)
    peers = [n for n in batch.nodes if n.label in {"BgpSession", "BgpPeerRange"}]
    assert len(peers) == 3
    assert all(n.props["remote_as_route_map"] == "AS-POOL" for n in peers)
    assert {n.props["peer_asn"] for n in peers if n.label == "BgpSession"} == {65099}
