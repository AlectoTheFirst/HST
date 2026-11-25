"""The remote router id each collector writes on a BgpSession.

Every platform states the peer's own BGP identifier in its neighbor detail
output; the collectors read it per (VRF, peer address) and write
`peer_router_id`, null when the output does not state it or states 0.0.0.0.
"""

import asyncio
import json

import pytest
from tests import test_iosxe, test_iosxr, test_nxos, test_vyos
from tests.conftest import FakeSshSession

from hst.collectors import iosxe, iosxr, nxos, ssh, vyos
from hst.collectors.base import RAW_OUTCOMES_KEY, raw_sha
from hst.collectors.cisco_bgp import PEER_ROUTER_IDS_MARKER, parse_neighbor_router_ids

# --- captured-output fixtures --------------------------------------------------------------

# IOS-XE `show bgp all neighbors`: the default VRF's peers, then one in BLUE.
# 192.0.2.1 never opened, so its identifier is 0.0.0.0.
IOSXE_NEIGHBORS = """\
BGP neighbor is 10.0.0.2,  remote AS 65001, internal link
  BGP version 4, remote router ID 10.255.255.2
  BGP state = Established, up for 1d02h
  Last read 00:00:20, last write 00:00:35, hold time is 180, keepalive interval is 60 seconds
 For address family: IPv4 Unicast
  Session: 10.0.0.2
  Route refresh request: received 0, sent 0

BGP neighbor is 192.0.2.1,  remote AS 65010, external link
  BGP version 4, remote router ID 0.0.0.0
  BGP state = Idle
 For address family: IPv4 Unicast
  Session: 192.0.2.1

BGP neighbor is 198.51.100.2,  vrf BLUE,  remote AS 65100, external link
  BGP version 4, remote router ID 198.51.100.254
  BGP state = Established, up for 00:10:22
 For address family: IPv4 Unicast
  Session: 198.51.100.2
"""

# the same address in the default VRF and in BLUE, with different identifiers
IOSXE_SAME_ADDRESS = """\
BGP neighbor is 10.9.9.9,  remote AS 65001, internal link
  BGP version 4, remote router ID 1.1.1.1
BGP neighbor is 10.9.9.9,  vrf BLUE,  remote AS 65100, external link
  BGP version 4, remote router ID 2.2.2.2
"""

IOSXE_VRF_CONFIG = """\
router bgp 65001
 bgp router-id 10.255.255.1
 neighbor 10.0.0.2 remote-as 65001
 neighbor 192.0.2.1 remote-as 65010
 neighbor 192.0.2.77 remote-as 65020
 !
 address-family ipv4
  neighbor 10.0.0.2 activate
  neighbor 192.0.2.1 activate
  neighbor 192.0.2.77 activate
 exit-address-family
 !
 address-family ipv4 vrf BLUE
  neighbor 198.51.100.2 remote-as 65100
  neighbor 198.51.100.2 activate
 exit-address-family
!
"""

# IOS-XR `show bgp neighbors` (default VRF) and `show bgp vrf all neighbors`
IOSXR_NEIGHBORS = """\
BGP neighbor is 192.0.2.1
 Remote AS 65100, local AS 65000, external link
 Remote router ID 192.0.2.254
  BGP state = Established, up for 00:10:22
  Multi-protocol capability received

BGP neighbor is 192.0.2.3
 Remote AS 65300, local AS 65000, external link
 Remote router ID 0.0.0.0
  BGP state = Idle
"""

IOSXR_VRF_NEIGHBORS = """\
VRF: BLUE
---------

BGP neighbor is 198.51.100.2, vrf BLUE
 Remote AS 65100, local AS 65000, external link
 Remote router ID 198.51.100.254
  BGP state = Established, up for 00:03:41
"""

IOSXR_VRF_CONFIG = (
    test_iosxr.BGP_TEXT.rstrip().rstrip("!")
    + """ vrf BLUE
  neighbor 198.51.100.2
   remote-as 65100
   address-family ipv4 unicast
   !
  !
 !
!
"""
)


def _nxos_neighbors(*, default_rid="10.9.9.9"):
    def row(neighbor, **extra):
        return {"neighbor": neighbor, "remoteas": "65001", **extra}

    return json.dumps(
        {
            "TABLE_vrf": {
                "ROW_vrf": [
                    {
                        "vrf-name-out": "default",
                        # the same address as a CUST-A peer, another identifier
                        "TABLE_neighbor": {"ROW_neighbor": row("10.1.1.2", rtrid=default_rid)},
                    },
                    {
                        "vrf-name-out": "CUST-A",
                        "TABLE_neighbor": {
                            "ROW_neighbor": [
                                row("10.1.1.2", rtrid="10.255.1.2"),
                                # a session that never opened
                                row("192.0.2.2", remoteas="65099", rtrid="0.0.0.0"),  # noqa: S104
                                # no identifier stated: 192.0.2.9 is absent altogether
                            ]
                        },
                    },
                ]
            }
        }
    )


# VyOS `show ip bgp vrf all neighbors json`, keyed by VRF name
VYOS_NEIGHBORS = json.dumps(
    {
        "default": {
            "203.0.113.2": {"remoteAs": 65001, "remoteRouterId": "203.0.113.254", "bgpState": "Established"},
            "10.0.0.2": {"remoteAs": 65000, "remoteRouterId": "0.0.0.0", "bgpState": "Active"},  # noqa: S104
            "192.0.2.9": {"remoteAs": 65009, "bgpState": "Idle"},
        },
        "RED": {
            "10.0.0.2": {"remoteAs": 65000, "remoteRouterId": "10.255.0.7", "bgpState": "Established"},
        },
    }
)


def _sessions(batch):
    return {n.props["peer_ip"]: n.props for n in batch.nodes if n.label == "BgpSession"}


# --- the shared text parser ------------------------------------------------------------------


def test_text_parser_reads_the_identifier_of_each_vrf_and_peer():
    ids = parse_neighbor_router_ids(IOSXE_NEIGHBORS)
    assert ids == {
        ("default", "10.0.0.2"): "10.255.255.2",
        ("BLUE", "198.51.100.2"): "198.51.100.254",
    }


def test_text_parser_keeps_the_same_address_apart_per_vrf():
    assert parse_neighbor_router_ids(IOSXE_SAME_ADDRESS) == {
        ("default", "10.9.9.9"): "1.1.1.1",
        ("BLUE", "10.9.9.9"): "2.2.2.2",
    }


def test_text_parser_merges_the_default_and_vrf_commands_of_ios_xr():
    ids = parse_neighbor_router_ids(IOSXR_NEIGHBORS, IOSXR_VRF_NEIGHBORS)
    assert ids == {("default", "192.0.2.1"): "192.0.2.254", ("BLUE", "198.51.100.2"): "198.51.100.254"}


@pytest.mark.parametrize("text", [None, "", "% Invalid input detected at '^' marker.\n", "BGP not active\n"])
def test_text_parser_yields_nothing_for_missing_or_refused_output(text):
    assert parse_neighbor_router_ids(text) == {}


# --- IOS-XE ------------------------------------------------------------------------------------


def _iosxe_batch(neighbors, config=IOSXE_VRF_CONFIG):
    raw = dict(test_iosxe.RAW, **{iosxe.CMD_BGP: config})
    if neighbors is not None:
        raw[iosxe.CMD_BGP_NEIGHBORS] = neighbors
    return test_iosxe._bgp_collector().normalize(raw)


def test_iosxe_session_carries_the_peer_router_id_by_vrf():
    sessions = _sessions(_iosxe_batch(IOSXE_NEIGHBORS))
    assert sessions["10.0.0.2"].get("peer_router_id") == "10.255.255.2"
    assert sessions["198.51.100.2"].get("peer_router_id") == "198.51.100.254"


def test_iosxe_zero_and_unstated_ids_are_null():
    sessions = _sessions(_iosxe_batch(IOSXE_NEIGHBORS))
    assert sessions["192.0.2.1"].get("peer_router_id") is None
    assert sessions["192.0.2.77"].get("peer_router_id") is None


@pytest.mark.parametrize("neighbors", [None, "", "% Invalid input detected\n"])
def test_iosxe_missing_or_refused_neighbor_output_leaves_every_id_null(neighbors):
    sessions = _sessions(_iosxe_batch(neighbors))
    assert sessions
    assert all(s.get("peer_router_id") is None for s in sessions.values())


def test_iosxe_fetch_asks_for_the_neighbors_and_stamps_what_they_state(monkeypatch):
    outputs = dict(test_iosxe.RAW, **{iosxe.CMD_BGP_NEIGHBORS: IOSXE_NEIGHBORS})
    outputs[iosxe.CMD_BGP] = IOSXE_VRF_CONFIG
    fake = FakeSshSession(lambda cmd: outputs[cmd] if cmd in outputs else _refuse(cmd)).install(monkeypatch)
    collector = test_iosxe._bgp_collector("sessions")
    raw = collector.fetch()
    assert iosxe.CMD_BGP_NEIGHBORS in fake.commands
    assert raw[PEER_ROUTER_IDS_MARKER] == [
        ["BLUE", "198.51.100.2", "198.51.100.254"],
        ["default", "10.0.0.2", "10.255.255.2"],
    ]
    # the counters of the neighbor output move on every fetch; the ids do not
    outputs[iosxe.CMD_BGP_NEIGHBORS] = IOSXE_NEIGHBORS.replace("up for 1d02h", "up for 1d03h")
    assert raw_sha(collector, collector.fetch()) == raw_sha(collector, raw)
    outputs[iosxe.CMD_BGP_NEIGHBORS] = IOSXE_NEIGHBORS.replace("10.255.255.2", "10.255.255.3")
    assert raw_sha(collector, collector.fetch()) != raw_sha(collector, raw)


def test_iosxe_refused_neighbor_command_does_not_fail_the_fetch(monkeypatch):
    outputs = dict(test_iosxe.RAW, **{iosxe.CMD_BGP: IOSXE_VRF_CONFIG})

    def run(cmd):
        if cmd == iosxe.CMD_BGP_NEIGHBORS:
            raise ssh.CommandFailed("% Invalid input detected at '^' marker.")
        return outputs[cmd] if cmd in outputs else _refuse(cmd)

    FakeSshSession(run).install(monkeypatch)
    collector = test_iosxe._bgp_collector("sessions")
    raw = collector.fetch()
    assert raw[iosxe.CMD_BGP_NEIGHBORS] == ""
    assert raw[RAW_OUTCOMES_KEY][iosxe.CMD_BGP_NEIGHBORS]["status"] != "ok"
    assert PEER_ROUTER_IDS_MARKER not in raw
    assert all(s.get("peer_router_id") is None for s in _sessions(collector.normalize(raw)).values())


def _refuse(cmd):
    raise ssh.CommandFailed(f"{cmd!r} exited 1: not stubbed")


# --- IOS-XR ------------------------------------------------------------------------------------


def _iosxr_batch(neighbors, vrf_neighbors, config=IOSXR_VRF_CONFIG):
    raw = dict(test_iosxr.RAW, **{iosxr.CMD_BGP: config})
    if neighbors is not None:
        raw[iosxr.CMD_BGP_NEIGHBORS] = neighbors
    if vrf_neighbors is not None:
        raw[iosxr.CMD_BGP_VRF_NEIGHBORS] = vrf_neighbors
    return test_iosxr._bgp_collector().normalize(raw)


def test_iosxr_session_carries_the_peer_router_id_by_vrf():
    sessions = _sessions(_iosxr_batch(IOSXR_NEIGHBORS, IOSXR_VRF_NEIGHBORS))
    assert sessions["192.0.2.1"].get("peer_router_id") == "192.0.2.254"
    assert sessions["198.51.100.2"].get("peer_router_id") == "198.51.100.254"


def test_iosxr_zero_id_is_null():
    assert (
        _sessions(_iosxr_batch(IOSXR_NEIGHBORS, IOSXR_VRF_NEIGHBORS))["192.0.2.3"].get("peer_router_id")
        is None
    )


def test_iosxr_a_missing_vrf_command_leaves_only_the_vrf_peers_null():
    sessions = _sessions(_iosxr_batch(IOSXR_NEIGHBORS, None))
    assert sessions["192.0.2.1"].get("peer_router_id") == "192.0.2.254"
    assert sessions["198.51.100.2"].get("peer_router_id") is None


def test_iosxr_fetch_asks_for_both_commands_and_tolerates_a_refusal(monkeypatch):
    outputs = dict(
        test_iosxr.RAW, **{iosxr.CMD_BGP: IOSXR_VRF_CONFIG, iosxr.CMD_BGP_NEIGHBORS: IOSXR_NEIGHBORS}
    )

    def run(cmd):
        if cmd == iosxr.CMD_BGP_VRF_NEIGHBORS:
            raise ssh.CommandFailed("% Invalid input")
        return outputs[cmd] if cmd in outputs else _refuse(cmd)

    fake = FakeSshSession(run).install(monkeypatch)
    collector = test_iosxr._bgp_collector("sessions")
    raw = collector.fetch()
    assert iosxr.CMD_BGP_NEIGHBORS in fake.commands
    assert iosxr.CMD_BGP_VRF_NEIGHBORS in fake.commands
    assert raw[PEER_ROUTER_IDS_MARKER] == [["default", "192.0.2.1", "192.0.2.254"]]
    sessions = _sessions(collector.normalize(raw))
    assert sessions["192.0.2.1"].get("peer_router_id") == "192.0.2.254"
    assert sessions["198.51.100.2"].get("peer_router_id") is None


# --- NX-OS -------------------------------------------------------------------------------------


def _nxos_batch(neighbors):
    raw = dict(test_nxos.RAW)
    if neighbors is not None:
        raw[nxos.CMD_BGP_NEIGHBORS] = neighbors
    return test_nxos._bgp_collector().normalize(raw)


def test_nxos_parser_reads_the_identifier_per_vrf_and_peer():
    assert nxos.parse_bgp_neighbor_router_ids(_nxos_neighbors()) == {
        ("default", "10.1.1.2"): "10.9.9.9",
        ("CUST-A", "10.1.1.2"): "10.255.1.2",
    }


@pytest.mark.parametrize("text", [None, "", "{}", "not json", "[]"])
def test_nxos_parser_yields_nothing_for_missing_or_unreadable_output(text):
    assert nxos.parse_bgp_neighbor_router_ids(text) == {}


def test_nxos_session_matches_its_own_vrf_and_zero_or_missing_is_null():
    sessions = _sessions(_nxos_batch(_nxos_neighbors()))
    assert sessions["10.1.1.2"].get("peer_router_id") == "10.255.1.2"
    assert sessions["192.0.2.2"].get("peer_router_id") is None
    assert sessions["192.0.2.9"].get("peer_router_id") is None


@pytest.mark.parametrize("neighbors", [None, "", "{}"])
def test_nxos_missing_neighbor_output_leaves_every_id_null(neighbors):
    sessions = _sessions(_nxos_batch(neighbors))
    assert sessions
    assert all(s.get("peer_router_id") is None for s in sessions.values())


def test_nxos_fetch_asks_for_the_neighbors_and_stamps_what_they_state(monkeypatch):
    outputs = dict(test_nxos.RAW, **{nxos.CMD_BGP_NEIGHBORS: _nxos_neighbors()})
    fake = FakeSshSession(lambda cmd: outputs[cmd] if cmd in outputs else _refuse(cmd)).install(monkeypatch)
    collector = test_nxos._bgp_collector("sessions")
    raw = collector.fetch()
    assert nxos.CMD_BGP_NEIGHBORS in fake.commands
    assert raw[PEER_ROUTER_IDS_MARKER] == [
        ["CUST-A", "10.1.1.2", "10.255.1.2"],
        ["default", "10.1.1.2", "10.9.9.9"],
    ]
    # a neighbor row's counters are volatile; the ids it states are not
    moved = json.loads(outputs[nxos.CMD_BGP_NEIGHBORS])
    moved["TABLE_vrf"]["ROW_vrf"][0]["TABLE_neighbor"]["ROW_neighbor"]["msgrecvd"] = "99"
    outputs[nxos.CMD_BGP_NEIGHBORS] = json.dumps(moved)
    assert raw_sha(collector, collector.fetch()) == raw_sha(collector, raw)
    outputs[nxos.CMD_BGP_NEIGHBORS] = _nxos_neighbors(default_rid="10.9.9.8")
    assert raw_sha(collector, collector.fetch()) != raw_sha(collector, raw)


def test_nxos_refused_neighbor_command_does_not_fail_the_fetch(monkeypatch):
    def run(cmd):
        if cmd == nxos.CMD_BGP_NEIGHBORS:
            raise ssh.CommandFailed("Invalid command")
        return test_nxos.RAW[cmd] if cmd in test_nxos.RAW else _refuse(cmd)

    FakeSshSession(run).install(monkeypatch)
    collector = test_nxos._bgp_collector("sessions")
    raw = collector.fetch()
    assert PEER_ROUTER_IDS_MARKER not in raw
    assert all(s.get("peer_router_id") is None for s in _sessions(collector.normalize(raw)).values())


# --- VyOS --------------------------------------------------------------------------------------


def _vyos_batch(neighbors, *, red=True):
    cfg = json.loads(json.dumps(test_vyos.BGP_CONFIG))
    # a configured neighbor the neighbor output does not list
    cfg["protocols"]["bgp"]["neighbor"]["198.18.0.2"] = {"remote-as": "65050"}
    if red:
        cfg["vrf"] = {
            "name": {
                "RED": {
                    "table": "100",
                    "protocols": {
                        "bgp": {
                            "system-as": "65000",
                            "neighbor": {"10.0.0.2": {"remote-as": "65000"}},
                        }
                    },
                }
            }
        }
    raw = {"config": cfg, "version_text": test_vyos.VERSION, "links": []}
    if neighbors is not None:
        raw[vyos.BGP_NEIGHBORS_COMMAND] = neighbors
    return vyos.normalize_vyos(raw, l3dom="wan")


def _vyos_by_vrf(batch):
    out = {}
    for n in batch.nodes:
        if n.label == "BgpSession":
            vrf = "RED" if n.uid.endswith(":RED") else "default"
            out[(vrf, n.props["peer_ip"])] = n.props.get("peer_router_id")
    return out


def test_vyos_parser_reads_remote_router_id_per_vrf():
    assert vyos.neighbor_router_ids(VYOS_NEIGHBORS) == {
        ("default", "203.0.113.2"): "203.0.113.254",
        ("RED", "10.0.0.2"): "10.255.0.7",
    }


def test_vyos_parser_reads_a_default_vrf_answer_keyed_by_peer_address():
    flat = json.dumps({"203.0.113.2": {"remoteAs": 65001, "remoteRouterId": "203.0.113.254"}})
    assert vyos.neighbor_router_ids(flat) == {("default", "203.0.113.2"): "203.0.113.254"}


@pytest.mark.parametrize("text", [None, "", "{}", "not json", "[]"])
def test_vyos_parser_yields_nothing_for_missing_or_unreadable_output(text):
    assert vyos.neighbor_router_ids(text) == {}


def test_vyos_session_matches_its_own_vrf_and_zero_or_missing_is_null():
    ids = _vyos_by_vrf(_vyos_batch(VYOS_NEIGHBORS))
    assert ids[("default", "203.0.113.2")] == "203.0.113.254"
    assert ids[("RED", "10.0.0.2")] == "10.255.0.7"
    assert ids[("default", "10.0.0.2")] is None
    assert ids[("default", "198.18.0.2")] is None


@pytest.mark.parametrize("neighbors", [None, "", "{}"])
def test_vyos_missing_neighbor_output_leaves_every_id_null(neighbors):
    ids = _vyos_by_vrf(_vyos_batch(neighbors))
    assert ids
    assert all(rid is None for rid in ids.values())


def _vyos_fetch(monkeypatch, answers):
    """One `_afetch_bgp_observations` over a device that answers from `answers`
    and refuses every other command."""
    monkeypatch.setattr(vyos.VyosCollector, "_op_mode", lambda self, cmd: cmd)
    seen = []

    class _Session:
        async def run(self, cmd):
            seen.append(cmd)
            if cmd in answers:
                return answers[cmd]
            raise ssh.CommandFailed(f"{cmd!r} rejected by device: % Unknown command")

    raw: dict = {}
    outcomes: dict = {}
    collector = test_vyos._bgp_collector("sessions")
    asyncio.run(collector._afetch_bgp_observations(_Session(), raw, outcomes))
    return raw, outcomes, seen


def test_vyos_fetch_keeps_the_neighbor_answer(monkeypatch):
    raw, _outcomes, seen = _vyos_fetch(monkeypatch, {vyos.BGP_NEIGHBORS_COMMAND: VYOS_NEIGHBORS})
    assert vyos.BGP_NEIGHBORS_COMMAND in seen
    assert vyos.neighbor_router_ids(raw[vyos.BGP_NEIGHBORS_COMMAND])


def test_vyos_refused_neighbor_command_records_nothing_and_does_not_fail_the_fetch(monkeypatch):
    raw, outcomes, seen = _vyos_fetch(monkeypatch, {})
    assert vyos.BGP_NEIGHBORS_COMMAND in seen
    assert vyos.BGP_NEIGHBORS_COMMAND not in raw
    assert vyos.BGP_NEIGHBORS_COMMAND not in outcomes
