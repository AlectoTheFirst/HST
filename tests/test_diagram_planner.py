"""The diagram planner (hst/diagram/planner.py) on a small campus:

    rth-01 ==== rth-02          SD-WAN hubs, each with a WAN link
      |           |
    fw-01  ==== fw-02           one Check Point cluster
      |           |
    swc-01 ==== swc-02          one vPC domain, peer-link between them
         \\      /
          swd-01                Po1 to both cores, a third member uncabled
          /    \\
      swa-01  swa-02
       |   \\
     ap-01  srv-9               srv-9 has no tier

swc-01 also has a cable to a DC spine outside the drawing.
"""

from __future__ import annotations

import random

from hst.diagram import planner


def _dev(uid, tier, role="router", site="ber1"):
    return {
        "uid": uid,
        "name": uid,
        "role": role,
        "tier": tier,
        "role_basis": "hostname",
        "site": site,
        "vendor": None,
        "model": None,
    }


def _cable(a, a_port, b, b_port):
    return {"a_dev": a, "a_port": a_port, "b_dev": b, "b_port": b_port, "source": "lldp"}


DEVICES = [
    _dev("rth-01", "sdwan-hub", "sdwan-hub"),
    _dev("rth-02", "sdwan-hub", "sdwan-hub"),
    _dev("fw-01", "firewall", "firewall"),
    _dev("fw-02", "firewall", "firewall"),
    _dev("swc-01", "core"),
    _dev("swc-02", "core"),
    _dev("swd-01", "distribution"),
    _dev("swa-01", "access", "switch"),
    _dev("swa-02", "access", "switch"),
    _dev("ap-01", "access-point", "ap"),
    _dev("srv-9", None, "unknown"),
]

CABLES = [
    _cable("rth-01", "GE3", "rth-02", "GE3"),
    _cable("rth-01", "GE1", "fw-01", "eth1"),
    _cable("rth-02", "GE1", "fw-02", "eth1"),
    _cable("fw-01", "sync", "fw-02", "sync"),
    _cable("fw-01", "eth2", "swc-01", "Eth1/1"),
    _cable("fw-02", "eth2", "swc-02", "Eth1/1"),
    _cable("swc-01", "Eth1/48", "swc-02", "Eth1/48"),
    # written from the inner end: the planner turns it outer end first
    _cable("swd-01", "Eth1/1", "swc-01", "Eth1/10"),
    _cable("swd-01", "Eth1/2", "swc-02", "Eth1/10"),
    _cable("swd-01", "Eth1/11", "swa-01", "Gi1/0/49"),
    _cable("swd-01", "Eth1/12", "swa-02", "Gi1/0/49"),
    _cable("swa-01", "Gi1/0/1", "ap-01", "eth0"),
    _cable("swa-01", "Gi1/0/2", "srv-9", "eno1"),
    # the same cable seen from the other end is one line
    _cable("swa-01", "Gi1/0/49", "swd-01", "Eth1/11"),
    # leaves the drawing
    {**_cable("swc-01", "Eth1/49", "dc-spine-1", "Eth1/1"), "b_name": "dc-spine-1"},
]

LAGS = [{"uid": "lag:swd-01:po1", "dev": "swd-01", "name": "Po1", "ports": ["Eth1/1", "Eth1/2", "Eth1/3"]}]

GROUPS = [
    {"uid": "rgrp:vpc:ber1:10", "kind": "vpc", "name": "vpc-domain-10", "members": ["swc-01", "swc-02"]},
    {"uid": "rgrp:cp-cluster:ber1", "kind": "cp-cluster", "name": "ber1-fw", "members": ["fw-01", "fw-02"]},
]

WAN = ["rth-01", "rth-02"]


def _plan(**over):
    args = {"devices": DEVICES, "cables": CABLES, "lags": LAGS, "groups": GROUPS, "wan_devices": WAN, **over}
    return planner.plan(**args)


def _nodes(model):
    return {n["id"]: n for n in model["nodes"]}


def test_the_hop_depth_counts_from_the_wan_devices():
    nodes = _nodes(_plan())
    depth = {
        u: nodes[u]["depth"] for u in ("rth-01", "fw-01", "swc-01", "swd-01", "swa-01", "ap-01", "srv-9")
    }
    assert depth == {"rth-01": 0, "fw-01": 1, "swc-01": 2, "swd-01": 3, "swa-01": 4, "ap-01": 5, "srv-9": 5}
    assert nodes["rth-01"]["anchor"] == "wan-link"
    assert nodes["swc-01"]["anchor"] is None


def test_each_cable_points_from_its_outer_end_and_a_peer_link_is_lateral():
    cables = {(c["from"]["dev"], c["to"]["dev"]): c for c in _plan()["cables"]}
    assert len(cables) == 13
    assert ("swc-01", "swd-01") in cables and ("swd-01", "swc-01") not in cables
    assert cables[("swc-01", "swd-01")]["from"]["port"] == "Eth1/10"
    assert not cables[("swc-01", "swd-01")]["lateral"]
    peer = cables.get(("swc-01", "swc-02")) or cables[("swc-02", "swc-01")]
    assert peer["lateral"]


def test_devices_go_in_the_block_of_their_tier_and_a_firewall_in_the_border_it_faces():
    nodes = _nodes(_plan())
    assert nodes["block:ber1:wan-edge"]["label"] == "WAN edge"
    fw_block = nodes["block:ber1:firewall:campus+wan-edge"]
    assert fw_block["label"] == "Firewall (Campus, WAN edge)"
    assert fw_block["faces"] == ["campus", "wan-edge"]
    assert fw_block["parent"] == "site:ber1"
    assert nodes["rth-01"]["parent"] == "block:ber1:wan-edge"
    assert nodes["swd-01"]["parent"] == "block:ber1:campus"
    assert nodes["swd-01"]["block_basis"] == "tier"


def test_a_device_with_no_tier_takes_the_block_of_its_neighbors():
    nodes = _nodes(_plan())
    assert nodes["srv-9"]["parent"] == "block:ber1:campus"
    assert nodes["srv-9"]["block_basis"] == "inferred"
    assert nodes["srv-9"]["partition"] is None


def test_a_redundancy_group_in_one_block_is_a_box_that_holds_its_members():
    nodes = _nodes(_plan())
    assert nodes["rgrp:vpc:ber1:10"]["parent"] == "block:ber1:campus"
    assert nodes["swc-01"]["parent"] == nodes["swc-02"]["parent"] == "rgrp:vpc:ber1:10"
    assert nodes["rgrp:cp-cluster:ber1"]["parent"] == "block:ber1:firewall:campus+wan-edge"
    assert nodes["fw-01"]["parent"] == "rgrp:cp-cluster:ber1"


def test_a_group_across_two_blocks_is_listed_and_draws_no_box():
    split = [{"uid": "rgrp:x", "kind": "vpc", "name": "x", "members": ["swd-01", "rth-01"]}]
    model = _plan(groups=split)
    assert "rgrp:x" not in _nodes(model)
    assert model["split_groups"] == [
        {"uid": "rgrp:x", "kind": "vpc", "name": "x", "members": ["rth-01", "swd-01"]}
    ]


def test_a_lag_to_both_peers_of_a_domain_is_multi_chassis_and_keeps_every_cable():
    [lag] = _plan()["lags"]
    assert lag["far"] == ["swc-01", "swc-02"]
    assert len(lag["cables"]) == 2
    assert lag["multi_chassis"] and lag["basis"] == "inferred"
    assert lag["ports_without_cable"] == ["Eth1/3"]


def test_a_cable_that_leaves_the_drawing_is_an_exit():
    assert _plan()["exits"] == [
        {
            "dev": "swc-01",
            "port": "Eth1/49",
            "far_dev": "dc-spine-1",
            "far_port": "Eth1/1",
            "far_name": "dc-spine-1",
            "source": "lldp",
        }
    ]


def test_the_partition_orders_the_tiers_inside_a_block():
    nodes = _nodes(_plan())
    assert [nodes[u]["partition"] for u in ("swc-01", "swd-01", "swa-01", "ap-01")] == [0, 1, 2, 3]


def test_the_same_rows_in_any_order_give_the_same_model():
    expected = _plan()
    rng = random.Random(7)
    for _ in range(5):
        devices, cables, groups = list(DEVICES), list(CABLES), list(GROUPS)
        rng.shuffle(devices)
        rng.shuffle(cables)
        rng.shuffle(groups)
        assert _plan(devices=devices, cables=cables, groups=groups) == expected


def test_with_no_wan_device_the_cables_that_leave_the_drawing_anchor_it():
    inner = [d for d in DEVICES if d["tier"] not in planner.OUTER_TIERS]
    nodes = _nodes(_plan(devices=inner, wan_devices=[]))
    # the firewalls' cables to the hubs and the core's cable to the spine leave the drawing
    assert {u for u, n in nodes.items() if n.get("anchor") == "exit"} == {"fw-01", "fw-02", "swc-01"}
    assert nodes["swd-01"]["depth"] == 1


def test_with_no_outer_device_and_no_exit_the_top_tier_anchors_it():
    campus = [d for d in DEVICES if d["tier"] in ("core", "distribution", "access")]
    keep = {d["uid"] for d in campus}
    cables = [c for c in CABLES if c["a_dev"] in keep and c["b_dev"] in keep]
    nodes = _nodes(_plan(devices=campus, cables=cables, wan_devices=[]))
    assert {u for u, n in nodes.items() if n.get("anchor")} == {"swc-01", "swc-02"}


def test_with_no_tier_at_all_the_best_connected_device_anchors_it():
    flat = [{**d, "tier": None, "role": "unknown"} for d in DEVICES]
    cables = [c for c in CABLES if c["b_dev"] != "dc-spine-1"]
    nodes = _nodes(_plan(devices=flat, wan_devices=[], cables=cables, groups=[]))
    assert {u for u, n in nodes.items() if n.get("anchor")} == {"swd-01"}
    assert all(n["parent"].startswith("block:ber1:other") for n in nodes.values() if n["kind"] == "device")


def test_a_neighbor_at_another_site_does_not_vote_for_the_block():
    devices = [_dev("ham-swc-01", "core", site="ham2"), _dev("ham-x", None, "unknown", site="ber1")]
    nodes = _nodes(planner.plan(devices, [_cable("ham-swc-01", "e1", "ham-x", "e1")]))
    assert nodes["ham-x"]["parent"] == "block:ber1:other"
    assert nodes["ham-x"]["block_basis"] == "none"


def test_a_device_with_no_site_goes_in_the_no_site_box():
    nodes = _nodes(planner.plan([_dev("lone", "core", site=None)], []))
    assert nodes["lone"]["parent"] == "block:-:campus"
    assert nodes["site:-"]["kind"] == "site"


def test_a_device_carries_its_management_address_and_a_cable_its_link_speed():
    devices = [{**DEVICES[0], "mgmt_ip": "10.0.0.1"}, *DEVICES[1:]]
    cables = [{**CABLES[1], "speed_mbps": 1000}, *CABLES[:1], *CABLES[2:]]
    model = _plan(devices=devices, cables=cables)
    nodes = _nodes(model)
    assert nodes["rth-01"]["mgmt_ip"] == "10.0.0.1"
    assert nodes["rth-02"]["mgmt_ip"] is None
    speeds = {(c["from"]["dev"], c["to"]["dev"]): c["speed_mbps"] for c in model["cables"]}
    assert speeds[("rth-01", "fw-01")] == 1000
    assert speeds[("rth-02", "fw-02")] is None
