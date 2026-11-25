"""The leak guard record and the rule explanation lines on a router that
mirrors core1 of the home estate: LAN-WAN rule 10 drops the 2 hosts of group
meta-download when they leave through eth2, 2 policy routes on eth0 and
eth0.10 send the same hosts into table 144, whose default route leaves through
wg44, and the default table routes the internet out pppoe0, 10.13.128.0/24 out
wg0 and 10.10.10.1 out eth0 into zone LAN.

The record names pppoe0 and wg0 as the exits the rule does not cover and
leaves eth0 out, because the LAN-WAN rulebase never sees traffic into zone LAN.
"""

from __future__ import annotations

import copy
from typing import Any

from tests.support.policy_route_graph import BatchGraph

from hst.collectors.vyos import normalize_vyos
from hst.path import leak_guard
from hst.path.session import CycleSession
from hst.results.words import FORBIDDEN_WORDS

HOST = "core1"
LAN_WAN = f"vyos:{HOST}:fw:LAN-WAN"
RULE = f"{LAN_WAN}:10"

MATCH_ROUTE = {"source": {"group": {"address-group": "meta-download"}}, "set": {"table": "144"}}

CONFIG: dict[str, Any] = {
    "system": {"host-name": HOST},
    "interfaces": {
        "ethernet": {
            "eth0": {"address": ["192.168.2.1/24"], "vif": {"10": {"address": ["192.168.10.1/24"]}}},
            "eth2": {"description": "modem"},
        },
        "dummy": {"dum0": {"address": ["10.255.255.1/32"]}},
        "pppoe": {"pppoe0": {"source-interface": "eth2", "description": "1und1", "no-default-route": {}}},
        "wireguard": {
            "wg0": {
                "address": ["10.13.128.2/32"],
                "description": "torguard usa",
                "peer": {"usa": {"address": "198.51.100.10", "port": "51820", "allowed-ips": ["0.0.0.0/0"]}},
            },
            "wg44": {
                "address": ["10.14.4.2/32"],
                "description": "torguard suisse",
                "peer": {
                    "suisse": {"address": "203.0.113.20", "port": "51820", "allowed-ips": ["0.0.0.0/0"]}
                },
            },
        },
    },
    "firewall": {
        "group": {"address-group": {"meta-download": {"address": ["192.168.2.45", "192.168.2.70"]}}},
        "ipv4": {
            "name": {
                "LAN-WAN": {
                    "default-action": "accept",
                    "rule": {
                        "10": {
                            "action": "drop",
                            "source": {"group": {"address-group": "meta-download"}},
                            "outbound-interface": {"name": "eth2"},
                        }
                    },
                }
            }
        },
        "zone": {
            "LAN": {"default-action": "drop", "member": {"interface": ["eth0", "eth0.10", "dum0"]}},
            "WAN": {
                "default-action": "drop",
                "member": {"interface": ["eth2", "pppoe0", "wg0", "wg44"]},
                "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
            },
        },
    },
    "policy": {
        "route": {
            "WIREGUARD-PBR": {"interface": ["eth0.10"], "rule": {"30": MATCH_ROUTE}},
            "WIREGUARD-PBR-MAIN": {"interface": ["eth0"], "rule": {"20": MATCH_ROUTE}},
        }
    },
    "protocols": {
        "static": {
            "route": {
                "0.0.0.0/0": {"interface": {"pppoe0": {}}},
                "10.13.128.0/24": {"interface": {"wg0": {}}},
                "10.10.10.1/32": {"next-hop": {"192.168.2.36": {}}},
            },
            "table": {"144": {"route": {"0.0.0.0/0": {"interface": {"wg44": {}}}}}},
        }
    },
}

VERSION = "Version:          VyOS 1.5-rolling-202607150020\nHardware S/N:     CORE1\n"
LINKS = [
    {"ifname": "eth0", "address": "aa:bb:cc:00:01:01"},
    {"ifname": "eth2", "address": "aa:bb:cc:00:01:03"},
]

LINES = [
    "LAN-WAN rule 10 on core1 drops traffic from 192.168.2.45 and 192.168.2.70 (group meta-download) "
    "when it leaves through eth2.",
    "These 2 hosts are normally policy-routed into wg44 by WIREGUARD-PBR rule 30 and WIREGUARD-PBR-MAIN "
    "rule 20. Rule 10 applies when that routing does not.",
    "It does not cover pppoe0 or wg0, so without the policy routes the hosts still get out through them.",
]


def session() -> CycleSession:
    batch = normalize_vyos(
        {"config": copy.deepcopy(CONFIG), "version_text": VERSION, "links": LINKS}, l3dom="home"
    )
    return CycleSession(BatchGraph(batch), BatchGraph.cts)


def test_the_record_names_the_wan_exits_the_rule_does_not_cover():
    found = leak_guard.leak_guards(session(), LAN_WAN, RULE, 4)

    assert found["leak_guards"] == []
    (gap,) = found["guard_gaps"]
    assert gap["decided"] is True and "missing" not in gap
    assert gap["kind"] == "gap" and gap["rule"] == RULE
    assert gap["tunnel"]["interface"] == "wg44" and gap["tunnel"]["description"] == "torguard suisse"
    assert gap["policy_routes"] == [
        f"vyos:{HOST}:pbr:WIREGUARD-PBR:30",
        f"vyos:{HOST}:pbr:WIREGUARD-PBR-MAIN:20",
    ]
    assert gap["hosts"] == ["192.168.2.45", "192.168.2.70"]
    assert gap["host_objects"] == ["meta-download"]
    assert gap["rule_exits"] == ["eth2"]
    assert gap["exits_not_covered"] == ["pppoe0", "wg0"]
    assert gap["line"] == LINES[2]


def test_an_exit_into_zone_lan_is_not_a_gap():
    found = leak_guard.leak_guards(session(), LAN_WAN, RULE, 4)

    exits = [out for record in found["guard_gaps"] for out in record["detail"]["breakout"]]
    assert exits and all("LAN" not in out["zones"] for out in exits)
    assert all(out["interface"]["name"] != "eth0" for out in exits)


def test_the_rule_facts_give_line_1():
    facts = leak_guard.rule_facts(session(), LAN_WAN, RULE, 4)

    assert facts == {
        "action": "drop",
        "hosts": ["192.168.2.45", "192.168.2.70"],
        "host_objects": ["meta-download"],
        "destinations": "any",
        "exits": ["eth2"],
        "device": "core1",
        "rulebase": "LAN-WAN",
        "position": 10,
    }


def test_the_explanation_is_the_3_lines():
    from hst.twin_tools.policy import explanation

    pinned = session()
    summary = explanation(
        leak_guard.rule_facts(pinned, LAN_WAN, RULE, 4), leak_guard.leak_guards(pinned, LAN_WAN, RULE, 4)
    )

    assert summary["lines"] == LINES
    assert summary["role"] == {
        "tunnels": ["wg44"],
        "policy_routes": ["WIREGUARD-PBR rule 30", "WIREGUARD-PBR-MAIN rule 20"],
    }
    assert summary["not_covered"] == ["pppoe0", "wg0"]
    text = " ".join(summary["lines"]).lower()
    banned = FORBIDDEN_WORDS | {
        "definite",
        "settled",
        "certain",
        "match set",
        "zone pair",
        "guards",
        "backs up",
    }
    assert not [word for word in banned if word in text]


def test_policy_evaluate_leads_with_the_3_lines(monkeypatch):
    from tests.test_twin_tools_assessment import _context, _explained, _published
    from tests.twin_tools_fakes import FakeGraph, call, install

    from hst import symbolic
    from hst.assessment import direct
    from hst.twin_tools import catalogue_registry, policy

    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    monkeypatch.setattr(
        direct,
        "run_isolated",
        lambda settings, inputs: _explained(action="drop", summary="the engine sentence"),
    )
    pinned = session()
    monkeypatch.setattr(policy.pathmod, "pinned", lambda graph, snapshot: pinned)
    analyse = leak_guard.leak_guards
    monkeypatch.setattr(leak_guard, "leak_guards", lambda s, rb, rule, af, rib=None: analyse(s, rb, rule, af))

    failed, envelope = call(
        "policy_evaluate",
        {"mode": "explain_rule", "rulebase": LAN_WAN, "rule": RULE},
        _context(analysis_engine="symbolic-v2"),
    )

    assert not failed, envelope
    result = envelope["result"]
    assert result["summary"]["lines"] == LINES
    assert result["match_detail"] == "the engine sentence"
    assert result["first_match"]
    assert not {"definite", "possible_only", "definite_count", "possible_count"} & set(result)
    assert (result["first_match_count"], result["not_decided_count"]) == (1, 2)
    assert catalogue_registry().get("policy_evaluate").version == 4
