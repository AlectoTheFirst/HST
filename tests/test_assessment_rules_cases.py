"""Assessment rules: a repair universe that leaves
rules out, the regression policy hook on reads that are no rule read, the
paged semantic input read, the scope classes of a rule behind a jump, and the
zone policy of a flow no zone-pair ruleset receives."""

from __future__ import annotations

import random
from types import SimpleNamespace

from tests.support import policy_route_graph as vyos
from tests.support.batch_inventory import inventory

from hst import path as pathmod
from hst.assessment import flow_match
from hst.assessment.adapters import _PolicyEdits
from hst.assessment.repair import generate_firewall_candidates, search_repairs
from hst.assessment.rule_scope import scope_space
from hst.assessment.search import FAILS, SearchLimits
from hst.assessment.semantic import digest, read_snapshot_inputs
from hst.core.manifest import DeviceEntry, SectionOutcome
from hst.path.gates.firewall import _JUMP_TARGET, _RULEBASE_RULES
from hst.path.leak_guard import _RULEBASE_SCOPE

HOST = vyos.HOST
LAN_WAN = f"vyos:{HOST}:fw:LAN-WAN"
GUARD = f"vyos:{HOST}:fw:GUARD"
SCOPE = {"source": ["10.0.0.0/24"], "destination": ["192.0.2.10/32"], "protocols": ["tcp"], "ports": ["443"]}


# --- repair.py: an excluded rule leaves the universe incomplete ---------------------------------


def _state_rule():
    # a drop rule with a connection-state match: rule_as_add cannot regenerate it
    return {
        "uid": f"{LAN_WAN}:10",
        "pos": 10,
        "action": "drop",
        "src_any": True,
        "dst_any": True,
        "svc_any": True,
        "states": ["new"],
    }


def test_a_rule_the_generator_excludes_withholds_a_complete_universe_and_infeasibility():
    generated = generate_firewall_candidates(
        {LAN_WAN: [_state_rule()]}, {LAN_WAN: "dev:gw"}, SCOPE, ["fw_rule.modify", "fw_rule.remove"]
    )

    assert generated["excluded"] and not generated["candidates"]
    assert generated["universe_complete"] is False
    result = search_repairs(generated, lambda intents: {"desired": FAILS, "protected": {}}, SearchLimits())
    assert not result["proved_infeasible"] and not result["search_complete"]


def test_a_family_whose_rules_are_all_regenerated_stays_complete():
    rule = {key: value for key, value in _state_rule().items() if key != "states"}
    generated = generate_firewall_candidates(
        {LAN_WAN: [rule]}, {LAN_WAN: "dev:gw"}, SCOPE, ["fw_rule.modify", "fw_rule.remove"]
    )

    assert not generated["excluded"] and len(generated["candidates"]) == 2
    assert generated["universe_complete"] is True


# --- adapters.py: only the gates' rule reads are rewritten --------------------------------------


def _edit(before, after):
    return {
        "family": "firewall",
        "selector": [GUARD, f"{GUARD}:10"],
        "before": before,
        "after": after,
        "preconditions": {"forward": digest(before), "reverse": digest(after)},
    }


def test_the_policy_hook_leaves_the_jump_target_and_rulebase_scope_reads_alone():
    rule = {"uid": f"{GUARD}:10", "pos": 10, "action": "drop"}
    target = [
        {
            "rb_uid": GUARD,
            "rb_name": "GUARD",
            "default_action": "return",
            "default_action_unknown": False,
            "default_jump_target": "",
        }
    ]
    for query in (_JUMP_TARGET, _RULEBASE_SCOPE):
        modified = _PolicyEdits([_edit([{**rule, "action": "accept"}], [rule])], "reverse")
        assert modified.rewrite(query, {"rb": GUARD}, target) is target
        removed = _PolicyEdits([_edit([rule], [])], "reverse")
        assert removed.rewrite(query, {"rb": GUARD}, target) is target
    reverted = _PolicyEdits([_edit([{**rule, "action": "accept"}], [rule])], "reverse")
    assert reverted.rewrite(_RULEBASE_RULES, {"rb": GUARD}, [rule]) == [{**rule, "action": "accept"}]


# --- semantic.py: the paged read asks for one total order ---------------------------------------


def test_the_paged_semantic_read_orders_every_page_so_no_row_is_read_twice_or_skipped(monkeypatch):
    nodes = [
        {
            "uid": f"n{i:04d}",
            "labels": ["Obj", "Interface"],
            "props": {"_sources": ["s"], "_scope": "ios:r1", "name": str(i)},
            "element_id": f"e{i}",
        }
        for i in range(2500)
    ]
    shuffle = random.Random(7)

    def read(session, query, **params):
        if "type(r)" in query:
            return []
        rows = list(nodes)
        # a database returns no stable order across executions unless asked
        if "ORDER BY uid, element_id" in query:
            rows.sort(key=lambda row: (row["uid"], row["element_id"]))
        else:
            shuffle.shuffle(rows)
        return rows[params["offset"] : params["offset"] + params["limit"]]

    monkeypatch.setattr(pathmod, "_read", read)
    device = DeviceEntry(
        source="s",
        host="r1",
        outcome="collected",
        expected_sections=["config"],
        sections={"config": SectionOutcome(status="ok")},
    )
    snapshot = SimpleNamespace(cts="1", manifest=SimpleNamespace(devices=[device], files=[]))

    read_back = read_snapshot_inputs(None, snapshot, SimpleNamespace(hst_data_dir="/nonexistent"))

    keys = [record["key"] for record in read_back["records"] if record["key"].startswith("node:")]
    assert sorted(keys) == [f"node:{node['uid']}" for node in nodes]


# --- rule_scope.py: the rules of a jumped ruleset split the classes -----------------------------

ZONES = {
    "LAN": {"member": {"interface": ["eth1", "eth1.10"]}, "default-action": "drop"},
    "WAN": {
        "member": {"interface": ["eth0", "eth2"]},
        "default-action": "drop",
        "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
    },
}


def _graph(rulesets, *, unrecorded=()):
    """The router with eth2, the rulesets and ZONES; the LAN zone without the
    properties `unrecorded` names."""

    def patch(cfg):
        cfg["interfaces"]["ethernet"]["eth2"] = {"address": ["dhcp"], "description": "WAN2"}
        cfg["firewall"] = {"ipv4": {"name": rulesets}, "zone": ZONES}

    batch = vyos.batch(patch)
    for node in batch.nodes:
        if node.label == "Zone" and node.props.get("name") == "LAN":
            for key in unrecorded:
                node.props.pop(key, None)
    return inventory(batch)


def _jump_graph(lan_wan_rules):
    return _graph(
        {
            "LAN-WAN": {"default-action": "drop", "rule": lan_wan_rules},
            "GUARD": {
                "default-action": "return",
                "rule": {
                    "10": {"action": "drop", "inbound-interface": {"name": "eth1.10"}},
                    "20": {"action": "drop", "state": {"invalid": "enable"}},
                },
            },
        }
    )


def test_a_jumped_ruleset_splits_the_ingress_and_state_classes_of_a_later_rule():
    graph = _jump_graph(
        {
            "5": {"action": "jump", "jump-target": "GUARD"},
            "10": {"action": "accept", "destination": {"address": "10.0.0.0/8"}},
        }
    )

    space = scope_space(graph, LAN_WAN, f"{LAN_WAN}:10")

    assert sorted(cls.members for cls in space.ingress) == [("eth1",), ("eth1.10",)]
    assert ("invalid",) in [cls.members for cls in space.states]
    assert all("invalid" not in cls.members for cls in space.states if len(cls.members) > 1)
    assert space.gaps == ()


def test_a_ruleset_without_a_jump_keeps_one_class_per_side():
    graph = _jump_graph({"10": {"action": "accept", "destination": {"address": "10.0.0.0/8"}}})

    space = scope_space(graph, LAN_WAN, f"{LAN_WAN}:10")

    assert [cls.members for cls in space.ingress] == [("eth1", "eth1.10")]
    assert len(space.states) == 1


# --- flow_match.py: the zone policy of a flow no zone-pair ruleset receives ---------------------


def test_a_flow_into_a_zone_no_ruleset_binds_takes_the_destination_zone_default():
    graph = _graph({"LAN-WAN": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}})
    device = next(uid for uid in sorted(graph.labels["Device"]) if HOST in uid)
    assert [
        flow_match._rulebase(graph, "test", device, uid, 4, None, None, "eth0", "eth1")["decision"]
        for uid in flow_match.device_rulebases(graph, device)
    ] == ["not_applicable"]

    entry = flow_match.zone_policy(graph, device, 4, "eth0", "eth1")

    assert entry is not None
    assert entry["uid"] == "zone-pair:WAN->LAN#unbound" and entry["by"] == "default-action"
    assert entry["decision"] == "deny" and entry["gaps"] == [] and entry["receives"] is True


def test_match_lists_the_zone_default_beside_the_rulesets_that_do_not_receive_the_flow():
    from tests.test_rule_explain_scope import _backend

    _backend()
    graph = _graph({"LAN-WAN": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}})
    device = next(uid for uid in sorted(graph.labels["Device"]) if HOST in uid)
    flow = {
        "sources": [[0x0A000005, 0x0A000005]],
        "destinations": [[0xC0A80205, 0xC0A80205]],
        "protocols": [6],
        "destination_ports": [[443, 443]],
        "source_ports": None,
    }

    document = flow_match.match(graph, "test", device, None, flow, 4, ingress="eth0", egress="eth1")

    assert "error" not in document, document
    assert [(entry["uid"], entry["decision"]) for entry in document["rulebases"]] == [
        (LAN_WAN, "not_applicable"),
        ("zone-pair:WAN->LAN#unbound", "deny"),
    ]
    # a named rulebase is answered alone
    named = flow_match.match(graph, "test", device, LAN_WAN, flow, 4, ingress="eth0", egress="eth1")
    assert [entry["uid"] for entry in named["rulebases"]] == [LAN_WAN]


def test_a_flow_inside_one_zone_takes_the_intra_zone_verdict_and_a_bound_pair_takes_none():
    graph = _graph({"LAN-WAN": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}})
    device = next(uid for uid in sorted(graph.labels["Device"]) if HOST in uid)

    intra = flow_match.zone_policy(graph, device, 4, "eth1", "eth1.10")

    assert intra is not None and intra["uid"] == "zone-pair:LAN->LAN#intra"
    # the collector records the zone's intra-zone filtering; a zone without it passes
    assert (
        graph.nodes[
            next(z for z in graph.labels["Zone"] if graph.nodes[z].props.get("name") == "LAN")
        ].props.get("intra_zone_filtering")
        is False
    )
    assert intra["decision"] == "permit" and intra["by"] == "intra-zone default"
    assert flow_match.zone_policy(graph, device, 4, "eth1", "eth0") is None
    assert flow_match.zone_policy(graph, device, 4, "eth1", None) is None


def test_a_zone_without_a_recorded_default_is_indeterminate_with_a_named_gap():
    graph = _graph(
        {"LAN-WAN": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}},
        unrecorded=("default_action", "default_action_unknown", "intra_zone_filtering"),
    )
    device = next(uid for uid in sorted(graph.labels["Device"]) if HOST in uid)

    into = flow_match.zone_policy(graph, device, 4, "eth0", "eth1")
    within = flow_match.zone_policy(graph, device, 4, "eth1", "eth1.10")

    assert into is not None and into["decision"] == "indeterminate"
    assert [gap["code"] for gap in into["gaps"]] == ["ZONE_DEFAULT_UNKNOWN"]
    # A zone without the intra-zone marker (UniFi) gets no zone verdict from the gate.
    assert within is None


def test_an_intra_zone_flow_on_an_unmarked_zone_gets_no_zone_entry(monkeypatch):
    graph = _graph(
        {"LAN-WAN": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}},
        unrecorded=("intra_zone_filtering",),
    )
    device = next(uid for uid in sorted(graph.labels["Device"]) if HOST in uid)
    _stub_engine(monkeypatch)

    document = flow_match.match(graph, "test", device, None, _FLOW, 4, ingress="eth1", egress="eth1.10")

    assert [entry["uid"] for entry in document["rulebases"]] == [LAN_WAN]
    assert document["rulebase_count"] == 1


def test_the_rulebase_count_counts_the_zone_entry_beside_a_truncated_list(monkeypatch):
    graph = _graph({"LAN-WAN": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}})
    device = next(uid for uid in sorted(graph.labels["Device"]) if HOST in uid)
    # 25 rulebases the device governs: more than one answer evaluates
    many = [LAN_WAN] * 25
    monkeypatch.setattr(flow_match, "device_rulebases", lambda graph, device: list(many))
    _stub_engine(monkeypatch)

    document = flow_match.match(graph, "test", device, None, _FLOW, 4, ingress="eth0", egress="eth1")

    entries = document["rulebases"]
    assert entries[-1]["uid"] == "zone-pair:WAN->LAN#unbound"
    assert len(entries) == flow_match.MAX_RULEBASES + 1 and document["rulebases_truncated"]
    # the entries not evaluated are the rulebases past the first 20, and no more
    assert document["rulebase_count"] - len(entries) == len(many) - flow_match.MAX_RULEBASES


_FLOW = {
    "sources": [[0x0A000005, 0x0A000005]],
    "destinations": [[0xC0A80205, 0xC0A80205]],
    "protocols": [6],
    "destination_ports": [[443, 443]],
    "source_ports": None,
}


def _stub_engine(monkeypatch):
    """match() without the native backend: each rulebase answers not_applicable,
    so the test reads only what match() adds around them."""
    import contextlib

    from hst import symbolic

    monkeypatch.setattr(symbolic, "SymbolicManager", lambda schema: contextlib.nullcontext())
    monkeypatch.setattr(
        flow_match,
        "_rulebase",
        lambda graph, estate, device, uid, *args: {"uid": uid, "decision": "not_applicable"},
    )
