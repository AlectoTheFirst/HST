"""The policy tools: `policy_evaluate` in match_flow mode (the
symbolic-v2 child and the trace-derived fallback), `policy_lookup_nat`,
`lb_lookup_vip`, and `reach_trace` in groups mode."""

from __future__ import annotations

import asyncio
import ipaddress
import os
from collections import defaultdict
from types import MappingProxyType

import pytest
from tests.twin_tools_fakes import FakeGraph, call, context, install, settings

from hst import path as pathmod
from hst import symbolic
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.app.agent import traffic
from hst.assessment import direct, flow_match
from hst.assessment import service as assessment_service
from hst.path.gates import firewall as fwmod

REFERENCE = {"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test", "observation_floor_ms": None}
_DEVICE = (
    "MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})",
    lambda p: [{"uid": p["uid"]}] if p["uid"] == "dev:fw1" else [],
)
_FLOW = {"src": "10.0.0.5", "dst": "192.0.2.1", "proto": "tcp", "port": 443}
_MATCH = {"mode": "match_flow", "device": "dev:fw1", "flow": _FLOW}


def _ip(value: str) -> int:
    return int(ipaddress.ip_address(value))


def _published(monkeypatch):
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: dict(REFERENCE))


def _interfaces(own):
    """The device-interface read: the interfaces of dev:fw1 among the uids
    asked, or the one its name names."""

    def rows(params):
        if params["dev"] != "dev:fw1":
            return []
        return [
            {"uid": uid, "name": name}
            for uid, name in own.items()
            if uid in params["uids"] or (params["name"] is not None and name == params["name"])
        ]

    return ("(i:Interface:Obj)-[o:ON]->(:Device:Obj {uid: $dev, collection_ts: $snap})", rows)


def _verdict(**overrides):
    verdict = {
        "rb_uid": "fw:rb",
        "rb_name": "edge",
        "zones": None,
        "rule_uid": "fw:rb/r1",
        "pos": 1,
        "action": "accept",
        "rule_name": "https",
        "by": "rule",
        "partial": False,
        "indeterminate_reason": None,
    }
    verdict.update(overrides)
    return verdict


def _pages(name, arguments, ctx):
    """The pages of one paged call, following next_cursor. Ten pages at
    most, so a cursor that does not advance fails the test's assertions."""
    pages, cursor = [], None
    for _ in range(10):
        failed, envelope = call(name, {**arguments, **({"cursor": cursor} if cursor else {})}, ctx)
        assert not failed, envelope
        pages.append(envelope)
        cursor = envelope["page"]["next_cursor"]
        if cursor is None:
            break
    return pages


# --- policy_evaluate match_flow: the trace-derived match -----------------------------------


@pytest.mark.parametrize(
    ("overrides", "backend", "published", "reason"),
    [
        ({"analysis_engine": "legacy-v1"}, True, True, "legacy-v1 analysis engine"),
        ({"analysis_engine": "symbolic-v2"}, False, True, "native backend is not installed"),
        ({"analysis_engine": "symbolic-v2"}, True, False, "evidence manifest is required"),
    ],
)
def test_match_flow_without_the_symbolic_prerequisites_or_derivable_interfaces_is_engine_unavailable(
    monkeypatch, tmp_path, overrides, backend, published, reason
):
    install(monkeypatch, FakeGraph([_DEVICE, _interfaces({"if:fw1:in": "eth1"})]))
    monkeypatch.setattr(symbolic, "backend_available", lambda: backend)
    if published:
        _published(monkeypatch)
    else:

        def unpublished(settings, value):
            raise ValueError("A published snapshot with an evidence manifest is required.")

        monkeypatch.setattr(assessment_service, "snapshot_reference", unpublished)
    # the trace crosses another device only
    trace = {"hops": [{"uid": "if:r9:in", "kind": "Interface", "stage": "INGRESS_IF", "lane": 0}]}
    monkeypatch.setattr(pathmod, "trace", lambda *args, **kwargs: trace)
    verdicts = []
    monkeypatch.setattr(fwmod, "_firewall_verdict", lambda *args, **kwargs: verdicts.append(args))

    failed, error = call("policy_evaluate", _MATCH, context(sidestore_dir=tmp_path, **overrides))

    assert failed and error["error"]["code"] == "engine_unavailable"
    assert error["error"]["field"] == "ingress_interface"
    assert reason in error["error"]["message"]
    assert verdicts == []


def test_match_flow_names_the_deciding_rule_between_the_interfaces_given(monkeypatch):
    graph = install(
        monkeypatch, FakeGraph([_DEVICE, _interfaces({"if:fw1:in": "eth1", "if:fw1:out": "eth2"})])
    )
    calls = []

    def verdict(session, device, ingress, egress, src_set, dst_set, port, proto, considered, **kwargs):
        calls.append((session.cts, device, ingress, egress, src_set, dst_set, port, proto, kwargs))
        return _verdict()

    monkeypatch.setattr(fwmod, "_firewall_verdict", verdict)

    failed, envelope = call(
        "policy_evaluate",
        {**_MATCH, "ingress_interface": "eth1", "egress_interface": "if:fw1:out"},
        context(analysis_engine="legacy-v1"),
    )

    assert not failed, envelope
    assert calls == [
        (
            4000,
            "dev:fw1",
            "if:fw1:in",
            "if:fw1:out",
            [(4, _ip("10.0.0.5"), _ip("10.0.0.5"))],
            [(4, _ip("192.0.2.1"), _ip("192.0.2.1"))],
            443,
            "tcp",
            {"src_port": None},
        )
    ]
    result = envelope["result"]
    assert result["mode"] == "match_flow" and result["engine"] == "legacy-v1"
    assert result["interfaces"] == [{"ingress": "if:fw1:in", "egress": "if:fw1:out", "derived": False}]
    (rulebase,) = result["rulebases"]
    assert rulebase["uid"] == "fw:rb" and rulebase["decision"] == "permit"
    assert rulebase["deciding_rule"] == {
        "uid": "fw:rb/r1",
        "position": 1,
        "action": "accept",
        "rulebase": "fw:rb",
    }
    assert rulebase["candidate_rules"][0]["match"] == "first_match"
    assert rulebase["evidence"]["result"]["statement"] == "rule-permits"
    assert rulebase["evidence"]["result"]["word"] == "permitted"
    assert rulebase["evidence"]["result"]["answer"] == "true"
    assert rulebase["evidence"]["basis"] == "derived"
    assert envelope["evidence"]["result"]["word"] == "permitted"
    assert envelope["evidence"]["result"]["answer"] == "true"
    assert envelope["provenance"]["engine"] == "legacy-v1"
    assert any("prerequisites are missing" in u for u in envelope["evidence"]["unknowns"])
    # the device-interface reads name the device the caller resolved
    assert {params["dev"] for params in graph.reads("(i:Interface:Obj)-[o:ON]->")} == {"dev:fw1"}


def test_match_flow_derives_the_interfaces_from_a_trace_of_the_flow(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph([_DEVICE, _interfaces({"if:fw1:in": "eth1", "if:fw1:out": "eth2"})]))
    traced = []
    hops = [
        {"uid": "if:r1:in", "kind": "Interface", "stage": "INGRESS_IF", "lane": 0},
        {"uid": "dev:r1", "kind": "Device", "stage": "DEVICE", "lane": 0},
        {"uid": "if:r1:out", "kind": "Interface", "stage": "EGRESS_IF", "lane": 0},
        {"uid": "if:fw1:in", "kind": "Interface", "stage": "INGRESS_IF", "lane": 0},
        {"uid": "dev:fw1", "kind": "Device", "stage": "DEVICE", "lane": 0},
        {"uid": "if:fw1:out", "kind": "Interface", "stage": "EGRESS_IF", "lane": 0},
    ]

    def trace(session, src, dst, port=None, proto=None, gateways=None, rib=None, **kwargs):
        traced.append((src, dst, port, proto, kwargs))
        return {"hops": hops}

    monkeypatch.setattr(pathmod, "trace", trace)
    pairs = []
    monkeypatch.setattr(
        fwmod,
        "_firewall_verdict",
        lambda session, device, ingress, egress, *args, **kwargs: (
            pairs.append((ingress, egress)) or _verdict(action="drop")
        ),
    )

    failed, envelope = call(
        "policy_evaluate", _MATCH, context(sidestore_dir=tmp_path, analysis_engine="legacy-v1")
    )

    assert not failed, envelope
    assert traced == [("10.0.0.5", "192.0.2.1", 443, "tcp", {})]
    assert pairs == [("if:fw1:in", "if:fw1:out")]
    assert envelope["result"]["interfaces"] == [
        {"ingress": "if:fw1:in", "egress": "if:fw1:out", "derived": True}
    ]
    rulebase = envelope["result"]["rulebases"][0]
    assert rulebase["decision"] == "deny"
    assert rulebase["evidence"]["result"]["answer"] == "false"


def test_a_ranged_verdict_folds_its_regions_per_rulebase(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE, _interfaces({"if:fw1:in": "eth1"})]))
    regions = [
        _verdict(),
        _verdict(rule_uid="fw:rb/r2", pos=2, action="drop"),
        _verdict(
            rb_uid="fw:other",
            rb_name="other",
            rule_uid=None,
            pos=None,
            action="bogus",
            by="default-action",
            indeterminate_reason="the chain's default action is not recorded",
        ),
    ]
    monkeypatch.setattr(fwmod, "_firewall_verdict", lambda *args, **kwargs: regions)

    failed, envelope = call(
        "policy_evaluate",
        {**_MATCH, "flow": {**_FLOW, "port": "1-1024"}, "ingress_interface": "if:fw1:in"},
        context(analysis_engine="legacy-v1"),
    )

    assert not failed, envelope
    mixed, undecided = envelope["result"]["rulebases"]
    assert mixed["decision"] == "partly" and mixed["deciding_rule"] is None
    assert [rule["uid"] for rule in mixed["candidate_rules"]] == ["fw:rb/r1", "fw:rb/r2"]
    assert mixed["evidence"]["result"]["answer"] == "partly"
    assert undecided["decision"] == "open"
    assert undecided["reason"] == "the chain's default action is not recorded"
    assert undecided["evidence"]["result"]["answer"] == "open"
    assert envelope["evidence"]["result"]["word"] == "each item states its own result"


@pytest.mark.parametrize("engine", ["legacy-v1", "symbolic-v2"])
def test_match_flow_pages_its_rulebases_with_the_cursor(monkeypatch, engine):
    install(monkeypatch, FakeGraph([_DEVICE, _interfaces({"if:fw1:in": "eth1"})]))
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    other = {"rb_uid": "fw:other", "rb_name": "other", "rule_uid": "fw:other/r1"}
    monkeypatch.setattr(fwmod, "_firewall_verdict", lambda *args, **kwargs: [_verdict(), _verdict(**other)])
    document = _child_document()
    document["rulebases"].append({**document["rulebases"][0], "uid": "fw:other", "name": "other"})
    document["rulebase_count"] = 2
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: document)

    pages = _pages(
        "policy_evaluate",
        {**_MATCH, "ingress_interface": "if:fw1:in", "limit": 1},
        context(analysis_engine=engine),
    )

    assert [[rulebase["uid"] for rulebase in page["result"]["rulebases"]] for page in pages] == [
        ["fw:rb"],
        ["fw:other"],
    ]
    assert [page["page"]["next_cursor"] is None for page in pages] == [False, True]
    assert [page["page"]["total"] for page in pages] == [2, 2]


def test_an_interface_the_device_does_not_have_is_not_found(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE, _interfaces({"if:fw1:in": "eth1"})]))

    failed, error = call(
        "policy_evaluate", {**_MATCH, "ingress_interface": "eth9"}, context(analysis_engine="legacy-v1")
    )

    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == "ingress_interface"


def test_a_flow_the_trace_grammar_refuses_is_invalid_argument_before_any_read(monkeypatch):
    graph = install(monkeypatch, FakeGraph([_DEVICE]))

    failed, error = call("policy_evaluate", {**_MATCH, "flow": {**_FLOW, "port": "http"}})

    assert failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "flow"
    assert graph.session_kwargs == []


# --- policy_evaluate match_flow: the symbolic-v2 child -------------------------------------


def _child_document(**overrides):
    rulebase = {
        "uid": "fw:rb",
        "name": "edge",
        "vendor": None,
        "firewall": None,
        "qualified": True,
        "decision": "permit",
        "deciding_rule": {"uid": "fw:rb/r1", "position": 1, "action": "permit", "rulebase": "fw:rb"},
        "candidate_rules": [
            {
                "uid": "fw:rb/r1",
                "position": 1,
                "rulebase": "fw:rb",
                "action": "permit",
                "match": "definite",
                "whole_flow": True,
            }
        ],
        "candidate_rules_truncated": False,
        "gaps": [],
    }
    rulebase.update(overrides)
    return {
        "device": "dev:fw1",
        "address_family": 4,
        "rulebases": [rulebase],
        "rulebase_count": 1,
        "rulebases_truncated": False,
    }


def test_match_flow_runs_in_the_analysis_child_with_the_symbolic_prerequisites(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    sent = []

    def isolated(settings, inputs):
        sent.append(inputs)
        return _child_document()

    monkeypatch.setattr(direct, "run_isolated", isolated)

    failed, envelope = call(
        "policy_evaluate", {**_MATCH, "rulebase": "fw:rb"}, context(analysis_engine="symbolic-v2")
    )

    assert not failed, envelope
    assert sent == [
        {
            "analysis": {"kind": "symbolic-match-flow"},
            "snapshot": REFERENCE,
            "device": "dev:fw1",
            "rulebase": "fw:rb",
            "flow": {
                "sources": [[_ip("10.0.0.5"), _ip("10.0.0.5")]],
                "destinations": [[_ip("192.0.2.1"), _ip("192.0.2.1")]],
                "protocols": [6],
                "destination_ports": [[443, 443]],
                "source_ports": None,
            },
            "address_family": 4,
        }
    ]
    (rulebase,) = envelope["result"]["rulebases"]
    assert rulebase["evidence"]["result"]["word"] == "permitted"
    assert rulebase["evidence"]["result"]["answer"] == "true"
    assert rulebase["evidence"]["basis"] == "computed"
    assert envelope["result"]["engine"] == "symbolic-v2"
    assert envelope["provenance"]["engine"] == "symbolic-v2"
    assert envelope["evidence"]["result"]["answer"] == "true"


def test_the_child_receives_the_interfaces_and_names_the_rulebases_it_leaves_open(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    sent = []

    def isolated(settings, inputs):
        sent.append(inputs)
        return _child_document(receives=None)

    monkeypatch.setattr(direct, "run_isolated", isolated)

    failed, envelope = call(
        "policy_evaluate",
        {**_MATCH, "ingress_interface": "eth1", "egress_interface": "eth2"},
        context(analysis_engine="symbolic-v2"),
    )

    assert not failed, envelope
    assert (sent[0]["ingress_interface"], sent[0]["egress_interface"]) == ("eth1", "eth2")
    assert any("fw:rb (receives is null)" in unknown for unknown in envelope["evidence"]["unknowns"])
    assert not any("are not used by" in unknown for unknown in envelope["evidence"]["unknowns"])


def test_a_rulebase_that_does_not_receive_the_flow_is_proven_not_applicable(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    document = _child_document(
        receives=False, decision="not_applicable", deciding_rule=None, candidate_rules=[]
    )
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: document)

    failed, envelope = call(
        "policy_evaluate",
        {**_MATCH, "ingress_interface": "eth1", "egress_interface": "eth2"},
        context(analysis_engine="symbolic-v2"),
    )

    assert not failed, envelope
    (rulebase,) = envelope["result"]["rulebases"]
    assert rulebase["evidence"]["result"]["answer"] == "not-applicable"
    assert not any("receives is null" in unknown for unknown in envelope["evidence"]["unknowns"])


def test_an_undecided_rulebase_is_not_established_with_its_gaps(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    document = _child_document(
        decision="indeterminate",
        deciding_rule=None,
        gaps=[{"code": "GRAPH_RULE_UNSUPPORTED_FIELD", "subject": "fw:rb/r1"}],
    )
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: document)

    failed, envelope = call("policy_evaluate", _MATCH, context(analysis_engine="symbolic-v2"))

    assert not failed, envelope
    rulebase = envelope["result"]["rulebases"][0]
    assert rulebase["evidence"]["result"]["answer"] == "open"
    assert [m["code"] for m in rulebase["evidence"]["result"]["missing"]] == ["GRAPH_RULE_UNSUPPORTED_FIELD"]
    assert envelope["evidence"]["result"]["answer"] == "open"
    assert envelope["evidence"]["gaps"][0]["code"] == "GRAPH_RULE_UNSUPPORTED_FIELD"


def test_the_child_refusal_of_a_match_is_a_tool_error(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    _published(monkeypatch)
    monkeypatch.setattr(symbolic, "backend_available", lambda: True)
    refusal = {
        "error": {
            "code": "not_found",
            "message": "fw:x is not an access rulebase that governs device dev:fw1",
            "field": "rulebase",
            "candidates": [{"uid": "fw:rb", "name": "edge"}],
        }
    }
    monkeypatch.setattr(direct, "run_isolated", lambda settings, inputs: refusal)

    failed, error = call(
        "policy_evaluate", {**_MATCH, "rulebase": "fw:x"}, context(analysis_engine="symbolic-v2")
    )

    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == "rulebase"
    assert error["error"]["candidates"] == [{"uid": "fw:rb", "name": "edge"}]


def test_the_child_dispatches_the_match_kind(monkeypatch):
    seen = []
    monkeypatch.setattr(
        flow_match, "execute_match", lambda settings, inputs, cancelled=None: seen.append(inputs) or {}
    )

    assessment_service.execute(None, {"analysis": {"kind": "symbolic-match-flow"}})

    assert seen == [{"analysis": {"kind": "symbolic-match-flow"}}]


def _inventory(nodes, relations):
    """A GraphInventory of `nodes` (uid, labels, props) and `relations` (kind, start, end)."""
    catalog = {
        uid: GraphNode(uid, frozenset(labels), MappingProxyType(props)) for uid, labels, props in nodes
    }
    outgoing, incoming, labels = defaultdict(list), defaultdict(list), defaultdict(list)
    for kind, start, end in relations:
        relation = GraphRelation(f"{start}>{kind}>{end}", kind, start, end, MappingProxyType({}))
        outgoing[start, kind].append(relation)
        incoming[end, kind].append(relation)
    for uid, node in catalog.items():
        for label in node.labels:
            labels[label].append(uid)
    return GraphInventory(
        "a" * 64,
        "fingerprint",
        MappingProxyType(catalog),
        MappingProxyType({key: tuple(value) for key, value in labels.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )


def test_the_rulebases_of_a_device_are_enforced_grouped_or_zone_bound():
    graph = _inventory(
        [
            ("dev:fw1", {"Device"}, {}),
            ("rb:own", {"FwRulebase"}, {"kind": "access"}),
            ("rb:nat", {"FwRulebase"}, {"kind": "nat"}),
            ("rg:1", {"RedundancyGroup"}, {}),
            ("rb:cluster", {"FwRulebase"}, {}),
            ("if:1", {"Interface"}, {}),
            ("zone:dmz", {"Zone"}, {}),
            ("rb:zone", {"FwRulebase"}, {"kind": "access"}),
            ("rb:elsewhere", {"FwRulebase"}, {"kind": "access"}),
        ],
        [
            ("ENFORCES", "dev:fw1", "rb:own"),
            ("ENFORCES", "dev:fw1", "rb:nat"),
            ("MEMBER_OF", "dev:fw1", "rg:1"),
            ("ENFORCES", "rg:1", "rb:cluster"),
            ("ON", "if:1", "dev:fw1"),
            ("CONTAINS", "zone:dmz", "if:1"),
            ("FROM_ZONE", "rb:zone", "zone:dmz"),
        ],
    )

    assert flow_match.device_rulebases(graph, "dev:fw1") == ["rb:cluster", "rb:own", "rb:zone"]
    assert flow_match.match(graph, "test", "dev:none", None, {}, 4)["error"]["field"] == "device"
    refused = flow_match.match(graph, "test", "dev:fw1", "rb:elsewhere", {}, 4)["error"]
    assert refused["code"] == "not_found" and refused["field"] == "rulebase"
    assert [c["uid"] for c in refused["candidates"]] == ["rb:cluster", "rb:own", "rb:zone"]


def _backend():
    if not symbolic.backend_available():
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")


_ANY = {"enabled": True, "dst_any": True, "svc_any": True}


def _one_rulebase(rules):
    """dev:fw1 enforces rulebase rb with default deny; `rules` holds (uid,
    props, source object uids); net:a is 10.0.0.0/24."""
    nodes = [
        ("dev:fw1", {"Device"}, {}),
        ("rb", {"FwRulebase"}, {"default_action": "deny"}),
        ("net:a", {"NetObject"}, {"cidr": "10.0.0.0/24"}),
    ]
    relations = [("ENFORCES", "dev:fw1", "rb")]
    for uid, props, sources in rules:
        nodes.append((uid, {"FwRule"}, props))
        relations.append(("HAS_RULE", "rb", uid))
        relations.extend(("SRC", uid, source) for source in sources)
    return _inventory(nodes, relations)


def _flow(src):
    return {
        "sources": [[_ip(src), _ip(src)]],
        "destinations": [[_ip("192.0.2.1"), _ip("192.0.2.1")]],
        "protocols": [6],
        "destination_ports": [[443, 443]],
        "source_ports": None,
    }


def test_the_first_rule_that_takes_the_whole_flow_decides_it():
    _backend()
    graph = _one_rulebase(
        [
            ("r1", {"position": 1, "action": "accept", **_ANY}, ["net:a"]),
            ("r2", {"position": 2, "action": "accept", "src_any": True, **_ANY}, []),
        ]
    )

    document = flow_match.match(graph, "test", "dev:fw1", None, _flow("10.0.0.5"), 4)

    (rulebase,) = document["rulebases"]
    assert rulebase["decision"] == "permit"
    assert rulebase["deciding_rule"] == {"uid": "r1", "position": 1, "action": "permit", "rulebase": "rb"}
    assert [(r["uid"], r["match"], r["whole_flow"]) for r in rulebase["candidate_rules"]] == [
        ("r1", "definite", True)
    ]


def test_a_flow_no_rule_takes_is_denied_by_the_default_action():
    _backend()
    graph = _one_rulebase([("r1", {"position": 1, "action": "accept", **_ANY}, ["net:a"])])

    rulebase = flow_match.match(graph, "test", "dev:fw1", None, _flow("10.1.0.5"), 4)["rulebases"][0]

    assert rulebase["decision"] == "deny"
    assert rulebase["deciding_rule"] is None and rulebase["candidate_rules"] == []


def test_an_opaque_rule_leaves_the_flow_undecided_and_names_its_gap():
    _backend()
    graph = _one_rulebase(
        [("r1", {"position": 1, "action": "accept", "src_any": True, "vendor_qualifier": "x", **_ANY}, [])]
    )

    rulebase = flow_match.match(graph, "test", "dev:fw1", None, _flow("10.1.0.5"), 4)["rulebases"][0]

    assert rulebase["decision"] == "indeterminate"
    assert "GRAPH_RULE_UNSUPPORTED_FIELD" in {gap["code"] for gap in rulebase["gaps"]}
    assert [(r["uid"], r["match"]) for r in rulebase["candidate_rules"]] == [("r1", "possible")]


# --- policy_lookup_nat -----------------------------------------------------------------------


def _nat_row(uid="nat:rb/1", **overrides):
    row = {
        "rulebase": "nat:rb",
        "rulebase_name": "edge-nat",
        "rulebase_approximate": False,
        "enforced_by": ["dev:fw1"],
        "uid": uid,
        "name": None,
        "position": 1,
        "kind": "dnat",
        "method": None,
        "auto_generated": None,
        "static_flag": False,
        "direction": None,
        "orig_src_raw": None,
        "orig_dst_raw": "203.0.113.10",
        "translation": "10.1.0.10",
        "orig_port": None,
        "orig_dst_port": "443",
        "xlate_port": None,
        "translation_port": None,
        "protocol": "tcp",
        "exclude": False,
        "rule_approximate": False,
        "targets": [],
    }
    row.update(overrides)
    return row


def _nat(monkeypatch, rows):
    return install(monkeypatch, FakeGraph([("(n:NatRule)", rows), _DEVICE]))


def test_a_rule_whose_objects_resolve_is_a_proven_match(monkeypatch):
    _nat(monkeypatch, [_nat_row()])

    failed, envelope = call("policy_lookup_nat", {"address": "203.0.113.10"})

    assert not failed, envelope
    (item,) = envelope["result"]["items"]
    assert item["rule_uid"] == "nat:rb/1" and item["kind"] == "dnat"
    assert (item["orig_dst"], item["xlate_dst"], item["xlate_src"]) == ("203.0.113.10", "10.1.0.10", None)
    assert item["matched_on"] == "original" and item["matched_columns"] == ["orig_dst"]
    assert item["device"] == "dev:fw1"
    assert item["evidence"]["result"]["statement"] == "nat-rule-matches"
    assert item["evidence"]["result"]["word"] == "matches"
    assert item["evidence"]["result"]["answer"] == "true"
    assert item["evidence"]["basis"] == "configured"
    assert envelope["evidence"]["result"]["word"] == "matches"


def test_a_translated_address_matches_on_the_translated_side(monkeypatch):
    _nat(monkeypatch, [_nat_row()])

    failed, translated = call("policy_lookup_nat", {"address": "10.1.0.10", "side": "translated"})
    failed_original, original = call("policy_lookup_nat", {"address": "10.1.0.10", "side": "original"})

    assert not failed and not failed_original
    assert translated["result"]["items"][0]["matched_on"] == "translated"
    assert original["result"]["items"] == []
    assert original["evidence"]["result"]["word"] == "no record matches in the snapshot"
    assert original["evidence"]["absence"] == "not_recorded"


def test_a_rule_with_an_unresolved_object_is_possible_with_a_gap(monkeypatch):
    opaque = {
        "column": "ORIG_DST",
        "uid": "obj:dyn",
        "name": "dynamic-servers",
        "net_object": True,
        "address": None,
        "ranges": None,
        "opaque": True,
        "opaque_reason": "a dynamic object has no recorded members",
        "resolved": [],
        "unresolvable": 0,
    }
    resolved = {
        **opaque,
        "uid": "obj:web",
        "name": "web",
        "opaque": False,
        "opaque_reason": None,
        "resolved": ["203.0.113.0/28"],
    }
    rows = [
        _nat_row(orig_dst_raw=None, targets=[opaque]),
        _nat_row("nat:rb/2", position=2, orig_dst_raw=None, targets=[resolved, opaque]),
    ]
    _nat(monkeypatch, rows)

    failed, envelope = call("policy_lookup_nat", {"address": "203.0.113.10", "side": "original"})

    assert not failed, envelope
    only_opaque, mixed = envelope["result"]["items"]
    for item in (only_opaque, mixed):
        # a match that depends on an opaque object is open on that object
        assert item["evidence"]["result"]["answer"] == "open"
        assert item["evidence"]["result"]["word"] == "not decided"
        assert item["evidence"]["result"]["missing"][0]["subject"] == "obj:dyn"
        assert [m["code"] for m in item["evidence"]["result"]["missing"]] == ["NAT_OBJECT_OPAQUE"]
        assert item["unresolved"][0]["uid"] == "obj:dyn"
    assert mixed["orig_dst"] == "203.0.113.0/28, dynamic-servers"
    assert envelope["evidence"]["result"]["answer"] == "open"
    gap = envelope["evidence"]["gaps"][0]
    assert (gap["code"], gap["kind"], gap["subject"]) == ("NAT_OBJECT_OPAQUE", "not-modeled", "obj:dyn")


def test_an_approximate_rulebase_makes_a_match_possible(monkeypatch):
    _nat(monkeypatch, [_nat_row(rulebase_approximate=True)])

    failed, envelope = call("policy_lookup_nat", {"address": "203.0.113.10"})

    assert not failed
    assert [m["code"] for m in envelope["result"]["items"][0]["evidence"]["result"]["missing"]] == [
        "NAT_RULEBASE_APPROXIMATE"
    ]
    assert envelope["result"]["items"][0]["evidence"]["result"]["word"] == "not decided"
    assert envelope["evidence"]["result"]["answer"] == "open"


def test_a_masquerade_translation_names_no_address(monkeypatch):
    _nat(
        monkeypatch,
        [_nat_row(kind="snat", orig_dst_raw=None, orig_src_raw="10.0.0.0/8", translation="masquerade")],
    )

    failed, envelope = call("policy_lookup_nat", {"address": "198.51.100.1", "side": "translated"})

    assert not failed
    assert envelope["result"]["items"] == []


def test_port_and_device_narrow_the_rules(monkeypatch):
    graph = _nat(monkeypatch, [_nat_row()])

    failed, other_port = call(
        "policy_lookup_nat", {"address": "203.0.113.10", "port": 80, "device": "dev:fw1"}
    )
    failed_same, same_port = call("policy_lookup_nat", {"address": "203.0.113.10", "port": 443})

    assert not failed and not failed_same
    assert other_port["result"]["items"] == [] and other_port["result"]["device"] == "dev:fw1"
    assert len(same_port["result"]["items"]) == 1
    assert [params["device"] for params in graph.reads("(n:NatRule)")] == ["dev:fw1", None]


def test_the_rules_page_with_the_cursor_to_the_last(monkeypatch):
    _nat(monkeypatch, [_nat_row(f"nat:rb/{n}", position=n) for n in (1, 2, 3)])

    pages = _pages("policy_lookup_nat", {"address": "203.0.113.10", "limit": 1}, context())

    assert [[item["rule_uid"] for item in page["result"]["items"]] for page in pages] == [
        ["nat:rb/1"],
        ["nat:rb/2"],
        ["nat:rb/3"],
    ]
    assert [page["page"]["next_cursor"] is None for page in pages] == [False, False, True]
    assert [page["page"]["total"] for page in pages] == [3, 3, 3]


def _address_target(column, address):
    return {
        "column": column,
        "uid": f"ip:{address}",
        "name": None,
        "net_object": False,
        "address": address,
        "ranges": None,
        "opaque": False,
        "opaque_reason": None,
        "resolved": [],
        "unresolvable": 0,
    }


# A VyOS static rule matches the public address on the destination and
# translates it to the real one on an XLATE_DST edge. A Cisco inside-source
# static rule matches the real source and translates it on an XLATE_SRC edge.
_VYOS_STATIC = _nat_row(
    kind="static",
    orig_dst_port=None,
    targets=[_address_target("ORIG_DST", "203.0.113.10"), _address_target("XLATE_DST", "10.1.0.10")],
)
_CISCO_STATIC = _nat_row(
    kind="snat",
    static_flag=True,
    direction="inside-source",
    orig_dst_raw=None,
    orig_dst_port=None,
    translation="203.0.113.10",
    targets=[_address_target("ORIG_SRC", "10.1.0.10"), _address_target("XLATE_SRC", "203.0.113.10")],
)


@pytest.mark.parametrize(
    ("row", "address", "column", "other"),
    [
        (_VYOS_STATIC, "10.1.0.10", "xlate_dst", "xlate_src"),
        (_CISCO_STATIC, "203.0.113.10", "xlate_src", "xlate_dst"),
    ],
    ids=["vyos", "cisco"],
)
def test_a_static_translation_is_read_in_the_column_the_gate_reads(monkeypatch, row, address, column, other):
    _nat(monkeypatch, [row])

    failed, envelope = call("policy_lookup_nat", {"address": address, "side": "translated"})

    assert not failed, envelope
    (item,) = envelope["result"]["items"]
    assert item["kind"] == "static"
    assert (item[column], item[other]) == (address, None)
    assert item["matched_columns"] == [column]


def test_an_address_that_is_not_one_is_invalid_argument_before_any_read(monkeypatch):
    graph = _nat(monkeypatch, [])

    failed, error = call("policy_lookup_nat", {"address": "web01"})

    assert failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "address"
    assert graph.session_kwargs == []


# --- lb_lookup_vip ---------------------------------------------------------------------------


def _vs(uid, kind="lb", **extra):
    row = {
        "uid": uid,
        "name": uid.split(":")[-1],
        "kind": kind,
        "proto": "tcp",
        "port": 443,
        "state": "up",
        "snat_mode": "automap",
        "carried": False,
        "vips": ["198.51.100.10"],
        "on_targets": ["dev:adc1"],
        "snat_from": [],
        "dispatches": [],
        "matched_members": [],
    }
    row.update(extra)
    return row


_MEMBERS = {
    "vs:web": [
        {
            "uid": "pm:1",
            "name": "web1",
            "port": 8443,
            "state": "up",
            "pool_uid": "pool:web",
            "pool_name": "web",
            "ip": "10.1.0.10",
        },
        {
            "uid": "pm:2",
            "name": "web2",
            "port": 8443,
            "state": "down",
            "pool_uid": "pool:web",
            "pool_name": "web",
            "ip": "10.1.0.11",
        },
    ]
}


def _lb(monkeypatch, services):
    return install(
        monkeypatch,
        FakeGraph(
            [
                ("RETURN vs.uid AS uid", services),
                ("RETURN pm.uid AS uid", lambda params: _MEMBERS.get(params["vs"], [])),
            ]
        ),
    )


def test_vip_to_members_lists_each_virtual_service_with_its_pool_members(monkeypatch):
    graph = _lb(monkeypatch, [_vs("vs:web")])

    failed, envelope = call("lb_lookup_vip", {"address": "198.51.100.10", "direction": "vip_to_members"})

    assert not failed, envelope
    (item,) = envelope["result"]["items"]
    assert item["virtual_service"] == "vs:web" and item["vip"] == "198.51.100.10"
    assert item["on_device"] == "dev:adc1" and item["pool"] == "pool:web"
    assert [(m["ip"], m["port"], m["state"]) for m in item["members"]] == [
        ("10.1.0.10", 8443, "up"),
        ("10.1.0.11", 8443, "down"),
    ]
    assert item["evidence"]["result"]["word"] == "recorded in this run"
    assert (item["evidence"]["result"]["kind"], item["evidence"]["basis"]) == ("record", "observed")
    assert envelope["evidence"]["result"]["word"] == "recorded in this run"
    (query_params,) = graph.reads("RETURN vs.uid AS uid")
    assert query_params["ip"] == "198.51.100.10"
    assert "(vs:VirtualService:Obj)-[ev:VIP]->(vip:IpAddress {ip: $ip})" in graph.calls[0][0]


@pytest.mark.parametrize("kind", ["cs", "gslb"])
def test_content_switching_and_gslb_kinds_are_not_established(monkeypatch, kind):
    _lb(monkeypatch, [_vs("vs:front", kind=kind, dispatches=["vs:web"])])

    failed, envelope = call("lb_lookup_vip", {"address": "198.51.100.10", "direction": "vip_to_members"})

    assert not failed, envelope
    (item,) = envelope["result"]["items"]
    assert item["evidence"]["result"]["word"] == "recorded; of a kind the engine does not evaluate"
    assert [m["code"] for m in item["evidence"]["result"]["missing"]] == ["LB_KIND_NOT_EVALUATED"]
    assert item["dispatches"] == ["vs:web"]
    assert envelope["evidence"]["result"]["word"] == "recorded; of a kind the engine does not evaluate"
    assert envelope["evidence"]["gaps"][0]["subject"] == "vs:front"
    assert any(f"kind {kind}" in unknown for unknown in envelope["evidence"]["unknowns"])


def test_an_evaluated_and_a_content_switching_service_are_mixed(monkeypatch):
    _lb(monkeypatch, [_vs("vs:front", kind="cs"), _vs("vs:web")])

    failed, envelope = call("lb_lookup_vip", {"address": "198.51.100.10", "direction": "vip_to_members"})

    assert not failed
    assert envelope["evidence"]["result"]["word"] == "each item states its own result"


def test_member_to_vips_reads_the_reverse_path(monkeypatch):
    graph = _lb(monkeypatch, [_vs("vs:web", matched_members=[{"uid": "pm:1", "port": 8443, "state": "up"}])])

    failed, envelope = call("lb_lookup_vip", {"address": "10.1.0.10", "direction": "member_to_vips"})
    failed_port, other_port = call(
        "lb_lookup_vip", {"address": "10.1.0.10", "direction": "member_to_vips", "port": 80}
    )

    assert not failed and not failed_port
    (item,) = envelope["result"]["items"]
    assert [(m["uid"], m["matched"]) for m in item["members"]] == [("pm:1", True), ("pm:2", False)]
    assert other_port["result"]["items"] == []
    assert "(pm:PoolMember:Obj)-[et:TARGETS]->(ip:IpAddress {ip: $ip})" in graph.calls[0][0]


def test_a_port_the_virtual_service_does_not_serve_leaves_it_out(monkeypatch):
    _lb(monkeypatch, [_vs("vs:web")])

    failed, envelope = call(
        "lb_lookup_vip", {"address": "198.51.100.10", "direction": "vip_to_members", "port": 80}
    )

    assert not failed
    assert envelope["result"]["items"] == []
    assert envelope["evidence"]["result"]["word"] == "no record matches in the snapshot"


# --- reach_trace groups ----------------------------------------------------------------------


def test_an_ambiguous_selector_returns_candidates(monkeypatch, tmp_path):
    zones = [
        {"uid": "zone:fw1:dmz", "name": "DMZ", "devices": ["dev:fw1"]},
        {"uid": "zone:fw2:dmz", "name": "DMZ", "devices": ["dev:fw2"]},
    ]
    install(
        monkeypatch,
        FakeGraph(
            [
                ("MATCH (z:Zone:Obj)", zones),
                (
                    "MATCH (:Zone:Obj {uid: $uid, collection_ts: $snap})",
                    lambda p: [{"cidr": "192.0.2.0/25", "context": "vrf:" + p["uid"]}],
                ),
            ]
        ),
    )

    failed, envelope = call(
        "reach_trace",
        {"mode": "groups", "source": {"kind": "zone", "value": "DMZ"}, "destination": {"kind": "rfc1918"}},
        context(sidestore_dir=tmp_path),
    )

    assert not failed, envelope
    result = envelope["result"]
    assert result["status"] == "needs_clarification"
    assert [(c["side"], c["uid"], c["context"]) for c in result["candidates"]] == [
        ("source", "zone:fw1:dmz", "vrf:zone:fw1:dmz"),
        ("source", "zone:fw2:dmz", "vrf:zone:fw2:dmz"),
    ]
    assert envelope["evidence"]["result"]["answer"] == "open"
    assert envelope["page"]["truncated"] is False


def test_an_application_group_selector_reads_the_catalog_of_the_tool_context(monkeypatch, tmp_path):
    from hst.applications.models import BusinessApplicationDefinition
    from hst.applications.service import save_definition
    from hst.assessment.store import MemoryAssessmentStore

    install(monkeypatch, FakeGraph())
    store = MemoryAssessmentStore()
    definition = BusinessApplicationDefinition.model_validate(
        {
            "id": "shop",
            "name": "Shop",
            "groups": [
                {"id": "web", "name": "Web", "members": [{"id": "w1", "address": "10.1.0.10"}]},
                {"id": "db", "name": "Database", "members": [{"id": "d1", "address": "10.2.0.5"}]},
            ],
        }
    )
    asyncio.run(save_definition(store, definition, expected_revision=0, actor=1))
    ctx = context(sidestore_dir=tmp_path)
    ctx.store = store

    failed, envelope = call(
        "reach_trace",
        {
            "mode": "groups",
            "source": {"kind": "app_group", "value": "shop"},
            "destination": {"kind": "rfc1918"},
        },
        ctx,
    )

    assert not failed, envelope
    assert envelope["result"]["status"] == "needs_clarification"
    assert [c["value"] for c in envelope["result"]["candidates"]] == ["shop/web", "shop/db"]


def _rect(n):
    return {
        "sources": [f"10.0.{n}.0/24"],
        "destinations": ["192.0.2.0/24"],
        "protocols": [6],
        "destination_ports": "443",
        "source_ports": "any",
    }


def _paged_query(monkeypatch, *, allowed=5, denied=2, unknown=0, cap=2):
    """traffic.query answering buckets of the given sizes, `cap` items from `offset` on."""
    calls = []
    full = {
        "allowed": [_rect(i) for i in range(allowed)],
        "denied": [_rect(100 + i) for i in range(denied)],
        "not_established": [_rect(200 + i) for i in range(unknown)],
        "evidence": [{"outcome": "allowed", "steps": []}],
    }

    def query(session, *, offset=0, **kwargs):
        calls.append({"offset": offset, **kwargs})
        body = {
            "status": "partial" if unknown else "complete",
            "plan": {"source": {}, "destination": {}},
            "coverage": {"entire_request_evaluated": True, "entire_request_decided": not unknown},
            "missing_evidence": [],
            "assumptions": [],
            "gaps": [],
            "model_errors": [],
        }
        for name, items in full.items():
            body[name] = {
                "count": len(items),
                "items": items[offset : offset + cap],
                "truncated": len(items) > offset + cap,
            }
        return body

    monkeypatch.setattr(traffic, "query", query)
    return calls, full


_GROUPS = {
    "mode": "groups",
    "source": {"kind": "rfc1918"},
    "destination": {"kind": "addresses", "addresses": ["192.0.2.0/24"]},
}


def test_the_buckets_page_past_the_result_cap_with_one_cursor(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    calls, full = _paged_query(monkeypatch)
    ctx = context(sidestore_dir=tmp_path)

    pages, cursor = [], None
    while True:
        failed, envelope = call("reach_trace", {**_GROUPS, **({"cursor": cursor} if cursor else {})}, ctx)
        assert not failed, envelope
        pages.append(envelope)
        cursor = envelope["page"]["next_cursor"]
        if cursor is None:
            break

    assert [c["offset"] for c in calls] == [0, 2, 4]
    assert [item for page in pages for item in page["result"]["passes"]["items"]] == full["allowed"]
    assert [item for page in pages for item in page["result"]["fails"]["items"]] == full["denied"]
    assert [page["result"]["passes"]["truncated"] for page in pages] == [True, True, False]
    assert pages[0]["result"]["explanations"]["items"] == [
        {**{k: v for k, v in e.items() if k != "outcome"}, "result": None} for e in full["evidence"]
    ]
    assert pages[0]["page"]["total"] == 5
    first = pages[0]
    assert first["result"]["passes"]["evidence"]["result"]["answer"] == "true"
    assert first["result"]["fails"]["evidence"]["result"]["answer"] == "false"
    assert first["evidence"]["result"]["answer"] == "false"
    assert first["evidence"]["bounds"]["lower_count"] == 5 and first["evidence"]["bounds"]["upper_count"] == 5
    assert callable(calls[0]["applications"]) and callable(calls[0]["checkpoint"])


def test_one_bucket_pages_alone(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    _paged_query(monkeypatch, unknown=3)

    failed, envelope = call(
        "reach_trace", {**_GROUPS, "bucket": "open", "limit": 2}, context(sidestore_dir=tmp_path)
    )

    assert not failed, envelope
    result = envelope["result"]
    assert len(result["open"]["items"]) == 2 and result["open"]["truncated"] is True
    assert result["passes"] == {"count": 5, "truncated": True, "evidence": result["passes"]["evidence"]}
    assert "items" not in result["explanations"]
    assert envelope["evidence"]["result"]["answer"] == "false"
    assert envelope["evidence"]["bounds"]["open_count"] == 3


def test_an_empty_request_is_not_applicable(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    monkeypatch.setattr(
        traffic,
        "query",
        lambda session, **kwargs: {
            "status": "empty",
            "reason": "the requested set is empty after exclusions",
            "plan": {},
            "coverage": {},
        },
    )

    failed, envelope = call("reach_trace", _GROUPS, context(sidestore_dir=tmp_path))

    assert not failed
    assert envelope["result"]["status"] == "empty"
    assert envelope["evidence"]["result"]["word"] == "no record matches in the snapshot"


def test_a_selector_the_resolver_refuses_is_invalid_argument(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())

    failed, error = call(
        "reach_trace",
        {**_GROUPS, "source": {"kind": "addresses", "addresses": ["not-an-address"]}},
        context(sidestore_dir=tmp_path),
    )

    assert failed and error["error"]["code"] == "invalid_argument"


def _mode_required(schema: dict, discriminator: str) -> dict[str, list[str]]:
    out = {}
    for branch in schema["oneOf"]:
        variant = schema["$defs"][branch["$ref"].rsplit("/", 1)[-1]]
        out[variant["properties"][discriminator]["const"]] = sorted(variant["required"])
    return out


async def test_each_mode_publishes_its_own_required_fields(monkeypatch):
    pytest.importorskip("mcp")
    from hst.mcp_server import build_server

    tools = {t.name: t.input_schema for t in await build_server().list_tools()}

    assert _mode_required(tools["reach_trace"], "mode") == {
        "path": ["flow", "mode"],
        "groups": ["destination", "mode", "source"],
    }
    assert _mode_required(tools["policy_evaluate"], "mode") == {
        "explain_rule": ["mode", "rule", "rulebase"],
        "match_flow": ["device", "flow", "mode"],
    }
    assert sorted(tools["policy_lookup_nat"]["required"]) == ["address"]
    assert sorted(tools["lb_lookup_vip"]["required"]) == ["address", "direction"]


async def test_mcp_refuses_a_path_call_without_a_flow_before_any_read(monkeypatch):
    pytest.importorskip("mcp")
    from hst.app.ai import mcp as ai_mcp
    from hst.mcp_server import build_server

    monkeypatch.setattr(ai_mcp, "Settings", lambda: settings())
    graph = install(monkeypatch, FakeGraph())

    res = await build_server().call_tool("reach_trace", {"mode": "path"})

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "invalid_argument"
    assert res.structured_content["error"]["field"] == "flow"
    assert graph.session_kwargs == []
