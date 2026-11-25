import pytest
from tests.test_checkpoint import _norm_cp
from tests.test_cisco_common import _PERMIT_ANY_ACE, INTER, L3DOM, SCOPE, SOURCE
from tests.test_unifi import CLASSIC_RULES, GROUPS, POLICIES, ZONES, _gw_batch
from tests.test_vyos import _batch, _fw_batch, _v6_batch

from hst import path
from hst.collectors.cisco_common import normalize_cisco
from hst.collectors.nxos import _ensure_vrf
from hst.collectors.util import GraphBuilder
from hst.path.gates.coverage import strict_gate_coverage


def _cisco_acl():
    return normalize_cisco(
        {
            **INTER,
            "acl": {
                "lists": {"EDGE-IN": [_PERMIT_ANY_ACE]},
                "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE-IN"}],
            },
        },
        source=SOURCE,
        scope=SCOPE,
        l3dom=L3DOM,
    )


@pytest.mark.parametrize(
    "batch,expected",
    [
        (_batch(), "zone-pair"),
        (_v6_batch(), "zone-pair"),
        (_fw_batch({"ipv4": {"forward": {"filter": {"default-action": "drop"}}}}), "device"),
        (_norm_cp(), "device"),
        (_gw_batch(firewall_zones=ZONES, firewall_policies=POLICIES), "zone-pair"),
        (_gw_batch(firewall_rules=CLASSIC_RULES, firewall_groups=GROUPS), "interface-acl"),
        (_cisco_acl(), "interface-acl"),
    ],
    ids=[
        "vyos-zones",
        "vyos-ipv6-zones",
        "vyos-chain",
        "checkpoint",
        "unifi-zones",
        "unifi-classic",
        "cisco-acl",
    ],
)
def test_normalized_policies_reach_their_evaluator_without_preflight_rejection(monkeypatch, batch, expected):
    policies = [n for n in batch.nodes if n.label == "FwRulebase" and n.props.get("kind") != "nat"]
    assert policies
    # An unused named ruleset is not device-wide.
    policies = [
        n
        for n in policies
        if any(
            (r.start_uid == n.uid and r.rel_type == "FROM_ZONE")
            or (r.end_uid == n.uid and r.rel_type == "ENFORCES")
            for r in batch.rels
        )
    ]
    assert policies
    details = []
    for node in policies:
        chain = node.props.get("chain")
        # a chain makes a rulebase device-wide, except an interface ACL that
        # records the forward chain (a UniFi classic LAN_IN)
        acl_chain = expected == "interface-acl" and chain == "forward"
        assert node.props.get("match_context") == ("device" if chain and not acl_chain else expected)
        details.append(
            {
                "uid": node.uid,
                "labels": ["Gate", "FwRulebase"],
                "model_kind": node.props["kind"],
                "chain": node.props.get("chain"),
                "match_context": node.props.get("match_context"),
            }
        )
    monkeypatch.setattr("hst.path.gates.coverage.unevaluated_gates", lambda *_args: details)
    monkeypatch.setattr(path, "_read", lambda *_args, **_kwargs: details)
    options = {
        "stage": "forward",
        "in_interface_uid": "ingress",
        "out_interface_uid": "egress",
        "evaluated_ids": (),
        "composed_kinds": {"FwRulebase"},
    }
    assert not strict_gate_coverage(object(), "device", **options, preflight=True).unknowns
    # Metadata only permits evaluation; it must not claim the policy was evaluated.
    assert {g.uid for g in strict_gate_coverage(object(), "device", **options).unknowns} == {
        n.uid for n in policies if n.props.get("chain") not in {"input", "output"}
    }


@pytest.mark.parametrize(
    "batch", [_batch(), _v6_batch(), _gw_batch(), _cisco_acl()], ids=["vyos", "vyos-ipv6", "unifi", "cisco"]
)
def test_device_local_contexts_have_explicit_real_device_owners(batch):
    devices = {n.uid for n in batch.nodes if n.label == "Device"}
    contexts = {n.uid for n in batch.nodes if n.label == "VrfInstance"}
    owners = [r for r in batch.rels if r.start_label == "VrfInstance" and r.rel_type == "OWNED_BY"]
    assert contexts
    assert {r.start_uid for r in owners} == contexts
    assert all(r.end_label == "Device" and r.end_uid in devices for r in owners)
    for context in contexts:
        assert len([r for r in owners if r.start_uid == context]) == 1


def test_policy_table_ownership_does_not_invent_interface_membership():
    batch = _batch()
    table = next(n.uid for n in batch.nodes if n.props.get("kind") == "policy-table")
    assert any(r.start_uid == table and r.rel_type == "OWNED_BY" for r in batch.rels)
    assert not any(
        r.end_uid == table and r.rel_type == "IN_VRF" and r.start_label == "Interface" for r in batch.rels
    )


def test_bgp_only_nxos_context_records_the_device_that_supplied_it():
    builder = GraphBuilder()
    vrf = _ensure_vrf(builder, "dev:leaf", "BGP-ONLY", set())
    assert any(
        r.start_uid == vrf and r.end_uid == "dev:leaf" and r.rel_type == "OWNED_BY"
        for r in builder.batch("nxos", "context-contract").rels
    )
