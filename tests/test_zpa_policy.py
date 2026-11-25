"""The shared ZPA first-match reader in hst.core.zpa_policy."""

import json

import pytest

from hst.core import zpa_policy

IDENTITY = "idg:scim:sales"
SEGMENT = "zpa:acme:seg:2001"


def _rule(**kw):
    base = {
        "uid": "zpa:acme:rule:100",
        "name": "sales-to-webshop",
        "position": 1,
        "action": "allow",
        "applies_to_all_identities": None,
        "conditions": None,
        "identity_named": True,
    }
    base.update(kw)
    return base


def test_rule_position_reads_integers_only():
    for value in (True, None, "high"):
        assert zpa_policy.rule_position({"position": value}) is None
    assert zpa_policy.rule_position({"position": 3}) == 3
    assert zpa_policy.rule_position({"position": " 10 "}) == 10


def test_access_decision_reports_one_gap_code_per_undecided_case():
    def gap(rows):
        return zpa_policy.access_decision(rows, IDENTITY, SEGMENT).gap

    assert gap([]) == "ZPA_NO_RULE_MATCHES_IDENTITY"
    assert gap([_rule(identity_named=False)]) == "ZPA_NO_RULE_MATCHES_IDENTITY"
    assert gap([_rule(uid="r:1", position=1), _rule(uid="r:2", name="other", position=1)]) == (
        "ZPA_RULE_ORDER_UNKNOWN"
    )
    assert gap([_rule(position="first")]) == "ZPA_RULE_ORDER_UNKNOWN"
    posture = json.dumps([{"operator": "OR", "operands": [{"type": "POSTURE", "rhs": "true"}]}])
    assert gap([_rule(conditions=posture)]) == "ZPA_RULE_CONDITIONS_UNSUPPORTED"
    assert gap([_rule(action="bypass")]) == "ZPA_RULE_ACTION_UNKNOWN"

    decided = zpa_policy.access_decision([_rule()], IDENTITY, SEGMENT)
    assert decided.action == "allow"
    assert decided.indeterminate is False
    assert decided.gap is None


def test_condition_blocks_keep_negation_and_lhs_only_when_sent():
    from hst.core.zpa_policy import condition_blocks

    blocks = condition_blocks(
        [
            {
                "operator": "OR",
                "negated": True,
                "operands": [{"objectType": "SCIM_GROUP", "lhs": "idp-1", "rhs": "77"}],
            },
            {"operator": "OR", "negated": False, "operands": [{"objectType": "APP", "name": "crm"}]},
        ]
    )
    assert blocks == [
        {
            "operator": "OR",
            "negated": True,
            "operands": [{"type": "SCIM_GROUP", "rhs": "77", "lhs": "idp-1"}],
        },
        {"operator": "OR", "operands": [{"type": "APP", "rhs": "crm"}]},
    ]


def test_conditions_summary_names_the_attribute_the_negation_and_a_rule_level_or():
    from hst.core.zpa_policy import conditions_summary

    def block(kind, rhs, lhs=None, negated=False):
        op = {"type": kind, "rhs": rhs, **({"lhs": lhs} if lhs else {})}
        return {"operator": "OR", "operands": [op], **({"negated": True} if negated else {})}

    assert conditions_summary([block("SAML", "admins", "attr-77")], None) == "SAML[attr-77]=admins"
    assert conditions_summary([block("POSTURE", "true", "udid-1")], None) == "POSTURE[udid-1]=true"
    assert conditions_summary([block("SCIM_GROUP", "77", "idp-1", negated=True)], None) == "NOT SCIM_GROUP=77"
    assert conditions_summary([block("APP", "2001", "id"), block("SCIM_GROUP", "77", "idp-1")], "OR") == (
        "APP=2001 OR SCIM_GROUP=77"
    )
    two = {
        "operator": "OR",
        "negated": True,
        "operands": [{"type": "APP", "rhs": "1"}, {"type": "APP", "rhs": "2"}],
    }
    assert conditions_summary([two], "AND") == "NOT (APP=1; APP=2)"


def _b(*types, negated=False):
    return {
        "operator": "OR",
        "operands": [{"type": t, "rhs": "x"} for t in types],
        **({"negated": True} if negated else {}),
    }


@pytest.mark.parametrize(
    ("blocks", "operator", "expected"),
    [
        ([], None, ("any", "any")),
        ([_b("SCIM_GROUP")], None, ("listed", "any")),
        ([_b("APP_GROUP")], None, ("any", "listed")),
        ([_b("APP"), _b("SCIM_GROUP")], "AND", ("listed", "listed")),
        ([_b("APP"), _b("SAML")], "AND", ("other", "listed")),
        ([_b("APP"), _b("IDP")], "AND", ("other", "listed")),
        ([_b("APP"), _b("POSTURE")], "AND", ("any", "listed")),
        ([_b("APP"), _b("NEW_TYPE")], "AND", ("other", "listed")),
        ([_b("SCIM_GROUP"), _b("NEW_TYPE"), _b("APP")], "AND", ("listed", "listed")),
        ([_b("APP"), _b("SCIM_GROUP")], "OR", ("other", "other")),
        ([_b("APP"), _b("SCIM_GROUP", negated=True)], "AND", ("other", "listed")),
        ([_b("APP", negated=True)], None, ("any", "other")),
        ([_b("SCIM_GROUP", "APP")], None, ("other", "other")),
    ],
)
def test_rule_scope_follows_the_condition_blocks(blocks, operator, expected):
    from hst.core.zpa_policy import rule_scope

    assert rule_scope(blocks, operator) == expected


def test_disabled_values_map_to_enabled_or_disabled_raw():
    from hst.core.zpa_policy import parse_disabled

    for value in ("0", 0, False):
        assert parse_disabled(value) == (True, None)
    for value in ("1", 1, True):
        assert parse_disabled(value) == (False, None)
    assert parse_disabled("7") == (None, "7")
    assert parse_disabled(None) == (None, None)


@pytest.mark.parametrize(
    ("blocks", "operator"),
    [
        ([_b("APP"), _b("SAML")], "AND"),
        ([_b("APP"), _b("IDP")], "AND"),
        ([_b("APP"), _b("NEW_TYPE")], "AND"),
        ([_b("APP"), _b("SCIM_GROUP")], "OR"),
        ([_b("APP"), _b("SCIM_GROUP", negated=True)], "AND"),
        ([_b("APP", negated=True)], None),
        ([_b("SCIM_GROUP", "APP")], None),
    ],
)
def test_every_other_scope_fails_the_shape_check(blocks, operator):
    from hst.core.zpa_policy import rule_scope, unsupported_condition_shape

    assert "other" in rule_scope(blocks, operator)
    assert unsupported_condition_shape(json.dumps(blocks), operator)


# --- the analysis model reads ZPA rules through the shared reader -------------------------


def _inventory(*batches):
    from hst.analysis_model.graph import GraphInventory
    from hst.analysis_model.read import MaterializedTable

    nodes = {
        n.uid: {"id": n.uid, "labels": [n.label], "props": {**n.props, "_scope": b.scope}}
        for b in batches
        for n in b.nodes
    }
    rels = [
        {
            "id": f"rel:{i}",
            "kind": r.rel_type,
            "start": r.start_uid,
            "end": r.end_uid,
            "props": {**r.key, **r.props},
        }
        for i, r in enumerate([r for b in batches for r in b.rels])
    ]
    return GraphInventory.from_tables(
        MaterializedTable("a" * 64, "nodes", tuple(nodes.values()), len(nodes), True, "b" * 64),
        MaterializedTable("a" * 64, "relationships", tuple(rels), len(rels), True, "c" * 64),
    )


def _ctx():
    from hst.policy.ir import ExecutionContext

    return ExecutionContext("estate", "authority", "domain", "fw", "vrf", 4)


def _uid(kind, ref, tenant="acme"):
    from hst.core import uid

    return uid.zpa(tenant, kind, ref)


def _scim_rule(rule_id, order, action, group, *apps):
    conditions = [
        {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": group, "idpId": "idp-1"}]}
    ]
    if apps:
        conditions.insert(0, {"operator": "OR", "operands": [{"objectType": "APP", "rhs": a} for a in apps]})
    return {
        "id": rule_id,
        "name": f"r{rule_id}",
        "action": action,
        "ruleOrder": order,
        "conditions": conditions,
    }


def test_the_analysis_model_decides_a_collected_rule_with_a_supported_shape():
    from tests.test_zpa import RAW

    from hst.analysis_model.gates import expand_zpa_broker, zpa_rule_decision
    from hst.analysis_model.model import StateKey
    from hst.collectors.zpa import normalize_zpa

    graph = _inventory(normalize_zpa(RAW, tenant="acme"))
    eng, contractors, seg = (
        _uid("idp", "idp-1-engineering"),
        _uid("idp", "idp-1-contractors"),
        _uid("seg", "2001"),
    )
    allow = zpa_rule_decision(graph, eng, seg)
    assert (allow.rule["uid"], allow.action) == (_uid("rule", "9001"), "allow")
    deny = zpa_rule_decision(graph, contractors, seg)
    assert (deny.rule["uid"], deny.action) == (_uid("rule", "9002"), "deny")
    expansion = expand_zpa_broker(graph, _ctx(), contractors, seg, StateKey("down", _ctx(), "proxy"))
    assert expansion.complete is True
    assert not expansion.gaps
    assert any(spec.terminal == "deny" for spec in expansion.nodes)


def test_the_analysis_model_answers_unknown_when_no_rule_matches():
    from tests.test_zpa import RAW

    from hst.analysis_model.gates import expand_zpa_broker
    from hst.analysis_model.model import StateKey
    from hst.collectors.zpa import normalize_zpa

    erp = RAW["app_segments"][1]["id"]
    rules = [_scim_rule("1", "1", "ALLOW", "sales", "2001"), _scim_rule("2", "2", "ALLOW", "it", erp)]
    graph = _inventory(normalize_zpa({**RAW, "access_rules": rules}, tenant="acme"))
    expansion = expand_zpa_broker(
        graph, _ctx(), _uid("idp", "idp-1-it"), _uid("seg", "2001"), StateKey("down", _ctx(), "proxy")
    )
    assert expansion.complete is False
    assert expansion.gaps == ("ZPA_NO_RULE_MATCHES_IDENTITY",)
    assert not any(spec.terminal == "deny" for spec in expansion.nodes)


def test_the_analysis_model_reads_a_rule_with_no_application_condition():
    from tests.test_zpa import RAW

    from hst.analysis_model.gates import zpa_rule_decision
    from hst.collectors.zpa import normalize_zpa

    raw = {
        **RAW,
        "access_rules": [_scim_rule("1", "1", "ALLOW", "it"), _scim_rule("2", "2", "ALLOW", "sales", "2001")],
    }
    graph = _inventory(normalize_zpa(raw, tenant="acme"))
    it = _uid("idp", "idp-1-it")
    for seg in RAW["app_segments"]:
        decision = zpa_rule_decision(graph, it, _uid("seg", seg["id"]))
        assert (decision.rule["uid"], decision.action) == (_uid("rule", "1"), "allow")


def test_another_tenants_rule_with_no_application_condition_does_not_apply():
    from tests.test_zpa import RAW

    from hst.analysis_model.gates import zpa_rule_decision
    from hst.collectors.zpa import normalize_zpa

    acme = {**RAW, "access_rules": [_scim_rule("1", "2", "ALLOW", "sales", "2001")]}
    other = {
        **RAW,
        "access_rules": [
            {"id": "1", "name": "deny-all", "action": "DENY", "ruleOrder": "1", "conditions": []}
        ],
    }
    graph = _inventory(normalize_zpa(acme, tenant="acme"), normalize_zpa(other, tenant="other"))
    decision = zpa_rule_decision(graph, _uid("idp", "idp-1-sales"), _uid("seg", "2001"))
    assert (decision.rule["uid"], decision.action) == (_uid("rule", "1"), "allow")


def test_a_tie_is_unknown_in_the_analysis_model():
    from tests.test_zpa import RAW

    from hst.analysis_model.gates import zpa_rule_decision
    from hst.collectors.zpa import normalize_zpa
    from hst.core.zpa_policy import GAP_RULE_ORDER_UNKNOWN

    raw = {
        **RAW,
        "access_rules": [
            _scim_rule("1", "1", "ALLOW", "sales", "2001"),
            _scim_rule("2", "1", "DENY", "sales", "2001"),
        ],
    }
    decision = zpa_rule_decision(
        _inventory(normalize_zpa(raw, tenant="acme")), _uid("idp", "idp-1-sales"), _uid("seg", "2001")
    )
    assert decision.indeterminate and decision.gap == GAP_RULE_ORDER_UNKNOWN


def test_the_analysis_model_blocks_a_disabled_segment_and_leaves_a_bypass_unknown():
    from tests.test_zpa import APP_SEGMENT_CRM, RAW

    from hst.analysis_model.gates import expand_zpa_broker
    from hst.analysis_model.model import StateKey
    from hst.collectors.zpa import normalize_zpa

    eng, seg = _uid("idp", "idp-1-engineering"), _uid("seg", "2001")
    down = StateKey("down", _ctx(), "proxy")
    disabled = {**RAW, "app_segments": [{**APP_SEGMENT_CRM, "enabled": False}, *RAW["app_segments"][1:]]}
    expansion = expand_zpa_broker(_inventory(normalize_zpa(disabled, tenant="acme")), _ctx(), eng, seg, down)
    assert expansion.complete is True
    assert any(spec.terminal == "deny" for spec in expansion.nodes)
    bypass = {**RAW, "app_segments": [{**APP_SEGMENT_CRM, "bypassType": "ALWAYS"}, *RAW["app_segments"][1:]]}
    expansion = expand_zpa_broker(_inventory(normalize_zpa(bypass, tenant="acme")), _ctx(), eng, seg, down)
    assert expansion.complete is False and expansion.gaps == ("ZPA_NOT_BROKERED",)


def test_the_analysis_model_denies_when_every_connector_is_disabled():
    from tests.test_zpa import CONNECTOR, RAW

    from hst.analysis_model.gates import expand_zpa_broker
    from hst.analysis_model.model import StateKey
    from hst.collectors.zpa import normalize_zpa

    raw = {**RAW, "connectors": [{**CONNECTOR, "enabled": False}]}
    graph = _inventory(normalize_zpa(raw, tenant="acme"))
    expansion = expand_zpa_broker(
        graph,
        _ctx(),
        _uid("idp", "idp-1-engineering"),
        _uid("seg", "2001"),
        StateKey("down", _ctx(), "proxy"),
    )
    assert expansion.complete is True
    assert any(spec.terminal == "deny" for spec in expansion.nodes)


def test_forwarding_bypass_is_not_brokered_and_names_the_rule():
    from hst.core.zpa_policy import GAP_NOT_BROKERED, forwarding_decision

    bypass = {"uid": "f:1", "name": "bypass-crm", "position": 1, "action": "bypass", "identity_named": True}
    decision = forwarding_decision([bypass], "idg:a", "seg:1")
    assert not decision.go_on and decision.gap == GAP_NOT_BROKERED and "bypass-crm" in decision.reason
    assert forwarding_decision([{**bypass, "action": "intercept"}], "idg:a", "seg:1").go_on
    empty = forwarding_decision([], "idg:a", "seg:1")
    assert empty.go_on and "read as intercepted" in empty.note
    other = forwarding_decision([{**bypass, "identity_named": False}], "idg:a", "seg:1")
    assert other.go_on and "read as intercepted" in other.note


def test_the_analysis_model_reads_a_bypass_forwarding_rule_ahead_of_the_access_rule():
    from tests.test_zpa import CLIENT_FORWARDING_RULE, RAW

    from hst.analysis_model.gates import expand_zpa_broker
    from hst.analysis_model.model import StateKey
    from hst.collectors.zpa import normalize_zpa

    eng_rule = {
        **CLIENT_FORWARDING_RULE,
        "action": "BYPASS",
        "conditions": [
            {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
            {
                "operator": "OR",
                "operands": [{"objectType": "SCIM_GROUP", "name": "engineering", "idpId": "idp-1"}],
            },
        ],
    }
    graph = _inventory(normalize_zpa({**RAW, "client_forwarding_rules": [eng_rule]}, tenant="acme"))
    expansion = expand_zpa_broker(
        graph,
        _ctx(),
        _uid("idp", "idp-1-engineering"),
        _uid("seg", "2001"),
        StateKey("down", _ctx(), "proxy"),
    )
    assert expansion.complete is False and expansion.gaps == ("ZPA_NOT_BROKERED",)
