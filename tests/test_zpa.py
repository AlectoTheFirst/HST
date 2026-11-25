"""ZPA collector: app segments, connectors and the access rules that gate them
(fixture-first, MockTransport)."""

import json
import logging

import httpx
import pytest

from hst.collectors.auth import OAuthClientCredentials
from hst.collectors.zpa import ZpaConfig, normalize_zpa
from hst.core import uid as uidmod

SEGMENT_GROUP = {"id": "3001", "name": "corp-apps"}

APP_SEGMENT_CRM = {
    "id": "2001",
    "name": "app-crm",
    "domainNames": ["crm.corp.internal"],
    "tcpPortRanges": ["443", "443"],
    "udpPortRanges": [],
    "enabled": True,
    "segmentGroupId": "3001",
    "serverGroups": [{"id": "4001"}],
}
APP_SEGMENT_ERP = {
    "id": "2002",
    "name": "app-erp",
    "domainNames": ["erp.corp.internal", "erp2.corp.internal"],
    "tcpPortRanges": ["8080", "8090"],
    "udpPortRanges": [],
    "enabled": True,
    "segmentGroupId": "3001",
    "serverGroups": [{"id": "4001"}],
}

SERVER_GROUP = {"id": "4001", "name": "crm-erp-servers", "appConnectorGroups": [{"id": "5001"}]}
# Only a static group (`dynamicDiscovery: false`) embeds `servers`.
APP_SERVER_WEB01 = {"id": "4101", "name": "web-01", "address": "10.1.1.10", "enabled": True}
SERVER_GROUP_STATIC = {
    "id": "4002",
    "name": "static-web-servers",
    "dynamicDiscovery": False,
    "appConnectorGroups": [{"id": "5001"}],
    "servers": [APP_SERVER_WEB01],
}

APP_CONNECTOR_GROUP = {"id": "5001", "name": "hq-connectors", "location": "hq-sunnyvale"}
CONNECTOR = {
    "id": "6001",
    "name": "connector-01",
    "appConnectorGroupId": "5001",
    "enabled": True,
    "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED",
    "privateIp": "10.0.0.6",
    "publicIp": "8.8.8.8",
}

SERVICE_EDGE = {"id": "7001", "name": "edge-01", "type": "PRIVATE", "location": "hq-sunnyvale"}

CLIENT_FORWARDING_RULE = {
    "id": "8001",
    "name": "intercept-crm",
    "action": "INTERCEPT",
    "priority": "1",
    "ruleOrder": "1",
    "conditions": [
        {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
        {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": "77001", "idpId": "idp-1"}]},
    ],
}

# The answer carries the enrollment secret in `provisioningKey`; fetch() removes it.
PROVISIONING_KEY = {
    "id": "900001",
    "name": "connector-key-01",
    "enabled": True,
    "maxUsage": "10",
    "usageCount": "3",
    "zcomponentId": "5001",
    "zcomponentName": "hq-connectors",
    "provisioningKey": "super-secret-enrollment-string",
}

SCIM_GROUPS = [{"id": 77001, "idpId": "idp-1", "name": "Sales EMEA", "idpGroupId": "g-77001"}]

ACCESS_RULE_ALLOW = {
    "id": "9001",
    "name": "allow-eng-to-crm",
    "action": "ALLOW",
    "priority": "1",
    "ruleOrder": "1",
    "conditions": [
        {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
        {
            "operator": "OR",
            "operands": [{"objectType": "SCIM_GROUP", "name": "engineering", "idpId": "idp-1"}],
        },
    ],
}
ACCESS_RULE_DENY = {
    "id": "9002",
    "name": "deny-contractors-crm",
    "action": "DENY",
    "priority": "2",
    "ruleOrder": "2",
    "conditions": [
        {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
        {
            "operator": "OR",
            "operands": [{"objectType": "SCIM_GROUP", "name": "contractors", "idpId": "idp-1"}],
        },
    ],
}
ACCESS_RULE_GROUP_SCOPED = {
    "id": "9003",
    "name": "allow-partners-corp-apps",
    "action": "ALLOW",
    "priority": "3",
    "ruleOrder": "3",
    "conditions": [
        {"operator": "OR", "operands": [{"objectType": "APP_GROUP", "rhs": "3001"}]},
    ],
}
# No idpId on the SCIM_GROUP operand: normalize_zpa keys the group by a bare slug(name)
# uid.
ACCESS_RULE_NO_IDP = {
    "id": "9004",
    "name": "allow-legacy-partners-crm",
    "action": "ALLOW",
    "priority": "4",
    "ruleOrder": "4",
    "conditions": [
        {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
        {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "name": "Legacy Partners"}]},
    ],
}

RAW = {
    "app_segments": [APP_SEGMENT_CRM, APP_SEGMENT_ERP],
    "segment_groups": [SEGMENT_GROUP],
    "server_groups": [SERVER_GROUP, SERVER_GROUP_STATIC],
    "connector_groups": [APP_CONNECTOR_GROUP],
    "connectors": [CONNECTOR],
    "service_edges": [SERVICE_EDGE],
    "access_rules": [ACCESS_RULE_ALLOW, ACCESS_RULE_DENY, ACCESS_RULE_GROUP_SCOPED, ACCESS_RULE_NO_IDP],
    "client_forwarding_rules": [CLIENT_FORWARDING_RULE],
    "provisioning_keys": [PROVISIONING_KEY],
    "scim_groups": SCIM_GROUPS,
}


def _cfg(**over):
    base = {
        "vanity_domain": "acme",
        "tenant": "acme",
        "customer_id": "cust-1",
        "auth": OAuthClientCredentials(client_id="cid", client_secret="sec"),
    }
    base.update(over)
    return ZpaConfig(**base)


def make_mock():
    calls = {"token": 0, "paths": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            calls["token"] += 1
            return httpx.Response(200, json={"access_token": "tok-1"})
        calls["paths"].append((request.url.path, dict(request.url.params)))
        path = request.url.path
        base = "/zpa/mgmtconfig/v1/admin/customers/cust-1"
        # the live ZPA envelope: a constant "list" key and totalPages
        if path == f"{base}/application":
            return httpx.Response(200, json={"list": [APP_SEGMENT_CRM, APP_SEGMENT_ERP], "totalPages": 1})
        if path == f"{base}/segmentGroup":
            return httpx.Response(200, json={"list": [SEGMENT_GROUP], "totalPages": 1})
        if path == f"{base}/serverGroup":
            return httpx.Response(200, json={"list": [SERVER_GROUP, SERVER_GROUP_STATIC], "totalPages": 1})
        if path == f"{base}/appConnectorGroup":
            return httpx.Response(200, json={"list": [APP_CONNECTOR_GROUP], "totalPages": 1})
        if path == f"{base}/connector":
            return httpx.Response(200, json={"list": [CONNECTOR], "totalPages": 1})
        if path == f"{base}/serviceEdge":
            return httpx.Response(200, json={"list": [SERVICE_EDGE], "totalPages": 1})
        if path == f"{base}/policySet/rules/policyType/ACCESS_POLICY":
            return httpx.Response(
                200,
                json={
                    "list": [
                        ACCESS_RULE_ALLOW,
                        ACCESS_RULE_DENY,
                        ACCESS_RULE_GROUP_SCOPED,
                        ACCESS_RULE_NO_IDP,
                    ],
                    "totalPages": 1,
                },
            )
        if path == f"{base}/policySet/rules/policyType/CLIENT_FORWARDING_POLICY":
            return httpx.Response(200, json={"list": [CLIENT_FORWARDING_RULE], "totalPages": 1})
        if path == f"{base}/associationType/CONNECTOR_GRP/provisioningKey":
            return httpx.Response(200, json={"list": [PROVISIONING_KEY], "totalPages": 1})
        if path == f"{base}/associationType/SERVICE_EDGE_GRP/provisioningKey":
            return httpx.Response(200, json={"list": [], "totalPages": 1})
        if path == "/zpa/userconfig/v1/customers/cust-1/scimgroup/idpId/idp-1":
            return httpx.Response(200, json={"list": SCIM_GROUPS, "totalPages": 1})
        raise AssertionError(f"unexpected path {path}")

    return httpx.MockTransport(handler), calls


def _norm():
    return normalize_zpa(RAW, tenant="acme")


# Scope, probe, fetch pagination, uid symmetry, batch coherence and the session from the
# auth model are tested for ZIA and ZPA in test_zscaler_conformance.py.


def test_app_segments_member_of_segment_group():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    crm = nodes[uidmod.zpa("acme", "seg", "2001")]
    assert crm.label == "ZpaAppSegment"
    assert crm.props["domains"] == ["crm.corp.internal"]
    assert crm.props["tcp_port_ranges"] == ["443", "443"]
    assert crm.props["enabled"] is True
    erp = nodes[uidmod.zpa("acme", "seg", "2002")]
    assert erp.props["domains"] == ["erp.corp.internal", "erp2.corp.internal"]
    grp = uidmod.zpa("acme", "seggrp", "3001")
    assert nodes[grp].label == "ZpaSegmentGroup"
    assert ("MEMBER_OF", crm.uid, grp) in rels
    assert ("MEMBER_OF", erp.uid, grp) in rels


def test_segment_served_by_server_group_uses_connector_group_has_connector():
    # (ZpaAppSegment)-[:SERVED_BY]->(ZpaServerGroup)
    #   -[:USES]->(ZpaAppConnectorGroup)-[:HAS]->(ZpaAppConnector)
    batch = _norm()
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    seg = uidmod.zpa("acme", "seg", "2001")
    srvgrp = uidmod.zpa("acme", "srvgrp", "4001")
    cgrp = uidmod.zpa("acme", "cgrp", "5001")
    conn = uidmod.zpa("acme", "conn", "6001")
    assert ("SERVED_BY", seg, srvgrp) in rels
    assert ("USES", srvgrp, cgrp) in rels
    assert ("HAS", cgrp, conn) in rels
    assert not [r for r in rels if r[0] == "MEMBER_OF" and r[2] == cgrp]


def test_connector_group_and_connector_nodes():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    cgrp = nodes[uidmod.zpa("acme", "cgrp", "5001")]
    assert cgrp.label == "ZpaAppConnectorGroup"
    assert cgrp.props == {"name": "hq-connectors", "location": "hq-sunnyvale"}
    conn = nodes[uidmod.zpa("acme", "conn", "6001")]
    assert conn.label == "ZpaAppConnector"
    assert conn.props == {
        "name": "connector-01",
        "enabled": True,
        "health": "up",
        "control_channel_status": "ZPN_STATUS_AUTHENTICATED",
        "private_ip": "10.0.0.6",
        "public_ip": "8.8.8.8",
    }


def test_a_connector_naming_a_vm_or_an_instance_writes_no_stub():
    # the connector's address is its private_ip.
    for extra in ({"vmId": "vm-201"}, {"instanceId": "i-0abc123"}):
        batch = normalize_zpa({**RAW, "connectors": [{**CONNECTOR, **extra}]}, tenant="acme")
        assert not [r for r in batch.rels if r.rel_type == "RUNS_ON"]
        assert not [n for n in batch.nodes if n.label in ("Vm", "Instance")]


def test_connector_naming_neither_emits_no_dangling_runs_on_edge():
    # The default RAW fixture's CONNECTOR names neither field.
    batch = _norm()
    assert not [r for r in batch.rels if r.rel_type == "RUNS_ON"]


def test_service_edge_node():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    edge = nodes[uidmod.zpa("acme", "edge", "7001")]
    assert edge.label == "ZpaServiceEdge"
    assert edge.props == {"name": "edge-01", "kind": "private", "location": "hq-sunnyvale"}


def test_service_edge_from_the_live_shape_is_private_with_its_health():
    # The live answer carries no `type`; the endpoint lists private service edges only.
    live = {
        "id": "7002",
        "name": "edge-02",
        "location": "dc-2",
        "enabled": False,
        "controlChannelStatus": "ZPN_STATUS_DISCONNECTED",
    }
    batch = normalize_zpa({**RAW, "service_edges": [live]}, tenant="acme")
    edge = {n.uid: n for n in batch.nodes}[uidmod.zpa("acme", "edge", "7002")]
    assert edge.props == {
        "name": "edge-02",
        "kind": "private",
        "location": "dc-2",
        "enabled": False,
        "health": "down",
        "control_channel_status": "ZPN_STATUS_DISCONNECTED",
    }


def test_access_rule_gate_label_present():
    from hst.core.labels import LABELS

    batch = _norm()
    assert "ZpaAccessRule" in {n.label for n in batch.nodes}
    assert LABELS["ZpaAccessRule"].gate is True


def test_access_rule_for_app_segment():
    # (ZpaAccessRule)-[:FOR]->(ZpaAppSegment|ZpaSegmentGroup)
    batch = _norm()
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    allow = uidmod.zpa("acme", "rule", "9001")
    deny = uidmod.zpa("acme", "rule", "9002")
    seg = uidmod.zpa("acme", "seg", "2001")
    assert ("FOR", allow, seg) in rels
    assert ("FOR", deny, seg) in rels


def test_access_rule_for_segment_group():
    # (ZpaAccessRule)-[:FOR]->(ZpaAppSegment|ZpaSegmentGroup)
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    rule = uidmod.zpa("acme", "rule", "9003")
    grp = uidmod.zpa("acme", "seggrp", "3001")
    assert ("FOR", rule, grp) in rels
    assert nodes[grp].label == "ZpaSegmentGroup"


def test_access_rule_grants_denies_identity_group():
    # (ZpaAccessRule)-[:GRANTS|DENIES]->(IdentityGroup)
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    allow = uidmod.zpa("acme", "rule", "9001")
    deny = uidmod.zpa("acme", "rule", "9002")
    eng = uidmod.zpa("acme", "idp", "idp-1-engineering")
    contractors = uidmod.zpa("acme", "idp", "idp-1-contractors")
    assert ("GRANTS", allow, eng) in rels
    assert ("DENIES", deny, contractors) in rels
    assert nodes[eng].label == "IdentityGroup"
    assert nodes[eng].props == {"name": "engineering", "source": "scim"}
    assert nodes[contractors].props == {"name": "contractors", "source": "scim"}


def test_access_rule_grants_identity_group_without_idpid_uses_bare_slug():
    # A SCIM_GROUP operand with no idpId gets a bare slug(name) uid.
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    rule = uidmod.zpa("acme", "rule", "9004")
    grp = uidmod.zpa("acme", "idp", "legacy-partners")
    assert ("GRANTS", rule, grp) in rels
    assert nodes[grp].label == "IdentityGroup"
    assert nodes[grp].props == {"name": "Legacy Partners", "source": "scim"}


def test_access_rule_action_and_position_props():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    allow = nodes[uidmod.zpa("acme", "rule", "9001")]
    assert allow.props["action"] == "allow"
    assert allow.props["position"] == 1
    assert allow.props["conditions_summary"] == "APP=2001; SCIM_GROUP=engineering"
    deny = nodes[uidmod.zpa("acme", "rule", "9002")]
    assert deny.props["action"] == "deny"


def test_access_rule_action_raw_preserved_alongside_lowercased_action():
    # RULE 2: `action_raw` keeps the action string as sent.
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    allow = nodes[uidmod.zpa("acme", "rule", "9001")]
    assert allow.props["action_raw"] == "ALLOW"
    deny = nodes[uidmod.zpa("acme", "rule", "9002")]
    assert deny.props["action_raw"] == "DENY"


def test_access_rule_applies_to_all_identities_when_no_scim_condition():
    # RULE 2: a rule with no SCIM_GROUP operand in any condition carries `applies_to_all_identities`.
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    group_scoped = nodes[uidmod.zpa("acme", "rule", "9003")]
    assert group_scoped.props["applies_to_all_identities"] is True
    # A rule with a SCIM_GROUP condition has no `applies_to_all_identities` prop.
    allow = nodes[uidmod.zpa("acme", "rule", "9001")]
    assert "applies_to_all_identities" not in allow.props


def test_access_rule_conditions_json_preserves_operator_and_operands():
    # RULE 3: `conditions` is a JSON-encoded string of each condition's operators and operands.
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    allow = nodes[uidmod.zpa("acme", "rule", "9001")]
    conditions = json.loads(allow.props["conditions"])
    assert conditions == [
        {"operator": "OR", "operands": [{"type": "APP", "rhs": "2001"}]},
        {
            "operator": "OR",
            "operands": [{"type": "SCIM_GROUP", "rhs": "engineering"}],
        },
    ]


def test_access_rule_identity_group_from_the_live_operand_shape():
    # A live SCIM_GROUP operand carries `rhs` (the SCIM group id), `idpId` and
    # `idpName`, and no group name.
    rule = {
        "id": "9005",
        "name": "allow-sales-crm-live-shape",
        "action": "ALLOW",
        "priority": "5",
        "ruleOrder": "5",
        "conditions": [
            {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
            {
                "operator": "OR",
                "operands": [
                    {"objectType": "SCIM_GROUP", "rhs": "88001", "idpId": "idp-1", "idpName": "Acme AAD"}
                ],
            },
        ],
    }
    raw = {**RAW, "access_rules": [*RAW["access_rules"], rule]}
    batch = normalize_zpa(raw, tenant="acme")
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    grp = uidmod.zpa("acme", "idp", "idp-1-88001")
    assert ("GRANTS", uidmod.zpa("acme", "rule", "9005"), grp) in rels
    # 88001 is not in SCIM_GROUPS, so the name is the id; the identity provider's
    # name is its own prop, not the group's name.
    assert nodes[grp].props == {"name": "88001", "name_is_id": True, "source": "scim", "idp_name": "Acme AAD"}


def test_identity_group_takes_its_name_from_the_scim_group_list():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    assert nodes[uidmod.zpa("acme", "idp", "idp-1-77001")].props["name"] == "Sales EMEA"


def test_server_group_contains_app_server_for_a_static_group_only():
    # SERVER_GROUP (dynamic) gets no AppServer node; SERVER_GROUP_STATIC does.
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    static_grp = uidmod.zpa("acme", "srvgrp", "4002")
    app_srv = uidmod.zpa("acme", "appsrv", "4101")
    assert ("CONTAINS", static_grp, app_srv) in rels
    assert nodes[app_srv].label == "AppServer"
    assert nodes[app_srv].props == {"name": "web-01", "address": "10.1.1.10", "enabled": True}
    dynamic_grp = uidmod.zpa("acme", "srvgrp", "4001")
    assert not [r for r in rels if r[0] == "CONTAINS" and r[1] == dynamic_grp]


def test_client_forwarding_rule_for_segment_and_applies_to_identity_group():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    fwdrule = uidmod.zpa("acme", "fwdrule", "8001")
    seg = uidmod.zpa("acme", "seg", "2001")
    idg = uidmod.zpa("acme", "idp", "idp-1-77001")
    assert nodes[fwdrule].label == "ZpaClientForwardingRule"
    assert nodes[fwdrule].props["action"] == "intercept"
    assert nodes[fwdrule].props["position"] == 1
    assert ("FOR", fwdrule, seg) in rels
    assert ("APPLIES_TO", fwdrule, idg) in rels
    assert not [r for r in rels if r[0] in ("GRANTS", "DENIES") and r[1] == fwdrule]
    # The evaluator's data is kept, as on an access rule.
    assert json.loads(nodes[fwdrule].props["conditions"])[1]["operands"] == [
        {"type": "SCIM_GROUP", "rhs": "77001"}
    ]
    assert "applies_to_all_identities" not in nodes[fwdrule].props


def test_client_forwarding_rule_with_no_identity_condition_applies_to_everyone():
    rule = {
        "id": "8002",
        "name": "bypass-all",
        "action": "BYPASS",
        "priority": "2",
        "ruleOrder": "2",
        "conditions": [{"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]}],
    }
    batch = normalize_zpa({**RAW, "client_forwarding_rules": [rule]}, tenant="acme")
    props = {n.uid: n for n in batch.nodes}[uidmod.zpa("acme", "fwdrule", "8002")].props
    assert props["action"] == "bypass" and props["applies_to_all_identities"] is True


def test_provisioning_key_is_metadata_only_never_the_secret_value():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    key = nodes[uidmod.zpa("acme", "provkey", "900001")]
    assert key.label == "ZpaProvisioningKey"
    assert key.props == {
        "name": "connector-key-01",
        "enabled": True,
        "max_usage": "10",
        "usage_count": "3",
        "zcomponent_id": "5001",
        "zcomponent_name": "hq-connectors",
    }
    # PROVISIONING_KEY carries the secret field, and normalize writes no prop from it.
    assert "provisioningKey" not in key.props
    assert "super-secret-enrollment-string" not in key.props.values()


def test_fetch_removes_the_provisioning_key_secret(monkeypatch):
    from hst.collectors import zpa
    from hst.core import Settings

    transport, _calls = make_mock()
    monkeypatch.setattr(zpa, "_transport", lambda config: transport)
    raw = zpa.ZpaCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert raw["provisioning_keys"][0]["name"] == "connector-key-01"
    assert "super-secret-enrollment-string" not in json.dumps(raw)


def test_the_http_trace_redacts_the_provisioning_key_secret():
    from hst.collectors import http_trace

    redacted = http_trace.redact({"list": [dict(PROVISIONING_KEY)]})
    assert redacted["list"][0]["provisioningKey"] == http_trace.REDACTED
    assert redacted["list"][0]["name"] == "connector-key-01"


def test_connector_health_maps_the_control_channel_status():
    down = {**CONNECTOR, "id": "6002", "controlChannelStatus": "ZPN_STATUS_DISCONNECTED", "enabled": False}
    odd = {**CONNECTOR, "id": "6003", "controlChannelStatus": "ZPN_STATUS_SOMETHING_NEW"}
    batch = normalize_zpa({**RAW, "connectors": [CONNECTOR, down, odd]}, tenant="acme")
    nodes = {n.uid: n for n in batch.nodes}
    assert nodes[uidmod.zpa("acme", "conn", "6001")].props["health"] == "up"
    assert nodes[uidmod.zpa("acme", "conn", "6002")].props["health"] == "down"
    assert nodes[uidmod.zpa("acme", "conn", "6002")].props["enabled"] is False
    # A status this collector does not map writes no health, and keeps the raw value.
    unknown = nodes[uidmod.zpa("acme", "conn", "6003")].props
    assert "health" not in unknown and unknown["control_channel_status"] == "ZPN_STATUS_SOMETHING_NEW"


def test_an_optional_section_that_is_refused_keeps_the_rest_of_the_collection(monkeypatch):
    from hst.collectors import zpa
    from hst.core import Settings

    transport, _calls = make_mock()

    def refuse_keys(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/provisioningKey"):
            return httpx.Response(403, json={"id": "authz.denied"})
        return transport.handle_request(request)

    monkeypatch.setattr(zpa, "_transport", lambda config: httpx.MockTransport(refuse_keys))
    collector = zpa.ZpaCollector(_cfg(), Settings(_env_file=None))
    raw = collector.fetch()
    assert raw["provisioning_keys"] == [] and raw["access_rules"]
    batch = collector.normalize(raw)
    assert batch.sections["provisioning_keys"].status == "unauthorized"
    assert "403" in batch.sections["provisioning_keys"].detail
    assert batch.sections["client_forwarding_rules"].status == "ok"
    assert any(n.label == "ZpaAccessRule" for n in batch.nodes)


def test_access_rule_skips_non_numeric_priority_with_warning(caplog):
    # RULE 1: a rule whose ruleOrder and priority do not parse as integers is skipped.
    bad_rule = {
        "id": "9099",
        "name": "bad-priority",
        "action": "ALLOW",
        "priority": "not-a-number",
        "ruleOrder": "not-a-number",
        "conditions": [{"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]}],
    }
    raw = dict(RAW)
    raw["access_rules"] = [*RAW["access_rules"], bad_rule]
    with caplog.at_level(logging.WARNING):
        batch = normalize_zpa(raw, tenant="acme")
    uids = {n.uid for n in batch.nodes}
    assert uidmod.zpa("acme", "rule", "9099") not in uids
    assert any("9099" in rec.message for rec in caplog.records)


def test_each_declared_section_label_is_written_by_that_section_alone():
    from hst.collectors import zpa

    declared = zpa.ZpaCollector.SECTION_LABELS
    assert set(declared) == set(zpa.OPTIONAL_SECTIONS)
    full = {n.label for n in normalize_zpa(RAW, tenant="acme").nodes}
    for section, labels in declared.items():
        without = {n.label for n in normalize_zpa({**RAW, section: []}, tenant="acme").nodes}
        assert not without & set(labels), section
        for label in labels:
            assert label in full, label


ZPA_BASE = "/zpa/mgmtconfig/v1/admin/customers/cust-1"


def _fetch_with(monkeypatch, refuse: dict[str, int], extra_access_rules: tuple[dict, ...] = ()):
    """Fetch and normalize against the mock, with each path in `refuse` answering
    its code and `extra_access_rules` added to the access policy list."""
    import functools

    from hst.collectors import zpa, zscaler_auth
    from hst.core import Settings

    transport, _calls = make_mock()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in refuse:
            return httpx.Response(refuse[path], json={"id": "refused"})
        if path == f"{ZPA_BASE}/policySet/rules/policyType/ACCESS_POLICY" and extra_access_rules:
            rules = [ACCESS_RULE_ALLOW, ACCESS_RULE_DENY, ACCESS_RULE_GROUP_SCOPED, ACCESS_RULE_NO_IDP]
            return httpx.Response(200, json={"list": [*rules, *extra_access_rules], "totalPages": 1})
        return transport.handle_request(request)

    monkeypatch.setattr(zpa, "_transport", lambda config: httpx.MockTransport(handler))
    monkeypatch.setattr(
        zpa, "ZscalerSession", functools.partial(zscaler_auth.ZscalerSession, sleep=lambda s: None)
    )
    collector = zpa.ZpaCollector(_cfg(), Settings(_env_file=None))
    raw = collector.fetch()
    return raw, collector.normalize(raw)


@pytest.mark.parametrize(("code", "status"), [(403, "unauthorized"), (503, "failed")])
def test_a_refused_association_type_keeps_the_keys_that_answered(monkeypatch, code, status):
    path = f"{ZPA_BASE}/associationType/SERVICE_EDGE_GRP/provisioningKey"
    raw, batch = _fetch_with(monkeypatch, {path: code})
    expected = {k: v for k, v in PROVISIONING_KEY.items() if k != "provisioningKey"}
    assert raw["provisioning_keys"] == [expected]
    outcome = batch.sections["provisioning_keys"]
    assert outcome.status == status
    assert outcome.row_count == 1
    assert str(code) in outcome.detail and "SERVICE_EDGE_GRP" in outcome.detail
    assert len([n for n in batch.nodes if n.label == "ZpaProvisioningKey"]) == 1


def test_an_unsupported_association_type_reads_partial(monkeypatch):
    from hst.core.model import section_verdict

    path = f"{ZPA_BASE}/associationType/SERVICE_EDGE_GRP/provisioningKey"
    _raw, batch = _fetch_with(monkeypatch, {path: 404})
    outcome = batch.sections["provisioning_keys"]
    assert outcome.status == "partial"
    assert outcome.row_count == 1
    assert section_verdict(batch.sections) == "ok"


@pytest.mark.parametrize(("code", "status"), [(404, "partial"), (503, "failed")])
def test_one_refused_identity_provider_keeps_the_names_of_the_others(monkeypatch, code, status):
    second_idp_rule = {
        "id": "9005",
        "name": "allow-idp-2-crm",
        "action": "ALLOW",
        "priority": "5",
        "ruleOrder": "5",
        "conditions": [
            {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
            {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": "88001", "idpId": "idp-2"}]},
        ],
    }
    path = "/zpa/userconfig/v1/customers/cust-1/scimgroup/idpId/idp-2"
    _raw, batch = _fetch_with(monkeypatch, {path: code}, (second_idp_rule,))
    nodes = {n.uid: n for n in batch.nodes}
    assert nodes[uidmod.zpa("acme", "idp", "idp-1-77001")].props["name"] == "Sales EMEA"
    assert nodes[uidmod.zpa("acme", "idp", "idp-2-88001")].props["name"] == "88001"
    outcome = batch.sections["scim_groups"]
    assert outcome.status == status
    assert "idp-2" in outcome.detail


# --- rule order: `position` comes from `ruleOrder`, not from `priority` ----------------------


def _rule_nodes(batch, label):
    return {n.uid: n.props for n in batch.nodes if n.label == label}


def test_rule_position_comes_from_rule_order_not_priority():
    first = {**ACCESS_RULE_ALLOW, "ruleOrder": "1", "priority": "2"}
    second = {**ACCESS_RULE_DENY, "ruleOrder": "2", "priority": "1"}
    batch = normalize_zpa({**RAW, "access_rules": [first, second]}, tenant="acme")
    rules = _rule_nodes(batch, "ZpaAccessRule")
    assert rules[uidmod.zpa("acme", "rule", "9001")]["position"] == 1
    assert rules[uidmod.zpa("acme", "rule", "9001")]["priority"] == 2
    assert rules[uidmod.zpa("acme", "rule", "9002")]["position"] == 2
    assert rules[uidmod.zpa("acme", "rule", "9002")]["priority"] == 1


def test_a_rule_without_an_integer_rule_order_is_skipped_whatever_its_priority(caplog):
    rule = {k: v for k, v in ACCESS_RULE_ALLOW.items() if k != "ruleOrder"}
    rule = {**rule, "id": "9098", "priority": "1"}
    with caplog.at_level(logging.WARNING):
        batch = normalize_zpa({**RAW, "access_rules": [rule]}, tenant="acme")
    assert uidmod.zpa("acme", "rule", "9098") not in {n.uid for n in batch.nodes}
    messages = [rec.getMessage() for rec in caplog.records]
    assert any("9098" in m and "ruleOrder" in m for m in messages)


# The list answer of ACCESS_POLICY after a bulk reorder, interaction 13 of
# https://github.com/zscaler/zscaler-sdk-python/blob/master/tests/integration/zpa/cassettes/TestAccessPolicyBulkReorderRule.yaml
# ruleOrder 1 to 5 carry priority 5 to 1.
RECORDED_ACCESS_RULES = [
    {"id": "216196257331404623", "name": "tests-vcr0009", "ruleOrder": "1", "priority": "5"},
    {"id": "216196257331404622", "name": "tests-vcr0007", "ruleOrder": "2", "priority": "4"},
    {"id": "216196257331404621", "name": "tests-vcr0005", "ruleOrder": "3", "priority": "3"},
    {"id": "216196257331404620", "name": "tests-vcr0003", "ruleOrder": "4", "priority": "2"},
    {"id": "216196257331404619", "name": "tests-vcr0001", "ruleOrder": "5", "priority": "1"},
]


def test_the_recorded_access_policy_list_orders_rules_by_rule_order():
    rules = [
        {**r, "policyType": "1", "operator": "AND", "action": "ALLOW", "disabled": "0"}
        for r in RECORDED_ACCESS_RULES
    ]
    batch = normalize_zpa({**RAW, "access_rules": rules}, tenant="acme")
    written = sorted(_rule_nodes(batch, "ZpaAccessRule").values(), key=lambda p: p["position"])
    assert [p["name"] for p in written] == [r["name"] for r in RECORDED_ACCESS_RULES]
    assert [p["priority"] for p in written] == [5, 4, 3, 2, 1]


def test_the_recorded_client_forwarding_default_rule_sorts_last():
    # The CLIENT_FORWARDING_POLICY list answer, interaction 7 of
    # https://github.com/zscaler/zscaler-sdk-python/blob/master/tests/integration/zpa/cassettes/TestAccessPolicyForwardingRuleV1.yaml
    rules = [
        {"id": "216196257331401659", "name": "DevTest", "ruleOrder": "1", "priority": "3"},
        {"id": "216196257331404615", "name": "tests-apfr1-vcr0001", "ruleOrder": "2", "priority": "2"},
        {
            "id": "216196257331281930",
            "name": "Default_Rule",
            "ruleOrder": "3",
            "priority": "1",
            "defaultRule": True,
        },
    ]
    rules = [{**r, "action": "INTERCEPT"} for r in rules]
    batch = normalize_zpa({**RAW, "client_forwarding_rules": rules}, tenant="acme")
    written = _rule_nodes(batch, "ZpaClientForwardingRule").values()
    last = max(written, key=lambda p: p["position"])
    assert last["name"] == "Default_Rule"
    assert last["priority"] == 1


def test_the_collector_declares_a_rules_normalization_version():
    from hst.collectors.zpa import ZpaCollector

    assert "rules" in ZpaCollector.NORMALIZATION_VERSIONS


# --- the whole rule: operator, enabled state, scopes, negation and lhs -------------------------


def _vendor_rule(rule_id, conditions, **extra):
    return {
        "id": rule_id,
        "name": f"r{rule_id}",
        "action": "ALLOW",
        "ruleOrder": rule_id,
        **extra,
        "conditions": conditions,
    }


def test_rule_keeps_its_operator_and_enabled_state():
    rules = [
        _vendor_rule("1", [], operator="OR", disabled="0"),
        _vendor_rule("2", [], disabled="1"),
        _vendor_rule("3", [], disabled="7"),
    ]
    props = _rule_nodes(normalize_zpa({**RAW, "access_rules": rules}, tenant="acme"), "ZpaAccessRule")
    first, second, third = (props[uidmod.zpa("acme", "rule", i)] for i in ("1", "2", "3"))
    assert first["operator"] == "OR" and first["enabled"] is True
    assert second["enabled"] is False
    assert third["disabled_raw"] == "7" and "enabled" not in third


def test_rule_scope_props_from_a_vendor_shaped_payload():
    scim = {
        "operator": "OR",
        "operands": [{"objectType": "SCIM_GROUP", "lhs": "idp-1", "rhs": "77001", "idpId": "idp-1"}],
    }
    app = {"operator": "OR", "operands": [{"objectType": "APP", "lhs": "id", "rhs": "2001"}]}
    saml = {"operator": "OR", "operands": [{"objectType": "SAML", "lhs": "attr-77", "rhs": "admins"}]}
    rules = [_vendor_rule("1", [scim]), _vendor_rule("2", [app, saml], operator="AND"), _vendor_rule("3", [])]
    props = _rule_nodes(normalize_zpa({**RAW, "access_rules": rules}, tenant="acme"), "ZpaAccessRule")
    scopes = {
        i: (
            props[uidmod.zpa("acme", "rule", i)]["identity_scope"],
            props[uidmod.zpa("acme", "rule", i)]["app_scope"],
        )
        for i in ("1", "2", "3")
    }
    assert scopes == {"1": ("listed", "any"), "2": ("other", "listed"), "3": ("any", "any")}


def test_conditions_json_keeps_negation_and_lhs_from_the_payload():
    cond = {
        "operator": "OR",
        "negated": True,
        "operands": [{"objectType": "SAML", "lhs": "attr-77", "rhs": "admins"}],
    }
    props = _rule_nodes(
        normalize_zpa({**RAW, "access_rules": [_vendor_rule("1", [cond])]}, tenant="acme"), "ZpaAccessRule"
    )
    rule = props[uidmod.zpa("acme", "rule", "1")]
    assert json.loads(rule["conditions"]) == [
        {"operator": "OR", "negated": True, "operands": [{"type": "SAML", "rhs": "admins", "lhs": "attr-77"}]}
    ]
    assert rule["conditions_summary"] == "NOT SAML[attr-77]=admins"


# --- edges from positive blocks and known actions ----------------------------------------------


def _edges(batch, rel_type, start):
    return {r.end_uid for r in batch.rels if r.rel_type == rel_type and r.start_uid == start}


def test_a_negated_block_draws_no_edge():
    rule = _vendor_rule(
        "1",
        [
            {"operator": "OR", "negated": True, "operands": [{"objectType": "APP", "rhs": "2001"}]},
            {
                "operator": "OR",
                "negated": True,
                "operands": [{"objectType": "SCIM_GROUP", "rhs": "77", "idpId": "idp-1"}],
            },
        ],
        action="DENY",
    )
    batch = normalize_zpa({**RAW, "access_rules": [rule]}, tenant="acme")
    ruid = uidmod.zpa("acme", "rule", "1")
    assert not _edges(batch, "FOR", ruid)
    assert not _edges(batch, "GRANTS", ruid) and not _edges(batch, "DENIES", ruid)
    assert uidmod.zpa("acme", "idp", "idp-1-77") not in {n.uid for n in batch.nodes}


def test_require_approval_draws_applies_to_not_denies():
    scim = {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": "77", "idpId": "idp-1"}]}
    batch = normalize_zpa(
        {**RAW, "access_rules": [_vendor_rule("1", [scim], action="REQUIRE_APPROVAL")]}, tenant="acme"
    )
    ruid = uidmod.zpa("acme", "rule", "1")
    assert _edges(batch, "APPLIES_TO", ruid) == {uidmod.zpa("acme", "idp", "idp-1-77")}
    assert not _edges(batch, "DENIES", ruid)
    assert _rule_nodes(batch, "ZpaAccessRule")[ruid]["action"] == "require_approval"


def test_an_unknown_access_action_keeps_only_action_raw():
    scim = {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": "77", "idpId": "idp-1"}]}
    batch = normalize_zpa(
        {**RAW, "access_rules": [_vendor_rule("1", [scim], action="ISOLATE")]}, tenant="acme"
    )
    ruid = uidmod.zpa("acme", "rule", "1")
    props = _rule_nodes(batch, "ZpaAccessRule")[ruid]
    assert "action" not in props and props["action_raw"] == "ISOLATE"
    assert _edges(batch, "APPLIES_TO", ruid) == {uidmod.zpa("acme", "idp", "idp-1-77")}


def test_applies_to_all_identities_only_without_an_identity_condition():
    def one(kind, lhs="attr-1"):
        return [{"operator": "OR", "operands": [{"objectType": kind, "lhs": lhs, "rhs": "x"}]}]

    rules = [
        _vendor_rule("1", one("SAML")),
        _vendor_rule("2", one("SCIM")),
        _vendor_rule("3", one("IDP", "id")),
        _vendor_rule("4", one("POSTURE")),
        _vendor_rule("5", []),
    ]
    props = _rule_nodes(normalize_zpa({**RAW, "access_rules": rules}, tenant="acme"), "ZpaAccessRule")
    flags = {i: props[uidmod.zpa("acme", "rule", i)].get("applies_to_all_identities") for i in "12345"}
    assert flags == {"1": None, "2": None, "3": None, "4": True, "5": True}


def test_a_stop_inside_an_optional_read_is_not_a_section_outcome(monkeypatch):
    import functools
    import threading

    from hst.collectors import zpa, zscaler_auth
    from hst.collectors.base import CollectionStopped
    from hst.core import Settings

    transport, calls = make_mock()
    collector = zpa.ZpaCollector(_cfg(), Settings(_env_file=None))
    collector.stop = threading.Event()
    keys = f"{ZPA_BASE}/associationType/CONNECTOR_GRP/provisioningKey"

    def handler(request):
        response = transport.handle_request(request)
        if request.url.path == keys:
            collector.stop.set()
        return response

    monkeypatch.setattr(zpa, "_transport", lambda config: httpx.MockTransport(handler))
    monkeypatch.setattr(
        zpa, "ZscalerSession", functools.partial(zscaler_auth.ZscalerSession, sleep=lambda s: None)
    )
    with pytest.raises(CollectionStopped):
        collector.fetch()
    paths = [p for p, _ in calls["paths"]]
    after = paths[paths.index(keys) + 1 :]
    assert not [p for p in after if "SERVICE_EDGE_GRP" in p or "scimgroup" in p]


def test_bypass_type_and_group_state_are_written():
    raw = {
        **RAW,
        "app_segments": [{**APP_SEGMENT_CRM, "bypassType": "always"}, APP_SEGMENT_ERP],
        "segment_groups": [{**SEGMENT_GROUP, "enabled": False}],
        "server_groups": [{**SERVER_GROUP, "enabled": "true", "dynamicDiscovery": True}, SERVER_GROUP_STATIC],
        "connector_groups": [{**APP_CONNECTOR_GROUP, "enabled": False}],
    }
    batch = normalize_zpa(raw, tenant="acme")
    nodes = {n.uid: n.props for n in batch.nodes}
    assert nodes[uidmod.zpa("acme", "seg", APP_SEGMENT_CRM["id"])]["bypass_type"] == "ALWAYS"
    group = nodes[uidmod.zpa("acme", "seggrp", SEGMENT_GROUP["id"])]
    assert group["enabled"] is False and group["zpa_id"] == SEGMENT_GROUP["id"]
    server = nodes[uidmod.zpa("acme", "srvgrp", SERVER_GROUP["id"])]
    assert server["enabled"] is True and server["dynamic_discovery"] is True
    assert nodes[uidmod.zpa("acme", "cgrp", APP_CONNECTOR_GROUP["id"])]["enabled"] is False


def test_an_access_rule_steers_via_the_groups_it_names():
    rule = {
        **ACCESS_RULE_ALLOW,
        "appConnectorGroups": [{"id": APP_CONNECTOR_GROUP["id"]}],
        "appServerGroups": [{"id": "4001"}],
    }
    batch = normalize_zpa({**RAW, "access_rules": [rule]}, tenant="acme")
    ruid = uidmod.zpa("acme", "rule", rule["id"])
    steer = {r.end_uid for r in batch.rels if r.rel_type == "STEERS_VIA" and r.start_uid == ruid}
    assert steer == {
        uidmod.zpa("acme", "cgrp", APP_CONNECTOR_GROUP["id"]),
        uidmod.zpa("acme", "srvgrp", "4001"),
    }


def test_segment_ranges_and_wildcards_come_from_domain_names():
    seg = {
        **APP_SEGMENT_CRM,
        "domainNames": ["crm.corp.internal", "10.20.0.5", "10.30.0.0/16", "*.corp.internal"],
    }
    batch = normalize_zpa({**RAW, "app_segments": [seg]}, tenant="acme")
    props = {n.uid: n.props for n in batch.nodes}[uidmod.zpa("acme", "seg", APP_SEGMENT_CRM["id"])]
    assert props["ranges"] == ["10.20.0.5/32", "10.30.0.0/16"]
    assert props["opaque"] is True and "*.corp.internal" in props["opaque_reason"]
    assert not [n for n in batch.nodes if n.label == "IpAddress"]


def test_an_identity_group_named_only_by_its_id_says_so():
    raw = {**RAW, "scim_groups": []}
    nodes = {n.uid: n for n in normalize_zpa(raw, tenant="acme").nodes}
    bare = nodes[uidmod.zpa("acme", "idp", "idp-1-77001")].props
    assert (bare["name"], bare["name_is_id"]) == ("77001", True)
    named = {n.uid: n for n in _norm().nodes}[uidmod.zpa("acme", "idp", "idp-1-77001")].props
    assert named["name"] == "Sales EMEA" and "name_is_id" not in named
