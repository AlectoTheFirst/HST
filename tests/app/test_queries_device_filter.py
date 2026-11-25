"""The optional device filter of the policy and routing queries."""

import pytest
from tests.app.conftest import login

import hst.app.routes.queries as queries_route
from hst.queries import QUERIES
from hst.twin_tools.query import named_query

FILTERED = {
    "firewall",
    "nat",
    "bgp-sessions",
    "bgp-peers-by-asn",
    "bgp-per-vrf",
    "bgp-originated",
    "bgp-session-policies",
    "route-maps",
    "prefix-lists",
}


def test_the_policy_and_routing_queries_take_an_optional_device_by_hostname():
    by_key = {q["key"]: q for q in QUERIES}
    for key in FILTERED:
        [param] = [p for p in by_key[key]["params"] if p["name"] == "device"]
        assert param["optional"] is True, key
        assert param["picker"] == {"label": "Device", "property": "hostname"}, key
        assert "$device = ''" in by_key[key]["cypher"], key


def test_a_rulebase_is_matched_through_every_ownership():
    cypher = {q["key"]: q for q in QUERIES}["firewall"]["cypher"]
    for edge in (
        "(rb)<-[e1:ENFORCES]-(d1:Device)",
        ":VrfInstance)-[:ON]->(d2:Device)",
        ":RedundancyGroup)<-[:MEMBER_OF]-(d3:Device)",
        "(rb)<-[e4:PROTECTED_BY]-(:Interface)",
    ):
        assert edge in cypher


def test_a_route_policy_is_matched_by_the_device_uid_in_its_own_uid():
    cypher = {q["key"]: q for q in QUERIES}["route-maps"]["cypher"]
    assert "pol.uid STARTS WITH 'rtpol:' + dd.uid + ':'" in cypher


def test_the_agent_tool_does_not_require_the_device():
    assert named_query("firewall", {})["key"] == "firewall"


@pytest.mark.parametrize(("body", "bound"), [({}, ""), ({"params": {"device": "fw-fra-01"}}, "fw-fra-01")])
async def test_the_route_binds_an_empty_device_when_it_is_left_out(client, monkeypatch, body, bound):
    await login(client, "vera")
    seen = {}

    def fake_run_readonly(settings, cypher, params, trusted=False, graph=False):
        seen.update(params)
        return {"columns": [], "data": [], "truncated": False}

    monkeypatch.setattr(queries_route, "run_readonly", fake_run_readonly)
    r = await client.post("/api/queries/firewall", json=body)
    assert r.status_code == 200
    assert seen == {"device": bound}
