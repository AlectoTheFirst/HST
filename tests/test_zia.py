"""ZIA collector: locations/sublocations, GRE/IPsec tunnels (fixture-first, MockTransport)."""

import httpx

from hst.collectors.auth import OAuthClientCredentials
from hst.collectors.zia import ZiaConfig, normalize_zia
from hst.core import uid as uidmod

LOCATION_HQ = {
    "id": 1001,
    "name": "hq-sunnyvale",
    "country": "US",
    "tz": "US/Pacific",
    "ipAddresses": ["203.0.113.10"],
}
LOCATION_BRANCH = {
    "id": 1002,
    "name": "branch-austin",
    "country": "US",
    "tz": "US/Central",
    "ipAddresses": ["198.51.100.20"],
    "authRequired": True,
    "sslScanEnabled": False,
}
SUBLOCATION = {
    "id": 1003,
    "name": "branch-austin-guest",
    "parentId": 1002,
    "country": "US",
    "tz": "US/Central",
    "ipAddresses": [],
}
GRE_TUNNEL = {
    "id": 5001,
    "sourceIp": "203.0.113.10",
    "primaryDestVip": {"id": 100, "virtualIp": "104.129.194.38", "datacenter": "San Jose II"},
    "secondaryDestVip": {"id": 101, "virtualIp": "104.129.198.38", "datacenter": "San Jose III"},
}
# The credential names its location; a location carries no `vpnCredentials`.
VPN_CREDENTIAL = {
    "id": 7001,
    "type": "IP",
    "ipAddress": "198.51.100.20",
    "comments": "branch-office-ipsec",
    "location": {"id": 1002, "name": "branch-austin"},
}

LOCATION_GROUP_DYNAMIC = {
    "id": 43780169,
    "name": "Corp Dynamic Traffic Group",
    "groupType": "DYNAMIC_GROUP",
    "dynamicLocationGroupCriteria": {"profiles": ["CORPORATE"]},
    "locations": [{"id": 1001, "name": "hq-sunnyvale"}],
}
LOCATION_GROUP_STATIC = {
    "id": 43780170,
    "name": "Branch Offices",
    "groupType": "STATIC_GROUP",
    "locations": [{"id": 1002, "name": "branch-austin"}],
}

# A ZPA rule names its segments by `externalId`, the ZPA segment id; `id` is ZIA's own.
FORWARDING_RULE_ZPA = {
    "id": 600001,
    "name": "crm-to-zpa",
    "order": 1,
    "state": "ENABLED",
    "forwardMethod": "ZPA",
    "zpaAppSegments": [
        {"id": 31, "externalId": "2001", "name": "app-crm", "deleted": False},
        {"id": 32, "externalId": "2999", "name": "app-gone", "deleted": True},
    ],
}
FORWARDING_RULE_DIRECT = {
    "id": 600002,
    "name": "direct-rest",
    "order": 2,
    "state": "DISABLED",
    "forwardMethod": "DIRECT",
}

RAW = {
    "locations": [LOCATION_HQ, LOCATION_BRANCH],
    "sublocations": [SUBLOCATION],
    "gre_tunnels": [GRE_TUNNEL],
    "vpn_credentials": [VPN_CREDENTIAL],
    "location_groups": [LOCATION_GROUP_DYNAMIC, LOCATION_GROUP_STATIC],
    "forwarding_rules": [FORWARDING_RULE_ZPA, FORWARDING_RULE_DIRECT],
}


def _cfg(**over):
    base = {
        "vanity_domain": "acme",
        "tenant": "acme",
        "auth": OAuthClientCredentials(client_id="cid", client_secret="sec"),
    }
    base.update(over)
    return ZiaConfig(**base)


def make_mock():
    calls = {"token": 0, "paths": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            calls["token"] += 1
            return httpx.Response(200, json={"access_token": "tok-1"})
        calls["paths"].append((request.url.path, dict(request.url.params)))
        path = request.url.path
        # ZIA answers a bare array with no totalPages.
        first_page = request.url.params.get("page") == "1"
        if path == "/zia/api/v1/locations":
            return httpx.Response(200, json=[LOCATION_HQ, LOCATION_BRANCH] if first_page else [])
        if path == "/zia/api/v1/locations/lite":
            return httpx.Response(200, json=[LOCATION_HQ, LOCATION_BRANCH, SUBLOCATION] if first_page else [])
        if path == "/zia/api/v1/locations/1001/sublocations":
            return httpx.Response(200, json=[])
        if path == "/zia/api/v1/locations/1002/sublocations":
            return httpx.Response(200, json=[SUBLOCATION])
        if path == "/zia/api/v1/greTunnels":
            return httpx.Response(200, json=[GRE_TUNNEL] if first_page else [])
        if path == "/zia/api/v1/vpnCredentials":
            return httpx.Response(200, json=[VPN_CREDENTIAL] if first_page else [])
        if path == "/zia/api/v1/locations/groups":
            return httpx.Response(
                200, json=[LOCATION_GROUP_DYNAMIC, LOCATION_GROUP_STATIC] if first_page else []
            )
        if path == "/zia/api/v1/forwardingRules":
            return httpx.Response(
                200, json=[FORWARDING_RULE_ZPA, FORWARDING_RULE_DIRECT] if first_page else []
            )
        raise AssertionError(f"unexpected path {path}")

    return httpx.MockTransport(handler), calls


def _norm():
    return normalize_zia(RAW, tenant="acme")


# Scope, probe, fetch pagination, uid symmetry, batch coherence and the session from the
# auth model are tested for ZIA and ZPA in test_zscaler_conformance.py.


def test_location_and_sublocation_nodes():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    hq = nodes[uidmod.zia("acme", "loc", 1001)]
    assert hq.label == "ZiaLocation"
    assert hq.props == {
        "name": "hq-sunnyvale",
        "zia_id": "1001",
        "country": "US",
        "tz": "US/Pacific",
        "egress_ips": ["203.0.113.10"],
    }
    branch = nodes[uidmod.zia("acme", "loc", 1002)]
    assert branch.props == {
        "name": "branch-austin",
        "zia_id": "1002",
        "country": "US",
        "tz": "US/Central",
        "egress_ips": ["198.51.100.20"],
        "auth_required": True,
        "ssl_scan_enabled": False,
    }
    sub = nodes[uidmod.zia("acme", "loc", 1003)]
    assert sub.label == "ZiaLocation" and sub.props["name"] == "branch-austin-guest"


def test_part_of_chain():
    batch = _norm()
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("PART_OF", uidmod.zia("acme", "loc", 1003), uidmod.zia("acme", "loc", 1002)) in rels


def test_tunnel_encaps():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    gre = nodes[uidmod.zia("acme", "gre", 5001)]
    assert gre.label == "Tunnel" and gre.props["encap"] == "gre"
    assert gre.props["source_ip"] == "203.0.113.10"
    ipsec = nodes[uidmod.zia("acme", "ipsec", 7001)]
    assert ipsec.label == "Tunnel" and ipsec.props["encap"] == "ipsec"
    assert ipsec.props["vpn_type"] == "IP"
    # `endpoint` is set from `fqdn` only, never from `ipAddress`.
    assert ipsec.props.get("endpoint") is None
    assert gre.props["source_ip"] == "203.0.113.10"
    assert ipsec.props["source_ip"] == "198.51.100.20"


def test_gre_terminates_on_wiring_to_dcs():
    """A Tunnel's far end is TERMINATES_ON."""
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    primary = uidmod.zia("acme", "dc", "san-jose-ii")
    secondary = uidmod.zia("acme", "dc", "san-jose-iii")
    assert nodes[primary].label == "ZscalerDc"
    assert nodes[primary].props == {"name": "San Jose II", "vip": "104.129.194.38"}
    assert nodes[secondary].props["vip"] == "104.129.198.38"
    gre = uidmod.zia("acme", "gre", 5001)
    assert ("TERMINATES_ON", gre, primary) in rels
    assert ("TERMINATES_ON", gre, secondary) in rels
    assert not [r for r in rels if r[0] == "ENDPOINT" and r[1] == gre]


def test_an_ipsec_credential_gets_no_far_end_edge_to_its_own_local_address():
    """A VPN credential's `ipAddress` is the customer's IKE identity."""
    batch = _norm()
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    ipsec = uidmod.zia("acme", "ipsec", 7001)
    assert not [r for r in rels if r[0] == "TERMINATES_ON" and r[1] == ipsec]
    assert uidmod.ip("zia:acme", "198.51.100.20") not in {n.uid for n in batch.nodes}


def test_zscaler_dc_provided_by_provider():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    prov_uid = uidmod.provider("zscaler")
    assert nodes[prov_uid].label == "Provider"
    assert nodes[prov_uid].props == {"name": "zscaler"}
    dcs = [n for n in batch.nodes if n.label == "ZscalerDc"]
    assert dcs
    for dc in dcs:
        assert ("PROVIDED_BY", dc.uid, prov_uid) in rels


def test_location_uses_tunnel_per_schema_8():
    # (ZiaLocation)-[:USES]->(Tunnel)
    batch = _norm()
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    hq = uidmod.zia("acme", "loc", 1001)
    branch = uidmod.zia("acme", "loc", 1002)
    gre = uidmod.zia("acme", "gre", 5001)
    ipsec = uidmod.zia("acme", "ipsec", 7001)
    assert ("USES", hq, gre) in rels
    assert ("USES", branch, ipsec) in rels
    assert not [r for r in rels if r[0] == "EGRESSES_VIA"]


def test_location_group_nodes_dynamic_and_static():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    dynamic = nodes[uidmod.zia("acme", "locgrp", 43780169)]
    assert dynamic.label == "ZiaLocationGroup"
    assert dynamic.props["dynamic"] is True
    assert dynamic.props["name"] == "Corp Dynamic Traffic Group"
    assert "profiles" in dynamic.props["dynamic_criteria"]
    static = nodes[uidmod.zia("acme", "locgrp", 43780170)]
    assert static.props["dynamic"] is False
    assert "dynamic_criteria" not in static.props
    # Both group types list their current members.
    assert ("MEMBER_OF", uidmod.zia("acme", "loc", 1002), static.uid) in rels
    assert ("MEMBER_OF", uidmod.zia("acme", "loc", 1001), dynamic.uid) in rels


def test_forwarding_rule_keeps_the_zpa_segment_ids_and_draws_no_cross_source_edge():
    batch = _norm()
    nodes = {n.uid: n for n in batch.nodes}
    zpa_rule = nodes[uidmod.zia("acme", "fwdrule", 600001)]
    assert zpa_rule.label == "ZiaForwardingRule"
    assert zpa_rule.props == {
        "name": "crm-to-zpa",
        "order": 1,
        "forward_method": "zpa",
        "enabled": True,
        "zpa_app_segment_ids": ["2001"],  # the deleted reference is dropped
    }
    direct = nodes[uidmod.zia("acme", "fwdrule", 600002)].props
    assert direct["enabled"] is False and "zpa_app_segment_ids" not in direct
    # FORWARDS_TO is the reasoner's (zia-forwarding-to-zpa-segment), not the collector's.
    assert not [r for r in batch.rels if r.rel_type == "FORWARDS_TO"]


def test_sublocations_are_read_only_for_a_location_that_has_one(monkeypatch):
    from hst.collectors import zia
    from hst.core import Settings

    transport, calls = make_mock()
    monkeypatch.setattr(zia, "_transport", lambda config: transport)
    raw = zia.ZiaCollector(_cfg(), Settings(_env_file=None)).fetch()
    paths = [p for p, _ in calls["paths"]]
    assert "/zia/api/v1/locations/1002/sublocations" in paths
    assert "/zia/api/v1/locations/1001/sublocations" not in paths
    assert raw["sublocations"] == [SUBLOCATION]


def test_a_refused_lite_list_falls_back_to_one_sublocation_call_per_location(monkeypatch):
    from hst.collectors import zia
    from hst.core import Settings

    transport, calls = make_mock()

    def no_lite(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/zia/api/v1/locations/lite":
            return httpx.Response(403)
        return transport.handle_request(request)

    monkeypatch.setattr(zia, "_transport", lambda config: httpx.MockTransport(no_lite))
    raw = zia.ZiaCollector(_cfg(), Settings(_env_file=None)).fetch()
    paths = [p for p, _ in calls["paths"]]
    assert {"/zia/api/v1/locations/1001/sublocations", "/zia/api/v1/locations/1002/sublocations"} <= set(
        paths
    )
    assert raw["sublocations"] == [SUBLOCATION]


def test_an_optional_section_that_is_missing_keeps_the_rest_of_the_collection(monkeypatch):
    from hst.collectors import zia
    from hst.core import Settings

    transport, _calls = make_mock()

    def no_rules(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/zia/api/v1/forwardingRules":
            return httpx.Response(404)
        return transport.handle_request(request)

    monkeypatch.setattr(zia, "_transport", lambda config: httpx.MockTransport(no_rules))
    collector = zia.ZiaCollector(_cfg(), Settings(_env_file=None))
    batch = collector.normalize(collector.fetch())
    assert batch.sections["forwarding_rules"].status == "unsupported"
    assert batch.sections["location_groups"].status == "ok"
    assert any(n.label == "Tunnel" for n in batch.nodes)


def test_location_sites_bind_a_location_and_its_sublocation_to_a_site():
    batch = normalize_zia(RAW, tenant="acme", location_sites={"1002": "aus01", "hq-sunnyvale": "sjc01"})
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    nodes = {n.uid: n for n in batch.nodes}
    assert ("REPRESENTS", uidmod.zia("acme", "loc", 1001), uidmod.site("sjc01")) in rels  # by name
    assert ("REPRESENTS", uidmod.zia("acme", "loc", 1002), uidmod.site("aus01")) in rels  # by id
    # the sublocation has no line of its own and takes its parent's site
    assert ("REPRESENTS", uidmod.zia("acme", "loc", 1003), uidmod.site("aus01")) in rels
    assert nodes[uidmod.site("aus01")].props == {"code": "aus01"}


def test_a_location_without_a_line_stays_unplaced():
    batch = normalize_zia(RAW, tenant="acme")
    assert not [r for r in batch.rels if r.rel_type == "REPRESENTS"]


def test_a_bad_location_sites_line_is_refused_at_save_time():
    import pytest

    with pytest.raises(ValueError, match="location_sites line 1"):
        _cfg(location_sites="only-one-field")


def test_each_declared_section_label_is_written_by_that_section_alone():
    from hst.collectors import zia

    declared = zia.ZiaCollector.SECTION_LABELS
    assert set(declared) == set(zia.OPTIONAL_SECTIONS)
    full = {n.label for n in normalize_zia(RAW, tenant="acme").nodes}
    for section, labels in declared.items():
        without = {n.label for n in normalize_zia({**RAW, section: []}, tenant="acme").nodes}
        assert not without & set(labels), section
        for label in labels:
            assert label in full, label


def test_a_stopped_run_ends_the_zia_fetch_before_its_next_request(monkeypatch):
    import functools
    import threading

    import pytest

    from hst.collectors import zia, zscaler_auth
    from hst.collectors.base import CollectionStopped
    from hst.core import Settings

    transport, calls = make_mock()
    collector = zia.ZiaCollector(_cfg(), Settings(_env_file=None))
    collector.stop = threading.Event()

    def handler(request):
        response = transport.handle_request(request)
        if request.url.path == "/zia/api/v1/locations" and request.url.params.get("page") == "1":
            collector.stop.set()
        return response

    monkeypatch.setattr(zia, "_transport", lambda config: httpx.MockTransport(handler))
    monkeypatch.setattr(
        zia, "ZscalerSession", functools.partial(zscaler_auth.ZscalerSession, sleep=lambda s: None)
    )
    with pytest.raises(CollectionStopped):
        collector.fetch()
    assert len(calls["paths"]) == 1


def _zia_fetch_with(monkeypatch, handler_for):
    import functools

    from hst.collectors import zia, zscaler_auth
    from hst.core import Settings

    transport, _calls = make_mock()

    def handler(request):
        answer = handler_for(request)
        return answer if answer is not None else transport.handle_request(request)

    monkeypatch.setattr(zia, "_transport", lambda config: httpx.MockTransport(handler))
    monkeypatch.setattr(
        zia, "ZscalerSession", functools.partial(zscaler_auth.ZscalerSession, sleep=lambda s: None)
    )
    collector = zia.ZiaCollector(_cfg(), Settings(_env_file=None))
    return collector


def test_a_timeout_in_an_optional_read_keeps_the_rest_of_the_collection(monkeypatch):
    def handler_for(request):
        if request.url.path == "/zia/api/v1/forwardingRules":
            raise httpx.ReadTimeout("timed out", request=request)
        return None

    collector = _zia_fetch_with(monkeypatch, handler_for)
    raw = collector.fetch()
    assert raw["locations"] and raw["forwarding_rules"] == []
    outcome = collector.normalize(raw).sections["forwarding_rules"]
    assert outcome.status == "failed"
    assert outcome.detail == "ReadTimeout for /zia/api/v1/forwardingRules"


def test_the_429_limit_in_an_optional_read_still_fails_the_fetch(monkeypatch):
    import pytest

    def handler_for(request):
        if request.url.path == "/zia/api/v1/forwardingRules":
            return httpx.Response(429, headers={"Retry-After": "0"})
        return None

    collector = _zia_fetch_with(monkeypatch, handler_for)
    with pytest.raises(RuntimeError, match="rate-limited"):
        collector.fetch()


def _sub_calls(calls, parent):
    return [
        params for path, params in calls["paths"] if path == f"/zia/api/v1/locations/{parent}/sublocations"
    ]


def test_a_parent_with_more_sublocations_than_one_answer_holds_is_read_page_by_page(monkeypatch):
    from hst.collectors import zia
    from hst.core import Settings

    subs = [{**SUBLOCATION, "id": 5000 + i, "name": f"sub-{i}"} for i in range(150)]
    transport, calls = make_mock()

    def handler(request):
        path, params = request.url.path, dict(request.url.params)
        if path == "/zia/api/v1/locations/lite":
            calls["paths"].append((path, params))
            first = params.get("page") == "1"
            return httpx.Response(200, json=[LOCATION_HQ, LOCATION_BRANCH, *subs] if first else [])
        if path == "/zia/api/v1/locations/1002/sublocations":
            calls["paths"].append((path, params))
            if not params:
                return httpx.Response(200, json=subs[:100])
            return httpx.Response(200, json=subs if params.get("page") == "1" else [])
        return transport.handle_request(request)

    monkeypatch.setattr(zia, "_transport", lambda config: httpx.MockTransport(handler))
    raw = zia.ZiaCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert len({s["id"] for s in raw["sublocations"]}) == 150
    assert _sub_calls(calls, 1002) == [{}, {"page": "1", "pageSize": "500"}, {"page": "2", "pageSize": "500"}]


def test_a_parent_whose_answer_holds_every_sublocation_is_read_once(monkeypatch):
    from hst.collectors import zia
    from hst.core import Settings

    transport, calls = make_mock()
    monkeypatch.setattr(zia, "_transport", lambda config: transport)
    zia.ZiaCollector(_cfg(), Settings(_env_file=None)).fetch()
    assert _sub_calls(calls, 1002) == [{}]


def test_a_refused_lite_list_reads_each_location_page_by_page(monkeypatch):
    from hst.collectors import zia
    from hst.core import Settings

    transport, calls = make_mock()

    def handler(request):
        if request.url.path == "/zia/api/v1/locations/lite":
            return httpx.Response(403, json={})
        return transport.handle_request(request)

    monkeypatch.setattr(zia, "_transport", lambda config: httpx.MockTransport(handler))
    raw = zia.ZiaCollector(_cfg(), Settings(_env_file=None)).fetch()
    for parent in (1001, 1002):
        assert all("page" in p and "pageSize" in p for p in _sub_calls(calls, parent)), parent
        assert _sub_calls(calls, parent)
    assert raw["sublocations"] == [SUBLOCATION]


def test_a_token_failure_inside_an_optional_read_fails_the_fetch(monkeypatch):
    import functools

    import pytest

    from hst.collectors import zia, zscaler_auth
    from hst.core import Settings

    transport, _calls = make_mock()
    clock = {"now": 0.0}
    tokens = {"n": 0}

    def handler(request):
        if request.url.host == "acme.zslogin.net":
            tokens["n"] += 1
            if tokens["n"] == 1:
                return httpx.Response(200, json={"access_token": "tok-1", "expires_in": 100})
            return httpx.Response(503, json={})
        response = transport.handle_request(request)
        if request.url.path == "/zia/api/v1/vpnCredentials":
            clock["now"] += 80
        return response

    monkeypatch.setattr(zia, "_transport", lambda config: httpx.MockTransport(handler))
    monkeypatch.setattr(
        zia,
        "ZscalerSession",
        functools.partial(zscaler_auth.ZscalerSession, sleep=lambda s: None, clock=lambda: clock["now"]),
    )
    with pytest.raises(zscaler_auth.ZscalerTokenError):
        zia.ZiaCollector(_cfg(), Settings(_env_file=None)).fetch()


# --- tunnel far ends: role and VIP ---------------------------------------------------------------


def test_gre_terminates_on_carries_the_role_and_the_vip():
    same_dc = {
        **GRE_TUNNEL,
        "secondaryDestVip": {"id": 102, "virtualIp": "104.129.194.40", "datacenter": "San Jose II"},
    }
    batch = normalize_zia({**RAW, "gre_tunnels": [same_dc]}, tenant="acme")
    ends = sorted(
        (r.key.get("role"), r.props.get("vip")) for r in batch.rels if r.rel_type == "TERMINATES_ON"
    )
    assert ends == [("primary", "104.129.194.38"), ("secondary", "104.129.194.40")]


def test_zscaler_dc_vip_is_the_lowest_vip_whatever_the_tunnel_order():
    a = {
        **GRE_TUNNEL,
        "id": 1,
        "primaryDestVip": {"virtualIp": "104.129.194.40", "datacenter": "X"},
        "secondaryDestVip": None,
    }
    b = {
        **GRE_TUNNEL,
        "id": 2,
        "primaryDestVip": {"virtualIp": "104.129.194.9", "datacenter": "X"},
        "secondaryDestVip": None,
    }
    for order in ([a, b], [b, a]):
        batch = normalize_zia({**RAW, "gre_tunnels": order}, tenant="acme")
        [dc] = [n for n in batch.nodes if n.label == "ZscalerDc"]
        assert dc.props["vip"] == "104.129.194.9"


def test_a_private_service_edge_vip_is_flagged():
    pse = {
        **GRE_TUNNEL,
        "primaryDestVip": {"virtualIp": "10.9.0.1", "datacenter": "PSE-1", "privateServiceEdge": True},
        "secondaryDestVip": None,
    }
    batch = normalize_zia({**RAW, "gre_tunnels": [pse]}, tenant="acme")
    [dc] = [n for n in batch.nodes if n.label == "ZscalerDc"]
    assert dc.props["private_service_edge"] is True
    assert [r for r in batch.rels if r.rel_type == "PROVIDED_BY" and r.start_uid == dc.uid]


def test_a_ufqdn_credential_writes_ike_id_and_no_endpoint():
    cred = {**VPN_CREDENTIAL, "type": "UFQDN", "fqdn": "branch@acme.example"}
    batch = normalize_zia({**RAW, "vpn_credentials": [cred]}, tenant="acme")
    [tunnel] = [n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "ipsec"]
    assert tunnel.props["ike_id"] == "branch@acme.example" and "endpoint" not in tunnel.props


# --- location options, sublocation ranges and top-level tunnel joins -----------------------------


def _loc_props(batch, loc_id):
    return {n.uid: n.props for n in batch.nodes}[uidmod.zia("acme", "loc", loc_id)]


def test_location_options_that_take_effect_are_written():
    options = {
        "profile": "CORPORATE",
        "ofwEnabled": True,
        "ipsControl": True,
        "xffForwardEnabled": False,
        "surrogateIP": True,
    }
    batch = normalize_zia({**RAW, "locations": [{**LOCATION_HQ, **options}, LOCATION_BRANCH]}, tenant="acme")
    hq = _loc_props(batch, LOCATION_HQ["id"])
    assert (
        hq["profile"],
        hq["ofw_enabled"],
        hq["ips_control"],
        hq["xff_forward_enabled"],
        hq["surrogate_ip"],
    ) == (
        "CORPORATE",
        True,
        True,
        False,
        True,
    )
    branch = _loc_props(batch, LOCATION_BRANCH["id"])
    assert not {"profile", "ofw_enabled", "ips_control", "xff_forward_enabled", "surrogate_ip"} & set(branch)


def test_a_sublocation_writes_address_ranges_and_no_egress_ips():
    sub = {**SUBLOCATION, "ipAddresses": ["10.1.0.0/24", "10.2.0.1-10.2.0.9"]}
    batch = normalize_zia({**RAW, "sublocations": [sub]}, tenant="acme")
    props = _loc_props(batch, SUBLOCATION["id"])
    assert props["address_ranges"] == ["10.1.0.0/24", "10.2.0.1-10.2.0.9"] and "egress_ips" not in props


def test_the_default_other_sublocation_is_flagged():
    batch = normalize_zia({**RAW, "sublocations": [{**SUBLOCATION, "otherSubLocation": True}]}, tenant="acme")
    assert _loc_props(batch, SUBLOCATION["id"])["other_sublocation"] is True


def _uses(batch):
    return {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "USES"}


def test_a_sublocation_that_lists_the_parent_egress_ip_leaves_the_gre_tunnel_on_the_parent():
    sub = {**SUBLOCATION, "parentId": LOCATION_HQ["id"], "ipAddresses": [GRE_TUNNEL["sourceIp"]]}
    batch = normalize_zia({**RAW, "sublocations": [sub]}, tenant="acme")
    tunnel = uidmod.zia("acme", "gre", GRE_TUNNEL["id"])
    assert (uidmod.zia("acme", "loc", LOCATION_HQ["id"]), tunnel) in _uses(batch)
    assert not [u for u in _uses(batch) if u[0] == uidmod.zia("acme", "loc", SUBLOCATION["id"])]


def test_a_gre_tunnel_whose_source_ip_only_a_sublocation_lists_joins_the_parent():
    gre = {**GRE_TUNNEL, "sourceIp": "192.0.2.77"}
    sub = {**SUBLOCATION, "ipAddresses": ["192.0.2.77"]}
    batch = normalize_zia({**RAW, "gre_tunnels": [gre], "sublocations": [sub]}, tenant="acme")
    parent = uidmod.zia("acme", "loc", SUBLOCATION["parentId"])
    assert (parent, uidmod.zia("acme", "gre", gre["id"])) in _uses(batch)


def test_a_vpn_credential_that_names_a_sublocation_joins_its_parent():
    cred = {**VPN_CREDENTIAL, "location": {"id": SUBLOCATION["id"], "name": SUBLOCATION["name"]}}
    batch = normalize_zia({**RAW, "vpn_credentials": [cred]}, tenant="acme")
    parent = uidmod.zia("acme", "loc", SUBLOCATION["parentId"])
    assert (parent, uidmod.zia("acme", "ipsec", cred["id"])) in _uses(batch)


def test_a_location_sites_edit_changes_the_change_hash():
    from hst.collectors import zia
    from hst.collectors.base import raw_sha
    from hst.core import Settings

    one = zia.ZiaCollector(_cfg(location_sites="1001, vie01"), Settings(_env_file=None))
    two = zia.ZiaCollector(_cfg(location_sites="1001, gra01"), Settings(_env_file=None))
    assert raw_sha(one, RAW) != raw_sha(two, RAW)


# --- location_sites lines bind one location or nothing -----------------------------------------


def test_a_name_line_that_two_locations_carry_binds_none():
    graz_a = {**SUBLOCATION, "id": 2001, "name": "Graz", "parentId": LOCATION_HQ["id"]}
    graz_b = {**SUBLOCATION, "id": 2002, "name": "Graz", "parentId": LOCATION_BRANCH["id"]}
    batch = normalize_zia(
        {**RAW, "sublocations": [graz_a, graz_b]}, tenant="acme", location_sites={"Graz": "vie01"}
    )
    represents = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "REPRESENTS"}
    assert not [r for r in represents if r[1] == uidmod.site("vie01")]
    assert batch.warnings == [
        "ZIA tenant acme: location_sites line 'Graz' names 2 locations (ids 2001, 2002); "
        "it binds none of them"
    ]


def test_a_line_that_matches_no_location_is_a_warning():
    batch = normalize_zia(RAW, tenant="acme", location_sites={"no-such-place": "gra01"})
    assert not [n for n in batch.nodes if n.label == "Site" and n.props.get("code") == "gra01"]
    assert batch.warnings == ["ZIA tenant acme: location_sites line 'no-such-place' matches no location"]


def test_an_id_line_binds_a_sublocation_whose_name_repeats():
    graz_a = {**SUBLOCATION, "id": 2001, "name": "Graz", "parentId": LOCATION_HQ["id"]}
    graz_b = {**SUBLOCATION, "id": 2002, "name": "Graz", "parentId": LOCATION_BRANCH["id"]}
    batch = normalize_zia(
        {**RAW, "sublocations": [graz_a, graz_b]}, tenant="acme", location_sites={"2001": "gra01"}
    )
    represents = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "REPRESENTS"}
    assert (uidmod.zia("acme", "loc", 2001), uidmod.site("gra01")) in represents
    assert not batch.warnings


# --- ZIA forwarding into ZPA: ECZPA lists and the ZPA gateway ----------------------------------


def _rule_props(batch, rule_id):
    return {n.uid: n.props for n in batch.nodes}[uidmod.zia("acme", "fwdrule", rule_id)]


def test_an_eczpa_rule_keeps_its_segment_and_segment_group_ids():
    rule = {
        **FORWARDING_RULE_ZPA,
        "zpaAppSegments": [],
        "zpaApplicationSegments": [{"zpaId": 2002}, {"zpaId": 2002}, {"zpaId": 2999, "deleted": True}],
        "zpaApplicationSegmentGroups": [{"zpaId": 3001}],
    }
    props = _rule_props(normalize_zia({**RAW, "forwarding_rules": [rule]}, tenant="acme"), rule["id"])
    assert props["zpa_app_segment_ids"] == ["2002"] and props["zpa_segment_group_ids"] == ["3001"]


def test_a_rule_gateway_resolves_to_the_server_group_external_id():
    rule = {**FORWARDING_RULE_ZPA, "zpaGateway": {"id": 77, "name": "gw-eu"}}
    gateways = [{"id": 77, "name": "gw-eu", "zpaServerGroup": {"externalId": "4001", "name": "srv"}}]
    batch = normalize_zia({**RAW, "forwarding_rules": [rule], "zpa_gateways": gateways}, tenant="acme")
    props = _rule_props(batch, rule["id"])
    assert (props["zpa_gateway_id"], props["zpa_gateway"], props["zpa_server_group_id"]) == (
        "77",
        "gw-eu",
        "4001",
    )


def _gateway_fetch(monkeypatch, rules, gateway_status=200):
    import functools

    from hst.collectors import zia, zscaler_auth
    from hst.core import Settings

    transport, calls = make_mock()

    def handler(request):
        if request.url.path == "/zia/api/v1/forwardingRules":
            calls["paths"].append((request.url.path, dict(request.url.params)))
            return httpx.Response(200, json=rules if request.url.params.get("page") == "1" else [])
        if request.url.path == "/zia/api/v1/zpaGateways":
            calls["paths"].append((request.url.path, dict(request.url.params)))
            if gateway_status != 200:
                return httpx.Response(gateway_status, json={})
            first = request.url.params.get("page") == "1"
            return httpx.Response(
                200, json=[{"id": 77, "zpaServerGroup": {"externalId": "4001"}}] if first else []
            )
        return transport.handle_request(request)

    monkeypatch.setattr(zia, "_transport", lambda config: httpx.MockTransport(handler))
    monkeypatch.setattr(
        zia, "ZscalerSession", functools.partial(zscaler_auth.ZscalerSession, sleep=lambda s: None)
    )
    collector = zia.ZiaCollector(_cfg(), Settings(_env_file=None))
    raw = collector.fetch()
    return raw, collector.normalize(raw), [p for p, _ in calls["paths"]]


def test_zpa_gateways_are_read_only_when_a_rule_names_one(monkeypatch):
    raw, _batch, paths = _gateway_fetch(monkeypatch, [FORWARDING_RULE_ZPA])
    assert "/zia/api/v1/zpaGateways" not in paths and "zpa_gateways" not in raw
    rule = {**FORWARDING_RULE_ZPA, "zpaGateway": {"id": 77, "name": "gw-eu"}}
    raw, batch, paths = _gateway_fetch(monkeypatch, [rule])
    assert "/zia/api/v1/zpaGateways" in paths and raw["zpa_gateways"]
    assert _rule_props(batch, rule["id"])["zpa_server_group_id"] == "4001"


def test_a_refused_zpa_gateway_read_keeps_the_forwarding_rules(monkeypatch):
    rule = {**FORWARDING_RULE_ZPA, "zpaGateway": {"id": 77, "name": "gw-eu"}}
    _raw, batch, _paths = _gateway_fetch(monkeypatch, [rule], gateway_status=403)
    assert batch.sections["zpa_gateways"].status == "unauthorized"
    props = _rule_props(batch, rule["id"])
    assert "zpa_server_group_id" not in props and props["zpa_gateway_id"] == "77"


# --- forwarding rule scope and criteria -----------------------------------------------------------


def test_a_forwarding_rule_applies_to_its_collected_locations_and_groups():
    rule = {
        **FORWARDING_RULE_ZPA,
        "locations": [{"id": LOCATION_HQ["id"]}, {"id": 999999}],
        "locationGroups": [{"id": LOCATION_GROUP_DYNAMIC["id"]}],
    }
    batch = normalize_zia({**RAW, "forwarding_rules": [rule]}, tenant="acme")
    ruid = uidmod.zia("acme", "fwdrule", rule["id"])
    applies = {r.end_uid for r in batch.rels if r.rel_type == "APPLIES_TO" and r.start_uid == ruid}
    assert applies == {
        uidmod.zia("acme", "loc", LOCATION_HQ["id"]),
        uidmod.zia("acme", "locgrp", LOCATION_GROUP_DYNAMIC["id"]),
    }
    props = _rule_props(batch, rule["id"])
    assert props["location_ids"] == [str(LOCATION_HQ["id"]), "999999"]


def test_forwarding_rule_criteria_are_kept_and_other_criteria_are_named():
    rule = {
        **FORWARDING_RULE_ZPA,
        "type": "FORWARDING",
        "srcIps": ["10.0.0.0/8"],
        "destAddresses": ["203.0.113.0/24"],
        "departments": [{"id": 1}],
        "nwServices": [{"id": 2}],
        "users": [],
    }
    props = _rule_props(normalize_zia({**RAW, "forwarding_rules": [rule]}, tenant="acme"), rule["id"])
    assert (props["rule_type"], props["src_ips"], props["dest_addresses"]) == (
        "FORWARDING",
        ["10.0.0.0/8"],
        ["203.0.113.0/24"],
    )
    assert props["other_criteria"] == ["departments", "nwServices"]


# --- OverlayConnection (schema v0.30.0) ----------------------------------------


def _connections(batch) -> dict[str, dict]:
    return {n.uid: n.props for n in batch.nodes if n.label == "OverlayConnection"}


def _between(batch, conn: str) -> dict[str, tuple[str, str, dict]]:
    return {
        r.props["end"]: (r.end_label, r.end_uid, r.props)
        for r in batch.rels
        if r.rel_type == "BETWEEN" and r.start_uid == conn
    }


def test_a_gre_tunnel_writes_one_connection_per_location_and_data_center():
    """The tunnel's primary and secondary VIPs are in two data centers: one
    connection from the location to each, each realized by the tunnel. The
    data center end is the gateway and the end that reports it."""
    batch = _norm()
    hq = uidmod.zia("acme", "loc", 1001)
    tunnel = uidmod.zia("acme", "gre", 5001)
    conns = _connections(batch)
    for dc_name in ("San Jose II", "San Jose III"):
        dc = uidmod.zia("acme", "dc", uidmod.slug(dc_name))
        conn = uidmod.overlay_connection("gre", hq, dc)
        props = conns[conn]
        assert props["kind"] == "tunnel" and props["technology"] == "gre"
        assert props["name"] == f"hq-sunnyvale to {dc_name}"
        ends = _between(batch, conn)
        # the data center uid sorts before the location uid: it is end a
        assert ends["a"][:2] == ("ZscalerDc", dc) and ends["a"][2]["role"] == "gateway"
        assert ends["b"][:2] == ("ZiaLocation", hq) and ends["b"][2]["role"] == "edge"
        assert props["observed_from"] == ["a"]
        realized = {r.end_uid for r in batch.rels if r.rel_type == "REALIZED_BY" and r.start_uid == conn}
        assert realized == {tunnel}


def test_a_location_with_two_tunnels_to_one_data_center_has_one_connection():
    second = {**GRE_TUNNEL, "id": 5002, "secondaryDestVip": None}
    batch = normalize_zia({**RAW, "gre_tunnels": [GRE_TUNNEL, second]}, tenant="acme")
    hq = uidmod.zia("acme", "loc", 1001)
    dc = uidmod.zia("acme", "dc", uidmod.slug("San Jose II"))
    conn = uidmod.overlay_connection("gre", hq, dc)
    realized = {r.end_uid for r in batch.rels if r.rel_type == "REALIZED_BY" and r.start_uid == conn}
    assert realized == {uidmod.zia("acme", "gre", 5001), uidmod.zia("acme", "gre", 5002)}
    names = [props["name"] for props in _connections(batch).values()]
    assert names.count("hq-sunnyvale to San Jose II") == 1


def test_an_ipsec_credential_has_a_connection_with_the_location_end_only():
    """A VPN credential names no data center: the connection is keyed by the
    location and the credential's tunnel, and names the IKE identity."""
    batch = _norm()
    branch = uidmod.zia("acme", "loc", 1002)
    tunnel = uidmod.zia("acme", "ipsec", 7001)
    conn = uidmod.overlay_connection("ipsec", branch, tunnel)
    props = _connections(batch)[conn]
    assert props["technology"] == "ipsec"
    assert props["name"] == "branch-austin 198.51.100.20 to Zscaler"
    ends = _between(batch, conn)
    assert next(iter(ends.values()))[:2] == ("ZiaLocation", branch)
    assert len(ends) == 1
