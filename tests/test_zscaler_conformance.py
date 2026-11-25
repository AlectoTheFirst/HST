"""Code shared by the two Zscaler collectors (`zscaler_auth.py`'s OAuth session,
`http.py`'s `get_paged`)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

import test_zia as tzia
import test_zpa as tzpa
from hst.collectors import zia, zpa
from hst.collectors.auth import OAuthClientCredentials
from hst.core import Settings
from hst.core import uid as uidmod


@dataclass(frozen=True)
class Vendor:
    id: str
    module: Any
    collector_cls: type
    config_cls: type
    cfg: Callable[[], Any]  # the vendor test module's own _cfg()
    make_mock: Callable[[], tuple]  # -> (transport, calls)
    norm: Callable[[], Any]  # the vendor test module's own _norm()
    scope: str
    probe_substring: str
    raw_expect: dict  # fetch()'s return keys -> expected value
    expect_paths: list  # (path, params) that must appear in calls["paths"]
    uid_fn: Callable
    uid_cases: list  # [(org, kind, obj_id, expected_uid), ...]
    session_kwargs: dict  # extra ConfigModel kwargs test_session needs (e.g. customer_id)


VENDORS = [
    Vendor(
        "zia",
        zia,
        zia.ZiaCollector,
        zia.ZiaConfig,
        tzia._cfg,
        tzia.make_mock,
        tzia._norm,
        "zia:acme",
        "2 location(s)",
        {
            "locations": [tzia.LOCATION_HQ, tzia.LOCATION_BRANCH],
            "sublocations": [tzia.SUBLOCATION],
            "gre_tunnels": [tzia.GRE_TUNNEL],
            "vpn_credentials": [tzia.VPN_CREDENTIAL],
            "location_groups": [tzia.LOCATION_GROUP_DYNAMIC, tzia.LOCATION_GROUP_STATIC],
            "forwarding_rules": [tzia.FORWARDING_RULE_ZPA, tzia.FORWARDING_RULE_DIRECT],
        },
        [
            ("/zia/api/v1/locations", {"page": "1", "pageSize": "500"}),
            ("/zia/api/v1/locations/lite", {"includeSubLocations": "true", "page": "1", "pageSize": "500"}),
            ("/zia/api/v1/locations/1002/sublocations", {}),
            ("/zia/api/v1/greTunnels", {"page": "1", "pageSize": "500"}),
            ("/zia/api/v1/vpnCredentials", {"page": "1", "pageSize": "500"}),
            ("/zia/api/v1/locations/groups", {"page": "1", "pageSize": "500"}),
            ("/zia/api/v1/forwardingRules", {"page": "1", "pageSize": "500"}),
        ],
        uidmod.zia,
        [
            ("acme", "loc", 1001, "zia:acme:loc:1001"),
            ("Acme Corp", "gre", 5001, "zia:acme-corp:gre:5001"),
        ],
        {},
    ),
    Vendor(
        "zpa",
        zpa,
        zpa.ZpaCollector,
        zpa.ZpaConfig,
        tzpa._cfg,
        tzpa.make_mock,
        tzpa._norm,
        "zpa:acme",
        "1 segment group(s)",
        {
            "app_segments": [tzpa.APP_SEGMENT_CRM, tzpa.APP_SEGMENT_ERP],
            "segment_groups": [tzpa.SEGMENT_GROUP],
            "server_groups": [tzpa.SERVER_GROUP, tzpa.SERVER_GROUP_STATIC],
            "connector_groups": [tzpa.APP_CONNECTOR_GROUP],
            "connectors": [tzpa.CONNECTOR],
            "service_edges": [tzpa.SERVICE_EDGE],
            "access_rules": [
                tzpa.ACCESS_RULE_ALLOW,
                tzpa.ACCESS_RULE_DENY,
                tzpa.ACCESS_RULE_GROUP_SCOPED,
                tzpa.ACCESS_RULE_NO_IDP,
            ],
            "client_forwarding_rules": [tzpa.CLIENT_FORWARDING_RULE],
            # fetch() removes the enrollment secret before it returns
            "provisioning_keys": [{k: v for k, v in tzpa.PROVISIONING_KEY.items() if k != "provisioningKey"}],
            "scim_groups": tzpa.SCIM_GROUPS,
        },
        [
            ("/zpa/mgmtconfig/v1/admin/customers/cust-1/application", {"page": "1", "pagesize": "500"}),
            ("/zpa/mgmtconfig/v1/admin/customers/cust-1/segmentGroup", {"page": "1", "pagesize": "500"}),
            ("/zpa/mgmtconfig/v1/admin/customers/cust-1/serverGroup", {"page": "1", "pagesize": "500"}),
            (
                "/zpa/mgmtconfig/v1/admin/customers/cust-1/appConnectorGroup",
                {"page": "1", "pagesize": "500"},
            ),
            ("/zpa/mgmtconfig/v1/admin/customers/cust-1/connector", {"page": "1", "pagesize": "500"}),
            ("/zpa/mgmtconfig/v1/admin/customers/cust-1/serviceEdge", {"page": "1", "pagesize": "500"}),
            (
                "/zpa/mgmtconfig/v1/admin/customers/cust-1/policySet/rules/policyType/ACCESS_POLICY",
                {"page": "1", "pagesize": "500"},
            ),
            (
                "/zpa/mgmtconfig/v1/admin/customers/cust-1/policySet/rules/policyType/"
                "CLIENT_FORWARDING_POLICY",
                {"page": "1", "pagesize": "500"},
            ),
            (
                "/zpa/mgmtconfig/v1/admin/customers/cust-1/associationType/CONNECTOR_GRP/provisioningKey",
                {"page": "1", "pagesize": "500"},
            ),
            (
                "/zpa/mgmtconfig/v1/admin/customers/cust-1/associationType/SERVICE_EDGE_GRP/provisioningKey",
                {"page": "1", "pagesize": "500"},
            ),
            ("/zpa/userconfig/v1/customers/cust-1/scimgroup/idpId/idp-1", {"page": "1", "pagesize": "500"}),
        ],
        uidmod.zpa,
        [
            ("acme", "seg", "2001", "zpa:acme:seg:2001"),
            ("Acme Corp", "rule", "9001", "zpa:acme-corp:rule:9001"),
        ],
        {"customer_id": "cust-1"},
    ),
]


@pytest.mark.parametrize("v", VENDORS, ids=lambda v: v.id)
def test_scope(v):
    assert v.collector_cls(v.cfg(), Settings(_env_file=None)).scope == v.scope


@pytest.mark.parametrize("v", VENDORS, ids=lambda v: v.id)
def test_probe(v, monkeypatch):
    transport, calls = v.make_mock()
    monkeypatch.setattr(v.module, "_transport", lambda config: transport)
    out = v.collector_cls(v.cfg(), Settings(_env_file=None)).probe()
    assert calls["token"] == 1
    assert v.probe_substring in out
    assert "acme" in out


@pytest.mark.parametrize("v", VENDORS, ids=lambda v: v.id)
def test_fetch_paths_and_pagination_params(v, monkeypatch):
    transport, calls = v.make_mock()
    monkeypatch.setattr(v.module, "_transport", lambda config: transport)
    raw = v.collector_cls(v.cfg(), Settings(_env_file=None)).fetch()

    for key, expected in v.raw_expect.items():
        assert raw[key] == expected
    for path in v.expect_paths:
        assert path in calls["paths"]


@pytest.mark.parametrize("v", VENDORS, ids=lambda v: v.id)
def test_uid_construction_is_symmetric(v):
    for org, kind, obj_id, expected in v.uid_cases:
        assert v.uid_fn(org, kind, obj_id) == expected


@pytest.mark.parametrize("v", VENDORS, ids=lambda v: v.id)
def test_batch_coherence_no_dangling(v):
    batch = v.norm()
    node_uids = {n.uid for n in batch.nodes}
    dangling = [
        (r.rel_type, r.start_uid, r.end_uid)
        for r in batch.rels
        if r.start_uid not in node_uids or r.end_uid not in node_uids
    ]
    assert not dangling, dangling
    assert batch.source == v.id and batch.scope == v.scope


@pytest.mark.parametrize("v", VENDORS, ids=lambda v: v.id)
def test_session_is_built_from_the_auth_model(v, monkeypatch):
    seen = {}
    monkeypatch.setattr(
        v.module,
        "ZscalerSession",
        lambda vv, cid, secret, transport=None: (
            seen.update(vanity=vv, client_id=cid, secret=secret) or object()
        ),
    )
    v.collector_cls(
        v.config_cls(
            vanity_domain="acme",
            tenant="t1",
            auth=OAuthClientCredentials(client_id="id", client_secret="sec"),
            **v.session_kwargs,
        ),
        None,
    )._session()
    assert seen == {"vanity": "acme", "client_id": "id", "secret": "sec"}
