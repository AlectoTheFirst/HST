"""The VeloCloud collector against the shapes the captured Portal responses
hold:

- `getEnterpriseEdges` answers a superset of the APIv2 `EdgeResource`: the
  numeric `id`, `isHub`, `site`, `links` and a `configuration` block that names
  every module of the operator profile and of the enterprise profile with a
  `version` stamp, an `isEdgeSpecific` flag and an `edgeSpecificData` delta. No
  listing module carries a body;
- `getEnterpriseConfigurations` answers the profile bodies, each module wrapping
  its body in `data`;
- `getEdgeConfigurationModules` answers an object keyed by module name, and it is
  the only source of `WAN` and `controlPlane`;
- `getEnterpriseRouteTable` answers the Overlay Flow Control table, keyed
  `cidr:segmentId` with `preferredExits` and `eligableExits`;
- `bgpSessions` answers `BgpSessionResource` with a linked `edge`.
"""

from __future__ import annotations

import json

import httpx

from hst.collectors.auth import ApiKeyCredential
from hst.collectors.velocloud import (
    BGP_SESSION_FILTER,
    PORTAL_READ_PATHS,
    RIB_SCOPE_KEY,
    VeloCloudCollector,
    VeloCloudConfig,
    bgp_session_rows,
    normalize_velocloud,
    rib_rows,
)
from hst.core import uid
from hst.core.config import Settings

ENT = "ent-1"
BASE = "/api/sdwan/v2"
ENT_ID = 1
# The two profiles every listing row binds to. Only the enterprise profile body
# is read.
OPERATOR_ID = 55
PROFILE_ID = 77


def _config(**overrides) -> VeloCloudConfig:
    values = {
        "url": "https://vco.example",
        "enterprise_logical_ids": ENT,
        "orchestrator_release": "6.4.0.0",
        "auth": ApiKeyCredential(key="read-only-token"),
    }
    values.update(overrides)
    return VeloCloudConfig(**values)


def _href(*parts: str) -> str:
    return "/".join((BASE, "enterprises", ENT, *parts))


# --- fixtures in the captured shapes -----------------------------------------------------


def _segment(sid: int, name: str) -> dict:
    """A Portal `segments[]` block names its segment inside the nested object
    only. That object carries no logicalId and no `_href`."""
    return {"segment": {"segmentId": sid, "name": name, "type": "REGULAR"}}


def _summary(name: str, version: str, override: dict | None = None) -> dict:
    """One module of a listing `configuration` scope: a version stamp, the
    `isEdgeSpecific` flag and the override delta. It carries no body."""
    module = {"name": name, "type": name, "version": version, "isEdgeSpecific": override is not None}
    if override is not None:
        module["edgeSpecificData"] = override
    return module


def _configuration(*, device_settings: dict | None = None, qos: dict | None = None) -> dict:
    """The `configuration` block of one listing row. `controlPlane` is an
    operator module and reports `version` 0 on every edge; `deviceSettings` and
    `QOS` are enterprise modules and are the two that carry an override."""
    return {
        "operator": {
            "id": OPERATOR_ID,
            "name": "operator-profile",
            "modules": [_summary("controlPlane", "0"), _summary("metaData", "3")],
        },
        "enterprise": {
            "id": PROFILE_ID,
            "name": "profile-1",
            "modules": [
                _summary("deviceSettings", "9", device_settings),
                _summary("QOS", "4", qos),
                _summary("WAN", "2"),
                _summary("firewall", "1"),
            ],
        },
    }


def _edge(
    eid: str,
    numeric: int,
    name: str,
    links: list[dict],
    *,
    site: str = "Frankfurt",
    is_hub: bool = False,
    configuration: dict | None = None,
) -> dict:
    return {
        "_href": _href("edges", eid),
        "id": numeric,
        "logicalId": eid,
        "name": name,
        "serialNumber": f"S-{eid}",
        "modelNumber": "edge610",
        "edgeState": "CONNECTED",
        "isHub": is_hub,
        "site": {"_href": _href("sites", f"site-{eid}"), "name": site, "city": site, "lat": 50.1, "lon": 8.7},
        "links": links,
        "configuration": _configuration() if configuration is None else configuration,
    }


def _link(lid: str, interface: str, ip: str, isp: str) -> dict:
    """One link of the listing row. `networkType` is ETHERNET on every link of
    the reference fleet, including a link the WAN module calls WIRELESS, so it is
    never read as the access kind."""
    return {
        "_href": _href("links", lid),
        "logicalId": lid,
        "internalId": f"int-{lid}",
        "interface": interface,
        "ipAddress": ip,
        "networkSide": "WAN",
        "networkType": "ETHERNET",
        "displayName": f"{isp} {interface}",
        "isp": isp,
        "state": "STABLE",
        "linkMode": "ACTIVE",
    }


def _wan_link(
    lid: str,
    interface: str,
    *,
    mode: str,
    isp: str,
    access: str = "WIRED",
    next_hop: str | None = None,
    up: int = 100,
    down: int = 200,
) -> dict:
    """One `WAN.data.links[]` row. `mode` is PRIVATE or PUBLIC and it is what
    `WanLink.kind` reads."""
    return {
        "logicalId": lid,
        "internalId": f"int-{lid}",
        "name": f"{isp} {interface}",
        "mode": mode,
        "type": access,
        "isp": isp,
        "upstreamMbps": up,
        "downstreamMbps": down,
        "MTU": 1500,
        "nextHopIpAddress": next_hop,
        "vlanId": 0,
        "interfaces": [interface],
    }


def _wan_module(links: list[dict]) -> dict:
    return {
        "version": "2",
        "schemaVersion": "3.2.0",
        "type": "WAN",
        "data": {"links": links, "networks": []},
    }


GATEWAYS = [
    # `controlPlane` prefixes the gateway uuid; every other operation does not.
    {
        "name": "gw-1",
        "ipAddress": "192.0.2.10",
        "logicalId": "gatewayg-1",
        "roles": [{"role": "VPN_TUNNEL"}, {"role": "primary"}],
    },
    # no VPN_TUNNEL role: it terminates no overlay tunnel
    {"name": "gw-dns", "ipAddress": "192.0.2.20", "logicalId": "gatewayg-2", "roles": [{"role": "DNS"}]},
]


def _control_module(*, gateways: list[dict] = GATEWAYS, hubs: tuple[str, ...] = ("e-hub",)) -> dict:
    """The `controlPlane` module: the assigned gateways per segment, the hub
    edges of each segment and the configured origin controls."""
    return {
        "version": "0",
        "type": "controlPlane",
        "data": {
            "gatewaySegmentDetailList": [
                {
                    "segment": {"segmentId": 1, "name": "corp", "type": "REGULAR"},
                    "gatewayDetailList": gateways,
                }
            ],
            "segments": [
                {
                    "segment": {"segmentId": 1, "name": "corp", "type": "REGULAR"},
                    "vpn": {"dataCenterEdges": [{"logicalId": hub} for hub in hubs]},
                }
            ],
            "routingConfiguration": {
                "edge": {
                    "ospf": {"advertiseExternal": True, "advertiseInterArea": False},
                    "bgp": {"advertiseStatic": True, "advertiseConnected": False},
                },
                "hub": {
                    "ospf": {"advertiseExternal": False, "advertiseInterArea": True},
                    "bgp": {"advertiseStatic": False, "advertiseConnected": True},
                },
                "preferenceBuckets": [{"entity": "HUB", "exitType": "EDGE", "protocol": "BGP"}],
            },
        },
    }


HUB_REFS = [{"_href": _href("edges", "e-hub"), "name": "hub-1", "type": "edgeHubCluster"}]


def _profile_device_settings(hubs: list[dict] = HUB_REFS) -> dict:
    """The profile `deviceSettings` body. The `vpn` section lives here only: an
    `edgeSpecificData` delta never carries one."""
    return {
        "segments": [
            {
                **_segment(0, "Global Segment"),
                "bgp": {"enabled": True, "ASN": "65010", "neighbors": [{"neighborIp": "10.255.0.9"}]},
                "vpn": {"enabled": True, "edgeToEdgeDetail": {"vpnHubs": hubs}},
            },
            # the edge's own delta replaces this block's `bgp` key
            {**_segment(1, "corp"), "bgp": {"enabled": True, "ASN": "65010"}},
        ]
    }


def _edge_device_settings(
    *,
    lan_cidr: str,
    lan_vlan: int,
    wan_if: str,
    wan_cidr: str,
    wan_gw: str,
    neighbor: str,
    transit_ip: str = "10.9.9.1",
) -> dict:
    """One edge's `deviceSettings.edgeSpecificData`: the override delta, not the
    effective body."""
    return {
        "routedInterfaces": [
            {
                "name": wan_if,
                "wanOverlay": "AUTO_DISCOVERED",
                # a WAN interface is in no segment
                "segmentId": -1,
                "addressing": {
                    "type": "STATIC",
                    "cidrIp": wan_cidr.split("/")[0],
                    "cidrPrefix": 30,
                    "gateway": wan_gw,
                },
            },
            {
                "name": "GE3",
                "wanOverlay": "DISABLED",
                "segmentId": 1,
                "addressing": {"type": "STATIC", "cidrIp": transit_ip, "cidrPrefix": 24},
            },
        ],
        "lan": {
            "networks": [
                {
                    "name": "users",
                    "vlanId": lan_vlan,
                    "cidrIp": lan_cidr.split("/")[0],
                    "cidrPrefix": 24,
                    # a LAN network names its segment by the integer alone
                    "segmentId": 1,
                }
            ]
        },
        "segments": [
            {
                **_segment(1, "corp"),
                "bgp": {
                    "enabled": True,
                    "ASN": "65010",
                    "routerId": transit_ip,
                    "neighbors": [{"neighborIp": neighbor, "neighborAS": "65000", "localIp": transit_ip}],
                },
            }
        ],
    }


def _qos(rules: list[dict]) -> dict:
    return {"segments": [{**_segment(1, "corp"), "rules": rules}]}


def _rule(name: str, **route) -> dict:
    return {
        "name": name,
        "ruleLogicalId": f"rule-{name}",
        "match": {},
        "action": {"edge2EdgeRouteAction": route},
    }


def _profile() -> dict:
    """One enterprise profile row of `getEnterpriseConfigurations`. Every module
    wraps its body in `data`, and the `WAN` body is empty."""
    return {
        "id": PROFILE_ID,
        "name": "profile-1",
        "type": "SEGMENT_BASED",
        "modules": [
            {"name": "deviceSettings", "version": "9", "data": _profile_device_settings()},
            {
                "name": "QOS",
                "version": "4",
                "data": _qos(
                    [
                        _rule("voice", linkPolicy="fixed", wanlink="l-br-mpls"),
                        _rule("web", linkPolicy="auto", interface="GE2"),
                        _rule("backup", linkPolicy="private"),
                    ]
                ),
            },
            {"name": "WAN", "version": "2", "data": {}},
        ],
    }


def _route_table() -> dict:
    """The reduced Overlay Flow Control table: a prefix the hub advertises, a
    prefix the branch advertises named by numeric edge id only, a prefix whose
    segment only the `subnet` key names, and an exit that names a local router."""
    return {
        "profiles": [PROFILE_ID],
        "reduced": True,
        "subnets": [
            {
                "subnet": "10.20.20.0/24:1",
                "ipVersion": 4,
                "learnedRoute": {
                    "cidrIp": "10.20.20.0",
                    "cidrPrefix": 24,
                    "segmentId": 1,
                    "logicalId": "r-1",
                },
                "preferredExits": [
                    {
                        "type": "LEARNED",
                        "exitType": "EDGE",
                        "entity": "HUB",
                        "protocol": "BGP",
                        "routeType": "E",
                        "segmentId": 1,
                        "edgeId": 2,
                        "edgeLogicalId": "e-hub",
                        "interface": "GE3",
                        "neighborIp": "10.9.8.2",
                        "cost": 20,
                    }
                ],
                "eligableExits": [
                    # a local router next hop: it names no device and becomes no row
                    {"type": "CONNECTED", "exitType": "ROUTER", "learnedBy": "10.9.8.2", "cost": 5}
                ],
            },
            {
                "subnet": "10.10.10.0/24:1",
                "ipVersion": 4,
                "learnedRoute": {"cidrIp": "10.10.10.0", "cidrPrefix": 24, "logicalId": "r-2"},
                "preferredExits": [
                    {
                        "type": "CONNECTED",
                        "exitType": "EDGE",
                        "entity": "EDGE",
                        "segmentId": 1,
                        "edgeId": 1,
                        "interface": "users",
                        "cost": 0,
                    }
                ],
                "eligableExits": [],
            },
            {
                "subnet": "10.30.30.0/24:9",
                "ipVersion": 4,
                "learnedRoute": {"cidrIp": "10.30.30.0", "cidrPrefix": 24, "logicalId": "r-3"},
                "preferredExits": [
                    {"type": "STATIC", "exitType": "EDGE", "edgeId": 1, "nextHopIp": "10.9.9.2"}
                ],
                "eligableExits": [],
            },
        ],
    }


BR_WAN_LINKS = [
    _wan_link("l-br-mpls", "GE1", mode="PRIVATE", isp="OurNet", next_hop="172.16.1.1"),
    _wan_link("l-br-dia", "GE2", mode="PUBLIC", isp="ThirdParty ISP", next_hop="198.51.100.1"),
]
HUB_WAN_LINKS = [
    _wan_link("l-hub-mpls", "GE1", mode="PRIVATE", isp="OurNet"),
    _wan_link("l-hub-dia", "GE2", mode="PUBLIC", isp="DC ISP"),
]


def _overlay_raw() -> dict:
    """A branch and a hub in one enterprise. Both bind to one enterprise
    profile; each carries its own `deviceSettings` override, its own `WAN` module
    and a `controlPlane` module that assigns one VPN gateway."""
    branch = _edge(
        "e-br",
        1,
        "branch-1",
        [
            _link("l-br-mpls", "GE1", "172.16.1.2", "OurNet"),
            _link("l-br-dia", "GE2", "198.51.100.2", "ThirdParty ISP"),
        ],
        configuration=_configuration(
            device_settings=_edge_device_settings(
                lan_cidr="10.10.10.1/24",
                lan_vlan=10,
                wan_if="GE1",
                wan_cidr="172.16.1.2/30",
                wan_gw="172.16.1.1",
                neighbor="10.9.9.2",
            )
        ),
    )
    hub = _edge(
        "e-hub",
        2,
        "hub-1",
        [
            _link("l-hub-mpls", "GE1", "172.16.9.2", "OurNet"),
            _link("l-hub-dia", "GE2", "203.0.113.2", "DC ISP"),
        ],
        site="Berlin",
        is_hub=True,
        configuration=_configuration(
            device_settings=_edge_device_settings(
                lan_cidr="10.20.20.1/24",
                lan_vlan=20,
                wan_if="GE1",
                wan_cidr="172.16.9.2/30",
                wan_gw="172.16.9.1",
                neighbor="10.9.8.2",
                # the hub's own transit net
                transit_ip="10.9.8.1",
            )
        ),
    )
    return {
        "api_profile": "velocloud-vco-6.4.0-v3",
        "orchestrator_release": "6.4.0.0",
        "fetched_at_ms": 1000,
        "discovered": False,
        "enterprises": [
            {
                "logicalId": ENT,
                "name": "Acme",
                "enterprise_id": ENT_ID,
                "edges": [branch, hub],
                "profiles": {str(PROFILE_ID): _profile()},
                "edge_details": {
                    "e-br": {
                        "modules": {"WAN": _wan_module(BR_WAN_LINKS), "controlPlane": _control_module()},
                        "_freshness": {"modules": {"observed_at_ms": 900, "stale": False}},
                    },
                    "e-hub": {
                        "modules": {"WAN": _wan_module(HUB_WAN_LINKS), "controlPlane": _control_module()},
                        "_freshness": {"modules": {"observed_at_ms": 900, "stale": False}},
                    },
                },
                "route_table": _route_table(),
                "bgp_sessions": [
                    {
                        "edge": {"_href": _href("edges", "e-br")},
                        "neighborIp": "10.9.9.2",
                        "neighborAS": 65000,
                        "state": "ESTABLISHED",
                        "pfxRcvd": 12,
                        "upDownTime": "01:02:03",
                    },
                    {
                        "edge": {"_href": _href("edges", "e-br"), "logicalId": "e-br"},
                        "neighborIp": "10.9.9.99",
                        "state": "IDLE",
                    },
                ],
                "gaps": [],
            }
        ],
    }


def _index(batch):
    nodes = {(n.label, n.uid): n.props for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    return nodes, rels


BR = f"vco:{ENT}:edge:e-br"
HUB = f"vco:{ENT}:edge:e-hub"
BR_CORP = uid.vrf(BR, "corp")
BR_GLOBAL = uid.vrf(BR, "global-segment")
HUB_CORP = uid.vrf(HUB, "corp")
HUB_GLOBAL = uid.vrf(HUB, "global-segment")
PRIVATE = {"ournet"}


# --- fetch -------------------------------------------------------------------------------


def _mock(monkeypatch, handler) -> None:
    monkeypatch.setattr("hst.collectors.velocloud._transport", lambda config: httpx.MockTransport(handler))


def test_fetch_reads_five_portal_operations_and_the_bgp_session_pages(monkeypatch) -> None:
    source = _overlay_raw()["enterprises"][0]
    posts: list[tuple[str, dict]] = []
    gets: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST":
            body = json.loads(request.content)
            posts.append((path, body))
            if path == PORTAL_READ_PATHS["aggregates"]:
                return httpx.Response(200, json={"enterprises": [{"id": ENT_ID, "logicalId": ENT}]})
            if path == PORTAL_READ_PATHS["enterprise_edges"]:
                return httpx.Response(200, json=source["edges"])
            if path == PORTAL_READ_PATHS["enterprise_configurations"]:
                return httpx.Response(200, json=list(source["profiles"].values()))
            if path == PORTAL_READ_PATHS["route_table"]:
                return httpx.Response(200, json=source["route_table"])
            eid = next(e["logicalId"] for e in source["edges"] if e["id"] == body["edgeId"])
            return httpx.Response(200, json=source["edge_details"][eid]["modules"])
        gets.append((path, dict(request.url.params)))
        assert path.endswith("/bgpSessions"), path
        if request.url.params.get("nextPageLink") == "page-2":
            return httpx.Response(200, json={"data": [], "metaData": {"more": False}})
        return httpx.Response(
            200, json={"data": source["bgp_sessions"], "metaData": {"nextPageLink": "page-2"}}
        )

    _mock(monkeypatch, handler)
    raw = VeloCloudCollector(_config(), Settings(_env_file=None)).fetch()
    assert raw["discovered"] is False
    body = raw["enterprises"][0]
    assert body["enterprise_id"] == ENT_ID
    assert [e["logicalId"] for e in body["edges"]] == ["e-br", "e-hub"]
    assert set(body["profiles"]) == {str(PROFILE_ID)}
    assert body["route_table"]["subnets"] == source["route_table"]["subnets"]
    assert len(body["bgp_sessions"]) == 2
    assert body["gaps"] == []
    assert body["edge_details"]["e-br"]["modules"]["WAN"]["data"]["links"][0]["mode"] == "PRIVATE"
    # one enterprise-wide read each, then one module read per edge, and no
    # per-edge APIv2 read at all
    assert [path for path, _ in posts[:4]] == [
        PORTAL_READ_PATHS["aggregates"],
        PORTAL_READ_PATHS["enterprise_edges"],
        PORTAL_READ_PATHS["enterprise_configurations"],
        PORTAL_READ_PATHS["route_table"],
    ]
    assert posts[1][1] == {"enterpriseId": ENT_ID, "with": ["site", "links", "ha", "configuration"]}
    assert posts[2][1] == {"enterpriseId": ENT_ID, "with": ["modules"]}
    assert posts[3][1] == {"enterpriseId": ENT_ID}
    assert {path for path, _ in posts[4:]} == {PORTAL_READ_PATHS["configuration_modules"]}
    assert sorted(b["edgeId"] for _, b in posts[4:]) == [1, 2]
    assert all(b["modules"] == ["WAN", "controlPlane"] for _, b in posts[4:])
    assert [path for path, _ in gets] == [f"{BASE}/enterprises/{ENT}/bgpSessions"] * 2
    assert [params for _, params in gets] == [BGP_SESSION_FILTER, {"nextPageLink": "page-2"}]


def test_fetch_reduces_the_route_table_to_the_fields_a_rib_row_reads(monkeypatch) -> None:
    source = _overlay_raw()["enterprises"][0]
    record = json.loads(json.dumps(source["route_table"]["subnets"][0]))
    record["preferredExits"][0].update(
        {"created": "2026-01-01", "modified": "2026-01-02", "id": 5, "routeId": 6, "attributes": {"a": 1}}
    )
    record["learnedRoute"]["edgeName"] = "branch-1"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == PORTAL_READ_PATHS["aggregates"]:
            return httpx.Response(200, json={"enterprises": [{"id": ENT_ID, "logicalId": ENT}]})
        if path == PORTAL_READ_PATHS["enterprise_edges"]:
            return httpx.Response(200, json=source["edges"])
        if path == PORTAL_READ_PATHS["enterprise_configurations"]:
            return httpx.Response(200, json=list(source["profiles"].values()))
        if path == PORTAL_READ_PATHS["route_table"]:
            return httpx.Response(200, json={"profiles": [PROFILE_ID], "subnets": [record]})
        if path == PORTAL_READ_PATHS["configuration_modules"]:
            return httpx.Response(200, json={})
        return httpx.Response(200, json=[])

    _mock(monkeypatch, handler)
    raw = VeloCloudCollector(_config(), Settings(_env_file=None)).fetch()
    table = raw["enterprises"][0]["route_table"]
    assert table["reduced"] is True
    assert table["subnets"][0] == source["route_table"]["subnets"][0]


def test_a_refused_listing_falls_back_to_the_apiv2_edges_and_records_the_gaps(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == PORTAL_READ_PATHS["aggregates"]:
            return httpx.Response(200, json={"enterprises": [{"id": ENT_ID, "logicalId": ENT}]})
        if path == PORTAL_READ_PATHS["enterprise_edges"]:
            return httpx.Response(403, json={"error": {"code": -32600, "message": "no privilege"}})
        if path == PORTAL_READ_PATHS["enterprise_configurations"]:
            return httpx.Response(200, json=[_profile()])
        if path == PORTAL_READ_PATHS["route_table"]:
            # the Portal answers an unsupported operation with a 200 and a body
            return httpx.Response(200, json={"error": {"code": -32601, "message": "methodError"}})
        # the per-edge module read needs a numeric id, and the fallback row has none
        assert path != PORTAL_READ_PATHS["configuration_modules"]
        if path.endswith("/edges"):
            return httpx.Response(
                200, json={"data": [{"logicalId": "e-br", "name": "branch-1"}], "metaData": {}}
            )
        return httpx.Response(200, json=[])

    _mock(monkeypatch, handler)
    raw = VeloCloudCollector(_config(), Settings(_env_file=None)).fetch()
    body = raw["enterprises"][0]
    assert [e["logicalId"] for e in body["edges"]] == ["e-br"]
    assert body["route_table"] is None
    gaps = [gap["_capability"] for gap in body["gaps"]]
    assert [gap["operation"] for gap in gaps] == [
        PORTAL_READ_PATHS["enterprise_edges"],
        PORTAL_READ_PATHS["route_table"],
    ]
    assert gaps[0]["http_status"] == 403
    assert "no privilege" in gaps[0]["detail"]
    assert "methodError" in gaps[1]["detail"]
    assert body["edge_details"]["e-br"]["modules"]["_capability"]["detail"] == "no numeric id for this edge"
    nodes, _ = _index(normalize_velocloud(raw))
    assert ("Device", BR) in nodes
    boundary = nodes[("ForwardingBoundary", f"vco:{ENT}:edge-e-br-boundary:global")]
    assert any("getEnterpriseEdges" in gap for gap in boundary["gaps"])
    assert any("getEnterpriseRouteTable" in gap for gap in boundary["gaps"])
    assert boundary["candidate_set_complete"] is False


def test_an_unresolved_enterprise_reads_no_portal_operation_and_keeps_the_edges(monkeypatch) -> None:
    posts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posts.append(request.url.path)
            return httpx.Response(200, json={"enterprises": [{"id": 9, "logicalId": "another"}]})
        if request.url.path.endswith("/edges"):
            return httpx.Response(200, json={"data": [{"logicalId": "e-br"}], "metaData": {}})
        return httpx.Response(200, json=[])

    _mock(monkeypatch, handler)
    body = VeloCloudCollector(_config(), Settings(_env_file=None)).fetch()["enterprises"][0]
    assert posts == [PORTAL_READ_PATHS["aggregates"]]
    assert [e["logicalId"] for e in body["edges"]] == ["e-br"]
    assert body["gaps"][0]["_capability"]["detail"] == f"no numeric id for enterprise {ENT}"


def test_fetch_discovers_every_enterprise_when_none_is_configured(monkeypatch) -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/enterprises"):
            return httpx.Response(
                200,
                json={
                    "data": [{"logicalId": "ent-a", "name": "Acme"}, {"logicalId": "ent-b", "name": "Bolt"}],
                    "metaData": {},
                },
            )
        if request.method == "POST":
            return httpx.Response(200, json={"enterprises": []})
        return httpx.Response(200, json={"data": [], "metaData": {}})

    _mock(monkeypatch, handler)
    raw = VeloCloudCollector(_config(enterprise_logical_ids=""), Settings(_env_file=None)).fetch()
    assert raw["discovered"] is True
    assert [(e["logicalId"], e["name"]) for e in raw["enterprises"]] == [("ent-a", "Acme"), ("ent-b", "Bolt")]
    # getAggregates is read once per poll, not once per enterprise
    assert paths.count(PORTAL_READ_PATHS["aggregates"]) == 1
    assert f"{BASE}/enterprises/ent-a/edges" in paths
    assert f"{BASE}/enterprises/ent-b/bgpSessions" in paths


def test_fetch_waits_out_a_rate_limit(monkeypatch) -> None:
    pauses: list[float] = []
    hits = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == PORTAL_READ_PATHS["aggregates"]:
            hits["n"] += 1
            if hits["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "2"}, json={"code": "RATE_LIMIT"})
            return httpx.Response(200, json={"enterprises": []})
        return httpx.Response(200, json={"data": [], "metaData": {}})

    _mock(monkeypatch, handler)
    monkeypatch.setattr("hst.collectors.velocloud._sleep", pauses.append)
    VeloCloudCollector(_config(), Settings(_env_file=None)).fetch()
    assert pauses == [2.0]
    assert hits["n"] == 2


def test_scope_is_the_orchestrator_not_the_enterprise() -> None:
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    assert collector.scope == "velocloud:vco.example"


# --- the effective configuration ---------------------------------------------------------


def test_the_effective_configuration_merges_the_profile_with_the_edge_override() -> None:
    nodes, rels = _index(normalize_velocloud(_overlay_raw()))
    # the profile-only segment and the merged segment both stand
    assert ("VrfInstance", BR_GLOBAL) in nodes
    assert ("VrfInstance", BR_CORP) in nodes
    # the hub reference lives in the profile `vpn` section only
    assert nodes[("Device", HUB)]["sdwan_role"] == "hub"
    assert ("Interface", uid.interface(BR, "GE3")) in nodes
    assert (
        "ENDPOINT",
        uid.bgp_session(uid.routing_process(BR, "corp", "bgp"), "10.9.9.2", "corp"),
        uid.ip(BR_CORP, "10.9.9.2"),
    ) in rels
    assert nodes[("RoutingProcess", uid.routing_process(BR, "corp", "bgp"))]["router_id"] == "10.9.9.1"


def test_a_refused_profile_read_leaves_the_effective_policy_unknown_not_empty() -> None:
    raw = _overlay_raw()
    raw["enterprises"][0]["profiles"] = {}
    nodes, _ = _index(normalize_velocloud(raw))
    policy = nodes[("SdwanBusinessPolicy", f"vco:{ENT}:edge-e-br-policy:edge")]
    gap = json.loads(policy["capability_gap"])
    assert gap["operation"] == PORTAL_READ_PATHS["enterprise_configurations"]
    assert gap["status"] == "unavailable"


def test_the_control_plane_module_resolves_a_hub_the_profile_only_names_by_cluster() -> None:
    """A `vpnHubs[]` entry of type `edgeHubCluster` names a cluster, and the
    cluster id matches no edge. `isHub` and the `controlPlane` module each
    resolve it on their own."""
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    for edge in ent["edges"]:
        edge["isHub"] = False
    profile = ent["profiles"][str(PROFILE_ID)]
    cluster = {"logicalId": "cluster-1", "name": "cluster-1"}
    profile["modules"][0]["data"] = _profile_device_settings([cluster])
    nodes, _ = _index(normalize_velocloud(raw))
    assert nodes[("Device", HUB)]["sdwan_role"] == "hub"
    assert "sdwan_role" not in nodes[("Device", BR)]
    # with neither the flag nor the module, no edge is a hub
    for detail in ent["edge_details"].values():
        detail["modules"]["controlPlane"]["data"]["segments"] = []
    nodes, _ = _index(normalize_velocloud(raw))
    assert "sdwan_role" not in nodes[("Device", HUB)]


def test_a_cluster_reference_resolves_through_the_member_cluster_id() -> None:
    """A hub reference names a cluster by its logicalId, and the `controlPlane`
    module of each member names the same id with the member list. The listing
    `ha` block names the high availability type of every edge."""
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    for edge in ent["edges"]:
        edge["isHub"] = False
    branch, hub = ent["edges"]
    ent["profiles"][str(PROFILE_ID)]["modules"][0]["data"] = _profile_device_settings(
        [{"type": "edgeHubCluster", "logicalId": "cl-dc", "name": " DC-CLUSTER"}]
    )
    for detail in ent["edge_details"].values():
        detail["modules"]["controlPlane"]["data"]["segments"] = []
    ent["edge_details"]["e-hub"]["modules"]["controlPlane"]["data"]["memberCluster"] = {
        "clusterLogicalId": "cl-dc",
        "clusterName": " DC-CLUSTER",
        "members": [{"edgeLogicalId": "e-hub", "edgeId": 2}],
    }
    hub["ha"] = {"type": "ACTIVE_ACTIVE", "data": {"clusterId": 31, "clusterName": " DC-CLUSTER"}}
    hub["haState"] = "UNCONFIGURED"
    branch["ha"] = {
        "type": "ACTIVE_STANDBY",
        "data": {"haSerialNumber": "S-standby", "haState": "READY", "haMode": "standard"},
    }
    nodes, _ = _index(normalize_velocloud(raw))
    hub_node, branch_node = nodes[("Device", HUB)], nodes[("Device", BR)]
    assert hub_node["sdwan_role"] == "hub"
    assert hub_node["hub_cluster_id"] == "cl-dc"
    # the orchestrator keeps the leading space an operator typed
    assert hub_node["hub_cluster_name"] == "DC-CLUSTER"
    assert hub_node["ha_type"] == "ACTIVE_ACTIVE"
    # the row-level pair state says nothing about a cluster member
    assert "ha_state" not in hub_node
    assert "sdwan_role" not in branch_node
    assert branch_node["ha_type"] == "ACTIVE_STANDBY"
    assert branch_node["ha_state"] == "READY"
    assert branch_node["ha_standby_serial"] == "S-standby"
    assert "hub_cluster_id" not in branch_node


# --- normalize ---------------------------------------------------------------------------


def test_normalize_keeps_enterprise_segment_edge_and_boundary_identity() -> None:
    nodes, rels = _index(normalize_velocloud(_overlay_raw()))
    assert nodes[("SdwanSegment", f"vco:{ENT}:segment:1")]["name"] == "corp"
    assert nodes[("SdwanSegment", f"vco:{ENT}:segment:0")]["enterprise_name"] == "Acme"
    policy = nodes[("SdwanBusinessPolicy", f"vco:{ENT}:edge-e-br-policy:edge")]
    # the body is parsed into one rule node per rule, not kept as a string
    assert "effective_qos" not in policy
    assert policy["rule_count"] == 3
    voice = nodes[("SdwanPolicyRule", f"vco:{ENT}:edge-e-br-rule:1:rule-voice")]
    assert voice["name"] == "voice"
    assert voice["position"] == 1
    assert voice["segment_name"] == "corp"
    assert ("HAS_RULE", f"vco:{ENT}:edge-e-br-policy:edge", f"vco:{ENT}:edge-e-br-rule:1:rule-voice") in rels
    assert ("IN", f"vco:{ENT}:edge-e-br-rule:1:rule-voice", f"vco:{ENT}:segment:1") in rels
    assert "capability_gap" not in policy
    boundary = nodes[("ForwardingBoundary", f"vco:{ENT}:edge-e-br-boundary:1")]
    assert boundary["candidate_set_complete"] is False
    assert boundary["segment_id"] == "1"
    assert boundary["orchestrator_release"] == "6.4.0.0"
    assert ("HAS_BOUNDARY", BR, f"vco:{ENT}:edge-e-br-boundary:1") in rels
    assert ("IN", f"vco:{ENT}:edge-e-br-boundary:1", f"vco:{ENT}:segment:1") in rels


def test_normalize_places_the_edge_by_the_orchestrator_site() -> None:
    nodes, _ = _index(normalize_velocloud(_overlay_raw()))
    device = nodes[("Device", BR)]
    assert device["reported_location"] == f"{ENT}/site-e-br"
    assert device["reported_location_name"] == "Frankfurt"
    assert device["site_lat"] == 50.1
    assert device["enterprise_name"] == "Acme"
    assert device["model"] == "edge610"
    # the listing and the profiles are read live: the poll time is when this
    # effective configuration was observed
    assert device["configuration_observed_at_ms"] == 1000


def test_normalize_writes_lan_interfaces_in_their_segment_and_wan_in_the_global_table() -> None:
    nodes, rels = _index(normalize_velocloud(_overlay_raw()))
    assert nodes[("VrfInstance", BR_GLOBAL)]["is_global"] is True
    users, ge1, ge3 = uid.interface(BR, "users"), uid.interface(BR, "GE1"), uid.interface(BR, "GE3")
    assert ("IN_VRF", users, BR_CORP) in rels
    assert ("IN_VRF", ge3, BR_CORP) in rels
    assert ("IN_VRF", ge1, BR_GLOBAL) in rels
    assert ("HAS_IP", users, uid.ip(BR_CORP, "10.10.10.1")) in rels
    assert nodes[("Prefix", uid.prefix(BR_CORP, "10.10.10.0/24"))]["kind"] == "connected"
    assert nodes[("Interface", ge1)]["next_hop"] == "172.16.1.1"
    assert nodes[("Interface", users)]["vlan"] == 10
    assert "sdwan_role" not in nodes[("Device", BR)]


def _hub_override(raw: dict) -> dict:
    """The hub's `deviceSettings.edgeSpecificData`."""
    hub = raw["enterprises"][0]["edges"][1]
    return next(
        m["edgeSpecificData"]
        for m in hub["configuration"]["enterprise"]["modules"]
        if m["name"] == "deviceSettings"
    )


def test_normalize_writes_each_subinterface_in_its_own_segment_on_the_parent_port() -> None:
    raw = _overlay_raw()
    override = _hub_override(raw)
    override["routedInterfaces"].append(
        {
            "name": "GE5",
            "wanOverlay": "DISABLED",
            "segmentId": 0,
            "addressing": {"type": "STATIC", "cidrIp": "10.77.9.1", "cidrPrefix": 30},
            "subinterfaces": [
                {
                    "subinterfaceId": 20,
                    "subinterfaceType": "SUB_INTERFACE",
                    "segmentId": 1,
                    "vlanId": 20,
                    "addressing": {"type": "STATIC", "cidrIp": "10.77.0.1", "cidrPrefix": 30},
                },
                # a disabled subinterface is not configured forwarding state
                {
                    "subinterfaceId": 21,
                    "segmentId": 1,
                    "vlanId": 21,
                    "disabled": True,
                    "addressing": {"type": "STATIC", "cidrIp": "10.77.0.5", "cidrPrefix": 30},
                },
            ],
        }
    )
    corp = next(s for s in override["segments"] if s["segment"]["segmentId"] == 1)
    corp["bgp"]["neighbors"].append({"neighborIp": "10.77.0.2", "neighborAS": "65077"})
    nodes, rels = _index(normalize_velocloud(raw))
    sub = uid.interface(HUB, "GE5:20")
    assert nodes[("Interface", sub)] == {"name": "GE5:20", "kind": "subif", "vlan": 20, "subinterface_id": 20}
    assert ("IN_VRF", sub, HUB_CORP) in rels
    assert ("IN_VRF", uid.interface(HUB, "GE5"), HUB_GLOBAL) in rels
    assert ("REALIZED_BY", sub, uid.port(HUB, "GE5")) in rels
    # the neighbor sits on the subinterface's connected prefix, in the same segment
    assert ("HAS_IP", sub, uid.ip(HUB_CORP, "10.77.0.1")) in rels
    assert nodes[("Prefix", uid.prefix(HUB_CORP, "10.77.0.0/30"))]["kind"] == "connected"
    session = uid.bgp_session(uid.routing_process(HUB, "corp", "bgp"), "10.77.0.2", "corp")
    assert ("ENDPOINT", session, uid.ip(HUB_CORP, "10.77.0.2")) in rels
    assert ("Interface", uid.interface(HUB, "GE5:21")) not in nodes


def test_normalize_writes_each_loopback_in_its_segment() -> None:
    raw = _overlay_raw()
    _hub_override(raw)["loopbackInterfaces"] = {
        "LO1": {"cidrIp": "10.250.0.9", "cidrPrefix": 32, "segmentId": 1, "disableV4": False},
        "LO2": {"cidrIp": "10.250.0.10", "cidrPrefix": 32, "segmentId": 0, "disableV4": True},
    }
    nodes, rels = _index(normalize_velocloud(raw))
    lo1, lo2 = uid.interface(HUB, "LO1"), uid.interface(HUB, "LO2")
    assert nodes[("Interface", lo1)] == {"name": "LO1", "kind": "loopback"}
    assert ("IN_VRF", lo1, HUB_CORP) in rels
    assert ("HAS_IP", lo1, uid.ip(HUB_CORP, "10.250.0.9")) in rels
    # a loopback with IPv4 turned off holds no IPv4 address
    assert ("IN_VRF", lo2, HUB_GLOBAL) in rels
    assert not any(r[0] == "HAS_IP" and r[1] == lo2 for r in rels)


def test_normalize_writes_bgp_sessions_and_records_the_asn_gap() -> None:
    nodes, rels = _index(normalize_velocloud(_overlay_raw()))
    ru = uid.routing_process(BR, "corp", "bgp")
    su = uid.bgp_session(ru, "10.9.9.2", "corp")
    assert nodes[("RoutingProcess", ru)]["asn"] == 65010
    assert nodes[("RoutingProcess", ru)]["router_id"] == "10.9.9.1"
    assert nodes[("BgpSession", su)] == {
        "local_asn": 65010,
        "peer_asn": 65000,
        "peer_ip": "10.9.9.2",
        "local_ip": "10.9.9.1",
    }
    assert ("HAS", ru, su) in rels
    assert ("ENDPOINT", su, uid.ip(BR_CORP, "10.9.9.2")) in rels
    # the neighbor without an ASN is a gap on the boundary, not a session
    assert not any(label == "BgpSession" and "10.255.0.9" in u for label, u in nodes)
    boundary = nodes[("ForwardingBoundary", f"vco:{ENT}:edge-e-br-boundary:1")]
    assert "bgp neighbor 10.255.0.9 has no ASN" in boundary["gaps"]


def test_normalize_writes_the_configured_origin_controls_on_the_routing_process() -> None:
    """`controlPlane.routingConfiguration` is what the orchestrator is
    configured to originate. The role the edge holds picks the section."""
    nodes, _ = _index(normalize_velocloud(_overlay_raw()))
    branch = nodes[("RoutingProcess", uid.routing_process(BR, "corp", "bgp"))]
    hub = nodes[("RoutingProcess", uid.routing_process(HUB, "corp", "bgp"))]
    assert branch["origin_role"] == "edge"
    assert branch["origin_config_recorded"] is True
    assert branch["advertise_external"] is True
    assert branch["advertise_static"] is True
    # a control the orchestrator turned off is evidence too, so False is written
    assert branch["advertise_inter_area"] is False
    assert branch["advertise_connected"] is False
    assert hub["origin_role"] == "hub"
    assert hub["advertise_inter_area"] is True
    assert hub["advertise_connected"] is True
    # the buckets order the exits of the overlay route table
    assert json.loads(branch["preference_buckets"])[0]["entity"] == "HUB"


def test_normalize_writes_wan_links_provider_networks_and_the_operator_provider() -> None:
    nodes, rels = _index(
        normalize_velocloud(_overlay_raw(), provider_name="Our Carrier", private_carriers=PRIVATE)
    )
    mpls, dia = f"vco:{ENT}:edge-e-br-link:l-br-mpls", f"vco:{ENT}:edge-e-br-link:l-br-dia"
    link = nodes[("WanLink", mpls)]
    # the WAN module's own mode decides the kind, not the carrier name
    assert link["kind"] == "mpls"
    assert link["wan_mode"] == "PRIVATE"
    assert link["access_type"] == "WIRED"
    assert link["origin_config_recorded"] is True
    assert link["state"] == "STABLE"
    assert link["upstream_mbps"] == 100
    assert link["downstream_mbps"] == 200
    assert link["mtu"] == 1500
    assert link["next_hop"] == "172.16.1.1"
    assert link["configuration_observed_at_ms"] == 900
    assert json.loads(link["configuration"])["isp"] == "OurNet"
    # no quality metric is read: the twin uses no latency, jitter, loss or score
    assert not {"latency_ms", "jitter_ms", "loss_pct"} & link.keys()
    assert nodes[("WanLink", dia)]["kind"] == "dia"
    assert nodes[("WanLink", dia)]["carrier"] == "ThirdParty ISP"
    assert ("PROVIDED_BY", mpls, "pnet:mpls:ournet") in rels
    assert ("PROVIDED_BY", dia, "pnet:internet:thirdparty-isp") in rels
    assert nodes[("ProviderNetwork", "pnet:mpls:ournet")]["kind"] == "mpls"
    assert ("PROVIDED_BY", "pnet:mpls:ournet", "provider:our-carrier") in rels
    assert not any(r[0] == "PROVIDED_BY" and r[1] == "pnet:internet:thirdparty-isp" for r in rels)
    assert ("HAS_IP", mpls, uid.ip(BR_GLOBAL, "172.16.1.2")) in rels
    assert ("HAS_IP", uid.interface(BR, "GE2"), uid.ip(BR_GLOBAL, "198.51.100.2")) in rels


def test_an_older_listing_row_with_the_same_logical_id_does_not_replace_the_configured_link() -> None:
    """The listing keeps every link an edge reported. A link provisioned again
    on the same port has the same logicalId and a new internalId, and the old
    row stays, disconnected, with its old address."""
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    old = _link("l-br-dia", "GE2", "10.66.0.7", "ThirdParty ISP")
    old.update(
        internalId="int-old-dia",
        displayName="10.66.0.7",
        state="DISCONNECTED",
        lastActive="2021-03-01T10:00:00.000Z",
    )
    ent["edges"][0]["links"][1]["lastActive"] = "2026-09-01T10:00:00.000Z"
    ent["edges"][0]["links"].append(old)
    nodes, rels = _index(normalize_velocloud(raw))
    link_uid = f"vco:{ENT}:edge-e-br-link:l-br-dia"
    link = nodes[("WanLink", link_uid)]
    assert link["state"] == "STABLE"
    assert link["public_ip"] == "198.51.100.2"
    assert link["name"] == "ThirdParty ISP GE2"
    assert ("HAS_IP", link_uid, uid.ip(BR_GLOBAL, "198.51.100.2")) in rels
    assert not any(r[0] == "HAS_IP" and r[2].endswith(":10.66.0.7") for r in rels)
    boundary = nodes[("ForwardingBoundary", f"vco:{ENT}:edge-e-br-boundary:1")]
    assert any("1 older listing link rows share a logicalId" in gap for gap in boundary["gaps"])


def test_a_link_behind_nat_keeps_the_outside_address_off_its_interface() -> None:
    """The listing names a link by the address the orchestrator sees, after the
    NAT in front of the edge. The interface holds its own configured address."""
    raw = _overlay_raw()
    raw["enterprises"][0]["edges"][0]["links"][0]["ipAddress"] = "203.0.113.50"
    nodes, rels = _index(normalize_velocloud(raw))
    link_uid = f"vco:{ENT}:edge-e-br-link:l-br-mpls"
    ge1 = uid.interface(BR, "GE1")
    assert nodes[("WanLink", link_uid)]["public_ip"] == "203.0.113.50"
    assert ("ON", link_uid, ge1) in rels
    assert ("HAS_IP", ge1, uid.ip(BR_GLOBAL, "172.16.1.2")) in rels
    assert ("HAS_IP", ge1, uid.ip(BR_GLOBAL, "203.0.113.50")) not in rels
    # the link holds both: its own address joins it to the interface, the
    # outside address is where a far tunnel ends
    assert ("HAS_IP", link_uid, uid.ip(BR_GLOBAL, "172.16.1.2")) in rels
    assert ("HAS_IP", link_uid, uid.ip(BR_GLOBAL, "203.0.113.50")) in rels
    # the tunnel leaves from the address the edge holds
    tunnel = nodes[("Tunnel", f"vco:{ENT}:path:e-br:l-br-mpls~gw:g-1")]
    assert tunnel["local_address"] == "172.16.1.2"


def test_the_link_is_named_by_its_wan_row() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    ent["edges"][0]["links"][1]["displayName"] = "198.51.100.2"
    ent["edge_details"]["e-br"]["modules"]["WAN"]["data"]["links"][1]["name"] = "Internet circuit 4471"
    nodes, _ = _index(normalize_velocloud(raw))
    assert nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-dia")]["name"] == "Internet circuit 4471"


def test_without_a_configured_row_the_newest_listing_row_is_written() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    newer = _link("l-br-dia", "GE2", "198.51.100.9", "ThirdParty ISP")
    newer.update(internalId="int-new-dia", lastActive="2026-09-02T10:00:00.000Z")
    ent["edges"][0]["links"][1].update(internalId="int-old-dia", lastActive="2024-01-01T10:00:00.000Z")
    ent["edges"][0]["links"].insert(0, newer)
    nodes, _ = _index(normalize_velocloud(raw))
    link = nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-dia")]
    assert link["public_ip"] == "198.51.100.9"
    assert link["wan_mode"] == "PUBLIC"


def test_a_listing_link_the_wan_module_does_not_describe_is_not_written() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    gone = _link("l-br-gone", "GE4", "10.66.0.9", "Gone ISP")
    gone.update(state="DISCONNECTED", lastActive="2019-05-01T10:00:00.000Z")
    ent["edges"][0]["links"].append(gone)
    nodes, _ = _index(normalize_velocloud(raw))
    assert ("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-gone") not in nodes
    assert ("Interface", uid.interface(BR, "GE4")) not in nodes
    boundary = nodes[("ForwardingBoundary", f"vco:{ENT}:edge-e-br-boundary:1")]
    assert any("1 listing links are not in the WAN module" in gap for gap in boundary["gaps"])


def test_a_private_link_with_no_isp_is_provided_by_its_private_network() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    ent["edges"][0]["links"][0].update(isp="", org="", vpnState="STABLE", backupState="UNCONFIGURED")
    row = ent["edge_details"]["e-br"]["modules"]["WAN"]["data"]["links"][0]
    row.update(isp="", privateNetwork="CORE-L3VPN", backupOnly=False, hotStandby=True)
    nodes, rels = _index(normalize_velocloud(raw))
    link_uid = f"vco:{ENT}:edge-e-br-link:l-br-mpls"
    link = nodes[("WanLink", link_uid)]
    assert link["carrier"] == "CORE-L3VPN"
    assert link["private_network"] == "CORE-L3VPN"
    assert link["hot_standby"] is True
    assert link["backup_only"] is False
    assert link["vpn_state"] == "STABLE"
    assert link["backup_state"] == "UNCONFIGURED"
    assert ("PROVIDED_BY", link_uid, "pnet:mpls:core-l3vpn") in rels


def test_normalize_reads_a_public_wireless_link_as_lte() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    ent["edges"][0]["links"].append(_link("l-br-lte", "CELL1", "100.64.0.2", "Mobile"))
    ent["edge_details"]["e-br"]["modules"]["WAN"]["data"]["links"].append(
        _wan_link("l-br-lte", "CELL1", mode="PUBLIC", access="WIRELESS", isp="Mobile")
    )
    nodes, _ = _index(normalize_velocloud(raw))
    link = nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-lte")]
    assert link["kind"] == "lte"
    assert link["access_type"] == "WIRELESS"
    assert link["origin_config_recorded"] is True
    assert ent["edges"][0]["links"][-1]["networkType"] == "ETHERNET"


def test_a_link_no_wan_module_describes_falls_back_to_the_carrier_name() -> None:
    raw = _overlay_raw()
    raw["enterprises"][0]["edge_details"]["e-br"]["modules"] = {
        "_capability": {"status": "unavailable", "operation": PORTAL_READ_PATHS["configuration_modules"]}
    }
    nodes, _ = _index(normalize_velocloud(raw, private_carriers=PRIVATE))
    link = nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-mpls")]
    assert link["kind"] == "mpls"
    # the carrier name is a hint, never proof
    assert link["origin_config_recorded"] is False
    assert "wan_mode" not in link
    assert nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-dia")]["kind"] == "dia"
    boundary = nodes[("ForwardingBoundary", f"vco:{ENT}:edge-e-br-boundary:1")]
    assert any("no WAN module body" in gap for gap in boundary["gaps"])
    assert any(PORTAL_READ_PATHS["configuration_modules"] in gap for gap in boundary["gaps"])
    # with no carrier list at all the same link reads as internet access
    nodes, _ = _index(normalize_velocloud(raw))
    assert nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-mpls")]["kind"] == "dia"


def test_an_edge_whose_link_kind_dia_is_assumed_gets_one_warning_the_run_shows() -> None:
    """No WAN module mode and no private carrier name: the kind stays the fallback `dia` (it feeds
    the ProviderNetwork uids), and the edge gets one line in `Batch.warnings` naming such links.
    A link the carrier name classifies as mpls, and every link the WAN module describes, warns nothing."""
    raw = _overlay_raw()
    raw["enterprises"][0]["edge_details"]["e-br"]["modules"] = {
        "_capability": {"status": "unavailable", "operation": PORTAL_READ_PATHS["configuration_modules"]}
    }
    batch = normalize_velocloud(raw, private_carriers=PRIVATE)
    nodes, _ = _index(batch)
    dia = nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-dia")]
    mpls = nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-mpls")]
    assert (dia["kind"], dia["origin_config_recorded"]) == ("dia", False)
    edge = f"edge {nodes[('Device', BR)]['hostname']} (e-br)"
    tail = ": the configuration does not describe them (no WAN module mode and no private carrier name)"
    assumed = [w for w in batch.warnings if 'kind "dia" is assumed' in w]
    assert assumed == [f'{edge}: kind "dia" is assumed for WAN link {dia["name"]} (l-br-dia){tail}']
    # deterministic: the same payload gives the same text
    assert normalize_velocloud(raw, private_carriers=PRIVATE).warnings == batch.warnings
    # with no carrier list the mpls link falls back to dia too: one line for the edge, both named, sorted
    both = sorted([f"{dia['name']} (l-br-dia)", f"{mpls['name']} (l-br-mpls)"])
    assert [w for w in normalize_velocloud(raw).warnings if 'kind "dia" is assumed' in w] == [
        f'{edge}: kind "dia" is assumed for WAN links {", ".join(both)}{tail}'
    ]
    # a fully described estate warns nothing of the kind
    assert not [w for w in normalize_velocloud(_overlay_raw()).warnings if "is assumed" in w]


def test_the_assumed_dia_warning_names_at_most_ten_links_and_counts_the_rest() -> None:
    from types import SimpleNamespace

    from hst.collectors import velocloud

    edge = SimpleNamespace(name="br", eid="e-br")
    links = [f"link-{i:02d} (l-{i:02d})" for i in range(13, -1, -1)]
    line = velocloud._assumed_dia_warning(edge, links)  # type: ignore[arg-type]
    named = ", ".join(f"link-{i:02d} (l-{i:02d})" for i in range(10))
    assert line == (
        f'edge br (e-br): kind "dia" is assumed for WAN links {named} and 4 more: the configuration '
        "does not describe them (no WAN module mode and no private carrier name)"
    )


def test_normalize_writes_one_tunnel_per_wan_link_and_vpn_gateway() -> None:
    nodes, rels = _index(normalize_velocloud(_overlay_raw()))
    gateway = f"vco:{ENT}:gateway:g-1"
    assert nodes[("SdwanGateway", gateway)]["ip"] == "192.0.2.10"
    assert json.loads(nodes[("SdwanGateway", gateway)]["roles"])[0]["role"] == "VPN_TUNNEL"
    # the gateway without the VPN_TUNNEL role terminates no tunnel
    assert ("SdwanGateway", f"vco:{ENT}:gateway:g-2") not in nodes
    mpls = f"vco:{ENT}:path:e-br:l-br-mpls~gw:g-1"
    dia = f"vco:{ENT}:path:e-br:l-br-dia~gw:g-1"
    tunnel = nodes[("Tunnel", mpls)]
    assert tunnel["encap"] == "velocloud-vcmp"
    assert tunnel["endpoint_port"] == 2426
    assert tunnel["endpoint"] == "192.0.2.10"
    assert tunnel["local_address"] == "172.16.1.2"
    assert tunnel["peer_type"] == "gateway"
    assert tunnel["name"] == "OurNet GE1 to gw-1"
    assert tunnel["pair"] == uid.tunnel("velocloud-vcmp", "e-br:l-br-mpls", "gw:g-1")
    # a configured tunnel is not a proven tunnel: no state and no metric
    assert tunnel["origin_config_recorded"] is True
    assert tunnel["direction_observed"] is False
    assert not {"state", "latency_ms", "jitter_ms", "loss_pct"} & tunnel.keys()
    assert tunnel["configuration_observed_at_ms"] == 900
    assert ("ENDPOINT", mpls, uid.interface(BR, "GE1")) in rels
    assert ("TERMINATES_ON", mpls, gateway) in rels
    assert ("TERMINATES_ON", dia, gateway) in rels
    assert ("CARRIES", mpls, f"vco:{ENT}:segment:1") in rels
    # a branch-to-branch tunnel is built on demand and names no link pair
    boundary = nodes[("ForwardingBoundary", f"vco:{ENT}:edge-e-br-boundary:1")]
    assert any("no branch-to-branch Tunnel is written" in gap for gap in boundary["gaps"])


def test_normalize_writes_both_ends_of_each_tunnel_to_the_hub_a_segment_names() -> None:
    """The profile names the hub of the Global Segment. Each branch link meets
    each hub link of the same kind, private with private and public with
    public, and each end is its own tunnel."""
    nodes, rels = _index(normalize_velocloud(_overlay_raw()))
    up = f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-mpls"
    down = f"vco:{ENT}:path:e-hub:l-hub-mpls~link:e-br:l-br-mpls"
    assert nodes[("Tunnel", up)]["name"] == "OurNet GE1 to OurNet GE1"
    assert nodes[("Tunnel", up)]["peer_type"] == "hub"
    assert nodes[("Tunnel", up)]["local_address"] == "172.16.1.2"
    assert nodes[("Tunnel", up)]["endpoint"] == "172.16.9.2"
    assert nodes[("Tunnel", up)]["direction_observed"] is False
    assert nodes[("Tunnel", down)]["peer_type"] == "edge"
    assert nodes[("Tunnel", down)]["endpoint"] == "172.16.1.2"
    assert nodes[("Tunnel", up)]["pair"] == nodes[("Tunnel", down)]["pair"]
    assert ("ENDPOINT", up, uid.interface(BR, "GE1")) in rels
    assert ("TERMINATES_ON", up, uid.ip(HUB_GLOBAL, "172.16.9.2")) in rels
    assert ("ENDPOINT", down, uid.interface(HUB, "GE1")) in rels
    assert ("TERMINATES_ON", down, uid.ip(BR_GLOBAL, "172.16.1.2")) in rels
    # the profile names the hub in the Global Segment only
    assert ("CARRIES", up, f"vco:{ENT}:segment:0") in rels
    assert ("CARRIES", up, f"vco:{ENT}:segment:1") not in rels
    assert ("Tunnel", f"vco:{ENT}:path:e-br:l-br-dia~link:e-hub:l-hub-dia") in nodes
    # a private link never meets a public one, and the hub names no tunnel to itself
    assert ("Tunnel", f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-dia") not in nodes
    assert not any(label == "Tunnel" and "l-hub-mpls~link:e-hub:l-hub" in u for label, u in nodes)


def test_a_branch_meets_only_the_cluster_member_its_control_plane_assigns() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    third = json.loads(json.dumps(ent["edges"][1]))
    third.update(logicalId="e-hub2", id=3, name="hub-2", _href=_href("edges", "e-hub2"))
    for link in third["links"]:
        link["logicalId"] = link["logicalId"].replace("l-hub", "l-hub2")
        link["internalId"] = link["internalId"].replace("l-hub", "l-hub2")
    ent["edges"].append(third)
    details = ent["edge_details"]
    details["e-hub2"] = json.loads(json.dumps(details["e-hub"]))
    for row in details["e-hub2"]["modules"]["WAN"]["data"]["links"]:
        row["logicalId"] = row["logicalId"].replace("l-hub", "l-hub2")
        row["internalId"] = row["internalId"].replace("l-hub", "l-hub2")
    cluster = {"clusterLogicalId": "cl-dc", "clusterName": "DC", "members": []}
    cluster["members"] = [{"edgeLogicalId": "e-hub"}, {"edgeLogicalId": "e-hub2"}]
    for hub in ("e-hub", "e-hub2"):
        details[hub]["modules"]["controlPlane"]["data"]["memberCluster"] = cluster
    ent["profiles"][str(PROFILE_ID)]["modules"][0]["data"] = _profile_device_settings(
        [{"type": "edgeHubCluster", "logicalId": "cl-dc", "name": "DC"}]
    )
    # the branch's own control plane assigns it the second member
    details["e-br"]["modules"]["controlPlane"]["data"]["segments"] = [
        {
            "segment": {"segmentId": 0, "name": "Global Segment", "type": "REGULAR"},
            "vpn": {"dataCenterEdges": [{"logicalId": "e-hub2", "clusterLogicalId": "cl-dc"}]},
        }
    ]
    nodes, _ = _index(normalize_velocloud(raw))
    assert ("Tunnel", f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub2:l-hub2-mpls") in nodes
    assert ("Tunnel", f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-mpls") not in nodes
    # without the assignment every member is a candidate
    details["e-br"]["modules"]["controlPlane"]["data"]["segments"] = []
    nodes, _ = _index(normalize_velocloud(raw))
    assert ("Tunnel", f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-mpls") in nodes
    assert ("Tunnel", f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub2:l-hub2-mpls") in nodes


def test_two_hubs_whose_links_share_a_logical_id_get_a_tunnel_each() -> None:
    """VCO can give links on different edges the same logicalId. Each tunnel
    end names its edge as well, so the branch has its own tunnel to each hub,
    with one far end and its own pair, not one node that ends on both hubs."""
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    second = json.loads(json.dumps(ent["edges"][1]))
    second.update(logicalId="e-hub2", id=3, name="hub-2", _href=_href("edges", "e-hub2"))
    for link in second["links"]:
        # the same link logicalIds as hub-1, other addresses
        link["ipAddress"] = {"172.16.9.2": "172.16.9.6", "203.0.113.2": "203.0.113.6"}[link["ipAddress"]]
    ent["edges"].append(second)
    ent["edge_details"]["e-hub2"] = json.loads(json.dumps(ent["edge_details"]["e-hub"]))
    ent["profiles"][str(PROFILE_ID)]["modules"][0]["data"] = _profile_device_settings(
        [*HUB_REFS, {"_href": _href("edges", "e-hub2"), "name": "hub-2", "type": "edgeHubCluster"}]
    )
    nodes, rels = _index(normalize_velocloud(raw))
    to_hub = f"vco:{ENT}:path:e-br:l-br-dia~link:e-hub:l-hub-dia"
    to_hub2 = f"vco:{ENT}:path:e-br:l-br-dia~link:e-hub2:l-hub-dia"
    # each tunnel realizes the connection to its own hub
    hub2 = f"vco:{ENT}:edge:e-hub2"
    assert ("REALIZED_BY", uid.overlay_connection("velocloud-vcmp", BR, HUB), to_hub) in rels
    assert ("REALIZED_BY", uid.overlay_connection("velocloud-vcmp", BR, hub2), to_hub2) in rels
    assert nodes[("Tunnel", to_hub)]["pair"] != nodes[("Tunnel", to_hub2)]["pair"]
    hub2_global = uid.vrf(f"vco:{ENT}:edge:e-hub2", "global-segment")
    far = {t: {e for kind, s, e in rels if kind == "TERMINATES_ON" and s == t} for t in (to_hub, to_hub2)}
    assert far[to_hub] == {uid.ip(HUB_GLOBAL, "203.0.113.2")}
    assert far[to_hub2] == {uid.ip(hub2_global, "203.0.113.6")}
    # the two hub ends of those tunnels are two nodes as well
    back = f"vco:{ENT}:path:e-hub:l-hub-dia~link:e-br:l-br-dia"
    back2 = f"vco:{ENT}:path:e-hub2:l-hub-dia~link:e-br:l-br-dia"
    assert nodes[("Tunnel", back)]["pair"] == nodes[("Tunnel", to_hub)]["pair"]
    assert nodes[("Tunnel", back2)]["pair"] == nodes[("Tunnel", to_hub2)]["pair"]


def test_two_branches_whose_links_share_a_logical_id_get_a_gateway_tunnel_each() -> None:
    """The same for the tunnels to a VPN gateway: two branches with the same
    link logicalId each have their own tunnel, which ends on its own branch."""
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    second = json.loads(json.dumps(ent["edges"][0]))
    second.update(logicalId="e-br2", id=4, name="branch-2", _href=_href("edges", "e-br2"))
    ent["edges"].append(second)
    ent["edge_details"]["e-br2"] = json.loads(json.dumps(ent["edge_details"]["e-br"]))
    nodes, rels = _index(normalize_velocloud(raw))
    first = f"vco:{ENT}:path:e-br:l-br-mpls~gw:g-1"
    other = f"vco:{ENT}:path:e-br2:l-br-mpls~gw:g-1"
    # the same link names on both branches: the connection tells the branches apart
    gateway = f"vco:{ENT}:gateway:g-1"
    br2 = f"vco:{ENT}:edge:e-br2"
    assert ("REALIZED_BY", uid.overlay_connection("velocloud-vcmp", BR, gateway), first) in rels
    assert ("REALIZED_BY", uid.overlay_connection("velocloud-vcmp", br2, gateway), other) in rels
    assert nodes[("Tunnel", first)]["pair"] != nodes[("Tunnel", other)]["pair"]
    ends = {t: {e for kind, s, e in rels if kind == "ENDPOINT" and s == t} for t in (first, other)}
    assert ends[first] == {uid.interface(BR, "GE1")}
    assert ends[other] == {uid.interface(f"vco:{ENT}:edge:e-br2", "GE1")}


def test_normalize_steers_the_policy_to_the_links_its_rules_name() -> None:
    batch = normalize_velocloud(_overlay_raw(), private_carriers=PRIVATE)
    policy = f"vco:{ENT}:edge-e-br-policy:edge"
    mpls, dia = f"vco:{ENT}:edge-e-br-link:l-br-mpls", f"vco:{ENT}:edge-e-br-link:l-br-dia"
    steers = {
        (r.props["application_class"], r.end_uid): r.props.get("preference")
        for r in batch.rels
        if r.rel_type == "STEERS_VIA"
        and r.start_uid == policy
        and r.end_uid.startswith(f"vco:{ENT}:edge-e-br-link")
    }
    assert steers == {("voice", mpls): None, ("web", dia): None, ("backup", mpls): "private"}
    assert any(
        r.rel_type == "STEERS_VIA" and r.end_uid == f"vco:{ENT}:edge-e-br-boundary:1" for r in batch.rels
    )


def test_a_route_policy_steers_to_the_hub_to_its_tunnels_and_to_the_public_links() -> None:
    """`routePolicy` says where a rule's traffic leaves: `backhaul` to the hubs
    `routeCfg.backhaulEdges` names, `direct` out of the public links, `gateway`
    through the cloud gateways."""
    raw = _overlay_raw()
    profile = raw["enterprises"][0]["profiles"][str(PROFILE_ID)]
    qos = next(m for m in profile["modules"] if m["name"] == "QOS")
    qos["data"]["segments"][0]["rules"] += [
        {
            "name": "to-dc",
            "ruleLogicalId": "rule-to-dc",
            "match": {},
            "action": {
                "edge2CloudRouteAction": {
                    "routePolicy": "backhaul",
                    "routeCfg": {"backhaulEdges": HUB_REFS, "type": "edge"},
                    "linkPolicy": "auto",
                }
            },
        },
        {
            "name": "saas",
            "ruleLogicalId": "rule-saas",
            "match": {},
            "action": {"edge2CloudRouteAction": {"routePolicy": "direct", "linkPolicy": "auto"}},
        },
        {
            "name": "via-cloud",
            "ruleLogicalId": "rule-via-cloud",
            "match": {},
            "action": {"edge2CloudRouteAction": {"routePolicy": "gateway", "linkPolicy": "auto"}},
        },
    ]
    batch = normalize_velocloud(raw, private_carriers=PRIVATE)
    policy = f"vco:{ENT}:edge-e-br-policy:edge"
    steers = {
        (r.props["application_class"], r.end_uid): r.props
        for r in batch.rels
        if r.rel_type == "STEERS_VIA" and r.start_uid == policy and "route_policy" in r.props
    }
    to_hub = steers[("to-dc", HUB)]
    assert to_hub["route_policy"] == "backhaul"
    assert to_hub["route_type"] == "edge2Cloud"
    assert ("to-dc", f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-mpls") in steers
    assert ("to-dc", f"vco:{ENT}:path:e-br:l-br-dia~link:e-hub:l-hub-dia") in steers
    # the hub's end of the same tunnel is not the branch policy's
    assert ("to-dc", f"vco:{ENT}:path:e-hub:l-hub-mpls~link:e-br:l-br-mpls") not in steers
    assert steers[("saas", f"vco:{ENT}:edge-e-br-link:l-br-dia")]["route_policy"] == "direct"
    assert ("saas", f"vco:{ENT}:edge-e-br-link:l-br-mpls") not in steers
    assert steers[("via-cloud", f"vco:{ENT}:path:e-br:l-br-mpls~gw:g-1")]["route_policy"] == "gateway"
    # each route-policy edge names the segment of its rule
    assert steers[("saas", f"vco:{ENT}:edge-e-br-link:l-br-dia")]["segment_id"] != ""
    assert {p["segment_id"] for p in steers.values() if p["route_policy"] == "direct"} <= {"0", "1"}


def test_normalize_keeps_two_enterprises_apart() -> None:
    raw = _overlay_raw()
    second = json.loads(json.dumps(raw["enterprises"][0]))
    second["logicalId"], second["name"] = "ent-2", "Bolt"
    raw["enterprises"].append(second)
    nodes, _ = _index(normalize_velocloud(raw))
    assert ("Device", BR) in nodes and ("Device", "vco:ent-2:edge:e-br") in nodes
    assert nodes[("Device", "vco:ent-2:edge:e-br")]["reported_location"] == "ent-2/site-e-br"
    assert ("SdwanSegment", "vco:ent-2:segment:1") in nodes
    # the same segment name in another enterprise is another routing domain
    batch = normalize_velocloud(raw)
    domain_of = {r.start_uid: r.end_uid for r in batch.rels if r.rel_type == "MEMBER_OF"}
    assert domain_of[BR_CORP] != domain_of[uid.vrf("vco:ent-2:edge:e-br", "corp")]


# --- side tables -------------------------------------------------------------------------


def test_rib_rows_hold_one_row_per_subnet_and_edge_exit() -> None:
    rows = {(r["device_uid"], r["prefix"]): r for r in rib_rows(_overlay_raw())}
    hub = rows[(HUB, "10.20.20.0/24")]
    assert hub["vrf"] == "corp"
    assert hub["context_uid"] == HUB_CORP
    assert hub["protocol"] == "bgp"
    assert hub["next_hop"] == "10.9.8.2"
    assert hub["next_hop_context_uid"] == HUB_CORP
    assert hub["interface"] == "GE3"
    assert hub["metric"] == 20
    assert hub["discard"] is None
    assert hub["prefixlen"] == 24
    # the exit named the edge by numeric id alone; the listing resolves it
    branch = rows[(BR, "10.10.10.0/24")]
    assert branch["protocol"] == "connected"
    assert branch["next_hop"] is None
    assert branch["metric"] == 0
    # no exit and no route named a segment: the `subnet` key tail did, and it
    # matches no segment of the enterprise, so the global table holds the row
    fallback = rows[(BR, "10.30.30.0/24")]
    assert fallback["vrf"] == "Global Segment"
    assert fallback["context_uid"] == BR_GLOBAL
    assert fallback["protocol"] == "static"
    # a ROUTER exit names a local router and no device
    assert len(rows) == 3


def test_a_route_table_segment_resolves_by_the_integer_inside_the_nested_segment() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    # a third segment, named the Portal way: the integer sits inside `segment` only
    ent["profiles"][str(PROFILE_ID)]["modules"][0]["data"]["segments"].append(_segment(4, "guest"))
    ent["route_table"]["subnets"] = [
        {
            "subnet": "10.44.0.0/24:4",
            "learnedRoute": {"cidrIp": "10.44.0.0", "cidrPrefix": 24, "segmentId": 4},
            "preferredExits": [
                {"type": "CONNECTED", "exitType": "EDGE", "edgeLogicalId": "e-br", "segmentId": 4}
            ],
            "eligableExits": [],
        }
    ]
    (row,) = rib_rows(raw)
    assert row["vrf"] == "guest"
    assert row["context_uid"] == uid.vrf(BR, "guest")
    nodes, _ = _index(normalize_velocloud(raw))
    assert nodes[("SdwanSegment", f"vco:{ENT}:segment:4")]["name"] == "guest"
    assert nodes[("VrfInstance", uid.vrf(BR, "guest"))]["table_id"] == "4"


def test_a_filtered_or_unreachable_exit_carries_no_rib_row() -> None:
    raw = _overlay_raw()
    exits = raw["enterprises"][0]["route_table"]["subnets"][0]["preferredExits"]
    base = exits[0]
    exits[:] = [
        {**base, "edgeLogicalId": "e-hub", "neighborIp": "10.9.8.2", "state": "UNREACHABLE"},
        {**base, "edgeLogicalId": "e-br", "edgeId": 1, "neighborIp": "10.9.9.2", "filtered": 1},
    ]
    rows = {(r["device_uid"], r["prefix"]) for r in rib_rows(raw)}
    assert (HUB, "10.20.20.0/24") not in rows
    assert (BR, "10.20.20.0/24") not in rows
    assert (BR, "10.10.10.0/24") in rows
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    detail = collector.table_outcomes(raw)[RIB_SCOPE_KEY].detail
    assert "2 edge exits are filtered or marked UNREACHABLE" in detail


def test_the_route_table_outcome_states_the_overlay_flow_control_scope() -> None:
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    outcomes = collector.table_outcomes(_overlay_raw())
    assert set(outcomes) == {RIB_SCOPE_KEY}
    assert outcomes[RIB_SCOPE_KEY].status == "partial"
    detail = outcomes[RIB_SCOPE_KEY].detail
    assert "not the routes it learned over the overlay" in detail
    assert "1 exits name a local router" in detail
    raw = _overlay_raw()
    raw["enterprises"][0]["route_table"] = None
    outcomes = collector.table_outcomes(raw)
    assert RIB_SCOPE_KEY not in outcomes
    assert [(name, o.status) for name, o in outcomes.items()] == [("rib", "failed")]


def test_an_ipv6_prefix_survives_the_segment_split() -> None:
    raw = _overlay_raw()
    raw["enterprises"][0]["route_table"]["subnets"] = [
        {
            "subnet": "2001:db8::/32:1",
            "ipVersion": 6,
            "learnedRoute": {"cidrIp": "2001:db8::", "cidrPrefix": 32, "segmentId": 1},
            "preferredExits": [
                {"type": "CONNECTED", "exitType": "EDGE", "edgeLogicalId": "e-br", "segmentId": 1}
            ],
            "eligableExits": [],
        }
    ]
    rows = rib_rows(raw)
    assert [r["prefix"] for r in rows] == ["2001:db8::/32"]
    assert rows[0]["af"] == 6
    assert rows[0]["vrf"] == "corp"


def test_bgp_session_rows_join_on_the_configured_session_uid() -> None:
    rows = bgp_session_rows(_overlay_raw())
    by_peer = {r["peer_ip"]: r for r in rows}
    ru = uid.routing_process(BR, "corp", "bgp")
    # the resource carries no segment: the configured neighbor names the VRF
    assert by_peer["10.9.9.2"]["session_uid"] == uid.bgp_session(ru, "10.9.9.2", "corp")
    assert by_peer["10.9.9.2"]["context_uid"] == BR_CORP
    assert by_peer["10.9.9.2"]["state"] == "ESTABLISHED"
    assert by_peer["10.9.9.2"]["prefixes_received"] == 12
    # the bgp_sessions schema has no column for the relative up/down time
    assert "up_down_time" not in by_peer["10.9.9.2"]
    # an unconfigured neighbor falls back to the global table
    assert by_peer["10.9.9.99"]["context_uid"] == BR_GLOBAL
    assert by_peer["10.9.9.99"]["established_since_ms"] is None


def test_bgp_session_rows_keep_the_newest_row_of_a_session() -> None:
    """The resource keeps a row per state it recorded for one neighbor."""
    raw = _overlay_raw()
    sessions = raw["enterprises"][0]["bgp_sessions"]
    current = next(r for r in sessions if r["neighborIp"] == "10.9.9.2")
    current["timestamp"] = "2026-08-01T10:00:00.000Z"
    sessions.append({**current, "state": "CONNECT", "pfxRcvd": 0, "timestamp": "2021-02-01T10:00:00.000Z"})
    rows = [r for r in bgp_session_rows(raw) if r["peer_ip"] == "10.9.9.2"]
    assert len(rows) == 1
    assert rows[0]["state"] == "ESTABLISHED"
    assert rows[0]["prefixes_received"] == 12


def test_an_eligible_exit_carries_no_rib_row() -> None:
    raw = _overlay_raw()
    record = raw["enterprises"][0]["route_table"]["subnets"][0]
    base = record["preferredExits"][0]
    record["preferredExits"] = [{**base, "edgeLogicalId": "e-br", "edgeId": 1, "neighborIp": "10.9.9.2"}]
    record["eligableExits"] = [{**base, "edgeLogicalId": "e-hub", "neighborIp": "10.9.8.2"}]
    rows = {(r["device_uid"], r["prefix"]) for r in rib_rows(raw)}
    assert (BR, "10.20.20.0/24") in rows
    assert (HUB, "10.20.20.0/24") not in rows
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    detail = collector.table_outcomes(raw)[RIB_SCOPE_KEY].detail
    assert "eligible exits are backups the orchestrator did not select and carry no row" in detail


def test_the_device_role_is_the_sdwan_role_and_never_router() -> None:
    nodes, _ = _index(normalize_velocloud(_overlay_raw()))
    assert nodes[("Device", HUB)]["role"] == "sdwan-hub"
    assert nodes[("Device", BR)]["role"] == "sdwan-edge"


def _named_links_raw() -> dict:
    """The overlay with WAN link names that name no port. A deep copy: the
    `WAN` rows of `_overlay_raw` are shared module-level dicts."""
    raw = json.loads(json.dumps(_overlay_raw()))
    names = {"l-br-mpls": "MPLS", "l-br-dia": "Internet", "l-hub-mpls": "MPLS", "l-hub-dia": "DC Internet"}
    for detail in raw["enterprises"][0]["edge_details"].values():
        for row in detail["modules"]["WAN"]["data"]["links"]:
            row["name"] = names.get(row["logicalId"], row["name"])
    return raw


def test_a_tunnel_is_named_by_its_two_wan_links_without_hostnames_or_ports() -> None:
    """A tunnel is one link path in one direction. Its name is the two WAN link
    names: the hostnames are on the devices and the local port is the
    `ENDPOINT` interface."""
    nodes, rels = _index(normalize_velocloud(_named_links_raw()))
    up = f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-mpls"
    down = f"vco:{ENT}:path:e-hub:l-hub-mpls~link:e-br:l-br-mpls"
    dia = f"vco:{ENT}:path:e-br:l-br-dia~link:e-hub:l-hub-dia"
    gateway = f"vco:{ENT}:path:e-br:l-br-mpls~gw:g-1"
    assert nodes[("Tunnel", up)]["name"] == "MPLS to MPLS"
    assert nodes[("Tunnel", down)]["name"] == "MPLS to MPLS"
    assert nodes[("Tunnel", dia)]["name"] == "Internet to DC Internet"
    assert nodes[("Tunnel", gateway)]["name"] == "MPLS to gw-1"
    tunnels = [props for (label, _), props in nodes.items() if label == "Tunnel"]
    assert tunnels
    for props in tunnels:
        assert "short_name" not in props
        assert not {"GE1", "GE2", "branch-1", "hub-1"} & set(props["name"].split())
    # the port is on the ENDPOINT edge
    assert ("ENDPOINT", up, uid.interface(BR, "GE1")) in rels


def test_a_tunnel_name_falls_back_to_the_link_name_the_wan_link_carries() -> None:
    """A WAN row with no name: the tunnel takes the `WanLink` name, which is
    the listing `displayName` then."""
    raw = _named_links_raw()
    for row in raw["enterprises"][0]["edge_details"]["e-br"]["modules"]["WAN"]["data"]["links"]:
        if row["logicalId"] == "l-br-mpls":
            del row["name"]
    nodes, _ = _index(normalize_velocloud(raw))
    link = nodes[("WanLink", f"vco:{ENT}:edge-e-br-link:l-br-mpls")]
    assert link["name"] == "OurNet GE1"
    up = f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-mpls"
    assert nodes[("Tunnel", up)]["name"] == "OurNet GE1 to MPLS"


def _between(batch, conn: str) -> dict[str, tuple[str, str, dict]]:
    """The `BETWEEN` edges of one connection by `end`: (label, uid, props)."""
    return {
        r.props["end"]: (r.end_label, r.end_uid, r.props)
        for r in batch.rels
        if r.rel_type == "BETWEEN" and r.start_uid == conn
    }


def test_one_overlay_connection_per_pair_of_edges_realized_by_both_directions() -> None:
    """One undirected `OverlayConnection` between the branch and the hub. Every
    tunnel of the pair, both directions and every link pair, realizes it."""
    batch = normalize_velocloud(_named_links_raw())
    nodes, rels = _index(batch)
    conn = uid.overlay_connection("velocloud-vcmp", BR, HUB)
    assert conn == f"oconn:velocloud-vcmp:{BR}~{HUB}"
    assert uid.overlay_connection("velocloud-vcmp", HUB, BR) == conn
    props = nodes[("OverlayConnection", conn)]
    assert props["kind"] == "tunnel"
    assert props["technology"] == "velocloud-vcmp"
    assert props["name"] == "branch-1 to hub-1"
    assert not {"bandwidth_mbps", "upstream_mbps", "qos_class"} & props.keys()
    # one connection between the two edges, whatever the links
    between_br_hub = [
        u
        for label, u in nodes
        if label == "OverlayConnection" and {e[1] for e in _between(batch, u).values()} == {BR, HUB}
    ]
    assert between_br_hub == [conn]
    hub_tunnels = {u for label, u in nodes if label == "Tunnel" and "~link:" in u}
    assert len(hub_tunnels) == 4  # two link pairs, both directions
    assert {t for kind, s, t in rels if kind == "REALIZED_BY" and s == conn} == hub_tunnels
    ends = _between(batch, conn)
    assert ends["a"][:2] == ("Device", BR) and ends["a"][2]["role"] == "edge"
    assert ends["b"][:2] == ("Device", HUB) and ends["b"][2]["role"] == "hub"
    # no bandwidth and no QoS on the ends; the branch reports, the hub does not
    assert set(ends["a"][2]) == {"end", "role", "reported"}
    assert ends["a"][2]["reported"] is True and ends["b"][2]["reported"] is False


def test_overlay_connection_observed_from_names_the_ends_that_report_it() -> None:
    """Only the branch's configuration names the hub, so only end `a` reports
    the connection. When the hub names the branch as well, both ends do."""
    batch = normalize_velocloud(_named_links_raw())
    nodes, _ = _index(batch)
    conn = uid.overlay_connection("velocloud-vcmp", BR, HUB)
    assert nodes[("OverlayConnection", conn)]["observed_from"] == ["a"]
    raw = _named_links_raw()
    ent = raw["enterprises"][0]
    ent["profiles"][str(PROFILE_ID)]["modules"][0]["data"] = _profile_device_settings(
        [*HUB_REFS, {"_href": _href("edges", "e-br"), "name": "branch-1", "type": "edgeHub"}]
    )
    nodes, _ = _index(normalize_velocloud(raw))
    assert nodes[("OverlayConnection", conn)]["observed_from"] == ["a", "b"]


def test_a_gateway_connection_ends_on_the_sdwan_gateway() -> None:
    """The edge and its VPN gateway: one connection, realized by the tunnel of
    every WAN link to that gateway. Only the edge reports it."""
    batch = normalize_velocloud(_named_links_raw())
    nodes, rels = _index(batch)
    gateway = f"vco:{ENT}:gateway:g-1"
    conn = uid.overlay_connection("velocloud-vcmp", BR, gateway)
    props = nodes[("OverlayConnection", conn)]
    assert props["name"] == "branch-1 to gw-1"
    assert props["observed_from"] == ["a"]
    ends = _between(batch, conn)
    assert ends["a"][:2] == ("Device", BR) and ends["a"][2]["role"] == "edge"
    assert ends["b"][:2] == ("SdwanGateway", gateway) and ends["b"][2]["role"] == "gateway"
    assert {t for kind, s, t in rels if kind == "REALIZED_BY" and s == conn} == {
        f"vco:{ENT}:path:e-br:l-br-mpls~gw:g-1",
        f"vco:{ENT}:path:e-br:l-br-dia~gw:g-1",
    }
    # a gateway without the VPN_TUNNEL role terminates no tunnel and has no connection
    assert not any(
        label == "OverlayConnection" and u.endswith(f"vco:{ENT}:gateway:g-2") for label, u in nodes
    )


def test_a_hub_with_no_wan_body_has_no_overlay_connection_to_the_branch() -> None:
    """No tunnel is written, so no connection is: a connection always has a
    tunnel that realizes it."""
    raw = _named_links_raw()
    raw["enterprises"][0]["edge_details"]["e-hub"]["modules"] = {
        "_capability": {"status": "unavailable", "operation": PORTAL_READ_PATHS["configuration_modules"]}
    }
    nodes, _ = _index(normalize_velocloud(raw))
    assert ("OverlayConnection", uid.overlay_connection("velocloud-vcmp", BR, HUB)) not in nodes


def test_a_segment_static_route_is_a_route_of_the_boundary_and_not_of_the_table():
    from hst.collectors.util import GraphBuilder
    from hst.collectors.velocloud import _static_routes

    class _Ent:
        segments = [{"id": "0", "keys": {"0", "Global Segment"}}, {"id": "6", "keys": {"6", "Internet"}}]

    class _E:
        b = GraphBuilder()
        ent = _Ent()
        enterprise = ENT
        eid = "e-hub"

    route = {
        "destination": "0.0.0.0",  # noqa: S104 - a route destination, not a bind
        "cidrPrefix": "0",
        "gateway": "10.18.55.33",
        "wanInterface": "SFP1",
        "subinterfaceId": 801,
        "cost": 0,
        "preferred": False,
        "advertise": False,
        "description": "Static default route towards Hosting ",
    }
    data = {
        "segments": [
            {"segment": {"segmentId": 0, "name": "Global Segment"}, "routes": {"static": [route]}},
            {
                "segment": {"segmentId": 6, "name": "Internet"},
                "routes": {"static": [{**route, "gateway": "10.18.59.166", "subinterfaceId": None}]},
            },
        ]
    }
    edge = _E()
    _static_routes(edge, data, "0", "fb-0")
    routes = [n.props for n in edge.b._nodes.values() if n.label == "SdwanStaticRoute"]
    assert routes == [
        {
            "cidr": "0.0.0.0/0",
            "next_hop": "10.18.55.33",
            "interface": "SFP1:801",
            "cost": 0,
            "preferred": False,
            "advertise": False,
            "description": "Static default route towards Hosting ",
            "segment_id": "0",
        }
    ]
    rels = [(r.rel_type, r.start_uid) for r in edge.b._rels.values()]
    assert rels == [("HAS_ROUTE", "fb-0")]
    _static_routes(edge, data, "6", "fb-6")
    other = [n.props for n in edge.b._nodes.values() if n.props.get("segment_id") == "6"]
    assert [(r["next_hop"], r["interface"]) for r in other] == [("10.18.59.166", "SFP1")]


def test_a_hub_the_branch_control_plane_names_as_an_edge_hub_gets_its_tunnels() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    ent["profiles"][str(PROFILE_ID)]["modules"][0]["data"] = _profile_device_settings([])
    control = ent["edge_details"]["e-br"]["modules"]["controlPlane"]["data"]
    control["segments"] = []
    up = f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-mpls"
    nodes, _ = _index(normalize_velocloud(raw))
    assert ("Tunnel", up) not in nodes
    control["segments"] = [
        {
            "segment": {"segmentId": 0, "name": "Global Segment", "type": "REGULAR"},
            "vpn": {"dataCenterEdges": [{"name": "hub-1_10_1_1", "type": "edgeHub", "logicalId": "e-hub"}]},
        }
    ]
    nodes, rels = _index(normalize_velocloud(raw))
    assert nodes[("Tunnel", up)]["peer_type"] == "hub"
    assert ("CARRIES", up, f"vco:{ENT}:segment:0") in rels
    # a cluster row of the same list adds nothing: it is the `vpnHubs` cluster again
    control["segments"][0]["vpn"]["dataCenterEdges"][0]["type"] = "edgeHubCluster"
    nodes, _ = _index(normalize_velocloud(raw))
    assert ("Tunnel", up) not in nodes


def test_static_v6_rows_and_a_netmask_only_row_are_read():
    from hst.collectors.util import GraphBuilder
    from hst.collectors.velocloud import _static_routes

    class _Ent:
        segments = [{"id": "0", "keys": {"0", "Global Segment"}}]

    class _E:
        b = GraphBuilder()
        ent = _Ent()
        enterprise = ENT
        eid = "e-br"

    v4 = {"destination": "10.40.0.0", "netmask": "255.255.0.0", "gateway": "10.1.1.1", "wanInterface": "GE3"}
    v6 = {"destination": "2001:db8:40::", "cidrPrefix": "48", "gateway": "2001:db8::1", "wanInterface": "GE3"}
    data = {"segments": [{"segment": {"segmentId": 0}, "routes": {"static": [v4], "staticV6": [v6]}}]}
    edge = _E()
    _static_routes(edge, data, "0", "fb-0")
    cidrs = sorted(n.props["cidr"] for n in edge.b._nodes.values() if n.label == "SdwanStaticRoute")
    assert cidrs == ["10.40.0.0/16", "2001:db8:40::/48"]


def test_a_hub_with_no_wan_body_writes_a_gap_on_both_boundaries_and_no_hub_tunnel() -> None:
    raw = _overlay_raw()
    raw["enterprises"][0]["edge_details"]["e-hub"]["modules"] = {
        "_capability": {"status": "unavailable", "operation": PORTAL_READ_PATHS["configuration_modules"]}
    }
    nodes, _ = _index(normalize_velocloud(raw))
    assert not [k for k in nodes if k[0] == "Tunnel" and "~link:" in k[1]]
    gaps = {
        eid: [
            g
            for k, n in nodes.items()
            if k[0] == "ForwardingBoundary" and f"edge-{eid}-" in k[1]
            for g in n.get("gaps") or []
        ]
        for eid in ("e-br", "e-hub")
    }
    assert "no Tunnel to hub-1 is written: hub-1 has no WAN module body" in gaps["e-br"]
    assert "no Tunnel to branch-1 is written: hub-1 has no WAN module body" in gaps["e-hub"]


def test_two_edges_that_name_each_other_keep_the_peer_type_of_the_far_role() -> None:
    raw = _overlay_raw()
    ent = raw["enterprises"][0]
    ent["profiles"][str(PROFILE_ID)]["modules"][0]["data"] = _profile_device_settings(
        [*HUB_REFS, {"_href": _href("edges", "e-br"), "name": "branch-1", "type": "edgeHub"}]
    )
    nodes, _ = _index(normalize_velocloud(raw))
    to_hub = nodes[("Tunnel", f"vco:{ENT}:path:e-br:l-br-mpls~link:e-hub:l-hub-mpls")]
    assert to_hub["peer_type"] == "hub"


def test_the_topology_query_counts_gateway_tunnels_apart_from_hub_tunnels() -> None:
    from hst.queries import QUERIES

    cypher = next(q for q in QUERIES if q["key"] == "sdwan-topology")["cypher"]
    assert "count(DISTINCT CASE WHEN gw IS NOT NULL THEN t END) AS gateway_tunnels" in cypher
    assert "AS hub_tunnels" in cypher
    paths = next(q for q in QUERIES if q["key"] == "sdwan-paths")
    assert "a hub or a branch" in paths["description"]
    assert "far_edge" in paths["cypher"]


def test_the_topology_query_counts_overlay_connections_and_names_the_peers() -> None:
    """The connections of an edge are the `OverlayConnection`s it is an end of:
    one per hub or gateway, however many tunnels realize each."""
    from hst.queries import QUERIES

    cypher = next(q for q in QUERIES if q["key"] == "sdwan-topology")["cypher"]
    assert "OPTIONAL MATCH (d)<-[cb:BETWEEN]-(c:OverlayConnection)" in cypher
    assert "count(DISTINCT c) AS connections" in cypher
    assert "AS peers" in cypher
    # the tunnel counts are taken before the connections are read
    assert cypher.index("AS hub_tunnels") < cypher.index("(c:OverlayConnection)")
