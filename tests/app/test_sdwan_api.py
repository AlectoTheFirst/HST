"""/api/sdwan: viewer surface, Neo4j faked at the module seam."""

import contextlib

from tests.app.conftest import login

import hst.app.routes.sdwan as route

EDGE = "vco:ent:edge:e1"
HUB = "vco:ent:edge:h1"
GW = "vco:ent:gateway:g1"


class _FakeSession:
    """Answers the pointer read and each route read from a map of Cypher
    constant to rows. A read that is not in the map gives no rows."""

    def __init__(self, rows):
        self._rows = rows
        self.params: dict[str, dict] = {}

    def run(self, cypher, **params):
        if "CyclePointer" in cypher:
            rows = [{"current": 4242}]
        else:
            self.params[cypher] = params
            rows = self._rows.get(cypher, [])

        class _Result:
            def data(self):
                return rows

        return _Result()


def _install(monkeypatch, rows):
    fake = _FakeSession(rows)

    @contextlib.contextmanager
    def cm(settings):
        yield fake

    monkeypatch.setattr(route, "_session", cm)
    return fake


def _tunnel(uid, interface, hub=None, gateway=None):
    return {
        "uid": uid,
        "interface": interface,
        "peer_type": "hub" if hub else "gateway",
        "hub": hub,
        "hub_name": "HUB-1" if hub else None,
        "gateway": gateway,
        "gateway_name": "GW-1" if gateway else None,
        "peer_ip": "203.0.113.1" if hub else None,
    }


TOPOLOGY = {
    route._EDGE: [{"uid": EDGE, "name": "EDGE-1", "model": "edge3800"}],
    route._LINKS: [{"uid": "l1", "name": "BT", "interface": "GE3", "provider": "BT"}],
    # the tunnel to the hub gives 2 rows: the interface and the WAN link hold the address
    route._TUNNELS: [
        _tunnel("t1", "GE3", hub=HUB),
        _tunnel("t1", "GE3", hub=HUB),
        _tunnel("t2", "GE3", gateway=GW),
    ],
    route._HUB_CABLES: [{"a_dev": HUB, "a_port": "GE5", "b_dev": "dev:sw1", "b_port": "Ethernet1/1"}],
    route._HUB_SITES: [{"site": "FR2"}],
    route._SITE_DEVICES: [
        {"uid": HUB, "name": "HUB-1", "platform": "velocloud-edge", "site": "FR2", "site_name": "FR2"},
        {"uid": "dev:sw1", "name": "SW-1", "platform": "nxos", "site": "FR2", "site_name": "FR2"},
        {"uid": "dev:sw2", "name": "SW-2", "platform": "nxos", "site": "FR2", "site_name": "FR2"},
    ],
    route._SITE_CABLES: [
        {
            "a_dev": "dev:sw1",
            "a_port": "Ethernet1/101",
            "b_dev": "dev:sw2",
            "b_port": "Ethernet1/101",
            "source": "cdp",
        }
    ],
    route._POLICY: [
        {
            "uid": "p1",
            "name": "Business Policy",
            "rule_count": 1,
            "capability_gap": None,
            "rules": [{"uid": "r1", "_run_id": "x", "collection_ts": 4242, "name": "voice", "position": 1}],
        }
    ],
}


async def test_sdwan_requires_auth(client):
    assert (await client.get("/api/sdwan/edges")).status_code == 401
    assert (await client.get("/api/sdwan/topology", params={"edge": EDGE})).status_code == 401


async def test_the_edge_list_reads_at_the_current_run(client, monkeypatch):
    await login(client, "vera")
    fake = _install(monkeypatch, {route._EDGES: [{"uid": EDGE, "name": "EDGE-1", "role": None}]})
    r = await client.get("/api/sdwan/edges")
    assert r.status_code == 200
    assert r.json() == {"edges": [{"uid": EDGE, "name": "EDGE-1", "role": None}]}
    assert fake.params[route._EDGES]["snap"] == 4242


async def test_an_unknown_edge_is_a_404(client, monkeypatch):
    await login(client, "vera")
    _install(monkeypatch, {})
    r = await client.get("/api/sdwan/topology", params={"edge": "vco:ent:edge:nope"})
    assert r.status_code == 404


async def test_the_topology_joins_tunnels_hubs_sites_and_cables(client, monkeypatch):
    await login(client, "vera")
    fake = _install(monkeypatch, TOPOLOGY)
    r = await client.get("/api/sdwan/topology", params={"edge": EDGE})
    assert r.status_code == 200
    body = r.json()
    assert body["edge"]["name"] == "EDGE-1"
    assert body["links"][0]["interface"] == "GE3"
    assert body["tunnels"] == [
        {"uid": "t1", "interface": "GE3", "peer": HUB, "peer_kind": "hub", "peer_ip": "203.0.113.1"},
        {"uid": "t2", "interface": "GE3", "peer": GW, "peer_kind": "gateway", "peer_ip": None},
    ]
    assert body["hubs"] == [{"uid": HUB, "name": "HUB-1", "site": "FR2"}]
    assert body["gateways"] == [{"uid": GW, "name": "GW-1"}]
    # only the devices one cable hop from a hub are drawn; SW-2 is counted
    assert [d["uid"] for d in body["devices"]] == ["dev:sw1"]
    assert body["sites"] == [{"code": "FR2", "name": "FR2", "other_devices": 1}]
    assert {(c["a_dev"], c["b_dev"]) for c in body["cables"]} == {(HUB, "dev:sw1")}
    assert fake.params[route._HUB_CABLES]["hubs"] == [HUB]
    assert fake.params[route._SITE_CABLES]["devices"] == ["dev:sw1"]


async def test_the_policy_rules_drop_the_loader_properties(client, monkeypatch):
    await login(client, "vera")
    _install(monkeypatch, TOPOLOGY)
    body = (await client.get("/api/sdwan/topology", params={"edge": EDGE})).json()
    assert body["policy"]["rule_count"] == 1
    assert body["policy"]["rules"] == [{"name": "voice", "position": 1}]


async def test_an_edge_without_tunnels_reads_no_hub_data(client, monkeypatch):
    await login(client, "vera")
    fake = _install(monkeypatch, {route._EDGE: [{"uid": EDGE, "name": "EDGE-1"}]})
    body = (await client.get("/api/sdwan/topology", params={"edge": EDGE})).json()
    assert body["hubs"] == [] and body["cables"] == [] and body["policy"] is None
    assert route._HUB_CABLES not in fake.params


BRANCH_1 = "vco:ent:edge:b1"
BRANCH_2 = "vco:ent:edge:b2"
HUB_2 = "vco:ent:edge:h2"


def _hub_end(uid, interface, far, name, peer_type="edge", role=None):
    """One tunnel row of a picked hub. The collector writes the hub end of a
    branch and hub pair with peer_type "edge", ending on the branch address."""
    return {
        "uid": uid,
        "interface": interface,
        "peer_type": peer_type,
        "hub": far,
        "hub_name": name,
        "hub_role": role,
        "gateway": None,
        "gateway_name": None,
        "peer_ip": "198.51.100.1",
    }


HUB_PICKED = {
    route._EDGE: [{"uid": HUB, "name": "HUB-1", "role": "hub"}],
    route._TUNNELS: [
        _hub_end("t1", "GE3", BRANCH_1, "BR-1"),
        _hub_end("t2", "GE4", BRANCH_1, "BR-1"),
        _hub_end("t3", "GE3", BRANCH_2, "BR-2"),
        # a hub to hub pair: the far device is a hub whatever the peer_type
        _hub_end("t4", "GE3", HUB_2, "HUB-2", role="hub"),
    ],
    route._BRANCH_SITES: [{"uid": BRANCH_1, "site": "BER"}],
    route._HUB_SITES: [{"site": "FR6"}],
    route._SITE_DEVICES: [
        {"uid": HUB_2, "name": "HUB-2", "platform": "velocloud-edge", "site": "FR6", "site_name": "FR6"},
    ],
}


async def test_a_picked_hub_lists_its_branches_apart_from_the_hubs(client, monkeypatch):
    await login(client, "vera")
    fake = _install(monkeypatch, HUB_PICKED)
    body = (await client.get("/api/sdwan/topology", params={"edge": HUB})).json()
    assert body["hubs"] == [{"uid": HUB_2, "name": "HUB-2", "site": "FR6"}]
    assert body["branches"] == [
        {"uid": BRANCH_2, "name": "BR-2", "site": None},
        {"uid": BRANCH_1, "name": "BR-1", "site": "BER"},
    ]
    assert [(t["uid"], t["peer"], t["peer_kind"]) for t in body["tunnels"]] == [
        ("t1", BRANCH_1, "branch"),
        ("t2", BRANCH_1, "branch"),
        ("t3", BRANCH_2, "branch"),
        ("t4", HUB_2, "hub"),
    ]
    # the site, device and cable reads name the hubs only, never the branches
    assert fake.params[route._HUB_CABLES]["hubs"] == [HUB_2]
    assert fake.params[route._HUB_SITES]["hubs"] == [HUB_2]
    assert fake.params[route._SITE_DEVICES]["sites"] == ["FR6"]
    assert fake.params[route._BRANCH_SITES]["branches"] == [BRANCH_1, BRANCH_2]
    assert [d["uid"] for d in body["devices"]] == []


async def test_a_hub_with_branch_tunnels_only_reads_no_hub_data(client, monkeypatch):
    await login(client, "vera")
    rows = {**HUB_PICKED, route._TUNNELS: HUB_PICKED[route._TUNNELS][:3]}
    fake = _install(monkeypatch, rows)
    body = (await client.get("/api/sdwan/topology", params={"edge": HUB})).json()
    assert body["hubs"] == [] and body["sites"] == [] and body["cables"] == []
    assert [b["uid"] for b in body["branches"]] == [BRANCH_2, BRANCH_1]
    for read in (route._HUB_CABLES, route._HUB_SITES, route._SITE_DEVICES, route._SITE_CABLES):
        assert read not in fake.params


async def test_a_refused_policy_read_gives_a_null_rule_count(client, monkeypatch):
    await login(client, "vera")
    gap = '{"operation":"/portal/rest/enterprise/getEnterpriseConfigurations","status":"unavailable"}'
    policy = {"uid": "p1", "name": "Business Policy", "rule_count": None, "capability_gap": gap, "rules": []}
    _install(monkeypatch, {**TOPOLOGY, route._POLICY: [policy]})
    body = (await client.get("/api/sdwan/topology", params={"edge": EDGE})).json()
    assert body["policy"]["rule_count"] is None
    assert body["policy"]["capability_gap"] == gap


async def test_every_topology_read_receives_the_snapshot(client, monkeypatch):
    await login(client, "vera")
    fake = _install(monkeypatch, TOPOLOGY)
    r = await client.get("/api/sdwan/topology", params={"edge": EDGE})
    assert r.status_code == 200
    reads = [c for c in fake.params if "CyclePointer" not in c]
    assert len(reads) >= 8
    assert all(fake.params[c]["snap"] == 4242 for c in reads)


async def test_a_branch_tunnel_row_with_peer_type_edge_is_a_branch(client, monkeypatch):
    await login(client, "vera")
    rows = dict(TOPOLOGY)
    rows[route._TUNNELS] = [
        {**_tunnel("t3", "GE3", hub="vco:ent:edge:b2"), "peer_type": "edge", "hub_role": None}
    ]
    fake = _install(monkeypatch, rows)
    body = (await client.get("/api/sdwan/topology", params={"edge": HUB})).json()
    assert body["tunnels"][0]["peer_kind"] == "branch"
    assert fake.params[route._BRANCH_SITES]["branches"] == ["vco:ent:edge:b2"]
