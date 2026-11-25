"""/api/topology: viewer surface, Neo4j faked at the module seam."""

import contextlib

import pytest
from tests.app.conftest import login

import hst.app.routes.topology as topology_route
from hst.core import cycle as cyclemod


@pytest.fixture(autouse=True)
def _no_run_node(monkeypatch):
    """These fakes hold no `:CycleRun` node, as a fixture load does: the reader
    lease's pruned-run check (routes/run_lease.py) reads the graph as it is."""
    monkeypatch.setattr(cyclemod, "run_present", lambda s, cts: False)


SNAP = 4242


class _FakeSession:
    """Answers the pointer read and the route's reads by query text. The route
    reads in a timed read transaction (`execute_read`), which runs here on the
    session itself."""

    def __init__(self, rows):
        self._rows = rows
        self.params: dict[str, dict] = {}

    def execute_read(self, work):
        return work(self)

    def run(self, cypher, **params):
        if "CyclePointer" in cypher:
            rows = [{"current": SNAP}]
        else:
            self.params[cypher] = params
            rows = self._rows.get(cypher, [])

        class _Result:
            def data(self):
                return rows

        return _Result()


def _seam(monkeypatch, rows):
    session = _FakeSession(rows)

    @contextlib.contextmanager
    def cm(settings):
        yield session

    monkeypatch.setattr(topology_route, "_session", cm)
    return session


def _dev(uid, tier, site="ber1"):
    return {
        "uid": uid,
        "name": uid,
        "role": "router",
        "tier": tier,
        "role_basis": "hostname",
        "site": site,
        "vendor": None,
        "model": None,
    }


async def test_topology_requires_auth(client):
    r = await client.get("/api/topology")
    assert r.status_code == 401


async def test_topology_plans_the_rows_of_one_snapshot(client, monkeypatch):
    await login(client, "vera")
    session = _seam(
        monkeypatch,
        {
            topology_route._SITE_DEVICES: [_dev("rth-01", "sdwan-hub"), _dev("swc-01", "core")],
            topology_route._CABLES: [
                {
                    "a_dev": "swc-01",
                    "a_port": "Eth1/1",
                    "a_name": "swc-01",
                    "b_dev": "rth-01",
                    "b_port": "GE1",
                    "b_name": "rth-01",
                    "source": "lldp",
                },
            ],
            topology_route._WAN_DEVICES: [{"dev": "rth-01"}],
        },
    )

    r = await client.get("/api/topology", params=[("site", "ber1"), ("site", "ham2")])

    assert r.status_code == 200
    body = r.json()
    assert body["snapshot"] == SNAP
    nodes = {n["id"]: n for n in body["nodes"]}
    assert nodes["rth-01"]["parent"] == "block:ber1:wan-edge"
    assert nodes["swc-01"]["parent"] == "block:ber1:campus"
    [cable] = body["cables"]
    assert cable["from"] == {"dev": "rth-01", "port": "GE1"}
    # every read is pinned to the one resolved snapshot, and the device read takes the sites
    assert {p["snap"] for p in session.params.values()} == {SNAP}
    assert session.params[topology_route._SITE_DEVICES]["site"] == ["site:ber1", "site:ham2"]


async def test_topology_with_no_site_reads_every_device(client, monkeypatch):
    await login(client, "vera")
    session = _seam(monkeypatch, {})

    r = await client.get("/api/topology")

    assert r.status_code == 200
    assert r.json()["nodes"] == []
    assert session.params[topology_route._DEVICES]["site"] is None


async def test_topology_carries_the_overlays_clients_and_freshness_of_the_drawn_devices(client, monkeypatch):
    """What the device map drew over the boxes comes with the drawing: the
    endpoints per device and SSID, the VLAN and subnet facts, and whether the
    run observed each device. Rows of a device outside the drawing are dropped."""
    await login(client, "vera")
    swc = {**_dev("swc-01", "core"), "carried": True, "carried_reason": "failed", "last_seen": 1000}
    _seam(
        monkeypatch,
        {
            topology_route._SITE_DEVICES: [swc],
            topology_route._CLIENTS: [
                {"dev": "swc-01", "ssid": None, "name": "nas", "uid": "ep:1", "ips": ["10.0.0.5"]},
                {"dev": "elsewhere", "ssid": None, "name": "x", "uid": "ep:2", "ips": []},
            ],
            topology_route._VLANS: [
                {
                    "dev": "swc-01",
                    "port": "Eth1/1",
                    "svi": False,
                    "vid": 10,
                    "name": "users",
                    "native": False,
                    "segment": None,
                },
                {
                    "dev": "elsewhere",
                    "port": "1",
                    "svi": False,
                    "vid": 10,
                    "name": None,
                    "native": False,
                    "segment": None,
                },
            ],
            topology_route._SUBNETS: [
                {
                    "dev": "swc-01",
                    "iface": "Vlan10",
                    "ip": "10.0.0.1",
                    "cidr": "10.0.0.0/24",
                    "af": 4,
                    "vrf": "default",
                    "domain": None,
                    "fhrp": None,
                },
            ],
        },
    )

    body = (await client.get("/api/topology", params={"site": "ber1"})).json()

    node = next(n for n in body["nodes"] if n["id"] == "swc-01")
    assert (node["carried"], node["carried_reason"], node["last_seen"], node["tables"]) == (
        True,
        "failed",
        1000,
        {},
    )
    assert body["clients"] == [
        {
            "dev": "swc-01",
            "port": None,
            "ssid": None,
            "count": 1,
            "by_bd": {},
            "clients": [
                {
                    "name": "nas",
                    "uid": "ep:1",
                    "ips": ["10.0.0.5"],
                    "mac": None,
                    "wired": None,
                    "vendor": None,
                    "last_seen": None,
                    "bd": None,
                }
            ],
        }
    ]
    assert [(v["dev"], v["vid"], v["ports"]) for v in body["vlans"]] == [("swc-01", 10, ["Eth1/1"])]
    assert [s["cidr"] for s in body["subnets"]] == ["10.0.0.0/24"]


async def test_topology_caps_the_sample_of_a_client_group(client, monkeypatch):
    """A device with hundreds of clients states the count and lists the first
    SAMPLE_CLIENTS of them, so the payload stays proportional to the drawing."""
    await login(client, "vera")
    many = [
        {"dev": "swc-01", "ssid": "corp", "name": f"c{i}", "uid": f"ep:{i}", "ips": []}
        for i in range(topology_route.SAMPLE_CLIENTS + 20)
    ]
    _seam(monkeypatch, {topology_route._DEVICES: [_dev("swc-01", "core")], topology_route._CLIENTS: many})

    [group] = (await client.get("/api/topology")).json()["clients"]
    assert group["count"] == topology_route.SAMPLE_CLIENTS + 20
    assert len(group["clients"]) == topology_route.SAMPLE_CLIENTS


def _client(uid, dev, port=None, ssid=None, bd=None, mac=None, name=None, cidrs=()):
    return {
        "dev": dev,
        "ssid": ssid,
        "port": port,
        "name": name or uid,
        "uid": uid,
        "mac": mac,
        "wired": ssid is None,
        "vendor": "Synology",
        "last_seen": 1_760_000_000_000,
        "bd": bd,
        "ips": [],
        "cidrs": list(cidrs),
    }


def _vlan(dev, port, vid, bd, svi=False, native=False):
    return {
        "dev": dev,
        "port": port,
        "svi": svi,
        "vid": vid,
        "name": None,
        "native": native,
        "segment": "Office",
        "bd": bd,
    }


async def test_a_site_is_asked_for_by_its_uid_so_a_code_in_another_case_finds_it(client, monkeypatch):
    """The code is case-sensitive and the graph Site is one node per uid."""
    await login(client, "vera")
    session = _seam(monkeypatch, {topology_route._SITE_DEVICES: [_dev("swc-01", "core")]})

    await client.get("/api/topology", params=[("site", "BER1"), ("site", "fra:2")])

    assert session.params[topology_route._SITE_DEVICES]["site"] == ["site:ber1", "site:fra-2"]
    assert "s.uid IN $site" in topology_route._SITE_DEVICES
    assert "s.code" not in topology_route._AT_SITE


async def test_the_client_overlay_and_subnet_reads_take_the_site_filter(client, monkeypatch):
    await login(client, "vera")
    session = _seam(monkeypatch, {topology_route._SITE_DEVICES: [_dev("swc-01", "core")]})

    await client.get("/api/topology", params=[("site", "ber1"), ("site", "ham2")])

    assert session.params[topology_route._SITE_DEVICES]["site"] == ["site:ber1", "site:ham2"]
    assert topology_route._DEVICES not in session.params
    reads = (
        topology_route._CABLES,
        topology_route._LAGS,
        topology_route._GROUPS,
        topology_route._WAN_DEVICES,
        topology_route._CLIENTS,
        topology_route._VLANS,
        topology_route._SUBNETS,
        topology_route._ATTACHED,
    )
    for read in reads:
        assert session.params[read] == {"devs": ["swc-01"], "snap": SNAP}
        assert "UNWIND $devs AS du\nMATCH (" in read and "{uid: du, collection_ts: $snap})" in read
        assert "$site" not in read


async def test_an_empty_site_code_is_refused(client, monkeypatch):
    await login(client, "vera")
    _seam(monkeypatch, {})

    assert (await client.get("/api/topology", params={"site": ""})).status_code == 400
    assert (await client.get("/api/topology/segment", params={"bd": "bd:x", "site": " "})).status_code == 400


async def test_clients_group_per_port_and_per_access_point_and_ssid(client, monkeypatch):
    """A wired client counts under its port, a wireless one under its access point
    and SSID; each group counts its clients per bridge domain, and each client
    carries its MAC, vendor, last seen and bridge domain."""
    await login(client, "vera")
    bd = "bd:vlan:fab0:10"
    _seam(
        monkeypatch,
        {
            topology_route._DEVICES: [_dev("swa-01", "access"), _dev("ap-01", "access-point")],
            topology_route._CLIENTS: [
                _client("ep:1", "swa-01", port="Port 2", bd=bd, mac="112233445566"),
                _client("ep:2", "swa-01", port="Port 2", bd="bd:vlan:fab0:20"),
                _client("ep:3", "swa-01", port="Port 4", bd=bd),
                _client("ep:4", "ap-01", ssid="Home", bd=bd),
            ],
        },
    )

    body = (await client.get("/api/topology")).json()

    groups = {(g["dev"], g["port"], g["ssid"]): g for g in body["clients"]}
    assert set(groups) == {("swa-01", "Port 2", None), ("swa-01", "Port 4", None), ("ap-01", None, "Home")}
    port2 = groups[("swa-01", "Port 2", None)]
    assert (port2["count"], port2["by_bd"]) == (2, {bd: 1, "bd:vlan:fab0:20": 1})
    first = port2["clients"][0]
    assert (first["mac"], first["vendor"], first["last_seen"], first["bd"]) == (
        "112233445566",
        "Synology",
        1_760_000_000_000,
        bd,
    )


async def test_a_client_that_is_a_drawn_device_or_on_a_cabled_port_is_dropped(client, monkeypatch):
    """The router seen as a client on the switch port its cable lands on, and a
    drawn device seen by its chassis MAC on another port, are the devices
    themselves: neither counts as a client."""
    await login(client, "vera")
    swa = {**_dev("swa-01", "access"), "mac": "aa:bb:cc:00:00:02"}
    _seam(
        monkeypatch,
        {
            topology_route._DEVICES: [_dev("rtr-01", "core"), swa],
            topology_route._CABLES: [
                {
                    "a_dev": "rtr-01",
                    "a_port": "eth0",
                    "a_name": "rtr-01",
                    "b_dev": "swa-01",
                    "b_port": "Port 1",
                    "b_name": "swa-01",
                    "source": "lldp",
                }
            ],
            topology_route._CLIENTS: [
                _client("ep:rtr", "swa-01", port="Port 1", mac="aabbcc000001"),
                _client("ep:self", "rtr-01", port="eth3", mac="aabbcc000002"),
                _client("ep:nas", "swa-01", port="Port 3", mac="112233445566"),
            ],
        },
    )

    body = (await client.get("/api/topology")).json()

    assert [c["uid"] for g in body["clients"] for c in g["clients"]] == ["ep:nas"]


async def test_the_topology_carries_one_segment_per_bridge_domain_of_the_drawing(client, monkeypatch):
    """The segments join the VLAN, subnet and client rows of the drawn devices per
    bridge domain: the carrying ports, the gateway SVI with its address, the
    prefix and the client count. A device outside the drawing adds nothing."""
    await login(client, "vera")
    bd = "bd:vlan:fab0:10"
    _seam(
        monkeypatch,
        {
            topology_route._SITE_DEVICES: [_dev("swc-01", "core")],
            topology_route._VLANS: [
                _vlan("swc-01", "Vlan10", 10, bd, svi=True),
                _vlan("swc-01", "Eth1/5", 10, bd, native=True),
                _vlan("elsewhere", "Eth1/1", 10, bd),
            ],
            topology_route._SUBNETS: [
                {
                    "dev": "swc-01",
                    "iface": "Vlan10",
                    "ip": "10.0.10.1",
                    "cidr": "10.0.10.0/24",
                    "af": 4,
                    "vrf": "default",
                    "domain": None,
                    "fhrp": None,
                }
            ],
            topology_route._CLIENTS: [
                _client("ep:1", "swc-01", port="Eth1/5", bd=bd),
                _client("ep:2", "elsewhere", port="1", bd=bd),
            ],
        },
    )

    body = (await client.get("/api/topology", params={"site": "ber1"})).json()

    [segment] = body["segments"]
    assert (segment["bd"], segment["vid"], segment["name"], segment["cidrs"]) == (
        bd,
        10,
        "Office",
        ["10.0.10.0/24"],
    )
    assert [(g["dev"], g["iface"], g["ip"]) for g in segment["gateways"]] == [
        ("swc-01", "Vlan10", "10.0.10.1")
    ]
    assert segment["carriers"] == [
        {"dev": "swc-01", "ports": ["Eth1/5"], "native": ["Eth1/5"], "access": ["Eth1/5"]}
    ]
    assert segment["clients"] == 1
    assert [v["bd"] for v in body["vlans"]] == [bd]


async def test_the_segment_list_pages_the_clients_of_one_bridge_domain(client, monkeypatch):
    """GET /topology/segment: every client of one bridge domain at the asked
    sites, one page at a time, with the same skips as the drawing."""
    await login(client, "vera")
    bd = "bd:vlan:fab0:10"
    rows = [
        {**_client(f"ep:{i:02d}", "swa-01", port=f"Port {i}", bd=bd), "dev_name": "swa-01", "cabled": False}
        for i in range(7)
    ]
    rows.append(
        {**_client("ep:uplink", "swa-01", port="Port 49", bd=bd), "dev_name": "swa-01", "cabled": True}
    )
    rows.append({**_client("ep:far", "elsewhere", port="1", bd=bd), "dev_name": "elsewhere", "cabled": False})
    # the database skips the cabled port and the device not drawn, and cuts the
    # page at offset 5 (tests/test_entity_filters_db.py); this is that answer
    session = _seam(
        monkeypatch,
        {
            topology_route._SITE_DEVICES: [{**_dev("swa-01", "access"), "mac": "AA-BB-CC-00-00-01"}],
            topology_route._SITE_SEGMENT_PAGE_QUERY: [{"total": 7, "page": rows[5:7]}],
        },
    )

    r = await client.get("/api/topology/segment", params={"bd": bd, "site": "ber1", "offset": 5, "limit": 5})

    assert r.status_code == 200
    body = r.json()
    assert (body["snapshot"], body["bd"], body["total"], body["offset"], body["limit"]) == (SNAP, bd, 7, 5, 5)
    assert [c["uid"] for c in body["clients"]] == ["ep:05", "ep:06"]
    assert (body["clients"][0]["port"], body["clients"][0]["dev_name"], body["clients"][0]["vendor"]) == (
        "Port 5",
        "swa-01",
        "Synology",
    )
    assert body["next_cursor"] is None
    # asked for a site, the read starts from that site's devices, not from the bridge domain;
    # the drawn devices' MACs go in canonical, for the skip of a device seen as a client
    assert session.params[topology_route._SITE_SEGMENT_PAGE_QUERY] == {
        "bd": bd,
        "devs": ["swa-01"],
        "snap": SNAP,
        "keep": ["swa-01"],
        "macs": ["aabbcc000001"],
        "hex": topology_route._HEX,
        "offset": 5,
        "limit": 5,
        "after_name": None,
        "after_uid": None,
    }


async def test_the_segment_list_needs_a_bridge_domain_and_a_bounded_page(client, monkeypatch):
    await login(client, "vera")
    _seam(monkeypatch, {})
    assert (await client.get("/api/topology/segment")).status_code == 422
    params = {"bd": "bd:vlan:fab0:10", "limit": topology_route.SEGMENT_PAGE_MAX + 1}
    assert (await client.get("/api/topology/segment", params=params)).status_code == 422


def _attached(dev, iface, bd, basis, ip=None, cidr=None, vid=None):
    return {
        "dev": dev,
        "iface": iface,
        "bd": bd,
        "basis": basis,
        "vid": vid,
        "segment": None,
        "ip": ip,
        "cidr": cidr,
        "af": 4 if ip else None,
        "vrf": "default",
        "domain": None,
        "fhrp": None,
    }


async def test_the_segments_read_the_graphs_attachments_and_prefixes(client, monkeypatch):
    """The attachment read takes the drawn devices; the prefix read takes the
    bridge domains of the drawn devices' rows. A router port the graph attaches
    by its cable is the gateway of the untagged segment with the edge's basis,
    and the segment's prefixes are the ones IN it, IPv4 first."""
    await login(client, "vera")
    bd1, bd10, far = "bd:vlan:fab0:1", "bd:vlan:fab0:10", "bd:vlan:fab0:77"
    session = _seam(
        monkeypatch,
        {
            topology_route._SITE_DEVICES: [_dev("gw-01", "core"), _dev("sw-01", "access")],
            topology_route._VLANS: [
                _vlan("sw-01", "Port 2", 1, bd1, native=True),
                _vlan("sw-01", "Port 3", 10, bd10),
                _vlan("elsewhere", "Eth1/1", 77, far),
            ],
            topology_route._ATTACHED: [
                _attached("gw-01", "eth0", bd1, "cable", "192.168.2.1", "192.168.2.0/24", vid=1),
                _attached("elsewhere", "eth9", far, "cable", "10.7.7.1", "10.7.7.0/24", vid=77),
            ],
            topology_route._SEGMENT_PREFIXES: [
                {"bd": bd1, "cidr": "2001:db8:1::/64", "af": 6},
                {"bd": bd1, "cidr": "192.168.2.0/24", "af": 4},
            ],
        },
    )

    body = (await client.get("/api/topology", params={"site": "ber1"})).json()

    assert session.params[topology_route._ATTACHED] == {"devs": ["gw-01", "sw-01"], "snap": SNAP}
    assert session.params[topology_route._SEGMENT_PREFIXES] == {"bds": [bd1, bd10], "snap": SNAP}
    by_bd = {s["bd"]: s for s in body["segments"]}
    assert set(by_bd) == {bd1, bd10}
    default = by_bd[bd1]
    assert default["gateways"] == [
        {
            "dev": "gw-01",
            "iface": "eth0",
            "ip": "192.168.2.1",
            "cidr": "192.168.2.0/24",
            "af": 4,
            "vrf": "default",
            "domain": None,
            "fhrp": None,
            "routes": None,
            "basis": "cable",
        }
    ]
    assert (default["cidrs"], default["cidr_basis"]) == (["192.168.2.0/24", "2001:db8:1::/64"], "gateway")


async def test_the_prefix_read_is_skipped_when_the_drawing_has_no_bridge_domain(client, monkeypatch):
    await login(client, "vera")
    session = _seam(monkeypatch, {topology_route._DEVICES: [_dev("swc-01", "core")]})

    body = (await client.get("/api/topology")).json()

    assert topology_route._SEGMENT_PREFIXES not in session.params
    assert body["segments"] == []
