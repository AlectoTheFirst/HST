"""/api/sites/graph: how sites connect, Neo4j faked at the module seam."""

import contextlib

from tests.app.conftest import login

import hst.app.routes.site_graph as site_graph

DEFAULT_SNAP = 4242


class _FakeSession:
    """Answers the pointer read plus the route's seven reads."""

    def __init__(self, rows: dict[str, list] | None = None, current=DEFAULT_SNAP):
        rows = rows or {}
        self._by_query = {
            site_graph._SITE_DEVICES: rows.get("devices", []),
            site_graph._CABLES: rows.get("cables", []),
            site_graph._CIRCUITS: rows.get("circuits", []),
            site_graph._TUNNEL_ENDS: rows.get("tunnel_ends", []),
            site_graph._SUBNET_MEMBERS: rows.get("subnet_members", []),
            site_graph._BGP: rows.get("bgp", []),
            site_graph._WAN: rows.get("wan", []),
        }
        self._current = current
        self.params: dict[str, dict] = {}
        self.pointer_calls = 0

    def run(self, cypher, **params):
        if "CyclePointer" in cypher:
            self.pointer_calls += 1
            rows = [{"current": self._current}] if self._current is not None else []
        else:
            self.params[cypher] = params
            rows = self._by_query[cypher]

        class _Result:
            def data(self):
                return rows

        return _Result()


def _session_with(rows=None, seen=None):
    @contextlib.contextmanager
    def cm(settings):
        s = _FakeSession(rows)
        if seen is not None:
            seen.append(s)
        yield s

    return cm


async def _sites(client):
    await login(client, "ada")
    for code, params in (
        ("FR2", {"lat": 50.12, "lon": 8.74}),
        ("FR6", {"lat": 50.1, "lon": 8.72}),
        ("AMS", {}),
    ):
        r = await client.post("/api/sites", json={"code": code, "name": f"Equinix {code}", "params": params})
        assert r.status_code == 201


def _cable(a_site, a_dev, a_port, b_site, b_dev, b_port, source="cdp"):
    return {
        "a_site": a_site,
        "a_dev": a_dev,
        "a_name": a_dev.split(":")[-1],
        "a_port": a_port,
        "b_site": b_site,
        "b_dev": b_dev,
        "b_name": b_dev.split(":")[-1],
        "b_port": b_port,
        "source": source,
    }


async def test_site_graph_requires_auth(client):
    assert (await client.get("/api/sites/graph")).status_code == 401


async def test_a_graph_site_written_in_another_case_is_the_stored_site(client, monkeypatch):
    """A collector writes `fr2` for the site stored as `FR2`; the uid is the
    identity, so the stored site has its devices and its edges."""
    await _sites(client)
    rows = {
        "devices": [{"site": "fr2", "devices": 3, "kind": "colo", "tiers": ["core"]}],
        "cables": [_cable("fr2", "dev:a", "p1", "FR6", "dev:b", "p2")],
        "wan": [{"site": "fr6", "kind": "internet", "carrier": "x", "bandwidth_mbps": 100}],
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))

    body = (await client.get("/api/sites/graph")).json()

    by_code = {s["code"]: s for s in body["sites"]}
    assert (by_code["FR2"]["devices"], by_code["FR2"]["kind"], by_code["FR2"]["tiers"]) == (
        3,
        "colo",
        {"core": 1},
    )
    assert [x["kind"] for x in by_code["FR6"]["exits"]] == ["internet"]
    assert [(e["a"], e["b"], e["count"]) for e in body["edges"]] == [("FR2", "FR6", 1)]


async def test_site_graph_lists_sites_with_their_place_and_device_count(client, monkeypatch):
    await _sites(client)
    rows = {"devices": [{"site": "FR2", "devices": 3}]}
    seen = []
    monkeypatch.setattr(site_graph, "_session", _session_with(rows, seen))

    r = await client.get("/api/sites/graph")
    assert r.status_code == 200
    body = r.json()
    assert body["sites"] == [
        {
            "code": "AMS",
            "name": "Equinix AMS",
            "lat": None,
            "lon": None,
            "devices": 0,
            "kind": None,
            "tiers": {},
            "exits": [],
        },
        {
            "code": "FR2",
            "name": "Equinix FR2",
            "lat": 50.12,
            "lon": 8.74,
            "devices": 3,
            "kind": None,
            "tiers": {},
            "exits": [],
        },
        {
            "code": "FR6",
            "name": "Equinix FR6",
            "lat": 50.1,
            "lon": 8.72,
            "devices": 0,
            "kind": None,
            "tiers": {},
            "exits": [],
        },
    ]
    assert body["edges"] == [] and body["unplaced"] == []
    # one pointer resolution, bound to every read
    assert seen[0].pointer_calls == 1
    assert {p["snap"] for p in seen[0].params.values()} == {DEFAULT_SNAP}


async def test_site_graph_keeps_cross_site_cables_and_sorts_the_pair(client, monkeypatch):
    """A cable between FR2 and FR6 is one edge whichever end the row came
    from, an intra-site cable is not an edge, and a cable to an unplaced
    device counts against the placed site."""
    await _sites(client)
    rows = {
        "cables": [
            _cable("FR6", "dev:fr6-sw1", "Eth1/49", "FR2", "dev:fr2-sw1", "Eth1/49"),
            _cable("FR2", "dev:fr2-sw1", "Eth1/50", "FR6", "dev:fr6-sw2", "Eth1/50"),
            _cable("FR2", "dev:fr2-sw1", "Eth1/1", "FR2", "dev:fr2-sw2", "Eth1/1"),
            _cable("FR2", "dev:fr2-sw1", "Eth1/2", None, "dev:nowhere", "Eth1/1"),
            _cable(None, "dev:lost", "Eth1/2", None, "dev:nowhere", "Eth1/2"),
        ]
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))

    body = (await client.get("/api/sites/graph")).json()
    assert len(body["edges"]) == 1
    edge = body["edges"][0]
    assert (edge["a"], edge["b"], edge["kind"], edge["count"]) == ("FR2", "FR6", "cable", 2)
    # the flipped row reads in the sorted site order: a_ fields are FR2's
    assert [(p["a_dev"], p["a_port"], p["b_dev"], p["b_port"]) for p in edge["pairs"]] == [
        ("dev:fr2-sw1", "Eth1/49", "dev:fr6-sw1", "Eth1/49"),
        ("dev:fr2-sw1", "Eth1/50", "dev:fr6-sw2", "Eth1/50"),
    ]
    assert body["unplaced"] == [{"site": "FR2", "kind": "cable", "count": 1}]


async def test_site_graph_pairs_tunnel_ends_and_subnet_members_across_sites(client, monkeypatch):
    await _sites(client)
    rows = {
        "tunnel_ends": [
            {
                "uid": "tun:1",
                "encap": "vxlan",
                "state": "up",
                "site": "FR6",
                "dev": "dev:b",
                "name": "b",
                "end": "vxlan1",
            },
            {
                "uid": "tun:1",
                "encap": "vxlan",
                "state": "up",
                "site": "FR2",
                "dev": "dev:a",
                "name": "a",
                "end": "vxlan1",
            },
            # a tunnel to a Zscaler DC has one device end: not an edge
            {
                "uid": "tun:zia",
                "encap": "gre",
                "state": "up",
                "site": "FR2",
                "dev": "dev:a",
                "name": "a",
                "end": "gre0",
            },
        ],
        "subnet_members": [
            {
                "site": "FR2",
                "dev": "dev:a",
                "name": "a",
                "iface": "Vlan100",
                "ip": "10.1.0.1",
                "cidr": "10.1.0.0/24",
                "vrf": "CORP",
                "domain": "ACME-EMEA:CORP",
            },
            {
                "site": "FR6",
                "dev": "dev:b",
                "name": "b",
                "iface": "Vlan100",
                "ip": "10.1.0.2",
                "cidr": "10.1.0.0/24",
                "vrf": "CORP",
                "domain": "ACME-EMEA:CORP",
            },
            # the hsrp pair at FR2: same site, same device pair is not an edge
            {
                "site": "FR2",
                "dev": "dev:a2",
                "name": "a2",
                "iface": "Vlan100",
                "ip": "10.1.0.3",
                "cidr": "10.1.0.0/24",
                "vrf": "CORP",
                "domain": "ACME-EMEA:CORP",
            },
            # same cidr in another domain: its own group, one member, no pair
            {
                "site": "AMS",
                "dev": "dev:c",
                "name": "c",
                "iface": "Vlan100",
                "ip": "10.1.0.1",
                "cidr": "10.1.0.0/24",
                "vrf": "GUEST",
                "domain": None,
            },
        ],
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))

    body = (await client.get("/api/sites/graph")).json()
    kinds = [(e["a"], e["b"], e["kind"], e["count"]) for e in body["edges"]]
    assert kinds == [("FR2", "FR6", "l3", 2), ("FR2", "FR6", "tunnel", 1)]
    l3 = body["edges"][0]["pairs"]
    assert [(p["a_dev"], p["b_dev"], p["cidr"]) for p in l3] == [
        ("dev:a", "dev:b", "10.1.0.0/24"),
        ("dev:a2", "dev:b", "10.1.0.0/24"),
    ]
    tunnel = body["edges"][1]["pairs"][0]
    assert (tunnel["a_dev"], tunnel["b_dev"], tunnel["encap"]) == ("dev:a", "dev:b", "vxlan")


async def test_site_graph_dedupes_bgp_peers_and_lists_wan_exits(client, monkeypatch):
    await _sites(client)
    session = {
        "uid": "bgp:1",
        "state": "established",
        "kind": "underlay",
        "a_site": "FR2",
        "a_dev": "dev:a",
        "a_name": "a",
        "a_ip": "10.9.0.1",
        "a_asn": 65001,
        "b_site": "FR6",
        "b_dev": "dev:b",
        "b_name": "b",
        "b_ip": "10.9.0.2",
        "b_asn": 65002,
        # the holder runs the session back (a sole holder is checked too)
        "reciprocal": True,
    }
    rows = {
        # the peer address held in two VRFs of one device: one pair
        "bgp": [session, dict(session)],
        "wan": [
            {
                "site": "FR2",
                "dev": "dev:a",
                "name": "a",
                "kind": "dia",
                "carrier": "DTAG",
                "bandwidth_mbps": 1000,
            },
            {
                "site": None,
                "dev": "dev:x",
                "name": "x",
                "kind": "lte",
                "carrier": None,
                "bandwidth_mbps": None,
            },
        ],
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))

    body = (await client.get("/api/sites/graph")).json()
    assert [(e["kind"], e["count"]) for e in body["edges"]] == [("bgp", 1)]
    assert body["edges"][0]["pairs"][0]["b_asn"] == 65002
    fr2 = next(s for s in body["sites"] if s["code"] == "FR2")
    assert fr2["exits"] == [
        {"dev": "dev:a", "name": "a", "kind": "dia", "carrier": "DTAG", "bandwidth_mbps": 1000}
    ]


async def test_site_graph_caps_the_listed_pairs_but_not_the_count(client, monkeypatch):
    await _sites(client)
    rows = {
        "cables": [
            _cable("FR2", "dev:a", f"Eth1/{i}", "FR6", "dev:b", f"Eth1/{i}")
            for i in range(site_graph.SAMPLE_PAIRS + 5)
        ]
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))
    edge = (await client.get("/api/sites/graph")).json()["edges"][0]
    assert edge["count"] == site_graph.SAMPLE_PAIRS + 5
    assert len(edge["pairs"]) == site_graph.SAMPLE_PAIRS


async def test_site_graph_folds_the_two_directions_of_an_sdwan_path_into_one_line(client, monkeypatch):
    """A VeloCloud path is two Tunnel nodes, one per edge's own observation,
    each with one ENDPOINT and a far end from TERMINATES_ON. They share a
    `pair`, so the map draws one line, carrying the WAN link kind the near
    end states and the interface name over the far row's bare address."""
    await _sites(client)
    rows = {
        "tunnel_ends": [
            {
                "uid": "vco:e:path:l-a~l-b",
                "pair": "tun:velocloud-vcmp:l-a~l-b",
                "encap": "velocloud-vcmp",
                "state": "STABLE",
                "link_kind": "mpls",
                "side": "near",
                "site": "FR2",
                "dev": "dev:edge-a",
                "name": "edge-a",
                "end": "GE1",
            },
            {
                "uid": "vco:e:path:l-a~l-b",
                "pair": "tun:velocloud-vcmp:l-a~l-b",
                "encap": "velocloud-vcmp",
                "state": "STABLE",
                "link_kind": None,
                "side": "far",
                "site": "FR6",
                "dev": "dev:edge-b",
                "name": "edge-b",
                "end": "172.16.9.2",
            },
            {
                "uid": "vco:e:path:l-b~l-a",
                "pair": "tun:velocloud-vcmp:l-a~l-b",
                "encap": "velocloud-vcmp",
                "state": "STABLE",
                "link_kind": "mpls",
                "side": "near",
                "site": "FR6",
                "dev": "dev:edge-b",
                "name": "edge-b",
                "end": "GE1",
            },
            {
                "uid": "vco:e:path:l-b~l-a",
                "pair": "tun:velocloud-vcmp:l-a~l-b",
                "encap": "velocloud-vcmp",
                "state": "STABLE",
                "link_kind": None,
                "side": "far",
                "site": "FR2",
                "dev": "dev:edge-a",
                "name": "edge-a",
                "end": "172.16.1.2",
            },
            # a path to a cloud gateway has one device end: not an edge
            {
                "uid": "vco:e:path:l-a~gw:g1",
                "pair": "tun:velocloud-vcmp:gw:g1~l-a",
                "encap": "velocloud-vcmp",
                "state": "STABLE",
                "link_kind": "dia",
                "side": "near",
                "site": "FR2",
                "dev": "dev:edge-a",
                "name": "edge-a",
                "end": "GE2",
            },
        ],
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))

    body = (await client.get("/api/sites/graph")).json()
    assert [(e["a"], e["b"], e["kind"], e["count"]) for e in body["edges"]] == [("FR2", "FR6", "tunnel", 1)]
    line = body["edges"][0]["pairs"][0]
    assert line["uid"] == "vco:e:path:l-a~l-b"
    assert line["link_kind"] == "mpls"
    assert (line["a_dev"], line["a_end"], line["b_dev"], line["b_end"]) == (
        "dev:edge-a",
        "GE1",
        "dev:edge-b",
        "GE1",
    )


async def test_a_tunnel_to_a_shared_nat_address_names_only_the_edge_its_uid_names(client, monkeypatch):
    """Two branches sit behind one NAT address, so the WAN links of both hold
    it. The hub's tunnel to br1 ends on that address: the far row of br2 is
    left out, because the tunnel uid names br1."""
    await _sites(client)

    def end(uid, side, site, dev, name, end_):
        return {
            "uid": uid,
            "pair": "tun:velocloud-vcmp:e-br1:l1~e-hub:lh",
            "encap": "velocloud-vcmp",
            "state": None,
            "link_kind": "dia" if side == "near" else None,
            "side": side,
            "site": site,
            "dev": dev,
            "name": name,
            "end": end_,
        }

    to_br1 = "vco:ent-1:path:e-hub:lh~link:e-br1:l1"
    to_hub = "vco:ent-1:path:e-br1:l1~link:e-hub:lh"
    rows = {
        "tunnel_ends": [
            end(to_br1, "near", "FR2", "vco:ent-1:edge:e-hub", "hub-1", "GE2"),
            end(to_br1, "far", "FR6", "vco:ent-1:edge:e-br1", "branch-1", "198.51.100.9"),
            end(to_br1, "far", "FR7", "vco:ent-1:edge:e-br2", "branch-2", "198.51.100.9"),
            end(to_hub, "near", "FR6", "vco:ent-1:edge:e-br1", "branch-1", "GE2"),
            end(to_hub, "far", "FR2", "vco:ent-1:edge:e-hub", "hub-1", "203.0.113.2"),
        ],
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))
    body = (await client.get("/api/sites/graph")).json()
    assert [(e["a"], e["b"], e["kind"]) for e in body["edges"]] == [("FR2", "FR6", "tunnel")]


async def test_site_graph_counts_the_tiers_of_each_site_and_names_its_kind(client, monkeypatch):
    """The network map's estate level draws a hub, a data center or a colocation
    site apart from the branches, by the tiers of its devices and the Site kind."""
    await _sites(client)
    rows = {"devices": [{"site": "FR2", "kind": "colo", "devices": 3, "tiers": ["leaf", "leaf", None]}]}
    monkeypatch.setattr(site_graph, "_session", _session_with(rows, []))

    body = (await client.get("/api/sites/graph")).json()
    fr2 = next(s for s in body["sites"] if s["code"] == "FR2")
    assert fr2["kind"] == "colo"
    assert fr2["tiers"] == {"leaf": 2}


def _member(site, dev, ip, cidr="10.255.0.0/20", vrf="CORP", domain="dom"):
    return {
        "site": site,
        "dev": dev,
        "name": dev,
        "iface": "Tunnel0",
        "ip": ip,
        "cidr": cidr,
        "vrf": vrf,
        "domain": domain,
    }


async def test_a_prefix_shared_by_many_sites_is_one_shared_segment_not_a_mesh(client, monkeypatch):
    """A prefix held at more sites than MAX_SUBNET_SITES is listed once and draws no pair edge."""
    await _sites(client)
    count = site_graph.MAX_SUBNET_SITES + 1
    members = [_member(f"S{i:03d}", f"dev:{i:03d}", f"10.255.0.{i + 1}") for i in range(count)]
    members += [
        _member("FR2", "dev:a", "10.1.0.1", "10.1.0.0/24"),
        _member("FR6", "dev:b", "10.1.0.2", "10.1.0.0/24"),
    ]
    monkeypatch.setattr(site_graph, "_session", _session_with({"subnet_members": members}))

    body = (await client.get("/api/sites/graph")).json()
    assert [(e["a"], e["b"], e["kind"]) for e in body["edges"]] == [("FR2", "FR6", "l3")]
    assert body["shared_subnets"] == [
        {"cidr": "10.255.0.0/20", "domain": "dom", "sites": count, "members": count}
    ]


async def test_a_large_group_at_two_sites_is_counted_without_building_its_pairs(client, monkeypatch):
    await _sites(client)
    n = 1500
    members = [_member("FR2", f"dev:a{i:04d}", f"10.0.{i // 250}.{i % 250 + 1}") for i in range(n)]
    members += [_member("FR6", f"dev:b{i:04d}", f"10.1.{i // 250}.{i % 250 + 1}") for i in range(n)]
    # one device at both sites does not pair with itself
    members += [_member("FR2", "dev:x", "10.2.0.1"), _member("FR6", "dev:x", "10.2.0.2")]
    monkeypatch.setattr(site_graph, "_session", _session_with({"subnet_members": members}))

    body = (await client.get("/api/sites/graph")).json()
    (edge,) = body["edges"]
    assert edge["count"] == (n + 1) * (n + 1) - 1
    assert len(edge["pairs"]) == site_graph.SAMPLE_PAIRS
    assert all(p["a_dev"] != p["b_dev"] for p in edge["pairs"])
    assert body["shared_subnets"] == []


async def test_a_member_without_a_site_counts_against_each_placed_site_of_its_prefix(client, monkeypatch):
    await _sites(client)
    members = [
        _member("FR2", "dev:a", "10.1.0.1", "10.1.0.0/24"),
        _member("FR2", "dev:a2", "10.1.0.3", "10.1.0.0/24"),
        _member("FR6", "dev:b", "10.1.0.2", "10.1.0.0/24"),
        _member(None, "dev:u", "10.1.0.9", "10.1.0.0/24"),
        _member(None, "dev:v", "10.1.0.8", "10.1.0.0/24"),
    ]
    monkeypatch.setattr(site_graph, "_session", _session_with({"subnet_members": members}))

    body = (await client.get("/api/sites/graph")).json()
    assert [(e["kind"], e["count"]) for e in body["edges"]] == [("l3", 2)]
    assert body["unplaced"] == [
        {"site": "FR2", "kind": "l3", "count": 4},
        {"site": "FR6", "kind": "l3", "count": 2},
    ]


def _peer(uid, b_dev, b_site, **extra):
    return {
        "uid": uid,
        "state": "established",
        "kind": "underlay",
        "a_site": "FR2",
        "a_dev": "dev:a",
        "a_name": "a",
        "a_ip": "10.9.0.1",
        "a_asn": 65001,
        "b_site": b_site,
        "b_dev": b_dev,
        "b_name": b_dev,
        "b_ip": "10.9.0.2",
        "b_asn": 65002,
        **extra,
    }


async def test_a_bgp_peer_address_held_by_several_devices_takes_the_holder_in_the_sessions_domain(
    client, monkeypatch
):
    """The peer is the holder in the session's VRF or a VRF of its routing domain; with no such
    single holder the session is counted as ambiguous and draws no edge."""
    await _sites(client)
    rows = {
        "bgp": [
            # one session, two holders: the one in the session's domain is the peer
            _peer("bgp:1", "dev:b", "FR6", a_vrf="v:a", a_domain="dom", b_vrf="v:b", b_domain="dom"),
            _peer("bgp:1", "dev:far", "AMS", a_vrf="v:a", a_domain="dom", b_vrf="v:far", b_domain="other"),
            # another session: both holders match, so it is ambiguous
            _peer("bgp:2", "dev:b", "FR6", a_vrf="v:a", a_domain="dom", b_vrf="v:b", b_domain="dom"),
            _peer("bgp:2", "dev:b2", "FR6", a_vrf="v:a", a_domain="dom", b_vrf="v:b2", b_domain="dom"),
            # a third: no holder matches
            _peer("bgp:3", "dev:far", "AMS", a_vrf="v:a", a_domain=None, b_vrf="v:far", b_domain="other"),
            _peer("bgp:3", "dev:far2", "AMS", a_vrf="v:a", a_domain=None, b_vrf="v:far2", b_domain=None),
        ]
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))

    body = (await client.get("/api/sites/graph")).json()
    assert [(e["a"], e["b"], e["kind"], e["count"]) for e in body["edges"]] == [("FR2", "FR6", "bgp", 1)]
    assert body["ambiguous"] == [{"site": "FR2", "kind": "bgp", "count": 2}]


async def test_a_sole_holder_of_a_bgp_peer_address_in_another_vrf_is_not_the_peer(client, monkeypatch):
    """One device holds the peer address, but in a VRF outside the session's VRF and domain
    and with no session back: it reuses the address, so the session is ambiguous, not an edge. A sole
    holder that runs the reciprocal session is the peer."""
    await _sites(client)
    rows = {
        "bgp": [
            _peer("bgp:1", "dev:far", "AMS", a_vrf="v:a", a_domain="dom", b_vrf="v:far", b_domain="other"),
            _peer(
                "bgp:2",
                "dev:b",
                "FR6",
                a_vrf="v:a",
                a_domain=None,
                b_vrf="v:b",
                b_domain=None,
                reciprocal=True,
            ),
        ]
    }
    monkeypatch.setattr(site_graph, "_session", _session_with(rows))

    body = (await client.get("/api/sites/graph")).json()
    assert [(e["a"], e["b"], e["kind"], e["count"]) for e in body["edges"]] == [("FR2", "FR6", "bgp", 1)]
    assert body["ambiguous"] == [{"site": "FR2", "kind": "bgp", "count": 1}]
