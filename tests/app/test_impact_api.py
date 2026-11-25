from contextlib import contextmanager, nullcontext
from typing import Any

import pytest
import tests.test_impact_evaluate as evfix
from tests.app.conftest import login
from tests.test_impact_evaluate import APP, R1, SHUT_A, B

import hst.app.routes.impact as impact_route
from hst import path as pathmod
from hst.app.simul_read import RibGraphInput
from hst.assessment import direct, evaluation, service
from hst.core import manifest
from hst.core import snapshot as snapshotmod
from hst.core.model import SectionOutcome

DEVICE = {
    "uid": "dev:leaf101",
    "hostname": "leaf101",
    "role": "switch",
    "software_version": "10.2(5)",
    "platform": "nxos",
    "vendor": "cisco",
    "model": "N9K-C93180YC-EX",
}

# one prefix served by this device alone, one it shares with a second gateway
PREFIXES = [
    {"uid": "pfx:a", "cidr": "10.0.1.0/24", "kind": "connected", "l3dom": "corp", "other_devices": []},
    {
        "uid": "pfx:b",
        "cidr": "10.0.2.0/24",
        "kind": "connected",
        "l3dom": "corp",
        "other_devices": ["dev:leaf102"],
    },
]
ENDPOINTS = [
    {"uid": "ep:one", "name": "srv-a", "kind": "server", "other_devices": []},
    {"uid": "ep:two", "name": "srv-b", "kind": "server", "other_devices": ["dev:leaf102"]},
]
GROUPS = [
    {
        "uid": "rgrp:vpc:fra01:leaf101-102",
        "kind": "vpc",
        "name": "leaf101-102",
        "role": "primary",
        "other_members": [{"uid": "dev:leaf102", "hostname": "leaf102"}],
    },
    {
        "uid": "rgrp:stack:fra01:lone",
        "kind": "stack",
        "name": "lone",
        "role": "member",
        # the group has no other member: collect() yields one all-null map
        "other_members": [{"uid": None, "hostname": None}],
    },
]
INTERFACES = [{"uid": "if:leaf101:Eth1/1", "name": "Ethernet1/1", "kind": "phys"}]
TUNNELS = [{"uid": "tun:vxlan:1", "encap": "vxlan", "state": "up"}]
SESSIONS = [
    {
        "uid": "bgp:leaf101:10.255.0.1",
        "local_ip": "10.255.0.101",
        "peer_ip": "10.255.0.1",
        "peer_asn": 65001,
        "kind": "underlay",
        "state": "established",
    }
]
FHRP = [
    {
        "uid": "fhrp:hsrp:corp:10",
        "kind": "hsrp",
        "group_id": 10,
        "vip": "10.0.1.1",
        "interfaces": ["Vlan10", None],
        "other_devices": ["dev:leaf102", None],
    }
]


# the one WAN circuit dev:leaf101 has: a single tunnel, no WanLink, no cabled port
LONE_TUNNEL_CIRCUIT = [{"dev": "dev:leaf101", "link": "tun:vxlan:1"}]
# two WanLinks on the same device: querying either one leaves a parallel circuit
PARALLEL_WANLINK_CIRCUITS = [
    {"dev": "dev:leaf101", "link": "wan:mpls:1"},
    {"dev": "dev:leaf101", "link": "wan:lte:2"},
]


def _rows_for(query: str) -> list[dict]:
    if "d.hostname AS hostname" in query:
        return [dict(DEVICE)]
    if "GATEWAY_FOR" in query:
        return [dict(r) for r in PREFIXES]
    if "(ep:Endpoint:Obj)" in query:
        return [dict(r) for r in ENDPOINTS]
    if "RedundancyGroup" in query:
        return [dict(r) for r in GROUPS]
    if "FhrpGroup" in query:
        return [dict(r) for r in FHRP]
    if "(t:Tunnel:Obj)" in query:
        return [dict(r) for r in TUNNELS]
    if "(b:BgpSession:Obj)" in query:
        return [dict(r) for r in SESSIONS]
    if "(i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})" in query:
        return [dict(r) for r in INTERFACES]
    return []


def _link_rows_for(
    wanlinks: list[dict], ports: list[dict], tunnels: list[dict], local: list[dict] | tuple = ()
) -> Any:
    """A rows function for GET /api/impact/link: the circuit-inventory queries
    return the given fixtures (`local`: the tunnels' local-address interfaces);
    everything else (the prefix/endpoint queries assess_link reuses from the
    device bucket) falls through to _rows_for.
    """

    def rows(query: str) -> list[dict]:
        if "AS local_ifs" in query:
            return [dict(r) for r in local]
        if "HAS_LINK" in query:
            return [dict(r) for r in wanlinks]
        if "CONNECTED_TO" in query:
            return [dict(r) for r in ports]
        if "d.uid AS dev, t.uid AS link" in query:
            return [dict(r) for r in tunnels]
        return _rows_for(query)

    return rows


class _FakeTx:
    def __init__(self, sink: list[dict[str, Any]], rows: Any, checks: list[Any], retained: bool) -> None:
        self._sink = sink
        self._rows = rows
        self._checks = checks
        self._retained = retained

    def run(self, query: str, **params: Any):
        if query == snapshotmod._RETAINED_GRAPH:
            # the run-existence check a named snapshot passes before any impact read
            self._checks.append(params["snap"])
            data = [{"uid": DEVICE["uid"]}] if self._retained else []
        else:
            self._sink.append({"query": query, "params": params})
            data = self._rows(query)

        class _Result:
            def data(_self) -> list:
                return data

        return _Result()


class _FakeGraphSession:
    """The pointer read (session.run) plus the impact reads (execute_read)."""

    def __init__(self, rows: Any = _rows_for, current: int | None = 2000, retained: bool = True) -> None:
        self.calls: list[dict[str, Any]] = []
        self.retained_checks: list[Any] = []
        self._rows = rows
        self._current = current
        self._retained = retained

    def run(self, query: str, **params: Any):
        current = self._current
        rows = [{"current": current}] if "CyclePointer" in query and current is not None else []

        class _Result:
            def data(_self) -> list:
                return rows

        return _Result()

    def execute_read(self, work: Any, *args: Any) -> Any:
        return work(_FakeTx(self.calls, self._rows, self.retained_checks, self._retained), *args)


def _seam(session):
    @contextmanager
    def cm(settings):
        yield session

    return cm


async def test_impact_requires_auth(client):
    assert (await client.get("/api/impact", params={"device": "dev:leaf101"})).status_code == 401


async def test_impact_reports_the_buckets_from_the_pinned_run(client, monkeypatch):
    await login(client, "vera")
    session = _FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    r = await client.get("/api/impact", params={"device": "dev:leaf101"})
    assert r.status_code == 200
    body = r.json()

    assert body["snapshot"] == "2000"
    assert body["device"] == DEVICE
    # single-homed keeps only the objects with no second device, and drops the
    # comparison field itself from the payload
    assert [p["uid"] for p in body["single_homed_prefixes"]["items"]] == ["pfx:a"]
    assert "other_devices" not in body["single_homed_prefixes"]["items"][0]
    assert body["single_homed_prefixes"]["count"] == 1
    assert body["gateway_prefixes"]["count"] == 2
    assert [e["uid"] for e in body["single_homed_endpoints"]["items"]] == ["ep:one"]
    assert body["attached_endpoints"]["count"] == 2
    assert body["interfaces"]["items"] == INTERFACES
    assert body["tunnels"]["items"] == TUNNELS
    assert body["bgp_sessions"]["items"] == SESSIONS
    assert body["fhrp_groups"]["items"][0]["interfaces"] == ["Vlan10"]
    assert body["fhrp_groups"]["items"][0]["other_devices"] == ["dev:leaf102"]


async def test_impact_reports_the_members_a_group_keeps(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession()))

    body = (await client.get("/api/impact", params={"device": "dev:leaf101"})).json()
    groups = {g["uid"]: g for g in body["redundancy_groups"]["items"]}
    assert body["redundancy_groups"]["count"] == 2
    vpc = groups["rgrp:vpc:fra01:leaf101-102"]
    assert vpc["has_other_members"] is True
    assert vpc["other_members"] == [{"uid": "dev:leaf102", "hostname": "leaf102"}]
    lone = groups["rgrp:stack:fra01:lone"]
    assert lone["has_other_members"] is False
    assert lone["other_members"] == []


async def test_impact_pins_every_query_to_the_requested_run(client, monkeypatch):
    await login(client, "vera")
    session = _FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    r = await client.get("/api/impact", params={"device": "dev:leaf101", "snapshot": "3000"})
    assert r.status_code == 200
    assert r.json()["snapshot"] == "3000"
    assert session.calls, "no query ran"
    assert {c["params"]["snap"] for c in session.calls} == {3000}
    assert {c["params"]["dev"] for c in session.calls} == {"dev:leaf101"}


async def test_impact_carries_the_run_it_was_pinned_to(client, monkeypatch):
    await login(client, "vera")
    session = _FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", _seam(session))
    status = {
        "snapshot": "2000",
        "created": "2026-09-01T00:00:00+00:00",
        "degraded": True,
        "sources_carried": ["vyos-gw"],
        "sources_failed": [],
        "sources_partial": [],
    }
    monkeypatch.setattr(
        impact_route.cyclemod, "run_status", lambda s, snap: status if snap.cts == 2000 else None
    )

    r = await client.get("/api/impact", params={"device": "dev:leaf101"})
    assert r.status_code == 200
    assert r.json()["run"] == status


async def test_impact_defaults_to_the_pointers_current_run(client, monkeypatch):
    await login(client, "vera")
    session = _FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    await client.get("/api/impact", params={"device": "dev:leaf101"})
    assert {c["params"]["snap"] for c in session.calls} == {2000}


async def test_impact_rejects_a_non_numeric_run_id(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession()))

    r = await client.get("/api/impact", params={"device": "dev:leaf101", "snapshot": "latest"})
    assert r.status_code == 400


_SUBJECT = {"/api/impact": {"device": "dev:leaf101"}, "/api/impact/link": {"link": "wan:fra01-ams01"}}


@pytest.mark.parametrize("route", sorted(_SUBJECT))
async def test_an_unknown_run_is_404_before_any_impact_read(client, monkeypatch, route):
    """A run id that parses but has no retained graph is an unknown run. The
    check runs before the assessment, so no impact query reads an empty pin."""
    await login(client, "vera")
    session = _FakeGraphSession(retained=False)
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    r = await client.get(route, params={**_SUBJECT[route], "snapshot": "3000"})
    assert r.status_code == 404
    assert r.json()["error"] == "unknown run: 3000"
    assert session.retained_checks == [3000]
    assert session.calls == []


@pytest.mark.parametrize("route", sorted(_SUBJECT))
@pytest.mark.parametrize(
    "value", ["latest", "-1", "3000 ", "3e3", "\u00b2", "\u0663\u0660\u0660\u0660", str(2**63)]
)
async def test_a_run_id_that_is_not_ascii_digits_is_400_before_any_read(client, monkeypatch, route, value):
    await login(client, "vera")
    session = _FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    r = await client.get(route, params={**_SUBJECT[route], "snapshot": value})
    assert r.status_code == 400
    assert "is not a run id" in r.json()["error"]
    assert session.retained_checks == []
    assert session.calls == []


async def test_a_retained_run_is_checked_once_and_then_read(client, monkeypatch):
    await login(client, "vera")
    session = _FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    r = await client.get("/api/impact", params={"device": "dev:leaf101", "snapshot": "3000"})
    assert r.status_code == 200
    assert session.retained_checks == [3000]
    assert session.calls


async def test_an_omitted_run_resolves_the_pointer_without_an_existence_check(client, monkeypatch):
    await login(client, "vera")
    session = _FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    r = await client.get("/api/impact", params={"device": "dev:leaf101"})
    assert r.status_code == 200
    assert r.json()["snapshot"] == "2000"
    assert session.retained_checks == []


async def test_impact_404_for_a_device_absent_from_the_run(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession(rows=lambda q: [])))

    r = await client.get("/api/impact", params={"device": "dev:ghost"})
    assert r.status_code == 404
    assert "dev:ghost" in r.json()["error"]


async def test_impact_caps_the_detail_and_keeps_the_complete_count(client, monkeypatch):
    await login(client, "vera")
    many = [
        {
            "uid": f"pfx:{n:04d}",
            "cidr": f"10.{n}.0.0/24",
            "kind": "connected",
            "l3dom": "corp",
            "other_devices": [],
        }
        for n in range(impact_route.DETAIL_CAP + 100)
    ]

    def rows(query: str) -> list[dict]:
        return [dict(r) for r in many] if "GATEWAY_FOR" in query else _rows_for(query)

    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession(rows=rows)))
    body = (await client.get("/api/impact", params={"device": "dev:leaf101"})).json()

    bucket = body["single_homed_prefixes"]
    assert bucket["count"] == impact_route.DETAIL_CAP + 100
    assert len(bucket["items"]) == impact_route.DETAIL_CAP
    assert bucket["truncated"] is True
    assert body["interfaces"]["truncated"] is False


async def test_link_impact_reports_a_prefix_single_homed_on_its_only_tunnel(client, monkeypatch):
    await login(client, "vera")
    rows = _link_rows_for(wanlinks=[], ports=[], tunnels=LONE_TUNNEL_CIRCUIT)
    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession(rows=rows)))

    r = await client.get("/api/impact/link", params={"link": "tun:vxlan:1"})
    assert r.status_code == 200
    body = r.json()
    assert body["device"] == "dev:leaf101"
    assert body["other_circuits"] == []
    assert [p["uid"] for p in body["single_homed_prefixes"]["items"]] == ["pfx:a"]
    assert body["single_homed_prefixes"]["count"] == 1


async def test_link_impact_with_a_parallel_circuit_reports_nothing_single_homed(client, monkeypatch):
    await login(client, "vera")
    rows = _link_rows_for(wanlinks=PARALLEL_WANLINK_CIRCUITS, ports=[], tunnels=[])
    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession(rows=rows)))

    r = await client.get("/api/impact/link", params={"link": "wan:mpls:1"})
    assert r.status_code == 200
    body = r.json()
    assert body["device"] == "dev:leaf101"
    assert body["other_circuits"] == ["wan:lte:2"]
    assert body["single_homed_prefixes"]["count"] == 0
    assert body["single_homed_endpoints"]["count"] == 0


async def _link_impact(client, monkeypatch, link, *, wanlinks, ports, tunnels=(), local=()):
    await login(client, "vera")
    rows = _link_rows_for(wanlinks=wanlinks, ports=ports, tunnels=list(tunnels), local=list(local))
    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession(rows=rows)))
    r = await client.get("/api/impact/link", params={"link": link})
    assert r.status_code == 200
    return r.json()


# a branch router with one WAN circuit and one LAN port cabled to an access switch
# that holds no WAN circuit of its own
BRANCH_WAN = [{"dev": "dev:leaf101", "link": "wan:br1-mpls"}]
BRANCH_LAN_PORT = [{"dev": "dev:leaf101", "link": "port:br1:gi0/1", "far": [["port:acc1:gi0/1", "dev:acc1"]]}]


async def test_a_lan_port_is_no_parallel_path_for_the_wan_circuit(client, monkeypatch):
    body = await _link_impact(client, monkeypatch, "wan:br1-mpls", wanlinks=BRANCH_WAN, ports=BRANCH_LAN_PORT)
    assert body["other_circuits"] == ["port:br1:gi0/1"]
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert [p["uid"] for p in body["single_homed_prefixes"]["items"]] == ["pfx:a"]
    assert body["single_homed_prefixes"]["count"] == 1


async def test_the_wan_circuit_is_no_parallel_path_for_a_lan_port(client, monkeypatch):
    body = await _link_impact(
        client, monkeypatch, "port:br1:gi0/1", wanlinks=BRANCH_WAN, ports=BRANCH_LAN_PORT
    )
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert body["single_homed_prefixes"]["count"] == 1


async def test_a_port_cabled_to_a_device_with_its_own_wan_circuit_is_a_parallel_path(client, monkeypatch):
    wanlinks = [
        {"dev": "dev:isp1", "link": "wan:isp1", "under": ["if:isp1:ge1", "port:isp1:ge1"]},
        {"dev": "dev:isp2", "link": "wan:isp2", "under": ["if:isp2:ge1", "port:isp2:ge1"]},
    ]
    ports = [
        {"dev": "dev:leaf101", "link": "port:sw:up1", "far": [["port:isp1:ge0", "dev:isp1"]]},
        {"dev": "dev:leaf101", "link": "port:sw:up2", "far": [["port:isp2:ge0", "dev:isp2"]]},
        {"dev": "dev:leaf101", "link": "port:sw:lan", "far": [["port:acc1:gi0/1", "dev:acc1"]]},
    ]
    body = await _link_impact(client, monkeypatch, "port:sw:up1", wanlinks=wanlinks, ports=ports)
    assert body["other_circuits"] == ["port:sw:lan", "port:sw:up2"]
    assert body["parallel_circuits"] == ["port:sw:up2"] and body["parallel_path"] == "established"
    assert body["single_homed_prefixes"]["count"] == 0 and body["single_homed_endpoints"]["count"] == 0


# a router with one WAN link and two tunnels. VeloCloud records the link ON its WAN
# interface and the tunnels' ENDPOINT on the same interface; here the link has no ON edge
# and the WireGuard tunnels' ENDPOINT is on their own wg interfaces.
VELO_WAN = [{"dev": "dev:leaf101", "link": "wan:e1:ge3", "under": ["if:e1:ge3"]}]
VELO_TUNNELS = [
    {"dev": "dev:leaf101", "link": "tun:e1:ge3~gw1", "under": ["if:e1:ge3"]},
    {"dev": "dev:leaf101", "link": "tun:e1:ge3~gw2", "under": ["if:e1:ge3"]},
]
VYOS_WAN = [{"dev": "dev:leaf101", "link": "wan:core1:pppoe0", "under": []}]
VYOS_TUNNELS = [
    {"dev": "dev:leaf101", "link": "tun:wireguard:core1~wg0~a", "under": ["if:core1:wg0"]},
    {"dev": "dev:leaf101", "link": "tun:wireguard:core1~wg44~b", "under": ["if:core1:wg44"]},
]


async def test_a_tunnel_over_the_lost_wan_link_is_lost_with_it(client, monkeypatch):
    body = await _link_impact(
        client, monkeypatch, "wan:e1:ge3", wanlinks=VELO_WAN, ports=[], tunnels=VELO_TUNNELS
    )
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert {r["reason"] for r in body["not_parallel"]} == {"runs over the lost circuit"}
    assert body["single_homed_prefixes"]["count"] == 1 and body["single_homed_endpoints"]["count"] == 1


async def test_a_tunnel_with_no_recorded_underlay_is_no_established_parallel_path(client, monkeypatch):
    body = await _link_impact(
        client, monkeypatch, "wan:core1:pppoe0", wanlinks=VYOS_WAN, ports=[], tunnels=VYOS_TUNNELS
    )
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert [r["uid"] for r in body["not_parallel"]] == [t["link"] for t in VYOS_TUNNELS]
    assert all("not recorded" in r["reason"] for r in body["not_parallel"])
    assert body["single_homed_prefixes"]["count"] == 1 and body["single_homed_endpoints"]["count"] == 1


# The dev router core1: its PPPoE WanLink is ON pppoe0, its two WireGuard tunnels end on
# their own wg interfaces, and the default route leaves by pppoe0.
CORE1_WAN = [{"dev": "dev:core1", "link": "wan:core1:pppoe0", "under": ["dev:core1/if/pppoe0"]}]
CORE1_TUNNELS = [
    {"dev": "dev:core1", "link": "tun:wireguard:dev:core1~wg0~us-streaming", "under": ["dev:core1/if/wg0"]},
    {
        "dev": "dev:core1",
        "link": "tun:wireguard:dev:core1~wg44~torguard-suisse",
        "under": ["dev:core1/if/wg44"],
    },
]


def _core1_local(source: Any = "derived:egress", held: list | None = None) -> list[dict]:
    """Each tunnel's local address, held by pppoe0 unless `held` says otherwise."""
    held = [["dev:core1/if/pppoe0", None]] if held is None else held
    return [
        {"dev": "dev:core1", "link": t["link"], "source": source, "local_ifs": held} for t in CORE1_TUNNELS
    ]


@pytest.mark.parametrize("source", ["derived:egress", "configured"])
async def test_a_wireguard_tunnel_whose_local_address_is_on_the_lost_link_is_lost_with_it(
    client, monkeypatch, source
):
    body = await _link_impact(
        client,
        monkeypatch,
        "wan:core1:pppoe0",
        wanlinks=CORE1_WAN,
        ports=[],
        tunnels=CORE1_TUNNELS,
        local=_core1_local(source),
    )
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert body["not_parallel"] == [
        {"uid": t["link"], "reason": "runs over the lost circuit"} for t in CORE1_TUNNELS
    ]
    assert [p["uid"] for p in body["single_homed_prefixes"]["items"]] == ["pfx:a"]
    assert body["single_homed_prefixes"]["count"] == 1 and body["single_homed_endpoints"]["count"] == 1


@pytest.mark.parametrize(
    "local",
    [
        pytest.param([], id="no-interface-holds-it"),
        pytest.param(_core1_local(None), id="address-not-known"),
        pytest.param(_core1_local("guessed"), id="address-of-another-source"),
        pytest.param(
            _core1_local(held=[["dev:core1/if/pppoe0", None], ["dev:core1/if/eth1", "dev:core1/port/eth1"]]),
            id="two-interfaces-hold-it",
        ),
    ],
)
async def test_a_wireguard_tunnel_whose_local_address_is_not_safe_keeps_its_underlay_unrecorded(
    client, monkeypatch, local
):
    body = await _link_impact(
        client,
        monkeypatch,
        "wan:core1:pppoe0",
        wanlinks=CORE1_WAN,
        ports=[],
        tunnels=CORE1_TUNNELS,
        local=local,
    )
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert [r["uid"] for r in body["not_parallel"]] == [t["link"] for t in CORE1_TUNNELS]
    assert all("not recorded" in r["reason"] for r in body["not_parallel"])
    assert body["single_homed_prefixes"]["count"] == 1


async def test_a_wireguard_tunnel_whose_local_address_is_on_a_second_wan_link_is_a_parallel_path(
    client, monkeypatch
):
    wanlinks = [*CORE1_WAN, {"dev": "dev:core1", "link": "wan:core1:eth0", "under": ["dev:core1/if/eth0"]}]
    local = _core1_local(held=[["dev:core1/if/eth0", "dev:core1/port/eth0"]])
    body = await _link_impact(
        client,
        monkeypatch,
        "wan:core1:pppoe0",
        wanlinks=wanlinks,
        ports=[],
        tunnels=CORE1_TUNNELS,
        local=local,
    )
    assert body["parallel_circuits"] == [t["link"] for t in CORE1_TUNNELS] + ["wan:core1:eth0"]
    assert body["parallel_path"] == "established" and body["not_parallel"] == []
    assert body["single_homed_prefixes"]["count"] == 0


async def test_the_wan_link_under_a_lost_tunnel_is_no_parallel_path(client, monkeypatch):
    body = await _link_impact(
        client, monkeypatch, "tun:e1:ge3~gw1", wanlinks=VELO_WAN, ports=[], tunnels=VELO_TUNNELS[:1]
    )
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert body["not_parallel"] == [{"uid": "wan:e1:ge3", "reason": "carries the lost tunnel"}]
    assert body["single_homed_prefixes"]["count"] == 1


async def test_a_tunnel_over_a_second_wan_link_is_a_parallel_path(client, monkeypatch):
    wanlinks = [*VELO_WAN, {"dev": "dev:leaf101", "link": "wan:e1:ge4", "under": ["if:e1:ge4"]}]
    tunnels = [*VELO_TUNNELS, {"dev": "dev:leaf101", "link": "tun:e1:ge4~gw1", "under": ["if:e1:ge4"]}]
    body = await _link_impact(client, monkeypatch, "wan:e1:ge3", wanlinks=wanlinks, ports=[], tunnels=tunnels)
    assert body["parallel_circuits"] == ["tun:e1:ge4~gw1", "wan:e1:ge4"]
    assert body["parallel_path"] == "established"
    assert body["single_homed_prefixes"]["count"] == 0


# a LAN port to a device behind this one whose own WAN circuit runs through it
async def test_a_port_to_a_device_whose_wan_link_leaves_by_that_cable_is_no_parallel_path(
    client, monkeypatch
):
    wanlinks = [
        *BRANCH_WAN,
        {"dev": "dev:edge9", "link": "wan:edge9", "under": ["if:edge9:ge1", "port:edge9:ge1"]},
    ]
    ports = [{"dev": "dev:leaf101", "link": "port:br1:gi0/1", "far": [["port:edge9:ge1", "dev:edge9"]]}]
    body = await _link_impact(client, monkeypatch, "wan:br1-mpls", wanlinks=wanlinks, ports=ports)
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert body["single_homed_prefixes"]["count"] == 1


async def test_a_port_to_a_device_whose_tunnel_is_its_only_circuit_is_no_parallel_path(client, monkeypatch):
    tunnels = [{"dev": "dev:fw1", "link": "tun:ipsec:fw1", "under": ["if:fw1:outside", "port:fw1:outside"]}]
    ports = [{"dev": "dev:leaf101", "link": "port:br1:gi0/1", "far": [["port:fw1:outside", "dev:fw1"]]}]
    body = await _link_impact(
        client, monkeypatch, "wan:br1-mpls", wanlinks=BRANCH_WAN, ports=ports, tunnels=tunnels
    )
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "not established"
    assert body["single_homed_endpoints"]["count"] == 1


async def test_a_lone_circuit_has_no_other_circuit_to_be_parallel(client, monkeypatch):
    body = await _link_impact(client, monkeypatch, "wan:br1-mpls", wanlinks=BRANCH_WAN, ports=[])
    assert body["parallel_circuits"] == [] and body["parallel_path"] == "none"


async def test_link_impact_404_for_a_link_absent_from_the_run(client, monkeypatch):
    """Matches the device route's behavior (test_impact_404_for_a_device_absent_from_the_run)."""
    await login(client, "vera")
    rows = _link_rows_for(wanlinks=[], ports=[], tunnels=[])
    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession(rows=rows)))

    r = await client.get("/api/impact/link", params={"link": "wan:ghost"})
    assert r.status_code == 404
    assert "wan:ghost" in r.json()["error"]


def test_every_impact_query_carries_the_snap_guard():
    """A query without the guard would mix runs on the archive, the same way an
    unguarded tracer query would (tests/test_time_travel.py)."""
    import re

    from hst.assessment import evaluation

    src = "\n".join(
        __import__("pathlib").Path(module.__file__).read_text() for module in (impact_route, evaluation)
    )
    queries = [q for q in re.findall(r'"""(.*?)"""', src, re.S) if "MATCH" in q and "RETURN" in q]
    assert queries, "the source scan found no queries"
    # the guard is an equality on the run
    missing = [
        q
        for q in queries
        if not ("collection_ts = $snap" in q or "collection_ts: $snap" in q) or ".collection_ts, $snap)" in q
    ]
    assert not missing, f"impact queries without a $snap guard: {missing}"


# --- POST /api/impact/evaluate -------------------------------------------------------

CLIENT_PREFIX = "10.0.0.0/24"

# The inline request set: the clients behind R1 asking for the application on
# tcp/443, with a one-member condition. Same question tests/test_impact_evaluate.py
# asks the evaluator directly.
REQUEST = {
    "name": "the application",
    "destination": "app",
    "sources": [CLIENT_PREFIX],
    "members": [{"name": "app", "addresses": [APP]}],
    "condition": {"kind": "member", "member": "app"},
    "proto": "tcp",
    "port": "443",
}

# A declared condition in the graph: the application needs at least two of three
# backends and states a capacity requirement over the first of them. The capacity
# group is declarable and never answered from connectivity evidence, so the whole
# `and` stays not-established while the threshold group under it holds.
REQUIREMENT = {
    "uid": "svcreq:checkout",
    "name": "checkout",
    "destination": "checkout",
    "proto": "tcp",
    "dport": "443",
    "sport": None,
    "sources": [CLIENT_PREFIX],
    "applications": ["bsvc:checkout"],
    "roots": ["depgrp:checkout:root"],
}
BACKENDS = [
    {"uid": "ip:app:203.0.113.10", "name": "backend-1", "address": "203.0.113.10"},
    {"uid": "ip:app:203.0.113.11", "name": "backend-2", "address": "203.0.113.11"},
    {"uid": "ip:app:203.0.113.12", "name": "backend-3", "address": "203.0.113.12"},
]
DEPENDENCY_GROUPS = {
    "depgrp:checkout:root": {
        "uid": "depgrp:checkout:root",
        "kind": "and",
        "n": None,
        "name": "checkout",
        "groups": ["depgrp:checkout:backends", "depgrp:checkout:headroom"],
        "members": [],
    },
    "depgrp:checkout:backends": {
        "uid": "depgrp:checkout:backends",
        "kind": "threshold",
        "n": 2,
        "name": "backends",
        "groups": [],
        "members": BACKENDS,
    },
    "depgrp:checkout:headroom": {
        "uid": "depgrp:checkout:headroom",
        "kind": "capacity",
        "n": None,
        "name": "headroom",
        "groups": [],
        "members": [BACKENDS[0]],
    },
}


def _interface_rows() -> list[dict]:
    """The interfaces of the scripted estate in the shape the route reads them."""
    return [
        {
            "device_uid": i.device_uid,
            "uid": i.uid,
            "name": i.name,
            "context_uid": i.context_uid,
            "prefixes": list(i.prefixes),
            "addresses": list(i.addresses),
            "segments": list(i.segments),
        }
        for i in evfix._interfaces()
    ]


def _context_domain_rows() -> list[dict]:
    """Every context of the scripted estate in one declared routing domain."""
    return [
        {"uid": uid, "declared": ["estate"], "realized": [], "stamped": []}
        for uid in (evfix.VRF_R1, evfix.VRF_A, evfix.VRF_B)
    ]


def _run_child_here(monkeypatch, session):
    """Run the evaluation child in this process over the scripted session."""
    monkeypatch.setattr(manifest, "digest_of", lambda settings, cts: "0" * 64)
    monkeypatch.setattr(
        direct,
        "run_isolated",
        lambda settings, inputs: service.execute(
            settings, inputs, snapshot_session_factory=lambda reference: nullcontext(session)
        ),
    )


def _wire(monkeypatch, graph, *, routing=None, requirement=None, groups=None, session=None):
    """Point the evaluate route at the scripted estate: its own reads from the
    fixtures here, the gates at `graph`, and the routing calculation at `routing`.
    Returns the dict the routing read records its scope in."""
    session = session or _FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", _seam(session))
    _run_child_here(monkeypatch, session)
    seen: dict[str, Any] = {}

    def policy_manifest(snapshot):
        if snapshot.cts is None:
            return None
        return manifest.SnapshotManifest(
            snapshot_key=snapshot.cts,
            kind="full",
            opened=manifest.iso(snapshot.cts),
            published=manifest.iso(snapshot.cts),
            sources=[manifest.SourceEntry(name="edge", type="nxos", status="ok", config_sha256="fixture")],
            devices=[
                manifest.DeviceEntry(
                    source="edge",
                    host=uid.removeprefix("dev:"),
                    device_uids=[uid],
                    outcome="collected",
                    effective_run=str(snapshot.cts),
                    sections={
                        name: SectionOutcome(status="empty")
                        for name in ("acl", "interface_config", "nat", "vlan_filter")
                    },
                )
                for uid in (evfix.R1, evfix.A, evfix.B)
            ],
        )

    # Policy absence must have explicit collection evidence in the pinned snapshot.
    monkeypatch.setattr(impact_route.snapshotmod.Snapshot, "_read_manifest", policy_manifest)

    def read_rib_input(_session, **kwargs):
        seen["contexts"] = list(kwargs.get("contexts") or ())
        return RibGraphInput(input=routing if routing is not None else evfix._routing())

    monkeypatch.setattr(impact_route.simul_read, "read_rib_input", read_rib_input)

    def read(session, query: str, **params: Any):
        if query == snapshotmod._RETAINED_GRAPH:
            return [{"uid": evfix.R1}]
        if "(sr:ServiceRequirement:Obj {uid: $req, collection_ts: $snap})" in query:
            return [dict(requirement)] if requirement and requirement["uid"] == params["req"] else []
        if "(g:DependencyGroup:Obj)" in query:
            return [dict(groups[u]) for u in params["uids"] if u in (groups or {})]
        if query == impact_route._NETWORK_INTERFACES_QUERY:
            return _interface_rows()
        if query == evaluation._CONTEXT_DOMAINS_QUERY:
            return _context_domain_rows()
        if "RETURN DISTINCT d.uid AS device_uid, ip.ip AS ip, vs.uid AS uid" in query:
            return []
        if "RETURN d.hostname AS host" in query:
            host = params["device_uid"].removeprefix("dev:")
            return [{"host": host, "source": "edge", "scope": f"edge:{host}"}]
        rows = graph.read(query, **params)
        overlay = getattr(session, "overlay", None)
        return rows if overlay is None else overlay(query, params, rows)

    def read_one(session, query: str, **params: Any):
        if "(sr:ServiceRequirement:Obj {uid: $req, collection_ts: $snap})" in query:
            rows = read(session, query, **params)
            return rows[0] if rows else None
        return graph.read_one(query, **params)

    monkeypatch.setattr(pathmod, "_read", read)
    monkeypatch.setattr(pathmod, "_read_one", read_one)
    return seen


def _items(bucket: dict) -> list:
    return bucket["items"]


async def test_evaluate_requires_auth(client):
    r = await client.post("/api/impact/evaluate", json={"request": REQUEST})
    assert r.status_code == 401


async def test_evaluate_over_the_snapshot_alone_proves_the_request(client, monkeypatch):
    """No change set at all: the question is what the snapshot itself establishes,
    and the baseline selects peer A and proves it."""
    await login(client, "vera")
    scope = _wire(monkeypatch, evfix.Graph())

    r = await client.post("/api/impact/evaluate", json={"request": REQUEST})
    assert r.status_code == 200
    body = r.json()

    assert body["snapshot"] == "2000"
    assert body["mode"] == "possible"
    assert body["request"]["name"] == "the application"
    assert body["request"]["condition"] == {"kind": "member", "member": "app"}
    assert _items(body["passes"]["before"]) == [CLIENT_PREFIX], body["missing_evidence"]
    assert _items(body["passes"]["after"]) == [CLIENT_PREFIX]
    assert body["decided_change"]["loss"]["count"] == 0
    assert body["open_change"]["loss"]["count"] == 0
    assert body["open"]["before"]["count"] == 0
    assert body["missing_evidence"] == []
    # the scope of the routing calculation is derived from what the request touches
    assert scope["contexts"] == ["vrf:a", "vrf:b", "vrf:r1"]
    outcomes = {(e["side"], e["result"]["answer"]) for e in body["evidence"]["items"]}
    assert outcomes == {("before", "true"), ("after", "true")}


async def test_evaluate_reports_no_loss_when_the_second_peer_carries_the_request(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph())

    body = (await client.post("/api/impact/evaluate", json={"request": REQUEST, "intents": [SHUT_A]})).json()
    assert body["decided_change"]["loss"]["count"] == 0
    assert body["open_change"]["loss"]["count"] == 0
    assert body["decided_change"]["gain"]["count"] == 0
    assert _items(body["passes"]["after"]) == [CLIENT_PREFIX]
    assert body["intents"] == [SHUT_A]


async def test_evaluate_proves_the_loss_when_a_downstream_filter_blocks(client, monkeypatch):
    """B is selected and a filter on it denies the flow,
    so the loss is proven and the evidence names the device that decided it."""
    await login(client, "vera")
    graph = evfix.Graph()
    evfix._firewall(graph, B, "rb:b", [evfix._deny(APP)])
    _wire(monkeypatch, graph)

    body = (await client.post("/api/impact/evaluate", json={"request": REQUEST, "intents": [SHUT_A]})).json()
    assert _items(body["decided_change"]["loss"]) == [CLIENT_PREFIX]
    assert _items(body["open_change"]["loss"]) == [CLIENT_PREFIX]
    assert body["passes"]["after"]["count"] == 0
    # the third part of the population, always present so a reader of a
    # capped result (no `outcomes`) can place every client: holds, fails or
    # not established
    assert _items(body["fails"]["after"]) == [CLIENT_PREFIX]
    assert body["fails"]["before"]["count"] == 0
    assert body["members"] == [
        {
            "name": "app",
            "decided_loss": True,
            "open_loss": True,
            "decided_gain": False,
            "open_gain": False,
            # the disjoint reading: passes before, fails after, and
            # nothing in the other six parts
            "triage": {
                "decided_loss": True,
                "passes_then_open": False,
                "open_then_fails": False,
                "open_throughout": False,
                "decided_gain": False,
                "open_then_passes": False,
                "fails_then_open": False,
            },
            "before": {"passes": 1, "fails": 0, "open": 0},
            "after": {"passes": 0, "fails": 1, "open": 0},
        }
    ]
    after = [e for e in body["evidence"]["items"] if e["side"] == "after"]
    assert [e["result"]["answer"] for e in after] == ["false"]
    denies = [s for s in after[0]["steps"] if s["stage"] == "filter" and s["kind"] == "deny"]
    assert [s["device_uid"] for s in denies] == [B]


async def test_evaluate_leaves_the_outcome_not_established_when_bs_routes_are_not_observed(
    client, monkeypatch
):
    """B's paths were never captured, so nothing is proven
    on either side. The clients stay in the upper bound and out of the lower one,
    and the answer says what evidence is missing."""
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph(), routing=evfix._routing(b_observed=False))

    body = (await client.post("/api/impact/evaluate", json={"request": REQUEST, "intents": [SHUT_A]})).json()
    assert body["decided_change"]["loss"]["count"] == 0
    assert _items(body["open_change"]["loss"]) == [CLIENT_PREFIX]
    assert _items(body["open"]["before"]) == [CLIENT_PREFIX]
    assert _items(body["open"]["after"]) == [CLIENT_PREFIX]
    assert body["passes"]["before"]["count"] == 0
    # unproven is not failed: the clients stay in the upper bound
    assert body["fails"]["before"]["count"] == 0
    assert body["fails"]["after"]["count"] == 0
    assert body["missing_evidence"]
    # a line stands alone here: it names the router and the peer (the session uid is in
    # the structured gap, gaps[].session_uid)
    assert any(f"BGP peer 10.0.2.2 on {R1}:" in line for line in body["missing_evidence"])


async def test_evaluate_proves_the_loss_when_bs_next_hop_cannot_resolve(client, monkeypatch):
    """B's advertisement names a next hop no interface in
    the model holds, so after the change there is no route at all."""
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph(), routing=evfix._routing(b_next_hop="10.77.0.1"))

    body = (await client.post("/api/impact/evaluate", json={"request": REQUEST, "intents": [SHUT_A]})).json()
    assert _items(body["decided_change"]["loss"]) == [CLIENT_PREFIX]
    assert [g["kind"] for g in body["gaps"]] == ["unresolved-next-hop"]
    after = [e for e in body["evidence"]["items"] if e["side"] == "after"]
    assert after[0]["steps"][-1]["kind"] == "no-route"
    assert after[0]["steps"][-1]["device_uid"] == R1


async def test_evaluate_builds_the_declared_condition_from_the_graph(client, monkeypatch):
    """A ServiceRequirement and its DependencyGroup tree: and over a threshold group
    and a capacity group, nested, with the members read off the groups themselves."""
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph(), requirement=REQUIREMENT, groups=DEPENDENCY_GROUPS)

    r = await client.post("/api/impact/evaluate", json={"requirement": "svcreq:checkout"})
    assert r.status_code == 200
    body = r.json()

    assert body["request"]["requirement"] == "svcreq:checkout"
    assert body["request"]["name"] == "checkout"
    assert [m["name"] for m in body["request"]["members"]] == [b["uid"] for b in BACKENDS]
    assert body["request"]["condition"] == {
        "kind": "every",
        "parts": [
            {
                "kind": "n-of-m",
                "n": 2,
                "parts": [{"kind": "member", "member": b["uid"]} for b in BACKENDS],
            },
            {"kind": "capacity", "parts": [{"kind": "member", "member": BACKENDS[0]["uid"]}]},
        ],
    }
    assert body["passes"]["before"]["count"] == 0
    assert _items(body["open"]["before"]) == [CLIENT_PREFIX]
    assert body["decided_change"]["loss"]["count"] == 0


async def test_a_capacity_group_does_not_stop_an_or_condition_from_holding(client, monkeypatch):
    """not-established is a third outcome, not a failure: an `or` that already has a
    part holding still holds beside a capacity group it cannot answer."""
    await login(client, "vera")
    groups = {k: dict(v) for k, v in DEPENDENCY_GROUPS.items()}
    groups["depgrp:checkout:root"] = {**groups["depgrp:checkout:root"], "kind": "or"}
    _wire(monkeypatch, evfix.Graph(), requirement=REQUIREMENT, groups=groups)

    body = (await client.post("/api/impact/evaluate", json={"requirement": "svcreq:checkout"})).json()
    assert body["request"]["condition"]["kind"] == "any-one"
    assert _items(body["passes"]["before"]) == [CLIENT_PREFIX]
    assert body["open"]["before"]["count"] == 0


async def test_evaluate_404_for_a_requirement_absent_from_the_run(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph())

    r = await client.post("/api/impact/evaluate", json={"requirement": "svcreq:ghost"})
    assert r.status_code == 404
    assert "svcreq:ghost" in r.json()["error"]


async def test_evaluate_rejects_a_dependency_group_kind_that_is_not_declared(client, monkeypatch):
    await login(client, "vera")
    groups = {k: dict(v) for k, v in DEPENDENCY_GROUPS.items()}
    groups["depgrp:checkout:backends"] = {
        **groups["depgrp:checkout:backends"],
        "kind": "at-least-one-ish",
    }
    _wire(monkeypatch, evfix.Graph(), requirement=REQUIREMENT, groups=groups)

    r = await client.post("/api/impact/evaluate", json={"requirement": "svcreq:checkout"})
    assert r.status_code == 400
    assert "at-least-one-ish" in r.json()["error"]


async def test_evaluate_refuses_a_cyclic_declaration(client, monkeypatch):
    await login(client, "vera")
    groups = {k: dict(v) for k, v in DEPENDENCY_GROUPS.items()}
    groups["depgrp:checkout:backends"] = {
        **groups["depgrp:checkout:backends"],
        "groups": ["depgrp:checkout:root"],
    }
    _wire(monkeypatch, evfix.Graph(), requirement=REQUIREMENT, groups=groups)

    r = await client.post("/api/impact/evaluate", json={"requirement": "svcreq:checkout"})
    assert r.status_code == 400
    assert "cyclic" in r.json()["error"]


async def test_evaluate_needs_exactly_one_of_a_requirement_and_a_request(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph())

    neither = await client.post("/api/impact/evaluate", json={})
    assert neither.status_code == 400
    both = await client.post(
        "/api/impact/evaluate", json={"requirement": "svcreq:checkout", "request": REQUEST}
    )
    assert both.status_code == 400
    assert "exactly one" in both.json()["error"]


async def test_evaluate_rejects_a_mode_the_evaluator_does_not_have(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph())

    r = await client.post("/api/impact/evaluate", json={"request": REQUEST, "mode": "certain"})
    assert r.status_code == 400
    assert "possible" in r.json()["error"]


async def test_evaluate_answers_in_guaranteed_mode_when_asked(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph())

    body = (await client.post("/api/impact/evaluate", json={"request": REQUEST, "mode": "guaranteed"})).json()
    assert body["mode"] == "guaranteed"


async def test_evaluate_pins_the_answer_to_the_requested_run(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph())

    body = (await client.post("/api/impact/evaluate", json={"request": REQUEST, "snapshot": "3000"})).json()
    assert body["snapshot"] == "3000"


async def test_evaluate_rejects_a_non_numeric_run_id(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph())

    r = await client.post("/api/impact/evaluate", json={"request": REQUEST, "snapshot": "latest"})
    assert r.status_code == 400


async def test_evaluate_404s_an_unknown_run_before_any_engine_read(client, monkeypatch):
    await login(client, "vera")
    session = _FakeGraphSession(retained=False)
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    def no_engine(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the engine ran against an unknown run")

    monkeypatch.setattr(impact_route, "evaluate_change", no_engine)
    monkeypatch.setattr(impact_route.ribsource, "for_snapshot", no_engine)

    r = await client.post("/api/impact/evaluate", json={"request": REQUEST, "snapshot": "3000"})
    assert r.status_code == 404
    assert r.json()["error"] == "unknown run: 3000"
    assert session.retained_checks == [3000]
    assert session.calls == []


async def test_evaluate_rejects_an_address_the_grammar_cannot_read(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph())
    request = {**REQUEST, "sources": ["not-an-address"]}

    r = await client.post("/api/impact/evaluate", json={"request": request})
    assert r.status_code == 400
    assert "not-an-address" in r.json()["error"]


def test_the_evaluate_queries_are_covered_by_the_snap_guard_scan():
    import re
    from pathlib import Path

    from hst.assessment import evaluation

    src = "\n".join(Path(module.__file__).read_text() for module in (impact_route, evaluation))
    queries = [q for q in re.findall(r'"""(.*?)"""', src, re.S) if "MATCH" in q and "RETURN" in q]
    added = [
        q
        for q in queries
        if "ServiceRequirement" in q or "(g:DependencyGroup:Obj)" in q or "AS device_uid" in q
    ]
    assert len(added) == 3, [q.splitlines()[1] for q in added]
    for query in added:
        assert "collection_ts = $snap" in query or "collection_ts: $snap" in query
        assert ".collection_ts, $snap)" not in query


async def test_captured_external_routes_do_not_silently_become_a_fixed_boundary(client, monkeypatch):
    await login(client, "vera")
    _wire(monkeypatch, evfix.Graph(), routing=evfix._routing(fixed_boundary=False))
    response = await client.post("/api/impact/evaluate", json={"request": REQUEST, "intents": [SHUT_A]})
    assert response.status_code == 200
    body = response.json()
    assert any("equal-cost paths" in a for a in body["assumptions"])
    assert body["decided_change"]["loss"]["count"] == body["decided_change"]["gain"]["count"] == 0
    assert _items(body["triage"]["passes_then_open"]) == [CLIENT_PREFIX]
    assert any(g["kind"] == "external-route-response-unobserved" for g in body["gaps"])


CIRCUIT = "eqx:connection:44444444-dddd"
CIRCUIT_PORTS = [
    {"dev": "dev:leaf101", "link": "dev:leaf101/port/eth1-49"},
    {"dev": "dev:pa3core", "link": "dev:pa3core/port/eth1-49"},
]


def _circuit_rows_for() -> Any:
    """GET /api/impact/link for a VirtualCircuit uid: the circuit-inventory
    queries know the two device ports the derived link joins; the circuit
    lookup (keyed by `circuit_uid`) resolves the uid to that link, and the
    bridge-domain read names what both ports carry."""

    def rows(query: str) -> list[dict]:
        if "circuit_uid = $link" in query:
            return [{"a": "dev:leaf101/port/eth1-49", "z": "dev:pa3core/port/eth1-49"}]
        if "CARRIES]->(va:VlanInstance)" in query:
            return [{"uid": "bd:vlan:fab0:100", "name": "users", "vid": 100}]
        if "HAS_LINK" in query or "d.uid AS dev, t.uid AS link" in query:
            return []
        if "CONNECTED_TO" in query:
            return [dict(r) for r in CIRCUIT_PORTS]
        return _rows_for(query)

    return rows


async def test_link_impact_resolves_a_fabric_circuit_to_its_derived_link(client, monkeypatch):
    await login(client, "vera")
    session = _FakeGraphSession(rows=_circuit_rows_for())
    monkeypatch.setattr(impact_route, "_session", _seam(session))

    r = await client.get("/api/impact/link", params={"link": CIRCUIT})
    assert r.status_code == 200
    body = r.json()
    assert body["device"] == "dev:leaf101"
    assert body["link"] == "dev:leaf101/port/eth1-49"
    assert body["circuit"] == {
        "uid": CIRCUIT,
        "ports": ["dev:leaf101/port/eth1-49", "dev:pa3core/port/eth1-49"],
        "bridge_domains": [{"uid": "bd:vlan:fab0:100", "name": "users", "vid": 100}],
    }
    # the derived link is the device's only circuit, so the assessment runs as for any link
    assert body["other_circuits"] == []
    assert [p["uid"] for p in body["single_homed_prefixes"]["items"]] == ["pfx:a"]
    lookups = [c for c in session.calls if "circuit_uid = $link" in c["query"]]
    assert [c["params"]["link"] for c in lookups] == [CIRCUIT]


async def test_link_impact_on_a_plain_link_names_no_circuit(client, monkeypatch):
    await login(client, "vera")
    rows = _link_rows_for(wanlinks=[], ports=[], tunnels=LONE_TUNNEL_CIRCUIT)
    monkeypatch.setattr(impact_route, "_session", _seam(_FakeGraphSession(rows=rows)))

    body = (await client.get("/api/impact/link", params={"link": "tun:vxlan:1"})).json()
    assert body["circuit"] is None and body["link"] == "tun:vxlan:1"
