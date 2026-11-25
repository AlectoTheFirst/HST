"""/api/equinix: viewer surface, Neo4j faked at the module seam. Every name
and uid here is made up."""

import contextlib

from tests.app.conftest import login

import hst.app.routes.equinix as route
from hst.queries import QUERIES

FP_PRI = "eqx:port:pri"
FP_SEC = "eqx:port:sec"
SWC = "dev:xx-swc-02"
EDGE = "eqx:device:edge-1"


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


def _port(uid, name, *, device=None, port_name=None, by=None):
    return {
        "uid": uid,
        "name": name,
        "ibx": "XX1",
        "state": "ACTIVE",
        "speed_mbps": 10000,
        "redundancy": "primary",
        "lag": None,
        "cable_ids": ["21000001"],
        "port": f"{device}/port/{port_name}" if device else None,
        "port_name": port_name,
        "device": device,
        "device_name": "XX-SWC-02" if device else None,
        "device_platform": "nxos" if device else None,
        "bound_by": by,
    }


def _circuit(uid, name, state, a, z=None, *, provider=None, a_tag=100, z_tag=None, cabled=False):
    return {
        "uid": uid,
        "name": name,
        "type": "EVPL_VC",
        "state": state,
        "bandwidth_mbps": 1000,
        "provider": provider,
        "a_side_kind": "colo",
        "z_side_kind": "sp" if provider else "colo",
        "a_virtual_device": None,
        "a": a,
        "a_tag": a_tag,
        "z": z,
        "z_tag": z_tag,
        "cabled": cabled,
    }


def _fp_end(uid, name, metro="XX", ibx="XX1"):
    return {
        "node": uid,
        "name": name,
        "fabric_port": True,
        "ibx": ibx,
        "metro": metro,
        "device": None,
        "device_name": None,
    }


METRO = {
    route._PORTS: [
        _port(FP_PRI, "ACME-XX1-EXT-PRI-01", device=SWC, port_name="Ethernet1/3", by="name+cable"),
        _port(FP_SEC, "ACME-XX1-EXT-SEC-01"),
    ],
    route._EDGE_DEVICES: [
        {
            "uid": EDGE,
            "name": "XX-EDGE-01",
            "vendor": "Cisco",
            "model": "C8000V",
            "role": "router",
            "ibx": "XX1",
            "status": "PROVISIONED",
            "bound_device": None,
            "same_as": None,
            "same_as_name": None,
        }
    ],
    route._CIRCUITS: [
        _circuit("vc1", "to-cloud", "ACTIVE", _fp_end(FP_PRI, "ACME-XX1-EXT-PRI-01"), provider="AWS"),
        _circuit(
            "vc2",
            "xx-to-yy",
            "ACTIVE",
            _fp_end(FP_PRI, "ACME-XX1-EXT-PRI-01"),
            _fp_end("eqx:port:yy", "ACME-YY1-EXT-PRI-01", metro="YY", ibx="YY1"),
            z_tag=200,
            cabled=True,
        ),
        _circuit("vc3", "old", "DEPROVISIONED", _fp_end(FP_SEC, "ACME-XX1-EXT-SEC-01")),
    ],
}


async def test_the_metro_list_counts_ports_and_edge_devices_and_names_the_queries(client, monkeypatch):
    await login(client, "vera")
    fake = _install(
        monkeypatch,
        {
            route._METROS: [{"metro": "XX", "ports": 2, "ibxs": ["XX2", "XX1"]}],
            route._EDGE_METROS: [{"metro": "XX", "edge_devices": 1}, {"metro": "ZZ", "edge_devices": 2}],
        },
    )
    r = await client.get("/api/equinix/metros")
    assert r.status_code == 200
    body = r.json()
    assert body["metros"] == [
        {"metro": "XX", "ports": 2, "ibxs": ["XX1", "XX2"], "edge_devices": 1},
        {"metro": "ZZ", "ports": 0, "ibxs": [], "edge_devices": 2},
    ]
    assert [q["key"] for q in body["queries"]] == [q["key"] for q in QUERIES if q["group"] == "equinix"]
    assert fake.params[route._METROS]["snap"] == 4242


async def test_a_metro_without_ports_and_edge_devices_is_a_404(client, monkeypatch):
    await login(client, "vera")
    fake = _install(monkeypatch, {})
    r = await client.get("/api/equinix/metro", params={"metro": "QQ"})
    assert r.status_code == 404
    assert route._CIRCUITS not in fake.params


async def test_the_metro_has_its_ports_switches_edge_devices_and_live_circuits(client, monkeypatch):
    await login(client, "vera")
    fake = _install(monkeypatch, METRO)
    r = await client.get("/api/equinix/metro", params={"metro": "XX"})
    assert r.status_code == 200
    body = r.json()
    assert body["metro"] == "XX"
    assert fake.params[route._PORTS] == {"metro": "XX", "snap": 4242}

    pri, sec = body["ports"]
    assert pri["bound"] == {
        "device": SWC,
        "port": f"{SWC}/port/Ethernet1/3",
        "port_name": "Ethernet1/3",
        "by": "name+cable",
    }
    assert sec["bound"] is None
    assert body["devices"] == [{"uid": SWC, "name": "XX-SWC-02", "platform": "nxos", "kind": "switch"}]
    assert [d["uid"] for d in body["edge_devices"]] == [EDGE]

    # the deprovisioned circuit is counted, not listed
    assert body["ended_circuits"] == 1
    assert [c["uid"] for c in body["circuits"]] == ["vc1", "vc2"]
    cloud, other_metro = body["circuits"]
    assert cloud["a"]["kind"] == "port" and cloud["a"]["tag"] == 100
    assert cloud["z"] == {"kind": "provider", "name": "AWS", "tag": None}
    assert other_metro["z"]["metro"] == "YY" and other_metro["z"]["tag"] == 200
    assert other_metro["cabled"] is True
    assert {q["key"] for q in body["queries"]} >= {"equinix-fabric-ports", "equinix-circuits"}


async def test_a_far_end_of_another_party_is_named_by_the_circuit(client, monkeypatch):
    await login(client, "vera")
    vd = _circuit("vc4", "from-partner", "ACTIVE", None, _fp_end(FP_PRI, "ACME-XX1-EXT-PRI-01"))
    vd["a_virtual_device"] = "PARTNER-FW-NODE0"
    foreign = _circuit("vc5", "to-partner-port", "ACTIVE", _fp_end(FP_PRI, "ACME-XX1-EXT-PRI-01"))
    _install(monkeypatch, {**METRO, route._CIRCUITS: [vd, foreign]})
    body = (await client.get("/api/equinix/metro", params={"metro": "XX"})).json()
    ends = {c["uid"]: c for c in body["circuits"]}
    assert ends["vc4"]["a"] == {"kind": "other", "name": "PARTNER-FW-NODE0", "tag": 100}
    assert ends["vc5"]["z"] == {"kind": "other", "name": "colo", "tag": None}


async def test_a_circuit_that_is_not_active_is_counted_by_state_and_not_drawn(client, monkeypatch):
    await login(client, "vera")
    end = _fp_end(FP_PRI, "ACME-XX1-EXT-PRI-01")
    rows = {
        **METRO,
        route._CIRCUITS: [
            _circuit("vc1", "pending", "PENDING", end),
            _circuit("vc2", "failed", "FAILED", end),
            _circuit("vc3", "stateless", None, end),
            _circuit("vc4", "live", "active", end),
            _circuit("vc5", "gone", "CANCELLED", end),
        ],
    }
    _install(monkeypatch, rows)
    body = (await client.get("/api/equinix/metro", params={"metro": "XX"})).json()
    assert [c["uid"] for c in body["circuits"]] == ["vc4"]
    assert body["other_circuits"] == {"FAILED": 1, "PENDING": 1, "none": 1}
    assert body["ended_circuits"] == 1


def test_an_unbound_fabric_port_names_its_reason():
    refused = {**_port("fp:r", "REFUSED"), "binding": "port:gone", "realized": False}
    several = {**_port("fp:s", "SEVERAL"), "issue": "several-ports", "issue_ports": ["port:1", "port:2"]}
    plain = _port("fp:p", "PLAIN")
    assert route._unbound(refused) == {"reason": "binding-refused", "ports": ["port:gone"]}
    assert route._unbound(several) == {"reason": "several-ports", "ports": ["port:1", "port:2"]}
    assert route._unbound(plain) is None
