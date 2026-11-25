"""Snapshot evidence wiring for POST /api/impact/evaluate."""

from typing import Any

import pytest
import tests.app.test_impact_api as api
from tests.app.conftest import login

import hst.app.routes.impact as impact_route
from hst import path as pathmod
from hst.app import simul_read
from hst.app.crypto import generate_key
from hst.app.simul_read import RibGraphInput
from hst.assessment import evaluation
from hst.core import Settings, ipenc, manifest, sidestore
from hst.core.model import SectionOutcome, TableOutcome
from hst.core.snapshot import Snapshot


class _Reader:
    def __init__(self, snapshot: Any) -> None:
        self.snapshot = snapshot
        self.closed = False

    def close(self) -> None:
        self.closed = True


async def test_endpoint_binds_all_routing_readers_to_the_resolved_snapshot(client, monkeypatch):
    """The graph pin and every observation reader come from one resolution."""
    await login(client, "vera")
    api._wire(monkeypatch, api.evfix.Graph())

    made: dict[str, _Reader] = {}

    def factory(kind: str):
        def make(snapshot):
            reader = _Reader(snapshot)
            made[kind] = reader
            return reader

        return make

    monkeypatch.setattr(impact_route.ribsource, "for_snapshot", factory("rib"))
    monkeypatch.setattr(impact_route.bgpsource, "for_snapshot", factory("bgp"))
    monkeypatch.setattr(impact_route.ospfsource, "for_snapshot", factory("ospf"))

    seen: dict[str, Any] = {}

    def compile_input(_session, **kwargs):
        seen.update(kwargs)
        return RibGraphInput(input=api.evfix._routing())

    monkeypatch.setattr(impact_route.simul_read, "read_rib_input", compile_input)

    response = await client.post("/api/impact/evaluate", json={"request": api.REQUEST, "snapshot": "2000"})

    assert response.status_code == 200
    assert {reader.snapshot.snapshot_id for reader in made.values()} == {"2000"}
    # the evaluation child records each read through the dependency recorder
    assert seen["rib_source"].reader is made["rib"]
    assert seen["bgp_source"].reader is made["bgp"]
    assert seen["ospf_source"].reader is made["ospf"]
    assert all(reader.closed for reader in made.values())


def test_direct_evaluator_callers_can_omit_observation_readers(monkeypatch):
    api._wire(monkeypatch, api.evfix.Graph())
    wired_read = pathmod._read

    def read_wired(session, query, **params):
        if "RETURN DISTINCT d.uid AS device_uid, ip.ip AS ip, vs.uid AS uid" in query:
            return []
        return wired_read(session, query, **params)

    monkeypatch.setattr(pathmod, "_read", read_wired)
    seen: dict[str, Any] = {}

    def compile_input(_session, **kwargs):
        seen.update(kwargs)
        return RibGraphInput(input=api.evfix._routing())

    monkeypatch.setattr(impact_route.simul_read, "read_rib_input", compile_input)
    impact_route.evaluate_change(
        api._FakeGraphSession(),
        intents=[],
        request=impact_route._request_from_body(impact_route.RequestBody(**api.REQUEST)),
    )

    assert seen["rib_source"] is None
    assert seen["bgp_source"] is None
    assert seen["ospf_source"] is None


def _path_row(session_uid: str, peer: str, *, prefix: str = "203.0.113.0/24") -> dict[str, Any]:
    lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
    return {
        "device_uid": api.R1,
        "context_uid": api.evfix.VRF_R1,
        "session_uid": session_uid,
        "peer_ip": peer,
        "af": af,
        "safi": "unicast",
        "direction": "received",
        "rib_type": "adj-rib-in",
        "policy_stage": "pre-import",
        "path_id": "0",
        "prefix": prefix,
        "prefixlen": prefixlen,
        "lo": lo,
        "hi": hi,
        "next_hop": peer,
        "next_hop_context_uid": None,
        "as_path": "65002" if session_uid == api.evfix.SESSION_A else "65003",
        "local_pref": 100,
        "med": 0,
        "origin": "i",
        "communities": None,
        "best": None,
    }


def _session_row(session_uid: str, peer: str) -> dict[str, Any]:
    return {
        "device_uid": api.R1,
        "context_uid": api.evfix.VRF_R1,
        "session_uid": session_uid,
        "peer_ip": peer,
        "af": 4,
        "safi": "unicast",
        "state": "established",
        "established_since_ms": None,
        "prefixes_received": 1,
        "prefixes_advertised": None,
        "capabilities": None,
    }


def _rib_row(
    next_hop: str | None,
    prefix: str = "203.0.113.0/24",
    *,
    device_uid: str = api.R1,
    context_uid: str = api.evfix.VRF_R1,
    interface: str = "eth1",
    protocol: str = "bgp",
) -> dict[str, Any]:
    lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
    return {
        "device_uid": device_uid,
        "context_uid": context_uid,
        "vrf": "default",
        "prefix": prefix,
        "next_hop": next_hop,
        "interface": interface,
        "protocol": protocol,
        "metric": 0,
        "af": af,
        "prefixlen": prefixlen,
        "lo": lo,
        "hi": hi,
    }


async def test_endpoint_compiles_only_manifest_published_observations_and_withdraws_a_peer(
    client, monkeypatch, tmp_path
):
    pytest.importorskip("duckdb")
    pytest.importorskip("pyarrow")
    await login(client, "vera")

    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    run_id = "2000-aaaaaaaa"
    paths = sidestore.write_table(
        settings.sidestore_dir,
        "bgp_session_routes",
        "edge",
        "r1",
        run_id,
        [
            _path_row(api.evfix.SESSION_A, "10.0.1.2"),
            _path_row(api.evfix.SESSION_B, "10.0.2.2"),
        ],
        2000,
    )
    sessions = sidestore.write_table(
        settings.sidestore_dir,
        "bgp_sessions",
        "edge",
        "r1",
        run_id,
        [
            _session_row(api.evfix.SESSION_A, "10.0.1.2"),
            _session_row(api.evfix.SESSION_B, "10.0.2.2"),
        ],
        2000,
    )
    observed_rib = [_rib_row("10.0.1.2")]
    observed_rib.extend(
        _rib_row(
            None,
            row["prefix"],
            device_uid=context["device_uid"],
            context_uid=row["context_uid"],
            interface=row["interface"],
            protocol="connected",
        )
        for context in api.evfix._routing().contexts
        for row in api.evfix._routing().connected
        if row["context_uid"] == context["uid"]
    )
    rib_file = sidestore.write_table(settings.sidestore_dir, "rib", "edge", "r1", run_id, observed_rib, 2000)
    assert paths and sessions and rib_file
    files = [manifest.file_entry(settings, p) for p in (paths, sessions, rib_file)]
    tables = {
        "bgp_session_routes": TableOutcome(status="complete", path=files[0].path),
        "bgp_sessions": TableOutcome(status="complete", path=files[1].path),
        "rib": TableOutcome(status="complete", path=files[2].path),
    }
    for uid in (api.evfix.SESSION_A, api.evfix.SESSION_B):
        tables[manifest.bgp_direction_key(uid, "received")] = TableOutcome(status="complete", row_count=1)
        tables[manifest.bgp_direction_key(uid, "accepted")] = TableOutcome(status="not-captured")
        tables[manifest.bgp_direction_key(uid, "advertised")] = TableOutcome(status="not-captured")
    record = manifest.SnapshotManifest(
        snapshot_key=2000,
        kind="full",
        opened=manifest.iso(2000),
        published=manifest.iso(2000),
        devices=[
            manifest.DeviceEntry(
                source="edge",
                host="r1",
                outcome="collected",
                effective_run=run_id,
                tables=tables,
                device_uids=[c["device_uid"] for c in api.evfix._routing().contexts],
                sections={
                    name: SectionOutcome(status="empty")
                    for name in ("acl", "interface_config", "nat", "vlan_filter")
                },
            )
        ],
        sources=[manifest.SourceEntry(name="edge", type="nxos", status="ok", config_sha256="fixture")],
        files=files,
    )
    manifest.write(settings, record)
    sidestore.write_table(
        settings.sidestore_dir,
        "bgp_session_routes",
        "edge",
        "r1",
        "2000-ffffffff",
        [_path_row(api.evfix.SESSION_A, "192.0.2.254", prefix="198.51.100.0/24")],
        2000,
    )

    graph = api.evfix.Graph()
    session = api._FakeGraphSession()
    monkeypatch.setattr(impact_route, "_session", api._seam(session))
    api._run_child_here(monkeypatch, session)
    monkeypatch.setattr(
        impact_route.snapshotmod,
        "resolve",
        lambda _session, _settings, _cts=None: Snapshot(2000, settings),
    )

    interfaces = api._interface_rows()
    contexts = [
        {
            "uid": c["uid"],
            "name": "default",
            "device_uids": [c["device_uid"]],
            "platforms": ["nxos"],
            "vendors": ["cisco"],
        }
        for c in api.evfix._routing().contexts
    ]
    connected = [
        {**row, "kind": "ORIGINATES", "proto": "connected", "gateways": [row["interface"]]}
        for row in api.evfix._routing().connected
    ]
    process = dict(api.evfix._routing().bgp.processes[0])
    process.update(origin_config_recorded=True, origin_afs=[4, 6])
    process_row = {
        "uid": process["uid"],
        "props": process,
        "context_uid": process["context_uid"],
        "platforms": ["nxos"],
        "vendors": ["cisco"],
    }
    session_rows = [
        {"uid": s["uid"], "process_uid": s["process_uid"], "props": s}
        for s in api.evfix._routing().bgp.sessions
    ]

    def read(session, query: str, **params: Any):
        if query == api.snapshotmod._RETAINED_GRAPH:
            rows = [{"uid": api.R1}]
        elif query == impact_route._NETWORK_INTERFACES_QUERY:
            rows = interfaces
        elif query == evaluation._CONTEXT_DOMAINS_QUERY:
            rows = api._context_domain_rows()
        elif "RETURN d.hostname AS host" in query:
            rows = [{"host": params["device_uid"].removeprefix("dev:"), "source": "edge", "scope": "edge:r1"}]
        elif "v.uid IN $vrfs" in query and "RETURN DISTINCT rp.uid AS uid" in query:
            rows = [{"uid": "rp:r1"}]
        elif "far.uid AS uid" in query:
            rows = []
        elif query == simul_read._CONTEXTS:
            rows = contexts
        elif query == simul_read._PROCESSES:
            rows = [process_row]
        elif "properties(b) AS props" in query:
            rows = session_rows
        elif "ip.ip AS ip" in query or query == simul_read._ORIGIN_POLICIES:
            rows = []
        elif query == simul_read._POLICIES:
            rows = [{"uid": "pol:a", **api.evfix.LP_200}]
        elif (
            "og.proto AS proto" in query
            or "RETURN v.uid AS vrf_uid, type(r) AS kind, rt.value AS rt" in query
        ):
            rows = []
        elif "type(r) AS kind" in query:
            rows = connected
        elif (
            "RouteTarget" in query
            or "toLower(coalesce(rp.proto, '')) = 'ospf'" in query
            or "PbrPolicy" in query
        ):
            rows = []
        else:
            rows = graph.read(query, **params)
        overlay = getattr(session, "overlay", None)
        return rows if overlay is None else overlay(query, params, rows)

    monkeypatch.setattr(pathmod, "_read", read)
    monkeypatch.setattr(pathmod, "_read_one", lambda session, query, **p: graph.read_one(query, **p))
    compiled: list[RibGraphInput] = []
    production_compiler = simul_read.read_rib_input

    def compile_and_record(*args, **kwargs):
        result = production_compiler(*args, **kwargs)
        compiled.append(result)
        return result

    monkeypatch.setattr(impact_route.simul_read, "read_rib_input", compile_and_record)

    baseline = (await client.post("/api/impact/evaluate", json={"request": api.REQUEST})).json()
    withdrawn = (
        await client.post("/api/impact/evaluate", json={"request": api.REQUEST, "intents": [api.SHUT_A]})
    ).json()

    assert baseline["passes"]["before"]["items"] == [api.CLIENT_PREFIX], (
        baseline["missing_evidence"],
        baseline["model_errors"],
    )
    assert withdrawn["passes"]["after"]["items"] == []
    assert withdrawn["open"]["after"]["items"] == [api.CLIENT_PREFIX]
    assert withdrawn["decided_change"]["loss"]["count"] == withdrawn["decided_change"]["gain"]["count"] == 0
    assert any(g["kind"] == "external-route-response-unobserved" for g in withdrawn["gaps"])
    assert len(compiled) == 2
    for result in compiled:
        assert {row["session_uid"] for row in result.input.observed_paths} == {
            api.evfix.SESSION_A,
            api.evfix.SESSION_B,
        }
        assert {row["prefix"] for row in result.input.observed_paths} == {"203.0.113.0/24"}
        app_route = next(
            row for row in result.input.observed_rib[api.evfix.VRF_R1] if row["prefix"] == "203.0.113.0/24"
        )
        assert app_route["next_hop"] == "10.0.1.2"
