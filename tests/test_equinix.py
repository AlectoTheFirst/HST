from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from hst.collectors import equinix
from hst.collectors.auth import OAuthClientCredentials
from hst.collectors.equinix import EquinixCollector, EquinixConfig, normalize_equinix, parse_pairs
from hst.core import uid

PORT_FR2 = "11111111-aaaa-4000-8000-000000000fr2"
PORT_PA3 = "22222222-bbbb-4000-8000-000000000pa3"
PORT_SV1 = "33333333-cccc-4000-8000-000000000sv1"
CONN_STRETCH = "44444444-dddd-4000-8000-00000000c100"
CONN_CLOUD = "55555555-eeee-4000-8000-00000000caws"
CONN_QINQ = "66666666-ffff-4000-8000-00000000qinq"

DEV_FR2_PORT = "dev:fdo00000fr2/port/eth1-49"
DEV_PA3_PORT = "dev:fdo00000pa3/port/eth1-49"

IBX_SITES = {"FR2": "fr2", "PA3": "pa3"}
PORT_BINDINGS = {PORT_FR2: DEV_FR2_PORT, PORT_PA3: DEV_PA3_PORT}


def _port(uuid: str, name: str, ibx: str, metro: str) -> dict[str, Any]:
    return {
        "uuid": uuid,
        "name": name,
        "state": "ACTIVE",
        "bandwidth": 10000,
        "physicalPortsSpeed": 10000,
        "encapsulation": {"type": "DOT1Q"},
        "location": {"ibx": ibx, "metroCode": metro},
    }


def _end(port_uuid: str, tag: int, protocol: str = "DOT1Q") -> dict[str, Any]:
    return {
        "accessPoint": {
            "type": "COLO",
            "port": {"uuid": port_uuid},
            "linkProtocol": {"type": protocol, "vlanTag": tag},
        }
    }


CONNECTION_STRETCH = {
    "uuid": CONN_STRETCH,
    "name": "fr2-to-pa3-users",
    "type": "EVPL_VC",
    "state": "ACTIVE",
    "bandwidth": 1000,
    "aSide": _end(PORT_FR2, 100),
    "zSide": _end(PORT_PA3, 100),
}

# a cloud on-ramp: the far end is a service profile
CONNECTION_CLOUD = {
    "uuid": CONN_CLOUD,
    "name": "fr2-to-aws",
    "type": "EVPL_VC",
    "state": "ACTIVE",
    "bandwidth": 500,
    "aSide": _end(PORT_FR2, 200),
    "zSide": {
        "accessPoint": {
            "type": "SP",
            "profile": {"uuid": "aws-profile-uuid", "name": "AWS Direct Connect"},
        }
    },
}

CONNECTION_QINQ = {
    "uuid": CONN_QINQ,
    "name": "fr2-to-pa3-qinq",
    "type": "EVPL_VC",
    "state": "ACTIVE",
    "bandwidth": 1000,
    "aSide": {
        "accessPoint": {
            "type": "COLO",
            "port": {"uuid": PORT_FR2},
            "linkProtocol": {"type": "QINQ", "vlanSTag": 300, "vlanCTag": 10},
        }
    },
    "zSide": _end(PORT_PA3, 300),
}

RAW = {
    "api_profile": equinix.API_PROFILE,
    "fetched_at_ms": 1,
    "port_pages": [
        {"data": [_port(PORT_FR2, "fr2-10g", "FR2", "FR"), _port(PORT_PA3, "pa3-10g", "PA3", "PA")]}
    ],
    "connection_pages": [{"data": [CONNECTION_STRETCH]}],
}


def _norm(raw: dict[str, Any] = RAW, **kw: Any):
    return normalize_equinix(
        raw,
        scope="equinix:test",
        ibx_sites=kw.get("ibx_sites", IBX_SITES),
        port_bindings=kw.get("bindings", PORT_BINDINGS),
    )


def _rels(batch) -> set[tuple[str, str, str]]:
    return {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}


# --- normalization ------------------------------------------------------------------------


def test_two_ports_and_one_stretched_connection():
    batch = _norm()
    nodes = {(n.label, n.uid): n for n in batch.nodes}
    ports = [n for n in batch.nodes if n.label == "FabricPort"]
    circuits = [n for n in batch.nodes if n.label == "VirtualCircuit"]
    assert len(ports) == 2 and len(circuits) == 1

    fr2 = nodes[("FabricPort", uid.equinix("port", PORT_FR2))]
    assert fr2.props["name"] == "fr2-10g"
    assert fr2.props["ibx"] == "FR2"
    assert fr2.props["metro"] == "FR"
    assert fr2.props["speed_mbps"] == 10000
    assert fr2.props["encapsulation"] == "dot1q"
    assert fr2.props["bound_port_uid"] == DEV_FR2_PORT

    vc = circuits[0]
    assert vc.uid == uid.equinix("connection", CONN_STRETCH)
    assert vc.props["bandwidth_mbps"] == 1000
    assert vc.props["state"] == "ACTIVE"
    assert vc.props["type"] == "EVPL_VC"
    assert "provider" not in vc.props

    rels = _rels(batch)
    assert ("LOCATED_IN", fr2.uid, uid.site("fr2")) in rels
    assert ("LOCATED_IN", uid.equinix("port", PORT_PA3), uid.site("pa3")) in rels
    assert sum(1 for r in rels if r[0] == "LOCATED_IN") == 2
    assert ("REALIZED_BY", fr2.uid, DEV_FR2_PORT) in rels
    assert ("REALIZED_BY", uid.equinix("port", PORT_PA3), DEV_PA3_PORT) in rels
    assert sum(1 for r in rels if r[0] == "REALIZED_BY") == 2
    assert ("A_END", vc.uid, fr2.uid) in rels
    assert ("Z_END", vc.uid, uid.equinix("port", PORT_PA3)) in rels
    assert ("PROVIDED_BY", vc.uid, uid.provider("equinix")) in rels
    assert ("Provider", uid.provider("equinix")) in nodes


def test_end_edges_carry_the_link_protocol_and_tag_per_side():
    batch = _norm()
    ends = {r.rel_type: r.props for r in batch.rels if r.rel_type in ("A_END", "Z_END")}
    assert ends["A_END"] == {"link_protocol": "dot1q", "vlan_tag": 100}
    assert ends["Z_END"] == {"link_protocol": "dot1q", "vlan_tag": 100}


def test_a_qinq_end_carries_the_s_tag_as_the_tag_and_the_c_tag_inside():
    raw = {**RAW, "connection_pages": [{"data": [CONNECTION_QINQ]}]}
    batch = _norm(raw)
    a_end = next(r.props for r in batch.rels if r.rel_type == "A_END")
    assert a_end == {"link_protocol": "qinq", "vlan_tag": 300, "inner_vlan_tag": 10}


def test_the_site_is_emitted_as_a_colo_site_the_port_sits_in():
    batch = _norm()
    site = next(n for n in batch.nodes if n.label == "Site" and n.uid == uid.site("fr2"))
    assert site.props == {"code": "fr2", "kind": "colo"}


def test_an_unknown_ibx_leaves_the_port_unplaced():
    raw = {**RAW, "port_pages": [{"data": [_port(PORT_SV1, "sv1-10g", "SV1", "SV")]}], "connection_pages": []}
    batch = _norm(raw, bindings={})
    port = next(n for n in batch.nodes if n.label == "FabricPort")
    assert port.props["ibx"] == "SV1"
    assert not [r for r in batch.rels if r.rel_type == "LOCATED_IN"]
    assert not [n for n in batch.nodes if n.label == "Site"]


def test_the_ibx_map_is_case_insensitive():
    batch = _norm(ibx_sites={"fr2": "fr2", "pa3": "pa3"})
    assert sum(1 for r in batch.rels if r.rel_type == "LOCATED_IN") == 2


def test_a_port_without_a_binding_gets_no_realized_by_and_no_bound_uid():
    batch = _norm(bindings={PORT_FR2: DEV_FR2_PORT})
    pa3 = next(n for n in batch.nodes if n.label == "FabricPort" and n.uid == uid.equinix("port", PORT_PA3))
    assert "bound_port_uid" not in pa3.props
    assert [r for r in batch.rels if r.rel_type == "REALIZED_BY"] == [
        r for r in batch.rels if r.rel_type == "REALIZED_BY" and r.start_uid == uid.equinix("port", PORT_FR2)
    ]


def test_a_service_profile_far_end_is_a_one_ended_circuit_with_a_provider():
    raw = {**RAW, "connection_pages": [{"data": [CONNECTION_CLOUD]}]}
    batch = _norm(raw)
    vc = next(n for n in batch.nodes if n.label == "VirtualCircuit")
    assert vc.props["provider"] == "AWS Direct Connect"
    assert vc.props["provider_profile_uuid"] == "aws-profile-uuid"
    assert vc.props["z_side_kind"] == "sp"
    rels = _rels(batch)
    assert ("A_END", vc.uid, uid.equinix("port", PORT_FR2)) in rels
    assert not [r for r in rels if r[0] == "Z_END"]
    # no cloud object is created for the far end
    assert {n.label for n in batch.nodes} == {"Provider", "FabricPort", "Site", "VirtualCircuit"}


def test_a_connection_end_on_a_port_outside_the_account_stays_unbound():
    raw = {**RAW, "connection_pages": [{"data": [{**CONNECTION_STRETCH, "zSide": _end("not-ours", 100)}]}]}
    batch = _norm(raw)
    assert [r.rel_type for r in batch.rels if r.rel_type in ("A_END", "Z_END")] == ["A_END"]


def test_pages_are_concatenated_and_items_without_a_uuid_are_skipped():
    raw = {
        **RAW,
        "port_pages": [
            {"data": [_port(PORT_FR2, "a", "FR2", "FR")]},
            {"data": [_port(PORT_PA3, "b", "PA3", "PA")]},
        ],
        "connection_pages": [{"data": [CONNECTION_STRETCH]}, {"data": [{"name": "no uuid"}]}],
    }
    batch = _norm(raw)
    assert len([n for n in batch.nodes if n.label == "FabricPort"]) == 2
    assert len([n for n in batch.nodes if n.label == "VirtualCircuit"]) == 1


def test_batch_is_coherent_no_dangling_endpoints_except_the_declared_device_ports():
    """Every relationship endpoint is a node of the batch, except REALIZED_BY's
    device Port: that node belongs to the device's own source, and the loader
    drops the edge when it is absent."""
    batch = _norm()
    uids = {n.uid for n in batch.nodes}
    for r in batch.rels:
        assert r.start_uid in uids, r
        if r.rel_type != "REALIZED_BY":
            assert r.end_uid in uids, r


def test_batch_source_and_scope():
    batch = _norm()
    assert batch.source == "equinix" and batch.scope == "equinix:test"


# --- config ------------------------------------------------------------------------------


def _config(**kw: Any) -> EquinixConfig:
    return EquinixConfig(
        auth=OAuthClientCredentials(client_id="cid", client_secret="cs"),
        ibx_sites=kw.pop("ibx_sites", "FR2, fr2\n# a comment\n\nPA3, pa3\n"),
        port_bindings=kw.pop("port_bindings", f"{PORT_FR2}, {DEV_FR2_PORT}\n{PORT_PA3}, {DEV_PA3_PORT}"),
        **kw,
    )


def test_config_parses_the_two_multiline_maps():
    c = _config()
    assert c.ibx_site_map == {"FR2": "fr2", "PA3": "pa3"}
    assert c.port_binding_map == {PORT_FR2: DEV_FR2_PORT, PORT_PA3: DEV_PA3_PORT}
    assert c.api_url == "https://api.equinix.com"


def test_config_refuses_a_malformed_line_and_a_repeated_key():
    with pytest.raises(ValidationError, match="line 1 must be"):
        _config(ibx_sites="FR2 fr2")
    with pytest.raises(ValidationError, match="repeats"):
        _config(port_bindings=f"{PORT_FR2}, a\n{PORT_FR2}, b")
    with pytest.raises(ValueError, match="line 2"):
        parse_pairs("a, b\n, c", field="x")


def test_scope_is_the_source_name():
    c = _config()
    c.source_name = "eqx-prod"
    assert EquinixCollector(c, None).scope == "equinix:eqx-prod"
    assert EquinixCollector(_config(), None).scope == "equinix:fabric"


# --- probe / fetch over a mock transport ---------------------------------------------------


def _transport(port_items: list[dict[str, Any]], connection_items: list[dict[str, Any]]):
    calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else None
        calls.append(
            {"method": request.method, "path": path, "params": dict(request.url.params), "body": body}
        )
        if request.method == "POST" and path == equinix.TOKEN_PATH:
            assert body == {"grant_type": "client_credentials", "client_id": "cid", "client_secret": "cs"}
            return httpx.Response(
                200, json={"access_token": "tok", "token_type": "Bearer", "token_timeout": "3599"}
            )
        assert request.headers["Authorization"] == "Bearer tok"
        if request.method == "GET" and path == equinix.PORTS_PATH:
            offset, limit = int(request.url.params["offset"]), int(request.url.params["limit"])
            page = port_items[offset : offset + limit]
            return httpx.Response(
                200,
                json={
                    "data": page,
                    "pagination": {"offset": offset, "limit": limit, "total": len(port_items)},
                },
            )
        if request.method == "POST" and path == equinix.CONNECTIONS_SEARCH_PATH:
            pagination = body["pagination"]
            offset, limit = pagination["offset"], pagination["limit"]
            page = connection_items[offset : offset + limit]
            return httpx.Response(
                200,
                json={
                    "data": page,
                    "pagination": {"offset": offset, "limit": limit, "total": len(connection_items)},
                },
            )
        raise AssertionError(f"unexpected {request.method} {path}")

    return httpx.MockTransport(handler), calls


def test_probe_takes_a_token_and_reads_one_port_page(monkeypatch):
    transport, calls = _transport([_port(PORT_FR2, "a", "FR2", "FR"), _port(PORT_PA3, "b", "PA3", "PA")], [])
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    assert EquinixCollector(_config(), None).probe() == "token ok: 2 Fabric port(s)"
    assert [c["path"] for c in calls] == [equinix.TOKEN_PATH, equinix.PORTS_PATH]
    assert calls[1]["params"] == {"offset": "0", "limit": "1"}


def test_fetch_reads_every_page_and_filters_the_search_to_the_accounts_ports(monkeypatch):
    ports = [
        _port(PORT_FR2, "a", "FR2", "FR"),
        _port(PORT_PA3, "b", "PA3", "PA"),
        _port(PORT_SV1, "c", "SV1", "SV"),
    ]
    connections = [CONNECTION_STRETCH, CONNECTION_CLOUD, CONNECTION_QINQ]
    transport, calls = _transport(ports, connections)
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)

    raw = EquinixCollector(_config(page_size=2), None).fetch()

    assert set(raw) == {"api_profile", "fetched_at_ms", "port_pages", "connection_pages"}
    assert len(raw["port_pages"]) == 2 and len(raw["connection_pages"]) == 2
    assert [p["uuid"] for page in raw["port_pages"] for p in page["data"]] == [PORT_FR2, PORT_PA3, PORT_SV1]
    assert [c["uuid"] for page in raw["connection_pages"] for c in page["data"]] == [
        CONN_STRETCH,
        CONN_CLOUD,
        CONN_QINQ,
    ]
    searches = [c for c in calls if c["path"] == equinix.CONNECTIONS_SEARCH_PATH]
    assert [s["body"]["pagination"] for s in searches] == [
        {"offset": 0, "limit": 2},
        {"offset": 2, "limit": 2},
    ]
    clauses = searches[0]["body"]["filter"]["or"]
    assert [c["property"] for c in clauses] == [equinix.A_SIDE_PORT_PROPERTY, equinix.Z_SIDE_PORT_PROPERTY]
    assert all(c["operator"] == "IN" and c["values"] == [PORT_FR2, PORT_PA3, PORT_SV1] for c in clauses)
    # every page came back unchanged: the raw store keeps the wire shape
    assert raw["port_pages"][0]["pagination"]["total"] == 3


def test_fetch_with_no_ports_searches_nothing(monkeypatch):
    transport, calls = _transport([], [CONNECTION_STRETCH])
    monkeypatch.setattr(equinix, "_transport", lambda config: transport)
    raw = EquinixCollector(_config(), None).fetch()
    assert raw["connection_pages"] == []
    assert [c["path"] for c in calls] == [equinix.TOKEN_PATH, equinix.PORTS_PATH]


def test_a_token_response_without_a_token_fails_before_any_read(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    monkeypatch.setattr(equinix, "_transport", lambda config: httpx.MockTransport(handler))
    with pytest.raises(ValueError, match="access_token"):
        EquinixCollector(_config(), None).probe()


def test_normalize_on_the_collector_uses_the_configured_maps(monkeypatch):
    batch = EquinixCollector(_config(), None).normalize(RAW)
    rels = _rels(batch)
    assert ("REALIZED_BY", uid.equinix("port", PORT_FR2), DEV_FR2_PORT) in rels
    assert ("LOCATED_IN", uid.equinix("port", PORT_PA3), uid.site("pa3")) in rels


def test_fetched_at_is_volatile_so_an_unchanged_account_does_not_read_as_changed():
    assert "fetched_at_ms" in EquinixCollector.VOLATILE_RAW_KEYS


# --- paging until the stated total and binding warnings ----------------------------------------


def _paged_ports(pages_by_offset, total):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == equinix.TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "tok"})
        if path == equinix.PORTS_PATH:
            offset = int(request.url.params["offset"])
            body = {"data": pages_by_offset.get(offset, [])}
            if total is not None:
                body["pagination"] = {"offset": offset, "total": total}
            return httpx.Response(200, json=body)
        if path == equinix.CONNECTIONS_SEARCH_PATH:
            return httpx.Response(200, json={"data": [], "pagination": {"offset": 0, "total": 0}})
        raise AssertionError(path)

    return httpx.MockTransport(handler)


def _five_ports():
    return [_port(f"00000000-0000-4000-8000-00000000000{i}", f"p{i}", "FR2", "FR") for i in range(5)]


def test_a_short_page_is_not_the_end_when_the_total_says_more(monkeypatch):
    ports = _five_ports()
    pages = {0: ports[0:2], 2: ports[2:4], 4: ports[4:5]}
    monkeypatch.setattr(equinix, "_transport", lambda config: _paged_ports(pages, 5))
    raw = EquinixCollector(_config(page_size=5), None).fetch()
    assert len(raw["port_pages"]) == 3
    assert len([p for page in raw["port_pages"] for p in page["data"]]) == 5


def test_an_empty_page_before_the_stated_total_fails_the_read(monkeypatch):
    ports = _five_ports()
    monkeypatch.setattr(equinix, "_transport", lambda config: _paged_ports({0: ports[0:2]}, 4))
    with pytest.raises(ValueError, match="2 of 4"):
        EquinixCollector(_config(page_size=5), None).fetch()


def test_without_a_total_a_short_page_ends_the_read(monkeypatch):
    ports = _five_ports()
    monkeypatch.setattr(
        equinix, "_transport", lambda config: _paged_ports({0: ports[0:2], 2: ports[2:4]}, None)
    )
    raw = EquinixCollector(_config(page_size=5), None).fetch()
    assert len(raw["port_pages"]) == 1


def test_a_port_binding_for_a_port_the_account_lacks_is_a_warning():
    missing = "99999999-0000-4000-8000-000000000999"
    batch = _norm(bindings={**PORT_BINDINGS, missing: "dev:x/port/eth1"})
    assert (
        f"port_bindings names Fabric port {missing}, which is not in the account's port list"
        in batch.warnings
    )


def test_a_port_binding_uuid_matches_in_any_case():
    batch = _norm(bindings={PORT_FR2.upper(): DEV_FR2_PORT})
    fabric = {n.props["port_uuid"]: n.props for n in batch.nodes if n.label == "FabricPort"}
    assert fabric[PORT_FR2]["bound_port_uid"] == DEV_FR2_PORT
    assert not batch.warnings
