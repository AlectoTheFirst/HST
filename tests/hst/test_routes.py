"""The HST map routes against a side store written by hand."""

from pathlib import Path
from typing import Any

import httpx
import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.fakes import FakeStore

from hst.app.main import create_app
from hst.app.routes import hst as hst_routes
from hst.app.security import hash_password
from hst.core import Settings
from hst.map import layout, markers, store
from hst.map.events import RUN_PUBLISHED, RUN_TIERS_READY, Event
from hst.map.tiers import delta
from hst.map.tiers.schemas import SCHEMA_VERSIONS, SCHEMAS

BLOCK = "block:fra:campus"


def _t0() -> list[dict[str, Any]]:
    return [
        {"uid": "site:fra", "kind": "site", "label": "fra", "device_count": 2},
        {"uid": "plate:fra", "kind": "plate", "parent_uid": "site:fra", "device_count": 2},
        {"uid": BLOCK, "kind": "block", "parent_uid": "plate:fra", "block_kind": "campus", "device_count": 2},
    ]


def _t1(key: int, ports: int) -> dict[str, dict[str, Any]]:
    return {
        uid: {
            "uid": uid,
            "block_uid": BLOCK,
            "label": uid,
            "status": "observed",
            "n_ports": ports,
            "snapshot_ts": key,
        }
        for uid in ("dev:a", "dev:b")
    }


def _ports(key: int) -> dict[str, dict[str, Any]]:
    names = ["eth0"] if key == 100 else ["eth0", "eth1"]
    return {
        f"dev:a/port/{n}": {"uid": f"dev:a/port/{n}", "device_uid": "dev:a", "tile": BLOCK, "name": n}
        for n in names
    }


def _write(sidestore: Path, name: str, key: int, rows: list[dict[str, Any]]) -> None:
    path = store.table_path(sidestore, name, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows, schema=SCHEMAS[name]), path)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    sidestore, markers_dir = settings.sidestore_dir, settings.manifests_dir
    estate = layout.Estate(
        devices=[
            {"uid": u, "name": u, "role": "switch", "tier": "access", "site": "fra"}
            for u in ("dev:a", "dev:b")
        ]
    )
    first = layout.place(estate, {}, 100)
    layout.write(store.table_path(sidestore, layout.TABLE, 100), first.rows)
    parent = None
    for key in (100, 200):
        _write(sidestore, "render_t0", key, _t0())
        _write(sidestore, "render_t1", key, list(_t1(key, 1 if key == 100 else 2).values()))
        _write(sidestore, "render_t2_ports", key, list(_ports(key).values()))
        if parent is not None:
            rows = [
                {**r, "snapshot_ts": key, "parent_ts": parent}
                for r in delta.changes("render_t1", _t1(parent, 1), _t1(key, 2))
            ]
            _write(sidestore, "render_t1_delta", key, rows)
            t2 = delta.changes("render_t2_ports", _ports(parent), _ports(key), lambda r: r.get("tile"))
            _write(
                sidestore,
                "render_t2_delta",
                key,
                [{**r, "snapshot_ts": key, "parent_ts": parent} for r in t2],
            )
        markers.write(
            markers_dir,
            {
                "key": key,
                "kind": "full",
                "parent": parent,
                "published_ts": key,
                "state": "warm",
                "tiers_ready": True,
            },
        )
        parent = key
    markers.write(
        markers_dir,
        {
            "key": 300,
            "kind": "device",
            "parent": 200,
            "published_ts": 300,
            "state": "warm",
            "tiers_ready": False,
        },
    )
    return tmp_path


@pytest.fixture
async def client(data_dir: Path) -> Any:
    from hst.app.crypto import generate_key

    fake = FakeStore()
    for name, role in (("vera", "viewer"), ("otto", "operator")):
        await fake.create_user(name, hash_password(PASSWORD), role)
    settings = Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=data_dir)
    app = create_app(settings=settings, store=fake)
    transport = httpx.ASGITransport(app=app)
    headers = {"X-HST-CSRF": "1"}
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers=headers) as c:
        c.app = app  # type: ignore[attr-defined]
        yield c


async def test_every_route_needs_a_session(client: Any) -> None:
    for path in ("/api/hst/timeline", "/api/hst/tier?name=render_t1", "/api/hst/layout", "/api/hst/events"):
        assert (await client.get(path)).status_code == 401, path


async def test_the_timeline_lists_the_runs_with_the_current_one(client: Any) -> None:
    await login(client, "vera")
    body = (await client.get("/api/hst/timeline")).json()
    assert body["current"] == 300
    assert [r["key"] for r in body["runs"]] == [100, 200, 300]
    assert [r["tiers_ready"] for r in body["runs"]] == [True, True, False]


async def test_a_tier_is_columnar_and_gzipped_when_the_client_accepts_it(client: Any) -> None:
    await login(client, "vera")
    r = await client.get("/api/hst/tier", params={"name": "render_t1", "snapshot": "200"})
    body = r.json()
    assert (body["name"], body["snapshot"], body["tile"], body["schema_version"]) == (
        "render_t1",
        200,
        None,
        SCHEMA_VERSIONS["render_t1"],
    )
    assert body["columns"] == SCHEMAS["render_t1"].names
    rows = [dict(zip(body["columns"], row, strict=True)) for row in body["rows"]]
    assert {(row["uid"], row["n_ports"]) for row in rows} == {("dev:a", 2), ("dev:b", 2)}
    raw = await client.get(
        "/api/hst/tier", params={"name": "render_t1", "snapshot": "200"}, headers={"Accept-Encoding": "gzip"}
    )
    assert raw.headers["content-encoding"] == "gzip"
    assert raw.json() == body


async def test_a_tiled_tier_needs_a_known_tile(client: Any) -> None:
    await login(client, "vera")
    assert (
        await client.get("/api/hst/tier", params={"name": "render_t2_ports", "snapshot": "200"})
    ).status_code == 400
    unknown = await client.get(
        "/api/hst/tier", params={"name": "render_t2_ports", "snapshot": "200", "tile": "block:x"}
    )
    assert unknown.status_code == 404 and "error" in unknown.json()
    body = (
        await client.get(
            "/api/hst/tier", params={"name": "render_t2_ports", "snapshot": "200", "tile": BLOCK}
        )
    ).json()
    assert len(body["rows"]) == 2 and body["tile"] == BLOCK


async def test_unknown_runs_and_unready_tiers_answer_in_the_error_envelope(client: Any) -> None:
    await login(client, "vera")
    for snapshot in ("999", "sim:200:1", "nope"):
        r = await client.get("/api/hst/tier", params={"name": "render_t1", "snapshot": snapshot})
        assert r.status_code == 404 and "error" in r.json(), snapshot
    r = await client.get("/api/hst/tier", params={"name": "render_t1", "snapshot": "300"})
    assert r.status_code == 409 and "not ready" in r.json()["error"]
    assert (await client.get("/api/hst/tier", params={"name": "render_t9"})).status_code == 404


async def test_the_delta_turns_the_parent_tier_into_the_tier_at_t(client: Any) -> None:
    await login(client, "vera")
    body = (await client.get("/api/hst/delta", params={"name": "render_t1", "snapshot": "200"})).json()
    assert (body["snapshot"], body["parent"]) == (200, 100)
    assert {(r["uid"], r["op"], r["after"]["n_ports"]) for r in body["rows"]} == {
        ("dev:a", "set", 2),
        ("dev:b", "set", 2),
    }
    ports = (
        await client.get(
            "/api/hst/delta", params={"name": "render_t2_ports", "snapshot": "200", "tile": BLOCK}
        )
    ).json()
    assert [(r["uid"], r["op"]) for r in ports["rows"]] == [("dev:a/port/eth1", "add")]


async def test_the_layout_and_the_layout_delta_at_a_run(client: Any) -> None:
    await login(client, "vera")
    at = (await client.get("/api/hst/layout", params={"snapshot": "200"})).json()
    uids = {row[at["columns"].index("uid")] for row in at["rows"]}
    assert {"dev:a", "dev:b", "site:fra", "plate:fra"} <= uids
    # Every device has a site, so the layout has no Unassigned plate.
    assert layout.UNASSIGNED_PLATE not in uids

    assert len((await client.get("/api/hst/layout-delta", params={"snapshot": "100"})).json()["rows"]) == len(
        at["rows"]
    )
    assert (await client.get("/api/hst/layout-delta", params={"snapshot": "200"})).json()["rows"] == []


async def test_the_device_route_answers_404_for_an_unknown_device(client: Any) -> None:
    await login(client, "vera")
    r = await client.get("/api/hst/device", params={"uid": "dev:zzz", "snapshot": "200"})
    assert r.status_code == 404


async def test_a_cold_run_answers_tier3_from_the_graph_delta(client: Any, data_dir: Path) -> None:
    settings = Settings(_env_file=None, hst_data_dir=data_dir)
    marker = markers.read(settings.manifests_dir, 200)
    markers.write(settings.manifests_dir, {**marker, "state": "cold"})
    row = {
        "snapshot_ts": 200,
        "parent_ts": 100,
        "kind": "node",
        "change": "added",
        "uid": "dev:a/port/eth1",
        "label": "Port",
        "device_uid": "dev:a",
    }
    _write(settings.sidestore_dir, "graph_delta", 200, [row])
    await login(client, "vera")
    body = (await client.get("/api/hst/device", params={"uid": "dev:a", "snapshot": "200"})).json()
    assert body["state"] == "cold"
    assert [r["uid"] for r in body["rows"]] == ["dev:a/port/eth1"]


async def test_the_segment_route_lists_the_clients_of_a_segment_from_the_graph(
    client: Any, data_dir: Path, monkeypatch: Any
) -> None:
    from hst.map import tier3

    settings = Settings(_env_file=None, hst_data_dir=data_dir)
    segment = {
        "uid": "dev:a/segment/bd:vlan:fab0:10",
        "device_uid": "dev:a",
        "tile": BLOCK,
        "bridge_domain_uid": "bd:vlan:fab0:10",
        "vid": 10,
        "name": "users",
        "prefix": "10.1.10.0/24",
        "client_count": 2,
        "change": "none",
    }
    _write(settings.sidestore_dir, "render_t2_segments", 200, [segment])
    asked: list[tuple[str, str | None, int]] = []

    def fake(settings_: Any, device: str, bd: str | None, cts: int) -> list[dict[str, Any]]:
        asked.append((device, bd, cts))
        return [
            {
                "uid": "ep:1",
                "name": "pc-1",
                "ip": ["10.1.10.5"],
                "mac": "aa",
                "port": "eth3",
                "last_seen_ts": 1,
            }
        ]

    monkeypatch.setattr(tier3, "segment", fake)
    await login(client, "vera")
    body = (await client.get("/api/hst/segment", params={"uid": segment["uid"], "snapshot": "200"})).json()
    assert body["state"] == "warm" and body["prefix"] == "10.1.10.0/24" and body["vid"] == 10
    assert [c["name"] for c in body["clients"]] == ["pc-1"]
    assert asked == [("dev:a", "bd:vlan:fab0:10", 200)]
    r = await client.get("/api/hst/segment", params={"uid": "dev:a/segment/none", "snapshot": "200"})
    assert r.status_code == 404
    r = await client.get("/api/hst/segment", params={"uid": "dev:zzz/segment/none", "snapshot": "200"})
    assert r.status_code == 404


async def test_the_event_stream_resumes_after_the_last_event_id_and_then_goes_live(client: Any) -> None:
    # httpx's ASGI transport buffers a whole response, so the stream's generator is read directly
    class Connected:
        async def is_disconnected(self) -> bool:
            return False

    bus = client.app.state.hst_bus
    stream = hst_routes.get_events(Connected(), bus, "200:0")  # type: ignore[arg-type]
    seen = []
    async for event in stream:
        seen.append((event.id, event.event))
        if len(seen) == 2:
            bus.publish(Event(RUN_PUBLISHED, 400, 0, {"kind": "full"}))
        if len(seen) == 3:
            break
    await stream.aclose()
    assert seen == [("200:1", RUN_TIERS_READY), ("300:0", RUN_PUBLISHED), ("400:0", RUN_PUBLISHED)]


async def test_the_layout_serves_ports_and_cables_per_block(client: Any) -> None:
    await login(client, "vera")
    at = (await client.get("/api/hst/layout", params={"snapshot": "200"})).json()
    kinds = {row[at["columns"].index("kind")] for row in at["rows"]}
    assert "port" not in kinds and "cable" not in kinds
    block = next(row[0] for row in at["rows"] if row[at["columns"].index("kind")] == "block")
    tiled = await client.get("/api/hst/layout", params={"snapshot": "200", "tile": block})
    assert tiled.status_code == 200 and tiled.json()["tile"] == block
    for path in ("/api/hst/layout", "/api/hst/layout-delta"):
        r = await client.get(path, params={"snapshot": "200", "tile": "block:none"})
        assert r.status_code == 404 and "error" in r.json()


@pytest.fixture
def interfaces(monkeypatch: Any) -> list[tuple[str, int]]:
    from hst.map import tier3

    calls: list[tuple[str, int]] = []
    facts = {"uid": "dev:a/port/eth0", "label": "Port", "device_uid": "dev:a", "name": "eth0"}

    def interface_facts(settings: Any, uid: str, cts: int) -> dict[str, Any] | None:
        calls.append((uid, cts))
        return {**facts, "uid": uid} if uid.startswith("dev:a/") else None

    monkeypatch.setattr(tier3, "interface_facts", interface_facts)

    def interface_text(settings: Any, key: str, device: str, run: int, name: str) -> dict[str, Any]:
        return {"command": "c", "fetched_ts": run, "text": f"interface {name}"}

    monkeypatch.setattr(tier3, "interface_text", interface_text)
    return calls


async def test_the_interface_facts_need_graph_read_and_the_configuration_interfaces_read(
    client: Any, interfaces: list[tuple[str, int]]
) -> None:
    await login(client, "vera")
    facts = await client.get("/api/hst/interface", params={"uid": "dev:a/port/eth0", "snapshot": "200"})
    assert facts.status_code == 200 and facts.json()["name"] == "eth0" and facts.json()["snapshot"] == 200
    text = await client.get("/api/hst/interface-text", params={"uid": "dev:a/port/eth0", "snapshot": "200"})
    assert text.status_code == 403
    await login(client, "otto")
    text = await client.get("/api/hst/interface-text", params={"uid": "dev:a/port/eth0", "snapshot": "200"})
    expected = {"uid": "dev:a/port/eth0", "command": "c", "fetched_ts": 200, "text": "interface eth0"}
    assert text.json() == expected


async def test_the_text_of_a_port_is_read_by_the_port_name_not_a_realized_interface(
    client: Any, interfaces: list[tuple[str, int]], monkeypatch: Any
) -> None:
    from hst.map import tier3

    facts = {
        "uid": "dev:a/port/eth0",
        "label": "Port",
        "device_uid": "dev:a",
        "name": "eth0",
        "interface": {"name": "eth0.105"},
        "interfaces": ["eth0", "eth0.10", "eth0.105"],
    }
    monkeypatch.setattr(tier3, "interface_facts", lambda settings, uid, cts: facts)
    await login(client, "otto")
    text = await client.get("/api/hst/interface-text", params={"uid": "dev:a/port/eth0", "snapshot": "200"})
    assert text.status_code == 200 and text.json()["text"] == "interface eth0"


async def test_an_unknown_interface_is_404_and_a_cold_run_409(
    client: Any, interfaces: list[tuple[str, int]], data_dir: Path
) -> None:
    await login(client, "otto")
    assert (await client.get("/api/hst/interface", params={"uid": "dev:z/port/x"})).status_code == 404
    markers_dir = Settings(_env_file=None, hst_data_dir=data_dir).manifests_dir
    markers.write(markers_dir, {**markers.read(markers_dir, 100), "state": "cold"})
    for path in ("/api/hst/interface", "/api/hst/interface-text"):
        r = await client.get(path, params={"uid": "dev:a/port/eth0", "snapshot": "100"})
        assert r.status_code == 409 and "cold" in r.json()["error"], path


@pytest.fixture
def cabled(data_dir: Path) -> Path:
    sidestore = Settings(_env_file=None, hst_data_dir=data_dir).sidestore_dir
    ports = [
        {"uid": f"{d}/port/{n}", "device_uid": d, "tile": BLOCK, "name": n, "oper_status": s}
        for d, n, s in (
            ("dev:a", "Ethernet1/2", "up"),
            ("dev:a", "Ethernet1/10", "down"),
            ("dev:a", "Ethernet2/1", "up"),
            ("dev:b", "eth0", "up"),
            ("dev:b", "eth1", None),
        )
    ]
    cables = [
        {
            "cable_id": "c1",
            "tile_a": BLOCK,
            "tile_b": BLOCK,
            "a_port": "dev:a/port/Ethernet1/2",
            "b_port": "dev:b/port/eth0",
            "a_dev": "dev:a",
            "b_dev": "dev:b",
        },
        {
            "cable_id": "c2",
            "tile_a": BLOCK,
            "tile_b": "block:other",
            "a_port": "dev:b/port/eth1",
            "b_port": "dev:z/port/eth0",
            "a_dev": "dev:b",
            "b_dev": "dev:z",
        },
    ]
    _write(sidestore, "render_t2_ports", 200, ports)
    _write(sidestore, "render_t2_cables", 200, cables)
    return data_dir


def _records(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(zip(body["columns"], row, strict=True)) for row in body["rows"]]


async def test_the_port_groups_are_derived_from_the_ports_and_cables_of_the_tile(
    client: Any, cabled: Path
) -> None:
    await login(client, "vera")
    params = {"name": "render_t2_port_groups", "snapshot": "200", "tile": BLOCK}
    body = (await client.get("/api/hst/tier", params=params)).json()
    assert (body["name"], body["snapshot"], body["tile"], body["schema_version"]) == (
        "render_t2_port_groups",
        200,
        BLOCK,
        1,
    )
    assert body["columns"] == [
        "device_uid",
        "tile",
        "group_key",
        "first_name",
        "last_name",
        "port_count",
        "up",
        "down",
        "admin_down",
        "connected",
    ]
    assert [tuple(r.values()) for r in _records(body)] == [
        ("dev:a", BLOCK, "Ethernet1/", "Ethernet1/2", "Ethernet1/10", 2, 1, 1, 0, 1),
        ("dev:a", BLOCK, "Ethernet2/", "Ethernet2/1", "Ethernet2/1", 1, 1, 0, 0, 0),
        ("dev:b", BLOCK, "eth", "eth0", "eth1", 2, 1, 0, 0, 2),
    ]
    raw = await client.get("/api/hst/tier", params=params, headers={"Accept-Encoding": "gzip"})
    assert raw.headers["content-encoding"] == "gzip" and raw.json() == body


async def test_the_port_groups_need_a_known_tile_and_have_no_delta(client: Any, cabled: Path) -> None:
    await login(client, "vera")
    name = "render_t2_port_groups"
    assert (await client.get("/api/hst/tier", params={"name": name, "snapshot": "200"})).status_code == 400
    unknown = await client.get("/api/hst/tier", params={"name": name, "snapshot": "200", "tile": "block:x"})
    assert unknown.status_code == 404 and "error" in unknown.json()
    for params in (
        {"name": name, "snapshot": "200", "tile": BLOCK},
        {"name": "render_t9", "snapshot": "200"},
    ):
        r = await client.get("/api/hst/delta", params=params)
        assert r.status_code == 404 and r.json()["error"] == f"unknown tier {params['name']}"


async def test_the_ports_and_cables_of_one_device(client: Any, cabled: Path) -> None:
    await login(client, "vera")
    base = {"snapshot": "200", "tile": BLOCK}
    ports = (
        await client.get("/api/hst/tier", params={**base, "name": "render_t2_ports", "device": "dev:b"})
    ).json()
    assert ports["device"] == "dev:b"
    assert [r["uid"] for r in _records(ports)] == ["dev:b/port/eth0", "dev:b/port/eth1"]
    cables = await client.get("/api/hst/tier", params={**base, "name": "render_t2_cables", "device": "dev:a"})
    assert [r["cable_id"] for r in _records(cables.json())] == ["c1"]
    cables = await client.get("/api/hst/tier", params={**base, "name": "render_t2_cables", "device": "dev:b"})
    assert [r["cable_id"] for r in _records(cables.json())] == ["c1", "c2"]
    whole = (await client.get("/api/hst/tier", params={**base, "name": "render_t2_ports"})).json()
    assert "device" not in whole and len(whole["rows"]) == 5


async def test_the_device_filter_needs_a_known_device_and_a_port_or_cable_table(
    client: Any, cabled: Path
) -> None:
    await login(client, "vera")
    base = {"snapshot": "200", "tile": BLOCK}
    unknown = await client.get("/api/hst/tier", params={**base, "name": "render_t2_ports", "device": "dev:z"})
    assert unknown.status_code == 404 and unknown.json()["error"] == "unknown device dev:z"
    for name in ("render_t2_contexts", "render_t2_port_groups", "render_t1"):
        r = await client.get("/api/hst/tier", params={**base, "name": name, "device": "dev:a"})
        assert r.status_code == 400 and "error" in r.json(), name
