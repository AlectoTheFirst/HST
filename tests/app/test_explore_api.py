"""The /api/explore routes: search, node, neighbors, labels, stats and values.

Neo4j is faked at the `run_readonly` seam, the way test_data_api.py fakes the
canned-query runner, so these tests check the route logic: what reaches Cypher
as text (only registered labels, relationship types and valid property
names), what travels as a parameter, the snapshot pin, how search merges its
three strategies, and the per-snapshot statistics cache.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from tests.app.conftest import login

import hst.app.routes.explore as explore

Table = dict[str, Any]


def table(columns: list[str], rows: list[list[Any]], graph: dict[str, Any] | None = None) -> Table:
    out: Table = {"columns": columns, "data": [{"row": r} for r in rows], "truncated": False}
    if graph is not None:
        out["graph"] = graph
    return out


class FakeGraph:
    """Answers each query with the first responder whose marker is in the Cypher."""

    def __init__(self, responders: list[tuple[str, Callable[[dict[str, Any]], Table]]]) -> None:
        self.responders = responders
        self.calls: list[tuple[str, dict[str, Any], bool]] = []

    def __call__(
        self, settings: Any, cypher: str, params: dict[str, Any], trusted: bool = False, graph: bool = False
    ) -> Table:
        assert trusted, "explore runs server-owned Cypher only"
        self.calls.append((cypher, params, graph))
        for marker, respond in self.responders:
            if marker in cypher:
                return respond(params)
        return table([], [])


@pytest.fixture
def snap(monkeypatch):
    current = {"value": 1700}
    monkeypatch.setattr(explore, "_snap", lambda request: current["value"])
    explore._STATS_CACHE.clear()
    return current


def install(monkeypatch, responders) -> FakeGraph:
    fake = FakeGraph(responders)
    monkeypatch.setattr(explore, "run_readonly", fake)
    return fake


async def test_routes_need_a_login(client):
    for path in ("/api/explore/stats", "/api/explore/search?q=x", "/api/explore/node?uid=x"):
        assert (await client.get(path)).status_code == 401


async def test_names_written_into_cypher_come_from_the_registry_only(client, monkeypatch, snap):
    fake = install(monkeypatch, [])
    await login(client, "vera")
    bad = [
        "/api/explore/labels/Device%60)%20DETACH%20DELETE%20n",
        "/api/explore/search?q=x&label=NotALabel",
        "/api/explore/neighbors?uid=x&type=NOT_A_REL&direction=out",
        "/api/explore/neighbors?uid=x&type=ON&direction=sideways",
        "/api/explore/values?label=Device&property=name%60)%20RETURN%201",
        "/api/explore/values?label=Nope&property=name",
    ]
    for path in bad:
        assert (await client.get(path)).status_code == 422, path
    assert fake.calls == [], "nothing reaches Neo4j before the names are checked"


async def test_search_merges_uid_address_and_text_matches_once_each(client, monkeypatch, snap):
    def by_uid(params):
        return table(
            ["uid", "label", "name", "detail", "matched"],
            [["ip:vrf1:10.0.0.1", "IpAddress", "10.0.0.1", "", "uid"]],
        )

    def by_address(params):
        return table(
            ["uid", "label", "name", "detail", "matched"],
            [
                ["ip:vrf1:10.0.0.1", "IpAddress", "10.0.0.1", "", "address"],
                ["ip:vrf2:10.0.0.10", "IpAddress", "10.0.0.10", "", "address"],
            ],
        )

    def by_text(params):
        return table(
            ["uid", "label", "name", "detail", "matched"],
            [["dev:1", "Device", "edge-10.0.0.1", "vyos", "text"]],
        )

    fake = install(
        monkeypatch,
        [("{uid: $q}", by_uid), ("STARTS WITH $q", by_address), ("queryNodes", by_text)],
    )
    await login(client, "vera")
    r = await client.get("/api/explore/search", params={"q": " 10.0.0.1 "})
    assert r.status_code == 200, r.text
    body = r.json()
    assert [(i["uid"], i["matched"]) for i in body["items"]] == [
        ("ip:vrf1:10.0.0.1", "uid"),
        ("ip:vrf2:10.0.0.10", "address"),
        ("dev:1", "text"),
    ]
    assert body["total"] == 3 and body["labels"] == [
        {"label": "IpAddress", "count": 2},
        {"label": "Device", "count": 1},
    ]
    address = next(c for c in fake.calls if "STARTS WITH" in c[0])
    assert "MATCH (n:IpAddress:Obj) WHERE n.ip" in address[0] and address[1]["q"] == "10.0.0.1"
    text = next(c for c in fake.calls if "queryNodes" in c[0])
    assert text[1]["lucene"] == r"10.0.0.1*"
    assert all(call[1]["snap"] == 1700 for call in fake.calls), "every query reads one snapshot"
    # each read starts from the run: an equality on collection_ts, never the coalesce guard
    assert all("collection_ts = $snap" in c[0] or "collection_ts: $snap" in c[0] for c in fake.calls)
    assert not any(".collection_ts, $snap)" in c[0] for c in fake.calls)


async def test_search_escapes_query_syntax_and_filters_by_label(client, monkeypatch, snap):
    fake = install(monkeypatch, [])
    await login(client, "vera")
    r = await client.get("/api/explore/search", params={"q": 'core-sw "a" (b)', "label": "Device"})
    assert r.status_code == 200 and r.json()["items"] == []
    text = next(c for c in fake.calls if "queryNodes" in c[0])
    assert text[1]["lucene"] == "core* AND sw* AND a* AND b*"
    assert "AND n:`Device`" in text[0]
    assert not any("STARTS WITH" in c[0] for c in fake.calls), (
        "text that is no address skips the address lookup"
    )
    r = await client.get("/api/explore/search", params={"q": "10.1.0.0/16"})
    assert any("MATCH (n:Prefix:Obj) WHERE n.cidr STARTS WITH $q" in c[0] for c in fake.calls)


async def test_node_returns_properties_apart_from_bookkeeping_and_groups_neighbors(client, monkeypatch, snap):
    node = {
        "id": "4:x:1",
        "labels": ["Device", "Obj", "Phys"],
        "properties": {"uid": "dev:1", "hostname": "edge1", "platform": "vyos", "_sources": ["lab"]},
    }
    groups = table(
        ["type", "direction", "label", "count"],
        [["ON", "in", "Interface", 12], ["LOCATED_IN", "out", "Site", 1]],
    )
    install(
        monkeypatch,
        [
            (
                "RETURN n AS _n LIMIT 1",
                lambda p: table([], [], {"nodes": [node], "relationships": [], "truncated": False}),
            ),
            ("MATCH (n)-[r]-(m)", lambda p: groups),
        ],
    )
    await login(client, "vera")
    r = await client.get("/api/explore/node", params={"uid": "dev:1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["node"]["label"] == "Device" and body["node"]["name"] == "edge1"
    assert body["node"]["properties"] == {"uid": "dev:1", "hostname": "edge1", "platform": "vyos"}
    assert body["node"]["bookkeeping"] == {"_sources": ["lab"]}
    assert body["neighbors"][0] == {"type": "ON", "direction": "in", "label": "Interface", "count": 12}
    install(monkeypatch, [])
    assert (await client.get("/api/explore/node", params={"uid": "dev:gone"})).status_code == 404


async def test_neighbors_page_one_group_in_the_asked_direction(client, monkeypatch, snap):
    graph = {"nodes": [], "relationships": [], "truncated": False}
    fake = install(
        monkeypatch,
        [
            ("RETURN count(m) AS total", lambda p: table(["total"], [[120]])),
            (
                "SKIP $offset",
                lambda p: table(["uid", "label", "name"], [["dev:1/if/eth0", "Interface", "eth0"]], graph),
            ),
        ],
    )
    await login(client, "vera")
    r = await client.get(
        "/api/explore/neighbors",
        params={
            "uid": "dev:1",
            "type": "ON",
            "direction": "in",
            "label": "Interface",
            "offset": 50,
            "limit": 50,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 120 and r.json()["items"][0]["name"] == "eth0" and r.json()["graph"] == graph
    page = next(c for c in fake.calls if "SKIP" in c[0])
    assert "(n)<-[r:`ON`]-(m)" in page[0] and "AND m:`Interface`" in page[0]
    assert page[1]["offset"] == 50 and page[1]["limit"] == 50 and page[2] is True


async def test_label_detail_reports_property_shares_from_a_sample(client, monkeypatch, snap):
    install(
        monkeypatch,
        [
            ("RETURN count(n) AS count", lambda p: table(["count"], [[5000]])),
            ("UNWIND keys(n)", lambda p: table(["key", "filled"], [["uid", 200], ["hostname", 150]])),
            (
                "MATCH (n)-[r]-(m)",
                lambda p: table(["type", "direction", "other", "count"], [["ON", "in", "Interface", 900]]),
            ),
            ("ORDER BY name LIMIT 25", lambda p: table(["uid", "name"], [["dev:1", "edge1"]])),
        ],
    )
    await login(client, "vera")
    r = await client.get("/api/explore/labels/Device")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 5000 and body["sampled"] is True and body["layers"] == ["Phys"]
    assert body["properties"] == [{"name": "uid", "share": 1.0}, {"name": "hostname", "share": 0.75}]
    assert body["relationships"] == [{"type": "ON", "direction": "in", "other": "Interface", "count": 900}]
    assert body["cypher"].startswith("MATCH (n:Device:Obj)")


async def test_stats_are_cached_per_snapshot_and_never_before_the_first_run(client, monkeypatch, snap):
    labels = table(["label", "count"], [["Interface", 40], ["Device", 2]])
    devices = table(
        ["vendor", "platform", "role", "count"], [["cisco", "iosxe", "router", 1], ["", "vyos", "router", 1]]
    )
    fake = install(
        monkeypatch,
        [("AS label WHERE label IS NOT NULL", lambda p: labels), ("MATCH (d:Device:Obj)", lambda p: devices)],
    )
    await login(client, "vera")
    first = (await client.get("/api/explore/stats")).json()
    assert first["total_nodes"] == 42 and first["snapshot"] == 1700
    assert first["devices"]["total"] == 2
    assert first["devices"]["by_role"] == [{"value": "router", "count": 2}]
    assert {"value": "unknown", "count": 1} in first["devices"]["by_vendor"]
    assert {"layer": "Phys", "count": 2} in first["layers"]
    calls = len(fake.calls)
    assert (await client.get("/api/explore/stats")).json() == first
    assert len(fake.calls) == calls, "a published snapshot is read once"
    snap["value"] = 1800
    await client.get("/api/explore/stats")
    assert len(fake.calls) == calls + 2, "a new snapshot is read again"
    snap["value"] = explore.LIVE_SNAP
    await client.get("/api/explore/stats")
    await client.get("/api/explore/stats")
    assert len(fake.calls) == calls + 6, "the graph before the first run is never cached"


async def test_values_filter_distinct_values_by_text(client, monkeypatch, snap):
    fake = install(monkeypatch, [("RETURN value", lambda p: table(["value", "count"], [["edge1", 1]]))])
    await login(client, "vera")
    r = await client.get(
        "/api/explore/values", params={"label": "Device", "property": "hostname", "q": " ED ", "limit": 5}
    )
    assert r.status_code == 200 and r.json()["items"] == [{"value": "edge1", "count": 1}]
    cypher, params, _ = fake.calls[0]
    assert "n.`hostname` IS NOT NULL" in cypher and params == {"snap": 1700, "q": "ED", "limit": 5}


def test_every_catalog_picker_names_a_registered_label_and_a_valid_property():
    from hst.core.labels import LABELS
    from hst.queries import catalog

    pickers = [p["picker"] for q in catalog() for p in q.get("params", []) if "picker" in p]
    assert pickers, "the catalog offers value pickers"
    for picker in pickers:
        assert picker["label"] in LABELS, picker
        assert explore._IDENT.match(picker["property"]), picker


# --- routes from the side store -------------------------------------------------------------


@pytest.fixture
def rib_store(tmp_path, monkeypatch):
    """A side store with one device's routes in two contexts, bound to a
    snapshot with no manifest, so the reader picks files by age."""
    pytest.importorskip("duckdb")
    from types import SimpleNamespace

    from hst.core import ipenc, sidestore
    from hst.core.snapshot import Snapshot

    def row(prefix, next_hop, protocol, context_uid):
        lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
        return {
            "device_uid": "dev:r1",
            "vrf": "x",
            "context_uid": context_uid,
            "prefix": prefix,
            "next_hop": next_hop,
            "interface": "eth0",
            "protocol": protocol,
            "metric": 1,
            "af": af,
            "prefixlen": prefixlen,
            "lo": lo,
            "hi": hi,
        }

    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000001000-bbbbbbbb",
        [
            row("0.0.0.0/0", "10.0.0.1", "static", "vrf:r1:blue"),
            row("10.1.0.0/16", "10.0.0.2", "ospf", "vrf:r1:blue"),
            row("10.1.2.0/24", "10.0.0.3", "bgp", "vrf:r1:blue"),
            row("192.0.2.0/24", "10.0.0.9", "bgp", "vrf:r1:red"),
        ],
        1700,
    )
    snapshot = Snapshot(1700, SimpleNamespace(sidestore_dir=tmp_path))
    monkeypatch.setattr(explore, "_snapshot", lambda request: snapshot)
    return tmp_path


def node_lookup(label, name=None, device_uid=None):
    return (
        "AS device_uid LIMIT 1",
        lambda p: table(["label", "name", "device_uid"], [[label, name, device_uid]]),
    )


async def test_routes_of_a_device_list_every_context_with_protocol_counts(client, monkeypatch, rib_store):
    fake = install(monkeypatch, [node_lookup("Device")])
    await login(client, "vera")
    r = await client.get("/api/explore/routes", params={"uid": "dev:r1"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["available"] and body["approximate"] and body["run_id"] == "1700000001000-bbbbbbbb"
    assert body["total"] == 4 and body["context_uid"] is None
    assert [i["prefix"] for i in body["items"]] == ["0.0.0.0/0", "10.1.0.0/16", "10.1.2.0/24", "192.0.2.0/24"]
    assert {i["context_uid"] for i in body["items"]} == {"vrf:r1:blue", "vrf:r1:red"}
    assert body["protocols"][0] == {"protocol": "bgp", "count": 2}
    assert fake.calls[0][1] == {"snap": 1700, "uid": "dev:r1"}


async def test_routes_of_a_vrf_answer_its_context_and_an_address_longest_match_first(
    client, monkeypatch, rib_store
):
    install(monkeypatch, [node_lookup("VrfInstance", "blue", "dev:r1")])
    await login(client, "vera")
    r = await client.get("/api/explore/routes", params={"uid": "vrf:r1:blue", "address": "10.1.2.7"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["device_uid"] == "dev:r1" and body["context_uid"] == "vrf:r1:blue"
    assert [i["prefix"] for i in body["items"]] == ["10.1.2.0/24", "10.1.0.0/16", "0.0.0.0/0"]
    r = await client.get("/api/explore/routes", params={"uid": "vrf:r1:blue", "protocol": "ospf"})
    assert [i["prefix"] for i in r.json()["items"]] == ["10.1.0.0/16"]


async def test_routes_refuse_other_nodes_bad_addresses_and_unowned_vrfs(client, monkeypatch, rib_store):
    await login(client, "vera")
    install(monkeypatch, [node_lookup("Interface")])
    assert (await client.get("/api/explore/routes", params={"uid": "if:1"})).status_code == 422
    install(monkeypatch, [node_lookup("VrfInstance", "blue", None)])
    assert (await client.get("/api/explore/routes", params={"uid": "vrf:x"})).status_code == 404
    install(monkeypatch, [])
    assert (await client.get("/api/explore/routes", params={"uid": "dev:gone"})).status_code == 404
    r = await client.get("/api/explore/routes", params={"uid": "dev:r1", "address": "10.1.2"})
    assert r.status_code == 422


async def test_routes_say_when_the_side_store_holds_nothing(client, monkeypatch, tmp_path):
    from types import SimpleNamespace

    from hst.core.snapshot import Snapshot

    monkeypatch.setattr(
        explore, "_snapshot", lambda request: Snapshot(1700, SimpleNamespace(sidestore_dir=tmp_path))
    )
    install(monkeypatch, [node_lookup("Device")])
    await login(client, "vera")
    body = (await client.get("/api/explore/routes", params={"uid": "dev:r1"})).json()
    assert body["available"] is False and body["total"] == 0 and body["items"] == []


async def test_routes_name_the_snapshot_each_page_was_read_from(client, monkeypatch, rib_store):
    from types import SimpleNamespace

    from hst.core.snapshot import Snapshot

    install(monkeypatch, [node_lookup("Device")])
    await login(client, "vera")
    first = (await client.get("/api/explore/routes", params={"uid": "dev:r1", "limit": 2})).json()
    assert first["snapshot"] == 1700

    later = Snapshot(2000, SimpleNamespace(sidestore_dir=rib_store))
    monkeypatch.setattr(explore, "_snapshot", lambda request: later)
    params = {"uid": "dev:r1", "offset": 2, "limit": 2}
    second = (await client.get("/api/explore/routes", params=params)).json()
    assert second["snapshot"] == 2000 and second["offset"] == 2


async def test_the_location_picker_leaves_out_zia_sublocations(client, monkeypatch, snap):
    fake = install(monkeypatch, [("RETURN value", lambda p: table(["value", "count"], [["hq", 1]]))])
    await login(client, "vera")
    r = await client.get("/api/explore/values", params={"label": "ZiaLocation", "property": "name"})
    assert r.status_code == 200
    cypher, _params, _ = fake.calls[0]
    assert "NOT (n)-[:PART_OF]->(:ZiaLocation)" in cypher
    await client.get("/api/explore/values", params={"label": "Device", "property": "hostname"})
    assert "PART_OF" not in fake.calls[1][0]


async def test_the_user_group_picker_marks_a_name_that_is_a_group_id(client, monkeypatch, snap):
    fake = install(
        monkeypatch,
        [("RETURN value", lambda p: table(["value", "count", "id_only"], [["77001", 1, True]]))],
    )
    await login(client, "vera")
    r = await client.get("/api/explore/values", params={"label": "IdentityGroup", "property": "name"})
    assert r.json()["items"] == [{"value": "77001", "count": 1, "id_only": True}]
    assert "n.name_is_id" in fake.calls[0][0]
    await client.get("/api/explore/values", params={"label": "Device", "property": "hostname"})
    assert "name_is_id" not in fake.calls[1][0]
