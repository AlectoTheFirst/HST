"""GET /api/explore/search?typed=true: the typed search of core/search.py at
the route, Neo4j faked at the explore module's session seam and the side
store at `search.side_rows`."""

from __future__ import annotations

import contextlib
import re
from typing import Any

import pytest
from tests.app.conftest import login

import hst.app.routes.explore as explore
from hst.core import cycle as cyclemod
from hst.core import filters as F
from hst.core import search as S
from hst.core import snapshot as snapshotmod

SNAP = 4242
OLD = 4000


@pytest.fixture(autouse=True)
def _no_run_node(monkeypatch):
    """These fakes hold no `:CycleRun` node, as a fixture load does: the reader
    lease's pruned-run check (routes/run_lease.py) reads the graph as it is."""
    monkeypatch.setattr(cyclemod, "run_present", lambda s, cts: False)


class _Session:
    """Answers the pointer read, the exact-uid read, the page, count and
    device-name reads by query text, and records every read."""

    def __init__(self, pages: dict[str, list[dict[str, Any]]] | None = None, exact: list[str] | None = None):
        self.pages = pages or {}
        self.exact = exact
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run(self, query, **params):
        text = getattr(query, "text", query)
        out: list[dict[str, Any]] = []
        if "CyclePointer" in text:
            out = [{"current": SNAP}]
        else:
            self.calls.append((text, params))
            if "{uid: $u_uid, collection_ts: $snap}" in text:
                out = [{"labels": self.exact}] if self.exact else []
            elif "RETURN count(" in text:
                kind = _kind_of(text)
                out = [{"n": len(self.pages.get(kind, []))}]
            elif "AS sort_key" in text:
                rows = sorted(self.pages.get(_kind_of(text), []), key=lambda r: (r["sort_key"], r["uid"]))
                if "c_key" in params:
                    rows = [r for r in rows if (r["sort_key"], r["uid"]) > (params["c_key"], params["c_uid"])]
                out = rows[: params["limit"]]
            elif "d.uid IN $uids" in text:
                out = [{"uid": u, "name": f"host-{u}"} for u in params["uids"]]

        class _R:
            def data(self_inner):
                return out

        return _R()


def _kind_of(text: str) -> str:
    """The kind a page or count query lists: the label of its first MATCH, or
    of the label check after the full-text call."""
    m = re.search(r"^MATCH \(\w+:(\w+)\)|^WHERE \w+:(\w+) AND", text.strip(), re.MULTILINE)
    assert m is not None, text
    return S.LABEL_KIND[m.group(1) or m.group(2)]


def _row(uid: str, name: str, detail: str = "") -> dict[str, Any]:
    return {"uid": uid, "sort_key": name, "name": name, "detail": detail}


@pytest.fixture
def graph(monkeypatch):
    def install(session: _Session) -> _Session:
        @contextlib.contextmanager
        def cm(settings):
            yield session

        monkeypatch.setattr(explore, "_session", cm)
        return session

    return install


@pytest.fixture(autouse=True)
def retained(monkeypatch):
    def check(session, cts):
        if cts not in (SNAP, OLD):
            raise ValueError(f"unknown run {cts}")

    monkeypatch.setattr(snapshotmod, "require_retained", check)


@pytest.fixture(autouse=True)
def no_side_store(monkeypatch):
    seen: list[tuple[Any, str, tuple[str, ...]]] = []

    def side_rows(snapshot, q, kinds):
        seen.append((snapshot.cts, q.mode, kinds))
        return S.SideRows()

    monkeypatch.setattr(S, "side_rows", side_rows)
    return seen


async def _get(client, **params):
    return await client.get("/api/explore/search", params={"typed": "true", **params})


async def test_an_address_answers_typed_groups_with_counts_and_the_untyped_fields(
    client, graph, no_side_store
):
    session = graph(
        _Session(
            pages={
                "device": [_row("dev:edge1", "edge1", "vyos")],
                "prefix": [_row("pfx:a", "10.1.2.0/24"), _row("pfx:b", "10.1.0.0/16")],
            }
        )
    )
    await login(client, "vera")
    r = await _get(client, q=" 10.1.2.7 ")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["query"] == "10.1.2.7" and body["mode"] == "ip" and body["snapshot"] == SNAP
    assert body["kinds"] == [
        {"kind": "device", "count": 1, "count_exact": True},
        {"kind": "prefix", "count": 2, "count_exact": True},
    ]
    device = body["groups"]["device"]["items"][0]
    assert device == {
        "kind": "device",
        "key": "dev:edge1",
        "uid": "dev:edge1",
        "name": "edge1",
        "detail": "vyos",
        "source": "graph",
        "matched": "ip",
        "run": SNAP,
        "source_run": None,
        "target": {"kind": "device", "uid": "dev:edge1"},
        "fields": {},
    }
    assert [(i["uid"], i["label"]) for i in body["items"]] == [
        ("dev:edge1", "Device"),
        ("pfx:b", "Prefix"),
        ("pfx:a", "Prefix"),
    ]
    assert body["total"] == 3
    assert body["labels"] == [{"label": "Prefix", "count": 2}, {"label": "Device", "count": 1}]
    assert body["side_store"] == {"available": False, "approximate": False, "capped": [], "timed_out": []}
    # every graph read binds the one run the request resolved
    assert session.calls and all(p["snap"] == SNAP for _, p in session.calls)
    assert no_side_store == [(SNAP, "ip", ("arp", "mac", "route", "ospf_lsa"))]
    # an address searches the kinds that hold addresses, through their keys
    listed = {_kind_of(t) for t, _ in session.calls if "AS sort_key" in t}
    assert listed == {"device", "interface", "prefix", "ip_address", "endpoint"}


async def test_a_kind_pages_by_cursor_in_the_run_of_the_cursor(client, graph):
    rows = [_row(f"dev:{i}", f"edge{i}") for i in range(5)]
    session = graph(_Session(pages={"device": rows}))
    await login(client, "vera")
    r = await _get(client, q="edge", kind="device", limit=2)
    body = r.json()
    group = body["groups"]["device"]
    assert [h["name"] for h in group["items"]] == ["edge0", "edge1"]
    assert body["kinds"] == [{"kind": "device", "count": 5, "count_exact": True}]
    cursor = group["next_cursor"]
    assert F.decode_cursor(cursor, kind="device", filter_print=S.detect("edge").fingerprint).run == SNAP

    session.calls.clear()
    r = await _get(client, q="edge", kind="device", limit=2, cursor=cursor)
    assert r.status_code == 200, r.text
    body = r.json()
    assert [h["name"] for h in body["groups"]["device"]["items"]] == ["edge2", "edge3"]
    assert body["kinds"] == [], "a next page reads no counts"
    page = next(p for t, p in session.calls if "AS sort_key" in t)
    assert (page["c_key"], page["c_uid"], page["snap"]) == ("edge1", "dev:1", SNAP)
    assert not any("{uid: $u_uid, collection_ts: $snap}" in t for t, _ in session.calls), (
        "a next page skips the uid lookup"
    )


async def test_a_cursor_is_refused_for_another_query_kind_or_run(client, graph):
    graph(_Session())
    await login(client, "vera")
    cursor = F.Cursor(kind="device", run=SNAP, key="a", uid="b", filter=S.detect("edge").fingerprint).encode()
    r = await _get(client, q="core", kind="device", cursor=cursor)
    assert r.status_code == 400 and "another filter" in r.json()["error"]
    r = await _get(client, q="edge", cursor=cursor)
    assert r.status_code == 400 and "exactly one kind" in r.json()["error"]
    r = await _get(client, q="edge", kind="device", cursor=cursor, snapshot=str(OLD))
    assert r.status_code == 400 and "another run" in r.json()["error"]


async def test_a_named_run_pins_every_read(client, graph, no_side_store):
    session = graph(_Session())
    await login(client, "vera")
    r = await _get(client, q="10.1.2.0/24", snapshot=str(OLD))
    assert r.status_code == 200 and r.json()["snapshot"] == OLD
    assert session.calls and all(p["snap"] == OLD for _, p in session.calls)
    assert no_side_store[-1][0] == OLD
    assert (await _get(client, q="edge", snapshot="999")).status_code == 404


async def test_the_regex_guard_and_unknown_kinds_are_400s(client, graph):
    session = graph(_Session())
    await login(client, "vera")
    r = await _get(client, q="/(a+)+/")
    assert r.status_code == 400 and "regex refused" in r.json()["error"]
    r = await _get(client, q="edge", kind="nodes")
    assert r.status_code == 400 and "unknown kind" in r.json()["error"]
    assert session.calls == [], "nothing is read before the query and kinds are checked"


async def test_an_exact_uid_answers_that_object_alone(client, graph):
    session = graph(_Session(pages={"site": [_row("site:ber", "BER")]}, exact=["Site", "Obj", "Phys"]))
    await login(client, "vera")
    body = (await _get(client, q="site:ber")).json()
    assert body["mode"] == "uid"
    assert list(body["groups"]) == ["site"]
    pages = [(t, p) for t, p in session.calls if "AS sort_key" in t]
    assert len(pages) == 1 and "s.uid = $u_uid" in pages[0][0] and pages[0][1]["u_uid"] == "site:ber"


async def test_side_store_hits_are_typed_and_named_by_the_graph(client, graph, monkeypatch):
    graph(_Session())

    def side_rows(snapshot, q, kinds):
        out = S.SideRows(available=True, approximate=False, capped=["route"])
        out.rows["arp"] = [
            {
                "device_uid": "dev:r1",
                "vrf": None,
                "context_uid": None,
                "ip": "10.1.2.7",
                "mac": "aabbcc000007",
                "interface_name": "Vlan20",
                "run_id": "4242-aa",
            }
        ]
        out.rows["route"] = []
        return out

    monkeypatch.setattr(S, "side_rows", side_rows)
    await login(client, "vera")
    body = (await _get(client, q="10.1.2.7", kind=["arp", "route"])).json()
    assert body["kinds"] == [{"kind": "arp", "count": 1, "count_exact": True}]
    hit = body["groups"]["arp"]["items"][0]
    assert hit["source"] == "arp" and hit["fields"]["device"] == "host-dev:r1"
    assert hit["detail"] == "host-dev:r1 Vlan20 aa:bb:cc:00:00:07"
    assert hit["source_run"] == "4242-aa" and hit["run"] == SNAP
    assert body["side_store"]["capped"] == ["route"]
    assert body["items"] == [] and body["total"] == 0


async def test_without_typed_the_answer_is_the_untyped_one(client, graph, monkeypatch):
    session = graph(_Session())
    monkeypatch.setattr(explore, "_snap", lambda request: SNAP)
    monkeypatch.setattr(
        explore, "run_readonly", lambda *a, **k: {"columns": [], "data": [], "truncated": False}
    )
    await login(client, "vera")
    body = (await client.get("/api/explore/search", params={"q": "edge"})).json()
    assert set(body) == {"query", "items", "total", "labels"}
    assert session.calls == []
