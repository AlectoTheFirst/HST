"""GET /api/endpoints and the filtered GET /api/topology/segment, Neo4j faked
at the module seams."""

from __future__ import annotations

import contextlib

import pytest
from tests.app.conftest import login

import hst.app.routes.endpoints as endpoints_route
import hst.app.routes.topology as topology_route
from hst.core import cycle as cyclemod
from hst.core import entity_read
from hst.core import filters as F
from hst.core import snapshot as snapshotmod


@pytest.fixture(autouse=True)
def _no_run_node(monkeypatch):
    """These fakes hold no `:CycleRun` node, as a fixture load does: the reader
    lease's pruned-run check (routes/run_lease.py) reads the graph as it is."""
    monkeypatch.setattr(cyclemod, "run_present", lambda s, cts: False)


SNAP = 4242
OLD = 4000


class _Session:
    """Answers the pointer read, the page, count and row reads by query text,
    and records every read with its parameters."""

    def __init__(self, page=(), count=0, rows=(), by_text=None):
        self.page = list(page)
        self.count = count
        self.rows = list(rows)
        self.by_text = by_text or {}
        self.calls: list[tuple[str, dict]] = []

    def run(self, query, **params):
        text = getattr(query, "text", query)
        if "CyclePointer" in text:
            out = [{"current": SNAP}]
        else:
            self.calls.append((text, params))
            if text in self.by_text:
                out = self.by_text[text]
            elif "count(e) AS n" in text:
                out = [{"n": self.count}]
            elif "AS sort_key" in text:
                out = self.page[: params["limit"]]
            elif "UNWIND $uids" in text:
                out = [r for r in self.rows if r["uid"] in params["uids"]]
            else:
                out = []

        class _R:
            def data(self_inner):
                return out

        return _R()

    def execute_read(self, work):
        return work(self)


def _seam(monkeypatch, session, module=endpoints_route):
    @contextlib.contextmanager
    def cm(settings):
        yield session

    monkeypatch.setattr(module, "_session", cm)
    return session


@pytest.fixture
def retained(monkeypatch):
    """The runs whose graph is retained; any other named run is unknown."""
    runs = {SNAP, OLD}

    def check(session, cts):
        if cts not in runs:
            raise ValueError(f"unknown run {cts}")

    monkeypatch.setattr(snapshotmod, "require_retained", check)
    return runs


def _ep(i):
    return {
        "uid": f"ep:{i}",
        "name": f"host-{i}",
        "label": f"host-{i}",
        "hostname": None,
        "mac": f"aa:bb:cc:00:00:0{i}",
        "vendor": "Synology",
        "kind": "client",
        "wired": True,
        "ip": None,
        "last_seen": 1_760_000_000_000,
        "ips": [f"10.0.0.{i}"],
        "attachments": [
            {
                "device": "swa-01",
                "device_name": "swa-01",
                "port": f"Port {i}",
                "ssid": None,
                "sites": ["ber1"],
            }
        ],
        "bd": "bd:vlan:fab0:10",
    }


async def test_endpoints_require_auth(client):
    assert (await client.get("/api/endpoints")).status_code == 401


async def test_endpoints_page_by_cursor_within_one_run(client, monkeypatch, retained):
    await login(client, "vera")
    page = [{"uid": f"ep:{i}", "sort_key": f"host-{i}"} for i in range(3)]
    s = _seam(monkeypatch, _Session(page=page, count=3, rows=[_ep(i) for i in range(3)]))

    r = await client.get("/api/endpoints", params={"q": "host", "site": "ber1", "limit": 2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["snapshot"], body["total_capped"], body["total_exact"], body["limit"]) == (SNAP, 3, True, 2)
    assert [i["uid"] for i in body["items"]] == ["ep:0", "ep:1"]
    assert body["items"][0]["attachments"][0]["port"] == "Port 0"
    assert body["next_cursor"]
    # every read of the request is pinned to the one resolved run
    assert {p["snap"] for _, p in s.calls} == {SNAP}
    page_text, page_params = s.calls[0]
    assert "(e:Endpoint:Obj)\nWHERE e.collection_ts = $snap" in page_text
    assert (page_params["f_text"], page_params["f_site"]) == ("host", ["site:ber1"])

    # the next page reads the cursor's run, even after the pointer moved on
    s2 = _seam(monkeypatch, _Session(page=page[2:], count=3, rows=[_ep(2)]))
    monkeypatch.setattr(endpoints_route.snapshotmod, "resolve", _resolve_spy := _Spy(snapshotmod.resolve))
    r = await client.get(
        "/api/endpoints", params={"q": "host", "site": "ber1", "limit": 2, "cursor": body["next_cursor"]}
    )
    assert r.status_code == 200, r.text
    assert [i["uid"] for i in r.json()["items"]] == ["ep:2"]
    assert r.json()["next_cursor"] is None
    assert _resolve_spy.cts == [SNAP]
    assert (s2.calls[0][1]["c_key"], s2.calls[0][1]["c_uid"]) == ("host-1", "ep:1")


class _Spy:
    def __init__(self, fn):
        self.fn = fn
        self.cts: list = []

    def __call__(self, session, settings, cts=None):
        self.cts.append(cts)
        return self.fn(session, settings, cts)


async def test_a_named_run_pins_every_read(client, monkeypatch, retained):
    await login(client, "vera")
    s = _seam(monkeypatch, _Session())
    r = await client.get("/api/endpoints", params={"snapshot": str(OLD)})
    assert r.status_code == 200
    assert r.json()["snapshot"] == OLD
    assert {p["snap"] for _, p in s.calls} == {OLD}
    assert (await client.get("/api/endpoints", params={"snapshot": "123"})).status_code == 404
    assert (await client.get("/api/endpoints", params={"snapshot": "x"})).status_code == 400


async def test_a_cursor_is_refused_for_another_run_filter_or_list(client, monkeypatch, retained):
    await login(client, "vera")
    _seam(monkeypatch, _Session())
    f = F.parse_filter({"text": "host"})
    cur = F.Cursor(kind="endpoint", run=OLD, key="a", uid="b", filter=f.fingerprint()).encode()
    r = await client.get("/api/endpoints", params={"q": "host", "cursor": cur, "snapshot": str(SNAP)})
    assert r.status_code == 400 and "another run" in r.json()["error"]
    r = await client.get("/api/endpoints", params={"q": "other", "cursor": cur})
    assert r.status_code == 400 and "another filter" in r.json()["error"]
    seg = F.Cursor(kind="segment_client", run=OLD, key="a", uid="b", filter=f.fingerprint()).encode()
    r = await client.get("/api/endpoints", params={"q": "host", "cursor": seg})
    assert r.status_code == 400 and "another list" in r.json()["error"]
    r = await client.get("/api/endpoints", params={"cursor": "garbage!"})
    assert r.status_code == 400 and "invalid cursor" in r.json()["error"]


@pytest.mark.parametrize(
    ("params", "message"),
    [
        ({"ip": "10.0.0.300"}, "not an IP address"),
        ({"subnet": "nope"}, "not a prefix"),
        ({"range_start": "10.0.0.1"}, "go together"),
        ({"regex": "(a+)+"}, "regex refused"),
        ({"regex": "(?=a)"}, "regex refused"),
        ({"q_field": "name"}, "needs text"),
        ({"last_seen_after": "yesterday"}, "last_seen_after"),
    ],
)
async def test_a_bad_filter_is_a_400_before_any_read(client, monkeypatch, params, message):
    await login(client, "vera")
    s = _seam(monkeypatch, _Session())
    r = await client.get("/api/endpoints", params=params)
    assert r.status_code == 400, r.text
    assert message in r.json()["error"]
    assert s.calls == []


async def test_the_page_size_is_bounded(client, monkeypatch):
    await login(client, "vera")
    _seam(monkeypatch, _Session())
    r = await client.get("/api/endpoints", params={"limit": endpoints_route.ENDPOINT_PAGE_MAX + 1})
    assert r.status_code == 422


async def test_the_reads_run_under_the_filter_timeout(client, monkeypatch):
    await login(client, "vera")
    seen: list = []

    class _Timed(_Session):
        def run(self, query, **params):
            if not isinstance(query, str):
                seen.append(query.timeout)
            return super().run(query, **params)

    _seam(monkeypatch, _Timed(page=[{"uid": "ep:0", "sort_key": "a"}], count=1, rows=[_ep(0)]))
    assert (await client.get("/api/endpoints", params={"regex": "host-.*"})).status_code == 200
    assert seen == [F.QUERY_TIMEOUT_S] * 3


# --- the segment list -----------------------------------------------------------------


def _client_row(i, bd="bd:vlan:fab0:10"):
    return {
        "dev": "swa-01",
        "dev_name": "swa-01",
        "ssid": None,
        "port": f"Port {i}",
        "cabled": False,
        "name": f"ep:{i:02d}",
        "uid": f"ep:{i:02d}",
        "mac": None,
        "wired": True,
        "vendor": "Synology",
        "last_seen": 1,
        "bd": bd,
        "ips": [],
    }


def _device():
    return {
        "uid": "swa-01",
        "name": "swa-01",
        "role": "switch",
        "tier": "access",
        "site": "ber1",
        "mac": None,
    }


async def test_the_segment_list_takes_the_endpoint_filters(client, monkeypatch):
    await login(client, "vera")
    bd = "bd:vlan:fab0:10"
    rows = [_client_row(i) for i in range(4)]
    devices = {topology_route._DEVICES: [_device()], topology_route._SITE_DEVICES: [_device()]}
    s = _seam(monkeypatch, _Session(by_text=devices), topology_route)
    s.rows = rows

    def answer(query, **params):
        text = getattr(query, "text", query)
        if text.startswith(("CALL () {\nMATCH (bd:Obj", "CALL () {\nUNWIND $devs")):
            s.calls.append((text, params))

            class _R:
                def data(self_inner):
                    return [{"total": len(rows), "page": rows[: params["limit"] + 1]}]

            return _R()
        return _Session.run(s, query, **params)

    s.run = answer  # type: ignore[method-assign]
    r = await client.get(
        "/api/topology/segment", params={"bd": bd, "site": "ber1", "q": "ep", "port": "Port 1"}
    )
    assert r.status_code == 200, r.text
    text, params = s.calls[-1]
    assert text != topology_route._SITE_SEGMENT_PAGE_QUERY
    assert "AND (" in text and "$f_text" in text
    # asked for a site, the read starts from the devices of the site
    assert (params["bd"], params["devs"], params["snap"], params["f_text"], params["f_port"]) == (
        bd,
        ["swa-01"],
        SNAP,
        "ep",
        ["Port 1"],
    )
    # the segment list states site and segment itself
    r = await client.get("/api/topology/segment", params={"bd": bd, "segment": "x"})
    assert r.status_code == 200
    assert "f_segment" not in s.calls[-1][1]


class _SegmentPages(_Session):
    """Answers the segment page read as the database cuts it (topology.py
    `_SEGMENT_PAGE_TAIL`) from rows already in (name, uid) order."""

    def __init__(self, rows, **kwargs):
        super().__init__(**kwargs)
        self.segment_rows = rows

    def run(self, query, **params):
        text = getattr(query, "text", query)
        if text != topology_route._SEGMENT_PAGE_QUERY:
            return super().run(query, **params)
        rows = self.segment_rows
        if params["after_name"] is None:
            start = params["offset"]
        else:
            at = (params["after_name"], params["after_uid"])
            start = len([r for r in rows if (r["name"], r["uid"]) <= at])
        out = [{"total": len(rows), "page": rows[start : start + params["limit"] + 1]}]

        class _R:
            def data(self_inner):
                return out

        return _R()


async def test_the_segment_list_pages_by_cursor(client, monkeypatch, retained):
    await login(client, "vera")
    bd = "bd:vlan:fab0:10"
    rows = [_client_row(i) for i in range(5)]
    _seam(monkeypatch, _SegmentPages(rows, by_text={topology_route._DEVICES: [_device()]}), topology_route)
    r = await client.get("/api/topology/segment", params={"bd": bd, "limit": 2})
    body = r.json()
    assert [c["uid"] for c in body["clients"]] == ["ep:00", "ep:01"]
    assert body["next_cursor"] and body["total"] == 5
    seen = [c["uid"] for c in body["clients"]]
    cursor = body["next_cursor"]
    while cursor:
        r = await client.get("/api/topology/segment", params={"bd": bd, "limit": 2, "cursor": cursor})
        assert r.status_code == 200, r.text
        seen += [c["uid"] for c in r.json()["clients"]]
        cursor = r.json()["next_cursor"]
    assert seen == [f"ep:{i:02d}" for i in range(5)]
    # a cursor pages the list it came from only
    r = await client.get(
        "/api/topology/segment", params={"bd": "bd:vlan:fab0:20", "cursor": body["next_cursor"]}
    )
    assert r.status_code == 400
    r = await client.get(
        "/api/topology/segment", params={"bd": bd, "cursor": body["next_cursor"], "offset": 2}
    )
    assert r.status_code == 400
    # the offset pages keep their answer, with the cursor of the page after
    r = await client.get("/api/topology/segment", params={"bd": bd, "offset": 3, "limit": 2})
    assert [c["uid"] for c in r.json()["clients"]] == ["ep:03", "ep:04"]
    assert r.json()["next_cursor"] is None


def test_the_unfiltered_segment_query_is_the_filtered_one_without_a_filter():
    assert (
        topology_route._SEGMENT_CLIENTS_FILTERED.replace("/*filter*/", "") == topology_route._SEGMENT_CLIENTS
    )
    assert "/*filter*/" not in topology_route._SEGMENT_CLIENTS
    assert (
        topology_route._SITE_SEGMENT_CLIENTS_FILTERED.replace("/*filter*/", "")
        == topology_route._SITE_SEGMENT_CLIENTS
    )
    assert "/*filter*/" not in topology_route._SITE_SEGMENT_CLIENTS


def test_every_list_query_carries_the_run_guard():
    for queries in entity_read.LISTS.values():
        for text in (queries.page, queries.count):
            # the listed node starts from :Obj with an equality on the run
            # (a Site, which can be an operator :Meta node, with the Meta form)
            assert ":Obj" in text and ("collection_ts = $snap" in text), text
            assert "coalesce(" not in text.split("WITH")[0], text
    assert "(e:Endpoint:Obj {uid: want, collection_ts: $snap})" in entity_read.ENDPOINT_ROWS


async def test_a_named_run_is_leased_while_it_is_read(client, monkeypatch, retained, store):
    """The read of an old run holds the same reader lease as GET /path."""
    await login(client, "vera")
    held: list[set[int]] = []

    class _Watched(_Session):
        def run(self, query, **params):
            held.append({key for key, _ in store._run_leases.values()})
            return super().run(query, **params)

    _seam(monkeypatch, _Watched())
    r = await client.get("/api/endpoints", params={"snapshot": str(OLD)})
    assert r.status_code == 200
    assert any(OLD in keys for keys in held)
    assert store._run_leases == {}


async def test_a_run_pruned_while_it_is_read_is_a_409_not_a_partial_page(client, monkeypatch, retained):
    """A run whose `:CycleRun` node existed before the lease and is gone after the
    read was pruned by a turn that decided without the lease."""
    await login(client, "vera")
    checks: list[int] = []

    def present(s, cts):
        checks.append(cts)
        return len(checks) <= 2  # before the lease, inside it, then gone

    monkeypatch.setattr(cyclemod, "run_present", present)
    _seam(monkeypatch, _Session())
    r = await client.get("/api/endpoints", params={"snapshot": str(OLD)})
    assert r.status_code == 409
    assert r.json()["error"] == f"run {OLD} was pruned while it was read"
