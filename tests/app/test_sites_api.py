"""Sites: geography, device assignment, and reachability between locations."""

from __future__ import annotations

import pytest
from tests.app.conftest import login

from hst.app.routes import sites as sites_routes
from hst.app.routes.sites import SitePrefix
from hst.core import Settings
from hst.core.snapshot import Snapshot

# Captured before the autouse fixture below stubs `sites_routes._site_prefix_pair`.
_real_site_prefix_pair = sites_routes._site_prefix_pair
RUN = Snapshot(None, Settings(_env_file=None))
_real_device_details = sites_routes._device_details


@pytest.fixture(autouse=True)
def _no_graph(monkeypatch):
    """Stub the two graph-facing helpers; each test overrides what it needs."""
    monkeypatch.setattr(
        sites_routes,
        "_device_details",
        lambda request, uids: [{"uid": u, "hostname": u.split(":")[-1], "platform": "vyos"} for u in uids],
    )
    monkeypatch.setattr(sites_routes, "_site_prefix_pair", lambda request, src, dst: (RUN, [], []))


# --- CRUD ---------------------------------------------------------------------


async def test_viewers_can_read_but_not_change(client):
    await login(client, "vera")
    assert (await client.get("/api/sites")).status_code == 200
    r = await client.post("/api/sites", json={"code": "DEU-FRA-1"})
    assert r.status_code == 403


async def test_create_list_patch_delete(client):
    await login(client, "otto")
    r = await client.post(
        "/api/sites", json={"code": "DEU-FRA-123123", "name": "Frankfurt", "location": "Example Street 1"}
    )
    assert r.status_code == 201
    assert r.json()["code"] == "DEU-FRA-123123"

    sites = (await client.get("/api/sites")).json()["sites"]
    assert [s["code"] for s in sites] == ["DEU-FRA-123123"]
    assert sites[0]["device_count"] == 0

    r = await client.patch("/api/sites/DEU-FRA-123123", json={"name": "FRA1"})
    assert r.status_code == 200 and r.json()["name"] == "FRA1"

    r = await client.delete("/api/sites/DEU-FRA-123123")
    assert r.status_code == 200
    assert r.json() == {"groups": [], "locations": [], "devices": []}
    assert (await client.get("/api/sites")).json()["sites"] == []


async def test_duplicate_code_is_rejected(client):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "hq"})
    assert (await client.post("/api/sites", json={"code": "hq"})).status_code == 409


async def test_a_code_that_is_the_same_site_as_another_is_rejected(client):
    """Codes are case-sensitive but the graph Site uid is the slug of the code, so
    `DC1` beside `dc1` or `fra:1` beside `fra-1` would be two rows for one node."""
    await login(client, "otto")
    assert (await client.post("/api/sites", json={"code": "dc1"})).status_code == 201
    assert (await client.post("/api/sites", json={"code": "DC1"})).status_code == 409
    assert (await client.post("/api/sites", json={"code": "fra-1"})).status_code == 201
    assert (await client.post("/api/sites", json={"code": "fra:1"})).status_code == 409
    assert [s["code"] for s in (await client.get("/api/sites")).json()["sites"]] == ["dc1", "fra-1"]


async def test_any_naming_scheme_is_accepted(client):
    await login(client, "otto")
    for code in ("DEU-FRA-123123", "hq", "dc1", "eu.west.1", "site:42"):
        assert (await client.post("/api/sites", json={"code": code})).status_code == 201
    for bad in ("with space", "", "x" * 100, "-leading"):
        assert (await client.post("/api/sites", json={"code": bad})).status_code == 422


async def test_patching_an_unknown_site_is_404(client):
    await login(client, "otto")
    assert (await client.patch("/api/sites/nope", json={"name": "x"})).status_code == 404
    assert (await client.delete("/api/sites/nope")).status_code == 404


# --- assignment ---------------------------------------------------------------


async def _controller_device(store, uid: str, *, source: str = "unifi1", location: str = "default"):
    """A collected controller device: the only thing that can be placed by hand."""
    if await store.get_source(source) is None:
        await store.create_source(source, "unifi", {}, b"", True)
    await store.record_target_devices(source, "controller", [uid], {uid: (location, "Office")})


async def test_placing_a_device_writes_the_intent_and_says_when_it_lands(client, store):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "DEU-FRA-1"})
    await _controller_device(store, "dev:abc")

    r = await client.post("/api/sites/assign", json={"device_uid": "dev:abc", "site": "DEU-FRA-1"})
    assert r.status_code == 200
    assert r.json() == {
        "device_uid": "dev:abc",
        "site": "DEU-FRA-1",
        "detail": "the placement appears in the graph at the next collection run",
    }
    assert (await client.get("/api/sites/DEU-FRA-1/devices")).json()["devices"][0]["uid"] == "dev:abc"


async def test_a_group_device_cannot_be_placed_by_hand(client, store):
    """Its site is its group's. A group is reached at one place, so a device
    that belongs somewhere else belongs in another group."""
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    await store.create_source("edge", "vyos", {"site_code": "a"}, b"", True)
    await store.record_target_devices("edge", "10.0.0.1", ["dev:r1"], {})

    r = await client.post("/api/sites/assign", json={"device_uid": "dev:r1", "site": "a"})
    assert r.status_code == 409
    assert "its own group" in r.json()["error"]
    # nothing was written: the device is at site a because its group is
    assert await store.device_sites() == {}
    assert [d["uid"] for d in (await client.get("/api/sites/a/devices")).json()["devices"]] == ["dev:r1"]


async def test_a_device_no_collection_has_seen_cannot_be_placed(client):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    r = await client.post("/api/sites/assign", json={"device_uid": "dev:ghost", "site": "a"})
    assert r.status_code == 404
    assert "no collected device" in r.json()["error"]


async def test_a_device_belongs_to_exactly_one_site(client, store):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    await client.post("/api/sites", json={"code": "b"})
    await _controller_device(store, "dev:x")
    await client.post("/api/sites/assign", json={"device_uid": "dev:x", "site": "a"})
    await client.post("/api/sites/assign", json={"device_uid": "dev:x", "site": "b"})

    assert (await client.get("/api/sites/a/devices")).json()["devices"] == []
    assert [d["uid"] for d in (await client.get("/api/sites/b/devices")).json()["devices"]] == ["dev:x"]


async def test_clearing_a_placement_returns_the_device_to_its_reported_location(client, store):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    await client.post("/api/sites", json={"code": "b"})
    await _controller_device(store, "dev:x")
    await store.bind_location("unifi1", "default", "b")
    await client.post("/api/sites/assign", json={"device_uid": "dev:x", "site": "a"})

    r = await client.post("/api/sites/assign", json={"device_uid": "dev:x", "site": None})
    assert r.status_code == 200
    assert (await client.get("/api/sites/a/devices")).json()["devices"] == []
    assert [d["uid"] for d in (await client.get("/api/sites/b/devices")).json()["devices"]] == ["dev:x"]


async def test_assigning_to_an_unknown_site_is_404(client, store):
    await login(client, "otto")
    await _controller_device(store, "dev:x")
    r = await client.post("/api/sites/assign", json={"device_uid": "dev:x", "site": "ghost"})
    assert r.status_code == 404


async def test_deleting_a_site_releases_what_named_it_and_says_so(client, store):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    await store.create_source("edge", "vyos", {"site_code": "a"}, b"", True)
    await _controller_device(store, "dev:x")
    await store.bind_location("unifi1", "default", "a")
    await client.post("/api/sites/assign", json={"device_uid": "dev:x", "site": "a"})

    r = await client.delete("/api/sites/a")
    assert r.status_code == 200
    assert r.json() == {
        "groups": ["edge"],
        "locations": [{"source": "unifi1", "location_id": "default"}],
        "devices": ["dev:x"],
    }
    assert (await store.get_source("edge")).config["site_code"] == ""
    assert [loc.site for loc in await store.list_reported_locations()] == [None]
    assert await store.device_sites() == {}


async def test_the_site_list_says_what_a_delete_would_release(client, store):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    await store.create_source("edge", "vyos", {"site_code": "a"}, b"", True)
    await _controller_device(store, "dev:x")
    await store.bind_location("unifi1", "default", "a")
    await client.post("/api/sites/assign", json={"device_uid": "dev:x", "site": "a"})

    site = (await client.get("/api/sites")).json()["sites"][0]
    assert (site["group_count"], site["location_count"], site["placed_count"]) == (1, 1, 1)


async def test_device_count_reflects_placement(client, store):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    for uid in ("dev:1", "dev:2"):
        await _controller_device(store, uid, source=f"unifi{uid[-1]}")
        await client.post("/api/sites/assign", json={"device_uid": uid, "site": "a"})
    assert (await client.get("/api/sites")).json()["sites"][0]["device_count"] == 2


async def test_a_placed_device_with_no_graph_node_is_listed(client, store):
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    await _controller_device(store, "dev:ghost")
    await client.post("/api/sites/assign", json={"device_uid": "dev:ghost", "site": "a"})
    devices = (await client.get("/api/sites/a/devices")).json()["devices"]
    assert [d["uid"] for d in devices] == ["dev:ghost"]


# --- site-to-site reachability -------------------------------------------------


async def test_site_trace_needs_both_sites_to_exist(client):
    await login(client, "vera")
    await client.post("/api/sites", json={"code": "a"})  # 403 for a viewer; create as otto
    await login(client, "otto")
    await client.post("/api/sites", json={"code": "a"})
    r = await client.post("/api/sites/trace", json={"src_site": "a", "dst_site": "ghost"})
    assert r.status_code == 404


async def test_site_trace_says_so_when_a_site_has_no_prefixes(client):
    await login(client, "otto")
    for code in ("a", "b"):
        await client.post("/api/sites", json={"code": code})
    r = await client.post("/api/sites/trace", json={"src_site": "a", "dst_site": "b"})
    body = r.json()
    assert body["pairs"] == []
    assert body["note"] == "no prefixes found behind a"


async def test_site_trace_walks_every_prefix_pair(client, monkeypatch):
    prefixes = {
        "a": [SitePrefix("10.1.0.0/24", "pfx:a1", "vrf:a1"), SitePrefix("10.2.0.0/24", "pfx:a2", "vrf:a2")],
        "b": [SitePrefix("10.9.0.0/24", "pfx:b", "vrf:b")],
    }
    monkeypatch.setattr(
        sites_routes, "_site_prefix_pair", lambda request, src, dst: (RUN, prefixes[src], prefixes[dst])
    )
    monkeypatch.setattr(sites_routes.dbmod, "session", lambda settings: _FakeSession())
    contexts = []

    def fake_trace(
        session, src, dst, port=None, proto=None, gateways=None, rib=None, src_context=None, dst_context=None
    ):
        contexts.append((src_context, dst_context))
        return {"verdict": f"{src} -> {dst}", "legs": [{"blocked": False}]}

    import hst.path as path_engine

    monkeypatch.setattr(path_engine, "trace", fake_trace)

    await login(client, "otto")
    for code in ("a", "b"):
        await client.post("/api/sites", json={"code": code})

    body = (await client.post("/api/sites/trace", json={"src_site": "a", "dst_site": "b"})).json()
    assert body["total_pairs"] == 2
    assert body["truncated"] is False
    assert [p["detail"] for p in body["pairs"]] == [
        "10.1.0.0/24 -> 10.9.0.0/24",
        "10.2.0.0/24 -> 10.9.0.0/24",
    ]
    # each prefix is traced in its own context, and the answer names the run
    assert contexts == [("vrf:a1", "vrf:b"), ("vrf:a2", "vrf:b")]
    assert [(p["src_context"], p["dst_context"]) for p in body["pairs"]] == contexts
    assert body["snapshot"] is None


async def test_site_trace_reports_truncation(client, monkeypatch):
    many = [SitePrefix(f"10.{i}.0.0/24", f"pfx:{i}", None) for i in range(20)]
    other = [SitePrefix(f"10.{i}.1.0/24", f"pfx:o{i}", None) for i in range(20)]
    monkeypatch.setattr(
        sites_routes,
        "_site_prefix_pair",
        lambda request, src, dst: (RUN, many, other),
    )
    monkeypatch.setattr(sites_routes.dbmod, "session", lambda settings: _FakeSession())

    import hst.path as path_engine

    monkeypatch.setattr(
        path_engine,
        "trace",
        lambda session, src, dst, port=None, proto=None, gateways=None, rib=None, **contexts: {
            "verdict": "ok",
            "legs": [],
        },
    )
    await login(client, "otto")
    for code in ("a", "b"):
        await client.post("/api/sites", json={"code": code})

    body = (await client.post("/api/sites/trace", json={"src_site": "a", "dst_site": "b"})).json()
    assert body["total_pairs"] == 400
    assert body["truncated"] is True
    assert len(body["pairs"]) == sites_routes.MAX_PAIRS


class _FakeResult:
    def data(self):
        return []


class _FakeTx:
    def run(self, *a, **k):
        return _FakeResult()


class _FakeSession:
    """A context manager plus `execute_read`."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute_read(self, work):
        return work(_FakeTx())


class _RecordingTx:
    def __init__(self, sink):
        self._sink = sink

    def run(self, query, **params):
        self._sink.append(params)
        return []


class _RecordingSession:
    """Like `_FakeSession`, but keeps the params each query ran with."""

    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute_read(self, work):
        return work(_RecordingTx(self.calls))


def test_site_prefixes_queries_the_uid_site_grammar_collectors_use(monkeypatch):
    from types import SimpleNamespace

    from hst.core import uid as uidmod

    recording = _RecordingSession()
    monkeypatch.setattr(sites_routes.dbmod, "session", lambda settings: recording)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=None)))

    _real_site_prefix_pair(request, "DEU-FRA-123123", "other")

    assert recording.calls[0]["site"] == uidmod.site("DEU-FRA-123123")
    assert recording.calls[0]["site"] == "site:deu-fra-123123"


# --- every reader pins: the device listings read from the resolved pointer's run,
# even between two label-move steps of a concurrent refresh ----------------------


class _PinRecordingSession:
    """Answers the pointer read plus one managed read, recording the params of
    each."""

    def __init__(self, current=None):
        self._current = current
        self.pointer_calls = 0
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        # the autocommit pointer read core.cycle.current_ts_or_none issues
        self.pointer_calls += 1
        rows = [{"current": self._current}] if self._current is not None else []
        return _FakeDataResult(rows)

    def execute_read(self, work):
        return work(_RecordingTx(self.calls))


class _FakeDataResult:
    def __init__(self, rows):
        self._rows = rows

    def data(self):
        return self._rows


def _request_with(settings=None):
    from types import SimpleNamespace

    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))


def test_collected_devices_resolves_the_pointer_once_and_pins_the_read(monkeypatch):
    session = _PinRecordingSession(current=4242)
    monkeypatch.setattr(sites_routes.dbmod, "session", lambda settings: session)

    sites_routes._collected_devices(_request_with())

    assert session.pointer_calls == 1
    assert session.calls[0]["snap"] == 4242


def test_collected_devices_falls_back_to_the_live_sentinel_with_no_pointer(monkeypatch):
    session = _PinRecordingSession(current=None)
    monkeypatch.setattr(sites_routes.dbmod, "session", lambda settings: session)

    sites_routes._collected_devices(_request_with())

    assert session.calls[0]["snap"] == "live"


def test_device_details_resolves_the_pointer_once_and_pins_the_read(monkeypatch):
    session = _PinRecordingSession(current=4242)
    monkeypatch.setattr(sites_routes.dbmod, "session", lambda settings: session)

    _real_device_details(_request_with(), ["dev:a1"])

    assert session.pointer_calls == 1
    assert session.calls[0]["snap"] == 4242
    assert session.calls[0]["uids"] == ["dev:a1"]


def test_the_prefixes_of_both_sites_come_from_one_resolution_of_the_pointer(monkeypatch):
    session = _PinRecordingSession(current=4242)
    monkeypatch.setattr(sites_routes.dbmod, "session", lambda settings: session)

    snapshot, src, dst = _real_site_prefix_pair(_request_with(), "home", "away")

    assert session.pointer_calls == 1
    assert snapshot.cts == 4242
    assert [call["snap"] for call in session.calls] == [4242, 4242]
    assert (src, dst) == ([], [])


async def test_a_prefix_held_at_both_sites_is_labelled_not_traced(client, monkeypatch):
    """A cidr both sites hold (a templated LAN) traces inside one site; its pairs are open
    with the reason, and the other pairs trace."""
    rows = {
        "a": [
            SitePrefix("192.168.1.0/24", "pfx:a-lan", "vrf:a"),
            SitePrefix("10.1.0.0/24", "pfx:a", "vrf:a"),
        ],
        "b": [
            SitePrefix("192.168.1.0/24", "pfx:b-lan", "vrf:b"),
            SitePrefix("10.9.0.0/24", "pfx:b", "vrf:b"),
        ],
    }
    monkeypatch.setattr(
        sites_routes, "_site_prefix_pair", lambda request, src, dst: (RUN, rows[src], rows[dst])
    )
    monkeypatch.setattr(sites_routes.dbmod, "session", lambda settings: _FakeSession())
    traced = []

    def fake_trace(session, src, dst, **kwargs):
        traced.append((src, dst))
        return {"verdict": "forwarded", "legs": [{"verdict": "forwarded"}]}

    import hst.path as path_engine

    monkeypatch.setattr(path_engine, "trace", fake_trace)
    await login(client, "otto")
    for code in ("a", "b"):
        await client.post("/api/sites", json={"code": code})

    body = (await client.post("/api/sites/trace", json={"src_site": "a", "dst_site": "b"})).json()
    assert traced == [("10.1.0.0/24", "10.9.0.0/24")]
    answers = {(p["src"], p["dst"]): p["result"]["answer"] for p in body["pairs"]}
    assert answers == {
        ("192.168.1.0/24", "192.168.1.0/24"): "open",
        ("192.168.1.0/24", "10.9.0.0/24"): "open",
        ("10.1.0.0/24", "192.168.1.0/24"): "open",
        ("10.1.0.0/24", "10.9.0.0/24"): "true",
    }
    open_pair = next(p for p in body["pairs"] if p["dst"] == "192.168.1.0/24" and p["src"] == "10.1.0.0/24")
    assert open_pair["result"]["missing"][0]["code"] == "prefix-at-both-sites"
    assert open_pair["blocked"] is None


# --- reported locations -------------------------------------------------------


async def test_locations_list_what_the_orchestrators_named_and_bind_one(client, store):
    """An orchestrator names places in its own terms. The operator binds an id to
    a site; nothing here matches on the name."""
    await login(client, "otto")
    await store.create_source("unifi1", "unifi", {}, b"", True)
    await store.create_site("dcber1", "Berlin", "")
    await store.record_target_devices(
        "unifi1",
        "controller",
        ["dev:a", "dev:b"],
        {"dev:a": ("default", "Office"), "dev:b": ("branch", "Branch office")},
    )

    body = (await client.get("/api/locations")).json()["locations"]
    assert [(x["location_id"], x["name"], x["site"], x["device_count"]) for x in body] == [
        ("branch", "Branch office", None, 1),
        ("default", "Office", None, 1),
    ]

    r = await client.patch("/api/locations/unifi1/default", json={"site": "dcber1"})
    assert r.status_code == 200, r.text
    assert r.json()["site"] == "dcber1"
    assert "next collection run" in r.json()["detail"]

    body = (await client.get("/api/locations")).json()["locations"]
    assert {x["location_id"]: x["site"] for x in body} == {"branch": None, "default": "dcber1"}


async def test_binding_an_unknown_location_or_site_is_404(client, store):
    await login(client, "otto")
    await store.create_source("unifi1", "unifi", {}, b"", True)
    await store.create_site("dcber1", "Berlin", "")
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Office")})

    assert (await client.patch("/api/locations/unifi1/nope", json={"site": "dcber1"})).status_code == 404
    r = await client.patch("/api/locations/unifi1/default", json={"site": "no-such-site"})
    assert r.status_code == 404
    assert "no such site" in r.json()["error"]


async def test_a_viewer_reads_locations_but_cannot_bind(client, store):
    await login(client, "vera")
    await store.create_source("unifi1", "unifi", {}, b"", True)
    await store.record_target_devices("unifi1", "controller", ["dev:a"], {"dev:a": ("default", "Office")})

    assert (await client.get("/api/locations")).status_code == 200
    assert (await client.patch("/api/locations/unifi1/default", json={"site": None})).status_code == 403


async def test_the_device_list_says_where_each_device_sits_and_who_may_move_it(client, store, monkeypatch):
    """A group device follows its group and offers no picker. A controller
    device offers one, and says whether a person has already used it."""
    await login(client, "otto")
    await store.create_site("dcber1", "Berlin", "")
    await store.create_site("other", "Other", "")
    await store.create_source("edge", "vyos", {"site_code": "dcber1"}, b"", True)
    await store.create_source("unifi1", "unifi", {}, b"", True)
    await store.record_target_devices("edge", "10.0.0.1", ["dev:core1"], {})
    await store.record_target_devices(
        "unifi1",
        "controller",
        ["dev:ap1", "dev:ap2"],
        {"dev:ap1": ("default", "Office"), "dev:ap2": ("default", "Office")},
    )
    await store.bind_location("unifi1", "default", "dcber1")
    await store.assign_device("dev:ap2", "other")

    monkeypatch.setattr(
        sites_routes,
        "_collected_devices",
        lambda request: [
            {"uid": u, "hostname": u.split(":")[-1], "platform": "x", "graph_site": None}
            for u in ("dev:core1", "dev:ap1", "dev:ap2", "dev:orphan")
        ],
    )
    body = (await client.get("/api/sites/devices")).json()["devices"]
    seen = {d["uid"]: (d["site"], d["hand_placed"], d["can_place"], d["source"]) for d in body}

    assert seen["dev:core1"] == ("dcber1", False, False, "edge")
    assert seen["dev:ap1"] == ("dcber1", False, True, "unifi1")
    assert seen["dev:ap2"] == ("other", True, True, "unifi1")
    # nothing collected it through a source, so nothing can place it either
    assert seen["dev:orphan"] == (None, False, False, "")


async def test_two_orchestrators_reporting_one_location_id_keep_their_own_names(client, store, monkeypatch):
    await login(client, "otto")
    await store.create_source("unifi-north", "unifi", {}, b"", True)
    await store.create_source("unifi-south", "unifi", {}, b"", True)
    await store.record_target_devices(
        "unifi-north", "controller", ["dev:a"], {"dev:a": ("default", "Head office")}
    )
    await store.record_target_devices("unifi-south", "controller", ["dev:b"], {"dev:b": ("default", "Depot")})

    monkeypatch.setattr(
        sites_routes,
        "_collected_devices",
        lambda request: [
            {"uid": u, "hostname": u.split(":")[-1], "platform": "x", "graph_site": None}
            for u in ("dev:a", "dev:b")
        ],
    )
    body = (await client.get("/api/sites/devices")).json()["devices"]
    seen = {d["uid"]: (d["source"], d["location_id"], d["location_name"]) for d in body}

    assert seen["dev:a"] == ("unifi-north", "default", "Head office")
    assert seen["dev:b"] == ("unifi-south", "default", "Depot")
