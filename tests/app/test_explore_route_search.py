"""GET /api/explore/route-search: an address looked up in every route table."""

from types import SimpleNamespace

from tests.app.conftest import login
from tests.app.test_explore_api import install, table

import hst.app.routes.explore as explore
from hst.core.ribsource import RoutePage

ROW = {
    "device_uid": "dev:fdo2335abc",
    "vrf": "hosting",
    "context_uid": "vrf:dev:fdo2335abc:hosting",
    "prefix": "10.24.0.0/16",
    "next_hop": "10.0.0.2",
    "interface": "Eth1/1",
    "protocol": "bgp",
    "metric": 0,
    "prefixlen": 16,
}


class _Rib:
    def __init__(self) -> None:
        self.asked: list[tuple[str, int]] = []
        self.closed = False

    def search_routes(self, text, *, limit):
        self.asked.append((text, limit))
        return RoutePage(total=1, rows=[ROW], protocols=[], run_id=None)

    def close(self) -> None:
        self.closed = True


async def test_routes_of_every_table_come_back_with_the_device_hostname(client, monkeypatch):
    await login(client, "vera")
    rib = _Rib()
    monkeypatch.setattr(explore, "_snapshot", lambda request: SimpleNamespace(cts=1700))
    monkeypatch.setattr(explore.ribsource, "for_snapshot", lambda snapshot: rib)
    install(
        monkeypatch,
        [
            (
                "RETURN d.uid AS uid, d.hostname AS hostname",
                lambda p: table(["uid", "hostname"], [[p["uids"][0], "leaf-a"]]),
            )
        ],
    )

    r = await client.get("/api/explore/route-search", params={"q": " 10.24.0.0 "})

    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["device"] == "leaf-a"
    assert body["items"][0]["prefix"] == "10.24.0.0/16"
    assert rib.asked == [("10.24.0.0", 100)] and rib.closed


async def test_text_that_is_no_address_reads_no_route_table(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(
        explore.ribsource, "for_snapshot", lambda snapshot: (_ for _ in ()).throw(AssertionError)
    )

    r = await client.get("/api/explore/route-search", params={"q": "fw-fra-01"})

    assert r.json() == {"query": "fw-fra-01", "total": 0, "items": []}


def _hostnames_of_two_runs(p):
    """The graph keeps one copy of a device per retained run. Unpinned, the
    query answers both copies, and the older hostname comes last."""
    uid = p["uids"][0]
    if p.get("snap") == 1700:
        return table(["uid", "hostname"], [[uid, "leaf-new"]])
    return table(["uid", "hostname"], [[uid, "leaf-new"], [uid, "leaf-old"]])


async def test_the_hostname_comes_from_the_run_the_routes_were_read_for(client, monkeypatch):
    await login(client, "vera")
    rib = _Rib()
    resolved: list[int] = []

    def snapshot(request):
        resolved.append(1700)
        return SimpleNamespace(cts=1700)

    monkeypatch.setattr(explore, "_snapshot", snapshot)
    monkeypatch.setattr(explore.ribsource, "for_snapshot", lambda snapshot: rib)
    fake = install(monkeypatch, [("RETURN d.uid AS uid, d.hostname AS hostname", _hostnames_of_two_runs)])

    body = (await client.get("/api/explore/route-search", params={"q": "10.24.0.0"})).json()

    assert body["items"][0]["device"] == "leaf-new"
    cypher, params, _ = fake.calls[0]
    assert "$snap" in cypher and "NOT d:Retired" in cypher
    assert params["snap"] == 1700 and params["uids"] == ["dev:fdo2335abc"]
    assert resolved == [1700], "the request resolves the snapshot once"


async def test_the_hostname_lookup_before_the_first_run_binds_the_unpinned_value(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(explore, "_snapshot", lambda request: SimpleNamespace(cts=None))
    monkeypatch.setattr(explore.ribsource, "for_snapshot", lambda snapshot: _Rib())
    fake = install(
        monkeypatch,
        [("RETURN d.uid AS uid", lambda p: table(["uid", "hostname"], [[p["uids"][0], "leaf-a"]]))],
    )

    await client.get("/api/explore/route-search", params={"q": "10.24.0.0"})

    assert fake.calls[0][1]["snap"] == explore.LIVE_SNAP
