"""The overlay's route table is read one VRF at a time (`hst.app.fw_overlay_read._RouteTable`)."""

from __future__ import annotations

import json
import re
import weakref
from typing import Any

import pytest
from tests.support import fw_overlay_golden as golden

from hst.app import fw_overlay_read
from hst.path.addrsets import _intervals, _subtract
from hst.simul.fw_overlay import DeniedAddresses

GOLDEN = json.loads(golden.GOLDEN.read_text())["cases"]


def test_the_golden_file_covers_every_case():
    assert sorted(GOLDEN) == sorted(golden.CASES)


@pytest.mark.parametrize("name", sorted(golden.CASES))
def test_the_answer_is_the_recorded_one(name):
    summary = golden.summarize(golden.run_case(golden.CASES[name]()))
    expected = dict(GOLDEN[name])
    stated, recorded = summary.pop(golden.REWORDED), expected.pop(golden.REWORDED)
    assert summary == expected
    if recorded is None:
        assert stated is None
    else:
        count = re.match(r"(\d+) recorded routes", recorded)
        assert count is not None
        listed = f"{fw_overlay_read._MAX_ROUTE_ROWS} of them are listed"
        assert stated == f"{count.group(1)} recorded routes lose a denied next hop; {listed}"


class _Table(list):
    """A side-store table a weak reference can watch."""


class _Row(dict):
    """A side-store row a weak reference can watch."""


class _WatchedRib(golden.FakeRib):
    """Records, at every read, how many tables read before it are still alive."""

    def __init__(self, rows: dict[tuple[str, str | None], list[dict[str, Any]]]) -> None:
        super().__init__(rows)
        self.tables: list[weakref.ref[_Table]] = []
        self.rows_out: list[weakref.ref[_Row]] = []
        self.alive_at_read: list[int] = []

    def routes(
        self, device_uid: str, context_uid: str | None, *, legacy_vrf: str | None = None
    ) -> list[dict[str, Any]]:
        self.alive_at_read.append(sum(1 for ref in self.tables if ref() is not None))
        rows = [_Row(r) for r in super().routes(device_uid, context_uid, legacy_vrf=legacy_vrf)]
        self.rows_out += [weakref.ref(r) for r in rows]
        table = _Table(rows)
        self.tables.append(weakref.ref(table))
        return table


@pytest.mark.parametrize("name", ["merge", "odd-prefixes", "generated-3", "generated-8", "wide-detail"])
def test_each_side_store_table_is_dropped_before_the_next_is_read(name):
    case = golden.CASES[name]()
    assert case.rib is not None
    rib = _WatchedRib(case.rib)
    body = golden.run_case(case, rib=rib)
    assert golden.digest(body) == GOLDEN[name]["digest"]
    assert rib.alive_at_read and set(rib.alive_at_read) == {0}
    # what the answer keeps is its own copy: no row the store handed out lives on
    assert rib.rows_out and all(ref() is None for ref in rib.rows_out)


def test_a_vrf_with_no_denied_next_hop_is_read_once():
    """The first level reads every table once, and a second time only for a
    VRF where a denied next hop is recorded, for the rest of that prefix's
    next hops."""
    denied_vrf = "vrf:dev:x:iosxe:edge1:default"
    quiet_vrf = "vrf:dev:x:iosxe:edge2:default"
    case = golden.Case(
        graph=[],
        intents=[golden.DENY_TO],
        vrf_devices=[golden._vd(denied_vrf, "dev:x:edge1"), golden._vd(quiet_vrf, "dev:x:edge2")],
        rib={
            ("dev:x:edge1", denied_vrf): [
                golden._rib_row("198.51.100.0/24", "10.1.1.1"),
                golden._rib_row("198.51.100.0/24", golden.DENIED_V4[0]),
                golden._rib_row("198.51.101.0/24", "10.1.1.1"),
            ],
            ("dev:x:edge2", quiet_vrf): [golden._rib_row(f"203.0.{i}.0/24", "10.2.2.2") for i in range(200)],
        },
        flows=[{"src": "10.0.0.5", "dst": "198.51.100.1"}],
    )
    rib = golden.FakeRib(case.rib or {})
    body = golden.run_case(case, rib=rib)
    assert rib.calls == [("dev:x:edge1", denied_vrf), ("dev:x:edge2", quiet_vrf), ("dev:x:edge1", denied_vrf)]
    [vrf] = body["routing_consequence"]["next_hop_withdrawal"]["vrfs"]
    [prefix] = vrf["prefixes"]
    assert prefix["prefix"] == "198.51.100.0/24"
    assert [n["next_hop"] for n in prefix["next_hops_before"]] == ["10.1.1.1", golden.DENIED_V4[0]]
    assert [n["next_hop"] for n in prefix["next_hops_after"]] == ["10.1.1.1"]


def test_the_walk_past_the_first_level_reads_only_a_vrf_that_strands_a_prefix():
    stranding_vrf = "vrf:dev:x:iosxe:edge1:default"
    keeping_vrf = "vrf:dev:x:iosxe:edge2:default"
    case = golden.Case(
        graph=[],
        intents=[golden.DENY_TO],
        vrf_devices=[golden._vd(stranding_vrf, "dev:x:edge1"), golden._vd(keeping_vrf, "dev:x:edge2")],
        rib={
            ("dev:x:edge1", stranding_vrf): [
                golden._rib_row("10.10.0.0/16", golden.DENIED_V4[0]),
                golden._rib_row("172.16.0.0/16", "10.10.0.1"),
            ],
            ("dev:x:edge2", keeping_vrf): [
                golden._rib_row("10.10.0.0/16", golden.DENIED_V4[0]),
                golden._rib_row("10.10.0.0/16", "10.3.3.3"),
                golden._rib_row("172.16.0.0/16", "10.10.0.1"),
            ],
        },
        depth=3,
    )
    rib = golden.FakeRib(case.rib or {})
    routing = golden.run_case(case, rib=rib)["routing_consequence"]
    edge1, edge2 = ("dev:x:edge1", stranding_vrf), ("dev:x:edge2", keeping_vrf)
    # one read each, the second read of both for their denied prefix, then
    # level 2 reads the next hops of the one VRF that stranded a prefix at
    # level 1 and the rows of the prefix it reaches; level 3 reads the next
    # hops again for the prefix level 2 stranded, and finds nothing more
    assert rib.calls == [edge1, edge2, edge1, edge2, edge1, edge1, edge1]
    vrfs = routing["next_hop_withdrawal"]["vrfs"]
    by_vrf = {v["context_uid"]: [p["prefix"] for p in v["prefixes"]] for v in vrfs}
    assert by_vrf == {stranding_vrf: ["10.10.0.0/16", "172.16.0.0/16"], keeping_vrf: ["10.10.0.0/16"]}
    assert routing["walk"]["levels_walked"] == 2


@pytest.mark.parametrize("name", sorted(golden.CASES))
def test_the_next_hops_of_a_vrf_are_its_merged_rows_next_hops(name, monkeypatch):
    """What the walk tests (`next_hops`) is the next hop of each row the merge
    keeps, prefix for prefix and route for route, so the row indexes of its
    hits point into the rows read for them afterwards."""
    case = golden.CASES[name]()
    answers = {
        fw_overlay_read._LEARNED_NEXT_HOPS: case.graph,
        fw_overlay_read._VRF_DEVICES: case.vrf_devices,
    }

    def read(session: Any, query: str, **params: Any) -> Any:
        routed = golden.answer_route_reads(case.graph, query, params)
        return routed if routed is not None else answers.get(query, [])

    monkeypatch.setattr(fw_overlay_read.pathmod, "_read", read)
    rib = golden.FakeRib(case.rib) if case.rib is not None else None
    table = fw_overlay_read._RouteTable(object(), rib, DeniedAddresses(to_specs=list(golden.DENIED_V4)))
    contexts = sorted({str(row.get("context_uid") or "") for row in (*case.graph, *case.vrf_devices)})
    assert contexts
    for context in contexts:
        rows = table._merged(context, bool)
        hops = table.next_hops(context)
        assert list(hops) == list(rows)
        for prefix, entries in rows.items():
            tested = [hop if isinstance(hop, str) else hop[0] for hop in hops[prefix]]
            assert tested == [str(row.get("next_hop") or "").strip() for row in entries]


def test_the_walk_builds_rows_only_for_the_prefixes_it_reaches(monkeypatch):
    """Past the first level the walk tests the next hops of a VRF's whole
    table, and builds rows for the prefixes a level reaches alone."""
    vrf = "vrf:dev:x:iosxe:edge1:default"
    case = golden.Case(
        graph=[],
        intents=[golden.DENY_TO],
        vrf_devices=[golden._vd(vrf, "dev:x:edge1")],
        rib={
            ("dev:x:edge1", vrf): [
                golden._rib_row("10.10.10.1/32", golden.DENIED_V4[0]),
                golden._rib_row("10.9.0.0/16", "10.10.10.1"),
                *(golden._rib_row(f"11.0.{i}.0/24", "172.16.0.1") for i in range(100)),
            ]
        },
        depth=3,
    )
    built: list[str] = []
    merged = fw_overlay_read._RouteTable._merged

    def watched(self: Any, context: str, wanted: Any) -> Any:
        def recorded(prefix: str) -> bool:
            if wanted(prefix):
                built.append(prefix)
                return True
            return False

        return merged(self, context, recorded)

    monkeypatch.setattr(fw_overlay_read._RouteTable, "_merged", watched)
    routing = golden.run_case(case)["routing_consequence"]
    # level 1 builds the rows of the denied prefix, level 2 those of the
    # prefix that resolves only through it, and level 3 reaches nothing
    assert built == ["10.10.10.1/32", "10.9.0.0/16"]
    [answer] = routing["next_hop_withdrawal"]["vrfs"]
    assert [p["prefix"] for p in answer["prefixes"]] == ["10.10.10.1/32", "10.9.0.0/16"]
    assert routing["walk"]["levels_walked"] == 2


def _covers(prefix: str, address: str) -> bool:
    """The interval test the index stands in for."""
    where = _intervals([address])
    covering = _intervals([prefix])
    return bool(where) and bool(covering) and not _subtract(where, covering)


PREFIXES = [
    "0.0.0.0/0",
    "10.0.0.0/8",
    "10.1.0.0/16",
    "10.1.2.3/16",
    "10.1.2.0/24",
    "10.1.2.0/25",
    "10.1.2.128/25",
    "10.1.2.7/32",
    "10.1.2.7",
    "10.1.2.0-10.1.2.99",
    "10.1.2.50-10.1.3.10",
    "10.1.9.9-10.1.9.1",
    "192.168.0.0/16",
    "::/0",
    "2001:db8::/32",
    "2001:db8:1::/48",
    "2001:db8:1::5",
    "2001:db8:1::-2001:db8:1::ff",
    "::ffff:10.1.2.0/120",
    "not-a-prefix",
    "",
]

ADDRESSES = [
    "10.1.2.7",
    "10.1.2.0",
    "10.1.2.255",
    "10.1.2.99",
    "10.1.2.100",
    "10.1.3.5",
    "10.200.0.1",
    "11.0.0.1",
    "192.168.200.200",
    "10.1.2.0/26",
    "10.1.2.40-10.1.2.60",
    "2001:db8:1::5",
    "2001:db8:1::1ff",
    "2001:db9::1",
    "::ffff:10.1.2.7",
    "not-an-address",
    "",
]


@pytest.mark.parametrize("address", ADDRESSES)
def test_the_prefix_index_finds_what_the_interval_test_finds(address):
    index = fw_overlay_read._PrefixIndex(PREFIXES)
    assert index.covering(address) == {p for p in PREFIXES if _covers(p, address)}
    # the memo answers the second lookup the same way
    assert index.covering(address) == {p for p in PREFIXES if _covers(p, address)}


def test_a_next_hop_resolves_only_through_stranded_prefixes_its_own_excluded():
    index = fw_overlay_read._PrefixIndex(["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"])
    stranded = {"10.1.0.0/16": 1, "10.1.2.0/24": 1}
    # 10.0.0.0/8 still holds a next hop
    assert index.resolves_only_through("10.1.2.9", stranded, own="10.9.0.0/16") == []
    assert index.resolves_only_through("10.1.2.9", {**stranded, "10.0.0.0/8": 1}, own="10.9.0.0/16") == [
        "10.0.0.0/8",
        "10.1.0.0/16",
        "10.1.2.0/24",
    ]
    # a route's own prefix does not resolve its next hop
    own_excluded = index.resolves_only_through("10.1.2.9", stranded, own="10.0.0.0/8")
    assert own_excluded == ["10.1.0.0/16", "10.1.2.0/24"]
    assert index.resolves_only_through("172.16.0.1", stranded, own="10.0.0.0/8") == []
    assert index.resolves_only_through("", stranded, own="10.0.0.0/8") == []


def test_no_route_edge_is_read_when_no_next_hop_is_denied(monkeypatch):
    """With no recorded next hop in the denied set, no prefix holds a
    hit, so the first-level route read is not made at all."""
    graph = [
        {"kind": "STATIC_ROUTE", "prefix": "10.9.0.0/16", "next_hop": "172.16.0.1", "context_uid": "vrf:a"}
    ]
    queries: list[str] = []

    def read(session: Any, query: str, **params: Any) -> Any:
        queries.append(query)
        routed = golden.answer_route_reads(graph, query, params)
        return routed if routed is not None else []

    monkeypatch.setattr(fw_overlay_read.pathmod, "_read", read)
    table = fw_overlay_read._RouteTable(object(), None, DeniedAddresses(to_specs=list(golden.DENIED_V4)))
    assert fw_overlay_read._LEARNED_NEXT_HOPS not in queries
    assert table.contexts == {"vrf:a"}
    assert table.relevant == []
