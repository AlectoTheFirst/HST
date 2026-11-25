"""The snapshot comparison streams each side through a bounded external sort (core/diff.py)."""

from __future__ import annotations

import json
import random
import tracemalloc
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest
from tests.support import finalize_reference as ref
from tests.support.finalize_reference import _owner_of as scanned_owner_of
from tests.support.finalize_reference import reference_diff

from hst.core import cycle as cyclemod
from hst.core import diff as diffmod
from hst.core.diff import diff_snapshots

A, B = 1000, 2000


class _Result:
    """A driver result: iterated lazily by the streamed reads, `data()` for
    the reference, which materializes as the driver's `data()` does."""

    def __init__(self, rows: Callable[[], Iterable[dict[str, Any]]]) -> None:
        self._rows = rows

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self._rows())

    def data(self) -> list[dict[str, Any]]:
        return list(self._rows())


class _Graph:
    """Two runs' nodes and relationships, answering the comparison's reads.

    `reverse` returns every read's rows in the opposite order, which is the
    freedom the database has: no read the comparison issues orders its rows.
    """

    def __init__(self, nodes: dict[int, list[dict]], rels: dict[int, list[dict]], reverse: bool = False):
        self.nodes = nodes
        self.rels = rels
        self.reverse = reverse
        self.queries: list[str] = []

    def answer(self, query: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        self.queries.append(query)
        snap = params["snap"]
        nodes, rels = self.nodes.get(snap, []), self.rels.get(snap, [])
        if query == diffmod._ALL_NODES:
            rows = list(nodes)
        elif query == diffmod._ALL_RELS:
            rows = list(rels)
        elif query == ref.NODE_LABEL_SETS:
            rows = [{"labels": list(t)} for t in dict.fromkeys(tuple(n["labels"]) for n in nodes)]
        elif query == ref.NODES_FOR_LABEL:
            rows = [n for n in nodes if params["label"] in n["labels"]]
        elif query == ref.NODES_NO_DOMAIN_LABEL:
            rows = [n for n in nodes if all(label in params["reserved"] for label in n["labels"])]
        elif query == ref.REL_TYPES:
            rows = [{"t": t} for t in dict.fromkeys(r["t"] for r in rels)]
        elif query == ref.RELS_FOR_TYPE:
            rows = [r for r in rels if r["t"] == params["type"]]
        else:
            raise AssertionError(f"unexpected query: {query}")
        return rows[::-1] if self.reverse else rows


class _Tx:
    def __init__(self, graph: Any) -> None:
        self._graph = graph

    def run(self, query: str, **params: Any) -> _Result:
        return _Result(lambda: self._graph.answer(query, params))


class _Session:
    def __init__(self, graph: Any) -> None:
        self._graph = graph

    def execute_read(self, work: Any) -> Any:
        return work(_Tx(self._graph))


@dataclass(frozen=True)
class _Device:
    source: str
    host: str
    outcome: str
    fetch_ts_ms: int | None = None
    fetch_started_ms: int | None = None
    carried: bool = False
    tables: dict[str, Any] = field(default_factory=dict)
    scope: str = ""


DOMAIN = {"Device": "Phys", "Interface": "L2", "Prefix": "L3", "FwRule": "Policy"}
HOSTS = ("h0", "h1", "h2", "h3", "h4")
SOURCES = ("edge", "core")

# B's manifest, recording no scopes, so every entry is matched by its host:
# h0 to h2 answered or not, h3 has two entries (no single owner), h4 none,
# and `core` carries a controller entry with no host, which owns every `core`
# object whose scope names no other entry of `core`.
DEVICES_B = (
    _Device("edge", "h0", "collected", fetch_ts_ms=1900, fetch_started_ms=1950),
    _Device("edge", "h1", "failed", fetch_ts_ms=1800),
    _Device("edge", "h2", "carried", fetch_ts_ms=1700, fetch_started_ms=1750),
    _Device("edge", "h3", "collected", fetch_ts_ms=1600),
    _Device("edge", "h3", "collected", fetch_ts_ms=1601),
    _Device("core", "", "collected", fetch_ts_ms=1500),
    _Device("core", "h1", "failed", fetch_ts_ms=1400),
)


def _node(rng: random.Random, uid: str, labels: list[str]) -> dict[str, Any]:
    source = rng.choice(SOURCES)
    props: dict[str, Any] = {
        "uid": uid,
        "name": None if rng.random() < 0.05 else f"name-{uid}",
        "role": rng.choice(("router", "switch", "firewall")),
        "mtu": rng.choice((1500, 9000, 1500.0)),
        "tags": rng.choice((["a"], ["a", "b"], [])),
        "_scope": rng.choice((f"vyos:{rng.choice(HOSTS)}", "apic:fab1", "")),
        "_sources": rng.choice(([source], [source, source], [], ["edge", "core"])),
        "collected_at": rng.randrange(100, 900),
        "_run_id": f"run-{rng.randrange(10**6)}",
        "carried": rng.random() < 0.3,
    }
    if props["name"] is None:
        del props["name"]
    if rng.random() < 0.2:
        props["carried_reason"] = rng.choice(cyclemod.CARRY_REASONS)
        props["last_seen_ts"] = props["collected_at"]
    if rng.random() < 0.25:
        left, right = rng.choice((("leaf", "router"), ("router", "router"), ("spine", "leaf")))
        props["_assert.role"] = [f'apic/fab1="{left}"', f'nxos/edge="{right}"']
    if rng.random() < 0.1:
        props["_assert.mtu"] = ['apic/fab1="1500"', 'nxos/edge="9000"']
    return {"uid": uid, "labels": labels, "props": props}


def _labels(rng: random.Random, label: str) -> list[str]:
    roll = rng.random()
    if roll < 0.05:
        return ["Obj"]  # no domain label at all
    return ["Obj", label, DOMAIN[label]]


def _changed(rng: random.Random, node: dict[str, Any]) -> dict[str, Any]:
    """B's copy of one node of A: most often unchanged apart from the cycle
    mechanics, sometimes changed in its payload, its labels or its assertions."""
    props = dict(node["props"])
    props["collected_at"] = props["collected_at"] + 1000
    props["_run_id"] = f"run-{rng.randrange(10**6)}"
    props["carried"] = rng.random() < 0.5
    labels = list(node["labels"])
    roll = rng.random()
    if roll < 0.15:
        props["role"] = rng.choice(("router", "switch", "firewall", "edge"))
    elif roll < 0.2:
        props["extra"] = rng.randrange(3)
    elif roll < 0.25:
        props.pop("tags", None)
    elif roll < 0.3:
        props["mtu"] = 1500 if props["mtu"] != 1500 else 9000
    elif roll < 0.35:
        new = rng.choice(list(DOMAIN))
        labels = ["Obj", new, DOMAIN[new]]
    elif roll < 0.4:
        props["_assert.role"] = ['apic/fab1="leaf"', 'nxos/edge="router"']
    return {"uid": node["uid"], "labels": labels, "props": props}


def _graph(
    seed: int, size: int, *, parallel: bool = False
) -> tuple[dict[int, list[dict]], dict[int, list[dict]]]:
    """Two runs of `size` objects and three edge types.

    An edge unchanged between the runs sometimes has a twin of the same
    payload on both sides, written by another scope, which every rule
    compares as unchanged. With `parallel`, an edge also sometimes has a
    parallel edge of its own on one side only, another next hop.
    """
    rng = random.Random(seed)
    uids = [f"obj:{i:04d}" for i in range(size)] + ["obj:é", "obj:中", "obj:Z", "obj:a"]
    nodes: dict[int, list[dict]] = {A: [], B: []}
    for uid in uids:
        node = _node(rng, uid, _labels(rng, rng.choice(list(DOMAIN))))
        roll = rng.random()
        if roll < 0.12:
            nodes[A].append(node)
        elif roll < 0.24:
            nodes[B].append(node)
        else:
            nodes[A].append(node)
            nodes[B].append(_changed(rng, node))
    rels: dict[int, list[dict]] = {A: [], B: []}
    for t in ("ON", "HAS_IP", "LEARNED_ROUTE"):
        for _ in range(size):
            start, end = rng.choice(uids), rng.choice([*uids, None])
            if any(r["t"] == t and r["start"] == start and r["end"] == end for r in rels[A] + rels[B]):
                continue
            payload = {"next_hop": rng.choice(("10.0.0.1", "10.0.0.2")), "metric": rng.randrange(3)}
            first = {"t": t, "start": start, "end": end, "props": {**payload, "_scope": "vyos:h0"}}
            roll = rng.random()
            sides = (A,) if roll < 0.15 else (B,) if roll < 0.3 else (A, B)
            bumped = len(sides) == 2 and rng.random() < 0.2
            twinned = len(sides) == 2 and not bumped and rng.random() < 0.1
            for side in sides:
                props = dict(first["props"], collected_at=side, carried=rng.random() < 0.3)
                if side == B and bumped:
                    props["metric"] = props["metric"] + 10
                rels[side].append({**first, "props": props})
                if twinned:
                    rels[side].append({**first, "props": dict(props, _scope="derived:x", _run_id="r")})
                if parallel and rng.random() < 0.2:
                    hop = f"10.0.1.{rng.randrange(3)}"
                    rels[side].append({**first, "props": dict(props, next_hop=hop, _scope="derived:y")})
    return nodes, rels


@pytest.fixture(params=["default", "spill"])
def spill(request, monkeypatch):
    """The default bucket, or one of seven rows merged two runs at a time."""
    if request.param == "spill":
        monkeypatch.setattr(cyclemod, "SPILL_ROWS", 7)
        monkeypatch.setattr(cyclemod, "SPILL_RUNS", 2)
    return request.param


@pytest.mark.parametrize("seed", [1, 2, 3])
@pytest.mark.parametrize("cap", [3, 500])
@pytest.mark.parametrize("devices", [None, DEVICES_B], ids=["no-manifest", "manifest"])
def test_the_streamed_comparison_is_the_whole_one(seed, cap, devices, spill, monkeypatch):
    """Counts, capped detail lists, conflicts and `truncated`, in the same
    order: the digest `core/manifest.py graph_delta` takes of them is the
    same value."""
    monkeypatch.setattr(diffmod, "DETAIL_CAP", cap)
    nodes, rels = _graph(seed, 150)
    session = _Session(_Graph(nodes, rels))

    streamed = diff_snapshots(session, A, B, devices_b=devices)
    whole = reference_diff(session, A, B, devices_b=devices, cap=cap)

    assert streamed == whole
    assert json.dumps(streamed, sort_keys=True) == json.dumps(whole, sort_keys=True)
    # the generated graphs reach every bucket, so the equality above covers them
    counts = streamed["counts"]
    assert all(counts["nodes"].values()) and all(counts["rels"].values())
    assert all(streamed["conflicts"]["counts"].values())
    assert streamed["truncated"] is (cap == 3)


def test_the_comparison_does_not_depend_on_the_order_rows_arrive_in(spill):
    """Parallel edges on one side only included. However the edges between
    one pair are matched, the added edges less the removed ones are the
    edges B holds less those A holds."""
    nodes, rels = _graph(4, 150, parallel=True)
    forward = diff_snapshots(_Session(_Graph(nodes, rels)), A, B, devices_b=DEVICES_B)
    backward = diff_snapshots(_Session(_Graph(nodes, rels, reverse=True)), A, B, devices_b=DEVICES_B)
    assert forward == backward
    counts = forward["counts"]["rels"]
    assert counts["added"] - counts["removed"] == len(rels[B]) - len(rels[A])
    assert all(counts.values())


def _routes(runs: dict[int, list[dict[str, Any]]], *, reverse: bool = False) -> _Graph:
    """The LEARNED_ROUTE edges `runs` holds from one VRF to one prefix."""
    nodes = {
        snap: [
            {"uid": uid, "labels": ["Obj", label, "L3"], "props": {"uid": uid}}
            for uid, label in (("vrf", "VrfInstance"), ("pfx", "Prefix"))
        ]
        for snap in (A, B)
    }
    rels = {
        snap: [{"t": "LEARNED_ROUTE", "start": "vrf", "end": "pfx", "props": p} for p in payloads]
        for snap, payloads in runs.items()
    }
    # the database returns rows in no stated order, and B's may come back in
    # an order unlike A's
    return _Graph(nodes, {A: rels[A], B: rels[B][::-1] if reverse else rels[B]})


def _hop(via: str, **props: Any) -> dict[str, Any]:
    return {"via": via, "protocol": "ospf", "_scope": "vyos:h0", **props}


EDGE = {"type": "LEARNED_ROUTE", "start": "vrf", "end": "pfx"}


@pytest.mark.parametrize("reverse", [False, True], ids=["as-stored", "reversed"])
@pytest.mark.parametrize(
    ("a", "b", "added", "removed", "changed"),
    [
        pytest.param(
            [_hop("10.0.0.1|eth0"), _hop("10.0.0.3|eth0")],
            [_hop("10.0.0.3|eth0"), _hop("10.0.0.1|eth0", _scope="reasoner")],
            0,
            0,
            [],
            id="unchanged",
        ),
        pytest.param(
            [_hop("10.0.0.1|eth0"), _hop("10.0.0.3|eth0")],
            [_hop("10.0.0.1|eth0"), _hop("10.0.0.2|eth0"), _hop("10.0.0.3|eth0")],
            1,
            0,
            [],
            id="next-hop-added",
        ),
        pytest.param(
            [_hop("10.0.0.1|eth0"), _hop("10.0.0.3|eth0")],
            [_hop("10.0.0.3|eth0")],
            0,
            1,
            [],
            id="next-hop-removed",
        ),
        pytest.param(
            [_hop("10.0.0.1|eth0"), _hop("10.0.0.1|eth0", _scope="reasoner")],
            [_hop("10.0.0.1|eth0")],
            0,
            1,
            [],
            id="one-of-two-equal-edges-removed",
        ),
        pytest.param(
            [_hop("10.0.0.1|eth0"), _hop("10.0.0.3|eth0")],
            [_hop("10.0.0.1|eth0"), _hop("10.0.0.2|eth0")],
            0,
            0,
            [{"via": ["10.0.0.3|eth0", "10.0.0.2|eth0"]}],
            id="next-hop-replaced",
        ),
        pytest.param(
            # the two next hops pair by the values they share
            [_hop("10.0.0.1|eth0", metric=1), _hop("10.0.0.2|eth0", metric=1)],
            [_hop("10.0.0.1|eth0", metric=2), _hop("10.0.0.2|eth0", metric=0)],
            0,
            0,
            [{"metric": [1, 2]}, {"metric": [1, 0]}],
            id="every-next-hop-changed",
        ),
        pytest.param(
            [_hop("10.0.0.1|eth0"), _hop("10.0.0.2|eth0")],
            [_hop("10.0.0.3|eth0")],
            1,
            2,
            [],
            id="two-next-hops-replaced-by-one",
        ),
        pytest.param(
            [_hop("10.0.0.1|eth0")],
            [_hop("10.0.0.2|eth0")],
            0,
            0,
            [{"via": ["10.0.0.1|eth0", "10.0.0.2|eth0"]}],
            id="one-edge-each",
        ),
    ],
)
def test_the_edges_between_one_pair_are_matched_edge_for_edge(a, b, added, removed, changed, reverse, spill):
    """Equal payloads are one unchanged edge; with as many edges left on each
    side, each pairs with the one it shares the most values with and reads as
    changed; otherwise what is left is removed from A and added in B."""
    out = diff_snapshots(_Session(_routes({A: a, B: b}, reverse=reverse)), A, B)

    assert out["counts"]["rels"] == {"added": added, "removed": removed, "changed": len(changed)}
    assert out["rels"]["added"] == [EDGE] * added
    assert out["rels"]["removed"] == [EDGE] * removed
    assert out["rels"]["changed"] == [{**EDGE, "changes": c} for c in changed]


# The entries of a manifest that records each collector's scope, beside one
# that records none.
SCOPED = (
    _Device("edge", "fd00::1", "failed", fetch_ts_ms=1900, scope="vyos:fd00::1"),
    _Device("gw", "FW1", "collected", fetch_ts_ms=1800, scope="checkpoint-gateway:fw1:obs1"),
    _Device("fab", "10.9.9.9", "carried", fetch_ts_ms=1700, scope="apic:fab1"),
    _Device("fab", "10.9.9.8", "collected", fetch_ts_ms=1700, scope="apic:fab1"),
    _Device("edge", "h0", "collected", fetch_ts_ms=1600, scope="vyos:h0"),
    _Device("edge", "h1", "collected", fetch_ts_ms=1500),
    _Device("core", "", "collected", fetch_ts_ms=1400),
)


def _scanned_owner(props: dict[str, Any], devices: Iterable[Any]) -> Any | None:
    """The owner rule as a scan over every entry: an entry that records a
    scope matches on it, one that does not matches on its host."""
    scope = str(props.get("_scope") or "")
    sources = props.get("_sources") or []
    if not scope or not sources:
        return None
    segments = scope.split(":")[1:]
    matches = [
        d
        for d in devices
        if d.source in sources and (d.scope == scope if d.scope else (not d.host or d.host in segments))
    ]
    return matches[0] if len(matches) == 1 else None


@pytest.mark.parametrize("devices", [DEVICES_B, SCOPED], ids=["no-scope", "scoped"])
def test_an_object_is_owned_by_the_one_entry_its_source_and_scope_name(devices):
    """The indexed owner lookup answers as a scan over every entry does,
    ambiguity and controller entries included, for a removal and for an
    object's freshness alike. With no scope recorded that is the host rule of
    `finalize_reference._owner_of`."""
    snapshot = SimpleNamespace(manifest=SimpleNamespace(devices=list(devices)), cts=B)
    rng = random.Random(9)
    index = cyclemod.device_index(devices)
    scopes = (
        *("vyos:h0", "vyos:h3", "apic:h1:h4", "vyos::h2", "x", "", "core:h1", "vyos:h1"),
        *("vyos:fd00::1", "vyos:fd00::2", "checkpoint-gateway:fw1:obs1", "apic:fab1", "apic:fab2"),
    )
    for _ in range(600):
        props = _node(rng, "obj:x", ["Obj", "Device", "Phys"])["props"]
        props["_scope"] = rng.choice(scopes)
        props["_sources"] = rng.choice(
            ([], ["edge"], ["gw"], ["fab"], ["core"], ["edge", "gw"], ["gw", "core"])
        )
        owner = _scanned_owner(props, devices)
        if devices is DEVICES_B:
            assert owner is scanned_owner_of(props, devices)
        assert cyclemod.device_owner(props, index) is owner
        freshness = cyclemod.freshness_for(snapshot, props)
        assert freshness == cyclemod.freshness_for(snapshot, props, index)
        assert freshness == (None if owner is None else cyclemod._device_freshness(owner, B))


def test_a_recorded_scope_owns_what_its_host_cannot_name():
    """An IPv6 management host holds colons, and a Check Point gateway's scope spells its host slugged."""
    index = cyclemod.device_index(SCOPED)
    ipv6 = {"_scope": "vyos:fd00::1", "_sources": ["edge"], "collected_at": 1}
    assert cyclemod.device_owner(ipv6, index) is SCOPED[0]
    record = diffmod._removal_record("u", {"labels": ["Obj", "Interface"], "props": ipv6}, index)
    assert record["status"] == diffmod.UNKNOWN
    assert record["device"] == {"source": "edge", "host": "fd00::1", "outcome": "failed"}
    assert record["absence_detected"] == 1900

    gateway = {"_scope": "checkpoint-gateway:fw1:obs1", "_sources": ["gw"]}
    assert cyclemod.device_owner(gateway, index) is SCOPED[1]
    # two entries of one source recording one scope: no single owner
    assert cyclemod.device_owner({"_scope": "apic:fab1", "_sources": ["fab"]}, index) is None
    # an entry that records a scope does not match another scope naming its host
    assert cyclemod.device_owner({"_scope": "nxos:h0", "_sources": ["edge"]}, index) is None


class _LazyGraph:
    """One label and one type of `size` objects per run, generated as each
    read is consumed and never held, so what a comparison holds is its own."""

    def __init__(self, size: int) -> None:
        self.size = size

    def _nodes(self, snap: int) -> Iterator[dict[str, Any]]:
        for i in range(self.size):
            if (snap == A and i % 10 == 9) or (snap == B and i % 10 == 8):
                continue
            role = "router" if snap == A or i % 3 else "switch"
            yield {
                "uid": f"prefix:{i:07d}",
                "labels": ["Obj", "Prefix", "L3"],
                "props": {
                    "uid": f"prefix:{i:07d}",
                    "name": f"10.{i // 65536}.{i // 256 % 256}.{i % 256}/32",
                    "role": role,
                    "_scope": f"vyos:h{i % 5}",
                    "_sources": ["edge"],
                    "collected_at": snap + i,
                    "_run_id": f"run-{snap}-{i}",
                },
            }

    def _rels(self, snap: int) -> Iterator[dict[str, Any]]:
        for i in range(self.size):
            if snap == B and i % 7 == 0:
                continue
            yield {
                "t": "LEARNED_ROUTE",
                "start": "vrf:default",
                "end": f"prefix:{i:07d}",
                "props": {"next_hop": f"10.255.0.{(i + (snap == B)) % 250}", "collected_at": snap},
            }

    def answer(self, query: str, params: dict[str, Any]) -> Iterable[dict[str, Any]]:
        snap = params["snap"]
        if query in (diffmod._ALL_NODES, ref.NODES_FOR_LABEL):
            return self._nodes(snap)
        if query in (diffmod._ALL_RELS, ref.RELS_FOR_TYPE):
            return self._rels(snap)
        if query == ref.NODE_LABEL_SETS:
            return [{"labels": ["Obj", "Prefix", "L3"]}]
        if query == ref.REL_TYPES:
            return [{"t": "LEARNED_ROUTE"}]
        raise AssertionError(f"unexpected query: {query}")


def _peak(run: Callable[[], dict[str, Any]]) -> tuple[int, dict[str, Any]]:
    tracemalloc.start()
    try:
        out = run()
        return tracemalloc.get_traced_memory()[1], out
    finally:
        tracemalloc.stop()


def test_what_a_comparison_holds_does_not_grow_with_the_runs(monkeypatch):
    monkeypatch.setattr(cyclemod, "SPILL_ROWS", 1000)
    monkeypatch.setattr(cyclemod, "SPILL_RUNS", 8)
    session = _Session(_LazyGraph(12_000))

    streamed_peak, streamed = _peak(lambda: diff_snapshots(session, A, B))
    whole_peak, whole = _peak(lambda: reference_diff(session, A, B))

    assert streamed == whole
    assert streamed["counts"]["nodes"]["changed"] > 3000
    assert streamed_peak * 5 < whole_peak, (streamed_peak, whole_peak)


@pytest.mark.parametrize("cap", [0, 1, 4, 50])
def test_a_bucket_keeps_what_sorting_the_whole_bucket_and_cutting_it_keeps(cap, monkeypatch):
    """Equal keys included, and records that differ under an equal key among
    them: those keep their arrival order, as the stable sort does."""
    monkeypatch.setattr(diffmod, "DETAIL_CAP", cap)
    rng = random.Random(cap)
    records = [
        {"label": rng.choice(("Device", "Port", None, "")), "uid": rng.choice(("u1", "u2", "u3")), "n": i}
        for i in range(60)
    ]
    bucket = diffmod._Detail("label", "uid")
    for record in records:
        bucket.add(record)

    whole = sorted(records, key=lambda r: tuple(str(r.get(k) or "") for k in ("label", "uid")))
    assert bucket.rows == whole[:cap]
    assert bucket.count == len(records)
    assert bucket.truncated is (len(records) > cap)


def test_a_client_whose_only_change_is_last_seen_is_no_change():
    """An Endpoint's `last_seen` is when its source last saw it, which moves every
    run for every client still on the network: a client that differs in it alone
    is no changed node. A change beside it is reported without it, and the name
    keeps its meaning on another label, where a move of it is a change."""

    def node(uid, label, layer, **props):
        return {"uid": uid, "labels": ["Obj", label, layer], "props": {"uid": uid, **props}}

    nodes = {
        A: [
            node("ep:home:112233445566", "Endpoint", "L2", mac="112233445566", name="nas", last_seen=1_000),
            node("ep:home:aabbccddeeff", "Endpoint", "L2", mac="aabbccddeeff", name="tv", last_seen=1_000),
            node("dev:sw-01", "Device", "Phys", hostname="sw-01", last_seen=1_000),
        ],
        B: [
            node("ep:home:112233445566", "Endpoint", "L2", mac="112233445566", name="nas", last_seen=2_000),
            node(
                "ep:home:aabbccddeeff",
                "Endpoint",
                "L2",
                mac="aabbccddeeff",
                name="living-room-tv",
                last_seen=2_000,
            ),
            node("dev:sw-01", "Device", "Phys", hostname="sw-01", last_seen=2_000),
        ],
    }
    out = diff_snapshots(_Session(_Graph(nodes, {})), A, B)

    changed = {c["uid"]: c["changes"] for c in out["nodes"]["changed"]}
    assert "ep:home:112233445566" not in changed
    assert changed["ep:home:aabbccddeeff"] == {"name": ["tv", "living-room-tv"]}
    assert changed["dev:sw-01"] == {"last_seen": [1_000, 2_000]}
    assert out["counts"]["nodes"]["changed"] == 2
