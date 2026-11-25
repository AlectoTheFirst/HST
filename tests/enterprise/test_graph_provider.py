"""Pinned graph provider loads a complete immutable graph through its real reader."""

from types import SimpleNamespace

import pytest

from hst.analysis_model import graph as graphmod
from hst.analysis_model.graph import (
    LOAD_QUERIES,
    ScopeExtension,
    graph_budget,
    load_graph,
    load_scoped,
)

SNAP = 10


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def data(self):
        return self.rows


def _node(uid, *labels, cts=SNAP, **props):
    return {"uid": uid, "labels": set(labels) | {"Obj"}, "cts": cts, "props": {"uid": uid, **props}}


def _rel(uid, kind, start, end, **props):
    return {"id": uid, "kind": kind, "start": start, "end": end, "props": props}


class _Session:
    """Answers each load query, named by its `// graph-load:` tag, from an
    in-memory run with the semantics the Cypher states: run membership on
    collection_ts, retired nodes and relationships left out, scope by the
    owning device, keyset pages on (anchor, key)."""

    def __init__(self, nodes=None, relationships=None):
        self.queries = []
        self.nodes = {
            node["uid"]: node
            for node in nodes or [_node("dev", "Device"), _node("if", "Interface", name="lan")]
        }
        self.relationships = relationships or [_rel("on", "ON", "if", "dev")]

    def execute_read(self, work):
        return work(self)

    # -- the run's semantics

    def _run_node(self, uid, snap):
        node = self.nodes.get(uid)
        return node is not None and node["cts"] == snap

    def _live(self, uid):
        return "Retired" not in self.nodes[uid]["labels"]

    def _run_rel(self, rel, snap):
        props = rel["props"]
        return props.get("_retired_at") is None and props.get("collection_ts") in (snap, None)

    def _owners(self, uid, snap):
        labels = self.nodes[uid]["labels"]

        def via(start, kind):
            return [
                rel["end"]
                for rel in self.relationships
                if rel["start"] == start
                and rel["kind"] == kind
                and "Device" in self.nodes[rel["end"]]["labels"]
                and self.nodes[rel["end"]]["cts"] == snap
            ]

        if labels & {"Interface", "Port"}:
            return via(uid, "ON")
        if "VrfInstance" in labels:
            return via(uid, "OWNED_BY")
        if labels & {"Prefix", "IpAddress"}:
            anchor = self.nodes[uid]["props"].get("anchor")
            vrf = self.nodes.get(anchor)
            if vrf is not None and "VrfInstance" in vrf["labels"] and vrf["cts"] == snap:
                return via(anchor, "OWNED_BY")
        return []

    def _loaded(self, uid, params):
        if "devices" not in params:
            return True
        if self.nodes[uid]["props"].get("cp_uid") is not None:
            return True
        owners = self._owners(uid, params["snap"])
        return not owners or any(owner in params["devices"] for owner in owners)

    def _shape(self, uid):
        node = self.nodes[uid]
        return {"labels": sorted(node["labels"]), "props": dict(node["props"])}

    # -- the queries

    def run(self, query, **params):
        self.queries.append((query, params))
        snap = params.get("snap")
        if "count(n) AS count" in query:
            return _Result([{"count": sum(1 for node in self.nodes.values() if node["cts"] == snap)}])
        tag = query.split("\n", 1)[0].removeprefix("// graph-load:")
        if tag == "nodes":
            rows = [
                {"id": uid, **self._shape(uid)}
                for uid in sorted(self.nodes)
                if self._run_node(uid, snap)
                and self._live(uid)
                and uid > params["after"]
                and self._loaded(uid, params)
            ]
            return _Result(rows[: params["limit"]])
        if tag == "vsx-transit":
            present = any(
                rel["props"].get("source") in params["sources"]
                and self._run_rel(rel, snap)
                and (self._run_node(rel["start"], snap) or self._run_node(rel["end"], snap))
                for rel in self.relationships
            )
            return _Result([{"present": present}])
        if tag == "scope-lookup":
            uid = params["uid"]
            if not (self._run_node(uid, snap) and self._live(uid)):
                return _Result([])
            return _Result([{"loaded": self._loaded(uid, params), "owners": self._owners(uid, snap)}])
        return _Result(self._keyed(tag, params))

    def _anchors(self, tag, params):
        snap, after, key = params["snap"], params["after_node"], params["after_key"]
        found = []
        for uid in sorted(self.nodes):
            if not self._run_node(uid, snap) or uid < after or (uid == after and key is None):
                continue
            if tag != "attached-nodes" and not (self._live(uid) and self._loaded(uid, params)):
                continue
            found.append(uid)
        return found[: params["window"]]

    def _keyed(self, tag, params):
        snap, scoped = params["snap"], "devices" in params
        rows = []
        for anchor in self._anchors(tag, params):
            matched = []
            for rel in sorted(self.relationships, key=lambda item: item["id"]):
                if not self._run_rel(rel, snap):
                    continue
                if tag == "attached-nodes":
                    other = (
                        rel["end"]
                        if rel["start"] == anchor
                        else rel["start"]
                        if rel["end"] == anchor
                        else None
                    )
                    if other is None or self.nodes[other]["cts"] is not None or not self._live(other):
                        continue
                    matched.append({"key": rel["id"], "id": other, **self._shape(other)})
                elif tag == "relationships-from-run":
                    end = rel["end"]
                    if (
                        rel["start"] != anchor
                        or self.nodes[end]["cts"] not in (snap, None)
                        or not self._live(end)
                    ):
                        continue
                    loaded = self._loaded(end, params)
                    if scoped and not loaded and rel["kind"] not in params["boundary"]:
                        continue
                    row = {"key": rel["id"], "kind": rel["kind"], "start": anchor, "end": end}
                    row["props"] = dict(rel["props"])
                    if scoped:
                        row["outside"] = None if loaded else self._owners(end, snap)
                    matched.append(row)
                elif tag == "relationships-from-unstamped":
                    start = rel["start"]
                    if rel["end"] != anchor or self.nodes[start]["cts"] is not None or not self._live(start):
                        continue
                    matched.append(
                        {
                            "key": rel["id"],
                            "kind": rel["kind"],
                            "start": start,
                            "end": anchor,
                            "props": dict(rel["props"]),
                        }
                    )
                elif tag == "boundary-relationships":
                    start = rel["start"]
                    if (
                        rel["end"] != anchor
                        or rel["kind"] not in params["boundary"]
                        or not self._run_node(start, snap)
                        or not self._live(start)
                        or self._loaded(start, params)
                    ):
                        continue
                    matched.append(
                        {
                            "key": rel["id"],
                            "kind": rel["kind"],
                            "start": start,
                            "end": anchor,
                            "props": dict(rel["props"]),
                            "outside": self._owners(start, snap),
                        }
                    )
            if tag == "scope-boundary":
                groups = {}
                for rel in self.relationships:
                    if not self._run_rel(rel, snap) or rel["kind"] in params["boundary"]:
                        continue
                    if rel["start"] == anchor:
                        other, direction = rel["end"], "out"
                    elif rel["end"] == anchor:
                        other, direction = rel["start"], "in"
                    else:
                        continue
                    if (
                        not self._run_node(other, snap)
                        or not self._live(other)
                        or self._loaded(other, params)
                    ):
                        continue
                    groups.setdefault((rel["kind"], direction), []).extend(self._owners(other, snap))
                matched = [
                    {"key": f"{kind}|{direction}", "kind": kind, "direction": direction, "owners": owners}
                    for (kind, direction), owners in sorted(groups.items())
                ]
            if not matched:
                matched = [{"key": None}]
            for row in matched:
                row["anchor"] = anchor
                if anchor > params["after_node"] or (
                    row["key"] is not None
                    and params["after_key"] is not None
                    and row["key"] > params["after_key"]
                ):
                    rows.append(row)
        rows.sort(key=lambda row: (row["anchor"], row["key"] is None, row["key"] or ""))
        return rows[: params["limit"]]


def _snapshot():
    return SimpleNamespace(cts=SNAP, manifest=object(), settings=object())


def _load(session, **options):
    return load_graph(session, _snapshot(), "a" * 64, digest_reader=lambda: "a" * 64, **options)


def test_provider_reads_pinned_complete_graph_once_and_indexes_relations():
    session = _Session()
    graph = _load(session, page_size=1)

    assert graph.complete is True
    assert graph.targets("if", "ON")[0].uid == "dev"
    # one count, then three pages of each of the four reads (nodes, attached
    # nodes, relationships from the run and from unstamped nodes): one key
    # per page, and an empty page that ends the read
    assert graph.database_reads == 13
    assert all(params["snap"] == SNAP for _query, params in session.queries)


def test_a_load_puts_the_check_point_envelopes_of_the_pinned_run_back_on_their_nodes(monkeypatch):
    """A Check Point node carries only its envelope's digest; the load
    reads the envelope from the pinned run's side-store file."""
    envelope = '{"uid":"raw-rule"}'
    digest = graphmod.checkpoint_envelopes.envelope_sha(envelope)
    asked = []

    def read(snapshot, wanted):
        asked.append((snapshot.cts, dict(wanted)))
        return {"cp:rule": envelope}

    monkeypatch.setattr(graphmod.checkpoint_envelopes, "read_envelopes", read)
    session = _Session(nodes=[_node("cp:rule", "FwRule", checkpoint_envelope_sha=digest)], relationships=[])
    graph = _load(session)

    assert asked == [(SNAP, {"cp:rule": digest})]
    assert graph.nodes["cp:rule"].props["checkpoint_envelope"] == envelope


def test_provider_keyset_pages_split_the_edges_of_one_start_node():
    relationships = [_rel(f"r{n}", "ON", "if", "dev") for n in (3, 1, 2)]
    session = _Session(relationships=relationships)
    graph = _load(session, page_size=1)

    assert [rel.uid for rel in graph.outgoing[("if", "ON")]] == ["r1", "r2", "r3"]
    assert not any("SKIP" in query or "offset" in params for query, params in session.queries)


def test_every_page_read_seeks_the_uid_index_and_sorts_only_its_window():
    """No load query sorts the whole run: each one seeks obj_uid_cts from the
    key the previous page ended on, and a relationship query sorts only the
    window of anchors it read."""
    for name, query in LOAD_QUERIES.items():
        if name in {"scope-lookup", "vsx-transit"}:
            continue
        assert "USING INDEX" in query and "Obj(uid, collection_ts)" in query, name
        assert "SKIP" not in query, name
        if name not in {"nodes", "scoped-nodes"}:
            assert "WITH x ORDER BY x.uid LIMIT $window" in query, name
            assert query.rstrip().endswith("ORDER BY anchor, key LIMIT $limit"), name


def test_pages_of_one_anchor_continue_after_its_last_key_and_skip_empty_anchors():
    nodes = [_node("a", "Device"), _node("b", "Device"), _node("c", "Device"), _node("d", "Device")]
    relationships = [_rel(f"k{n}", "PEERS_WITH", "a", "d") for n in range(5)] + [
        _rel("z", "PEERS_WITH", "c", "a")
    ]
    session = _Session(nodes, relationships)
    graph = _load(session, page_size=2)

    assert [rel.uid for rel in graph.outgoing[("a", "PEERS_WITH")]] == [f"k{n}" for n in range(5)]
    assert [rel.uid for rel in graph.incoming[("a", "PEERS_WITH")]] == ["z"]
    assert len({rel.uid for rels in graph.outgoing.values() for rel in rels}) == 6


def test_table_budgets_follow_the_analysis_worker_memory(monkeypatch):
    assert graph_budget(1024) == (1_000_000, 256 * 1024 * 1024)
    assert graph_budget(2048) == (2_000_000, 512 * 1024 * 1024)
    assert graph_budget(16384) == (16_000_000, 4096 * 1024 * 1024)
    with pytest.raises(ValueError):
        graph_budget(0)

    budgets = []
    reader = graphmod.BoundedTableReader

    class Recording(reader):
        def __init__(self, *args, **kwargs):
            budgets.append((kwargs["max_rows"], kwargs["max_bytes"]))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(graphmod, "BoundedTableReader", Recording)
    _load(_Session(), memory_mb=4096)
    _load(_Session())

    assert budgets == [(4_000_000, 1024 * 1024 * 1024), (1_000_000, 256 * 1024 * 1024)]


def _estate():
    """Two devices. Each has an interface, a VRF and an address anchored on
    it; a rulebase enforced on device b's interface; an unstamped site."""
    nodes = [
        _node("dev:a", "Device"),
        _node("dev:b", "Device"),
        _node("dev:a/if/lan", "Interface", name="lan"),
        _node("dev:b/if/lan", "Interface", name="lan"),
        _node("vrf:dev:a:main", "VrfInstance", name="main"),
        _node("vrf:dev:b:main", "VrfInstance", name="main"),
        _node("ip:a", "IpAddress", ip="10.0.0.1", anchor="vrf:dev:a:main"),
        _node("ip:b", "IpAddress", ip="10.0.1.1", anchor="vrf:dev:b:main"),
        _node("rb", "FwRulebase", vendor="cisco"),
        _node("site", "Site", cts=None),
        _node("dev:gw", "Device", cp_uid="cp:gw"),
    ]
    relationships = [
        _rel("on-a", "ON", "dev:a/if/lan", "dev:a"),
        _rel("on-b", "ON", "dev:b/if/lan", "dev:b"),
        _rel("own-a", "OWNED_BY", "vrf:dev:a:main", "dev:a"),
        _rel("own-b", "OWNED_BY", "vrf:dev:b:main", "dev:b"),
        _rel("ip-a", "HAS_IP", "dev:a/if/lan", "ip:a"),
        _rel("ip-b", "HAS_IP", "dev:b/if/lan", "ip:b"),
        _rel("enf-b", "ENFORCES", "dev:b/if/lan", "rb", direction="in"),
        _rel("loc-a", "LOCATED_IN", "dev:a", "site"),
        _rel("loc-b", "LOCATED_IN", "dev:b", "site"),
    ]
    return nodes, relationships


def test_a_scoped_load_reads_the_bulk_of_its_devices_only():
    whole = _load(_Session(*_estate()))
    scoped = _load(_Session(*_estate()), devices={"dev:a"})

    assert scoped.scope == frozenset({"dev:a"})
    assert scoped.nodes["dev:a/if/lan"] == whole.nodes["dev:a/if/lan"]
    assert scoped.targets("dev:a/if/lan", "HAS_IP") == whole.targets("dev:a/if/lan", "HAS_IP")
    assert scoped.sources("dev:a", "OWNED_BY") == whole.sources("dev:a", "OWNED_BY")
    # the unstamped site and the Check Point gateway are read whatever the scope
    assert scoped.sources("site", "LOCATED_IN") == whole.sources("site", "LOCATED_IN")
    assert [node.uid for node in scoped.nodes_carrying("cp_uid")] == ["dev:gw"]
    # a policy binding from an omitted interface is kept whole
    assert [rel.uid for rel in scoped.incoming[("rb", "ENFORCES")]] == ["enf-b"]
    assert scoped.labels.get("FwRulebase") == whole.labels.get("FwRulebase")
    assert scoped.has_vsx_transit() is False


@pytest.mark.parametrize(
    ("read", "devices"),
    [
        (lambda graph: graph.sources("dev:b", "ON"), {"dev:b"}),
        (lambda graph: graph.nodes.get("dev:b/if/lan"), {"dev:b"}),
        (lambda graph: "ip:b" in graph.nodes, {"dev:b"}),
        (lambda graph: graph.sources("rb", "ENFORCES"), {"dev:b"}),
        (lambda graph: graph.outgoing.get(("vrf:dev:b:main", "OWNED_BY")), {"dev:b"}),
        (lambda graph: graph.labels.get("Interface"), None),
        (lambda graph: list(graph.nodes.values()), None),
        (lambda graph: list(graph.nodes_carrying("name")), None),
    ],
)
def test_a_read_past_the_scope_names_the_devices_to_load(read, devices):
    scoped = _load(_Session(*_estate()), devices={"dev:a"})

    with pytest.raises(ScopeExtension) as raised:
        read(scoped)

    assert raised.value.devices == (None if devices is None else frozenset(devices))
    assert raised.value.scope is scoped.scope
    assert raised.value.widened() == (None if devices is None else frozenset({"dev:a", *devices}))


def test_a_uid_the_run_does_not_hold_is_absent_not_out_of_scope():
    scoped = _load(_Session(*_estate()), devices={"dev:a"})

    assert scoped.nodes.get("dev:nowhere") is None
    assert scoped.outgoing.get(("dev:nowhere", "ON"), ()) == ()
    assert "dev:nowhere" not in scoped.nodes


def test_load_scoped_widens_until_the_reads_are_whole_and_matches_the_whole_run():
    session = _Session(*_estate())
    scopes = []

    def load(scope):
        scopes.append(scope)
        return _load(session, devices=scope)

    def use(graph):
        return [node.uid for node in graph.sources("dev:b", "ON")], graph.targets("dev:b/if/lan", "HAS_IP")

    scoped = load_scoped(load, use, frozenset({"dev:a"}))
    whole = _load(_Session(*_estate()))

    assert scoped == (
        [node.uid for node in whole.sources("dev:b", "ON")],
        whole.targets("dev:b/if/lan", "HAS_IP"),
    )
    assert scopes == [frozenset({"dev:a"}), frozenset({"dev:a", "dev:b"})]


def test_load_scoped_loads_the_whole_run_for_a_whole_run_read():
    session = _Session(*_estate())
    scopes = []

    def load(scope):
        scopes.append(scope)
        return _load(session, devices=scope)

    assert load_scoped(load, lambda graph: graph.labels.get("Interface"), frozenset({"dev:a"})) == (
        "dev:a/if/lan",
        "dev:b/if/lan",
    )
    assert scopes == [frozenset({"dev:a"}), None]


def test_a_run_past_the_table_budget_is_reported_as_scope_too_large():
    with pytest.raises(graphmod.GraphTooLarge, match="SCOPE_TOO_LARGE") as raised:
        _load(_Session(), max_rows=1)

    assert raised.value.code == "SCOPE_TOO_LARGE"
    assert "the whole run" in str(raised.value)
    with pytest.raises(graphmod.GraphTooLarge, match="the objects of 1 devices"):
        _load(_Session(*_estate()), devices={"dev:a"}, max_rows=2)
