"""`collectors/base.py load_payload` and `execute` with a batch digest to
compare (`graph_gate`): a payload whose batch digests as the batch on record
writes its raw file and side tables and, of its graph, only what another
writer shares and what carries an anchor (`_shared_part`).

A load that is stopped ends at its next stage (`Collector.check_stop`).
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from tests.test_collector_execute import FakeSession

from hst.app.crypto import dek, generate_key
from hst.collectors import base as collectors_base
from hst.collectors.base import CollectionStopped, Collector, GraphGate, SourceConfig, graph_sha
from hst.collectors.util import GraphBuilder, connected_address
from hst.core import Settings, rawstore, uid
from hst.core.model import Batch, NodeRecord, SectionOutcome

PARENT = 1_000


class _Cfg(SourceConfig):
    host: str = ""


class _Router(Collector):
    """One device: a Device node named from the payload, a warning, one
    section and one side-store table of ARP rows."""

    name = "vyos"
    KIND = "group"
    ConfigModel = _Cfg
    SIDE_TABLES = ("arp",)

    def __init__(self, config: _Cfg, settings: Settings) -> None:
        super().__init__(config, settings)
        self.scope = f"vyos:{config.host}"
        self.released = 0

    def fetch(self) -> Any:
        return {"hostname": "r1", "uptime": 1, "arp": [["10.0.0.9", "aa:bb:cc:dd:ee:ff"]]}

    def normalize(self, raw: Any) -> Any:
        b = GraphBuilder()
        b.node("Device", f"dev:{self.config.host}", hostname=raw["hostname"], role="router")
        batch = b.batch(self.name, self.scope)
        batch.sections["config"] = SectionOutcome(status="ok", row_count=1)
        batch.warnings.append(f"dev:{self.config.host}: one thing the payload could not settle")
        return batch

    def side_tables(self, raw: Any) -> dict[str, list[dict[str, Any]]]:
        return {
            "arp": [{"device_uid": f"dev:{self.config.host}", "ip": ip, "mac": mac} for ip, mac in raw["arp"]]
        }

    def probe(self) -> str:
        return "ok"

    def release_payload(self) -> None:
        self.released += 1


DEV = "dev:sn1"
PORT = uid.port(DEV, "Ethernet1/1")
IFACE = uid.interface(DEV, "Ethernet1/1")
VLAN = uid.vlan("nxos:leaf1", 10)
BD = uid.bridge_domain("fab0", 10)
PEER = uid.port("dev:sn2", "Ethernet1/1")


class _Leaf(_Router):
    """A switch whose device, port and broadcast domain other writers can
    share: its own interface and VLAN, a connected address and prefix that
    carry an anchor, and a link to a port of another device's batch."""

    name = "nxos"

    def __init__(self, config: _Cfg, settings: Settings) -> None:
        super().__init__(config, settings)
        self.scope = f"nxos:{config.host}"

    def normalize(self, raw: Any) -> Any:
        b = GraphBuilder()
        b.node("Device", DEV, hostname="leaf1", role="leaf")
        b.node("Port", PORT, name="Ethernet1/1")
        b.node("Interface", IFACE, name="Ethernet1/1")
        b.node("VlanInstance", VLAN, vid=10)
        b.node("BridgeDomain", BD, name="users")
        b.rel("ON", "Port", PORT, "Device", DEV)
        b.rel("ON", "Interface", IFACE, "Device", DEV)
        b.rel("REALIZES", "VlanInstance", VLAN, "BridgeDomain", BD)
        b.rel("CONNECTED_TO", "Port", PORT, "Port", PEER)
        self.ip, self.prefix = connected_address(b, "10.0.0.1/24", anchor=f"vrf:{DEV}:default", dom="corp")
        return b.batch(self.name, self.scope)


class _Graph(FakeSession):
    """A graph session that answers the upserts as FakeSession does, answers
    the relationship upserts with every row, and finds `shared` shared
    (`SHARED_OBJECTS`), recording each time it was asked."""

    def __init__(self, shared: set[str] | None = None) -> None:
        self.shared = shared or set()
        self.asked: list[dict[str, Any]] = []

    def run(self, q, **p):
        graph = self

        class _Result:
            def data(self_inner):
                if q == collectors_base.SHARED_OBJECTS:
                    graph.asked.append(p)
                    return [{"uid": u} for u in p["uids"] if u in graph.shared]
                if "UNWIND $rows" in q and "MERGE (a)-" in q:
                    return [{"start": r["start"], "end": r["end"], "before": {}} for r in p["rows"]]
                return FakeSession.run(graph, q, **p).data()

        return _Result()


@pytest.fixture
def rig(tmp_path, monkeypatch):
    pytest.importorskip("pyarrow")
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())
    loads: list[Batch] = []
    real = collectors_base.load

    def load(session, batch, **kw):
        loads.append(batch)
        return real(session, batch, **kw)

    monkeypatch.setattr(collectors_base, "load", load)
    return settings, loads


def _router(settings: Settings) -> _Router:
    return _Router(_Cfg(host="r1", source_name="edge"), settings)


def _digest(settings: Settings, raw: dict[str, Any]) -> str:
    """The digest a load of `raw` from source row `edge` computes."""
    collector = _router(settings)
    batch = collector.normalize(raw).model_copy(update={"source": "edge"})
    return graph_sha(collector, batch)


def _gate(answer: bool, asked: list[str] | None = None) -> GraphGate:
    def matches(digest: str) -> bool:
        if asked is not None:
            asked.append(digest)
        return answer

    return GraphGate(matches, PARENT)


def _load(settings: Settings, raw: dict[str, Any], *, collector: _Router | None = None, session=None, **kw):
    collector = collector or _router(settings)
    manifest = collectors_base.load_payload(
        collector,
        session or FakeSession(),
        raw,
        collection_ts=2_000,
        run_id="1700000000000-aaaaaaaa",
        ts_ms=1_700_000_000_000,
        source_name="edge",
        **kw,
    )
    return collector, manifest


def _tables_written(settings: Settings) -> list[Any]:
    return list((settings.sidestore_dir / "arp").rglob("*.parquet"))


def test_a_batch_that_digests_as_the_record_writes_its_tables_and_nothing_it_holds_alone(rig):
    settings, loads = rig
    raw = _router(settings).fetch()
    asked: list[str] = []
    graph = _Graph()

    collector, manifest = _load(settings, raw, session=graph, graph_gate=_gate(True, asked))

    assert loads == []
    assert asked == [_digest(settings, raw)] == [manifest.graph_sha]
    # which of its objects another writer shares is read from the parent run
    # and the run being built
    (params,) = graph.asked
    assert params == {
        "uids": ["dev:r1"],
        "prev": PARENT,
        "cts": 2_000,
        "scope": "vyos:r1",
        "source": "edge",
        "derived": ["derived:", "app:", "meta:"],
    }
    assert manifest.graph_unchanged
    assert (manifest.nodes_upserted, manifest.rels_upserted) == (0, 0)
    assert (manifest.source, manifest.scope, manifest.run_id) == ("edge", "vyos:r1", "1700000000000-aaaaaaaa")
    # what the run records from the batch is recorded whether or not it is written
    assert manifest.sections["config"].status == "ok"
    assert manifest.warnings == ["dev:r1: one thing the payload could not settle"]
    assert collector.last_device_uids == ["dev:r1"]
    # the payload is new even where its graph is not
    assert manifest.tables["arp"].status == "complete" and manifest.tables["arp"].row_count == 1
    assert _tables_written(settings)
    assert collector.released == 1


def test_a_kept_batch_writes_what_other_writers_share_and_what_carries_an_anchor(rig):
    """The device, its port and the broadcast domain are shared; the
    connected address and prefix carry an anchor; the interface and the VLAN
    are the device's alone and come forward from the parent run, with every
    relationship that has one of them for an end."""
    settings, loads = rig
    collector = _Leaf(_Cfg(host="leaf1", source_name="leaves"), settings)
    graph = _Graph({DEV, PORT, BD})

    _collector, manifest = _load(
        settings, collector.fetch(), collector=collector, session=graph, graph_gate=_gate(True)
    )

    (part,) = loads
    assert sorted(n.uid for n in part.nodes) == sorted([DEV, PORT, BD, collector.ip, collector.prefix])
    assert sorted((r.rel_type, r.start_uid, r.end_uid) for r in part.rels) == [
        ("CONNECTED_TO", PORT, PEER),
        ("IN", collector.ip, collector.prefix),
        ("ON", PORT, DEV),
    ]
    assert (part.source, part.scope) == ("edge", "nxos:leaf1")
    assert manifest.graph_unchanged
    assert (manifest.nodes_upserted, manifest.rels_upserted) == (5, 3)
    # the digest is of the whole batch, not of the part written
    whole = collector.normalize(collector.fetch()).model_copy(update={"source": "edge"})
    assert manifest.graph_sha == graph_sha(collector, whole)


def test_a_relationship_to_an_object_outside_the_batch_is_written_with_a_shared_end(rig):
    settings, loads = rig
    collector = _Leaf(_Cfg(host="leaf1", source_name="leaves"), settings)

    _load(settings, collector.fetch(), collector=collector, session=_Graph({PORT}), graph_gate=_gate(True))

    (part,) = loads
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in part.rels}
    assert ("CONNECTED_TO", PORT, PEER) in rels
    # the port's relationship to the device the batch holds alone is left to
    # the carry, which copies it with the device
    assert ("ON", PORT, DEV) not in rels


def test_the_shared_objects_are_read_in_chunks_of_the_loaders_size(rig, monkeypatch):
    settings, loads = rig
    monkeypatch.setattr(collectors_base, "CHUNK", 2)
    collector = _Leaf(_Cfg(host="leaf1", source_name="leaves"), settings)
    graph = _Graph({DEV, BD, IFACE})

    _load(settings, collector.fetch(), collector=collector, session=graph, graph_gate=_gate(True))

    assert [len(p["uids"]) for p in graph.asked] == [2, 2, 2, 1]
    (part,) = loads
    assert {DEV, BD, IFACE} <= {n.uid for n in part.nodes}


def test_a_kept_batch_the_registry_refuses_is_refused_and_writes_nothing(rig, monkeypatch):
    settings, loads = rig
    collector = _router(settings)

    def unregistered(raw: Any) -> Batch:
        return Batch(source="vyos", scope="vyos:r1", nodes=[NodeRecord(label="NoSuchLabel", uid="x:1")])

    monkeypatch.setattr(collector, "normalize", unregistered)

    with pytest.raises(ValueError, match="unregistered label"):
        _load(settings, collector.fetch(), collector=collector, graph_gate=_gate(True))
    assert loads == [] and not _tables_written(settings)
    assert collector.released == 1


def test_a_batch_that_digests_otherwise_is_loaded_whole(rig):
    settings, loads = rig
    raw = _router(settings).fetch()
    graph = _Graph({"dev:r1"})

    _collector, manifest = _load(settings, raw, session=graph, graph_gate=_gate(False))

    assert [b.source for b in loads] == ["edge"]
    assert graph.asked == []
    assert not manifest.graph_unchanged
    assert manifest.graph_sha == _digest(settings, raw)
    assert manifest.nodes_upserted == 1
    assert manifest.tables["arp"].status == "complete"


def test_a_load_with_nothing_to_compare_loads_and_reports_the_digest(rig):
    settings, loads = rig
    raw = _router(settings).fetch()

    _collector, manifest = _load(settings, raw)

    assert [b.source for b in loads] == ["edge"]
    assert not manifest.graph_unchanged
    assert manifest.graph_sha == _digest(settings, raw)


def test_the_digest_is_not_part_of_the_run_node_the_loader_writes(rig):
    settings, _loads = rig
    _collector, manifest = _load(settings, _router(settings).fetch(), graph_gate=_gate(True))

    dumped = manifest.model_dump()
    assert "graph_sha" not in dumped and "graph_unchanged" not in dumped


def test_execute_writes_and_joins_the_raw_file_whichever_way_the_gate_answers(rig):
    settings, loads = rig
    written: list[str] = []

    for answer in (True, False):
        collectors_base.execute(
            _router(settings),
            FakeSession(),
            collection_ts=2_000 + answer,
            source_name="edge",
            on_write=lambda path, sha, size: written.append(path.name),
            graph_gate=_gate(answer),
        )

    assert [b.source for b in loads] == ["edge"]  # the False answer only
    raws = sorted(settings.raw_dir.rglob(f"*{rawstore.SUFFIX}"))
    assert len(raws) == 2
    for path in raws:
        assert rawstore.read(path, dek(settings))["hostname"] == "r1"
        assert rawstore.sibling(path, rawstore.META_SUFFIX).exists()
    assert sum(name.endswith(rawstore.SUFFIX) for name in written) == 2


def test_execute_with_nothing_to_compare_hands_the_load_no_gate(rig, monkeypatch):
    """A load with nothing to compare hands `load_payload` no gate keyword."""
    settings, _loads = rig
    seen: list[str] = []
    real = collectors_base.load_payload

    def load_payload(
        collector, session, raw, *, collection_ts, run_id, ts_ms, source_name=None, on_write=None
    ):
        seen.append(run_id)
        return real(
            collector,
            session,
            raw,
            collection_ts=collection_ts,
            run_id=run_id,
            ts_ms=ts_ms,
            source_name=source_name,
            on_write=on_write,
        )

    monkeypatch.setattr(collectors_base, "load_payload", load_payload)

    manifest = collectors_base.execute(
        _router(settings), FakeSession(), collection_ts=2_000, source_name="edge"
    )

    assert len(seen) == 1 and manifest.graph_sha


def test_a_load_that_raises_after_the_gate_answered_releases_the_collector(rig, monkeypatch):
    settings, _loads = rig
    collector = _router(settings)

    def broken(raw: Any) -> Any:
        raise RuntimeError("side store unavailable")

    monkeypatch.setattr(collector, "side_tables", broken)

    with pytest.raises(RuntimeError, match="side store unavailable"):
        _load(settings, collector.fetch(), collector=collector, graph_gate=_gate(True))
    assert collector.released == 1


# --- a stopped run ends the load at its next stage ---------------------------------------------


@pytest.mark.parametrize(
    ("raised_in", "loaded"),
    [("before", False), ("normalize", False), ("load", True)],
    ids=["before-the-load", "during-normalize", "during-the-graph-write"],
)
def test_a_stopped_run_ends_the_load_at_its_next_stage(rig, monkeypatch, raised_in, loaded):
    """Raised before the load starts, the load normalizes nothing; raised
    while the payload normalizes, nothing is written; raised while the graph
    is written, the side tables are not."""
    settings, loads = rig
    collector = _router(settings)
    collector.stop = threading.Event()
    real_normalize, real_load = collector.normalize, collectors_base.load
    normalized: list[str] = []

    def normalize(raw: Any) -> Any:
        normalized.append(raw["hostname"])
        if raised_in == "normalize":
            collector.stop.set()
        return real_normalize(raw)

    def load(session, batch, **kw):
        manifest = real_load(session, batch, **kw)
        if raised_in == "load":
            collector.stop.set()
        return manifest

    monkeypatch.setattr(collector, "normalize", normalize)
    monkeypatch.setattr(collectors_base, "load", load)
    if raised_in == "before":
        collector.stop.set()

    with pytest.raises(CollectionStopped):
        _load(settings, collector.fetch(), collector=collector)

    assert normalized == ([] if raised_in == "before" else ["r1"])
    assert bool(loads) is loaded
    assert not _tables_written(settings)
    assert collector.released == 1


def test_a_stopped_run_ends_a_kept_batch_before_its_shared_write(rig):
    settings, loads = rig
    collector = _router(settings)
    collector.stop = threading.Event()
    graph = _Graph({"dev:r1"})

    def matches(digest: str) -> bool:
        collector.stop.set()
        return True

    with pytest.raises(CollectionStopped):
        _load(
            settings,
            collector.fetch(),
            collector=collector,
            session=graph,
            graph_gate=GraphGate(matches, PARENT),
        )

    assert graph.asked == [] and loads == []
    assert not _tables_written(settings)


def test_a_stopped_run_ends_an_observation_load_before_its_tables(rig, monkeypatch):
    settings, _loads = rig
    collector = _router(settings)
    collector.stop = threading.Event()

    def sections(raw: Any) -> dict[str, SectionOutcome]:
        collector.stop.set()
        return {"config": SectionOutcome(status="ok")}

    monkeypatch.setattr(collector, "sections", sections, raising=False)

    with pytest.raises(CollectionStopped):
        collectors_base.load_observations(
            collector,
            collector.fetch(),
            collection_ts=2_000,
            run_id="1700000000000-aaaaaaaa",
            ts_ms=1_700_000_000_000,
            source_name="edge",
        )

    assert not _tables_written(settings)
    assert collector.released == 1
