"""A run in which a VyOS device was unchanged publishes the graph a run that
loaded it would, against a real Neo4j (collectors/base.py `load_payload`,
app/runs_exec.py `CarryScopes`, core/cycle.py `carry_forward`).

The devices are the VyOS collector's own normalization of the fixture in
tests/test_vyos.py, loaded the way a run loads them: a full load, or a load
whose batch digests as the batch on record, which writes the objects other
writers share and leaves the rest to the carry. The carry is named by the
scopes the run records for each unit, the way `_collect_sources` records
them.

Opt-in like tests/test_snapshot_db.py: set NEO4J_TEST_URI to a scratch
database. The fixture deletes this suite's run keys before and after every
test; every object here is written under one of them.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from tests import test_unchanged_carry as fixtures

from hst.app import runs_exec
from hst.app.crypto import generate_key
from hst.collectors import base as collectors_base
from hst.collectors.base import GraphGate
from hst.collectors.vyos import VyosCollector
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import manifest as manifests
from hst.core.config import Settings
from hst.core.loader import load
from hst.core.model import RunManifest

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

pytest.importorskip("pyarrow")

PREV, NEW, REF = 7_330_000_001_000, 7_330_000_002_000, 7_330_000_003_000
KEYS = [PREV, NEW, REF]
SOURCE, CORE, EDGE = fixtures.SOURCE, fixtures.CORE, fixtures.EDGE


def _refuse_if_live() -> None:
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This suite deletes data. "
            f"Point it at a scratch database.",
            returncode=2,
        )


@pytest.fixture(scope="module")
def _driver():
    from neo4j import GraphDatabase

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
    yield driver
    driver.close()


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        yield s
        _cleanup(s)


def _cleanup(s) -> None:
    s.run("MATCH (n:Obj) WHERE n.collection_ts IN $keys DETACH DELETE n", keys=KEYS).consume()
    s.run("MATCH (r:CollectionRun) WHERE r.snapshot_ts IN $keys DETACH DELETE r", keys=KEYS).consume()


@pytest.fixture()
def settings(tmp_path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _collector(settings: Settings, host: str) -> VyosCollector:
    return fixtures._collector(host, settings)


def _load(
    s, collector: VyosCollector, raw: dict[str, Any], cts: int, n: int, *, kept: bool = False
) -> RunManifest:
    """One device's load into run `cts`; `kept` loads it as a batch that
    digests as the one on record, against the parent run."""
    gate = {"graph_gate": GraphGate(lambda digest: True, PREV)} if kept else {}
    return collectors_base.load_payload(
        collector,
        s,
        raw,
        collection_ts=cts,
        run_id=f"{cts - 100 + n}-aaaaaaa{n}",
        ts_ms=cts - 100 + n,
        source_name=SOURCE,
        **gate,
    )


def _carry(s, scopes: runs_exec.CarryScopes) -> dict[str, int]:
    return cyclemod.carry_forward(
        s, PREV, NEW, [SOURCE, "vyos"], scopes=scopes.reasons, collected=scopes.collected, unasked=[]
    )


def _shape(s, cts: int) -> tuple[list[tuple[str, ...]], list[tuple[str, str, str]]]:
    nodes = s.run(
        "MATCH (n:Obj {collection_ts: $cts}) RETURN n.uid AS uid, labels(n) AS labels", cts=cts
    ).data()
    rels = s.run(
        "MATCH (a:Obj {collection_ts: $cts})-[r]->(b:Obj {collection_ts: $cts}) "
        "RETURN type(r) AS t, a.uid AS start, b.uid AS end",
        cts=cts,
    ).data()
    return (
        sorted((n["uid"], *sorted(set(n["labels"]) - {"Latest"})) for n in nodes),
        sorted((r["t"], r["start"], r["end"]) for r in rels),
    )


def _parent(s, core: VyosCollector, edge: VyosCollector) -> None:
    _load(s, core, fixtures._raw("core1", "S1"), PREV, 0)
    _load(s, edge, fixtures._raw("edge1", "S2"), PREV, 1)


def test_a_full_run_then_an_unchanged_one_publish_the_same_graph(session, settings):
    """Both devices' batches digest as the ones on record: each load writes
    its shared objects, and the run holds every node and relationship its
    parent holds, the core router among them."""
    core, edge = _collector(settings, CORE), _collector(settings, EDGE)
    _parent(session, core, edge)
    scopes = runs_exec.CarryScopes()
    for n, (collector, hostname, serial) in enumerate(((core, "core1", "S1"), (edge, "edge1", "S2"))):
        manifest = _load(session, collector, fixtures._raw(hostname, serial), NEW, n, kept=True)
        assert manifest.graph_unchanged and manifest.scope == collector.scope
        scopes.carry(fixtures._unit(collector), cyclemod.UNCHANGED)

    _carry(session, scopes)

    assert cyclemod.cycle_counts(session, NEW) == cyclemod.cycle_counts(session, PREV)
    assert _shape(session, NEW) == _shape(session, PREV)
    core_device = session.run(
        "MATCH (d:Device {uid: 'dev:core1', collection_ts: $cts}) RETURN d._scope AS scope", cts=NEW
    ).single()
    assert core_device is not None and core_device["scope"] == core.scope


def test_a_mixed_run_publishes_what_loading_both_devices_would(session, settings):
    """The edge router lost its policy routes and was loaded in full; the core
    router's batch digested as the one on record. The run holds what a run
    that loaded both batches whole holds."""
    core, edge = _collector(settings, CORE), _collector(settings, EDGE)
    _parent(session, core, edge)
    # the reference: both batches written whole
    _load(session, core, fixtures._raw("core1", "S1"), REF, 0)
    _load(session, edge, fixtures._raw("edge1", "S2", pbr=False), REF, 1)
    scopes = runs_exec.CarryScopes()
    kept = _load(session, core, fixtures._raw("core1", "S1"), NEW, 0, kept=True)
    scopes.carry(fixtures._unit(core), cyclemod.UNCHANGED)
    changed = _load(session, edge, fixtures._raw("edge1", "S2", pbr=False), NEW, 1)
    scopes.ran(fixtures._unit(edge), changed.sections)

    _carry(session, scopes)

    assert kept.graph_unchanged and not changed.graph_unchanged
    assert _shape(session, NEW) == _shape(session, REF)
    assert cyclemod.cycle_counts(session, NEW) == cyclemod.cycle_counts(session, REF)


def test_a_parent_run_that_holds_the_device_under_its_hostname_still_carries_it(session, settings):
    core = _collector(settings, CORE)
    before = fixtures._batch(core, fixtures._raw("core1", "S1")).model_copy(update={"scope": "vyos:core1"})
    load(session, before, collection_ts=PREV, ts_ms=PREV - 100, run_id=f"{PREV - 100}-aaaaaaa0")
    scopes = runs_exec.CarryScopes()
    scopes.carry(fixtures._unit(core), cyclemod.UNCHANGED)
    previous = {
        (SOURCE, CORE): manifests.DeviceEntry(
            source=SOURCE, host=CORE, outcome="collected", device_uids=["dev:core1"], scope=core.scope
        )
    }

    assert cyclemod.written_scopes(session, PREV, [(SOURCE, core.scope, ["dev:core1"])]) == {
        core.scope: ["vyos:core1"]
    }
    runs_exec._name_written_scopes(session, PREV, fixtures._prepared(core), previous, scopes)
    _carry(session, scopes)

    assert scopes.reasons == {core.scope: cyclemod.UNCHANGED, "vyos:core1": cyclemod.UNCHANGED}
    assert _shape(session, NEW) == _shape(session, PREV)
