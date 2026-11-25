"""tests/test_carry_contributions.py against a real Neo4j: the assertions of
a scope that did not collect, on the objects another load of the run wrote,
are laid over them as loading both sources in one run lays them, run after
run; the relationships it alone wrote come forward; and a scope carried as
unchanged whose uid the run wrote under another anchor fails the carry
(core/cycle.py `carry_forward`).

Opt-in like tests/test_finalize_stream_db.py: set NEO4J_TEST_URI to a scratch
database. The fixture deletes this suite's run keys before and after every
test; every object here is written under one of them, and the keys are this
suite's own.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core.config import Settings
from hst.core.cycle import CARRIED_SCOPES
from hst.core.labels import CycleIdentityCollision
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

PREV, NEW, NEXT, BOTH = 7_330_000_001_000, 7_330_000_002_000, 7_330_000_003_000, 7_330_000_004_000
KEYS = [PREV, NEW, NEXT, BOTH]
APIC, NXOS = "apic:carry-contrib", "nxos:carry-contrib"
SOURCES = {APIC: "fab1", NXOS: "leaves"}
UID, UID_B = "dev:carry-contrib-sn1", "dev:carry-contrib-sn2"


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


def _controller() -> Batch:
    """Two fabric leaves with a field only the controller asserts, and its
    link between them."""
    return Batch(
        source=SOURCES[APIC],
        scope=APIC,
        nodes=[
            NodeRecord(label="Device", uid=uid, props={"name": name, "role": "leaf", "apic_role": "leaf"})
            for uid, name in ((UID, "leaf1"), (UID_B, "leaf2"))
        ],
        rels=[RelRecord(type="CONNECTED_TO", start=["Device", UID], end=["Device", UID_B])],
    )


def _device() -> Batch:
    """The same two leaves as the device source reads them, each with an
    interface of its own."""
    nodes, rels = [], []
    for uid, name in ((UID, "leaf1"), (UID_B, "leaf2")):
        iface = f"if:{uid}:eth1"
        nodes.append(
            NodeRecord(label="Device", uid=uid, props={"name": name, "role": "switch", "os": "10.3"})
        )
        nodes.append(NodeRecord(label="Interface", uid=iface, props={"name": "eth1"}))
        rels.append(RelRecord(type="ON", start=["Interface", iface], end=["Device", uid]))
    return Batch(source=SOURCES[NXOS], scope=NXOS, nodes=nodes, rels=rels)


BATCHES = {APIC: _controller, NXOS: _device}


def _load(s, batch: Batch, cts: int) -> None:
    load(s, batch, collection_ts=cts, ts_ms=cts - 100, run_id=f"carry-contrib-{cts}-{batch.source}")


def _props(s, cts: int, uid: str = UID) -> dict[str, Any]:
    record = s.run(
        "MATCH (n:Obj {uid: $uid, collection_ts: $cts}) RETURN properties(n) AS p", uid=uid, cts=cts
    )
    return dict(record.single()["p"])


# Different by construction between a run that loaded both sources and one
# that carried one of them: the run key, the load and its time, the first
# writer, and the carry's own record of what it laid.
_NOT_COMPARED = ("collection_ts", "collected_at", "_run_id", "carried", "_scope", CARRIED_SCOPES)


def _compared(props: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in props.items() if k not in _NOT_COMPARED}
    out["_sources"] = sorted(out.get("_sources") or [])
    return out


def _links(s, cts: int) -> list[tuple[str, str, str]]:
    rows = s.run(
        "MATCH (a:Obj {collection_ts: $cts})-[r]->(b:Obj {collection_ts: $cts}) "
        "RETURN type(r) AS t, a.uid AS start, b.uid AS end",
        cts=cts,
    ).data()
    return sorted((r["t"], r["start"], r["end"]) for r in rows)


@pytest.mark.parametrize("carried", [APIC, NXOS], ids=["controller-carried", "device-carried"])
def test_a_carried_scope_keeps_its_assertions_as_loading_both_gives_run_after_run(session, carried):
    """The controller writes each leaf first, in the parent run and in the
    run that loads both. Carried, the controller is found as a leaf's first
    writer and, a run later, by what the first carry laid; the device, which
    wrote each leaf second, by the relationships of its interfaces."""
    collected = NXOS if carried == APIC else APIC
    for cts in (PREV, BOTH):
        _load(session, _controller(), cts)
        _load(session, _device(), cts)
    for prev, cts in ((PREV, NEW), (NEW, NEXT)):
        _load(session, BATCHES[collected](), cts)
        cyclemod.carry_forward(
            session,
            prev,
            cts,
            [SOURCES[carried]],
            scopes={carried: cyclemod.UNCHANGED},
            collected=[collected],
            unasked=[],
        )

    for cts in (NEW, NEXT):
        for uid in (UID, UID_B):
            carried_props, loaded = _props(session, cts, uid), _props(session, BOTH, uid)
            assert _compared(carried_props) == _compared(loaded), (cts, uid)
            assert carried_props[CARRIED_SCOPES] == [f"{SOURCES[carried]}/{carried}"]
            assert not carried_props["carried"]
        assert _links(session, cts) == _links(session, BOTH)
    loaded = _props(session, BOTH)
    assert (loaded["role"], loaded["apic_role"], loaded["os"]) == ("switch", "leaf", "10.3")
    assert len(loaded["_assert.role"]) == 2


def _anchored(s, scope: str, cts: int, anchor: str, laid: list[str] | None = None) -> None:
    s.run(
        "CREATE (n:Obj:Prefix:L3 {uid: 'pfx:carry-contrib', collection_ts: $cts, _scope: $scope, "
        "_sources: [$source], anchor: $anchor, carried: false}) SET n._carried_scopes = $laid",
        cts=cts,
        scope=scope,
        source=SOURCES.get(scope, "edge"),
        anchor=anchor,
        laid=laid,
    ).consume()


@pytest.mark.parametrize("laid", [False, True], ids=["first-writer", "laid-by-a-carry"])
def test_an_unchanged_scope_whose_uid_was_written_under_another_anchor_fails_the_carry(session, laid):
    if laid:
        _anchored(session, "iosxe:carry-contrib", PREV, "vrf:a", laid=[f"{SOURCES[APIC]}/{APIC}"])
    else:
        _anchored(session, APIC, PREV, "vrf:a")
    _anchored(session, NXOS, NEW, "vrf:b")

    with pytest.raises(CycleIdentityCollision, match="pfx:carry-contrib"):
        cyclemod.carry_forward(
            session, PREV, NEW, ["fab1"], scopes={APIC: cyclemod.UNCHANGED}, collected=[NXOS], unasked=[]
        )


@pytest.mark.parametrize(("carried", "fresh"), [(APIC, NXOS), (NXOS, APIC)], ids=["configured", "observed"])
def test_a_scope_that_did_not_answer_yields_its_anchor_to_the_fresh_write(session, carried, fresh):
    _anchored(session, carried, PREV, "vrf:a")
    _anchored(session, fresh, NEW, "vrf:b")

    cyclemod.carry_forward(
        session, PREV, NEW, [SOURCES[carried]], scopes={carried: "failed"}, collected=[fresh], unasked=[]
    )

    props = session.run(
        "MATCH (n:Obj {uid: 'pfx:carry-contrib', collection_ts: $cts}) RETURN properties(n) AS p", cts=NEW
    ).single()["p"]
    assert (props["anchor"], props["_sources"]) == ("vrf:b", [SOURCES[fresh]])
    assert not any(k.startswith("_assert.") for k in props)
