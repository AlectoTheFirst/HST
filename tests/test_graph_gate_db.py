"""A batch that digests as the batch on record, against a real Neo4j
(collectors/base.py `load_payload` with a `GraphGate`, core/cycle.py
`carry_forward`).

The load writes the objects another writer shares and the objects that carry
an anchor, and the carry brings the rest forward from the parent run. On the
objects two writers share, what the run holds is what a load of the whole
batch leaves: the kept device's properties, its assertions and its entry in
`_sources`. And a load of another batch that declares one of the kept
device's anchored uids under another anchor fails, whichever of the two
loads comes first.

Opt-in like tests/test_snapshot_db.py: set NEO4J_TEST_URI to a scratch
database. The fixture deletes this suite's run keys before and after every
test; every object here is written under one of them.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from hst.app.crypto import generate_key
from hst.collectors import base as collectors_base
from hst.collectors.base import Collector, GraphGate, SourceConfig
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import uid
from hst.core.config import Settings
from hst.core.labels import CycleIdentityCollision
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

PREV, FULL, KEPT = 7_320_000_001_000, 7_320_000_002_000, 7_320_000_003_000
KEYS = [PREV, FULL, KEPT]

FABRIC, LEAVES = "gatetest-fab", "gatetest-leaves"
APIC, LEAF1, LEAF2 = "apic:gatetest", "nxos:gatetest-leaf1", "nxos:gatetest-leaf2"
DEV1, DEV2 = "dev:gatetest1", "dev:gatetest2"
PORT = uid.port(DEV1, "Ethernet1/1")
IFACE = uid.interface(DEV1, "Ethernet1/1")
BD = uid.bridge_domain("gatetest", 10)
ANCHOR, FOLDED = f"vrf:{DEV1}:default", f"vrf/{DEV1}/default"
PREFIX = uid.prefix(ANCHOR, "10.0.0.0/24")
ADDRESS = uid.ip(ANCHOR, "10.0.0.1")


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


def _apic(role: str) -> Batch:
    """The controller's view of the leaf: the device and its port."""
    return Batch(
        source=FABRIC,
        scope=APIC,
        nodes=[
            NodeRecord(label="Device", uid=DEV1, props={"role": role, "model": "N9K-C93180YC-EX"}),
            NodeRecord(label="Port", uid=PORT, props={"name": "eth1/1"}),
        ],
        rels=[RelRecord(type="ON", start=["Port", PORT], end=["Device", DEV1])],
    )


def _leaf1() -> Batch:
    """The leaf's own view: the device and the port the controller also
    writes, the broadcast domain the other leaf also declares, and its own
    interface, VLAN and connected addressing."""
    vlan = uid.vlan(LEAF1, 10)
    return Batch(
        source=LEAVES,
        scope=LEAF1,
        nodes=[
            NodeRecord(
                label="Device", uid=DEV1, props={"role": "router", "vendor": "cisco", "hostname": "leaf1"}
            ),
            NodeRecord(label="Port", uid=PORT, props={"name": "Ethernet1/1", "lldp_neighbor_name": "spine1"}),
            NodeRecord(label="Interface", uid=IFACE, props={"name": "Ethernet1/1", "mtu": 9216}),
            NodeRecord(label="VlanInstance", uid=vlan, props={"vid": 10}),
            NodeRecord(label="BridgeDomain", uid=BD, props={"name": "users-leaf1"}),
            NodeRecord(label="IpAddress", uid=ADDRESS, props={"ip": "10.0.0.1", "af": 4, "anchor": ANCHOR}),
            NodeRecord(label="Prefix", uid=PREFIX, props={"cidr": "10.0.0.0/24", "af": 4, "anchor": ANCHOR}),
        ],
        rels=[
            RelRecord(type="ON", start=["Port", PORT], end=["Device", DEV1]),
            RelRecord(type="ON", start=["Interface", IFACE], end=["Device", DEV1]),
            RelRecord(type="HAS_PORT", start=["Interface", IFACE], end=["Port", PORT]),
            RelRecord(type="REALIZES", start=["VlanInstance", vlan], end=["BridgeDomain", BD]),
            RelRecord(type="HAS_IP", start=["Interface", IFACE], end=["IpAddress", ADDRESS]),
            RelRecord(type="IN", start=["IpAddress", ADDRESS], end=["Prefix", PREFIX]),
        ],
    )


def _leaf2() -> Batch:
    vlan = uid.vlan(LEAF2, 10)
    return Batch(
        source=LEAVES,
        scope=LEAF2,
        nodes=[
            NodeRecord(label="Device", uid=DEV2, props={"role": "router", "hostname": "leaf2"}),
            NodeRecord(label="VlanInstance", uid=vlan, props={"vid": 10}),
            NodeRecord(label="BridgeDomain", uid=BD, props={"name": "users-leaf2"}),
        ],
        rels=[RelRecord(type="REALIZES", start=["VlanInstance", vlan], end=["BridgeDomain", BD])],
    )


def _folded(scope: str) -> Batch:
    """Another device's batch declaring the leaf's prefix uid under an anchor
    that folds onto the same uid."""
    assert uid.prefix(FOLDED, "10.0.0.0/24") == PREFIX
    return Batch(
        source=LEAVES,
        scope=scope,
        nodes=[
            NodeRecord(label="Prefix", uid=PREFIX, props={"cidr": "10.0.0.0/24", "af": 4, "anchor": FOLDED})
        ],
    )


class _Fixed(Collector):
    """Normalizes to the batch it was built with; no side tables."""

    name = "nxos"
    KIND = "group"
    ConfigModel = SourceConfig

    def __init__(self, batch: Batch, settings: Settings) -> None:
        super().__init__(SourceConfig(source_name=batch.source), settings)
        self.scope = batch.scope
        self.batch = batch

    def fetch(self) -> Any:
        return {}

    def normalize(self, raw: Any) -> Batch:
        return self.batch.model_copy(deep=True)

    def probe(self) -> str:
        return "ok"


def _load(s, batch: Batch, cts: int, n: int) -> None:
    load(s, batch, collection_ts=cts, ts_ms=cts - 100 + n, run_id=f"gatetest-{cts}-{n}")


def _keep(s, batch: Batch, cts: int, settings: Settings) -> Any:
    """`load_payload` of a batch whose digest is the one on record."""
    return collectors_base.load_payload(
        _Fixed(batch, settings),
        s,
        {},
        collection_ts=cts,
        run_id=f"{cts - 50}-aaaaaaaa",
        ts_ms=cts - 50,
        source_name=batch.source,
        graph_gate=GraphGate(lambda digest: True, PREV),
    )


@pytest.fixture()
def settings(tmp_path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


# Written by the load and the carry, and so different by construction between
# a run that wrote an object and a run that carried it.
_BOOKKEEPING = ("collection_ts", "collected_at", "_run_id", "carried", "carried_reason", "last_seen_ts")


def _state(s, cts: int, node: str) -> dict[str, Any]:
    props = s.run(
        "MATCH (n:Obj {uid: $uid, collection_ts: $cts}) RETURN properties(n) AS p", uid=node, cts=cts
    ).single()["p"]
    state = {k: v for k, v in props.items() if k not in _BOOKKEEPING}
    state["_sources"] = sorted(state.get("_sources") or [])
    return state


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
        sorted((n["uid"], *sorted(n["labels"])) for n in nodes),
        sorted((r["t"], r["start"], r["end"]) for r in rels),
    )


def _parent(s) -> None:
    for n, batch in enumerate((_apic("leaf"), _leaf1(), _leaf2())):
        _load(s, batch, PREV, n)


def test_a_kept_batch_leaves_the_shared_objects_as_a_load_of_the_whole_batch_does(session, settings):
    """The controller's answer changed and the leaf's did not. Every object
    the two runs hold, and every relationship, is the same; on the device, the
    port and the broadcast domain the state is the same to the assertion; and
    the leaf's own objects came forward from the parent run."""
    _parent(session)
    # the reference: every batch written whole
    for n, batch in enumerate((_apic("border-leaf"), _leaf1(), _leaf2())):
        _load(session, batch, FULL, n)
    # the leaf's batch digested as the one on record
    _load(session, _apic("border-leaf"), KEPT, 0)
    manifest = _keep(session, _leaf1(), KEPT, settings)
    _load(session, _leaf2(), KEPT, 2)
    cyclemod.carry_forward(
        session,
        PREV,
        KEPT,
        [FABRIC, LEAVES],
        scopes={LEAF1: "unchanged"},
        collected=[APIC, LEAF2],
        unasked=[],
    )

    assert manifest.graph_unchanged
    assert _shape(session, KEPT) == _shape(session, FULL)
    for shared in (DEV1, PORT, BD, ADDRESS, PREFIX):
        assert _state(session, KEPT, shared) == _state(session, FULL, shared), shared
    device = _state(session, KEPT, DEV1)
    assert device["_sources"] == sorted([FABRIC, LEAVES])
    assert device["role"] == "router" and device["vendor"] == "cisco"
    assert len(device["_assert.role"]) == 2
    # the leaf's own objects are the parent run's, marked as such
    for own in (IFACE, uid.vlan(LEAF1, 10)):
        carried = session.run(
            "MATCH (n:Obj {uid: $uid, collection_ts: $cts}) RETURN n.carried AS c, n.carried_reason AS r",
            uid=own,
            cts=KEPT,
        ).single()
        assert (carried["c"], carried["r"]) == (True, "unchanged"), own


@pytest.mark.parametrize("folded_first", [False, True], ids=["kept-first", "other-first"])
def test_an_anchor_folding_onto_a_kept_batchs_uid_fails_whichever_load_comes_first(
    session, settings, folded_first
):
    _parent(session)
    other = _folded(LEAF2)

    with pytest.raises(CycleIdentityCollision):
        if folded_first:
            _load(session, other, KEPT, 2)
            _keep(session, _leaf1(), KEPT, settings)
        else:
            _keep(session, _leaf1(), KEPT, settings)
            _load(session, other, KEPT, 2)
