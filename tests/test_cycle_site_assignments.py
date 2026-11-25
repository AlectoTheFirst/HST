"""Operator site assignment: the Site uid `apply_site_assignments` writes is the
same one every collector mints for the same code.

cisco_common.py, unifi.py and vyos.py all build a device's Site node through
`uid.site(site_code)`, which slugs the code.

The two tests at the bottom of this file cover the coexistence case:
an operator-invented :Meta Site and a later collector-reported Site of the pinned run
sharing a uid. They run against the scratch Neo4j that NEO4J_TEST_URI names.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import uid as uidmod
from hst.core.config import Settings
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord


class _CaptureTx:
    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self._sink = sink

    def run(self, query: str, **params: Any) -> Any:
        self._sink.append({"query": query, "params": params})

        class _Result:
            def data(self) -> list[dict[str, Any]]:
                return [{"n": 1}]

        return _Result()


class _CaptureSession:
    """The part of the driver's Session that `core.cycle._write` uses; it calls
    `session.execute_write(lambda tx: tx.run(query, **params).data())`."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def execute_write(self, work: Any) -> Any:
        return work(_CaptureTx(self.calls))


SNAP = 4242  # the run the assignment materializes onto


def test_apply_site_assignments_mints_the_same_site_uid_a_collector_would() -> None:
    session = _CaptureSession()
    code = "DEU-FRA-123123"

    cyclemod.apply_site_assignments(session, {"dev:1": code}, SNAP)

    ensure = next(c for c in session.calls if "MERGE (m:Site:Obj {uid: row.uid" in c["query"])
    apply_ = next(c for c in session.calls if "MERGE (d)-[li:LOCATED_IN]->(s)" in c["query"])

    # the exact grammar every collector uses for the same code (cisco_common.py,
    # unifi.py, vyos.py all call uid.site(site_code)).
    expected = uidmod.site(code)
    assert expected == "site:deu-fra-123123"
    assert ensure["params"]["sites"] == [{"uid": expected, "code": code}]
    assert apply_["params"]["rows"][0]["site_uid"] == expected


def test_apply_site_assignments_clears_before_reapplying() -> None:
    session = _CaptureSession()
    cyclemod.apply_site_assignments(session, {"dev:1": "hq", "dev:2": None}, SNAP)

    clear = next(c for c in session.calls if "DELETE r" in c["query"])
    assert clear["params"]["rows"] == [{"uid": "dev:1", "site": "hq"}, {"uid": "dev:2", "site": None}]
    # dev:2's code is None (unassignment): it is cleared but never re-applied
    apply_ = next(c for c in session.calls if "MERGE (d)-[li:LOCATED_IN]->(s)" in c["query"])
    assert [r["uid"] for r in apply_["params"]["rows"]] == ["dev:1"]


def test_every_statement_binds_the_run_being_materialized() -> None:
    """`$snap` is the only thing separating a Site of this run from the same
    uid in another run, a collected one or an operator's copy."""
    session = _CaptureSession()

    cyclemod.apply_site_assignments(session, {"dev:1": "hq"}, SNAP)

    assert [c["params"].get("snap") for c in session.calls] == [SNAP] * 3


def test_an_operators_site_is_a_copy_in_the_run_and_nothing_retracts_a_shared_node() -> None:
    """No statement deletes a Site, so a collector that reports the uid in a later run
    cannot take the edges of the runs before it, and no statement matches a Site by uid alone."""
    for query in (
        cyclemod._ENSURE_META_SITES,
        cyclemod._APPLY_ASSIGNMENTS,
        cyclemod._CARRY_META_SITES,
        cyclemod._CARRY_SITES,
    ):
        assert "DELETE" not in query
        assert "Site:Meta {uid" not in query
    assert not hasattr(cyclemod, "_RETRACT_ORPHANED_META_SITES")
    assert "MERGE (m:Site:Obj {uid: row.uid, collection_ts: $snap})" in cyclemod._ENSURE_META_SITES
    assert "_sources = ['app:sites']" in cyclemod._ENSURE_META_SITES
    assert "OPTIONAL MATCH (ls:Site:Obj {uid: row.uid, collection_ts: $snap})" in cyclemod._ENSURE_META_SITES


def test_an_unplaced_device_loses_only_the_edge_an_operator_made() -> None:
    """A device with no operator site is no assertion that it sits nowhere, so the
    edge a collector reported for it (an Equinix Network Edge, a ZIA location) stays."""
    assert "WHERE row.site IS NOT NULL OR r._scope = 'app:sites'" in cyclemod._CLEAR_ASSIGNMENTS
    session = _CaptureSession()

    cyclemod.apply_site_assignments(
        session, {"dev:placed": "hq", "dev:unplaced": None, "dev:blank": ""}, SNAP
    )

    clear = next(c for c in session.calls if "DELETE r" in c["query"])
    assert clear["params"]["rows"] == [
        {"uid": "dev:blank", "site": None},
        {"uid": "dev:placed", "site": "hq"},
        {"uid": "dev:unplaced", "site": None},
    ]


# --- Meta and collected Site reconciliation ---------------------------------------------

URI = os.environ.get("NEO4J_TEST_URI")
_DB_SCOPE = "test:site-assignment-reconciliation"


def _refuse_if_live() -> None:
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This suite deletes data "
            f"in its own scope before and after every test. Point it at a scratch database.",
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
def db_session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup_db(s)
        yield s
        _cleanup_db(s)


def _cleanup_db(s: Any) -> None:
    # an operator's Site copies carry _scope = 'app:sites' (set by _ENSURE_META_SITES), not the
    # batch scope, so both have to be swept.
    s.run("MATCH (n:Obj) WHERE n._scope IN [$s, 'app:sites'] DETACH DELETE n", s=_DB_SCOPE).consume()


def _device_and_site_batch(dev_uid: str, site_uid: str, code: str) -> Batch:
    return Batch(
        source="test",
        scope=_DB_SCOPE,
        nodes=[
            NodeRecord(label="Device", uid=dev_uid, props={"role": "router"}),
            NodeRecord(label="Site", uid=site_uid, props={"code": code}),
        ],
    )


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_apply_assignments_targets_the_collected_site_and_makes_no_copy(db_session) -> None:
    """A collector that reports the site in the run owns it: the assigned device gets exactly one
    LOCATED_IN edge, to the collected node, and the run holds no operator copy beside it."""
    dev_uid, code = "dev:reconcile-1", "hq"
    site_uid = uidmod.site(code)

    load(db_session, _device_and_site_batch(dev_uid, site_uid, code), collection_ts=1000)
    cyclemod.set_pointer(db_session, 1000)

    cyclemod.apply_site_assignments(db_session, {dev_uid: code}, 1000)

    rows = db_session.run(
        "MATCH (d:Device {uid: $u, collection_ts: 1000})-[:LOCATED_IN]->(s:Site) "
        "RETURN s.collection_ts AS cts, s._scope AS scope",
        u=dev_uid,
    ).data()
    assert rows == [{"cts": 1000, "scope": _DB_SCOPE}]
    assert db_session.run("MATCH (s:Site {uid: $u}) RETURN count(s) AS c", u=site_uid).data()[0]["c"] == 1


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_a_later_collector_site_leaves_the_earlier_run_its_operator_copy(db_session) -> None:
    """Assignment applied before any collector reports the site makes the run's own copy;
    a later run in which a collector reports the same code does not touch it. The device of the
    earlier, published run keeps its site, and the later run's device is at the collected one."""
    dev_uid, code = "dev:reconcile-2", "branch-1"
    site_uid = uidmod.site(code)

    load(
        db_session,
        Batch(
            source="test",
            scope=_DB_SCOPE,
            nodes=[NodeRecord(label="Device", uid=dev_uid, props={"role": "router"})],
        ),
        collection_ts=2000,
    )
    cyclemod.set_pointer(db_session, 2000)

    cyclemod.apply_site_assignments(db_session, {dev_uid: code}, 2000)
    before = db_session.run(
        "MATCH (s:Site {uid: $u}) RETURN s.collection_ts AS cts, s._scope AS scope", u=site_uid
    ).data()
    assert before == [{"cts": 2000, "scope": "app:sites"}]  # the copy of run 2000

    # a later collector run reports the device and the same site code
    load(db_session, _device_and_site_batch(dev_uid, site_uid, code), collection_ts=3000)
    cyclemod.set_pointer(db_session, 3000)

    cyclemod.apply_site_assignments(db_session, {dev_uid: code}, 3000)

    after = db_session.run(
        "MATCH (d:Device {uid: $u})-[:LOCATED_IN]->(s:Site) "
        "RETURN d.collection_ts AS dev_cts, s.collection_ts AS site_cts, s._scope AS scope "
        "ORDER BY dev_cts",
        u=dev_uid,
    ).data()
    assert after == [
        {"dev_cts": 2000, "site_cts": 2000, "scope": "app:sites"},
        {"dev_cts": 3000, "site_cts": 3000, "scope": _DB_SCOPE},
    ]


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_migrate_meta_sites_gives_each_run_its_own_copy(db_session) -> None:
    """The unversioned node that every run's device pointed at is split into
    one copy per run, each run's edge follows its copy, and the shared node is gone. A second
    call finds nothing."""
    dev_uid, code = "dev:reconcile-4", "fr5"
    site_uid = uidmod.site(code)
    batch = Batch(
        source="test",
        scope=_DB_SCOPE,
        nodes=[NodeRecord(label="Device", uid=dev_uid, props={"role": "router"})],
    )
    for cts in (6000, 7000):
        load(db_session, batch, collection_ts=cts)
    db_session.run(
        "MERGE (m:Site:Obj:Meta {uid: $u}) ON CREATE SET m.code = $code, m._scope = 'app:sites' "
        "WITH m MATCH (d:Device {uid: $d}) "
        "MERGE (d)-[l:LOCATED_IN]->(m) SET l._scope = 'app:sites', l.collection_ts = d.collection_ts",
        u=site_uid,
        code=code,
        d=dev_uid,
    ).consume()

    assert cyclemod.migrate_meta_sites(db_session) == 1

    rows = db_session.run(
        "MATCH (d:Device {uid: $d})-[l:LOCATED_IN]->(s:Site) "
        "RETURN d.collection_ts AS dev_cts, s.collection_ts AS site_cts, s.code AS code, "
        "l.collection_ts AS edge_cts, 'Meta' IN labels(s) AS meta ORDER BY dev_cts",
        d=dev_uid,
    ).data()
    assert rows == [
        {"dev_cts": 6000, "site_cts": 6000, "code": code, "edge_cts": 6000, "meta": False},
        {"dev_cts": 7000, "site_cts": 7000, "code": code, "edge_cts": 7000, "meta": False},
    ]
    unversioned = db_session.run(
        "MATCH (s:Site:Meta {uid: $u}) WHERE s.collection_ts IS NULL RETURN count(s) AS c", u=site_uid
    ).data()
    assert unversioned[0]["c"] == 0
    assert cyclemod.migrate_meta_sites(db_session) == 0


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_apply_assignments_lands_on_the_named_run_not_the_pointer(db_session) -> None:
    """The run being built names itself, and never the pointer: the assignment
    lands on the run the caller passed."""
    dev_uid, code = "dev:reconcile-3", "hq"
    site_uid = uidmod.site(code)

    load(db_session, _device_and_site_batch(dev_uid, site_uid, code), collection_ts=4000)
    load(db_session, _device_and_site_batch(dev_uid, site_uid, code), collection_ts=5000)
    cyclemod.set_pointer(db_session, 5000)

    assert cyclemod.apply_site_assignments(db_session, {dev_uid: code}, 4000) == 1

    rows = db_session.run(
        "MATCH (d:Device {uid: $u})-[:LOCATED_IN]->(:Site) RETURN d.collection_ts AS cts", u=dev_uid
    ).data()
    assert [r["cts"] for r in rows] == [4000]  # the published run of 5000 is untouched


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_an_unplaced_device_keeps_the_site_a_collector_reported(db_session) -> None:
    """The operator's None removes the edge the operator made and leaves the collector's;
    an operator site replaces the collector's."""
    kept, replaced, code = "dev:reconcile-5", "dev:reconcile-6", "fr5"
    batch = Batch(
        source="test",
        scope=_DB_SCOPE,
        nodes=[
            NodeRecord(label="Device", uid=kept, props={"role": "router"}),
            NodeRecord(label="Device", uid=replaced, props={"role": "router"}),
            NodeRecord(label="Site", uid=uidmod.site(code), props={"code": code}),
        ],
        rels=[
            RelRecord(
                type="LOCATED_IN",
                start_label="Device",
                start_uid=uid,
                end_label="Site",
                end_uid=uidmod.site(code),
            )
            for uid in (kept, replaced)
        ],
    )
    load(db_session, batch, collection_ts=8000)

    cyclemod.apply_site_assignments(db_session, {kept: None, replaced: "hq"}, 8000)

    rows = db_session.run(
        "MATCH (d:Device {collection_ts: 8000})-[:LOCATED_IN]->(s:Site) "
        "WHERE d.uid IN [$a, $b] RETURN d.uid AS uid, s.code AS code ORDER BY uid",
        a=kept,
        b=replaced,
    ).data()
    assert rows == [{"uid": kept, "code": code}, {"uid": replaced, "code": "hq"}]
