"""A run that carries a device keeps the device at its site.

LOCATED_IN is written per run. A run that carries a device forward (a device
run, a refresh, a source that failed) resolves sites only for what it collected
or what has pending intent. Every other carried device keeps the site of its
previous copy (core/cycle.py carry_site_assignments).

The db tests run against a real Neo4j as tests/test_cycle_site_assignments.py
does: opt in with NEO4J_TEST_URI to a scratch database; skipped otherwise.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import finalize
from hst.core import uid as uidmod
from hst.core.config import Settings
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord


class _CaptureTx:
    def __init__(self, sink: list[dict[str, Any]]) -> None:
        self._sink = sink

    def run(self, query: str, **params: Any) -> Any:
        self._sink.append({"query": query, "params": params})

        class _Result:
            def data(self) -> list[dict[str, Any]]:
                return [{"n": 2}]

        return _Result()


class _CaptureSession:
    def __init__(self, previous_run: int | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.reads: list[dict[str, Any]] = []
        self.previous_run = previous_run

    def execute_read(self, work: Any) -> Any:
        previous_run = self.previous_run

        class _ReadTx:
            def __init__(self, sink: list[dict[str, Any]]) -> None:
                self._sink = sink

            def run(self, query: str, **params: Any) -> Any:
                self._sink.append({"query": query, "params": params})

                class _Result:
                    def data(self) -> list[dict[str, Any]]:
                        return [{"prev": previous_run}]

                return _Result()

        return work(_ReadTx(self.reads))

    def execute_write(self, work: Any) -> Any:
        return work(_CaptureTx(self.calls))


def test_the_carry_binds_the_run_and_leaves_every_resolved_device_out() -> None:
    session = _CaptureSession()

    n = cyclemod.carry_site_assignments(session, {"dev:b": "hq", "dev:a": None}, 4242, parent=4100)

    assert n == 2
    made, call = session.calls
    assert made["query"] == cyclemod._CARRY_META_SITES
    assert made["params"] == call["params"]
    assert call["params"] == {"resolved": ["dev:a", "dev:b"], "snap": 4242, "parent": 4100}
    assert "coalesce(d.carried, false)" in call["query"]
    assert "(p:Device:Obj {uid: d.uid, collection_ts: $parent})" in call["query"]
    assert "ORDER BY" not in call["query"]


def test_the_carry_reads_the_copy_in_the_runs_parent_when_it_is_given() -> None:
    """A build that failed after its carry leaves a copy newer than the parent."""
    session = _CaptureSession()

    cyclemod.carry_site_assignments(session, {"dev:a": None}, 4242, 4000)

    assert len(session.calls) == 2
    for call in session.calls:
        assert call["params"] == {"resolved": ["dev:a"], "snap": 4242, "parent": 4000}
        assert "(p:Device:Obj {uid: d.uid, collection_ts: $parent})" in call["query"]


def test_the_carry_without_a_parent_reads_the_copy_in_the_newest_earlier_run() -> None:
    """A caller that names no parent (a replay) carries from the newest run
    before this one, read by its run node."""
    session = _CaptureSession(previous_run=4100)
    cyclemod.carry_site_assignments(session, {}, 4242)
    (read,) = session.reads
    assert read["params"] == {"snap": 4242} and "CycleRun" in read["query"]
    assert all(c["params"]["parent"] == 4100 and "ORDER BY" not in c["query"] for c in session.calls)


def test_the_carry_without_any_earlier_run_writes_nothing() -> None:
    session = _CaptureSession(previous_run=None)
    assert cyclemod.carry_site_assignments(session, {}, 4242) == 0
    assert session.calls == []


def test_the_finalize_step_hands_the_parent_to_the_carry(tmp_path) -> None:
    calls: list[tuple[Any, ...]] = []

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

        def carry_site_assignments(
            self, session: Any, resolved: Any, cts: int, parent: int | None = None
        ) -> int:
            calls.append((cts, parent))
            return 0

    class _Quiet:
        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

        def execute(self, *a: Any, **k: Any) -> Any:
            from hst.core.model import RunManifest

            return RunManifest(run_id="x", source="reasoner", scope="x")

        execute_rt_domains = execute_link_speed = execute

    finalize.finalize_derivations(
        object(),
        Settings(_env_file=None, hst_data_dir=tmp_path),
        7,
        {},
        rules=_Quiet(),
        route_targets=_Quiet(),
        cycle=_Cycle(),
        parent=5,
    )

    assert calls == [(7, 5)]


def test_the_finalize_step_carries_after_it_applies_the_assignments(tmp_path) -> None:
    from hst.core.model import RunManifest

    calls: list[tuple[str, Any, int | None]] = []

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            calls.append(("apply", dict(assigned), cts))
            return 0

        def carry_site_assignments(self, session: Any, resolved: Any, cts: int) -> int:
            calls.append(("carry", dict(resolved), cts))
            return 0

    class _RouteTargets:
        def execute(self, session: Any, settings: Any, collection_ts: int | None = None) -> RunManifest:
            return RunManifest(run_id="rt-i", source="reasoner", scope="rt-imports")

        def execute_rt_domains(
            self, session: Any, settings: Any, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

        def execute_link_speed(
            self, session: Any, settings: Any, collection_ts: int | None = None
        ) -> RunManifest:
            return RunManifest(run_id="ls", source="reasoner", scope="link-speed")

    class _Rules:
        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            return []

    assigned = {"dev:core1": "hq"}
    finalize.finalize_derivations(
        object(),
        Settings(_env_file=None, hst_data_dir=tmp_path),
        7,
        assigned,
        rules=_Rules(),
        route_targets=_RouteTargets(),
        cycle=_Cycle(),
    )

    assert [c[0] for c in calls] == ["apply", "carry"]
    assert calls[1] == ("carry", assigned, 7)


# --- against a real Neo4j ------------------------------------------------------------------

URI = os.environ.get("NEO4J_TEST_URI")
_DB_SCOPE = "test:carried-site-edges"


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
    s.run("MATCH (n:Obj) WHERE n._scope IN [$s, 'app:sites'] DETACH DELETE n", s=_DB_SCOPE).consume()


def _run(cts: int, devices: dict[str, bool], site_uid: str, code: str) -> Batch:
    """One run of the devices (uid to carried) and the site."""
    nodes = [NodeRecord(label="Site", uid=site_uid, props={"code": code})]
    nodes += [
        NodeRecord(label="Device", uid=uid, props={"role": "switch", "carried": carried})
        for uid, carried in devices.items()
    ]
    return Batch(source="test", scope=_DB_SCOPE, nodes=nodes)


def _mark_carried(s: Any, uids: list[str], cts: int) -> None:
    """The loader clears `carried` on what it writes; the carry step of a run stamps
    it on the copies it brings forward. Stamp it as that step does."""
    s.run(
        "MATCH (d:Device) WHERE d.uid IN $uids AND d.collection_ts = $c SET d.carried = true",
        uids=uids,
        c=cts,
    ).consume()


def _site_of(s: Any, uid: str, cts: int) -> list[str]:
    rows = s.run(
        "MATCH (d:Device {uid: $u, collection_ts: $c})-[:LOCATED_IN]->(x:Site) RETURN x.code AS code",
        u=uid,
        c=cts,
    ).data()
    return [r["code"] for r in rows]


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_a_device_run_keeps_the_site_of_every_device_it_carries(db_session) -> None:
    code = "hq"
    site_uid = uidmod.site(code)
    sw, core, gone = "dev:carry-sw", "dev:carry-core", "dev:carry-gone"

    # the cycle: every device collected and placed
    load(db_session, _run(1000, {sw: False, core: False, gone: False}, site_uid, code), collection_ts=1000)
    cyclemod.apply_site_assignments(db_session, {sw: code, core: code, gone: code}, 1000)

    # the device run: core collected and resolved; sw carried, not resolved;
    # gone carried, but the run resolved it to no site
    load(db_session, _run(2000, {sw: True, core: False, gone: True}, site_uid, code), collection_ts=2000)
    _mark_carried(db_session, [sw, gone], 2000)
    cyclemod.apply_site_assignments(db_session, {core: code, gone: None}, 2000)
    # the run builder names the run the carried copies came from
    carried = cyclemod.carry_site_assignments(db_session, {core: code, gone: None}, 2000, parent=1000)

    assert carried == 1
    assert _site_of(db_session, sw, 2000) == [code]
    assert _site_of(db_session, core, 2000) == [code]
    assert _site_of(db_session, gone, 2000) == []

    # the next device run carries it again from the run before
    load(db_session, _run(3000, {sw: True, core: False, gone: True}, site_uid, code), collection_ts=3000)
    _mark_carried(db_session, [sw, gone], 3000)
    cyclemod.apply_site_assignments(db_session, {core: code, gone: None}, 3000)
    cyclemod.carry_site_assignments(db_session, {core: code, gone: None}, 3000, parent=2000)

    assert _site_of(db_session, sw, 3000) == [code]
    assert _site_of(db_session, gone, 3000) == []


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_a_carried_device_keeps_an_operators_site_that_no_collector_reports(db_session) -> None:
    """The operator's site is a copy per run: the carried device is pointed at a copy made in its
    run, the run before it keeps its own, and a run that no longer has the device at the site
    holds no copy of it."""
    code = "fr5"
    dev = "dev:carry-meta"
    batch = Batch(
        source="test",
        scope=_DB_SCOPE,
        nodes=[NodeRecord(label="Device", uid=dev, props={"role": "switch"})],
    )

    load(db_session, batch, collection_ts=1000)
    cyclemod.apply_site_assignments(db_session, {dev: code}, 1000)

    load(db_session, batch, collection_ts=2000)
    _mark_carried(db_session, [dev], 2000)
    cyclemod.apply_site_assignments(db_session, {}, 2000)
    assert cyclemod.carry_site_assignments(db_session, {}, 2000, parent=1000) == 1

    assert _site_of(db_session, dev, 1000) == [code]
    assert _site_of(db_session, dev, 2000) == [code]
    copies = db_session.run(
        "MATCH (s:Site {uid: $u}) RETURN s.collection_ts AS cts ORDER BY cts", u=uidmod.site(code)
    ).data()
    assert [r["cts"] for r in copies] == [1000, 2000]
