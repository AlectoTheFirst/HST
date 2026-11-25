"""Run model against a real Neo4j: versioned loads, the pointer, carry-forward,
diff, and retention.

Opt-in like tests/test_integration_db.py: set NEO4J_TEST_URI to a scratch
database. The fixture deletes this suite's scopes before and after every test.
"""

import os

import pytest

from hst import path as pathmod
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core.config import Settings
from hst.core.diff import diff_snapshots
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

SCOPE = "cycle-test"


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


def _cleanup(s):
    # STARTS WITH as well as the exact match: the per-device scopes below are
    # `<SCOPE>:<host>`, the shape a fleet collector stamps
    s.run(
        "MATCH (n:Obj) WHERE n._scope IN ['meta:cycles', 'meta:cycle', 'meta:runs'] "
        "OR n._scope STARTS WITH $s DETACH DELETE n",
        s=SCOPE,
    ).consume()


def _batch(source: str, *devices: tuple[str, str]) -> Batch:
    """devices: (uid, role). One ON relationship per device from a shared
    interface-per-device keeps the rel path covered too."""
    nodes = []
    rels = []
    for uid, role in devices:
        nodes.append(NodeRecord(label="Device", uid=uid, props={"role": role, "name": uid}))
        if_uid = f"if:{uid}:eth0"
        nodes.append(NodeRecord(label="Interface", uid=if_uid, props={"name": "eth0"}))
        rels.append(
            RelRecord(
                rel_type="ON",
                start_label="Interface",
                start_uid=if_uid,
                end_label="Device",
                end_uid=uid,
            )
        )
    return Batch(source=source, scope=SCOPE, nodes=nodes, rels=rels)


def _load_cycle(
    s,
    cts: int,
    statuses: dict[str, str],
    *batches: Batch,
    carry_from: int | None = None,
    kind: str = "full",
    parent: int | None = None,
    also_carry: tuple[str, ...] = (),
):
    """Build one run the way app/runs_exec.py does: load, carry, count, write the
    meta node, and move the pointer last."""
    for b in batches:
        load(s, b, collection_ts=cts)
    carried = sorted({n for n, v in statuses.items() if v != "fresh"} | set(also_carry))
    if carried and carry_from is not None:
        cyclemod.carry_forward(s, carry_from, cts, carried)
    counts = cyclemod.cycle_counts(s, cts)
    cyclemod.write_cycle_meta(
        s,
        cts,
        statuses=statuses,
        carried_from=carry_from,
        nodes=counts["nodes"],
        rels=counts["rels"],
        degraded=False,
        kind=kind,
        parent=parent if parent is not None else carry_from,
    )
    cyclemod.set_pointer(s, cts)


def test_two_cycles_diff_and_pinned_reads(session):
    _load_cycle(session, 1000, {"a": "fresh"}, _batch("a", ("dev:s1", "router")))
    _load_cycle(session, 2000, {"a": "fresh"}, _batch("a", ("dev:s1", "firewall"), ("dev:s2", "router")))

    assert cyclemod.current_ts(session) == 2000
    listing, truncated = cyclemod.list_cycles(session)
    assert [row["id"] for row in listing][:2] == ["2000", "1000"]
    assert truncated is False

    out = diff_snapshots(session, 1000, 2000)
    assert out["counts"]["nodes"]["added"] == 2  # dev:s2 and its interface
    assert out["counts"]["nodes"]["changed"] == 1
    assert out["nodes"]["changed"][0]["changes"] == {"role": ["router", "firewall"]}

    # the pointer answers current-state queries with exactly one version
    rows = session.run(
        "MATCH (d:Device {uid: 'dev:s1', collection_ts: $cts}) RETURN d.role AS role",
        cts=cyclemod.current_ts(session),
    ).data()
    assert [r["role"] for r in rows] == ["firewall"]

    # a tracer-style guarded read pins per run through the one $snap parameter
    q = "MATCH (d:Device {uid: $u}) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d.role AS role"
    for cts, expected in ((1000, "router"), (2000, "firewall")):
        rows = pathmod._read(pathmod.CycleSession(session, cts), q, u="dev:s1")
        assert [r["role"] for r in rows] == [expected]


def test_the_parent_runs_observation_time_is_readable_per_device_scope(session):
    """The comparison a parked payload has to beat before a device run applies it
    (app/runs_exec.py `build_device_run`): the device's observation time in the
    run being built on. `collected_at` is the fetch time the loader stamps, and
    carry-forward copies it verbatim, so it stays readable off the parent run
    however many runs the device goes uncollected."""
    devices = Batch(
        source="edge",
        scope=f"{SCOPE}:r1",
        nodes=[NodeRecord(label="Device", uid="dev:r1", props={"role": "router"})],
    )
    load(session, devices, collection_ts=1000, ts_ms=1500)

    assert cyclemod.scope_collected_at(session, 1000, f"{SCOPE}:r1") == 1500
    assert cyclemod.scope_collected_at(session, 1000, f"{SCOPE}:r9") is None

    cyclemod.carry_forward(session, 1000, 2000, ["edge"])
    assert cyclemod.scope_collected_at(session, 2000, f"{SCOPE}:r1") == 1500


def test_a_pinned_read_across_a_refresh_answers_from_one_run(session):
    _load_cycle(session, 1000, {"a": "fresh"}, _batch("a", ("dev:f1", "router"), ("dev:f2", "router")))
    pinned = pathmod.CycleSession(session, 1000)
    q = (
        "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap "
        "RETURN d.uid AS uid, d.role AS role ORDER BY uid"
    )

    before = pathmod._read(pinned, q)

    _load_cycle(
        session,
        2000,
        {"a": "fresh"},
        _batch("a", ("dev:f1", "firewall")),
        carry_from=1000,
        kind="refresh",
    )
    assert cyclemod.current_ts(session) == 2000

    # a new session pinned to the same run: a CycleSession caches its reads,
    # and this read must come from the graph
    after = pathmod._read(pathmod.CycleSession(session, 1000), q)
    assert before == after
    assert [(r["uid"], r["role"]) for r in after] == [("dev:f1", "router"), ("dev:f2", "router")]


def test_carry_forward_marks_and_completes_the_run(session):
    _load_cycle(
        session,
        1000,
        {"a": "fresh", "b": "fresh"},
        _batch("a", ("dev:a1", "router")),
        _batch("b", ("dev:b1", "router")),
    )
    # source b does not run in cycle 2000; its objects are carried
    _load_cycle(
        session,
        2000,
        {"a": "fresh", "b": "carried"},
        _batch("a", ("dev:a1", "router")),
        carry_from=1000,
    )
    rows = session.run(
        "MATCH (d:Device {collection_ts: $cts}) "
        "RETURN d.uid AS uid, d.carried AS carried, d.collection_ts AS cts ORDER BY uid",
        cts=cyclemod.current_ts(session),
    ).data()
    assert [(r["uid"], r["carried"], r["cts"]) for r in rows] == [
        ("dev:a1", False, 2000),
        ("dev:b1", True, 2000),
    ]
    # the carried device keeps its relationship, marked the same way
    rel = session.run(
        "MATCH (:Interface {uid: 'if:dev:b1:eth0', collection_ts: 2000})"
        "-[r:ON]->(:Device {uid: 'dev:b1', collection_ts: 2000}) "
        "RETURN r.carried AS carried"
    ).data()
    assert [r["carried"] for r in rel] == [True]
    _load_cycle(
        session,
        3000,
        {"a": "fresh", "b": "carried"},
        _batch("a"),
        carry_from=2000,
    )
    gone = session.run(
        "MATCH (d:Device {uid: 'dev:a1', collection_ts: $cts}) RETURN d",
        cts=cyclemod.current_ts(session),
    ).data()
    assert gone == []


def test_carry_matches_row_and_type_names_and_keeps_ownerless_objects(session):
    _load_cycle(session, 1000, {"vyos1": "fresh"}, _batch("vyos", ("dev:v1", "router")))
    session.run(
        "CREATE (s:Obj:Site:Phys {uid: 'site:hq', name: 'hq', collection_ts: 1000, _scope: $s})",
        s=SCOPE,
    ).consume()

    # The carry ids hold the row name and the type name, as execute_cycle builds them.
    counts = cyclemod.carry_forward(session, 1000, 2000, ["reasoner", "vyos", "vyos1"])
    cyclemod.set_pointer(session, 2000)
    assert counts["nodes"] == 3  # device + interface (stamped 'vyos') + ownerless site
    rows = session.run(
        "MATCH (n:Obj {collection_ts: 2000}) RETURN n.uid AS uid, n.carried AS carried ORDER BY uid"
    ).data()
    assert [(r["uid"], r["carried"]) for r in rows] == [
        ("dev:v1", True),
        ("if:dev:v1:eth0", True),
        ("site:hq", True),
    ]


def test_a_refresh_publishes_a_new_run_and_leaves_its_parent_alone(session):
    _load_cycle(
        session,
        1000,
        {"a": "fresh", "b": "fresh"},
        _batch("a", ("dev:a1", "router"), ("dev:a2", "router")),
        _batch("b", ("dev:b1", "router")),
    )
    # the press: source a now reports only a1, with a changed role; b is carried
    _load_cycle(
        session,
        2000,
        {"a": "fresh", "b": "carried"},
        _batch("a", ("dev:a1", "firewall")),
        carry_from=1000,
        kind="refresh",
    )

    assert cyclemod.current_ts(session) == 2000
    rows, _ = cyclemod.list_cycles(session)
    assert [(r["id"], r["kind"], r["parent"]) for r in rows] == [
        ("2000", "refresh", 1000),
        ("1000", "full", None),
    ]

    current = session.run(
        "MATCH (d:Device {collection_ts: 2000}) RETURN d.uid AS uid, d.role AS role, "
        "d.carried AS carried ORDER BY uid"
    ).data()
    assert [(r["uid"], r["role"], r["carried"]) for r in current] == [
        ("dev:a1", "firewall", False),
        ("dev:b1", "router", True),
    ]

    parent = session.run(
        "MATCH (d:Device {collection_ts: 1000}) RETURN d.uid AS uid, d.role AS role ORDER BY uid"
    ).data()
    assert [(r["uid"], r["role"]) for r in parent] == [
        ("dev:a1", "router"),
        ("dev:a2", "router"),
        ("dev:b1", "router"),
    ]


def test_a_device_run_carries_everything_it_did_not_fetch(session):
    """One window of per-device fetches publishes one run: the devices that were
    fetched are fresh under the new key, and every other device and source comes
    forward carried."""
    _load_cycle(
        session,
        1000,
        {"edge": "fresh", "b": "fresh"},
        _batch("edge", ("dev:r1", "router"), ("dev:r2", "router")),
        _batch("b", ("dev:b1", "router")),
    )
    _load_cycle(
        session,
        2000,
        {"edge": "fresh", "b": "carried"},
        _batch("edge", ("dev:r1", "firewall")),
        carry_from=1000,
        kind="device",
        also_carry=("edge",),
    )

    rows = session.run(
        "MATCH (d:Device {collection_ts: 2000}) RETURN d.uid AS uid, d.role AS role, "
        "d.carried AS carried ORDER BY uid"
    ).data()
    assert [(r["uid"], r["role"], r["carried"]) for r in rows] == [
        ("dev:b1", "router", True),  # a source the window never touched
        ("dev:r1", "firewall", False),  # the fetched device
        ("dev:r2", "router", True),  # another device of the same fleet, not fetched
    ]
    listing, _ = cyclemod.list_cycles(session)
    assert listing[0]["kind"] == "device" and listing[0]["parent"] == 1000


def test_list_cycles_reports_a_capped_page_as_truncated(session):
    for cts in (1000, 2000, 3000):
        _load_cycle(session, cts, {"a": "fresh"}, _batch("a", ("dev:l1", "router")))

    rows, truncated = cyclemod.list_cycles(session, limit=2)
    assert [r["id"] for r in rows] == ["3000", "2000"]
    assert truncated is True

    rows, truncated = cyclemod.list_cycles(session, limit=2, offset=2)
    assert [r["id"] for r in rows] == ["1000"]
    assert truncated is False


def test_prune_keeps_n_cycles_and_the_refresh_runs_chained_off_them(session):
    """Retention counts full and partial cycles only."""
    _load_cycle(session, 1000, {"a": "fresh"}, _batch("a", ("dev:k1", "router")))
    _load_cycle(session, 2000, {"a": "fresh"}, _batch("a", ("dev:k1", "router")), carry_from=1000)
    for cts in (2100, 2200, 2300):  # three refreshes chained off the 2000 cycle
        _load_cycle(
            session,
            cts,
            {"a": "fresh"},
            _batch("a", ("dev:k1", "router")),
            carry_from=cts - 100,
            kind="refresh",
        )
    _load_cycle(
        session,
        3000,
        {"a": "fresh", "b": "carried"},
        _batch("a", ("dev:k1", "router")),
        carry_from=2300,
        kind="partial",
    )

    # 2 cycles kept: the partial at 3000 and the full at 2000. The refreshes at
    # 2100-2300 chain to 2000, so they stay; the full cycle at 1000 goes.
    victims = cyclemod.prune(session, keep=2)
    assert victims == [1000]
    rows, _ = cyclemod.list_cycles(session)
    assert [r["id"] for r in rows] == ["3000", "2300", "2200", "2100", "2000"]

    victims = cyclemod.prune(session, keep=1)
    assert victims == [2300, 2200, 2100, 2000]
    rows, _ = cyclemod.list_cycles(session)
    assert [r["id"] for r in rows] == ["3000"]
    assert cyclemod.current_ts(session) == 3000


def test_prune_never_deletes_the_run_the_pointer_names(session):
    for cts in (1000, 2000, 3000):
        _load_cycle(session, cts, {"a": "fresh"}, _batch("a", ("dev:p1", "router")))
    victims = cyclemod.prune(session, keep=2)
    assert victims == [1000]
    left = session.run("MATCH (n:Obj {uid: 'dev:p1'}) RETURN n.collection_ts AS cts ORDER BY cts").data()
    assert [r["cts"] for r in left] == [2000, 3000]
    assert cyclemod.current_ts(session) == 3000


def test_prune_removes_the_per_load_meta_nodes_of_a_pruned_run(session):
    """The loader stamps its per-load meta node with `snapshot_ts`."""
    for cts in (1000, 2000, 3000):
        _load_cycle(session, cts, {"a": "fresh"}, _batch("a", ("dev:m1", "router")))

    def meta_keys() -> list[int]:
        rows = session.run(
            "MATCH (r:CollectionRun) WHERE r.snapshot_ts IN [1000, 2000, 3000] "
            "RETURN r.snapshot_ts AS ts ORDER BY ts"
        ).data()
        return [r["ts"] for r in rows]

    assert meta_keys() == [1000, 2000, 3000]
    assert session.run("MATCH (n:Obj {collection_ts: 1000}) WHERE n:CollectionRun RETURN n").data() == []

    assert cyclemod.prune(session, keep=2) == [1000]
    assert meta_keys() == [2000, 3000]


def test_migrate_bootstrap_stamps_a_graph_without_collection_ts(session):
    session.run(
        "CREATE (d:Obj:Device:Phys {uid: 'dev:m1', role: 'router', _scope: $s, _last_seen: 555})",
        s=SCOPE,
    ).consume()
    out = cyclemod.migrate_bootstrap(session)
    assert out["migrated"] is True and out["nodes"] == 1
    rows = session.run(
        "MATCH (d:Device {uid: 'dev:m1', collection_ts: $cts}) "
        "RETURN d.collection_ts AS cts, d.collected_at AS at",
        cts=out["collection_ts"],
    ).data()
    assert rows and rows[0]["cts"] == out["collection_ts"] and rows[0]["at"] == 555
    assert cyclemod.migrate_bootstrap(session) == {"migrated": False}
