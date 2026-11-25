"""The graph load queries run against the scratch Neo4j database that NEO4J_TEST_URI sets."""

import os
import re
from types import SimpleNamespace

import pytest

from hst.analysis_model.graph import BOUNDARY_KINDS, LOAD_QUERIES, ScopeExtension, load_graph
from hst.core import db as dbmod
from hst.core.config import Settings

URI = os.environ.get("NEO4J_TEST_URI")
SCOPE = "test:graph-load"
CTS = 3_800_000_000_000

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

_FIXTURE = """
CREATE (a:Obj:Device {uid: 'gl:dev:a', collection_ts: $cts, _scope: $scope})
CREATE (b:Obj:Device {uid: 'gl:dev:b', collection_ts: $cts, _scope: $scope})
CREATE (old:Obj:Device {uid: 'gl:dev:a', collection_ts: $old, _scope: $scope})
CREATE (gone:Obj:Device:Retired {uid: 'gl:dev:gone', collection_ts: $cts, _scope: $scope})
CREATE (ia:Obj:Interface {uid: 'gl:dev:a/if/lan', name: 'lan', collection_ts: $cts, _scope: $scope})
CREATE (ib:Obj:Interface {uid: 'gl:dev:b/if/lan', name: 'lan', collection_ts: $cts, _scope: $scope})
CREATE (va:Obj:VrfInstance {uid: 'gl:vrf:a', name: 'main', collection_ts: $cts, _scope: $scope})
CREATE (vb:Obj:VrfInstance {uid: 'gl:vrf:b', name: 'main', collection_ts: $cts, _scope: $scope})
CREATE (pa:Obj:IpAddress {uid: 'gl:ip:a', ip: '10.0.0.1', anchor: 'gl:vrf:a',
                          collection_ts: $cts, _scope: $scope})
CREATE (pb:Obj:IpAddress {uid: 'gl:ip:b', ip: '10.0.1.1', anchor: 'gl:vrf:b',
                          collection_ts: $cts, _scope: $scope})
CREATE (rb:Obj:FwRulebase {uid: 'gl:rb', vendor: 'cisco', collection_ts: $cts, _scope: $scope})
CREATE (site:Obj:Site {uid: 'gl:site', _scope: $scope})
CREATE (ia)-[:ON {collection_ts: $cts}]->(a)
CREATE (ib)-[:ON {collection_ts: $cts}]->(b)
CREATE (va)-[:OWNED_BY {collection_ts: $cts}]->(a)
CREATE (vb)-[:OWNED_BY {collection_ts: $cts}]->(b)
CREATE (ia)-[:HAS_IP {collection_ts: $cts}]->(pa)
CREATE (ib)-[:HAS_IP {collection_ts: $cts}]->(pb)
CREATE (ib)-[:ENFORCES {collection_ts: $cts, direction: 'in'}]->(rb)
CREATE (a)-[:LOCATED_IN]->(site)
CREATE (b)-[:LOCATED_IN]->(site)
CREATE (gone)-[:LOCATED_IN]->(site)
"""


def _refuse_if_live() -> None:
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). Point it at a scratch database.", returncode=2
        )


@pytest.fixture(scope="module")
def _driver():
    from neo4j import GraphDatabase

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI, auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"])
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as session:
        dbmod.init_db(session)
    yield driver
    driver.close()


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as current:
        current.run("MATCH (n:Obj) WHERE n._scope = $scope DETACH DELETE n", scope=SCOPE).consume()
        current.run(_FIXTURE, cts=CTS, old=CTS - 1, scope=SCOPE).consume()
        yield current
        current.run("MATCH (n:Obj) WHERE n._scope = $scope DETACH DELETE n", scope=SCOPE).consume()


def _params(**extra):
    return {
        "snap": CTS,
        "after": "",
        "after_node": "",
        "after_key": None,
        "limit": 1000,
        "window": 1001,
        "devices": ["gl:dev:a"],
        "boundary": list(BOUNDARY_KINDS),
        "uid": "gl:dev:b/if/lan",
        "sources": ["vsx-bridge", "vsx-warp"],
        **extra,
    }


def _details(operator):
    arguments = operator.get("args") or operator.get("arguments") or {}
    return str(arguments.get("Details") or arguments.get("details") or "")


def _paths(operator, above=()):
    """Every operator with the operators above it, root first."""
    chain = (*above, operator)
    yield chain
    for child in operator.get("children") or ():
        yield from _paths(child, chain)


def _render(operator, depth=0):
    line = (
        f"{'  ' * depth}{operator['operatorType']} rows={operator.get('rows')}"
        f" dbHits={operator.get('dbHits')} {_details(operator)}"
    )
    return "\n".join([line, *(_render(child, depth + 1) for child in operator.get("children") or ())])


_ORDERING = ("Limit", "Top", "PartialTop", "Sort", "PartialSort")


@pytest.mark.parametrize("name", sorted(LOAD_QUERIES))
def test_each_load_query_pages_on_the_uid_index(session, name):
    query = LOAD_QUERIES[name]
    summary = session.run("PROFILE " + query, parameters=_params()).consume()
    profile = summary.profile
    print(f"\n-- {name}\n{_render(profile)}")

    operators = [chain[-1] for chain in _paths(profile)]
    kinds = [operator["operatorType"].split("@")[0] for operator in operators]
    assert not any(kind in {"AllNodesScan", "NodeByLabelScan"} for kind in kinds), kinds
    if name == "vsx-transit":
        assert any("IndexSeek" in kind for kind in kinds), kinds
        return
    seeks = [
        chain
        for chain in _paths(profile)
        # obj_uid_cts, or a label's uid index (core/db.py) where the
        # planner prefers it; a range from the first key reads as an ordered
        # index scan, the same keyset paging over the same index
        if re.search(r"NodeIndex(Seek|Scan)|NodeUniqueIndexSeek", chain[-1]["operatorType"])
        and re.search(r"\(uid\b", _details(chain[-1]))
    ]
    assert seeks, kinds
    if name == "scope-lookup":
        return
    # the read's own LIMIT is the first ordering operator above its seek:
    # the index order serves it, nothing sorts the nodes of the run
    anchor = "n" if name in {"nodes", "scoped-nodes"} else "x"
    seek = next(chain for chain in seeks if f"{anchor}:Obj(uid, collection_ts)" in _details(chain[-1]))
    ordering = [
        op["operatorType"].split("@")[0]
        for op in reversed(seek[:-1])
        if op["operatorType"].split("@")[0] in _ORDERING
    ]
    assert ordering and ordering[0] == "Limit", ordering


def _snapshot():
    return SimpleNamespace(cts=CTS, manifest=object(), settings=Settings(_env_file=None))


def _load(session, **options):
    return load_graph(session, _snapshot(), "a" * 64, digest_reader=lambda: "a" * 64, page_size=2, **options)


def test_the_whole_run_and_a_scoped_load_against_the_server(session):
    whole = _load(session)

    assert whole.complete is True
    assert whole.targets("gl:dev:b/if/lan", "ON")[0].uid == "gl:dev:b"
    assert {node.uid for node in whole.sources("gl:site", "LOCATED_IN")} == {"gl:dev:a", "gl:dev:b"}
    assert whole.nodes.get("gl:dev:gone") is None

    scoped = _load(session, devices={"gl:dev:a"})

    assert scoped.nodes["gl:dev:a/if/lan"] == whole.nodes["gl:dev:a/if/lan"]
    assert scoped.targets("gl:dev:a/if/lan", "HAS_IP") == whole.targets("gl:dev:a/if/lan", "HAS_IP")
    assert scoped.sources("gl:site", "LOCATED_IN") == whole.sources("gl:site", "LOCATED_IN")
    assert [rel.uid for rel in scoped.incoming[("gl:rb", "ENFORCES")]] == [
        rel.uid for rel in whole.incoming[("gl:rb", "ENFORCES")]
    ]
    with pytest.raises(ScopeExtension) as raised:
        scoped.nodes.get("gl:dev:b/if/lan")
    assert raised.value.devices == frozenset({"gl:dev:b"})
    with pytest.raises(ScopeExtension) as raised:
        scoped.sources("gl:dev:b", "ON")
    assert raised.value.devices == frozenset({"gl:dev:b"})
    with pytest.raises(ScopeExtension) as raised:
        scoped.nodes.get("gl:ip:b")
    assert raised.value.devices == frozenset({"gl:dev:b"})
    assert scoped.nodes.get("gl:nowhere") is None
    assert scoped.has_vsx_transit() is False
