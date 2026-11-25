"""The typed search (core/search.py) against a real Neo4j: every graph kind,
each query mode, the integer address keys, the full-text index, cursor pages
and the run pin.

Opt-in like tests/test_entity_filters_db.py: set NEO4J_TEST_URI to a scratch
database. The fixture deletes this suite's runs before and after every test.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from hst.core import db as dbmod
from hst.core import filters as F
from hst.core import search as S
from hst.core import uid
from hst.core.config import Settings
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord
from hst.core.snapshot import Snapshot

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

OLD, RUN = 7_320_000_001_000, 7_320_000_002_000
KEYS = [OLD, RUN]

SITE = uid.site("srch-ber")
R1 = "dev:srch-r1"
IF1 = uid.interface(R1, "Vlan20")
VRF = uid.vrf(R1, "srch-red")
PFX = uid.prefix(VRF, "10.88.2.0/24")
PFX16 = uid.prefix(VRF, "10.88.0.0/16")
IP1 = uid.ip(VRF, "10.88.2.1")
BD = uid.bridge_domain("srchfab", 20)
VLAN = uid.vlan(R1, 20)
EP = uid.endpoint("srch-ber", "aa:bb:cc:00:88:07")
EP_IP = uid.ip(BD, "10.88.2.7")
APP = "app:srch-payroll"


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


def _cleanup(s) -> None:
    s.run("MATCH (n:Obj) WHERE n.collection_ts IN $keys DETACH DELETE n", keys=KEYS).consume()
    s.run("MATCH (r:CollectionRun) WHERE r.snapshot_ts IN $keys DETACH DELETE r", keys=KEYS).consume()


def _load(s, cts: int, hostname: str) -> None:
    nodes = [
        NodeRecord(label="Site", uid=SITE, props={"code": "srch-ber", "name": "Berlin search"}),
        NodeRecord(
            label="Device", uid=R1, props={"role": "router", "hostname": hostname, "mac": "aabbcc008801"}
        ),
        NodeRecord(label="Interface", uid=IF1, props={"name": "Vlan20", "mac": "aa:bb:cc:00:88:02"}),
        NodeRecord(label="VrfInstance", uid=VRF, props={"name": "srch-red"}),
        NodeRecord(label="Prefix", uid=PFX, props={"cidr": "10.88.2.0/24", "af": 4, "anchor": VRF}),
        NodeRecord(label="Prefix", uid=PFX16, props={"cidr": "10.88.0.0/16", "af": 4, "anchor": VRF}),
        NodeRecord(label="IpAddress", uid=IP1, props={"ip": "10.88.2.1", "anchor": VRF}),
        NodeRecord(label="IpAddress", uid=EP_IP, props={"ip": "10.88.2.7", "anchor": BD}),
        NodeRecord(label="BridgeDomain", uid=BD),
        NodeRecord(label="VlanInstance", uid=VLAN, props={"vid": 20}),
        NodeRecord(
            label="Endpoint",
            uid=EP,
            props={"mac": "aa:bb:cc:00:88:07", "name": "srch-printer", "ip": "10.88.2.7", "kind": "client"},
        ),
        NodeRecord(label="BusinessService", uid=APP, props={"name": "srch-payroll"}),
    ]
    rels = [
        RelRecord(type="LOCATED_IN", start=["Device", R1], end=["Site", SITE]),
        RelRecord(type="ON", start=["Interface", IF1], end=["Device", R1]),
        RelRecord(type="HAS_IP", start=["Interface", IF1], end=["IpAddress", IP1]),
        RelRecord(type="IN_VRF", start=["Interface", IF1], end=["VrfInstance", VRF]),
        RelRecord(
            type="ORIGINATES", start=["VrfInstance", VRF], end=["Prefix", PFX], key={"proto": "connected"}
        ),
        RelRecord(type="REALIZES", start=["VlanInstance", VLAN], end=["BridgeDomain", BD]),
        RelRecord(type="BOUND_TO", start=["Interface", IF1], end=["VlanInstance", VLAN]),
        RelRecord(type="HAS_IP", start=["Endpoint", EP], end=["IpAddress", EP_IP]),
        RelRecord(type="IN", start=["Endpoint", EP], end=["BridgeDomain", BD]),
    ]
    batch = Batch(source="srch", scope="cli:srch-r1", nodes=nodes, rels=rels)
    manifest = load(s, batch, ts_ms=cts, collection_ts=cts)
    assert manifest.rels_dropped_missing_endpoint == 0, manifest.errors


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        _load(s, RUN, "srch-edge1")
        _load(s, OLD, "srch-old1")
        yield s
        _cleanup(s)


class _Settings:
    manifests_dir = None
    sidestore_dir = None


def _search(s, text: str, cts: int = RUN, **kw: Any) -> S.Result:
    return S.search(s, Snapshot(cts, _Settings()), S.detect(text), kinds=kw.pop("kinds", S.GRAPH_KINDS), **kw)


def _found(result: S.Result) -> dict[str, list[str]]:
    return {k: [h["uid"] for h in g.items] for k, g in result.groups.items() if g.items}


def test_an_address_finds_what_is_or_holds_it(session):
    found = _found(_search(session, "10.88.2.1"))
    assert found == {
        "device": [R1],
        "interface": [IF1],
        "prefix": [PFX, PFX16],
        "ip_address": [IP1],
    }


def test_a_prefix_and_a_range_find_what_lies_inside(session):
    found = _found(_search(session, "10.88.2.0/24"))
    assert found == {
        "device": [R1],
        "interface": [IF1],
        "prefix": [PFX],
        "ip_address": [IP1, EP_IP],
        "endpoint": [EP],
    }
    ranged = _found(_search(session, "10.88.2.5-10.88.2.9"))
    assert ranged == {"ip_address": [EP_IP], "endpoint": [EP]}


def test_a_mac_in_any_notation_finds_its_owner(session):
    assert _found(_search(session, "AABB.CC00.8807")) == {"endpoint": [EP]}
    assert _found(_search(session, "aa-bb-cc-00-88-01")) == {"device": [R1]}
    assert _found(_search(session, "aabbcc008802")) == {"interface": [IF1]}


def test_text_finds_names_through_the_full_text_index_and_the_kinds_own_fields(session):
    assert _found(_search(session, "srch edge1")) == {"device": [R1]}
    assert _found(_search(session, "srch-red"))["vrf"] == [VRF]
    assert _found(_search(session, "payroll")) == {"application": [APP]}
    assert _found(_search(session, "srch-ber"))["site"] == [SITE]
    assert _found(_search(session, "vlan 20"))["segment"] == [BD]
    assert _found(_search(session, "10.88.2"))["ip_address"] == [IP1, EP_IP]


def test_a_regex_matches_whole_names(session):
    found = _found(_search(session, "/srch-(edge|red)[0-9]*/"))
    assert found == {"device": [R1], "vrf": [VRF]}


def test_an_exact_uid_answers_that_object(session):
    result = _search(session, IF1)
    assert result.query.mode == "uid" and _found(result) == {"interface": [IF1]}
    assert result.groups["interface"].items[0]["detail"] == "srch-edge1"


def test_every_kind_reads_one_run(session):
    assert _found(_search(session, "srch old1", OLD)) == {"device": [R1]}
    assert _found(_search(session, "srch old1")) == {}
    assert _found(_search(session, "srch edge1", OLD)) == {}


def test_a_kind_pages_by_cursor(session):
    q = S.detect("10.88.0.0/16")
    first = S.search(session, Snapshot(RUN, _Settings()), q, kinds=("ip_address",), limit=1)
    group = first.groups["ip_address"]
    assert [h["uid"] for h in group.items] == [IP1]
    assert group.count == 2 and group.count_exact and group.next_cursor is not None
    cursor = F.decode_cursor(group.next_cursor, kind="ip_address", filter_print=q.fingerprint)
    second = S.search(session, Snapshot(RUN, _Settings()), q, cursor=cursor, limit=1)
    assert [h["uid"] for h in second.groups["ip_address"].items] == [EP_IP]
    assert second.groups["ip_address"].next_cursor is None
