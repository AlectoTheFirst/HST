"""The GraphQL reads run against the scratch Neo4j database that NEO4J_TEST_URI sets."""

from __future__ import annotations

import contextlib
import os
from types import SimpleNamespace

import pytest
from tests.test_entity_filters_db import (
    AP,
    BD10,
    BD20,
    ENDPOINTS,
    OLD,
    PFX4,
    PFX6,
    RUN,
    SITE,
    SW,
    URI,
    VRF,
    _cleanup,
    _ep_uid,
    _load_estate,
    _refuse_if_live,
)

from hst.core import db as dbmod
from hst.core import entity_read
from hst.core import filters as F
from hst.core.config import Settings

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

DATABASE = os.environ.get("NEO4J_TEST_DATABASE", "neo4j")


@pytest.fixture(scope="module")
def _driver():
    from neo4j import GraphDatabase

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    with driver.session(database=DATABASE) as s:
        dbmod.init_db(s)
    yield driver
    driver.close()


@pytest.fixture()
def session(_driver):
    with _driver.session(database=DATABASE) as s:
        _cleanup(s)
        _load_estate(s, RUN, ENDPOINTS)
        _load_estate(s, OLD, [("flt-old", "aa:bb:cc:00:77:09", "Old", None, "10.77.0.99", None, BD10, None)])
        yield s
        _cleanup(s)


def _list(s, kind: str, values: dict | None = None, *, snap: int = RUN) -> list[str]:
    page = entity_read.read_page(
        s, kind, F.parse_filter(values or {}), snap=snap, run=snap, cursor=None, limit=50
    )
    return page.uids


def _ip(addr: str, anchor: str) -> str:
    from hst.core import uid

    return uid.ip(anchor, addr)


@pytest.mark.parametrize(
    ("kind", "values", "expected"),
    [
        ("device", {}, [AP, SW]),
        ("device", {"text": "SW1"}, [SW]),
        ("device", {"regex": "flt-ap.*"}, [AP]),
        ("device", {"site": ["flt-ber"]}, [AP, SW]),
        ("device", {"device": ["flt-sw1"]}, [SW]),
        ("device", {"text": "port 2", "text_fields": ["port"]}, [SW]),
        ("site", {}, [SITE]),
        ("site", {"text": "BER"}, [SITE]),
        ("segment", {}, [BD20, BD10]),
        ("segment", {"text": "users"}, [BD10]),
        ("segment", {"segment": ["flt-iot"]}, [BD20]),
        ("prefix", {}, [PFX4, PFX6]),
        ("prefix", {"ip": "10.77.0.5"}, [PFX4]),
        ("prefix", {"subnet": "10.0.0.0/8"}, [PFX4]),
        ("prefix", {"subnet": "10.77.0.0/25"}, []),
        ("prefix", {"range_start": "2001:db8::", "range_end": "2001:db9::"}, [PFX6]),
        ("prefix", {"vrf": ["flt-red"]}, [PFX4, PFX6]),
        ("prefix", {"routing_domain": ["flt-corp"]}, [PFX4, PFX6]),
        ("ip_address", {"subnet": "10.77.0.0/24"}, [_ip("10.77.0.10", BD10), _ip("10.77.0.20", BD10)]),
        (
            "ip_address",
            {"vrf": ["flt-red"]},
            [_ip("10.77.0.10", BD10), _ip("10.77.0.20", BD10), _ip("2001:db8:77::5", BD20)],
        ),
        ("ip_address", {"segment": [BD20]}, [_ip("10.78.0.4", BD20), _ip("2001:db8:77::5", BD20)]),
    ],
)
def test_each_kind_lists_and_filters_in_its_run(session, kind, values, expected):
    assert _list(session, kind, values) == expected


def test_the_older_run_holds_its_own_objects(session):
    assert _list(session, "ip_address", {"ip": "10.77.0.99"}) == []
    assert _list(session, "ip_address", {"ip": "10.77.0.99"}, snap=OLD) == [_ip("10.77.0.99", BD10)]


def test_the_rows_of_each_kind(session):
    devices = entity_read.read_rows(session, "device", [SW, "dev:missing"], snap=RUN)
    assert set(devices) == {SW}
    assert (devices[SW]["hostname"], devices[SW]["site"]) == ("flt-sw1", SITE)
    prefixes = entity_read.read_rows(session, "prefix", [PFX4], snap=RUN)
    assert (prefixes[PFX4]["cidr"], prefixes[PFX4]["vrf"]) == ("10.77.0.0/24", "flt-red")
    ips = entity_read.read_rows(session, "ip_address", [_ip("10.77.0.10", BD10)], snap=RUN)
    assert ips[_ip("10.77.0.10", BD10)]["prefix"] == PFX4
    segments = entity_read.read_rows(session, "segment", [BD10], snap=RUN)
    assert segments[BD10]["name"] == "flt-users"
    sites = entity_read.read_rows(session, "site", [SITE], snap=RUN)
    assert sites[SITE]["code"] == "flt-ber"


def test_the_child_lists_are_batched_and_bounded(session):
    printer, nas, phone = (_ep_uid(e[1]) for e in ENDPOINTS[:3])
    got = entity_read.read_children(session, "device", "endpoint", [SW, AP], first=10, snap=RUN)
    assert got == {SW: [nas, printer], AP: [phone]}
    got = entity_read.read_children(session, "device", "endpoint", [SW], first=1, snap=RUN)
    assert got == {SW: [nas]}
    assert entity_read.read_children(session, "site", "device", [SITE], first=10, snap=RUN) == {
        SITE: [AP, SW]
    }
    assert entity_read.read_children(session, "segment", "endpoint", [BD10], first=10, snap=RUN) == {
        BD10: [nas, printer]
    }
    assert entity_read.read_children(session, "prefix", "ip_address", [PFX4], first=10, snap=RUN) == {
        PFX4: [_ip("10.77.0.10", BD10), _ip("10.77.0.20", BD10)]
    }
    assert entity_read.read_children(
        session, "ip_address", "endpoint", [_ip("10.77.0.10", BD10)], first=10, snap=RUN
    ) == {_ip("10.77.0.10", BD10): [printer]}
    assert entity_read.read_children(session, "endpoint", "ip_address", [phone], first=10, snap=RUN) == {
        phone: [_ip("2001:db8:77::5", BD20)]
    }
    # a parent of another run is not read
    assert entity_read.read_children(session, "device", "endpoint", [SW], first=10, snap=OLD) == {SW: []}


async def test_a_nested_graphql_query_reads_one_run(session, _driver, monkeypatch):
    import hst.app.graphql.context as gql_context
    from hst.app.graphql.schema import schema

    @contextlib.contextmanager
    def own_session(settings):
        with _driver.session(database=DATABASE) as s:
            yield s

    monkeypatch.setattr(gql_context, "_session", own_session)
    ctx = gql_context.GraphContext(Settings(_env_file=None), SimpleNamespace(role="viewer"))
    query = """query($run: ID) {
      endpoints(run: $run, filter: {subnet: "10.77.0.0/24"}) {
        run totalCountCapped
        edges { node { name attachments { port device { hostname site { code } } }
                       segment { name } addresses { ip prefix { cidr vrf } } } }
      }
      sites { edges { node { code devices { hostname endpoints { name } } } } }
    }"""
    result = await schema.execute(query, variable_values={"run": str(RUN)}, context_value=ctx)
    assert result.errors is None, result.errors
    data = result.data
    assert data["endpoints"]["run"] == str(RUN)
    assert data["endpoints"]["totalCountCapped"] == 2
    nodes = [e["node"] for e in data["endpoints"]["edges"]]
    assert [n["name"] for n in nodes] == ["flt-nas", "flt-printer"]
    assert nodes[0]["attachments"] == [
        {"port": "Port 2", "device": {"hostname": "flt-sw1", "site": {"code": "flt-ber"}}}
    ]
    assert nodes[0]["segment"] == {"name": "flt-users"}
    assert nodes[0]["addresses"] == [
        {"ip": "10.77.0.20", "prefix": {"cidr": "10.77.0.0/24", "vrf": "flt-red"}}
    ]
    [site] = [e["node"] for e in data["sites"]["edges"]]
    assert [d["hostname"] for d in site["devices"]] == ["flt-ap1", "flt-sw1"]
    assert [e["name"] for e in site["devices"][1]["endpoints"]] == ["flt-nas", "flt-printer"]
    assert VRF  # the prefix's VrfInstance is the estate's
