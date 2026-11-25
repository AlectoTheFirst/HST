"""The Zscaler reasoner rules and every zscaler catalog query on collector-shaped
data: ZPA and ZIA batches from the collectors' own normalizers, one campus
batch, one run key."""

from __future__ import annotations

import copy
import os
from typing import Any

import pytest
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver

from hst import reasoner
from hst.collectors.util import GraphBuilder
from hst.collectors.zia import normalize_zia
from hst.collectors.zpa import normalize_zpa
from hst.core.loader import load
from hst.queries import catalog

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]

KEY = 7_350_000_001_000
KEYS = [KEY]

PARAM_VALUES = {
    "app_group": "corp-apps",
    "user_group": "engineering",
    "segment": "app-crm",
    "connector_group": "hq-connectors",
    "location": "branch-austin",
    "location_group": "Branch Offices",
    "dc": "San Jose II",
    "forwarding_rule": "crm-to-zpa",
}


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        yield s
        _cleanup(s)


def _cleanup(s) -> None:
    s.run("MATCH (n:Obj) WHERE n.collection_ts IN $keys DETACH DELETE n", keys=KEYS).consume()
    s.run("MATCH (r:CollectionRun) WHERE r.snapshot_ts IN $keys DETACH DELETE r", keys=KEYS).consume()


def _campus_batch():
    b = GraphBuilder()
    a = b.node("Interface", "dev:zs-a/if/eth0", name="eth0")
    c = b.node("Interface", "dev:zs-b/if/eth0", name="eth0")
    for anchor, owner, ip in (
        ("zs-ctx-a", a, "10.0.0.6"),
        ("zs-ctx-b", c, "10.0.0.6"),
        ("zs-ctx-a", a, "10.1.1.10"),
        ("zs-ctx-a", a, "203.0.113.10"),
        ("zs-ctx-a", a, "8.8.8.8"),
    ):
        node = b.node("IpAddress", f"ip:{anchor}:{ip}", ip=ip, anchor=anchor)
        b.rel("HAS_IP", "Interface", owner, "IpAddress", node)
    return b.batch("test", "test:zscaler-campus")


def _zscaler_run(session) -> list[dict[str, Any]]:
    from tests.test_zia import RAW as ZIA_RAW
    from tests.test_zpa import RAW as ZPA_RAW

    zia_raw = copy.deepcopy(ZIA_RAW)
    zia_raw["forwarding_rules"].append(
        {
            "id": 600003,
            "name": "erp-gone-to-zpa",
            "order": 3,
            "state": "ENABLED",
            "forwardMethod": "ZPA",
            "zpaAppSegments": [{"id": 34, "externalId": "2998", "name": "app-missing", "deleted": False}],
        }
    )
    load(session, normalize_zpa(ZPA_RAW, tenant="acme"), ts_ms=KEY, run_id="zs-zpa", collection_ts=KEY)
    zia = normalize_zia(zia_raw, tenant="acme", location_sites={"1001": "hq"})
    load(session, zia, ts_ms=KEY, run_id="zs-zia", collection_ts=KEY)
    load(session, _campus_batch(), ts_ms=KEY, run_id="zs-campus", collection_ts=KEY)
    return reasoner.run(session, ts_ms=KEY + 100, collection_ts=KEY)


def _count(session, rel: str) -> int:
    return session.run(
        f"MATCH ()-[r:{rel} {{source: 'reasoner'}}]->() WHERE r.collection_ts = $key RETURN count(r) AS n",
        key=KEY,
    ).single()["n"]


def test_a_collector_shaped_run_derives_the_zscaler_edges(session):
    results = {r["rule"]: r for r in _zscaler_run(session)}
    join = results["zia-forwarding-to-zpa-segment"]
    assert (join["edges"], join["unresolved"]) == (1, 1)
    edge = session.run(
        "MATCH (f:ZiaForwardingRule)-[r:FORWARDS_TO]->(s:ZpaAppSegment) WHERE r.collection_ts = $key "
        "RETURN f.uid AS f, s.uid AS s, r.derived AS derived, r.rule AS rule",
        key=KEY,
    ).data()
    assert edge == [
        {
            "f": "zia:acme:fwdrule:600001",
            "s": "zpa:acme:seg:2001",
            "derived": False,
            "rule": "zia-forwarding-to-zpa-segment",
        }
    ]
    links = session.run(
        "MATCH (a)-[r:SAME_AS {rule: 'zpa-zia-ip-same-as'}]->(b) WHERE r.collection_ts = $key "
        "RETURN a.uid AS a, b.ip AS ip, r.basis AS basis, r.derived AS derived, r.confidence AS confidence",
        key=KEY,
    ).data()
    assert results["zpa-zia-ip-same-as"]["edges"] == len(links) == 4
    assert sorted((link["a"], link["ip"], link["basis"]) for link in links) == [
        ("zia:acme:gre:5001", "203.0.113.10", "source_ip"),
        ("zpa:acme:appsrv:4101", "10.1.1.10", "address"),
        ("zpa:acme:conn:6001", "10.0.0.6", "private_ip"),
        ("zpa:acme:conn:6001", "10.0.0.6", "private_ip"),
    ]
    # every address here is private or documentation space
    assert all(link["derived"] is True for link in links)
    assert all(link["confidence"] == reasoner.PRIVATE_ADDRESS_CONFIDENCE for link in links)
    assert not [link for link in links if link["ip"] == "8.8.8.8"]
    assert not [link for link in links if link["a"] == "zia:acme:ipsec:7001"]


def test_the_zscaler_rules_rebuild_the_same_edges_on_a_second_run(session):
    _zscaler_run(session)
    forwards, same_as = _count(session, "FORWARDS_TO"), _count(session, "SAME_AS")
    reasoner.run(session, ts_ms=KEY + 200, collection_ts=KEY)
    assert (_count(session, "FORWARDS_TO"), _count(session, "SAME_AS")) == (forwards, same_as) == (1, 4)


def _rows(rows: list[dict[str, Any]], column: str) -> list[Any]:
    return [r[column] for r in rows]


# Facts on this data, by catalog key. List columns compare as sets. An
# optional param is bound to '', so a query with one answers for every value.
def _one(rows: list[dict[str, Any]], **facts: Any) -> bool:
    return len(rows) == 1 and _has(rows[0], **facts)


def _has(row: dict[str, Any], **facts: Any) -> bool:
    for column, want in facts.items():
        got = row[column]
        if isinstance(want, set):
            if set(got or []) != want:
                return False
        elif got != want:
            return False
    return True


def _by(rows: list[dict[str, Any]], column: str) -> dict[Any, dict[str, Any]]:
    return {r[column]: r for r in rows}


def _policy(rows: list[dict[str, Any]]) -> bool:
    access = [r for r in rows if r["policy"] == "access"]
    forwarding = [r for r in rows if r["policy"] == "client forwarding"]
    everyone = [r for r in access if r["everyone"]]
    return (
        len(access) == 4
        and [r["rule"] for r in everyone] == ["allow-partners-corp-apps"]
        and _has(everyone[0], segments=0, segment_groups=1)
        and len(forwarding) == 1
        and _has(
            forwarding[0], rule="intercept-crm", action="intercept", everyone=False, user_groups=1, segments=1
        )
    )


def _connectors(rows: list[dict[str, Any]]) -> bool:
    by_kind = _by(rows, "kind")
    return (
        len(rows) == 2
        and _has(
            by_kind["app connector"],
            connector="connector-01",
            connector_group="hq-connectors",
            state="active",
            status="ZPN_STATUS_AUTHENTICATED",
            private_ip="10.0.0.6",
            segments=2,
        )
        and _has(by_kind["private service edge"], connector="edge-01", state="unknown")
    )


def _locations(rows: list[dict[str, Any]]) -> bool:
    by_name = _by(rows, "location")
    return (
        set(by_name) == {"hq-sunnyvale", "branch-austin", "branch-austin-guest"}
        and _has(
            by_name["hq-sunnyvale"],
            site="hq",
            gre_tunnels=1,
            primary_dcs={"San Jose II"},
            secondary_dcs={"San Jose III"},
            egress_dcs={"San Jose II", "San Jose III"},
            gaps=set(),
        )
        and _has(
            by_name["branch-austin"], ipsec_tunnels=1, location_groups={"Branch Offices"}, gaps={"no site"}
        )
        and _has(by_name["branch-austin-guest"], parent="branch-austin", gaps=set())
        and rows[0]["location"] == "branch-austin"
    )


def _forwarding(rows: list[dict[str, Any]]) -> bool:
    by_rule = _by(rows, "rule")
    return (
        [(r["rule"], r["named_segments"], r["resolved_segments"]) for r in rows]
        == [("crm-to-zpa", 1, 1), ("direct-rest", 0, 0), ("erp-gone-to-zpa", 1, 0)]
        and _has(by_rule["crm-to-zpa"], segment_groups={"corp-apps"}, connector_groups={"hq-connectors"})
        and _has(by_rule["direct-rest"], segment_groups=set(), connector_groups=set())
    )


EXPECTED: dict[str, Any] = {
    "zpa-app-group": lambda rows: _one(
        rows, segment_group="corp-apps", segments=2, rules=4, user_groups=3, picture_nodes=10
    ),
    "zpa-user-group": lambda rows: _one(rows, rules=1, actions={"allow"}, segments=1, segment_groups=1),
    "zpa-app-segment": lambda rows: _one(
        rows, segment_group="corp-apps", rules=4, user_groups=3, connectors=1, active_connectors=1
    ),
    "zpa-connector-group": lambda rows: _one(
        rows,
        connectors=1,
        active=1,
        connector_states={"connector-01: active"},
        server_groups=2,
        segments=2,
    ),
    "zpa-connectors": _connectors,
    "zpa-policy-rules": _policy,
    "zpa-segments-at-risk": lambda rows: rows == [],
    "zpa-groups-without-rules": lambda rows: rows == [],
    "zia-location": lambda rows: _one(rows, zia_id="1002", sublocations=1, tunnels={"ipsec"}, egress_ips=1),
    "zia-location-group": lambda rows: _one(rows, location="branch-austin", dynamic_group=False),
    "zia-dc-users": lambda rows: _one(
        rows, location="hq-sunnyvale", other_dcs={"San Jose III"}, no_other_egress=False, roles={"primary"}
    ),
    "zia-forwarding-rules": _forwarding,
    "zia-location-egress": _locations,
    "scenario-zia-guest-egress": lambda rows: rows is not None,
}


def test_every_zscaler_catalog_query_answers_collector_shaped_data(session):
    from hst.app.tables import _GraphCollector

    _zscaler_run(session)
    entries = [q for q in catalog() if q["group"] == "zscaler"]
    assert set(EXPECTED) == {q["key"] for q in entries}
    failures = []
    for entry in entries:
        params: dict[str, Any] = {"snap": KEY}
        for param in entry.get("params") or []:
            params[param["name"]] = "" if param.get("optional") else PARAM_VALUES[param["name"]]
        result = session.run(entry["cypher"], **params)
        collector = _GraphCollector()
        rows = []
        for record in result:
            for value in record.values():
                collector.add(value)
            rows.append({k: v for k, v in record.data().items() if not k.startswith("_")})
        for param in entry.get("params") or []:
            picker = param.get("picker")
            if picker and not param.get("optional"):
                held = [
                    n
                    for n in collector.nodes.values()
                    if picker["label"] in n["labels"]
                    and n["properties"].get(picker["property"]) == params[param["name"]]
                ]
                if not held:
                    failures.append(
                        f"{entry['key']}: the picture holds no {picker['label']} {params[param['name']]}"
                    )
        if not EXPECTED[entry["key"]](rows):
            failures.append(f"{entry['key']}: {rows}")
    assert not failures, "\n".join(failures)


def test_init_db_creates_the_zscaler_lookup_indexes(session):
    wanted = {
        "zpaappsegment_zpa_id": ("ZpaAppSegment", "zpa_id"),
        "zpaappsegment_name": ("ZpaAppSegment", "name"),
        "zpasegmentgroup_name": ("ZpaSegmentGroup", "name"),
        "identitygroup_name": ("IdentityGroup", "name"),
        "zialocation_name": ("ZiaLocation", "name"),
        "tunnel_source_ip": ("Tunnel", "source_ip"),
    }
    rows = session.run("SHOW INDEXES YIELD name, labelsOrTypes, properties").data()
    found = {r["name"]: (r["labelsOrTypes"][0], r["properties"][0]) for r in rows if r["name"] in wanted}
    assert found == wanted


def test_the_presence_statement_finds_zpa_and_zia_in_the_run(session):
    from hst.queries import presence_cypher

    _zscaler_run(session)
    row = session.run(presence_cypher(), snap=KEY).single().data()
    assert (row["zpa"], row["zia"]) == (True, True)
