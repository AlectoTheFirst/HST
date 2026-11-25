"""The list filters (core/filters.py) and the paged endpoint read
(core/entity_read.py) against a real Neo4j: every filter kind, the address
keys and their indexes, cursor stability across a newer run, and the run pin.

Opt-in like tests/test_snapshot_db.py: set NEO4J_TEST_URI to a scratch
database. The fixture deletes this suite's runs before and after every test.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from hst.app.routes import topology as topology_route
from hst.core import db as dbmod
from hst.core import entity_read, uid
from hst.core import filters as F
from hst.core.config import Settings
from hst.core.loader import load
from hst.core.model import Batch, NodeRecord, RelRecord

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

OLD, RUN, NEWER = 7_310_000_001_000, 7_310_000_002_000, 7_310_000_003_000
KEYS = [OLD, RUN, NEWER]

SITE = uid.site("flt-ber")
SW = "dev:flt-sw1"
AP = "dev:flt-ap1"
P1, P2 = uid.port(SW, "Port 1"), uid.port(SW, "Port 2")
BD10, BD20 = uid.bridge_domain("fltfab", 10), uid.bridge_domain("fltfab", 20)
VRF = uid.vrf("dev:flt-r1", "flt-red")
RD = uid.routing_domain("flt-corp")
PFX4 = uid.prefix(VRF, "10.77.0.0/24")
PFX6 = uid.prefix(VRF, "2001:db8:77::/64")


def _ms(y: int, m: int, d: int) -> int:
    return int(datetime(y, m, d, tzinfo=UTC).timestamp() * 1000)


# name, mac, vendor, last seen, address, attachment (port uid, or (ap, ssid)), bridge domain, hostname
ENDPOINTS = [
    ("flt-printer", "aa:bb:cc:00:77:01", "Brother", _ms(2026, 1, 1), "10.77.0.10", P1, BD10, None),
    ("flt-nas", "aa:bb:cc:00:77:02", "Synology", _ms(2026, 3, 1), "10.77.0.20", P2, BD10, None),
    ("flt-phone", "aa:bb:cc:00:77:03", "Apple", _ms(2026, 5, 1), "2001:db8:77::5", (AP, "corp"), BD20, None),
    ("flt-cam", "aa:bb:cc:00:77:04", "Axis", None, "10.78.0.4", None, BD20, "cam-host"),
]


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


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        _load_estate(s, RUN, ENDPOINTS)
        # the older run holds one more endpoint and none of the others
        _load_estate(s, OLD, [("flt-old", "aa:bb:cc:00:77:09", "Old", None, "10.77.0.99", P1, BD10, None)])
        yield s
        _cleanup(s)


def _ep_uid(mac: str) -> str:
    return uid.endpoint("flt-ber", mac)


def _load_estate(s, cts: int, endpoints) -> None:
    nodes = [
        NodeRecord(label="Site", uid=SITE, props={"code": "flt-ber"}),
        NodeRecord(label="Device", uid=SW, props={"role": "switch", "hostname": "flt-sw1"}),
        NodeRecord(label="Device", uid=AP, props={"role": "ap", "hostname": "flt-ap1"}),
        NodeRecord(label="Port", uid=P1, props={"name": "Port 1"}),
        NodeRecord(label="Port", uid=P2, props={"name": "Port 2"}),
        NodeRecord(label="BridgeDomain", uid=BD10, props={"name": "flt-users"}),
        NodeRecord(label="BridgeDomain", uid=BD20, props={"name": "flt-iot"}),
        NodeRecord(label="VrfInstance", uid=VRF, props={"name": "flt-red"}),
        NodeRecord(label="RoutingDomain", uid=RD, props={"name": "flt-corp"}),
        NodeRecord(label="Prefix", uid=PFX4, props={"cidr": "10.77.0.0/24", "af": 4, "anchor": VRF}),
        NodeRecord(label="Prefix", uid=PFX6, props={"cidr": "2001:db8:77::/64", "af": 6, "anchor": VRF}),
    ]
    rels = [
        RelRecord(type="LOCATED_IN", start=["Device", SW], end=["Site", SITE]),
        RelRecord(type="LOCATED_IN", start=["Device", AP], end=["Site", SITE]),
        RelRecord(type="ON", start=["Port", P1], end=["Device", SW]),
        RelRecord(type="ON", start=["Port", P2], end=["Device", SW]),
        RelRecord(
            type="MEMBER_OF",
            start=["VrfInstance", VRF],
            end=["RoutingDomain", RD],
            props={"basis": "declared"},
        ),
        RelRecord(
            type="ORIGINATES", start=["VrfInstance", VRF], end=["Prefix", PFX4], key={"proto": "connected"}
        ),
        RelRecord(
            type="ORIGINATES", start=["VrfInstance", VRF], end=["Prefix", PFX6], key={"proto": "connected"}
        ),
    ]
    for name, mac, vendor, seen, addr, attach, bd, hostname in endpoints:
        ep = _ep_uid(mac)
        props = {"mac": mac, "kind": "client", "name": name, "oui": vendor}
        if seen is not None:
            props["last_seen"] = seen
        if hostname is not None:
            props["hostname"] = hostname
        nodes.append(NodeRecord(label="Endpoint", uid=ep, props=props))
        ip_uid = uid.ip(bd, addr)
        nodes.append(NodeRecord(label="IpAddress", uid=ip_uid, props={"ip": addr, "anchor": bd}))
        rels.append(RelRecord(type="HAS_IP", start=["Endpoint", ep], end=["IpAddress", ip_uid]))
        rels.append(RelRecord(type="IN", start=["Endpoint", ep], end=["BridgeDomain", bd]))
        for pfx, net in ((PFX4, "10.77.0."), (PFX6, "2001:db8:77:")):
            if addr.startswith(net):
                rels.append(RelRecord(type="IN", start=["IpAddress", ip_uid], end=["Prefix", pfx]))
        if isinstance(attach, tuple):
            rels.append(
                RelRecord(
                    type="ATTACHED",
                    start=["Endpoint", ep],
                    end=["Device", attach[0]],
                    props={"ssid": attach[1]},
                )
            )
        elif attach is not None:
            rels.append(RelRecord(type="ATTACHED", start=["Endpoint", ep], end=["Port", attach]))
    batch = Batch(source="flt", scope="unifi:flt-ber", nodes=nodes, rels=rels)
    manifest = load(s, batch, ts_ms=cts, collection_ts=cts)
    assert manifest.rels_dropped_missing_endpoint == 0, manifest.errors


def _names(s, values: dict, *, snap: int = RUN, limit: int = 50) -> list[str]:
    f = F.parse_filter(values)
    page = entity_read.read_page(s, "endpoint", f, snap=snap, run=snap, cursor=None, limit=limit)
    return [i["name"] for i in entity_read.read_endpoints(s, page.uids, snap=snap)]


def test_the_loader_writes_the_keys_and_the_indexes_exist(session):
    keys = {
        r["ip"]: r["k"]
        for r in session.run(
            "MATCH (a:IpAddress) WHERE a.collection_ts = $cts RETURN a.ip AS ip, a.ip_key AS k", cts=RUN
        ).data()
    }
    assert keys["10.77.0.10"] == "4:0a4d000a"
    assert keys["2001:db8:77::5"] == "6:20010db8007700000000000000000005"
    pfx = session.run(
        "MATCH (p:Prefix {uid: $u, collection_ts: $cts}) RETURN p.lo_key AS lo, p.hi_key AS hi",
        u=PFX4,
        cts=RUN,
    ).single()
    assert (pfx["lo"], pfx["hi"]) == ("4:0a4d0000", "4:0a4d00ff")
    names = {r["name"] for r in session.run("SHOW INDEXES YIELD name RETURN name").data()}
    assert {"ipaddress_ip_key", "endpoint_ip_key", "prefix_lo_key"} <= names


def test_no_filter_lists_the_run_and_only_the_run(session):
    assert _names(session, {}) == ["cam-host", "flt-nas", "flt-phone", "flt-printer"]
    assert _names(session, {}, snap=OLD) == ["flt-old"]


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"ip": "10.77.0.20"}, ["flt-nas"]),
        ({"ip": "2001:db8:77:0::5"}, ["flt-phone"]),
        ({"subnet": "10.77.0.0/24"}, ["flt-nas", "flt-printer"]),
        ({"subnet": "10.0.0.0/8"}, ["cam-host", "flt-nas", "flt-printer"]),
        ({"subnet": "2001:db8::/32"}, ["flt-phone"]),
        ({"subnet": "::/0"}, ["flt-phone"]),
        ({"range_start": "10.77.0.15", "range_end": "10.78.0.4"}, ["cam-host", "flt-nas"]),
        ({"range_start": "2001:db8:77::1", "range_end": "2001:db8:77::4"}, []),
        ({"text": "PRINT"}, ["flt-printer"]),
        ({"text": "synology", "text_fields": ["vendor"]}, ["flt-nas"]),
        (
            {"text": "AA-BB-CC-00-77-0", "text_fields": ["mac"]},
            ["cam-host", "flt-nas", "flt-phone", "flt-printer"],
        ),
        ({"text": "aabbcc007703", "text_fields": ["mac"]}, ["flt-phone"]),
        ({"text": "port 2", "text_fields": ["port"]}, ["flt-nas"]),
        ({"text": "cam-h", "text_fields": ["hostname"]}, ["cam-host"]),
        ({"regex": "flt-(?:nas|cam)"}, ["cam-host", "flt-nas"]),
        ({"regex": "CAM-.*", "regex_fields": ["hostname"]}, ["cam-host"]),
        ({"regex": "nas"}, []),
        ({"site": ["flt-ber"]}, ["flt-nas", "flt-phone", "flt-printer"]),
        ({"device": ["flt-sw1"]}, ["flt-nas", "flt-printer"]),
        ({"device": [AP]}, ["flt-phone"]),
        ({"device": ["flt-sw1"], "port": ["Port 1"]}, ["flt-printer"]),
        ({"device": [AP], "port": ["Port 1"]}, []),
        ({"segment": [BD20]}, ["cam-host", "flt-phone"]),
        ({"segment": ["flt-users"]}, ["flt-nas", "flt-printer"]),
        ({"vrf": ["flt-red"]}, ["flt-nas", "flt-phone", "flt-printer"]),
        ({"vrf": [VRF]}, ["flt-nas", "flt-phone", "flt-printer"]),
        ({"routing_domain": ["flt-corp"]}, ["flt-nas", "flt-phone", "flt-printer"]),
        ({"routing_domain": ["other"]}, []),
        ({"last_seen_after": "2026-02-01T00:00:00Z"}, ["flt-nas", "flt-phone"]),
        ({"last_seen_before": "2026-03-01T00:00:00Z"}, ["flt-printer"]),
        (
            {"last_seen_after": "2026-01-01T00:00:00Z", "last_seen_before": "2026-05-01T00:00:00Z"},
            ["flt-nas", "flt-printer"],
        ),
        ({"subnet": "10.77.0.0/24", "text": "nas"}, ["flt-nas"]),
    ],
)
def test_each_filter_kind(session, values, expected):
    assert _names(session, values) == expected


def test_the_count_matches_the_filter(session):
    f = F.parse_filter({"subnet": "10.0.0.0/8"})
    page = entity_read.read_page(session, "endpoint", f, snap=RUN, run=RUN, cursor=None, limit=1)
    assert (page.total_capped, page.total_exact) == (3, True)
    assert len(page.uids) == 1 and page.next_cursor


def test_the_cursor_pages_one_run_even_after_a_newer_one(session):
    f = F.EntityFilter()
    seen: list[str] = []
    page = entity_read.read_page(session, "endpoint", f, snap=RUN, run=RUN, cursor=None, limit=1)
    seen += page.uids
    # a newer run with more endpoints lands while the client pages
    _load_estate(
        session,
        NEWER,
        [*ENDPOINTS, ("aaa-new", "aa:bb:cc:00:77:0a", "New", None, "10.77.0.30", P1, BD10, None)],
    )
    while page.next_cursor:
        cur = F.decode_cursor(page.next_cursor, kind="endpoint", filter_print=f.fingerprint())
        assert cur.run == RUN
        page = entity_read.read_page(session, "endpoint", f, snap=cur.run, run=cur.run, cursor=cur, limit=1)
        seen += page.uids
    assert seen == [_ep_uid(e[1]) for e in sorted(ENDPOINTS, key=lambda e: e[7] or e[0])]
    assert len(set(seen)) == len(seen)


def test_the_page_order_is_stable_on_equal_names(session):
    """Two endpoints of one name are ordered by uid, and the cursor seeks past
    the first without dropping the second."""
    twins = [
        ("flt-twin", "aa:bb:cc:00:77:21", "X", None, "10.77.0.41", P1, BD10, None),
        ("flt-twin", "aa:bb:cc:00:77:22", "X", None, "10.77.0.42", P1, BD10, None),
    ]
    _load_estate(session, NEWER, twins)
    f = F.parse_filter({"text": "twin"})
    first = entity_read.read_page(session, "endpoint", f, snap=NEWER, run=NEWER, cursor=None, limit=1)
    cur = F.decode_cursor(first.next_cursor or "", kind="endpoint", filter_print=f.fingerprint())
    second = entity_read.read_page(session, "endpoint", f, snap=NEWER, run=NEWER, cursor=cur, limit=1)
    assert first.uids + second.uids == sorted(_ep_uid(t[1]) for t in twins)
    assert second.next_cursor is None


def test_a_regex_runs_under_the_guard_and_the_value_cap(session):
    long_name = "flt-" + "a" * (F.REGEX_MAX_VALUE + 10)
    _load_estate(session, NEWER, [(long_name, "aa:bb:cc:00:77:31", "X", None, "10.77.0.51", P1, BD10, None)])
    # a value past the cap is never handed to the regex engine
    assert _names(session, {"regex": "flt-a*"}, snap=NEWER) == []
    with pytest.raises(F.FilterError):
        F.parse_filter({"regex": "(a*)*$"})


def test_the_detail_read_carries_the_attachments(session):
    f = F.parse_filter({"ip": "2001:db8:77::5"})
    page = entity_read.read_page(session, "endpoint", f, snap=RUN, run=RUN, cursor=None, limit=5)
    [item] = entity_read.read_endpoints(session, page.uids, snap=RUN)
    assert item["ips"] == ["2001:db8:77::5"]
    assert item["bd"] == BD20
    assert item["attachments"] == [
        {"device": AP, "device_name": "flt-ap1", "port": None, "ssid": "corp", "sites": ["flt-ber"]}
    ]


def test_the_site_segment_query_reads_the_endpoints_of_the_asked_devices_only(session):
    """Asked for sites, the segment list starts from their devices; the bridge domain of the default
    fabric holds every site's endpoints, and the read must give the asked devices' own."""
    both = session.run(topology_route._SITE_SEGMENT_CLIENTS, bd=BD10, devs=[SW, AP], snap=RUN).data()
    assert [r["name"] for r in both] == ["flt-nas", "flt-printer"]
    assert both == session.run(topology_route._SEGMENT_CLIENTS, bd=BD10, site=None, snap=RUN).data()
    only_ap = session.run(topology_route._SITE_SEGMENT_CLIENTS, bd=BD10, devs=[AP], snap=RUN).data()
    assert only_ap == []
    f = F.parse_filter({"subnet": "10.77.0.0/24", "text": "nas"})
    compiled = F.compile_filter(f, "endpoint")
    text = topology_route._SITE_SEGMENT_CLIENTS_FILTERED.replace("/*filter*/", "\n  AND " + compiled.where)
    rows = session.run(entity_read.timed(text), bd=BD10, devs=[SW], snap=RUN, **compiled.params).data()
    assert [r["name"] for r in rows] == ["flt-nas"]


def test_the_filtered_segment_query_runs(session):
    f = F.parse_filter({"subnet": "10.77.0.0/24", "text": "nas"})
    compiled = F.compile_filter(f, "endpoint")
    text = topology_route._SEGMENT_CLIENTS_FILTERED.replace("/*filter*/", "\n  AND " + compiled.where)
    rows = session.run(entity_read.timed(text), bd=BD10, site=None, snap=RUN, **compiled.params).data()
    assert [r["name"] for r in rows] == ["flt-nas"]


def _segment_page(session, query=None, **over):
    params = {
        "bd": BD10,
        "devs": [SW, AP],
        "snap": RUN,
        "keep": [SW, AP],
        "macs": [],
        "hex": topology_route._HEX,
        "offset": 0,
        "limit": 10,
        "after_name": None,
        "after_uid": None,
    } | over
    [found] = session.run(query or topology_route._SITE_SEGMENT_PAGE_QUERY, **params).data()
    return found["total"], [r["name"] for r in found["page"]]


def test_the_segment_list_is_paged_in_the_database(session):
    """The segment list cuts its page in the read: the total, the rows
    of the page and one past it, an offset, and a cursor past (name, uid)."""
    assert _segment_page(session) == (2, ["flt-nas", "flt-printer"])
    assert _segment_page(session, topology_route._SEGMENT_PAGE_QUERY, site=None) == (
        2,
        ["flt-nas", "flt-printer"],
    )
    # one past the limit tells the route that a next page exists
    assert _segment_page(session, limit=0) == (2, ["flt-nas"])
    assert _segment_page(session, offset=1) == (2, ["flt-printer"])
    nas = _ep_uid("aa:bb:cc:00:77:02")
    assert _segment_page(session, after_name="flt-nas", after_uid=nas) == (2, ["flt-printer"])
    # a cursor row gone from the list starts the page at the rows that sort after it
    assert _segment_page(session, after_name="flt-m", after_uid="") == (2, ["flt-nas", "flt-printer"])


def test_the_segment_page_skips_as_the_drawing_does(session):
    # a drawn device's MAC, in any notation, is that device, not a client
    assert _segment_page(session, macs=["aabbcc007702"]) == (1, ["flt-printer"])
    # a device that is not drawn gives no rows
    assert _segment_page(session, keep=[AP]) == (0, [])
    f = F.parse_filter({"text": "nas"})
    compiled = F.compile_filter(f, "endpoint")
    text = topology_route._segment_page(
        topology_route._SITE_SEGMENT_CLIENTS_FILTERED.replace("/*filter*/", "\n  AND " + compiled.where)
    )
    assert _segment_page(session, entity_read.timed(text), **compiled.params) == (1, ["flt-nas"])
