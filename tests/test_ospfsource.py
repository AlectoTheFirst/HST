"""OspfSource: the link-state database read back out of the side store."""

import pytest

pytest.importorskip("pyarrow")

from hst.app.crypto import generate_key
from hst.collectors.cisco_common import normalize_cisco, ospf_side_rows, side_rows
from hst.core import Settings, manifest, sidestore, uid
from hst.core.model import TableOutcome
from hst.core.ospfsource import OspfSource, for_snapshot
from hst.core.snapshot import Snapshot

AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id
DEV = "dev:fdo1234abcd"
CTX = uid.vrf(DEV, "default")
MGMT_CTX = uid.vrf(DEV, "mgmt")
RUN_A = "1700000000000-aaaaaaaa"
RUN_B = "1700000001000-bbbbbbbb"


def _snap(settings, cts):
    """The resolved Snapshot a caller hands `for_snapshot` (core/snapshot.py)."""
    return Snapshot(cts, settings)


def _lsa(lsa_type="router", **over):
    row = {
        "device_uid": DEV,
        "context_uid": CTX,
        "process": "1",
        "area": AREA_0,
        "lsa_type": lsa_type,
        "lsid": "10.255.0.1",
        "adv_router": "10.255.0.1",
        "seq": 0x80000005,
        "age": 120,
        "metric": None,
        "links": None,
        "attached_routers": None,
        "mask": None,
        "forwarding_address": None,
        "metric_type": None,
    }
    row.update(over)
    return row


ROUTER_LSA = _lsa(
    links=[
        {"link_type": "point-to-point", "link_id": "10.255.0.2", "link_data": "10.0.0.1", "metric": 40},
        {"link_type": "stub", "link_id": "10.0.0.0", "link_data": "255.255.255.0", "metric": 40},
    ]
)
NETWORK_LSA = _lsa(
    "network", lsid="10.0.0.1", attached_routers=["10.255.0.1", "10.255.0.2"], mask="255.255.255.0"
)
SUMMARY_LSA = _lsa("summary", area="0.0.0.10", lsid="10.10.10.0", mask="255.255.255.0", metric=20)
EXTERNAL_LSA = _lsa(
    "external",
    area=None,
    lsid="203.0.113.0",
    adv_router="10.255.0.2",
    mask="255.255.255.0",
    metric=100,
    metric_type=2,
    forwarding_address="10.0.0.2",
)
# The two types a shortest-path calculation needs beside the four above: an
# NSSA external (type 7, a type 5's body but scoped to the NSSA it was
# originated in) and an ASBR summary (type 4, whose lsid is the ASBR's router
# id and whose metric is the cost to reach it).
NSSA_LSA = _lsa(
    "nssa-external",
    area="0.0.0.10",
    lsid="198.51.100.0",
    adv_router="10.255.0.3",
    mask="255.255.255.128",
    metric=50,
    metric_type=1,
    forwarding_address="10.10.10.2",
)
ASBR_SUMMARY_LSA = _lsa(
    "asbr-summary", area="0.0.0.10", lsid="10.255.0.9", adv_router="10.255.0.1", metric=30
)


# --- the reader: what one device's database reads back as --------------------


@pytest.fixture
def store(tmp_path):
    pytest.importorskip("duckdb")
    sidestore.write_table(
        tmp_path,
        "ospf_lsdb",
        "nxos",
        "n9k1",
        RUN_A,
        [ROUTER_LSA, NETWORK_LSA, SUMMARY_LSA, EXTERNAL_LSA, NSSA_LSA, ASBR_SUMMARY_LSA],
        1000,
    )
    return tmp_path


def test_lsdb_roundtrip_returns_every_lsa_with_its_typed_body(store):
    rows = OspfSource(store).lsdb(DEV, CTX)
    # LSA order: by area, then type, then link-state id and advertising
    # router. The area-less AS-external LSA sorts last.
    assert [r["lsa_type"] for r in rows] == [
        "network",
        "router",
        "asbr-summary",
        "nssa-external",
        "summary",
        "external",
    ]
    router = next(r for r in rows if r["lsa_type"] == "router")
    assert (router["lsid"], router["seq"], router["age"]) == ("10.255.0.1", 0x80000005, 120)
    assert [link["link_id"] for link in router["links"]] == ["10.255.0.2", "10.0.0.0"]
    external = next(r for r in rows if r["lsa_type"] == "external")
    assert (external["metric"], external["metric_type"]) == (100, 2)
    assert external["forwarding_address"] == "10.0.0.2"


def test_lsdb_returns_the_nssa_and_asbr_summary_bodies(store):
    """The two types the shortest-path calculation needs beside the first
    four. A type 7 stays in the NSSA it was originated in and carries a type
    5's body; a type 4 names the ASBR in its lsid and the cost to it in its
    metric."""
    rows = {r["lsa_type"]: r for r in OspfSource(store).lsdb(DEV, CTX, area="0.0.0.10")}
    assert {"nssa-external", "asbr-summary", "summary"} <= set(rows)

    nssa = rows["nssa-external"]
    assert (nssa["lsid"], nssa["adv_router"]) == ("198.51.100.0", "10.255.0.3")
    assert (nssa["mask"], nssa["metric"], nssa["metric_type"]) == ("255.255.255.128", 50, 1)
    assert nssa["forwarding_address"] == "10.10.10.2"

    asbr = rows["asbr-summary"]
    assert (asbr["lsid"], asbr["adv_router"], asbr["metric"]) == ("10.255.0.9", "10.255.0.1", 30)
    # neither type has a router LSA's links or a network LSA's routers
    assert asbr["links"] is None and asbr["attached_routers"] is None
    assert nssa["links"] is None and nssa["attached_routers"] is None


def test_lsdb_narrows_by_process_and_area(store):
    rs = OspfSource(store)
    assert [r["lsid"] for r in rs.lsdb(DEV, CTX, area="0.0.0.10")] == [
        "10.255.0.9",
        "198.51.100.0",
        "10.10.10.0",
    ]
    assert rs.lsdb(DEV, CTX, process="2") == []
    # an AS-external LSA belongs to no area, so no area's answer holds it
    assert "203.0.113.0" not in {r["lsid"] for r in rs.lsdb(DEV, CTX, area=AREA_0)}


def test_lsdb_of_another_context_on_the_same_device_is_a_separate_database(store):
    """One device runs a separate process, with a separate database, per
    routing context: a read of one context never answers with another's."""
    assert OspfSource(store).lsdb(DEV, MGMT_CTX) == []


def test_lsdb_unknown_device_returns_empty(store):
    assert OspfSource(store).lsdb("dev:unknown", CTX) == []


def test_lsdb_reads_the_newest_run_within_the_bound(tmp_path):
    pytest.importorskip("duckdb")
    sidestore.write_table(tmp_path, "ospf_lsdb", "nxos", "n9k1", RUN_A, [ROUTER_LSA], 1000)
    sidestore.write_table(tmp_path, "ospf_lsdb", "nxos", "n9k1", RUN_B, [_lsa(seq=0x80000006, age=30)], 2000)
    assert [r["seq"] for r in OspfSource(tmp_path).lsdb(DEV, CTX)] == [0x80000006]
    bounded = OspfSource(tmp_path, as_of_ms=1500)
    assert [r["seq"] for r in bounded.lsdb(DEV, CTX)] == [0x80000005]


def test_a_store_with_no_lsdb_table_answers_nothing_and_does_not_raise(tmp_path):
    rs = OspfSource(tmp_path / "absent")
    assert rs.available is False
    assert rs.lsdb(DEV, CTX) == []
    assert rs.has_rows(DEV) is False


# --- manifest-driven evidence -----------------------------------------------


def _settings(tmp_path):
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _lsdb_file(settings, run_id, rows, snapshot_ts):
    path = sidestore.write_table(
        settings.sidestore_dir, "ospf_lsdb", "edge", "n9k1", run_id, rows, snapshot_ts
    )
    assert path is not None
    return manifest.file_entry(settings, path)


def _device(run_id, status=None, *, outcome="collected", path=""):
    tables = {} if status is None else {"ospf_lsdb": TableOutcome(status=status, path=path)}
    return manifest.DeviceEntry(
        source="edge", host="n9k1", outcome=outcome, effective_run=run_id, tables=tables
    )


def _publish(settings, key, parent, devices, files):
    manifest.write(
        settings,
        manifest.SnapshotManifest(
            snapshot_key=key,
            kind="full",
            parent=parent,
            opened=manifest.iso(key),
            published=manifest.iso(key),
            devices=devices,
            files=files,
        ),
    )


def _read(settings, cts):
    """What one reader bound to `cts` says, read and released in one call: two
    connections open at once on one store's catalog conflict on its locked
    configuration, so no test below holds two readers at a time."""
    rs = for_snapshot(_snap(settings, cts))
    return {
        "approximate": rs.approximate,
        "available": rs.available,
        "lsids": [r["lsid"] for r in rs.lsdb(DEV, CTX)],
        "has_rows": rs.has_rows(DEV),
        "coverage": rs.coverage(DEV),
    }


def _publish_a(settings):
    file_a = _lsdb_file(settings, RUN_A, [ROUTER_LSA], 1000)
    _publish(settings, 1000, None, [_device(RUN_A, "complete", path=file_a.path)], [file_a])
    return file_a


def test_for_snapshot_reads_the_files_the_pinned_snapshot_publishes(tmp_path):
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    assert _read(settings, 1000) == {
        "approximate": False,
        "available": True,
        "lsids": ["10.255.0.1"],
        "has_rows": True,
        "coverage": "complete",
    }


def test_a_device_without_the_ospf_feature_reads_unsupported_not_empty(tmp_path):
    """`coverage` separates an absent feature from a database that came back empty."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    _publish(settings, 2000, 1000, [_device(RUN_B, "unsupported")], [])

    at_b = _read(settings, 2000)
    assert (at_b["lsids"], at_b["has_rows"], at_b["coverage"]) == ([], False, "unsupported")


def test_an_empty_database_reads_complete_empty_and_never_falls_back(tmp_path):
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    _publish(settings, 2000, 1000, [_device(RUN_B, "complete-empty")], [])

    at_b = _read(settings, 2000)
    assert (at_b["lsids"], at_b["coverage"]) == ([], "complete-empty")
    # read by age alone, a pin with no manifest answers from the older file
    by_age = OspfSource(settings.sidestore_dir, as_of_ms=2000)
    assert [r["lsid"] for r in by_age.lsdb(DEV, CTX)] == ["10.255.0.1"]
    assert by_age.approximate is True


def test_a_failed_table_answers_no_rows_and_reports_the_gap(tmp_path):
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    _publish(settings, 2000, 1000, [_device(RUN_B, "failed", outcome="partial")], [])

    at_b = _read(settings, 2000)
    assert (at_b["lsids"], at_b["coverage"]) == ([], "failed")


def _publish_with_contexts(settings, contexts):
    """Run A holds the default VRF's database; the device entry also records
    the outcome of each context named in `contexts` (status by context uid)."""
    file_a = _lsdb_file(settings, RUN_A, [ROUTER_LSA], 1000)
    device = _device(RUN_A, "complete", path=file_a.path)
    device.tables.update(
        {manifest.ospf_context_key(ctx): TableOutcome(status=status) for ctx, status in contexts.items()}
    )
    _publish(settings, 1000, None, [device], [file_a])


def test_the_manifest_states_the_database_of_each_context(tmp_path):
    """The device's outcome says its default VRF was read, and says
    nothing about a tenant VRF, whose own outcome the reader answers."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    tenant = uid.vrf(DEV, "TENANT")
    _publish_with_contexts(settings, {CTX: "complete", tenant: "not-captured"})
    rs = for_snapshot(_snap(settings, 1000))
    assert rs.coverage(DEV) == "complete"
    assert rs.context_coverage(CTX) == "complete"
    assert rs.context_coverage(tenant) == "not-captured"
    assert rs.context_coverage(MGMT_CTX) is None


def test_a_context_outcome_is_not_a_table_outcome():
    key = manifest.ospf_context_key(CTX)
    assert key == f"ospf_lsdb/{CTX}"
    tables = {
        "ospf_lsdb": TableOutcome(status="complete"),
        key: TableOutcome(status="complete-empty"),
        "bgp_session_routes/s/received": TableOutcome(status="not-captured"),
    }
    assert {ctx: o.status for ctx, o in manifest.ospf_context_outcomes(tables).items()} == {
        CTX: "complete-empty"
    }


def test_an_approximate_read_records_no_context_outcome(store):
    assert OspfSource(store).context_coverage(CTX) is None


def test_the_contexts_a_device_holds_rows_for(tmp_path):
    pytest.importorskip("duckdb")
    sidestore.write_table(
        tmp_path,
        "ospf_lsdb",
        "nxos",
        "n9k1",
        RUN_A,
        [ROUTER_LSA, _lsa(context_uid=MGMT_CTX, lsid="10.255.9.1")],
        1000,
    )
    rs = OspfSource(tmp_path)
    assert rs.contexts_with_rows(DEV) == {CTX, MGMT_CTX}
    assert rs.contexts_with_rows("dev:unknown") == set()


def test_a_file_no_manifest_publishes_is_ignored(tmp_path):
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    sidestore.write_table(
        settings.sidestore_dir, "ospf_lsdb", "edge", "n9k1", RUN_B, [_lsa(lsid="10.9.9.9")], 2000
    )
    at_a = _read(settings, 1000)
    assert at_a["lsids"] == ["10.255.0.1"]


# --- two collections that differ in one fact --------------------------------
#
# The intermediate shape below is the smallest one `normalize_cisco` accepts:
# a device, the two interfaces the OSPF process runs on, and the process
# itself. Each test varies exactly one fact and reads what the collection made
# of it.

SERIAL = "FDO1234ABCD"
# minted by the in-memory registry from the hostname below
BASE_DEV = "dev:sw1"
BASE_RPU = uid.routing_process(BASE_DEV, "default", "ospf-1")
AREA_0_UID = uid.ospf_area(BASE_RPU, AREA_0)
ETH1 = uid.interface(BASE_DEV, "Ethernet1/1")
ETH2 = uid.interface(BASE_DEV, "Ethernet1/2")


def _inter(*, adjacencies, interfaces, lsdb=()):
    return {
        "device": {"hostname": "sw1", "serial": SERIAL, "platform": "nxos", "os_version": "9.3(5)"},
        "interfaces": [
            {
                "name": name,
                "kind": "phys",
                "mac": None,
                "admin_up": True,
                "ips": [{"ip": ip, "prefixlen": 24, "vrf": ""}],
                "vlan": None,
            }
            for name, ip in (("Ethernet1/1", "10.0.0.1"), ("Ethernet1/2", "10.0.1.1"))
        ],
        "neighbors": [],
        "vlans": [],
        "vrfs": [],
        "rib": [],
        "mac_table": [],
        "arp": [],
        "ospf": {
            "processes": [
                {
                    "process": "1",
                    "vrf": "",
                    "router_id": "10.255.0.1",
                    "areas": [{"area_id": AREA_0, "type": "normal"}],
                    "redistribute": [],
                }
            ],
            "interfaces": list(interfaces),
            "adjacencies": list(adjacencies),
            "lsdb": list(lsdb),
        },
    }


def _ospf_if(name, area=AREA_0, cost=40):
    return {
        "process": "1",
        "vrf": "",
        "name": name,
        "area": area,
        "cost": cost,
        "network_type": "point-to-point",
        "passive": False,
    }


def _adjacency(name, rid, state="FULL"):
    return {
        "process": "1",
        "vrf": "",
        "area": AREA_0,
        "local_interface": name,
        "neighbor_router_id": rid,
        "neighbor_ip": "10.0.0.2",
        "state": state,
    }


BOTH_UP = _inter(
    interfaces=[_ospf_if("Ethernet1/1"), _ospf_if("Ethernet1/2")],
    adjacencies=[_adjacency("Ethernet1/1", "10.255.0.2"), _adjacency("Ethernet1/2", "10.255.0.3")],
)
ADJ_1 = uid.ospf_adjacency(BASE_RPU, ETH1, "10.255.0.2")
ADJ_2 = uid.ospf_adjacency(BASE_RPU, ETH2, "10.255.0.3")


def _batch(inter):
    return normalize_cisco(inter, source="nxos", scope="nxos:sw1", l3dom="corp")


def _facts(inter):
    """The OSPF facts one collection asserts: each adjacency's own properties,
    and each interface's area membership with the properties of that
    membership. Keyed by uid, so two collections are compared fact by fact."""
    batch = _batch(inter)
    nodes = {n.uid: n.props for n in batch.nodes if n.label == "OspfAdjacency"}
    areas = {
        (r.start_uid, r.end_uid): r.props
        for r in batch.rels
        if r.rel_type == "IN_AREA" and r.start_label == "Interface"
    }
    return nodes, areas


def _diff(before, after):
    """The uids whose facts differ between two collections, with what they
    changed from and to."""
    changed = {}
    for key in set(before) | set(after):
        if before.get(key) != after.get(key):
            changed[key] = (before.get(key), after.get(key))
    return changed


def test_two_collections_that_differ_in_one_neighbor_state_diff_to_that_adjacency():
    """One neighbor drops to INIT and nothing else changes: the diff names
    that adjacency, states the state it moved between, and names nothing
    else."""
    dropped = _inter(
        interfaces=[_ospf_if("Ethernet1/1"), _ospf_if("Ethernet1/2")],
        adjacencies=[
            _adjacency("Ethernet1/1", "10.255.0.2"),
            _adjacency("Ethernet1/2", "10.255.0.3", state="INIT"),
        ],
    )
    before_adj, before_areas = _facts(BOTH_UP)
    after_adj, after_areas = _facts(dropped)

    assert _diff(before_areas, after_areas) == {}
    changed = _diff(before_adj, after_adj)
    assert list(changed) == [ADJ_2]
    was, now = changed[ADJ_2]
    assert (was["state"], now["state"]) == ("FULL", "INIT")


def test_an_adjacency_that_is_gone_and_an_interface_out_of_its_area_are_distinct_facts():
    """Two different things happen to one interface, and the collection must
    not fold them into one. The adjacency going away leaves the interface in
    its area with its cost; the interface leaving the area takes the area
    membership with it and is not a statement about any neighbor."""
    adjacency_down = _inter(
        interfaces=[_ospf_if("Ethernet1/1"), _ospf_if("Ethernet1/2")],
        adjacencies=[_adjacency("Ethernet1/1", "10.255.0.2")],
    )
    out_of_area = _inter(
        interfaces=[_ospf_if("Ethernet1/1")],
        adjacencies=[_adjacency("Ethernet1/1", "10.255.0.2"), _adjacency("Ethernet1/2", "10.255.0.3")],
    )
    base_adj, base_areas = _facts(BOTH_UP)
    down_adj, down_areas = _facts(adjacency_down)
    out_adj, out_areas = _facts(out_of_area)

    # the adjacency is gone; the area membership is untouched
    assert list(_diff(base_adj, down_adj)) == [ADJ_2]
    assert down_adj.get(ADJ_2) is None
    assert _diff(base_areas, down_areas) == {}

    # the interface is out of the area; every adjacency stands
    assert _diff(base_adj, out_adj) == {}
    assert list(_diff(base_areas, out_areas)) == [(ETH2, AREA_0_UID)]
    assert (ETH2, AREA_0_UID) not in out_areas
    assert (ETH1, AREA_0_UID) in out_areas


def test_a_collection_with_no_ospf_key_carries_no_lsdb_table_at_all():
    """A platform whose collector does not read OSPF must not have the table
    appear in its run's outcomes as though it had looked and found nothing."""
    no_ospf = {k: v for k, v in BOTH_UP.items() if k != "ospf"}
    assert ospf_side_rows(no_ospf, BASE_DEV) == {}
    assert "ospf_lsdb" not in side_rows(no_ospf, BASE_DEV)
    assert "ospf_lsdb" in side_rows(BOTH_UP, BASE_DEV)


# --- the table outcome one run records for the database ----------------------


def _write_tables(tmp_path, monkeypatch, outputs):
    from tests.conftest import FakeSshSession
    from tests.test_nxos import HOST, USER
    from tests.test_nxos import RAW as NXOS_RAW

    from hst.collectors.auth import SshPassword
    from hst.collectors.base import _write_side_tables
    from hst.collectors.nxos import NxosCollector, NxosConfig

    FakeSshSession(outputs).install(monkeypatch)
    collector = NxosCollector(
        NxosConfig(host=HOST, auth=SshPassword(username=USER, password="pw"), site_code="hq", l3dom="corp"),
        _settings(tmp_path),
    )
    assert NXOS_RAW  # the fixture the outputs are built from
    return _write_side_tables(
        collector,
        collector.fetch(),
        "edge",
        "n9k1",
        run_id=RUN_A,
        collection_ts=1000,
        on_write=None,
    )


def test_a_run_records_the_lsdb_rows_it_wrote(tmp_path, monkeypatch):
    pytest.importorskip("duckdb")
    from tests.test_nxos import RAW as NXOS_RAW

    tables = _write_tables(tmp_path, monkeypatch, NXOS_RAW)
    assert tables["ospf_lsdb"].status == "complete"
    assert tables["ospf_lsdb"].row_count == 6
    assert tables["ospf_lsdb"].path.startswith("sidestore/ospf_lsdb/")


def test_a_box_without_the_ospf_feature_records_the_table_unsupported(tmp_path, monkeypatch):
    """`complete-empty` claims that the device looked and found nothing."""
    from tests.test_nxos import RAW as NXOS_RAW

    from hst.collectors import ssh
    from hst.collectors.nxos import OSPF_COMMANDS
    from hst.core.model import DEGRADING_TABLE_STATUSES, table_verdict

    def outputs(cmd):
        if cmd in OSPF_COMMANDS:
            raise ssh.CommandFailed(f"{cmd!r} exited 1: % Invalid command at '^' marker")
        return NXOS_RAW[cmd]

    tables = _write_tables(tmp_path, monkeypatch, outputs)
    outcome = tables["ospf_lsdb"]
    assert outcome.status == "unsupported"
    assert outcome.detail
    assert outcome.path == ""
    assert "unsupported" not in DEGRADING_TABLE_STATUSES
    assert table_verdict(tables) == "ok"
    # the rest of the device's tables are untouched by the missing feature
    assert tables["rib"].status == "complete"


def test_an_enabled_process_with_an_empty_database_records_complete_empty(tmp_path, monkeypatch):
    from tests.test_nxos import RAW as NXOS_RAW

    from hst.collectors.nxos import CMD_OSPF_CONFIG, OSPF_COMMANDS

    answered = {**NXOS_RAW, **dict.fromkeys(OSPF_COMMANDS, "{}"), CMD_OSPF_CONFIG: ""}
    tables = _write_tables(tmp_path, monkeypatch, answered)
    assert tables["ospf_lsdb"].status == "complete-empty"


# --- the same three run-manifest facts, against the IOS-XE and IOS-XR fixtures -------------


def _write_iosxe_tables(tmp_path, monkeypatch, outputs):
    from tests.conftest import FakeSshSession
    from tests.test_iosxe import HOST, USER
    from tests.test_iosxe import OSPF_RAW as IOSXE_OSPF_RAW

    from hst.collectors.auth import SshPassword
    from hst.collectors.base import _write_side_tables
    from hst.collectors.iosxe import IosxeCollector, IosxeConfig

    FakeSshSession(outputs).install(monkeypatch)
    collector = IosxeCollector(
        IosxeConfig(host=HOST, auth=SshPassword(username=USER, password="pw"), site_code="hq", l3dom="corp"),
        _settings(tmp_path),
    )
    assert IOSXE_OSPF_RAW  # the fixture the outputs are built from
    return _write_side_tables(
        collector, collector.fetch(), "edge", "sw1x", run_id=RUN_A, collection_ts=1000, on_write=None
    )


def test_iosxe_a_run_records_the_lsdb_rows_it_wrote(tmp_path, monkeypatch):
    pytest.importorskip("duckdb")
    from tests.test_iosxe import OSPF_RAW as IOSXE_OSPF_RAW

    tables = _write_iosxe_tables(tmp_path, monkeypatch, IOSXE_OSPF_RAW)
    assert tables["ospf_lsdb"].status == "complete"
    assert tables["ospf_lsdb"].row_count == 6
    assert tables["ospf_lsdb"].path.startswith("sidestore/ospf_lsdb/")


def test_iosxe_a_device_with_no_router_ospf_process_records_the_table_unsupported(tmp_path, monkeypatch):
    """IOS-XE has no `feature ospf` gate."""
    from tests.test_iosxe import RAW as IOSXE_RAW

    from hst.core.model import DEGRADING_TABLE_STATUSES, table_verdict

    tables = _write_iosxe_tables(tmp_path, monkeypatch, IOSXE_RAW)
    outcome = tables["ospf_lsdb"]
    assert outcome.status == "unsupported"
    assert outcome.detail
    assert outcome.path == ""
    assert "unsupported" not in DEGRADING_TABLE_STATUSES
    assert table_verdict(tables) == "ok"
    assert tables["rib"].status == "complete"


def test_iosxe_an_enabled_process_with_an_empty_database_records_complete_empty(tmp_path, monkeypatch):
    from tests.test_iosxe import CMD_OSPF_CONFIG, OSPF_COMMANDS
    from tests.test_iosxe import OSPF_RAW as IOSXE_OSPF_RAW

    answered = {
        **IOSXE_OSPF_RAW,
        **dict.fromkeys(OSPF_COMMANDS, ""),
        CMD_OSPF_CONFIG: IOSXE_OSPF_RAW[CMD_OSPF_CONFIG],
    }
    tables = _write_iosxe_tables(tmp_path, monkeypatch, answered)
    assert tables["ospf_lsdb"].status == "complete-empty"


def _write_iosxr_tables(tmp_path, monkeypatch, outputs):
    from tests.conftest import FakeSshSession
    from tests.test_iosxr import HOST, USER
    from tests.test_iosxr import OSPF_RAW as IOSXR_OSPF_RAW

    from hst.collectors.auth import SshPassword
    from hst.collectors.base import _write_side_tables
    from hst.collectors.iosxr import IosxrCollector, IosxrConfig

    FakeSshSession(outputs).install(monkeypatch)
    collector = IosxrCollector(
        IosxrConfig(host=HOST, auth=SshPassword(username=USER, password="pw"), site_code="hq", l3dom="corp"),
        _settings(tmp_path),
    )
    assert IOSXR_OSPF_RAW  # the fixture the outputs are built from
    return _write_side_tables(
        collector, collector.fetch(), "edge", "xr1", run_id=RUN_A, collection_ts=1000, on_write=None
    )


def test_iosxr_a_run_records_the_lsdb_rows_it_wrote(tmp_path, monkeypatch):
    pytest.importorskip("duckdb")
    from tests.test_iosxr import OSPF_RAW as IOSXR_OSPF_RAW

    tables = _write_iosxr_tables(tmp_path, monkeypatch, IOSXR_OSPF_RAW)
    assert tables["ospf_lsdb"].status == "complete"
    assert tables["ospf_lsdb"].row_count == 6
    assert tables["ospf_lsdb"].path.startswith("sidestore/ospf_lsdb/")


def test_iosxr_a_device_with_no_router_ospf_process_records_the_table_unsupported(tmp_path, monkeypatch):
    """IOS-XR has no `feature ospf` gate."""
    from tests.test_iosxr import RAW as IOSXR_RAW

    from hst.core.model import DEGRADING_TABLE_STATUSES, table_verdict

    tables = _write_iosxr_tables(tmp_path, monkeypatch, IOSXR_RAW)
    outcome = tables["ospf_lsdb"]
    assert outcome.status == "unsupported"
    assert outcome.detail
    assert outcome.path == ""
    assert "unsupported" not in DEGRADING_TABLE_STATUSES
    assert table_verdict(tables) == "ok"
    assert tables["rib"].status == "complete"


def test_iosxr_an_enabled_process_with_an_empty_database_records_complete_empty(tmp_path, monkeypatch):
    from tests.test_iosxr import CMD_OSPF_CONFIG, OSPF_COMMANDS
    from tests.test_iosxr import OSPF_RAW as IOSXR_OSPF_RAW

    answered = {
        **IOSXR_OSPF_RAW,
        **dict.fromkeys(OSPF_COMMANDS, ""),
        CMD_OSPF_CONFIG: IOSXR_OSPF_RAW[CMD_OSPF_CONFIG],
    }
    tables = _write_iosxr_tables(tmp_path, monkeypatch, answered)
    assert tables["ospf_lsdb"].status == "complete-empty"
    assert tables["ospf_lsdb"].row_count == 0


# --- VyOS: the same table outcomes, off FRR's own capture ---------------------------------


def _write_vyos_tables(tmp_path, raw):
    from hst.collectors.auth import SshPassword
    from hst.collectors.base import _write_side_tables
    from hst.collectors.vyos import VyosCollector, VyosConfig

    collector = VyosCollector(
        VyosConfig(host="gw1", auth=SshPassword(username="v", password="pw"), site_code="hq", l3dom="corp"),
        _settings(tmp_path),
    )
    return _write_side_tables(collector, raw, "edge", "gw1", run_id=RUN_A, collection_ts=1000, on_write=None)


def test_vyos_ospf_run_records_all_six_lsa_types(tmp_path):
    pytest.importorskip("duckdb")
    from tests.test_vyos import OSPF_RAW as VYOS_OSPF_RAW

    tables = _write_vyos_tables(tmp_path, VYOS_OSPF_RAW)
    assert tables["ospf_lsdb"].status == "complete"
    assert tables["ospf_lsdb"].row_count == 6
    assert tables["ospf_lsdb"].path.startswith("sidestore/ospf_lsdb/")


def test_vyos_ospf_lsdb_reads_back_through_ospfsource(tmp_path):
    """The reader is vendor-neutral: rows a VyOS run wrote read back the same
    way an NX-OS run's do, keyed on the same `context_uid` convention."""
    pytest.importorskip("duckdb")
    from tests.test_vyos import OSPF_RAW as VYOS_OSPF_RAW

    from hst.core import uid as uidmod

    _write_vyos_tables(tmp_path, VYOS_OSPF_RAW)
    dev = "dev:gw-ospf"  # minted from the host-name of VYOS_OSPF_RAW
    ctx = uidmod.vrf(dev, "default")
    rows = OspfSource(_settings(tmp_path).sidestore_dir).lsdb(dev, ctx)
    assert {r["lsa_type"] for r in rows} == {
        "router",
        "network",
        "summary",
        "asbr-summary",
        "external",
        "nssa-external",
    }


def test_vyos_a_box_with_no_ospf_configured_records_the_table_unsupported(tmp_path):
    pytest.importorskip("duckdb")
    raw = {"config": {"system": {"host-name": "gw-ospf"}}, "version_text": "Hardware S/N: OSPFVYOS1\n"}
    tables = _write_vyos_tables(tmp_path, raw)
    outcome = tables["ospf_lsdb"]
    assert outcome.status == "unsupported"
    assert outcome.detail
    assert outcome.path == ""
    # the rest of the device's tables are untouched by the missing feature
    assert tables["rib"].status == "complete-empty"


# --- APIC: the class model exposes no link-state database ---------------------------------


def test_apic_ospf_lsdb_is_declared_not_captured_regardless_of_the_fetch(tmp_path):
    pytest.importorskip("duckdb")
    from tests.test_apic import RAW as APIC_RAW

    from hst.collectors.apic import ApicCollector, ApicConfig
    from hst.collectors.base import _write_side_tables

    collector = ApicCollector(
        ApicConfig(
            url="https://apic.example",
            auth={"method": "user_password", "username": "ro", "password": "pw"},
            fabric="fab1",
            site_code="dc1",
            l3dom="dc1",
        ),
        _settings(tmp_path),
    )
    tables = _write_side_tables(
        collector, APIC_RAW, "apic1", "", run_id=RUN_A, collection_ts=1000, on_write=None
    )
    outcome = tables["ospf_lsdb"]
    assert outcome.status == "not-captured"
    assert outcome.detail
    assert outcome.path == ""
