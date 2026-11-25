"""BgpSource: the observed BGP session state and path tables of one snapshot.

The evidence the `rib` table cannot hold: which peer supplied a path, which
alternatives existed beside it, which one the device chose, and what the
session itself was doing. Each test publishes manifests by hand in the shape
app/runs_exec.py writes them.

Only one reader is open at a time: one store's catalog is opened read-only
with its configuration locked, so two readers of it conflict (see
`BgpSource.close`). A comparison across two snapshots therefore reads one,
closes it, and reads the other.
"""

import pytest

pytest.importorskip("pyarrow")

from hst.app.crypto import generate_key
from hst.core import Settings, ipenc, manifest, sidestore, uid
from hst.core.bgpsource import BgpSource, compare, for_snapshot
from hst.core.model import TableOutcome
from hst.core.snapshot import Snapshot

DEV = "dev:r1"
VRF = "CUST-A"
CONTEXT = uid.vrf(DEV, VRF)
PEER_A, PEER_B = "10.1.1.2", "192.0.2.2"
PREFIX = "10.20.0.0/24"
RUN_A = "1700000000000-aaaaaaaa"
RUN_B = "1700000001000-bbbbbbbb"
ROUTES, SESSIONS = "bgp_session_routes", "bgp_sessions"


def _session_uid(peer_ip):
    """The BgpSession uid the collector stamps on an observed row, the same
    formula the graph node carries (collectors/nxos.py `_bgp_session_uid`)."""
    return uid.bgp_session(uid.routing_process(DEV, VRF, "bgp"), peer_ip, VRF)


SESSION_A, SESSION_B = _session_uid(PEER_A), _session_uid(PEER_B)


def _snap(settings, cts):
    """The resolved Snapshot a caller hands `for_snapshot` (core/snapshot.py),
    built directly."""
    return Snapshot(cts, settings)


def _path(
    session_uid,
    peer_ip,
    prefix=PREFIX,
    *,
    direction="accepted",
    best=None,
    local_pref=100,
    as_path="65099",
):
    lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
    stage = {
        "received": ("adj-rib-in", "pre-import"),
        "accepted": ("loc-rib", "post-import"),
        "advertised": ("adj-rib-out", "post-export"),
    }[direction]
    return {
        "device_uid": DEV,
        "context_uid": CONTEXT,
        "session_uid": session_uid,
        "peer_ip": peer_ip,
        "af": af,
        "safi": "unicast",
        "direction": direction,
        "rib_type": stage[0],
        "policy_stage": stage[1],
        "path_id": "0",
        "prefix": prefix,
        "prefixlen": prefixlen,
        "lo": lo,
        "hi": hi,
        "next_hop": peer_ip,
        "next_hop_context_uid": None,
        "as_path": as_path,
        "local_pref": local_pref,
        "med": 0,
        "origin": "i",
        "communities": None,
        "best": best,
    }


def _session_row(session_uid, peer_ip, state):
    return {
        "device_uid": DEV,
        "context_uid": CONTEXT,
        "session_uid": session_uid,
        "peer_ip": peer_ip,
        "af": 4,
        "safi": "unicast",
        "state": state,
        "established_since_ms": None,
        "prefixes_received": None,
        "prefixes_advertised": None,
        "capabilities": None,
    }


def _settings(tmp_path):
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _write(settings, table, run_id, rows, snapshot_ts, source="edge", host="r1"):
    path = sidestore.write_table(settings.sidestore_dir, table, source, host, run_id, rows, snapshot_ts)
    assert path is not None
    return manifest.file_entry(settings, path)


def _raw_entry(run_id, source="edge", host="r1"):
    """A raw file entry by description only: no reader here opens a raw file."""
    return manifest.FileEntry(
        kind="raw",
        path=f"raw/{source}/{host}/{run_id}.json.gz.enc",
        sha256="0" * 64,
        bytes=0,
        source=source,
        host=host,
        run_id=run_id,
    )


def _device(run_id, tables, *, outcome="collected", carried=False, source="edge", host="r1"):
    return manifest.DeviceEntry(
        source=source, host=host, outcome=outcome, effective_run=run_id, carried=carried, tables=tables
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


def _directions(**statuses):
    """The per-session direction outcomes a run records, keyed as the manifest
    keys them. Every value is a status, or a (status, row_count) pair."""
    out = {}
    for key, value in statuses.items():
        session_uid, direction = key.rsplit("_", 1)
        session = {"a": SESSION_A, "b": SESSION_B}[session_uid]
        status, rows = value if isinstance(value, tuple) else (value, None)
        out[manifest.bgp_direction_key(session, direction)] = TableOutcome(status=status, row_count=rows)
    return out


def _snapshot_a(settings):
    """Snapshot 1000: both peers supply the prefix, peer A's path is best,
    peer A's received table was not retained by the platform and peer B's
    was."""
    routes = _write(
        settings,
        ROUTES,
        RUN_A,
        [
            _path(SESSION_A, PEER_A, best=True, local_pref=150, as_path=""),
            _path(SESSION_B, PEER_B, best=False),
            _path(SESSION_B, PEER_B, direction="received"),
        ],
        1000,
    )
    sessions = _write(
        settings,
        SESSIONS,
        RUN_A,
        [
            _session_row(SESSION_A, PEER_A, "Established"),
            _session_row(SESSION_B, PEER_B, "Established"),
        ],
        1000,
    )
    tables = {
        ROUTES: TableOutcome(status="complete", row_count=3, path=routes.path),
        SESSIONS: TableOutcome(status="complete", row_count=2, path=sessions.path),
        **_directions(
            a_received="not-captured",
            a_accepted=("complete", 1),
            a_advertised=("complete-empty", 0),
            b_received=("complete", 1),
            b_accepted=("complete", 1),
            b_advertised=("complete-empty", 0),
        ),
    }
    _publish(settings, 1000, None, [_device(RUN_A, tables)], [_raw_entry(RUN_A), routes, sessions])


def _snapshot_b(settings):
    """Snapshot 2000: peer A withdrew the prefix and its session is down, so
    peer B's path is the one the device chose."""
    routes = _write(
        settings,
        ROUTES,
        RUN_B,
        [_path(SESSION_B, PEER_B, best=True)],
        2000,
    )
    sessions = _write(
        settings,
        SESSIONS,
        RUN_B,
        [
            _session_row(SESSION_A, PEER_A, "Idle"),
            _session_row(SESSION_B, PEER_B, "Established"),
        ],
        2000,
    )
    tables = {
        ROUTES: TableOutcome(status="complete", row_count=1, path=routes.path),
        SESSIONS: TableOutcome(status="complete", row_count=2, path=sessions.path),
        **_directions(
            a_received="not-captured",
            a_accepted=("complete-empty", 0),
            a_advertised=("complete-empty", 0),
            b_received=("complete-empty", 0),
            b_accepted=("complete", 1),
            b_advertised=("complete-empty", 0),
        ),
    }
    _publish(settings, 2000, 1000, [_device(RUN_B, tables)], [_raw_entry(RUN_B), routes, sessions])


@pytest.fixture
def store(tmp_path):
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _snapshot_a(settings)
    _snapshot_b(settings)
    return settings


def _reader(settings, cts):
    """One reader, for one assertion block. Closed by the caller: two readers
    of one store must not be open at the same time."""
    return for_snapshot(_snap(settings, cts))


# --- what the peers supplied ------------------------------------------------------------


def test_two_peers_supplying_one_prefix_are_two_rows_and_best_marks_one(store):
    rs = _reader(store, 1000)
    try:
        rows = rs.paths(DEV, CONTEXT, PREFIX, direction="accepted")
        assert [(r["peer_ip"], r["best"], r["local_pref"]) for r in rows] == [
            (PEER_A, True, 150),
            (PEER_B, False, 100),
        ]
        assert {r["rib_type"] for r in rows} == {"loc-rib"}
        assert {r["policy_stage"] for r in rows} == {"post-import"}
    finally:
        rs.close()


def test_a_later_snapshot_shows_the_other_peer_as_best(store):
    """The winner withdrew: at the later snapshot the alternative is the path
    the device chose, and the earlier best path is not in the table at all."""
    rs = _reader(store, 2000)
    try:
        rows = rs.paths(DEV, CONTEXT, PREFIX, direction="accepted")
        assert [(r["peer_ip"], r["best"]) for r in rows] == [(PEER_B, True)]
    finally:
        rs.close()


def test_the_diff_between_the_two_snapshots_names_the_change(store):
    """Read one snapshot, then the other, and the comparison names the prefix
    the withdrawing peer stopped supplying, per session and direction."""
    rs = _reader(store, 1000)
    try:
        before_a = rs.prefixes(SESSION_A, "accepted")
        before_b = rs.prefixes(SESSION_B, "accepted")
    finally:
        rs.close()
    rs = _reader(store, 2000)
    try:
        after_a = rs.prefixes(SESSION_A, "accepted")
        after_b = rs.prefixes(SESSION_B, "accepted")
    finally:
        rs.close()
    assert compare(before_a, after_a) == {"added": [], "removed": [PREFIX]}
    assert compare(before_b, after_b) == {"added": [], "removed": []}


def test_the_import_policy_is_what_received_minus_accepted_names(store):
    """Peer B's received table holds the path before the import policy ran and
    its accepted table after, so the difference is the policy's own."""
    rs = _reader(store, 1000)
    try:
        received = rs.paths(DEV, session_uid=SESSION_B, direction="received")
        accepted = rs.paths(DEV, session_uid=SESSION_B, direction="accepted")
        assert [r["policy_stage"] for r in received] == ["pre-import"]
        assert [r["policy_stage"] for r in accepted] == ["post-import"]
        assert received[0]["best"] is None  # a received table is pre-decision
    finally:
        rs.close()


# --- what the run did not capture -------------------------------------------------------


def test_an_uncaptured_received_direction_reports_not_captured(store):
    """Peer A's platform does not retain the pre-policy table without soft
    reconfiguration inbound. That direction is `not-captured` and holds no
    rows."""
    rs = _reader(store, 1000)
    try:
        assert rs.direction_status(SESSION_A, "received") == "not-captured"
        assert rs.paths(DEV, session_uid=SESSION_A, direction="received") == []
        # the same session's other directions were captured, and one of them
        # was captured and found empty, which is a different answer
        assert rs.direction_status(SESSION_A, "accepted") == "complete"
        assert rs.direction_status(SESSION_A, "advertised") == "complete-empty"
        assert rs.direction_status(SESSION_B, "received") == "complete"
    finally:
        rs.close()


def test_a_direction_no_manifest_records_answers_none(store):
    rs = _reader(store, 1000)
    try:
        assert rs.direction_status(_session_uid("203.0.113.1"), "accepted") is None
    finally:
        rs.close()


def test_a_table_a_run_captured_none_of_reports_not_captured(tmp_path):
    """A source with `capture_bgp` of none: the run states `not-captured` for
    the whole table and publishes no file, so the reader answers no rows and
    says which of the two it is."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    tables = {
        ROUTES: TableOutcome(status="not-captured", detail="the source's capture_bgp setting is none"),
        SESSIONS: TableOutcome(status="not-captured", detail="the source's capture_bgp setting is none"),
    }
    _publish(settings, 1000, None, [_device(RUN_A, tables)], [_raw_entry(RUN_A)])
    rs = _reader(settings, 1000)
    try:
        assert rs.paths(DEV, CONTEXT, PREFIX) == []
        assert rs.session_state(SESSION_A) is None
        assert rs.coverage(DEV, ROUTES) is None  # no run holds rows to select
    finally:
        rs.close()


def test_a_failed_write_answers_no_rows_and_never_falls_back(store):
    """A later run whose path table failed to write holds no rows for the
    device: the reader answers none from it and none from the two older runs
    whose files are still on disk.

    The per-session directions name the failure.
    """
    pytest.importorskip("duckdb")
    run_c = "1700000002000-cccccccc"
    tables = {
        ROUTES: TableOutcome(status="failed", detail="OSError: disk full"),
        **_directions(a_accepted="failed", b_accepted="failed"),
    }
    _publish(store, 3000, 2000, [_device(run_c, tables)], [_raw_entry(run_c)])
    rs = _reader(store, 3000)
    try:
        assert rs.paths(DEV, CONTEXT, PREFIX) == []
        assert rs.prefixes(SESSION_B, "accepted") == []
        assert rs.direction_status(SESSION_B, "accepted") == "failed"
    finally:
        rs.close()
    by_age = BgpSource(store.sidestore_dir, as_of_ms=3000)
    try:
        assert [r["peer_ip"] for r in by_age.paths(DEV, CONTEXT, PREFIX)] == [PEER_B]
    finally:
        by_age.close()


# --- observed session state -------------------------------------------------------------


def test_a_session_reported_down_is_a_row_of_its_own(store):
    """The storage contract's distinction: a session going down and a peer
    configuration being removed are different facts. The configured session
    still exists."""
    rs = _reader(store, 2000)
    try:
        state = rs.session_state(SESSION_A)
        assert state is not None
        assert state["session_uid"] == SESSION_A
        assert (state["state"], state["peer_ip"]) == ("Idle", PEER_A)
        assert state["context_uid"] == CONTEXT
        assert rs.session_state(SESSION_B)["state"] == "Established"
    finally:
        rs.close()
    rs = _reader(store, 1000)
    try:
        assert rs.session_state(SESSION_A)["state"] == "Established"
    finally:
        rs.close()


def test_a_configured_session_with_no_observation_answers_none(store):
    """The inverse fact: a session the graph holds and no run observed has no
    row here, and that is not a report that it is down."""
    rs = _reader(store, 1000)
    try:
        assert rs.session_state(_session_uid("203.0.113.1")) is None
    finally:
        rs.close()


# --- file selection ---------------------------------------------------------------------


def test_a_file_no_manifest_publishes_is_ignored(store):
    """A parquet file from a run that never published sits after snapshot B by
    `snapshot_ts`. Pinned at B, the reader never opens it."""
    sidestore.write_table(
        store.sidestore_dir,
        ROUTES,
        "edge",
        "r1",
        "1700000009000-ffffffff",
        [_path(SESSION_A, PEER_A, "203.0.113.0/24", best=True)],
        2000,
    )
    rs = _reader(store, 2000)
    try:
        assert [r["prefix"] for r in rs.paths(DEV, CONTEXT)] == [PREFIX]
        assert rs.approximate is False
    finally:
        rs.close()
    by_age = BgpSource(store.sidestore_dir, as_of_ms=2000)
    try:
        assert "203.0.113.0/24" in [r["prefix"] for r in by_age.paths(DEV, CONTEXT)]
        assert by_age.approximate is True
    finally:
        by_age.close()


def test_a_pin_without_a_manifest_is_approximate(tmp_path):
    """A fixture store, or a run with no manifest: the newest file at
    or before the bound answers, and the reader says the answer is not one a
    published manifest stands behind."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    sidestore.write_table(
        settings.sidestore_dir, ROUTES, "edge", "r1", RUN_A, [_path(SESSION_A, PEER_A, best=True)], 1000
    )
    rs = _reader(settings, 1000)
    try:
        assert rs.approximate is True
        assert [r["peer_ip"] for r in rs.paths(DEV, CONTEXT, PREFIX)] == [PEER_A]
        assert rs.coverage(DEV) is None
        assert rs.direction_status(SESSION_A, "received") is None
    finally:
        rs.close()


def test_no_store_at_all_answers_nothing_rather_than_raising(tmp_path):
    rs = BgpSource(tmp_path / "absent")
    assert rs.available is False
    assert rs.paths(DEV, CONTEXT, PREFIX) == []
    assert rs.session_state(SESSION_A) is None
    assert rs.prefixes(SESSION_A, "accepted") == []


def test_coverage_names_what_the_run_recorded(store):
    rs = _reader(store, 1000)
    try:
        assert rs.coverage(DEV, ROUTES) == "complete"
        assert rs.coverage(DEV, SESSIONS) == "complete"
    finally:
        rs.close()


# a real platform's own row-shaping function


def test_the_vyos_collectors_own_rows_round_trip_through_the_reader(tmp_path):
    """`vyos.bgp_side_rows`'s own session_uid/context_uid formulas match what
    this reader expects."""
    pytest.importorskip("duckdb")
    import json

    from hst.collectors import vyos as vyos_mod

    dev = "dev:edge1"
    cfg = {
        "system": {"host-name": "edge1"},
        "protocols": {"bgp": {"system-as": "65000", "neighbor": {"203.0.113.2": {"remote-as": "65001"}}}},
    }
    peer_state = {"state": "Established", "pfxRcd": 1, "pfxSnt": 1}
    summary = {"default": {"ipv4Unicast": {"peers": {"203.0.113.2": peer_state}}}}
    accepted = {
        "routes": {
            "10.20.0.0/24": [
                {
                    "aspath": {"string": "65001"},
                    "origin": "i",
                    "bestpath": True,
                    "nexthops": [{"ip": "203.0.113.2", "used": True}],
                }
            ]
        }
    }
    raw = {
        "config": cfg,
        vyos_mod.BGP_SUMMARY_COMMAND: json.dumps(summary),
        vyos_mod.bgp_route_command("default", "203.0.113.2", "accepted"): json.dumps(accepted),
    }
    tables = vyos_mod.bgp_side_rows(raw, dev)
    session_uid = tables["bgp_sessions"][0]["session_uid"]
    context_uid = tables["bgp_sessions"][0]["context_uid"]
    assert context_uid == "vrf:dev:edge1:default"

    settings = _settings(tmp_path)
    routes = _write(settings, ROUTES, RUN_A, tables["bgp_session_routes"], 1000, source="vyos1", host="edge1")
    sessions = _write(settings, SESSIONS, RUN_A, tables["bgp_sessions"], 1000, source="vyos1", host="edge1")
    route_rows, session_rows = tables["bgp_session_routes"], tables["bgp_sessions"]
    outcome_tables = {
        ROUTES: TableOutcome(status="complete", row_count=len(route_rows), path=routes.path),
        SESSIONS: TableOutcome(status="complete", row_count=len(session_rows), path=sessions.path),
        manifest.bgp_direction_key(session_uid, "accepted"): TableOutcome(status="complete", row_count=1),
    }
    _publish(
        settings,
        1000,
        None,
        [_device(RUN_A, outcome_tables, source="vyos1", host="edge1")],
        [_raw_entry(RUN_A, source="vyos1", host="edge1"), routes, sessions],
    )
    rs = _reader(settings, 1000)
    try:
        rows = rs.paths(dev, context_uid, "10.20.0.0/24", direction="accepted")
        assert len(rows) == 1
        assert rows[0]["session_uid"] == session_uid
        assert rows[0]["best"] is True
        state = rs.session_state(session_uid)
        assert state is not None
        assert (state["peer_ip"], state["state"]) == ("203.0.113.2", "Established")
        assert rs.direction_status(session_uid, "accepted") == "complete"
    finally:
        rs.close()


def test_the_apic_collectors_own_rows_round_trip_through_the_reader(tmp_path):
    """The APIC twin of the VyOS test above: `apic.bgp_side_rows`'s own
    session_uid/context_uid formulas, and `apic.bgp_table_outcomes`'s
    not-captured statement for the one table APIC's class model never fills,
    round-trip through the same reader."""
    pytest.importorskip("duckdb")

    from hst.collectors import apic as apic_mod

    fabric = "fab1"
    peer_dn = "topology/pod-1/node-101/sys/bgp/inst/dom-prod:prod-vrf/peer-[203.0.113.2]"
    node = {"fabricNode": {"attributes": {"dn": "topology/pod-1/node-101", "serial": "FDO101LEAF"}}}
    raw = {
        "fabricNode": [node],
        "bgpPeerEntry": [{"bgpPeerEntry": {"attributes": {"dn": peer_dn, "operSt": "established"}}}],
        "bgpPeerAfEntry": [{"bgpPeerAfEntry": {"attributes": {"dn": f"{peer_dn}/af-[ipv4-ucast]"}}}],
    }
    tables = apic_mod.bgp_side_rows(raw, fabric)
    session_uid = tables["bgp_sessions"][0]["session_uid"]
    context_uid = tables["bgp_sessions"][0]["context_uid"]
    assert context_uid == "aci:fab1:uni/tn-prod/ctx-prod-vrf"
    dev = tables["bgp_sessions"][0]["device_uid"]

    settings = _settings(tmp_path)
    sessions = _write(settings, SESSIONS, RUN_A, tables["bgp_sessions"], 1000, source="apic1", host="")
    outcome_tables = {
        SESSIONS: TableOutcome(status="complete", row_count=len(tables["bgp_sessions"]), path=sessions.path),
        **apic_mod.bgp_table_outcomes(raw, fabric, capture="all"),
    }
    _publish(
        settings,
        1000,
        None,
        [_device(RUN_A, outcome_tables, source="apic1", host="")],
        [_raw_entry(RUN_A, source="apic1", host=""), sessions],
    )
    rs = _reader(settings, 1000)
    try:
        state = rs.session_state(session_uid)
        assert state is not None
        assert (state["peer_ip"], state["state"]) == ("203.0.113.2", "established")
        # the class model exposes no per-peer path table for any direction,
        # on any run: every direction reads not-captured
        for direction in ("received", "accepted", "advertised"):
            assert rs.direction_status(session_uid, direction) == "not-captured"
        assert rs.paths(dev, context_uid, "10.20.0.0/24") == []
    finally:
        rs.close()
