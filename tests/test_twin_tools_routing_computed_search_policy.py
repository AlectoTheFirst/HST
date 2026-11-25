"""The routing tools: `routing_routes` with `source: computed|both`
and `mode: search_prefix`, the whole-call deadline, and
`routing_evaluate_policy` with its clause attribution and gaps."""

from __future__ import annotations

import threading

import pytest
from tests.twin_tools_fakes import FakeGraph, call, context, install, settings

from hst.app import simul_read
from hst.core import ipenc, ribsource
from hst.simul import rib
from hst.simul.errors import ErrorSink
from hst.twin_tools import catalogue_registry, routing
from hst.twin_tools.route_policy import NAMED_UNKNOWN, NO_POLICY_UNKNOWN
from hst.twin_tools.routing import ADMIN_UNKNOWN, COMPUTED_UNKNOWN

_DEVICE = ("MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})", [{"uid": "dev:r1"}])
_CTX = "vrf:r1:default"
_RUN = "1700000001000-bbbbbbbb"


def _node(label, name=None, device_uid=None):
    """The node lookup of the explore route body."""
    return ("CASE WHEN n:VrfInstance THEN", [{"label": label, "name": name, "device_uid": device_uid}])


def _join_abandoned_workers():
    for thread in threading.enumerate():
        if thread.name == "hst-tool-deadline":
            thread.join(5)


# --- computed routes -----------------------------------------------------------------------


def _observed(prefix, next_hop, protocol, interface="Ethernet1/1"):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "interface": interface,
        "protocol": protocol,
        "discard": None,
        "metric": 0,
        "prefixlen": int(prefix.split("/")[1]),
        "af": 4,
    }


def _rib_input():
    """One NX-OS context: a connected /30, a static the device also holds, and
    a static the device does not hold."""
    return rib.RibInput(
        contexts=[{"uid": _CTX, "device_uid": "dev:r1", "name": "default", "platform": "nxos"}],
        connected=[{"context_uid": _CTX, "prefix": "10.0.0.0/30", "interface": "Ethernet1/1"}],
        static=[
            {
                "context_uid": _CTX,
                "prefix": prefix,
                "next_hop": "10.0.0.2",
                "interface": None,
                "next_hop_context_uid": None,
                "discard": None,
            }
            for prefix in ("10.1.0.0/16", "10.1.2.0/24")
        ],
        observed_rib={
            _CTX: [
                _observed("10.0.0.0/30", "10.0.0.1", "direct"),
                _observed("10.1.0.0/16", "10.0.0.2", "static"),
            ]
        },
        rib_coverage={_CTX: "complete"},
        platform="nxos",
    )


@pytest.fixture
def computed(monkeypatch):
    """`read_rib_input` answers with `_rib_input` and records how it was called."""
    seen = {}

    def read(session, *, contexts=(), devices=(), rib_source=None, bgp_source=None, ospf_source=None, **_):
        seen.update(
            contexts=list(contexts), devices=list(devices), readers=(rib_source, bgp_source, ospf_source)
        )
        return simul_read.RibGraphInput(_rib_input(), [_CTX], ErrorSink())

    monkeypatch.setattr(simul_read, "read_rib_input", read)
    return seen


def test_computed_rows_carry_admin_and_the_validation_decides_their_evidence(monkeypatch, tmp_path, computed):
    install(monkeypatch, FakeGraph([_DEVICE]))

    failed, envelope = call(
        "routing_routes",
        {"mode": "lookup", "device": "dev:r1", "address": "10.1.2.7", "source": "computed"},
        context(sidestore_dir=tmp_path),
    )

    assert not failed, envelope
    result = envelope["result"]
    assert computed["devices"] == ["dev:r1"] and computed["contexts"] == []
    # the readers the calculation read through were bound to the call's run
    assert all(reader is not None for reader in computed["readers"])
    # observed fields stay empty when only the calculation answers
    assert result.get("routes") is None and result.get("available") is None
    part = result["computed"]
    assert part["contexts"] == [_CTX] and part["convergence"] == "settled"
    rows = part["routes"]
    assert [r["prefix"] for r in rows] == ["10.1.2.0/24", "10.1.0.0/16"]
    assert [r["longest_match"] for r in rows] == [True, False]
    # criterion 2: computed rows carry the administrative distance
    assert [r["admin"] for r in rows] == [1, 1]
    assert all(isinstance(r["admin"], int) for r in rows)
    by_prefix = {r["prefix"]: r for r in rows}
    assert by_prefix["10.1.0.0/16"]["validation"] == "validated"
    validated = by_prefix["10.1.0.0/16"]["evidence"]
    assert validated["result"]["word"] == "computed and confirmed by the observed table"
    assert (validated["result"]["kind"], validated["basis"]) == ("record", "computed")
    # the device holds no route for the /24: a mismatch establishes nothing
    assert by_prefix["10.1.2.0/24"]["validation"] == "mismatch"
    assert by_prefix["10.1.2.0/24"]["evidence"]["result"]["word"] == "computed; the observed table disagrees"
    assert [m["code"] for m in by_prefix["10.1.2.0/24"]["evidence"]["result"]["missing"]] == [
        "rib-route-mismatch"
    ]
    assert envelope["evidence"]["result"]["word"] == "each item states its own result"
    assert COMPUTED_UNKNOWN in envelope["evidence"]["unknowns"]
    assert ADMIN_UNKNOWN not in envelope["evidence"]["unknowns"]
    assert envelope["provenance"]["engine_function"] == "hst.simul.rib.compute"


def test_both_sources_side_by_side_observed_admin_is_null_and_says_why(monkeypatch, tmp_path, computed):
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    lo, hi, prefixlen, af = ipenc.prefix_bounds("10.1.0.0/16")
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        _RUN,
        [
            {
                "device_uid": "dev:r1",
                "vrf": "default",
                "context_uid": _CTX,
                "prefix": "10.1.0.0/16",
                "next_hop": "10.0.0.2",
                "interface": None,
                "protocol": "static",
                "metric": 0,
                "af": af,
                "prefixlen": prefixlen,
                "lo": lo,
                "hi": hi,
            }
        ],
        1700,
    )
    install(monkeypatch, FakeGraph([_DEVICE, _node("Device")]))

    failed, envelope = call(
        "routing_routes",
        {"mode": "lookup", "device": "dev:r1", "address": "10.1.2.7", "source": "both"},
        context(sidestore_dir=tmp_path),
    )

    assert not failed, envelope
    result = envelope["result"]
    # criterion 3: observed rows carry admin null, with the unknown about the side store
    assert [r["prefix"] for r in result["routes"]] == ["10.1.0.0/16"]
    assert all(r["admin"] is None for r in result["routes"])
    assert ADMIN_UNKNOWN in envelope["evidence"]["unknowns"]
    # criterion 2 beside it: computed rows carry admin
    assert [r["admin"] for r in result["computed"]["routes"]] == [1, 1]
    assert COMPUTED_UNKNOWN in envelope["evidence"]["unknowns"]
    assert result["source"] == "both"


def test_a_computed_table_pages_filters_and_counts_protocols(monkeypatch, tmp_path, computed):
    install(monkeypatch, FakeGraph([_DEVICE]))
    ctx = context(sidestore_dir=tmp_path)

    _, first = call(
        "routing_routes", {"mode": "table", "device": "dev:r1", "source": "computed", "limit": 2}, ctx
    )
    _, second = call(
        "routing_routes",
        {
            "mode": "table",
            "device": "dev:r1",
            "source": "computed",
            "limit": 2,
            "cursor": first["page"]["next_cursor"],
        },
        ctx,
    )
    _, statics = call(
        "routing_routes",
        {"mode": "table", "device": "dev:r1", "source": "computed", "protocol": "static"},
        ctx,
    )

    assert [r["prefix"] for r in first["result"]["computed"]["routes"]] == ["10.0.0.0/30", "10.1.0.0/16"]
    assert first["page"]["truncated"] is True and first["page"]["total"] == 3
    assert [r["prefix"] for r in second["result"]["computed"]["routes"]] == ["10.1.2.0/24"]
    assert second["page"]["truncated"] is False
    assert first["result"]["computed"]["protocols"] == [
        {"protocol": "static", "count": 2},
        {"protocol": "connected", "count": 1},
    ]
    assert [r["admin"] for r in statics["result"]["computed"]["routes"]] == [1, 1]


async def test_a_table_accepts_no_both_source(monkeypatch):
    pytest.importorskip("mcp")
    from hst.app.ai import mcp as ai_mcp
    from hst.mcp_server import build_server

    monkeypatch.setattr(ai_mcp, "Settings", lambda: settings())
    graph = install(monkeypatch, FakeGraph())

    res = await build_server().call_tool(
        "routing_routes", {"mode": "table", "device": "dev:r1", "source": "both"}
    )

    assert res.is_error is True
    assert res.structured_content["error"]["code"] == "invalid_argument"
    assert res.structured_content["error"]["field"] == "source"
    assert graph.session_kwargs == []


# --- criterion 4: the whole-call deadline ---------------------------------------------------


def test_a_routing_calculation_past_the_deadline_returns_timeout(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph([_DEVICE]))
    release = threading.Event()

    def slow(*args, **kwargs):
        release.wait(5)
        return simul_read.RibGraphInput(_rib_input(), [_CTX], ErrorSink())

    monkeypatch.setattr(simul_read, "read_rib_input", slow)
    monkeypatch.setattr(routing, "DEADLINE_S", 0.2)
    try:
        failed, error = call(
            "routing_routes",
            {"mode": "lookup", "device": "dev:r1", "address": "10.1.2.7", "source": "computed"},
            context(sidestore_dir=tmp_path),
        )
    finally:
        release.set()
        _join_abandoned_workers()

    assert failed
    assert error["error"]["code"] == "timeout"
    assert error["error"]["retryable"] is True
    assert "deadline" in error["error"]["message"]


def test_a_prefix_search_past_the_deadline_returns_timeout(monkeypatch):
    release = threading.Event()

    def slow(params):
        release.wait(5)
        return []

    install(monkeypatch, FakeGraph([("ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE", slow)]))
    monkeypatch.setattr(routing, "DEADLINE_S", 0.2)
    try:
        failed, error = call(
            "routing_routes", {"mode": "search_prefix", "prefix": "10.0.0.0/8", "role": "originated"}
        )
    finally:
        release.set()
        _join_abandoned_workers()

    assert failed and error["error"]["code"] == "timeout"


def test_an_engine_error_inside_the_deadline_reaches_the_caller(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph([_DEVICE]))

    def broken(*args, **kwargs):
        raise ValueError("the read failed")

    monkeypatch.setattr(simul_read, "read_rib_input", broken)

    failed, error = call(
        "routing_routes",
        {"mode": "lookup", "device": "dev:r1", "address": "10.1.2.7", "source": "computed"},
        context(sidestore_dir=tmp_path),
    )

    assert failed and error["error"]["code"] == "internal"
    assert "the read failed" in error["error"]["message"]


# --- search_prefix -------------------------------------------------------------------------


def _rib_row(device_uid, context_uid, prefix, next_hop, protocol="bgp"):
    lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
    return {
        "device_uid": device_uid,
        "vrf": "default",
        "context_uid": context_uid,
        "prefix": prefix,
        "next_hop": next_hop,
        "interface": None,
        "protocol": protocol,
        "metric": 0,
        "af": af,
        "prefixlen": prefixlen,
        "lo": lo,
        "hi": hi,
    }


def _bgp_row(device_uid, session_uid, prefix, direction):
    lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
    return {
        "device_uid": device_uid,
        "context_uid": f"vrf:{device_uid[4:]}:default",
        "session_uid": session_uid,
        "peer_ip": "10.9.9.9",
        "af": af,
        "safi": "unicast",
        "direction": direction,
        "rib_type": "adj-rib-in",
        "policy_stage": "pre-import" if direction == "received" else "post-export",
        "path_id": "0",
        "prefix": prefix,
        "prefixlen": prefixlen,
        "lo": lo,
        "hi": hi,
        "next_hop": "10.9.9.9",
        "next_hop_context_uid": None,
        "as_path": "65009",
        "local_pref": 100,
        "med": 0,
        "origin": "i",
        "communities": None,
        "best": True,
    }


@pytest.fixture
def estate(tmp_path):
    """Two devices' route tables and one device's BGP paths. dev:r1 has an
    older run the snapshot does not select and a newer run past the bound."""
    pytest.importorskip("duckdb")
    from hst.core import sidestore

    r1, r2 = "vrf:r1:default", "vrf:r2:default"
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "r1",
        "1000-aaaaaaaa",
        [_rib_row("dev:r1", r1, "10.1.0.0/16", "10.0.0.8")],
        1000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "r1",
        "2000-bbbbbbbb",
        [
            _rib_row("dev:r1", r1, "10.1.0.0/16", "10.0.0.2"),
            _rib_row("dev:r1", r1, "10.1.2.0/24", "10.0.0.3"),
            _rib_row("dev:r1", r1, "10.0.0.0/8", "10.0.0.4", "static"),
            _rib_row("dev:r1", r1, "192.0.2.0/24", "10.0.0.5"),
        ],
        2000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "r1",
        "9000-cccccccc",
        [_rib_row("dev:r1", r1, "10.1.0.0/16", "10.0.0.9")],
        9000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "r2",
        "1500-dddddddd",
        [_rib_row("dev:r2", r2, "10.1.0.0/16", "10.2.0.1")],
        1500,
    )
    sidestore.write_table(
        tmp_path,
        "bgp_session_routes",
        "nxos",
        "r2",
        "1500-dddddddd",
        [
            _bgp_row("dev:r2", "bgp:r2:10.9.9.9", "10.1.0.0/16", "received"),
            _bgp_row("dev:r2", "bgp:r2:10.9.9.9", "10.1.0.0/16", "advertised"),
            _bgp_row("dev:r2", "bgp:r2:10.9.9.9", "172.16.0.0/12", "received"),
        ],
        1500,
    )
    return tmp_path


_GRAPH_ROUTES = [
    {
        "device_uid": "dev:r1",
        "context_uid": "vrf:r1:default",
        "prefix": "10.1.0.0/16",
        "edge": "STATIC_ROUTE",
        "protocol": None,
        "next_hop": "10.0.0.2",
        "next_hop_context_uid": None,
        "derived": None,
    },
    {
        "device_uid": "dev:r2",
        "context_uid": "vrf:r2:default",
        "prefix": "10.1.0.0/16",
        "edge": "LEARNED_ROUTE",
        "protocol": "bgp",
        "next_hop": None,
        "next_hop_context_uid": None,
        "derived": "rt-import",
    },
]


def test_an_exact_search_reads_every_device_from_its_selected_run_ordered_by_device(monkeypatch, estate):
    graph = install(monkeypatch, FakeGraph([("ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE", _GRAPH_ROUTES)]))

    failed, envelope = call(
        "routing_routes", {"mode": "search_prefix", "prefix": "10.1.0.0/16"}, context(sidestore_dir=estate)
    )

    assert not failed, envelope
    items = envelope["result"]["items"]
    assert [(i["device_uid"], i["role"], i["source"]) for i in items] == [
        ("dev:r1", "originated", "graph"),
        ("dev:r1", "installed", "rib"),
        ("dev:r2", "learned", "graph"),
        ("dev:r2", "learned", "bgp_session_routes"),
        ("dev:r2", "installed", "rib"),
        ("dev:r2", "advertised", "bgp_session_routes"),
    ]
    by_key = {(i["device_uid"], i["source"], i["role"]): i for i in items}
    # dev:r1 answers from the run at 2000: the older run and the run past the bound do not
    assert by_key[("dev:r1", "rib", "installed")]["next_hop"] == "10.0.0.2"
    assert by_key[("dev:r1", "rib", "installed")]["run_id"] == "2000-bbbbbbbb"
    assert by_key[("dev:r1", "graph", "originated")]["protocol"] == "static"
    assert by_key[("dev:r1", "graph", "originated")]["evidence"]["basis"] == "configured"
    assert by_key[("dev:r2", "graph", "learned")]["evidence"]["basis"] == "derived"
    assert by_key[("dev:r2", "bgp_session_routes", "learned")]["direction"] == "received"
    assert envelope["result"]["total"] == 6
    # no manifest governs the run, so the observed rows are possible and say why
    assert (
        by_key[("dev:r1", "rib", "installed")]["evidence"]["result"]["word"]
        == "recorded from an incomplete table"
    )
    assert any("route table files were chosen by age" in u for u in envelope["evidence"]["unknowns"])
    assert envelope["evidence"]["absence"] == "not_recorded"
    (read,) = graph.reads("ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE")
    assert read["cidrs"] == ["10.1.0.0/16"] and read["starts"] is None
    assert set(read["kinds"]) == {"ORIGINATES", "STATIC_ROUTE", "LEARNED_ROUTE"}


def test_longer_and_shorter_matches_and_a_role_narrow_the_search(monkeypatch, estate):
    graph = install(monkeypatch, FakeGraph())
    ctx = context(sidestore_dir=estate)

    _, longer = call(
        "routing_routes",
        {"mode": "search_prefix", "prefix": "10.1.0.0/16", "match": "longer", "role": "installed"},
        ctx,
    )
    _, shorter = call(
        "routing_routes",
        {"mode": "search_prefix", "prefix": "10.1.2.0/24", "match": "shorter", "role": "installed"},
        ctx,
    )
    _, advertised = call(
        "routing_routes",
        {"mode": "search_prefix", "prefix": "10.0.0.0/8", "match": "longer", "role": "advertised"},
        ctx,
    )

    assert [(i["device_uid"], i["prefix"]) for i in longer["result"]["items"]] == [
        ("dev:r1", "10.1.0.0/16"),
        ("dev:r1", "10.1.2.0/24"),
        ("dev:r2", "10.1.0.0/16"),
    ]
    assert [(i["device_uid"], i["prefix"]) for i in shorter["result"]["items"]] == [
        ("dev:r1", "10.0.0.0/8"),
        ("dev:r1", "10.1.0.0/16"),
        ("dev:r1", "10.1.2.0/24"),
        ("dev:r2", "10.1.0.0/16"),
    ]
    assert [(i["role"], i["direction"]) for i in advertised["result"]["items"]] == [
        ("advertised", "advertised")
    ]
    # a role that reads no graph edge sends no graph read
    assert graph.reads("ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE") == []


def test_a_search_pages_with_a_cursor(monkeypatch, estate):
    install(monkeypatch, FakeGraph())
    ctx = context(sidestore_dir=estate)
    arguments = {
        "mode": "search_prefix",
        "prefix": "10.0.0.0/8",
        "match": "longer",
        "role": "installed",
        "limit": 2,
    }

    _, first = call("routing_routes", arguments, ctx)
    _, second = call("routing_routes", {**arguments, "cursor": first["page"]["next_cursor"]}, ctx)

    assert [i["prefix"] for i in first["result"]["items"]] == ["10.0.0.0/8", "10.1.0.0/16"]
    assert first["page"]["total"] == 4 and first["page"]["truncated"] is True
    assert [(i["device_uid"], i["prefix"]) for i in second["result"]["items"]] == [
        ("dev:r1", "10.1.2.0/24"),
        ("dev:r2", "10.1.0.0/16"),
    ]
    assert second["page"]["truncated"] is False


def test_a_search_names_devices_whose_table_was_not_recorded_complete(monkeypatch, estate):
    install(monkeypatch, FakeGraph())
    outcomes = {"dev:r1": "complete", "dev:r2": "partial"}
    monkeypatch.setattr(ribsource.RibSource, "approximate", property(lambda self: False))
    monkeypatch.setattr(ribsource.RibSource, "coverage", lambda self, device_uid: outcomes[device_uid])

    failed, envelope = call(
        "routing_routes",
        {"mode": "search_prefix", "prefix": "10.1.0.0/16", "role": "installed"},
        context(sidestore_dir=estate),
    )

    assert not failed
    statuses = {i["device_uid"]: i["evidence"]["result"]["word"] for i in envelope["result"]["items"]}
    assert statuses == {
        "dev:r1": "recorded from a complete table",
        "dev:r2": "recorded from an incomplete table",
    }
    assert envelope["evidence"]["result"]["word"] == "each item states its own result"
    assert any(u.endswith("as complete: dev:r2") for u in envelope["evidence"]["unknowns"])


def _governed(monkeypatch, base, *devices):
    """Route every search's route table reader through a snapshot evidence
    that lists `devices`."""
    evidence = ribsource.SnapshotEvidence(
        snapshot_key=2000, data_dir=base, devices=list(devices), chain=ribsource._Chain(None)
    )
    monkeypatch.setattr(
        ribsource, "for_snapshot", lambda snapshot: ribsource.RibSource(base, evidence=evidence)
    )


def test_a_search_names_the_devices_the_snapshot_holds_no_complete_table_for(monkeypatch, estate):
    install(monkeypatch, FakeGraph())
    arguments = {"mode": "search_prefix", "prefix": "10.1.0.0/16", "role": "installed"}
    _governed(
        monkeypatch,
        estate,
        ribsource.DeviceEvidence(
            "nxos", "r1", "2000-bbbbbbbb", "complete", path=estate / "rib/nxos/r1/2000-bbbbbbbb.parquet"
        ),
        ribsource.DeviceEvidence("nxos", "r2", "1500-dddddddd", "failed"),
        ribsource.DeviceEvidence("nxos", "r3", None, None),
    )

    failed, envelope = call("routing_routes", arguments, context(sidestore_dir=estate))

    assert not failed, envelope
    # dev:r2 has rows on disk, but the snapshot selects no file for it
    assert [(i["device_uid"], i["evidence"]["result"]["word"]) for i in envelope["result"]["items"]] == [
        ("dev:r1", "recorded from a complete table")
    ]
    assert envelope["evidence"]["unknowns"] == [
        "the snapshot holds no complete route table for these devices, named by source/host, so they "
        "answer no rows: nxos/r2, nxos/r3"
    ]

    # a snapshot that publishes no route table file at all
    _governed(monkeypatch, estate, ribsource.DeviceEvidence("nxos", "r1", "2000-bbbbbbbb", "partial"))

    failed, envelope = call("routing_routes", arguments, context(sidestore_dir=estate))

    assert not failed, envelope
    assert envelope["result"]["items"] == [] and envelope["result"]["available"] is True
    assert envelope["evidence"]["unknowns"] == [
        "the snapshot publishes no route table file",
        "the snapshot holds no complete route table for these devices, named by source/host, so they "
        "answer no rows: nxos/r1",
    ]


def test_the_search_cap_counts_only_the_rows_of_each_devices_selected_run(monkeypatch, estate):
    from hst.core import sidestore

    install(monkeypatch, FakeGraph())
    # dev:r2 also holds an older run under the run id dev:r1 stands on
    sidestore.write_table(
        estate,
        "rib",
        "nxos",
        "r2",
        "2000-bbbbbbbb",
        [_rib_row("dev:r2", "vrf:r2:default", "10.1.0.0/16", "10.2.0.9")],
        1200,
    )
    monkeypatch.setattr(routing, "SEARCH_CAP", 2)

    failed, envelope = call(
        "routing_routes",
        {"mode": "search_prefix", "prefix": "10.1.0.0/16", "role": "installed"},
        context(sidestore_dir=estate),
    )

    assert not failed, envelope
    assert [(i["device_uid"], i["run_id"]) for i in envelope["result"]["items"]] == [
        ("dev:r1", "2000-bbbbbbbb"),
        ("dev:r2", "1500-dddddddd"),
    ]


def test_a_shorter_search_reads_the_covering_prefixes_and_a_longer_one_their_text(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    call(
        "routing_routes",
        {"mode": "search_prefix", "prefix": "10.1.2.0/24", "match": "shorter", "role": "originated"},
    )
    call(
        "routing_routes",
        {"mode": "search_prefix", "prefix": "10.16.0.0/12", "match": "longer", "role": "originated"},
    )

    shorter, longer = graph.reads("ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE")
    assert shorter["cidrs"][0] == "0.0.0.0/0" and shorter["cidrs"][-1] == "10.1.2.0/24"
    assert len(shorter["cidrs"]) == 25
    assert longer["cidrs"] is None
    assert longer["starts"] == [f"10.{n}." for n in range(16, 32)]
    assert shorter["kinds"] == ["ORIGINATES", "STATIC_ROUTE"]


def test_a_search_that_matches_too_many_routes_is_refused(monkeypatch):
    monkeypatch.setattr(routing, "SEARCH_CAP", 1)
    install(monkeypatch, FakeGraph([("ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE", _GRAPH_ROUTES)]))

    failed, error = call(
        "routing_routes", {"mode": "search_prefix", "prefix": "10.1.0.0/16", "role": "originated"}
    )

    assert failed and error["error"]["code"] == "limit_exceeded"


def test_a_prefix_that_is_no_prefix_is_refused_before_any_read(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    failed, error = call("routing_routes", {"mode": "search_prefix", "prefix": "10.1.0.0/33"})

    assert failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "prefix"
    assert graph.session_kwargs == []


# --- the published modes --------------------------------------------------------------------


def test_the_input_schema_lists_the_served_modes_and_sources():
    schema = catalogue_registry().get("routing_routes").input_schema()

    assert schema["properties"]["mode"]["enum"] == ["lookup", "table", "search_prefix"]
    sources = {}
    for branch in schema["oneOf"]:
        variant = schema["$defs"][branch["$ref"].rsplit("/", 1)[-1]]
        mode = variant["properties"]["mode"]["const"]
        sources[mode] = variant["properties"].get("source", {}).get("enum")
        if mode == "search_prefix":
            assert variant["required"] == ["mode", "prefix"]
    assert sources == {
        "lookup": ["observed", "computed", "both"],
        "table": ["observed", "computed"],
        "search_prefix": None,
    }


async def test_mcp_serves_search_prefix_and_the_policy_tool(monkeypatch):
    pytest.importorskip("mcp")
    from hst.app.ai import mcp as ai_mcp
    from hst.mcp_server import build_server

    monkeypatch.setattr(ai_mcp, "Settings", lambda: settings())
    install(monkeypatch, FakeGraph([("ORIGINATES|STATIC_ROUTE|LEARNED_ROUTE", _GRAPH_ROUTES)]))
    server = build_server()

    tools = {t.name: t for t in await server.list_tools()}
    res = await server.call_tool(
        "routing_routes", {"mode": "search_prefix", "prefix": "10.1.0.0/16", "role": "originated"}
    )

    assert "routing_evaluate_policy" in tools
    assert tools["routing_routes"].input_schema["properties"]["mode"]["enum"] == [
        "lookup",
        "table",
        "search_prefix",
    ]
    assert res.is_error is False
    assert [i["device_uid"] for i in res.structured_content["result"]["items"]] == ["dev:r1"]


# --- routing_evaluate_policy ---------------------------------------------------------------

_SESSION_UID = "bgp:r1:10.1.0.2"


def _session(platform="iosxe", **props):
    return (
        "{uid: $session_uid, collection_ts: $snap}",
        [
            {
                "props": {
                    "uid": _SESSION_UID,
                    "peer_ip": "10.1.0.2",
                    "peer_asn": 65002,
                    "local_asn": 65001,
                    **props,
                },
                "process": {"asn": 65001},
                "context_uid": _CTX,
                "device_uid": "dev:r1",
                "platform": platform,
                "vendor": "cisco",
            }
        ],
    )


def _prefix_list(name, *lines):
    return {
        "uid": f"rtpol:dev:r1:prefix-list:{name}",
        "name": name,
        "kind": "prefix-list",
        "entries": [
            {"seq": seq, "action": action, "prefix": prefix, "min_len": low, "max_len": high}
            for seq, action, prefix, low, high in lines
        ],
    }


def _route_map(name, *clauses, kind="route-map"):
    return {"uid": f"rtpol:dev:r1:{kind}:{name}", "name": name, "kind": kind, "entries": list(clauses)}


_PL = _prefix_list("PL", (5, "permit", "10.0.0.0/8", 8, 24))
_PL_DENY = _prefix_list("PL-DENY", (5, "permit", "192.168.0.0/16", 16, 32))
_RM_IN = _route_map(
    "RM-IN",
    {"seq": 10, "kind": "clause", "action": "deny", "match_prefix_lists": ["PL-DENY"]},
    {"seq": 20, "kind": "clause", "action": "permit", "match_prefix_lists": ["PL"], "set_local_pref": 200},
)
# A route map attached in the other direction, whose faults are not this answer's.
_RM_OUT = _route_map(
    "RM-OUT", {"seq": 10, "kind": "clause", "action": "permit", "match_community_lists": ["CL"]}
)


def _evaluate(**overrides):
    arguments = {
        "device": "dev:r1",
        "session_uid": _SESSION_UID,
        "direction": "import",
        "route": {"prefix": "10.1.0.0/16", "as_path": "65002 65010"},
    }
    arguments.update(overrides)
    return call("routing_evaluate_policy", arguments)


def test_an_attached_policy_decides_with_the_clause_and_prefix_list_line_that_matched(monkeypatch):
    graph = install(
        monkeypatch,
        FakeGraph(
            [
                _DEVICE,
                _session(import_policy_name="RM-IN", export_policy_name="RM-OUT"),
                ("b.uid IN $sessions", [_RM_IN, _RM_OUT, _PL, _PL_DENY]),
            ]
        ),
    )

    failed, envelope = _evaluate()

    assert not failed, envelope
    result = envelope["result"]
    assert result["decision"] == "accept" and result["outcome"] == "accept"
    assert result["policy"] == {
        "name": "RM-IN",
        "kind": "route-map",
        "uid": "rtpol:dev:r1:route-map:RM-IN",
        "attached": True,
        "defined": True,
    }
    assert result["matched"] == {"clause_seq": 20, "action": "permit", "prefix_list": "PL", "entry_seq": 5}
    assert [(c["seq"], c["matches"]) for c in result["clauses"]] == [(10, False), (20, True)]
    assert result["rewritten"]["local_pref"] == 200 and result["rewritten"]["changed"] == ["local_pref"]
    assert result["evidence"]["result"]["statement"] == "route-policy-accepts"
    assert result["evidence"]["result"]["word"] == "accepted"
    assert result["evidence"]["result"]["answer"] == "true"
    assert envelope["evidence"]["result"]["word"] == "accepted"
    assert envelope["evidence"]["result"]["word"] == "accepted"
    # the export policy's community list is not this answer's gap
    assert envelope["evidence"]["gaps"] == []
    (read,) = graph.reads("b.uid IN $sessions")
    assert read["sessions"] == [_SESSION_UID]


def test_a_prefix_list_beside_the_route_map_filters_first(monkeypatch):
    """The prefix-list attached beside the route-map is loaded with it
    and runs first, though no clause of the route-map references it."""
    permit_all = _route_map("RM-ALL", {"seq": 10, "kind": "clause", "action": "permit"})
    beside = _prefix_list("PL-BESIDE", (5, "permit", "10.0.0.0/8", 8, 24))
    install(
        monkeypatch,
        FakeGraph(
            [
                _DEVICE,
                _session(
                    import_policy_name="RM-ALL",
                    import_policy_kind="route-map",
                    import_prefix_list_name="PL-BESIDE",
                ),
                ("b.uid IN $sessions", [permit_all, beside]),
            ]
        ),
    )

    failed, envelope = _evaluate()
    assert not failed, envelope
    assert envelope["result"]["outcome"] == "accept"
    assert envelope["evidence"]["gaps"] == []

    failed, envelope = _evaluate(route={"prefix": "192.168.1.0/24"})
    assert not failed, envelope
    assert envelope["result"]["decision"] == "reject" and envelope["result"]["outcome"] == "reject"
    assert envelope["evidence"]["gaps"] == []


def test_a_neighbor_filter_list_leaves_the_decision_open_with_an_unsupported_gap(monkeypatch):
    """The engine denies at an AS-path filter-list it does not evaluate."""
    install(
        monkeypatch,
        FakeGraph(
            [
                _DEVICE,
                _session(import_policy_name="RM-IN", import_filter_list_name="AS-IN"),
                ("b.uid IN $sessions", [_RM_IN, _PL, _PL_DENY]),
            ]
        ),
    )

    failed, envelope = _evaluate()

    assert not failed, envelope
    assert envelope["result"]["outcome"] == "reject"
    (gap,) = envelope["evidence"]["gaps"]
    assert (gap["code"], gap["kind"]) == ("neighbor-filter-list-not-modeled", "unsupported")
    assert envelope["evidence"]["result"]["word"] == "not decided"


def test_an_attached_but_undefined_policy_is_undefined_policy_with_a_gap(monkeypatch):
    install(
        monkeypatch,
        FakeGraph([_DEVICE, _session(import_policy_name="RM-GONE", import_policy_kind="route-map")]),
    )

    failed, envelope = _evaluate()

    assert not failed, envelope
    result = envelope["result"]
    # criterion 1
    assert result["decision"] == "undefined-policy"
    assert result["policy"]["attached"] is True and result["policy"]["defined"] is False
    # IOS-XE denies every route at a route map it cannot find
    assert result["outcome"] == "reject"
    assert result["matched"] is None
    (gap,) = envelope["evidence"]["gaps"]
    assert gap["code"] == "undefined-neighbor-route-map" and gap["subject"] == "RM-GONE"
    assert envelope["evidence"]["result"]["word"] == "not decided"
    assert [m["code"] for m in result["evidence"]["result"]["missing"]] == ["undefined-neighbor-route-map"]


def test_a_named_policy_the_device_does_not_define_is_undefined_policy_with_a_gap(monkeypatch):
    graph = install(
        monkeypatch,
        FakeGraph(
            [_DEVICE, ("{uid: $device, collection_ts: $snap}", [{"platform": "iosxe", "vendor": "cisco"}])]
        ),
    )

    failed, envelope = _evaluate(session_uid=None, policy_name="NOPE")

    assert not failed, envelope
    result = envelope["result"]
    assert result["decision"] == "undefined-policy" and result["outcome"] is None
    assert result["policy"]["attached"] is False and result["policy"]["defined"] is False
    (gap,) = envelope["evidence"]["gaps"]
    assert gap["code"] == "undefined-policy" and gap["subject"] == "NOPE"
    assert envelope["evidence"]["result"]["word"] == "not decided"
    assert NAMED_UNKNOWN in envelope["evidence"]["unknowns"]
    (read,) = graph.reads("seed.name = $name")
    assert read["name"] == "NOPE" and read["uid_prefix"] == "rtpol:dev:r1:"


def test_a_named_policy_runs_outside_a_session(monkeypatch):
    install(
        monkeypatch,
        FakeGraph(
            [
                _DEVICE,
                ("{uid: $device, collection_ts: $snap}", [{"platform": "iosxe", "vendor": "cisco"}]),
                ("seed.name = $name", [_RM_IN, _PL, _PL_DENY]),
            ]
        ),
    )

    failed, envelope = _evaluate(session_uid=None, policy_name="RM-IN", route={"prefix": "192.168.1.0/24"})

    assert not failed, envelope
    result = envelope["result"]
    assert result["decision"] == "reject" and result["outcome"] == "reject"
    assert result["matched"] == {"clause_seq": 10, "action": "deny", "prefix_list": "PL-DENY", "entry_seq": 5}
    assert result["rewritten"] is None
    assert result["evidence"]["result"]["answer"] == "false"
    assert envelope["provenance"]["engine_function"] == "hst.simul.bestpath._run_policy"


def test_an_evaluated_clause_with_an_unsupported_term_is_not_established(monkeypatch):
    rm = _route_map(
        "RM-IN",
        {"seq": 10, "kind": "clause", "action": "deny", "match_community_lists": ["CL"]},
        {"seq": 20, "kind": "clause", "action": "permit", "match_prefix_lists": ["PL"]},
    )
    install(
        monkeypatch,
        FakeGraph([_DEVICE, _session(import_policy_name="RM-IN"), ("b.uid IN $sessions", [rm, _PL])]),
    )

    failed, envelope = _evaluate()

    assert not failed
    result = envelope["result"]
    assert result["decision"] == "accept"
    assert result["clauses"][0]["unsupported"] == ["community-list CL"]
    assert result["evidence"]["result"]["answer"] == "open"
    (gap,) = envelope["evidence"]["gaps"]
    assert (gap["code"], gap["kind"], gap["subject"]) == ("undefined-community-list", "unsupported", "CL")


def test_a_continue_is_followed_and_the_skipped_clause_is_not_evaluated(monkeypatch):
    rm = _route_map(
        "RM-IN",
        {
            "seq": 10,
            "kind": "clause",
            "action": "permit",
            "match_prefix_lists": ["PL"],
            "set_local_pref": 150,
            "continues": True,
            "continue_seq": 30,
        },
        {"seq": 20, "kind": "clause", "action": "deny", "match_prefix_lists": ["PL"]},
        {"seq": 30, "kind": "clause", "action": "deny", "match_prefix_lists": ["PL-DENY"]},
    )
    install(
        monkeypatch,
        FakeGraph(
            [_DEVICE, _session(import_policy_name="RM-IN"), ("b.uid IN $sessions", [rm, _PL, _PL_DENY])]
        ),
    )

    failed, envelope = _evaluate()

    assert not failed
    result = envelope["result"]
    assert result["decision"] == "accept" and result["rewritten"]["local_pref"] == 150
    assert [(c["seq"], c["matches"], c.get("continues_to")) for c in result["clauses"]] == [
        (10, True, 30),
        (30, False, None),
    ]
    # the continue's permit set the outcome when no later clause decided
    assert result["matched"]["clause_seq"] == 10
    assert result["evidence"]["result"]["answer"] == "true"


_PL_B = _prefix_list("PL-B", (5, "permit", "172.16.0.0/12", 12, 32))


def _nxos_continue(second_action, second_list):
    """10 continues to 30, which starts the second interval; 20 closes the first."""
    return _route_map(
        "RM-IN",
        {
            "seq": 10,
            "kind": "clause",
            "action": "permit",
            "match_prefix_lists": ["PL"],
            "set_local_pref": 150,
            "continues": True,
            "continue_seq": 30,
        },
        {"seq": 20, "kind": "clause", "action": second_action, "match_prefix_lists": [second_list]},
        {"seq": 30, "kind": "clause", "action": "deny", "match_prefix_lists": ["PL-DENY"]},
    )


@pytest.mark.parametrize(
    ("second", "prefix", "decision", "clauses", "matched"),
    [
        # no clause of the first interval holds: its local default, reject, decides and 30 is never evaluated
        (
            ("permit", "PL-B"),
            "192.168.1.0/24",
            "reject",
            [(10, False, None), (20, False, None)],
            None,
        ),
        # the called interval returns, and 20 decides in the calling interval
        (
            ("deny", "PL"),
            "10.1.0.0/16",
            "reject",
            [(10, True, 30), (30, False, None), (20, True, None)],
            {"clause_seq": 20, "action": "deny", "prefix_list": "PL", "entry_seq": 5},
        ),
        # the first interval runs out after the continue: 10's permit set its local default
        (
            ("permit", "PL-B"),
            "10.1.0.0/16",
            "accept",
            [(10, True, 30), (30, False, None), (20, False, None)],
            {"clause_seq": 10, "action": "permit", "prefix_list": "PL", "entry_seq": 5},
        ),
    ],
    ids=["first-interval-default", "calling-interval-resumes", "continue-sets-the-default"],
)
def test_an_nxos_continue_runs_the_route_map_in_intervals(
    monkeypatch, second, prefix, decision, clauses, matched
):
    rm = _nxos_continue(*second)
    install(
        monkeypatch,
        FakeGraph(
            [
                _DEVICE,
                _session(platform="nxos", import_policy_name="RM-IN"),
                ("b.uid IN $sessions", [rm, _PL, _PL_B, _PL_DENY]),
            ]
        ),
    )

    failed, envelope = _evaluate(route={"prefix": prefix})

    assert not failed, envelope
    result = envelope["result"]
    assert result["platform"] == "nxos"
    assert result["decision"] == decision
    assert [(c["seq"], c["matches"], c.get("continues_to")) for c in result["clauses"]] == clauses
    assert result["matched"] == matched
    assert result["evidence"]["result"]["answer"] in ("true", "false")
    assert envelope["evidence"]["unknowns"] == []


def test_an_rpl_statement_with_a_disposition_decides(monkeypatch):
    policy = _route_map(
        "RP-IN",
        {"seq": 1, "kind": "statement", "match_prefix_lists": ["PL"], "set_local_pref": 300},
        {"seq": 2, "kind": "statement", "match_prefix_lists": ["PL"], "action": "permit"},
        kind="rpl",
    )
    install(
        monkeypatch,
        FakeGraph(
            [
                _DEVICE,
                _session(platform="iosxr", import_policy_name="RP-IN", import_policy_kind="rpl"),
                ("b.uid IN $sessions", [policy, _PL]),
            ]
        ),
    )

    failed, envelope = _evaluate()

    assert not failed
    result = envelope["result"]
    assert result["decision"] == "accept" and result["rewritten"]["local_pref"] == 300
    assert result["matched"]["clause_seq"] == 2
    assert result["platform"] == "iosxr"


def test_a_session_with_no_policy_is_no_policy_and_possible(monkeypatch):
    graph = install(monkeypatch, FakeGraph([_DEVICE, _session()]))

    failed, envelope = _evaluate()

    assert not failed
    result = envelope["result"]
    assert result["decision"] == "no-policy"
    assert result["policy"]["attached"] is False and result["policy"]["name"] is None
    # IOS-XE imposes no filter on an eBGP session with no policy
    assert result["outcome"] == "accept"
    assert result["evidence"]["result"]["word"] == "platform default"
    assert result["evidence"]["result"]["answer"] == "default"
    assert NO_POLICY_UNKNOWN in envelope["evidence"]["unknowns"]
    assert graph.reads("b.uid IN $sessions") == []


def test_a_session_of_another_device_is_not_found(monkeypatch):
    session = _session()
    session[1][0]["device_uid"] = "dev:r9"
    install(monkeypatch, FakeGraph([_DEVICE, session]))

    failed, error = _evaluate()

    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == "session_uid"


@pytest.mark.parametrize(
    "overrides",
    [{"policy_name": "RM-IN"}, {"session_uid": None}],
    ids=["both", "neither"],
)
def test_exactly_one_of_session_and_policy_name_is_required(monkeypatch, overrides):
    graph = install(monkeypatch, FakeGraph())

    failed, error = _evaluate(**overrides)

    assert (
        failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "session_uid"
    )
    assert graph.session_kwargs == []


def test_an_as_path_that_is_not_as_numbers_is_refused(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, error = _evaluate(route={"prefix": "10.1.0.0/16", "as_path": "{65001 65002}"})

    assert failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "route"


# --- collected community lists and RPL if/else attribution ----------


def test_a_collected_community_list_decides_its_clause(monkeypatch):
    """The community list is in the snapshot, so the clause is evaluated
    against it and nothing is open."""
    rm = _route_map(
        "RM-IN",
        {"seq": 10, "kind": "clause", "action": "deny", "match_community_lists": ["CL"]},
        {"seq": 20, "kind": "clause", "action": "permit", "match_prefix_lists": ["PL"]},
    )
    cl = {
        "uid": "rtpol:dev:r1:community-list:CL",
        "name": "CL",
        "kind": "community-list",
        "entries": [{"seq": 1, "action": "permit", "match_type": "standard", "value": "65000:666"}],
    }
    install(
        monkeypatch,
        FakeGraph([_DEVICE, _session(import_policy_name="RM-IN"), ("b.uid IN $sessions", [rm, _PL, cl])]),
    )

    failed, envelope = _evaluate(route={"prefix": "10.1.0.0/16", "communities": ["65000:666"]})

    assert not failed, envelope
    result = envelope["result"]
    assert result["decision"] == "reject"
    assert result["clauses"][0] == {"seq": 10, "action": "deny", "matches": True, "unsupported": []}
    assert result["matched"]["clause_seq"] == 10
    assert envelope["evidence"]["gaps"] == []


def test_an_rpl_else_branch_is_attributed_only_when_the_guard_fails(monkeypatch):
    """`if not destination in BOGONS then pass else drop endif`: a route
    outside BOGONS is accepted, and the walk never enters the `else`."""
    rp = _route_map(
        "EDGE-IN",
        {
            "seq": 1,
            "kind": "statement",
            "passes": True,
            "match_expr": '{"not":{"prefix_list":"BOGONS"}}',
            "match_prefix_lists": ["BOGONS"],
            "continues": True,
            "continue_seq": 2,
        },
        {"seq": 2, "kind": "statement", "action": "deny"},
        kind="rpl",
    )
    bogons = _prefix_list("BOGONS", (5, "permit", "10.0.0.0/8", 8, 32))
    install(
        monkeypatch,
        FakeGraph(
            [
                _DEVICE,
                _session(platform="iosxr", import_policy_name="EDGE-IN"),
                ("b.uid IN $sessions", [rp, bogons]),
            ]
        ),
    )

    failed, envelope = _evaluate(route={"prefix": "8.8.8.0/24"})

    assert not failed, envelope
    result = envelope["result"]
    assert result["decision"] == "accept"
    assert [(c["seq"], c["matches"]) for c in result["clauses"]] == [(1, True)]
