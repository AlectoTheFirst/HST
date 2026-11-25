"""RibSource: longest-prefix match / overlap over the RIB side store."""

import pytest

pytest.importorskip("pyarrow")

from hst.app.crypto import generate_key
from hst.core import Settings, ipenc, manifest, sidestore, uid
from hst.core.model import TableOutcome
from hst.core.ribsource import RibSource, for_snapshot
from hst.core.snapshot import Snapshot


def _snap(settings, cts):
    """The resolved Snapshot a caller hands `for_snapshot` (core/snapshot.py)."""
    return Snapshot(cts, settings)


def _row(prefix: str, next_hop: str, interface: str, protocol: str = "static", metric: int = 1) -> dict:
    lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
    return {
        "device_uid": "dev:r1",
        "vrf": "default",
        "prefix": prefix,
        "next_hop": next_hop,
        "interface": interface,
        "protocol": protocol,
        "metric": metric,
        "af": af,
        "prefixlen": prefixlen,
        "lo": lo,
        "hi": hi,
    }


# No row below holds the `context_uid` column.


@pytest.fixture
def store(tmp_path):
    pytest.importorskip("duckdb")
    # Older run: default route only, via a next hop that must never surface.
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000000-aaaaaaaa",
        [_row("0.0.0.0/0", "10.0.0.1", "eth0", "static")],
        1000,
    )
    # Newer run: default route (different next hop), a /8, and an ECMP /24 pair.
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000001000-bbbbbbbb",
        [
            _row("0.0.0.0/0", "0.0.0.0", "pppoe0", "static"),  # noqa: S104 - a default route, not a bind
            _row("8.0.0.0/8", "10.9.0.1", "eth2", "bgp"),
            _row("8.8.8.0/24", "10.9.0.2", "eth3", "bgp"),
            _row("8.8.8.0/24", "10.9.0.3", "eth4", "bgp"),
            # the v6 default: in the v4-mapped byte encoding its [lo, hi]
            # covers every v4 address, so only the af filter keeps it out of
            # the v4 answers below
            _row("::/0", "fe80::1", "pppoe0", "ra"),
            _row("2001:db8::/32", "fe80::2", "eth5", "bgp"),
        ],
        2000,
    )
    return tmp_path


def test_lpm_returns_ecmp_set_at_longest_prefix(store):
    rs = RibSource(store)
    out = rs.lpm("dev:r1", None, "8.8.8.8", legacy_vrf="default")
    assert len(out) == 2
    assert {r["next_hop"] for r in out} == {"10.9.0.2", "10.9.0.3"}
    assert all(r["prefixlen"] == 24 for r in out)
    assert all(r["prefix"] == "8.8.8.0/24" for r in out)


def test_lpm_falls_back_to_default_route_from_latest_run(store):
    rs = RibSource(store)
    out = rs.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert len(out) == 1
    assert out[0]["next_hop"] == "0.0.0.0"  # noqa: S104 - a default route, not a bind
    assert out[0]["interface"] == "pppoe0"
    assert out[0]["prefixlen"] == 0


def test_lpm_answers_a_v6_probe_from_v6_routes_only(store):
    rs = RibSource(store)
    out = rs.lpm("dev:r1", None, "2001:db8::1", legacy_vrf="default")
    assert [r["prefix"] for r in out] == ["2001:db8::/32"]
    # a v6 probe outside every v6 route falls to the v6 default, never to
    # 0.0.0.0/0: families do not mix in either direction
    out = rs.lpm("dev:r1", None, "2606:4700::1", legacy_vrf="default")
    assert [r["prefix"] for r in out] == ["::/0"]


def test_lpm_unknown_device_returns_empty(store):
    rs = RibSource(store)
    assert rs.lpm("dev:unknown", None, "8.8.8.8", legacy_vrf="default") == []


@pytest.mark.parametrize("probe", ["8.8.8.8", "8.1.1.1", "1.2.3.4", "2001:db8::1", "2606:4700::1"])
def test_covering_lengths_answers_every_table_with_the_lpm_length(store, probe):
    """One statement answers what `lpm` per table answers, the latest
    run only and the probe's family only, so a trace from a VRF name every
    device holds does not ask the store once per device."""
    rs = RibSource(store)
    expected = {r["prefixlen"] for r in rs.lpm("dev:r1", "vrf:r1:default", probe, legacy_vrf="default")}
    tables = [("dev:r1", "vrf:r1:default", "default"), ("dev:unknown", "vrf:x:default", "default")]
    assert rs.covering_lengths(tables, probe) == {"vrf:r1:default": max(expected)}


def test_covering_lengths_reads_a_row_without_context_uid_only_through_its_vrf_name(store):
    rs = RibSource(store)
    assert rs.covering_lengths([("dev:r1", "vrf:r1:default", None)], "8.8.8.8") == {}
    assert rs.covering_lengths([("dev:r1", "vrf:r1:other", "other")], "8.8.8.8") == {}


# --- routes(): the whole table, for the change-simulation withdrawal -----


def test_routes_returns_every_row_with_a_next_hop_for_the_latest_run(store):
    sidestore.write_table(
        store,
        "rib",
        "other",  # a distinct source directory with the run_id of the "nxos" write above
        "",
        "1700000001000-bbbbbbbb",
        [{**_row("10.9.0.0/24", "0.0.0.0", "eth9", "connected"), "next_hop": None}],  # noqa: S104
        2000,
    )
    rs = RibSource(store)
    out = rs.routes("dev:r1", None, legacy_vrf="default")
    assert "10.9.0.0/24" not in {r["prefix"] for r in out}
    assert all(r["next_hop"] for r in out)
    # only the latest run's default route is present, not the older run's
    assert {r["next_hop"] for r in out if r["prefix"] == "0.0.0.0/0"} == {"0.0.0.0"}  # noqa: S104


def test_routes_rows_with_and_without_context_uid_stay_isolated(tmp_path):
    """Mirrors test_lpm_context_and_legacy_rows_stay_isolated: routes() follows
    the same context_uid/legacy_vrf matching rule as lpm/overlapping."""
    pytest.importorskip("duckdb")
    default_ctx = uid.vrf("dev:ctx1", "default")
    corp_ctx = uid.vrf("dev:ctx1", "CORP")
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000002000-dddddddd",
        [
            {
                **_row("8.8.8.0/24", "10.1.1.1", "eth0", "static"),
                "device_uid": "dev:ctx1",
                "context_uid": default_ctx,
            },
            {
                **_row("9.9.9.0/24", "10.2.2.2", "eth1", "static"),
                "device_uid": "dev:ctx1",
                "vrf": "CORP",
                "context_uid": corp_ctx,
            },
        ],
        2000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000500-eeeeeeee",
        [{**_row("0.0.0.0/0", "10.9.9.9", "pppoe0", "static"), "device_uid": "dev:legacy1"}],
        1000,
    )
    rs = RibSource(tmp_path)

    # a context_uid match is found directly, isolated from the sibling context
    # sharing the same run.
    assert [r["next_hop"] for r in rs.routes("dev:ctx1", default_ctx)] == ["10.1.1.1"]
    assert [r["next_hop"] for r in rs.routes("dev:ctx1", corp_ctx)] == ["10.2.2.2"]

    # a legacy_vrf naming another context's vrf column never leaks that
    # context's row in: it already carries its own context_uid.
    assert [r["next_hop"] for r in rs.routes("dev:ctx1", default_ctx, legacy_vrf="CORP")] == ["10.1.1.1"]

    # a device with no context_uid at all is found only through legacy_vrf.
    assert rs.routes("dev:legacy1", "vrf:not-real") == []
    out = rs.routes("dev:legacy1", "vrf:not-real", legacy_vrf="default")
    assert [r["next_hop"] for r in out] == ["10.9.9.9"]


def test_routes_unknown_device_returns_empty(store):
    rs = RibSource(store)
    assert rs.routes("dev:unknown", None, legacy_vrf="default") == []


def test_lpm_and_routes_return_discard_and_next_hop_context_uid_columns(tmp_path):
    """`discard` and `next_hop_context_uid` are projected columns like
    any other."""
    pytest.importorskip("duckdb")
    red_ctx = uid.vrf("dev:r2", "RED")
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000003000-ffffffff",
        [
            {
                **_row("172.16.0.0/12", None, None, "static"),
                "device_uid": "dev:r2",
                "discard": "blackhole",
            },
            {
                **_row("10.60.0.0/24", "10.0.0.9", "eth10", "bgp"),
                "device_uid": "dev:r2",
                "next_hop_context_uid": red_ctx,
            },
        ],
        3000,
    )
    rs = RibSource(tmp_path)

    blackhole = rs.lpm("dev:r2", None, "172.16.5.5", legacy_vrf="default")
    assert [r["discard"] for r in blackhole] == ["blackhole"]
    assert blackhole[0]["next_hop_context_uid"] is None

    leaked = rs.lpm("dev:r2", None, "10.60.0.5", legacy_vrf="default")
    assert [r["next_hop_context_uid"] for r in leaked] == [red_ctx]
    assert leaked[0]["discard"] is None

    out = {r["prefix"]: r for r in rs.routes("dev:r2", None, legacy_vrf="default")}
    # the blackhole row has no next hop, so routes() (which filters on
    # next_hop IS NOT NULL) never returns it.
    assert "172.16.0.0/12" not in out
    assert out["10.60.0.0/24"]["next_hop_context_uid"] == red_ctx
    assert out["10.60.0.0/24"]["discard"] is None


def test_for_snapshot_binds_sidestore_dir_and_as_of_ms(tmp_path):
    """for_snapshot is the shared constructor every trace caller binds to: the
    side store at settings.sidestore_dir, bounded to the given run."""
    pytest.importorskip("duckdb")
    unbounded_dir, bounded_dir = tmp_path / "a", tmp_path / "b"
    for base in (unbounded_dir, bounded_dir):
        sidestore.write_table(
            base,
            "rib",
            "nxos",
            "",
            "1700000000000-aaaaaaaa",
            [_row("0.0.0.0/0", "10.0.0.1", "eth0", "static")],
            1000,
        )
        sidestore.write_table(
            base,
            "rib",
            "nxos",
            "",
            "1700000001000-bbbbbbbb",
            [_row("0.0.0.0/0", "10.0.0.2", "eth0", "static")],
            2000,
        )

    class _UnboundedSettings:
        sidestore_dir = unbounded_dir

    class _BoundedSettings:
        sidestore_dir = bounded_dir

    unbounded = for_snapshot(_snap(_UnboundedSettings(), None))
    out = unbounded.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert [r["next_hop"] for r in out] == ["10.0.0.2"]

    bounded = for_snapshot(_snap(_BoundedSettings(), 1000))
    out = bounded.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert [r["next_hop"] for r in out] == ["10.0.0.1"]


def test_ribsource_on_nonexistent_dir_returns_empty(tmp_path):
    rs = RibSource(tmp_path / "does-not-exist")
    assert rs.lpm("dev:r1", None, "8.8.8.8", legacy_vrf="default") == []
    assert rs.overlapping("dev:r1", None, b"\x00" * 16, b"\xff" * 16, 0, 4, legacy_vrf="default") == []


def test_overlapping_returns_more_specific_intersecting_routes(store):
    rs = RibSource(store)
    lo, hi, prefixlen, af = ipenc.prefix_bounds("8.0.0.0/8")
    out = rs.overlapping("dev:r1", None, lo, hi, prefixlen, af, legacy_vrf="default")
    assert len(out) == 2
    assert {r["next_hop"] for r in out} == {"10.9.0.2", "10.9.0.3"}
    assert all(r["prefix"] == "8.8.8.0/24" for r in out)


def test_lpm_v4_ignores_the_v6_default_and_vice_versa(store):
    """0.0.0.0/0 and ::/0 tie at prefixlen 0 in a familyless comparison."""
    rs = RibSource(store)
    out = rs.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert [r["prefix"] for r in out] == ["0.0.0.0/0"]
    assert out[0]["interface"] == "pppoe0" and out[0]["next_hop"] == "0.0.0.0"  # noqa: S104


def test_run_id_pick_is_cached_per_device_for_the_life_of_the_instance(tmp_path):
    pytest.importorskip("duckdb")
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000000-aaaaaaaa",
        [_row("0.0.0.0/0", "10.0.0.1", "eth0", "static")],
        1000,
    )
    rs = RibSource(tmp_path)
    out = rs.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert out[0]["next_hop"] == "10.0.0.1"

    # a newer run lands after the first lookup
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000001000-bbbbbbbb",
        [_row("0.0.0.0/0", "10.9.9.9", "pppoe0", "static")],
        2000,
    )
    out = rs.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert out[0]["next_hop"] == "10.0.0.1"  # unchanged: the cached pick, not a rescan


def test_run_id_cache_is_keyed_per_device(tmp_path):
    """A cached pick for one device must never answer for another."""
    pytest.importorskip("duckdb")
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000000-aaaaaaaa",
        [
            {**_row("0.0.0.0/0", "10.0.0.1", "eth0", "static"), "device_uid": "dev:r1"},
            {**_row("0.0.0.0/0", "10.0.0.2", "eth1", "static"), "device_uid": "dev:r2"},
        ],
        1000,
    )
    rs = RibSource(tmp_path)
    assert rs.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")[0]["next_hop"] == "10.0.0.1"
    assert rs.lpm("dev:r2", None, "1.2.3.4", legacy_vrf="default")[0]["next_hop"] == "10.0.0.2"


def test_latest_run_survives_source_name_ordering(tmp_path):
    """Selection is by the `snapshot_ts` column alone."""
    pytest.importorskip("duckdb")
    # older run, under the lexically-larger source directory name
    sidestore.write_table(
        tmp_path,
        "rib",
        "vyos-new",
        "",
        "1699999999999-aaaaaaaa",
        [_row("0.0.0.0/0", "10.0.0.1", "eth0", "static")],
        1000,
    )
    # newer run, under the lexically-smaller source directory name
    sidestore.write_table(
        tmp_path,
        "rib",
        "vyos",
        "",
        "1700000000000-bbbbbbbb",
        [_row("0.0.0.0/0", "10.9.9.9", "pppoe0", "static")],
        2000,
    )
    rs = RibSource(tmp_path)
    out = rs.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert len(out) == 1
    assert out[0]["next_hop"] == "10.9.9.9"  # the newer run by snapshot_ts wins


def test_two_writes_same_snapshot_ts_the_one_fetched_second_wins(tmp_path):
    """A refresh or a per-device job can mint more than one run_id under one
    unchanged collection_ts (`snapshot_ts` here)."""
    pytest.importorskip("duckdb")
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000000-ffffffff",  # fetched first
        [_row("0.0.0.0/0", "10.0.0.1", "eth0", "static")],
        1000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000001-aaaaaaaa",  # fetched second, despite "a" sorting below "f"
        [_row("0.0.0.0/0", "10.9.9.9", "pppoe0", "static")],
        1000,
    )
    rs = RibSource(tmp_path)
    out = rs.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert len(out) == 1
    assert out[0]["next_hop"] == "10.9.9.9"  # the run fetched second, by its own embedded timestamp


def test_as_of_ms_bound_excludes_a_later_run(tmp_path):
    """The fetch-order tie-break must never override the as_of_ms snapshot bound."""
    pytest.importorskip("duckdb")
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000000-aaaaaaaa",
        [_row("0.0.0.0/0", "10.0.0.1", "eth0", "static")],
        1000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000001000-bbbbbbbb",
        [_row("0.0.0.0/0", "10.9.9.9", "pppoe0", "static")],
        2000,
    )
    rs = RibSource(tmp_path, as_of_ms=1500)
    out = rs.lpm("dev:r1", None, "1.2.3.4", legacy_vrf="default")
    assert len(out) == 1
    assert out[0]["next_hop"] == "10.0.0.1"  # the later run's snapshot_ts (2000) is past the bound


# --- isolation of context_uid rows and vrf-name-only rows -------------------------------


def test_lpm_context_and_legacy_rows_stay_isolated(tmp_path):
    """Rows with a `context_uid` and rows with a `vrf` name only never
    cross-contaminate."""
    pytest.importorskip("duckdb")
    default_ctx = uid.vrf("dev:ctx1", "default")
    corp_ctx = uid.vrf("dev:ctx1", "CORP")
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000002000-dddddddd",
        [
            {
                **_row("8.8.8.0/24", "10.1.1.1", "eth0", "static"),
                "device_uid": "dev:ctx1",
                "context_uid": default_ctx,
            },
            {
                **_row("9.9.9.0/24", "10.2.2.2", "eth1", "static"),
                "device_uid": "dev:ctx1",
                "vrf": "CORP",
                "context_uid": corp_ctx,
            },
        ],
        2000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000500-eeeeeeee",
        [{**_row("0.0.0.0/0", "10.9.9.9", "pppoe0", "static"), "device_uid": "dev:legacy1"}],
        1000,
    )
    rs = RibSource(tmp_path)

    # 1. a context_uid match is found directly, with no legacy_vrf needed.
    out = rs.lpm("dev:ctx1", default_ctx, "8.8.8.8")
    assert [r["next_hop"] for r in out] == ["10.1.1.1"]

    # 2. two contexts sharing one run stay isolated by context_uid alone.
    out = rs.lpm("dev:ctx1", corp_ctx, "9.9.9.9")
    assert [r["next_hop"] for r in out] == ["10.2.2.2"]

    # 3. a context_uid query with no legacy_vrf never falls back to vrf-name-only
    # or sibling-context rows.
    assert rs.lpm("dev:ctx1", default_ctx, "9.9.9.9") == []

    # 4. legacy_vrf pulling in a name that coincides with another context's
    # vrf column does not match that context's row.
    assert rs.lpm("dev:ctx1", default_ctx, "9.9.9.9", legacy_vrf="CORP") == []

    # 5. a device with no context_uid is found only through legacy_vrf.
    assert rs.lpm("dev:legacy1", "vrf:not-real", "1.2.3.4") == []
    out = rs.lpm("dev:legacy1", "vrf:not-real", "1.2.3.4", legacy_vrf="default")
    assert [r["next_hop"] for r in out] == ["10.9.9.9"]

    # overlapping() applies the same predicate.
    lo, hi, prefixlen, af = ipenc.prefix_bounds("9.0.0.0/8")
    out = rs.overlapping("dev:ctx1", corp_ctx, lo, hi, prefixlen, af)
    assert [r["next_hop"] for r in out] == ["10.2.2.2"]
    out = rs.overlapping("dev:ctx1", default_ctx, lo, hi, prefixlen, af)
    assert out == []


# --- manifest-driven evidence -----------------------------------------------------------
#
# Bound to a published snapshot, the reader opens exactly the files that
# snapshot's manifest publishes, device by device, and answers no rows for a
# device whose run recorded no rows, never an older run's file. Each test
# builds the manifests by hand in the shape app/runs_exec.py publishes them.

RUN_A = "1700000000000-aaaaaaaa"
RUN_B = "1700000001000-bbbbbbbb"


def _settings(tmp_path):
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _rib_file(settings, run_id, rows, snapshot_ts, source="edge", host="r1"):
    path = sidestore.write_table(settings.sidestore_dir, "rib", source, host, run_id, rows, snapshot_ts)
    assert path is not None
    return manifest.file_entry(settings, path)


def _raw_entry(run_id, source="edge", host="r1"):
    """A raw file entry by description only: the reader joins a carried device
    to the manifest holding its run by run id and never opens the raw file."""
    return manifest.FileEntry(
        kind="raw",
        path=f"raw/{source}/{host}/{run_id}.json.gz.enc",
        sha256="0" * 64,
        bytes=0,
        source=source,
        host=host,
        run_id=run_id,
    )


def _device(run_id, status=None, *, outcome="collected", carried=False, path="", source="edge", host="r1"):
    tables = {} if status is None else {"rib": TableOutcome(status=status, path=path)}
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


def _publish_a(settings, rows=None):
    """Snapshot 1000: run A collected r1 and published its RIB file."""
    file_a = _rib_file(settings, RUN_A, rows or [_row("0.0.0.0/0", "10.0.0.1", "eth0")], 1000)
    devices = [_device(RUN_A, "complete", path=file_a.path)]
    _publish(settings, 1000, None, devices, [_raw_entry(RUN_A), file_a])
    return file_a


def _next_hops(rs, device="dev:r1", context_uid=None, legacy_vrf="default"):
    return [r["next_hop"] for r in rs.lpm(device, context_uid, "1.2.3.4", legacy_vrf=legacy_vrf)]


def _read(settings, cts, device="dev:r1"):
    """What one reader bound to `cts` says for the device, read and released
    in one call: two connections open at once on one store's catalog conflict
    on its locked configuration (see
    test_for_snapshot_binds_sidestore_dir_and_as_of_ms), so no test below
    holds two readers at a time."""
    rs = for_snapshot(_snap(settings, cts))
    return {
        "approximate": rs.approximate,
        "available": rs.available,
        "next_hops": _next_hops(rs, device),
        "has_rows": rs.has_rows(device),
        "coverage": rs.coverage(device),
    }


def _by_age(settings, cts):
    """The same lookup read by age alone, the way a pin with no manifest reads."""
    return _next_hops(RibSource(settings.sidestore_dir, as_of_ms=cts))


def test_a_complete_empty_run_answers_no_rows_and_never_falls_back(tmp_path):
    """Run A wrote the device's routes, and run B found the table empty."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    _publish(settings, 2000, 1000, [_device(RUN_B, "complete-empty")], [_raw_entry(RUN_B)])

    assert _read(settings, 1000) == {
        "approximate": False,
        "available": True,
        "next_hops": ["10.0.0.1"],
        "has_rows": True,
        "coverage": "complete",
    }
    assert _read(settings, 2000) == {
        "approximate": False,
        "available": True,  # the store answered: this snapshot publishes no RIB file
        "next_hops": [],
        "has_rows": False,
        "coverage": "complete-empty",
    }
    assert _by_age(settings, 2000) == ["10.0.0.1"]


@pytest.mark.parametrize("status", ["failed", "partial"])
def test_a_failed_or_partial_table_answers_no_rows_and_reports_the_gap(tmp_path, status):
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    files_b = [_raw_entry(RUN_B)]
    path_b = ""
    if status == "partial":
        file_b = _rib_file(settings, RUN_B, [_row("0.0.0.0/0", "10.9.9.9", "eth9")], 2000)
        files_b.append(file_b)
        path_b = file_b.path
    _publish(settings, 2000, 1000, [_device(RUN_B, status, outcome="partial", path=path_b)], files_b)

    at_b = _read(settings, 2000)
    expected = ["10.9.9.9"] if status == "partial" else []
    assert (at_b["next_hops"], at_b["coverage"]) == (expected, status)


def test_a_file_no_manifest_publishes_is_ignored(tmp_path):
    """A parquet file from a run that never published sits between A and C by `snapshot_ts`."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    sidestore.write_table(
        settings.sidestore_dir, "rib", "edge", "r1", RUN_B, [_row("0.0.0.0/0", "10.9.9.9", "eth9")], 2000
    )
    # C carries the device with no outcome and no file of its own
    _publish(settings, 3000, 1000, [_device(RUN_A, outcome="carried", carried=True)], [])

    at_c = _read(settings, 3000)
    assert (at_c["next_hops"], at_c["coverage"]) == (["10.0.0.1"], "complete")
    assert _by_age(settings, 3000) == ["10.9.9.9"]


def test_an_unchanged_device_stands_on_the_run_that_collected_it(tmp_path):
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    file_a = _rib_file(settings, RUN_A, [_row("0.0.0.0/0", "10.0.0.1", "eth0")], 1000)
    empty = "1700000000000-eeeeeeee"
    _publish(
        settings,
        1000,
        None,
        [
            _device(RUN_A, "complete", path=file_a.path),
            _device(empty, "complete-empty", host="r2"),
        ],
        [_raw_entry(RUN_A), file_a, _raw_entry(empty, host="r2")],
    )
    _publish(
        settings,
        2000,
        1000,
        [
            _device(RUN_A, "unchanged", outcome="unchanged", carried=True),
            _device(empty, "unchanged", outcome="unchanged", carried=True, host="r2"),
        ],
        [],
    )

    at_b = for_snapshot(_snap(settings, 2000))
    assert _next_hops(at_b) == ["10.0.0.1"]
    assert at_b.coverage("dev:r1") == "complete"
    # r2 stands on a run that found its table empty
    assert _next_hops(at_b, "dev:r2") == []
    assert at_b.coverage("dev:r2") is None


def test_a_run_with_rows_only_in_another_vrf_answers_that_vrf_only(tmp_path):
    """Rows in one context never answer for another."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings, [{**_row("0.0.0.0/0", "10.0.0.1", "eth0"), "vrf": "b", "context_uid": "vrf:b"}])

    rs = for_snapshot(_snap(settings, 1000))
    assert _next_hops(rs, context_uid="vrf:a", legacy_vrf=None) == []
    assert _next_hops(rs, context_uid="vrf:b", legacy_vrf=None) == ["10.0.0.1"]
    assert rs.coverage("dev:r1") == "complete"  # the device answered; vrf:a holds no route


def test_a_pin_without_a_manifest_is_approximate(tmp_path):
    """A run that predates manifests, a fixture store, or no pin at all: the
    reader keeps selecting by age and says so, and records no outcome."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    sidestore.write_table(
        settings.sidestore_dir, "rib", "edge", "r1", RUN_A, [_row("0.0.0.0/0", "10.0.0.1", "eth0")], 1000
    )

    assert _read(settings, 1000) == {
        "approximate": True,
        "available": True,
        "next_hops": ["10.0.0.1"],
        "has_rows": True,
        "coverage": None,
    }
    assert for_snapshot(_snap(settings, None)).approximate is True


def test_a_published_file_that_is_gone_from_disk_reads_as_missing(tmp_path):
    """Retention can remove a file a still-readable manifest names."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _publish_a(settings)
    file_b = _rib_file(settings, RUN_B, [_row("0.0.0.0/0", "10.9.9.9", "eth9")], 2000)
    devices = [_device(RUN_B, "complete", path=file_b.path)]
    _publish(settings, 2000, 1000, devices, [_raw_entry(RUN_B), file_b])
    (settings.hst_data_dir / file_b.path).unlink()

    at_b = _read(settings, 2000)
    assert (at_b["next_hops"], at_b["coverage"]) == ([], "missing")


def test_route_page_lists_the_selected_run_in_address_order_with_protocol_counts(store):
    src = RibSource(store)
    page = src.route_page("dev:r1", "ctx:none", legacy_vrf="default", limit=3)
    assert page.run_id == "1700000001000-bbbbbbbb" and page.total == 6
    assert [r["prefix"] for r in page.rows] == ["0.0.0.0/0", "8.0.0.0/8", "8.8.8.0/24"]
    assert page.protocols == [
        {"protocol": "bgp", "count": 4},
        {"protocol": "ra", "count": 1},
        {"protocol": "static", "count": 1},
    ]
    rest = src.route_page("dev:r1", "ctx:none", legacy_vrf="default", offset=3, limit=3)
    assert [r["prefix"] for r in rest.rows] == ["8.8.8.0/24", "::/0", "2001:db8::/32"]


def test_route_page_address_lists_covering_routes_longest_first(store):
    src = RibSource(store)
    page = src.route_page("dev:r1", address="8.8.8.8")
    assert [r["prefix"] for r in page.rows] == ["8.8.8.0/24", "8.8.8.0/24", "8.0.0.0/8", "0.0.0.0/0"]
    assert all(r["af"] == 4 for r in page.rows), "the v6 default covers no v4 address here"


def test_route_page_filters_by_prefix_text_and_protocol(store):
    src = RibSource(store)
    page = src.route_page("dev:r1", prefix_text="8.8", protocol="bgp")
    assert page.total == 2 and {r["next_hop"] for r in page.rows} == {"10.9.0.2", "10.9.0.3"}
    assert page.protocols == [{"protocol": "bgp", "count": 2}], "the counts ignore the protocol filter only"
    assert src.route_page("dev:r1", prefix_text="%").total == 0, "a LIKE wildcard is matched as text"


def test_route_page_unknown_device_is_an_empty_page(store):
    page = RibSource(store).route_page("dev:nope")
    assert page.total == 0 and page.rows == [] and page.run_id is None


# --- route_page: a total order, and the run the reader is bound to ----------------------


def _all_pages(src, *, limit, **kwargs):
    rows, offset = [], 0
    while True:
        page = src.route_page("dev:r1", offset=offset, limit=limit, **kwargs)
        if not page.rows:
            return page.total, rows
        rows += page.rows
        offset += limit


def _key(row):
    return (row["context_uid"], row["prefix"], row["next_hop"])


def test_route_page_pages_hold_every_tied_row_once(tmp_path, request):
    """The Device view lists every context. Rows of two contexts with the same
    prefix and next hop tie on the address order, and so do rows without a
    next hop. Read page by page, every row is on exactly one page."""
    pytest.importorskip("duckdb")
    contexts = [{"vrf": f"v{i}", "context_uid": f"ctx:v{i}"} for i in range(4)]
    rows = [{**_row(f"10.0.{j}.0/24", "169.254.0.1", "eth0"), **ctx} for ctx in contexts for j in range(100)]
    rows += [{**_row("192.0.2.0/24", None, "null0"), **ctx} for ctx in contexts]
    sidestore.write_table(tmp_path, "rib", "nxos", "", "1700000001000-bbbbbbbb", rows, 2000)
    src = RibSource(tmp_path)
    request.addfinalizer(src.close)

    for kwargs in ({}, {"address": "10.0.3.7"}):
        total, seen = _all_pages(src, limit=50, **kwargs)
        assert len(seen) == total, kwargs
        assert len({_key(r) for r in seen}) == total, f"a row is on two pages and another on none: {kwargs}"
    assert total == 4, "the address keeps the /24 that covers it in each context"
    whole = [_key(r) for r in src.route_page("dev:r1", limit=404).rows]
    assert whole == [_key(r) for r in _all_pages(src, limit=7)[1]], "small pages follow the one order"


def _two_runs(base):
    sidestore.write_table(base, "rib", "nxos", "", RUN_A, [_row("0.0.0.0/0", "10.0.0.1", "eth0")], 1000)
    sidestore.write_table(
        base,
        "rib",
        "nxos",
        "",
        RUN_B,
        [_row("0.0.0.0/0", "10.9.9.9", "eth9"), _row("10.0.0.0/8", "10.9.9.9", "eth9")],
        2000,
    )


def _page(src):
    """The run, the total and the next hops of the first page, read and released."""
    try:
        page = src.route_page("dev:r1")
    finally:
        src.close()
    return page.run_id, page.total, [r["next_hop"] for r in page.rows]


def test_route_page_reads_the_run_at_or_before_as_of_ms(tmp_path):
    """A reader bound to a time between two runs pages the older run."""
    pytest.importorskip("duckdb")
    _two_runs(tmp_path)

    assert _page(RibSource(tmp_path, as_of_ms=1500)) == (RUN_A, 1, ["10.0.0.1"])
    assert _page(RibSource(tmp_path)) == (RUN_B, 2, ["10.9.9.9", "10.9.9.9"])


def test_route_page_reads_the_file_the_snapshot_evidence_publishes(tmp_path):
    """Bound to the evidence of the older snapshot, the reader pages the file
    that snapshot published, although a newer file is on disk."""
    pytest.importorskip("duckdb")
    from hst.core.ribsource import snapshot_evidence

    settings = _settings(tmp_path)
    _publish_a(settings)
    file_b = _rib_file(
        settings, RUN_B, [_row("0.0.0.0/0", "10.9.9.9", "eth9"), _row("10.0.0.0/8", "10.9.9.9", "eth9")], 2000
    )
    devices = [_device(RUN_B, "complete", path=file_b.path)]
    _publish(settings, 2000, 1000, devices, [_raw_entry(RUN_B), file_b])

    older = RibSource(settings.sidestore_dir, evidence=snapshot_evidence(settings, 1000))
    assert _page(older) == (RUN_A, 1, ["10.0.0.1"])
    newer = RibSource(settings.sidestore_dir, evidence=snapshot_evidence(settings, 2000))
    assert _page(newer) == (RUN_B, 2, ["10.9.9.9", "10.9.9.9"])


def _two_units(settings, *, record_uids):
    """Snapshot 1000: two units, edge/r1 holding dev:r1 and edge/r2 holding dev:r2, each with its file."""
    rows_1 = [{**_row("0.0.0.0/0", "10.0.0.1", "eth0"), "device_uid": "dev:r1"}]
    rows_2 = [{**_row("0.0.0.0/0", "10.0.0.2", "eth0"), "device_uid": "dev:r2"}]
    run_2 = "1700000000500-cccccccc"
    file_1 = _rib_file(settings, RUN_A, rows_1, 1000, host="r1")
    file_2 = _rib_file(settings, run_2, rows_2, 1000, host="r2")
    devices = [
        manifest.DeviceEntry(
            source="edge",
            host=host,
            outcome="collected",
            effective_run=run,
            carried=False,
            tables={"rib": TableOutcome(status="complete", path=f.path)},
            device_uids=[uid] if record_uids else [],
        )
        for host, run, f, uid in (("r1", RUN_A, file_1, "dev:r1"), ("r2", run_2, file_2, "dev:r2"))
    ]
    _publish(settings, 1000, None, devices, [_raw_entry(RUN_A, host="r1"), file_1, file_2])
    return file_1, file_2


def test_a_lookup_opens_only_the_files_that_can_hold_the_device(tmp_path):
    """One lookup per hop must not read the footer of every RIB file of the snapshot."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    file_1, file_2 = _two_units(settings, record_uids=True)
    rs = for_snapshot(_snap(settings, 1000))
    try:
        assert _next_hops(rs, "dev:r1") == ["10.0.0.1"]
        assert _next_hops(rs, "dev:r2") == ["10.0.0.2"]
        assert _next_hops(rs, "dev:nobody") == []
        one = rs._from(["dev:r1"])
        assert str(settings.hst_data_dir / file_1.path) in one or file_1.path in one
        assert file_2.path not in one
        assert "false" in rs._from(["dev:nobody"])
        assert rs._from(["dev:r1", "dev:r2"]) == "rib"
        assert [r["next_hop"] for r in rs.routes("dev:r2", None, legacy_vrf="default")] == ["10.0.0.2"]
        assert rs.route_page("dev:r1").total == 1
    finally:
        rs.close()


def test_a_manifest_that_records_no_device_uids_is_read_through_every_file(tmp_path):
    """A unit that records none may hold any device, so it is never left out of a device's files."""
    pytest.importorskip("duckdb")
    settings = _settings(tmp_path)
    _two_units(settings, record_uids=False)
    rs = for_snapshot(_snap(settings, 1000))
    try:
        assert rs._from(["dev:r1"]) == "rib"
        assert _next_hops(rs, "dev:r2") == ["10.0.0.2"]
    finally:
        rs.close()


def test_the_readers_of_one_snapshot_share_one_evidence_build(tmp_path, monkeypatch):
    """The route table, neighbor tables and OSPF database of a request are each read through
    `for_snapshot`; the evidence of a table is built once per resolved snapshot."""
    from hst.core import ribsource

    settings = _settings(tmp_path)
    _two_units(settings, record_uids=True)
    built = []
    real = ribsource.snapshot_evidence

    def counting(*args, **kwargs):
        built.append(kwargs.get("table", "rib"))
        return real(*args, **kwargs)

    monkeypatch.setattr(ribsource, "snapshot_evidence", counting)
    snap = _snap(settings, 1000)
    first, second = for_snapshot(snap), for_snapshot(snap)
    assert first._evidence is second._evidence and built == ["rib"]
    assert for_snapshot(_snap(settings, 1000))._evidence is not first._evidence
    assert built == ["rib", "rib"]


def test_route_page_marks_the_longest_match_before_the_protocol_filter(store):
    src = RibSource(store)
    page = src.route_page("dev:r1", address="8.8.8.8")
    assert [(r["prefix"], r["longest"]) for r in page.rows] == [
        ("8.8.8.0/24", True),
        ("8.8.8.0/24", True),
        ("8.0.0.0/8", False),
        ("0.0.0.0/0", False),
    ]
    # the static default is the only row the filter keeps, and it is not the match
    static = src.route_page("dev:r1", address="8.8.8.8", protocol="static")
    assert [(r["prefix"], r["longest"]) for r in static.rows] == [("0.0.0.0/0", False)]


def test_route_page_marks_the_longest_match_of_each_vrf(tmp_path):
    pytest.importorskip("duckdb")
    rows = [
        {**_row("10.1.0.0/16", "10.9.0.1", "eth1"), "vrf": "blue"},
        {**_row("10.1.2.0/24", "10.9.0.2", "eth2"), "vrf": "blue"},
        {**_row("10.0.0.0/8", "10.9.0.3", "eth3"), "vrf": "red"},
    ]
    sidestore.write_table(tmp_path, "rib", "nxos", "", "1700000001000-bbbbbbbb", rows, 1000)
    page = RibSource(tmp_path).route_page("dev:r1", address="10.1.2.7")
    marked = {(r["vrf"], r["prefix"]): r["longest"] for r in page.rows}
    assert marked == {
        ("blue", "10.1.2.0/24"): True,
        ("blue", "10.1.0.0/16"): False,
        ("red", "10.0.0.0/8"): True,
    }


def test_lpm_reads_a_store_with_a_quote_in_its_path(tmp_path):
    pytest.importorskip("duckdb")
    base = tmp_path / "o'brien"
    sidestore.write_table(
        base, "rib", "nxos", "", "1700000000000-aaaaaaaa", [_row("10.0.0.0/8", "10.9.0.1", "eth2")], 1000
    )
    out = RibSource(base).lpm("dev:r1", None, "10.1.1.1", legacy_vrf="default")
    assert [r["next_hop"] for r in out] == ["10.9.0.1"]
