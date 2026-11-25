"""The row facts a side-store write records for the manifest."""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
from collections import OrderedDict
from pathlib import Path
from typing import Any

import pytest

pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")

from tests.support import synthetic_payloads as sp  # noqa: E402

from hst.app.crypto import generate_key  # noqa: E402
from hst.core import Settings, ipenc, manifest, sidestore  # noqa: E402


def _reference_digest(rows: list[dict[str, Any]]) -> tuple[int, str]:
    """The row digest over `rows` as it is defined, written out in full."""
    digests = sorted(
        hashlib.sha256(
            json.dumps(row, sort_keys=True, default=str, separators=(",", ":")).encode()
        ).hexdigest()
        for row in rows
    )
    h = hashlib.sha256()
    for digest in digests:
        h.update(digest.encode())
        h.update(b"\n")
    return len(rows), h.hexdigest()


def _reference_facts(path: Path) -> tuple[int, str]:
    return _reference_digest(pq.read_table(path).to_pylist())


def _settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


@pytest.fixture(autouse=True)
def _empty_record(monkeypatch):
    """Every test starts with nothing recorded, whatever ran before it."""
    monkeypatch.setattr(sidestore, "_written", OrderedDict())


# --- rows that exercise every column type -----------------------------------------------


def _rib_rows() -> list[dict[str, Any]]:
    rows = []
    for n, prefix in enumerate(("10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32", "0.0.0.0/0", "192.0.2.1/32")):
        lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
        rows.append(
            {
                "device_uid": "dev:r1",
                "vrf": "default" if n % 2 else "CUST \u00e9\u2603",
                "context_uid": "vrf:dev:r1:default",
                "prefix": prefix,
                "next_hop": None if n == 3 else f"10.9.0.{n}",
                "interface": 'Eth1/1 "uplink" \\ \u2028',
                "protocol": "bgp",
                "metric": None if n == 1 else n * 1000,
                "af": af,
                "prefixlen": prefixlen,
                "lo": lo,
                "hi": hi,
            }
        )
    # a row that names 3 of the columns
    rows.append({"device_uid": "dev:r1", "vrf": "default", "prefix": "172.16.0.0/12"})
    return rows


def _mac_rows() -> list[dict[str, Any]]:
    return [
        {"device_uid": "dev:s1", "vlan": vid, "mac": f"aabbccddee{vid:02x}", "port_name": f"Ethernet1/{vid}"}
        for vid in range(1, 8)
    ] + [{"device_uid": "dev:s1", "vlan": None, "mac": "aabbccddeeff", "port_name": None}]


def _arp_rows() -> list[dict[str, Any]]:
    return [
        {
            "device_uid": "dev:r1",
            "vrf": "default",
            "context_uid": "vrf:dev:r1:default",
            "ip": ip,
            "mac": "aa:bb:cc:dd:ee:ff",
            "interface_name": "Vlan10",
            "af": af,
        }
        for ip, af in (("10.0.0.1", 4), ("2001:db8::1", 6), ("not-an-ip", None))
    ]


def _ospf_rows() -> list[dict[str, Any]]:
    link = {"link_type": "point-to-point", "link_id": "10.255.0.2", "link_data": "10.0.0.1", "metric": 40}
    return [
        {
            "device_uid": "dev:r1",
            "context_uid": "vrf:dev:r1:default",
            "process": "1",
            "area": "0.0.0.0",  # noqa: S104 - an OSPF area id, not a bind address
            "lsa_type": "router",
            "lsid": "10.255.0.1",
            "adv_router": "10.255.0.1",
            "seq": 0x80000005,
            "age": 120,
            "metric": None,
            "links": [link, None, {"link_type": "stub", "link_id": None}],
            "attached_routers": None,
        },
        {
            "device_uid": "dev:r1",
            "process": "1",
            "area": "0.0.0.1",
            "lsa_type": "network",
            "lsid": "10.0.0.1",
            "links": [],
            "attached_routers": ["10.255.0.1", None, "10.255.0.2"],
            "mask": "255.255.255.252",
        },
        {"device_uid": "dev:r1", "lsa_type": "external", "metric": 20, "metric_type": 2, "links": None},
    ]


def _bgp_route_rows() -> list[dict[str, Any]]:
    lo, hi, prefixlen, af = ipenc.prefix_bounds("10.20.0.0/24")
    return [
        {
            "device_uid": "dev:r1",
            "context_uid": "vrf:dev:r1:default",
            "session_uid": "bgp:dev:r1:default:10.9.0.1",
            "peer_ip": "10.9.0.1",
            "af": af,
            "safi": "unicast",
            "direction": direction,
            "rib_type": "adj-rib-in",
            "policy_stage": "pre-import",
            "path_id": str(n),
            "prefix": "10.20.0.0/24",
            "prefixlen": prefixlen,
            "lo": lo,
            "hi": hi,
            "next_hop": "10.9.0.1",
            "as_path": "65001 65002 {65003,65004}",
            "local_pref": 100,
            "med": None,
            "origin": "i",
            "communities": '65001:100 "no-export"',
            "best": best,
        }
        for n, (direction, best) in enumerate((("received", None), ("accepted", True), ("advertised", False)))
    ]


def _bgp_session_rows() -> list[dict[str, Any]]:
    return [
        {
            "device_uid": "dev:r1",
            "context_uid": "vrf:dev:r1:default",
            "session_uid": "bgp:dev:r1:default:10.9.0.1",
            "peer_ip": "10.9.0.1",
            "af": 4,
            "safi": "unicast",
            "state": "Established",
            "established_since_ms": 1_700_000_000_000,
            "prefixes_received": 950_000,
            "prefixes_advertised": 0,
            "capabilities": "route-refresh, 4-byte-as",
        }
    ]


def _checkpoint_envelope_rows() -> list[dict[str, Any]]:
    return [
        {
            "uid": "cp:mgmt:access-rule:r1",
            "label": "FwRule",
            "envelope_sha": "0" * 64,
            "envelope": '{"uid": "r1", "type": "access-rule"}',
        }
    ]


TABLE_ROWS = {
    "rib": _rib_rows,
    "mac": _mac_rows,
    "arp": _arp_rows,
    "ospf_lsdb": _ospf_rows,
    "bgp_session_routes": _bgp_route_rows,
    "bgp_sessions": _bgp_session_rows,
    "checkpoint_envelopes": _checkpoint_envelope_rows,
}


def test_every_side_store_table_has_rows_here():
    assert set(TABLE_ROWS) == set(sidestore.SCHEMAS)


@pytest.mark.parametrize("slice_rows", [1, 2, 8192], ids=["slice-1", "slice-2", "slice-8192"])
@pytest.mark.parametrize("table", sorted(TABLE_ROWS))
def test_the_recorded_facts_are_the_defined_digest(tmp_path, monkeypatch, table, slice_rows):
    """Row groups of two rows, and digest slices of one, two and 8192 rows:
    the recorded facts, the read-back and the digest definition agree."""
    monkeypatch.setattr(manifest, "ROW_DIGEST_SLICE", slice_rows)
    path = sidestore.write_table(
        tmp_path, table, "src", "h1", "1700000000000-aaaaaaaa", TABLE_ROWS[table](), 7, 2
    )
    assert path is not None

    recorded = sidestore.written_row_facts(path)

    assert recorded == manifest.sidestore_row_facts(path) == _reference_facts(path)
    assert recorded[0] == len(TABLE_ROWS[table]())


GOLDEN_CASES = [
    *(sp.case_key(family, "fixture", variant) for family in sp.FAMILIES for variant in sp.VARIANTS),
    *(sp.case_key(family, "small", "plain") for family in sp.FAMILIES),
    *(sp.case_key(family, "small", "unicode") for family in sp.FAMILIES),
]


@pytest.mark.parametrize("key", GOLDEN_CASES)
def test_the_recorded_facts_of_the_golden_payloads_are_the_golden_values(tmp_path, monkeypatch, key):
    """The manifest entry of each table of each golden payload carries the
    golden row facts, and takes them without reading the file back."""
    golden = sp.load_golden()["cases"][key]["parquet"]
    family, _scale, _variant = sp.split_case(key)
    settings = _settings(tmp_path)
    side = sp.make_collector(family, None).side_tables(sp.case_payload(key))

    def no_read_back(path: Path) -> tuple[int, str]:
        raise AssertionError(f"{path} was read back")

    written = {}
    for table, rows in sorted(side.items()):
        written[table] = sidestore.write_table(
            settings.sidestore_dir,
            table,
            sp.COLLECTOR_SOURCE,
            sp.COLLECTOR_HOST,
            sp.RUN_ID,
            rows,
            snapshot_ts=sp.SNAPSHOT_TS,
            row_group_rows=sp.ROW_GROUP_ROWS,
        )
    monkeypatch.setattr(manifest, "sidestore_row_facts", no_read_back)
    for table, path in written.items():
        if path is None:
            assert golden[table] == [0, None], table
            continue
        entry = manifest.file_entry(settings, path)
        assert [entry.row_count, entry.rows_sha256] == golden[table], table


# --- when the record answers, and when the file is read back -----------------------------


def _write(
    base: Path, run_id: str = "1700000000000-aaaaaaaa", rows: list[dict[str, Any]] | None = None
) -> Path:
    path = sidestore.write_table(base, "rib", "src", "h1", run_id, rows or _rib_rows(), 7)
    assert path is not None
    return path


def test_a_file_rewritten_after_its_write_is_read_back(tmp_path):
    settings = _settings(tmp_path)
    path = _write(settings.sidestore_dir)
    other = pa.Table.from_pylist(
        [{**row, "run_id": "x", "snapshot_ts": 7} for row in _rib_rows()[:2]], schema=sidestore.SCHEMAS["rib"]
    )
    pq.write_table(other, path)
    os.utime(path, ns=(1_000_000_000, 1_000_000_000))

    assert sidestore.written_row_facts(path) is None
    entry = manifest.file_entry(settings, path)
    assert (entry.row_count, entry.rows_sha256) == _reference_facts(path)
    assert entry.row_count == 2


def test_a_file_this_process_did_not_write_is_read_back(tmp_path):
    settings = _settings(tmp_path)
    path = settings.sidestore_dir / "rib" / "src" / "h1" / "1700000000000-bbbbbbbb.parquet"
    path.parent.mkdir(parents=True)
    rows = [{**row, "run_id": "1700000000000-bbbbbbbb", "snapshot_ts": 7} for row in _rib_rows()]
    pq.write_table(pa.Table.from_pylist(rows, schema=sidestore.SCHEMAS["rib"]), path)

    assert sidestore.written_row_facts(path) is None
    entry = manifest.file_entry(settings, path)
    assert (entry.row_count, entry.rows_sha256) == _reference_facts(path)


def test_a_file_removed_after_its_write_has_no_recorded_facts(tmp_path):
    path = _write(tmp_path)
    path.unlink()
    assert sidestore.written_row_facts(path) is None


def test_the_record_is_found_under_another_spelling_of_the_path(tmp_path, monkeypatch):
    path = _write(tmp_path / "store")
    monkeypatch.chdir(tmp_path)
    relative = Path("store") / path.relative_to(tmp_path / "store")
    assert sidestore.written_row_facts(relative) == _reference_facts(path)


def test_the_record_keeps_the_newest_files_only(tmp_path, monkeypatch):
    monkeypatch.setattr(sidestore, "WRITTEN_FACTS_KEEP", 2)
    first, second, third = (_write(tmp_path, f"170000000000{n}-aaaaaaaa") for n in range(3))

    assert sidestore.written_row_facts(first) is None
    assert sidestore.written_row_facts(second) == _reference_facts(second)
    assert sidestore.written_row_facts(third) == _reference_facts(third)
    assert len(sidestore._written) == 2


def test_a_file_written_again_records_its_new_rows(tmp_path):
    path = _write(tmp_path)
    again = _write(tmp_path, rows=_rib_rows()[:3])
    assert again == path
    assert sidestore.written_row_facts(path) == _reference_facts(path)
    assert sidestore.written_row_facts(path)[0] == 3


@pytest.mark.parametrize("step", ["add", "digest"])
def test_a_digest_that_cannot_be_taken_leaves_the_write_whole(tmp_path, monkeypatch, caplog, step):
    """The digest spills to temporary files, which can fail to be written. The
    table write does not depend on it: the file is written, nothing is
    recorded, and the manifest reads the file back."""
    settings = _settings(tmp_path)

    def full(*args: Any, **kwargs: Any) -> Any:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(manifest.RowDigests, step, full)
    with caplog.at_level(logging.WARNING, logger=sidestore.logger.name):
        path = _write(settings.sidestore_dir)
    monkeypatch.undo()
    monkeypatch.setattr(sidestore, "_written", OrderedDict())

    assert path.is_file()
    assert sidestore.written_row_facts(path) is None
    assert any("was not taken during its write" in r.getMessage() for r in caplog.records)
    entry = manifest.file_entry(settings, path)
    assert (entry.row_count, entry.rows_sha256) == _reference_facts(path)


def test_a_failed_write_records_nothing_and_leaves_no_temporary_file(tmp_path):
    def rows():
        yield _rib_rows()[0]
        raise RuntimeError("the device answer ended early")

    with pytest.raises(RuntimeError, match="ended early"):
        sidestore.write_table(tmp_path, "rib", "src", "h1", "1700000000000-aaaaaaaa", rows(), 7, 1)

    assert list(tmp_path.rglob(f"*{sidestore.TMP_SUFFIX}")) == []
    assert list(tmp_path.rglob(f"*{sidestore.SUFFIX}")) == []
    assert len(sidestore._written) == 0


# --- the digest itself --------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        {"b": 1, "a": {"d": [3, {"z": None, "y": True}], "c": "\u00e9\u2603\U0001f600"}},
        {"lo": b"\x00\x0b\xff", "when": datetime.datetime(2026, 9, 27, tzinfo=datetime.UTC)},
        ["x", 1.5, float("nan"), -0.0, 10**30, "\x00\x1f\x7f\ud800", ("t", 1)],
        '"quoted" \\ back',
        None,
    ],
    ids=["nested", "default-str", "list", "string", "null"],
)
def test_canonical_json_renders_what_json_dumps_renders(value):
    expected = json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    assert manifest.canonical_json(value) == expected


def _batch_digest(batch: Any) -> tuple[int, str]:
    with manifest.RowDigests() as digests:
        digests.add(batch)
        return digests.count, digests.digest()


def test_a_batch_with_repeated_column_names_digests_as_to_pylist_reads_it():
    batch = pa.RecordBatch.from_arrays([pa.array([1, 2]), pa.array(["a", "b"])], names=["k", "k"])
    assert _batch_digest(batch) == _reference_digest(batch.to_pylist())


def test_a_dictionary_column_of_structs_digests_with_sorted_keys():
    structs = pa.array([{"z": 1, "a": "x"}, {"z": 2, "a": "y"}])
    column = pa.DictionaryArray.from_arrays(pa.array([0, 1, 0], pa.int32()), structs)
    batch = pa.RecordBatch.from_arrays([column, pa.array([3, 2, 1])], names=["s", "b"])
    assert _batch_digest(batch) == _reference_digest(batch.to_pylist())


def test_a_flat_batch_digests_as_to_pylist_reads_it():
    batch = pa.RecordBatch.from_arrays(
        [
            pa.array(["\u2603", None, 'q"'], pa.string()),
            pa.array([b"\x00" * 16, None, b"\xff" * 16], pa.binary(16)),
            pa.array([True, None, False]),
            pa.array([1, None, -(2**63)], pa.int64()),
            pa.array([0.5, None, 1e300]),
            pa.array(["a", "b", "a"]).dictionary_encode(),
        ],
        names=["zeta", "lo", "best", "metric", "ratio", "kind"],
    )
    assert _batch_digest(batch) == _reference_digest(batch.to_pylist())
