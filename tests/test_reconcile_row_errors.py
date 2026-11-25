"""A missing side-store file whose rows cannot be rebuilt is a finding of the
repair, not a crash of it (core/reconcile.py `repair_derived`)."""

from __future__ import annotations

from typing import Any

import pyarrow as pa
import pytest

from hst.app.crypto import dek, generate_key
from hst.collectors import streams
from hst.core import manifest as manifestmod
from hst.core import rawstore, reconcile, sidestore
from hst.core.config import Settings

SNAPSHOT = 1_700_000_000_000
RUN_ID = "1700000000000-aaaaaaaa"
ARP = [
    {"device_uid": "dev:r1", "vrf": "default", "ip": "10.0.0.1", "mac": "00:00:5e:00:53:01", "af": 4},
    {"device_uid": "dev:r1", "vrf": "default", "ip": "10.0.0.2", "mac": "00:00:5e:00:53:02", "af": 4},
]
MAC = [{"device_uid": "dev:r1", "vlan": 10, "mac": "00:00:5e:00:53:01", "port_name": "Eth1/1"}]


class _Collector:
    """What `repair_derived` asks of a collector: `side_tables` alone."""

    def __init__(self, tables: dict[str, Any]) -> None:
        self.tables = tables

    def side_tables(self, raw: Any) -> dict[str, Any]:
        return self.tables


def _unbuildable(record: dict[str, Any]) -> dict[str, Any]:
    return {**record, "interface_name": record["interface"]}


def _lost_tables(tmp_path) -> tuple[Settings, reconcile.ReconcileReport, dict[str, str]]:
    """A published snapshot of one device with an arp and a mac table, both of
    whose side-store files are then lost. Returns the settings, the scan that
    finds them missing, and each table's path relative to the data directory."""
    settings = Settings(_env_file=None, hst_data_dir=tmp_path / "data", hst_secret_key=generate_key())
    raw = rawstore.write(settings.raw_dir, "edge", RUN_ID, {"seen": 1}, host="r1", key=dek(settings))
    rawstore.mark_joined(raw, SNAPSHOT)
    tables = {
        name: sidestore.write_table(settings.sidestore_dir, name, "edge", "r1", RUN_ID, rows, SNAPSHOT)
        for name, rows in (("arp", ARP), ("mac", MAC))
    }
    files = [manifestmod.file_entry(settings, raw)]
    files += [manifestmod.file_entry(settings, path) for path in tables.values() if path is not None]
    record = manifestmod.SnapshotManifest(
        snapshot_key=SNAPSHOT,
        kind="full",
        opened=manifestmod.iso(SNAPSHOT),
        published=manifestmod.now_iso(),
        devices=[],
        files=files,
    )
    manifestmod.write(settings, record)
    relative = {}
    for name, path in tables.items():
        assert path is not None
        relative[name] = path.relative_to(settings.hst_data_dir).as_posix()
        path.unlink()
    report = reconcile.scan(settings)
    assert report.missing_derived == sorted(relative.values())
    return settings, report, relative


def test_a_row_that_cannot_be_built_is_a_finding_and_the_repair_goes_on(tmp_path):
    settings, report, relative = _lost_tables(tmp_path)
    collector = _Collector(
        {"arp": streams.MappedRows(ARP, _unbuildable), "mac": streams.MappedRows(MAC, dict)}
    )
    target = tmp_path / "repair"

    lines = reconcile.repair_derived(
        settings, report, target, collector_for=lambda source, host: collector, key=dek(settings)
    )

    assert lines[0] == f"{relative['arp']}: could not regenerate (KeyError: 'interface')"
    assert lines[1].startswith(f"{relative['mac']}: rebuilt into ")
    assert lines[1].endswith("the recorded row digest matches")
    assert report.rebuilt_paths == [relative["mac"]]
    assert sorted(p.relative_to(target).as_posix() for p in target.rglob("*.parquet")) == [
        f"mac/edge/r1/{RUN_ID}.parquet"
    ]


def test_it_reads_as_a_raising_side_tables_does(tmp_path):
    """The eager build of the same rows fails the whole payload, the mac table
    included, and the view fails the arp table alone; the arp finding reads
    the same either way."""

    class _Raising(_Collector):
        def side_tables(self, raw: Any) -> dict[str, Any]:
            return {"arp": [_unbuildable(r) for r in ARP], "mac": MAC}

    findings = []
    for name, collector in (
        ("eager", _Raising({})),
        ("view", _Collector({"arp": streams.MappedRows(ARP, _unbuildable), "mac": MAC})),
    ):
        settings, report, relative = _lost_tables(tmp_path / name)
        lines = reconcile.repair_derived(
            settings,
            report,
            tmp_path / name / "repair",
            collector_for=lambda s, h, c=collector: c,
            key=dek(settings),
        )
        findings.append(lines[0].removeprefix(relative["arp"]))

    assert findings == [": could not regenerate (KeyError: 'interface')"] * 2


def test_a_row_arrow_cannot_convert_propagates(tmp_path):
    settings, report, _relative = _lost_tables(tmp_path)
    collector = _Collector({"arp": [{**ARP[0], "af": "four"}], "mac": MAC})

    with pytest.raises((pa.ArrowInvalid, pa.ArrowTypeError)):
        reconcile.repair_derived(
            settings, report, tmp_path / "repair", collector_for=lambda s, h: collector, key=dek(settings)
        )
