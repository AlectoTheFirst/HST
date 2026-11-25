"""A side-table row the collector cannot build is reported by the offline parse
(collectors/offline.py `parse_report`), the engine of `hst parse-raw` and of
the UI's debug re-parse."""

from __future__ import annotations

from typing import Any

import pytest
from tests.test_iosxe import RAW, _collector

from hst.collectors import cisco_common, iosxe, offline, streams
from hst.core.model import Batch

ARP = [
    {"device_uid": "dev:r1", "vrf": "default", "ip": "10.0.0.1", "mac": "00:00:5e:00:53:01", "af": 4},
    {"device_uid": "dev:r1", "vrf": "default", "ip": "10.0.0.2", "mac": "00:00:5e:00:53:02", "af": 4},
]
MAC = [{"device_uid": "dev:r1", "vlan": 10, "mac": "00:00:5e:00:53:01", "port_name": "Eth1/1"}]


class _Stub:
    """What `parse_report` asks of a collector, with the side tables given."""

    name = "stub"
    SIDE_TABLES = ("arp", "mac")

    def __init__(self, tables: dict[str, Any]) -> None:
        self.tables = tables

    def normalize(self, raw: Any) -> Batch:
        return Batch(source=self.name, scope="stub:r1")

    def side_tables(self, raw: Any) -> dict[str, Any]:
        return self.tables

    def table_outcomes(self, raw: Any) -> dict[str, Any]:
        return {}


class _Raising(_Stub):
    """The same rows built eagerly: the failure raises inside `side_tables`."""

    def side_tables(self, raw: Any) -> dict[str, Any]:
        return {"arp": [_unbuildable(r) for r in ARP], "mac": list(MAC)}


def _unbuildable(record: dict[str, Any]) -> dict[str, Any]:
    return {**record, "interface_name": record["interface"]}


def _outcomes(report: offline.ParseReport) -> dict[str, tuple[str, int | None]]:
    return {name: (o.status, o.row_count) for name, o in report.outcomes.items()}


def test_a_row_that_cannot_be_built_is_the_reports_error():
    collector = _Stub({"arp": streams.MappedRows(ARP, _unbuildable), "mac": streams.MappedRows(MAC, dict)})

    report = offline.parse_report(collector, {}, path="memory")

    assert report.error == "side_tables: KeyError: 'interface'"
    assert not report.ok
    assert report.side_tables == {"arp": 0, "mac": 0}
    assert _outcomes(report) == {"arp": ("complete-empty", 0), "mac": ("complete-empty", 0)}


def test_it_reads_as_a_raising_side_tables_does():
    """The eager build of the same rows raises inside `side_tables`; the view
    raises on the read. The report is the same either way."""
    view = _Stub({"arp": streams.MappedRows(ARP, _unbuildable), "mac": list(MAC)})

    by_view = offline.parse_report(view, {}, path="memory")
    eager = offline.parse_report(_Raising({}), {}, path="memory")

    assert by_view.as_dict() == eager.as_dict()


def test_an_exception_outside_a_row_view_keeps_the_generic_report():
    """A table that is not a view and fails on its read reports the exception
    it raised, the same prefix a raising `side_tables` gets."""

    class _Broken:
        def __len__(self) -> int:
            return 1

        def __iter__(self):
            raise ValueError("broken table")

    report = offline.parse_report(_Stub({"arp": _Broken(), "mac": list(MAC)}), {}, path="memory")

    assert report.error == "side_tables: ValueError: broken table"
    assert _outcomes(report) == {"arp": ("complete-empty", 0), "mac": ("complete-empty", 0)}


def test_views_that_build_every_row_report_their_counts():
    collector = _Stub({"arp": streams.MappedRows(ARP, dict), "mac": streams.MappedRows(MAC, dict)})

    report = offline.parse_report(collector, {}, path="memory")

    assert report.error is None
    assert report.side_tables == {"arp": 2, "mac": 1}
    assert _outcomes(report) == {"arp": ("complete", 2), "mac": ("complete", 1)}


def _fail_on_second_call(monkeypatch, module: Any) -> None:
    real = module.lpm_columns
    calls = {"n": 0}

    def failing(prefix: str) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyError(f"forced on {prefix}")
        return real(prefix)

    monkeypatch.setattr(module, "lpm_columns", failing)


@pytest.mark.parametrize(
    ("module", "table"), [(cisco_common, "rib"), (iosxe, "bgp_session_routes")], ids=["rib", "bgp"]
)
def test_an_ios_xe_row_that_cannot_be_built_fails_the_side_tables(monkeypatch, module, table):
    """The real collector's rib and BGP path views: the second row of the table
    cannot be built. The report names the collector's own exception and states
    no table as complete, as a load of the same payload would fail."""
    _fail_on_second_call(monkeypatch, module)

    report = offline.parse_report(_collector(), dict(RAW), path="memory")

    assert report.error is not None
    assert report.error.startswith("side_tables: KeyError: 'forced on ")
    assert report.outcomes[table].status == "complete-empty"
    assert report.outcomes["rib"].status == "complete-empty"
    assert report.outcomes["bgp_session_routes"].status == "complete-empty"
    assert set(report.side_tables.values()) == {0}


def test_an_ios_xe_payload_that_builds_reports_its_tables_complete():
    report = offline.parse_report(_collector(), dict(RAW), path="memory")

    assert report.error is None
    for table in ("rib", "bgp_session_routes"):
        assert report.side_tables[table] > 0
        assert report.outcomes[table].status == "complete"
        assert report.outcomes[table].row_count == report.side_tables[table]
