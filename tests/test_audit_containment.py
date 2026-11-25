"""`hst audit containment`: data-quality report on held addresses missing the
IN edge the address-containment rule derives."""

from typer.testing import CliRunner

import hst.cli as cli
from hst.core import Settings, cycle

runner = CliRunner()


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def data(self):
        return self._rows


class FakeTx:
    """The report reads four queries; dispatch on distinctive query text."""

    def __init__(self, addresses, prefixes, bd_serving, live):
        self._by_marker = {
            "MATCH (h)-[r:HAS_IP]": addresses,
            "cidr AS cidr": prefixes,
            "AS bd": bd_serving,
            "MATCH (ia:IpAddress:Obj)-[e:IN]->(p:Prefix)": live,
        }

    def run(self, query, **params):
        for marker, rows in self._by_marker.items():
            if marker in query:
                return FakeResult(rows)
        raise AssertionError(f"unexpected audit query: {query}")


class FakeSession:
    def __init__(self, tx):
        self._tx = tx

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute_read(self, work, *args, **kwargs):
        return work(self._tx, *args, **kwargs)


ADDRESS = {"uid": "ip:bd-vlan-fab0-10:10.0.0.5", "ip": "10.0.0.5", "l3dom": "home", "anchor": "home"}
PREFIX = {
    "uid": "pfx:vrf-d-r1-default:10.0.0.0/24",
    "cidr": "10.0.0.0/24",
    "l3dom": "home",
    "anchor": "vrf:d:r1:default",
}


def _patch(monkeypatch, addresses, prefixes, bd_serving, live, cts=42):
    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(
        cli.dbmod, "session", lambda settings: FakeSession(FakeTx(addresses, prefixes, bd_serving, live))
    )
    monkeypatch.setattr(cycle, "current_ts_or_none", lambda s: cts)


def test_reports_one_line_per_missing_pair_and_a_trailing_count(monkeypatch):
    _patch(monkeypatch, [ADDRESS], [PREFIX], [], live=[])
    r = runner.invoke(cli.app, ["audit", "containment"])
    assert r.exit_code == 0, r.output
    assert ADDRESS["uid"] in r.output
    assert "10.0.0.5" in r.output
    assert PREFIX["uid"] in r.output
    assert "10.0.0.0/24" in r.output
    assert "1 containment edge(s) missing" in r.output


def test_a_live_edge_satisfies_the_pair_and_the_report_is_clean(monkeypatch):
    _patch(monkeypatch, [ADDRESS], [PREFIX], [], live=[{"ip": ADDRESS["uid"], "pfx": PREFIX["uid"]}])
    r = runner.invoke(cli.app, ["audit", "containment"])
    assert r.exit_code == 0, r.output
    assert "every held address inside a known connected prefix has its IN edge" in r.output


def test_exits_zero_even_when_findings_are_reported(monkeypatch):
    _patch(monkeypatch, [ADDRESS], [PREFIX], [], live=[])
    r = runner.invoke(cli.app, ["audit", "containment"])
    assert r.exit_code == 0, r.output


def test_no_cycle_pointer_is_stated_not_an_error(monkeypatch):
    _patch(monkeypatch, [], [], [], live=[], cts=None)
    r = runner.invoke(cli.app, ["audit", "containment"])
    assert r.exit_code == 0, r.output
    assert "no cycle pointer" in r.output
