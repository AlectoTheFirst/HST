"""`hst audit domains`: components of the route-target pairing relation that
span more than one declared domain."""

from typer.testing import CliRunner

import hst.cli as cli
from hst.core import Settings

runner = CliRunner()


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def data(self):
        return self._rows


class FakeTx:
    """Dispatches by query content: `read_topology`/`read_realizes` each run one
    query, told apart by the label each names."""

    def __init__(self, rt_rows, realizes_rows):
        self._rt_rows = rt_rows
        self._realizes_rows = realizes_rows
        self.calls = []

    def run(self, query, **params):
        self.calls.append((query, params))
        if "RouteTarget" in query:
            return FakeResult(self._rt_rows)
        if "RoutingDomain" in query or "L3Domain" in query:
            return FakeResult(self._realizes_rows)
        return FakeResult([])


class FakeSession:
    """Mirrors execute_read(work, *args) the way tests/test_mcp_server.py does."""

    def __init__(self, rt_rows, realizes_rows, current=None):
        self.tx = FakeTx(rt_rows, realizes_rows)
        self._current = current
        self.pointer_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        # the autocommit pointer read core.cycle.current_ts_or_none issues once,
        # shared by both read_topology and read_realizes below
        self.pointer_calls += 1
        rows = [{"current": self._current}] if self._current is not None else []
        return FakeResult(rows)

    def execute_read(self, work, *args, **kwargs):
        return work(self.tx, *args, **kwargs)


def _patch(monkeypatch, rt_rows, realizes_rows, current=None):
    session = FakeSession(rt_rows, realizes_rows, current=current)
    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(cli.dbmod, "session", lambda settings: session)
    return session


def test_a_component_spanning_two_declared_domains_prints_the_block(monkeypatch):
    rt_rows = [
        {"vrf_uid": "vrf:dev:a:default", "kind": "EXPORTS", "rt": "65000:1"},
        {"vrf_uid": "vrf:dev:b:default", "kind": "IMPORTS", "rt": "65000:1"},
    ]
    realizes_rows = [
        {"vrf_uid": "vrf:dev:a:default", "domain_name": "corp-a"},
        {"vrf_uid": "vrf:dev:b:default", "domain_name": "corp-b"},
    ]
    _patch(monkeypatch, rt_rows, realizes_rows)

    r = runner.invoke(cli.app, ["audit", "domains"])

    assert r.exit_code == 0, r.output
    assert "65000:1" in r.output
    assert "vrf:dev:a:default" in r.output and "(dev:a)" in r.output
    assert "vrf:dev:b:default" in r.output and "(dev:b)" in r.output
    assert "corp-a" in r.output
    assert "corp-b" in r.output
    assert "splits across 2 declared domain(s): corp-a, corp-b" in r.output
    assert "1 component(s) span more than one declared domain" in r.output


def test_a_clean_graph_prints_the_explicit_no_findings_line(monkeypatch):
    _patch(monkeypatch, [], [])

    r = runner.invoke(cli.app, ["audit", "domains"])

    assert r.exit_code == 0, r.output
    assert "no route-target-connected VRFs span more than one declared domain" in r.output


def test_a_component_that_stays_within_one_domain_is_not_reported(monkeypatch):
    rt_rows = [
        {"vrf_uid": "vrf:dev:a:default", "kind": "EXPORTS", "rt": "65000:1"},
        {"vrf_uid": "vrf:dev:b:default", "kind": "IMPORTS", "rt": "65000:1"},
    ]
    realizes_rows = [
        {"vrf_uid": "vrf:dev:a:default", "domain_name": "corp"},
        {"vrf_uid": "vrf:dev:b:default", "domain_name": "corp"},
    ]
    _patch(monkeypatch, rt_rows, realizes_rows)

    r = runner.invoke(cli.app, ["audit", "domains"])

    assert r.exit_code == 0, r.output
    assert "no route-target-connected VRFs span more than one declared domain" in r.output


def test_two_import_only_vrfs_sharing_an_rt_are_not_reported():
    """Plain shared-RT (no exporter) never pairs."""
    from hst.core import reasoner

    topology = reasoner.pair_and_group(
        [
            {"vrf_uid": "vrf:c", "kind": "IMPORTS", "rt": "rt1"},
            {"vrf_uid": "vrf:d", "kind": "IMPORTS", "rt": "rt1"},
        ]
    )
    realizes = [
        {"vrf_uid": "vrf:c", "domain_name": "x"},
        {"vrf_uid": "vrf:d", "domain_name": "y"},
    ]
    assert reasoner.find_domain_splits(topology, realizes) == []


def test_exits_zero_even_when_findings_are_reported(monkeypatch):
    rt_rows = [
        {"vrf_uid": "a", "kind": "EXPORTS", "rt": "rt1"},
        {"vrf_uid": "b", "kind": "IMPORTS", "rt": "rt1"},
    ]
    realizes_rows = [{"vrf_uid": "a", "domain_name": "x"}, {"vrf_uid": "b", "domain_name": "y"}]
    _patch(monkeypatch, rt_rows, realizes_rows)

    r = runner.invoke(cli.app, ["audit", "domains"])

    assert r.exit_code == 0, r.output


def test_resolves_the_pointer_once_and_shares_it_between_both_reads(monkeypatch):
    """The pointer is resolved once and the same value pins both read_topology and
    read_realizes."""
    session = _patch(monkeypatch, [], [], current=4242)

    r = runner.invoke(cli.app, ["audit", "domains"])

    assert r.exit_code == 0, r.output
    assert session.pointer_calls == 1
    assert {p["cts"] for _, p in session.tx.calls} == {4242}
