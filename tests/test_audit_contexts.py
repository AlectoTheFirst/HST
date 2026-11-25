"""`hst audit contexts`: data-quality report on interfaces missing a forwarding
context."""

from typer.testing import CliRunner

import hst.cli as cli
from hst import queries
from hst.core import Settings

runner = CliRunner()


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def data(self):
        return self._rows


class FakeTx:
    def __init__(self, rows):
        self._rows = rows
        self.calls = []

    def run(self, query, **params):
        self.calls.append((query, params))
        return FakeResult(self._rows)


class FakeSession:
    """Mirrors execute_read(work, *args) the way tests/test_mcp_server.py does."""

    def __init__(self, rows, current=None):
        self._rows = rows
        self._current = current
        self.tx = FakeTx(rows)
        self.pointer_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        # the autocommit pointer read core.cycle.current_ts_or_none issues once,
        # before the managed audit-contexts read
        self.pointer_calls += 1
        rows = [{"current": self._current}] if self._current is not None else []
        return FakeResult(rows)

    def execute_read(self, work, *args, **kwargs):
        return work(self.tx, *args, **kwargs)


def _patch(monkeypatch, rows, current=None):
    session = FakeSession(rows, current=current)
    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(cli.dbmod, "session", lambda settings: session)
    return session


def test_reports_one_line_per_row_and_a_trailing_count(monkeypatch):
    rows = [
        {
            "device_uid": "dev:a1",
            "interface_uid": "dev:a1/if/eth0",
            "interface_name": "eth0",
            "address_count": 2,
        },
        {
            "device_uid": "dev:b1",
            "interface_uid": "dev:b1/if/eth1",
            "interface_name": "eth1",
            "address_count": 1,
        },
    ]
    _patch(monkeypatch, rows)
    r = runner.invoke(cli.app, ["audit", "contexts"])
    assert r.exit_code == 0, r.output
    assert "dev:a1" in r.output
    assert "dev:a1/if/eth0" in r.output
    assert "eth0" in r.output
    assert "2 address(es)" in r.output
    assert "dev:b1" in r.output
    assert "dev:b1/if/eth1" in r.output
    assert "2 interface(s) missing forwarding context" in r.output


def test_no_findings_says_so_explicitly(monkeypatch):
    _patch(monkeypatch, [])
    r = runner.invoke(cli.app, ["audit", "contexts"])
    assert r.exit_code == 0, r.output
    assert "no interfaces with addresses are missing an IN_VRF edge" in r.output


def test_exits_zero_even_when_findings_are_reported(monkeypatch):
    row = {"device_uid": "d", "interface_uid": "d/if/e0", "interface_name": "e0", "address_count": 1}
    _patch(monkeypatch, [row])
    r = runner.invoke(cli.app, ["audit", "contexts"])
    assert r.exit_code == 0, r.output


def test_resolves_the_pointer_once_and_pins_the_read_to_it(monkeypatch):
    """The pointer is resolved once and bound as $snap."""
    session = _patch(monkeypatch, [], current=4242)
    r = runner.invoke(cli.app, ["audit", "contexts"])
    assert r.exit_code == 0, r.output
    assert session.pointer_calls == 1
    assert session.tx.calls == [(queries.AUDIT_INTERFACES_MISSING_CONTEXT, {"snap": 4242})]


def test_falls_back_to_the_live_sentinel_with_no_pointer(monkeypatch):
    session = _patch(monkeypatch, [], current=None)
    r = runner.invoke(cli.app, ["audit", "contexts"])
    assert r.exit_code == 0, r.output
    assert session.tx.calls == [(queries.AUDIT_INTERFACES_MISSING_CONTEXT, {"snap": "live"})]
