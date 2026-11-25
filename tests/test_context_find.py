"""`hst context find`: name-to-forwarding-context resolution. A name that
matches more than one context prints every match."""

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
    """queries.resolve_context binds $name/$domain through `parameters=`."""

    def __init__(self, rows):
        self._rows = rows
        self.calls = []

    def run(self, query, parameters=None):
        self.calls.append((query, parameters))
        return FakeResult(self._rows)


class FakeSession:
    """Mirrors execute_read(work, *args) the way tests/test_mcp_server.py does."""

    def __init__(self, tx, current=None):
        self._tx = tx
        self._current = current
        self.pointer_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        # the autocommit pointer read core.cycle.current_ts_or_none issues once,
        # before the managed resolve_context read
        self.pointer_calls += 1
        rows = [{"current": self._current}] if self._current is not None else []
        return FakeResult(rows)

    def execute_read(self, work, *args, **kwargs):
        return work(self._tx, *args, **kwargs)


def _patch(monkeypatch, rows, current=None):
    tx = FakeTx(rows)
    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(cli.dbmod, "session", lambda settings: FakeSession(tx, current=current))
    return tx


def _row(**over):
    row = {
        "uid": "vrf:dev:a1:CORP",
        "name": "CORP",
        "table_id": "CORP",
        "is_global": False,
        "rd": "65000:1",
        "domains": ["campus"],
        "devices": ["dev:a1"],
    }
    row.update(over)
    return row


def test_single_match_prints_one_line_and_no_trailer(monkeypatch):
    _patch(monkeypatch, [_row()])
    r = runner.invoke(cli.app, ["context", "find", "CORP"])
    assert r.exit_code == 0, r.output
    assert "vrf:dev:a1:CORP" in r.output
    assert "table=CORP" in r.output
    assert "campus" in r.output
    assert "dev:a1" in r.output
    assert "contexts match" not in r.output


def test_multiple_matches_get_a_trailer_naming_the_narrowing_options(monkeypatch):
    rows = [
        _row(uid="vrf:dev:a1:default", table_id="default", domains=[], devices=["dev:a1"]),
        _row(uid="vrf:dev:b1:default", table_id="default", domains=[], devices=["dev:b1"]),
    ]
    _patch(monkeypatch, rows)
    r = runner.invoke(cli.app, ["context", "find", "default"])
    assert r.exit_code == 0, r.output
    assert "vrf:dev:a1:default" in r.output
    assert "vrf:dev:b1:default" in r.output
    assert "2 contexts match: narrow with --domain or use the uid" in r.output


def test_no_match_is_reported_explicitly(monkeypatch):
    _patch(monkeypatch, [])
    r = runner.invoke(cli.app, ["context", "find", "nope"])
    assert r.exit_code == 0, r.output
    assert "no context named 'nope' found" in r.output


def test_no_match_mentions_the_domain_filter_that_was_applied(monkeypatch):
    _patch(monkeypatch, [])
    r = runner.invoke(cli.app, ["context", "find", "nope", "--domain", "campus"])
    assert r.exit_code == 0, r.output
    assert "no context named 'nope' found" in r.output
    assert "campus" in r.output


def test_domain_option_narrows_by_binding_the_query_parameter(monkeypatch):
    tx = _patch(monkeypatch, [_row()])
    r = runner.invoke(cli.app, ["context", "find", "CORP", "--domain", "campus"])
    assert r.exit_code == 0, r.output
    # snap is bound too: no cycle has run against this fake, so the pointer read
    # comes back empty and the guard falls back to the live sentinel.
    assert tx.calls[0][1] == {"name": "CORP", "domain": "campus", "snap": "live"}


def test_omitting_domain_binds_a_null_parameter_not_a_missing_one(monkeypatch):
    tx = _patch(monkeypatch, [_row()])
    r = runner.invoke(cli.app, ["context", "find", "CORP"])
    assert r.exit_code == 0, r.output
    assert tx.calls[0][1] == {"name": "CORP", "domain": None, "snap": "live"}


def test_resolves_the_pointer_once_and_pins_the_read_to_it(monkeypatch):
    """`resolve_context` pins to the resolved run, as every other reader does:
    $snap binds the resolved collection_ts, not the live sentinel, once a cycle
    has run."""
    tx = _patch(monkeypatch, [_row()], current=4242)
    r = runner.invoke(cli.app, ["context", "find", "CORP"])
    assert r.exit_code == 0, r.output
    assert tx.calls[0][1] == {"name": "CORP", "domain": None, "snap": 4242}


def test_global_contexts_are_marked(monkeypatch):
    _patch(monkeypatch, [_row(uid="vrf:dev:a1:default", table_id="default", is_global=True)])
    r = runner.invoke(cli.app, ["context", "find", "default"])
    assert r.exit_code == 0, r.output
    assert "global" in r.output


def test_exits_zero_even_with_multiple_ambiguous_matches(monkeypatch):
    rows = [_row(uid="vrf:dev:a1:default"), _row(uid="vrf:dev:b1:default")]
    _patch(monkeypatch, rows)
    r = runner.invoke(cli.app, ["context", "find", "default"])
    assert r.exit_code == 0, r.output
