"""The L2 chain and VSX transit reads over a database of kept runs."""

from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path
from typing import Any
from unittest import mock

import neo4j
import pytest

import hst.path as path
from hst.core import cycle as cyclemod
from hst.core import db
from hst.core.snapshot import NoRun
from hst.path import vsx

trace = importlib.import_module("hst.path.trace")


def _forked_block(query: str) -> str:
    start = query.index("forked:")
    return query[start : query.index("} AS hop", start)]


# --- the L2 chain ---------------------------------------------------------------------------


def test_the_l2_chain_anchors_seek_at_the_pinned_run_and_its_paths_carry_no_run_guard():
    q = trace._L2_CHAIN_QUERY
    assert "MATCH (a:Obj {uid: $a, collection_ts: $snap}), (z:Obj {uid: $z, collection_ts: $snap})" in q
    assert q.count("collection_ts") == 2
    assert "coalesce(" not in q.split("UNWIND", 1)[0]


def test_forked_stops_at_the_first_path():
    block = _forked_block(trace._L2_CHAIN_QUERY)
    assert "MATCH q = shortestPath((alt)-[:ON|CONNECTED_TO*..12]-(z))" in block
    assert "MATCH q = (alt)-[" not in block


def test_forked_answers_a_neighbour_that_is_z_in_its_own_branch():
    # shortestPath raises when its start and end are the same node, so the
    # neighbour that is z never reaches the search: it has its own branch, and
    # the search branch drops it in the MATCH that binds alt
    block = _forked_block(trace._L2_CHAIN_QUERY)
    equal, search = block.split("} OR EXISTS {")
    assert "WHERE alt = z AND az._retired_at IS NULL" in equal
    assert "shortestPath" not in equal
    bind, rest = search.split("MATCH q = shortestPath", 1)
    assert "WHERE alt <> z" in bind
    assert "alt <> z" not in rest


# --- VSX transit ----------------------------------------------------------------------------


def test_the_vsx_transit_path_carries_no_run_guard_past_its_anchor():
    assert "MATCH (a:Obj {uid: $start, collection_ts: $snap})" in vsx.QUERY
    assert vsx.QUERY.count("collection_ts") == 1
    assert "coalesce(n.collection_ts" not in vsx.QUERY
    assert "coalesce(r.collection_ts" not in vsx.QUERY


def test_the_vsx_edge_check_seeks_on_its_relationship_indexes():
    assert (
        "CREATE INDEX connected_to_source_cts IF NOT EXISTS "
        "FOR ()-[r:CONNECTED_TO]-() ON (r.source, r.collection_ts)" in db.CONSTRAINT_STATEMENTS
    )
    assert (
        "CREATE INDEX bridged_to_source_cts IF NOT EXISTS "
        "FOR ()-[r:BRIDGED_TO]-() ON (r.source, r.collection_ts)" in db.CONSTRAINT_STATEMENTS
    )
    q = vsx.VSX_EDGES
    assert (
        "MATCH (:Obj {collection_ts: $snap})-[r:CONNECTED_TO]->()\n"
        "  WHERE r.source = 'vsx-warp' AND r.collection_ts = $snap" in q
    )
    assert (
        "MATCH (:Obj {collection_ts: $snap})-[r:BRIDGED_TO]->()\n"
        "  WHERE r.source = 'vsx-bridge' AND r.collection_ts = $snap" in q
    )


class _Reads:
    """Answers each query by its text and records what was read."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.queries: list[str] = []

    def __call__(self, _session: Any, query: str, **params: Any) -> Any:
        self.queries.append(query)
        return self.answers.get(query, [])


def _transit_row(target: str) -> dict[str, Any]:
    return {
        "target": {"if_uid": target},
        "nodes": [{"uid": "if:start"}, {"uid": target}],
        "edges": [{"type": "CONNECTED_TO", "source": "vsx-warp"}],
    }


def test_resolve_skips_the_transit_read_in_a_run_without_vsx_edges(monkeypatch):
    reads = _Reads({vsx.VSX_EDGES: []})
    monkeypatch.setattr(path, "_read", reads)
    assert vsx.resolve(None, "if:start", "10.0.0.1") == (None, [], None)
    assert vsx.QUERY not in reads.queries


def test_a_warp_egress_is_still_reported_in_a_run_without_vsx_edges(monkeypatch):
    reads = _Reads({vsx.VSX_EDGES: [], vsx.EGRESS: [{"kind": "warp", "complete": False}]})
    monkeypatch.setattr(path, "_read", reads)
    _, _, error = vsx.resolve(None, "if:start", None)
    assert error == "warp egress has no unique observed forwarding path to the next context"
    assert vsx.QUERY not in reads.queries


def test_resolve_reads_the_transit_paths_in_a_run_with_vsx_edges(monkeypatch):
    reads = _Reads({vsx.VSX_EDGES: [{"present": 1}], vsx.QUERY: [_transit_row("if:vs7")]})
    monkeypatch.setattr(path, "_read", reads)
    target, crossings, error = vsx.resolve(None, "if:start", None)
    assert target == {"if_uid": "if:vs7"} and crossings == [] and error is None


class _Tx:
    def __init__(self, session: _CountingSession) -> None:
        self.session = session

    def run(self, query: str, **params: Any) -> Any:
        self.session.runs.append(query)
        # a run without VSX edges: every read answers nothing
        return mock.Mock(data=lambda: [])


class _CountingSession:
    def __init__(self) -> None:
        self.runs: list[str] = []

    def execute_read(self, work: Any, /) -> Any:
        return work(_Tx(self))


def test_the_vsx_edge_check_is_read_once_per_pinned_session():
    inner = _CountingSession()
    pinned = path.CycleSession(inner, 1_700_000_000_000)
    for start in ("if:a", "if:b", "if:c"):
        vsx.resolve(pinned, start, None)
    assert inner.runs.count(vsx.VSX_EDGES) == 1
    assert vsx.QUERY not in inner.runs


# --- a trace with no published run ---------------------------------------------------------


def test_a_trace_on_a_database_with_no_published_run_answers_no_run(monkeypatch):
    monkeypatch.setattr(cyclemod, "current_ts_or_none", lambda session: None)
    session = mock.MagicMock(spec=neo4j.Session)
    with pytest.raises(NoRun, match="no run is published yet"):
        path.trace(session, "10.0.0.1", "10.0.0.2")
    # nothing was read with the LIVE_SNAP binding
    session.execute_read.assert_not_called()


def test_a_trace_on_a_database_with_a_run_is_pinned_to_it(monkeypatch):
    monkeypatch.setattr(cyclemod, "current_ts_or_none", lambda session: 1_700_000_000_000)
    session = mock.MagicMock(spec=neo4j.Session)
    pinned = trace._pinned_session(session)
    assert isinstance(pinned, path.CycleSession) and pinned.cts == 1_700_000_000_000


def test_a_session_that_is_not_a_database_keeps_the_live_sentinel(monkeypatch):
    monkeypatch.setattr(cyclemod, "current_ts_or_none", lambda session: None)
    fake = object()
    assert trace._pinned_session(fake) is fake


def test_a_change_simulation_overlay_on_a_database_with_no_run_answers_no_run(monkeypatch):
    # OverlaySession copies the missing pin as cts = None; read as a pin, it
    # would bind $snap to null and every anchor would match nothing
    from hst.app.fw_overlay_read import OverlaySession

    monkeypatch.setattr(cyclemod, "current_ts_or_none", lambda session: None)
    session = mock.MagicMock(spec=neo4j.Session)
    overlaid = OverlaySession(session, mock.Mock())
    assert overlaid.cts is None
    with pytest.raises(NoRun):
        trace._pinned_session(overlaid)
    with pytest.raises(NoRun):
        path.trace(overlaid, "10.0.0.1", "10.0.0.2")
    session.execute_read.assert_not_called()


def test_an_impact_overlay_on_a_database_with_no_run_answers_no_run(monkeypatch):
    from hst.impact.evaluate import _OverlaySession

    monkeypatch.setattr(cyclemod, "current_ts_or_none", lambda session: None)
    overlaid = _OverlaySession(mock.MagicMock(spec=neo4j.Session), mock.Mock())
    assert not hasattr(overlaid, "cts")
    with pytest.raises(NoRun):
        trace._pinned_session(overlaid)


def test_an_overlay_on_a_pinned_run_keeps_its_pin():
    from hst.app.fw_overlay_read import OverlaySession

    inner = path.CycleSession(mock.MagicMock(spec=neo4j.Session), 1_700_000_000_000)
    overlaid = OverlaySession(inner, mock.Mock())
    assert trace._pinned_session(overlaid) is overlaid


def test_an_overlay_on_a_fake_session_keeps_the_live_sentinel(monkeypatch):
    from hst.app.fw_overlay_read import OverlaySession

    monkeypatch.setattr(cyclemod, "current_ts_or_none", lambda session: None)
    overlaid = OverlaySession(_CountingSession(), mock.Mock())
    assert trace._pinned_session(overlaid) is overlaid


def test_the_path_command_reports_no_run(monkeypatch):
    from contextlib import contextmanager

    from typer.testing import CliRunner

    from hst import cli

    @contextmanager
    def fake_session(settings, access_mode=None):
        yield object()

    def no_run(*args: Any, **kwargs: Any) -> Any:
        raise NoRun()

    monkeypatch.setattr(cli.dbmod, "session", fake_session)
    monkeypatch.setattr(path, "trace", no_run)
    result = CliRunner().invoke(cli.app, ["path", "10.0.0.1", "10.0.0.2"])
    assert result.exit_code == 1
    assert "no run is published yet" in result.output


# --- no uid anchor without a label anywhere -----------------------------------------------

_UNLABELLED_UID = re.compile(r"\(\w*\s*\{uid:\s*\$")


def test_no_query_in_the_source_tree_matches_a_uid_on_a_node_without_a_label():
    root = Path(path.__file__).parents[1]
    found = []
    for file in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(file.read_text())):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "MATCH" in node.value
                and _UNLABELLED_UID.search(node.value)
            ):
                found.append(str(file.relative_to(root)))
    assert found == []
