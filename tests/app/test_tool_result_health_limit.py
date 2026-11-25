"""Large shared snapshot health must not turn small queries into tool errors."""

import json

import pytest
from tests.twin_tools_fakes import FakeGraph, context, install

from hst.app.agent.tools import cap_model_copy, unframe
from hst.app.agent.traffic import MAX_RESULT_CHARS
from hst.core import cycle
from hst.twin_tools import catalogue_registry, query


def _freshness():
    return {
        "approximate": False,
        "truncated": False,
        "devices": [
            {
                "source": "nxos",
                "host": f"switch-{i}",
                "outcome": "partial",
                "carried": True,
                "carried_reason": "section_failed",
                "last_seen": 3000,
                "tables": {
                    f"table-{n}": {"status": "collected", "observed_ms": 3000, "age_ms": 1000}
                    for n in range(16)
                },
            }
            for i in range(cycle.FRESHNESS_CAP)
        ],
    }


@pytest.mark.parametrize("surface", ["drawer", "changesim", "assessment_qa", "mcp"])
@pytest.mark.parametrize("row_count", [0, 1, 500])
def test_query_with_large_run_health_keeps_results_and_provenance(monkeypatch, surface, row_count):
    freshness = _freshness()
    assert len(json.dumps(freshness)) > MAX_RESULT_CHARS
    monkeypatch.setattr(cycle, "freshness", lambda snapshot: freshness)
    install(
        monkeypatch,
        FakeGraph([(cycle.RUN_STATUS, [{"degraded": True, "sources_failed": ["nxos"]}])]),
    )
    table = {
        "columns": ["uid", "description"],
        "data": [[f"dev:{i}", "x" * 1000] for i in range(row_count)],
        "truncated": False,
    }
    monkeypatch.setattr(query, "run_readonly", lambda *args, **kwargs: table)
    ctx = context()
    ctx.surface = surface
    outcome = catalogue_registry().invoke(
        ctx,
        "query_cypher",
        {"query": "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap RETURN d.uid"},
    )

    assert not outcome.is_error, outcome.model_text
    original = json.loads(outcome.ui_text)
    model_text = unframe(outcome.model_text)
    body = json.loads(model_text)
    assert original["snapshot"]["run"]["freshness"] == freshness
    assert outcome.provenance.run == original["snapshot"]["run"]
    assert body["provenance"] == original["provenance"]
    assert body["snapshot"]["id"] == "4000"
    assert body["snapshot"]["run"]["degraded"] is True
    assert body["snapshot"]["run"]["sources_failed"] == ["nxos"]
    assert body["evidence"] == original["evidence"]
    if surface == "mcp":
        assert model_text == outcome.ui_text
        return

    assert len(model_text) <= MAX_RESULT_CHARS
    assert body["output_truncated"] is True
    kept_health = body["snapshot"]["run"]["freshness"]
    assert kept_health["truncated"] is True
    assert kept_health["approximate"] is False
    kept = len(kept_health["devices"])
    assert 0 < kept < len(freshness["devices"])
    assert kept_health["devices"] == freshness["devices"][:kept]
    assert any("snapshot.run.freshness.devices" in w for w in body["warnings"])
    assert body["result"]["columns"] == table["columns"]
    assert body["result"]["truncated"] is False
    assert body["result"]["pinned"] is True
    if row_count < 500:
        assert body["result"] == original["result"]
        assert body["page"] == original["page"]
        assert not any("narrow the request" in w for w in body["warnings"])
    else:
        rows = body["result"]["data"]
        assert 0 < len(rows) < row_count
        assert rows == table["data"][: len(rows)]


def test_small_health_is_unchanged_when_only_rows_need_trimming():
    run = {"degraded": True, "sources_failed": ["nxos"], "freshness": {"devices": []}}
    envelope = {
        "snapshot": {"id": "4000", "run": run},
        "provenance": {},
        "result": {"rows": ["x" * 1000] * 500},
        "warnings": [],
    }
    body = json.loads(cap_model_copy(json.dumps(envelope)))
    assert body["snapshot"]["run"] == run


def test_health_truncation_does_not_mark_a_complete_result_page_as_incomplete():
    envelope = {
        "snapshot": {"id": "4000", "run": {"degraded": True, "freshness": _freshness()}},
        "provenance": {"tool": "inventory_list"},
        "result": {"items": [{"uid": "dev:one"}], "count": 1},
        "page": {"limit": 50, "next_cursor": None, "truncated": False},
        "warnings": ["An existing warning."],
    }
    body = json.loads(cap_model_copy(json.dumps(envelope)))
    assert body["result"] == envelope["result"]
    assert body["page"] == envelope["page"]
    assert body["warnings"][0] == "An existing warning."
    assert not any("page.next_cursor" in w for w in body["warnings"])


def test_large_failed_source_list_keeps_degraded_flag_and_records_omissions():
    sources = [f"source-{i}-" + "x" * 1000 for i in range(150)]
    envelope = {
        "snapshot": {"id": "4000", "run": {"degraded": True, "sources_failed": sources}},
        "provenance": {},
        "result": {"count": 7},
        "warnings": [],
    }
    text = cap_model_copy(json.dumps(envelope))
    body = json.loads(text)
    assert len(text) <= MAX_RESULT_CHARS
    assert body["result"] == {"count": 7}
    run = body["snapshot"]["run"]
    assert run["degraded"] is True
    assert run["output_truncated"] is True
    kept = len(run["sources_failed"])
    assert 0 < kept < len(sources)
    assert run["sources_failed"] == sources[:kept]
    assert f"snapshot.run.sources_failed lists {kept} of 150" in body["warnings"][0]
