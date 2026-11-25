"""Exact result bounds survive persistence-oriented evaluation."""

from tests.app import test_impact_api as fixture

from hst.assessment import evaluation as ev
from hst.core import Settings
from hst.core.snapshot import Snapshot
from hst.path import pinned


def test_full_evaluation_preserves_region_dimensions_and_verdict(monkeypatch):
    graph = fixture.evfix.Graph()
    fixture._wire(monkeypatch, graph)
    settings = Settings(_env_file=None)
    session = pinned(fixture._FakeGraphSession(), Snapshot(2000, settings))
    request = ev._request_from_body(ev.RequestBody(**fixture.REQUEST))
    answer = ev.evaluate_change(session, request=request, intents=[], detail=True)
    assert answer["outcomes"]["after"]["verdict"] in {"holds", "does-not-hold", "not-established"}
    assert answer["evidence"]["count"] == len(answer["evidence"]["items"])
    assert not answer["evidence"]["truncated"]
    assert all("request_region" in item for item in answer["evidence"]["items"])
    assert all(item["request_region"]["src"] for item in answer["evidence"]["items"])
    legacy = ev.evaluate_change(session, request=request, intents=[])
    assert "outcomes" not in legacy
    assert all("request_region" not in item for item in legacy["evidence"]["items"])


def test_isolation_needs_empty_upper_bound(monkeypatch):
    from hst.impact.evaluate import Answer
    from hst.path.addrsets import _intervals

    request = ev._request_from_body(ev.RequestBody(**fixture.REQUEST))
    uncertain = Answer(request, "possible", (), request.sources, {})
    assert ev.outcome(uncertain)["isolated"] is False
    denied = Answer(request, "possible", (), (), {})
    assert ev.outcome(denied)["isolated"] is True
    mixed = Answer(request, "possible", tuple(_intervals(["10.0.0.1"])), request.sources, {})
    assert ev.outcome(mixed)["verdict"] == "not-established"
