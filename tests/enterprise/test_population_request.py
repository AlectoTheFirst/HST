"""Durable request documents retain a bound population, never a live selector."""

import pytest

from hst.assessment.evaluation import RequestBody
from hst.assessment.population_request import (
    PopulationBindingError,
    bind_pinned_request,
    bind_request_population,
    pinned_inventory,
    replay_bound_request,
)
from hst.assessment.populations import InventorySnapshot
from hst.core.manifest import DeviceEntry, SectionOutcome, SourceEntry


def _request():
    return {
        "name": "web",
        "destination": "service",
        "source_context": "vrf:blue",
        "population": {"kind": "nautobot", "vrf_id": "blue"},
        "members": [{"name": "web", "addresses": ["198.51.100.10"]}],
        "condition": {"kind": "member", "member": "web"},
    }


def _inventory():
    return InventorySnapshot(
        "a" * 64,
        "nautobot",
        "complete",
        ({"id": "host", "namespace_id": "prod", "address": "192.0.2.10/24", "vrf_id": "blue"},),
    )


def test_submission_binding_persists_sources_and_replay_uses_saved_membership():
    bound = bind_request_population(_request(), _inventory())
    parsed = RequestBody.model_validate(bound.request)

    assert parsed.sources == ["192.0.2.10/32"]
    assert bound.request["population_artifact"]["digest"] == bound.artifact.digest
    assert parsed.model_dump()["population_complete"] is True
    assert parsed.model_dump()["population_scope"] == "nautobot:prod:blue"
    assert replay_bound_request(bound.request).artifact == bound.artifact


def test_unbound_selector_cannot_reach_request_evaluation_or_replay():
    RequestBody.model_validate(_request())
    with pytest.raises(PopulationBindingError, match="no population artifact"):
        replay_bound_request(_request())
    with pytest.raises(PopulationBindingError, match="literal request sources"):
        bind_request_population({**_request(), "sources": ["10.0.0.0/24"]}, _inventory())


def test_replay_revalidates_the_saved_population_scope_against_the_pinned_graph(monkeypatch):
    bound = bind_request_population({**_request(), "source_context": "vrf:live:blue"}, _inventory())
    monkeypatch.setattr(
        "hst.assessment.population_request.pathmod._read",
        lambda *_args, **_kwargs: [{"contexts": ["vrf:live:blue"]}],
    )
    snapshot = type("Snapshot", (), {"cts": 42})()

    assert (
        bind_pinned_request(None, object(), snapshot, bound.request)["population_scope"]
        == "nautobot:prod:blue"
    )
    with pytest.raises(PopulationBindingError, match="source_context"):
        bind_pinned_request(None, object(), snapshot, {**bound.request, "source_context": "vrf:other"})


def _pinned(monkeypatch, sources, devices):
    monkeypatch.setattr(
        "hst.assessment.population_request.pathmod._read",
        lambda *_args, **_kwargs: [{"id": "ip1", "address": "192.0.2.10/24"}],
    )
    monkeypatch.setattr("hst.assessment.population_request.manifest.digest_of", lambda *_args: "a" * 64)
    manifest = type("Manifest", (), {"sources": sources, "devices": devices})()
    return pinned_inventory(None, object(), type("Snapshot", (), {"cts": 42, "manifest": manifest})())


def _entry(source, status):
    return DeviceEntry(
        source=source,
        host="nautobot.example",
        outcome="collected",
        sections={"ipam:addresses": SectionOutcome(status=status)},
    )


def test_pinned_inventory_is_complete_when_ipam_was_read_by_a_renamed_nautobot_source(monkeypatch):
    sources = [SourceEntry(name="nautobot-prod", type="nautobot", status="ok", config_sha256="x")]
    for status in ("ok", "empty"):
        inventory = _pinned(monkeypatch, sources, [_entry("nautobot-prod", status)])
        assert inventory.status == "complete"


def test_pinned_inventory_is_incomplete_when_ipam_failed_or_was_not_recorded(monkeypatch):
    sources = [SourceEntry(name="nautobot-prod", type="nautobot", status="ok", config_sha256="x")]
    assert _pinned(monkeypatch, sources, [_entry("nautobot-prod", "failed")]).status == "incomplete"
    assert _pinned(monkeypatch, sources, [_entry("other", "ok")]).status == "incomplete"
