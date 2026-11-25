"""Assessment core: request parsing, incomplete populations on failure trials,
open verification sides and the time verification measures age at."""

from copy import deepcopy
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from tests.test_assessment_service_semantic_integration import REQUEST, inputs
from tests.test_assessment_service_semantic_integration import contexts as contexts
from tests.test_impact_evaluate import B
from tests.test_impact_evaluate import ev as engine
from tests.test_impact_evaluate import graph as graph

from hst.assessment import evaluation as ev
from hst.assessment import failure_evidence, service
from hst.assessment.request_document import request_document, service_fields
from hst.assessment.search import HOLDS, UNKNOWN
from hst.assessment.verification import observation_coverage
from hst.core.manifest import DeviceEntry, SnapshotManifest, SourceEntry
from hst.core.model import SectionOutcome
from hst.results.project import project_engine
from hst.results.words import ANSWER_OF_VALUE

_REAL_CONTEXT = service.EvaluationContext


def _body(**changes):
    return ev.RequestBody(**{**deepcopy(REQUEST), **changes})


@pytest.mark.parametrize("bad", ["10.0.1.300", "any", "10.0.0.0/33", "10.0.0.9-10.0.0.1", "host.example"])
def test_an_unreadable_source_beside_a_readable_one_is_a_bad_request(bad):
    with pytest.raises(HTTPException) as caught:
        ev._request_from_body(_body(sources=["10.0.0.0/24", bad]))
    assert caught.value.status_code == 400 and bad in caught.value.detail


def test_an_unreadable_member_address_is_a_bad_request():
    member = {"name": "app", "addresses": ["192.0.2.10", "192.0.2.999"]}
    with pytest.raises(HTTPException) as caught:
        ev._request_from_body(_body(members=[member]))
    assert "192.0.2.999" in caught.value.detail


def test_readable_specs_keep_their_whole_address_set():
    req = ev._request_from_body(_body(sources=["10.0.0.0/25", "10.0.0.128/25", "10.0.1.5-10.0.1.9"]))
    assert ev._cidrs(req.sources) == ev._cidrs(ev._intervals(["10.0.0.0/24", "10.0.1.5-10.0.1.9"]))


@pytest.mark.parametrize("proto", ["tcp", "tcp_udp", "all", "!tcp", "6,17"])
def test_request_document_protocol_round_trips(proto):
    service_ = ev._service_of(proto, "443", None)
    doc = service_fields(service_)
    assert ev._service_of(doc["proto"], doc["port"], doc["source_port"]) == service_


def test_request_document_of_a_two_protocol_request_is_accepted_again():
    req = ev._request_from_body(_body(proto="tcp_udp"))
    again = ev._request_from_body(ev.RequestBody(**request_document(req)))
    assert again.service == req.service and again.service.proto == frozenset({6, 17})


@pytest.mark.parametrize("proto", ["tcp,", ",", "tcp,bogus"])
def test_a_protocol_list_with_an_empty_or_unknown_entry_is_a_bad_request(proto):
    with pytest.raises(HTTPException):
        ev._service_of(proto, None, None)


def _resilience(monkeypatch, complete):
    monkeypatch.setattr(failure_evidence, "validate_failure_evidence", lambda *args: {})
    document = {**deepcopy(REQUEST), "population_complete": complete}
    monkeypatch.setattr(service.EvaluationContext, "request_document", document, raising=False)
    data = inputs("resilience")
    data["snapshot_refs"] = [{"snapshot": "1"}]
    data["analysis"]["targets"] = [{"id": "b", "kind": "device", "uid": B}]
    data["analysis"]["domains"] = []
    return service.execute(None, data)


def test_a_failure_trial_over_an_incomplete_population_is_not_established(graph, contexts, monkeypatch):
    result = _resilience(monkeypatch, False)
    trial = next(t for t in result["trials"] if t["candidates"] == ["b"])
    assert trial["result"]["answer"] == ANSWER_OF_VALUE[UNKNOWN]
    assert trial["evaluation"]["isolated"] is False
    assert "SOURCE_POPULATION_INCOMPLETE" in trial["evaluation"]["reason"]
    assert result["survives_all_single_failures"] is False


def test_a_failure_trial_over_a_complete_population_stays_decided(graph, contexts, monkeypatch):
    result = _resilience(monkeypatch, True)
    trial = next(t for t in result["trials"] if t["candidates"] == ["b"])
    assert trial["result"]["answer"] == ANSWER_OF_VALUE[HOLDS]


@pytest.fixture
def verify_inputs(graph, contexts, monkeypatch):
    """A verification whose observation runs the engine on the collected
    model and the context's own population downgrade."""
    seen = {}

    def evaluate(self, intents, mode, request=None):
        answer = engine.answer(self.network, self.request, mode)
        result = {
            "outcomes": {"after": ev.outcome(answer)},
            "evidence": {"count": 0, "items": []},
            "gaps": [],
            "snapshot": self.reference["snapshot"],
        }
        _REAL_CONTEXT._population_result(self, result, seen["declaration"])
        return result

    def coverage(*args, **kwargs):
        seen["as_of"] = kwargs.get("as_of")
        return {"qualifies": True}

    monkeypatch.setattr(service.EvaluationContext, "evaluate", evaluate)
    monkeypatch.setattr(service, "observation_floor", lambda record: 2000)
    monkeypatch.setattr(service, "observation_coverage", coverage)
    monkeypatch.setattr(service, "_configuration_realization", lambda *args: {"state": "not-decided"})
    data = inputs("verify")
    data["snapshot_refs"] = [{"snapshot": "1"}]
    data["deployment"] = {"deployed_at": "1970-01-01T00:00:01Z"}

    def predicted(complete):
        seen["declaration"] = {"population_complete": complete}
        request = ev._request_from_body(ev.RequestBody(**REQUEST))
        body = {
            "outcomes": {"after": ev.outcome(engine.answer(contexts[0]["1"], request, "possible"))},
            "constraints": {"desired": HOLDS, "protected": {}, "verdict": HOLDS, "verified": True},
        }
        _REAL_CONTEXT._population_result(None, body, seen["declaration"])
        return project_engine(body, "possible")

    return data, predicted, seen


def test_verification_of_two_open_sides_with_empty_open_lists_is_insufficient(verify_inputs):
    data, predicted, _ = verify_inputs
    data["prediction"] = predicted(False)
    result = service.execute(None, data)
    assert result["observed"]["outcomes"]["after"]["open"] == []
    assert result["state"] == "insufficient-evidence"


def test_verification_of_a_decided_prediction_and_an_open_observation_is_insufficient(verify_inputs):
    data, predicted, seen = verify_inputs
    data["prediction"] = predicted(True)
    seen["declaration"] = {"population_complete": False}
    assert service.execute(None, data)["state"] == "insufficient-evidence"


def test_verification_of_two_decided_sides_stays_agreement(verify_inputs):
    data, predicted, _ = verify_inputs
    data["prediction"] = predicted(True)
    assert service.execute(None, data)["state"] == "agreement"


def test_verification_measures_age_at_submission_when_recorded(verify_inputs):
    data, predicted, seen = verify_inputs
    data["prediction"] = predicted(True)
    service.execute(None, data)
    assert seen["as_of"] is None
    data["submitted_at"] = "2026-11-13T10:00:00+00:00"
    service.execute(None, data)
    assert seen["as_of"] == "2026-11-13T10:00:00+00:00"


_OBSERVED = datetime(2026, 9, 8, 10, 0, tzinfo=UTC)


def _manifest():
    observed_ms = int(_OBSERVED.timestamp() * 1000)
    device = DeviceEntry(
        source="s",
        host="edge",
        outcome="collected",
        raw_sha256="same",
        fetch_started_ms=observed_ms,
        device_uids=["edge"],
        expected_sections=["rules"],
        sections={"rules": SectionOutcome(status="ok")},
    )
    return SnapshotManifest(
        snapshot_key=1,
        kind="full",
        opened="2026-09-08T10:00:00+00:00",
        published="2026-09-08T10:01:00+00:00",
        estate="test",
        devices=[device],
        sources=[SourceEntry(name="s", type="vyos", status="ok", config_sha256="same")],
    )


@pytest.mark.parametrize(
    ("submitted_at", "state"),
    [
        (None, "agreement"),
        ("2026-09-08T10:10:00+00:00", "agreement"),
        ("2026-09-08T12:00:00+00:00", "insufficient-evidence"),
    ],
)
def test_observation_age_is_measured_at_submission_on_the_collected_manifest(
    verify_inputs, monkeypatch, submitted_at, state
):
    data, predicted, _ = verify_inputs
    monkeypatch.setattr(service, "observation_coverage", observation_coverage)
    opened = service.EvaluationContext.__init__

    def with_manifest(self, *args, **kwargs):
        opened(self, *args, **kwargs)
        self.snapshot.manifest = _manifest()

    monkeypatch.setattr(service.EvaluationContext, "__init__", with_manifest)
    data["prediction"] = predicted(True)
    data["definition"]["freshness_s"] = 3600
    data["deployment"] = {"deployed_at": "2026-09-08T09:00:00+00:00"}
    if submitted_at is not None:
        data["submitted_at"] = submitted_at
    result = service.execute(None, data)
    assert result["state"] == state
    reasons = [r for m in result["observation_coverage"]["missing"] for r in m["reasons"]]
    assert ("observation-expired" in reasons) == (state == "insufficient-evidence")


def test_repair_default_scope_reads_a_stored_protocol_list_one_value_per_protocol(graph, contexts):
    from tests.test_impact_evaluate import _firewall
    from tests.test_path_trace import _rule

    _firewall(graph, B, "rb:b", [_rule(uid="deny", action="drop")])
    data = inputs("repair")
    data["definition"]["request"] = {**deepcopy(REQUEST), "proto": "6,17"}
    del data["analysis"]["scope"]
    result = service.execute(None, data)
    assert result["scope"]["protocols"] == ["17", "6"]
