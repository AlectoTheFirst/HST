"""The application tools and the application_connection form of
impact_evaluate_service: catalog reads, resolution that is never saved, and
graph application-model objects reported as related evidence."""

from __future__ import annotations

import asyncio

import neo4j
import pytest
from tests.test_business_applications import one_connection_definition
from tests.twin_tools_fakes import FakeGraph, call, context, install

from hst.applications.service import save_definition
from hst.assessment import direct
from hst.assessment import service as assessment_service
from hst.assessment.store import MemoryAssessmentStore
from hst.twin_tools import catalogue_registry

REFERENCE = {"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test", "observation_floor_ms": None}


class CatalogStore(MemoryAssessmentStore):
    """An application catalog that refuses to save a resolution."""

    saved: list[dict]

    async def save_application_resolution(self, resolution: dict) -> dict:
        raise AssertionError("a catalogue tool saved a resolution record")


def _catalog(*definitions) -> CatalogStore:
    store = CatalogStore()
    for definition in definitions:
        asyncio.run(save_definition(store, definition, expected_revision=0, actor=1))
    return store


def _context(store):
    ctx = context()
    ctx.store = store
    return ctx


def _reference_rows(addresses: dict[str, tuple[list[str], list]]):
    """The reference read of GraphInventoryReader: uid to labels and bindings,
    in the shape the filtered collect returns."""

    def answer(params):
        found = addresses.get(params.get("uid"))
        if found is None:
            return []
        labels, bindings = found
        return [
            {
                "uid": params["uid"],
                "labels": labels,
                "bindings": bindings,
                "binding_count": len(bindings),
                "evidence": None,
            }
        ]

    return ("binding_count", answer)


_DNS_READY = _reference_rows(
    {"dns:web.corp": (["Obj", "DnsRecord"], [{"address": "10.0.0.5", "context": None}])}
)
_DEVICE_ONLY = _reference_rows({"dev:core1": (["Obj", "Device"], [])})
_RELATED = (
    "toLower($name)",
    [{"uid": "snow:bs-webshop", "labels": ["Obj", "BusinessService"], "name": "Webshop"}],
)


def _published(monkeypatch):
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: dict(REFERENCE))


# --- app_applications ----------------------------------------------------------------------


def test_list_mode_lists_the_catalog_and_filters_by_name(monkeypatch):
    install(monkeypatch, FakeGraph())
    other = one_connection_definition("dns", "dns:web.corp").model_copy(
        update={"id": "ledger", "name": "Ledger"}
    )
    store = _catalog(one_connection_definition("dns", "dns:web.corp"), other)

    failed, everything = call("app_applications", {"mode": "list"}, _context(store))
    _, filtered = call("app_applications", {"mode": "list", "name_contains": "SHOP"}, _context(store))
    _, limited = call("app_applications", {"mode": "list", "limit": 1}, _context(store))

    assert not failed, everything
    assert {item["id"] for item in everything["result"]["items"]} == {"webshop", "ledger"}
    assert everything["evidence"]["result"]["word"] == "stored record"
    stored = everything["result"]["items"][0]["evidence"]
    assert (stored["result"]["kind"], stored["result"]["word"]) == ("record", "stored record")
    assert stored["basis"] == "stored"
    assert (stored["result"]["answer"], stored["result"]["missing"]) == (None, [])
    assert everything["page"]["truncated"] is False
    assert [item["id"] for item in filtered["result"]["items"]] == ["webshop"]
    assert limited["page"]["truncated"] is True and limited["page"]["next_cursor"] is None


def test_get_mode_returns_the_definition_and_graph_objects_of_the_same_name_as_related(monkeypatch):
    graph = install(monkeypatch, FakeGraph([_RELATED]))
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))

    failed, envelope = call("app_applications", {"mode": "get", "application_id": "webshop"}, _context(store))

    assert not failed, envelope
    result = envelope["result"]
    assert result["definition"]["id"] == "webshop" and result["revision"] == 1
    assert result["connections"] is None and result["resolution"] is None
    assert result["evidence"]["basis"] == "declared"
    (related,) = result["related"]
    assert related["uid"] == "snow:bs-webshop" and related["label"] == "BusinessService"
    assert "application model" in related["reason"]
    assert graph.reads("toLower($name)")[0]["name"] == "Webshop"
    assert graph.reads("toLower($name)")[0]["snap"] == 4000


def test_get_mode_serves_an_old_stored_definition_without_choice_scope(monkeypatch):
    from hst.applications.yaml_format import definition_digest, normalized_document

    install(monkeypatch, FakeGraph([]))
    store = CatalogStore()
    stored = normalized_document(one_connection_definition("dns", "dns:web.corp"))
    stored["connections"] = [{**item, "choice_scope": "unspecified"} for item in stored["connections"]]
    asyncio.run(
        store.create_application_revision(
            definition=stored, digest=definition_digest(stored), created_by=1, expected_revision=0
        )
    )

    failed, envelope = call("app_applications", {"mode": "get", "application_id": "webshop"}, _context(store))

    assert not failed, envelope
    (connection,) = envelope["result"]["definition"]["connections"]
    assert "choice_scope" not in connection
    assert envelope["result"]["digest"] == definition_digest(stored)


def test_get_with_resolve_resolves_each_connection_and_writes_no_resolution_record(monkeypatch):
    install(monkeypatch, FakeGraph([_DNS_READY]))
    _published(monkeypatch)
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))

    failed, envelope = call(
        "app_applications", {"mode": "get", "application_id": "webshop", "resolve": True}, _context(store)
    )

    assert not failed, envelope
    result = envelope["result"]
    (connection,) = result["connections"]
    assert connection["readiness"] == "ready"
    assert connection["request"]["members"][0]["addresses"] == ["10.0.0.5"]
    assert connection["evidence"]["result"]["answer"] == "true"
    assert result["resolution"]["saved"] is False and result["resolution"]["ready"] is True
    assert result["resolution"]["snapshot"] == REFERENCE
    assert envelope["evidence"]["result"]["word"] == "resolved"
    assert asyncio.run(store.get_application_resolution(result["resolution"]["digest"])) is None


def test_an_unresolved_connection_is_not_established_with_its_issues_as_gaps(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE_ONLY]))
    _published(monkeypatch)
    store = _catalog(one_connection_definition("device", "dev:core1"))

    failed, envelope = call(
        "app_applications", {"mode": "get", "application_id": "webshop", "resolve": True}, _context(store)
    )

    assert not failed, envelope
    (connection,) = envelope["result"]["connections"]
    assert connection["readiness"] == "unresolved"
    codes = [m["code"] for m in connection["evidence"]["result"]["missing"]]
    assert "inventory-address-unavailable" in codes
    assert "inventory-read-incomplete" not in codes
    assert envelope["evidence"]["result"]["word"] == "unresolved"
    assert "inventory-address-unavailable" in {gap["code"] for gap in envelope["evidence"]["gaps"]}


def test_resolve_on_a_run_without_a_manifest_is_snapshot_not_published(monkeypatch):
    install(monkeypatch, FakeGraph())

    def unpublished(settings, value):
        raise ValueError("A published snapshot with an evidence manifest is required.")

    monkeypatch.setattr(assessment_service, "snapshot_reference", unpublished)
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))

    failed, error = call(
        "app_applications", {"mode": "get", "application_id": "webshop", "resolve": True}, _context(store)
    )

    assert failed and error["error"]["code"] == "snapshot_not_published"


def test_an_unknown_application_or_revision_is_not_found(monkeypatch):
    install(monkeypatch, FakeGraph())
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))

    for arguments in ({"application_id": "nothing"}, {"application_id": "webshop", "revision": 7}):
        failed, error = call("app_applications", {"mode": "get", **arguments}, _context(store))
        assert failed and error["error"]["code"] == "not_found"
        assert error["error"]["field"] == "application_id"


def test_a_store_that_cannot_be_read_is_engine_unavailable(monkeypatch):
    install(monkeypatch, FakeGraph())

    class Broken(MemoryAssessmentStore):
        async def list_applications(self, limit=100):
            raise OSError("connection refused")

    failed, error = call("app_applications", {"mode": "list"}, _context(Broken()))

    assert failed and error["error"]["code"] == "engine_unavailable"
    assert error["error"]["retryable"] is True


# --- app_find_affected ---------------------------------------------------------------------


def test_find_affected_lists_explicit_references_and_related_graph_objects(monkeypatch):
    related = (
        "UNWIND $uids AS target",
        [
            {
                "uid": "sreq:web",
                "labels": ["Obj", "ServiceRequirement"],
                "name": "web",
                "inventory_uid": "dns:web.corp",
            }
        ],
    )
    graph = install(monkeypatch, FakeGraph([related]))
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))

    failed, envelope = call(
        "app_find_affected", {"inventory_uids": ["dns:web.corp", "dev:x"]}, _context(store)
    )
    _, nothing = call("app_find_affected", {"inventory_uids": ["dev:x"]}, _context(store))

    assert not failed, envelope
    (match,) = envelope["result"]["applications"]
    assert match["application_id"] == "webshop"
    assert match["matched_inventory_uids"] == ["dns:web.corp"]
    assert envelope["result"]["complete"] is True
    assert envelope["evidence"]["complete"] is True
    assert envelope["evidence"]["absence"] == "not_recorded"
    assert any("absence is not proof" in u for u in envelope["evidence"]["unknowns"])
    assert envelope["result"]["related"][0]["uid"] == "sreq:web"
    assert graph.reads("UNWIND $uids AS target")[0]["uids"] == ["dns:web.corp", "dev:x"]
    assert nothing["result"]["applications"] == []
    assert nothing["evidence"]["result"]["word"] == "no record matches in the snapshot"


def test_find_affected_answers_when_the_related_graph_read_fails(monkeypatch):
    def timed_out(params):
        raise neo4j.exceptions.ClientError("the transaction timed out")

    install(monkeypatch, FakeGraph([("UNWIND $uids AS target", timed_out)]))
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))

    failed, envelope = call("app_find_affected", {"inventory_uids": ["dns:web.corp"]}, _context(store))

    assert not failed, envelope
    assert envelope["result"]["applications"][0]["application_id"] == "webshop"
    assert envelope["result"]["related"] == []
    assert any("were not read (ClientError)" in u for u in envelope["evidence"]["unknowns"])


def test_find_affected_answers_when_the_graph_driver_fails(monkeypatch):
    def unavailable(params):
        raise neo4j.exceptions.ServiceUnavailable("the database is not reachable")

    install(monkeypatch, FakeGraph([("UNWIND $uids AS target", unavailable)]))
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))

    failed, envelope = call("app_find_affected", {"inventory_uids": ["dns:web.corp"]}, _context(store))

    assert not failed, envelope
    assert envelope["result"]["applications"][0]["application_id"] == "webshop"
    assert envelope["result"]["related"] == []
    assert any("were not read (ServiceUnavailable)" in u for u in envelope["evidence"]["unknowns"])


# --- impact_evaluate_service, form: application_connection -----------------------------------

_CONNECTION = {"application": {"id": "webshop", "revision": 1}, "service_id": "shop", "connection_id": "web"}


def _evaluation():
    bucket = {"count": 0, "items": [], "truncated": False}
    return {
        "mode": "possible",
        "decided_change": {"loss": bucket, "gain": bucket},
        "open_change": {"loss": bucket, "gain": bucket},
        "open": {"before": bucket, "after": bucket},
        "passes": {"before": {**bucket, "count": 1}, "after": {**bucket, "count": 1}},
        "fails": {"before": bucket, "after": bucket},
        "evidence": {"count": 0, "items": [], "truncated": False},
        "missing_evidence": [],
        "gaps": [],
    }


def test_an_application_connection_evaluates_its_resolved_request_without_saving(monkeypatch):
    install(monkeypatch, FakeGraph([_DNS_READY]))
    _published(monkeypatch)
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))
    seen = {}

    def evaluate(settings, session, snap, **kwargs):
        seen.update(kwargs)
        return _evaluation()

    monkeypatch.setattr(direct, "evaluate_request", evaluate)

    failed, envelope = call(
        "impact_evaluate_service",
        {"form": "application_connection", "application_connection": _CONNECTION},
        _context(store),
    )

    assert not failed, envelope
    assert seen["requirement"] is None
    assert seen["request"]["members"][0]["addresses"] == ["10.0.0.5"]
    assert seen["request"]["sources"] == ["10.9.0.0/24"]
    block = envelope["result"]["application_connection"]
    assert block["readiness"] == "ready" and block["resolution_saved"] is False
    assert block["application"]["id"] == "webshop" and block["application"]["revision"] == 1
    assert envelope["evidence"]["result"]["word"] == "passes"


def test_an_unresolved_application_connection_is_not_evaluated(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE_ONLY]))
    _published(monkeypatch)
    store = _catalog(one_connection_definition("device", "dev:core1"))

    def evaluate(*args, **kwargs):
        raise AssertionError("an unresolved connection was evaluated")

    monkeypatch.setattr(direct, "evaluate_request", evaluate)

    failed, envelope = call(
        "impact_evaluate_service",
        {"form": "application_connection", "application_connection": _CONNECTION},
        _context(store),
    )

    assert not failed, envelope
    assert envelope["evidence"]["result"]["word"] == "not decided"
    assert envelope["result"]["application_connection"]["readiness"] == "unresolved"
    assert "inventory-address-unavailable" in {gap["code"] for gap in envelope["evidence"]["gaps"]}


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"application": {"id": "webshop", "revision": 1, "digest": "f" * 64}}, "conflict"),
        ({"service_id": "other"}, "not_found"),
        ({"connection_id": "other"}, "not_found"),
        ({"application": {"id": "webshop", "revision": 2}}, "not_found"),
    ],
)
def test_an_application_connection_that_does_not_match_the_catalog_is_refused(monkeypatch, change, code):
    install(monkeypatch, FakeGraph())
    _published(monkeypatch)
    store = _catalog(one_connection_definition("dns", "dns:web.corp"))

    failed, error = call(
        "impact_evaluate_service",
        {"form": "application_connection", "application_connection": {**_CONNECTION, **change}},
        _context(store),
    )

    assert failed and error["error"]["code"] == code
    assert error["error"]["field"] == "application_connection"


def test_the_application_connection_form_publishes_its_required_fields():
    schema = catalogue_registry().get("impact_evaluate_service").input_schema()

    assert schema["properties"]["form"]["enum"] == ["requirement", "request", "application_connection"]
    required = {}
    for branch in schema["oneOf"]:
        variant = schema["$defs"][branch["$ref"].rsplit("/", 1)[-1]]
        required[variant["properties"]["form"]["const"]] = sorted(variant["required"])
    assert required["application_connection"] == ["application_connection", "form"]
