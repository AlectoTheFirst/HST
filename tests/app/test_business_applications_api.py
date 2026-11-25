import copy

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore

from hst.assessment.store import MemoryAssessmentStore

YAML = """\
schema_version: 1
kind: BusinessApplication
id: checkout-production
name: Checkout
groups:
  - id: clients
    name: Clients
    members: [{id: client, address: 192.0.2.1}]
  - id: servers
    name: Servers
    members: [{id: server, address: 198.51.100.10}]
connections:
  - id: web
    name: Web
    source: clients
    destination: servers
    protocol: tcp
    destination_ports: [443]
    destination_condition: {kind: member, member: server}
services:
  - id: frontend
    name: Frontend
    connection_ids: [web]
"""


class ApplicationFakeStore(MemoryAssessmentStore, FakeStore):
    pass


@pytest.fixture
def store():
    return ApplicationFakeStore()


async def test_import_preview_commit_history_exact_export_and_noop(client, store):
    assert (await client.get("/api/business-applications")).status_code == 401
    await login(client, "otto")
    preview = await client.post("/api/business-applications/import/preview", json={"yaml": YAML})
    assert preview.status_code == 200, preview.text
    assert await store.list_applications() == []
    body = preview.json()
    committed = await client.post(
        "/api/business-applications/import/commit",
        json={
            "yaml": YAML,
            "base_revision": body["base_revision"],
            "base_digest": body["base_digest"],
            "preview_digest": body["preview_digest"],
        },
    )
    assert committed.status_code == 201, committed.text
    assert committed.json()["revision"] == 1
    second_preview = (
        await client.post("/api/business-applications/import/preview", json={"yaml": YAML})
    ).json()
    assert second_preview["no_op"] is True
    unchanged = await client.post(
        "/api/business-applications/import/commit",
        json={
            "yaml": YAML,
            **{key: second_preview[key] for key in ("base_revision", "base_digest", "preview_digest")},
        },
    )
    assert unchanged.json()["revision"] == 1
    history = await client.get("/api/business-applications/checkout-production/history")
    assert [item["revision"] for item in history.json()["revisions"]] == [1]
    exported = await client.get("/api/business-applications/checkout-production/export?revision=1")
    assert exported.status_code == 200
    assert exported.headers["x-hst-application-revision"] == "1"
    assert "id: checkout-production" in exported.text


async def test_a_revision_stored_with_the_removed_choice_scope_is_listed_exported_and_merged(
    client, store, monkeypatch
):
    from contextlib import contextmanager

    from tests.test_business_applications import GraphReferenceSession

    from hst.applications.yaml_format import definition_digest, normalized_document, parse_application_yaml
    from hst.assessment import service as assessment_service
    from hst.core import db

    stored = normalized_document(parse_application_yaml(YAML))
    stored["connections"] = [{**item, "choice_scope": "unspecified"} for item in stored["connections"]]
    old_digest = definition_digest(stored)
    await store.create_application_revision(
        definition=stored, digest=old_digest, created_by=None, expected_revision=0
    )
    reference = {
        "snapshot": "4000",
        "manifest_sha256": "a" * 64,
        "estate": "test",
        "observation_floor_ms": None,
    }
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: reference)

    @contextmanager
    def session(settings, **kwargs):
        yield GraphReferenceSession({})

    monkeypatch.setattr(db, "session", session)
    await login(client, "otto")

    listed = await client.get("/api/business-applications")
    assert listed.status_code == 200, listed.text
    assert [item["digest"] for item in listed.json()["applications"]] == [old_digest]
    assert (await client.get("/api/business-applications/checkout-production")).status_code == 200
    exported = await client.get("/api/business-applications/checkout-production/export")
    assert exported.status_code == 200, exported.text
    assert "choice_scope" not in exported.text
    assert exported.headers["x-hst-application-digest"] == old_digest
    resolved = await client.post(
        "/api/business-applications/checkout-production/resolve", json={"snapshot": "4000"}
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["ready"] is True

    preview = await client.post("/api/business-applications/import/preview", json={"yaml": YAML})
    assert preview.status_code == 200, preview.text
    token = preview.json()
    assert not any(v for k, v in token["changes"].items() if not k.endswith("_unchanged"))
    committed = await client.post(
        "/api/business-applications/import/commit",
        json={
            "yaml": YAML,
            **{key: token[key] for key in ("base_revision", "base_digest", "preview_digest")},
        },
    )
    assert committed.status_code == 201, committed.text
    assert committed.json()["revision"] == 2
    again = await client.post("/api/business-applications/import/preview", json={"yaml": YAML})
    assert again.json()["no_op"] is True

    strict = YAML.replace("    protocol: tcp\n", "    protocol: tcp\n    choice_scope: unspecified\n")
    refused = await client.post("/api/business-applications/import/preview", json={"yaml": strict})
    assert refused.status_code == 422
    body = {**normalized_document(parse_application_yaml(YAML)), "name": "Checkout API"}
    body["connections"] = [{**item, "choice_scope": "unspecified"} for item in body["connections"]]
    revised = await client.put(
        "/api/business-applications/checkout-production", json={"definition": body, "expected_revision": 2}
    )
    assert revised.status_code == 422, revised.text
    assert "choice_scope" in revised.text
    assert (await store.get_application("checkout-production")).revision == 2


async def test_a_stored_choice_scope_is_left_out_of_reads_and_the_editor_saves_it(client, store):
    from hst.applications.yaml_format import definition_digest, normalized_document, parse_application_yaml

    stored = normalized_document(parse_application_yaml(YAML))
    stored["connections"] = [{**item, "choice_scope": "unspecified"} for item in stored["connections"]]
    old_digest = definition_digest(stored)
    await store.create_application_revision(
        definition=stored, digest=old_digest, created_by=None, expected_revision=0
    )
    await login(client, "otto")

    read = (await client.get("/api/business-applications/checkout-production")).json()["application"]
    listed = (await client.get("/api/business-applications")).json()["applications"]
    history = (await client.get("/api/business-applications/checkout-production/history")).json()
    served = [read, listed[0], history["revisions"][0]]
    assert all(
        "choice_scope" not in connection
        for item in served
        for connection in item["definition"]["connections"]
    )
    assert {item["digest"] for item in served} == {old_digest}

    edited = {**read["definition"], "name": "Checkout renamed"}
    saved = await client.put(
        "/api/business-applications/checkout-production",
        json={"definition": edited, "expected_revision": 1, "source": "editor"},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["revision"] == 2
    # the stored row of revision 1 is not changed
    assert (await store.get_application("checkout-production", 1)).definition == stored


async def test_replace_import_round_trips_the_export_and_removes_omitted_entities(client, store):
    await login(client, "otto")

    async def preview(text, mode):
        response = await client.post(
            "/api/business-applications/import/preview", json={"yaml": text, "mode": mode}
        )
        assert response.status_code == 200, response.text
        return response.json()

    async def commit(text, mode, token):
        return await client.post(
            "/api/business-applications/import/commit",
            json={
                "yaml": text,
                "mode": mode,
                **{key: token[key] for key in ("base_revision", "base_digest", "preview_digest")},
            },
        )

    assert (await commit(YAML, "merge", await preview(YAML, "merge"))).status_code == 201
    exported = (await client.get("/api/business-applications/checkout-production/export")).text
    unchanged = await preview(exported, "replace")
    assert unchanged["no_op"] is True
    assert (await commit(exported, "replace", unchanged)).json()["revision"] == 1

    without_services = YAML.split("services:")[0]
    merged = await preview(without_services, "merge")
    assert merged["no_op"] is True
    assert merged["changes"]["services_removed"] == []
    replaced = await preview(without_services, "replace")
    assert replaced["no_op"] is False
    assert replaced["changes"]["services_removed"] == ["frontend"]
    assert (await commit(without_services, "merge", replaced)).status_code == 409
    assert (await commit(without_services, "replace", merged)).status_code == 409
    saved = await commit(without_services, "replace", replaced)
    assert saved.status_code == 201, saved.text
    assert saved.json()["revision"] == 2
    assert saved.json()["definition"]["services"] == []
    rejected = await client.post(
        "/api/business-applications/import/preview", json={"yaml": YAML, "mode": "overwrite"}
    )
    assert rejected.status_code == 422


async def test_viewer_reads_but_cannot_author_and_stale_commit_conflicts(client):
    await login(client, "vera")
    assert (await client.get("/api/business-applications")).status_code == 200
    assert (
        await client.post("/api/business-applications/import/preview", json={"yaml": YAML})
    ).status_code == 403
    await client.post("/api/logout")
    await login(client, "otto")
    preview = (await client.post("/api/business-applications/import/preview", json={"yaml": YAML})).json()
    create = await client.post(
        "/api/business-applications",
        json={
            "definition": {
                "schema_version": 1,
                "kind": "BusinessApplication",
                "id": "checkout-production",
                "name": "Concurrent",
            }
        },
    )
    assert create.status_code == 201
    stale = await client.post(
        "/api/business-applications/import/commit",
        json={
            "yaml": YAML,
            **{key: preview[key] for key in ("base_revision", "base_digest", "preview_digest")},
        },
    )
    assert stale.status_code == 409


async def test_affected_lookup_reports_only_explicit_inventory_references(client, store):
    await login(client, "otto")
    definition = {
        "schema_version": 1,
        "kind": "BusinessApplication",
        "id": "checkout",
        "name": "Checkout",
        "state": "draft",
        "services": [],
        "groups": [
            {
                "id": "api",
                "name": "API",
                "members": [
                    {
                        "id": "api-one",
                        "inventory": {
                            "kind": "interface",
                            "uid": "interface:api-1",
                            "role": "component",
                        },
                    }
                ],
            }
        ],
        "connections": [],
    }
    await store.create_application_revision(
        definition=definition, digest="a" * 64, created_by=1, expected_revision=0
    )
    response = await client.get("/api/business-applications/affected?inventory_uid=interface%3Aapi-1")
    assert response.status_code == 200
    assert response.json()["applications"][0]["application_id"] == "checkout"
    assert response.json()["coverage"]["meaning"].startswith("explicit inventory references only")


async def test_resolve_reports_no_incomplete_read_for_a_device_reference(client, store, monkeypatch):
    from contextlib import contextmanager

    from tests.test_business_applications import GraphReferenceSession, one_connection_definition

    from hst.applications.yaml_format import definition_digest
    from hst.assessment import service as assessment_service
    from hst.core import db

    await login(client, "otto")
    definition = one_connection_definition("device", "dev:core1")
    await store.create_application_revision(
        definition=definition.model_dump(mode="json"),
        digest=definition_digest(definition),
        created_by=1,
        expected_revision=0,
    )
    reference = {
        "snapshot": "4000",
        "manifest_sha256": "a" * 64,
        "estate": "test",
        "observation_floor_ms": None,
    }
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: reference)
    graph = GraphReferenceSession({"dev:core1": {"labels": ["Obj", "Device"]}})

    @contextmanager
    def session(settings, **kwargs):
        yield graph

    monkeypatch.setattr(db, "session", session)

    response = await client.post("/api/business-applications/webshop/resolve", json={"snapshot": "4000"})

    assert response.status_code == 200, response.text
    codes = {issue["code"] for issue in response.json()["issues"]}
    assert "inventory-read-incomplete" not in codes
    assert "inventory-address-unavailable" in codes
    assert graph.params[0]["uid"] == "dev:core1"


async def test_post_resolve_records_the_resolution_under_changes_write(client, store, monkeypatch):
    from contextlib import contextmanager

    from tests.test_business_applications import GraphReferenceSession

    from hst.assessment import service as assessment_service
    from hst.core import db

    reference = {
        "snapshot": "4000",
        "manifest_sha256": "a" * 64,
        "estate": "test",
        "observation_floor_ms": None,
    }
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: reference)

    @contextmanager
    def session(settings, **kwargs):
        yield GraphReferenceSession({})

    monkeypatch.setattr(db, "session", session)
    await login(client, "otto")
    preview = (await client.post("/api/business-applications/import/preview", json={"yaml": YAML})).json()
    token = {key: preview[key] for key in ("base_revision", "base_digest", "preview_digest")}
    committed = await client.post("/api/business-applications/import/commit", json={"yaml": YAML, **token})
    assert committed.status_code == 201, committed.text
    await client.post("/api/logout")

    await login(client, "vera")
    denied = await client.post(
        "/api/business-applications/checkout-production/resolve", json={"snapshot": "4000"}
    )
    assert denied.status_code == 403
    await client.post("/api/logout")

    await login(client, "otto")
    response = await client.post(
        "/api/business-applications/checkout-production/resolve",
        json={"snapshot": "4000", "connection_ids": ["web"]},
    )
    assert response.status_code == 200, response.text
    resolved = response.json()
    assert resolved["ready"] is True
    assert resolved["selection"] == {"service_ids": [], "connection_ids": ["web"]}
    assert resolved["application"]["revision"] == 1
    assert (await store.get_application_resolution(resolved["digest"]))["digest"] == resolved["digest"]

    by_service = await client.post(
        "/api/business-applications/checkout-production/resolve",
        json={"snapshot": "4000", "service_ids": ["frontend"]},
    )
    assert by_service.json()["selection"] == {"service_ids": ["frontend"], "connection_ids": ["web"]}

    # resolving records the resolved scope, so the path answers POST only
    removed = await client.get("/api/business-applications/checkout-production/resolve?snapshot=4000")
    assert removed.status_code == 405

    missing = await client.post("/api/business-applications/absent/resolve", json={"snapshot": "4000"})
    assert missing.status_code == 404
    unknown = await client.post(
        "/api/business-applications/checkout-production/resolve",
        json={"snapshot": "4000", "connection_ids": ["absent"]},
    )
    assert unknown.status_code == 422


async def test_resolve_answers_200_with_a_member_placeholder_issue(client, store, monkeypatch):
    from contextlib import contextmanager

    from tests.test_business_applications import PLACEHOLDERS, GraphReferenceSession

    from hst.applications.yaml_format import definition_digest, normalized_document, parse_application_yaml
    from hst.assessment import service as assessment_service
    from hst.core import db

    definition = normalized_document(parse_application_yaml(PLACEHOLDERS))
    await store.create_application_revision(
        definition=definition, digest=definition_digest(definition), created_by=1, expected_revision=0
    )
    reference = {
        "snapshot": "4000",
        "manifest_sha256": "a" * 64,
        "estate": "test",
        "observation_floor_ms": None,
    }
    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: reference)
    graph = GraphReferenceSession(
        {"ip:corp:10.0.10.6": {"labels": ["Obj", "IpAddress"], "rows": [("10.0.10.6", None)]}}
    )

    @contextmanager
    def session(settings, **kwargs):
        yield graph

    monkeypatch.setattr(db, "session", session)
    await login(client, "otto")

    response = await client.post("/api/business-applications/webshop/resolve", json={"snapshot": "4000"})

    assert response.status_code == 200, response.text
    resolved = response.json()
    assert resolved["ready"] is False
    assert [issue["path"] for issue in resolved["issues"] if issue["code"] == "member-placeholder"] == [
        "groups.web-tier.members.web01",
        "groups.snip.members.ns01-snip",
    ]
    assert resolved["groups"]["web-tier"]["web02"]["bindings"][0]["address"] == "10.0.10.6"
    assert [params["uid"] for params in graph.params] == ["ip:corp:10.0.10.6"]


REFERENCE = {
    "snapshot": "4000",
    "manifest_sha256": "a" * 64,
    "estate": "test",
    "observation_floor_ms": None,
}


@pytest.fixture
def pinned(monkeypatch):
    """Snapshot 4000 pins and the graph holds no nodes, so YAML resolves by its
    literal addresses."""
    from contextlib import contextmanager

    from tests.test_business_applications import GraphReferenceSession

    from hst.assessment import service as assessment_service
    from hst.core import db

    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: REFERENCE)

    @contextmanager
    def session(settings, **kwargs):
        yield GraphReferenceSession({})

    monkeypatch.setattr(db, "session", session)


async def _recorded_validation(client, text: str, **body) -> str:
    response = await client.post(
        "/api/business-applications/validate",
        json={"yaml": text, "snapshot": "4000", "record": True, **body},
    )
    assert response.status_code == 200, response.text
    digest = response.json()["validation_digest"]
    assert isinstance(digest, str)
    return digest


async def _commit(client, text: str, mode: str = "merge", **body):
    preview = await client.post(
        "/api/business-applications/import/preview", json={"yaml": text, "mode": mode}
    )
    assert preview.status_code == 200, preview.text
    token = {key: preview.json()[key] for key in ("base_revision", "base_digest", "preview_digest")}
    return await client.post(
        "/api/business-applications/import/commit", json={"yaml": text, "mode": mode, **token, **body}
    )


async def test_a_commit_records_its_origin_and_resolves_the_saved_revision(client, store, pinned):
    from hst.applications.yaml_format import definition_digest, parse_application_yaml

    await login(client, "otto")
    digest = await _recorded_validation(client, YAML)
    record = await store.get_application_validation(digest)
    assert record["definition_digest"] == definition_digest(parse_application_yaml(YAML))
    assert record["snapshot"] == REFERENCE
    assert record["ready"] is True
    assert record["resolution"]["application"]["revision"] == 0

    committed = await _commit(client, YAML, validation_digest=digest)

    assert committed.status_code == 201, committed.text
    saved = committed.json()
    assert saved["revision"] == 1
    assert saved["origin"] == {
        "source": "import",
        "generation_id": None,
        "generated_digest": None,
        "validation": {
            "validation_digest": digest,
            "snapshot": {"snapshot": "4000", "manifest_sha256": "a" * 64, "estate": "test"},
            "definition_digest": saved["digest"],
            "ready": True,
            "blocking_count": 0,
        },
    }
    assert saved["resolution_error"] is None
    resolution = await store.get_application_resolution(saved["resolution_digest"])
    # the saved revision is resolved, so Coverage and Analysis can use the record
    assert resolution["application"] == {
        "id": "checkout-production",
        "revision": 1,
        "digest": saved["digest"],
    }
    assert resolution["snapshot"] == REFERENCE
    assert resolution["ready"] is True

    history = (await client.get("/api/business-applications/checkout-production/history")).json()
    assert [item["origin"]["source"] for item in history["revisions"]] == ["import"]
    exported = await client.get("/api/business-applications/checkout-production/export")
    assert "origin" not in exported.text
    assert "validation" not in exported.text

    definition = {**saved["definition"], "name": "Checkout from a trace"}
    traced = await client.put(
        "/api/business-applications/checkout-production",
        json={"definition": definition, "expected_revision": 1, "source": "trace"},
    )
    assert traced.status_code == 200, traced.text
    assert traced.json()["revision"] == 2
    assert traced.json()["origin"]["source"] == "trace"
    assert traced.json()["origin"]["validation"] is None
    assert (traced.json()["resolution_digest"], traced.json()["resolution_error"]) == (None, None)

    created = await client.post(
        "/api/business-applications",
        json={"definition": {"schema_version": 1, "id": "billing", "name": "Billing"}},
    )
    assert created.status_code == 201, created.text
    assert created.json()["origin"]["source"] == "api"
    generated = await _commit(
        client, YAML.replace("id: checkout-production", "id: generated"), generation_id="generation-7"
    )
    assert generated.status_code == 201, generated.text
    assert generated.json()["origin"]["source"] == "generator"
    assert generated.json()["origin"]["generation_id"] == "generation-7"
    refused = await client.put(
        "/api/business-applications/billing",
        json={"definition": {"schema_version": 1, "id": "billing", "name": "B"}, "source": "generator"},
    )
    assert refused.status_code == 422


async def test_a_validation_digest_for_another_definition_is_rejected(client, store, pinned):
    await login(client, "otto")
    digest = await _recorded_validation(client, YAML)
    other = YAML.replace("name: Checkout\n", "name: Checkout Two\n", 1)

    rejected = await _commit(client, other, validation_digest=digest)

    assert rejected.status_code == 422
    assert "is for another definition" in rejected.text
    assert await store.list_applications() == []
    unknown = await _commit(client, YAML, validation_digest="e" * 64)
    assert unknown.status_code == 422
    assert "unknown application validation" in unknown.text
    malformed = await _commit(client, YAML, validation_digest="E" * 64)
    assert malformed.status_code == 422
    assert await store.list_applications() == []

    created = await client.post(
        "/api/business-applications",
        json={
            "definition": {"schema_version": 1, "id": "billing", "name": "Billing"},
            "validation_digest": digest,
        },
    )
    assert created.status_code == 422
    assert "is for another definition" in created.text

    # a result with a schema error has no definition, so nothing is recorded
    broken = await client.post(
        "/api/business-applications/validate",
        json={"yaml": YAML.replace("192.0.2.1", "ten"), "snapshot": "4000", "record": True},
    )
    assert broken.status_code == 200
    assert broken.json()["errors"] != []
    assert broken.json()["validation_digest"] is None

    await client.post("/api/logout")
    await login(client, "vera")
    before = copy.deepcopy(store._assessment_records)
    denied = await client.post(
        "/api/business-applications/validate", json={"yaml": other, "snapshot": "4000", "record": True}
    )
    assert denied.status_code == 403
    viewer = await client.post(
        "/api/business-applications/validate", json={"yaml": other, "snapshot": "4000"}
    )
    assert viewer.status_code == 200
    assert viewer.json()["validation_digest"] is None
    assert store._assessment_records == before


async def test_a_commit_that_inserts_nothing_resolves_nothing(client, store, pinned, monkeypatch):
    from hst.app.routes import business_applications as routes

    await login(client, "otto")
    digest = await _recorded_validation(client, YAML)
    first = await _commit(client, YAML, validation_digest=digest)
    assert first.status_code == 201, first.text
    assert first.json()["resolution_digest"] is not None
    resolved: list[tuple] = []
    monkeypatch.setattr(routes, "_resolve_graph", lambda *args: resolved.append(args))

    again = await _commit(client, YAML, validation_digest=digest)
    saved = first.json()
    revised = await client.put(
        "/api/business-applications/checkout-production",
        json={"definition": saved["definition"], "expected_revision": 1, "validation_digest": digest},
    )

    for response, status in ((again, 201), (revised, 200)):
        assert response.status_code == status, response.text
        body = response.json()
        assert (body["revision"], body["origin"]) == (1, saved["origin"])
        assert (body["resolution_digest"], body["resolution_error"]) == (None, None)
    assert resolved == []
    assert (await store.get_application("checkout-production")).revision == 1


async def test_a_resolution_failure_after_the_insert_keeps_the_revision(client, store, pinned, monkeypatch):
    from hst.app.routes import business_applications as routes
    from hst.applications.yaml_format import parse_application_yaml
    from hst.assessment import service as assessment_service

    await login(client, "otto")
    digest = await _recorded_validation(client, YAML)
    renamed = YAML.replace("name: Checkout\n", "name: Checkout Two\n", 1)
    second = await _recorded_validation(client, renamed, mode="replace")

    def released(settings, value):
        raise ValueError("A published snapshot with an evidence manifest is required.")

    monkeypatch.setattr(assessment_service, "snapshot_reference", released)
    committed = await _commit(client, YAML, validation_digest=digest)

    assert committed.status_code == 201, committed.text
    assert committed.json()["revision"] == 1
    assert committed.json()["resolution_digest"] is None
    assert committed.json()["resolution_error"] == (
        "A published snapshot with an evidence manifest is required."
    )
    saved = await store.get_application("checkout-production")
    assert saved.revision == 1
    assert saved.origin["validation"]["validation_digest"] == digest

    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: REFERENCE)

    def unavailable(*args):
        raise RuntimeError("graph database unavailable")

    monkeypatch.setattr(routes, "_resolve_graph", unavailable)
    definition = parse_application_yaml(renamed).model_dump(mode="json", exclude_none=True)
    revised = await client.put(
        "/api/business-applications/checkout-production",
        json={
            "definition": definition,
            "expected_revision": 1,
            "source": "editor",
            "validation_digest": second,
        },
    )

    assert revised.status_code == 200, revised.text
    assert revised.json()["revision"] == 2
    assert revised.json()["origin"]["source"] == "editor"
    assert revised.json()["resolution_digest"] is None
    assert (
        revised.json()["resolution_error"]
        == "the saved revision could not be resolved at the validation snapshot"
    )
    assert (await store.get_application("checkout-production")).revision == 2


DRAFT = """\
schema_version: 2
kind: BusinessApplication
id: checkout-production
name: Checkout
groups:
  - id: clients
    name: Clients
    members: [{id: client, address: 192.0.2.1}]
  - id: servers
    name: Servers
    members: [{id: server, address: 198.51.100.10}]
  - id: batch
    name: Batch
    members:
      - id: batch01
        placeholder: {text: the nightly batch host, expected_kind: ip}
connections:
  - id: web
    name: Web
    source: clients
    destination: servers
    protocol: tcp
    destination_ports: [443]
    destination_condition: {kind: member, member: server}
  - id: nightly
    name: Nightly
    source: batch
    destination: servers
    protocol: tcp
    destination_ports: [443]
    destination_condition: {kind: member, member: server}
services:
  - id: frontend
    name: Frontend
    connection_ids: [web, nightly]
"""


async def test_a_recorded_validation_keeps_the_flow_verdicts_and_the_placeholder_issues(
    client, store, pinned, monkeypatch
):
    from hst.assessment import direct
    from hst.results.project import condition_result

    # `evaluate_pinned` answers in the result vocabulary
    after = {
        "result": condition_result("does-not-hold").model_dump(mode="json"),
        "passes": [],
        "fails": ["192.0.2.1/32"],
        "open": [],
    }
    monkeypatch.setattr(
        direct, "evaluate_pinned", lambda settings, session, snap, **kwargs: {"outcomes": {"after": after}}
    )
    await login(client, "otto")
    validated = await client.post(
        "/api/business-applications/validate",
        json={"yaml": DRAFT, "snapshot": "4000", "evaluate": True, "record": True},
    )
    assert validated.status_code == 200, validated.text
    result = validated.json()
    record = await store.get_application_validation(result["validation_digest"])

    assert record["flows"] == result["flows"]
    assert [
        (flow["connection_id"], flow["result"] and flow["result"]["answer"], flow["not_evaluated_reason"])
        for flow in record["flows"]
    ] == [
        ("web", "false", None),
        ("nightly", None, "not-ready"),
    ]
    # the placeholder blocks the ready state and the verdict blocks nothing
    assert "groups.batch.members.batch01" in record["blocking"]
    assert record["blocking"] == result["blocking"]
    assert record["ready"] is False

    committed = await _commit(client, DRAFT, validation_digest=result["validation_digest"])

    assert committed.status_code == 201, committed.text
    saved = committed.json()
    assert saved["origin"]["validation"]["ready"] is False
    assert saved["origin"]["validation"]["blocking_count"] == len(record["blocking"])
    assert saved["resolution_error"] is None
    resolution = await store.get_application_resolution(saved["resolution_digest"])
    assert resolution["application"]["revision"] == 1
    assert resolution["ready"] is False
    assert [issue["path"] for issue in resolution["issues"] if issue["code"] == "member-placeholder"] == [
        "groups.batch.members.batch01"
    ]
