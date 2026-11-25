"""The generation routes: a durable turn in a service_generator conversation,
the owner-only record, and the result a viewer and a committer receive."""

from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.app.conftest import login
from tests.app.fakes import FakeStore
from tests.app.test_ai_api import _configure
from tests.test_business_applications import GraphReferenceSession

from hst.app.agent import base as agent_base
from hst.app.agent.tools import dispatch
from hst.app.ai import prompt
from hst.app.routes import application_generator as routes
from hst.applications import generator
from hst.applications.resolution import AddressBinding, InventoryCandidate
from hst.applications.service import export_revision, save_definition
from hst.applications.yaml_format import parse_application_yaml
from hst.assessment.store import MemoryAssessmentStore

REFERENCE = {
    "snapshot": "4000",
    "manifest_sha256": "a" * 64,
    "estate": "test",
    "observation_floor_ms": None,
}
DESCRIPTION = "Checkout: clients in 192.0.2.0/24 reach the web server web01 on tcp 443."
WEB = "ip:corp:198.51.100.10"

MODEL_YAML = f"""\
schema_version: 1
kind: BusinessApplication
id: checkout
name: Checkout
groups:
  - id: clients
    name: Clients
    members: [{{id: lan, address: 192.0.2.0/24}}]
  - id: servers
    name: Servers
    members:
      - {{id: web01, name: web01, inventory: {{kind: ip, uid: "{WEB}", role: destination}}}}
      - {{id: web02, name: web02, inventory: {{kind: ip, uid: "ip:corp:198.51.100.11", role: destination}}}}
connections:
  - id: web
    name: Web
    source: clients
    destination: servers
    protocol: tcp
    destination_ports: [443]
    destination_condition: {{kind: member, member: web01}}
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


class Facts:
    def resolve(self, reference):
        if reference.uid != WEB:
            return []
        return [
            InventoryCandidate(uid=WEB, kind="ip", addresses=(AddressBinding("198.51.100.10", None, WEB),))
        ]

    def ip_nodes(self, address):
        return [WEB]

    def dns_answers(self, uid):
        return []


class Tools:
    """The real generator specs with a body that answers every call with the
    web server's record and records the run it read."""

    def __init__(self, specs):
        self.real = specs
        self.reads: list[tuple[int | None, Any]] = []

    def specs(self):
        def run(ctx, arguments):
            self.reads.append((ctx.snapshot.cts if ctx.snapshot else None, arguments.get("snapshot")))
            return json.dumps({"items": [{"uid": WEB, "label": "IpAddress", "name": "web01"}]})

        return [replace(spec, run=run) for spec in self.real]


class Model:
    """Calls inventory_search once, naming another run, then answers the YAML."""

    def __init__(self, answer=MODEL_YAML):
        self.answer = answer
        self.calls = []

    def ask(self, question, **kwargs):
        self.calls.append({"question": question, **kwargs})
        step = dispatch(kwargs["tools"], "inventory_search", {"q": "web01", "snapshot": "999"})
        kwargs["on_step"](step)
        return agent_base.AgentAnswer(answer=f"```yaml\n{self.answer}```", steps=[step])


@pytest.fixture
def pinned(monkeypatch):
    """Snapshot 4000 pins, validation reads an empty graph, and the
    post-processor reads `Facts`."""
    from hst.assessment import service as assessment_service
    from hst.core import db

    monkeypatch.setattr(assessment_service, "snapshot_reference", lambda settings, value: REFERENCE)

    @contextmanager
    def session(settings, **kwargs):
        yield GraphReferenceSession(
            {WEB: {"labels": ["Obj", "IpAddress"], "rows": [("198.51.100.10", None)]}}
        )

    monkeypatch.setattr(db, "session", session)

    @contextmanager
    def facts(settings, snap, reference):
        yield Facts()

    monkeypatch.setattr(routes, "_graph_facts", facts)
    tools = Tools(generator.generator_specs())
    monkeypatch.setattr(generator, "generator_specs", tools.specs)
    return tools


async def _drain(app):
    for task in list(getattr(app.state, "ask_tasks", ())):
        await task


async def _finished(client, generation_id):
    for _ in range(500):
        response = await client.get(f"/api/business-applications/generations/{generation_id}")
        assert response.status_code == 200, response.text
        if response.json()["status"] != "running":
            return response.json()
        await asyncio.sleep(0.01)
    raise AssertionError("the generation never finished")


async def _generate(app, client, **body):
    response = await client.post(
        "/api/business-applications/generations",
        json={"description": DESCRIPTION, "snapshot": "4000", **body},
    )
    assert response.status_code == 202, response.text
    generation_id = response.json()["generation_id"]
    try:
        return generation_id, await _finished(client, generation_id)
    finally:
        await _drain(app)


async def _as(client, username):
    await client.post("/api/logout")
    await login(client, username)


async def _user_id(store, username):
    return (await store.get_user_by_username(username)).id


async def test_a_viewer_generates_and_receives_the_yaml_and_the_validation_without_a_preview(
    app, client, store, pinned, monkeypatch
):
    model = Model()
    await _configure(client, monkeypatch, model)
    await _as(client, "vera")

    generation_id, result = await _generate(app, client)

    assert result["status"] == "done", result
    assert result["generation_id"] == generation_id
    assert result["snapshot"] == REFERENCE
    assert result["errors"] == []
    assert "id: checkout" in result["yaml"]
    validation = result["validation"]
    assert validation["errors"] == []
    assert validation["resolution"]["snapshot"] == REFERENCE
    assert validation["definition"]["id"] == "checkout"
    assert validation["preview"] is None
    assert result["validation_digest"] is None
    # the uid no lookup returned is a placeholder
    refs = {ref["path"]: ref for ref in result["report"]["references"]}
    assert refs["groups.servers.members.web01"]["status"] == "resolved"
    assert refs["groups.servers.members.web02"]["status"] == "unresolved"
    assert "not returned by any lookup" in result["yaml"]
    assert "schema_version: 2" in result["yaml"]

    # the turn ran in an ephemeral service_generator conversation
    turn = next(m for m in store.ai_messages.values() if m.id == generation_id)
    conversation = store.ai_conversations[turn.conversation_id]
    assert (conversation.surface, conversation.ephemeral) == ("service_generator", True)
    assert turn.status == "done"
    (row,) = [step for step in store.ai_steps.values() if step.message_id == generation_id]
    assert (row.tool, row.arguments) == ("inventory_search", {"q": "web01", "snapshot": "999"})

    record = await store.get_application_generation(generation_id)
    assert record["created_by"] == await _user_id(store, "vera")
    assert record["source"] == {"kind": "description"}
    assert record["description"] == DESCRIPTION
    (step,) = record["steps"]
    assert step["tool"] == "inventory_search"
    # the ai_steps row keeps the run the model named; the record leaves it out, as the call read run 4000
    assert step["arguments"] == {"q": "web01"}
    assert len(step["result_sha256"]) == 64
    assert "result" not in step
    assert record["validation_digest"] is None
    assert record["definition_digest"] == result["report"]["definition_digest"]


async def test_the_generation_takes_no_site_instructions_and_is_offered_the_generator_tools(
    app, client, store, pinned, monkeypatch
):
    model = Model()
    await _configure(client, monkeypatch, model)
    saved = await client.put(
        "/api/settings/ai",
        json={
            "enabled": True,
            "provider": "anthropic",
            "model": "claude-opus-5",
            "system_prompt": "SITE-INSTRUCTION-MARKER",
        },
    )
    assert saved.status_code == 200, saved.text

    _generation_id, result = await _generate(app, client)

    assert result["status"] == "done", result
    (call,) = model.calls
    assert call["question"] == DESCRIPTION
    assert call["system"] == prompt.BASE_STRUCTURED + "\n\n" + generator.SYSTEM
    assert "SITE-INSTRUCTION-MARKER" not in call["system"]
    assert [tool.name for tool in call["tools"]] == [
        "inventory_search",
        "inventory_resolve",
        "app_applications",
        "lb_lookup_vip",
        "search_objects",
        "resolve_hostname",
        "object_addresses",
        "policy_route_sources",
    ]
    assert all('"snapshot"' not in json.dumps(tool.schema) for tool in call["tools"])


async def test_one_generation_reads_one_snapshot(app, client, store, pinned, monkeypatch):
    await _configure(client, monkeypatch, Model())

    generation_id, result = await _generate(app, client)

    assert result["status"] == "done", result
    # the model named run 999; the tool read run 4000
    assert pinned.reads == [(4000, "4000")]
    record = await store.get_application_generation(generation_id)
    assert record["snapshot"] == REFERENCE
    assert record["report"]["snapshot"] == REFERENCE
    assert record["validation"]["snapshot"] == REFERENCE


async def test_only_the_owner_reads_the_generation(app, client, store, pinned, monkeypatch):
    await _configure(client, monkeypatch, Model())
    await _as(client, "vera")
    generation_id, result = await _generate(app, client)
    assert result["status"] == "done", result

    for other in ("otto", "ada"):
        await _as(client, other)
        response = await client.get(f"/api/business-applications/generations/{generation_id}")
        assert response.status_code == 404, other

    await _as(client, "vera")
    response = await client.get(f"/api/business-applications/generations/{generation_id}")
    assert response.status_code == 200
    missing = await client.get("/api/business-applications/generations/not-a-generation")
    assert missing.status_code == 404


async def test_a_committer_receives_the_preview_and_a_recorded_validation(
    app, client, store, pinned, monkeypatch
):
    await _configure(client, monkeypatch, Model())
    await _as(client, "otto")

    generation_id, result = await _generate(app, client)

    assert result["status"] == "done", result
    preview = result["validation"]["preview"]
    assert preview is not None
    assert (preview["application_id"], preview["base_revision"]) == ("checkout", 0)
    digest = result["validation_digest"]
    assert (await store.get_application_validation(digest))["definition_digest"] == result["report"][
        "definition_digest"
    ]

    committed = await client.post(
        "/api/business-applications/import/commit",
        json={
            "yaml": result["yaml"],
            "mode": "replace",
            **{key: preview[key] for key in ("base_revision", "base_digest", "preview_digest")},
            "generation_id": generation_id,
            "validation_digest": digest,
        },
    )
    assert committed.status_code == 201, committed.text
    origin = committed.json()["origin"]
    assert (origin["source"], origin["generation_id"]) == ("generator", generation_id)
    assert origin["generated_digest"] == result["report"]["definition_digest"]
    assert origin["validation"]["validation_digest"] == digest


async def test_a_generation_needs_a_pinned_snapshot_and_a_configured_agent(app, client, store, pinned):
    await login(client, "vera")
    latest = await client.post(
        "/api/business-applications/generations", json={"description": DESCRIPTION, "snapshot": "latest"}
    )
    assert latest.status_code == 400
    unconfigured = await client.post(
        "/api/business-applications/generations", json={"description": DESCRIPTION, "snapshot": "4000"}
    )
    assert unconfigured.status_code == 503


async def test_a_service_draft_starts_a_generation_from_conversation_messages(
    app, client, store, pinned, monkeypatch
):
    model = Model()
    await _configure(client, monkeypatch, model)
    await _as(client, "vera")
    vera = await _user_id(store, "vera")
    now = datetime.now(UTC)
    conversation = await store.create_conversation(vera, "drawer", now)
    questions = []
    for text in ("Checkout: clients in 192.0.2.0/24", "reach web01 on tcp 443."):
        reply = await store.start_turn(vera, conversation.id, text, None, now, per_user_cap=2, global_cap=16)
        assert await store.claim_turn(reply.id, "seed", 60, now)
        assert await store.finish_turn(reply.id, "seed", "done", now, content="noted")
        questions.append(
            next(
                m
                for m in store.ai_messages.values()
                if m.seq == reply.seq - 1 and m.conversation_id == conversation.id
            )
        )

    response = await client.post(
        "/api/ai/service-drafts",
        json={
            "conversation_id": conversation.id,
            "message_ids": [questions[1].id, questions[0].id],
            "snapshot": "4000",
        },
    )
    assert response.status_code == 202, response.text
    generation_id = response.json()["generation_id"]
    try:
        result = await _finished(client, generation_id)
    finally:
        await _drain(app)

    assert result["status"] == "done", result
    assert model.calls[0]["question"] == "Checkout: clients in 192.0.2.0/24\n\nreach web01 on tcp 443."
    record = await store.get_application_generation(generation_id)
    assert record["source"] == {
        "kind": "conversation",
        "conversation_id": conversation.id,
        "message_ids": [questions[0].id, questions[1].id],
    }

    answer = next(
        m
        for m in store.ai_messages.values()
        if m.conversation_id == conversation.id and m.role == "assistant"
    )
    refused = await client.post(
        "/api/ai/service-drafts",
        json={"conversation_id": conversation.id, "message_ids": [answer.id], "snapshot": "4000"},
    )
    assert refused.status_code == 404
    await _as(client, "otto")
    foreign = await client.post(
        "/api/ai/service-drafts",
        json={"conversation_id": conversation.id, "message_ids": [questions[0].id], "snapshot": "4000"},
    )
    assert foreign.status_code == 404


async def test_a_failed_generation_answers_the_error_and_stores_no_record(
    app, client, store, pinned, monkeypatch
):
    class Failing:
        def ask(self, question, **kwargs):
            raise agent_base.AgentError("upstream said no")

    await _configure(client, monkeypatch, Failing())
    generation_id, result = await _generate(app, client)

    assert result["status"] == "error"
    assert "see the server log" in result["detail"]
    assert "upstream said no" not in result["detail"]
    assert await store.get_application_generation(generation_id) is None


CHANGE = "Open tcp 8443 on the web connection and add the web server web03."
WEB02 = (
    "      - {id: web02, name: web02, "
    + 'inventory: {kind: ip, uid: "ip:corp:198.51.100.11", role: destination}}\n'
)
WEB03 = WEB02.replace("web02", "web03").replace("198.51.100.11", "198.51.100.12")
# The model's edit of MODEL_YAML: it renames the application, changes the
# ports and adds a member whose uid no lookup returned.
EDIT_YAML = (
    MODEL_YAML.replace("id: checkout\n", "id: storefront\n")
    .replace("destination_ports: [443]\n", "destination_ports: [443, 8443]\n")
    .replace(WEB02, WEB02 + WEB03)
)
GENERATIONS = "/api/business-applications/generations"
COMMIT = "/api/business-applications/import/commit"


async def _saved(store):
    """Revision 1 of checkout: MODEL_YAML as written, with web02's uid unknown to every lookup."""
    return await save_definition(store, parse_application_yaml(MODEL_YAML), expected_revision=0, actor=None)


async def _edit(app, client, base):
    return await _generate(
        app, client, description=CHANGE, application_id=base.id, base_revision=base.revision
    )


def _commit_body(result, generation_id, base_revision, base_digest, preview_digest):
    return {
        "yaml": result["yaml"],
        "mode": "replace",
        "base_revision": base_revision,
        "base_digest": base_digest,
        "preview_digest": preview_digest,
        "generation_id": generation_id,
        "validation_digest": result["validation_digest"],
    }


async def test_an_edit_sends_the_saved_revision_and_keeps_the_members_it_leaves_unchanged(
    app, client, store, pinned, monkeypatch
):
    assert (EDIT_YAML.count("storefront"), EDIT_YAML.count("8443"), EDIT_YAML.count("web03")) == (1, 1, 2)
    base = await _saved(store)
    model = Model(EDIT_YAML)
    await _configure(client, monkeypatch, model)
    await _as(client, "otto")

    generation_id, result = await _edit(app, client, base)

    assert result["status"] == "done", result
    (call,) = model.calls
    export = export_revision(base)
    assert call["question"] == generator.edit_question(CHANGE, export, application_id="checkout", revision=1)
    assert export.rstrip() in call["question"]
    assert call["system"] == "\n\n".join((prompt.BASE_STRUCTURED, generator.SYSTEM, generator.EDIT_SYSTEM))
    source = {"kind": "edit", "application_id": "checkout", "base_revision": 1, "base_digest": base.digest}
    assert result["source"] == source
    record = await store.get_application_generation(generation_id)
    assert (record["source"], record["description"]) == (source, CHANGE)

    definition = result["validation"]["definition"]
    # the model renamed the application; the edit keeps the saved id
    assert definition["id"] == "checkout"
    servers = {member["id"]: member for member in definition["groups"][1]["members"]}
    # web02 stays as saved although no lookup returned its uid
    assert servers["web02"]["inventory"]["uid"] == "ip:corp:198.51.100.11"
    assert servers["web03"]["placeholder"]["status"] == "unresolved"
    assert [ref["path"] for ref in result["report"]["references"]] == ["groups.servers.members.web03"]
    preview = result["validation"]["preview"]
    assert (preview["application_id"], preview["base_revision"]) == ("checkout", 1)
    assert preview["changes"]["connections_updated"] == ["web"]

    committed = await client.post(
        COMMIT, json=_commit_body(result, generation_id, 1, base.digest, preview["preview_digest"])
    )
    assert committed.status_code == 201, committed.text
    saved = committed.json()
    assert (saved["id"], saved["revision"]) == ("checkout", 2)
    assert (saved["origin"]["source"], saved["origin"]["generation_id"]) == ("generator", generation_id)


async def test_an_edit_commit_after_a_concurrent_change_answers_409(app, client, store, pinned, monkeypatch):
    base = await _saved(store)
    await _configure(client, monkeypatch, Model(EDIT_YAML))
    await _as(client, "otto")
    generation_id, result = await _edit(app, client, base)
    assert result["status"] == "done", result
    preview = result["validation"]["preview"]

    # revision 2 is saved while the edit is reviewed
    renamed = parse_application_yaml(MODEL_YAML.replace("name: Checkout\n", "name: Checkout web\n"))
    await save_definition(store, renamed, expected_revision=1, actor=None)

    stale = await client.post(
        COMMIT, json=_commit_body(result, generation_id, 1, base.digest, preview["preview_digest"])
    )
    assert stale.status_code == 409, stale.text

    # a preview taken now states revision 2; the edit started from revision 1
    fresh = await client.post(
        "/api/business-applications/import/preview", json={"yaml": result["yaml"], "mode": "replace"}
    )
    assert fresh.status_code == 200, fresh.text
    token = fresh.json()
    assert token["base_revision"] == 2
    moved = await client.post(
        COMMIT, json=_commit_body(result, generation_id, 2, token["base_digest"], token["preview_digest"])
    )
    assert moved.status_code == 409, moved.text
    assert "revision 1 of checkout" in moved.text

    current = await store.get_application("checkout")
    assert (current.revision, current.name) == (2, "Checkout web")


async def test_an_edit_names_a_saved_revision(app, client, store, pinned, monkeypatch):
    await _saved(store)
    model = Model(EDIT_YAML)
    await _configure(client, monkeypatch, model)
    await _as(client, "otto")
    body = {"description": CHANGE, "snapshot": "4000"}

    half = await client.post(GENERATIONS, json={**body, "application_id": "checkout"})
    assert half.status_code == 422
    for application_id, revision in (("checkout", 2), ("billing", 1)):
        missing = await client.post(
            GENERATIONS, json={**body, "application_id": application_id, "base_revision": revision}
        )
        assert missing.status_code == 404, (application_id, revision)
    assert model.calls == []


async def test_the_poll_route_reads_a_generation_id_in_any_uuid_form(app, client, store, pinned, monkeypatch):
    await _configure(client, monkeypatch, Model())
    generation_id, result = await _generate(app, client)
    assert result["status"] == "done", result

    upper = await client.get(f"{GENERATIONS}/{generation_id.upper()}")

    assert upper.status_code == 200, upper.text
    assert (upper.json()["generation_id"], upper.json()["yaml"]) == (generation_id, result["yaml"])


async def test_a_validation_that_raises_keeps_the_yaml_and_the_report(
    app, client, store, pinned, monkeypatch
):
    from hst.app.routes import business_applications

    def over_bound(*args):
        raise ValueError("the resolution exceeds 10000 addresses")

    monkeypatch.setattr(business_applications, "_resolve_graph", over_bound)
    await _configure(client, monkeypatch, Model())
    await _as(client, "otto")

    generation_id, result = await _generate(app, client)

    assert result["status"] == "done", result
    assert "id: checkout" in result["yaml"]
    assert result["errors"] == []
    assert result["report"]["definition_digest"] is not None
    assert result["validation"]["errors"] == [
        {"path": "$", "message": "the resolution exceeds 10000 addresses", "line": None, "column": None}
    ]
    assert result["validation"]["blocking"] == ["$"]
    assert result["validation_digest"] is None
    assert (await store.get_application_generation(generation_id))["yaml"] == result["yaml"]


async def test_an_edit_of_an_export_over_the_bound_answers_413(app, client, store, pinned, monkeypatch):
    base = await _saved(store)
    model = Model(EDIT_YAML)
    await _configure(client, monkeypatch, model)
    await _as(client, "otto")
    monkeypatch.setattr(routes, "MAX_EDIT_EXPORT_CHARS", len(export_revision(base)) - 1)

    response = await client.post(
        GENERATIONS,
        json={"description": CHANGE, "snapshot": "4000", "application_id": "checkout", "base_revision": 1},
    )

    assert response.status_code == 413, response.text
    assert model.calls == []


async def test_an_edit_of_an_older_revision_answers_409_before_the_model_runs(
    app, client, store, pinned, monkeypatch
):
    await _saved(store)
    renamed = parse_application_yaml(MODEL_YAML.replace("name: Checkout\n", "name: Checkout web\n"))
    await save_definition(store, renamed, expected_revision=1, actor=None)
    model = Model(EDIT_YAML)
    await _configure(client, monkeypatch, model)
    await _as(client, "otto")

    response = await client.post(
        GENERATIONS,
        json={"description": CHANGE, "snapshot": "4000", "application_id": "checkout", "base_revision": 1},
    )

    assert response.status_code == 409, response.text
    assert "not the current revision 2" in response.text
    assert model.calls == []


async def test_the_save_routes_refuse_an_edit_onto_another_revision(app, client, store, pinned, monkeypatch):
    base = await _saved(store)
    await _configure(client, monkeypatch, Model(EDIT_YAML))
    await _as(client, "otto")
    generation_id, result = await _edit(app, client, base)
    assert result["status"] == "done", result
    definition = result["validation"]["definition"]

    saved = await client.put(
        "/api/business-applications/checkout",
        json={"definition": definition, "expected_revision": 1, "generation_id": generation_id},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["revision"] == 2

    moved = await client.put(
        "/api/business-applications/checkout",
        json={
            "definition": {**definition, "name": "Checkout web"},
            "expected_revision": 2,
            "generation_id": generation_id,
        },
    )
    assert moved.status_code == 409, moved.text
    assert "revision 1 of checkout" in moved.text
    assert (await store.get_application("checkout")).revision == 2
