"""The request body limit (app/body_limit.py) on the routes, the GraphQL route and /api/mcp."""

from __future__ import annotations

import json

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.inventory_rig import fake_rig

import hst.app.routes.cypher as cypher_route
from hst.app.body_limit import MIB
from hst.app.crypto import generate_key
from hst.app.inventory import inventory_routes
from hst.app.inventory.contracts import API_PREFIX, MAX_BULK_ROWS
from hst.app.main import create_app
from hst.app.routes import mcp_http
from hst.app.security import hash_password
from hst.assessment.store import MAX_DOCUMENT_BYTES
from hst.core import Settings

LIMIT_MB = 1
LIMIT = LIMIT_MB * MIB
CHUNK = 64 * 1024
REFUSAL = {"error": "the request body exceeds 1 MiB"}
JSON = {"Content-Type": "application/json"}
TABLE = {"columns": ["n"], "data": [], "truncated": False}


class Feed:
    """A request body sent in 64 KiB chunks. `read` is the byte count the app has received."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.read = 0

    async def __aiter__(self):
        while self.read < len(self.body):
            chunk = self.body[self.read : self.read + CHUNK]
            self.read += len(chunk)
            yield chunk


def cypher_body(size: int) -> bytes:
    """A valid POST /api/cypher body of exactly `size` bytes."""
    empty = json.dumps({"query": "RETURN 1", "params": {"pad": ""}}).encode()
    return json.dumps({"query": "RETURN 1", "params": {"pad": "x" * (size - len(empty))}}).encode()


@pytest.fixture
def app(seeded):
    settings = Settings(_env_file=None, hst_secret_key=generate_key(), HST_MAX_REQUEST_BODY_MB=LIMIT_MB)
    return create_app(settings=settings, store=seeded)


@pytest.mark.parametrize(
    "path", ["/api/cypher", "/api/login", "/api/graphql", "/api/mcp", "/api/auth/idp/acs"]
)
async def test_a_content_length_over_the_limit_is_413_and_no_body_byte_is_read(client, path):
    feed = Feed(b" " * (LIMIT + 1))

    r = await client.post(path, content=feed, headers={**JSON, "Content-Length": str(LIMIT + 1)})

    assert r.status_code == 413
    assert r.json() == REFUSAL
    assert r.headers["connection"] == "close"
    assert feed.read == 0


@pytest.mark.parametrize("path", ["/api/cypher", "/api/login"])
async def test_a_streamed_body_over_the_limit_is_413_without_a_session(client, path):
    feed = Feed(b" " * (8 * MIB))

    r = await client.post(path, content=feed, headers=JSON)

    assert "content-length" not in r.request.headers
    assert r.status_code == 413
    assert r.json() == REFUSAL
    assert LIMIT < feed.read <= LIMIT + CHUNK


async def test_a_streamed_graphql_body_over_the_limit_is_413(client):
    await login(client, "otto")
    feed = Feed(b" " * (8 * MIB))

    r = await client.post("/api/graphql", content=feed, headers=JSON)

    assert r.status_code == 413
    assert r.json() == REFUSAL
    assert LIMIT < feed.read <= LIMIT + CHUNK


async def test_a_streamed_mcp_body_over_the_limit_is_413(client, store):
    pytest.importorskip("mcp")
    await login(client, "otto")
    token = (await client.post("/api/access-tokens", json={"name": "laptop"})).json()["token"]
    await store.put_setting(mcp_http.SETTINGS_KEY, {"enabled": True}, b"")
    feed = Feed(b" " * (8 * MIB))
    headers = {**JSON, "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {token}"}

    r = await client.post("/api/mcp", content=feed, headers=headers)

    assert r.status_code == 413
    assert r.json() == REFUSAL
    assert LIMIT < feed.read <= LIMIT + CHUNK


@pytest.mark.parametrize("streamed", [False, True])
async def test_a_body_at_the_limit_reaches_the_route(client, monkeypatch, streamed):
    monkeypatch.setattr(cypher_route, "run_readonly", lambda s, q, p, graph=False: TABLE)
    await login(client, "otto")
    body = cypher_body(LIMIT)

    r = await client.post("/api/cypher", content=Feed(body) if streamed else body, headers=JSON)

    assert ("content-length" in r.request.headers) is not streamed
    assert r.status_code == 200
    assert r.json() == TABLE


@pytest.mark.parametrize("streamed", [False, True])
async def test_a_body_one_byte_over_the_limit_is_413(client, monkeypatch, streamed):
    monkeypatch.setattr(cypher_route, "run_readonly", lambda s, q, p, graph=False: TABLE)
    await login(client, "otto")
    body = cypher_body(LIMIT + 1)

    r = await client.post("/api/cypher", content=Feed(body) if streamed else body, headers=JSON)

    assert r.status_code == 413
    assert r.json() == REFUSAL


async def test_a_request_with_no_body_passes(client):
    assert (await client.get("/api/livez")).status_code == 200
    assert (await client.post("/api/logout")).status_code == 204


async def test_a_content_length_that_is_not_a_number_is_counted(client):
    feed = Feed(b" " * (8 * MIB))

    r = await client.post("/api/cypher", content=feed, headers={**JSON, "Content-Length": "1e3"})

    assert r.status_code == 413
    assert LIMIT < feed.read <= LIMIT + CHUNK


def test_the_default_limit_is_above_the_assessment_document_cap():
    assert Settings(_env_file=None).max_request_body_mb * MIB > MAX_DOCUMENT_BYTES


async def test_a_site_import_of_the_row_cap_passes_the_default_limit():
    rig = fake_rig()
    await rig.store.create_user("otto", hash_password(PASSWORD), "operator")
    app = create_app(
        settings=Settings(_env_file=None, hst_secret_key=generate_key()),
        store=rig.store,
        register_inventory=False,
    )
    app.state.inventory_context = rig.ctx
    inventory_routes.register(app)
    rows = [{"code": f"s{n}", "name": "n" * 200, "location": "l" * 200} for n in range(MAX_BULK_ROWS)]
    body = json.dumps({"sites": rows, "dry_run": True}).encode()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}) as c:
        await login(c, "otto")

        r = await c.post(f"{API_PREFIX}/sites/import", content=body, headers=JSON)

    assert len(body) > 2 * MIB
    assert r.status_code == 200, r.text
    assert r.json()["created"] == MAX_BULK_ROWS
