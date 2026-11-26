"""The review flag that `app_save_application` opens on the MCP HTTP transport."""

from __future__ import annotations

import pytest
from tests.app.test_application_review_store import connection_session, save_session
from tests.app.test_mcp_write_tools import (  # noqa: F401
    WriteFakeStore,
    _definition,
    _tool,
    _write_token,
    wired,
)

pytest.importorskip("mcp")


@pytest.fixture
def store():
    return WriteFakeStore()


async def test_app_save_application_opens_a_flag_when_a_session_binds_an_older_revision(app, store):
    token = await _write_token(app, store)
    definition = _definition()
    created = await _tool(app, token, "app_save_application", {"definition": definition})
    assert created["isError"] is False, created
    assert await store.list_application_reviews("webshop") == []
    await save_session(store, connection_session("bound", [("webshop", 1)]))

    same = await _tool(app, token, "app_save_application", {"definition": definition, "expected_revision": 1})
    assert same["structuredContent"]["result"]["unchanged"] is True
    assert await store.list_application_reviews("webshop") == []

    revised = await _tool(
        app,
        token,
        "app_save_application",
        {"definition": {**definition, "name": "Webshop EU"}, "expected_revision": 1},
    )
    assert revised["structuredContent"]["result"]["revision"] == 2
    [review] = await store.list_application_reviews("webshop")
    assert (review.state, review.reason, review.revision, review.opened_by) == (
        "open",
        "revision 2 saved",
        2,
        None,
    )
