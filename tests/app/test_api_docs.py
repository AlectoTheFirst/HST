"""Docs preserve session protection and serve the application's live schema."""

import pytest
from tests.app.conftest import login


@pytest.mark.parametrize("path", ["docs", "openapi.json", "docs-init.js", "docs-assets/swagger-ui.css"])
async def test_docs_require_session(client, path):
    assert (await client.get(f"/api/{path}")).status_code == 401


async def test_docs_schema_and_security_headers(client, app):
    await login(client, "vera")
    response = await client.get("/api/openapi.json")
    assert response.status_code == 200
    assert response.json() == app.openapi()
    assert "/api/path" in response.json()["paths"]
    assert "/api/docs" not in response.json()["paths"]
    schema = response.json()
    assert schema["components"]["securitySchemes"]["SessionCookie"]["in"] == "cookie"
    assert schema["paths"]["/api/path"]["get"]["security"] == [{"SessionCookie": []}]
    assert "security" not in schema["paths"]["/api/login"]["post"]
    assert response.headers["cache-control"] == "no-store"
    page = await client.get("/api/docs")
    assert page.status_code == 200
    assert "swagger-ui-bundle.js" in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    script = await client.get("/api/docs-init.js")
    assert "X-HST-CSRF" in script.text
    # Documentation access does not elevate a viewer's API permissions.
    assert (await client.get("/api/users")).status_code == 403


def test_each_operation_has_a_tag_and_an_untagged_route_gets_the_name_of_its_module(app):
    paths = app.openapi()["paths"]
    assert all(operation.get("tags") for item in paths.values() for operation in item.values())
    assert paths["/api/path"]["get"]["tags"] == ["path"]
    assert paths["/api/changesim/export"]["post"]["tags"] == ["changesim"]


async def test_docs_assets_allowlist_and_missing_build(client, app, tmp_path):
    await login(client, "vera")
    app.state.settings.web_dist = tmp_path
    assert (await client.get("/api/docs-assets/swagger-ui.css")).status_code == 503
    assets = tmp_path / "swagger-ui"
    assets.mkdir()
    (assets / "swagger-ui.css").write_text("body { margin: 0; }")
    response = await client.get("/api/docs-assets/swagger-ui.css")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert (await client.get("/api/docs-assets/package.json")).status_code == 404
