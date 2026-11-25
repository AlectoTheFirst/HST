"""A built SPA must not mask API extensions registered after app creation."""

import httpx
from fastapi import APIRouter
from tests.app.fakes import FakeStore

from hst.app.main import create_app
from hst.core import Settings


async def test_late_api_registration_remains_reachable_with_built_spa(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("inventory app")
    app = create_app(Settings(_env_file=None, web_dist=tmp_path), store=FakeStore())
    router = APIRouter()

    @router.get("/api/inventory-extension")
    def extension():
        return {"available": True}

    app.include_router(router)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/api/inventory-extension")).json() == {"available": True}
        assert (await client.get("/api/unknown")).status_code == 404
        assert (await client.get("/inventory/devices")).text == "inventory app"
