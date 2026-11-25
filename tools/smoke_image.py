"""Check the packaged API and SPA without external services during image build.

Database-backed startup is exercised separately in hosted integration CI.
"""

import asyncio
import sys
from pathlib import Path

import httpx

from hst.app.main import create_app
from hst.core.config import Settings
from hst.symbolic.manager import backend_available


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


async def main() -> None:
    require(backend_available(), "native symbolic backend missing")
    settings = Settings(_env_file=None)
    require((settings.web_dist / "index.html").is_file(), "SPA missing")
    app = create_app(settings)
    # ASGITransport runs no lifespan and opens no database connection at build time.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://smoke") as client:
        response = await client.get("/api/livez")
        require(response.status_code == 200 and response.json() == {"status": "ok"}, "liveness failed")
        response = await client.get("/")
        require(response.status_code == 200 and "text/html" in response.headers["content-type"], "SPA failed")
        assets = list((settings.web_dist / "assets").glob("*.js"))
        require(bool(assets), "compiled JavaScript missing")
        response = await client.get(f"/assets/{assets[0].name}")
        require(response.status_code == 200 and bool(response.content), "asset serving failed")


if __name__ == "__main__":
    asyncio.run(main())
    Path(sys.argv[1]).write_text("API, SPA, native backend and place file verified\n")
