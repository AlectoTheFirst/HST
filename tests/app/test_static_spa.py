"""SPA serving: index fallback for app routes, /api never swallowed."""

import httpx
from tests.app.fakes import FakeStore

from hst.app.main import create_app
from hst.core import Settings


async def _get(app, url):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        return await c.get(url)


async def test_serves_index_and_assets_when_built(tmp_path):
    (tmp_path / "assets").mkdir(parents=True)
    (tmp_path / "index.html").write_text("<title>hst</title>")
    (tmp_path / "assets" / "app.js").write_text("//js")
    settings = Settings(_env_file=None, web_dist=tmp_path)
    app = create_app(settings=settings, store=FakeStore())
    assert "<title>hst" in (await _get(app, "/")).text
    assert "<title>hst" in (await _get(app, "/some/spa/route")).text  # SPA fallback
    assert (await _get(app, "/assets/app.js")).text == "//js"
    assert (await _get(app, "/api/nope")).status_code in (401, 404)  # api untouched


async def test_no_build_no_page(tmp_path):
    settings = Settings(_env_file=None, web_dist=tmp_path / "missing")
    app = create_app(settings=settings, store=FakeStore())
    assert (await _get(app, "/")).status_code == 404


async def test_serves_favicon_when_built(tmp_path):
    (tmp_path / "assets").mkdir(parents=True)
    (tmp_path / "index.html").write_text("<title>hst</title>")
    (tmp_path / "favicon.svg").write_text("<svg></svg>")
    settings = Settings(_env_file=None, web_dist=tmp_path)
    app = create_app(settings=settings, store=FakeStore())

    resp = await _get(app, "/favicon.svg")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"
    assert resp.text == "<svg></svg>"
    assert (await _get(app, "/api/nope")).status_code in (401, 404)


async def test_no_favicon_falls_back_to_spa(tmp_path):
    (tmp_path / "assets").mkdir(parents=True)
    (tmp_path / "index.html").write_text("<title>hst</title>")
    settings = Settings(_env_file=None, web_dist=tmp_path)
    app = create_app(settings=settings, store=FakeStore())

    resp = await _get(app, "/favicon.svg")
    assert "<title>hst" in resp.text


async def test_serves_the_third_party_licences_of_the_build(tmp_path):
    (tmp_path / "assets").mkdir(parents=True)
    (tmp_path / "index.html").write_text("<title>hst</title>")
    (tmp_path / "THIRD-PARTY-LICENSES.txt").write_text("elkjs\nEPL-2.0\n")
    settings = Settings(_env_file=None, web_dist=tmp_path)
    app = create_app(settings=settings, store=FakeStore())

    resp = await _get(app, "/THIRD-PARTY-LICENSES.txt")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"
    assert resp.text == "elkjs\nEPL-2.0\n"


async def test_index_revalidates_while_hashed_assets_are_immutable(tmp_path):
    (tmp_path / "assets").mkdir(parents=True)
    (tmp_path / "index.html").write_text("<title>hst</title>")
    (tmp_path / "assets" / "index-abc123.js").write_text("//js")
    settings = Settings(_env_file=None, web_dist=tmp_path)
    app = create_app(settings=settings, store=FakeStore())

    index = await _get(app, "/")
    assert index.headers["cache-control"] == "no-cache"
    # the SPA fallback serves the same document, so it needs the same header
    assert (await _get(app, "/explore")).headers["cache-control"] == "no-cache"

    asset = await _get(app, "/assets/index-abc123.js")
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
