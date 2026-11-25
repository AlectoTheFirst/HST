"""GET /api/path on a database with no published run: the answer says
no run exists, not a trace over nothing and not a 500."""

from contextlib import contextmanager

from tests.app.conftest import login

import hst.app.routes.path as path_route
from hst.core.snapshot import NoRun


@contextmanager
def _fake_session_cm(settings):
    yield object()


async def test_path_with_no_published_run_is_a_404(client, monkeypatch):
    await login(client, "vera")

    def no_run(session, src, dst, **kw):
        raise NoRun()

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", no_run)

    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8"})

    assert r.status_code == 404
    assert r.json() == {"error": "no run is published yet"}
