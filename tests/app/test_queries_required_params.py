"""A required catalog param that is absent or blank gets HTTP 400 naming its label."""

from __future__ import annotations

from tests.app.conftest import login

from hst.queries import catalog


def _required_entry():
    for entry in catalog():
        params = entry.get("params") or []
        required = [p for p in params if not p.get("optional")]
        if len(params) == 1 and required:
            return entry, required[0]
    raise AssertionError("no catalog entry with one required param")


async def test_a_blank_required_value_is_a_400_with_the_param_label(client):
    entry, param = _required_entry()
    await login(client, "vera")
    for value in ("", "   "):
        r = await client.post(f"/api/queries/{entry['key']}", json={"params": {param["name"]: value}})
        assert r.status_code == 400
        assert r.json()["error"] == f"missing params: {param.get('label') or param['name']}"
    r = await client.post(f"/api/queries/{entry['key']}", json={"params": {}})
    assert r.status_code == 400
    assert r.json()["error"] == f"missing params: {param.get('label') or param['name']}"
