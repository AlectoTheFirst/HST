"""GET /api/queries lists a vendor entry only when the pinned run holds data
for that vendor, and lists everything when presence is not known."""

from __future__ import annotations

from typing import Any

import pytest
from tests.app.conftest import login

import hst.app.routes.explore as explore
from hst.queries import PRODUCT_LABELS, catalog


def _presence(**held: bool) -> dict[str, Any]:
    columns = list(PRODUCT_LABELS)
    return {"columns": columns, "data": [{"row": [held.get(c, False) for c in columns]}], "truncated": False}


@pytest.fixture(autouse=True)
def _clear(monkeypatch):
    explore._PRESENCE_CACHE.clear()
    monkeypatch.setattr(explore, "_snap", lambda request: 1700)
    yield
    explore._PRESENCE_CACHE.clear()


def _answer(monkeypatch, table: dict[str, Any]) -> list[str]:
    calls: list[str] = []

    def fake(settings, cypher, params, trusted=False, graph=False):
        calls.append(cypher)
        return table

    monkeypatch.setattr(explore, "run_readonly", fake)
    return calls


async def _keys(client) -> tuple[set[str], dict[str, Any]]:
    body = (await client.get("/api/queries")).json()
    return {q["key"] for q in body["queries"]}, body


async def test_no_zpa_data_hides_the_zpa_entries_and_keeps_the_core_ones(client, monkeypatch):
    _answer(monkeypatch, _presence(zia=True, sdwan=True, equinix=True))
    await login(client, "vera")
    keys, body = await _keys(client)
    assert "zpa-app-segment" not in keys
    assert {"devices", "zia-location", "sdwan-edges", "equinix-circuits"} <= keys
    assert body["products"] == ["equinix", "sdwan", "zia"]
    assert all("requires" not in q for q in body["queries"])


@pytest.mark.parametrize("product", sorted(PRODUCT_LABELS))
async def test_each_product_keeps_only_its_own_entries(client, monkeypatch, product):
    _answer(monkeypatch, _presence(**{product: True}))
    await login(client, "vera")
    keys, _ = await _keys(client)
    vendor = {q["key"] for q in catalog() if q.get("requires")}
    own = {q["key"] for q in catalog() if q.get("requires") == product}
    assert own and own <= keys
    assert not (vendor - own) & keys


async def test_a_probe_that_raises_lists_every_entry(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no database")

    monkeypatch.setattr(explore, "run_readonly", boom)
    await login(client, "vera")
    keys, body = await _keys(client)
    assert keys == {q["key"] for q in catalog()}
    assert "products" not in body


async def test_an_empty_answer_lists_every_entry_and_is_not_cached(client, monkeypatch):
    _answer(monkeypatch, {"columns": [], "data": [], "truncated": False})
    await login(client, "vera")
    keys, _ = await _keys(client)
    assert keys == {q["key"] for q in catalog()}
    assert explore._PRESENCE_CACHE == {}


async def test_the_answer_is_read_once_per_snapshot(client, monkeypatch):
    calls = _answer(monkeypatch, _presence(zpa=True))
    await login(client, "vera")
    await _keys(client)
    await _keys(client)
    assert len(calls) == 1


async def test_a_hidden_entry_runs_by_its_key(client, monkeypatch):
    _answer(monkeypatch, _presence())
    import hst.app.routes.queries as queries_route

    monkeypatch.setattr(
        queries_route, "run_readonly", lambda *a, **k: {"columns": [], "data": [], "truncated": False}
    )
    await login(client, "vera")
    keys, _ = await _keys(client)
    assert "zpa-policy-rules" not in keys
    r = await client.post("/api/queries/zpa-policy-rules", json={})
    assert r.status_code == 200
