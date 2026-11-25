"""The read cache for each pinned session (`hst.path.session._read`).

No database: a fake session answers `execute_read` with a fake transaction
and counts the round trips.
"""

from __future__ import annotations

from typing import Any

from hst import path as pathmod
from hst.app import fw_overlay_read
from hst.path.session import READ_CACHE_MAX, CycleSession, _freeze


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self._rows


class _Store:
    """The session `CycleSession` wraps: records every query `execute_read` runs."""

    def __init__(self) -> None:
        self.queries: list[tuple[str, dict[str, Any]]] = []

    def execute_read(self, work: Any) -> Any:
        return work(_Tx(self))


class _Tx:
    def __init__(self, owner: _Store) -> None:
        self.owner = owner

    def run(self, query: str, **params: Any) -> _Result:
        self.owner.queries.append((query, params))
        return _Result([{"query": query, "snap": params.get("snap"), "items": [1, 2]}])


def test_a_repeated_read_runs_once() -> None:
    store = _Store()
    session = CycleSession(store, 42)
    first = pathmod._read(session, "MATCH (n) RETURN n", uid="a")
    second = pathmod._read(session, "MATCH (n) RETURN n", uid="a")
    assert first == second
    assert len(store.queries) == 1


def test_list_and_set_parameters_give_a_stable_key() -> None:
    assert _freeze({"uids": ["a", "b"], "x": 1}) == _freeze({"x": 1, "uids": ["a", "b"]})
    assert _freeze({"s": {"a", "b"}}) == _freeze({"s": {"b", "a"}})
    assert _freeze({"uids": ["a", "b"]}) != _freeze({"uids": ("a", "b", "c")})
    store = _Store()
    session = CycleSession(store, 42)
    pathmod._read(session, "Q", uids=["a", "b"], tags={"x", "y"})
    pathmod._read(session, "Q", tags={"y", "x"}, uids=["a", "b"])
    assert len(store.queries) == 1


def test_the_overlay_runs_on_every_hit() -> None:
    store = _Store()
    session = CycleSession(store, 42)
    calls: list[str] = []

    def overlay(query: str, params: dict[str, Any], rows: Any) -> Any:
        calls.append(query)
        return [dict(r, overlaid=len(calls)) for r in rows]

    session.overlay = overlay  # type: ignore[attr-defined]
    first = pathmod._read(session, "Q")
    second = pathmod._read(session, "Q")
    assert len(store.queries) == 1
    assert calls == ["Q", "Q"]
    assert first[0]["overlaid"] == 1
    assert second[0]["overlaid"] == 2


def test_a_change_to_returned_rows_does_not_change_the_next_read() -> None:
    store = _Store()
    session = CycleSession(store, 42)
    rows = pathmod._read(session, "Q")
    rows[0]["items"].append(3)
    rows[0]["query"] = "changed"
    rows.append({"extra": True})
    again = pathmod._read(session, "Q")
    assert again == [{"query": "Q", "snap": 42, "items": [1, 2]}]
    again[0]["items"].clear()
    assert pathmod._read(session, "Q")[0]["items"] == [1, 2]
    assert len(store.queries) == 1


def test_a_different_snap_misses() -> None:
    store = _Store()
    session = CycleSession(store, 42)
    pathmod._read(session, "Q")
    pathmod._read(session, "Q", snap=41)
    assert [params["snap"] for _, params in store.queries] == [42, 41]


def test_a_plain_session_never_caches() -> None:
    store = _Store()
    pathmod._read(store, "Q")
    pathmod._read(store, "Q")
    assert len(store.queries) == 2


def test_an_unhashable_parameter_skips_the_cache() -> None:
    store = _Store()
    session = CycleSession(store, 42)
    pathmod._read(session, "Q", obj=bytearray(b"x"))
    pathmod._read(session, "Q", obj=bytearray(b"x"))
    assert len(store.queries) == 2
    assert session._read_cache == {}


def test_a_full_cache_drops_its_oldest_entry() -> None:
    store = _Store()
    session = CycleSession(store, 42)
    for i in range(READ_CACHE_MAX + 1):
        pathmod._read(session, "Q", i=i)
    assert len(session._read_cache) == READ_CACHE_MAX
    pathmod._read(session, "Q", i=READ_CACHE_MAX)
    assert len(store.queries) == READ_CACHE_MAX + 1
    pathmod._read(session, "Q", i=0)
    assert len(store.queries) == READ_CACHE_MAX + 2


class _Changes:
    """The two hooks `OverlaySession` installs, and a rewrite that marks rows."""

    zone_of: Any = None
    pair_rows: Any = None

    def rewrite(self, query: str, params: Any, rows: Any) -> Any:
        return [dict(r, rewritten=True) for r in rows]


def test_the_overlay_session_uses_the_inner_session_cache() -> None:
    store = _Store()
    inner = CycleSession(store, 42)
    overlaid = fw_overlay_read.OverlaySession(inner, _Changes())  # type: ignore[arg-type]
    assert overlaid._read_cache is inner._read_cache
    plain = pathmod._read(inner, "Q")
    rewritten = pathmod._read(overlaid, "Q")
    assert len(store.queries) == 1
    assert "rewritten" not in plain[0]
    assert rewritten[0]["rewritten"] is True
    assert "rewritten" not in pathmod._read(inner, "Q")[0]
    assert len(store.queries) == 1


def test_the_overlay_session_over_a_plain_session_has_no_cache() -> None:
    store = _Store()
    overlaid = fw_overlay_read.OverlaySession(store, _Changes())  # type: ignore[arg-type]
    assert overlaid._read_cache is None
    pathmod._read(overlaid, "Q")
    pathmod._read(overlaid, "Q")
    assert len(store.queries) == 2
