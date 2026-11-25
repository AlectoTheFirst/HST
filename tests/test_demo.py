"""`hst.demo`: the validation scenario suite pins to one run for the whole
run."""

from __future__ import annotations

from typing import Any

from hst import demo


class _FakeRecord:
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def data(self) -> dict[str, Any]:
        return self._data


class _FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self._rows

    def __iter__(self):
        return iter(_FakeRecord(r) for r in self._rows)


class FakeSession:
    """Answers the pointer read plus every scenario's managed read, recording the
    params each scenario ran with."""

    def __init__(self, current: int | None = None) -> None:
        self._current = current
        self.pointer_calls = 0
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run(self, query: str, **params: Any) -> _FakeResult:
        # the autocommit pointer read core.cycle.current_ts_or_none issues
        self.pointer_calls += 1
        rows = [{"current": self._current}] if self._current is not None else []
        return _FakeResult(rows)

    def execute_read(self, work: Any) -> Any:
        def tx_run(query: str, **params: Any) -> _FakeResult:
            self.calls.append((query, params))
            return _FakeResult([])

        tx = type("Tx", (), {"run": staticmethod(tx_run)})()
        return work(tx)


def test_every_scenario_cypher_references_snap() -> None:
    for sc in demo.SCENARIOS:
        assert ":Latest" not in sc["cypher"], sc["key"]
        assert "$snap" in sc["cypher"], sc["key"]


def test_run_all_resolves_the_pointer_once_for_the_whole_suite() -> None:
    session = FakeSession(current=4242)

    demo.run_all(session)

    assert session.pointer_calls == 1
    assert len(session.calls) == len(demo.SCENARIOS)
    assert all(params.get("snap") == 4242 for _, params in session.calls)


def test_run_all_falls_back_to_the_live_sentinel_with_no_pointer() -> None:
    session = FakeSession(current=None)

    demo.run_all(session)

    assert all(params.get("snap") == "live" for _, params in session.calls)


def test_run_all_reports_the_scenario_key_even_on_error() -> None:
    class _RaisingSession(FakeSession):
        def execute_read(self, work: Any) -> Any:
            raise RuntimeError("boom")

    results = demo.run_all(_RaisingSession(current=1))
    assert len(results) == len(demo.SCENARIOS)
    assert all(r["ok"] is False and r["error"] == "boom" for r in results)
