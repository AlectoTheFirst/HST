"""The trace warning for a device whose state is carried forward (hst.path.trace_draw)."""

from __future__ import annotations

from typing import Any

import pytest

from hst.core import cycle
from hst.path import session as path_session
from hst.path.gates import routing
from hst.path.trace_draw import _CARRIED_WHY, _warn_carried


class _Trail:
    def __init__(self) -> None:
        self.warnings: list[str] = []

    def warn(self, text: str) -> None:
        self.warnings.append(text)


def _warned(dev: dict[str, Any]) -> list[str]:
    trail = _Trail()
    _warn_carried(trail, {"dev_uid": "dev:core1", "dev_name": "core1", **dev})  # type: ignore[arg-type]
    return trail.warnings


@pytest.mark.parametrize("key", ["dev_carried_reason", "carried_reason"])
def test_a_device_fetched_and_found_unchanged_is_not_warned(key: str) -> None:
    assert _warned({key: cycle.UNCHANGED}) == []


@pytest.mark.parametrize("key", ["dev_carried_reason", "carried_reason"])
def test_each_other_reason_is_named(key: str) -> None:
    for reason in cycle.CARRY_REASONS:
        if reason == cycle.UNCHANGED:
            continue
        assert _warned({key: reason}) == [
            f"core1: state carried forward from an earlier run ({_CARRIED_WHY[reason]})"
        ]


def test_a_carried_device_with_no_recorded_reason_reads_as_a_source_that_did_not_run() -> None:
    assert _warned({}) == [
        "core1: state carried forward from an earlier run (its source did not run this cycle)"
    ]


def test_each_carry_reason_has_words_or_is_unchanged() -> None:
    assert set(cycle.CARRY_REASONS) == {*_CARRIED_WHY, cycle.UNCHANGED}


def test_each_query_that_reads_the_carried_mark_reads_its_reason() -> None:
    assert "d.carried_reason AS dev_carried_reason" in path_session.GATEWAYS
    queries = [
        value
        for value in vars(routing).values()
        if isinstance(value, str) and "coalesce(d.carried, false) AS carried" in value
    ]
    assert len(queries) == 2
    assert all("d.carried_reason AS carried_reason" in query for query in queries)
