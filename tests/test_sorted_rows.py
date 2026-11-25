"""The bounded external sort the finalize reads stream through
(core/cycle.py `SortedRows`, `read_sorted`)."""

from __future__ import annotations

import math
import random
from operator import itemgetter
from typing import Any

import pytest
from neo4j.spatial import WGS84Point
from neo4j.time import Date, DateTime, Duration

from hst.core import cycle as cyclemod
from hst.core.cycle import SortedRows, read_sorted


@pytest.mark.parametrize(("bucket", "fan_in"), [(1, 2), (2, 2), (3, 3), (7, 2), (10, 4), (1000, 32)])
def test_the_rows_come_back_as_a_stable_sort_of_all_of_them_gives_them(bucket, fan_in):
    rng = random.Random(bucket * 100 + fan_in)
    pairs = [((rng.choice("abcde"), rng.randrange(4)), {"n": i}) for i in range(500)]
    with SortedRows(bucket, fan_in) as rows:
        for key, row in pairs:
            rows.add(key, row)
        assert list(rows) == sorted(pairs, key=itemgetter(0))


@pytest.fixture
def opened(monkeypatch) -> list[Any]:
    """Every temporary file a `SortedRows` opens, in order."""
    files: list[Any] = []
    real = cyclemod.tempfile.TemporaryFile

    def tracked(*args: Any, **kwargs: Any) -> Any:
        files.append(real(*args, **kwargs))
        return files[-1]

    monkeypatch.setattr(cyclemod.tempfile, "TemporaryFile", tracked)
    return files


def test_the_rows_held_and_the_files_open_stay_bounded(opened):
    """Fewer than `fan_in` runs of each level are open, and the levels grow
    with the logarithm of the rows: 80 buckets of five at a fan-in of three
    make four levels."""
    with SortedRows(5, 3) as rows:
        for i in range(400):
            rows.add((i * 7919) % 400, i)
            assert len(rows._held) < 5
            assert all(len(level) < 3 for level in rows._levels)
            assert sum(not f.closed for f in opened) == sum(map(len, rows._levels))
        assert len(rows._levels) == 4
        entries = iter(rows)
        # read back through at most `fan_in` runs
        assert sum(not f.closed for f in opened) <= 3
        assert [key for key, _row in entries] == list(range(400))
    assert opened and all(f.closed for f in opened)


def test_each_row_is_rewritten_once_per_level_it_climbs(monkeypatch):
    """1,024 rows in buckets of four at a fan-in of four: 256 runs, which
    climb four levels to one run, so every row is written five times. The
    writes grow with the rows times the logarithm of the runs, not with the
    square of the runs."""
    written = 0
    real = SortedRows._write

    def counted(self: SortedRows, entries: Any) -> Any:
        def each() -> Any:
            nonlocal written
            for entry in entries:
                written += 1
                yield entry

        return real(self, each())

    monkeypatch.setattr(SortedRows, "_write", counted)
    with SortedRows(4, 4) as rows:
        for i in range(1024):
            rows.add(1023 - i, i)
        assert [len(level) for level in rows._levels] == [0, 0, 0, 0, 1]
        assert written == 1024 * 5
        assert [key for key, _row in rows] == list(range(1024))
    assert written == 1024 * 5


@pytest.mark.parametrize("count", [17, 63, 64, 65, 250, 1000])
def test_reading_back_merges_the_lower_levels_until_at_most_fan_in_runs_remain(count, opened):
    with SortedRows(1, 4) as rows:
        for i in range(count):
            rows.add(i % 7, i)
        before = sum(map(len, rows._levels))
        entries = iter(rows)
        open_runs = sum(not f.closed for f in opened)
        assert open_runs == sum(map(len, rows._levels))
        assert open_runs <= 4 and (before > 4 or open_runs == before)
        assert list(entries) == sorted(((i % 7, i) for i in range(count)), key=itemgetter(0))


def test_close_releases_the_files_whether_or_not_the_rows_were_read(monkeypatch):
    opened: list[Any] = []
    real = cyclemod.tempfile.TemporaryFile
    monkeypatch.setattr(
        cyclemod.tempfile, "TemporaryFile", lambda *a, **k: opened.append(real(*a, **k)) or opened[-1]
    )
    rows = SortedRows(2, 8)
    for i in range(9):
        rows.add(i, i)
    rows.close()
    assert len(opened) == 4 and all(f.closed for f in opened)


def test_the_drivers_values_come_back_unchanged():
    values = [
        DateTime(2026, 9, 27, 1, 2, 3, 123456789),
        Date(2026, 9, 27),
        Duration(months=1, nanoseconds=5),
        WGS84Point((1.5, 2.5)),
        b"\x00\xff",
        -0.0,
        1500,
        1500.0,
        True,
        ["a", 1, 2.5],
        "é中",
    ]
    with SortedRows(2, 2) as rows:
        for i, value in enumerate(values):
            rows.add(i, {"v": value})
        out = [row["v"] for _key, row in rows]
    assert [(type(v), v) for v in out] == [(type(v), v) for v in values]
    assert math.copysign(1, out[5]) == -1


class _Result:
    def __init__(self, rows: list[dict[str, Any]], fail_after: int | None = None) -> None:
        self._rows = rows
        self._fail_after = fail_after
        self.iterated = False

    def __iter__(self):
        self.iterated = True
        for i, row in enumerate(self._rows):
            if self._fail_after is not None and i == self._fail_after:
                raise ConnectionResetError("the connection dropped mid-read")
            yield row


class _RetryingSession:
    """Calls the work once more after it fails, as the driver's managed
    transactions do on a transient failure."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self.results: list[_Result] = []

    def execute_read(self, work: Any) -> Any:
        try:
            return work(self)
        except ConnectionResetError:
            return work(self)

    def run(self, query: str, **params: Any) -> _Result:
        self.results.append(_Result(self._rows, fail_after=5 if not self.results else None))
        return self.results[-1]


def test_a_retried_read_starts_over_and_releases_what_the_failed_attempt_wrote(opened, monkeypatch):
    """The first attempt spills two runs of two rows before the connection
    drops at its sixth row; the second reads all twelve into six runs."""
    monkeypatch.setattr(cyclemod, "SPILL_ROWS", 2)
    session = _RetryingSession([{"k": i % 3, "n": i} for i in range(12)])

    with read_sorted(session, "MATCH (n) RETURN n", lambda r: (r["k"], r["n"])) as rows:
        assert len(opened) == 8
        assert [f.closed for f in opened] == [True, True] + [False] * 6
        assert [n for _k, n in rows] == [0, 3, 6, 9, 1, 4, 7, 10, 2, 5, 8, 11]
    assert len(session.results) == 2 and all(result.iterated for result in session.results)
    assert all(f.closed for f in opened)


def test_a_result_that_is_already_a_list_is_read_through_data():
    class _Listed:
        def data(self) -> list[dict[str, Any]]:
            return [{"k": 2}, {"k": 1}]

    class _Session:
        def execute_read(self, work: Any) -> Any:
            return work(self)

        def run(self, query: str, **params: Any) -> _Listed:
            return _Listed()

    with read_sorted(_Session(), "q", lambda r: (r["k"], r)) as rows:
        assert [row for _k, row in rows] == [{"k": 1}, {"k": 2}]
