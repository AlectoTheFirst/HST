"""streams: line-aligned windows over a text, and the read-only row views."""

from __future__ import annotations

import random

import pytest

from hst.collectors import streams
from hst.collectors.streams import ChainRows, MappedRows, RowMappingError, line_windows

# --- line_windows -------------------------------------------------------------------

# Every line separator `str.splitlines` knows, the '\r\n' pair, and plain text, so a
# random text puts each separator next to every other and next to a window cut.
_PIECES = [
    "a",
    "bc",
    " ",
    "route 10.0.0.0/8",
    "\n",
    "\n",
    "\n",
    "\r\n",
    "\r",
    "\x85",
    "\u2028",
    "\u2029",
    "\x0b",
    "\x0c",
    "\x1c",
    "\x1d",
    "\x1e",
    "\n\n",
]


def _random_text(rnd: random.Random) -> str:
    parts = [rnd.choice(_PIECES) for _ in range(rnd.randrange(0, 60))]
    if rnd.random() < 0.3:
        # A line longer than any window size used below.
        parts.insert(rnd.randrange(len(parts) + 1), "x" * rnd.randrange(40, 200))
    return "".join(parts)


def _check_windows(text: str, start: int, size: int) -> None:
    windows = list(line_windows(text, start, size))
    rest = text[start:]
    assert "".join(windows) == rest
    assert [line for w in windows for line in w.splitlines()] == rest.splitlines()
    assert all(windows), "no window is empty"
    for w in windows[:-1]:
        assert w.endswith("\n")
    for w in windows:
        # Longer than `size` only when it is one line that is itself longer.
        if len(w) > size:
            assert "\n" not in w[:-1]


def test_windows_join_back_and_split_into_the_same_lines_over_random_texts():
    rnd = random.Random(20260926)
    for _ in range(3000):
        text = _random_text(rnd)
        start = rnd.choice([0, 0, rnd.randrange(len(text) + 2)])
        size = rnd.choice([1, 2, 3, 7, 16, 64, 1 << 20])
        _check_windows(text, start, size)


def test_crlf_text_never_splits_a_pair():
    text = "one\r\ntwo\r\nthree\r\n" * 50
    for size in (1, 2, 4, 5, 6, 11):
        windows = list(line_windows(text, 0, size))
        assert all(w.endswith("\r\n") for w in windows)
        _check_windows(text, 0, size)


def test_separators_other_than_newline_stay_inside_a_window():
    text = "a\rb\x85c\u2028d\ne\r\nf"
    assert list(line_windows(text, 0, 1)) == ["a\rb\x85c\u2028d\n", "e\r\n", "f"]


def test_a_window_holds_whole_lines_up_to_the_size():
    text = "aaa\nbbb\nccc\nddd\n"
    assert list(line_windows(text, 0, 8)) == ["aaa\nbbb\n", "ccc\nddd\n"]
    assert list(line_windows(text, 0, 9)) == ["aaa\nbbb\n", "ccc\nddd\n"]
    assert list(line_windows(text, 0, 7)) == ["aaa\n", "bbb\n", "ccc\n", "ddd\n"]
    assert list(line_windows(text, 0, 100)) == [text]


def test_a_line_longer_than_the_window_is_one_window():
    text = "short\n" + "y" * 50 + "\nend"
    assert list(line_windows(text, 0, 10)) == ["short\n", "y" * 50 + "\n", "end"]
    assert list(line_windows("z" * 30, 0, 4)) == ["z" * 30]


def test_one_character_windows_give_one_line_each():
    text = "a\n\nbb\nccc"
    assert list(line_windows(text, 0, 1)) == ["a\n", "\n", "bb\n", "ccc"]


def test_an_empty_remainder_yields_nothing():
    assert list(line_windows("")) == []
    assert list(line_windows("abc\n", 4)) == []
    assert list(line_windows("abc\n", 99)) == []


def test_a_start_offset_windows_the_rest_of_the_text():
    text = "banner\nmore banner\nreal output\nsecond\n"
    offset = text.index("real")
    assert "".join(line_windows(text, offset, 5)) == text[offset:]
    assert list(line_windows(text, offset, 5)) == ["real output\n", "second\n"]
    # A negative start counts from the end, as a slice does.
    assert "".join(line_windows(text, -7, 3)) == text[-7:]


def test_the_default_size_is_the_module_window():
    assert streams.WINDOW_CHARS == 1 << 20
    line = "x" * 99 + "\n"
    text = line * ((3 << 20) // len(line))
    windows = list(line_windows(text))
    # As many whole lines as fit in the window, then the rest.
    full = streams.WINDOW_CHARS // len(line) * len(line)
    assert [len(w) for w in windows] == [full, full, full, len(text) - 3 * full]
    assert "".join(windows) == text


def test_a_window_size_below_one_is_refused():
    with pytest.raises(ValueError, match="at least 1"):
        list(line_windows("a\n", 0, 0))


# --- RowMappingError ----------------------------------------------------------------


def test_row_mapping_error_names_the_original():
    original = KeyError("prefix")
    exc = RowMappingError(original)
    assert exc.original is original
    assert str(exc) == "KeyError: 'prefix'"
    assert str(RowMappingError(ValueError("bad metric"))) == "ValueError: bad metric"


# --- MappedRows ---------------------------------------------------------------------


def _double(item: int) -> dict[str, int]:
    return {"n": item, "twice": item * 2}


def test_mapped_rows_has_the_source_length_and_the_mapped_rows():
    rows = MappedRows([1, 2, 3], _double)
    assert len(rows) == 3
    assert list(rows) == [_double(1), _double(2), _double(3)]
    assert bool(rows) is True
    assert bool(MappedRows([], _double)) is False


def test_each_pass_builds_fresh_equal_dicts():
    rows = MappedRows([1, 2], _double)
    first = list(rows)
    first[0]["n"] = 99
    second = list(rows)
    assert second == [_double(1), _double(2)]
    assert first[1] is not second[1]


def test_mapped_rows_is_lazy():
    calls: list[int] = []

    def fn(item: int) -> dict[str, int]:
        calls.append(item)
        return {"n": item}

    rows = MappedRows([1, 2, 3], fn)
    assert len(rows) == 3
    assert calls == []
    assert next(iter(rows)) == {"n": 1}
    assert calls == [1]


def test_mapped_rows_indexing():
    rows = MappedRows([10, 20, 30], _double)
    assert rows[0] == _double(10)
    assert rows[2] == _double(30)
    assert rows[-1] == _double(30)
    assert rows[-3] == _double(10)
    for bad in (3, 4, -4):
        with pytest.raises(IndexError):
            rows[bad]
    with pytest.raises(TypeError):
        rows["0"]  # type: ignore[index]


def test_mapped_rows_slices_are_lists():
    rows = MappedRows([10, 20, 30, 40], _double)
    assert rows[1:3] == [_double(20), _double(30)]
    assert isinstance(rows[1:3], list)
    assert rows[::-1] == [_double(40), _double(30), _double(20), _double(10)]
    assert rows[5:] == []


def test_mapped_rows_compares_equal_to_lists_and_sequences():
    rows = MappedRows([1, 2], _double)
    assert rows == [_double(1), _double(2)]
    assert [_double(1), _double(2)] == rows
    assert rows == (_double(1), _double(2))
    assert rows == MappedRows([1, 2], _double)
    assert rows != [_double(1)]
    assert rows != [_double(2), _double(1)]
    assert MappedRows([], _double) == []
    assert [] == MappedRows([], _double)  # noqa: SIM300 - the reflected comparison is the case
    assert MappedRows([], _double) != ""
    assert MappedRows([], _double) != b""
    assert rows != {"n": 1}
    assert rows != 1


def test_mapped_rows_is_unhashable_and_names_its_length():
    rows = MappedRows([1, 2, 3], _double)
    with pytest.raises(TypeError):
        hash(rows)
    assert repr(rows) == "<MappedRows len=3>"


def test_mapped_rows_membership_and_count_iterate():
    rows = MappedRows([1, 2, 2], _double)
    assert _double(2) in rows
    assert _double(5) not in rows
    assert rows.count(_double(2)) == 2


def test_an_error_in_fn_is_a_row_mapping_error():
    def fn(item: dict[str, str]) -> dict[str, str]:
        return {"prefix": item["network"]}

    rows = MappedRows([{"network": "10.0.0.0"}, {}], fn)
    with pytest.raises(RowMappingError) as caught:
        list(rows)
    assert isinstance(caught.value.original, KeyError)
    assert caught.value.__cause__ is caught.value.original
    assert str(caught.value) == "KeyError: 'network'"
    # The rows before the bad one were built.
    iterator = iter(rows)
    assert next(iterator) == {"prefix": "10.0.0.0"}
    with pytest.raises(RowMappingError):
        next(iterator)


def test_a_stop_iteration_from_fn_is_an_error_not_the_end():
    def fn(item: int) -> dict[str, int]:
        if item == 2:
            raise StopIteration
        return {"n": item}

    with pytest.raises(RowMappingError) as caught:
        list(MappedRows([1, 2, 3], fn))
    assert isinstance(caught.value.original, StopIteration)


class _BrokenSource(list):
    """A list whose iterator fails after `good` items."""

    def __init__(self, items: list[int], good: int) -> None:
        super().__init__(items)
        self.good = good

    def __iter__(self):
        for position, item in enumerate(list.__iter__(self)):
            if position == self.good:
                raise OSError("source went away")
            yield item


class _UniterableSource(list):
    def __iter__(self):
        raise RuntimeError("cannot iterate")


def test_an_error_in_the_source_is_a_row_mapping_error():
    rows = MappedRows(_BrokenSource([1, 2, 3], good=1), _double)
    assert len(rows) == 3
    with pytest.raises(RowMappingError) as caught:
        list(rows)
    assert isinstance(caught.value.original, OSError)
    assert str(caught.value) == "OSError: source went away"

    with pytest.raises(RowMappingError) as caught:
        list(MappedRows(_UniterableSource([1]), _double))
    assert isinstance(caught.value.original, RuntimeError)


def test_a_row_mapping_error_passes_through_unwrapped():
    def fn(item: int) -> dict[str, int]:
        raise RowMappingError(ValueError("inner"))

    inner = MappedRows([1], fn)
    outer = MappedRows(inner, lambda row: row)
    with pytest.raises(RowMappingError) as caught:
        list(outer)
    assert isinstance(caught.value.original, ValueError)

    with pytest.raises(RowMappingError) as caught:
        list(MappedRows([1], fn))
    assert isinstance(caught.value.original, ValueError)


def test_indexing_surfaces_the_error_of_a_row_it_passes():
    def fn(item: int) -> dict[str, int]:
        if item == 1:
            raise ValueError("bad row")
        return {"n": item}

    rows = MappedRows([0, 1, 2], fn)
    assert rows[0] == {"n": 0}
    with pytest.raises(RowMappingError):
        rows[2]


def test_an_exception_thrown_in_by_the_consumer_is_not_wrapped():
    iterator = iter(MappedRows([1, 2], _double))
    next(iterator)
    with pytest.raises(KeyError):
        iterator.throw(KeyError("consumer"))


def test_a_view_over_a_view():
    base = MappedRows([1, 2, 3], _double)
    rows = MappedRows(base, lambda row: {"n": row["n"] + 1})
    assert len(rows) == 3
    assert rows == [{"n": 2}, {"n": 3}, {"n": 4}]


# --- ChainRows ----------------------------------------------------------------------


def _part(*values: int):
    return lambda: ({"v": value} for value in values)


def test_chain_rows_yields_every_part_in_order():
    rows = ChainRows([(2, _part(1, 2)), (0, _part()), (1, _part(3))])
    assert len(rows) == 3
    assert list(rows) == [{"v": 1}, {"v": 2}, {"v": 3}]
    assert list(rows) == [{"v": 1}, {"v": 2}, {"v": 3}]
    assert bool(rows) is True
    assert bool(ChainRows([])) is False
    assert ChainRows([]) == []
    assert ChainRows([(0, _part())]) == []


def test_chain_rows_calls_each_factory_on_every_pass():
    calls: list[str] = []

    def factory():
        calls.append("built")
        return [{"v": 1}]

    rows = ChainRows([(1, factory)])
    assert len(rows) == 1
    assert calls == []
    first, second = list(rows), list(rows)
    assert first == second == [{"v": 1}]
    assert calls == ["built", "built"]


def test_chain_rows_takes_any_iterable_of_parts_once():
    rows = ChainRows((count, factory) for count, factory in [(1, _part(1)), (1, _part(2))])
    assert len(rows) == 2
    assert list(rows) == list(rows) == [{"v": 1}, {"v": 2}]


def test_chain_rows_indexing_slices_and_equality():
    rows = ChainRows([(2, _part(1, 2)), (2, _part(3, 4))])
    assert rows[0] == {"v": 1}
    assert rows[2] == {"v": 3}
    assert rows[-1] == {"v": 4}
    assert rows[-4] == {"v": 1}
    for bad in (4, -5):
        with pytest.raises(IndexError):
            rows[bad]
    assert rows[1:3] == [{"v": 2}, {"v": 3}]
    assert rows == [{"v": 1}, {"v": 2}, {"v": 3}, {"v": 4}]
    assert [{"v": 1}, {"v": 2}, {"v": 3}, {"v": 4}] == rows  # noqa: SIM300 - the reflected comparison is the case
    assert rows != [{"v": 1}]
    assert rows == MappedRows([1, 2, 3, 4], lambda v: {"v": v})
    assert repr(rows) == "<ChainRows len=4>"
    with pytest.raises(TypeError):
        hash(rows)


def test_a_part_with_fewer_rows_than_its_count_raises():
    rows = ChainRows([(1, _part(1)), (3, _part(2, 3)), (1, _part(4))])
    seen: list[dict[str, int]] = []
    with pytest.raises(RowMappingError) as caught:
        for row in rows:
            seen.append(row)
    assert seen == [{"v": 1}, {"v": 2}, {"v": 3}]
    assert isinstance(caught.value.original, RuntimeError)
    assert str(caught.value) == "RuntimeError: ChainRows part 1 yielded 2 of its 3 row(s)"


def test_a_part_with_more_rows_than_its_count_raises_before_the_extra_row():
    rows = ChainRows([(1, _part(1, 2)), (1, _part(3))])
    seen: list[dict[str, int]] = []
    with pytest.raises(RowMappingError) as caught:
        for row in rows:
            seen.append(row)
    assert seen == [{"v": 1}]
    assert isinstance(caught.value.original, RuntimeError)
    assert str(caught.value) == "RuntimeError: ChainRows part 0 yielded more than its 1 row(s)"


def test_an_error_inside_a_part_passes_through():
    def factory():
        yield {"v": 1}
        raise ValueError("unreadable path line")

    with pytest.raises(ValueError, match="unreadable path line"):
        list(ChainRows([(2, factory)]))

    def broken_factory():
        raise KeyError("text")

    with pytest.raises(KeyError):
        list(ChainRows([(1, broken_factory)]))


def test_mapped_rows_over_chain_rows_wraps_a_part_error_once():
    def factory():
        raise ValueError("unreadable path line")
        yield {}

    rows = MappedRows(ChainRows([(1, factory)]), lambda row: row)
    with pytest.raises(RowMappingError) as caught:
        list(rows)
    assert isinstance(caught.value.original, ValueError)

    mismatch = MappedRows(ChainRows([(2, _part(1))]), lambda row: row)
    with pytest.raises(RowMappingError) as caught:
        list(mismatch)
    assert isinstance(caught.value.original, RuntimeError)
