"""`jsonstream.iter_json` gives what `json.dumps` gives beyond the shapes of tests/test_jsonstream.py."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from typing import Any

import pytest

from hst.core import jsonstream
from hst.core.jsonstream import WALKED_LEVELS, iter_json

SEPARATORS = (",", ":")


def _dumps(obj: Any, sort_keys: bool) -> str:
    return json.dumps(obj, sort_keys=sort_keys, default=str, separators=SEPARATORS)


def _streamed(obj: Any, sort_keys: bool, max_depth: int) -> str:
    return "".join(iter_json(obj, sort_keys=sort_keys, separators=SEPARATORS, max_depth=max_depth))


class _Inheriting(dict):
    """Reads its items through `dict.items`, as the encoder does."""


class _OwnItems(dict):
    """Given an `items` of its own on the instance."""


class _Shadowing(dict):
    """Answers `items` through `__getattribute__`."""

    def __getattribute__(self, name: str) -> Any:
        if name == "items":
            return lambda: [("shadowed", {"n": 1})]
        return super().__getattribute__(name)


def _own_items() -> _OwnItems:
    value = _OwnItems(a=1, b="x")
    value.items = lambda: [("other", [2, 3])]  # type: ignore[method-assign]
    return value


@pytest.mark.parametrize("sort_keys", [False, True])
@pytest.mark.parametrize("max_depth", [1, 2, 3])
def test_a_subclass_is_read_by_the_items_the_encoder_finds(sort_keys: bool, max_depth: int) -> None:
    for value in (_own_items(), _Shadowing(a=1), _Inheriting(b={"c": 2}, a="x")):
        obj = {"payload": value, "z": 1}
        assert _streamed(obj, sort_keys, max_depth) == _dumps(obj, sort_keys), type(value).__name__


def test_only_an_items_that_is_dict_items_bound_to_the_value_is_walked() -> None:
    assert jsonstream._walks_items({})
    assert jsonstream._walks_items(_Inheriting(a=1))
    assert not jsonstream._walks_items(_own_items())
    assert not jsonstream._walks_items(_Shadowing(a=1))


def test_a_walk_stops_at_walked_levels_whatever_max_depth_asks(monkeypatch: pytest.MonkeyPatch) -> None:
    depths: list[int] = []
    real = jsonstream._Encoder.mapping

    def spy(self: Any, value: Any, items: Any, depth: int) -> Any:
        depths.append(depth)
        return real(self, value, items, depth)

    monkeypatch.setattr(jsonstream._Encoder, "mapping", spy)
    obj: dict[str, Any] = {}
    level = obj
    for index in range(3 * WALKED_LEVELS):
        level["n"] = {"i": index}
        level = level["n"]

    assert _streamed(obj, True, 100_000) == _dumps(obj, True)
    assert max(depths) == WALKED_LEVELS - 1
    depths.clear()
    assert _streamed(obj, True, 3) == _dumps(obj, True)
    assert max(depths) == 2


class _Unprintable:
    def __str__(self) -> str:
        raise TypeError("no text for this value")


def _failing() -> list[Any]:
    """Values `json.dumps` cannot encode, each failing at another depth and
    through another kind of container."""
    self_loop: dict[str, Any] = {"a": "x"}
    self_loop["self"] = self_loop
    list_loop: dict[str, Any] = {"a": "x"}
    list_loop["l"] = [1, {"back": list_loop}]
    via: dict[str, Any] = {"inner": {"back": None}}
    via["inner"]["back"] = via
    return [
        self_loop,
        list_loop,
        via,
        {"payload": self_loop},
        {"a": {"b": {"c": {"d": _Unprintable()}}}},
        {"a": _Inheriting(k={(1, 2): 3})},
        {"a": {"b": 10**5000}},
        {"x": [1, {"y": 10**5000}]},
        {"x": {"y": [{"z": _Unprintable()}]}},
    ]


# The digit limit on an int's text that CPython applies by default. The two
# `10**5000` values fail to encode only under a limit below their 5001
# digits, which PYTHONINTMAXSTRDIGITS can lift, so the test sets it itself.
INT_MAX_STR_DIGITS = 4300


@pytest.fixture()
def _int_digit_limit() -> Iterator[None]:
    before = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(INT_MAX_STR_DIGITS)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(before)


def _raised(fn: Any) -> tuple[type[BaseException], str, list[str] | None]:
    with pytest.raises(Exception) as caught:
        fn()
    return type(caught.value), str(caught.value), getattr(caught.value, "__notes__", None)


@pytest.mark.usefixtures("_int_digit_limit")
@pytest.mark.parametrize("sort_keys", [False, True])
@pytest.mark.parametrize("max_depth", [0, 1, 2, 5, 100_000])
def test_a_value_that_cannot_be_encoded_raises_what_dumps_raises(sort_keys: bool, max_depth: int) -> None:
    for obj in _failing():
        expected = _raised(lambda obj=obj: _dumps(obj, sort_keys))
        assert _raised(lambda obj=obj: _streamed(obj, sort_keys, max_depth)) == expected
