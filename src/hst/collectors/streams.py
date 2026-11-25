"""`MappedRows` and `ChainRows` build each row when it is read."""

from __future__ import annotations

import itertools
import operator
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Any

# The window size is in characters.
WINDOW_CHARS = 1 << 20

_END = object()


def line_windows(text: str, start: int = 0, size: int | None = None) -> Iterator[str]:
    """Each slice of `text[start:]` ends right after a '\\n', except the last."""
    if size is None:
        size = WINDOW_CHARS
    if size < 1:
        raise ValueError(f"window size must be at least 1, not {size}")
    pos, end, _ = slice(start, None).indices(len(text))
    while pos < end:
        limit = pos + size
        if limit >= end:
            yield text[pos:]
            return
        cut = text.rfind("\n", pos, limit)
        if cut < 0:
            # A line longer than the window is yielded whole.
            cut = text.find("\n", limit)
            if cut < 0:
                yield text[pos:]
                return
        yield text[pos : cut + 1]
        pos = cut + 1


class RowMappingError(Exception):
    """A row of a row view could not be built."""

    def __init__(self, original: BaseException) -> None:
        super().__init__(f"{type(original).__name__}: {original}")
        self.original = original

    def __reduce__(self) -> tuple[Any, ...]:
        return (type(self), (self.original,), self.__dict__)


class _RowView(Sequence[dict[str, Any]]):
    """A subclass supplies `__len__` and `__iter__`."""

    # A view compares equal to a list and is unhashable like a list.
    __hash__ = None  # type: ignore[assignment]

    def __getitem__(self, index: int | slice) -> Any:
        if isinstance(index, slice):
            return list(self)[index]
        size = len(self)
        position = operator.index(index)
        if position < 0:
            position += size
        if not 0 <= position < size:
            raise IndexError(f"{type(self).__name__} index out of range")
        for row in itertools.islice(self, position, None):
            return row
        raise IndexError(f"{type(self).__name__} index out of range")

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (str, bytes)) or not isinstance(other, Sequence):
            return NotImplemented
        return list(self) == list(other)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} len={len(self)}>"


class MappedRows(_RowView):
    """The view calls `fn` on each item of `source` on every read."""

    def __init__(self, source: Sequence[Any], fn: Callable[[Any], dict[str, Any]]) -> None:
        self._source = source
        self._fn = fn

    def __len__(self) -> int:
        return len(self._source)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        fn = self._fn
        try:
            items = iter(self._source)
        except RowMappingError:
            raise
        except Exception as exc:
            raise RowMappingError(exc) from exc
        while True:
            try:
                item = next(items, _END)
                if item is _END:
                    return
                row = fn(item)
            except RowMappingError:
                raise
            except Exception as exc:
                raise RowMappingError(exc) from exc
            # A consumer's exception thrown into this generator stays unwrapped.
            yield row


class ChainRows(_RowView):
    """`parts` pairs each part's row count with a factory that returns a fresh
    iterable of its rows."""

    def __init__(self, parts: Iterable[tuple[int, Callable[[], Iterable[dict[str, Any]]]]]) -> None:
        self._parts = tuple(parts)
        self._len = sum(count for count, _ in self._parts)

    def __len__(self) -> int:
        return self._len

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for index, (count, factory) in enumerate(self._parts):
            seen = 0
            for row in factory():
                seen += 1
                if seen > count:
                    raise RowMappingError(
                        RuntimeError(f"ChainRows part {index} yielded more than its {count} row(s)")
                    )
                yield row
            if seen != count:
                raise RowMappingError(
                    RuntimeError(f"ChainRows part {index} yielded {seen} of its {count} row(s)")
                )
