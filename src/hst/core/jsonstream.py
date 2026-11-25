"""The text is exactly `json.dumps(obj, sort_keys=sort_keys, default=str,
separators=separators)` with `ensure_ascii`, `allow_nan` and
`check_circular` at their defaults."""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Callable, Iterable, Iterator
from json.encoder import encode_basestring_ascii
from operator import itemgetter
from typing import Any

_BY_KEY = itemgetter(0)

# A pass walks at most this number of dict levels. A larger `max_depth` is cut to it.
WALKED_LEVELS = 16

# Whether `json.dumps` notes the path to a value it cannot encode on the
# exception it raises (Python 3.14 and later).
_NOTES = sys.version_info >= (3, 14)

# The C encoder factory `JSONEncoder.iterencode` uses, None without the C
# accelerator.
_C_MAKE_ENCODER: Callable[..., Callable[[Any, int], Iterable[str]]] | None = getattr(
    json.encoder, "c_make_encoder", None
)


def _type_name(cls: type) -> str:
    """The name of a type as the notes of the C encoder print it. The name has
    the module as a prefix unless the module is `builtins` or `__main__`."""
    module = cls.__module__
    return cls.__qualname__ if module in ("builtins", "__main__") else f"{module}.{cls.__qualname__}"


def _walks_items(value: dict[Any, Any]) -> bool:
    """Whether the C encoder reads the items of `value` through `dict.items`.

    True for an exact dict. True for a subclass when the attribute `items` of
    the instance is `dict.items` bound to `value`. False when the read of
    `items` raises. The encoder then raises the same exception."""
    if type(value) is dict:
        return True
    try:
        found = value.items
    except Exception:
        return False
    # bound builtin methods are equal when they bind the same method to the
    # same object
    return bool(found == dict.items.__get__(value))


class _Encoder:
    """The options of one encoding pass and the dicts on the current path."""

    __slots__ = ("item_sep", "key_sep", "max_depth", "open", "slice_chars", "sort_keys", "whole")

    def __init__(
        self, sort_keys: bool, separators: tuple[str, str], max_depth: int, slice_chars: int
    ) -> None:
        self.sort_keys = sort_keys
        self.item_sep, self.key_sep = separators
        self.max_depth = min(max_depth, WALKED_LEVELS)
        self.slice_chars = slice_chars
        # The dicts on the current path, by id. The C encoder gets this dict as its
        # `markers`. A value encoded whole that refers back to one of the dicts
        # raises "Circular reference detected", as `json.dumps` of the whole
        # document does.
        self.open: dict[int, Any] = {}
        self.whole = self._whole_encoder(sort_keys, separators)

    def _whole_encoder(self, sort_keys: bool, separators: tuple[str, str]) -> Callable[[Any], str]:
        if _C_MAKE_ENCODER is None:
            return json.JSONEncoder(sort_keys=sort_keys, default=str, separators=separators).encode
        item_sep, key_sep = separators
        encode = _C_MAKE_ENCODER(
            self.open, str, encode_basestring_ascii, None, key_sep, item_sep, sort_keys, False, True
        )

        def whole(value: Any) -> str:
            return "".join(encode(value, 0))

        return whole

    def items(self, value: Any, depth: int) -> Iterable[tuple[str, Any]] | None:
        """The items to walk `value` by, or None when it is encoded whole."""
        if depth >= self.max_depth or not isinstance(value, dict) or id(value) in self.open:
            return None
        if not _walks_items(value):
            return None
        for key in dict.keys(value):
            if type(key) is not str:
                return None
        if self.sort_keys:
            return sorted(dict.items(value), key=_BY_KEY)
        return dict.items(value)

    def string(self, head: str, value: str) -> Iterator[str]:
        step = self.slice_chars
        if len(value) <= step:
            yield head + encode_basestring_ascii(value)
            return
        yield head + '"'
        for start in range(0, len(value), step):
            yield encode_basestring_ascii(value[start : start + step])[1:-1]
        yield '"'

    def encoded(self, head: str, value: Any) -> Iterator[str]:
        text = self.whole(value)
        step = self.slice_chars
        if len(text) <= step:
            yield head + text
            return
        yield head
        for start in range(0, len(text), step):
            yield text[start : start + step]

    def mapping(self, value: dict[str, Any], items: Iterable[tuple[str, Any]], depth: int) -> Iterator[str]:
        self.open[id(value)] = value
        yield "{"
        sep = ""
        for key, item in items:
            head = sep + encode_basestring_ascii(key) + self.key_sep
            sep = self.item_sep
            if type(item) is str:
                if len(item) <= self.slice_chars:
                    yield head + encode_basestring_ascii(item)
                else:
                    yield from self.string(head, item)
                continue
            try:
                nested = self.items(item, depth + 1)
                if nested is None:
                    yield from self.encoded(head, item)
                else:
                    yield head
                    yield from self.mapping(item, nested, depth + 1)
            except Exception as exc:
                if _NOTES:
                    exc.add_note(f"when serializing {_type_name(type(value))} item {key!r}")
                raise
        yield "}"
        del self.open[id(value)]

    def value(self, value: Any) -> Iterator[str]:
        if type(value) is str:
            yield from self.string("", value)
            return
        items = self.items(value, 0)
        if items is None:
            yield from self.encoded("", value)
        else:
            yield from self.mapping(value, items, 0)


def iter_json(
    obj: Any,
    *,
    sort_keys: bool,
    separators: tuple[str, str],
    max_depth: int,
    slice_chars: int = 1 << 20,
) -> Iterator[str]:
    """`obj` must not change while the iterator is in use."""
    if slice_chars < 1:
        raise ValueError(f"slice_chars must be at least 1, not {slice_chars}")
    return _Encoder(sort_keys, separators, max_depth, slice_chars).value(obj)


def _drain(held: list[str]) -> bytes:
    text = "".join(held)
    held.clear()
    return text.encode()


def _coalesce(pieces: Iterator[str], chunk_bytes: int) -> Iterator[bytes]:
    held: list[str] = []
    size = 0
    for piece in pieces:
        held.append(piece)
        size += len(piece)
        if size >= chunk_bytes:
            del piece
            size = 0
            yield _drain(held)
    if held:
        yield _drain(held)


def iter_json_bytes(
    obj: Any,
    *,
    sort_keys: bool,
    separators: tuple[str, str],
    max_depth: int,
    slice_chars: int = 1 << 20,
    chunk_bytes: int = 1 << 16,
) -> Iterator[bytes]:
    """`iter_json` encoded as UTF-8, in chunks of at least `chunk_bytes` (the last one excepted)."""
    if chunk_bytes < 1:
        raise ValueError(f"chunk_bytes must be at least 1, not {chunk_bytes}")
    pieces = iter_json(
        obj, sort_keys=sort_keys, separators=separators, max_depth=max_depth, slice_chars=slice_chars
    )
    return _coalesce(pieces, chunk_bytes)


def sha256_json(obj: Any, *, sort_keys: bool, separators: tuple[str, str], max_depth: int) -> str:
    """`hashlib.sha256(json.dumps(obj, sort_keys=sort_keys, default=str,
    separators=separators).encode()).hexdigest()`, without holding the text."""
    digest = hashlib.sha256()
    for chunk in iter_json_bytes(obj, sort_keys=sort_keys, separators=separators, max_depth=max_depth):
        digest.update(chunk)
    return digest.hexdigest()
