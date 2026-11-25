"""`streams.line_windows` without a size reads `streams.WINDOW_CHARS` when it
starts, so a test that sets the module constant to force small windows
reaches a caller that passes no size as well as one that passes the constant."""

from __future__ import annotations

import pytest

from hst.collectors import streams


def test_a_call_without_a_size_takes_the_window_size_set_on_the_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "aaa\nbbb\nccc\n"
    assert list(streams.line_windows(text)) == [text]

    monkeypatch.setattr(streams, "WINDOW_CHARS", 4)

    assert list(streams.line_windows(text)) == ["aaa\n", "bbb\n", "ccc\n"]
    assert list(streams.line_windows(text, 4)) == ["bbb\n", "ccc\n"]
    assert list(streams.line_windows(text, 0, 8)) == ["aaa\nbbb\n", "ccc\n"]


def test_a_size_below_one_is_refused_when_the_windows_are_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(streams, "WINDOW_CHARS", 0)
    with pytest.raises(ValueError, match="at least 1"):
        list(streams.line_windows("abc\n"))
