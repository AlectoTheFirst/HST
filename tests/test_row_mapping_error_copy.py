"""A copied or unpickled `RowMappingError` states the message of the error it
was copied from (collectors/streams.py)."""

from __future__ import annotations

import copy
import pickle

import pytest

from hst.collectors.streams import RowMappingError

NOTE = "while writing the arp table"


def _error() -> RowMappingError:
    error = RowMappingError(KeyError("interface"))
    error.add_note(NOTE)
    return error


def _round_trip(error: RowMappingError) -> RowMappingError:
    copied: RowMappingError = pickle.loads(pickle.dumps(error))  # noqa: S301 - bytes this test pickled
    return copied


@pytest.mark.parametrize(
    "duplicate", [copy.copy, copy.deepcopy, _round_trip], ids=["copy", "deepcopy", "pickle"]
)
def test_a_copy_states_the_same_message_and_keeps_the_original_and_the_notes(duplicate):
    error = _error()

    copied = duplicate(error)

    assert type(copied) is RowMappingError
    assert str(copied) == str(error) == "KeyError: 'interface'"
    assert copied.args == error.args
    assert type(copied.original) is KeyError
    assert copied.original.args == ("interface",)
    assert copied.__notes__ == [NOTE]


def test_a_shallow_copy_holds_the_same_original():
    error = _error()

    assert copy.copy(error).original is error.original
