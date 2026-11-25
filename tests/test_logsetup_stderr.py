"""The root handler `configure_logging` attaches writes to the `sys.stderr`
of each record, so a stderr swapped in and closed by a caller (a CLI test
harness) leaves no handler writing into a closed file."""

from __future__ import annotations

import io
import logging
import sys

import pytest

from hst.core import Settings
from hst.core.logsetup import configure_logging


@pytest.fixture(autouse=True)
def _restore_root_logger():
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def test_a_record_after_a_swapped_stderr_closed_reaches_the_current_stderr(monkeypatch, capsys):
    swapped = io.StringIO()
    monkeypatch.setattr(sys, "stderr", swapped)
    configure_logging(Settings(_env_file=None))
    swapped.close()
    monkeypatch.undo()

    logging.getLogger("hst.test").warning("after the swap")

    err = capsys.readouterr().err
    assert "after the swap" in err
    assert "Logging error" not in err
