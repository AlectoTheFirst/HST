"""Close PySAML2's temporary files at the end of a synchronous operation."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from typing import Any

_files: ContextVar[ExitStack | None] = ContextVar("saml_temporary_files", default=None)


def _tracked_file(*args: Any, **kwargs: Any) -> Any:
    file = tempfile.NamedTemporaryFile(*args, **kwargs)  # noqa: SIM115 -- the ExitStack of saml_tempfiles closes the file
    stack = _files.get()
    if stack is not None:
        stack.callback(file.close)
    return file


@contextmanager
def saml_tempfiles() -> Iterator[None]:
    from saml2 import sigver

    sigver.NamedTemporaryFile = _tracked_file
    with ExitStack() as stack:
        token = _files.set(stack)
        try:
            yield
        finally:
            _files.reset(token)
