"""`manifest.checkpoint` under a driver that retries its read: the attempt
that failed part way leaves nothing in the value, so the checkpoint equals
one clean read of the same state."""

from __future__ import annotations

import contextlib
from typing import Any

from hst.core import manifest

NODES = [
    {"uid": uid, "labels": ["Obj", "Device"], "props": {"uid": uid, "name": uid[4:], "collection_ts": 7}}
    for uid in ("dev:r1", "dev:r2")
]
RELS = [{"t": "CONNECTS", "start": "dev:r1", "end": "dev:r2", "props": {"collection_ts": 7}}]


class _Tx:
    def __init__(self, fail_after: int | None) -> None:
        self._fail_after = fail_after

    def run(self, query: str, **params: Any) -> Any:
        rows = NODES if "RETURN n.uid" in query else RELS
        if self._fail_after is None or "RETURN n.uid" not in query:
            return list(rows)

        def failing() -> Any:
            yield from rows[: self._fail_after]
            raise ConnectionError("the connection ended mid-stream")

        return failing()


class _RetryingSession:
    """Runs the work once with a transaction that fails part way through the
    node rows, then again with one that does not, as the driver retries a
    transient failure."""

    def __init__(self, fail_after: int | None) -> None:
        self._fail_after = fail_after
        self.attempts = 0

    def execute_read(self, work: Any) -> Any:
        if self._fail_after is not None:
            self.attempts += 1
            with contextlib.suppress(ConnectionError):
                work(_Tx(self._fail_after))
        self.attempts += 1
        return work(_Tx(None))


def test_a_retried_read_digests_as_one_clean_read() -> None:
    clean = manifest.checkpoint(_RetryingSession(None), 7)  # type: ignore[arg-type]
    session = _RetryingSession(fail_after=1)
    retried = manifest.checkpoint(session, 7)  # type: ignore[arg-type]

    assert session.attempts == 2
    assert (clean.nodes, clean.rels) == (2, 1)
    assert retried == clean
