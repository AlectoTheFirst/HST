"""A lost side-store file whose rows cannot be built releases its payload before
the next file is read (core/reconcile.py `repair_derived`).

A row view that cannot build a row fails inside `sidestore.write_table` with
`streams.RowMappingError`. Its `original` carries the traceback of the failed
build, whose frames hold the view and, through the view's source, the payload.
The repair reports the file and lets go of all of it before it reads the next
payload, as on every other path out of a file (tests/test_reconcile_release.py).
"""

from __future__ import annotations

import gc
from typing import Any

from tests.test_reconcile_release import _watch_reads
from tests.test_reconcile_row_errors import ARP, MAC, _lost_tables, _unbuildable

from hst.app.crypto import dek
from hst.collectors import streams
from hst.core import reconcile


class _Source(list):
    """Records that hold the payload they were parsed from, as a parse's
    records do."""

    def __init__(self, rows: list[dict[str, Any]], payload: Any) -> None:
        super().__init__(rows)
        self.payload = payload


class _Unbuildable:
    """A collector whose row views read records it cannot map to rows, and
    whose parse cache holds the payload until `release_payload`."""

    def __init__(self) -> None:
        self._parsed_for: Any = None
        self.released = 0

    def side_tables(self, raw: Any) -> dict[str, Any]:
        self._parsed_for = raw
        return {
            "arp": streams.MappedRows(_Source(ARP, raw), _unbuildable),
            "mac": streams.MappedRows(_Source(MAC, raw), _unbuildable),
        }

    def release_payload(self) -> None:
        self.released += 1
        self._parsed_for = None


def test_a_row_that_cannot_be_built_releases_its_payload_before_the_next_read(tmp_path, monkeypatch):
    settings, report, relative = _lost_tables(tmp_path)
    seen, alive_at_read = _watch_reads(monkeypatch)
    collector = _Unbuildable()

    lines = reconcile.repair_derived(
        settings, report, tmp_path / "repair", collector_for=lambda s, h: collector, key=dek(settings)
    )

    assert lines == [
        f"{path}: could not regenerate (KeyError: 'interface')" for path in sorted(relative.values())
    ]
    assert report.rebuilt_paths == []
    assert alive_at_read == [[], [False]]
    assert collector._parsed_for is None
    assert collector.released == 2
    gc.collect()
    assert [ref() is None for ref in seen] == [True, True]
