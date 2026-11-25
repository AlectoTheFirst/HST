"""A side-store file a manifest replay regenerates into its scratch directory
is compared with the row digest the manifest recorded for it, from the digest
`sidestore.write_table` took as it wrote the rows, and the note says whether
they match, as the side-store repair's does (core/reconcile.py
`repair_derived`)."""

from __future__ import annotations

import pytest
from tests.test_replay import MARCH, RecordingSession, _one_device_manifest, _RibCollector, _settings, _write

from hst.core import manifest, replay

pytest.importorskip("pyarrow")


class _OtherRows(_RibCollector):
    def side_tables(self, raw):
        return {"rib": [{"device_uid": "dev:r1", "prefix": "10.0.0.0/8"}]}


@pytest.mark.parametrize(("collector_type", "said"), [(_RibCollector, "matches"), (_OtherRows, "differs")])
def test_the_note_says_whether_the_regenerated_rows_digest_as_recorded(tmp_path, collector_type, said):
    from hst.core import sidestore

    s = _settings(tmp_path)
    raw_path = _write(s, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    rib_path = sidestore.write_table(
        s.sidestore_dir, "rib", "vyos", "", run_id, [{"device_uid": "dev:r1", "prefix": "0.0.0.0/0"}], MARCH
    )
    rib_entry = manifest.file_entry(s, rib_path)
    rib_path.unlink()
    _one_device_manifest(s, "vyos", "", run_id, MARCH, [manifest.file_entry(s, raw_path), rib_entry])
    lookup = replay.SourceLookup(collector=collector_type("vyos"), type="vyos", enabled=True, config={})

    report = replay.rebuild_from_manifest(
        s,
        RecordingSession(),
        2_000,
        source_for=lambda name: lookup,
        sidestore_scratch_dir=tmp_path / "scratch",
    )

    (note,) = report.side_table_notes
    written = tmp_path / "scratch" / "rib" / "vyos" / f"{run_id}.parquet"
    if said == "matches":
        assert note == f"vyos: rib regenerated into {written}, the recorded row digest matches"
    else:
        facts = sidestore.written_row_facts(written)
        assert facts is not None
        assert note == (
            f"vyos: rib regenerated into {written}, and the row digest differs "
            f"(manifest {rib_entry.rows_sha256}, regenerated {facts[1]})"
        )
