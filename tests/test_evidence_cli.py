"""Check recomputes every file digest, every side-store row digest, the signature when one
exists, and the manifest chain from disk alone."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest
from typer.testing import CliRunner

import hst.cli as cli
from hst.app.crypto import dek, generate_key
from hst.core import manifest, rawstore
from hst.core.config import Settings

runner = CliRunner()

KEY = generate_key()
MARCH = 1_772_000_000_000


def _settings(monkeypatch, tmp_path, **kw):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=KEY, **kw)
    monkeypatch.setattr(cli, "Settings", lambda: settings)
    return settings


def _raw_file(settings, source, ts, payload, host=""):
    return rawstore.write(settings.raw_dir, source, f"{ts}-abc12345", payload, host=host, key=dek(settings))


def _publish(settings, key, files, parent=None, sources=None):
    """`manifest.build` resolves `previous` from what is on disk."""
    record = manifest.build(
        settings=settings,
        snapshot_key=key,
        kind="full",
        parent=parent,
        sources=list(sources or []),
        devices=[],
        files=files,
        delta=manifest.GraphDelta(),
    )
    manifest.write(settings, record, manifest.signer_for(settings))
    return record


# --- export ---------------------------------------------------------------------------


def test_export_writes_the_manifest_and_a_file_list_only(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    raw_path = _raw_file(settings, "vyos", MARCH, {"n": 1})
    entry = manifest.file_entry(settings, raw_path)
    _publish(settings, 2_000, [entry])

    out = tmp_path / "out"
    r = runner.invoke(cli.app, ["evidence", "export", "2000", str(out)])
    assert r.exit_code == 0, r.output

    # unsigned: no .sig, and no raw or side-store file bytes of any kind
    assert {p.name for p in out.iterdir()} == {"2000.json", "2000.files.json"}
    file_list = json.loads((out / "2000.files.json").read_text())
    assert len(file_list) == 1
    assert file_list[0]["path"] == entry.path
    assert file_list[0]["sha256"] == entry.sha256
    assert "no signature (unsigned)" in r.output


def test_export_includes_the_signature_when_one_exists(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path, evidence_signing_key=generate_key())
    raw_path = _raw_file(settings, "vyos", MARCH, {"n": 1})
    _publish(settings, 2_000, [manifest.file_entry(settings, raw_path)])

    out = tmp_path / "out"
    r = runner.invoke(cli.app, ["evidence", "export", "2000", str(out)])
    assert r.exit_code == 0, r.output
    assert (out / "2000.sig").is_file()
    assert "no signature" not in r.output


def test_export_of_an_unknown_snapshot_fails(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    r = runner.invoke(cli.app, ["evidence", "export", "999", str(tmp_path / "out")])
    assert r.exit_code == 1, r.output
    assert "no manifest for snapshot 999" in r.output


# --- check ------------------------------------------------------------------------------


def test_check_reports_every_digest_and_chain_link_good(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    _publish(settings, 2_000, [manifest.file_entry(settings, raw1)])
    raw2 = _raw_file(settings, "vyos", MARCH + 1_000, {"n": 2})
    _publish(settings, 3_000, [manifest.file_entry(settings, raw2)], parent=2_000)

    r = runner.invoke(cli.app, ["evidence", "check", "3000"])
    assert r.exit_code == 0, r.output
    assert "all digests and chain links match" in r.output
    assert "chain walked back 2 manifest(s)" in r.output


def test_check_reports_exactly_the_tampered_files_digest_mismatch(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    raw2 = _raw_file(settings, "unifi", MARCH, {"n": 2})
    entry1 = manifest.file_entry(settings, raw1)
    entry2 = manifest.file_entry(settings, raw2)
    _publish(settings, 2_000, [entry1, entry2])

    raw1.write_bytes(raw1.read_bytes() + b"\x00")  # tampered after the fact

    r = runner.invoke(cli.app, ["evidence", "check", "2000"])
    assert r.exit_code == 1, r.output
    assert f"{entry1.path}: digest mismatch" in r.output
    assert f"{entry2.path}: digest mismatch" not in r.output
    assert r.output.count("digest mismatch") == 1


def test_check_reports_a_missing_file(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    entry1 = manifest.file_entry(settings, raw1)
    _publish(settings, 2_000, [entry1])
    raw1.unlink()

    r = runner.invoke(cli.app, ["evidence", "check", "2000"])
    assert r.exit_code == 1, r.output
    assert f"{entry1.path}: file missing" in r.output


def test_check_of_an_unknown_snapshot_fails(monkeypatch, tmp_path):
    _settings(monkeypatch, tmp_path)
    r = runner.invoke(cli.app, ["evidence", "check", "999"])
    assert r.exit_code == 1, r.output
    assert "no manifest for snapshot 999" in r.output


def test_check_reports_a_missing_manifest_in_the_chain(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    _publish(settings, 2_000, [manifest.file_entry(settings, raw1)])
    raw2 = _raw_file(settings, "vyos", MARCH + 1_000, {"n": 2})
    _publish(settings, 3_000, [manifest.file_entry(settings, raw2)], parent=2_000)

    manifest.path_for(settings, 2_000).unlink()

    r = runner.invoke(cli.app, ["evidence", "check", "3000"])
    assert r.exit_code == 1, r.output
    assert "chain: manifest for snapshot 2000 is missing" in r.output


def test_check_reports_a_broken_chain_link(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    _publish(settings, 2_000, [manifest.file_entry(settings, raw1)])
    raw2 = _raw_file(settings, "vyos", MARCH + 1_000, {"n": 2})
    _publish(settings, 3_000, [manifest.file_entry(settings, raw2)], parent=2_000)

    path = manifest.path_for(settings, 2_000)
    path.write_bytes(path.read_bytes().replace(b'"kind":"full"', b'"kind":"idle"'))

    r = runner.invoke(cli.app, ["evidence", "check", "3000"])
    assert r.exit_code == 1, r.output
    assert "chain: snapshot 3000 recorded snapshot 2000's digest as" in r.output


def test_check_reports_unsigned_when_there_is_no_signature(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    _publish(settings, 2_000, [manifest.file_entry(settings, raw1)])

    r = runner.invoke(cli.app, ["evidence", "check", "2000"])
    assert r.exit_code == 0, r.output
    assert "unsigned" in r.output


def test_check_verifies_a_signature(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path, evidence_signing_key=generate_key())
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    _publish(settings, 2_000, [manifest.file_entry(settings, raw1)])

    r = runner.invoke(cli.app, ["evidence", "check", "2000"])
    assert r.exit_code == 0, r.output
    assert "signature verifies" in r.output


def test_check_reports_a_signature_that_does_not_verify(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path, evidence_signing_key=generate_key())
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    _publish(settings, 2_000, [manifest.file_entry(settings, raw1)])

    sig_path = manifest.sig_path_for(settings, 2_000)
    sig = json.loads(sig_path.read_text())
    sig["signature"] = "00" * 64  # well-formed but wrong
    sig_path.write_text(json.dumps(sig))

    r = runner.invoke(cli.app, ["evidence", "check", "2000"])
    assert r.exit_code == 1, r.output
    assert "signature does not verify" in r.output


def test_check_fails_for_a_signature_from_a_key_that_is_not_configured(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path, evidence_signing_key=generate_key())
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    _publish(settings, 2_000, [manifest.file_entry(settings, raw1)])
    _settings(monkeypatch, tmp_path, evidence_signing_key=generate_key())

    r = runner.invoke(cli.app, ["evidence", "check", "2000"])
    assert r.exit_code == 1, r.output
    assert "not the configured signing key" in r.output


def test_check_verifies_side_store_row_digests(monkeypatch, tmp_path):
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    settings = _settings(monkeypatch, tmp_path)
    raw1 = _raw_file(settings, "vyos", MARCH, {"n": 1})
    run_id = f"{MARCH}-abc12345"
    rows = [{"device_uid": "dev:r1", "prefix": "0.0.0.0/0"}]
    rib_path = sidestore.write_table(settings.sidestore_dir, "rib", "vyos", "", run_id, rows, MARCH)
    _publish(settings, 2_000, [manifest.file_entry(settings, raw1), manifest.file_entry(settings, rib_path)])

    r = runner.invoke(cli.app, ["evidence", "check", "2000"])
    assert r.exit_code == 0, r.output
    assert "all digests and chain links match" in r.output


# --- reconcile --------------------------------------------------------------------------


def _flat(output):
    """The console wraps at the test terminal's width."""
    return " ".join(output.split())


def _committed(settings, source, ts, payload, snapshot_key, host="r1"):
    """A raw file joined to `snapshot_key`, the way a published run settles one:
    the payload plus the `<run>.meta.json` sidecar recording what it joined."""
    path = _raw_file(settings, source, ts, payload, host=host)
    rawstore.mark_joined(path, snapshot_key)
    return path


def _relative(settings, path):
    return path.relative_to(settings.hst_data_dir).as_posix()


def _sidecar_of(path):
    return path.with_name(path.name.replace(".json.gz.enc", ".meta.json"))


class _LockStore:
    """The store `reconcile --apply` takes the cycle lock from. `events` records
    the order of the lock and of what runs under it, and `on_lock` stands for a
    run that publishes while the command waits for the lock."""

    def __init__(self):
        self.events = []
        self.on_lock = None

    @asynccontextmanager
    async def cycle_lock(self):
        self.events.append("lock")
        if self.on_lock is not None:
            self.on_lock()
        try:
            yield 1
        finally:
            self.events.append("unlock")


@pytest.fixture(autouse=True)
def store(monkeypatch):
    rig = _LockStore()
    monkeypatch.setattr(cli, "_with_store", lambda fn: asyncio.run(fn(rig)))
    return rig


def _quarantine_run(tmp_path):
    """The one directory a quarantine run created, and its report."""
    roots = sorted((tmp_path / "quarantine").iterdir())
    assert len(roots) == 1, roots
    return roots[0], json.loads((roots[0] / "report.json").read_text())


def test_reconcile_passes_on_a_coherent_tree(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    path = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, path)])

    r = runner.invoke(cli.app, ["evidence", "reconcile"])
    assert r.exit_code == 0, r.output
    assert "1 file(s) verified against the manifest that names them" in _flat(r.output)
    assert "runs, manifests and files agree" in _flat(r.output)


def test_reconcile_reports_a_tampered_file_without_moving_it(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    path = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, path)])
    path.write_bytes(path.read_bytes() + b"\x00")

    r = runner.invoke(cli.app, ["evidence", "reconcile", "--apply"])
    assert r.exit_code == 1, r.output
    assert _relative(settings, path) in _flat(r.output)
    assert "digest mismatch" in _flat(r.output)
    assert path.is_file()
    _root, report = _quarantine_run(tmp_path)
    assert report["moved"] == []


def test_reconcile_quarantines_an_orphan_and_leaves_the_committed_file(monkeypatch, tmp_path):
    """A payload whose sidecar names a snapshot no manifest covers any more is an orphan."""
    settings = _settings(monkeypatch, tmp_path)
    kept = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, kept)])
    orphan = _committed(settings, "vyos", MARCH + 5_000, {"n": 2}, 1_000, host="r2")

    r = runner.invoke(cli.app, ["evidence", "reconcile", "--apply"])
    assert r.exit_code == 0, r.output
    assert "it joined snapshot 1000, whose manifest is not on disk" in _flat(r.output)
    assert "every finding was resolved" in _flat(r.output)

    relative = _relative(settings, orphan)
    root, report = _quarantine_run(tmp_path)
    assert [m["path"] for m in report["moved"]] == [relative]
    assert (root / relative).is_file()
    assert _sidecar_of(root / relative).is_file()
    assert not orphan.exists()
    assert not _sidecar_of(orphan).exists()
    assert kept.is_file()


def test_reconcile_apply_moves_files_only_under_the_cycle_lock(monkeypatch, tmp_path, store):
    """A collection holds the lock from its fetch until its manifest is written,
    so with the lock held no run is between loading its files and publishing them."""
    from hst.core import reconcile

    settings = _settings(monkeypatch, tmp_path)
    kept = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, kept)])
    orphan = _committed(settings, "vyos", MARCH + 5_000, {"n": 2}, 1_000, host="r2")
    moved = reconcile.quarantine
    monkeypatch.setattr(
        reconcile, "quarantine", lambda *args, **kw: store.events.append("quarantine") or moved(*args, **kw)
    )

    r = runner.invoke(cli.app, ["evidence", "reconcile", "--apply"])

    assert r.exit_code == 0, r.output
    assert store.events == ["lock", "quarantine", "unlock"]
    assert not orphan.exists()


def test_reconcile_report_only_takes_no_lock(monkeypatch, tmp_path, store):
    settings = _settings(monkeypatch, tmp_path)
    _committed(settings, "vyos", MARCH, {"n": 1}, 1_000)
    _publish(settings, 2_000, [])

    runner.invoke(cli.app, ["evidence", "reconcile"])

    assert store.events == []


def test_a_side_store_file_whose_run_publishes_during_the_wait_is_not_moved(monkeypatch, tmp_path, store):
    """The scan listed the parquet of a run in flight, which no manifest names yet.
    The run publishes before the lock is granted, and its manifest names the file."""
    pytest.importorskip("pyarrow")
    from hst.core import sidestore

    settings = _settings(monkeypatch, tmp_path)
    kept = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, kept)])
    rows = [{"device_uid": "dev:r1", "prefix": "0.0.0.0/0"}]
    rib = sidestore.write_table(settings.sidestore_dir, "rib", "vyos", "", "run-3000", rows, MARCH)
    store.on_lock = lambda: _publish(settings, 3_000, [manifest.file_entry(settings, rib)], parent=2_000)

    r = runner.invoke(cli.app, ["evidence", "reconcile", "--apply"])

    assert r.exit_code == 0, r.output
    assert rib.is_file()
    _root, report = _quarantine_run(tmp_path)
    assert report["moved"] == []
    assert report["manifests"] == [2_000, 3_000]


def test_a_raw_file_joined_to_a_manifest_published_during_the_wait_is_not_moved(monkeypatch, tmp_path, store):
    """Its sidecar names snapshot 3000, whose manifest is newer than the scan and
    does not list the file: the run is accounted for, so the file is not an orphan."""
    settings = _settings(monkeypatch, tmp_path)
    kept = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, kept)])
    _publish(settings, 4_000, [manifest.file_entry(settings, kept)], parent=2_000)
    stray = _committed(settings, "vyos", MARCH + 5_000, {"n": 2}, 3_000, host="r2")
    store.on_lock = lambda: _publish(settings, 3_000, [], parent=2_000)

    r = runner.invoke(cli.app, ["evidence", "reconcile", "--apply"])

    assert r.exit_code == 0, r.output
    assert stray.is_file()
    assert _sidecar_of(stray).is_file()


def test_an_unreadable_manifest_published_during_the_wait_stops_the_move(monkeypatch, tmp_path, store):
    settings = _settings(monkeypatch, tmp_path)
    kept = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, kept)])
    orphan = _committed(settings, "vyos", MARCH + 5_000, {"n": 2}, 1_000, host="r2")
    store.on_lock = lambda: manifest.path_for(settings, 3_000).write_text("{not json")

    r = runner.invoke(cli.app, ["evidence", "reconcile", "--apply"])

    assert r.exit_code == 1, r.output
    assert "nothing was moved" in _flat(r.output)
    assert orphan.is_file()
    assert not (tmp_path / "quarantine").exists()


def test_a_raw_file_joined_to_a_run_newer_than_every_manifest_is_pending_not_an_orphan(monkeypatch, tmp_path):
    """The run loaded it and has not written its manifest. A report-only run must
    not ask the operator to move it."""
    settings = _settings(monkeypatch, tmp_path)
    kept = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, kept)])
    in_flight = _committed(settings, "vyos", MARCH + 5_000, {"n": 2}, 3_000, host="r2")

    r = runner.invoke(cli.app, ["evidence", "reconcile"])

    assert r.exit_code == 0, r.output
    assert "joined a run whose manifest is not written yet" in _flat(r.output)
    assert _relative(settings, in_flight) in _flat(r.output)
    assert in_flight.is_file()


def test_reconcile_without_apply_moves_nothing(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    orphan = _committed(settings, "vyos", MARCH, {"n": 1}, 1_000)
    _publish(settings, 2_000, [])

    r = runner.invoke(cli.app, ["evidence", "reconcile"])
    assert r.exit_code == 1, r.output
    assert orphan.is_file()
    assert not (tmp_path / "quarantine").exists()


def test_reconcile_leaves_a_parked_payload_alone(monkeypatch, tmp_path):
    """Fetched and not yet folded into a run is pending, not orphaned."""
    settings = _settings(monkeypatch, tmp_path)
    committed = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, committed)])
    parked = _raw_file(settings, "vyos", MARCH + 5_000, {"n": 2}, host="r2")

    r = runner.invoke(cli.app, ["evidence", "reconcile", "--apply"])
    assert r.exit_code == 0, r.output
    assert "fetched, not yet folded into a run" in _flat(r.output)
    assert parked.is_file()
    _root, report = _quarantine_run(tmp_path)
    assert report["moved"] == []


def test_reconcile_writes_the_join_sidecar_a_manifest_derives(monkeypatch, tmp_path):
    """The manifest states which snapshot the file joined."""
    settings = _settings(monkeypatch, tmp_path)
    path = _raw_file(settings, "vyos", MARCH, {"n": 1}, host="r1")
    _publish(settings, 2_000, [manifest.file_entry(settings, path)])
    assert not _sidecar_of(path).exists()

    r = runner.invoke(cli.app, ["evidence", "reconcile", "--apply"])
    assert r.exit_code == 0, r.output
    assert json.loads(_sidecar_of(path).read_text()) == {"snapshot_ts": 2_000}
    assert "join sidecar recorded snapshot 2000" in _flat(r.output)


def test_reconcile_reports_a_file_the_manifest_names_and_disk_does_not_hold(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    path = _committed(settings, "vyos", MARCH, {"n": 1}, 2_000)
    entry = manifest.file_entry(settings, path)
    _publish(settings, 2_000, [entry])
    path.unlink()

    r = runner.invoke(cli.app, ["evidence", "reconcile"])
    assert r.exit_code == 1, r.output
    assert entry.path in _flat(r.output)
    assert "named by a manifest and not on disk" in _flat(r.output)


def test_reconcile_refuses_a_repair_target_inside_the_estates_own_stores(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    _publish(settings, 2_000, [])

    r = runner.invoke(
        cli.app, ["evidence", "reconcile", "--repair-target", str(settings.sidestore_dir / "rib")]
    )
    assert r.exit_code == 2, r.output
    assert "rebuild derived data into a directory" in _flat(r.output)


# --- recovery check ---------------------------------------------------------------------


def _recovery_set(tmp_path, settings, snapshot, **overrides):
    body = {
        "schema_version": 1,
        "created": "20260905T030000Z",
        "postgres_dump_key": "postgres/hst-pg-20260905T030000Z.dump",
        "snapshot_key": snapshot,
        "manifest_sha256": manifest.digest_of(settings, snapshot),
        "data_prefix": "data",
        "data_object_list_sha256": "0" * 64,
        **overrides,
    }
    path = tmp_path / "recovery-set.json"
    path.write_text(json.dumps(body))
    return path


def _sources(monkeypatch, rows):
    """Stand in for the Postgres read: `recovery check` asks the store for the
    source rows and compares each one's digest with the manifest's."""
    monkeypatch.setattr(cli, "_with_store", lambda fn: rows)


def _source_entry(name, config):
    return manifest.SourceEntry(
        name=name,
        type="vyos",
        status="fresh",
        config_sha256=manifest.source_config_digest(name, "vyos", True, config),
    )


def test_recovery_check_passes_on_a_restored_tree(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    config = {"host": "r1", "password": "hunter2"}
    path = _committed(settings, "edge", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, path)], sources=[_source_entry("edge", config)])
    _sources(monkeypatch, {"edge": ("vyos", True, config)})

    r = runner.invoke(cli.app, ["recovery", "check", str(_recovery_set(tmp_path, settings, 2_000))])
    assert r.exit_code == 0, r.output
    assert "1 source configuration digest(s) checked" in _flat(r.output)
    assert "the restored tree matches the recovery set" in _flat(r.output)


def test_recovery_check_reports_a_manifest_that_is_not_the_one_the_set_names(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    path = _committed(settings, "edge", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, path)])
    _sources(monkeypatch, {})
    set_path = _recovery_set(tmp_path, settings, 2_000, manifest_sha256="ab" * 32)

    r = runner.invoke(cli.app, ["recovery", "check", str(set_path)])
    assert r.exit_code == 1, r.output
    assert "the set recorded abababab" in _flat(r.output)


def test_recovery_check_reports_a_source_configuration_that_moved(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    path = _committed(settings, "edge", MARCH, {"n": 1}, 2_000)
    _publish(
        settings,
        2_000,
        [manifest.file_entry(settings, path)],
        sources=[_source_entry("edge", {"host": "r1"})],
    )
    _sources(monkeypatch, {"edge": ("vyos", True, {"host": "r9"})})

    r = runner.invoke(cli.app, ["recovery", "check", str(_recovery_set(tmp_path, settings, 2_000))])
    assert r.exit_code == 1, r.output
    assert "source 'edge': the manifest recorded configuration digest" in _flat(r.output)


def test_recovery_check_reports_a_source_the_restored_postgres_does_not_hold(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    path = _committed(settings, "edge", MARCH, {"n": 1}, 2_000)
    _publish(
        settings,
        2_000,
        [manifest.file_entry(settings, path)],
        sources=[_source_entry("edge", {"host": "r1"})],
    )
    _sources(monkeypatch, {})

    r = runner.invoke(cli.app, ["recovery", "check", str(_recovery_set(tmp_path, settings, 2_000))])
    assert r.exit_code == 1, r.output
    assert "named by the manifest and not in the restored Postgres" in _flat(r.output)


def test_recovery_check_reports_a_snapshot_the_restored_tree_does_not_hold(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    path = _committed(settings, "edge", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, path)])
    set_path = _recovery_set(tmp_path, settings, 2_000)
    manifest.path_for(settings, 2_000).unlink()
    _sources(monkeypatch, {})

    r = runner.invoke(cli.app, ["recovery", "check", str(set_path)])
    assert r.exit_code == 1, r.output
    assert "the restored tree holds no manifest for snapshot 2000" in _flat(r.output)


def test_recovery_check_refuses_a_set_version_it_does_not_read(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    path = _committed(settings, "edge", MARCH, {"n": 1}, 2_000)
    _publish(settings, 2_000, [manifest.file_entry(settings, path)])
    set_path = _recovery_set(tmp_path, settings, 2_000, schema_version=99)

    r = runner.invoke(cli.app, ["recovery", "check", str(set_path)])
    assert r.exit_code == 2, r.output
    assert "recovery-set schema version 99" in _flat(r.output)
