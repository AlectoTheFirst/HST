"""Historical graph archives are exact, bounded, and fail closed."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from hst.core import grapharchive, replay
from hst.core import manifest as manifestmod
from hst.core.config import Settings


class Result(list):
    def data(self):
        return list(self)


class ReadTx:
    def __init__(self, nodes, rels):
        self.nodes = nodes
        self.rels = rels

    def run(self, query, **_params):
        return Result(self.rels if "RETURN type(r)" in query else self.nodes)


class SourceSession:
    def __init__(self, nodes, rels):
        self.tx = ReadTx(nodes, rels)

    def execute_read(self, work):
        return work(self.tx)


class RetryingSourceSession(SourceSession):
    def execute_read(self, work):
        work(self.tx)
        return work(self.tx)


class RestoreSession:
    def __init__(self, *, report_counts=True):
        self.writes = []
        self.report_counts = report_counts

    def execute_write(self, work):
        outer = self

        class Tx:
            def run(self, query, **params):
                outer.writes.append((query, params))
                if outer.report_counts:
                    return Result([{"created": len(params["rows"])}])
                return Result()

        return work(Tx())


def _settings(tmp_path: Path) -> Settings:
    return Settings(hst_data_dir=tmp_path)


def _archive(tmp_path: Path, source_cls=SourceSession):
    settings = _settings(tmp_path)
    key = Fernet.generate_key().decode()
    source = source_cls(
        [
            {
                "uid": "site:a",
                "labels": ["Meta", "Obj", "Site"],
                "props": {"uid": "site:a", "name": "A"},
            },
            {
                "uid": "dev:1",
                "labels": ["Device", "Obj"],
                "props": {"uid": "dev:1", "collection_ts": 10, "role": "leaf"},
            },
            {
                "uid": "site:a",
                "labels": ["Obj", "Site"],
                "props": {"uid": "site:a", "collection_ts": 10, "name": "reported A"},
            },
        ],
        [
            {
                "type": "LOCATED_IN",
                "start": "dev:1",
                "end": "site:a",
                "start_versioned": True,
                "end_versioned": False,
                "snapshot_valid": True,
                "props": {"assigned": True},
            }
        ],
    )
    entry = grapharchive.write(
        source,
        settings,
        10,
        key,
        normalization_context={"device": "digest"},
        chunk_records=1,
    )
    return settings, key, entry


def test_exact_archive_roundtrip_remaps_only_collection_timestamp(tmp_path):
    settings, key, entry = _archive(tmp_path)
    grapharchive.verify(settings, entry, key)
    target = RestoreSession()

    # The archive record of the relationship is not part of CycleRun totals.
    assert grapharchive.restore(target, settings, entry, key, 99) == (2, 0)
    assert entry["rels"] == 1
    props = [prop for _query, params in target.writes for prop in params["rows"]]
    props = [row.get("props", row) for row in props]
    assert props == [
        {"uid": "site:a", "name": "A"},
        {"uid": "dev:1", "collection_ts": 99, "role": "leaf"},
        {"uid": "site:a", "collection_ts": 99, "name": "reported A"},
        {"assigned": True},
    ]
    assert entry["normalization_context"] == {"device": "digest"}


def test_restore_rejects_a_missing_created_count(tmp_path):
    settings, key, entry = _archive(tmp_path)

    with pytest.raises(grapharchive.ArchiveError, match="did not report created nodes"):
        grapharchive.restore(RestoreSession(report_counts=False), settings, entry, key, 99)


def test_managed_read_retry_restarts_archive_staging(tmp_path):
    retry_settings, retry_key, entry = _archive(tmp_path, RetryingSourceSession)

    grapharchive.verify(retry_settings, entry, retry_key)
    assert (entry["nodes"], entry["rels"], entry["chunks"]) == (3, 1, 4)


@pytest.mark.parametrize("damage", ["tamper", "truncate"])
def test_archive_rejects_tamper_and_truncation(tmp_path, damage):
    settings, key, entry = _archive(tmp_path)
    path = settings.hst_data_dir / entry["path"]
    body = bytearray(path.read_bytes())
    if damage == "tamper":
        body[len(grapharchive.MAGIC) + 8] ^= 1
    else:
        del body[-20:]
    path.write_bytes(body)
    # The inner Fernet/final-frame contract rejects the damage.
    entry["sha256"], entry["bytes"] = grapharchive._file_facts(path)

    with pytest.raises(grapharchive.ArchiveError):
        grapharchive.verify(settings, entry, key)


def test_verify_happens_before_any_restore_write(tmp_path):
    settings, key, entry = _archive(tmp_path)
    path = settings.hst_data_dir / entry["path"]
    path.write_bytes(path.read_bytes()[:-1])
    target = RestoreSession()

    with pytest.raises(grapharchive.ArchiveError):
        grapharchive.verify(settings, entry, key)
    assert target.writes == []


def test_reseal_writes_the_same_records_under_the_new_key(tmp_path):
    settings, key, entry = _archive(tmp_path / "data")
    new_key = Fernet.generate_key().decode()
    copy = _settings(tmp_path / "copy")
    target = copy.hst_data_dir / entry["path"]
    target.parent.mkdir(parents=True)

    sha, size = grapharchive.reseal(settings, entry, key, new_key, target)

    assert target.stat().st_mode & 0o777 == 0o600
    resealed = {**entry, "sha256": sha, "bytes": size}
    restored, original = RestoreSession(), RestoreSession()
    assert grapharchive.restore(restored, copy, resealed, new_key, 99) == (2, 0)
    grapharchive.restore(original, settings, entry, key, 99)
    assert restored.writes == original.writes
    with pytest.raises(grapharchive.ArchiveError):
        grapharchive.verify(copy, resealed, key)


def test_reseal_refuses_a_wrong_key_and_bytes_that_differ_from_the_manifest(tmp_path):
    settings, key, entry = _archive(tmp_path)
    new_key = Fernet.generate_key().decode()

    with pytest.raises(grapharchive.ArchiveError, match="authentication"):
        grapharchive.reseal(settings, entry, new_key, new_key, tmp_path / "wrong-key")
    with pytest.raises(grapharchive.ArchiveError, match="digest or size"):
        grapharchive.reseal(settings, {**entry, "sha256": "0" * 64}, key, new_key, tmp_path / "changed")
    with pytest.raises(FileExistsError):
        grapharchive.reseal(settings, entry, key, new_key, tmp_path / "changed")


def test_manifest_archive_ignores_current_config_collectors_and_derivations(tmp_path, monkeypatch):
    """Carried and deleted state is already resolved in the archived graph."""
    settings, key, entry_dict = _archive(tmp_path)
    entry = manifestmod.GraphArchiveEntry.model_validate(entry_dict)
    record = SimpleNamespace(graph_archive=entry)
    events = []
    monkeypatch.setattr(replay.manifestmod, "read", lambda *_args: record)
    monkeypatch.setattr("hst.app.crypto.dek", lambda _settings: key)
    monkeypatch.setattr(grapharchive, "verify", lambda *_args: events.append("verified"))
    monkeypatch.setattr(replay, "_clear_target", lambda _target: events.append("cleared") or 7)
    monkeypatch.setattr(
        grapharchive,
        "restore",
        lambda *_args: events.append("restored") or (2, 1),
    )
    monkeypatch.setattr(replay, "_publish", lambda *_args, **_kwargs: events.append("published"))

    report = replay.rebuild_from_manifest(
        settings,
        object(),
        10,
        source_for=lambda _name: pytest.fail("current source/config must not be read"),
        allow_config_drift=True,
    )

    assert report.exact is True
    assert report.cleared == 7
    assert events == ["verified", "cleared", "restored", "published"]


def test_restore_finds_an_unversioned_end_as_a_meta_node_and_a_versioned_one_at_the_run(tmp_path):
    settings, key, entry = _archive(tmp_path)
    target = RestoreSession()

    grapharchive.restore(target, settings, entry, key, 99)

    [(query, params)] = [(q, p) for q, p in target.writes if "LOCATED_IN" in q]
    assert "MATCH (a:Obj {uid: row.start, collection_ts: $cts})" in query
    assert "MATCH (b:Obj:Meta {uid: row.end}) WHERE b.collection_ts IS NULL" in query
    assert "{collection_ts: $cts, uid: row.end}" not in query
    assert params["cts"] == 99


def test_the_archive_reads_start_from_the_runs_nodes():
    """No OR over collection_ts: each branch starts from the run through obj_cts."""
    for query in (grapharchive._NODES, grapharchive._RELS):
        assert "{collection_ts: $snap}" in query
        assert "WHERE n.collection_ts = $snap OR" not in query
    assert "UNION ALL" in grapharchive._RELS


def test_the_archive_reads_hold_no_sort_and_no_distinct_over_the_run():
    """The query has no sort and no DISTINCT over the run's rows."""
    for query in (grapharchive._NODES, grapharchive._RELS):
        assert "ORDER BY" not in query
        assert "UNION " not in query.replace("UNION ALL ", "")
    assert grapharchive._NODES.count("DISTINCT") == 1
    assert "RETURN DISTINCT n } " in grapharchive._NODES
    assert "DISTINCT" not in grapharchive._RELS
