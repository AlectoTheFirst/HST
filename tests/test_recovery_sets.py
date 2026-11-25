from __future__ import annotations

import json
import os
import shutil

import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

import hst.cli as cli
from hst.app import crypto
from hst.core import grapharchive, manifest, reconcile
from hst.core.config import Settings

runner = CliRunner()


class _Result(list):
    def data(self):
        return list(self)


class _Graph:
    def __init__(self, key):
        self.key = key

    def execute_read(self, work):
        key = self.key

        class Tx:
            def run(self, query, **_params):
                if "RETURN type(r)" in query:
                    return _Result()
                return _Result(
                    [
                        {
                            "uid": "device:1",
                            "labels": ["Obj", "Device"],
                            "props": {"uid": "device:1", "collection_ts": key},
                        }
                    ]
                )

        return work(Tx())


def _publish(
    settings: Settings,
    key: int,
    dek: str,
    previous: manifest.SnapshotManifest | None = None,
    files: list[manifest.FileEntry] | None = None,
) -> manifest.SnapshotManifest:
    archive = grapharchive.write(
        _Graph(key), settings, key, dek, normalization_context={"setting": f"at-{key}"}
    )
    record = manifest.SnapshotManifest(
        snapshot_key=key,
        kind="full",
        opened=manifest.iso(key),
        published=manifest.iso(key),
        previous=manifest.PreviousLink(
            snapshot_key=previous.snapshot_key,
            sha256=manifest.digest_of(settings, previous.snapshot_key),
            chain_index=previous.chain_index or 0,
        )
        if previous
        else None,
        chain_index=(previous.chain_index or 0) + 1 if previous else 0,
        files=files or [],
        graph_archive=manifest.GraphArchiveEntry.model_validate(archive),
    )
    manifest.write(settings, record)
    return record


def _with_dump(objects: list[reconcile.RecoveryObject], set_id: str) -> list[reconcile.RecoveryObject]:
    return [
        *objects,
        reconcile.RecoveryObject(
            role="postgres",
            key=f"sets/{set_id}/postgres.dump",
            sha256="b" * 64,
            bytes=10,
        ),
    ]


def _sealed_dump(root, set_id: str, recovery_key: str, content: bytes) -> reconcile.RecoveryObject:
    (root / reconcile.POSTGRES_DUMP).write_bytes(content)
    sealed = reconcile.seal_postgres_dump(root, recovery_key)
    sha, size = manifest.file_facts(sealed)
    return reconcile.RecoveryObject(
        role="postgres", key=f"sets/{set_id}/{sealed.name}", sha256=sha, bytes=size
    )


def _staged_set(tmp_path, recovery_key: str, set_id: str = "job"):
    """A staged set with its draft record, as `hst recovery prepare` leaves it."""
    operator = b"k" * 32
    live = Settings(_env_file=None, hst_data_dir=tmp_path / "live", hst_secret_key=operator.decode())
    live.hst_data_dir.mkdir()
    record = _publish(live, 1_000, crypto.dek(live))
    staging = tmp_path / "staging"
    objects = reconcile.stage_recovery_data(
        live,
        record.snapshot_key,
        staging,
        set_id=set_id,
        encrypted_configuration=crypto.encrypt(recovery_key, b"{}"),
        encrypted_operator_key=crypto.encrypt(recovery_key, operator),
        operator_key=operator,
    )
    root = staging / "sets" / set_id
    draft = {
        "schema_version": reconcile.SET_SCHEMA_VERSION,
        "created": set_id,
        "snapshot_key": record.snapshot_key,
        "manifest_sha256": manifest.digest_of(live, record.snapshot_key),
        "chain_index": record.chain_index,
        "boundary": "ordered",
        "objects": [obj.model_dump(mode="json") for obj in objects],
    }
    (root / "draft.json").write_text(json.dumps(draft), encoding="utf-8")
    return staging, root, objects


def test_finalize_encrypts_the_dump_and_materialize_decrypts_it(monkeypatch, tmp_path):
    recovery_key = Fernet.generate_key().decode()
    staging, root, _objects = _staged_set(tmp_path, recovery_key)
    dump = os.urandom(reconcile._DUMP_PIECE_BYTES * 2 + 7)
    (root / "postgres.dump").write_bytes(dump)
    monkeypatch.setenv("HST_BACKUP_ENCRYPTION_KEY", recovery_key)
    monkeypatch.setenv("HST_BACKUP_OBJECT_PREFIX", "hst/prod")

    finalized = runner.invoke(cli.app, ["recovery", "finalize", str(staging), "--set-id", "job"])

    assert finalized.exit_code == 0, finalized.output
    assert sorted(path.name for path in root.iterdir() if path.is_file()) == [
        "configuration.enc",
        "draft.json",
        "operator-key.enc",
        "postgres.dump.enc",
        "recovery-set.json",
    ]
    assert not (root / ".verified").exists()
    sealed = root / "postgres.dump.enc"
    assert dump[:64] not in sealed.read_bytes()
    record = reconcile.read_set(root / "recovery-set.json")
    entry = next(obj for obj in record.objects if obj.role == "postgres")
    assert entry.key == record.postgres_dump_key == "hst/prod/sets/job/postgres.dump.enc"
    assert (entry.sha256, entry.bytes) == manifest.file_facts(sealed)

    restored = tmp_path / "restored"
    materialized = runner.invoke(
        cli.app, ["recovery", "materialize", str(root / "recovery-set.json"), str(root), str(restored)]
    )

    assert materialized.exit_code == 0, materialized.output
    assert (restored / ".recovery" / "postgres.dump").read_bytes() == dump
    assert not (restored / ".recovery" / "postgres.dump.enc").exists()


def test_finalize_without_the_recovery_key_leaves_the_dump_and_writes_no_record(monkeypatch, tmp_path):
    staging, root, _objects = _staged_set(tmp_path, Fernet.generate_key().decode())
    (root / "postgres.dump").write_bytes(b"PGDMP")
    monkeypatch.delenv("HST_BACKUP_ENCRYPTION_KEY", raising=False)

    finalized = runner.invoke(cli.app, ["recovery", "finalize", str(staging), "--set-id", "job"])

    assert finalized.exit_code == 1
    assert "HST_BACKUP_ENCRYPTION_KEY is required" in finalized.output
    assert (root / "postgres.dump").read_bytes() == b"PGDMP"
    assert not (root / "postgres.dump.enc").exists()
    assert not (root / "recovery-set.json").exists()


@pytest.mark.parametrize("sealed_under_another_key", [False, True])
def test_materialization_refuses_a_dump_that_the_recovery_key_does_not_open(
    tmp_path, sealed_under_another_key
):
    recovery_key = Fernet.generate_key().decode()
    _staging, root, objects = _staged_set(tmp_path, recovery_key)
    if sealed_under_another_key:
        objects.append(_sealed_dump(root, "job", Fernet.generate_key().decode(), b"PGDMP"))
    else:
        (root / "postgres.dump").write_bytes(b"PGDMP")
        sha, size = manifest.file_facts(root / "postgres.dump")
        objects.append(
            reconcile.RecoveryObject(role="postgres", key="sets/job/postgres.dump", sha256=sha, bytes=size)
        )
    record = reconcile.RecoverySet(
        snapshot_key=1_000,
        manifest_sha256=next(obj.sha256 for obj in objects if obj.role == "manifest"),
        boundary="ordered",
        objects=objects,
    )
    target = tmp_path / "restored"

    with pytest.raises(ValueError, match="the Postgres dump does not open under the recovery key"):
        reconcile.materialize_recovery_bundle(record, root, target, recovery_key)

    assert not target.exists()
    assert not list(tmp_path.glob("restored.*.partial"))


@pytest.mark.parametrize(
    ("second_key", "first_path", "second_path", "problem"),
    [
        ("data/first", "first", "second", "duplicate recovery object key"),
        ("data/second", "same", "same", "duplicate or reserved recovery restore path"),
        ("data/second", "first", ".recovery/operator", "duplicate or reserved recovery restore path"),
    ],
)
def test_materialization_rejects_ambiguous_inventory_before_creating_target(
    tmp_path, second_key, first_path, second_path, problem
):
    root = tmp_path / "objects"
    objects = []
    for key, restore_path in (("data/first", first_path), (second_key, second_path)):
        path = root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"immutable evidence")
        sha, size = manifest.file_facts(path)
        objects.append(
            reconcile.RecoveryObject(
                role="data", key=f"sets/example/{key}", sha256=sha, bytes=size, restore_path=restore_path
            )
        )
    record = reconcile.RecoverySet(snapshot_key=1000, manifest_sha256="a" * 64, objects=objects)
    target = tmp_path / "restored"
    with pytest.raises(ValueError, match=problem):
        reconcile.materialize_recovery_bundle(record, root, target, Fernet.generate_key().decode())
    assert not target.exists()


def test_older_set_restores_after_a_second_backup_and_key_config_change(tmp_path):
    old_operator = b"o" * 32
    recovery_key = Fernet.generate_key().decode()
    live = Settings(_env_file=None, hst_data_dir=tmp_path / "live", hst_secret_key=old_operator.decode())
    live.hst_data_dir.mkdir()
    old_dek = crypto.dek(live)
    first = _publish(live, 1_000, old_dek)
    staging = tmp_path / "staging"
    first_objects = reconcile.stage_recovery_data(
        live,
        first.snapshot_key,
        staging,
        set_id="first",
        encrypted_configuration=crypto.encrypt(recovery_key, b'{"setting":"old"}'),
        encrypted_operator_key=crypto.encrypt(recovery_key, old_operator),
        operator_key=old_operator,
    )

    # A later backup sees different graph configuration and a rewrapped DEK.
    # Its immutable directory cannot alter any object named by the first set.
    new_operator = b"n" * 32
    crypto.rewrap_dek(live, new_operator.decode())
    live.hst_secret_key = new_operator.decode()
    second = _publish(live, 2_000, old_dek, first)
    reconcile.stage_recovery_data(
        live,
        second.snapshot_key,
        staging,
        set_id="second",
        encrypted_configuration=crypto.encrypt(recovery_key, b'{"setting":"new"}'),
        encrypted_operator_key=crypto.encrypt(recovery_key, new_operator),
        operator_key=new_operator,
    )

    restored = Settings(_env_file=None, hst_data_dir=tmp_path / "restored")
    for obj in first_objects:
        if not obj.restore_path:
            continue
        source = staging / "sets" / "first" / "data" / obj.restore_path
        destination = restored.hst_data_dir / obj.restore_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    recovery_set = reconcile.RecoverySet(
        created="first",
        snapshot_key=first.snapshot_key,
        manifest_sha256=next(obj.sha256 for obj in first_objects if obj.role == "manifest"),
        boundary="committed graph pointer under cycle lock; identity store follows",
        objects=_with_dump(first_objects, "first"),
    )
    checked = reconcile.check_recovery_set(restored, recovery_set, {})
    assert checked.ok, checked.problems
    grapharchive.verify(restored, first.graph_archive, old_dek)


def test_recovery_stages_and_materializes_the_complete_manifest_chain(tmp_path):
    operator = b"k" * 32
    recovery_key = Fernet.generate_key().decode()
    live = Settings(_env_file=None, hst_data_dir=tmp_path / "live", hst_secret_key=operator.decode())
    live.hst_data_dir.mkdir()
    dek = crypto.dek(live)
    first = _publish(live, 1_000, dek)
    from hst.core import sidestore

    rib_path = sidestore.write_table(
        live.sidestore_dir,
        "rib",
        "iosxe",
        "edge-1",
        "2000-run",
        [
            {
                "device_uid": "device:1",
                "vrf": "default",
                "context_uid": "vrf:device-1:default",
                "prefix": "10.0.0.0/24",
                "next_hop": "192.0.2.1",
                "protocol": "bgp",
                "af": 4,
                "prefixlen": 24,
            }
        ],
        2_000,
    )
    assert rib_path is not None
    rib_entry = manifest.file_entry(live, rib_path)
    second = _publish(live, 2_000, dek, first, [rib_entry])
    staging = tmp_path / "staging"
    objects = reconcile.stage_recovery_data(
        live,
        second.snapshot_key,
        staging,
        set_id="chain",
        encrypted_configuration=crypto.encrypt(recovery_key, b"{}"),
        encrypted_operator_key=crypto.encrypt(recovery_key, operator),
        operator_key=operator,
    )
    objects.append(_sealed_dump(staging / "sets" / "chain", "chain", recovery_key, b"pg-dump-placeholder"))
    record = reconcile.RecoverySet(
        snapshot_key=second.snapshot_key,
        manifest_sha256=manifest.digest_of(live, second.snapshot_key),
        boundary="ordered",
        objects=objects,
    )
    materialized = reconcile.materialize_recovery_bundle(
        record, staging / "sets" / "chain", tmp_path / "restored-chain", recovery_key
    )
    assert (materialized.data_dir / "manifests" / "1000.json").is_file()
    assert materialized.operator_key == operator
    assert materialized.dek == dek
    restored_rib = materialized.data_dir / rib_entry.path
    assert manifest.sidestore_row_facts(restored_rib) == (
        rib_entry.row_count,
        rib_entry.rows_sha256,
    )


def test_stage_fails_if_wrapped_dek_no_longer_matches_historical_operator(tmp_path):
    operator = b"k" * 32
    settings = Settings(_env_file=None, hst_data_dir=tmp_path / "live", hst_secret_key=operator.decode())
    settings.hst_data_dir.mkdir()
    dek = crypto.dek(settings)
    record = _publish(settings, 1_000, dek)
    (settings.hst_data_dir / "dek.wrapped").write_bytes(Fernet.generate_key())

    with pytest.raises(crypto.SecretKeyError):
        reconcile.stage_recovery_data(
            settings,
            record.snapshot_key,
            tmp_path / "stage",
            set_id="bad-key",
            encrypted_configuration=b"encrypted",
            encrypted_operator_key=b"encrypted",
            operator_key=operator,
        )


def test_stage_fails_when_a_predecessor_manifest_is_missing(tmp_path):
    operator = b"k" * 32
    settings = Settings(_env_file=None, hst_data_dir=tmp_path / "live", hst_secret_key=operator.decode())
    settings.hst_data_dir.mkdir()
    dek = crypto.dek(settings)
    first = _publish(settings, 1_000, dek)
    second = _publish(settings, 2_000, dek, first)
    manifest.path_for(settings, first.snapshot_key).unlink()

    with pytest.raises(ValueError, match="manifest for snapshot 1000 is missing"):
        reconcile.stage_recovery_data(
            settings,
            second.snapshot_key,
            tmp_path / "stage",
            set_id="broken-chain",
            encrypted_configuration=b"encrypted",
            encrypted_operator_key=b"encrypted",
            operator_key=operator,
        )


def test_schema_two_fails_closed_without_exact_key_and_config_material(tmp_path):
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    record = reconcile.RecoverySet(
        snapshot_key=1,
        manifest_sha256="a" * 64,
        boundary="ordered",
        objects=[
            reconcile.RecoveryObject(role="postgres", key="mutable/postgres.dump", sha256="b" * 64, bytes=1)
        ],
    )
    checked = reconcile.check_recovery_set(settings, record, {})
    assert not checked.ok
    assert any("graph-archive" in problem for problem in checked.problems)
    assert any("operator-key" in problem for problem in checked.problems)
    assert any("mutable" in problem for problem in checked.problems)


@pytest.mark.db
@pytest.mark.skipif(not os.environ.get("NEO4J_TEST_URI"), reason="NEO4J_TEST_URI not set")
def test_older_authenticated_bundle_restores_graph_and_manifest_pinned_routing(tmp_path):
    from neo4j import GraphDatabase

    from hst.core import db as dbmod
    from hst.core import sidestore

    uri = os.environ["NEO4J_TEST_URI"]
    if dbmod.same_endpoint(uri, Settings(_env_file=None).neo4j_uri):
        pytest.exit("NEO4J_TEST_URI must name the scratch database", returncode=2)
    operator, replacement = b"o" * 32, b"n" * 32
    recovery_key = Fernet.generate_key().decode()
    live = Settings(_env_file=None, hst_data_dir=tmp_path / "live", hst_secret_key=operator.decode())
    live.hst_data_dir.mkdir()
    dek = crypto.dek(live)
    rib = sidestore.write_table(
        live.sidestore_dir,
        "rib",
        "iosxe",
        "edge-1",
        "1000-run",
        [
            {
                "device_uid": "device:1",
                "vrf": "default",
                "prefix": "10.0.0.0/24",
                "next_hop": "192.0.2.1",
                "protocol": "bgp",
                "af": 4,
                "prefixlen": 24,
            }
        ],
        1_000,
    )
    assert rib is not None
    first = _publish(live, 1_000, dek, files=[manifest.file_entry(live, rib)])
    stage = tmp_path / "stage"
    objects = reconcile.stage_recovery_data(
        live,
        first.snapshot_key,
        stage,
        set_id="old",
        encrypted_configuration=crypto.encrypt(recovery_key, b'{"routing":"old"}'),
        encrypted_operator_key=crypto.encrypt(recovery_key, operator),
        operator_key=operator,
    )
    objects.append(_sealed_dump(stage / "sets" / "old", "old", recovery_key, b"PGDMP authenticated fixture"))
    old_set = reconcile.RecoverySet(
        snapshot_key=1_000,
        manifest_sha256=manifest.digest_of(live, 1_000),
        boundary="ordered",
        objects=objects,
    )

    crypto.rewrap_dek(live, replacement.decode())
    live.hst_secret_key = replacement.decode()
    _publish(live, 2_000, dek, first)
    bundle = reconcile.materialize_recovery_bundle(
        old_set, stage / "sets" / "old", tmp_path / "restore", recovery_key
    )

    settings = Settings(
        _env_file=None,
        hst_data_dir=bundle.data_dir,
        neo4j_uri=uri,
        neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
        neo4j_database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"),
    )
    driver = GraphDatabase.driver(uri, auth=(settings.neo4j_user, settings.neo4j_password))
    try:
        with driver.session(database=settings.neo4j_database) as session:
            session.run("MATCH (n) DETACH DELETE n").consume()
            restored = manifest.read(settings, 1_000)
            assert restored.graph_archive is not None
            grapharchive.restore(session, settings, restored.graph_archive, bundle.dek, 9_000)
            answer = session.run(
                "MATCH (d:Device {collection_ts: $cts}) RETURN d.uid AS uid", cts=9_000
            ).single()
            assert answer["uid"] == "device:1"
        routes = sidestore.query(
            bundle.data_dir / "sidestore",
            "SELECT prefix, next_hop FROM rib WHERE snapshot_ts = 1000",
        )
        assert routes == [{"prefix": "10.0.0.0/24", "next_hop": "192.0.2.1"}]
    finally:
        with driver.session(database=settings.neo4j_database) as session:
            session.run("MATCH (n) DETACH DELETE n").consume()
        driver.close()


def test_a_set_without_a_version_is_schema_one():
    record = reconcile.RecoverySet(
        snapshot_key=1_000,
        manifest_sha256="a" * 64,
        data_prefix="data",
        data_object_list_sha256="b" * 64,
    )

    assert record.schema_version == 1
    assert record.objects == []


def _record_migrations(monkeypatch, *, current: bool) -> list[str]:
    from hst.app.store import pg

    calls: list[str] = []
    monkeypatch.setattr(pg, "upgrade_to_head", lambda *args: calls.append("upgrade"))
    monkeypatch.setattr(pg, "schema_is_current", lambda *args: current)
    return calls


def test_prepare_stops_at_another_schema_revision_and_applies_no_migration(monkeypatch, tmp_path):
    calls = _record_migrations(monkeypatch, current=False)
    monkeypatch.setenv("HST_BACKUP_ENCRYPTION_KEY", Fernet.generate_key().decode())

    prepared = runner.invoke(cli.app, ["recovery", "prepare", str(tmp_path), "--set-id", "job"])

    assert prepared.exit_code == 1, prepared.output
    assert "the Postgres schema is not at the revision" in " ".join(prepared.output.split())
    assert calls == []
    assert not (tmp_path / "sets").exists()


def test_the_store_of_prepare_opens_at_the_current_revision_without_a_migration(monkeypatch):
    from hst.app.store import pg

    calls = _record_migrations(monkeypatch, current=True)
    settings = Settings(_env_file=None, postgres_dsn="postgresql+asyncpg://u:p@localhost:1/d")

    store = cli._open_store(settings, migrate=False)

    assert isinstance(store, pg.PgStore)
    assert calls == []
