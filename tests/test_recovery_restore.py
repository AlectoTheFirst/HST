"""The storage acceptance test: a backed-up estate
restores into scratch stores and answers the same questions."""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime
from typing import Any

import pytest
from typer.testing import CliRunner

import hst.cli as cli
from hst.app.crypto import generate_key
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.util import GraphBuilder, connected_address
from hst.core import manifest, reconcile, replay, uid
from hst.core.config import Settings
from hst.path import trace

runner = CliRunner()

URI = os.environ.get("NEO4J_TEST_URI")
KEY = generate_key()
NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)

# The two interface addresses the trace below runs between. Both sit on the one
# router, in two connected prefixes it originates, so the answer rests on the
# reasoner's gateway edges as well as on the replayed payload: a rebuild that
# skipped the finalization answers differently.
SRC_IP = "10.10.0.1"
DST_IP = "10.10.1.1"


class _HostCfg(SourceConfig):
    host: str = ""


class _RouterCollector(Collector):
    """One router with two addressed interfaces in its global table, and a RIB
    table in the side store."""

    name = "vyos"
    ConfigModel = _HostCfg
    SIDE_TABLES = ("rib",)

    def fetch(self) -> Any:
        return {"host": self.config.host}

    def probe(self) -> str:
        return "ok"

    def normalize(self, raw: Any) -> Any:
        b = GraphBuilder()
        host = raw["host"]
        device = b.node("Device", f"dev:{host}", hostname=host, role="router")
        vrf = b.node("VrfInstance", uid.vrf(device, "default"), name="default", anchor=device, is_global=True)
        for name, address in (("eth0", f"{SRC_IP}/24"), ("eth1", f"{DST_IP}/24")):
            iface = b.node("Interface", uid.interface(device, name), name=name, anchor=device)
            b.rel("ON", "Interface", iface, "Device", device)
            b.rel("IN_VRF", "Interface", iface, "VrfInstance", vrf)
            ip_uid, _prefix = connected_address(b, address, anchor=vrf, dom="default", vrf_uid=vrf)
            b.rel("HAS_IP", "Interface", iface, "IpAddress", ip_uid)
        return b.batch(self.config.source_name or self.name, f"vyos:{host}")

    def side_tables(self, raw: Any) -> dict[str, list[dict]]:
        device = f"dev:{raw['host']}"
        return {
            "rib": [
                {
                    "device_uid": device,
                    "vrf": "default",
                    "prefix": cidr,
                    "protocol": "connected",
                    "interface": name,
                }
                for cidr, name in (("10.10.0.0/24", "eth0"), ("10.10.1.0/24", "eth1"))
            ]
        }


def _answer(session: Any) -> dict[str, Any]:
    """One trace answer, as the estate would answer it."""
    return trace(session, SRC_IP, DST_IP)


def _recovery_set(settings: Settings, snapshot_key: int, into) -> reconcile.RecoverySet:
    """Write the set the backup CronJob writes, and read it back the way
    `recovery check` does.

    Built from the same two values the CronJob reads off the volume: the newest
    manifest's key, and the sha256 of that manifest's file.
    """
    record = manifest.read(settings, snapshot_key)
    written = reconcile.RecoverySet(
        created="20260905T033000Z",
        postgres_dump_key="postgres/hst-pg-20260905T030000Z.dump",
        snapshot_key=snapshot_key,
        manifest_sha256=manifest.digest_of(settings, snapshot_key),
        chain_index=record.chain_index,
        data_prefix="data",
        data_object_list_sha256="0" * 64,
        secrets={"operatorKey": "hst", "objectStore": "hst-backup-s3"},
        settings=["HST_SECRET_KEY_FILE", "HST_DATA_DIR", "POSTGRES_DSN", "NEO4J_URI"],
    )
    path = into / f"{written.created}.json"
    path.write_text(written.model_dump_json())
    return reconcile.read_set(path)


@pytest.mark.db
@pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")
def test_a_restored_estate_rebuilds_to_the_same_snapshot_and_answers_the_same(monkeypatch, tmp_path):
    pytest.importorskip("pyarrow")

    from neo4j import GraphDatabase

    from hst.app import runs_exec
    from hst.app.store import Device, Source
    from hst.core import db as dbmod

    live_root = tmp_path / "live"
    live_root.mkdir()
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This test wipes its target. "
            f"Point it at a scratch database.",
            returncode=2,
        )

    def _settings(root) -> Settings:
        return Settings(
            _env_file=None,
            hst_data_dir=root,
            hst_secret_key=KEY,
            neo4j_uri=URI,
            neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
            neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
            neo4j_database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"),
        )

    settings = _settings(live_root)
    row = Source(1, "edge", "vyos", {"host": "r1"}, b"", True, NOW, NOW)
    device_row = Device(1, "edge", "r1", None, True, "", NOW, NOW)
    driver = GraphDatabase.driver(URI, auth=(settings.neo4j_user, settings.neo4j_password))
    try:
        with driver.session(database=settings.neo4j_database) as session:
            dbmod.init_db(session)
            replay._clear_target(session)  # a cold start: no pointer, nothing to carry

            collector = _RouterCollector(_HostCfg(host="r1", source_name="edge"), settings)
            prepared = [
                runs_exec.PreparedSource(row, [runs_exec.PreparedDevice(device_row, collector, None)])
            ]
            _summary, _ran, cts, _ = runs_exec.execute_cycle(settings, prepared, {"edge"}, {})
            assert cts is not None

            record = manifest.read(settings, cts)
            assert record.checkpoint is not None and record.checkpoint.sha256
            published = record.checkpoint.sha256
            assert record.checkpoint.nodes > 0 and record.checkpoint.rels > 0
            assert [e.kind for e in record.files].count("sidestore") == 1

            published_answer = _answer(session)
            # the answer rests on something: the gateway edge the reasoner derived
            # from this payload puts the router in the path
            assert "dev:r1" in {hop["uid"] for hop in published_answer["hops"]}

            # The export leg: the evidence about the snapshot, and the recovery set
            # beside it, are what an operator carries off the box.
            export = tmp_path / "export"
            monkeypatch.setattr(cli, "Settings", lambda: settings)
            result = runner.invoke(cli.app, ["evidence", "export", str(cts), str(export)])
            assert result.exit_code == 0, result.output
            exported = (export / f"{cts}.json").read_bytes()
            assert exported == manifest.path_for(settings, cts).read_bytes()
            recovery_set = _recovery_set(settings, cts, export)

            # The restore: the data volume, as a backup restores it onto a fresh
            # PVC. The wrapped data key travels with it, so the same operator key
            # opens the payloads in their new location.
            restored_root = tmp_path / "restored"
            shutil.copytree(live_root, restored_root)
            restored = _settings(restored_root)

            # The restored tree accounts for itself: every file its manifests name
            # is present and digests to what was recorded, and nothing is orphaned.
            scan = reconcile.scan(restored)
            assert scan.ok, scan.problems
            assert scan.verified == len(record.files)
            assert not scan.orphans

            check = reconcile.check_recovery_set(
                restored, recovery_set, {"edge": (row.type, row.enabled, row.config)}
            )
            assert check.ok, check.problems
            assert check.sources_checked == 1
            assert check.evidence is not None and check.evidence.files == len(record.files)

            lookup = replay.SourceLookup(
                collector=_RouterCollector(_HostCfg(host="r1", source_name="edge"), restored),
                type=row.type,
                enabled=row.enabled,
                config=row.config,
            )
            report = replay.rebuild_from_manifest(restored, session, cts, source_for=lambda _n: lookup)
            assert report.ok, report.failed
            assert report.cleared  # the published run was wiped, then rebuilt from the restore
            assert report.side_table_notes == []  # the restored parquet file verified in place

            assert manifest.checkpoint(session, cts).sha256 == published
            assert _answer(session) == published_answer
    finally:
        with driver.session(database=settings.neo4j_database) as session:
            replay._clear_target(session)
        driver.close()
        dbmod.close_drivers()
