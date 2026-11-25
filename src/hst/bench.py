"""Fake-fleet benchmark for the collection engine."""

from __future__ import annotations

import asyncio
import hashlib
import json
import resource
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import asyncssh
from pydantic import SecretStr

from hst.app.runs_exec import PreparedDevice, _fetch_phase, _fetch_phase_async
from hst.app.store import Device, DeviceStatus
from hst.collectors import assh
from hst.collectors.auth import SshPassword
from hst.collectors.base import Collector, SourceConfig, raw_sha
from hst.core import Settings
from hst.core.model import Batch

if TYPE_CHECKING:
    from neo4j import Session

GROUP = "bench"

BENCH_USER = "bench"
BENCH_PASSWORD = "bench"  # noqa: S105 - the fixture password of the loopback bench server


class BenchConfig(SourceConfig):
    transport: str = "asyncssh"


class BenchCollector(Collector):
    """A fake device. `fetch` sleeps for the modeled round trip and returns a canned
    payload. A changed `seq` changes the payload hash."""

    name = "bench"
    VOLATILE_RAW_KEYS = ("uptime",)

    def __init__(self, host: str, latency_s: float, payload_bytes: int, seq: int = 0) -> None:
        super().__init__(BenchConfig(routing_scope=""), None)  # type: ignore[arg-type]  # no Settings needed
        self.host = host
        self.latency_s = latency_s
        self.payload_bytes = payload_bytes
        self.seq = seq
        self.scope = f"bench:{host}"

    def payload(self) -> dict:
        return {
            "host": self.host,
            "config": "x" * self.payload_bytes,
            "seq": self.seq,
            "uptime": time.monotonic(),  # a VOLATILE_RAW_KEYS key
        }

    def fetch(self) -> dict:
        time.sleep(self.latency_s)
        return self.payload()

    async def afetch(self) -> dict:
        await asyncio.sleep(self.latency_s)
        return self.payload()

    def normalize(self, raw: dict) -> Batch:
        raise NotImplementedError("the bench never normalizes")

    def probe(self) -> str:
        return f"bench device {self.host}"


class SshBenchCollector(BenchCollector):
    """Mode B's device fetches the payload over an asyncssh session to the
    in-process server. The server sleeps the latency that the command holds.
    `_mode_b_fetch` sets `port` once the listener knows its port."""

    port = 0

    async def afetch(self) -> dict:
        auth = SshPassword(username=BENCH_USER, password=SecretStr(BENCH_PASSWORD))
        async with assh.session("127.0.0.1", auth, port=self.port) as s:
            text = await s.run(f"show bench {int(self.latency_s * 1000)}")
        return {
            "host": self.host,
            "config": text[: self.payload_bytes],
            "seq": self.seq,
            "uptime": time.monotonic(),
        }

    def fetch(self) -> dict:
        return asyncio.run(self.afetch())


class _BenchServer(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == BENCH_USER and password == BENCH_PASSWORD


def _bench_handler(payload_bytes: int):
    async def handle(process: asyncssh.SSHServerProcess) -> None:
        parts = (process.command or "").split()
        sleep_ms = int(parts[-1]) if parts and parts[-1].isdigit() else 0
        await asyncio.sleep(sleep_ms / 1000.0)
        process.stdout.write("x" * payload_bytes)
        process.exit(0)

    return handle


async def _mode_b_fetch(
    settings: Settings,
    units: list[tuple[str, PreparedDevice]],
    prior: dict[tuple[str, str], DeviceStatus],
    payload_bytes: int,
) -> dict:
    """Run the fetch phase of the engine with one client session per device against one SSH listener."""
    key = asyncssh.generate_private_key("ssh-ed25519")
    listener = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_factory=_BenchServer,
        server_host_keys=[key],
        process_factory=_bench_handler(payload_bytes),
    )
    for _, unit in units:
        if isinstance(unit.collector, SshBenchCollector):
            unit.collector.port = listener.get_port()
    try:
        return await _fetch_phase_async(settings, units, prior, allow_skip=True)
    finally:
        listener.close()
        await listener.wait_closed()


def _jitter(host: str) -> float:
    """A stable per-host fraction in [0, 1) that spreads latencies without a
    random source."""
    digest = hashlib.blake2b(host.encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") % 1_000_000 / 1_000_000


@dataclass
class BenchResult:
    devices: int
    concurrency: int
    latency_ms: int
    change_rate: float
    wall_s: float
    fetched: int
    loaded: int
    skipped: int
    failed: int
    load_wall_s: float
    mode: str = "a"

    @property
    def total_s(self) -> float:
        return self.wall_s + self.load_wall_s

    def fits(self, cadence_s: float) -> bool:
        return self.total_s <= cadence_s

    def line(self, cadence_s: float) -> str:
        verdict = "fits" if self.fits(cadence_s) else "does not fit"
        return (
            f"mode {self.mode.upper()}: "
            f"{self.devices} devices @ {self.latency_ms}ms latency, "
            f"concurrency {self.concurrency}, change rate {self.change_rate:.0%}: "
            f"fetch {self.wall_s:.1f}s + load {self.load_wall_s:.1f}s = "
            f"{self.total_s:.1f}s, {verdict} the {cadence_s:.0f}s budget "
            f"({self.loaded} loaded, {self.skipped} skipped, {self.failed} failed)"
        )


def run_bench(
    *,
    devices: int,
    latency_ms: int = 500,
    jitter_ms: int = 200,
    concurrency: int = 64,
    change_rate: float = 0.05,
    payload_bytes: int = 20_000,
    load_ms: int = 0,
    mode: str = "a",
) -> BenchResult:
    """One measured cycle over a warm fleet.

    In a warm fleet, every device has a prior `device_status` row whose hash
    matches the baseline payload. The `change_rate` fraction of the devices gets
    `seq` 1, misses the skip and reaches the load stage.

    `mode` "a" models the round trip with a sleep. `mode` "b" opens an asyncssh
    session per device against an in-process server, with the sleep on the
    server side.
    """
    if mode not in ("a", "b"):
        raise ValueError(f"unknown bench mode {mode!r}")
    settings = Settings(collect_max_concurrency=concurrency, collect_spill_mb=0)
    now = datetime.now(UTC)
    changed_every = int(1 / change_rate) if change_rate > 0 else 0
    collector_cls = SshBenchCollector if mode == "b" else BenchCollector

    units: list[tuple[str, PreparedDevice]] = []
    prior: dict[tuple[str, str], DeviceStatus] = {}
    for i in range(devices):
        host = f"dev{i:05d}"
        latency = (latency_ms + _jitter(host) * jitter_ms) / 1000.0
        collector = collector_cls(host, latency, payload_bytes)
        baseline = raw_sha(collector, collector.payload())
        if changed_every and i % changed_every == 0:
            collector.seq = 1  # The hash differs from the baseline hash. The device reaches the load stage.
        device = Device(i, GROUP, host, None, True, "", now, now)
        units.append((GROUP, PreparedDevice(device, collector, None)))
        prior[(GROUP, host)] = DeviceStatus(
            id=i,
            source=GROUP,
            host=host,
            last_raw_sha=baseline,
            last_attempt_at=now,
            last_success_at=now,
            last_full_at=now,
            consecutive_failures=0,
            last_error="",
            fetch_ms=None,
            normalize_ms=None,
            load_ms=None,
            updated_at=now,
        )

    t0 = time.perf_counter()
    if mode == "b":
        fetched = asyncio.run(_mode_b_fetch(settings, units, prior, payload_bytes))
    else:
        fetched = _fetch_phase(settings, units, prior, allow_skip=True)
    wall_s = time.perf_counter() - t0

    loaded = skipped = failed = 0
    t1 = time.perf_counter()
    for _, unit in units:
        f = fetched[id(unit)]
        if f.error:
            failed += 1
        elif f.skipped:
            skipped += 1
        else:
            loaded += 1
            if load_ms:
                time.sleep(load_ms / 1000.0)  # the serial session-holding phase
    load_wall_s = time.perf_counter() - t1

    return BenchResult(
        devices=devices,
        concurrency=concurrency,
        latency_ms=latency_ms,
        change_rate=change_rate,
        wall_s=wall_s,
        fetched=len(fetched),
        loaded=loaded,
        skipped=skipped,
        failed=failed,
        load_wall_s=load_wall_s,
        mode=mode,
    )


# --- the estate benchmark ---------------------------------------------------------------


def _prefix(device: int, index: int) -> str:
    """A distinct /24 per (device, row), derived from both."""
    n = device * 1_000_003 + index
    return f"{10 + n // 65_536 % 100}.{n // 256 % 256}.{n % 256}.0/24"


def _rib_rows(device_uid: str, context_uid: str, device: int, count: int) -> list[dict]:
    from hst.core.ipenc import prefix_bounds

    rows = []
    for i in range(count):
        prefix = _prefix(device, i)
        lo, hi, plen, af = prefix_bounds(prefix)
        rows.append(
            {
                "device_uid": device_uid,
                "vrf": "default",
                "context_uid": context_uid,
                "prefix": prefix,
                "next_hop": f"10.255.{i % 256}.1",
                "next_hop_context_uid": None,
                "interface": "eth0",
                "protocol": "bgp",
                "discard": None,
                "metric": 20,
                "af": af,
                "prefixlen": plen,
                "lo": lo,
                "hi": hi,
            }
        )
    return rows


def _path_rows(device_uid: str, context_uid: str, device: int, peers: int, paths: int) -> list[dict]:
    """The `bgp_session_routes` rows with `paths` prefixes per peer and one received
    path per prefix. `bgp_session_routes` is the widest table that an estate writes."""
    from hst.core.ipenc import prefix_bounds

    rows = []
    for peer in range(peers):
        peer_ip = f"192.0.2.{peer % 254 + 1}"
        session_uid = f"{device_uid}:bgp:{peer_ip}"
        for i in range(paths):
            prefix = _prefix(device, peer * paths + i)
            lo, hi, plen, af = prefix_bounds(prefix)
            rows.append(
                {
                    "device_uid": device_uid,
                    "context_uid": context_uid,
                    "session_uid": session_uid,
                    "peer_ip": peer_ip,
                    "af": af,
                    "safi": "unicast",
                    "direction": "received",
                    "rib_type": "adj-rib-in",
                    "policy_stage": "pre-import",
                    "path_id": "0",
                    "prefix": prefix,
                    "prefixlen": plen,
                    "lo": lo,
                    "hi": hi,
                    "next_hop": peer_ip,
                    "next_hop_context_uid": None,
                    "as_path": f"65000 {64512 + peer}",
                    "local_pref": 100,
                    "med": 0,
                    "origin": "igp",
                    "communities": "65000:100",
                    "best": peer == 0,
                }
            )
    return rows


def _session_rows(device_uid: str, context_uid: str, peers: int, paths: int) -> list[dict]:
    return [
        {
            "device_uid": device_uid,
            "context_uid": context_uid,
            "session_uid": f"{device_uid}:bgp:192.0.2.{peer % 254 + 1}",
            "peer_ip": f"192.0.2.{peer % 254 + 1}",
            "af": 4,
            "safi": "unicast",
            "state": "Established",
            "established_since_ms": 1_780_000_000_000,
            "prefixes_received": paths,
            "prefixes_advertised": 0,
            "capabilities": "multiprotocol, route-refresh",
        }
        for peer in range(peers)
    ]


class _EstateSession:
    """Answers the two reads of `manifest.checkpoint` with the shape of the estate.

    The shape is one node per device plus one per BGP session, and one relationship
    per session. The rows are generated as they are read."""

    def __init__(self, devices: int, peers: int) -> None:
        self.devices = devices
        self.peers = peers

    def execute_read(self, work: Any) -> Any:
        return work(self)

    def run(self, query: str, **params: Any) -> Iterator[dict]:
        return self._nodes() if "MATCH (n:Obj" in query else self._rels()

    def _nodes(self) -> Iterator[dict]:
        for device in range(self.devices):
            uid = f"dev:bench{device:05d}"
            yield {"uid": uid, "labels": ["Obj", "Device"], "props": {"name": uid, "vendor": "bench"}}
            for peer in range(self.peers):
                yield {
                    "uid": f"{uid}:bgp:{peer}",
                    "labels": ["Obj", "BgpSession"],
                    "props": {"peer_ip": f"192.0.2.{peer % 254 + 1}", "peer_as": 64512 + peer},
                }

    def _rels(self) -> Iterator[dict]:
        for device in range(self.devices):
            uid = f"dev:bench{device:05d}"
            for peer in range(self.peers):
                yield {"t": "HAS_SESSION", "start": uid, "end": f"{uid}:bgp:{peer}", "props": {}}


def _evidence(store: Path, devices: int, run_id: str) -> Any:
    """The snapshot evidence that a published manifest of the newest run gives the
    reader. The evidence holds one `rib` file per device with its exact path."""
    from hst.core import ribsource

    return ribsource.SnapshotEvidence(
        snapshot_key=1_780_000_000_000,
        data_dir=store,
        devices=[
            ribsource.DeviceEvidence(
                source=GROUP,
                host=f"bench{device:05d}",
                run_id=run_id,
                outcome="complete",
                path=store / "rib" / GROUP / f"bench{device:05d}" / f"{run_id}.parquet",
            )
            for device in range(devices)
        ],
        chain=ribsource._Chain(None),
    )


def _peak_rss_mb() -> float:
    """Peak resident set size of this process, in MiB. `ru_maxrss` is bytes on
    macOS and kilobytes on Linux."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


@dataclass
class EstateResult:
    devices: int
    runs: int
    rib_rows: int
    peers: int
    paths: int
    rows: int
    files: int
    bytes_on_disk: int
    write_s: float
    digest_s: float
    lookups: int
    lpm_ms: float
    lpm_glob_ms: float
    lpm_matched: int
    checkpoint_nodes: int
    checkpoint_rels: int
    checkpoint_s: float
    rss_mb: float

    def line(self) -> str:
        return (
            f"{self.devices} devices x {self.runs} runs, "
            f"{self.rib_rows} RIB rows and {self.peers} peers x {self.paths} paths per device: "
            f"{self.rows:,} rows in {self.files:,} files, "
            f"{self.bytes_on_disk / 1024 / 1024:.1f} MiB on disk; "
            f"write {self.write_s:.1f}s, digest {self.digest_s:.1f}s, "
            f"LPM {self.lpm_ms:.1f}ms from the manifest and {self.lpm_glob_ms:.1f}ms from the glob "
            f"over {self.lookups} lookups, "
            f"checkpoint {self.checkpoint_s:.1f}s over "
            f"{self.checkpoint_nodes:,} nodes and {self.checkpoint_rels:,} relationships; "
            f"peak RSS {self.rss_mb:.0f} MiB"
        )


@dataclass
class EstateAcceptanceResult:
    """Machine-readable end-to-end estate measurement."""

    estate: EstateResult
    graph_runs: int
    graph_nodes_written: int
    graph_rels_written: int
    graph_write_s: float
    graph_checkpoint_s: float
    manifest_lpm_ms: float
    manifest_lpm_matched: int
    retention_s: float
    retention_deleted: list[int]
    archive_bytes: int
    archive_s: float
    restore_s: float
    restored_nodes: int
    restored_rels: int
    sample_answers: dict[str, int]
    rss_mb: float

    def as_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2)


def _write_graph_run(
    session: Any, snapshot_key: int, devices: int, peers: int, parent: int | None
) -> tuple[int, int]:
    """Write one retained graph run in bounded UNWIND batches."""
    from hst.core import cycle

    batch = 2_000
    node_count = rel_count = 0
    for start in range(0, devices, batch):
        stop = min(devices, start + batch)
        device_rows = [
            {"uid": f"dev:bench{i:05d}", "collection_ts": snapshot_key, "name": f"bench{i:05d}"}
            for i in range(start, stop)
        ]
        session.run(
            "UNWIND $rows AS row CREATE (n:Obj:Device) SET n = row",
            rows=device_rows,
        ).consume()
        node_count += len(device_rows)
        for peer in range(peers):
            session_rows = [
                {
                    "uid": f"dev:bench{i:05d}:bgp:{peer}",
                    "collection_ts": snapshot_key,
                    "peer_ip": f"192.0.2.{peer + 1}",
                }
                for i in range(start, stop)
            ]
            session.run(
                "UNWIND $rows AS row CREATE (n:Obj:BgpSession) SET n = row",
                rows=session_rows,
            ).consume()
            session.run(
                "UNWIND $rows AS row "
                "MATCH (d:Device:Obj {uid: row.device, collection_ts: $snap}), "
                "(p:BgpSession:Obj {uid: row.peer, collection_ts: $snap}) "
                "CREATE (d)-[:HAS_SESSION {collection_ts: $snap}]->(p)",
                rows=[
                    {
                        "device": f"dev:bench{i:05d}",
                        "peer": f"dev:bench{i:05d}:bgp:{peer}",
                    }
                    for i in range(start, stop)
                ],
                snap=snapshot_key,
            ).consume()
            node_count += len(session_rows)
            rel_count += len(session_rows)
    cycle.write_cycle_meta(
        session,
        snapshot_key,
        statuses={"bench": "fresh"},
        carried_from=None,
        nodes=node_count,
        rels=rel_count,
        degraded=False,
        kind="full",
        parent=parent,
    )
    cycle.set_pointer(session, snapshot_key)
    return node_count, rel_count


def run_estate_acceptance(
    *,
    settings: Settings,
    devices: int,
    runs: int = 3,
    rib_rows: int = 1_000,
    peers: int = 2,
    paths: int = 500,
    lookups: int = 50,
    output: Path | None = None,
) -> EstateAcceptanceResult:
    """Measure the full retained estate against a disposable Neo4j.

    It runs in the manually dispatched scratch-database workflow.
    """
    from cryptography.fernet import Fernet

    from hst.core import cycle, db, grapharchive, manifest
    from hst.core import replay as replaymod

    settings.hst_data_dir.mkdir(parents=True, exist_ok=True)
    with db.session(settings) as session:
        replaymod._clear_target(session)
        db.init_db(session)
        estate = run_estate_bench(
            devices=devices,
            runs=runs,
            rib_rows=rib_rows,
            peers=peers,
            paths=paths,
            lookups=lookups,
            base_dir=settings.sidestore_dir,
        )
        graph_nodes = graph_rels = 0
        graph_start = time.perf_counter()
        keys = [1_780_000_000_000 + run * 600_000 for run in range(runs)]
        for index, key in enumerate(keys):
            nodes, rels = _write_graph_run(session, key, devices, peers, keys[index - 1] if index else None)
            graph_nodes += nodes
            graph_rels += rels
        graph_write_s = time.perf_counter() - graph_start

        checkpoint_start = time.perf_counter()
        checkpoint = manifest.checkpoint(session, keys[-1])
        graph_checkpoint_s = time.perf_counter() - checkpoint_start

        retention_start = time.perf_counter()
        deleted = cycle.prune(session, max(1, runs - 1))
        retention_s = time.perf_counter() - retention_start

        archive_key = Fernet.generate_key().decode()
        archive_start = time.perf_counter()
        entry = grapharchive.write(
            session,
            settings,
            keys[-1],
            archive_key,
            normalization_context={"benchmark": "estate-acceptance"},
        )
        grapharchive.verify(settings, entry, archive_key)
        archive_s = time.perf_counter() - archive_start

        # Write a manifest for the current run, then resolve the LPM input through it.
        from hst.core import ribsource
        from hst.core.model import TableOutcome

        latest_run_id = f"{keys[-1]}-{runs - 1:08x}"
        files = []
        device_entries = []
        for device in range(devices):
            host = f"bench{device:05d}"
            rib_path = settings.sidestore_dir / "rib" / GROUP / host / f"{latest_run_id}.parquet"
            file_entry = manifest.file_entry(settings, rib_path)
            files.append(file_entry)
            device_entries.append(
                manifest.DeviceEntry(
                    source=GROUP,
                    host=host,
                    outcome="collected",
                    effective_run=latest_run_id,
                    tables={
                        "rib": TableOutcome(
                            status="complete",
                            row_count=rib_rows,
                            path=file_entry.path,
                        )
                    },
                )
            )
        manifest_record = manifest.SnapshotManifest(
            snapshot_key=keys[-1],
            kind="full",
            parent=keys[-2] if len(keys) > 1 else None,
            opened=manifest.iso(keys[-1]),
            published=manifest.now_iso(),
            devices=device_entries,
            files=files,
            graph_archive=manifest.GraphArchiveEntry.model_validate(entry),
        )
        manifest.write(settings, manifest_record)
        evidence = ribsource.snapshot_evidence(settings, keys[-1], manifest=manifest_record)
        if evidence is None:
            raise AssertionError("current manifest did not resolve RIB evidence")
        manifest_reader = ribsource.RibSource(settings.sidestore_dir, evidence=evidence)
        lpm_start = time.perf_counter()
        manifest_matches = manifest_reader.lpm("dev:bench00000", "dev:bench00000:vrf:default", "10.0.0.7")
        manifest_lpm_ms = (time.perf_counter() - lpm_start) * 1_000

        def count(query: str, **params: Any) -> int:
            record = session.run(query, **params).single()
            if record is None:
                raise AssertionError("benchmark count query returned no row")
            return int(record["n"])

        expected_samples = {
            "devices": count(
                "MATCH (n:Device:Obj {collection_ts: $snap}) RETURN count(n) AS n", snap=keys[-1]
            ),
            "sessions": count(
                "MATCH (n:BgpSession:Obj {collection_ts: $snap}) RETURN count(n) AS n", snap=keys[-1]
            ),
            "links": count(
                "MATCH ()-[r:HAS_SESSION {collection_ts: $snap}]->() RETURN count(r) AS n",
                snap=keys[-1],
            ),
        }

        replaymod._clear_target(session)
        restore_start = time.perf_counter()
        restored_nodes, restored_rels = grapharchive.restore(session, settings, entry, archive_key, keys[-1])
        restore_s = time.perf_counter() - restore_start
        restored_samples = {
            "devices": count("MATCH (n:Device) RETURN count(n) AS n"),
            "sessions": count("MATCH (n:BgpSession) RETURN count(n) AS n"),
            "links": count("MATCH ()-[r:HAS_SESSION]->() RETURN count(r) AS n"),
        }
        if restored_samples != expected_samples:
            raise AssertionError(f"restored graph answers differ: {restored_samples} != {expected_samples}")
        result = EstateAcceptanceResult(
            estate=estate,
            graph_runs=runs,
            graph_nodes_written=graph_nodes,
            graph_rels_written=graph_rels,
            graph_write_s=graph_write_s,
            graph_checkpoint_s=graph_checkpoint_s,
            manifest_lpm_ms=manifest_lpm_ms,
            manifest_lpm_matched=len(manifest_matches),
            retention_s=retention_s,
            retention_deleted=deleted,
            archive_bytes=entry["bytes"],
            archive_s=archive_s,
            restore_s=restore_s,
            restored_nodes=restored_nodes,
            restored_rels=restored_rels,
            sample_answers=restored_samples,
            rss_mb=_peak_rss_mb(),
        )
        if checkpoint.nodes != devices * (1 + peers) or checkpoint.rels != devices * peers:
            raise AssertionError("current graph checkpoint cardinality differs from the requested estate")
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(result.as_json() + "\n", encoding="utf-8")
        replaymod._clear_target(session)
        return result


@dataclass
class CheckpointResult:
    nodes: int
    rels: int
    seconds: float
    rss_mb: float

    def line(self) -> str:
        return (
            f"checkpoint over {self.nodes:,} nodes and {self.rels:,} relationships: "
            f"{self.seconds:.1f}s, peak RSS {self.rss_mb:.0f} MiB"
        )


def run_checkpoint_bench(*, devices: int, peers: int) -> CheckpointResult:
    """Digest the open state of a graph with one node per device plus one per BGP
    session, and one relationship per session.

    The rows are generated as the digest reads them.
    """
    from hst.core import manifest as manifestmod

    session = cast("Session", _EstateSession(devices, peers))
    t0 = time.perf_counter()
    checkpoint = manifestmod.checkpoint(session, 1_780_000_000_000)
    seconds = time.perf_counter() - t0
    return CheckpointResult(
        nodes=checkpoint.nodes, rels=checkpoint.rels, seconds=seconds, rss_mb=_peak_rss_mb()
    )


def run_estate_bench(
    *,
    devices: int,
    runs: int = 1,
    rib_rows: int = 1000,
    peers: int = 0,
    paths: int = 0,
    lookups: int = 20,
    base_dir: Path | None = None,
    row_group_rows: int | None = None,
) -> EstateResult:
    """Write, digest, look up and checkpoint a synthetic estate.

    The estate has N devices and K retained runs. Each device writes M RIB rows
    and the path tables of P peers. Every stage is the production stage.
    `sidestore.write_table` writes the parquet and digests its rows as it writes
    them. The row facts of each file for the manifest are taken from that record
    right after the write (`sidestore.written_row_facts`), as the manifest of a
    run takes them. `manifest.sidestore_row_facts` reads them back from the file
    only where the record holds none. `ribsource.RibSource` answers longest-prefix
    match over the store as a trace does. `manifest.checkpoint` digests the open
    state that a graph of that shape holds. The benchmark needs no database and
    no network.

    `base_dir` is where the estate is written. Without it, the estate goes to a
    temporary directory that is removed at the end. The reported RSS is the
    peak of the whole process.
    """
    from hst.core import manifest as manifestmod
    from hst.core import ribsource, sidestore

    with tempfile.TemporaryDirectory(prefix="hst-estate-") as scratch:
        store = Path(base_dir) if base_dir is not None else Path(scratch)
        rows = 0
        write_s = digest_s = 0.0
        for run in range(runs):
            snapshot_ts = 1_780_000_000_000 + run * 600_000
            run_id = f"{snapshot_ts}-{run:08x}"
            for device in range(devices):
                host = f"bench{device:05d}"
                device_uid = f"dev:{host}"
                context_uid = f"{device_uid}:vrf:default"
                tables = {
                    "rib": _rib_rows(device_uid, context_uid, device, rib_rows),
                    "bgp_session_routes": _path_rows(device_uid, context_uid, device, peers, paths),
                    "bgp_sessions": _session_rows(device_uid, context_uid, peers, paths),
                }
                for table, table_rows in tables.items():
                    if not table_rows:
                        continue
                    rows += len(table_rows)
                    t0 = time.perf_counter()
                    written = sidestore.write_table(
                        store,
                        table,
                        GROUP,
                        host,
                        run_id,
                        table_rows,
                        snapshot_ts,
                        row_group_rows=row_group_rows,
                    )
                    t1 = time.perf_counter()
                    write_s += t1 - t0
                    if written is not None:
                        # The `on_write` of the collection gives the file to the
                        # manifest at the same point, right after the write.
                        _facts = sidestore.written_row_facts(written) or manifestmod.sidestore_row_facts(
                            written
                        )
                        digest_s += time.perf_counter() - t1

        files = sorted(store.rglob("*.parquet"))
        bytes_on_disk = sum(path.stat().st_size for path in files)

        def measure(reader: ribsource.RibSource) -> tuple[float, int]:
            def probe(i: int) -> list[dict]:
                device = (i * max(1, devices // max(1, lookups))) % max(1, devices)
                address = _prefix(device, i % max(1, rib_rows)).removesuffix(".0/24") + ".7"
                uid = f"dev:bench{device:05d}"
                return reader.lpm(uid, f"{uid}:vrf:default", address)

            # The first lookup opens the connection and builds the view before the clock starts.
            matched = len(probe(0))
            t0 = time.perf_counter()
            for i in range(lookups):
                probe(i)
            return (time.perf_counter() - t0) * 1000 / max(1, lookups), matched

        # The snapshot-bound reader opens the files that a manifest publishes
        # for the devices it lists (one per device). The approximate reader
        # globs every file under rib/.
        lpm_ms, matched = measure(ribsource.RibSource(store, evidence=_evidence(store, devices, run_id)))
        lpm_glob_ms, _ = measure(ribsource.RibSource(store))

        # The checkpoint reads through a session. `_EstateSession` answers the two
        # reads with the shape of the estate.
        session = cast("Session", _EstateSession(devices, peers))
        t0 = time.perf_counter()
        checkpoint = manifestmod.checkpoint(session, 1_780_000_000_000)
        checkpoint_s = time.perf_counter() - t0

        return EstateResult(
            devices=devices,
            runs=runs,
            rib_rows=rib_rows,
            peers=peers,
            paths=paths,
            rows=rows,
            files=len(files),
            bytes_on_disk=bytes_on_disk,
            write_s=write_s,
            digest_s=digest_s,
            lookups=lookups,
            lpm_ms=lpm_ms,
            lpm_glob_ms=lpm_glob_ms,
            lpm_matched=matched,
            checkpoint_nodes=checkpoint.nodes,
            checkpoint_rels=checkpoint.rels,
            checkpoint_s=checkpoint_s,
            rss_mb=_peak_rss_mb(),
        )


# --- the HST map benchmark ----------------------------------

MAP_BATCH = 5_000
MAP_RUN_STEP_MS = 3_600_000
MAP_FIRST_RUN = 1_800_000_000_000
# The assumed cadence is 24 full cycles and 144 device runs per day.
RUNS_PER_YEAR = 61_320


def _write_map_run(session: Session, estate: Any, run: int, cts: int, parent: int | None) -> tuple[int, int]:
    """Write one run of the synthetic estate as a stamped copy, then move the pointer to it."""
    from hst.core import cycle
    from hst.map import estate as estatemod

    nodes = rels = 0
    pending: dict[str, list[dict]] = {}
    pending_rels: dict[str, list[dict]] = {}

    def flush_nodes(label: str) -> None:
        rows = pending.pop(label, [])
        if rows:
            session.run(f"UNWIND $rows AS row CREATE (n:Obj:`{label}`) SET n = row", rows=rows).consume()

    def flush_rels(kind: str) -> None:
        rows = pending_rels.pop(kind, [])
        if rows:
            session.run(
                "UNWIND $rows AS row "
                "MATCH (a:Obj {uid: row.a, collection_ts: $cts}) USING INDEX a:Obj(uid, collection_ts) "
                "MATCH (b:Obj {uid: row.b, collection_ts: $cts}) USING INDEX b:Obj(uid, collection_ts) "
                f"CREATE (a)-[r:`{kind}`]->(b) SET r = row.props, r.collection_ts = $cts",
                rows=rows,
                cts=cts,
            ).consume()

    chunks = list(estatemod.run_objects(estate, run))
    for chunk_nodes, _chunk_rels in chunks:
        for label, row in chunk_nodes:
            pending.setdefault(label, []).append({**row, "collection_ts": cts})
            nodes += 1
            if len(pending[label]) >= MAP_BATCH:
                flush_nodes(label)
    for label in list(pending):
        flush_nodes(label)
    for _chunk_nodes, chunk_rels in chunks:
        for kind, start, end, props in chunk_rels:
            pending_rels.setdefault(kind, []).append({"a": start, "b": end, "props": props})
            rels += 1
            if len(pending_rels[kind]) >= MAP_BATCH:
                flush_rels(kind)
    for kind in list(pending_rels):
        flush_rels(kind)
    cycle.write_cycle_meta(
        session,
        cts,
        statuses={"bench": "fresh"},
        carried_from=None,
        nodes=nodes,
        rels=rels,
        degraded=False,
        kind="full",
        parent=parent,
    )
    cycle.set_pointer(session, cts)
    return nodes, rels


def _size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def run_map_bench(
    *,
    settings: Settings,
    devices: int = 10_000,
    runs: int = 12,
    change_rate: float = 0.05,
    seed: int = 1,
    tier3_samples: int = 100,
    output: Path | None = None,
) -> dict[str, Any]:
    """Run the HST map benchmark against a disposable Neo4j.

    The benchmark writes `runs` runs of a synthetic estate of `devices` devices.
    `change_rate` of the devices change between two runs. Each run is projected
    the way the publish path projects it. The target is cleared first."""
    import gzip
    import statistics

    import pyarrow.parquet as pq

    from hst.core import db
    from hst.core import manifest as manifestmod
    from hst.core import replay as replaymod
    from hst.map import estate as estatemod
    from hst.map import layout_read, store, tier3, timeline
    from hst.map.project import Projection
    from hst.map.tiers import read as tierread
    from hst.map.tiers.schemas import COUNTS, DELTA_OF

    if db.same_endpoint(settings.neo4j_uri, Settings().neo4j_uri):
        raise RuntimeError(
            f"{settings.neo4j_uri} is the configured twin; point the benchmark at a scratch database"
        )
    spec = estatemod.Spec(devices=devices, seed=seed, change_rate=change_rate)
    estate = estatemod.build(spec)
    sidestore, markers_dir = settings.sidestore_dir, settings.manifests_dir
    keys = [MAP_FIRST_RUN + i * MAP_RUN_STEP_MS for i in range(runs)]
    per_run: list[dict[str, Any]] = []
    with db.session(settings) as session:
        replaymod._clear_target(session)
        db.init_db(session)
        parent: int | None = None
        for i, cts in enumerate(keys):
            t0 = time.perf_counter()
            nodes, rels = _write_map_run(session, estate, i, cts, parent)
            load_s = time.perf_counter() - t0
            t0 = time.perf_counter()
            projection = Projection(
                sidestore,
                markers_dir,
                cts,
                parent,
                "full",
                checkpoint_every=settings.hst_tier_checkpoint_every,
            )
            if parent is not None:
                manifestmod.graph_delta(session, parent, cts, observer=projection.observe)
            diff_s = time.perf_counter() - t0
            projection.prepare(session)
            marker = projection.publish()
            projection_s = time.perf_counter() - t0
            sizes = {
                name: _size(store.table_path(sidestore, name, cts))
                for name in (
                    "graph_delta",
                    "layout",
                    "render_bindings",
                    *sorted(set(DELTA_OF.values())),
                    *DELTA_OF,
                )
            }
            per_run.append(
                {
                    "run": i,
                    "key": cts,
                    "nodes": nodes,
                    "rels": rels,
                    "load_s": round(load_s, 2),
                    "diff_s": round(diff_s, 2),
                    "projection_s": round(projection_s, 2),
                    "durations_ms": marker.get("durations_ms"),
                    "hst_s": round(sum((marker.get("durations_ms") or {}).values()) / 1000, 2),
                    "peak_memory_bytes": marker.get("peak_memory_bytes"),
                    "tiers_ready": marker.get("tiers_ready"),
                    "failure": projection.failed,
                    "read_devices": projection.folded.read_devices if projection.folded else None,
                    "counts": marker.get("counts"),
                    "consistency_differences": len(projection.differences),
                    "bytes": sizes,
                }
            )
            print(json.dumps(per_run[-1]), file=sys.stderr, flush=True)
            parent = cts

        last = keys[-1]
        chain = timeline.chain(markers_dir)
        t1 = tierread.tier_at(sidestore, "render_t1", last, chain).to_pylist()
        totals = {c: sum(r[c] or 0 for r in t1) for c in COUNTS}
        largest = max(
            ("n_ports", "n_rules", "n_vlans", "n_interfaces", "n_endpoints"), key=lambda c: totals[c]
        )
        heavy = sorted(t1, key=lambda r: -(r[largest] or 0))[: max(1, tier3_samples // 2)]
        sample = heavy + t1[:: max(1, len(t1) // max(1, tier3_samples - len(heavy)))]
        timings = []
        for row in sample[:tier3_samples]:
            start = time.perf_counter()
            for query in tier3.QUERIES[largest]:
                session.run(query, uids=[row["uid"]], cts=last, reserved=[]).data()
            timings.append((time.perf_counter() - start) * 1000)
        whole = []
        for row in sample[: min(20, len(sample))]:
            start = time.perf_counter()
            tier3.read(session, row["uid"], last)
            whole.append((time.perf_counter() - start) * 1000)
        orphans = session.run(
            "RETURN COUNT { MATCH (d:Device:Obj {collection_ts: $cts}) "
            "WHERE NOT (d)-[:LOCATED_IN]->(:Site) } AS devices, "
            "COUNT { MATCH (rb:FwRulebase:Obj {collection_ts: $cts}) "
            "WHERE NOT ()-[:ENFORCES]->(rb) } AS rulebases, "
            "COUNT { MATCH (r:FwRule:Obj {collection_ts: $cts}) WHERE NOT ()-[:HAS_RULE]->(r) } AS rules",
            cts=last,
        ).data()[0]

    def p95(values: list[float]) -> float:
        return round(statistics.quantiles(values, n=20)[-1], 1) if len(values) >= 2 else round(values[0], 1)

    t1_path = store.table_path(sidestore, "render_t1", last)
    columns = pq.read_schema(t1_path).names
    t1_json = json.dumps({"columns": columns, "rows": [[r.get(c) for c in columns] for r in t1]}).encode()
    incremental = [
        r for r in per_run[1:] if r["consistency_differences"] == 0 and r["read_devices"] != devices
    ]
    per_run_bytes = [
        sum(
            r["bytes"][n]
            for n in ("graph_delta", "layout", "render_t0_delta", "render_t1_delta", "render_t2_delta")
        )
        for r in per_run[1:]
    ]
    result = {
        "devices": devices,
        "runs": runs,
        "change_rate": change_rate,
        "estate": estatemod.ratios(estate),
        "per_run": per_run,
        "bootstrap_s": per_run[0]["projection_s"],
        "projection_s_mean": round(statistics.mean(r["projection_s"] for r in incremental), 2)
        if incremental
        else None,
        "projection_s_max": max((r["projection_s"] for r in incremental), default=None),
        "hst_steps_s_mean": round(statistics.mean(r["hst_s"] for r in incremental), 2)
        if incremental
        else None,
        "hst_steps_s_max": max((r["hst_s"] for r in incremental), default=None),
        "diff_s_mean": round(statistics.mean(r["diff_s"] for r in per_run[1:]), 2) if runs > 1 else None,
        "per_run_bindings_bytes_mean": round(statistics.mean(r["bytes"]["render_bindings"] for r in per_run)),
        "per_run_tier_bytes": {
            name: per_run[-1]["bytes"].get(name, 0) for name in DELTA_OF if not name.endswith("_delta")
        },
        "peak_memory_bytes": max(r["peak_memory_bytes"] or 0 for r in per_run),
        "per_run_delta_bytes_mean": round(statistics.mean(per_run_bytes)) if per_run_bytes else 0,
        "one_year_bytes": round(statistics.mean(per_run_bytes) * RUNS_PER_YEAR) if per_run_bytes else 0,
        "tier1": {
            "rows": len(t1),
            "parquet_bytes": _size(t1_path),
            "json_gzip_bytes": len(gzip.compress(t1_json)),
        },
        "tier3": {
            "largest": largest,
            "samples": len(timings),
            "p95_ms": p95(timings),
            "device_p95_ms": p95(whole),
        },
        "orphans": {
            "devices": orphans["devices"],
            "unbound_rulebases": orphans["rulebases"],
            "rules_without_rulebase": orphans["rules"],
        },
        "coverage": {
            "ports_with_context": round(totals["n_ports_with_context"] / max(1, totals["n_ports"]), 4),
            "ports_with_port_edge": round(totals["n_ports_with_port_edge"] / max(1, totals["n_ports"]), 4),
        },
        "layout_rows_at_last": len(layout_read.rows_at(sidestore, last)),
    }
    if output is not None:
        output.write_text(json.dumps(result, indent=2))
    return result
