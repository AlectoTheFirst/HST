"""hst CLI: init-db, check-db, load-fixture, validate-demo, status,
serve (the application server), worker (the scheduler and the job executor
without the server), user (account management), geo-places (the site address
lookup)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from neo4j import unit_of_work
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from hst import __version__
from hst.core import Settings
from hst.core import db as dbmod
from hst.core.fixtures import load_fixture
from hst.core.loader import load
from hst.core.logsetup import configure_logging

if TYPE_CHECKING:  # the evidence commands import it lazily, as every command here does
    from hst.core.reconcile import EvidenceReport

app = typer.Typer(help="Network digital twin on Neo4j.", no_args_is_help=True)
console = Console(emoji=False)  # A uid can contain ":x:". Rich prints it as text with emoji=False.


def _version_callback(value: bool) -> None:
    if not value:
        return
    settings = Settings()
    rev = settings.hst_build_revision
    console.print(f"hst {__version__}" + (f" ({rev})" if rev != "unknown" else ""))
    raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show the version."),
    ] = False,
) -> None:
    """Network digital twin on Neo4j."""
    # Under `hst mcp` the log handlers write to stderr.
    configure_logging()


@app.command("migrate")
def migrate_cmd(
    check: Annotated[
        bool,
        typer.Option("--check", help="Exit 0 only if the schema is already at head; apply nothing."),
    ] = False,
) -> None:
    """Apply Alembic migrations to the Postgres store, or check whether they are applied.

    The app applies these itself on start-up when HST_RUN_MIGRATIONS is true. The Helm
    chart sets it false and runs this in a Job.
    """
    from hst.app.store.pg import schema_is_current, upgrade_to_head

    settings = Settings()
    dsn = settings.postgres_dsn
    if check:
        if schema_is_current(dsn, settings.postgres_ca_file):
            console.print("schema is at head")
            return
        console.print("[yellow]schema is behind[/yellow]: migrations not applied")
        raise typer.Exit(1)
    upgrade_to_head(dsn, settings.postgres_ca_file)
    console.print("[green]migrations applied[/green]")


@app.command("init-db")
def init_db() -> None:
    """Apply constraints and indexes (idempotent)."""
    settings = Settings()
    with dbmod.session(settings) as s:
        applied = dbmod.init_db(s)
    for stmt in applied:
        console.print(f"[green]ok[/green] {stmt}")


@app.command("check-db")
def check_db() -> None:
    """Connectivity check and basic counts."""
    settings = Settings()
    with dbmod.session(settings) as s:
        info = dbmod.check(s)
    console.print(f"uri            : {settings.neo4j_uri} (db: {settings.neo4j_database})")
    console.print(f"nodes          : {info['nodes']} ({info['nodes_retired']} retired)")
    console.print(f"relationships  : {info['rels']}")
    console.print(f"constraints    : {', '.join(info['constraints']) or '[red]none (run init-db)[/red]'}")


@app.command("cycle")
def cycle_cmd() -> None:
    """Run one full collection cycle.

    The cycle runs every enabled source, the rule reasoner and the route-target
    derivations, and switches over to the new collection_ts."""
    from hst.app import runs_exec

    async def go(store):
        run = await runs_exec.run_blocking(store, Settings(), "cycle")
        if run is None:
            console.print("[yellow]a cycle is already running[/yellow]")
            raise typer.Exit(1)
        colour = "green" if run.status == "ok" else "red"
        console.print(f"run {run.id} [{colour}]{run.status}[/{colour}]: {run.detail or ''}")
        if run.status != "ok":
            raise typer.Exit(1)

    _with_store(go)


@app.command("prune")
def prune_cmd(
    keep: Annotated[
        int | None,
        typer.Option(help="Cycles to keep; default the stored Lifecycle value, else CYCLE_KEEP_RUNS"),
    ] = None,
) -> None:
    """Delete old graph runs, preserving the current run and retained assessment evidence.

    The command keeps the newest `--keep` cycles, the newest device and refresh runs
    (Settings, Lifecycle, else CYCLE_KEEP_DEVICE_RUNS) newer than the oldest of
    them, the runs that retained assessments reference and the runs that readers
    hold open. It calls the function of the scheduled graph prune, under the same
    cycle lock, one run at a time, followed by the same HST sweep.
    The command ends without deleting when a collection holds the lock.

    Requires the app extra and its configured, migrated Postgres store. An unavailable
    store stops pruning.
    """
    from hst.core import cycle as cyclemod

    settings = Settings()

    async def prune_with_references(store):
        from hst.worker.maintenance import prune_graph

        if not callable(getattr(store, "retained_snapshot_refs", None)):
            raise ValueError("The store does not expose assessment retention references.")
        from hst.app import retention

        stored = await retention.resolve(store, settings)
        limits = cyclemod.Keep(
            keep if keep is not None else stored.cycle_keep_runs, stored.cycle_keep_device_runs
        )
        return await prune_graph(settings, store, limits)

    try:
        victims = _assessment_store_read(settings, prune_with_references, hold_lock=False)
    except Exception as exc:
        typer.echo(
            "Pruning stopped: assessment retention state or its protected evidence could not be verified. "
            "Install the app extra and configure the migrated Postgres store. "
            f"Failure type: {type(exc).__name__}.",
            err=True,
        )
        raise typer.Exit(1) from exc
    if victims is None:
        typer.echo(
            "A collection holds the cycle lock; nothing was pruned. Run it again when it ends.", err=True
        )
        raise typer.Exit(1)
    if victims:
        console.print(f"[green]deleted {len(victims)} run(s)[/green]: {', '.join(map(str, victims))}")
    else:
        console.print("nothing to delete")


@app.command("migrate-cycle")
def migrate_cycle_cmd() -> None:
    """Stamp a pre-cycle-model graph as the first run (idempotent).

    The command gives every existing object the bootstrap collection_ts, moves
    the pointer to it, and writes the run meta node. It also splits an operator's
    Site that every run points at into one copy per run. Run `hst init-db` first.
    """
    from hst.core import cycle as cyclemod

    settings = Settings()
    with dbmod.session(settings) as s:
        result = cyclemod.migrate_bootstrap(s)
        # after the bootstrap, an unversioned reasoner edge belongs to no run
        cyclemod.sweep_unversioned_reasoner_edges(s)
        split = cyclemod.migrate_meta_sites(s)
    if split:
        console.print(f"[green]split[/green] {split} operator site(s) into one copy per run")
    if not result["migrated"]:
        console.print("pointer already set; nothing to migrate")
        return
    console.print(
        f"[green]migrated[/green] collection_ts={result['collection_ts']} "
        f"({result['nodes']} nodes, {result['rels']} rels)"
    )


@app.command("load-fixture")
def load_fixture_cmd(
    path: Annotated[Path, typer.Argument(help="YAML fixture (see fixtures/mini-dc.yaml)")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Validate only, do not load")] = False,
    new_run: Annotated[
        bool, typer.Option("--new-run", help="Start without carrying the preceding snapshot")
    ] = False,
) -> None:
    """Validate and load a YAML fixture batch, and derive its edges.

    Every invocation publishes a fresh immutable snapshot. Without --new-run,
    the previous snapshot's authenticated graph archive is verified and its
    graph is copied into the unpublished target first. --new-run starts from
    empty.

    The rule reasoner runs here, over the run this load builds.

    The load writes the HST map tables of the run, with the projection that a
    collection run uses. The parent of the projection is the run published
    before this load, also with --new-run. The map timeline is the publish
    order, and the graph delta is taken against that run in both modes. A
    projection failure leaves the run without map tables and does not fail
    the load.
    """
    from hst.app import fixture_runs

    settings = Settings()
    batch = load_fixture(path)
    console.print(
        f"fixture ok: {len(batch.nodes)} nodes, {len(batch.rels)} rels "
        f"(source={batch.source}, scope={batch.scope})"
    )
    if dry_run:
        return
    with dbmod.session(settings) as s:
        try:
            published = fixture_runs.publish(s, settings, batch, path, new_run=new_run, loader=load)
        except fixture_runs.FixtureExtendError as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(1) from None
        if published.tiers_ready:
            console.print(f"map tables written for snapshot {published.cts}")
        elif published.marker is not None:
            console.print(
                f"[yellow]map tables not written for snapshot {published.cts}[/yellow]: "
                f"{escape(str(published.map_failure))}"
            )
    _print_manifest(published.loaded)
    for line in published.derived:
        console.print(line)


@app.command("run")
def run_cmd(
    name: Annotated[str, typer.Argument(help="source name; `hst sources list`")],
) -> None:
    """Run a configured source against its management plane and load the result.

    The run takes the run lock and writes its Run row, as an API run does.
    """
    from hst.app import runs_exec

    async def go(store):
        settings = Settings()
        row = await store.get_source(name)
        if row is None:
            names = ", ".join(s.name for s in await store.list_sources()) or "none configured"
            console.print(f"[red]unknown source {name!r}[/red] (available: {names})")
            raise typer.Exit(2)
        if not row.enabled:
            console.print(f"[red]{name} is disabled[/red]")
            raise typer.Exit(2)
        run = await runs_exec.run_blocking(store, settings, name)
        if run is None:
            console.print(
                f"[yellow]{name} is already running[/yellow]: one collection per source "
                f"at a time. The Runs page shows what is in flight."
            )
            raise typer.Exit(1)
        colour = "green" if run.status == "ok" else "red"
        console.print(f"run {run.id} [{colour}]{run.status}[/{colour}]: {run.detail or ''}")
        if run.status != "ok":
            raise typer.Exit(1)

    _with_store(go)


@app.command("mcp")
def mcp_cmd(
    remote: Annotated[
        str | None,
        typer.Option(
            "--remote",
            help="relay stdio to the MCP HTTP transport at this URL, e.g. https://host/api/mcp, "
            "with the personal access token in HST_MCP_TOKEN",
        ),
    ] = None,
) -> None:
    """Run the MCP server on stdio.

    With POSTGRES_DSN set, the server opens the app store and audits every call there.
    With --remote, no local server runs. Every message goes to the remote transport.
    The remote transport authenticates the token and applies the permissions of its user.
    """
    if remote is not None:
        # The bridge needs no mcp extra and no database. Its diagnostics go to stderr.
        from hst.mcp_bridge import main as bridge_main

        raise typer.Exit(bridge_main(remote))
    try:
        # build_server imports mcp.server when it runs. The import here runs
        # inside this guard.
        import mcp.server  # noqa: F401

        from hst.mcp_server import main as mcp_main
        from hst.mcp_server import serve
    except ImportError as exc:
        hint = escape(f"({exc}): pip install -e '.[mcp]'")
        console.print(f"[red]MCP dependencies missing[/red] {hint}")
        raise typer.Exit(2) from exc
    # No console output follows. stdout is the protocol channel.
    if "postgres_dsn" not in Settings().model_fields_set:
        mcp_main()
        return
    _with_store(serve)


@app.command("rebuild")
def rebuild_cmd(
    as_of: Annotated[
        str,
        typer.Option("--as-of", help="ISO date or datetime, e.g. 2026-03-31 or 2026-03-31T18:00:00Z"),
    ] = "",
    snapshot: Annotated[
        int | None,
        typer.Option(
            "--snapshot",
            help="snapshot key from `hst status`: replay that published snapshot's manifest",
        ),
    ] = None,
    into: Annotated[
        str,
        typer.Option("--into", help="bolt URI of a scratch database to rebuild into, not the live twin"),
    ] = "",
    dry_run: Annotated[bool, typer.Option("--dry-run", help="report the plan without writing")] = False,
    allow_config_drift: Annotated[
        bool,
        typer.Option(
            "--allow-config-drift",
            help="--snapshot only: replay a source whose configuration digests differently today",
        ),
    ] = False,
    sidestore_scratch: Annotated[
        Path | None,
        typer.Option(
            "--sidestore-scratch",
            help="--snapshot only: directory to regenerate missing or altered side-store files into",
        ),
    ] = None,
) -> None:
    """Reconstruct a past graph into a scratch database, by replaying raw payloads.

    The payloads are replayed through the normalize + load path that built the graph.

    `--as-of` is the date path. It replays the newest snapshot per (source, host) at
    or before the date. It is the only option for raw files that have no snapshot
    manifest.

    `--snapshot` is the manifest path. It replays one published snapshot, device by
    device, from the exact raw file of the recorded `effective_run` of each device. A
    source whose configuration digest differs from the digest in the manifest
    refuses its devices unless `--allow-config-drift` replays them under the current
    configuration. A kept side-store file that is missing or does not match its
    recorded digest is regenerated into `--sidestore-scratch`. Without that directory
    the file is left unresolved and reported.

    Needs a scratch database. It refuses to write to the configured NEO4J_URI.
    """
    from hst.app import sources as glue
    from hst.core import replay
    from hst.core.uid import slug

    settings = Settings()
    # A date and a snapshot key are mutually exclusive.
    if bool(as_of) == (snapshot is not None):
        console.print(
            "[red]name exactly one past[/red]: --as-of <date> for the date path "
            "or --snapshot <key> for a published snapshot's manifest."
        )
        raise typer.Exit(2)
    for flag, given in (
        ("--allow-config-drift", allow_config_drift),
        ("--sidestore-scratch", sidestore_scratch),
    ):
        if given and snapshot is None:
            console.print(f"[red]{flag} applies to --snapshot only[/red]; the date path reads no manifest.")
            raise typer.Exit(2)

    # The guards run before any read.
    if not dry_run:
        if not into:
            console.print(
                "\n[red]--into is required[/red] to write. A rebuild overwrites the "
                "target, so it will not guess one."
            )
            raise typer.Exit(2)
        if dbmod.same_endpoint(into, settings.neo4j_uri):
            console.print(
                f"\n[red]--into is the live twin[/red] ({into}). Rebuild into a "
                "scratch database; this would overwrite the estate's current state."
            )
            raise typer.Exit(2)

    if snapshot is not None:
        _rebuild_from_manifest(
            settings,
            snapshot,
            into=into,
            dry_run=dry_run,
            allow_config_drift=allow_config_drift,
            sidestore_scratch=sidestore_scratch,
        )
        return

    try:
        text = as_of.replace("Z", "+00:00")
        when = datetime.fromisoformat(text if "T" in text else f"{text}T23:59:59+00:00")
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
    except ValueError:
        console.print(f"[red]cannot parse --as-of {as_of!r}[/red]: use 2026-03-31 or 2026-03-31T18:00:00Z")
        raise typer.Exit(2) from None
    as_of_ms = int(when.timestamp() * 1000)

    selected, missing = replay.plan(settings.raw_dir, as_of_ms)
    if not selected and not missing:
        console.print(
            f"[red]no snapshots under {settings.raw_dir}[/red]: nothing to "
            "replay. Point HST_DATA_DIR at the directory holding them."
        )
        raise typer.Exit(1)

    console.print(f"as of {when.isoformat()}:")
    for snap in selected:
        age = (as_of_ms - snap.ts_ms) / 86_400_000
        label = snap.source if not snap.host else f"{snap.source}/{snap.host}"
        console.print(
            f"  [green]{label}[/green]  {snap.taken_at.isoformat()}  "
            f"[dim]({age:.1f}d before the target)[/dim]"
        )
    for source in missing:
        console.print(
            f"  [yellow]{source}[/yellow]  no snapshot at or before this date; "
            f"the rebuild will not contain it"
        )

    if dry_run:
        return

    target = settings.model_copy(update={"neo4j_uri": into})
    rows, devices, sites = _replay_inventory()
    registry = _registry_snapshot()
    # Raw files are under the slugged source row name and the slugged host.
    # A row name (^[a-z0-9-]{2,32}$) is its own slug.
    by_directory = {slug(r.name): r for r in rows.values()}

    def collector_for(source: str):
        row = by_directory.get(source)
        return (
            glue.build_collector(row, settings, sites=sites, sources=rows, identity=registry) if row else None
        )

    def device_collector_for(source: str, host: str):
        row = by_directory.get(source)
        device = devices.get((source, host))
        if row is None or device is None:
            return None
        return glue.build_device_collector(
            row, device, settings, sites=sites, sources=rows, identity=registry
        )

    console.print(f"\nrebuilding into {into} ...")
    with dbmod.session(target) as s:
        report = replay.rebuild(
            settings, s, as_of_ms, collector_for=collector_for, device_collector_for=device_collector_for
        )

    if report.cleared:
        console.print(f"[dim]cleared {report.cleared} existing node(s) from the target[/dim]")
    for m in report.manifests:
        _print_manifest(m)
    for source, why in report.failed:
        console.print(f"[red]{source}: {why}[/red]")
    console.print(f"\nreplayed {len(report.replayed)} snapshot(s)")
    if not report.ok:
        console.print(
            "[yellow]incomplete: the rebuilt graph is missing at least one "
            "source; treat it as partial evidence[/yellow]"
        )
        raise typer.Exit(1)


def _source_rows() -> dict[str, Any]:
    """Every configured source row, by name."""
    rows: dict[str, Any] = {}

    async def go(store):
        rows.update({r.name: r for r in await store.list_sources()})

    _with_store(go)
    return rows


def _replay_inventory() -> tuple[dict[str, Any], dict[tuple[str, str], Any], dict[str, Any]]:
    """Every configured source row by name, every fleet device by the slugged
    (source, host) directory names its raw files sit under, and every site by
    code."""
    from hst.core.uid import slug

    rows: dict[str, Any] = {}
    devices: dict[tuple[str, str], Any] = {}
    sites: dict[str, Any] = {}

    async def go(store):
        rows.update({r.name: r for r in await store.list_sources()})
        devices.update({(slug(d.source), slug(d.host)): d for d in await store.list_devices()})
        sites.update({site.code: site for site in await store.list_sites()})

    _with_store(go)
    return rows, devices, sites


def _sites() -> dict[str, Any]:
    """Every site, by code."""
    sites: dict[str, Any] = {}

    async def go(store):
        sites.update({site.code: site for site in await store.list_sites()})

    _with_store(go)
    return sites


def _registry_snapshot() -> Any:
    """The current device identity registry, read one time, for a replay or a
    repair. The snapshot resolves the uids that the cycle resolves and does not
    write to the registry (app/sources.py `registry_snapshot`)."""
    from hst.app import sources as glue

    snapshot: list[Any] = []

    async def go(store):
        snapshot.append(await glue.registry_snapshot(store))

    _with_store(go)
    return snapshot[0]


def _rebuild_from_manifest(
    settings: Settings,
    snapshot: int,
    *,
    into: str,
    dry_run: bool,
    allow_config_drift: bool,
    sidestore_scratch: Path | None,
) -> None:
    """Replay the manifest of one published snapshot for `rebuild --snapshot`
    (`core/replay.py rebuild_from_manifest`).

    The guards on the target run in `rebuild_cmd`. The manifest is read before
    any source row is looked up.

    `source_for` resolves one collector per source row, with the row's own type,
    enabled flag and stored configuration.
    """
    from hst.app import sources as glue
    from hst.core import manifest as manifestmod
    from hst.core import replay

    try:
        record = manifestmod.read(settings, snapshot)
    except FileNotFoundError:
        console.print(
            f"[red]no manifest for snapshot {snapshot}[/red]: a manifest-driven replay needs one. "
            "Rebuild a snapshot without a manifest by date, with --as-of."
        )
        raise typer.Exit(1) from None
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(1) from exc

    console.print(
        f"snapshot {snapshot}: opened {record.opened}, published {record.published}, "
        f"{len(record.devices)} device(s), {len(record.files)} file(s)"
    )
    for device in record.devices:
        label = device.source if not device.host else f"{device.source}/{device.host}"
        style = "yellow" if device.outcome in ("failed", "carried") else "green"
        console.print(
            f"  [{style}]{escape(label)}[/{style}]  {device.outcome}  "
            f"[dim]run {device.effective_run or 'none'}[/dim]"
        )
    if dry_run:
        return

    # Exact archive replay is independent of today's Postgres and collector
    # configuration. Only raw replay needs current source rows.
    if record.graph_archive is None:
        rows = _source_rows()
        # A group that inherits its routing scope from its site replays under
        # the site's scope, as the cycle loads it. With no row there is no
        # collector to build, and no site to read.
        sites = _sites() if rows else {}
        registry = _registry_snapshot() if rows else None

        def source_for(name: str):
            row = rows.get(name)
            if row is None:
                return None
            return replay.SourceLookup(
                collector=glue.build_collector(row, settings, sites=sites, sources=rows, identity=registry),
                type=row.type,
                enabled=row.enabled,
                config=row.config,
            )

    else:

        def source_for(name: str):
            return None

    target = settings.model_copy(update={"neo4j_uri": into})
    console.print(f"\nrebuilding snapshot {snapshot} into {into} ...")
    with dbmod.session(target) as s:
        report = replay.rebuild_from_manifest(
            settings,
            s,
            snapshot,
            source_for=source_for,
            allow_config_drift=allow_config_drift,
            sidestore_scratch_dir=sidestore_scratch,
        )

    if report.cleared:
        console.print(f"[dim]cleared {report.cleared} existing node(s) from the target[/dim]")
    for m in report.manifests:
        _print_manifest(m)
    for line in report.drift:
        console.print(f"[yellow]{escape(line)}[/yellow]")
    for line in report.side_table_notes:
        console.print(f"[dim]{escape(line)}[/dim]")
    for line in report.derived:
        console.print(f"[dim]derived {escape(line)}[/dim]")
    for label in report.missing:
        console.print(f"[yellow]{escape(label)}: no payload in this snapshot to replay[/yellow]")
    for label, why in report.failed:
        console.print(f"[red]{escape(label)}: {escape(why)}[/red]")
    console.print(f"\nreplayed {len(report.replayed)} device(s) of snapshot {snapshot}")
    if not report.ok:
        console.print(
            "[yellow]incomplete: the rebuilt graph is missing at least one "
            "device; treat it as partial evidence[/yellow]"
        )
        raise typer.Exit(1)


evidence_app = typer.Typer(help="Snapshot evidence: the signed manifest, its file list and the chain.")
app.add_typer(evidence_app, name="evidence")


@evidence_app.command("export")
def evidence_export(
    snapshot: Annotated[int, typer.Argument(help="snapshot key, e.g. 1772000000000")],
    into: Annotated[Path, typer.Argument(help="output directory, created if it does not exist")],
) -> None:
    """Write one snapshot's manifest, signature and file list to `into`.

    The output holds the paths and digests of the files and no copy of the file bytes.
    """
    from hst.core import manifest

    settings = Settings()
    try:
        record = manifest.read(settings, snapshot)
    except FileNotFoundError:
        console.print(f"[red]no manifest for snapshot {snapshot}[/red]")
        raise typer.Exit(1) from None

    into.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest.path_for(settings, snapshot)
    (into / manifest_path.name).write_bytes(manifest_path.read_bytes())

    sig_path = manifest.sig_path_for(settings, snapshot)
    signed = sig_path.is_file()
    if signed:
        (into / sig_path.name).write_bytes(sig_path.read_bytes())

    import json as _json

    file_list = [f.model_dump(mode="json") for f in record.files]
    (into / f"{snapshot}.files.json").write_text(_json.dumps(file_list, indent=2, sort_keys=True))

    console.print(
        f"exported snapshot {snapshot}: manifest, "
        f"{'signature, ' if signed else 'no signature (unsigned), '}"
        f"{len(record.files)} file(s) listed (paths and digests only, no file bytes) -> {into}"
    )


@evidence_app.command("check")
def evidence_check(
    snapshot: Annotated[int, typer.Argument(help="snapshot key, e.g. 1772000000000")],
) -> None:
    """Verify the evidence of one snapshot.

    The check covers every file digest, the row digest of every side-store file,
    the signature when one exists, and the manifest chain back to the first
    manifest on disk (or the first one missing).

    Every mismatch is reported. The check reads only files on disk and needs no data
    key and no graph connection. A signature from a key other than the configured
    signing key fails the check.
    """
    from hst.core import reconcile

    settings = Settings()
    try:
        report = reconcile.verify_evidence(settings, snapshot)
    except FileNotFoundError:
        console.print(f"[red]no manifest for snapshot {snapshot}[/red]")
        raise typer.Exit(1) from None

    _print_evidence(report)
    if report.problems or report.signature_key_configured is False:
        raise typer.Exit(1)
    console.print("[green]all digests and chain links match[/green]")


def _print_evidence(report: EvidenceReport) -> None:
    """The signature line, the file and chain counts, and every problem, for the
    two commands that verify a snapshot's evidence (`core/reconcile.py
    verify_evidence`)."""
    if report.signature == "unsigned":
        console.print("[dim]unsigned[/dim]")
    elif report.signature == "verified" and report.signature_key_configured is False:
        console.print(
            f"[red]signature key {escape(report.signature_key_id)} is not the configured signing key[/red]"
        )
    elif report.signature == "verified":
        console.print(f"[green]signature verifies[/green] (key {escape(report.signature_key_id)})")
    console.print(f"{report.files} file(s), chain walked back {report.chain_len} manifest(s)")
    for problem in report.problems:
        console.print(f"[red]{escape(problem)}[/red]")


@evidence_app.command("reconcile")
def evidence_reconcile(
    apply: Annotated[
        bool,
        typer.Option(
            "--apply",
            help="quarantine the orphans and write the join sidecars that are derivable; "
            "without it nothing on disk is touched",
        ),
    ] = False,
    repair_target: Annotated[
        Path | None,
        typer.Option(
            "--repair-target",
            help="directory to rebuild missing derived side-store files into, not the "
            "estate's own side store",
        ),
    ] = None,
) -> None:
    """Reconcile the committed runs, the manifests and the files on disk.

    The command reports 4 kinds of difference between the 3 stores. A file in a
    manifest has bytes that do not digest to the recorded value. A file in a
    manifest is not on disk. A file on disk is in no retained manifest. A committed
    raw file has no join sidecar. A raw file that was fetched and not yet folded
    into a run, and a raw file that a newer collection superseded, are accounted for
    and not reported.

    Without `--apply` the command writes nothing. The command deletes nothing.
    `--apply` needs the Postgres store. It waits for any collection run in progress,
    which holds the cycle lock until its manifest is written, and then moves files.
    With `--apply`, an orphan moves under `data/quarantine/<ts>/` with a report that
    holds its path and the reason. A missing join sidecar is written from the
    snapshot key of the manifest that lists the file. A file whose digest does not
    match stays in place.

    A missing derived side-store file is rebuilt only with `--repair-target`, and only
    into that directory. The rebuild reads the raw payload that the manifest lists
    and needs the data key. It reports whether the regenerated rows reproduce the row
    digest that the manifest recorded.
    """
    from hst.core import reconcile

    settings = Settings()
    if repair_target is not None:
        try:
            reconcile.check_repair_target(settings, repair_target)
        except reconcile.RepairTargetRefused as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(2) from None

    report = reconcile.scan(settings)
    console.print(
        f"{len(report.manifests)} manifest(s), {report.verified} file(s) verified against the "
        f"manifest that names them"
    )
    for label, entries in (
        ("digest mismatch", report.tampered),
        ("named by a manifest and not on disk", report.missing_raw),
        ("derived dataset named by a manifest and not on disk", report.missing_derived),
        ("its run joined a snapshot whose manifest does not list it", report.unlisted),
    ):
        for path in entries:
            console.print(f"  [red]{escape(path)}[/red]  {label}")
    for orphan in report.orphans:
        console.print(f"  [yellow]{escape(orphan.path)}[/yellow]  {escape(orphan.reason)}")
    for path in report.parked:
        console.print(f"  [dim]{escape(path)}  fetched, not yet folded into a run[/dim]")
    for path in report.pending:
        console.print(f"  [dim]{escape(path)}  joined a run whose manifest is not written yet[/dim]")
    for path in report.unjoined:
        console.print(f"  [dim]{escape(path)}  superseded by a newer collection; no run applied it[/dim]")
    for path, key in report.repairable_metadata:
        console.print(f"  [yellow]{escape(path)}[/yellow]  join sidecar missing; snapshot {key} names it")

    if apply:
        # The scan took no lock and a run can publish while it reads. The moves
        # wait for the lock that a collection holds from fetch to publish, and
        # drop the files that a manifest published since the scan lists.
        async def move(store):
            async with store.cycle_lock():
                reconcile.settle_since_scan(settings, report)
                return reconcile.quarantine(settings, report), reconcile.repair_metadata(settings, report)

        try:
            root, lines = _with_store(move)
        except reconcile.ScanSuperseded as exc:
            console.print(f"[red]{escape(str(exc))}; nothing was moved[/red]")
            raise typer.Exit(1) from None
        console.print(f"\nquarantined {len(report.quarantined)} file(s) under {root}")
        for line in lines:
            console.print(f"  [green]{escape(line)}[/green]")

    if repair_target is not None and report.missing_derived:
        from hst.app import sources as glue
        from hst.app.crypto import dek

        console.print(f"\nrebuilding {len(report.missing_derived)} derived file(s) into {repair_target}")
        for line in reconcile.repair_derived(
            settings,
            report,
            repair_target,
            collector_for=_repair_collector_for(settings, glue),
            key=dek(settings),
        ):
            console.print(f"  {escape(line)}")

    problems = report.problems
    if problems:
        console.print(f"\n[red]{len(problems)} finding(s) still need an operator[/red]")
        raise typer.Exit(1)
    if report.quarantined or report.repaired_metadata or report.rebuilt_paths:
        console.print("\n[green]every finding was resolved[/green]")
    else:
        console.print("\n[green]runs, manifests and files agree[/green]")


def _repair_collector_for(settings: Settings, glue: Any) -> Any:
    """`collector_for(source, host)` for `reconcile.repair_derived`.

    `collector_for` returns the collector of one device of one configured source.
    The rows are read from Postgres once. They are indexed by the slugged source
    and host directory names. A manifest entry holds these names, and the raw and
    side-store layouts are keyed by them.
    """
    from hst.core import replay
    from hst.core.uid import slug

    rows, devices, sites = _replay_inventory()
    registry = _registry_snapshot()
    by_directory = {slug(r.name): r for r in rows.values()}

    def collector_for(source: str, host: str) -> Any:
        row = by_directory.get(source)
        if row is None:
            return None
        device = devices.get((source, host))
        if device is None:
            # No configured device has this host. The result is the collector
            # of the group with the name of the host directory in its
            # configuration. A device without a serial derives its uid from
            # that host, and the regenerated rows derive their uids from it.
            return replay.device_collector(
                glue.build_collector(row, settings, sites=sites, sources=rows, identity=registry),
                host,
                slugged=True,
            )
        return glue.build_device_collector(
            row, device, settings, sites=sites, sources=rows, identity=registry
        )

    return collector_for


recovery_app = typer.Typer(
    help="Restore verification: check a restored tree against the recovery set the backup wrote."
)
app.add_typer(recovery_app, name="recovery")


@recovery_app.command("prepare")
def recovery_prepare(
    target: Annotated[Path, typer.Argument(help="private emptyDir shared with the backup job")],
    set_id: Annotated[str, typer.Option("--set-id", help="immutable set identifier used in object keys")],
) -> None:
    """Stage the committed graph snapshot and its recovery material.

    This deployment command holds the same cross-pod lock as collection while
    it resolves the graph pointer and copies the committed manifest's exact
    files. Configuration metadata and the operator key are encrypted under the
    separate HST_BACKUP_ENCRYPTION_KEY before they enter the staging volume.

    The command applies no migration. It stops when the Postgres schema is not at
    the revision that this hst version expects.
    """
    import json

    from hst.app import crypto
    from hst.core import cycle, manifest, reconcile

    settings = Settings()
    backup_key = os.environ.get("HST_BACKUP_ENCRYPTION_KEY", "").strip()
    if not backup_key:
        console.print("[red]HST_BACKUP_ENCRYPTION_KEY is required[/red]")
        raise typer.Exit(2)

    async def go(store):
        async with store.cycle_lock():
            with dbmod.session(settings) as session:
                snapshot_key = cycle.current_ts(session)
            if snapshot_key is None:
                raise RuntimeError("the graph has no committed snapshot")
            record = manifest.read(settings, snapshot_key)
            sources = await store.list_sources()
            context = {
                "snapshot_key": snapshot_key,
                "manifest_sha256": manifest.digest_of(settings, snapshot_key),
                "normalization_context": record.graph_archive.normalization_context
                if record.graph_archive is not None
                else {},
                "sources": [
                    {"name": row.name, "type": row.type, "enabled": row.enabled, "config": row.config}
                    for row in sources
                ],
            }
            config_blob = crypto.encrypt(backup_key, json.dumps(context, sort_keys=True).encode())
            if settings.hst_secret_key_file:
                operator_key = Path(settings.hst_secret_key_file).read_bytes().strip()  # noqa: ASYNC240
            else:
                operator_key = settings.hst_secret_key.strip().encode()
            if len(operator_key) < crypto.MIN_KEK_BYTES:
                raise crypto.SecretKeyError(crypto.GUIDANCE)
            key_blob = crypto.encrypt(backup_key, operator_key)
            objects = reconcile.stage_recovery_data(
                settings,
                snapshot_key,
                target,
                set_id=set_id,
                key_prefix=os.environ.get("HST_BACKUP_OBJECT_PREFIX", ""),
                encrypted_configuration=config_blob,
                encrypted_operator_key=key_blob,
                operator_key=operator_key,
            )
            return record, objects

    try:
        record, objects = _with_store(go, migrate=False)
        draft = {
            "schema_version": reconcile.SET_SCHEMA_VERSION,
            "created": set_id,
            "estate": settings.estate_name,
            "snapshot_key": record.snapshot_key,
            "manifest_sha256": manifest.digest_of(settings, record.snapshot_key),
            "chain_index": record.chain_index,
            "boundary": "committed graph pointer under cycle lock; identity store follows in one backup job",
            "objects": [obj.model_dump(mode="json") for obj in objects],
        }
        path = target / "sets" / set_id / "draft.json"
        path.write_text(json.dumps(draft, sort_keys=True), encoding="utf-8")
        path.chmod(0o600)
    except Exception as exc:
        console.print(f"[red]cannot stage recovery set[/red]: {escape(str(exc))}")
        raise typer.Exit(1) from None
    console.print(f"staged recovery inputs for committed snapshot {record.snapshot_key}")


@recovery_app.command("finalize")
def recovery_finalize(
    target: Annotated[Path, typer.Argument(help="private emptyDir shared with the backup job")],
    set_id: Annotated[str, typer.Option("--set-id")],
) -> None:
    """Encrypt the Postgres dump under HST_BACKUP_ENCRYPTION_KEY and write the schema-2 set record.

    The set record holds the digest and the length of the encrypted dump
    `postgres.dump.enc`. The plain dump is deleted.
    """
    import json
    import shutil

    from hst.core import manifest, reconcile

    root = target / "sets" / set_id
    try:
        recovery_key = os.environ.get("HST_BACKUP_ENCRYPTION_KEY", "").strip()
        if not recovery_key:
            raise ValueError("HST_BACKUP_ENCRYPTION_KEY is required")
        draft = json.loads((root / "draft.json").read_text(encoding="utf-8"))
        dump = reconcile.seal_postgres_dump(root, recovery_key)
        sha, size = manifest.file_facts(dump)
        objects = [reconcile.RecoveryObject.model_validate(item) for item in draft.pop("objects")]
        objects.append(
            reconcile.RecoveryObject(
                role="postgres",
                key="/".join(
                    part
                    for part in (
                        os.environ.get("HST_BACKUP_OBJECT_PREFIX", "").strip("/"),
                        "sets",
                        set_id,
                        dump.name,
                    )
                    if part
                ),
                sha256=sha,
                bytes=size,
            )
        )
        record = reconcile.RecoverySet(
            **draft,
            postgres_dump_key=objects[-1].key,
            objects=objects,
            secrets={"recoveryEncryptionKey": "mounted by the backup job"},
            settings=["HST_BACKUP_ENCRYPTION_KEY", "HST_DATA_DIR", "POSTGRES_DSN", "NEO4J_URI"],
        )
        verified_target = root / ".verified"
        reconcile.materialize_recovery_bundle(record, root, verified_target, recovery_key)
        shutil.rmtree(verified_target)
        path = root / "recovery-set.json"
        path.write_text(record.model_dump_json(), encoding="utf-8")
        path.chmod(0o600)
    except Exception as exc:
        console.print(f"[red]cannot finalize recovery set[/red]: {escape(str(exc))}")
        raise typer.Exit(1) from None
    console.print(f"finalized recovery set {set_id}")


@recovery_app.command("check")
def recovery_check(
    recovery_set: Annotated[
        Path, typer.Argument(help="the recovery-set JSON the backup wrote, e.g. recovery-set/<ts>.json")
    ],
) -> None:
    """Verify a restored tree against the recovery set that describes it.

    The manifest of the snapshot of the set must be present and digest to the value
    the set recorded. That snapshot's evidence must verify, chain included, as in
    `hst evidence check`. The restored Postgres must hold every source of the
    manifest, and the redacted configuration of each row must digest to the
    `config_sha256` that the manifest recorded.

    The command reads the data directory and Postgres. It writes nothing and
    rebuilds nothing.
    """
    from hst.core import reconcile

    settings = Settings()
    try:
        record = reconcile.read_set(recovery_set)
    except OSError as exc:
        console.print(f"[red]cannot read {recovery_set}[/red]: {escape(str(exc))}")
        raise typer.Exit(2) from None
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(2) from None

    console.print(f"recovery set: {record.label}")
    if record.postgres_dump_key:
        console.print(f"  postgres dump   {escape(record.postgres_dump_key)}")
    if record.data_prefix:
        console.print(f"  data prefix     {escape(record.data_prefix)}")
    if record.data_object_list_sha256:
        console.print(f"  object list     {escape(record.data_object_list_sha256)}")

    rows: dict[str, tuple[str, bool, dict]] | None = {}

    async def go(store):
        return {r.name: (r.type, r.enabled, r.config) for r in await store.list_sources()}

    try:
        rows = _with_store(go)
    except Exception as exc:
        console.print(f"[yellow]the source rows could not be read[/yellow]: {escape(str(exc))}")
        rows = None

    check = reconcile.check_recovery_set(settings, record, rows)
    if check.evidence is not None:
        _print_evidence(check.evidence)
    console.print(f"{check.sources_checked} source configuration digest(s) checked")
    for note in check.notes:
        console.print(f"[dim]{escape(note)}[/dim]")
    for problem in check.problems:
        console.print(f"[red]{escape(problem)}[/red]")
    if check.problems:
        raise typer.Exit(1)
    console.print("[green]the restored tree matches the recovery set[/green]")


@recovery_app.command("materialize")
def recovery_materialize(
    recovery_set: Annotated[Path, typer.Argument(help="downloaded recovery-set JSON")],
    objects: Annotated[Path, typer.Argument(help="downloaded immutable sets/<id> directory")],
    target: Annotated[Path, typer.Argument(help="new restore data directory")],
) -> None:
    """Authenticate a downloaded bundle before exposing its restore tree."""
    from hst.core import reconcile

    recovery_key = os.environ.get("HST_BACKUP_ENCRYPTION_KEY", "").strip()
    if not recovery_key:
        console.print("[red]HST_BACKUP_ENCRYPTION_KEY is required[/red]")
        raise typer.Exit(2)
    try:
        record = reconcile.read_set(recovery_set)
        bundle = reconcile.materialize_recovery_bundle(record, objects, target, recovery_key)
    except Exception as exc:
        console.print(f"[red]cannot materialize recovery set[/red]: {escape(str(exc))}")
        raise typer.Exit(1) from None
    console.print(f"materialized authenticated snapshot {record.snapshot_key} at {bundle.data_dir}")
    console.print(f"decrypted Postgres dump: {bundle.postgres_dump}")


reason_app = typer.Typer(
    help="Derived-edge rules: cabling/gateway inference, RT-import routes, RT-component "
    "domains, and CONNECTED_TO link speed."
)
app.add_typer(reason_app, name="reason")


@reason_app.callback(invoke_without_command=True)
def reason_cmd(ctx: typer.Context) -> None:
    """Rebuild derived edges (cross-source stitching, e.g. cabling by MAC match).

    With no subcommand the command refuses. Every collection trigger derives the
    cabling/gateway edges into the run it builds. See
    `hst reason rt-domains --help` for the route-target derivation.
    """
    if ctx.invoked_subcommand is not None:
        return
    from hst.app.runs_exec import REASONER_REFUSAL

    console.print(f"[red]{REASONER_REFUSAL}[/red]")
    raise typer.Exit(1)


@reason_app.command("rt-domains")
def reason_rt_domains_cmd() -> None:
    """Derive RoutingDomain groupings from VrfInstance route-target connected components.

    Every component with 2 or more members of the route-target pairing relation
    (VRF B receives VRF A's ORIGINATES prefixes iff A exports a route target B
    imports) becomes a RoutingDomain, with `MEMBER_OF {basis: "rt-component"}`
    from each member. A lone VRF gets no grouping. The result is loaded as its
    own Batch(source="reasoner", scope="derived:rt-domains").

    Every cycle and every single-source refresh runs this derivation (app/runs_exec.py).
    """
    from hst.core import reasoner as rt_reasoner

    settings = Settings()
    with dbmod.session(settings) as s:
        manifest = rt_reasoner.execute_rt_domains(s, settings)
    _print_manifest(manifest)


@reason_app.command("link-speed")
def reason_link_speed_cmd() -> None:
    """Derive CONNECTED_TO `speed_mbps`/`speed_agreement` from the two Port nodes
    each cabled link joins.

    Two known and equal speeds give that value and `agree`. Two known and different
    speeds give the minimum and `disagree`. One known speed gives that value and
    `one-side`. No known speed gives null and `unknown`. The result is loaded as
    its own Batch(source="reasoner", scope="derived:link-speed") onto the
    CONNECTED_TO edges that collection created between the two ports.

    A collection cycle does not run this (app/runs_exec.py).
    """
    from hst.core import reasoner as rt_reasoner

    settings = Settings()
    with dbmod.session(settings) as s:
        manifest = rt_reasoner.execute_link_speed(s, settings)
    _print_manifest(manifest)


def _render_trace_block(result: dict) -> None:
    """Render one direction of a trace() result with the per-leg hop loop, the
    verdict and the visualize hint."""
    legs = result.get("legs") or []
    single = len(legs) <= 1
    shared = [h for h in result["hops"] if single or h.get("shared", True)]
    for h in sorted(shared, key=lambda x: x["rank"]):
        console.print(
            f"  {h['rank'] + 1:>2}. [cyan]{h['kind']:<12}[/cyan] {h['label']:<26} [dim]{h['note']}[/dim]"
        )
    if len(legs) > 1:
        for leg in legs:
            mark = "[red]blocked[/red]" if leg["blocked"] else "[green]open[/green]"
            # With several source groups, the line has the subset that this leg serves.
            who = f"{leg['src_label']} " if len({ll["src_label"] for ll in legs}) > 1 else ""
            egress, nh = leg["egress"], leg["next_hop"]
            via = f"{egress} to {nh}" if egress and nh and nh != egress else (egress or nh or "-")
            console.print(f"   ├─ path {leg['lane'] + 1}/{len(legs)}: {who}via [bold]{via}[/bold], {mark}")
            for h in [x for x in result["hops"] if x["lane"] == leg["lane"] and not x.get("shared", True)]:
                console.print(
                    f"   │   {h['rank'] + 1:>2}. [cyan]{h['kind']:<12}[/cyan] "
                    f"{h['label']:<26} [dim]{h['note']}[/dim]"
                )
    console.print(f"[bold]{result['verdict']}[/bold]")
    if result["hops"]:
        console.print("\n[dim]visualize: query browser → 'Traced path' → paste into $uids:[/dim]")
        # soft_wrap keeps each uid whole on one line
        console.print(",".join(h["uid"] for h in result["hops"]), soft_wrap=True)


def _reply_blocks(reply: Any) -> list[tuple[str, dict]]:
    """The reply direction as (heading, block) pairs, one per lane.

    `trace(reply=True)` answers with a single reply object for a trace with
    one forward leg, and a list with one entry per forward leg when the
    forward trace fanned out. Each entry holds its forward leg and the source
    partition that the leg answers for.
    """
    if not isinstance(reply, list):
        return [("reply", reply)]
    # The heading is 1-based "path N/M", and the JSON `forward_leg` is 0-based.
    total = len(reply)
    return [
        (f"reply for path {lane['forward_leg'] + 1}/{total}: {lane['src_label']}", lane) for lane in reply
    ]


@app.command("path")
def path_cmd(
    src: Annotated[str, typer.Argument(help="source IP, prefix or range (192.168.10.44 or 192.168.10.0/24)")],
    dst: Annotated[str, typer.Argument(help="destination IP, prefix or range (8.8.8.8 or 192.168.105.0/24)")],
    port: Annotated[int | None, typer.Option("--port", "-p", help="destination service port")] = None,
    proto: Annotated[str, typer.Option("--proto", help="tcp/udp/icmp")] = "tcp",
    src_context: Annotated[
        str | None,
        typer.Option(
            "--src-context",
            help="forwarding-context uid narrowing which source candidate to trace (see 'context find')",
        ),
    ] = None,
    dst_context: Annotated[
        str | None,
        typer.Option(
            "--dst-context",
            help="forwarding-context uid asserting which destination instance is expected; "
            "it never steers forwarding, and a path delivered outside it is not decided",
        ),
    ] = None,
    reply: Annotated[
        bool,
        typer.Option(
            "--reply",
            help="also trace the reply direction and note asymmetric routing, one lane per "
            "forward path (a source that resolves to several interpretations is not supported)",
        ),
    ] = False,
    mtu_mode: Annotated[str, typer.Option(help="off, inventory, unfragmented or packet")] = "off",
    mtu_ip_packet_bytes: Annotated[
        int | None, typer.Option(help="Complete IP packet bytes including IP header")
    ] = None,
    mtu_ipv4_df: Annotated[
        bool | None, typer.Option("--mtu-ipv4-df/--mtu-no-ipv4-df", help="IPv4 DF state; omit if unknown")
    ] = None,
    mtu_reply_ip_packet_bytes: Annotated[
        int | None, typer.Option(help="Independent reply IP packet bytes; requires --reply")
    ] = None,
    mtu_traffic_class: Annotated[str | None, typer.Option(help="Recorded traffic class selector")] = None,
) -> None:
    """Trace source to destination: attachment, gateway, PBR verdict, route, firewall, egress."""
    from hst import path as pathmod
    from hst.core import ribsource
    from hst.core import snapshot as snapshotmod
    from hst.core.mtu import MtuRequest

    try:
        mtu = MtuRequest.model_validate(
            {
                "mode": mtu_mode,
                "ip_packet_bytes": mtu_ip_packet_bytes,
                "ipv4_df": mtu_ipv4_df,
                "reply_ip_packet_bytes": mtu_reply_ip_packet_bytes,
                "traffic_class": mtu_traffic_class,
            }
        )
        if mtu.reply_ip_packet_bytes is not None and not reply:
            raise ValueError("--mtu-reply-ip-packet-bytes requires --reply")
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    settings = Settings()
    with dbmod.session(settings) as s:
        # The command uses one snapshot. The graph pin and the RIB bound are
        # the same run, resolved once (core/snapshot.py).
        snap = snapshotmod.resolve(s, settings)
        kwargs: dict[str, Any] = {}
        if reply:
            kwargs["reply"] = True
        if mtu.mode != "off":
            kwargs["mtu"] = mtu
        try:
            result = pathmod.trace(
                pathmod.pinned(s, snap),
                src,
                dst,
                port=port,
                proto=proto,
                rib=ribsource.for_snapshot(snap),
                src_context=src_context,
                dst_context=dst_context,
                **kwargs,
            )
        except pathmod.NoRun as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(1) from exc
    if mtu.mode != "off":
        console.print_json(data=result)
        return
    if not reply:
        _render_trace_block(result)
        return
    _render_trace_block(result["forward"])
    console.print()
    for note in result.get("notes") or []:
        console.print(f"[yellow]{note}[/yellow]")
    for heading, block in _reply_blocks(result["reply"]):
        console.print(f"[bold]{heading}[/bold]")
        _render_trace_block(block)


@dataclass(frozen=True)
class TlsFiles:
    """The uvicorn ssl_* arguments for app-native TLS. TLS is off when all are None."""

    certfile: str | None = None
    keyfile: str | None = None
    keyfile_password: str | None = None


def _tls_kwargs_or_die(settings: Settings) -> TlsFiles:
    """Validate tls_cert_file/tls_key_file and build the uvicorn ssl_* arguments.

    A cert without a key, or a key without a cert, exits non-zero before binding.
    """
    cert, key = settings.tls_cert_file, settings.tls_key_file
    if not cert and not key:
        return TlsFiles()
    if not cert or not key:
        missing = "tls_cert_file" if not cert else "tls_key_file"
        console.print(f"[red]TLS misconfigured[/red]: {missing} is not set (cert and key are both required)")
        raise typer.Exit(1)
    password = None
    if settings.tls_key_password_file:
        password = Path(settings.tls_key_password_file).read_text().strip()
    return TlsFiles(certfile=cert, keyfile=key, keyfile_password=password)


@app.command("serve")
def serve_cmd(
    host: Annotated[str, typer.Option(help="bind address")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="listen port")] = 8787,
) -> None:
    """Serve the hst application (login, Flow Desk UI, twin API)."""
    try:
        import uvicorn

        from hst.app.main import create_app
    except ImportError as exc:
        console.print(f"[red]app dependencies missing[/red] ({exc}): pip install -e '.[app]'")
        raise typer.Exit(2) from exc
    settings = Settings()
    _secret_key_or_die(settings)
    tls = _tls_kwargs_or_die(settings)
    scheme = "https" if tls.certfile else "http"
    console.print(f"[green]hst app[/green] {scheme}://{host}:{port}/  (ctrl-c to stop)")
    # Empty keeps uvicorn's default (trust only localhost).
    uvicorn.run(
        create_app(settings),
        host=host,
        port=port,
        forwarded_allow_ips=settings.forwarded_allow_ips or None,
        ssl_certfile=tls.certfile,
        ssl_keyfile=tls.keyfile,
        ssl_keyfile_password=tls.keyfile_password,
        # uvicorn's own access/error loggers at HST_LOG_LEVEL
        log_level=settings.hst_log_level.lower(),
    )


@app.command("worker")
def worker_cmd() -> None:
    """Run the scheduler and the job executor without the HTTP server.

    Every job that this process claims executes here. The jobs are maintenance,
    scheduled cycles, per-device fetches, device runs, and the runs that an API with
    RUN_EXECUTION=queue enqueues. Both loops run at any value of SCHEDULER_ENABLED.
    On SIGTERM or ctrl-c the
    executor cancels the jobs it is running, each run finishes its row as cancelled,
    and the process exits.
    """
    try:
        from hst.worker import runtime
    except ImportError as exc:
        console.print(f"[red]app dependencies missing[/red] ({exc}): pip install -e '.[app]'")
        raise typer.Exit(2) from exc
    settings = Settings()
    # The worker fails closed before it starts, as serve does. A job that seals a
    # payload or reads the credentials of a source needs the operator key.
    _secret_key_or_die(settings)
    console.print("[green]hst worker[/green]: scheduler and executor, no HTTP server (ctrl-c to stop)")
    runtime.main(settings)


@app.command("secret-key")
def secret_key_cmd() -> None:
    """Generate an operator key for HST_SECRET_KEY (any 32+ byte value works)."""
    from hst.app.crypto import generate_key

    console.print(generate_key())


@app.command("rotate-secret-key")
def rotate_secret_key_cmd(
    new_key_file: Annotated[
        Path | None,
        typer.Option("--new-key-file", help="file holding the new key; omitted, one is generated"),
    ] = None,
) -> None:
    """Rotate the operator key. The command re-wraps the internal data key and leaves stored data unchanged.

    The command prints the generated key once. Then set HST_SECRET_KEY (or the file
    HST_SECRET_KEY_FILE points at) to it. The old key opens an old copy of
    dek.wrapped.
    """
    from hst.app.crypto import SecretKeyError, generate_key, rewrap_dek

    settings = Settings()
    new = new_key_file.read_text().strip() if new_key_file else generate_key()
    try:
        rewrap_dek(settings, new)
    except SecretKeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    if not new_key_file:
        console.print(new)
    console.print("[green]re-wrapped[/green], set HST_SECRET_KEY or the key file to the new key")


@app.command("collectors")
def collectors_cmd() -> None:
    """List available collector types (use `hst sources list` for configured sources)."""
    from hst import collectors as coll

    for name in sorted(coll.REGISTRY):
        console.print(name)
    console.print("[dim]configured sources: `hst sources list`[/dim]")


@app.command("http-trace")
def http_trace_cmd(
    path: Annotated[
        Path | None,
        typer.Argument(help="a sealed trace (.http.jsonl.gz.enc); omitted, the traces on disk are listed"),
    ] = None,
    summary: Annotated[
        bool, typer.Option("--summary", help="one row per method and URL path: count, statuses, elapsed")
    ] = False,
) -> None:
    """Read an HTTP exchange trace of a collection (collectors/http_trace.py).

    A trace is written beside the raw file of a fetch whose source is in
    `HST_HTTP_TRACE`. Without a path, the traces under the raw store
    are listed. With one, its JSON lines go to stdout as they are, one
    exchange per line. `--summary` folds them by method and URL path.
    """
    import json as jsonlib
    import sys
    from collections import defaultdict
    from urllib.parse import urlsplit

    from hst.app.crypto import SecretKeyError, dek
    from hst.core import rawstore

    settings = Settings()
    if path is None:
        found = rawstore.traces(settings.raw_dir)
        if not found:
            enabled = settings.hst_http_trace or "off"
            console.print(f"[dim]no HTTP trace under {settings.raw_dir} (HST_HTTP_TRACE is {enabled})[/dim]")
            return
        table = Table(title="HTTP traces")
        for col in ("source", "host", "run id", "fetched", "size", "path"):
            table.add_column(col)
        for t in found:
            fetched = datetime.fromtimestamp(t.fetch_ts_ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(t.source, t.host, t.run_id, fetched, f"{t.size:,}", str(t.path))
        console.print(table)
        return
    if not path.is_file():
        console.print(f"[red]{path} is not a file[/red]")
        raise typer.Exit(2)
    try:
        body = rawstore.read_trace(path, dek(settings))
    except SecretKeyError as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(2) from None
    if not summary:
        sys.stdout.buffer.write(body)
        return
    rows: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "statuses": set(), "elapsed": []}
    )
    for line in body.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        exchange = jsonlib.loads(line)
        row = rows[(exchange.get("method", ""), urlsplit(exchange.get("url", "")).path)]
        row["count"] += 1
        row["statuses"].add(exchange.get("status"))
        if exchange.get("elapsed_ms") is not None:
            row["elapsed"].append(exchange["elapsed_ms"])
    table = Table(title=f"{path.name}: {sum(r['count'] for r in rows.values())} exchanges")
    for col in ("method", "path", "count", "statuses", "elapsed ms (mean, max)"):
        table.add_column(col)
    for (method, url_path), row in sorted(rows.items(), key=lambda item: -item[1]["count"]):
        elapsed = row["elapsed"]
        mean_max = f"{sum(elapsed) / len(elapsed):.0f}, {max(elapsed)}" if elapsed else ""
        table.add_row(
            method,
            url_path,
            str(row["count"]),
            ", ".join(str(s) for s in sorted(row["statuses"], key=str)),
            mean_max,
        )
    console.print(table)


@app.command("parse-raw")
def parse_raw_cmd(
    collector: Annotated[str, typer.Argument(help="collector name, as `hst collectors` lists them")],
    path: Annotated[
        Path | None,
        typer.Argument(help="a raw-store file (.json.gz.enc) or a directory of per-command files"),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", help="JSON file with the source configuration; omitted, a stand-in is used"),
    ] = None,
    json_out: Annotated[bool, typer.Option("--json", help="print the report as JSON")] = False,
    commands: Annotated[
        bool, typer.Option("--commands", help="list the collector's commands and their capture file names")
    ] = False,
) -> None:
    """Parse one captured payload offline and report what each section produced.

    The command uses no database and no device session. The payload is a raw-store
    file, decrypted with the configured secret key, or a directory holding one file
    per command named as `--commands` prints them (`show vrf | json` is
    `show-vrf.json`). The capture goes through the `sections`, `normalize`,
    `side_tables` and `table_outcomes` of the collector. The report holds what a
    run of that payload records. It has one row per section with its status, the
    node count per label, the side-table row counts and the table outcomes of the
    manifest.

    The exit status is 1 when a section is malformed, failed or unauthorized, or
    when the parse raised.
    """
    import json as jsonlib

    from hst.collectors import offline
    from hst.core import rawstore

    settings = Settings()
    source_config = None
    if config is not None:
        try:
            source_config = jsonlib.loads(config.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            console.print(f"[red]cannot read --config {config}[/red]: {exc}")
            raise typer.Exit(2) from None
    try:
        instance = offline.build_collector(collector, settings, source_config)
    except (ValueError, TypeError) as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(2) from None

    if commands:
        rows = offline.expected_commands(instance)
        if json_out:
            console.print_json(data=[{"command": c, "kind": k, "file": f} for c, k, f in rows])
            return
        table = Table(title=f"{collector} capture files")
        for col in ("command", "kind", "file"):
            table.add_column(col)
        for c, k, f in rows:
            table.add_row(escape(c), k, f)
        console.print(table)
        console.print(
            "[dim]commands derived from the payload (per-neighbor BGP tables, Gaia per-context "
            "reads) are named by the same rule and are not listed[/dim]"
        )
        return

    if path is None:
        console.print("[red]a capture path is required[/red] unless --commands is given")
        raise typer.Exit(2)
    if path.is_dir():
        report = offline.parse_directory(instance, path)
    elif path.is_file():
        try:
            from hst.app.crypto import SecretKeyError, dek

            raw = rawstore.read(path, dek(settings))
        except SecretKeyError as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(2) from None
        except Exception as exc:
            console.print(f"[red]cannot open {path} as a raw-store file[/red]: {escape(str(exc))}")
            raise typer.Exit(2) from None
        report = offline.parse_report(instance, raw, path=str(path))
    else:
        console.print(f"[red]{path} does not exist[/red]")
        raise typer.Exit(2)

    if json_out:
        console.print_json(data=report.as_dict())
    else:
        _print_parse_report(report)
    if not report.ok:
        raise typer.Exit(1)


def _print_parse_report(report) -> None:
    console.print(f"collector {report.collector}, capture {report.path}")
    if report.error:
        console.print(f"[red]{escape(report.error)}[/red]")
    colours = {"ok": "green", "empty": "yellow", "unknown": "dim"}
    table = Table(title="sections")
    for col in ("section", "status", "rows", "detail", "file"):
        table.add_column(col)
    for name, s in report.sections.items():
        colour = colours.get(s.status, "red")
        command = report.commands.get(name, "")
        file_name = report.files.get(command) or report.missing_files.get(command) or ""
        table.add_row(
            name,
            f"[{colour}]{s.status}[/{colour}]",
            "" if s.row_count is None else str(s.row_count),
            escape(s.detail),
            file_name,
        )
    console.print(table)
    if report.labels:
        console.print("nodes: " + ", ".join(f"{label} {n}" for label, n in report.labels.items()))
        console.print(f"relationships: {report.rels}")
    if report.side_tables:
        console.print("side tables: " + ", ".join(f"{t} {n}" for t, n in report.side_tables.items()))
    if report.outcomes:
        outcomes = Table(title="table outcomes")
        for col in ("table", "status", "rows", "detail"):
            outcomes.add_column(col)
        for name, o in report.outcomes.items():
            outcomes.add_row(
                escape(name), o.status, "" if o.row_count is None else str(o.row_count), escape(o.detail)
            )
        console.print(outcomes)
    if report.missing_files:
        console.print("missing files: " + ", ".join(sorted(set(report.missing_files.values()))))
    if report.unrecognised_files:
        console.print("files matching no command: " + ", ".join(report.unrecognised_files))


@app.command("validate-demo")
def validate_demo() -> None:
    """Run the scenario suite against the loaded demo fixtures. `make e2e` loads the 3 fixtures first."""
    from hst.demo import run_all

    settings = Settings()
    with dbmod.session(settings) as s:
        results = run_all(s)
    table = Table(title="schema scenario validation")
    for col in ("", "scenario", "rows", "min"):
        table.add_column(col)
    failed = 0
    for r in results:
        ok = r["ok"]
        failed += 0 if ok else 1
        mark = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(mark, r["title"], str(r["rows"]), str(r["min_rows"]))
        if r["error"]:
            table.add_row("", f"[red]{r['error']}[/red]", "", "")
    console.print(table)
    if failed:
        console.print(f"[red]{failed} scenario(s) failed[/red]")
        raise typer.Exit(1)
    console.print(f"[green]all {len(results)} scenarios pass[/green]")


@unit_of_work(timeout=30.0)
def _status_work(tx: Any, q: str) -> list[dict[str, Any]]:
    return tx.run(q).data()


@app.command("status")
def status() -> None:
    """Latest CollectionRun per source."""
    settings = Settings()
    q = """
MATCH (r:CollectionRun)
WITH r ORDER BY r.finished_ms DESC
WITH r.source AS source, collect(r)[0] AS last
RETURN source, last.run_id AS run_id, last.finished AS finished,
       last.nodes_upserted AS nodes, last.rels_upserted AS rels,
       last.nodes_retired AS retired,
       last.retirement_skipped OR coalesce(last.rel_retirement_skipped, false) AS skipped
ORDER BY source
"""
    with dbmod.session(settings) as s:
        rows = s.execute_read(_status_work, q)
    if not rows:
        console.print("no collection runs recorded yet")
        return
    table = Table(title="collection status")
    for col in ("source", "finished", "nodes", "rels", "retired", "retire-skipped", "run id"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            str(r["source"]),
            str(r["finished"]),
            str(r["nodes"]),
            str(r["rels"]),
            str(r["retired"]),
            str(r["skipped"]),
            str(r["run_id"]),
        )
    console.print(table)


audit_app = typer.Typer(help="Data-quality reports over the graph.")
app.add_typer(audit_app, name="audit")


@unit_of_work(timeout=30.0)
def _audit_contexts_work(tx: Any, q: str, snap: Any) -> list[dict[str, Any]]:
    return tx.run(q, snap=snap).data()


@audit_app.command("mtu")
def mtu_audit_cmd(
    scope: Annotated[
        str, typer.Option(help="link, bridge-domain or fabric; use path for path audits")
    ] = "link",
    subject_uid: Annotated[str | None, typer.Option(help="Recorded interface/domain/fabric UID")] = None,
    snapshot: Annotated[int | None, typer.Option(help="Exact run ID; omit for current")] = None,
    af: Annotated[int, typer.Option(help="IP family 4 or 6")] = 4,
    limit: Annotated[int, typer.Option(help="Page size 1..200")] = 50,
    cursor: Annotated[str | None, typer.Option(help="Cursor bound to returned snapshot and scope")] = None,
) -> None:
    """Read MTU differences and gaps. The audit assumes no target MTU and no default MTU."""
    from typing import Literal, cast

    from hst import path
    from hst.core import snapshot as snapshotmod
    from hst.core.mtu_audit_read import AuditScope, audit_mtu

    settings = Settings()
    try:
        with dbmod.session(settings) as session:
            snap = snapshotmod.resolve(session, settings, snapshot)
            result = audit_mtu(
                path.pinned(session, snap),
                scope=cast(AuditScope, scope),
                subject_uid=subject_uid,
                af=cast(Literal[4, 6], af),
                limit=limit,
                cursor=cursor,
            )
        console.print_json(data=result.model_dump())
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@audit_app.command("contexts")
def audit_contexts() -> None:
    """Interfaces with an address but no IN_VRF edge to a forwarding context.

    On a hit the collector did not determine the VRF (or global routing table)
    of the interface, and the tracer matches the interface by name. The command
    only reports. It exits 0 also with findings.
    """
    from hst import queries
    from hst.core import snapshot as snapshotmod

    settings = Settings()
    with dbmod.session(settings) as s:
        cts = snapshotmod.resolve(s, settings).cts
        snap = snapshotmod.snap_param(cts)
        rows = s.execute_read(_audit_contexts_work, queries.AUDIT_INTERFACES_MISSING_CONTEXT, snap)
    if not rows:
        console.print("[green]no interfaces with addresses are missing an IN_VRF edge[/green]")
        return
    for r in rows:
        console.print(
            f"  {r['device_uid']}  {r['interface_uid']}  {r['interface_name']}  "
            f"{r['address_count']} address(es)"
        )
    console.print(f"[yellow]{len(rows)} interface(s) missing forwarding context[/yellow]")


@audit_app.command("domains")
def audit_domains() -> None:
    """VRFs that exchange routes over a shared route target but land in different declared domains.

    Computes the connected components of the route-target pairing relation and
    reports every component whose members declare more than one distinct domain
    (`core.reasoner.REALIZES_AT_CYCLE_QUERY`). The command only reports and
    always exits 0.
    """
    from hst.core import reasoner as rt_reasoner
    from hst.core import snapshot as snapshotmod

    settings = Settings()
    with dbmod.session(settings) as s:
        # The run is resolved once and passed to both reads.
        cts = snapshotmod.resolve(s, settings).cts
        topology = rt_reasoner.read_topology(s, cts)
        realizes = rt_reasoner.read_realizes(s, cts)
    splits = rt_reasoner.find_domain_splits(topology, realizes)
    if not splits:
        console.print("[green]no route-target-connected VRFs span more than one declared domain[/green]")
        return
    for split in splits:
        console.print(f"route targets: {', '.join(split.rts)}")
        for vrf_uid, device_uid in split.members:
            console.print(f"  {vrf_uid}  ({device_uid})")
        console.print(f"  splits across {len(split.domains)} declared domain(s): {', '.join(split.domains)}")
    console.print(f"[yellow]{len(splits)} component(s) span more than one declared domain[/yellow]")


@audit_app.command("segments")
def audit_segments() -> None:
    """Broadcast domains whose carriage evidence disagrees with declared segment identity.

    The audit joins VLAN instances where one collected link has the same VID on both
    ends (802.1Q: a VID is significant per link) and reports 2 shapes. A merge is one
    observed broadcast domain realized as more than one declared segment (per-source
    scope drift). A split is one declared segment whose evidenced members have no
    collected trunk path between them. Ports without carriage evidence give no
    finding. The command only reports and always exits 0.
    """
    from hst.core import reasoner as rt_reasoner
    from hst.core import snapshot as snapshotmod

    settings = Settings()
    with dbmod.session(settings) as s:
        # The run is resolved once and passed to all three reads.
        cts = snapshotmod.resolve(s, settings).cts
        carriage = rt_reasoner.read_carriage(s, cts)
        links = rt_reasoner.read_port_links(s, cts)
        realizes = rt_reasoner.read_segment_realizes(s, cts)
    if not carriage:
        console.print(
            "[yellow]no carriage evidence in the graph (no CARRIES edges): nothing to judge; "
            "re-collect with a collector that reports VLAN carriage[/yellow]"
        )
        return
    components = rt_reasoner.bridge_components(links, carriage)
    merges = rt_reasoner.find_segment_merges(components, realizes)
    splits = rt_reasoner.find_segment_splits(components, realizes)
    if not merges and not splits:
        console.print("[green]carriage evidence and declared segment identity agree[/green]")
        return
    for m in merges:
        vids = ", ".join(str(v) for v in m.vids)
        console.print(f"one broadcast domain (vlan {vids}) is declared as {len(m.segments)} segments:")
        for seg in m.segments:
            console.print(f"  {seg}")
        console.print(f"  members: {', '.join(m.members)}")
    for sp in splits:
        console.print(f"{sp.segment} has no collected trunk path between its member groups:")
        for group in sp.components:
            console.print(f"  {', '.join(group)}")
    console.print(f"[yellow]{len(merges)} merge finding(s), {len(splits)} split finding(s)[/yellow]")


# Reads live IN pairs for the cycle the reasoner's three containment reads cover.
AUDIT_LIVE_IN_PAIRS = """
MATCH (ia:IpAddress:Obj)-[e:IN]->(p:Prefix)
WHERE e._retired_at IS NULL AND NOT ia:Retired AND NOT p:Retired
  AND ia.collection_ts = $cts
RETURN ia.uid AS ip, p.uid AS pfx
"""


@unit_of_work(timeout=30.0)
def _audit_containment_work(
    tx: Any, cts: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    from hst import reasoner

    return (
        tx.run(reasoner.CONTAINMENT_ADDRESSES, cts=cts).data(),
        tx.run(reasoner.CONTAINMENT_PREFIXES, cts=cts).data(),
        tx.run(reasoner.CONTAINMENT_BD_MAP, cts=cts).data(),
        tx.run(AUDIT_LIVE_IN_PAIRS, cts=cts).data(),
    )


@audit_app.command("containment")
def audit_containment() -> None:
    """Held addresses inside a known connected prefix that lack their IN edge.

    The audit recomputes the pairs that the address-containment rule of the
    reasoner derives, with the same three reads and the same `containment_pairs`
    helper. It reports every expected pair without a live IN edge in the current
    cycle. Only a missing
    pair is a finding. The command only reports and always exits 0.
    """
    from hst import reasoner
    from hst.core import snapshot as snapshotmod

    settings = Settings()
    with dbmod.session(settings) as s:
        cts = snapshotmod.resolve(s, settings).cts
        if cts is None:
            console.print("no cycle pointer: build a run before this report")
            return
        addresses, prefixes, bd_serving, live = s.execute_read(_audit_containment_work, cts)
    expected = reasoner.containment_pairs(addresses, prefixes, bd_serving)
    have = {(r["ip"], r["pfx"]) for r in live}
    missing = [m for m in expected if (m["ip"], m["pfx"]) not in have]
    if not missing:
        console.print("[green]every held address inside a known connected prefix has its IN edge[/green]")
        return
    ip_of = {a["uid"]: a.get("ip") or "?" for a in addresses}
    cidr_of = {pfx["uid"]: pfx.get("cidr") or "?" for pfx in prefixes}
    for m in missing:
        console.print(f"  {m['ip']}  {ip_of.get(m['ip'], '?')}  ->  {m['pfx']}  {cidr_of.get(m['pfx'], '?')}")
    console.print(f"[yellow]{len(missing)} containment edge(s) missing; build a run to re-derive[/yellow]")


context_app = typer.Typer(help="Resolve names to forwarding-context uids.")
app.add_typer(context_app, name="context")


@unit_of_work(timeout=30.0)
def _context_find_work(tx: Any, name: str, domain: str | None, snap: Any) -> list[dict[str, Any]]:
    from hst import queries

    return queries.resolve_context(tx, name, domain=domain, snap=snap)


@context_app.command("find")
def context_find(
    name: Annotated[str, typer.Argument(help="VRF/context name (case-insensitive)")],
    domain: Annotated[
        str | None,
        typer.Option("--domain", help="narrow to contexts MEMBER_OF this RoutingDomain (case-insensitive)"),
    ] = None,
) -> None:
    """Resolve a name to forwarding-context uids.

    The result is every live VrfInstance whose name matches, with table id, scope,
    domain and device. A name can match more than one context. Every match is
    printed, and --domain narrows the matches. The command only reports and always
    exits 0.
    """
    from hst.core import snapshot as snapshotmod

    settings = Settings()
    with dbmod.session(settings) as s:
        cts = snapshotmod.resolve(s, settings).cts
        snap = snapshotmod.snap_param(cts)
        rows = s.execute_read(_context_find_work, name, domain, snap)
    if not rows:
        where = f" in domain {domain!r}" if domain else ""
        console.print(f"[yellow]no context named {name!r} found{where}[/yellow]")
        return
    for r in rows:
        marker = " [cyan]global[/cyan]" if r["is_global"] else ""
        domains = ", ".join(r["domains"]) or "-"
        devices = ", ".join(r["devices"]) or "-"
        console.print(f"  {r['uid']}  table={r['table_id']}{marker}  domains={domains}  devices={devices}")
    if len(rows) > 1:
        console.print(f"[yellow]{len(rows)} contexts match: narrow with --domain or use the uid[/yellow]")


sidestore_app = typer.Typer(help="Query the parquet side store (high-churn tables).")
app.add_typer(sidestore_app, name="sidestore")


@sidestore_app.command("query")
def sidestore_query(
    sql: Annotated[str, typer.Argument(help="SQL over side-store tables, e.g. SELECT * FROM rib")],
) -> None:
    """Run a read-only SQL query over the parquet side store."""
    settings = Settings()
    try:
        from hst.core import sidestore

        rows = sidestore.query(settings.sidestore_dir, sql)
    except (ImportError, RuntimeError) as exc:
        console.print(
            f"[red]side store dependencies missing[/red] ({escape(str(exc))}): "
            "pip install -e '.\\[sidestore]'"
        )
        raise typer.Exit(2) from exc
    except Exception as exc:
        import duckdb

        if not isinstance(exc, duckdb.Error):
            raise
        console.print(f"[red]query failed[/red]: {escape(str(exc))}")
        raise typer.Exit(1) from exc
    if not rows:
        console.print("no rows")
        return
    table = Table()
    for col in rows[0]:
        table.add_column(col)
    for r in rows:
        table.add_row(*(str(v) for v in r.values()))
    console.print(table)


@sidestore_app.command("prune")
def sidestore_prune(
    keep: Annotated[
        int | None,
        typer.Option(
            "--keep",
            help="cycles of graph history to keep; default the stored Lifecycle value, else CYCLE_KEEP_RUNS",
        ),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", help="actually delete; omit for a dry run")] = False,
) -> None:
    """Delete side-store files that no retained run needs.

    The command runs the scheduled side-store prune (`worker.maintenance.prune_sidestore`).
    A file is kept when its run is one the graph keeps at `--keep` cycles and
    the stored number of device or refresh runs, when a retained assessment
    references its run, when a reader holds its run open, or when the manifest of
    any of those runs binds it. With EVIDENCE_RETENTION_DAYS set, a file is also
    kept until its run is past that period. The command takes the cycle lock
    without waiting and stops when a collection holds it.

    Requires the app extra and its configured, migrated Postgres store, as
    `hst prune` does.

    Without --yes this reports what would be deleted and deletes nothing.
    """
    if keep is not None and keep <= 0:
        console.print("[red]--keep must be a positive integer[/red]")
        raise typer.Exit(2)
    from hst.core import cycle as cyclemod

    settings = Settings()
    base = settings.sidestore_dir
    if not base.is_dir():
        console.print("nothing to prune")
        return

    async def prune_with_references(store):
        from hst.app import retention
        from hst.worker.maintenance import prune_sidestore

        if not callable(getattr(store, "retained_snapshot_refs", None)):
            raise ValueError("The store does not expose assessment retention references.")
        stored = await retention.resolve(store, settings)
        limits = cyclemod.Keep(
            keep if keep is not None else stored.cycle_keep_runs, stored.cycle_keep_device_runs
        )
        return await prune_sidestore(settings, store, limits, dry_run=not yes)

    try:
        victims = _assessment_store_read(settings, prune_with_references, hold_lock=False)
    except Exception as exc:
        typer.echo(
            "Pruning stopped: assessment retention state or its protected evidence could not be verified. "
            "Install the app extra and configure the migrated Postgres store. "
            f"Failure type: {type(exc).__name__}.",
            err=True,
        )
        raise typer.Exit(1) from exc
    if victims is None:
        typer.echo(
            "A collection holds the cycle lock; nothing was pruned. Run it again when it ends.", err=True
        )
        raise typer.Exit(1)
    if not victims:
        console.print("nothing to prune")
        return
    verb = "deleted" if yes else "would delete"
    for path in victims:
        console.print(f"{'deleting' if yes else 'would delete'} {path.relative_to(base)}")
    console.print(f"{verb} {len(victims)} file(s)")
    if not yes:
        console.print("[dim]pass --yes to actually delete[/dim]")


def _print_manifest(m) -> None:
    style = "red" if m.errors else "green"
    console.print(
        f"[{style}]run {m.run_id}[/{style}] "
        f"nodes: {m.nodes_upserted} (+{m.nodes_created} new, {m.nodes_revived} revived, "
        f"-{m.nodes_retired} retired); "
        f"rels: {m.rels_upserted} (+{m.rels_created} new, -{m.rels_retired} retired, "
        f"{m.rels_dropped_missing_endpoint} dropped)"
    )
    for e in m.errors:
        console.print(f"[yellow]warn[/yellow] {e}")


geo_places_app = typer.Typer(help="The offline place table behind the site address lookup.")
app.add_typer(geo_places_app, name="geo-places")


@geo_places_app.command("load")
def geo_places_load(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            help="A GeoNames postal code file from download.geonames.org/export/zip: "
            "allCountries.zip, one country's zip, or the text file inside it.",
        ),
    ],
) -> None:
    """Replace the place table with the places in PATH. The data is GeoNames,
    CC BY 4.0 (app/geo_places.py). The app does not replace a file loaded here
    with the file of `GEO_PLACES_FILE`."""
    from hst.app.geo_places import SOURCE_SETTING_KEY, read_geonames, source_record

    async def go(store):
        try:
            count = await store.replace_geo_places(read_geonames(path))
        except (ValueError, UnicodeDecodeError) as exc:
            console.print(f"[red]{escape(str(exc))}[/red]")
            raise typer.Exit(1) from exc
        await store.put_setting(SOURCE_SETTING_KEY, source_record(path, "operator"), b"")
        console.print(f"loaded {count:,} places from {escape(path.name)}")

    _with_store(go)


ipam_app = typer.Typer(help="The IPAdmin subnet register the runs annotate prefixes from.")
app.add_typer(ipam_app, name="ipam")


@ipam_app.command("import")
def ipam_import(
    path: Annotated[
        Path,
        typer.Argument(dir_okay=False, help="An IPAdmin network-list CSV export, or - for stdin."),
    ],
) -> None:
    """Seal the export in PATH into the raw store (core/ipam.py). No snapshot
    changes. The next run applies the newest import to its prefixes."""
    import sys

    from hst.core import ipam

    try:
        text = sys.stdin.read() if str(path) == "-" else path.read_text(encoding="utf-8-sig")
        raw, count = ipam.import_export(Settings(), path, text)
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"imported {count:,} subnets as {escape(raw.name)}; the next run applies them")


user_app = typer.Typer(help="Manage application accounts (stored in Postgres).")
app.add_typer(user_app, name="user")


def _open_store(settings: Settings, *, migrate: bool = True):
    """The Postgres store.

    With `migrate`, the migrations run first. Without it, no migration runs, and a
    schema that is not at the newest revision raises RuntimeError.
    """
    from hst.app.store.pg import PgStore, schema_is_current, upgrade_to_head

    if migrate:
        upgrade_to_head(settings.postgres_dsn, settings.postgres_ca_file)
    elif not schema_is_current(settings.postgres_dsn, settings.postgres_ca_file):
        raise RuntimeError(
            "the Postgres schema is not at the revision that this hst version expects, "
            "and this command applies no migration"
        )
    return PgStore(settings.postgres_dsn, settings.postgres_ca_file)


def _with_store(fn, *, migrate: bool = True):
    """Run an async store operation from a sync CLI command. `migrate` goes to `_open_store`."""
    import asyncio

    settings = Settings()
    # The migration and the revision check each call asyncio.run(). The store
    # opens before the loop below starts.
    store = _open_store(settings, migrate=migrate)

    async def go():
        from hst.app.inventory.repository import InventoryError
        from hst.app.inventory.runtime import initialize_fresh

        try:
            await initialize_fresh(store)
            return await fn(store)
        except InventoryError as exc:
            console.print(str(exc), markup=False)
            raise typer.Exit(1) from exc
        finally:
            await store.dispose()

    return asyncio.run(go())


sources_app = typer.Typer(help="Manage configured sources (rows in Postgres).")
app.add_typer(sources_app, name="sources")


def _secret_key_or_die(settings: Settings) -> str:
    """The data key, unwrapped (or created on first use) under the operator key."""
    from hst.app.crypto import SecretKeyError, dek

    try:
        return dek(settings)
    except SecretKeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc


def _config_text(config: str) -> str:
    return typer.get_text_stream("stdin").read() if config == "-" else config


def _collect_payload(type_: str, config_json: str) -> dict:
    """Parse --config JSON and prompt (hidden) for each secret field not provided."""
    import json as _json

    from hst.app import sources as glue

    config_json = _config_text(config_json)
    try:
        payload = _json.loads(config_json) if config_json else {}
    except _json.JSONDecodeError as exc:
        console.print(f"[red]--config is not valid JSON: {exc}[/red]")
        raise typer.Exit(1) from exc
    from hst import collectors as coll

    if type_ not in coll.REGISTRY:
        console.print(f"[red]unknown type {type_!r}[/red] (available: {', '.join(sorted(coll.REGISTRY))})")
        raise typer.Exit(1)
    model_cls = coll.REGISTRY[type_].ConfigModel
    for path in sorted(glue.secret_paths_for_payload(model_cls, payload)):
        if not _path_missing(payload, path):
            continue
        _set_path(payload, path, typer.prompt(path, hide_input=True, confirmation_prompt=True))
    return payload


def _path_missing(payload: dict, path: str) -> bool:
    node = payload
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return True
        node = node[part]
    return False


def _set_path(payload: dict, path: str, value: str) -> None:
    parts = path.split(".")
    node = payload
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


@sources_app.command("add")
def sources_add(
    name: str,
    type_: Annotated[str, typer.Option("--type", help="`hst collectors` lists types")],
    config: Annotated[
        str, typer.Option("--config", help="non-secret fields as JSON, or - for standard input")
    ] = "",
) -> None:
    """Add a source. The command prompts for secret fields that are not in --config."""
    import re

    from pydantic import ValidationError

    from hst.app import sources as glue
    from hst.app.crypto import SecretKeyError, encrypt_secrets

    if name in ("reasoner", "snapshot"):
        console.print(f"[red]{name} is a reserved name[/red]")
        raise typer.Exit(1)
    if not re.fullmatch(glue.NAME_PATTERN, name):
        console.print(f"[red]name must match {glue.NAME_PATTERN}[/red]")
        raise typer.Exit(1)

    payload = _collect_payload(type_, config)
    payload.pop("source_name", None)

    async def go(store):
        settings = Settings()
        from hst.app.inventory.legacy import LegacyConnections, active

        if await active(store):
            await LegacyConnections(store, settings).create(name, type_, payload)
            console.print(f"{type_} source {name} created")
            return
        key = _secret_key_or_die(settings)
        try:
            cfg, secrets = glue.validate_source(type_, payload)
        except ValidationError as exc:
            e = exc.errors()[0]
            console.print(f"[red]invalid config: {'.'.join(str(p) for p in e['loc'])}: {e['msg']}[/red]")
            raise typer.Exit(1) from exc
        try:
            await store.create_source(name, type_, cfg, encrypt_secrets(key, secrets))
        except SecretKeyError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        console.print(f"[green]{type_} source {name} created[/green]")

    _with_store(go)


@sources_app.command("list")
def sources_list() -> None:
    """List configured sources."""

    async def go(store):
        rows = await store.list_sources()
        if not rows:
            console.print("no sources configured: `hst sources add`")
            return
        table = Table(title="sources")
        for col in ("name", "type", "enabled", "updated"):
            table.add_column(col)
        for s in rows:
            table.add_row(s.name, s.type, "yes" if s.enabled else "[red]no[/red]", str(s.updated_at or ""))
        console.print(table)

    _with_store(go)


@sources_app.command("set")
def sources_set(
    name: str,
    config: Annotated[
        str, typer.Option("--config", help="fields to change as JSON, or - for standard input")
    ] = "",
    enable: Annotated[bool | None, typer.Option("--enable/--disable")] = None,
) -> None:
    """Update a source.

    The command merges config and secrets as the API PATCH does, and sets `enabled`
    with --enable or --disable."""
    import json as _json

    from pydantic import ValidationError

    from hst.app import sources as glue
    from hst.app.crypto import SecretKeyError

    config = _config_text(config)
    try:
        overlay = _json.loads(config) if config else {}
    except _json.JSONDecodeError as exc:
        console.print(f"[red]--config is not valid JSON: {exc}[/red]")
        raise typer.Exit(1) from exc

    async def go(store):
        settings = Settings()
        from hst.app.inventory.legacy import LegacyConnections, active

        if await active(store):
            await LegacyConnections(store, settings).patch(name, overlay or None, enable)
            console.print(f"ok {name}")
            return
        key = _secret_key_or_die(settings) if overlay else ""

        def change(row):
            if overlay:
                try:
                    row.config, row.secrets = glue.merge_config(row, overlay, key)
                except SecretKeyError as exc:
                    console.print(f"[red]{exc}[/red]")
                    raise typer.Exit(1) from exc
                except glue.SecretsUnreadable as exc:
                    console.print(f"[red]{exc}[/red]")
                    raise typer.Exit(1) from exc
                except ValidationError as exc:
                    e = exc.errors()[0]
                    console.print(
                        f"[red]invalid config: {'.'.join(str(p) for p in e['loc'])}: {e['msg']}[/red]"
                    )
                    raise typer.Exit(1) from exc
            if enable is not None:
                row.enabled = enable
            return row

        if await store.modify_source(name, change) is None:
            console.print(f"[red]no source {name!r}[/red]")
            raise typer.Exit(1)
        console.print(f"[green]ok[/green] {name}")

    _with_store(go)


@sources_app.command("remove")
def sources_remove(name: str) -> None:
    """Remove a source (refuses while it has a run in flight)."""

    async def go(store):
        from hst.app.inventory.legacy import LegacyConnections, active

        if await active(store):
            await LegacyConnections(store, Settings()).delete(name)
            console.print(f"removed {name}")
            return
        from hst.app.store import live_run

        if await live_run(store, name):
            console.print(f"[red]{name} has a run in flight[/red]")
            raise typer.Exit(1)
        if not await store.delete_source(name):
            console.print(f"[red]no source {name!r}[/red]")
            raise typer.Exit(1)
        console.print(f"[green]removed[/green] {name}")

    _with_store(go)


@sources_app.command("test")
def sources_test(name: str) -> None:
    """Probe a source with a login and a version fetch. No collection runs."""
    from hst.app import runs_exec
    from hst.app import sources as glue

    async def go(store):
        settings = Settings()
        from hst.app.inventory.legacy import LegacyConnections, active

        if await active(store):
            result = await LegacyConnections(store, settings).probe(name)
            console.print(result["detail"], markup=False)
            if not result["ok"]:
                raise typer.Exit(1)
            return
        row = await store.get_source(name)
        if row is None:
            console.print(f"[red]no source {name!r}[/red]")
            raise typer.Exit(1)
        try:
            rows = {r.name: r for r in await store.list_sources()}
            collector = glue.build_collector(row, settings, sources=rows)
            detail = collector.probe()
        except Exception as exc:
            console.print(f"[red]{type(exc).__name__}: {exc}[/red]")
            raise typer.Exit(1) from exc
        await runs_exec.pin_host_key(store, row, collector)
        console.print(f"[green]ok[/green] {detail}")

    _with_store(go)


@sources_app.command("unpin")
def sources_unpin(name: str) -> None:
    """Clear a source's pinned SSH host keys so the next connection re-pins.

    The command is for a device replacement or a host OS reinstall. No command
    accepts a changed key in place.
    """

    async def go(store):
        changed = False

        def change(row):
            nonlocal changed
            config = row.config
            if config.get("host_key"):
                config["host_key"] = ""
                changed = True
            jump = config.get("jump_host")
            if isinstance(jump, dict) and jump.get("host_key"):
                config["jump_host"] = {**jump, "host_key": ""}
                changed = True
            return row if changed else None

        if await store.modify_source(name, change) is None:
            console.print(f"[red]no source {name!r}[/red]")
            raise typer.Exit(1)
        if not changed:
            console.print("nothing pinned")
            return
        console.print(f"[green]unpinned[/green] {name}: the next connection re-pins")

    _with_store(go)


bench_app = typer.Typer(help="Engine benchmarks against a fake fleet.")
app.add_typer(bench_app, name="bench")


@bench_app.command("fleet")
def bench_fleet(
    devices: Annotated[int, typer.Option("--devices")] = 1000,
    latency_ms: Annotated[int, typer.Option("--latency-ms", help="modeled device round trip")] = 500,
    concurrency: Annotated[int, typer.Option("--concurrency")] = 64,
    cadence: Annotated[int, typer.Option("--cadence", help="budget in seconds")] = 60,
    change_rate: Annotated[float, typer.Option("--change-rate", help="fraction that must load")] = 0.05,
    load_ms: Annotated[int, typer.Option("--load-ms", help="serial cost per changed device")] = 0,
    mode: Annotated[
        str, typer.Option("--mode", help="a = modeled round trip; b = real SSH with KEX/auth cost")
    ] = "a",
) -> None:
    """Measure one cycle over a warm fake fleet.

    The cycle has the concurrent fetch phase, the payload hashing and the skip
    decision. Mode a sleeps for the round trip. Mode b runs a real asyncssh
    session per device against an in-process server. The loader is stubbed.
    --load-ms models the serial phase per changed device."""
    from hst.bench import run_bench

    result = run_bench(
        devices=devices,
        latency_ms=latency_ms,
        concurrency=concurrency,
        change_rate=change_rate,
        load_ms=load_ms,
        mode=mode,
    )
    console.print(result.line(cadence))
    raise typer.Exit(0 if result.fits(cadence) else 1)


@bench_app.command("estate")
def bench_estate(
    devices: Annotated[int, typer.Option("--devices")] = 100,
    runs: Annotated[int, typer.Option("--runs", help="retained runs to write")] = 3,
    rib_rows: Annotated[int, typer.Option("--rib-rows", help="RIB rows per device per run")] = 1000,
    peers: Annotated[int, typer.Option("--peers", help="BGP peers per device")] = 2,
    paths: Annotated[int, typer.Option("--paths", help="path-table rows per peer")] = 500,
    lookups: Annotated[int, typer.Option("--lookups", help="LPM probes to time")] = 50,
    row_group_rows: Annotated[
        int, typer.Option("--row-group-rows", help="0 takes the configured default")
    ] = 0,
) -> None:
    """Write, digest, look up and checkpoint a synthetic estate of this size.

    The command prints the measured rows, files, bytes on disk, write and digest
    time, longest-prefix-match latency, checkpoint time and peak RSS. It needs no
    database and no network. The store is a temporary directory."""
    from hst.bench import run_estate_bench

    result = run_estate_bench(
        devices=devices,
        runs=runs,
        rib_rows=rib_rows,
        peers=peers,
        paths=paths,
        lookups=lookups,
        row_group_rows=row_group_rows or None,
    )
    console.print(result.line())


devices_app = typer.Typer(
    help="Manage a source's device fleet. "
    "The source row is the group: shared credentials, site and routing scope."
)
app.add_typer(devices_app, name="devices")


@devices_app.command("list")
def devices_list(source: str) -> None:
    """List the devices of one source."""

    async def go(store):
        if await store.get_source(source) is None:
            console.print(f"[red]no source {source!r}[/red]")
            raise typer.Exit(1)
        rows = await store.list_devices(source)
        if not rows:
            console.print(f"no devices in {source}: `hst devices import`")
            return
        table = Table(title=f"devices of {source}")
        for col in ("host", "port", "enabled", "pinned"):
            table.add_column(col)
        for d in rows:
            table.add_row(
                d.host,
                str(d.port) if d.port is not None else "",
                "yes" if d.enabled else "[red]no[/red]",
                "yes" if d.host_key else "no",
            )
        console.print(table)

    _with_store(go)


@devices_app.command("import")
def devices_import(
    source: str,
    file: Annotated[Path, typer.Option("--file", help="one device per line: host[,port]")],
) -> None:
    """Replace the source's fleet with the file's hosts.

    Hosts already in the fleet keep their pinned keys. Hosts absent from the
    file are removed. The API PUT does the same.
    """
    from hst.app import sources as glue
    from hst.app.store import DeviceSpec

    specs: list[DeviceSpec] = []
    for line_no, raw in enumerate(file.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host, _, port = line.partition(",")
        if port and not port.strip().isdigit():
            console.print(f"[red]line {line_no}: port {port.strip()!r} is not a number[/red]")
            raise typer.Exit(1)
        specs.append(DeviceSpec(host.strip(), port=int(port) if port.strip() else None))

    async def go(store):
        row = await store.get_source(source)
        if row is None:
            console.print(f"[red]no source {source!r}[/red]")
            raise typer.Exit(1)
        if not glue.is_group(row.type):
            console.print(f"[red]source type {row.type!r} does not take a device list[/red]")
            raise typer.Exit(1)
        try:
            from hst.app.inventory.legacy import LegacyConnections, active

            if await active(store):
                rows = await LegacyConnections(store, Settings()).replace_devices(source, specs)
            else:
                rows = await store.replace_devices(source, specs)
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        console.print(f"[green]{source} now has {len(rows)} devices[/green]")

    _with_store(go)


@devices_app.command("unpin")
def devices_unpin(source: str, host: str) -> None:
    """Clear one device's pinned SSH host key so the next connection re-pins."""

    async def go(store):
        if await store.clear_device_host_key(source, host):
            console.print(f"[green]unpinned[/green] {source}/{host}: the next connection re-pins")
        else:
            console.print("nothing pinned (or no such device)")

    _with_store(go)


device_app = typer.Typer(help="The device identity registry: the uid of each device.")
app.add_typer(device_app, name="device")


@device_app.command("rekey")
def device_rekey(
    old_uid: str,
    new_uid: str,
    merge: Annotated[
        bool,
        typer.Option(
            "--merge",
            help="move the identifiers into a uid that another device has, for a replaced chassis",
        ),
    ] = False,
) -> None:
    """Give a device a new uid. The next run writes the new uid."""
    from hst.core.identity import valid_uid

    if not valid_uid(new_uid):
        console.print(
            f"{new_uid!r} is not a device uid: write dev:<name>, with the name in lower case "
            "letters, digits, '.', '_' and '-'",
            markup=False,
        )
        raise typer.Exit(2)

    async def go(store):
        try:
            moved = await store.rekey_device(old_uid, new_uid, merge=merge)
        except (LookupError, ValueError) as exc:
            console.print(str(exc), markup=False)
            raise typer.Exit(1) from exc
        noun = "identifier" if moved == 1 else "identifiers"
        console.print(f"{old_uid} is now {new_uid} ({moved} {noun}).", markup=False, soft_wrap=True)
        console.print("The next run writes the new uid.")

    _with_store(go)


def _check_username(username: str) -> None:
    """Exit 1 when `username` is outside the bounds of the login form."""
    from hst.app.security import MAX_USERNAME_LENGTH

    if not 1 <= len(username) <= MAX_USERNAME_LENGTH:
        console.print(f"[red]username must have 1 to {MAX_USERNAME_LENGTH} characters[/red]")
        raise typer.Exit(1)


def _check_password(password: str, name: str = "password") -> None:
    """Exit 1 when `password` is outside the bounds of the login form."""
    from hst.app.routes.setup import MIN_PASSWORD_LENGTH
    from hst.app.security import MAX_PASSWORD_LENGTH

    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        console.print(
            f"[red]{name} must have {MIN_PASSWORD_LENGTH} to {MAX_PASSWORD_LENGTH} characters[/red]"
        )
        raise typer.Exit(1)


def _prompt_password() -> str:
    from hst.app.security import hash_password

    pw = typer.prompt("password", hide_input=True, confirmation_prompt=True)
    _check_password(pw)
    return hash_password(pw)


ADMIN_PASSWORD_ENV = "HST_ADMIN_PASSWORD"  # noqa: S105 - an environment variable name


@user_app.command("create-admin")
def user_create_admin(
    username: Annotated[str, typer.Option("--username", help="Account name. Prompts if omitted.")] = "",
    if_not_exists: Annotated[
        bool,
        typer.Option(
            "--if-not-exists",
            help="Exit 0 without changing anything when an admin already exists.",
        ),
    ] = False,
) -> None:
    """Bootstrap the first admin account.

    The command is interactive by default.

    For an automated deploy, pass --username and put the password in the
    HST_ADMIN_PASSWORD environment variable. No command-line option takes the password.
    With --if-not-exists the command does not change an existing account.
    """
    from hst.app.routes.setup import MIN_PASSWORD_LENGTH
    from hst.app.security import MAX_PASSWORD_LENGTH, hash_password

    env_password = os.environ.get(ADMIN_PASSWORD_ENV, "")
    non_interactive = bool(env_password)

    if non_interactive:
        if not username:
            console.print(f"[red]--username is required when {ADMIN_PASSWORD_ENV} is set[/red]")
            raise typer.Exit(2)
        _check_username(username)
        if not MIN_PASSWORD_LENGTH <= len(env_password) <= MAX_PASSWORD_LENGTH:
            console.print(
                f"[red]{ADMIN_PASSWORD_ENV} must have {MIN_PASSWORD_LENGTH} to "
                f"{MAX_PASSWORD_LENGTH} characters[/red]"
            )
            raise typer.Exit(2)
        pw_hash = hash_password(env_password)
    else:
        username = username or typer.prompt("username")
        _check_username(username)
        pw_hash = _prompt_password()

    async def go(store):
        if if_not_exists:
            existing = [u for u in await store.list_users() if u.role == "admin"]
            if existing:
                console.print(
                    f"admin already exists ({', '.join(u.username for u in existing)}); leaving it alone"
                )
                return
        try:
            u = await store.create_user(username, pw_hash, "admin")
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        console.print(f"[green]admin {u.username} created[/green]")

    _with_store(go)


@user_app.command("add")
def user_add(
    username: str, role: Annotated[str, typer.Option(help="viewer/operator/admin")] = "viewer"
) -> None:
    """Add an account (prompts for the password)."""
    from hst.app.store import ROLES

    if role not in ROLES:
        console.print(f"[red]role must be one of {', '.join(ROLES)}[/red]")
        raise typer.Exit(1)
    _check_username(username)
    pw_hash = _prompt_password()

    async def go(store):
        try:
            u = await store.create_user(username, pw_hash, role)
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1) from exc
        console.print(f"[green]{u.role} {u.username} created[/green]")

    _with_store(go)


def _patch_by_name(username: str, **changes) -> None:
    async def go(store):
        u = await store.get_user_by_username(username)
        if u is None:
            console.print(f"[red]no user {username!r}[/red]")
            raise typer.Exit(1)
        await store.update_user(u.id, **changes)
        console.print(f"[green]ok[/green] {username}")

    _with_store(go)


@user_app.command("role")
def user_role(username: str, role: str) -> None:
    """Change an account's role."""
    from hst.app.store import ROLES

    if role not in ROLES:
        console.print(f"[red]role must be one of {', '.join(ROLES)}[/red]")
        raise typer.Exit(1)
    _patch_by_name(username, role=role)


@user_app.command("disable")
def user_disable(username: str) -> None:
    """Disable an account (sessions stop working immediately)."""
    _patch_by_name(username, disabled=True)


@user_app.command("enable")
def user_enable(username: str) -> None:
    """Re-enable an account."""
    _patch_by_name(username, disabled=False)


@user_app.command("reset-password")
def user_reset_password(username: str) -> None:
    """Set a new password for an account."""
    _patch_by_name(username, password_hash=_prompt_password())


@user_app.command("enable-local-login")
def user_enable_local_login() -> None:
    """Turn local login on."""
    from hst.app import sso_flow

    async def go(store):
        await store.put_setting(sso_flow.LOCAL_LOGIN_KEY, {"enabled": True}, b"")
        console.print("[green]local login is on[/green]")

    _with_store(go)


assessments_app = typer.Typer(help="Inspect, export and replay recorded assessments.", no_args_is_help=True)
app.add_typer(assessments_app, name="assessments")


def _assessment_store_read(settings: Settings, callback, *, hold_lock: bool = True):
    """Use configured local database access without applying migrations.

    The callback runs holding the blocking cycle lock, unless `hold_lock` is
    false for a callback that takes the lock itself. The prune functions take
    the lock without waiting, on a connection of their own.
    """
    import asyncio

    from hst.app.store.pg import PgStore

    async def run():
        store = PgStore(settings.postgres_dsn, settings.postgres_ca_file)
        try:
            if not hold_lock:
                return await callback(store)
            async with store.cycle_lock():
                return await callback(store)
        finally:
            await store.dispose()

    return asyncio.run(run())


@assessments_app.command("jobs")
def assessments_jobs(
    assessment_id: Annotated[
        str | None, typer.Option("--assessment", help="Filter by saved assessment.")
    ] = None,
    limit: Annotated[
        int, typer.Option(min=1, max=1000, help="Maximum number of recent analysis jobs.")
    ] = 100,
) -> None:
    """Inspect analysis progress and immutable result references, excluding worker lease capabilities."""
    import json

    async def inspect_jobs(store):
        values = []
        for run in await store.list_analysis_runs(assessment_id, limit=limit):
            value = run.as_dict()
            for field in ("lease_token", "claimed_by", "checkpoint"):
                value.pop(field, None)
            values.append(value)
        return {"jobs": values, "limit": limit}

    try:
        typer.echo(json.dumps(_assessment_store_read(Settings(), inspect_jobs), sort_keys=True))
    except (OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@assessments_app.command("job")
def assessments_job(run_id: str) -> None:
    """Read one durable analysis job by its stable identifier."""
    import json

    async def inspect_job(store):
        run = await store.get_analysis_run(run_id)
        if run is None:
            raise ValueError("Analysis job not found.")
        value = run.as_dict()
        for field in ("lease_token", "claimed_by", "checkpoint"):
            value.pop(field, None)
        return value

    try:
        typer.echo(json.dumps(_assessment_store_read(Settings(), inspect_job), sort_keys=True))
    except (OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@assessments_app.command("export")
def assessments_export(
    run_id: str,
    output: Annotated[
        Path, typer.Option("--output", help="New private output file; existing files are refused.")
    ],
    portable: Annotated[
        bool, typer.Option(help="Include encrypted graph, manifest chain and evidence bytes.")
    ] = False,
    package_key_file: Annotated[
        Path | None,
        typer.Option(help="New private file for the key of the portable package"),
    ] = None,
) -> None:
    """Export an exact recorded run using configured database access, without a new evaluation."""
    import asyncio
    import json

    from hst.app.crypto import SecretKeyError
    from hst.assessment.package import PackageError, build_portable, export_document

    if package_key_file is not None and not portable:
        typer.echo("--package-key-file is only used with --portable.", err=True)
        raise typer.Exit(1)
    settings = Settings()

    async def export_run(store):
        run = await store.get_analysis_run(run_id)
        if run is None:
            raise PackageError("Assessment run not found.")
        if portable:
            return await asyncio.to_thread(build_portable, settings, run, output, key_file=package_key_file)
        document = export_document(run)
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            json.dump(document, file, sort_keys=True, indent=2)
        return {"path": str(output), "sha256": document["sha256"]}

    try:
        result = _assessment_store_read(settings, export_run)
    except (OSError, ValueError, SecretKeyError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(result, sort_keys=True))


@assessments_app.command("package-key")
def assessments_package_key(
    file: Path,
    output: Annotated[Path, typer.Option("--output", help="New private file for the package key")],
) -> None:
    """Write the key of a portable package that this deployment exported."""
    from hst.app.crypto import SecretKeyError
    from hst.assessment.package import package_key

    try:
        key = package_key(Settings(), file)
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            stream.write(key + "\n")
    except (OSError, ValueError, SecretKeyError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc


@assessments_app.command("check")
def assessments_check(file: Path) -> None:
    """Check package integrity and evidence closure without graph access or secret keys."""
    import json

    from hst.assessment.package import check_package

    try:
        result = check_package(file)
    except (OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(result, sort_keys=True))


@assessments_app.command("replay")
def assessments_replay(
    file: Path,
    into: Annotated[
        str | None, typer.Option(help="Explicit empty, non-live Neo4j target for portable restore.")
    ] = None,
    package_key_file: Annotated[
        Path | None, typer.Option(help="File that holds the key of the portable package")
    ] = None,
) -> None:
    """Rerun exact inputs against retained evidence, or restore into an explicit empty target."""
    import json

    from hst.assessment.package import replay_package

    try:
        result = replay_package(Settings(), file, into=into, package_key_file=package_key_file)
    except (OSError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc
    typer.echo(json.dumps(result, sort_keys=True))
    if not result.get("available") or not result.get("matches"):
        raise typer.Exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
