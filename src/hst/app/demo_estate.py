"""Load the synthetic Norlund estate (fixtures/demo-enterprise) as a `demo` run.

On an instance with `HST_DEMO_FIXTURES` set to the folder, an admin starts the load from the Runs
page (POST /api/runs with source `demo`). The run does 3 steps in order:

1. creates the sites of `sites.yaml` that do not exist, with the code POST /api/sites uses
   (`routes.sites.create_site_row`), and gives a created site the named blocks `sites.yaml` lists
   for it (the site parameter `blocks`). An existing site without named blocks gets the blocks
   that `sites.yaml` lists for it. Any other existing site is unchanged.
2. loads estate-v1, v2 and v3 as three published runs, each from empty as
   `hst load-fixture --new-run` loads them, with the map projection, under the cycle lock
   (`runs_exec.execute_demo`).
3. imports the applications of `apps/*.yaml` with the service the application import uses, in
   merge mode, and resolves each at the last of the three runs. An import that changes nothing
   writes no new revision. The resolution at the new run is saved in both cases.

A second load on a loaded instance publishes three new runs and leaves the sites and the
application revisions as they are. Without the setting, the source does not exist.
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from hst.core import Settings

DEMO = "demo"
RUN_FILES = ("estate-v1.yaml", "estate-v2.yaml", "estate-v3.yaml")
SITES_FILE = "sites.yaml"
APPS_DIR = "apps"
# The permissions of the writes of a demo load.
PERMISSIONS = frozenset({"runs.manage", "sites.write", "changes.write", "sources.write"})


class DemoEstateError(ValueError):
    """The demo estate folder is missing a file or holds one that does not parse."""


@dataclass(frozen=True)
class DemoSite:
    code: str
    name: str
    location: str
    lat: float
    lon: float
    # `blocks` holds the site parameter `blocks` in the shape that the site contract stores.
    blocks: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class DemoEstate:
    runs: tuple[Path, ...]
    sites: tuple[DemoSite, ...]
    apps: tuple[tuple[str, str], ...]


def folder(settings: Settings | None) -> Path | None:
    """The demo estate folder this instance is configured with, None on any other instance and
    for a caller with no settings."""
    found: Path | None = getattr(settings, "hst_demo_fixtures", None)
    return found


def allowed(role: str) -> bool:
    from hst.app.permissions import permissions_for

    return permissions_for(role) >= PERMISSIONS


def read(root: Path) -> DemoEstate:
    """The run files, the sites and the application documents of the estate in `root`."""
    runs = tuple(root / name for name in RUN_FILES)
    missing = [p.name for p in runs if not p.is_file()]
    if not (root / SITES_FILE).is_file():
        missing.append(SITES_FILE)
    apps_dir = root / APPS_DIR
    app_files = sorted(apps_dir.glob("*.yaml")) if apps_dir.is_dir() else []
    if not app_files:
        missing.append(f"{APPS_DIR}/*.yaml")
    if missing:
        raise DemoEstateError(f"the demo estate folder {root} has no {', '.join(missing)}")
    try:
        entries = yaml.safe_load((root / SITES_FILE).read_text(encoding="utf-8"))["sites"]
        sites = tuple(
            DemoSite(
                code=str(e["code"]),
                name=str(e["name"]),
                location=str(e["location"]),
                lat=float(e["lat"]),
                lon=float(e["lon"]),
                blocks=_blocks(e.get("blocks")),
            )
            for e in entries
        )
    except (yaml.YAMLError, KeyError, TypeError, ValueError) as exc:
        raise DemoEstateError(f"{SITES_FILE}: {exc}") from None
    apps = tuple((p.name, p.read_text(encoding="utf-8")) for p in app_files)
    return DemoEstate(runs=runs, sites=sites, apps=apps)


def _blocks(value: Any) -> tuple[dict[str, Any], ...]:
    """The `blocks` of one site entry, validated by the rules of the site contract
    (`inventory.site_params.SiteBlocks`) and in the shape it stores."""
    from pydantic import TypeAdapter

    from hst.app.inventory.site_params import SiteBlocks

    adapter: TypeAdapter[Any] = TypeAdapter(SiteBlocks)
    return tuple(adapter.dump_python(adapter.validate_python(value)) or ())


def _with_blocks(blocks: Sequence[dict[str, Any]]) -> Callable[[dict], dict]:
    """The `change_params` of `Store.update_site` that adds `blocks` to params
    that hold no blocks."""

    def change(params: dict) -> dict:
        if params.get("blocks"):
            return params
        return {**params, "blocks": [dict(b) for b in blocks]}

    return change


async def seed_sites(store: Any, settings: Settings, sites: Sequence[DemoSite], actor_id: int | None) -> str:
    """Create each site that does not exist, and give a site that exists and has no
    named blocks the blocks `sites.yaml` lists for it. Returns the summary line of the run detail."""
    from hst.app.inventory.observations import InventoryContext
    from hst.app.routes import sites as site_routes

    ctx_of = functools.cache(lambda: InventoryContext(store, settings))
    have = await site_routes.site_codes(store, ctx_of)
    created = 0
    blocked = 0
    for site in sites:
        if site.code in have:
            if site.blocks:
                current = await store.get_site(site.code)
                if not (getattr(current, "params", None) or {}).get("blocks"):
                    await store.update_site(site.code, change_params=_with_blocks(site.blocks))
                    blocked += 1
            continue
        body = site_routes.SiteBody(
            code=site.code,
            name=site.name,
            location=site.location,
            params=site_routes.SiteParams(lat=site.lat, lon=site.lon),
        )
        await site_routes.create_site_row(store, ctx_of, body, actor_id)
        if site.blocks:
            # The create shape has no blocks. A site update writes the blocks and keeps the
            # other params of the new site.
            await store.update_site(site.code, change_params=_with_blocks(site.blocks))
        created += 1
    line = f"sites: {created} created, {len(sites) - created} already present"
    return f"{line} ({blocked} given their named blocks)" if blocked else line


async def import_applications(
    store: Any, settings: Settings, apps: Sequence[tuple[str, str]], snapshot: int, actor_id: int | None
) -> str:
    """Import each application in merge mode and resolve its revision at run `snapshot`.

    Each revision is resolved here, as POST /api/business-applications/{id}/resolve does. A file
    that fails is named in the summary line and the other files are imported."""
    if not hasattr(store, "get_application"):
        return "applications: not imported, the store has no application storage"
    from hst.app.routes.business_applications import _resolve_graph
    from hst.applications import service as application_service
    from hst.applications.models import RemovalSet
    from hst.assessment import service as assessment_service

    reference = await asyncio.to_thread(assessment_service.snapshot_reference, settings, str(snapshot))
    imported = 0
    new_revisions = 0
    resolved = 0
    failed: list[str] = []
    for name, text in apps:
        try:
            preview = await application_service.preview_import(store, text, RemovalSet(), "merge")
            origin = await application_service.revision_origin(store, "import", actor=actor_id)
            saved = await application_service.commit_import(
                store,
                text,
                RemovalSet(),
                base_revision=preview.base_revision,
                base_digest=preview.base_digest,
                preview_digest=preview.preview_digest,
                actor=actor_id,
                mode="merge",
                origin=origin,
            )
            imported += 1
            if saved.revision != preview.base_revision:
                new_revisions += 1
            result = await asyncio.to_thread(
                _resolve_graph, settings, saved.definition, saved.revision, reference, [], []
            )
            await store.save_application_resolution(result)
            resolved += 1
        except Exception as exc:
            failed.append(f"{name}: {type(exc).__name__}: {exc}")
    line = (
        f"applications: {imported} imported ({new_revisions} new revisions), "
        f"{resolved} resolved at run {snapshot}"
    )
    return line + (f"; failed: {'; '.join(failed)}" if failed else "")
