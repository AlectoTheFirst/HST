"""Liveness of the two backends the app fronts."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Request, Response

from hst import __version__
from hst.app.auth import require_permission
from hst.core import Settings
from hst.core import db as dbmod

router = APIRouter()
log = logging.getLogger(__name__)


def _neo4j_ok(settings: Settings) -> bool:
    try:
        with dbmod.session(settings) as s:
            s.execute_read(lambda tx: tx.run("RETURN 1").consume())
        return True
    except Exception:
        log.warning("neo4j health probe failed", exc_info=True)
        return False


async def _agent_ready(request: Request) -> bool:
    """Whether Ask-agent is switched on and has the credentials it needs."""
    from hst.app.agent import registry
    from hst.app.crypto import SecretKeyError, decrypt_secrets, dek

    row = await request.app.state.store.get_setting(registry.SETTINGS_KEY)
    settings = registry.merged(row.value if row else None)
    if not settings["enabled"]:
        return False
    try:
        secrets = decrypt_secrets(dek(request.app.state.settings), row.secrets) if row and row.secrets else {}
    except SecretKeyError:
        return False
    return registry.is_configured(settings, secrets)


@router.get("/livez")
async def livez() -> dict:
    """Unauthenticated liveness for the container healthcheck."""
    return {"status": "ok"}


@router.get("/readyz")
async def readyz(request: Request, response: Response) -> dict:
    """Unauthenticated readiness. The pod is ready when the store answers and the
    inventory resolver version is compatible."""
    ok = await request.app.state.store.ping()
    if ok:
        from hst.app.inventory.runtime import compatible

        ok = await compatible(request.app.state.store)
    if not ok:
        response.status_code = 503
    return {"status": "ok" if ok else "unavailable"}


@router.get("/analysis/readyz", dependencies=[Depends(require_permission("graph.read"))])
async def analysis_readyz(request: Request, response: Response) -> dict:
    from dataclasses import asdict

    from hst.symbolic.backend import backend_identity

    settings = request.app.state.settings
    engine = getattr(settings, "analysis_engine", "legacy-v1")
    identity = await asyncio.to_thread(backend_identity) if engine == "symbolic-v2" else None
    ready = bool(settings.analysis_enabled) and (identity is None or identity.verified)
    if not ready:
        response.status_code = 503
    return {
        "status": "ready" if ready else "unavailable",
        "engine": engine,
        "backend": asdict(identity) if identity is not None else None,
        "limits": {"memory_mb": settings.analysis_memory_mb, "timeout_s": settings.analysis_timeout_s},
    }


@router.get("/health", dependencies=[Depends(require_permission("graph.read"))])
async def health(request: Request) -> dict:
    neo = await asyncio.to_thread(_neo4j_ok, request.app.state.settings)
    pg = await request.app.state.store.ping()
    settings = request.app.state.settings
    return {
        "path": True,
        "neo4j": neo,
        "postgres": pg,
        "agent": await _agent_ready(request),
        "version": __version__,
        "revision": settings.hst_build_revision,
    }
