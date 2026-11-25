"""GET /api/mtu/audit returns the pages of the MTU audit at one pinned snapshot."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request

from hst import path
from hst.app.auth import require_permission
from hst.app.routes.path import _requested_run
from hst.app.routes.run_lease import reading
from hst.core import db
from hst.core import snapshot as snapshotmod
from hst.core.mtu_audit_read import AuditScope, audit_mtu

router = APIRouter()
_session = db.session


@router.get("/mtu/audit", dependencies=[Depends(require_permission("graph.read"))])
def get_mtu_audit(
    request: Request,
    scope: AuditScope = "link",
    subject_uid: str | None = None,
    snapshot: str | None = None,
    af: Literal[4, 6] = 4,
    limit: int = 50,
    cursor: str | None = None,
) -> dict:
    settings = request.app.state.settings
    try:
        with _session(settings) as session:
            snap = snapshotmod.resolve(session, settings, _requested_run(session, snapshot))
            with reading(request, session, snap):
                return audit_mtu(
                    path.pinned(session, snap),
                    scope=scope,
                    subject_uid=subject_uid,
                    af=af,
                    limit=limit,
                    cursor=cursor,
                ).model_dump()
    except ValueError as exc:
        raise HTTPException(400, detail=str(exc)) from exc
