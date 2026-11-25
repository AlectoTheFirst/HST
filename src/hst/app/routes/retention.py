"""Admin retention settings for graph history and the audit trail."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from hst.app import retention
from hst.app.auth import require_permission
from hst.app.store import AppSetting

router = APIRouter(prefix="/settings/retention")
require_settings_retention = require_permission("settings.retention")


class RetentionPatch(BaseModel):
    """A day count of 0 keeps everything."""

    cycle_keep_runs: int | None = Field(default=None, ge=1, le=retention.MAX_KEEP_RUNS)
    cycle_keep_device_runs: int | None = Field(default=None, ge=0, le=retention.MAX_KEEP_RUNS)
    login_event_retention_days: int | None = Field(default=None, ge=0, le=retention.MAX_RETENTION_DAYS)
    cypher_event_retention_days: int | None = Field(default=None, ge=0, le=retention.MAX_RETENTION_DAYS)
    job_history_retention_days: int | None = Field(default=None, ge=0, le=retention.MAX_RETENTION_DAYS)
    ai_conversation_retention_days: int | None = Field(default=None, ge=0, le=retention.MAX_RETENTION_DAYS)
    ai_step_result_days: int | None = Field(default=None, ge=0, le=retention.MAX_RETENTION_DAYS)
    ai_event_retention_days: int | None = Field(default=None, ge=0, le=retention.MAX_RETENTION_DAYS)


def _json(limits: retention.Retention, updated_at: Any) -> dict[str, Any]:
    return {
        "cycle_keep_runs": limits.cycle_keep_runs,
        "cycle_keep_device_runs": limits.cycle_keep_device_runs,
        "login_event_retention_days": limits.login_event_retention_days,
        "cypher_event_retention_days": limits.cypher_event_retention_days,
        "job_history_retention_days": limits.job_history_retention_days,
        "ai_conversation_retention_days": limits.ai_conversation_retention_days,
        "ai_step_result_days": limits.ai_step_result_days,
        "ai_event_retention_days": limits.ai_event_retention_days,
        # The value is None when nothing is stored.
        "updated_at": updated_at.isoformat() if updated_at else None,
    }


@router.get("")
async def get_retention(request: Request, admin=Depends(require_settings_retention)) -> dict[str, Any]:
    store, settings = request.app.state.store, request.app.state.settings
    row = await store.get_setting(retention.SETTINGS_KEY)
    return _json(retention.merged(row.value if row else None, settings), row.updated_at if row else None)


@router.patch("")
async def patch_retention(
    request: Request, body: RetentionPatch, admin=Depends(require_settings_retention)
) -> dict[str, Any]:
    store, settings = request.app.state.store, request.app.state.settings
    supplied = body.model_dump(exclude_none=True)

    def change(row: AppSetting | None) -> tuple[dict, bytes]:
        # A field left out stays unstored. The document holds no secret.
        return {**(row.value if row else {}), **supplied}, b""

    saved = cast(AppSetting, await store.modify_setting(retention.SETTINGS_KEY, change))
    return _json(retention.merged(saved.value, settings), saved.updated_at)
