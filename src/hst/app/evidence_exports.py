"""Record each download of decrypted evidence, a debug bundle or an HTTP trace.

Each download writes one log line and one `evidence_exports` row with the
account that asked. The log line is a WARNING for an unredacted bundle."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import Request

from hst.app.store import User

log = logging.getLogger("hst.app.evidence_exports")


async def record(
    request: Request,
    user: User,
    *,
    kind: str,
    raw_mode: str | None,
    source: str,
    host: str,
    run_id: str,
    payloads: int,
) -> bool:
    """Log the download and write its row. The result is False when the row
    could not be written. The log line is written in every case."""
    log.log(
        logging.WARNING if raw_mode == "full" else logging.INFO,
        "evidence export: user %s (id %s) kind %s raw %s source %s host %s run %s payloads %d",
        user.username,
        user.id,
        kind,
        raw_mode,
        source,
        host,
        run_id,
        payloads,
    )
    try:
        await request.app.state.store.record_evidence_export(
            user_id=user.id,
            username=user.username,
            kind=kind,
            raw_mode=raw_mode,
            source=source,
            host=host,
            run_id=run_id,
            payloads=payloads,
            at=datetime.now(UTC),
        )
    except Exception:
        log.warning(
            "evidence export: the row for user %s run %s was not written",
            user.username,
            run_id,
            exc_info=True,
        )
        return False
    return True
