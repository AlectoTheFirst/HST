"""Optional-section reads shared by the ZIA and ZPA collectors.

An optional section is read with one or more calls. `SectionReads.read` makes
one call and keeps its rows. A refused call records its HTTP code and the path
for its section and gives no rows. The other calls of the same section keep
their rows. `SectionReads.errors()` is the `section_errors` entry of the raw
payload. `section_outcomes` builds the section outcomes from the payload.

- A section without a refused read has the status `ok` or `empty`, with `row_count`.
- A section with a refused read has the worst status of its refusals. `failed`
  ranks above `unauthorized`, and `unauthorized` ranks above `unsupported`.
- When 1 or more reads of the section answered, `row_count` is the number of
  rows kept, and `unsupported` becomes `partial`.
- A section whose every read was refused stores no `answered` count.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

import httpx

from hst.core.model import SectionOutcome, SectionStatus

# Higher is worse. The worst refusal of a section sets its status.
_RANK: dict[SectionStatus, int] = {"unsupported": 0, "unauthorized": 1, "failed": 2}


def section_status(http_status: int) -> SectionStatus:
    """Return the section status of a refused read.

    401 and 403 give `unauthorized`, 404 gives `unsupported`, and any other code
    gives `failed`."""
    if http_status in (401, 403):
        return "unauthorized"
    if http_status == 404:
        return "unsupported"
    return "failed"


class SectionReads:
    """The reads of one fetch, per optional section."""

    def __init__(self) -> None:
        self._refused: dict[str, list[tuple[int, str]]] = {}
        self._answered: dict[str, int] = {}

    def read(self, section: str, fetch: Callable[..., list[dict]], *args: Any) -> list[dict]:
        """Return the rows of `fetch(*args)` for `section`.

        A refused call records its code and path and returns no rows. A transport
        error records status 0 and returns no rows."""
        try:
            rows = fetch(*args)
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            self._refused.setdefault(section, []).append((code, f"HTTP {code} for {exc.request.url.path}"))
            return []
        except httpx.TransportError as exc:
            # A timeout or a connection error records status 0, and status 0 gives
            # `failed`. A token failure, a cancel and the 429 limit raise other
            # exception types and end the fetch.
            detail = f"{type(exc).__name__} for {exc.request.url.path}"
            self._refused.setdefault(section, []).append((0, detail))
            return []
        self._answered[section] = self._answered.get(section, 0) + 1
        return rows

    def errors(self) -> dict[str, dict[str, Any]]:
        """Return one entry for each section with a refused read.

        An entry holds the code of the worst refusal, the details of every refusal
        in read order, and the number of reads that answered when it is above 0."""
        out: dict[str, dict[str, Any]] = {}
        for section, refusals in self._refused.items():
            worst = refusals[0][0]
            for code, _detail in refusals[1:]:
                if _RANK[section_status(code)] > _RANK[section_status(worst)]:
                    worst = code
            entry: dict[str, Any] = {
                "status": worst,
                "detail": "; ".join(detail for _code, detail in refusals),
            }
            answered = self._answered.get(section, 0)
            if answered > 0:
                entry["answered"] = answered
            out[section] = entry
        return out


def section_outcomes(raw: dict[str, Any], sections: Iterable[str]) -> dict[str, SectionOutcome]:
    errors = raw.get("section_errors") or {}
    out: dict[str, SectionOutcome] = {}
    for section in sections:
        if section not in raw and section not in errors:
            continue
        error = errors.get(section)
        rows = len(raw.get(section) or [])
        if not error:
            out[section] = SectionOutcome(status="ok" if rows else "empty", row_count=rows)
            continue
        status = section_status(int(error.get("status") or 0))
        detail = str(error.get("detail") or "")
        if int(error.get("answered") or 0) > 0:
            out[section] = SectionOutcome(
                status="partial" if status == "unsupported" else status, detail=detail, row_count=rows
            )
        else:
            out[section] = SectionOutcome(status=status, detail=detail)
    return out
