"""The site address lookup, a prefix search over the offline place table
(app/geo_places.py). It reads Postgres only and makes no external request."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from hst.app.auth import require_permission
from hst.app.geo_places import MAX_RESULTS, parse_query

router = APIRouter()


@router.get("/geo-places", dependencies=[Depends(require_permission("graph.read"))])
async def search_geo_places(
    request: Request,
    q: str = Query("", max_length=200),
    limit: int = Query(10, ge=1, le=MAX_RESULTS),
) -> dict[str, Any]:
    """Places whose name or postal code starts with the typed text. A result
    without `postal_code` stands for every postal code of that place."""
    store = request.app.state.store
    query = parse_query(q)
    result = await store.search_geo_places(query.name if query else "", query.postal if query else "", limit)
    return {
        "items": [
            {
                "country_code": p.country_code,
                "postal_code": p.postal_code,
                "name": p.name,
                "admin1": p.admin1,
                "admin2": p.admin2,
                "lat": round(p.lat, 5),
                "lon": round(p.lon, 5),
            }
            for p in result.items
        ],
        "available": result.available,
    }
