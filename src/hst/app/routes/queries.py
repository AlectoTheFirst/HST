"""The canned-query catalog and its runner. Only declared params reach Cypher."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from hst.app.auth import require_permission
from hst.app.routes.explore import products_present
from hst.app.tables import run_readonly
from hst.queries import catalog

router = APIRouter()


class RunBody(BaseModel):
    params: dict[str, str] = {}


@router.get("/queries", dependencies=[Depends(require_permission("graph.read"))])
def list_catalog(request: Request) -> dict:
    """The catalog for the pinned run. An entry keyed on a vendor product is
    left out when the run holds no data for it. When presence is not known,
    every entry is listed and `products` is left out."""
    present = products_present(request)
    entries = []
    for entry in catalog():
        product = entry.pop("requires", None)
        if present is not None and product is not None and product not in present:
            continue
        entries.append(entry)
    body: dict = {"queries": entries}
    if present is not None:
        body["products"] = sorted(present)
    return body


@router.post("/queries/{key}", dependencies=[Depends(require_permission("graph.read"))])
def run_canned(request: Request, key: str, body: RunBody | None = None) -> dict:
    q = next((q for q in catalog() if q["key"] == key), None)
    if q is None:
        raise HTTPException(404, detail=f"no query {key!r}")
    declared = {p["name"] for p in q.get("params", [])}
    # An optional param that is left out binds "". For the device filter, "" matches any device.
    optional = {p["name"] for p in q.get("params", []) if p.get("optional")}
    given = {**dict.fromkeys(optional, ""), **(body.params if body else {})}
    # A required param that is absent or blank is missing. The detail names it
    # by the label that the form shows.
    labels = {p["name"]: p.get("label") or p["name"] for p in q.get("params", [])}
    missing = {
        name
        for name in declared - optional
        if name not in given or (isinstance(given[name], str) and not given[name].strip())
    }
    if missing:
        raise HTTPException(400, detail=f"missing params: {', '.join(sorted(labels[n] for n in missing))}")
    # Only the declared params come from the caller.
    return run_readonly(
        request.app.state.settings,
        q["cypher"],
        {k: v for k, v in given.items() if k in declared},
        trusted=True,
        graph=True,
    )
