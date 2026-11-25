"""The operator-declared delta, provider 1 of the route-delta interface."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

# The change intent catalog, split by stage.
from hst.simul.intents import (
    RIB_SHAPING_KINDS as RIB_SHAPING_KINDS,
)
from hst.simul.intents import (
    STAGE_2_KINDS as STAGE_2_KINDS,
)
from hst.simul.intents import (
    STAGE_3_KINDS as STAGE_3_KINDS,
)
from hst.simul.intents import STORED_KINDS
from hst.simul.propagate import RouteDelta

NAME = "declared"
INTENT_KINDS = STORED_KINDS

# The RIB row shape that `hst.simul.bestpath.rib_rows` fixes for every
# route-delta provider. The params of `route_delta.declared` hold rows in this
# shape. A field that the operator omits defaults to the value of a locally
# originated route.
_RIB_ROW_FIELDS = (
    "next_hop",
    "protocol",
    "metric",
    "local_pref",
    "med",
    "weight",
    "as_path",
    "origin",
    "origin_mechanism",
    "session_protocol",
    "admin",
    "communities",
    "originator_ip",
    "cluster_list",
    "tag",
)


def _static_route_row(params: Mapping[str, Any]) -> dict[str, Any]:
    """A `static_route.add` intent's row, as the operator declared it."""
    return {
        "context_uid": str(params["context_uid"]),
        "prefix": str(params["prefix"]),
        "next_hop": params.get("next_hop"),
        "protocol": "static",
        "metric": params.get("metric"),
        "local_pref": params.get("local_pref"),
        "med": params.get("med"),
        "weight": params.get("weight"),
        "as_path": list(params.get("as_path") or ()),
        "origin": params.get("origin"),
        "origin_mechanism": "static",
        "session_protocol": "static",
        "admin": params.get("admin", 1),
        "communities": sorted(params.get("communities") or ()),
        "originator_ip": params.get("originator_ip"),
        "cluster_list": list(params.get("cluster_list") or ()),
        "tag": params.get("tag"),
    }


def _declared_row(row: Mapping[str, Any]) -> dict[str, Any]:
    """One row of a `route_delta.declared` intent's `rows` list, filled out to the
    full RIB row shape. `protocol` defaults to 'declared'."""
    out: dict[str, Any] = {
        "context_uid": str(row["context_uid"]),
        "prefix": str(row["prefix"]),
    }
    for field in _RIB_ROW_FIELDS:
        out[field] = row.get(field)
    if out["protocol"] is None:
        out["protocol"] = "declared"
    out["as_path"] = list(out["as_path"] or ())
    out["communities"] = sorted(out["communities"] or ())
    out["cluster_list"] = list(out["cluster_list"] or ())
    return out


def compute_route_delta(intents: Sequence[Mapping[str, Any]]) -> RouteDelta:
    """Predict the per-VRF RIB from a change's stored intents.

    Every intent in `intents` is `{"kind": ..., "params": ...}`, the shape
    `app/routes/changes.py` stores and returns. `static_route.add` and
    `route_delta.declared` each contribute rows. `static_route.remove` contributes
    none. Every other kind is a named model error.
    """
    rib: list[dict[str, Any]] = []
    errors: list[dict[str, str | None]] = []

    def _error(kind: str, detail: str, subject: str | None) -> None:
        errors.append({"kind": kind, "detail": detail, "subject": subject})

    for intent in intents:
        kind = str(intent.get("kind"))
        params = intent.get("params") or {}

        if kind not in RIB_SHAPING_KINDS:
            _error(
                "declared-not-simulatable",
                f"provider 1 (the declared route-delta) cannot express intent kind {kind!r}",
                kind,
            )
        elif kind == "static_route.add":
            try:
                rib.append(_static_route_row(params))
            except KeyError as exc:
                _error(
                    "declared-missing-param",
                    f"static_route.add is missing required param {exc}",
                    kind,
                )
        elif kind == "static_route.remove":
            # Provider 1 has rows only for routes that are present.
            continue
        elif kind == "route_delta.declared":
            rows = params.get("rows")
            if not isinstance(rows, list) or not rows:
                _error(
                    "declared-empty-rows",
                    "route_delta.declared has no rows to predict",
                    kind,
                )
                continue
            for row in rows:
                try:
                    rib.append(_declared_row(row))
                except KeyError as exc:
                    _error(
                        "declared-missing-param",
                        f"a route_delta.declared row is missing required field {exc}",
                        kind,
                    )

    return RouteDelta(rib=rib, model_errors=errors)
