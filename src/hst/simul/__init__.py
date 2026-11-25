"""Route prediction from configuration, the stage 3 engine of change simulation.

The package does no I/O. It reads plain dicts in the shape of the schema nodes
(`RoutingProcess`, `BgpSession`, `RoutePolicy`, `RoutePolicyEntry`,
`PrefixListEntry`, `MatchListEntry`). It returns the RIB rows of each VRF, keyed by
`context_uid`, and a list of named model errors.
"""

from __future__ import annotations

from .errors import ErrorSink, ModelError
from .propagate import RouteDelta, SimulationInput, run
from .provider import compute_route_delta
from .route import Route

__all__ = [
    "ErrorSink",
    "ModelError",
    "Route",
    "RouteDelta",
    "SimulationInput",
    "compute_route_delta",
    "run",
]
