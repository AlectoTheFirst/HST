"""The computed provider of the route-delta interface.

The route-delta interface has two providers and one output shape. The output is
the per-VRF RIB rows keyed by `context_uid`.

The entry point takes plain node dicts.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .errors import ErrorSink
from .propagate import RouteDelta, SimulationInput, run

NAME = "computed"


def compute_route_delta(
    *,
    processes: Sequence[Mapping[str, Any]],
    sessions: Sequence[Mapping[str, Any]],
    policies: Sequence[Mapping[str, Any]] = (),
    local_routes: Sequence[Mapping[str, Any]] = (),
    platform: str = "iosxe",
) -> RouteDelta:
    """Predict the per-VRF RIB from normalized BGP nodes.

    `platform` is the source kind of the collector. A process node without a
    `platform` property uses it. The platform selects the no-policy default and
    the route-map conversion shape.
    """
    return run(
        SimulationInput(
            processes=list(processes),
            sessions=list(sessions),
            policies=list(policies),
            local_routes=list(local_routes),
            platform=platform,
        ),
        ErrorSink(),
    )
