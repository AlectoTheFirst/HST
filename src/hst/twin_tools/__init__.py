"""The tool catalogue, declared once for every surface.

Each domain module declares its tools as registry specs (`hst.app.ai.registry`)
whose output model is the envelope of `envelope.py`, and whose `snapshot`
argument is the selector of `selectors.py`. `catalogue_registry` holds the
read tools of the snapshot, inventory, routing, policy, NAT, load balancer,
path, impact, change, application, assessment, evidence, operations and query
domains, in catalogue order. `write_registry` holds the four write tools. They
are offered only to a personal access token with scope `read-write`.

The modules import no web framework at import time. A tool body that reuses a
route helper imports it inside the function that needs it.
"""

from __future__ import annotations

from hst.app.ai.registry import ToolRegistry


def catalogue_registry() -> ToolRegistry:
    """A registry of the catalogue tools."""
    from hst.twin_tools import (
        apps,
        assessment,
        change,
        evidence,
        impact,
        inventory,
        lb,
        nat,
        ops,
        policy,
        query,
        reach,
        routing,
        snapshot,
    )

    registry = ToolRegistry()
    snapshot.register(registry)
    inventory.register(registry)
    routing.register(registry)
    policy.register(registry)
    nat.register(registry)
    lb.register(registry)
    reach.register(registry)
    impact.register(registry)
    change.register(registry)
    apps.register(registry)
    assessment.register(registry)
    evidence.register(registry)
    ops.register(registry)
    query.register(registry)
    return registry


def write_registry() -> ToolRegistry:
    """A registry of the write tools:
    `change_submit_simulation`, `app_save_application`,
    `assessment_submit_run` and `assessment_cancel_run`."""
    from hst.twin_tools import write

    registry = ToolRegistry()
    write.register(registry)
    return registry
