"""Named permissions and the mapping from a role to its permission set."""

from __future__ import annotations

PERMISSIONS = {
    "inventory.write",  # archive and restore inventory devices
    "graph.read",  # /api/path, /api/queries*, /api/sites (read) + trace + devices, /api/health
    "agent.ask",  # /api/agent/ask (tool list filtered per permission)
    "cypher.run",  # /api/cypher, the query_cypher tool
    "runs.manage",  # /api/runs, /api/sources (read/test)
    "interfaces.read",  # /api/hst/interface-text: the redacted show interface section
    "sites.write",  # /api/sites mutations + assign
    "changes.write",  # /api/changes mutations (reads are graph.read)
    "sources.write",  # /api/sources mutations, unredacted debug bundles
    "graph.purge",  # /api/graph/purge, /api/snapshots/{key}/rebuild
    "users.manage",  # /api/users*
    "settings.auth",  # /api/settings/auth*: providers and group mappings
    "settings.ai",  # /api/settings/ai*
    "settings.retention",  # /api/settings/retention (graph and audit-table keep intervals)
}

_VIEWER = {"graph.read", "agent.ask"}
_OPERATOR = _VIEWER | {
    "cypher.run",
    "runs.manage",
    "sites.write",
    "changes.write",
    "inventory.write",
    "interfaces.read",
}

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset(_VIEWER),
    "operator": frozenset(_OPERATOR),
    "admin": frozenset(PERMISSIONS),
}


def permissions_for(role: str) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())
