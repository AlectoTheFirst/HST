"""Authorization matrix: every /api route x every role, expected allow/deny."""

from __future__ import annotations

from typing import Any

import pytest
from tests.app.conftest import PASSWORD, login

from hst.app.store import ROLES

USERNAME_FOR_ROLE = {"viewer": "vera", "operator": "otto", "admin": "ada"}

# (method, OpenAPI path template, minimal role required, request kwargs).
# "any" means every authenticated role passes: no permission gate
# (login/logout/me/liveness/setup), or the route's permission is held by
# every role (agent.ask). Path params are filled with a value that never
# exists, so an allowed call hits a 404/409 and does not change fixture
# state.
ROUTES: list[tuple[str, str, str, dict[str, Any]]] = [
    ("GET", "/api/assessment-options", "viewer", {"url": "/api/assessment-options"}),
    (
        "POST",
        "/api/assessment-assistant/drafts",
        "viewer",
        {"url": "/api/assessment-assistant/drafts", "json": {}},
    ),
    (
        "GET",
        "/api/assessment-assistant/drafts/{job_id}",
        "viewer",
        {"url": "/api/assessment-assistant/drafts/missing"},
    ),
    (
        "POST",
        "/api/assessments/{identifier}/runs/{run_id}/proposals",
        "operator",
        {"url": "/api/assessments/missing/runs/missing/proposals", "json": {}},
    ),
    ("GET", "/api/change-revisions/{identifier}", "viewer", {"url": "/api/change-revisions/missing"}),
    (
        "GET",
        "/api/change-revisions/{identifier}/revisions",
        "viewer",
        {"url": "/api/change-revisions/missing/revisions"},
    ),
    (
        "PATCH",
        "/api/change-revisions/{identifier}",
        "operator",
        {"url": "/api/change-revisions/missing", "json": {}},
    ),
    (
        "GET",
        "/api/assessments/{identifier}/retention",
        "viewer",
        {"url": "/api/assessments/missing/retention"},
    ),
    (
        "PUT",
        "/api/assessments/{identifier}/retention",
        "admin",
        {"url": "/api/assessments/missing/retention", "json": {}},
    ),
    (
        "GET",
        "/api/assessments/{identifier}/runs/{run_id}/replay-status",
        "viewer",
        {"url": "/api/assessments/missing/runs/missing/replay-status"},
    ),
    ("GET", "/api/assessment-capabilities", "viewer", {"url": "/api/assessment-capabilities"}),
    ("GET", "/api/requirements", "viewer", {"url": "/api/requirements"}),
    ("POST", "/api/requirements", "operator", {"url": "/api/requirements", "json": {}}),
    ("GET", "/api/requirements/{identifier}", "viewer", {"url": "/api/requirements/missing"}),
    ("PATCH", "/api/requirements/{identifier}", "operator", {"url": "/api/requirements/missing", "json": {}}),
    ("GET", "/api/business-applications", "viewer", {"url": "/api/business-applications"}),
    (
        "POST",
        "/api/business-applications",
        "operator",
        {"url": "/api/business-applications", "json": {}},
    ),
    (
        "POST",
        "/api/business-applications/import/preview",
        "operator",
        {"url": "/api/business-applications/import/preview", "json": {}},
    ),
    (
        "POST",
        "/api/business-applications/import/commit",
        "operator",
        {"url": "/api/business-applications/import/commit", "json": {}},
    ),
    (
        "GET",
        "/api/business-applications/{application_id}",
        "viewer",
        {"url": "/api/business-applications/missing"},
    ),
    (
        "PUT",
        "/api/business-applications/{application_id}",
        "operator",
        {"url": "/api/business-applications/missing", "json": {}},
    ),
    (
        "GET",
        "/api/business-applications/{application_id}/history",
        "viewer",
        {"url": "/api/business-applications/missing/history"},
    ),
    (
        "GET",
        "/api/business-applications/{application_id}/export",
        "viewer",
        {"url": "/api/business-applications/missing/export"},
    ),
    (
        "POST",
        "/api/business-applications/{application_id}/resolve",
        "operator",
        {"url": "/api/business-applications/missing/resolve", "json": {}},
    ),
    (
        "GET",
        "/api/business-applications/{application_id}/graph",
        "viewer",
        {"url": "/api/business-applications/missing/graph", "params": {"snapshot": "100"}},
    ),
    (
        "GET",
        "/api/business-applications/{application_id}/flows",
        "viewer",
        {"url": "/api/business-applications/missing/flows", "params": {"snapshot": "100"}},
    ),
    (
        "POST",
        "/api/business-applications/validate",
        "viewer",
        {"url": "/api/business-applications/validate", "json": {}},
    ),
    (
        "GET",
        "/api/business-applications/affected",
        "viewer",
        {"url": "/api/business-applications/affected", "params": {"inventory_uid": "missing"}},
    ),
    # the generation routes: graph.read and agent.ask, and the record to its owner
    (
        "POST",
        "/api/business-applications/generations",
        "viewer",
        {"url": "/api/business-applications/generations", "json": {}},
    ),
    (
        "GET",
        "/api/business-applications/generations/{generation_id}",
        "viewer",
        {"url": "/api/business-applications/generations/missing"},
    ),
    ("POST", "/api/ai/service-drafts", "viewer", {"json": {}}),
    (
        "GET",
        "/api/analysis-snapshot",
        "viewer",
        {"url": "/api/analysis-snapshot", "params": {"snapshot": "100"}},
    ),
    ("GET", "/api/analysis-sessions", "viewer", {"url": "/api/analysis-sessions"}),
    (
        "POST",
        "/api/analysis-sessions",
        "operator",
        {"url": "/api/analysis-sessions", "json": {}},
    ),
    (
        "GET",
        "/api/analysis-sessions/{session_id}",
        "viewer",
        {"url": "/api/analysis-sessions/missing"},
    ),
    (
        "GET",
        "/api/analysis-sessions/{session_id}/history",
        "viewer",
        {"url": "/api/analysis-sessions/missing/history"},
    ),
    (
        "POST",
        "/api/analysis-sessions/{session_id}/execute",
        "operator",
        {
            "url": "/api/analysis-sessions/missing/execute",
            "json": {"session_revision": 1, "input_digest": "a" * 64},
        },
    ),
    (
        "POST",
        "/api/analysis-sessions/{session_id}/runs",
        "operator",
        {
            "url": "/api/analysis-sessions/missing/runs",
            "json": {"session_revision": 1, "input_digest": "a" * 64},
        },
    ),
    (
        "GET",
        "/api/analysis-sessions/{session_id}/runs/{run_id}",
        "viewer",
        {"url": "/api/analysis-sessions/missing/runs/missing"},
    ),
    (
        "GET",
        "/api/analysis-sessions/{session_id}/runs/{run_id}/export",
        "viewer",
        {"url": "/api/analysis-sessions/missing/runs/missing/export"},
    ),
    (
        "GET",
        "/api/analysis-sessions/{session_id}/export",
        "viewer",
        {"url": "/api/analysis-sessions/missing/export"},
    ),
    ("GET", "/api/assessments", "viewer", {"url": "/api/assessments"}),
    ("POST", "/api/assessments", "operator", {"url": "/api/assessments", "json": {}}),
    ("GET", "/api/assessments/{identifier}", "viewer", {"url": "/api/assessments/missing"}),
    ("PATCH", "/api/assessments/{identifier}", "operator", {"url": "/api/assessments/missing", "json": {}}),
    (
        "POST",
        "/api/assessments/{identifier}/analyses",
        "operator",
        {"url": "/api/assessments/missing/analyses", "json": {}},
    ),
    (
        "POST",
        "/api/assessments/{identifier}/evaluations",
        "operator",
        {"url": "/api/assessments/missing/evaluations", "json": {}},
    ),
    ("GET", "/api/analysis-jobs/{identifier}", "viewer", {"url": "/api/analysis-jobs/missing"}),
    (
        "GET",
        "/api/assessments/{identifier}/runs/{run_id}/buckets",
        "viewer",
        {"url": "/api/assessments/missing/runs/missing/buckets", "params": {"bucket": "invalid"}},
    ),
    (
        "POST",
        "/api/analysis-jobs/{identifier}/cancel",
        "operator",
        {"url": "/api/analysis-jobs/missing/cancel", "json": {}},
    ),
    (
        "POST",
        "/api/assessments/{identifier}/deployments",
        "operator",
        {"url": "/api/assessments/missing/deployments", "json": {}},
    ),
    (
        "POST",
        "/api/assessments/{identifier}/collection-actions",
        "operator",
        {"url": "/api/assessments/missing/collection-actions", "json": {}},
    ),
    (
        "GET",
        "/api/assessments/{identifier}/runs/{run_id}/export",
        "viewer",
        {"url": "/api/assessments/missing/runs/missing/export"},
    ),
    ("POST", "/api/login", "any", {"json": {"username": "ghost", "password": PASSWORD}}),
    ("POST", "/api/logout", "any", {}),
    ("GET", "/api/me", "any", {}),
    ("PATCH", "/api/me", "any", {"json": {"theme": "dark"}}),
    ("GET", "/api/livez", "any", {}),
    ("GET", "/api/readyz", "any", {}),
    ("GET", "/api/analysis/readyz", "viewer", {}),
    ("GET", "/api/setup", "any", {}),
    ("POST", "/api/setup", "any", {"json": {"username": "nope", "password": "x" * 12}}),
    ("GET", "/api/health", "viewer", {}),
    ("GET", "/api/path", "viewer", {}),
    ("GET", "/api/path/vrfs", "viewer", {}),
    ("GET", "/api/mtu/audit", "viewer", {"params": {"scope": "invalid"}}),
    # no `device` query param: an allowed role gets 422 before any backend read
    ("GET", "/api/impact", "viewer", {}),
    # no `link` query param: an allowed role gets 422 before any backend read
    ("GET", "/api/impact/link", "viewer", {}),
    # `intents` is a list: a string is a 422 before any backend read
    ("POST", "/api/impact/evaluate", "viewer", {"json": {"intents": "not-a-list"}}),
    # the unified map's view model: _no_backend stubs its session seam
    ("GET", "/api/topology", "viewer", {}),
    # no `bd` query param: an allowed role gets 422 before any backend read
    ("GET", "/api/topology/segment", "viewer", {}),
    # the filtered endpoint list: _no_backend stubs its session seam
    ("GET", "/api/endpoints", "viewer", {}),
    # the read-only GraphQL endpoint: the typename query reads nothing
    ("POST", "/api/graphql", "viewer", {"json": {"query": "{ __typename }"}}),
    # the network map's shared layouts and views: reads as the drawing, writes as sites.write
    ("GET", "/api/network-map/layouts/{scope}", "viewer", {"url": "/api/network-map/layouts/site/missing"}),
    (
        "PUT",
        "/api/network-map/layouts/{scope}",
        "operator",
        {"url": "/api/network-map/layouts/site/missing", "json": {}},
    ),
    (
        "DELETE",
        "/api/network-map/layouts/{scope}",
        "operator",
        {"url": "/api/network-map/layouts/site/missing?expected_revision=1"},
    ),
    ("GET", "/api/network-map/views", "viewer", {"url": "/api/network-map/views"}),
    ("POST", "/api/network-map/views", "operator", {"url": "/api/network-map/views", "json": {}}),
    (
        "PATCH",
        "/api/network-map/views/{view_id}",
        "operator",
        {"url": "/api/network-map/views/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    (
        "DELETE",
        "/api/network-map/views/{view_id}",
        "operator",
        {"url": "/api/network-map/views/00000000-0000-0000-0000-000000000001?expected_revision=1"},
    ),
    # the edge picker: _no_backend stubs its session seam
    ("GET", "/api/sdwan/edges", "viewer", {}),
    # no `edge` query param: an allowed role gets 422 before any backend read
    ("GET", "/api/sdwan/topology", "viewer", {}),
    # the metro picker: _no_backend stubs its session seam
    ("GET", "/api/equinix/metros", "viewer", {}),
    # no `metro` query param: an allowed role gets 422 before any backend read
    ("GET", "/api/equinix/metro", "viewer", {}),
    # the HST map reads: the side store and the markers, which the app's data dir may lack
    ("GET", "/api/hst/timeline", "viewer", {}),
    ("GET", "/api/hst/tier", "viewer", {"url": "/api/hst/tier?name=render_t1&snapshot=1"}),
    ("GET", "/api/hst/delta", "viewer", {"url": "/api/hst/delta?name=render_t1&snapshot=1"}),
    ("GET", "/api/hst/layout", "viewer", {"url": "/api/hst/layout?snapshot=1"}),
    ("GET", "/api/hst/layout-delta", "viewer", {"url": "/api/hst/layout-delta?snapshot=1"}),
    ("GET", "/api/hst/device", "viewer", {"url": "/api/hst/device?uid=dev:x&snapshot=1"}),
    ("GET", "/api/hst/segment", "viewer", {"url": "/api/hst/segment?uid=dev:x/segment/1&snapshot=1"}),
    # no `uid` query param: an allowed role gets 422 before any read
    ("GET", "/api/hst/interface", "viewer", {}),
    ("GET", "/api/hst/interface-text", "operator", {}),
    ("GET", "/api/hst/device-text", "operator", {}),
    # an over-long Last-Event-ID is a 422 for an allowed role, before the endless stream starts
    ("GET", "/api/hst/events", "viewer", {"headers": {"Last-Event-ID": "9" * 65}}),
    # both served from the run listing; _no_backend stubs their session seam
    ("GET", "/api/snapshots", "viewer", {}),
    ("GET", "/api/diff", "viewer", {}),
    # no `at` query param: an allowed role gets 422 before any backend read
    ("GET", "/api/snapshots/resolve", "viewer", {}),
    # A rebuild deletes every node of its target and sends the graph credentials
    # to it, so its permission is `graph.purge`. An empty body names no target,
    # which is a 400 before the source rows or the target database are touched.
    (
        "POST",
        "/api/snapshots/{key}/rebuild",
        "admin",
        {"url": "/api/snapshots/999999/rebuild", "json": {}},
    ),
    ("GET", "/api/queries", "viewer", {}),
    ("POST", "/api/queries/{key}", "viewer", {"url": "/api/queries/no-such-key", "json": {}}),
    ("POST", "/api/cypher", "operator", {"json": {"query": "RETURN 1"}}),
    ("GET", "/api/explore/stats", "viewer", {}),
    ("GET", "/api/explore/labels/{label}", "viewer", {"url": "/api/explore/labels/NoSuchLabel"}),
    ("GET", "/api/explore/search", "viewer", {}),
    ("GET", "/api/explore/node", "viewer", {}),
    ("GET", "/api/explore/neighbors", "viewer", {}),
    ("GET", "/api/explore/values", "viewer", {}),
    ("GET", "/api/explore/device-names", "viewer", {}),
    ("GET", "/api/explore/device-identity", "viewer", {}),
    # no `q` query param: an allowed role gets 422 before any backend read
    ("GET", "/api/explore/route-search", "viewer", {}),
    ("GET", "/api/explore/routes", "viewer", {}),
    ("POST", "/api/runs", "operator", {"json": {}}),
    ("GET", "/api/runs", "operator", {}),
    ("POST", "/api/runs/{run_id}/cancel", "operator", {"url": "/api/runs/999999/cancel"}),
    # the HTTP exchange traces of traced fetches, under the gate of the runs
    ("GET", "/api/runs/http-traces", "operator", {}),
    (
        "GET",
        "/api/runs/http-traces/{run_id}",
        "operator",
        {"url": "/api/runs/http-traces/1790000000000-abcdef12?source=none"},
    ),
    # collection debug capture, the re-parse and the switch, under the gate of the traces
    ("GET", "/api/debug-capture", "operator", {}),
    (
        "PUT",
        "/api/debug-capture/sources/{name}",
        "operator",
        {"url": "/api/debug-capture/sources/none", "json": {"enabled": False}},
    ),
    ("GET", "/api/debug-capture/payloads", "operator", {"url": "/api/debug-capture/payloads?source=none"}),
    ("POST", "/api/debug-capture/reparse", "operator", {"json": {}}),
    (
        "GET",
        "/api/debug-capture/bundle",
        "operator",
        {"url": "/api/debug-capture/bundle?source=none&run_id=1790000000000-abcdef12"},
    ),
    ("GET", "/api/runs/{run_id}/debug-bundle", "operator", {"url": "/api/runs/999999/debug-bundle"}),
    # the maintenance queue's history, under the operator-and-above gate of /api/runs
    ("GET", "/api/jobs", "operator", {}),
    ("POST", "/api/graph/purge", "admin", {}),
    ("GET", "/api/users", "admin", {}),
    ("POST", "/api/users", "admin", {"json": {}}),
    ("PATCH", "/api/users/{user_id}", "admin", {"url": "/api/users/999999", "json": {}}),
    ("DELETE", "/api/users/{user_id}/sessions", "admin", {"url": "/api/users/999999/sessions"}),
    ("GET", "/api/users/{user_id}/access-tokens", "admin", {"url": "/api/users/999999/access-tokens"}),
    (
        "DELETE",
        "/api/users/{user_id}/access-tokens/{token_id}",
        "admin",
        {"url": "/api/users/999999/access-tokens/1"},
    ),
    ("GET", "/api/source-types", "operator", {}),
    ("GET", "/api/sources", "operator", {}),
    ("POST", "/api/sources", "admin", {"json": {}}),
    ("PATCH", "/api/sources/{name}", "admin", {"url": "/api/sources/no-such-source", "json": {}}),
    ("DELETE", "/api/sources/{name}", "admin", {"url": "/api/sources/no-such-source"}),
    ("POST", "/api/sources/{name}/test", "operator", {"url": "/api/sources/no-such-source/test"}),
    ("GET", "/api/sources/{name}/devices", "operator", {"url": "/api/sources/no-such-source/devices"}),
    (
        "PUT",
        "/api/sources/{name}/devices",
        "admin",
        {"url": "/api/sources/no-such-source/devices", "json": {"devices": []}},
    ),
    (
        "POST",
        "/api/sources/{name}/devices/{host}/test",
        "operator",
        {"url": "/api/sources/no-such-source/devices/h/test"},
    ),
    ("GET", "/api/sources/{name}/effective", "viewer", {"url": "/api/sources/missing/effective"}),
    ("GET", "/api/locations", "viewer", {}),
    (
        "PATCH",
        "/api/locations/{source}/{location_id}",
        "operator",
        {"url": "/api/locations/missing/loc-1", "json": {}},
    ),
    ("GET", "/api/settings/ai/providers", "admin", {}),
    ("GET", "/api/settings/ai", "admin", {}),
    ("PUT", "/api/settings/ai", "admin", {"json": {}}),
    ("POST", "/api/settings/ai/test", "admin", {"json": {}}),
    ("GET", "/api/settings/ai/events", "admin", {}),
    # the MCP HTTP transport switch; an empty body is 422 and changes nothing
    ("GET", "/api/settings/mcp", "admin", {}),
    ("PUT", "/api/settings/mcp", "admin", {"json": {}}),
    # personal access tokens: issuing needs agent.ask, which every role holds;
    # listing and revoking need a session. An empty body is 422.
    ("GET", "/api/access-tokens", "any", {}),
    ("POST", "/api/access-tokens", "any", {"json": {}}),
    ("DELETE", "/api/access-tokens/{token_id}", "any", {"url": "/api/access-tokens/999999"}),
    ("GET", "/api/auth/providers", "any", {}),
    ("GET", "/api/auth/{name}/login", "any", {"url": "/api/auth/no-such-provider/login"}),
    ("GET", "/api/auth/{name}/callback", "any", {"url": "/api/auth/no-such-provider/callback"}),
    (
        "POST",
        "/api/auth/{name}/acs",
        "any",
        {"url": "/api/auth/no-such-provider/acs", "data": {"SAMLResponse": "x"}},
    ),
    ("GET", "/api/auth/{name}/metadata", "any", {"url": "/api/auth/no-such-provider/metadata"}),
    ("GET", "/api/settings/retention", "admin", {}),
    ("PATCH", "/api/settings/retention", "admin", {"json": {}}),
    ("GET", "/api/settings/auth/events", "admin", {}),
    ("GET", "/api/settings/auth", "admin", {}),
    ("PUT", "/api/settings/auth", "admin", {"json": {}}),
    ("GET", "/api/settings/auth/providers", "admin", {}),
    ("POST", "/api/settings/auth/providers", "admin", {"json": {}}),
    (
        "PATCH",
        "/api/settings/auth/providers/{name}",
        "admin",
        {"url": "/api/settings/auth/providers/no-such-provider", "json": {}},
    ),
    (
        "DELETE",
        "/api/settings/auth/providers/{name}",
        "admin",
        {"url": "/api/settings/auth/providers/no-such-provider"},
    ),
    (
        "POST",
        "/api/settings/auth/providers/{name}/test",
        "admin",
        {"url": "/api/settings/auth/providers/no-such-provider/test"},
    ),
    (
        "GET",
        "/api/settings/auth/providers/{name}/mappings",
        "admin",
        {"url": "/api/settings/auth/providers/no-such-provider/mappings"},
    ),
    (
        "POST",
        "/api/settings/auth/providers/{name}/mappings",
        "admin",
        {"url": "/api/settings/auth/providers/no-such-provider/mappings", "json": {}},
    ),
    (
        "DELETE",
        "/api/settings/auth/providers/{name}/mappings/{group_name}",
        "admin",
        {"url": "/api/settings/auth/providers/no-such-provider/mappings/no-such-group"},
    ),
    ("POST", "/api/agent/ask", "any", {"json": {}}),
    ("GET", "/api/agent/ask/{job_id}", "any", {"url": "/api/agent/ask/no-such-job"}),
    # the conversation routes: agent.ask, or ownership of the named row
    ("POST", "/api/ai/conversations", "any", {"json": {}}),
    ("GET", "/api/ai/conversations", "any", {}),
    ("GET", "/api/ai/conversations/{conversation_id}", "any", {"url": "/api/ai/conversations/missing"}),
    ("DELETE", "/api/ai/conversations/{conversation_id}", "any", {"url": "/api/ai/conversations/missing"}),
    (
        "POST",
        "/api/ai/conversations/{conversation_id}/messages",
        "any",
        {"url": "/api/ai/conversations/missing/messages", "json": {}},
    ),
    ("GET", "/api/ai/messages/{message_id}", "any", {"url": "/api/ai/messages/missing"}),
    ("GET", "/api/ai/messages/{message_id}/events", "any", {"url": "/api/ai/messages/missing/events"}),
    ("POST", "/api/ai/messages/{message_id}/cancel", "any", {"url": "/api/ai/messages/missing/cancel"}),
    ("GET", "/api/ai/steps/{step_id}", "any", {"url": "/api/ai/steps/missing"}),
    # the handoffs of a stored step: the draft to the step's owner, the saved
    # session under changes.write
    (
        "GET",
        "/api/ai/steps/{step_id}/assessment-draft",
        "any",
        {"url": "/api/ai/steps/missing/assessment-draft"},
    ),
    (
        "POST",
        "/api/ai/steps/{step_id}/analysis-session",
        "operator",
        {"url": "/api/ai/steps/missing/analysis-session"},
    ),
    ("GET", "/api/sites", "viewer", {}),
    ("GET", "/api/geo-places", "viewer", {"url": "/api/geo-places?q=fra"}),
    ("POST", "/api/sites", "operator", {"json": {}}),
    ("PATCH", "/api/sites/{code}", "operator", {"url": "/api/sites/no-such-code", "json": {}}),
    ("DELETE", "/api/sites/{code}", "operator", {"url": "/api/sites/no-such-code"}),
    ("GET", "/api/sites/{code}/devices", "viewer", {"url": "/api/sites/no-such-code/devices"}),
    ("GET", "/api/sites/devices", "viewer", {}),
    ("POST", "/api/sites/assign", "operator", {"json": {}}),
    ("POST", "/api/sites/trace", "viewer", {"json": {}}),
    # the site map: _no_backend stubs its session seam
    ("GET", "/api/sites/graph", "viewer", {}),
    ("GET", "/api/changes", "viewer", {}),
    ("POST", "/api/changes", "operator", {"json": {}}),
    ("GET", "/api/changes/{change_id}", "viewer", {"url": "/api/changes/999999"}),
    ("PATCH", "/api/changes/{change_id}", "operator", {"url": "/api/changes/999999", "json": {}}),
    ("DELETE", "/api/changes/{change_id}", "operator", {"url": "/api/changes/999999"}),
    # the change-simulation download: the same graph.read gate simulate_policy_change
    # carries. An empty body is 422 before any backend read.
    ("POST", "/api/changesim/export", "viewer", {"json": {}}),
]


# Inventory capabilities, including the activation boundary on an unconfigured store.
ROUTES += [
    ("GET", "/api/inventory/devices", "viewer", {"url": "/api/inventory/devices"}),
    (
        "GET",
        "/api/inventory/devices/{device_id}",
        "viewer",
        {"url": "/api/inventory/devices/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "GET",
        "/api/inventory/devices/{device_id}/history",
        "viewer",
        {"url": "/api/inventory/devices/00000000-0000-0000-0000-000000000001/history"},
    ),
    (
        "GET",
        "/api/inventory/devices/{device_id}/routing",
        "viewer",
        {"url": "/api/inventory/devices/00000000-0000-0000-0000-000000000001/routing"},
    ),
    (
        "PATCH",
        "/api/inventory/devices/{device_id}/placement",
        "operator",
        {"url": "/api/inventory/devices/00000000-0000-0000-0000-000000000001/placement", "json": {}},
    ),
    (
        "PATCH",
        "/api/inventory/devices/{device_id}/lifecycle",
        "operator",
        {"url": "/api/inventory/devices/00000000-0000-0000-0000-000000000001/lifecycle", "json": {}},
    ),
    (
        "POST",
        "/api/inventory/devices/{device_id}/collect",
        "operator",
        {"url": "/api/inventory/devices/00000000-0000-0000-0000-000000000001/collect", "json": {}},
    ),
    ("GET", "/api/inventory/connections", "operator", {"url": "/api/inventory/connections"}),
    ("POST", "/api/inventory/connections", "admin", {"url": "/api/inventory/connections", "json": {}}),
    (
        "GET",
        "/api/inventory/connections/{connection_id}",
        "operator",
        {"url": "/api/inventory/connections/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "PATCH",
        "/api/inventory/connections/{connection_id}",
        "admin",
        {"url": "/api/inventory/connections/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    (
        "DELETE",
        "/api/inventory/connections/{connection_id}",
        "admin",
        {"url": "/api/inventory/connections/00000000-0000-0000-0000-000000000001"},
    ),
    ("GET", "/api/inventory/targets", "operator", {"url": "/api/inventory/targets"}),
    ("POST", "/api/inventory/targets", "admin", {"url": "/api/inventory/targets", "json": {}}),
    (
        "GET",
        "/api/inventory/targets/{target_id}",
        "operator",
        {"url": "/api/inventory/targets/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "PATCH",
        "/api/inventory/targets/{target_id}",
        "admin",
        {"url": "/api/inventory/targets/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    (
        "DELETE",
        "/api/inventory/targets/{target_id}",
        "admin",
        {"url": "/api/inventory/targets/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "GET",
        "/api/inventory/targets/{target_id}/effective",
        "operator",
        {"url": "/api/inventory/targets/00000000-0000-0000-0000-000000000001/effective"},
    ),
    (
        "POST",
        "/api/inventory/targets/{target_id}/probe",
        "operator",
        {"url": "/api/inventory/targets/00000000-0000-0000-0000-000000000001/probe", "json": {}},
    ),
    (
        "POST",
        "/api/inventory/targets/{target_id}/replace",
        "admin",
        {"url": "/api/inventory/targets/00000000-0000-0000-0000-000000000001/replace", "json": {}},
    ),
    ("GET", "/api/inventory/profiles", "admin", {"url": "/api/inventory/profiles"}),
    ("POST", "/api/inventory/profiles", "admin", {"url": "/api/inventory/profiles", "json": {}}),
    (
        "GET",
        "/api/inventory/profiles/{profile_id}",
        "admin",
        {"url": "/api/inventory/profiles/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "PATCH",
        "/api/inventory/profiles/{profile_id}",
        "admin",
        {"url": "/api/inventory/profiles/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    (
        "DELETE",
        "/api/inventory/profiles/{profile_id}",
        "admin",
        {"url": "/api/inventory/profiles/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "GET",
        "/api/inventory/profiles/{profile_id}/impact",
        "admin",
        {"url": "/api/inventory/profiles/00000000-0000-0000-0000-000000000001/impact"},
    ),
    (
        "GET",
        "/api/inventory/profiles/{profile_id}/versions",
        "admin",
        {"url": "/api/inventory/profiles/00000000-0000-0000-0000-000000000001/versions"},
    ),
    ("GET", "/api/inventory/credentials", "admin", {"url": "/api/inventory/credentials"}),
    ("POST", "/api/inventory/credentials", "admin", {"url": "/api/inventory/credentials", "json": {}}),
    (
        "GET",
        "/api/inventory/credentials/{credential_id}",
        "admin",
        {"url": "/api/inventory/credentials/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "PATCH",
        "/api/inventory/credentials/{credential_id}",
        "admin",
        {"url": "/api/inventory/credentials/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    (
        "DELETE",
        "/api/inventory/credentials/{credential_id}",
        "admin",
        {"url": "/api/inventory/credentials/00000000-0000-0000-0000-000000000001"},
    ),
    ("GET", "/api/inventory/sites", "viewer", {"url": "/api/inventory/sites"}),
    ("POST", "/api/inventory/sites", "operator", {"url": "/api/inventory/sites", "json": {}}),
    ("GET", "/api/inventory/sites/search", "viewer", {"url": "/api/inventory/sites/search"}),
    ("POST", "/api/inventory/sites/import", "operator", {"url": "/api/inventory/sites/import", "json": {}}),
    (
        "GET",
        "/api/inventory/sites/{site_id}",
        "viewer",
        {"url": "/api/inventory/sites/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "PATCH",
        "/api/inventory/sites/{site_id}",
        "operator",
        {"url": "/api/inventory/sites/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    (
        "DELETE",
        "/api/inventory/sites/{site_id}",
        "operator",
        {"url": "/api/inventory/sites/00000000-0000-0000-0000-000000000001"},
    ),
    ("GET", "/api/inventory/views", "viewer", {"url": "/api/inventory/views"}),
    ("POST", "/api/inventory/views", "viewer", {"url": "/api/inventory/views", "json": {}}),
    (
        "GET",
        "/api/inventory/views/{view_id}",
        "viewer",
        {"url": "/api/inventory/views/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "PATCH",
        "/api/inventory/views/{view_id}",
        "viewer",
        {"url": "/api/inventory/views/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    (
        "DELETE",
        "/api/inventory/views/{view_id}",
        "viewer",
        {"url": "/api/inventory/views/00000000-0000-0000-0000-000000000001"},
    ),
    ("GET", "/api/inventory/routing-groups", "viewer", {"url": "/api/inventory/routing-groups"}),
    ("POST", "/api/inventory/routing-groups", "admin", {"url": "/api/inventory/routing-groups", "json": {}}),
    (
        "GET",
        "/api/inventory/routing-groups/{group_id}",
        "viewer",
        {"url": "/api/inventory/routing-groups/00000000-0000-0000-0000-000000000001"},
    ),
    (
        "PATCH",
        "/api/inventory/routing-groups/{group_id}",
        "admin",
        {"url": "/api/inventory/routing-groups/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    (
        "DELETE",
        "/api/inventory/routing-groups/{group_id}",
        "admin",
        {"url": "/api/inventory/routing-groups/00000000-0000-0000-0000-000000000001"},
    ),
    ("GET", "/api/inventory/locations", "viewer", {"url": "/api/inventory/locations"}),
    ("GET", "/api/inventory/locations/search", "viewer", {"url": "/api/inventory/locations/search"}),
    (
        "POST",
        "/api/inventory/locations/bindings",
        "operator",
        {"url": "/api/inventory/locations/bindings", "json": {}},
    ),
    (
        "PATCH",
        "/api/inventory/locations/{handle}",
        "operator",
        {"url": "/api/inventory/locations/00000000-0000-0000-0000-000000000001", "json": {}},
    ),
    ("GET", "/api/inventory/field-metadata", "operator", {"url": "/api/inventory/field-metadata"}),
    ("GET", "/api/inventory/state", "viewer", {"url": "/api/inventory/state"}),
    (
        "POST",
        "/api/inventory/operations/preview",
        "viewer",
        {"url": "/api/inventory/operations/preview", "json": {}},
    ),
    (
        "POST",
        "/api/inventory/operations/apply",
        "viewer",
        {"url": "/api/inventory/operations/apply", "json": {}},
    ),
    (
        "GET",
        "/api/inventory/operations/previews/{token}/impact",
        "viewer",
        {"url": "/api/inventory/operations/previews/00000000-0000-0000-0000-000000000001/impact"},
    ),
]


class _FakeGraphSession:
    """Stands in for a Neo4j driver session: answers the purge count probe and
    records nothing, so an admin's allowed /api/graph/purge call completes
    without a real driver."""

    def __enter__(self) -> _FakeGraphSession:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def run(self, query: str, **params: Any) -> Any:
        class _Result:
            def single(_self) -> dict:
                return {"c": 0}

            def data(_self) -> list:
                return []

        return _Result()

    # the snapshots routes read through execute_read; the fake doubles as its
    # own transaction, so the empty run listing above answers them too
    def execute_read(self, work: Any, *args: Any) -> Any:
        return work(self, *args)


@pytest.fixture(autouse=True)
def _no_backend(monkeypatch):
    """Stubs the seams an allowed role's call would carry to a real Neo4j driver."""
    import hst.app.routes.cypher as cypher_route
    import hst.app.routes.endpoints as endpoints_route
    import hst.app.routes.equinix as equinix_route
    import hst.app.routes.explore as explore_route
    import hst.app.routes.health as health_route
    import hst.app.routes.runs as runs_route
    import hst.app.routes.sdwan as sdwan_route
    import hst.app.routes.site_graph as site_graph_route
    import hst.app.routes.sites as sites_route
    import hst.app.routes.snapshots as snapshots_route
    import hst.app.routes.topology as topology_route

    monkeypatch.setattr(
        cypher_route, "run_readonly", lambda *a, **k: {"columns": [], "data": [], "truncated": False}
    )
    monkeypatch.setattr(health_route, "_neo4j_ok", lambda settings: True)
    monkeypatch.setattr(explore_route, "_snap", lambda request: 1)
    monkeypatch.setattr(
        explore_route, "run_readonly", lambda *a, **k: {"columns": [], "data": [], "truncated": False}
    )
    monkeypatch.setattr(runs_route, "_session", lambda settings: _FakeGraphSession())
    monkeypatch.setattr(sdwan_route, "_session", lambda settings: _FakeGraphSession())
    monkeypatch.setattr(equinix_route, "_session", lambda settings: _FakeGraphSession())
    monkeypatch.setattr(sites_route, "_collected_devices", lambda request: [])
    monkeypatch.setattr(site_graph_route, "_session", lambda settings: _FakeGraphSession())
    monkeypatch.setattr(snapshots_route, "_session", lambda settings: _FakeGraphSession())
    monkeypatch.setattr(topology_route, "_session", lambda settings: _FakeGraphSession())
    monkeypatch.setattr(endpoints_route, "_session", lambda settings: _FakeGraphSession())


def _live_routes(app) -> set[tuple[str, str]]:
    schema = app.openapi()
    return {
        (method.upper(), path)
        for path, methods in schema["paths"].items()
        for method in methods
        if method.upper() != "OPTIONS"
    }


def test_every_route_is_in_the_matrix(app):
    known = {(method, path) for method, path, _, _ in ROUTES}
    assert _live_routes(app) == known


def _expected_allow(min_role: str, role: str) -> bool:
    if min_role == "any":
        return True
    return ROLES.index(role) >= ROLES.index(min_role)


@pytest.mark.parametrize("role", ROLES)
async def test_authorization_matrix(client, role):
    await login(client, USERNAME_FOR_ROLE[role])
    for method, path, min_role, kwargs in ROUTES:
        url = kwargs.get("url", path)
        request_kwargs = {k: v for k, v in kwargs.items() if k not in ("url",)}
        resp = await client.request(method, url, **request_kwargs)
        allow = _expected_allow(min_role, role)
        if allow:
            assert resp.status_code != 403, (
                f"{role} unexpectedly denied {method} {path}: {resp.status_code} {resp.text}"
            )
        else:
            assert resp.status_code == 403, (
                f"{role} unexpectedly allowed {method} {path}: {resp.status_code} {resp.text}"
            )
        # /api/logout kills the session; every route after it in this loop needs
        # one restored, or they would all read as 401 (not the case under test).
        if (method, path) == ("POST", "/api/logout"):
            await login(client, USERNAME_FOR_ROLE[role])
