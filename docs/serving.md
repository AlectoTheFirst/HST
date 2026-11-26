# Serving

## Entry

`hst serve` gives the result of `src/hst/app/main.py` `create_app` to uvicorn. The options `--host` and `--port` set the listen address. The defaults are `127.0.0.1` and `8787`.

`create_app` does these steps in this order.

1. `_install_middleware` adds the 3 middleware of the table below.
2. `_install_exception_handlers` adds the exception handlers.
3. `_include_routers` includes the routers of `src/hst/app/auth.py`, `src/hst/app/graphql` and `src/hst/app/routes` with the prefix `/api`.
4. `src/hst/app/inventory/runtime.py` `register` includes the inventory routers.
5. Each route without a tag gets the last part of the module name of its function as the tag, with a space for each underscore.
6. `create_app` includes the router of `src/hst/app/api_docs.py` with the prefix `/api`.
7. `_mount_static` adds the routes of the web UI.

`_include_routers` includes the router of `src/hst/app/routes/hst.py` only if the package `pyarrow` is installed. It includes `src/hst/app/routes/application_generator.py` before `src/hst/app/routes/business_applications.py`. `src/hst/app/routes/mcp_http.py` `install` adds the MCP HTTP transport as 1 route outside the OpenAPI schema.

A request goes through the middleware in this order.

| Order | Middleware | Function |
|---|---|---|
| 1 | `src/hst/app/main.py` `SecurityHeaders` | adds `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options` and `Referrer-Policy` to each response |
| 2 | `src/hst/app/body_limit.py` `BodyLimit` | answers 413 to a request body above the setting `HST_MAX_REQUEST_BODY_MB`, default 16 MiB |
| 3 | `src/hst/app/main.py` `csrf_guard` | answers 403 to a `POST`, `PUT`, `PATCH` or `DELETE` request without the header `X-HST-CSRF: 1` |

`SecurityHeaders` also adds `Cache-Control: no-store` to a response for a path below `/api`. It adds `Strict-Transport-Security` to a response for an HTTPS request.

`src/hst/app/main.py` `_csrf_exempt` lets 2 requests through without the CSRF header:

- a `POST` to the SAML route `POST /api/auth/{name}/acs`
- a `POST` to the MCP HTTP transport with a bearer token

The exception handlers give each fault of this table a JSON body with the key `error`.

| Exception | Status | Value of `error` |
|---|---|---|
| `src/hst/app/crypto.py` `SecretKeyError` | 500 | the text of `src/hst/app/crypto.py` `GUIDANCE` |
| `neo4j.exceptions.ServiceUnavailable` | 502 | `twin unreachable` |
| `src/hst/core/snapshot.py` `NoRun` | 404 | `no run is published yet` |
| `RequestValidationError` | 422 | the place and the message of the first fault |
| `HTTPException` with a text in `detail` | the status of the exception | the text of `detail` |
| each other exception | 500 | `internal error`, with 12 hex digits in the key `request_id` |

`src/hst/app/main.py` `_make_lifespan` builds the lifespan of the app. If `create_app` gets no store, the lifespan opens one with `src/hst/worker/runtime.py` `open_store`. `_start_workers` starts the scheduler and the executor if the setting `SCHEDULER_ENABLED` is true. [Code flow of a collection](collection-code-flow.md#worker) describes these 2 loops.

### Web UI

`_mount_static` reads the directory of the setting `WEB_DIST`. The default is `web/dist`. If the directory holds no `index.html`, the function adds no route.

| Path | Answer |
|---|---|
| `/assets` | a file of `<WEB_DIST>/assets`, with `Cache-Control: public, max-age=31536000, immutable` |
| `/favicon.svg` | the file `<WEB_DIST>/favicon.svg`, if it exists |
| `/THIRD-PARTY-LICENSES.txt` | the file `<WEB_DIST>/THIRD-PARTY-LICENSES.txt`, if it exists |
| each other path that is not below `api` | `index.html`, with `Cache-Control: no-cache` |

### API reference

`create_app` turns off the documentation routes of FastAPI with `docs_url`, `redoc_url` and `openapi_url`. `src/hst/app/api_docs.py` has 4 routes, and each one needs a session.

| Route | Answer |
|---|---|
| `GET /api/docs` | the Swagger UI page |
| `GET /api/docs-init.js` | the script that starts Swagger UI and adds the CSRF header to each request |
| `GET /api/docs-assets/{filename}` | `swagger-ui.css` or `swagger-ui-bundle.js` from `<WEB_DIST>/swagger-ui`, or 503 if the file does not exist |
| `GET /api/openapi.json` | the result of `app.openapi()` |

## Authentication and permission

### Session cookie

`POST /api/login` calls `src/hst/app/auth.py` `login`. After a successful login, `issue_session` makes a token with `src/hst/app/security.py` `new_session_token`. The store keeps the SHA-256 digest of the token in a session row. The response sets the token in the cookie `hst_session`.

| Property of the cookie | Value |
|---|---|
| `Max-Age` | the setting `SESSION_TTL_HOURS`, default 168 hours |
| `HttpOnly` | on |
| `SameSite` | `lax` |
| `Secure` | on for an HTTPS request, or if the setting `COOKIE_SECURE` is true |

`src/hst/app/auth.py` `current_user` reads the cookie and gets the user from `src/hst/app/store/pg.py` `PgStore.get_session_user`. It answers 401 without a cookie, for an expired session and for a disabled user. A session also expires after the setting `SESSION_IDLE_TIMEOUT_HOURS` without a use. The default is 8 hours.

`login` takes 1 unit for each login request in 3 buckets of `src/hst/app/security.py` `RateLimiter`. If a bucket is full, the route answers 429. A successful login gives the 3 units back.

| Bucket | Limit in 1 window |
|---|---|
| user and client address | the setting `LOGIN_RATE_LIMIT`, default 5 |
| client address | the setting `LOGIN_RATE_LIMIT` |
| user | 10 times the setting `LOGIN_RATE_LIMIT` |

The setting `LOGIN_RATE_WINDOW_S` sets the window. The default is 60 seconds.

### Personal access token

`POST /api/access-tokens` makes a token and needs the permission `agent.ask`. The store keeps the SHA-256 digest of the token. A token has the scope `read` or `read-write` and a lifetime of 1 to 90 days. A user can have a maximum of 20 tokens.

2 entries accept the token in the header `Authorization: Bearer <token>`:

- `src/hst/app/graphql/context.py` `authenticate` for the GraphQL route. Without the header, it uses the session cookie.
- `src/hst/app/routes/mcp_http.py` `McpHttpEndpoint` for the MCP HTTP transport. The user of the token needs the permission `agent.ask`.

`current_user` does not read the header. Each other route with authentication needs the session cookie.

### Roles and permissions

`src/hst/app/permissions.py` `ROLE_PERMISSIONS` gives the permissions of the 3 roles. `permissions_for` returns the permissions of 1 role.

| Role | Permissions |
|---|---|
| `viewer` | `graph.read`, `agent.ask` |
| `operator` | the permissions of `viewer`, and `cypher.run`, `runs.manage`, `sites.write`, `changes.write`, `inventory.write`, `interfaces.read` |
| `admin` | the permissions of `operator`, and `sources.write`, `graph.purge`, `users.manage`, `settings.auth`, `settings.ai`, `settings.retention` |

`src/hst/app/auth.py` `require_permission` returns a dependency for 1 permission. The dependency calls `current_user` and answers 403 if the role of the user does not have the permission. A route declares its check in 1 of these 6 forms.

| Form | Check | Example |
|---|---|---|
| `dependencies=[Depends(require_permission("graph.read"))]` in the route decorator or in the `APIRouter` call | the permission | `src/hst/app/routes/path.py` `get_path`, the router of `src/hst/app/routes/explore.py` |
| a parameter `user: User = Depends(...)` with a module constant | the permission, and the function gets the user | `src/hst/app/routes/cypher.py` `require_cypher_run` |
| `Depends(current_user)` on the function or on the router | a session | `src/hst/app/auth.py` `me`, the router of `src/hst/app/api_docs.py` |
| `Depends(require_inventory)` on the router of the inventory routes | the permission of the route in `src/hst/app/inventory/contracts.py` `ROUTE_PERMISSIONS` | `src/hst/app/inventory/runtime.py` `register` |
| the context getter `src/hst/app/graphql/context.py` `graph_context`, which calls `authenticate` | a session or a personal access token | `POST /api/graphql` |
| no dependency | none | `POST /api/login`, `POST /api/logout`, `GET /api/livez`, `GET /api/readyz`, the routes of `src/hst/app/routes/setup.py` and `src/hst/app/routes/sso.py` |

`src/hst/app/inventory/runtime.py` `require_inventory` finds the permission by the method and the path of the route. A route without a row in `ROUTE_PERMISSIONS` needs `graph.read`. `GET /api/inventory/profiles/{profile_id}/versions` has no row and needs `sources.write`.

### Single sign-on

`src/hst/app/routes/sso.py` holds the login routes for OIDC and SAML 2.0. `src/hst/app/sso_flow.py` holds the OIDC code and `src/hst/app/saml_flow.py` holds the SAML code. A successful login calls `src/hst/app/auth.py` `issue_session` with the id of the provider.

## Pinned run and read guards

### Run selection

`src/hst/core/snapshot.py` `resolve` returns 1 `Snapshot` for a request. With a run key, the function uses that run. Without a run key, it reads the run pointer with `src/hst/core/cycle.py` `current_ts_or_none`. [Conventions](conventions.md#run-key-and-run-pointer) describes the run pointer. The run of the `Snapshot` is the pinned run of the request.

| Member of `Snapshot` | Content |
|---|---|
| `cts` | the run key, or `None` if the graph has no run pointer |
| `settings` | the `Settings` of the caller |
| `manifest` | the manifest of the run, read from disk 1 time. The value is `None` without a run key, without a manifest directory and for a manifest file that `src/hst/core/manifest.py` `read` cannot read |
| `approximate` | true if `manifest` is `None` |
| `snapshot_id` | the run key as a string, for a response |
| `evidence(key, build)` | the result of `build` for `key`, built 1 time for each `Snapshot` |
| `completeness()` | 1 `DeviceCompleteness` for each device of the manifest, with the key `<source>/<host>` |
| `device_completeness(source, host)` | the `DeviceCompleteness` of 1 device |

`src/hst/app/routes/path.py` `_requested_run` reads the run key from a request parameter. `src/hst/core/snapshot.py` `parse_snapshot_id` accepts ASCII digits with a maximum value of `2**63 - 1`. The route answers 400 for each other value that is not empty. `src/hst/core/snapshot.py` `require_retained` does a check for 1 `Obj` node with the run key. The route answers 404 if the graph has no such node.

These code paths set the query parameter `$snap`.

| Code | Value of `$snap` |
|---|---|
| `src/hst/path/session.py` `_read` | the parameter `snap` of the caller. Without it, the `cts` of the session, or `LIVE_SNAP` for a session without `cts` |
| `src/hst/app/tables.py` `run_readonly` | the parameter `snap` of the caller. Without it, the result of `src/hst/core/snapshot.py` `snap_param` for the run key of the run pointer |
| a caller that passes the parameter `snap` to the database session, such as `src/hst/app/routes/explore.py` `_snap` | the value of the caller. `_snap` returns the result of `snap_param` for the `cts` of its `Snapshot` |

For a `Snapshot` with a run key, `src/hst/path/session.py` `pinned` wraps a database session in a `CycleSession` that holds the `cts` and the `Snapshot`. For a `Snapshot` without a run key, it returns the database session. `src/hst/core/snapshot.py` `snap_param` returns `LIVE_SNAP` for a `cts` of `None`. `LIVE_SNAP` is the string `live`. No node has this value in `collection_ts`, and the guard `x.collection_ts = $snap` matches no node. `src/hst/path/trace.py` `_pinned_session` raises `NoRun` for a database session without a run.

`_read` runs each query in a read transaction with the timeout `READ_TIMEOUT_S`, 30 seconds. A `CycleSession` keeps the rows of each query by query text and parameters. `READ_CACHE_MAX` limits the cache to 4,096 entries.

### Guard forms

Each query holds its own guard. A query without a guard reads each run that the graph holds. The table gives the forms of a guard with `$snap`.

| Form | Place in the query | Example |
|---|---|---|
| `x.collection_ts = $snap` | the `WHERE` of a `MATCH`, for a node or a relationship | `src/hst/core/search.py` `DEVICE_NAMES`, `src/hst/app/routes/explore.py` `_pinned` |
| `{collection_ts: $snap}` | the pattern of a node | `src/hst/core/search.py` `EXACT_UID`, `src/hst/core/snapshot.py` `_RETAINED_GRAPH` |
| `{collection_ts: $snap}` | the pattern of a relationship | `src/hst/path/session.py` `GATEWAYS` |
| `(x:Meta OR x.collection_ts = $snap)` | the `WHERE` of a `MATCH` for a `Site` node | `src/hst/core/entity_read.py` `SITE_PAGE` |
| `((x:Meta AND x.collection_ts IS NULL) OR x.collection_ts = $snap)` | the `WHERE` of a `MATCH`, for a node that can be a `Meta` node without `collection_ts` | `src/hst/core/search.py` `GRAPH_PAGE`, `src/hst/app/routes/explore.py` `_at_run` |
| `(x.collection_ts = $snap OR x.collection_ts IS NULL)` | the `WHERE` of a `MATCH`, for a node or a relationship that can have no `collection_ts` | `src/hst/analysis_model/graph.py` `_run`, `src/hst/core/grapharchive.py` `_RELS` |
| `x.collection_ts IS NULL` | the `WHERE` of a `MATCH` for a node without `collection_ts`, in a query that also has form 1, 2 or 6 | `src/hst/app/routes/explore.py` `_of_label`, `src/hst/core/grapharchive.py` `_NODES` |

The page queries and the count queries of `src/hst/core/search.py` use form 5. These 6 files use form 4: `src/hst/core/entity_read.py`, `src/hst/app/routes/topology.py`, `src/hst/app/fw_overlay_read.py`, `src/hst/app/agent/traffic.py`, `src/hst/twin_tools/inventory.py` and `src/hst/demo.py`. The queries of `src/hst/core/loader.py`, `src/hst/reasoner` and `src/hst/map` use the parameter `$cts` for the run key.

A query also has the guard `NOT x:Retired` for a node and the guard `r._retired_at IS NULL` for a relationship. [Conventions](conventions.md#naming) describes the 2 marks.

`src/hst/app/tables.py` `is_pinned` does a check of the guards of 1 query text. `src/hst/twin_tools/query.py` `check_cypher` calls `src/hst/app/tables.py` `check_pinned` for the tool `query_cypher`. The setting `HST_AI_CYPHER_PINNING` sets the result for a query without a guard. The value `refuse` raises `QueryRejected`, and the value `warn` adds a warning to the result.

`is_pinned` accepts forms 1 to 4 and 2 more forms: `$snap = x.collection_ts` and `coalesce(x.collection_ts, $snap) = $snap`. No query in `src/hst` uses these 2 forms. `is_pinned` does not accept forms 5, 6 and 7.

### Lease

`src/hst/app/routes/run_lease.py` has 3 context managers that hold a lease on a run for a route.

| Context manager | Caller | Function |
|---|---|---|
| `leased` | a route on a worker thread | holds a lease on a list of run keys |
| `aleased` | a route on the event loop | holds a lease on a list of run keys |
| `reading` | a route on a worker thread | holds a lease on the run of 1 `Snapshot` and answers 409 for a pruned run |

Each one calls `src/hst/app/store/pg.py` `PgStore.lease_run`. The method writes 1 row for each run key to the table `run_leases` and deletes the rows at the end of the block. A row expires after `src/hst/app/store/pg.py` `RUN_LEASE_TTL_S`, 600 seconds. [Storage](storage.md#retention) describes the effect of a lease on the retention jobs.

`reading` reads the `CycleRun` node of the run with `src/hst/core/cycle.py` `run_present` before the lease. Inside the lease, it reads the node again before and after the block. If the node existed and does not exist in 1 of these 2 reads, the route answers 409.

### Read-only Cypher

`POST /api/cypher` calls `src/hst/app/routes/cypher.py` `run_cypher` and needs the permission `cypher.run`. The route answers 413 for a query text above `src/hst/app/tables.py` `MAX_QUERY_BYTES`, 64 KiB. It gives the query to `src/hst/app/tables.py` `run_readonly`.

`src/hst/app/tables.py` `check_readonly` decodes each Unicode escape of the query text. Then it raises `QueryRejected` in these 7 cases, and the route answers 400.

1. The first clause is `SHOW` or `TERMINATE`.
2. The query has a `USE` clause.
3. The query has `LOAD CSV`.
4. A string literal starts with 1 of the URL schemes `file`, `http`, `https`, `ftp` and `jar`.
5. The query calls a procedure that is not in `ALLOWED_PROCEDURES`.
6. The query uses a function of the namespaces `apoc`, `gds`, `dbms`, `genai` or `vector`.
7. The query has a label or a relationship type that `src/hst/core/labels.py` does not hold in `LABELS`, `RESERVED_LABELS` or `RELS`.

`run_readonly` runs the query in a read transaction of a session with read access.

| Limit | Constant of `src/hst/app/tables.py` | Value | Result above the limit |
|---|---|---|---|
| time | `NEO4J_TIMEOUT_S` | 15 seconds | the transaction stops |
| rows | `MAX_ROWS` | 500 | `truncated` is true in the result |
| bytes of rows and graph | `MAX_RESULT_BYTES` | 4 MiB | `ResultTooLarge`, and the route answers 400 |
| nodes of the graph | `MAX_GRAPH_NODES` | 300 | `truncated` is true in the key `graph` |
| relationships of the graph | `MAX_GRAPH_RELS` | 600 | `truncated` is true in the key `graph` |

`run_cypher` does not call `check_pinned`. `run_readonly` skips `check_readonly` for a caller that passes `trusted=True`. These callers are in `src/hst/app/routes/queries.py`, `src/hst/app/routes/explore.py` and `src/hst/twin_tools/query.py`.

`src/hst/app/routes/cypher.py` `record` writes 1 audit row for each call. `src/hst/app/tables.py` `audit_outcome` gives the outcome of a call that raised: `rejected`, `result_too_large` or `error`. The 2 other outcomes are `ok` and `too_large`.

## Side-store readers and the manifest

4 modules have a function `for_snapshot` that builds a reader for the pinned run.

| Function | Reader | Table |
|---|---|---|
| `src/hst/core/ribsource.py` `for_snapshot` | `RibSource` | `rib` |
| `src/hst/core/bgpsource.py` `for_snapshot` | `BgpSource` | `bgp_session_routes`, `bgp_sessions` |
| `src/hst/core/ospfsource.py` `for_snapshot` | `OspfSource` | `ospf_lsdb` |
| `src/hst/core/neighborsource.py` `for_snapshot` | `NeighborSource` | `arp` or `mac`, from the argument `table` |

Each function reads `src/hst/core/snapshot.py` `Snapshot.manifest`. With a manifest, it gets the files of each device from `snapshot_evidence` of its module or of `src/hst/core/ribsource.py`. `Snapshot.evidence` keeps this result for the request. The function gives the reader the side-store directory, the run key as `as_of_ms` and the result as `evidence`.

Without a manifest, the reader gets no `evidence` and its property `approximate` is true. [Storage](storage.md#side-store) describes the file selection of the 2 cases and the format of the files. [Storage](storage.md#manifests) describes the manifest.

`src/hst/core/ribsource.py` `DeviceEvidence` holds the run id, the outcome and the file of 1 device. If the manifest has no outcome of the table for the device, or the outcome `unchanged`, `_device_evidence` reads the manifests of the chain. `EVIDENCE_WALK_MAX` limits the read to 32 manifests.

## Tracer

### Request

`GET /api/path` calls `src/hst/app/routes/path.py` `get_path` and needs the permission `graph.read`. `GET /api/path/vrfs` returns each VRF name that `start_vrf` accepts.

| Parameter | Content |
|---|---|
| `src` | the source as an address, a prefix or a range |
| `dst` | the destination as an address, a prefix or a range |
| `port` | a destination port, or a port spec such as `80,443` or `1-1024` |
| `proto` | a protocol, or a list of protocols with commas |
| `src_context` | the uid of the context that limits the source candidates |
| `dst_context` | the uid of the context that the caller expects for the destination |
| `start_table` | the uid of the `VrfInstance` in which the trace starts |
| `start_vrf` | a VRF name. `src/hst/path/trace.py` `vrf_starts` finds the devices on which the trace starts |
| `snapshot` | the run key of the run to read. Without it, the route reads the run of the pointer |
| `snapshot_b` | the run key of a second run. The answer holds 1 trace for each of the 2 runs |
| `reply` | `true` adds the trace of the reply direction |
| `dscp` | the DSCP value of the flow, 0 to 63. Only `src/hst/path/gates/sdwan.py` reads it |
| `mtu_mode` | `off`, `inventory`, `unfragmented` or `packet`. The default is `off` |
| `mtu_ip_packet_bytes`, `mtu_ipv4_df`, `mtu_reply_ip_packet_bytes`, `mtu_traffic_class` | fields of `src/hst/core/mtu.py` `MtuRequest` |

`src` and `dst` are the 2 parameters without a default. `src/hst/path/trace.py` `trace` also has the arguments `gateways`, `src_port` and `max_hops`, and the route does not pass them.

| Status | Cause |
|---|---|
| 400 | a port spec, a protocol spec or an MTU value that does not parse |
| 400 | `mtu_reply_ip_packet_bytes` without `reply` |
| 400 | `reply` together with `snapshot_b` |
| 400 | `start_vrf` together with `start_table` or `src_context` |
| 400 | a value of `snapshot` or `snapshot_b` that is not a run key |
| 400 | `snapshot_b` for a graph without a run |
| 400 | a `ValueError` of the engine, such as a reply for a source with 2 or more interpretations |
| 404 | a run key without an `Obj` node in the graph |
| 404 | `NoRun` |
| 409 | the `CycleRun` node of the run existed at the start and does not exist before or after the trace |

### Call chain

1. `get_path` builds 1 `Snapshot` for each run of the request and holds a lease on the runs with `src/hst/app/routes/run_lease.py` `leased`.
2. `run_trace` calls `src/hst/path/trace.py` `trace`. With `start_vrf`, it calls `src/hst/path/trace.py` `trace_from_vrf`. The session is the result of `src/hst/path/session.py` `pinned`. The argument `rib` is the result of `src/hst/core/ribsource.py` `for_snapshot`.
3. `trace` does a check of the request with `_check_trace_request` and reads the gateway rows with `src/hst/path/session.py` `load_gateways`. Then it selects 1 of the 3 starts of the table below.
4. `_trace_domain` finds the attachment of the source with `_source_attachment` and the gateway with `_pick_gateway`.
5. If the source and the destination are in the connected prefix of the gateway, `_switched_legs_with_crossings` builds the legs of the switched flow. If not, `_walk_from_gateway` draws the L2 path to the gateway with `_gateway_walk` and calls `_device_stage`.
6. `_device_stage` does the forwarding decision of 1 device. [Stages](#stages) gives its order.
7. `_next_hop_stage` finds the device of the next hop with `src/hst/path/gates/routing.py` `_next_hop_device`. `_next_hop_walk` calls `_device_stage` for that device.
8. `_finish_trace` writes the verdict text, calls `_flow_gates` and builds the walk.
9. With `reply`, `_compose_bidirectional` adds the reply. [Reply direction](#reply-direction) describes it.
10. `run_trace` gives the result to `src/hst/results/trace.py` `project_trace` and adds the key `run`.

| Start | Condition | Function |
|---|---|---|
| a routing table | `start_table` has a value | `_trace_start_table`, which calls `_trace_from_table` |
| a host | the source is 1 address without a prefix length | `_trace_host_source` |
| a network | each other source | `_trace_network_source` |

`_trace_host_source` reads the source candidates with `_source_candidates`. For 1 candidate, it calls `_trace_domain`. For 2 or more, `_trace_interpretations` traces a maximum of `MAX_INTERPRETATIONS` candidates, and `_merge_lanes` joins the results. `MAX_INTERPRETATIONS` is 8. `trace_from_vrf` uses the same limit and the same merge for its starts.

The setting `MAX_L3_HOPS` limits the count of L3 hops of 1 path. The default is 32. The setting `PATH_LANE_CAP` limits the count of lanes of 1 trace. The default is 64. `_routed_part_legs` opens 1 lane for each equal-cost route.

`src/hst/path/trace.py` `trace_from_identity` traces a flow that ZPA brokers. No code in `src/hst` calls it. For `hst path`, `src/hst/cli.py` `path_cmd` calls `trace` with a session of `pinned` and the same `rib`.

[Walkthrough of one query](query-walkthrough.md#the-path-call) goes through 1 path query step by step.

### Stages

`src/hst/path/gates/__init__.py` `Stage` gives the place of a hop on the path. `src/hst/path/gates/__init__.py` `_Trail.hop` records 1 hop with its stage. `_Trail.rank_hops` computes the key `rank` of each hop from the depth of the device, the stage value and the index in the stage.

| Value | Stage | Hop |
|---|---|---|
| 1 | `IDENTITY` | the `IdentityGroup` of a brokered request |
| 2 | `BROKER` | no code records a hop at this stage |
| 3 | `ACCESS_RULE` | the `ZpaAccessRule` of a brokered request |
| 4 | `CONNECTOR` | the `ZpaAppConnector` of a brokered request |
| 10 | `SRC_ENDPOINT` | the `Endpoint` of the source, or the origin of a reply |
| 20 | `SRC_ATTACH` | the port and the switch of the source |
| 30 | `L2_FABRIC` | the ports, the LAGs and the switches between the source and the gateway |
| 40 | `INGRESS_IF` | the ingress interface of the device |
| 50 | `DEVICE` | the device, and the `FirewallInstance` of a virtual system |
| 60 | `DNAT` | the `NatRule` of a destination translation |
| 70 | `PBR_POLICY` | the `PbrPolicy` of the ingress interface |
| 80 | `PBR_RULE` | the rule of the policy that claims the flow |
| 90 | `VRF` | the `VrfInstance` of the route lookup |
| 100 | `ROUTE` | the `Prefix` of the route, or the `ForwardingBoundary` of an SD-WAN edge |
| 105 | `NEXT_HOP` | the next hop of 1 lane, if 2 or more equal-cost routes have a next hop |
| 110 | `FILTER_RB` | the `FwRulebase` of the filter, or an ACI `Contract` that denies |
| 120 | `FILTER_RULE` | the `FwRule` of the filter |
| 130 | `SNAT` | the `NatRule` of a source translation |
| 134 | `EGRESS_FILTER_RB` | the `FwRulebase` of an outbound interface ACL |
| 136 | `EGRESS_FILTER_RULE` | the `FwRule` of an outbound interface ACL |
| 140 | `EGRESS_IF` | the egress interface |
| 145 | `LOAD_BALANCER` | the `VirtualService`, the `Pool` and the `PoolMember` |
| 150 | `ENCAP` | the `Tunnel` of the egress interface |
| 152 | `CARRIER_ROUTE` | the `Prefix` of the route of the encapsulated packet, or the cloud node at the far end of the tunnel |
| 154 | `CARRIER_FILTER` | the `FwRulebase` for the encapsulated packet |
| 156 | `CARRIER_SNAT` | the `NatRule` for the encapsulated packet |
| 158 | `CARRIER_EGRESS_IF` | the egress interface of the encapsulated packet |
| 159 | `TRANSPORT` | the route to a recursive next hop |
| 160 | `LINK` | the `WanLink` or the `ProviderNetwork` |
| 165 | `DECAP` | the `Tunnel` on the far device, or a `ZiaForwardingRule` |
| 170 | `DST_FABRIC` | the ports, the LAGs and the switches before the destination |
| 180 | `DST_ATTACH` | the port, the switch or the interface of the destination |
| 190 | `DST_ENDPOINT` | the `Endpoint` of the destination |

For 1 device, `src/hst/path/trace.py` `_walk_device` and the functions below it do the steps in this order.

1. `_device_groups` applies the destination NAT rules and then the PBR rules. It returns 1 group for each part of the flow.
2. `_walk_group` records the table hops and reads the routes of the table. An address of the device ends the flow on the device.
3. `_routed_part_legs` builds 1 leg for each best route, or a leg with the text `no route found`.
4. `_route_egress` calls the filter gate of `src/hst/path/gates/firewall.py`.
5. For a route with an egress interface, `_egress_snat_tunnel` applies the source NAT rules and then the outbound interface ACL.
6. `_egress_snat_tunnel` then records the egress interface. If the interface has a tunnel, `_carrier_trace` traces the encapsulated packet.
7. `_next_hop_stage` calls `_next_hop_walk`, which goes to the device of the next hop.
8. If no next device exists, `_route_region_legs` ends the leg. For 1 destination address on a network of the device, it calls `_lb_stage` if the address is a VIP.

`src/hst/path/trace.py` `_family_routes` reads the routes of 1 table from the graph with `_ROUTES_QUERY`. The query returns the `STATIC_ROUTE`, `LEARNED_ROUTE` and `ORIGINATES` relationships of the `VrfInstance`. It also joins `src/hst/core/reasoner.py` `RT_IMPORTED_ROUTES`, which returns the prefixes that the table imports over a route target. Such a row has the value `rt-import` in `derived` and no next hop. `_rib_lookup` builds the lookups of the same table on `RibSource.lpm` and `RibSource.overlapping` of the argument `rib`.

A query with a range of ports, a range of protocols or a source port goes through the same steps as a `FlowRegion` of `src/hst/path/state.py`. The trace then has 1 leg for each region that a rule decides.

### Gate modules

| Module | Gate label | Functions that the trace calls |
|---|---|---|
| `src/hst/path/gates/firewall.py` | `FwRulebase` | `_apply_firewall`, `_apply_firewall_reply`, `_apply_egress_acl` |
| `src/hst/path/gates/local_zone.py` | `FwRulebase` | `LocalZoneTransition`, which `src/hst/path/gates/firewall.py` `_local_zone_verdict` calls |
| `src/hst/path/gates/nat.py` | `NatRule` | `_nat_rows`, `_nat_partition`, `_apply_snat` |
| `src/hst/path/gates/pbr.py` | `PbrPolicy` | `_pbr_partition` |
| `src/hst/path/gates/lb.py` | `VirtualService` | `_vip_bindings`, `_pool_members`, `_lb_snat` |
| `src/hst/path/gates/sdwan.py` | `ForwardingBoundary`, `SdwanBusinessPolicy` | `candidate_routes`, `flow_dscp` |
| `src/hst/path/gates/aci.py` | `Contract` | `aci_contract_verdict` |
| `src/hst/path/gates/zia.py` | `ZiaForwardingRule` | `tunnel_location`, `tenant_rules`, `forwarding_decision` |
| `src/hst/path/gates/zpa.py` | `ZpaAccessRule`, `ZpaClientForwardingRule` | `_access_rule_match`, `_forwarding_match` |

4 more modules of `src/hst/path/gates` evaluate no gate label of their own.

| Module | Content |
|---|---|
| `src/hst/path/gates/__init__.py` | `Stage`, `_Trail` and `unevaluated_gates` |
| `src/hst/path/gates/routing.py` | the route lookup with `_route_partition` and the device of a next hop with `_next_hop_device` |
| `src/hst/path/gates/tunnel.py` | `_wireguard_regions`, which selects the WireGuard peer for a flow |
| `src/hst/path/gates/coverage.py` | `policy_evidence`, which finds a device with policy sections that the pinned run did not collect completely |

`src/hst/path/trace.py` does not import `src/hst/path/gates/aci_symbolic.py`. `src/hst/impact/evaluate.py` imports it.

No module of `src/hst/path` reads the 4 gate labels `VzAny`, `RoutePolicy`, `NatGw` and `AzFirewall`. `src/hst/core/labels.py` `GATE_BINDINGS` gives each of the 4 the value `NOT_DEVICE_BOUND`. [Graph schema](schema.md#gate-bindings) lists the binding patterns.

`src/hst/path/gates/__init__.py` `gate_safeguard_query` builds 1 query from the binding patterns. `unevaluated_gates` returns each gate that a pattern binds to a device of the path and that the walk did not evaluate. `src/hst/path/trace.py` `_gate_coverage` makes each leg indeterminate for such a gate. `src/hst/path/trace.py` `_leg_gate_credits` reads the evaluated gates from these 6 keys of a leg: `fw_uid`, `fw_uids`, `nat_uids`, `lb_uids`, `pbr_uids` and `sdwan_uids`.

### Filter view of a device

`src/hst/path/gates/firewall.py` `_device_filter_view` gives the packet that the access rulebases of a device match. The view `original` is the packet before the destination NAT of the device. The view `translated` is the packet after it. `_read_device_filter_view` reads the vendor and the `match_context` of each access rulebase of the device.

| Access rulebases of the device | View |
|---|---|
| none | `ungoverned` |
| vendor `checkpoint` | `original` |
| vendor `vyos`, `ubiquiti` or `cisco` | `translated` |
| `match_context` `interface-acl`, for each vendor | `original` |
| a rulebase without a vendor | no view, with a reason text |
| a vendor outside `_FILTER_VIEW_BY_VENDOR` | no view, with a reason text |
| rulebases with 2 different views | no view, with a reason text |

### Verdict values

`src/hst/path/verdict.py` `classify_action` converts the action of a rule to 1 of 3 values.

| Value | Actions |
|---|---|
| `permit` | the actions of `PERMIT_ACTIONS`: `accept`, `permit`, `allow`, `pass` |
| `deny` | the actions of `DENY_ACTIONS`: `drop`, `reject`, `deny`, `blocked`, `block` |
| `indeterminate` | each other action, and no action |

### Response

`run_trace` returns the result of `src/hst/results/trace.py` `project_trace` with the key `run`. The request sets the top-level keys.

| Request | Top-level keys |
|---|---|
| without `reply` and without `snapshot_b` | the keys of 1 walk, and `run` |
| with `reply` | `forward`, `reply`, `asymmetric`, `notes`, `run` |
| with `snapshot_b` | `a` and `b`. Each one holds `snapshot` with the run key and `result` with the answer for that run |

With `reply`, a trace that stops before it calls `_trace_domain` returns the keys of 1 walk. `_trace_start_table` also returns 1 walk if `_trace_domain` stops before the first leg.

After the projection, a walk of `src/hst/path/trace.py` `_finish_trace` has these 10 keys.

| Key of a walk | Content |
|---|---|
| `hops` | the hops of each lane |
| `legs` | 1 leg for each candidate path |
| `detail` | the verdict text of the walk |
| `result` | the `Result` for the statement `trace-forwards` |
| `notes` | the notes of the trace |
| `warnings` | each place where the trace could not prove a fact. `_Trail.warn` adds each of its warnings to `notes` too |
| `indeterminate` | true if 1 or more legs are indeterminate |
| `boundary` | true if 1 or more legs have `boundary` |
| `left_estate` | the exit markers of the walk |
| `reach` | the end of the candidate paths |

The tracer writes the verdict text to the key `verdict`. `src/hst/results/trace.py` `project_walk` moves it to `detail` and adds `result`. It does the same for each leg with the statement `hop-forwards`.

| `answer` of a `result` | Condition for a leg | Condition for a walk |
|---|---|---|
| `open` | the leg has `indeterminate` | no leg is `false`, and a leg is `open` or the walk is indeterminate or has no leg |
| `false` | the leg does not have `indeterminate`, and it is blocked or its text is `no route found` | 1 or more legs are `false` |
| `true` | each other leg | each other walk |

A walk that stops before the first leg does not have each of the 10 keys. `src/hst/path/trace.py` `_no_gateway_result` returns `hops`, `legs`, `notes`, `warnings` and `verdict`. `src/hst/path/trace.py` `_with_edge_keys` then adds `left_estate` and `reach`.

`_Trail.hop` writes these keys of a hop: `uid`, `kind`, `label`, `note`, `stage`, `lane`, `shared`, `layer`, `tier` and `gate`. `_Trail.rank_hops` adds `rank`. A hop in a tunnel also has `overlay` and `tunnel`, and a hop on the path to a recursive next hop has `transport`. `src/hst/path/trace.py` `_build_route_leg` writes these keys of a leg: `lane`, `sources`, `cidr`, `egress`, `next_hop`, `table`, `src_label`, `context_uid`, `device_uid`, `blocked` and `indeterminate`. The stages add more keys to a leg.

`src/hst/core/cycle.py` `run_status` builds the value of `run` with the keys `snapshot`, `created`, `degraded`, `sources_carried`, `sources_failed`, `sources_partial`, `sources_cancelled` and `freshness`. The value is null for a run without a `CycleRun` node.

With an `mtu_mode` other than `off`, `src/hst/path/mtu_topology.py` `ensure_result` adds the key `mtu` to an answer that has no `mtu` and no `forward`.

### Reply direction

`src/hst/path/trace.py` `_compose_bidirectional` calls `_walk_reply_leg` 1 time for each forward leg.

1. `_capture_reply_state` keeps the device sequence of the forward walk, and the end device and the gate state of each leg.
2. `_build_reply_tuple` swaps the source and the destination. It reverses each translation of the key `nat_chain` of the forward leg.
3. `_walk_reply_leg` calls `_device_stage` on the end device of the forward leg, without a port and a protocol and with `conn_state="established"`.
4. With that `conn_state`, the filter step calls `src/hst/path/gates/firewall.py` `_apply_firewall_reply`.
5. `_reply_comparison` compares the device sequence of each reply lane with the reversed sequence of the forward leg.

`_apply_firewall_reply` reads the state policy of a device that the forward walk crossed. It does not use the policy for a firewall instance.

| State policy for established traffic | Forward leg | Result |
|---|---|---|
| accept | the device permitted the flow, and the leg is not blocked and not indeterminate | permit, and the gate reads no rule |
| accept | the device permitted the flow, and the leg is blocked or indeterminate | indeterminate |
| drop or reject | each leg | deny |
| actions in conflict, or an action that is not known | each leg | indeterminate |
| each other case | each leg | the result of `_apply_firewall` |

If the forward leg ended on the device, `_apply_local_reply` decides the reply. In the last row of the table, `_apply_firewall` gets `conn_state="established"` for a device that the forward walk crossed. It gets `conn_state="new"` for each other device.

The key `asymmetric` of a reply is true if no reply lane has the reversed device sequence of the forward leg. A stopped lane does not count if its devices are the start of the reversed sequence. The top-level key `asymmetric` is true if 1 or more replies are asymmetric. The top-level `notes` hold the notes of the comparison.

For 1 forward leg, `reply` is 1 walk with the key `destinations`. For 2 or more, `reply` is a list with 1 entry for each forward leg. An entry also has `forward_leg`, `src_label`, `destinations` and `asymmetric`.

| Case | Answer |
|---|---|
| the forward leg has no end device | a reply walk without a leg, with `reply not derived: the forward leg never confirmed delivery` |
| the forward leg has a translation and a firewall instance on its path, and `src/hst/path/reply_nat.py` `valid_chain` returns false | a reply walk without a leg, with `reply not derived: NAT inversion is not established` |
| the forward leg has a translation and a firewall instance on its path, and `valid_chain` returns true | each reply leg is indeterminate |
| the forward leg crossed a load balancer VIP | each reply leg is indeterminate |
| the source has 2 or more interpretations | `ValueError`, and the route answers 400 |
| `start_vrf` gives 2 or more starts | `ValueError`, and the route answers 400 |

### Indeterminate legs

The table gives cases in which the trace sets the key `indeterminate` of a leg. More functions of `src/hst/path/trace.py` set the key. The key `indeterminate_reason` of the leg holds the cause, if the code records one.

| Function of `src/hst/path/trace.py` | Cause |
|---|---|
| `_build_route_leg` | the destination NAT rule of the leg or the PBR claim of its group has the mark `opaque` |
| `_build_route_leg` | the route has the mark `derived` or the mark `unconfirmed` |
| `_routed_part_legs` | the trace is at the limit of `PATH_LANE_CAP`, or an SD-WAN candidate set is not complete |
| `_egress_snat_tunnel` | `_select_tunnel` does not decide the tunnel of the egress interface |
| `src/hst/path/gates/firewall.py` `_apply_firewall_reply` | the state policy does not decide the reply |
| `_flow_gates` | the ACI contract verdict is `indeterminate` |
| `_gate_coverage` | a gate on a device of the path has no verdict |
| `_gate_coverage` | the pinned run did not collect the policy sections of a device completely |
| `_trace_domain` | a part of the source is outside the prefix of the gateway |
| `_finish_trace` | the graph has no cable path for the L2 part of a leg that is not blocked and has a route |
| `_finish_trace` | a VLAN or a bridge domain does not agree on the L2 path |
| `_check_delivery_context` | the leg ends in a context other than `dst_context` |

`src/hst/path/trace.py` `_ambiguous_gateway_result` and `src/hst/path/trace.py` `_unknown_gateway_result` return a walk without a leg and with `indeterminate` true. `_merge_lanes` sets `indeterminate` of the merged walk if a start has no leg or the trace has more starts than `MAX_INTERPRETATIONS`.

### When a gate is indeterminate

A gate module returns the value `indeterminate` of `src/hst/path/verdict.py`, or a value of its own for a result that it cannot decide. The table gives the conditions in the order of the code.

| Gate module | Function | Result | Condition |
|---|---|---|---|
| `src/hst/path/gates/firewall.py` | `_intra_zone_verdict` | the action `indeterminate` | the 2 interfaces are in 1 zone that filters its own traffic, no rulebase of the address family binds the zone to itself, and the zone has no `intra_zone_action` |
| `src/hst/path/gates/firewall.py` | `_zone_default` | the action `indeterminate` | no rulebase of the address family binds the zone pair, and the destination zone has no `default_action` |
| `src/hst/path/gates/firewall.py` | `_fallthrough` | the action `indeterminate` | the connection state is `established` or `related`, the default action is not a permit, and the zone or the rulebase has `established_default_unknown` |
| `src/hst/path/gates/firewall.py` | `_first_match_point` | the action `indeterminate` | an address of a rule does not parse |
| `src/hst/path/gates/firewall.py` | `_first_match_point` | the action `indeterminate` | `_net_side` cannot decide the source side or the destination side of a rule |
| `src/hst/path/gates/firewall.py` | `_first_match_point` | the action `indeterminate` | a rule matches the addresses, and the match of its services is not decided |
| `src/hst/path/gates/local_zone.py` | `LocalZoneTransition.apply` | an effect `indeterminate` | the chain is not `input` and not `output` |
| `src/hst/path/gates/local_zone.py` | `LocalZoneTransition.apply` | an effect `indeterminate` | `_OWNED_ZONES_QUERY` returns no zone, and `_LOCAL_ZONE_RULEBASES_QUERY` returns 1 or more rulebases |
| `src/hst/path/gates/local_zone.py` | `LocalZoneTransition.apply` | an effect `indeterminate` | a zone of the device has no value in `local_zone` |
| `src/hst/path/gates/local_zone.py` | `LocalZoneTransition.apply` | an effect `indeterminate` | 2 or more zones of the device have `local_zone` true |
| `src/hst/path/gates/local_zone.py` | `LocalZoneTransition.apply` | an effect `indeterminate` | the interface of the flow has no zone, or it has 2 or more zones |
| `src/hst/path/gates/local_zone.py` | `LocalZoneTransition.apply` | an effect `indeterminate` | the rows of the interface hold 2 or more values of `if_name` |
| `src/hst/path/gates/nat.py` | `_nat_base_rule` | `opaque` true on the rule | the row has `rule_approximate` or `approximate` |
| `src/hst/path/gates/nat.py` | `_nat_base_rule` | `opaque` true on the rule | the rule has an original source object or an original destination object, and the object gives no address |
| `src/hst/path/gates/nat.py` | `_nat_base_rule` | `opaque` true on the rule | the row has `xlate_src_opaque` or `xlate_dst_opaque` |
| `src/hst/path/gates/nat.py` | `_nat_base_rule` | `opaque` true on the rule | `_nat_service_unknown` returns a reason |
| `src/hst/path/gates/nat.py` | `_nat_base_rule` | `opaque` true on the rule | the row has `install_on` or `install_on_unresolved` |
| `src/hst/path/gates/nat.py` | `_ingress_role_gate` | `opaque` true on the rule | the NAT role of the ingress interface is `None` |
| `src/hst/path/gates/pbr.py` | `partition_rules` | `opaque` true on the group | the rule that claims the flow has `states_opaque` |
| `src/hst/path/gates/pbr.py` | `partition_rules` | `opaque` true on the group | the rule that claims the flow has a value in `addr_opaque_reasons` |
| `src/hst/path/gates/pbr.py` | `partition_rules` | `opaque` true on the group | a side of the rule gives no address, and it has address objects or an address that does not parse |
| `src/hst/path/gates/pbr.py` | `_service_state` | a reason, and `partition_rules` sets `opaque` | the rule has a service object, and no member has a protocol or a port |
| `src/hst/path/gates/pbr.py` | `_service_state` | a reason, and `partition_rules` sets `opaque` | the service of the rule matches, and the rule has `svc_src_port` |
| `src/hst/path/gates/pbr.py` | `_service_state` | a reason, and `partition_rules` sets `opaque` | the match state of the service is `unknown` |
| `src/hst/path/gates/lb.py` | `_vip_claims` | the match state `unknown` | the `VirtualService` has a protocol or a port, and the flow has no value for it |
| `src/hst/path/gates/lb.py` | `_member_regions` | `collapsed` true | the pool has no member |
| `src/hst/path/gates/lb.py` | `_member_regions` | `collapsed` true | no member of the pool has a value in `state` |
| `src/hst/path/gates/lb.py` | `_member_regions` | `collapsed` true | each member of the pool has the state `down` |
| `src/hst/path/gates/lb.py` | `_lb_snat` | `indeterminate` true | `snat_mode` is `snat_from`, and the `VirtualService` has 2 or more `SNAT_FROM` addresses |
| `src/hst/path/gates/lb.py` | `_lb_snat` | `indeterminate` true | `snat_mode` is `snat_from`, and the `VirtualService` has no `SNAT_FROM` address |
| `src/hst/path/gates/sdwan.py` | `rule_verdict` | `maybe` | the rule has `match_src` or `match_dst`, and the prefix holds only a part of the addresses of the flow |
| `src/hst/path/gates/sdwan.py` | `rule_verdict` | `maybe` | the rule has `match_proto`, and the flow has no protocol |
| `src/hst/path/gates/sdwan.py` | `rule_verdict` | `maybe` | the rule has `match_dst_port` or `match_src_port`, and the flow has no such port or the port spec does not parse |
| `src/hst/path/gates/sdwan.py` | `rule_verdict` | `maybe` | the rule has `match_dscp`, and the request has no `dscp` or the value of the rule is not a number |
| `src/hst/path/gates/sdwan.py` | `rule_verdict` | `maybe` | the rule has a value for a key of `_OPEN_MATCHES` |
| `src/hst/path/gates/sdwan.py` | `rule_verdict` | `maybe` | the rule has a value in `match_unmapped` |
| `src/hst/path/gates/aci.py` | `aci_contract_verdict` | the action `indeterminate` | `src/hst/core/aci_filter.py` `endpoint_identity` returns a fault for an endpoint |
| `src/hst/path/gates/aci.py` | `aci_contract_verdict` | the action `indeterminate` | only 1 of the 2 endpoints is in an EPG |
| `src/hst/path/gates/aci.py` | `aci_contract_verdict` | the action `indeterminate` | the 2 endpoints are in the same EPG |
| `src/hst/path/gates/aci.py` | `_contracts_verdict` | the action `indeterminate` | the EPG pair has no contract, and `_vrf_enforcement` returns `unknown` |
| `src/hst/path/gates/aci.py` | `_contracts_verdict` | the action `indeterminate` | the EPG pair has no contract, and `reverse_contract_gap` or `contract_bypass` of `src/hst/core/aci_filter.py` returns a reason |
| `src/hst/path/gates/aci.py` | `_contracts_verdict` | the action `indeterminate` | `_contract_outcome` returns `indeterminate` for 1 or more contracts |
| `src/hst/path/gates/zia.py` | `forwarding_decision` | a `ZiaDecision` without a decided rule | `_flow_location` finds no location for the source of the flow |
| `src/hst/path/gates/zia.py` | `forwarding_decision` | a `ZiaDecision` without a decided rule | a rule has the parent location of the sublocation of the flow as a target |
| `src/hst/path/gates/zia.py` | `forwarding_decision` | a `ZiaDecision` without a decided rule | a rule has no target in the location of the flow, and it has more location ids and group ids than targets |
| `src/hst/path/gates/zia.py` | `forwarding_decision` | a `ZiaDecision` without a decided rule | a rule has a value in `other_criteria` |
| `src/hst/path/gates/zia.py` | `forwarding_decision` | a `ZiaDecision` without a decided rule | a source criterion or a destination criterion holds an entry that is not an address, or it holds only a part of the flow |
| `src/hst/path/gates/zpa.py` | `_choose_segment` | a `SegmentChoice` without `uid` and without `blocking_uid` | no `ZpaAppSegment` has the reference as its uid or as a domain |
| `src/hst/path/gates/zpa.py` | `_choose_segment` | a `SegmentChoice` without `uid` and without `blocking_uid` | 2 or more segments have the reference as a domain, and 1 or more of them is not disabled and does not exclude the port |
| `src/hst/path/gates/zpa.py` | `_segment_port_match` | `indeterminate` true | the protocol of the request is not `tcp` and not `udp` |
| `src/hst/path/gates/zpa.py` | `_segment_port_match` | `indeterminate` true | the segment has no port ranges for the protocol |
| `src/hst/path/gates/zpa.py` | `_segment_port_match` | `indeterminate` true | the port ranges of the segment do not parse as pairs |
| `src/hst/path/gates/zpa.py` | `_forwarding_match` | a `ForwardingDecision` with `go_on` false and no `action` | `src/hst/core/zpa_policy.py` `first_match` cannot decide the `ZpaClientForwardingRule`, or the action of the rule is not `bypass`, `intercept` or `intercept_accessible` |
| `src/hst/path/gates/coverage.py` | `_entry_policy_evidence` | 1 or more gaps | the manifest entry of the device has the outcome `failed` and a value in `ingested_ms` |
| `src/hst/path/gates/coverage.py` | `_entry_policy_evidence` | 1 or more gaps | the entry has a value in `mixed_since` |
| `src/hst/path/gates/coverage.py` | `_entry_policy_evidence` | 1 or more gaps | the entry has no `effective_run`, and it has `carried` true or the outcome `failed` |
| `src/hst/path/gates/coverage.py` | `_entry_policy_evidence` | 1 or more gaps | a policy section of `_TRACE_POLICY_SECTIONS` has a status of `_DEGRADED_POLICY_SECTION` in the entry |
| `src/hst/path/gates/coverage.py` | `_entry_policy_evidence` | 1 or more gaps | the entry does not hold a section of `_POLICY_SECTIONS` for its source type |

The table gives the first 6 conditions of a module. These 8 modules hold more conditions: `src/hst/path/gates/firewall.py`, `src/hst/path/gates/local_zone.py`, `src/hst/path/gates/nat.py`, `src/hst/path/gates/pbr.py`, `src/hst/path/gates/lb.py`, `src/hst/path/gates/aci.py`, `src/hst/path/gates/zpa.py` and `src/hst/core/zpa_policy.py`. `src/hst/path/gates/coverage.py` `policy_evidence` returns the gaps of `_entry_policy_evidence`.

For a `ZiaDecision` without a decided rule, `src/hst/path/trace.py` `_zia_forwarding` adds 1 note and does not change the leg. For the result `maybe`, `src/hst/results/trace.py` `_rule_result` gives the rule the `answer` `open`.

## End of a path

### Boundary

The key `boundary` of a leg is true if the path goes out of the graph at a device. The trace does not evaluate the path after that device.

| Function of `src/hst/path/trace.py` | Case |
|---|---|
| `_next_hop_walk` | no interface in the graph holds the next hop of the route |
| `_next_hop_walk` | `src/hst/path/vsx.py` `resolve` returns a fault for the path to the next hop |
| `_mark_twin_exit` | the route has no next hop, the device does not serve the destination and the leg has no tunnel |
| `_finish_trace` | the graph has no cable path for the L2 part of the leg |
| `_carrier_far_boundary`, `_far_owner_start`, `_carrier_walk` | the carrier packet of a tunnel goes out of the graph |

### Exit marker

The key `left_estate` of a leg holds 1 exit marker if the leg ends at the edge of the estate. `src/hst/path/trace.py` `_left_estate` builds the marker.

| Key of the marker | Content |
|---|---|
| `basis` | `wan-link`, `access-client-default` or `site-zone` |
| `device_uid`, `device` | the device that the leg goes out of |
| `interface_uid`, `interface` | the egress interface |
| `next_hop` | the next hop of the route, or null |
| `wan_link_uid`, `wan_link` | the WAN link, only for the basis `wan-link` |
| `site_block` | the site block of the device, only for the basis `site-zone` |

`src/hst/path/trace.py` `exit_basis` returns the basis of an exit or `None`. `src/hst/path/trace.py` `_estate_exit` calls it for a route with a next hop, and `_mark_twin_exit` calls it for a route without one. `_estate_exit` returns no exit for a route other than `0.0.0.0/0` and `::/0`.

| Basis | Condition |
|---|---|
| `wan-link` | the first WAN link of the egress interface does not have the kind `mpls` |
| `access-client-default` | the route is IPv4 and has a next hop, and the interface has a value in `ipv4_default_origin` |
| `site-zone` | the device has the value `internet` in `site_zone`, the first WAN link is not `mpls` and the route is not an SD-WAN boundary row |

`exit_basis` does the 3 checks in the order of the table and returns the first basis.

A leg gets no marker if a part of its destination is an address of the estate. `src/hst/path/trace.py` `_estate_part` finds that part with `src/hst/path/trace.py` `estate_prefixes`. `_warn_estate_destination` then adds 1 warning for each cause. The estate holds these 3 sets of prefixes.

| Set | Source |
|---|---|
| served | the prefixes with a `GATEWAY_FOR` relationship from an interface of the pinned run, or from a group of which the interface is a member |
| routed | the prefixes of the routes of the devices of the pinned run that overlap the destination |
| not on the internet | `src/hst/path/trace.py` `NOT_INTERNET` |

`NOT_INTERNET` holds `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `fc00::/7`, `fe80::/10` and `::1/128`. `estate_prefixes` removes the prefixes of an uplink interface from the sets served and routed. `src/hst/path/trace.py` `_uplink_interface` finds an uplink interface with `exit_basis`.

`src/hst/path/trace.py` `estate_exit` returns the marker for a caller outside the tracer.

### Keys of a walk

`src/hst/path/trace.py` `_walk_exits` builds the key `left_estate` of a walk. It collects the markers of each leg, of its carrier, of its outer carriers and of their underlay legs. The list holds each marker 1 time, in the order of `_exit_key`.

`src/hst/path/trace.py` `_leg_end` gives the end of 1 leg, and `src/hst/path/trace.py` `_walk_reach` gives the key `reach` of the walk.

| End of a leg | Condition |
|---|---|
| `left_estate` | the leg has an exit marker |
| `destination` | the leg has no `boundary`, and the walk delivered the flow on a network of the device, as a switched flow in the prefix of the source or on the device |
| `None` | each other leg |

| `reach` | Condition |
|---|---|
| `destination` | each leg ends at `destination` |
| `left_estate` | each leg ends at `left_estate` |
| `split` | the legs have the 2 ends |
| null | a leg has the end `None`, the walk has no leg or the `answer` of the walk is not `true` |

`src/hst/path/trace.py` `_with_edge_keys` gives each walk of an answer the 2 keys. A walk without them gets an empty list and null. `_merge_lanes` joins the markers of its parts. Its `reach` is null if a part has no `reach` or the merge is indeterminate.
