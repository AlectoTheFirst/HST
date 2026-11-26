# Walkthrough of one query

## Example

The example uses the fixture `fixtures/demo-enterprise/estate-v3.yaml`. `fixtures/demo-enterprise/README.md` describes the estate. The fixture holds the 4 keys `source`, `scope`, `nodes` and `rels`. It holds no side-store row.

These 2 commands load the fixture into an empty database.

```sh
hst init-db
hst load-fixture --new-run fixtures/demo-enterprise/estate-v3.yaml
```

`src/hst/cli.py` `load_fixture_cmd` reads the file with `src/hst/core/fixtures.py` `load_fixture` and calls `src/hst/app/fixture_runs.py` `publish`. The function `publish` writes the batch as 1 run and calls `src/hst/core/finalize.py` `finalize_derivations`, which runs the reasoner rules. Then it writes the manifest and sets the run pointer. [Code flow of a collection](collection-code-flow.md#kinds-of-run) describes these steps.

The flow goes from the endpoint `osl01-cam-01` to the endpoint `osl01-nas-01` on TCP port 1883. The 2 endpoints are in the Oslo office of the fixture. The router `osl01-vyos-01` has 1 interface in each of the 2 networks.

The path call is `GET /api/path?src=10.18.20.31&dst=10.18.10.20&port=1883&proto=tcp`.

The impact call is `POST /api/impact/evaluate` with this body.

```json
{
  "request": {
    "name": "mqtt to nas",
    "destination": "osl01-nas-01",
    "sources": ["10.18.20.31"],
    "members": [{"name": "osl01-nas-01", "addresses": ["10.18.10.20"]}],
    "condition": {"kind": "member", "member": "osl01-nas-01"},
    "proto": "tcp",
    "port": "1883"
  }
}
```

No fixture holds a `ServiceRequirement` node, and no code under `src/hst` writes one. For this reason the body states the request in the field `request`. `tests/app/test_impact_api.py` answers the requirement query with test rows for the field `requirement`.

The fixture holds these nodes for the flow.

| Role in the flow | Label | `uid` | Properties and relationships in the fixture |
|---|---|---|---|
| endpoint of the source address | `Endpoint` | `ep:osl01:021800001404` | `name` `osl01-cam-01`, `ATTACHED` to the port, `IN` `bd:vlan:osl01:20` |
| source address | `IpAddress` | `ip:vrf-dev-osl01-vyos-01-default:10.18.20.31` | `anchor` `vrf:dev:osl01-vyos-01:default` |
| port of the 2 endpoints | `Port` | `dev:osl01-vyos-01/port/eth1` | `ON` the router, no `CONNECTED_TO` relationship |
| router | `Device` | `dev:osl01-vyos-01` | `role` `router` |
| ingress interface | `Interface` | `dev:osl01-vyos-01/if/eth1.20` | address 10.18.20.1, in the zone `IOT`, `BOUND_TO` `vlan:dev:osl01-vyos-01:20` |
| routing table | `VrfInstance` | `vrf:dev:osl01-vyos-01:default` | `rib_mirrored` true |
| route | `Prefix` | `pfx:vrf-dev-osl01-vyos-01-default:10.18.10.0/24` | `kind` `connected`, `ORIGINATES` from the routing table |
| egress interface | `Interface` | `dev:osl01-vyos-01/if/eth1.10` | address 10.18.10.1, in the zone `LAN`, `BOUND_TO` `vlan:dev:osl01-vyos-01:10` |
| rulebase | `FwRulebase` | `vyos:osl01-vyos-01:fw:IOT-LAN` | `FROM_ZONE` `IOT`, `TO_ZONE` `LAN`, `default_action` `drop` |
| rule | `FwRule` | `vyos:osl01-vyos-01:fw:IOT-LAN:10` | `position` 10, `action` `accept`, `SVC` `vyos:osl01-vyos-01:svc:tcp-1883` |
| destination address | `IpAddress` | `ip:vrf-dev-osl01-vyos-01-default:10.18.10.20` | `anchor` `vrf:dev:osl01-vyos-01:default` |
| destination endpoint | `Endpoint` | `ep:osl01:021800000a02` | `name` `osl01-nas-01`, `ATTACHED` to the port, `IN` `bd:vlan:osl01:10` |

`tests/test_demo_enterprise_vyos.py` runs the same IPv4 trace on the fixture without a database, in the test `test_3_an_ipv6_iot_to_lan_flow_is_dropped_by_the_ipv6_rule_set`. The test expects 1 leg with `blocked` false and the `firewall` text `IOT-LAN (IOT→LAN) accept by rule 10`.

## The path call

Each code block of this section holds patterns of 1 query without the `WHERE` lines. A block can leave out patterns of the query.

### Route

`GET /api/path` is `src/hst/app/routes/path.py` `get_path`. [Serving](serving.md#request) describes the entry and the parameters. The function does these steps for the example.

1. It reads the parameters. `src/hst/app/routes/path.py` `_parse_port` converts `1883` to an integer. A parameter that a check refuses gives the status 400.
2. `src/hst/core/snapshot.py` `resolve` reads the run pointer 1 time, because the call has no parameter `snapshot`.
3. `src/hst/app/routes/run_lease.py` `leased` holds a lease on the run while the trace reads.
4. The inner function `run_trace` pins the session with `src/hst/path/session.py` `pinned`.
5. `run_trace` makes the RIB reader with `src/hst/core/ribsource.py` `for_snapshot` and calls `src/hst/path/trace.py` `trace`.
6. `src/hst/results/trace.py` `project_trace` writes the `result` objects of the answer.
7. `run_trace` adds the key `run` from `src/hst/core/cycle.py` `run_status`.

`run_trace` reads the `CycleRun` node of the run before and after the trace. If the node existed before the lease and is gone, the status is 409. The detail is `run <run key> was pruned while the trace ran`.

With the parameter `start_vrf`, `run_trace` calls `src/hst/path/trace.py` `trace_from_vrf`. With the parameter `snapshot_b`, the answer holds 1 result for each of 2 runs in the keys `a` and `b`.

### Pinned run

`src/hst/path/session.py` `pinned` returns a `src/hst/path/session.py` `CycleSession` that holds the run key in `cts`. Each read of the tracer goes through `src/hst/path/session.py` `_read`. The function binds `$snap` to `cts`. For a session without `cts`, it binds `$snap` to `src/hst/core/snapshot.py` `LIVE_SNAP`, the value `live`. Each read has a timeout of 30 seconds. [Serving](serving.md#pinned-run-and-read-guards) describes the read guards.

`src/hst/path/trace.py` `trace` does 4 things before the first step of the walk.

- `_check_trace_request` refuses `start_table` together with `src_context`.
- `_pinned_session` pins a session that has no run key.
- `src/hst/path/addrsets.py` `_intervals` converts the flow source and the destination to address ranges. If one of them is no address, prefix or range, the answer has no leg.
- It makes a `_TraceRequest` with the gateway rows, the instances of the destination address and the hop limit. The setting `MAX_L3_HOPS` gives the hop limit, and the default is 32.

`trace` then selects 1 of 3 functions.

| Request | Function |
|---|---|
| `start_table` has a value | `_trace_start_table` |
| the flow source holds more than 1 address, or its text has a `/` | `_trace_network_source` |
| the flow source is 1 address without a `/` | `_trace_host_source` |

The example goes through `_trace_host_source`.

### Flow source

`src/hst/path/trace.py` `_trace_host_source` calls `_source_candidates`, which reads `_SOURCE_QUERY` for the source address.

```cypher
MATCH (ip:IpAddress:Obj {ip: $ip})
OPTIONAL MATCH (ep:Endpoint)-[hi:HAS_IP]->(ip)
OPTIONAL MATCH (ep)-[at:ATTACHED]->(att)
OPTIONAL MATCH (att:Port)-[aon:ON]->(sw:Device)
OPTIONAL MATCH (ep)-[ein:IN]->(seg)
```

The column `owned` is true if a node has a `HAS_IP` relationship to the address. If 1 or more rows are owned, `_source_candidates` drops the rows that are not owned. It groups the rows with `src/hst/path/gates/__init__.py` `_anchor_of` and keeps the first row of each group. `_anchor_of` returns `anchor`, or `l3dom` for a row without `anchor`.

| Rows | Result |
|---|---|
| 0 | an answer without a leg and the verdict `source <src> is not in the graph` |
| 1 | `_trace_domain` traces the flow in the anchor of the row |
| 2 or more | `_trace_interpretations` calls `_trace_domain` for each row, and `_merge_lanes` merges the results |

`_trace_interpretations` traces a maximum of 8 rows, the value of `MAX_INTERPRETATIONS`. Each merged hop and each merged leg has the key `domain`.

The fixture holds 1 `IpAddress` node with the address 10.18.20.31. Its row holds the endpoint, the port `eth1`, the router and the segment `bd:vlan:osl01:20`.

`_trace_domain` calls `_source_attachment` first. The function adds this to the answer:

- a hop of the kind `Endpoint` at the stage `SRC_ENDPOINT`
- a hop of the kind `Port` and a hop of the kind `Device` at the stage `SRC_ATTACH`
- the note `src segment: <uid>`

If the attachment of the endpoint is no `Port`, the function adds 1 `Device` hop for the attachment. The function returns the uid of the attachment device.

### Gateway

`src/hst/path/session.py` `load_gateways` reads `GATEWAYS`.

```cypher
MATCH (i:Interface:Obj)-[g:GATEWAY_FOR {collection_ts: $snap}]->(p:Prefix)
MATCH (i)-[:ON]->(d:Device)
```

A process keeps the gateway rows of its last 4 runs, the value of `GATEWAY_CACHE_RUNS`. A request on a kept run reads `_RUN_IDENTITY` only and gets a copy of the rows.

The fixture holds no `GATEWAY_FOR` relationship for the 2 interfaces of the example. The rule `gateway-from-router-interface` of `src/hst/reasoner/catalog.py` `RULES` writes the relationship for this pattern.

```cypher
MATCH (d:Device:Obj)<-[o:ON]-(i:Interface)-[h:HAS_IP]->(ia:IpAddress)
      -[ip:IN]->(p:Prefix {kind: 'connected'})
```

The rule needs a device role of `src/hst/reasoner/_constants.py` `GATEWAY_ROLES`, which holds `router`. In the fixture, the address 10.18.20.1 of `eth1.20` is `IN` the connected prefix 10.18.20.0/24.

`src/hst/path/trace.py` `_pick_gateway` selects the gateway row in this order.

1. `_containing` returns the rows whose prefix contains the first address of the flow source. If a gateway row has the anchor of the source address row, only the rows of that anchor stay.
2. For rows with `vsx_cluster`, the member with `vsx_state` `active` stays for each `firewall_instance_uid`. If a cluster has no instance uid or its count of active devices is other than 1, the pick is ambiguous.
3. If the source address row has a segment, `_segment_tie` keeps the rows whose interface has that segment. `_iface_segments` reads the segments with `_IFACE_SEGMENTS_QUERY`.
4. If no anchor limits the rows, `_fhrp_gateway` returns the forwarding member of 1 FHRP group from `_GATEWAY_FHRP_QUERY`.
5. If no anchor limits the rows and the rows have more than 1 anchor, `_anycast_gateway` decides. Without its result, the pick is ambiguous.
6. `src/hst/path/addrsets.py` `_lpm_all` returns the rows with the longest prefix. If more than 1 row stays, the row with the lowest device uid is the gateway, and a warning lists the devices.

```cypher
MATCH (i:Interface:Obj {uid: u, collection_ts: $snap})
OPTIONAL MATCH (i)-[b:BOUND_TO]->(v:VlanInstance)-[rz:REALIZES]->(bound)
OPTIONAL MATCH (i)-[a:ATTACHED_TO]->(attached:BridgeDomain)
OPTIONAL MATCH (s)-[x:EXTENDS*..2]-(s2)
```

In step 3, if each interface with a recorded segment has other segments than the source address row, the gateway is unknown. If no interface has a recorded segment, all rows stay and a note states this. In step 4, the gateway is unknown if the records of the FHRP group do not give 1 forwarding member.

`_anycast_gateway` returns rows only if these 4 conditions are true.

- The attachment device of the flow source is known.
- All rows have the same prefix.
- `_GATEWAY_ADDRESSES_QUERY` returns 1 or more addresses of that prefix that each interface holds.
- `src/hst/path/gates/routing.py` `_NEXT_HOP_DOMAIN_QUERY` returns each other anchor. The query returns an anchor that shares a `RoutingDomain` or an `L3Domain` with the first anchor.

The function then returns the rows of the attachment device. If that device has no row, it returns the rows of the device with the shortest chain of `_L2_CHAIN_QUERY` from the attachment device. Two devices at the same distance give no result. The note of the pick starts with `gateway <address> for <source address> is a distributed anycast gateway on <n> devices`.

A pick without a gateway gives an answer without a leg.

| Pick | Function | Verdict starts with |
|---|---|---|
| ambiguous | `_ambiguous_gateway_result` | `ambiguous: source matches gateway prefixes in` |
| unknown | `_unknown_gateway_result` | `gateway not established:` |
| no row | `_no_gateway_result` | `no gateway found for the source prefix` |

In the example, the source address row has the anchor `vrf:dev:osl01-vyos-01:default` and the segment `bd:vlan:osl01:20`. The interface `eth1.20` is `BOUND_TO` the `VlanInstance` that `REALIZES` that segment.

`_trace_domain` then compares the flow source and the destination with the prefix of the gateway. If the 2 sets are inside the prefix, `_switched_legs_with_crossings` makes the legs. `_gateway_own_part` splits off a destination that is an address of the gateway. In each other case `_walk_from_gateway` continues. The destination 10.18.10.20 of the example is outside 10.18.20.0/24.

### L2 walk

`src/hst/path/trace.py` `_walk_from_gateway` calls `_source_walk`, which calls `_gateway_walk`. `_gateway_walk` reads the trunk of the gateway interface with `_TRUNK_BY_IF_UID_QUERY`.

```cypher
MATCH (i:Interface {uid: $if_uid})
OPTIONAL MATCH (i)-[rb:REALIZED_BY]->(rp:Port)-[c:CONNECTED_TO]-(swp:Port)
```

If the row has no switch port, `_gateway_walk` reads `_TRUNK_BY_PARENT_NAME_QUERY`. That query starts at the interface whose name is the text before the first `.` of the gateway interface name.

| Trunk | Function | Read |
|---|---|---|
| no switch port | `_gateway_device_walk` | `_L2_CHAIN_QUERY` from the attachment device to the gateway device |
| 1 cable | `_trunk_chain` | `_L2_CHAIN_QUERY` from the attachment device to the switch port, without the gateway device |
| more than 1 cable | `_gateway_walk` | no chain, a warning with each peer port, and `l2_boundary` |

```cypher
MATCH (a:Obj {uid: $a, collection_ts: $snap}), (z:Obj {uid: $z, collection_ts: $snap})
MATCH p = allShortestPaths((a)-[:ON|CONNECTED_TO*..12]-(z))
```

For each node of the path, `_L2_CHAIN_QUERY` also returns the `Lag` of a port and the bridge domains of a port. It reads the bridge domains from these 2 patterns.

```cypher
(n)-[c3:CARRIES]->(v3:VlanInstance)-[rz3:REALIZES]->(bd3)
(n)<-[rb:REALIZED_BY]-(:Interface)-[sw:SWITCHES]->(v4:VlanInstance)-[rz4:REALIZES]->(bd4)
```

`_draw_l2_chain` adds 1 hop at the stage `L2_FABRIC` for each port and each device of the chain. The ports of 1 `Lag` are 1 hop of the kind `Lag`. The function compares the bridge domains of each port with the bridge domains of the gateway interface from `_IFACE_SEGMENT_QUERY`. If they have no common bridge domain, it sets `l2_mismatch` and adds a warning. If no port has a bridge domain, it adds a note.

If the attachment device is known and the query returns no chain, the walk adds a warning that starts with `no cable path from` and sets `l2_boundary`.

After the chain, `src/hst/path/trace_draw.py` `_draw_arrival` adds an `Interface` hop at the stage `INGRESS_IF` and a `Device` hop at the stage `DEVICE`. The note of the interface hop is `gateway for <prefix>`. For a trunk with a switch port, `_gateway_walk` first adds the router port as a `Port` hop. If the gateway row has `dev_carried` true, `src/hst/path/trace_draw.py` `_warn_carried` adds a warning.

In the example, the port of the flow source is on the gateway device. `_gateway_device_walk` returns without a read in that case. `src/hst/path/gates/__init__.py` `_Trail.hop` adds a node 1 time for each lane and depth, so the router has 1 `Device` hop.

### Stages of 1 device

`src/hst/path/gates/__init__.py` `Stage` gives the order of the hops of 1 device. The enum has 4 values below `SRC_ENDPOINT`: `IDENTITY`, `BROKER`, `ACCESS_RULE` and `CONNECTOR`.

`src/hst/path/trace.py` `_walk_from_gateway` calls `_device_stage`, which calls `_walk_device`. `_walk_device` does these steps.

1. `_enter_device` records the visit of the device.
2. `src/hst/path/gates/nat.py` `_nat_rows` reads the NAT rules of the device with `_NAT_RULES_QUERY`.
3. `_device_groups` makes 1 part for each destination NAT rule that claims a part of the flow, and 1 part for the rest.
4. `_part_groups` calls `src/hst/path/gates/pbr.py` `_pbr_partition` for each part. That function reads `_INTERFACE_POLICY_RULES` for the ingress interface.
5. `_walk_group` does the route lookup and the later stages for each group.
6. `_credit_device_gates` writes `nat_uids` on each leg, and `pbr_uids` if the device has a PBR policy.

`_NAT_RULES_QUERY` finds the NAT rulebases in 4 branches and then reads the rules.

```cypher
MATCH (d:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
MATCH (d:Device {uid: $dev})-[m:MEMBER_OF]->(rg:RedundancyGroup)-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
MATCH (iin:Interface {uid: $in_if})-[c:IN_CONTEXT]->(fi:FirewallInstance)
MATCH (vs:Device:Obj)-[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
MATCH (i:Interface:Obj {uid: $in_if, collection_ts: $snap})-[c:IN_CONTEXT]->(fi:FirewallInstance)
      -[e:ENFORCES]->(rb:FwRulebase {kind: 'nat'})
MATCH (i)-[v:IN_VRF]->(vrf:VrfInstance)
MATCH (rb)-[hr:HAS_RULE]->(n:NatRule)
```

`_INTERFACE_POLICY_RULES` starts with this pattern.

```cypher
MATCH (ifc:Interface {uid: $if_uid})-[e:ENFORCES]->(pol:PbrPolicy)
```

This code writes the hops of a device after the stage `DEVICE`.

| Stage | Code that writes the hop | Hop |
|---|---|---|
| `DNAT` | `_record_dnat_hop` | `NatRule`, for a group with a destination NAT rule |
| `PBR_POLICY`, `PBR_RULE` | `_record_table_hops` | `PbrPolicy` and `FwRule`, for a group that a PBR rule claims |
| `VRF` | `_record_table_hops` | `VrfInstance`, with the note `main table (no PBR match)` for a group without a PBR rule |
| `ROUTE` | `_record_route_match` | `Prefix` |
| `NEXT_HOP` | `_routed_part_legs` | `NextHop`, only for a route with more than 1 equal path |
| `FILTER_RB`, `FILTER_RULE` | `src/hst/path/gates/firewall.py` `_apply_firewall` | `FwRulebase` and `FwRule` |
| `SNAT` | `src/hst/path/gates/nat.py` `_apply_snat` | `NatRule`, for a part of the flow that a source NAT rule translates |
| `EGRESS_FILTER_RB`, `EGRESS_FILTER_RULE` | `src/hst/path/gates/firewall.py` `_apply_egress_acl` | `FwRulebase` and `FwRule`, for an outbound interface ACL with a verdict |
| `EGRESS_IF` | `_egress_snat_tunnel` | `Interface`, with the note `egress` |
| `ENCAP` | `_egress_snat_tunnel` | `Tunnel`, if `_EGRESS_TUNNEL_QUERY` gives a tunnel for the egress interface |
| `DST_FABRIC`, `DST_ATTACH`, `DST_ENDPOINT` | `_delivery_walk` | `Port`, `Lag`, `Device` and `Endpoint` |

`_egress_snat_tunnel` calls `_apply_snat` and `_apply_egress_acl` before it writes the egress hop. This doc does not walk the stages `LOAD_BALANCER`, `CARRIER_ROUTE` to `CARRIER_EGRESS_IF`, `TRANSPORT`, `LINK` and `DECAP`. [Serving](serving.md#tracer) describes the tracer.

In the fixture, the router `ENFORCES` 3 rulebases of the kind `nat`. `eth1.10` is the only interface that `ENFORCES` the 2 `PbrPolicy` nodes.

### Route lookup

`src/hst/path/trace.py` `_walk_group` reads the routes of 1 table from the graph and from the side store.

`_family_routes` reads `_ROUTES_QUERY` for the uid of the table. It drops the routes of the other address family.

```cypher
MATCH (v:VrfInstance {uid: $vrf})-[r:STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES]->(p:Prefix)
OPTIONAL MATCH (p)-[via:VIA {vrf: $vrf}]->(egress:Interface)
```

The query has 2 branches.

- Branch 1 reads the pattern above. It leaves out an `ORIGINATES` relationship with `proto` `network`. For `proto` `aggregate` it returns the kind `AGGREGATE` with `discard` `blackhole`.
- Branch 2 adds the routes that the table imports over route targets, from `src/hst/core/reasoner.py` `RT_IMPORTED_ROUTES`. Each row has the kind `LEARNED_ROUTE`, `derived` `rt-import`, no next hop and no egress.

`_rib_lookup` makes 2 lookups on the `src/hst/core/ribsource.py` `RibSource` of the request: `RibSource.lpm` and `RibSource.overlapping`. The 2 methods read the side-store table `rib`. `RibSource.lpm` selects the rows with these values:

- `device_uid` is the uid of the device
- `context_uid` is the uid of the table, or `context_uid` is null and `vrf` is the name of the table
- `run_id` is the run id that the reader selects for the device
- `af` is the address family of the destination
- the range `lo` to `hi` holds the destination address
- `prefixlen` is the maximum of the rows that pass the conditions above

`src/hst/core/ribsource.py` `for_snapshot` gives the reader the files that the manifest of the run publishes. For a run without a manifest, the reader reads each file below `rib` and selects 1 run id for each device with `src/hst/core/ribsource.py` `pick_run`. `RibSource.approximate` is then true, and `_walk_group` adds a note. The note starts with `RIB evidence is approximate`.

`_walk_group` then does these steps.

1. `_pbr_fall_through` changes the table to the table of the ingress interface if the PBR target table has no route for the flow.
2. `_record_table_hops` adds the hops of the table.
3. `_rib_gap` returns the reason for which the side store has no answer for the device. If the request has a RIB reader and the function returns no reason, `observed` is true.
4. If `observed` is false, `_rib_mirrored` reads `rib_mirrored` of the `VrfInstance`.
5. `_router_local_part` reads `_OWN_ADDRS_QUERY`. A destination that is an address of the device does not go to the route lookup.
6. `_routed_parts` calls `src/hst/path/gates/routing.py` `_route_partition`.
7. `_routed_part_legs` makes the legs of each part.
8. `_mark_rib_gap` marks legs if `_rib_gap` returned a reason. [Missing data](#missing-data) has the rule.

`_route_partition` selects the routes for the first address of the destination set and repeats for the rest of the set.

- It gets the side-store rows from `RibSource.lpm`.
- A side-store row with the prefix and the next hop of a graph route sets `rib` on the graph route. A route without a next hop compares the interface.
- A connected side-store row sets `rib` on the `ORIGINATES` route with the same prefix.
- Each other side-store row is a candidate of the kind `RIB` without a uid.
- `src/hst/path/addrsets.py` `_lpm_all` keeps the candidates with the longest prefix.
- `_route_provenance` compares the tied candidates. If the device holds 1 or more of them, it drops each `STATIC_ROUTE` without `rib` and each derived route. An `AGGREGATE` route loses to each other kind. A `STATIC_ROUTE` with `discard` stays unless `observed` is true.
- With `observed`, the winners go to `_mark_unconfirmed`. With `mirrored`, they go to `_mark_mirrored_unconfirmed`.

`_routed_part_legs` adds a leg from `src/hst/path/gates/routing.py` `_no_route_leg` if a part has no route. For a part with a route, `_record_route_match` adds the `Prefix` hop. The hop of a side-store row has the uid `rib:<device uid>:<table uid>:<prefix>`, and a note holds the text `rib matched`.

Each route of an equal-cost set gets 1 lane. If the set has more than 1 route, each lane with a next hop gets a `NextHop` hop with the uid `<route uid or prefix>#nh:<next hop>`. The setting `PATH_LANE_CAP` limits the lanes of 1 trace, and the default is 64. If routes stay outside the limit, each leg of the part is `indeterminate` and a warning lists the routes.

`_walk_route` then handles 1 route. For a route with `discard`, `_discard_leg` makes a blocked leg. For each other route, `_resolve_route_egress` finds the egress interface.

- A route with an interface name and no egress uid reads `_IFACE_BY_NAME_QUERY` on the device.
- A route with a `Prefix` uid and no egress calls `src/hst/path/gates/routing.py` `_connected_egress`.

`_connected_egress` reads this pattern in 3 queries and stops at the first row.

```cypher
MATCH (i:Interface)-[g:GATEWAY_FOR]->(p:Prefix {uid: $p})
```

| Query | Interface | Result |
|---|---|---|
| `_CONNECTED_LOCAL_QUERY` | on the device, other than the ingress interface | the egress interface of the route |
| `_CONNECTED_INGRESS_QUERY` | the ingress interface | no egress, and the note `intra-network, no zone boundary to evaluate` |
| `_CONNECTED_REMOTE_QUERY` | on a device of the run | the interface with the lowest uid, for the zone policy only |

`_route_region_legs` then makes the leg with `_build_route_leg`. A leg is `indeterminate` at this point if its route is derived from a route target or has `unconfirmed`.

In the example, the manifest of the run publishes no side-store file, and the table has `rib_mirrored` true. The graph route for 10.18.10.20 is the `ORIGINATES` relationship to `pfx:vrf-dev-osl01-vyos-01-default:10.18.10.0/24`. `eth1.10` holds the address 10.18.10.1 in that prefix.

### Firewall gate

For a route with an egress interface on the device, `src/hst/path/trace.py` `_route_egress` calls `_local_egress_stage`. That function calls `src/hst/path/gates/firewall.py` `_apply_firewall`, which calls `_firewall_verdict`.

`_firewall_verdict` reads the rulebases in 2 forms. `_zone_pair_verdict` holds the query of the zone pair.

```cypher
MATCH (iin:Interface:Obj {uid: $in_if, collection_ts: $snap})<-[ci:CONTAINS]-(src:Zone)
MATCH (iout:Interface:Obj {uid: $out_if, collection_ts: $snap})<-[co:CONTAINS]-(dst:Zone)
MATCH (rb:FwRulebase)-[fz:FROM_ZONE]->(src), (rb)-[tz:TO_ZONE]->(dst)
```

`_RULEBASE_CANDIDATES` finds the rulebases of the device in 3 branches. It returns only a rulebase without a `FROM_ZONE` or `TO_ZONE` relationship.

```cypher
MATCH (dev:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase:Obj)
MATCH (dev:Device {uid: $dev})-[e2:MEMBER_OF]->(:RedundancyGroup)-[e3:ENFORCES]->(rb:FwRulebase:Obj)
MATCH (iin:Interface {uid: $in_if})-[c:IN_CONTEXT]->(fi:FirewallInstance)
MATCH (vs:Device:Obj {collection_ts: $snap})-[e5:ENFORCES]->(rb:FwRulebase)
```

The query also returns the interface ACL bindings of a rulebase from `(bi:Interface)-[pb:PROTECTED_BY]->(rb)`.

`_RULEBASE_RULES` reads the rules of 1 rulebase.

```cypher
MATCH (rb:FwRulebase {uid: $rb})-[hr:HAS_RULE]->(r:FwRule)
OPTIONAL MATCH (r)-[:SVC]->(sv0:SvcObject)
OPTIONAL MATCH (r)-[:SRC]->(so:NetObject) OPTIONAL MATCH (so)-[:RESOLVES_TO]->(st)
OPTIONAL MATCH (r)-[:DST]->(do:NetObject) OPTIONAL MATCH (do)-[:RESOLVES_TO]->(dt)
```

If the 2 forms give a verdict, `_both_rulebase_models` selects 1 verdict. A deny is first, an undecided verdict is second and a permit is third.

`_apply_firewall` adds this to the answer:

- a `FwRulebase` hop at the stage `FILTER_RB` with the note `<zones> · <action> (<by>)`
- a `FwRule` hop at the stage `FILTER_RULE`, if a rule decided
- the leg key `firewall` with the text `<rulebase> (<zones>) <action> by rule <position>` or `<rulebase> (<zones>) <action> by default-action`
- the leg key `fw_uid` with the uid of the rulebase
- the leg key `fw_uids` with the uids that `_firewall_verdict` adds to its list `considered`
- a note with the text of `firewall` at its end

| Outcome | Leg |
|---|---|
| permit | no change |
| deny | `blocked` true and `verdict` `BLOCKED by <rulebase> <by>` |
| undecided | `indeterminate` true, and a warning with the reason |
| no rulebase governs the device | no `firewall` key |
| no rulebase governs a VSX virtual system | `indeterminate` true and `firewall` `VS policy not established` |

`_apply_firewall` also writes the leg key `gate_state`. `_capture_reply_state` removes that key before the answer.

After a deny, `_route_region_legs` calls `_blocked_destination` and the leg ends. After each other outcome, `_egress_snat_tunnel` continues. If it does not block the leg, `_local_egress_stage` sets the leg `verdict` to `egress via <interface>`.

In the fixture, the zone `IOT` `CONTAINS` `eth1.20` and the zone `LAN` `CONTAINS` `eth1.10`. The rulebase `IOT-LAN` goes from `IOT` to `LAN`. Its rule at position 10 has the action `accept`, the service `tcp/1883` and the destination object `NAS`. The object `NAS` `RESOLVES_TO` `ip:osl01:10.18.10.20`.

### Next hop

`src/hst/path/trace.py` `_route_region_legs` calls `_next_hop_stage` for each leg that is not blocked. For a route with a next hop, `_next_hop_stage` calls `src/hst/path/gates/routing.py` `_next_hop_device`, which reads `_NEXT_HOP_DEVICE_QUERY`.

```cypher
MATCH (i:Interface)-[h:HAS_IP]->(ip:IpAddress:Obj)
MATCH (i)-[o:ON]->(d:Device)
```

For an IPv6 link-local next hop, `_link_local_owner` reads `_LINK_PEER_QUERY` on the link of the egress interface.

If all rows are in 1 context, `_next_hop_device` selects the owner from them. Rows with the same FHRP protocol and group on the `HAS_IP` relationship count as 1 context. If the rows are in more than 1 context, the function tries 4 sets of rows in this order. It uses the first set that is not empty.

| Order | Rows of the set |
|---|---|
| 1 | `anchor` is the table of the route |
| 2 | `anchor` shares a `RoutingDomain` or an `L3Domain` with the table, from `_NEXT_HOP_DOMAIN_QUERY` |
| 3 | `_anchor_of` of the row is `_anchor_of` of the gateway |
| 4 | the row has no `anchor` and has the `l3dom` of the gateway |

```cypher
MATCH (tbl:VrfInstance {uid: $table})-[m1:MEMBER_OF]->(rd:RoutingDomain)<-[m2:MEMBER_OF]-(v:VrfInstance)
MATCH (tbl:VrfInstance {uid: $table})-[r1:REALIZES]->(ld:L3Domain)<-[r2:REALIZES]-(v:VrfInstance)
```

If the set is in more than 1 context, the function returns no owner and a reason that ends with `trace stopped`.

The function handles 2 or more rows of 1 context as follows.

| Rows | Owner |
|---|---|
| 1 row has the HSRP state `active` or the VRRP state `master` | that row, with a `tie_note` |
| 2 or more rows have that state | no owner |
| no row has that state | the row with the lowest device uid and interface uid, with a `tie_note` and the other rows in `tie_rivals` |

`_single_owner_scope` then compares the context of the owner with the table of the route. Two VRFs that are not global, have different values of `name` and share no domain stop the trace. An owner in a context without a recorded relation to the table gets a `context_note`.

`_next_hop_stage` handles an owner with `tie_rivals` in 3 steps.

1. It draws the walk through the owner.
2. It walks each rival on a copy of the trail and compares the result of `_walk_outcomes`.
3. If a rival gives another result, each drawn leg is `indeterminate` and a warning ends with `no record names the device that forwards`.

A trace walks a maximum of 16 rivals, the value of `_TIE_PROBE_CAP`. A rival outside the limit makes the drawn legs `indeterminate` too. If each rival gives the same result as the owner, the legs do not change and the `tie_note` is a note.

`_next_hop_walk` does the walk through 1 owner. `_next_hop_stop_reason` returns a reason in 4 cases, and the leg is then `indeterminate` with a warning.

- `_next_hop_device` returned a reason and no owner.
- No connected prefix, host route or address of the device in the table covers the next hop.
- The device of the owner is in the visited set for the table of the far leg.
- The depth of the far device is at the hop limit.

Without a reason, `_draw_arrival` adds the `Interface` hop and the `Device` hop of the owner at the next depth. `_device_stage` then runs for that device, and its legs are the answer for the flow.

If the route has a next hop and no interface holds it, `_next_hop_walk` sets `boundary` on the leg. It then writes `left_estate` on the leg, or adds a warning that ends with `the path leaves the twin at <device>`.

The route of the example has no next hop, so `_next_hop_stage` returns no far leg.

### Delivery

`src/hst/path/trace.py` `_route_region_legs` delivers a leg on the device if 2 conditions are true.

- The destination is 1 address.
- The route is intra-network, has an egress from `_connected_egress`, or has the kind `ORIGINATES`.

If the load balancer checks claim no part of the leg, `_deliver_locally` calls `_dst_attachment` and `_delivery_walk`.

`_dst_attachment` gets the rows of the destination address from `_source_candidates`. It reads the segments of the egress interface with `_IFACE_SEGMENT_QUERY`, which has the patterns of `_IFACE_SEGMENTS_QUERY` for 1 interface. A row whose anchor or segment is in those segments is first. Without such a row, the first row with the anchor of the gateway is the result.

`_delivery_walk` reads `_L2_CHAIN_QUERY` from the egress interface to the attachment device of the destination. It adds this to the answer:

- the hops of the chain at the stage `DST_FABRIC`, from `_draw_l2_chain`
- a `Device` hop and a `Port` hop at the stage `DST_ATTACH`
- an `Endpoint` hop at the stage `DST_ENDPOINT`

If the 2 ends are known and the query returns no chain, the function adds a warning and sets `l2_boundary`. `_delivery_walk` returns true if the row of the destination holds an endpoint, and `_deliver_locally` writes that value to the leg key `delivered`.

A route without a next hop and without a tunnel, to a network that the device does not serve, goes to `_mark_twin_exit`. That function sets `boundary`.

The fixture holds 2 `IpAddress` nodes with the address 10.18.10.20. The node `ip:osl01:10.18.10.20` has no `HAS_IP` relationship, so `_source_candidates` drops its row. `_dst_duplicate_notes` adds 1 note for that node. The 2 endpoints of the example are on the same port, and `_Trail.hop` adds the port 1 time.

### Answer

`src/hst/path/trace.py` `_finish_trace` makes the result of the walk. `src/hst/results/trace.py` `project_walk` renames each `verdict` to `detail` and adds `result`.

| Key | Content |
|---|---|
| `hops` | the hops in the order of the walk |
| `legs` | 1 leg for each path of the flow |
| `detail` | the verdict line from `_combined_verdict`, the text of `_flow_gates` and the text of the exits |
| `result` | the answer for the statement `trace-forwards` |
| `notes` | each note and each warning |
| `warnings` | each warning |
| `indeterminate` | true if a leg is `indeterminate` |
| `boundary` | true if a leg has `boundary` |
| `left_estate` | the exits at the edge of the estate |
| `reach` | the value of `_walk_reach` for the ends of the legs, or null if the answer of `result` is other than `true` |
| `run` | the run of the answer |

`src/hst/path/gates/__init__.py` `_Trail.hop` writes these keys of a hop: `uid`, `kind`, `label`, `note`, `stage`, `lane`, `shared`, `layer`, `tier` and `gate`. `_Trail.rank_hops` adds `rank`. A hop inside a tunnel walk also has `overlay` and `tunnel`. A hop inside a transport walk also has `transport`.

`_build_route_leg` writes these keys of a leg: `lane`, `sources`, `cidr`, `egress`, `next_hop`, `blocked`, `indeterminate`, `table`, `src_label`, `context_uid` and `device_uid`. `_finish_trace` adds `interpretation`. The steps above add `detail`, `result`, `firewall`, `fw_uid`, `fw_uids`, `nat_uids`, `pbr_uids`, `delivered`, `boundary`, `left_estate`, `indeterminate_reason`, `dnat`, `nat_chain` and `dst_label`.

A `result` object is a `src/hst/results/words.py` `Result` with the keys `kind`, `statement`, `answer`, `word`, `quantifier`, `condition` and `missing`. The `statement` of a leg is `hop-forwards`. The `answer` is `true`, `false` or `open`.

For 1 leg, `_combined_verdict` writes `<flow>: <verdict of the leg> (<prefix>, main table)`. For a table with another name than `main` or `default`, the text is `table <name>`.

`src/hst/core/cycle.py` `run_status` returns the 8 keys of `run`: `snapshot`, `created`, `degraded`, `sources_carried`, `sources_failed`, `sources_partial`, `sources_cancelled` and `freshness`.

### Answer of the example

The trace of the example returns `reach` with the value `destination` and 1 leg with `delivered` true. The leg has the `firewall` text `IOT-LAN (IOT→LAN) accept by rule 10`. The answer has 10 hops.

| Stage | Kind | Label |
|---|---|---|
| `SRC_ENDPOINT` | `Endpoint` | `osl01-cam-01` |
| `SRC_ATTACH` | `Port` | `eth1` |
| `SRC_ATTACH` | `Device` | `osl01-vyos-01` |
| `INGRESS_IF` | `Interface` | `eth1.20` |
| `VRF` | `VrfInstance` | `default` |
| `ROUTE` | `Prefix` | `10.18.10.0/24` |
| `FILTER_RB` | `FwRulebase` | `IOT-LAN` |
| `FILTER_RULE` | `FwRule` | `rule 10 (mqtt to nas)` |
| `EGRESS_IF` | `Interface` | `eth1.10` |
| `DST_ENDPOINT` | `Endpoint` | `osl01-nas-01` |

## The impact call

### Route and child process

`POST /api/impact/evaluate` is `src/hst/app/routes/impact.py` `post_impact_evaluate`. The body is a `src/hst/assessment/evaluation.py` `EvaluateBody` with the fields `intents`, `requirement`, `request`, `mode` and `snapshot`. The default of `mode` is `possible`. The route resolves the run and pins the session as the path call does. It calls `src/hst/assessment/direct.py` `evaluate_request` and adds the keys `snapshot` and `run` to the answer.

`evaluate_request` refuses more than 50 intents with the status 422. It calls `evaluate_pinned`, which does these checks.

| Check | Status |
|---|---|
| the body has `requirement` and `request`, or none of the 2 | 400 |
| `mode` is other than `possible` or `guaranteed` | 400 |
| the pointer has no run, or the run has no manifest | 409 |
| the population selector of the request cannot bind | 422 |

`evaluate_pinned` then calls `run_isolated` with 3 inputs.

- `definition` holds the request, the mode and the intents.
- `analysis` holds the kind `evaluate` and the limits.
- `snapshot_refs` holds the run key, the digest of the manifest, the estate and `observation_floor_ms`.

`run_isolated` takes the process slot `src/hst/assessment/jobs.py` `PROCESS_CAPACITY`, which has 1 place. If the slot is busy, the status is 503. `_run_owned` starts 1 child process with the entry `src/hst/assessment/jobs.py` `_execute_child`. The child runs `src/hst/assessment/service.py` `execute`.

| Setting | Default | Use |
|---|---|---|
| `ANALYSIS_ENABLED` | true | With the value false, the status is 503. |
| `ANALYSIS_MEMORY_MB` | 1024 | the memory limit of the child |
| `ANALYSIS_TIMEOUT_S` | 120 | the time limit of the child |

If the child reaches a limit or ends without a result, the status is 503. In the child, `execute` writes the `result` objects with `src/hst/results/project.py` `project_engine`. After the child returns, `evaluate_request` calls `src/hst/results/project.py` `project_evaluation` on the answer.

### Requirement

With the field `requirement`, `src/hst/assessment/evaluation.py` `_request_from_requirement` reads `_REQUIREMENT_QUERY` in the pinned session.

```cypher
MATCH (sr:ServiceRequirement:Obj {uid: $req, collection_ts: $snap})
OPTIONAL MATCH (sr)-[s:SRC]->(src)
OPTIONAL MATCH (app:BusinessService)-[dep:DEPENDS_ON]->(sr)
OPTIONAL MATCH (sr)-[h:HAS]->(root:DependencyGroup)
```

`_group_tree` then reads `_GROUP_QUERY` for 1 level of groups at a time, to a depth of 16.

```cypher
MATCH (g:DependencyGroup:Obj)
OPTIONAL MATCH (g)-[hm:HAS_MEMBER]->(sub:DependencyGroup)
OPTIONAL MATCH (g)-[dep:DEPENDS_ON]->(t)
```

The request set gets these values from the 2 queries.

| Part of the request set | Read from |
|---|---|
| source addresses | `cidr` or `ip` of each node at the end of `SRC` |
| service | `proto`, `dport` and `sport` of the `ServiceRequirement` |
| member | each node at the end of `DEPENDS_ON` of a group, with its `uid` as the name |
| address of a member | `cidr`, `ip` or `vip` of that node |
| condition | the tree of the groups |

`_GROUP_KIND_TO_CONDITION` maps the `kind` of a `DependencyGroup` to the condition.

| `kind` | Condition |
|---|---|
| `and` | `every` |
| `or` | `any-one` |
| `threshold` | `n-of-m`, with the property `n` of the group |
| `capacity` | `capacity` |

A uid without a `ServiceRequirement` node gives the status 404. A requirement without a group, a group without a member and without a nested group, and a member without an address give the status 400. `evaluate_pinned` converts the request set to a document with `src/hst/assessment/request_document.py` `request_document`.

With the field `request`, `src/hst/assessment/evaluation.py` `RequestBody` and `_request_from_body` do the checks of the request. The request of the example has 1 source address, 1 member and a condition of the kind `member`. Its `success` is the default `forward`. The `intents` list of the body is empty.

### Network model

In the child, `src/hst/assessment/service.py` `execute` calls `_execute`, which opens an `EvaluationContext`. `EvaluationContext.__enter__` reads the network model in these steps.

1. It opens a session of its own with `src/hst/core/db.py` `session` and resolves the run key of `snapshot_refs`.
2. It compares the digest of the manifest with `manifest_sha256` of `snapshot_refs`. A manifest that is gone or has another digest stops the evaluation.
3. It pins the session.
4. It makes 3 side-store readers for the run.
5. It calls `src/hst/assessment/evaluation.py` `load_network` and closes the readers.

| Reader | Side-store tables |
|---|---|
| `src/hst/core/ribsource.py` `for_snapshot` | `rib` |
| `src/hst/core/bgpsource.py` `for_snapshot` | `bgp_sessions`, `bgp_session_routes` |
| `src/hst/core/ospfsource.py` `for_snapshot` | `ospf_lsdb` |

`load_network` does 4 reads.

- `_model_interfaces` reads `_NETWORK_INTERFACES_QUERY`.
- For a request with an MTU requirement, `src/hst/core/mtu_read.py` `read_mtu` reads the MTU observations of the interfaces.
- `src/hst/app/simul_read.py` `read_rib_input` reads the input of the routing calculation from the pinned session and the 3 readers.
- `_context_domains` reads `_CONTEXT_DOMAINS_QUERY`.

```cypher
MATCH (i:Interface:Obj)-[o:ON]->(d:Device)
OPTIONAL MATCH (i)-[iv:IN_VRF]->(v:VrfInstance)
OPTIONAL MATCH (i)-[m:MEMBER_OF*0..1]->(gw)-[gf:GATEWAY_FOR]->(p:Prefix)
OPTIONAL MATCH (i)-[hi:HAS_IP]->(ip:IpAddress)
MATCH (w:WanLink)-[won:ON]->(i)
MATCH (i)-[bt:BOUND_TO]->(vl:VlanInstance)-[rz:REALIZES]->(s0)
OPTIONAL MATCH (s0)-[x:EXTENDS*..2]-(s1)
```

`_CONTEXT_DOMAINS_QUERY` reads 3 patterns for each `VrfInstance`.

```cypher
MATCH (v)-[m:MEMBER_OF]->(rd:RoutingDomain)
MATCH (v)-[r:REALIZES]->(ld:L3Domain)
MATCH (v)<-[iv:IN_VRF]-(i:Interface)-[h:HAS_IP]->(ip:IpAddress)
```

`load_network` returns a `src/hst/impact/evaluate.py` `Network`. The network holds the routing input, the interfaces, the routing domains of each context and a `src/hst/impact/evaluate.py` `GraphGates` on the pinned session.

`EvaluationContext.__enter__` reads 3 stores: Neo4j, the side store and the manifests. [Storage](storage.md) describes them.

### Engines

The setting `ANALYSIS_ENGINE` has the values `legacy-v1` and `symbolic-v2`, and the default is `legacy-v1`. `src/hst/assessment/service.py` `EvaluationContext.uses_symbolic` reads the setting. The 2 engines run in the child process, in `EvaluationContext._evaluate`.

With `legacy-v1`, `_evaluate` calls `src/hst/assessment/evaluation.py` `evaluate_change` with `detail` true and the network of `load_network`. `_evaluate_change` calls `src/hst/impact/evaluate.py` `evaluate`, which does 3 steps.

1. `answer` evaluates the request set on the network. It runs 1 `_Walk` for each member.
2. `apply` makes the network after the change set, and `answer` evaluates the request set on it.
3. `compare` returns the differences of the 2 answers.

With `symbolic-v2`, `_evaluate` does these steps.

1. `EvaluationContext._symbolic_engine` reads the graph with `src/hst/analysis_model/graph.py` `load_graph` and makes a `src/hst/assessment/symbolic_evaluation.py` `SymbolicEvaluation`.
2. `EvaluationContext.change_set` reads the intents with `src/hst/analysis_model/native_changes.py` `native_changes` on the graph of step 1.
3. `SymbolicEvaluation.compare_networks` evaluates the request set on the network and on the result of `src/hst/impact/evaluate.py` `apply`.

`_execute` then adds `constraints` and `verdict` to the answer of the engine. Its inner function `finish` adds the keys of the evaluation.

### Answer

The answer of `legacy-v1` has these keys after `src/hst/results/project.py` `project_engine`.

| Key | Content | Code that writes |
|---|---|---|
| `snapshot`, `run` | the run of the answer | `finish` in `_execute`, `post_impact_evaluate` |
| `kind`, `snapshot_refs`, `mode`, `dependencies`, `assumptions`, `engine_evaluations`, `evaluation_budget_unit`, `elapsed_seconds` | the evaluation | `finish` in `_execute` |
| `constraints`, `result` | the constraints and their verdict | `_execute` |
| `outcomes` | `before` and `after`, each with `result`, `isolated`, `passes`, `fails` and `open` | `src/hst/assessment/evaluation.py` `outcome` |
| `request` | `name`, `destination`, `sources`, `members`, `condition`, `requirement`, `success`, `source_context`, `source_device_uid`, `identity_uid`, `segment_uid` | `_evaluate_change` |
| `intents`, `contexts_in_scope` | the change set and the forwarding contexts of the model | `_evaluate_change` |
| `decided_change`, `open_change` | each with `loss` and `gain` | `_evaluate_change` |
| `passes`, `fails`, `open` | each with `before` and `after` | `_evaluate_change` |
| `triage` | the parts of the comparison that do not overlap | `_evaluate_change` |
| `members` | 1 row for each member | `_member_rows` |
| `evidence` | `count`, `items` and `truncated` | `_evaluate_change`, with the items of `_evidence` |
| `missing_evidence`, `gaps`, `model_errors` | [Missing data](#missing-data) | `_evaluate_change` |

`project_engine` renames keys of the engine with 4 tables of `src/hst/results/project.py`.

| Table | Engine key | Answer key |
|---|---|---|
| `BUCKET_NAMES` | `proven`, `possible`, `not_established`, `condition_holds`, `condition_fails` | `decided_change`, `open_change`, `open`, `passes`, `fails` |
| `CHANGE_NAMES` | `proven_loss`, `possible_loss`, `proven_gain`, `possible_gain` | `decided_loss`, `open_loss`, `decided_gain`, `open_gain` |
| `PART_NAMES` | `holds`, `does-not-hold`, `fails`, `not-established`, `unknown` | `passes`, `fails`, `fails`, `open`, `open` |
| `TRIAGE_NAMES` | `proven_loss`, `worked_now_unknown`, `unknown_now_broken`, `unknown_throughout`, `proven_gain`, `unknown_now_works`, `broken_now_unknown` | `decided_loss`, `passes_then_open`, `open_then_fails`, `open_throughout`, `decided_gain`, `open_then_passes`, `fails_then_open` |

It also renames a `verdict` with an engine value to `result`, and the `outcome` of an evidence item to `result`.

An item of `evidence.items` has the keys `side`, `member`, `result`, `steps`, `missing` and `request_region`. A step has the keys `device_uid`, `stage`, `kind`, `detail` and `unknown`.

Because `detail` is true, `evidence.items` holds each item, `truncated` is false and the answer has `outcomes`. If the body has `requirement`, `evaluate_pinned` writes the uid to `request.requirement`. If the body has `request`, `src/hst/assessment/service.py` `EvaluationContext._population_result` adds the keys `population`, `population_artifact`, `population_complete`, `population_gaps` and `population_scope` to `request`.

With `symbolic-v2`, `SymbolicEvaluation.compare_networks` makes the answer from `src/hst/assessment/symbolic_results.py` `comparison`. `_evaluate` adds `intents`, `snapshot` and the model errors of `load_network`. The answer has the keys of the table of `legacy-v1` without `contexts_in_scope`, and these other keys.

| Key | Content | Code that writes |
|---|---|---|
| `semantic_version`, `result_schema` | the values `symbolic-v2` and 2 | `comparison` |
| `complete`, `completion_status` | true and `complete` if the 2 sides are complete, false and `incomplete` in each other case | `comparison` |
| `units` | `population` with the value `client-addresses`, `display` with the value `CIDR-prefixes` | `comparison` |
| `symbolic` | `backend`, `header_schema`, `ordering_version`, `model_fingerprints`, `database_reads_during_walk`, `build`, `preflight`, `artifact_sha256`, `artifact_ref`, `cache` and `metrics` | `comparison`, `SymbolicEvaluation.compare_networks` |

Each side of `outcomes` also has `display_truncated` and `counts`. `request` also has `proto`, `port`, `source_port`, `ingress_interface_uid`, `destination_context` and `header_constraints`. `evidence` also has `observations`, and `evidence.items` holds a maximum of 100 items.

`src/hst/assessment/symbolic_results.py` `_evidence` writes each item of `evidence.items`. An item has the keys `side`, `member`, `kind`, `choice`, `state`, `outcome`, `gap_code`, `packet_scope`, `observation_scope`, `observation_refs`, `missing`, `steps`, `artifact_root`, `manifest_sha256`, `model_fingerprint` and `request_id`. `project_engine` renames `outcome` to `result` for an item with the outcome `unknown`. An item with the outcome `permit`, `deny` or `no_route` keeps `outcome`.

### Answer of the example

With the engine `legacy-v1` and the mode `possible`, the impact call of the example returns `open` in `result.answer`. `evidence.items` holds 1 item for each of the 2 sides `before` and `after`. An item has 2 steps.

| `stage` | `kind` |
|---|---|
| `entry` | `attach` |
| `gate-coverage` | `indeterminate` |

The `missing` list of the item holds 1 text: `gate-coverage on dev:osl01-vyos-01: applicable gate(s) were not evaluated: ObservationGap evidence:dev:osl01-vyos-01`.

## Missing data

### Path answer

A leg has `indeterminate` true if the walk cannot decide it. `indeterminate_reason` holds the first reason. The code of the steps above sets `indeterminate` in these cases.

| Code in `src/hst/path/trace.py` | Condition |
|---|---|
| `_build_route_leg` | a NAT rule or a PBR rule claims the flow and is not decided |
| `_build_route_leg` | the route comes from a route target, or the route has `unconfirmed` |
| `_egress_snat_tunnel` | the tunnel of the egress interface is not decided |
| `_next_hop_walk` | `_next_hop_stop_reason` returns a reason |
| `_warn_context_crossing` | the owner of the next hop has a `context_note` |
| `_next_hop_stage` | 2 owners of the next hop give different results |
| `_routed_part_legs` | equal-cost routes are outside `PATH_LANE_CAP` |
| `_mark_rib_gap` | the side store has no answer for the device |
| `_trace_domain` | a part of the flow source is outside the prefix of the gateway |
| `_finish_trace` | `l2_boundary` is true, for a leg that is not blocked and has a route |
| `_finish_trace` | `l2_mismatch` is true, for a leg with a mismatch on the L2 walk to the gateway, or a leg that is not blocked and has a route |
| `_check_delivery_context` | the leg ends outside the context of the parameter `dst_context` |
| `_flow_gates` | the ACI contract verdict is undecided |
| `_gate_coverage` | a gate on a device of the path has no verdict, or the run did not collect the policy of a device completely |

`src/hst/path/gates/firewall.py` `_apply_firewall` sets `indeterminate` for an undecided verdict and for a VSX virtual system without a rulebase. It also sets the key for a permit that covers only a part of the flow.

`_gate_coverage` finds the gates with `src/hst/path/gates/__init__.py` `unevaluated_gates`. [Graph schema](schema.md#gate-bindings) holds the gate bindings that the query of that function reads.

The answer has these other signals.

| Signal | Code that sets it | Content |
|---|---|---|
| `indeterminate` of the answer | `_finish_trace`, `_merge_lanes`, `_ambiguous_gateway_result`, `_unknown_gateway_result` | true if a leg is `indeterminate`, a source address row is not traced or the gateway is not decided |
| `boundary` | `_finish_trace`, `_next_hop_walk`, `_mark_twin_exit` | an L2 part without a cable path, a next hop that no interface holds, or a route without a next hop to a network that the device does not serve |
| `left_estate` | `_next_hop_walk`, `_mark_twin_exit` | the exit, if the path ends at the edge of the estate |
| `warnings` | `src/hst/path/gates/__init__.py` `_Trail.warn` | each text that the walk cannot prove |
| `detail` | `_combined_verdict` | for 1 leg, the text `; INDETERMINATE, <reason>` |
| `detail` | `_gate_coverage` | the text `<n> gate(s) not evaluated` or `policy of <n> device(s) not collected completely` |
| `result.missing` of a leg | `src/hst/results/trace.py` `leg_result` | the code `hop-not-decided` or `l2-path-not-found` |
| `result.missing` of the answer | `src/hst/results/trace.py` `walk_result` | the entries of the first open leg, or the code `no-hop` or `not-decided` |
| `reach` | `src/hst/results/trace.py` `project_walk` | null if the answer of `result` is other than `true` |
| `run` | `src/hst/core/cycle.py` `run_status` | `degraded`, `sources_carried`, `sources_failed`, `sources_partial`, `sources_cancelled` and `freshness` |
| a note | `_walk_group` | the text of `_APPROXIMATE_RIB_NOTE`, for a run without a manifest |
| a note | `_draw_l2_chain` | a text that starts with `VLAN carriage not verified` |
| a warning | `src/hst/path/trace_draw.py` `_warn_carried` | `<device>: state carried forward from an earlier run (<reason>)` |

`_warn_carried` writes 1 of 4 reasons from `_CARRIED_WHY`:

- `its source did not run this cycle`
- `its collection failed this cycle`
- `its collection was stopped this cycle`
- `a section of it was not collected this cycle`

A device with `carried_reason` `unchanged` gets no warning.

`_rib_gap` returns a reason and the flag `recorded` for a device.

| State of the side store for the device | `recorded` |
|---|---|
| `src/hst/core/ribsource.py` `RibSource.available` is false | false |
| `RibSource.coverage` returns `failed` or `partial` | true |
| `RibSource.coverage` returns `complete-empty` | true |
| `RibSource.coverage` returns `missing` | true |
| `RibSource.coverage` returns `unknown` | true |
| `RibSource.has_rows` is false | false |

`_mark_rib_gap` adds the reason `RIB of <device> table <table> not consulted (<reason>); routed on graph edges only`. With `recorded` true, it marks each routed leg of the group and each leg of a later device. With `recorded` false, it marks only a leg without a route or with a default route. It does that only if the side store is not available or a `RoutingProcess` is `IN_VRF` of the table.

An answer without a leg holds the reason in `detail`.

| `detail` | Function |
|---|---|
| ends with `: not an address, prefix or range` | `trace` |
| `source <src> is not in the graph` | `_trace_host_source` |
| `source <src> has no gateway in context <context>` | `_trace_network_source` |
| starts with `ambiguous: source matches gateway prefixes in` | `_ambiguous_gateway_result` |
| starts with `gateway not established:` | `_unknown_gateway_result` |
| starts with `no gateway found for the source prefix` | `_no_gateway_result` |

`_no_gateway_result` reads `_UNROUTED_INTERFACES_QUERY`. The query returns a maximum of 5 interfaces. Each interface holds an address in a connected prefix that contains the source address, and has no `GATEWAY_FOR` relationship to that prefix. The role of its device is not in `src/hst/reasoner/_constants.py` `GATEWAY_ROLES` and is not `firewall`. If the query returns interfaces, `detail` lists them.

### Impact answer

| Signal | Code that sets it | Content |
|---|---|---|
| `open` | `src/hst/assessment/evaluation.py` `_evaluate_change` | the source addresses in the upper bound and outside the lower bound, for `before` and `after` |
| `outcomes.<side>.result` | `src/hst/assessment/evaluation.py` `outcome` | the `answer` `open` if no source address fails and `open` of the side is not empty |
| `evidence.items[].missing` | `_evidence` | the missing evidence of 1 part of 1 member |
| `evidence.items[].steps[].unknown` | `_steps` | the unknown dimensions of the step |
| `evidence.items[].steps[].evidence_gap` | `src/hst/impact/evaluate.py` `_Walk._end`, `_Walk.mtu_egress` | the gap of a step that ends a part as not established, or of an `mtu` step of the kind `packet-shape-unknown` |
| `evidence.items[].left_estate`, `left_estate_note` | `_evidence` | the exits of a part whose path ends at the edge of the estate |
| `missing_evidence` | `_evaluate_change` | each distinct entry of `missing` of the evidence items |
| `gaps` | `src/hst/impact/evaluate.py` `answer` | the gaps of the routing result of the side after the change |
| `model_errors` | `_evaluate_change`, `EvaluationContext._evaluate` | the errors of `load_network`, of the change set and of the routing result of the side after the change |
| `stop_reason` | `finish` in `_execute` | the reason, if the evaluation budget stopped the evaluation |

`answer` adds a gap with the code `MTU_PATH_COVERAGE_INCOMPLETE` for a request with an MTU requirement. `src/hst/impact/evaluate.py` `scoped_model_errors` leaves out an error of the kind `rib-route-mismatch` on a prefix that holds no requested address.

If the request has `population_complete` false, `EvaluationContext._population_result` changes the answer.

- It sets `complete` to false and `completion_status` to `incomplete`.
- It adds the entries of `population_gaps` to `missing_evidence`. Without entries, it adds `SOURCE_POPULATION_INCOMPLETE`.
- Before `project_engine`, it changes each `outcomes` verdict with the value `holds` to `not-established`. It sets `isolated` of each side to false.

The route answers 409 for a run without a manifest and 503 for a child process without a result.

### Gap codes

`src/hst/impact/gaps.py` `gap_from_step` makes the gap of a step from the stage and the kind of the step. It removes the prefix `carrier/` from the stage. `_GAPS` maps 19 pairs.

| Stage | Kind of the step | Code | Kind of the gap | Dimension |
|---|---|---|---|---|
| `route` | `no-context` | `routing-context-missing` | `not-collected` | `routing-context` |
| `route` | `not-computed` | `routing-context-not-computed` | `not-modeled` | `routing` |
| `route` | `incomplete` | `routing-inputs-incomplete` | `unclassified` | `routing` |
| `route` | `resolution-incomplete` | `recursive-route-incomplete` | `unclassified` | `routing` |
| `entry` | `unattached` | `source-attachment-missing` | `not-collected` | `interface` |
| `entry` | `unowned` | `source-ownership-missing` | `not-collected` | `interface` |
| `next-hop` | `unowned` | `next-hop-ownership-missing` | `not-collected` | `interface` |
| `next-hop` | `duplicated` | `next-hop-context-conflict` | `unclassified` | `routing-context` |
| `forwarding` | `beyond-interface` | `interface-forwarding-unmodeled` | `not-modeled` | `topology` |
| `pbr` | `unknown-predicate` | `pbr-predicate-unsupported` | `unsupported` | `policy` |
| `pbr` | `missing-table` | `pbr-table-unmodeled` | `not-modeled` | `routing` |
| `output-filter` | `missing` | `output-filter-unmodeled` | `not-modeled` | `policy` |
| `snat` | `masquerade` | `nat-egress-address-missing` | `not-collected` | `interface` |
| `snat` | `ambiguous-egress-address` | `nat-egress-selection-unknown` | `unclassified` | `nat` |
| `tunnel` | `missing-endpoint` | `tunnel-endpoint-unmodeled` | `not-modeled` | `tunnel` |
| `tunnel` | `carrier-unknown` | `tunnel-carrier-unknown` | `unclassified` | `tunnel` |
| `budget` | `exhausted` | `evaluation-budget-exhausted` | `not-modeled` | `execution` |
| `device` | `hop-limit` | `evaluation-hop-limit` | `not-modeled` | `execution` |
| `session` | `unrestored-tuple` | `session-tuple-unrestored` | `unclassified` | `session` |

A pair outside the table gets the code `<stage>.<kind>`, the kind `unclassified` and the stage as the dimension. The gap has the keys `code`, `kind`, `dimension`, `subject`, `detail`, `producer` and `recipe_id`.

`src/hst/impact/gaps.py` `gap_from_effect` makes the gap of a gate without a decision. If the gate supplies a gap in `evidence_gaps` or `evidence_gap`, the function uses the first one. Without a supplied gap, the code is `<gate>-decision-not-established`. The kind is `unsupported` for the gates `firewall`, `nat`, `zpa`, `aci` and `pbr`, and `unclassified` for each other gate. The function adds the keys `context_uid`, `unknown_dimensions`, `evidence_refs` and `related_gaps`.
