# Graph schema

<!-- generated: schema-version -->
`src/hst/core/labels.py` `SCHEMA_VERSION` is `0.32.0`.
<!-- end generated: schema-version -->

## Node labels

`src/hst/core/labels.py` `LABELS` holds each label with a `LabelSpec`. A write uses 3 fields of the `LabelSpec`.

| Field | Content |
|---|---|
| `layers` | the layer labels of the node |
| `gate` | true for a label whose node gets the label `Gate` |
| `requires` | the properties that a node of the label must have |

`src/hst/core/labels.py` `labels_clause` returns the label string of a node. The string holds `Obj`, the label, each layer of the label and, for a gate label, `Gate`. The label string of a `Contract` node is `:Obj:Contract:Policy:Gate`. `src/hst/core/loader.py` `node_upsert_query` puts the string in the `MERGE` of a node. If `LABELS` does not hold the label, `labels_clause` raises `ValueError`.

`src/hst/core/labels.py` `LAYERS` holds the 10 layers: `Phys`, `L2`, `L3`, `Transport`, `Policy`, `Service`, `Workload`, `App`, `Cloud` and `Meta`.

A gate label is a label with `gate` set to true. `src/hst/core/labels.py` `GATE_BINDINGS` has 1 entry for each gate label. [Gate bindings](#gate-bindings) lists the entries.

`src/hst/core/model.py` `Batch.validate_registry` calls `src/hst/core/labels.py` `validate_props` for each node of a [batch](conventions.md#loader-contract). A property of `requires` with the value `None` or with an empty string is missing. The value `unknown` is valid.

`src/hst/core/labels.py` `RESERVED_LABELS` holds `Obj`, `Retired`, `Gate`, `Latest` and the 10 layers. The primary label of a node is its 1 label outside this set. `src/hst/core/diff.py` `_primary_label` and `src/hst/app/tables.py` `_ordered_labels` find the primary label in this way. No collector, no query of the loader and no reasoner rule writes the label `Retired`, the label `Latest` or the relationship property `_retired_at`.

`src/hst/core/labels.py` `STRATA_TIERS` holds the 4 tiers `physical`, `routing`, `policy` and `application`. `TIER_BY_KIND` gives each label 1 tier, and the column Tier of the table has it. `tier_of` returns the tier of a hop kind, and each hop of a trace holds it in `tier`.

<!-- generated: labels -->
| Label | Layers | Tier | Gate | Required properties |
|---|---|---|---|---|
| `Site` | `Phys` | physical | no |  |
| `Rack` | `Phys` | physical | no |  |
| `Device` | `Phys` | physical | no | `role` |
| `RedundancyGroup` | `Phys` | physical | no |  |
| `FailureDomain` | `Phys` | physical | no |  |
| `Module` | `Phys` | physical | no |  |
| `Port` | `Phys` | physical | no |  |
| `Provider` | `Meta` | physical | no |  |
| `ProviderNetwork` | `Transport` | physical | no |  |
| `Pnic` | `Phys` | physical | no |  |
| `Interface` | `L2` | physical | no |  |
| `Lag` | `L2` | physical | no |  |
| `VlanInstance` | `L2` | physical | no |  |
| `BridgeDomain` | `L2` | physical | no |  |
| `L2Vni` | `L2` | physical | no |  |
| `L2Segment` | `L2` | physical | no |  |
| `FhrpGroup` | `L2`, `L3` | routing | no |  |
| `Endpoint` | `L2` | application | no |  |
| `Ssid` | `L2` | physical | no |  |
| `VrfInstance` | `L3` | routing | no |  |
| `FirewallInstance` | `L3`, `Policy` | policy | no |  |
| `RoutingDomain` | `L3` | routing | no |  |
| `L3Domain` | `L3` | routing | no |  |
| `Prefix` | `L3` | routing | no |  |
| `IpAddress` | `L3` | routing | no |  |
| `RouteTarget` | `L3` | routing | no |  |
| `RoutingProcess` | `L3` | routing | no | `proto` |
| `BgpSession` | `L3` | routing | no | `local_asn`, `peer_asn` |
| `BgpPeerRange` | `L3` | routing | no | `local_asn`, `prefix` |
| `OspfArea` | `L3` | routing | no |  |
| `OspfAdjacency` | `L3` | routing | no |  |
| `RoutePolicy` | `L3` | routing | yes | `kind` |
| `RoutePolicyEntry` | `L3` | routing | no | `seq`, `kind` |
| `PrefixListEntry` | `L3` | routing | no | `seq`, `prefix`, `action`, `min_len`, `max_len` |
| `MatchListEntry` | `L3` | routing | no | `seq`, `action`, `match_type` |
| `Fabric` | `Transport` | physical | no |  |
| `Pod` | `Transport` | physical | no |  |
| `Tunnel` | `Transport` | routing | no |  |
| `OverlayConnection` | `Transport` | routing | no |  |
| `EvpnInstance` | `Transport` | routing | no |  |
| `SdwanSegment` | `Transport` | routing | no |  |
| `ForwardingBoundary` | `Transport` | routing | yes |  |
| `WanLink` | `Transport` | physical | no |  |
| `SdwanGateway` | `Transport` | physical | no |  |
| `SdwanBusinessPolicy` | `Policy` | policy | yes |  |
| `SdwanPolicyRule` | `Policy` | policy | no |  |
| `SdwanStaticRoute` | `L3` | routing | no |  |
| `NdoSchema` | `Meta` | physical | no |  |
| `NdoTemplate` | `Meta` | physical | no |  |
| `Tenant` | `Policy` | policy | no |  |
| `AppProfile` | `Policy` | policy | no |  |
| `Epg` | `Policy` | policy | no |  |
| `Esg` | `Policy` | policy | no |  |
| `ExtEpg` | `Policy` | policy | no |  |
| `L3Out` | `L3` | routing | no |  |
| `Contract` | `Policy` | policy | yes |  |
| `ContractSubject` | `Policy` | policy | no |  |
| `AciFilter` | `Policy` | policy | no |  |
| `FilterEntry` | `Policy` | policy | no |  |
| `VzAny` | `Policy` | policy | yes |  |
| `ServiceGraphTemplate` | `Policy` | policy | no |  |
| `ServiceGraphInstance` | `Policy` | policy | no |  |
| `ServiceNode` | `Policy` | policy | no |  |
| `PbrPolicy` | `Policy` | policy | yes |  |
| `PbrDest` | `Policy` | policy | no |  |
| `FwRulebase` | `Policy` | policy | yes |  |
| `FwRule` | `Policy` | policy | no |  |
| `FwSection` | `Policy` | policy | no |  |
| `CpPolicyPackage` | `Policy` | policy | no |  |
| `CpPolicyObject` | `Policy` | policy | no |  |
| `PolicyInstallation` | `Meta` | physical | no |  |
| `NetObject` | `Policy` | application | no |  |
| `SvcObject` | `Policy` | application | no |  |
| `Zone` | `Policy` | policy | no |  |
| `NatRule` | `Policy` | policy | yes |  |
| `VirtualService` | `Service` | application | yes |  |
| `Pool` | `Service` | application | no |  |
| `PoolMember` | `Service` | application | no |  |
| `Monitor` | `Service` | application | no |  |
| `DnsRecord` | `Service` | application | no |  |
| `ZscalerDc` | `Transport` | physical | no |  |
| `ZiaLocation` | `Policy` | policy | no |  |
| `ZiaLocationGroup` | `Policy` | policy | no |  |
| `ZiaForwardingRule` | `Policy` | policy | yes |  |
| `ZpaAppSegment` | `Policy` | policy | no |  |
| `ZpaSegmentGroup` | `Policy` | policy | no |  |
| `ZpaServerGroup` | `Policy` | policy | no |  |
| `AppServer` | `Workload` | physical | no |  |
| `ZpaAppConnectorGroup` | `Policy` | policy | no |  |
| `ZpaAppConnector` | `Workload` | physical | no |  |
| `ZpaAccessRule` | `Policy` | policy | yes |  |
| `ZpaClientForwardingRule` | `Policy` | policy | yes |  |
| `ZpaProvisioningKey` | `Policy` | policy | no |  |
| `ZpaServiceEdge` | `Transport` | physical | no |  |
| `IdentityGroup` | `App` | application | no |  |
| `Organization` | `Cloud` | physical | no |  |
| `Account` | `Cloud` | physical | no |  |
| `Region` | `Cloud` | physical | no |  |
| `Az` | `Cloud` | physical | no |  |
| `Vpc` | `Cloud`, `L3` | routing | no |  |
| `Subnet` | `Cloud`, `L3` | routing | no |  |
| `RouteTable` | `Cloud`, `L3` | routing | no |  |
| `CloudRoute` | `Cloud`, `L3` | routing | no |  |
| `Igw` | `Cloud` | physical | no |  |
| `NatGw` | `Cloud` | policy | yes |  |
| `Eni` | `Cloud` | physical | no |  |
| `VpcPeering` | `Cloud` | routing | no |  |
| `Tgw` | `Cloud`, `Transport` | routing | no |  |
| `TgwAttachment` | `Cloud`, `Transport` | routing | no |  |
| `TgwRouteTable` | `Cloud`, `Transport` | routing | no |  |
| `VpcEndpoint` | `Cloud` | application | no |  |
| `EndpointService` | `Cloud` | application | no |  |
| `DxConnection` | `Transport` | physical | no |  |
| `DxVif` | `Transport` | routing | no |  |
| `DxGw` | `Transport` | routing | no |  |
| `VpnConnection` | `Transport` | routing | no |  |
| `Instance` | `Workload` | physical | no |  |
| `Subscription` | `Cloud` | physical | no |  |
| `ResourceGroup` | `Cloud` | physical | no |  |
| `VNet` | `Cloud`, `L3` | routing | no |  |
| `Nic` | `Cloud` | physical | no |  |
| `VNetPeering` | `Cloud`, `Transport` | routing | no |  |
| `VirtualWan` | `Transport` | routing | no |  |
| `VHub` | `Transport` | routing | no |  |
| `HubRouteTable` | `Transport` | routing | no |  |
| `ErCircuit` | `Transport` | physical | no |  |
| `ErPeering` | `Transport` | routing | no |  |
| `VNetGw` | `Transport` | routing | no |  |
| `AzFirewall` | `Cloud` | policy | yes |  |
| `PrivateEndpoint` | `Cloud` | application | no |  |
| `PrivateLinkService` | `Cloud` | application | no |  |
| `FabricPort` | `Transport` | physical | no |  |
| `VirtualCircuit` | `Transport` | physical | no |  |
| `Vcenter` | `Workload` | physical | no |  |
| `VmwCluster` | `Workload` | physical | no |  |
| `EsxHost` | `Workload` | physical | no |  |
| `Vm` | `Workload` | physical | no |  |
| `Vnic` | `Workload` | physical | no |  |
| `Dvs` | `L2` | physical | no |  |
| `DvPortgroup` | `L2` | physical | no |  |
| `Server` | `Workload` | physical | no |  |
| `BusinessService` | `App` | application | no |  |
| `AppComponent` | `App` | application | no |  |
| `ServiceRequirement` | `App` | application | no |  |
| `DependencyGroup` | `App` | application | no | `kind` |
| `CollectionRun` | `Meta` | physical | no |  |
| `MtuObservation` | `Meta` | physical | no | `subject_uid`, `source`, `source_field`, `raw_value_json`, `metric`, `bound_kind` |
<!-- end generated: labels -->

## Relationship types

`src/hst/core/labels.py` `RELS` holds each relationship type. `src/hst/core/model.py` `Batch.validate_registry` refuses a batch with a relationship type outside `RELS` or with an end label outside `LABELS`. `src/hst/core/loader.py` `load` calls it before the first write.

A relationship of a batch has a `key` and `props`. `src/hst/core/loader.py` `rel_upsert_query` puts the fields of `key` in the `MERGE` pattern and sets the fields of `props` after the `MERGE`. The fields of `key` and the fields of `props` are properties of the relationship. 2 relationships of 1 type between the same 2 nodes exist only if their `key` values differ.

<!-- generated: relationship-types -->
- `APPLIES_GRAPH`
- `APPLIES_TO`
- `ASSOCIATED`
- `ATTACHED`
- `ATTACHED_TO`
- `A_END`
- `BETWEEN`
- `BOUND_TO`
- `BRIDGED_TO`
- `CARRIES`
- `CHECKED_BY`
- `CONNECTED_TO`
- `CONSUMES`
- `CONTAINS`
- `DEFINES`
- `DENIES`
- `DEPENDS_ON`
- `DISPATCHES`
- `DST`
- `EGRESSES_VIA`
- `ENDPOINT`
- `ENFORCES`
- `EXPORTS`
- `EXTENDS`
- `FILTERED_BY`
- `FOR`
- `FORWARDS_TO`
- `FROM_ZONE`
- `FRONTS`
- `GATEWAY_FOR`
- `GRANTS`
- `HAS`
- `HAS_BOUNDARY`
- `HAS_DEST`
- `HAS_INSTALLATION`
- `HAS_IP`
- `HAS_LAYER`
- `HAS_LINK`
- `HAS_MEMBER`
- `HAS_MTU`
- `HAS_NODE`
- `HAS_PORT`
- `HAS_ROUTE`
- `HAS_RULE`
- `IMPORTS`
- `IN`
- `INSTALLS`
- `INTERCONNECTED_BY`
- `IN_ACCOUNT`
- `IN_AREA`
- `IN_AZ`
- `IN_BD`
- `IN_CONTEXT`
- `IN_EPG`
- `IN_ORG`
- `IN_POD`
- `IN_RACK`
- `IN_REGION`
- `IN_VRF`
- `JUMPS_TO`
- `L3_ADJACENT`
- `LEARNED_ROUTE`
- `LOCATED_IN`
- `MATCHES`
- `MEMBER_OF`
- `OF`
- `ON`
- `ORIGINATES`
- `ORIG_DST`
- `ORIG_SRC`
- `OWNED_BY`
- `PART_OF`
- `PEERS_WITH`
- `PLUGGED_INTO`
- `PROPAGATES`
- `PROTECTED_BY`
- `PROVIDED_BY`
- `PROVIDES`
- `REALIZED_BY`
- `REALIZES`
- `REDIRECTS_VIA`
- `REFERENCES`
- `REPRESENTS`
- `RESOLVES_TO`
- `ROUTES`
- `RUNS_ON`
- `SAME_AS`
- `SERVED_BY`
- `SNAT_FROM`
- `SRC`
- `STATIC_BINDING`
- `STATIC_ROUTE`
- `STEERS_VIA`
- `SVC`
- `SWITCHES`
- `TARGETS`
- `TERMINATES_ON`
- `TO_ZONE`
- `USES`
- `USES_FILTER`
- `USES_RT`
- `VIA`
- `VIP`
- `VMM_BINDING`
- `WITHIN`
- `XLATE_DST`
- `XLATE_SRC`
- `Z_END`
<!-- end generated: relationship-types -->

## Vocabularies

<!-- generated: vocabularies -->
| Name | Values |
|---|---|
| `DEPENDENCY_GROUP_KINDS` | `and`, `capacity`, `or`, `threshold` |
| `DEVICE_ROLES` | `access point`, `ap`, `controller`, `firewall`, `gateway`, `leaf`, `management`, `router`, `sdwan-edge`, `sdwan-hub`, `spine`, `switch`, `unknown` |
| `FWRULEBASE_KINDS` | `access`, `azfw-collection`, `ips-profile`, `nat`, `nsg`, `sg`, `zone` |
| `MATCH_CONTEXTS` | `device`, `interface-acl`, `object-attached`, `zone-pair` |
| `MTU_SUBJECT_LABELS` | `BridgeDomain`, `Device`, `DvPortgroup`, `Dvs`, `Endpoint`, `EsxHost`, `Fabric`, `Interface`, `Lag`, `Pnic`, `Port`, `Server`, `Tunnel`, `Vm`, `Vnic` |
| `NATRULE_KINDS` | `dnat`, `snat`, `static` |
| `ZPA_ACCESS_ACTIONS` | `allow`, `deny`, `require_approval` |
| `ZPA_RULE_SCOPES` | `any`, `listed`, `other` |
<!-- end generated: vocabularies -->

## Gate bindings

A binding pattern is a Cypher path from a device `d` to a gate node `g`. The relationship variables of the pattern are `e1` to `eN`. An entry of `src/hst/core/labels.py` `GATE_BINDINGS` holds the patterns of 1 gate label. An entry that starts with `NOT_DEVICE_BOUND` holds a reason and no pattern.

`src/hst/path/gates/__init__.py` `gate_safeguard_query` builds 1 query with a `UNION` branch for each pattern. `src/hst/path/gates/__init__.py` `unevaluated_gates` runs the query for the devices of a path. It returns each gate node for which the path engine has no verdict.

`src/hst/map/tiers/bootstrap.py` `_gate` reads the patterns of `FwRulebase` and `PbrPolicy`. `src/hst/map/tiers/bootstrap.py` `CATEGORIES` uses them to count the rulebases, the rules, the NAT rules and the PBR policies of a device.

`tests/test_schema_contract.py` `test_every_gate_label_declares_its_binding_or_its_exemption` fails if a gate label of `LABELS` has no entry in `GATE_BINDINGS`.

<!-- generated: gate-bindings -->
- `ForwardingBoundary`
  - `(d)-[e1:HAS_BOUNDARY]->(g)`
- `FwRulebase`
  - `(d)-[e1:ENFORCES]->(g)`
  - `(d)-[e1:MEMBER_OF]->(:RedundancyGroup)-[e2:ENFORCES]->(g)`
  - `(d)<-[e1:ON]-(:Interface)-[e2:IN_VRF]->(:VrfInstance)-[e3:ENFORCES]->(g)`
  - `(d)-[e1:PROTECTED_BY]->(g)`
  - `(d)<-[e1:ON]-(:Interface)-[e2:PROTECTED_BY]->(g)`
  - `(d)<-[e1:ON]-(:Interface)<-[e2:CONTAINS]-(:Zone)<-[e3:FROM_ZONE|TO_ZONE]-(g)`
- `NatRule` has no device binding. credited through its FwRulebase kind=nat (path/trace.py nat_uids)
- `PbrPolicy`
  - `(d)<-[e1:ON]-(:Interface)-[e2:ENFORCES]->(g)`
  - `(d)-[e1:MEMBER_OF]->(:Fabric)<-[e2:MEMBER_OF]-(:Device)<-[e3:ON]-(:Interface)-[e4:ENFORCES]->(g)`
- `Contract` has no device binding. evaluated per flow on the EPG pair (path/gates/aci.py); credited by contract uid
- `VzAny` has no device binding. evaluated with the ACI contract gate once collected
- `RoutePolicy` has no device binding. a route-policy filters advertisements, not flows; consulted by the BGP model
- `VirtualService`
  - `(d)<-[e1:ON]-(g)`
  - `(d)-[e1:MEMBER_OF]->(:RedundancyGroup)<-[e2:ON]-(g)`
- `SdwanBusinessPolicy`
  - `(d)-[e1:HAS_LINK]->(:WanLink)<-[e2:STEERS_VIA]-(g)`
  - `(d)<-[e1:ON]-(:Interface)<-[e2:ENDPOINT]-(:Tunnel)<-[e3:STEERS_VIA]-(g)`
- `ZpaAccessRule` has no device binding. identity-keyed; first match runs in core/zpa_policy.py for hst.path.trace.trace_from_identity, the impact engine and the analysis model
- `ZpaClientForwardingRule` has no device binding. identity-keyed; first match runs in core/zpa_policy.py before the access rule, for hst.path.trace.trace_from_identity, the impact engine and the analysis model
- `ZiaForwardingRule` has no device binding. a ZIA forwarding decision (ZPA, DIRECT, DROP); first match runs in path/gates/zia.py at the ZIA boundary of a traced tunnel
- `NatGw` has no device binding. cloud route target; no cloud collector exists
- `AzFirewall` has no device binding. cloud route target; no cloud collector exists
<!-- end generated: gate-bindings -->

## Run metadata

3 kinds of node have no run key in `collection_ts`. [Storage](storage.md#neo4j) gives the label, the `uid` and the code that writes each of them. `CyclePointer` and `CycleRun` are not in `LABELS`. The 3 nodes have the labels `Obj` and `Meta`.

| Label | Property | Content |
|---|---|---|
| `CyclePointer` | `current` | the run key of the published run |
| `CyclePointer` | `fence` | the highest fence value of a pointer move |
| `CyclePointer` | `updated` | the run key of the published run as an ISO string |
| `CyclePointer` | `_scope` | `meta:cycle` |
| `CycleRun` | `cts` | the run key |
| `CycleRun` | `created` | the run key as an ISO string |
| `CycleRun` | `kind` | `full`, `partial`, `refresh` or `device` |
| `CycleRun` | `parent` | the run key of the parent run |
| `CycleRun` | `state` | `building` or `built` |
| `CycleRun` | `sources_fresh`, `sources_carried`, `sources_failed`, `sources_partial`, `sources_cancelled` | the sorted list of the sources with that status |
| `CycleRun` | `carried_from` | the run key of the run that is the origin of the carry |
| `CycleRun` | `nodes`, `rels` | the node count and the relationship count of the run |
| `CycleRun` | `degraded` | in a run of the run builder, true if a source has the status `failed`, `partial` or `cancelled` |
| `CycleRun` | `manifest_digest` | the digest of the manifest of the run |
| `CycleRun` | `reprocessed_from` | the run key of the manifest that `src/hst/core/replay.py` `rebuild_from_manifest` replays |
| `CycleRun` | `app_version`, `build_revision` | the version and the build revision of the application |
| `CycleRun` | `_scope` | `meta:cycles` |
| `CollectionRun` | `run_id` | the run id of the fetch, or `reasoner-rt-domains-<run key>-<nonce>` or `reasoner-link-speed-<run key>-<nonce>` for a load of `src/hst/core/reasoner.py` |
| `CollectionRun` | `scope` | the scope of the batch |
| `CollectionRun` | `source` | the name of the source, the source type for a load without a source name, or `reasoner` for a load of `src/hst/core/reasoner.py` |
| `CollectionRun` | `started`, `finished`, `finished_ms` | the start time and the end time of the load |
| `CollectionRun` | `nodes_upserted`, `nodes_created`, `nodes_revived`, `nodes_retired` | node counters of the load |
| `CollectionRun` | `rels_upserted`, `rels_created`, `rels_revived`, `rels_retired`, `rels_dropped_missing_endpoint` | relationship counters of the load |
| `CollectionRun` | `retirement_skipped`, `rel_retirement_skipped` | booleans |
| `CollectionRun` | `errors` | the first 20 errors of the load |
| `CollectionRun` | `sections` | 1 string `<section>=<status>` for each section of the batch |
| `CollectionRun` | `snapshot_ts` | the run key |
| `CollectionRun` | `_scope` | `meta:runs` |
| `CollectionRun` | `_first_seen`, `_last_seen` | the time of the first load and of the last load with this `uid` |

`src/hst/core/cycle.py` `begin_run` writes `cts`, `created`, `kind`, `parent` and `state` of a `CycleRun`. `src/hst/core/cycle.py` `write_cycle_meta` writes these 5 properties again with the `state` `built`, and it writes the other properties. The `CollectionRun` properties from `run_id` to `sections` are fields of `src/hst/core/model.py` `RunManifest`. `src/hst/core/loader.py` `load` does not write the fields `tables`, `warnings`, `graph_sha` and `graph_unchanged`. No code sets `nodes_revived`, `rels_revived`, `nodes_retired`, `rels_retired`, `retirement_skipped` and `rel_retirement_skipped`, so they hold 0 or `false`.

## Properties and relationships

Each section below gives the properties and the relationships that code under `src/hst` writes. [Uids](conventions.md#uids), [Loader-owned properties](conventions.md#loader-owned-properties) and [Derived elements](conventions.md#derived-elements) describe the `uid`, the properties that the loader owns and the mark of a derived element. The tables below do not list them.

[Graph schema by source type](schema-by-source-type.md) has the rows of these sections in the order of the source type that writes them.

The column "Written by" holds a source type, a reasoner rule or a code citation. A relationship is in the section of the label of its start node. The cell "Properties" holds the fields of `key` and of `props`. [Storage](storage.md#side-store) lists the tables of the side store.

The 3 source types `nxos`, `iosxe` and `iosxr` build their batch with `src/hst/collectors/cisco_common.py` `normalize_cisco`. `nxos` adds the BGP batch of `src/hst/collectors/nxos.py` `bgp_stage`. The source type `checkpoint_gateway` uses `src/hst/collectors/checkpoint_topology.py` and `src/hst/collectors/checkpoint_bgp.py`. The source type `apic` uses `src/hst/collectors/mtu_apic.py`. The source type `vyos` calls `src/hst/collectors/cisco_common.py` `ospf_stage` and `src/hst/collectors/cisco_common.py` `match_list_stage`.

### Location, physical and device

#### Site

| Property | Content | Written by |
|---|---|---|
| `code` | the site code | `equinix`, `zia`, `src/hst/core/cycle.py` `apply_site_assignments`, `src/hst/core/cycle.py` `carry_site_assignments`, `src/hst/core/cycle.py` `migrate_meta_sites` |
| `kind` | `colo` | `equinix` |

`apply_site_assignments` writes a `Site` only if the run holds no `Site` with the same `uid`. Its input maps a device `uid` to a site code.

#### Rack

| Property | Content | Written by |
|---|---|---|
| `name` | the rack name | `nautobot` |

#### Device

Each source type of the table writes `role`. The table gives `platform` and `role` for each source type.

| Source type | `platform` | `role` |
|---|---|---|
| `nxos` | `nxos` | `router` |
| `iosxe` | `iosxe` | `router` |
| `iosxr` | `iosxr` | `router` |
| `vyos` | `vyos` | `router` |
| `apic` | `apic`, `aci-leaf`, `aci-spine`, or `aci` for another role | the `role` of the fabric node, or `unknown` |
| `checkpoint` | `checkpoint` | `management` for a type in `src/hst/collectors/checkpoint.py` `MANAGEMENT_TYPES`, or `firewall` |
| `checkpoint_gateway` | `checkpoint-gaia` | `firewall` |
| `equinix` | `network-edge` | `router`, `firewall` or `sdwan-edge` |
| `unifi` | `unifi-<type>` | `switch`, `ap` or `gateway` from `src/hst/collectors/unifi.py` `ROLE`, or the device type, or `unknown` |
| `velocloud` | `velocloud-edge` | `sdwan-hub` for an edge in the hub set, or `sdwan-edge` |
| `nautobot` | the platform name in lower case | the role name in lower case, or `unknown` |
| `manual` | the platform column | the role column, or `unknown` |

`checkpoint_gateway` also writes 1 `Device` for each context of the kind `virtual-router`, `virtual-switch` or `management`. The `role` of this node is `router`, `switch` or `management`. The node has no `platform`.

`src/hst/reasoner/device_roles.py` `apply_device_roles` runs before the reasoner rules. It sets `role` to the result of `src/hst/core/device_roles.py` `classify` and keeps the value of the collector in `role_reported`.

| Property | Content | Written by |
|---|---|---|
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic`, `checkpoint`, `checkpoint_gateway`, `equinix`, `unifi`, `velocloud`, `nautobot`, `manual` |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic`, `unifi`, `velocloud`, `nautobot`, `manual` |
| `identities` | the list of the identity strings of the device | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint`, `equinix`, `unifi`, `nautobot` |
| `vendor` | `cisco` | `nxos`, `iosxe`, `iosxr` |
| `vendor` | `vyos` | `vyos` |
| `vendor` | `ubiquiti` | `unifi` |
| `vendor` | `VeloCloud` | `velocloud` |
| `vendor` | `deviceTypeVendor` of the device | `equinix` |
| `vendor` | the manufacturer name in lower case | `nautobot` |
| `os_version` | the software version | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic`, `checkpoint_gateway`, `equinix`, `unifi` |
| `model` | the hardware model | `apic`, `equinix`, `unifi`, `velocloud`, `nautobot` |
| `mgmt_ip` | the management address | `apic`, `checkpoint`, `unifi`, `nautobot`, `manual` |
| `reported_location`, `reported_location_name` | the location that the source reports | `unifi`, `velocloud`, `nautobot` |
| `reported_location`, `reported_location_name` | `<fabric>/<pod DN>` and `<fabric> <pod DN>`. The pod DN is the first 2 segments of the DN of the fabric node | `apic` |
| `dn` | the DN of the fabric node | `apic` |
| `mac` | the MAC address of the device | `unifi` |
| `cp_type`, `cp_uid`, `cp_raw_uid` | the type and the uid of the management object | `checkpoint` |
| `observation_uid` | `effective_observation_uid` of the source configuration | `checkpoint_gateway` |
| `gateway_object_uid`, `authority`, `domain`, `kind`, `name` | the identity of a virtual device | `checkpoint_gateway` |
| `virtual` | `true` | `equinix` |
| `redundancy` | `redundancyType` in lower case | `equinix` |
| `bound_device_uid` | the uid of the device that the source configuration binds | `equinix` |
| `edge_device_uuid`, `edge_device_name`, `edge_device_type`, `edge_status`, `edge_management_ip`, `ibx`, `metro` | fields of the Network Edge device | `equinix` |
| `hostname_fqdn`, `status`, `asset_tag`, `position`, `location` | fields of the Nautobot device | `nautobot` |
| `software_version`, `edge_state`, `edge_logical_id` | fields of the edge row | `velocloud` |
| `enterprise_logical_id`, `enterprise_name` | the enterprise of the edge | `velocloud` |
| `site_city`, `site_country`, `site_lat`, `site_lon` | fields of the site of the edge | `velocloud` |
| `sdwan_role` | `hub` for an edge in the hub set | `velocloud` |
| `configuration_observed_at_ms` | the time of the configuration read | `velocloud` |
| `ha_type`, `ha_state`, `ha_standby_serial`, `hub_cluster_id`, `hub_cluster_name` | the result of `src/hst/collectors/velocloud.py` `_ha_props` | `velocloud` |
| `role_reported`, `role_basis`, `tier` | the role of the collector, the basis and the tier of the role | `src/hst/reasoner/device_roles.py` `apply_device_roles` |
| `site_block`, `site_zone` | the block and the zone of the device in its site | `src/hst/core/cycle.py` `apply_site_blocks` |

For `nxos`, `iosxe` and `iosxr`, `hostname` is the name that the device reports, else the host that the collector connects to, else `unknown`. `identities` holds the reported name only.

| Relationship | Properties | Written by |
|---|---|---|
| `(Device)-[:LOCATED_IN]->(Site)` | | `equinix`, `src/hst/core/cycle.py` `apply_site_assignments`, `src/hst/core/cycle.py` `carry_site_assignments`, `src/hst/core/cycle.py` `migrate_meta_sites` |
| `(Device)-[:IN_RACK]->(Rack)` | | `nautobot` |
| `(Device)-[:MEMBER_OF]->(Fabric)` | | `apic` |
| `(Device)-[:IN_POD]->(Pod)` | | `apic` |
| `(Device)-[:MEMBER_OF]->(RedundancyGroup)` | `role`, `peer_link`, `peer_status` | `nxos` |
| `(Device)-[:MEMBER_OF]->(RedundancyGroup)` | | `checkpoint`, `unifi` |
| `(Device)-[:PROVIDED_BY]->(Provider)` | | `equinix` |
| `(Device)-[:HAS_IP]->(IpAddress)` | | `manual` |
| `(Device)-[:HAS_LINK]->(WanLink)` | | `velocloud`, `vyos` |
| `(Device)-[:HAS_BOUNDARY]->(ForwardingBoundary)` | | `velocloud` |
| `(Device)-[:ENFORCES]->(SdwanBusinessPolicy)` | | `velocloud` |
| `(Device)-[:ENFORCES]->(PbrPolicy)` | | `vyos` |
| `(Device)-[:ENFORCES]->(FwRulebase)` | `approximate` or `configured` | `checkpoint` |
| `(Device)-[:ENFORCES]->(FwRulebase)` | `installed`, `coverage`, `installed_revision`, `context_uid`, `ingress_interface_uid`, `egress_interface_uid`, `address_family` for an access list, no property for a NAT rulebase and for the `vyos` rulebase `unread VyOS 1.3 firewall` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `(Device)-[:ENFORCES]->(FwRulebase)` | `approximate`, `installed`, `coverage`, `installed_revision`, `context_uid`, `address_family`, `ingress_interface_uid`, `egress_interface_uid` | `unifi` |
| `(Device)-[:RUNS_ON]->(Device)` | `vsid`, `state`, `observation_uid` | `checkpoint_gateway` |
| `(Device)-[:SAME_AS]->(Device)` | | `edge-device-from-binding` |
| `(Device)-[:HAS_MTU]->(MtuObservation)` | | `nxos`, `iosxe`, `unifi` |

`vyos` writes `ENFORCES` to the filter of a chain, to a NAT rulebase and to the rulebase of `_legacy_firewall`. On the filter of a chain, `context_uid`, `ingress_interface_uid` and `egress_interface_uid` hold `*`. `equinix` writes `LOCATED_IN` only for a device with a site code and no `bound_device_uid`. `(Device)-[:RUNS_ON]->(Device)` starts at a virtual device and ends at the device of the gateway.

This code reads `role` and acts on the value. `src/hst/reasoner/_constants.py` `GATEWAY_ROLES` holds `router`, `gateway`, `sdwan-hub` and `sdwan-edge`.

| Reader | Use of `role` |
|---|---|
| `src/hst/reasoner/device_roles.py` `FETCH_DEVICE_ROLES` | gives `role_reported`, or else `role`, to `src/hst/core/device_roles.py` `classify` as the role of the collector |
| the rule `gateway-from-router-interface` in `src/hst/reasoner/catalog.py` | writes `GATEWAY_FOR` from each interface of a device with a role in `GATEWAY_ROLES` to its connected prefix |
| the rule `gateway-from-sole-firewall-interface` in `src/hst/reasoner/catalog.py` | writes `GATEWAY_FOR` from an interface of a device with the role `firewall` if no device with a role in `GATEWAY_ROLES` has an address on the prefix |
| the rule `gateway-from-sole-segment-interface` in `src/hst/reasoner/catalog.py` | writes `GATEWAY_FOR` only from an interface of a device with a role outside `GATEWAY_ROLES` and other than `firewall` |
| `src/hst/path/trace.py` `_UNROUTED_INTERFACES_QUERY` | lists a maximum of 5 interfaces on the source prefix of devices with a role outside `GATEWAY_ROLES` and other than `firewall`, in the verdict of `src/hst/path/trace.py` `_no_gateway_result` |
| `src/hst/analysis_model/network.py` `_access_policy` | gives an unknown policy with the reason `FIREWALL_POLICY_INSTALLATION_UNKNOWN` to a device with the role `firewall` and no bound rulebase |
| `src/hst/applications/generator.py` `_inventory_member` | turns a member device into a placeholder with the status `unresolved` if its role is in `src/hst/applications/generator.py` `TRANSIT_ROLES` |
| `src/hst/map/tiers/bootstrap.py` `DEVICES` | reads `role` into the column `role` of the network map table `render_t1` |
| `src/hst/map/layout.py` `layer_of` | gives a device without `tier` the layer of its role in `src/hst/map/layout.py` `ROLE_LAYER` |
| `src/hst/map/layout.py` `hierarchy` | puts a device without a site in the block `block:unassigned:<role>`, and makes a site with a device of the role `sdwan-hub` a hub site |
| `src/hst/diagram/planner.py` `_blocks` | puts a device without `tier` and with the role `firewall` in a firewall block |
| `web/src/netmap/look.ts` `symbolOf` | gives the symbol of a device of `GET /api/topology` from `ROLE_SYMBOL`, and else from the tier |
| `web/src/hst/render/symbols/index.ts` `symbolOf` | gives the symbol of a `render_t1` row from `ROLE_SYMBOL`, and else `unknown` |
| `web/src/hst/render/scene.ts` `keyDevice` | draws a `render_t1` row with the role `firewall` as a model at site zoom |
| `web/src/hst/render/scene.ts` `HUB_ROLE` | makes the site of a `render_t1` row with the role `sdwan-hub` a hub site, and groups the tunnels of the device to the sites of its own region into 1 line |

#### RedundancyGroup

| Property | Content | Written by |
|---|---|---|
| `kind` | `vpc` | `nxos` |
| `kind` | `cp-cluster` | `checkpoint` |
| `kind` | `unifi-ha` | `unifi` |
| `name` | `vpc-domain-<domain>` | `nxos` |
| `name` | the name of the cluster object | `checkpoint` |
| `name` | `gateway HA` | `unifi` |
| `domain_id` | the vPC domain id | `nxos` |
| `cp_type`, `cp_raw_uid` | the type and the uid of the cluster object | `checkpoint` |

| Relationship | Properties | Written by |
|---|---|---|
| `(RedundancyGroup)-[:ENFORCES]->(FwRulebase)` | the properties of the `unifi` row of `Device` | `unifi` |

`unifi` writes the `RedundancyGroup` and the `ENFORCES` from it if the payload holds 2 or more gateway devices. If the payload holds 1 gateway device, `unifi` writes `ENFORCES` from that `Device`.

#### Port

| Property | Content | Written by |
|---|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic`, `checkpoint_gateway`, `equinix`, `unifi`, `velocloud`, `nautobot` |
| `mac` | the MAC address | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway`, `equinix`, `nautobot` |
| `kind` | `phys`, `lag` or `mgmt` | `nxos` |
| `kind` | `phys` or `lag` | `iosxe`, `iosxr` |
| `kind` | `lag` for a `pcAggrIf` object | `apic` |
| `kind` | `physical` | `checkpoint_gateway` |
| `kind` | `mgmt` for the type `SSH`, or `phys` | `equinix` |
| `speed_mbps`, `duplex`, `speed_source` | the operational speed, `full` or `half`, and `nxos:eth_speed`, `iosxe:show interfaces` or `iosxr:show interfaces`. `speed_mbps` is absent if the device gives no speed number. `duplex` is absent if the device gives no `full` or `half` | `nxos`, `iosxe`, `iosxr` |
| `speed_mbps`, `duplex`, `speed_source` | the operational speed, the duplex and the field that gives them | `vyos`, `unifi` |
| `bandwidth_kbit` | the bandwidth of the interface | `nxos`, `iosxe`, `iosxr` |
| `speed_configured_mbps`, `duplex_configured` | the configured speed and duplex | `vyos` |
| `description` | the description of the port | `nxos`, `iosxe`, `iosxr`, `nautobot` |
| `lldp_neighbor_name`, `lldp_neighbor_mac`, `lldp_neighbor_port` | the LLDP neighbor of the port | `nxos`, `iosxe`, `iosxr` |
| `cdp_neighbor_name`, `cdp_neighbor_port` | the CDP neighbor of the port | `nxos`, `iosxe`, `iosxr` |
| `cdp_neighbor_serial` | the serial in the device id of the CDP neighbor | `nxos` |
| `lldp_neighbor_name`, `lldp_neighbor_mac`, `lldp_neighbor_port`, `cdp_neighbor_name`, `cdp_neighbor_port` | the neighbor of the port | `apic` |
| `lldp_neighbor_mac`, `lldp_neighbor_port` | the LLDP neighbor of the port | `unifi` |
| `admin_state` | `adminSt` of the port | `apic` |
| `dn` | the DN of the port | `apic` |
| `edge_interface_uuid`, `edge_device_uid` | the uuid of the interface and the uid of its device | `equinix` |
| `media` | the interface type | `nautobot` |
| `admin` | `up` or `down` | `nautobot` |
| `oper` | `up` or `down` | `unifi` |
| `poe` | `port_poe` of the port | `unifi` |
| `last_conn_mac` | the MAC address of the last connection, if `connected` of the last connection is true | `unifi` |
| `uplink_mac`, `uplink_remote_port` | the uplink neighbor of the device | `unifi` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Port)-[:ON]->(Device)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic`, `checkpoint_gateway`, `equinix`, `unifi`, `velocloud`, `nautobot` |
| `(Port)-[:ON]->(Device)` | | `edge-device-from-binding` |
| `(Port)-[:CARRIES]->(VlanInstance)` | | `nxos` |
| `(Port)-[:CARRIES]->(VlanInstance)` | `native` | `vyos`, `unifi`, `checkpoint_gateway` |
| `(Port)-[:MEMBER_OF]->(Lag)` | `state`, `source_command`, `assertion_kind`, `eligible` | `nxos`, `iosxe`, `iosxr` |
| `(Port)-[:MEMBER_OF]->(Lag)` | `state`, `assertion_kind` | `vyos` |
| `(Port)-[:MEMBER_OF]->(Lag)` | `state` | `checkpoint_gateway` |
| `(Port)-[:MEMBER_OF]->(Lag)` | `basis`, `membership_state`, `forwarding_eligible`, `evidence_ref` | `apic` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `nautobot-cable` | `nautobot` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `unifi` | `unifi` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `unifi-uplink` | `cable-from-uplink-record` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `unifi-lldp` | `cable-from-lldp-record` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `cdp` or `lldp` | `cable-from-neighbor-name` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `reasoner` | `cable-from-endpoint-mac`, `cable-from-last-connection` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `reasoner`, `basis` | `src/hst/reasoner/arp_cables.py` `ARP_CABLE_WRITE` with the rule name `cable-from-arp-port` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `equinix-circuit`, `circuit_uid`, `vlan_tag_a`, `vlan_tag_z`, `link_protocol_a`, `link_protocol_z` | `cable-from-fabric-circuit` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `speed_mbps`, `speed_agreement` | `src/hst/core/reasoner.py` `execute_link_speed` |
| `(Port)-[:HAS_MTU]->(MtuObservation)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic`, `unifi`, `nautobot`, `manual` |

`cable-from-uplink-record`, `cable-from-lldp-record` and `cable-from-neighbor-name` write `derived` with the value `false`. `execute_link_speed` adds the 2 properties to each `CONNECTED_TO` relationship between 2 ports. `speed_agreement` is `agree`, `disagree`, `one-side` or `unknown`.

#### Provider

| Property | Content | Written by |
|---|---|---|
| `name` | `Equinix` | `equinix` |
| `name` | `zscaler` | `zia` |
| `name` | `provider_name` of the source configuration | `velocloud` |
| `kind` | `colo` | `equinix` |

`velocloud` writes a `Provider` only for a provider network of the kind `mpls` and only if the source configuration holds `provider_name`.

#### ProviderNetwork

| Property | Content | Written by |
|---|---|---|
| `name` | the carrier of the WAN link | `velocloud` |
| `kind` | the value of `src/hst/collectors/velocloud.py` `_PROVIDER_KIND` for the kind of the WAN link | `velocloud` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ProviderNetwork)-[:PROVIDED_BY]->(Provider)` | | `velocloud` |

### Interfaces and L2

#### Interface

The table gives the values of `kind` for each source type.

| Source type | `kind` |
|---|---|
| `nxos` | `phys`, `subif`, `svi`, `loopback`, `lag`, `mgmt` |
| `iosxe` | `phys`, `subif`, `svi`, `loopback`, `lag` |
| `iosxr` | `phys`, `subif`, `loopback`, `lag` |
| `vyos` | the value of `src/hst/collectors/vyos.py` `_IF_KIND` for the interface type, or the interface type, and `subif` for a `vif`, a `vif-s` or a `vif-c` |
| `velocloud` | `phys`, `subif`, `loopback`, `vlan-if` |
| `unifi` | `svi` |
| `equinix` | the interface type in lower case |
| `checkpoint_gateway` | `warp`, `vlan` |
| `apic` | `l3out-floating`, `l3out-attachment` |

| Property | Content | Written by |
|---|---|---|
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway`, `equinix`, `velocloud`, `netscaler` |
| `name` | `ifInstT` of the L3Out attachment, or the APIC class name if `ifInstT` is absent. The interface id in the DN of an `ospfIf` object | `apic` |
| `name` | the network name, or `br<VLAN id>` for a network with no name | `unifi` |
| `mac` | the MAC address | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway`, `equinix` |
| `admin_up` | a boolean | `nxos`, `iosxe`, `iosxr`, `checkpoint_gateway` |
| `oper_status` | the operational state | `iosxe`, `iosxr`, `checkpoint_gateway` |
| `description` | the description of the interface | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `parent_interface_uid` | the uid of the parent interface | `nxos`, `iosxe`, `iosxr`, `checkpoint_gateway` |
| `parent_source_command` | the command that gives the parent | `nxos`, `iosxe`, `iosxr` |
| `nat_role` | the NAT role of the interface | `nxos`, `iosxe` |
| `ipv4_default_origin` | `pppoe` or `dhcp` | `vyos` |
| `ipv6_link_local` | the sorted link-local addresses | `vyos` |
| `mtu` | `mtu` of the row of the interface in `ip -j address show`, or in `ip -d -j link show` for an interface with no address | `checkpoint_gateway` |
| `vsid`, `vsx_kind` | the VSID and the kind of the context | `checkpoint_gateway` |
| `vsx_state` | `active`, `standby`, `backup`, `down`, `ready`, `init` or `unknown` from the `(local)` row of `cphaprob state`. `standalone` if `cluster_mode` is `standalone` | `checkpoint_gateway` |
| `vsx_cluster` | `true` if `cluster_mode` is `cluster`. With `cluster_mode` `auto`, `true` if the appliance type or `cphaprob state` shows a cluster | `checkpoint_gateway` |
| `firewall_instance_uid` | the uid of the `FirewallInstance` or of the virtual `Device` of the context | `checkpoint_gateway` |
| `installed_policy_in`, `installed_policy_out`, `installed_at_in`, `installed_at_out` | the policy name and the date text of 1 row of `src/hst/collectors/checkpoint_operational.py` `installed_policy` with the name of the interface. `<` in the row gives `in`, and `>` gives `out` | `checkpoint_gateway` |
| `vsx_topology_complete` | a boolean | `checkpoint_gateway` |
| `state`, `assigned`, `edge_interface_uuid`, `edge_interface_id`, `edge_device_uid` | fields of the Network Edge interface | `equinix` |
| `vlan`, `subinterface_id` | the VLAN id and the id of a subinterface | `velocloud` |
| `wan_overlay`, `next_hop` | `true` and the gateway address for a WAN interface | `velocloud` |
| `dn`, `address`, `encap`, `path_dn` | fields of the L3Out attachment | `apic` |
| `attachment_resolved` | `true` if `src/hst/collectors/mtu_apic.py` `_attachment_targets` finds the device and the port of each node of `tDn`. `false` for an `l3out-floating` interface | `apic` |
| `attachment_basis`, `mtu_operational_state`, `mtu_receive_state`, `ip_fragmentation`, `ip_fragmentation_basis` | `configured`, `unknown`, `unknown`, `unsupported` and `documented-aci` | `apic` |
| `mtu_source`, `operational_mtu_basis` | `NITRO Interface` and `unknown` | `netscaler` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Interface)-[:ON]->(Device)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic`, `checkpoint_gateway`, `equinix`, `unifi`, `velocloud`, `netscaler`, `edge-device-from-binding` |
| `(Interface)-[:REALIZED_BY]->(Port)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway`, `equinix`, `velocloud`, `edge-device-from-binding` |
| `(Interface)-[:REALIZED_BY]->(Lag)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway` |
| `(Interface)-[:BOUND_TO]->(VlanInstance)` | | `nxos`, `iosxe`, `vyos`, `checkpoint_gateway` |
| `(Interface)-[:BOUND_TO]->(Port)` | `basis`, `evidence_ref`, `physical_path_known` | `apic` |
| `(Interface)-[:HAS_IP]->(IpAddress)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud` |
| `(Interface)-[:HAS_IP]->(IpAddress)` | `fhrp`, `group`, `state` for a virtual address | `nxos`, `iosxe`, `iosxr` |
| `(Interface)-[:HAS_IP]->(IpAddress)` | `vrf` | `checkpoint_gateway` |
| `(Interface)-[:IN_VRF]->(VrfInstance)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `checkpoint_gateway` |
| `(Interface)-[:IN_CONTEXT]->(FirewallInstance)` | | `checkpoint_gateway` |
| `(Interface)-[:IN_CONTEXT]->(Device)` | | `checkpoint_gateway` |
| `(Interface)-[:MEMBER_OF]->(FhrpGroup)` | `priority`, `state` | `nxos`, `iosxe`, `iosxr` |
| `(Interface)-[:IN_AREA]->(OspfArea)` | `cost`, `network_type`, `passive` | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |
| `(Interface)-[:GATEWAY_FOR]->(Prefix)` | `vrf` | `checkpoint_gateway` |
| `(Interface)-[:GATEWAY_FOR]->(Prefix)` | | `gateway-from-router-interface`, `gateway-from-sole-firewall-interface`, `gateway-from-sole-segment-interface` |
| `(Interface)-[:ATTACHED_TO]->(BridgeDomain)` | `basis` with the value `svi` or `subif` | `attached-from-vlan-binding` |
| `(Interface)-[:ATTACHED_TO]->(BridgeDomain)` | `basis` with the value `cable` | `attached-from-cable` |
| `(Interface)-[:IN_BD]->(BridgeDomain)` | | `checkpoint_gateway` |
| `(Interface)-[:BRIDGED_TO]->(Interface)` | `bridge`, `source` with the value `vsx-bridge`, `evidence_uid`, `context_uid`, `policy_required` | `checkpoint_gateway` |
| `(Interface)-[:CONNECTED_TO]->(Interface)` | `source` with the value `vsx-warp`, `evidence_uid`, `member_uid` | `checkpoint_gateway` |
| `(Interface)-[:PROTECTED_BY]->(FwRulebase)` | `direction` | `nxos`, `iosxe`, `iosxr`, `unifi` |
| `(Interface)-[:ENFORCES]->(PbrPolicy)` | | `vyos` |
| `(Interface)-[:PART_OF]->(L3Out)` | | `apic` |
| `(Interface)-[:HAS_MTU]->(MtuObservation)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic`, `netscaler`, `manual` |

`(Interface)-[:IN_CONTEXT]->(Device)` ends at a virtual device of `checkpoint_gateway`. `checkpoint_gateway` writes `GATEWAY_FOR` only in a context of the kind `virtual-system` or `virtual-router`. The 3 gateway rules write `GATEWAY_FOR` only to a `Prefix` with the `kind` `connected`.

#### Lag

| Property | Content | Written by |
|---|---|---|
| `name` | the name of the aggregate | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway`, `apic` |
| `mode` | `mode` of the bond | `vyos` |
| `dn` | the DN of the aggregate | `apic` |
| `member_state` | `unknown` | `apic` |
| `membership_basis` | `configured` | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Lag)-[:ON]->(Device)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway`, `apic` |
| `(Lag)-[:REALIZED_BY]->(Port)` | | `apic` |

#### VlanInstance

| Property | Content | Written by |
|---|---|---|
| `vid` | the VLAN id. For `unifi`, `vlan` of the network, or 1 for a network with no `vlan` | `nxos`, `iosxe`, `vyos`, `unifi`, `checkpoint_gateway` |
| `name` | the VLAN name | `nxos`, `unifi` |

| Relationship | Properties | Written by |
|---|---|---|
| `(VlanInstance)-[:REALIZES]->(BridgeDomain)` | | `nxos`, `iosxe`, `vyos`, `unifi`, `checkpoint_gateway` |

#### BridgeDomain

`nxos`, `iosxe`, `vyos` and `checkpoint_gateway` write the `BridgeDomain` of a VLAN with no property. `unifi` does the same for the VLAN of a client whose network the payload does not hold.

| Property | Content | Written by |
|---|---|---|
| `name` | the network name | `unifi` |
| `security_class` | `guest` for a guest network | `unifi` |
| `name`, `dn` | the name and the DN of the ACI bridge domain | `apic` |
| `name` | the name of a VSX bridge | `checkpoint_gateway` |

| Relationship | Properties | Written by |
|---|---|---|
| `(BridgeDomain)-[:IN_VRF]->(VrfInstance)` | | `apic` |

#### FhrpGroup

| Property | Content | Written by |
|---|---|---|
| `kind` | the protocol in lower case | `nxos`, `iosxe`, `iosxr` |
| `group_id` | the group number | `nxos`, `iosxe`, `iosxr` |
| `vip` | the virtual address | `nxos`, `iosxe`, `iosxr` |
| `af` | the address family of `vip`, 4 or 6 | `nxos`, `iosxe`, `iosxr` |
| `virtual_mac` | the virtual MAC address | `nxos` |

| Relationship | Properties | Written by |
|---|---|---|
| `(FhrpGroup)-[:HAS_IP]->(IpAddress)` | | `nxos`, `iosxe`, `iosxr` |

#### Endpoint

| Property | Content | Written by |
|---|---|---|
| `mac` | the MAC address | `apic`, `unifi`, `checkpoint_gateway` |
| `name` | the name of the endpoint | `apic`, `unifi` |
| `kind` | `client` | `unifi` |
| `wired` | a boolean | `unifi` |
| `oui` | the vendor of the MAC OUI | `unifi` |
| `last_seen` | `last_seen` of the client in milliseconds | `unifi` |
| `context_uid`, `neighbor_interface` | the context and the interface of the neighbor row | `checkpoint_gateway` |
| `evidence` | `arp-nd` | `checkpoint_gateway` |
| `infra` | `true` | `cable-from-endpoint-mac` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Endpoint)-[:IN_EPG]->(Epg)` | | `apic` |
| `(Endpoint)-[:IN]->(BridgeDomain)` | | `apic`, `unifi` |
| `(Endpoint)-[:HAS_IP]->(IpAddress)` | | `apic`, `unifi`, `checkpoint_gateway` |
| `(Endpoint)-[:ATTACHED]->(Port)` | | `unifi` |
| `(Endpoint)-[:ATTACHED]->(Device)` | `ssid` | `unifi` |
| `(Endpoint)-[:HAS_MTU]->(MtuObservation)` | | `manual` |

No collector writes `Endpoint.ip`. `src/hst/core/labels.py` `ENDPOINT_ADDRESS_REL` gives `HAS_IP` as the relationship to the addresses of an endpoint.

#### Ssid

| Property | Content | Written by |
|---|---|---|
| `name` | the WLAN name | `unifi` |
| `security` | `security` of the WLAN | `unifi` |
| `enabled` | `enabled` of the WLAN, with the default `true` | `unifi` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Ssid)-[:BRIDGED_TO]->(VlanInstance)` | | `unifi` |

### L3 and routing

`src/hst/collectors/util.py` `VrfDomains.add` writes a `VrfInstance`, its `RouteTarget` nodes and its `RoutingDomain`. Only `iosxe` and `iosxr` give it route targets. `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi` and `velocloud` use it. `src/hst/collectors/util.py` `connected_address` writes an `IpAddress` and its connected `Prefix`. `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud` and `checkpoint_gateway` use it.

#### VrfInstance

| Property | Content | Written by |
|---|---|---|
| `name` | the name of the VRF | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `apic` |
| `name` | `vs:<VSID>`, or `vrf_uid` of the context in the payload | `checkpoint_gateway` |
| `name` | `table<table number>` for a numbered routing table | `vyos` |
| `name` | the id of the Nautobot VRF | `nautobot` |
| `rd` | the route distinguisher | `nxos`, `iosxe`, `iosxr` |
| `table_id` | the name of the VRF | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi` |
| `table_id` | the segment id: `logicalId` of the segment, else `segmentId`, else the segment name. `global` if no edge of the enterprise has a segment in `deviceSettings`. `Global Segment` on the VRF that the collector adds for an edge with no global segment | `velocloud` |
| `is_global` | `true` for the global table | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud` |
| `table` | `table` of the VRF in the configuration | `vyos` |
| `kind` | `policy-table` for a numbered routing table | `vyos` |
| `rib_mirrored` | `true` if `src/hst/collectors/vyos.py` `_route_stage` finds that the graph holds the whole RIB of the table, else `false` | `vyos` |
| `dn`, `pc_enf_pref` | the DN of the ACI VRF, and `pcEnfPref` in lower case | `apic` |
| `contract_bypass` | the flags `esg`, `preferred-group` and `vzany` of the VRF, sorted and joined with commas. `not-collected` if the payload lacks a class of `src/hst/collectors/apic.py` `CONTRACT_BYPASS_CLASSES`. An empty string if the VRF has no flag. `esg` on each VRF if an `fvESg` object has no `fvRsScope` with a `tDn` | `apic` |
| `firewall_instance_uid`, `authority`, `domain` | the context of the VRF | `checkpoint_gateway` |
| `vsx_runtime_sessions` | the result of `src/hst/collectors/checkpoint_evidence.py` `sessions_for` | `checkpoint_gateway` |
| `anchor`, `namespace_id`, `nautobot_vrf_id` | the namespace and the id of the Nautobot VRF | `nautobot` |
| `population_source` | `nautobot` | `nautobot` |

| Relationship | Properties | Written by |
|---|---|---|
| `(VrfInstance)-[:OWNED_BY]->(Device)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `checkpoint_gateway` |
| `(VrfInstance)-[:IMPORTS]->(RouteTarget)` | | `iosxe`, `iosxr` |
| `(VrfInstance)-[:EXPORTS]->(RouteTarget)` | | `iosxe`, `iosxr` |
| `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `declared` | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud` |
| `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `rt-component`, `rts` | `src/hst/core/reasoner.py` `execute_rt_domains` |
| `(VrfInstance)-[:IN_CONTEXT]->(FirewallInstance)` | | `checkpoint_gateway` |
| `(VrfInstance)-[:IN_CONTEXT]->(Device)` | | `checkpoint_gateway` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `connected` | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `checkpoint_gateway` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `network`, `route_map` | `nxos`, `iosxe`, `iosxr` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `network` | `vyos` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `aggregate`, `summary_only`, `as_set`, `attribute_map`, `unsupported_options` | `nxos`, `iosxe`, `iosxr` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `aggregate` | `vyos` |
| `(VrfInstance)-[:STATIC_ROUTE]->(Prefix)` | 1 of `next_hop`, `interface` and `discard` as the key, `distance`, `next_hop_vrf`, `rib_interface`, `via_dhcp`, `rib_confirmed` | `vyos` |
| `(VrfInstance)-[:LEARNED_ROUTE]->(Prefix)` | `via`, `next_hop`, `interface`, `protocol`, `metric`, `discard` | `vyos`, `checkpoint_gateway` |
| `(VrfInstance)-[:LEARNED_ROUTE]->(Prefix)` | `next_hop_vrf` | `vyos` |

The value of `via` is `<next hop>|<interface>`. `checkpoint_gateway` writes `LEARNED_ROUTE` only in a context of the kind `virtual-system` or `virtual-router`, and only for a route of the main table.

#### FirewallInstance

`checkpoint_gateway` writes 1 `FirewallInstance` for each context of the kind `virtual-system` or `bridge`.

| Property | Content | Written by |
|---|---|---|
| `gateway_object_uid`, `authority`, `domain` | the identity of the context in the management | `checkpoint_gateway` |
| `kind` | the kind of the context | `checkpoint_gateway` |
| `name` | the name of the context in `vsx stat -v` | `checkpoint_gateway` |

| Relationship | Properties | Written by |
|---|---|---|
| `(FirewallInstance)-[:RUNS_ON]->(Device)` | `vsid`, `state`, `observation_uid` | `checkpoint_gateway` |
| `(FirewallInstance)-[:HAS_INSTALLATION]->(PolicyInstallation)` | | `checkpoint_gateway` |
| `(FirewallInstance)-[:ENFORCES]->(FwRulebase)` | the key `context`, `ingress`, `egress`, `af`, and `installed`, `coverage`, `installed_revision`, `context_uid`, `ingress_interface_uid`, `egress_interface_uid`, `address_family`, `evidence_uid`, `observation_uid` | `checkpoint_gateway` |

#### RoutingDomain

| Property | Content | Written by |
|---|---|---|
| `name` | the display name of the domain | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `src/hst/core/reasoner.py` `execute_rt_domains` |
| `basis` | `rt-component` | `src/hst/core/reasoner.py` `execute_rt_domains` |
| `rts` | the route targets of the component, sorted and joined with commas | `src/hst/core/reasoner.py` `execute_rt_domains` |

`src/hst/core/reasoner.py` `build_rt_domains` makes 1 `RoutingDomain` for each group of 2 or more VRFs that route targets connect.

#### RouteTarget

| Property | Content | Written by |
|---|---|---|
| `value` | the route target | `iosxe`, `iosxr` |

#### Prefix

| Property | Content | Written by |
|---|---|---|
| `cidr` | the network in CIDR form | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `apic`, `checkpoint`, `checkpoint_gateway` |
| `af` | 4 or 6 | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `checkpoint`, `checkpoint_gateway` |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `checkpoint`, `checkpoint_gateway` |
| `anchor` | the routing domain of the VRF of the bridge domain, the same value as `l3dom` | `apic` |
| `l3dom` | the routing domain | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `apic`, `checkpoint` |
| `l3dom` | the name of the `VrfInstance`, on a connected `Prefix` only | `checkpoint_gateway` |
| `kind` | `connected` | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `checkpoint_gateway` |
| `kind` | `bgp-network`, `aggregate` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `kind` | `nat-pool` | `nxos`, `iosxe` |
| `name`, `security_class` | the network name, and `guest` for a guest network | `unifi` |
| `dhcp` | `true` | `vyos` |
| `gateway_ip`, `dn` | the gateway address and the DN of the ACI subnet | `apic` |
| `ipam_cidr`, `ipam_match`, `ipam_import`, `ipam_description`, `ipam_location`, `ipam_vlan` | the IPAM entry of the prefix | `src/hst/core/ipam.py` `annotate` |

A BGP statement sets `kind` only if the batch does not hold the `Prefix`. `ipam_match` is `exact` or `covering`.

| Relationship | Properties | Written by |
|---|---|---|
| `(Prefix)-[:IN]->(BridgeDomain)` | | `apic`, `prefix-in-from-attachment` |
| `(Prefix)-[:VIA]->(Interface)` | `vrf` | `vyos`, `checkpoint_gateway` |

`src/hst/collectors/checkpoint.py` `_write_carriage` and `src/hst/collectors/cisco_common.py` `_acl_address` write the addresses of a policy object. On these `Prefix` and `IpAddress` nodes, `l3dom` has the value `l3dom:unresolved:<scope>` with the scope of the batch. No reasoner rule changes the value.

#### IpAddress

| Property | Content | Written by |
|---|---|---|
| `ip` | the address | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `apic`, `checkpoint`, `checkpoint_gateway`, `netscaler`, `nautobot`, `manual` |
| `af` | 4 or 6 | the same source types |
| `anchor` | the value that the `uid` uses as scope | the same source types |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `apic`, `checkpoint`, `netscaler`, `manual` |
| `l3dom` | the name of the `VrfInstance`. Absent on a next hop address | `checkpoint_gateway` |
| `origin` | `configured` for an address of the configuration, `dynamic` for an address of `ip -j addr show`, on an interface address only | `vyos` |
| `ns_role` | `snip` | `netscaler` |
| `nautobot_id`, `vrf_id`, `namespace_id`, `role_id`, `location_id`, `tag_ids` | ids of the Nautobot address | `nautobot` |
| `population_source` | `nautobot` | `nautobot` |

| Relationship | Properties | Written by |
|---|---|---|
| `(IpAddress)-[:IN]->(Prefix)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `unifi`, `velocloud`, `checkpoint_gateway` |
| `(IpAddress)-[:IN]->(Prefix)` | | `src/hst/reasoner/containment.py` `CONTAINMENT_WRITE` with the rule name `address-containment` |
| `(IpAddress)-[:IN_VRF]->(VrfInstance)` | | `nautobot` |

#### RoutingProcess

| Property | Content | Written by |
|---|---|---|
| `proto` | `bgp` | `nxos`, `iosxe`, `iosxr`, `vyos`, `velocloud`, `checkpoint_gateway` |
| `proto` | `ospf` | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |
| `asn` | the local AS number | `nxos`, `iosxe`, `iosxr`, `vyos`, `velocloud`, `checkpoint_gateway` |
| `router_id` | the router id | `nxos`, `iosxe`, `iosxr`, `vyos`, `velocloud`, `apic` |
| `process_id` | the OSPF process id. An empty string for `vyos` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `always_compare_med` | `true` if configured | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `multipath_config_recorded`, `multipath_relax`, `maximum_paths_<ebgp or ibgp>_v<4 or 6>` | the result of `src/hst/collectors/util.py` `bgp_multipath_props` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `default_information_originate_afs` | the address families of a BGP default origin | `nxos`, `iosxe`, `iosxr` |
| `default_information_originate` | `true` if the OSPF process holds `default-information originate` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `default_information_originate_always` | `true` if that statement holds `always` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `redistribute_protocols` | the sorted protocols that the BGP process redistributes. For `nxos` and `iosxr`, without the statements of the IPv6 unicast address family. For `checkpoint_gateway`, the protocols of the `match protocol` terms of the enabled `permit` clauses of an exported route map, with `connected` for `direct` and without `bgp` and `ibgp` | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway` |
| `redist_<protocol>_route_map` | the route map of 1 redistribution of a BGP process | `nxos` |
| `redist_<protocol>_route_map` | the route map or the route policy of 1 redistribution of an OSPF process | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `origin_config_recorded` | a boolean | `nxos`, `iosxe`, `iosxr`, `vyos`, `velocloud`, `checkpoint_gateway` |
| `origin_afs` | `[4, 6]` | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway` |
| `origin_context_gaps` | a list of texts | `nxos`, `iosxe`, `iosxr`, `checkpoint_gateway` |
| `session_gaps` | a list of texts | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `ebgp_requires_policy`, `network_import_check` | `true` if `parameters` of the BGP process holds `ebgp-requires-policy`, and `true` if it holds `network-import-check`, else `false` | `vyos` |
| `platform` | `checkpoint-gaia` | `checkpoint_gateway` |
| `origin_role`, `preference_buckets`, `advertise_external`, `advertise_inter_area`, `advertise_intra_area`, `advertise_internal`, `advertise_static`, `advertise_connected` | the result of `src/hst/collectors/velocloud.py` `_origin_controls` | `velocloud` |

| Relationship | Properties | Written by |
|---|---|---|
| `(RoutingProcess)-[:IN_VRF]->(VrfInstance)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `velocloud`, `apic`, `checkpoint_gateway` |
| `(RoutingProcess)-[:HAS]->(BgpSession)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `velocloud`, `checkpoint_gateway` |
| `(RoutingProcess)-[:HAS]->(BgpPeerRange)` | | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `(RoutingProcess)-[:HAS]->(OspfArea)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |
| `(RoutingProcess)-[:HAS]->(OspfAdjacency)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |
| `(RoutingProcess)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `redistribute`, `protocol` | `nxos`, `iosxe`, `iosxr` |

#### BgpSession

`src/hst/collectors/cisco_bgp.py` `emit_bgp_peer` writes a `BgpSession` for a neighbor address and a `BgpPeerRange` for a neighbor network.

| Property | Content | Written by |
|---|---|---|
| `peer_ip`, `local_asn`, `peer_asn` | the neighbor address and the 2 AS numbers | `nxos`, `iosxe`, `iosxr`, `vyos`, `velocloud`, `checkpoint_gateway` |
| `state` | `shutdown` for a neighbor that is shut down | `nxos`, `iosxe`, `iosxr` |
| `state` | the state of the peer in `show bgp peers` in lower case. Else `shutdown` for a peer that the configuration turns off, else `unknown` | `checkpoint_gateway` |
| `afi_safi` | the list of address families | `nxos`, `iosxr`, `vyos` |
| `dynamic_range` | the listen range of a dynamic peer | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `observed_state` | the state of a dynamic peer in the session table of the device. For `nxos`, the `state` text of the device. For `iosxe` and `iosxr`, `Established` for a number in the state column, else the text of the column | `nxos`, `iosxe`, `iosxr` |
| `inheritance_gaps` | a list of texts, 1 for each template or group of the neighbor that the configuration does not hold | `iosxe`, `iosxr` |
| `import_policy_name`, `import_policy_kind`, `export_policy_name`, `export_policy_kind` | the session policy for each direction | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway` |
| `import_prefix_list_name`, `export_prefix_list_name` | a prefix list beside a route map | `nxos`, `iosxe`, `vyos` |
| `import_filter_list_name`, `export_filter_list_name` | the AS-path filter list | `nxos`, `iosxe`, `vyos` |
| `route_reflector_client`, `cluster_id` | the route reflector settings | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `peer_router_id` | the router id of the peer | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `next_hop_self` | the setting of the neighbor | `nxos`, `iosxe`, `vyos` |
| `peer_group` | the peer group of the neighbor | `iosxe`, `vyos` |
| `remote_as_route_map` | a field of the parsed neighbor | `nxos` |
| `local_ip`, `description` | `localIp` and `neighborTag` of the neighbor | `velocloud` |
| `af`, `local_address`, `context_uid`, `vsid` | the address family, the local address and the context | `checkpoint_gateway` |
| `platform` | `checkpoint-gaia` | `checkpoint_gateway` |

| Relationship | Properties | Written by |
|---|---|---|
| `(BgpSession)-[:MEMBER_OF]->(BgpPeerRange)` | | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `(BgpSession)-[:ENDPOINT]->(IpAddress)` | | `vyos`, `velocloud` |
| `(BgpSession)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `in`, `out`, `in-prefix-list` or `out-prefix-list` | `nxos`, `iosxe`, `vyos` |
| `(BgpSession)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `in` or `out` | `iosxr`, `checkpoint_gateway` |
| `(BgpSession)-[:PEERS_WITH]->(BgpSession)` | `basis` with the value `peer-address` | `bgp-peer-from-address` |

`bgp-peer-from-address` reads the `ENDPOINT` relationship of each of the 2 sessions.

#### BgpPeerRange

| Property | Content | Written by |
|---|---|---|
| `prefix`, `local_asn` | the neighbor network and the local AS number | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `peer_group` | the peer group of the range | `iosxe`, `vyos` |

A `BgpPeerRange` of `nxos`, `iosxe` or `iosxr` also holds the `BgpSession` properties of that source type, without `peer_ip`, `peer_router_id`, `dynamic_range` and `observed_state`. A `BgpPeerRange` of `nxos` also holds `inheritance_gaps`.

| Relationship | Properties | Written by |
|---|---|---|
| `(BgpPeerRange)-[:FILTERED_BY]->(RoutePolicy)` | `direction` | `nxos`, `iosxe`, `iosxr` |

#### OspfArea

| Property | Content | Written by |
|---|---|---|
| `area_id` | the area id | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |
| `type` | the area type | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |

#### OspfAdjacency

| Property | Content | Written by |
|---|---|---|
| `state` | the state of the adjacency | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |
| `area` | the area id | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |
| `neighbor_router_id`, `neighbor_ip` | the router id and the address of the neighbor | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |
| `local_interface` | the name of the local interface | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(OspfAdjacency)-[:ENDPOINT]->(Interface)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `apic` |

Each device writes its `OspfAdjacency` with 1 `ENDPOINT` relationship to the local interface.

#### RoutePolicy

| Property | Content | Written by |
|---|---|---|
| `name` | the name of the policy | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway` |
| `kind` | `route-map`, `prefix-list`, `community-list` or `as-path-list` | `nxos`, `iosxe`, `vyos` |
| `kind` | `rpl`, `prefix-list`, `community-list` or `as-path-list` | `iosxr` |
| `kind` | `gaia-route-map` or `gaia-chain` | `checkpoint_gateway` |
| `platform` | `checkpoint-gaia` on a `gaia-route-map` | `checkpoint_gateway` |
| `policy_names` | the route maps of a `gaia-chain` | `checkpoint_gateway` |
| `context_uid` | the context of the policy | `checkpoint_gateway` |

| Relationship | Properties | Written by |
|---|---|---|
| `(RoutePolicy)-[:HAS_RULE]->(RoutePolicyEntry)` | | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway` |
| `(RoutePolicy)-[:HAS_RULE]->(PrefixListEntry)` | | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `(RoutePolicy)-[:HAS_RULE]->(MatchListEntry)` | | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `(RoutePolicy)-[:REFERENCES]->(RoutePolicy)` | | `checkpoint_gateway` |

`(RoutePolicy)-[:REFERENCES]->(RoutePolicy)` starts at a `gaia-chain` and ends at a `gaia-route-map`.

#### RoutePolicyEntry

| Property | Content | Written by |
|---|---|---|
| `seq` | the sequence number. For `iosxr`, the position of the statement in the route policy, from 1. For a `gaia-clause`, the `id` of the route map clause, and 10 for `default`. For a `gaia-chain-member`, the position of the route map in the chain, from 0 | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway` |
| `kind` | `clause` | `nxos`, `iosxe`, `vyos` |
| `kind` | `statement` | `iosxr` |
| `kind` | `gaia-clause` or `gaia-chain-member` | `checkpoint_gateway` |
| `action` | the action of the entry. For `iosxr`, `permit` for `done` and `deny` for `drop`, else absent. For `checkpoint_gateway`, `permit`, `deny` or `unknown` on a `gaia-clause`, and absent on a `gaia-chain-member` | `nxos`, `iosxe`, `iosxr`, `vyos`, `checkpoint_gateway` |
| `continues`, `continue_seq` | the continue clause | `nxos`, `iosxe`, `vyos` |
| `continues`, `continue_seq` | `true` and the `seq` of the next branch, on a branch of an `if` statement that another branch follows | `iosxr` |
| `match_prefix_lists`, `match_as_path_lists`, `match_community_lists` | the lists that the match clauses reference | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `match_tags`, `match_metric` | values of the match clauses | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `match_protocols` | values of the match clauses | `nxos`, `iosxe` |
| `match_unsupported`, `set_unsupported` | the lines that the parser does not model | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `match_ignored` | a field of the parsed clause | `nxos` |
| `match_expr`, `match_policies`, `parent_seq`, `passes` | fields of the parsed statement | `iosxr` |
| `set_local_pref`, `set_metric`, `set_as_path_prepend`, `set_communities`, `set_communities_additive`, `set_comm_list_delete` | values of the set clauses | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `set_origin`, `set_tag`, `set_weight`, `set_next_hop` | values of the set clauses | `nxos`, `iosxe`, `iosxr` |
| `calls_policy` | the name of the called policy | `nxos`, `iosxr`, `vyos` |
| `enabled`, `gaia_terms`, `context_uid` | the state, the terms as JSON and the context of a `gaia-clause` | `checkpoint_gateway` |
| `policy_name`, `address_families` | the route map and the address families of a `gaia-chain-member` | `checkpoint_gateway` |

| Relationship | Properties | Written by |
|---|---|---|
| `(RoutePolicyEntry)-[:REFERENCES]->(RoutePolicy)` | `kind` with the value `prefix-list`, `community-list`, `as-path-list` or `call` | `nxos`, `iosxr`, `vyos` |
| `(RoutePolicyEntry)-[:REFERENCES]->(RoutePolicy)` | `kind` with the value `prefix-list`, `community-list` or `as-path-list` | `iosxe` |

A collector writes `REFERENCES` only if the batch holds the `RoutePolicy` with that name.

#### PrefixListEntry

| Property | Content | Written by |
|---|---|---|
| `seq`, `action`, `prefix` | the sequence number, the action and the prefix. For `iosxr`, `seq` is the position of the line in the prefix set, from 1, and `action` is `permit` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `ge`, `le` | the length bounds of the entry | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `eq` | the exact length of the entry | `nxos`, `iosxe`, `iosxr` |
| `min_len`, `max_len` | the lowest and the highest prefix length that the entry matches | `nxos`, `iosxe`, `iosxr`, `vyos` |

#### MatchListEntry

| Property | Content | Written by |
|---|---|---|
| `seq`, `action` | the sequence number and the action. For `iosxr`, `seq` is the position of the element in the set, from 1, and `action` is `permit` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `match_type` | the type that `src/hst/simul/matchlist.py` uses to read `value` | `nxos`, `iosxe`, `iosxr`, `vyos` |
| `value` | the value of the entry | `nxos`, `iosxe`, `iosxr`, `vyos` |

### Overlay and transport

#### Fabric

| Property | Content | Written by |
|---|---|---|
| `name` | the fabric name of the source | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Fabric)-[:HAS_MTU]->(MtuObservation)` | | `apic` |

#### Pod

| Property | Content | Written by |
|---|---|---|
| `name` | the DN of the pod | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Pod)-[:PART_OF]->(Fabric)` | | `apic` |

#### Tunnel

The table gives the values of `encap` for each source type.

| Source type | `encap` |
|---|---|
| `velocloud` | `velocloud-vcmp` |
| `vyos` | `wireguard`, `vxlan`, `ipsec` for a `vti` interface, or `encapsulation` of a `tunnel` interface |
| `zia` | `gre`, `ipsec` |

| Property | Content | Written by |
|---|---|---|
| `name` | `<WAN link> to <far end>` | `velocloud` |
| `name` | the name of the WireGuard peer | `vyos` |
| `endpoint` | the address of the far end | `velocloud`, `vyos` |
| `local_address` | the address of the local end | `velocloud`, `vyos` |
| `carrier_proto` | the protocol of the outer packet | `velocloud`, `vyos` |
| `endpoint_port` | the port of the far end | `velocloud`, `vyos` |
| `pair`, `peer_type`, `direction_observed`, `origin_config_recorded` | the result of `src/hst/core/uid.py` `tunnel` for the 2 ends, `gateway`, `hub` or `edge`, `false`, `true` | `velocloud` |
| `configuration_observed_at_ms`, `configuration_stale` | the time and the state of the configuration read | `velocloud` |
| `local_address_source` | `configured`, `derived:egress` for a WireGuard tunnel, or `derived:source-interface` | `vyos` |
| `allowed_ips`, `tunnel_mtu` | `allowed-ips` of the WireGuard peer, and the MTU of the WireGuard interface in `ip -j link`, else its configured `mtu` | `vyos` |
| `gre_key`, `gre_checksum`, `gre_sequence` | `true` if the `gre` or `gre-bridge` tunnel holds `parameters ip key`, `false` and `false` | `vyos` |
| `esp_encryption`, `esp_hash`, `esp_mode`, `esp_proposals` | fields of the ESP group of a `vti` tunnel | `vyos` |
| `source_ip` | the source address of the tunnel | `zia` |
| `vpn_type`, `ike_id` | `type` and `fqdn` of the VPN credential | `zia` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Tunnel)-[:ENDPOINT]->(Interface)` | | `velocloud`, `vyos` |
| `(Tunnel)-[:TERMINATES_ON]->(SdwanGateway)` | | `velocloud` |
| `(Tunnel)-[:TERMINATES_ON]->(IpAddress)` | | `velocloud` |
| `(Tunnel)-[:TERMINATES_ON]->(ZscalerDc)` | `role`, `vip` | `zia` |
| `(Tunnel)-[:CARRIES]->(SdwanSegment)` | | `velocloud` |
| `(Tunnel)-[:SAME_AS]->(IpAddress)` | `basis` with the value `source_ip`, `confidence` | `zpa-zia-ip-same-as` |
| `(Tunnel)-[:HAS_MTU]->(MtuObservation)` | | `manual` |

No code writes `bandwidth_mbps` or `bandwidth_source` on a `Tunnel` or on a `WanLink`.

#### OverlayConnection

`src/hst/collectors/util.py` `overlay_connection` writes the node and its relationships.

| Property | Content | Written by |
|---|---|---|
| `kind` | `tunnel` | `velocloud`, `vyos`, `zia` |
| `technology` | the `encap` of the tunnels | `velocloud`, `vyos`, `zia` |
| `name` | a text with the 2 ends | `velocloud`, `vyos`, `zia`, `overlay-connection-ends` |
| `observed_from` | the list of the end letters `a` and `b` that a batch reported | `velocloud`, `vyos`, `zia`, `overlay-connection-ends` |

| Relationship | Properties | Written by |
|---|---|---|
| `(OverlayConnection)-[:BETWEEN]->(Device)` | `end`, `role`, `reported` | `velocloud`, `vyos` |
| `(OverlayConnection)-[:BETWEEN]->(SdwanGateway)` | `end`, `role`, `reported` | `velocloud` |
| `(OverlayConnection)-[:BETWEEN]->(IpAddress)` | `end`, `role`, `reported` | `vyos` |
| `(OverlayConnection)-[:BETWEEN]->(ZiaLocation)` | `end`, `role`, `reported` | `zia` |
| `(OverlayConnection)-[:BETWEEN]->(ZscalerDc)` | `end`, `role`, `reported` | `zia` |
| `(OverlayConnection)-[:REALIZED_BY]->(Tunnel)` | | `velocloud`, `vyos`, `zia` |

`end` is `a` or `b`. `role` is `hub`, `edge` or `gateway` for `velocloud`, `peer` for `vyos` and `edge` or `gateway` for `zia`. `overlay-connection-ends` sets `name` and `observed_from` only for a connection with 2 reported ends.

#### SdwanSegment

| Property | Content | Written by |
|---|---|---|
| `segment_id`, `name` | the id and the name of the segment. `name` is `segment-<segment id>` for a segment with no name | `velocloud` |
| `enterprise_logical_id`, `enterprise_name` | the enterprise of the segment | `velocloud` |

#### ForwardingBoundary

| Property | Content | Written by |
|---|---|---|
| `edge_logical_id`, `segment_id` | the edge and the segment of the boundary | `velocloud` |
| `api_profile`, `orchestrator_release` | fields of the payload | `velocloud` |
| `candidate_set_complete` | `false` | `velocloud` |
| `selector` | `dynamic-steering` | `velocloud` |
| `unsupported_reason` | `VeloCloud dynamic path selection is opaque` | `velocloud` |
| `gaps` | a list of texts | `velocloud` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ForwardingBoundary)-[:IN]->(SdwanSegment)` | | `velocloud` |
| `(ForwardingBoundary)-[:HAS_ROUTE]->(SdwanStaticRoute)` | | `velocloud` |

#### WanLink

| Property | Content | Written by |
|---|---|---|
| `name` | the name of the link. For `velocloud`, `name` of the WAN configuration row, else `displayName` of the link row, else the interface, else the logical id of the link | `velocloud`, `vyos` |
| `kind` | `mpls`, `dia` or `lte` | `velocloud` |
| `kind` | `dia` or `static` | `vyos` |
| `carrier`, `public_ip`, `interface`, `link_logical_id` | the carrier, the address, the interface and the id of the link. `carrier` is `isp` or `org` of the link row, else `isp` of the WAN configuration row, else the private network of an `mpls` link, else `mpls` or `unknown` | `velocloud` |
| `state`, `link_mode`, `vpn_state`, `backup_state` | `state`, `linkMode`, `vpnState` and `backupState` of the link row | `velocloud` |
| `wan_mode`, `access_type`, `upstream_mbps`, `downstream_mbps`, `mtu`, `next_hop`, `backup_only`, `hot_standby` | fields of the WAN configuration row | `velocloud` |
| `private_network` | the private network of the link | `velocloud` |
| `configuration` | the WAN configuration row as JSON | `velocloud` |
| `configuration_observed_at_ms`, `configuration_stale` | the time and the state of the configuration read | `velocloud` |
| `origin_config_recorded` | a boolean | `velocloud` |
| `candidate_set_complete` | `false` | `velocloud` |

| Relationship | Properties | Written by |
|---|---|---|
| `(WanLink)-[:ON]->(Interface)` | | `velocloud`, `vyos` |
| `(WanLink)-[:HAS_IP]->(IpAddress)` | | `velocloud` |
| `(WanLink)-[:PROVIDED_BY]->(ProviderNetwork)` | | `velocloud` |

#### SdwanGateway

| Property | Content | Written by |
|---|---|---|
| `name`, `ip` | the name and the address of the gateway | `velocloud` |
| `roles` | `roles` of the gateway row as JSON | `velocloud` |

#### SdwanBusinessPolicy

| Property | Content | Written by |
|---|---|---|
| `name` | `<edge name> effective business policy` | `velocloud` |
| `precedence` | `edge-effective` | `velocloud` |
| `capability_gap` | JSON with `status`, `operation` and `reason` if no QOS profile body exists | `velocloud` |
| `observed_at_ms` | the time of the configuration read | `velocloud` |
| `rule_count` | the result of `src/hst/collectors/velocloud.py` `_policy_rules` | `velocloud` |

| Relationship | Properties | Written by |
|---|---|---|
| `(SdwanBusinessPolicy)-[:HAS_RULE]->(SdwanPolicyRule)` | `position` | `velocloud` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(WanLink)` | `application_class`, `preference` | `velocloud` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(WanLink)` | `application_class`, `route_type`, `segment_id`, `route_policy` | `velocloud` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(Tunnel)` | `application_class`, `route_type`, `segment_id`, `route_policy` | `velocloud` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(Tunnel)` | `application_class`, `route_type`, `route_policy` with the value `backhaul` | `velocloud` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(Device)` | `application_class`, `route_type`, `segment_id`, `route_policy` | `velocloud` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(ForwardingBoundary)` | | `velocloud` |

#### SdwanPolicyRule

| Property | Content | Written by |
|---|---|---|
| `name`, `rule_logical_id`, `position`, `default`, `override` | the identity and the position of the rule | `velocloud` |
| `segment_id`, `segment_name` | the segment of the rule | `velocloud` |
| `match_app_id`, `match_app_class_id`, `match_dscp`, `match_proto`, `match_src`, `match_dst`, `match_src_port`, `match_dst_port`, `match_hostname`, `match_src_interface`, `match_dst_interface`, `match_src_vlan`, `match_dst_vlan`, `match_ip_version`, `match_summary` | the result of `src/hst/collectors/velocloud.py` `_rule_match` | `velocloud` |
| `match_unmapped` | the result of `src/hst/collectors/velocloud.py` `_unmapped_match` | `velocloud` |
| `qos_class`, `priority_tx`, `priority_rx`, `bandwidth_cap_pct_tx`, `bandwidth_cap_pct_rx`, `route_type`, `sla_latency_ms`, `sla_jitter_ms`, `sla_loss_pct`, `nat_source`, `nat_dest` | the result of `src/hst/collectors/velocloud.py` `_rule_action` | `velocloud` |
| `<prefix>_route_policy`, `<prefix>_link_policy`, `<prefix>_wanlink`, `<prefix>_outer_dscp`, `<prefix>_backhaul_hubs` | the route action of the rule for each `<prefix>` of `edge2edge`, `edge2datacenter` and `edge2cloud` | `velocloud` |

| Relationship | Properties | Written by |
|---|---|---|
| `(SdwanPolicyRule)-[:IN]->(SdwanSegment)` | | `velocloud` |

#### SdwanStaticRoute

| Property | Content | Written by |
|---|---|---|
| `cidr`, `next_hop`, `interface` | the prefix, the gateway and the interface of the route | `velocloud` |
| `cost`, `preferred`, `advertise`, `description` | fields of the route row | `velocloud` |
| `segment_id` | the segment of the route | `velocloud` |

#### NdoSchema

| Property | Content | Written by |
|---|---|---|
| `name` | `displayName` of the schema | `ndo` |

| Relationship | Properties | Written by |
|---|---|---|
| `(NdoSchema)-[:HAS]->(NdoTemplate)` | | `ndo` |

#### NdoTemplate

| Property | Content | Written by |
|---|---|---|
| `name` | `displayName` or `name` of the template | `ndo` |
| `tenant` | `tenantName` of the template | `ndo` |

| Relationship | Properties | Written by |
|---|---|---|
| `(NdoTemplate)-[:DEFINES]->(Epg)` | | `ndo` |
| `(NdoTemplate)-[:DEFINES]->(BridgeDomain)` | | `ndo` |

### ACI policy and service insertion

3 functions of the `apic` collector write the nodes of an APIC object.

| Function | Labels |
|---|---|
| `src/hst/collectors/apic.py` `_tenant_stage` | `Tenant`, `AppProfile`, `Epg` |
| `src/hst/collectors/apic.py` `_contract_stage` | `Contract`, `ContractSubject`, `AciFilter`, `FilterEntry`, `L3Out`, `ExtEpg` |
| `src/hst/collectors/apic.py` `_service_stage` | `ServiceGraphTemplate`, `ServiceGraphInstance`, `PbrPolicy`, `PbrDest`, `DvPortgroup` |

Each of these nodes holds the DN of its APIC object in `dn`. The tables below do not list `dn`. A relationship cell gives the 2 labels of the collector record. The loader finds each end of a relationship by `uid`.

#### Tenant

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `fvTenant` object | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Tenant)-[:HAS]->(AppProfile)` | | `apic` |
| `(Tenant)-[:HAS]->(Contract)` | | `apic` |

The start of each `HAS` relationship is the parent DN of the child object.

#### AppProfile

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `fvAp` object | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(AppProfile)-[:HAS]->(Epg)` | | `apic` |

#### Epg

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `fvAEPg` object | `apic` |
| `pref_group_member` | `prefGrMemb` of the `fvAEPg` object in lower case | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Epg)-[:IN_BD]->(BridgeDomain)` | | `apic` |
| `(Epg)-[:PROVIDES]->(Contract)` | | `apic` |
| `(Epg)-[:CONSUMES]->(Contract)` | | `apic` |
| `(Epg)-[:STATIC_BINDING]->(Port)` | `encap`, `mode` | `apic` |
| `(Epg)-[:VMM_BINDING]->(DvPortgroup)` | | `apic` |

| Relationship | APIC class | Start | End |
|---|---|---|---|
| `IN_BD` | `fvRsBd` | the parent DN | `tDn` |
| `PROVIDES` | `fvRsProv` | the parent DN | `tDn` |
| `CONSUMES` | `fvRsCons` | the parent DN | `tDn` |
| `STATIC_BINDING` | `fvRsPathAtt` | the parent DN | the `Port` of the path in `tDn` |
| `VMM_BINDING` | `fvRsDomAtt` | the parent DN | `tDn` |

`src/hst/collectors/apic.py` `_service_stage` writes 1 `STATIC_BINDING` relationship for each node id of the path. A `protpaths` segment holds its node ids with `-` between them. The function writes no relationship for a node id that has no `fabricNode` object. `encap` and `mode` hold the attributes `encap` and `mode` of `fvRsPathAtt`. The function writes `VMM_BINDING` only if `tDn` starts with `uni/vmmp-`.

#### ExtEpg

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `l3extInstP` object | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ExtEpg)-[:PART_OF]->(L3Out)` | | `apic` |
| `(ExtEpg)-[:MATCHES]->(Prefix)` | | `apic` |
| `(ExtEpg)-[:PROVIDES]->(Contract)` | | `apic` |
| `(ExtEpg)-[:CONSUMES]->(Contract)` | | `apic` |

#### L3Out

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `l3extOut` object | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(L3Out)-[:PART_OF]->(Tenant)` | | `apic` |
| `(L3Out)-[:IN_VRF]->(VrfInstance)` | | `apic` |

#### Contract

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `vzBrCP` object | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Contract)-[:HAS]->(ContractSubject)` | | `apic` |

#### ContractSubject

`src/hst/collectors/apic.py` `_contract_stage` writes a `ContractSubject` only for a `vzSubj` object whose parent is a `vzBrCP` object.

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `vzSubj` object | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ContractSubject)-[:USES_FILTER]->(AciFilter)` | `action`, `directives`, `direction` | `apic` |
| `(ContractSubject)-[:APPLIES_GRAPH]->(ServiceGraphTemplate)` | | `apic` |

2 APIC classes give a `USES_FILTER` relationship.

| APIC class | `direction` | Key of the relationship |
|---|---|---|
| `vzRsSubjFiltAtt` | absent | none |
| `vzRsFiltAtt` below the term `intmnl` | `in` | `direction` |
| `vzRsFiltAtt` below the term `outtmnl` | `out` | `direction` |

`action` and `directives` hold the attributes `action` and `directives` of the APIC object. `APPLIES_GRAPH` comes from the class `vzRsSubjGraphAtt`, and its end is `tDn`.

#### AciFilter

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `vzFilter` object | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(AciFilter)-[:HAS]->(FilterEntry)` | | `apic` |

#### FilterEntry

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `vzEntry` object | `apic` |
| `proto` | `prot` | `apic` |
| `ether_type` | `etherT`, or `unspecified` if the reply has no `etherT` | `apic` |
| `s_from_port` | `sFromPort` | `apic` |
| `s_to_port` | `sToPort` | `apic` |
| `d_from_port` | `dFromPort` | `apic` |
| `d_to_port` | `dToPort` | `apic` |
| `tcp_rules` | `tcpRules`, or `unspecified` if the reply has no `tcpRules` | `apic` |
| `apply_to_frag` | `applyToFrag`, or `no` if the reply has no `applyToFrag` | `apic` |
| `stateful` | `stateful` | `apic` |

`src/hst/core/aci_filter.py` `aci_port` converts each of the 4 port attributes. A port name of `src/hst/core/aci_filter.py` `ACI_PORT_NAMES` becomes its number as a string. An absent attribute becomes `unspecified`. No relationship starts at a `FilterEntry`.

#### ServiceGraphTemplate

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `vnsAbsGraph` object | `apic` |

No relationship starts at a `ServiceGraphTemplate`.

#### ServiceGraphInstance

| Property | Content | Written by |
|---|---|---|
| `ctrct_dn` | `ctrctDn` of the `vnsGraphInst` object | `apic` |

No relationship starts or ends at a `ServiceGraphInstance`.

#### PbrPolicy

The `apic` collector writes a `PbrPolicy` for each `vnsSvcRedirectPol` object. The `vyos` collector writes a `PbrPolicy` for each policy below `policy route` and `policy route6`. A VyOS node has no `dn`.

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the `vnsSvcRedirectPol` object, or the name of the VyOS policy | `apic`, `vyos` |
| `vendor` | `vyos` | `vyos` |
| `af` | 4 for `policy route`, 6 for `policy route6` | `vyos` |

| Relationship | Properties | Written by |
|---|---|---|
| `(PbrPolicy)-[:HAS_DEST]->(PbrDest)` | | `apic` |
| `(PbrPolicy)-[:HAS_RULE]->(FwRule)` | | `vyos` |

`src/hst/collectors/vyos.py` `_pbr` writes the VyOS policy and its rules. Each rule is a `FwRule` with the action `route`. [FwRule](#fwrule) lists the properties and the relationships of the rule.

`src/hst/collectors/vyos.py` `_legacy_policy_route` writes 1 `PbrPolicy` for each interface that has an `Interface` node and holds a `policy` node in the configuration. The policy has the name `unread VyOS 1.3 policy on <interface>`, no `af` and 1 rule. The rule has `states_opaque` true.

#### PbrDest

| Property | Content | Written by |
|---|---|---|
| `ip` | `ip` of the `vnsRedirectDest` object | `apic` |
| `mac` | `mac` of the `vnsRedirectDest` object | `apic` |

No relationship starts at a `PbrDest`.

#### DvPortgroup

`src/hst/core/labels.py` `LABELS` holds `DvPortgroup` in the group of the virtualization labels. `src/hst/collectors/apic.py` `_service_stage` writes 1 `DvPortgroup` for each VMM domain DN in the `tDn` of an `fvRsDomAtt` object.

| Property | Content | Written by |
|---|---|---|
| `name` | the text after `dom-` in the DN | `apic` |

| Relationship | Properties | Written by |
|---|---|---|
| `(DvPortgroup)-[:HAS_MTU]->(MtuObservation)` | | `manual` |

### Firewall model

| Function | Source types | Labels |
|---|---|---|
| `src/hst/collectors/checkpoint.py` `normalize_checkpoint` | `checkpoint` | `FwRulebase`, `FwRule`, `CpPolicyPackage`, `CpPolicyObject`, `NetObject`, `SvcObject` |
| `src/hst/collectors/checkpoint.py` `_nat_stage` | `checkpoint` | `FwRulebase`, `NatRule` |
| `src/hst/collectors/checkpoint_gateway.py` `normalize_checkpoint_gateway` | `checkpoint_gateway` | `PolicyInstallation` |
| `src/hst/collectors/vyos.py` `_firewall` | `vyos` | `FwRulebase`, `FwRule`, `NetObject`, `SvcObject`, `Zone` |
| `src/hst/collectors/vyos.py` `_legacy_firewall` | `vyos` | `FwRulebase` |
| `src/hst/collectors/vyos.py` `_legacy_policy_route` | `vyos` | `FwRule` |
| `src/hst/collectors/vyos.py` `_nat` | `vyos` | `FwRulebase`, `NatRule`, `NetObject` |
| `src/hst/collectors/vyos.py` `_pbr` | `vyos` | `FwRule`, `NetObject`, `SvcObject` |
| `src/hst/collectors/unifi.py` `_zone_firewall` | `unifi` | `FwRulebase`, `FwRule`, `NetObject`, `SvcObject`, `Zone` |
| `src/hst/collectors/unifi.py` `_classic_firewall` | `unifi` | `FwRulebase`, `FwRule`, `NetObject`, `SvcObject` |
| `src/hst/collectors/cisco_common.py` `acl_stage` | `nxos`, `iosxe`, `iosxr` | `FwRulebase`, `FwRule`, `NetObject`, `SvcObject` |
| `src/hst/collectors/cisco_common.py` `nat_stage` | `nxos`, `iosxe` | `FwRulebase`, `NatRule` |

The `iosxr` collector reads the bindings of an access list and no entries. Each rulebase of `iosxr` holds 1 placeholder rule.

#### FwRulebase

The collectors write these rulebases.

| Source type | Rulebase | `kind` | `match_context` |
|---|---|---|---|
| `checkpoint` | an access layer | `access` | `device` |
| `checkpoint` | the NAT rules of 1 package | `nat` | absent |
| `vyos` | a ruleset below `firewall ipv4 name` or `firewall ipv6 name` | `access` | `zone-pair` if a zone binds the ruleset, else absent |
| `vyos` | the filter of the chain `forward`, `input` or `output` | `access` | `device` |
| `vyos` | the configuration of VyOS 1.3 that the collector does not read | `access` | `device` |
| `vyos` | the rules of 1 direction below `nat` or `nat66` | `nat` | absent |
| `unifi` | a pair of a source zone and a destination zone | `zone` | `zone-pair` |
| `unifi` | a classic ruleset of `LAN`, `WAN` or `GUEST` with the direction `IN` or `OUT` | `access` | `interface-acl` |
| `unifi` | each other classic ruleset | `access` | `device` |
| `nxos`, `iosxe`, `iosxr` | a pair of a family of `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` and a list name with 1 or more interface bindings | `access` | `interface-acl` |
| `nxos`, `iosxe` | the NAT rules of 1 direction | `nat` | absent |

| Property | Content | Written by |
|---|---|---|
| `name` | the name of the layer, the ruleset or the access list. The filter of a VyOS chain has `ipv4-<chain>` or `ipv6-<chain>`. The rulebase of `_legacy_firewall` has `unread VyOS 1.3 firewall`. A UniFi zone pair has `<source zone>-<destination zone>`, with ` (IPv6)` after it on the IPv6 rulebase. For `nxos`, `iosxe` and `iosxr`, the family `vlan-map` has the name of the VLAN access map, the family `zone` has the zone name, the family `common` has `<common list> <list>` or the common list alone, and the family `unparsed` has the binding line. A NAT rulebase has `NAT:<package>`, `<tree>-<direction>` or `nat-<direction>` | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `kind` | `access`, `nat` or `zone` | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `vendor` | `checkpoint`, `vyos`, `ubiquiti` or `cisco` | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `match_context` | `device`, `zone-pair` or `interface-acl` | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `af` | 4 or 6. Absent on a NAT rulebase, on the rulebase of `_legacy_firewall`, on the first rulebase of a UniFi zone pair and on a Cisco list with no address family | `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `chain` | `forward`, `input` or `output` | `vyos`, `unifi` |
| `default_action` | the action for a flow that no rule matches | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `default_action_unknown` | true if the rulebase has no `default_action` | `checkpoint`, `vyos`, `unifi` |
| `default_jump_target` | the uid of the ruleset of `default-jump-target` if the default action is `jump`, else an empty string | `vyos` |
| `global_state_policy` | a list of `<state>=<action>` strings | `checkpoint`, `vyos` |
| `state_policy_basis` | `vendor-default` | `checkpoint` |
| `configured_revision` | the revision of the configuration that the collector read | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `installed` | true | `vyos`, `unifi` |
| `coverage` | `complete` | `vyos`, `unifi` |
| `installed_revision` | the value of `configured_revision` | `vyos`, `unifi` |
| `established_default_unknown` | true | `unifi` |
| `unreported_bindings` | a list of `<interface> <direction>` strings for the bindings with no `Interface` node | `unifi`, `nxos`, `iosxe`, `iosxr` |
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object | `checkpoint` |

`default_action` has these values.

| Source type | `default_action` |
|---|---|
| `checkpoint` | `accept` or `drop` from `implicit-cleanup-action` of the layer |
| `vyos` | `default-action` of the ruleset |
| `unifi` | `accept` for a classic ruleset of `src/hst/collectors/unifi.py` `_CLASSIC_DEFAULTS` |
| `nxos`, `iosxe`, `iosxr` | `deny` |

If an enabled network has isolation on or internet access off, `src/hst/collectors/unifi.py` `_classic_firewall` writes no `default_action`.

`configured_revision` has these values.

| Source type | `configured_revision` |
|---|---|
| `checkpoint` | the first revision that `package_revisions` holds for a package of the layer, else the result of `src/hst/collectors/checkpoint.py` `_policy_revision` for the layer |
| `vyos` | the SHA-256 of the `firewall` node of the configuration |
| `unifi` | the result of `src/hst/collectors/unifi.py` `_firewall_revision` |
| `nxos`, `iosxe`, `iosxr` | the SHA-256 of the name and the entries of the access list |

A NAT rulebase holds `name`, `kind` and `vendor` only. The rulebase of `_legacy_firewall` holds `name`, `kind`, `vendor`, `chain` with the value `forward`, `match_context` and `default_action_unknown` only. Each rulebase of `src/hst/collectors/vyos.py` `_firewall` holds `installed`, `coverage` and `installed_revision`. For UniFi, only the rulebase of a zone pair holds the 3 properties. No collector writes the values `ips-profile`, `sg`, `nsg` and `azfw-collection` of `src/hst/core/labels.py` `FWRULEBASE_KINDS`. No collector writes the value `object-attached` of `src/hst/core/labels.py` `MATCH_CONTEXTS`.

`src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` gives the `af` of a Cisco rulebase.

| Family | `af` | Rules |
|---|---|---|
| `ipv4` | 4 | 1 rule for each entry of the access list. 1 placeholder rule if the payload holds no entry of the list |
| `ipv6` | 6 | 1 placeholder rule |
| `mac`, `vlan-map`, `common`, `unparsed`, `zone` | absent | 1 placeholder rule |

| Relationship | Properties | Written by |
|---|---|---|
| `(FwRulebase)-[:HAS_RULE]->(FwRule)` | | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `(FwRulebase)-[:HAS_RULE]->(NatRule)` | | `checkpoint`, `vyos`, `nxos`, `iosxe` |
| `(FwRulebase)-[:FROM_ZONE]->(Zone)` | | `vyos`, `unifi` |
| `(FwRulebase)-[:TO_ZONE]->(Zone)` | | `vyos`, `unifi` |

For `zone Z from X firewall`, the `vyos` collector writes `FROM_ZONE` to zone X and `TO_ZONE` to zone Z. For `intra-zone-filtering firewall`, the 2 relationships end at the same zone.

#### FwRule

A `FwRule` is a rule of a `FwRulebase` or a rule of a VyOS `PbrPolicy`.

| Property | Content | Written by |
|---|---|---|
| `position` | the number of the rule in its rulebase | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `action` | the action of the rule | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `enabled` | false for a rule that the configuration disables. True on each rule of `nxos`, `iosxe` and `iosxr` | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `name` | the name or the description of the rule | `checkpoint`, `vyos`, `unifi` |
| `rule_uid` | `uid` of the Check Point rule. `_id` of the UniFi rule. For `vyos`, `<ruleset name>:<rule number>` on a rule of `_firewall`, `pbr:<policy name>:<rule number>` or `pbr:ipv6:<policy name>:<rule number>` on a rule of `_pbr`, and `pbr:unread-legacy:<interface name>:1` on the rule of `_legacy_policy_route`. `_legacy_policy_route` writes the rule for each interface that has an `Interface` node and holds a `policy` node in the configuration | `checkpoint`, `vyos`, `unifi` |
| `rulebase_uid` | the API uid of the layer | `checkpoint` |
| `src_any` | true if the rule has no source address match | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `dst_any` | true if the rule has no destination address match | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `svc_any` | true if the rule has no protocol match and no port match. For `nxos`, `iosxe` and `iosxr`, true only on a rule with no `SVC` relationship | `checkpoint`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `src_negate` | true if the rule negates the source side | `checkpoint`, `vyos`, `unifi` |
| `dst_negate` | true if the rule negates the destination side | `checkpoint`, `vyos`, `unifi` |
| `svc_negate` | `service-negate` of the rule | `checkpoint` |
| `install_on` | the API uids of the gateways in the column `install-on`, without Any and Policy Targets | `checkpoint` |
| `install_on_unresolved` | true if an entry of `install-on` is not a gateway of the payload | `checkpoint` |
| `states` | the list of connection states that the rule matches | `vyos`, `unifi`, `nxos`, `iosxe` |
| `states_opaque` | true if the rule holds a match that the collector does not model | `checkpoint`, `vyos`, `unifi` |
| `states_opaque_reason` | the text of that match | `checkpoint`, `vyos`, `unifi` |
| `unmodeled_fields` | a list of the rule fields that the collector does not model | `checkpoint`, `unifi`, `nxos`, `iosxe` |
| `jump_target` | the uid of the ruleset of `jump-target` if the action is `jump`, else an empty string | `vyos` |
| `in_interface`, `out_interface` | `name` of `inbound-interface` and of `outbound-interface` | `vyos` |
| `in_interface_group`, `out_interface_group` | `group` of `inbound-interface` and of `outbound-interface`, or an empty string | `vyos` |
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object | `checkpoint` |

`action` has these values.

| Source type | `action` |
|---|---|
| `checkpoint` | the name of the `RulebaseAction` object in lower case |
| `vyos` | `action` of the rule. `route` for a rule of a `PbrPolicy` |
| `unifi` | `accept`, `drop` or `reject` for the policy actions `ALLOW`, `BLOCK` and `REJECT`. The classic `action` in lower case |
| `nxos`, `iosxe`, `iosxr` | the action of the entry. `deny` for a placeholder rule |

A rule of `src/hst/collectors/vyos.py` `_pbr` holds `position`, `action`, `name`, `enabled`, `rule_uid`, `states_opaque`, `states_opaque_reason`, `src_negate` and `dst_negate` only. The rule of `src/hst/collectors/vyos.py` `_legacy_policy_route` holds `position`, `action`, `enabled`, `rule_uid`, `states_opaque` and `states_opaque_reason` only. The `unifi` collector writes `src_negate` and `dst_negate` only on a rule of a zone pair. `src/hst/collectors/unifi.py` `_zone_firewall` writes no rule for a policy with `enabled` false. A placeholder rule of `src/hst/collectors/cisco_common.py` `_acl_placeholder_rule` has `position` 1 and holds no `states` and no `unmodeled_fields`.

| Relationship | Properties | Written by |
|---|---|---|
| `(FwRule)-[:SRC]->(NetObject)` | | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `(FwRule)-[:DST]->(NetObject)` | | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `(FwRule)-[:SVC]->(SvcObject)` | | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `(FwRule)-[:REDIRECTS_VIA]->(VrfInstance)` | `table` | `vyos` |

`_pbr` reads `set table` of a rule. If the table is `main` or `src/hst/collectors/vyos.py` `_route_stage` wrote a `VrfInstance` for the table, `_pbr` writes `REDIRECTS_VIA`. `table` holds the table name of the rule. No collector writes `SRC`, `DST` or `SVC` for a side that matches Any.

#### CpPolicyPackage

`src/hst/collectors/checkpoint.py` `normalize_checkpoint` writes 1 node for each entry of `package_details` in the payload.

| Property | Content | Written by |
|---|---|---|
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the package detail | `checkpoint` |
| `capture_complete` | false if the payload holds an entry in `policy_section_errors` | `checkpoint` |
| `implied_complete` | true if `implied_rules_complete` of the payload is true | `checkpoint` |
| `authority_uid` | the host of the source | `checkpoint` |
| `domain_uid` | the `uid` of `domain` in the package detail, else the domain of the source | `checkpoint` |
| `management_release` | the result of `src/hst/collectors/checkpoint.py` `_management_release` | `checkpoint` |
| `gateway_release` | the result of `src/hst/collectors/checkpoint.py` `_gateway_release` | `checkpoint` |
| `api_version` | `api_version` of the payload | `checkpoint` |

| Relationship | Properties | Written by |
|---|---|---|
| `(CpPolicyPackage)-[:HAS_LAYER]->(FwRulebase)` | `position` | `checkpoint` |

`position` is the index of the package in the sorted list of the packages of the layer.

#### CpPolicyObject

`src/hst/collectors/checkpoint.py` `normalize_checkpoint` writes 1 node for each entry of the objects dictionary with the type `CpmiAnyObject` or `RulebaseAction`.

| Property | Content | Written by |
|---|---|---|
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object | `checkpoint` |

No relationship starts or ends at a `CpPolicyObject`.

#### PolicyInstallation

`src/hst/collectors/checkpoint_gateway.py` `normalize_checkpoint_gateway` reads the installation observations of each context of the kind `virtual-system` or `bridge`. The observations are `installations` of the context in the payload and the result of `src/hst/collectors/checkpoint_evidence.py` `installations_for`. `normalize_checkpoint_gateway` writes 1 node for each pair of a rulebase uid and an installed revision in the observations of 1 context.

`installations_for` reads `installations` of `vsx_evidence` in the payload. It returns an installation with the `vsid` of the context only if these 3 conditions are true.

- `authority` and `gateway_object_uid` agree with the context.
- The `installation` text of the context holds a policy with the same `policy_name` and `installed_at_raw`.
- `ingress_interface` and `egress_interface` are `*` or an interface of the context.

| Property | Content | Written by |
|---|---|---|
| `installed_revision` | the installed revision of the observation | `checkpoint_gateway` |
| `context_uid` | the uid of the `VrfInstance` of the context | `checkpoint_gateway` |
| `observation_uid` | the observation uid of the source | `checkpoint_gateway` |

| Relationship | Properties | Written by |
|---|---|---|
| `(PolicyInstallation)-[:INSTALLS]->(FwRulebase)` | | `checkpoint_gateway` |

#### NetObject

| Property | Content | Written by |
|---|---|---|
| `name` | the name of the object or of the group, or the address of an inline match. For `unifi`, also `group:<group id>`, `network:<network id>`, `gateway:<network id>`, `src side (opaque)` and `dst side (opaque)`. For `nxos`, `iosxe` and `iosxr`, the access list name on a placeholder rule. On an entry side with no address, the reason text, else `src` or `dst` | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `kind` | the kind of the object | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `ip`, `cidr`, `ip6`, `cidr6` | `ipv4-address`, `subnet4` with `mask-length4`, `ipv6-address`, `subnet6` with `mask-length6` | `checkpoint` |
| `ranges` | a list of `<first>-<last>` address ranges | `checkpoint`, `vyos` |
| `opaque` | true if the collector cannot give the address set of the object | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `opaque_reason` | the reason as text | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe`, `iosxr` |
| `opaque_note` | a short form of the reason | `nxos`, `iosxe`, `iosxr` |
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object | `checkpoint` |

`kind` has these values.

| Source type | `kind` |
|---|---|
| `checkpoint` | `type` of the API object |
| `vyos` | `group` for an address group or a network group, `inline` for an address in a rule |
| `unifi` | `group`, `host`, `cidr`, `network` or `opaque` |
| `nxos`, `iosxe`, `iosxr` | `inline` |

| Relationship | Properties | Written by |
|---|---|---|
| `(NetObject)-[:RESOLVES_TO]->(Prefix)` | | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `(NetObject)-[:RESOLVES_TO]->(IpAddress)` | | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `(NetObject)-[:MEMBER_OF]->(NetObject)` | | `checkpoint` |

`MEMBER_OF` starts at the member and ends at the group. `src/hst/collectors/checkpoint.py` `_group_closure` gives the addresses of each member of a group to a maximum depth of 16. The group has a `RESOLVES_TO` relationship to each of these addresses.

#### SvcObject

| Property | Content | Written by |
|---|---|---|
| `name` | the name of the Check Point object or of the port group. The service of a rule has `<proto>/<ports>`, with `any` for an absent part and ` src <ports>` after it for a source port. In a VyOS rule with a port group, `<ports>` is the group name. For `nxos` and `iosxe`, an ICMP entry with a type has `icmp <type>`. A UniFi service has `all` for an absent protocol. An opaque UniFi service has `service (opaque)` | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `kind` | `type` of the Check Point API object, or `group` for a port group | `checkpoint`, `vyos`, `unifi` |
| `proto` | the protocol | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `ports` | the destination ports | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `src_port` | the source ports | `vyos`, `unifi`, `nxos`, `iosxe` |
| `icmp_type` | the ICMP type of an ICMP entry | `nxos`, `iosxe` |
| `opaque` | true if the collector cannot give the match of the service | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `opaque_reason` | the reason as text | `checkpoint`, `vyos`, `unifi`, `nxos`, `iosxe` |
| `opaque_note` | a short form of the reason | `nxos`, `iosxe` |
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object | `checkpoint` |

The `checkpoint` collector writes `proto` and `ports` only for the types of `src/hst/collectors/checkpoint.py` `_CP_REAL_PROTO_KINDS`. `ports` is a string for `checkpoint`, `nxos` and `iosxe`. It is a list of strings for `vyos`. For `unifi`, it is a list for a port group and a string for each other service. A `!` before the value of `proto` negates the protocol for `vyos` and `unifi`.

| Relationship | Properties | Written by |
|---|---|---|
| `(SvcObject)-[:MEMBER_OF]->(SvcObject)` | | `checkpoint` |

`MEMBER_OF` starts at the member and ends at the service group.

#### Zone

| Property | Content | Written by |
|---|---|---|
| `name` | the name of the zone | `vyos`, `unifi` |
| `local_zone` | true if the zone holds `local-zone` | `vyos` |
| `intra_zone_filtering` | true if the zone holds `intra-zone-filtering` | `vyos` |
| `intra_zone_action` | `action` of `intra-zone-filtering` | `vyos` |
| `default_action` | `default-action` of the zone | `vyos` |
| `default_action_unknown` | true if the zone has no `default_action`. True on each UniFi zone | `vyos`, `unifi` |
| `configured_revision` | the value of the same property of the rulebases | `vyos`, `unifi` |
| `installed` | true | `vyos`, `unifi` |
| `coverage` | `complete` | `vyos`, `unifi` |
| `installed_revision` | the value of `configured_revision` | `vyos`, `unifi` |
| `established_default_unknown` | true | `unifi` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Zone)-[:OWNED_BY]->(Device)` | | `vyos` |
| `(Zone)-[:CONTAINS]->(Interface)` | | `vyos`, `unifi` |

#### NatRule

| Property | Content | Written by |
|---|---|---|
| `position` | the number of the rule in its rulebase | `checkpoint`, `vyos`, `nxos`, `iosxe` |
| `kind` | `snat`, `dnat` or `static` | `vyos`, `nxos`, `iosxe` |
| `name` | the name, the comment or the description of the rule | `checkpoint`, `vyos` |
| `enabled` | false for a rule that the configuration disables | `checkpoint`, `vyos` |
| `approximate` | true if the collector cannot give the full match of the rule | `checkpoint`, `vyos`, `nxos`, `iosxe` |
| `approximate_reason` | the reason as text | `checkpoint`, `vyos` |
| `protocol` | the protocol of the match | `checkpoint`, `vyos`, `nxos`, `iosxe` |
| `src_any` | true if the original source is Any. `nat_stage` writes it only on a rule with a match access list. It is true if a permit entry of the list has `any` on the source side. For the direction `inside-destination`, `nat_stage` reads the destination side | `checkpoint`, `nxos`, `iosxe` |
| `dst_any` | true if the original destination is Any | `checkpoint` |
| `xlate_src_original`, `xlate_dst_original` | true if the translated source or the translated destination is Any | `checkpoint` |
| `method` | `method` of the rule | `checkpoint` |
| `auto_generated` | `auto-generated` of the rule | `checkpoint` |
| `install_on`, `install_on_unresolved` | as on `FwRule` | `checkpoint` |
| `orig_service`, `xlate_service` | `name` of the original service object and of the translated service object | `checkpoint` |
| `orig_port` | the port of the original match | `checkpoint`, `nxos`, `iosxe` |
| `xlate_port` | the port of the translated service | `checkpoint` |
| `service_unknown` | true if the collector cannot give the service match in `protocol` and the ports | `checkpoint` |
| `translation` | the translated address, prefix or range, `masquerade`, or `interface` | `vyos`, `nxos`, `iosxe` |
| `translation_port` | the translated port | `vyos`, `nxos`, `iosxe` |
| `orig_src`, `orig_dst` | `address` or `prefix` of `source` and of `destination` | `vyos` |
| `orig_src_port`, `orig_dst_port` | `port` of `source` and of `destination`, or the ports of a port group | `vyos` |
| `in_if`, `out_if` | the interface of `inbound-interface` and of `outbound-interface` | `vyos` |
| `exclude` | true if the rule holds `exclude` | `vyos` |
| `af` | 4 for the tree `nat`, 6 for the tree `nat66` | `vyos` |
| `direction` | the NAT direction of the rule, such as `inside-source` | `nxos`, `iosxe` |
| `static` | true for a static translation | `nxos`, `iosxe` |
| `overload` | true for a rule with overload | `nxos`, `iosxe` |
| `translation_interface` | the interface of the translation | `nxos`, `iosxe` |
| `match_acl`, `match_route_map` | the access list and the route map of the match | `nxos`, `iosxe` |
| `pool`, `pool_start`, `pool_end` | the name, the first address and the last address of the pool | `nxos`, `iosxe` |

A Check Point `NatRule` has no `kind`. `src/hst/collectors/cisco_common.py` `nat_stage` writes `kind` `snat` for the direction `inside-source` and `dnat` for each other direction. Only the `vyos` collector writes `kind` `static`. `nat_stage` gives the static rules of a direction the lower positions.

| Relationship | Properties | Written by |
|---|---|---|
| `(NatRule)-[:ORIG_SRC]->(NetObject)` | | `checkpoint`, `vyos` |
| `(NatRule)-[:ORIG_DST]->(NetObject)` | | `checkpoint`, `vyos` |
| `(NatRule)-[:XLATE_SRC]->(NetObject)` | | `checkpoint` |
| `(NatRule)-[:XLATE_DST]->(NetObject)` | | `checkpoint` |
| `(NatRule)-[:ORIG_SRC]->(Prefix)`, `(NatRule)-[:ORIG_SRC]->(IpAddress)` | | `vyos`, `nxos`, `iosxe` |
| `(NatRule)-[:ORIG_DST]->(Prefix)`, `(NatRule)-[:ORIG_DST]->(IpAddress)` | | `vyos`, `nxos`, `iosxe` |
| `(NatRule)-[:XLATE_SRC]->(Prefix)`, `(NatRule)-[:XLATE_SRC]->(IpAddress)` | | `vyos`, `nxos`, `iosxe` |
| `(NatRule)-[:XLATE_DST]->(Prefix)`, `(NatRule)-[:XLATE_DST]->(IpAddress)` | | `vyos`, `nxos`, `iosxe` |

The `vyos` collector writes a relationship to a `NetObject` for an address group or a network group of the rule. It writes no relationship for a range, for a negated address, for a negated group and for `masquerade`. `nat_stage` writes no relationship for a rule with a route map.

### Load balancing and DNS

`src/hst/collectors/netscaler.py` `normalize_netscaler` writes each node of this section. The source type is `netscaler`.

#### VirtualService

The collector writes 1 `VirtualService` for each `lbvserver` row with a name.

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the row | `netscaler` |
| `vip` | `ipv46` of the row | `netscaler` |
| `port` | `port` of the row as an integer | `netscaler` |
| `proto` | `udp` for the service types `UDP` and `DNS`, else `tcp` | `netscaler` |
| `kind` | `lb` | `netscaler` |
| `snat_mode` | `none`, `snat_from` or `automap` | `netscaler` |

| `snat_mode` | Condition |
|---|---|
| `none` | `usip` of the row is `true`, `yes`, `1` or `on`. The collector ignores the letter case |
| `snat_from` | `usip` has another value and the row holds `snat_ip` |
| `automap` | each other row |

| Relationship | Properties | Written by |
|---|---|---|
| `(VirtualService)-[:ON]->(RedundancyGroup)` | | `netscaler` |
| `(VirtualService)-[:ON]->(Device)` | | `netscaler` |
| `(VirtualService)-[:VIP]->(IpAddress)` | | `netscaler` |
| `(VirtualService)-[:SNAT_FROM]->(IpAddress)` | | `netscaler` |
| `(VirtualService)-[:USES]->(Pool)` | | `netscaler` |

The fields `on_label` and `on_uid` of `src/hst/collectors/netscaler.py` `NetScalerConfig` give the end of `ON`. The default of `on_label` is `RedundancyGroup`. The collector writes `SNAT_FROM` only for the mode `snat_from`. The `IpAddress` at the end of `SNAT_FROM` holds `ns_role` `snip`.

#### Pool

The collector writes 1 `Pool` for each service group that a row of `lbvserver_servicegroup_binding` binds to a `VirtualService`.

| Property | Content | Written by |
|---|---|---|
| `name` | `servicegroupname` of the binding | `netscaler` |
| `lb_method` | `lbmethod` of the `lbvserver` row in lower case | `netscaler` |

| Relationship | Properties | Written by |
|---|---|---|
| `(Pool)-[:HAS_MEMBER]->(PoolMember)` | | `netscaler` |
| `(Pool)-[:CHECKED_BY]->(Monitor)` | | `netscaler` |

#### PoolMember

The collector writes 1 `PoolMember` for each row of `servicegroup_servicegroupmember_binding` that holds `ip` and the name of such a service group.

| Property | Content | Written by |
|---|---|---|
| `port` | `port` of the row as an integer | `netscaler` |
| `weight` | `weight` of the row as an integer | `netscaler` |
| `state` | `up` if `svrstate` is `UP`, else `down`. Absent if the service group has no monitor binding | `netscaler` |

| Relationship | Properties | Written by |
|---|---|---|
| `(PoolMember)-[:TARGETS]->(IpAddress)` | | `netscaler` |

#### Monitor

The collector writes 1 `Monitor` for each monitor name in the rows of `servicegroup_lbmonitor_binding` that hold `servicegroupname` and `monitor_name`.

| Property | Content | Written by |
|---|---|---|
| `kind` | `type` of the `lbmonitor` row in lower case | `netscaler` |
| `target` | the monitor name | `netscaler` |

No relationship starts at a `Monitor`.

### Zscaler

`src/hst/collectors/zia.py` `normalize_zia` writes the nodes of the source type `zia`. `src/hst/collectors/zpa.py` `normalize_zpa` writes the nodes of the source type `zpa`. 5 reasoner rules write relationships that start at these nodes.

| Reasoner rule | Relationship | `derived` |
|---|---|---|
| `zpa-zia-ip-same-as` | `SAME_AS` | true |
| `zia-forwarding-to-zpa-segment` | `FORWARDS_TO` | false |
| `zia-forwarding-to-zpa-segment-group` | `FORWARDS_TO` | false |
| `zia-forwarding-to-zpa-server-group` | `STEERS_VIA` | false |
| `zpa-segment-domain-to-dns` | `RESOLVES_TO` | false |

`src/hst/reasoner/catalog.py` `RULES` holds the queries of the last 4 rules. `src/hst/reasoner/zscaler.py` `resolve_zpa_zia_ip_links` gives the rows of the first rule. Each of these relationships holds `source` `reasoner` and the rule name in `rule`.

#### ZscalerDc

The `zia` collector writes 1 `ZscalerDc` for each `datacenter` value in `primaryDestVip` and `secondaryDestVip` of a GRE tunnel.

| Property | Content | Written by |
|---|---|---|
| `name` | `datacenter` of the VIP object | `zia` |
| `private_service_edge` | true if `privateServiceEdge` of the VIP object is true, else absent | `zia` |
| `vip` | the lowest `virtualIp` of the data center in address order | `zia` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ZscalerDc)-[:PROVIDED_BY]->(Provider)` | | `zia` |

The `Provider` node has the name `zscaler`.

#### ZiaLocation

The collector writes 1 node for each entry of `locations` and of `sublocations` in the payload.

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the location | `zia` |
| `zia_id` | `id` of the location as a string | `zia` |
| `country` | `country` | `zia` |
| `tz` | `tz` | `zia` |
| `egress_ips` | `ipAddresses` of a location. Absent on a sublocation | `zia` |
| `address_ranges` | `ipAddresses` of a sublocation. Absent on a location | `zia` |
| `other_sublocation` | true if `otherSubLocation` of a sublocation is true, else absent | `zia` |
| `auth_required` | `authRequired` | `zia` |
| `ssl_scan_enabled` | `sslScanEnabled` | `zia` |
| `profile` | `profile` | `zia` |
| `ofw_enabled` | `ofwEnabled` | `zia` |
| `ips_control` | `ipsControl` | `zia` |
| `xff_forward_enabled` | `xffForwardEnabled` | `zia` |
| `surrogate_ip` | `surrogateIP` | `zia` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ZiaLocation)-[:PART_OF]->(ZiaLocation)` | | `zia` |
| `(ZiaLocation)-[:REPRESENTS]->(Site)` | | `zia` |
| `(ZiaLocation)-[:USES]->(Tunnel)` | | `zia` |
| `(ZiaLocation)-[:MEMBER_OF]->(ZiaLocationGroup)` | | `zia` |

`PART_OF` starts at a sublocation and ends at the location of its `parentId`. `REPRESENTS` comes from the field `location_sites` of `src/hst/collectors/zia.py` `ZiaConfig`. A sublocation with no line in `location_sites` gets the site of its parent location.

A tunnel that agrees with no row of the table gets no `USES`.

| Tunnel | Start of `USES` |
|---|---|
| GRE, `sourceIp` is in the `ipAddresses` of a location | that location |
| GRE, `sourceIp` is only in the `ipAddresses` of a sublocation with a `parentId` | the parent location |
| IPsec, the `location` of the VPN credential is a location | that location |
| IPsec, the `location` of the VPN credential is a sublocation with a `parentId` | the parent location |
| IPsec, the `location` of the VPN credential is a sublocation with no `parentId` | that sublocation |

#### ZiaLocationGroup

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the group | `zia` |
| `dynamic` | true if `groupType` is `DYNAMIC_GROUP` | `zia` |
| `dynamic_criteria` | `dynamicLocationGroupCriteria` as a JSON string | `zia` |

No relationship starts at a `ZiaLocationGroup`.

#### ZiaForwardingRule

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the rule | `zia` |
| `order` | `order` as an integer | `zia` |
| `forward_method` | `forwardMethod` in lower case | `zia` |
| `enabled` | true if `state` is `ENABLED`. Absent if the rule has no `state` | `zia` |
| `rule_type` | `type` | `zia` |
| `zpa_app_segment_ids` | `externalId` of each entry of `zpaAppSegments` and `zpaId` of each entry of `zpaApplicationSegments` | `zia` |
| `zpa_segment_group_ids` | `zpaId` of each entry of `zpaApplicationSegmentGroups` | `zia` |
| `zpa_gateway_id` | `id` of `zpaGateway` as a string | `zia` |
| `zpa_gateway` | `name` of `zpaGateway` | `zia` |
| `zpa_server_group_id` | `externalId` of the `zpaServerGroup` of that gateway in `zpa_gateways` of the payload | `zia` |
| `location_ids` | `id` of each entry of `locations` | `zia` |
| `location_group_ids` | `id` of each entry of `locationGroups` | `zia` |
| `src_ips` | `srcIps` | `zia` |
| `dest_addresses` | `destAddresses` | `zia` |
| `other_criteria` | the sorted keys of `src/hst/collectors/zia.py` `_OTHER_FORWARDING_CRITERIA` that hold a value in the rule | `zia` |

Each id list holds strings and leaves out an entry with `deleted` true. An empty list is absent.

| Relationship | Properties | Written by |
|---|---|---|
| `(ZiaForwardingRule)-[:APPLIES_TO]->(ZiaLocation)` | | `zia` |
| `(ZiaForwardingRule)-[:APPLIES_TO]->(ZiaLocationGroup)` | | `zia` |
| `(ZiaForwardingRule)-[:FORWARDS_TO]->(ZpaAppSegment)` | | `zia-forwarding-to-zpa-segment` |
| `(ZiaForwardingRule)-[:FORWARDS_TO]->(ZpaSegmentGroup)` | | `zia-forwarding-to-zpa-segment-group` |
| `(ZiaForwardingRule)-[:STEERS_VIA]->(ZpaServerGroup)` | | `zia-forwarding-to-zpa-server-group` |

The collector writes `APPLIES_TO` only to a location or a location group of the same payload. Each of the 3 reasoner rules compares an id of the rule with `zpa_id` of the target label. A rule writes the relationship only if exactly 1 node of the run holds the id.

#### ZpaAppSegment

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the segment | `zpa` |
| `zpa_id` | `id` of the segment as a string | `zpa` |
| `domains` | `domainNames` | `zpa` |
| `ranges` | the entries of `domainNames` that are an IP address or a CIDR, as networks | `zpa` |
| `opaque` | true if an entry of `domainNames` starts with `*` | `zpa` |
| `opaque_reason` | the text `wildcard domain entries` with the entries | `zpa` |
| `tcp_port_ranges` | `tcpPortRanges` | `zpa` |
| `udp_port_ranges` | `udpPortRanges` | `zpa` |
| `enabled` | `enabled` | `zpa` |
| `bypass_type` | `bypassType` in upper case | `zpa` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ZpaAppSegment)-[:MEMBER_OF]->(ZpaSegmentGroup)` | | `zpa` |
| `(ZpaAppSegment)-[:SERVED_BY]->(ZpaServerGroup)` | | `zpa` |
| `(ZpaAppSegment)-[:RESOLVES_TO]->(DnsRecord)` | `domain` | `zpa-segment-domain-to-dns` |

The rule `zpa-segment-domain-to-dns` compares each entry of `domains` with `fqdn` of each `DnsRecord` of the run in lower case. It skips an entry that starts with `*` and an entry with `:`. It also skips an entry of digits and dots with or without a prefix length. `domain` is part of the key of the relationship.

#### ZpaSegmentGroup

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the group | `zpa` |
| `zpa_id` | `id` of the group as a string | `zpa` |
| `enabled` | `enabled` as a boolean | `zpa` |

No relationship starts at a `ZpaSegmentGroup`.

#### ZpaServerGroup

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the group | `zpa` |
| `zpa_id` | `id` of the group as a string | `zpa` |
| `enabled` | `enabled` as a boolean | `zpa` |
| `dynamic_discovery` | `dynamicDiscovery` as a boolean | `zpa` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ZpaServerGroup)-[:USES]->(ZpaAppConnectorGroup)` | | `zpa` |
| `(ZpaServerGroup)-[:CONTAINS]->(AppServer)` | | `zpa` |

#### AppServer

The collector writes an `AppServer` for each entry of `servers` of a server group with `dynamicDiscovery` false.

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the server | `zpa` |
| `address` | `address` of the server | `zpa` |
| `enabled` | `enabled` | `zpa` |

| Relationship | Properties | Written by |
|---|---|---|
| `(AppServer)-[:SAME_AS]->(IpAddress)` | `basis`, `confidence` | `zpa-zia-ip-same-as` |

#### ZpaAppConnectorGroup

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the group | `zpa` |
| `location` | `location` | `zpa` |
| `enabled` | `enabled` as a boolean | `zpa` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ZpaAppConnectorGroup)-[:HAS]->(ZpaAppConnector)` | | `zpa` |

#### ZpaAppConnector

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the connector | `zpa` |
| `enabled` | `enabled` | `zpa` |
| `control_channel_status` | `controlChannelStatus` | `zpa` |
| `health` | `up` for the status `ZPN_STATUS_AUTHENTICATED`, `down` for `ZPN_STATUS_DISCONNECTED`, else absent | `zpa` |
| `private_ip` | `privateIp` | `zpa` |
| `public_ip` | `publicIp` | `zpa` |

| Relationship | Properties | Written by |
|---|---|---|
| `(ZpaAppConnector)-[:SAME_AS]->(IpAddress)` | `basis`, `confidence` | `zpa-zia-ip-same-as` |

The rule `zpa-zia-ip-same-as` reads 3 properties.

| Start label | Property | `basis` |
|---|---|---|
| `ZpaAppConnector` | `private_ip` | `private_ip` |
| `AppServer` | `address` | `address` |
| `Tunnel` with a uid that starts with `zia:` | `source_ip` | `source_ip` |

The end is each `IpAddress` of the run with the same address and a `HAS_IP` relationship to it. `confidence` is 0.8 for a global address and 0.6 for each other address. The rule writes no relationship for an unspecified address, a loopback address or a link-local address. `basis` is part of the key of the relationship.

#### ZpaAccessRule

The collector writes no node for a rule with a `ruleOrder` that is not a number.

| Property | Content | Written by |
|---|---|---|
| `position` | `ruleOrder` as an integer | `zpa` |
| `priority` | `priority` as an integer | `zpa` |
| `name` | `name` of the rule | `zpa` |
| `action` | `action` in lower case, if it is a value of `src/hst/core/labels.py` `ZPA_ACCESS_ACTIONS`. Absent for each other value | `zpa` |
| `action_raw` | `action` | `zpa` |
| `operator` | `operator` | `zpa` |
| `conditions` | the result of `src/hst/core/zpa_policy.py` `condition_blocks` as a JSON string | `zpa` |
| `conditions_summary` | the result of `src/hst/core/zpa_policy.py` `conditions_summary` | `zpa` |
| `identity_scope` | `any`, `listed` or `other` | `zpa` |
| `app_scope` | `any`, `listed` or `other` | `zpa` |
| `applies_to_all_identities` | true if `identity_scope` is `any`, else absent | `zpa` |
| `enabled` | true if `disabled` is `0` or false. False if `disabled` is `1` or true. Absent for each other value | `zpa` |
| `disabled_raw` | `disabled` as a string, if `enabled` is absent and the rule holds `disabled` | `zpa` |

`src/hst/core/zpa_policy.py` `rule_scope` gives `identity_scope` and `app_scope`.

| Relationship | Properties | Written by |
|---|---|---|
| `(ZpaAccessRule)-[:FOR]->(ZpaAppSegment)` | | `zpa` |
| `(ZpaAccessRule)-[:FOR]->(ZpaSegmentGroup)` | | `zpa` |
| `(ZpaAccessRule)-[:GRANTS]->(IdentityGroup)` | | `zpa` |
| `(ZpaAccessRule)-[:DENIES]->(IdentityGroup)` | | `zpa` |
| `(ZpaAccessRule)-[:APPLIES_TO]->(IdentityGroup)` | | `zpa` |
| `(ZpaAccessRule)-[:STEERS_VIA]->(ZpaAppConnectorGroup)` | | `zpa` |
| `(ZpaAccessRule)-[:STEERS_VIA]->(ZpaServerGroup)` | | `zpa` |

`src/hst/collectors/zpa.py` `_rule_edges` reads each operand of each condition block that is not negated.

| `objectType` of the operand | Relationship |
|---|---|
| `APP` | `FOR` to the `ZpaAppSegment` of `rhs` |
| `APP_GROUP` | `FOR` to the `ZpaSegmentGroup` of `rhs` |
| `SCIM_GROUP` | `GRANTS` for the action `ALLOW`, `DENIES` for `DENY`, `APPLIES_TO` for each other action |

`STEERS_VIA` comes from `appConnectorGroups` and `appServerGroups` of the rule.

#### ZpaClientForwardingRule

A `ZpaClientForwardingRule` holds the properties of the table of [ZpaAccessRule](#zpaaccessrule). `action` holds the `action` of the rule in lower case for each value. `action` is an empty string for a rule with no `action`.

| Relationship | Properties | Written by |
|---|---|---|
| `(ZpaClientForwardingRule)-[:FOR]->(ZpaAppSegment)` | | `zpa` |
| `(ZpaClientForwardingRule)-[:FOR]->(ZpaSegmentGroup)` | | `zpa` |
| `(ZpaClientForwardingRule)-[:APPLIES_TO]->(IdentityGroup)` | | `zpa` |

#### ZpaProvisioningKey

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the key | `zpa` |
| `enabled` | `enabled` | `zpa` |
| `max_usage` | `maxUsage` | `zpa` |
| `usage_count` | `usageCount` | `zpa` |
| `zcomponent_id` | `zcomponentId` | `zpa` |
| `zcomponent_name` | `zcomponentName` | `zpa` |

No relationship starts or ends at a `ZpaProvisioningKey`.

#### ZpaServiceEdge

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the service edge | `zpa` |
| `kind` | `private` | `zpa` |
| `location` | `location` | `zpa` |
| `enabled` | `enabled` | `zpa` |
| `control_channel_status` | `controlChannelStatus` | `zpa` |
| `health` | as on `ZpaAppConnector` | `zpa` |

No relationship starts or ends at a `ZpaServiceEdge`.

#### IdentityGroup

`src/hst/collectors/zpa.py` `_identity_group_node` writes 1 node for each `SCIM_GROUP` operand that holds `rhs` or `name`. The operand is in a condition block that is not negated.

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the operand, else the name of the SCIM group in `scim_groups` of the payload, else `rhs` | `zpa` |
| `name_is_id` | true if `name` holds `rhs`, else absent | `zpa` |
| `source` | `scim` | `zpa` |
| `idp_name` | `idpName` of an operand that holds `rhs` | `zpa` |

No relationship starts at an `IdentityGroup`.

### Equinix

`src/hst/collectors/equinix.py` `normalize_equinix` writes the nodes of the source type `equinix`.

#### FabricPort

The collector writes 1 `FabricPort` for each port of the account with a `uuid`.

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the port, else its `uuid` | `equinix` |
| `port_uuid` | `uuid` of the port | `equinix` |
| `state` | `state` | `equinix` |
| `ibx` | `ibx` of `location` | `equinix` |
| `metro` | `metroCode` of `location` | `equinix` |
| `speed_mbps` | `bandwidth` as an integer above 0 | `equinix` |
| `physical_ports_speed` | `physicalPortsSpeed` | `equinix` |
| `encapsulation` | `type` of `encapsulation` in lower case | `equinix` |
| `bound_port_uid` | the `Port` uid for the port in the field `port_bindings` of `src/hst/collectors/equinix.py` `EquinixConfig` | `equinix` |
| `cross_connect_ids` | the sorted cable ids from `tether.crossConnectId` of each physical port | `equinix` |
| `redundancy` | `priority` of `redundancy` in lower case | `equinix` |
| `lag_name` | `name` of `lag` if `enabled` of `lag` is true | `equinix` |
| `binding_issue` | `cable-conflict`, `several-ports` or `several-fabric-ports` | `fabric-port-from-description` |
| `binding_ports` | the sorted `Port` uids of the issue | `fabric-port-from-description` |

`src/hst/collectors/equinix.py` `_cross_connect_id` gives a cable id in upper case without the text after the first `-`. Before the reasoner rules run, `src/hst/reasoner/_constants.py` `CLEAR_PROPS` removes `binding_issue` and `binding_ports` from each `FabricPort` of the run. `src/hst/reasoner/fabric_ports.py` `fabric_port_issues` gives the 2 properties.

| Relationship | Properties | Written by |
|---|---|---|
| `(FabricPort)-[:LOCATED_IN]->(Site)` | | `equinix` |
| `(FabricPort)-[:REALIZED_BY]->(Port)` | | `equinix` |
| `(FabricPort)-[:REALIZED_BY]->(Port)` | `evidence` | `fabric-port-from-description` |

The collector writes `LOCATED_IN` if the field `ibx_sites` of `EquinixConfig` holds the IBX of the port. It writes `REALIZED_BY` to the `Port` of `bound_port_uid`. If the run holds no node with that uid, the loader writes no relationship.

`src/hst/reasoner/fabric_ports.py` `resolve_fabric_port_bindings` gives the relationships of the reasoner rule. The rule binds a `FabricPort` without `bound_port_uid` to the 1 `Port` whose `description` holds the name of the `FabricPort` as a full word. `evidence` is `name+cable` if the description also holds a cable id of `cross_connect_ids`. `evidence` is `name` if the description holds no cable id.

#### VirtualCircuit

The collector writes 2 kinds of `VirtualCircuit`.

| Kind | Code | `type` |
|---|---|---|
| a connection of `connection_pages` or `edge_connection_pages` with a `uuid` | `normalize_equinix` | `type` of the connection |
| a pair of members of a device link group of `edge_link_pages` | `src/hst/collectors/equinix.py` `_edge_link_stage` | `DEVICE_LINK` |

| Property | Content | Written by |
|---|---|---|
| `name` | `name` of the connection, else its `uuid`. `groupName` of the group, else its `uuid` | `equinix` |
| `type` | `type` of the connection, or `DEVICE_LINK` | `equinix` |
| `state` | `state` of the connection, or `status` of the group | `equinix` |
| `bandwidth_mbps` | `bandwidth` of the connection as an integer above 0, or the lowest `throughput` of the `metroLinks` of the group with the unit Mbps | `equinix` |
| `a_side_kind`, `z_side_kind` | `type` of the access point of the side in lower case, or `vd` for a device link | `equinix` |
| `connection_uuid` | `uuid` of the connection | `equinix` |
| `provider` | `name` of `profile` of the access point of the Z side | `equinix` |
| `provider_profile_uuid` | `uuid` of that `profile` | `equinix` |
| `a_virtual_device`, `a_virtual_device_uuid` | `name` and `uuid` of `virtualDevice` of the access point of the A side | `equinix` |
| `redundancy` | `redundancyType` of the group in lower case | `equinix` |
| `device_link_group_uuid` | `uuid` of the group | `equinix` |

A connection has no `redundancy` and no `device_link_group_uuid`. A device link has no `connection_uuid`, no `provider`, no `provider_profile_uuid`, no `a_virtual_device` and no `a_virtual_device_uuid`.

| Relationship | Properties | Written by |
|---|---|---|
| `(VirtualCircuit)-[:PROVIDED_BY]->(Provider)` | | `equinix` |
| `(VirtualCircuit)-[:A_END]->(FabricPort)` | `link_protocol`, `vlan_tag`, `inner_vlan_tag` | `equinix` |
| `(VirtualCircuit)-[:Z_END]->(FabricPort)` | `link_protocol`, `vlan_tag`, `inner_vlan_tag` | `equinix` |
| `(VirtualCircuit)-[:A_END]->(Interface)` | `link_protocol`, `vlan_tag`, `inner_vlan_tag` | `equinix` |
| `(VirtualCircuit)-[:Z_END]->(Interface)` | `link_protocol`, `vlan_tag`, `inner_vlan_tag` | `equinix` |

The end of a connection side is a `FabricPort` if the port of the access point is a port of the account. Else the end is the `Interface` of a Network Edge device of the account with the interface `uuid` of the access point. A side with no such port and no such interface gets no relationship. The `A_END` and the `Z_END` of a device link end at an `Interface` and hold no property.

`src/hst/collectors/equinix.py` `_link_protocol` gives the 3 properties from `linkProtocol` of the access point.

| Property | Content |
|---|---|
| `link_protocol` | `dot1q`, `qinq` or `untagged`, else `type` in lower case |
| `vlan_tag` | `vlanSTag` for `QINQ`, or `vlanTag` if the S tag is absent. `vlanTag` for each other type |
| `inner_vlan_tag` | `vlanCTag` for `QINQ`, else absent |

### Applications

No code under `src/hst` writes a node with the label `BusinessService`, `AppComponent`, `ServiceRequirement` or `DependencyGroup`. The package `src/hst/applications` writes no node and no relationship to the graph. [Labels and relationship types with no writer](#labels-and-relationship-types-with-no-writer) lists the 4 labels.

The table gives each query under `src/hst` whose text or label map holds one of the 4 labels.

| Query | Label | Properties that the query reads | Relationships that the query reads |
|---|---|---|---|
| `src/hst/assessment/evaluation.py` `_REQUIREMENT_QUERY` | `ServiceRequirement` | `name`, `destination`, `proto`, `dport`, `sport`, `success`, `source_context`, `source_device_uid`, `identity_uid`, `segment_uid`, `mtu_json` | `(ServiceRequirement)-[:SRC]->()`, `(BusinessService)-[:DEPENDS_ON]->(ServiceRequirement)`, `(ServiceRequirement)-[:HAS]->(DependencyGroup)` |
| `src/hst/assessment/evaluation.py` `_GROUP_QUERY` | `DependencyGroup` | `kind`, `n`, `name` | `(DependencyGroup)-[:HAS_MEMBER]->(DependencyGroup)`, `(DependencyGroup)-[:DEPENDS_ON]->()` |
| `src/hst/assessment/discovery.py` `_OBJECTS` for the kind `service` of `src/hst/assessment/discovery.py` `KINDS` | `ServiceRequirement` | `name`, `hostname`, `source`, `kind`, `origin`, `collector`, `evidence_reference`, `evidence_section`, `evidence_host`, `observed_ms`, `valid_from_ms`, `valid_until_ms` | a path of 1 to 3 relationships of the types `ON`, `ENFORCES`, `PROTECTED_BY`, `HAS_LINK`, `ENDPOINT`, `MEMBER_OF` and `LOCATED_IN` to a `Device` or a `Site` |
| `src/hst/assessment/discovery.py` `_DETAILS` | `ServiceRequirement`, `BusinessService` | `source_device_uid`, `source_context`, `identity_uid` and `segment_uid` of the `ServiceRequirement`, `name` of the `BusinessService` | `(BusinessService)-[:DEPENDS_ON]->(ServiceRequirement)`, `(ServiceRequirement)-[:SRC]->()`, `(ServiceRequirement)-[:ENDPOINT]->()`, `(ServiceRequirement)-[:IN_VRF]->(VrfInstance)`, `(ServiceRequirement)-[:HAS_IP]->(IpAddress)` |
| `src/hst/twin_tools/apps.py` `_RELATED_BY_NAME` | `BusinessService`, `ServiceRequirement` | `name` | |
| `src/hst/twin_tools/apps.py` `_RELATED_BY_OBJECT` | `BusinessService`, `ServiceRequirement` | `name` | a path of 1 to 4 relationships of the types `SRC`, `HAS`, `HAS_MEMBER`, `DEPENDS_ON` and `PART_OF`, in each direction |
| `src/hst/applications/generator_tools.py` `_COMPONENT` | `AppComponent` | | `()-[:PART_OF]->(AppComponent)` |
| `src/hst/applications/generator_tools.py` `_search_query` for the kinds `business_service` and `app_component` of `src/hst/applications/generator_tools.py` `LABELS` | `BusinessService`, `AppComponent` | `name`, `hostname`, `code`, `fqdn`, `cidr`, `ip` | |
| `src/hst/applications/generator_tools.py` `_NODE` for a label of `src/hst/applications/generator_tools.py` `CHAIN_LABELS` | `AppComponent` | `name`, `hostname`, `fqdn`, `code`, `ip`, `cidr` | |
| `src/hst/applications/resolution.py` `_GRAPH_REFERENCE` for a label of `src/hst/applications/resolution.py` `LABEL_KIND` | `ServiceRequirement` | `ip`, `cidr`, `prefix`, `evidence_reference`, `raw_evidence_ref` | `(ServiceRequirement)-[:HAS_IP]->()`, `(ServiceRequirement)-[:RESOLVES_TO]->()`, `(ServiceRequirement)-[:IN_VRF]->(VrfInstance)` |
| `src/hst/core/search.py` `GRAPH` for the kind `application` of `src/hst/core/search.py` `KIND_LABEL`, with the filter target `src/hst/core/filters.py` `APPLICATION` | `BusinessService` | `name`, `description` | |
| `src/hst/core/search.py` `EXACT_UID` for a label of `src/hst/core/search.py` `LABEL_KIND` | `BusinessService` | | |
| `src/hst/demo.py` `SCENARIOS`, the scenario `blast-radius` | `AppComponent`, `BusinessService` | `name` of the `BusinessService` | `(Vm)-[:PART_OF]->(AppComponent)`, `(AppComponent)-[:PART_OF]->(BusinessService)` |

These 2 queries match a node by `uid` with the label `Obj` only. The code passes them the uid of an object of the label in the table.

| Query | Source of the uid | Label | Properties that the query reads | Relationships that the query reads |
|---|---|---|---|---|
| `src/hst/applications/inventory_graph.py` `INVENTORY_QUERY` | `inventory_uid` of a member that `src/hst/applications/resolution.py` `_GRAPH_REFERENCE` resolves | `ServiceRequirement` | `name`, `hostname`, `ip`, `cidr`, `prefix`, `fqdn`, `role`, `vendor`, `site` | `(ServiceRequirement)-[:HAS_IP]->()`, `(ServiceRequirement)-[:RESOLVES_TO]->()`, `(ServiceRequirement)-[:IN_VRF]->()`, `(ServiceRequirement)-[:IN]->()`, `(ServiceRequirement)-[:ON]->()`, `()-[:HAS_IP]->(ServiceRequirement)`, `()-[:VIP]->(ServiceRequirement)`, `()-[:RESOLVES_TO]->(ServiceRequirement)` |
| `src/hst/queries.py` `QUERIES`, the entry `application-inventory` | the parameter `uids`, which `src/hst/app/routes/business_applications.py` `application_graph` returns in `library_query` | `ServiceRequirement` | each property of the node | `(ServiceRequirement)-[:HAS_IP]->()`, `(ServiceRequirement)-[:RESOLVES_TO]->()`, `(ServiceRequirement)-[:IN_VRF]->()`, `(ServiceRequirement)-[:IN]->()`, `(ServiceRequirement)-[:ON]->()`, `(Interface)-[:HAS_IP]->(ServiceRequirement)` |

### MTU observations

#### MtuObservation

`src/hst/core/mtu_profiles.py` `emit_observation` writes 1 `MtuObservation` node and 1 `HAS_MTU` relationship for each observation. `src/hst/core/mtu_profiles.py` `observation_from_raw` makes the observation from a raw value.

| Source type | Code that calls `emit_observation` | Start labels of `HAS_MTU` | `source` |
|---|---|---|---|
| `apic` | `src/hst/collectors/mtu_apic.py` `normalize_mtu_apic` through `src/hst/collectors/mtu_apic.py` `_physical`, `src/hst/collectors/mtu_apic.py` `_fabric_default` and `src/hst/collectors/mtu_apic.py` `_attachments` | `Port`, `Fabric`, `Interface` | `apic` |
| `nxos`, `iosxe` | `src/hst/collectors/cisco_common.py` `_mtu_stage` | `Device`, `Interface`, `Port` | the source type |
| `iosxr` | `src/hst/collectors/cisco_common.py` `_mtu_stage` | `Interface`, `Port` | the source type |
| `vyos` | `src/hst/collectors/vyos.py` `_mtu_stage`, `src/hst/collectors/vyos.py` `_emit_port_frame_ceiling` | `Interface`, `Port` | `vyos:` and the source name, or the host if the source has no name |
| `unifi` | `src/hst/collectors/unifi.py` `normalize_unifi` through `src/hst/collectors/mtu_import.py` `preserve_raw_mtu_fields`, `src/hst/collectors/unifi.py` `_l2_frame_stage` | `Device`, `Port` | `unifi` |
| `nautobot` | `src/hst/collectors/nautobot.py` `normalize_nautobot` | `Port` | `nautobot` |
| `netscaler` | `src/hst/collectors/netscaler.py` `_netscaler_mtu` | `Interface` | `netscaler` |
| `manual` | `src/hst/collectors/mtu_import.py` `emit_import` | the labels of `src/hst/collectors/mtu_import.py` `IMPORT_SUBJECT_LABELS` | `manual:` and the source name, or `manual:unnamed` if the source has no name |

`src/hst/core/mtu.py` `MtuObservation.graph_props` gives the properties of the node. Each source type of the table writes each property of the table below. A property with no value is absent.

| Property | Content |
|---|---|
| `subject_uid` | the uid of the start node of `HAS_MTU` |
| `source` | the value in the column `source` of the table above |
| `source_target` | the fabric, the scope, the device, the site or the host of the read. For the `manual` collector, `source` of the import row |
| `source_field` | the name of the field or the command that holds the value. For `nxos`, `iosxe` and `iosxr`, `<command>:<field>` |
| `raw_value_json` | the raw value as JSON, a scalar |
| `raw_basis` | `profile_id` if it is a value of `src/hst/core/mtu_profiles.py` `PROFILE_IDS`, else `unknown` |
| `raw_units` | `bytes` by default |
| `metric` | `l2_max_frame_bytes`, `l2_payload_mtu_bytes`, `ipv4_mtu_bytes`, `ipv6_mtu_bytes`, `path_pmtu_bytes` or `unknown` |
| `normalized_value` | the value in bytes after the profile conversion. Absent if `observation_from_raw` cannot convert the raw value |
| `direction` | `tx`, `rx`, `both` or `unknown` |
| `bound_kind` | `ceiling`, `acceptance_lower_bound` or `unknown` |
| `af` | 4 for the metric `ipv4_mtu_bytes`, 6 for `ipv6_mtu_bytes` |
| `enforcement` | `l2`, `l3`, `source`, `destination`, `tunnel`, `fabric`, `control_plane`, `path` or `unknown` |
| `enforcement_key` | `interface` by default |
| `traffic_class` | the traffic class of the limit |
| `assertion_kind` | `configured`, `operational`, `intent`, `hardware_max` or `measurement` |
| `resolution_state` | `explicit`, `inherited`, `profile_default`, `unknown`, `unsupported` or `conflict` |
| `policy_ref` | the policy of the limit. For `nxos` and `iosxe`, only an observation with the `scope` `system_policy` holds it. The value is the name of the policy map, else `system` or `qos` |
| `scope` | `interface` by default |
| `selector_json` | a JSON object with `version` 1 and the context keys of the collector |
| `profile_id` | the profile of the raw value |
| `profile_version` | `1` |
| `collector_version` | the version text of the collector stage |
| `raw_evidence_ref` | a reference to the raw value in the payload |
| `observed_at_ms` | the time of the observation in milliseconds. Absent for `nxos`, `iosxe` and `iosxr` |
| `dependency_uids` | a list of uids. An empty list for `nxos`, `iosxe` and `iosxr` |
| `tag_accounting` | `included`, `extra_allowance` or `unknown` |
| `tag_depth` | the count of VLAN tags, 0 to 8 |
| `tag_allowance_bytes` | the bytes for VLAN tags above the raw value |
| `gaps` | a list of gap codes of `src/hst/core/mtu.py` `MtuGapCode` |
| `contract_version` | `src/hst/core/mtu.py` `MTU_CONTRACT_VERSION` |
| `normalization_version` | `src/hst/core/mtu.py` `MTU_NORMALIZATION_VERSION` |

If `observation_from_raw` cannot convert the raw value, it sets `resolution_state` to `unknown` and adds `MTU_SEMANTICS_UNKNOWN` to `gaps`. A state of `unsupported` or `conflict` stays.

`selector_json` has a maximum of 4096 characters. The table gives the keys for each code that sets `selector_json`. An observation of `src/hst/collectors/netscaler.py` `_netscaler_mtu` or of `src/hst/collectors/mtu_import.py` `preserve_raw_mtu_fields` holds the key `version` only.

| Code | Keys of `selector_json` |
|---|---|
| `src/hst/collectors/cisco_common.py` `_mtu_stage` | `version`, `platform`, `os_version`, `model`, `validation`, `interface_kind`, `encapsulation`, `configured_tag_depth`, and `derived_from_subject_uid` for a subinterface that has a parent interface and no `mtu` line of its own in the configuration |
| `src/hst/collectors/vyos.py` `_mtu_stage` | `version`, `source_profile`, `profile_validation`, `interface_kind`, `configured_tag_depth`, `qinq_carriage_unmodeled`, `parent_subject_uid`, `configured_parent_subject_uid`, `operational_parent_subject_uid`, `parent_namespace`, `master_subject_uid`, `configured_member_uids`, `member_list_truncated`, `member_eligibility`, `parent_resolution`, `kernel_link_kind`, `operstate`, `link_type`, `section_outcome`, `command` |
| `src/hst/collectors/vyos.py` `_emit_port_frame_ceiling` | `version`, `source_profile`, `profile_validation`, `derivation` |
| `src/hst/collectors/mtu_apic.py` `_physical` | `version`, `platform`, `scope`, `semantics` |
| `src/hst/collectors/mtu_apic.py` `_fabric_default` | `version`, `applies_to`, `physical_fabric_capacity` |
| `src/hst/collectors/mtu_apic.py` `_attachments` | `version`, `attachment_class`, `attachment_resolved`, `fragmentation` |
| `src/hst/collectors/unifi.py` `_l2_frame_stage` | `version`, `source_profile`, `profile_validation`, `jumboframe_enabled`, `port_table_jumbo_is_authoritative` |
| `src/hst/collectors/nautobot.py` `normalize_nautobot` | `version`, `basis_origin`, `evidence_origin` |
| `src/hst/collectors/mtu_import.py` `ImportedMtu.observation` | `version`, `evidence_origin`, `declared_authority`, `source_verified` |

The section of each start label lists its `HAS_MTU` relationship. 3 start labels of the `manual` collector have no section, because no code writes a node with the label.

| Relationship | Properties | Written by |
|---|---|---|
| `(Pnic)-[:HAS_MTU]->(MtuObservation)` | | `manual` |
| `(Vnic)-[:HAS_MTU]->(MtuObservation)` | | `manual` |
| `(Dvs)-[:HAS_MTU]->(MtuObservation)` | | `manual` |

No relationship starts at an `MtuObservation`.

`src/hst/core/model.py` `Batch.validate_registry` accepts `HAS_MTU` only from a label of `src/hst/core/labels.py` `MTU_SUBJECT_LABELS`. It also makes sure that `subject_uid` is the uid of the start node. The `manual` collector writes no subject node. `src/hst/collectors/mtu_import.py` `validate_import_subjects` makes sure that the published run holds each subject of the import.

## Labels and relationship types with no writer

A name in the 2 tables is in `src/hst/core/labels.py` `LABELS` or `src/hst/core/labels.py` `RELS`. No collector, no reasoner rule and no other code under `src/hst` writes a node or a relationship with the name. A name that only a read query or `src/hst/demo.py` holds is in the tables.

`hst load-fixture` writes a fixture through the loader. The column `Fixture` gives 1 fixture file that holds the name.

| Label | Group of `LABELS` | Fixture |
|---|---|---|
| `FailureDomain` | location / physical | none |
| `Module` | location / physical | none |
| `Pnic` | location / physical | `fixtures/mini-dc.yaml` |
| `L2Vni` | L2 | none |
| `L2Segment` | L2 | none |
| `L3Domain` | L3 / routing | none |
| `EvpnInstance` | overlay / transport | `fixtures/mini-enterprise.yaml` |
| `Esg` | ACI policy & service insertion | none |
| `VzAny` | ACI policy & service insertion | none |
| `ServiceNode` | ACI policy & service insertion | `fixtures/mini-dc.yaml` |
| `FwSection` | generic firewall model | none |
| `DnsRecord` | LB / DNS | `fixtures/mini-enterprise.yaml` |
| `Organization` | AWS | `fixtures/mini-enterprise.yaml` |
| `Account` | AWS | `fixtures/mini-enterprise.yaml` |
| `Region` | AWS | `fixtures/mini-enterprise.yaml` |
| `Az` | AWS | none |
| `Vpc` | AWS | `fixtures/mini-enterprise.yaml` |
| `Subnet` | AWS | `fixtures/mini-enterprise.yaml` |
| `RouteTable` | AWS | `fixtures/mini-enterprise.yaml` |
| `CloudRoute` | AWS | `fixtures/mini-enterprise.yaml` |
| `Igw` | AWS | none |
| `NatGw` | AWS | none |
| `Eni` | AWS | `fixtures/mini-enterprise.yaml` |
| `VpcPeering` | AWS | none |
| `Tgw` | AWS | `fixtures/mini-enterprise.yaml` |
| `TgwAttachment` | AWS | `fixtures/mini-enterprise.yaml` |
| `TgwRouteTable` | AWS | `fixtures/mini-enterprise.yaml` |
| `VpcEndpoint` | AWS | none |
| `EndpointService` | AWS | none |
| `DxConnection` | AWS | `fixtures/mini-enterprise.yaml` |
| `DxVif` | AWS | `fixtures/mini-enterprise.yaml` |
| `DxGw` | AWS | `fixtures/mini-enterprise.yaml` |
| `VpnConnection` | AWS | none |
| `Instance` | AWS | `fixtures/mini-enterprise.yaml` |
| `Subscription` | Azure | `fixtures/mini-enterprise.yaml` |
| `ResourceGroup` | Azure | none |
| `VNet` | Azure | `fixtures/mini-enterprise.yaml` |
| `Nic` | Azure | `fixtures/mini-enterprise.yaml` |
| `VNetPeering` | Azure | none |
| `VirtualWan` | Azure | none |
| `VHub` | Azure | none |
| `HubRouteTable` | Azure | none |
| `ErCircuit` | Azure | `fixtures/mini-enterprise.yaml` |
| `ErPeering` | Azure | none |
| `VNetGw` | Azure | `fixtures/mini-enterprise.yaml` |
| `AzFirewall` | Azure | none |
| `PrivateEndpoint` | Azure | none |
| `PrivateLinkService` | Azure | none |
| `Vcenter` | virtualization / compute / app | none |
| `VmwCluster` | virtualization / compute / app | none |
| `EsxHost` | virtualization / compute / app | `fixtures/mini-enterprise.yaml` |
| `Vm` | virtualization / compute / app | `fixtures/mini-enterprise.yaml` |
| `Vnic` | virtualization / compute / app | `fixtures/mini-enterprise.yaml` |
| `Dvs` | virtualization / compute / app | none |
| `Server` | virtualization / compute / app | none |
| `BusinessService` | virtualization / compute / app | `fixtures/mini-dc.yaml` |
| `AppComponent` | virtualization / compute / app | `fixtures/mini-enterprise.yaml` |
| `ServiceRequirement` | virtualization / compute / app | none |
| `DependencyGroup` | virtualization / compute / app | none |

| Relationship type | Fixture |
|---|---|
| `ASSOCIATED` | `fixtures/mini-enterprise.yaml` |
| `DEPENDS_ON` | none |
| `DISPATCHES` | none |
| `EGRESSES_VIA` | none |
| `EXTENDS` | none |
| `FRONTS` | none |
| `HAS_NODE` | `fixtures/mini-dc.yaml` |
| `HAS_PORT` | none |
| `INTERCONNECTED_BY` | `fixtures/mini-enterprise.yaml` |
| `IN_ACCOUNT` | `fixtures/mini-enterprise.yaml` |
| `IN_AZ` | none |
| `IN_ORG` | `fixtures/mini-enterprise.yaml` |
| `IN_REGION` | `fixtures/mini-enterprise.yaml` |
| `JUMPS_TO` | none |
| `L3_ADJACENT` | `fixtures/mini-enterprise.yaml` |
| `OF` | `fixtures/mini-enterprise.yaml` |
| `PLUGGED_INTO` | `fixtures/mini-dc.yaml` |
| `PROPAGATES` | `fixtures/mini-enterprise.yaml` |
| `ROUTES` | none |
| `SWITCHES` | none |
| `USES_RT` | `fixtures/mini-enterprise.yaml` |
| `WITHIN` | `fixtures/mini-enterprise.yaml` |
