# Graph schema by source type

`tools/gen_docs.py` builds each section of this doc from the label tables of [Graph schema](schema.md#properties-and-relationships). A change goes into that doc, and the script writes it here.

<!-- generated: schema-by-source-type -->
## `apic`

### Device of `apic`

| Property | Content |
|---|---|
| `platform` | `apic`, `aci-leaf`, `aci-spine`, or `aci` for another role |
| `role` | the `role` of the fabric node, or `unknown` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `os_version` | the software version |
| `model` | the hardware model |
| `mgmt_ip` | the management address |
| `reported_location`, `reported_location_name` | `<fabric>/<pod DN>` and `<fabric> <pod DN>`. The pod DN is the first 2 segments of the DN of the fabric node |
| `dn` | the DN of the fabric node |

| Relationship | Properties |
|---|---|
| `(Device)-[:MEMBER_OF]->(Fabric)` |  |
| `(Device)-[:IN_POD]->(Pod)` |  |

### Port of `apic`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `kind` | `lag` for a `pcAggrIf` object |
| `lldp_neighbor_name`, `lldp_neighbor_mac`, `lldp_neighbor_port`, `cdp_neighbor_name`, `cdp_neighbor_port` | the neighbor of the port |
| `admin_state` | `adminSt` of the port |
| `dn` | the DN of the port |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |
| `(Port)-[:MEMBER_OF]->(Lag)` | `basis`, `membership_state`, `forwarding_eligible`, `evidence_ref` |
| `(Port)-[:HAS_MTU]->(MtuObservation)` |  |

### Interface of `apic`

| Property | Content |
|---|---|
| `kind` | `l3out-floating`, `l3out-attachment` |
| `name` | `ifInstT` of the L3Out attachment, or the APIC class name if `ifInstT` is absent. The interface id in the DN of an `ospfIf` object |
| `dn`, `address`, `encap`, `path_dn` | fields of the L3Out attachment |
| `attachment_resolved` | `true` if `src/hst/collectors/mtu_apic.py` `_attachment_targets` finds the device and the port of each node of `tDn`. `false` for an `l3out-floating` interface |
| `attachment_basis`, `mtu_operational_state`, `mtu_receive_state`, `ip_fragmentation`, `ip_fragmentation_basis` | `configured`, `unknown`, `unknown`, `unsupported` and `documented-aci` |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:BOUND_TO]->(Port)` | `basis`, `evidence_ref`, `physical_path_known` |
| `(Interface)-[:IN_AREA]->(OspfArea)` | `cost`, `network_type`, `passive` |
| `(Interface)-[:PART_OF]->(L3Out)` |  |
| `(Interface)-[:HAS_MTU]->(MtuObservation)` |  |

### Lag of `apic`

| Property | Content |
|---|---|
| `name` | the name of the aggregate |
| `dn` | the DN of the aggregate |
| `member_state` | `unknown` |
| `membership_basis` | `configured` |

| Relationship | Properties |
|---|---|
| `(Lag)-[:ON]->(Device)` |  |
| `(Lag)-[:REALIZED_BY]->(Port)` |  |

### BridgeDomain of `apic`

| Property | Content |
|---|---|
| `name`, `dn` | the name and the DN of the ACI bridge domain |

| Relationship | Properties |
|---|---|
| `(BridgeDomain)-[:IN_VRF]->(VrfInstance)` |  |

### Endpoint of `apic`

| Property | Content |
|---|---|
| `mac` | the MAC address |
| `name` | the name of the endpoint |

| Relationship | Properties |
|---|---|
| `(Endpoint)-[:IN_EPG]->(Epg)` |  |
| `(Endpoint)-[:IN]->(BridgeDomain)` |  |
| `(Endpoint)-[:HAS_IP]->(IpAddress)` |  |

### VrfInstance of `apic`

| Property | Content |
|---|---|
| `name` | the name of the VRF |
| `dn`, `pc_enf_pref` | the DN of the ACI VRF, and `pcEnfPref` in lower case |
| `contract_bypass` | the flags `esg`, `preferred-group` and `vzany` of the VRF, sorted and joined with commas. `not-collected` if the payload lacks a class of `src/hst/collectors/apic.py` `CONTRACT_BYPASS_CLASSES`. An empty string if the VRF has no flag. `esg` on each VRF if an `fvESg` object has no `fvRsScope` with a `tDn` |

### Prefix of `apic`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `anchor` | the routing domain of the VRF of the bridge domain, the same value as `l3dom` |
| `l3dom` | the routing domain |
| `gateway_ip`, `dn` | the gateway address and the DN of the ACI subnet |

| Relationship | Properties |
|---|---|
| `(Prefix)-[:IN]->(BridgeDomain)` |  |

### IpAddress of `apic`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |

### RoutingProcess of `apic`

| Property | Content |
|---|---|
| `proto` | `ospf` |
| `router_id` | the router id |

| Relationship | Properties |
|---|---|
| `(RoutingProcess)-[:IN_VRF]->(VrfInstance)` |  |
| `(RoutingProcess)-[:HAS]->(OspfArea)` |  |
| `(RoutingProcess)-[:HAS]->(OspfAdjacency)` |  |

### OspfArea of `apic`

| Property | Content |
|---|---|
| `area_id` | the area id |
| `type` | the area type |

### OspfAdjacency of `apic`

| Property | Content |
|---|---|
| `state` | the state of the adjacency |
| `area` | the area id |
| `neighbor_router_id`, `neighbor_ip` | the router id and the address of the neighbor |
| `local_interface` | the name of the local interface |

| Relationship | Properties |
|---|---|
| `(OspfAdjacency)-[:ENDPOINT]->(Interface)` |  |

### Fabric of `apic`

| Property | Content |
|---|---|
| `name` | the fabric name of the source |

| Relationship | Properties |
|---|---|
| `(Fabric)-[:HAS_MTU]->(MtuObservation)` |  |

### Pod of `apic`

| Property | Content |
|---|---|
| `name` | the DN of the pod |

| Relationship | Properties |
|---|---|
| `(Pod)-[:PART_OF]->(Fabric)` |  |

### Tenant of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `fvTenant` object |

| Relationship | Properties |
|---|---|
| `(Tenant)-[:HAS]->(AppProfile)` |  |
| `(Tenant)-[:HAS]->(Contract)` |  |

### AppProfile of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `fvAp` object |

| Relationship | Properties |
|---|---|
| `(AppProfile)-[:HAS]->(Epg)` |  |

### Epg of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `fvAEPg` object |
| `pref_group_member` | `prefGrMemb` of the `fvAEPg` object in lower case |

| Relationship | Properties |
|---|---|
| `(Epg)-[:IN_BD]->(BridgeDomain)` |  |
| `(Epg)-[:PROVIDES]->(Contract)` |  |
| `(Epg)-[:CONSUMES]->(Contract)` |  |
| `(Epg)-[:STATIC_BINDING]->(Port)` | `encap`, `mode` |
| `(Epg)-[:VMM_BINDING]->(DvPortgroup)` |  |

### ExtEpg of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `l3extInstP` object |

| Relationship | Properties |
|---|---|
| `(ExtEpg)-[:PART_OF]->(L3Out)` |  |
| `(ExtEpg)-[:MATCHES]->(Prefix)` |  |
| `(ExtEpg)-[:PROVIDES]->(Contract)` |  |
| `(ExtEpg)-[:CONSUMES]->(Contract)` |  |

### L3Out of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `l3extOut` object |

| Relationship | Properties |
|---|---|
| `(L3Out)-[:PART_OF]->(Tenant)` |  |
| `(L3Out)-[:IN_VRF]->(VrfInstance)` |  |

### Contract of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `vzBrCP` object |

| Relationship | Properties |
|---|---|
| `(Contract)-[:HAS]->(ContractSubject)` |  |
| `(Contract)-[:REDIRECTS_VIA]->(PbrPolicy)` | `graph`, `node`, `connector` |

### ContractSubject of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `vzSubj` object |

| Relationship | Properties |
|---|---|
| `(ContractSubject)-[:USES_FILTER]->(AciFilter)` | `action`, `directives`, `direction` |
| `(ContractSubject)-[:APPLIES_GRAPH]->(ServiceGraphTemplate)` |  |

### AciFilter of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `vzFilter` object |

| Relationship | Properties |
|---|---|
| `(AciFilter)-[:HAS]->(FilterEntry)` |  |

### FilterEntry of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `vzEntry` object |
| `proto` | `prot` |
| `ether_type` | `etherT`, or `unspecified` if the reply has no `etherT` |
| `s_from_port` | `sFromPort` |
| `s_to_port` | `sToPort` |
| `d_from_port` | `dFromPort` |
| `d_to_port` | `dToPort` |
| `tcp_rules` | `tcpRules`, or `unspecified` if the reply has no `tcpRules` |
| `apply_to_frag` | `applyToFrag`, or `no` if the reply has no `applyToFrag` |
| `stateful` | `stateful` |

### ServiceGraphTemplate of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `vnsAbsGraph` object |

| Relationship | Properties |
|---|---|
| `(ServiceGraphTemplate)-[:HAS_NODE]->(ServiceNode)` |  |

### ServiceNode of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `vnsAbsNode` object |

### ServiceGraphInstance of `apic`

| Property | Content |
|---|---|
| `ctrct_dn` | `ctrctDn` of the `vnsGraphInst` object |

### PbrPolicy of `apic`

| Property | Content |
|---|---|
| `name` | `name` of the `vnsSvcRedirectPol` object, or the name of the VyOS policy |

| Relationship | Properties |
|---|---|
| `(PbrPolicy)-[:HAS_DEST]->(PbrDest)` |  |

### PbrDest of `apic`

| Property | Content |
|---|---|
| `ip` | `ip` of the `vnsRedirectDest` object |
| `mac` | `mac` of the `vnsRedirectDest` object |

### DvPortgroup of `apic`

| Property | Content |
|---|---|
| `name` | the text after `dom-` in the DN |

### MtuObservation of `apic`

| Property | Content |
|---|---|
| `source` | `apic` |
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

## `checkpoint`

### Device of `checkpoint`

| Property | Content |
|---|---|
| `platform` | `checkpoint` |
| `role` | `management` for a type in `src/hst/collectors/checkpoint.py` `MANAGEMENT_TYPES`, or `firewall` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `identities` | the list of the identity strings of the device |
| `mgmt_ip` | the management address |
| `cp_type`, `cp_uid`, `cp_raw_uid` | the type and the uid of the management object |

| Relationship | Properties |
|---|---|
| `(Device)-[:MEMBER_OF]->(RedundancyGroup)` |  |
| `(Device)-[:ENFORCES]->(FwRulebase)` | `approximate` or `configured` |

### RedundancyGroup of `checkpoint`

| Property | Content |
|---|---|
| `kind` | `cp-cluster` |
| `name` | the name of the cluster object |
| `cp_type`, `cp_raw_uid` | the type and the uid of the cluster object |

### Prefix of `checkpoint`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `af` | 4 or 6 |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string |
| `l3dom` | the routing domain |

### IpAddress of `checkpoint`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |

### FwRulebase of `checkpoint`

| Property | Content |
|---|---|
| `kind` | `access` on an access layer |
| `match_context` | `device` on an access layer |
| `kind` | `nat` on the NAT rules of 1 package |
| `match_context` | absent on the NAT rules of 1 package |
| `name` | the name of the layer, the ruleset or the access list. The filter of a VyOS chain has `ipv4-<chain>` or `ipv6-<chain>`. The rulebase of `_legacy_firewall` has `unread VyOS 1.3 firewall`. A UniFi zone pair has `<source zone>-<destination zone>`, with ` (IPv6)` after it on the IPv6 rulebase. For `nxos`, `iosxe` and `iosxr`, the family `vlan-map` has the name of the VLAN access map, the family `zone` has the zone name, the family `common` has `<common list> <list>` or the common list alone, and the family `unparsed` has the binding line. A NAT rulebase has `NAT:<package>`, `<tree>-<direction>` or `nat-<direction>` |
| `kind` | `access`, `nat` or `zone` |
| `vendor` | `checkpoint`, `vyos`, `ubiquiti` or `cisco` |
| `match_context` | `device`, `zone-pair` or `interface-acl` |
| `default_action` | the action for a flow that no rule matches |
| `default_action_unknown` | true if the rulebase has no `default_action` |
| `global_state_policy` | a list of `<state>=<action>` strings |
| `state_policy_basis` | `vendor-default` |
| `configured_revision` | the revision of the configuration that the collector read |
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object |
| `default_action` | `accept` or `drop` from `implicit-cleanup-action` of the layer |
| `configured_revision` | the first revision that `package_revisions` holds for a package of the layer, else the result of `src/hst/collectors/checkpoint.py` `_policy_revision` for the layer |

| Relationship | Properties |
|---|---|
| `(FwRulebase)-[:HAS_RULE]->(FwRule)` |  |
| `(FwRulebase)-[:HAS_RULE]->(NatRule)` |  |

### FwRule of `checkpoint`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `action` | the action of the rule |
| `enabled` | false for a rule that the configuration disables. True on each rule of `nxos`, `iosxe` and `iosxr` |
| `name` | the name or the description of the rule |
| `rule_uid` | `uid` of the Check Point rule. `_id` of the UniFi rule. For `vyos`, `<ruleset name>:<rule number>` on a rule of `_firewall`, `pbr:<policy name>:<rule number>` or `pbr:ipv6:<policy name>:<rule number>` on a rule of `_pbr`, and `pbr:unread-legacy:<interface name>:1` on the rule of `_legacy_policy_route`. `_legacy_policy_route` writes the rule for each interface that has an `Interface` node and holds a `policy` node in the configuration |
| `rulebase_uid` | the API uid of the layer |
| `src_any` | true if the rule has no source address match |
| `dst_any` | true if the rule has no destination address match |
| `svc_any` | true if the rule has no protocol match and no port match. For `nxos`, `iosxe` and `iosxr`, true only on a rule with no `SVC` relationship |
| `src_negate` | true if the rule negates the source side |
| `dst_negate` | true if the rule negates the destination side |
| `svc_negate` | `service-negate` of the rule |
| `install_on` | the API uids of the gateways in the column `install-on`, without Any and Policy Targets |
| `install_on_unresolved` | true if an entry of `install-on` is not a gateway of the payload |
| `states_opaque` | true if the rule holds a match that the collector does not model |
| `states_opaque_reason` | the text of that match |
| `unmodeled_fields` | a list of the rule fields that the collector does not model |
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object |
| `action` | the name of the `RulebaseAction` object in lower case |

| Relationship | Properties |
|---|---|
| `(FwRule)-[:SRC]->(NetObject)` |  |
| `(FwRule)-[:DST]->(NetObject)` |  |
| `(FwRule)-[:SVC]->(SvcObject)` |  |

### CpPolicyPackage of `checkpoint`

| Property | Content |
|---|---|
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the package detail |
| `capture_complete` | false if the payload holds an entry in `policy_section_errors` |
| `implied_complete` | true if `implied_rules_complete` of the payload is true |
| `authority_uid` | the host of the source |
| `domain_uid` | the `uid` of `domain` in the package detail, else the domain of the source |
| `management_release` | the result of `src/hst/collectors/checkpoint.py` `_management_release` |
| `gateway_release` | the result of `src/hst/collectors/checkpoint.py` `_gateway_release` |
| `api_version` | `api_version` of the payload |

| Relationship | Properties |
|---|---|
| `(CpPolicyPackage)-[:HAS_LAYER]->(FwRulebase)` | `position` |

### CpPolicyObject of `checkpoint`

| Property | Content |
|---|---|
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object |

### NetObject of `checkpoint`

| Property | Content |
|---|---|
| `name` | the name of the object or of the group, or the address of an inline match. For `unifi`, also `group:<group id>`, `network:<network id>`, `gateway:<network id>`, `src side (opaque)` and `dst side (opaque)`. For `nxos`, `iosxe` and `iosxr`, the access list name on a placeholder rule. On an entry side with no address, the reason text, else `src` or `dst` |
| `kind` | the kind of the object |
| `ip`, `cidr`, `ip6`, `cidr6` | `ipv4-address`, `subnet4` with `mask-length4`, `ipv6-address`, `subnet6` with `mask-length6` |
| `ranges` | a list of `<first>-<last>` address ranges |
| `opaque` | true if the collector cannot give the address set of the object |
| `opaque_reason` | the reason as text |
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object |
| `kind` | `type` of the API object |

| Relationship | Properties |
|---|---|
| `(NetObject)-[:RESOLVES_TO]->(Prefix)` |  |
| `(NetObject)-[:RESOLVES_TO]->(IpAddress)` |  |
| `(NetObject)-[:MEMBER_OF]->(NetObject)` |  |

### SvcObject of `checkpoint`

| Property | Content |
|---|---|
| `name` | the name of the Check Point object or of the port group. The service of a rule has `<proto>/<ports>`, with `any` for an absent part and ` src <ports>` after it for a source port. In a VyOS rule with a port group, `<ports>` is the group name. For `nxos` and `iosxe`, an ICMP entry with a type has `icmp <type>`. A UniFi service has `all` for an absent protocol. An opaque UniFi service has `service (opaque)` |
| `kind` | `type` of the Check Point API object, or `group` for a port group |
| `proto` | the protocol |
| `ports` | the destination ports |
| `opaque` | true if the collector cannot give the match of the service |
| `opaque_reason` | the reason as text |
| `checkpoint_envelope_sha` | the SHA-256 of the JSON of the API object |

| Relationship | Properties |
|---|---|
| `(SvcObject)-[:MEMBER_OF]->(SvcObject)` |  |

### NatRule of `checkpoint`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `name` | the name, the comment or the description of the rule |
| `enabled` | false for a rule that the configuration disables |
| `approximate` | true if the collector cannot give the full match of the rule |
| `approximate_reason` | the reason as text |
| `protocol` | the protocol of the match |
| `src_any` | true if the original source is Any. `nat_stage` writes it only on a rule with a match access list. It is true if a permit entry of the list has `any` on the source side. For the direction `inside-destination`, `nat_stage` reads the destination side |
| `dst_any` | true if the original destination is Any |
| `xlate_src_original`, `xlate_dst_original` | true if the translated source or the translated destination is Any |
| `method` | `method` of the rule |
| `auto_generated` | `auto-generated` of the rule |
| `install_on`, `install_on_unresolved` | as on `FwRule` |
| `orig_service`, `xlate_service` | `name` of the original service object and of the translated service object |
| `orig_port` | the port of the original match |
| `xlate_port` | the port of the translated service |
| `service_unknown` | true if the collector cannot give the service match in `protocol` and the ports |

| Relationship | Properties |
|---|---|
| `(NatRule)-[:ORIG_SRC]->(NetObject)` |  |
| `(NatRule)-[:ORIG_DST]->(NetObject)` |  |
| `(NatRule)-[:XLATE_SRC]->(NetObject)` |  |
| `(NatRule)-[:XLATE_DST]->(NetObject)` |  |

## `checkpoint_gateway`

### Device of `checkpoint_gateway`

| Property | Content |
|---|---|
| `platform` | `checkpoint-gaia` |
| `role` | `firewall` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `os_version` | the software version |
| `observation_uid` | `effective_observation_uid` of the source configuration |
| `gateway_object_uid`, `authority`, `domain`, `kind`, `name` | the identity of a virtual device |

| Relationship | Properties |
|---|---|
| `(Device)-[:RUNS_ON]->(Device)` | `vsid`, `state`, `observation_uid` |

### Port of `checkpoint_gateway`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `mac` | the MAC address |
| `kind` | `physical` |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |
| `(Port)-[:CARRIES]->(VlanInstance)` | `native` |
| `(Port)-[:MEMBER_OF]->(Lag)` | `state` |

### Interface of `checkpoint_gateway`

| Property | Content |
|---|---|
| `kind` | `warp`, `vlan` |
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` |
| `mac` | the MAC address |
| `admin_up` | a boolean |
| `oper_status` | the operational state |
| `parent_interface_uid` | the uid of the parent interface |
| `mtu` | `mtu` of the row of the interface in `ip -j address show`, or in `ip -d -j link show` for an interface with no address |
| `vsid`, `vsx_kind` | the VSID and the kind of the context |
| `vsx_state` | `active`, `standby`, `backup`, `down`, `ready`, `init` or `unknown` from the `(local)` row of `cphaprob state`. `standalone` if `cluster_mode` is `standalone` |
| `vsx_cluster` | `true` if `cluster_mode` is `cluster`. With `cluster_mode` `auto`, `true` if the appliance type or `cphaprob state` shows a cluster |
| `firewall_instance_uid` | the uid of the `FirewallInstance` or of the virtual `Device` of the context |
| `installed_policy_in`, `installed_policy_out`, `installed_at_in`, `installed_at_out` | the policy name and the date text of 1 row of `src/hst/collectors/checkpoint_operational.py` `installed_policy` with the name of the interface. `<` in the row gives `in`, and `>` gives `out` |
| `vsx_topology_complete` | a boolean |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:REALIZED_BY]->(Port)` |  |
| `(Interface)-[:REALIZED_BY]->(Lag)` |  |
| `(Interface)-[:BOUND_TO]->(VlanInstance)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` | `vrf` |
| `(Interface)-[:IN_VRF]->(VrfInstance)` |  |
| `(Interface)-[:IN_CONTEXT]->(FirewallInstance)` |  |
| `(Interface)-[:IN_CONTEXT]->(Device)` |  |
| `(Interface)-[:GATEWAY_FOR]->(Prefix)` | `vrf` |
| `(Interface)-[:IN_BD]->(BridgeDomain)` |  |
| `(Interface)-[:BRIDGED_TO]->(Interface)` | `bridge`, `source` with the value `vsx-bridge`, `evidence_uid`, `context_uid`, `policy_required` |
| `(Interface)-[:CONNECTED_TO]->(Interface)` | `source` with the value `vsx-warp`, `evidence_uid`, `member_uid` |

### Lag of `checkpoint_gateway`

| Property | Content |
|---|---|
| `name` | the name of the aggregate |

| Relationship | Properties |
|---|---|
| `(Lag)-[:ON]->(Device)` |  |

### VlanInstance of `checkpoint_gateway`

| Property | Content |
|---|---|
| `vid` | the VLAN id. For `unifi`, `vlan` of the network, or 1 for a network with no `vlan` |

| Relationship | Properties |
|---|---|
| `(VlanInstance)-[:REALIZES]->(BridgeDomain)` |  |

### BridgeDomain of `checkpoint_gateway`

| Property | Content |
|---|---|
| `name` | the name of a VSX bridge |

### Endpoint of `checkpoint_gateway`

| Property | Content |
|---|---|
| `mac` | the MAC address |
| `context_uid`, `neighbor_interface` | the context and the interface of the neighbor row |
| `evidence` | `arp-nd` |

| Relationship | Properties |
|---|---|
| `(Endpoint)-[:HAS_IP]->(IpAddress)` |  |

### VrfInstance of `checkpoint_gateway`

| Property | Content |
|---|---|
| `name` | `vs:<VSID>`, or `vrf_uid` of the context in the payload |
| `firewall_instance_uid`, `authority`, `domain` | the context of the VRF |
| `vsx_runtime_sessions` | the result of `src/hst/collectors/checkpoint_evidence.py` `sessions_for` |

| Relationship | Properties |
|---|---|
| `(VrfInstance)-[:OWNED_BY]->(Device)` |  |
| `(VrfInstance)-[:IN_CONTEXT]->(FirewallInstance)` |  |
| `(VrfInstance)-[:IN_CONTEXT]->(Device)` |  |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `connected` |
| `(VrfInstance)-[:LEARNED_ROUTE]->(Prefix)` | `via`, `next_hop`, `interface`, `protocol`, `metric`, `discard` |

### FirewallInstance of `checkpoint_gateway`

| Property | Content |
|---|---|
| `gateway_object_uid`, `authority`, `domain` | the identity of the context in the management |
| `kind` | the kind of the context |
| `name` | the name of the context in `vsx stat -v` |

| Relationship | Properties |
|---|---|
| `(FirewallInstance)-[:RUNS_ON]->(Device)` | `vsid`, `state`, `observation_uid` |
| `(FirewallInstance)-[:HAS_INSTALLATION]->(PolicyInstallation)` |  |
| `(FirewallInstance)-[:ENFORCES]->(FwRulebase)` | the key `context`, `ingress`, `egress`, `af`, and `installed`, `coverage`, `installed_revision`, `context_uid`, `ingress_interface_uid`, `egress_interface_uid`, `address_family`, `evidence_uid`, `observation_uid` |

### Prefix of `checkpoint_gateway`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `af` | 4 or 6 |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string |
| `l3dom` | the name of the `VrfInstance`, on a connected `Prefix` only |
| `kind` | `connected` |

| Relationship | Properties |
|---|---|
| `(Prefix)-[:VIA]->(Interface)` | `vrf` |

### IpAddress of `checkpoint_gateway`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the name of the `VrfInstance`. Absent on a next hop address |

| Relationship | Properties |
|---|---|
| `(IpAddress)-[:IN]->(Prefix)` |  |

### RoutingProcess of `checkpoint_gateway`

| Property | Content |
|---|---|
| `proto` | `bgp` |
| `asn` | the local AS number |
| `redistribute_protocols` | the sorted protocols that the BGP process redistributes. For `nxos` and `iosxr`, without the statements of the IPv6 unicast address family. For `checkpoint_gateway`, the protocols of the `match protocol` terms of the enabled `permit` clauses of an exported route map, with `connected` for `direct` and without `bgp` and `ibgp` |
| `origin_config_recorded` | a boolean |
| `origin_afs` | `[4, 6]` |
| `origin_context_gaps` | a list of texts |
| `platform` | `checkpoint-gaia` |

| Relationship | Properties |
|---|---|
| `(RoutingProcess)-[:IN_VRF]->(VrfInstance)` |  |
| `(RoutingProcess)-[:HAS]->(BgpSession)` |  |

### BgpSession of `checkpoint_gateway`

| Property | Content |
|---|---|
| `peer_ip`, `local_asn`, `peer_asn` | the neighbor address and the 2 AS numbers |
| `state` | the state of the peer in `show bgp peers` in lower case. Else `shutdown` for a peer that the configuration turns off, else `unknown` |
| `import_policy_name`, `import_policy_kind`, `export_policy_name`, `export_policy_kind` | the session policy for each direction |
| `af`, `local_address`, `context_uid`, `vsid` | the address family, the local address and the context |
| `platform` | `checkpoint-gaia` |

| Relationship | Properties |
|---|---|
| `(BgpSession)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `in` or `out` |

### RoutePolicy of `checkpoint_gateway`

| Property | Content |
|---|---|
| `name` | the name of the policy |
| `kind` | `gaia-route-map` or `gaia-chain` |
| `platform` | `checkpoint-gaia` on a `gaia-route-map` |
| `policy_names` | the route maps of a `gaia-chain` |
| `context_uid` | the context of the policy |

| Relationship | Properties |
|---|---|
| `(RoutePolicy)-[:HAS_RULE]->(RoutePolicyEntry)` |  |
| `(RoutePolicy)-[:REFERENCES]->(RoutePolicy)` |  |

### RoutePolicyEntry of `checkpoint_gateway`

| Property | Content |
|---|---|
| `seq` | the sequence number. For `iosxr`, the position of the statement in the route policy, from 1. For a `gaia-clause`, the `id` of the route map clause, and 10 for `default`. For a `gaia-chain-member`, the position of the route map in the chain, from 0 |
| `kind` | `gaia-clause` or `gaia-chain-member` |
| `action` | the action of the entry. For `iosxr`, `permit` for `done` and `deny` for `drop`, else absent. For `checkpoint_gateway`, `permit`, `deny` or `unknown` on a `gaia-clause`, and absent on a `gaia-chain-member` |
| `enabled`, `gaia_terms`, `context_uid` | the state, the terms as JSON and the context of a `gaia-clause` |
| `policy_name`, `address_families` | the route map and the address families of a `gaia-chain-member` |

### PolicyInstallation of `checkpoint_gateway`

| Property | Content |
|---|---|
| `installed_revision` | the installed revision of the observation |
| `context_uid` | the uid of the `VrfInstance` of the context |
| `observation_uid` | the observation uid of the source |

| Relationship | Properties |
|---|---|
| `(PolicyInstallation)-[:INSTALLS]->(FwRulebase)` |  |

## `equinix`

### Site of `equinix`

| Property | Content |
|---|---|
| `code` | the site code |
| `kind` | `colo` |

### Device of `equinix`

| Property | Content |
|---|---|
| `platform` | `network-edge` |
| `role` | `router`, `firewall` or `sdwan-edge` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `identities` | the list of the identity strings of the device |
| `vendor` | `deviceTypeVendor` of the device |
| `os_version` | the software version |
| `model` | the hardware model |
| `virtual` | `true` |
| `redundancy` | `redundancyType` in lower case |
| `bound_device_uid` | the uid of the device that the source configuration binds |
| `edge_device_uuid`, `edge_device_name`, `edge_device_type`, `edge_status`, `edge_management_ip`, `ibx`, `metro` | fields of the Network Edge device |

| Relationship | Properties |
|---|---|
| `(Device)-[:LOCATED_IN]->(Site)` |  |
| `(Device)-[:PROVIDED_BY]->(Provider)` |  |

### Port of `equinix`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `mac` | the MAC address |
| `kind` | `mgmt` for the type `SSH`, or `phys` |
| `edge_interface_uuid`, `edge_device_uid` | the uuid of the interface and the uid of its device |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |

### Provider of `equinix`

| Property | Content |
|---|---|
| `name` | `Equinix` |
| `kind` | `colo` |

### Interface of `equinix`

| Property | Content |
|---|---|
| `kind` | the interface type in lower case |
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` |
| `mac` | the MAC address |
| `state`, `assigned`, `edge_interface_uuid`, `edge_interface_id`, `edge_device_uid` | fields of the Network Edge interface |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:REALIZED_BY]->(Port)` |  |

### FabricPort of `equinix`

| Property | Content |
|---|---|
| `name` | `name` of the port, else its `uuid` |
| `port_uuid` | `uuid` of the port |
| `state` | `state` |
| `ibx` | `ibx` of `location` |
| `metro` | `metroCode` of `location` |
| `speed_mbps` | `bandwidth` as an integer above 0 |
| `physical_ports_speed` | `physicalPortsSpeed` |
| `encapsulation` | `type` of `encapsulation` in lower case |
| `bound_port_uid` | the `Port` uid for the port in the field `port_bindings` of `src/hst/collectors/equinix.py` `EquinixConfig` |
| `cross_connect_ids` | the sorted cable ids from `tether.crossConnectId` of each physical port |
| `redundancy` | `priority` of `redundancy` in lower case |
| `lag_name` | `name` of `lag` if `enabled` of `lag` is true |

| Relationship | Properties |
|---|---|
| `(FabricPort)-[:LOCATED_IN]->(Site)` |  |
| `(FabricPort)-[:REALIZED_BY]->(Port)` |  |

### VirtualCircuit of `equinix`

| Property | Content |
|---|---|
| `name` | `name` of the connection, else its `uuid`. `groupName` of the group, else its `uuid` |
| `type` | `type` of the connection, or `DEVICE_LINK` |
| `state` | `state` of the connection, or `status` of the group |
| `bandwidth_mbps` | `bandwidth` of the connection as an integer above 0, or the lowest `throughput` of the `metroLinks` of the group with the unit Mbps |
| `a_side_kind`, `z_side_kind` | `type` of the access point of the side in lower case, or `vd` for a device link |
| `connection_uuid` | `uuid` of the connection |
| `provider` | `name` of `profile` of the access point of the Z side |
| `provider_profile_uuid` | `uuid` of that `profile` |
| `a_virtual_device`, `a_virtual_device_uuid` | `name` and `uuid` of `virtualDevice` of the access point of the A side |
| `redundancy` | `redundancyType` of the group in lower case |
| `device_link_group_uuid` | `uuid` of the group |
| `link_protocol` | `dot1q`, `qinq` or `untagged`, else `type` in lower case |
| `vlan_tag` | `vlanSTag` for `QINQ`, or `vlanTag` if the S tag is absent. `vlanTag` for each other type |
| `inner_vlan_tag` | `vlanCTag` for `QINQ`, else absent |

| Relationship | Properties |
|---|---|
| `(VirtualCircuit)-[:PROVIDED_BY]->(Provider)` |  |
| `(VirtualCircuit)-[:A_END]->(FabricPort)` | `link_protocol`, `vlan_tag`, `inner_vlan_tag` |
| `(VirtualCircuit)-[:Z_END]->(FabricPort)` | `link_protocol`, `vlan_tag`, `inner_vlan_tag` |
| `(VirtualCircuit)-[:A_END]->(Interface)` | `link_protocol`, `vlan_tag`, `inner_vlan_tag` |
| `(VirtualCircuit)-[:Z_END]->(Interface)` | `link_protocol`, `vlan_tag`, `inner_vlan_tag` |

## `iosxe`

### Device of `iosxe`

| Property | Content |
|---|---|
| `platform` | `iosxe` |
| `role` | `router` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `identities` | the list of the identity strings of the device |
| `vendor` | `cisco` |
| `os_version` | the software version |

| Relationship | Properties |
|---|---|
| `(Device)-[:ENFORCES]->(FwRulebase)` | `installed`, `coverage`, `installed_revision`, `context_uid`, `ingress_interface_uid`, `egress_interface_uid`, `address_family` for an access list, no property for a NAT rulebase and for the `vyos` rulebase `unread VyOS 1.3 firewall` |
| `(Device)-[:HAS_MTU]->(MtuObservation)` |  |

### Port of `iosxe`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `mac` | the MAC address |
| `kind` | `phys` or `lag` |
| `speed_mbps`, `duplex`, `speed_source` | the operational speed, `full` or `half`, and `nxos:eth_speed`, `iosxe:show interfaces` or `iosxr:show interfaces`. `speed_mbps` is absent if the device gives no speed number. `duplex` is absent if the device gives no `full` or `half` |
| `bandwidth_kbit` | the bandwidth of the interface |
| `description` | the description of the port |
| `lldp_neighbor_name`, `lldp_neighbor_mac`, `lldp_neighbor_port` | the LLDP neighbor of the port |
| `cdp_neighbor_name`, `cdp_neighbor_port` | the CDP neighbor of the port |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |
| `(Port)-[:MEMBER_OF]->(Lag)` | `state`, `source_command`, `assertion_kind`, `eligible` |
| `(Port)-[:HAS_MTU]->(MtuObservation)` |  |

### Interface of `iosxe`

| Property | Content |
|---|---|
| `kind` | `phys`, `subif`, `svi`, `loopback`, `lag` |
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` |
| `mac` | the MAC address |
| `admin_up` | a boolean |
| `oper_status` | the operational state |
| `description` | the description of the interface |
| `parent_interface_uid` | the uid of the parent interface |
| `parent_source_command` | the command that gives the parent |
| `nat_role` | the NAT role of the interface |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:REALIZED_BY]->(Port)` |  |
| `(Interface)-[:REALIZED_BY]->(Lag)` |  |
| `(Interface)-[:BOUND_TO]->(VlanInstance)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` | `fhrp`, `group`, `state` for a virtual address |
| `(Interface)-[:IN_VRF]->(VrfInstance)` |  |
| `(Interface)-[:MEMBER_OF]->(FhrpGroup)` | `priority`, `state` |
| `(Interface)-[:IN_AREA]->(OspfArea)` | `cost`, `network_type`, `passive` |
| `(Interface)-[:PROTECTED_BY]->(FwRulebase)` | `direction` |
| `(Interface)-[:HAS_MTU]->(MtuObservation)` |  |

### Lag of `iosxe`

| Property | Content |
|---|---|
| `name` | the name of the aggregate |

| Relationship | Properties |
|---|---|
| `(Lag)-[:ON]->(Device)` |  |

### VlanInstance of `iosxe`

| Property | Content |
|---|---|
| `vid` | the VLAN id. For `unifi`, `vlan` of the network, or 1 for a network with no `vlan` |

| Relationship | Properties |
|---|---|
| `(VlanInstance)-[:REALIZES]->(BridgeDomain)` |  |

### FhrpGroup of `iosxe`

| Property | Content |
|---|---|
| `kind` | the protocol in lower case |
| `group_id` | the group number |
| `vip` | the virtual address |
| `af` | the address family of `vip`, 4 or 6 |

| Relationship | Properties |
|---|---|
| `(FhrpGroup)-[:HAS_IP]->(IpAddress)` |  |

### VrfInstance of `iosxe`

| Property | Content |
|---|---|
| `name` | the name of the VRF |
| `rd` | the route distinguisher |
| `table_id` | the name of the VRF |
| `is_global` | `true` for the global table |

| Relationship | Properties |
|---|---|
| `(VrfInstance)-[:OWNED_BY]->(Device)` |  |
| `(VrfInstance)-[:IMPORTS]->(RouteTarget)` |  |
| `(VrfInstance)-[:EXPORTS]->(RouteTarget)` |  |
| `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `declared` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `connected` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `network`, `route_map` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `aggregate`, `summary_only`, `as_set`, `attribute_map`, `unsupported_options` |

### RoutingDomain of `iosxe`

| Property | Content |
|---|---|
| `name` | the display name of the domain |

### RouteTarget of `iosxe`

| Property | Content |
|---|---|
| `value` | the route target |

### Prefix of `iosxe`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `af` | 4 or 6 |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string |
| `l3dom` | the routing domain |
| `kind` | `connected` |
| `kind` | `bgp-network`, `aggregate` |
| `kind` | `nat-pool` |

### IpAddress of `iosxe`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |

| Relationship | Properties |
|---|---|
| `(IpAddress)-[:IN]->(Prefix)` |  |

### RoutingProcess of `iosxe`

| Property | Content |
|---|---|
| `proto` | `bgp` |
| `proto` | `ospf` |
| `asn` | the local AS number |
| `router_id` | the router id |
| `process_id` | the OSPF process id. An empty string for `vyos` |
| `always_compare_med` | `true` if configured |
| `multipath_config_recorded`, `multipath_relax`, `maximum_paths_<ebgp or ibgp>_v<4 or 6>` | the result of `src/hst/collectors/util.py` `bgp_multipath_props` |
| `default_information_originate_afs` | the address families of a BGP default origin |
| `default_information_originate` | `true` if the OSPF process holds `default-information originate` |
| `default_information_originate_always` | `true` if that statement holds `always` |
| `redistribute_protocols` | the sorted protocols that the BGP process redistributes. For `nxos` and `iosxr`, without the statements of the IPv6 unicast address family. For `checkpoint_gateway`, the protocols of the `match protocol` terms of the enabled `permit` clauses of an exported route map, with `connected` for `direct` and without `bgp` and `ibgp` |
| `redist_<protocol>_route_map` | the route map or the route policy of 1 redistribution of an OSPF process |
| `origin_config_recorded` | a boolean |
| `origin_afs` | `[4, 6]` |
| `origin_context_gaps` | a list of texts |
| `session_gaps` | a list of texts |

| Relationship | Properties |
|---|---|
| `(RoutingProcess)-[:IN_VRF]->(VrfInstance)` |  |
| `(RoutingProcess)-[:HAS]->(BgpSession)` |  |
| `(RoutingProcess)-[:HAS]->(BgpPeerRange)` |  |
| `(RoutingProcess)-[:HAS]->(OspfArea)` |  |
| `(RoutingProcess)-[:HAS]->(OspfAdjacency)` |  |
| `(RoutingProcess)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `redistribute`, `protocol` |

### BgpSession of `iosxe`

| Property | Content |
|---|---|
| `peer_ip`, `local_asn`, `peer_asn` | the neighbor address and the 2 AS numbers |
| `state` | `shutdown` for a neighbor that is shut down |
| `dynamic_range` | the listen range of a dynamic peer |
| `observed_state` | the state of a dynamic peer in the session table of the device. For `nxos`, the `state` text of the device. For `iosxe` and `iosxr`, `Established` for a number in the state column, else the text of the column |
| `inheritance_gaps` | a list of texts, 1 for each template or group of the neighbor that the configuration does not hold |
| `import_policy_name`, `import_policy_kind`, `export_policy_name`, `export_policy_kind` | the session policy for each direction |
| `import_prefix_list_name`, `export_prefix_list_name` | a prefix list beside a route map |
| `import_filter_list_name`, `export_filter_list_name` | the AS-path filter list |
| `route_reflector_client`, `cluster_id` | the route reflector settings |
| `peer_router_id` | the router id of the peer |
| `next_hop_self` | the setting of the neighbor |
| `peer_group` | the peer group of the neighbor |

| Relationship | Properties |
|---|---|
| `(BgpSession)-[:MEMBER_OF]->(BgpPeerRange)` |  |
| `(BgpSession)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `in`, `out`, `in-prefix-list` or `out-prefix-list` |

### BgpPeerRange of `iosxe`

| Property | Content |
|---|---|
| `prefix`, `local_asn` | the neighbor network and the local AS number |
| `peer_group` | the peer group of the range |

| Relationship | Properties |
|---|---|
| `(BgpPeerRange)-[:FILTERED_BY]->(RoutePolicy)` | `direction` |

### OspfArea of `iosxe`

| Property | Content |
|---|---|
| `area_id` | the area id |
| `type` | the area type |

### OspfAdjacency of `iosxe`

| Property | Content |
|---|---|
| `state` | the state of the adjacency |
| `area` | the area id |
| `neighbor_router_id`, `neighbor_ip` | the router id and the address of the neighbor |
| `local_interface` | the name of the local interface |

| Relationship | Properties |
|---|---|
| `(OspfAdjacency)-[:ENDPOINT]->(Interface)` |  |

### RoutePolicy of `iosxe`

| Property | Content |
|---|---|
| `name` | the name of the policy |
| `kind` | `route-map`, `prefix-list`, `community-list` or `as-path-list` |

| Relationship | Properties |
|---|---|
| `(RoutePolicy)-[:HAS_RULE]->(RoutePolicyEntry)` |  |
| `(RoutePolicy)-[:HAS_RULE]->(PrefixListEntry)` |  |
| `(RoutePolicy)-[:HAS_RULE]->(MatchListEntry)` |  |

### RoutePolicyEntry of `iosxe`

| Property | Content |
|---|---|
| `seq` | the sequence number. For `iosxr`, the position of the statement in the route policy, from 1. For a `gaia-clause`, the `id` of the route map clause, and 10 for `default`. For a `gaia-chain-member`, the position of the route map in the chain, from 0 |
| `kind` | `clause` |
| `action` | the action of the entry. For `iosxr`, `permit` for `done` and `deny` for `drop`, else absent. For `checkpoint_gateway`, `permit`, `deny` or `unknown` on a `gaia-clause`, and absent on a `gaia-chain-member` |
| `continues`, `continue_seq` | the continue clause |
| `match_prefix_lists`, `match_as_path_lists`, `match_community_lists` | the lists that the match clauses reference |
| `match_tags`, `match_metric` | values of the match clauses |
| `match_protocols` | values of the match clauses |
| `match_unsupported`, `set_unsupported` | the lines that the parser does not model |
| `set_local_pref`, `set_metric`, `set_as_path_prepend`, `set_communities`, `set_communities_additive`, `set_comm_list_delete` | values of the set clauses |
| `set_origin`, `set_tag`, `set_weight`, `set_next_hop` | values of the set clauses |

| Relationship | Properties |
|---|---|
| `(RoutePolicyEntry)-[:REFERENCES]->(RoutePolicy)` | `kind` with the value `prefix-list`, `community-list` or `as-path-list` |

### PrefixListEntry of `iosxe`

| Property | Content |
|---|---|
| `seq`, `action`, `prefix` | the sequence number, the action and the prefix. For `iosxr`, `seq` is the position of the line in the prefix set, from 1, and `action` is `permit` |
| `ge`, `le` | the length bounds of the entry |
| `eq` | the exact length of the entry |
| `min_len`, `max_len` | the lowest and the highest prefix length that the entry matches |

### MatchListEntry of `iosxe`

| Property | Content |
|---|---|
| `seq`, `action` | the sequence number and the action. For `iosxr`, `seq` is the position of the element in the set, from 1, and `action` is `permit` |
| `match_type` | the type that `src/hst/simul/matchlist.py` uses to read `value` |
| `value` | the value of the entry |

### FwRulebase of `iosxe`

| Property | Content |
|---|---|
| `kind` | `access` on a pair of a family of `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` and a list name with 1 or more interface bindings |
| `match_context` | `interface-acl` on a pair of a family of `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` and a list name with 1 or more interface bindings |
| `kind` | `nat` on the NAT rules of 1 direction |
| `match_context` | absent on the NAT rules of 1 direction |
| `name` | the name of the layer, the ruleset or the access list. The filter of a VyOS chain has `ipv4-<chain>` or `ipv6-<chain>`. The rulebase of `_legacy_firewall` has `unread VyOS 1.3 firewall`. A UniFi zone pair has `<source zone>-<destination zone>`, with ` (IPv6)` after it on the IPv6 rulebase. For `nxos`, `iosxe` and `iosxr`, the family `vlan-map` has the name of the VLAN access map, the family `zone` has the zone name, the family `common` has `<common list> <list>` or the common list alone, and the family `unparsed` has the binding line. A NAT rulebase has `NAT:<package>`, `<tree>-<direction>` or `nat-<direction>` |
| `kind` | `access`, `nat` or `zone` |
| `vendor` | `checkpoint`, `vyos`, `ubiquiti` or `cisco` |
| `match_context` | `device`, `zone-pair` or `interface-acl` |
| `af` | 4 or 6. Absent on a NAT rulebase, on the rulebase of `_legacy_firewall`, on the first rulebase of a UniFi zone pair and on a Cisco list with no address family |
| `default_action` | the action for a flow that no rule matches |
| `configured_revision` | the revision of the configuration that the collector read |
| `unreported_bindings` | a list of `<interface> <direction>` strings for the bindings with no `Interface` node |
| `default_action` | `deny` |
| `configured_revision` | the SHA-256 of the name and the entries of the access list |

| Relationship | Properties |
|---|---|
| `(FwRulebase)-[:HAS_RULE]->(FwRule)` |  |
| `(FwRulebase)-[:HAS_RULE]->(NatRule)` |  |

### FwRule of `iosxe`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `action` | the action of the rule |
| `enabled` | false for a rule that the configuration disables. True on each rule of `nxos`, `iosxe` and `iosxr` |
| `src_any` | true if the rule has no source address match |
| `dst_any` | true if the rule has no destination address match |
| `svc_any` | true if the rule has no protocol match and no port match. For `nxos`, `iosxe` and `iosxr`, true only on a rule with no `SVC` relationship |
| `states` | the list of connection states that the rule matches |
| `unmodeled_fields` | a list of the rule fields that the collector does not model |
| `action` | the action of the entry. `deny` for a placeholder rule |

| Relationship | Properties |
|---|---|
| `(FwRule)-[:SRC]->(NetObject)` |  |
| `(FwRule)-[:DST]->(NetObject)` |  |
| `(FwRule)-[:SVC]->(SvcObject)` |  |

### NetObject of `iosxe`

| Property | Content |
|---|---|
| `name` | the name of the object or of the group, or the address of an inline match. For `unifi`, also `group:<group id>`, `network:<network id>`, `gateway:<network id>`, `src side (opaque)` and `dst side (opaque)`. For `nxos`, `iosxe` and `iosxr`, the access list name on a placeholder rule. On an entry side with no address, the reason text, else `src` or `dst` |
| `kind` | the kind of the object |
| `opaque` | true if the collector cannot give the address set of the object |
| `opaque_reason` | the reason as text |
| `opaque_note` | a short form of the reason |
| `kind` | `inline` |

| Relationship | Properties |
|---|---|
| `(NetObject)-[:RESOLVES_TO]->(Prefix)` |  |
| `(NetObject)-[:RESOLVES_TO]->(IpAddress)` |  |

### SvcObject of `iosxe`

| Property | Content |
|---|---|
| `name` | the name of the Check Point object or of the port group. The service of a rule has `<proto>/<ports>`, with `any` for an absent part and ` src <ports>` after it for a source port. In a VyOS rule with a port group, `<ports>` is the group name. For `nxos` and `iosxe`, an ICMP entry with a type has `icmp <type>`. A UniFi service has `all` for an absent protocol. An opaque UniFi service has `service (opaque)` |
| `proto` | the protocol |
| `ports` | the destination ports |
| `src_port` | the source ports |
| `icmp_type` | the ICMP type of an ICMP entry |
| `opaque` | true if the collector cannot give the match of the service |
| `opaque_reason` | the reason as text |
| `opaque_note` | a short form of the reason |

### NatRule of `iosxe`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `kind` | `snat`, `dnat` or `static` |
| `approximate` | true if the collector cannot give the full match of the rule |
| `protocol` | the protocol of the match |
| `src_any` | true if the original source is Any. `nat_stage` writes it only on a rule with a match access list. It is true if a permit entry of the list has `any` on the source side. For the direction `inside-destination`, `nat_stage` reads the destination side |
| `orig_port` | the port of the original match |
| `translation` | the translated address, prefix or range, `masquerade`, or `interface` |
| `translation_port` | the translated port |
| `direction` | the NAT direction of the rule, such as `inside-source` |
| `static` | true for a static translation |
| `overload` | true for a rule with overload |
| `translation_interface` | the interface of the translation |
| `match_acl`, `match_route_map` | the access list and the route map of the match |
| `pool`, `pool_start`, `pool_end` | the name, the first address and the last address of the pool |

| Relationship | Properties |
|---|---|
| `(NatRule)-[:ORIG_SRC]->(Prefix)`, `(NatRule)-[:ORIG_SRC]->(IpAddress)` |  |
| `(NatRule)-[:ORIG_DST]->(Prefix)`, `(NatRule)-[:ORIG_DST]->(IpAddress)` |  |
| `(NatRule)-[:XLATE_SRC]->(Prefix)`, `(NatRule)-[:XLATE_SRC]->(IpAddress)` |  |
| `(NatRule)-[:XLATE_DST]->(Prefix)`, `(NatRule)-[:XLATE_DST]->(IpAddress)` |  |

### MtuObservation of `iosxe`

| Property | Content |
|---|---|
| `source` | the source type |
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

## `iosxr`

### Device of `iosxr`

| Property | Content |
|---|---|
| `platform` | `iosxr` |
| `role` | `router` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `identities` | the list of the identity strings of the device |
| `vendor` | `cisco` |
| `os_version` | the software version |

| Relationship | Properties |
|---|---|
| `(Device)-[:ENFORCES]->(FwRulebase)` | `installed`, `coverage`, `installed_revision`, `context_uid`, `ingress_interface_uid`, `egress_interface_uid`, `address_family` for an access list, no property for a NAT rulebase and for the `vyos` rulebase `unread VyOS 1.3 firewall` |

### Port of `iosxr`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `mac` | the MAC address |
| `kind` | `phys` or `lag` |
| `speed_mbps`, `duplex`, `speed_source` | the operational speed, `full` or `half`, and `nxos:eth_speed`, `iosxe:show interfaces` or `iosxr:show interfaces`. `speed_mbps` is absent if the device gives no speed number. `duplex` is absent if the device gives no `full` or `half` |
| `bandwidth_kbit` | the bandwidth of the interface |
| `description` | the description of the port |
| `lldp_neighbor_name`, `lldp_neighbor_mac`, `lldp_neighbor_port` | the LLDP neighbor of the port |
| `cdp_neighbor_name`, `cdp_neighbor_port` | the CDP neighbor of the port |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |
| `(Port)-[:MEMBER_OF]->(Lag)` | `state`, `source_command`, `assertion_kind`, `eligible` |
| `(Port)-[:HAS_MTU]->(MtuObservation)` |  |

### Interface of `iosxr`

| Property | Content |
|---|---|
| `kind` | `phys`, `subif`, `loopback`, `lag` |
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` |
| `mac` | the MAC address |
| `admin_up` | a boolean |
| `oper_status` | the operational state |
| `description` | the description of the interface |
| `parent_interface_uid` | the uid of the parent interface |
| `parent_source_command` | the command that gives the parent |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:REALIZED_BY]->(Port)` |  |
| `(Interface)-[:REALIZED_BY]->(Lag)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` | `fhrp`, `group`, `state` for a virtual address |
| `(Interface)-[:IN_VRF]->(VrfInstance)` |  |
| `(Interface)-[:MEMBER_OF]->(FhrpGroup)` | `priority`, `state` |
| `(Interface)-[:IN_AREA]->(OspfArea)` | `cost`, `network_type`, `passive` |
| `(Interface)-[:PROTECTED_BY]->(FwRulebase)` | `direction` |
| `(Interface)-[:HAS_MTU]->(MtuObservation)` |  |

### Lag of `iosxr`

| Property | Content |
|---|---|
| `name` | the name of the aggregate |

| Relationship | Properties |
|---|---|
| `(Lag)-[:ON]->(Device)` |  |

### FhrpGroup of `iosxr`

| Property | Content |
|---|---|
| `kind` | the protocol in lower case |
| `group_id` | the group number |
| `vip` | the virtual address |
| `af` | the address family of `vip`, 4 or 6 |

| Relationship | Properties |
|---|---|
| `(FhrpGroup)-[:HAS_IP]->(IpAddress)` |  |

### VrfInstance of `iosxr`

| Property | Content |
|---|---|
| `name` | the name of the VRF |
| `rd` | the route distinguisher |
| `table_id` | the name of the VRF |
| `is_global` | `true` for the global table |

| Relationship | Properties |
|---|---|
| `(VrfInstance)-[:OWNED_BY]->(Device)` |  |
| `(VrfInstance)-[:IMPORTS]->(RouteTarget)` |  |
| `(VrfInstance)-[:EXPORTS]->(RouteTarget)` |  |
| `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `declared` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `connected` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `network`, `route_map` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `aggregate`, `summary_only`, `as_set`, `attribute_map`, `unsupported_options` |

### RoutingDomain of `iosxr`

| Property | Content |
|---|---|
| `name` | the display name of the domain |

### RouteTarget of `iosxr`

| Property | Content |
|---|---|
| `value` | the route target |

### Prefix of `iosxr`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `af` | 4 or 6 |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string |
| `l3dom` | the routing domain |
| `kind` | `connected` |
| `kind` | `bgp-network`, `aggregate` |

### IpAddress of `iosxr`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |

| Relationship | Properties |
|---|---|
| `(IpAddress)-[:IN]->(Prefix)` |  |

### RoutingProcess of `iosxr`

| Property | Content |
|---|---|
| `proto` | `bgp` |
| `proto` | `ospf` |
| `asn` | the local AS number |
| `router_id` | the router id |
| `process_id` | the OSPF process id. An empty string for `vyos` |
| `always_compare_med` | `true` if configured |
| `multipath_config_recorded`, `multipath_relax`, `maximum_paths_<ebgp or ibgp>_v<4 or 6>` | the result of `src/hst/collectors/util.py` `bgp_multipath_props` |
| `default_information_originate_afs` | the address families of a BGP default origin |
| `default_information_originate` | `true` if the OSPF process holds `default-information originate` |
| `default_information_originate_always` | `true` if that statement holds `always` |
| `redistribute_protocols` | the sorted protocols that the BGP process redistributes. For `nxos` and `iosxr`, without the statements of the IPv6 unicast address family. For `checkpoint_gateway`, the protocols of the `match protocol` terms of the enabled `permit` clauses of an exported route map, with `connected` for `direct` and without `bgp` and `ibgp` |
| `redist_<protocol>_route_map` | the route map or the route policy of 1 redistribution of an OSPF process |
| `origin_config_recorded` | a boolean |
| `origin_afs` | `[4, 6]` |
| `origin_context_gaps` | a list of texts |
| `session_gaps` | a list of texts |

| Relationship | Properties |
|---|---|
| `(RoutingProcess)-[:IN_VRF]->(VrfInstance)` |  |
| `(RoutingProcess)-[:HAS]->(BgpSession)` |  |
| `(RoutingProcess)-[:HAS]->(BgpPeerRange)` |  |
| `(RoutingProcess)-[:HAS]->(OspfArea)` |  |
| `(RoutingProcess)-[:HAS]->(OspfAdjacency)` |  |
| `(RoutingProcess)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `redistribute`, `protocol` |

### BgpSession of `iosxr`

| Property | Content |
|---|---|
| `peer_ip`, `local_asn`, `peer_asn` | the neighbor address and the 2 AS numbers |
| `state` | `shutdown` for a neighbor that is shut down |
| `afi_safi` | the list of address families |
| `dynamic_range` | the listen range of a dynamic peer |
| `observed_state` | the state of a dynamic peer in the session table of the device. For `nxos`, the `state` text of the device. For `iosxe` and `iosxr`, `Established` for a number in the state column, else the text of the column |
| `inheritance_gaps` | a list of texts, 1 for each template or group of the neighbor that the configuration does not hold |
| `import_policy_name`, `import_policy_kind`, `export_policy_name`, `export_policy_kind` | the session policy for each direction |
| `route_reflector_client`, `cluster_id` | the route reflector settings |
| `peer_router_id` | the router id of the peer |

| Relationship | Properties |
|---|---|
| `(BgpSession)-[:MEMBER_OF]->(BgpPeerRange)` |  |
| `(BgpSession)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `in` or `out` |

### BgpPeerRange of `iosxr`

| Property | Content |
|---|---|
| `prefix`, `local_asn` | the neighbor network and the local AS number |

| Relationship | Properties |
|---|---|
| `(BgpPeerRange)-[:FILTERED_BY]->(RoutePolicy)` | `direction` |

### OspfArea of `iosxr`

| Property | Content |
|---|---|
| `area_id` | the area id |
| `type` | the area type |

### OspfAdjacency of `iosxr`

| Property | Content |
|---|---|
| `state` | the state of the adjacency |
| `area` | the area id |
| `neighbor_router_id`, `neighbor_ip` | the router id and the address of the neighbor |
| `local_interface` | the name of the local interface |

| Relationship | Properties |
|---|---|
| `(OspfAdjacency)-[:ENDPOINT]->(Interface)` |  |

### RoutePolicy of `iosxr`

| Property | Content |
|---|---|
| `name` | the name of the policy |
| `kind` | `rpl`, `prefix-list`, `community-list` or `as-path-list` |

| Relationship | Properties |
|---|---|
| `(RoutePolicy)-[:HAS_RULE]->(RoutePolicyEntry)` |  |
| `(RoutePolicy)-[:HAS_RULE]->(PrefixListEntry)` |  |
| `(RoutePolicy)-[:HAS_RULE]->(MatchListEntry)` |  |

### RoutePolicyEntry of `iosxr`

| Property | Content |
|---|---|
| `seq` | the sequence number. For `iosxr`, the position of the statement in the route policy, from 1. For a `gaia-clause`, the `id` of the route map clause, and 10 for `default`. For a `gaia-chain-member`, the position of the route map in the chain, from 0 |
| `kind` | `statement` |
| `action` | the action of the entry. For `iosxr`, `permit` for `done` and `deny` for `drop`, else absent. For `checkpoint_gateway`, `permit`, `deny` or `unknown` on a `gaia-clause`, and absent on a `gaia-chain-member` |
| `continues`, `continue_seq` | `true` and the `seq` of the next branch, on a branch of an `if` statement that another branch follows |
| `match_prefix_lists`, `match_as_path_lists`, `match_community_lists` | the lists that the match clauses reference |
| `match_tags`, `match_metric` | values of the match clauses |
| `match_unsupported`, `set_unsupported` | the lines that the parser does not model |
| `match_expr`, `match_policies`, `parent_seq`, `passes` | fields of the parsed statement |
| `set_local_pref`, `set_metric`, `set_as_path_prepend`, `set_communities`, `set_communities_additive`, `set_comm_list_delete` | values of the set clauses |
| `set_origin`, `set_tag`, `set_weight`, `set_next_hop` | values of the set clauses |
| `calls_policy` | the name of the called policy |

| Relationship | Properties |
|---|---|
| `(RoutePolicyEntry)-[:REFERENCES]->(RoutePolicy)` | `kind` with the value `prefix-list`, `community-list`, `as-path-list` or `call` |

### PrefixListEntry of `iosxr`

| Property | Content |
|---|---|
| `seq`, `action`, `prefix` | the sequence number, the action and the prefix. For `iosxr`, `seq` is the position of the line in the prefix set, from 1, and `action` is `permit` |
| `ge`, `le` | the length bounds of the entry |
| `eq` | the exact length of the entry |
| `min_len`, `max_len` | the lowest and the highest prefix length that the entry matches |

### MatchListEntry of `iosxr`

| Property | Content |
|---|---|
| `seq`, `action` | the sequence number and the action. For `iosxr`, `seq` is the position of the element in the set, from 1, and `action` is `permit` |
| `match_type` | the type that `src/hst/simul/matchlist.py` uses to read `value` |
| `value` | the value of the entry |

### FwRulebase of `iosxr`

| Property | Content |
|---|---|
| `kind` | `access` on a pair of a family of `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` and a list name with 1 or more interface bindings |
| `match_context` | `interface-acl` on a pair of a family of `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` and a list name with 1 or more interface bindings |
| `name` | the name of the layer, the ruleset or the access list. The filter of a VyOS chain has `ipv4-<chain>` or `ipv6-<chain>`. The rulebase of `_legacy_firewall` has `unread VyOS 1.3 firewall`. A UniFi zone pair has `<source zone>-<destination zone>`, with ` (IPv6)` after it on the IPv6 rulebase. For `nxos`, `iosxe` and `iosxr`, the family `vlan-map` has the name of the VLAN access map, the family `zone` has the zone name, the family `common` has `<common list> <list>` or the common list alone, and the family `unparsed` has the binding line. A NAT rulebase has `NAT:<package>`, `<tree>-<direction>` or `nat-<direction>` |
| `kind` | `access`, `nat` or `zone` |
| `vendor` | `checkpoint`, `vyos`, `ubiquiti` or `cisco` |
| `match_context` | `device`, `zone-pair` or `interface-acl` |
| `af` | 4 or 6. Absent on a NAT rulebase, on the rulebase of `_legacy_firewall`, on the first rulebase of a UniFi zone pair and on a Cisco list with no address family |
| `default_action` | the action for a flow that no rule matches |
| `configured_revision` | the revision of the configuration that the collector read |
| `unreported_bindings` | a list of `<interface> <direction>` strings for the bindings with no `Interface` node |
| `default_action` | `deny` |
| `configured_revision` | the SHA-256 of the name and the entries of the access list |

| Relationship | Properties |
|---|---|
| `(FwRulebase)-[:HAS_RULE]->(FwRule)` |  |

### FwRule of `iosxr`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `action` | the action of the rule |
| `enabled` | false for a rule that the configuration disables. True on each rule of `nxos`, `iosxe` and `iosxr` |
| `src_any` | true if the rule has no source address match |
| `dst_any` | true if the rule has no destination address match |
| `svc_any` | true if the rule has no protocol match and no port match. For `nxos`, `iosxe` and `iosxr`, true only on a rule with no `SVC` relationship |
| `action` | the action of the entry. `deny` for a placeholder rule |

| Relationship | Properties |
|---|---|
| `(FwRule)-[:SRC]->(NetObject)` |  |

### NetObject of `iosxr`

| Property | Content |
|---|---|
| `name` | the name of the object or of the group, or the address of an inline match. For `unifi`, also `group:<group id>`, `network:<network id>`, `gateway:<network id>`, `src side (opaque)` and `dst side (opaque)`. For `nxos`, `iosxe` and `iosxr`, the access list name on a placeholder rule. On an entry side with no address, the reason text, else `src` or `dst` |
| `kind` | the kind of the object |
| `opaque` | true if the collector cannot give the address set of the object |
| `opaque_reason` | the reason as text |
| `opaque_note` | a short form of the reason |
| `kind` | `inline` |

### MtuObservation of `iosxr`

| Property | Content |
|---|---|
| `source` | the source type |
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

## `manual`

### Device of `manual`

| Property | Content |
|---|---|
| `platform` | the platform column |
| `role` | the role column, or `unknown` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `mgmt_ip` | the management address |

| Relationship | Properties |
|---|---|
| `(Device)-[:HAS_IP]->(IpAddress)` |  |

### Port of `manual`

| Relationship | Properties |
|---|---|
| `(Port)-[:HAS_MTU]->(MtuObservation)` |  |

### Interface of `manual`

| Relationship | Properties |
|---|---|
| `(Interface)-[:HAS_MTU]->(MtuObservation)` |  |

### Endpoint of `manual`

| Relationship | Properties |
|---|---|
| `(Endpoint)-[:HAS_MTU]->(MtuObservation)` |  |

### IpAddress of `manual`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |

### Tunnel of `manual`

| Relationship | Properties |
|---|---|
| `(Tunnel)-[:HAS_MTU]->(MtuObservation)` |  |

### DvPortgroup of `manual`

| Relationship | Properties |
|---|---|
| `(DvPortgroup)-[:HAS_MTU]->(MtuObservation)` |  |

### MtuObservation of `manual`

| Property | Content |
|---|---|
| `source` | `manual:` and the source name, or `manual:unnamed` if the source has no name |
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

| Relationship | Properties |
|---|---|
| `(Pnic)-[:HAS_MTU]->(MtuObservation)` |  |
| `(Vnic)-[:HAS_MTU]->(MtuObservation)` |  |
| `(Dvs)-[:HAS_MTU]->(MtuObservation)` |  |

## `nautobot`

### Rack of `nautobot`

| Property | Content |
|---|---|
| `name` | the rack name |

### Device of `nautobot`

| Property | Content |
|---|---|
| `platform` | the platform name in lower case |
| `role` | the role name in lower case, or `unknown` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `identities` | the list of the identity strings of the device |
| `vendor` | the manufacturer name in lower case |
| `model` | the hardware model |
| `mgmt_ip` | the management address |
| `reported_location`, `reported_location_name` | the location that the source reports |
| `hostname_fqdn`, `status`, `asset_tag`, `position`, `location` | fields of the Nautobot device |

| Relationship | Properties |
|---|---|
| `(Device)-[:IN_RACK]->(Rack)` |  |

### Port of `nautobot`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `mac` | the MAC address |
| `description` | the description of the port |
| `media` | the interface type |
| `admin` | `up` or `down` |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `nautobot-cable` |
| `(Port)-[:HAS_MTU]->(MtuObservation)` |  |

### VrfInstance of `nautobot`

| Property | Content |
|---|---|
| `name` | the id of the Nautobot VRF |
| `anchor`, `namespace_id`, `nautobot_vrf_id` | the namespace and the id of the Nautobot VRF |
| `population_source` | `nautobot` |

### IpAddress of `nautobot`

| Property | Content |
|---|---|
| `ip` | the address |
| `nautobot_id`, `vrf_id`, `namespace_id`, `role_id`, `location_id`, `tag_ids` | ids of the Nautobot address |
| `population_source` | `nautobot` |

| Relationship | Properties |
|---|---|
| `(IpAddress)-[:IN_VRF]->(VrfInstance)` |  |

### MtuObservation of `nautobot`

| Property | Content |
|---|---|
| `source` | `nautobot` |
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

## `ndo`

### NdoSchema of `ndo`

| Property | Content |
|---|---|
| `name` | `displayName` of the schema |

| Relationship | Properties |
|---|---|
| `(NdoSchema)-[:HAS]->(NdoTemplate)` |  |

### NdoTemplate of `ndo`

| Property | Content |
|---|---|
| `name` | `displayName` or `name` of the template |
| `tenant` | `tenantName` of the template |

| Relationship | Properties |
|---|---|
| `(NdoTemplate)-[:DEFINES]->(Epg)` |  |
| `(NdoTemplate)-[:DEFINES]->(BridgeDomain)` |  |

## `netscaler`

### Interface of `netscaler`

| Property | Content |
|---|---|
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` |
| `mtu_source`, `operational_mtu_basis` | `NITRO Interface` and `unknown` |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:HAS_MTU]->(MtuObservation)` |  |

### IpAddress of `netscaler`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |
| `ns_role` | `snip` |

### VirtualService of `netscaler`

| Property | Content |
|---|---|
| `name` | `name` of the row |
| `vip` | `ipv46` of the row |
| `port` | `port` of the row as an integer |
| `proto` | `udp` for the service types `UDP` and `DNS`, else `tcp` |
| `kind` | `lb` |
| `snat_mode` | `none`, `snat_from` or `automap` |

| Relationship | Properties |
|---|---|
| `(VirtualService)-[:ON]->(RedundancyGroup)` |  |
| `(VirtualService)-[:ON]->(Device)` |  |
| `(VirtualService)-[:VIP]->(IpAddress)` |  |
| `(VirtualService)-[:SNAT_FROM]->(IpAddress)` |  |
| `(VirtualService)-[:USES]->(Pool)` |  |

### Pool of `netscaler`

| Property | Content |
|---|---|
| `name` | `servicegroupname` of the binding |
| `lb_method` | `lbmethod` of the `lbvserver` row in lower case |

| Relationship | Properties |
|---|---|
| `(Pool)-[:HAS_MEMBER]->(PoolMember)` |  |
| `(Pool)-[:CHECKED_BY]->(Monitor)` |  |

### PoolMember of `netscaler`

| Property | Content |
|---|---|
| `port` | `port` of the row as an integer |
| `weight` | `weight` of the row as an integer |
| `state` | `up` if `svrstate` is `UP`, else `down`. Absent if the service group has no monitor binding |

| Relationship | Properties |
|---|---|
| `(PoolMember)-[:TARGETS]->(IpAddress)` |  |

### Monitor of `netscaler`

| Property | Content |
|---|---|
| `kind` | `type` of the `lbmonitor` row in lower case |
| `target` | the monitor name |

### MtuObservation of `netscaler`

| Property | Content |
|---|---|
| `source` | `netscaler` |
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

## `nxos`

### Device of `nxos`

| Property | Content |
|---|---|
| `platform` | `nxos` |
| `role` | `router` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `identities` | the list of the identity strings of the device |
| `vendor` | `cisco` |
| `os_version` | the software version |

| Relationship | Properties |
|---|---|
| `(Device)-[:MEMBER_OF]->(RedundancyGroup)` | `role`, `peer_link`, `peer_status` |
| `(Device)-[:ENFORCES]->(FwRulebase)` | `installed`, `coverage`, `installed_revision`, `context_uid`, `ingress_interface_uid`, `egress_interface_uid`, `address_family` for an access list, no property for a NAT rulebase and for the `vyos` rulebase `unread VyOS 1.3 firewall` |
| `(Device)-[:HAS_MTU]->(MtuObservation)` |  |

### RedundancyGroup of `nxos`

| Property | Content |
|---|---|
| `kind` | `vpc` |
| `name` | `vpc-domain-<domain>` |
| `domain_id` | the vPC domain id |

### Port of `nxos`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `mac` | the MAC address |
| `kind` | `phys`, `lag` or `mgmt` |
| `speed_mbps`, `duplex`, `speed_source` | the operational speed, `full` or `half`, and `nxos:eth_speed`, `iosxe:show interfaces` or `iosxr:show interfaces`. `speed_mbps` is absent if the device gives no speed number. `duplex` is absent if the device gives no `full` or `half` |
| `bandwidth_kbit` | the bandwidth of the interface |
| `description` | the description of the port |
| `lldp_neighbor_name`, `lldp_neighbor_mac`, `lldp_neighbor_port` | the LLDP neighbor of the port |
| `cdp_neighbor_name`, `cdp_neighbor_port` | the CDP neighbor of the port |
| `cdp_neighbor_serial` | the serial in the device id of the CDP neighbor |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |
| `(Port)-[:CARRIES]->(VlanInstance)` |  |
| `(Port)-[:MEMBER_OF]->(Lag)` | `state`, `source_command`, `assertion_kind`, `eligible` |
| `(Port)-[:HAS_MTU]->(MtuObservation)` |  |

### Interface of `nxos`

| Property | Content |
|---|---|
| `kind` | `phys`, `subif`, `svi`, `loopback`, `lag`, `mgmt` |
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` |
| `mac` | the MAC address |
| `admin_up` | a boolean |
| `description` | the description of the interface |
| `parent_interface_uid` | the uid of the parent interface |
| `parent_source_command` | the command that gives the parent |
| `nat_role` | the NAT role of the interface |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:REALIZED_BY]->(Port)` |  |
| `(Interface)-[:REALIZED_BY]->(Lag)` |  |
| `(Interface)-[:BOUND_TO]->(VlanInstance)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` | `fhrp`, `group`, `state` for a virtual address |
| `(Interface)-[:IN_VRF]->(VrfInstance)` |  |
| `(Interface)-[:MEMBER_OF]->(FhrpGroup)` | `priority`, `state` |
| `(Interface)-[:IN_AREA]->(OspfArea)` | `cost`, `network_type`, `passive` |
| `(Interface)-[:PROTECTED_BY]->(FwRulebase)` | `direction` |
| `(Interface)-[:HAS_MTU]->(MtuObservation)` |  |

### Lag of `nxos`

| Property | Content |
|---|---|
| `name` | the name of the aggregate |

| Relationship | Properties |
|---|---|
| `(Lag)-[:ON]->(Device)` |  |

### VlanInstance of `nxos`

| Property | Content |
|---|---|
| `vid` | the VLAN id. For `unifi`, `vlan` of the network, or 1 for a network with no `vlan` |
| `name` | the VLAN name |

| Relationship | Properties |
|---|---|
| `(VlanInstance)-[:REALIZES]->(BridgeDomain)` |  |

### FhrpGroup of `nxos`

| Property | Content |
|---|---|
| `kind` | the protocol in lower case |
| `group_id` | the group number |
| `vip` | the virtual address |
| `af` | the address family of `vip`, 4 or 6 |
| `virtual_mac` | the virtual MAC address |

| Relationship | Properties |
|---|---|
| `(FhrpGroup)-[:HAS_IP]->(IpAddress)` |  |

### VrfInstance of `nxos`

| Property | Content |
|---|---|
| `name` | the name of the VRF |
| `rd` | the route distinguisher |
| `table_id` | the name of the VRF |
| `is_global` | `true` for the global table |

| Relationship | Properties |
|---|---|
| `(VrfInstance)-[:OWNED_BY]->(Device)` |  |
| `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `declared` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `connected` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `network`, `route_map` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `aggregate`, `summary_only`, `as_set`, `attribute_map`, `unsupported_options` |

### RoutingDomain of `nxos`

| Property | Content |
|---|---|
| `name` | the display name of the domain |

### Prefix of `nxos`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `af` | 4 or 6 |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string |
| `l3dom` | the routing domain |
| `kind` | `connected` |
| `kind` | `bgp-network`, `aggregate` |
| `kind` | `nat-pool` |

### IpAddress of `nxos`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |

| Relationship | Properties |
|---|---|
| `(IpAddress)-[:IN]->(Prefix)` |  |

### RoutingProcess of `nxos`

| Property | Content |
|---|---|
| `proto` | `bgp` |
| `proto` | `ospf` |
| `asn` | the local AS number |
| `router_id` | the router id |
| `process_id` | the OSPF process id. An empty string for `vyos` |
| `always_compare_med` | `true` if configured |
| `multipath_config_recorded`, `multipath_relax`, `maximum_paths_<ebgp or ibgp>_v<4 or 6>` | the result of `src/hst/collectors/util.py` `bgp_multipath_props` |
| `default_information_originate_afs` | the address families of a BGP default origin |
| `default_information_originate` | `true` if the OSPF process holds `default-information originate` |
| `default_information_originate_always` | `true` if that statement holds `always` |
| `redistribute_protocols` | the sorted protocols that the BGP process redistributes. For `nxos` and `iosxr`, without the statements of the IPv6 unicast address family. For `checkpoint_gateway`, the protocols of the `match protocol` terms of the enabled `permit` clauses of an exported route map, with `connected` for `direct` and without `bgp` and `ibgp` |
| `redist_<protocol>_route_map` | the route map of 1 redistribution of a BGP process |
| `redist_<protocol>_route_map` | the route map or the route policy of 1 redistribution of an OSPF process |
| `origin_config_recorded` | a boolean |
| `origin_afs` | `[4, 6]` |
| `origin_context_gaps` | a list of texts |
| `session_gaps` | a list of texts |

| Relationship | Properties |
|---|---|
| `(RoutingProcess)-[:IN_VRF]->(VrfInstance)` |  |
| `(RoutingProcess)-[:HAS]->(BgpSession)` |  |
| `(RoutingProcess)-[:HAS]->(BgpPeerRange)` |  |
| `(RoutingProcess)-[:HAS]->(OspfArea)` |  |
| `(RoutingProcess)-[:HAS]->(OspfAdjacency)` |  |
| `(RoutingProcess)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `redistribute`, `protocol` |

### BgpSession of `nxos`

| Property | Content |
|---|---|
| `peer_ip`, `local_asn`, `peer_asn` | the neighbor address and the 2 AS numbers |
| `state` | `shutdown` for a neighbor that is shut down |
| `afi_safi` | the list of address families |
| `dynamic_range` | the listen range of a dynamic peer |
| `observed_state` | the state of a dynamic peer in the session table of the device. For `nxos`, the `state` text of the device. For `iosxe` and `iosxr`, `Established` for a number in the state column, else the text of the column |
| `import_policy_name`, `import_policy_kind`, `export_policy_name`, `export_policy_kind` | the session policy for each direction |
| `import_prefix_list_name`, `export_prefix_list_name` | a prefix list beside a route map |
| `import_filter_list_name`, `export_filter_list_name` | the AS-path filter list |
| `route_reflector_client`, `cluster_id` | the route reflector settings |
| `peer_router_id` | the router id of the peer |
| `next_hop_self` | the setting of the neighbor |
| `remote_as_route_map` | a field of the parsed neighbor |

| Relationship | Properties |
|---|---|
| `(BgpSession)-[:MEMBER_OF]->(BgpPeerRange)` |  |
| `(BgpSession)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `in`, `out`, `in-prefix-list` or `out-prefix-list` |

### BgpPeerRange of `nxos`

| Property | Content |
|---|---|
| `prefix`, `local_asn` | the neighbor network and the local AS number |

| Relationship | Properties |
|---|---|
| `(BgpPeerRange)-[:FILTERED_BY]->(RoutePolicy)` | `direction` |

### OspfArea of `nxos`

| Property | Content |
|---|---|
| `area_id` | the area id |
| `type` | the area type |

### OspfAdjacency of `nxos`

| Property | Content |
|---|---|
| `state` | the state of the adjacency |
| `area` | the area id |
| `neighbor_router_id`, `neighbor_ip` | the router id and the address of the neighbor |
| `local_interface` | the name of the local interface |

| Relationship | Properties |
|---|---|
| `(OspfAdjacency)-[:ENDPOINT]->(Interface)` |  |

### RoutePolicy of `nxos`

| Property | Content |
|---|---|
| `name` | the name of the policy |
| `kind` | `route-map`, `prefix-list`, `community-list` or `as-path-list` |

| Relationship | Properties |
|---|---|
| `(RoutePolicy)-[:HAS_RULE]->(RoutePolicyEntry)` |  |
| `(RoutePolicy)-[:HAS_RULE]->(PrefixListEntry)` |  |
| `(RoutePolicy)-[:HAS_RULE]->(MatchListEntry)` |  |

### RoutePolicyEntry of `nxos`

| Property | Content |
|---|---|
| `seq` | the sequence number. For `iosxr`, the position of the statement in the route policy, from 1. For a `gaia-clause`, the `id` of the route map clause, and 10 for `default`. For a `gaia-chain-member`, the position of the route map in the chain, from 0 |
| `kind` | `clause` |
| `action` | the action of the entry. For `iosxr`, `permit` for `done` and `deny` for `drop`, else absent. For `checkpoint_gateway`, `permit`, `deny` or `unknown` on a `gaia-clause`, and absent on a `gaia-chain-member` |
| `continues`, `continue_seq` | the continue clause |
| `match_prefix_lists`, `match_as_path_lists`, `match_community_lists` | the lists that the match clauses reference |
| `match_tags`, `match_metric` | values of the match clauses |
| `match_protocols` | values of the match clauses |
| `match_unsupported`, `set_unsupported` | the lines that the parser does not model |
| `match_ignored` | a field of the parsed clause |
| `set_local_pref`, `set_metric`, `set_as_path_prepend`, `set_communities`, `set_communities_additive`, `set_comm_list_delete` | values of the set clauses |
| `set_origin`, `set_tag`, `set_weight`, `set_next_hop` | values of the set clauses |
| `calls_policy` | the name of the called policy |

| Relationship | Properties |
|---|---|
| `(RoutePolicyEntry)-[:REFERENCES]->(RoutePolicy)` | `kind` with the value `prefix-list`, `community-list`, `as-path-list` or `call` |

### PrefixListEntry of `nxos`

| Property | Content |
|---|---|
| `seq`, `action`, `prefix` | the sequence number, the action and the prefix. For `iosxr`, `seq` is the position of the line in the prefix set, from 1, and `action` is `permit` |
| `ge`, `le` | the length bounds of the entry |
| `eq` | the exact length of the entry |
| `min_len`, `max_len` | the lowest and the highest prefix length that the entry matches |

### MatchListEntry of `nxos`

| Property | Content |
|---|---|
| `seq`, `action` | the sequence number and the action. For `iosxr`, `seq` is the position of the element in the set, from 1, and `action` is `permit` |
| `match_type` | the type that `src/hst/simul/matchlist.py` uses to read `value` |
| `value` | the value of the entry |

### FwRulebase of `nxos`

| Property | Content |
|---|---|
| `kind` | `access` on a pair of a family of `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` and a list name with 1 or more interface bindings |
| `match_context` | `interface-acl` on a pair of a family of `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` and a list name with 1 or more interface bindings |
| `kind` | `nat` on the NAT rules of 1 direction |
| `match_context` | absent on the NAT rules of 1 direction |
| `name` | the name of the layer, the ruleset or the access list. The filter of a VyOS chain has `ipv4-<chain>` or `ipv6-<chain>`. The rulebase of `_legacy_firewall` has `unread VyOS 1.3 firewall`. A UniFi zone pair has `<source zone>-<destination zone>`, with ` (IPv6)` after it on the IPv6 rulebase. For `nxos`, `iosxe` and `iosxr`, the family `vlan-map` has the name of the VLAN access map, the family `zone` has the zone name, the family `common` has `<common list> <list>` or the common list alone, and the family `unparsed` has the binding line. A NAT rulebase has `NAT:<package>`, `<tree>-<direction>` or `nat-<direction>` |
| `kind` | `access`, `nat` or `zone` |
| `vendor` | `checkpoint`, `vyos`, `ubiquiti` or `cisco` |
| `match_context` | `device`, `zone-pair` or `interface-acl` |
| `af` | 4 or 6. Absent on a NAT rulebase, on the rulebase of `_legacy_firewall`, on the first rulebase of a UniFi zone pair and on a Cisco list with no address family |
| `default_action` | the action for a flow that no rule matches |
| `configured_revision` | the revision of the configuration that the collector read |
| `unreported_bindings` | a list of `<interface> <direction>` strings for the bindings with no `Interface` node |
| `default_action` | `deny` |
| `configured_revision` | the SHA-256 of the name and the entries of the access list |

| Relationship | Properties |
|---|---|
| `(FwRulebase)-[:HAS_RULE]->(FwRule)` |  |
| `(FwRulebase)-[:HAS_RULE]->(NatRule)` |  |

### FwRule of `nxos`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `action` | the action of the rule |
| `enabled` | false for a rule that the configuration disables. True on each rule of `nxos`, `iosxe` and `iosxr` |
| `src_any` | true if the rule has no source address match |
| `dst_any` | true if the rule has no destination address match |
| `svc_any` | true if the rule has no protocol match and no port match. For `nxos`, `iosxe` and `iosxr`, true only on a rule with no `SVC` relationship |
| `states` | the list of connection states that the rule matches |
| `unmodeled_fields` | a list of the rule fields that the collector does not model |
| `action` | the action of the entry. `deny` for a placeholder rule |

| Relationship | Properties |
|---|---|
| `(FwRule)-[:SRC]->(NetObject)` |  |
| `(FwRule)-[:DST]->(NetObject)` |  |
| `(FwRule)-[:SVC]->(SvcObject)` |  |

### NetObject of `nxos`

| Property | Content |
|---|---|
| `name` | the name of the object or of the group, or the address of an inline match. For `unifi`, also `group:<group id>`, `network:<network id>`, `gateway:<network id>`, `src side (opaque)` and `dst side (opaque)`. For `nxos`, `iosxe` and `iosxr`, the access list name on a placeholder rule. On an entry side with no address, the reason text, else `src` or `dst` |
| `kind` | the kind of the object |
| `opaque` | true if the collector cannot give the address set of the object |
| `opaque_reason` | the reason as text |
| `opaque_note` | a short form of the reason |
| `kind` | `inline` |

| Relationship | Properties |
|---|---|
| `(NetObject)-[:RESOLVES_TO]->(Prefix)` |  |
| `(NetObject)-[:RESOLVES_TO]->(IpAddress)` |  |

### SvcObject of `nxos`

| Property | Content |
|---|---|
| `name` | the name of the Check Point object or of the port group. The service of a rule has `<proto>/<ports>`, with `any` for an absent part and ` src <ports>` after it for a source port. In a VyOS rule with a port group, `<ports>` is the group name. For `nxos` and `iosxe`, an ICMP entry with a type has `icmp <type>`. A UniFi service has `all` for an absent protocol. An opaque UniFi service has `service (opaque)` |
| `proto` | the protocol |
| `ports` | the destination ports |
| `src_port` | the source ports |
| `icmp_type` | the ICMP type of an ICMP entry |
| `opaque` | true if the collector cannot give the match of the service |
| `opaque_reason` | the reason as text |
| `opaque_note` | a short form of the reason |

### NatRule of `nxos`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `kind` | `snat`, `dnat` or `static` |
| `approximate` | true if the collector cannot give the full match of the rule |
| `protocol` | the protocol of the match |
| `src_any` | true if the original source is Any. `nat_stage` writes it only on a rule with a match access list. It is true if a permit entry of the list has `any` on the source side. For the direction `inside-destination`, `nat_stage` reads the destination side |
| `orig_port` | the port of the original match |
| `translation` | the translated address, prefix or range, `masquerade`, or `interface` |
| `translation_port` | the translated port |
| `direction` | the NAT direction of the rule, such as `inside-source` |
| `static` | true for a static translation |
| `overload` | true for a rule with overload |
| `translation_interface` | the interface of the translation |
| `match_acl`, `match_route_map` | the access list and the route map of the match |
| `pool`, `pool_start`, `pool_end` | the name, the first address and the last address of the pool |

| Relationship | Properties |
|---|---|
| `(NatRule)-[:ORIG_SRC]->(Prefix)`, `(NatRule)-[:ORIG_SRC]->(IpAddress)` |  |
| `(NatRule)-[:ORIG_DST]->(Prefix)`, `(NatRule)-[:ORIG_DST]->(IpAddress)` |  |
| `(NatRule)-[:XLATE_SRC]->(Prefix)`, `(NatRule)-[:XLATE_SRC]->(IpAddress)` |  |
| `(NatRule)-[:XLATE_DST]->(Prefix)`, `(NatRule)-[:XLATE_DST]->(IpAddress)` |  |

### MtuObservation of `nxos`

| Property | Content |
|---|---|
| `source` | the source type |
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

## `unifi`

### Device of `unifi`

| Property | Content |
|---|---|
| `platform` | `unifi-<type>` |
| `role` | `switch`, `ap` or `gateway` from `src/hst/collectors/unifi.py` `ROLE`, or the device type, or `unknown` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `identities` | the list of the identity strings of the device |
| `vendor` | `ubiquiti` |
| `os_version` | the software version |
| `model` | the hardware model |
| `mgmt_ip` | the management address |
| `reported_location`, `reported_location_name` | the location that the source reports |
| `mac` | the MAC address of the device |

| Relationship | Properties |
|---|---|
| `(Device)-[:MEMBER_OF]->(RedundancyGroup)` |  |
| `(Device)-[:ENFORCES]->(FwRulebase)` | `approximate`, `installed`, `coverage`, `installed_revision`, `context_uid`, `address_family`, `ingress_interface_uid`, `egress_interface_uid` |
| `(Device)-[:HAS_MTU]->(MtuObservation)` |  |

### RedundancyGroup of `unifi`

| Property | Content |
|---|---|
| `kind` | `unifi-ha` |
| `name` | `gateway HA` |

| Relationship | Properties |
|---|---|
| `(RedundancyGroup)-[:ENFORCES]->(FwRulebase)` | the properties of the `unifi` row of `Device` |

### Port of `unifi`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `speed_mbps`, `duplex`, `speed_source` | the operational speed, the duplex and the field that gives them |
| `lldp_neighbor_mac`, `lldp_neighbor_port` | the LLDP neighbor of the port |
| `oper` | `up` or `down` |
| `poe` | `port_poe` of the port |
| `last_conn_mac` | the MAC address of the last connection, if `connected` of the last connection is true |
| `uplink_mac`, `uplink_remote_port` | the uplink neighbor of the device |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |
| `(Port)-[:CARRIES]->(VlanInstance)` | `native` |
| `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `unifi` |
| `(Port)-[:HAS_MTU]->(MtuObservation)` |  |

### Interface of `unifi`

| Property | Content |
|---|---|
| `kind` | `svi` |
| `name` | the network name, or `br<VLAN id>` for a network with no name |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` |  |
| `(Interface)-[:IN_VRF]->(VrfInstance)` |  |
| `(Interface)-[:PROTECTED_BY]->(FwRulebase)` | `direction` |

### VlanInstance of `unifi`

| Property | Content |
|---|---|
| `vid` | the VLAN id. For `unifi`, `vlan` of the network, or 1 for a network with no `vlan` |
| `name` | the VLAN name |

| Relationship | Properties |
|---|---|
| `(VlanInstance)-[:REALIZES]->(BridgeDomain)` |  |

### BridgeDomain of `unifi`

| Property | Content |
|---|---|
| `name` | the network name |
| `security_class` | `guest` for a guest network |

### Endpoint of `unifi`

| Property | Content |
|---|---|
| `mac` | the MAC address |
| `name` | the name of the endpoint |
| `kind` | `client` |
| `wired` | a boolean |
| `oui` | the vendor of the MAC OUI |
| `last_seen` | `last_seen` of the client in milliseconds |

| Relationship | Properties |
|---|---|
| `(Endpoint)-[:IN]->(BridgeDomain)` |  |
| `(Endpoint)-[:HAS_IP]->(IpAddress)` |  |
| `(Endpoint)-[:ATTACHED]->(Port)` |  |
| `(Endpoint)-[:ATTACHED]->(Device)` | `ssid` |

### Ssid of `unifi`

| Property | Content |
|---|---|
| `name` | the WLAN name |
| `security` | `security` of the WLAN |
| `enabled` | `enabled` of the WLAN, with the default `true` |

| Relationship | Properties |
|---|---|
| `(Ssid)-[:BRIDGED_TO]->(VlanInstance)` |  |

### VrfInstance of `unifi`

| Property | Content |
|---|---|
| `name` | the name of the VRF |
| `table_id` | the name of the VRF |
| `is_global` | `true` for the global table |

| Relationship | Properties |
|---|---|
| `(VrfInstance)-[:OWNED_BY]->(Device)` |  |
| `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `declared` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `connected` |

### RoutingDomain of `unifi`

| Property | Content |
|---|---|
| `name` | the display name of the domain |

### Prefix of `unifi`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `af` | 4 or 6 |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string |
| `l3dom` | the routing domain |
| `kind` | `connected` |
| `name`, `security_class` | the network name, and `guest` for a guest network |

### IpAddress of `unifi`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |

| Relationship | Properties |
|---|---|
| `(IpAddress)-[:IN]->(Prefix)` |  |

### FwRulebase of `unifi`

| Property | Content |
|---|---|
| `kind` | `zone` on a pair of a source zone and a destination zone |
| `match_context` | `zone-pair` on a pair of a source zone and a destination zone |
| `kind` | `access` on a classic ruleset of `LAN`, `WAN` or `GUEST` with the direction `IN` or `OUT` |
| `match_context` | `interface-acl` on a classic ruleset of `LAN`, `WAN` or `GUEST` with the direction `IN` or `OUT` |
| `kind` | `access` on each other classic ruleset |
| `match_context` | `device` on each other classic ruleset |
| `name` | the name of the layer, the ruleset or the access list. The filter of a VyOS chain has `ipv4-<chain>` or `ipv6-<chain>`. The rulebase of `_legacy_firewall` has `unread VyOS 1.3 firewall`. A UniFi zone pair has `<source zone>-<destination zone>`, with ` (IPv6)` after it on the IPv6 rulebase. For `nxos`, `iosxe` and `iosxr`, the family `vlan-map` has the name of the VLAN access map, the family `zone` has the zone name, the family `common` has `<common list> <list>` or the common list alone, and the family `unparsed` has the binding line. A NAT rulebase has `NAT:<package>`, `<tree>-<direction>` or `nat-<direction>` |
| `kind` | `access`, `nat` or `zone` |
| `vendor` | `checkpoint`, `vyos`, `ubiquiti` or `cisco` |
| `match_context` | `device`, `zone-pair` or `interface-acl` |
| `af` | 4 or 6. Absent on a NAT rulebase, on the rulebase of `_legacy_firewall`, on the first rulebase of a UniFi zone pair and on a Cisco list with no address family |
| `chain` | `forward`, `input` or `output` |
| `default_action` | the action for a flow that no rule matches |
| `default_action_unknown` | true if the rulebase has no `default_action` |
| `configured_revision` | the revision of the configuration that the collector read |
| `installed` | true |
| `coverage` | `complete` |
| `installed_revision` | the value of `configured_revision` |
| `established_default_unknown` | true |
| `unreported_bindings` | a list of `<interface> <direction>` strings for the bindings with no `Interface` node |
| `default_action` | `accept` for a classic ruleset of `src/hst/collectors/unifi.py` `_CLASSIC_DEFAULTS` |
| `configured_revision` | the result of `src/hst/collectors/unifi.py` `_firewall_revision` |

| Relationship | Properties |
|---|---|
| `(FwRulebase)-[:HAS_RULE]->(FwRule)` |  |
| `(FwRulebase)-[:FROM_ZONE]->(Zone)` |  |
| `(FwRulebase)-[:TO_ZONE]->(Zone)` |  |

### FwRule of `unifi`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `action` | the action of the rule |
| `enabled` | false for a rule that the configuration disables. True on each rule of `nxos`, `iosxe` and `iosxr` |
| `name` | the name or the description of the rule |
| `rule_uid` | `uid` of the Check Point rule. `_id` of the UniFi rule. For `vyos`, `<ruleset name>:<rule number>` on a rule of `_firewall`, `pbr:<policy name>:<rule number>` or `pbr:ipv6:<policy name>:<rule number>` on a rule of `_pbr`, and `pbr:unread-legacy:<interface name>:1` on the rule of `_legacy_policy_route`. `_legacy_policy_route` writes the rule for each interface that has an `Interface` node and holds a `policy` node in the configuration |
| `src_any` | true if the rule has no source address match |
| `dst_any` | true if the rule has no destination address match |
| `svc_any` | true if the rule has no protocol match and no port match. For `nxos`, `iosxe` and `iosxr`, true only on a rule with no `SVC` relationship |
| `src_negate` | true if the rule negates the source side |
| `dst_negate` | true if the rule negates the destination side |
| `states` | the list of connection states that the rule matches |
| `states_opaque` | true if the rule holds a match that the collector does not model |
| `states_opaque_reason` | the text of that match |
| `unmodeled_fields` | a list of the rule fields that the collector does not model |
| `action` | `accept`, `drop` or `reject` for the policy actions `ALLOW`, `BLOCK` and `REJECT`. The classic `action` in lower case |

| Relationship | Properties |
|---|---|
| `(FwRule)-[:SRC]->(NetObject)` |  |
| `(FwRule)-[:DST]->(NetObject)` |  |
| `(FwRule)-[:SVC]->(SvcObject)` |  |

### NetObject of `unifi`

| Property | Content |
|---|---|
| `name` | the name of the object or of the group, or the address of an inline match. For `unifi`, also `group:<group id>`, `network:<network id>`, `gateway:<network id>`, `src side (opaque)` and `dst side (opaque)`. For `nxos`, `iosxe` and `iosxr`, the access list name on a placeholder rule. On an entry side with no address, the reason text, else `src` or `dst` |
| `kind` | the kind of the object |
| `opaque` | true if the collector cannot give the address set of the object |
| `opaque_reason` | the reason as text |
| `kind` | `group`, `host`, `cidr`, `network` or `opaque` |

| Relationship | Properties |
|---|---|
| `(NetObject)-[:RESOLVES_TO]->(Prefix)` |  |
| `(NetObject)-[:RESOLVES_TO]->(IpAddress)` |  |

### SvcObject of `unifi`

| Property | Content |
|---|---|
| `name` | the name of the Check Point object or of the port group. The service of a rule has `<proto>/<ports>`, with `any` for an absent part and ` src <ports>` after it for a source port. In a VyOS rule with a port group, `<ports>` is the group name. For `nxos` and `iosxe`, an ICMP entry with a type has `icmp <type>`. A UniFi service has `all` for an absent protocol. An opaque UniFi service has `service (opaque)` |
| `kind` | `type` of the Check Point API object, or `group` for a port group |
| `proto` | the protocol |
| `ports` | the destination ports |
| `src_port` | the source ports |
| `opaque` | true if the collector cannot give the match of the service |
| `opaque_reason` | the reason as text |

### Zone of `unifi`

| Property | Content |
|---|---|
| `name` | the name of the zone |
| `default_action_unknown` | true if the zone has no `default_action`. True on each UniFi zone |
| `configured_revision` | the value of the same property of the rulebases |
| `installed` | true |
| `coverage` | `complete` |
| `installed_revision` | the value of `configured_revision` |
| `established_default_unknown` | true |

| Relationship | Properties |
|---|---|
| `(Zone)-[:CONTAINS]->(Interface)` |  |

### MtuObservation of `unifi`

| Property | Content |
|---|---|
| `source` | `unifi` |
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

## `velocloud`

### Device of `velocloud`

| Property | Content |
|---|---|
| `platform` | `velocloud-edge` |
| `role` | `sdwan-hub` for an edge in the hub set, or `sdwan-edge` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `vendor` | `VeloCloud` |
| `model` | the hardware model |
| `reported_location`, `reported_location_name` | the location that the source reports |
| `software_version`, `edge_state`, `edge_logical_id` | fields of the edge row |
| `enterprise_logical_id`, `enterprise_name` | the enterprise of the edge |
| `site_city`, `site_country`, `site_lat`, `site_lon` | fields of the site of the edge |
| `sdwan_role` | `hub` for an edge in the hub set |
| `configuration_observed_at_ms` | the time of the configuration read |
| `ha_type`, `ha_state`, `ha_standby_serial`, `hub_cluster_id`, `hub_cluster_name` | the result of `src/hst/collectors/velocloud.py` `_ha_props` |

| Relationship | Properties |
|---|---|
| `(Device)-[:HAS_LINK]->(WanLink)` |  |
| `(Device)-[:HAS_BOUNDARY]->(ForwardingBoundary)` |  |
| `(Device)-[:ENFORCES]->(SdwanBusinessPolicy)` |  |

### Port of `velocloud`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |

### Provider of `velocloud`

| Property | Content |
|---|---|
| `name` | `provider_name` of the source configuration |

### ProviderNetwork of `velocloud`

| Property | Content |
|---|---|
| `name` | the carrier of the WAN link |
| `kind` | the value of `src/hst/collectors/velocloud.py` `_PROVIDER_KIND` for the kind of the WAN link |

| Relationship | Properties |
|---|---|
| `(ProviderNetwork)-[:PROVIDED_BY]->(Provider)` |  |

### Interface of `velocloud`

| Property | Content |
|---|---|
| `kind` | `phys`, `subif`, `loopback`, `vlan-if` |
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` |
| `vlan`, `subinterface_id` | the VLAN id and the id of a subinterface |
| `wan_overlay`, `next_hop` | `true` and the gateway address for a WAN interface |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:REALIZED_BY]->(Port)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` |  |
| `(Interface)-[:IN_VRF]->(VrfInstance)` |  |

### VrfInstance of `velocloud`

| Property | Content |
|---|---|
| `name` | the name of the VRF |
| `table_id` | the segment id: `logicalId` of the segment, else `segmentId`, else the segment name. `global` if no edge of the enterprise has a segment in `deviceSettings`. `Global Segment` on the VRF that the collector adds for an edge with no global segment |
| `is_global` | `true` for the global table |

| Relationship | Properties |
|---|---|
| `(VrfInstance)-[:OWNED_BY]->(Device)` |  |
| `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `declared` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `connected` |

### RoutingDomain of `velocloud`

| Property | Content |
|---|---|
| `name` | the display name of the domain |

### Prefix of `velocloud`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `af` | 4 or 6 |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string |
| `l3dom` | the routing domain |
| `kind` | `connected` |

### IpAddress of `velocloud`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |

| Relationship | Properties |
|---|---|
| `(IpAddress)-[:IN]->(Prefix)` |  |

### RoutingProcess of `velocloud`

| Property | Content |
|---|---|
| `proto` | `bgp` |
| `asn` | the local AS number |
| `router_id` | the router id |
| `origin_config_recorded` | a boolean |
| `origin_role`, `preference_buckets`, `advertise_external`, `advertise_inter_area`, `advertise_intra_area`, `advertise_internal`, `advertise_static`, `advertise_connected` | the result of `src/hst/collectors/velocloud.py` `_origin_controls` |

| Relationship | Properties |
|---|---|
| `(RoutingProcess)-[:IN_VRF]->(VrfInstance)` |  |
| `(RoutingProcess)-[:HAS]->(BgpSession)` |  |

### BgpSession of `velocloud`

| Property | Content |
|---|---|
| `peer_ip`, `local_asn`, `peer_asn` | the neighbor address and the 2 AS numbers |
| `local_ip`, `description` | `localIp` and `neighborTag` of the neighbor |

| Relationship | Properties |
|---|---|
| `(BgpSession)-[:ENDPOINT]->(IpAddress)` |  |

### Tunnel of `velocloud`

| Property | Content |
|---|---|
| `encap` | `velocloud-vcmp` |
| `name` | `<WAN link> to <far end>` |
| `endpoint` | the address of the far end |
| `local_address` | the address of the local end |
| `carrier_proto` | the protocol of the outer packet |
| `endpoint_port` | the port of the far end |
| `pair`, `peer_type`, `direction_observed`, `origin_config_recorded` | the result of `src/hst/core/uid.py` `tunnel` for the 2 ends, `gateway`, `hub` or `edge`, `false`, `true` |
| `configuration_observed_at_ms`, `configuration_stale` | the time and the state of the configuration read |

| Relationship | Properties |
|---|---|
| `(Tunnel)-[:ENDPOINT]->(Interface)` |  |
| `(Tunnel)-[:TERMINATES_ON]->(SdwanGateway)` |  |
| `(Tunnel)-[:TERMINATES_ON]->(IpAddress)` |  |
| `(Tunnel)-[:CARRIES]->(SdwanSegment)` |  |

### OverlayConnection of `velocloud`

| Property | Content |
|---|---|
| `kind` | `tunnel` |
| `technology` | the `encap` of the tunnels |
| `name` | a text with the 2 ends |
| `observed_from` | the list of the end letters `a` and `b` that a batch reported |

| Relationship | Properties |
|---|---|
| `(OverlayConnection)-[:BETWEEN]->(Device)` | `end`, `role`, `reported` |
| `(OverlayConnection)-[:BETWEEN]->(SdwanGateway)` | `end`, `role`, `reported` |
| `(OverlayConnection)-[:REALIZED_BY]->(Tunnel)` |  |

### SdwanSegment of `velocloud`

| Property | Content |
|---|---|
| `segment_id`, `name` | the id and the name of the segment. `name` is `segment-<segment id>` for a segment with no name |
| `enterprise_logical_id`, `enterprise_name` | the enterprise of the segment |

### ForwardingBoundary of `velocloud`

| Property | Content |
|---|---|
| `edge_logical_id`, `segment_id` | the edge and the segment of the boundary |
| `api_profile`, `orchestrator_release` | fields of the payload |
| `candidate_set_complete` | `false` |
| `selector` | `dynamic-steering` |
| `unsupported_reason` | `VeloCloud dynamic path selection is opaque` |
| `gaps` | a list of texts |

| Relationship | Properties |
|---|---|
| `(ForwardingBoundary)-[:IN]->(SdwanSegment)` |  |
| `(ForwardingBoundary)-[:HAS_ROUTE]->(SdwanStaticRoute)` |  |

### WanLink of `velocloud`

| Property | Content |
|---|---|
| `name` | the name of the link. For `velocloud`, `name` of the WAN configuration row, else `displayName` of the link row, else the interface, else the logical id of the link |
| `kind` | `mpls`, `dia` or `lte` |
| `carrier`, `public_ip`, `interface`, `link_logical_id` | the carrier, the address, the interface and the id of the link. `carrier` is `isp` or `org` of the link row, else `isp` of the WAN configuration row, else the private network of an `mpls` link, else `mpls` or `unknown` |
| `state`, `link_mode`, `vpn_state`, `backup_state` | `state`, `linkMode`, `vpnState` and `backupState` of the link row |
| `wan_mode`, `access_type`, `upstream_mbps`, `downstream_mbps`, `mtu`, `next_hop`, `backup_only`, `hot_standby` | fields of the WAN configuration row |
| `private_network` | the private network of the link |
| `configuration` | the WAN configuration row as JSON |
| `configuration_observed_at_ms`, `configuration_stale` | the time and the state of the configuration read |
| `origin_config_recorded` | a boolean |
| `candidate_set_complete` | `false` |

| Relationship | Properties |
|---|---|
| `(WanLink)-[:ON]->(Interface)` |  |
| `(WanLink)-[:HAS_IP]->(IpAddress)` |  |
| `(WanLink)-[:PROVIDED_BY]->(ProviderNetwork)` |  |

### SdwanGateway of `velocloud`

| Property | Content |
|---|---|
| `name`, `ip` | the name and the address of the gateway |
| `roles` | `roles` of the gateway row as JSON |

### SdwanBusinessPolicy of `velocloud`

| Property | Content |
|---|---|
| `name` | `<edge name> effective business policy` |
| `precedence` | `edge-effective` |
| `capability_gap` | JSON with `status`, `operation` and `reason` if no QOS profile body exists |
| `observed_at_ms` | the time of the configuration read |
| `rule_count` | the result of `src/hst/collectors/velocloud.py` `_policy_rules` |

| Relationship | Properties |
|---|---|
| `(SdwanBusinessPolicy)-[:HAS_RULE]->(SdwanPolicyRule)` | `position` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(WanLink)` | `application_class`, `preference` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(WanLink)` | `application_class`, `route_type`, `segment_id`, `route_policy` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(Tunnel)` | `application_class`, `route_type`, `segment_id`, `route_policy` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(Tunnel)` | `application_class`, `route_type`, `route_policy` with the value `backhaul` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(Device)` | `application_class`, `route_type`, `segment_id`, `route_policy` |
| `(SdwanBusinessPolicy)-[:STEERS_VIA]->(ForwardingBoundary)` |  |

### SdwanPolicyRule of `velocloud`

| Property | Content |
|---|---|
| `name`, `rule_logical_id`, `position`, `default`, `override` | the identity and the position of the rule |
| `segment_id`, `segment_name` | the segment of the rule |
| `match_app_id`, `match_app_class_id`, `match_dscp`, `match_proto`, `match_src`, `match_dst`, `match_src_port`, `match_dst_port`, `match_hostname`, `match_src_interface`, `match_dst_interface`, `match_src_vlan`, `match_dst_vlan`, `match_ip_version`, `match_summary` | the result of `src/hst/collectors/velocloud.py` `_rule_match` |
| `match_unmapped` | the result of `src/hst/collectors/velocloud.py` `_unmapped_match` |
| `qos_class`, `priority_tx`, `priority_rx`, `bandwidth_cap_pct_tx`, `bandwidth_cap_pct_rx`, `route_type`, `sla_latency_ms`, `sla_jitter_ms`, `sla_loss_pct`, `nat_source`, `nat_dest` | the result of `src/hst/collectors/velocloud.py` `_rule_action` |
| `<prefix>_route_policy`, `<prefix>_link_policy`, `<prefix>_wanlink`, `<prefix>_outer_dscp`, `<prefix>_backhaul_hubs` | the route action of the rule for each `<prefix>` of `edge2edge`, `edge2datacenter` and `edge2cloud` |

| Relationship | Properties |
|---|---|
| `(SdwanPolicyRule)-[:IN]->(SdwanSegment)` |  |

### SdwanStaticRoute of `velocloud`

| Property | Content |
|---|---|
| `cidr`, `next_hop`, `interface` | the prefix, the gateway and the interface of the route |
| `cost`, `preferred`, `advertise`, `description` | fields of the route row |
| `segment_id` | the segment of the route |

## `vyos`

### Device of `vyos`

| Property | Content |
|---|---|
| `platform` | `vyos` |
| `role` | `router` |
| `hostname` | the host name. For `unifi`, the device name in lower case. For `velocloud`, the edge name, else the logical id of the edge |
| `serial` | the chassis serial. For `unifi`, the MAC address of a device with no serial or a placeholder serial. For `velocloud`, the logical id of an edge with no serial or a placeholder serial |
| `identities` | the list of the identity strings of the device |
| `vendor` | `vyos` |
| `os_version` | the software version |

| Relationship | Properties |
|---|---|
| `(Device)-[:HAS_LINK]->(WanLink)` |  |
| `(Device)-[:ENFORCES]->(PbrPolicy)` |  |
| `(Device)-[:ENFORCES]->(FwRulebase)` | `installed`, `coverage`, `installed_revision`, `context_uid`, `ingress_interface_uid`, `egress_interface_uid`, `address_family` for an access list, no property for a NAT rulebase and for the `vyos` rulebase `unread VyOS 1.3 firewall` |

### Port of `vyos`

| Property | Content |
|---|---|
| `name` | the port name. For `unifi`, `Port <port index>` for a port with no name, and `eth0` for the port that the collector adds to an AP with no port table |
| `mac` | the MAC address |
| `speed_mbps`, `duplex`, `speed_source` | the operational speed, the duplex and the field that gives them |
| `speed_configured_mbps`, `duplex_configured` | the configured speed and duplex |

| Relationship | Properties |
|---|---|
| `(Port)-[:ON]->(Device)` |  |
| `(Port)-[:CARRIES]->(VlanInstance)` | `native` |
| `(Port)-[:MEMBER_OF]->(Lag)` | `state`, `assertion_kind` |
| `(Port)-[:HAS_MTU]->(MtuObservation)` |  |

### Interface of `vyos`

| Property | Content |
|---|---|
| `kind` | the value of `src/hst/collectors/vyos.py` `_IF_KIND` for the interface type, or the interface type, and `subif` for a `vif`, a `vif-s` or a `vif-c` |
| `name` | the interface name. For `velocloud`, a subinterface has `<parent>:<subinterface id>`, and a LAN network with no name has `vlan<VLAN id>` |
| `mac` | the MAC address |
| `description` | the description of the interface |
| `ipv4_default_origin` | `pppoe` or `dhcp` |
| `ipv6_link_local` | the sorted link-local addresses |

| Relationship | Properties |
|---|---|
| `(Interface)-[:ON]->(Device)` |  |
| `(Interface)-[:REALIZED_BY]->(Port)` |  |
| `(Interface)-[:REALIZED_BY]->(Lag)` |  |
| `(Interface)-[:BOUND_TO]->(VlanInstance)` |  |
| `(Interface)-[:HAS_IP]->(IpAddress)` |  |
| `(Interface)-[:IN_VRF]->(VrfInstance)` |  |
| `(Interface)-[:IN_AREA]->(OspfArea)` | `cost`, `network_type`, `passive` |
| `(Interface)-[:ENFORCES]->(PbrPolicy)` |  |
| `(Interface)-[:HAS_MTU]->(MtuObservation)` |  |

### Lag of `vyos`

| Property | Content |
|---|---|
| `name` | the name of the aggregate |
| `mode` | `mode` of the bond |

| Relationship | Properties |
|---|---|
| `(Lag)-[:ON]->(Device)` |  |

### VlanInstance of `vyos`

| Property | Content |
|---|---|
| `vid` | the VLAN id. For `unifi`, `vlan` of the network, or 1 for a network with no `vlan` |

| Relationship | Properties |
|---|---|
| `(VlanInstance)-[:REALIZES]->(BridgeDomain)` |  |

### VrfInstance of `vyos`

| Property | Content |
|---|---|
| `name` | the name of the VRF |
| `name` | `table<table number>` for a numbered routing table |
| `table_id` | the name of the VRF |
| `is_global` | `true` for the global table |
| `table` | `table` of the VRF in the configuration |
| `kind` | `policy-table` for a numbered routing table |
| `rib_mirrored` | `true` if `src/hst/collectors/vyos.py` `_route_stage` finds that the graph holds the whole RIB of the table, else `false` |

| Relationship | Properties |
|---|---|
| `(VrfInstance)-[:OWNED_BY]->(Device)` |  |
| `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `declared` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `connected` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `network` |
| `(VrfInstance)-[:ORIGINATES]->(Prefix)` | `proto` with the value `aggregate` |
| `(VrfInstance)-[:STATIC_ROUTE]->(Prefix)` | 1 of `next_hop`, `interface` and `discard` as the key, `distance`, `next_hop_vrf`, `rib_interface`, `via_dhcp`, `rib_confirmed` |
| `(VrfInstance)-[:LEARNED_ROUTE]->(Prefix)` | `via`, `next_hop`, `interface`, `protocol`, `metric`, `discard` |
| `(VrfInstance)-[:LEARNED_ROUTE]->(Prefix)` | `next_hop_vrf` |

### RoutingDomain of `vyos`

| Property | Content |
|---|---|
| `name` | the display name of the domain |

### Prefix of `vyos`

| Property | Content |
|---|---|
| `cidr` | the network in CIDR form |
| `af` | 4 or 6 |
| `anchor` | the value that the `uid` uses as scope: a `VrfInstance` uid or a domain string |
| `l3dom` | the routing domain |
| `kind` | `connected` |
| `kind` | `bgp-network`, `aggregate` |
| `dhcp` | `true` |

| Relationship | Properties |
|---|---|
| `(Prefix)-[:VIA]->(Interface)` | `vrf` |

### IpAddress of `vyos`

| Property | Content |
|---|---|
| `ip` | the address |
| `l3dom` | the routing domain. For `velocloud`, absent on an address that only `src/hst/collectors/velocloud.py` `_wan_links` writes |
| `origin` | `configured` for an address of the configuration, `dynamic` for an address of `ip -j addr show`, on an interface address only |

| Relationship | Properties |
|---|---|
| `(IpAddress)-[:IN]->(Prefix)` |  |

### RoutingProcess of `vyos`

| Property | Content |
|---|---|
| `proto` | `bgp` |
| `proto` | `ospf` |
| `asn` | the local AS number |
| `router_id` | the router id |
| `process_id` | the OSPF process id. An empty string for `vyos` |
| `always_compare_med` | `true` if configured |
| `multipath_config_recorded`, `multipath_relax`, `maximum_paths_<ebgp or ibgp>_v<4 or 6>` | the result of `src/hst/collectors/util.py` `bgp_multipath_props` |
| `default_information_originate` | `true` if the OSPF process holds `default-information originate` |
| `default_information_originate_always` | `true` if that statement holds `always` |
| `redistribute_protocols` | the sorted protocols that the BGP process redistributes. For `nxos` and `iosxr`, without the statements of the IPv6 unicast address family. For `checkpoint_gateway`, the protocols of the `match protocol` terms of the enabled `permit` clauses of an exported route map, with `connected` for `direct` and without `bgp` and `ibgp` |
| `redist_<protocol>_route_map` | the route map or the route policy of 1 redistribution of an OSPF process |
| `origin_config_recorded` | a boolean |
| `origin_afs` | `[4, 6]` |
| `session_gaps` | a list of texts |
| `ebgp_requires_policy`, `network_import_check` | `true` if `parameters` of the BGP process holds `ebgp-requires-policy`, and `true` if it holds `network-import-check`, else `false` |

| Relationship | Properties |
|---|---|
| `(RoutingProcess)-[:IN_VRF]->(VrfInstance)` |  |
| `(RoutingProcess)-[:HAS]->(BgpSession)` |  |
| `(RoutingProcess)-[:HAS]->(BgpPeerRange)` |  |
| `(RoutingProcess)-[:HAS]->(OspfArea)` |  |
| `(RoutingProcess)-[:HAS]->(OspfAdjacency)` |  |

### BgpSession of `vyos`

| Property | Content |
|---|---|
| `peer_ip`, `local_asn`, `peer_asn` | the neighbor address and the 2 AS numbers |
| `afi_safi` | the list of address families |
| `dynamic_range` | the listen range of a dynamic peer |
| `import_policy_name`, `import_policy_kind`, `export_policy_name`, `export_policy_kind` | the session policy for each direction |
| `import_prefix_list_name`, `export_prefix_list_name` | a prefix list beside a route map |
| `import_filter_list_name`, `export_filter_list_name` | the AS-path filter list |
| `route_reflector_client`, `cluster_id` | the route reflector settings |
| `peer_router_id` | the router id of the peer |
| `next_hop_self` | the setting of the neighbor |
| `peer_group` | the peer group of the neighbor |

| Relationship | Properties |
|---|---|
| `(BgpSession)-[:MEMBER_OF]->(BgpPeerRange)` |  |
| `(BgpSession)-[:ENDPOINT]->(IpAddress)` |  |
| `(BgpSession)-[:FILTERED_BY]->(RoutePolicy)` | `direction` with the value `in`, `out`, `in-prefix-list` or `out-prefix-list` |

### BgpPeerRange of `vyos`

| Property | Content |
|---|---|
| `prefix`, `local_asn` | the neighbor network and the local AS number |
| `peer_group` | the peer group of the range |

### OspfArea of `vyos`

| Property | Content |
|---|---|
| `area_id` | the area id |
| `type` | the area type |

### OspfAdjacency of `vyos`

| Property | Content |
|---|---|
| `state` | the state of the adjacency |
| `area` | the area id |
| `neighbor_router_id`, `neighbor_ip` | the router id and the address of the neighbor |
| `local_interface` | the name of the local interface |

| Relationship | Properties |
|---|---|
| `(OspfAdjacency)-[:ENDPOINT]->(Interface)` |  |

### RoutePolicy of `vyos`

| Property | Content |
|---|---|
| `name` | the name of the policy |
| `kind` | `route-map`, `prefix-list`, `community-list` or `as-path-list` |

| Relationship | Properties |
|---|---|
| `(RoutePolicy)-[:HAS_RULE]->(RoutePolicyEntry)` |  |
| `(RoutePolicy)-[:HAS_RULE]->(PrefixListEntry)` |  |
| `(RoutePolicy)-[:HAS_RULE]->(MatchListEntry)` |  |

### RoutePolicyEntry of `vyos`

| Property | Content |
|---|---|
| `seq` | the sequence number. For `iosxr`, the position of the statement in the route policy, from 1. For a `gaia-clause`, the `id` of the route map clause, and 10 for `default`. For a `gaia-chain-member`, the position of the route map in the chain, from 0 |
| `kind` | `clause` |
| `action` | the action of the entry. For `iosxr`, `permit` for `done` and `deny` for `drop`, else absent. For `checkpoint_gateway`, `permit`, `deny` or `unknown` on a `gaia-clause`, and absent on a `gaia-chain-member` |
| `continues`, `continue_seq` | the continue clause |
| `match_prefix_lists`, `match_as_path_lists`, `match_community_lists` | the lists that the match clauses reference |
| `match_tags`, `match_metric` | values of the match clauses |
| `match_unsupported`, `set_unsupported` | the lines that the parser does not model |
| `set_local_pref`, `set_metric`, `set_as_path_prepend`, `set_communities`, `set_communities_additive`, `set_comm_list_delete` | values of the set clauses |
| `calls_policy` | the name of the called policy |

| Relationship | Properties |
|---|---|
| `(RoutePolicyEntry)-[:REFERENCES]->(RoutePolicy)` | `kind` with the value `prefix-list`, `community-list`, `as-path-list` or `call` |

### PrefixListEntry of `vyos`

| Property | Content |
|---|---|
| `seq`, `action`, `prefix` | the sequence number, the action and the prefix. For `iosxr`, `seq` is the position of the line in the prefix set, from 1, and `action` is `permit` |
| `ge`, `le` | the length bounds of the entry |
| `min_len`, `max_len` | the lowest and the highest prefix length that the entry matches |

### MatchListEntry of `vyos`

| Property | Content |
|---|---|
| `seq`, `action` | the sequence number and the action. For `iosxr`, `seq` is the position of the element in the set, from 1, and `action` is `permit` |
| `match_type` | the type that `src/hst/simul/matchlist.py` uses to read `value` |
| `value` | the value of the entry |

### Tunnel of `vyos`

| Property | Content |
|---|---|
| `encap` | `wireguard`, `vxlan`, `ipsec` for a `vti` interface, or `encapsulation` of a `tunnel` interface |
| `name` | the name of the WireGuard peer |
| `endpoint` | the address of the far end |
| `local_address` | the address of the local end |
| `carrier_proto` | the protocol of the outer packet |
| `endpoint_port` | the port of the far end |
| `local_address_source` | `configured`, `derived:egress` for a WireGuard tunnel, or `derived:source-interface` |
| `allowed_ips`, `tunnel_mtu` | `allowed-ips` of the WireGuard peer, and the MTU of the WireGuard interface in `ip -j link`, else its configured `mtu` |
| `gre_key`, `gre_checksum`, `gre_sequence` | `true` if the `gre` or `gre-bridge` tunnel holds `parameters ip key`, `false` and `false` |
| `esp_encryption`, `esp_hash`, `esp_mode`, `esp_proposals` | fields of the ESP group of a `vti` tunnel |

| Relationship | Properties |
|---|---|
| `(Tunnel)-[:ENDPOINT]->(Interface)` |  |

### OverlayConnection of `vyos`

| Property | Content |
|---|---|
| `kind` | `tunnel` |
| `technology` | the `encap` of the tunnels |
| `name` | a text with the 2 ends |
| `observed_from` | the list of the end letters `a` and `b` that a batch reported |

| Relationship | Properties |
|---|---|
| `(OverlayConnection)-[:BETWEEN]->(Device)` | `end`, `role`, `reported` |
| `(OverlayConnection)-[:BETWEEN]->(IpAddress)` | `end`, `role`, `reported` |
| `(OverlayConnection)-[:REALIZED_BY]->(Tunnel)` |  |

### WanLink of `vyos`

| Property | Content |
|---|---|
| `name` | the name of the link. For `velocloud`, `name` of the WAN configuration row, else `displayName` of the link row, else the interface, else the logical id of the link |
| `kind` | `dia` or `static` |

| Relationship | Properties |
|---|---|
| `(WanLink)-[:ON]->(Interface)` |  |

### PbrPolicy of `vyos`

| Property | Content |
|---|---|
| `name` | `name` of the `vnsSvcRedirectPol` object, or the name of the VyOS policy |
| `vendor` | `vyos` |
| `af` | 4 for `policy route`, 6 for `policy route6` |

| Relationship | Properties |
|---|---|
| `(PbrPolicy)-[:HAS_RULE]->(FwRule)` |  |

### FwRulebase of `vyos`

| Property | Content |
|---|---|
| `kind` | `access` on a ruleset below `firewall ipv4 name` or `firewall ipv6 name` |
| `match_context` | `zone-pair` if a zone binds the ruleset, else absent on a ruleset below `firewall ipv4 name` or `firewall ipv6 name` |
| `kind` | `access` on the filter of the chain `forward`, `input` or `output` |
| `match_context` | `device` on the filter of the chain `forward`, `input` or `output` |
| `kind` | `access` on the configuration of VyOS 1.3 that the collector does not read |
| `match_context` | `device` on the configuration of VyOS 1.3 that the collector does not read |
| `kind` | `nat` on the rules of 1 direction below `nat` or `nat66` |
| `match_context` | absent on the rules of 1 direction below `nat` or `nat66` |
| `name` | the name of the layer, the ruleset or the access list. The filter of a VyOS chain has `ipv4-<chain>` or `ipv6-<chain>`. The rulebase of `_legacy_firewall` has `unread VyOS 1.3 firewall`. A UniFi zone pair has `<source zone>-<destination zone>`, with ` (IPv6)` after it on the IPv6 rulebase. For `nxos`, `iosxe` and `iosxr`, the family `vlan-map` has the name of the VLAN access map, the family `zone` has the zone name, the family `common` has `<common list> <list>` or the common list alone, and the family `unparsed` has the binding line. A NAT rulebase has `NAT:<package>`, `<tree>-<direction>` or `nat-<direction>` |
| `kind` | `access`, `nat` or `zone` |
| `vendor` | `checkpoint`, `vyos`, `ubiquiti` or `cisco` |
| `match_context` | `device`, `zone-pair` or `interface-acl` |
| `af` | 4 or 6. Absent on a NAT rulebase, on the rulebase of `_legacy_firewall`, on the first rulebase of a UniFi zone pair and on a Cisco list with no address family |
| `chain` | `forward`, `input` or `output` |
| `default_action` | the action for a flow that no rule matches |
| `default_action_unknown` | true if the rulebase has no `default_action` |
| `default_jump_target` | the uid of the ruleset of `default-jump-target` if the default action is `jump`, else an empty string |
| `global_state_policy` | a list of `<state>=<action>` strings |
| `configured_revision` | the revision of the configuration that the collector read |
| `installed` | true |
| `coverage` | `complete` |
| `installed_revision` | the value of `configured_revision` |
| `default_action` | `default-action` of the ruleset |
| `configured_revision` | the SHA-256 of the `firewall` node of the configuration |

| Relationship | Properties |
|---|---|
| `(FwRulebase)-[:HAS_RULE]->(FwRule)` |  |
| `(FwRulebase)-[:HAS_RULE]->(NatRule)` |  |
| `(FwRulebase)-[:FROM_ZONE]->(Zone)` |  |
| `(FwRulebase)-[:TO_ZONE]->(Zone)` |  |

### FwRule of `vyos`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `action` | the action of the rule |
| `enabled` | false for a rule that the configuration disables. True on each rule of `nxos`, `iosxe` and `iosxr` |
| `name` | the name or the description of the rule |
| `rule_uid` | `uid` of the Check Point rule. `_id` of the UniFi rule. For `vyos`, `<ruleset name>:<rule number>` on a rule of `_firewall`, `pbr:<policy name>:<rule number>` or `pbr:ipv6:<policy name>:<rule number>` on a rule of `_pbr`, and `pbr:unread-legacy:<interface name>:1` on the rule of `_legacy_policy_route`. `_legacy_policy_route` writes the rule for each interface that has an `Interface` node and holds a `policy` node in the configuration |
| `src_any` | true if the rule has no source address match |
| `dst_any` | true if the rule has no destination address match |
| `src_negate` | true if the rule negates the source side |
| `dst_negate` | true if the rule negates the destination side |
| `states` | the list of connection states that the rule matches |
| `states_opaque` | true if the rule holds a match that the collector does not model |
| `states_opaque_reason` | the text of that match |
| `jump_target` | the uid of the ruleset of `jump-target` if the action is `jump`, else an empty string |
| `in_interface`, `out_interface` | `name` of `inbound-interface` and of `outbound-interface` |
| `in_interface_group`, `out_interface_group` | `group` of `inbound-interface` and of `outbound-interface`, or an empty string |
| `action` | `action` of the rule. `route` for a rule of a `PbrPolicy` |

| Relationship | Properties |
|---|---|
| `(FwRule)-[:SRC]->(NetObject)` |  |
| `(FwRule)-[:DST]->(NetObject)` |  |
| `(FwRule)-[:SVC]->(SvcObject)` |  |
| `(FwRule)-[:REDIRECTS_VIA]->(VrfInstance)` | `table` |

### NetObject of `vyos`

| Property | Content |
|---|---|
| `name` | the name of the object or of the group, or the address of an inline match. For `unifi`, also `group:<group id>`, `network:<network id>`, `gateway:<network id>`, `src side (opaque)` and `dst side (opaque)`. For `nxos`, `iosxe` and `iosxr`, the access list name on a placeholder rule. On an entry side with no address, the reason text, else `src` or `dst` |
| `kind` | the kind of the object |
| `ranges` | a list of `<first>-<last>` address ranges |
| `opaque` | true if the collector cannot give the address set of the object |
| `opaque_reason` | the reason as text |
| `kind` | `group` for an address group or a network group, `inline` for an address in a rule |

| Relationship | Properties |
|---|---|
| `(NetObject)-[:RESOLVES_TO]->(Prefix)` |  |
| `(NetObject)-[:RESOLVES_TO]->(IpAddress)` |  |

### SvcObject of `vyos`

| Property | Content |
|---|---|
| `name` | the name of the Check Point object or of the port group. The service of a rule has `<proto>/<ports>`, with `any` for an absent part and ` src <ports>` after it for a source port. In a VyOS rule with a port group, `<ports>` is the group name. For `nxos` and `iosxe`, an ICMP entry with a type has `icmp <type>`. A UniFi service has `all` for an absent protocol. An opaque UniFi service has `service (opaque)` |
| `kind` | `type` of the Check Point API object, or `group` for a port group |
| `proto` | the protocol |
| `ports` | the destination ports |
| `src_port` | the source ports |
| `opaque` | true if the collector cannot give the match of the service |
| `opaque_reason` | the reason as text |

### Zone of `vyos`

| Property | Content |
|---|---|
| `name` | the name of the zone |
| `local_zone` | true if the zone holds `local-zone` |
| `intra_zone_filtering` | true if the zone holds `intra-zone-filtering` |
| `intra_zone_action` | `action` of `intra-zone-filtering` |
| `default_action` | `default-action` of the zone |
| `default_action_unknown` | true if the zone has no `default_action`. True on each UniFi zone |
| `configured_revision` | the value of the same property of the rulebases |
| `installed` | true |
| `coverage` | `complete` |
| `installed_revision` | the value of `configured_revision` |

| Relationship | Properties |
|---|---|
| `(Zone)-[:OWNED_BY]->(Device)` |  |
| `(Zone)-[:CONTAINS]->(Interface)` |  |

### NatRule of `vyos`

| Property | Content |
|---|---|
| `position` | the number of the rule in its rulebase |
| `kind` | `snat`, `dnat` or `static` |
| `name` | the name, the comment or the description of the rule |
| `enabled` | false for a rule that the configuration disables |
| `approximate` | true if the collector cannot give the full match of the rule |
| `approximate_reason` | the reason as text |
| `protocol` | the protocol of the match |
| `translation` | the translated address, prefix or range, `masquerade`, or `interface` |
| `translation_port` | the translated port |
| `orig_src`, `orig_dst` | `address` or `prefix` of `source` and of `destination` |
| `orig_src_port`, `orig_dst_port` | `port` of `source` and of `destination`, or the ports of a port group |
| `in_if`, `out_if` | the interface of `inbound-interface` and of `outbound-interface` |
| `exclude` | true if the rule holds `exclude` |
| `af` | 4 for the tree `nat`, 6 for the tree `nat66` |

| Relationship | Properties |
|---|---|
| `(NatRule)-[:ORIG_SRC]->(NetObject)` |  |
| `(NatRule)-[:ORIG_DST]->(NetObject)` |  |
| `(NatRule)-[:ORIG_SRC]->(Prefix)`, `(NatRule)-[:ORIG_SRC]->(IpAddress)` |  |
| `(NatRule)-[:ORIG_DST]->(Prefix)`, `(NatRule)-[:ORIG_DST]->(IpAddress)` |  |
| `(NatRule)-[:XLATE_SRC]->(Prefix)`, `(NatRule)-[:XLATE_SRC]->(IpAddress)` |  |
| `(NatRule)-[:XLATE_DST]->(Prefix)`, `(NatRule)-[:XLATE_DST]->(IpAddress)` |  |

### MtuObservation of `vyos`

| Property | Content |
|---|---|
| `source` | `vyos:` and the source name, or the host if the source has no name |
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

## `zia`

### Site of `zia`

| Property | Content |
|---|---|
| `code` | the site code |

### Provider of `zia`

| Property | Content |
|---|---|
| `name` | `zscaler` |

### Tunnel of `zia`

| Property | Content |
|---|---|
| `encap` | `gre`, `ipsec` |
| `source_ip` | the source address of the tunnel |
| `vpn_type`, `ike_id` | `type` and `fqdn` of the VPN credential |

| Relationship | Properties |
|---|---|
| `(Tunnel)-[:TERMINATES_ON]->(ZscalerDc)` | `role`, `vip` |

### OverlayConnection of `zia`

| Property | Content |
|---|---|
| `kind` | `tunnel` |
| `technology` | the `encap` of the tunnels |
| `name` | a text with the 2 ends |
| `observed_from` | the list of the end letters `a` and `b` that a batch reported |

| Relationship | Properties |
|---|---|
| `(OverlayConnection)-[:BETWEEN]->(ZiaLocation)` | `end`, `role`, `reported` |
| `(OverlayConnection)-[:BETWEEN]->(ZscalerDc)` | `end`, `role`, `reported` |
| `(OverlayConnection)-[:REALIZED_BY]->(Tunnel)` |  |

### ZscalerDc of `zia`

| Property | Content |
|---|---|
| `name` | `datacenter` of the VIP object |
| `private_service_edge` | true if `privateServiceEdge` of the VIP object is true, else absent |
| `vip` | the lowest `virtualIp` of the data center in address order |

| Relationship | Properties |
|---|---|
| `(ZscalerDc)-[:PROVIDED_BY]->(Provider)` |  |

### ZiaLocation of `zia`

| Property | Content |
|---|---|
| `name` | `name` of the location |
| `zia_id` | `id` of the location as a string |
| `country` | `country` |
| `tz` | `tz` |
| `egress_ips` | `ipAddresses` of a location. Absent on a sublocation |
| `address_ranges` | `ipAddresses` of a sublocation. Absent on a location |
| `other_sublocation` | true if `otherSubLocation` of a sublocation is true, else absent |
| `auth_required` | `authRequired` |
| `ssl_scan_enabled` | `sslScanEnabled` |
| `profile` | `profile` |
| `ofw_enabled` | `ofwEnabled` |
| `ips_control` | `ipsControl` |
| `xff_forward_enabled` | `xffForwardEnabled` |
| `surrogate_ip` | `surrogateIP` |

| Relationship | Properties |
|---|---|
| `(ZiaLocation)-[:PART_OF]->(ZiaLocation)` |  |
| `(ZiaLocation)-[:REPRESENTS]->(Site)` |  |
| `(ZiaLocation)-[:USES]->(Tunnel)` |  |
| `(ZiaLocation)-[:MEMBER_OF]->(ZiaLocationGroup)` |  |

### ZiaLocationGroup of `zia`

| Property | Content |
|---|---|
| `name` | `name` of the group |
| `dynamic` | true if `groupType` is `DYNAMIC_GROUP` |
| `dynamic_criteria` | `dynamicLocationGroupCriteria` as a JSON string |

### ZiaForwardingRule of `zia`

| Property | Content |
|---|---|
| `name` | `name` of the rule |
| `order` | `order` as an integer |
| `forward_method` | `forwardMethod` in lower case |
| `enabled` | true if `state` is `ENABLED`. Absent if the rule has no `state` |
| `rule_type` | `type` |
| `zpa_app_segment_ids` | `externalId` of each entry of `zpaAppSegments` and `zpaId` of each entry of `zpaApplicationSegments` |
| `zpa_segment_group_ids` | `zpaId` of each entry of `zpaApplicationSegmentGroups` |
| `zpa_gateway_id` | `id` of `zpaGateway` as a string |
| `zpa_gateway` | `name` of `zpaGateway` |
| `zpa_server_group_id` | `externalId` of the `zpaServerGroup` of that gateway in `zpa_gateways` of the payload |
| `location_ids` | `id` of each entry of `locations` |
| `location_group_ids` | `id` of each entry of `locationGroups` |
| `src_ips` | `srcIps` |
| `dest_addresses` | `destAddresses` |
| `other_criteria` | the sorted keys of `src/hst/collectors/zia.py` `_OTHER_FORWARDING_CRITERIA` that hold a value in the rule |

| Relationship | Properties |
|---|---|
| `(ZiaForwardingRule)-[:APPLIES_TO]->(ZiaLocation)` |  |
| `(ZiaForwardingRule)-[:APPLIES_TO]->(ZiaLocationGroup)` |  |

## `zpa`

### ZpaAppSegment of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the segment |
| `zpa_id` | `id` of the segment as a string |
| `domains` | `domainNames` |
| `ranges` | the entries of `domainNames` that are an IP address or a CIDR, as networks |
| `opaque` | true if an entry of `domainNames` starts with `*` |
| `opaque_reason` | the text `wildcard domain entries` with the entries |
| `tcp_port_ranges` | `tcpPortRanges` |
| `udp_port_ranges` | `udpPortRanges` |
| `enabled` | `enabled` |
| `bypass_type` | `bypassType` in upper case |

| Relationship | Properties |
|---|---|
| `(ZpaAppSegment)-[:MEMBER_OF]->(ZpaSegmentGroup)` |  |
| `(ZpaAppSegment)-[:SERVED_BY]->(ZpaServerGroup)` |  |

### ZpaSegmentGroup of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the group |
| `zpa_id` | `id` of the group as a string |
| `enabled` | `enabled` as a boolean |

### ZpaServerGroup of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the group |
| `zpa_id` | `id` of the group as a string |
| `enabled` | `enabled` as a boolean |
| `dynamic_discovery` | `dynamicDiscovery` as a boolean |

| Relationship | Properties |
|---|---|
| `(ZpaServerGroup)-[:USES]->(ZpaAppConnectorGroup)` |  |
| `(ZpaServerGroup)-[:CONTAINS]->(AppServer)` |  |

### AppServer of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the server |
| `address` | `address` of the server |
| `enabled` | `enabled` |

### ZpaAppConnectorGroup of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the group |
| `location` | `location` |
| `enabled` | `enabled` as a boolean |

| Relationship | Properties |
|---|---|
| `(ZpaAppConnectorGroup)-[:HAS]->(ZpaAppConnector)` |  |

### ZpaAppConnector of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the connector |
| `enabled` | `enabled` |
| `control_channel_status` | `controlChannelStatus` |
| `health` | `up` for the status `ZPN_STATUS_AUTHENTICATED`, `down` for `ZPN_STATUS_DISCONNECTED`, else absent |
| `private_ip` | `privateIp` |
| `public_ip` | `publicIp` |

### ZpaAccessRule of `zpa`

| Property | Content |
|---|---|
| `position` | `ruleOrder` as an integer |
| `priority` | `priority` as an integer |
| `name` | `name` of the rule |
| `action` | `action` in lower case, if it is a value of `src/hst/core/labels.py` `ZPA_ACCESS_ACTIONS`. Absent for each other value |
| `action_raw` | `action` |
| `operator` | `operator` |
| `conditions` | the result of `src/hst/core/zpa_policy.py` `condition_blocks` as a JSON string |
| `conditions_summary` | the result of `src/hst/core/zpa_policy.py` `conditions_summary` |
| `identity_scope` | `any`, `listed` or `other` |
| `app_scope` | `any`, `listed` or `other` |
| `applies_to_all_identities` | true if `identity_scope` is `any`, else absent |
| `enabled` | true if `disabled` is `0` or false. False if `disabled` is `1` or true. Absent for each other value |
| `disabled_raw` | `disabled` as a string, if `enabled` is absent and the rule holds `disabled` |

| Relationship | Properties |
|---|---|
| `(ZpaAccessRule)-[:FOR]->(ZpaAppSegment)` |  |
| `(ZpaAccessRule)-[:FOR]->(ZpaSegmentGroup)` |  |
| `(ZpaAccessRule)-[:GRANTS]->(IdentityGroup)` |  |
| `(ZpaAccessRule)-[:DENIES]->(IdentityGroup)` |  |
| `(ZpaAccessRule)-[:APPLIES_TO]->(IdentityGroup)` |  |
| `(ZpaAccessRule)-[:STEERS_VIA]->(ZpaAppConnectorGroup)` |  |
| `(ZpaAccessRule)-[:STEERS_VIA]->(ZpaServerGroup)` |  |

### ZpaClientForwardingRule of `zpa`

| Relationship | Properties |
|---|---|
| `(ZpaClientForwardingRule)-[:FOR]->(ZpaAppSegment)` |  |
| `(ZpaClientForwardingRule)-[:FOR]->(ZpaSegmentGroup)` |  |
| `(ZpaClientForwardingRule)-[:APPLIES_TO]->(IdentityGroup)` |  |

### ZpaProvisioningKey of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the key |
| `enabled` | `enabled` |
| `max_usage` | `maxUsage` |
| `usage_count` | `usageCount` |
| `zcomponent_id` | `zcomponentId` |
| `zcomponent_name` | `zcomponentName` |

### ZpaServiceEdge of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the service edge |
| `kind` | `private` |
| `location` | `location` |
| `enabled` | `enabled` |
| `control_channel_status` | `controlChannelStatus` |
| `health` | as on `ZpaAppConnector` |

### IdentityGroup of `zpa`

| Property | Content |
|---|---|
| `name` | `name` of the operand, else the name of the SCIM group in `scim_groups` of the payload, else `rhs` |
| `name_is_id` | true if `name` holds `rhs`, else absent |
| `source` | `scim` |
| `idp_name` | `idpName` of an operand that holds `rhs` |

## Loader, reasoner rules and other code

| Label | Property or relationship | Content or properties | Written by |
|---|---|---|---|
| `Device` | `role_reported`, `role_basis`, `tier` | the role of the collector, the basis and the tier of the role | `src/hst/reasoner/device_roles.py` `apply_device_roles` |
| `Device` | `site_block`, `site_zone` | the block and the zone of the device in its site | `src/hst/core/cycle.py` `apply_site_blocks` |
| `Device` | `(Device)-[:SAME_AS]->(Device)` |  | `edge-device-from-binding` |
| `Port` | `(Port)-[:ON]->(Device)` |  | `edge-device-from-binding` |
| `Port` | `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `unifi-uplink` | `cable-from-uplink-record` |
| `Port` | `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `unifi-lldp` | `cable-from-lldp-record` |
| `Port` | `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `cdp` or `lldp` | `cable-from-neighbor-name` |
| `Port` | `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `reasoner` | `cable-from-endpoint-mac`, `cable-from-last-connection` |
| `Port` | `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `reasoner`, `basis` | `src/hst/reasoner/arp_cables.py` `ARP_CABLE_WRITE` with the rule name `cable-from-arp-port` |
| `Port` | `(Port)-[:CONNECTED_TO]->(Port)` | `source` with the value `equinix-circuit`, `circuit_uid`, `vlan_tag_a`, `vlan_tag_z`, `link_protocol_a`, `link_protocol_z` | `cable-from-fabric-circuit` |
| `Port` | `(Port)-[:CONNECTED_TO]->(Port)` | `speed_mbps`, `speed_agreement` | `src/hst/core/reasoner.py` `execute_link_speed` |
| `Interface` | `(Interface)-[:GATEWAY_FOR]->(Prefix)` |  | `gateway-from-router-interface`, `gateway-from-sole-firewall-interface`, `gateway-from-sole-segment-interface` |
| `Interface` | `(Interface)-[:ATTACHED_TO]->(BridgeDomain)` | `basis` with the value `svi` or `subif` | `attached-from-vlan-binding` |
| `Interface` | `(Interface)-[:ATTACHED_TO]->(BridgeDomain)` | `basis` with the value `cable` | `attached-from-cable` |
| `Endpoint` | `infra` | `true` | `cable-from-endpoint-mac` |
| `VrfInstance` | `(VrfInstance)-[:MEMBER_OF]->(RoutingDomain)` | `basis` with the value `rt-component`, `rts` | `src/hst/core/reasoner.py` `execute_rt_domains` |
| `RoutingDomain` | `basis` | `rt-component` | `src/hst/core/reasoner.py` `execute_rt_domains` |
| `RoutingDomain` | `rts` | the route targets of the component, sorted and joined with commas | `src/hst/core/reasoner.py` `execute_rt_domains` |
| `Prefix` | `ipam_cidr`, `ipam_match`, `ipam_import`, `ipam_description`, `ipam_location`, `ipam_vlan` | the IPAM entry of the prefix | `src/hst/core/ipam.py` `annotate` |
| `IpAddress` | `af` | 4 or 6 | the same source types |
| `IpAddress` | `anchor` | the value that the `uid` uses as scope | the same source types |
| `IpAddress` | `(IpAddress)-[:IN]->(Prefix)` |  | `src/hst/reasoner/containment.py` `CONTAINMENT_WRITE` with the rule name `address-containment` |
| `BgpSession` | `(BgpSession)-[:PEERS_WITH]->(BgpSession)` | `basis` with the value `peer-address` | `bgp-peer-from-address` |
| `Tunnel` | `(Tunnel)-[:SAME_AS]->(IpAddress)` | `basis` with the value `source_ip`, `confidence` | `zpa-zia-ip-same-as` |
| `ZiaForwardingRule` | `(ZiaForwardingRule)-[:FORWARDS_TO]->(ZpaAppSegment)` |  | `zia-forwarding-to-zpa-segment` |
| `ZiaForwardingRule` | `(ZiaForwardingRule)-[:FORWARDS_TO]->(ZpaSegmentGroup)` |  | `zia-forwarding-to-zpa-segment-group` |
| `ZiaForwardingRule` | `(ZiaForwardingRule)-[:STEERS_VIA]->(ZpaServerGroup)` |  | `zia-forwarding-to-zpa-server-group` |
| `ZpaAppSegment` | `(ZpaAppSegment)-[:RESOLVES_TO]->(DnsRecord)` | `domain` | `zpa-segment-domain-to-dns` |
| `AppServer` | `(AppServer)-[:SAME_AS]->(IpAddress)` | `basis`, `confidence` | `zpa-zia-ip-same-as` |
| `ZpaAppConnector` | `(ZpaAppConnector)-[:SAME_AS]->(IpAddress)` | `basis`, `confidence` | `zpa-zia-ip-same-as` |
| `FabricPort` | `binding_issue` | `cable-conflict`, `several-ports` or `several-fabric-ports` | `fabric-port-from-description` |
| `FabricPort` | `binding_ports` | the sorted `Port` uids of the issue | `fabric-port-from-description` |
| `FabricPort` | `(FabricPort)-[:REALIZED_BY]->(Port)` | `evidence` | `fabric-port-from-description` |
<!-- end generated: schema-by-source-type -->
