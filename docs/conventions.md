# Conventions

## Naming

`src/hst/core/labels.py` `LABELS` holds each label. `src/hst/core/labels.py` `RELS` holds each relationship type. [Node labels](schema.md#node-labels) and [Relationship types](schema.md#relationship-types) list the 2 registries.

| Element | Form | Example |
|---|---|---|
| label in `LABELS` | `[A-Z][A-Za-z0-9]*` | `VrfInstance` |
| relationship type in `RELS` | `[A-Z][A-Z0-9_]*` | `CONNECTED_TO` |
| key of a [relationship record](#loader-contract) | `[A-Za-z_][A-Za-z0-9_]*` | `proto` |

Each entry of the 2 registries has the form of its row. `src/hst/core/model.py` `Batch.validate_registry` rejects a key outside the form of row 3.

`src/hst/core/labels.py` `labels_clause` gives the label string of a node. [Node labels](schema.md#node-labels) describes the string.

`src/hst/core/labels.py` `RESERVED_LABELS` holds `Obj`, `Gate`, `Retired`, `Latest` and the 10 layers. The layers are `Phys`, `L2`, `L3`, `Transport`, `Policy`, `Service`, `Workload`, `App`, `Cloud` and `Meta`. The labels `CyclePointer` and `CycleRun` are outside `LABELS`. [Storage](storage.md#neo4j) describes the nodes of these 2 labels and of `CollectionRun`.

No code under `src/hst` sets the label `Retired`, the label `Latest` or the property `_retired_at`. The statements of `src/hst/reasoner/catalog.py` `RULES` exclude a node with `Retired` and a relationship with `_retired_at`.

[Loader contract](#loader-contract) gives the reserved property keys.

## Uids

A uid is a string with a namespace prefix. `src/hst/core/uid.py` holds the uid builders. The constraint `obj_uid_cts` allows 1 node for each uid in 1 [run](#run-versions), for all labels. [Storage](storage.md#neo4j) describes the constraint.

### Segment functions

5 functions convert a value to a segment of a uid.

| Function | Rule | Example |
|---|---|---|
| `src/hst/core/uid.py` `slug` | The value is in lowercase. Each space and each run of characters outside `[a-z0-9._-]` is 1 `-`. The 2 ends have no `-`. | `Carrier-X MPLS VPN` gives `carrier-x-mpls-vpn` |
| `src/hst/core/uid.py` `exact_slug` | A value that `slug` does not change is the segment. Each other value gives the slug, `~` and the first 8 hex digits of the SHA-256 of the value. | `WEB-IN` gives `web-in~d601880c` |
| `src/hst/core/uid.py` `anchor_slug` | The rule of `slug` applies, with 1 difference. An ASCII uppercase letter gives `~` and the lowercase letter. | `vrf:dev:fra01-core-01:corp` gives `vrf-dev-fra01-core-01-corp` |
| `src/hst/core/uid.py` `norm_mac` | The MAC address has 12 lowercase hex digits and no separator. Each other length raises `ValueError`. | `00:1c:7f:aa:bb:01` gives `001c7faabb01` |
| `src/hst/core/normalize.py` `iface_slug` | The segment is the result of `short_ifname` with `-` for each `/` and each `:`. A `.` stays. | `ethernet1/2` gives `eth1-2` |

The example of `exact_slug` uses a value of `tests/test_uid.py`. The other examples use values of `fixtures/mini-enterprise.yaml` and `fixtures/mini-dc.yaml`.

`src/hst/core/uid.py` `IFACE_UID_VERSION` holds the version of the rule of `iface_slug`. The value is `2`. The collectors of 10 [source types](collectors.md#sources) hold the value in `NORMALIZATION_VERSIONS` under the key `iface_uid`. The source types are `apic`, `checkpoint_gateway`, `equinix`, `iosxe`, `iosxr`, `nautobot`, `netscaler`, `nxos`, `velocloud` and `vyos`.

### Builders

The table has 1 row for each of the 47 builders.

| Builder | Format | Example | Source types that call the builder |
|---|---|---|---|
| `site` | `site:<slug(code)>` | `site:fra01` | `equinix`, `zia` |
| `rack` | `rack:<slug(site_code)>:<slug(name)>` | `rack:home:lab-rack` | `nautobot` |
| `provider` | `provider:<slug(name)>` | `provider:carrier-x` | `equinix`, `velocloud`, `zia` |
| `provider_network` | `pnet:<slug(kind)>:<slug(name)>` | `pnet:mpls:carrier-x-mpls-vpn` | `velocloud` |
| `rgrp` | `rgrp:<slug(kind)>:<slug(scope)>:<slug(name)>` | `rgrp:cp-cluster:dc1:cpfw01` | `checkpoint`, `nxos`, `unifi` |
| `fhrp` | `fhrp:<slug(kind)>:<anchor_slug(domain)>:<vip>` | `fhrp:hsrp:corp:10.20.0.1` | `iosxe`, `iosxr`, `nxos` |
| `port` | `<device_uid>/port/<iface_slug(port_name)>` | `dev:fra01-core-01/port/eth1-2` | `checkpoint_gateway`, `equinix`, `iosxe`, `iosxr`, `nautobot`, `nxos`, `velocloud`, `vyos` |
| `interface` | `<device_uid>/if/<iface_slug(if_name)>` | `dev:fra01-core-01/if/eth1-2` | `apic`, `equinix`, `iosxe`, `iosxr`, `netscaler`, `nxos`, `unifi`, `velocloud`, `vyos` |
| `vlan` | `vlan:<scope_uid>:<vid>` | `vlan:dev:fra01-core-01:100` | `checkpoint_gateway`, `iosxe`, `nxos`, `unifi`, `vyos` |
| `bridge_domain` | `bd:vlan:<slug(fabric)>:<vid>` | `bd:vlan:fab0:100` | `checkpoint_gateway`, `iosxe`, `nxos`, `unifi`, `vyos` |
| `l3dom` | `l3dom:<slug(name)>` | `l3dom:corp` | none |
| `routing_domain` | `rdom:<slug(name)>` | `rdom:corp` | `iosxe`, `iosxr`, `nxos`, `unifi`, `velocloud`, `vyos` |
| `vrf` | `vrf:<scope_uid>:<name>` | `vrf:dev:fra01-core-01:corp` | `iosxe`, `iosxr`, `nautobot`, `nxos`, `unifi`, `velocloud` |
| `prefix` | `pfx:<anchor_slug(anchor)>:<cidr>` | `pfx:vrf-dev-fra01-core-01-corp:10.20.0.0/24` | `checkpoint`, `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos`, `unifi`, `velocloud`, `vyos` |
| `ip` | `ip:<anchor_slug(anchor)>:<addr>` | `ip:vrf-dev-fra01-core-01-corp:10.20.0.1` | `apic`, `checkpoint`, `checkpoint_gateway`, `iosxe`, `iosxr`, `manual`, `nautobot`, `netscaler`, `nxos`, `unifi`, `velocloud`, `vyos` |
| `endpoint` | `ep:<slug(scope)>:<norm_mac(mac)>` | `ep:corp:001c7faabb01` | `apic`, `checkpoint_gateway` |
| `route_target` | `rt:<value>` | `rt:65001:50001` | `iosxe`, `iosxr` |
| `fc` | `fc:<device_uid>:<slug(table_id)>` | `fc:dev:fra01-core-01:corp` | none |
| `routing_process` | `rproc:<device_uid>:<slug(vrf_name)>:<slug(proto)>` | `rproc:dev:fra01-core-01:corp:bgp` | `apic`, `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos`, `velocloud`, `vyos` |
| `bgp_session` | `bgp:<local_uid>~<peer_ip>:<vrf_name>` | `bgp:rproc:dev:fra01-core-01:corp:bgp~10.99.0.1:corp` | `apic`, `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos`, `velocloud`, `vyos` |
| `bgp_peer_range` | `bgprange:<local_uid>~<prefix>:<vrf_name>` | `bgprange:rproc:dev:fra01-core-01:corp:bgp~10.99.0.0/24:corp` | `iosxe`, `iosxr`, `nxos`, `vyos` |
| `ospf_area` | `ospfarea:<process_uid>:<slug(area_id)>` | `ospfarea:rproc:dev:fra01-core-01:default:ospf:0.0.0.0` | `apic`, `iosxe`, `iosxr`, `nxos`, `vyos` |
| `ospf_adjacency` | `ospfadj:<process_uid>:<local_if_uid>~<neighbor_router_id>` | `ospfadj:rproc:dev:fra01-core-01:default:ospf:dev:fra01-core-01/if/eth1-2~10.255.255.1` | `apic`, `iosxe`, `iosxr`, `nxos`, `vyos` |
| `route_policy` | `rtpol:<device_uid>:<slug(kind)>:<name>` | `rtpol:dev:fra01-core-01:route-map:RM-IN` | `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos`, `vyos` |
| `route_policy_entry` | `<policy_uid>/clause/<seq>` | `rtpol:dev:fra01-core-01:route-map:RM-IN/clause/10` | `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos`, `vyos` |
| `prefix_list_entry` | `<policy_uid>/line/<seq>` | `rtpol:dev:fra01-core-01:prefix-list:PL-CUSTOMER-IN/line/10` | `iosxe`, `iosxr`, `nxos`, `vyos` |
| `match_list_entry` | `<policy_uid>/line/<seq>` | `rtpol:dev:fra01-core-01:community-list:CL-STD/line/1` | `iosxe`, `iosxr`, `nxos`, `vyos` |
| `tunnel` | `tun:<slug(encap)>:<end>~<end>` | `tun:velocloud-vcmp:dev:fra01-vce-01~vco:acme:gw:fra-gw1` | `velocloud`, `vyos` |
| `overlay_connection` | `oconn:<slug(technology)>:<end>~<end>` | `oconn:velocloud-vcmp:dev:fra01-vce-01~vco:acme:gw:fra-gw1` | `velocloud`, `vyos`, `zia` |
| `fabric` | `fabric:<slug(name)>` | `fabric:fab1` | `apic` |
| `aci` | `aci:<slug(fabric_name)>:<dn>` | `aci:fab1:uni/tn-PROD/ap-webshop` | `apic`, `ndo` |
| `checkpoint` | `cp:<slug(mgmt)>:<slug(domain)>:<api_uid>` | `cp:mgmt01:smc:pkg-dc-access` | `checkpoint` |
| `fortigate` | `fgt:<serial>:<vdom>:<table>:<mkey>` | `fgt:FGT60F0000000001:root:policy:1` | none |
| `ndo` | `ndo:<slug(host)>:<ref>` | `ndo:ndo-example:sch-1` | `ndo` |
| `netscaler` | `ns:<slug(rgrp_name)>:<slug(obj_type)>:<name>` | `ns:dc1-ns01:lbvs:web-443` | `netscaler` |
| `velocloud` | `vco:<slug(enterprise)>:<slug(obj_type)>:<obj_id>` | `vco:acme:link:fra01-mpls` | `velocloud` |
| `zia` | `zia:<slug(org)>:<slug(obj_type)>:<obj_id>` | `zia:acme:gre:9301` | `zia` |
| `zpa` | `zpa:<slug(customer)>:<slug(obj_type)>:<obj_id>` | `zpa:acme:conn:600` | `zpa` |
| `aws` | `aws:<arn>` | `aws:arn:aws:ec2:eu-central-1:111111111111:security-group/sg-0web` | none |
| `azure` | `az:<resource_id>` in lowercase | `az:/subscriptions/00000000-0000-0000-0000-000000000001` | none |
| `vcenter` | `vc:<slug(vc)>:<moref>` | `vc:vc01:vm-101` | none |
| `snow` | `snow:<sys_id>` | `snow:bs-webshop` | none |
| `dns` | `dns:<fqdn>:<rtype>` | `dns:webshop.corp.example:A` | none |
| `equinix` | `eqx:<slug(obj_type)>:<uuid>` | `eqx:port:11111111-aaaa` | `equinix` |
| `run` | `run:<run_id>` | `run:1700000000000-aaaaaaaa` | none |
| `mtu_observation` | `mtu:<digest>` | `mtu:dc885dcf61c1539e4811a2e59b7effc55cfc26a714e6555d940b406d7c7abc9d` | none |
| `lag` | `<device_uid>/lag/<iface_slug(name)>` | `dev:fra01-core-01/lag/po1` | `apic`, `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos`, `vyos` |

The examples use values of `fixtures/mini-enterprise.yaml` and `fixtures/mini-dc.yaml`. 7 files give the values of the other examples.

| Builders | File |
|---|---|
| `rack` | `tests/test_nautobot.py` |
| `ndo` | `tests/test_ndo.py` |
| `lag` | `tests/test_cisco_common.py` |
| `ospf_adjacency`, `route_policy`, `route_policy_entry`, `prefix_list_entry`, `match_list_entry` | `tests/test_iosxe.py` |
| `run` | `tests/test_schema_contract.py` |
| `mtu_observation` | `fixtures/mtu/cisco/observations-v1.json`, `tests/test_mtu_cisco.py` |

These rules apply to the formats:

- The fabric `fab0` of the `bridge_domain` example is the value of `src/hst/core/config.py` `DEFAULT_L2_FABRIC`.
- `tunnel` and `overlay_connection` sort the 2 ends. The 2 ends of a connection give 1 uid.
- `ndo` replaces each `.` of the host slug with `-`.
- `dns` removes each `.` at the end of the name, writes the name in lowercase and writes the type in uppercase.
- The digest of `mtu_observation` is the SHA-256 of a JSON list. The list holds `subject_uid`, `source`, `source_target`, `source_field`, `metric`, `direction`, `scope`, `assertion_kind`, `traffic_class`, `policy_ref` and `enforcement_key`.
- `prefix_list_entry` and `match_list_entry` have 1 format. The kind in the uid of the route policy keeps the 2 uids apart.

3 functions outside the collectors call a builder for a node that they write:

- `src/hst/core/cycle.py` `apply_site_assignments` calls `site` for the site that an operator assigns.
- `src/hst/core/reasoner.py` `build_rt_domains` calls `routing_domain`.
- `src/hst/core/mtu_profiles.py` `observation_from_raw` calls `mtu_observation` for each collector that writes an `MtuObservation` node.

`src/hst/core/loader.py` `load` builds the uid `run:<run id>` without the builder `run`.

### Scope arguments

`vlan`, `vrf`, `endpoint` and `rgrp` take a scope. [Batch scope](#batch-scope) gives the batch scope of each source type.

| Builder | Source type | Scope value |
|---|---|---|
| `vlan` | `nxos`, `iosxe` | the batch scope |
| `vlan` | `vyos`, `checkpoint_gateway` | the uid of the device |
| `vlan` | `unifi` | `unifi:<site>` |
| `vrf` | `nxos`, `iosxe`, `iosxr` | the uid of the device |
| `vrf` | `unifi` | the uid of the gateway device |
| `vrf` | `velocloud` | the uid of the edge |
| `vrf` | `nautobot` | `nautobot:<namespace id>:<VRF id>` |
| `endpoint` | `apic` | the uid of the bridge domain of the EPG, or the uid of the EPG if no bridge domain resolves |
| `endpoint` | `checkpoint_gateway` | the `context_uid` of the neighbor row |
| `rgrp` | `checkpoint` | the batch scope, with the kind `cp-cluster` |
| `rgrp` | `nxos` | the name of the source, or the batch scope for a collector without a source name, with the kind `vpc` |
| `rgrp` | `unifi` | the partition of the batch scope, with the kind `unifi-ha` |

The `VlanInstance` of VLAN 100 on an NX-OS device with the host `10.20.99.1` has the uid `vlan:nxos:10.20.99.1:100`. The host is the `mgmt_ip` of `fra01-core-01` in `fixtures/mini-enterprise.yaml`.

`prefix` and `ip` take an anchor. A caller passes the uid of a `VrfInstance`, the uid of a `BridgeDomain`, a domain string, its batch scope or another string of its source. `src/hst/collectors/util.py` `connected_address` writes the same value to the property `anchor` of the 2 nodes.

### Uids without a builder

The table gives 9 of the uid formats that code builds with a format string. `src/hst/collectors/apic.py`, `src/hst/collectors/checkpoint_topology.py`, `src/hst/collectors/cisco_common.py`, `src/hst/collectors/netscaler.py`, `src/hst/collectors/unifi.py` and `src/hst/collectors/vyos.py` build more formats.

| Format | Label | Code |
|---|---|---|
| `dev:<name>` | `Device` | [Device identity](#device-identity) |
| `unifi:<site>:zone:<exact_slug(zone id)>` | `Zone` | `src/hst/collectors/unifi.py` |
| `ssid:unifi:<partition>:<exact_slug(WLAN id)>` | `Ssid` | `src/hst/collectors/unifi.py` |
| `ep:unifi:<partition>:<norm_mac(mac)>` | `Endpoint` | `src/hst/collectors/unifi.py` |
| `vrf:<device uid>:<slug(name)>` | `VrfInstance` | `src/hst/collectors/vyos.py` |
| `cp-install:<instance uid>:<slug(rulebase uid)>:<slug(revision)>:<slug(VRF uid)>` | `PolicyInstallation` | `src/hst/collectors/checkpoint_gateway.py` |
| `cycle:<run key>` | `CycleRun` | `src/hst/core/cycle.py` `begin_run` |
| `meta:cycle-pointer` | `CyclePointer` | `src/hst/core/cycle.py` `POINTER_UID` |
| `run:<run id>` | `CollectionRun` | `src/hst/core/loader.py` `load` |

## Device identity

The device identity registry gives the uid `dev:<name>` of a `Device` node. `src/hst/core/identity.py` holds the rule. `src/hst/app/store/pg.py` `PgStore.resolve_device` holds the registry in the table `device_identity`. `src/hst/core/identity.py` `MemoryResolver` holds the same rule in memory.

A collector has a `MemoryResolver` in its attribute `identity`. For a run, `src/hst/app/runs_exec.py` `_arm_identity` sets 1 `src/hst/app/sources.py` `StoreResolver` on each collector of the run.

The registry keys a device by an identifier. An identifier of the kind `serial` holds the chassis serial. An identifier of the kind `ref` holds `<source>:<ref>`. `src/hst/core/identity.py` `identifier` gives the form in the registry. The form is the `slug` of a serial, and the `slug` of each part of a ref between `:`.

`resolve_device` returns the uid of an identifier that the registry holds. For each other identifier, it mints a uid and writes the row. `bind_device` adds an identifier to a uid that the registry holds. `hst device rekey` moves each identifier of a uid to another uid and increments the generation of the registry.

`src/hst/core/identity.py` `chassis_serial` returns no serial in 3 cases:

- The device reports no serial.
- The serial is a value of `PLACEHOLDER_SERIALS`, such as `n/a` or `to be filled by o.e.m.`.
- The serial has 1 character, or 1 character that repeats.

`src/hst/core/identity.py` `resolve_chassis` resolves a device by its serial. A device without a serial resolves by its fallback identifier. If 2 devices with 2 fallback identifiers and 2 short hostnames report 1 serial in 1 run, the second device resolves by its fallback identifier.

`src/hst/core/identity.py` `mint` builds the uid in this order:

1. `short_name` takes the hostname up to the first `.` and applies `slug`. A hostname that is an IP address stays complete. A device without a hostname gets the name `unknown`.
2. If no device has `dev:<name>` and the name is outside `DEFAULT_NAMES`, the uid is `dev:<name>`.
3. If not, the uid is `dev:<name>-<suffix>`. The suffix is the last 4 characters of the serial slug. Without a serial, the suffix is the first 4 hex digits of the SHA-256 of the ref.
4. If a device has that uid, the suffix gets 1 more character for each try.
5. If the serial or the hash has no more characters, the longest suffix gets `-<n>`, and `n` starts at 2.

`DEFAULT_NAMES` holds `switch`, `router`, `localhost`, `unknown` and `vyos`.

| Call of `mint` | Uids in use | Result |
|---|---|---|
| hostname `fra01-core-01`, serial `FDO22220001` | none | `dev:fra01-core-01` |
| hostname `fra01-core-01`, serial `FDO22220002` | `dev:fra01-core-01` | `dev:fra01-core-01-0002` |
| hostname `switch`, serial `FDO22220001` | none | `dev:switch-0001` |

The hostname `fra01-core-01` and the 2 serials are in `fixtures/mini-enterprise.yaml`.

Each collector that writes a `Device` node passes these identifiers.

| Source type | Serial | Fallback identifier |
|---|---|---|
| `nxos`, `iosxe`, `iosxr` | the chassis serial | `ref` `<batch scope>:<hostname>` |
| `vyos` | the serial of the version text | `ref` `<source name>:<host>`, or `vyos:<host>` without a source name |
| `apic` | the serial of the fabric node | `ref` `<fabric>:<node dn>` |
| `unifi` | the serial of the device | `serial` with the MAC address of the device |
| `nautobot` | the serial of the device record | `ref` `nautobot:<name>` |
| `manual` | the serial of the CSV row | `ref` `<batch scope>:<hostname>` |
| `checkpoint` | none | `ref` `<batch scope>:<API uid of the gateway object>` |
| `checkpoint_gateway` | none | `ref` `<authority>:<appliance uid>` |

`src/hst/collectors/iosxe.py` `IosxeCollector.normalize` binds each other serial of a stack to the uid of the first serial.

2 source types write a `Device` node without the registry:

- `equinix` writes `eqx:device:<uuid>` for a Network Edge device.
- `velocloud` writes `vco:<enterprise>:edge:<id>` for an edge.

## One object from 2 sources

2 batches that hold 1 uid write 1 node in a run. The node keeps the `_scope` of the first batch and gets the source of each batch in `_sources`.

### Identity checks

`src/hst/core/labels.py` `check_identity` raises `IdentityCollision` if 1 batch declares 1 uid with 2 values of an identity property. The identity properties of `Device` and `VrfInstance` are `anchor`, `name` and `hostname`. The identity property of each other label is `anchor`.

`src/hst/collectors/util.py` `GraphBuilder.node` and `src/hst/core/model.py` `Batch.validate_registry` call `check_identity`. A property without a value is not compared.

`src/hst/core/loader.py` `_check_cycle_anchors` does the same check for `anchor` between the loads of 1 run. It raises `CycleIdentityCollision` if a node of the batch has another `anchor` than the node with the same uid in the run. `src/hst/core/cycle.py` `_check_carry_anchors` does the check between the run and the parent run, for each scope with the reason `unchanged`. The run builder in `src/hst/app/runs_exec.py` raises `CycleIdentityCollision` again, and the build of the run stops.

### Source assertions

After a second source writes a node, `src/hst/core/loader.py` `assertion_props` gives the node 1 property `_assert.<field>` for each payload field. The property is a sorted list with 1 string for each source that gave the field. The string has the format `<collector type>/<source>=<JSON value>`. `src/hst/core/loader.py` `collector_type` returns the collector type, the part of the batch scope before the first `:`. A node that 1 source wrote has no such property.

If the sources give 2 values for a field, `src/hst/core/loader.py` `effective_value` selects the value of the field. `COLLECTOR_CLASSES` gives each collector type 1 of 3 classes. The value of the first class in this table is the value of the field.

| Order | Class | Collector types |
|---|---|---|
| 1 | `observed` | `cp`, `iosxe`, `iosxr`, `netscaler`, `nxos`, `vyos` |
| 2 | `configured` | `apic`, `manual`, `nautobot`, `ndo`, `unifi`, `zia`, `zpa` |
| 3 | `derived` | `derived` |

A collector type outside `COLLECTOR_CLASSES` has the class `configured`. The table has no entry for `checkpoint-gateway`, `equinix` and `velocloud`. For 2 assertions of 1 class, the lower collector type and then the lower source name gives the value. `LABEL_PRECEDENCE` can give a label another order. Its entries for `BridgeDomain`, `Device`, `IpAddress`, `Port`, `Prefix` and `Site` hold the order of the table.

### Source-local labels

`src/hst/core/loader.py` `SOURCE_LOCAL_LABELS` holds `FwRulebase`, `FwRule`, `Zone`, `NatRulebase`, `NatRule`, `NetObject`, `SvcObject`, `PbrPolicy`, `WanLink` and `Rack`. If 2 sources of 1 collector type write 1 uid of these labels in a run, the load adds a warning to its manifest.

## Run versions

### Run key and run pointer

`src/hst/core/cycle.py` `new_collection_ts` returns the time in milliseconds as the run key. Each node and each relationship of the run holds the run key in `collection_ts`. A load without a run key uses the time of the load as the run key.

The run pointer is the node `meta:cycle-pointer`. Its property `current` holds the run key of the published run. `src/hst/core/cycle.py` `set_pointer` writes the run key, and `current_ts` reads it. With a fence, `set_pointer` writes only if the fence of the pointer is not above the fence of the call. If it is above, `set_pointer` raises `StaleFence`.

### Kinds and states of a run

A `CycleRun` node holds the kind and the state of 1 run. `src/hst/core/cycle.py` `KINDS` holds the 4 kinds.

| Kind | Run |
|---|---|
| `full` | a run that collects each prepared source |
| `partial` | a run that collects a part of the prepared sources |
| `refresh` | 1 source that an operator starts |
| `device` | the device fetches of 1 window |

`src/hst/core/cycle.py` `begin_run` sets the state `building` before the first write of the run. `src/hst/core/cycle.py` `write_cycle_meta` sets the state `built`. A `CycleRun` node without a state reads as `built`. `write_cycle_meta` also writes the parent run in `parent` and the status of each source in 5 lists. The lists are `sources_fresh`, `sources_carried`, `sources_failed`, `sources_partial` and `sources_cancelled`.

`src/hst/app/runs_exec.py` `_building` calls `begin_run`. At the end of the build, it deletes the run with `src/hst/core/cycle.py` `discard_run` if the pointer does not hold the run key. [Code flow of a collection](collection-code-flow.md#sequence-of-a-run) gives the call order of a run.

### Carry

`src/hst/core/cycle.py` `carry_forward` copies objects from the parent run to the run. The parent run is the run of the pointer at the start of the build. The carry copies a node only if the run holds no node with the same uid.

`src/hst/app/runs_exec.py` `_carry_phase` gives `carry_forward` the session, the 2 run keys and these 5 arguments.

| Parameter | Content |
|---|---|
| `scopes` | the batch scope of each device or controller that did not load, with a reason |
| `collected` | the batch scope of each device or controller that loaded |
| `sources` | the name and the source type of each source of the carry |
| `unasked` | the part of `sources` that the run asked nothing |
| `section_labels` | the labels of the failed sections of each batch scope in `collected` |

A node of the parent run is in the carry in 4 cases:

1. The node has no `_sources`.
2. The `_scope` of the node is in `scopes`.
3. The node has no `_scope`, and 1 of its `_sources` is in `sources`.
4. The `_scope` of the node is outside `scopes` and `collected`, and 1 of its `_sources` is in `unasked`.

Case 2 to case 4 leave out a node with a `_scope` that is in `collected` and outside `scopes`.

A relationship of the parent run is in the carry if its 2 ends are in the run and 1 of these is true:

- 1 end is a copy of the carry.
- The `_scope` of the relationship is in `scopes`.

The carry leaves a relationship out in 2 cases:

- The run holds a relationship of the same type between the 2 nodes.
- The `_scope` of the relationship is `reasoner` or starts with `derived:`.

A copy holds the labels and the properties of the object in the parent run, without the labels `Latest` and `Retired` and with these changes:

| Property | Value on a copy |
|---|---|
| `collection_ts` | the run key of the run |
| `carried` | `true` |
| `carried_reason` | the reason, 1 of `src/hst/core/cycle.py` `CARRY_REASONS` |
| `last_seen_ts` | the `collected_at` of the object in the parent run |

A copy keeps `collected_at`, `_run_id`, `_scope` and `_sources`.

| Reason | Case |
|---|---|
| `failed` | The fetch or the load of the scope failed. |
| `not-run` | The run did not ask the scope. The carry also gives this reason to an object without a scope in `scopes`. |
| `cancelled` | An operator stopped the source. |
| `unchanged` | The payload or the batch of the scope is equal to the record of the device. |
| `section-failed` | The device loaded, and a section of its payload failed. |

For the reason `section-failed`, a collector declares labels for a section in `src/hst/collectors/base.py` `Collector.SECTION_LABELS`. If the section fails, the carry copies the nodes of the scope that have 1 of these labels.

For a device with an equal batch, `src/hst/collectors/base.py` `load_payload` writes a part of the batch. The carry copies the other objects of the device. [Code flow of a collection](collection-code-flow.md#load-of-one-payload) gives the part.

`src/hst/core/cycle.py` `_carry_contributions` handles a node that the run wrote without 1 of its sources of the parent run. The function acts if that source has a scope in `scopes` or is in `unasked`. It writes the fields and the `_assert.` lists of the source on the node. It adds the source to `_sources` and writes the pairs `<source>/<scope>` to `_carried_scopes`.

### Prune

`src/hst/core/cycle.py` `prune` deletes each run outside the graph window with `delete_run`. [Storage](storage.md#neo4j) gives the graph window, the retention counts and the jobs that call `prune`.

## Loader contract

`src/hst/core/loader.py` `load` writes 1 batch to 1 run. A collector returns a `src/hst/core/model.py` `Batch` with a source, a scope, node records and relationship records.

### Validation

`src/hst/core/model.py` `NodeRecord` and `src/hst/core/model.py` `RelRecord` reject 2 kinds of property key:

- the key `uid`
- a key that starts with `_`

The rule applies to the properties of a node record and to the properties and the keys of a relationship record. The 2 models also reject a field that the model does not define.

`Batch.validate_registry` rejects a batch in these cases:

| Case | Check |
|---|---|
| A uid has 2 values of an identity property. | `src/hst/core/labels.py` `check_identity` |
| The label of a node, or of an end of a relationship, is outside `LABELS`. | `src/hst/core/labels.py` `validate_label` |
| A node has no value for a property in `requires` of its label. | `src/hst/core/labels.py` `validate_props` |
| The relationship type is outside `RELS`. | `src/hst/core/labels.py` `validate_rel` |
| A `HAS_MTU` relationship starts at a label outside `MTU_SUBJECT_LABELS` or ends at a label other than `MtuObservation`. | `Batch.validate_registry` |
| A `HAS_MTU` relationship starts at another uid than the `subject_uid` of its `MtuObservation` node. | `Batch.validate_registry` |
| A key of a relationship record is outside `[A-Za-z_][A-Za-z0-9_]*`. | `Batch.validate_registry` |

`validate_props` reads `None` and the empty string as no value. An identity collision raises `IdentityCollision` at once. For each other case, the function collects the faults and raises 1 `ValueError`. [Graph schema](schema.md#node-labels) gives the `requires` properties of each label.

`src/hst/collectors/util.py` `GraphBuilder.batch` calls `validate_registry`, and `load` calls it again.

### Steps of a load

1. `load` calls `validate_registry`.
2. `_check_cycle_anchors` compares the `anchor` of each node with the run.
3. `load` writes the nodes of each label with `node_upsert_query`, in statements of 5000 rows.
4. After each statement of step 3, `load` writes the `_assert.` properties of the nodes that have a second source.
5. `load` writes the relationships of each type and key set with `rel_upsert_query`.
6. `load` writes the `CollectionRun` node with the counts of the load.

`rel_upsert_query` finds the 2 ends by `uid` and `collection_ts` in the run. If an end is not in the run, the statement writes no relationship. `load` counts the record in `rels_dropped_missing_endpoint` of `src/hst/core/model.py` `RunManifest` and adds an entry to `errors`. The loader deletes no node and no relationship.

`RunManifest` has 6 fields that no code sets: `nodes_retired`, `rels_retired`, `nodes_revived`, `rels_revived`, `retirement_skipped` and `rel_retirement_skipped`.

### Merge keys

The merge key of `src/hst/core/loader.py` `node_upsert_query` is the label string of `labels_clause`, `uid` and `collection_ts`. The merge key of `src/hst/core/loader.py` `rel_upsert_query` is the start node, the end node, the relationship type and each key of the record.

`rel_upsert_query` does not read the 2 labels of a relationship record. Without a key, 2 records of 1 type between the same 2 nodes are 1 relationship. With a key, each set of key values is 1 relationship. `src/hst/collectors/util.py` `connected_address` writes `ORIGINATES` with the key `proto`.

### Loader-owned properties

`node_upsert_query` writes the properties of the record first and then these properties.

| Property | On | Value | Code that sets the value |
|---|---|---|---|
| `uid` | node | the uid of the record | `node_upsert_query` |
| `collection_ts` | node, relationship | the run key | `node_upsert_query`, `rel_upsert_query` |
| `collected_at` | node, relationship | the parameter `ts_ms` of `load`, or the time of the load | `node_upsert_query`, `rel_upsert_query` |
| `carried` | node, relationship | `false` | `node_upsert_query`, `rel_upsert_query` |
| `carried_reason` | node, relationship | null | `node_upsert_query`, `rel_upsert_query` |
| `last_seen_ts` | node, relationship | null | `node_upsert_query`, `rel_upsert_query` |
| `_run_id` | node, relationship | the run id of the load | `node_upsert_query`, `rel_upsert_query` |
| `_scope` | node, relationship | the batch scope of the first load that wrote the object | `node_upsert_query`, `rel_upsert_query` |
| `_sources` | node | the list of the batch sources, in the order of the first write | `node_upsert_query` |
| `_assert.<field>` | node | the [source assertions](#source-assertions) of 1 field | `assertion_props`, `src/hst/core/cycle.py` `_carry_contributions` |
| `_carried_scopes` | node | the pairs `<source>/<scope>` of the carry | `src/hst/core/cycle.py` `_carry_contributions` |
| `ip_key` | `IpAddress`, `Endpoint` | the address key of `ip` | `src/hst/core/ipenc.py` `graph_address_props` |
| `lo_key`, `hi_key` | `Prefix` | the 2 address keys of `cidr` | `src/hst/core/ipenc.py` `graph_address_props` |

[Carry](#carry) gives the values of `carried`, `carried_reason` and `last_seen_ts` on a copy. `graph_address_props` keeps an address key that the record holds.

`load` uses the run id of its caller. Without one, the run id is `<source>-<time in milliseconds>-<8 hex digits>`.

### Batch scope

The batch scope is the string `scope` of a `Batch`. The format is `<collector type>:<partition>`. Each collector sets `src/hst/collectors/base.py` `Collector.scope` in its `__init__`.

| Source type | Batch scope |
|---|---|
| `nxos`, `iosxe`, `iosxr` | `<source type>:<host>` |
| `vyos` | `vyos:<host>` |
| `apic` | `apic:<fabric>` |
| `checkpoint` | `cp:<host>`, or `cp:<host>:<domain>` for a domain of a multi-domain server |
| `checkpoint_gateway` | `checkpoint-gateway:<slug(host)>:<slug(effective_observation_uid)>`, with the source name or `appliance` in place of an empty host |
| `equinix` | `equinix:<slug(source name)>`, or `equinix:fabric` without a source name |
| `manual` | `manual:<source name>`, or `manual:unnamed` without a source name |
| `nautobot` | `nautobot:<slug(host)>`, with `-` for each `.` |
| `ndo` | `ndo:<slug(host)>`, with `-` for each `.` |
| `netscaler` | `netscaler:<scope_name>` |
| `unifi` | `unifi:<slug(source name)>:<site>`, or `unifi:<site>` without a source name |
| `velocloud` | `velocloud:<slug(host of the URL)>` |
| `zia` | `zia:<slug(tenant)>` |
| `zpa` | `zpa:<slug(tenant)>` |

A collector of a group source has 1 scope for each device, except for `netscaler`. The `netscaler` scope holds the `scope_name` of the config and no host. A collector of an orchestrator source has 1 scope for the source. [Collectors](collectors.md#sources) describes the 2 kinds of source.

Code outside the collectors writes these fixed scopes.

| Scope | Object | Code |
|---|---|---|
| `meta:cycle` | the `CyclePointer` node | `src/hst/core/cycle.py` `set_pointer` |
| `meta:cycles` | each `CycleRun` node | `src/hst/core/cycle.py` `begin_run`, `src/hst/core/cycle.py` `write_cycle_meta` |
| `meta:runs` | each `CollectionRun` node | `src/hst/core/loader.py` `load` |
| `app:sites` | the `Site` node and the `LOCATED_IN` relationship of an operator assignment | `src/hst/core/cycle.py` `apply_site_assignments`, `src/hst/core/cycle.py` `carry_site_assignments` |
| `reasoner` | each relationship of a reasoner rule | `src/hst/reasoner/runner.py` `run` |
| `derived:rt-domains`, `derived:link-speed` | the 2 batches of `src/hst/core/reasoner.py` | `src/hst/core/reasoner.py` `execute_rt_domains`, `src/hst/core/reasoner.py` `execute_link_speed` |

This code reads the property `_scope`:

| Code | Use |
|---|---|
| `src/hst/core/loader.py` `assertion_props`, `src/hst/core/loader.py` `rival_writers` | the collector type of the first source of a node |
| `src/hst/core/cycle.py` `carry_forward` | the objects of the carry and their reason |
| `src/hst/core/cycle.py` `device_scopes`, `src/hst/core/cycle.py` `written_scopes` | the scope of the `Device` nodes of a device that did not load, in the parent run |
| `src/hst/core/cycle.py` `scope_collected_at`, `src/hst/core/cycle.py` `scopes_collected_at` | the highest `collected_at` of a scope in a run |
| `src/hst/core/cycle.py` `device_owner` | the manifest entry of the device that wrote an object, for `freshness_for` and for `src/hst/core/diff.py` |
| `src/hst/collectors/base.py` `SHARED_OBJECTS` | the nodes of an equal batch that have a second writer |
| `src/hst/core/cycle.py` `apply_site_assignments` | the delete of the `LOCATED_IN` relationship with the scope `app:sites` of a device that has no operator site |
| `src/hst/reasoner/runner.py` `run` | the delete of each relationship with the scope `reasoner` in the run |
| `src/hst/path/gates/firewall.py` `_RULEBASE_CANDIDATES`, `src/hst/path/gates/nat.py` `_NAT_RULES_QUERY_STRICT`, `src/hst/path/gates/nat.py` `_NAT_CREDITS_QUERY` | the join of a Check Point `Device` to a `FirewallInstance` whose `authority` is equal to the `_scope` of the device |
| `src/hst/path/gates/zpa.py` `_ACCESS_RULE_QUERY` | the ZPA rules without an application condition that apply to a segment of the same scope |
| `src/hst/path/gates/coverage.py` `_DEVICE_EVIDENCE` | the scope of a device in the coverage evidence |
| `src/hst/assessment/semantic.py` `_category` | the category `derived` for a scope that starts with `derived:` |

`src/hst/demo.py` and `src/hst/analysis_model/checkpoint_graph.py` hold the Check Point join. `src/hst/queries.py` and `src/hst/analysis_model/gates.py` hold the ZPA comparison.

`src/hst/collectors/base.py` `graph_sha` puts the batch scope in the digest of a batch. `load` writes the batch scope to the `CollectionRun` node and to `RunManifest.scope`.

## Derived elements

`src/hst/reasoner/runner.py` `run` writes the derived elements of 1 run. `src/hst/core/finalize.py` `finalize_derivations` calls `run` in the build of a run, before the run builder moves the pointer. [Code flow of a collection](collection-code-flow.md#sequence-of-a-run) gives the call order. `hst reason` without a subcommand stops with an error.

`run` runs each reasoner rule of `src/hst/reasoner/catalog.py` `RULES` in the order of the block below. [Code flow of a collection](collection-code-flow.md#rule-runner) gives the steps of `run`.

<!-- generated: reasoner-rules -->
1. `cable-from-uplink-record`
2. `cable-from-lldp-record`
3. `cable-from-neighbor-name`
4. `cable-from-endpoint-mac`
5. `cable-from-last-connection`
6. `fabric-port-from-description`
7. `edge-device-from-binding`
8. `zpa-zia-ip-same-as`
9. `zia-forwarding-to-zpa-segment`
10. `zia-forwarding-to-zpa-segment-group`
11. `zia-forwarding-to-zpa-server-group`
12. `zpa-segment-domain-to-dns`
13. `cable-from-fabric-circuit`
14. `gateway-from-router-interface`
15. `gateway-from-sole-firewall-interface`
16. `attached-from-vlan-binding`
17. `attached-from-cable`
18. `prefix-in-from-attachment`
19. `gateway-from-sole-segment-interface`
20. `bgp-peer-from-address`
21. `overlay-connection-ends`
<!-- end generated: reasoner-rules -->

A rule reads the nodes of the run and writes relationships with these properties.

| Property | Value |
|---|---|
| `rule` | the name of the rule |
| `derived` | `true` or `false` |
| `_scope` | `reasoner` |
| `source` | `reasoner`, with the exceptions below |
| `collection_ts` | the run key |
| `collected_at` | the parameter `ts_ms` of `run`, or the time of the call |

`source` is in the merge key of each rule. 4 rules write another value.

| Rule | `source` |
|---|---|
| `cable-from-uplink-record` | `unifi-uplink` |
| `cable-from-lldp-record` | `unifi-lldp` |
| `cable-from-neighbor-name` | `cdp` or `lldp` |
| `cable-from-fabric-circuit` | `equinix-circuit` |

7 rules set `derived` to `false`:

- `cable-from-uplink-record`
- `cable-from-lldp-record`
- `cable-from-neighbor-name`
- `zia-forwarding-to-zpa-segment`
- `zia-forwarding-to-zpa-segment-group`
- `zia-forwarding-to-zpa-server-group`
- `zpa-segment-domain-to-dns`

Each other rule that writes a relationship sets `derived` to `true`. `overlay-connection-ends` writes no relationship. It sets `observed_from` and `name` on `OverlayConnection` nodes, and `run` does not remove them.

After `run`, `finalize_derivations` writes more derived data:

- `src/hst/reasoner/arp_cables.py` `derive_arp_cables` writes `CONNECTED_TO` with the rule `cable-from-arp-port` and the properties of the table.
- `src/hst/core/reasoner.py` `execute_rt_domains` loads `RoutingDomain` nodes and `MEMBER_OF` relationships with the key `basis` and the value `rt-component`.
- `src/hst/core/reasoner.py` `execute_link_speed` loads `speed_mbps` and `speed_agreement` on `CONNECTED_TO` relationships.

The 2 loads use `src/hst/core/loader.py` `load` with the source `reasoner`. They set no property `derived` and no property `rule`. `hst reason rt-domains` and `hst reason link-speed` do the same 2 loads on the run of the pointer.

### Guards of `cable-from-endpoint-mac`

The rule `cable-from-endpoint-mac` of `src/hst/reasoner/catalog.py` `RULES` reads an `Endpoint` with a MAC address on a `Port`. It finds the `Interface` of the run with the same MAC address and the `Port` of that interface. It writes `(Port)-[:CONNECTED_TO]->(Port)` between the 2 ports under 3 guards.

1. The port of the endpoint has no other endpoint in the run.
2. The port of the endpoint has no neighbor record of a different device. The 3 neighbor properties are `last_conn_mac`, `lldp_neighbor_mac` and `uplink_mac`. Each one is absent, or holds the MAC address of the endpoint or of the device of the interface.
3. None of the 2 ports has a `CONNECTED_TO` relationship to a different port with a stated cable source or with `derived` false.

The MAC addresses of the device are the `mac` of each node with an `ON` relationship to the device, and the `mac` of the device. The rule also sets `infra` to true on the endpoint.

## Engine contracts

`tests/test_schema_contract.py` holds the checks of the contracts between the collectors and the engine. `src/hst/core/labels.py` holds the constants of the contracts. [Vocabularies](schema.md#vocabularies) lists the vocabularies, and [Gate bindings](schema.md#gate-bindings) lists the gate bindings.

| Contract | Tests |
|---|---|
| Each gate label has an entry in `GATE_BINDINGS`, and each entry is a gate label. An entry with `NOT_DEVICE_BOUND` has a reason. | `test_every_gate_label_declares_its_binding_or_its_exemption` |
| A reason that gives a module or a function gives one that exists. | `test_not_device_bound_reasons_naming_an_evaluator_reference_real_symbols`, `test_zpa_access_rule_reason_names_the_real_evaluator` |
| A binding pattern starts at `(d)`, holds `(g)` and uses registered labels and relationship types. | `test_binding_patterns_use_registered_labels_and_relationships` |
| `src/hst/path/gates/__init__.py` `gate_safeguard_query` holds each device-bound gate label and a `_retired_at` filter for each hop of its patterns. | `test_safeguard_query_is_generated_from_the_registry` |
| `FWRULEBASE_KINDS`, `NATRULE_KINDS` and `MATCH_CONTEXTS` hold the values of the test. The 2 tunnel end types are in `RELS`. | `test_closed_vocabularies_are_declared` |
| A `NetObject` that a `FwRule` matches has a `RESOLVES_TO` relationship to a `Prefix`, `IpAddress` or `DnsRecord` node, a `ranges` list or `opaque`. | `test_vyos_rule_objects_carry_addresses_by_resolves_to`, `test_unifi_zone_policy_objects_carry_addresses_by_resolves_to`, `test_unifi_classic_rule_objects_carry_addresses_by_resolves_to`, `test_checkpoint_rule_objects_carry_addresses_by_resolves_to`, `test_cisco_interface_acl_rule_objects_carry_addresses_by_resolves_to` |
| An `Endpoint` gives its addresses as `HAS_IP` relationships to `IpAddress` nodes and has no property `ip`. | `test_apic_endpoints_carry_addresses_by_has_ip`, `test_aci_gate_resolves_endpoints_through_has_ip` |
| The APIC collector writes each `FilterEntry` property that the ACI gate reads. | `test_apic_filter_entries_use_the_property_names_the_gate_reads` |
| `GATEWAY_ROLES` of the reasoner is a part of `DEVICE_ROLES`. | `test_gateway_roles_is_a_subset_of_device_roles` |
| Each `Device.role` of a collector batch is in `DEVICE_ROLES`. | `test_cisco_common_device_roles_are_registered`, `test_iosxe_device_roles_are_registered`, `test_nxos_device_roles_are_registered`, `test_iosxr_device_roles_are_registered`, `test_vyos_device_roles_are_registered`, `test_unifi_device_roles_are_registered`, `test_checkpoint_device_roles_are_registered`, `test_manual_device_roles_are_registered`, `test_nautobot_device_roles_are_registered`, `test_apic_device_roles_are_registered` |
| An `OspfAdjacency` has an `ENDPOINT` relationship to an `Interface`. An `IN_AREA` relationship goes from an `Interface` to an `OspfArea`. | `test_nxos_ospf_objects_use_registered_labels_and_relationship_types`, `test_vyos_ospf_objects_use_registered_labels_and_relationship_types`, `test_apic_ospf_objects_use_registered_labels_and_relationship_types` |
| The table `ospf_lsdb` of IOS-XE and IOS-XR has the status `complete` with an OSPF process and `unsupported` with a reason without one. | `test_iosxe_and_iosxr_ospf_lsdb_table_is_captured_or_not_captured_with_a_reason` |
| `DEPENDENCY_GROUP_KINDS` is equal to the keys of `src/hst/assessment/evaluation.py` `_GROUP_KIND_TO_CONDITION`. | `test_the_dependency_group_kinds_are_the_ones_the_endpoint_maps` |
| `identity_scope` and `app_scope` of a ZPA rule are in `ZPA_RULE_SCOPES`. | `test_zpa_rule_scopes_use_the_registered_vocabulary` |
| A ZPA access rule has a `FOR` relationship and an identity relationship only for the operands of its positive condition blocks. | `test_zpa_rule_edges_follow_their_positive_condition_blocks` |
| `action` of a `ZpaAccessRule` is in `ZPA_ACCESS_ACTIONS`. | `test_zpa_access_actions_use_the_registered_vocabulary` |

The file has no test that reads a batch of `velocloud`, `zia`, `netscaler`, `ndo`, `equinix` or `checkpoint_gateway`.
