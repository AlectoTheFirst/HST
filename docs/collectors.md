# Collectors

## Sources

`src/hst/collectors/base.py` `REGISTRY` maps each source type to its collector class. `src/hst/collectors/base.py` `register` adds a class to the map. The import of the package `src/hst/collectors` registers each collector of this table.

<!-- generated: sources -->
| Source type | Kind | Class | Module | Side-store tables | Also in the graph |
|---|---|---|---|---|---|
| `apic` | orchestrator | `ApicCollector` | `src/hst/collectors/apic.py` | `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |  |
| `checkpoint` | orchestrator | `CpCollector` | `src/hst/collectors/checkpoint.py` | `checkpoint_envelopes` |  |
| `checkpoint_gateway` | group | `CpGatewayCollector` | `src/hst/collectors/checkpoint_gateway.py` | `rib`, `arp` |  |
| `equinix` | orchestrator | `EquinixCollector` | `src/hst/collectors/equinix.py` |  |  |
| `iosxe` | group | `IosxeCollector` | `src/hst/collectors/iosxe.py` | `rib`, `mac`, `arp`, `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |  |
| `iosxr` | group | `IosxrCollector` | `src/hst/collectors/iosxr.py` | `rib`, `mac`, `arp`, `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |  |
| `manual` | orchestrator | `ManualCollector` | `src/hst/collectors/manual.py` |  |  |
| `nautobot` | orchestrator | `NautobotCollector` | `src/hst/collectors/nautobot.py` |  |  |
| `ndo` | orchestrator | `NdoCollector` | `src/hst/collectors/ndo.py` |  |  |
| `netscaler` | group | `NetScalerCollector` | `src/hst/collectors/netscaler.py` |  |  |
| `nxos` | group | `NxosCollector` | `src/hst/collectors/nxos.py` | `rib`, `mac`, `arp`, `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |  |
| `unifi` | orchestrator | `UnifiCollector` | `src/hst/collectors/unifi.py` |  |  |
| `velocloud` | orchestrator | `VeloCloudCollector` | `src/hst/collectors/velocloud.py` | `bgp_sessions`, `rib` |  |
| `vyos` | group | `VyosCollector` | `src/hst/collectors/vyos.py` | `rib`, `arp`, `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` | `rib` |
| `zia` | orchestrator | `ZiaCollector` | `src/hst/collectors/zia.py` |  |  |
| `zpa` | orchestrator | `ZpaCollector` | `src/hst/collectors/zpa.py` |  |  |
<!-- end generated: sources -->

Each collector class sets `KIND` to `group` or `orchestrator`. The function `register` raises `TypeError` for a class with another value. `src/hst/app/sources.py` `kind_of` returns the kind of a source type.

A group source holds the credentials for a list of devices. 1 collector fetches 1 device. [Devices of a group](#devices-of-a-group) describes the device list.

An orchestrator source has no device list. 1 collector fetches the source. The devices of the source are the `Device` nodes that `normalize` writes from the payload. [Reported location](#reported-location) describes how such a device gets a site.

A collector implements 3 methods of `src/hst/collectors/base.py` `Collector`.

| Method | Result |
|---|---|
| `fetch` | the payload |
| `normalize` | a `src/hst/core/model.py` `Batch` of nodes, relationships, [section outcomes](#section-outcomes-and-table-outcomes) and warnings |
| `probe` | a status text. The method loads no data |

A collector with a [side-store](storage.md#side-store) table also implements `side_tables` and can implement `table_outcomes`. [Device commands](device-commands.md) lists each command and each API read. [Graph schema](schema.md#properties-and-relationships) lists the properties of each label. [New collector](new-collector.md) gives the steps to add a collector.

## Source types

[Graph schema by source type](schema-by-source-type.md) has each label, each property and each relationship that a source type writes.

Each section gives the fields that the `ConfigModel` adds to the base models of [Config model](#config-model). A limit is a thing that the collector does not read or does not settle. [Batch scope](conventions.md#batch-scope) gives the batch scope of each source type. [Device identity](conventions.md#device-identity) gives the identifiers for the uid of a `Device`.

### `apic`

`src/hst/collectors/apic.py` `ApicCollector` reads 1 ACI fabric through the REST API of the APIC. `ApicCollector._login` sends the user name and the password and stores the token in the cookie `APIC-cookie`. `_keep_alive` runs before each page. After 0.66 of the token lifetime it asks for a token refresh, and it logs in again if the refresh fails. `_get_class` reads 1 class in pages of 1000 objects in the order of `dn`. If the pages hold fewer objects than `totalCount`, the read fails.

| Item | Values |
|---|---|
| Classes of `CLASSES` | `fabricNode`, `topSystem`, `l1PhysIf`, `lldpAdjEp`, `pcAggrIf`, `cdpAdjEp`, `fvTenant`, `fvAp`, `fvAEPg`, `fvBD`, `fvSubnet`, `fvCtx`, `fvRsCtx`, `fvRsBd`, `vzBrCP`, `vzSubj`, `vzRsSubjFiltAtt`, `vzRsFiltAtt`, `vzRsSubjGraphAtt`, `vzFilter`, `vzEntry`, `fvRsProv`, `fvRsCons`, `l3extOut`, `l3extInstP`, `vnsAbsGraph`, `vnsGraphInst`, `vnsSvcRedirectPol`, `vnsRedirectDest`, `fvCEp`, `fvIp`, `fvRsPathAtt`, `fvRsDomAtt`, `ospfDom`, `ospfArea`, `ospfIf`, `ospfAdjEp` |
| Classes of `CONTRACT_BYPASS_CLASSES` | `vzAny`, `vzRsAnyToProv`, `vzRsAnyToCons`, `vzRsAnyToConsIf`, `fvESg`, `fvRsScope` |
| Classes of `BGP_CLASSES`, unless `capture_bgp` is `none` | `bgpPeerEntry`, `bgpPeerAfEntry` |
| Classes of `MTU_CLASSES`, with `capture_mtu` | `l2InstPol`, `l3extRsPathL3OutAtt`, `l3extVirtualLIfP`, `pcRsMbrIfs` |
| Sections | `policy`, `endpoint`, `mtu:<class>` for each class of `MTU_CLASSES`, `mtu:operational`, `mtu:member_state` |
| Labels | `AciFilter`, `AppProfile`, `BridgeDomain`, `Contract`, `ContractSubject`, `Device`, `DvPortgroup`, `Endpoint`, `Epg`, `ExtEpg`, `Fabric`, `FilterEntry`, `Interface`, `IpAddress`, `L3Out`, `Lag`, `MtuObservation`, `OspfAdjacency`, `OspfArea`, `PbrDest`, `PbrPolicy`, `Pod`, `Port`, `Prefix`, `RoutingProcess`, `ServiceGraphInstance`, `ServiceGraphTemplate`, `Tenant`, `VrfInstance` |
| `SIDE_TABLES` | `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |
| `AUTHORITATIVE_SECTIONS` | none |

| Field | Default | Use |
|---|---|---|
| `url` | no default | the base URL |
| `auth` | no default | a `user_password` login |
| `fabric` | no default | the fabric name in the batch scope and in the uids of `src/hst/core/uid.py` `aci` and `fabric` |
| `capture_mtu` | `false` | the reads of `MTU_CLASSES` |
| `tls` | `TlsConfig` defaults | the TLS settings |

If the read of a class of `CLASSES` fails, the fetch fails. If the read of a class of `CONTRACT_BYPASS_CLASSES` fails, the payload does not hold the class. The property `contract_bypass` of each `VrfInstance` then has the value `not-collected`. A failed read of a class of `BGP_CLASSES` or `MTU_CLASSES` stores an outcome, and the fetch continues.

Limits:

- `src/hst/collectors/apic.py` `bgp_side_rows` makes rows only for the table `bgp_sessions`. The tables `ospf_lsdb` and `bgp_session_routes` have no row writer. `ApicCollector.table_outcomes` returns `not-captured` for the 2 tables.
- For `capture_bgp`, the values `all` and `sessions` give the same reads.
- A `bgp_sessions` row has no uptime, no prefix count and no capability list. `_BGP_AF_SAFI` holds the address families `ipv4-ucast` and `ipv6-ucast`.
- The collector does not read the intra-EPG isolation of an EPG. `src/hst/path/gates/aci.py` `aci_contract_verdict` gives an intra-EPG flow the reason `intra-EPG flow; intra-EPG isolation is not collected`.
- The collector reads `vzAny` with its preferred group and the ESG scope only as flags in `contract_bypass`.
- From an L3Out, the collector reads `l3extOut` and `l3extInstP`. With `capture_mtu`, it also reads `l3extRsPathL3OutAtt` and `l3extVirtualLIfP`.
- The section `mtu:operational` and the section `mtu:member_state` always get `unsupported`.

### `checkpoint`

`src/hst/collectors/checkpoint.py` `CpCollector` reads 1 Check Point management server or 1 domain of a Multi-Domain Server through the Web API. `CpCollector._login` sends an API key or a user name with a password, the field `domain` if it has a value, and `read-only` true. It sets the `sid` of the answer in the header `X-chkp-sid`. `_post` logs in again after 2/3 of the session timeout and after a refused session. `fetch` and `probe` log out when they end. `_paged` reads pages of 100 objects, the value of `PAGE_LIMIT`.

| Item | Values |
|---|---|
| Operations of `READ_COMMANDS` | `show-gateways-and-servers`, `show-access-layers`, `show-access-rulebase`, `show-packages`, `show-nat-rulebase`, `show-api-versions`, `show-last-published-session`, `show-global-properties` |
| Operation outside `READ_COMMANDS` | `show-package` |
| Sections | `access`, `nat`, `installation`, `mtu` |
| Labels | `CpPolicyObject`, `CpPolicyPackage`, `Device`, `FwRule`, `FwRulebase`, `IpAddress`, `NatRule`, `NetObject`, `Prefix`, `RedundancyGroup`, `SvcObject` |
| `SIDE_TABLES` | `checkpoint_envelopes` |
| `AUTHORITATIVE_SECTIONS` | none |

`show-access-rulebase` runs for each layer. `show-nat-rulebase` and `show-package` run for each package. A row of `checkpoint_envelopes` holds the uid, the label, the API object as JSON and its SHA-256.

| Field | Default | Use |
|---|---|---|
| `host` | no default | the address of the management server |
| `port` | `443` | the HTTPS port |
| `auth` | no default | an `api_key` login or a `user_password` login |
| `domain` | empty | the domain of a Multi-Domain Server |
| `tls` | `TlsConfig` defaults | the TLS settings |

`normalize_checkpoint` binds a rulebase to a gateway with an `ENFORCES` relationship. `_package_targets` reads the installation targets of each package from the `show-package` answer.

| Case | Property of `ENFORCES` |
|---|---|
| 1 package has the gateway as a target | `configured` true |
| 2 or more packages have the gateway as a target | `approximate` true |
| `show-packages` failed | `approximate` true from each firewall to each layer that is no inline layer |
| `show-package` failed for each package | `approximate` true from each firewall to each layer |
| `show-package` failed for a package, and the payload holds the answer for another package | `approximate` true from each firewall to each layer that is in no package of the payload and is no inline layer |

In the last case, a layer of a package of the payload that is no inline layer gets more bindings. Each one has `approximate` true and comes from a firewall that is no cluster member and no target of a package.

After such a failure, the sections `nat` and `installation` get `failed`.

`CpCollector._cached_pages` returns the rulebase pages of a layer from the replay cache if the key is equal. The key holds the uid of the last published session, the last change time of the layer and its last modifier. [Storage](storage.md#raw-store) gives the path of the cache files.

Limits:

- The collector reads 1 domain. It does not list the domains of a Multi-Domain Server.
- `show-access-rulebase` does not return the implied rules.
- The package targets are configuration. The section `installation` gets `unknown` with the text `Management package targets are configured evidence only; Gaia installation observation required`.
- The section `mtu` always gets `unsupported`.
- An object of a kind of `_CP_OPAQUE_KINDS` gets a reason text and no address set. The kinds are `access-role`, `security-zone`, `dns-domain`, `updatable-object`, `dynamic-object`, `wildcard` and `group-with-exclusion`.
- A rule with an entry that is not Any in the column `vpn`, `time` or `content` gets a reason text that starts with `the rule is scoped by`.
- An `install-on` entry that is no gateway object of the payload sets `install_on_unresolved` on the rule.
- The collector follows nested groups to a depth of 16, the value of `_GROUP_DEPTH`.
- The ICMP type of a NAT service gets a reason text. A translated service that is no TCP or UDP service with a port also gets a reason text.
- A `NatRule` and a NAT `FwRulebase` have no row in `checkpoint_envelopes`.
- The payload key `replayed_layers` lists the layers from the replay cache. No code reads the key.

### `checkpoint_gateway`

`src/hst/collectors/checkpoint_gateway.py` `CpGatewayCollector` reads 1 Gaia appliance over SSH. `_expert_command` puts `vsenv <vsid> >/dev/null &&` before each command of a virtual system. For a `clish` command it also adds `set virtual-system <vsid>`. The collector sends no `expert` command.

`_device_uid` resolves the appliance with the reference `<authority>:<appliance uid>`. If the 2 parts are the batch scope of the `checkpoint` source and the uid of its gateway object, the 2 sources write 1 `Device`. Without the field `appliance_uid` and without a gateway object that matches, the appliance uid is the host of this source.

| Item | Values |
|---|---|
| Commands of `COMMANDS` | `VERSION_COMMAND`, `HOSTNAME_COMMAND`, `VSX_STAT_COMMAND` |
| Reads for each VSID | `interfaces`, `routes4`, `routes6`, `installation`, `links`, `neighbors4`, `neighbors6`, `cluster`, `proxy_arp`, `fw_interfaces`, `bridge_groups`, `bridge_members` |
| Reads for each VSID with `capture_bgp` | `bgp_as`, `bgp_peers`, `bgp_config`, `bgp_routemaps` |
| Sections | `interfaces`, `routes`, `installation`, `neighbors`, `topology`, `bgp` |
| Labels | `BgpSession`, `BridgeDomain`, `Device`, `Endpoint`, `FirewallInstance`, `Interface`, `IpAddress`, `Lag`, `PolicyInstallation`, `Port`, `Prefix`, `RoutePolicy`, `RoutePolicyEntry`, `RoutingProcess`, `VlanInstance`, `VrfInstance` |
| `SIDE_TABLES` | `rib`, `arp` |
| `AUTHORITATIVE_SECTIONS` | `show version osedition` |

If `VERSION_COMMAND` fails, the fetch fails. The VSID list is the field `gateway_contexts`. Without a value, it holds the number at the start of each line of the `vsx stat -v` answer that starts with a number. The payload holds the outcome of each read under `vs:<vsid>:<read>`. `_captured_section` gets the status of the 5 sections `interfaces`, `routes`, `neighbors`, `topology` and `bgp` from these outcomes. If a JSON read fails, the fetch sends the text command of `src/hst/collectors/checkpoint_iproute.py` `COMMANDS` for the same read.

A virtual system and a bridge get a `FirewallInstance`. A virtual router, a virtual switch and the VSID 0 get a `Device`. `src/hst/collectors/checkpoint_topology.py` `topology` writes a `CARRIES` relationship from the parent `Port` of a VLAN interface to its `VlanInstance`.

| Field | Default | Use |
|---|---|---|
| `estate` | no default | the estate name in the uid of each `FirewallInstance` |
| `evidence_file` | empty | the path of a JSON file of version 1 with a maximum of 32 MiB. `read_evidence` reads the warp links, the bridge groups, the installations and the sessions from it |
| `management_source` | empty | the name of the `checkpoint` source of the appliance |
| `management_authority_uid` | empty | a batch scope of a `checkpoint` source, in place of the batch scope of the row `management_source` |
| `management_domain_uid` | empty | a domain uid in place of the domain uid of the management payload |
| `appliance_uid` | empty | the uid of the appliance object of the management server |
| `observation_uid` | empty | the name of the observation in the batch scope. Without a value, it is the source name |
| `management_host` | empty | the host of the batch scope of the `checkpoint` source, if the source has no management link and no `management_authority_uid` |
| `management_domain` | empty | the domain of that batch scope, together with `management_host` |
| `gateway_release` | empty | a release in place of the release of the version answer |
| `gateway_contexts` | empty | the VSID list |
| `capture_bgp` | `true` | the 4 BGP reads. The field is a boolean in this model |
| `cluster_mode` | `auto` | `auto`, `standalone` or `cluster` |
| `vsid_gateway_object_uids` | empty | a map from a VSID to the uid of its management object |
| `expert_shell_account` | no default | the account with an Expert shell. It must be equal to `auth.username` |
| `read_only_profile` | `checkpoint-gaia-vsx-expert-account-r81.20-v1` | a fixed value. The collector does not read the field |
| `management_link` | empty | `link_sources` sets the field |

The model needs `management_source`, or `management_authority_uid` together with `appliance_uid`. `CpGatewayCollector.link_sources` finds the row of `management_source` and writes its name, host, domain and batch scope to `management_link`. `management_inventory` reads the gateway objects from the newest raw file of that source. `src/hst/collectors/checkpoint_identity.py` `resolve_identity` then finds the management object of the appliance and of each VSID. `normalization_inputs` adds these objects to the inputs of the payload hash.

Limits:

- No section of the batch has the name of `AUTHORITATIVE_SECTIONS`. No section status gives the device the verdict `failed`.
- An empty VSID list gives the gap text `gateway contexts missing, empty or malformed; VS discovery is not complete`. The sections `interfaces`, `routes` and `neighbors` then get `failed`.
- The fetch writes no key `installations` to a context of the payload. After a fetch, a `PolicyInstallation` comes only from `evidence_file`. Without an installation and without a gap, the section `installation` gets `unknown` with the text `fw stat -s did not prove an exact installed revision`.
- A VSID without a name in the `vsx stat -v` answer and without an entry in `vsid_gateway_object_uids` gives the gap text `lacks an authoritative management-object mapping`. The collector does not write such a VSID.
- If the name of a VSID matches no management object, `resolve_identity` uses the name as the object uid and adds a warning.
- `_route_rows` does not write a route of a routing table that is not the main table.
- The fetch removes each line with `authtype` from the `bgp_config` answer before it stores the payload.
- No code in `normalize` reads `proxy_arp`, `fw_interfaces` and `bridge_groups`.
- Without `capture_bgp`, the section `bgp` gets `unknown`.

### `equinix`

`src/hst/collectors/equinix.py` `EquinixCollector` reads the Fabric ports and the connections of 1 Equinix account over HTTPS. `EquinixCollector._client` sends the client id and the client secret to `TOKEN_PATH` and sets the `access_token` of the answer as a bearer token. A fetch uses 1 token.

`EquinixCollector._pages` reads each list in pages of `page_size` items until the count of `pagination.total`. If a page is empty before that count, the fetch fails.

| Item | Values |
|---|---|
| Reads | the ports, the connection search for the port uuids |
| Reads with `network_edge` | the Network Edge devices, the device link groups, the connection search for the device uuids |
| Sections | `connections`, and with `network_edge` the 3 sections `network_edge_devices`, `network_edge_links` and `network_edge_connections` |
| Labels | `Provider`, `FabricPort`, `VirtualCircuit`, `Site`, and with `network_edge` also `Device`, `Interface` and `Port` |
| `SIDE_TABLES` | none |
| `AUTHORITATIVE_SECTIONS` | `ports`, `connections` |

| Field | Default | Use |
|---|---|---|
| `api_url` | `https://api.equinix.com` | the base URL |
| `auth` | no default | an `oauth_client` login |
| `tls` | `TlsConfig` defaults | the TLS settings |
| `ibx_sites` | empty | 1 line for each IBX: `IBX, site_code`. A port in that IBX gets a `Site` node and `LOCATED_IN` |
| `port_bindings` | empty | 1 line for each Fabric port: `fabric port uuid, device port uid`. The port gets `bound_port_uid` and `REALIZED_BY` |
| `page_size` | `100` | the item count of a page, from 1 to 1000 |
| `network_edge` | `false` | the reads of Network Edge |
| `edge_device_bindings` | empty | 1 line for each Network Edge device of another source: `network edge device uuid or name, device uid` |

`src/hst/collectors/util.py` `parse_pairs` reads the 3 fields with lines. It ignores an empty line and a line that starts with `#`. A key in 2 lines is an error.

The port read and the first connection search are necessary. A Network Edge read with an HTTP error status gets the section status `unauthorized` for 401 and 403 and `failed` for each other status. Then the section `connections` gets `failed`, and the verdict of the source is `failed`.

Limits:

- `src/hst/collectors/equinix.py` `normalize_equinix` records no outcome for the section `ports` and records `connections` only as `failed`.
- The collector does not filter the connections on their state. A deprovisioned connection is a `VirtualCircuit` with its `state`.
- An end of a connection on a port outside the port list of the account has no `A_END` or `Z_END` relationship.
- For a connection to a service profile, the `VirtualCircuit` holds the provider name in `provider`. The collector writes no cloud object.
- A port binding writes no `Port` node. A device binding writes no `Device` node for the bound uid.
- A port in an IBX without a line in `ibx_sites` gets no `LOCATED_IN`.
- `_without_secrets` removes each key that holds a word of `_EDGE_SECRET_KEYS` from the Network Edge device pages and link pages before `fetch` returns.
- A binding line without a match in the account gives a warning in `Batch.warnings`.

### `iosxe`

`src/hst/collectors/iosxe.py` `IosxeCollector` reads 1 IOS-XE device over SSH. [SSH collector base classes](#ssh-collector-base-classes) describes the fetch and the parse. `src/hst/collectors/cli_parse.py` `parse` parses the text answers with the platform `cisco_ios`. After the commands of `COMMANDS`, `_afetch_over` sends the ARP command for each VRF, the BGP commands, the MTU commands and the match list commands.

| Item | Values |
|---|---|
| Sections with a necessary command | `device`, `interfaces`, `vrfs`, `rib` |
| Sections with an optional command | `vrf_detail`, `arp`, `lldp`, `cdp`, `nat`, `nat_stats`, `acl`, `bgp`, `prefix_lists`, `route_maps`, `interface_config`, `vlan_filter`, `ospf`, `ospf_interfaces`, `ospf_neighbors`, `ospf_lsdb_router`, `ospf_lsdb_network`, `ospf_lsdb_summary`, `ospf_lsdb_asbr_summary`, `ospf_lsdb_external`, `ospf_lsdb_nssa_external`, `ospf_config`, `hsrp`, `vrrp` |
| MTU sections | `mtu_ipv4`, `mtu_ipv6`, `mtu_system`, `mtu_members` |
| Labels | `BgpPeerRange`, `BgpSession`, `BridgeDomain`, `Device`, `FhrpGroup`, `FwRule`, `FwRulebase`, `Interface`, `IpAddress`, `Lag`, `MatchListEntry`, `MtuObservation`, `NatRule`, `NetObject`, `OspfAdjacency`, `OspfArea`, `Port`, `Prefix`, `PrefixListEntry`, `RoutePolicy`, `RoutePolicyEntry`, `RouteTarget`, `RoutingDomain`, `RoutingProcess`, `SvcObject`, `VlanInstance`, `VrfInstance` |
| `SIDE_TABLES` | `rib`, `mac`, `arp`, `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |
| `AUTHORITATIVE_SECTIONS` | `device`, `interfaces`, `vrfs`, `rib` |

`IosxeConfig` adds the field `capture_mtu` with the default `false` to `SshSourceConfig`.

Limits:

- The table `mac` has no writer. `IosxeCollector.table_outcomes` returns `not-captured` with the text `the IOS-XE collector reads no MAC table`.
- The collector reads 1 address for each interface and no secondary address.
- The collector reads no trunk membership and writes no `CARRIES` relationship.
- The collector does not read the zone-based firewall. With zones in the configuration, the section `interface_config` gets `partial` with a detail text that ends with `zone-pair inspect policies are not modeled`.
- An ACE with an object group gets a reason text that ends with `which is not collected`. A wildcard mask that is no prefix gets a reason text.
- `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` gives a reason text to an IPv6 access list, a MAC access list and a VLAN access map.
- A NAT rule with a route map gets `approximate` and no address relationship.
- The BGP session read and the BGP path commands use IPv4 unicast only.
- The route command reads the IPv4 routes of each VRF. The collector reads no IPv6 route.
- If the ARP read of a VRF fails, the section `arp` gets `partial`.
- If the route template leaves lines unread, the section `rib` gets `partial`.

### `iosxr`

`src/hst/collectors/iosxr.py` `IosxrCollector` reads 1 IOS-XR device over SSH. [SSH collector base classes](#ssh-collector-base-classes) describes the fetch and the parse. `src/hst/collectors/cli_parse.py` `parse` parses the text answers with the platform `cisco_xr`. After the commands of `COMMANDS`, `_afetch_over` sends the BGP commands and the MTU commands. If a route policy uses a set, it also sends `CMD_COMMUNITY_SET` and `CMD_AS_PATH_SET`.

| Item | Values |
|---|---|
| Sections with a necessary command | `device`, `inventory`, `interfaces`, `vrfs`, `rib` |
| Sections with an optional command | `hostname`, `arp`, `lldp`, `cdp`, `bgp`, `prefix_sets`, `route_policies`, `ospf`, `ospf_interfaces`, `ospf_neighbors`, `ospf_lsdb_router`, `ospf_lsdb_network`, `ospf_lsdb_summary`, `ospf_lsdb_asbr_summary`, `ospf_lsdb_external`, `ospf_lsdb_nssa_external`, `ospf_config`, `hsrp`, `interface_config` |
| MTU sections | `mtu_ipv4`, `mtu_ipv6`, `mtu_config`, `mtu_members` |
| Labels | `BgpPeerRange`, `BgpSession`, `Device`, `FhrpGroup`, `FwRule`, `FwRulebase`, `Interface`, `IpAddress`, `Lag`, `MatchListEntry`, `MtuObservation`, `NetObject`, `OspfAdjacency`, `OspfArea`, `Port`, `Prefix`, `PrefixListEntry`, `RoutePolicy`, `RoutePolicyEntry`, `RouteTarget`, `RoutingDomain`, `RoutingProcess`, `VrfInstance` |
| `SIDE_TABLES` | `rib`, `mac`, `arp`, `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |
| `AUTHORITATIVE_SECTIONS` | `device`, `inventory`, `interfaces`, `vrfs`, `rib` |

`IosxrConfig` adds the field `capture_mtu` with the default `false` to `SshSourceConfig`.

The serial of the device is the `sn` of the entry `Rack 0` of the inventory. Without that entry, the device has no serial.

Limits:

- The table `mac` has no writer. `IosxrCollector.table_outcomes` returns `not-captured` with the text `the IOS-XR collector reads no MAC table`.
- The collector reads no NAT configuration, no VLAN, no trunk membership and no vPC.
- The collector reads HSRP and no VRRP.
- The collector reads the access group of each interface and not the entries of the access lists. The rulebase of an IPv4 access group holds 1 rule. The reason text of its `NetObject` starts with `the access list this interface is bound to was not collected`.
- `SECTION_LABELS` holds `SvcObject` for the section `interface_config`, and no code of this family writes that label.
- The collector reads 1 address for each interface.
- The BGP session read and the BGP path commands use IPv4 unicast only.
- The route command reads the IPv4 routes of each VRF. The collector reads no IPv6 route.
- If the route template leaves lines unread, the section `rib` gets `partial`.

### `manual`

`src/hst/collectors/manual.py` `ManualCollector` has no transport. `fetch` returns a payload with the text of the field `devices`. `normalize` writes 1 `Device` for each line and an `IpAddress` for each management address.

| Item | Values |
|---|---|
| Sections | `mtu:import` |
| Labels | `Device`, `IpAddress`, `MtuObservation` |
| `SIDE_TABLES` | none |
| `AUTHORITATIVE_SECTIONS` | none |

| Field | Default | Use |
|---|---|---|
| `devices` | no default | 1 device in each line: `hostname, mgmt_ip, platform, role, serial`. Only `hostname` is necessary. A line that starts with `#` is a comment |
| `mtu_evidence` | empty | JSON text of `src/hst/collectors/mtu_import.py` `MtuImport` with a maximum of 512 observations and 1 MiB |

With `mtu_evidence`, `fetch` and `probe` do a check that the published run holds each subject of the import. `normalize` raises `ValueError` if the payload does not hold these subjects.

Limits:

- A device without a role gets the role `unknown`.
- The subject of an MTU observation has 1 of these labels: `Endpoint`, `Interface`, `Port`, `Pnic`, `Vnic`, `Dvs`, `DvPortgroup`, `Tunnel`. The import creates no subject.

### `nautobot`

`src/hst/collectors/nautobot.py` `NautobotCollector` reads 1 Nautobot through its GraphQL API. The client sends the API key in the header `Authorization` of each request. `_paged` reads each query in pages of 100 objects.

| Item | Values |
|---|---|
| Queries | `LOCATIONS_QUERY`, `RACKS_QUERY`, `DEVICES_QUERY`, `CABLES_QUERY`, `IP_ADDRESSES_QUERY`, and `DEVICES_QUERY` with the field `mtu` if `capture_mtu` is true |
| Sections | `mtu`, `mtu:operational`, `ipam:addresses` |
| Labels | `Rack`, `Device`, `Port`, `VrfInstance`, `IpAddress`, `MtuObservation` |
| `SIDE_TABLES` | none |
| `AUTHORITATIVE_SECTIONS` | none |

| Field | Default | Use |
|---|---|---|
| `url` | no default | the base URL |
| `auth` | no default | an `api_key` login |
| `tls` | `TlsConfig` defaults | the TLS settings |
| `capture_mtu` | `false` | the read of the interface MTU |
| `mtu_basis` | `unknown` | the meaning of the MTU value: `unknown`, `ip_packet`, `ethernet_frame_excluding_fcs` or `ethernet_frame_including_fcs` |

With `mtu_basis` `unknown`, an `MtuObservation` has the metric `unknown`. With `ip_packet`, an interface gets 1 observation for IPv4 and 1 for IPv6. With the 2 other values, the metric is `l2_max_frame_bytes`.

Limits:

- The collector writes no node for a location. The id and the name of the location of a device are its reported location.
- The collector does not write an interface whose type holds `virtual`, `lag` or `bridge`.
- Only a cable with 2 ends that are interfaces becomes a `CONNECTED_TO` relationship.
- The collector does not write an IP address without a VRF.
- The queries read no VLAN and no prefix.
- The collector does not write a device without a serial and without a name.
- If the read of the IP addresses fails, the section `ipam:addresses` gets `failed` and the fetch continues.
- The section `mtu:operational` always gets `unsupported`.

### `ndo`

`src/hst/collectors/ndo.py` `NdoCollector` reads 1 Nexus Dashboard Orchestrator through its HTTP API. `NdoCollector._login` sends the user name and the password and sets the token of the answer as a bearer token.

| Item | Values |
|---|---|
| Reads | the schemas with their templates, the sites |
| Sections | none |
| Labels | `NdoSchema`, `NdoTemplate` |
| `SIDE_TABLES` | none |
| `AUTHORITATIVE_SECTIONS` | none |

| Field | Default | Use |
|---|---|---|
| `url` | no default | the base URL |
| `auth` | no default | a `user_password` login |
| `tls` | `TlsConfig` defaults | the TLS settings |
| `site_fabrics` | empty | a map from the name of an NDO site to the field `fabric` of an `apic` source |

`src/hst/collectors/ndo.py` `normalize_ndo` writes a `DEFINES` relationship from a template to the uid of each `Epg` and each `BridgeDomain` of the template. The uid has the form that the `apic` collector writes for the fabric of `site_fabrics`.

Limits:

- The collector writes no `Epg` node and no `BridgeDomain` node.
- A template on a site without an entry in `site_fabrics` gets no `DEFINES` relationship.
- A template without `tenantName` gets no `DEFINES` relationship.

### `netscaler`

`src/hst/collectors/netscaler.py` `NetScalerCollector` reads 1 NetScaler appliance through the NITRO API. The client sends the user name and the password in the headers `X-NITRO-USER` and `X-NITRO-PASS` of each request. The source type is a group, and its model is a subclass of `SourceConfig`.

| Item | Values |
|---|---|
| Reads | `lbvserver`, `lbvserver_servicegroup_binding`, `servicegroup`, `servicegroup_servicegroupmember_binding`, `servicegroup_lbmonitor_binding`, `lbmonitor`, and `Interface` with `capture_mtu` |
| Sections | `mtu` |
| Labels | `VirtualService`, `Pool`, `PoolMember`, `Monitor`, `IpAddress`, and `Interface` and `MtuObservation` with `capture_mtu` |
| `SIDE_TABLES` | none |
| `AUTHORITATIVE_SECTIONS` | none |

| Field | Default | Use |
|---|---|---|
| `host` | no default | the base URL of the management address |
| `auth` | no default | a `user_password` login |
| `tls` | `TlsConfig` defaults | the TLS settings |
| `scope_name` | no default | the name in the batch scope and in each uid of the source. The 2 addresses of an HA pair use 1 name |
| `on_uid` | no default | the uid of the node that each `VirtualService` is `ON` |
| `on_label` | `RedundancyGroup` | the label of that node: `Device` or `RedundancyGroup` |
| `l3dom` | empty | the anchor of each `IpAddress`. Without a value, the anchor is `effective_routing_scope`. A payload with the key `l3dom` sets this field and `routing_scope` |
| `capture_mtu` | `false` | the read of `Interface` |
| `mtu_device_uid` | empty | the `Device` uid for the interfaces. Without a value, the uid is `on_uid` if `on_label` is `Device` |

Limits:

- The collector writes no `Device` node. The field `on_uid` gives the uid of a node of another source.
- The collector reads no `gslbvserver` and no `csvserver`. Each `VirtualService` has the `kind` `lb`.
- A virtual server gets a `Pool` only from a service group. A virtual server with `service` objects gets no `Pool`.
- The collector reads no net profile.
- A `PoolMember` of a pool without a monitor has no `state`.
- If the payload holds `Interface` rows and the collector has no device uid, the section `mtu` gets `partial` and the collector writes no interface.
- If the payload holds `Interface` rows and the collector has a device uid, the section `mtu` gets `partial`. The detail text is `configured untagged frame limits; actualmtu size basis and tagged allowances unverified`.

### `nxos`

`src/hst/collectors/nxos.py` `NxosCollector` reads 1 NX-OS device over SSH. [SSH collector base classes](#ssh-collector-base-classes) describes the fetch. The show commands end with `| json`, and the collector parses the JSON answers without a template. The commands for the running configuration and the MTU commands return text. After the commands of `COMMANDS`, `_afetch_over` sends the BGP commands and the MTU commands.

| Item | Values |
|---|---|
| Sections with a necessary command | `device`, `interfaces`, `vrf_interfaces`, `vlans`, `vrfs`, `rib`, `mac_table` |
| Sections with an optional command | `neighbors`, `cdp`, `arp`, `nat`, `acl`, `bgp`, `route_maps`, `prefix_lists`, `interface_config`, `vlan_filter`, `ospf`, `ospf_interfaces`, `ospf_neighbors`, `ospf_lsdb_router`, `ospf_lsdb_network`, `ospf_lsdb_summary`, `ospf_lsdb_external`, `ospf_lsdb_nssa_external`, `ospf_lsdb_asbr_summary`, `ospf_config`, `trunks`, `hsrp`, `vrrp`, `vpc` |
| MTU sections | `mtu_media`, `mtu_ipv4`, `mtu_ipv6`, `mtu_system`, `mtu_qos`, `mtu_queuing`, `mtu_members` |
| Labels | `BgpPeerRange`, `BgpSession`, `BridgeDomain`, `Device`, `FhrpGroup`, `FwRule`, `FwRulebase`, `Interface`, `IpAddress`, `Lag`, `MatchListEntry`, `MtuObservation`, `NatRule`, `NetObject`, `OspfAdjacency`, `OspfArea`, `Port`, `Prefix`, `PrefixListEntry`, `RedundancyGroup`, `RoutePolicy`, `RoutePolicyEntry`, `RoutingDomain`, `RoutingProcess`, `SvcObject`, `VlanInstance`, `VrfInstance` |
| `SIDE_TABLES` | `rib`, `mac`, `arp`, `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |
| `AUTHORITATIVE_SECTIONS` | `device`, `interfaces`, `vrf_interfaces`, `vlans`, `vrfs`, `rib`, `mac_table` |

| Field | Default | Use |
|---|---|---|
| `capture_mtu` | `false` | the MTU commands |
| `json_native` | `false` | the fetch adds the word `native` to each command that ends with `\| json` |

`src/hst/collectors/cisco_common.py` `carriage_stage` writes a `CARRIES` relationship from a `Port` to each `VlanInstance` that has the port as a member. `src/hst/collectors/nxos.py` `parse_vlan_ports` gives the members from the port list of each VLAN and from the trunk table. `src/hst/collectors/cisco_common.py` `vpc_stage` writes the `RedundancyGroup` of a vPC domain.

Limits:

- The collector writes no `RouteTarget`. The parse sets no route target on a VRF.
- The collector reads 1 address for each interface.
- An ACE with an address group or a port group gets the reason text `which is not collected`.
- `src/hst/collectors/cisco_common.py` `_ACL_FAMILIES` gives a reason text to an IPv6 access list, a MAC access list and a VLAN access map.
- A NAT rule with a route map gets `approximate` and no address relationship.
- The BGP path commands use IPv4 unicast only. The direction `received` needs `soft-reconfiguration inbound` on the neighbor. Without it, the direction gets `not-captured`.
- The route command reads the IPv4 routes of each VRF. The collector reads no IPv6 route.
- If the `| json` filter of the device returns `JSONScripterror` for a table, the command fails.
- After 2 timeouts in a row, the fetch sends no more BGP path commands. The value is `PATH_TIMEOUT_LIMIT`.

### `unifi`

`src/hst/collectors/unifi.py` `UnifiCollector` reads 1 site of 1 UniFi Network application through its HTTP API. `UnifiCollector._login` sends the user name and the password to the login path of the console. A fetch uses 1 login.

| Item | Values |
|---|---|
| Reads of `READ_PATHS` that are necessary | `devices`, `networks`, `wlans`, `clients` |
| Reads of `READ_PATHS` that are optional | `port_profiles`, `firewall_rules`, `firewall_groups`, `firewall_zones`, `firewall_policies` |
| Sections | `mtu`, `policy` |
| Labels | `BridgeDomain`, `Device`, `Endpoint`, `FwRule`, `FwRulebase`, `Interface`, `IpAddress`, `MtuObservation`, `NetObject`, `Port`, `Prefix`, `RedundancyGroup`, `RoutingDomain`, `Ssid`, `SvcObject`, `VlanInstance`, `VrfInstance`, `Zone` |
| `SIDE_TABLES` | none |
| `AUTHORITATIVE_SECTIONS` | none |

An optional read with the HTTP status 400 or 404 returns an empty list, and the payload holds its path in `refused_reads`. Each other error status fails the fetch.

| Field | Default | Use |
|---|---|---|
| `url` | no default | the base URL of the console |
| `auth` | no default | a `user_password` login |
| `site` | `default` | the site id in each request path. The pattern is `^[A-Za-z0-9_-]{1,32}$` |
| `tls` | `TlsConfig` defaults | the TLS settings |
| `include_clients` | `true` | the write of the clients as `Endpoint` nodes |
| `tls_fingerprint_sha256` | empty | the SHA-256 of the certificate of the console, as 64 hex digits |

With a value in `tls_fingerprint_sha256`, `_pinned_transport` accepts only that certificate, and the client does not use `tls.verify` and `tls.ca_bundle`. Another certificate raises `CertificatePinMismatch`.

With `include_clients` false, `UnifiCollector.side_tables` returns the wired clients as rows of the side-store table `mac`. `SIDE_TABLES` does not hold that table.

`_carriage_stage` writes a `CARRIES` relationship from a `Port` to each `VlanInstance` of the port.

Limits:

- The collector writes `Interface` and `VrfInstance` nodes only for a site with 1 gateway device. With another count and classic rules or zone policies in the payload, the section `policy` gets `partial` with the text `zone membership is not bound to an interface`.
- With 2 or more gateway devices, the collector writes 1 `RedundancyGroup`.
- `_network_stage` reads only a network with the purpose `corporate`, `guest` or `vlan-only`. The collector does not read the WAN interface of the gateway.
- A flow that no zone policy matches is not decided. The default action of the rulesets `WAN_IN`, `WAN_LOCAL` and of each `GUEST` ruleset is not known.
- A zone policy with an IP group or a port group gets a reason text, because the collector does not read these groups.
- A zone policy that refers to a zone outside the zone read gives a gap text in the section `policy`. A refused read of the firewall groups with classic rules in the payload also gives a gap text.
- A client address that no gateway of the console routes has its anchor on the bridge domain of its VLAN. In the L2 fabric `fab0`, another source with the same VLAN id and address writes the same node. The collector then adds a warning that asks for an entry in `L2_FABRICS`.
- The section `mtu` gets `partial` if the payload holds MTU fields and `unsupported` if it holds none.

### `velocloud`

`src/hst/collectors/velocloud.py` `VeloCloudCollector` reads the enterprises of 1 VeloCloud Orchestrator through its APIv2 and its Portal API. The client sends the API key in the header `Authorization` of each request. `VeloCloudCollector._read` sends a `GET` request to an APIv2 path below `api_base_path` or a `POST` request to a Portal path. `_portal_read` raises `ValueError` for an operation outside `PORTAL_READ_PATHS`.

| Item | Values |
|---|---|
| Reads of `READ_PATHS` | `enterprises`, `edges`, `bgp_sessions` |
| Reads of `PORTAL_READ_PATHS` | `aggregates`, `enterprise_edges`, `enterprise_configurations`, `configuration_modules`, `route_table` |
| Sections | `configuration`, `profile_segments`, `edges`, `poll_refresh` |
| Labels | `BgpSession`, `Device`, `ForwardingBoundary`, `Interface`, `IpAddress`, `OverlayConnection`, `Port`, `Prefix`, `Provider`, `ProviderNetwork`, `RoutingDomain`, `RoutingProcess`, `SdwanBusinessPolicy`, `SdwanGateway`, `SdwanPolicyRule`, `SdwanSegment`, `SdwanStaticRoute`, `Tunnel`, `VrfInstance`, `WanLink` |
| `SIDE_TABLES` | `bgp_sessions`, `rib` |
| `AUTHORITATIVE_SECTIONS` | `edges`, `segments` |

The read `configuration_modules` runs 1 time for each edge and reads the modules `WAN` and `controlPlane`. The read `bgp_sessions` has the filter `state[is]=ESTABLISHED`. The read `edges` of `READ_PATHS` replaces the Portal read `enterprise_edges` if the Portal reads give no edge.

| Field | Default | Use |
|---|---|---|
| `url` | no default | the base URL |
| `enterprise_logical_ids` | empty | 1 enterprise `logicalId` in each line. Without a value, the collector reads each enterprise of the read `enterprises`. A payload can give the value under the key `enterprise_logical_id` |
| `orchestrator_release` | no default | the release of the orchestrator as 3 or 4 numbers with dots. The minimum is `5.0.0.0` |
| `auth` | no default | an `api_key` login |
| `tls` | `TlsConfig` defaults | the TLS settings |
| `jump_host` | none | a [jump host](#jump-host). `VeloCloudJumpHost` makes `host_key` necessary |
| `api_base_path` | `/api/sdwan/v2` | the prefix of each APIv2 path |
| `poll_concurrency` | `4` | the maximum of parallel requests, from 1 to 16 |
| `cache_enabled` | `true` | the use of the cached answers of `PollCache` |
| `configuration_refresh_s` | `1800` | the maximum age in seconds of a cached module read. The value `0` gives a read in each fetch |
| `provider_name` | empty | the name of the `Provider` of each MPLS `ProviderNetwork` |
| `private_carriers` | empty | 1 carrier name in each line. A link of such a carrier without a WAN mode gets the kind `mpls` |

`src/hst/collectors/velocloud_poll.py` `PollCache` holds the answers of `configuration_modules`. [Storage](storage.md#raw-store) gives the path of the cache file. A fetch uses a cached answer if the signature of `_edge_signature` is equal and the answer is not older than `configuration_refresh_s`.

`_read` sends a request with the status 429 again, a maximum of 3 times. It waits the time of the header `Retry-After` or 5 seconds.

| Failure | Result |
|---|---|
| `aggregates`, `enterprise_edges` or `enterprise_configurations` with a status of `PORTAL_GAP_STATUSES`: 400, 403, 404, 405 or 501 | a gap in the payload. `_read_failure_sections` gives `failed` to the sections `configuration` and `profile_segments`. It gives `partial` to the section `edges` if the edges come from the APIv2 read |
| `configuration_modules` with a status of `PORTAL_GAP_STATUSES` | a gap in place of the modules of the edge, and the section `configuration` gets `failed` |
| `route_table` with a status of `PORTAL_GAP_STATUSES` | a gap in the payload, and the table `rib` gets `failed` |
| `configuration_modules` with a transport error, a 429 after the retries or a status of 500 or more | the cached answer or, without one, a gap. The read gets `stale` true, and the section `poll_refresh` gets `failed` |
| `bgp_sessions` with the status 403, 404, 405 or 501 | the table `bgp_sessions` gets `failed` |
| each other error | the fetch fails |

`reports_progress` is true. `fetch` writes its progress with `src/hst/core/collection_progress.py` `CollectionProgress`.

Limits:

- The section `segments` is in `AUTHORITATIVE_SECTIONS` and `SECTION_LABELS`. The section `observations` is in `SECTION_LABELS`. No code records an outcome for the 2 sections. A fetch without a failed read has no section outcome.
- The table `rib` holds the routes that each edge advertises to the overlay. `VeloCloudCollector.table_outcomes` returns `partial` under the key `rib:overlay-flow-control` with the counts of the exits without a row.
- A `bgp_sessions` row has no uptime, no count of advertised prefixes and no capability list.
- A `ForwardingBoundary` has `candidate_set_complete` false and the reason `VeloCloud dynamic path selection is opaque`. A `Tunnel` has `direction_observed` false.
- The collector writes no `Tunnel` between 2 branch edges.
- The collector reads the gateways of an edge from the module `controlPlane` of the edge. Only a gateway with the role `VPN_TUNNEL` gets a `Tunnel`.
- From the profile of an enterprise, the collector reads the modules `deviceSettings` and `QOS`.
- A WAN link without a WAN mode and without a private carrier name gets the kind `dia` and a warning.
- An edge of the APIv2 read `edges` has no numeric id and no hub flag.

### `vyos`

`src/hst/collectors/vyos.py` `VyosCollector` reads 1 VyOS router over SSH. `VyosCollector._op_mode` puts `/opt/vyatta/bin/vyatta-op-cmd-wrapper` before each command that starts with `show `. Each other command starts with a `PATH` assignment and runs `ip`, `vtysh` or `sh`. `probe` sends `show version`. `VyosConfig` adds no field to `SshSourceConfig`.

If the read `config` or the read `version` fails, the fetch fails. Each other read stores an outcome, and the fetch continues.

| Item | Values |
|---|---|
| Reads of `READ_COMMANDS` | `config`, `version`, `links`, `addrs`, `routes`, `routes6`, `link_speeds`, `neigh` |
| Reads for each numeric key of `protocols static table` | `routes_table_<N>`, `routes6_table_<N>` |
| Reads of `_OSPF_SUBCOMMANDS` for each VRF with `protocols ospf` | `process`, `interfaces`, `neighbors`, `lsdb_router`, `lsdb_network`, `lsdb_summary`, `lsdb_asbr_summary`, `lsdb_external`, `lsdb_nssa_external` |
| BGP reads | `BGP_SUMMARY_COMMAND`, `BGP_NEIGHBORS_COMMAND`, and `bgp_route_command` for each target with the 3 directions of `BGP_DIRECTION_KEYWORDS`: `received-routes`, `routes` and `advertised-routes` |
| Labels | `BgpPeerRange`, `BgpSession`, `BridgeDomain`, `Device`, `FwRule`, `FwRulebase`, `Interface`, `IpAddress`, `Lag`, `MatchListEntry`, `MtuObservation`, `NatRule`, `NetObject`, `OspfAdjacency`, `OspfArea`, `OverlayConnection`, `PbrPolicy`, `Port`, `Prefix`, `PrefixListEntry`, `RoutePolicy`, `RoutePolicyEntry`, `RoutingDomain`, `RoutingProcess`, `SvcObject`, `Tunnel`, `VlanInstance`, `VrfInstance`, `WanLink`, `Zone` |
| `SIDE_TABLES` | `rib`, `arp`, `ospf_lsdb`, `bgp_session_routes`, `bgp_sessions` |
| `AUTHORITATIVE_SECTIONS` | `config`, `version` |

Each read of the first 2 rows is 1 section with the name of the read. The section of an OSPF read has the name `ospf_<vrf>_<read>`, with `default` for the default VRF. The section of a BGP read has the command text as its name. `BGP_NEIGHBORS_COMMAND` stores no outcome and has no section.

With `capture_bgp` `none`, the fetch sends no BGP command. With `sessions`, it sends `BGP_SUMMARY_COMMAND` and `BGP_NEIGHBORS_COMMAND`. With `all`, it also sends the 3 path commands for each target of `bgp_capture_targets`.

`GRAPH_MIRRORED_TABLES` holds `rib`. `_learned_routes` writes the routes of a routing table to the graph as `LEARNED_ROUTE` relationships if the table has a maximum of `RIB_GRAPH_MAX_ROUTES` rows. The default of the setting is 1000. A table with more rows is in the side store only. The property `rib_mirrored` of a `VrfInstance` shows if the graph holds its routing table.

`VyosCollector.table_outcomes` returns `unsupported` for `ospf_lsdb` if no VRF has `protocols ospf`. It returns `not-captured` for each BGP table that `capture_bgp` excludes.

`_interface_stage` writes a `CARRIES` relationship from the parent `Port` of a `vif` to its `VlanInstance`. `_membership_stage` writes `CARRIES` for the member ports of a bond with a `vif` and for the member ports of a bridge with VLAN settings.

Limits:

- The collector reads the configuration model of VyOS 1.4 and 1.5. `legacy_unread` lists the parts of a VyOS 1.3 configuration that the collector does not read. The parts are `firewall name`, `firewall ipv6-name`, `zone-policy`, the `firewall` and `policy` bindings of an interface, `protocols bgp <asn>`, `protocols static interface-route`, `protocols static interface-route6` and `protocols vrf`. For a version text below 1.4, the list also holds the configuration model of that version. With 1 such part, the section `config` gets the status `partial`.
- A firewall rule with a match key outside `_RULE_KEYS` and `_SIDE_KEYS` gets a reason text, and the rule is not decided. `_SIDE_KEYS` holds `address`, `group` and `port`.
- The collector stores the `state-policy` of the firewall on the rulebase and does not apply it as a verdict.
- A NAT rule with an interface group gets a reason text that ends with `is not collected`.
- The policy route code reads only the action `set table`.
- The BGP path commands read the IPv4 unicast paths. The direction `received` needs `soft-reconfiguration inbound` on the neighbor.
- The OSPF reads use `show ip ospf`, and only for a VRF with `protocols ospf`.
- A static route with `dhcp-interface` has no next hop in the configuration.
- From the read `addrs`, the collector writes no address of the scope `link` or `host` and no RFC 4941 privacy address.

### `zia`

`src/hst/collectors/zia.py` `ZiaCollector` reads 1 Zscaler Internet Access tenant over HTTPS with `src/hst/collectors/zscaler_auth.py` `ZscalerSession`. The session gets a token from `https://<vanity_domain>.zslogin.net/oauth2/v1/token` with the client id and the client secret. It sends each read to `https://api.zsapi.net` with the token as a bearer token. The model has no `tls` field.

| Item | Values |
|---|---|
| Reads | `LOCATIONS_PATH`, `LOCATIONS_LITE_PATH`, `SUBLOCATIONS_PATH`, `GRE_TUNNELS_PATH`, `VPN_CREDENTIALS_PATH` |
| Optional reads | `LOCATION_GROUPS_PATH`, `FORWARDING_RULES_PATH`, `ZPA_GATEWAYS_PATH` |
| Sections | `mtu`, and the 3 sections of `OPTIONAL_SECTIONS`: `location_groups`, `forwarding_rules`, `zpa_gateways` |
| Labels | `ZiaLocation`, `ZiaLocationGroup`, `ZiaForwardingRule`, `ZscalerDc`, `Tunnel`, `OverlayConnection`, `Provider`, `Site` |
| `SIDE_TABLES` | none |
| `AUTHORITATIVE_SECTIONS` | none |

| Field | Default | Use |
|---|---|---|
| `vanity_domain` | no default | the first label of the token host |
| `tenant` | no default | the name in the batch scope and in the uids of `src/hst/core/uid.py` `zia` |
| `auth` | no default | an `oauth_client` login |
| `location_sites` | empty | 1 line for each location: `<location id or name>, <site code>`. The location gets a `REPRESENTS` relationship to a `Site` node with that code |

The session renews the token after 0.66 of its lifetime. After a 401 it gets 1 token and sends the request again 1 time. After a 429 it sends the request again a maximum of 4 times and halves its request rate. `get_paged` reads pages of 500 items.

`src/hst/collectors/zscaler_sections.py` `section_status` gives the status of a refused optional read: `unauthorized` for 401 and 403, `unsupported` for 404, `failed` for each other error. If another read of the same section has an answer, `unsupported` becomes `partial`. A token failure or a 429 after the retries fails the fetch.

Limits:

- The collector writes no relationship to a ZPA object. A `ZiaForwardingRule` holds the ids of its ZPA objects as properties.
- The collector reads `ZPA_GATEWAYS_PATH` only if a forwarding rule has a ZPA gateway.
- A forwarding rule with a criterion of `_OTHER_FORWARDING_CRITERIA` holds the key in `other_criteria`. `src/hst/path/gates/zia.py` `forwarding_decision` does not decide such a rule and gives the reason `the rule also matches on` with the keys.
- A `Tunnel` from VPN credentials has no `TERMINATES_ON` relationship.
- A member of a location group that the fetch did not read gets no relationship.
- A line of `location_sites` without a matching location gives a warning in `Batch.warnings`.
- The section `mtu` always gets `unsupported`.

### `zpa`

`src/hst/collectors/zpa.py` `ZpaCollector` reads 1 Zscaler Private Access tenant over HTTPS with `src/hst/collectors/zscaler_auth.py` `ZscalerSession`. [`zia`](#zia) describes the session and the status of a refused optional read. The model has no `tls` field.

| Item | Values |
|---|---|
| Reads | `APPLICATION_PATH`, `SEGMENT_GROUP_PATH`, `SERVER_GROUP_PATH`, `APP_CONNECTOR_GROUP_PATH`, `CONNECTOR_PATH`, `SERVICE_EDGE_PATH`, `RULES_PATH` |
| Optional reads | `CLIENT_FORWARDING_RULES_PATH`, `PROVISIONING_KEY_PATH` for the association types `CONNECTOR_GRP` and `SERVICE_EDGE_GRP`, `SCIM_GROUP_PATH` for each identity provider of a rule |
| Sections | `mtu`, and the 3 sections of `OPTIONAL_SECTIONS`: `client_forwarding_rules`, `provisioning_keys`, `scim_groups` |
| Labels | `AppServer`, `IdentityGroup`, `ZpaAccessRule`, `ZpaAppConnector`, `ZpaAppConnectorGroup`, `ZpaAppSegment`, `ZpaClientForwardingRule`, `ZpaProvisioningKey`, `ZpaSegmentGroup`, `ZpaServerGroup`, `ZpaServiceEdge` |
| `SIDE_TABLES` | none |
| `AUTHORITATIVE_SECTIONS` | none |

| Field | Default | Use |
|---|---|---|
| `vanity_domain` | no default | the first label of the token host |
| `tenant` | no default | the name in the batch scope and in the uids of `src/hst/core/uid.py` `zpa` |
| `customer_id` | no default | the customer id in each API path |
| `auth` | no default | an `oauth_client` login |

Limits:

- A `ZpaAppConnector` has no `RUNS_ON` relationship.
- A negated condition block of a rule gives no relationship. The collector writes a relationship only for an operand of the type `APP`, `APP_GROUP` or `SCIM_GROUP`.
- A rule with a `ruleOrder` that is no number gets no node. `_rule_position` writes a warning to the log only.
- Each `ZpaServiceEdge` has the `kind` `private`.
- `fetch` removes the key `provisioningKey` from each provisioning key before it returns.
- An `IdentityGroup` without a name from the rule and from the SCIM read has `name_is_id` true.
- A `ZpaAppSegment` with a wildcard domain has an `opaque_reason`.
- A connector status outside `CONNECTOR_HEALTH` gives no `health`.
- The section `mtu` always gets `unsupported`.

## Source configuration and credentials

### Config model

Each collector class has a `ConfigModel`. The model is a subclass of `src/hst/collectors/base.py` `SourceConfig`, which has these fields.

| Field | Default | Use |
|---|---|---|
| `site_code` | `home` | the code of the site of the devices |
| `routing_scope` | none | the routing scope of the source. A payload can give the value under the key `l3dom` |
| `l2fabric` | none | the L2 fabric of the source |
| `interval_s` | `0` | the interval in seconds of the fetch jobs for the devices of the source. The value `0` gives no such job |
| `capture_bgp` | `all` | the BGP observations that a collector reads: `all`, `sessions` or `none` |
| `source_name` | empty | the name of the source row. `src/hst/app/sources.py` `build_collector` sets the field |
| `resolved_origins` | empty | the origin of each resolved field. `resolve_normalization` sets the field |

The values of `routing_scope` and `l2fabric` match the pattern `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`. The property `effective_routing_scope` returns `routing_scope` or, without a value, `site_code`. `src/hst/core/config.py` `Settings.l2fabric_of` returns the L2 fabric of a source. The result is the first of these values: the field `l2fabric`, the fabric of the setting `L2_FABRICS` that lists the source name, `fab0`.

With `capture_bgp` `sessions`, a collector reads the session state and no path table. With `none`, it reads no BGP observation. A table that the collector did not read gets the table outcome `not-captured`.

The model of each SSH collector is a subclass of `src/hst/collectors/cli_collector.py` `SshSourceConfig`, which adds these fields.

| Field | Default | Use |
|---|---|---|
| `host` | empty | the address of the device. A group with device rows leaves the field empty |
| `auth` | no default | the login model of [Credentials](#credentials) |
| `port` | `22` | the SSH port |
| `jump_host` | none | the [jump host](#jump-host) |
| `host_key` | empty | the pinned host key |
| `transport` | `asyncssh` | the [SSH transport](#ssh-transports): `asyncssh` or `paramiko` |
| `fresh_connection_per_command` | `false` | a connection and a login for each command |
| `channel` | `exec` | `exec` opens 1 exec channel for each command. `shell` opens 1 interactive shell for the fetch |
| `timeout` | `120` | the limit in seconds for the SSH handshake and for the open of a channel. With `asyncssh`, the limit of the handshake includes the login |
| `connect_timeout` | `10` | the limit in seconds for the TCP connection |
| `read_timeout` | `300` | the limit in seconds for the read of 1 answer. With `paramiko` on an exec channel, the limit starts again at each output of the device |

The model of each HTTP collector except `zia` and `zpa` has the field `tls` of the type `src/hst/collectors/auth.py` `TlsConfig`.

| Field | Default | Use |
|---|---|---|
| `verify` | `true` | the check of the server certificate |
| `ca_bundle` | empty | a CA bundle as PEM text. It replaces the system store |
| `client_cert` | none | a client certificate for mutual TLS: `cert` as PEM text and the secret `key` |

`src/hst/app/sources.py` `source_types` returns the JSON schema of each model. `hst collectors` lists the source types.

### Credentials

`src/hst/collectors/auth.py` defines the login models. The field `method` selects the model of an `auth` field.

| `method` | Model | Fields | Secret fields |
|---|---|---|---|
| `password` | `SshPassword` | `username` | `password` |
| `private_key` | `SshPrivateKey` | `username` | `private_key` as PEM text, `passphrase` |
| `agent` | `SshAgent` | `username` | |
| `user_password` | `UserPassword` | `username` | `password` |
| `api_key` | `ApiKeyCredential` | | `key` |
| `oauth_client` | `OAuthClientCredentials` | `client_id` | `client_secret` |

A secret field has the type `SecretStr`. `src/hst/app/sources.py` `secret_paths` returns the dotted path of each secret field of a model, such as `auth.password`. `src/hst/app/sources.py` `validate_source` validates a payload against the model of its source type. Then `split_secrets` returns the config without the secret fields and the map from each path to its secret value.

A source row is a `src/hst/app/store/__init__.py` `Source`. The field `config` holds the config without secrets. The field `secrets` holds the encrypted map. [Storage](storage.md#postgres) describes the encryption of the column `sources.secrets`.

`hst sources add` adds a source row and prompts for each secret field that `--config` does not hold. `hst sources set` changes a row through `src/hst/app/sources.py` `merge_config`. The function decrypts the stored secrets, applies the change, validates the result and encrypts the secrets. `hst sources test` calls `probe` of the collector.

### Build of a collector

`src/hst/app/sources.py` `build_collector` builds the collector of a source row in 5 steps.

1. `resolve_normalization` sets `site_code`, `routing_scope`, `l2fabric` and `resolved_origins` in a copy of the config.
2. `src/hst/app/secrets.py` `FernetResolver` decrypts the secrets of the row, and `inject_secrets` puts each value at its path.
3. The function sets `source_name` to the name of the row.
4. If the caller gives the parameter `sources`, `link_sources` of the collector class gets the payload and the source rows. The method of `Collector` returns the payload without a change.
5. The function validates the payload with the `ConfigModel` and makes the collector with the model and the settings.

`resolve_normalization` uses the value of the config for each of the 3 fields. Without a value, it uses these values.

| Field | Value without a value in the config |
|---|---|
| `site_code` | `home` |
| `routing_scope` of a group | the parameter `routing_scope` of the site, then the site code |
| `routing_scope` of an orchestrator of `READS_ROUTING_SCOPE` | `inventory:<source name>` |
| `routing_scope` of each other orchestrator | the parameter `routing_scope` of the site, then the site code |
| `l2fabric` | the result of `Settings.l2fabric_of` for the source name |

`src/hst/app/inventory/normalization.py` `READS_ROUTING_SCOPE` holds the source types `apic`, `iosxe`, `iosxr`, `manual`, `netscaler`, `nxos`, `unifi` and `vyos`.

If the caller gives the parameter `effective`, `build_collector` uses the payload of `src/hst/app/inventory/collection.py` `ResolvedCollection` and does not do steps 1 and 2. If the caller gives the parameter `identity`, the collector resolves each `Device` uid with that registry. Without it, the collector uses `src/hst/core/identity.py` `MemoryResolver`.

### Devices of a group

`src/hst/app/store/__init__.py` `Device` is 1 device row of a group. It holds `host`, `port`, `enabled` and `host_key`. `hst devices import` and `PUT /api/sources/{name}/devices` replace the device list of a group. A row that stays in the list keeps its `host_key`. `hst devices list` shows the rows.

`src/hst/app/sources.py` `build_device_collector` builds the collector of 1 device. `device_config` copies the config of the group and sets `host` and `host_key` from the device row. It sets `port` only if the device row has a port. Each other field comes from the group.

`src/hst/app/runs_exec.py` `_prepare_all` builds the collectors of a run.

| Source | Collectors |
|---|---|
| a source with 1 or more enabled device rows | 1 for each enabled device row |
| a source with device rows and no enabled row | none, with the error `no enabled devices` |
| a group without device rows and without `host` in the config | none, with the error `no enabled devices and no host` |
| each other source | 1 for the source row |

If the resolver of the device inventory is active, `src/hst/app/runs_exec.py` `_prepare_all_v2` builds the collectors from `src/hst/app/inventory/collection.py` `Resolver`.

### Reported location

An orchestrator collector sets 2 properties on a `Device` node: `reported_location` and `reported_location_name`. `src/hst/collectors/base.py` `REPORTED_LOCATION_PROP` and `REPORTED_LOCATION_NAME_PROP` hold the 2 names. `src/hst/collectors/base.py` `_load_payload` copies the pair of each device to `last_device_locations` of the collector. A device without `reported_location_name` gets the location id as its name. After the load, the run stores the pairs with `record_target_devices` of the store.

`src/hst/app/sources.py` `resolve_device_sites` gives each device a site and an origin.

| Device | Site | Origin |
|---|---|---|
| a device of a group | `site_code` of the group | `group` |
| a device of an orchestrator with a site set by hand | that site | `hand` |
| a device of an orchestrator with a reported location that is bound to a site | that site | `location` |

A device without a row in this table has no site. 4 source types set a reported location.

| Source type | `reported_location` | `reported_location_name` |
|---|---|---|
| `apic` | `<fabric>/<pod dn>` | `<fabric> <pod dn>` |
| `nautobot` | the id of the location of the device | the name of that location |
| `unifi` | the field `site` | the field `site` |
| `velocloud` | `<enterprise logicalId>/<site id>` | the name of the site or, without a name, the site id |

## Shared code

### SSH transports

The field `transport` of `SshSourceConfig` selects 1 of 2 transports. The 2 modules have the same session interface, the same error classes and the same host key format.

| `transport` | Module | Library | Use in a run |
|---|---|---|---|
| `asyncssh` | `src/hst/collectors/assh.py` | asyncssh | an asyncio task. The setting `COLLECT_MAX_CONCURRENCY` limits the tasks. The default is 8 |
| `paramiko` | `src/hst/collectors/ssh.py` | paramiko | a thread. The setting `COLLECT_THREAD_WORKERS` sets the size of the thread pool. The default is 8 |

`src/hst/collectors/ssh.py` `session` and `src/hst/collectors/assh.py` `session` open 1 connection for a fetch. The keepalive interval of the device connection is 30 seconds, the value of `KEEPALIVE_INTERVAL`. If `fresh_connection_per_command` is true, `src/hst/collectors/cli_collector.py` `SshCliCollector` opens a connection for each command.

| `channel` | Session classes | Read of 1 answer |
|---|---|---|
| `exec` | `SshSession`, `AsyncSshSession` | 1 exec channel for each command. The read ends when the device closes the channel |
| `shell` | `ShellSession`, `AsyncShellSession` | 1 interactive shell with a PTY of 511 columns. The read ends at the prompt of the device |

A shell session finds the prompt before the first command. It sends an empty line a maximum of 3 times and needs the same prompt 2 times. Then it sends the commands of `SHELL_SETUP` of the collector class.

`src/hst/collectors/ssh.py` `sanitize_cli_text` removes the terminal control sequences from an answer. `_cli_rejection` finds a rejection line of `_CLI_ERROR_MARKERS` at the start of a line. The session then raises `CommandFailed`.

| Error class | Cause |
|---|---|
| `SshUnreachable` | no TCP connection |
| `SshRefused` | the peer closed the connection before the login |
| `SshRejected` | the peer refused the credentials |
| `HostKeyMismatch` | the host key is different from the pinned key |
| `CommandFailed` | a command with an exit status above 0 or a rejection line |
| `AnswerTooLarge` | an answer above the limit of the setting `COLLECT_MAX_ANSWER_MB` |
| `AnswerIncomplete` | the connection ended before the end of the answer |
| `SshTimeout` | no channel or no output in the time limit |

The default of `COLLECT_MAX_ANSWER_MB` is 1024, and the value 0 sets no limit. After `AnswerTooLarge` on a shell, the session opens another shell on the same connection for the next command.

A session returns the host key of the device and of the jump host as `<algorithm> <base64 key>`. With a value in `host_key`, a connection with another key raises `HostKeyMismatch` before the login. `src/hst/app/runs_exec.py` `pin_host_key` writes the key of the first connection to an empty `host_key`. The key of a device row goes to the device row. `hst sources unpin` and `hst devices unpin` clear a pinned key.

### SSH collector base classes

`src/hst/collectors/cli_collector.py` `SshCliCollector` is the base class of the 5 SSH collectors `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos` and `vyos`. `SshCliCollector._afetch_over` sends each command of `COMMANDS` and stores the answer under the command text. It stores the outcome of each command under the key `_strata_outcomes` of the payload. Each of the 5 collector classes has its own `_afetch_over` with more reads.

If a command of `OPTIONAL_COMMANDS` fails, the fetch stores the replacement text of that map and continues. `classify_command_failure` gives the status of the failed command.

| Status | Condition |
|---|---|
| `unauthorized` | the failure text holds a marker of `_UNAUTHORIZED_MARKERS`, or the device refused a command of `ALWAYS_PRESENT_COMMANDS` |
| `unsupported` | the failure text holds a marker of `_UNSUPPORTED_MARKERS` |
| `failed` | each other failure |

If a command outside `OPTIONAL_COMMANDS` fails, the fetch fails.

`src/hst/collectors/cli_collector.py` `CiscoCliCollector` is the base class of `iosxe`, `iosxr` and `nxos`. In a shell, it first sends `terminal length 0` and `terminal width 511`. The method `_parse` of each family returns 1 intermediate structure. `src/hst/collectors/cisco_common.py` `normalize_cisco` makes the batch from that structure. `side_rows` makes the rows of the tables `rib`, `mac`, `arp` and `ospf_lsdb`. The function `bgp_side_rows` of each family module makes the rows of the 2 BGP tables.

`CiscoCliCollector.SECTIONS` maps each section to a `Section` with its command. `build_sections` gives the outcome of each section.

- A section without a stored command outcome gets `unknown`.
- A section with a failed command gets the status of the command.
- A section with rows gets `ok` and the row count.
- A section with a blank answer gets `empty`.
- `Section.empty_answer` holds the words of the empty answer of a text section. A text answer that is not blank, parses to no rows and holds none of these words gets `malformed`.
- For a section with a value in `Section.table`, an answer that is not blank and is no JSON object with the key `TABLE_<table>` gets `malformed`.
- An optional command with a TextFSM error gets `malformed`.

`src/hst/collectors/cisco_common.py` `mtu_sections` gives 1 section `mtu_<role>` for each command of `MTU_COMMANDS` of the family. The fetch sends these commands only if `capture_mtu` is true. Without the answer of a command, its section gets `unknown` with the detail `MTU_NOT_CAPTURED`.

`STRIP_EXEC_BANNER` is true for `iosxe` and `iosxr`. On an exec channel, `exec_banner_of` finds the lines that each answer starts with, and the fetch removes them.

### HTTP clients

`src/hst/collectors/http.py` `client` makes the `httpx.Client` of each HTTP collector. The default timeout is 60 seconds.

- With `verify` false, the client does not do a check of the server certificate.
- With `verify` true and a `ca_bundle`, the client trusts only that bundle.
- With `client_cert`, the function writes the certificate and the key to 2 temporary files with the mode 0600. It deletes the files after the TLS context loads them.
- A response body above `COLLECT_MAX_ANSWER_MB` raises `AnswerTooLarge`. The count is the size before the content decoding.
- If the URL has the scheme `http`, the function writes 1 warning to the log for each fetch.

`src/hst/collectors/http.py` `logged_in_client` makes a client and calls a login function. `src/hst/collectors/util.py` `offset_paged` reads pages until the fetch function returns no next offset. `src/hst/collectors/util.py` `renew_deadline` gives the time of the next token renewal from the lifetime that the server reports.

### Jump host

`src/hst/collectors/auth.py` `SshJumpHost` holds `host`, `port` with the default 22, `auth` and `host_key`. The SSH session first connects and logs in to the jump host with the credentials of the jump host. Then it opens a `direct-tcpip` channel to the device and logs in to the device through that channel. The host key of the jump host has its own pin in `jump_host.host_key`.

`src/hst/collectors/http_jump.py` `JumpTransport` sends HTTPS requests through a `direct-tcpip` channel of 1 paramiko connection. It refuses a URL without the scheme `https` and a request to another origin. `src/hst/collectors/http.py` `client` uses it if the caller gives `jump_host`. Only `velocloud` gives it.

### TextFSM parse

`src/hst/collectors/cli_parse.py` `parse` parses the text answer of 1 command with a TextFSM template. `iosxe` uses the platform `cisco_ios` and `iosxr` uses the platform `cisco_xr`. `_template_dir` returns the folder `src/hst/collectors/templates` if the file `src/hst/collectors/templates/index` lists the platform and the command. For each other command it returns the folder of the installed package ntc-templates. The folder holds 3 templates.

| Template | Platform | Command |
|---|---|---|
| `src/hst/collectors/templates/cisco_ios_show_ip_access-lists.textfsm` | `cisco_ios` | `show ip access-lists` |
| `src/hst/collectors/templates/cisco_ios_show_ip_route.textfsm` | `cisco_ios` | `show ip route vrf *` |
| `src/hst/collectors/templates/cisco_xr_show_ip_route.textfsm` | `cisco_xr` | `show route vrf all ipv4` |

A template of the folder can declare the value `UNREAD`. Such a template records each line that no other rule reads. `parse_with_unread` returns the records and the count of these lines. `unread_outcome` changes the status `ok` or `empty` of the section to `partial` and puts the count in the detail. If the answer has text and the template reads no line, `parse_with_unread` raises `TextFSMError`.

`_preamble` counts the lines at the start of an answer that the `Start` state of the template sends to `Error`. The parse drops these lines. The function reads a maximum of 50 lines.

`tolerating` gets the set of the commands outside `OPTIONAL_COMMANDS`. A TextFSM error of a command of that set stops the parse of the payload. A TextFSM error of each other command gives no records, and the section gets the status `malformed`.

### Interface names

`src/hst/core/normalize.py` holds the functions for interface names.

| Function | Result | Example |
|---|---|---|
| `canonical_ifname` | the full type word in lower case and the number | `Eth1/1` gives `ethernet1/1` |
| `short_ifname` | the short type word of `_SHORT` and the number | `ethernet1/1` gives `eth1/1` |
| `iface_slug` | the short name with `-` in place of `/` and `:` | `GigabitEthernet0/0.1` gives `gi0-0.1` |

The interface segment of a uid is the result of `iface_slug`. A name with a type word outside the table of netutils stays as the device printed it, in lower case.

`src/hst/core/normalize.py` `IfNameResolver` maps an abbreviated name of a command answer to a name of the interface table of the device. It returns the first of these names:

1. the name, if the interface table holds it
2. the 1 table name with the same canonical type and the same number
3. the 1 table name with the same number whose type word starts with the abbreviation
4. the 1 table name with the same number whose part initials start with the abbreviation, such as `BE` for `Bundle-Ether`

The number is equal only as the same text. If 2 table names match in a step, the resolver returns the name as the command printed it.

### HTTP trace

The setting `HST_HTTP_TRACE` lists the source names with an HTTP trace, with commas between them. The value `*` selects each source. `src/hst/collectors/base.py` `fetch_traced` makes a `src/hst/collectors/http_trace.py` `HttpTrace` for the fetch of such a source. Each client of `src/hst/collectors/http.py` `client` records its requests and responses in the active trace. A fetch that raises deletes its trace. [Storage](storage.md#raw-store) gives the path and the encryption of the trace file.

Each line of a trace is 1 JSON object with `ts`, `method`, `url`, `status`, `elapsed_ms`, `request` and `response`.

- A body has a maximum of 1,048,576 bytes, the value of `BODY_LIMIT`. A longer body is cut and gets the mark `truncated`.
- The trace holds only the headers of `REQUEST_HEADERS` and `RESPONSE_HEADERS`. The 2 lists hold no `Authorization`, `Cookie` and `Set-Cookie`.
- The value of a credential key of `src/hst/core/redaction.py` becomes `[redacted]` in a JSON body and in a form body.
- The trace removes each secret value of the source config from each line.

`hst http-trace` reads a trace file.

## Section outcomes and table outcomes

`src/hst/core/model.py` `SectionOutcome` holds the outcome of 1 section of a payload: `status`, `detail` and `row_count`. A collector puts the outcomes in `Batch.sections`. `SectionStatus` has 8 values.

| Status | Meaning | Degrades |
|---|---|---|
| `ok` | the section has an answer | no |
| `empty` | the answer has no rows | no |
| `unsupported` | the device or the API does not have the command or the read | no |
| `partial` | the collector read a part of the answer | no |
| `unknown` | the payload holds no outcome for the section. It is the default | no |
| `unauthorized` | the account cannot do the read | yes |
| `malformed` | the parser cannot read the answer | yes |
| `failed` | each other failure | yes |

`DEGRADING_SECTION_STATUSES` holds the 3 values of the last 3 rows. `src/hst/core/model.py` `section_verdict` gives the verdict of a device from its section outcomes and the `AUTHORITATIVE_SECTIONS` of the collector class.

| Condition | Verdict |
|---|---|
| a section of `AUTHORITATIVE_SECTIONS` has a status of `DEGRADING_SECTION_STATUSES` | `failed` |
| another section has such a status | `partial` |
| no section has such a status | `ok` |

`src/hst/core/model.py` `TableOutcome` holds the outcome of 1 side-store table: `status`, `detail`, `row_count`, `path`, `observed_ms` and `parser_version`. `src/hst/collectors/base.py` `_write_side_tables` gives an outcome to each table of `SIDE_TABLES` and to each other table that `side_tables` returns. `TableStatus` has 7 values.

| Status | Condition | Code that sets it |
|---|---|---|
| `complete` | the load wrote the rows | `written_table_outcome` |
| `complete-empty` | the collector made no rows, and each section of the table has an answer | `empty_table_outcome` |
| `partial` | the load wrote rows, and a section of the table has a degrading status or the collector stated `failed` or `partial` | `written_table_outcome` |
| `failed` | the write raised an error, or the table has no rows and a section of the table has a degrading status | `_write_side_tables`, `empty_table_outcome` |
| `unchanged` | the payload is equal to the payload of the last fetch, and no load ran | `src/hst/app/runs_exec.py` `_unchanged_tables` |
| `unsupported` | the device does not have the feature of the table | `table_outcomes` of the collector |
| `not-captured` | the run did not read the table | `table_outcomes` of the collector |

`Collector.table_feeds` returns the sections of each table. The default is `TABLE_SECTIONS` of the collector class. `table_outcomes` can also return an outcome under a key that is no table, such as 1 direction of 1 BGP session.

`DEGRADING_TABLE_STATUSES` holds `failed` and `partial`. `src/hst/core/model.py` `table_verdict` returns `partial` if 1 table has such a status. `src/hst/app/runs_exec.py` `_completeness` returns the verdict of `section_verdict`. If that verdict is `ok` and `table_verdict` returns `partial`, it returns `partial`.

`SECTION_LABELS` of a collector class maps a section to a tuple of labels. `src/hst/app/runs_exec.py` `_failed_section_labels` returns the labels of each section with a degrading status. [Code flow of a collection](collection-code-flow.md#carry) describes the carry of these objects from the parent run.
