# Device commands

## Notation

- A name in angle brackets is a variable part of a command or of a path, such as `<peer>`.
- The column "Section" holds the name of the [section](collectors.md#section-outcomes-and-table-outcomes) of the payload. If the cell is empty, the command has no section name and the payload holds the answer under the command.
- The value `always` in the column "Sent when" marks a command or a request of each fetch.
- A field is a field of the source configuration. [Collectors](collectors.md#source-types) describes the fields.
- The connection test of a source is the method `probe` of its collector. `src/hst/collectors/base.py` `Collector.probe` declares the method.

`src/hst/collectors/base.py` `SourceConfig` has the field `capture_bgp` with the values `all`, `sessions` and `none`. The default is `all`. The field `capture_mtu` of a source type is a boolean with the default false.

## SSH transport

5 [source types](collectors.md#sources) send commands over SSH: `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos` and `vyos`. `src/hst/collectors/cli_collector.py` `SshSourceConfig` holds the fields `transport`, `channel`, `fresh_connection_per_command` and `jump_host`.

`src/hst/collectors/assh.py` `session` opens the connection for the transport `asyncssh`, which is the default. `src/hst/collectors/ssh.py` `session` opens the connection for the transport `paramiko`. The login is the SSH authentication with the credential of the source. If the source has a jump host, the transport first logs in to the jump host. It then opens the device connection through the jump host. If the jump host or the device closes the connection before the authentication, the transport `asyncssh` connects 1 more time after 2 seconds.

With the channel `exec`, which is the default, the transport opens 1 exec channel for each command. The exec request holds the command. The transport sends no other text.

With the channel `shell`, the transport opens 1 shell for the fetch and sends this sequence:

1. A PTY request with 511 columns and 1000 rows. The transport `asyncssh` asks for the terminal type `vt100`.
2. A newline, a maximum of 3 times, until 2 answers in sequence end with the same prompt.
3. Each command of `src/hst/collectors/cli_collector.py` `SshCliCollector.SHELL_SETUP` of the collector.
4. Each command of the fetch with a newline at its end.

`src/hst/collectors/cli_collector.py` `CiscoCliCollector.SHELL_SETUP` holds `terminal length 0` and `terminal width 511` for `nxos`, `iosxe` and `iosxr`. `SHELL_SETUP` is empty for `vyos` and `checkpoint_gateway`. If the device refuses a setup command, the transport writes a warning to the log and the fetch continues.

The setting `COLLECT_MAX_ANSWER_MB` sets the answer limit, and the default is 1024. If an answer in a shell is larger than the answer limit, the transport closes the shell. Before the next command, the transport opens a shell on the same connection and sends steps 1 to 3 again.

If the source sets `fresh_connection_per_command`, the fetch opens 1 connection for each command. `src/hst/collectors/ssh.py` `KEEPALIVE_INTERVAL` sets an SSH keepalive of 30 seconds on the device connection. At the end of the fetch, the transport closes the channel and the connection. It sends no logout command.

A collector class for SSH sets `src/hst/collectors/cli_collector.py` `SshCliCollector.COMMANDS` and `src/hst/collectors/cli_collector.py` `SshCliCollector.OPTIONAL_COMMANDS`. `src/hst/collectors/cli_collector.py` `SshCliCollector._afetch_over` sends each command of `COMMANDS` in order. If the device refuses a command that is not in `OPTIONAL_COMMANDS`, the fetch stops with the exception `src/hst/collectors/ssh.py` `CommandFailed` and returns no payload. If the device refuses a command of `OPTIONAL_COMMANDS`, the payload gets the stand-in answer of `OPTIONAL_COMMANDS` and the fetch continues. A refused command that is not in `COMMANDS` does not stop the fetch, with the exception of 2 commands of [vyos](#vyos).

`src/hst/collectors/cli_collector.py` `classify_command_failure` gives a refused command the status `unauthorized`, `unsupported` or `failed`.

A path command is a BGP command for 1 peer and 1 direction of `nxos`, `iosxe` or `iosxr`. With the channel `exec` or with `fresh_connection_per_command`, a timeout of a path command does not stop the fetch. After 2 timeouts in sequence, the fetch sends no more path commands. `src/hst/collectors/cli_collector.py` `PATH_TIMEOUT_LIMIT` holds this limit. With 1 shell for the fetch, a timeout of a path command stops the fetch.

`hst parse-raw <collector> --commands` prints the result of `src/hst/collectors/offline.py` `expected_commands`. The result holds the commands of `COMMANDS`, the constant `CMD_BGP_SESSIONS` of the collector module and the commands of `src/hst/collectors/cisco_common.py` `MTU_COMMANDS` for the source type. An example of the constant is `src/hst/collectors/nxos.py` `CMD_BGP_SESSIONS`. The result holds no other command of the tables in the sections of the source types.

## HTTP transport

10 source types send HTTP requests: `apic`, `checkpoint`, `equinix`, `nautobot`, `ndo`, `netscaler`, `unifi`, `velocloud`, `zia` and `zpa`. `src/hst/collectors/http.py` `client` makes the HTTP client of each collector and sends no request. For `apic`, `checkpoint`, `ndo` and `unifi`, `src/hst/collectors/http.py` `logged_in_client` calls the login function of the collector 1 time. Each collector closes its client at the end of the fetch.

The source type `velocloud` has the field `jump_host`. With a jump host, `src/hst/collectors/http_jump.py` `JumpTransport` logs in to the jump host over SSH and opens 1 `direct-tcpip` channel for each HTTP connection. It sends no command to the jump host. `src/hst/collectors/ssh.py` `KEEPALIVE_INTERVAL` sets an SSH keepalive of 30 seconds on the connection to the jump host.

## Helper modules

This code is not in the collector class of a source type. A fetch of each source type in column 2 uses it.

| Code | Source types | Role in a fetch |
|---|---|---|
| `src/hst/collectors/ssh.py` `session` | `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos`, `vyos` | the SSH session of the transport `paramiko` |
| `src/hst/collectors/assh.py` `session` | `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos`, `vyos` | the SSH session of the transport `asyncssh` |
| `src/hst/collectors/cli_collector.py` `SshCliCollector._afetch_over` | `checkpoint_gateway`, `iosxe`, `iosxr`, `nxos` | the loop over `COMMANDS` |
| `src/hst/collectors/cisco_common.py` `capture_mtu` | `iosxe`, `iosxr`, `nxos` | sends the commands of `src/hst/collectors/cisco_common.py` `MTU_COMMANDS` |
| `src/hst/collectors/cisco_common.py` `capture_match_lists` | `iosxe`, `iosxr` | sends the 2 list commands or the 2 set commands |
| `src/hst/collectors/cisco_bgp.py` `expand_dynamic_neighbors` | `iosxe`, `iosxr`, `nxos` | adds the dynamic peers to the target peers |
| `src/hst/collectors/iosxr_bgp.py` `parse_bgp` | `iosxr` | reads the BGP processes from the configuration answer |
| `src/hst/collectors/iosxr_bgp.py` `names_a_set` | `iosxr` | finds a reference to a set in the route-policy answer |
| `src/hst/collectors/checkpoint_iproute.py` `COMMANDS` | `checkpoint_gateway` | the 6 text commands |
| `src/hst/collectors/checkpoint_iproute.py` `parse` | `checkpoint_gateway` | reads the answer to a text command |
| `src/hst/collectors/checkpoint_evidence.py` `read_evidence` | `checkpoint_gateway` | reads a file on the HST host |
| `src/hst/collectors/mtu_apic.py` `MTU_CLASSES` | `apic` | the 4 classes of the MTU read |
| `src/hst/collectors/mtu_apic.py` `MTU_POLICY_PATH` | `apic` | the path of the class `l2InstPol` |
| `src/hst/collectors/velocloud_poll.py` `PollCache` | `velocloud` | stores the answers to `getEdgeConfigurationModules` between fetches |
| `src/hst/collectors/zscaler_auth.py` `ZscalerSession` | `zia`, `zpa` | sends the token request and each GET request |
| `src/hst/collectors/zscaler_sections.py` `SectionReads` | `zia`, `zpa` | records a refused read |
| `src/hst/collectors/mtu_import.py` `validate_import_subjects` | `manual` | reads Neo4j |
| `src/hst/collectors/http.py` `client` | each HTTP source type | makes the HTTP client |
| `src/hst/collectors/http_jump.py` `JumpTransport` | `velocloud` | connects the HTTP client through the SSH jump host |

## apic

The collector is `src/hst/collectors/apic.py` `ApicCollector`. The field `url` of the source is the base URL. Each path starts with `/api`.

The login is `POST /api/aaaLogin.json` with the user name and the password in the JSON body `aaaUser`. The collector sends the token of the answer in the cookie `APIC-cookie`. The collector sends no logout request.

`src/hst/collectors/apic.py` `ApicCollector._keep_alive` runs before each read. After 66 % of the token lifetime, it sends `GET /api/aaaRefresh.json`. The token lifetime is the value `refreshTimeoutSeconds` of the login answer, with a default of 600 seconds and a minimum of 60 seconds. After a refresh, the token lifetime is 600 seconds. If the refresh fails, the collector sends the login again. If a read gets the status 401 or 403, the collector sends the login again and sends the read 1 more time.

The class lists are `src/hst/collectors/apic.py` `CLASSES`, `src/hst/collectors/apic.py` `CONTRACT_BYPASS_CLASSES`, `src/hst/collectors/apic.py` `BGP_CLASSES` and `src/hst/collectors/mtu_apic.py` `MTU_CLASSES`.

| Method | Path | Sent when |
|---|---|---|
| GET | `/api/class/<class>.json` | always, for each class of `CLASSES` |
| GET | `/api/class/<class>.json` | always, for each class of `CONTRACT_BYPASS_CLASSES` |
| GET | `/api/class/<class>.json` | `capture_bgp` is `all` or `sessions`, for each class of `BGP_CLASSES` |
| GET | `/api/mo/uni/fabric/l2pol-default.json` | `capture_mtu` is true |
| GET | `/api/class/<class>.json` | `capture_mtu` is true, for each of the other 3 classes of `MTU_CLASSES` |
| GET | `/api/class/firmwareCtrlrRunning.json` | the connection test only |

| Constant | Classes |
|---|---|
| `CLASSES` | `fabricNode`, `topSystem`, `l1PhysIf`, `lldpAdjEp`, `pcAggrIf`, `cdpAdjEp`, `fvTenant`, `fvAp`, `fvAEPg`, `fvBD`, `fvSubnet`, `fvCtx`, `fvRsCtx`, `fvRsBd`, `vzBrCP`, `vzSubj`, `vzRsSubjFiltAtt`, `vzRsFiltAtt`, `vzRsSubjGraphAtt`, `vzFilter`, `vzEntry`, `fvRsProv`, `fvRsCons`, `l3extOut`, `l3extInstP`, `l3extRsEctx`, `l3extSubnet`, `vnsAbsGraph`, `vnsGraphInst`, `vnsSvcRedirectPol`, `vnsRedirectDest`, `fvCEp`, `fvIp`, `fvRsPathAtt`, `fvRsDomAtt`, `ospfDom`, `ospfArea`, `ospfIf`, `ospfAdjEp` |
| `CONTRACT_BYPASS_CLASSES` | `vzAny`, `vzRsAnyToProv`, `vzRsAnyToCons`, `vzRsAnyToConsIf`, `fvESg`, `fvRsScope` |
| `BGP_CLASSES` | `bgpPeerEntry`, `bgpPeerAfEntry` |
| `MTU_CLASSES` | `l2InstPol`, `l3extRsPathL3OutAtt`, `l3extVirtualLIfP`, `pcRsMbrIfs` |

The collector reads the class `l2InstPol` from the path `/api/mo/uni/fabric/l2pol-default.json`. The read of this path has no query parameters.

Each class read has the query parameters `page-size=1000`, `page=<n>` and `order-by=<class>.dn`. The first page is page 0. The read stops after a page with fewer than 1000 rows. A read of a class of `MTU_CLASSES` has a maximum of 100 pages.

## checkpoint

The collector is `src/hst/collectors/checkpoint.py` `CpCollector`. The base URL is `https://<host>:<port>` with the fields `host` and `port` of the source, and the default port is 443. The base path is `/web_api/`. Each request is a POST with a JSON body.

The login is `POST /web_api/login`. The body holds `api-key`, or `user` and `password`. It holds `domain` if the source sets the field `domain`. It always holds `read-only` with the value true. The collector sends the session id of the answer in the header `X-chkp-sid`.

The session release is `POST /web_api/logout` at the end of the fetch and at the end of the connection test.

The collector sends the logout and the login again in 2 cases. In case 1, 2 thirds of the session lifetime are past. The session lifetime is the value `session-timeout` of the login answer, with a default of 600 seconds. In case 2, a request gets the status 401 or 403, or the status 400 with the code `generic_err_wrong_session_id`. In case 2, the collector then sends the request 1 more time.

`src/hst/collectors/checkpoint.py` `READ_COMMANDS` holds 8 of the 9 paths of the table. `src/hst/collectors/checkpoint.py` `CpCollector.fetch` holds the path `show-package`.

| Method | Path | Sent when |
|---|---|---|
| POST | `show-api-versions` | always, and in the connection test |
| POST | `show-last-published-session` | always |
| POST | `show-gateways-and-servers` | always |
| POST | `show-access-layers` | always |
| POST | `show-global-properties` | always |
| POST | `show-access-rulebase` | for each access layer without a replay-cache file of the same revision |
| POST | `show-packages` | always |
| POST | `show-package` | for each package with a `uid` |
| POST | `show-nat-rulebase` | for each package with a `name` |

5 paths have pages: `show-gateways-and-servers`, `show-access-layers`, `show-access-rulebase`, `show-packages` and `show-nat-rulebase`. Each page request holds `offset` and `limit` with the value 100.

| Path | Other fields of the body |
|---|---|
| `show-gateways-and-servers`, `show-access-layers`, `show-packages` | `details-level: full` |
| `show-access-rulebase` | `uid` of the layer, `details-level: full`, `use-object-dictionary: true` |
| `show-package` | `uid` of the package, `details-level: full` |
| `show-nat-rulebase` | `package` with the package name, `details-level: full`, `use-object-dictionary: true` |
| `show-api-versions`, `show-last-published-session`, `show-global-properties` | an empty object |

The cache revision of a layer holds the `uid` of the last published session and the revision of the layer. `src/hst/collectors/checkpoint.py` `CpCollector._cached_pages` returns the pages of the replay-cache file if the file holds the same revision. The fetch then sends no `show-access-rulebase` for the layer. [Storage](storage.md#raw-store) gives the path of the replay cache.

## checkpoint_gateway

The collector is `src/hst/collectors/checkpoint_gateway.py` `CpGatewayCollector`. The connection test sends `clish -c 'show version osedition'`.

`src/hst/collectors/checkpoint_gateway.py` `CpGatewayCollector.COMMANDS` holds 3 commands.

| Section | Command | Sent when |
|---|---|---|
| | `clish -c 'show version osedition'` | always |
| | `clish -c 'show hostname'` | always |
| | `vsx stat -v` | always |

The first command is not in `src/hst/collectors/checkpoint_gateway.py` `CpGatewayCollector.OPTIONAL_COMMANDS`.

`src/hst/collectors/checkpoint_gateway.py` `CpGatewayCollector._afetch_over` then makes the list of VSIDs. If the field `gateway_contexts` holds values, they are the list. If not, the list holds each number at the start of a line of the answer to `vsx stat -v`. With an empty list, the fetch sends no more commands.

For each VSID, in order from the lowest, the fetch sends the commands of the next table. `src/hst/collectors/checkpoint_gateway.py` `_expert_command` makes each command. The column "Section" holds the key of the answer in the context of the VSID in the payload. The key of the outcome is `vs:<vsid>:<section>`. The field `capture_bgp` of this source type is a boolean with the default true.

| Section | Command | Sent when |
|---|---|---|
| `interfaces` | `vsenv <vsid> >/dev/null && ip -j address show` | always |
| `routes4` | `vsenv <vsid> >/dev/null && ip -j route show table all` | always |
| `routes6` | `vsenv <vsid> >/dev/null && ip -6 -j route show table all` | always |
| `installation` | `vsenv <vsid> >/dev/null && fw stat -s` | always |
| `links` | `vsenv <vsid> >/dev/null && ip -d -j link show` | always |
| `neighbors4` | `vsenv <vsid> >/dev/null && ip -4 -j neigh show` | always |
| `neighbors6` | `vsenv <vsid> >/dev/null && ip -6 -j neigh show` | always |
| `cluster` | `vsenv <vsid> >/dev/null && cphaprob state` | always |
| `proxy_arp` | `vsenv <vsid> >/dev/null && fw ctl arp -n` | always |
| `fw_interfaces` | `vsenv <vsid> >/dev/null && fw getifs` | always |
| `bridge_groups` | `vsenv <vsid> >/dev/null && clish -c 'set virtual-system <vsid>; show bridging groups'` | always |
| `bridge_members` | `vsenv <vsid> >/dev/null && brctl show` | always |
| `bgp_as` | `vsenv <vsid> >/dev/null && clish -c 'set virtual-system <vsid>; show as'` | `capture_bgp` is true |
| `bgp_peers` | `vsenv <vsid> >/dev/null && clish -c 'set virtual-system <vsid>; show bgp peers'` | `capture_bgp` is true |
| `bgp_config` | `vsenv <vsid> >/dev/null && clish -c 'set virtual-system <vsid>; show configuration bgp'` | `capture_bgp` is true |
| `bgp_routemaps` | `vsenv <vsid> >/dev/null && clish -c 'set virtual-system <vsid>; show configuration routemaps'` | `capture_bgp` is true |

6 commands of the table have a text command as a fallback. `src/hst/collectors/checkpoint_iproute.py` `COMMANDS` holds the text commands. The fetch sends the text command of a section in 2 cases. In case 1, the command of the table fails with a refusal, a timeout or a different SSH fault. In case 2, the answer is not a JSON array of objects.

| Section | Command | Sent when |
|---|---|---|
| `interfaces` | `vsenv <vsid> >/dev/null && ip -o address show` | after a failed JSON command of the section |
| `links` | `vsenv <vsid> >/dev/null && ip -d -o link show` | after a failed JSON command of the section |
| `routes4` | `vsenv <vsid> >/dev/null && ip -o -4 route show table all` | after a failed JSON command of the section |
| `routes6` | `vsenv <vsid> >/dev/null && ip -o -6 route show table all` | after a failed JSON command of the section |
| `neighbors4` | `vsenv <vsid> >/dev/null && ip -o -4 neigh show` | after a failed JSON command of the section |
| `neighbors6` | `vsenv <vsid> >/dev/null && ip -o -6 neigh show` | after a failed JSON command of the section |

If the source sets the field `evidence_file`, the fetch reads that file on the HST host with `src/hst/collectors/checkpoint_evidence.py` `read_evidence`. The read sends nothing to the device.

## equinix

The collector is `src/hst/collectors/equinix.py` `EquinixCollector`. The field `api_url` of the source is the base URL, and the default is `https://api.equinix.com`.

The login is `POST /oauth2/v1/token` with the JSON fields `grant_type` with the value `client_credentials`, `client_id` and `client_secret`. The collector sends the token of the answer in the header `Authorization: Bearer <token>`. The collector sends no logout request.

| Method | Path | Sent when |
|---|---|---|
| GET | `/fabric/v4/ports` | always, and in the connection test with `limit=1` |
| POST | `/fabric/v4/connections/search` | the port list holds 1 or more ports with a `uuid` |
| GET | `/ne/v1/devices` | `network_edge` is true |
| GET | `/ne/v1/links` | `network_edge` is true |
| POST | `/fabric/v4/connections/search` | `network_edge` is true and the device list holds 1 or more devices with a `uuid` |

Each GET has the query parameters `offset` and `limit`. The value of `limit` is the field `page_size` of the source, and the default is 100.

The body of a search holds `filter`, `pagination` and `sort`. `pagination` holds `offset` and `limit`. `sort` holds the property `/changeLog/createdDateTime` with the direction `ASC`. `filter` holds 2 conditions with the operator `IN` under `or`.

| Search | Properties of the 2 conditions | Values |
|---|---|---|
| row 2 of the table | `/aSide/accessPoint/port/uuid`, `/zSide/accessPoint/port/uuid` | the `uuid` of each port |
| row 5 of the table | `/aSide/accessPoint/virtualDevice/uuid`, `/zSide/accessPoint/virtualDevice/uuid` | the `uuid` of each device |

## iosxe

The collector is `src/hst/collectors/iosxe.py` `IosxeCollector`. The connection test sends `show version`.

`src/hst/collectors/iosxe.py` `COMMANDS` holds these commands.

| Section | Command | Sent when |
|---|---|---|
| `device` | `show version` | always |
| `interfaces` | `show interfaces` | always |
| `lldp` | `show lldp neighbors detail` | always |
| `vrfs` | `show vrf` | always |
| `vrf_detail` | `show vrf detail` | always |
| `rib` | `show ip route vrf *` | always |
| `arp` | `show ip arp` | always |
| `cdp` | `show cdp neighbors detail` | always |
| `nat` | `show running-config \| include ^ip nat` | always |
| `nat_stats` | `show ip nat statistics` | always |
| `acl` | `show ip access-lists` | always |
| `bgp` | `show running-config \| section ^router bgp` | always |
| `prefix_lists` | `show running-config \| include ^ip prefix-list` | always |
| `route_maps` | `show running-config \| section ^route-map` | always |
| `interface_config` | `show running-config \| section ^interface` | always |
| `vlan_filter` | `show running-config \| include ^vlan filter` | always |
| `ospf` | `show ip ospf` | always |
| `ospf_interfaces` | `show ip ospf interface` | always |
| `ospf_neighbors` | `show ip ospf neighbor` | always |
| `ospf_lsdb_router` | `show ip ospf database router` | always |
| `ospf_lsdb_network` | `show ip ospf database network` | always |
| `ospf_lsdb_summary` | `show ip ospf database summary` | always |
| `ospf_lsdb_asbr_summary` | `show ip ospf database asbr-summary` | always |
| `ospf_lsdb_external` | `show ip ospf database external` | always |
| `ospf_lsdb_nssa_external` | `show ip ospf database nssa-external` | always |
| `ospf_config` | `show running-config \| section ^router ospf` | always |
| `hsrp` | `show standby brief` | always |
| `vrrp` | `show vrrp brief` | always |

These commands are not in `src/hst/collectors/iosxe.py` `IosxeCollector.OPTIONAL_COMMANDS`: `show version`, `show interfaces`, `show vrf` and `show ip route vrf *`.

After `COMMANDS`, `src/hst/collectors/iosxe.py` `IosxeCollector._afetch_over` sends the commands of the next table. `src/hst/collectors/cisco_common.py` `capture_mtu` sends the MTU commands of `src/hst/collectors/cisco_common.py` `MTU_COMMANDS`. The order is the ARP commands, the BGP commands, the MTU commands and the 2 list commands.

| Section | Command | Sent when |
|---|---|---|
| | `show ip arp vrf <vrf>` | always, for each VRF of the answer to `show vrf` |
| | `show ip bgp summary` | `capture_bgp` is `all` or `sessions` |
| | `show ip bgp vpnv4 vrf <vrf> summary` | `capture_bgp` is `all` or `sessions`, for each VRF other than the default VRF with an IPv4 BGP process |
| | `show bgp all neighbors` | `capture_bgp` is `all` or `sessions` |
| | `show ip bgp neighbors <peer> received-routes` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show ip bgp neighbors <peer> routes` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show ip bgp neighbors <peer> advertised-routes` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show ip bgp vpnv4 vrf <vrf> neighbors <peer> received-routes` | `capture_bgp` is `all`, for each target peer of a different VRF |
| | `show ip bgp vpnv4 vrf <vrf> neighbors <peer> routes` | `capture_bgp` is `all`, for each target peer of a different VRF |
| | `show ip bgp vpnv4 vrf <vrf> neighbors <peer> advertised-routes` | `capture_bgp` is `all`, for each target peer of a different VRF |
| `mtu_ipv4` | `show ip interface` | `capture_mtu` is true |
| `mtu_ipv6` | `show ipv6 interface` | `capture_mtu` is true |
| `mtu_system` | `show system mtu` | `capture_mtu` is true |
| `mtu_members` | `show etherchannel summary` | `capture_mtu` is true |
| | `show running-config \| include ^ip community-list` | the route-map answer refers to a list |
| | `show running-config \| include ^ip as-path access-list` | the route-map answer refers to a list |

The fetch gets the BGP processes from the answer to `show running-config | section ^router bgp`. `src/hst/collectors/iosxe.py` `_bgp_scoped_targets` returns the target peers. A target peer is a neighbor with 1 address in an IPv4 process. `src/hst/collectors/cisco_bgp.py` `expand_dynamic_neighbors` adds a peer of a summary answer as a target peer only if the peer is in exactly 1 listen range.

The route-map answer is the answer to `show running-config | section ^route-map`. `src/hst/collectors/iosxe.py` `match_list_commands` finds a reference to a list in a line that starts with `match community`, `match as-path` or `set comm-list`.

## iosxr

The collector is `src/hst/collectors/iosxr.py` `IosxrCollector`. The connection test sends `show version`.

`src/hst/collectors/iosxr.py` `COMMANDS` holds these commands.

| Section | Command | Sent when |
|---|---|---|
| `device` | `show version` | always |
| `interfaces` | `show interfaces` | always |
| `lldp` | `show lldp neighbors detail` | always |
| `vrfs` | `show vrf all detail` | always |
| `rib` | `show route vrf all ipv4` | always |
| `arp` | `show arp vrf all` | always |
| `cdp` | `show cdp neighbors detail` | always |
| `inventory` | `show inventory` | always |
| `hostname` | `show running-config hostname` | always |
| `bgp` | `show running-config router bgp` | always |
| `prefix_sets` | `show running-config prefix-set` | always |
| `route_policies` | `show running-config route-policy` | always |
| `ospf` | `show ospf` | always |
| `ospf_interfaces` | `show ospf interface` | always |
| `ospf_neighbors` | `show ospf neighbor` | always |
| `ospf_lsdb_router` | `show ospf database router detail` | always |
| `ospf_lsdb_network` | `show ospf database network detail` | always |
| `ospf_lsdb_summary` | `show ospf database summary detail` | always |
| `ospf_lsdb_asbr_summary` | `show ospf database asbr-summary detail` | always |
| `ospf_lsdb_external` | `show ospf database external detail` | always |
| `ospf_lsdb_nssa_external` | `show ospf database nssa-external detail` | always |
| `ospf_config` | `show running-config router ospf` | always |
| `hsrp` | `show hsrp` | always |
| `interface_config` | `show running-config interface \| include "^interface \|access-group"` | always |

These commands are not in `src/hst/collectors/iosxr.py` `IosxrCollector.OPTIONAL_COMMANDS`: `show version`, `show interfaces`, `show vrf all detail`, `show route vrf all ipv4` and `show inventory`.

After `COMMANDS`, `src/hst/collectors/iosxr.py` `IosxrCollector._afetch_over` sends the commands of the next table. `src/hst/collectors/cisco_common.py` `capture_mtu` sends the MTU commands of `src/hst/collectors/cisco_common.py` `MTU_COMMANDS`. The order is the BGP commands, the MTU commands and the 2 set commands.

| Section | Command | Sent when |
|---|---|---|
| | `show bgp summary` | `capture_bgp` is `all` or `sessions` |
| | `show bgp vrf <vrf> ipv4 unicast summary` | `capture_bgp` is `all` or `sessions`, for each VRF other than the default VRF with an IPv4 BGP process |
| | `show bgp neighbors` | `capture_bgp` is `all` or `sessions` |
| | `show bgp vrf all neighbors` | `capture_bgp` is `all` or `sessions` |
| | `show bgp neighbors <peer> received routes` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show bgp neighbors <peer> routes` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show bgp neighbors <peer> advertised-routes` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show bgp vrf <vrf> ipv4 unicast neighbors <peer> received routes` | `capture_bgp` is `all`, for each target peer of a different VRF |
| | `show bgp vrf <vrf> ipv4 unicast neighbors <peer> routes` | `capture_bgp` is `all`, for each target peer of a different VRF |
| | `show bgp vrf <vrf> ipv4 unicast neighbors <peer> advertised-routes` | `capture_bgp` is `all`, for each target peer of a different VRF |
| `mtu_ipv4` | `show ipv4 interface` | `capture_mtu` is true |
| `mtu_ipv6` | `show ipv6 interface` | `capture_mtu` is true |
| `mtu_config` | `show running-config interface` | `capture_mtu` is true |
| `mtu_members` | `show bundle` | `capture_mtu` is true |
| | `show running-config community-set` | the route-policy answer refers to a set |
| | `show running-config as-path-set` | the route-policy answer refers to a set |

The fetch gets the BGP processes from the answer to `show running-config router bgp`. `src/hst/collectors/iosxr.py` `_bgp_scoped_targets` returns the target peers. A target peer is a neighbor with 1 address in an IPv4 process. An IPv6 neighbor is a target peer only if it has the address family IPv4 unicast. `src/hst/collectors/cisco_bgp.py` `expand_dynamic_neighbors` adds a peer of a summary answer as a target peer only if the peer is in exactly 1 neighbor range.

The route-policy answer is the answer to `show running-config route-policy`. `src/hst/collectors/iosxr_bgp.py` `names_a_set` finds a reference to a community set or to an AS path set in that answer.

## manual

The collector is `src/hst/collectors/manual.py` `ManualCollector`. It sends nothing to a device or to a controller. `src/hst/collectors/manual.py` `ManualCollector.fetch` returns the text of the fields `devices` and `mtu_evidence` of the source.

If `mtu_evidence` holds 1 or more observations, the fetch and the connection test read Neo4j. `src/hst/collectors/mtu_import.py` `validate_import_subjects` reads the nodes of the published run that the observations refer to.

## nautobot

The collector is `src/hst/collectors/nautobot.py` `NautobotCollector`. The field `url` of the source is the base URL. The collector sends the API key in the header `Authorization: Token <key>` of each request. It sends no login request and no logout request.

| Method | Path | Sent when |
|---|---|---|
| POST | `/api/graphql` | always, for each page of each of the 5 queries |
| POST | `/api/graphql` | `capture_mtu` is true, for each page of the MTU query |
| GET | `/api/status/` | the connection test only |

| Query | Root field |
|---|---|
| `src/hst/collectors/nautobot.py` `LOCATIONS_QUERY` | `locations` |
| `src/hst/collectors/nautobot.py` `RACKS_QUERY` | `racks` |
| `src/hst/collectors/nautobot.py` `DEVICES_QUERY` | `devices` |
| `src/hst/collectors/nautobot.py` `CABLES_QUERY` | `cables` |
| `src/hst/collectors/nautobot.py` `IP_ADDRESSES_QUERY` | `ip_addresses` |

The body of each request holds `query` and `variables`. The variables are `limit` with the value 100 and `offset`. A query stops after a page with fewer than 100 rows. The MTU query is `DEVICES_QUERY` with the field `mtu` in the interface fields, and it has a maximum of 100 pages.

## ndo

The collector is `src/hst/collectors/ndo.py` `NdoCollector`. The field `url` of the source is the base URL.

The login is `POST /login` with the JSON fields `username` and `password`. The collector sends the token of the answer in the header `Authorization: Bearer <token>`. The collector sends no logout request.

| Method | Path | Sent when |
|---|---|---|
| GET | `/api/v1/schemas` | always |
| GET | `/api/v1/sites` | always |
| GET | `/api/v1/platform/version` | the connection test only |

## netscaler

The collector is `src/hst/collectors/netscaler.py` `NetScalerCollector`. The field `host` of the source is the base URL. The base path is `/nitro/v1/config/`. The collector sends the user name in the header `X-NITRO-USER` and the password in the header `X-NITRO-PASS` of each request. It sends no login request and no logout request.

| Method | Path | Sent when |
|---|---|---|
| GET | `lbvserver` | always, and in the connection test |
| GET | `lbvserver_servicegroup_binding` | always |
| GET | `servicegroup` | always |
| GET | `servicegroup_servicegroupmember_binding` | always |
| GET | `servicegroup_lbmonitor_binding` | always |
| GET | `lbmonitor` | always |
| GET | `Interface` | `capture_mtu` is true |

## nxos

The collector is `src/hst/collectors/nxos.py` `NxosCollector`. The connection test sends `show version | json`.

`src/hst/collectors/nxos.py` `COMMANDS` holds these commands.

| Section | Command | Sent when |
|---|---|---|
| `device` | `show version \| json` | always |
| `interfaces` | `show interface \| json` | always |
| `neighbors` | `show lldp neighbors detail \| json` | always |
| `cdp` | `show cdp neighbors \| json` | always |
| `vlans` | `show vlan \| json` | always |
| `vrfs` | `show vrf \| json` | always |
| `rib` | `show ip route vrf all \| json` | always |
| `mac_table` | `show mac address-table \| json` | always |
| `arp` | `show ip arp vrf all \| json` | always |
| `vrf_interfaces` | `show vrf interface \| json` | always |
| `nat` | `show running-config nat` | always |
| `acl` | `show ip access-lists \| json` | always |
| `bgp` | `show running-config bgp` | always |
| `route_maps`, `prefix_lists` | `show running-config rpm` | always |
| `interface_config` | `show running-config interface` | always |
| `vlan_filter` | `show running-config \| include "^vlan filter"` | always |
| `ospf` | `show ip ospf vrf all \| json` | always |
| `ospf_interfaces` | `show ip ospf interface vrf all \| json` | always |
| `ospf_neighbors` | `show ip ospf neighbors vrf all \| json` | always |
| `ospf_lsdb_router` | `show ip ospf database router detail vrf all \| json` | always |
| `ospf_lsdb_network` | `show ip ospf database network detail vrf all \| json` | always |
| `ospf_lsdb_summary` | `show ip ospf database summary detail vrf all \| json` | always |
| `ospf_lsdb_external` | `show ip ospf database external detail vrf all \| json` | always |
| `ospf_lsdb_nssa_external` | `show ip ospf database nssa-external detail vrf all \| json` | always |
| `ospf_lsdb_asbr_summary` | `show ip ospf database asbr-summary detail vrf all \| json` | always |
| `ospf_config` | `show running-config ospf` | always |
| `trunks` | `show interface trunk \| json` | always |
| `hsrp` | `show hsrp all \| json` | always |
| `vrrp` | `show vrrp detail \| json` | always |
| `vpc` | `show vpc \| json` | always |

These commands are not in `src/hst/collectors/nxos.py` `NxosCollector.OPTIONAL_COMMANDS`: `show version | json`, `show interface | json`, `show vlan | json`, `show vrf | json`, `show ip route vrf all | json`, `show mac address-table | json` and `show vrf interface | json`.

If the source sets the field `json_native`, the fetch adds the word `native` to each command that ends with ` | json`. An example is `show version | json native`. The payload holds the answer under the command without `native`. The change applies to `COMMANDS` and to the BGP commands of the next table. The connection test sends `show version | json` without `native`.

After `COMMANDS`, `src/hst/collectors/nxos.py` `NxosCollector._afetch_over` sends the commands of the next table. `src/hst/collectors/cisco_common.py` `capture_mtu` sends the MTU commands of `src/hst/collectors/cisco_common.py` `MTU_COMMANDS`. The order is the BGP commands and then the MTU commands.

| Section | Command | Sent when |
|---|---|---|
| | `show bgp sessions vrf all \| json` | `capture_bgp` is `all` or `sessions` |
| | `show bgp vrf all neighbors \| json` | `capture_bgp` is `all` or `sessions` |
| | `show bgp sessions \| json` | `capture_bgp` is `all` or `sessions`, the command of row 1 has the status `unsupported` and `show running-config bgp` has the status `ok` |
| | `show bgp ipv4 unicast neighbors <peer> received-routes \| json` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show bgp ipv4 unicast neighbors <peer> routes \| json` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show bgp ipv4 unicast neighbors <peer> advertised-routes \| json` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `show bgp vrf <vrf> ipv4 unicast neighbors <peer> received-routes \| json` | `capture_bgp` is `all`, for each target peer of a different VRF |
| | `show bgp vrf <vrf> ipv4 unicast neighbors <peer> routes \| json` | `capture_bgp` is `all`, for each target peer of a different VRF |
| | `show bgp vrf <vrf> ipv4 unicast neighbors <peer> advertised-routes \| json` | `capture_bgp` is `all`, for each target peer of a different VRF |
| `mtu_media` | `show interface` | `capture_mtu` is true |
| `mtu_ipv4` | `show ip interface` | `capture_mtu` is true |
| `mtu_ipv6` | `show ipv6 interface` | `capture_mtu` is true |
| `mtu_system` | `show running-config all \| i jumbomtu` | `capture_mtu` is true |
| `mtu_qos` | `show policy-map system type network-qos` | `capture_mtu` is true |
| `mtu_queuing` | `show queuing interface` | `capture_mtu` is true |
| `mtu_members` | `show port-channel summary` | `capture_mtu` is true |

The fetch gets the BGP processes from the answer to `show running-config bgp`. `src/hst/collectors/nxos.py` `bgp_capture_targets` returns the target peers. A target peer is a neighbor with 1 address. Its block has the address family `ipv4 unicast`, or it has no address family and an IPv4 address. The function leaves out a neighbor for which `src/hst/collectors/nxos.py` `_states_no_remote_as` returns true.

`src/hst/collectors/cisco_bgp.py` `expand_dynamic_neighbors` adds a peer of the session table only if the peer is in exactly 1 neighbor range. Such a peer goes through the same checks.

## unifi

The collector is `src/hst/collectors/unifi.py` `UnifiCollector`. The field `url` of the source is the base URL. `<site>` is the field `site` of the source, and the default is `default`.

The login is `POST /api/auth/login` with the JSON fields `username` and `password`. The collector sends no logout request. The connection test sends the login only.

| Method | Path | Sent when |
|---|---|---|
| GET | `/proxy/network/api/s/<site>/stat/device` | always |
| GET | `/proxy/network/api/s/<site>/rest/networkconf` | always |
| GET | `/proxy/network/api/s/<site>/rest/portconf` | always |
| GET | `/proxy/network/api/s/<site>/rest/wlanconf` | always |
| GET | `/proxy/network/api/s/<site>/stat/sta` | always |
| GET | `/proxy/network/api/s/<site>/rest/firewallrule` | always |
| GET | `/proxy/network/api/s/<site>/rest/firewallgroup` | always |
| GET | `/proxy/network/v2/api/site/<site>/firewall/zones` | always |
| GET | `/proxy/network/v2/api/site/<site>/firewall-policies` | always |

`src/hst/collectors/unifi.py` `READ_PATHS` holds the last part of each path. If the answer to `rest/portconf`, `rest/firewallrule`, `rest/firewallgroup`, `firewall/zones` or `firewall-policies` has the status 400 or 404, the fetch continues. The payload then holds the path in `refused_reads`.

## velocloud

The collector is `src/hst/collectors/velocloud.py` `VeloCloudCollector`. The field `url` of the source is the base URL. A GET path is relative to the field `api_base_path`, and the default is `/api/sdwan/v2`. A POST path is relative to the base URL.

The collector sends the API key in the header `Authorization: Token <key>` of each request. It sends no login request and no logout request.

| Method | Path | Sent when |
|---|---|---|
| GET | `/enterprises` | the field `enterprise_logical_ids` is empty |
| POST | `/portal/rest/monitoring/getAggregates` | before the reads of each enterprise, until 1 request gets an answer |
| POST | `/portal/rest/enterprise/getEnterpriseEdges` | for each enterprise with a numeric id in the `getAggregates` answer |
| POST | `/portal/rest/enterprise/getEnterpriseConfigurations` | for each enterprise with a numeric id in the `getAggregates` answer |
| POST | `/portal/rest/enterprise/getEnterpriseRouteTable` | for each enterprise with a numeric id in the `getAggregates` answer |
| GET | `/enterprises/<enterprise>/edges` | for each enterprise without an edge from `getEnterpriseEdges` |
| POST | `/portal/rest/edge/getEdgeConfigurationModules` | for each edge with a numeric id, if the enterprise has a numeric id and the poll cache has no valid answer |
| GET | `/enterprises/<enterprise>/bgpSessions` | for each enterprise |

`<enterprise>` is the `logicalId` of the enterprise. The enterprises are the values of `enterprise_logical_ids`, or the rows of `GET /enterprises` if the field is empty.

The connection test sends 1 request. With an enterprise in `enterprise_logical_ids`, it sends `GET /enterprises/<enterprise>/edges` with `limit=1` for the first enterprise. With an empty field, it sends `GET /enterprises` with `limit=1`.

| Path | Body or query |
|---|---|
| `getAggregates` | an empty object |
| `getEnterpriseEdges` | `enterpriseId`, and `with` with the values `site`, `links`, `ha` and `configuration` |
| `getEnterpriseConfigurations` | `enterpriseId`, and `with` with the value `modules` |
| `getEnterpriseRouteTable` | `enterpriseId` |
| `getEdgeConfigurationModules` | `enterpriseId`, `edgeId`, and `modules` with the values `WAN` and `controlPlane` |
| `bgpSessions` | the query parameter `state[is]=ESTABLISHED` on the first page |

A GET for the next page holds only the query parameter `nextPageLink` from the answer before it.

`src/hst/collectors/velocloud_poll.py` `PollCache.read` returns a stored answer to `getEdgeConfigurationModules` in place of a request. The stored answer is valid if the field `cache_enabled` is true, the signature of the edge is the same and the age is below `configuration_refresh_s`. The default of `configuration_refresh_s` is 1800 seconds. [Storage](storage.md#raw-store) gives the path of the poll cache.

`src/hst/collectors/velocloud.py` `VeloCloudCollector._read` sends each request. It sends a maximum of `poll_concurrency` requests in 1 second, and the default is 4. If an answer has the status 429, it sends the request again, a maximum of 3 times.

## vyos

The collector is `src/hst/collectors/vyos.py` `VyosCollector`. `src/hst/collectors/vyos.py` `VyosCollector._op_mode` puts `/opt/vyatta/bin/vyatta-op-cmd-wrapper` before each command that starts with `show `. The connection test sends `/opt/vyatta/bin/vyatta-op-cmd-wrapper show version`.

`src/hst/collectors/vyos.py` `READ_COMMANDS` holds the commands of the first 8 rows. For rows 1 and 2, it holds `show configuration json` and `show version` without the wrapper.

| Section | Command | Sent when |
|---|---|---|
| `config` | `/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration json` | always |
| `version` | `/opt/vyatta/bin/vyatta-op-cmd-wrapper show version` | always |
| `links` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin ip -j link show` | always |
| `addrs` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin ip -j addr show` | always |
| `neigh` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin ip -j neigh show` | always |
| `link_speeds` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin sh -c 'for i in /sys/class/net/*; do n=$(basename "$i"); s=$(cat "$i/speed" 2>/dev/null \|\| echo unknown); d=$(cat "$i/duplex" 2>/dev/null \|\| echo unknown); echo "$n $s $d"; done'` | always |
| `routes` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip route vrf all json"` | always |
| `routes6` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ipv6 route vrf all json"` | always |
| `routes_table_<table>` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip route table <table> json"` | always, for each table with a number under `protocols static table` in the configuration |
| `routes6_table_<table>` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ipv6 route table <table> json"` | always, for each table with a number under `protocols static table` in the configuration |
| `ospf_default_process` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf json"` | the configuration has `protocols ospf` |
| `ospf_default_interfaces` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf interface json"` | the configuration has `protocols ospf` |
| `ospf_default_neighbors` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf neighbor json"` | the configuration has `protocols ospf` |
| `ospf_default_lsdb_router` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf database router json"` | the configuration has `protocols ospf` |
| `ospf_default_lsdb_network` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf database network json"` | the configuration has `protocols ospf` |
| `ospf_default_lsdb_summary` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf database summary json"` | the configuration has `protocols ospf` |
| `ospf_default_lsdb_asbr_summary` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf database asbr-summary json"` | the configuration has `protocols ospf` |
| `ospf_default_lsdb_external` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf database external json"` | the configuration has `protocols ospf` |
| `ospf_default_lsdb_nssa_external` | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf database nssa-external json"` | the configuration has `protocols ospf` |
| | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show bgp vrf all summary json"` | `capture_bgp` is `all` or `sessions` |
| | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip bgp vrf all neighbors json"` | `capture_bgp` is `all` or `sessions` |
| | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show bgp ipv4 unicast neighbors <peer> received-routes json"` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show bgp ipv4 unicast neighbors <peer> routes json"` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show bgp ipv4 unicast neighbors <peer> advertised-routes json"` | `capture_bgp` is `all`, for each target peer of the default VRF |
| | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show bgp vrf <vrf> ipv4 unicast neighbors <peer> received-routes json"` | `capture_bgp` is `all`, for each target peer of a different VRF |
| | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show bgp vrf <vrf> ipv4 unicast neighbors <peer> routes json"` | `capture_bgp` is `all`, for each target peer of a different VRF |
| | `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show bgp vrf <vrf> ipv4 unicast neighbors <peer> advertised-routes json"` | `capture_bgp` is `all`, for each target peer of a different VRF |

If the device refuses the command of row 1 or row 2, the fetch stops. If the device refuses a different command, the fetch continues.

The 9 OSPF rows hold the commands for the default VRF. `src/hst/collectors/vyos.py` `_ospf_command` makes each OSPF command from `src/hst/collectors/vyos.py` `_OSPF_SUBCOMMANDS`. For each VRF that has `protocols ospf` under `vrf name <vrf>` in the configuration, the fetch sends the same 9 commands with `vrf <vrf>` after `ospf`. An example is `PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf vrf <vrf> database router json"`. The section of such a command is `ospf_<vrf>_<name>`, such as `ospf_<vrf>_lsdb_router`.

`src/hst/collectors/vyos.py` `bgp_capture_targets` returns the target peers. A target peer is a neighbor under `protocols bgp` in the configuration of the default VRF or of a different VRF. `src/hst/collectors/vyos.py` `_neighbor_remote_as` must return an AS number for the neighbor. A peer of the summary answer that is in exactly 1 listen range is also a neighbor.

## zia

The collector is `src/hst/collectors/zia.py` `ZiaCollector`. `src/hst/collectors/zscaler_auth.py` `ZscalerSession` sends each request.

The login is `POST https://<vanity_domain>.zslogin.net/oauth2/v1/token`. `<vanity_domain>` is the field `vanity_domain` of the source. The form body holds `grant_type` with the value `client_credentials`, `client_id` and `client_secret`. If the token answer has a status of 500 or more or the status 429, the session sends the token request again after 5 seconds. It does the same after a connection fault. It sends the token request a maximum of 2 times for 1 token.

The session sends the token in the header `Authorization: Bearer <token>`. It gets another token after 66 % of the token lifetime. The token lifetime is the value `expires_in` of the token answer, with a default of 3600 seconds and a minimum of 60 seconds. If a request gets the status 401, the session gets another token and sends the request 1 more time. The session sends no logout request.

The base URL is `https://api.zsapi.net`. The base path is `/zia/api/v1/`.

| Method | Path | Sent when |
|---|---|---|
| GET | `locations` | always, and in the connection test with `page=1` and `pageSize=1` |
| GET | `locations/lite` | always |
| GET | `locations/<id>/sublocations` | for each location that is a `parentId` in the answer to `locations/lite` |
| GET | `locations/<id>/sublocations` | for each location, if the server refuses `locations/lite` |
| GET | `greTunnels` | always |
| GET | `vpnCredentials` | always |
| GET | `locations/groups` | always |
| GET | `forwardingRules` | always |
| GET | `zpaGateways` | a forwarding rule holds a ZPA gateway with an `id` |

Each request for a page has the query parameters `page` and `pageSize` with the value 500. The first page is page 1. The read of `locations/lite` also has `includeSubLocations=true`.

In row 3, the first request for a location has no page parameters. If the answer holds fewer sublocations than the answer to `locations/lite` gives for the location, the fetch reads the pages.

The session sends a maximum of 2 requests in 1 second. If an answer has the status 429, the session waits and sends the request again, a maximum of 4 times.

## zpa

The collector is `src/hst/collectors/zpa.py` `ZpaCollector`. The login, the token and the limits are the same as for [zia](#zia).

The base URL is `https://api.zsapi.net`. The base path is `/zpa/mgmtconfig/v1/admin/customers/<customer_id>/`. `<customer_id>` is the field `customer_id` of the source.

| Method | Path | Sent when |
|---|---|---|
| GET | `application` | always |
| GET | `segmentGroup` | always, and in the connection test with `page=1` and `pagesize=1` |
| GET | `serverGroup` | always |
| GET | `appConnectorGroup` | always |
| GET | `connector` | always |
| GET | `serviceEdge` | always |
| GET | `policySet/rules/policyType/ACCESS_POLICY` | always |
| GET | `policySet/rules/policyType/CLIENT_FORWARDING_POLICY` | always |
| GET | `associationType/CONNECTOR_GRP/provisioningKey` | always |
| GET | `associationType/SERVICE_EDGE_GRP/provisioningKey` | always |
| GET | `/zpa/userconfig/v1/customers/<customer_id>/scimgroup/idpId/<idp_id>` | for each `idpId` of an operand of the type `SCIM_GROUP` in a rule of row 7 or row 8 |

The path of the last row is relative to the base URL. Each request for a page has the query parameters `page` and `pagesize` with the value 500. The first page is page 1.
