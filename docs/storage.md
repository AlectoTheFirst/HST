# Storage

## Data directory and keys

The setting `HST_DATA_DIR` of `src/hst/core/config.py` `Settings` sets the data directory. The default is `./data`. 4 properties of `Settings` give the directories of the file stores.

| Property | Directory | Store |
|---|---|---|
| `raw_dir` | `<HST_DATA_DIR>/raw` | [Raw store](#raw-store) |
| `sidestore_dir` | `<HST_DATA_DIR>/sidestore` | [Side store](#side-store) |
| `manifests_dir` | `<HST_DATA_DIR>/manifests` | [Manifests](#manifests) |
| `graph_archives_dir` | `<HST_DATA_DIR>/graph-archives` | [Graph archives](#graph-archives) |

The stores use 3 keys.

| Key | Source | Use |
|---|---|---|
| operator key | the setting `HST_SECRET_KEY_FILE` or `HST_SECRET_KEY` | encrypts the data key |
| data key | the file `<HST_DATA_DIR>/dek.wrapped` | encrypts the raw store, the graph archives, the encrypted columns in [Postgres](#postgres) and the artifacts in [Other directories of the data directory](#other-directories-of-the-data-directory) |
| signing key | the setting `EVIDENCE_SIGNING_KEY_FILE` or `EVIDENCE_SIGNING_KEY` | signs each manifest |

`src/hst/app/crypto.py` `dek` returns the data key. If `dek.wrapped` does not exist, the function makes a Fernet key and writes it to `dek.wrapped`, encrypted under the operator key. `src/hst/app/crypto.py` `_fernet_for_kek` derives the key for that encryption from the operator key with HKDF-SHA256. The operator key has a minimum of 32 bytes. If the 2 settings of a key have a value, the code reads the file.

Each encrypted file and each encrypted column of the stores holds 1 or more Fernet tokens under the data key. A Fernet token holds AES-128-CBC ciphertext and an HMAC-SHA256 tag.

`hst secret-key` prints a value for the operator key. `hst rotate-secret-key` calls `src/hst/app/crypto.py` `rewrap_dek`. The function encrypts the same data key under another operator key and replaces `dek.wrapped`. The stored data does not change.

## Neo4j

The settings `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` and `NEO4J_DATABASE` give the address, the account and the database. The default address is `bolt://localhost:7687`. If the setting `NEO4J_TLS_CA_FILE` holds the path of a CA bundle, the driver uses TLS. `src/hst/core/db.py` `get_driver` makes 1 driver for each set of address, user and password. `src/hst/core/db.py` `session` opens a session on the database.

Each node of a run has the label `Obj` and holds the run key in `collection_ts`. [Conventions](conventions.md#run-versions) describes the run versions and the run pointer. [Graph schema](schema.md#node-labels) lists the labels. 3 kinds of node have no `collection_ts`.

| Label | `uid` | Content | Code that writes |
|---|---|---|---|
| `CyclePointer` | `meta:cycle-pointer` | the run key of the published run in `current` | `src/hst/core/cycle.py` `set_pointer` |
| `CycleRun` | `cycle:<run key>` | the kind, the state and the source statuses of 1 run | `src/hst/core/cycle.py` `begin_run`, `src/hst/core/cycle.py` `write_cycle_meta` |
| `CollectionRun` | `run:<run id>` | 1 load of 1 collector [batch](conventions.md#loader-contract), with the run key in `snapshot_ts` | `src/hst/core/loader.py` `load` |

`src/hst/core/db.py` `CONSTRAINT_STATEMENTS` holds 1 constraint and the indexes. The constraint `obj_uid_cts` makes the pair of `uid` and `collection_ts` unique for the label `Obj`. `hst init-db` applies the statements with `src/hst/core/db.py` `init_db`.

<!-- generated: neo4j-statements -->
- `CREATE CONSTRAINT obj_uid_cts IF NOT EXISTS FOR (n:Obj) REQUIRE (n.uid, n.collection_ts) IS UNIQUE`
- `CREATE INDEX obj_cts IF NOT EXISTS FOR (n:Obj) ON (n.collection_ts)`
- `CREATE INDEX device_serial IF NOT EXISTS FOR (n:Device) ON (n.serial)`
- `CREATE INDEX device_hostname_fqdn IF NOT EXISTS FOR (n:Device) ON (n.hostname_fqdn)`
- `CREATE INDEX ipaddress_ip IF NOT EXISTS FOR (n:IpAddress) ON (n.ip)`
- `CREATE INDEX prefix_cidr IF NOT EXISTS FOR (n:Prefix) ON (n.cidr)`
- `CREATE INDEX endpoint_mac IF NOT EXISTS FOR (n:Endpoint) ON (n.mac)`
- `CREATE INDEX fwrule_rule_uid IF NOT EXISTS FOR (n:FwRule) ON (n.rule_uid)`
- `CREATE INDEX interface_name IF NOT EXISTS FOR (n:Interface) ON (n.name)`
- `CREATE INDEX interface_edge_device_uid IF NOT EXISTS FOR (n:Interface) ON (n.edge_device_uid)`
- `CREATE INDEX dnsrecord_fqdn IF NOT EXISTS FOR (n:DnsRecord) ON (n.fqdn)`
- `CREATE INDEX vrfinstance_name IF NOT EXISTS FOR (n:VrfInstance) ON (n.name)`
- `CREATE INDEX routingdomain_name IF NOT EXISTS FOR (n:RoutingDomain) ON (n.name)`
- `CREATE INDEX zpaappsegment_zpa_id IF NOT EXISTS FOR (n:ZpaAppSegment) ON (n.zpa_id)`
- `CREATE INDEX zpaappsegment_name IF NOT EXISTS FOR (n:ZpaAppSegment) ON (n.name)`
- `CREATE INDEX zpasegmentgroup_name IF NOT EXISTS FOR (n:ZpaSegmentGroup) ON (n.name)`
- `CREATE INDEX zpasegmentgroup_zpa_id IF NOT EXISTS FOR (n:ZpaSegmentGroup) ON (n.zpa_id)`
- `CREATE INDEX identitygroup_name IF NOT EXISTS FOR (n:IdentityGroup) ON (n.name)`
- `CREATE INDEX zialocation_name IF NOT EXISTS FOR (n:ZiaLocation) ON (n.name)`
- `CREATE INDEX tunnel_source_ip IF NOT EXISTS FOR (n:Tunnel) ON (n.source_ip)`
- `CREATE INDEX ipaddress_ip_key IF NOT EXISTS FOR (n:IpAddress) ON (n.ip_key)`
- `CREATE INDEX endpoint_ip_key IF NOT EXISTS FOR (n:Endpoint) ON (n.ip_key)`
- `CREATE INDEX prefix_lo_key IF NOT EXISTS FOR (n:Prefix) ON (n.lo_key)`
- `CREATE INDEX connected_to_source_cts IF NOT EXISTS FOR ()-[r:CONNECTED_TO]-() ON (r.source, r.collection_ts)`
- `CREATE INDEX bridged_to_source_cts IF NOT EXISTS FOR ()-[r:BRIDGED_TO]-() ON (r.source, r.collection_ts)`
- `CREATE FULLTEXT INDEX obj_names IF NOT EXISTS FOR (n:Obj) ON EACH [n.name, n.description, n.hostname]`
- `CREATE INDEX device_cts IF NOT EXISTS FOR (n:Device) ON (n.collection_ts)`
- `CREATE INDEX interface_cts IF NOT EXISTS FOR (n:Interface) ON (n.collection_ts)`
- `CREATE INDEX port_cts IF NOT EXISTS FOR (n:Port) ON (n.collection_ts)`
- `CREATE INDEX ipaddress_cts IF NOT EXISTS FOR (n:IpAddress) ON (n.collection_ts)`
- `CREATE INDEX prefix_cts IF NOT EXISTS FOR (n:Prefix) ON (n.collection_ts)`
- `CREATE INDEX vrfinstance_cts IF NOT EXISTS FOR (n:VrfInstance) ON (n.collection_ts)`
- `CREATE INDEX endpoint_cts IF NOT EXISTS FOR (n:Endpoint) ON (n.collection_ts)`
- `CREATE INDEX bridgedomain_cts IF NOT EXISTS FOR (n:BridgeDomain) ON (n.collection_ts)`
- `CREATE INDEX interface_uid IF NOT EXISTS FOR (n:Interface) ON (n.uid)`
- `CREATE INDEX device_uid IF NOT EXISTS FOR (n:Device) ON (n.uid)`
- `CREATE INDEX vrfinstance_uid IF NOT EXISTS FOR (n:VrfInstance) ON (n.uid)`
- `CREATE INDEX prefix_uid IF NOT EXISTS FOR (n:Prefix) ON (n.uid)`
- `CREATE INDEX fwrulebase_uid IF NOT EXISTS FOR (n:FwRulebase) ON (n.uid)`
- `CREATE INDEX ipaddress_uid IF NOT EXISTS FOR (n:IpAddress) ON (n.uid)`
- `CREATE INDEX netobject_uid IF NOT EXISTS FOR (n:NetObject) ON (n.uid)`
- `CREATE INDEX pbrpolicy_uid IF NOT EXISTS FOR (n:PbrPolicy) ON (n.uid)`
- `CREATE INDEX tunnel_uid IF NOT EXISTS FOR (n:Tunnel) ON (n.uid)`
- `CREATE INDEX gate_uid IF NOT EXISTS FOR (n:Gate) ON (n.uid)`
- `CREATE INDEX zpaappsegment_uid IF NOT EXISTS FOR (n:ZpaAppSegment) ON (n.uid)`
- `CREATE INDEX virtualservice_uid IF NOT EXISTS FOR (n:VirtualService) ON (n.uid)`
- `CREATE INDEX meta_uid IF NOT EXISTS FOR (n:Meta) ON (n.uid)`
- `CREATE INDEX site_uid IF NOT EXISTS FOR (n:Site) ON (n.uid)`
- `CREATE INDEX site_code IF NOT EXISTS FOR (n:Site) ON (n.code)`
- `CREATE INDEX cyclerun_uid IF NOT EXISTS FOR (n:CycleRun) ON (n.uid)`
- `CREATE INDEX collectionrun_uid IF NOT EXISTS FOR (n:CollectionRun) ON (n.uid)`
- `CREATE INDEX interface_mac_cts IF NOT EXISTS FOR (n:Interface) ON (n.mac, n.collection_ts)`
- `CREATE INDEX device_hostname IF NOT EXISTS FOR (n:Device) ON (n.hostname)`
- `CREATE INDEX gateway_for_cts IF NOT EXISTS FOR ()-[r:GATEWAY_FOR]-() ON (r.collection_ts)`
<!-- end generated: neo4j-statements -->

No code encrypts a value before the write to Neo4j.

`src/hst/core/loader.py` `load` writes the nodes and the relationships of 1 collector batch. [Code flow of a collection](collection-code-flow.md#sequence-of-a-run) describes each other write of a run. `src/hst/core/grapharchive.py` `restore` writes the content of 1 graph archive to a target database.

Each reader gets a session from `src/hst/core/db.py` `session`. [Serving](serving.md#pinned-run-and-read-guards) describes the pinned run and the read guards.

`src/hst/core/cycle.py` `retained_runs` returns the graph window. `src/hst/core/cycle.py` `prune` deletes each run outside the graph window. `src/hst/core/cycle.py` `Keep` holds the 2 counts.

| Runs in the graph window | Count | Setting | Default |
|---|---|---|---|
| the run of the pointer | 1 | | |
| the newest runs of the kinds `full` and `partial` | `cycles` | `CYCLE_KEEP_RUNS` | 30 |
| the newest runs of the kinds `device` and `refresh` that are above the lowest run key of row 2 | `device_runs` | `CYCLE_KEEP_DEVICE_RUNS` | 48 |
| each run in the state `building` that the function `prune` does not delete | | | |

A run key is a time in milliseconds. `src/hst/core/cycle.py` `prune` deletes a run in the state `building` only if its run key is below the pointer and older than 24 hours. `src/hst/core/cycle.py` `orphan_runs` finds the run keys that have objects or `CollectionRun` nodes and no `CycleRun` node. The function `prune` deletes them under the same 2 conditions.

`src/hst/core/cycle.py` `delete_run` deletes the `CycleRun` node first. Then it deletes the relationships, the nodes and the `CollectionRun` nodes of the run in batches of 10,000 rows.

The job `maintenance.prune_graph` and the command `hst prune --keep` call `src/hst/worker/maintenance.py` `prune_graph`. The function deletes 1 run for each hold of the cycle lock and starts with the lowest run key. It does not delete a run with an assessment reference or with a lease. [Retention](#retention) describes these 2 sets of runs.

## Raw store

A raw file holds the payload of 1 fetch. `src/hst/core/rawstore.py` `write` writes the file `<raw_dir>/<source>/<host>/<run_id>.json.gz.enc`.

- `<source>` is the name of the source row and `<host>` is the host of the device.
- `src/hst/core/uid.py` `slug` converts each of the 2 values to a directory name.
- A fetch without a host has no host directory.
- `<run_id>` has the format `<fetch_ts_ms>-<nonce>`.
- `src/hst/collectors/base.py` `new_run_id` makes the run id from the start time of the fetch in milliseconds and 8 hex digits.

The file is 1 Fernet token under the data key. The plaintext is the gzip of the payload as JSON. The setting `RAW_COMPRESS_LEVEL` sets the gzip level, and the default is 6. `src/hst/core/rawstore.py` `write` first writes `<run_id>.json.gz.enc.tmp` and renames the file when the token is complete. Each raw file has the mode 0600 and each directory of its path has the mode 0700.

`src/hst/core/rawstore.py` `read` returns the payload. `src/hst/app/crypto.py` `TokenReader` does a check of the HMAC of the full token before it decrypts the first byte.

These files are in the directory of the raw file and start with the same run id.

| Suffix | Content | Encryption | Code that writes |
|---|---|---|---|
| `.json.gz.enc` | the payload | data key | `src/hst/core/rawstore.py` `write`, `src/hst/core/rawstore.py` `adopt` |
| `.kind.json` | JSON with `kind`, `normalization_context`, `hashes` and `fetch_finished_ms` | none | `src/hst/core/rawstore.py` `mark_kind` |
| `.meta.json` | JSON with `snapshot_ts` and, for a superseded file, `superseded_by` | none | `src/hst/core/rawstore.py` `mark_joined`, `src/hst/core/rawstore.py` `mark_superseded` |
| `.http.jsonl.gz.enc` | the HTTP trace of the fetch, gzip JSON lines in 1 Fernet token | data key | `src/hst/core/rawstore.py` `write_trace` |
| `.debug.jsonl` | the debug records of a load, 1 Fernet token in each line | data key | `src/hst/core/debug_capture.py` `Capture` |
| `.debug-stack.txt` | the stack dump that `faulthandler` writes for a load | none | `src/hst/core/debug_capture.py` `Capture` |
| `.reparse.debug.jsonl` | the debug records of a re-parse, 1 Fernet token in each line | data key | `src/hst/core/debug_capture.py` `Capture` |
| `.reparse.debug-stack.txt` | the stack dump that `faulthandler` writes for a re-parse | none | `src/hst/core/debug_capture.py` `Capture` |
| `.reparse.json.enc` | the result of a re-parse, JSON in 1 Fernet token | data key | `src/hst/core/debug_capture.py` `write_reparse` |

The setting `HST_HTTP_TRACE` lists the sources that get an HTTP trace. `src/hst/core/debug_capture.py` `capture` opens the debug files if the debug switch of the source is on.

The meta file gives the state of a raw file.

| State | Meta file | Code that sets the state |
|---|---|---|
| parked | no meta file | `src/hst/collectors/base.py` `park` |
| joined | `snapshot_ts` holds the run key of the run that loaded the payload | `src/hst/core/rawstore.py` `mark_joined` |
| superseded | `snapshot_ts` is null and `superseded_by` holds a run key | `src/hst/core/rawstore.py` `mark_superseded` |

`src/hst/core/rawstore.py` `parked` returns each raw file without a meta file that has a host directory or a kind file. The kind file of a parked file holds `full` or `observation` in `kind`. A device run loads a `full` payload to the graph and to the side store. It loads an `observation` payload to the side store only, with the 1 exception in [Code flow of a collection](collection-code-flow.md#sequence-of-a-run).

The raw directory holds 6 more kinds of entry.

| Path below `<raw_dir>` | Content | Code that writes |
|---|---|---|
| `.spill/<run_id>-<random>.json.gz.enc.spill` | a payload in the format of a raw file, before its load | `src/hst/core/rawstore.py` `spill` |
| `.pending/<source>/<host>/<run_id>.pending` | an empty marker for 1 raw file without a meta file | `src/hst/core/rawstore.py` `write`, `src/hst/core/rawstore.py` `adopt` |
| `.pending/.built` | an empty marker for a complete `.pending` index | `src/hst/core/rawstore.py` `parked` |
| `.http-trace-<random>.jsonl.gz` | the HTTP trace of a fetch in progress, gzip without encryption | `src/hst/collectors/http_trace.py` `HttpTrace` |
| `checkpoint/replay-cache/<stem>.json.gz.enc` | the rulebase pages of 1 Check Point layer with their revision, in the format of a raw file | `src/hst/collectors/checkpoint.py` `CpCollector.fetch` |
| `velocloud/poll-cache/<digest>/current.json.gz.enc` | the poll cache of the VeloCloud collector, in the format of a raw file | `src/hst/collectors/velocloud_poll.py` `PollCache.save` |

`src/hst/core/rawstore.py` `adopt` renames a spill file to the path of its raw file. The setting `COLLECT_SPILL_MB` sets the payload size from which the fetch phase of a run writes a spill file. The default is 8 MiB, and the value 0 turns the spill files off.

`CpCollector.fetch` and `PollCache.save` write the cache files of the table above with `src/hst/core/rawstore.py` `write`. This code writes the other raw files and the meta files:

- `src/hst/collectors/base.py` `execute` writes the payload and the meta file with the run key.
- `src/hst/collectors/base.py` `execute_observations` writes the payload and the meta file with the run key.
- `src/hst/collectors/base.py` `park` writes the payload and the kind file.
- `src/hst/core/ipam.py` `import_export` writes the payload of an IPAM import, without a host, a kind file and a meta file.
- `src/hst/app/runs_exec.py` `_settle_joined` and `src/hst/app/runs_exec.py` `_settle_superseded` write the meta file of each parked payload of a device run.
- `src/hst/core/reconcile.py` `repair_metadata` writes a missing meta file.

`src/hst/core/rawstore.py` `read` has 14 callers:

- `src/hst/collectors/base.py` `execute` and `src/hst/collectors/base.py` `execute_observations` read the payload of a spill file after the rename.
- `src/hst/app/runs_exec.py` `_join_payload` reads a parked payload for a device run.
- `src/hst/core/replay.py` `rebuild` and `src/hst/core/replay.py` `rebuild_from_manifest` read payloads for `hst rebuild`.
- `src/hst/core/reconcile.py` `repair_derived` reads a payload to write a missing side-store file again.
- `src/hst/core/ipam.py` `annotate` reads an IPAM import.
- `src/hst/map/tier3.py` `_device_payload` reads the payload of a device for the network map.
- `src/hst/collectors/checkpoint_gateway.py` `CpGatewayCollector.management_inventory` reads the newest raw file of another source.
- `src/hst/collectors/checkpoint.py` `CpCollector._cached_pages` and `src/hst/collectors/velocloud_poll.py` `PollCache` read the 2 cache files.
- `src/hst/cli.py` `parse_raw_cmd` reads a payload for `hst parse-raw`.
- `src/hst/app/debug_reparse.py` `_child` reads a payload for a re-parse.
- `src/hst/core/debug_capture.py` `_raw_file_entries` reads a payload for a debug bundle.

`src/hst/cli.py` `http_trace_cmd` and `src/hst/app/routes/runs.py` `http_trace` read an HTTP trace with `src/hst/core/rawstore.py` `read_trace`.

The job `maintenance.prune_rawstore` calls `src/hst/worker/maintenance.py` `prune_rawstore`. If the setting `EVIDENCE_RETENTION_DAYS` has no value, the function deletes no raw file. With a value, the function reads the run key from the meta file and the age from the fetch time in the run id.

| Raw file | Rule |
|---|---|
| without a meta file | The function keeps the file. |
| superseded | The function deletes the file if it is past the period. |
| joined | The function deletes the file if [Retention](#retention) does not keep it and it is past the period. |

A parked file, an IPAM import and the 2 cache files have no meta file. The function also keeps a joined file of a run without a manifest in 2 cases. In case 1, the manifest directory holds no manifest. In case 2, the run key is below the first manifest of the chain.

`src/hst/worker/maintenance.py` `_unlink_raw` deletes the raw file, its HTTP trace and its debug files. It leaves the kind file and the meta file.

`src/hst/worker/maintenance.py` `prune_rawstore` deletes 3 kinds of leftover file with or without a period.

| Leftover file | Minimum time since the last change |
|---|---|
| `.json.gz.enc.tmp` | 6 hours |
| a file in `.spill` | 24 hours |
| `.http-trace-<random>.jsonl.gz` | 24 hours |

## Side store

`src/hst/core/sidestore.py` `write_table` writes the rows of 1 table from 1 load to `<sidestore_dir>/<table>/<source>/<host>/<run_id>.parquet`. The source, the host and the run id are those of the raw file. A load without a host has no host directory.

The file is parquet with the schema of the table in `src/hst/core/sidestore.py` `SCHEMAS`. Each column is nullable. The function sets `run_id` and `snapshot_ts` in each row, and `snapshot_ts` holds the run key. The setting `SIDESTORE_ROW_GROUP_ROWS` sets the maximum row count of 1 row group, and the default is 65,536. The side store has no encryption. Each file of a table has the mode 0600 and each directory of its path has the mode 0700.

<!-- generated: sidestore-tables -->
| Table | Schema version | Column | Type |
|---|---|---|---|
| `rib` | 1 | `device_uid` | `string` |
| `rib` | 1 | `vrf` | `string` |
| `rib` | 1 | `context_uid` | `string` |
| `rib` | 1 | `prefix` | `string` |
| `rib` | 1 | `next_hop` | `string` |
| `rib` | 1 | `next_hop_context_uid` | `string` |
| `rib` | 1 | `interface` | `string` |
| `rib` | 1 | `protocol` | `string` |
| `rib` | 1 | `discard` | `string` |
| `rib` | 1 | `metric` | `int64` |
| `rib` | 1 | `af` | `int64` |
| `rib` | 1 | `prefixlen` | `int64` |
| `rib` | 1 | `lo` | `fixed_size_binary[16]` |
| `rib` | 1 | `hi` | `fixed_size_binary[16]` |
| `rib` | 1 | `run_id` | `string` |
| `rib` | 1 | `snapshot_ts` | `int64` |
| `mac` | 1 | `device_uid` | `string` |
| `mac` | 1 | `vlan` | `int64` |
| `mac` | 1 | `mac` | `string` |
| `mac` | 1 | `port_name` | `string` |
| `mac` | 1 | `bridge_domain_uid` | `string` |
| `mac` | 1 | `run_id` | `string` |
| `mac` | 1 | `snapshot_ts` | `int64` |
| `arp` | 1 | `device_uid` | `string` |
| `arp` | 1 | `vrf` | `string` |
| `arp` | 1 | `context_uid` | `string` |
| `arp` | 1 | `ip` | `string` |
| `arp` | 1 | `mac` | `string` |
| `arp` | 1 | `interface_name` | `string` |
| `arp` | 1 | `af` | `int64` |
| `arp` | 1 | `run_id` | `string` |
| `arp` | 1 | `snapshot_ts` | `int64` |
| `ospf_lsdb` | 1 | `device_uid` | `string` |
| `ospf_lsdb` | 1 | `context_uid` | `string` |
| `ospf_lsdb` | 1 | `process` | `string` |
| `ospf_lsdb` | 1 | `area` | `string` |
| `ospf_lsdb` | 1 | `lsa_type` | `string` |
| `ospf_lsdb` | 1 | `lsid` | `string` |
| `ospf_lsdb` | 1 | `adv_router` | `string` |
| `ospf_lsdb` | 1 | `seq` | `int64` |
| `ospf_lsdb` | 1 | `age` | `int64` |
| `ospf_lsdb` | 1 | `metric` | `int64` |
| `ospf_lsdb` | 1 | `links` | `list<item: struct<link_type: string, link_id: string, link_data: string, metric: int64>>` |
| `ospf_lsdb` | 1 | `attached_routers` | `list<item: string>` |
| `ospf_lsdb` | 1 | `mask` | `string` |
| `ospf_lsdb` | 1 | `forwarding_address` | `string` |
| `ospf_lsdb` | 1 | `metric_type` | `int64` |
| `ospf_lsdb` | 1 | `run_id` | `string` |
| `ospf_lsdb` | 1 | `snapshot_ts` | `int64` |
| `bgp_session_routes` | 1 | `device_uid` | `string` |
| `bgp_session_routes` | 1 | `context_uid` | `string` |
| `bgp_session_routes` | 1 | `session_uid` | `string` |
| `bgp_session_routes` | 1 | `peer_ip` | `string` |
| `bgp_session_routes` | 1 | `af` | `int64` |
| `bgp_session_routes` | 1 | `safi` | `string` |
| `bgp_session_routes` | 1 | `direction` | `string` |
| `bgp_session_routes` | 1 | `rib_type` | `string` |
| `bgp_session_routes` | 1 | `policy_stage` | `string` |
| `bgp_session_routes` | 1 | `path_id` | `string` |
| `bgp_session_routes` | 1 | `prefix` | `string` |
| `bgp_session_routes` | 1 | `prefixlen` | `int64` |
| `bgp_session_routes` | 1 | `lo` | `fixed_size_binary[16]` |
| `bgp_session_routes` | 1 | `hi` | `fixed_size_binary[16]` |
| `bgp_session_routes` | 1 | `next_hop` | `string` |
| `bgp_session_routes` | 1 | `next_hop_context_uid` | `string` |
| `bgp_session_routes` | 1 | `as_path` | `string` |
| `bgp_session_routes` | 1 | `local_pref` | `int64` |
| `bgp_session_routes` | 1 | `med` | `int64` |
| `bgp_session_routes` | 1 | `origin` | `string` |
| `bgp_session_routes` | 1 | `communities` | `string` |
| `bgp_session_routes` | 1 | `best` | `bool` |
| `bgp_session_routes` | 1 | `run_id` | `string` |
| `bgp_session_routes` | 1 | `snapshot_ts` | `int64` |
| `bgp_sessions` | 1 | `device_uid` | `string` |
| `bgp_sessions` | 1 | `context_uid` | `string` |
| `bgp_sessions` | 1 | `session_uid` | `string` |
| `bgp_sessions` | 1 | `peer_ip` | `string` |
| `bgp_sessions` | 1 | `af` | `int64` |
| `bgp_sessions` | 1 | `safi` | `string` |
| `bgp_sessions` | 1 | `state` | `string` |
| `bgp_sessions` | 1 | `established_since_ms` | `int64` |
| `bgp_sessions` | 1 | `prefixes_received` | `int64` |
| `bgp_sessions` | 1 | `prefixes_advertised` | `int64` |
| `bgp_sessions` | 1 | `capabilities` | `string` |
| `bgp_sessions` | 1 | `run_id` | `string` |
| `bgp_sessions` | 1 | `snapshot_ts` | `int64` |
| `checkpoint_envelopes` | 1 | `uid` | `string` |
| `checkpoint_envelopes` | 1 | `label` | `string` |
| `checkpoint_envelopes` | 1 | `envelope_sha` | `string` |
| `checkpoint_envelopes` | 1 | `envelope` | `string` |
| `checkpoint_envelopes` | 1 | `run_id` | `string` |
| `checkpoint_envelopes` | 1 | `snapshot_ts` | `int64` |
<!-- end generated: sidestore-tables -->

If a load has no rows for a table, `src/hst/core/sidestore.py` `write_table` writes no file. `src/hst/core/sidestore.py` `_publish` writes `<run_id>.parquet.tmp`, does an fsync and renames the file.

The side store directory holds 5 more kinds of entry.

| Path below `<sidestore_dir>` | Content | Code |
|---|---|---|
| `.query-catalog.duckdb` | an empty DuckDB catalog that each reader attaches read-only | `src/hst/core/sidestore.py` `connect_reader` |
| `.query-spill/<pid>-<token>/` | the DuckDB spill directory of 1 reader process | `src/hst/core/sidestore.py` `spill_dir` |
| `hst/<table>/<run key>.parquet` | the [tables of the network map](#network-map-tables) | `src/hst/map/store.py` `table_path` |
| `hst/.staging/<run key>/` | the tables of the network map for 1 run before the publish | `src/hst/map/store.py` `staging_dir` |
| `hst/.config/site_config.json` | the site configuration of the network map | `src/hst/map/site_config.py` `write` |

This code writes side-store files:

- `src/hst/collectors/base.py` `_write_side_tables` writes the tables of 1 load.
- `src/hst/core/replay.py` `_replay_side_tables` writes to a scratch directory for `hst rebuild --snapshot --sidestore-scratch`.
- `src/hst/core/reconcile.py` `repair_derived` writes a missing file again from its raw payload, to a repair directory.

If a stop or a row fault ends `src/hst/collectors/base.py` `_write_side_tables`, the function deletes the files that the load wrote.

| Reader | Tables |
|---|---|
| `src/hst/core/ribsource.py` `RibSource` | `rib` |
| `src/hst/core/bgpsource.py` `BgpSource` | `bgp_session_routes`, `bgp_sessions` |
| `src/hst/core/ospfsource.py` `OspfSource` | `ospf_lsdb` |
| `src/hst/core/neighborsource.py` `NeighborSource` | `arp`, `mac` |
| `src/hst/analysis_model/checkpoint_envelopes.py` `read_envelopes` | `checkpoint_envelopes` |
| `src/hst/reasoner/arp_cables.py` `derive_arp_cables` | `arp`, `mac` |
| `src/hst/reasoner/vlan_stretch.py` `read_mac_rows` | `mac` |
| `src/hst/cli.py` `sidestore_query` for `hst sidestore query` | each table in the SQL text |

4 functions read a side-store file with pyarrow and without DuckDB: `src/hst/core/manifest.py` `sidestore_row_facts`, `src/hst/core/sidestore.py` `file_devices`, `src/hst/worker/maintenance.py` `_file_snapshot_ts` and `src/hst/assessment/semantic.py` `read_snapshot_inputs`.

Each reader gets a DuckDB connection from `src/hst/core/sidestore.py` `connect_reader`. The connection is read-only and reads files only below the side store directory. Its limits are 512 MiB of memory, 2 threads and 2,048 MiB of spill space. `src/hst/core/sidestore.py` `query` accepts only `SELECT` and `EXPLAIN` statements and makes no view for the directory `hst`.

A reader for a run with a manifest opens the files that the manifest gives for each device. A reader for a run without a manifest opens each file of the table. For each device, `src/hst/core/ribsource.py` `pick_run` then takes the run id with the highest `snapshot_ts` at or below the run key.

The job `maintenance.prune_sidestore` and the command `hst sidestore prune --keep --yes` call `src/hst/worker/maintenance.py` `prune_sidestore`. Without `--yes`, the command deletes no file.

The function walks the tables of `src/hst/worker/maintenance.py` `SIDESTORE_TABLES` and reads the run key of a file from the column `snapshot_ts`. If the plan of [Retention](#retention) keeps no run, the function deletes no file. It keeps a file if the column does not hold exactly 1 value. It keeps a file that [Retention](#retention) keeps or that is inside the period. It deletes each other file.

The function also deletes a `.parquet.tmp` file after 6 hours without a change. It deletes a spill directory after 6 hours without a use. `src/hst/worker/maintenance.py` `_sweep_hst` applies the retention of the map tables after each graph prune.

### Network map tables

A parquet file of a network map table has the path `<sidestore_dir>/hst/<table>/<run key>.parquet`. `src/hst/map/store.py` `table_path` gives the path. `src/hst/map/tiers/schemas.py` `SCHEMAS` holds the schema of each table. The table `layout_full` has the schema `src/hst/map/tiers/schemas.py` `LAYOUT`. `src/hst/map/tiers/schemas.py` `SCHEMA_VERSIONS` gives the schema version 2 to `render_t1` and the version 1 to each other table of `SCHEMAS`.

`src/hst/app/runs_exec.py` `_hst_projection` makes 1 `src/hst/map/project.py` `Projection` for each run. `src/hst/app/fixture_runs.py` `publish` also calls `_hst_projection`. The projection writes and publishes the tables in 3 steps:

1. `src/hst/app/runs_exec.py` `_write_manifest` gives `Projection.observe` to `_graph_evidence` as the observer of the graph diff. With a parent run, `Projection.observe` writes each record of the diff to `graph_delta`.
2. `_write_manifest` then calls `Projection.prepare`. The function sets `device_uid` in the rows of `graph_delta` with `src/hst/map/graph_delta.py` `fill_devices`. If the graph diff did not finish, it deletes the staged `graph_delta` file. It reads the devices of the run from Neo4j and calls `src/hst/map/tiers/fold.py` `fold`. It places the layout and writes each table to `<sidestore_dir>/hst/.staging/<run key>/<table>.parquet`. It also writes the staged marker `marker.json` to that directory.
3. `src/hst/app/runs_exec.py` `_finalize_cycle` moves the run pointer and then calls `Projection.publish`. `Projection.publish` calls `src/hst/map/store.py` `publish_staged`, which renames each staged table file to its table path. Then it writes the marker file of the run with `src/hst/map/markers.py` `write`.

`fold` reads again the devices that the graph diff changed. It copies the rows of each other device from the tables of the parent run. `src/hst/map/tiers/fold.py` `Parent.load` reads those tables. `fold` reads each device in 5 cases:

- The parent run has no tables.
- The projection of the parent run failed.
- The graph diff of the run did not finish.
- `Projection.replan` is true.
- The count of runs in the timeline divides by the setting `HST_TIER_CHECKPOINT_EVERY` with no remainder. The default is 30.

If a step fails, `Projection.publish` deletes the staged files and the run has no table files. The marker of the run then holds `tiers_ready` false.

| Table | Row | Columns |
|---|---|---|
| `render_t0` | 1 site, plate or block of the map, with the counts of its devices | `uid`, `kind`, `parent_uid`, `label`, `code`, `block_kind`, `device_count`, `observed_count`, `carried_count`, `failed_count`, `added_count`, `removed_count`, `changed_count`, `snapshot_ts` |
| `render_t1` | 1 device of the map | `uid`, `site_uid`, `block_uid`, `group_uid`, `label`, `role`, `tier`, `vendor`, `model`, `os_version`, `mgmt_ip`, `status`, `carried_reason`, `last_seen_ts`, `change`, the 18 count columns of `src/hst/map/tiers/schemas.py` `COUNTS`, `snapshot_ts` |
| `render_t1_edges` | 1 pair of devices with 1 or more cables or tunnels between them | `pair_id`, `a_uid`, `b_uid`, `cable_count`, `lag_count`, `tunnel_count`, `change`, `snapshot_ts` |
| `render_t1_contexts` | 1 context of 1 device, of the kind `vrf`, `vdom`, `zone` or `cp-vs` | `device_uid`, `context_uid`, `identity_uid`, `kind`, `name`, `rd` |
| `render_t1_circuits` | 1 Equinix Fabric virtual circuit with a state other than `DEPROVISIONED`, `DEPROVISIONING` or `DELETED` | `uid`, `name`, `type`, `state`, `bandwidth_mbps`, `provider`, `family`, `a_device`, `a_port`, `a_vlan`, `z_device`, `z_port`, `z_vlan`, `cable_id`, `change` |
| `render_t1_fabric_ports` | 1 Equinix Fabric port | `uid`, `device_uid`, `name`, `ibx`, `metro`, `state`, `speed_mbps`, `redundancy`, `lag_name`, `cable_ids`, `bound_by`, `port_uid`, `port_device`, `binding_issue`, `binding_ports`, `change` |
| `context_identity` | 1 group of the contexts with the same route distinguisher, or with the same name if they have no route distinguisher | `identity_uid`, `basis`, `rd`, `name`, `routing_domain_uid`, `member_count` |
| `render_t2_ports` | 1 port of 1 device | `uid`, `device_uid`, `tile`, `name`, `name_short`, `admin_status`, `oper_status`, `speed_mbps`, `lag_uid`, `connected`, `interface_uid`, `context_uid`, `change` |
| `render_t2_cables` | 1 cable between 2 ports | `cable_id`, `tile_a`, `tile_b`, `a_port`, `b_port`, `a_dev`, `b_dev`, `source`, `speed_mbps`, `speed_agreement`, `carried`, `change` |
| `render_t2_contexts` | 1 context of 1 device, with its position in the order of the device | `uid`, `device_uid`, `tile`, `kind`, `name`, `is_default`, `order`, `change` |
| `render_t2_segments` | 1 bridge domain of 1 device | `uid`, `device_uid`, `tile`, `bridge_domain_uid`, `vid`, `name`, `prefix`, `client_count`, `change` |
| `render_bindings` | 1 object that a count column of `render_t1` counts, if the uid of the object does not hold the uid of its device | `object_uid`, `device_uid`, `label` |
| `render_t0_delta` | 1 row of `render_t0` that the run added, removed or changed | `snapshot_ts`, `parent_ts`, `table`, `tile`, `uid`, `op`, `before`, `after` |
| `render_t1_delta` | 1 row of `render_t1`, `render_t1_edges`, `render_t1_contexts`, `render_t1_circuits`, `render_t1_fabric_ports` or `context_identity` that the run added, removed or changed | the columns of `render_t0_delta` |
| `render_t2_delta` | 1 row of `render_t2_ports`, `render_t2_cables`, `render_t2_contexts` or `render_t2_segments` that the run added, removed or changed | the columns of `render_t0_delta` |
| `graph_delta` | 1 node or relationship that the graph diff of the run against the parent run added, removed or changed | `snapshot_ts`, `parent_ts`, `kind`, `change`, `uid`, `label`, `start_uid`, `end_uid`, `device_uid`, `props_before`, `props_after`, `run_id` |
| `layout` | 1 placement that the run added or changed | `uid`, `kind`, `parent_uid`, `u`, `v`, `w`, `h`, `side`, `slot`, `points`, `valid_from_ts`, `reason`, `layout_version`, `run_id`, `snapshot_ts` |
| `layout_full` | 1 placement in force at the run | the columns of `layout` |

The column `tile` holds the uid of the block of the device. `src/hst/map/tiers/schemas.py` `KEYS` gives the key columns of each table that has a delta table. In a delta row, `uid` holds the key of the changed row, and `op` holds `add`, `remove` or `set`. The column `change` holds `added`, `changed` or `none` against the parent run. In `render_t1`, `change` holds `not-observed` for a device of the parent run with a `status` other than `observed`. In `graph_delta` and `layout`, the column `run_id` holds the run key as text. The `kind` of a `layout` row is 1 of `src/hst/map/layout.py` `KINDS`.

`Projection.prepare` writes `graph_delta` only for a run with a parent run. It writes `layout` only if the run changed a placement. It writes `layout_full` only if the `layout` files since the last `layout_full` file, with the file of the run, reach the count `HST_TIER_CHECKPOINT_EVERY`. It writes each other table at each run.

`src/hst/app/routes/hst.py` reads the tables for the API. A read of a tier table goes through `src/hst/map/tiers/read.py` `tier_at`. For a run without a file of the table, `tier_at` applies the next delta rows to the newest file of an older run. That file is a maximum of 29 runs back, the value of `src/hst/map/tiers/read.py` `MAX_COMPOSE`.

| Route | Tables |
|---|---|
| `GET /api/hst/tier` | the 11 tables of `KEYS`. The name `render_t2_port_groups` gives rows that `src/hst/map/tiers/read.py` `port_groups_at` derives from `render_t2_ports` and `render_t2_cables`. |
| `GET /api/hst/delta` | `render_t0_delta`, `render_t1_delta`, `render_t2_delta`, through `src/hst/map/tiers/read.py` `delta_rows` |
| `GET /api/hst/layout` | `layout`, `layout_full`, through `src/hst/map/layout_read.py` `layout_at` |
| `GET /api/hst/layout-delta` | `layout`, `layout_full` |
| `GET /api/hst/device` | `render_t1`, and `graph_delta` for a cold run through `src/hst/map/tiers/read.py` `device_delta` |
| `GET /api/hst/segment` | `render_t1`, `render_t2_segments` |
| `GET /api/hst/events` | `graph_delta`, `layout`, through `src/hst/map/events.py` `LocalBus.replay` |

The routes `/api/hst/tier`, `/api/hst/delta`, `/api/hst/device` and `/api/hst/segment` answer 409 if the marker of the run holds `tiers_ready` false. `src/hst/app/routes/network_map.py` reads no table file. It reads and writes the Postgres tables `network_map_layouts` and `network_map_views`.

`src/hst/worker/maintenance.py` `_prune_one_run` deletes a maximum of 1 run from Neo4j and then calls `_sweep_hst`. `_sweep_hst` calls `src/hst/map/project.py` `reconcile` for the run of the pointer. Then it calls `src/hst/map/sweep.py` `sweep`, which applies these rules:

- `src/hst/map/sweep.py` `mark_cold` sets `state` to `cold` in the marker of each run that the graph prune deleted.
- If a reader holds a lease on a cold run, the function deletes no file in that turn.
- `src/hst/map/sweep.py` `prune_tiers` deletes the files of the 11 tier tables of each cold run. It keeps the files of 1 cold run for each `HST_TIER_CHECKPOINT_EVERY` runs as a base for `tier_at`. It also keeps the files of a cold run if the projection of the run before it failed.
- If the setting `HST_HISTORY_DAYS` has a value, `src/hst/map/sweep.py` `prune_history` also deletes the oldest cold runs with a `published_ts` older than that count of days. For each such run, it deletes the files of each table and the marker file. It keeps the `layout` files and the `layout_full` file that the oldest remaining run reads.
- The setting `HST_HISTORY_DAYS` has no default value. Without a value, the sweep keeps the files of `graph_delta`, the delta tables, `render_bindings`, `layout` and `layout_full`.

## Manifests

`src/hst/core/manifest.py` `write` writes the manifest of 1 run to `<manifests_dir>/<run key>.json`. `src/hst/core/manifest.py` `path_for` returns that path. The file holds `src/hst/core/manifest.py` `SnapshotManifest` as JSON with sorted keys and without whitespace. The manifest has no encryption. The function writes `<run key>.json.tmp` and renames the file. The file has the mode 0600.

| Field | Content |
|---|---|
| `snapshot_key`, `kind`, `parent`, `opened`, `published` | the run key, the kind of the run, the run key of the parent run and 2 times |
| `app_version`, `build_revision`, `estate` | the version of the code and the value of the setting `ESTATE_NAME` |
| `chain_index`, `previous` | the position in the chain and the link to the previous manifest |
| `sources` | each source with its type, its status and the digest of its redacted configuration |
| `devices` | each device with its outcome, its fetch times, its `effective_run`, and its section and table outcomes |
| `files` | each raw file and each side-store file of the run with its path, its SHA-256 and its size |
| `graph_archive` | the path, the SHA-256, the size and the counts of the graph archive |
| `graph_delta` | the digest of the diff to the previous run |
| `checkpoint` | the digest of the full run, in each manifest where `chain_index` modulo 24 is 0 |
| `site_assignments`, `site_blocks` | the site and the block that the run set for each device |
| `stretch_observations`, `warnings` | the VLAN stretch observations of the reasoner and the warnings of the run |

A side-store entry of `files` also holds `table`, `row_count`, `rows_sha256`, `schema_version` and `device_uids`. The `effective_run` of a device is the run id of the raw file that gives the state of the device in the run.

`src/hst/core/manifest.py` `build` sets `schema_version` to 7 for a run with site blocks and to 6 for each other run. `src/hst/core/manifest.py` `read` accepts the versions 1 to 7 and raises `ValueError` for each other version.

`src/hst/core/manifest.py` `previous_link` finds the manifest with the highest run key below the run key of the manifest in progress. `previous` holds that run key, the SHA-256 of that file and its `chain_index`. The first manifest has no `previous`.

If the deployment has a signing key, `src/hst/core/manifest.py` `write` also writes `<run key>.sig`. `src/hst/core/manifest.py` `sig_path_for` returns that path. `src/hst/core/manifest.py` `AppKeySigner` derives an Ed25519 key from the signing key with HKDF-SHA256 and signs the SHA-256 of the manifest file. The signature file holds `algorithm`, `key_id`, `public_key`, `digest` and `signature`. `src/hst/core/manifest.py` `verify` does a check of a signature. Without a signing key, `src/hst/core/manifest.py` `signer_for` returns `None` and the run has no signature file.

The directory also holds `<run key>.hst.json`, the marker file of the network map. `src/hst/map/markers.py` `write` writes it.

This code writes manifests:

- `src/hst/app/runs_exec.py` `_write_manifest` builds and writes the manifest of a run.
- `src/hst/app/fixture_runs.py` `publish` builds and writes the manifest of a fixture run.
- `src/hst/core/cycle.py` `write_cycle_meta` writes the SHA-256 of the manifest file to `manifest_digest` of the `CycleRun` node.

If a run stops before the publish, `src/hst/app/runs_exec.py` `_remove_run_files` deletes its manifest, its signature file, its graph archive and its staged map tables.

`src/hst/core/manifest.py` `read` returns the manifest of 1 run key.

| Purpose | Code that reads |
|---|---|
| the files of the pinned run for the side-store readers | `src/hst/core/snapshot.py` `Snapshot`, `src/hst/core/ribsource.py` `_Chain`, `src/hst/core/bgpsource.py` `snapshot_evidence` |
| the manifest of the next run | `src/hst/core/manifest.py` `previous_link`, `src/hst/core/manifest.py` `carried_entries`, `src/hst/app/runs_exec.py` `_write_manifest`, `src/hst/app/runs_exec.py` `_previous_devices`, `src/hst/app/fixture_runs.py` `publish` |
| retention | `src/hst/app/retention.py` `manifest_protected_identities`, `src/hst/worker/maintenance.py` `prune_manifests`, `src/hst/worker/maintenance.py` `_assessment_pins`, `src/hst/worker/maintenance.py` `_predates_manifests` |
| `hst rebuild --snapshot` | `src/hst/core/replay.py` `rebuild_from_manifest`, `src/hst/cli.py` `_rebuild_from_manifest` |
| evidence checks and recovery | `src/hst/core/reconcile.py` `verify_evidence` for `hst evidence check`, `src/hst/core/reconcile.py` `materialize_recovery_bundle`, `src/hst/core/reconcile.py` `stage_recovery_data`, `src/hst/core/reconcile.py` `_named_files`, `src/hst/core/reconcile.py` `settle_since_scan`, `src/hst/core/reconcile.py` `repair_derived`, `src/hst/core/reconcile.py` `check_recovery_set`, `src/hst/cli.py` `evidence_export`, `src/hst/cli.py` `recovery_prepare` |
| assessments | `src/hst/assessment/archive_sessions.py`, `src/hst/assessment/lifecycle.py`, `src/hst/assessment/package.py` |
| network map | `src/hst/map/tier3.py` `_device_payload`, `src/hst/app/runs_exec.py` `_hst_marker_fallback` |

The job `maintenance.prune_manifests` calls `src/hst/worker/maintenance.py` `prune_manifests`. If the setting `EVIDENCE_RETENTION_DAYS` has no value, the function deletes no manifest. With a value, the function deletes a manifest that is past the period, with its signature file and its graph archive. The age of a manifest is the time since `opened`. The function keeps these manifests at each age:

1. The newest manifest.
2. The manifest of a run in the graph window, of a run with a lease and of a run with an assessment reference.
3. Each manifest in the `previous` chain below a run with an assessment reference.
4. The `previous` of a manifest from rule 1, 2 or 3, and the `previous` of a manifest inside the period.

## Graph archives

`src/hst/core/grapharchive.py` `write` writes the graph of 1 run to `<graph_archives_dir>/<run key>.graph.enc`. `src/hst/core/grapharchive.py` `path_for` returns that path. If the file exists, the function raises `FileExistsError`. The function writes `<run key>.graph.enc.<random>.tmp`, does an fsync and renames the file. The file has the mode 0600.

The file starts with the 22 bytes of `src/hst/core/grapharchive.py` `MAGIC`. Frames follow. 1 frame is a length of 4 bytes in big-endian order and 1 Fernet token of that length under the data key. The maximum length is 64 MiB.

The token of a data frame holds JSON with `archive_id`, `sequence` and a maximum of 2,000 `records`. The token of the last frame holds JSON with `archive_id`, `sequence`, `final`, `chunks`, `counts`, `records_sha256`, `snapshot_key`, `format_version` and `graph_schema_version`. `records_sha256` is the SHA-256 of the plaintext of the data frames.

A node record holds `kind`, `uid`, `labels`, `props` and `versioned`. A relationship record holds `kind`, `type`, `start`, `end`, `start_versioned`, `end_versioned`, `props` and `versioned`. `versioned` is true if `collection_ts` of the record is the run key.

The archive holds each `Obj` node of the run and each relationship of these nodes. It also holds each `Obj` node without `collection_ts` that such a relationship connects.

The field `graph_archive` of the manifest holds the path, the SHA-256 and the size of the file, and the counts of frames, nodes and relationships. `src/hst/core/grapharchive.py` `verify` compares the file with these values and decrypts each frame.

`src/hst/app/runs_exec.py` `_write_manifest` and `src/hst/app/fixture_runs.py` `publish` call `src/hst/core/grapharchive.py` `write` before they build the manifest.

This code reads graph archives:

- `src/hst/core/replay.py` `rebuild_from_manifest` restores the archive for `hst rebuild --snapshot`.
- `src/hst/assessment/archive_sessions.py` `ArchiveSessions` restores archives to an empty replay target for an assessment.
- `src/hst/assessment/package.py` `_reseal` copies the archive to an assessment package and encrypts each frame under the package key.
- `src/hst/assessment/package.py` `package_key` and `src/hst/assessment/package.py` `replay_status` do the checks of an archive in a package.
- `src/hst/core/reconcile.py` `materialize_recovery_bundle` and `src/hst/core/reconcile.py` `stage_recovery_data` do the checks of the archive of a recovery set.
- `src/hst/app/fixture_runs.py` `publish` does the checks of the archive of the previous run.

`src/hst/core/grapharchive.py` `restore` does the same checks on the full file before the first write. Then it creates the nodes and the relationships. A record with `versioned` true gets the target run key in `collection_ts`.

`src/hst/worker/maintenance.py` `prune_manifests` deletes a graph archive together with its manifest. No other job deletes a graph archive. No code deletes a `.tmp` file that a killed process left in the directory.

## Other directories of the data directory

The code writes these paths below `<HST_DATA_DIR>` outside the directories of the file stores.

| Path below `<HST_DATA_DIR>` | Content | Code that writes | Code that deletes |
|---|---|---|---|
| `analysis-cache/<SHA-256>.artifact` | 1 compiled analysis model in 1 Fernet token under the data key | `src/hst/analysis_model/cache.py` `ArtifactCache.publish` | `src/hst/analysis_model/cache.py` `ArtifactCache.evict`, if the cache is above the size of the setting `ANALYSIS_CACHE_MB` |
| `analysis-cache/.<SHA-256>.lock` | an empty lock file for 1 artifact | `src/hst/analysis_model/cache.py` `ArtifactCache._blob_lock` | no code |
| `analysis-results/<SHA-256>.artifact` | the result of 1 analysis with its binding and its evidence, JSON in 1 Fernet token under the data key | `src/hst/assessment/result_artifacts.py` `ResultArtifactStore.publish` | no code |
| `collection-progress/<SHA-256 of the source name>.json` | the progress of the collection of 1 source | `src/hst/core/collection_progress.py` `CollectionProgress.write` | no code |
| `debug-capture/switches.json` | the debug switch of each source with its end time | `src/hst/core/debug_capture.py` `set_switch` | no code |
| `quarantine/<time>/` | the raw files and the side-store files that `hst evidence reconcile --apply` moves out of the stores, and `report.json` | `src/hst/core/reconcile.py` `quarantine` | no code |
| `replay/<run key>/` | the side-store files that `POST /api/snapshots/{key}/rebuild` writes again from the raw payloads | `src/hst/app/routes/snapshots.py` `rebuild_snapshot`, `src/hst/core/replay.py` `_replay_side_tables` | no code |
| `run-cancel/<id>-<random>.json` | 1 cancel request for 1 row of `runs` | `src/hst/core/run_cancel.py` `request` | `src/hst/core/run_cancel.py` `take` for each request of the run that it reads and for each file that it cannot read as a request, `src/hst/core/run_cancel.py` `request` for each file older than 3,600 s |

## Postgres

The setting `POSTGRES_DSN` gives the address. The default is `postgresql+asyncpg://hst:change-me@localhost:5433/hst`. If the setting `POSTGRES_CA_FILE` holds the path of a CA bundle, the connection uses TLS.

`src/hst/app/store/pg.py` `metadata` holds the definitions of the tables. The definitions are in `src/hst/app/store/pg.py` and in `src/hst/app/inventory/tables.py`. The migrations are in `src/hst/app/store/migrations/versions`. `src/hst/app/store/pg.py` `upgrade_to_head` applies the migrations, and `hst migrate` calls it. If the setting `HST_RUN_MIGRATIONS` is true, `src/hst/worker/runtime.py` `open_store` calls it at the start of `hst serve` and `hst worker`.

| Class | Tables |
|---|---|
| `src/hst/app/store/pg.py` `PgStore` | the tables of `src/hst/app/store/pg.py` without `analysis_cache_artifacts` and `analysis_cache_leases`, and `inventory_devices` for a change of a device uid |
| `src/hst/app/inventory/repository.py` `PgInventoryRepository` | the tables of `src/hst/app/inventory/tables.py` |
| `src/hst/analysis_model/cache.py` `PgCacheIndex` | `analysis_cache_artifacts`, `analysis_cache_leases` |

`src/hst/assessment/store.py` `AssessmentStoreMixin` gives `PgStore` the operations on `assessment_records`. A row of that table holds 1 JSON document with a kind, an id and a revision. A Business Application has the kind `application`. The table `application_reviews` holds the review flags of the Business Applications. A row has the `state` `open` or `closed`, and `src/hst/app/store/pg.py` `PgStore.open_application_review` writes a row with the state `open`.

| Group | Tables |
|---|---|
| accounts and sessions | `users`, `sessions`, `personal_access_tokens` |
| single sign-on | `auth_providers`, `identities`, `group_mappings`, `auth_state` |
| sources and devices | `sources`, `devices`, `device_status`, `target_devices`, `device_identity`, `device_identity_meta` |
| sites and places | `sites`, `site_members`, `reported_locations`, `geo_places` |
| runs and jobs | `runs`, `jobs`, `run_leases` |
| settings | `app_settings` |
| audit records | `login_events`, `cypher_events`, `evidence_exports`, `ai_events` |
| AI conversations | `ai_prompt_versions`, `ai_conversations`, `ai_messages`, `ai_steps`, `ai_links` |
| changes | `changes`, `change_intents` |
| assessments, Business Applications and the analysis cache | `assessment_records`, `application_reviews`, `analysis_cache_artifacts`, `analysis_cache_leases` |
| network map | `network_map_layouts`, `network_map_views` |
| collection profiles and credentials | `collection_credentials`, `collection_credential_versions`, `collection_profiles`, `collection_profile_versions` |
| device inventory | `inventory_devices`, `inventory_targets`, `inventory_observations`, `inventory_placements`, `inventory_publications`, `inventory_staged_targets`, `inventory_staged_observations`, `inventory_events`, `inventory_saved_views`, `inventory_routing_groups`, `inventory_routing_members`, `inventory_state`, `inventory_operation_results`, `inventory_operation_previews`, `inventory_preview_impacts`, `inventory_outbox` |

5 columns hold a Fernet token under the data key. `src/hst/app/crypto.py` `encrypt_secrets` makes the token from a JSON map. No other column has encryption.

| Column | Content | Code that encrypts |
|---|---|---|
| `sources.secrets` | the credentials of a source | `src/hst/app/routes/sources.py` `create_source`, `src/hst/app/sources.py` `merge_config`, `src/hst/cli.py` `sources_add` |
| `app_settings.secrets` | the credentials of the AI provider | `src/hst/app/routes/ai.py` `put_ai_settings` |
| `auth_providers.secrets` | the OIDC client secret or the SAML private key | `src/hst/app/routes/auth_settings.py` `create_provider`, `src/hst/app/routes/auth_settings.py` `patch_provider` |
| `collection_credential_versions.sealed` | the secret map of 1 credential version | `src/hst/app/inventory/credentials.py` `seal` |
| `inventory_operation_previews.secret_draft` | the secret draft of 1 preview | `src/hst/app/inventory/credentials.py` `seal_draft` |

`users.password_hash` holds an Argon2 hash from `src/hst/app/security.py` `hash_password`. `sessions.token_hash` and `personal_access_tokens.token_hash` hold the SHA-256 of a token from `src/hst/app/security.py` `token_hash`.

The purge jobs in [Retention](#retention) delete rows by age. No code deletes a row of `evidence_exports`.

## Retention

`src/hst/worker/scheduler.py` `SYSTEM_SCHEDULES` holds the interval of each maintenance job except `maintenance.build_device_run`. `src/hst/worker/scheduler.py` `Scheduler` adds that job with the interval of the setting `DEVICE_RUN_INTERVAL_S`. `src/hst/worker/maintenance.py` `BODIES` gives the function of each job kind.

| Job kind | Interval | Action | Setting of the limit | Default |
|---|---|---|---|---|
| `maintenance.prune_graph` | 3,600 s | deletes runs in Neo4j | `CYCLE_KEEP_RUNS`, `CYCLE_KEEP_DEVICE_RUNS` | 30, 48 |
| `maintenance.prune_sidestore` | 3,600 s | deletes side-store files | `CYCLE_KEEP_RUNS`, `CYCLE_KEEP_DEVICE_RUNS`, `EVIDENCE_RETENTION_DAYS` | 30, 48, no value |
| `maintenance.prune_rawstore` | 3,600 s | deletes raw files | `EVIDENCE_RETENTION_DAYS` | no value |
| `maintenance.prune_manifests` | 3,600 s | deletes manifests and graph archives | `EVIDENCE_RETENTION_DAYS` | no value |
| `maintenance.purge_sessions` | 3,600 s | deletes the expired and the idle rows of `sessions` and the expired rows of `auth_state`, and calls `src/hst/worker/maintenance.py` `_inventory_housekeeping` | `SESSION_TTL_HOURS`, `SESSION_IDLE_TIMEOUT_HOURS` | 168, 8 |
| `maintenance.purge_login_events` | 3,600 s | deletes rows of `login_events` | `LOGIN_EVENT_RETENTION_DAYS` | 90 |
| `maintenance.purge_cypher_events` | 3,600 s | deletes rows of `cypher_events` | `CYPHER_EVENT_RETENTION_DAYS` | 180 |
| `maintenance.purge_ai_conversations` | 3,600 s | deletes rows of `ai_conversations` by the time of the last message | `AI_CONVERSATION_RETENTION_DAYS` | 90 |
| `maintenance.compact_ai_steps` | 3,600 s | sets `result` of rows of `ai_steps` to null | `AI_STEP_RESULT_DAYS` | 14 |
| `maintenance.purge_ai_ephemeral` | 3,600 s | deletes the ephemeral rows of `ai_conversations` after 24 hours | | |
| `maintenance.purge_ai_events` | 3,600 s | deletes rows of `ai_events` | `AI_EVENT_RETENTION_DAYS` | 180 |
| `maintenance.purge_job_history` | 86,400 s | deletes the finished rows of `jobs` | `JOB_HISTORY_RETENTION_DAYS` | 30 |
| `maintenance.build_device_run` | `DEVICE_RUN_INTERVAL_S`, default 600 s | builds 1 run from the parked raw files | | |

5 purge jobs and the compact job have a limit in days. For these 6 limits, the value 0 keeps each row. With the value 0 of `AI_CONVERSATION_RETENTION_DAYS`, the job `maintenance.purge_ai_ephemeral` deletes no row. The row `retention` of the table `app_settings` replaces the defaults of the 2 run counts and of these 6 limits. `src/hst/app/retention.py` `resolve` reads the row, and `PATCH /api/settings/retention` writes it.

`src/hst/worker/maintenance.py` `prune_sidestore` and `src/hst/worker/maintenance.py` `prune_rawstore` each build 1 `src/hst/app/retention.py` `Plan` for each turn. The plan keeps 3 sets of runs.

| Set | Source |
|---|---|
| graph window | the result of `src/hst/core/cycle.py` `retained_runs` |
| assessment references | the run of each retained assessment, from `src/hst/worker/maintenance.py` `_assessment_refs` |
| leases | the rows of `run_leases` that are not expired, which `src/hst/app/store/pg.py` `PgStore.lease_run` writes for a reader |

`src/hst/app/retention.py` `Plan.keeps` keeps a raw file or a side-store file in 4 cases:

1. A run of the 3 sets has the run key of the file.
2. The manifest of such a run lists the file, or has the run id of the file as the `effective_run` of a device.
3. A run of the 3 sets has no manifest, and the run key of the file is not above the run key of that run.
4. The run key of the file is above the highest run key of the graph window.

The setting `EVIDENCE_RETENTION_DAYS` sets the period in days. Each prune function tries the cycle lock with `src/hst/app/store/pg.py` `PgStore.try_cycle_lock`. If a run holds the lock, the function ends the turn before it deletes a run, a store file or a manifest.
