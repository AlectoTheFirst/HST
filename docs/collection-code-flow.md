# Code flow of a collection

## Entry points

`src/hst/app/runs_exec.py` `launch` starts each cycle, each source run and each device run. [Kinds of run](#kinds-of-run) describes these 3 runs. [Conventions](conventions.md#run-versions) describes the run key and the run pointer. `src/hst/app/runs_exec.py` `run_blocking` calls `launch` and waits for the run with `wait_for_run`. `src/hst/app/runs_exec.py` `run_device_fetch` fetches 1 device and does no load.

| Entry | Code | Call |
|---|---|---|
| `hst cycle` | `src/hst/cli.py` `cycle_cmd` | `run_blocking` with the source `cycle` |
| `hst run <name>` | `src/hst/cli.py` `run_cmd` | `run_blocking` with the name of the source row |
| `POST /api/runs` with `RUN_EXECUTION=inline` | `src/hst/app/routes/runs.py` `trigger` | `launch` with the source of the request body |
| `POST /api/runs` with `RUN_EXECUTION=queue` | `src/hst/app/routes/runs.py` `_enqueue` | `src/hst/worker/collect.py` `enqueue_run`, which queues a `collect.run` job |
| job `collect.run` | `src/hst/worker/collect.py` `collect_run_body` | `launch`, then `wait_for_run` |
| job `collect.cycle` | `src/hst/worker/collect.py` `collect_cycle_body` | `run_blocking` with the source `cycle` |
| job `maintenance.build_device_run` | `src/hst/worker/maintenance.py` `_build_device_run_body` | `run_blocking` with the source `device-run` |
| job `collect.fetch` | `src/hst/worker/collect.py` `collect_fetch_body` | `run_device_fetch` |
| `hst load-fixture <path>` | `src/hst/cli.py` `load_fixture_cmd` | `src/hst/app/fixture_runs.py` `publish` |
| `hst rebuild` | `src/hst/cli.py` `rebuild_cmd` | [Point-in-time rebuild](#point-in-time-rebuild) |

The default of `RUN_EXECUTION` is `inline`. [Worker](#worker) lists the code that queues each job kind.

The argument `source` of `launch` is the name of a source row or 1 of 4 fixed values. The value selects the builder.

| Source | Builder in `src/hst/app/runs_exec.py` | Kind of run |
|---|---|---|
| `cycle` | `execute_cycle` | `full` |
| the name of a source row | `execute_refresh` | `refresh` |
| `device-run` | `build_device_run` | `device` |
| `demo`, if `HST_DEMO_FIXTURES` has a value | `execute_demo` | `full` |
| `reasoner` | `execute_source` | no run |

`execute_source` raises `RuntimeError` with the text of `REASONER_REFUSAL`, and `launch` gives the row in `runs` the status `error`. `hst reason` without a subcommand prints the same text and exits with the status 1.

`launch` returns `None` and writes no row in the table `runs` in these cases:

- The source row does not exist or is disabled.
- A different run holds the [run claim](#locks-and-the-fence) of the source.
- The source is `device-run` and `src/hst/core/rawstore.py` `parked` returns no [parked payload](storage.md#raw-store).

`launch` writes a row in `runs` and starts no builder in 2 cases. If a cycle has no enabled source, the row has the status `ok`. If the requested source has a source fault from `_prepare_all`, the row has the status `error`.

## Kinds of run

[Conventions](conventions.md#kinds-and-states-of-a-run) gives the values of `kind` on a `CycleRun` node.

| Run | `kind` | Fetch | Load | Carry |
|---|---|---|---|---|
| cycle | `full` | each unit of each enabled source | each fetched payload that [Change detection](#change-detection) does not skip | each unit without a load |
| source run | `refresh` | each unit of 1 source | each fetched payload | each unit of each other source, and each unit of the source without a load |
| device run | `device` | none | the parked payload with the highest fetch time for each device | each other unit |
| fixture run | `full` | none | 1 batch from a YAML fixture | the objects of the sources in the manifest of the published run, if `--new-run` is absent |
| rebuild | `full`, or the kind in the manifest | none | raw files or 1 graph archive, into a target database | none |

A unit is 1 `PreparedDevice` object, and `src/hst/app/runs_exec.py` `_prepare_all` makes the units. A source with enabled device rows has 1 unit for each enabled device row. Under resolver version 2, a device row that `src/hst/app/inventory/collection.py` `Resolver.resolve` returns as not enabled is not a unit. A source without device rows has 1 unit. A source has no unit and gets a source fault in 6 cases:

- The source has device rows and no enabled device row.
- The source is a group source without device rows and without `host` in its configuration.
- Under resolver version 1, the read of the credentials of the source raises.
- Under resolver version 1, the source has no device rows and the build of its collector raises.
- Under resolver version 2, the source has no device rows and `Resolver.resolve` raises.
- Under resolver version 2, `Resolver.resolve` returns no enabled target for the source.

`execute_cycle` sets the kind `partial` if the argument `fresh` does not hold each prepared source. `launch` puts each prepared source in `fresh`. No code in `src/hst` passes a smaller set, so no entry point writes the kind `partial`.

If the pointer has no run key, `execute_refresh` calls `execute_cycle` and the run has the kind `full`. If the pointer has no run key, `build_device_run` returns and makes no run.

`src/hst/app/fixture_runs.py` `publish` makes a fixture run. An example of a fixture is `fixtures/mini-dc.yaml`.

- The run key is the result of `src/hst/core/cycle.py` `new_collection_ts`. If the result is not above the key of the published run, the run key is that key plus 1.
- The run writes no raw file and no side-store file.
- With `--new-run`, the run has no parent and holds only the batch of the fixture.
- Without `--new-run`, the function does a check of the graph archive of the published run with `src/hst/core/grapharchive.py` `verify`. Then `src/hst/core/cycle.py` `carry_forward` copies the objects of the sources in the manifest of that run.
- Without `--new-run`, the function raises `FixtureExtendError` if the published run has no manifest or no graph archive.
- `--dry-run` reads the fixture and stops before the load.

`execute_demo` calls `publish` with `new_run=True` for each run file of the demo estate, in order.

## Sequence of a run

The list gives the steps of a cycle. `launch` does steps 1 to 8 and 26 to 29 on the event loop. `_drained` runs the builder on a thread of the pool `_BUILDERS`, and the builder does steps 9 to 25. Each function without a path is in `src/hst/app/runs_exec.py`.

1. `_write_site_config` reads the sites from Postgres. It writes the site configuration of the network map below the side-store directory.
2. `_prepare_all` reads the source rows and the device rows. It decrypts the credentials and builds 1 collector for each unit. A fault of 1 source or of 1 unit goes into `error` of `PreparedSource` or `PreparedDevice`.
3. `capture_execution` reads the resolver version, the placement generation and the placement revisions from the inventory into an `ExecutionCapture`. `launch` puts the result of `_site_blocks` for the site configuration of step 1 into the capture.
4. `src/hst/app/store/pg.py` `PgStore.start_run` takes the run claim of the source. It inserts a row with the status `running` in the table `runs`.
5. `_arm_identity` gives each collector the device identity registry of the store.
6. `_effective_assignments` reads the site of each device uid that Postgres holds.
7. `src/hst/app/store/pg.py` `PgStore.cycle_lock` takes the cycle lock and returns the fence.
8. `launch` reads the rows of the table `device_status` with `PgStore.list_device_status`. A source run does not read them.
9. `_arm_stop` gives each collector the stop flag of its source.
10. The builder takes the process lock `_CYCLE_LOCK` and opens a Neo4j session. `src/hst/core/cycle.py` `current_ts` reads the run key of the pointer, which is the parent run. `src/hst/core/cycle.py` `new_collection_ts` returns the time in milliseconds as the run key.
11. `_building` calls `src/hst/core/cycle.py` `begin_run`. The function writes the `CycleRun` node of the run with the state `building`.
12. `_clear_spills` deletes each spill file in the raw store. The builder makes a `_FetchBuffer` with each unit that has a collector.
13. `_collect_sources` goes through the units in the order of `_prepare_all`. For each unit it gets the fetch result from the `_FetchBuffer`. If the buffer does not hold the result, `_fetch_phase` fetches the next window of units. [Fetch](#fetch) and [Change detection](#change-detection) describe this step.
14. `_collect_sources` handles each fetch result in 1 of 4 ways. A fetch fault fails the unit. A skipped result writes nothing. A result with changed observations goes to `_publish_observations`, which calls `src/hst/collectors/base.py` `execute_observations`. Each other result goes to `src/hst/collectors/base.py` `execute`.
15. `execute` writes the raw file with `src/hst/core/rawstore.py` `write`, or moves the spill file with `src/hst/core/rawstore.py` `adopt`. `_seal_trace` writes the HTTP trace if the fetch has one. `src/hst/core/rawstore.py` `mark_joined` writes the meta file with the run key. `_report` gives the path and the SHA-256 of the file to `RunEvidence`. After a move of a spill file, `src/hst/core/rawstore.py` `read` reads the payload from the raw file.
16. `execute` calls `src/hst/collectors/base.py` `load_payload`. `execute_observations` does the writes of step 15 and calls `src/hst/collectors/base.py` `load_observations`. [Load of one payload](#load-of-one-payload) describes this step. After the last unit, `_FetchBuffer.close` releases each fetch result that no load took.
17. `_stopped` does a check of the stop flag. `_note_rechecks` reads the last check time of each unit without a result from its `device_status` row.
18. `_carry_phase` calls `src/hst/core/cycle.py` `carry_forward`. [Carry](#carry) describes this step.
19. `_finalize_cycle` gets the site assignments. If the inventory is activated, the hook `before_finalize` calls `_stage_results` and returns the site assignments of the inventory. Without the hook, `_with_group_sites` adds the `site_code` of each group source to the result of step 6.
20. `_device_entries` makes the device entries of the manifest. `src/hst/core/manifest.py` `carried_entries` copies the file entries of the units without a load from the manifests of the parent chain.
21. `src/hst/core/finalize.py` `finalize_derivations` does the derivations. [Reasoner run](#reasoner-run) describes this step.
22. `src/hst/core/cycle.py` `cycle_counts` counts the nodes and the relationships of the run.
23. `_hst_projection` makes the `Projection` of the network map. `_write_manifest` writes the graph archive and the manifest.
24. `src/hst/core/cycle.py` `write_cycle_meta` writes the `CycleRun` node with the state `built`. `_stopped` does a check of the stop flag. `src/hst/core/cycle.py` `set_pointer` moves the pointer to the run key.
25. `src/hst/map/project.py` `Projection.publish` moves the staged map tables into place. `_building` ends, and `_discard_unpublished` deletes nothing because the pointer holds the run key.
26. `_record_outcomes` writes 1 `device_status` row for each unit with a result.
27. `launch` releases the cycle lock.
28. `_record_ran` calls `pin_host_key` for each unit that the builder returns in `ran`. It calls `PgStore.record_target_devices` for each of those units with a value in `last_device_uids`. Then `_publish_inventory` publishes the inventory observations of the run.
29. `PgStore.finish_run` writes the status, the detail and the run key into the row of step 4. It releases the run claim.

[Publication](#publication) describes steps 22 to 25 and a run that stops before step 24.

A source run does the same steps with `execute_refresh`. It differs in 5 points:

- `_arm_stop` gives a source flag only to the collectors of the requested source.
- The `_FetchBuffer` holds only the units of the requested source and gets no `device_status` rows.
- If the requested source has the status `failed` after step 16, the builder raises `RuntimeError` and publishes nothing.
- If an operator cancels the requested source, the builder raises `RunCancelled` and publishes nothing.
- The builder does not call `_note_rechecks` in step 17.

A device run does steps 1 to 11 and 17 to 29 with `build_device_run`. It does these steps in place of steps 12 to 16:

1. Before step 11, `src/hst/core/rawstore.py` `parked` lists the parked payloads. If the list is empty, the builder returns and makes no run. `_window` selects the payload with the highest fetch time for each pair of source and host.
2. `_last_observed` returns the time of the last observation of the device in the parent run. If the fetch time of the payload is not above that time, the builder does not load the payload.
3. `_join_payload` reads the payload with `src/hst/core/rawstore.py` `read`.
4. For a payload of the kind `observation`, `_join_payload` calls `load_observations`.
5. For a payload of the kind `full`, `_join_payload` sets the `normalization_context` of the kind file on the configuration of the collector. Then it calls `load_payload`.
6. An `observation` payload gets the load of step 5 in 1 case. The window holds a `full` payload of the same device, and step 2 does not exclude that payload.

A device run has 6 more differences:

- `launch` returns `None` before step 1 if `parked` returns no payload. In step 4, `launch` holds the cycle lock, calls `parked` a second time and then calls `start_run`.
- If no prepared unit has the source and the host of a payload, the payload stays parked.
- `_arm_stop` gives each collector the flag of the run, and no source has a flag.
- If the load of a payload raises, the payload stays parked and the unit gets the carry reason `failed`.
- If no payload gets a load, the builder returns without a run key and `_discard_unpublished` deletes the run.
- In step 26, `_record_graphs` writes the digests in place of `_record_outcomes`.

After `Projection.publish` in step 25 of a device run, `_settle_joined` writes the meta file of each loaded payload with the run key. `_settle_superseded` writes 2 groups of meta files. Group 1 holds each payload that step 2 excluded and each older payload of the same device. Group 2 holds each payload that step 1 excluded for a loaded payload. If no payload gets a load, the builder writes only group 1. If the run fails before step 24, each payload of the window stays parked.

## Fetch

`src/hst/collectors/base.py` `Collector.fetch` reads 1 device or 1 controller and returns the payload. `Collector.afetch` calls `fetch` on a thread. `src/hst/collectors/cli_collector.py` `SshCliCollector.afetch` sends the commands over an asyncssh session if the transport of the configuration is `asyncssh`.

Code in 3 places starts a fetch.

| Code | Use | Fetch |
|---|---|---|
| `src/hst/app/runs_exec.py` `_fetch_phase_async` | a cycle and a source run from `launch` | 1 window of units in 2 lanes |
| `src/hst/app/runs_exec.py` `run_device_fetch` | the job `collect.fetch` | 1 unit |
| `src/hst/collectors/base.py` `execute` | a caller that gives no payload | 1 unit, with `fetch_traced` |

A run from `launch` gives a fetched payload to each call of `execute`.

A `_FetchBuffer` fetches the units in windows. `_FetchBuffer.__getitem__` calls `_fetch_phase` if it does not hold the result of the requested unit. `_fetch_phase` runs `_fetch_phase_async` with `asyncio.run` on the builder thread. `_wants_loop` selects the lane of each unit.

| Lane | Units | Fetch | Digests |
|---|---|---|---|
| asyncio tasks | the transport of the configuration is `asyncssh` | `Collector.afetch` | on the thread pool `fetch-post` |
| thread pool `fetch` | each other unit | `src/hst/collectors/base.py` `fetch_traced` | on the thread of the fetch |

`fetch_traced` calls `fetch` inside `src/hst/collectors/http.py` `fetching`, which sets the answer limit of the HTTP clients. If `HST_HTTP_TRACE` holds the name of the source or `*`, `fetch_traced` also records an `HttpTrace`. The asyncio lane records no HTTP trace.

After each fetch, the lane computes 2 digests and calls the function `decide` of `_fetch_phase_async`. If the payload has the size of `COLLECT_SPILL_MB` in MiB or more, `_spill_large` writes it to a spill file with `src/hst/collectors/base.py` `spill`. [Storage](storage.md#raw-store) describes the spill file.

| Setting | Default | Bound |
|---|---|---|
| `COLLECT_FETCH_BUFFER` | 64 | the units in 1 window, and the fetch results that 1 window holds |
| `COLLECT_MAX_CONCURRENCY` | 8 | the fetches of the asyncio lane at the same time |
| `COLLECT_THREAD_WORKERS` | 8 | the threads of the pool `fetch`, and the threads of the pool `fetch-post` |
| `COLLECT_SPILL_MB` | 8 | the payload size in MiB from which the fetch writes a spill file |
| `COLLECT_MAX_ANSWER_MB` | 1024 | the size in MiB of the answer to 1 SSH command and of 1 HTTP response body |

`_fetch_phase_async` uses 1 for a value below 1 of the first 3 settings. If `COLLECT_SPILL_MB` is above 0, the asyncio lane has `COLLECT_MAX_CONCURRENCY` plus 1 permits. A unit holds 1 permit from the start of its fetch to the end of its digests and its spill.

`run_device_fetch` fetches 1 unit. If `_wants_loop` is true, `_afetch_apart` runs `afetch` on the event loop of `_fetch_loop`. If it is false, `fetch_traced` runs on a thread.

### Stop flag

`src/hst/app/runs_exec.py` `RunStop` is a `threading.Event` with 1 more flag for each source. `_arm_stop` sets a flag as `Collector.stop` on each collector. This code sets a flag:

- `cancel_run` sets the flag of the run or the flag of 1 source. `POST /api/runs/{run_id}/cancel` calls it through `request_cancel`.
- `RunStop.lose` sets the flag of the run when the connection of the cycle lock gives no answer.
- `_drained` and `wait_for_run` set the flag of the run when their task gets a cancellation.

This code reads a flag:

| Code | Point of the read | Result if the flag is set |
|---|---|---|
| `src/hst/app/runs_exec.py` `_stopped` | before each fetch window, before the load of each unit, after the loads, before the pointer moves | `RuntimeError` with the text of `RUN_STOPPED` or `LOCK_LOST` |
| `Collector.check_stop` in a fetch | where the collector calls it, such as before each command in `SshCliCollector._afetch_over` | `CollectionStopped` |
| `src/hst/collectors/base.py` `_check_stop` | before the normalization, before the graph write, before the side tables | `CollectionStopped` |
| `src/hst/core/sidestore.py` `write_table` | before each row group | `CollectionStopped` |

If the flag of 1 source is set in a cycle, `_collect_sources` gives the source the status `cancelled`. Each unit of the source without a load gets the carry reason `cancelled`, and the run continues.

If a different process runs the builder, `request_cancel` writes a request file with `src/hst/core/run_cancel.py` `request`. `_watch_cancel_requests` reads the request files of its run each 2 seconds with `src/hst/core/run_cancel.py` `take`.

After the pointer holds the run key, `RunStop.built` is true and `cancel_run` returns `False`.

## Change detection

3 functions of `src/hst/collectors/base.py` compute the digests. Each digest is a SHA-256.

| Digest | Function | Content | Column in `device_status` |
|---|---|---|---|
| raw digest | `raw_sha` | the payload and the normalization context | `last_raw_sha` |
| observation digest | `obs_sha` | the observation keys of the payload | `last_obs_sha` |
| graph digest | `graph_sha` | the batch that `normalize` returns | `last_graph_sha` |

`raw_sha` omits 3 sets of top-level keys of the payload:

- the keys in `VOLATILE_RAW_KEYS` of the collector
- the keys that `VOLATILE_RAW_KEY_PATTERN` of the collector matches
- the key `_strata_outcomes`

The normalization context holds the site code, the routing scope and the L2 fabric of the collector, and the constant `resolver_version`. It holds 5 more entries if the collector has them:

- `NORMALIZATION_VERSIONS` with `PARSER_VERSION`
- `capture_mtu` of the configuration
- the configuration fields in `NORMALIZATION_CONFIG_KEYS`
- the result of `Collector.normalization_inputs`, which in the base class is the generation of the device identity registry
- the command outcomes in `NORMALIZATION_OUTCOME_KEYS`

`obs_sha` reads only the keys in `OBSERVATION_RAW_KEYS` and the keys that `OBSERVATION_RAW_KEY_PATTERN` matches. It returns an empty string if the collector has neither or if the payload is not a dict.

`graph_sha` reads the source and the scope of the batch, each node and each relationship. It omits the properties in `VOLATILE_GRAPH_PROPS` of the collector. It does not read the sections and the warnings of the batch.

`src/hst/app/inventory/collection.py` `fingerprint_for` returns the value that the run compares with `last_raw_sha` and `last_graph_sha`. Under resolver version 1 the value is the digest. Under resolver version 2 the value is the result of `skip_fingerprint` for the digest, the normalization revision and the placement generation.

The function `decide` finds a payload unchanged if these 4 conditions are true:

- The run has a parent run and is a cycle.
- `last_raw_sha` is equal to the value of `fingerprint_for` for the raw digest.
- `last_full_at` has a value, and its age is below `COLLECT_FULL_INTERVAL_S` seconds. The default of the setting is 900.
- `src/hst/core/rawstore.py` `parked` returns no payload of the device.

`decide` returns 1 of 4 results.

| Result | Condition | Skipped | Written | Carry reason |
|---|---|---|---|---|
| skipped | unchanged, and the observation digest is equal to `last_obs_sha` or 1 of the 2 is empty | raw file, normalization, graph write, side tables | nothing | `unchanged` |
| observations only | unchanged, and the 2 observation digests have a value and differ | normalization, graph write | raw file, side tables | `unchanged` |
| load with a graph gate | changed, and `_recorded_graph` returns a value | the graph write of the objects that only this unit writes, if the graph digest matches | raw file, side tables, and the graph as [Load of one payload](#load-of-one-payload) describes | `unchanged` if the graph digest matches |
| full load | each other payload | nothing | raw file, graph, side tables | none |

`_recorded_graph` returns `last_graph_sha` if `last_graph_at` has a value and its age is below `COLLECT_FULL_INTERVAL_S` seconds. `_graph_kw` makes the `GraphGate` only if the run has a parent run.

A skipped unit gets the table outcome `unchanged` for each table in `SIDE_TABLES` of its collector.

A source run compares no digest and loads each fetched payload in full.

`run_device_fetch` compares the raw digest and the observation digest with `last_raw_sha` and `last_obs_sha`. A payload is unchanged if conditions 2 and 3 of the list are true and the device has no parked payload of the kind `full`. The function returns 1 of 4 results.

| Result | Condition | Write |
|---|---|---|
| no parked payload | the payload is unchanged, and the condition of the next row is false | `last_attempt_at` and the check time in `device_status` |
| parked payload of the kind `observation` | the payload is unchanged and has an observation digest, and that digest differs from a value in `last_obs_sha` or the device has a parked `observation` payload | `src/hst/collectors/base.py` `park` |
| no second parked payload | the parked payload with the highest fetch time is above `last_full_at` and `last_graph_fetch_at`, and `_parked_same` finds the same 2 digests in its kind file | `last_attempt_at` in `device_status` |
| parked payload of the kind `full` | each other payload | `park`, and an empty `last_raw_sha` |

In a device run, `build_device_run` gives `load_payload` a `GraphGate` for a `full` payload if `_recorded_graph` returns a value.

After a cycle and a source run, `_record_outcomes` writes the 3 digests with `PgStore.upsert_device_status`. After a device run, `_record_graphs` writes them with `PgStore.record_device_graph` and `PgStore.record_device_basis`. If a write fails, `_forget_device` clears `last_graph_sha` and `last_raw_sha` of the device.

## Normalization

`src/hst/collectors/base.py` `Collector.normalize` converts the payload of 1 fetch to 1 `src/hst/core/model.py` `Batch`. The batch holds the nodes and the relationships for the graph. The normalization writes nothing. `src/hst/core/loader.py` `load` writes the batch in [Load of one payload](#load-of-one-payload).

### From the payload to the batch

A collector builds the batch with 1 `src/hst/collectors/util.py` `GraphBuilder`.

1. `GraphBuilder.node` adds 1 `NodeRecord` with a label, a uid and the properties. It drops each property with the value `None`.
2. `GraphBuilder.rel` adds 1 `RelRecord` with a type, the label and the uid of the 2 ends, the `key` and the properties.
3. A function of `src/hst/core/uid.py` builds each uid from the identifiers of the object. The uid of a `Device` comes from the device identity registry.
4. `GraphBuilder.batch` returns the `Batch` with the source type and the batch scope. It calls `Batch.validate_registry`, which raises `ValueError` for a label or a relationship type outside the registry.

[New collector](new-collector.md#builder) lists the methods of the builder. [Conventions](conventions.md#uids) has the uid of each kind of object.

### NX-OS example

The collector of the source type `nxos` normalizes a payload in 3 steps.

1. The payload is a map from the command text to the answer text of the device.
2. `src/hst/collectors/nxos.py` `parse` converts the payload to 1 intermediate structure. The collectors of `iosxe` and `iosxr` make the same structure.
3. `src/hst/collectors/cisco_common.py` `normalize_cisco` converts the intermediate structure to the batch.

`src/hst/collectors/cli_collector.py` `CiscoCliCollector.normalize` does step 2 and step 3 and puts the section outcomes in the batch. `src/hst/collectors/nxos.py` `NxosCollector.normalize` calls it. If the intermediate structure has the key `bgp`, it then adds the nodes and the relationships of `src/hst/collectors/nxos.py` `bgp_stage` to the batch.

In step 2, `parse` reads these commands of the payload. The docstring of `normalize_cisco` lists each key of the intermediate structure.

| Command of the payload | Key of the intermediate structure | Fields |
|---|---|---|
| `show version \| json` | `device` | `hostname` from `host_name`, `serial` from `proc_board_id`, `platform` with the value `nxos`, `os_version` from `nxos_ver_str` or `sys_ver_str` |
| `show interface \| json` | `interfaces` | 1 entry for each row from `_parse_interface`: `name` from `interface`, `kind`, `mac` from `eth_hw_addr` or `svi_mac`, `admin_up`, `ips`, `vlan`, `speed_mbps` from `eth_speed`, `duplex` from `eth_duplex`, `bandwidth_kbit` from `eth_bw`, `description` |
| `show vrf interface \| json` | `interfaces` | the `vrf` of each address in `ips` |
| `show vlan \| json` | `vlans` | `vid` from `vlanshowbr-vlanid`, `name` from `vlanshowbr-vlanname` |
| `show vrf \| json` | `vrfs` | `name` from `vrf_name`, `rd` |
| `show lldp neighbors detail \| json`, `show cdp neighbors \| json` | `neighbors` | `local_port`, `name`, `mac`, `port`, `proto`, and `serial` for a CDP row |

In step 3, `normalize_cisco` makes 1 `GraphBuilder` and calls these functions in this order.

1. `_device_stage`
2. `_register_vrfs`
3. `_interface_stage`
4. `fhrp_stage`
5. `vpc_stage`
6. `_mtu_stage`
7. a loop over `vlans`
8. `_neighbor_stage`
9. `carriage_stage`
10. `routing_stage`
11. `nat_stage`
12. `acl_stage`
13. `bgp_stage`
14. `ospf_stage`

Then it returns `b.batch(source, scope)`. The first functions write these records.

| Entry of the intermediate structure | Function | Records in the batch |
|---|---|---|
| `device` | `_device_stage` | 1 `Device` node. `device_uid` gets the uid from the device identity registry. The properties are `hostname`, `platform`, `vendor` with the value `cisco`, `role` with the value `router`, `os_version`, `serial` and `identities`. |
| 1 entry of `interfaces` | `_interface_stage` | 1 `Interface` node with the uid of `uid.interface(dev, name)` and the properties `name`, `kind`, `mac`, `admin_up` and `description`. 1 relationship `(Interface)-[:ON]->(Device)`. |
| the same entry, if `kind` is in `_PORT_KINDS` | `_interface_stage` | 1 `Port` node with the uid of `uid.port(dev, name)` and the properties `name`, `mac`, `kind`, `speed_mbps`, `duplex`, `speed_source`, `bandwidth_kbit` and `description`. The relationships `(Port)-[:ON]->(Device)` and `(Interface)-[:REALIZED_BY]->(Port)`. |
| the same entry, if `vlan` has a value | `_interface_stage` | 1 `VlanInstance` node with the uid of `uid.vlan(scope, vid)`, and 1 `BridgeDomain` node with the uid of `uid.bridge_domain(l2fabric, vid)`. The relationships `(VlanInstance)-[:REALIZES]->(BridgeDomain)` and `(Interface)-[:BOUND_TO]->(VlanInstance)`. |
| each address of `ips` | `_interface_stage` | `src/hst/collectors/util.py` `connected_address` writes the `IpAddress` node and the `Prefix` node of its network. The relationships `(Interface)-[:HAS_IP]->(IpAddress)` and `(Interface)-[:IN_VRF]->(VrfInstance)`. |
| 1 entry of `vlans` | the loop of `normalize_cisco` | 1 `VlanInstance` node with the properties `vid` and `name` |

`_PORT_KINDS` holds `phys`, `lag` and `mgmt`.

The payload of `tests/test_nxos.py` has the host name `sw1` and the interface `Ethernet1/1`. For that row, the batch holds the `Device` `dev:sw1`, the `Interface` `dev:sw1/if/eth1-1` and the `Port` `dev:sw1/port/eth1-1`. For the interface `Vlan10` of the same payload, the batch holds the `Interface` `dev:sw1/if/vlan10` and, with the default L2 fabric, the `BridgeDomain` `bd:vlan:fab0:10`.

### From the batch to the graph

`load` writes each record of the batch under the run key of the run.

| Record | Query of `src/hst/core/loader.py` | Write |
|---|---|---|
| `NodeRecord` | `node_upsert_query` | a `MERGE` of 1 node with the labels of `src/hst/core/labels.py` `labels_clause`, on the pair of `uid` and `collection_ts`. `SET n += row.props` puts the properties of the record on the node. |
| `RelRecord` | `rel_upsert_query` | a `MATCH` of the 2 end nodes with the label `Obj` by `uid` and `collection_ts`, then a `MERGE` of the relationship with the fields of `key`. `SET r += row.props` puts the properties of the record on the relationship. |

If an end node of a relationship is not in the run, the `MATCH` returns no row and the graph gets no relationship. `load` counts it in `rels_dropped_missing_endpoint` of the run manifest and adds an error text.

[Conventions](conventions.md#loader-contract) has the validation, the merge keys and the loader-owned properties. [Graph schema](schema.md#properties-and-relationships) has the properties and the relationships that each source type writes.

## Graph or side store

The collector decides what goes to the graph and what goes to the side store. No other code moves data between the 2 stores during a load.

| Method of `src/hst/collectors/base.py` `Collector` | Returns | Store | Code that writes |
|---|---|---|---|
| `normalize` | the batch with the nodes and the relationships | the graph | `src/hst/core/loader.py` `load` |
| `side_tables` | the rows of each side-store table | the side store | `src/hst/collectors/base.py` `_write_side_tables` |

The default `side_tables` returns no table. A collector with a side-store table declares the table in `SIDE_TABLES`. `_write_side_tables` gives each declared table a table outcome, also when the table has no rows. The table of [Collectors](collectors.md#sources) gives the side-store tables of each source type. [Storage](storage.md#side-store) gives the columns of each table.

`GRAPH_MIRRORED_TABLES` holds each side-store table that the collector also writes to the graph. Only `vyos` sets it, and its value is `rib`. `src/hst/collectors/vyos.py` `_learned_routes` writes the routes of a routing table as `LEARNED_ROUTE` relationships if the table has a maximum of `RIB_GRAPH_MAX_ROUTES` rows. The default is 1,000. A larger routing table is in the side-store table `rib` only. `src/hst/core/manifest.py` `file_entry` sets `graph_mirrored` on the manifest entry of a `rib` file of `vyos` with a maximum of `RIB_GRAPH_MAX_ROUTES` rows.

2 settings of a source change what a collector writes to each store.

| Setting | Source type | Effect |
|---|---|---|
| `capture_bgp` | each source type | The value `all` reads the session state and the paths of each session for the tables `bgp_sessions` and `bgp_session_routes`. The value `sessions` reads the session state only. The value `none` reads none of them. A table that the fetch did not read gets the outcome `not-captured`. |
| `include_clients` | `unifi` | With the value true, which is the default, `normalize` writes the clients to the graph and `side_tables` returns no table. With the value false, `normalize` writes no client and `side_tables` returns the clients as rows of the table `mac`. |

## Load of one payload

`src/hst/collectors/base.py` `load_payload` opens the debug capture and calls `_load_payload`. When `_load_payload` returns or raises, `load_payload` calls `Collector.release_payload`. `_load_payload` does these steps:

1. `_check_stop` reads the stop flag.
2. `Collector.normalize` converts the payload to a `Batch`.
3. The function sets `last_device_uids`, `last_device_facts` and `last_device_locations` on the collector from the `Device` nodes of the batch.
4. The function replaces `source` of the batch with the name of the source row.
5. `graph_sha` computes the graph digest, and `GraphGate.matches` compares it with `last_graph_sha`.
6. `_check_stop` reads the stop flag.
7. `src/hst/core/loader.py` `load` writes the batch to the graph. If the graph digest matches, the function writes only a part of the batch.
8. The function puts the graph digest and the warnings of the batch on the `RunManifest`.
9. `_check_stop` reads the stop flag.
10. `_write_side_tables` writes the side tables and returns 1 `TableOutcome` for each table.

If the graph digest matches in step 7, the function first calls `Batch.validate_registry` for the full batch. `_shared_uids` then runs the query `SHARED_OBJECTS`, and `_shared_part` keeps 3 sets of objects:

- each node that `SHARED_OBJECTS` returns
- each node with the property `anchor`
- each relationship between 2 kept nodes

`SHARED_OBJECTS` returns a node uid in 5 cases:

- The parent run does not hold the node.
- The node of the parent run has a different `_scope` than the batch.
- The node of the parent run has a source in `_sources` that is not the source of the batch.
- A load of this run wrote the node before.
- The node of the parent run has a relationship with a different collector scope.

If the part has no node and no relationship, `load` does not run. After a match, the manifest has `graph_unchanged` set to true.

[Steps of a load](conventions.md#steps-of-a-load) gives the steps of `src/hst/core/loader.py` `load`. [Loader-owned properties](conventions.md#loader-owned-properties) gives the properties that the loader sets. `load` writes the nodes in chunks of 5,000 rows, and each chunk is 1 transaction of `execute_write`. The statements `ASSERT_UPDATE` and `WRITE_RUN` write the source assertions and the `CollectionRun` node.

A chunk of relationships can hold a relationship with a node outside the run. For each such chunk, `load` adds 1 entry with a maximum of 5 node pairs to `errors`. The `CollectionRun` node holds the first 20 entries. The load does not fail.

`src/hst/collectors/base.py` `load_observations` writes no graph object. It calls `sections` of the collector if the collector has that method. Then it calls `_check_stop` and `_write_side_tables`.

### Side tables

`_write_side_tables` calls `Collector.side_tables` and `Collector.table_outcomes`. Then it writes each table that has rows with `src/hst/core/sidestore.py` `write_table`. The graph write of the load is complete before this function starts, and no code reverses it. [Collectors](collectors.md#section-outcomes-and-table-outcomes) lists the values of a table outcome.

| Fault | Result |
|---|---|
| `side_tables` or `table_outcomes` raises | The load fails. |
| `write_table` raises `CollectionStopped` | The function deletes the table files of this call. The load fails. |
| `write_table` raises `src/hst/collectors/streams.py` `RowMappingError` | The function deletes the table files of this call. The load fails with the exception in `original`. |
| `write_table` raises a different exception | The table gets the outcome `failed`. The function continues with the next table. |
| the import of `src/hst/core/sidestore.py` fails | Each table gets the outcome `failed`. The load returns. |
| a table has no rows and a section that feeds it has a fault | The table gets the outcome `failed`. |
| a table has rows and a section that feeds it has a fault | The table gets the outcome `partial`. |

`unread_table_feeds` finds the sections with a fault from `Collector.table_feeds`. A section has a fault if its status is `failed`, `unauthorized` or `malformed`. `_write_side_tables` reports the table files to `RunEvidence` only after it writes the last table.

### Result of a load

`_collect_sources` catches each exception of `execute` except `CycleIdentityCollision`.

| Result of the load | Unit | Carry reason of the unit |
|---|---|---|
| `CycleIdentityCollision` | The run fails. | none |
| `CollectionStopped` and the flag of the source is set | not counted as a fault | `cancelled` |
| a different exception | `failed` | `failed` |
| the load returns and a section in `AUTHORITATIVE_SECTIONS` has a fault | `failed` | `failed` |
| the load returns and a different section has a fault, or a table has the outcome `failed` or `partial` | `partial` | none, and `section-failed` for the labels in `SECTION_LABELS` of the section. If the graph digest matches, `unchanged` and no `section-failed` |
| the load returns without a fault | `ok` | none, or `unchanged` if the graph digest matches |

`_completeness` computes the 3 values `ok`, `partial` and `failed` with `src/hst/core/model.py` `section_verdict` and `src/hst/core/model.py` `table_verdict`. `_GraphWrites` records if a write transaction of a failed load changed the graph.

`_collect_sources` gives each source 1 of 5 statuses.

| Status | Condition |
|---|---|
| `carried` | The source is disabled or is not in `fresh`. |
| `cancelled` | An operator cancelled the source. |
| `failed` | The source has a fault from `_prepare_all`, has no unit, or each unit failed. |
| `partial` | 1 or more units failed and 1 or more did not, or no unit failed and 1 or more units are `partial`. |
| `fresh` | Each unit is `ok`. |

`_cycle_status` gives the row in `runs` the status `error` if a source is `failed` and no source is `fresh` or `partial`.

## Carry

`src/hst/app/runs_exec.py` `CarryScopes` holds the carry decision of each collector scope. `_collect_sources` fills it, and `_carry_phase` gives it to `src/hst/core/cycle.py` `carry_forward`.

| Field of `CarryScopes` | Content | Argument of `carry_forward` |
|---|---|---|
| `reasons` | the scope of each unit to copy, with the reason | `scopes` |
| `collected` | the scope of each `ok` or `partial` unit with a load of the full batch | `collected` |
| `sections` | the scope of each `partial` unit, with the labels of its failed sections | `section_labels` |

`src/hst/core/cycle.py` `CARRY_REASONS` holds the 5 values of `carried_reason`.

| `carried_reason` | Objects |
|---|---|
| `not-run` | the scope of a unit of a source with the status `carried`, of a disabled device row, and of each unit at the start of a device run |
| `failed` | the scope of a unit with a fetch fault, with a failed load, or without a collector |
| `unchanged` | the scope of a unit with the result skipped or observations only, or with a matching graph digest |
| `cancelled` | the scope of a unit that an operator cancelled with its source |
| `section-failed` | the labels in `SECTION_LABELS` for each failed section of a `partial` unit |

An object without an entry in `reasons` that `carry_forward` copies gets the reason `not-run`.

`_carry_phase` also gives `carry_forward` 2 lists of sources. The list `sources` holds each source with the status `carried`, `failed`, `partial` or `cancelled`. It also holds each source in the set `needs_carry`. `_collect_sources` puts each source with an `unchanged` unit in that set, and `src/hst/app/runs_exec.py` `build_device_run` puts each source with a loaded payload in it. If the run has a parent run, `_carry_phase` adds each source with a disabled device row or a unit without a collector. Each source is in the list with the name and the type of its row. The list `unasked` holds the sources of that list for which `_unasked` is true.

[Conventions](conventions.md#carry) gives the nodes and the relationships that `carry_forward` copies, and the properties of a copy. The queries `_READ_CARRY_NODES`, `_READ_CARRY_SECTION_NODES` and `_READ_CARRY_RELS` select them. A copied relationship gets the `carried_reason` of its copied node. Without a copied node it gets the reason of its scope.

`carry_forward` does 2 steps before it copies:

- `_check_carry_anchors` reads the parent nodes of each scope with the reason `unchanged`. It raises `CycleIdentityCollision` if a node of this run has a different `anchor` than its parent node.
- `_carry_contributions` reads the nodes that this run wrote and that a source without a load also wrote in the parent run. It writes the assertions of that source onto those nodes.

If the run has no parent run, `_carry_phase` copies nothing. It changes each source status `carried` and `cancelled` to `failed`.

## Reasoner run

`src/hst/core/finalize.py` `finalize_derivations` does these steps in order. Each step writes only graph objects with the run key of the run.

1. `src/hst/reasoner/device_roles.py` `apply_device_roles` sets `role`, `role_reported`, `role_basis` and `tier` on each `Device` node with the setting `HOSTNAME_TIER_TOKENS`.
2. `src/hst/reasoner/runner.py` `run` clears the reasoner writes and runs each reasoner rule.
3. `src/hst/reasoner/arp_cables.py` `derive_arp_cables` runs the rule `cable-from-arp-port` with the `arp` and `mac` tables of the side store.
4. `src/hst/core/ipam.py` `annotate` applies the IPAM import. If it raises, the function logs a warning and the run continues.
5. `src/hst/core/reasoner.py` `execute_rt_domains` derives the routing domains.
6. `src/hst/core/reasoner.py` `execute_link_speed` derives the link speeds.
7. `src/hst/core/cycle.py` `apply_site_assignments` writes a `LOCATED_IN` relationship from each `Device` node to the `Site` node of its site assignment.
8. `src/hst/core/cycle.py` `carry_site_assignments` gives each copied `Device` node without a site assignment the site of its parent node.
9. `src/hst/core/cycle.py` `apply_site_blocks` sets `site_block` and `site_zone` on the `Device` nodes, if the caller gives a map of site blocks.
10. `src/hst/reasoner/vlan_stretch.py` `check_vlan_stretch` reads the graph and the `mac` table and returns observations and warnings.
11. `src/hst/reasoner/edge_devices.py` `check_edge_devices` reads the graph and returns warnings.
12. `src/hst/reasoner/zscaler.py` `check_zscaler` reads the graph and returns warnings.

An exception that a step other than step 4 raises fails the run. Steps 10 to 12 write nothing to the graph. `_finalize_cycle` puts their results into the detail of the run and into the manifest.

4 callers use `finalize_derivations`:

- `src/hst/app/runs_exec.py` `_finalize_cycle` for a cycle, a source run and a device run
- `src/hst/app/fixture_runs.py` `publish` for a fixture run
- `src/hst/core/replay.py` `rebuild`
- `src/hst/core/replay.py` `rebuild_from_manifest`, if the manifest has no graph archive

### Rule runner

`src/hst/reasoner/runner.py` `run` does these steps. Each call of `execute_write` is 1 transaction, and no transaction spans 2 steps.

1. The statement `CLEAR` deletes the relationships of the run with the `_scope` `reasoner`. Each transaction deletes a maximum of 5,000 relationships.
2. The statement `CLEAR_PROPS` removes `infra` from the `Endpoint` nodes. It removes `binding_issue` and `binding_ports` from the `FabricPort` nodes.
3. The function runs each entry of `src/hst/reasoner/catalog.py` `RULES` in the order of the list. [Conventions](conventions.md#derived-elements) lists the reasoner rules.
4. The function reads the queries `CONTAINMENT_ADDRESSES`, `CONTAINMENT_PREFIXES` and `CONTAINMENT_BD_MAP` in 1 read transaction. `containment_pairs` computes the pairs, and `CONTAINMENT_WRITE` writes them in chunks of 5,000. The result has the rule name `address-containment`.

A reasoner rule reads the relationships that the rules before it wrote. If a rule raises, the writes of the rules before it stay in the run. The run then fails, and [Publication](#publication) describes the delete.

An entry of `RULES` with a Cypher query runs as 1 statement in 1 transaction. 6 entries have no query, and Python code runs them.

| Rule | Function | Transactions |
|---|---|---|
| `cable-from-uplink-record`, `cable-from-lldp-record`, `cable-from-neighbor-name` | `src/hst/reasoner/stated_cables.py` `_run_stated_cable_rules` | 1 read transaction for the 3 rules, then 1 write transaction for each 5,000 relationships |
| `fabric-port-from-description` | `src/hst/reasoner/fabric_ports.py` `_run_fabric_port_rule` | 1 |
| `edge-device-from-binding` | `src/hst/reasoner/edge_devices.py` `_run_edge_device_rule` | 1 |
| `zpa-zia-ip-same-as` | `src/hst/reasoner/zscaler.py` `_run_zpa_zia_same_as_rule` | 1 |

`_run_stated_cable_rules` runs 1 time, when `run` gets to the first of its 3 rules.

The rules `address-containment` of step 4 and `cable-from-arp-port` of `derive_arp_cables` are not in `RULES`.

### Derivations of the core reasoner

`src/hst/core/reasoner.py` holds 2 derivations that write and 2 audits that only read.

| Derivation | Function | Batch scope | CLI command |
|---|---|---|---|
| routing domains | `execute_rt_domains` | `derived:rt-domains` | `hst reason rt-domains` |
| link speeds | `execute_link_speed` | `derived:link-speed` | `hst reason link-speed` |

Each of the 2 functions builds a `Batch` with the source `reasoner` and writes it with `src/hst/core/loader.py` `load`. `carry_forward` does not copy a relationship with a scope that starts with `derived:`.

`execute_rt_domains` calls these functions:

1. `read_topology` reads the `IMPORTS` and `EXPORTS` relationships from `VrfInstance` nodes to `RouteTarget` nodes with the query `RT_EDGES_AT_CYCLE_QUERY`.
2. `pair_and_group` pairs an importer with each different exporter of the same route target. It groups the paired `VrfInstance` nodes into components.
3. `build_rt_domains` makes 1 `RoutingDomain` node for each component with 2 or more members. It makes 1 `MEMBER_OF` relationship with `basis` `rt-component` for each member.

The uid of the `RoutingDomain` node comes from `src/hst/core/uid.py` `routing_domain` with `rt:` and the first route target of the component in sort order.

`execute_link_speed` calls these functions:

1. `read_connected_to_speed` reads each `CONNECTED_TO` relationship between 2 `Port` nodes in its stored direction with the query `CONNECTED_TO_SPEED_AT_CYCLE_QUERY`.
2. `link_speed_agreement` computes `speed_mbps` and `speed_agreement` from the speeds of the 2 ports.
3. `build_connected_to_speed` makes 1 relationship record with an empty key for each row.

The write sets the 2 properties on each `CONNECTED_TO` relationship between the 2 ports in that direction. Step 2 of `finalize_derivations` is complete before this derivation, so the read includes the relationships of the reasoner rules.

| `speed_agreement` | Speeds of the 2 ports | `speed_mbps` |
|---|---|---|
| `agree` | 2 equal values | the value |
| `disagree` | 2 different values | the lower value |
| `one-side` | 1 value | the value |
| `unknown` | no value | null |

Each of the 2 CLI commands calls its function without a run key. The function then reads and writes the run of the pointer.

No code in `src/hst` writes the routes of a route-target pair to the graph. `RT_IMPORTED_ROUTES` is a Cypher fragment that the read code joins. [Serving](serving.md#stages) describes the read code.

| Audit | Functions | CLI command |
|---|---|---|
| components with more than 1 declared routing domain | `read_topology`, `read_realizes`, `find_domain_splits` | `hst audit domains` |
| VLAN components with more than 1 declared segment, and declared segments in more than 1 component | `read_carriage`, `read_port_links`, `read_segment_realizes`, `bridge_components`, `find_segment_merges`, `find_segment_splits` | `hst audit segments` |

## Publication

`src/hst/app/runs_exec.py` `_finalize_cycle` does these steps after `finalize_derivations` returns. [Storage](storage.md) describes the format and the path of each file.

1. `src/hst/core/cycle.py` `cycle_counts` counts the nodes and the relationships with the run key.
2. `_hst_projection` calls `src/hst/map/project.py` `reconcile` for the marker of the parent run and makes a `Projection`. Without the `sidestore` extra, it returns `None`.
3. `_write_manifest` calls `src/hst/core/manifest.py` `graph_delta` with the parent run and this run. If the call raises, the manifest holds a note in place of the digest and the run continues.
4. `Projection.prepare` writes the map tables of the run as staged files.
5. `src/hst/core/grapharchive.py` `write` writes the graph archive of the run with the normalization context.
6. `src/hst/core/manifest.py` `build` makes the manifest. `src/hst/core/manifest.py` `write` writes and signs it and returns its digest. If the write raises, the run fails.
7. `src/hst/core/cycle.py` `write_cycle_meta` sets the state `built` on the `CycleRun` node. It sets the kind, the parent, the source statuses, the counts and the manifest digest.
8. `_stopped` reads the stop flag.
9. `src/hst/core/cycle.py` `set_pointer` sets `current` of the `CyclePointer` node to the run key.
10. The builder sets `RunStop.built`.
11. `Projection.publish` moves the staged files into place and writes the marker of the run.

A fault of `Projection.prepare` or `Projection.publish` does not fail the run.

In step 9, `set_pointer` gets the fence of the cycle lock. The statement `_SET_POINTER_FENCED` sets `current` and `fence` only if the fence of the node is not above the given fence. If the statement sets nothing, `set_pointer` raises `StaleFence`.

`_building` wraps each step of the builder from `begin_run` to step 11. When the builder leaves `_building`, `_discard_unpublished` reads the pointer. If the pointer does not hold the run key, the function does 2 deletes:

- `src/hst/core/cycle.py` `discard_run` deletes the `CycleRun` node, the objects and the `CollectionRun` nodes of the run.
- `_remove_run_files` deletes the manifest, its signature, the graph archive and the staged map tables of the run.

The function does not delete the raw files and the side-store files that the loads of the run wrote. [Storage](storage.md#retention) describes their retention. If the function cannot read the pointer, it deletes nothing. If `discard_run` raises, the function logs a warning, and `src/hst/core/cycle.py` `prune` deletes the run later.

A run stops or fails before the publication in these cases:

| Cause | Exception | Status of the row in `runs` |
|---|---|---|
| an operator cancels the run | `RuntimeError` with `RUN_STOPPED` | `cancelled` |
| the connection of the cycle lock gives no answer | `RuntimeError` with `LOCK_LOST` | `error` |
| an operator cancels the source of a source run | `RunCancelled` | `cancelled` |
| the source of a source run has the status `failed` | `RuntimeError` | `error` |
| 2 loads give 1 uid 2 values of `anchor` | `CycleIdentityCollision` | `error` |
| a step of `finalize_derivations` raises | the exception of the step | `error` |
| the graph archive write or the manifest write raises | the exception of the write | `error` |
| the pointer holds a higher fence | `StaleFence` | `error` |

A cancellation can get to `_drained` after step 8. If the builder then publishes the run, `_drained` returns the published run and adds the text of `LATE_CANCEL` to the detail.

## Worker

### Queue

`src/hst/worker/queue.py` holds the rules of the job queue. [Storage](storage.md#postgres) lists the table `jobs`.

| Function | Rule |
|---|---|
| `enqueue` | returns `None` if a job with the same kind, source and device is queued or running |
| `claim` | gives a job to 1 executor with a lease of 5 minutes, the value of `LEASE` |
| `heartbeat` | extends the lease of the jobs that the executor runs |
| `finish` | records the result of 1 try |
| `reap` | queues each job with a lease that ended, or gives it the state `dead` if `attempt` is not below `max_attempts` |

`finish` compares `attempt` of the job with `max_attempts`. The default of `max_attempts` is 4, the value of `DEFAULT_MAX_ATTEMPTS`.

- A job body that returns gives the job the state `ok`.
- A job body that raises while `attempt` is below `max_attempts` gives the job the state `queued`. The job is due after the result of `backoff`, which is 60 seconds for try 1. The result doubles for each try to a maximum of 1,800 seconds.
- A job body that raises on the last try gives the job the state `dead`. A job with `max_attempts` of 1 gets the state `error`.

`reap` applies the same delay to the 4 kinds in `LEASE_BACKOFF_KINDS`, which are the kinds of the next table.

### Job kinds

`src/hst/worker/runtime.py` `bodies` maps each job kind to its body. 4 kinds start a fetch or a run. The other kinds are the other maintenance kinds of `src/hst/worker/maintenance.py` `BODIES` and the debug re-parse.

| Kind | Code that queues the job | Priority | `max_attempts` |
|---|---|---|---|
| `collect.cycle` | `src/hst/worker/scheduler.py` `Scheduler.tick`, each `COLLECT_INTERVAL_S` seconds if the value is above 0 | 0 | 4 |
| `collect.run` | `src/hst/worker/collect.py` `enqueue_run` for `POST /api/runs` | 1 | 1 |
| `collect.fetch` | `src/hst/worker/scheduler.py` `Scheduler.fanout_collect` | 0 | 4 |
| `collect.fetch` | `src/hst/app/inventory/inventory_routes.py` `collect_device` for `POST /api/inventory/devices/{device_id}/collect` | 0 | 4 |
| `collect.fetch` | `src/hst/app/routes/assessments.py` `collect` for `POST /api/assessments/{identifier}/collection-actions` | 1 | 1 |
| `maintenance.build_device_run` | `Scheduler.tick`, each `DEVICE_RUN_INTERVAL_S` seconds | 0 | 4 |

The default of `COLLECT_INTERVAL_S` is 0, and the default of `DEVICE_RUN_INTERVAL_S` is 600.

`collect_run_body` does the checks of `trigger` a second time before it calls `launch`. A run with the status `error` does not fail the job.

### Executor

`src/hst/worker/executor.py` `Executor.poll` runs each 5 seconds. It calls `reap`, then `heartbeat`, then `claim` for the free slots. The setting `COLLECT_WORKER_CONCURRENCY` sets the count of job bodies that 1 executor runs at the same time, and the default is 16. If `heartbeat` does not extend the lease of a job, `Executor._cancel_lost` cancels the task of the job.

### Scheduler

`src/hst/worker/scheduler.py` `Scheduler.run` takes the leader lock with `PgStore.try_scheduler_lock`. Only the process with the lock queues jobs. A process without the lock tries again each 30 seconds.

The leader calls `src/hst/app/inventory/collection.py` `reconcile_on_startup` and `Scheduler.arm`. Then it calls `Scheduler.tick` each 15 seconds. `arm` sets the first due time of each schedule to the start time plus the interval plus the result of `jitter`. `tick` queues each due schedule if its `guard` returns true.

`src/hst/worker/runtime.py` `build_loops` gives the scheduler the entries of `SYSTEM_SCHEDULES`. It adds a schedule for `collect.cycle` if `COLLECT_INTERVAL_S` is above 0. `Scheduler.__init__` adds the schedule for `maintenance.build_device_run`.

`Scheduler.fanout_collect` queues the `collect.fetch` jobs in each tick.

- The budget of 1 tick is `COLLECT_QUEUE_HIGH_WATER` minus the count of queued and running jobs. The default of the setting is 1,000. With a budget of 0 or below, the tick queues no `collect.fetch` job.
- `Scheduler._due_targets` returns each enabled target of each enabled source with its interval. Under resolver version 1 the interval is `interval_s` of the source configuration. Under resolver version 2 the interval is the profile interval of the target.
- A target with an interval of 0 gets no job.
- `Scheduler._device_due` returns true if the device has no `device_status` row or the row has no `last_attempt_at`. If not, the device is due at `last_attempt_at` plus the delay.
- The delay is the interval times 2 to the power of `consecutive_failures`, with a maximum exponent of 16. The maximum of the delay is the higher value of the interval and `COLLECT_BACKOFF_CAP_S`, with a default of 900.

2 commands start the 2 loops.

| Command | Code | Condition |
|---|---|---|
| `hst serve` | `src/hst/app/main.py` `_start_workers` | `SCHEDULER_ENABLED` is true, which is the default |
| `hst worker` | `src/hst/worker/runtime.py` `run` | none |

### Locks and the fence

A run holds 3 locks.

| Lock | Code | Scope |
|---|---|---|
| run claim | `src/hst/app/store/pg.py` `PgStore._try_claim` | a Postgres advisory lock for each source name, from `start_run` to `finish_run` |
| cycle lock | `src/hst/app/store/pg.py` `PgStore.cycle_lock` | 1 Postgres advisory lock with the key `CYCLE_LOCK`, for the builders of all processes |
| process lock | `src/hst/app/runs_exec.py` `_CYCLE_LOCK` | a `threading.Lock` for the builders of 1 process |

`cycle_lock` waits until the lock is free. `PgStore.try_cycle_lock` does not wait. `POST /api/graph/purge` and 4 functions of `src/hst/worker/maintenance.py` use it: `prune_graph`, `prune_sidestore`, `prune_rawstore` and `prune_manifests`.

`cycle_lock` holds the lock on its own connection and returns the next value of the sequence `cycle_fence_seq` as the fence. `PgStore._watch_lock` sends 1 statement on that connection each 5 seconds. If the statement fails, it calls `RunStop.lose`. The builder then stops at its next call of `_stopped`.

A builder that lost the lock can continue until that call. If a builder with a higher fence moved the pointer, `set_pointer` raises `StaleFence`.

`launch` holds the cycle lock while it reads the `device_status` rows before the builder and while it writes them after the builder.

## Point-in-time rebuild

`hst rebuild` calls `src/hst/cli.py` `rebuild_cmd`. The command needs exactly 1 of `--as-of` and `--snapshot`.

| Option | Rule |
|---|---|
| `--as-of` | a date or a date with a time. A date without a time is 23:59:59 UTC of that date. |
| `--snapshot` | the run key of a published run with a manifest |
| `--into` | the bolt URI of the target database. The command needs it for a write and refuses the endpoint of `NEO4J_URI`. |
| `--dry-run` | prints the plan and writes nothing |
| `--allow-config-drift` | only with `--snapshot` |
| `--sidestore-scratch` | only with `--snapshot` |

The command exits with the status 1 if the report holds a missing or a failed entry.

### Date path

`src/hst/core/replay.py` `plan` lists the raw files with `list_snapshots`. For each pair of source directory and host directory, it selects the raw file with the highest fetch time at or before the date. `src/hst/core/replay.py` `rebuild` then does these steps:

1. `_clear_target` deletes each node of the target database in batches of 10,000.
2. For each selected raw file, the function gets a collector from the callback `device_collector_for` or from `device_collector`.
3. `src/hst/core/rawstore.py` `read` reads the payload, and `Collector.normalize` converts it.
4. `src/hst/core/loader.py` `load` writes the batch with the date in milliseconds as the run key. The load keeps the run id and the fetch time of the raw file.
5. `src/hst/core/finalize.py` `finalize_derivations` runs with an empty map of site assignments.
6. `_publish` calls `write_cycle_meta` with the kind `full`, the application version and the build revision. Then it calls `set_pointer` without a fence.

The date path writes no side-store file, no manifest and no graph archive. A raw file without a configured source goes into `failed` of the `RebuildReport`.

### Manifest path

`src/hst/cli.py` `_rebuild_from_manifest` reads the manifest with `src/hst/core/manifest.py` `read`. It calls `src/hst/core/replay.py` `rebuild_from_manifest`.

If the manifest holds a graph archive, the function does these steps and uses no collector:

1. `src/hst/core/grapharchive.py` `verify` does a check of the archive.
2. `_clear_target` deletes each node of the target database.
3. `src/hst/core/grapharchive.py` `restore` writes the records of the archive with the run key of the manifest.
4. `_publish` writes the `CycleRun` node with the source statuses, the kind, the parent and the digest of the manifest. Then it moves the pointer.

If the manifest holds no graph archive, the function does these steps:

1. `_clear_target` deletes each node of the target database.
2. For each source of the manifest, `src/hst/core/manifest.py` `source_config_digest` computes the digest of the stored configuration. If it differs from `config_sha256` of the manifest, each device of the source fails. With `--allow-config-drift`, the devices load and the report holds the 2 digests in `drift`.
3. For each device, the function finds the raw file entry with the run id in `effective_run`. A device without `effective_run` goes into `missing`.
4. `device_collector` builds the collector for the host of the device, and `Collector.normalize` converts the payload.
5. `_replay_side_tables` compares each side-store file of the run id with the SHA-256 and the size in the manifest. If a file is absent or differs, the function writes the table again into the directory of `--sidestore-scratch`. Without the option, the report holds a note.
6. `load` writes the batch with the run key of the manifest.
7. `finalize_derivations` runs with the site assignments and the site blocks of the manifest.
8. `_publish` writes the `CycleRun` node with `reprocessed_from` set to the run key. Then it moves the pointer.
