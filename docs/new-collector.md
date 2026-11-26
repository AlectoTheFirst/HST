# New collector

## Files to change

`<name>` is the [source type](collectors.md#sources) of the collector. Each collector needs these changes.

| File | Content | Test that fails without the content |
|---|---|---|
| 1 module in `src/hst/collectors/` | the config model, the collector class and the normalize function | |
| `src/hst/collectors/__init__.py` | the line `from . import <name> as _<name>` | the tests of the rows `COLLECTORS` and `CLASSIFICATION`, if these 2 tables hold the source type |
| `src/hst/app/inventory/field_metadata.py` `COLLECTORS` | 1 `CollectorClassification` with 1 `FieldClassification` for each leaf field of the config model | `tests/app/test_inventory_contracts.py` `test_every_registered_collector_field_is_classified_and_nothing_else_is` and `test_field_metadata_contract_shape` |
| `tests/app/test_inventory_contracts.py` | the field total of `COLLECTORS` in the last assertion of `test_every_registered_collector_field_is_classified_and_nothing_else_is` | the same test |
| `src/hst/app/inventory/normalization.py` `CLASSIFICATION` | 1 entry with the keys `site_code`, `routing_scope`, `l2fabric` and `l3dom` | `tests/test_inventory_routing_identity.py` `test_classification_covers_the_registry_exactly` |
| `tests/app/test_registry_contract.py` `MINIMAL_PAYLOADS` | 1 entry with a config payload that the config model accepts | `tests/app/test_registry_contract.py` `test_registry_contract` |
| `docs/collectors.md` | the generated block `sources`, which `tools/gen_docs.py` writes | `tests/test_docs.py` `test_generated_blocks_match_the_code` |
| 1 test module in `tests/` | the tests of the collector | |

A collector needs these changes only if the condition applies.

| Condition | File | Change | Check that fails without the change |
|---|---|---|---|
| The collector needs the authority class `observed`. | `src/hst/core/loader.py` `COLLECTOR_CLASSES` | the scope prefix with the class `observed`. A scope prefix without an entry gets the class `configured`. [Conventions](conventions.md#source-assertions) describes the classes. | none |
| The collector writes a label other than `Device` with an id of the management plane, and no uid builder covers the id. | `src/hst/core/uid.py` | 1 builder function, such as `src/hst/core/uid.py` `equinix` | none |
| The collector reads `effective_routing_scope` of the config. | `src/hst/app/inventory/normalization.py` `READS_ROUTING_SCOPE` | the source type | none |
| The entry in `CLASSIFICATION` has the sensitivity `identity` for `routing_scope`, `l2fabric` or `l3dom`. | `tests/test_inventory_routing_identity.py` | the source type in the literal sets of `test_identity_classification_matches_what_the_collectors_embed_in_uids`. For `routing_scope`, the test also needs the source type in `READS_ROUTING_SCOPE`. For `l3dom`, it also needs the source type in `ALIAS_EFFECTIVE`. | the same test |
| A payload key is in `OBSERVATION_RAW_KEYS` and in `VOLATILE_RAW_KEYS`, or the collector sets `OBSERVATION_RAW_KEY_PATTERN`. | `tests/test_observation_sections.py` | the source type in the list of `test_every_collector_that_can_take_the_observation_path_reads_its_sections`. The test also fails if the collector has no method `sections`. | the same test |
| The collector sets `VOLATILE_RAW_KEY_PATTERN` or `OBSERVATION_RAW_KEY_PATTERN`. | `tests/test_cisco_rib_volatility.py` | a change of `test_no_other_collector_declares_a_key_pattern`, which accepts a pattern only for `iosxe`, `iosxr` and `nxos` | the same test |
| A section of the payload holds the gate configuration of a `Device`. | `src/hst/path/gates/coverage.py` `_POLICY_SECTIONS` | the source type with the name of each of these sections. Without the entry, `_observation_unknown` returns the text `collector has no declared policy-section completeness contract` for a `Device` of the source type. | none |
| `src/hst/assessment/evidence.py` `troubleshoot` must offer a read of a section of the collector for a gap of the kind `not-collected`. | `src/hst/collectors/recipes.py` `section_recipe` and `troubleshoot` | 1 `Recipe` for the source type and the section. For a gap of the dimension `policy`, `troubleshoot` takes the sections from `_POLICY_SECTIONS`. For the dimensions `interface` and `topology`, add the source type and the sections to the `if` chain of `troubleshoot`. [Extending assessment workflows](../CONTRIBUTING.md#extending-assessment-workflows) holds the rules. | none |
| The connection page must show the collection progress of the source. | `web/src/inventory/connections/ConnectionDetailPage.tsx` | the source type in the condition that renders `ConnectionProgress` | none |
| The collector calls `src/hst/collectors/util.py` `without_keys` with a constant that holds the words. | `tests/test_http_trace.py` | the name of the constant in the set of `test_the_trace_redacts_every_word_a_collector_strips_from_the_raw_store`, and the constant in the loop of the test. The test also fails if `src/hst/core/redaction.py` `redact` keeps the value of a key with one of the words. | the same test |
| A constant of the module has `COMMAND` in its name or has the name `SECTIONS`. | [Device commands](device-commands.md) | each command string of the constant | `tests/test_docs.py` `test_each_command_constant_is_in_the_device_commands_doc` |
| The collector needs a package that `pyproject.toml` does not list. | `pyproject.toml` and `uv.lock` | the package | `uv lock --check`, which `make check` runs |

## Config model

Make a subclass of `src/hst/collectors/base.py` `SourceConfig` and set it as `ConfigModel` of the collector class. `SourceConfig` has the fields `site_code`, `routing_scope`, `interval_s`, `capture_bgp`, `source_name`, `l2fabric` and `resolved_origins`. [Collectors](collectors.md#config-model) describes them. `src/hst/app/sources.py` `build_collector` sets `source_name` to the name of the source.

`src/hst/collectors/auth.py` holds the credential models. For an HTTP API, use `UserPassword`, `ApiKeyCredential` or `OAuthClientCredentials`, and `TlsConfig` for the TLS settings.

### Secret fields

Give each secret field the type `SecretStr`. `src/hst/app/sources.py` `secret_paths` finds each field with the annotation `SecretStr` in the config model, in a nested model and in each member of a union. It does not find a field of the type `SecretStr | None` or `str`. For an optional secret, use the default `SecretStr("")`, as `src/hst/collectors/auth.py` `SshPrivateKey.passphrase` does.

`src/hst/app/sources.py` `split_secrets` moves each `SecretStr` value from the config to the secrets of the source. [Storage](storage.md#postgres) describes the column of the secrets. The JSON schema of a `SecretStr` field has `writeOnly`. For each path of `secret_paths`, `tests/app/test_registry_contract.py` `test_registry_contract` makes sure that the annotation is `SecretStr` and that the schema has `writeOnly`. It also makes sure that `validate_source` returns a config without a secret for the entry in `MINIMAL_PAYLOADS`.

### Forms

`GET /api/source-types` returns the type, the kind and the JSON schema of each config model. `src/hst/app/sources.py` `source_types` makes the answer. The web UI has 2 forms that read the schema.

`web/src/settings/SchemaForm.tsx` renders the schema in this way.

| Schema of a field | Form |
|---|---|
| `title` | the label. Without a title, the label is the field name. |
| `description` | the hint of the input |
| the type `string`, `integer`, `number` or `boolean` | 1 input |
| `enum`, which a `Literal` type with 2 or more values gives | 1 select with the values |
| a nested model | the inputs of the model |
| a union of 2 or more models | 1 select with 1 option for each model, and the inputs of the selected model. The value of an option is the `method` of the model. |
| `writeOnly` | an input that does not show the stored value |
| `json_schema_extra={"format": "multiline"}` on a `str` field | a text area |
| `json_schema_extra={"format": "source", "sourceType": "<name>"}` on a `str` field | 1 option for each source of that source type |
| another schema, such as a list, a dict or a `str` field that accepts `None` | no input |

The form does not show `source_name`.

If the device inventory is active with resolver version 2, `web/src/inventory/InventoryGate.tsx` `InventoryRedirect` sends the settings routes to the inventory pages. Their form is `web/src/inventory/connections/MetadataFields.tsx`. It takes the answer of `GET /api/inventory/field-metadata` and renders a field only if `COLLECTORS` holds the path of the field in the category of the form. The inventory pages use the form with the categories `connection`, `target` and `profile`. The label is `FieldClassification.label`, and then the `title` of the schema. The form renders a list or a dict as a text area for JSON.

### Field classification

`tests/app/test_inventory_contracts.py` `test_every_registered_collector_field_is_classified_and_nothing_else_is` sets these rules for the entry in `src/hst/app/inventory/field_metadata.py` `COLLECTORS`.

- `config_model` is the module path and the class name of the config model, and `kind` is the value of `KIND`.
- `fields` holds 1 `FieldClassification` for each leaf of the JSON schema and no other entry. The fields of `SourceConfig` are leaves too.
- `path` is the dotted path of the leaf. `variant` is the model name for a leaf below an `anyOf` or a `oneOf` of the schema, such as `ClientCert` for `tls.client_cert.key`. For each other leaf, `variant` is `None`.
- `category` is a value of `CATEGORIES`, and `identity_sensitivity` is a value of `IDENTITY_SENSITIVITIES`.
- `secret` is `True` for each path of `secret_paths` and `False` for each other path. A secret field has the category `credential`.
- A field of the category `profile` or `credential` has the source type in `profile_applicability`. Each other field has `n/a`.
- A field of the category `profile` does not have the sensitivity `identity`.

`tests/app/test_inventory_contracts.py` `test_field_metadata_contract_shape` needs the source type in `collector_type` of the entry.

In `src/hst/app/inventory/normalization.py` `CLASSIFICATION`, each key holds a `Classification`. `tests/test_inventory_routing_identity.py` `test_classification_covers_the_registry_exactly` accepts the sensitivity `identity` or `label` and an evidence text that holds the string `".py"`. Use `identity` for a field whose value is part of a uid that the collector makes. Use `label` for each other field.

## Collector class

Make a subclass of `src/hst/collectors/base.py` `Collector`. The collector sets or can set these attributes.

| Attribute | Default | Use in the code |
|---|---|---|
| `name` | `""` | the source type. `register` uses it as the key in `REGISTRY`. |
| `ConfigModel` | `SourceConfig` | the config model. `src/hst/app/sources.py` `validate_source` and `build_collector` make the config with it. |
| `KIND` | no default | `group` or `orchestrator`. [Registration and kind](#registration-and-kind) describes the 2 values. |
| `scope` | `""` | the scope of the collector. Set it in `__init__`, as [Scope](#scope) describes. |
| `reports_progress` | `False` | `True` for a collector that writes its own `CollectionProgress`. `src/hst/app/runs_exec.py` `FleetProgress` makes no progress record for such a source. |
| `PARSER_VERSION` | `"1"` | the `parser_version` of each table outcome in the manifest. It is part of `raw_sha` if `NORMALIZATION_VERSIONS` is not empty. |
| `NORMALIZATION_VERSIONS` | `{}` | version strings that are part of `raw_sha` |
| `NORMALIZATION_CONFIG_KEYS` | `()` | config fields whose values are part of `raw_sha` |
| `NORMALIZATION_OUTCOME_KEYS` | `()` | keys below `_strata_outcomes` of the payload whose values are part of `raw_sha` |
| `VOLATILE_RAW_KEYS` | `()` | top-level keys of the payload that `raw_sha` leaves out |
| `VOLATILE_RAW_KEY_PATTERN` | `None` | a pattern for top-level keys that `raw_sha` leaves out |
| `OBSERVATION_RAW_KEYS` | `()` | top-level keys of the payload that `obs_sha` covers |
| `OBSERVATION_RAW_KEY_PATTERN` | `None` | a pattern for top-level keys that `obs_sha` covers |
| `VOLATILE_GRAPH_PROPS` | `{}` | for a label or a relationship type, the properties that `graph_sha` leaves out |
| `GRAPH_MIRRORED_TABLES` | `()` | side-store tables that the collector also writes to the graph. `src/hst/core/manifest.py` `file_entry` sets `graph_mirrored` on the file of such a table if the row count is within the setting `RIB_GRAPH_MAX_ROUTES`. |
| `AUTHORITATIVE_SECTIONS` | `()` | the sections that fail the device. [Section outcomes](#section-outcomes) describes the verdict. |
| `SECTION_LABELS` | `{}` | for a section, the labels that only this section writes |
| `SIDE_TABLES` | `()` | side-store tables that get a `TableOutcome` in each load |
| `TABLE_SECTIONS` | `{}` | for a side-store table, the sections that feed it |
| `SECTIONS` | not in `Collector` | the expected sections of a device. `src/hst/app/runs_exec.py` `_expected_sections` returns its keys. Without the attribute, the function returns the keys of the section outcomes. |

`src/hst/collectors/base.py` `raw_sha` is the hash of the payload and of a normalization context. `obs_sha` is the hash of the observation keys. `graph_sha` is the digest of the batch. A run does not call `normalize` for a fetch whose `raw_sha` and `obs_sha` match the record of the device. The setting `COLLECT_FULL_INTERVAL_S` limits this skip to 900 seconds after the last full load by default. [Code flow of a collection](collection-code-flow.md#change-detection) describes the 3 comparisons.

- Put a key in `VOLATILE_RAW_KEYS` only if no node, relationship or property of the batch comes from it. A property in `VOLATILE_GRAPH_PROPS` is the exception.
- If a key of `VOLATILE_RAW_KEYS` feeds a side-store table or a section outcome, put it in `OBSERVATION_RAW_KEYS` too.
- If a change of the normalize code changes the batch of the same payload, change a value in `NORMALIZATION_VERSIONS`.
- If a config field changes the batch and is not in the payload, put it in `NORMALIZATION_CONFIG_KEYS`.

The collector has these methods.

| Method | Needed | Use |
|---|---|---|
| `__init__(config, settings)` | yes | Call the base method, then set `self.scope`. |
| `fetch()` | yes | returns the payload of 1 fetch. The raw store writes it with `json.dumps(payload, default=str)`. |
| `normalize(raw)` | yes | returns the `Batch` of a payload. `src/hst/collectors/base.py` `load_payload` calls it for a fetched payload. `src/hst/core/replay.py` `rebuild` and `hst parse-raw` call it for a stored payload. |
| `probe()` | yes | does a login and 1 small read and returns a text. `hst sources test <name>` prints the text. |
| `side_tables(raw)` | no | returns the rows for each side-store table. The default returns no table. [Storage](storage.md#side-store) lists the tables. |
| `table_outcomes(raw)` | no | returns a `TableOutcome` for each table with a status that the rows do not show, such as `not-captured` |
| `table_feeds(raw)` | no | returns the sections that feed each table. The default returns `TABLE_SECTIONS`. |
| `sections(raw)` | no | returns the section outcomes of a payload without a call of `normalize`. `load_observations` calls it if the collector has it. |
| `afetch()` | no | the fetch as a coroutine. The default runs `fetch` in a thread. `src/hst/app/runs_exec.py` `_wants_loop` selects it only for a config with the `transport` `asyncssh`. |
| `normalization_inputs()` | no | returns data outside the payload and the config that is part of `raw_sha`. The default returns the generation of the identity registry. |
| `link_sources(payload, sources)` | no | a class method that writes data of another source into the config payload. `build_collector` calls it before it makes the config. |
| `release_payload()` | no | drops the cache that the collector holds for the last payload. `load_payload` and `load_observations` call it at the end. |

`Collector.check_stop` raises `CollectionStopped` after the run asked the fetch to stop. Do not replace it.

### Registration and kind

Put the decorator `@register` on the class. `src/hst/collectors/base.py` `register` adds the class to `REGISTRY` with `name` as the key. It raises `TypeError` if `KIND` is not `group` or `orchestrator`. Add the import line of the module to `src/hst/collectors/__init__.py`. `hst collectors` lists the source types of `REGISTRY`.

A source of the kind `group` has a device list. `src/hst/app/sources.py` `build_device_collector` builds the collector of 1 device. `device_config` writes `host` and `host_key` of the device into the config payload, and `port` if the device has one. Declare the field `host` in the config model of a group. A device of a group gets the site of `site_code` of the source.

A source of the kind `orchestrator` has no device list, and `build_collector` builds 1 collector for the source. To report the place of a device, set the properties `reported_location` and `reported_location_name` on the `Device`. `src/hst/app/sources.py` `resolve_device_sites` gives such a device the site of a hand placement. Without a hand placement, the device gets the site that its reported location is bound to.

[Collectors](collectors.md#sources) describes the 2 kinds.

## Normalization

`normalize` returns a `src/hst/core/model.py` `Batch`.

| Record | Fields |
|---|---|
| `NodeRecord` | `label`, `uid`, `props` |
| `RelRecord` | `rel_type`, `start_label`, `start_uid`, `end_label`, `end_uid`, `key`, `props` |
| `Batch` | `source`, `scope`, `nodes`, `rels`, `sections`, `warnings` |

[Uids](conventions.md#uids) and [Loader contract](conventions.md#loader-contract) describe the uid grammar and the loader contract. [Node labels](schema.md#node-labels) lists the labels and the properties that each label needs. [Relationship types](schema.md#relationship-types) lists the relationship types.

### Builder

Build the batch with `src/hst/collectors/util.py` `GraphBuilder`.

| Method | Effect |
|---|---|
| `node(label, uid_, **props)` | adds a node and returns its uid. It drops each property with the value `None`. A second call with the same label and uid adds its properties to the node. |
| `rel(rtype, start_label, start_uid, end_label, end_uid, key=None, **props)` | adds a relationship. A second call with the same type, ends and key adds its properties to the relationship. |
| `props(label, uid_)` | returns a copy of the properties of a node |
| `batch(source, scope)` | returns the `Batch` and calls `Batch.validate_registry` |

If 2 relationships of 1 type join the same 2 nodes, put the property that makes them different in `key`.

`node` raises `src/hst/core/labels.py` `IdentityCollision` if 2 calls give 1 uid 2 different values of `anchor`. For a `Device` and a `VrfInstance`, this also applies to `name` and `hostname`. `Batch.validate_registry` raises `ValueError` for a label or a relationship type that `src/hst/core/labels.py` does not hold, and for a missing property that the label needs. A record does not accept a property with the name `uid` or with the prefix `_`.

`src/hst/collectors/util.py` has more helpers.

| Helper | Use |
|---|---|
| `VrfDomains` | `add` writes a `VrfInstance` with `OWNED_BY` to its `Device`, the `RouteTarget` nodes, and the `RoutingDomain` with `MEMBER_OF`. |
| `connected_address` | writes an `IpAddress` and the `Prefix` of its network with `IN`, and sets `anchor` and `l3dom` on the 2 nodes |
| `overlay_connection` | writes an `OverlayConnection` with `BETWEEN` to its 2 ends and `REALIZED_BY` to each tunnel |
| `canonical_mac` | returns a MAC address in the form of `src/hst/core/uid.py` `norm_mac`, or `None` |
| `offset_paged` | calls a read function for each offset until the function returns no next offset |
| `without_keys` | returns a value without each mapping key that holds one of the given words |

### Device uid

Every `Device` uid comes from the device identity registry in `self.identity`. Call `self.identity.resolve_device` with the chassis serial and the hostname. If the device reports no serial, call it with `<source>:<ref>` and the hostname. Do not build a `dev:` uid by hand.

`src/hst/core/identity.py` `resolve_chassis` does this call. It takes the registry, the serial, a fallback identifier and the hostname. It calls `DeviceResolver.resolve_device` with the kind `serial` and the serial. For a device without a serial or with a placeholder serial, it uses the fallback, such as `("ref", "<scope>:<id>")`. The registry makes the uid at the first call for an identifier, and each later call returns the same uid. [Conventions](conventions.md#device-identity) describes the uid.

`chassis_serial` returns `None` for a placeholder serial. Use its result for the property `serial`. By default, `self.identity` is a `MemoryResolver`, so a collector in a test needs no Postgres.

A `Device` needs the property `role`. Use a value of `src/hst/core/labels.py` `DEVICE_ROLES`, and `unknown` if the management plane gives no role. `validate_registry` only makes sure that `role` has a value. `src/hst/collectors/base.py` `_load_payload` reads `hostname` or `name`, `platform`, and `mgmt_ip` or `management_address` of each `Device`.

### Interface uid

Make each interface uid with `src/hst/core/uid.py` `interface`, `port` or `lag`. The 3 builders apply `src/hst/core/normalize.py` `iface_slug` to the interface name, which gives `gi0-0` for `GigabitEthernet0/0`. For a dict of interfaces, use `canonical_ifname` of the name as the key. `IfNameResolver` resolves a short name from a command answer to the name in the interface table. A collector that makes these uids sets the key `iface_uid` of `NORMALIZATION_VERSIONS` to `uid.IFACE_UID_VERSION`.

### Scope

Set `self.scope` to `<prefix>:<partition>`, and make the partition from the config. `src/hst/collectors/netscaler.py` uses `netscaler:<scope_name>`. `src/hst/core/loader.py` `collector_type` reads the prefix, which is the text before the first colon. `COLLECTOR_CLASSES` maps the prefix to the authority class. Give the same scope to `GraphBuilder.batch`. `src/hst/collectors/base.py` `load_payload` replaces `Batch.source` with the name of the source. [Conventions](conventions.md#batch-scope) describes the scopes.

### Section outcomes

`Batch.sections` maps a section name to a `SectionOutcome` with `status`, `detail` and `row_count`. A section is 1 part of the payload, such as the answer to 1 request. The status is `ok`, `empty`, `unsupported`, `unauthorized`, `malformed`, `partial`, `failed` or `unknown`.

`src/hst/core/model.py` `section_verdict` reads the statuses `failed`, `unauthorized` and `malformed`. On a section of `AUTHORITATIVE_SECTIONS`, such a status gives the device the verdict `failed`. On each other section, it gives the verdict `partial`. For a section with such a status, `src/hst/app/runs_exec.py` `_failed_section_labels` returns the labels of `SECTION_LABELS`. [Code flow of a collection](collection-code-flow.md#carry) describes what a run does with these labels.

A fetch that continues after a failed read records the outcome of the read in the payload. `src/hst/collectors/netscaler.py` `NetScalerCollector._fetch_mtu_interfaces` writes it below the key `_strata_outcomes`, the value of `src/hst/collectors/base.py` `RAW_OUTCOMES_KEY`. `raw_sha` leaves this key out, and reads from it only the keys of `NORMALIZATION_OUTCOME_KEYS`. `_netscaler_mtu` makes the `SectionOutcome` from the record.

Put the hostname of the device in each text of `Batch.warnings`. `src/hst/collectors/base.py` `_load_payload` gives a device each warning that holds its uid or its hostname.

## Sample collector

The sample is a collector for an HTTP API with the source type `example`. `tests/test_docs_example.py` runs the block and holds a payload for it.

<!-- example: collector -->
```python
"""The Example collector reads the devices and the interfaces of an Example controller."""

from __future__ import annotations

from typing import Any, ClassVar

import httpx
from pydantic import Field

from hst.core import uid
from hst.core.identity import DeviceResolver, chassis_serial, resolve_chassis
from hst.core.model import Batch, SectionOutcome

from . import http
from .auth import ApiKeyCredential, TlsConfig
from .base import Collector, SourceConfig, register
from .util import GraphBuilder, canonical_mac

VERSION_PATH = "/api/v1/version"
DEVICES_PATH = "/api/v1/devices"

# Maps the `type` of an Example device to a value of `DEVICE_ROLES`.
_ROLES = {"ROUTER": "router", "SWITCH": "switch", "FIREWALL": "firewall"}


class ExampleConfig(SourceConfig):
    url: str = Field(title="Controller URL")
    auth: ApiKeyCredential
    tls: TlsConfig = TlsConfig()


def _transport(config: ExampleConfig) -> httpx.BaseTransport | None:
    return None  # A test replaces this function.


def _scope(url: str) -> str:
    return f"example:{uid.slug(httpx.URL(url).host or url)}"


@register
class ExampleCollector(Collector):
    name = "example"
    ConfigModel = ExampleConfig
    KIND = "orchestrator"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {"iface_uid": uid.IFACE_UID_VERSION}

    def __init__(self, config: ExampleConfig, settings):
        super().__init__(config, settings)
        self.scope = _scope(config.url)

    def _client(self) -> httpx.Client:
        c = self.config
        client = http.client(c.url, c.tls, timeout=30, transport=_transport(c))
        client.headers["Authorization"] = f"Bearer {c.auth.key.get_secret_value()}"
        return client

    def _get(self, client: httpx.Client, path: str) -> dict[str, Any]:
        self.check_stop()
        response = client.get(path)
        response.raise_for_status()
        return response.json()

    def probe(self) -> str:
        client = self._client()
        try:
            version = self._get(client, VERSION_PATH).get("version", "?")
            return f"login ok: Example {version} at {self.config.url}"
        finally:
            client.close()

    def fetch(self) -> dict[str, Any]:
        client = self._client()
        try:
            return {"devices": self._get(client, DEVICES_PATH).get("devices", [])}
        finally:
            client.close()

    def normalize(self, raw: dict[str, Any]) -> Batch:
        return normalize_example(raw, scope=self.scope, resolver=self.identity)


def normalize_example(raw: dict[str, Any], *, scope: str, resolver: DeviceResolver) -> Batch:
    b = GraphBuilder()
    devices = raw.get("devices", [])
    for device in devices:
        hostname = device.get("hostname")
        dev = b.node(
            "Device",
            resolve_chassis(resolver, device.get("serial"), ("ref", f"{scope}:{device['id']}"), hostname),
            hostname=hostname,
            serial=chassis_serial(device.get("serial")),
            model=device.get("model"),
            platform="example",
            role=_ROLES.get(str(device.get("type") or "").upper(), "unknown"),
            reported_location=device.get("location_id"),
            reported_location_name=device.get("location_name"),
        )
        for interface in device.get("interfaces", []):
            name = interface["name"]
            mac = canonical_mac(interface.get("mac"))
            iu = b.node("Interface", uid.interface(dev, name), name=name, mac=mac)
            pu = b.node("Port", uid.port(dev, name), name=name, mac=mac)
            b.rel("ON", "Interface", iu, "Device", dev)
            b.rel("ON", "Port", pu, "Device", dev)
            b.rel("REALIZED_BY", "Interface", iu, "Port", pu)
    batch = b.batch("example", scope)
    batch.sections["devices"] = SectionOutcome(status="ok" if devices else "empty", row_count=len(devices))
    return batch
```

## Rules

[Writing a collector](../CONTRIBUTING.md#writing-a-collector) holds the rules for a collector. A contributor needs these rules too.

- Build each HTTP client with `src/hst/collectors/http.py` `client` or `logged_in_client`. The client applies the TLS settings, the answer limit and the HTTP trace.
- Give the client `transport=_transport(config)`, where `_transport` is a function of the module that returns `None`. A test replaces the function.
- Call `src/hst/collectors/base.py` `Collector.check_stop` before each request of a fetch.
- Read each page of a paged answer.
- Remove each key that holds a secret from an answer before `fetch` returns. `src/hst/collectors/equinix.py` `_without_secrets` does this with `src/hst/collectors/util.py` `without_keys`.
- Send no request in `normalize`.

## Tests

- Write the payload by hand in the test module.
- Build the collector with its config model and `Settings(_env_file=None)`.
- Call `normalize` on the payload, and do a check of the uids, the properties and the relationships. `tests/test_netscaler.py` does this for a normalize function.
- For `probe` and `fetch`, replace `_transport` of the module with a function that returns an `httpx.MockTransport`. `tests/test_ndo.py` and `tests/test_equinix.py` do this with `monkeypatch.setattr`.
- Give `self.identity` a `src/hst/core/identity.py` `MemoryResolver` that holds 1 identifier of the payload. Make sure that the `Device` has the uid of that identifier.
- `tests/test_schema_contract.py` `_assert_device_roles_are_registered` makes sure that each `role` of a batch is a value of `src/hst/core/labels.py` `DEVICE_ROLES`. For a collector that writes a `Device`, add 1 test to that file that calls it.
- `_assert_net_objects_carry_addresses` of that file does a check of each `NetObject` at the end of a `SRC` or `DST` relationship of a `FwRule`. The `NetObject` needs a `RESOLVES_TO` relationship, the property `ranges` or the property `opaque`. For a collector that writes such a `FwRule`, add 1 test that calls it.
- Change the tests of the conditional rows in [Files to change](#files-to-change).

`make test` runs the unit tests without a database. `make check` runs the targets `no-run-data`, `lock-check`, `lint`, `typecheck`, `helm-check`, `test` and `web-check`.

`hst sources add <name> --type <type>` makes a source and asks for each secret field that `--config` does not hold. `hst sources test <name>` does the probe of a source.

## Checklist

1. Add the module with the config model, the collector class and the normalize function.
2. Set `name`, `ConfigModel` and `KIND` on the class.
3. Put `@register` on the class.
4. Add the import line to `src/hst/collectors/__init__.py`.
5. Give each secret field the type `SecretStr`.
6. Set `self.scope` in `__init__`.
7. Write `fetch`, `normalize` and `probe`.
8. Build the batch with `GraphBuilder` and the scope of the collector.
9. Get each `Device` uid from `self.identity`.
10. Give each `Device` a `role` of `DEVICE_ROLES`.
11. Make each interface uid with a builder of `src/hst/core/uid.py`, and set `iface_uid` in `NORMALIZATION_VERSIONS`.
12. Do a check of the collector against each rule of [Rules](#rules).
13. Add the entry to `COLLECTORS`.
14. Change the field total in `tests/app/test_inventory_contracts.py`.
15. Add the entry to `CLASSIFICATION`.
16. Add the entry to `MINIMAL_PAYLOADS`.
17. Write the tests with a hand-written payload.
18. Do each conditional change of [Files to change](#files-to-change).
19. Run `tools/gen_docs.py`.
20. Run `make check`.
