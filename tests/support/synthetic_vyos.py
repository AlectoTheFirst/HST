"""Deterministic VyOS device answers, the payloads a fetch seals from them, and
the digests the VyOS streaming-parity tests compare by.

The VyOS fetch keeps each FRR RIB answer as the text vtysh printed. The answers
here are the inputs those tests share. `vyos_golden.json` beside this module,
the base record, holds the recorded values of each case. Nothing in the
repository writes it. `vyos_namespace_golden.json` and
`vyos_iface_uid_golden.json` are overlays that `load_golden` lays over the
base record. tests/test_vyos_stream_parity.py holds what a load produces from
the answers of a case to the recorded values.

A case is named `<scale>/<variant>` (`CASES`):

- scale `fixture` is built from the fixtures of `tests/test_vyos.py`: its
  `CONFIG` with `BGP_CONFIG`'s BGP process and policies, `VERSION`, `LINKS`,
  `ADDRS`, `LINK_SPEEDS_TEXT`, a small RIB made with its `_route`/`_nh`
  helpers, and the BGP answers of `_bgp_capture_raw`;
- `small` and `medium` (`SCALES`) are synthetic: `routes` prefixes per address
  family across the default table and one VRF, two policy tables, and two BGP
  peers, one of them in the VRF, each with a received, accepted and
  advertised path table of `paths` rows;
- variant `plain` is the answers as built; `malformed_rib` truncates the IPv6
  RIB answer, `malformed_table` the first policy table's IPv4 answer, so
  neither is JSON; `percent_bgp` makes the first peer's received table the
  `%` banner FRR prints without soft reconfiguration; `empty_bgp` makes the
  last peer's advertised table an empty answer; `refused` has the device
  refuse the first policy table's IPv6 read as an unknown command and the
  last peer's accepted table for want of privilege.

`answers(key)` maps each command, as `VyosCollector._afetch_over` names it
before the op-mode wrapper, to the device's text or to a `Refusal`.
`base_raw(answers)` is the payload the base record was computed from (RIB
trees decoded, a `<key>_error` note and `[]` for an answer that is not JSON)
and `new_raw(answers)` the one this tree's fetch seals (RIB text). The
generator is integer arithmetic on a fixed seed (`_Rng`), so the answers are
byte-for-byte the same on every Python version, which `answers_sha` pins.
Nothing here was captured from real infrastructure.

Per case (`CASES`), `vyos_golden.json` holds:

- `answers_sha`: `answers_sha`, which proves the generator still builds the
  answers these values were computed from;
- `base_payload_sha`: `payload_json_sha` of `base_raw(answers)`, the JSON the
  raw store seals for it;
- `raw_sha`, `obs_sha`: `collectors.base.raw_sha`/`obs_sha` of that payload
  under `make_collector`;
- `normalize`: `batch_digest` of the collector's `normalize`;
- `sections`, `table_outcomes`: `Batch.sections` and the collector's
  `table_outcomes`, as `outcomes_json`;
- `side_tables`: `[count, sha]` from `rows_digest` per `side_tables` table;
- `parquet`: per table, `sidestore.write_table` with `RUN_ID`, `SNAPSHOT_TS`
  and `ROW_GROUP_ROWS`, then `manifest.sidestore_row_facts`: `[count,
  rows_sha]`, or `[0, null]` for a table with no rows;
- `parquet_layout`: per table, `parquet_layout` of the same file: its row
  groups, schema and row order. Null for a table with no rows;
- `tables`: the outcomes `collectors.base._write_side_tables` returns for the
  same run id and snapshot, whose `path` is relative to the data directory;
- `base_peak_bytes`: for the medium cases only, a tracemalloc peak of
  `collectors.base.load_payload` (`tests.test_collector_execute.FakeSession`,
  row groups of `MEMORY_ROW_GROUP_ROWS`) on a fresh collector, with the
  payload already allocated. tests/test_vyos_stream_memory.py bounds the peak
  of a load by a share of it.

The BGP path commands are in the spelling without the IPv4 unicast family
clause (`vyos.legacy_bgp_route_command`). `fetch` runs the collector's fetch with
that spelling. The family spelling and FRR's real
shapes are tested in `tests/test_vyos.py`.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib
import json
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple
from unittest.mock import patch

from tests.support.synthetic_payloads import (
    COLLECTOR_HOST,
    COLLECTOR_ROUTING_SCOPE,
    COLLECTOR_SITE,
    COLLECTOR_SOURCE,
    BaseRecordUids,
)

if TYPE_CHECKING:
    from hst.collectors.vyos import VyosCollector
    from hst.core import Settings
    from hst.core.model import Batch

GOLDEN_PATH = Path(__file__).with_name("vyos_golden.json")
NAMESPACE_GOLDEN_PATH = Path(__file__).with_name("vyos_namespace_golden.json")
IFACE_UID_GOLDEN_PATH = Path(__file__).with_name("vyos_iface_uid_golden.json")

VARIANTS: tuple[str, ...] = (
    "plain",
    "malformed_rib",
    "malformed_table",
    "percent_bgp",
    "empty_bgp",
    "refused",
)

# Keyword arguments of `_synthetic_answers` per scale: prefixes per address
# family in the `vrf all` answers, and rows per path table.
SCALES: dict[str, dict[str, int]] = {
    "small": {"routes": 2_000, "paths": 2_000},
    "medium": {"routes": 20_000, "paths": 20_000},
}

# Every variant at the two small scales; the medium scale, which the memory
# test loads, as built and with its large IPv6 answer malformed.
CASES: tuple[str, ...] = (
    *(f"{scale}/{variant}" for scale in ("fixture", "small") for variant in VARIANTS),
    "medium/plain",
    "medium/malformed_rib",
)

# The row group size `load_payload` writes with in the memory test.
MEMORY_ROW_GROUP_ROWS = 8192

# What `_op_mode` puts in front of an op-mode command; the fake session takes
# it off again so the answers are keyed by the command the collector names.
_OP_WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper "


class Refusal(NamedTuple):
    """A command the device refuses: the fake session raises
    `ssh.CommandFailed(message)` for it, as the SSH layer does."""

    message: str


Answers = dict[str, str | Refusal]


def split_case(key: str) -> tuple[str, str]:
    scale, variant = key.split("/")
    if scale not in ("fixture", *SCALES) or variant not in VARIANTS:
        raise ValueError(f"unknown case {key!r}")
    return scale, variant


def answers(key: str) -> Answers:
    """The device's answer to every command a `capture_bgp="all"` fetch of
    case `key` issues."""
    scale, variant = split_case(key)
    built = _fixture_answers() if scale == "fixture" else _synthetic_answers(**SCALES[scale])
    return _apply_variant(built, variant)


def answers_sha(built: Mapping[str, str | Refusal]) -> str:
    """SHA-256 hex of the answers in sorted-key JSON: the generator's fingerprint."""
    body = {
        command: {"refused": answer.message} if isinstance(answer, Refusal) else answer
        for command, answer in built.items()
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


# --- the sealed payloads -------------------------------------------------------------------


def _answer(built: Mapping[str, str | Refusal], command: str) -> str:
    """The text the device printed for `command`; raises as the SSH layer does
    for a refused one."""
    from hst.collectors import ssh

    answer = built.get(command)
    if answer is None:
        raise ssh.CommandFailed(f"{command!r} rejected by device: % Unknown command")
    if isinstance(answer, Refusal):
        raise ssh.CommandFailed(answer.message)
    return answer


def _seal(built: Mapping[str, str | Refusal], *, rib_text: bool, capture: str) -> dict[str, Any]:
    """The payload `_afetch_over` seals from `built`, key order included.

    `rib_text` False is the payload of the base record, with every RIB answer
    decoded; True is this tree's, which keeps the text and reads the neighbor
    table after the addresses. Everything else is the same in both:
    the command order, the `<key>_error` notes and `[]` stand-ins of a failed
    read, the outcome of every command.
    """
    from hst.collectors import vyos
    from hst.collectors.base import RAW_OUTCOMES_KEY
    from hst.collectors.cli_collector import classify_command_failure

    outcomes: dict[str, dict[str, Any]] = {}

    def as_text(text: str) -> str:
        return text

    def optional(key: str, command: str, parse: Callable[[str], Any] = json.loads) -> Any:
        try:
            value = parse(_answer(built, command))
            if key == "links" and (
                not isinstance(value, list) or any(not isinstance(row, dict) for row in value)
            ):
                raise json.JSONDecodeError("ip-link response must be an array of objects", "", 0)
        except (RuntimeError, json.JSONDecodeError) as exc:
            raw[f"{key}_error"] = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, json.JSONDecodeError):
                outcomes[key] = {"status": "malformed", "detail": str(exc)}
            else:
                status, detail = classify_command_failure(exc)
                outcomes[key] = {"status": status, "detail": detail}
            return []
        outcomes[key] = {"status": "ok"}
        return value

    rib_parse = as_text if rib_text else json.loads
    commands = vyos.READ_COMMANDS
    raw: dict[str, Any] = {
        "config": json.loads(_answer(built, commands["config"])),
        "version_text": _answer(built, commands["version"]),
    }
    outcomes["config"] = {"status": "ok"}
    outcomes["version"] = {"status": "ok"}
    raw["links"] = optional("links", commands["links"])
    raw["addrs"] = optional("addrs", commands["addrs"])
    if rib_text:
        raw["neigh"] = optional("neigh", commands["neigh"])
    raw["link_speeds"] = optional("link_speeds", commands["link_speeds"], as_text)
    raw["routes"] = optional("routes", commands["routes"], rib_parse)
    raw["routes6"] = optional("routes6", commands["routes6"], rib_parse)
    static = ((raw["config"].get("protocols") or {}).get("static") or {}).get("table") or {}
    for key, ip_word in (("routes", "ip"), ("routes6", "ipv6")):
        tables: dict[str, Any] = {}
        for t in static:
            number = int(t)
            tables[str(t)] = optional(
                f"{key}_table_{number}", policy_table_command(ip_word, number), rib_parse
            )
        raw[f"{key}_tables"] = tables
    for vname in vyos._ospf_vrf_names(raw["config"]):
        for sub_key, sub in vyos._OSPF_SUBCOMMANDS:
            key = vyos._ospf_raw_key(vname, sub_key)
            raw[key] = optional(key, vyos._ospf_command(sub, vname))
    if capture != "none":
        bgp_commands = [vyos.BGP_SUMMARY_COMMAND]
        if capture == "all":
            for vrf_name, peer_ip in vyos.bgp_capture_targets(raw.get("config") or {}):
                bgp_commands.extend(
                    vyos.legacy_bgp_route_command(vrf_name, peer_ip, d) for d in vyos.BGP_DIRECTION_KEYWORDS
                )
        for command in bgp_commands:
            try:
                raw[command] = _answer(built, command)
                outcomes[command] = {"status": "ok"}
            except RuntimeError as exc:
                raw[command] = "{}"
                status, detail = classify_command_failure(exc)
                outcomes[command] = {"status": status, "detail": detail}
    raw[RAW_OUTCOMES_KEY] = outcomes
    return raw


def base_raw(built: Mapping[str, str | Refusal], *, capture: str = "all") -> dict[str, Any]:
    """The payload of `built` that the base record was computed from: every
    RIB answer decoded, and one that is not JSON replaced by `[]` beside its
    `<key>_error` note and a `malformed` outcome."""
    return _seal(built, rib_text=False, capture=capture)


def new_raw(built: Mapping[str, str | Refusal], *, capture: str = "all") -> dict[str, Any]:
    """The payload this tree's fetch seals from `built`: every RIB answer as
    the text the device printed, with an `ok` outcome whatever the text is."""
    return _seal(built, rib_text=True, capture=capture)


def policy_table_command(ip_word: str, number: int) -> str:
    """The per-table RIB read `_afetch_over` issues for a policy table."""
    from hst.collectors import vyos

    return f'{vyos._IP_PATH} vtysh -c "show {ip_word} route table {number} json"'


class AnswerSession:
    """An async session that answers each command from `built`, the seam
    `VyosCollector._afetch_over` runs over. It records what was run."""

    def __init__(self, built: Mapping[str, str | Refusal]) -> None:
        self._built = built
        self.commands: list[str] = []

    async def run(self, command: str) -> str:
        self.commands.append(command)
        return _answer(self._built, command.removeprefix(_OP_WRAPPER))


def fetch(collector: VyosCollector, built: Mapping[str, str | Refusal]) -> dict[str, Any]:
    """What `collector`'s own fetch code seals from `built`, the BGP path
    commands sent in the spelling `built` answers (`old_route_spelling`)."""
    with old_route_spelling():
        payload: dict[str, Any] = asyncio.run(collector._afetch_over(AnswerSession(built)))
    return payload


@contextmanager
def old_route_spelling() -> Iterator[None]:
    """The fetch sends the BGP path commands without the family clause
    (`vyos.legacy_bgp_route_command`), the commands every case
    answers."""
    from hst.collectors import vyos

    with patch.object(vyos, "bgp_route_command", vyos.legacy_bgp_route_command):
        yield


def base_spelled(capture: Mapping[str, Any]) -> dict[str, Any]:
    """`capture` with every BGP path command in the spelling without the
    family clause, each key in its place."""
    return {key.replace(" ipv4 unicast neighbors ", " neighbors "): value for key, value in capture.items()}


# --- collectors and digests ----------------------------------------------------------------


def make_collector(settings: Settings | None, *, capture_bgp: str = "all") -> VyosCollector:
    """The VyOS collector with the fixed per-device configuration every golden
    value was computed with (`synthetic_payloads.make_collector`'s)."""
    from pydantic import SecretStr

    from hst.collectors.auth import SshPassword
    from hst.collectors.vyos import VyosCollector, VyosConfig

    config = VyosConfig(
        host=COLLECTOR_HOST,
        auth=SshPassword(username="golden", password=SecretStr("golden")),
        site_code=COLLECTOR_SITE,
        routing_scope=COLLECTOR_ROUTING_SCOPE,
        source_name=COLLECTOR_SOURCE,
        capture_bgp=capture_bgp,
    )
    collector = VyosCollector(config, settings)
    collector.identity = BaseRecordUids()
    return collector


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _without_overlay_connections(batch: Batch) -> tuple[list[Any], list[Any]]:
    """The batch's nodes and relationships without the `OverlayConnection`
    objects (schema v0.30.0): the connections, their `BETWEEN` and
    `REALIZED_BY` edges, and an `IpAddress` that only a `BETWEEN` edge names.
    A base digest holds none of them."""
    dropped = {n.uid for n in batch.nodes if n.label == "OverlayConnection"}
    rels = [r for r in batch.rels if r.start_uid not in dropped]
    named = {u for r in rels for u in (r.start_uid, r.end_uid)}
    far = {r.end_uid for r in batch.rels if r.rel_type == "BETWEEN" and r.start_uid in dropped} - named
    nodes = [n for n in batch.nodes if n.uid not in dropped and not (n.label == "IpAddress" and n.uid in far)]
    return nodes, rels


def batch_digest(batch: Batch) -> str:
    """SHA-256 hex of a Batch's source, scope, warnings and every node and
    relationship with its key and properties, the records in sorted order:
    what the graph receives, whatever order the builder emitted it in. The
    `OverlayConnection` objects are left out (`_without_overlay_connections`)."""
    kept_nodes, kept_rels = _without_overlay_connections(batch)
    nodes = sorted(_canonical(node.model_dump(mode="json")) for node in kept_nodes)
    rels = sorted(_canonical(rel.model_dump(mode="json", by_alias=True)) for rel in kept_rels)
    body = {
        "source": batch.source,
        "scope": batch.scope,
        "warnings": list(batch.warnings),
        "nodes": nodes,
        "rels": rels,
    }
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


def is_device_pbr_enforces(rel: Any) -> bool:
    """`(Device)-[:ENFORCES]->(PbrPolicy)`: the edge from the router to each policy
    route it holds, which the base record does not cover."""
    return rel.rel_type == "ENFORCES" and rel.start_label == "Device" and rel.end_label == "PbrPolicy"


def is_wanlink_on(rel: Any) -> bool:
    """`(WanLink)-[:ON]->(Interface)`: the interface a WAN link leaves the router
    by, which the base record does not cover."""
    return rel.rel_type == "ON" and rel.start_label == "WanLink" and rel.end_label == "Interface"


def tree_family(node: Any) -> int | None:
    """The address family the uid of a PbrPolicy or a NatRule names by its tree
    (`pbr:ipv6:` and `nat66:` are IPv6, `pbr:` and `nat:` IPv4), which the node
    records as `af`; None for any other node."""
    if node.label == "PbrPolicy":
        return 6 if ":pbr:ipv6:" in node.uid else 4
    if node.label == "NatRule":
        return 6 if ":nat66:" in node.uid else 4
    return None


def base_shape(batch: Batch) -> Batch:
    """`batch` in the shape the `normalize` digests of the base record cover:
    without the `is_device_pbr_enforces` and `is_wanlink_on` edges, and with
    the changes below. tests/test_vyos_stream_parity.py holds the edges taken
    out to exactly one per PbrPolicy and one per WanLink, so this strip can
    hide no other change.

    The scope of the base record is `vyos:<hostname>`, from the `hostname` of
    the batch's one Device node. The batch takes the collector's own scope,
    `vyos:<host>`, the string a run names the device's partition by. Only the
    scope is changed.

    An `ORIGINATES` edge is keyed by its `proto`, so a connected prefix and
    a BGP network or aggregate statement for it are two edges. The base record
    covers the edge with no key. The key is taken off, and the `proto`
    property it repeats stays.

    A WireGuard Tunnel uid names its interface and the exact peer name,
    `tun:wireguard:<dev>~<interface>~<peer>`. The base record covers
    `tun:wireguard:<dev>~<slug of the peer>`. That uid is put on the node and
    on every edge that names it.

    A PbrPolicy and a NatRule record the address family of their tree as
    `af`, which the base record does not cover. It is taken off where it is the
    family the uid names (`tree_family`), so a wrong family stays and changes
    the digest.

    A VrfInstance records whether the graph holds its whole RIB as the
    boolean `rib_mirrored`, which the base record does not cover. It is taken
    off where it is a boolean; tests/test_vyos_stream_parity.py holds every
    VrfInstance to one."""
    from hst.core import uid

    [device] = [n for n in batch.nodes if n.label == "Device"]
    renamed = {
        n.uid: f"tun:wireguard:{device.uid}~{uid.slug(str(n.props['name']))}"
        for n in batch.nodes
        if n.label == "Tunnel" and n.uid.startswith(f"tun:wireguard:{device.uid}~")
    }
    return batch.model_copy(
        update={
            "scope": f"vyos:{device.props['hostname']}",
            "nodes": [
                n.model_copy(
                    update={
                        "uid": renamed.get(n.uid, n.uid),
                        "props": {
                            k: v
                            for k, v in n.props.items()
                            if not (k == "af" and v is not None and v == tree_family(n))
                            and not (k == "rib_mirrored" and n.label == "VrfInstance" and isinstance(v, bool))
                        },
                    }
                )
                if n.uid in renamed or tree_family(n) is not None or n.label == "VrfInstance"
                else n
                for n in batch.nodes
            ],
            "rels": [
                r.model_copy(
                    update={
                        "key": {} if r.rel_type == "ORIGINATES" else r.key,
                        "start_uid": renamed.get(r.start_uid, r.start_uid),
                        "end_uid": renamed.get(r.end_uid, r.end_uid),
                    }
                )
                for r in batch.rels
                if not is_device_pbr_enforces(r) and not is_wanlink_on(r)
            ],
        }
    )


# The properties the base record does not cover, with the value a load writes
# when the configuration states nothing they record (`defaults_free`), by node
# label or relationship type: the distance of a static route, a rule's
# jump target and a ruleset's default jump target, a NAT rule's
# unmodeled scope, and a zone's intra-zone filtering.
DEFAULT_PROPS: dict[str, dict[str, Any]] = {
    "STATIC_ROUTE": {"distance": 1},
    "FwRule": {"jump_target": ""},
    "FwRulebase": {"default_jump_target": ""},
    "NatRule": {"approximate": False, "approximate_reason": ""},
    "Zone": {"intra_zone_filtering": False},
    # the BGP process records that its maximum-paths were read
    "RoutingProcess": {"multipath_config_recorded": True},
}


def defaults_free(batch: Batch) -> Batch:
    """`batch` without each `DEFAULT_PROPS` property where it holds its default
    value, so its digest can be held to the base record. A value other than
    the default stays and changes the digest, so the strip hides no change a
    case's configuration makes."""

    def kept(label: str, props: dict[str, Any]) -> dict[str, Any]:
        defaults = DEFAULT_PROPS[label]
        return {k: v for k, v in props.items() if k not in defaults or defaults[k] != v}

    return batch.model_copy(
        update={
            "nodes": [
                n.model_copy(update={"props": kept(n.label, n.props)}) if n.label in DEFAULT_PROPS else n
                for n in batch.nodes
            ],
            "rels": [
                r.model_copy(update={"props": kept(r.rel_type, r.props)})
                if r.rel_type in DEFAULT_PROPS
                else r
                for r in batch.rels
            ],
        }
    )


def link_local_free(batch: Batch) -> Batch:
    """`batch` without the IPv6 link-local addresses an Interface keeps
    (`ipv6_link_local`), which the base record does not cover, so its
    digest can be held to the base record. A list holding anything but
    link-local addresses stays and changes the digest, so the strip hides no
    other change."""
    import ipaddress

    def link_local(value: Any) -> bool:
        return isinstance(value, list) and all(ipaddress.ip_address(str(v)).is_link_local for v in value)

    return batch.model_copy(
        update={
            "nodes": [
                n.model_copy(
                    update={
                        "props": {
                            k: v for k, v in n.props.items() if not (k == "ipv6_link_local" and link_local(v))
                        }
                    }
                )
                if n.label == "Interface"
                else n
                for n in batch.nodes
            ]
        }
    )


# The installation evidence a VyOS ruleset, zone and filter-chain binding
# carry, which the base record does not cover: on the FwRulebase and Zone
# nodes, and on the (Device)-[:ENFORCES]->(FwRulebase) edges with their scope.
INSTALLATION_NODE_PROPS: tuple[str, ...] = (
    "installed",
    "coverage",
    "installed_revision",
    "configured_revision",
)
INSTALLATION_EDGE_PROPS: tuple[str, ...] = (
    "installed",
    "coverage",
    "installed_revision",
    "context_uid",
    "ingress_interface_uid",
    "egress_interface_uid",
    "address_family",
)


def is_ruleset_enforces(rel: Any, batch: Batch) -> bool:
    """Whether `rel` is a `(Device)-[:ENFORCES]->(FwRulebase)` edge of `batch`."""
    rulebases = {n.uid for n in batch.nodes if n.label == "FwRulebase"}
    return rel.rel_type == "ENFORCES" and rel.end_uid in rulebases


def installation_free(batch: Batch) -> Batch:
    """`batch` without the installation evidence the base record does not cover
    (`INSTALLATION_NODE_PROPS` on FwRulebase and Zone nodes,
    `INSTALLATION_EDGE_PROPS` on ruleset ENFORCES edges), so its digest can
    be held to the base record. tests/test_vyos_stream_parity.py holds what
    this takes out to exactly that evidence, one revision per load."""
    rulebases = {n.uid for n in batch.nodes if n.label == "FwRulebase"}
    return batch.model_copy(
        update={
            "nodes": [
                n.model_copy(
                    update={"props": {k: v for k, v in n.props.items() if k not in INSTALLATION_NODE_PROPS}}
                )
                if n.label in ("FwRulebase", "Zone")
                else n
                for n in batch.nodes
            ],
            "rels": [
                r.model_copy(
                    update={"props": {k: v for k, v in r.props.items() if k not in INSTALLATION_EDGE_PROPS}}
                )
                if r.rel_type == "ENFORCES" and r.end_uid in rulebases
                else r
                for r in batch.rels
            ],
        }
    )


# The BgpSession settings the base record does not cover: route-reflector-client
# and the cluster id, an AS-path filter-list and a prefix-list beside a
# route-map.
SESSION_SETTING_PROPS: frozenset[str] = frozenset(
    {
        "route_reflector_client",
        "cluster_id",
        "import_filter_list_name",
        "export_filter_list_name",
        "import_prefix_list_name",
        "export_prefix_list_name",
    }
)


def is_beside_prefix_list_filter(rel: Any) -> bool:
    """Whether `rel` is the FILTERED_BY edge of a prefix-list attached beside
    a route-map (`direction` `in-prefix-list` or `out-prefix-list`)."""
    return rel.rel_type == "FILTERED_BY" and str(rel.key.get("direction") or "").endswith("-prefix-list")


def session_settings_free(batch: Batch) -> Batch:
    """`batch` without the BgpSession settings the base record does not cover
    (`SESSION_SETTING_PROPS`, and the FILTERED_BY edge of a prefix-list beside
    a route-map) and without the RoutingProcess's `session_gaps`, so
    its digest can be held to the base record.
    tests/test_vyos_stream_parity.py holds what this takes out to exactly
    those settings."""
    return batch.model_copy(
        update={
            "nodes": [
                n.model_copy(
                    update={"props": {k: v for k, v in n.props.items() if k not in SESSION_SETTING_PROPS}}
                )
                if n.label == "BgpSession"
                else n.model_copy(update={"props": {k: v for k, v in n.props.items() if k != "session_gaps"}})
                if n.label == "RoutingProcess"
                else n
                for n in batch.nodes
            ],
            "rels": [r for r in batch.rels if not is_beside_prefix_list_filter(r)],
        }
    )


def payload_json_sha(payload: Mapping[str, Any]) -> str:
    """SHA-256 hex of `json.dumps(payload, default=str)`, key order included:
    the JSON the raw store seals."""
    return hashlib.sha256(json.dumps(payload, default=str).encode()).hexdigest()


# The uid prefixes of a router's device-local objects (firewall rulebases and
# rules, zones, groups, NAT, PBR and WAN links): `vyos:<namespace>:` and
# `wan:<namespace>:` (`vyos.local_namespace`).
LOCAL_UID_PREFIXES: tuple[str, ...] = ("vyos", "wan")


def hostname_keyed(batch: Batch) -> Batch:
    """`batch` with every device-local uid keyed by the configured hostname,
    the key of the base record (`LOCAL_UID_PREFIXES`).

    The namespace is the name part of the batch's one Device uid and the
    hostname is that Device's `hostname`. A uid, a relationship end, or a
    key or property value (or a list item of one) that starts with
    `vyos:<namespace>:` or `wan:<namespace>:` gets the hostname in place of
    the namespace; nothing else is touched. A batch whose namespace is its
    hostname comes back as it is."""
    from hst.collectors.vyos import local_namespace

    [device] = [n for n in batch.nodes if n.label == "Device"]
    namespace, host = local_namespace(device.uid), device.props["hostname"]
    if namespace == host:
        return batch
    moves = tuple((f"{prefix}:{namespace}:", f"{prefix}:{host}:") for prefix in LOCAL_UID_PREFIXES)

    def back(value: Any) -> Any:
        if isinstance(value, list):
            return [back(item) for item in value]
        if isinstance(value, str):
            for new, old in moves:
                if value.startswith(new):
                    return old + value[len(new) :]
        return value

    def mapped(fields: Mapping[str, Any]) -> dict[str, Any]:
        return {name: back(value) for name, value in fields.items()}

    return batch.model_copy(
        update={
            "nodes": [
                n.model_copy(update={"uid": back(n.uid), "props": mapped(n.props)}) for n in batch.nodes
            ],
            "rels": [
                r.model_copy(
                    update={
                        "start_uid": back(r.start_uid),
                        "end_uid": back(r.end_uid),
                        "key": mapped(r.key),
                        "props": mapped(r.props),
                    }
                )
                for r in batch.rels
            ],
        }
    )


def _slug_version_1(name: str) -> str:
    from hst.core.normalize import short_ifname

    return short_ifname(name).replace("/", "-").replace(".", "-").replace(":", "-")


@contextmanager
def iface_uid_version_1() -> Iterator[None]:
    """Run with `iface_slug` as interface uid version 1 wrote it: '.'
    folded to '-' with '/' and ':', so `eth1.30` is the uid segment `eth1-30`.
    Every `hst` module that holds `iface_slug` by name gets the version 1
    function for the length of the block."""
    from hst.core import normalize

    current = normalize.iface_slug
    with ExitStack() as stack:
        for name, module in list(sys.modules.items()):
            if (name == "hst" or name.startswith("hst.")) and getattr(module, "iface_slug", None) is current:
                stack.enter_context(patch.object(module, "iface_slug", _slug_version_1))
        yield


def load_golden(*, namespace: bool = True, iface_uid: bool = True) -> dict[str, Any]:
    """`vyos_golden.json`, with `vyos_namespace_golden.json` and then
    `vyos_iface_uid_golden.json` laid over it.

    The first overlay holds the `normalize` digest of every case whose router
    has a uid namespace other than its configured hostname: there the
    device-local uids are `vyos:<namespace>:`.
    Each digest is `batch_digest(base_shape(batch))` of the load with the
    interface uids as version 1 wrote them (`iface_uid_version_1`).
    tests/test_vyos_namespace_golden.py holds each of these digests to the
    one without the overlay (`namespace=False`) once the uids are keyed by
    the hostname (`hostname_keyed`).

    The second holds the `normalize` digest of every case with a subinterface:
    its Interface and Port uids keep the '.' of the name. Each digest
    is `batch_digest(base_shape(batch))` of the load as it is.
    tests/test_vyos_iface_uid_golden.py holds each of these digests to the one
    without the overlay (`iface_uid=False`) when the same answers load under
    version 1 uids (`iface_uid_version_1`). It is recorded over the first, so the first can be left
    out only together with it."""
    if not namespace and iface_uid:
        raise ValueError("the interface uid overlay is recorded over the namespace overlay; leave out both")
    golden: dict[str, Any] = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    paths = [NAMESPACE_GOLDEN_PATH] if namespace else []
    if iface_uid:
        paths.append(IFACE_UID_GOLDEN_PATH)
    for path in paths:
        overlay: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        for key, fields in overlay["cases"].items():
            golden["cases"][key].update(fields)
    return golden


# --- deterministic generator ---------------------------------------------------------------

_MASK64 = (1 << 64) - 1


class _Rng:
    """splitmix64 on a seed derived from `stream`, so every scale draws the
    same values on every Python version."""

    def __init__(self, stream: str) -> None:
        digest = hashlib.sha256(f"vyos:{stream}".encode()).digest()
        self._state = int.from_bytes(digest[:8], "big")

    def draw(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & _MASK64
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
        return z ^ (z >> 31)

    def below(self, bound: int) -> int:
        return self.draw() % bound


def _ip4(value: int) -> str:
    return f"{value >> 24}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}"


def _dump(value: Any) -> str:
    """JSON the way vtysh prints it: two-space indentation and a final newline."""
    return json.dumps(value, indent=2) + "\n"


HOST_NAME = "edge-vyos"
VERSION_TEXT = (
    "Version:          VyOS 1.5-rolling-202607150020\n"
    "Release train:    current\n"
    "Built by:         autobuild@vyos.net\n"
    "Hardware vendor:  QEMU\n"
    "Hardware model:   Standard PC (Q35 + ICH9, 2009)\n"
    "Hardware S/N:     SYNTH0001\n"
    "Uptime:           12 days, 3:04:05\n"
)
LOCAL_AS = "65000"
ROUTER_ID = "203.0.113.2"
RED_TABLE = 300
POLICY_TABLES = (100, 200)
# (vrf, address, remote-as, hostname)
PEERS = (
    ("default", "192.0.2.1", "65001", "peer-a"),
    ("RED", "198.51.100.9", "65002", "peer-b"),
)
NO_SOFT_RECONFIG = "% Inbound soft-reconfiguration is not configured for this neighbor\n"

_PROTOCOLS = ("bgp",) * 14 + ("ospf", "ospf", "static", "kernel", "connected", "isis")
_UPTIMES = ("00:10:00", "1d02h03m", "2w3d04h", "5w6d01h")
_ORIGINS = ("IGP", "IGP", "IGP", "incomplete", "EGP")


def _synthetic_config() -> dict[str, Any]:
    peer_a, peer_b = PEERS
    return {
        "system": {"host-name": HOST_NAME},
        "interfaces": {
            "ethernet": {
                "eth0": {"address": ["203.0.113.2/30"], "description": "uplink"},
                "eth1": {"address": ["10.10.0.1/24", "2001:db8:10::1/64"], "description": "core"},
                "eth2": {"address": ["10.20.0.1/24"], "vrf": "RED", "description": "red"},
                "eth3": {"address": ["10.30.0.1/24", "2001:db8:30::1/64"], "description": "policy"},
            },
            # No source-address: the carrier address is derived from the main
            # table's route toward the endpoint (`_carrier_egress_interface`).
            "wireguard": {
                "wg0": {
                    "address": ["10.99.0.1/24"],
                    "peer": {
                        "remote": {"address": "198.18.7.7", "port": "51820", "allowed-ips": ["10.99.0.2/32"]}
                    },
                }
            },
        },
        "vrf": {
            "name": {
                "RED": {
                    "table": str(RED_TABLE),
                    "protocols": {
                        "bgp": {
                            "system-as": LOCAL_AS,
                            "neighbor": {
                                peer_b[1]: {"remote-as": peer_b[2], "address-family": {"ipv4-unicast": {}}}
                            },
                        }
                    },
                }
            }
        },
        "protocols": {
            "static": {
                "route": {"10.40.0.0/16": {"next-hop": {"10.10.0.254": {}}}},
                "route6": {"2001:db8:40::/48": {"next-hop": {"2001:db8:10::fe": {}}}},
                "table": {
                    str(number): {
                        "route": {"0.0.0.0/0": {"next-hop": {f"10.30.0.{2 + index}": {}}}},
                        "route6": {"::/0": {"interface": {"eth3": {}}}},
                    }
                    for index, number in enumerate(POLICY_TABLES)
                },
            },
            "bgp": {
                "system-as": LOCAL_AS,
                "parameters": {"router-id": ROUTER_ID},
                "neighbor": {
                    peer_a[1]: {"remote-as": peer_a[2], "address-family": {"ipv4-unicast": {}}},
                    # symbolic remote-as: no BgpSession node, so no path read either
                    "192.0.2.99": {"remote-as": "external"},
                },
            },
        },
    }


def _hop(
    ip: str | None = None,
    ifname: str | None = None,
    *,
    index: int = 2,
    fib: bool = True,
    active: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    """One FRR nexthop object. FRR prints `fib` only when it is true."""
    hop: dict[str, Any] = {"flags": 3 if fib else 1}
    if fib:
        hop["fib"] = True
    if ip is not None:
        hop["ip"] = ip
        hop["afi"] = "ipv6" if ":" in ip else "ipv4"
    if ifname is not None:
        hop["interfaceIndex"] = index
        hop["interfaceName"] = ifname
    if active:
        hop["active"] = True
    hop.update(extra)
    hop["weight"] = 1
    return hop


def _frr_route(
    prefix: str,
    hops: list[dict[str, Any]],
    *,
    protocol: str,
    table: int | None,
    vrf: str,
    metric: int | None = 0,
    installed: bool = True,
    selected: bool = True,
    uptime: str = "1d02h03m",
    group: int = 1,
) -> dict[str, Any]:
    """One route object of `show ip route ... json`: the fields FRR prints, in
    its order, `installed`/`selected` left out when false, as FRR does."""
    route: dict[str, Any] = {
        "prefix": prefix,
        "prefixLen": int(prefix.rsplit("/", 1)[1]),
        "protocol": protocol,
        "vrfId": 0 if vrf == "default" else 7,
        "vrfName": vrf,
    }
    if selected:
        route["selected"] = True
        route["destSelected"] = True
    route["distance"] = {"bgp": 20, "ospf": 110, "static": 1, "isis": 115}.get(protocol, 0)
    if metric is not None:
        route["metric"] = metric
    if installed:
        route["installed"] = True
    if table is not None:
        route["table"] = table
    route["internalStatus"] = 16
    route["internalFlags"] = 8
    route["internalNextHopNum"] = len(hops)
    route["internalNextHopActiveNum"] = sum(1 for hop in hops if hop.get("active"))
    route["nexthopGroupId"] = group
    route["installedNexthopGroupId"] = group
    route["uptime"] = uptime
    route["nexthops"] = hops
    return route


def _v4_rib(count: int, rng: _Rng) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """`show ip route vrf all json` with `count` prefixes: fixed routes that
    reach every filter and fold `_rib_entries` and `_learned_routes` apply,
    then generated /24s, one in twenty of them in VRF RED."""
    default: dict[str, list[dict[str, Any]]] = {}
    red: dict[str, list[dict[str, Any]]] = {}

    def put(listing: dict[str, list[dict[str, Any]]], prefix: str, *routes: dict[str, Any]) -> None:
        listing.setdefault(prefix, []).extend(routes)

    main = {"table": 254, "vrf": "default"}
    put(
        default,
        "0.0.0.0/0",
        _frr_route("0.0.0.0/0", [_hop("203.0.113.1", "eth0")], protocol="kernel", **main),
    )
    put(
        default,
        "10.10.0.0/24",
        _frr_route(
            "10.10.0.0/24", [_hop(None, "eth1", directlyConnected=True)], protocol="connected", **main
        ),
    )
    put(default, "10.10.0.1/32", _frr_route("10.10.0.1/32", [_hop(None, "eth1")], protocol="local", **main))
    # the config's static route, installed: folded onto its STATIC_ROUTE edge
    put(
        default,
        "10.40.0.0/16",
        _frr_route("10.40.0.0/16", [_hop("10.10.0.254", "eth1")], protocol="static", **main),
    )
    # a discard route: neither a next hop nor an interface
    put(
        default,
        "10.66.0.0/16",
        _frr_route(
            "10.66.0.0/16", [_hop(None, None, unreachable=True, blackhole=True)], protocol="static", **main
        ),
    )
    # leaked from RED: the nexthop names the VRF it resolves in
    put(
        default,
        "10.20.0.0/24",
        _frr_route("10.20.0.0/24", [_hop(None, "eth2", vrf="RED")], protocol="static", **main),
    )
    # a worse admin distance: in the RIB, neither installed nor selected
    put(
        default,
        "10.67.0.0/16",
        _frr_route(
            "10.67.0.0/16",
            [_hop("10.10.0.9", "eth1", fib=False)],
            protocol="ospf",
            installed=False,
            selected=False,
            **main,
        ),
    )
    # a recursive nexthop listed beside what it resolved to
    put(
        default,
        "10.68.0.0/16",
        _frr_route(
            "10.68.0.0/16",
            [_hop("10.200.0.1", None, fib=False, recursive=True), _hop("10.10.0.2", "eth1", resolver=True)],
            protocol="bgp",
            **main,
        ),
    )
    # no nexthop in the FIB set: the active ones stand in
    put(
        default,
        "10.69.0.0/16",
        _frr_route("10.69.0.0/16", [_hop("10.10.0.3", "eth1", fib=False)], protocol="bgp", **main),
    )
    # keys `ip_network` rejects, a key it rewrites, and a v6 key in the v4 answer
    put(
        default,
        "10.70.1.1/24",
        _frr_route("10.70.1.1/24", [_hop("10.10.0.4", "eth1")], protocol="bgp", **main),
    )
    put(
        default,
        "010.71.0.0/16",
        _frr_route("010.71.0.0/16", [_hop("10.10.0.4", "eth1")], protocol="bgp", **main),
    )
    put(
        default, "10.0.0.0/08", _frr_route("10.0.0.0/08", [_hop("10.10.0.4", "eth1")], protocol="bgp", **main)
    )
    put(
        default,
        "2001:db8:70::/48",
        _frr_route("2001:db8:70::/48", [_hop("10.10.0.4", "eth1")], protocol="bgp", **main),
    )
    # the kernel's legacy table and a route with no table at all
    put(
        default,
        "10.72.0.0/16",
        _frr_route("10.72.0.0/16", [_hop("10.10.0.5", "eth1")], protocol="kernel", table=253, vrf="default"),
    )
    put(
        default,
        "10.73.0.0/16",
        _frr_route("10.73.0.0/16", [_hop("10.10.0.5", "eth1")], protocol="kernel", table=None, vrf="default"),
    )
    red_table = {"table": RED_TABLE, "vrf": "RED"}
    put(
        red,
        "10.20.0.0/24",
        _frr_route("10.20.0.0/24", [_hop(None, "eth2", index=4)], protocol="connected", **red_table),
    )
    put(
        red,
        "0.0.0.0/0",
        _frr_route("0.0.0.0/0", [_hop("10.20.0.254", "eth2", index=4)], protocol="static", **red_table),
    )

    fixed = len(default) + len(red)
    base = 0x64400000  # 100.64.0.0
    for index in range(max(0, count - fixed)):
        prefix = f"{_ip4(base + index * 256)}/24"
        roll = rng.below(100)
        protocol = _PROTOCOLS[rng.below(len(_PROTOCOLS))]
        uptime = _UPTIMES[rng.below(len(_UPTIMES))]
        metric = (0, 0, 0, 10, 20, 100, 4096, 70000)[rng.below(8)]
        in_red = index % 20 == 7
        listing, where, ifname = (red, red_table, "eth2") if in_red else (default, main, "eth1")
        gateway = f"10.{20 if in_red else 10}.0.{2 + rng.below(4)}"
        if roll < 10:
            hops = [_hop(gateway, ifname), _hop(f"10.{20 if in_red else 10}.0.9", ifname)]
        elif roll < 14:
            hops = [
                _hop(f"172.31.{rng.below(256)}.1", None, fib=False, recursive=True),
                _hop(gateway, ifname),
            ]
        else:
            hops = [_hop(gateway, ifname)]
        routes = [
            _frr_route(
                prefix,
                hops,
                protocol=protocol,
                metric=metric,
                uptime=uptime,
                group=10 + index % 50,
                installed=roll != 99,
                selected=roll != 99,
                **where,
            )
        ]
        if roll in (97, 98):
            # a worse candidate for the same prefix, sitting uninstalled
            routes.append(
                _frr_route(
                    prefix,
                    [_hop(gateway, ifname, fib=False)],
                    protocol="ospf",
                    metric=20,
                    installed=False,
                    selected=False,
                    **where,
                )
            )
        put(listing, prefix, *routes)
    return {"default": default, "RED": red}


def _v6_rib(count: int, rng: _Rng) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """`show ipv6 route vrf all json` with `count` prefixes, the IPv6 twin of
    `_v4_rib`, next hops on link-local addresses."""
    default: dict[str, list[dict[str, Any]]] = {}
    main = {"table": 254, "vrf": "default"}
    default["::/0"] = [_frr_route("::/0", [_hop("fe80::1", "eth0")], protocol="kernel", **main)]
    default["2001:db8:10::/64"] = [
        _frr_route(
            "2001:db8:10::/64", [_hop(None, "eth1", directlyConnected=True)], protocol="connected", **main
        ),
        # the kernel's SLAAC copy: installed, never selected
        _frr_route("2001:db8:10::/64", [_hop(None, "eth1")], protocol="kernel", selected=False, **main),
    ]
    default["2001:db8:10::1/128"] = [
        _frr_route("2001:db8:10::1/128", [_hop(None, "eth1")], protocol="local", **main)
    ]
    default["2001:db8:40::/48"] = [
        _frr_route("2001:db8:40::/48", [_hop("2001:db8:10::fe", "eth1")], protocol="static", **main)
    ]
    # written the way `ipaddress` does not: the row carries its canonical form
    default["2001:DB8:FFFF::/48"] = [
        _frr_route("2001:DB8:FFFF::/48", [_hop("fe80::2", "eth1")], protocol="bgp", **main)
    ]
    default["10.74.0.0/16"] = [_frr_route("10.74.0.0/16", [_hop("fe80::2", "eth1")], protocol="bgp", **main)]
    red: dict[str, list[dict[str, Any]]] = {}
    red_table = {"table": RED_TABLE, "vrf": "RED"}
    fixed = len(default)
    for index in range(max(0, count - fixed)):
        prefix = f"2001:db8:{0x1000 + index // 256:x}:{index % 256:x}00::/56"
        roll = rng.below(100)
        in_red = index % 20 == 11
        listing, where, ifname = (red, red_table, "eth2") if in_red else (default, main, "eth1")
        gateway = f"fe80::{1 + rng.below(4):x}"
        hops = [_hop(gateway, ifname)]
        if roll < 8:
            hops.append(_hop(f"fe80::{10 + rng.below(4):x}", ifname))
        listing[prefix] = [
            _frr_route(
                prefix,
                hops,
                protocol=_PROTOCOLS[rng.below(len(_PROTOCOLS))],
                metric=(0, 0, 20, 100, 1024)[rng.below(5)],
                uptime=_UPTIMES[rng.below(len(_UPTIMES))],
                group=200 + index % 50,
                **where,
            )
        ]
    return {"default": default, "RED": red}


def _policy_table(number: int, af: int, rng: _Rng) -> dict[str, list[dict[str, Any]]]:
    """`show ip[v6] route table <number> json`: the table's own default route,
    which the config declares, and a handful of learned routes."""
    where = {"table": number, "vrf": "default"}
    listing: dict[str, list[dict[str, Any]]] = {}
    if af == 4:
        gateway = f"10.30.0.{2 + POLICY_TABLES.index(number)}"
        listing["0.0.0.0/0"] = [
            _frr_route("0.0.0.0/0", [_hop(gateway, "eth3", index=5)], protocol="static", **where)
        ]
        for index in range(12):
            prefix = f"10.{100 + POLICY_TABLES.index(number)}.{index}.0/24"
            listing[prefix] = [
                _frr_route(
                    prefix, [_hop(gateway, "eth3", index=5)], protocol="bgp", metric=rng.below(200), **where
                )
            ]
    else:
        listing["::/0"] = [_frr_route("::/0", [_hop(None, "eth3", index=5)], protocol="static", **where)]
        for index in range(6):
            prefix = f"2001:db8:{0x100 + number:x}:{index:x}::/64"
            listing[prefix] = [
                _frr_route(
                    prefix,
                    [_hop("fe80::30", "eth3", index=5)],
                    protocol="bgp",
                    metric=rng.below(200),
                    **where,
                )
            ]
    return listing


def _summary(paths: int) -> dict[str, Any]:
    """`show bgp vrf all summary json` for `PEERS`."""
    out: dict[str, Any] = {}
    for index, (vrf, address, remote_as, hostname) in enumerate(PEERS):
        out[vrf] = {
            "ipv4Unicast": {
                "routerId": ROUTER_ID,
                "as": int(LOCAL_AS),
                "vrfId": 0 if vrf == "default" else 7,
                "vrfName": vrf,
                "tableVersion": 4 * paths,
                "ribCount": 2 * paths,
                "peerCount": 1,
                "peers": {
                    address: {
                        "hostname": hostname,
                        "remoteAs": int(remote_as),
                        "localAs": int(LOCAL_AS),
                        "version": 4,
                        "msgRcvd": 10_000 + index,
                        "msgSent": 9_000 + index,
                        "tableVersion": 0,
                        "outq": 0,
                        "inq": 0,
                        "peerUptime": "01w2d03h",
                        "peerUptimeMsec": 788_400_000,
                        "peerUptimeEstablishedEpoch": 1_699_211_600,
                        "pfxRcd": paths,
                        "pfxSnt": paths,
                        "state": "Established",
                        "peerState": "OK",
                        "connectionsEstablished": 1,
                        "connectionsDropped": 0,
                        "idType": "ipv4",
                    }
                },
                "failedPeers": 0,
                "displayedPeers": 1,
                "totalPeers": 1,
                "dynamicPeers": 0,
            }
        }
    return out


def _path(
    prefix: str, peer: tuple[str, str, str, str], direction: str, rng: _Rng, *, best: bool
) -> dict[str, Any]:
    """One path object of a per-neighbor route table, with the attributes
    `parse_bgp_paths` reads and the ones FRR prints beside them."""
    _vrf, address, remote_as, hostname = peer
    hops = 1 + rng.below(3)
    as_path = (
        ""
        if direction == "advertised"
        else " ".join([remote_as, *(str(64_600 + rng.below(300)) for _ in range(hops))])
    )
    path: dict[str, Any] = {
        "valid": True,
        "bestpath": best,
        "selectionReason": "First path received" if best else "Older Path",
        "pathFrom": "external",
        "prefix": prefix.split("/")[0],
        "prefixLen": int(prefix.split("/")[1]),
        "network": prefix,
        "version": 1 + rng.below(1000),
    }
    roll = rng.below(20)
    if roll < 12:
        path["metric"] = (0, 10, 100, 4_294_967_295)[rng.below(4)]
    path["locPrf"] = "150" if roll == 13 else (100, 100, 200)[rng.below(3)]
    path["weight"] = 0
    path["peerId"] = address if direction != "advertised" else "(unspec)"
    path["path"] = as_path
    path["origin"] = _ORIGINS[rng.below(len(_ORIGINS))]
    path["aspath"] = {"string": as_path, "segments": [], "length": len(as_path.split())}
    if roll < 6:
        path["communityList"] = [f"{LOCAL_AS}:{100 + rng.below(50)}" for _ in range(1 + rng.below(3))]
    elif roll == 6:
        path["communityList"] = f"{LOCAL_AS}:999 no-export"
    if direction == "advertised":
        path["nexthops"] = [{"ip": ROUTER_ID, "hostname": HOST_NAME, "afi": "ipv4", "used": True}]
    elif roll == 7:
        # a global and a link-local nexthop, the second one used
        path["nexthops"] = [
            {"ip": address, "hostname": hostname, "afi": "ipv4"},
            {"ip": "10.10.0.77", "hostname": hostname, "afi": "ipv4", "used": True},
        ]
    else:
        path["nexthops"] = [{"ip": address, "hostname": hostname, "afi": "ipv4", "used": True}]
    return path


def _path_table(peer: tuple[str, str, str, str], direction: str, rows: int, rng: _Rng) -> dict[str, Any]:
    """`show bgp [vrf X] neighbors <peer> received-routes|routes|
    advertised-routes json` with `rows` path records: one prefix in ten holds
    two paths, and two entries `parse_bgp_paths` skips (a prefix whose value
    is not a list, a path that is not an object)."""
    key = {"received": "receivedRoutes", "accepted": "routes", "advertised": "advertisedRoutes"}[direction]
    base = 0xAC100000 if peer is PEERS[0] else 0xAC400000  # 172.16.0.0, 172.64.0.0
    table: dict[str, Any] = {}
    written = 0
    index = 0
    while written < rows:
        prefix = f"{_ip4(base + index * 256)}/24"
        index += 1
        count = 2 if rng.below(10) == 3 and rows - written >= 2 else 1
        table[prefix] = [
            _path(prefix, peer, direction, rng, best=path_index == 0) for path_index in range(count)
        ]
        written += count
    table["192.0.2.128/25"] = {"valid": True, "note": "not a list of paths"}
    table["192.0.2.0/25"] = ["not a path object"]
    return {
        "bgpTableVersion": 3 * rows,
        "bgpLocalRouterId": ROUTER_ID,
        "defaultLocPrf": 100,
        "localAS": int(LOCAL_AS),
        key: table,
        "totalPrefixCounter": index,
        "filteredPrefixCounter": 0,
    }


def _synthetic_answers(*, routes: int, paths: int) -> Answers:
    from hst.collectors import vyos

    rng = _Rng(f"answers:{routes}:{paths}")
    cfg = _synthetic_config()
    commands = vyos.READ_COMMANDS
    built: Answers = {
        commands["config"]: _dump(cfg),
        commands["version"]: VERSION_TEXT,
        commands["links"]: json.dumps(
            [
                {
                    "ifindex": i + 1,
                    "ifname": name,
                    "mtu": 1500,
                    "address": f"52:54:00:00:00:{i:02x}",
                    "link_type": "ether",
                }
                for i, name in enumerate(("eth0", "eth1", "eth2", "eth3"))
            ]
        ),
        commands["addrs"]: json.dumps(
            [
                {
                    "ifname": "eth0",
                    "addr_info": [
                        {"family": "inet", "local": "203.0.113.2", "prefixlen": 30, "scope": "global"}
                    ],
                }
            ]
        ),
        commands[
            "link_speeds"
        ]: "eth0 10000 full\neth1 1000 full\neth2 1000 full\neth3 -1 unknown\nlo unknown unknown\n",
        commands["routes"]: _dump(_v4_rib(routes, rng)),
        commands["routes6"]: _dump(_v6_rib(routes, rng)),
    }
    for number in POLICY_TABLES:
        built[policy_table_command("ip", number)] = _dump(_policy_table(number, 4, rng))
    for number in POLICY_TABLES:
        built[policy_table_command("ipv6", number)] = _dump(_policy_table(number, 6, rng))
    built[vyos.BGP_SUMMARY_COMMAND] = _dump(_summary(paths))
    for peer in PEERS:
        for direction in vyos.BGP_DIRECTION_KEYWORDS:
            command = vyos.legacy_bgp_route_command(peer[0], peer[1], direction)
            built[command] = _dump(_path_table(peer, direction, paths, rng))
    return built


def _fixture_answers() -> Answers:
    """The answers a box configured and answering as `tests/test_vyos.py`'s
    fixtures describe gives a `capture_bgp="all"` fetch."""
    from hst.collectors import vyos

    t = importlib.import_module("tests.test_vyos")
    cfg = copy.deepcopy(t.CONFIG)
    bgp = copy.deepcopy(t.BGP_CONFIG)
    cfg["protocols"]["bgp"] = bgp["protocols"]["bgp"]
    cfg["policy"].update(bgp["policy"])
    route, nh = t._route, t._nh
    routes = {
        "default": {
            **route("0.0.0.0/0", nh(ip="203.0.113.1", dev="eth0"), protocol="kernel"),
            **route("192.168.1.0/24", nh(dev="eth1", directlyConnected=True), protocol="connected"),
            **route("192.168.1.1/32", nh(dev="eth1"), protocol="local"),
            **route("10.99.0.0/24", nh(ip="192.168.1.2", dev="eth1"), protocol="static"),
            **route("10.80.0.0/24", nh(ip="192.168.1.10", dev="eth1"), protocol="bgp", metric=0),
            **route(
                "10.81.0.0/24",
                nh(ip="192.168.1.10", dev="eth1"),
                nh(ip="192.168.1.11", dev="eth1"),
                protocol="bgp",
            ),
            **route("10.82.0.0/24", nh(ip="192.168.1.12", dev="eth1"), protocol="bgp", installed=False),
        }
    }
    routes6 = {
        "default": {
            **route("::/0", nh(ip="fe80::1", dev="eth0"), protocol="kernel"),
            **route("fd00:1234::/64", nh(dev="eth1", directlyConnected=True), protocol="connected"),
            **route("2001:db8:abcd::/64", nh(dev="eth1", directlyConnected=True), protocol="connected"),
        }
    }
    table_100 = route("0.0.0.0/0", nh(dev="wg0"), nh(dev="wg1"), protocol="static", table=100)
    commands = vyos.READ_COMMANDS
    built: Answers = {
        commands["config"]: json.dumps(cfg),
        commands["version"]: t.VERSION,
        commands["links"]: json.dumps(t.LINKS),
        commands["addrs"]: json.dumps(t.ADDRS),
        commands["link_speeds"]: t.LINK_SPEEDS_TEXT,
        commands["routes"]: json.dumps(routes),
        commands["routes6"]: json.dumps(routes6),
        policy_table_command("ip", 100): json.dumps(table_100),
        policy_table_command("ipv6", 100): "{}",
    }
    built.update(base_spelled(t._bgp_capture_raw()))
    return built


def _apply_variant(built: Answers, variant: str) -> Answers:
    """`built` with the one change `variant` names (`VARIANTS`)."""
    from hst.collectors import vyos

    if variant == "plain":
        return built
    out = dict(built)
    cfg = json.loads(str(built[vyos.READ_COMMANDS["config"]]))
    first_table = int(next(iter(cfg["protocols"]["static"]["table"])))
    targets = vyos.bgp_capture_targets(cfg)
    first, last = targets[0], targets[-1]

    def truncated(command: str) -> str:
        text = str(out[command])
        return text[: max(1, len(text) // 2)]

    if variant == "malformed_rib":
        out[vyos.READ_COMMANDS["routes6"]] = truncated(vyos.READ_COMMANDS["routes6"])
    elif variant == "malformed_table":
        command = policy_table_command("ip", first_table)
        out[command] = truncated(command)
    elif variant == "percent_bgp":
        out[vyos.legacy_bgp_route_command(*first, "received")] = NO_SOFT_RECONFIG
    elif variant == "empty_bgp":
        out[vyos.legacy_bgp_route_command(*last, "advertised")] = ""
    elif variant == "refused":
        table = policy_table_command("ipv6", first_table)
        out[table] = Refusal(f"{table!r} rejected by device: % Unknown command")
        accepted = vyos.legacy_bgp_route_command(*last, "accepted")
        out[accepted] = Refusal(f"{accepted!r} exited 1: Permission denied")
    else:
        raise ValueError(f"unknown variant {variant!r}")
    return out
