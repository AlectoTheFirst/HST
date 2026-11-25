"""Deterministic IOS-XE, IOS-XR and NX-OS payloads, and the digests the
streaming-parity tests compare them by.

The payloads here are the inputs those tests share. `stream_golden.json`
beside this module, the base record, holds the recorded values of each case
(`gen_stream_golden.py` documents its fields). The other golden files are
overlays that `load_golden` lays over the base record. `parser2_golden.json`
holds the fields of the IOS-XE and IOS-XR cases their column-position BGP path
reader changes. `acl_golden.json` and `port_description_golden.json` hold the
`inter` digest of the cases the ACL and the port description parse alter. A
parity test holds what the working tree computes from a payload to the
recorded value.

A case is named `<family>/<scale>/<variant>` (`CASES`):

- scale `fixture` is the family test module's own `RAW`, unchanged;
- `small`, `medium` and `tenth` (`SCALES`) are built on that `RAW`: every
  command is copied except the routing table, the BGP running-config and the
  BGP observation commands, which are replaced by synthetic ones of the stated
  size;
- variant `plain` is the payload as built, `no_trailing_newline` drops the
  final newline of every answer, and `unicode` puts a non-Latin-1 character and
  U+2028 into free-text fields (`_unicode`).

Every text is what the SSH transport hands a parser: '\\n' line ends and no
control bytes. The generator is integer arithmetic on a fixed seed (`_Rng`), so
a payload is byte-for-byte the same on every Python version, and
`payload_sha` in the golden file pins it.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from itertools import groupby
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple
from unittest.mock import patch

from hst.core.uid import slug

if TYPE_CHECKING:
    from hst.collectors.cli_collector import CiscoCliCollector
    from hst.core import Settings

GOLDEN_PATH = Path(__file__).with_name("stream_golden.json")
PARSER2_GOLDEN_PATH = Path(__file__).with_name("parser2_golden.json")
PORT_DESCRIPTION_GOLDEN_PATH = Path(__file__).with_name("port_description_golden.json")
ACL_GOLDEN_PATH = Path(__file__).with_name("acl_golden.json")
IFNAME_GOLDEN_PATH = Path(__file__).with_name("ifname_golden.json")
RPL_PASS_GOLDEN_PATH = Path(__file__).with_name("rpl_pass_golden.json")
ROUTE_SESSION_GOLDEN_PATH = Path(__file__).with_name("route_session_golden.json")

FAMILIES: tuple[str, ...] = ("iosxe", "iosxr", "nxos")
VARIANTS: tuple[str, ...] = ("plain", "no_trailing_newline", "unicode")

# Keyword arguments of the family builders per synthetic scale. `paths` is the
# number of path lines in each full direction's table; `tenth` keeps every
# received table (both peers retain it) and advertises a small table, which is
# the shape of a full-feed edge router at a tenth of its size.
SCALES: dict[str, dict[str, Any]] = {
    "small": {"routes": 2_000, "peers": 2, "paths": 2_000},
    "medium": {"routes": 20_000, "peers": 2, "paths": 20_000},
    "tenth": {"routes": 100_000, "peers": 2, "paths": 100_000, "advertised": 1_000, "denied_received": False},
}

CASES: tuple[str, ...] = (
    *(
        f"{family}/{scale}/{variant}"
        for family in FAMILIES
        for scale in ("fixture", "small", "medium")
        for variant in VARIANTS
    ),
    "iosxe/tenth/plain",
)

# The side-store identity every golden parquet digest was written under.
RUN_ID = "1700000000000-aaaaaaaa"
SNAPSHOT_TS = 1_700_000_000_000
ROW_GROUP_ROWS = 4096

# The per-device configuration every golden hash was computed with
# (`make_collector`). `raw_sha` covers site, routing scope and L2 fabric, so a
# test that builds its collector any other way compares different hashes.
COLLECTOR_HOST = "edge1.example.net"
COLLECTOR_SOURCE = "edge"
COLLECTOR_SITE = "hq"
COLLECTOR_ROUTING_SCOPE = "corp"

# The `unicode` variant's free text: a Latin-1 letter, two characters beyond
# Latin-1 (U+2603, U+03A9), and U+2028, which `str.splitlines` and therefore
# TextFSM read as a line break while `split("\n")` does not.
UNICODE_TEXT = "Z\u00fcrich \u2603 \u03a9 uplink"
LINE_SEPARATOR = "\u2028"


def case_key(family: str, scale: str, variant: str) -> str:
    return f"{family}/{scale}/{variant}"


def split_case(key: str) -> tuple[str, str, str]:
    """(family, scale, variant) of a case key."""
    family, scale, variant = key.split("/")
    return family, scale, variant


def case_payload(key: str) -> dict[str, Any]:
    """The payload of one golden case, built fresh on every call."""
    family, scale, variant = split_case(key)
    if scale == "fixture":
        return _apply_variant(family, dict(fixture_raw(family)), variant)
    return _BUILDERS[family](**SCALES[scale], variant=variant)


# The neighbor detail commands a collector reads beside its BGP session table
# (the peer router id), by collector attribute. No golden payload holds them.
NEIGHBOR_COMMANDS_SINCE_BASE: dict[str, tuple[str, ...]] = {
    "iosxe": ("CMD_BGP_NEIGHBORS",),
    "iosxr": ("CMD_BGP_NEIGHBORS", "CMD_BGP_VRF_NEIGHBORS"),
    "nxos": ("CMD_BGP_NEIGHBORS",),
}


def fixture_raw(family: str) -> dict[str, Any]:
    """The family test module's `RAW` less the commands that no golden payload
    holds (`ADDED_SINCE_BASE`, `NEIGHBOR_COMMANDS_SINCE_BASE`, the IOS-XE
    per-VRF ARP commands). The result is a new dict, and the module's `RAW`
    is not mutated.

    The IOS-XE `show vrf` text of `RAW` prints its members abbreviated, as
    the device does. A fixture payload holds the same table with the names in
    full (`tests.test_iosxe.FULL_NAME_VRF_TEXT`), which the golden values were
    computed from."""
    module = importlib.import_module(f"tests.test_{family}")
    added = set(ADDED_SINCE_BASE.get(family, {}).values())
    collector = importlib.import_module(f"hst.collectors.{family}")
    added.update(getattr(collector, name) for name in NEIGHBOR_COMMANDS_SINCE_BASE.get(family, ()))
    # the per-VRF ARP commands IOS-XE derives from `show vrf`
    derived = getattr(collector, "ARP_VRF_KEY_RE", None)
    raw: dict[str, Any] = {
        key: value
        for key, value in module.RAW.items()
        if key not in added and not (derived is not None and derived.fullmatch(key))
    }
    if family == "iosxe":
        return {**raw, module.CMD_VRF: module.FULL_NAME_VRF_TEXT}
    return raw


# digests


def _json_default(value: Any) -> str:
    """Bytes as lowercase hex (the side-store `lo`/`hi` columns), anything else
    JSON cannot render as its `str`."""
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    return str(value)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, default=_json_default).encode()


def rows_digest(rows: Iterable[Mapping[str, Any]]) -> tuple[int, str]:
    """(row count, SHA-256 hex) of `rows` in iteration order.

    The digest covers the newline-joined canonical JSON of each row, so it
    changes with row order, which the side store preserves. Rows are read one
    at a time; a lazy view is never materialized.
    """
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        if count:
            digest.update(b"\n")
        digest.update(_canonical(row if isinstance(row, dict) else dict(row)))
        count += 1
    return count, digest.hexdigest()


def without_rpl_passes(inter: Mapping[str, Any]) -> dict[str, Any]:
    """An IOS-XR parse with every route-policy entry's `passes` taken out, the
    shape without the `pass` statements."""
    policies = inter.get("xr_route_policies")
    if not policies:
        return dict(inter)
    return {
        **inter,
        "xr_route_policies": [
            {**p, "entries": [{k: v for k, v in e.items() if k != "passes"} for e in p["entries"]]}
            for p in policies
        ],
    }


# The side-store RIB columns of the discard routes and the next-hop VRF.
ROUTE_SESSION_RIB_COLUMNS: tuple[str, ...] = ("discard", "next_hop_context_uid")


@contextlib.contextmanager
def route_session_change_taken_out() -> Iterator[None]:
    """Run the Cisco parse and side rows without the RIB and BGP session
    changes, so a digest computed
    inside the block is the one `load_golden(route_session=False)` holds:

    - a RIB row keeps the template's next hop (`connected` included) and
      interface (`vrf <name>` included) and has no `next_hop_vrf`
      (`cisco_common.rib_row`), and a side-store RIB row has no `discard` or
      `next_hop_context_uid` and keeps the row's next hop (`side_rows`);
    - IOS-XR reads no process address-family block and only the
      redistribution protocols `connected`, `static`, `rip` and `ospf`
      (`iosxr_bgp`), and its groups and sessions carry no
      `route_reflector_client`.

    The template rules for a next hop's VRF read no line of a golden
    payload, which holds no leaked route."""
    from hst.collectors import cisco_common, cli_collector, iosxe, iosxr, iosxr_bgp

    rib_row = cisco_common.rib_row
    side_rows = cisco_common.side_rows
    group_body = iosxr_bgp._parse_group_body
    resolve = iosxr_bgp.resolve_bgp_sessions

    def rib_row_before(r: dict[str, Any], **keys: Any) -> dict[str, Any]:
        row = rib_row(r, **keys)
        del row["next_hop_vrf"]
        row["next_hop"] = r.get(keys["next_hop_key"]) or None
        row["interface"] = r.get(keys["interface_key"]) or None
        return row

    def side_rows_before(inter: dict[str, Any], device_uid: str, **kwargs: Any) -> dict[str, Any]:
        tables = side_rows(inter, device_uid, **kwargs)
        rib = [
            {
                **{k: v for k, v in row.items() if k not in ROUTE_SESSION_RIB_COLUMNS},
                "next_hop": r.get("next_hop"),
            }
            for row, r in zip(tables["rib"], inter.get("rib") or [], strict=True)
        ]
        return {**tables, "rib": rib}

    def group_body_before(lines: list[str]) -> dict[str, Any]:
        fields = group_body(lines)
        del fields["route_reflector_client"]
        return fields

    def resolve_before(bgp: dict[str, Any]) -> list[dict[str, Any]]:
        return [{k: v for k, v in s.items() if k != "route_reflector_client"} for s in resolve(bgp)]

    with contextlib.ExitStack() as stack:
        for module in (iosxe, iosxr):
            stack.enter_context(patch.object(module, "rib_row", rib_row_before))
        stack.enter_context(patch.object(cli_collector, "side_rows", side_rows_before))
        stack.enter_context(patch.object(iosxr_bgp, "_parse_group_body", group_body_before))
        stack.enter_context(patch.object(iosxr_bgp, "resolve_bgp_sessions", resolve_before))
        stack.enter_context(patch.object(iosxr_bgp, "_RE_ANY_ADDRESS_FAMILY", re.compile(r"(?!)")))
        stack.enter_context(
            patch.object(
                iosxr_bgp,
                "_RE_REDISTRIBUTE_HDR",
                re.compile(r"^redistribute (connected|static|rip|ospf)\b(.*)$"),
            )
        )
        yield


def inter_digest(inter: Mapping[str, Any]) -> str:
    """SHA-256 hex of a family parse's intermediate shape, in the canonical form
    `rows_digest` uses. `bgp_observed.routes` is read into a list first, so a
    lazy view of the paths digests the same as the list it stands for."""
    body = dict(inter)
    observed = body.get("bgp_observed")
    if isinstance(observed, Mapping) and "routes" in observed:
        body["bgp_observed"] = {**observed, "routes": list(observed["routes"] or [])}
    return hashlib.sha256(_canonical(body)).hexdigest()


def parquet_layout(path: Path | None) -> dict[str, Any] | None:
    """How a side-store parquet file is laid out on disk: the row count of each
    row group in file order, SHA-256 hex of its arrow schema's text, and
    `rows_digest` of its rows read back in file order. None for a table with
    no rows, for which `write_table` writes no file.

    `manifest.sidestore_row_facts` digests the per-row digests in sorted
    order, so the same rows reordered or regrouped keep its digest; this is
    what pins the order and the row-group boundaries.
    """
    if path is None:
        return None
    import pyarrow.parquet as pq

    with pq.ParquetFile(path) as reader:
        metadata = reader.metadata
        groups = [metadata.row_group(index).num_rows for index in range(metadata.num_row_groups)]
        schema = hashlib.sha256(reader.schema_arrow.to_string().encode()).hexdigest()
        _count, rows = rows_digest(
            row for batch in reader.iter_batches(batch_size=8192) for row in batch.to_pylist()
        )
    return {"row_groups": groups, "schema_sha": schema, "rows_sha": rows}


def outcomes_json(outcomes: Mapping[str, Any]) -> dict[str, Any]:
    """Section or table outcomes as the JSON the golden file stores them in."""
    return {name: outcome.model_dump(mode="json") for name, outcome in sorted(outcomes.items())}


# The families whose collector reads no MAC table and states the declared
# `mac` table `not-captured`.
UNREAD_MAC_FAMILIES = frozenset({"iosxe", "iosxr"})


def held_mac_statement(family: str, outcomes: Mapping[str, Any], *, written: bool) -> dict[str, Any]:
    """Table outcomes as the golden files hold them. The IOS-XE or IOS-XR
    `mac` statement (`UNREAD_MAC_FAMILIES`) is taken out of `table_outcomes`,
    which has no `mac` key in the golden files. With `written`, the statement
    is set to the `complete-empty` that the golden `tables` hold."""
    from hst.core.model import TableOutcome

    out = dict(outcomes)
    if family not in UNREAD_MAC_FAMILIES:
        return out
    stated = out.pop("mac")
    if (stated.status, stated.row_count, stated.path) != ("not-captured", None, ""):
        raise AssertionError(f"{family}: the mac table is not stated not-captured: {stated!r}")
    if written:
        out["mac"] = TableOutcome(status="complete-empty", row_count=0)
    return out


def payload_sha(payload: Mapping[str, Any]) -> str:
    """SHA-256 hex of the payload's sorted-key JSON: the generator's fingerprint."""
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def raw_json_sha(payload: Mapping[str, Any]) -> str:
    """SHA-256 hex of the JSON the raw store seals for this payload."""
    return hashlib.sha256(json.dumps(payload, default=str).encode()).hexdigest()


def load_golden(
    *,
    acl: bool = True,
    port_description: bool = True,
    ifname: bool = True,
    rpl_pass: bool | None = None,
    route_session: bool | None = None,
) -> dict[str, Any]:
    """`stream_golden.json` with `parser2_golden.json`, `acl_golden.json`,
    `port_description_golden.json`, `ifname_golden.json`,
    `rpl_pass_golden.json` and `route_session_golden.json` laid over it, in
    that order.

    The first overlay holds, for the IOS-XE and IOS-XR cases, the fields the
    column-position BGP path reader (parser version 2) changes. A field named
    plainly replaces the value of the base record; a dotted one such as
    `side_tables.bgp_session_routes` replaces one table inside the field.
    `gen_stream_golden.parser2_case` computes these fields and refuses any
    other change.

    The second holds the `inter` digest of the IOS-XE and NX-OS cases whose
    parse carries an ACE field the interface ACL parse adds: the short notes
    beside an opaque reason and the ICMP type (`ACL_ACE_FIELDS`). Each digest
    is that of the parse with the interface descriptions taken out, the change
    the overlay after it records. tests/test_cisco_acl_golden.py holds each of
    these digests to the one without the overlay (`acl=False`) once those ACE
    fields are taken out as well.

    The third holds the `inter` digest of the IOS-XE, IOS-XR and NX-OS cases whose
    payload describes an interface: the parse keeps that text as the
    interface's `description`. Its digests are of the whole parse, the ACE
    fields above included. tests/test_port_description.py holds each of
    these digests to the one without the overlay (`port_description=False`)
    once the descriptions are taken out again.

    The fourth holds the `inter` digest of the IOS-XE and IOS-XR cases whose
    neighbor or FHRP rows name an interface: the parse keeps the name as the
    device prints it. Its digests are of the whole parse,
    the ACE fields and descriptions above included.
    tests/test_cisco_ifname_golden.py holds each of these digests to the one
    without the overlay (`ifname=False`) once the names are spelled again.

    The fifth holds the `inter` digest of the IOS-XR cases whose route-policy
    has a `pass` statement: the parse records it as the entry's `passes`,
    which the engine needs to accept a route through a `pass`.
    tests/test_rpl_pass_golden.py holds each of these digests to the one
    without the overlay (`rpl_pass=False`) once `passes` is taken out again
    (`without_rpl_passes`). It is laid exactly when the name overlay is,
    unless `rpl_pass` says otherwise.

    The sixth holds, for every IOS-XE, IOS-XR and NX-OS case, the fields the
    RIB and BGP session changes alter: a RIB row's next-hop VRF and discard
    columns and the IOS-XR `connected` next hop, the IOS-XR
    process address-family origins and its `route_reflector_client`.
    tests/test_route_session_golden.py holds each of these values to
    the one without the overlay (`route_session=False`) when the case runs
    with the change taken out (`route_session_change_taken_out`). It is laid
    exactly when the rpl-pass overlay is, unless `route_session` says
    otherwise.

    Each overlay is recorded over the ones before it, so an overlay can be
    left out only together with every overlay after it."""
    if not acl and port_description:
        raise ValueError("the port-description overlay is recorded over the ACL overlay; leave out both")
    if (not acl or not port_description) and ifname:
        raise ValueError("the name overlay is recorded over the others; leave out all that are left out")
    if rpl_pass is None:
        rpl_pass = ifname
    if not ifname and rpl_pass:
        raise ValueError("the rpl-pass overlay is recorded over the name overlay; leave out both")
    if route_session is None:
        route_session = rpl_pass
    if not rpl_pass and route_session:
        raise ValueError("the route-session overlay is recorded over the rpl-pass overlay; leave out both")
    golden: dict[str, Any] = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    overlays = [PARSER2_GOLDEN_PATH]
    if acl:
        overlays.append(ACL_GOLDEN_PATH)
    if port_description:
        overlays.append(PORT_DESCRIPTION_GOLDEN_PATH)
    if ifname:
        overlays.append(IFNAME_GOLDEN_PATH)
    if rpl_pass:
        overlays.append(RPL_PASS_GOLDEN_PATH)
    if route_session:
        overlays.append(ROUTE_SESSION_GOLDEN_PATH)
    for path in overlays:
        overlay: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        for key, fields in overlay["cases"].items():
            case = golden["cases"][key]
            for field, value in fields.items():
                name, _dot, table = field.partition(".")
                if table:
                    case[name] = {**case[name], table: value}
                else:
                    case[name] = value
    return golden


# The ACE fields the interface ACL parse adds to the intermediate `acl` shape
# (collectors/cisco_common.py documents the ACE shape): the short note
# beside each opaque reason, which the firewall table lists, and the ICMP type an
# ACE names. Each is present only when it holds something, so a parse with
# them taken out has the shape of the digests without the ACL overlay.
ACL_ACE_FIELDS: frozenset[str] = frozenset(
    {"src_opaque_note", "dst_opaque_note", "svc_opaque_note", "qualifier_note", "icmp_type"}
)


def without_acl_ace_fields(inter: Mapping[str, Any]) -> dict[str, Any]:
    """`inter` with the `ACL_ACE_FIELDS` of every ACE taken out. A parse with no
    `acl` key, or one whose ACEs carry none of them, comes back equal."""
    acl = inter.get("acl")
    if not isinstance(acl, Mapping) or not acl.get("lists"):
        return dict(inter)
    lists = {
        name: [{k: v for k, v in ace.items() if k not in ACL_ACE_FIELDS} for ace in aces]
        for name, aces in acl["lists"].items()
    }
    return {**inter, "acl": {**acl, "lists": lists}}


def without_descriptions(inter: Mapping[str, Any]) -> dict[str, Any]:
    """`inter` with the `description` of every interface taken out."""
    return {
        **inter,
        "interfaces": [{k: v for k, v in i.items() if k != "description"} for i in inter["interfaces"]],
    }


def canonical_neighbor_names(family: str, inter: Mapping[str, Any]) -> dict[str, Any]:
    """`inter` with the interface names of its neighbor and FHRP rows spelled as
    netutils spells them."""
    if family not in ("iosxe", "iosxr"):
        return dict(inter)
    from netutils.interface import canonical_interface_name

    body = dict(inter)
    if "neighbors" in body:
        body["neighbors"] = [
            {
                **n,
                "local_port": canonical_interface_name(n["local_port"] or ""),
                "port": canonical_interface_name(n["port"] or ""),
            }
            for n in body["neighbors"]
        ]
    if "fhrp" in body:
        body["fhrp"] = [
            {**row, "interface": canonical_interface_name(row["interface"])} for row in body["fhrp"]
        ]
    return body


# collectors


def make_settings(data_dir: Path, **overrides: Any) -> Settings:
    """Settings for a golden comparison: the data directory the caller owns,
    `ROW_GROUP_ROWS`, and neither a `.env` file nor an L2 fabric declaration
    from the environment, since `raw_sha` covers the fabric."""
    from hst.core import Settings

    values: dict[str, Any] = {
        "_env_file": None,
        "hst_data_dir": data_dir,
        "sidestore_row_group_rows": ROW_GROUP_ROWS,
        "l2_fabrics": {},
        **overrides,
    }
    return Settings(**values)


def make_collector(family: str, settings: Settings | None, *, capture_bgp: str = "all") -> CiscoCliCollector:
    """The family's collector with the fixed per-device configuration every
    golden value was computed with."""
    from pydantic import SecretStr

    from hst.collectors.auth import SshPassword

    module = importlib.import_module(f"hst.collectors.{family}")
    prefix = {"iosxe": "Iosxe", "iosxr": "Iosxr", "nxos": "Nxos"}[family]
    config = getattr(module, f"{prefix}Config")(
        host=COLLECTOR_HOST,
        auth=SshPassword(username="golden", password=SecretStr("golden")),
        site_code=COLLECTOR_SITE,
        routing_scope=COLLECTOR_ROUTING_SCOPE,
        source_name=COLLECTOR_SOURCE,
        capture_bgp=capture_bgp,
    )
    collector: CiscoCliCollector = getattr(module, f"{prefix}Collector")(config, settings)
    collector.identity = BaseRecordUids()
    return collector


class BaseRecordUids:
    """A device identity registry that gives each device the uid the golden
    values were computed with: `dev:<serial>`, or `dev:x:<source>:<ref>` for a
    device without a serial."""

    def resolve_device(self, kind: str, value: str, hostname: str | None) -> str:
        if kind == "serial":
            return f"dev:{slug(value)}"
        source, _, ref = value.rpartition(":")
        return f"dev:x:{slug(source)}:{slug(ref)}"

    def bind_device(self, uid: str, kind: str, value: str) -> None:
        return None

    def identity_generation(self) -> int:
        return 0


# the change-hash declarations of the base record

# The declarations of each family's collector class that every `raw_sha` and
# `obs_sha` of `stream_golden.json` was computed with (`collectors.base.raw_sha`,
# `obs_sha`): the keys the configuration hash leaves out, the keys the
# observation hash covers, and the parser version the configuration hash
# covers.
BASE_VOLATILE_RAW_KEYS: dict[str, tuple[str, ...]] = {
    "iosxe": ("show version", "show ip nat statistics", "show ip arp", "show ip bgp summary"),
    "iosxr": ("show version", "show arp", "show bgp summary"),
    "nxos": (
        "show version | json",
        "show mac address-table | json",
        "show ip arp vrf all | json",
        "show bgp sessions | json",
    ),
}
BASE_OBSERVATION_RAW_KEYS: dict[str, tuple[str, ...]] = {
    "iosxe": ("show ip arp", "show ip route vrf *", "show ip bgp summary"),
    "iosxr": ("show arp", "show route vrf all ipv4", "show bgp summary"),
    "nxos": (
        "show ip arp vrf all | json",
        "show mac address-table | json",
        "show ip route vrf all | json",
        "show bgp sessions | json",
    ),
}
BASE_PARSER_VERSION: dict[str, str] = {"iosxe": "1", "iosxr": "1", "nxos": "3"}
# The same for every family.
BASE_NORMALIZATION_VERSIONS: dict[str, str] = {"mtu": "1", "bgp_dynamic_peers": "1"}


# The commands a family spells differently from the base record, as the
# working tree's spelling mapped to the spelling of the base record. Every
# value of the base record is a value of the payload in that spelling
# (`base_spelling`), and the change hash reads the recorded outcomes of
# `NORMALIZATION_OUTCOME_KEYS` in that spelling too (`base_declarations`).
RESPELLED_SINCE_BASE: dict[str, dict[str, str]] = {
    # IOS-XE has no `detail` keyword after an OSPF database type.
    "iosxe": {
        f"show ip ospf database {lsa}": f"show ip ospf database {lsa} detail"
        for lsa in ("router", "network", "summary", "asbr-summary", "external", "nssa-external")
    },
    # The ARP table of every VRF.
    "iosxr": {"show arp vrf all": "show arp"},
    # The session table and every OSPF read of every VRF.
    "nxos": {
        "show bgp sessions vrf all | json": "show bgp sessions | json",
        "show ip ospf vrf all | json": "show ip ospf | json",
        "show ip ospf interface vrf all | json": "show ip ospf interface | json",
        "show ip ospf neighbors vrf all | json": "show ip ospf neighbors | json",
        **{
            f"show ip ospf database {lsa} detail vrf all | json": f"show ip ospf database {lsa} detail | json"
            for lsa in ("router", "network", "summary", "external", "nssa-external", "asbr-summary")
        },
    },
}


# The sections a family declares that the base record does not hold, by the
# command behind each: the VLAN access map bindings of IOS-XE and NX-OS and the
# interface filter bindings of IOS-XR. No golden payload holds these commands,
# so each such section reads `unknown` on every golden case, and the outcomes
# of the base record are the rest (`without_added_sections`).
ADDED_SINCE_BASE: dict[str, dict[str, str]] = {
    "iosxe": {"vlan_filter": "show running-config | include ^vlan filter"},
    "nxos": {"vlan_filter": 'show running-config | include "^vlan filter"'},
    "iosxr": {
        "interface_config": 'show running-config interface | include "^interface |access-group"',
        # the hostname
        "hostname": "show running-config hostname",
    },
}


def without_added_sections(family: str, outcomes: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """(the outcomes of the sections the base record holds, those of the
    sections `ADDED_SINCE_BASE` names), from one `outcomes_json` mapping."""
    added = ADDED_SINCE_BASE.get(family, {})
    return (
        {name: value for name, value in outcomes.items() if name not in added},
        {name: value for name, value in outcomes.items() if name in added},
    )


def base_spelling(family: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """`payload` with every command of `RESPELLED_SINCE_BASE` in the spelling
    of the base record, its recorded outcome included, each key in its place.
    A payload with none of them comes back equal to itself."""
    from hst.collectors.base import RAW_OUTCOMES_KEY

    names = RESPELLED_SINCE_BASE.get(family, {})
    respelled = {names.get(key, key): value for key, value in payload.items()}
    outcomes = respelled.get(RAW_OUTCOMES_KEY)
    if isinstance(outcomes, Mapping):
        respelled[RAW_OUTCOMES_KEY] = {names.get(key, key): value for key, value in outcomes.items()}
    return respelled


def base_declarations(family: str) -> dict[str, Any]:
    """The collector class attributes `raw_sha` and `obs_sha` read, with the
    values that `stream_golden.json` was computed with for `family`. A class
    given these hashes a golden payload in the spelling of the base record
    (`base_spelling`) to the digests of the base record. They hold no key
    pattern and no normalization inputs."""
    module = importlib.import_module(f"hst.collectors.{family}")
    prefix = {"iosxe": "Iosxe", "iosxr": "Iosxr", "nxos": "Nxos"}[family]
    added = set(ADDED_SINCE_BASE.get(family, {}).values())
    outcome_keys = [
        key for key in getattr(module, f"{prefix}Collector").NORMALIZATION_OUTCOME_KEYS if key not in added
    ]
    names = RESPELLED_SINCE_BASE.get(family, {})
    return {
        "VOLATILE_RAW_KEYS": BASE_VOLATILE_RAW_KEYS[family],
        "OBSERVATION_RAW_KEYS": BASE_OBSERVATION_RAW_KEYS[family],
        "VOLATILE_RAW_KEY_PATTERN": None,
        "OBSERVATION_RAW_KEY_PATTERN": None,
        "PARSER_VERSION": BASE_PARSER_VERSION[family],
        "NORMALIZATION_VERSIONS": dict(BASE_NORMALIZATION_VERSIONS),
        "NORMALIZATION_OUTCOME_KEYS": tuple(names.get(key, key) for key in outcome_keys),
        "normalization_inputs": _no_normalization_inputs,
    }


def _no_normalization_inputs(self: Any) -> None:
    return None


# deterministic generator

_MASK64 = (1 << 64) - 1


class _Rng:
    """splitmix64. The golden file pins the exact payload bytes on each Python
    version the suite runs on."""

    def __init__(self, family: str, seed: int, stream: str) -> None:
        digest = hashlib.sha256(f"{family}:{seed}:{stream}".encode()).digest()
        self._state = int.from_bytes(digest[:8], "big")

    def draw(self) -> int:
        """The next 64-bit value."""
        self._state = (self._state + 0x9E3779B97F4A7C15) & _MASK64
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
        return z ^ (z >> 31)

    def below(self, bound: int) -> int:
        return self.draw() % bound


def _ip(value: int) -> str:
    return f"{value >> 24}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}"


def _collapse(rows: list[dict[str, Any]]) -> dict[str, Any] | list[dict[str, Any]]:
    """NX-OS JSON's one-row collapse: a single `ROW_<table>` is a bare object."""
    return rows[0] if len(rows) == 1 else rows


# One hop of a route: its next hop (None for a connected or local route) and
# its interface, as an uplink key ("u1", "u2"), a subinterface number, or None.
Hop = tuple[str | None, str | int | None]


class _Route(NamedTuple):
    vrf: str
    code: str  # the IOS legend code: C, L, S, S*, O, O IA, O E2 or B
    network: int
    length: int
    hops: tuple[Hop, ...]
    distance: int
    metric: int
    uptime: str


_UPTIMES = ("00:10:00", "1d02h", "2w3d", "5w6d")
_NXOS_UPTIMES = {"00:10:00": "PT10M", "1d02h": "P1DT2H", "2w3d": "P17D", "5w6d": "P41D"}
_IFNAMES: dict[str, dict[str, str]] = {
    "iosxe": {"u1": "GigabitEthernet1/0/1", "u2": "GigabitEthernet1/0/3", "sub": "GigabitEthernet1/0/2.{}"},
    "iosxr": {
        "u1": "GigabitEthernet0/0/0/0",
        "u2": "GigabitEthernet0/0/0/2",
        "sub": "GigabitEthernet0/0/0/9.{}",
    },
    "nxos": {"u1": "Ethernet1/1", "u2": "Ethernet1/3", "sub": "Vlan{}"},
}
# The RIB's VRFs in output order, each with the first address its routes are
# allocated from.
_VRF_POOLS = (("default", 0x0B000000), ("CUST", 0x64400000), ("mgmt", 0x0AC80000))


def _ifname(family: str, key: str | int | None) -> str | None:
    if key is None:
        return None
    names = _IFNAMES[family]
    return names["sub"].format(key) if isinstance(key, int) else names[key]


def _rib(count: int, peer_ips: list[str], rng: _Rng) -> list[_Route]:
    """`count` RIB entries across three VRFs: most in the default VRF, where
    BGP dominates beside OSPF, static and connected/local pairs; about 10% of
    the non-connected entries carry a second, equal-cost hop. Prefixes are
    allocated upward from each VRF's pool, aligned to their own length, so the
    table is sorted and holds no duplicate. The default VRF's BGP routes are
    learned from the first two peers; addresses of no configured peer stand in
    for those a device with fewer neighbors lacks."""
    mgmt = max(1, count // 50)
    cust = max(1, count * 8 // 100)
    sizes = {"default": max(1, count - mgmt - cust), "CUST": cust, "mgmt": mgmt}
    first_hop, second_hop = (*peer_ips[:2], "198.18.255.1", "198.18.255.2")[:2]
    routes: list[_Route] = []
    subif = 100
    for vrf, pointer in _VRF_POOLS:
        target = len(routes) + sizes[vrf]
        if vrf == "default":
            routes.append(_Route(vrf, "S*", 0, 0, (("10.0.0.254", None),), 1, 0, "2w3d"))
        while len(routes) < target:
            kind = _route_kind(vrf, rng.below(100))
            if kind == "pair" and target - len(routes) < 2:
                kind = "S"
            length = _route_length(kind, rng.below(1000))
            size = 1 << (32 - length)
            pointer = -(-pointer // size) * size
            network = pointer
            pointer += size
            uptime = _UPTIMES[rng.below(len(_UPTIMES))]
            if kind == "pair":
                routes.append(_Route(vrf, "C", network, length, ((None, subif),), 0, 0, uptime))
                routes.append(_Route(vrf, "L", network + 1, 32, ((None, subif),), 0, 0, uptime))
                subif += 1
                continue
            hops: tuple[Hop, ...]
            if kind == "S":
                code, distance, metric = "S", 1, 0
                hops = (("10.0.0.254", None), ("10.0.3.254", None))
            elif kind == "O":
                code = ("O", "O", "O IA", "O IA", "O E2")[rng.below(5)]
                distance, metric = 110, 2 + rng.below(199)
                hops = (("10.0.0.2", "u1"), ("10.0.3.2", "u2"))
            elif vrf == "default":
                code, distance = "B", 20
                metric = 0 if rng.below(5) else 10 * (1 + rng.below(50))
                hops = ((first_hop, None), (second_hop, None))
            else:
                pe = 1 + rng.below(8)
                code, distance, metric = "B", 200, 0
                hops = ((f"10.255.0.{pe}", None), (f"10.255.0.{pe + 8}", None))
            ecmp = rng.below(10) == 0
            routes.append(
                _Route(vrf, code, network, length, hops if ecmp else hops[:1], distance, metric, uptime)
            )
    return routes


def _route_kind(vrf: str, roll: int) -> str:
    if vrf == "default":
        return "pair" if roll < 1 else "S" if roll < 3 else "O" if roll < 15 else "B"
    if vrf == "CUST":
        return "pair" if roll < 5 else "S" if roll < 15 else "B"
    return "pair" if roll < 20 else "S"


def _route_length(kind: str, roll: int) -> int:
    if kind == "pair":
        return 24
    if kind == "S":
        return 24 if roll < 700 else 28
    if kind == "O":
        return 24 if roll < 600 else 30 if roll < 800 else 32
    return 16 if roll < 2 else 20 if roll < 12 else 22 if roll < 52 else 23 if roll < 102 else 24


def _by_vrf(rib: list[_Route]) -> Iterator[tuple[str, list[_Route]]]:
    for vrf, group in groupby(rib, key=lambda r: r.vrf):
        yield vrf, list(group)


def _gateway(group: list[_Route]) -> str:
    default = next((r for r in group if r.length == 0), None)
    if default is None:
        return "Gateway of last resort is not set"
    return f"Gateway of last resort is {default.hops[0][0]} to network 0.0.0.0"


_IOSXE_CODES = (
    "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP",
    "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area",
    "       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2",
    "       E1 - OSPF external type 1, E2 - OSPF external type 2",
    "       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2",
    "       ia - IS-IS inter area, * - candidate default, U - per-user static route",
    "       o - ODR, P - periodic downloaded static route, H - NHRP, l - LISP",
    "       a - application route",
    "       + - replicated route, % - next hop override, p - overrides from PfR",
)


def _iosxe_rib(rib: list[_Route]) -> str:
    """`show ip route vrf *` as IOS-XE prints it: one `Routing Table:` block per
    VRF, a subnetted header per major network, and each further equal-cost
    hop on its own continuation line."""
    lines: list[str] = []
    for vrf, group in _by_vrf(rib):
        lines += [f"Routing Table: {vrf}", *_IOSXE_CODES, "", _gateway(group), ""]
        majors: dict[int, tuple[int, set[int]]] = {}
        for r in group:
            if r.length:
                count, masks = majors.get(r.network >> 24, (0, set()))
                masks.add(r.length)
                majors[r.network >> 24] = (count + 1, masks)
        current = -1
        for r in group:
            if r.length and r.network >> 24 != current:
                current = r.network >> 24
                count, masks = majors[current]
                if len(masks) == 1:
                    lines.append(f"      {current}.0.0.0/{min(masks)} is subnetted, {count} subnets")
                else:
                    lines.append(
                        f"      {current}.0.0.0/8 is variably subnetted, {count} subnets, {len(masks)} masks"
                    )
            head = f"{r.code:<9}{_ip(r.network)}/{r.length}"
            first, *rest = r.hops
            if r.code in ("C", "L"):
                lines.append(f"{head} is directly connected, {_ifname('iosxe', first[1])}")
                continue
            lines.append(f"{head} {_iosxe_via(r, first)}")
            lines += [f"{'':<21}{_iosxe_via(r, hop)}" for hop in rest]
        lines.append("")
    return "\n".join(lines)


def _iosxe_via(r: _Route, hop: Hop) -> str:
    text = f"[{r.distance}/{r.metric}] via {hop[0]}"
    if not r.code.startswith("S"):
        text += f", {r.uptime}"
    if hop[1] is not None:
        text += f", {_ifname('iosxe', hop[1])}"
    return text


_IOSXR_CODES = (
    "Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path",
    "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area",
    "       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2",
    "       E1 - OSPF external type 1, E2 - OSPF external type 2, E - EGP",
    "       i - ISIS, L1 - IS-IS level-1, L2 - IS-IS level-2",
    "       ia - IS-IS inter area, su - IS-IS summary null, * - candidate default",
    "       U - per-user static route, o - ODR, L - local, G  - DAGR, l - LISP",
    "       A - access/subscriber, a - Application route",
    "       M - mobile route, r - RPL, t - Traffic Engineering, (!) - FRR Backup path",
)


def _iosxr_rib(rib: list[_Route]) -> str:
    """`show route vrf all ipv4` as IOS-XR prints it, limited to the line
    shapes `cisco_xr_show_ip_route` reads, so that every line of it is read
    (the repository's copy of that template records any other line as
    unread, `cli_parse.parse_with_unread`)."""
    lines = ["Thu Jul 30 12:05:00.123 UTC", ""]
    for vrf, group in _by_vrf(rib):
        lines += [f"VRF: {vrf}", "", *_IOSXR_CODES, "", _gateway(group), ""]
        for r in group:
            head = f"{r.code:<5}{_ip(r.network)}/{r.length}"
            first, *rest = r.hops
            if r.code in ("C", "L"):
                lines.append(f"{head} is directly connected, {r.uptime}, {_ifname('iosxr', first[1])}")
                continue
            lines.append(f"{head} {_iosxr_via(r, first)}")
            lines += [f"{'':<11}{_iosxr_via(r, hop)}" for hop in rest]
        lines.append("")
    return "\n".join(lines)


def _iosxr_via(r: _Route, hop: Hop) -> str:
    text = f"[{r.distance}/{r.metric}] via {hop[0]}, {r.uptime}"
    if hop[1] is not None:
        text += f", {_ifname('iosxr', hop[1])}"
    return text


_NXOS_CLIENTS = {
    "C": "direct",
    "L": "local",
    "S": "static",
    "S*": "static",
    "O": "ospf-1",
    "O IA": "ospf-1",
    "O E2": "ospf-1",
    "B": "bgp-65001",
}
_NXOS_ROUTE_TYPES = {"O": "intra", "O IA": "inter", "O E2": "type-2"}


def _nxos_rib(rib: list[_Route]) -> str:
    """`show ip route vrf all | json`: vrf, address family, prefix and path
    tables, every single-row table collapsed to a bare object as NX-OS does."""
    vrfs = []
    for vrf, group in _by_vrf(rib):
        prefixes = []
        for r in group:
            paths = []
            for next_hop, interface in r.hops:
                path: dict[str, Any] = {
                    # a connected or local route names the interface's own address
                    "ipnexthop": next_hop or _ip(r.network if r.code == "L" else r.network + 1),
                }
                if interface is not None:
                    path["ifname"] = _ifname("nxos", interface)
                path.update(
                    uptime=_NXOS_UPTIMES[r.uptime],
                    pref=r.distance,
                    metric=r.metric,
                    clientname=_NXOS_CLIENTS[r.code],
                )
                if r.code in _NXOS_ROUTE_TYPES:
                    path["type"] = _NXOS_ROUTE_TYPES[r.code]
                elif r.code == "B":
                    path["type"] = "external" if r.distance == 20 else "internal"
                path["ubest"] = True
                paths.append(path)
            prefixes.append(
                {
                    "ipprefix": f"{_ip(r.network)}/{r.length}",
                    "ucast-nhops": len(paths),
                    "mcast-nhops": 0,
                    "attached": r.code in ("C", "L"),
                    "TABLE_path": {"ROW_path": _collapse(paths)},
                }
            )
        vrfs.append(
            {
                "vrf-name-out": vrf,
                "TABLE_addrf": {
                    "ROW_addrf": {"addrf": "ipv4", "TABLE_prefix": {"ROW_prefix": _collapse(prefixes)}}
                },
            }
        )
    return json.dumps({"TABLE_vrf": {"ROW_vrf": _collapse(vrfs)}})


# BGP path tables


class _Path(NamedTuple):
    # "row" is a complete path line. The other shapes are lines an IOS-XE or
    # IOS-XR table prints in a form of their own: "split" (a `* i` status, a
    # space inside the status column), "cont" (a further path of the previous
    # prefix, network column blank), "blank" (an empty LocPrf column) and
    # "nomask" (a classful network printed without its length). NX-OS JSON has
    # no such lines: there "cont" is a second path of the prefix and the rest
    # are ordinary paths.
    shape: str
    status: str
    prefix: str
    next_hop: str
    metric: int
    local_pref: int
    weight: int
    as_path: str
    origin: str


def _table_prefix(index: int, base: int) -> str:
    network = base + (index << 8)
    if index % 101 == 7:
        return f"{_ip(network & ~0x1FF)}/23"
    return f"{_ip(network)}/24"


def _path_rows(direction: str, count: int, peer: tuple[str, int], router_id: str, rng: _Rng) -> list[_Path]:
    """`count` path lines of one direction's table. The received and accepted
    tables carry the peer's full feed; the advertised table carries locally
    originated prefixes.

    Each line's choices come from disjoint bit fields of one draw, and the AS
    path from a second."""
    peer_ip, peer_asn = peer
    rows: list[_Path] = []
    index = 0
    while len(rows) < count:
        if direction == "advertised":
            rows.append(
                _Path("row", "*>", _table_prefix(index, 0x0A640000), router_id, 0, 100, 32768, "", "i")
            )
            index += 1
            continue
        z = rng.draw()
        roll = (z & 0x3FF) % 1000
        if 15 <= roll < 30 and rows:
            rows.append(rows[-1]._replace(shape="cont", status="*", next_hop="198.18.255.2"))
            continue
        shape = "split" if roll < 15 else "blank" if roll < 40 else "nomask" if roll < 45 else "row"
        pick = ((z >> 10) & 0xFF) % 5
        if shape == "split":
            status = "* i"
        elif direction == "received":
            status = "*>" if pick < 2 else "*"
        else:
            status = ("*>", "*>", "*>", "*", "r>")[pick]
        as_path = str(peer_asn)
        hops = (z >> 18) & 3
        if hops:
            # transit AS numbers below the private range, so none repeats a peer's own
            w = rng.draw()
            as_path += "".join(f" {1000 + ((w >> (15 * i)) & 0x7FFF)}" for i in range(hops))
        origin_roll = ((z >> 20) & 0x7F) % 100
        origin = "i" if origin_roll < 90 else "e" if origin_roll < 94 else "?"
        metric = 0 if (z >> 27) & 3 else ((z >> 29) & 0x3FF) % 1000
        local_pref = 150 if direction != "received" and not (z >> 39) & 3 else 100
        rows.append(
            _Path(
                shape,
                status,
                _table_prefix(index, 0x0B000000),
                peer_ip,
                metric,
                local_pref,
                0,
                as_path,
                origin,
            )
        )
        index += 1
    return rows


_IOSXE_TABLE_HEAD = (
    "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,",
    "              r RIB-failure, S Stale, m multipath, b backup-path, f RT-Filter,",
    "              x best-external, a additional-path, c RIB-compressed,",
    "              t secondary path, L long-lived-stale,",
    "Origin codes: i - IGP, e - EGP, ? - incomplete",
    "RPKI validation codes: V valid, I invalid, N Not found",
    "",
    "     Network          Next Hop            Metric LocPrf Weight Path",
)
_IOSXR_TABLE_HEAD = (
    "Status codes: s suppressed, d damped, h history, * valid, > best",
    "              i - internal, r RIB-failure, S stale, N Nexthop-discard",
    "Origin codes: i - IGP, e - EGP, ? - incomplete",
    "",
    "   Network            Next Hop            Metric LocPrf Weight Path",
)


_IOSXR_FROM_TABLE_HEAD = "Network            Next Hop        From            AS Path"


class _IosPath(NamedTuple):
    """One path as an IOS-XE or IOS-XR table prints it: the network column
    ("" for a "cont" path), the prefix that states (the last printed network
    for a "cont" path), and the Metric and LocPrf columns ("" when blank)."""

    path: _Path
    network: str
    prefix: str
    metric: str
    local_pref: str


def _ios_network(p: _Path) -> tuple[str, str]:
    """(printed network, stated prefix) of a path that prints its network.

    A "nomask" path prints a class C network without its length. A "row" path
    whose third octet is 17 modulo 64 prints an 18-character /25, longer than
    the IOS-XE network column, so IOS-XE wraps it. Both are derived from a key
    unique per prefix of a table, so no two paths of a table state the same
    prefix unless one continues the other."""
    address, length = p.prefix.split("/")
    first, second, third, _fourth = (int(octet) for octet in address.split("."))
    if p.shape == "nomask" or (p.shape == "row" and third % 64 == 17):
        key = (((first << 16) | (second << 8) | third) << 1) | (length == "23")
        if p.shape == "nomask":
            network = f"{192 + (key >> 16)}.{(key >> 8) & 255}.{key & 255}.0"
            return network, f"{network}/24"
        network = f"{100 + (key >> 14)}.{100 + ((key >> 7) & 127)}.{100 + (key & 127)}.128/25"
        return network, network
    return p.prefix, p.prefix


def _ios_paths(rows: list[_Path], direction: str) -> Iterator[_IosPath]:
    """Every path of one table as IOS prints it. Metric is blank for a zero
    metric outside the advertised table, and LocPrf is printed only for an
    accepted path whose local preference is not the default 100, except a
    "blank" one."""
    prefix = ""
    for p in rows:
        metric = "" if p.metric == 0 and direction != "advertised" else str(p.metric)
        printed = direction == "accepted" and p.local_pref != 100 and p.shape != "blank"
        local_pref = str(p.local_pref) if printed else ""
        if p.shape == "cont":
            yield _IosPath(p, "", prefix, metric, local_pref)
            continue
        network, prefix = _ios_network(p)
        yield _IosPath(p, network, prefix, metric, local_pref)


def _as_path_column(p: _Path) -> str:
    return f"{p.as_path} {p.origin}" if p.as_path else p.origin


def _iosxe_lines(ios: _IosPath) -> list[str]:
    """The line of one IOS-XE path, or the two lines of one whose network is
    wider than its 16-character column."""
    p = ios.path
    rest = f"{p.next_hop:<15} {ios.metric:>10} {ios.local_pref:>6} {p.weight:>6} {_as_path_column(p)}"
    lead = f" {p.status:<3} "
    if len(ios.network) > 16:
        return [lead + ios.network, " " * 22 + rest]
    return [f"{lead}{ios.network:<16} {rest}"]


def _iosxr_lines(ios: _IosPath, direction: str) -> list[str]:
    """The line of one IOS-XR path; the advertised table has the "Network
    Next Hop From AS Path" layout."""
    p = ios.path
    if direction == "advertised":
        return [f"{ios.network:<19}{p.next_hop:<16}{'Local':<16}{_as_path_column(p)}"]
    return [
        f"{p.status:<3}{ios.network:<18} {p.next_hop:<15} {ios.metric:>10} {ios.local_pref:>6} {p.weight:>6} "
        f"{_as_path_column(p)}"
    ]


def _iosxe_table(rows: list[_Path], router_id: str, direction: str) -> str:
    prefixes = sum(1 for p in rows if p.shape != "cont")
    body = [line for ios in _ios_paths(rows, direction) for line in _iosxe_lines(ios)]
    head = f"BGP table version is 412345, local router ID is {router_id}"
    return "\n".join([head, *_IOSXE_TABLE_HEAD, *body, "", f"Total number of prefixes {prefixes}", ""])


def _iosxr_table(rows: list[_Path], router_id: str, direction: str) -> str:
    prefixes = sum(1 for p in rows if p.shape != "cont")
    body = [line for ios in _ios_paths(rows, direction) for line in _iosxr_lines(ios, direction)]
    footer = f"Processed {prefixes} prefixes, {len(rows)} paths"
    if direction == "advertised":
        return "\n".join([_IOSXR_FROM_TABLE_HEAD, *body, "", footer, ""])
    head = f"BGP table version is 412345, local router ID is {router_id}"
    return "\n".join([head, *_IOSXR_TABLE_HEAD, *body, "", footer, ""])


def _nxos_table(rows: list[_Path], *, rd_level: bool) -> str:
    """One `show bgp ipv4 unicast neighbors <peer> <direction> | json` answer.
    `rd_level` wraps the prefixes in the route-distinguisher table some
    releases print for a plain IPv4 unicast table and others leave out."""
    prefixes: list[dict[str, Any]] = []
    for index, p in enumerate(rows):
        path: dict[str, Any] = {"pathnr": 0, "ipnexthop": p.next_hop, "aspath": p.as_path}
        if p.shape != "blank":
            path["localpref"] = p.local_pref
        path.update(metric=p.metric, origin=p.origin)
        if index % 3 == 0:
            path["community"] = [f"{p.as_path.split(' ')[0] or '65001'}:100", "65001:200"]
        elif index % 3 == 1:
            path["community"] = "65001:300"
        best = "true" if ">" in p.status else "false"
        path["bestpath" if index % 7 == 0 else "best"] = best
        if p.shape == "cont" and prefixes:
            paths = prefixes[-1]["TABLE_path"]["ROW_path"]
            siblings = paths if isinstance(paths, list) else [paths]
            path["pathnr"] = len(siblings)
            prefixes[-1]["TABLE_path"]["ROW_path"] = [*siblings, path]
            continue
        prefixes.append({"ipprefix": p.prefix, "TABLE_path": {"ROW_path": path}})
    holder: dict[str, Any] = {"TABLE_prefix": {"ROW_prefix": _collapse(prefixes)}}
    safi: dict[str, Any] = {"safi": 1, "af-name": "IPv4 Unicast"}
    safi.update({"TABLE_rd": {"ROW_rd": holder}} if rd_level else holder)
    return json.dumps(
        {
            "TABLE_vrf": {
                "ROW_vrf": {
                    "vrf-name-out": "default",
                    "TABLE_afi": {"ROW_afi": {"afi": 1, "TABLE_safi": {"ROW_safi": safi}}},
                }
            }
        }
    )


# BGP configuration and session summary


def _peers(count: int) -> list[tuple[str, int]]:
    return [(f"198.18.{i // 250}.{i % 250 + 1}", 64601 + i) for i in range(count)]


def _iosxe_bgp_config(peers: list[tuple[str, int]], soft: list[bool]) -> str:
    lines = ["router bgp 65001", " bgp router-id 10.255.255.1", " bgp log-neighbor-changes"]
    for index, (ip, asn) in enumerate(peers):
        lines += [f" neighbor {ip} remote-as {asn}", f" neighbor {ip} description transit-{index + 1}"]
    lines += [" !", " address-family ipv4", "  redistribute static route-map RM-STATIC-TO-BGP"]
    for index, (ip, _asn) in enumerate(peers):
        lines.append(f"  neighbor {ip} activate")
        if soft[index]:
            lines.append(f"  neighbor {ip} soft-reconfiguration inbound")
        if index == 0:
            lines.append(f"  neighbor {ip} route-map RM-IN in")
    lines += [" exit-address-family", "!", ""]
    return "\n".join(lines)


def _iosxr_bgp_config(peers: list[tuple[str, int]], soft: list[bool]) -> str:
    lines = [
        "router bgp 65000",
        " bgp router-id 10.0.0.1",
        " address-family ipv4 unicast",
        "  redistribute connected",
    ]
    lines.append(" !")
    for index, (ip, asn) in enumerate(peers):
        lines += [f" neighbor {ip}", f"  remote-as {asn}", f"  description transit-{index + 1}"]
        lines.append("  address-family ipv4 unicast")
        if index == 0:
            lines += ["   route-policy PL_CUST_IN in", "   route-policy PL_CUST_OUT out"]
        if soft[index]:
            lines.append("   soft-reconfiguration inbound always")
        lines += ["  !", " !"]
    lines += ["!", ""]
    return "\n".join(lines)


def _nxos_bgp_config(peers: list[tuple[str, int]], soft: list[bool]) -> str:
    lines = [
        "!Command: show running-config bgp",
        "!Running configuration last done at: Thu Jul 30 12:05:00 2026",
        "feature bgp",
        "",
        "router bgp 65001",
        "  router-id 10.255.0.1",
        "  address-family ipv4 unicast",
        "    redistribute direct route-map RM-CONN",
    ]
    for index, (ip, asn) in enumerate(peers):
        lines += [f"  neighbor {ip}", f"    remote-as {asn}", f"    description transit-{index + 1}"]
        lines.append("    address-family ipv4 unicast")
        if index == 0:
            lines.append("      route-map RM-IN in")
        if soft[index]:
            lines.append("      soft-reconfiguration inbound")
    lines.append("")
    return "\n".join(lines)


def _iosxe_summary(peers: list[tuple[str, int]], received: list[int]) -> str:
    lines = [
        "BGP router identifier 10.255.255.1, local AS number 65001",
        "BGP table version is 412345, main routing table version 412345",
        f"{max(received, default=0)} network entries using {248 * max(received, default=0)} bytes of memory",
        f"{sum(received)} path entries using {104 * sum(received)} bytes of memory",
        "",
        "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd",
    ]
    for (ip, asn), count in zip(peers, received, strict=True):
        lines.append(f"{ip:<16}4 {asn:>12} {812345:>7} {1234:>7} {412345:>8}    0    0 2w3d     {count:>8}")
    lines.append("")
    return "\n".join(lines)


def _iosxr_summary(peers: list[tuple[str, int]], received: list[int]) -> str:
    lines = [
        "BGP router identifier 10.0.0.1, local AS number 65000",
        "BGP generic scan interval 60 secs",
        "BGP table state: Active",
        "Table ID: 0xe0000000   RD version: 412345",
        "BGP main routing table version 412345",
        "BGP scan interval 60 secs",
        "",
        "BGP is operating in STANDALONE mode.",
        "",
        "",
        "Process       RcvTblVer   bRIB/RIB   LabelVer  ImportVer  SendTblVer  StandbyVer",
        "Speaker          412345     412345     412345     412345      412345      412345",
        "",
        "Neighbor        Spk    AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down  St/PfxRcd",
    ]
    for (ip, asn), count in zip(peers, received, strict=True):
        lines.append(
            f"{ip:<16}{0:>2} {asn:>5} {812345:>7} {1234:>7} {412345:>8}    0    0     2w3d {count:>10}"
        )
    lines.append("")
    return "\n".join(lines)


def _nxos_summary(peers: list[tuple[str, int]], received: list[int]) -> str:
    neighbors = [
        {
            "neighbor-id": ip,
            "remoteas": asn,
            "connectionsdropped": index,
            "lastflap": "P17D",
            "lastread": "PT20S",
            "lastwrite": "PT8S",
            "state": "Established",
            "localport": 179,
            "remoteport": 40000 + index,
            "notificationssent": 0,
            "notificationsreceived": 0,
        }
        for index, (ip, asn) in enumerate(peers)
    ]
    return json.dumps(
        {
            "totalpeers": len(peers),
            "totalestablishedpeers": len(peers),
            "localas": 65001,
            "TABLE_vrf": {
                "ROW_vrf": {
                    "vrf-name-out": "default",
                    "local-as": 65001,
                    "router-id": "10.255.0.1",
                    "TABLE_neighbor": {"ROW_neighbor": _collapse(neighbors)},
                }
            },
        }
    )


# family builders


class _Family(NamedTuple):
    route_command: str
    bgp_command: str
    sessions_command: str
    path_command: Callable[[str, str], str]
    refusal: str
    router_id: str
    rib: Callable[[list[_Route]], str]
    bgp_config: Callable[[list[tuple[str, int]], list[bool]], str]
    summary: Callable[[list[tuple[str, int]], list[int]], str]
    # (path lines, router id, index of the answer among the path answers, direction)
    table: Callable[[list[_Path], str, int, str], str]


def _family(name: str) -> _Family:
    module = importlib.import_module(f"hst.collectors.{name}")
    tests = importlib.import_module(f"tests.test_{name}")
    if name == "iosxe":
        return _Family(
            module.CMD_ROUTE,
            module.CMD_BGP,
            module.CMD_BGP_SESSIONS,
            module.bgp_route_command,
            tests.BGP_NO_SOFT_RECONFIG_TEXT,
            "10.255.255.1",
            _iosxe_rib,
            _iosxe_bgp_config,
            _iosxe_summary,
            lambda rows, router_id, _index, direction: _iosxe_table(rows, router_id, direction),
        )
    if name == "iosxr":
        return _Family(
            module.CMD_ROUTE,
            module.CMD_BGP,
            module.CMD_BGP_SESSIONS,
            module.bgp_route_command,
            tests.BGP_NO_SOFT_RECONFIG_TEXT,
            "10.0.0.1",
            _iosxr_rib,
            _iosxr_bgp_config,
            _iosxr_summary,
            lambda rows, router_id, _index, direction: _iosxr_table(rows, router_id, direction),
        )
    return _Family(
        module.CMD_ROUTE,
        module.CMD_BGP,
        module.CMD_BGP_SESSIONS,
        lambda peer_ip, direction: module.bgp_route_command("default", peer_ip, direction),
        tests.BGP_NO_SOFT_RECONFIG,
        "10.255.0.1",
        _nxos_rib,
        _nxos_bgp_config,
        _nxos_summary,
        # the advertised tables leave the route-distinguisher level out
        lambda rows, _router_id, index, _direction: _nxos_table(rows, rd_level=index % 3 != 2),
    )


# The path answers `_path_answers` yields no path lines for: the received table
# of a peer without soft reconfiguration inbound, which the device refuses, and
# the empty advertised table of the last peer.
_REFUSED: list[_Path] = []
_EMPTY: list[_Path] = []


def _path_answers(
    family: str,
    spec: _Family,
    peer_list: list[tuple[str, int]],
    soft: list[bool],
    *,
    paths: int,
    seed: int,
    advertised: int | None,
) -> Iterator[tuple[str, tuple[str, int], str, list[_Path]]]:
    """(command, peer, direction, path lines) of every BGP path answer of a
    payload, in the order `_build` writes them, drawing the path lines from
    the payload's own random stream: `_REFUSED` and `_EMPTY` stand for the
    answers that hold no table."""
    rng = _Rng(family, seed, "paths")
    for index, peer in enumerate(peer_list):
        for direction in ("received", "accepted", "advertised"):
            command = spec.path_command(peer[0], direction)
            if direction == "received" and not soft[index]:
                yield command, peer, direction, _REFUSED
                continue
            if direction == "advertised" and index == len(peer_list) - 1:
                yield command, peer, direction, _EMPTY
                continue
            count = advertised if direction == "advertised" and advertised is not None else paths
            yield command, peer, direction, _path_rows(direction, count, peer, spec.router_id, rng)


def _build(
    family: str,
    *,
    routes: int,
    peers: int,
    paths: int,
    variant: str,
    seed: int,
    advertised: int | None,
    denied_received: bool,
) -> dict[str, Any]:
    """One synthetic payload in the order a fetch writes it: the static
    commands, the recorded outcomes, then the BGP observation commands.

    The first peer answers its received direction with the device's `%` line
    when `denied_received` (no soft reconfiguration inbound, and so no
    `soft-reconfiguration` line for it in the running-config), and the last
    peer's advertised table is an empty answer. Every command's outcome is
    recorded `ok`, as a fetch records a command the device answered."""
    from hst.collectors.base import RAW_OUTCOMES_KEY

    spec = _family(family)
    raw = fixture_raw(family)
    fixture_capture = set(importlib.import_module(f"tests.test_{family}")._bgp_capture_raw())
    peer_list = _peers(peers)
    soft = [not (denied_received and index == 0) for index in range(peers)]
    rib = _rib(routes, [ip for ip, _asn in peer_list], _Rng(family, seed, "rib"))

    payload: dict[str, Any] = {}
    for command, text in raw.items():
        if command in fixture_capture:
            continue
        if command == spec.route_command:
            payload[command] = spec.rib(rib)
        elif command == spec.bgp_command:
            payload[command] = spec.bgp_config(peer_list, soft)
        else:
            payload[command] = text
    outcomes: dict[str, dict[str, str]] = {command: {"status": "ok"} for command in payload}
    payload[RAW_OUTCOMES_KEY] = outcomes

    observed: dict[str, str] = {}
    received: list[int] = []
    for command, _peer, direction, rows in _path_answers(
        family, spec, peer_list, soft, paths=paths, seed=seed, advertised=advertised
    ):
        if rows is _REFUSED:
            observed[command] = spec.refusal
        elif rows is _EMPTY:
            observed[command] = ""
        else:
            observed[command] = spec.table(rows, spec.router_id, len(observed), direction)
            if direction == "accepted":
                received.append(sum(1 for p in rows if p.shape != "cont"))
    payload[spec.sessions_command] = spec.summary(peer_list, received)
    outcomes[spec.sessions_command] = {"status": "ok"}
    for command, text in observed.items():
        payload[command] = text
        outcomes[command] = {"status": "ok"}
    return _apply_variant(family, payload, variant)


def iosxe_payload(
    *,
    routes: int,
    peers: int,
    paths: int,
    variant: str = "plain",
    seed: int = 0,
    advertised: int | None = None,
    denied_received: bool = True,
) -> dict[str, Any]:
    """An IOS-XE payload with `routes` RIB entries and `peers` BGP neighbors,
    each with `paths` lines per direction (`advertised` for the advertised
    tables when given)."""
    return _build(
        "iosxe",
        routes=routes,
        peers=peers,
        paths=paths,
        variant=variant,
        seed=seed,
        advertised=advertised,
        denied_received=denied_received,
    )


def iosxr_payload(
    *,
    routes: int,
    peers: int,
    paths: int,
    variant: str = "plain",
    seed: int = 0,
    advertised: int | None = None,
    denied_received: bool = True,
) -> dict[str, Any]:
    """The IOS-XR counterpart of `iosxe_payload`."""
    return _build(
        "iosxr",
        routes=routes,
        peers=peers,
        paths=paths,
        variant=variant,
        seed=seed,
        advertised=advertised,
        denied_received=denied_received,
    )


def nxos_payload(
    *,
    routes: int,
    peers: int,
    paths: int,
    variant: str = "plain",
    seed: int = 0,
    advertised: int | None = None,
    denied_received: bool = True,
) -> dict[str, Any]:
    """The NX-OS counterpart of `iosxe_payload`, with JSON route and path tables."""
    return _build(
        "nxos",
        routes=routes,
        peers=peers,
        paths=paths,
        variant=variant,
        seed=seed,
        advertised=advertised,
        denied_received=denied_received,
    )


_BUILDERS: dict[str, Callable[..., dict[str, Any]]] = {
    "iosxe": iosxe_payload,
    "iosxr": iosxr_payload,
    "nxos": nxos_payload,
}


# variants


def _apply_variant(family: str, payload: dict[str, Any], variant: str) -> dict[str, Any]:
    if variant == "plain":
        return payload
    if variant == "no_trailing_newline":
        return {k: v.removesuffix("\n") if isinstance(v, str) else v for k, v in payload.items()}
    if variant == "unicode":
        return _unicode(family, payload)
    raise ValueError(f"unknown variant {variant!r}")


def _unicode(family: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Free text carrying `UNICODE_TEXT` and U+2028: an interface description,
    a BGP neighbor description, every `%` refusal line and, on NX-OS, the
    LLDP neighbor's system name and description. A line break inside
    a description is followed by a deeper-indented continuation, so the
    config parsers read it as a child line of the description. On the text
    families one path line of the first table with rows also carries U+2028
    between its next hop and its metric, which `splitlines` reads as a line break.
    """
    module = importlib.import_module(f"hst.collectors.{family}")
    out = dict(payload)
    free = f"{UNICODE_TEXT}{LINE_SEPARATOR}"
    if family == "nxos":
        out[module.CMD_INTERFACE] = _edit_json(
            out[module.CMD_INTERFACE], "interface", lambda row: row.update(desc=f"{free}rack 7")
        )
        out[module.CMD_LLDP] = _edit_json(
            out[module.CMD_LLDP],
            "nbor_detail",
            lambda row: row.update(sys_name=f"core1 {free}rack 7", sys_desc=f"{free}rack 7"),
        )
    else:
        out[module.CMD_INTERFACES] = _insert_after(
            out[module.CMD_INTERFACES], r"  Hardware is .*", f"  Description: {free}    rack 7"
        )
    out[module.CMD_BGP] = _describe_neighbor(family, out[module.CMD_BGP], free)
    for command, text in out.items():
        if isinstance(text, str) and text.startswith("%"):
            body = text.removesuffix("\n")
            out[command] = f"{body} ({free}rack 7){text[len(body) :]}"
    if family != "nxos":
        probe = "192.0.2.255"
        prefix = _family(family).path_command(probe, "accepted").split(probe)[0]
        for command, text in out.items():
            if command.startswith(prefix) and isinstance(text, str):
                split, count = _PATH_ROW.subn(rf"\1{LINE_SEPARATOR}", text, count=1)
                if count:
                    out[command] = split
                    break
    return out


# The first complete path line of a text table: status (after the leading
# space of the IOS-XE layout), network with a length, next hop, then the space
# the separator replaces.
_PATH_ROW = re.compile(r"(?m)^( ?[*>isdhrSmbfxacV\-]+ +\S+/\d+ +\S+) ")


def expected_ios_paths(key: str) -> dict[str, list[dict[str, Any]]]:
    """The paths the family parse must read from each BGP path answer of a
    synthetic IOS-XE or IOS-XR case, keyed by command, as `iter_bgp_paths`
    builds them and the parse stamps them with `vrf` and `af`: the values the
    generator printed, not what a parser read. A refused or empty answer has
    none.

    The IOS-XR advertised table prints no status, metric or local preference,
    so its paths carry `best`, `med` and `local_pref` as None. The `unicode`
    variant splits the first path line `_PATH_ROW` matches in two, neither of
    which is a path row, and the paths on the lines right after it that
    continue its prefix then have no network to take, so none of them is read
    either."""
    from hst.core.l3domain import DEFAULT_VRF

    family, scale, variant = split_case(key)
    if family not in ("iosxe", "iosxr") or scale not in SCALES:
        raise ValueError(f"{key!r} is not a synthetic IOS-XE or IOS-XR case")
    options: dict[str, Any] = {"advertised": None, "denied_received": True, **SCALES[scale]}
    spec = _family(family)
    peer_list = _peers(options["peers"])
    soft = [not (options["denied_received"] and index == 0) for index in range(options["peers"])]
    split = variant == "unicode"
    out: dict[str, list[dict[str, Any]]] = {}
    for command, (peer_ip, _asn), direction, rows in _path_answers(
        family, spec, peer_list, soft, paths=options["paths"], seed=0, advertised=options["advertised"]
    ):
        from_table = family == "iosxr" and direction == "advertised"
        paths: list[dict[str, Any]] = []
        dropping = False
        for ios in _ios_paths(rows, direction):
            if split:
                lines = _iosxe_lines(ios) if family == "iosxe" else _iosxr_lines(ios, direction)
                if any(_PATH_ROW.match(line) for line in lines):
                    split, dropping = False, True
                    continue
            if dropping and not ios.network:
                continue
            dropping = False
            p = ios.path
            paths.append(
                {
                    "peer_ip": peer_ip,
                    "direction": direction,
                    "prefix": ios.prefix,
                    "path_id": None,
                    "next_hop": p.next_hop,
                    "as_path": p.as_path or None,
                    "local_pref": int(ios.local_pref) if ios.local_pref and not from_table else None,
                    "med": int(ios.metric) if ios.metric and not from_table else None,
                    "origin": p.origin,
                    "communities": None,
                    "best": None if direction == "received" or from_table else ">" in p.status,
                    "vrf": DEFAULT_VRF,
                    "af": 4,
                }
            )
        out[command] = paths
    return out


def _insert_after(text: str, pattern: str, line: str) -> str:
    lines = text.split("\n")
    for index, current in enumerate(lines):
        if re.fullmatch(pattern, current):
            lines.insert(index + 1, line)
            return "\n".join(lines)
    raise ValueError(f"no line matches {pattern!r}")


def _describe_neighbor(family: str, text: str, free: str) -> str:
    """The running-config with a description line for its first neighbor, or
    unchanged when it configures none."""
    lines = text.split("\n")
    for index, line in enumerate(lines):
        if family == "iosxe" and (m := re.match(r"^(\s*)neighbor (\S+) remote-as ", line)):
            indent, peer = m.group(1), m.group(2)
            end = index + 1
            while end < len(lines) and lines[end].startswith(f"{indent}neighbor {peer} "):
                end += 1
            lines.insert(end, f"{indent}neighbor {peer} description {free}{indent}   rack 7")
            return "\n".join(lines)
        if family != "iosxe" and (m := re.match(r"^( +)neighbor (\S+)$", line)):
            child = m.group(1) + (" " if family == "iosxr" else "  ")
            lines.insert(index + 1, f"{child}description {free}{child}    rack 7")
            return "\n".join(lines)
    return text


def _edit_json(text: str, table: str, edit: Callable[[dict[str, Any]], None]) -> str:
    """The JSON answer with `edit` applied to the first row of `TABLE_<table>`,
    rendered with its non-ASCII characters unescaped."""
    document = json.loads(text)
    rows = document[f"TABLE_{table}"][f"ROW_{table}"]
    edit(rows[0] if isinstance(rows, list) else rows)
    return json.dumps(document, ensure_ascii=False)
