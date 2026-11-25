"""Read-only Gaia/VSX observations, isolated one ``vsenv`` context at a time."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections.abc import Mapping
from typing import Any, ClassVar, Literal, cast

from pydantic import Field, model_validator

from hst.app import crypto
from hst.core import rawstore, uid
from hst.core.firewall_context import (
    FirewallAuthority,
    FirewallInstance,
    InterfaceContext,
    PhysicalAppliance,
    QualifiedVsid,
    VrfContext,
)
from hst.core.identity import DeviceResolver, MemoryResolver
from hst.core.ipenc import prefix_bounds
from hst.core.model import Batch, SectionOutcome, SectionStatus, TableOutcome

from .base import RAW_OUTCOMES_KEY, register
from .checkpoint import scope_of
from .checkpoint_bgp import project as project_bgp
from .checkpoint_evidence import VsxEvidence, installations_for, read_evidence, sessions_for
from .checkpoint_identity import (
    GaiaObservation,
    GatewayIdentity,
    ManagementInventory,
    gateway_objects,
    parse_hostname,
    parse_release,
    parse_vs_names,
    resolve_identity,
)
from .checkpoint_iproute import COMMANDS as TEXT_COMMANDS
from .checkpoint_iproute import parse as parse_iproute_text
from .checkpoint_operational import bgp_peers, cluster_state, context_kind, installed_policy, local_as
from .checkpoint_topology import connect_virtual_devices, topology
from .cli_collector import SshCliCollector, SshSourceConfig, classify_command_failure
from .util import GraphBuilder, canonical_mac, connected_address

logger = logging.getLogger(__name__)

_VSID = re.compile(r"^\s*(\d+)\s+")

VERSION_COMMAND = "clish -c 'show version osedition'"
# FIRST CONTACT: `show hostname` is assumed to be the Gaia clish command for the
# configured hostname. checkpoint_identity.parse_hostname reads its output.
HOSTNAME_COMMAND = "clish -c 'show hostname'"
VSX_STAT_COMMAND = "vsx stat -v"


class CpGatewayConfig(SshSourceConfig):
    """A separately configured Gaia source."""

    estate: str
    evidence_file: str = Field(
        default="", description="Versioned appliance-bound VSX management/runtime evidence JSON"
    )
    management_source: str = Field(
        default="",
        title="Management source",
        description=(
            "Check Point management source of this appliance; its data resolves the management "
            "scope (its scope string), the appliance object (the gateway object whose IPv4 "
            "address equals this source's host or whose name equals the hostname the appliance "
            "reports) and each VSID (the virtual system object whose name equals the VS name in "
            "vsx stat -v); required unless the management scope override and the appliance "
            "object uid override are both set"
        ),
        json_schema_extra={"format": "source", "sourceType": "checkpoint"},
    )
    management_authority_uid: str = Field(
        default="",
        title="Management scope override",
        description=(
            "Empty: the scope string of the management source; set: written to "
            "FirewallInstance.authority as typed, cp:<host> for a single-domain server, "
            "cp:<host>:<domain> for an MDS domain, <host> being the host field of the "
            "management source"
        ),
    )
    management_domain_uid: str = Field(
        default="",
        title="Management domain uid override",
        description=(
            "Empty: the domain uid from the appliance object's domain block in the management "
            "source's data, else from any gateway object's domain block; with no domain uid in "
            "the data, the domain name of the management scope, or on a single-domain server "
            "the scope string; set: used as typed"
        ),
    )
    appliance_uid: str = Field(
        default="",
        title="Appliance object uid override",
        description=(
            "Empty: the gateway object of the management source with this IPv4 address, else "
            "with the reported hostname; set: this management object uid, as typed; for a VSX "
            "cluster, the CpmiVsxClusterMember object; the device identity registry keys the "
            "appliance Device by it and by the management scope, so the Gaia Device and the "
            "management Device are one node"
        ),
    )
    observation_uid: str = Field(
        default="",
        title="Observation uid",
        description=(
            "Name of the observation the VSIDs of this appliance are qualified by; empty: the "
            "name of this source, or its host when the source has no name"
        ),
    )
    management_host: str = Field(
        default="",
        title="Management host override",
        description=(
            "Empty: the host of the management source; read only when the management source "
            "is not linked and no management scope override is set, for the fallback scope "
            "cp:<host> or cp:<host>:<domain>"
        ),
    )
    management_domain: str = Field(
        default="",
        title="Management domain override",
        description=(
            "Empty: the MDS domain of the management source; read only with the management host override"
        ),
    )
    gateway_release: str = Field(
        default="",
        title="Gaia release override",
        description=(
            "Empty: the release from the clish show version output; set: written to the "
            "appliance Device as typed"
        ),
    )
    gateway_contexts: tuple[int, ...] = ()
    capture_bgp: bool = True
    cluster_mode: Literal["auto", "standalone", "cluster"] = "auto"
    vsid_gateway_object_uids: dict[int, str] = Field(
        default_factory=dict,
        title="VSID to object uid overrides",
        description=(
            "Empty: each VSID maps to the virtual system object whose name equals the VS name "
            "in vsx stat -v; an entry: used as typed for its VSID"
        ),
    )
    # The SSH account itself must already open an Expert shell.  The collector
    # never invokes `expert`, answers an escalation prompt, or changes privilege.
    expert_shell_account: str = Field(min_length=1)
    read_only_profile: Literal["checkpoint-gaia-vsx-expert-account-r81.20-v1"] = (
        "checkpoint-gaia-vsx-expert-account-r81.20-v1"
    )
    # The platform sets this field from the row of the management source when it builds
    # the collector (`CpGatewayCollector.link_sources`). The keys are `source` and
    # either `scope`, `host` and `domain`, or `problem`.
    management_link: dict[str, str] = Field(default_factory=dict, exclude=True)

    @property
    def effective_observation_uid(self) -> str:
        return self.observation_uid or self.source_name or self.host or "appliance"

    @property
    def authority_fallback(self) -> str:
        """The scope of the authority when the management source is not linked and no
        scope override is set. The scope uses the typed management host and domain.
        Without a typed host, the name of the management source stands for the host."""
        host = self.management_host or self.management_source or "unknown"
        return scope_of(host, self.management_domain)

    @model_validator(mode="after")
    def _require_expert_login(self) -> CpGatewayConfig:
        if self.expert_shell_account != self.auth.username:
            raise ValueError("expert_shell_account must match the configured SSH username")
        return self

    @model_validator(mode="after")
    def _require_an_identity_source(self) -> CpGatewayConfig:
        if not self.management_source and not (self.management_authority_uid and self.appliance_uid):
            raise ValueError(
                "management_source is required unless management_authority_uid and appliance_uid are both set"
            )
        return self


def gateway_scope(config: CpGatewayConfig) -> str:
    """The retirement partition of one Gaia source, built from the SSH host and the
    observation. Both are known before an identity is resolved."""
    subject = uid.slug(config.host or config.source_name or "appliance")
    return f"checkpoint-gateway:{subject}:{uid.slug(config.effective_observation_uid)}"


def appliance_label(config: CpGatewayConfig) -> str:
    """The label of this appliance in warnings, the source name and the host."""
    return f"{config.source_name or 'checkpoint_gateway'}/{config.host}"


def observe(raw: Mapping[str, Any]) -> GaiaObservation:
    """The hostname and the virtual system names that the appliance reported in the
    payload.
    """
    return GaiaObservation(
        hostname=parse_hostname(str(raw.get(HOSTNAME_COMMAND) or "")),
        vs_names=parse_vs_names(str(raw.get(VSX_STAT_COMMAND) or "")),
    )


def _context_vsids(raw: Mapping[str, Any]) -> list[int]:
    contexts = raw.get("contexts")
    if not isinstance(contexts, Mapping):
        return []
    vsids: list[int] = []
    for key, value in contexts.items():
        try:
            vsids.append(int(value.get("vsid", key) if isinstance(value, Mapping) else key))
        except (TypeError, ValueError):
            continue
    return vsids


def resolve_gateway_identity(
    raw: Mapping[str, Any], config: CpGatewayConfig, inventory: ManagementInventory | None
) -> GatewayIdentity:
    """The identity this payload's contexts are written under (checkpoint_identity)."""
    return resolve_identity(
        appliance=appliance_label(config),
        host=config.host,
        vsids=_context_vsids(raw),
        observed=observe(raw),
        inventory=inventory,
        authority_override=config.management_authority_uid,
        authority_fallback=config.authority_fallback,
        appliance_override=config.appliance_uid,
        domain_override=config.management_domain_uid,
        vs_overrides=config.vsid_gateway_object_uids,
    )


def gateway_release(raw: Mapping[str, Any], config: CpGatewayConfig) -> str:
    """The Gaia release of the Device, the typed override or else the release in the
    `show version` output."""
    return config.gateway_release or parse_release(str(raw.get(VERSION_COMMAND) or ""))


@register
class CpGatewayCollector(SshCliCollector):
    """Capture VSX contexts serially so shell selection cannot bleed between reads."""

    name: ClassVar[str] = "checkpoint_gateway"
    ConfigModel: ClassVar[type[CpGatewayConfig]] = CpGatewayConfig
    KIND: ClassVar[str] = "group"
    COMMANDS: ClassVar[tuple[str, ...]] = (VERSION_COMMAND, HOSTNAME_COMMAND, VSX_STAT_COMMAND)
    OPTIONAL_COMMANDS: ClassVar[dict[str, str]] = {HOSTNAME_COMMAND: "", VSX_STAT_COMMAND: ""}
    AUTHORITATIVE_SECTIONS: ClassVar[tuple[str, ...]] = ("show version osedition",)
    SIDE_TABLES: ClassVar[tuple[str, ...]] = ("rib", "arp")
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "interfaces": ("Interface", "VrfInstance", "IpAddress", "Prefix"),
        "installation": (),
        "routes": (),
        "neighbors": ("Endpoint",),
        "topology": ("Port", "Lag", "VlanInstance", "BridgeDomain"),
        "bgp": ("RoutingProcess", "BgpSession", "RoutePolicy", "RoutePolicyEntry"),
    }
    # A change in the identity inputs defeats the unchanged-payload skip (base.py `raw_sha`).
    NORMALIZATION_CONFIG_KEYS: ClassVar[tuple[str, ...]] = (
        "management_source",
        "management_link",
        "management_authority_uid",
        "management_domain_uid",
        "appliance_uid",
        "vsid_gateway_object_uids",
        "effective_observation_uid",
        "gateway_release",
        "cluster_mode",
    )
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {"vsx": "3", "iface_uid": uid.IFACE_UID_VERSION}

    def __init__(self, config: CpGatewayConfig, settings):
        super().__init__(config, settings)
        self.scope = gateway_scope(config)
        self._inventory: ManagementInventory | None = None

    @classmethod
    def link_sources(cls, payload: dict[str, Any], sources: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve `management_source` to the management row's host, domain
        and scope string.

        The `host` and `domain` of the row decide the scope (collectors/checkpoint.py
        `scope_of`) and are stored beside it in `management_link`. A name that
        matches no row, or a row of another type, is stored as `problem`.
        """
        name = str(payload.get("management_source") or "")
        if not name:
            return payload
        row = sources.get(name)
        if row is None:
            link = {"source": name, "problem": f"no source named {name!r} is configured"}
        elif getattr(row, "type", "") != "checkpoint":
            link = {
                "source": name,
                "problem": (
                    f"source {name!r} has type {getattr(row, 'type', '')!r}; "
                    "only a checkpoint management source can be linked"
                ),
            }
        else:
            config = getattr(row, "config", None) or {}
            host = str(config.get("host") or "")
            domain = str(config.get("domain") or "")
            link = {"source": name, "host": host, "domain": domain, "scope": scope_of(host, domain)}
        payload["management_link"] = link
        return payload

    def management_inventory(self) -> ManagementInventory | None:
        """The scope and the last stored gateway list of the linked management source.

        The result is None when the source names no management source. The gateway list
        is read from the newest raw payload of the management source. A missing link, a
        source that was never collected or an unreadable payload sets `problem`, and the
        identity resolution records it as a warning. The inventory is read once per
        collector instance.
        """
        name = self.config.management_source
        if not name:
            return None
        if self._inventory is not None:
            return self._inventory
        link = self.config.management_link
        scope = str(link.get("scope") or "")
        problem = str(link.get("problem") or "")
        if not link:
            problem = "the collector was built without the source rows; the management source was not linked"
        objects = ()
        if not problem:
            settings = getattr(self, "settings", None)
            if settings is None:
                problem = "no settings, so the raw store of the management source cannot be read"
            else:
                path = rawstore.latest_path(settings.raw_dir, name)
                if path is None:
                    problem = f"management source {name!r} has no collected payload yet"
                else:
                    try:
                        objects = gateway_objects(rawstore.read(path, crypto.dek(settings)))
                    except Exception as exc:
                        logger.warning("checkpoint_gateway: management payload %s unreadable: %s", path, exc)
                        problem = (
                            f"the last payload of management source {name!r} could not be read: "
                            f"{type(exc).__name__}: {exc}"
                        )
                    else:
                        if not objects:
                            problem = f"the last payload of management source {name!r} has no gateway objects"
        self._inventory = ManagementInventory(
            source=name,
            scope=scope,
            domain=str(link.get("domain") or ""),
            objects=objects,
            problem=problem,
        )
        return self._inventory

    def gateway_identity(self, raw: Mapping[str, Any]) -> GatewayIdentity:
        return resolve_gateway_identity(raw, self.config, self.management_inventory())

    def normalization_inputs(self) -> dict[str, Any] | None:
        """Add the management inventory to the inputs of the change hash. A management
        source collected after this appliance, or a renamed object, loads the appliance
        again even when the payload of the appliance is unchanged. The result includes
        the base inputs (the identity registry generation)."""
        inputs = super().normalization_inputs() or {}
        inventory = self.management_inventory()
        if inventory is None:
            return inputs or None
        return {
            **inputs,
            "management": {
                "source": inventory.source,
                "scope": inventory.scope,
                "problem": inventory.problem,
                "objects": [[o.uid, o.name, o.ipv4, o.type] for o in inventory.objects],
            },
        }

    def probe(self) -> str:
        return self._run(VERSION_COMMAND).splitlines()[0]

    async def _afetch_over(self, session) -> dict[str, Any]:
        raw = await super()._afetch_over(session)
        vsids = self.config.gateway_contexts or tuple(
            int(match.group(1))
            for line in str(raw.get(VSX_STAT_COMMAND, "")).splitlines()
            if (match := _VSID.match(line)) is not None
        )
        contexts: dict[str, dict[str, Any]] = {}
        outcomes = raw.setdefault(RAW_OUTCOMES_KEY, {})
        for vsid in sorted(set(vsids)):
            # Each operation includes its own selection. No mutable interactive
            # shell is shared across VS contexts or concurrent collectors.
            section: dict[str, Any] = {"vsid": vsid}
            for key, command in (
                ("interfaces", "ip -j address show"),
                ("routes4", "ip -j route show table all"),
                ("routes6", "ip -6 -j route show table all"),
                ("installation", "fw stat -s"),
                ("links", "ip -d -j link show"),
                ("neighbors4", "ip -4 -j neigh show"),
                ("neighbors6", "ip -6 -j neigh show"),
                ("cluster", "cphaprob state"),
                ("proxy_arp", "fw ctl arp -n"),
                ("fw_interfaces", "fw getifs"),
                ("bridge_groups", "clish -c 'show bridging groups'"),
                ("bridge_members", "brctl show"),
                *(
                    (
                        ("bgp_as", "clish -c 'show as'"),
                        ("bgp_peers", "clish -c 'show bgp peers'"),
                        ("bgp_config", "clish -c 'show configuration bgp'"),
                        ("bgp_routemaps", "clish -c 'show configuration routemaps'"),
                    )
                    if self.config.capture_bgp
                    else ()
                ),
            ):
                json_section = key in {
                    "interfaces",
                    "routes4",
                    "routes6",
                    "links",
                    "neighbors4",
                    "neighbors6",
                }
                # `check_stop` reads the stop flag of the run before each command. It
                # runs outside the `try` below, which would handle a `CollectionStopped`
                # as a `RuntimeError` (`SshCliCollector._afetch_over`).
                self.check_stop()
                try:
                    value = await session.run(_expert_command(vsid, command))
                    parsed = json.loads(value) if json_section else value
                    if json_section and (
                        not isinstance(parsed, list) or any(not isinstance(row, dict) for row in parsed)
                    ):
                        raise ValueError("expected a JSON array of records")
                    # Routing config lines with an MD5 secret (` authtype `) are
                    # dropped, also from the encrypted raw storage.
                    if key == "bgp_config":
                        parsed = "\n".join(line for line in value.splitlines() if " authtype " not in line)
                    section[key] = parsed
                    outcomes[f"vs:{vsid}:{key}"] = {"status": "ok"}
                except (RuntimeError, ValueError) as exc:
                    section[key] = [] if json_section else ""
                    status, detail = classify_command_failure(exc)
                    outcomes[f"vs:{vsid}:{key}"] = {"status": status, "detail": detail}
                    if json_section and key in TEXT_COMMANDS:
                        try:
                            text_output = await session.run(_expert_command(vsid, TEXT_COMMANDS[key]))
                            section[f"{key}_text"] = text_output
                            section[key] = parse_iproute_text(key, text_output)
                            outcomes[f"vs:{vsid}:{key}"] = {
                                "status": "ok",
                                "detail": "iproute2 text fallback",
                            }
                        except (RuntimeError, ValueError, IndexError) as fallback_error:
                            status, detail = classify_command_failure(fallback_error)
                            outcomes[f"vs:{vsid}:{key}"] = {"status": status, "detail": detail}
            # The address list holds only numbered interfaces. The link inventory adds
            # the unnumbered warp and bridge interfaces.
            named = {r["ifname"] for r in section.get("interfaces", []) if "ifname" in r}
            for link in section.get("links", []):
                if link.get("ifname") and link["ifname"] not in named:
                    section["interfaces"].append(dict(link, addr_info=[]))
            section["neighbors"] = section.get("neighbors4", []) + section.get("neighbors6", [])
            contexts[str(vsid)] = section
        raw["contexts"] = contexts
        if self.config.evidence_file:
            identity = self.gateway_identity(raw)
            raw["vsx_evidence"] = read_evidence(
                self.config.evidence_file, identity.appliance_uid, self.config.effective_observation_uid
            )
        return raw

    def normalize(self, raw: dict[str, Any]) -> Batch:
        fabric = (
            self.settings.l2fabric_of(self.config.source_name, self.config.l2fabric)
            if self.settings is not None
            else self.config.effective_l2fabric
        )
        return normalize_checkpoint_gateway(
            raw, self.config, self.gateway_identity(raw), l2fabric=fabric, resolver=self.identity
        )

    def side_tables(self, raw: dict[str, Any]) -> dict[str, list[dict]]:
        identity = self.gateway_identity(raw)
        return {
            "rib": gateway_rib_rows(raw, self.config, identity, self.identity),
            "arp": gateway_neighbor_rows(raw, self.config, identity, self.identity),
        }

    def table_outcomes(self, raw: dict[str, Any]) -> dict[str, TableOutcome]:
        result = self._rib_outcomes(raw)
        status = _captured_section(raw, ("neighbors4", "neighbors6"), "unknown")
        if status != "ok" or _context_gaps(raw, self.config, self.gateway_identity(raw)):
            result["arp"] = TableOutcome(status="partial", detail="VS ARP/ND coverage incomplete")
        return result

    def _rib_outcomes(self, raw: dict[str, Any]) -> dict[str, TableOutcome]:
        outcomes = raw.get(RAW_OUTCOMES_KEY)
        if not isinstance(outcomes, Mapping):
            outcomes = {}
        failed = [
            entry
            for key, entry in outcomes.items()
            if (str(key).endswith(":routes4") or str(key).endswith(":routes6"))
            and isinstance(entry, Mapping)
            and entry.get("status") != "ok"
        ]
        if failed:
            return {"rib": TableOutcome(status="partial", detail="one or more VS RIB reads failed")}
        structural = _context_gaps(raw, self.config, self.gateway_identity(raw))
        if structural:
            return {"rib": TableOutcome(status="partial", detail="; ".join(structural))}
        gaps = tuple(
            gap
            for context in (raw.get("contexts") or {}).values()
            if isinstance(context, Mapping)
            for gap in _route_gaps(context)
        )
        if gaps:
            return {"rib": TableOutcome(status="partial", detail="; ".join(sorted(set(gaps))))}
        return {}


def _expert_command(vsid: int, command: str) -> str:
    """Return one Expert shell command that selects the VSID with `vsenv` and runs
    `command`.
    """
    if type(vsid) is not int or vsid < 0:
        raise ValueError("VSID must be a nonnegative integer")
    if command.startswith("clish -c 'show ") and command.endswith("'"):
        # Each clish process has its own context. A clish invocation does not select the
        # context of a later process. The command selects the virtual system and reads
        # in one clish invocation.
        statement = command[len("clish -c '") : -1]
        command = f"clish -c 'set virtual-system {vsid}; {statement}'"
    return f"vsenv {vsid} >/dev/null && {command}"


def _instance(identity: GatewayIdentity, authority: FirewallAuthority, vsid: int) -> FirewallInstance | None:
    gateway_uid = identity.vs_object_uids.get(vsid)
    if not isinstance(gateway_uid, str) or not gateway_uid or gateway_uid.strip() != gateway_uid:
        return None
    return FirewallInstance.authoritative(authority, gateway_uid)


def _placement(
    config: CpGatewayConfig, identity: GatewayIdentity
) -> tuple[FirewallAuthority, PhysicalAppliance]:
    """(authority, appliance) for one resolved identity."""
    authority = FirewallAuthority(config.estate, identity.authority, identity.domain)
    appliance = PhysicalAppliance(config.estate, identity.authority, identity.appliance_uid)
    return authority, appliance


def _device_uid(raw: Mapping[str, Any], identity: GatewayIdentity, resolver: DeviceResolver | None) -> str:
    """The appliance Device uid. The registry resolves the ref that the management
    source resolves for the same gateway object (checkpoint.py `normalize_checkpoint`).
    Both sources write one Device. None selects a `MemoryResolver`."""
    return (resolver or MemoryResolver()).resolve_device(
        "ref", f"{identity.authority}:{identity.appliance_uid}", _hostname(raw)
    )


def _hostname(raw: Mapping[str, Any]) -> str | None:
    """The hostname that `show hostname` printed, or None."""
    return parse_hostname(str(raw.get(HOSTNAME_COMMAND) or "")) or None


def _route_rows(
    value: Mapping[str, Any], vrf_uid: str, device_uid: str, vrf_name: str
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    sources: tuple[tuple[str, int | None], ...] = (
        (
            ("routes4", 4),
            ("routes6", 6),
        )
        if "routes4" in value or "routes6" in value
        else (("routes", None),)
    )
    for field, expected_af in sources:
        for raw in value.get(field, ()) or ():
            if not isinstance(raw, Mapping):
                continue
            table = raw.get("table")
            if table not in (None, "main", 254, "254"):
                # A route of a non-main policy table is skipped. Such a table needs its
                # own mapped VrfContext and is not part of the main FIB of the VS.
                continue
            if str(raw.get("type") or "").lower() in {"local", "broadcast"}:
                continue
            alternatives = raw.get("nexthops")
            if alternatives is not None:
                if not isinstance(alternatives, list) or not alternatives:
                    continue
                candidates = [
                    {**raw, **hop}
                    for hop in alternatives
                    if isinstance(hop, Mapping)
                    and (isinstance(hop.get("gateway"), str) or isinstance(hop.get("dev"), str))
                ]
                if len(candidates) != len(alternatives):
                    continue
            else:
                candidates = [raw]
            for raw in candidates:
                destination = raw.get("dst")
                if not isinstance(destination, str):
                    continue
                if destination == "default":
                    destination = "::/0" if expected_af == 6 else "0.0.0.0/0"
                try:
                    prefix = ipaddress.ip_network(destination, strict=False)
                except ValueError:
                    continue
                if expected_af is not None and prefix.version != expected_af:
                    continue
                next_hop = raw.get("gateway")
                if not isinstance(next_hop, str):
                    next_hop = None
                interface = raw.get("dev")
                if not isinstance(interface, str):
                    interface = None
                kind = str(raw.get("type") or "").lower()
                discard = kind if kind in {"blackhole", "unreachable", "prohibit"} else None
                try:
                    metric = int(raw["metric"]) if raw.get("metric") is not None else None
                except (TypeError, ValueError):
                    metric = None
                lo, hi, prefixlen, af = prefix_bounds(str(prefix))
                rows.append(
                    {
                        "device_uid": device_uid,
                        "vrf": vrf_name,
                        "context_uid": vrf_uid,
                        "prefix": str(prefix),
                        "next_hop": next_hop,
                        "next_hop_context_uid": None,
                        "interface": interface,
                        "protocol": str(raw.get("protocol") or "kernel"),
                        "discard": discard,
                        "metric": metric,
                        "af": af,
                        "prefixlen": prefixlen,
                        "lo": lo,
                        "hi": hi,
                    }
                )
    return rows


def _route_gaps(value: Mapping[str, Any]) -> tuple[str, ...]:
    gaps: set[str] = set()
    fields = ("routes4", "routes6") if "routes4" in value or "routes6" in value else ("routes",)
    for field in fields:
        for raw in value.get(field, ()) or ():
            if not isinstance(raw, Mapping):
                gaps.add("malformed route row")
                continue
            if str(raw.get("type") or "").lower() in {"local", "broadcast"}:
                continue
            if raw.get("table") not in (None, "main", 254, "254"):
                gaps.add(f"unmapped forwarding table {raw.get('table')!r}")
            alternatives = raw.get("nexthops")
            if alternatives is not None and (
                not isinstance(alternatives, list)
                or not alternatives
                or any(
                    not isinstance(hop, Mapping)
                    or not (isinstance(hop.get("gateway"), str) or isinstance(hop.get("dev"), str))
                    for hop in alternatives
                )
            ):
                gaps.add("incomplete multipath route")
    return tuple(sorted(gaps))


def gateway_rib_rows(
    raw: Mapping[str, Any],
    config: CpGatewayConfig,
    identity: GatewayIdentity | None = None,
    resolver: DeviceResolver | None = None,
) -> list[dict[str, Any]]:
    if identity is None:
        identity = resolve_gateway_identity(raw, config, None)
    authority, appliance = _placement(config, identity)
    device_uid = _device_uid(raw, identity, resolver)
    contexts = raw.get("contexts") if isinstance(raw.get("contexts"), Mapping) else {}
    rows: list[dict[str, Any]] = []
    for key, value in contexts.items():
        if not isinstance(value, Mapping):
            continue
        try:
            vsid = QualifiedVsid(appliance, config.effective_observation_uid, int(value.get("vsid", key)))
        except (TypeError, ValueError):
            continue
        instance = _instance(identity, authority, vsid.value)
        if instance is None:
            continue
        if context_kind(raw, vsid.value, value) in {"bridge", "virtual-switch", "management"}:
            continue
        vrf_name = str(value.get("vrf_uid") or f"vs:{vsid.value}")
        rows.extend(
            _route_rows(value, VrfContext(instance.uid, f"{device_uid}:{vrf_name}").uid, device_uid, vrf_name)
        )
    return rows


def gateway_neighbor_rows(
    raw: Mapping[str, Any],
    config: CpGatewayConfig,
    identity: GatewayIdentity | None = None,
    resolver: DeviceResolver | None = None,
) -> list[dict[str, Any]]:
    """ARP and IPv6 ND rows use the same device and context keys as the RIB of the VS.

    A FAILED or INCOMPLETE neighbor is skipped. A STALE neighbor is kept. STALE is a
    valid Linux neighbor state.
    """
    identity = identity or resolve_gateway_identity(raw, config, None)
    authority, _appliance = _placement(config, identity)
    device_uid = _device_uid(raw, identity, resolver)
    contexts = raw.get("contexts")
    if not isinstance(contexts, Mapping):
        return []
    rows: list[dict[str, Any]] = []
    for key, value in contexts.items():
        if not isinstance(value, Mapping):
            continue
        try:
            instance = _instance(identity, authority, int(value.get("vsid", key)))
        except (TypeError, ValueError):
            continue
        if instance is None:
            continue
        vrf_name = str(value.get("vrf_uid") or f"vs:{value.get('vsid', key)}")
        context_uid = VrfContext(instance.uid, f"{device_uid}:{vrf_name}").uid
        for neighbor in value.get("neighbors", ()) or ():
            if not isinstance(neighbor, Mapping):
                continue
            state = neighbor.get("state", ())
            states = {str(s).upper() for s in (state if isinstance(state, list) else [state])}
            if states & {"FAILED", "INCOMPLETE"}:
                continue
            try:
                address = ipaddress.ip_address(neighbor.get("dst", ""))
            except ValueError:
                continue
            mac = canonical_mac(neighbor.get("lladdr"))
            interface = neighbor.get("dev")
            if mac and isinstance(interface, str) and interface:
                rows.append(
                    {
                        "device_uid": device_uid,
                        "context_uid": context_uid,
                        "vrf": vrf_name,
                        "ip": str(address),
                        "mac": mac,
                        "interface_name": interface,
                        "af": address.version,
                    }
                )
    return rows


def _context_gaps(
    raw: Mapping[str, Any], config: CpGatewayConfig, identity: GatewayIdentity | None = None
) -> tuple[str, ...]:
    contexts = raw.get("contexts")
    if not isinstance(contexts, Mapping) or not contexts:
        return ("gateway contexts missing, empty or malformed; VS discovery is not complete",)
    if identity is None:
        identity = resolve_gateway_identity(raw, config, None)
    authority, appliance = _placement(config, identity)
    gaps: list[str] = []
    expected = set(config.gateway_contexts) or set(observe(raw).vs_names)
    observed = set(_context_vsids(raw))
    for missing in sorted(expected - observed):
        gaps.append(f"context {missing} was discovered/configured but not captured")
    for key, value in contexts.items():
        if not isinstance(value, Mapping):
            gaps.append(f"context {key} malformed")
            continue
        try:
            vsid = QualifiedVsid(appliance, config.effective_observation_uid, int(value.get("vsid", key)))
        except (TypeError, ValueError):
            gaps.append(f"context {key} has invalid VSID")
            continue
        if _instance(identity, authority, vsid.value) is None:
            gaps.append(f"context {vsid.value} lacks an authoritative management-object mapping")
        for field in ("interfaces", "links", "routes", "routes4", "routes6", "neighbors"):
            if field in value and (
                not isinstance(value[field], list)
                or any(not isinstance(row, Mapping) for row in value[field])
            ):
                gaps.append(f"context {vsid.value} has malformed {field}")
    return tuple(sorted(set(gaps)))


def _captured_section(
    raw: Mapping[str, Any], fields: tuple[str, ...], fallback: SectionStatus
) -> SectionStatus:
    outcomes = raw.get(RAW_OUTCOMES_KEY)
    if not isinstance(outcomes, Mapping):
        return fallback
    statuses = [
        str(entry.get("status"))
        for key, entry in outcomes.items()
        if any(str(key).endswith(f":{field}") for field in fields) and isinstance(entry, Mapping)
    ]
    if not statuses:
        return fallback
    for status in ("failed", "unauthorized", "malformed", "partial", "unsupported"):
        if status in statuses:
            return cast(SectionStatus, status)
    return "ok" if all(status == "ok" for status in statuses) else "unknown"


def normalize_checkpoint_gateway(
    raw: Mapping[str, Any],
    config: CpGatewayConfig,
    identity: GatewayIdentity | None = None,
    *,
    l2fabric: str | None = None,
    resolver: DeviceResolver | None = None,
) -> Batch:
    """Project only context-qualified observed gateway state into graph labels.

    `identity` is the result of `resolve_gateway_identity` for this payload.
    Without one, the typed overrides alone decide the identity, as on the
    offline and fixture path. The batch holds the warnings of the identity.
    `resolver` is the device identity registry (`Collector.identity`) that
    gives the appliance its Device uid (`_device_uid`). None selects a
    `MemoryResolver`.
    """
    if identity is None:
        identity = resolve_gateway_identity(raw, config, None)
    authority, appliance = _placement(config, identity)
    device_uid = _device_uid(raw, identity, resolver)
    evidence = raw.get("vsx_evidence") or {}
    if evidence:
        parsed_evidence = VsxEvidence.model_validate({k: v for k, v in evidence.items() if k != "sha256"})
        if (
            parsed_evidence.appliance_uid != identity.appliance_uid
            or parsed_evidence.observation_uid != config.effective_observation_uid
        ):
            raise ValueError("VSX evidence belongs to another appliance/observation")
    installation_gaps: list[str] = []
    builder = GraphBuilder()
    device = builder.node(
        "Device",
        device_uid,
        role="firewall",
        platform="checkpoint-gaia",
        os_version=gateway_release(raw, config) or None,
        observation_uid=config.effective_observation_uid,
        hostname=_hostname(raw),
    )
    contexts = raw.get("contexts") if isinstance(raw.get("contexts"), Mapping) else {}
    failures: list[str] = list(_context_gaps(raw, config, identity))
    route_gaps: list[str] = []
    installed = 0
    routes = 0
    topology_gaps: list[str] = []
    topology_contexts: dict[int, tuple[str, str, dict[str, str]]] = {}
    bgp_gaps: list[str] = []
    for key, value in contexts.items():
        if not isinstance(value, Mapping):
            failures.append(f"context {key} malformed")
            continue
        try:
            vsid = QualifiedVsid(appliance, config.effective_observation_uid, int(value.get("vsid", key)))
        except (TypeError, ValueError):
            failures.append(f"context {key} has invalid VSID")
            continue
        instance = _instance(identity, authority, vsid.value)
        if instance is None:
            failures.append(f"context {vsid.value} lacks an authoritative management-object mapping")
            continue
        kind = context_kind(raw, vsid.value, value)
        state = cluster_state(str(value.get("cluster", "")))
        clustered = config.cluster_mode == "cluster" or (
            config.cluster_mode == "auto"
            and (
                "Cluster" in identity.appliance_type
                or "cluster" in identity.appliance_type
                or "Cluster Mode:" in str(value.get("cluster", ""))
            )
        )
        if config.cluster_mode == "standalone":
            state = "standalone"
        # Virtual routers and switches do not enforce firewall policy.
        instance_label = "FirewallInstance" if kind in {"virtual-system", "bridge"} else "Device"
        instance_node = builder.node(
            instance_label,
            instance.uid,
            gateway_object_uid=instance.gateway_object_uid,
            authority=identity.authority,
            domain=identity.domain,
            kind=kind,
            role={"virtual-router": "router", "virtual-switch": "switch", "management": "management"}.get(
                kind
            )
            if instance_label == "Device"
            else None,
            name=observe(raw).vs_names.get(vsid.value),
        )
        builder.rel(
            "RUNS_ON",
            instance_label,
            instance_node,
            "Device",
            device,
            vsid=vsid.value,
            state=state,
            observation_uid=config.effective_observation_uid,
        )
        vrf_name = str(value.get("vrf_uid") or f"vs:{vsid.value}")
        vrf = VrfContext(instance.uid, f"{device_uid}:{vrf_name}")
        vrf_node = builder.node(
            "VrfInstance",
            vrf.uid,
            name=vrf_name,
            firewall_instance_uid=instance.uid,
            authority=identity.authority,
            domain=identity.domain,
        )
        builder.rel("OWNED_BY", "VrfInstance", vrf_node, "Device", device)
        builder.rel("IN_CONTEXT", "VrfInstance", vrf_node, instance_label, instance_node)
        interface_uids: dict[str, str] = {}
        for row in value.get("interfaces", []) or []:
            if not isinstance(row, Mapping) or not isinstance(row.get("ifname"), str):
                continue
            interface = InterfaceContext(instance.uid, f"{device_uid}:{row['ifname']}")
            interface_node = builder.node(
                "Interface",
                interface.uid,
                name=row["ifname"],
                vsid=vsid.value,
                mac=canonical_mac(row.get("address")),
                oper_status=str(row.get("operstate", "")).lower() or None,
                admin_up="UP" in row["flags"] if isinstance(row.get("flags"), list) else None,
                mtu=row.get("mtu"),
                vsx_kind=kind,
                firewall_instance_uid=instance.uid,
                vsx_state=state,
                vsx_cluster=clustered,
            )
            interface_uids[row["ifname"]] = interface_node
            builder.rel("ON", "Interface", interface_node, "Device", device)
            builder.rel("IN_VRF", "Interface", interface_node, "VrfInstance", vrf_node)
            builder.rel("IN_CONTEXT", "Interface", interface_node, instance_label, instance_node)
            for address in row.get("addr_info", []) or []:
                if not isinstance(address, Mapping) or not isinstance(address.get("local"), str):
                    continue
                prefixlen = address.get("prefixlen")
                if isinstance(prefixlen, int):
                    ip_node, prefix_node = connected_address(
                        builder,
                        f"{address['local']}/{prefixlen}",
                        anchor=vrf.uid,
                        dom=vrf_name,
                        vrf_uid=vrf_node,
                    )
                    builder.rel(
                        "HAS_IP", "Interface", interface_node, "IpAddress", ip_node, key={"vrf": vrf.uid}
                    )
                    if prefix_node is not None and kind in {"virtual-system", "virtual-router"}:
                        builder.rel(
                            "GATEWAY_FOR",
                            "Interface",
                            interface_node,
                            "Prefix",
                            prefix_node,
                            key={"vrf": vrf.uid},
                        )
        if evidence:
            builder.node("VrfInstance", vrf_node, vsx_runtime_sessions=sessions_for(evidence, vsid.value))
        topology_contexts[vsid.value] = (vrf.uid, kind, interface_uids)
        topology_gaps.extend(
            topology(
                builder,
                value,
                device=device,
                context=vrf.uid,
                interfaces=interface_uids,
                fabric=l2fabric or config.effective_l2fabric,
            )
        )
        for observation in installed_policy(str(value.get("installation", ""))):
            interface_uid = interface_uids.get(observation["interface"])
            if interface_uid:
                builder.node(
                    "Interface",
                    interface_uid,
                    **{
                        f"installed_policy_{observation['direction']}": observation["policy_name"],
                        f"installed_at_{observation['direction']}": observation["installed_at_raw"],
                    },
                )
        peers = bgp_peers(str(value.get("bgp_peers", "")))
        asn = local_as(str(value.get("bgp_as", "")))
        if value.get("bgp_peers") and not peers:
            bgp_gaps.append(f"VS {vsid.value}: BGP output did not establish parsed peer coverage")
        if peers and asn is None:
            bgp_gaps.append(f"VS {vsid.value}: BGP peers observed without a parsed local AS")
        if asn is not None and (peers or value.get("bgp_config")):
            process = builder.node(
                "RoutingProcess",
                uid.routing_process(device, vrf.uid, "bgp"),
                proto="bgp",
                asn=asn,
                platform="checkpoint-gaia",
                origin_config_recorded=False,
                origin_context_gaps=["Gaia BGP origination/policy semantics not compiled"],
            )
            builder.rel("IN_VRF", "RoutingProcess", process, "VrfInstance", vrf_node)
            bgp_gaps.extend(
                project_bgp(
                    builder, value, process=process, context=vrf.uid, asn=asn, observed=peers, vsid=vsid.value
                )
            )
        context_routes = _route_rows(value, vrf.uid, device, vrf_name)
        if kind in {"virtual-switch", "bridge", "management"}:
            # These addresses/routes are not a routed firewall transit table.
            context_routes = []
        route_gaps.extend(_route_gaps(value))
        routes += len(context_routes)
        for route in context_routes:
            prefix = builder.node(
                "Prefix",
                uid.prefix(vrf.uid, route["prefix"]),
                cidr=route["prefix"],
                af=route["af"],
                anchor=vrf.uid,
            )
            builder.rel(
                "LEARNED_ROUTE",
                "VrfInstance",
                vrf_node,
                "Prefix",
                prefix,
                key={"via": f"{route['next_hop'] or ''}|{route['interface'] or ''}"},
                next_hop=route["next_hop"],
                interface=route["interface"],
                protocol=route["protocol"],
                metric=route["metric"],
                discard=route["discard"],
            )
            if route["next_hop"]:
                builder.node(
                    "IpAddress",
                    uid.ip(vrf.uid, route["next_hop"]),
                    ip=route["next_hop"],
                    af=route["af"],
                    anchor=vrf.uid,
                )
            if route["interface"] in interface_uids:
                builder.rel(
                    "VIA",
                    "Prefix",
                    prefix,
                    "Interface",
                    interface_uids[route["interface"]],
                    key={"vrf": vrf.uid},
                )
        observations = (
            list(value.get("installations", []) or []) if kind in {"virtual-system", "bridge"} else []
        )
        if evidence and kind in {"virtual-system", "bridge"}:
            resolved, gaps = installations_for(
                evidence,
                vsid=vsid.value,
                authority=identity.authority,
                gateway=instance.gateway_object_uid,
                observed=installed_policy(str(value.get("installation", ""))),
                interfaces=interface_uids,
            )
            observations.extend(resolved)
            installation_gaps.extend(gaps)
        for observation in observations:
            if not isinstance(observation, Mapping):
                continue
            rulebase_uid = observation.get("rulebase_uid")
            revision = observation.get("installed_revision")
            if not isinstance(rulebase_uid, str) or not isinstance(revision, str):
                continue
            installation_uid = (
                f"cp-install:{instance.uid}:{uid.slug(rulebase_uid)}:{uid.slug(revision)}:{uid.slug(vrf.uid)}"
            )
            installation_node = builder.node(
                "PolicyInstallation",
                installation_uid,
                installed_revision=revision,
                context_uid=vrf.uid,
                observation_uid=config.effective_observation_uid,
            )
            builder.rel(
                "HAS_INSTALLATION", "FirewallInstance", instance_node, "PolicyInstallation", installation_node
            )
            builder.rel("INSTALLS", "PolicyInstallation", installation_node, "FwRulebase", rulebase_uid)
            builder.rel(
                "ENFORCES",
                "FirewallInstance",
                instance_node,
                "FwRulebase",
                rulebase_uid,
                key={
                    "context": vrf.uid,
                    "ingress": observation.get("ingress_interface_uid", "*"),
                    "egress": observation.get("egress_interface_uid", "*"),
                    "af": observation.get("address_family"),
                },
                installed=True,
                ingress_interface_uid=observation.get("ingress_interface_uid"),
                egress_interface_uid=observation.get("egress_interface_uid"),
                address_family=observation.get("address_family"),
                evidence_uid=observation.get("evidence_uid"),
                installed_revision=revision,
                coverage="complete" if observation.get("complete") is True else "partial",
                context_uid=vrf.uid,
                observation_uid=config.effective_observation_uid,
            )
            installed += 1
    topology_gaps.extend(connect_virtual_devices(builder, raw, device=device, contexts=topology_contexts))
    for neighbor in gateway_neighbor_rows(raw, config, identity):
        context_uid = neighbor["context_uid"]
        endpoint = builder.node(
            "Endpoint",
            uid.endpoint(context_uid, neighbor["mac"]),
            mac=neighbor["mac"],
            context_uid=context_uid,
            neighbor_interface=neighbor["interface_name"],
            evidence="arp-nd",
        )
        address = builder.node(
            "IpAddress",
            uid.ip(context_uid, neighbor["ip"]),
            ip=neighbor["ip"],
            af=neighbor["af"],
            anchor=context_uid,
            l3dom=neighbor["vrf"],
        )
        builder.rel("HAS_IP", "Endpoint", endpoint, "IpAddress", address)
    batch = builder.batch("checkpoint_gateway", gateway_scope(config))
    batch.warnings = list(identity.warnings)
    fallback: SectionStatus = "failed" if failures else "ok"
    batch.sections["interfaces"] = SectionOutcome(
        status="failed" if failures else _captured_section(raw, ("interfaces",), fallback),
        row_count=len(contexts),
    )
    route_status = (
        "failed" if failures else _captured_section(raw, ("routes4", "routes6", "routes"), fallback)
    )
    if route_status == "ok" and route_gaps:
        route_status = "partial"
    batch.sections["routes"] = SectionOutcome(
        status=route_status,
        row_count=routes,
        detail="; ".join(sorted(set(route_gaps))),
    )
    batch.sections["installation"] = SectionOutcome(
        status="partial"
        if installation_gaps or (installed and failures)
        else "ok"
        if installed
        else "unknown",
        row_count=installed,
        detail="; ".join(failures + installation_gaps)
        if failures or installation_gaps
        else ""
        if installed
        else "fw stat -s did not prove an exact installed revision",
    )
    batch.sections["neighbors"] = SectionOutcome(
        status="failed" if failures else _captured_section(raw, ("neighbors4", "neighbors6"), "unknown"),
        row_count=len(gateway_neighbor_rows(raw, config, identity)),
    )
    batch.sections["topology"] = SectionOutcome(
        status="partial" if topology_gaps else _captured_section(raw, ("links",), "unknown"),
        detail="; ".join(sorted(set(topology_gaps))),
    )
    batch.sections["bgp"] = SectionOutcome(
        status="partial" if bgp_gaps else _captured_section(raw, ("bgp_as", "bgp_peers"), "unknown"),
        detail="; ".join(bgp_gaps),
    )
    return batch
