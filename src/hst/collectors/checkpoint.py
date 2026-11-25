"""Check Point collector (R8x Web API): rulebases, objects, gateways, NAT.

    mgmt_cli -r true --format json show gateways-and-servers details-level full
    mgmt_cli -r true --format json show access-layers
    mgmt_cli -r true --format json show access-rulebase name "<layer>" \
        details-level full use-object-dictionary true offset 0 limit 100
    # repeat offset until total; save under data/raw/checkpoint/first-contact/
    # and rerun normalize_checkpoint on the captures.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, ClassVar

import httpx
from pydantic import Field

from hst.app import crypto
from hst.app.crypto import SecretKeyError
from hst.core import rawstore, uid
from hst.core.identity import DeviceResolver, MemoryResolver
from hst.core.model import Batch, SectionOutcome
from hst.policy.profiles import CONTEXT_FIELDS, METADATA, RULE_FIELDS

from . import http
from .auth import ApiKeyCredential, TlsConfig, UserPassword
from .base import Collector, SourceConfig, register
from .util import GraphBuilder, offset_paged, renew_deadline

logger = logging.getLogger(__name__)

PAGE_LIMIT = 100

# The login reply holds the session lifetime in `session-timeout`.
SESSION_LIFETIME_S = 600
SESSION_RENEW_FRACTION = 2 / 3

_now = time.monotonic  # test seam


def _transport(config: CpConfig) -> httpx.BaseTransport | None:
    return None  # test seam


def _session_rejected(resp: httpx.Response) -> bool:
    if resp.status_code in (401, 403):
        return True
    if resp.status_code == 400:
        try:
            return resp.json().get("code") == "generic_err_wrong_session_id"
        except ValueError:
            return False
    return False


def _iter_rules(items: list[dict[str, Any]]):
    for it in items:
        if "-section" in it.get("type", ""):
            yield from it.get("rulebase", [])
        else:
            yield it


# FIRST CONTACT: the `type` vocabulary of show-gateways-and-servers is taken from the
# R8x Web API reference and has not been confirmed on a management server. An object of
# a type in GATEWAY_TYPES enforces a policy and becomes a Device with role "firewall".
# An object of a type in MANAGEMENT_TYPES is the management server or a log server. It
# becomes a Device with role "management". It is no policy target and no gateway on a
# path. An object of a type in neither set becomes a Device with role "firewall". Its
# rulebase is bound and a trace judges it.
GATEWAY_TYPES = frozenset(
    {
        "simple-gateway",
        "simple-cluster",
        "cluster-member",
        "CpmiGatewayCluster",
        "CpmiClusterMember",
        "CpmiVsxClusterNetobj",
        "CpmiVsxClusterMember",
        "CpmiVsClusterNetobj",
        "CpmiVsNetobj",
        "CpmiVsxNetobj",
    }
)
MANAGEMENT_TYPES = frozenset({"checkpoint-host", "CpmiHostCkp", "CpmiLogServer", "log-server"})
# FIRST CONTACT: these cluster object types are assumed to have a member list. Each such
# object becomes a RedundancyGroup of kind "cp-cluster" with MEMBER_OF from its member
# Devices. The virtual systems of a VSX cluster are separate gateway objects and are not
# members of the group.
CLUSTER_TYPES = frozenset(
    {"simple-cluster", "CpmiGatewayCluster", "CpmiVsxClusterNetobj", "CpmiVsClusterNetobj"}
)
# Every other access-rule field makes the rule undecided (policy/profiles.py).
_ACCESS_RULE_KEYS = RULE_FIELDS | CONTEXT_FIELDS | METADATA | {"track"}

READ_COMMANDS = {
    "gateways": "show-gateways-and-servers",
    "layers": "show-access-layers",
    "access": "show-access-rulebase",
    "packages": "show-packages",
    "nat": "show-nat-rulebase",
    "versions": "show-api-versions",
    "published": "show-last-published-session",
    "global_properties": "show-global-properties",
}

# FIRST CONTACT: the cluster member object types are assumed. A member is no policy
# target. A package installed on all gateways is installed on the cluster object, which
# lists its members.
CLUSTER_MEMBER_TYPES = frozenset({"cluster-member", "CpmiClusterMember", "CpmiVsxClusterMember"})

# The reply of an accepted connection is matched against the connection table
# before any rule of the policy.
VENDOR_STATE_POLICY = ["established=accept", "related=accept"]

# The side-store table that holds the full API envelope of every rule, layer,
# package and object.
ENVELOPE_TABLE = "checkpoint_envelopes"


class CpConfig(SourceConfig):
    host: str
    port: int = 443
    auth: ApiKeyCredential | UserPassword = Field(discriminator="method")
    domain: str = ""  # MDS domain, or empty for a single-domain SMS
    tls: TlsConfig = TlsConfig()


@register
class CpCollector(Collector):
    name = "checkpoint"
    ConfigModel = CpConfig
    KIND = "orchestrator"

    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {"policy": "3"}
    SIDE_TABLES: ClassVar[tuple[str, ...]] = (ENVELOPE_TABLE,)

    def __init__(self, config: CpConfig, settings):
        super().__init__(config, settings)
        self.scope = scope_of(config.host, config.domain)
        self._renew_at = 0.0  # monotonic deadline that `_login` sets
        # The (payload, envelope rows) of the payload that `normalize` last read.
        # `side_tables` reuses the rows for the same payload.
        self._envelopes: tuple[Any, list[dict[str, str]]] | None = None

    def _client(self) -> httpx.Client:
        c = self.config
        return http.logged_in_client(
            f"https://{c.host}:{c.port}", c.tls, self._login, timeout=120, transport=_transport(c)
        )

    def _login(self, client: httpx.Client) -> None:
        c = self.config
        if isinstance(c.auth, ApiKeyCredential):
            creds: dict[str, Any] = {"api-key": c.auth.key.get_secret_value()}
        else:
            creds = {"user": c.auth.username, "password": c.auth.password.get_secret_value()}
        if c.domain:
            creds["domain"] = c.domain
        creds["read-only"] = True
        resp = client.post("/web_api/login", json=creds)
        if resp.status_code != 200:
            raise RuntimeError(f"Check Point login failed: HTTP {resp.status_code}")
        body = resp.json()
        client.headers["X-chkp-sid"] = body["sid"]
        self._renew_at = renew_deadline(
            _now(), body.get("session-timeout"), default=SESSION_LIFETIME_S, fraction=SESSION_RENEW_FRACTION
        )

    def _relogin(self, client: httpx.Client, why: str) -> None:
        logger.info("checkpoint: %s; renewing the management session", why)
        with contextlib.suppress(httpx.HTTPError):
            client.post("/web_api/logout", json={})
        self._login(client)

    def _post(self, client: httpx.Client, cmd: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if _now() >= self._renew_at:
            self._relogin(client, "session nearing expiry")
        resp = client.post(f"/web_api/{cmd}", json=payload or {})
        if _session_rejected(resp):
            self._relogin(client, f"{cmd} rejected with HTTP {resp.status_code}")
            resp = client.post(f"/web_api/{cmd}", json=payload or {})
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _release(client: httpx.Client) -> None:
        try:
            client.post("/web_api/logout", json={})
        except httpx.HTTPError as exc:
            logger.warning("checkpoint: logout failed (%s); session will idle out", exc)
        finally:
            client.close()

    def _optional(self, client: httpx.Client, cmd: str) -> dict[str, Any]:
        """Return the reply of `cmd`, or an empty dict when the server refuses the read.
        A 401 or 403 is raised.
        """
        try:
            reply = self._post(client, cmd)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                raise
            logger.warning("checkpoint: %s failed (%s)", cmd, exc)
            return {}
        return reply if isinstance(reply, dict) else {}

    def probe(self) -> str:
        client = self._client()
        try:
            v = self._post(client, "show-api-versions")
            return f"login ok: Check Point API {v.get('current-version', '?')} at {self.config.host}"
        finally:
            self._release(client)

    def _cache_dir(self):
        return self.settings.raw_dir / "checkpoint" / "replay-cache"

    @staticmethod
    def _discard(path: Path) -> None:
        path.unlink(missing_ok=True)

    def _cached_pages(self, stem: str, rev: str) -> list[dict[str, Any]] | None:
        """Pages from a replay-cache entry whose revision matches, else None.

        The cache holds full rulebase pages, sealed through rawstore under the
        data key of the raw store (base.py).
        """
        d = self._cache_dir()
        self._discard(d / f"{stem}.json")
        for path in (d / f"{stem}{rawstore.SUFFIX}",):
            if not path.is_file():
                continue
            try:
                stored = rawstore.read(path, key=crypto.dek(self.settings))
                if stored["revision"] == rev:
                    return stored["pages"]
            except (OSError, EOFError, KeyError, ValueError, SecretKeyError):
                logger.warning("checkpoint: replay cache unreadable for %s, refetching", stem)
            self._discard(path)
            return None
        return None

    @staticmethod
    def _revision(layer: dict[str, Any]) -> str | None:
        """The revision of the layer or package, or None when the reply has no usable
        revision. A layer without a revision is not replayed from the cache."""
        return _policy_revision(layer)

    def _paged(self, client: httpx.Client, cmd: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Full pages, offset-paginated until total is covered."""

        def fetch(offset: int) -> tuple[dict[str, Any], int | None]:
            page = self._post(client, cmd, {**payload, "offset": offset, "limit": PAGE_LIMIT})
            total = page.get("total")
            if total is None:
                raise RuntimeError(f"{cmd}: reply missing 'total', cannot verify completeness")
            new_offset = page.get("to", offset + PAGE_LIMIT)
            if new_offset >= total:
                return page, None
            if new_offset <= offset:
                raise RuntimeError("show pagination did not advance")
            return page, new_offset

        return offset_paged(fetch)

    def _paged_items(
        self, client: httpx.Client, cmd: str, key: str, payload: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        return [item for page in self._paged(client, cmd, payload or {}) for item in page.get(key, [])]

    def fetch(self) -> dict[str, Any]:
        client = self._client()
        try:
            api_version = self._optional(client, READ_COMMANDS["versions"]).get("current-version")
            # Every publish creates a new published session.
            published = self._optional(client, READ_COMMANDS["published"]).get("uid")
            gateways = self._paged_items(
                client, READ_COMMANDS["gateways"], "objects", {"details-level": "full"}
            )
            # details-level full returns implicit-cleanup-action and meta-info
            layers = self._paged_items(
                client, READ_COMMANDS["layers"], "access-layers", {"details-level": "full"}
            )
            global_properties = self._optional(client, READ_COMMANDS["global_properties"])
            rulebases: dict[str, list[dict[str, Any]]] = {}
            replayed: list[str] = []
            for layer in layers:
                layer_rev = self._revision(layer)
                rev = (
                    f"{published}|{layer_rev}"
                    if isinstance(published, str) and published and layer_rev
                    else None
                )
                # slug keeps the cache write and the unlink inside the cache dir
                stem = f"{uid.slug(self.scope)}-{uid.slug(layer['uid'])}"
                if rev is not None:
                    cached = self._cached_pages(stem, rev)
                    if cached is not None:
                        rulebases[layer["uid"]] = cached
                        replayed.append(layer["uid"])
                        continue
                pages = self._paged(
                    client,
                    READ_COMMANDS["access"],
                    {"uid": layer["uid"], "details-level": "full", "use-object-dictionary": True},
                )
                rulebases[layer["uid"]] = pages
                if rev is not None:
                    rawstore.write(
                        self.settings.raw_dir / "checkpoint",
                        "replay-cache",
                        stem,
                        {"revision": rev, "pages": pages},
                        key=crypto.dek(self.settings),
                    )
            policy_errors: list[str] = []
            try:
                packages = self._paged_items(
                    client, READ_COMMANDS["packages"], "packages", {"details-level": "full"}
                )
            except httpx.HTTPStatusError as exc:
                logger.warning("checkpoint: show-packages failed (%s)", exc)
                packages = []
                policy_errors.append(f"show-packages: HTTP {exc.response.status_code}")
            package_details: dict[str, dict[str, Any]] = {}
            package_revisions: dict[str, str | None] = {}
            for package in packages:
                package_uid = package.get("uid")
                if not isinstance(package_uid, str):
                    policy_errors.append("show-packages: package without UID")
                    continue
                try:
                    detail = self._post(client, "show-package", {"uid": package_uid, "details-level": "full"})
                except httpx.HTTPError as exc:
                    detail = (
                        f"HTTP {exc.response.status_code}"
                        if isinstance(exc, httpx.HTTPStatusError)
                        else type(exc).__name__
                    )
                    policy_errors.append(f"show-package {package_uid}: {detail}")
                    continue
                if detail.get("uid") != package_uid:
                    policy_errors.append(f"show-package {package_uid}: mismatched UID {detail.get('uid')!r}")
                    continue
                package_details[package_uid] = detail
                package_revisions[package_uid] = self._revision(detail)
            pkg_names = [p["name"] for p in packages if isinstance(p.get("name"), str)]
            # The NAT pages are keyed by package. A NAT rule position orders rules only
            # within the rulebase of one package.
            nat: dict[str, list[dict[str, Any]]] = {}
            for pkg_name in pkg_names:
                try:
                    nat[pkg_name] = self._paged(
                        client,
                        READ_COMMANDS["nat"],
                        {"package": pkg_name, "details-level": "full", "use-object-dictionary": True},
                    )
                except httpx.HTTPStatusError as exc:
                    logger.warning(
                        "checkpoint: show-nat-rulebase failed for package "
                        "%r (%s), continuing with an empty NAT list for that package",
                        pkg_name,
                        exc,
                    )
                    nat[pkg_name] = []
                    policy_errors.append(f"show-nat-rulebase {pkg_name}: HTTP {exc.response.status_code}")
            return {
                "management_domain": self.config.domain,
                "api_version": api_version if isinstance(api_version, str) else None,
                "published_session": published if isinstance(published, str) else None,
                "implied_rules_complete": _implied_rules_complete(global_properties),
                "gateways": gateways,
                "layers": layers,
                "packages": packages,
                "package_details": package_details,
                "package_revisions": package_revisions,
                "rulebases": rulebases,
                "nat": nat,
                "replayed_layers": replayed,
                "policy_section_errors": policy_errors,
            }
        finally:
            self._release(client)

    def normalize(self, raw: dict[str, Any]) -> Batch:
        rows: list[dict[str, str]] = []
        batch = normalize_checkpoint(
            raw, mgmt=self.config.host, domain=self.config.domain, resolver=self.identity, envelope_rows=rows
        )
        self._envelopes = (raw, rows)
        access_rows = sum(len(pages) for pages in raw.get("rulebases", {}).values())
        batch.sections["access"] = SectionOutcome(
            status="ok" if access_rows else "empty", row_count=access_rows
        )
        nat_rows = sum(len(pages) for pages in raw.get("nat", {}).values())
        errors = raw.get("policy_section_errors") or []
        batch.sections["nat"] = SectionOutcome(
            status="failed" if errors else ("ok" if nat_rows else "empty"),
            detail="; ".join(str(error) for error in errors),
            row_count=None if errors else nat_rows,
        )
        batch.sections["installation"] = SectionOutcome(
            status="failed" if errors else "unknown",
            detail=(
                "; ".join(str(error) for error in errors)
                if errors
                else (
                    "Management package targets are configured evidence only; "
                    "Gaia installation observation required"
                )
            ),
        )
        return batch

    def side_tables(self, raw: dict[str, Any]) -> dict[str, list[dict]]:
        held = self._envelopes
        if held is not None and held[0] is raw:
            rows = held[1]
        else:
            rows = []
            normalize_checkpoint(raw, mgmt=self.config.host, domain=self.config.domain, envelope_rows=rows)
        return {ENVELOPE_TABLE: rows}

    def release_payload(self) -> None:
        self._envelopes = None


# Check Point object kinds that this collector cannot express as an address set
# (core/labels.py OPAQUE_PROP).
_CP_OPAQUE_KINDS: dict[str, str] = {
    "access-role": "an access-role identifies users, not addresses",
    "security-zone": "a security-zone object is a zone reference, not an address",
    "dns-domain": "a dns-domain object resolves by name; no address is captured",
    "updatable-object": (
        "an updatable-object's address set is managed by Check Point and not exposed via this API"
    ),
    "dynamic-object": "a dynamic-object's members are resolved by the gateway at runtime, not captured here",
    "wildcard": "a wildcard object matches by mask pattern, not a plain address",
    "group-with-exclusion": "a group-with-exclusion's include/exclude semantics are not modeled",
}


_CP_ADDRESS_KINDS = frozenset({"host", "network"})


# Every other service-* kind is opaque.
_CP_REAL_PROTO_KINDS = frozenset(
    {"service-tcp", "service-udp", "service-icmp", "service-icmp6", "service-sctp"}
)
# A spec outside this grammar marks the object opaque.
_CP_PORT_SPEC_RE = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")


def _cp_leaf_addresses(obj: dict[str, Any]) -> tuple[list[tuple[str, str, int]], list[str], str | None]:
    """The addresses of a non-group object as (targets, ranges, opaque reason). Exactly
    one of the 3 is set.

    A target is a `(kind, value, af)` triple for a RESOLVES_TO edge. `kind` is "cidr" or
    "ip".
    """
    targets: list[tuple[str, str, int]] = []
    if obj.get("ipv4-address"):
        targets.append(("ip", obj["ipv4-address"], 4))
    if obj.get("subnet4") is not None:
        targets.append(("cidr", f"{obj['subnet4']}/{obj['mask-length4']}", 4))
    if obj.get("ipv6-address"):
        targets.append(("ip", obj["ipv6-address"], 6))
    if obj.get("subnet6") is not None:
        targets.append(("cidr", f"{obj['subnet6']}/{obj['mask-length6']}", 6))
    if targets:
        return targets, [], None
    t = obj.get("type", "")
    if t == "address-range":
        ranges = []
        if obj.get("ipv4-address-first") and obj.get("ipv4-address-last"):
            ranges.append(f"{obj['ipv4-address-first']}-{obj['ipv4-address-last']}")
        if obj.get("ipv6-address-first") and obj.get("ipv6-address-last"):
            ranges.append(f"{obj['ipv6-address-first']}-{obj['ipv6-address-last']}")
        if ranges:
            return [], ranges, None
        return [], [], "address-range object carries no first/last address pair"
    if t in _CP_OPAQUE_KINDS:
        return [], [], _CP_OPAQUE_KINDS[t]
    if t in _CP_ADDRESS_KINDS:
        return [], [], f"checkpoint {t} object carries no address in the payload"
    return [], [], f"checkpoint object type {t!r} is not modeled as an address set"


def _write_carriage(
    b: GraphBuilder,
    scope: str,
    obj_uid: str,
    targets: list[tuple[str, str, int]],
    ranges: list[str],
    opaque_reason: str | None,
) -> None:
    """`scope` anchors the Prefix/IpAddress targets."""
    l3dom = f"l3dom:unresolved:{scope}"
    for kind, value, af in targets:
        if kind == "cidr":
            target = b.node("Prefix", uid.prefix(scope, value), cidr=value, af=af, anchor=scope, l3dom=l3dom)
            b.rel("RESOLVES_TO", "NetObject", obj_uid, "Prefix", target)
        else:
            target = b.node("IpAddress", uid.ip(scope, value), ip=value, af=af, anchor=scope, l3dom=l3dom)
            b.rel("RESOLVES_TO", "NetObject", obj_uid, "IpAddress", target)
    if ranges:
        b.node("NetObject", obj_uid, ranges=sorted(set(ranges)))
    if opaque_reason:
        b.node("NetObject", obj_uid, opaque=True, opaque_reason=opaque_reason)


# _GROUP_DEPTH equals hst.simul.fw_overlay._GROUP_DEPTH.
_GROUP_DEPTH = 16


def _group_closure(
    ouid: str,
    objs: dict[str, dict[str, Any]],
    any_uids: set[str],
    seen: set[str],
    depth: int,
) -> tuple[list[tuple[str, str, int]], list[str], bool, list[str]]:
    """The transitive union of a group's non-group members' addresses.

    `seen` holds the group uids already expanded in the walk of this top-level
    group.

    Returns (targets, ranges, opaque, reasons). `opaque` is set, and the
    partial closure is returned, when a member uid is absent from `objs`, a
    member is opaque or unaddressable, or the depth bound is hit.
    """
    targets: list[tuple[str, str, int]] = []
    ranges: list[str] = []
    reasons: list[str] = []
    if depth > _GROUP_DEPTH:
        return targets, ranges, True, [f"group nesting exceeded the depth bound ({_GROUP_DEPTH})"]
    obj = objs[ouid]
    for member in obj.get("members", []) or []:
        if member in any_uids:
            continue
        mobj = objs.get(member)
        if mobj is None:
            reasons.append(f"member {member!r} is not in the object dictionary")
            continue
        if mobj.get("type") == "group":
            if member in seen:
                continue
            seen.add(member)
            m_targets, m_ranges, m_opaque, m_reasons = _group_closure(member, objs, any_uids, seen, depth + 1)
            targets.extend(m_targets)
            ranges.extend(m_ranges)
            if m_opaque:
                reasons.append(f"nested group {member!r} is opaque: {'; '.join(m_reasons)}")
        else:
            m_targets, m_ranges, m_reason = _cp_leaf_addresses(mobj)
            if m_reason:
                reasons.append(f"member {member!r}: {m_reason}")
            targets.extend(m_targets)
            ranges.extend(m_ranges)
    return targets, ranges, bool(reasons), reasons


def scope_of(host: str, domain: str = "") -> str:
    """The scope string of one management source. It is `cp:<host>` for a single-domain
    server and `cp:<host>:<domain>` for an MDS domain. Every Device that the source
    writes has it as `_scope`. The `FirewallInstance.authority` of the Gaia source must
    equal it for the rulebase join."""
    return f"cp:{host}:{domain}" if domain else f"cp:{host}"


def normalize_checkpoint(
    raw: dict[str, Any],
    *,
    mgmt: str,
    domain: str,
    resolver: DeviceResolver | None = None,
    envelope_rows: list[dict[str, str]] | None = None,
) -> Batch:
    """The twin of one management server or MDS domain. `resolver` is the device
    identity registry (`Collector.identity`) that gives each gateway object its Device
    uid. None selects a `MemoryResolver`.

    A node of a rule, layer, package or policy object holds the SHA-256 of its API
    envelope as `checkpoint_envelope_sha`. `envelope_rows`, when given, receives one
    `ENVELOPE_TABLE` row per node (uid, label, envelope_sha, envelope)."""
    resolver = resolver or MemoryResolver()
    b = GraphBuilder()
    scope = scope_of(mgmt, domain)
    envelopes: dict[str, dict[str, str]] = {}

    def cp(api_uid: str) -> str:
        return uid.checkpoint(mgmt, domain, api_uid)

    def envelope(label: str, node_uid: str, value: Any) -> str:
        """Return the SHA-256 of the envelope `value` of `node_uid` and record the row
        for the side store. A node written twice keeps its last envelope."""
        text = json.dumps(value, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(text.encode()).hexdigest()
        envelopes[node_uid] = {"uid": node_uid, "label": label, "envelope_sha": sha, "envelope": text}
        return sha

    gateways = [gw for gw in raw.get("gateways", []) if isinstance(gw, dict) and gw.get("uid")]
    # Device uid by api uid. A cluster member and a package installation target resolve
    # through this map. A reference to an object outside the payload writes no edge.
    devices: dict[str, str] = {}
    for gw in gateways:
        # READ_COMMANDS["gateways"] also returns the management and log servers.
        # The Device is keyed by its source ref, the CP-native api uid.
        # cp_raw_uid ties a Gaia FirewallInstance to this node.
        devices[gw["uid"]] = b.node(
            "Device",
            resolver.resolve_device("ref", f"{scope}:{gw['uid']}", gw.get("name")),
            hostname=gw.get("name"),
            platform="checkpoint",
            role=_gateway_role(gw),
            mgmt_ip=gw.get("ipv4-address"),
            cp_type=gw.get("type"),
            cp_uid=cp(gw["uid"]),
            cp_raw_uid=gw["uid"],
            identities=sorted({x for x in (gw.get("name"), gw.get("ipv4-address")) if x}),
        )

    # One RedundancyGroup per cluster object, for the map. A trace does not read the
    # group of a Check Point cluster. The rulebase is bound to the Device of the cluster
    # object, which the package installation targets reference. A VSX rulebase is found
    # through the context of the ingress interface.
    by_name = {gw["name"]: gw["uid"] for gw in gateways if isinstance(gw.get("name"), str)}
    for gw in gateways:
        if gw.get("type") not in CLUSTER_TYPES:
            continue
        members = _cluster_member_refs(gw, by_name)
        if not members:
            continue
        group = b.node(
            "RedundancyGroup",
            uid.rgrp("cp-cluster", scope, gw.get("name") or gw["uid"]),
            kind="cp-cluster",
            name=gw.get("name"),
            cp_type=gw.get("type"),
            cp_raw_uid=gw["uid"],
        )
        for member_uid in members:
            if member_uid in devices:
                b.rel("MEMBER_OF", "Device", devices[member_uid], "RedundancyGroup", group)

    # An objects-dictionary entry is repeated on every page and layer that references
    # it. `objs` holds one entry per uid. A RulebaseAction entry resolves `rule.action`.
    # Every other entry is a NetObject or SvcObject candidate.
    actions: dict[str, str] = {}
    objs: dict[str, dict[str, Any]] = {}
    for pages in (*raw.get("rulebases", {}).values(), *_nat_by_package(raw).values()):
        for page in pages:
            for obj in page.get("objects-dictionary", []):
                if obj.get("type") == "RulebaseAction":
                    actions[obj["uid"]] = obj.get("name", "").lower()
                objs[obj["uid"]] = obj

    any_uids = {u for u, o in objs.items() if o.get("type") == "CpmiAnyObject"}
    # An application or URL category in an access rule's service column is a SvcObject.
    svc_uids: set[str] = set()
    pending = [
        ouid
        for pages in raw.get("rulebases", {}).values()
        for page in pages
        for rule in _iter_rules(page.get("rulebase", []))
        if rule.get("type") == "access-rule"
        for ouid in rule.get("service", []) or []
    ]
    while pending:
        ouid = pending.pop()
        if ouid in svc_uids or ouid in any_uids or ouid not in objs:
            continue
        svc_uids.add(ouid)
        pending.extend(objs[ouid].get("members", []) or [])
    # The install-on entry "Policy Targets" stands for every target of the policy
    # package. A rule with this entry is installed wherever its layer is installed.
    policy_targets = {u for u, o in objs.items() if o.get("name") == "Policy Targets"}

    for ouid, obj in objs.items():
        if ouid in any_uids or obj.get("type") == "RulebaseAction":
            b.node(
                "CpPolicyObject", cp(ouid), checkpoint_envelope_sha=envelope("CpPolicyObject", cp(ouid), obj)
            )
            continue  # Any is a rule-level flag in the graph projection.
        t = obj.get("type", "")
        if t.startswith("service-") or ouid in svc_uids:
            svc_props: dict[str, Any] = {"name": obj.get("name"), "kind": t}
            if t == "service-group":
                # A service group has no protocol and no ports. The gate unions its
                # MEMBER_OF members. A member that the objects dictionary does not hold
                # has no node, and the match of the group is then not known.
                missing = [
                    str(m) for m in obj.get("members", []) or [] if m not in objs and m not in any_uids
                ]
                if missing:
                    svc_props["opaque"] = True
                    svc_props["opaque_reason"] = (
                        f"service group {obj.get('name')!r} has members not in the objects dictionary: "
                        + ", ".join(missing)
                    )
            elif not t.startswith("service-"):
                svc_props["opaque"] = True
                svc_props["opaque_reason"] = (
                    f"checkpoint {t or 'object'} {obj.get('name')!r} is matched by application control, "
                    "not by protocol and port"
                )
            elif t in _CP_REAL_PROTO_KINDS:
                proto, port = t.removeprefix("service-"), obj.get("port")
                svc_props["proto"] = proto
                svc_props["ports"] = port
                if port and not _CP_PORT_SPEC_RE.match(str(port)):
                    svc_props["opaque"] = True
                    svc_props["opaque_reason"] = f"relational or unparseable port spec: {port!r}"
            else:
                svc_props["opaque"] = True
                svc_props["opaque_reason"] = f"unsupported checkpoint service kind: {t}"
            b.node(
                "SvcObject",
                cp(ouid),
                checkpoint_envelope_sha=envelope("SvcObject", cp(ouid), obj),
                **svc_props,
            )
        else:
            props: dict[str, Any] = {"name": obj.get("name"), "kind": t}
            if obj.get("ipv4-address"):
                props["ip"] = obj["ipv4-address"]
            if obj.get("subnet4") is not None:
                props["cidr"] = f"{obj['subnet4']}/{obj['mask-length4']}"
            if obj.get("ipv6-address"):
                props["ip6"] = obj["ipv6-address"]
            if obj.get("subnet6") is not None:
                props["cidr6"] = f"{obj['subnet6']}/{obj['mask-length6']}"
            netobj_uid = cp(ouid)
            b.node(
                "NetObject",
                netobj_uid,
                checkpoint_envelope_sha=envelope("NetObject", netobj_uid, obj),
                **props,
            )
            if t != "group":
                targets, ranges, opaque_reason = _cp_leaf_addresses(obj)
                _write_carriage(b, scope, netobj_uid, targets, ranges, opaque_reason)

    for ouid, obj in objs.items():
        if ouid in any_uids:
            continue
        for member in obj.get("members", []) or []:
            if member in objs and member not in any_uids:
                label = (
                    "SvcObject"
                    if obj.get("type", "").startswith("service-") or ouid in svc_uids
                    else "NetObject"
                )
                b.rel("MEMBER_OF", label, cp(member), label, cp(ouid))

    for ouid, obj in objs.items():
        if ouid in any_uids or obj.get("type") != "group":
            continue
        targets, ranges, opaque, reasons = _group_closure(ouid, objs, any_uids, {ouid}, 0)
        group_uid = cp(ouid)
        _write_carriage(
            b, scope, group_uid, targets, ranges, "; ".join(dict.fromkeys(reasons)) if opaque else None
        )

    # legacy_binding binds a raw snapshot without package details to every firewall.
    gateway_uids = [devices[gw["uid"]] for gw in gateways if _gateway_role(gw) == "firewall"]
    every_target = _every_policy_target(gateways, by_name)
    package_targets = _package_targets(raw, every_target)
    package_bindings = _package_bindings(package_targets, devices)
    legacy_binding = ("packages" not in raw and "package_details" not in raw) or (
        not raw.get("package_details")
        and any(str(item).startswith("show-package ") for item in raw.get("policy_section_errors", ()))
    )
    # After a failed show-packages, or a failed show-package for a package, no package
    # claims the layers of the packages that were not returned.
    package_unknown = any(
        str(item).startswith(("show-packages:", "show-package "))
        for item in raw.get("policy_section_errors", ())
    )
    claimed_targets = {dev_uid for bound in package_bindings.values() for dev_uid in bound}
    unclaimed_targets = sorted(
        {devices[target] for target in every_target if target in devices} - claimed_targets
    )
    inline_layers = {
        inline
        for pages in raw.get("rulebases", {}).values()
        for page in pages
        for rule in _iter_rules(page.get("rulebase", []))
        if (inline := _uid_of(rule.get("inline-layer"))) is not None
    }
    management_release = _management_release(raw, gateways)

    layer_packages: dict[str, tuple[str, ...]] = {}
    for package_uid, detail in (raw.get("package_details") or {}).items():
        if not isinstance(detail, dict):
            continue
        for layer in detail.get("access-layers", detail.get("access-layers-uid", [])) or []:
            layer_uid = (
                layer if isinstance(layer, str) else layer.get("uid") if isinstance(layer, dict) else None
            )
            if isinstance(layer_uid, str):
                layer_packages.setdefault(layer_uid, ())
                layer_packages[layer_uid] = tuple(sorted({*layer_packages[layer_uid], package_uid}))

    package_nodes: dict[str, str] = {}
    for package_uid, detail in (raw.get("package_details") or {}).items():
        if not isinstance(detail, dict):
            continue
        package_nodes[package_uid] = b.node(
            "CpPolicyPackage",
            cp(f"package:{package_uid}"),
            checkpoint_envelope_sha=envelope("CpPolicyPackage", cp(f"package:{package_uid}"), detail),
            capture_complete=not bool(raw.get("policy_section_errors")),
            implied_complete=raw.get("implied_rules_complete") is True,
            authority_uid=mgmt,
            domain_uid=(
                detail.get("domain", {}).get("uid") if isinstance(detail.get("domain"), dict) else domain
            ),
            management_release=management_release,
            gateway_release=_gateway_release(raw, package_targets.get(package_uid, ((), False))[0], gateways),
            api_version=raw.get("api_version") if isinstance(raw.get("api_version"), str) else None,
        )

    for layer in raw.get("layers", []):
        package_revisions = raw.get("package_revisions") or {}
        associated_packages = layer_packages.get(layer.get("uid", ""), ())
        configured_revision = next(
            (
                package_revisions.get(package_uid)
                for package_uid in associated_packages
                if isinstance(package_revisions.get(package_uid), str)
            ),
            _policy_revision(layer),
        )
        # The layer's implicit cleanup rule decides what no explicit rule matches.
        cleanup = str(layer.get("implicit-cleanup-action") or "").strip().lower()
        default_action = cleanup if cleanup in ("accept", "drop") else None
        rb = b.node(
            "FwRulebase",
            cp(layer["uid"]),
            name=layer.get("name"),
            kind="access",
            vendor="checkpoint",
            match_context="device",
            configured_revision=configured_revision,
            default_action=default_action,
            default_action_unknown=default_action is None,
            global_state_policy=VENDOR_STATE_POLICY,
            state_policy_basis="vendor-default",
            checkpoint_envelope_sha=envelope("FwRulebase", cp(layer["uid"]), layer),
        )
        for package_index, package_uid in enumerate(associated_packages):
            if package_uid in package_nodes:
                b.rel(
                    "HAS_LAYER",
                    "CpPolicyPackage",
                    package_nodes[package_uid],
                    "FwRulebase",
                    rb,
                    position=package_index,
                )
        targets: dict[str, bool] = {}
        for package_uid in associated_packages:
            for dev_uid, approximate in package_bindings.get(package_uid, {}).items():
                targets[dev_uid] = targets.get(dev_uid, False) or approximate
        if package_unknown and layer.get("uid") not in inline_layers:
            for dev_uid in unclaimed_targets:
                targets.setdefault(dev_uid, True)
        if legacy_binding or (
            package_unknown and not associated_packages and layer.get("uid") not in inline_layers
        ):
            for dev_uid in gateway_uids:
                b.rel("ENFORCES", "Device", dev_uid, "FwRulebase", rb, approximate=True)
        else:
            for dev_uid, approximate in sorted(targets.items()):
                if approximate:
                    b.rel("ENFORCES", "Device", dev_uid, "FwRulebase", rb, approximate=True)
                else:
                    b.rel("ENFORCES", "Device", dev_uid, "FwRulebase", rb, configured=True)
        for page in raw.get("rulebases", {}).get(layer["uid"], []):
            for rule in _iter_rules(page.get("rulebase", [])):
                if rule.get("type") != "access-rule":
                    continue
                sources = rule.get("source", [])
                dests = rule.get("destination", [])
                svcs = rule.get("service", [])
                install_on, install_unresolved = _install_on(rule, devices, any_uids | policy_targets)
                # A VPN community, a time object or a content type in its column limits
                # the rule to traffic that the flow tuple cannot decide.
                scoped = [
                    f"its {field} column"
                    for field in ("vpn", "time", "content")
                    if any(_uid_of(v) not in any_uids for v in rule.get(field) or [])
                ]
                # user-check and action-settings make the action depend on what the user
                # does. policy/checkpoint.py reads them in the same way.
                if rule.get("user-check") not in (None, {}, "") or rule.get("action-settings") not in (
                    None,
                    {},
                ):
                    scoped.append("its action settings")
                fields = sorted(str(k) for k in rule if k not in _ACCESS_RULE_KEYS)
                scoped += [f"the field {name!r}" for name in fields]
                r = b.node(
                    "FwRule",
                    cp(rule["uid"]),
                    name=rule.get("name"),
                    position=rule.get("rule-number"),
                    rule_uid=rule.get("uid"),
                    rulebase_uid=layer.get("uid"),
                    action=actions.get(rule.get("action"), str(rule.get("action", ""))).lower(),
                    enabled=rule.get("enabled", True),
                    checkpoint_envelope_sha=envelope("FwRule", cp(rule["uid"]), rule),
                    src_any=bool(sources) and all(s in any_uids for s in sources),
                    dst_any=bool(dests) and all(d in any_uids for d in dests),
                    svc_any=bool(svcs) and all(s in any_uids for s in svcs),
                    src_negate=bool(rule.get("source-negate", False)),
                    dst_negate=bool(rule.get("destination-negate", False)),
                    svc_negate=bool(rule.get("service-negate", False)),
                    install_on=install_on,
                    install_on_unresolved=install_unresolved,
                    states_opaque=bool(scoped),
                    states_opaque_reason=(
                        f"the rule is scoped by {', '.join(scoped)}, which is not modeled" if scoped else None
                    ),
                    # The list is written also when it is empty. An empty list
                    # overwrites the list of an earlier load.
                    unmodeled_fields=fields,
                )
                b.rel("HAS_RULE", "FwRulebase", rb, "FwRule", r)
                for field, rtype, label in (
                    ("source", "SRC", "NetObject"),
                    ("destination", "DST", "NetObject"),
                    ("service", "SVC", "SvcObject"),
                ):
                    for ouid in rule.get(field, []):
                        if ouid in any_uids:
                            continue
                        if ouid not in objs:
                            b.node(
                                label,
                                cp(ouid),
                                opaque=True,
                                opaque_reason=(
                                    f"the {field} entry {ouid!r} of rule {rule.get('uid')!r} "
                                    "is not in the objects dictionary"
                                ),
                            )
                        b.rel(rtype, "FwRule", r, label, cp(ouid))
    _nat_stage(
        b,
        raw,
        cp,
        gateway_uids,
        package_bindings,
        legacy_binding,
        objs,
        any_uids,
        devices=devices,
        everywhere=any_uids | policy_targets,
        package_unknown=package_unknown,
    )
    if envelope_rows is not None:
        envelope_rows.extend(envelopes.values())
    batch = b.batch("checkpoint", scope)
    batch.sections["mtu"] = SectionOutcome(
        status="unsupported",
        detail=(
            "Management API inventory lacks verified Gaia dataplane MTU; "
            "separate read-only Gaia source required"
        ),
    )
    return batch


def _policy_revision(value: dict[str, Any]) -> str | None:
    """Return the policy revision that the API recorded, or None.

    The R8x Web API reports last-modify-time and last-modifier under meta-info. A reply
    that has them at the top level is read in the same way. The string is
    "{posix}|{last-modifier}". A VSX installation observation states its configured and
    installed revisions in this form (checkpoint_evidence.Installation).
    """
    meta = value.get("meta-info")
    holder = meta if isinstance(meta, dict) and isinstance(meta.get("last-modify-time"), dict) else value
    modified = holder.get("last-modify-time") or {}
    if not isinstance(modified, dict) or modified.get("posix") is None:
        return None
    return f"{modified['posix']}|{holder.get('last-modifier', '')}"


def _implied_rules_complete(global_properties: dict[str, Any]) -> bool:
    """Whether the captured rulebases hold every implied rule that applies.

    show-access-rulebase does not return implied rules, and their placement is not
    captured. The capture is complete only when the global properties were read and
    enable no implied rule. FIRST CONTACT: every accept-* key of the `firewall` section
    of show-global-properties is read as one implied-rule switch. The result is False
    for a reply without that section, without a switch, with a switch that is not a
    boolean, or with an enabled switch.
    """
    section = global_properties.get("firewall") if isinstance(global_properties, dict) else None
    if not isinstance(section, dict):
        return False
    switches = [v for k, v in section.items() if str(k).startswith("accept-")]
    return bool(switches) and all(v is False for v in switches)


def _nat_by_package(raw: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    nat = raw.get("nat") or {}
    if isinstance(nat, list):
        return {"Standard": nat} if nat else {}
    return nat


def _gateway_role(gw: dict[str, Any]) -> str:
    return "management" if gw.get("type") in MANAGEMENT_TYPES else "firewall"


def _cluster_member_refs(gw: dict[str, Any], by_name: dict[str, str]) -> list[str]:
    """The management object uids of a cluster object's members, in payload order.

    FIRST CONTACT: with details-level full a cluster object is expected to have
    `cluster-members`, a list of objects with `uid` and `name`, or
    `cluster-member-names`, a list of names. Both are read. A name is resolved against
    the other objects of the same reply. A member that resolves to no object is dropped.
    """
    refs: list[str] = []
    for value in gw.get("cluster-members") or []:
        if isinstance(value, dict):
            member = value.get("uid") or by_name.get(str(value.get("name") or ""))
        else:
            member = by_name.get(str(value))
        if isinstance(member, str) and member not in refs:
            refs.append(member)
    for name in gw.get("cluster-member-names") or []:
        member = by_name.get(str(name))
        if isinstance(member, str) and member not in refs:
            refs.append(member)
    return [ref for ref in refs if ref != gw["uid"]]


def _install_on(
    rule: dict[str, Any], devices: dict[str, str], everywhere: set[str]
) -> tuple[list[str], bool]:
    """(gateways, unresolved) for a rule's install-on column.

    `gateways` holds the management object uids of the gateways that the rule is
    installed on. Each is the `cp_raw_uid` of the Device, RedundancyGroup or virtual
    system of a rulebase binding. The path gate compares them with the owner of that
    binding. The list is empty when the rule is installed wherever its rulebase is. That
    is the case when the column is absent or holds only Any or the Policy Targets of the
    package (`everywhere`).

    `unresolved` is set when an entry is no gateway object of the payload, such as a
    gateway group. The gate then reads the rule as undecided.
    """
    values = [_uid_of(v) for v in rule.get("install-on") or []]
    named = [v for v in values if v not in everywhere]
    gateways = sorted({v for v in named if v is not None and v in devices})
    return gateways, any(v is None or v not in devices for v in named)


def _uid_of(value: Any) -> str | None:
    """The uid of a column entry, given as a uid string or as an object."""
    if isinstance(value, dict):
        value = value.get("uid")
    return value if isinstance(value, str) and value else None


def _every_policy_target(gateways: list[dict[str, Any]], by_name: dict[str, str]) -> tuple[str, ...]:
    """The api uids of every gateway object that a package can be installed on. These
    are the firewalls without the members of a cluster. A cluster member takes the
    policy installed on its cluster object. A management or log server takes no policy."""
    members = {
        member
        for gw in gateways
        if gw.get("type") in CLUSTER_TYPES
        for member in _cluster_member_refs(gw, by_name)
    }
    return tuple(
        gw["uid"]
        for gw in gateways
        if _gateway_role(gw) == "firewall"
        and gw.get("type") not in CLUSTER_MEMBER_TYPES
        and gw["uid"] not in members
    )


def _package_targets(
    raw: dict[str, Any], every_target: tuple[str, ...]
) -> dict[str, tuple[tuple[str, ...], bool]]:
    """(target api uids, installed on all) keyed by package UID.

    show-package states installation-targets as a list of gateway objects,
    or as the string "all" (alone or in a list) for a package installed on
    every gateway. "all" selects `every_target`.
    """
    result: dict[str, tuple[tuple[str, ...], bool]] = {}
    for package_uid, detail in (raw.get("package_details") or {}).items():
        if not isinstance(package_uid, str) or not isinstance(detail, dict):
            continue
        values = detail.get("installation-targets", detail.get("installation-targets-objects", [])) or []
        if isinstance(values, (str, dict)):
            values = [values]
        if any(isinstance(value, str) and value.strip().lower() == "all" for value in values):
            result[package_uid] = (every_target, True)
            continue
        target_uids = [target for value in values if (target := _uid_of(value)) is not None]
        result[package_uid] = (tuple(sorted(set(target_uids))), False)
    return result


def _package_bindings(
    package_targets: dict[str, tuple[tuple[str, ...], bool]], devices: dict[str, str]
) -> dict[str, dict[str, bool]]:
    """The configured targets by package UID, each as a map of Device uid to
    `approximate`.

    `devices` maps the api uid of a gateway object to its Device uid. A target that is
    no gateway object of the payload has no Device and is left out. A gateway holds one
    installed access policy. When 2 packages claim the same gateway, from "all" or from
    explicit targets, the configuration does not decide which package is installed
    there. Both bindings are then approximate. checkpoint_policy of analysis_model
    leaves such a gateway undecided.
    """
    claims: dict[str, int] = {}
    for uids, _all in package_targets.values():
        for target in set(uids):
            claims[target] = claims.get(target, 0) + 1
    return {
        package_uid: {devices[target]: claims.get(target, 0) > 1 for target in uids if target in devices}
        for package_uid, (uids, _installed_on_all) in package_targets.items()
    }


def _management_release(raw: dict[str, Any], gateways: list[dict[str, Any]]) -> str | None:
    """The management server's release ("R81.20"), from the `version` of its
    show-gateways-and-servers object, or None when it is not one value.

    The server that holds the policy is the management object with the network policy
    management blade. When no object has that flag, every management object is read. 2
    different versions give None.
    """
    if isinstance(raw.get("management_release"), str):
        return raw["management_release"]
    servers = [gw for gw in gateways if gw.get("type") in MANAGEMENT_TYPES]
    policy_servers = [
        gw
        for gw in servers
        if isinstance(gw.get("management-blades"), dict)
        and gw["management-blades"].get("network-policy-management") is True
    ]
    versions = {gw.get("version") for gw in (policy_servers or servers)}
    return next(iter(versions)) if len(versions) == 1 and isinstance(next(iter(versions)), str) else None


def _gateway_release(
    raw: dict[str, Any], targets: tuple[str, ...], gateways: list[dict[str, Any]]
) -> str | None:
    """The gateway release of a package. It is the one `version` that its installation
    targets share, or None when they have no version or different versions."""
    if isinstance(raw.get("gateway_release"), str):
        return raw["gateway_release"]
    by_uid = {gw["uid"]: gw for gw in gateways}
    versions = {by_uid[target].get("version") if target in by_uid else None for target in targets}
    return next(iter(versions)) if len(versions) == 1 and isinstance(next(iter(versions)), str) else None


# The NAT rule columns as (raw field, edge type, flag). The flag is set when the column
# holds the Any object. Check Point encodes "Original" on the translated side as the Any
# object.
_NAT_COLUMNS = (
    ("original-source", "ORIG_SRC", "src_any"),
    ("original-destination", "ORIG_DST", "dst_any"),
    ("translated-source", "XLATE_SRC", "xlate_src_original"),
    ("translated-destination", "XLATE_DST", "xlate_dst_original"),
)


def _nat_service_leaves(
    suid: Any, objs: dict[str, Any], any_uids: set[str], seen: set[str], reasons: list[str]
) -> list[tuple[str, str | None]] | None:
    """The (protocol, port spec) pairs that one NAT service entry matches. A group is
    read through its members. The result is None when the entry matches every service
    (Any).

    The port of a pair is None when the service states no port that `_CP_PORT_SPEC_RE`
    reads. Each part whose match is not known appends a reason. Such a part is an entry
    that the objects dictionary does not hold, an ICMP type, a service kind without a
    protocol (such as service-other), a TCP, UDP or SCTP service without a readable
    port, or a group nested in itself.
    """
    uid = _uid_of(suid)
    if uid is not None and uid in any_uids:
        return None
    obj = objs.get(uid) if uid is not None else None
    if obj is None:
        reasons.append(f"the service {uid!r} is not in the objects dictionary")
        return []
    t = str(obj.get("type") or "")
    name = obj.get("name") or uid
    if t == "service-group":
        if uid in seen:
            reasons.append(f"the service group {name!r} contains itself")
            return []
        leaves: list[tuple[str, str | None]] = []
        for member in obj.get("members") or []:
            member_leaves = _nat_service_leaves(member, objs, any_uids, seen | {uid}, reasons)
            if member_leaves is None:
                return None
            leaves.extend(member_leaves)
        return leaves
    if t in _CP_REAL_PROTO_KINDS:
        proto, port = t.removeprefix("service-"), obj.get("port")
        if t in ("service-icmp", "service-icmp6"):
            reasons.append(f"the ICMP type of the service {name!r} is not modeled")
            return [(proto, None)]
        if port and _CP_PORT_SPEC_RE.match(str(port)):
            return [(proto, str(port))]
        reasons.append(f"the service {name!r} states no port that is modeled ({port!r})")
        return [(proto, None)]
    reasons.append(f"the service {name!r} of kind {t or 'unknown'} is not matched by protocol and port")
    return [("any", None)]


def _nat_service_props(
    rule: dict[str, Any], objs: dict[str, Any], any_uids: set[str]
) -> tuple[dict[str, Any], bool]:
    """The service-column props of a nat-rule, and whether a service uid is absent from
    the objects dictionary.

    A resolvable non-Any service keeps its raw name (orig_service / xlate_service). The
    original service, with a group read through its members, gives `protocol` (one name,
    or names joined by '_') and `orig_port` (a string, a range like "8000-8080" or a
    comma list). When that scope is wider than the service, or not known,
    `service_unknown` is set and `service_unknown_reason` holds the reason. The readers
    then claim the protocol and ports for the rule and leave the translation undecided.
    A translated service gives `xlate_port` only for one TCP or UDP service with a port.
    Any other translated service sets `service_unknown` for the port rewrite. Any gives
    no props.
    """
    props: dict[str, Any] = {}
    unresolved = False
    reasons: list[str] = []
    suid = rule.get("original-service")
    if suid and suid not in any_uids:
        obj = objs.get(suid)
        if obj is None:
            unresolved = True
            reasons.append(f"the original service {suid!r} is not in the objects dictionary")
        elif obj.get("name"):
            props["orig_service"] = obj["name"]
        leaves = _nat_service_leaves(suid, objs, any_uids, set(), reasons) if obj is not None else []
        if leaves == [] and not reasons:
            reasons.append(f"the original service {props.get('orig_service') or suid!r} names no member")
        if leaves:
            protos = sorted({proto for proto, _ in leaves})
            ports = sorted({port for _, port in leaves if port is not None})
            if "any" not in protos:
                props["protocol"] = "_".join(protos)
                if all(port is not None for _, port in leaves):
                    props["orig_port"] = ",".join(ports)
                    if (
                        len(protos) > 1
                        and len({frozenset(p for q, p in leaves if q == x) for x in protos}) > 1
                    ):
                        # A NAT rule has one protocol scope and one port scope. tcp/80
                        # beside udp/53 also claims tcp/53 and udp/80.
                        reasons.append("the service group pairs different ports with different protocols")
                elif ports:
                    reasons.append("the service group mixes members with and without a port")
    suid = rule.get("translated-service")
    if suid and suid not in any_uids:
        obj = objs.get(suid)
        if obj is None:
            unresolved = True
            reasons.append(f"the translated service {suid!r} is not in the objects dictionary")
        else:
            if obj.get("name"):
                props["xlate_service"] = obj["name"]
            t = obj.get("type", "")
            port = obj.get("port")
            if t in ("service-tcp", "service-udp") and port and _CP_PORT_SPEC_RE.match(str(port)):
                props["xlate_port"] = str(port)
                props.setdefault("protocol", t.removeprefix("service-"))
            else:
                reasons.append(
                    f"the port rewrite of the translated service {obj.get('name') or suid!r} is not modeled"
                )
    props["service_unknown"] = bool(reasons)
    if reasons:
        props["service_unknown_reason"] = "; ".join(dict.fromkeys(reasons))
    return props, unresolved


def _nat_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    cp,
    gateway_uids: list[str],
    package_bindings: dict[str, dict[str, bool]],
    legacy_binding: bool,
    objs: dict[str, Any],
    any_uids: set[str],
    *,
    devices: dict[str, str],
    everywhere: set[str],
    package_unknown: bool = False,
) -> None:
    package_uids = {
        package.get("name"): package.get("uid")
        for package in raw.get("packages", [])
        if isinstance(package, dict)
        and isinstance(package.get("name"), str)
        and isinstance(package.get("uid"), str)
    }
    for pkg_name, pages in _nat_by_package(raw).items():
        if not any(p.get("rulebase") for p in pages):
            continue
        # One rulebase per package. Positions are ordered only within a package.
        rb = b.node(
            "FwRulebase", cp(f"nat:{pkg_name}"), name=f"NAT:{pkg_name}", kind="nat", vendor="checkpoint"
        )
        # The NAT rulebase is bound as the access layers of the package are. A package
        # whose show-package read failed is bound approximately to every firewall.
        package_uid = package_uids.get(pkg_name, "")
        if legacy_binding or (package_unknown and package_uid not in package_bindings):
            for dev_uid in gateway_uids:
                b.rel("ENFORCES", "Device", dev_uid, "FwRulebase", rb, approximate=True)
        else:
            for dev_uid, approximate in sorted(package_bindings.get(package_uid, {}).items()):
                if approximate:
                    b.rel("ENFORCES", "Device", dev_uid, "FwRulebase", rb, approximate=True)
                else:
                    b.rel("ENFORCES", "Device", dev_uid, "FwRulebase", rb, configured=True)
        for page in pages:
            for rule in _iter_rules(page.get("rulebase", [])):
                if rule.get("type") != "nat-rule":
                    continue
                flags: dict[str, bool] = {}
                edges: list[tuple[str, str]] = []
                unresolvable = False
                for field, rtype, flag in _NAT_COLUMNS:
                    ouid = rule.get(field)
                    if not ouid:
                        continue
                    if ouid in any_uids:
                        flags[flag] = True
                    elif ouid in objs:
                        edges.append((rtype, ouid))
                    else:
                        unresolvable = True
                svc_props, svc_unresolved = _nat_service_props(rule, objs, any_uids)
                svc_reason = svc_props.pop("service_unknown_reason", None)
                reasons = [svc_reason] if svc_reason else []
                if unresolvable:
                    reasons.append("an address column names an object the objects dictionary does not hold")
                # A NAT rule has its own install-on column. `_install_on` reads it as
                # for an access rule.
                install_on, install_unresolved = _install_on(rule, devices, everywhere)
                r = b.node(
                    "NatRule",
                    cp(rule["uid"]),
                    name=rule.get("name") or rule.get("comments") or None,
                    position=rule.get("rule-number"),
                    method=rule.get("method"),
                    enabled=rule.get("enabled", True),
                    auto_generated=rule.get("auto-generated"),
                    approximate=True if (unresolvable or svc_unresolved or reasons) else None,
                    approximate_reason="; ".join(reasons) if reasons else None,
                    install_on=install_on,
                    install_on_unresolved=install_unresolved,
                    **flags,
                    **svc_props,
                )
                b.rel("HAS_RULE", "FwRulebase", rb, "NatRule", r)
                for rtype, ouid in edges:
                    b.rel(rtype, "NatRule", r, "NetObject", cp(ouid))
