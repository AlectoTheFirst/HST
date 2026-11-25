"""The ZIA collector reads locations and sublocations, GRE and IPsec tunnels to the
Zscaler cloud, location groups, and the forwarding rules that send traffic to ZPA.

First contact with a tenant:
    curl -s -X POST https://<vanity>.zslogin.net/oauth2/v1/token \\
        -d grant_type=client_credentials -d client_id=<id> -d client_secret=<secret>
    curl -s -H "Authorization: Bearer <token>" \\
        "https://api.zsapi.net/zia/api/v1/locations?page=1&pageSize=1"
    curl -s -H "Authorization: Bearer <token>" \\
        "https://api.zsapi.net/zia/api/v1/forwardingRules?page=1&pageSize=1"
    # save under data/raw/zia/first-contact/ and rerun normalize_zia on the captures.

API shape this collector reads:
- Each collection that this collector reads answers a bare JSON array with
  page/pageSize paging and no `totalPages`. `ZscalerSession.get_paged` reads it
  with `item_key=None`.
- A location has `ipAddresses`, the GRE join key. A location has no VPN
  credentials. A `vpnCredentials` row holds its location in `location: {id, name}`.
- `locations/lite?includeSubLocations=true` returns the `parentId` of each
  sublocation in one call. A parent whose unpaged answer holds fewer rows than
  the lite list has for it is read again page by page. When the lite list is
  refused, each location is read page by page.
- `primaryDestVip` and `secondaryDestVip` of a GRE tunnel hold `datacenter` (the
  PoP name) and `virtualIp`.
- A location group has `groupType` `STATIC_GROUP` or `DYNAMIC_GROUP`. Both types
  list their current members in `locations: [{id, name}]`. A dynamic group also
  has `dynamicLocationGroupCriteria`.
- A forwarding rule has `order`, `state` (`ENABLED`/`DISABLED`),
  `forwardMethod` (`ZPA`, `DIRECT`, `DROP`, ...) and, for a ZPA rule,
  `zpaAppSegments: [{id, externalId, name, deleted}]`. `externalId` is the id of
  the ZPA segment. The reasoner rule `zia-forwarding-to-zpa-segment` joins it to
  the `ZpaAppSegment`. This collector writes no edge to a ZPA object.
- Location groups, forwarding rules and ZPA gateways are optional sections. A
  refused read sets the status of its section, and the rest of the collection is
  kept. HTTP 401 and 403 set `unauthorized`, 404 sets `unsupported`, and any
  other HTTP error sets `failed`.
- A timeout or another transport error on an optional read sets `failed`. A token
  failure or the 429 limit fails the whole fetch.
- The objects of a section with the status `unauthorized` or `failed` come
  forward from the previous run with `carried_reason` `section-failed`
  (`SECTION_LABELS`). A section with the status `unsupported` brings nothing
  forward.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from typing import Any, ClassVar

import httpx
from pydantic import Field, field_validator

from hst.core import uid
from hst.core.model import Batch, SectionOutcome

from .auth import OAuthClientCredentials
from .base import Collector, SourceConfig, register
from .util import GraphBuilder, OverlayEnd, as_int, overlay_connection, parse_pairs
from .zscaler_auth import ZscalerSession, check_tenant, check_vanity
from .zscaler_sections import SectionReads, section_outcomes

LOCATIONS_PATH = "/zia/api/v1/locations"
SUBLOCATIONS_PATH = "/zia/api/v1/locations/{id}/sublocations"
GRE_TUNNELS_PATH = "/zia/api/v1/greTunnels"
VPN_CREDENTIALS_PATH = "/zia/api/v1/vpnCredentials"
LOCATION_GROUPS_PATH = "/zia/api/v1/locations/groups"
# SUBLOCATIONS_PATH is read only for a location that is a `parentId` in the lite list.
LOCATIONS_LITE_PATH = "/zia/api/v1/locations/lite"
FORWARDING_RULES_PATH = "/zia/api/v1/forwardingRules"
# ZPA_GATEWAYS_PATH is read only when a forwarding rule has a ZPA gateway.
ZPA_GATEWAYS_PATH = "/zia/api/v1/zpaGateways"

OPTIONAL_SECTIONS = ("location_groups", "forwarding_rules", "zpa_gateways")


def _transport(config: ZiaConfig) -> httpx.BaseTransport | None:
    return None  # test seam


def _scope(tenant: str) -> str:
    return f"zia:{uid.slug(tenant)}"


class ZiaConfig(SourceConfig):
    vanity_domain: str = Field(
        description="The ZIdentity tenant name: the first label of the token host "
        "https://<vanity domain>.zslogin.net, for example acme. It can differ from the company name."
    )
    tenant: str = Field(
        description="The key of this source's scope and of every uid it writes, for example acme. "
        "A change gives every node of the source a new uid."
    )
    auth: OAuthClientCredentials
    interval_s: int = Field(
        default=0,
        title="Collection interval (seconds)",
        description="Collect this source every this many seconds. 0 leaves it to full cycles only.",
    )
    location_sites: str = Field(
        "",
        title="Location to site",
        description="One line per ZIA location: the location id or name, a comma, and the site code, "
        "for example 12345678, vie01. A location whose name holds a comma takes its id. A sublocation "
        "takes its parent's site unless it has its own line. A location with no line stays unplaced. A "
        "name that more than one location carries binds none.",
        json_schema_extra={"format": "multiline"},
    )

    @field_validator("location_sites")
    @classmethod
    def _location_sites_shape(cls, value: str) -> str:
        parse_pairs(value, field="location_sites")
        return value

    @property
    def location_site_map(self) -> dict[str, str]:
        return parse_pairs(self.location_sites, field="location_sites")

    @field_validator("tenant")
    @classmethod
    def _tenant_keys_a_scope(cls, value: str) -> str:
        return check_tenant(value)

    @field_validator("vanity_domain")
    @classmethod
    def _one_label(cls, value: str) -> str:
        return check_vanity(value)


@register
class ZiaCollector(Collector):
    name = "zia"
    ConfigModel = ZiaConfig
    KIND = "orchestrator"
    NORMALIZATION_CONFIG_KEYS: ClassVar[tuple[str, ...]] = ("location_sites",)
    # `normalize_zia` writes each label only in the section of its key.
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "location_groups": ("ZiaLocationGroup",),
        "forwarding_rules": ("ZiaForwardingRule",),
        "zpa_gateways": (),
    }

    def __init__(self, config: ZiaConfig, settings):
        super().__init__(config, settings)
        self.scope = _scope(config.tenant)

    def _session(self, **options: Any) -> ZscalerSession:
        c = self.config
        return ZscalerSession(
            c.vanity_domain,
            c.auth.client_id,
            c.auth.client_secret.get_secret_value(),
            transport=_transport(c),
            **options,
        )

    def probe(self) -> str:
        session = self._session()
        try:
            page = session.get(LOCATIONS_PATH, params={"page": 1, "pageSize": 1})
            count = len(page)
            return f"token ok: {count} location(s) on page 1 for tenant {self.config.tenant}"
        finally:
            session.close()

    def fetch(self) -> dict[str, Any]:
        session = self._session(check=self.check_stop)
        reads = SectionReads()

        try:
            locations = session.get_paged(LOCATIONS_PATH, None)
            sublocations: list[dict] = []
            counts = _sublocation_counts(session)
            for loc in locations:
                if counts is None:
                    sublocations.extend(session.get_paged(SUBLOCATIONS_PATH.format(id=loc["id"]), None))
                elif loc["id"] in counts:
                    sublocations.extend(_sublocations_of(session, loc["id"], counts[loc["id"]]))
            gre_tunnels = session.get_paged(GRE_TUNNELS_PATH, None)
            vpn_credentials = session.get_paged(VPN_CREDENTIALS_PATH, None)
            location_groups = reads.read("location_groups", session.get_paged, LOCATION_GROUPS_PATH, None)
            forwarding_rules = reads.read("forwarding_rules", session.get_paged, FORWARDING_RULES_PATH, None)
            raw: dict[str, Any] = {
                "locations": locations,
                "sublocations": sublocations,
                "gre_tunnels": gre_tunnels,
                "vpn_credentials": vpn_credentials,
                "location_groups": location_groups,
                "forwarding_rules": forwarding_rules,
            }
            if any(
                isinstance(r.get("zpaGateway"), dict) and r["zpaGateway"].get("id") for r in forwarding_rules
            ):
                raw["zpa_gateways"] = reads.read("zpa_gateways", session.get_paged, ZPA_GATEWAYS_PATH, None)
            raw["section_errors"] = reads.errors()
            return raw
        finally:
            session.close()

    def normalize(self, raw: dict[str, Any]) -> Batch:
        return normalize_zia(raw, tenant=self.config.tenant, location_sites=self.config.location_site_map)


def _sublocation_counts(session: ZscalerSession) -> dict[Any, int] | None:
    """Return the number of sublocations of each parent from one lite call.

    The result is None when the lite list is refused. `fetch` then reads each
    location page by page."""
    try:
        lite = session.get_paged(LOCATIONS_LITE_PATH, None, params={"includeSubLocations": "true"})
    except httpx.HTTPStatusError:
        return None
    counts: dict[Any, int] = {}
    for row in lite:
        if row.get("parentId"):
            counts[row["parentId"]] = counts.get(row["parentId"], 0) + 1
    return counts


def _sublocations_of(session: ZscalerSession, parent_id: Any, expected: int) -> list[dict]:
    """Return the sublocations of a parent from one unpaged call.

    The paged walk replaces an answer that holds fewer than `expected` rows."""
    path = SUBLOCATIONS_PATH.format(id=parent_id)
    answer = session.get(path)
    if isinstance(answer, list) and len(answer) >= expected:
        return answer
    return session.get_paged(path, None)


def _zia_connection(
    b: GraphBuilder,
    technology: str,
    local: str,
    tunnels: list[str],
    *,
    far: str | None = None,
    label: Any = None,
) -> str | None:
    """The `OverlayConnection` between a ZIA location and a Zscaler data center.

    `local` is the `ZiaLocation` uid, or the tunnel source address when no
    location holds it. `far` is the `ZscalerDc` uid."""
    location = b.props("ZiaLocation", local)
    near_name = location.get("name") or location.get("zia_id") or local
    near = OverlayEnd(local, "ZiaLocation" if location else None, local if location else None, "edge")
    if far:
        dc_name = b.props("ZscalerDc", far).get("name") or far
        far_end = OverlayEnd(far, "ZscalerDc", far, "gateway", reported=True)
        name = f"{near_name} to {dc_name}"
    else:
        far_end = OverlayEnd(tunnels[0], None, None, "gateway", reported=True)
        name = f"{near_name} {label} to Zscaler" if label else f"{near_name} to Zscaler"
    return overlay_connection(b, technology, (near, far_end), tunnels, name=name)


def _location_node(b: GraphBuilder, tenant: str, loc: dict[str, Any], *, sublocation: bool = False) -> str:
    # A top-level location's `ipAddresses` are its egress IPs, the GRE join key.
    # A sublocation's `ipAddresses` are its internal address ranges, kept verbatim.
    # `ssl_scan_enabled` is the deprecated vendor flag `sslScanEnabled`. It does
    # not show SSL inspection. `profile`, `ofw_enabled`, `ips_control`,
    # `xff_forward_enabled` and `surrogate_ip` are the location options that take
    # effect.
    addresses = loc.get("ipAddresses") or None
    return b.node(
        "ZiaLocation",
        uid.zia(tenant, "loc", loc["id"]),
        name=loc.get("name"),
        zia_id=str(loc["id"]),
        country=loc.get("country"),
        tz=loc.get("tz"),
        egress_ips=None if sublocation else loc.get("ipAddresses"),
        address_ranges=addresses if sublocation else None,
        other_sublocation=True if sublocation and loc.get("otherSubLocation") is True else None,
        auth_required=loc.get("authRequired"),
        ssl_scan_enabled=loc.get("sslScanEnabled"),
        profile=loc.get("profile"),
        ofw_enabled=loc.get("ofwEnabled"),
        ips_control=loc.get("ipsControl"),
        xff_forward_enabled=loc.get("xffForwardEnabled"),
        surrogate_ip=loc.get("surrogateIP"),
    )


def _resolve_location_sites(
    raw: dict[str, Any], sites: Mapping[str, str], tenant: str
) -> tuple[dict[str, str], list[str]]:
    """The site code of each location and sublocation id that a
    `location_sites` line binds, and one warning per line that binds nothing.
    An id line binds that location. A name line binds the one location that
    has the name. A name that 2 or more locations have binds none."""
    every = [*raw.get("locations", []), *raw.get("sublocations", [])]
    ids = {str(loc["id"]) for loc in every}
    by_name: dict[str, list[str]] = {}
    for loc in every:
        if loc.get("name"):
            by_name.setdefault(str(loc["name"]), []).append(str(loc["id"]))
    own: dict[str, str] = {}
    warnings: list[str] = []
    for key, code in sites.items():
        if key in ids:
            own[key] = code
            continue
        named = by_name.get(key, [])
        if len(named) == 1:
            own.setdefault(named[0], code)
        elif not named:
            warnings.append(f"ZIA tenant {tenant}: location_sites line '{key}' matches no location")
        else:
            warnings.append(
                f"ZIA tenant {tenant}: location_sites line '{key}' names {len(named)} locations "
                f"(ids {', '.join(sorted(named))}); it binds none of them"
            )
    return own, warnings


def _address_key(value: str) -> tuple[int, int, str]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return (9, 0, value)
    return (ip.version, int(ip), value)


# ZIA forwarding rule match criteria that the engine does not compare.
_OTHER_FORWARDING_CRITERIA = (
    "departments",
    "groups",
    "users",
    "srcIpGroups",
    "srcIpv6Groups",
    "destIpCategories",
    "destCountries",
    "destIpGroups",
    "destIpv6Groups",
    "nwServices",
    "nwServiceGroups",
    "nwApplicationGroups",
    "appServiceGroups",
    "ecGroups",
    "deviceGroups",
)


def _ids(values: list[Any]) -> list[str]:
    """Each id once, as a string, in payload order."""
    out: list[str] = []
    for value in values:
        if value is not None and value != "" and str(value) not in out:
            out.append(str(value))
    return out


def normalize_zia(
    raw: dict[str, Any], *, tenant: str, location_sites: Mapping[str, str] | None = None
) -> Batch:
    """Build the Batch of a raw ZIA payload.

    `(ZiaLocation)-[:REPRESENTS]->(Site)` comes from the `location_sites` map of
    the source.
    """
    b = GraphBuilder()
    loc_by_ip: dict[str, str] = {}  # ZiaLocation uid by location public IP
    loc_by_id: dict[Any, str] = {}  # ZiaLocation uid by location id

    for loc in raw.get("locations", []):
        luid = _location_node(b, tenant, loc)
        loc_by_id[loc["id"]] = luid
        for ip in loc.get("ipAddresses") or []:
            loc_by_ip[ip] = luid

    # The USES edge of a tunnel starts at a top-level location. A tunnel source
    # address in the `ipAddresses` of a sublocation maps to the parent location.
    # A VPN credential of a sublocation maps to the parent location.
    parent_of: dict[Any, str] = {}
    sub_ip_parent: dict[str, str] = {}
    for sub in raw.get("sublocations", []):
        suid = _location_node(b, tenant, sub, sublocation=True)
        loc_by_id[sub["id"]] = suid
        parent_id = sub.get("parentId")
        if parent_id is not None:
            puid = uid.zia(tenant, "loc", parent_id)
            b.rel("PART_OF", "ZiaLocation", suid, "ZiaLocation", puid)
            parent_of[sub["id"]] = puid
            for ip in sub.get("ipAddresses") or []:
                sub_ip_parent.setdefault(str(ip), puid)
    for ip, puid in sub_ip_parent.items():
        loc_by_ip.setdefault(ip, puid)

    sites = location_sites or {}
    own, unbound = _resolve_location_sites(raw, sites, tenant)
    site_by_id: dict[Any, str] = {}
    for loc in raw.get("locations", []):
        code = own.get(str(loc["id"]))
        if code:
            site_by_id[loc["id"]] = code
    for sub in raw.get("sublocations", []):
        code = own.get(str(sub["id"])) or site_by_id.get(sub.get("parentId"))
        if code:
            site_by_id[sub["id"]] = code
    for loc_id, code in site_by_id.items():
        site = b.node("Site", uid.site(code), code=code)
        b.rel("REPRESENTS", "ZiaLocation", loc_by_id[loc_id], "Site", site)

    dc_vips: dict[str, list[str]] = {}
    # The GRE tunnels of each pair (location uid or source address, ZscalerDc uid).
    gre_pairs: dict[tuple[str, str], list[str]] = {}
    for gre in raw.get("gre_tunnels", []):
        tuid = b.node("Tunnel", uid.zia(tenant, "gre", gre["id"]), encap="gre", source_ip=gre.get("sourceIp"))
        for side, role in (("primaryDestVip", "primary"), ("secondaryDestVip", "secondary")):
            vip = gre.get(side)
            if not vip:
                continue
            dc_name = vip.get("datacenter")
            if not dc_name:
                continue
            duid = b.node(
                "ZscalerDc",
                uid.zia(tenant, "dc", uid.slug(dc_name)),
                name=dc_name,
                # A Private Service Edge is Zscaler software in the data center of
                # the customer. Any other data center has no such property.
                private_service_edge=True if vip.get("privateServiceEdge") is True else None,
            )
            if vip.get("virtualIp"):
                dc_vips.setdefault(duid, []).append(str(vip["virtualIp"]))
            # The role is part of the edge key. 2 VIPs of one tunnel in one data
            # center give 2 edges.
            b.rel(
                "TERMINATES_ON",
                "Tunnel",
                tuid,
                "ZscalerDc",
                duid,
                key={"role": role},
                vip=vip.get("virtualIp"),
            )
            # The dora-providers scenario of demo.py reads this edge.
            prov = b.node("Provider", uid.provider("zscaler"), name="zscaler")
            b.rel("PROVIDED_BY", "ZscalerDc", duid, "Provider", prov)
            local = loc_by_ip.get(gre.get("sourceIp")) or gre.get("sourceIp")
            if local:
                pair = gre_pairs.setdefault((str(local), duid), [])
                if tuid not in pair:
                    pair.append(tuid)
        loc_uid = loc_by_ip.get(gre.get("sourceIp"))
        if loc_uid:
            b.rel("USES", "ZiaLocation", loc_uid, "Tunnel", tuid)
    for (local, duid), tunnels in sorted(gre_pairs.items()):
        _zia_connection(b, "gre", local, tunnels, far=duid)
    # The `vip` of a data center is its lowest VIP in address order.
    # assessment/evaluation.py reads it as a member address.
    for duid, vips in dc_vips.items():
        b.node("ZscalerDc", duid, vip=min(vips, key=_address_key))

    for cred in raw.get("vpn_credentials", []):
        tuid = b.node(
            "Tunnel",
            uid.zia(tenant, "ipsec", cred["id"]),
            encap="ipsec",
            vpn_type=cred.get("type"),
            # `fqdn` is the IKE identity of the customer.
            ike_id=cred.get("fqdn"),
            source_ip=cred.get("ipAddress"),
        )
        # The credential holds its location in `location`.
        cred_loc = cred.get("location") or {}
        loc_uid = parent_of.get(cred_loc.get("id")) or loc_by_id.get(cred_loc.get("id"))
        if loc_uid:
            b.rel("USES", "ZiaLocation", loc_uid, "Tunnel", tuid)
            _zia_connection(b, "ipsec", loc_uid, [tuid], label=cred.get("fqdn") or cred.get("ipAddress"))
        # `cred["ipAddress"]` gets no TERMINATES_ON edge.

    for grp in raw.get("location_groups", []):
        criteria = grp.get("dynamicLocationGroupCriteria")
        guid = b.node(
            "ZiaLocationGroup",
            uid.zia(tenant, "locgrp", grp["id"]),
            name=grp.get("name"),
            dynamic=grp.get("groupType") == "DYNAMIC_GROUP",
            dynamic_criteria=json.dumps(criteria) if criteria else None,
        )
        # Both group types list their current members. ZIA evaluates the criteria
        # of a dynamic group. A member that this run did not collect gets no edge.
        for member in grp.get("locations") or []:
            member_uid = loc_by_id.get(member.get("id") if isinstance(member, dict) else member)
            if member_uid:
                b.rel("MEMBER_OF", "ZiaLocation", member_uid, "ZiaLocationGroup", guid)

    loc_by_id_str = {str(k): v for k, v in loc_by_id.items()}
    group_ids_written = {str(g["id"]) for g in raw.get("location_groups", []) if g.get("id") is not None}
    # a ZPA gateway's server group, by the gateway id
    gateway_group = {
        str(gw["id"]): str(gw["zpaServerGroup"]["externalId"])
        for gw in raw.get("zpa_gateways") or []
        if gw.get("id") is not None
        and isinstance(gw.get("zpaServerGroup"), dict)
        and gw["zpaServerGroup"].get("externalId") is not None
    }
    for rule in raw.get("forwarding_rules", []):
        state = rule.get("state")
        method = rule.get("forwardMethod")
        segment_ids = _ids(
            [
                *(s.get("externalId") for s in rule.get("zpaAppSegments") or [] if not s.get("deleted")),
                # ECZPA rules list their segments by `zpaId`
                *(s.get("zpaId") for s in rule.get("zpaApplicationSegments") or [] if not s.get("deleted")),
            ]
        )
        group_ids = _ids(
            [g.get("zpaId") for g in rule.get("zpaApplicationSegmentGroups") or [] if not g.get("deleted")]
        )
        gateway = rule.get("zpaGateway") if isinstance(rule.get("zpaGateway"), dict) else {}
        gateway_id = str(gateway["id"]) if gateway.get("id") is not None else None
        location_ids = _ids([x.get("id") for x in rule.get("locations") or [] if not x.get("deleted")])
        loc_group_ids = _ids([x.get("id") for x in rule.get("locationGroups") or [] if not x.get("deleted")])
        other = sorted(key for key in _OTHER_FORWARDING_CRITERIA if rule.get(key))
        ruid = b.node(
            "ZiaForwardingRule",
            uid.zia(tenant, "fwdrule", rule["id"]),
            name=rule.get("name"),
            order=as_int(rule.get("order")),
            forward_method=method.lower() if method else None,
            enabled=None if state is None else state == "ENABLED",
            zpa_app_segment_ids=segment_ids or None,
            zpa_segment_group_ids=group_ids or None,
            zpa_gateway_id=gateway_id,
            zpa_gateway=gateway.get("name"),
            zpa_server_group_id=gateway_group.get(gateway_id) if gateway_id else None,
            rule_type=rule.get("type"),
            location_ids=location_ids or None,
            location_group_ids=loc_group_ids or None,
            src_ips=rule.get("srcIps") or None,
            dest_addresses=rule.get("destAddresses") or None,
            other_criteria=other or None,
        )
        # APPLIES_TO edges go to the locations and location groups that this
        # batch wrote. A rule without a location and without a location group
        # applies to every location.
        for loc_id in location_ids:
            target = loc_by_id_str.get(loc_id)
            if target:
                b.rel("APPLIES_TO", "ZiaForwardingRule", ruid, "ZiaLocation", target)
        for grp_id in loc_group_ids:
            if grp_id in group_ids_written:
                b.rel(
                    "APPLIES_TO",
                    "ZiaForwardingRule",
                    ruid,
                    "ZiaLocationGroup",
                    uid.zia(tenant, "locgrp", grp_id),
                )

    batch = b.batch("zia", _scope(tenant))
    batch.sections["mtu"] = SectionOutcome(
        status="unsupported",
        detail=(
            "Current ZIA location/GRE/credential APIs provide no validated carrier MTU; "
            "proxy connections have separate budgets"
        ),
    )
    batch.sections.update(section_outcomes(raw, OPTIONAL_SECTIONS))
    batch.warnings.extend(unbound)
    return batch
