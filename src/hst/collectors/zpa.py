"""The ZPA collector reads app segments, the connector fabric and the access rules that gate them.

First contact with a tenant:
    curl -s -X POST https://<vanity>.zslogin.net/oauth2/v1/token \\
        -d grant_type=client_credentials -d client_id=<id> -d client_secret=<secret>
    curl -s -H "Authorization: Bearer <token>" \\
        "https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/<customer_id>/segmentGroup?page=1&pagesize=1"
    curl -s -H "Authorization: Bearer <token>" \\
        "https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/<customer_id>/policySet/rules/policyType/ACCESS_POLICY?page=1&pagesize=1"
    # save under data/raw/zpa/first-contact/ and rerun normalize_zpa on the captures.
    # A ZpaX label below with zero nodes means a wrong path or envelope key.

API shape this collector reads:
- The config API is `/zpa/mgmtconfig/v1/admin/customers/{customer_id}`. Every
  collection answers `{"list": [...], "totalPages": ...}` (`ITEM_KEY`) and reads
  its page size from `pagesize` (`PAGE_SIZE_PARAM`), up to 500.
- One call lists the policy rules of one policy type,
  `policySet/rules/policyType/{ACCESS_POLICY|CLIENT_FORWARDING_POLICY}`. Each rule
  has its `policySetId`. `ZpaAccessRule.position` and
  `ZpaClientForwardingRule.position` come from `ruleOrder`, coerced to `int`.
  `ruleOrder` is the policy evaluation order, lowest first. A rule whose
  `ruleOrder` is absent or not an integer is skipped with a logged warning.
  `priority` is kept as ZPA sends it, coerced to `int`. The list API returns
  `priority` in the reverse order of `ruleOrder`.
- A `SCIM_GROUP` condition operand has `idpId`, `idpName` and `rhs`, the SCIM
  group id. It has no group name. The names come from the user config API,
  `/zpa/userconfig/v1/customers/{customer_id}/scimgroup/idpId/{idpId}`, read once
  for each identity provider in the rules. A refused read of one identity
  provider keeps the names of the others.
- A connector has `enabled` (configuration), `controlChannelStatus`
  (`ZPN_STATUS_AUTHENTICATED` or `ZPN_STATUS_DISCONNECTED`), `privateIp` and
  `publicIp`. `CONNECTOR_HEALTH` maps the status to the `up` and `down` values
  that the path engine reads. The connector payload has no host and no VM. The
  collector writes no `RUNS_ON`. The address of the connector is its `private_ip`.
- Provisioning keys are listed per association type. The answer holds the
  enrollment secret in `provisioningKey`. `fetch()` removes it before it returns,
  and `core/redaction.py` redacts it from a trace. A refused read of one
  association type keeps the keys of the others.
- A static server group (`dynamicDiscovery: false`) embeds its `servers`
  (`id`, `name`, `address`, `enabled`). `address` is an IP address or a host name.
- Client-forwarding rules, provisioning keys and SCIM group names are optional
  sections. A refused read sets the status of its section, and the rest of the
  collection is kept. HTTP 401 and 403 set `unauthorized`, 404 sets
  `unsupported`, and any other HTTP error sets `failed`. A section with 2 or
  more reads gets the worst status of its refused reads. `unsupported` becomes
  `partial` when another read of the section answered (`zscaler_sections.py`).
- A timeout or another transport error on an optional read sets `failed`. A token
  failure or the 429 limit fails the whole fetch.
- The objects of a section with the status `unauthorized` or `failed` come
  forward from the previous run with `carried_reason` `section-failed`
  (`SECTION_LABELS`). A section with the status `unsupported` brings nothing
  forward.
- An access rule draws `GRANTS` for ALLOW, `DENIES` for DENY and `APPLIES_TO` for
  any other action (case-insensitive). `action` is written only for a value in
  `ZPA_ACCESS_ACTIONS`. `action_raw` keeps the string that ZPA sent. A negated
  condition block draws no edge.
- `serviceEdge` lists the Private Service Edges that the customer runs. The
  public service edges of Zscaler are not in the customer API. Every row is
  `kind = "private"`. A service edge has `enabled` and `controlChannelStatus`,
  and its `health` comes from `CONNECTOR_HEALTH`.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Any, ClassVar

import httpx
from pydantic import Field, field_validator

from hst.core import uid, zpa_policy
from hst.core.labels import ZPA_ACCESS_ACTIONS
from hst.core.model import Batch, SectionOutcome

from .auth import OAuthClientCredentials
from .base import Collector, SourceConfig, register
from .util import GraphBuilder, without_keys
from .zscaler_auth import ZscalerSession, check_tenant, check_vanity
from .zscaler_sections import SectionReads, section_outcomes

logger = logging.getLogger(__name__)

ITEM_KEY = "list"
# ZPA reads `pagesize` in lower case. It ignores `pageSize` and sends 20 items.
PAGE_SIZE_PARAM = "pagesize"

BASE = "/zpa/mgmtconfig/v1/admin/customers/{customer_id}"
APPLICATION_PATH = f"{BASE}/application"
SEGMENT_GROUP_PATH = f"{BASE}/segmentGroup"
SERVER_GROUP_PATH = f"{BASE}/serverGroup"
APP_CONNECTOR_GROUP_PATH = f"{BASE}/appConnectorGroup"
CONNECTOR_PATH = f"{BASE}/connector"
SERVICE_EDGE_PATH = f"{BASE}/serviceEdge"
RULES_PATH = f"{BASE}/policySet/rules/policyType/ACCESS_POLICY"
CLIENT_FORWARDING_RULES_PATH = f"{BASE}/policySet/rules/policyType/CLIENT_FORWARDING_POLICY"
# PROVISIONING_KEY_ASSOCIATION_TYPES holds the group-level association types.
# The other association types bind a key to one connector or one service edge.
PROVISIONING_KEY_PATH = f"{BASE}/associationType/{{association_type}}/provisioningKey"
PROVISIONING_KEY_ASSOCIATION_TYPES = ("CONNECTOR_GRP", "SERVICE_EDGE_GRP")
SCIM_GROUP_PATH = "/zpa/userconfig/v1/customers/{customer_id}/scimgroup/idpId/{idp_id}"

_PROVISIONING_SECRET_KEYS = ("provisioningkey",)

# CONNECTOR_HEALTH maps the `controlChannelStatus` of a connector or a service
# edge to the health values that `path/gates/zpa.py` and
# `analysis_model/gates.py` read. A status outside this map writes no `health`.
CONNECTOR_HEALTH = {"ZPN_STATUS_AUTHENTICATED": "up", "ZPN_STATUS_DISCONNECTED": "down"}

OPTIONAL_SECTIONS = ("client_forwarding_rules", "provisioning_keys", "scim_groups")


def _transport(config: ZpaConfig) -> httpx.BaseTransport | None:
    return None  # test seam


def _scope(tenant: str) -> str:
    return f"zpa:{uid.slug(tenant)}"


class ZpaConfig(SourceConfig):
    vanity_domain: str = Field(
        description="The ZIdentity tenant name: the first label of the token host "
        "https://<vanity domain>.zslogin.net, for example acme. It can differ from the company name."
    )
    tenant: str = Field(
        description="The key of this source's scope and of every uid it writes, for example acme. "
        "A change gives every node of the source a new uid."
    )
    customer_id: str = Field(description="The ZPA customer id that the API paths name.")
    auth: OAuthClientCredentials
    interval_s: int = Field(
        default=0,
        title="Collection interval (seconds)",
        description="Collect this source every this many seconds. 0 leaves it to full cycles only.",
    )

    @field_validator("tenant")
    @classmethod
    def _tenant_keys_a_scope(cls, value: str) -> str:
        return check_tenant(value)

    @field_validator("customer_id")
    @classmethod
    def _customer_id_set(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("customer_id is empty")
        return value.strip()

    @field_validator("vanity_domain")
    @classmethod
    def _one_label(cls, value: str) -> str:
        return check_vanity(value)


@register
class ZpaCollector(Collector):
    name = "zpa"
    ConfigModel = ZpaConfig
    KIND = "orchestrator"
    # `normalize_zpa` writes each label only in the section of its key.
    # The access rules also write IdentityGroup. An IdentityGroup that only a
    # client-forwarding rule refers to does not come forward, and the APPLIES_TO
    # edge to it does not come forward. `scim_groups` sets names on IdentityGroup
    # nodes and has no label.
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "client_forwarding_rules": ("ZpaClientForwardingRule",),
        "provisioning_keys": ("ZpaProvisioningKey",),
        "scim_groups": (),
    }

    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {"rules": "4"}

    def __init__(self, config: ZpaConfig, settings):
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
            page = session.get(
                SEGMENT_GROUP_PATH.format(customer_id=self.config.customer_id),
                params={"page": 1, PAGE_SIZE_PARAM: 1},
            )
            count = len(page.get(ITEM_KEY, [])) if isinstance(page, dict) else 0
            return f"token ok: {count} segment group(s) on page 1 for tenant {self.config.tenant}"
        finally:
            session.close()

    def fetch(self) -> dict[str, Any]:
        session = self._session(check=self.check_stop)
        reads = SectionReads()

        def paged(path: str) -> list[dict]:
            return session.get_paged(path, ITEM_KEY, size_param=PAGE_SIZE_PARAM)

        try:
            cid = self.config.customer_id
            app_segments = paged(APPLICATION_PATH.format(customer_id=cid))
            segment_groups = paged(SEGMENT_GROUP_PATH.format(customer_id=cid))
            server_groups = paged(SERVER_GROUP_PATH.format(customer_id=cid))
            connector_groups = paged(APP_CONNECTOR_GROUP_PATH.format(customer_id=cid))
            connectors = paged(CONNECTOR_PATH.format(customer_id=cid))
            service_edges = paged(SERVICE_EDGE_PATH.format(customer_id=cid))
            access_rules = paged(RULES_PATH.format(customer_id=cid))
            client_forwarding_rules = reads.read(
                "client_forwarding_rules", paged, CLIENT_FORWARDING_RULES_PATH.format(customer_id=cid)
            )
            # Each association type and each identity provider has its own read.
            # A refused read keeps the rows of the other reads.
            keys: list[dict] = []
            for assoc_type in PROVISIONING_KEY_ASSOCIATION_TYPES:
                path = PROVISIONING_KEY_PATH.format(customer_id=cid, association_type=assoc_type)
                keys.extend(reads.read("provisioning_keys", paged, path))
            provisioning_keys = without_keys(keys, _PROVISIONING_SECRET_KEYS)
            scim_groups: list[dict] = []
            for idp_id in sorted(_scim_idp_ids(access_rules + client_forwarding_rules)):
                path = SCIM_GROUP_PATH.format(customer_id=cid, idp_id=idp_id)
                scim_groups.extend(reads.read("scim_groups", paged, path))

            return {
                "app_segments": app_segments,
                "segment_groups": segment_groups,
                "server_groups": server_groups,
                "connector_groups": connector_groups,
                "connectors": connectors,
                "service_edges": service_edges,
                "access_rules": access_rules,
                "client_forwarding_rules": client_forwarding_rules,
                "provisioning_keys": provisioning_keys,
                "scim_groups": scim_groups,
                "section_errors": reads.errors(),
            }
        finally:
            session.close()

    def normalize(self, raw: dict[str, Any]) -> Batch:
        return normalize_zpa(raw, tenant=self.config.tenant)


def _scim_idp_ids(rules: list[dict[str, Any]]) -> set[str]:
    return {
        str(op["idpId"])
        for rule in rules
        for cond in rule.get("conditions") or []
        for op in cond.get("operands") or []
        if op.get("objectType") == "SCIM_GROUP" and op.get("idpId")
    }


def _identity_group_node(
    b: GraphBuilder, tenant: str, op: dict[str, Any], scim_names: dict[tuple[str, str], str]
) -> str | None:
    """Write the `IdentityGroup` stub node of a `SCIM_GROUP` condition operand and return its uid.

    The result is `None` when the operand has no `rhs` and no `name`. The uid is
    keyed on the identity provider and the SCIM group id (`rhs`). The name is the
    name in the operand, else the SCIM group name from the user config API, else
    the group id. The uid of an operand with a group name and no `rhs` is keyed
    on the name.
    """
    name = op.get("name")
    group_id = op.get("rhs")
    idp_id = op.get("idpId")
    if group_id is not None:
        ref = f"{idp_id}-{group_id}" if idp_id else str(group_id)
        known = name or scim_names.get((str(idp_id), str(group_id)))
        return b.node(
            "IdentityGroup",
            uid.zpa(tenant, "idp", ref),
            name=known or str(group_id),
            # `name_is_id` is True when the rule and the SCIM group read gave no name.
            name_is_id=None if known else True,
            source="scim",
            idp_name=op.get("idpName"),
        )
    if name:
        ref = f"{idp_id}-{uid.slug(name)}" if idp_id else uid.slug(name)
        return b.node("IdentityGroup", uid.zpa(tenant, "idp", ref), name=name, source="scim")
    return None


def _rule_position(rule: dict[str, Any], kind: str) -> int | None:
    """Return `ruleOrder` as an `int`, or None with a logged warning.

    `ruleOrder` is the ZPA evaluation order and the first-match position of the
    rule. The list API returns `priority` in the reverse order of `ruleOrder`.
    """
    raw_order = rule.get("ruleOrder")
    try:
        return int(raw_order)
    except (TypeError, ValueError):
        logger.warning("zpa: %s %r has a non-numeric ruleOrder %r, skipping", kind, rule.get("id"), raw_order)
        return None


def _rule_priority(rule: dict[str, Any]) -> int | None:
    """Return the `priority` that ZPA sends as an `int`, or None."""
    try:
        return int(rule.get("priority"))
    except (TypeError, ValueError):
        return None


def _rule_props(rule: dict[str, Any]) -> dict[str, Any]:
    """Return the node properties of a policy rule that the first-match evaluator reads.

    The properties include the raw `action`, the condition structure as JSON and
    `applies_to_all_identities`."""
    action_raw = rule.get("action")
    blocks = zpa_policy.condition_blocks(rule.get("conditions"))
    operator = rule.get("operator")
    enabled, disabled_raw = zpa_policy.parse_disabled(rule.get("disabled"))
    identity_scope, app_scope = zpa_policy.rule_scope(blocks, operator)
    return {
        "name": rule.get("name"),
        "action": (action_raw or "").lower(),
        "action_raw": action_raw,
        "applies_to_all_identities": True if identity_scope == "any" else None,
        "conditions": json.dumps(blocks) if blocks else None,
        "conditions_summary": zpa_policy.conditions_summary(blocks, operator) or None,
        "operator": operator,
        "enabled": enabled,
        "disabled_raw": disabled_raw,
        "identity_scope": identity_scope,
        "app_scope": app_scope,
    }


_ACCESS_EDGES = {"ALLOW": "GRANTS", "DENY": "DENIES"}


def _segment_destinations(entries: Any) -> dict[str, Any]:
    """Return the IP and CIDR entries of a segment's `domainNames` as `ranges`.

    A wildcard entry sets `opaque` and `opaque_reason`."""
    ranges: list[str] = []
    wildcards: list[str] = []
    for entry in entries or []:
        text = str(entry).strip()
        if text.startswith("*"):
            wildcards.append(text)
            continue
        try:
            ranges.append(str(ipaddress.ip_network(text, strict=False)))
        except ValueError:
            continue
    out: dict[str, Any] = {"ranges": ranges or None}
    if wildcards:
        out["opaque"] = True
        out["opaque_reason"] = f"wildcard domain entries: {', '.join(wildcards)}"
    return out


def _flag(value: Any) -> bool | None:
    """Return a ZPA boolean as a bool. The API sends a bool, "true" or "false"."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None


def _rule_edges(
    b: GraphBuilder,
    tenant: str,
    label: str,
    ruid: str,
    rule: dict[str, Any],
    identity_rel: str,
    scim_names: dict[tuple[str, str], str],
) -> None:
    for cond in rule.get("conditions") or []:
        # A negated block lists what the rule excludes. It draws no edge.
        if cond.get("negated") is True:
            continue
        for op in cond.get("operands") or []:
            objtype = op.get("objectType")
            ref = op.get("rhs")
            if objtype == "APP" and ref is not None:
                b.rel("FOR", label, ruid, "ZpaAppSegment", uid.zpa(tenant, "seg", ref))
            elif objtype == "APP_GROUP" and ref is not None:
                b.rel("FOR", label, ruid, "ZpaSegmentGroup", uid.zpa(tenant, "seggrp", ref))
            elif objtype == "SCIM_GROUP":
                iuid = _identity_group_node(b, tenant, op, scim_names)
                if iuid is not None:
                    b.rel(identity_rel, label, ruid, "IdentityGroup", iuid)


def normalize_zpa(raw: dict[str, Any], *, tenant: str) -> Batch:
    """Build the Batch of a raw ZPA payload.

    `ZpaAppConnector` writes no `RUNS_ON`. The address of a connector is its
    `private_ip`, and the reasoner rule `zpa-zia-ip-same-as` links it to a campus
    address.

    `conditions` on a rule is a JSON string of its condition blocks
    (`[{"operator": "OR", "operands": [{"type": "APP", "rhs": "2001"}]}]`).
    """
    b = GraphBuilder()
    scim_names = {
        (str(g.get("idpId")), str(g.get("id"))): g["name"]
        for g in raw.get("scim_groups", [])
        if g.get("name")
    }

    for grp in raw.get("segment_groups", []):
        b.node(
            "ZpaSegmentGroup",
            uid.zpa(tenant, "seggrp", grp["id"]),
            name=grp.get("name"),
            zpa_id=str(grp["id"]),
            enabled=_flag(grp.get("enabled")),
        )

    for seg in raw.get("app_segments", []):
        suid = b.node(
            "ZpaAppSegment",
            uid.zpa(tenant, "seg", seg["id"]),
            name=seg.get("name"),
            # `zpa_id` is the ZPA object id. The reasoner rule
            # `zia-forwarding-to-zpa-segment` joins a ZIA forwarding rule to the
            # segment on this id.
            zpa_id=str(seg["id"]),
            domains=seg.get("domainNames"),
            **_segment_destinations(seg.get("domainNames")),
            tcp_port_ranges=seg.get("tcpPortRanges"),
            udp_port_ranges=seg.get("udpPortRanges"),
            enabled=seg.get("enabled"),
            # With ALWAYS, ZPA never brokers the segment. With ON_NET, ZPA brokers
            # it only off the trusted network. With NEVER or no value, ZPA brokers it.
            bypass_type=(str(seg["bypassType"]).upper() if seg.get("bypassType") else None),
        )
        grp_id = seg.get("segmentGroupId")
        if grp_id is not None:
            b.rel("MEMBER_OF", "ZpaAppSegment", suid, "ZpaSegmentGroup", uid.zpa(tenant, "seggrp", grp_id))
        for sgref in seg.get("serverGroups") or []:
            b.rel(
                "SERVED_BY", "ZpaAppSegment", suid, "ZpaServerGroup", uid.zpa(tenant, "srvgrp", sgref["id"])
            )

    for srv in raw.get("server_groups", []):
        sruid = b.node(
            "ZpaServerGroup",
            uid.zpa(tenant, "srvgrp", srv["id"]),
            name=srv.get("name"),
            zpa_id=str(srv["id"]),
            enabled=_flag(srv.get("enabled")),
            dynamic_discovery=_flag(srv.get("dynamicDiscovery")),
        )
        for cg in srv.get("appConnectorGroups") or []:
            b.rel("USES", "ZpaServerGroup", sruid, "ZpaAppConnectorGroup", uid.zpa(tenant, "cgrp", cg["id"]))
        # Only a static group lists its servers.
        if srv.get("dynamicDiscovery") is False:
            for app_srv in srv.get("servers") or []:
                asuid = b.node(
                    "AppServer",
                    uid.zpa(tenant, "appsrv", app_srv["id"]),
                    name=app_srv.get("name"),
                    address=app_srv.get("address"),
                    enabled=app_srv.get("enabled"),
                )
                b.rel("CONTAINS", "ZpaServerGroup", sruid, "AppServer", asuid)

    for cg in raw.get("connector_groups", []):
        b.node(
            "ZpaAppConnectorGroup",
            uid.zpa(tenant, "cgrp", cg["id"]),
            name=cg.get("name"),
            location=cg.get("location"),
            enabled=_flag(cg.get("enabled")),
        )

    for conn in raw.get("connectors", []):
        status = conn.get("controlChannelStatus")
        cuid = b.node(
            "ZpaAppConnector",
            uid.zpa(tenant, "conn", conn["id"]),
            name=conn.get("name"),
            enabled=conn.get("enabled"),
            health=CONNECTOR_HEALTH.get(status) if status else None,
            control_channel_status=status,
            private_ip=conn.get("privateIp"),
            public_ip=conn.get("publicIp"),
        )
        grp_id = conn.get("appConnectorGroupId")
        if grp_id is not None:
            b.rel("HAS", "ZpaAppConnectorGroup", uid.zpa(tenant, "cgrp", grp_id), "ZpaAppConnector", cuid)

    for edge in raw.get("service_edges", []):
        status = edge.get("controlChannelStatus")
        b.node(
            "ZpaServiceEdge",
            uid.zpa(tenant, "edge", edge["id"]),
            name=edge.get("name"),
            kind="private",
            location=edge.get("location"),
            enabled=edge.get("enabled"),
            health=CONNECTOR_HEALTH.get(status) if status else None,
            control_channel_status=status,
        )

    for rule in raw.get("access_rules", []):
        position = _rule_position(rule, "access rule")
        if position is None:
            continue
        props = _rule_props(rule)
        if props["action"] not in ZPA_ACCESS_ACTIONS:
            props["action"] = None
        ruid = b.node(
            "ZpaAccessRule",
            uid.zpa(tenant, "rule", rule["id"]),
            position=position,
            priority=_rule_priority(rule),
            **props,
        )
        verdict = _ACCESS_EDGES.get((props["action_raw"] or "").upper(), "APPLIES_TO")
        _rule_edges(b, tenant, "ZpaAccessRule", ruid, rule, verdict, scim_names)
        # STEERS_VIA edges go to the connector groups and the server groups of
        # the rule. The broker chooses its connector among them.
        for ref in rule.get("appConnectorGroups") or []:
            if isinstance(ref, dict) and ref.get("id") is not None:
                b.rel(
                    "STEERS_VIA",
                    "ZpaAccessRule",
                    ruid,
                    "ZpaAppConnectorGroup",
                    uid.zpa(tenant, "cgrp", ref["id"]),
                )
        for ref in rule.get("appServerGroups") or []:
            if isinstance(ref, dict) and ref.get("id") is not None:
                b.rel(
                    "STEERS_VIA",
                    "ZpaAccessRule",
                    ruid,
                    "ZpaServerGroup",
                    uid.zpa(tenant, "srvgrp", ref["id"]),
                )

    for rule in raw.get("client_forwarding_rules", []):
        position = _rule_position(rule, "client forwarding rule")
        if position is None:
            continue
        fruid = b.node(
            "ZpaClientForwardingRule",
            uid.zpa(tenant, "fwdrule", rule["id"]),
            position=position,
            priority=_rule_priority(rule),
            **_rule_props(rule),
        )
        _rule_edges(b, tenant, "ZpaClientForwardingRule", fruid, rule, "APPLIES_TO", scim_names)

    for key in raw.get("provisioning_keys", []):
        b.node(
            "ZpaProvisioningKey",
            uid.zpa(tenant, "provkey", key["id"]),
            name=key.get("name"),
            enabled=key.get("enabled"),
            max_usage=key.get("maxUsage"),
            usage_count=key.get("usageCount"),
            zcomponent_id=key.get("zcomponentId"),
            zcomponent_name=key.get("zcomponentName"),
        )

    batch = b.batch("zpa", _scope(tenant))
    batch.sections["mtu"] = SectionOutcome(
        status="unsupported",
        detail=(
            "Current ZPA connector/service-edge APIs provide no validated host or transport MTU; "
            "brokered legs are separate connections"
        ),
    )
    batch.sections.update(section_outcomes(raw, OPTIONAL_SECTIONS))
    return batch
