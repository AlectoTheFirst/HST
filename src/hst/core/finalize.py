"""The finalization stages write nothing but graph objects under the run's own `collection_ts`."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .config import Settings
from .model import RunManifest

if TYPE_CHECKING:
    from .manifest import SidestoreFiles

logger = logging.getLogger(__name__)


@dataclass
class RunFindings:
    stretch_observations: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def manifest_line(m: RunManifest) -> str:
    """One load's counters as a run-detail line."""
    line = (
        f"nodes {m.nodes_upserted} (+{m.nodes_created}, -{m.nodes_retired}) · "
        f"rels {m.rels_upserted} (+{m.rels_created}, -{m.rels_retired})"
    )
    if m.errors:
        line += " · warnings: " + "; ".join(m.errors)
    return line


def finalize_derivations(
    session: Any,
    settings: Settings,
    cts: int,
    assigned_sites: Mapping[str, str | None] | None,
    *,
    ts_ms: int | None = None,
    rules: Any = None,
    route_targets: Any = None,
    cycle: Any = None,
    findings: RunFindings | None = None,
    parent: int | None = None,
    sidestore_files: SidestoreFiles | None = None,
    site_blocks: Mapping[str, tuple[str, str | None]] | None = None,
) -> list[str]:
    """The readers of the detail lines depend on the order of the stages."""
    from hst import reasoner as default_rules

    from . import cycle as default_cycle
    from . import reasoner as default_route_targets

    rules = default_rules if rules is None else rules
    route_targets = default_route_targets if route_targets is None else route_targets
    cycle = default_cycle if cycle is None else cycle

    stamp: dict[str, int] = {} if ts_ms is None else {"ts_ms": ts_ms}
    files: dict[str, SidestoreFiles] = {} if sidestore_files is None else {"sidestore_files": sidestore_files}
    # The gateway rule reads Device.role.
    device_roles = getattr(rules, "apply_device_roles", None)
    roles = None
    if device_roles is not None:
        roles = device_roles(session, collection_ts=cts, tokens=settings.hostname_tier_tokens)
    results = rules.run(session, collection_ts=cts, **stamp)
    detail_lines = []
    # The warnings of the rules are separate lines after the derivation lines.
    rule_warnings: list[str] = []
    for r in results:
        rule_warnings.extend(r.get("warnings") or [])
        extra = ", ".join(f"{k}: {v}" for k, v in r.items() if k not in ("rule", "edges", "warnings"))
        detail_lines.append(f"{r['rule']}: {r['edges']}" + (f" ({extra})" if extra else ""))
    arp_cables = getattr(rules, "derive_arp_cables", None)
    if arp_cables is not None:
        r = arp_cables(session, collection_ts=cts, sidestore_dir=settings.sidestore_dir, **stamp, **files)
        rule_warnings.extend(r.get("warnings") or [])
        extra = ", ".join(f"{k}: {v}" for k, v in r.items() if k not in ("rule", "edges", "warnings"))
        detail_lines.append(f"{r['rule']}: {r['edges']}" + (f" ({extra})" if extra else ""))
    details = ["reasoner: " + (", ".join(detail_lines) or "no rules fired")]
    from . import ipam

    try:
        report = ipam.annotate(session, settings, collection_ts=cts, ts_ms=ts_ms)
    except Exception as exc:
        logger.warning("ipam: register not applied (%s: %s)", type(exc).__name__, exc)
        details.append(f"ipam: not applied ({type(exc).__name__}: {exc})")
    else:
        if report is not None:
            details.append(ipam.detail_line(report))
    domains = route_targets.execute_rt_domains(session, settings, collection_ts=cts, **stamp)
    details.append(f"rt-domains: {manifest_line(domains)}")
    speed = route_targets.execute_link_speed(session, settings, collection_ts=cts, **stamp)
    details.append(f"link-speed: {manifest_line(speed)}")
    details.extend(f"warning: {line}" for line in rule_warnings)
    if findings is not None:
        findings.warnings.extend(rule_warnings)
    # The vlan-stretch check below reads each device's LOCATED_IN site.
    cycle.apply_site_assignments(session, assigned_sites or {}, cts)
    carry = getattr(cycle, "carry_site_assignments", None)
    if carry is not None:
        if parent is None:
            carry(session, assigned_sites or {}, cts)
        else:
            carry(session, assigned_sites or {}, cts, parent)
    # An empty map clears every stamp.
    stamp_blocks = getattr(cycle, "apply_site_blocks", None)
    if site_blocks is not None and stamp_blocks is not None:
        stamp_blocks(session, site_blocks, cts)
    check = getattr(rules, "check_vlan_stretch", None)
    if check is not None:
        report = check(session, collection_ts=cts, sidestore_dir=settings.sidestore_dir, **files)
        observations = report["observations"]
        warnings = report["warnings"]
        if observations or warnings or report["uncarried"]:
            refused, uncarried = len(report["unbound_ports"]), report["uncarried"]
            details.append(
                f"vlan-stretch: {len(observations)} observation(s), {len(warnings)} warning(s), "
                f"{refused} refused binding(s), {uncarried} uncarried circuit(s)"
            )
            details.extend(f"warning: {w}" for w in warnings)
        if findings is not None:
            findings.stretch_observations.extend(observations)
            findings.warnings.extend(warnings)
    edge_check = getattr(rules, "check_edge_devices", None)
    if edge_check is not None:
        edge_report = edge_check(session, collection_ts=cts)
        if edge_report["warnings"]:
            details.append(
                f"edge-devices: {len(edge_report['proposed'])} proposed binding(s), "
                f"{len(edge_report['warnings'])} warning(s)"
            )
            details.extend(f"warning: {w}" for w in edge_report["warnings"])
            if findings is not None:
                findings.warnings.extend(edge_report["warnings"])
    zscaler_check = getattr(rules, "check_zscaler", None)
    if zscaler_check is not None:
        zscaler_report = zscaler_check(session, collection_ts=cts)
        if zscaler_report["warnings"]:
            details.append(f"zscaler: {len(zscaler_report['warnings'])} warning(s)")
            details.extend(f"warning: {w}" for w in zscaler_report["warnings"])
            if findings is not None:
                findings.warnings.extend(zscaler_report["warnings"])
    # The role step's line goes last.
    if roles is not None:
        details.append(device_roles_line(roles))
    return details


def device_roles_line(roles: Mapping[str, Any]) -> str:
    """The run detail line of the role step, e.g. `device-roles: 412
    device(s), 300 role(s) changed (collector 20, default 12, hostname 380)`."""
    basis = ", ".join(f"{k} {v}" for k, v in roles["basis"].items())
    line = f"device-roles: {roles['devices']} device(s), {roles['changed']} role(s) changed"
    return line + (f" ({basis})" if basis else "")
