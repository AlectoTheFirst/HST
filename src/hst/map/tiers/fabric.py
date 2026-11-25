"""Equinix Fabric on the map.

The fold reads the Fabric ports and the virtual circuits of a run in full. A Fabric port is a port of the
Equinix device of its site and IBX, else of the Fabric device of its metro in the site `EQUINIX-FABRIC`. A
cross-connect from a port of the account to a Fabric port is a cable, and a circuit end outside the
account is the device of the circuit's provider family.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .. import layout

FABRIC_SITE = "EQUINIX-FABRIC"
FABRIC_NAME = "Equinix Fabric"
# The provider families of a service profile name, each with the site code, the name and the match words.
FAMILIES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("CLOUD-AZURE", "Microsoft Azure", ("azure", "microsoft")),
    ("CLOUD-AWS", "Amazon Web Services", ("aws", "amazon")),
    ("CLOUD-GOOGLE", "Google Cloud", ("google",)),
    ("CLOUD-ORACLE", "Oracle Cloud", ("oracle",)),
    ("CLOUD-AKAMAI", "Akamai", ("akamai",)),
)
OTHER = ("CLOUD-OTHER", "Other parties")
ENDED = frozenset({"DEPROVISIONED", "DEPROVISIONING", "DELETED"})
CROSS_CONNECT = "equinix-cross-connect"
# The `source` of the cable the reasoner derives from a circuit between two ports of the account.
CIRCUIT_CABLE = "equinix-circuit"


def family(provider: str | None) -> tuple[str, str]:
    """The site code and the name of the provider family of a service profile name."""
    words = (provider or "").casefold()
    for code, name, keys in FAMILIES:
        if any(k in words for k in keys):
            return code, name
    return OTHER


def metro_device(metro: str | None) -> str:
    return f"eqx:fabric:{metro or 'unknown'}"


def provider_device(code: str) -> str:
    return "eqx:" + code.lower()


def ibx_device(site: str, ibx: str | None) -> str:
    return f"eqx:ibx:{site}:{ibx or 'unknown'}"


def spine_site(metro: str) -> str:
    return f"{layout.SPINE_PREFIX}{metro}"


def _common(paths: Iterable[tuple[str, ...]]) -> tuple[str, ...]:
    """The longest group path that starts every path of `paths`."""
    out: tuple[str, ...] | None = None
    for p in paths:
        if out is None:
            out = p
            continue
        n = 0
        while n < min(len(out), len(p)) and out[n] == p[n]:
            n += 1
        out = out[:n]
    return out or ()


def ibx_site(ibx: str | None, site_codes: Iterable[str]) -> str | None:
    """The site whose code is `ibx`, else the first site whose last code token is `ibx`."""
    if not ibx:
        return None
    key = ibx.upper()
    hits = [c for c in site_codes if c.upper() == key or c.upper().rsplit("-", 1)[-1] == key]
    return min(hits, key=lambda c: (c.upper() != key, c)) if hits else None


def _joined(values: Any) -> str | None:
    return ", ".join(str(v) for v in values) if values else None


@dataclass
class FabricMap:
    """The map elements of Equinix Fabric at one run, in the shapes of the bootstrap rows."""

    devices: dict[str, dict[str, Any]] = field(default_factory=dict)
    ports: list[dict[str, Any]] = field(default_factory=list)
    cables: list[dict[str, Any]] = field(default_factory=list)
    # `render_t1_circuits` rows without `change` and `snapshot_ts`.
    circuits: list[dict[str, Any]] = field(default_factory=list)
    # `render_t1_fabric_ports` rows without `change` and `snapshot_ts`.
    fabric_ports: list[dict[str, Any]] = field(default_factory=list)
    # The cloud sites, code to name.
    sites: dict[str, str] = field(default_factory=dict)
    # The spine site of a metro maps to its group path and to the sites of its bound ports in code order.
    spines: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = field(default_factory=dict)

    def device(self, uid: str, label: str, site: str, name: str | None, *, ibx: bool = False) -> str:
        """The device `uid` in `site`. A `name` is the name of a cloud site. An Equinix device of a site and
        IBX or of a spine (`ibx`) is a WAN edge device of platform `equinix-fabric`."""
        if uid not in self.devices:
            self.devices[uid] = {
                "uid": uid,
                "label": label,
                "role": "cloud",
                "tier": "wan-edge" if ibx else None,
                "vendor": "Equinix" if ibx or site == FABRIC_SITE else None,
                "model": None,
                "os_version": None,
                "mgmt_ip": None,
                "platform": layout.FABRIC_PLATFORM if ibx else None,
                "carried": False,
                "carried_reason": None,
                "last_seen_ts": None,
                "site": site,
                "group_uid": None,
                "wan": False,
            }
            if name is not None:
                self.sites[site] = name
        return uid


def build(
    ports: Iterable[Mapping[str, Any]],
    circuits: Iterable[Mapping[str, Any]],
    site_codes: Iterable[str] = (),
    groups: Mapping[str, tuple[str, ...]] | None = None,
) -> FabricMap:
    """The Fabric map of a run. `site_codes` holds the codes of the sites of the estate, and `groups` holds
    their site group paths."""
    out = FabricMap()
    fabric_ports = {p["uid"]: p for p in ports}
    codes = sorted(set(site_codes))
    groups = groups or {}
    # A metro whose bound ports are in sites of one site group is a spine in that group.
    bound: dict[str, set[str]] = {}
    for p in fabric_ports.values():
        if p.get("port") and p.get("device_site") and p.get("metro"):
            bound.setdefault(str(p["metro"]), set()).add(str(p["device_site"]))
    for code, sites in sorted(bound.items()):
        if all(s in groups for s in sites) and (path := _common(groups[s] for s in sorted(sites))):
            out.spines[spine_site(code)] = (path, tuple(sorted(sites)))

    def metro(p: Mapping[str, Any] | None) -> str:
        code = (p or {}).get("metro")
        if code and spine_site(code) in out.spines:
            # A spine draws as the Equinix device of its sites, with a model at site zoom.
            name = f"Fabric {code}"
            return out.device(metro_device(code), name, spine_site(code), name, ibx=True)
        return out.device(metro_device(code), f"Fabric {code or 'unknown'}", FABRIC_SITE, FABRIC_NAME)

    def home(p: Mapping[str, Any]) -> str:
        """The map device of Fabric port `p`."""
        if p.get("metro") and spine_site(str(p["metro"])) in out.spines:
            return metro(p)
        ibx = p.get("ibx")
        site = p.get("device_site") or p.get("located") or ibx_site(ibx, codes)
        if site is None:
            return metro(p)
        return out.device(ibx_device(site, ibx), f"Equinix {ibx or site}", site, None, ibx=True)

    port_device: dict[str, str] = {}
    for uid, p in sorted(fabric_ports.items()):
        device = port_device[uid] = home(p)
        issue, candidates = p.get("binding_issue"), p.get("binding_ports")
        if p.get("binding") and not p.get("port"):
            # The operator's binding names a port that is not in the run.
            issue, candidates = issue or "binding-not-in-run", candidates or [p["binding"]]
        out.fabric_ports.append(
            {
                "uid": uid,
                "device_uid": device,
                "name": p.get("name") or uid,
                "ibx": p.get("ibx"),
                "metro": p.get("metro"),
                "state": p.get("state"),
                "speed_mbps": p.get("speed_mbps"),
                "redundancy": p.get("redundancy"),
                "lag_name": p.get("lag_name"),
                "cable_ids": _joined(p.get("cable_ids")),
                "bound_by": p.get("bound_by") if p.get("port") else None,
                "port_uid": p.get("port"),
                "port_device": p.get("device"),
                "binding_issue": issue,
                "binding_ports": _joined(candidates),
            }
        )
        out.ports.append(
            {
                "device": device,
                "uid": uid,
                "name": p.get("name") or uid,
                "admin": "up",
                "oper": "up" if str(p.get("state") or "").upper() == "ACTIVE" else "down",
                "speed_mbps": p.get("speed_mbps"),
                "speed": None,
                "lag_uid": None,
                "interface_uid": None,
                "if_admin_up": None,
                "if_oper": None,
                "context_uid": None,
                "connected": p.get("port") is not None,
            }
        )
        if p.get("port") and p.get("device"):
            out.cables.append(
                {
                    "a_dev": p["device"],
                    "a_port": p["port"],
                    "b_dev": device,
                    "b_port": uid,
                    "source": CROSS_CONNECT,
                    "carried": False,
                    "a_speed": None,
                    "b_speed": p.get("speed_mbps"),
                }
            )
    for c in sorted(circuits, key=lambda r: r["uid"]):
        if str(c.get("state") or "").upper() in ENDED:
            continue
        code, name = family(c.get("provider"))
        ends: list[tuple[str, str | None, str | None]] = []
        for side in ("a", "z"):
            end_device: str | None = c.get(f"{side}_device")
            end_port: str | None = c.get(f"{side}_port")
            vlan = c.get(f"{side}_vlan")
            if "FabricPort" in (c.get(f"{side}_labels") or ()):
                end = c[f"{side}_end"]
                end_device, end_port = port_device.get(end) or metro(fabric_ports.get(end)), end
            elif end_device is None:
                end_device, end_port = out.device(provider_device(code), name, code, name), None
            ends.append((end_device, end_port, None if vlan is None else str(vlan)))
        (a_device, a_port, a_vlan), (z_device, z_port, z_vlan) = ends
        bandwidth = c.get("bandwidth_mbps")
        out.circuits.append(
            {
                "uid": c["uid"],
                "name": c.get("name"),
                "type": c.get("type"),
                "state": c.get("state"),
                "bandwidth_mbps": int(bandwidth) if bandwidth is not None else None,
                "provider": c.get("provider"),
                "family": name if c.get("provider") else None,
                "a_device": a_device,
                "a_port": a_port,
                "a_vlan": a_vlan,
                "z_device": z_device,
                "z_port": z_port,
                "z_vlan": z_vlan,
                "cable_id": None,
            }
        )
    return out
