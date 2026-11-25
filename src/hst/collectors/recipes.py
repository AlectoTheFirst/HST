"""Recipes never execute caller-supplied commands."""

from dataclasses import dataclass
from importlib import import_module


@dataclass(frozen=True)
class Recipe:
    id: str
    collector: str
    section: str
    af: int | None
    commands: tuple[str, ...]
    prerequisites: tuple[str, ...] = (
        "Configured collector credentials with read access",
        "Reachable device and collection permission",
        "Successful normalization and committed snapshot publication before reevaluation",
    )
    cost_class: str = "device-fetch"
    scope: str = "device"
    tables: tuple[str, ...] = ()


def routing_recipe(collector: str, af: int) -> Recipe | None:
    if af == 4 and collector in {"nxos", "iosxe", "iosxr"}:
        from importlib import import_module

        module = import_module(f"hst.collectors.{collector}")
        return Recipe(f"{collector}.rib.ipv4", collector, "rib", af, (module.SECTIONS["rib"].command,))
    if collector == "vyos" and af in {4, 6}:
        from hst.collectors.vyos import _IP_PATH

        family = "ip" if af == 4 else "ipv6"
        return Recipe(
            f"vyos.rib.ipv{af}",
            collector,
            "routes" if af == 4 else "routes6",
            af,
            (f'{_IP_PATH} vtysh -c "show {family} route vrf all json"',),
        )
    return None


def section_recipe(collector: str, section: str, *, af: int | None = None) -> Recipe | None:
    if collector in {"nxos", "iosxe", "iosxr"}:
        if section == "rib":
            return routing_recipe(collector, af or 4)
        # Each section of `SECTIONS` has a read recipe. This includes the optional
        # sections `hsrp` and `vrrp` and the NX-OS section `vpc`.
        module = import_module(f"hst.collectors.{collector}")
        operation = module.SECTIONS.get(section)
        if operation is None:
            return None
        tables = ("ospf_lsdb",) if section.startswith("ospf") else ()
        return Recipe(f"{collector}.{section}", collector, section, af, (operation.command,), tables=tables)
    if collector == "vyos":
        from hst.collectors.vyos import READ_COMMANDS, VyosCollector

        command = READ_COMMANDS.get(section)
        if command is not None:
            return Recipe(
                f"vyos.{section}",
                collector,
                section,
                af,
                (VyosCollector._op_mode(command),),
                tables=("rib",) if section in {"routes", "routes6"} else (),
            )
    if collector == "checkpoint" and section in {"access", "nat"}:
        from hst.collectors.checkpoint import READ_COMMANDS as cp

        keys = ("gateways", "layers", "access") if section == "access" else ("packages", "nat")
        return Recipe(
            f"checkpoint.{section}",
            collector,
            section,
            af,
            tuple(f"POST /web_api/{cp[key]}" for key in keys),
            scope="source",
            cost_class="controller-fetch",
        )
    if collector == "apic" and section in {"policy", "endpoint"}:
        from hst.collectors.apic import CLASS_PATH, CLASSES

        return Recipe(
            f"apic.{section}",
            collector,
            section,
            af,
            tuple(f"GET {CLASS_PATH.format(cls=name)}" for name in CLASSES),
            scope="source",
            cost_class="controller-fetch",
        )
    if collector == "unifi" and section in {"policy", "devices", "networks", "clients"}:
        from hst.collectors.unifi import READ_PATHS

        keys = (
            [key for key in READ_PATHS if key.startswith("firewall_")] if section == "policy" else [section]
        )
        paths = []
        for key in keys:
            prefix = (
                "/proxy/network/v2/api/site/{site}/"
                if key in {"firewall_zones", "firewall_policies"}
                else "/proxy/network/api/s/{site}/"
            )
            paths.append(f"GET {prefix}{READ_PATHS[key]}")
        return Recipe(
            f"unifi.{section}",
            collector,
            section,
            af,
            tuple(paths),
            scope="source",
            cost_class="controller-fetch",
        )
    if collector == "zpa":
        from hst.collectors import zpa

        paths = {
            "app_segments": zpa.APPLICATION_PATH,
            "segment_groups": zpa.SEGMENT_GROUP_PATH,
            "server_groups": zpa.SERVER_GROUP_PATH,
            "connector_groups": zpa.APP_CONNECTOR_GROUP_PATH,
            "connectors": zpa.CONNECTOR_PATH,
            "service_edges": zpa.SERVICE_EDGE_PATH,
            "access_rules": zpa.RULES_PATH,
        }
        if section in paths:
            return Recipe(
                f"zpa.{section}",
                collector,
                section,
                af,
                (f"GET {paths[section]}",),
                scope="source",
                cost_class="controller-fetch",
            )
    return None
