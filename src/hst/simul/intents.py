"""One catalog of stored intents and the engines that can interpret them."""

from dataclasses import dataclass

FW_KINDS = frozenset({"fw_rule.add", "fw_rule.remove", "fw_rule.modify"})
NAT_KINDS = frozenset({"nat_rule.add", "nat_rule.remove", "nat_rule.modify"})
ZONE_KINDS = frozenset({"zone.add_interface", "zone.remove_interface"})
ROUTING_KINDS = frozenset({"bgp_session.shut", "ospf.interface_cost", "ospf.adjacency_down"})
# `interface.set_mtu` restates the rows of the MTU evidence read
# (`hst.core.mtu_read.MTU_QUERY`).
INTERFACE_KINDS = frozenset({"interface.set_mtu"})
OVERLAY_KINDS = FW_KINDS | NAT_KINDS | ZONE_KINDS | ROUTING_KINDS | INTERFACE_KINDS
STAGE_2_KINDS = frozenset(
    {"device.exclude", "static_route.add", "static_route.remove", "route_delta.declared"}
)
STAGE_3_KINDS = frozenset(
    {
        "prefix_list_entry.add",
        "prefix_list_entry.remove",
        "prefix_list_entry.replace",
        "route_policy.attach",
        "route_policy.detach",
        "bgp_session.shut",
        "bgp_session.unshut",
    }
)
STORED_KINDS = STAGE_2_KINDS | STAGE_3_KINDS | OVERLAY_KINDS
RIB_SHAPING_KINDS = STAGE_2_KINDS - {"device.exclude"}


@dataclass(frozen=True)
class IntentCapability:
    kind: str
    stored: bool
    engines: tuple[str, ...]
    generated: bool
    reversible: bool


def capabilities() -> list[IntentCapability]:
    """Returns one `IntentCapability` for each stored intent kind, sorted by kind.

    The target and the platform of an intent are validated at runtime.
    """
    return [
        IntentCapability(
            kind,
            True,
            tuple(
                name
                for name, kinds in (
                    ("declared", RIB_SHAPING_KINDS),
                    ("overlay", INTERFACE_KINDS),
                    ("impact", OVERLAY_KINDS - INTERFACE_KINDS),
                )
                if kind in kinds
            ),
            kind in FW_KINDS,
            kind in FW_KINDS or kind in INTERFACE_KINDS,
        )
        for kind in sorted(STORED_KINDS)
    ]
