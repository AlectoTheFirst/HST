"""Shared gate infrastructure: the pipeline Stage model, the hop accumulator
`_Trail`, the anchor/context identity key every gate-adjacent lookup groups
on, and the safeguard that catches a :Gate on the path the engine produced no
verdict for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import hst.path as _path
from hst.core.labels import LABELS, STRATA_TIERS, gate_binding_patterns, layer_of, tier_of

_GATE_KIND = (
    "[l IN labels(g) WHERE NOT l IN "
    "['Obj', 'Latest', 'Gate', 'Policy', 'L3', 'L2', 'Phys', 'Transport', 'Service', "
    "'Workload', 'App', 'Cloud', 'Meta']][0] AS kind"
)


def forwarding_visit(gateway: dict[str, Any]) -> str:
    """Member and virtual device jointly identify a forwarding/session visit."""
    instance = gateway.get("firewall_instance_uid")
    return f"{gateway['dev_uid']}|{instance}" if instance else str(gateway["dev_uid"])


def routing_visit(gateway: dict[str, Any], table_uid: str | None) -> str:
    """The key of a forwarding visit in one routing table. A routing loop is a
    second visit with the same key. A path that enters a device again in
    another table is a new visit (a firewall between two VRFs of one core
    switch). The key of a gateway with no table has an empty table uid."""
    return f"{forwarding_visit(gateway)}|table:{table_uid or ''}"


def gate_safeguard_query() -> str:
    """The safeguard's Cypher, generated from `core/labels.py` GATE_BINDINGS.

    The query has one UNION branch per declared binding pattern. Each branch
    has a `_retired_at IS NULL` guard per relationship. A gate label registered
    without a binding fails the registry test (tests/test_schema_contract.py).
    """
    branches = []
    for label, patterns in gate_binding_patterns().items():
        for pattern in patterns:
            rels = re.findall(r"\[(e\d+):", pattern)
            fragment = pattern.replace("(g)", f"(g:{label})")
            guards = " AND ".join(f"{r}._retired_at IS NULL" for r in rels)
            branches.append(f"  WITH d\n  MATCH {fragment}\n  WHERE NOT g:Retired AND {guards}\n  RETURN g")
    body = "\n  UNION\n".join(branches)
    return (
        "// gate safeguard: generated from core/labels.py GATE_BINDINGS\n"
        "MATCH (d:Device)\n"
        "WHERE d.uid IN $devs AND NOT d:Retired AND d:Obj AND d.collection_ts = $snap\n"
        "CALL {\n"
        f"{body}\n"
        "}\n"
        f"RETURN DISTINCT g.uid AS uid, g.name AS name, {_GATE_KIND}"
    )


def unevaluated_gates(session: Any, device_uids: list[str], evaluated: set[str]) -> list[dict[str, Any]]:
    """The gates on the path that the engine produced no verdict for.

    A `:Gate` is a node that the schema declares can permit, deny or rewrite traffic.
    The function returns each gate that a pattern of GATE_BINDINGS binds to a device
    of `device_uids` and that is not in `evaluated`. Gates the registry marks
    NOT_DEVICE_BOUND (per-flow ACI contracts, route policies) are credited by their
    own evaluators.
    """
    if not device_uids:
        return []
    rows = _path._read(session, gate_safeguard_query(), devs=device_uids)
    return [r for r in rows if r["uid"] not in evaluated]


class Stage(IntEnum):
    """The position of a hop in the journey of the packet.

    The order is the netfilter forwarding path. It has PREROUTING (destination
    NAT), the routing decision with policy first, the FORWARD filter,
    POSTROUTING (source NAT), the egress interface, the encapsulation and the
    link. A Cisco interface ACL has another order. An inbound list runs before
    every translation and an outbound list runs after every translation (the
    IOS-XE order of operations). The outbound list has the stages
    EGRESS_FILTER_RB and EGRESS_FILTER_RULE after source NAT. The inbound list
    is read on the original packet at the filter stage (gates/firewall.py).

    The 4 values below SRC_ENDPOINT are the stages of a brokered flow before
    SRC_ENDPOINT. Identity and policy decide the request of a ZPA client before
    a packet exists. IDENTITY is the IdentityGroup of the request. BROKER is the
    service edge that brokers the connection (reserved). ACCESS_RULE is the
    winning ZpaAccessRule. CONNECTOR is the chosen ZpaAppConnector. From
    SRC_ENDPOINT on, the pipeline runs for a new flow that starts at the
    attachment of the connector.
    """

    IDENTITY = 1
    BROKER = 2
    ACCESS_RULE = 3
    CONNECTOR = 4
    SRC_ENDPOINT = 10
    SRC_ATTACH = 20
    L2_FABRIC = 30
    INGRESS_IF = 40
    DEVICE = 50
    DNAT = 60
    PBR_POLICY = 70
    PBR_RULE = 80
    VRF = 90
    ROUTE = 100
    # The next hop that the routing decision chose. The trace draws it only
    # when an ECMP set forks. Each lane has the hop of its own next hop.
    NEXT_HOP = 105
    FILTER_RB = 110
    FILTER_RULE = 120
    SNAT = 130
    # An outbound interface ACL. IOS-XE runs it after the inside-to-outside
    # translation, on the translated packet (gates/firewall.py
    # `_apply_egress_acl`).
    EGRESS_FILTER_RB = 134
    EGRESS_FILTER_RULE = 136
    EGRESS_IF = 140
    # A destination that is a VirtualService VIP is terminated here. What
    # follows is the chosen pool member's own address.
    LOAD_BALANCER = 145
    ENCAP = 150
    # The encapsulated packet is a NEW flow (peer endpoint, its own route,
    # the output chain, its own POSTROUTING).
    CARRIER_ROUTE = 152
    CARRIER_FILTER = 154
    CARRIER_SNAT = 156
    CARRIER_EGRESS_IF = 158
    # The path to a recursive next hop. It holds the devices that reach the
    # next hop of a VRF route (a PE loopback) in the global table. The trace
    # draws it under that route.
    TRANSPORT = 159
    LINK = 160
    # The far end of a tunnel. The carrier packet arrives on the device that
    # holds the far address of the tunnel. The inner flow resumes there as a
    # forwarding decision of that device.
    DECAP = 165
    DST_FABRIC = 170
    DST_ATTACH = 180
    DST_ENDPOINT = 190


def _anchor_of(row: dict[str, Any]) -> Any:
    """The grouping/identity key for an IpAddress or Prefix row.

    `anchor` is the identity of the row. It is the uid of the owning
    VrfInstance for routed and connected addressing, an l2seg uid for endpoint
    addressing, or a source-scoped domain string. Two rows with the same anchor
    are in the same forwarding context or segment, whatever their `l3dom`
    strings are. `l3dom` is a display string. A row with no `anchor` groups on
    `l3dom`.
    """
    return row.get("anchor") or row.get("l3dom")


def is_gate_kind(kind: str) -> bool:
    """Whether a hop of `kind` draws as a gate. The gate kinds are the kinds of
    the gate registry of labels.py without `NatRule`. The engine evaluates a
    `NatRule` as a translation."""
    spec = LABELS.get(kind)
    return bool(spec and spec.gate) and kind != "NatRule"


@dataclass
class _Trail:
    """The hop accumulator shared by the trace stages.

    A hop holds its stage in the journey of the packet (`Stage`) and its
    device (`depth`). `rank_hops()` derives `rank` from the two.

    `lane` distinguishes parallel legs. A hop appended before the path
    branches has shared=True.
    """

    hops: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Every place the engine could not prove something. They stay in `notes`
    # as well.
    warnings: list[str] = field(default_factory=list)
    lane: int = 0
    shared: bool = True
    depth: int = 0
    # set once any `_dst_attachment` lookup in this trail finds the
    # destination address inside the domain being traced.
    dst_found: bool = False
    # the ip_uid of the destination instance a `_dst_attachment` lookup landed
    # on
    dst_uid: str | None = None
    # The count of writes of `dst_uid` (`pin_dst`). A replay of a recorded walk
    # (`walk_memo`) repeats the last write of the walk if the walk wrote it.
    dst_writes: int = 0
    # The destination address of the query, set once by `_trace_domain` before
    # the dNAT of any device runs. `_dst_duplicate_notes` compares against the
    # instances of this address. The `orig_dst` of a group is the destination
    # of one device before its translation.
    orig_dst: list[tuple[int, int, int]] | None = None
    # set True by `_device_stage` the first time any dNAT part rewrites the
    # destination, on any device along the path
    dst_translated: bool = False
    # Every destination set that a device on the path handled, before and after
    # its dNAT. A VirtualService whose every VIP is outside these sets is a
    # service that the flow does not reach (`trace._vip_misses_removed`).
    dst_seen: list[tuple[int, int, int]] = field(default_factory=list)
    # device uid -> (filter view, why it could not be derived), read once per
    # device per trace
    filter_views: dict[str, tuple[str | None, str | None]] = field(default_factory=dict)
    # The count of firewall or NAT regions that this trace has turned into
    # legs (`path_region_cap`).
    regions_spent: int = 0
    # The lanes this walk has opened beyond the first, counted over every
    # equal-cost fork of the trace (`path_lane_cap`).
    lanes_spent: int = 0
    # (device uid, table uid) -> the prefixes and addresses that table records
    # as directly attached, read once per trace.
    table_adjacency: dict[tuple[str, str | None], list[str]] = field(default_factory=dict)
    # interface uid -> the table of its IN_VRF edge (`pbr.interface_table`),
    # read once per trace. The PBR fall-through and the routing-loop key
    # (`routing_visit`) read it at every device visit.
    interface_tables: dict[str, str | None] = field(default_factory=dict)
    # set by `_gateway_walk` and `_delivery_walk` when the hop cap or a
    # missing path leaves a stretch of the L2 leg undrawn. `_trace_domain` ORs
    # this into every leg's `boundary` key once legs exist.
    l2_boundary: bool = False
    # set by `_draw_l2_chain` when a crossing on the L2 leg proves a VLAN/
    # BridgeDomain mismatch (carriage data present and disagreeing on both
    # sides). `_trace_domain` ORs this into every leg's `indeterminate` key
    # once legs exist.
    l2_mismatch: bool = False
    _seq: dict[tuple[int, int, int], int] = field(default_factory=dict)
    # Indexes of `hops`. `_hop_at` holds (uid, lane, depth) for a hop with a
    # pipeline position. `_hop_ranked` holds (uid, lane) for a ranked hop, which
    # has no position. `_hop_held` holds (lane, uid, `_pos`) for
    # `_replay_upstream`.
    _hop_at: set[tuple[str, int, int]] = field(default_factory=set)
    _hop_ranked: set[tuple[str, int]] = field(default_factory=set)
    _hop_held: set[tuple[int, str, Any]] = field(default_factory=set)
    # The devices that `_device_stage` visited, in call order. The sequence of
    # the reply walk is compared with the reverse of this sequence to flag
    # asymmetric routing.
    device_sequence: list[str] = field(default_factory=list)
    # forwarding visit -> the state that this trace read on the device for the
    # firewall verdict of a forward leg. The state holds the
    # `global_state_policy` of the device (None when not collected) and whether
    # the forward leg through the device was a permit with no undecided rule. A
    # reply walk reads the entry of its device to admit a reply from session
    # state.
    device_gate_state: dict[str, dict[str, Any]] = field(default_factory=dict)
    reply_nat_chain: tuple[dict[str, Any], ...] | None = None
    # the device/interface the forward walk delivered to, or terminated on as
    # router-local, set once by whichever of those two outcomes the forward
    # walk reaches. None when the forward walk did not get there (blocked,
    # indeterminate, or boundary before delivery).
    terminal: dict[str, Any] | None = None
    # The L3 hop cap of this trace, set once by the entry points. A stage that
    # starts a walk (the walk of a tunnel carrier to its peer) uses the same
    # cap.
    max_hops: int = 12
    # The tunnels whose carrier packet the walk is inside of, innermost last.
    # `_carrier_trace` pushes a context before it passes the encapsulated
    # packet to the device walk and pops the context after the walk. The decap
    # stage on the far device reads the top context to select the inner flow
    # that resumes. Every hop recorded while the stack is non-empty has
    # `overlay` (the stack depth) and `tunnel`. The decap stage stores the
    # continuation legs of the inner flow in `resumed` of the context, and
    # `_carrier_trace` returns them.
    carrier_stack: list[dict[str, Any]] = field(default_factory=list)
    # Greater than 0 while the routing gate walks the path to a recursive next
    # hop (the label-switched path under a VRF route whose next hop is a PE
    # loopback). A hop recorded during that walk has `transport`.
    transport: int = 0
    # The recorded device walks of this trace (`walk_memo`). A later lane that
    # enters the same device with the same flow replays a recorded walk.
    walk_memo: dict[Any, list[Any]] = field(default_factory=dict)
    # One set per device walk that is being recorded, innermost last. A set
    # holds the visits that the walk tested against the visited set
    # (`probe_visit`). A lane with another visited set replays the walk only if
    # the tests have the same results on its visited set.
    visit_probes: list[set[str]] = field(default_factory=list)
    # The notes written at most once per trace (`note_once`). A replay of a
    # recorded walk does not write them again.
    once_notes: set[str] = field(default_factory=set)
    # How many tied next-hop owners this trace walked on a copy of the trail
    # (`trace._next_hop_stage`), counted over the copies as well.
    tie_probes: int = 0

    def hop(self, uid: str, kind: str, label: str, note: str = "", *, stage: Stage) -> None:
        """Record a hop at `stage` of the current device, in the current lane."""
        if not uid:
            return
        # A node has one hop per lane and per pipeline depth. `rank_hops`
        # removes `_pos`. A hop recorded after the ranking is matched on uid
        # and lane.
        if (uid, self.lane) in self._hop_ranked or (uid, self.lane, self.depth) in self._hop_at:
            return
        # A stage can hold more than one hop, for example the L2 fabric. The
        # position within a stage is counted per depth and lane.
        key = (self.depth, int(stage), self.lane)
        seq = self._seq.get(key, 0)
        self._seq[key] = seq + 1
        self.append_hop(
            {
                "uid": uid,
                "kind": kind,
                "label": label,
                "note": note,
                "stage": stage.name,
                "lane": self.lane,
                "shared": self.shared,
                "layer": list(layer_of(kind)),
                "tier": STRATA_TIERS[tier_of(kind)],
                "gate": is_gate_kind(kind),
                "_pos": (self.depth, int(stage), seq),
                **(
                    {"overlay": len(self.carrier_stack), "tunnel": self.carrier_stack[-1]["tunnel_uid"]}
                    if self.carrier_stack
                    else {}
                ),
                **({"transport": True} if self.transport else {}),
            }
        )

    def append_hop(self, hop: dict[str, Any]) -> None:
        """Add one hop to `hops` and to the indexes `hop` and `_replay_upstream` check it by."""
        self.hops.append(hop)
        pos = hop.get("_pos")
        if pos is None:
            self._hop_ranked.add((hop["uid"], hop["lane"]))
        else:
            self._hop_at.add((hop["uid"], hop["lane"], pos[0]))
        self._hop_held.add((hop["lane"], hop["uid"], pos))

    def has_replayed(self, hop: dict[str, Any]) -> bool:
        """Whether this lane already holds `hop` at its own pipeline position."""
        return (self.lane, hop["uid"], hop.get("_pos")) in self._hop_held

    def append_drawn(self, hop: dict[str, Any]) -> None:
        """Add a hop that `hop` drew, at its own pipeline position
        (`walk_memo`). The stage count of the lane moves past the position of
        the hop."""
        self.append_hop(hop)
        depth, stage, seq = hop["_pos"]
        key = (depth, stage, hop["lane"])
        self._seq[key] = max(self._seq.get(key, 0), seq + 1)

    def lane_state(self, lane: int, depth: int) -> tuple[Any, ...]:
        """The state of `lane` that a walk reads when it enters a device at
        `depth` (`walk_memo`). It holds the hops of the lane at that depth or
        deeper and the position count of the lane per stage there."""
        held = sorted(
            (h["uid"], h["_pos"])
            for h in self.hops
            if h["lane"] == lane and h.get("_pos") is not None and h["_pos"][0] >= depth
        )
        counts = sorted((d, s, n) for (d, s, n_lane), n in self._seq.items() if n_lane == lane and d >= depth)
        return tuple(held), tuple(counts)

    def probe_visit(self, visit: str) -> None:
        """Record that the walk tested `visit` against its visited set."""
        for probes in self.visit_probes:
            probes.add(visit)

    def find_dst(self, ip_uid: str) -> None:
        """The lane landed on the destination instance `ip_uid`."""
        self.dst_found = True
        self.pin_dst(ip_uid)

    def pin_dst(self, ip_uid: str) -> None:
        """Set `ip_uid` as the destination instance that the lane landed on."""
        self.dst_uid = ip_uid
        self.dst_writes += 1

    def note_once(self, text: str) -> None:
        """Add a note that the trace holds at most once."""
        if text not in self.notes:
            self.notes.append(text)
        self.once_notes.add(text)

    def warn(self, text: str) -> None:
        """Add `text` as a note and as a warning that the answer is not proven."""
        self.notes.append(text)
        self.warnings.append(text)

    def at(self, lane: int) -> None:
        """Move onto a per-leg lane. Every later hop is unshared."""
        self.lane, self.shared = lane, False

    def rank_hops(self) -> None:
        """Project the pipeline positions onto the viewer's x-axis.

        The ranks are dense. Every hop at the same (device, stage, index) gets
        the same rank in every lane. A lane with no hop at a stage has a gap
        there.
        """
        order = {pos: i for i, pos in enumerate(sorted({h["_pos"] for h in self.hops}))}
        for h in self.hops:
            h["rank"] = order[h.pop("_pos")]
        # The hops have no position after the ranking. The indexes are rebuilt on uid and lane.
        self._hop_at.clear()
        self._hop_ranked = {(h["uid"], h["lane"]) for h in self.hops}
        self._hop_held = {(h["lane"], h["uid"], None) for h in self.hops}
