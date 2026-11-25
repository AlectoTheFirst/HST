"""Network-level construction for bounded compiled round-trip evaluation."""

from __future__ import annotations

from collections.abc import Callable
from ipaddress import ip_network

from hst.impact.evaluate import Member, Network, RequestSet
from hst.impact.symbolic_walk import DEFAULT_LIMITS, WalkLimits, walk
from hst.policy.bounds import ChoiceMode
from hst.policy.ir import ExecutionContext
from hst.symbolic import PacketSet, SymbolicManager
from hst.symbolic.address_render import address_prefixes

from .compile import AnalysisModel, compile_model
from .evidence import EvidenceEvaluation
from .graph import GraphInventory
from .model import ModelInput, StateKey
from .network import normalize_reply_network
from .session_walk import SessionWalkResult, session_walk
from .sessions import (
    SessionCatalog,
    install_reverse_binding,
    install_reverse_translations,
    reject_session,
)

ModelCompiler = Callable[[ModelInput, SymbolicManager, frozenset[str]], AnalysisModel]

# `reply_destinations` returns at most this count of prefixes one by one.
MAX_REPLY_PREFIXES = 256


def reply_destinations(permitted: PacketSet, af: int) -> tuple[tuple[int, int, int], ...]:
    """Return the source addresses of the permitted forward packets after
    any source translation.

    A reply is sent to these addresses. A cover of more than
    `MAX_REPLY_PREFIXES` prefixes is widened to the one range from its lowest
    to its highest address. A set that `address_prefixes` cannot count is
    widened to the whole address family."""
    if permitted.is_empty():
        return ()
    bits = 32 if af == 4 else 128
    try:
        page = address_prefixes(permitted, field="source_address", bank="current", limit=MAX_REPLY_PREFIXES)
        if page.next_offset is None:
            prefixes = page.items
        else:
            last = address_prefixes(
                permitted, field="source_address", bank="current", offset=page.count - 1, limit=1
            )
            low = ip_network(page.items[0]).network_address
            high = ip_network(last.items[-1]).broadcast_address
            return ((af, int(low), int(high)),)
    except ValueError:
        return ((af, 0, (1 << bits) - 1),)
    return tuple(
        (af, int(network.network_address), int(network.broadcast_address))
        for network in (ip_network(prefix) for prefix in prefixes)
    )


def network_session_walk(
    network: Network,
    graph: GraphInventory,
    request: RequestSet,
    member: Member,
    manager: SymbolicManager,
    forward_model: AnalysisModel,
    request_packets: PacketSet,
    *,
    estate: str,
    request_id: str,
    compiler: ModelCompiler = compile_model,
    catalog: SessionCatalog | None = None,
    binding_id: str | None = None,
    reply_context: ExecutionContext | None = None,
    requires_state: bool = False,
    mode: ChoiceMode = "unspecified",
    limits: WalkLimits = DEFAULT_LIMITS,
    cancelled: Callable[[], bool] | None = None,
    evidence: EvidenceEvaluation | None = None,
) -> SessionWalkResult:
    """Build the reverse model from exact forward terminal contexts and evaluate it."""
    preview = walk(
        forward_model,
        request_packets,
        request_id=request_id,
        mode=mode,
        limits=limits,
        cancelled=cancelled,
    )
    entries = tuple(
        dict.fromkeys(
            terminal.state
            for result in preview.by_choice
            for terminal in result.terminal_reaches
            if terminal.outcome == "permit" and not terminal.packets.intersect(result.bounds.lower).is_empty()
        )
    )
    permitted = manager.empty()
    for result in preview.by_choice:
        for terminal in result.terminal_reaches:
            if terminal.outcome == "permit":
                permitted = permitted.union(terminal.packets.intersect(result.bounds.lower))
    reply_input = normalize_reply_network(
        network,
        graph,
        request,
        member,
        estate,
        entries,
        evidence=evidence,
        destinations=reply_destinations(permitted, request.sources[0][0]),
        # These contexts masqueraded the request with a port of their own.
        masquerading=frozenset(node.key.context for node in forward_model.nodes if node.free_source_ports),
    )
    reply_model = compiler(reply_input, manager, forward_model.universe.known_fields)
    if binding_id is None:
        reply_model = install_reverse_translations(
            forward_model,
            reply_model,
            interface_addresses=_interface_addresses(network),
            request=request_packets,
            # a virtual system's hide NAT is undone only by an observed binding
            binding_required=frozenset(
                uid
                for uid in {node.key.context.firewall_instance for node in forward_model.nodes}
                if (instance := graph.nodes.get(uid)) is not None and "FirewallInstance" in instance.labels
            ),
            reply_order=lambda context, ingress: reply_order_gap(
                graph, context, ingress, request.sources[0][0]
            ),
        )
    else:
        if catalog is None:
            from .checkpoint_sessions import catalog_from_graph

            choices = forward_model.choices
            if len(choices) == 1:
                catalog = catalog_from_graph(
                    graph,
                    estate=estate,
                    request_id=request_id,
                    choice_scope=tuple(value for _scope, value in choices[0].bindings),
                    binding_id=binding_id,
                )
            else:
                catalog = SessionCatalog(complete=False)
        binding = catalog.binding(binding_id)
        if binding is None:
            code = "NAT_BINDING_ABSENT" if catalog.complete else "NAT_BINDING_NOT_OBSERVED"
            reply_model = reject_session(reply_model, code)
        else:
            owner = reply_context or binding.owner.execution_context
            restored = catalog.reverse(
                manager,
                binding_id,
                reply_context=owner,
                request_id=request_id,
                choice_scope=binding.owner.choice_scope,
            )
            if restored.status == "exact" and restored.relation is not None:
                reply_model = install_reverse_binding(
                    reply_model,
                    restored.relation,
                    owner_context=owner,
                    choice_scope=binding.owner.choice_scope,
                )
            else:
                reply_model = reject_session(
                    reply_model,
                    restored.gap_code or "SESSION_BINDING_UNKNOWN",
                )
    return session_walk(
        forward_model,
        reply_model,
        request_packets,
        request_id=request_id,
        requires_state=requires_state,
        mode=mode,
        limits=limits,
        cancelled=cancelled,
        forward_result=preview,
        # `normalize_reply_network` builds one reply entry per forward terminal, in this order.
        entry_terminals=entries,
        edge_sources=_uplink_addresses(network, entries),
    )


# On these platforms the device-wide filter reads the reply after the reverse
# translation (`_FILTER_VIEW_BY_VENDOR` 'translated' in path/gates/firewall.py),
# and the model reads the state admission from the collected configuration.
# VyOS has a global state policy or state matches in its rule sets.
# Cisco IOS-XE and NX-OS have interface ACLs and no device-wide filter.
# An outbound interface ACL runs after the translation.
# An inbound interface ACL gives `SESSION_REPLY_ACL_BEFORE_RESTORE`.
_REPLY_ORDER_DECIDED = frozenset({"vyos", "iosxe", "ios", "nxos"})
# Check Point reads its access policy on the packet as it arrived ('original').
# Its reply is decided where the collected state policy (vendor default)
# admits or drops the packet before any rule.
_STATE_POLICY_FIRST = frozenset({"checkpoint", "checkpoint-gaia"})


def reply_order_gap(graph: GraphInventory, context: ExecutionContext, ingress: str, af: int) -> str | None:
    """Return the gap code for an owner `context` that handles a reply in
    another order than the model, or None.

    The reply enters by `ingress`, an interface uid. The model restores the
    reply first and then reads the inbound filter of the routing state and
    the state admission (`install_reverse_translations`).

    - An inbound interface ACL on `ingress` gives
      `SESSION_REPLY_ACL_BEFORE_RESTORE` on any platform. The device reads
      the ACL on the packet as it arrived, before the translation is undone
      (the tracer's `_INTERFACE_ACL_VIEW`). A device with an unreported
      interface ACL binding gives the same code.
    - VyOS, Cisco IOS-XE and NX-OS are decided.
    - Check Point is decided where the collected state policy decides an
      established packet. Elsewhere, and for a VSX virtual system, the code
      is `SESSION_STATE_POLICY_NOT_COLLECTED`. The tracer reads the rules of
      a virtual system without the chassis policy.
    - FortiGate is stateful and has no collected state policy. The code is
      `SESSION_STATE_POLICY_NOT_COLLECTED`.
    - Any other platform, or a missing device, gives
      `SESSION_REPLY_ORDER_NOT_ESTABLISHED`."""
    from .network import _bindings, _state_admission

    instance = graph.nodes.get(context.firewall_instance)
    if instance is None:
        return "SESSION_REPLY_ORDER_NOT_ESTABLISHED"
    if _inbound_acl(graph, context.firewall_instance, ingress):
        return "SESSION_REPLY_ACL_BEFORE_RESTORE"
    if "FirewallInstance" in instance.labels:
        return "SESSION_STATE_POLICY_NOT_COLLECTED"
    platform = str(instance.props.get("platform") or "").lower()
    if platform in _REPLY_ORDER_DECIDED:
        return None
    if platform in _STATE_POLICY_FIRST:
        rulebases, _installation = _bindings(graph, context, ingress, None, af)
        admission = _state_admission(graph, context, rulebases, "established") if rulebases else None
        return None if admission in {"permit", "deny"} else "SESSION_STATE_POLICY_NOT_COLLECTED"
    if platform == "fortigate":
        return "SESSION_STATE_POLICY_NOT_COLLECTED"
    return "SESSION_REPLY_ORDER_NOT_ESTABLISHED"


def _inbound_acl(graph: GraphInventory, device: str, interface: str) -> bool:
    """Return whether an interface ACL may read packets that arrive on `interface`.

    True for an ACL bound to `interface` inbound or with no direction. True
    also for an ACL of `device` with an unreported binding that is not
    outbound."""
    for relation in graph.outgoing.get((interface, "PROTECTED_BY"), ()):
        base = graph.nodes.get(relation.end)
        if (
            base is not None
            and base.props.get("match_context") == "interface-acl"
            and relation.props.get("direction") != "out"
        ):
            return True
    for base in graph.targets(device, "ENFORCES"):
        unreported = base.props.get("unreported_bindings")
        if base.props.get("match_context") == "interface-acl" and any(
            not str(entry).endswith(" out")
            for entry in (unreported if isinstance(unreported, (list, tuple)) else ())
        ):
            return True
    return False


def _interface_addresses(network: Network) -> dict[str, dict[str, tuple[tuple[int, int, int], ...]]]:
    """The addresses each interface holds, by VRF uid and interface uid
    (`install_reverse_translations`)."""
    from hst.path.addrsets import _intervals

    result: dict[str, dict[str, tuple[tuple[int, int, int], ...]]] = {}
    for interface in network.interfaces:
        if interface.context_uid is not None and interface.addresses:
            result.setdefault(interface.context_uid, {})[interface.uid] = tuple(
                _intervals(list(interface.addresses))
            )
    return result


def _uplink_addresses(
    network: Network, terminals: tuple[StateKey, ...]
) -> dict[str, tuple[tuple[int, int, int], ...]]:
    """Return the addresses of the interface that each forward terminal is
    bound to (`reply-ingress`), by interface uid.

    `session_walk` compares them with the translated source of the packets
    at an estate edge."""
    from hst.path.addrsets import _intervals

    bound = {
        value.removeprefix("reply-ingress:")
        for terminal in terminals
        for value in terminal.binding_scope
        if value.startswith("reply-ingress:")
    }
    return {
        interface.uid: tuple(_intervals(list(interface.addresses)))
        for interface in network.interfaces
        if interface.uid in bound and interface.addresses
    }
