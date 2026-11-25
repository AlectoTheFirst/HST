import importlib
from dataclasses import dataclass, replace

from hst.impact import GraphGates, Interface, Member, Network, RequestSet, Service, answer, member
from hst.path.addrsets import _intervals, _ports
from hst.path.gates.nat import NatTransition
from hst.path.gates.tunnel import build_carrier_legs
from hst.path.state import Effect, FlowRegion
from hst.simul.rib import RibInput


def ips(spec):
    return tuple(_intervals([spec]))


@dataclass
class Verdict:
    kind: str = "pass"

    def apply(self, region):
        return [(region, Effect(self.kind, "firewall", terminal=self.kind == "deny"))]


class Gates:
    def __init__(
        self, *, deny_reply=False, stateful=False, snat=False, carrier_state="up", block_carrier=False
    ):
        self.deny_reply = deny_reply
        self.stateful = stateful
        self.use_snat = snat
        self.carrier_state = carrier_state
        self.block_carrier = block_carrier

    def dnat(self, device, ingress):
        return Verdict()

    def filter(self, device, ingress, egress):
        return Verdict()

    def reply_filter(self, device, ingress, egress, established):
        return Verdict("deny" if self.deny_reply and not (self.stateful and established) else "pass")

    def local_filter(self, device, ingress):
        return Verdict("deny" if self.block_carrier and ingress and ingress.name == "wan" else "pass")

    def output_filter(self, device, egress):
        return Verdict()

    def load_balancer(self, device, address):
        return None

    def snat(self, device, ingress, egress):
        if not self.use_snat or device != "r1":
            return Verdict()
        return NatTransition(
            [
                {
                    "uid": "nat:source",
                    "match_src": list(ips("10.0.0.10")),
                    "match_dst": [],
                    "rewrite": "src",
                    "xlate": list(ips("192.0.2.1")),
                    "src_port_spec": "40000",
                    "xlate_src_port_spec": "50000",
                    "protos": ["tcp"],
                    "port_spec": None,
                }
            ],
            complete_service=True,
        )

    def tunnels(self, egress, inner):
        if egress.name != "wg":
            return ()
        one, two = ("1", "2") if egress.device_uid == "r1" else ("2", "1")
        return build_carrier_legs(
            [
                {
                    "tunnel_uid": f"t{one}",
                    "encap": "wireguard",
                    "binding_kind": "interface",
                    "state": self.carrier_state,
                    "allowed_ips": ["0.0.0.0/0"],
                    "local_address": f"192.0.2.{one}",
                    "remote_address": f"192.0.2.{two}",
                    "carrier_proto": "udp",
                    "carrier_port": 51820,
                    "local_device_uid": f"r{one}",
                    "local_interface_uid": f"wg{one}",
                    "local_context_uid": f"c{one}",
                    "local_underlay_interface_uid": f"wan{one}",
                    "local_underlay_context_uid": f"u{one}",
                    "remote_device_uid": f"r{two}",
                    "remote_interface_uid": f"wg{two}",
                    "remote_context_uid": f"c{two}",
                    "remote_underlay_interface_uid": f"wan{two}",
                    "remote_underlay_context_uid": f"u{two}",
                    "peer_tunnel_uid": f"t{two}",
                }
            ],
            inner,
        )


def network(*, return_route=True, tunnel=False, **gate_options):
    interfaces = [
        Interface("r1", "lan1", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
        Interface("r2", "lan2", "lan", "c2", ("203.0.113.0/24",), ("203.0.113.1",)),
    ]
    for n in (1, 2):
        interfaces.append(
            Interface(
                f"r{n}",
                f"wan{n}",
                "wan",
                f"u{n}" if tunnel else f"c{n}",
                ("192.0.2.0/30",),
                (f"192.0.2.{n}",),
            )
        )
        if tunnel:
            interfaces.append(Interface(f"r{n}", f"wg{n}", "wg", f"c{n}", ("10.8.0.0/30",), (f"10.8.0.{n}",)))
    contexts = [{"uid": i.context_uid, "device_uid": i.device_uid, "platform": "nxos"} for i in interfaces]
    connected = [
        {"context_uid": i.context_uid, "prefix": p, "interface": i.name}
        for i in interfaces
        for p in i.prefixes
    ]
    transit = "10.8.0" if tunnel else "192.0.2"
    static = [{"context_uid": "c1", "prefix": "203.0.113.0/24", "next_hop": f"{transit}.2"}]
    if return_route:
        static.append({"context_uid": "c2", "prefix": "10.0.0.0/24", "next_hop": f"{transit}.1"})
    return Network(
        RibInput(contexts=contexts, connected=connected, static=static),
        tuple(interfaces),
        Gates(**gate_options),
        # every context is in one routing domain
        context_domains={i.context_uid: frozenset({"declared:estate"}) for i in interfaces},
    )


def request(success="session"):
    return RequestSet(
        "app",
        ips("10.0.0.10"),
        "app",
        (Member("server", ips("203.0.113.10")),),
        member("server"),
        Service(frozenset({6}), tuple(_ports("443")), tuple(_ports("40000"))),
        success=success,
    )


def test_forward_delivery_does_not_establish_a_session_without_a_return_route():
    net = network(return_route=False)
    assert answer(net, request("forward")).lower
    result = answer(net, request())
    assert not result.lower
    assert not result.upper


def test_device_origin_is_explicit_and_uses_output_policy():
    class OriginGates(Gates):
        def filter(self, device, ingress, egress):
            return Verdict("deny" if device == "r1" else "pass")

    net = replace(network(), gates=OriginGates())
    clients = replace(request("forward"), sources=ips("10.0.0.1"))
    assert not answer(net, clients).upper
    originated = replace(clients, source_device_uid="r1", source_context="c1")
    assert answer(net, originated).lower == originated.sources
    unowned = replace(originated, sources=ips("10.0.0.10"))
    result = answer(net, unowned)
    assert not result.lower
    assert result.upper == unowned.sources


def test_reply_policy_uses_only_state_created_on_the_forward_branch():
    assert not answer(network(deny_reply=True), request()).upper
    assert answer(network(deny_reply=True, stateful=True), request()).lower == request().sources
    assert not answer(network(deny_reply=True, stateful=True), request("round-trip")).upper


def test_correlated_reply_restores_source_address_and_pat_port():
    result = answer(network(snat=True), request())
    assert result.lower == result.upper == request().sources
    assert any(s.stage == "reply-nat" for e in result.members["server"].explanations for s in e.steps)


def test_tunnel_evaluates_outer_policy_and_resumes_the_overlay_context():
    result = answer(network(tunnel=True), request())
    assert result.lower == request().sources
    stages = [s.stage for e in result.members["server"].explanations for s in e.steps]
    assert "carrier/input-filter" in stages
    assert "tunnel" in stages
    assert not answer(network(tunnel=True, block_carrier=True), request()).upper


def test_unobserved_tunnel_state_cannot_support_a_proof():
    result = answer(network(tunnel=True, carrier_state=None), request())
    assert not result.lower
    assert result.upper == request().sources


def test_graph_gate_factories_request_strict_symbolic_modes(monkeypatch):
    module = importlib.import_module("hst.impact.evaluate")
    monkeypatch.setattr(module, "_nat_rows", lambda *_, **__: [])
    monkeypatch.setattr(module, "nat_rulebase_credits", lambda *_: [])
    gates = GraphGates(None)
    assert gates.dnat("r1", None).transition.complete_service
    assert gates.snat("r1", None, None).transition.complete_service


def test_global_state_policy_decodes_its_action_strings(monkeypatch):
    module = importlib.import_module("hst.impact.evaluate")
    rows = [{"uid": "rb:state", "global_state_policy": ["established=drop", "related=accept"]}]
    monkeypatch.setattr(module.pathmod, "_read", lambda *_, **__: rows)
    region = request().member_region(request().members[0])
    gate = module._StatePolicyFilter(None, "r1", "established", Verdict(), Verdict())
    assert gate.apply(region)[0][1].kind == "deny"
    rows[0]["global_state_policy"] = ["established=accept"]
    gate = module._StatePolicyFilter(None, "r1", "established", Verdict("deny"), Verdict("deny"))
    # A recorded state accept never bypasses a separate stateless interface ACL.
    assert gate.apply(region)[0][1].kind == "deny"
    rows.append({"uid": "rb:conflict", "global_state_policy": ["established=drop"]})
    assert gate.apply(region)[0][1].kind == "indeterminate"


class FrontendPolicy:
    def apply(self, region):
        out = []
        for rect in region:
            wanted = rect.narrow(dst=ips("203.0.113.10"), dport=tuple(_ports("443")))
            accepted = FlowRegion.single(rect).intersect(FlowRegion.single(wanted))
            if accepted:
                out.append((accepted, Effect("permit", "firewall")))
            denied = FlowRegion.single(rect).subtract(accepted)
            if denied:
                out.append((denied, Effect("deny", "firewall", terminal=True)))
        return out


class DestinationNatGates(Gates):
    def __init__(self, view="original"):
        super().__init__()
        self.view = view

    def filter_view(self, device):
        return self.view, "the vendor's filter order is unrecorded" if self.view is None else None

    def dnat(self, device, ingress):
        if device != "r1":
            return Verdict()
        return NatTransition(
            [
                {
                    "uid": "nat:destination",
                    "match_src": [],
                    "match_dst": list(ips("203.0.113.0/24")),
                    "rewrite": "dst",
                    "xlate": list(ips("203.0.113.20")),
                    "protos": ["tcp"],
                    "port_spec": "443",
                    "xlate_port": 8443,
                }
            ],
            complete_service=True,
        )

    def filter(self, device, ingress, egress):
        return FrontendPolicy() if device == "r1" else Verdict()


def test_original_header_policy_preserves_a_partial_constant_nat_preimage():
    req = replace(request("forward"), members=(Member("server", ips("203.0.113.0/24")),))
    net = replace(network(), gates=DestinationNatGates())
    result = answer(net, req).members["server"]
    assert result.lower == req.member_region(req.members[0]).intersect(
        FlowRegion.from_query(
            req.sources, ips("203.0.113.10"), frozenset({6}), _ports("443"), _ports("40000")
        )
    )
    assert result.upper == result.lower


def test_unknown_nat_policy_order_cannot_prove_failure_from_translated_headers():
    net = replace(network(), gates=DestinationNatGates(None))
    result = answer(net, request("forward"))
    assert not result.lower
    assert result.upper == request().sources


def test_virtual_service_not_assigned_to_an_interface_is_evaluated():
    class VipGates(Gates):
        virtual_services = ({"device_uid": "r2", "ip": "203.0.113.10", "uid": "vs:app"},)

        def load_balancer(self, device, address):
            return Verdict("deny") if device == "r2" and address == "203.0.113.10" else None

    result = answer(replace(network(), gates=VipGates()), request("forward"))
    assert not result.upper


def test_gate_preflight_prevents_a_later_route_absence_from_becoming_proven_failure():
    class UnknownGate(Gates):
        def coverage(self, branch, stage, egress, *, preflight):
            return Verdict("indeterminate")

    net = replace(network(return_route=False), gates=UnknownGate())
    result = answer(net, request())
    assert not result.lower
    assert result.upper == request().sources
