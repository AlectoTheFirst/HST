"""VrfDomains: the VrfInstance/RouteTarget minting collectors/util.py owns."""

from hst.collectors.util import GraphBuilder, VrfDomains
from hst.core import uid
from hst.core.l3domain import DomainPolicy, Vrf, resolve

DEV = "dev:leaf1"
SCOPE = "fabric"


def _vrfs() -> tuple[GraphBuilder, VrfDomains]:
    b = GraphBuilder()
    policy = DomainPolicy(scope=SCOPE)
    return b, VrfDomains(b, DEV, policy, lambda name: uid.vrf(DEV, name))


def test_add_without_route_target_args_mints_no_route_targets():
    """No rd/rt_import/rt_export/is_global: no RouteTarget nodes or IMPORTS/EXPORTS
    edges appear, and MEMBER_OF points at exactly the RoutingDomain uid
    resolve() gives for a bare Vrf(device, name)."""
    b, vrfs = _vrfs()
    vu = vrfs.add("RED")
    batch = b.batch("test", "test:scope")

    vrf_node = next(n for n in batch.nodes if n.uid == vu)
    assert vrf_node.props == {"name": "RED", "table_id": "RED"}
    assert not any(n.label == "RouteTarget" for n in batch.nodes)
    assert not any(r.rel_type in ("IMPORTS", "EXPORTS") for r in batch.rels)

    expected_domain = resolve(Vrf(device=DEV, name="RED"), DomainPolicy(scope=SCOPE))
    assert vrfs.domains["RED"] == expected_domain
    du = uid.routing_domain(expected_domain)
    assert any(n.uid == du and n.label == "RoutingDomain" for n in batch.nodes)
    assert not any(n.label == "L3Domain" for n in batch.nodes)
    member_of = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "MEMBER_OF"}
    assert (vu, du) in member_of
    assert not any(r.rel_type == "REALIZES" for r in batch.rels)


def test_member_of_carries_basis_declared():
    """The RoutingDomain grouping is provenance-tagged: `VrfDomains.add` knows only
    the declared (DomainPolicy-ladder) basis; rt-component/adjacency basis
    is reasoner territory."""
    b, vrfs = _vrfs()
    vu = vrfs.add("RED")
    batch = b.batch("test", "test:scope")
    du = uid.routing_domain(vrfs.domains["RED"])
    rel = next(r for r in batch.rels if r.rel_type == "MEMBER_OF" and r.start_uid == vu and r.end_uid == du)
    assert rel.props["basis"] == "declared"


def test_add_with_rd_and_route_targets_emits_rt_nodes_and_directional_rels():
    b, vrfs = _vrfs()
    vu = vrfs.add(
        "CORP",
        rd="65000:1",
        rt_import=("65000:200", "65000:100"),
        rt_export=("65000:100",),
    )
    batch = b.batch("test", "test:scope")

    vrf_node = next(n for n in batch.nodes if n.uid == vu)
    assert vrf_node.props["rd"] == "65000:1"
    assert vrf_node.props["table_id"] == "CORP"

    rt100, rt200 = uid.route_target("65000:100"), uid.route_target("65000:200")
    rt_nodes = [n for n in batch.nodes if n.label == "RouteTarget"]
    assert {n.uid for n in rt_nodes} == {rt100, rt200}
    assert next(n for n in rt_nodes if n.uid == rt100).props == {"value": "65000:100"}

    imports = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IMPORTS"}
    exports = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "EXPORTS"}
    assert imports == {(vu, rt100), (vu, rt200)}
    assert exports == {(vu, rt100)}
    # 65000:100 is in both lists: one RouteTarget node, two distinct edges
    assert sum(1 for n in batch.nodes if n.uid == rt100) == 1


def test_add_drops_empty_and_duplicate_route_targets():
    b, vrfs = _vrfs()
    vu = vrfs.add("CORP", rt_import=("65000:1", "65000:1", "", "65000:2"))
    batch = b.batch("test", "test:scope")
    imports = {r.end_uid for r in batch.rels if r.rel_type == "IMPORTS" and r.start_uid == vu}
    assert imports == {uid.route_target("65000:1"), uid.route_target("65000:2")}


def test_add_is_global_prop_present_only_when_given():
    b, vrfs = _vrfs()
    global_vu = vrfs.add("default", is_global=True)
    named_vu = vrfs.add("CORP")
    batch = b.batch("test", "test:scope")
    global_node = next(n for n in batch.nodes if n.uid == global_vu)
    named_node = next(n for n in batch.nodes if n.uid == named_vu)
    assert global_node.props["is_global"] is True
    assert "is_global" not in named_node.props


def test_add_table_id_defaults_to_name_but_can_be_overridden():
    b, vrfs = _vrfs()
    vu = vrfs.add("CORP", table_id="native-corp-table")
    batch = b.batch("test", "test:scope")
    assert next(n for n in batch.nodes if n.uid == vu).props["table_id"] == "native-corp-table"


def test_add_memoizes_first_call_wins_by_name():
    b, vrfs = _vrfs()
    first = vrfs.add("CORP", rd="65000:1")
    second = vrfs.add("CORP", rd="65000:2")  # ignored: "CORP" is already memoized
    assert first == second
    batch = b.batch("test", "test:scope")
    assert next(n for n in batch.nodes if n.uid == first).props["rd"] == "65000:1"
