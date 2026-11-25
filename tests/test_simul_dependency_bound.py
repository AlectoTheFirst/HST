"""The calculation of a context reads only the contexts upstream of it.

`app/simul_read.read_rib_input` bounds its read by this property:
for any set of contexts, the calculation over their upstream closure under
`certainty.dependencies` gives the same rows, validation and gaps for them as
the calculation over the whole input, before and after a change. The
estates are random and seeded, so a failure names a reproducible case.
"""

import ipaddress
import random
from collections import defaultdict
from typing import Any

import pytest

from hst.simul import certainty, rib
from hst.simul.propagate import SimulationInput

AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id, not a bind address
PERMIT_ALL = {
    "name": "RM_ALL",
    "kind": "route-map",
    "entries": [{"seq": 10, "kind": "clause", "action": "permit"}],
}


def _ctx(i: int) -> str:
    return f"vrf:{i}"


def _lsa(adv_router: str, links: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "process": "1",
        "area": AREA_0,
        "lsa_type": "router",
        "lsid": adv_router,
        "adv_router": adv_router,
        "seq": 0x80000001,
        "age": 100,
        "metric": None,
        "links": links,
        "attached_routers": None,
        "mask": None,
        "forwarding_address": None,
        "metric_type": None,
    }


def _link(link_type: str, link_id: str, link_data: str, metric: int) -> dict[str, Any]:
    return {"link_type": link_type, "link_id": link_id, "link_data": link_data, "metric": metric}


def _estate(seed: int) -> rib.RibInput:
    """BGP peerings with and without captured paths, route-target leaks,
    statics resolving in another context, two OSPF domains with
    redistributing routers, observed rib rows and a policy that writes a
    next hop."""
    rng = random.Random(seed)
    n = rng.randint(6, 10)
    contexts = [
        {"uid": _ctx(i), "device_uid": f"dev:{i}", "name": f"t{i}", "platform": "nxos"} for i in range(n)
    ]
    connected: list[dict[str, Any]] = []
    for i in range(n):
        connected.append({"context_uid": _ctx(i), "prefix": f"10.{i}.0.0/24", "interface": "e0"})
        connected.append({"context_uid": _ctx(i), "prefix": f"10.255.0.{i}/32", "interface": "lo0"})
    bgp_contexts = [i for i in range(n) if rng.random() < 0.8]
    processes = [
        {
            "uid": f"bgp:{i}",
            "context_uid": _ctx(i),
            "proto": "bgp",
            "asn": 65000 + i,
            "router_id": f"10.255.0.{i}",
            "platform": "nxos",
        }
        for i in bgp_contexts
    ]
    sessions: list[dict[str, Any]] = []
    observed_paths: list[dict[str, Any]] = []
    direction_status: dict[tuple[str, str], str] = {}
    link = 0
    for a in bgp_contexts:
        for b in bgp_contexts:
            if a >= b or rng.random() > 0.35:
                continue
            link += 1
            near, far = f"172.16.{link}.1", f"172.16.{link}.2"
            connected.append(
                {"context_uid": _ctx(a), "prefix": f"172.16.{link}.0/30", "interface": f"p{link}"}
            )
            connected.append(
                {"context_uid": _ctx(b), "prefix": f"172.16.{link}.0/30", "interface": f"p{link}"}
            )
            for here, there, local, peer in ((a, b, near, far), (b, a, far, near)):
                uid = f"s:{here}:{there}"
                session = {
                    "uid": uid,
                    "process_uid": f"bgp:{here}",
                    "local_asn": 65000 + here,
                    "peer_asn": 65000 + there,
                    "local_ip": local,
                    "peer_ip": peer,
                }
                if rng.random() < 0.2:
                    session["import_policy_name"] = "RM_NH"
                    session["import_policy_kind"] = "route-map"
                sessions.append(session)
                if rng.random() < 0.4:
                    direction_status[(uid, "received")] = "complete"
                    observed_paths.append(
                        {
                            "device_uid": f"dev:{here}",
                            "context_uid": _ctx(here),
                            "session_uid": uid,
                            "peer_ip": peer,
                            "af": 4,
                            "safi": "unicast",
                            "direction": "received",
                            "rib_type": "adj-rib-in",
                            "policy_stage": "pre-import",
                            "path_id": None,
                            "prefix": f"10.{there}.0.0/24",
                            "prefixlen": 24,
                            "next_hop": peer,
                            "next_hop_context_uid": None,
                            "as_path": str(65000 + there),
                            "local_pref": 100,
                            "med": None,
                            "origin": "igp",
                            "communities": None,
                            "best": None,
                        }
                    )
    local_routes = [
        {"process_uid": f"bgp:{i}", "prefix": f"10.{i}.0.0/24", "origin_mechanism": "network", "intent": True}
        for i in bgp_contexts
        if rng.random() < 0.7
    ]
    rt_pairs = [
        {"importer": _ctx(b), "exporter": _ctx(a), "via_rt": [f"65000:{a}"]}
        for a in bgp_contexts
        for b in range(n)
        if a != b and rng.random() < 0.12
    ]
    static: list[dict[str, Any]] = []
    for a in range(n):
        if rng.random() < 0.3:
            b = rng.randrange(n)
            if b != a:
                static.append(
                    {
                        "context_uid": _ctx(a),
                        "prefix": f"192.168.{a}.0/24",
                        "next_hop": f"10.{b}.0.1",
                        "interface": None,
                        "next_hop_context_uid": _ctx(b),
                        "discard": None,
                    }
                )
    ospf_entries: list[dict[str, Any]] = []
    domains: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        if rng.random() < 0.5:
            domains[rng.randrange(2)].append(i)
    for members in domains.values():
        rows = []
        for position, i in enumerate(members):
            links = [_link("stub", f"10.255.0.{i}", "255.255.255.255", 1)]
            for j in (members[position - 1], members[(position + 1) % len(members)]):
                if j != i:
                    links.append(_link("point-to-point", f"10.255.0.{j}", f"10.{i}.0.1", 10))
            rows.append(_lsa(f"10.255.0.{i}", links))
        for i in members:
            entry: dict[str, Any] = {
                "uid": f"ospf:{i}",
                "context_uid": _ctx(i),
                "router_id": f"10.255.0.{i}",
                "process": "1",
                "rows": rows,
                "area_types": {},
                "coverage": "complete",
            }
            if rng.random() < 0.4:
                entry["redist_static_route_map"] = "RM_ALL"
            ospf_entries.append(entry)
    observed_rib: dict[str, list[dict[str, Any]]] = {}
    for i in range(n):
        if rng.random() < 0.5:
            rows = [
                {
                    "prefix": f"10.{i}.0.0/24",
                    "next_hop": None,
                    "next_hop_context_uid": None,
                    "interface": "e0",
                    "protocol": "direct",
                    "discard": None,
                    "metric": 0,
                    "prefixlen": 24,
                    "af": 4,
                }
            ]
            if rng.random() < 0.5:
                j = rng.randrange(n)
                rows.append(
                    {
                        "prefix": f"198.51.{i}.0/24",
                        "next_hop": f"10.{j}.0.9",
                        "next_hop_context_uid": _ctx(j) if j != i else None,
                        "interface": None,
                        "protocol": "static",
                        "discard": None,
                        "metric": 0,
                        "prefixlen": 24,
                        "af": 4,
                    }
                )
            observed_rib[_ctx(i)] = rows
    next_hop_policy = {
        "name": "RM_NH",
        "kind": "route-map",
        "entries": [
            {"seq": 10, "kind": "clause", "action": "permit", "set_next_hop": f"10.{rng.randrange(n)}.0.7"}
        ],
    }
    return rib.RibInput(
        contexts=contexts,
        connected=connected,
        static=static,
        ospf=ospf_entries,
        bgp=SimulationInput(
            processes=processes,
            sessions=sessions,
            policies=[PERMIT_ALL, next_hop_policy],
            local_routes=local_routes,
        )
        if processes
        else None,
        observed_paths=observed_paths,
        direction_status=direction_status,
        rt_pairs=rt_pairs,
        observed_rib=observed_rib,
        rib_coverage=dict.fromkeys(observed_rib, "complete"),
        platform="nxos",
    )


def _upstream(inp: rib.RibInput, contexts: set[str]) -> set[str]:
    producers: dict[str, set[str]] = defaultdict(set)
    for source, targets in certainty.dependencies(inp).items():
        for target in targets:
            producers[target].add(source)
    found = set(contexts)
    todo = list(found)
    while todo:
        for producer in producers.get(todo.pop(), ()):
            if producer not in found:
                found.add(producer)
                todo.append(producer)
    return found


def _view(result: rib.RibResult, contexts: set[str]) -> dict[str, list[str]]:
    def keep(items: list[dict[str, Any]]) -> list[str]:
        return sorted(
            repr(sorted(item.items())) for item in items if str(item.get("context_uid")) in contexts
        )

    return {"rib": keep(result.rib), "validation": keep(result.validation), "gaps": keep(result.gaps)}


def _settled(result: rib.RibResult) -> bool:
    return result.convergence.get("status") == "settled"


SEEDS = range(40)


@pytest.mark.parametrize("seed", SEEDS)
def test_a_contexts_results_depend_only_on_its_upstream_closure(seed):
    inp = _estate(seed)
    full = rib.compute(inp)
    if not _settled(full):
        pytest.skip("the random estate does not settle")
    rng = random.Random(seed * 7 + 1)
    uids = [str(c["uid"]) for c in inp.contexts]
    for _ in range(3):
        asked = set(rng.sample(uids, rng.randint(1, 2)))
        scope = _upstream(inp, asked)
        bounded = rib.compute(rib._component_input(inp, scope))
        assert _view(bounded, asked) == _view(full, asked), (seed, sorted(asked), sorted(scope))


@pytest.mark.parametrize("seed", SEEDS)
def test_a_changes_results_depend_only_on_its_downstream_closure_and_what_that_reads(seed):
    inp = _estate(seed)
    rng = random.Random(seed * 11 + 3)
    intents: list[dict[str, Any]] = []
    if inp.bgp is not None and inp.bgp.sessions:
        session = rng.choice(list(inp.bgp.sessions))
        intents.append({"kind": "bgp_session.shut", "params": {"session": session["uid"]}})
    if inp.ospf:
        entry = rng.choice(list(inp.ospf))
        router = str(entry["router_id"])
        intents.append(
            {
                "kind": "ospf.interface_cost",
                "params": {"router_id": router, "address": f"10.{router.rsplit('.', 1)[1]}.0.1", "cost": 50},
            }
        )
    if not intents:
        pytest.skip("the random estate has nothing to change")
    changed = rib.apply_intents(inp, intents)
    full_after = rib.compute(changed)
    if not _settled(full_after):
        pytest.skip("the random estate does not settle after the change")
    # the engine's own account of what the change can alter
    affected = set(changed.superseded_contexts)
    asked = affected | {rng.choice([str(c["uid"]) for c in inp.contexts])}
    scope = _upstream(inp, asked)
    bounded_input = rib._component_input(inp, scope)
    bounded_after = rib.compute(rib.apply_intents(bounded_input, intents))
    assert _view(bounded_after, asked) == _view(full_after, asked), (seed, sorted(asked), sorted(scope))
    # nothing outside the change's closure differs before and after
    full_before = rib.compute(inp)
    outside = {str(c["uid"]) for c in inp.contexts} - affected
    assert _view(full_before, outside)["rib"] == _view(full_after, outside)["rib"]


def test_the_estates_exercise_every_cross_context_dependency():
    kinds: set[str] = set()
    bounded = 0
    for seed in SEEDS:
        inp = _estate(seed)
        uids = {str(c["uid"]) for c in inp.contexts}
        bounded += sum(len(_upstream(inp, {uid})) < len(uids) for uid in uids)
        if certainty.paired_sessions(inp):
            kinds.add("bgp")
        if inp.rt_pairs:
            kinds.add("leak")
        if inp.static:
            kinds.add("static")
        if any(rib._redistribute_statements(e) for e in inp.ospf):
            kinds.add("ospf-redistribution")
        if any(r.get("next_hop_context_uid") for rows in inp.observed_rib.values() for r in rows):
            kinds.add("observed-next-hop")
        if inp.bgp and any(s.get("import_policy_name") for s in inp.bgp.sessions):
            kinds.add("policy-next-hop")
    assert kinds == {"bgp", "leak", "static", "ospf-redistribution", "observed-next-hop", "policy-next-hop"}
    assert bounded > sum(len(_estate(seed).contexts) for seed in SEEDS) // 2


def test_ospf_routes_never_depend_on_a_database_that_does_not_hold_the_router():
    """Two OSPF contexts in separate databases: neither feeds the other."""
    rows_a = [_lsa("10.255.0.1", [_link("stub", "10.255.0.1", "255.255.255.255", 1)])]
    rows_b = [_lsa("10.255.0.2", [_link("stub", "10.255.0.2", "255.255.255.255", 1)])]
    inp = rib.RibInput(
        contexts=[{"uid": _ctx(1), "device_uid": "dev:1"}, {"uid": _ctx(2), "device_uid": "dev:2"}],
        ospf=[
            {"uid": "ospf:1", "context_uid": _ctx(1), "router_id": "10.255.0.1", "rows": rows_a},
            {
                "uid": "ospf:2",
                "context_uid": _ctx(2),
                "router_id": "10.255.0.2",
                "rows": rows_b,
                "redist_static_route_map": "RM_ALL",
                "coverage": "partial",
            },
        ],
    )
    assert certainty.dependencies(inp) == {_ctx(2): {_ctx(2)}}
    gaps = rib.compute(inp).gaps
    assert {g["context_uid"] for g in gaps if g["kind"] == rib.NOT_OBSERVED} == {_ctx(2)}


def test_a_redistributing_router_feeds_every_database_that_holds_its_lsas():
    shared = [
        _lsa("10.255.0.1", [_link("stub", "10.255.0.1", "255.255.255.255", 1)]),
        _lsa("10.255.0.2", [_link("stub", "10.255.0.2", "255.255.255.255", 1)]),
    ]
    inp = rib.RibInput(
        contexts=[{"uid": _ctx(i), "device_uid": f"dev:{i}"} for i in (1, 2, 3)],
        ospf=[
            {"uid": "ospf:1", "context_uid": _ctx(1), "router_id": "10.255.0.1", "rows": shared},
            {
                "uid": "ospf:2",
                "context_uid": _ctx(2),
                "router_id": "10.255.0.2",
                "rows": shared,
                "redist_static_route_map": "RM_ALL",
            },
            {
                "uid": "ospf:3",
                "context_uid": _ctx(3),
                "router_id": "10.255.0.3",
                "rows": [_lsa("10.255.0.3", [])],
            },
        ],
    )
    assert certainty.dependencies(inp) == {_ctx(2): {_ctx(1), _ctx(2)}}


def test_an_ospf_change_supersedes_only_the_databases_it_alters_and_their_consumers():
    shared = [
        _lsa(
            "10.255.0.1",
            [
                _link("point-to-point", "10.255.0.2", "10.1.0.1", 10),
                _link("stub", "10.255.0.1", "255.255.255.255", 1),
            ],
        ),
        _lsa(
            "10.255.0.2",
            [
                _link("point-to-point", "10.255.0.1", "10.2.0.1", 10),
                _link("stub", "10.255.0.2", "255.255.255.255", 1),
            ],
        ),
    ]
    inp = rib.RibInput(
        contexts=[{"uid": _ctx(i), "device_uid": f"dev:{i}"} for i in (1, 2, 3)],
        ospf=[
            {"uid": "ospf:1", "context_uid": _ctx(1), "router_id": "10.255.0.1", "rows": shared},
            {"uid": "ospf:2", "context_uid": _ctx(2), "router_id": "10.255.0.2", "rows": shared},
            {
                "uid": "ospf:3",
                "context_uid": _ctx(3),
                "router_id": "10.255.0.3",
                "rows": [_lsa("10.255.0.3", [_link("stub", "10.255.0.3", "255.255.255.255", 1)])],
            },
        ],
    )
    changed = rib.with_ospf_interface_cost(inp, "10.255.0.1", "10.1.0.1", 50)
    assert changed.superseded_contexts == {_ctx(1), _ctx(2)}


def test_a_bgp_covered_next_hop_roots_its_own_context_not_an_unrelated_one():
    """Two BGP islands. In the first a static next hop falls inside a prefix BGP carries."""

    def island(a: int, b: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        processes = [
            {"uid": f"bgp:{i}", "context_uid": _ctx(i), "asn": 65000 + i, "router_id": f"10.255.0.{i}"}
            for i in (a, b)
        ]
        sessions = [
            {
                "uid": f"s:{x}:{y}",
                "process_uid": f"bgp:{x}",
                "local_ip": f"172.16.{a}.{x}",
                "peer_ip": f"172.16.{a}.{y}",
                "local_asn": 65000 + x,
                "peer_asn": 65000 + y,
                "state": "shutdown",
            }
            for x, y in ((a, b), (b, a))
        ]
        return processes, sessions

    p1, s1 = island(1, 2)
    p2, s2 = island(3, 4)
    inp = rib.RibInput(
        contexts=[{"uid": _ctx(i), "device_uid": f"dev:{i}"} for i in (1, 2, 3, 4)],
        static=[
            {"context_uid": _ctx(1), "prefix": "192.0.2.0/24", "next_hop": "203.0.113.9", "interface": None}
        ],
        bgp=SimulationInput(
            processes=[*p1, *p2],
            sessions=[*s1, *s2],
            local_routes=[
                {"process_uid": "bgp:2", "prefix": "203.0.113.0/24", "origin_mechanism": "network"}
            ],
        ),
    )
    # vrf:1's next hop resolves through a prefix vrf:2 sends it; vrf:2
    # consumes vrf:1 in turn. The second island holds neither.
    assert {g["context_uid"] for g in certainty.proof_gaps(inp)} == {_ctx(1), _ctx(2)}


def test_a_leak_roots_the_importer_and_not_the_exporter():
    inp = rib.RibInput(
        contexts=[{"uid": _ctx(i), "device_uid": f"dev:{i}"} for i in (1, 2)],
        bgp=SimulationInput(
            processes=[{"uid": "bgp:1", "context_uid": _ctx(1), "asn": 65001, "router_id": "10.255.0.1"}]
        ),
        rt_pairs=[{"importer": _ctx(2), "exporter": _ctx(1), "via_rt": ["65000:1"]}],
    )
    assert {g["context_uid"] for g in certainty.proof_gaps(inp)} == {_ctx(2)}


def test_two_processes_in_one_context_root_that_context_alone():
    inp = rib.RibInput(
        contexts=[{"uid": _ctx(i), "device_uid": f"dev:{i}"} for i in (1, 2)],
        bgp=SimulationInput(
            processes=[
                {"uid": "bgp:1a", "context_uid": _ctx(1), "asn": 65001, "router_id": "10.255.0.1"},
                {"uid": "bgp:1b", "context_uid": _ctx(1), "asn": 65011, "router_id": "10.255.0.11"},
                {"uid": "bgp:2", "context_uid": _ctx(2), "asn": 65002, "router_id": "10.255.0.2"},
            ]
        ),
    )
    assert {g["context_uid"] for g in certainty.proof_gaps(inp)} == {_ctx(1)}


def test_the_upstream_cover_follows_producers_not_consumers():
    edges = {"a": {"b"}, "b": {"c"}, "x": {"c"}}
    cover = certainty._UpstreamCover(
        edges, {"a": [(4, int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("10.0.0.255")))]}
    )
    hop = ipaddress.ip_address("10.0.0.9")
    assert [context for context in ("a", "b", "c", "x") if cover.covers(context, hop)] == ["a", "b", "c"]
