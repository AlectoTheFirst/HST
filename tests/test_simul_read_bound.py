"""The integrated RIB read covers what the calculation needs, and no more."""

from typing import Any

import pytest

from hst import path as pathmod
from hst.app import simul_read
from hst.simul import certainty, rib
from hst.simul.errors import ErrorSink

AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id, not a bind address
E, P, Q, I1, I2, X, Y, ASBR, U, V = (f"vrf:{i}" for i in (1, 2, 3, 4, 5, 6, 7, 9, 10, 11))
ALL = [E, P, Q, I1, I2, X, Y, ASBR, U, V]


def _n(uid: str) -> int:
    return int(uid.split(":")[1])


def _lsa(router: str, neighbour: str, link_data: str) -> dict[str, Any]:
    return {
        "process": "1",
        "area": AREA_0,
        "lsa_type": "router",
        "lsid": router,
        "adv_router": router,
        "seq": 0x80000001,
        "age": 100,
        "metric": None,
        "links": [
            {"link_type": "point-to-point", "link_id": neighbour, "link_data": link_data, "metric": 10},
            {"link_type": "stub", "link_id": router, "link_data": "255.255.255.255", "metric": 1},
        ],
        "attached_routers": None,
        "mask": None,
        "forwarding_address": None,
        "metric_type": None,
    }


def _rib_row(prefix: str, protocol: str, next_hop=None, interface=None, next_hop_context_uid=None):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "next_hop_context_uid": next_hop_context_uid,
        "interface": interface,
        "protocol": protocol,
        "discard": None,
        "metric": 0,
        "prefixlen": int(prefix.rsplit("/", 1)[1]),
        "af": 4,
    }


class _Graph:
    """The estate as the read's queries see it."""

    def __init__(
        self,
        *,
        missing_next_hop_context: bool = False,
        links: dict[tuple[str, str], int] | None = None,
        asn: int | None = None,
    ) -> None:
        links = dict(links or {(E, P): 1, (P, Q): 2, (U, V): 3})
        peers = {uid for pair in links for uid in pair}
        self.contexts = set(ALL) | peers
        self.routes: list[dict[str, Any]] = []
        for uid in sorted(self.contexts):
            self.routes.append(self._connected(uid, f"10.{_n(uid)}.0.0/24", "e0"))
        asn_of = {uid: asn or 65000 + _n(uid) for uid in peers}
        self.bgp = {
            uid: {
                "proto": "bgp",
                "asn": asn_of[uid],
                "router_id": f"10.255.0.{_n(uid)}",
                "origin_config_recorded": True,
            }
            for uid in sorted(peers)
        }
        self.sessions: list[dict[str, Any]] = []
        self.addresses: dict[str, set[str]] = {f"bgp:{uid}": set() for uid in self.bgp}
        for (a, b), link in links.items():
            for here, there, local, peer in ((a, b, 1, 2), (b, a, 2, 1)):
                self.routes.append(self._connected(here, f"172.16.{link}.0/30", f"p{link}"))
                self.addresses[f"bgp:{here}"].add(f"172.16.{link}.{local}")
                self.sessions.append(
                    {
                        "uid": f"s:{_n(here)}:{_n(there)}",
                        "process_uid": f"bgp:{here}",
                        "props": {
                            "local_asn": asn_of[here],
                            "peer_asn": asn_of[there],
                            "peer_ip": f"172.16.{link}.{peer}",
                        },
                    }
                )
        self.routes.append(
            {
                "context_uid": I1,
                "prefix": "192.168.4.0/24",
                "kind": "STATIC_ROUTE",
                "proto": None,
                "next_hop": "10.6.0.1",
                "interface": None,
                "next_hop_context_uid": "vrf:gone" if missing_next_hop_context else X,
                "discard": None,
                "gateways": [],
            }
        )
        self.rt = [
            {"vrf_uid": E, "kind": "EXPORTS", "rt": "65000:1"},
            {"vrf_uid": I1, "kind": "IMPORTS", "rt": "65000:1"},
            {"vrf_uid": I2, "kind": "IMPORTS", "rt": "65000:1"},
        ]
        self.ospf = {
            f"ospf:{E}": {
                "context": E,
                "props": {"proto": "ospf", "router_id": "10.255.0.1", "process_id": "1"},
            },
            f"ospf:{ASBR}": {
                "context": ASBR,
                "props": {
                    "proto": "ospf",
                    "router_id": "10.255.0.9",
                    "process_id": "1",
                    "redist_connected_route_map": "RM_ALL",
                },
            },
        }
        self.adjacent = {f"ospf:{E}": ["10.255.0.9"], f"ospf:{ASBR}": ["10.255.0.1"]}
        self.queries: list[str] = []

    @staticmethod
    def _connected(uid: str, prefix: str, interface: str) -> dict[str, Any]:
        return {
            "context_uid": uid,
            "prefix": prefix,
            "kind": "ORIGINATES",
            "proto": "connected",
            "next_hop": None,
            "interface": interface,
            "next_hop_context_uid": None,
            "discard": None,
            "gateways": [interface],
        }

    def _context_of(self, process_uid: str) -> str:
        return process_uid.split(":", 1)[1]

    def read(self, _session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
        q = simul_read
        vrfs = set(params.get("vrfs") or ())
        procs = set(params.get("procs") or ())
        name = next((key for key, value in vars(q).items() if value is query and key.startswith("_")), "?")
        self.queries.append(name)
        if name == "_RT_EDGES":
            return list(self.rt)
        if name == "_SEED_BY_VRFS":
            return [{"uid": f"bgp:{uid}"} for uid in sorted(vrfs & set(self.bgp))]
        if name == "_PEER_PROCESSES":
            owners = {ip: process for process, held in self.addresses.items() for ip in held}
            far = {
                owners[s["props"]["peer_ip"]]
                for s in self.sessions
                if s["process_uid"] in procs and s["props"]["peer_ip"] in owners
            }
            return [{"uid": uid} for uid in sorted(far)]
        if name == "_PROCESS_CONTEXTS":
            return [{"process_context_uid": self._context_of(p)} for p in sorted(procs)]
        if name == "_PROCESSES":
            return [
                {
                    "uid": p,
                    "props": dict(self.bgp[self._context_of(p)]),
                    "context_uid": self._context_of(p),
                    "platforms": ["nxos"],
                    "vendors": [],
                }
                for p in sorted(procs)
                if self._context_of(p) in self.bgp
            ]
        if name == "_SESSIONS":
            return [dict(s) for s in self.sessions if s["process_uid"] in procs]
        if name == "_PROCESS_ADDRESSES":
            return [
                {"process_uid": p, "ip": ip}
                for p in sorted(procs)
                for ip in sorted(self.addresses.get(p, ()))
            ]
        if name == "_ORIGINATED":
            return [
                {
                    "process_uid": p,
                    "prefix": f"10.{_n(self._context_of(p))}.0.0/24",
                    "proto": "network",
                    "origin_props": {},
                    "origin_policy_name": None,
                }
                for p in sorted(procs)
            ]
        if name == "_CONTEXT_ROUTES":
            return [row for row in self.routes if row["context_uid"] in vrfs]
        if name == "_NEXT_HOP_CONSUMERS":
            return [
                {"consumer_uid": row["context_uid"]}
                for row in self.routes
                if row["kind"] == "STATIC_ROUTE" and row["next_hop_context_uid"] in vrfs
            ]
        if name == "_CONTEXTS_OF_DEVICE":
            return [{"uid": uid} for uid in sorted(self.contexts) if f"dev:{uid}" == params["dev"]]
        if name == "_CONTEXTS":
            return [
                {"uid": uid, "name": uid, "device_uids": [f"dev:{uid}"], "platforms": ["nxos"], "vendors": []}
                for uid in sorted(vrfs & self.contexts)
            ]
        if name == "_OSPF_PROCESSES":
            return [
                {"uid": uid, "context_uid": entry["context"], "props": dict(entry["props"]), "areas": []}
                for uid, entry in sorted(self.ospf.items())
                if entry["context"] in vrfs
            ]
        if name == "_OSPF_ROUTERS":
            routers = set(params["router_ids"])
            return [
                {"uid": uid, "context_uid": entry["context"], "props": dict(entry["props"])}
                for uid, entry in sorted(self.ospf.items())
                if entry["props"]["router_id"] in routers
            ]
        if name == "_OSPF_NEIGHBOURS":
            by_router = {entry["props"]["router_id"]: uid for uid, entry in self.ospf.items()}
            return [
                {"neighbour_uid": by_router[r], "context_uid": self.ospf[by_router[r]]["context"]}
                for p in sorted(procs)
                for r in self.adjacent.get(p, ())
            ]
        if name in (
            "_POLICIES",
            "_ORIGIN_POLICIES",
            "_ROUTE_NEXT_HOP_CONTEXTS",
            "_PBR_DEPENDENCIES",
            "_PBR_BINDINGS",
            "_ACCESS_DEFAULTS",
        ):
            return []
        raise AssertionError(f"unexpected query {name}")


class _RibSource:
    def __init__(self, legacy: frozenset[str] = frozenset()) -> None:
        self.asked: list[str] = []
        # contexts whose rows carry only the legacy vrf name
        self.legacy = legacy
        self.rows = {
            E: [
                _rib_row("10.1.0.0/24", "direct", interface="e0"),
                _rib_row("198.51.100.0/24", "static", next_hop="10.7.0.1", next_hop_context_uid=Y),
            ],
            I1: [_rib_row("10.4.0.0/24", "direct", interface="e0")],
        }

    def overlapping(self, device_uid, context_uid, lo, hi, minlen, af, legacy_vrf=None):
        if af == 4:
            self.asked.append(context_uid)
            return [dict(row) for row in self.rows.get(context_uid, ())]
        return []

    def coverage(self, device_uid):
        return "complete"

    def next_hop_context_consumers(self, context_uids):
        wanted = set(context_uids)
        return sorted(
            (f"dev:{uid}", None, uid) if uid in self.legacy else (f"dev:{uid}", uid, None)
            for uid, rows in self.rows.items()
            if any(row.get("next_hop_context_uid") in wanted for row in rows)
        )


class _BgpSource:
    def __init__(self, captured: frozenset[tuple[str, str]] = frozenset({("s:2:3", "received")})) -> None:
        self.asked: list[str] = []
        self.closed = 0
        self.captured = captured
        # context to the next-hop contexts its observed paths name
        self.next_hops: dict[str, set[str]] = {}

    def direction_status(self, session_uid, direction):
        return "complete" if (session_uid, direction) in self.captured else "not-captured"

    def next_hop_context_consumers(self, context_uids):
        wanted = set(context_uids)
        return sorted((f"dev:{uid}", uid) for uid, hops in self.next_hops.items() if hops & wanted)

    def session_state(self, session_uid):
        return None

    def paths(self, device_uid, context_uid, prefix=None, *, direction=None, session_uid=None):
        self.asked.append(session_uid)
        if session_uid != "s:2:3":
            return []
        return [
            {
                "device_uid": device_uid,
                "context_uid": context_uid,
                "session_uid": session_uid,
                "peer_ip": "172.16.2.2",
                "af": 4,
                "safi": "unicast",
                "direction": "received",
                "rib_type": "adj-rib-in",
                "policy_stage": "pre-import",
                "path_id": None,
                "prefix": "10.3.0.0/24",
                "prefixlen": 24,
                "next_hop": "172.16.2.2",
                "next_hop_context_uid": None,
                "as_path": "65003",
                "local_pref": 100,
                "med": None,
                "origin": "igp",
                "communities": None,
                "best": None,
            }
        ]

    def close(self):
        self.closed += 1


class _OspfSource:
    def __init__(self) -> None:
        self.asked: list[str] = []
        self.rows = [
            _lsa("10.255.0.1", "10.255.0.9", "10.1.0.1"),
            _lsa("10.255.0.9", "10.255.0.1", "10.9.0.1"),
        ]

    def lsdb(self, device_uid, context_uid=None, process=None, area=None):
        self.asked.append(context_uid)
        return [dict(row) for row in self.rows]

    def coverage(self, device_uid):
        return "complete"

    def context_coverage(self, context_uid):
        return None

    def contexts_with_rows(self, device_uid):
        return set()

    def close(self):
        pass


def _read(
    monkeypatch, graph: _Graph, *, sources: dict[str, Any] | None = None, **kwargs: Any
) -> tuple[simul_read.RibGraphInput, dict[str, Any]]:
    monkeypatch.setattr(pathmod, "_read", graph.read)
    sources = {
        "rib_source": _RibSource(),
        "bgp_source": _BgpSource(),
        "ospf_source": _OspfSource(),
        **(sources or {}),
    }
    return simul_read.read_rib_input(object(), **kwargs, **sources), sources


def _scope(result: simul_read.RibGraphInput) -> list[str]:
    return [str(c["uid"]) for c in result.input.contexts]


def _view(result: rib.RibResult, contexts: set[str]) -> dict[str, list[str]]:
    def keep(items: list[dict[str, Any]]) -> list[str]:
        return sorted(
            repr(sorted(item.items())) for item in items if str(item.get("context_uid")) in contexts
        )

    return {"rib": keep(result.rib), "validation": keep(result.validation), "gaps": keep(result.gaps)}


def test_a_read_covers_what_the_context_reads_and_not_what_consumes_it(monkeypatch):
    result, sources = _read(monkeypatch, _Graph(), contexts=[E])

    assert _scope(result) == sorted([E, P, Y, ASBR])
    assert sorted(set(sources["rib_source"].asked)) == sorted([E, P, Y, ASBR])
    assert sorted(set(sources["ospf_source"].asked)) == [E, ASBR]
    assert sorted(set(sources["bgp_source"].asked)) == ["s:1:2", "s:2:1", "s:2:3"]
    held = {s["uid"]: s for s in result.input.bgp.sessions}
    assert held["s:2:3"][certainty.OMITTED_FAR_END] == "s:3:2"
    assert result.input.rt_pairs == []
    assert result.scopes == [E]


def test_a_change_adds_every_context_it_can_alter_and_what_those_read(monkeypatch):
    result, _sources = _read(monkeypatch, _Graph(), contexts=[E], changed=[E])

    assert _scope(result) == sorted([E, P, Q, Y, ASBR, I1, I2, X])
    assert [(p["exporter"], p["importer"]) for p in result.input.rt_pairs] == [(E, I1), (E, I2)]


def test_an_ospf_router_change_adds_its_flooding_domain(monkeypatch):
    """ASBR's LSAs are held by E's database too, so the change alters E, and
    with it everything E feeds."""
    result, _sources = _read(monkeypatch, _Graph(), ospf_routers=["10.255.0.9"])

    assert _scope(result) == sorted([E, P, Q, Y, ASBR, I1, I2, X])
    assert result.scopes == []


def test_the_bounded_read_calculates_what_the_whole_estate_calculates(monkeypatch):
    whole, _ = _read(monkeypatch, _Graph(), contexts=ALL)
    expected = rib.compute(whole.input)
    for asked in ([E], [I1], [Q], [U]):
        bounded, _ = _read(monkeypatch, _Graph(), contexts=asked)
        held = set(_scope(bounded))
        assert held < set(ALL)
        assert _view(rib.compute(bounded.input), held) == _view(expected, held), asked


def test_the_bounded_read_predicts_the_change_the_whole_estate_predicts(monkeypatch):
    intents = [{"kind": "bgp_session.shut", "params": {"session": "s:1:2"}}]

    def delta(read: simul_read.RibGraphInput) -> tuple[list[str], list[str]]:
        before = rib.compute(read.input)
        after = rib.compute(rib.apply_intents(read.input, intents, ErrorSink()))
        old = {repr(sorted(r.items())) for r in before.rib}
        new = {repr(sorted(r.items())) for r in after.rib}
        return sorted(old - new), sorted(new - old)

    whole, _ = _read(monkeypatch, _Graph(), contexts=ALL, changed=[E])
    bounded, _ = _read(monkeypatch, _Graph(), contexts=[E], changed=[E])
    withdrawn, added = delta(bounded)

    assert set(_scope(bounded)) < set(ALL)
    assert (withdrawn, added) == delta(whole)
    assert withdrawn
    after_whole = rib.compute(rib.apply_intents(whole.input, intents, ErrorSink()))
    after_bounded = rib.compute(rib.apply_intents(bounded.input, intents, ErrorSink()))
    held = set(_scope(bounded))
    assert _view(after_bounded, held) == _view(after_whole, held)


def test_a_missing_context_is_reported_against_the_context_that_reads_it(monkeypatch):
    result, _ = _read(monkeypatch, _Graph(missing_next_hop_context=True), contexts=[I1])

    missing = [e for e in result.errors.as_dicts() if e["kind"] == "required-context-missing"]
    assert [(e["subject"], "vrf:gone" in e["detail"]) for e in missing] == [(I1, True)]
    compiler = [
        g for g in result.input.observation_gaps if g.get("model_error_kind") == "required-context-missing"
    ]
    assert {g["context_uid"] for g in compiler} == {I1}


@pytest.mark.parametrize("spokes", [50])
def test_a_hub_exporting_to_many_spokes_reads_none_of_them(monkeypatch, spokes):
    graph = _Graph()
    for i in range(spokes):
        graph.contexts.add(f"spoke:{i}")
        graph.rt.append({"vrf_uid": f"spoke:{i}", "kind": "IMPORTS", "rt": "65000:1"})
    result, sources = _read(monkeypatch, graph, contexts=[E])

    assert not any(uid.startswith("spoke:") for uid in _scope(result))
    assert not any(uid.startswith("spoke:") for uid in sources["rib_source"].asked)
    changed, _ = _read(monkeypatch, graph, contexts=[E], changed=[E])
    assert sum(uid.startswith("spoke:") for uid in _scope(changed)) == spokes


HUB = "vrf:99"
SHUT_E_P = [{"kind": "bgp_session.shut", "params": {"session": "s:1:2"}}]


def _reflector(clients: int) -> _Graph:
    """One route reflector peering with `clients` clients in one AS."""
    return _Graph(links={(HUB, f"vrf:{100 + i}"): 10 + i for i in range(clients)}, asn=65100)


def _captured(clients: int, *, client_side: bool) -> frozenset[tuple[str, str]]:
    """Every session's received direction captured on the reflector's side,
    and on the clients' side too when `client_side`."""
    held = {(f"s:{_n(HUB)}:{100 + i}", "received") for i in range(clients)}
    if client_side:
        held |= {(f"s:{100 + i}:{_n(HUB)}", "received") for i in range(clients)}
    return frozenset(held)


def _after(read: simul_read.RibGraphInput, intents: list[dict[str, Any]]) -> rib.RibResult:
    return rib.compute(rib.apply_intents(read.input, intents, ErrorSink()))


@pytest.mark.parametrize("clients", [5, 50])
@pytest.mark.parametrize("client_side", [True, False])
def test_reading_one_client_of_a_route_reflector_reads_no_other_client(monkeypatch, clients, client_side):
    """The reflector's received paths from every client are captured, so a
    read of one client reads at most the reflector."""
    client = "vrf:100"
    graph = _reflector(clients)
    captured = _captured(clients, client_side=client_side)
    bounded, sources = _read(
        monkeypatch, graph, contexts=[client], sources={"bgp_source": _BgpSource(captured)}
    )

    expected = [client] if client_side else [client, HUB]
    assert _scope(bounded) == sorted(expected)
    assert sorted(set(sources["rib_source"].asked)) == sorted(expected)
    assert len(set(sources["bgp_source"].asked)) == (1 if client_side else 1 + clients)
    whole, _ = _read(
        monkeypatch,
        _reflector(clients),
        contexts=sorted(graph.contexts),
        sources={"bgp_source": _BgpSource(captured)},
    )
    held = set(_scope(bounded))
    assert _view(rib.compute(bounded.input), held) == _view(rib.compute(whole.input), held)


def test_a_change_on_one_client_reads_the_clients_the_reflector_sends_it_to(monkeypatch):
    """What one client sends, the reflector can send to every other client,
    so the change can alter all of them: they are its downstream closure,
    the contexts the engine supersedes, and the bounded read predicts them as
    the whole estate does."""
    clients = 20
    client = "vrf:100"
    captured = _captured(clients, client_side=True)
    intents = [{"kind": "bgp_session.shut", "params": {"session": f"s:100:{_n(HUB)}"}}]
    graph = _reflector(clients)
    bounded, _ = _read(
        monkeypatch, graph, contexts=[client], changed=[client], sources={"bgp_source": _BgpSource(captured)}
    )
    whole, _ = _read(
        monkeypatch,
        _reflector(clients),
        contexts=sorted(graph.contexts),
        changed=[client],
        sources={"bgp_source": _BgpSource(captured)},
    )

    clients_held = {uid for uid in _scope(bounded) if _n(uid) >= 100}
    assert clients_held == {f"vrf:{100 + i}" for i in range(clients)}
    assert HUB in _scope(bounded)
    assert set(_scope(bounded)) < graph.contexts
    held = set(_scope(bounded))
    assert _view(_after(bounded, intents), held) == _view(_after(whole, intents), held)


@pytest.mark.parametrize("legacy", [False, True])
def test_a_context_resolving_observed_routes_in_a_changed_one_joins_the_change(monkeypatch, legacy):
    """vrf:12's observed rib row resolves its next hop in E. Shutting E's
    session can alter that resolution, so vrf:12 is in the closure of the
    change and the bounded read predicts it as the whole estate does, also
    when its rows carry only the legacy vrf name."""
    consumer = "vrf:12"

    def sources() -> dict[str, Any]:
        rib_source = _RibSource(legacy=frozenset({consumer}) if legacy else frozenset())
        rib_source.rows[consumer] = [
            _rib_row("10.12.0.0/24", "direct", interface="e0"),
            _rib_row("203.0.113.0/24", "static", next_hop="10.1.0.1", next_hop_context_uid=E),
        ]
        return {"rib_source": rib_source}

    graph = _Graph()
    graph.contexts.add(consumer)
    graph.routes.append(_Graph._connected(consumer, "10.12.0.0/24", "e0"))
    bounded, _ = _read(monkeypatch, graph, contexts=[E], changed=[E], sources=sources())
    whole, _ = _read(monkeypatch, graph, contexts=sorted(graph.contexts), changed=[E], sources=sources())

    assert consumer in _scope(bounded)
    held = set(_scope(bounded))
    assert held < graph.contexts
    after_whole = _after(whole, SHUT_E_P)
    assert consumer in rib.apply_intents(whole.input, SHUT_E_P, ErrorSink()).superseded_contexts
    assert _view(_after(bounded, SHUT_E_P), held) == _view(after_whole, held)


def test_a_context_resolving_observed_bgp_paths_in_a_changed_one_joins_the_change(monkeypatch):
    graph = _Graph()
    monkeypatch.setattr(pathmod, "_read", graph.read)
    bgp_source = _BgpSource()
    bgp_source.next_hops = {U: {E}}

    affected = simul_read._affected_contexts(object(), {E}, [], {}, _RibSource(), bgp_source)

    assert U in affected
    assert V in affected  # what U sends to its peer
    assert bgp_source.closed


def test_a_fault_of_an_omitted_far_end_is_no_gap_of_the_observed_side(monkeypatch):
    """Q records no origin configuration, a fault of Q's process. P takes
    what Q sends from the observation, so the fault is a gap of Q alone in
    the whole estate, and the read of E, which leaves Q out, gives E and P
    the same gaps."""

    def graph() -> _Graph:
        built = _Graph()
        built.bgp[Q]["origin_config_recorded"] = False
        return built

    whole, _ = _read(monkeypatch, graph(), contexts=ALL)
    bounded, _ = _read(monkeypatch, graph(), contexts=[E])

    assert Q not in _scope(bounded)
    assert not any(e["subject"] == f"bgp:{Q}" for e in bounded.errors.as_dicts())
    whole_gaps = {g["context_uid"] for g in whole.input.observation_gaps if g.get("subject") == f"bgp:{Q}"}
    assert whole_gaps == {Q}
    held = set(_scope(bounded))
    assert _view(rib.compute(bounded.input), held) == _view(rib.compute(whole.input), held)
