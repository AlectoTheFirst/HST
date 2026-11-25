"""The compiled FIB reads the same PBR rule rows the tracer's PBR stage reads."""

import inspect
import re
from dataclasses import replace
from typing import Any

from tests import test_impact_evaluate as estate
from tests import test_simul_read_bound as bound
from tests.test_impact_evaluate import graph as graph

from hst.app import simul_read
from hst.path.addrsets import _intervals
from hst.path.gates import pbr
from hst.simul import rib

IF_LAN = "if:eth1"
DEV = f"dev:{bound.E}"


def _return_columns(query: str) -> list[str]:
    """The column names of the last RETURN of `query`, in order."""
    body = query[query.rindex("RETURN") :].split("ORDER BY")[0]
    body = body.removeprefix("RETURN").strip().removeprefix("DISTINCT")
    items, depth, cur = [], 0, ""
    for ch in body:
        depth += ch in "([{"
        depth -= ch in ")]}"
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    items.append(cur)
    return [re.split(r"\s+AS\s+", item.strip())[-1].strip() for item in items if item.strip()]


def _keys_read_by_the_partition() -> set[str]:
    source = "".join(
        inspect.getsource(f)
        for f in (pbr.partition_rules, pbr._as_firewall_row, pbr._service_state, pbr._service_boxes)
    )
    return set(re.findall(r"\br\.get\(\"(\w+)\"", source)) | set(re.findall(r"\br\[\"(\w+)\"\]", source))


def test_the_binding_read_returns_every_column_of_the_tracer_rule_read() -> None:
    fragment = _return_columns(pbr._PBR_RULE_ROWS)
    bindings = _return_columns(simul_read._PBR_BINDINGS)
    assert len(bindings) == len(set(bindings))
    assert set(bindings) == set(fragment) | {"if_uid", "context_uid"}


def test_the_binding_read_returns_every_column_the_partition_reads() -> None:
    read = _keys_read_by_the_partition()
    assert {"src_negate", "dst_negate", "states_opaque", "addr_opaque_reasons"} <= read
    assert read <= set(_return_columns(simul_read._PBR_BINDINGS))


def test_the_binding_read_runs_the_tracer_rule_fragment_itself() -> None:
    assert pbr._PBR_RULE_ROWS in simul_read._PBR_BINDINGS


def _row(**over: Any) -> dict[str, Any]:
    """One `_PBR_BINDINGS` row with every column the query returns."""
    row: dict[str, Any] = dict.fromkeys(_return_columns(simul_read._PBR_BINDINGS))
    row.update(
        if_uid=IF_LAN,
        context_uid=bound.E,
        pol_af=4,
        src_cidrs=[],
        src_ips=[],
        dst_cidrs=[],
        dst_ips=[],
        src_ranges=[],
        dst_ranges=[],
        src_obj_count=0,
        dst_obj_count=0,
        svc_obj_count=0,
        svc_protos=[],
        svc_port_specs=[],
        svc_opaque=False,
        svc_opaque_reasons=[],
        svc_src_port=False,
        svc_src_ports=[],
        # the read's coalesce() defaults, which a rule without the property gets
        states_opaque=False,
        states_opaque_reason=None,
        src_negate=False,
        dst_negate=False,
        addr_opaque_reasons=[],
    )
    row.update(over)
    return row


class _PbrGraph(bound._Graph):
    """The estate of `test_simul_read_bound` with PBR rule rows on one
    device. A row comes back with the columns the binding query it is
    handed returns, and no other, so a query that drops a column drops it
    here too."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        super().__init__()
        self.pbr_rows = rows

    def read(self, _session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
        if query is simul_read._PBR_BINDINGS:
            if params.get("dev") != DEV:
                return []
            columns = _return_columns(query)
            return [{k: r[k] for k in columns if k in r} for r in self.pbr_rows]
        return super().read(_session, query, **params)


def _fib(monkeypatch, rows: list[dict[str, Any]]) -> rib.Fib:
    result, _sources = bound._read(monkeypatch, _PbrGraph(rows), contexts=[bound.E])
    return rib.compute(result.input).fib


def _claims(groups: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    return [
        (g["rule_uid"], g["table_uid"], tuple(g["sources"]), tuple(g["dst"]), g["opaque"], g["opaque_reason"])
        for g in groups
    ]


def test_a_negated_source_claims_what_its_addresses_exclude(monkeypatch) -> None:
    fib = _fib(
        monkeypatch,
        [
            _row(
                pol_uid="pbr:lan",
                pol_name="LAN",
                rule_uid="r:10",
                pos=10,
                src_cidrs=["10.10.0.0/24"],
                src_obj_count=1,
                src_negate=True,
                table_uid="vrf:wg",
                table_name="100",
            )
        ],
    )
    groups = fib.partition(IF_LAN, _intervals(["10.0.0.0/8"]), _intervals(["198.51.100.0/24"]))
    redirected = [g for g in groups if g["rule_uid"] == "r:10"]
    assert len(redirected) == 1
    claimed = redirected[0]["sources"]
    assert not any(lo <= _intervals(["10.10.0.5"])[0][1] <= hi for _af, lo, hi in claimed)
    assert any(lo <= _intervals(["10.20.0.5"])[0][1] <= hi for _af, lo, hi in claimed)
    main = [g for g in groups if g["rule_uid"] is None]
    assert any(lo <= _intervals(["10.10.0.5"])[0][1] <= hi for g in main for _af, lo, hi in g["sources"])


def test_an_opaque_rule_is_an_undecided_claim_not_a_decided_redirect(monkeypatch) -> None:
    fib = _fib(
        monkeypatch,
        [
            _row(
                pol_uid="pbr:lan",
                pol_name="LAN",
                rule_uid="r:10",
                pos=10,
                src_cidrs=["10.10.0.0/24"],
                src_obj_count=1,
                states_opaque=True,
                states_opaque_reason="matches on connection-mark, which is not modeled",
                table_uid="vrf:wg",
                table_name="100",
            ),
            _row(
                pol_uid="pbr:lan",
                pol_name="LAN",
                rule_uid="r:20",
                pos=20,
                src_cidrs=["10.10.0.0/24"],
                src_obj_count=1,
                addr_opaque_reasons=["address group IOT_HOSTS could not be resolved"],
                table_uid="vrf:wg2",
                table_name="200",
            ),
        ],
    )
    groups = fib.partition(IF_LAN, _intervals(["10.10.0.0/24"]), _intervals(["198.51.100.0/24"]))
    claimed = [g for g in groups if g["rule_uid"] == "r:10"]
    assert len(claimed) == 1
    assert claimed[0]["opaque"] is True
    assert "connection-mark" in claimed[0]["opaque_reason"]
    # the undecided claim is not a decided miss either: the flow does not
    # continue to the later rule or to the interface's own table
    assert [g["rule_uid"] for g in groups] == ["r:10"]
    # nor does the forwarding decision route it through the rule's table or
    # let it fall through to the interface's own
    forwarded = fib.forward(IF_LAN, _intervals(["10.10.0.0/24"]), _intervals(["198.51.100.0/24"]))
    assert [(g["rule_uid"], g["opaque"], g["parts"]) for g in forwarded] == [("r:10", True, [])]
    assert not any("fell_through_from" in g for g in forwarded)

    groups = fib.partition(IF_LAN, _intervals(["10.20.0.0/24"]), _intervals(["198.51.100.0/24"]))
    assert all(g["rule_uid"] is None for g in groups)


def test_an_unresolved_address_object_is_an_undecided_claim(monkeypatch) -> None:
    fib = _fib(
        monkeypatch,
        [
            _row(
                pol_uid="pbr:iot",
                pol_name="IOT",
                rule_uid="r:10",
                pos=10,
                src_cidrs=["10.30.0.0/24"],
                src_obj_count=2,
                addr_opaque_reasons=["address group IOT_HOSTS could not be resolved"],
                table_uid="vrf:wg",
                table_name="100",
            )
        ],
    )
    groups = fib.partition(IF_LAN, _intervals(["10.30.0.0/24"]), _intervals(["198.51.100.0/24"]))
    assert [(g["rule_uid"], g["opaque"]) for g in groups] == [("r:10", True)]
    assert "IOT_HOSTS" in groups[0]["opaque_reason"]


_OWNER_POLICIES = (
    ("if:eth1.20", "PBR-GUEST", {"src_cidrs": ["192.168.20.0/24", "10.20.0.0/24"]}, "vrf:wg-guest"),
    ("if:eth1.30", "PBR-IOT", {"src_ranges": [["192.168.30.10-192.168.30.20"]]}, "vrf:wg-iot"),
    ("if:eth1.10", "PBR-LAN", {"src_cidrs": ["192.168.10.0/24"], "src_ips": ["192.168.11.5"]}, "vrf:wg-lan"),
)


def _owner_rows() -> list[dict[str, Any]]:
    """The shapes of the owner's VyOS router: three policies on three
    interfaces, each first keeping local traffic (destination
    192.168.0.0/16) in the main table, then sending a source address group,
    or one source range, into a WireGuard table."""
    rows = []
    for if_uid, name, src, table in _OWNER_POLICIES:
        common = {"if_uid": if_uid, "pol_uid": f"pbr:{name}", "pol_name": name}
        rows.append(
            _row(
                **common,
                rule_uid=f"{name}:10",
                pos=10,
                dst_cidrs=["192.168.0.0/16"],
                dst_obj_count=1,
                table_uid=bound.E,
                table_name="main",
            )
        )
        rows.append(
            _row(
                **common,
                rule_uid=f"{name}:20",
                pos=20,
                src_obj_count=1,
                table_uid=table,
                table_name="wg",
                **src,
            )
        )
    return rows


_NEW_COLUMNS = ("states_opaque", "states_opaque_reason", "src_negate", "dst_negate", "addr_opaque_reasons")


def test_owner_router_rules_compile_one_fib_with_or_without_negation_and_opaque_columns(monkeypatch) -> None:
    rows = _owner_rows()
    new = _fib(monkeypatch, rows)
    old = _fib(monkeypatch, [{k: v for k, v in r.items() if k not in _NEW_COLUMNS} for r in rows])
    src = _intervals(["192.168.0.0/16", "10.20.0.0/24"])
    dst = _intervals(["0.0.0.0/0"])
    for if_uid, name, src_side, table in _OWNER_POLICIES:
        groups = new.partition(if_uid, src, dst)
        assert _claims(groups) == _claims(old.partition(if_uid, src, dst))
        assert not any(g["opaque"] for g in groups)
        assert [g["rule_uid"] for g in groups][:2] == [f"{name}:10", f"{name}:20"]
        assert {g["rule_uid"] for g in groups[2:]} == {None}
        local, tunnel = groups[0], groups[1]
        assert (local["table_uid"], local["dst"]) == (bound.E, _intervals(["192.168.0.0/16"]))
        assert tunnel["table_uid"] == table
        assert tunnel["sources"] == _intervals(
            [
                *src_side.get("src_cidrs", []),
                *src_side.get("src_ips", []),
                *(src_side.get("src_ranges") or [[]])[0],
            ]
        )


def _impact(rule: dict[str, Any]) -> Any:
    """The impact walk over the estate of `test_impact_evaluate`, with one
    PBR rule row on R1's ingress interface, in the shape the binding query
    returns."""
    if_uid = next(i.uid for i in estate._interfaces() if i.device_uid == estate.R1 and i.name == "eth0")
    row = _row(pol_uid="pbr:lan", pol_name="LAN", rule_uid="r:10", pos=10, table_uid="vrf:wg", **rule)
    rules = [{k: v for k, v in row.items() if k not in ("if_uid", "context_uid")}]
    inp = replace(
        estate._routing(),
        pbr=[{"if_uid": if_uid, "device_uid": estate.R1, "context_uid": estate.VRF_R1, "rules": rules}],
    )
    return estate.ev.answer(estate._network(inp), estate._request())


def test_an_opaque_rule_leaves_the_impact_answer_not_established(graph) -> None:
    explanation = estate._only(
        _impact({"states_opaque": True, "states_opaque_reason": "matches on connection-mark"})
    )
    assert explanation.outcome == estate.ev.NOT_ESTABLISHED
    assert estate._step(explanation, "pbr", "unknown-predicate")
    assert any("connection-mark" in m for m in explanation.missing)


def test_a_negated_rule_that_excludes_the_clients_leaves_them_on_the_main_table(graph) -> None:
    answer = _impact({"src_cidrs": ["10.0.0.0/24"], "src_obj_count": 1, "src_negate": True})
    assert answer.lower == estate.CLIENTS
    # read as a plain rule, it claims the clients into a table the
    # calculation does not hold
    plain = _impact({"src_cidrs": ["10.0.0.0/24"], "src_obj_count": 1, "src_negate": False})
    assert plain.lower == ()
