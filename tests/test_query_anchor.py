"""Run anchors of the per-request reads: each starts from one node of the pinned
run found through the obj_uid_cts constraint (`:Obj` with `uid` and an exact
`collection_ts`), not from a label scan over every kept run, and the analysis
model reads its graph from the run's own nodes through obj_cts."""

from __future__ import annotations

import ast
import importlib
import inspect
import re
from pathlib import Path
from typing import Any

import pytest

import hst.path as pathpkg
from hst.analysis_model import graph
from hst.path import netobjects, vsx
from hst.path.gates import coverage, firewall, gate_safeguard_query, nat, routing, zpa

# the package exports a `trace` function under the module's own name
trace = importlib.import_module("hst.path.trace")

_UNLABELLED_UID = re.compile(r"\(\w*\s*\{uid:\s*\$")


def _query_constants(module: Any) -> list[str]:
    tree = ast.parse(inspect.getsource(module))
    return [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and "MATCH" in n.value
    ]


def _path_modules() -> list[Any]:
    import pkgutil

    return [
        importlib.import_module(info.name)
        for info in pkgutil.walk_packages(pathpkg.__path__, pathpkg.__name__ + ".")
    ]


def test_no_path_read_matches_a_uid_on_a_node_without_a_label():
    found = [
        (module.__name__, q.strip().splitlines()[0])
        for module in _path_modules()
        for q in _query_constants(module)
        if _UNLABELLED_UID.search(q)
    ]
    assert found == []


def _anchor_pinned(query: str) -> bool:
    """Whether the query's uid anchor seeks on obj_uid_cts at the pinned run."""
    if re.search(r"\(\w+:(?:\w+:)?Obj \{uid: \$\w+, collection_ts: \$snap\}\)", query):
        return True
    m = re.search(r"\((\w+):\w+ \{uid: ?\$\w+\}\)", query) or re.search(r"\b(\w+)\.uid IN \$\w+", query)
    if m is None:
        return False
    v = m.group(1)
    return (
        re.search(rf"\b{v}:Obj\b", query) is not None
        and re.search(rf"\b{v}\.collection_ts\s*=\s*\$snap", query) is not None
        and f"coalesce({v}.collection_ts" not in query
    )


@pytest.mark.parametrize(
    "query",
    [
        trace._L2_CHAIN_QUERY,
        trace._ROUTES_QUERY,
        trace._VRF_NAME_QUERY,
        trace._START_TABLE_QUERY,
        trace._CARRIER_TUNNEL_QUERY,
        vsx.QUERY,
        vsx.EGRESS,
        routing._CONNECTED_INGRESS_QUERY,
        firewall._ZONE_OF_INTERFACE,
        nat._IFACE_ROLE_QUERY,
        zpa._SEGMENT_STATE_QUERY,
        coverage._DEVICE_EVIDENCE,
        netobjects.NET_OBJECTS,
        gate_safeguard_query(),
    ],
)
def test_the_uid_anchor_seeks_on_the_constraint_at_the_pinned_run(query: str) -> None:
    assert _anchor_pinned(query), query


def test_the_tier_reads_reach_the_device_without_a_disjunction_over_unbound_nodes():
    source = (Path(pathpkg.__file__).parents[1] / "map" / "tiers" / "bootstrap.py").read_text()
    disjunction = re.compile(r"WHERE\s+\w+\s*=\s*\w+\s+OR\b")
    assert disjunction.findall(source) == []
    assert "MATCH (d:Device:Obj {uid: $device, collection_ts: $cts})" in source


# --- the analysis model's graph load ------------------------------------------------------


@pytest.mark.parametrize("name", sorted(graph.LOAD_QUERIES))
def test_every_graph_load_match_starts_from_the_pinned_run(name: str) -> None:
    """A page read starts from the run's nodes in uid order through the
    obj_uid_cts hint; a single read pins the run on its anchor's map."""
    query = graph.LOAD_QUERIES[name]
    matches = [line.strip() for line in query.splitlines() if line.strip().startswith("MATCH")]
    assert matches
    for line in matches:
        if line in {"MATCH (x:Obj)", "MATCH (n:Obj)"}:
            variable = line[7]
            assert f"USING INDEX {variable}:Obj(uid, collection_ts)" in query, name
            assert f"{variable}.collection_ts = $snap" in query, name
        else:
            assert "collection_ts: $snap}" in line, (name, line)


# --- every single-uid anchor of hst.path ----------------------------------------------

_EXISTS_BLOCK = re.compile(r"EXISTS\s*\{")
_UID_NODE = re.compile(r"\((\w*)(?::\w+)*\s*\{[^}]*\buid:\s*\$\w+[^}]*\}\)")
_UID_LIST = re.compile(r"\b(\w+)\.uid IN \$\w+")
_CLAUSE_END = re.compile(r"\bWHERE\b|^\s*(?:RETURN|WITH|UNWIND|MATCH|OPTIONAL MATCH|CALL|UNION|\})", re.M)


def _without_exists_blocks(query: str) -> str:
    """The query with each `EXISTS { ... }` body removed: a node there is a test
    on a node the outer match has bound, not an anchor."""
    out, i = [], 0
    for m in _EXISTS_BLOCK.finditer(query):
        if m.start() < i:
            continue
        out.append(query[i : m.start()])
        depth, j = 1, m.end()
        while depth and j < len(query):
            depth += {"{": 1, "}": -1}.get(query[j], 0)
            j += 1
        i = j
    out.append(query[i:])
    return "".join(out)


def _uid_anchors(branch: str) -> list[tuple[str, str]]:
    """(variable, text) of each node a match clause of the branch finds by uid:
    `(x:Label {uid: $p})` in a MATCH pattern and `x.uid IN $uids` in its WHERE."""
    found: list[tuple[str, str]] = []
    clauses = re.split(r"^\s*(?:OPTIONAL\s+)?MATCH\b", branch, flags=re.M)[1:]
    for clause in clauses:
        end = _CLAUSE_END.search(clause)
        pattern = clause[: end.start()] if end else clause
        found += [(m.group(1), m.group(0)) for m in _UID_NODE.finditer(pattern)]
        found += [(m.group(1), m.group(0)) for m in _UID_LIST.finditer(clause)]
    return found


def _unpinned_anchors(query: str) -> list[str]:
    lines = [line for line in query.splitlines() if not line.strip().startswith("//")]
    text = _without_exists_blocks("\n".join(lines))
    unpinned = []
    for branch in re.split(r"^\s*UNION\b.*$", text, flags=re.M):
        for var, node in _uid_anchors(branch):
            in_pattern = re.search(r":Obj\b[^)]*collection_ts:\s*\$snap", node) is not None
            in_where = (
                var != ""
                and re.search(rf"\b{var}:Obj\b", branch) is not None
                and re.search(rf"\b{var}\.collection_ts\s*=\s*\$snap", branch) is not None
                and f"coalesce({var}.collection_ts" not in branch
            )
            # run bookkeeping carries no run of its own; its uid has an index
            bookkeeping = re.match(r"\(\w*:(CycleRun|CollectionRun|CyclePointer)\b", node) is not None
            if not (in_pattern or in_where or bookkeeping):
                unpinned.append(node)
    return unpinned


def test_every_single_uid_anchor_in_the_path_package_is_pinned_to_the_run():
    found = [
        (module.__name__, q.strip().splitlines()[0], anchor)
        for module in _path_modules()
        for q in _query_constants(module)
        for anchor in _unpinned_anchors(q)
    ]
    assert found == []


@pytest.mark.parametrize(
    "query, count",
    [
        ("MATCH (:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase)\nRETURN rb", 1),
        ("MATCH (d:Device {uid: $dev})\nWHERE coalesce(d.collection_ts, $snap) = $snap\nRETURN d", 1),
        ("MATCH (v:VrfInstance)\nWHERE v.uid IN $anchors AND NOT v:Retired\nRETURN v", 1),
        ("MATCH (d:Device {uid: $dev})\nWHERE d:Obj AND d.collection_ts = $snap\nRETURN d", 0),
        (
            "MATCH (i:Interface {uid: $i})\nWHERE i:Obj AND i.collection_ts = $snap\n"
            "  AND EXISTS { MATCH (i)-[:ON]->(:Device {uid: $dev}) }\nRETURN i",
            0,
        ),
    ],
)
def test_the_anchor_guard_flags_the_label_only_and_coalesce_forms(query: str, count: int) -> None:
    assert len(_unpinned_anchors(query)) == count


# --- queries composed at import time ------------------------------------------------------


def _composed_queries() -> list[tuple[str, str]]:
    return [
        (f"{module.__name__}.{name}", value)
        for module in _path_modules()
        for name, value in vars(module).items()
        if isinstance(value, str) and "MATCH" in value
    ]


def test_no_composed_path_query_splices_a_function_into_an_identifier():
    # a textual .replace() on `n.collection_ts` also matches `iin.collection_ts`
    found = [name for name, q in _composed_queries() if re.search(r"\w(?:coalesce|count|head|collect)\(", q)]
    assert found == []


def test_the_nat_rules_default_query_keeps_its_anchor_variable_intact():
    assert "iicoalesce" not in nat._NAT_RULES_QUERY
    assert "iin.collection_ts = $snap" in nat._NAT_RULES_QUERY
    assert "iin.collection_ts = $snap" in nat._NAT_RULES_QUERY_STRICT


def test_the_trunk_by_name_anchor_does_not_shadow_the_tail_device_variable():
    # _TRUNK_TAIL declares `d` inside a pattern comprehension for the switch's
    # device; a `d` bound by the head MATCH would stay in scope and replace it
    assert "(d:Device)" in trace._TRUNK_TAIL
    head = trace._TRUNK_BY_PARENT_NAME_QUERY.split(trace._TRUNK_TAIL)[0]
    assert not re.search(r"\bd:Device\b", head)
