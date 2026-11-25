"""The trace walk's shape."""

from __future__ import annotations

import ast
import dataclasses
import importlib
import inspect
from pathlib import Path

import pytest

from hst.path.walk import WalkContext

# the module, not the `trace` function that hst.path re-exports
trace_mod = importlib.import_module("hst.path.trace")

SOURCE = Path(trace_mod.__file__).read_text()
# the wrappers keep their parameters, so every caller and test reaches them unchanged
SIGNATURES = {
    "_group_legs": [
        "session", "trail", "grp", "gw", "lane", "port", "proto", "rib", "nat_rows", "depth", "visited",
        "max_hops", "conn_state",
    ],
    "_route_leg": [
        "session", "trail", "grp", "gw", "route", "dst_part", "dst_label", "lane", "port", "proto", "rib",
        "nat_rows", "depth", "visited", "src_label", "max_hops", "lane_pre", "conn_state",
    ],
    "_device_stage": [
        "session", "trail", "gw", "src_set", "dst_set", "port", "proto", "lane", "rib", "depth", "visited",
        "max_hops", "conn_state", "src_port",
    ],
    "trace": [
        "session", "src_ip", "dst_ip", "port", "proto", "gateways", "rib", "src_context", "dst_context",
        "start_table", "max_hops", "reply", "src_port", "mtu", "dscp",
    ],
}  # fmt: skip


def _functions() -> dict[str, ast.FunctionDef]:
    return {n.name: n for n in ast.parse(SOURCE).body if isinstance(n, ast.FunctionDef)}


def _body_lines(node: ast.FunctionDef) -> int:
    body = node.body
    if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return body[-1].end_lineno - body[0].lineno + 1  # type: ignore[operator]


def test_the_walk_context_is_frozen_and_changes_by_copy():
    ctx = WalkContext(session=None, trail=None, port=80, proto="tcp", rib=None, max_hops=8)  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.port = 443  # type: ignore[misc]
    deeper = ctx.but(depth=1, visited=frozenset({"dev:a"}))
    assert (ctx.depth, ctx.visited) == (0, frozenset())
    assert (deeper.depth, deeper.visited, deeper.port) == (1, frozenset({"dev:a"}), 80)


def test_the_wrappers_keep_their_signatures():
    for name, params in SIGNATURES.items():
        assert list(inspect.signature(getattr(trace_mod, name)).parameters) == params, name


def test_the_three_walk_wrappers_only_build_the_context():
    functions = _functions()
    for name, walk in (
        ("_group_legs", "_walk_group"),
        ("_route_leg", "_walk_route"),
        ("_device_stage", "_walk_device"),
    ):
        assert _body_lines(functions[name]) <= 15, name
        assert walk in ast.unparse(functions[name]), name


def test_no_split_function_grows_past_150_lines():
    functions = _functions()
    split = [
        "_walk_group", "_routed_parts", "_router_local_legs", "_sdwan_candidates", "_routed_part_legs",
        "_walk_route", "_route_egress", "_route_region_legs", "_deliver_locally", "_walk_device",
        "_device_groups", "_part_groups", "_trace_host_source", "_trace_network_source", "trace",
    ]  # fmt: skip
    sizes = {name: functions[name].end_lineno - functions[name].lineno + 1 for name in split}  # type: ignore[operator]
    assert {name: size for name, size in sizes.items() if size > 150 and name != "trace"} == {}
    assert _body_lines(functions["trace"]) <= 100
