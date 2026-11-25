"""VRF starts past the cap leave the answer open."""

import copy
import importlib

from tests.test_path_start_table import LEAF_A, LEAF_B, graph  # noqa: F401
from tests.test_path_start_vrf import vrf_graph  # noqa: F401

from hst import path
from hst.results.trace import project_trace

tracemod = importlib.import_module("hst.path.trace")


def test_vrf_starts_past_the_cap_leave_the_answer_open(vrf_graph, monkeypatch):  # noqa: F811
    monkeypatch.setattr(tracemod, "MAX_INTERPRETATIONS", 1)

    result = path.trace_from_vrf(None, "10.0.0.0/24", "203.0.113.5", "hosting", gateways=[LEAF_A, LEAF_B])

    assert {h["uid"] for h in result["hops"] if h["kind"] == "Device"} == {"dev:leaf-a"}
    assert (
        result["notes"][0] == "VRF hosting starts the trace on 1 devices (hosting on leaf-a); each is traced"
    )
    assert result["indeterminate"] is True
    assert "not traced: 1 more devices have it (hosting on leaf-b)" in result["warnings"]
    assert project_trace(copy.deepcopy(result))["result"]["answer"] == "open"
