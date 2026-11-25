"""The pure drawing helpers of the trace walk (`hst.path.trace_draw`)."""

from __future__ import annotations

from hst.path.gates import _Trail
from hst.path.trace_draw import _zpa_early_result, _zpa_stop


def test_a_stop_without_a_blocking_object_is_indeterminate_and_warned():
    trail = _Trail()
    result = _zpa_stop(trail, "seg-1: no connector determined")
    assert result["verdict"] == "seg-1: no connector determined"
    assert result["indeterminate"] is True
    assert result["legs"] == [{"indeterminate": True}]
    assert result["warnings"] == trail.warnings == ["seg-1: no connector determined"]


def test_a_stop_with_a_blocking_object_is_a_blocked_leg():
    result = _zpa_stop(_Trail(), "seg-1 is disabled", blocking_uid="seg-1")
    assert result["indeterminate"] is False
    assert result["legs"] == [{"indeterminate": False, "blocked": True, "blocking_uid": "seg-1"}]
    assert result["boundary"] is False


def test_a_stop_is_the_warning_plus_the_early_result():
    warned, direct = _Trail(), _Trail()
    direct.warn("reason")
    assert _zpa_stop(warned, "reason") == _zpa_early_result(direct, verdict="reason", indeterminate=True)
