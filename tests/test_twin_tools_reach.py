"""The path tools: `reach_trace` against GET /api/path, the leg
evidence, and `reach_audit_mtu` cursors. `test_twin_tools_policy.py` tests the
groups mode."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from tests.twin_tools_fakes import FakeGraph, call, context, install, settings

from hst import path as pathmod
from hst.core.mtu_read import MtuEvidenceSet

_PERMIT = {"lane": 0, "blocked": False, "indeterminate": False, "verdict": "egress via eth1"}
_BLOCK = {"lane": 1, "blocked": True, "indeterminate": False, "verdict": "BLOCKED by fw1 rule 7"}
_UNDECIDED = {"lane": 2, "blocked": False, "indeterminate": True, "verdict": "egress via eth2"}


def _answer(*legs, **extra):
    return {
        "hops": [{"lane": 0, "uid": "dev:r1"}],
        "legs": [dict(leg) for leg in legs],
        "verdict": "; ".join(leg["verdict"] for leg in legs),
        "notes": ["one note"],
        "warnings": [],
        "indeterminate": any(leg["indeterminate"] for leg in legs),
        "boundary": False,
        **extra,
    }


def _fake_trace(monkeypatch, answer):
    """Replace the tracer; every call records the arguments it was given."""
    calls = []

    def trace(session, src, dst, port=None, proto="tcp", gateways=None, rib=None, **kwargs):
        calls.append(
            {
                "cts": session.cts,
                "src": src,
                "dst": dst,
                "port": port,
                "proto": proto,
                "rib": type(rib).__name__,
            }
            | kwargs
        )
        return answer() if callable(answer) else answer

    monkeypatch.setattr(pathmod, "trace", trace)
    return calls


def _unwrapped(part):
    """A tool answer part with each leg back in the tracer's own shape."""
    out = {k: v for k, v in part.items() if k != "legs_truncated"}
    out["legs"] = [item["leg"] for item in part["legs"]]
    return out


def _trace(tmp_path, flow, **extra):
    """One path-mode call, with a side store for the RIB reader to bind to."""
    return call("reach_trace", {"mode": "path", "flow": flow, **extra}, context(sidestore_dir=tmp_path))


# --- criterion 1: the same answer as GET /api/path ------------------------------------------


def test_path_mode_without_a_protocol_equals_get_api_path_without_one(monkeypatch, tmp_path):
    from hst.app.routes import path as path_route

    graph = install(monkeypatch, FakeGraph())

    @contextmanager
    def route_session(route_settings):
        yield graph

    monkeypatch.setattr(path_route, "_session", route_session)
    calls = _fake_trace(monkeypatch, lambda: _answer(_PERMIT, _BLOCK))
    configured = settings(sidestore_dir=tmp_path)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=configured)))

    rest = path_route.get_path(request, src="10.0.0.1", dst="10.0.0.2")
    failed, envelope = call(
        "reach_trace",
        {"mode": "path", "flow": {"src": "10.0.0.1", "dst": "10.0.0.2"}},
        context(sidestore_dir=tmp_path),
    )

    assert not failed, envelope
    route_call, tool_call = calls
    assert route_call == tool_call
    assert tool_call["proto"] is None and tool_call["port"] is None
    assert _unwrapped(envelope["result"]) == {k: v for k, v in rest.items() if k != "run"}
    assert envelope["snapshot"]["run"] == rest["run"]
    assert envelope["snapshot"]["id"] == "4000"


def test_a_stated_protocol_and_port_reach_the_tracer_as_the_route_parses_them(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    calls = _fake_trace(monkeypatch, lambda: _answer(_PERMIT))

    failed, _ = _trace(tmp_path, {"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "tcp", "port": 443})

    assert not failed
    assert (calls[0]["proto"], calls[0]["port"]) == ("tcp", 443)
    assert "src_port" not in calls[0]


# --- criterion 2: leg evidence ------------------------------------------------------------


def test_an_indeterminate_leg_makes_the_answer_not_established(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    _fake_trace(monkeypatch, lambda: _answer(_PERMIT, _UNDECIDED))

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.1", "dst": "10.0.0.2"})

    assert not failed
    assert envelope["evidence"]["result"]["word"] == "not decided"
    assert [leg["evidence"]["result"]["answer"] for leg in envelope["result"]["legs"]] == ["true", "open"]


def test_decided_legs_are_proven_one_way_or_the_other(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    _fake_trace(monkeypatch, lambda: _answer(_PERMIT, _BLOCK))

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.1", "dst": "10.0.0.2"})

    assert not failed
    assert envelope["evidence"]["result"]["word"] == "blocked"
    assert [leg["evidence"]["result"]["answer"] for leg in envelope["result"]["legs"]] == ["true", "false"]


def test_a_leg_with_no_route_is_proven_not_to_hold_and_names_the_missing_route(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    no_route = {
        "lane": 0,
        "blocked": False,
        "indeterminate": False,
        "verdict": "no route found",
        "device_uid": "dev:r1",
    }
    _fake_trace(monkeypatch, lambda: _answer(no_route))

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.1", "dst": "10.0.0.2"})

    assert not failed
    (leg,) = envelope["result"]["legs"]
    assert leg["evidence"]["result"]["statement"] == "hop-forwards"
    assert leg["evidence"]["result"]["word"] == "no route"
    assert leg["evidence"]["result"]["answer"] == "false"
    assert leg["evidence"]["basis"] == "derived"
    assert envelope["evidence"]["result"]["word"] == "blocked at dev:r1"
    assert envelope["evidence"]["result"]["statement"] == "trace-forwards"
    assert envelope["evidence"]["result"]["word"] == "blocked at dev:r1"
    assert any("records no route" in text for text in envelope["evidence"]["unknowns"])


def test_an_indeterminate_reply_leg_makes_a_reply_answer_not_established(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    reply = [
        {**_answer(_PERMIT), "forward_leg": 0, "asymmetric": False},
        {**_answer(_UNDECIDED), "forward_leg": 1, "asymmetric": True},
    ]
    nested = {"forward": _answer(_PERMIT, _PERMIT), "reply": reply, "asymmetric": True, "notes": []}
    calls = _fake_trace(monkeypatch, nested)

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.0/24", "dst": "10.0.1.2"}, reply=True)

    assert not failed
    assert calls[0]["reply"] is True
    result = envelope["result"]
    assert [leg["evidence"]["result"]["answer"] for leg in result["forward"]["legs"]] == ["true", "true"]
    assert [part["legs"][0]["evidence"]["result"]["answer"] for part in result["reply"]] == [
        "true",
        "open",
    ]
    assert envelope["evidence"]["result"]["word"] == "not decided"


def test_a_trace_with_no_leg_establishes_nothing(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    _fake_trace(
        monkeypatch, {"hops": [], "legs": [], "notes": [], "warnings": [], "verdict": "not an address"}
    )

    failed, envelope = _trace(tmp_path, {"src": "x", "dst": "10.0.0.2"})

    assert not failed
    assert envelope["evidence"]["result"]["word"] == "not decided"


def test_a_port_the_route_grammar_refuses_is_invalid_argument_before_any_read(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    failed, error = call(
        "reach_trace", {"mode": "path", "flow": {"src": "10.0.0.1", "dst": "10.0.0.2", "port": "http"}}
    )

    assert failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "flow"
    assert graph.session_kwargs == []


# --- the estate's edge: `left_estate` and `reach` -------------------------------------------

_ZONE_EXIT = {
    "basis": "site-zone",
    "device_uid": "dev:edge1",
    "device": "edge1",
    "interface_uid": "if:edge1:gi0",
    "interface": "Gi0/0/0",
    "next_hop": "198.51.100.1",
    "wan_link_uid": None,
    "wan_link": None,
    "site_block": "dc-edge",
}
_WAN_EXIT = {
    "basis": "wan-link",
    "device_uid": "dev:vyos",
    "device": "vyos",
    "interface_uid": "if:vyos:eth0",
    "interface": "eth0",
    "next_hop": None,
    "wan_link_uid": "wan:1",
    "wan_link": "isp-a",
    "site_block": None,
}


def _edge_leg(exit_):
    return {
        **_PERMIT,
        "boundary": True,
        "carrier": {"verdict": "carrier ok", "left_estate": exit_},
        "left_estate": exit_,
    }


def _edge_answer(exit_, reach="left_estate"):
    return _answer(_edge_leg(exit_), boundary=True, left_estate=[exit_], reach=reach)


def test_the_estate_exit_passes_through_the_tool_unchanged(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    _fake_trace(monkeypatch, lambda: _edge_answer(_ZONE_EXIT))

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.1", "dst": "8.8.8.8"})

    assert not failed, envelope
    result = envelope["result"]
    assert result["reach"] == "left_estate"
    assert result["left_estate"] == [_ZONE_EXIT]
    (item,) = result["legs"]
    assert item["leg"]["left_estate"] == _ZONE_EXIT
    assert item["leg"]["carrier"]["left_estate"] == _ZONE_EXIT
    assert envelope["evidence"]["result"]["answer"] == "true"
    assert result["exits"] == [
        "the walk: the last hop is outside the estate: edge1 Gi0/0/0 to next hop 198.51.100.1 "
        '(the operator\'s site zone "internet" of block dc-edge)'
    ]
    assert not [text for text in envelope["evidence"]["unknowns"] if "outside the estate" in text]


def test_each_reply_walk_names_its_own_exit(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    forward = _answer(_PERMIT, _PERMIT, left_estate=[], reach="destination")
    one = {**_edge_answer(_WAN_EXIT), "forward_leg": 0, "src_label": "10.0.0.0/25", "asymmetric": False}
    two = {
        **_edge_answer(_ZONE_EXIT, "split"),
        "forward_leg": 1,
        "src_label": "10.0.0.128/25",
        "asymmetric": False,
    }
    nested = {"forward": forward, "reply": [one, two], "asymmetric": False, "notes": []}
    _fake_trace(monkeypatch, nested)

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.0/24", "dst": "8.8.8.8"}, reply=True)

    assert not failed, envelope
    result = envelope["result"]
    assert result["forward"]["reach"] == "destination" and result["forward"]["left_estate"] == []
    assert [part["reach"] for part in result["reply"]] == ["left_estate", "split"]
    assert [part["left_estate"] for part in result["reply"]] == [[_WAN_EXIT], [_ZONE_EXIT]]
    assert not [text for text in envelope["evidence"]["unknowns"] if "outside the estate" in text]
    assert result["exits"] == [
        "reply for 10.0.0.0/25: the last hop is outside the estate: vyos eth0 with no next hop "
        "(a collected WAN link isp-a)",
        "reply for 10.0.0.128/25: split by path; the last hop of some paths is outside the estate: "
        'edge1 Gi0/0/0 to next hop 198.51.100.1 (the operator\'s site zone "internet" of block dc-edge)',
    ]


def test_a_single_reply_walk_names_its_exit(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    client = {**_ZONE_EXIT, "basis": "access-client-default", "site_block": None}
    nested = {"forward": _answer(_PERMIT), "reply": _edge_answer(client), "asymmetric": False, "notes": []}
    _fake_trace(monkeypatch, nested)

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.1", "dst": "8.8.8.8"}, reply=True)

    assert not failed, envelope
    assert envelope["result"]["reply"]["left_estate"] == [client]
    assert envelope["result"]["exits"] == [
        "reply: the last hop is outside the estate: edge1 Gi0/0/0 to next hop 198.51.100.1 "
        "(the access client's default)"
    ]


def test_an_answer_without_the_marker_has_no_exit_fields(monkeypatch, tmp_path):
    install(monkeypatch, FakeGraph())
    _fake_trace(monkeypatch, lambda: _answer(_PERMIT, boundary=True))

    failed, envelope = _trace(tmp_path, {"src": "10.0.0.1", "dst": "8.8.8.8"})

    assert not failed, envelope
    assert not {"reach", "left_estate", "exits"} & set(envelope["result"])
    assert envelope["evidence"]["unknowns"] == [
        "at least one leg leaves the modeled estate; the path past that boundary is not evaluated"
    ]


def test_exit_sentences_name_what_the_exit_records():
    from hst.twin_tools.reach import exit_sentences

    zone_no_block = {**_ZONE_EXIT, "site_block": None, "device": None}
    other = {**_WAN_EXIT, "basis": "something-new", "interface": None}
    walk = {"reach": "left_estate", "left_estate": [zone_no_block, other]}

    assert exit_sentences(walk) == [
        "the walk: the last hop is outside the estate: dev:edge1 Gi0/0/0 to next hop 198.51.100.1 "
        '(the operator\'s site zone "internet")',
        "the walk: the last hop is outside the estate: vyos if:vyos:eth0 with no next hop "
        "(basis something-new)",
    ]
    for reach in (None, "destination"):
        assert exit_sentences({"reach": reach, "left_estate": [_ZONE_EXIT]}) == []


# --- criterion 4: reach_audit_mtu cursors ----------------------------------------------------


_LINKS = [{"subject_uid": "a", "peer_uid": "b"}, {"subject_uid": "b", "peer_uid": "c"}]


def _audit_rows(params):
    after = (params["after_a"], params["after_b"])
    return [r for r in _LINKS if (r["subject_uid"], r["peer_uid"]) > after][: params["row_limit"]]


def _audit_graph(monkeypatch):
    monkeypatch.setattr("hst.core.mtu_audit_read.read_mtu", lambda *a, **k: MtuEvidenceSet())
    return install(monkeypatch, FakeGraph([("RETURN DISTINCT a.uid AS subject_uid", _audit_rows)]))


def test_a_reach_audit_mtu_cursor_continues_the_next_page(monkeypatch):
    _audit_graph(monkeypatch)

    failed, first = call("reach_audit_mtu", {"limit": 1})
    next_failed, second = call("reach_audit_mtu", {"limit": 1, "cursor": first["page"]["next_cursor"]})

    assert not failed and not next_failed, second
    assert [item["subject_uid"] for item in first["result"]["items"]] == ["a"]
    assert first["page"]["truncated"] is True
    assert first["evidence"]["complete"] is False
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in [gap["code"] for gap in first["evidence"]["gaps"]]
    assert [item["subject_uid"] for item in second["result"]["items"]] == ["b"]
    assert second["page"]["next_cursor"] is None


def test_a_cursor_for_another_scope_is_cursor_mismatch(monkeypatch):
    _audit_graph(monkeypatch)

    _, first = call("reach_audit_mtu", {"limit": 1})
    failed, error = call("reach_audit_mtu", {"limit": 1, "af": 6, "cursor": first["page"]["next_cursor"]})

    assert failed and error["error"]["code"] == "cursor_mismatch" and error["error"]["field"] == "cursor"


def test_a_domain_audit_without_a_subject_is_invalid_argument(monkeypatch):
    _audit_graph(monkeypatch)

    failed, error = call("reach_audit_mtu", {"scope": "fabric"})

    assert (
        failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "subject_uid"
    )


def test_exit_sentences_use_only_result_words():
    from hst.results.words import FORBIDDEN_WORDS, _contains_word
    from hst.twin_tools.reach import exit_sentences

    exits = [
        _ZONE_EXIT,
        _WAN_EXIT,
        {**_ZONE_EXIT, "basis": "access-client-default"},
        {**_ZONE_EXIT, "site_block": None, "next_hop": None},
    ]
    texts = [
        text
        for reach in ("left_estate", "split")
        for text in exit_sentences({"forward": {"reach": reach, "left_estate": exits}, "reply": None})
    ]
    assert len(texts) == 8
    for text in texts:
        assert not [w for w in FORBIDDEN_WORDS if _contains_word(text.lower(), w)], text
        assert not _contains_word(text.lower(), "not established"), text
