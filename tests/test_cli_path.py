"""`hst path`: src_context/dst_context passthrough. Route validation and the
trace fan-out itself are covered in tests/test_path_trace.py and
tests/app/test_data_api.py; this checks that the CLI passes its two options to
path.trace() verbatim."""

from contextlib import contextmanager

from typer.testing import CliRunner

import hst.cli as cli
import hst.path as pathmod
from hst.core import Settings

runner = CliRunner()

TRACE = {"verdict": "ok", "notes": [], "hops": [], "legs": []}


@contextmanager
def _fake_session_cm(settings):
    yield object()


def _patch(monkeypatch, fake_trace):
    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(cli.dbmod, "session", _fake_session_cm)
    monkeypatch.setattr(pathmod, "trace", fake_trace)


def test_src_context_and_dst_context_options_pass_through(monkeypatch):
    seen = {}

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None
    ):
        seen.update(src_context=src_context, dst_context=dst_context)
        return TRACE

    _patch(monkeypatch, fake_trace)
    r = runner.invoke(
        cli.app,
        [
            "path",
            "10.0.0.5",
            "8.8.8.8",
            "--src-context",
            "vrf:dev:r1:home",
            "--dst-context",
            "vrf:dev:r2:guest",
        ],
    )

    assert r.exit_code == 0, r.output
    assert seen == {"src_context": "vrf:dev:r1:home", "dst_context": "vrf:dev:r2:guest"}


def test_context_options_default_to_none(monkeypatch):
    seen = {}

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None
    ):
        seen.update(src_context=src_context, dst_context=dst_context)
        return TRACE

    _patch(monkeypatch, fake_trace)
    r = runner.invoke(cli.app, ["path", "10.0.0.5", "8.8.8.8"])

    assert r.exit_code == 0, r.output
    assert seen == {"src_context": None, "dst_context": None}


def test_reply_option_renders_both_blocks(monkeypatch):
    """--reply renders the forward block, then a second block for the reply
    headed by the asymmetric-routing note when present."""
    seen = {}
    nested = {
        "forward": {
            "verdict": "forward verdict",
            "notes": [],
            "hops": [{"rank": 0, "kind": "Gateway", "label": "gw1", "note": "", "uid": "u:1"}],
            "legs": [],
        },
        "reply": {
            "verdict": "reply verdict",
            "notes": [],
            "hops": [{"rank": 0, "kind": "Gateway", "label": "gw2", "note": "", "uid": "u:2"}],
            "legs": [],
        },
        "asymmetric": True,
        "notes": ["asymmetric routing: the reply's own path (r2 → r1) does not retrace r1 → r2"],
    }

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None, **kw
    ):
        seen["reply"] = kw.get("reply", False)
        return dict(nested) if kw.get("reply") else TRACE

    _patch(monkeypatch, fake_trace)

    plain = runner.invoke(cli.app, ["path", "10.0.0.5", "8.8.8.8"])
    assert plain.exit_code == 0, plain.output
    assert seen["reply"] is False
    assert "ok" in plain.output
    assert "reply verdict" not in plain.output

    replied = runner.invoke(cli.app, ["path", "10.0.0.5", "8.8.8.8", "--reply"])
    assert replied.exit_code == 0, replied.output
    assert seen["reply"] is True
    assert "forward verdict" in replied.output
    assert "reply verdict" in replied.output
    assert "asymmetric routing" in replied.output
    assert replied.output.index("asymmetric routing") < replied.output.index("reply verdict")


def test_reply_option_renders_one_block_per_forward_leg(monkeypatch):
    """A trace that fanned out answers with one reply lane per forward
    leg, and every lane is printed under a heading naming the source partition
    its forward leg answers for."""
    nested = {
        "forward": {
            "verdict": "forward verdict",
            "notes": [],
            "hops": [{"rank": 0, "kind": "Gateway", "label": "gw1", "note": "", "uid": "u:1"}],
            "legs": [],
        },
        "reply": [
            {
                "forward_leg": 0,
                "src_label": "10.0.0.0/25",
                "destinations": ["10.0.0.0/25"],
                "verdict": "first lane verdict",
                "notes": [],
                "hops": [{"rank": 0, "kind": "Gateway", "label": "gw2", "note": "", "uid": "u:2"}],
                "legs": [],
                "asymmetric": False,
            },
            {
                "forward_leg": 1,
                "src_label": "10.0.0.128/25",
                "destinations": ["10.0.0.128/25"],
                "verdict": "second lane verdict",
                "notes": [],
                "hops": [{"rank": 0, "kind": "Gateway", "label": "gw3", "note": "", "uid": "u:3"}],
                "legs": [],
                "asymmetric": True,
            },
        ],
        "asymmetric": True,
        "notes": [],
    }

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None, **kw
    ):
        return dict(nested)

    _patch(monkeypatch, fake_trace)

    r = runner.invoke(cli.app, ["path", "10.0.0.0/24", "8.8.8.8", "--reply"])

    assert r.exit_code == 0, r.output
    # "path N/M" names the total.
    assert "reply for path 1/2: 10.0.0.0/25" in r.output
    assert "reply for path 2/2: 10.0.0.128/25" in r.output
    assert "first lane verdict" in r.output
    assert "second lane verdict" in r.output
    assert r.output.index("first lane verdict") < r.output.index("reply for path 2/2")


class _FakeCycleSession:
    """A session whose `.run().data()` answers empty, the "no pointer yet"
    row `current_ts` reads on a real graph before the first cycle."""

    def run(self, query, **params):
        return self

    def data(self):
        return []


@contextmanager
def _fake_cycle_session_cm(settings):
    yield _FakeCycleSession()


def test_proto_by_number_answers_like_the_name(monkeypatch):
    """`--proto` passes its raw string to `path.trace()`, never
    through `routes/path.py`'s `_parse_proto`. A rule scoped by name
    matches a query naming the same protocol by number, so `--proto
    6` and `--proto tcp` answer identically."""
    from tests.test_path_trace import GW, FakeGraph, _route, _rule, _src_row

    g = FakeGraph()
    g.sources = [_src_row()]
    g.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    g.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "drop",
        "approximate": False,
    }
    g.rules = [_rule(uid="cp:ok", pos=1, action="accept", svc_any=False, protos=["tcp"], ports=["443"])]

    monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None))
    monkeypatch.setattr(cli.dbmod, "session", _fake_cycle_session_cm)
    monkeypatch.setattr(pathmod, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(pathmod, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    monkeypatch.setattr(pathmod, "load_gateways", lambda session: [GW])

    by_number = runner.invoke(cli.app, ["path", "10.0.0.5", "8.8.8.8", "--port", "443", "--proto", "6"])
    by_name = runner.invoke(cli.app, ["path", "10.0.0.5", "8.8.8.8", "--port", "443", "--proto", "tcp"])

    assert by_number.exit_code == 0, by_number.output
    assert by_name.exit_code == 0, by_name.output
    # the query's own proto token is echoed verbatim in the summary line;
    # normalize it away so the comparison is the trace's own verdict, not
    # the caller's spelling.
    assert by_number.output.replace("443/6:", "443/PROTO:") == by_name.output.replace(
        "443/tcp:", "443/PROTO:"
    )
    assert "FwRule       rule 1                     accept" in by_number.output
    assert "BLOCKED" not in by_number.output
