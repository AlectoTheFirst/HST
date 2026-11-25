"""Strict router-local handling of device-wide access policies."""

from hst.path.gates import firewall

SRC = [(4, 0x0A000001, 0x0A000001)]
DST = [(4, 0x0A000002, 0x0A000002)]


def _candidate(*, vendor, chain=None, uid="rb:access"):
    return {
        "rb_uid": uid,
        "rb_name": "Access",
        "vendor": vendor,
        "af": 4,
        "default_action": None,
        "default_action_unknown": False,
        "global_state_policy": None,
        "match_context": None,
        "chain": chain,
        "approximate": False,
    }


def _verdict(monkeypatch, candidate, *, strict_local):
    def read(_session, query, **params):
        if query == firewall._RULEBASE_CANDIDATES:
            assert params["strict_local"] is strict_local
            return [candidate]
        if query.startswith("MATCH (i:Interface)"):
            return []
        raise AssertionError("strict local uncertainty must precede rule reads")

    monkeypatch.setattr(firewall._path, "_read", read)
    return firewall._device_rulebase_verdict(
        None,
        "dev:gateway",
        "if:inside",
        None,
        SRC,
        DST,
        443,
        "tcp",
        4,
        chain="input",
        strict_local=strict_local,
    )


def test_strict_local_includes_chainless_checkpoint_policy_as_unknown(monkeypatch):
    verdict = _verdict(monkeypatch, _candidate(vendor="checkpoint"), strict_local=True)
    assert verdict["action"] == "indeterminate"
    assert verdict["rb_uid"] == "rb:access"
    assert "implied rules" in verdict["indeterminate_reason"]


def test_strict_local_rejects_unrecognized_chainless_pipeline(monkeypatch):
    verdict = _verdict(monkeypatch, _candidate(vendor="mystery"), strict_local=True)
    assert verdict["action"] == "indeterminate"
    assert "no modeled router-local pipeline scope" in verdict["indeterminate_reason"]


def test_non_strict_local_mode_keeps_the_chainless_forward_default(monkeypatch):
    def read(_session, query, **params):
        if query == firewall._RULEBASE_CANDIDATES:
            assert params["strict_local"] is False
            return []
        raise AssertionError("unexpected query")

    monkeypatch.setattr(firewall._path, "_read", read)
    assert (
        firewall._device_rulebase_verdict(
            None,
            "dev:gateway",
            "if:inside",
            None,
            SRC,
            DST,
            443,
            "tcp",
            4,
            chain="input",
        )
        is None
    )
