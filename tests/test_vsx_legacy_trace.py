"""The legacy engine's VSX context branch: the rulebase of a virtual system is
found through the ingress interface's FirewallInstance, joined to the
management Device by cp_raw_uid under a _scope guard, in the access and the
NAT queries alike. The database cases live in test_integration_db.py; these
pin the query shape and the parameter plumbing without a database.
"""

from __future__ import annotations

from typing import Any

from hst.path.gates import firewall, nat

_CONTEXT_MATCH = "MATCH (iin:Interface {uid: $in_if})-[c:IN_CONTEXT]->(fi:FirewallInstance)"
_JOIN = "vs.cp_raw_uid = fi.gateway_object_uid AND vs._scope = fi.authority"


def test_the_access_candidates_query_carries_the_context_branch_with_the_scope_guard():
    q = firewall._RULEBASE_CANDIDATES
    assert q.count(_CONTEXT_MATCH) == 1
    assert q.count(_JOIN) == 1
    # the branch repeats the guards of the two device-bound branches
    assert q.count("rb.collection_ts = $snap") == 3
    assert q.count("FROM_ZONE|TO_ZONE") == 3
    assert q.count("coalesce(rb.chain, 'forward') = $chain") == 3
    # and stays inside the ordered CALL subquery
    body = q.strip()
    assert body.index(_CONTEXT_MATCH) < body.rindex("}")


def test_the_nat_queries_carry_the_context_branch_with_the_scope_guard():
    for q in (nat._NAT_RULES_QUERY_STRICT, nat._NAT_RULES_QUERY, nat._NAT_CREDITS_QUERY):
        assert q.count(_CONTEXT_MATCH) == 1, q
        assert q.count(_JOIN) == 1, q
        assert q.count("(rb:FwRulebase {kind: 'nat'})") == (3 if q == nat._NAT_CREDITS_QUERY else 4), q
    # both forms pin the context branch to the run (no coalesce run guard)
    assert "vs.collection_ts = $snap" in nat._NAT_RULES_QUERY
    assert "vs.collection_ts = $snap" in nat._NAT_RULES_QUERY_STRICT


class _Reads:
    """Records every `_read` call and answers each query with nothing."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, _session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
        self.calls.append((query, params))
        return []

    def params_of(self, query: str) -> list[dict[str, Any]]:
        return [p for q, p in self.calls if q == query]


def test_the_verdict_binds_the_ingress_interface_into_the_candidates_read(monkeypatch):
    reads = _Reads()
    monkeypatch.setattr(firewall._path, "_read", reads)
    firewall._device_rulebase_verdict(None, "dev:vsx", "if:vs1-in", "if:vs1-out", [], [], 443, "tcp", 4)
    (params,) = reads.params_of(firewall._RULEBASE_CANDIDATES)
    assert params["dev"] == "dev:vsx"
    assert params["in_if"] == "if:vs1-in"


def test_a_verdict_with_no_ingress_interface_binds_null_so_the_branch_matches_nothing(monkeypatch):
    reads = _Reads()
    monkeypatch.setattr(firewall._path, "_read", reads)
    firewall._device_rulebase_verdict(None, "dev:vsx", "", None, [], [], 443, "tcp", 4)
    (params,) = reads.params_of(firewall._RULEBASE_CANDIDATES)
    assert params["in_if"] is None


def test_the_other_chain_credit_reads_the_same_candidates_for_the_same_interface(monkeypatch):
    reads = _Reads()
    monkeypatch.setattr(firewall._path, "_read", reads)
    monkeypatch.setattr(
        firewall._path,
        "_read",
        lambda s, q, **p: [{"chain": "input"}] if q == firewall._DEVICE_CHAINS else reads(s, q, **p),
    )
    firewall._other_chain_rulebases(None, "dev:vsx", "forward", "if:vs1-in")
    (params,) = reads.params_of(firewall._RULEBASE_CANDIDATES)
    assert params == {"dev": "dev:vsx", "in_if": "if:vs1-in", "chain": "input", "strict_local": False}


def test_the_nat_readers_bind_the_ingress_interface(monkeypatch):
    reads = _Reads()
    monkeypatch.setattr(nat._path, "_read", reads)
    nat._nat_rows(None, "dev:vsx", in_if="if:vs1-in")
    nat._nat_rows(None, "dev:vsx", strict=True)
    nat.nat_rulebase_credits(None, "dev:vsx", "if:vs1-in")
    nat.nat_rulebase_credits(None, "dev:vsx")
    # the point and the strict forms are one pinned query
    assert nat._NAT_RULES_QUERY == nat._NAT_RULES_QUERY_STRICT
    assert reads.params_of(nat._NAT_RULES_QUERY) == [
        {"dev": "dev:vsx", "in_if": "if:vs1-in", "af": None},
        {"dev": "dev:vsx", "in_if": None, "af": None},
    ]
    assert reads.params_of(nat._NAT_CREDITS_QUERY) == [
        {"dev": "dev:vsx", "in_if": "if:vs1-in"},
        {"dev": "dev:vsx", "in_if": None},
    ]
