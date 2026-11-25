"""Independent finite checks for the symbolic contracts."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).parents[2]


def _load(name: str) -> dict:
    return json.loads((ROOT / "fixtures" / "enterprise" / name).read_text())


def _case(contract: dict, case_id: str) -> dict:
    return next(case for case in contract["cases"] if case["id"] == case_id)


def _first_match(case: dict) -> dict:
    universe = set(case["universe"])
    earlier_must: set[str] = set()
    earlier_may: set[str] = set()
    rule_must: dict[str, set[str]] = {}
    rule_may: dict[str, set[str]] = {}
    for rule in case["rules"]:
        must = set(rule["must"]) & universe
        may = set(rule["may"]) & universe
        assert must <= may
        first_must = must - earlier_may
        first_may = may - earlier_must
        rule_must[rule["uid"]] = first_must
        rule_may[rule["uid"]] = first_may
        earlier_must |= must
        earlier_may |= may
    return {
        "rule_must": rule_must,
        "rule_may": rule_may,
    }


def _terminal(universe: set[str], action: str, outcome: str) -> tuple[set[str], set[str]]:
    return (set(universe), set(universe)) if action == outcome else (set(), set())


def _conditional(
    universe: set[str],
    predicate: tuple[set[str], set[str]],
    match: tuple[set[str], set[str]],
    miss: tuple[set[str], set[str]],
) -> tuple[set[str], set[str]]:
    must, may = predicate
    definite_match = must
    definite_miss = universe - may
    undecided = may - must
    lower = definite_match & match[0] | definite_miss & miss[0] | undecided & match[0] & miss[0]
    upper = definite_match & match[1] | definite_miss & miss[1] | undecided & (match[1] | miss[1])
    return lower, upper


def _action_bounds(case: dict, outcome: str) -> tuple[set[str], set[str]]:
    universe = set(case["universe"])
    result = _terminal(universe, case["default_action"], outcome)
    for rule in reversed(case["rules"]):
        predicate = set(rule["must"]), set(rule["may"])
        match = _terminal(universe, rule["action"], outcome)
        result = _conditional(universe, predicate, match, result)
    return result


def _sorted_map(values: dict[str, set[str]]) -> dict[str, list[str]]:
    return {key: sorted(value) for key, value in values.items()}


def test_fixture_versions_and_contract_terms() -> None:
    contract = _load("contracts.json")
    profiles = _load("profiles.json")
    assert contract["contract_version"] == "1.0"
    assert contract["schema_version"] == "2"
    assert contract["header_schema_version"] == "1"
    assert contract["result_schema_version"] == "2"
    assert contract["semantic_version"] == "symbolic-v2"
    assert contract["ordering_version"] == "1"
    assert profiles["profile_version"] == "1.0"
    assert profiles["measurement_status"] == "requirements_only_no_measured_claim"
    assert profiles["backend"]["header_schema_version"] == "1"
    assert profiles["backend"]["result_schema_version"] == "2"
    assert profiles["backend"]["semantic_version"] == "symbolic-v2"
    assert profiles["backend"]["ordering_version"] == "1"
    assert "A01-A23" in profiles["workloads"]["P0-conformance"]["shape"]
    assert "A24" in profiles["workloads"]["P0-conformance"]["shape"]
    assert set(contract["semantics"]["unknown_codes"]) == {
        "UNSTATED_DIMENSION",
        "UNSUPPORTED_PREDICATE",
        "INCOMPLETE_EVIDENCE",
        "RESOURCE_CUTOFF",
        "CHOICE_CORRELATION",
    }
    client_aggregation = contract["semantics"]["client_aggregation"]
    assert client_aggregation["holds_equation"] == (
        "holds = sources minus projection_client(requests minus lower)"
    )
    assert client_aggregation["open_equation"] == (
        "open = sources minus projection_client(requests minus upper)"
    )


def test_malformed_contexts_and_incomplete_results_are_rejected() -> None:
    semantics = _load("contracts.json")["semantics"]
    context = semantics["execution_context"]
    pattern = re.compile(context["identity_pattern"])

    def valid_context(value: dict) -> bool:
        return (
            set(value) == set(context["fields"])
            and all(
                isinstance(value[field], str) and pattern.fullmatch(value[field])
                for field in context["fields"][:-1]
            )
            and value["address_family"] in context["address_family_values"]
        )

    assert valid_context(context["valid_example"])
    assert all(not valid_context(example) for example in context["invalid_examples"])
    required = set(semantics["result_serialization"]["required_fields"])
    assert all(
        not required <= set(example) for example in semantics["result_serialization"]["invalid_examples"]
    )


def test_firstmatch_bounds_are_independently_recomputed() -> None:
    case = _case(_load("contracts.json"), "A01-firstmatch-bounds")
    result = _first_match(case)
    expected = case["expected"]
    assert _sorted_map(result["rule_must"]) == expected["rule_must"]
    assert _sorted_map(result["rule_may"]) == expected["rule_may"]
    assert sorted(_action_bounds(case, "permit")[0]) == expected["action_must"]["permit"]
    assert sorted(_action_bounds(case, "permit")[1]) == expected["action_may"]["permit"]
    assert sorted(_action_bounds(case, "deny")[0]) == expected["action_must"]["deny"]
    assert sorted(_action_bounds(case, "deny")[1]) == expected["action_may"]["deny"]


def test_unknown_rule_can_retain_same_outcome_proof() -> None:
    case = _case(_load("contracts.json"), "A04-same-outcome-unknown")
    attribution = _first_match(case)
    assert sorted(attribution["rule_must"]["unknown-permit"]) == case["expected"]["rule_attribution_must"]
    assert sorted(attribution["rule_may"]["unknown-permit"]) == case["expected"]["rule_attribution_may"]
    assert sorted(_action_bounds(case, "permit")[0]) == case["expected"]["permit_must"]
    assert sorted(_action_bounds(case, "permit")[1]) == case["expected"]["permit_may"]
    assert sorted(_action_bounds(case, "deny")[0]) == case["expected"]["deny_must"]
    assert sorted(_action_bounds(case, "deny")[1]) == case["expected"]["deny_may"]


def test_known_world_keeps_unstated_distinct_from_explicit_values() -> None:
    cases = {case["id"]: case for case in _load("contracts.json")["cases"]}
    case = cases["A02-known-world-and-dimensions"]
    for request in case["requests"]:
        expected = case["expected"][request["request_id"]]
        values = request["known"].get(request["predicate_requires"])
        if values is None:
            result = {"must": False, "may": True, "unknown_code": "UNSTATED_DIMENSION"}
        elif isinstance(values, list):
            matches = set(values) & set(request["predicate_values"])
            result = {"must": matches == set(values), "may": bool(matches), "unknown_code": None}
            result["partition"] = {"match": sorted(matches), "non_match": sorted(set(values) - matches)}
        else:
            matches = values in request["predicate_values"]
            result = {"must": matches, "may": matches, "unknown_code": None}
        assert result == expected


def test_masks_service_conjunction_negation_and_ipv6_high_bits() -> None:
    case = _case(_load("contracts.json"), "A03-masks-services-ipv6")
    mask = case["noncontiguous_mask"]
    width_mask = (1 << mask["width"]) - 1
    wildcard = int(mask["wildcard"], 16)
    base = int(mask["base"], 16)
    mask_matches = {
        request["request_id"]
        for request in case["address_requests"]
        if request["address_family"] == "ipv4"
        and ((int(request["source_bits"], 16) ^ base) & (width_mask ^ wildcard)) == 0
    }
    ipv6 = case["ipv6_high_bits"]
    prefix_length = ipv6["prefix_length"]
    prefix_mask = ((1 << 64) - 1) ^ ((1 << (64 - prefix_length)) - 1)
    ipv6_matches = {
        request["request_id"]
        for request in case["address_requests"]
        if request["address_family"] == "ipv6"
        and (int(request["source_high_64"], 16) & prefix_mask) == (int(ipv6["prefix"], 16) & prefix_mask)
    }
    service = case["service_predicate"]
    service_matches = {
        request["request_id"]
        for request in case["service_requests"]
        if request["protocol"] == service["protocol"]
        and request["destination_port"] in service["destination_ports"]
        and request["source_group"] != service["source_group_not"]
    }
    expected = case["expected"]
    assert sorted(mask_matches) == expected["noncontiguous_matches"]
    assert sorted(ipv6_matches) == expected["ipv6_high_bit_matches"]
    assert sorted(service_matches) == expected["service_and_negation_matches"]


def test_policy_changes_invalidate_their_independent_dependencies() -> None:
    case = _case(_load("contracts.json"), "A06-policy-invalidation")
    rules = case["rules"]
    by_uid = {rule["uid"]: rule for rule in rules}
    for change in case["changes"]:
        if change["kind"] == "object_edit":
            invalidated = {rule["uid"] for rule in rules if change["object"] in rule["objects"]}
        elif change["kind"] in {"enabled_edit", "install_on_edit"}:
            invalidated = {change["rule"]}
            if change["kind"] == "enabled_edit":
                assert by_uid[change["rule"]]["enabled"] is True
        elif change["kind"] == "position_edit":
            positions = {change["old_position"], change["new_position"]}
            invalidated = {rule["uid"] for rule in rules if rule["position"] in positions}
        else:
            raise AssertionError(f"unhandled change kind: {change['kind']}")
        assert sorted(invalidated) == change["expected_invalidated"]


def test_layered_policy_and_evidence_bounds() -> None:
    contract = _load("contracts.json")
    layered = _case(contract, "A04-layered-firstmatch")
    universe = {"web", "admin", "db", "unknown"}
    inline = layered["layers"][1]["steps"]
    permit_must = set(inline[0]["must"]) & universe
    permit_may = set(inline[0]["may"]) | set(inline[1]["may"])
    assert sorted(permit_must) == layered["expected"]["permit_must"]
    assert sorted(permit_may) == layered["expected"]["permit_may"]
    assert sorted(universe - permit_may) == layered["expected"]["deny_must"]
    assert sorted(universe - permit_must) == layered["expected"]["deny_may"]
    evidence = _case(contract, "A05-incomplete-evidence")
    predicate = evidence["predicate"]
    assert set(predicate["must"]) <= set(predicate["may"]) <= set(predicate["known_scope"])
    assert sorted(predicate["must"]) == evidence["expected"]["must"]
    assert sorted(predicate["may"]) == evidence["expected"]["may"]
    assert predicate["gap"] in evidence["expected"]["gap_codes"]


def test_nat_preserves_original_current_pairs_and_choice_scope() -> None:
    case = _case(_load("contracts.json"), "A08-nat-original-current")
    policy = set(case["current_policy_match"])
    by_original: dict[str, list[dict]] = {request: [] for request in case["original_requests"]}
    for pair in case["pairs"]:
        by_original[pair["original"]].append(pair)
    possible = {
        original
        for original, pairs in by_original.items()
        if any(pair["current"] in policy for pair in pairs)
    }
    guaranteed = {
        original
        for original, pairs in by_original.items()
        if pairs and all(pair["current"] in policy for pair in pairs)
    }
    image = {original: sorted(pair["current"] for pair in pairs) for original, pairs in by_original.items()}
    expected = case["expected"]
    assert sorted(possible) == expected["possible_original"]
    assert sorted(guaranteed) == expected["guaranteed_original"]
    assert image == expected["image"]
    assert {pair["choice_id"] for pair in by_original["o1"]} == {"pool-a", "pool-b"}
    assert {pair["choice_id"] for pair in by_original["o2"]} == {"pool-a", "pool-b"}
    assert {pair["choice_id"] for pair in case["pairs"] if pair["choice_scope"] == "nat-pool"} == {
        "pool-a",
        "pool-b",
    }


def test_correlated_choices_use_complete_tuples() -> None:
    case = _case(_load("contracts.json"), "A11-correlated-choices")
    outcomes = {request: [] for request in case["requests"]}
    for choice in case["choices"]:
        for request, outcome in choice["outcomes"].items():
            outcomes[request].append(outcome)
    possible = sorted(
        request for request, values in outcomes.items() if any(value == "permit" for value in values)
    )
    guaranteed = sorted(
        request
        for request, values in outcomes.items()
        if values and all(value == "permit" for value in values)
    )
    assert possible == case["expected"]["possible_success"]
    assert guaranteed == case["expected"]["guaranteed_success"]
    unspecified_lower = sorted(
        request
        for request, values in outcomes.items()
        if values and all(value == "permit" for value in values)
    )
    unspecified_upper = sorted(
        request for request, values in outcomes.items() if any(value == "permit" for value in values)
    )
    assert unspecified_lower == case["expected"]["unspecified_lower_success"]
    assert unspecified_upper == case["expected"]["unspecified_upper_success"]
    assert set(case["expected"]["incorrect_marginal_cross_product_would_claim"]) == (
        set(possible) - set(guaranteed)
    )


def test_world_completions_and_choices_have_separate_quantifiers() -> None:
    case = _case(_load("contracts.json"), "A11-worlds-and-choices")
    per_world_possible: dict[str, list[str]] = {}
    per_world_guaranteed: dict[str, list[str]] = {}
    for world in case["worlds"]:
        outcomes = [set(choice["success"]) for choice in world["choices"]]
        per_world_possible[world["world_id"]] = sorted(set().union(*outcomes))
        per_world_guaranteed[world["world_id"]] = sorted(set.intersection(*outcomes))
    assert per_world_possible == case["expected"]["per_world_possible"]
    assert per_world_guaranteed == case["expected"]["per_world_guaranteed"]
    possible_intersection = set.intersection(*(set(values) for values in per_world_possible.values()))
    possible_union = set().union(*(set(values) for values in per_world_possible.values()))
    guaranteed_intersection = set.intersection(*(set(values) for values in per_world_guaranteed.values()))
    guaranteed_union = set().union(*(set(values) for values in per_world_guaranteed.values()))
    expected_modes = case["expected"]["selected_mode_bounds"]
    assert sorted(possible_intersection) == expected_modes["possible"]["lower"]
    assert sorted(possible_union) == expected_modes["possible"]["upper"]
    assert sorted(guaranteed_intersection) == expected_modes["guaranteed"]["lower"]
    assert sorted(guaranteed_union) == expected_modes["guaranteed"]["upper"]
    assert guaranteed_intersection != possible_intersection


def _client_sets(case: dict) -> tuple[set[str], set[str], set[str], dict[str, set[str]]]:
    requested: dict[str, set[str]] = {}
    for request in case["requests"]:
        requested.setdefault(request["client"], set()).add(request["request_id"])
    sources = set(requested)
    all_requests = {request_id for ids in requested.values() for request_id in ids}
    lower = set(case["lower"])
    upper = set(case["upper"])
    client_of = {request["request_id"]: request["client"] for request in case["requests"]}
    # Exact contract equations: Sources minus projection(Requests minus bound).
    holds = sources - {client_of[request_id] for request_id in all_requests - lower}
    open_clients = sources - {client_of[request_id] for request_id in all_requests - upper}
    return open_clients, holds, open_clients - holds, requested


def test_client_universal_aggregation_uses_projection_difference() -> None:
    contract = _load("contracts.json")
    for case_id in ("A21-client-universal", "A21-client-universal-unknown"):
        case = _case(contract, case_id)
        assert case["selected_mode"] == "possible"
        open_clients, holds, unknown, requested = _client_sets(case)
        expected = case["expected"]
        assert sorted(open_clients) == expected["open_clients"]
        assert sorted(holds) == expected["holds_clients"]
        assert sorted(unknown) == expected["unknown_clients"]
        expected_dedup = expected.get("deduplicated_request_ids")
        if expected_dedup is not None:
            assert {client: sorted(ids) for client, ids in requested.items()} == expected_dedup


def test_profile_timing_requirements_state_targets_and_no_percentile_claim() -> None:
    profiles = _load("profiles.json")
    timing = profiles["timing_requirements"]
    assert timing["collection"]["target_seconds"] == 300
    assert timing["collection"]["alternative_seconds"] == 600
    assert timing["existing_graph_rib_path_queries"]["target_seconds_exclusive"] == 5
    assert timing["simulations_and_assessments"]["timing"] == "may_take_minutes"
    assert timing["simulations_and_assessments"]["fixed_limit"] is None
    assert all("p95" not in json.dumps(profile) for profile in profiles["workloads"].values())
