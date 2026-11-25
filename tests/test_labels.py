"""Totality checks for core/labels.py's tier collapse."""

import pytest

from hst.core.labels import (
    DEPENDENCY_GROUP_KINDS,
    FALLBACK_TIER,
    LABELS,
    RELS,
    STRATA_TIERS,
    SYNTHETIC_KIND_TIER,
    TIER_BY_KIND,
    labels_clause,
    layer_of,
    tier_of,
    validate_props,
)


def test_every_label_has_a_tier():
    missing = set(LABELS) - set(TIER_BY_KIND)
    assert missing == set()


def test_every_tier_key_is_a_label_or_a_declared_synthetic_kind():
    unexplained = set(TIER_BY_KIND) - set(LABELS)
    assert unexplained == set()


def test_tier_values_are_valid_strata_tier_indices():
    valid = set(range(len(STRATA_TIERS)))
    bad = {k: v for k, v in TIER_BY_KIND.items() if v not in valid}
    assert bad == {}
    bad_synthetic = {k: v for k, v in SYNTHETIC_KIND_TIER.items() if v not in valid}
    assert bad_synthetic == {}


def test_layer_of_known_kind_matches_labels_spec():
    assert layer_of("Device") == ("Phys",)
    assert layer_of("FhrpGroup") == ("L2", "L3")


def test_layer_of_synthetic_kind_is_empty():
    assert layer_of("NextHop") == ()


def test_tier_of_prefers_tier_by_kind():
    assert tier_of("Prefix") == TIER_BY_KIND["Prefix"]


def test_tier_of_falls_back_to_synthetic_kind_tier():
    assert tier_of("NextHop") == SYNTHETIC_KIND_TIER["NextHop"]


def test_tier_of_unknown_kind_falls_back_to_fallback_tier():
    assert tier_of("SomeVendorSpecificKindNoOneRegisteredYet") == FALLBACK_TIER


def test_l2segment_is_registered_like_l3domain():
    assert labels_clause("L2Segment") == ":Obj:L2Segment:L2"
    assert labels_clause("L3Domain") == ":Obj:L3Domain:L3"


# --- the OSPF observation objects ------------------------------------------


def test_the_ospf_labels_and_relationship_types_a_collector_emits_are_registered():
    """A label or a rel type that this test does not find needs a schema version bump."""
    for label in ("RoutingProcess", "OspfArea", "OspfAdjacency"):
        assert label in LABELS
        assert LABELS[label].layers == ("L3",)
        assert label in TIER_BY_KIND
    for rel in ("IN_AREA", "ENDPOINT", "HAS", "IN_VRF", "FILTERED_BY"):
        assert rel in RELS


# --- the declared success condition ----------------------------------------


def test_the_success_condition_labels_sit_on_the_application_layer():
    """A ServiceRequirement and the DependencyGroup tree under it state one
    application's success condition, so both are App-layer objects and both
    collapse to the application tier the answer is drawn on."""
    for label in ("ServiceRequirement", "DependencyGroup"):
        assert label in LABELS
        assert LABELS[label].layers == ("App",)
        assert TIER_BY_KIND[label] == STRATA_TIERS.index("application")
    assert labels_clause("ServiceRequirement") == ":Obj:ServiceRequirement:App"
    assert labels_clause("DependencyGroup") == ":Obj:DependencyGroup:App"


def test_a_dependency_group_must_carry_its_kind():
    assert LABELS["DependencyGroup"].requires == ("kind",)
    validate_props("DependencyGroup", {"kind": "and"})
    with pytest.raises(ValueError, match="kind"):
        validate_props("DependencyGroup", {"name": "backends"})


def test_zero_is_a_present_value_for_a_required_prop():
    """A `0.0.0.0/0` prefix-list entry carries `min_len` 0; only an absent or
    empty value is missing, never a zero."""
    validate_props(
        "PrefixListEntry", {"seq": 5, "prefix": "0.0.0.0/0", "action": "permit", "min_len": 0, "max_len": 0}
    )
    with pytest.raises(ValueError, match="min_len"):
        validate_props("PrefixListEntry", {"seq": 5, "prefix": "0.0.0.0/0", "action": "permit", "max_len": 0})
    with pytest.raises(ValueError, match="action"):
        validate_props(
            "PrefixListEntry", {"seq": 5, "prefix": "0.0.0.0/0", "action": "", "min_len": 0, "max_len": 0}
        )


def test_the_dependency_group_kinds_are_the_declared_vocabulary():
    assert {"and", "or", "threshold", "capacity"} == DEPENDENCY_GROUP_KINDS


def test_the_success_condition_reuses_relationship_types_already_registered():
    for rel in ("DEPENDS_ON", "SRC", "HAS", "HAS_MEMBER"):
        assert rel in RELS


def test_a_match_list_line_must_say_how_its_value_reads():
    validate_props(
        "MatchListEntry", {"seq": 1, "action": "permit", "match_type": "standard", "value": "65000:1"}
    )
    with pytest.raises(ValueError, match="match_type"):
        validate_props("MatchListEntry", {"seq": 1, "action": "permit", "value": "65000:1"})
    assert TIER_BY_KIND["MatchListEntry"] == TIER_BY_KIND["PrefixListEntry"]
