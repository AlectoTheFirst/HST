"""Bounded structural estimates over the normalized input, before BDD compilation."""

from __future__ import annotations

from hst.analysis_model.model import ModelInput


def model_preflight(source: ModelInput) -> dict:
    policies = {id(node.policy): node.policy for node in source.nodes if node.policy is not None}
    return {
        "kind": "estimate",
        "scope": "normalized model structure before native compilation",
        "normalized_nodes": len(source.nodes),
        "normalized_edges": sum(len(node.edges) for node in source.nodes),
        "entry_points": len(source.entries),
        "joint_choices": len(source.choices),
        "estimated_location_choice_pairs": len(source.nodes) * max(1, len(source.choices)),
        "policy_instances": len(policies),
        "ordered_rules": sum(len(layer.rules) for policy in policies.values() for layer in policy.layers),
        "object_definitions": sum(len(policy.objects) for policy in policies.values()),
        "incomplete_nodes": sum(not node.complete for node in source.nodes),
        "unknown_terminals": sum(node.terminal == "unknown" for node in source.nodes),
        "choices_complete": source.choices_complete,
        "native_memory_estimate_bytes": None,
        "requested_population_changed": False,
    }
