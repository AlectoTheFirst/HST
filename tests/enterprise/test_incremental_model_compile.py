"""Model integration retains ordered-policy work across candidate changes."""

from dataclasses import replace

from hst.analysis_model.compile import compile_model
from hst.analysis_model.model import ChoiceAssignment, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.policy.ir import Constant, ExecutionContext, Layer, Policy, Rule

from .test_assessment_symbolic_bridge import native as native


def test_policy_blocks_reuse_without_reusing_changed_decision(native):
    context = ExecutionContext("estate", "authority", "domain", "device", "vrf", 4)
    rules = tuple(Rule(f"r:{index}", Constant(False), "deny") for index in range(256))
    rules += (Rule("last", Constant(True), "permit"),)
    layer = Layer("access", rules, default="deny")
    policy = Policy(
        "package",
        "revision",
        context,
        (layer,),
        ("access",),
        (),
        installation=Constant(True),
        manifest_digest="a" * 64,
    )
    state = StateKey("destination", context)
    source = ModelInput(
        "a" * 64,
        (NodeSpec(state, terminal="permit", policy=policy),),
        (EntrySpec(state),),
        (ChoiceAssignment("only"),),
        True,
    )
    compilers, metrics = {}, {}
    before = compile_model(source, native, frozenset(), policy_compilers=compilers, metrics=metrics)
    changed_policy = replace(
        policy,
        layers=(replace(layer, rules=(*rules[:-1], replace(rules[-1], action="deny"))),),
    )
    after_source = replace(source, nodes=(replace(source.nodes[0], policy=changed_policy),))
    after = compile_model(after_source, native, frozenset(), policy_compilers=compilers, metrics=metrics)
    assert metrics["reused_blocks"] >= 1
    assert before.fingerprint != after.fingerprint
    assert not dict(before.nodes[0].terminals)["permit"].is_empty()
    assert dict(after.nodes[0].terminals)["permit"].is_empty()
