"""Reproducible native PolicyCompiler scale diagnostics."""

from __future__ import annotations

import argparse
import json
import platform
import random
import resource
import statistics
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from hst.policy.compile import CompiledPolicy, PolicyCompiler
from hst.policy.ir import (
    AllOf,
    AnyOf,
    Atom,
    Constant,
    ExecutionContext,
    Layer,
    ObjectDefinition,
    ObjectKey,
    Policy,
    Ref,
    Rule,
)
from hst.symbolic import HeaderSchema, PacketSet, SymbolicManager, header

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "enterprise" / "policy-scale.json"
DEFAULT_RULE_COUNTS = (1000,)
MIN_RULE_COUNT = 43
INLINE_LAYER_COUNT = 20
GROUP_DEPTH = 12
GROUP_BRANCHES = 10
SERVICE_OBJECT_COUNT = 16
MAX_IPV4 = (1 << 32) - 1
KNOWN_FIELDS = frozenset(HeaderSchema.ipv4().field_names)


def load_fixture(path: Path = FIXTURE) -> dict[str, Any]:
    """Load and validate the versioned scale input descriptor."""

    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("format_version") != 1:
        raise ValueError("unsupported policy scale fixture format")
    if document.get("kind") != "synthetic-policy-scale-inputs":
        raise ValueError("unexpected policy scale fixture kind")
    if not document.get("purpose", "").startswith("Synthetic math-compiler diagnostics only"):
        raise ValueError("scale fixture must state its synthetic diagnostic scope")
    return document


def _context(inputs: dict[str, Any]) -> ExecutionContext:
    values = inputs["context"]
    return ExecutionContext(**values)


def _object_key(uid: str) -> ObjectKey:
    return ObjectKey("synthetic-manager", "synthetic-domain", uid)


def _source_range(index: int, rng: random.Random) -> tuple[int, int]:
    if index == 0:
        return 100, 100
    if index <= 4:
        start = 10_000 + index * 20_000
        return start, start + 128
    # A stride smaller than the window makes the generated ranges overlap.
    start = 1000 + ((index - 1) * 257 + rng.randrange(97)) % 2_000_000
    width = 4096 + ((index - 1) * 13) % 4096
    return start, min(MAX_IPV4, start + width)


def _destination_range(index: int, rng: random.Random) -> tuple[int, int]:
    if index == 0:
        return 200, 200
    start = 1000 + ((index - 1) * 389 + rng.randrange(113)) % 2_000_000
    width = 2048 + ((index - 1) * 17) % 4096
    return start, min(MAX_IPV4, start + width)


def _service(index: int) -> tuple[int, int]:
    # The first service is the observable anchor.
    ports = (443, 8443, 80, 22, 53, 8080, 25, 3389, 123, 161, 500, 4500, 5060, 5222, 6443, 9443)
    port = ports[index % len(ports)]
    return (6 if index % 5 else 17), port


def _stats(stats: Any) -> dict[str, int]:
    return asdict(stats)


def _semantic_equal(left: CompiledPolicy, right: CompiledPolicy) -> bool:
    if not left.bounds.lower.equivalent(right.bounds.lower):
        return False
    if not left.bounds.upper.equivalent(right.bounds.upper):
        return False
    if len(left.gaps) != len(right.gaps):
        return False
    for a, b in zip(left.gaps, right.gaps, strict=True):
        if a.reason != b.reason or not a.packets.equivalent(b.packets):
            return False
    return True


def _outcome(compiled: CompiledPolicy, query: PacketSet) -> tuple[bool, bool]:
    decision = compiled.evaluate(query)
    return decision.bounds.lower.is_empty(), decision.bounds.upper.is_empty()


def generate_policy(
    rule_count: int,
    *,
    seed: int = 1209,
    fixture: dict[str, Any] | None = None,
) -> tuple[Policy, dict[str, Any]]:
    """``rule_count`` counts enabled rules across primary and inline layers."""

    if isinstance(rule_count, bool) or not isinstance(rule_count, int) or rule_count < MIN_RULE_COUNT:
        raise ValueError(f"rule_count must be an integer of at least {MIN_RULE_COUNT}")
    inputs = fixture or load_fixture()
    rng = random.Random(seed)  # noqa: S311 - reproducibility, not cryptography
    context = _context(inputs)
    inline_count = int(inputs["workload"]["inline_layer_count"])
    group_depth = int(inputs["workload"]["group_depth"])
    group_branches = int(inputs["workload"]["group_branches"])
    service_count = int(inputs["workload"]["service_object_count"])
    if inline_count != INLINE_LAYER_COUNT or group_depth != GROUP_DEPTH or group_branches != GROUP_BRANCHES:
        raise ValueError("this runner requires the fixed policy-scale workload shape")
    if service_count != SERVICE_OBJECT_COUNT:
        raise ValueError("this runner requires the fixed service-object count")

    objects: list[ObjectDefinition] = []
    rule_object_keys: list[ObjectKey] = []
    source_ranges: list[tuple[int, int]] = []
    destination_ranges: list[tuple[int, int]] = []
    services = []
    for index in range(rule_count):
        source = _source_range(index, rng)
        destination = _destination_range(index, rng)
        source_ranges.append(source)
        destination_ranges.append(destination)
        key = _object_key(f"rule-object-{index:06d}")
        rule_object_keys.append(key)
        objects.append(
            ObjectDefinition(
                key,
                "1",
                Atom("source_address", "range", source[0], source[1]),
            )
        )
    for service_index in range(service_count):
        protocol, port = _service(service_index)
        key = _object_key(f"service-{service_index:02d}")
        services.append(key)
        objects.append(
            ObjectDefinition(
                key,
                "1",
                AllOf((Atom("protocol", "eq", protocol), Atom("destination_port", "eq", port))),
            )
        )

    # Four shared roots each have twelve levels and ten references per level.
    group_roots: list[ObjectKey] = []
    group_objects = 0
    membership_edges = 0
    for bucket in range(4):
        previous: list[ObjectKey] = []
        for depth in range(group_depth):
            current: list[ObjectKey] = []
            for branch in range(group_branches):
                key = _object_key(f"group-{bucket:02d}-d{depth:02d}-b{branch:02d}")
                if depth == 0:
                    low = 0 if bucket == 0 else 500 + bucket * 1000 + branch * 257
                    high = MAX_IPV4 if bucket == 0 else min(MAX_IPV4, low + 2_000_000)
                    predicate = Atom("source_address", "range", low, high)
                else:
                    # The child order rotates by a seed-derived branch offset.
                    offset = (seed + bucket + depth + branch) % group_branches
                    refs = tuple(
                        Ref(previous[(offset + item) % group_branches]) for item in range(group_branches)
                    )
                    predicate = AnyOf(refs)
                    membership_edges += len(refs)
                objects.append(ObjectDefinition(key, "1", predicate))
                current.append(key)
                group_objects += 1
            previous = current
        group_roots.append(previous[0])

    regular_count = rule_count - inline_count - inline_count
    if regular_count < 3:
        raise ValueError("rule_count leaves too few primary rules")
    call_rules = tuple(
        Rule(
            f"inline-call-{index:02d}",
            Atom("dscp", "eq", index),
            "call",
            called_layer=f"inline-{index:02d}",
            source_position=(index,),
        )
        for index in range(inline_count)
    )
    inline_layers = tuple(
        Layer(
            f"inline-{index:02d}",
            (
                Rule(
                    f"inline-rule-{index:02d}",
                    AllOf(
                        (
                            Ref(rule_object_keys[rule_count - inline_count + index]),
                            Atom("ecn", "eq", index % 4),
                        )
                    ),
                    "permit",
                    source_position=(index,),
                ),
            ),
            "return",
        )
        for index in range(inline_count)
    )

    regular_rules: list[Rule] = []
    for index in range(regular_count):
        source_index = index
        protocol, _port = _service(index)
        service_key = services[index % service_count]
        predicate = AllOf(
            (
                Ref(rule_object_keys[source_index]),
                Ref(group_roots[index % len(group_roots)]),
                Ref(service_key),
                Atom(
                    "destination_address",
                    "range",
                    destination_ranges[source_index][0],
                    destination_ranges[source_index][1],
                ),
                Atom("protocol", "eq", protocol),
            )
        )
        regular_rules.append(
            Rule(
                f"rule-{index:06d}",
                predicate,
                "permit" if index in {0, 4} or index % 5 else "deny",
                source_position=(index,),
            )
        )
    regular_rules.extend(call_rules)
    primary_layers: list[Layer] = []
    cursor = 0
    primary_rule_count = len(regular_rules)
    for layer_index in range(3):
        take = primary_rule_count // 3 + (1 if layer_index < primary_rule_count % 3 else 0)
        primary_layers.append(
            Layer(
                f"primary-{layer_index}",
                tuple(regular_rules[cursor : cursor + take]),
                "deny" if layer_index == 0 else "permit",
            )
        )
        cursor += take
    layers = tuple(primary_layers) + inline_layers
    policy = Policy(
        "synthetic-policy",
        f"seed-{seed}-rules-{rule_count}",
        context,
        layers,
        tuple(layer.uid for layer in primary_layers),
        tuple(objects),
        installation=Constant(True),
        configured_revision=f"configured-{seed}",
        installed_revision=f"installed-{seed}",
    )
    metadata = {
        "seed": seed,
        "rule_count": rule_count,
        "source_ranges": tuple(source_ranges),
        "destination_ranges": tuple(destination_ranges),
        "service_ports": tuple(_service(index)[1] for index in range(rule_count)),
        "service_protocols": tuple(_service(index)[0] for index in range(rule_count)),
        "rule_object_keys": tuple(rule_object_keys),
        "group_roots": tuple(group_roots),
        "object_counts": {
            "definitions": len(objects),
            "rule_objects": rule_count,
            "service_objects": service_count,
            "group_objects": group_objects,
            "membership_edges": membership_edges,
        },
        "layer_counts": {
            "ordered": len(primary_layers),
            "inline": len(inline_layers),
            "enabled_rules": sum(len(layer.rules) for layer in layers),
        },
    }
    return policy, metadata


def _query(
    manager: SymbolicManager, metadata: dict[str, Any], index: int, *, source: int | None = None
) -> PacketSet:
    source_low, source_high = metadata["source_ranges"][index]
    destination_low, destination_high = metadata["destination_ranges"][index]
    source_value = source if source is not None else source_low + (source_high - source_low) // 2
    destination_value = destination_low + (destination_high - destination_low) // 2
    return header(
        manager,
        {
            "protocol": metadata["service_protocols"][index],
            "fragment_offset": 0,
            "source_address": source_value,
            "destination_address": destination_value,
            "destination_port": metadata["service_ports"][index],
            "dscp": 63,
            "ecn": index % 4,
            "tcp_flags": 0,
            "icmp_type": 0,
            "icmp_code": 0,
            "more_fragments": 0,
        },
        explicitly_all=KNOWN_FIELDS,
    )


def _warm_queries(manager: SymbolicManager, metadata: dict[str, Any], count: int) -> tuple[PacketSet, ...]:
    return tuple(_query(manager, metadata, index % metadata["rule_count"]) for index in range(count))


def _rss() -> dict[str, int | str]:
    platform_units = "bytes" if sys.platform == "darwin" else "kilobytes"
    return {
        "value": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        "platform_units": platform_units,
    }


def _distinct_packet_sets(packet_sets: tuple[PacketSet, ...]) -> int:
    representatives: list[PacketSet] = []
    for packet_set in packet_sets:
        if not any(packet_set.equivalent(existing) for existing in representatives):
            representatives.append(packet_set)
    return len(representatives)


def _edit_policy_rule(policy: Policy) -> Policy:
    layer = policy.layers[0]
    rules = list(layer.rules)
    anchor = next(index for index, rule in enumerate(rules) if rule.uid == "rule-000000")
    rules[anchor] = replace(rules[anchor], action="deny", evidence=("synthetic-observable-rule-edit",))
    edited_layer = replace(layer, rules=tuple(rules))
    return replace(policy, revision=f"{policy.revision}-rule-edit", layers=(edited_layer, *policy.layers[1:]))


def _edit_policy_object(policy: Policy, metadata: dict[str, Any]) -> Policy:
    # Object 4 is a permit rule in the first primary layer. The high source
    # probe is outside every generated range but remains in shared group 0.
    key = metadata["rule_object_keys"][4]
    objects = list(policy.objects)
    object_index = next(index for index, item in enumerate(objects) if item.key == key)
    objects[object_index] = replace(
        objects[object_index],
        revision="2",
        predicate=Atom("source_address", "eq", MAX_IPV4 - 100),
    )
    return replace(policy, revision=f"{policy.revision}-object-edit", objects=tuple(objects))


def _run_one(rule_count: int, seed: int, inputs: dict[str, Any]) -> dict[str, Any]:
    before_rss = _rss()
    policy, metadata = generate_policy(rule_count, seed=seed, fixture=inputs)
    schema = HeaderSchema.ipv4()
    with SymbolicManager(schema) as manager:
        source_query = _query(manager, metadata, 0, source=100)
        compiler = PolicyCompiler(manager, policy.context, source_query.known_fields)
        start = time.perf_counter()
        cpu_start = time.process_time()
        compiled = compiler.compile(policy)
        cold_elapsed = time.perf_counter() - start
        cold_cpu = time.process_time() - cpu_start
        warmup_count = int(inputs["warmup_count"])
        warm_query_count = int(inputs["warm_query_count"])
        warm_queries = _warm_queries(manager, metadata, warmup_count + warm_query_count)
        for query in warm_queries[:warmup_count]:
            compiled.evaluate(query)
        warm_samples: list[float] = []
        warm_cpu_samples: list[float] = []
        for query in warm_queries[warmup_count:]:
            tick = time.perf_counter()
            cpu_tick = time.process_time()
            compiled.evaluate(query)
            warm_samples.append(time.perf_counter() - tick)
            warm_cpu_samples.append(time.process_time() - cpu_tick)

        original_outcome = _outcome(compiled, source_query)
        edited_rule = _edit_policy_rule(policy)
        tick = time.perf_counter()
        incremental_rule = compiler.compile(edited_rule)
        incremental_rule_elapsed = time.perf_counter() - tick
        cold_rule_compiler = PolicyCompiler(manager, policy.context, source_query.known_fields)
        tick = time.perf_counter()
        cold_rule = cold_rule_compiler.compile(edited_rule)
        cold_rule_elapsed = time.perf_counter() - tick
        rule_outcome = _outcome(incremental_rule, source_query)

        object_compiler = PolicyCompiler(manager, policy.context, source_query.known_fields)
        object_compiler.compile(policy)
        edited_object = _edit_policy_object(policy, metadata)
        object_query = _query(manager, metadata, 4, source=MAX_IPV4 - 100)
        tick = time.perf_counter()
        incremental_object = object_compiler.compile(edited_object)
        incremental_object_elapsed = time.perf_counter() - tick
        cold_object_compiler = PolicyCompiler(manager, policy.context, source_query.known_fields)
        tick = time.perf_counter()
        cold_object = cold_object_compiler.compile(edited_object)
        cold_object_elapsed = time.perf_counter() - tick
        object_before = _outcome(object_compiler.compile(policy), object_query)
        object_after = _outcome(incremental_object, object_query)
        manager.collect_garbage()

        source_query_cardinality = source_query.cardinality(("source_address",))
        source_projection = {
            "lower": compiled.bounds.lower.cardinality(("source_address",)),
            "upper": compiled.bounds.upper.cardinality(("source_address",)),
        }
        rule_edit_equal = _semantic_equal(incremental_rule, cold_rule)
        rule_edit_changed = original_outcome != rule_outcome
        object_edit_equal = _semantic_equal(incremental_object, cold_object)
        object_edit_changed = object_before != object_after
        if not rule_edit_equal or not rule_edit_changed:
            raise RuntimeError("rule edit failed semantic equality or observable-query checks")
        if not object_edit_equal or not object_edit_changed:
            raise RuntimeError("object edit failed semantic equality or observable-query checks")
        backend = {
            "name": manager.capabilities.backend,
            "version": manager.capabilities.backend_version,
            "schema_version": manager.capabilities.schema_version,
            "ordering_version": manager.capabilities.ordering_version,
        }
        result = {
            "rule_count": rule_count,
            "seed": seed,
            "probe_source_cardinality": source_query_cardinality,
            "compiled_source_projection_cardinality": source_projection,
            "object_counts": metadata["object_counts"],
            "layer_counts": metadata["layer_counts"],
            "backend": backend,
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "peak_rss": _rss(),
            "rss_scope": "process-lifetime peak; includes all runs in this process",
            "coldcompile": {
                "elapsed_seconds": cold_elapsed,
                "cpu_seconds": cold_cpu,
                "stats": _stats(compiled.stats),
                "outcome": {"lower_empty": original_outcome[0], "upper_empty": original_outcome[1]},
            },
            "warm_evaluations": {
                "requested_count": warm_query_count,
                "warmup_count": warmup_count,
                "measured_count": len(warm_samples),
                "elapsed_seconds": sum(warm_samples),
                "cpu_seconds": sum(warm_cpu_samples),
                "p50_seconds": statistics.median(warm_samples),
                "p95_seconds": sorted(warm_samples)[max(0, int(len(warm_samples) * 0.95) - 1)],
                "max_seconds": max(warm_samples),
                "differing_requests": _distinct_packet_sets(tuple(warm_queries[warmup_count:])),
            },
            "rule_edit": {
                "incremental_elapsed_seconds": incremental_rule_elapsed,
                "cold_elapsed_seconds": cold_rule_elapsed,
                "semantic_incremental_equals_cold": rule_edit_equal,
                "observable_query_changed": rule_edit_changed,
                "incremental_stats": _stats(incremental_rule.stats),
                "cold_stats": _stats(cold_rule.stats),
            },
            "object_edit": {
                "incremental_elapsed_seconds": incremental_object_elapsed,
                "cold_elapsed_seconds": cold_object_elapsed,
                "semantic_incremental_equals_cold": object_edit_equal,
                "observable_query_changed": object_edit_changed,
                "incremental_stats": _stats(incremental_object.stats),
                "cold_stats": _stats(cold_object.stats),
            },
        }
    result["peak_rss"] = _rss() if result["peak_rss"]["value"] < before_rss["value"] else result["peak_rss"]
    return result


def run(rule_counts: tuple[int, ...] = DEFAULT_RULE_COUNTS, *, seed: int | None = None) -> dict[str, Any]:
    inputs = load_fixture()
    selected_seed = int(inputs["seed"] if seed is None else seed)
    if not rule_counts:
        raise ValueError("at least one rule count is required")
    return {
        "schema_version": 1,
        "report_kind": "synthetic_math_compiler_diagnostics",
        "profile": "synthetic_policy_compiler_scale_subset",
        "qualification_scope": "synthetic math-compiler diagnostics only; not whole-enterprise qualification",
        "backend": "dd.cudd",
        "fixture": {
            "path": str(FIXTURE.relative_to(ROOT)),
            "seed": selected_seed,
            "rule_counts": list(rule_counts),
            "warmup_count": inputs["warmup_count"],
            "warm_query_count": inputs["warm_query_count"],
        },
        "runs": [_run_one(count, selected_seed, inputs) for count in rule_counts],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rules", type=int, nargs="+", default=list(DEFAULT_RULE_COUNTS), help="rule counts to run"
    )
    parser.add_argument("--seed", type=int, default=None, help="override the fixture's primary seed")
    parser.add_argument("--output", type=Path, default=None, help="write JSON to this path (default: stdout)")
    args = parser.parse_args(argv)
    try:
        report = run(tuple(args.rules), seed=args.seed)
    except Exception as exc:  # a native backend failure exits with status 2
        parser.exit(2, f"benchmark unavailable or invalid: {exc}\n")
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(payload)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
