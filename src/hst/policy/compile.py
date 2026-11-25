from __future__ import annotations

from dataclasses import dataclass, field

from hst.symbolic import PacketSet, SymbolicManager

from .bounds import Bounds, conditional
from .ir import AllOf, Constant, ExecutionContext, Layer, ObjectKey, Policy, Rule, Unknown
from .predicates import CompiledPredicate, PredicateCompiler


@dataclass(frozen=True, slots=True)
class ScopedGap:
    reason: Unknown
    packets: PacketSet


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    bounds: Bounds[PacketSet]
    gaps: tuple[ScopedGap, ...]


@dataclass(frozen=True, slots=True)
class CompileStats:
    compiled_blocks: int
    reused_blocks: int
    recomposed_nodes: int
    compiled_objects: int
    reused_objects: int


@dataclass(frozen=True, slots=True)
class _Flow:
    permit: PacketSet
    deny: PacketSet
    returns: PacketSet
    next: PacketSet

    def then(self, other: _Flow) -> _Flow:
        return _Flow(
            self.permit.union(self.next.intersect(other.permit)),
            self.deny.union(self.next.intersect(other.deny)),
            self.returns.union(self.next.intersect(other.returns)),
            self.next.intersect(other.next),
        )


@dataclass(frozen=True, slots=True, eq=False)
class _Block:
    rules: tuple[Rule, ...]
    matches: tuple[CompiledPredicate, ...]
    steps: tuple[_Flow, ...]
    flow: _Flow
    gaps: tuple[ScopedGap, ...]
    dependencies: frozenset[ObjectKey]
    calls: tuple[_CompiledLayer | None, ...]


@dataclass(frozen=True, slots=True, eq=False)
class _Tree:
    flow: _Flow
    gaps: tuple[ScopedGap, ...]
    left: _Tree | None = None
    right: _Tree | None = None
    block: _Block | None = None


@dataclass(frozen=True, slots=True, eq=False)
class _CompiledLayer:
    uid: str
    default: str
    tree: _Tree
    flow: _Flow
    gaps: tuple[ScopedGap, ...]


@dataclass(frozen=True, slots=True)
class RuleAttribution:
    """Bounds on reaching and matching this rule."""

    layer_uid: str
    rule_uid: str
    bounds: Bounds[PacketSet]
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    policy: Policy
    known_fields: frozenset[str]
    bounds: Bounds[PacketSet]
    gaps: tuple[ScopedGap, ...]
    stats: CompileStats
    _layers: tuple[_CompiledLayer, ...] = field(repr=False)

    def evaluate(self, request: PacketSet) -> PolicyDecision:
        universe = self.bounds.universe
        universe.manager._assert_sets(request)
        if request.known_fields != self.known_fields:
            raise ValueError("compiled policy and request knowledge masks differ")
        if not request.subtract(universe).is_empty():
            raise ValueError("request contains values outside the compiled header universe")
        bounds = Bounds(request, request.intersect(self.bounds.lower), request.intersect(self.bounds.upper))
        undecided = bounds.upper.subtract(bounds.lower)
        gaps = tuple(
            ScopedGap(gap.reason, scope)
            for gap in self.gaps
            if not (scope := gap.packets.intersect(undecided)).is_empty()
        )
        return PolicyDecision(bounds, gaps)

    def explain_rule(self, layer_uid: str, rule_uid: str) -> RuleAttribution:
        """Local layer attribution, generated on demand without packet expansion.

        Call-site and preceding ordered-layer reachability must be applied by the
        consumer. A shared inline layer can have more than one call site.
        """
        universe = self.bounds.universe
        empty = universe.subtract(universe)
        prefix = _Flow(empty, empty, empty, universe)
        layer = next((layer for layer in self._layers if layer.uid == layer_uid), None)
        if layer is None:
            raise KeyError(layer_uid)
        pending = [layer.tree]
        while pending:
            tree = pending.pop()
            if tree.block is None:
                if tree.right is not None:
                    pending.append(tree.right)
                if tree.left is not None:
                    pending.append(tree.left)
                continue
            block = tree.block
            if not any(rule.uid == rule_uid for rule in block.rules):
                prefix = prefix.then(block.flow)
                continue
            for rule, match, step in zip(block.rules, block.matches, block.steps, strict=True):
                if rule.uid == rule_uid:
                    must_reach = universe.subtract(prefix.permit.union(prefix.deny).union(prefix.returns))
                    return RuleAttribution(
                        layer_uid,
                        rule_uid,
                        Bounds(
                            universe,
                            must_reach.intersect(match.bounds.lower),
                            prefix.next.intersect(match.bounds.upper),
                        ),
                        rule.evidence,
                    )
                prefix = prefix.then(step)
        raise KeyError((layer_uid, rule_uid))


class PolicyCompiler:
    """Incrementally compile one qualified execution context and knowledge mask.

    Ordered layers require permit from every layer. Inline permit/deny terminates
    the containing layer. Inline return resumes after the call. Top-level return
    is unresolved and cannot establish a permit or deny. Source adapters must
    translate their documented vendor semantics into these explicit operations.
    """

    BLOCK_SIZE = 256

    def __init__(self, manager: SymbolicManager, context: ExecutionContext, known_fields: frozenset[str]):
        if context.address_family != manager.schema.address_family:
            raise ValueError("policy context and manager families differ")
        self.context = context
        self.predicates = PredicateCompiler(manager, known_fields)
        self.universe = self.predicates.universe
        self.empty = manager.empty()
        self._blocks: dict[tuple[str, int], _Block] = {}
        self._trees: dict[tuple[str, int, int], _Tree] = {}
        self._layers: dict[str, _CompiledLayer] = {}
        self._active: dict[str, _CompiledLayer] = {}
        self._definitions: dict[str, Layer] = {}
        self._dirty: frozenset[ObjectKey] = frozenset()
        self._used_blocks: set[tuple[str, int]] = set()
        self._used_trees: set[tuple[str, int, int]] = set()
        self._compiled_blocks = self._reused_blocks = self._recomposed = 0

    def _identity(self) -> _Flow:
        return _Flow(self.empty, self.empty, self.empty, self.universe)

    def _terminal(self, action: str) -> _Flow:
        if action == "unknown":
            return _Flow(self.universe, self.universe, self.universe, self.empty)
        return _Flow(
            self.universe if action == "permit" else self.empty,
            self.universe if action == "deny" else self.empty,
            self.universe if action == "return" else self.empty,
            self.empty,
        )

    def compile(self, policy: Policy) -> CompiledPolicy:
        self.universe.manager._ensure_open()
        if policy.context != self.context:
            raise ValueError("policy belongs to a different qualified execution context")
        if policy.semantic_profile != "explicit-filter-v1":
            raise ValueError("unsupported semantic profile; normalize vendor behavior explicitly")
        self._dirty = self.predicates.update(policy.objects)
        self._definitions = {layer.uid: layer for layer in policy.layers}
        self._active = {}
        self._used_blocks = set()
        self._used_trees = set()
        self._compiled_blocks = self._reused_blocks = self._recomposed = 0
        result = Bounds.terminal(self.universe, "permit")
        gaps: list[ScopedGap] = []
        for uid in policy.ordered_layers:
            layer = self._layer(uid, ())
            success = Bounds(
                self.universe,
                self.universe.subtract(layer.flow.deny.union(layer.flow.returns)),
                layer.flow.permit.union(layer.flow.returns),
            )
            gaps.extend(ScopedGap(gap.reason, gap.packets.intersect(result.upper)) for gap in layer.gaps)
            if not layer.flow.returns.is_empty():
                gaps.append(
                    ScopedGap(Unknown("TOP_LEVEL_RETURN", uid), layer.flow.returns.intersect(result.upper))
                )
            result = Bounds(
                self.universe, result.lower.intersect(success.lower), result.upper.intersect(success.upper)
            )
        installed = self.predicates.compile(policy.installation)
        # If the selected policy is not established as installed, its outcome is
        # unknown.
        result = conditional(installed.bounds, result, Bounds.terminal(self.universe, "unknown"))
        gap_scope = self.universe.subtract(installed.bounds.lower)
        if not gap_scope.is_empty():
            reasons = installed.gaps or frozenset({Unknown("POLICY_NOT_INSTALLED", policy.uid)})
            gaps.extend(ScopedGap(reason, gap_scope) for reason in reasons)
        self._blocks = {key: value for key, value in self._blocks.items() if key in self._used_blocks}
        self._trees = {key: value for key, value in self._trees.items() if key in self._used_trees}
        self._layers = dict(self._active)
        stats = CompileStats(
            self._compiled_blocks,
            self._reused_blocks,
            self._recomposed,
            self.predicates.compiled_objects,
            self.predicates.reused_objects,
        )
        return CompiledPolicy(
            policy, self.predicates.known_fields, result, tuple(gaps), stats, tuple(self._active.values())
        )

    def _opaque_layer(self, uid: str, code: str) -> _CompiledLayer:
        flow = self._terminal("unknown")
        gaps = (ScopedGap(Unknown(code, uid), self.universe),)
        tree = _Tree(flow, gaps)
        return _CompiledLayer(uid, "unknown", tree, flow, gaps)

    def _layer(self, uid: str, stack: tuple[str, ...]) -> _CompiledLayer:
        if uid in stack:
            return self._opaque_layer(uid, "LAYER_CALL_CYCLE")
        if len(stack) >= 64:
            return self._opaque_layer(uid, "LAYER_CALL_DEPTH_LIMIT")
        if uid in self._active:
            return self._active[uid]
        definition = self._definitions.get(uid)
        if definition is None:
            result = self._opaque_layer(uid, "LAYER_MISSING")
            self._active[uid] = result
            return result
        blocks: list[_Block] = []
        for offset in range(0, len(definition.rules), self.BLOCK_SIZE):
            rules = definition.rules[offset : offset + self.BLOCK_SIZE]
            calls = tuple(
                self._layer(rule.called_layer, (*stack, uid))
                if rule.enabled and rule.called_layer is not None
                else None
                for rule in rules
            )
            key = (uid, offset)
            self._used_blocks.add(key)
            old = self._blocks.get(key)
            if (
                old is not None
                and old.rules == rules
                and old.calls == calls
                and not old.dependencies & self._dirty
            ):
                self._reused_blocks += 1
                block = old
            else:
                self._compiled_blocks += 1
                block = self._block(rules, calls)
                self._blocks[key] = block
            blocks.append(block)
        tree = self._tree(uid, blocks, 0, len(blocks))
        old_layer = self._layers.get(uid)
        if old_layer is not None and old_layer.tree is tree and old_layer.default == definition.default:
            result = old_layer
        else:
            flow = tree.flow.then(self._terminal(definition.default))
            gaps = tree.gaps
            if definition.default == "unknown":
                gaps += (ScopedGap(Unknown("LAYER_DEFAULT_UNKNOWN", uid), tree.flow.next),)
            result = _CompiledLayer(uid, definition.default, tree, flow, gaps)
        self._active[uid] = result
        return result

    def _tree(self, uid: str, blocks: list[_Block], start: int, end: int) -> _Tree:
        key = (uid, start, end)
        self._used_trees.add(key)
        old = self._trees.get(key)
        if end - start <= 1:
            block = blocks[start] if end > start else None
            if old is not None and old.block is block:
                return old
            tree = (
                _Tree(block.flow, block.gaps, block=block)
                if block is not None
                else _Tree(self._identity(), ())
            )
        else:
            middle = (start + end) // 2
            left = self._tree(uid, blocks, start, middle)
            right = self._tree(uid, blocks, middle, end)
            if old is not None and old.left is left and old.right is right:
                return old
            self._recomposed += 1
            gaps = left.gaps + tuple(
                ScopedGap(gap.reason, gap.packets.intersect(left.flow.next)) for gap in right.gaps
            )
            tree = _Tree(left.flow.then(right.flow), gaps, left, right)
        self._trees[key] = tree
        return tree

    def _block(self, rules: tuple[Rule, ...], calls: tuple[_CompiledLayer | None, ...]) -> _Block:
        flow = self._identity()
        matches: list[CompiledPredicate] = []
        steps: list[_Flow] = []
        gaps: list[ScopedGap] = []
        dependencies: set[ObjectKey] = set()
        for rule, called in zip(rules, calls, strict=True):
            predicate = rule.predicate
            if not rule.enabled or (
                rule.install_targets and self.context.firewall_instance not in rule.install_targets
            ):
                predicate = Constant(False)
            elif rule.install_targets is None:
                predicate = AllOf((predicate, Unknown("INSTALL_ON_UNKNOWN", rule.uid, rule.evidence)))
            match = self.predicates.compile(predicate)
            matches.append(match)
            dependencies.update(match.dependencies)
            for reason in match.gaps:
                gaps.append(
                    ScopedGap(reason, flow.next.intersect(match.bounds.upper.subtract(match.bounds.lower)))
                )
            matched, missed = match.bounds.upper, self.universe.subtract(match.bounds.lower)
            if called is not None:
                outcome = called.flow
                step = _Flow(
                    matched.intersect(outcome.permit),
                    matched.intersect(outcome.deny),
                    self.empty,
                    missed.union(matched.intersect(outcome.returns)),
                )
                gaps.extend(
                    ScopedGap(gap.reason, flow.next.intersect(matched).intersect(gap.packets))
                    for gap in called.gaps
                )
            else:
                outcome = self._terminal(rule.action)
                step = _Flow(
                    matched.intersect(outcome.permit),
                    matched.intersect(outcome.deny),
                    matched.intersect(outcome.returns),
                    missed,
                )
            if rule.action == "unknown":
                gaps.append(
                    ScopedGap(
                        Unknown("ACTION_UNKNOWN", rule.uid, rule.evidence), flow.next.intersect(matched)
                    )
                )
            steps.append(step)
            flow = flow.then(step)
        return _Block(rules, tuple(matches), tuple(steps), flow, tuple(gaps), frozenset(dependencies), calls)
