"""The limits and the permission check of the GraphQL endpoint."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Iterator
from typing import Any

from graphql import (
    DocumentNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLError,
    GraphQLObjectType,
    GraphQLSchema,
    InlineFragmentNode,
    IntValueNode,
    KnownFragmentNamesRule,
    NoFragmentCyclesRule,
    OperationDefinitionNode,
    SelectionSetNode,
    ValidationRule,
    VariableNode,
    get_named_type,
    get_nullable_type,
    is_list_type,
    is_object_type,
    validate,
)
from strawberry.extensions import SchemaExtension

log = logging.getLogger("hst.graphql")

MAX_DEPTH = 10
MAX_TOKENS = 2000
MAX_ALIASES = 15
MAX_SELECTIONS = 2000
PAGE_DEFAULT = 25
PAGE_MAX = 100
CHILD_DEFAULT = 10
CHILD_MAX = 100
UNPAGED_WEIGHT = 5
MAX_COST = 10_000

ENTITY_TYPES = ("Endpoint", "Device", "Site", "Segment", "Prefix", "IpAddress")
_HELPER_TYPES = ("Attachment",)

# The permission that the fields of each type need. It is the permission of the
# REST route that serves the same data (`GET /api/endpoints`, `GET /api/topology`).
TYPE_PERMISSIONS: dict[str, str] = {
    "Query": "graph.read",
    "PageInfo": "graph.read",
    **dict.fromkeys((*ENTITY_TYPES, *_HELPER_TYPES), "graph.read"),
    **{f"{name}Connection": "graph.read" for name in ENTITY_TYPES},
    **{f"{name}Edge": "graph.read" for name in ENTITY_TYPES},
}


class FieldPermissions(SchemaExtension):
    """Refuses every field whose type's permission the caller lacks."""

    def resolve(self, _next: Callable[..., Any], root: Any, info: Any, *args: Any, **kwargs: Any) -> Any:
        if not (info.field_name.startswith("__") or info.parent_type.name.startswith("__")):
            need = TYPE_PERMISSIONS.get(info.parent_type.name)
            if need is None or need not in info.context.permissions:
                raise GraphQLError(f"requires permission: {need or 'none is declared for this type'}")
        return _next(root, info, *args, **kwargs)


def _first(node: FieldNode, default: Any, maximum: int) -> int:
    for arg in node.arguments or ():
        if arg.name.value != "first":
            continue
        if isinstance(arg.value, IntValueNode):
            return max(0, min(int(arg.value.value), maximum))
        if isinstance(arg.value, VariableNode):
            return maximum
        return maximum
    return default if isinstance(default, int) else maximum


def _selections(selection: SelectionSetNode) -> tuple[int, Counter[str]]:
    """The count of the selections in `selection` and the count of its spreads
    per fragment name. A spread counts as 1 selection."""
    count = 0
    spreads: Counter[str] = Counter()
    stack = [selection]
    while stack:
        for node in stack.pop().selections:
            count += 1
            if isinstance(node, FragmentSpreadNode):
                spreads[node.name.value] += 1
            elif isinstance(node, FieldNode | InlineFragmentNode) and node.selection_set is not None:
                stack.append(node.selection_set)
    return count, spreads


def expanded_selections(document: DocumentNode) -> int | None:
    """The count of the selections in the operations of `document`, with the
    selections of a fragment added for each spread of it. None if a fragment
    spreads itself, directly or through other fragments."""
    own = {
        d.name.value: _selections(d.selection_set)
        for d in document.definitions
        if isinstance(d, FragmentDefinitionNode)
    }
    users: dict[str, list[str]] = {name: [] for name in own}
    waiting: dict[str, int] = {}
    for name, (_, spreads) in own.items():
        targets = [target for target in spreads if target in own]
        waiting[name] = len(targets)
        for target in targets:
            users[target].append(name)
    # A fragment is sized after each fragment it spreads.
    ready = [name for name, pending in waiting.items() if pending == 0]
    sizes: dict[str, int] = {}
    while ready:
        name = ready.pop()
        count, spreads = own[name]
        sizes[name] = count + sum(n * sizes.get(target, 0) for target, n in spreads.items())
        for user in users[name]:
            waiting[user] -= 1
            if waiting[user] == 0:
                ready.append(user)
    if len(sizes) < len(own):
        return None
    total = 0
    for d in document.definitions:
        if isinstance(d, OperationDefinitionNode):
            count, spreads = _selections(d.selection_set)
            total += count + sum(n * sizes.get(target, 0) for target, n in spreads.items())
    return total


def empty_selection(document: DocumentNode) -> bool:
    """Whether a selection set of `document` holds no selection."""
    stack = [
        d.selection_set
        for d in document.definitions
        if isinstance(d, OperationDefinitionNode | FragmentDefinitionNode)
    ]
    while stack:
        selection = stack.pop()
        if not selection.selections:
            return True
        stack.extend(
            node.selection_set
            for node in selection.selections
            if isinstance(node, FieldNode | InlineFragmentNode) and node.selection_set is not None
        )
    return False


def document_errors(schema: GraphQLSchema, document: DocumentNode) -> list[GraphQLError]:
    """The errors that refuse `document` before the validation rules of the schema run.

    `KnownFragmentNamesRule` reports a spread of an undefined fragment. `validate`
    reports a document whose selections nest through its fragments deeper than
    the parser allows in one definition. A document with a fragment cycle is
    validated by `NoFragmentCyclesRule` alone."""
    errors = validate(schema, document, [KnownFragmentNamesRule])
    if errors:
        return errors
    if empty_selection(document):
        return [GraphQLError("the query holds an empty selection set")]
    size = expanded_selections(document)
    if size is None:
        # The rule reads only the first of 2 fragment definitions with one name.
        return validate(schema, document, [NoFragmentCyclesRule]) or [
            GraphQLError("the query spreads a fragment within itself")
        ]
    if size > MAX_SELECTIONS:
        return [GraphQLError(f"the query expands to more than {MAX_SELECTIONS} selections")]
    return []


class FragmentLimit(SchemaExtension):
    """Refuses a document with `document_errors` before the validation rules run."""

    def on_validate(self) -> Iterator[None]:
        context = self.execution_context
        document = context.graphql_document
        if document is not None:
            errors = document_errors(context.schema._schema, document)
            if errors:
                context.pre_execution_errors = errors
        yield


def operation_cost(
    selection: SelectionSetNode | None,
    parent: GraphQLObjectType,
    fragments: dict[str, FragmentDefinitionNode],
    schema: Any,
) -> int:
    """The highest count of entity objects that `selection` can return.

    The walk holds a multiplier that starts at 1. A field with a `first`
    argument multiplies it by the value of `first`, capped at `PAGE_MAX` on
    `Query` and at `CHILD_MAX` on another type. A field that gives no `first`
    counts the default of the argument. A `first` that is a variable counts the
    cap. A list of objects without a `first` argument multiplies it by
    `UNPAGED_WEIGHT`, except on a connection type. A field of a type in
    `ENTITY_TYPES` adds the multiplier to the cost. A fragment adds its cost for
    each spread of it."""
    # The cost of a fragment at multiplier 1, by fragment name and parent type name.
    unit: dict[tuple[str, str], int] = {}
    # The fragments whose cost is in computation. A spread of one of them costs 0.
    walking: set[str] = set()

    def cost(selection: SelectionSetNode | None, parent: GraphQLObjectType, multiplier: int) -> int:
        if selection is None:
            return 0
        total = 0
        for node in selection.selections:
            if isinstance(node, FieldNode):
                name = node.name.value
                if name.startswith("__") or name not in parent.fields:
                    continue
                field = parent.fields[name]
                named = get_named_type(field.type)
                m = multiplier
                if "first" in field.args:
                    maximum = PAGE_MAX if parent.name == "Query" else CHILD_MAX
                    m *= _first(node, field.args["first"].default_value, maximum)
                elif (
                    is_list_type(get_nullable_type(field.type))
                    and is_object_type(named)
                    and not parent.name.endswith("Connection")
                ):
                    m *= UNPAGED_WEIGHT
                if is_object_type(named):
                    if named.name in ENTITY_TYPES:
                        total += m
                    total += cost(node.selection_set, named, m)
            elif isinstance(node, InlineFragmentNode):
                target = parent
                if node.type_condition is not None:
                    found = schema.get_type(node.type_condition.name.value)
                    target = found if is_object_type(found) else parent
                total += cost(node.selection_set, target, multiplier)
            elif isinstance(node, FragmentSpreadNode):
                name = node.name.value
                frag = fragments.get(name)
                if frag is None or name in walking:
                    continue
                found = schema.get_type(frag.type_condition.name.value)
                target = found if is_object_type(found) else parent
                key = (name, target.name)
                if key not in unit:
                    walking.add(name)
                    unit[key] = cost(frag.selection_set, target, 1)
                    walking.discard(name)
                total += multiplier * unit[key]
        return total

    return cost(selection, parent, 1)


class CostLimit(ValidationRule):
    """Refuses an operation whose `operation_cost` passes `MAX_COST`."""

    def enter_operation_definition(self, node: OperationDefinitionNode, *_args: Any) -> None:
        schema = self.context.schema
        root = schema.get_root_type(node.operation)
        if root is None:
            return
        fragments = {
            d.name.value: d
            for d in self.context.document.definitions
            if isinstance(d, FragmentDefinitionNode)
        }
        cost = operation_cost(node.selection_set, root, fragments, schema)
        if cost > MAX_COST:
            self.report_error(
                GraphQLError(f"the query may return {cost} objects, above the limit of {MAX_COST}", node)
            )


def should_mask(error: GraphQLError) -> bool:
    """Mask and log an error that the API did not raise."""
    original = error.original_error
    if original is None or isinstance(original, GraphQLError):
        return False
    log.error("graphql: unexpected error at %s", error.path, exc_info=original)
    return True
