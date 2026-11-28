"""Bounded YAML parsing, canonical serialization and semantic identity."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any, TypeVar

import yaml
from pydantic import ValidationError
from pydantic_core import ErrorDetails
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from yaml.error import MarkedYAMLError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from hst.applications.models import NEW_REVISION, BusinessApplicationDefinition, BusinessApplicationPatch

MAX_YAML_BYTES = 1024 * 1024
MAX_YAML_DEPTH = 32
# A schema error result lists the first MAX_FORMAT_ISSUES errors and one `$`
# issue with the total count.
MAX_FORMAT_ISSUES = 100
# The parse slots of the process. `parse_application_bounded` runs at most
# MAX_CONCURRENT_PARSES parses at once. At most MAX_WAITING_PARSES callers wait
# for a slot, each for at most PARSE_WAIT_S seconds.
MAX_CONCURRENT_PARSES = 2
MAX_WAITING_PARSES = 8
PARSE_WAIT_S = 30.0
_PARSE_POLL_S = 0.05
_PARSE_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_PARSES)
_waiting = 0
T = TypeVar("T", BusinessApplicationDefinition, BusinessApplicationPatch)


@dataclass(frozen=True)
class FormatIssue:
    """One parse or schema error.

    `path` is the field path of the pydantic location joined with dots, or `$`
    for the document. `line` and `column` count from 1 and point at the YAML
    key or list item the path names. They are None when the error has no place
    in the text, such as the size bound or a check across the whole document.
    """

    path: str
    message: str
    line: int | None = None
    column: int | None = None

    def as_dict(self) -> dict:
        return asdict(self)


class ApplicationFormatError(ValueError):
    """A document that did not parse or validate.

    The message is the joined string form the routes answer with. `errors`
    holds the same errors as `FormatIssue` values with their positions.
    """

    def __init__(self, message: str, errors: Sequence[FormatIssue] | None = None) -> None:
        super().__init__(message)
        self.errors: list[FormatIssue] = list(errors) if errors else [FormatIssue("$", message)]


class ParseBusy(Exception):
    """No parse slot became free within PARSE_WAIT_S seconds, or
    MAX_WAITING_PARSES callers already wait."""

    def __init__(self) -> None:
        super().__init__("Business Application parsing is busy")


@dataclass(frozen=True)
class ParsedApplication:
    """A validated document with the mapping as written and its YAML node tree."""

    document: BusinessApplicationDefinition | BusinessApplicationPatch
    source: dict
    node: Node

    def issue(self, loc: Sequence[int | str], message: str) -> FormatIssue:
        line, column = _position(self.node, loc, {})
        return FormatIssue(_path(loc), message, line, column)


class _ApplicationLoader(yaml.SafeLoader):
    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            event = self.peek_event()
            raise ComposerError(None, None, "YAML aliases are not supported", event.start_mark)
        return super().compose_node(parent, index)


def _construct_mapping(loader: _ApplicationLoader, node: MappingNode, deep: bool = False) -> dict:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ConstructorError(
                "while constructing a mapping", node.start_mark, f"duplicate key {key!r}", key_node.start_mark
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_ApplicationLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def parse_application_yaml(
    text: str, *, partial: bool = False
) -> BusinessApplicationDefinition | BusinessApplicationPatch:
    return parse_application_source(text, partial=partial).document


def parse_application_source(text: str, *, partial: bool = False) -> ParsedApplication:
    """Parse and validate one document, keeping the source mapping and node tree.

    The document is the input of a new revision. A reserved application id is
    an error. The function raises `ApplicationFormatError`, whose `errors` hold
    the line and column of each YAML syntax error and each schema error.
    """
    if len(text.encode()) > MAX_YAML_BYTES:
        raise ApplicationFormatError("YAML document exceeds 1 MiB")
    loader = _ApplicationLoader(text)
    try:
        node = loader.get_single_node()
        value = loader.construct_document(node) if node is not None else None
    except yaml.YAMLError as exc:
        raise ApplicationFormatError(str(exc), [_syntax_issue(exc)]) from exc
    finally:
        loader.dispose()
    if node is None or not isinstance(value, dict):
        raise ApplicationFormatError("Business Application YAML must contain one mapping document")
    if _depth(value) > MAX_YAML_DEPTH:
        raise ApplicationFormatError(f"YAML nesting exceeds {MAX_YAML_DEPTH} levels")
    model: type[BusinessApplicationDefinition] | type[BusinessApplicationPatch]
    model = BusinessApplicationPatch if partial else BusinessApplicationDefinition
    try:
        document = model.model_validate(value, context={NEW_REVISION: True})
    except ValidationError as exc:
        issues = _schema_issues(node, exc.errors(include_url=False))
        raise ApplicationFormatError(
            "; ".join(f"{issue.path}: {issue.message}" for issue in issues), issues
        ) from exc
    return ParsedApplication(document, value, node)


async def parse_application_bounded(text: str, *, partial: bool = False) -> ParsedApplication:
    """`parse_application_source` in a worker thread that holds one of the
    MAX_CONCURRENT_PARSES parse slots. The caller waits on the event loop for a
    slot. `ParseBusy` is raised when MAX_WAITING_PARSES callers already wait or
    no slot is free after PARSE_WAIT_S seconds. The thread releases the slot
    when the parse ends, also after the caller is cancelled."""
    global _waiting
    loop = asyncio.get_running_loop()
    if not _PARSE_SLOTS.acquire(blocking=False):
        if _waiting >= MAX_WAITING_PARSES:
            raise ParseBusy()
        _waiting += 1
        try:
            deadline = loop.time() + PARSE_WAIT_S
            while not _PARSE_SLOTS.acquire(blocking=False):
                if loop.time() >= deadline:
                    raise ParseBusy()
                await asyncio.sleep(_PARSE_POLL_S)
        finally:
            _waiting -= 1
    try:
        future = loop.run_in_executor(None, _parse_in_slot, text, partial)
    except BaseException:
        _PARSE_SLOTS.release()
        raise
    # A cancelled caller leaves the executor job to run and release its slot.
    return await asyncio.shield(future)


def _parse_in_slot(text: str, partial: bool) -> ParsedApplication:
    try:
        return parse_application_source(text, partial=partial)
    finally:
        _PARSE_SLOTS.release()


def _schema_issues(node: Node, errors: list[ErrorDetails]) -> list[FormatIssue]:
    """The issues of the first MAX_FORMAT_ISSUES errors, and a `$` issue with
    the total count when there are more."""
    index: dict[int, dict[str, tuple[ScalarNode, Node]]] = {}
    issues = []
    for error in errors[:MAX_FORMAT_ISSUES]:
        line, column = _position(node, error["loc"], index)
        issues.append(FormatIssue(_path(error["loc"]), error["msg"], line, column))
    if len(errors) > MAX_FORMAT_ISSUES:
        message = (
            f"the document has {len(errors)} schema errors and the list holds the first {MAX_FORMAT_ISSUES}"
        )
        issues.append(FormatIssue("$", message))
    return issues


def _path(loc: Sequence[int | str]) -> str:
    return ".".join(str(part) for part in loc) or "$"


def _position(
    node: Node, loc: Sequence[int | str], index: dict[int, dict[str, tuple[ScalarNode, Node]]]
) -> tuple[int | None, int | None]:
    """The line and column, from 1, of the deepest key or list item on `loc`.

    The walk follows mapping keys by their text and list items by index. A
    location part the tree does not hold, such as a missing field or the
    member name pydantic adds for a union type, ends the walk at the node
    before it. The empty location is the whole document and has no position.
    `index` maps the id of each mapping node the walk entered to its scalar
    keys by text. The first key of a text wins. Calls on the same tree share
    one `index`.
    """
    mark = None
    current = node
    for part in loc:
        if isinstance(current, MappingNode):
            keys = index.get(id(current))
            if keys is None:
                keys = index[id(current)] = {}
                for key, value in current.value:
                    if isinstance(key, ScalarNode):
                        keys.setdefault(key.value, (key, value))
            entry = keys.get(str(part))
            if entry is None:
                break
            mark, current = entry[0].start_mark, entry[1]
        elif isinstance(current, SequenceNode) and isinstance(part, int) and 0 <= part < len(current.value):
            current = current.value[part]
            mark = current.start_mark
        else:
            break
    if mark is None:
        return None, None
    return mark.line + 1, mark.column + 1


def _syntax_issue(exc: yaml.YAMLError) -> FormatIssue:
    if not isinstance(exc, MarkedYAMLError):
        return FormatIssue("$", str(exc))
    mark = exc.problem_mark or exc.context_mark
    message = ": ".join(part for part in (exc.context, exc.problem) if part) or str(exc)
    if mark is None:
        return FormatIssue("$", message)
    return FormatIssue("$", message, mark.line + 1, mark.column + 1)


def normalized_document(definition: BusinessApplicationDefinition) -> dict:
    return definition.model_dump(mode="json", exclude_none=True)


def definition_digest(definition: BusinessApplicationDefinition | dict) -> str:
    value = (
        normalized_document(definition)
        if isinstance(definition, BusinessApplicationDefinition)
        else definition
    )
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def canonical_yaml(definition: BusinessApplicationDefinition) -> str:
    return yaml.safe_dump(
        normalized_document(definition),
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=100,
    )


def _depth(value: Any, depth: int = 0) -> int:
    if isinstance(value, dict):
        return max([depth + 1, *(_depth(entry, depth + 1) for entry in value.values())])
    if isinstance(value, list):
        return max([depth + 1, *(_depth(entry, depth + 1) for entry in value)])
    return depth
