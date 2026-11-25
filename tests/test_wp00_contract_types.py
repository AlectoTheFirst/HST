"""The TypeScript types of web/src/analysis/contracts.ts match the models of hst.analysis.contracts.

The test reads the TypeScript file. A type pair matches when it has the same
field names, the same literal values of each discriminator and state field,
and when the TypeScript optional fields are the Python fields that accept None.
"""

from __future__ import annotations

import re
import types
import typing
from pathlib import Path

import pytest
from pydantic import BaseModel

from hst.analysis import contracts as py

CONTRACTS_TS = Path(__file__).resolve().parents[1] / "web" / "src" / "analysis" / "contracts.ts"


def _strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n]*", "", source)


def _split_top(body: str, separators: str) -> list[str]:
    """`body` split at each separator outside braces, brackets and parentheses."""
    parts, depth, current = [], 0, ""
    for character in body:
        if character in "{[(<":
            depth += 1
        elif character in "}])>":
            depth -= 1
        if depth == 0 and character in separators:
            parts.append(current)
            current = ""
        else:
            current += character
    parts.append(current)
    return [part.strip() for part in parts if part.strip()]


def _braced(text: str, start: int) -> str:
    """The text inside the brace at `start` and its matching close."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : index]
    raise ValueError("unbalanced braces")


TsFields = dict[str, tuple[bool, str]]


def _fields(body: str) -> TsFields:
    """Each field name with whether it is optional and its type text."""
    fields: TsFields = {}
    for entry in _split_top(body, ";\n"):
        name, _, kind = entry.partition(":")
        optional = name.strip().endswith("?")
        fields[name.strip().rstrip("?")] = (optional, kind.strip())
    return fields


def _parse(source: str) -> tuple[dict[str, TsFields], dict[str, str]]:
    """The interfaces as fields, and the type aliases as their type text."""
    text = _strip_comments(source)
    interfaces = {
        match.group(1): _fields(_braced(text, match.end() - 1))
        for match in re.finditer(r"export interface (\w+)\s*{", text)
    }
    aliases = {}
    for match in re.finditer(r"export type (\w+)\s*=", text):
        rest = text[match.end() :]
        depth, end = 0, len(rest)
        for index, character in enumerate(rest):
            depth += character == "{"
            depth -= character == "}"
            if character == ";" and depth == 0:
                end = index
                break
        aliases[match.group(1)] = rest[:end].strip()
    return interfaces, aliases


INTERFACES, ALIASES = _parse(CONTRACTS_TS.read_text(encoding="utf-8"))


def _variants(alias: str) -> dict[str, TsFields]:
    """The object variants of a union type alias, keyed by their `kind`."""
    variants = {}
    for part in _split_top(ALIASES[alias], "|"):
        fields = _fields(part.strip()[1:-1])
        variants[_literals(fields["kind"][1])[0]] = fields
    return variants


def _literals(type_text: str) -> list[str]:
    return re.findall(r'"([^"]+)"', type_text)


def _accepts_none(annotation: object) -> bool:
    origin = typing.get_origin(annotation)
    if origin is typing.Annotated:
        return _accepts_none(typing.get_args(annotation)[0])
    if origin in (typing.Union, types.UnionType):
        return type(None) in typing.get_args(annotation)
    return annotation is type(None)


def _python_literals(annotation: object) -> list[str]:
    return sorted(str(value) for value in typing.get_args(annotation))


PAIRS: dict[str, tuple[TsFields, type[BaseModel]]] = {
    "SnapshotReference": (INTERFACES["SnapshotReference"], py.SnapshotReference),
    "RevisionReference": (INTERFACES["RevisionReference"], py.RevisionReference),
    "ApplicationConnectionReference": (
        INTERFACES["ApplicationConnectionReference"],
        py.ApplicationConnectionReference,
    ),
    "ConnectionSource inline": (_variants("ConnectionSource")["inline"], py.InlineConnection),
    "ConnectionSource saved_requirement": (
        _variants("ConnectionSource")["saved_requirement"],
        py.SavedRequirementConnection,
    ),
    "ConnectionSource graph_requirement": (
        _variants("ConnectionSource")["graph_requirement"],
        py.GraphRequirementConnection,
    ),
    "ConnectionSource application_connection": (
        _variants("ConnectionSource")["application_connection"],
        py.ApplicationConnection,
    ),
    "ConnectionSelection": (INTERFACES["ConnectionSelection"], py.ConnectionSelection),
    "ChangeIntent": (INTERFACES["ChangeIntent"], py.ChangeIntent),
    "ConnectionAnalysisInput": (INTERFACES["ConnectionAnalysisInput"], py.ConnectionAnalysisInput),
    "SimulationFlow": (INTERFACES["SimulationFlow"], py.SimulationFlow),
    "SimulationScope": (INTERFACES["SimulationScope"], py.SimulationScope),
    "SimulationBounds": (INTERFACES["SimulationBounds"], py.SimulationBounds),
    "Protection inline": (_variants("Protection")["inline"], py.InlineProtection),
    "Protection application_connection": (
        _variants("Protection")["application_connection"],
        py.ApplicationProtection,
    ),
    "SimulationAnalysisInput": (INTERFACES["SimulationAnalysisInput"], py.SimulationAnalysisInput),
    "AnalysisRunSummary": (INTERFACES["AnalysisRunSummary"], py.AnalysisRunSummary),
    "AnalysisSession": (INTERFACES["AnalysisSession"], py.AnalysisSession),
    "AnalysisSession legacy_assessment": (
        _fields(INTERFACES["AnalysisSession"]["legacy_assessment"][1].split("|")[0].strip()[1:-1]),
        py.LegacyAssessmentReference,
    ),
}


@pytest.mark.parametrize("name", list(PAIRS))
def test_each_typescript_type_has_the_fields_of_its_model(name):
    fields, model = PAIRS[name]

    assert set(fields) == set(model.model_fields)


@pytest.mark.parametrize("name", list(PAIRS))
def test_the_typescript_optional_fields_are_the_model_fields_that_accept_none(name):
    fields, model = PAIRS[name]
    optional = {field for field, (is_optional, _) in fields.items() if is_optional}
    nullable = {field for field, info in model.model_fields.items() if _accepts_none(info.annotation)}

    assert optional == nullable


@pytest.mark.parametrize("name", list(PAIRS))
def test_each_literal_field_has_the_values_of_its_model(name):
    fields, model = PAIRS[name]
    for field, info in model.model_fields.items():
        if typing.get_origin(info.annotation) is not typing.Literal:
            continue
        if not all(isinstance(value, str) for value in typing.get_args(info.annotation)):
            continue
        type_text = fields[field][1]
        assert sorted(_literals(ALIASES.get(type_text, type_text))) == _python_literals(info.annotation), (
            field
        )


def test_the_union_kinds_and_state_names_are_the_model_values():
    assert {INTERFACES[name]["kind"][1] for name in ALIASES["AnalysisInput"].split(" | ")} == {
        '"connection"',
        '"simulation"',
    }
    assert sorted(_variants("ConnectionSource")) == sorted(
        typing.get_args(member.model_fields["kind"].annotation)[0]
        for member in typing.get_args(typing.get_args(py.ConnectionSource)[0])
    )
    assert sorted(_variants("Protection")) == sorted(
        typing.get_args(member.model_fields["kind"].annotation)[0]
        for member in typing.get_args(typing.get_args(py.Protection)[0])
    )
    assert sorted(_literals(ALIASES["ExecutionState"])) == _python_literals(py.ExecutionState)
    assert sorted(_literals(ALIASES["CoverageState"])) == _python_literals(py.CoverageState)
    assert sorted(_literals(ALIASES["AnalysisSection"])) == _python_literals(
        py.AnalysisLocation.model_fields["section"].annotation
    )


def test_the_schema_version_is_the_model_version():
    assert INTERFACES["AnalysisSession"]["schema_version"] == (False, str(py.ANALYSIS_SESSION_SCHEMA_VERSION))
