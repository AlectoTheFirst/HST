"""The answer envelope of a conversational turn.

`strata/ai/answer-envelope/v2` records the run the turn was pinned to, the
model, the prompt version, the tool steps that the turn ran, and one entry per
claim of the answer text. It is stored in
`ai_messages.envelope` beside the poll fields the turn keeps under `payload`.
The poll of a conversation message (`GET /api/ai/messages/{id}`) returns it
without `payload`.

The claim splitter reads the answer as the web renderer does
(`web/src/shell/markdown.tsx`). Each sentence of a paragraph, each list item
and each table body row is a claim. Headings, table header rows and fenced
code blocks are not claims. A section title written as a plain line is not a
claim. A section title is a line that is only bold text, or a line of at most
8 words without punctuation that is a paragraph of its own, when a list, a
paragraph or a table follows it. A marker is `[s3]`
or `[s3, s5]`, outside inline code. A marker after the full stop of a sentence
belongs to that sentence. A list item without a marker of its own takes the
markers of the item it is nested under.

Each claim gets the first citation status that applies:

- `citation-invalid`: a marker names no step of the conversation's window, or
  names an error step.
- `cross-snapshot`: a cited step read a run other than the turn's run.
- `prior-turn`: every marker names a step of an earlier turn.
- `cited`: at least one marker names a step of this turn.
- `matched`: the claim has no marker, and a result record of a step of this
  turn holds what it names (`support.py`).
- `process`: the claim has no marker and states what the assistant did, a
  sentence that starts with "I".
- `uncited`: the claim has no marker.

`support` lists, per cited or matched step, the JSON pointers of the result
records that hold what the claim names. A pointer is null for the summary of
a compacted step. The `support` of a cited claim can be empty.

When a claim uses a word of the result vocabulary, `evidence_status` is the
first such word that a cited step's result holds as a key or a value. After
compaction the check reads the step's `result_summary`. The AI layer adds only
citation statuses, and they describe only the link between a sentence and a
tool result.

`links` holds one `step` link per cited step, then the stored objects that the
steps of the answer read (`object_links`). These objects are the assessments,
runs, findings, analysis sessions, applications and devices that the web
client opens from the answer. Each object is listed once. A run or a finding
also has the assessment and run links of its own step (`new_object_links`).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, Literal, get_args
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, NonNegativeInt, StringConstraints

from hst.app.agent.budget import INCOMPLETE_ANSWER
from hst.app.agent.tools import step_label
from hst.app.ai import support as support_mod
from hst.app.store import AiStep

if TYPE_CHECKING:
    from hst.app.agent.base import AgentAnswer
    from hst.app.ai.registry import Provenance
    from hst.app.ai.turns import TurnRunner

log = logging.getLogger("hst.ai")

SCHEMA_ID = "strata/ai/answer-envelope/v2"
# The envelope version a stored row holds.
VERSION = 2

EnvelopeKind = Literal["answer", "declined", "incomplete", "assessment_draft", "service_draft"]
SnapshotOrigin = Literal["context", "conversation", "pointer"]
CitationStatus = Literal[
    "cited", "prior-turn", "cross-snapshot", "citation-invalid", "matched", "process", "uncited"
]
GroundingStatus = Literal["grounded", "partially-grounded", "no-evidence"]
# The words that a claim is checked for in the result of a cited step. They are
# the result vocabulary (hst.results.words), longest first, the rule actions
# and the `unknown` value that records hold.
EvidenceWord = Literal[
    "forwarded, all candidate paths",
    "split by path",
    "partly permitted",
    "platform default",
    "not applicable",
    "not decided",
    "permitted",
    "blocked",
    "forwarded",
    "passes",
    "fails",
    "accepted",
    "rejected",
    "removed",
    "added",
    "changed",
    "present",
    "resolved",
    "unresolved",
    "permit",
    "deny",
    "unknown",
]
LinkKind = Literal[
    "snapshot",
    "analysis_session",
    "assessment",
    "assessment_run",
    "finding",
    "application",
    "change",
    "service_draft",
    "graph_node",
    "step",
]
RunId = Annotated[str, StringConstraints(pattern=r"^[0-9]{1,19}$")]
StepName = Annotated[str, StringConstraints(pattern=r"^s[0-9]+$")]


# --- the schema -----------------------------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnvelopeSnapshot(_Strict):
    id: RunId | None
    origin: SnapshotOrigin
    manifest_sha256: str | None = None
    degraded: bool | None = None
    others_used: list[RunId] = Field(default_factory=list)


class EnvelopeModel(_Strict):
    provider: str
    requested: str
    served: str | None = None


class QueryUsed(_Strict):
    kind: Literal["fixed", "catalog", "cypher"]
    id: str


class ToolUsed(_Strict):
    step: StepName
    step_id: UUID
    tool: str
    version: int
    is_error: bool
    snapshot: str | None = None
    engine: str | None = None
    queries: list[QueryUsed] = Field(default_factory=list)


class ClaimGap(_Strict):
    kind: Literal["not-collected", "not-modeled", "unsupported", "unclassified"]
    code: str | None = None


class ClaimSupport(_Strict):
    step: StepName
    pointer: str | None = Field(
        description="JSON pointer of the record in the step's stored result; null for its result_summary"
    )


class Claim(_Strict):
    id: str
    span: tuple[NonNegativeInt, NonNegativeInt] = Field(
        description="code point offsets [start, end) into answer_markdown"
    )
    citations: list[StepName]
    evidence_status: EvidenceWord | None = None
    citation_status: CitationStatus
    support: list[ClaimSupport] = Field(default_factory=list)
    gaps: list[ClaimGap] = Field(default_factory=list)


class Grounding(_Strict):
    status: GroundingStatus
    cited: NonNegativeInt
    uncited: NonNegativeInt
    invalid: NonNegativeInt
    cross_snapshot: NonNegativeInt
    matched: NonNegativeInt
    process: NonNegativeInt


class EnvelopeLink(_Strict):
    kind: LinkKind
    ref_id: str
    ref_revision: int | None = None
    step: str | None = None


class AnswerEnvelope(_Strict):
    """The `strata/ai/answer-envelope/v2` object."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"$id": SCHEMA_ID})

    version: Literal[2]
    message_id: UUID
    conversation_id: UUID
    kind: EnvelopeKind
    snapshot: EnvelopeSnapshot
    model: EnvelopeModel
    prompt_hash: str
    tools_used: list[ToolUsed]
    answer_markdown: str
    claims: list[Claim]
    grounding: Grounding
    links: list[EnvelopeLink] = Field(default_factory=list)
    payload: dict[str, Any] | None = None


def schema() -> dict[str, Any]:
    """The JSON Schema of the answer envelope."""
    return AnswerEnvelope.model_json_schema()


# --- the claim splitter ---------------------------------------------------------------------

# A citation marker is one or more step names in square brackets.
MARKER = re.compile(r"\[(s[0-9]{1,9}(?:[ \t]*,[ \t]*s[0-9]{1,9})*)\]")
_MARKER_NAME = re.compile(r"s[0-9]{1,9}")
# The line forms of web/src/shell/markdown.tsx.
_UL = re.compile(r"\s*[-*]\s+")
_OL = re.compile(r"\s*\d+[.)]\s+")
_HEADING = re.compile(r"#{1,4}\s+")
_DIVIDER = re.compile(r"[|\s:-]+")
# An inline code span on one line (a list item or a table row), and one that
# wraps across the lines of a paragraph, as the renderer joins them.
_CODE_SPAN = re.compile(r"`[^`\n]+`")
_PARAGRAPH_CODE_SPAN = re.compile(r"`[^`]+`")
# Characters that close a sentence after its full stop.
_CLOSERS = "\"')*_"
_ABBREVIATIONS = frozenset({"e.g", "i.e", "vs", "cf"})
_ALNUM = re.compile(r"[^\W_]")
_BOLD_TITLE = re.compile(r"(\*\*|__)(?:(?!\1).)+\1:?")
_TITLE_PUNCTUATION = re.compile(r"[,;!?]|[.:](?:\s|$)")
_TITLE_WORDS = 8
_TITLE_CHARS = 80


@dataclass(frozen=True)
class ClaimText:
    """One claim of an answer. It holds the code point range of the claim in
    the answer text, the step names of its markers in order and its text
    without the markers. A claim without a marker has the step names of the
    list item it is nested under."""

    start: int
    end: int
    citations: tuple[str, ...]
    text: str


def _is_table_row(line: str) -> bool:
    stripped = line.strip()
    return len(stripped) > 1 and stripped.startswith("|") and stripped.endswith("|")


def _is_divider(line: str) -> bool:
    return _is_table_row(line) and _DIVIDER.fullmatch(line.strip()) is not None


def _is_fence(line: str) -> bool:
    return line.lstrip().startswith("```")


def _starts_block(line: str) -> bool:
    return (
        line.strip() == ""
        or _is_fence(line)
        or _is_table_row(line)
        or _UL.match(line) is not None
        or _OL.match(line) is not None
        or _HEADING.match(line) is not None
    )


def _is_title(line: str, masked_line: str, *, wraps: bool) -> bool:
    """Whether a paragraph line is a section title. A title is only bold text
    that does not end with `.`, `!` or `?`, or a line of at most 8 words and
    80 characters without punctuation. A line with a marker or an open code
    span is not a title. When the paragraph continues on the next line
    (`wraps`), only bold text is a title. A plain line there can be the first
    part of a wrapped sentence."""
    text = line.strip()
    if not text or MARKER.search(masked_line) or text.count("`") % 2:
        return False
    if _BOLD_TITLE.fullmatch(text):
        return text.rstrip(":*_ ")[-1:] not in (".", "!", "?")
    return (
        not wraps
        and len(text) <= _TITLE_CHARS
        and len(text.split()) <= _TITLE_WORDS
        and _TITLE_PUNCTUATION.search(text) is None
    )


def _content_follows(lines: Sequence[str], i: int) -> bool:
    """Whether a list, a table or a paragraph line is the next line from `i`
    that is not blank."""
    while i < len(lines) and lines[i].strip() == "":
        i += 1
    return i < len(lines) and not _is_fence(lines[i]) and _HEADING.match(lines[i]) is None


def _markers(masked: str, start: int, end: int) -> tuple[str, ...]:
    """The step names of the markers in `masked[start:end]`, each once."""
    names = (name for m in MARKER.finditer(masked, start, end) for name in _MARKER_NAME.findall(m.group(1)))
    return tuple(dict.fromkeys(names))


def _mask_code(text: str, pattern: re.Pattern[str] = _CODE_SPAN) -> str:
    """`text` with the content of each inline code span replaced by `x`
    characters. A full stop or a marker inside code does not count."""
    return pattern.sub(lambda m: "`" + "x" * (len(m.group()) - 2) + "`", text)


def _strip_range(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def _skip_space(text: str, i: int, end: int) -> int:
    while i < end and text[i].isspace():
        i += 1
    return i


def _ends_sentence(masked: str, i: int, end: int) -> bool:
    """Whether the `.`, `!` or `?` at `i` ends a sentence. It ends a sentence
    when whitespace, a marker or the end of the block follows it and its
    closing characters, and it does not end an abbreviation of
    `_ABBREVIATIONS`."""
    j = i + 1
    if j < end and masked[j] in ".!?":
        return False
    while j < end and masked[j] in _CLOSERS:
        j += 1
    if j < end and not masked[j].isspace() and MARKER.match(masked, j, end) is None:
        return False
    if masked[i] == ".":
        k = i
        while k > 0 and (masked[k - 1].isalpha() or masked[k - 1] == "."):
            k -= 1
        if masked[k:i].lower() in _ABBREVIATIONS:
            return False
    return True


def _sentences(masked: str, start: int, end: int) -> list[tuple[int, int]]:
    """The sentence ranges of the paragraph `masked[start:end]`. The markers
    that follow a full stop, and the whitespace between them, belong to the
    sentence before it."""
    ranges: list[tuple[int, int]] = []
    begin = _skip_space(masked, start, end)
    i = begin
    while i < end:
        if masked[i] in ".!?" and _ends_sentence(masked, i, end):
            stop = i + 1
            while stop < end and masked[stop] in _CLOSERS:
                stop += 1
            while True:
                marker = MARKER.match(masked, _skip_space(masked, stop, end), end)
                if marker is None:
                    break
                stop = marker.end()
            ranges.append((begin, stop))
            begin = i = _skip_space(masked, stop, end)
            continue
        i += 1
    if begin < end:
        ranges.append(_strip_range(masked, begin, end))
    return ranges


def _claim(
    markdown: str, masked: str, start: int, end: int, inherited: tuple[str, ...] = ()
) -> ClaimText | None:
    start, end = _strip_range(markdown, start, end)
    names: list[str] = []
    pieces: list[str] = []
    last = start
    for marker in MARKER.finditer(masked, start, end):
        names.extend(_MARKER_NAME.findall(marker.group(1)))
        pieces.append(markdown[last : marker.start()])
        last = marker.end()
    pieces.append(markdown[last:end])
    text = "".join(pieces).strip()
    if _ALNUM.search(text) is None:
        return None
    # A text without a marker that ends with a colon is a lead-in to a list or a table. It is
    # not a claim.
    if not names and text.rstrip(_CLOSERS).endswith(":"):
        return None
    return ClaimText(start, end, tuple(dict.fromkeys(names)) or inherited, text)


def split_claims(markdown: str) -> list[ClaimText]:
    """The claims of an answer, in text order."""
    masked = _mask_code(markdown)
    lines = markdown.split("\n")
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line) + 1)
    # (start, end, the markers of the list item it is nested under)
    ranges: list[tuple[int, int, tuple[str, ...]]] = []
    # the indentation and markers of the list items that are open
    items: list[tuple[int, tuple[str, ...]]] = []
    i = 0
    while i < len(lines):
        line, at = lines[i], offsets[i]
        if line.strip() == "":
            i += 1
            continue
        if _UL.match(line) is None and _OL.match(line) is None:
            items = []
        if _is_fence(line):
            i += 1
            while i < len(lines) and not _is_fence(lines[i]):
                i += 1
            i += 1
        elif _is_table_row(line):
            first = i
            while i < len(lines) and _is_table_row(lines[i]):
                row = lines[i]
                header = i == first and i + 1 < len(lines) and _is_divider(lines[i + 1])
                if not header and not _is_divider(row):
                    left = offsets[i] + row.index("|") + 1
                    right = offsets[i] + row.rindex("|")
                    ranges.append((left, right, ()))
                i += 1
        elif (prefix := _UL.match(line) or _OL.match(line)) is not None:
            start, end = at + prefix.end(), at + len(line)
            indent = len(line) - len(line.lstrip())
            while items and items[-1][0] >= indent:
                items.pop()
            own = _markers(masked, start, end)
            inherited = items[-1][1] if items and not own else ()
            items.append((indent, own or inherited))
            ranges.append((start, end, inherited))
            i += 1
        elif _HEADING.match(line):
            i += 1
        else:
            first = i
            i += 1
            while i < len(lines) and not _starts_block(lines[i]):
                i += 1
            wraps = first + 1 < i
            if _is_title(line, masked[at : at + len(line)], wraps=wraps) and _content_follows(
                lines, first + 1
            ):
                # The line is a section title. The paragraph starts on the next line.
                if not wraps:
                    continue
                at = offsets[first + 1]
            stop = offsets[i] - 1
            paragraph = _mask_code(markdown[at:stop], _PARAGRAPH_CODE_SPAN)
            masked = masked[:at] + paragraph + masked[stop:]
            ranges.extend((start, end, ()) for start, end in _sentences(masked, at, stop))
    claims = [_claim(markdown, masked, start, end, inherited) for start, end, inherited in ranges]
    return [claim for claim in claims if claim is not None]


# --- citation statuses ----------------------------------------------------------------------

_RUN_ID = re.compile(r"[0-9]{1,19}")
_WORDS: tuple[str, ...] = get_args(EvidenceWord)
_WORD = "|".join(re.escape(word) for word in _WORDS)
_CLAIM_WORD = re.compile(rf"(?<![\w-])({_WORD})(?![\w-])", re.IGNORECASE)
_RESULT_WORD = re.compile(rf"(?<![\w-])({_WORD})(?![\w-])")
_CITED = frozenset({"cited", "prior-turn"})
# A claim that states what the assistant did. It starts with "I".
_PROCESS = re.compile(r"[*_\s]*I(?:['\u2019](?:ve|m|d|ll))?\s+[^\W\d_]")


def provenance_json(provenance: Provenance | None) -> dict[str, Any] | None:
    """The `ai_steps.provenance` of one step. It holds the run the step read,
    the health and the manifest digest of that run, the engine and the
    queries."""
    if provenance is None:
        return None
    run = provenance.run if isinstance(provenance.run, Mapping) else {}
    snapshot = provenance.snapshot
    return {
        "snapshot": snapshot if isinstance(snapshot, str) and _RUN_ID.fullmatch(snapshot) else None,
        "degraded": bool(run["degraded"]) if "degraded" in run else None,
        "manifest_sha256": provenance.manifest_sha256,
        "engine": provenance.engine,
        "queries": [{"kind": query.kind, "id": query.id} for query in provenance.queries],
    }


def _provenance(step: AiStep) -> Mapping[str, Any]:
    return step.provenance if isinstance(step.provenance, Mapping) else {}


def step_run(step: AiStep) -> str | None:
    """The run a stored step read, from its provenance."""
    run = _provenance(step).get("snapshot")
    return run if isinstance(run, str) and _RUN_ID.fullmatch(run) else None


def result_words(step: AiStep) -> frozenset[str]:
    """The vocabulary words a step's result holds as a key or a value. A JSON
    result counts a word only as a whole string, key or value. After
    compaction the words of the step's `result_summary` count."""
    if step.result is None:
        return frozenset(_RESULT_WORD.findall(step.result_summary or ""))
    text = step.result
    if text.lstrip()[:1] in ("{", "["):
        return frozenset(word for word in _WORDS if f'"{word}"' in text)
    return frozenset(_RESULT_WORD.findall(text))


@dataclass(frozen=True)
class _Cited:
    step: AiStep
    current: bool
    run: str | None


def _citation_status(
    names: Sequence[str], steps: Mapping[str, _Cited], snapshot: str | None
) -> CitationStatus:
    if not names:
        return "uncited"
    cited = [steps.get(name) for name in names]
    if any(ref is None or ref.step.is_error for ref in cited):
        return "citation-invalid"
    refs = [ref for ref in cited if ref is not None]
    if snapshot is not None and any(ref.run is not None and ref.run != snapshot for ref in refs):
        return "cross-snapshot"
    if not any(ref.current for ref in refs):
        return "prior-turn"
    return "cited"


def _evidence_status(text: str, refs: Sequence[_Cited], words: dict[str, frozenset[str]]) -> str | None:
    """The first vocabulary word of `text` that a cited step's result holds."""
    for match in _CLAIM_WORD.finditer(text):
        word = match.group(1).lower()
        for ref in refs:
            held = words.get(ref.step.id)
            if held is None:
                held = words[ref.step.id] = result_words(ref.step)
            if word in held:
                return word
    return None


def grounding(statuses: Sequence[str], *, called_tool: bool) -> dict[str, Any]:
    """The grounding of the citation statuses of one answer. The status is
    `grounded` when every claim other than a `process` claim is cited, cites
    an earlier turn or is matched. It is `no-evidence` when the turn called no
    tool or no claim is cited or matched. It is `partially-grounded`
    otherwise. `cited` counts the cited and prior-turn claims."""
    cited = sum(1 for status in statuses if status in _CITED)
    matched = statuses.count("matched")
    process = statuses.count("process")
    if not called_tool or cited + matched == 0:
        status: GroundingStatus = "no-evidence"
    elif cited + matched == len(statuses) - process:
        status = "grounded"
    else:
        status = "partially-grounded"
    return {
        "status": status,
        "cited": cited,
        "uncited": statuses.count("uncited"),
        "invalid": statuses.count("citation-invalid"),
        "cross_snapshot": statuses.count("cross-snapshot"),
        "matched": matched,
        "process": process,
    }


def answer_kind(answer: AgentAnswer) -> EnvelopeKind:
    if answer.declined:
        return "declined"
    if answer.answer == INCOMPLETE_ANSWER:
        return "incomplete"
    return "answer"


def _result_object(step: AiStep) -> dict[str, Any] | None:
    """The `result` object of the catalogue envelope a successful step
    stored, or None when the step failed or its result is gone or unreadable."""
    if step.is_error or not step.result:
        return None
    try:
        body = json.loads(step.result)
    except ValueError:
        return None
    result = body.get("result") if isinstance(body, dict) else None
    return result if isinstance(result, dict) else None


def _field(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else None


def object_links(step: AiStep) -> list[dict[str, Any]]:
    """The stored objects one step read, as envelope links with the label of the step.

    A successful read gives objects that exist. `assessment_read` gives an
    assessment and its run in the modes run, finding and findings, the
    reference of the finding in mode finding, and an analysis session in mode
    analysis_session. `change_get_simulation` gives an analysis session.
    `app_applications` gives an application in mode get. `inventory_get` gives
    the graph uid of a device. A failed step, a compacted step and any other
    tool give no object.
    """
    result = _result_object(step)
    if result is None:
        return []
    arguments = step.arguments if isinstance(step.arguments, dict) else {}
    mode = result.get("mode")
    found: list[tuple[str, Any, Any]] = []
    if step.tool == "assessment_read" and mode in ("run", "finding"):
        run = result.get("run")
        found += [
            ("assessment", _field(run, "assessment_id"), _field(run, "assessment_revision")),
            ("assessment_run", _field(run, "id"), None),
        ]
        if mode == "finding":
            found.append(("finding", _field(result.get("finding"), "reference"), None))
    elif step.tool == "assessment_read" and mode == "findings":
        found += [
            ("assessment", arguments.get("assessment_id"), None),
            ("assessment_run", arguments.get("run_id"), None),
        ]
    elif step.tool == "assessment_read" and mode == "analysis_session":
        session = result.get("session")
        found.append(("analysis_session", _field(session, "id"), _field(session, "revision")))
    elif step.tool == "change_get_simulation":
        found.append(("analysis_session", result.get("session_id"), None))
    elif step.tool == "app_applications" and mode == "get":
        found.append(("application", result.get("id"), result.get("revision")))
    elif step.tool == "inventory_get" and result.get("kind") == "device":
        found.append(("graph_node", _field(result.get("device"), "uid"), None))
    return [
        {
            "kind": kind,
            "ref_id": ref_id,
            "ref_revision": None if isinstance(revision, bool) or not isinstance(revision, int) else revision,
            "step": step_label(step.label),
        }
        for kind, ref_id, revision in found
        if isinstance(ref_id, str) and ref_id
    ]


def build_envelope(
    answer_markdown: str,
    *,
    message_id: str,
    conversation_id: str,
    kind: EnvelopeKind,
    snapshot: str | None,
    origin: SnapshotOrigin,
    provider: str,
    model_requested: str,
    model_served: str | None,
    prompt_hash: str,
    steps: Sequence[AiStep],
    earlier: Sequence[AiStep] = (),
) -> dict[str, Any]:
    """The answer envelope of one turn.

    `steps` are the turn's stored steps and `earlier` the steps of the earlier
    turns in the conversation's history window. A declined or incomplete
    answer has no claims. The result is checked against `AnswerEnvelope`.
    """
    known: dict[str, _Cited] = {}
    for step in earlier:
        known[step_label(step.label)] = _Cited(step, False, step_run(step))
    for step in steps:
        known[step_label(step.label)] = _Cited(step, True, step_run(step))

    claims: list[dict[str, Any]] = []
    cited_steps: dict[str, _Cited] = {}
    words: dict[str, frozenset[str]] = {}
    found: dict[str, list[support_mod.Record]] = {}

    def held(ref: _Cited, terms: support_mod.ClaimTerms) -> list[dict[str, Any]]:
        if ref.step.id not in found:
            found[ref.step.id] = support_mod.records(ref.step)
        name = step_label(ref.step.label)
        return [
            {"step": name, "pointer": record.pointer}
            for record in support_mod.supporting(terms, found[ref.step.id])
        ]

    current = [known[step_label(step.label)] for step in steps if not step.is_error]
    texts = split_claims(answer_markdown) if kind == "answer" else []
    for number, claim in enumerate(texts, start=1):
        status = _citation_status(claim.citations, known, snapshot)
        refs = [known[name] for name in claim.citations if name in known and not known[name].step.is_error]
        for name in claim.citations:
            if name in known and not known[name].step.is_error:
                cited_steps[name] = known[name]
        terms = support_mod.claim_terms(claim.text)
        support: list[dict[str, Any]] = []
        if status == "uncited":
            refs = []
            for ref in current:
                records = held(ref, terms)
                if records:
                    refs.append(ref)
                    support.extend(records)
            if refs:
                status = "matched"
                cited_steps.update((step_label(ref.step.label), ref) for ref in refs)
            elif _PROCESS.match(claim.text):
                status = "process"
        elif status != "citation-invalid":
            support = [record for ref in refs for record in held(ref, terms)]
        claims.append(
            {
                "id": f"c{number}",
                "span": [claim.start, claim.end],
                "citations": list(claim.citations),
                "evidence_status": _evidence_status(claim.text, refs, words)
                if status not in ("uncited", "citation-invalid", "process")
                else None,
                "citation_status": status,
                "support": support,
            }
        )

    used = [step for step in steps if not step.is_error] + [ref.step for ref in cited_steps.values()]
    others = [run for run in dict.fromkeys(step_run(step) for step in used) if run and run != snapshot]
    health = next(
        (_provenance(step) for step in steps if snapshot is not None and step_run(step) == snapshot),
        {},
    )
    envelope: dict[str, Any] = {
        "version": VERSION,
        "message_id": message_id,
        "conversation_id": conversation_id,
        "kind": kind,
        "snapshot": {
            "id": snapshot,
            "origin": origin,
            "manifest_sha256": health.get("manifest_sha256"),
            "degraded": health.get("degraded"),
            "others_used": others,
        },
        "model": {"provider": provider, "requested": model_requested, "served": model_served},
        "prompt_hash": prompt_hash,
        "tools_used": [
            {
                "step": step_label(step.label),
                "step_id": step.id,
                "tool": step.tool,
                "version": step.tool_version,
                "is_error": step.is_error,
                "snapshot": step_run(step),
                "engine": _provenance(step).get("engine"),
                "queries": list(_provenance(step).get("queries") or []),
            }
            for step in steps
        ],
        "answer_markdown": answer_markdown,
        "claims": claims,
        "grounding": grounding([c["citation_status"] for c in claims], called_tool=bool(steps)),
        "links": [
            {"kind": "step", "ref_id": ref.step.id, "ref_revision": None, "step": name}
            for name, ref in sorted(cited_steps.items(), key=lambda item: item[1].step.label)
        ],
    }
    # the objects the answer's steps read (`new_object_links`)
    seen: set[tuple[Any, ...]] = set()
    for step in {step.id: step for step in used}.values():
        envelope["links"] += new_object_links(object_links(step), seen)
    AnswerEnvelope.model_validate(envelope)
    return envelope


def new_object_links(links: Sequence[dict[str, Any]], seen: set[tuple[Any, ...]]) -> list[dict[str, Any]]:
    """The links of one step to an object that no earlier step linked, and
    the links that the web client needs to open them.

    A finding is one entry of one run. The key of a finding holds the run. The
    client opens a run through the assessment link of the same step, and a
    finding through the assessment and run links of the same step. A step with
    a new run keeps its assessment link. A step with a new finding keeps its
    assessment and run links. `seen` collects the keys of every link of the
    step.
    """
    run = next((link["ref_id"] for link in links if link["kind"] == "assessment_run"), None)
    keys = [
        ("finding", run, link["ref_id"])
        if link["kind"] == "finding"
        else (link["kind"], link["ref_id"], link["ref_revision"])
        for link in links
    ]
    fresh = {link["kind"] for link, key in zip(links, keys, strict=True) if key not in seen}
    needed: set[str] = set()
    if "finding" in fresh:
        needed = {"assessment", "assessment_run"}
    elif "assessment_run" in fresh:
        needed = {"assessment"}
    kept = [link for link, key in zip(links, keys, strict=True) if key not in seen or link["kind"] in needed]
    seen.update(keys)
    return kept


async def for_turn(
    runner: TurnRunner,
    answer: AgentAnswer,
    *,
    snapshot: str | None,
    origin: SnapshotOrigin,
    provider: str,
    model_requested: str,
    prompt_hash: str,
    earlier: Sequence[AiStep] = (),
) -> dict[str, Any] | None:
    """The envelope of the answer `runner` holds, built from the steps the
    turn stored. The result is None when the envelope cannot be built. The
    turn keeps its answer."""
    try:
        return build_envelope(
            answer.answer,
            message_id=runner.id,
            conversation_id=runner.conversation_id or "",
            kind=answer_kind(answer),
            snapshot=snapshot,
            origin=origin,
            provider=answer.provider or provider,
            model_requested=model_requested,
            model_served=answer.model_served,
            prompt_hash=prompt_hash,
            steps=await runner.stored_steps(),
            earlier=earlier,
        )
    except Exception:
        log.warning("the answer envelope of turn %s could not be built", runner.id, exc_info=True)
        return None


def stored_answer(stored: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The answer envelope of a stored `ai_messages.envelope`, without the
    poll fields under `payload`. None when the row holds no answer envelope
    of the current version."""
    if not isinstance(stored, Mapping) or stored.get("version") != VERSION:
        return None
    return {key: value for key, value in stored.items() if key != "payload"}
