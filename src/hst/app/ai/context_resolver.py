"""The page context of one ask, with its request model, its checks and its rendered block.

The client describes the page that a question is asked from. The description
holds the route, the selected objects, the snapshot that the page shows, the
assessment, application or analysis session in view, and the generated
Business Application draft open in the pane. The schema is
`strata/ai/page-context/v1`.
Every object in it rejects unknown fields and every string is capped.
Oversize or unknown input fails request validation with 422.

The context is untrusted input. `ContextResolver` checks each reference before
the model sees it. It checks graph uids in one read pinned to the snapshot of
the turn, Postgres ids through the store getters, a run against its
assessment, a finding against the stored result of the run
(`hst.assessment.findings`), inventory device ids through the inventory
repository, and every reference against the permissions of the caller. It
renders one compact block of at most `MAX_BLOCK_CHARS` characters, framed as
untrusted data, that the ask appends to the system prompt. An application
draft adds a section of at most `MAX_DRAFT_CHARS` characters inside the same
frame. The section holds the YAML of the draft and the report of the generator
as the page shows them. The generation is checked against the stored
generations of the caller. A verified reference shows its graph label. Any
other reference shows its status: `not-in-snapshot`, `not-found`,
`not-permitted`, or `unverified` when the check could not run.

`record_resolution` stores a conversation turn's context and its block on the
question row (`ai_messages.context`) and records one `context.resolve` event.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, get_args

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, Strict

from hst.app.store import AiEvent
from hst.assessment import findings as findings_mod
from hst.core.snapshot import Snapshot, parse_snapshot_id

log = logging.getLogger("hst.ai")

MAX_BLOCK_CHARS = 2000
# The bounds of the draft section of the block, of the draft YAML and of the member list.
MAX_DRAFT_CHARS = 16_000
MAX_DRAFT_YAML_CHARS = 12_000
MAX_DRAFT_MEMBERS = 40

VERIFIED = "verified"
NOT_IN_SNAPSHOT = "not-in-snapshot"
NOT_FOUND = "not-found"
NOT_PERMITTED = "not-permitted"
UNVERIFIED = "unverified"


def _run_id(value: str) -> str:
    # The pattern admits 19 digits. `parse_snapshot_id` rejects a value above the 64-bit run id
    # range of the graph.
    parse_snapshot_id(value)
    return value


RunId = Annotated[str, Field(pattern=r"^[0-9]{1,19}$"), AfterValidator(_run_id)]
# Strict mode accepts JSON integers and rejects numeric strings, floats and booleans.
# Revisions and change ids are 32-bit integer columns in the store.
StoreId = Annotated[int, Strict(), Field(ge=1, le=2**31 - 1)]
PaneView = Literal[
    "hst",
    "trace",
    "explore",
    "map",
    "diff",
    "applications",
    "analysis",
    "changesim",
    "assessments",
    "sdwan",
    "equinix",
]
SelectionKind = Literal[
    "device",
    "interface",
    "ip",
    "prefix",
    "vrf",
    "site",
    "link",
    "hop",
    "service_requirement",
    "graph_node",
    "inventory_device",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RouteContext(_Strict):
    pathname: str = Field(max_length=200)
    search: str | None = Field(default=None, max_length=500)
    pane_id: str | None = Field(default=None, max_length=20)
    pane_view: PaneView | None = None
    section: str | None = Field(default=None, max_length=40)


class SelectionItem(_Strict):
    """One selected object. For kind `device`, `uid` is the graph uid and
    `inventory_id` the inventory device id when the page knows both. For kind
    `inventory_device`, `uid` is the inventory device id."""

    kind: SelectionKind
    uid: str = Field(max_length=500)
    inventory_id: str | None = Field(default=None, max_length=200)
    label: str | None = Field(default=None, max_length=200)
    source: Literal["selection", "result", "url", "pane"] | None = None


class SnapshotRef(_Strict):
    id: RunId
    origin: Literal["pinned", "page-default"]
    compare_id: RunId | None = None


class FlowContext(_Strict):
    src: str | None = Field(default=None, max_length=200)
    dst: str | None = Field(default=None, max_length=200)
    port: Annotated[int, Strict()] | Annotated[str, Field(max_length=20)] | None = None
    proto: str | None = Field(default=None, max_length=20)
    reply: bool | None = None


class SimulationContext(_Strict):
    conversation_id: uuid.UUID | None = None
    step_id: uuid.UUID | None = None
    analysis_session_id: str | None = Field(default=None, max_length=200)
    analysis_session_revision: StoreId | None = None
    change_id: StoreId | None = None


class AssessmentContext(_Strict):
    assessment_id: str = Field(max_length=200)
    revision: StoreId | None = None
    run_id: str | None = Field(default=None, max_length=200)
    finding_id: str | None = Field(default=None, max_length=200)


class ApplicationContext(_Strict):
    application_id: str = Field(max_length=200)
    revision: StoreId | None = None
    connection_ids: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=50)


class AnalysisSessionContext(_Strict):
    id: str = Field(max_length=200)
    revision: StoreId | None = None


class DraftMemberContext(_Strict):
    """One member of the generation report as the draft workspace shows it.
    It holds the decision of the generator, the candidates, the placeholder
    note of the member in the current YAML and the issues of the report."""

    path: str = Field(max_length=200)
    status: Literal["resolved", "ambiguous", "unresolved"]
    phrase: str | None = Field(default=None, max_length=200)
    uid: str | None = Field(default=None, max_length=500)
    candidates: list[Annotated[str, Field(max_length=500)]] = Field(default_factory=list, max_length=8)
    note: str | None = Field(default=None, max_length=500)
    issues: list[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=5)


class ApplicationDraftContext(_Strict):
    """The generated Business Application draft open in the pane. `yaml` is
    the text on screen. The page cuts it to `MAX_DRAFT_YAML_CHARS` and sets
    `yaml_truncated`. `edited` is true when the text differs from the
    generated text. `errors` are the YAML errors that the page lists."""

    generation_id: uuid.UUID
    status: Literal["running", "done", "error"] | None = None
    run_id: RunId | None = None
    edited: bool | None = None
    yaml: str | None = Field(default=None, max_length=MAX_DRAFT_YAML_CHARS)
    yaml_truncated: bool | None = None
    members: list[DraftMemberContext] = Field(default_factory=list, max_length=MAX_DRAFT_MEMBERS)
    members_truncated: bool | None = None
    errors: list[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=10)


class PageContext(_Strict):
    """The `strata/ai/page-context/v1` request object. The server takes the
    user and the permissions from the session."""

    version: Literal[1]
    route: RouteContext
    selection: list[SelectionItem] = Field(default_factory=list, max_length=8)
    snapshot: SnapshotRef | None = None
    flow: FlowContext | None = None
    simulation: SimulationContext | None = None
    assessment: AssessmentContext | None = None
    application: ApplicationContext | None = None
    analysis_session: AnalysisSessionContext | None = None
    application_draft: ApplicationDraftContext | None = None


# The permission that each kind of reference needs. It is the permission of the
# REST read of the same object. A kind without an entry is not permitted.
_PERMISSION: dict[str, str] = {
    **dict.fromkeys(get_args(SelectionKind), "graph.read"),
    "assessment": "graph.read",
    "analysis_run": "graph.read",
    "finding": "graph.read",
    "application": "graph.read",
    "analysis_session": "graph.read",
    # the generation routes need agent.ask
    "application_draft": "agent.ask",
}

# Every graph uid of one context, checked in one read pinned to the turn's run.
_VERIFY_UIDS = """
MATCH (n:Obj) USING INDEX n:Obj(uid, collection_ts)
WHERE n.uid IN $uids AND n.collection_ts = $snap
RETURN n.uid AS uid, labels(n) AS labels, coalesce(n.hostname, n.name) AS name"""

_OPEN = '<page_context untrusted="true">\n'
_CLOSE = "\n</page_context>"
_TRUNCATED = "\n[truncated]"
_CUT = " [truncated]"
_BARE = re.compile(r"[A-Za-z0-9_.:/@+=-]+")
_STATUS_TAG = re.compile(
    r"\[(" + "|".join((VERIFIED, NOT_IN_SNAPSHOT, NOT_FOUND, NOT_PERMITTED, UNVERIFIED)) + r")\]"
)
# A value that `_quote` wrote. The value can hold text that looks like a status tag.
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def _quote(value: object) -> str:
    """A value as a JSON string. Angle brackets are escaped and line breaks are
    written as escapes. A value cannot close the frame or start a line."""
    return json.dumps(str(value)).replace("<", "\\u003c").replace(">", "\\u003e")


def _text(value: object) -> str:
    """A value written bare when it is one plain token, quoted otherwise."""
    text = str(value)
    return text if _BARE.fullmatch(text) else _quote(text)


def _frame(lines: list[str], draft: list[str] | None = None) -> str:
    """The block. The frame with `lines` is at most `MAX_BLOCK_CHARS`
    characters. The draft section follows `lines`. `ContextResolver._draft`
    bounds the draft section to `MAX_DRAFT_CHARS`."""
    body = "\n".join(lines)
    room = MAX_BLOCK_CHARS - len(_OPEN) - len(_CLOSE)
    if len(body) > room:
        body = body[: room - len(_TRUNCATED)].rstrip() + _TRUNCATED
    if draft:
        body += "\n" + "\n".join(draft)
    return _OPEN + body + _CLOSE


def _fit_quoted(text: str, room: int) -> tuple[str, bool]:
    """`text` quoted, cut so the quoted form is at most `room` characters, and
    whether it was cut. The text is cut before quoting. No escape is split."""
    quoted = _quote(text)
    cut = False
    while len(quoted) > room and text:
        # The cut is in proportion to the quoted length and removes at least 1 character.
        text = text[: min(len(text) - 1, len(text) * max(room, 0) // len(quoted))]
        quoted = _quote(text)
        cut = True
    return quoted, cut


def status_counts(block: str) -> dict[str, int]:
    """The count of the references of a rendered block for each status. Quoted
    values are skipped. A label cannot add to a count."""
    counts: dict[str, int] = {}
    for status in _STATUS_TAG.findall(_QUOTED.sub("", block)):
        counts[status] = counts.get(status, 0) + 1
    return counts


async def record_resolution(
    store: Any,
    message_id: str,
    context: PageContext,
    block: str | None,
    *,
    user_id: int,
    surface: str,
    conversation_id: str,
    snapshot: str | None,
    latency_ms: int,
) -> None:
    """Store the page context of turn `message_id` with its rendered block on
    the question row (`ai_messages.context`) and record one `context.resolve`
    event. `snapshot` is the run the turn is pinned to. `block` is None when
    the block could not be built. The event then has the outcome 'error'. A
    failed write is logged and the turn goes on."""
    stored = {
        "page_context": context.model_dump(mode="json", exclude_none=True),
        "block": block,
        "snapshot": snapshot,
    }
    try:
        await store.set_question_context(message_id, stored)
    except Exception:
        log.warning("the page context of turn %s could not be stored", message_id, exc_info=True)
    try:
        await store.record_ai_event(
            AiEvent(
                at=datetime.now(UTC),
                origin="web",
                event="context.resolve",
                outcome="ok" if block is not None else "error",
                user_id=user_id,
                surface=surface,
                conversation_id=conversation_id,
                message_id=message_id,
                snapshot=snapshot,
                latency_ms=latency_ms,
                detail={
                    "selection": len(context.selection),
                    "statuses": status_counts(block) if block is not None else {},
                },
            )
        )
    except Exception:
        log.warning("the context.resolve event could not be recorded", exc_info=True)


class ContextResolver:
    """Checks one page context and renders it as the block the model reads.

    `store` has the assessment, run, application and analysis session
    getters. `inventory` returns the inventory repository. It is called when
    the context names an inventory device. `permissions` is the permission set
    of the caller. `user_id` is the caller. An application draft can name a
    generation of the caller. A check that cannot run marks its reference
    `unverified` and does not fail the ask.
    """

    def __init__(
        self,
        settings: Any,
        store: Any,
        permissions: frozenset[str],
        inventory: Callable[[], Any] | None = None,
        user_id: int | None = None,
    ) -> None:
        self._settings = settings
        self._store = store
        self._permissions = permissions
        self._inventory = inventory
        self._user_id = user_id

    def _allowed(self, kind: str) -> bool:
        return _PERMISSION.get(kind) in self._permissions

    async def render(self, context: PageContext, snapshot: Snapshot | None) -> str:
        """The `<page_context>` block for `context`, checked against `snapshot`,
        the run the turn is pinned to (None when the ask could not pin one)."""
        lines = [self._route(context)]
        view = [part for part in (context.route.pane_view, context.route.section) if part]
        if view:
            lines.append("view: " + "/".join(_text(part) for part in view))
        lines.append(self._snapshot(context, snapshot))

        allowed = [item for item in context.selection if self._allowed(item.kind)]
        inventory_ids = [item.uid for item in allowed if item.kind == "inventory_device"]
        inventory_ids += [
            item.inventory_id for item in allowed if item.kind == "device" and item.inventory_id
        ]
        inventory = await self._inventory_devices(inventory_ids)
        uids = {item.uid for item in allowed if item.kind != "inventory_device"}
        if inventory is not None:
            uids.update(device.graph_uid for device in inventory.values() if device is not None)
        names = await self._graph_names(sorted(uids), snapshot)
        if context.selection:
            lines.append(
                "selected: " + "; ".join(self._item(item, names, inventory) for item in context.selection)
            )

        if context.flow is not None:
            lines.append(self._flow(context.flow))
        if context.assessment is not None:
            lines.append(await self._assessment(context.assessment))
        if context.application is not None:
            lines.append(await self._application(context.application))
        if context.analysis_session is not None:
            session = context.analysis_session
            lines.append("analysis session: " + await self._session(session.id, session.revision))
        if context.simulation is not None:
            lines.append(await self._simulation(context.simulation))
        draft = None
        if context.application_draft is not None:
            draft = await self._draft(context.application_draft)
        return _frame(lines, draft)

    # --- checks -------------------------------------------------------------------

    async def _graph_names(self, uids: list[str], snapshot: Snapshot | None) -> dict[str, Any] | None:
        """A map of graph uid to label for every uid that the run of the turn
        holds, or None when the read could not run."""
        if not uids:
            return {}
        if snapshot is None:
            return None
        try:
            return await asyncio.to_thread(self._read_names, uids, snapshot)
        except Exception:
            log.warning("page context graph check failed", exc_info=True)
            return None

    def _read_names(self, uids: list[str], snapshot: Snapshot) -> dict[str, Any]:
        # The import is deferred. `hst.path` imports core modules at load time.
        from hst import path as pathmod
        from hst.core import db as dbmod

        with dbmod.session(self._settings, access_mode="READ") as session:
            rows = pathmod._read(pathmod.pinned(session, snapshot), _VERIFY_UIDS, uids=uids)
        return {str(row["uid"]): row.get("name") for row in rows}

    async def _inventory_devices(self, ids: list[str]) -> dict[str, Any] | None:
        """A map of inventory id to device. The value is None when the
        repository holds no such device. An id that is not a UUID is absent. The
        result is None when the repository could not be read."""
        parsed: dict[str, uuid.UUID] = {}
        for raw in ids:
            try:
                parsed[raw] = uuid.UUID(raw)
            except ValueError:
                continue
        if not parsed:
            return {}
        try:
            if self._inventory is None:
                return None
            repo = self._inventory()
            async with repo.transaction() as tx:
                devices = await tx.get_devices(sorted(set(parsed.values())))
        except Exception:
            log.warning("page context inventory check failed", exc_info=True)
            return None
        by_id = {device.id: device for device in devices}
        return {raw: by_id.get(value) for raw, value in parsed.items()}

    async def _lookup(self, getter: str, *args: Any, **kwargs: Any) -> tuple[str, Any]:
        """Call one store getter and return (status, item)."""
        read = getattr(self._store, getter, None)
        if read is None:
            return UNVERIFIED, None
        try:
            item = await read(*args, **kwargs)
        except Exception:
            log.warning("page context check %s failed", getter, exc_info=True)
            return UNVERIFIED, None
        return (VERIFIED, item) if item is not None else (NOT_FOUND, None)

    # --- rendering ----------------------------------------------------------------

    @staticmethod
    def _route(context: PageContext) -> str:
        route = context.route.pathname
        if context.route.search:
            search = context.route.search
            route += search if search.startswith("?") else "?" + search
        return "route: " + _text(route)

    @staticmethod
    def _snapshot(context: PageContext, snapshot: Snapshot | None) -> str:
        if snapshot is None or snapshot.cts is None:
            line = "snapshot: none"
        elif context.snapshot is None:
            line = f"snapshot: {snapshot.cts} (current run)"
        else:
            origin = "pinned by page" if context.snapshot.origin == "pinned" else "page default"
            line = f"snapshot: {snapshot.cts} ({origin})"
        if context.snapshot is not None and context.snapshot.compare_id:
            line += f", compare {context.snapshot.compare_id}"
        return line

    def _item(
        self, item: SelectionItem, names: dict[str, Any] | None, inventory: dict[str, Any] | None
    ) -> str:
        head = f"{item.kind} {_text(item.uid)}"
        if not self._allowed(item.kind):
            return f"{head} [{NOT_PERMITTED}]"
        client_label = f" {_quote(item.label)}" if item.label else ""

        if item.kind == "inventory_device":
            if inventory is None:
                return f"{head}{client_label} [{UNVERIFIED}]"
            device = inventory.get(item.uid)
            if device is None:
                return f"{head}{client_label} [{NOT_FOUND}]"
            status, name = self._graph_status(device.graph_uid, names)
            label = name if status == VERIFIED and name else device.hostname
            label_text = f" {_quote(label)}" if label else ""
            return f"{head} {_text(device.graph_uid)}{label_text} [{status}]"

        status, name = self._graph_status(item.uid, names)
        verified_label = f" {_quote(name)}" if name else ""
        label_text = verified_label if status == VERIFIED else client_label
        line = f"{head}{label_text} [{status}]"
        if item.kind == "device" and item.inventory_id:
            line += f" inventory {_text(item.inventory_id)} [{self._inventory_status(item, inventory)}]"
        return line

    @staticmethod
    def _graph_status(uid: str, names: dict[str, Any] | None) -> tuple[str, Any]:
        if names is None:
            return UNVERIFIED, None
        if uid in names:
            return VERIFIED, names[uid]
        return NOT_IN_SNAPSHOT, None

    @staticmethod
    def _inventory_status(item: SelectionItem, inventory: dict[str, Any] | None) -> str:
        if inventory is None:
            return UNVERIFIED
        device = inventory.get(item.inventory_id or "")
        # the inventory id must name the device the graph uid names
        return VERIFIED if device is not None and device.graph_uid == item.uid else NOT_FOUND

    @staticmethod
    def _flow(flow: FlowContext) -> str:
        parts = [
            f"{name} {_text(value)}"
            for name, value in (
                ("src", flow.src),
                ("dst", flow.dst),
                ("port", flow.port),
                ("proto", flow.proto),
            )
            if value is not None and value != ""
        ]
        if flow.reply is not None:
            parts.append("reply " + ("yes" if flow.reply else "no"))
        return "flow: " + (", ".join(parts) if parts else "none")

    async def _assessment(self, assessment: AssessmentContext) -> str:
        head = _text(assessment.assessment_id)
        if assessment.revision is not None:
            head += f" rev {assessment.revision}"
        if not self._allowed("assessment"):
            parts = [f"{head} [{NOT_PERMITTED}]"]
        else:
            status, _ = await self._lookup("get_assessment", assessment.assessment_id, assessment.revision)
            parts = [f"{head} [{status}]"]

        run_status, run = UNVERIFIED, None
        if assessment.run_id:
            if not self._allowed("analysis_run"):
                run_status = NOT_PERMITTED
            else:
                run_status, run = await self._lookup("get_analysis_run", assessment.run_id)
            owner = getattr(run, "assessment_id", None) if run is not None else None
            if owner is not None and owner != assessment.assessment_id:
                # The run belongs to another assessment.
                run_status, run = NOT_FOUND, None
            state = f" ({_text(run.state)})" if run is not None else ""
            parts.append(f"run {_text(assessment.run_id)}{state} [{run_status}]")

        if assessment.finding_id:
            if not self._allowed("finding"):
                status = NOT_PERMITTED
            elif run is not None:
                located = findings_mod.locate(run.result, getattr(run, "kind", None), assessment.finding_id)
                status = VERIFIED if located is not None else NOT_FOUND
            elif run_status == NOT_FOUND:
                status = NOT_FOUND
            else:
                # The context names no run, or the run could not be read.
                status = UNVERIFIED
            parts.append(f"finding {_text(assessment.finding_id)} [{status}]")
        return "assessment: " + ", ".join(parts)

    async def _application(self, application: ApplicationContext) -> str:
        head = _text(application.application_id)
        if application.revision is not None:
            head += f" rev {application.revision}"
        if self._allowed("application"):
            status, _ = await self._lookup(
                "get_application", application.application_id, application.revision
            )
        else:
            status = NOT_PERMITTED
        line = f"application: {head} [{status}]"
        if application.connection_ids:
            line += ", connections " + ", ".join(_text(c) for c in application.connection_ids)
        return line

    async def _session(self, session_id: str, revision: int | None) -> str:
        head = _text(session_id)
        if revision is not None:
            head += f" rev {revision}"
        if not self._allowed("analysis_session"):
            return f"{head} [{NOT_PERMITTED}]"
        status, _ = await self._lookup("get_analysis_session", session_id, revision)
        return f"{head} [{status}]"

    async def _simulation(self, simulation: SimulationContext) -> str:
        parts = []
        if simulation.conversation_id is not None:
            parts.append(f"conversation {simulation.conversation_id}")
        if simulation.step_id is not None:
            parts.append(f"step {simulation.step_id}")
        if simulation.analysis_session_id:
            session = await self._session(
                simulation.analysis_session_id, simulation.analysis_session_revision
            )
            parts.append("analysis session " + session)
        if simulation.change_id is not None:
            parts.append(f"change {simulation.change_id}")
        return "simulation: " + (", ".join(parts) if parts else "none")

    # --- the application draft ----------------------------------------------------

    async def _generation(self, generation_id: str) -> tuple[str, Any]:
        """(status, stored record) of the caller's generation `generation_id`.
        A generation of another user has the status `not-found`, as on its
        poll route. A running generation has no record. Its turn is the
        service_generator message of the caller with the same id."""
        if not self._allowed("application_draft"):
            return NOT_PERMITTED, None
        if self._user_id is None:
            return UNVERIFIED, None
        status, record = await self._lookup("get_application_generation", generation_id)
        if status == VERIFIED:
            owned = isinstance(record, dict) and record.get("created_by") == self._user_id
            return (VERIFIED, record) if owned else (NOT_FOUND, None)
        if status == UNVERIFIED:
            return UNVERIFIED, None
        status, message = await self._lookup(
            "get_message", self._user_id, generation_id, surface="service_generator"
        )
        if status == VERIFIED and getattr(message, "role", None) != "assistant":
            status = NOT_FOUND
        return status, None

    async def _draft(self, draft: ApplicationDraftContext) -> list[str]:
        """The draft section. It holds a head line with the checked generation,
        one line per member and the YAML last. The section is at most
        `MAX_DRAFT_CHARS` characters."""
        status, record = await self._generation(str(draft.generation_id))
        head = f"application draft: generation {draft.generation_id} [{status}]"
        snapshot = record.get("snapshot") if isinstance(record, dict) else None
        recorded = snapshot.get("snapshot") if isinstance(snapshot, dict) else None
        if recorded:
            head += f", run {_text(recorded)} (recorded)"
        elif draft.run_id:
            head += f", run {draft.run_id} (page)"
        if draft.status:
            head += f", {draft.status}"
        if draft.edited is not None:
            head += ", edited on the page" if draft.edited else ", as generated"
        lines = [head]
        if status == NOT_PERMITTED:
            return lines
        if draft.errors:
            lines.append("draft errors: " + "; ".join(_quote(error) for error in draft.errors))
        members = [self._draft_member(member) for member in draft.members]
        if draft.members_truncated:
            members.append(f"draft members: only the first {len(draft.members)} sent by the page")
        used = sum(len(line) + 1 for line in lines)
        # the YAML keeps at least a quarter of the section
        member_room = MAX_DRAFT_CHARS - len(_CLOSE) - (MAX_DRAFT_CHARS // 4 if draft.yaml else 0)
        for index, line in enumerate(members):
            if used + len(line) + 1 > member_room:
                lines.append(f"draft members: {len(members) - index} more not shown [truncated]")
                used += len(lines[-1]) + 1
                break
            lines.append(line)
            used += len(line) + 1
        if draft.yaml:
            label = "draft yaml (cut by the page): " if draft.yaml_truncated else "draft yaml: "
            room = MAX_DRAFT_CHARS - used - len(label) - len(_CUT)
            quoted, cut = _fit_quoted(draft.yaml, room)
            lines.append(label + quoted + (_CUT if cut else ""))
        return lines

    @staticmethod
    def _draft_member(member: DraftMemberContext) -> str:
        parts = [f"draft member {_text(member.path)}: {member.status}"]
        if member.phrase:
            parts.append(f"phrase {_quote(member.phrase)}")
        if member.uid:
            parts.append(f"uid {_text(member.uid)}")
        if member.candidates:
            parts.append("candidates " + ", ".join(_text(c) for c in member.candidates))
        if member.note:
            parts.append(f"note {_quote(member.note)}")
        if member.issues:
            parts.append("issues " + "; ".join(_quote(issue) for issue in member.issues))
        return ", ".join(parts)
