"""Input fragments shared by the catalogue tools: the snapshot selector, the
cursor, the limit and the argument digest.

`snapshot` is an argument of every catalogue tool. `latest` selects the run of
the published pointer. A run id selects one run. `bind` resolves the selector
once per call through `parse_snapshot_id` and the run-existence check. A run
id with no retained graph raises `snapshot_not_found` before any engine read.

A cursor is base64url JSON of `[tool, snapshot id, args_sha256, position]`.
`decode_cursor` refuses a cursor that another tool, another run or another
argument set wrote, with `cursor_mismatch`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from hst.app.ai.registry import ToolError
from hst.core import snapshot as snapshotmod

if TYPE_CHECKING:
    from hst.app.ai.registry import ToolContext

LATEST = "latest"
SNAPSHOT_PATTERN = r"^(latest|[0-9]{1,19})$"
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_CURSOR_CHARS = 4096

# A cursor and `provenance.args_sha256` leave out these arguments.
_UNHASHED = frozenset({"snapshot", "cursor", "limit"})


def _digits(value: Any) -> Any:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return str(value)
    return value


# `_digits` runs before the pattern check. The published schema has the pattern.
SnapshotSelector = Annotated[
    str,
    Field(
        pattern=SNAPSHOT_PATTERN,
        description=(
            "A run id as snapshot_list returns it (the run's collection_ts in ms), or 'latest' "
            "for the published pointer. Resolved once per call. An id whose graph rows retention "
            "removed, or that was never written, returns the error snapshot_not_found before any "
            "read. Pass envelope.snapshot.id to keep follow-up calls on the same run."
        ),
    ),
    BeforeValidator(_digits),
]

Cursor = Annotated[
    str | None,
    Field(
        max_length=MAX_CURSOR_CHARS,
        description=(
            "Opaque. Pass page.next_cursor of the previous call unchanged. It is bound to the tool "
            "name, the run and a hash of the other arguments."
        ),
    ),
]

Limit = Annotated[int, Field(ge=1, le=MAX_LIMIT, description="Items per page.")]

DeviceRef = Annotated[
    str,
    Field(
        min_length=1,
        max_length=512,
        description=(
            "A device uid, or a hostname. A hostname is matched exactly first and then as a "
            "prefix; a name that matches more than one device is an error listing the candidates."
        ),
    ),
]


Cidr = Annotated[
    str,
    Field(
        max_length=64,
        pattern=r"^[0-9A-Fa-f:.]+/[0-9]{1,3}$",
        description="An IPv4 or IPv6 prefix as address/length, e.g. 10.1.0.0/16.",
    ),
]


class Intent(BaseModel):
    """One typed change, in the shape the policy overlay and the assessments take."""

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(
        min_length=1,
        max_length=100,
        description="One of the kinds GET /api/assessment-capabilities lists (hst.simul.intents).",
    )
    params: dict[str, Any] = Field(
        default_factory=dict, max_length=100, description="The parameters the kind takes."
    )


# The maximum count of intents in one change set. `MAX_INTENTS` of
# hst/assessment/evaluation.py and of hst/app/routes/changesim.py has the same value.
MAX_INTENTS = 50


class ToolInput(BaseModel):
    """The fragment every catalogue tool input starts with."""

    model_config = ConfigDict(extra="forbid")

    snapshot: SnapshotSelector = LATEST


class PagedInput(ToolInput):
    """The fragment of a tool that returns more than one page."""

    cursor: Cursor = None
    limit: Limit = DEFAULT_LIMIT


def bind(ctx: ToolContext, session: Any, selector: str, *, field: str = "snapshot") -> snapshotmod.Snapshot:
    """The run one call reads.

    `latest` resolves the pointer, or takes the run the context pinned for a
    conversation turn. A run id is parsed by `parse_snapshot_id` and checked
    with `require_retained` before any engine read. A value that is not a run
    id raises `invalid_argument`. A run with no retained graph raises
    `snapshot_not_found`.
    """
    value = None if selector == LATEST else selector
    try:
        snapshotmod.parse_snapshot_id(value)
    except ValueError as exc:
        raise ToolError("invalid_argument", str(exc), field=field) from None
    try:
        return ctx.bind_snapshot(session, value)
    except ValueError as exc:
        raise ToolError("snapshot_not_found", str(exc), field=field) from None


def snap_binding(snapshot: snapshotmod.Snapshot) -> int | str:
    """The `$snap` parameter of a read of `snapshot`. The value is the run id,
    or the live sentinel when no run is published."""
    return snapshotmod.snap_param(snapshot.cts)


def args_sha256(params: BaseModel) -> str:
    """The sha256 of the arguments other than `snapshot`, `cursor` and `limit`,
    as canonical JSON. Two pages of one question share it."""
    other = {k: v for k, v in params.model_dump(mode="json").items() if k not in _UNHASHED}
    text = json.dumps(other, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode()).hexdigest()


def encode_cursor(tool: str, snapshot_id: str | None, digest: str, position: int) -> str:
    """The cursor of the page that starts at `position`."""
    raw = json.dumps([tool, snapshot_id, digest, position], separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str, tool: str, snapshot_id: str | None, digest: str) -> int:
    """The position that a cursor holds.

    A cursor that does not decode raises `invalid_argument`. A cursor written
    by another tool, for another run or for other arguments raises
    `cursor_mismatch`.
    """
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        value = json.loads(raw)
    except (binascii.Error, ValueError):
        raise ToolError(
            "invalid_argument", "the cursor is not one this server wrote", field="cursor"
        ) from None
    if (
        not isinstance(value, list)
        or len(value) != 4
        or not isinstance(value[3], int)
        or isinstance(value[3], bool)
        or value[3] < 0
    ):
        raise ToolError("invalid_argument", "the cursor is not one this server wrote", field="cursor")
    written_tool, written_run, written_digest, position = value
    if written_tool != tool:
        raise ToolError(
            "cursor_mismatch",
            f"the cursor was written by {written_tool}; pass a cursor that {tool} returned",
            field="cursor",
        )
    if written_run != snapshot_id:
        raise ToolError(
            "cursor_mismatch",
            f"the cursor belongs to run {written_run}, and this call reads run {snapshot_id}; "
            "pass the run of the first page as snapshot to continue",
            field="cursor",
        )
    if written_digest != digest:
        raise ToolError(
            "cursor_mismatch", "the cursor belongs to a call with other arguments", field="cursor"
        )
    return int(position)
