"""Offline TextFSM parsing (ntc-templates) for the IOS-XE/IOS-XR collectors."""

from __future__ import annotations

import io
import logging
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from functools import cache, lru_cache, partial
from pathlib import Path
from typing import Any, NamedTuple

from ntc_templates.parse import _get_template_dir, parse_output
from textfsm import TextFSM, TextFSMError, clitable

from hst.core import debug_capture
from hst.core.model import SectionOutcome

from . import streams

logger = logging.getLogger(__name__)

# ntc-templates has the IOS-XE commands under the platform cisco_ios. cisco_xr
# is a separate platform.
_PLATFORM = {"iosxe": "cisco_ios", "iosxr": "cisco_xr"}

# The maximum number of lines in a preamble.
_PREAMBLE_LIMIT = 50

# `tolerating` sets this for the parse of one payload. It holds the commands
# whose TextFSM failure raises, and the record of every other failure.
_TOLERANCE: ContextVar[tuple[frozenset[str], dict[str, str]] | None] = ContextVar(
    "cli_parse_tolerance", default=None
)


@contextmanager
def tolerating(required: Iterable[str]) -> Iterator[dict[str, str]]:
    """Within the block, a TextFSM failure on a command outside `required`
    returns no records. The yielded dict maps the command to the error. A
    parser that reads no template, such as the NX-OS JSON parser, calls
    `tolerated` for the same handling.
    """
    failures: dict[str, str] = {}
    token = _TOLERANCE.set((frozenset(required), failures))
    try:
        yield failures
    finally:
        _TOLERANCE.reset(token)


def tolerated(command: str, error: str) -> bool:
    """Return whether the parse of `command` can fail.

    The result is True within `tolerating` for a command outside its required
    set, and `error` is recorded for the command. The result is False in every
    other case, and the caller raises.
    """
    tolerance = _TOLERANCE.get()
    if tolerance is None or command in tolerance[0]:
        return False
    tolerance[1][command] = error
    return True


# The directory of the repository templates that replace installed ntc-templates
# templates. Each one corrects a fault of the upstream template. The index of the
# directory lists only those commands. Every other command parses with the
# installed template.
_OVERRIDE_DIR = str(Path(__file__).with_name("templates"))

# A repository template records a line that no other rule reads into this value.
_UNREAD = "UNREAD"


class _UnreadTemplate(NamedTuple):
    """A template that declares `_UNREAD`, as the direct driver runs it.

    TextFSM applies Required before it keeps a record. The record of an unread
    line holds only that line and the Filldown values. An empty Required value
    drops such a record. `text` is the template without the Required option on
    any value. `_collect_reading` applies Required to every record that is not
    an unread line. TextFSM clears a record that it drops for Required in the
    same way as a record that it keeps.
    """

    text: str
    # The position of UNREAD among the template's values.
    unread_index: int
    # The positions of the values the template marks Required.
    required: tuple[int, ...]


class _Unread:
    """Holds the count of the lines that one parse left unread, the count of
    those lines with more than whitespace, and the first of those lines."""

    __slots__ = ("count", "first", "written")

    def __init__(self) -> None:
        self.count = 0
        self.written = 0
        self.first = ""

    def add(self, line: str) -> None:
        if not self.count:
            self.first = line
        self.count += 1
        if not line.isspace():
            self.written += 1


@lru_cache(maxsize=2)
def _index(directory: str) -> Any:
    """The parsed index of one template directory, read once."""
    return clitable.CliTable("index", directory)


@cache
def _template_dir(platform: str, command: str) -> str:
    """The override directory if its index lists (platform, command), else the
    installed ntc-templates directory."""
    if _index(_OVERRIDE_DIR).index.GetRowMatch({"Command": command, "Platform": platform}):
        return _OVERRIDE_DIR
    return _get_template_dir()


@cache
def _start_rules(platform: str, command: str) -> tuple[Any, ...] | None:
    """The `Start` state of the template for (platform, command), or None."""
    try:
        directory = _template_dir(platform, command)
        table = _index(directory)
        row = table.index.GetRowMatch({"Command": command, "Platform": platform})
        if not row:
            return None
        name = table.index.index[row]["Template"].split(":")[0]
        with (Path(directory) / name).open() as handle:
            return tuple(TextFSM(handle).states["Start"])
    except Exception:
        return None


def _preamble(platform: str, command: str, lines: list[str]) -> int:
    """Return the count of the leading lines that the `Start` state of the
    template cannot read.

    For a template without `_UNREAD`, the empty item after a final newline is
    read as a blank line. An answer is dropped whole and parses to no records
    when the `Start` state has a rule for a blank line, the template sends
    every line of the answer to Error, the answer ends in a newline and the
    answer has fewer than `_PREAMBLE_LIMIT` lines. Without the final newline,
    the template raises its error.
    """
    rules = _start_rules(platform, command)
    if rules is None:
        return 0
    counts_unread = _unread_template(platform, command) is not None
    errored = False
    for index, line in enumerate(lines[:_PREAMBLE_LIMIT]):
        if counts_unread and (not line or line.isspace()):
            continue
        for rule in rules:
            match = rule.regex_obj.match(line)
            if not match:
                continue
            if rule.line_op != "Error" and _UNREAD not in match.re.groupindex:
                return index if errored else 0
            errored = True
            break
    return 0


def parse(
    os_name: str,
    command: str,
    output: str,
    *,
    row: Callable[[dict[str, Any]], Any] | None = None,
) -> list[Any]:
    """Parse `output` (verbatim CLI text for `command`) into template records,
    offline.

    Each record is a dict from the lowercase value names of the template to
    strings (or lists of strings), as `ntc_templates.parse_output` returns it.
    With `row`, the result is `[row(record) for record in records]`. Where the
    direct driver runs (`_single_template`), the result is built one record at a
    time without a list of the records.

    A line that the template records as unread (`_UNREAD`) is left out of the
    records. `parse_with_unread` also returns the count of these lines.
    """
    return parse_with_unread(os_name, command, output, row=row)[0]


def parse_with_unread(
    os_name: str,
    command: str,
    output: str,
    *,
    row: Callable[[dict[str, Any]], Any] | None = None,
) -> tuple[list[Any], int]:
    """Return the result of `parse` and the count of the lines of `output`
    that the template left unread.

    The count is nonzero only for a repository template that records each
    line that no other rule reads (`_UNREAD`).

    TextFSMError is raised when the answer has lines with more than whitespace
    and the template read none of them.
    """
    unread = _Unread()
    with debug_capture.step(
        "textfsm", command=command, chars=len(output), lines=output.count("\n") + 1
    ) as out:
        try:
            records = _parse(os_name, command, output, row, unread)
        except TextFSMError as exc:
            if not tolerated(command, str(exc)):
                raise
            out["error"] = str(exc)
            logger.warning("%s: %r: %s; continuing without its records", os_name, command, exc)
            records = []
            unread = _Unread()
        out["records"] = len(records)
        if unread.count:
            out["unread"] = unread.count
            logger.warning(
                "%s: %r: %d line(s) of the answer could not be read and were left out, first %r",
                os_name,
                command,
                unread.count,
                unread.first[:80],
            )
        return records, unread.count


def unread_outcome(outcome: SectionOutcome, unread: int) -> SectionOutcome:
    """Return the outcome of a section whose answer held `unread` lines that
    the template could not read (`parse_with_unread`).

    An `ok` or `empty` outcome becomes `partial`. An `unknown` outcome gets
    the detail text. Any other outcome is returned unchanged.
    """
    if not unread:
        return outcome
    detail = f"{unread} {'line' if unread == 1 else 'lines'} of the answer could not be read"
    if outcome.status in ("ok", "empty"):
        return SectionOutcome(status="partial", detail=detail, row_count=outcome.row_count or 0)
    if outcome.status == "unknown":
        return outcome.model_copy(update={"detail": detail})
    return outcome


def _head(output: str) -> list[str]:
    """The first `_PREAMBLE_LIMIT` items of `output.split("\\n")`, without
    splitting the rest of the text."""
    head: list[str] = []
    start = 0
    while len(head) < _PREAMBLE_LIMIT:
        end = output.find("\n", start)
        if end < 0:
            head.append(output[start:])
            break
        head.append(output[start:end])
        start = end + 1
    return head


def _parse(
    os_name: str, command: str, output: str, row: Callable[[dict[str, Any]], Any] | None, unread: _Unread
) -> list[Any]:
    platform = _PLATFORM[os_name]
    head = _head(output)
    skipped = _preamble(platform, command, head)
    if skipped:
        logger.info(
            "%s: %r: dropped %d preamble line(s) the template cannot read, first %r",
            os_name,
            command,
            skipped,
            head[0][:80],
        )
    offset = sum(len(line) + 1 for line in head[:skipped])
    reading = _unread_template(platform, command)
    template = _single_template(platform, command) if reading is None else None
    try:
        if reading is not None:
            records = _parse_direct(reading.text, output, offset, row, (reading, unread))
            # A record comes from a line that a rule read. The lines are counted
            # only for an answer without records.
            if not records and unread.written and unread.written == _written_lines(output, offset):
                raise TextFSMError("no line of the answer could be read")
            return records
        if template is None:
            records = _parse_via_clitable(platform, command, output[offset:] if skipped else output)
            return records if row is None else [row(record) for record in records]
        return _parse_direct(template, output, offset, row)
    except TextFSMError as exc:
        # A TextFSM state error holds only a rule number and one input line.
        head_text = " | ".join(line.strip() for line in head[:3] if line.strip())
        raise TextFSMError(
            f"{os_name} ({platform}), command {command!r}: {exc}; "
            f"{skipped} preamble line(s) dropped, output starts {head_text[:160]!r}"
        ) from exc


def _written_lines(output: str, offset: int) -> int:
    """Return the count of the lines in `output[offset:]` that hold more than
    whitespace. The lines are counted one window at a time."""
    return sum(
        1
        for window in streams.line_windows(output, offset, streams.WINDOW_CHARS)
        for line in window.splitlines()
        if line and not line.isspace()
    )


def _parse_via_clitable(platform: str, command: str, data: str) -> list[dict[str, Any]]:
    """Parse with ntc-templates. CliTable finds the template in the index and
    parses the whole text at once. Every command that the direct driver does
    not take uses this function. The tests compare the direct driver with it.

    `parse` does not call this function for a template that declares UNREAD.
    CliTable runs such a template with Required, and Required drops the records
    of some unread lines (`_UnreadTemplate`). For such a template, this function
    leaves out the records of the unread lines and removes the UNREAD value from
    the other records. The result equals the records of the direct driver. The
    unread lines are not counted. When no record is left, the whole text is read
    once more with the template that `parse` runs. TextFSMError is raised when
    no line was read, as in `parse_with_unread`.
    """
    records = parse_output(
        platform=platform,
        command=command,
        template_dir=_template_dir(platform, command),
        data=data,
    )
    reading = _unread_template(platform, command)
    if reading is None:
        return records
    key = _UNREAD.lower()
    kept = [record for record in records if not record.pop(key)]
    if not kept:
        at = reading.unread_index
        result = TextFSM(io.StringIO(reading.text)).ParseText(data)
        written = sum(1 for values in result if values[at] and not values[at].isspace())
        if written and written == _written_lines(data, 0):
            raise TextFSMError("no line of the answer could be read")
    return kept


# The smallest template that shows whether the installed TextFSM keeps the state
# the direct driver relies on.
_PROBE_TEMPLATE = "Value WORD (\\S+)\n\nStart\n  ^${WORD} -> Record\n"


@cache
def _direct_supported() -> bool:
    """Return whether the installed TextFSM works as `_parse_direct` requires.

    The driver reads 2 private attributes. It empties `_result` between windows
    and stops on `_cur_state_name`. `ParseText` must return the list `_result`.
    """
    try:
        fsm = TextFSM(io.StringIO(_PROBE_TEMPLATE))
        if not isinstance(fsm._result, list) or fsm._cur_state_name != "Start":
            return False
        result = fsm.ParseText("probe\n", eof=False)
        return result is fsm._result and result == [["probe"]]
    except Exception:
        return False


@cache
def _single_template(platform: str, command: str) -> str | None:
    """The text of the one template for (platform, command) when the direct
    driver can run it, else None."""
    if not _direct_supported():
        return None
    try:
        directory = _template_dir(platform, command)
        table = _index(directory)
        row = table.index.GetRowMatch({"Command": command, "Platform": platform})
        if not row:
            return None
        name = table.index.index[row]["Template"]
        if ":" in name:
            return None
        text = (Path(directory) / name).read_text()
        if any("Fillup" in value.OptionNames() for value in TextFSM(io.StringIO(text)).values):
            return None
        return text
    except Exception:
        return None


@cache
def _unread_template(platform: str, command: str) -> _UnreadTemplate | None:
    """The template for (platform, command) as the direct driver runs it when it
    declares UNREAD, else None.

    A repository template that cannot be read raises.
    """
    try:
        # The override directory is chosen only for a command its index matches.
        if _template_dir(platform, command) != _OVERRIDE_DIR:
            return None
        table = _index(_OVERRIDE_DIR)
        row = table.index.GetRowMatch({"Command": command, "Platform": platform})
        name = table.index.index[row]["Template"]
    except Exception:
        return None
    if ":" in name:
        return None
    text = (Path(_OVERRIDE_DIR) / name).read_text()
    values = TextFSM(io.StringIO(text)).values
    names = [value.name for value in values]
    if _UNREAD not in names:
        return None
    required = tuple(index for index, value in enumerate(values) if "Required" in value.OptionNames())
    lifted = _without_required(text)
    run = TextFSM(io.StringIO(lifted)).values
    if [value.name for value in run] != names or any("Required" in value.OptionNames() for value in run):
        raise ValueError(f"{name}: the Required option could not be taken off its values")
    return _UnreadTemplate(lifted, names.index(_UNREAD), required)


def _without_required(text: str) -> str:
    """Return `text` without the Required option on any `Value` line.

    TextFSM reads a Value line as `Value [OPTIONS] NAME (REGEX)` split on single
    spaces. OPTIONS is the second token when the third token does not open the
    regex. This function reads the line in the same way."""
    lines = text.split("\n")
    for index, line in enumerate(lines):
        tokens = line.split(" ")
        if tokens[0] != "Value" or len(tokens) < 3 or tokens[2].startswith("("):
            continue
        options = [option for option in tokens[1].split(",") if option != "Required"]
        lines[index] = " ".join([tokens[0], *([",".join(options)] if options else []), *tokens[2:]])
    return "\n".join(lines)


def _parse_direct(
    template: str,
    output: str,
    offset: int,
    row: Callable[[dict[str, Any]], Any] | None,
    reading: tuple[_UnreadTemplate, _Unread] | None = None,
) -> list[Any]:
    """Run `template` over `output[offset:]` one line-aligned window at a time.

    The windows give the same records as one call on the whole text. The parser
    keeps across calls the current state, and the Filldown, List and
    Clear/Clearall values of the record that it builds. Required, Continue and
    Error act on one line or one record. Fillup and multi-template Key merges are
    not kept across calls (`_single_template`). A window ends directly after a
    newline.

    With `reading`, `template` declares UNREAD (`_UnreadTemplate`) and
    `_collect_reading` collects its records.
    """
    fsm = TextFSM(io.StringIO(template))
    keys = [name.lower() for name in fsm.header]
    records: list[Any] = []
    collect: Callable[[list[list[Any]]], None]
    if reading is None:
        collect = partial(_collect, keys=keys, row=row, records=records)
    else:
        del keys[reading[0].unread_index]
        collect = partial(
            _collect_reading, keys=keys, row=row, records=records, template=reading[0], unread=reading[1]
        )
        if not _direct_supported():
            collect(fsm.ParseText(output[offset:]))
            return records
    for window in streams.line_windows(output, offset, streams.WINDOW_CHARS):
        result = fsm.ParseText(window, eof=False)
        collect(result)
        del result[:]
        # ParseText stops reading at End or EOF and keeps the rules of the
        # previous state. With another window, it reads one more line with these
        # rules. One call on the whole text does not read after that point.
        if fsm._cur_state_name in ("End", "EOF"):
            break
    # This call makes the implicit Record at EOF. TextFSM skips the Record in the
    # End state and when the template declares an EOF state.
    collect(fsm.ParseText("", eof=True))
    return records


def _collect(
    result: list[list[Any]],
    keys: list[str],
    row: Callable[[dict[str, Any]], Any] | None,
    records: list[Any],
) -> None:
    """Append each TextFSM record in `result` to `records` as the dict
    `parse_output` builds from it, passed through `row` when given.

    The values are converted as CliTable converts them for its table. A list
    becomes a list of strings, and any other value becomes a string.
    """
    for values in result:
        record = dict(
            zip(keys, [value if type(value) is str else _to_str(value) for value in values], strict=True)
        )
        records.append(record if row is None else row(record))


def _collect_reading(
    result: list[list[Any]],
    keys: list[str],
    row: Callable[[dict[str, Any]], Any] | None,
    records: list[Any],
    template: _UnreadTemplate,
    unread: _Unread,
) -> None:
    """`_collect` for a template that declares UNREAD.

    The record of an unread line is counted in `unread` and left out. Every
    other record is kept only when each value that the template marks Required
    is set, as in TextFSM (`_UnreadTemplate`). The record is built without its
    empty UNREAD value. It equals the record that the template gives without
    UNREAD.
    """
    at = template.unread_index
    required = template.required
    for values in result:
        line = values[at]
        if line:
            unread.add(line)
            continue
        for index in required:
            if not values[index]:
                break
        else:
            del values[at]
            record = dict(
                zip(keys, [value if type(value) is str else _to_str(value) for value in values], strict=True)
            )
            records.append(record if row is None else row(record))


def _to_str(value: Any) -> Any:
    """CliTable's conversion of one record value (texttable `Row._SetValues`)."""
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return str(value)
