"""Scaffolding shared by the SSH CLI collectors (VyOS and the Cisco trio)."""

from __future__ import annotations

import asyncio
import json
import logging
from abc import abstractmethod
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from contextlib import asynccontextmanager, contextmanager
from itertools import islice
from typing import Any, ClassVar, Literal, NamedTuple

from pydantic import Field, ValidationError

from hst.core import Settings, redaction
from hst.core.model import DEGRADING_SECTION_STATUSES, Batch, SectionOutcome, SectionStatus, TableOutcome

from . import assh, cli_parse, ssh
from .auth import SshAuth, SshJumpHost
from .base import RAW_OUTCOMES_KEY, Collector, SourceConfig
from .cisco_common import device_uid, normalize_cisco, side_rows

logger = logging.getLogger(__name__)

# Device wording for a command the credential is not allowed to run.
_UNAUTHORIZED_MARKERS = (
    "permission denied",
    "not authorized",
    "authorization failed",
    "access denied",
    "insufficient privilege",
)
# The rejection banners for a command that the device does not have.
_UNSUPPORTED_MARKERS = (
    "% invalid input",
    "% invalid command",
    "% incomplete command",
    "% ambiguous command",
    "% unknown command",
    "% unrecognized command",
    "line has invalid autocommand",
    # NX-OS answers on an exec channel with exit status 16 and this line. The
    # NX-OS shell prints the `%` banner. The NX-OS parser has no command of a
    # feature that is not enabled (`feature ospf`, `feature vpc`, `feature lldp`).
    "syntax error while parsing",
)


# A fetch stops sending optional path commands after this number of timeouts in a row.
PATH_TIMEOUT_LIMIT = 2


def not_sent_after_timeouts(timeouts: int) -> dict[str, str]:
    """The outcome of an optional command a fetch did not send because the
    commands before it timed out."""
    return {"status": "failed", "detail": f"not sent: the {timeouts} commands before it timed out"}


# The note is appended to the detail of a refused command that the platform
# has on every release (`SshCliCollector.ALWAYS_PRESENT_COMMANDS`).
_ALWAYS_PRESENT_NOTE = (
    "; the command exists on every release of this platform, so the refusal is a permission"
)


def classify_command_failure(
    exc: Exception, *, command: str | None = None, always_present: Collection[str] = ()
) -> tuple[SectionStatus, str]:
    """Return (status, detail) for one command that the device refused.

    A command in `always_present` exists on every release of the platform. A
    privilege-1 account gets the answer `% Invalid input` in a shell and
    `Line has invalid autocommand` on an exec channel. A missing feature gets
    the same answers. The refusal of a command in `always_present` is
    `unauthorized`.
    """
    detail = str(exc)
    text = detail.lower()
    if any(m in text for m in _UNAUTHORIZED_MARKERS):
        return "unauthorized", detail
    if any(m in text for m in _UNSUPPORTED_MARKERS):
        if command is not None and command in always_present:
            return "unauthorized", detail + _ALWAYS_PRESENT_NOTE
        return "unsupported", detail
    return "failed", detail


def failed_feature_outcome(
    recorded: Mapping[str, SectionOutcome], commands: Iterable[str], feature: str
) -> TableOutcome | None:
    """Return a `failed` table outcome that lists every command of `commands`
    that did not answer (failed, refused or unparsed), or None when every
    command answered."""
    bad = [
        f"{command!r}={recorded[command].status}"
        for command in commands
        if command in recorded and recorded[command].status in DEGRADING_SECTION_STATUSES
    ]
    if not bad:
        return None
    return TableOutcome(status="failed", detail=f"{feature} command did not answer: " + ", ".join(bad))


def recorded_outcomes(raw: Mapping[str, Any]) -> dict[str, SectionOutcome]:
    """The per-command outcomes a fetch recorded under `RAW_OUTCOMES_KEY`.

    An entry that does not validate gets the status `unknown`.
    """
    stored = raw.get(RAW_OUTCOMES_KEY)
    if not isinstance(stored, Mapping):
        return {}
    out: dict[str, SectionOutcome] = {}
    for command, entry in stored.items():
        if not isinstance(entry, Mapping):
            continue
        try:
            out[str(command)] = SectionOutcome.model_validate(dict(entry))
        except ValidationError:
            out[str(command)] = SectionOutcome(status="unknown")
    return out


class Section(NamedTuple):
    """The description of one named section of a payload.

    `command` is the command that produced the section. `rows_key` is the key
    of the intermediate-shape list whose length is the row count of the
    section. With None, the section has no rows and the raw text decides
    whether the section is empty. `table` is the NX-OS
    `TABLE_<table>`/`ROW_<table>` wrapper that holds the rows.

    `empty_answer` holds the words of the empty answer of a row-shaped text
    section. An empty tuple means that the command has no empty answer.
    With None, the default, a section without rows is `empty`.
    """

    command: str
    rows_key: str | None = None
    table: str | None = None
    empty_answer: tuple[str, ...] | None = None


def _table_rows(payload: Any, table: str) -> int:
    """Return the row count of an NX-OS `TABLE_<table>`/`ROW_<table>` wrapper.
    A single row is a bare dict."""
    wrapper = payload.get(f"TABLE_{table}")
    rows = wrapper.get(f"ROW_{table}") if isinstance(wrapper, dict) else None
    if isinstance(rows, dict):
        return 1
    return len(rows or [])


def _blank(text: Any) -> bool:
    if isinstance(text, str):
        return not text or text.isspace()
    return not str(text or "").strip()


def _content_status(text: Any, rows: int | None, table: str | None) -> tuple[SectionStatus, int | None]:
    """Return the status and the row count of a section whose command succeeded.

    An empty payload is `empty`. A non-empty payload is `malformed` if it is
    text that is not JSON, JSON that is not an object, or an object without
    `TABLE_<table>`.
    """
    if rows:
        return "ok", rows
    if table is not None:
        if _blank(text):
            return "empty", 0
        try:
            payload = json.loads(text) if isinstance(text, str) else text
        except ValueError:
            return "malformed", None
        if isinstance(payload, dict) and not payload:
            return "empty", 0
        if not isinstance(payload, dict) or f"TABLE_{table}" not in payload:
            return "malformed", None
        count = _table_rows(payload, table) if rows is None else rows
        return ("ok", count) if count else ("empty", 0)
    if rows is not None:
        return "empty", 0
    return ("empty", None) if _blank(text) else ("ok", None)


# The key of the intermediate shape for the parse failures. The value maps an
# optional command to its TextFSM error (`CiscoCliCollector._inter`).
PARSE_FAILURES_KEY = "parse_failures"


def effective_outcomes(
    raw: Mapping[str, Any], inter: Mapping[str, Any], always_present: Collection[str] = ()
) -> dict[str, SectionOutcome]:
    """Return `recorded_outcomes` with 3 changes. An optional command that the
    parse could not read (`cli_parse.tolerating`) is `malformed`.

    An answer recorded `ok` that starts with a rejection banner
    (`ssh._CLI_ERROR_MARKERS`) is a refusal.

    A command in `always_present` recorded `unsupported` is `unauthorized`
    (`classify_command_failure`).
    """
    outcomes = recorded_outcomes(raw)
    for command, current in list(outcomes.items()):
        if current.status == "unsupported" and command in always_present:
            outcomes[command] = SectionOutcome(
                status="unauthorized", detail=current.detail + _ALWAYS_PRESENT_NOTE
            )
            continue
        text = raw.get(command)
        if current.status != "ok" or not isinstance(text, str):
            continue
        rejection = ssh.opening_rejection(text)
        if rejection is not None:
            status, detail = classify_command_failure(
                ssh.CommandFailed(f"{command!r} rejected by device: {rejection}"),
                command=command,
                always_present=always_present,
            )
            outcomes[command] = SectionOutcome(status=status, detail=detail)
    for command, error in (inter.get(PARSE_FAILURES_KEY) or {}).items():
        current = outcomes.get(command)
        if current is None or current.status == "ok":
            outcomes[command] = SectionOutcome(status="malformed", detail=error)
    return outcomes


def build_sections(
    raw: Mapping[str, Any],
    inter: Mapping[str, Any],
    specs: Mapping[str, Section],
    always_present: Collection[str] = (),
) -> dict[str, SectionOutcome]:
    """Return the outcome of each section name for one fetched payload and its
    parse.

    A section whose command has no recorded outcome is `unknown`.
    """
    recorded = effective_outcomes(raw, inter, always_present)
    sections: dict[str, SectionOutcome] = {}
    for name, spec in specs.items():
        outcome = recorded.get(spec.command)
        if outcome is None:
            sections[name] = SectionOutcome(status="unknown")
            continue
        if outcome.status != "ok":
            sections[name] = outcome
            continue
        rows = len(inter.get(spec.rows_key) or []) if spec.rows_key is not None else None
        text = raw.get(spec.command)
        status, row_count = _content_status(text, rows, spec.table)
        if status == "empty" and _unrecognized_empty(text, spec.empty_answer):
            sections[name] = SectionOutcome(
                status="malformed",
                detail="the answer is not blank and parsed to no rows: " + _first_line(text),
            )
            continue
        sections[name] = SectionOutcome(status=status, row_count=row_count)
    return sections


def _unrecognized_empty(text: Any, empty_answer: tuple[str, ...] | None) -> bool:
    """Return whether the answer of a section without rows is text that is not
    blank and does not hold the empty answer of the command
    (`Section.empty_answer`)."""
    if empty_answer is None or not isinstance(text, str) or _blank(text):
        return False
    return not any(words in text for words in empty_answer)


def _first_line(text: str) -> str:
    """The first line of an answer that is not blank, for an outcome's detail."""
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


# A docstring on this class would become the JSON-schema description of all four models.
class SshSourceConfig(SourceConfig):
    # The host is empty for a device group.
    host: str = ""
    auth: SshAuth
    port: int = 22
    jump_host: SshJumpHost | None = None
    host_key: str = ""  # The key is empty until first contact and pinned after it.
    # paramiko 5 and later has no SHA-1 key exchange.
    transport: Literal["asyncssh", "paramiko"] = "asyncssh"
    fresh_connection_per_command: bool = Field(
        default=False,
        description=(
            "Open a fresh SSH connection for each command. Enable for devices that close "
            "the connection after one command. Adds a login for every command and can "
            "make collection slower."
        ),
    )
    channel: Literal["exec", "shell"] = Field(
        default="exec",
        description=(
            "How commands reach the device. 'exec' opens one exec channel per command. "
            "'shell' opens one interactive shell for the whole fetch and delimits each "
            "command by the device's prompt, so a login banner arrives once and reaches "
            "no parser. Use 'shell' for a device that answers no exec channel, or that "
            "prints a banner into every one."
        ),
    )
    # `read_timeout` is per read for paramiko and in total for asyncssh.
    timeout: int = 120
    connect_timeout: int = 10
    read_timeout: int = ssh.DEFAULT_READ_TIMEOUT


def _split_lines(text: str) -> Iterator[str]:
    """Yield the items of `text.split("\\n")` one at a time.

    The last item is "" when the text ends with a newline. An empty text
    gives one "".
    """
    start = 0
    while True:
        end = text.find("\n", start)
        if end < 0:
            yield text[start:]
            return
        yield text[start:end]
        start = end + 1


def exec_banner_of(outputs: Iterable[str]) -> str:
    """Return the lines that every output starts with, or "".

    An exec channel is a new EXEC session per command. A device prints its
    login banner into each session before the output of the command.
    """
    texts = list(outputs)
    if len(texts) < 2:
        return ""
    first = texts[0]
    # None means that every line of the first answer is shared.
    shared: int | None = None
    for text in texts[1:]:
        count = 0
        for mine, theirs in zip(islice(_split_lines(first), shared), _split_lines(text), strict=False):
            if mine != theirs:
                break
            count += 1
        if count == 0:
            return ""
        shared = count
    return "\n".join(islice(_split_lines(first), shared)) + "\n"


def without_exec_banner(text: str, banner: str) -> str:
    """Return `text` without `banner` at its start. An answer that is a prefix
    of the banner, such as the banner without its last newline, gives ""."""
    if not banner:
        return text
    if text.startswith(banner):
        return text[len(banner) :]
    if banner.startswith(text):
        return ""
    return text


class _AsyncSessionFacade:
    """A sync `ssh.SshSession` with the async session interface."""

    def __init__(self, s) -> None:
        self._s = s
        self.host_key = s.host_key
        self.jump_host_key = s.jump_host_key

    async def run(self, command: str) -> str:
        return self._s.run(command)


class _FreshConnectionSession:
    """The command-session interface with a new connection for every run.

    A reconnect checks the host keys against the first keys of the fetch.
    """

    def __init__(self, host: str, auth: SshAuth, kwargs: dict, transport: str) -> None:
        self._host = host
        self._auth = auth
        self._kwargs = kwargs
        self._transport = transport
        self.host_key = ""
        self.jump_host_key = ""

    def _connection_kwargs(self) -> dict:
        kwargs = dict(self._kwargs)
        if self.host_key:
            kwargs["known_host_key"] = self.host_key
        jump = kwargs.get("jump")
        if jump is not None and self.jump_host_key:
            kwargs["jump"] = jump.model_copy(update={"host_key": self.jump_host_key})
        return kwargs

    def _observe(self, session) -> None:
        self.host_key = session.host_key
        self.jump_host_key = session.jump_host_key

    async def run(self, command: str) -> str:
        kwargs = self._connection_kwargs()
        if self._transport == "asyncssh":
            async with assh.session(self._host, self._auth, **kwargs) as session:
                self._observe(session)
                return await session.run(command)
        # The paramiko collector runs this entire loop in its worker thread.
        with ssh.session(self._host, self._auth, **kwargs) as session:
            self._observe(session)
            return session.run(command)


class SshCliCollector(Collector):
    """Requires a config with the `SshSourceConfig` fields."""

    COMMANDS: ClassVar[tuple[str, ...]] = ()
    # Maps a command to the raw output that replaces the answer when the device
    # refuses the command.
    OPTIONAL_COMMANDS: ClassVar[dict[str, str]] = {}
    # These commands run first in an interactive shell, before any collected
    # command, when the source sets `channel="shell"`.
    SHELL_SETUP: ClassVar[tuple[str, ...]] = ()
    # When True, the login banner is removed from every answer of an exec
    # channel after the fetch has all answers (`exec_banner_of`).
    STRIP_EXEC_BANNER: ClassVar[bool] = False
    # Optional commands the platform has on every release.
    ALWAYS_PRESENT_COMMANDS: ClassVar[frozenset[str]] = frozenset()

    def __init__(self, config, settings):
        super().__init__(config, settings)
        self.observed_host_key = ""
        self.observed_jump_key = ""

    @property
    def transport(self) -> str:
        return getattr(self.config, "transport", "asyncssh")

    def _session_kwargs(self) -> dict:
        c = self.config
        return {
            "port": c.port,
            "jump": c.jump_host,
            "known_host_key": c.host_key,
            "timeout": getattr(c, "timeout", 120),
            "connect_timeout": getattr(c, "connect_timeout", 10),
            "read_timeout": getattr(c, "read_timeout", ssh.DEFAULT_READ_TIMEOUT),
            "channel": getattr(c, "channel", "exec"),
            "shell_setup": self.SHELL_SETUP,
            "max_answer_mb": self._max_answer_mb(),
        }

    def _max_answer_mb(self) -> int:
        """`COLLECT_MAX_ANSWER_MB`, or its default for a collector built without settings."""
        limit = getattr(self.settings, "collect_max_answer_mb", None)
        if limit is None:
            return Settings.model_fields["collect_max_answer_mb"].default
        return limit

    @contextmanager
    def _session(self):
        c = self.config
        with ssh.session(c.host, c.auth, **self._session_kwargs()) as s:
            try:
                yield s
            finally:
                self.observed_host_key = s.host_key
                self.observed_jump_key = s.jump_host_key

    @asynccontextmanager
    async def _asession(self):
        c = self.config
        async with assh.session(c.host, c.auth, **self._session_kwargs()) as s:
            try:
                yield s
            finally:
                self.observed_host_key = s.host_key
                self.observed_jump_key = s.jump_host_key

    def _run(self, command: str) -> str:
        if self.transport == "asyncssh":
            return asyncio.run(self._arun(command))
        with self._session() as s:
            return s.run(command)

    async def _arun(self, command: str) -> str:
        async with self._asession() as s:
            return await s.run(command)

    async def _afetch_over(self, s) -> dict[str, Any]:
        """Run the command loop over a session with an async `run`.

        The outcome of every command is recorded under `RAW_OUTCOMES_KEY`
        beside the outputs. `raw_sha` excludes the key.
        """
        raw: dict[str, Any] = {}
        outcomes: dict[str, dict[str, Any]] = {}
        for cmd in self.COMMANDS:
            self.check_stop()
            try:
                raw[cmd] = await s.run(cmd)
                outcomes[cmd] = {"status": "ok"}
            except ssh.CommandFailed as exc:
                if cmd not in self.OPTIONAL_COMMANDS:
                    raise
                logger.warning(
                    "%s: %r failed (%s); continuing without it",
                    self.name,
                    cmd,
                    redaction.redact_text(str(exc)),
                )
                raw[cmd] = self.OPTIONAL_COMMANDS[cmd]
                status, detail = classify_command_failure(
                    exc, command=cmd, always_present=self.ALWAYS_PRESENT_COMMANDS
                )
                outcomes[cmd] = {"status": status, "detail": detail}
        raw[RAW_OUTCOMES_KEY] = outcomes
        return raw

    async def _afetch_clean(self, s) -> dict[str, Any]:
        """Run the whole fetch over `s` and remove the exec channel banner from every answer."""
        raw = await self._afetch_over(s)
        self._strip_exec_banner(raw)
        return raw

    def _strip_exec_banner(self, raw: dict[str, Any]) -> None:
        """The banner is taken off only on an exec channel."""
        if not self.STRIP_EXEC_BANNER or getattr(self.config, "channel", "exec") != "exec":
            return
        outcomes = raw.get(RAW_OUTCOMES_KEY)
        answered = [
            command
            for command, text in raw.items()
            if command != RAW_OUTCOMES_KEY
            and isinstance(text, str)
            and (not isinstance(outcomes, dict) or (outcomes.get(command) or {}).get("status") == "ok")
        ]
        banner = exec_banner_of(raw[command] for command in answered)
        if not banner:
            return
        logger.info(
            "%s: the exec channel printed %d banner line(s) in front of every command, first %r; removed",
            self.name,
            banner.count("\n"),
            banner.split("\n", 1)[0][:80],
        )
        for command in answered:
            raw[command] = without_exec_banner(raw[command], banner)

    async def afetch(self) -> dict[str, Any]:
        """The async entry that the collection engine awaits for asyncssh devices."""
        if self.transport != "asyncssh":
            return await asyncio.to_thread(self.fetch)
        if self.config.fresh_connection_per_command:
            return await self._fetch_per_command()
        async with self._asession() as s:
            return await self._afetch_clean(s)

    async def _fetch_per_command(self) -> dict[str, Any]:
        c = self.config
        session = _FreshConnectionSession(c.host, c.auth, self._session_kwargs(), self.transport)
        try:
            return await self._afetch_clean(session)
        finally:
            self.observed_host_key = session.host_key
            self.observed_jump_key = session.jump_host_key

    def fetch(self) -> dict[str, Any]:
        """The blocking entry for callers without a running loop."""
        if self.transport == "asyncssh":
            return asyncio.run(self.afetch())
        if self.config.fresh_connection_per_command:
            return asyncio.run(self._fetch_per_command())
        with self._session() as s:
            return asyncio.run(self._afetch_clean(_AsyncSessionFacade(s)))


class CiscoCliCollector(SshCliCollector):
    """The base of the NX-OS, IOS-XE and IOS-XR collectors. The pure `_parse`
    of a family returns the intermediate shape of all families. `cisco_common`
    builds the twin from the intermediate shape. Each family defines `name`,
    `ConfigModel`, `COMMANDS`, `OPTIONAL_COMMANDS`, `SECTIONS`, `probe` and
    `_parse`."""

    # Maps a section name to its `Section`. The names are the names of the
    # twin. `arp` is the ARP table on every family.
    SECTIONS: ClassVar[dict[str, Section]] = {}

    # `side_rows` maps the intermediate shape onto these 3 tables for every Cisco family.
    SIDE_TABLES: ClassVar[tuple[str, ...]] = ("rib", "mac", "arp")
    # The sections that give the rows of each table (`Collector.TABLE_SECTIONS`).
    # A family that reads a MAC table adds the table. A family without a MAC
    # table reports the table as `not-captured` in its `table_outcomes`.
    TABLE_SECTIONS: ClassVar[dict[str, tuple[str, ...]]] = {
        "rib": ("rib",),
        "arp": ("arp",),
        "ospf_lsdb": (
            "ospf",
            "ospf_lsdb_router",
            "ospf_lsdb_network",
            "ospf_lsdb_summary",
            "ospf_lsdb_asbr_summary",
            "ospf_lsdb_external",
            "ospf_lsdb_nssa_external",
        ),
    }

    # NX-OS, IOS-XE and IOS-XR accept both commands. The width keeps a wide
    # table on one line. Every `show` template reads its table by columns.
    SHELL_SETUP: ClassVar[tuple[str, ...]] = ("terminal length 0", "terminal width 511")
    # IOS-XE and IOS-XR answer in text, and a `banner motd` precedes every
    # exec-channel answer. NX-OS sets this to False. The NX-OS answers are JSON
    # documents that start with the same line.
    STRIP_EXEC_BANNER: ClassVar[bool] = True

    def __init__(self, config, settings):
        super().__init__(config, settings)
        self.scope = f"{self.name}:{config.host}"

    @staticmethod
    @abstractmethod
    def _parse(raw: dict[str, str]) -> dict[str, Any]:
        """Parse the raw outputs of the family into the intermediate shape. The parse is pure."""

    def sections(self, raw: dict[str, Any]) -> dict[str, SectionOutcome]:
        """Return the outcome of each declared section of this payload."""
        return build_sections(raw, self._inter(raw), self.SECTIONS, self.ALWAYS_PRESENT_COMMANDS)

    def _inter(self, raw: dict[str, str]) -> dict[str, Any]:
        # The cache is keyed by the identity of `raw`.
        if getattr(self, "_parsed_for", None) is not raw:
            # An unreadable optional answer fails only its own section (`effective_outcomes`).
            required = set(self.COMMANDS) - self.OPTIONAL_COMMANDS.keys()
            with cli_parse.tolerating(required) as failures:
                parsed = self._parse(raw)
            parsed[PARSE_FAILURES_KEY] = failures
            self._parsed = parsed
            self._parsed_for = raw
        return self._parsed

    def release_payload(self) -> None:
        """Drop the parse cache and its payload."""
        self._parsed = None
        self._parsed_for = None

    def normalize(self, raw: dict[str, str]) -> Batch:
        batch = normalize_cisco(
            self._inter(raw),
            source=self.name,
            scope=self.scope,
            l3dom=self.config.effective_routing_scope,
            # The single-fabric default applies without a Settings.
            l2fabric=(
                self.settings.l2fabric_of(self.config.source_name, self.config.l2fabric)
                if self.settings
                else self.config.effective_l2fabric
            ),
            # All devices of one group share the name of the source row.
            group_scope=self.config.source_name or self.scope,
            resolver=self.identity,
            target_host=self.config.host,
        )
        batch.sections = self.sections(raw)
        return batch

    def side_tables(self, raw: dict[str, str]) -> dict[str, Sequence[dict[str, Any]]]:
        inter = self._inter(raw)
        # normalize_cisco derives the same uid for the Device node.
        dev = device_uid(inter, self.scope, self.identity, self.config.host)
        return side_rows(
            inter,
            dev,
            # The l2fabric value is the same as in normalize().
            l2fabric=(
                self.settings.l2fabric_of(self.config.source_name, self.config.l2fabric)
                if self.settings
                else self.config.effective_l2fabric
            ),
        )
