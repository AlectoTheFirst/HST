"""`hst parse-raw` parses one captured payload offline."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from hst.core.model import DEGRADING_SECTION_STATUSES, SectionOutcome, TableOutcome

from . import ssh, streams
from .base import (
    RAW_OUTCOMES_KEY,
    REGISTRY,
    Collector,
    empty_table_outcome,
    unread_table_feeds,
    written_table_outcome,
)
from .cisco_common import MTU_COMMANDS
from .cli_collector import SshCliCollector

# Each key is a raw key that `fetch` of collectors/checkpoint.py returns. Each
# value is the default for an absent file. `management_domain` comes from the
# configuration.
CHECKPOINT_RAW_KEYS: dict[str, Any] = {
    "gateways": [],
    "layers": [],
    "packages": [],
    "package_details": {},
    "package_revisions": {},
    "rulebases": {},
    "nat": {},
    "replayed_layers": [],
    "policy_section_errors": [],
}

_STAND_IN_AUTHS: tuple[dict[str, str], ...] = (
    {"method": "agent", "username": "first-contact"},
    {"method": "user_password", "username": "first-contact", "password": "first-contact"},
    {"method": "api_key", "key": "first-contact"},
)
STAND_IN_HOST = "first-contact"


def raw_file_name(command: str) -> str:
    """The file name of the output of one command in a directory capture.

    A command with a trailing `| json` gets the stem of the command without the
    pipe and the `.json` extension. Every other command gets `.txt`. `*` becomes
    `star`. Every other run of characters outside `[a-z0-9]` becomes one dash.
    A command that a collector derives at fetch time (a per-neighbor BGP table,
    a Gaia `vsenv` command) has a file name too.
    """
    text = command.strip()
    is_json = False
    m = re.match(r"^(.*?)\s*\|\s*json\s*$", text, re.IGNORECASE)
    if m:
        text, is_json = m.group(1), True
    stem = re.sub(r"[^a-z0-9]+", "-", text.lower().replace("*", " star ")).strip("-")
    return f"{stem}.json" if is_json else f"{stem}.txt"


class MissingCapture(ssh.CommandFailed):
    """The directory holds no file for this command."""


class DirectorySession:
    """A stand-in for an SSH session that answers each command from a file.

    For an absent file of a command in `required`, `run` returns an empty
    payload and records the command in `missing_required`. `load_directory`
    records such a command as `malformed`. Every other absent command raises
    `MissingCapture`. The fetch loop handles `MissingCapture` as the refusal
    of an optional command.
    """

    def __init__(self, directory: Path, *, required: Collection[str]) -> None:
        self.directory = directory
        self.required = set(required)
        self.read: dict[str, str] = {}
        self.missing_required: dict[str, str] = {}
        self.missing_optional: dict[str, str] = {}
        self.host_key = ""
        self.jump_host_key = ""

    async def run(self, command: str) -> str:
        name = raw_file_name(command)
        path = self.directory / name
        if path.is_file():
            self.read[command] = name
            return ssh.sanitize_cli_text(path.read_text(encoding="utf-8", errors="replace"))
        if command in self.required:
            self.missing_required[command] = name
            return "{}" if name.endswith(".json") else ""
        self.missing_optional[command] = name
        raise MissingCapture(f"no file {name} in {self.directory}")


def build_collector(name: str, settings: Any, config: Mapping[str, Any] | None = None) -> Collector:
    """A collector instance with no source row behind it.

    `config` is the source configuration as the settings form stores it. Without
    one, a stand-in configuration is built from the model's defaults, a
    placeholder host and a placeholder credential. For a model with required
    fields that the stand-in cannot fill (for example the identity fields of
    the Gaia collector), the function raises `ValueError` with the validation
    error.
    """
    cls = REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"unknown collector {name!r}; `hst collectors` lists the names")
    model = cls.ConfigModel
    if config is not None:
        cfg = model.model_validate(dict(config))
        return cls(cfg, settings)
    errors: list[str] = []
    for auth in _STAND_IN_AUTHS:
        try:
            cfg = model.model_validate({"host": STAND_IN_HOST, "auth": auth})
        except ValidationError as exc:
            errors.append(str(exc))
            continue
        return cls(cfg, settings)
    raise ValueError(
        f"collector {name!r} needs --config: its configuration has fields the stand-in "
        f"cannot fill.\n{errors[-1]}"
    )


def load_directory(collector: Collector, directory: Path) -> tuple[dict[str, Any], DirectorySession | None]:
    """The raw dict of a directory capture and the session that read it.

    For an `SshCliCollector`, the fetch code of the collector runs over a
    `DirectorySession`. The maps `read` and `missing_*` of the session hold
    the file accounting. For the Check Point management collector, each raw
    key is read from `<key>.json` and the session is None.
    """
    if isinstance(collector, SshCliCollector):
        required = [c for c in collector.COMMANDS if c not in collector.OPTIONAL_COMMANDS]
        session = DirectorySession(directory, required=required)
        raw = asyncio.run(collector._afetch_over(session))
        outcomes = raw.get(RAW_OUTCOMES_KEY)
        if not isinstance(outcomes, dict):
            outcomes = {}
            raw[RAW_OUTCOMES_KEY] = outcomes
        for cmd, name in session.missing_required.items():
            outcomes[cmd] = {"status": "malformed", "detail": f"no file {name} in the capture directory"}
        return raw, session
    if collector.name == "checkpoint":
        raw: dict[str, Any] = {"management_domain": getattr(collector.config, "domain", "")}
        for key, default in CHECKPOINT_RAW_KEYS.items():
            path = directory / f"{key}.json"
            raw[key] = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default
        return raw, None
    raise ValueError(
        f"collector {collector.name!r} has no per-command capture shape; pass a raw-store "
        f"file ({collector.name} payloads are read from `.json.gz.enc` files only)"
    )


def section_commands(collector: Collector) -> dict[str, str]:
    """Maps each section name to its command, for the sections of `SECTIONS`
    and the MTU roles of `MTU_COMMANDS`."""
    out: dict[str, str] = {}
    for name, spec in (getattr(collector, "SECTIONS", None) or {}).items():
        command = getattr(spec, "command", None)
        if isinstance(command, str):
            out[name] = command
    for role, command in MTU_COMMANDS.get(collector.name, {}).items():
        out[f"mtu_{role}"] = command
    return out


def expected_commands(collector: Collector) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    optional = set(getattr(collector, "OPTIONAL_COMMANDS", {}) or {})
    for cmd in getattr(collector, "COMMANDS", ()) or ():
        rows.append((cmd, "optional" if cmd in optional else "required", raw_file_name(cmd)))
    module = __import__(type(collector).__module__, fromlist=["_"])
    sessions = getattr(module, "CMD_BGP_SESSIONS", None)
    if isinstance(sessions, str) and sessions not in {r[0] for r in rows}:
        rows.append((sessions, "optional (capture_bgp)", raw_file_name(sessions)))
    for cmd in MTU_COMMANDS.get(collector.name, {}).values():
        if cmd not in {r[0] for r in rows}:
            rows.append((cmd, "optional (capture_mtu)", raw_file_name(cmd)))
    return rows


@dataclass
class ParseReport:
    collector: str
    path: str
    sections: dict[str, SectionOutcome] = field(default_factory=dict)
    commands: dict[str, str] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    missing_files: dict[str, str] = field(default_factory=dict)
    unrecognised_files: list[str] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)
    rels: int = 0
    side_tables: dict[str, int] = field(default_factory=dict)
    outcomes: dict[str, TableOutcome] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        if self.error:
            return False
        return not any(s.status in DEGRADING_SECTION_STATUSES for s in self.sections.values())

    def as_dict(self) -> dict[str, Any]:
        return {
            "collector": self.collector,
            "path": self.path,
            "ok": self.ok,
            "error": self.error,
            "sections": {
                name: {
                    "status": s.status,
                    "row_count": s.row_count,
                    "detail": s.detail,
                    "command": self.commands.get(name),
                    "file": self.files.get(self.commands.get(name, ""))
                    or self.missing_files.get(self.commands.get(name, "")),
                }
                for name, s in self.sections.items()
            },
            "files": self.files,
            "missing_files": self.missing_files,
            "unrecognised_files": self.unrecognised_files,
            "labels": self.labels,
            "rels": self.rels,
            "side_tables": self.side_tables,
            "outcomes": {
                name: {"status": o.status, "row_count": o.row_count, "detail": o.detail}
                for name, o in self.outcomes.items()
            },
        }


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def parse_report(collector: Collector, raw: Any, *, path: str) -> ParseReport:
    report = ParseReport(collector=collector.name, path=path, commands=section_commands(collector))
    sections_fn = getattr(collector, "sections", None)
    if callable(sections_fn):
        try:
            report.sections.update(sections_fn(raw))
        except Exception as exc:
            report.error = f"sections: {_describe(exc)}"
    try:
        batch = collector.normalize(raw)
    except Exception as exc:
        report.error = f"normalize: {_describe(exc)}"
        return report
    for name, outcome in batch.sections.items():
        report.sections.setdefault(name, outcome)
    counts: dict[str, int] = {}
    for node in batch.nodes:
        counts[node.label] = counts.get(node.label, 0) + 1
    report.labels = dict(sorted(counts.items()))
    report.rels = len(batch.rels)
    try:
        produced = collector.side_tables(raw)
        # This pass builds every row of a view.
        for rows in produced.values():
            for _ in rows:
                pass
    except streams.RowMappingError as exc:
        report.error = f"side_tables: {_describe(exc.original)}"
        produced = {}
    except Exception as exc:
        report.error = f"side_tables: {_describe(exc)}"
        produced = {}
    try:
        stated = collector.table_outcomes(raw)
    except Exception as exc:
        report.error = f"table_outcomes: {_describe(exc)}"
        stated = {}
    names = sorted({*collector.SIDE_TABLES, *produced})
    report.side_tables = {table: len(produced.get(table) or []) for table in names}
    unread = unread_table_feeds(collector, raw, report.sections)
    for table in names:
        rows = produced.get(table) or []
        if rows:
            report.outcomes[table] = written_table_outcome(
                len(rows), "", unread.get(table), stated.get(table)
            )
        else:
            report.outcomes[table] = stated.get(table) or empty_table_outcome(unread.get(table))
    for name, outcome in stated.items():
        report.outcomes.setdefault(name, outcome)
    return report


def parse_directory(collector: Collector, directory: Path) -> ParseReport:
    """`parse_report` over a directory capture, with the file accounting."""
    try:
        raw, session = load_directory(collector, directory)
    except (ValueError, json.JSONDecodeError, ssh.SshError) as exc:
        return ParseReport(
            collector=collector.name,
            path=str(directory),
            commands=section_commands(collector),
            error=f"load: {_describe(exc)}",
        )
    report = parse_report(collector, raw, path=str(directory))
    if session is not None:
        report.files = dict(session.read)
        report.missing_files = {**session.missing_required, **session.missing_optional}
    else:
        report.files = {
            key: f"{key}.json" for key in CHECKPOINT_RAW_KEYS if (directory / f"{key}.json").is_file()
        }
        report.missing_files = {
            key: f"{key}.json" for key in CHECKPOINT_RAW_KEYS if not (directory / f"{key}.json").is_file()
        }
    known = set(report.files.values()) | set(report.missing_files.values())
    report.unrecognised_files = sorted(
        p.name
        for p in directory.iterdir()
        if p.is_file() and p.name not in known and not p.name.startswith(".")
    )
    return report
