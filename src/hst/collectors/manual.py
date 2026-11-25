"""Manual inventory of devices with no orchestrator."""

from __future__ import annotations

import ipaddress
from typing import Any, ClassVar

from pydantic import Field, field_validator

from hst.core import uid
from hst.core.identity import chassis_serial, resolve_chassis
from hst.core.l3domain import DomainPolicy, Vrf
from hst.core.l3domain import resolve as l3d_resolve
from hst.core.model import Batch, SectionOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION

from .base import Collector, SourceConfig, register
from .mtu_import import emit_import, parse_mtu_import, validate_import_subjects
from .util import GraphBuilder


def _manual_dom(c: Any) -> str:
    """The management address of a manual row is in the global table."""
    return l3d_resolve(
        Vrf(device=f"manual:{c.source_name or 'manual'}"),
        DomainPolicy(scope=c.effective_routing_scope),
    )


FIELDS = ("hostname", "mgmt_ip", "platform", "role", "serial")


def parse_devices(text: str) -> list[dict[str, str]]:
    rows = []
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) > len(FIELDS):
            raise ValueError(f"line {lineno}: more than {len(FIELDS)} fields")
        row = dict(zip(FIELDS, parts + [""] * (len(FIELDS) - len(parts)), strict=True))
        if not row["hostname"]:
            raise ValueError(f"line {lineno}: hostname is required")
        if row["mgmt_ip"]:
            try:
                ipaddress.ip_address(row["mgmt_ip"])
            except ValueError as exc:
                raise ValueError(f"line {lineno}: bad mgmt_ip {row['mgmt_ip']!r}") from exc
        rows.append(row)
    return rows


class ManualConfig(SourceConfig):
    # The list has one device per line: hostname, mgmt_ip[, platform][, role][, serial].
    devices: str = Field(..., json_schema_extra={"format": "multiline"})

    mtu_evidence: str = Field(
        default="",
        json_schema_extra={"format": "multiline"},
        description="MTU evidence",
    )

    @field_validator("mtu_evidence")
    @classmethod
    def must_parse_mtu(cls, value: str) -> str:
        parse_mtu_import(value)
        return value

    @field_validator("devices")
    @classmethod
    def must_parse(cls, v: str) -> str:
        parse_devices(v)
        return v


@register
class ManualCollector(Collector):
    name = "manual"
    ConfigModel = ManualConfig
    KIND = "orchestrator"
    PARSER_VERSION = "2"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        "mtu": MTU_NORMALIZATION_VERSION,
        # A placeholder serial identifies no chassis. When 2 devices report one
        # serial in one run, the later device is keyed by its ref.
        "serial": "1",
    }

    def __init__(self, config: ManualConfig, settings):
        super().__init__(config, settings)
        self.scope = f"manual:{config.source_name or 'unnamed'}"

    def _validate_mtu(self) -> tuple[int | None, list[dict[str, str]]]:
        imported = parse_mtu_import(self.config.mtu_evidence)
        if not imported.observations:
            return None, []
        from hst.core import cycle, db

        with db.session(self.settings) as session:
            snap = cycle.current_ts(session)
            return snap, validate_import_subjects(session, imported, snap)

    def probe(self) -> str:
        _snapshot, subjects = self._validate_mtu()
        text = f"{len(parse_devices(self.config.devices))} device(s) parsed"
        return text if not subjects else f"{text}; {len(subjects)} MTU subject(s) resolved"

    def fetch(self) -> dict[str, Any]:
        raw: dict[str, Any] = {"devices": self.config.devices}
        if self.config.mtu_evidence.strip():
            snapshot, subjects = self._validate_mtu()
            raw.update(
                mtu_evidence=self.config.mtu_evidence, mtu_subject_snapshot=snapshot, mtu_subjects=subjects
            )
        return raw

    def normalize(self, raw: dict[str, Any]) -> Batch:
        c = self.config
        b = GraphBuilder()
        dom = _manual_dom(c)
        for row in parse_devices(raw["devices"]):
            # `chassis_serial` returns None for a placeholder serial.
            row["serial"] = chassis_serial(row["serial"])
            duid = resolve_chassis(
                self.identity, row["serial"], ("ref", f"{self.scope}:{row['hostname']}"), row["hostname"]
            )
            props = {
                k: v
                for k, v in (
                    ("hostname", row["hostname"]),
                    ("platform", row["platform"]),
                    ("serial", row["serial"]),
                    ("mgmt_ip", row["mgmt_ip"]),
                )
                if v
            }
            # core/labels.py requires a role.
            b.node("Device", duid, role=row["role"] or "unknown", **props)
            if row["mgmt_ip"]:
                ipu = b.node(
                    "IpAddress",
                    uid.ip(dom, row["mgmt_ip"]),
                    ip=row["mgmt_ip"],
                    af=ipaddress.ip_address(row["mgmt_ip"]).version,
                    l3dom=dom,
                    anchor=dom,
                )
                b.rel("HAS_IP", "Device", duid, "IpAddress", ipu)
        imported = parse_mtu_import(raw.get("mtu_evidence", ""))
        expected = {(r.subject_uid, r.subject_label) for r in imported.observations}
        validated = {(r.get("uid"), r.get("label")) for r in raw.get("mtu_subjects", [])}
        if expected and (expected != validated or type(raw.get("mtu_subject_snapshot")) is not int):
            raise ValueError(
                "MTU import subject preflight missing; fetch/probe must resolve explicit subjects"
            )
        emit_import(b, imported, c.source_name or "unnamed")
        batch = b.batch(self.name, self.scope)
        if imported.observations:
            batch.sections["mtu:import"] = SectionOutcome(
                status="ok",
                row_count=len(imported.observations),
                detail=(
                    f"operator-imported evidence; subjects verified in snapshot {raw['mtu_subject_snapshot']}"
                ),
            )
        return batch
