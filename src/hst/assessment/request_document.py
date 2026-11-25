"""Lossless request documents shared by submission and evaluation entry points."""

from __future__ import annotations

from typing import Any

from hst.assessment import evaluation as ev


def service_fields(item: Any) -> dict:
    if item is None:
        return {}

    def ports(values: Any) -> str | None:
        return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for _, lo, hi in values) if values else None

    return {
        "proto": ",".join(str(p) for p in sorted(item.proto)) if item.proto is not None else None,
        "port": ports(item.dport),
        "source_port": ports(item.sport),
    }


def request_document(req: Any) -> dict:
    return {
        "name": req.name,
        "destination": req.destination,
        "sources": ev._cidrs(req.sources),
        "members": [
            {"name": m.name, "addresses": ev._cidrs(m.addresses), **service_fields(m.service)}
            for m in req.members
        ],
        "condition": ev._condition_body(req.condition),
        **service_fields(req.service),
        "success": req.success,
        "source_context": req.source_context,
        "source_device_uid": req.source_device_uid,
        "identity_uid": req.identity_uid,
        "segment_uid": req.segment_uid,
        **({"ingress_interface_uid": req.ingress_interface_uid} if req.ingress_interface_uid else {}),
        **({"destination_context": req.destination_context} if req.destination_context else {}),
        **(
            {"header_constraints": {name: list(ranges) for name, ranges in req.header_constraints}}
            if req.header_constraints
            else {}
        ),
        **({"mtu": req.mtu.as_request().model_dump(mode="json")} if req.mtu is not None else {}),
    }
