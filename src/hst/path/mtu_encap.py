"""Pure size functions in original-IP, carrier-IP and Ethernet-payload coordinates."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from hst.core.mtu import AddressFamily, MtuEncapsulation, MtuGapCode, canonical_json

Coordinate = Literal["ip", "ethernet_payload"]
PROFILES = {
    "vxlan": "vxlan_rfc7348_v1",
    "gre": "gre_rfc2784_2890_v1",
    "wireguard": "wireguard_data_v1",
    "ipsec": "esp_explicit_v1",
    "vlan": "vlan_explicit_v1",
    "pppoe": "pppoe_rfc2516_v1",
    "mpls": "mpls_rfc3032_v1",
    "macsec": "macsec_explicit_v1",
}
_IP_KINDS = {"vxlan", "gre", "wireguard", "ipsec"}
_REQUIRED = {
    "vxlan": {"outer_header_bytes", "retained_inner_tags", "inner_min_frame_bytes"},
    "gre": {"outer_header_bytes", "checksum", "key", "sequence", "routing", "payload_kind"},
    "wireguard": {"outer_header_bytes", "padding_mode", "inner_mtu_bytes"},
    "ipsec": {"outer_header_bytes", "mode", "cipher", "iv_bytes", "icv_bytes", "nat_t", "tfc_padding_bytes"},
    "vlan": {"tag_count"},
    "pppoe": {"ppp_protocol_bytes"},
    "mpls": {"label_count"},
    "macsec": {"sectag_bytes", "icv_bytes", "minimum_payload_bytes"},
}


class _Unknown(ValueError):
    pass


class _UnsupportedLength(ValueError):
    pass


class _TooShort(_UnsupportedLength):
    pass


def _integer(p: dict[str, Any], key: str, low: int, high: int) -> int:
    value = p.get(key)
    if type(value) is not int or not low <= value <= high:
        raise _Unknown(key)
    return value


def _boolean(p: dict[str, Any], key: str) -> bool:
    value = p.get(key)
    if type(value) is not bool:
        raise _Unknown(key)
    return value


def _ip_header(p: dict[str, Any], af: AddressFamily | None) -> None:
    if af == 4:
        if _integer(p, "outer_header_bytes", 20, 60) % 4:
            raise _Unknown("IPv4 header alignment")
    elif af == 6:
        _integer(p, "outer_header_bytes", 40, 2048)
    else:
        raise _Unknown("outer address family")


@dataclass(frozen=True)
class _Step:
    kind: str
    af: AddressFamily | None
    params: dict[str, Any]
    signature: str


def _step(item: MtuEncapsulation) -> _Step:
    if item.kind not in PROFILES or item.profile_id != PROFILES[item.kind]:
        raise _Unknown("profile")
    if len(item.parameters_json) > 4096:
        raise _Unknown("parameter bound")
    p = json.loads(item.parameters_json)
    if not isinstance(p, dict) or type(p.get("version")) is not int or p["version"] != 1:
        raise _Unknown("parameter version")
    if p.get("options_complete") is not True or set(p) != _REQUIRED[item.kind] | {
        "version",
        "options_complete",
    }:
        raise _Unknown("incomplete or unrecognized options")
    kind = item.kind
    if kind in _IP_KINDS:
        _ip_header(p, item.outer_af)
    elif item.outer_af is not None:
        raise _Unknown("link shim cannot change address family")
    if kind == "vxlan":
        _integer(p, "retained_inner_tags", 0, 8)
        _integer(p, "inner_min_frame_bytes", 0, 128)
    elif kind == "gre":
        for field in ("checksum", "key", "sequence", "routing"):
            _boolean(p, field)
        if p["routing"] or p["payload_kind"] != "ip":
            raise _Unknown("unsupported GRE form")
    elif kind == "wireguard":
        if p["padding_mode"] == "multiple_16":
            if p["inner_mtu_bytes"] is not None:
                raise _Unknown("unexpected WireGuard cap")
        elif p["padding_mode"] == "linux_mtu_cap":
            _integer(p, "inner_mtu_bytes", 1, 65575)
        else:
            raise _Unknown("WireGuard padding")
    elif kind == "ipsec":
        if p["mode"] not in {"tunnel", "transport"}:
            raise _Unknown("ESP mode")
        _boolean(p, "nat_t")
        _integer(p, "tfc_padding_bytes", 0, 65535)
        iv = _integer(p, "iv_bytes", 1, 32)
        icv = _integer(p, "icv_bytes", 1, 32)
        if p["cipher"] == "aes_gcm":
            if iv != 8 or icv not in {8, 12, 16}:
                raise _Unknown("AES-GCM IV/ICV")
        elif p["cipher"] == "aes_cbc":
            # icv_bytes comes from the parameters.
            if iv != 16:
                raise _Unknown("AES-CBC IV")
        else:
            raise _Unknown("ESP cipher")
    elif kind == "vlan":
        _integer(p, "tag_count", 1, 8)
    elif kind == "pppoe":
        if _integer(p, "ppp_protocol_bytes", 2, 2) != 2:
            raise _Unknown("PPP protocol compression")
    elif kind == "mpls":
        _integer(p, "label_count", 1, 16)
    elif kind == "macsec":
        if _integer(p, "sectag_bytes", 8, 16) not in {8, 16}:
            raise _Unknown("MACsec SecTAG")
        _integer(p, "icv_bytes", 8, 16)
        _integer(p, "minimum_payload_bytes", 0, 128)
    signature = canonical_json({"kind": kind, "profile": item.profile_id, "af": item.outer_af, "params": p})
    return _Step(kind, item.outer_af, p, signature)


def _active(stack: Sequence[MtuEncapsulation]) -> list[_Step]:
    if len(stack) > 32:
        raise _Unknown("stack bound")
    active: list[_Step] = []
    for item in stack:
        step = _step(item)
        if item.operation == "encapsulate":
            active.append(step)
        elif not active or active[-1].signature != step.signature:
            raise _Unknown("unmatched decapsulation")
        else:
            active.pop()
    return active


def _family(original_af: AddressFamily) -> None:
    if type(original_af) is not int or original_af not in (4, 6):
        raise _Unknown("original address family")


def _size(n: int, steps: Sequence[_Step], original_af: AddressFamily, coordinate: Coordinate) -> int:
    af = original_af
    # shim and tags count against the enclosing frame budget only.
    size, shim, tags = n, 0, 0
    for step in steps:
        p, kind = step.params, step.kind
        if kind == "vlan":
            tags += p["tag_count"]
            if tags > 8:
                raise _Unknown("tag depth")
            continue
        if kind == "mpls":
            shim += 4 * p["label_count"]
            continue
        if kind == "pppoe":
            shim += 6 + p["ppp_protocol_bytes"]
            continue
        if kind == "macsec":
            shim = max(size + shim, p["minimum_payload_bytes"]) - size + p["sectag_bytes"] + p["icv_bytes"]
            continue
        if kind != "vxlan" and (shim or tags):
            raise _Unknown("L2 envelope cannot be silently passed as IP payload")
        h = p["outer_header_bytes"]
        if kind == "vxlan":
            if tags and tags != p["retained_inner_tags"]:
                raise _Unknown("conflicting retained tag evidence")
            frame = max(size + shim + 14 + 4 * p["retained_inner_tags"], p["inner_min_frame_bytes"])
            size = frame + 8 + 8 + h
        elif kind == "gre":
            size += h + 4 + 4 * sum(p[k] for k in ("checksum", "key", "sequence"))
        elif kind == "wireguard":
            padded = (size + 15) // 16 * 16
            if p["padding_mode"] == "linux_mtu_cap":
                cap = p["inner_mtu_bytes"]
                last_unit = size % cap if size > cap else size
                padded = size + min((last_unit + 15) // 16 * 16, cap) - last_unit
            size = h + 8 + 16 + padded + 16
        elif kind == "ipsec":
            if p["mode"] == "transport":
                if step.af != af:
                    raise _Unknown("ESP transport family")
                if size < h:
                    raise _TooShort("ESP transport header length")
                protected = size - h
            else:
                protected = size
            protected += p["tfc_padding_bytes"] + 2
            alignment = 4 if p["cipher"] == "aes_gcm" else 16
            encrypted = (protected + alignment - 1) // alignment * alignment
            size = h + (8 if p["nat_t"] else 0) + 8 + p["iv_bytes"] + encrypted + p["icv_bytes"]
        if step.af is None:
            raise _Unknown("missing carrier family")
        af = step.af
        if size > (65535 if af == 4 else 65575):
            raise _UnsupportedLength("outer jumbogram unsupported")
        shim, tags = 0, 0
    return size + (shim if coordinate == "ethernet_payload" else 0)


def carrier_af(
    stack: Sequence[MtuEncapsulation], *, original_af: AddressFamily
) -> tuple[AddressFamily | None, list[MtuGapCode]]:
    """Address family of the current carrier after matched decapsulation."""
    try:
        _family(original_af)
        steps = _active(stack)
        af = original_af
        for step in steps:
            if step.kind == "ipsec" and step.params["mode"] == "transport" and step.af != af:
                raise _Unknown("transport family change")
            if step.af is not None:
                af = step.af
        return af, []
    except (ValueError, TypeError):
        return None, ["MTU_ENCAP_UNKNOWN"]


def carrier_tag_depth(stack: Sequence[MtuEncapsulation]) -> tuple[int | None, list[MtuGapCode]]:
    """The outer VLAN tag count the active stack states, or None when it states none."""
    try:
        tags: int | None = None
        for step in _active(stack):
            if step.kind in _IP_KINDS:
                tags = None
            elif step.kind == "vlan":
                tags = (tags or 0) + step.params["tag_count"]
        return tags, []
    except (ValueError, TypeError):
        return None, ["MTU_ENCAP_UNKNOWN"]


def packet_size(
    original_ip_bytes: int,
    stack: Sequence[MtuEncapsulation],
    *,
    original_af: AddressFamily,
    coordinate: Coordinate = "ip",
) -> tuple[int | None, list[MtuGapCode]]:
    """Current IP/payload bytes, excluding outer Ethernet and outer VLAN headers."""
    try:
        _family(original_af)
        if coordinate not in {"ip", "ethernet_payload"}:
            raise _Unknown("coordinate")
        if type(original_ip_bytes) is not int or not (
            20 if original_af == 4 else 40
        ) <= original_ip_bytes <= (65535 if original_af == 4 else 65575):
            raise _UnsupportedLength("original packet length")
        return _size(original_ip_bytes, _active(stack), original_af, coordinate), []
    except _UnsupportedLength:
        return None, ["MTU_LENGTH_UNSUPPORTED"]
    except (ValueError, TypeError):
        return None, ["MTU_ENCAP_UNKNOWN"]


def inner_budget(
    outer_ip_budget: int,
    stack: Sequence[MtuEncapsulation],
    *,
    original_af: AddressFamily,
    coordinate: Coordinate = "ip",
) -> tuple[int | None, list[MtuGapCode]]:
    """Invert a monotone size function with at most 17 bounded evaluations.

    ``ethernet_payload`` includes MPLS/PPPoE/MACsec overhead left after the caller
    removes outer MAC and VLAN headers. Zero means no valid original packet fits.
    None means the transform is not known. A decapsulated tunnel constrains only
    the stages before its decapsulation.
    """
    try:
        _family(original_af)
        if (
            type(outer_ip_budget) is not int
            or outer_ip_budget < 0
            or coordinate not in {"ip", "ethernet_payload"}
        ):
            raise _Unknown("budget or coordinate")
        steps = _active(stack)
        low, high = (20 if original_af == 4 else 40), (65535 if original_af == 4 else 65575)
        best = 0
        while low <= high:
            middle = (low + high) // 2
            try:
                fits = _size(middle, steps, original_af, coordinate) <= outer_ip_budget
            except _TooShort:
                low = middle + 1
                continue
            except _UnsupportedLength:
                fits = False
            if fits:
                best, low = middle, middle + 1
            else:
                high = middle - 1
        return best, []
    except (ValueError, TypeError):
        return None, ["MTU_ENCAP_UNKNOWN"]
