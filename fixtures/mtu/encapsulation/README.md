# Explicit encapsulation profiles

All values in this directory and the M08 tests are synthetic protocol inputs, not
captured device settings. Public numerical boundary cases are shared with
`../conformance.json` (T12–T14); executable cases are in
`tests/test_mtu_encap.py`.

`MtuEncapsulation.parameters_json` must contain integer `version: 1`, boolean
`options_complete: true`, and exactly the profile's fields below. Missing,
unsupported, or extra options produce `MTU_ENCAP_UNKNOWN`. These profiles establish
arithmetic only: collectors must have evidence that every required option applies.
No profile is automatically selected from a tunnel name or vendor.

| Kind / profile_id | Required fields and supported values |
| --- | --- |
| vxlan / vxlan_rfc7348_v1 | outer_header_bytes; retained_inner_tags 0–8; inner_min_frame_bytes 0–128 (excluding FCS) |
| gre / gre_rfc2784_2890_v1 | outer_header_bytes; checksum, key, sequence booleans; routing false; payload_kind "ip" |
| wireguard / wireguard_data_v1 | outer_header_bytes; padding_mode "multiple_16" with inner_mtu_bytes null, or "linux_mtu_cap" with explicit positive inner_mtu_bytes |
| ipsec / esp_explicit_v1 | outer_header_bytes; mode "tunnel" or "transport"; cipher "aes_gcm" (IV 8, ICV 8/12/16) or "aes_cbc" (IV 16, explicit ICV 1–32); iv_bytes; icv_bytes; nat_t boolean; tfc_padding_bytes 0–65535 |
| vlan / vlan_explicit_v1 | tag_count 1–8 |
| pppoe / pppoe_rfc2516_v1 | ppp_protocol_bytes 2 |
| mpls / mpls_rfc3032_v1 | label_count 1–16 (no pseudowire/control-word inference) |
| macsec / macsec_explicit_v1 | sectag_bytes 8/16 (including added EtherType); icv_bytes 8–16; minimum_payload_bytes 0–128 |

IP tunnels require outer_af 4 or 6, with explicit complete outer_header_bytes
(IPv4 20–60, aligned to four; IPv6 40–2048). Link shims require outer_af null.
ESP transport uses the explicit unencrypted IP-header byte count, preserves AF,
and protects the remaining packet. Header placement must be established externally.
GCM rounds protected bytes plus the two-byte ESP trailer to four; CBC rounds to
sixteen. NAT-T adds only the eight-byte UDP header to ESP data, not a non-ESP marker.
WireGuard's Linux cap describes padding, not a receiver or interface rejection
ceiling; the verified modulo rule also handles inputs above that cap.

The stack lists operations from original packet outward. Decapsulation matches and
removes the latest encapsulation with the same kind/profile/AF/parameters; evidence
IDs do not affect matching. A stage after removal no longer pays that overhead;
limits from earlier stages remain in the enclosing path evaluation. There is no
per-switch re-encapsulation. Maximum stack length is 32 and inverse evaluation uses
at most 17 size probes. Unsupported original/intermediate jumbograms return an
explicit length gap; an inverse ceiling of zero means no valid original packet fits.

`packet_size` and `inner_budget` default to the current carrier IP coordinate.
`coordinate="ethernet_payload"` also counts current MPLS/PPPoE/MACsec
shims. Outer MAC, FCS, and outer VLAN headers are never included; constraint_budget
removes the canonical frame's MAC and current tags exactly once. Explicit VLAN
operations are checked against that tag depth. VXLAN incorporates inner Ethernet,
retained inner tags and inner shims, without FCS. Inner frame padding is explicit.
Unsupported GRE Ethernet payloads and an L2 envelope passed to an IP-only tunnel
return a gap. Unknown forwarding encapsulation options must remain unknown even
when an arithmetic profile exists.

Connection/proxy boundaries are outside this pure module: initialize a new original
packet and stack for each independently originated connection; never subtract a
front-end stack from an unrelated back-end connection. M06 groups connection budgets.

Public references reviewed 2026-09-08:

- [VXLAN RFC 7348](https://www.rfc-editor.org/rfc/rfc7348.html)
- [GRE RFC 2784](https://datatracker.ietf.org/doc/html/rfc2784) and [GRE key/sequence RFC 2890](https://www.rfc-editor.org/rfc/rfc2890.html)
- [WireGuard protocol](https://www.wireguard.com/protocol/) and [Linux calculate_skb_padding source](https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/send.c)
- [ESP RFC 4303](https://www.rfc-editor.org/rfc/rfc4303.html), [GCM RFC 4106](https://www.rfc-editor.org/rfc/rfc4106.html), [AES-CBC RFC 3602](https://datatracker.ietf.org/doc/html/rfc3602), [NAT-T RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html)
- [PPPoE RFC 2516](https://www.rfc-editor.org/rfc/rfc2516.html), [MPLS RFC 3032](https://www.rfc-editor.org/rfc/rfc3032.html)
- [Cisco MACsec overhead](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-series-switches/216849-troubleshoot-macsec-on-catalyst-9000.html)

Device-profile and private replay validation remain pending. The profiles qualify no estate platform.
