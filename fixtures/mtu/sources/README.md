# Other-source MTU evidence

All examples are hand-written synthetic data. No production capture or scrubbed
capture belongs here. `endpoint-import.json` is a version-1 import example; its
subject UID must be replaced with an existing explicitly chosen graph subject.

## Manual endpoint/interface import

Set the existing manual source's multiline `mtu_evidence` configuration field to
the JSON document. `devices` can be empty. Each observation requires exact subject
UID and label, source, evidence reference, original observation time, explicit byte
basis/metric, direction and bound kind. Authority defaults to `intent`; explicitly
reported configured/operational evidence retains the declared authority and the
operator-import/unverified-source provenance. Intent is never promoted to observed.
Receive acceptance lower bounds are distinct from exact rejection limits.

`probe()` and `fetch()` resolve the current published snapshot once and check all
UID/label pairs in one read. Missing, retired or ambiguous subjects fail visibly.
The normalizer requires the preflight receipt; it emits only MtuObservation and
HAS_MTU. It cannot invent an interface, host address, attachment or route. The
existing loader also reports an error if an endpoint disappears before load.
The import is bounded at 512 observations and 1 MiB. Duplicate assertions and
conflicting labels for the same UID are rejected. `mtu_import.py` exposes
`parse_mtu_import`, `validate_import_subjects` and `emit_import` for other import
entry points; source schema discovery/validation exposes the field.

## Existing source behavior

- UniFi preserves observed scalar keys containing `mtu` or `jumbo` on already
  resolved device/port records, as configured raw unknown evidence. A Boolean is
  never assigned a numeric frame size. No new UniFi endpoint is guessed.
- Check Point management APIs explicitly report that verified Gaia dataplane MTU
  is unavailable; current management authentication does not establish Gaia access.
- ZIA and ZPA report the exact carrier/host MTU capability gaps. Their service
  inventories do not establish one PMTU across independent proxy connections.
- Nautobot optionally adds `mtu` to its existing device/interface GraphQL projection
  with `capture_mtu=true`. The optional response is preserved separately as
  `mtu_devices`; normalization joins device ID and interface name to existing
  physical Port subjects. Schema/authorization failure leaves base inventory
  intact. The optional query is capped at 100 pages. `mtu_basis` defaults to
  unknown; an operator can explicitly declare IP-packet or frame/FCS basis for
  their inventory convention. Every resulting observation remains intent.
  Virtual interfaces not modeled by this collector remain outside coverage;
  use explicit subject imports for existing guest/vSwitch interfaces.
- NetScaler optionally reads documented `GET /nitro/v1/config/Interface`, using
  existing NITRO credentials, with `capture_mtu=true`. Bind the appliance explicitly
  using `mtu_device_uid`, or `on_uid` when `on_label=Device`. An HA group is not an
  inferred appliance. Configured `mtu` excludes 14-byte Ethernet header and 4-byte
  CRC, so the converter exposes an untagged-only frame constraint of `mtu+14`;
  tag allowance stays unverified. `actualmtu` is retained as raw operational unknown
  because its complete frame coordinate is not proven. The read accepts at most
  4096 interface records; it creates observed Interface identity/ownership but no
  addressing, gateway or routing topology. NITRO deployment and receive claims
  remain explicitly configured predictions, pending private capture qualification.

Primary references reviewed 2026-09-08:

- Nautobot interface MTU field:
  https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/interface/
- Maintainer's GraphQL API documentation:
  https://docs.nautobot.com/projects/core/en/v1.0.3/additional-features/graphql/
- NetScaler current NITRO Interface reference, including exact read resource, `mtu`
  byte semantics and `actualmtu` field:
  https://developer-docs.netscaler.com/en-us/adc-nitro-api/current-release/configuration/network/Interface.html
- NetScaler 12.1 Interface reference corroborates header-based authentication:
  https://developer-docs.netscaler.com/en-us/adc-nitro-api/12-1/configuration/network/interface/interface.html

No vendor-wide defaults, cloud virtual-NIC ceilings or cluster-backplane constants
are asserted. First-contact profile qualification and full graph-path integration
remain pending.
