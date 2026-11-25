# Synthetic cross-vendor MTU estate

`estate.json` is hand-written test input for the M14 end-to-end and performance
tests. Every serial, hostname, managed-object DN, address and byte value is
invented. Addresses use only the RFC 5737 and RFC 3849 documentation ranges.
It is not a capture, an export or a scrubbed copy of any real estate.

## Shape

| Element | Source path exercised | Evidence |
| --- | --- | --- |
| Client endpoint `ep:estate:client-a` | Manual endpoint import (`collectors/mtu_import.py`) | IPv4 tx ceiling 1500 and rx acceptance lower bound 1500, both operational, both operator supplied |
| Access switch `ESTATE-XE-ACCESS-1` (IOS-XE) | `cisco_common.parse_mtu` and `normalize_cisco` | SVI Vlan10 and Port-channel1 IP MTU 1500; members GigabitEthernet1/0/1 9000 (bundled), 1/0/2 1500 (bundled), 1/0/3 1400 (down); system MTU 1500 |
| Core router `ESTATE-XR-CORE-1` (IOS-XR) | `cisco_common.parse_mtu` and `normalize_cisco` | Media 1514 with ARPA encapsulation on the fixture profile, IPv4 1500 on every routed port; subinterface .20 with configured `ipv4 mtu 1450` and operational 1500 |
| VXLAN carrier stage | `path/mtu_encap.py` profile `vxlan_rfc7348_v1` and the trace's carrier crossing | Outer IPv4 20-byte header, no retained inner tags, outer IP budget 1500, inner IP budget 1450 |
| ACI border leaf `ESTATE-ACI-LEAF-101` | `collectors/mtu_apic.py` | Fabric default `l2InstPol.fabricMtu` 9000, L3Out attachment 1500 with `ip_fragmentation=unsupported`, physical ports with raw unknown basis |
| Proxy `dev:estate-proxy-1` | Synthetic observations plus the trace's load-balancer stage | Virtual service `web-443` on 198.51.100.200 re-originating to 198.51.100.130:8443; interface IP ceilings 1500, configured |
| Host `ESTATE-VYOS-HOST-1` (VyOS) | `collectors/vyos.normalize_vyos` | eth0 configured 9000, operational 1500 (drift); receive acceptance lower bound 1500 |
| Stretch without evidence | `aci:estate:uni/tn-estate/BD-server` | Only rows from another snapshot (9000) and a retired row (1500) exist; the pinned snapshot holds nothing |

`synthetic.access_member_ports` supplies port-level IP payload ceilings on the
three aggregate member ports. The tests use these synthetic port rows to drive the M07
member expansion end to end and state that provenance in the observation source.

`topology` describes the rows a snapshot-pinned `TOPOLOGY_QUERY` read would
return: Port-channel1 realized by a Lag with two eligible members and one
explicitly inactive member, routed ports realized by their physical Port, and
the L3Out attachment carrying `ip_fragmentation=unsupported`.

## Public references used for the syntax

- IOS-XE `show ip interface`, `show system mtu`, `show etherchannel summary`:
  [Catalyst 9000 MTU](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/217233-troubleshoot-mtu-on-catalyst-9000-series.html)
- IOS-XR `show ipv4 interface` parenthetical protocol MTU and media MTU:
  [IOS XR MTU behavior](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xr-software/116350-trouble-ios-xr-mtu-00.html)
- VyOS Ethernet `mtu` and Linux netdevice semantics:
  [VyOS 1.5 Ethernet](https://docs.vyos.io/en/1.5/configuration/interfaces/ethernet.html),
  [Linux netdevices](https://www.kernel.org/doc/html/latest/networking/netdevices.html#mtu)
- APIC `l2InstPol.fabricMtu` and `l3extRsPathL3OutAtt.mtu`:
  [APIC 6.0 L3Out node and interface](https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/6x/l3-configuration/cisco-apic-layer-3-networking-configuration-guide-60x/node-and-interface-for-l3out-layer3-config-60x.html),
  [ACI L3Out fragmentation limitation](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/aci/apic/sw/4-x/rest-api-config/Cisco-APIC-REST-API-Configuration-Guide-401/Cisco-APIC-REST-API-Configuration-Guide-401_chapter_01101.html)
- VXLAN and ESP arithmetic: [RFC 7348](https://www.rfc-editor.org/rfc/rfc7348.html),
  [RFC 4303](https://www.rfc-editor.org/rfc/rfc4303.html), [RFC 4106](https://www.rfc-editor.org/rfc/rfc4106.html)
- Documentation address ranges: [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737.html),
  [RFC 3849](https://www.rfc-editor.org/rfc/rfc3849.html)

These references establish command and object syntax. They do not certify any
platform, release or driver profile. Operational validation with private
captures (acceptance case T30) remains pending.
