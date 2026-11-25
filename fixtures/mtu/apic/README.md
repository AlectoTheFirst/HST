# APIC MTU synthetic fixture

`configured.json` is hand-written and contains synthetic identifiers and sizes.
It is not a capture or a derivative of a real estate. It covers physical raw
unknown semantics, logical aggregate membership, separate fabric default and
regular/floating L3Out configuration, plus inherited MTU.

Public sources reviewed for M04:

- The M00 source matrix verifies fabric and L3Out reads from Cisco's official
  upgrade guide and Cisco-maintained pre-upgrade validator source.
- Cisco Nexus Dashboard 4.3.1's ACI managed-object list includes `pcRsMbrIfs`:
  https://www.cisco.com/c/en/us/td/docs/dcn/nd/4x/articles-431/editing-fabric-settings-aci.html
- Cisco's NX-API model reference documents `pcRsMbrIfs.tDn` as the member relation;
  ACI source compatibility remains fixture-first. The adapter creates configured
  membership only when explicit complete relation DNs match both collected
  endpoints, and never infers active eligibility:
  https://developer.cisco.com/docs/cisco-nexus-3000-and-9000-series-nx-api-rest-sdk-user-guide-and-api-reference-release-9-2x/configuring-a-port-channel-interface/
- Floating attachment `nodeDn` and regular `tDn` are shown in Cisco's multiple
  encapsulation REST examples:
  https://www.cisco.com/c/en/us/td/docs/dcn/aci/apic/all/floating-l3outs/simplify-outside-network-connections-using-floating-l3outs/m-support-for-multiple-encapsulation-for-l3outs-with-svi.pdf

These references establish configured source shapes. Operational MTU, programmed fabric
capacities, active members, spine/IPN/ISN paths and private first-contact validation
remain pending. Baseline physical `mtu` is preserved without numeric normalization.
L3Out IP settings can be normalized as configured predictions.
