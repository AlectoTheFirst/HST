# Cisco dynamic BGP network fixtures

Synthetic, documentation-shaped captures for NX-OS, IOS-XE and IOS-XR. Each declares
the same WAN VRF, dynamic range `10.252.32.0/23`, remote AS 65099 and inbound/outbound
policies. The summary contains an established peer, an idle peer and an unrelated
address. Only the two peers in the range may instantiate it.

`tests/test_cisco_dynamic_bgp.py` replays these fixtures through collection,
normalization, policy edges, route side tables and collection fingerprints.
IOS-XE exercises peer-group inheritance and its dynamic-peer `*` marker;
IOS-XR exercises a globally declared neighbor group used in a VRF.
