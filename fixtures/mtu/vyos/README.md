# VyOS MTU fixtures

`netdevice.json` is hand-written test input. Its version string, serial, host,
interface topology and values are invented. It is not a sanitized estate export.

It covers physical, VLAN, bond, bridge, WireGuard and GRE interface MTU; configured
versus operational drift; missing/invalid MACs; and configured members whose active
forwarding eligibility is unknown. The tests construct QinQ, malformed and failed
capture variants from this fixture. No live-device profile is certified.

Normalization uses Linux netdevice semantics: MTU excludes link-layer headers;
receive support is an acceptance lower bound, never an exact rejection ceiling.
AF-specific IPv6 effective MTU is unknown. See [Linux netdevices](https://www.kernel.org/doc/html/latest/networking/netdevices.html#mtu).

Public iproute2 source verifies `mtu`, `ifname`, `master`, `operstate` and
`link_type` in [ipaddress.c](https://raw.githubusercontent.com/iproute2/iproute2/main/ip/ipaddress.c).
Same-namespace parent links use `link`; foreign namespace links use `link_index`
and `link_netnsid`, as shown by `print_name_and_link` in
[utils.c](https://raw.githubusercontent.com/iproute2/iproute2/main/lib/utils.c).
The collector does not resolve foreign indexes against the local interface map.
`linkinfo` is preserved when present in replayed input; ordinary `ip -j link show`
does not establish full bond/LACP eligibility or STP forwarding state.

[VyOS 1.5 Ethernet documentation](https://docs.vyos.io/en/1.5/configuration/interfaces/ethernet.html)
confirms configured MTU and separate vif/vif-s/vif-c settings. These values
exclude tag headers. The collector performs no tag subtraction. QinQ interface
subjects retain two-tag context and a carriage gap because the single-tag
bridge-domain model does not establish complete QinQ forwarding.
