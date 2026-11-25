import { describe, expect, it } from "vitest";
import { describePair } from "./siteEdges";

describe("describePair", () => {
  it("prints each kind's two ends and its note", () => {
    expect(
      describePair("cable", { a_name: "fr2-sw1", a_port: "Eth1/49", b_name: "fr6-sw1", b_port: "Eth1/49", source: "cdp" }),
    ).toEqual({ a: "fr2-sw1 Eth1/49", b: "fr6-sw1 Eth1/49", note: "cdp" });
    expect(
      describePair("l3", {
        a_name: "a",
        a_iface: "Vlan100",
        a_ip: "10.1.0.1",
        b_name: "b",
        b_iface: "Vlan100",
        b_ip: "10.1.0.2",
        cidr: "10.1.0.0/24",
        vrf: "CORP",
        domain: null,
      }),
    ).toEqual({ a: "a Vlan100 10.1.0.1", b: "b Vlan100 10.1.0.2", note: "10.1.0.0/24, VRF CORP" });
    expect(
      describePair("circuit", {
        name: "FR2-FR6-10G",
        state: "ACTIVE",
        bandwidth_mbps: 10000,
        a_fabric_port: "fr2-port-1",
        a_name: null,
        a_port: null,
        b_fabric_port: "fr6-port-1",
        b_name: "fr6-sw1",
        b_port: "Eth1/50",
      }),
    ).toEqual({
      a: "fr2-port-1",
      b: "fr6-port-1, fr6-sw1 Eth1/50",
      note: "FR2-FR6-10G, ACTIVE, 10000 Mb/s",
    });
    expect(
      describePair("bgp", { a_name: "a", a_ip: "10.9.0.1", a_asn: 65001, b_name: "b", b_ip: "10.9.0.2", b_asn: 65002, kind: "underlay", state: "established" }),
    ).toEqual({ a: "a 10.9.0.1 AS65001", b: "b 10.9.0.2 AS65002", note: "underlay, established" });
  });
});
