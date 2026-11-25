import { describe, expect, it } from "vitest";
import type { MapSubnet, MapVlan } from "../api/types";
import { vlanOptions, vlanOverlay, vrfOptions, vrfOverlay } from "./overlay";

function vlan(dev: string, vid: number, ports: string[], extra: Partial<MapVlan> = {}): MapVlan {
  return { dev, vid, name: null, segment: null, ports, native: [], svi: null, ...extra };
}

/** fr2 and fr6 trunk VLAN 100 to each other; fr6 also carries 200 towards
 *  ams, where the far end has no VLAN 200 on its port */
const VLANS: MapVlan[] = [
  vlan("dev:fr2", 100, ["Eth1/49"], { name: "servers", svi: "Vlan100" }),
  vlan("dev:fr6", 100, ["Eth1/49", "Eth1/1"]),
  vlan("dev:fr6", 200, ["Eth1/50"], { segment: "guest" }),
  vlan("dev:ams", 300, ["Eth1/1"]),
];

const EDGES = [
  { a: "dev:fr2", aPort: "Eth1/49", b: "dev:fr6", bPort: "Eth1/49" },
  { a: "dev:fr6", aPort: "Eth1/50", b: "dev:ams", bPort: "Eth1/1" },
];

describe("vlanOptions", () => {
  it("lists every VLAN once, by id, named from any device that names it", () => {
    expect(vlanOptions(VLANS)).toEqual([
      { vid: 100, label: "VLAN 100 servers", devices: 2 },
      { vid: 200, label: "VLAN 200 guest", devices: 1 },
      { vid: 300, label: "VLAN 300", devices: 1 },
    ]);
  });
});

describe("vlanOverlay", () => {
  it("marks a cable trunked when both end ports carry the VLAN", () => {
    const o = vlanOverlay(VLANS, EDGES, 100);
    expect([...o.devices].sort()).toEqual(["dev:fr2", "dev:fr6"]);
    expect(o.svi.get("dev:fr2")).toBe("Vlan100");
    expect(o.svi.has("dev:fr6")).toBe(false);
    expect(o.edges).toEqual(["both", "none"]);
  });

  it("marks the side that carries it when the far end does not", () => {
    expect(vlanOverlay(VLANS, EDGES, 200).edges).toEqual(["none", "a"]);
    expect(vlanOverlay(VLANS, EDGES, 300).edges).toEqual(["none", "b"]);
  });

  it("is empty for a VLAN no device has", () => {
    const o = vlanOverlay(VLANS, EDGES, 999);
    expect(o.devices.size).toBe(0);
    expect(o.edges).toEqual(["none", "none"]);
  });
});

function subnet(cidr: string, members: [string, string, string][], extra: Partial<MapSubnet> = {}): MapSubnet {
  return {
    cidr,
    af: 4,
    vrf: "CORP",
    domain: "ACME-EMEA:CORP",
    members: members.map(([dev, iface, ip]) => ({ dev, iface, ip, fhrp: null })),
    ...extra,
  };
}

const SUBNETS: MapSubnet[] = [
  // the stretched server segment: both halls, an hsrp pair
  subnet("10.1.0.0/24", [
    ["dev:fr2", "Vlan100", "10.1.0.1"],
    ["dev:fr2", "Vlan100", "10.1.0.254"],
    ["dev:fr6", "Vlan100", "10.1.0.2"],
  ]),
  // a point to point towards ams in the same domain
  subnet("10.9.0.0/30", [
    ["dev:fr6", "Eth1/50", "10.9.0.1"],
    ["dev:ams", "Eth1/1", "10.9.0.2"],
  ]),
  // a guest VRF with no declared domain, only one router in the picture
  subnet("192.168.50.0/24", [["dev:fr6", "Vlan50", "192.168.50.1"]], {
    vrf: "GUEST",
    domain: null,
  }),
];

describe("vrfOptions", () => {
  it("lists a declared domain by name and a bare VRF as one", () => {
    expect(vrfOptions(SUBNETS)).toEqual([
      { key: "ACME-EMEA:CORP", label: "ACME-EMEA:CORP", devices: 3 },
      { key: "vrf:GUEST", label: "VRF GUEST", devices: 1 },
    ]);
  });
});

describe("vrfOverlay", () => {
  it("pairs the devices that share a prefix, once per pair and prefix", () => {
    const o = vrfOverlay(SUBNETS, EDGES, "ACME-EMEA:CORP");
    expect([...o.devices].sort()).toEqual(["dev:ams", "dev:fr2", "dev:fr6"]);
    expect(o.adjacencies.map((a) => [a.a, a.b, a.subnet.cidr])).toEqual([
      ["dev:fr2", "dev:fr6", "10.1.0.0/24"],
      ["dev:ams", "dev:fr6", "10.9.0.0/30"],
    ]);
    expect(o.edges).toEqual([true, true]);
  });

  it("leaves a cable unmarked when its two devices share no prefix in the domain", () => {
    const o = vrfOverlay(SUBNETS, EDGES, "vrf:GUEST");
    expect([...o.devices]).toEqual(["dev:fr6"]);
    expect(o.adjacencies).toEqual([]);
    expect(o.edges).toEqual([false, false]);
  });
});
