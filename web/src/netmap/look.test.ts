import { describe, expect, it } from "vitest";
import type { TopologyModel } from "../api/types";
import { toFlatElkGraph, type CyElement } from "./layout";
import {
  caption,
  categoryOf,
  decorate,
  fitTransform,
  interfaceAddresses,
  portTag,
  speedKey,
  speedText,
  svgOf,
  symbolOf,
  type SymbolName,
} from "./look";

const MODEL: TopologyModel = {
  snapshot: 1,
  nodes: [
    { id: "site:ber1", kind: "site", parent: null, label: "ber1" },
    { id: "block:ber1:campus", kind: "block", parent: "site:ber1", label: "Campus" },
    { id: "swc-01", kind: "device", parent: "block:ber1:campus", label: "swc-01", role: "router", tier: "core", mgmt_ip: "10.0.0.1" },
    { id: "swa-01", kind: "device", parent: "block:ber1:campus", label: "swa-01", role: "switch", tier: "access" },
  ],
  cables: [
    { id: "swc-01~swa-01", from: { dev: "swc-01", port: "Eth1/1" }, to: { dev: "swa-01", port: "Gi1/0/49" }, source: "lldp", speed_mbps: 10_000, lateral: false },
  ],
  exits: [],
  lags: [],
  split_groups: [],
};

const ELEMENTS: CyElement[] = [
  { group: "nodes", data: { id: "site:ber1", label: "ber1", kind: "site" }, classes: "site" },
  { group: "nodes", data: { id: "swc-01", label: "swc-01", kind: "device" }, position: { x: 0, y: 0 }, classes: "device tier-core" },
  { group: "nodes", data: { id: "swa-01", label: "swa-01", kind: "device" }, position: { x: 0, y: 99 }, classes: "device tier-access" },
  { group: "edges", data: { id: "swc-01~swa-01", source: "swc-01", target: "swa-01", sourcePort: "Eth1/1", targetPort: "Gi1/0/49" }, classes: "cable routed" },
  { group: "edges", data: { id: "exit:0:cable", source: "swa-01", target: "exit:0" }, classes: "cable" },
  { group: "edges", data: { id: "bundle:a~b", source: "a", target: "b" }, classes: "bundle" },
];

describe("the device symbols", () => {
  it("draws a routing-tier switch or router as a layer-3 switch", () => {
    expect(symbolOf("router", "core")).toBe("l3switch");
    expect(symbolOf("switch", "distribution")).toBe("l3switch");
    expect(symbolOf("router", "wan-edge")).toBe("router");
    expect(symbolOf("switch", "access")).toBe("switch");
  });

  it("reads the tier when the role is not one it knows, and else draws unknown", () => {
    expect(symbolOf("unknown", "access-point")).toBe("ap");
    expect(symbolOf(null, "firewall")).toBe("firewall");
    expect(symbolOf("unknown", null)).toBe("unknown");
    expect(symbolOf("firewall", null)).toBe("firewall");
  });

  it("draws unknown for a role and a tier that are inherited members of the tables", () => {
    for (const name of ["constructor", "toString", "__proto__"]) expect(symbolOf(name, name), name).toBe("unknown");
  });

  it("puts each symbol in one device group", () => {
    expect(categoryOf("router")).toBe("l3");
    expect(categoryOf("switch")).toBe("l2");
    expect(categoryOf("server")).toBe("host");
    expect(categoryOf("unknown")).toBe("other");
  });

  it("gives a well-formed SVG document for every symbol", () => {
    const names: SymbolName[] = ["router", "l3switch", "switch", "firewall", "ap", "controller", "loadbalancer", "sdwan", "server", "cloud", "unknown"];
    for (const name of names) {
      const doc = new DOMParser().parseFromString(svgOf(name), "image/svg+xml");
      expect(doc.getElementsByTagName("parsererror")).toHaveLength(0);
      expect(doc.documentElement.childElementCount).toBeGreaterThan(0);
    }
  });
});

describe("the link speed", () => {
  it("puts a speed in its bin, a gigabit link in the 100 to 1000 Mbps bin", () => {
    expect([null, undefined, 0, 1, 1.5, 2, 10, 100, 1000, 2500, 10_000, 40_000].map(speedKey)).toEqual([
      "unknown",
      "unknown",
      "unknown",
      "s1",
      "s1",
      "s2",
      "s2",
      "s3",
      "s4",
      "s5",
      "s5",
      "s6",
    ]);
  });

  it("writes a speed as text", () => {
    expect(speedText(100)).toBe("100 Mbps");
    expect(speedText(1000)).toBe("1 Gbps");
    expect(speedText(2500)).toBe("2.5 Gbps");
    expect(speedText(null)).toBe("");
  });
});

describe("decorate", () => {
  it("gives each device its symbol, its group and its caption with the address", () => {
    const out = decorate(ELEMENTS, MODEL);
    const core = out.find((e) => e.data.id === "swc-01")!;
    expect(core.data.symbol).toBe("l3switch");
    expect(String(core.data.icon)).toMatch(/^data:image\/svg\+xml;utf8,/);
    expect(core.data.caption).toBe("swc-01\n10.0.0.1");
    expect(core.classes).toBe("device tier-core sym-l3switch cat-l3");
    expect(out.find((e) => e.data.id === "swa-01")!.data.caption).toBe("swa-01");
  });

  it("gives each cable its speed bin and its speed as text, a stub cable unknown, and leaves the rest", () => {
    const out = decorate(ELEMENTS, MODEL);
    const cable = out.find((e) => e.data.id === "swc-01~swa-01")!;
    expect(cable.classes).toBe("cable routed spd-s5");
    expect(cable.data.speedText).toBe("10 Gbps");
    expect(out.find((e) => e.data.id === "exit:0:cable")!.classes).toBe("cable spd-unknown");
    expect(out.find((e) => e.data.id === "bundle:a~b")).toBe(ELEMENTS[5]);
    expect(out[0]).toBe(ELEMENTS[0]);
    expect(ELEMENTS[1].classes).toBe("device tier-core");
  });

  it("puts the address on a second line only when there is one", () => {
    expect(caption("fw-01", "192.0.2.1")).toBe("fw-01\n192.0.2.1");
    expect(caption("fw-01", null)).toBe("fw-01");
  });
});

describe("fitTransform", () => {
  it("fits the drawing into the overview, centred, inside the padding", () => {
    const box = { x1: 100, y1: 50, w: 400, h: 100 };
    const { scale, ox, oy } = fitTransform(box, 200, 130, 6);
    expect(scale).toBeCloseTo(188 / 400, 6);
    expect(box.x1 * scale + ox).toBeCloseTo(6, 6);
    expect((box.x1 + box.w) * scale + ox).toBeCloseTo(194, 6);
    const top = box.y1 * scale + oy;
    const bottom = (box.y1 + box.h) * scale + oy;
    expect(top + bottom).toBeCloseTo(130, 6);
  });
});

describe("the port tags", () => {
  const withSubnets: TopologyModel = {
    ...MODEL,
    subnets: [
      {
        cidr: "10.20.0.0/30",
        af: 4,
        vrf: "default",
        domain: "global",
        members: [
          { dev: "swc-01", iface: "Eth1/1", ip: "10.20.0.1", fhrp: null },
          { dev: "swa-01", iface: "Gi1/0/49", ip: "10.20.0.2", fhrp: null },
        ],
      },
      {
        cidr: "10.30.0.0/24",
        af: 4,
        vrf: "default",
        domain: "global",
        members: [
          { dev: "swc-01", iface: "Vlan30", ip: "10.30.0.2", fhrp: null },
          { dev: "swc-01", iface: "Vlan30", ip: "10.30.0.1", fhrp: "hsrp" },
        ],
      },
    ],
  };

  it("reads each interface address with its prefix length, and not a first-hop virtual address", () => {
    const addresses = interfaceAddresses(withSubnets);
    expect(addresses.get("swc-01|Eth1/1")).toBe("10.20.0.1/30");
    expect(addresses.get("swc-01|Vlan30")).toBe("10.30.0.2/24");
  });

  it("puts the address of the port in the tag at each end", () => {
    const cable = decorate(ELEMENTS, withSubnets).find((e) => e.data.id === "swc-01~swa-01")!;
    expect(cable.data.sourceTag).toBe("Eth1/1 10.20.0.1/30");
    expect(cable.data.targetTag).toBe("Gi1/0/49 10.20.0.2/30");
    expect(portTag("Eth1/1", undefined)).toBe("Eth1/1");
  });
});

describe("the flat ELK graph of the tiered layout", () => {
  it("holds the devices and the stubs with no box, and leaves the lateral cables out", () => {
    const model: TopologyModel = {
      ...MODEL,
      cables: [...MODEL.cables, { id: "swa-01~swa-02", from: { dev: "swa-01", port: "1" }, to: { dev: "swa-02", port: "1" }, source: null, lateral: true }],
      nodes: [...MODEL.nodes, { id: "swa-02", kind: "device", parent: "block:ber1:campus", label: "swa-02" }],
      exits: [{ dev: "swc-01", port: "Eth1/49", far_dev: "dc", far_port: null, far_name: "dc", source: null }],
    };
    const graph = toFlatElkGraph(model);
    expect(graph.layoutOptions?.["elk.hierarchyHandling"]).toBeUndefined();
    expect(graph.children!.map((c) => c.id)).toEqual(["swc-01", "swa-01", "swa-02", "exit:0"]);
    expect(graph.children!.every((c) => !c.children)).toBe(true);
    expect(graph.edges!.map((e) => e.id)).toEqual(["swc-01~swa-01", "exit:0:cable"]);
  });
});
