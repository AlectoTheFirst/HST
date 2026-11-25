import { describe, expect, it } from "vitest";
import type { TopologyModel } from "../api/types";
import { paint } from "./overlays";

const dev = (id: string) => ({ id, kind: "device" as const, parent: "block:s:campus", label: id });

const MODEL: TopologyModel = {
  snapshot: 1,
  nodes: [dev("a"), dev("b"), dev("c")],
  cables: [
    { id: "a~b", from: { dev: "a", port: "e1" }, to: { dev: "b", port: "e1" }, source: "lldp", lateral: false },
    { id: "b~c", from: { dev: "b", port: "e2" }, to: { dev: "c", port: "e1" }, source: "lldp", lateral: false },
  ],
  exits: [],
  lags: [],
  split_groups: [],
  vlans: [
    { dev: "a", vid: 10, name: "users", segment: null, ports: ["e1"], native: [], svi: null },
    { dev: "b", vid: 10, name: "users", segment: null, ports: ["e1", "e2"], native: [], svi: "Vlan10" },
  ],
  subnets: [
    {
      cidr: "10.0.0.0/24",
      af: 4,
      vrf: "default",
      domain: null,
      members: [
        { dev: "a", iface: "Vlan10", ip: "10.0.0.2", fhrp: null },
        { dev: "c", iface: "Vlan10", ip: "10.0.0.3", fhrp: null },
      ],
    },
  ],
};

describe("paint", () => {
  it("lights a trunk on both ends and a VLAN on one end of a cable", () => {
    const p = paint(MODEL, "l2", 10, null);
    expect(p.classes.get("a~b")).toBe("ov-both");
    expect(p.classes.get("b~c")).toBe("ov-half");
    expect(p.classes.get("c")).toBe("ov-off");
    expect(p.note).toBe("2 devices, 1 trunked cable, 1 one-sided");
  });

  it("draws an L3 adjacency that no cable joins as its own line", () => {
    const p = paint(MODEL, "l3", null, "vrf:default");
    expect(p.extra.map((e) => [e.data.source, e.data.target, e.data.label])).toEqual([["a", "c", "10.0.0.0/24"]]);
    expect(p.classes.get("b")).toBe("ov-off");
  });

  it("paints nothing on the physical layer, and says when a layer has no data", () => {
    expect(paint(MODEL, "phys", null, null).classes.size).toBe(0);
    expect(paint(MODEL, "l2", null, null).note).toBe("no VLAN data");
  });

  it("puts a gateway of the VLAN in the layer, and an untagged routed port's cable carries the VLAN", () => {
    // c routes VLAN 10 on its untagged e1, cabled to b's e2; no VLAN row states it
    const model: TopologyModel = {
      ...MODEL,
      segments: [
        {
          bd: "bd:vlan:f:10",
          vid: 10,
          name: "users",
          cidrs: ["10.0.0.0/24"],
          cidr_basis: "gateway",
          gateways: [{ dev: "c", iface: "e1", ip: "10.0.0.3", cidr: "10.0.0.0/24", af: 4, vrf: "default", domain: null, fhrp: null, basis: "cable" }],
          carriers: [],
          clients: 0,
          attachments: [],
        },
      ],
    };
    const p = paint(model, "l2", 10, null);
    expect(p.classes.get("c")).toBe("ov-on");
    expect(p.classes.get("b~c")).toBe("ov-both");
    expect(p.note).toBe("3 devices, 2 trunked cables");
  });
});
