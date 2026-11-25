import { describe, it, expect } from "vitest";
import {
  CAPTION_MAX,
  LAYOUTS,
  OTHER_SLOT,
  growSlots,
  SLOT_COUNT,
  caption,
  captionFull,
  layoutOptions,
  MAX_SPREAD,
  startPosition,
  legend,
  slots,
  toElements,
} from "./graphElements";
import type { ResultGraph } from "../api/types";

const GRAPH: ResultGraph = {
  nodes: [
    { id: "n1", labels: ["Device", "Phys"], properties: { hostname: "core1" } },
    { id: "n2", labels: ["Iface"], properties: { name: "eth0" } },
    { id: "n3", labels: ["Device"], properties: { uid: "dev:x:edge1" } },
  ],
  relationships: [{ id: "r1", type: "HAS_IFACE", start: "n1", end: "n2", properties: {} }],
  truncated: false,
};

describe("captions", () => {
  it("names a node by the property an operator recognises it by", () => {
    expect(caption(GRAPH.nodes[0])).toBe("core1");
    expect(caption(GRAPH.nodes[1])).toBe("eth0");
    expect(caption(GRAPH.nodes[2])).toBe("dev:x:edge1");
  });

  it("names an address by its address, never by its uid", () => {
    const address = {
      labels: ["IpAddress"],
      properties: { uid: "ip:vrf-dev-x-vyos-core1-default:192.168.10.1", ip: "192.168.10.1" },
    };
    const prefix = {
      labels: ["Prefix"],
      properties: { uid: "pfx:vrf-dev-x-vyos-core1-default:10.0.0.0/24", cidr: "10.0.0.0/24" },
    };
    expect(caption(address)).toBe("192.168.10.1");
    expect(caption(prefix)).toBe("10.0.0.0/24");
  });

  it("truncates a long value from the tail, where the difference is", () => {
    const node = {
      labels: ["VrfInstance"],
      properties: { uid: "vrf:dev-x-vyos-core1-with-a-very-long-scope:default" },
    };
    const drawn = caption(node);
    expect(drawn.length).toBeLessThanOrEqual(CAPTION_MAX);
    expect(drawn.startsWith("…")).toBe(true);
    expect(drawn.endsWith("default")).toBe(true);
    // the whole value stays available for the property panel and the text list
    expect(captionFull(node)).toBe("vrf:dev-x-vyos-core1-with-a-very-long-scope:default");
  });

  it("draws a VeloCloud tunnel by its name, the two WAN link names", () => {
    const tunnel = { labels: ["Tunnel"], properties: { name: "MPLS to MPLS" } };
    expect(caption(tunnel)).toBe("MPLS to MPLS");
    expect(captionFull(tunnel)).toBe("MPLS to MPLS");
  });

  it("draws an overlay connection by its name, the two device names", () => {
    const connection = {
      labels: ["OverlayConnection"],
      properties: { name: "vie01-vce-01 to dc1-vch-01" },
    };
    expect(caption(connection)).toBe("vie01-vce-01 to dc1-vch-01");
  });

  it("falls back to the label", () => {
    expect(caption({ labels: ["Gate"], properties: {} })).toBe("Gate");
    expect(caption({ labels: [], properties: {} })).toBe("node");
  });
});

describe("slots", () => {
  it("gives the most common label the lowest slot", () => {
    // two Devices and one Iface: Device takes slot 0
    expect(slots(GRAPH)).toEqual(
      new Map([
        ["Device", 0],
        ["Iface", 1],
      ]),
    );
  });

  it("breaks a tie by name", () => {
    const tied: ResultGraph = {
      nodes: [
        { id: "a", labels: ["Zone"], properties: {} },
        { id: "b", labels: ["Alarm"], properties: {} },
      ],
      relationships: [],
      truncated: false,
    };
    expect(slots(tied).get("Alarm")).toBe(0);
    expect(slots(tied).get("Zone")).toBe(1);
  });

  it("folds every label past the eighth into one neutral slot", () => {
    const kinds = [..."ABCDEFGHIJK"];
    const many: ResultGraph = {
      // a descending count per kind, so the rank is the position in `kinds` and
      // the tie-break never comes into it
      nodes: kinds.flatMap((kind, rank) =>
        Array.from({ length: kinds.length - rank }, (_unused, i) => ({
          id: `${kind}${i}`,
          labels: [kind],
          properties: {},
        })),
      ),
      relationships: [],
      truncated: false,
    };
    const assigned = slots(many);
    expect(kinds.slice(0, SLOT_COUNT).map((kind) => assigned.get(kind))).toEqual([
      0, 1, 2, 3, 4, 5, 6, 7,
    ]);
    expect(kinds.slice(SLOT_COUNT).map((kind) => assigned.get(kind))).toEqual([
      OTHER_SLOT,
      OTHER_SLOT,
      OTHER_SLOT,
    ]);
    // and every label is still named, none dropped
    expect(assigned.size).toBe(kinds.length);
  });
});

describe("toElements", () => {
  it("carries a node's caption, label and palette slot in its element data", () => {
    const nodes = toElements(GRAPH).filter((e) => e.group === "nodes");
    expect(nodes).toHaveLength(3);
    expect(nodes[0].data).toMatchObject({
      id: "n1",
      caption: "core1",
      kind: "Device",
      slot: 0,
    });
  });

  it("drops an edge whose endpoint the server capped away", () => {
    const elements = toElements({
      ...GRAPH,
      relationships: [
        ...GRAPH.relationships,
        { id: "r2", type: "CABLED", start: "n1", end: "gone", properties: {} },
      ],
    });
    const edges = elements.filter((e) => e.group === "edges");
    expect(edges.map((e) => e.data.id)).toEqual(["r1"]);
  });
});

describe("legend", () => {
  it("counts the labels, most common first", () => {
    expect(legend(GRAPH)).toEqual([
      { kind: "Device", slot: 0, count: 2 },
      { kind: "Iface", slot: 1, count: 1 },
    ]);
  });

  it("is empty for an empty result", () => {
    expect(legend({ nodes: [], relationships: [], truncated: false })).toEqual([]);
  });
});

describe("layoutOptions", () => {
  it("returns options for every layout in the picker", () => {
    for (const { name } of LAYOUTS) {
      expect(layoutOptions(name, 20)).toMatchObject({ name, animate: false, fit: true });
    }
  });

  it("holds the force layout deterministic", () => {
    // fcose accepts `randomize: false` only at "proof" quality
    expect(layoutOptions("fcose", 20)).toMatchObject({
      randomize: false,
      quality: "proof",
      nodeDimensionsIncludeLabels: true,
    });
  });

  it("spreads a bigger graph further, up to a cap", () => {
    const at = (n: number) => (layoutOptions("fcose", n) as { idealEdgeLength: number }).idealEdgeLength;
    expect(at(20)).toBeGreaterThan(at(12));
    expect(at(300)).toBe(at(12) * MAX_SPREAD);
    expect(at(1000)).toBe(at(300));
    expect(layoutOptions("fcose", 50)).not.toHaveProperty("nodeSeparation");
  });

  it("starts every node at a position from the element order alone", () => {
    expect(startPosition(0)).toEqual({ x: 0, y: 0 });
    const a = startPosition(7);
    const b = startPosition(7);
    expect(a).toEqual(b);
    expect(Math.hypot(startPosition(8).x, startPosition(8).y)).toBeGreaterThan(Math.hypot(a.x, a.y));
  });
});

describe("growSlots", () => {
  const graphOf = (counts: Record<string, number>): ResultGraph => ({
    nodes: Object.entries(counts).flatMap(([label, n]) =>
      Array.from({ length: n }, (_, i) => ({ id: `${label}:${i}`, labels: [label], properties: {} })),
    ),
    relationships: [],
    truncated: false,
  });
  const ZPA = {
    ZpaAppConnector: 6,
    IdentityGroup: 5,
    AppServer: 4,
    ZpaAccessRule: 3,
    ZpaServerGroup: 2,
    ZpaAppConnectorGroup: 2,
    ZpaAppSegment: 1,
    ZpaSegmentGroup: 1,
  };

  it("keeps the slot of every drawn label when a growth reorders the counts", () => {
    const before = slots(graphOf(ZPA));
    const after = growSlots(before, graphOf({ ...ZPA, IpAddress: 3 }));
    for (const [kind, slot] of before) expect(after.get(kind)).toBe(slot);
    // all eight slots are taken, so the new label is the neutral one
    expect(after.get("IpAddress")).toBe(OTHER_SLOT);
  });

  it("gives a new label the lowest free slot", () => {
    const before = slots(graphOf({ Device: 2, Interface: 1 }));
    const after = growSlots(before, graphOf({ Device: 2, Interface: 1, IpAddress: 5 }));
    expect([after.get("Device"), after.get("Interface"), after.get("IpAddress")]).toEqual([0, 1, 2]);
  });
});
