import { describe, expect, it } from "vitest";
import { METRO } from "./fixture";
import { anchorOf, layoutMetro, METRICS, OTHER_PARTIES } from "./layout";

describe("layoutMetro", () => {
  const layout = layoutMetro(METRO);
  const node = (uid: string) => layout.nodes.find((n) => n.uid === uid)!;

  it("puts the devices on top, the Fabric ports in the middle and the far ends at the bottom", () => {
    const sw = node("dev:xx-swc-02");
    const edge = node("eqx:device:edge");
    const pri = node("eqx:port:pri");
    const cloud = node("far:provider:AWS Direct Connect");
    expect(sw.y).toBe(edge.y);
    expect(pri.y).toBeGreaterThan(sw.y);
    expect(cloud.y).toBeGreaterThan(pri.y);
    expect(sw.kind).toBe("switch");
    expect(edge.kind).toBe("edge");
    expect(cloud.kind).toBe("provider");
  });

  it("draws one frame per IBX around its ports, in IBX order", () => {
    expect(layout.frames.map((f) => f.label)).toEqual(["IBX XX1", "IBX XX2"]);
    const [xx1, xx2] = layout.frames;
    for (const uid of ["eqx:port:pri", "eqx:port:sec"]) {
      const n = node(uid);
      expect(n.x - n.w / 2).toBeGreaterThanOrEqual(xx1.x);
      expect(n.x + n.w / 2).toBeLessThanOrEqual(xx1.x + xx1.width);
    }
    expect(node("eqx:port:int").x).toBeGreaterThan(xx2.x);
  });

  it("cables each switch to the Fabric ports that its ports realize", () => {
    expect(layout.cables).toEqual([
      { device: "dev:xx-swc-02", fabricPort: "eqx:port:pri", portName: "Ethernet1/3", by: "name+cable" },
      { device: "dev:xx-swc-02", fabricPort: "eqx:port:sec", portName: "Ethernet1/4", by: "operator" },
    ]);
    expect(node("eqx:port:int").caption).toContain("no switch port");
  });

  it("bundles the circuits of one node pair and names each far end once", () => {
    const pair = (a: string, b: string) => layout.bundles.find((x) => [x.a, x.b].sort().join("|") === [a, b].sort().join("|"));
    expect(pair("eqx:port:pri", "far:provider:AWS Direct Connect")?.circuits.map((c) => c.uid)).toEqual([
      "vc:cloud-1",
      "vc:cloud-2",
    ]);
    expect(pair("eqx:port:sec", "far:metro:YY")?.circuits).toHaveLength(1);
    expect(pair("eqx:port:sec", OTHER_PARTIES)?.circuits).toHaveLength(1);
    // both ends in the metro: the bundle goes between the two nodes
    expect(pair("eqx:port:sec", "eqx:port:int")?.circuits).toHaveLength(1);
    expect(pair("eqx:device:edge", "eqx:port:int")?.circuits).toHaveLength(1);
    expect(node("far:provider:AWS Direct Connect").caption).toBe("2 circuits");
    expect(layout.nodes.filter((n) => n.kind === "metro").map((n) => n.name)).toEqual(["Metro YY"]);
    expect(layout.undrawn).toBe(0);
  });

  it("orders the bottom row: metros, providers by circuit count, other parties last", () => {
    const bottom = layout.nodes.filter((n) => ["metro", "provider", "other"].includes(n.kind)).sort((a, b) => a.x - b.x);
    expect(bottom.map((n) => n.kind)).toEqual(["metro", "provider", "other"]);
  });

  it("fits every node", () => {
    for (const n of layout.nodes) {
      expect(n.x + n.w / 2).toBeLessThanOrEqual(layout.fit.w);
      expect(n.y + n.h / 2).toBeLessThanOrEqual(layout.fit.h);
    }
  });

  it("anchors an end of another metro on that metro, and an unknown end on the other parties", () => {
    const drawn = new Set(["eqx:port:pri"]);
    expect(anchorOf({ kind: "port", node: "eqx:port:pri", name: "p", metro: "XX", tag: null }, "XX", drawn)).toBe(
      "eqx:port:pri",
    );
    expect(anchorOf({ kind: "port", node: "eqx:port:zz", name: "p", metro: "ZZ", tag: null }, "XX", drawn)).toBe("far:metro:ZZ");
    expect(anchorOf({ kind: "other", name: "colo", tag: null }, "XX", drawn)).toBe(OTHER_PARTIES);
    expect(anchorOf(null, "XX", drawn)).toBe(OTHER_PARTIES);
  });

  it("lays out a metro with only a Network Edge device", () => {
    const only = layoutMetro({ ...METRO, ports: [], devices: [], circuits: [] });
    expect(only.nodes.map((n) => n.uid)).toEqual(["eqx:device:edge"]);
    expect(only.frames).toEqual([]);
    expect(only.fit.w).toBeGreaterThan(METRICS.chipW);
  });
});
