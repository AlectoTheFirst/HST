import { describe, expect, it } from "vitest";
import { MAX_ROW_CHIPS, layoutSdwan } from "./layout";
import { TOPOLOGY } from "./fixture";

describe("layoutSdwan rows and lanes", () => {
  it("keeps the fit width bounded with 100 devices at one site", () => {
    const devices = Array.from({ length: 100 }, (_, i) => ({
      uid: `sw${i}`,
      name: `SW-${String(i).padStart(3, "0")}`,
      platform: "nxos",
      site: "FR2",
    }));
    const one = layoutSdwan({
      ...TOPOLOGY,
      devices: devices.slice(0, MAX_ROW_CHIPS),
    });
    const many = layoutSdwan({ ...TOPOLOGY, devices });
    expect(many.fit.w).toBeLessThan(one.fit.w * 1.5);
    const rows = new Set(
      many.nodes.filter((n) => n.uid.startsWith("sw")).map((n) => n.y),
    );
    expect(rows.size).toBe(Math.ceil(100 / MAX_ROW_CHIPS));
  });

  it("gives 2 tunnels from one link to one hub 2 lanes", () => {
    const tunnels = [
      {
        uid: "ta",
        interface: "GE3",
        peer: "h1",
        peer_kind: "hub" as const,
        peer_ip: "203.0.113.1",
      },
      {
        uid: "tb",
        interface: "GE3",
        peer: "h1",
        peer_kind: "hub" as const,
        peer_ip: "203.0.113.2",
      },
    ];
    const lines = layoutSdwan({ ...TOPOLOGY, tunnels }).tunnels;
    expect(lines.map((t) => [t.from, t.to])).toEqual([
      ["l3", "h1"],
      ["l3", "h1"],
    ]);
    expect(lines.map((t) => t.lane)).toEqual([0, 1]);
  });
});

describe("layoutSdwan site counts", () => {
  it("labels a site frame with the site name alone", () => {
    const sites = TOPOLOGY.sites.map((s, i) => (i === 0 ? { ...s, other_devices: 3 } : s));
    const frame = layoutSdwan({ ...TOPOLOGY, sites }).frames.find((f) => f.key === TOPOLOGY.sites[0].code)!;
    expect(frame.label).toBe("FR6");
  });
});
