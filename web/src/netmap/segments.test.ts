import ELK from "elkjs/lib/elk.bundled.js";
import { describe, expect, it } from "vitest";
import type { MapClient, TopologyModel } from "../api/types";
import { toFlatElkGraph, type CyElement } from "./layout";
import type { Layer } from "./overlays";
import { clientElements, GLYPHS, groupKey, macText, segmentLabel } from "./segments";
import { estimate, layoutRow, planRow, rowBars, rowElements } from "./segrow";

const dev = (id: string) => ({ id, kind: "device" as const, parent: "block:s:campus", label: id });
const BD10 = "bd:vlan:fab0:10";
const BD20 = "bd:vlan:fab0:20";

const client = (i: number, bd = BD10): MapClient => ({
  name: `c${i}`,
  uid: `ep:${i}`,
  ips: [`192.168.10.${i}`],
  mac: "11223344556" + (i % 10),
  vendor: "Synology",
  last_seen: 1_760_000_000_000,
  bd,
});

/**
 *   gw-01            eth0.10 192.168.10.1/24, eth0 192.168.2.1/24
 *     |
 *   sw-01            Port 2 to Port 5 carry VLAN 10 untagged
 *     |
 *   ap-01            SSID Home
 */
const MODEL: TopologyModel = {
  snapshot: 1_760_000_000_000,
  nodes: [dev("gw-01"), dev("sw-01"), dev("ap-01")],
  cables: [],
  exits: [],
  lags: [],
  split_groups: [],
  subnets: [
    {
      cidr: "192.168.10.0/24",
      af: 4,
      vrf: "default",
      domain: "home",
      members: [{ dev: "gw-01", iface: "eth0.10", ip: "192.168.10.1", fhrp: null }],
    },
    {
      cidr: "192.168.2.0/24",
      af: 4,
      vrf: "default",
      domain: "home",
      members: [{ dev: "gw-01", iface: "eth0", ip: "192.168.2.1", fhrp: null }],
    },
    {
      cidr: "10.9.0.0/30",
      af: 4,
      vrf: "default",
      domain: "other",
      members: [{ dev: "gw-01", iface: "wg0", ip: "10.9.0.1", fhrp: null }],
    },
  ],
  segments: [
    {
      bd: BD10,
      vid: 10,
      name: "Office",
      cidrs: ["192.168.10.0/24", "2001:db8:a::/64"],
      cidr_basis: "gateway",
      gateways: [
        { dev: "gw-01", iface: "eth0.10", ip: "2001:db8:a::1", cidr: "2001:db8:a::/64", af: 6, vrf: "default", domain: "home", fhrp: null, basis: "svi" },
        { dev: "gw-01", iface: "eth0.10", ip: "192.168.10.1", cidr: "192.168.10.0/24", af: 4, vrf: "default", domain: "home", fhrp: null, basis: "svi" },
      ],
      carriers: [
        { dev: "gw-01", ports: ["eth0"], native: [], access: [] },
        { dev: "sw-01", ports: ["Port 1", "Port 2", "Port 3", "Port 4", "Port 5"], native: ["Port 2", "Port 3", "Port 4", "Port 5"], access: ["Port 2", "Port 3", "Port 4", "Port 5"] },
      ],
      clients: 30,
      attachments: [],
    },
    { bd: BD20, vid: 20, name: "Guest", cidrs: [], cidr_basis: null, gateways: [], carriers: [], clients: 0, attachments: [] },
  ],
  clients: [
    {
      dev: "ap-01",
      port: null,
      ssid: "Home",
      count: 30,
      by_bd: { [BD10]: 28, [BD20]: 2 },
      clients: [...Array.from({ length: 28 }, (_, i) => client(i)), client(98, BD20), client(99, BD20)],
    },
    { dev: "sw-01", port: "Port 2", ssid: null, count: 1, by_bd: { [BD20]: 1 }, clients: [client(50, BD20)] },
  ],
};

const AT = new Map([
  ["gw-01", { x: 0, y: 0, width: 120 }],
  ["sw-01", { x: 0, y: 200, width: 120 }],
  ["ap-01", { x: 300, y: 400, width: 120 }],
]);

const nodes = (els: CyElement[], kind: string) => els.filter((e) => e.group === "nodes" && e.data.kind === kind);

/** The segment row of a layer, laid out with the devices (segrow.ts). */
async function rowOf(layer: Layer, vid: number | null, domain: string | null) {
  const elk = new ELK();
  return layoutRow((g) => elk.layout(g), toFlatElkGraph(MODEL), MODEL, planRow(MODEL, rowBars(MODEL, layer, vid, domain), estimate));
}

describe("the segment bars", () => {
  it("names a segment by its VLAN, its name and its IPv4 prefixes", () => {
    expect(segmentLabel(MODEL.segments![0])).toBe("VLAN 10 Office 192.168.10.0/24");
    expect(segmentLabel({ vid: null, name: null, cidrs: ["2001:db8::/64"] })).toBe("2001:db8::/64");
  });

  it("draws the picked VLAN in L2 as one bar in the layout, with a drop to the gateway and to the access ports", async () => {
    const { laid, row } = await rowOf("l2", 10, null);
    const [bar] = row.bars;
    expect(row.bars).toHaveLength(1);
    expect([bar.bar.title, ...bar.bar.prefixes]).toEqual(["VLAN 10 Office", "192.168.10.0/24", "2001:db8:a::/64"]);
    expect(bar.north.map((s) => [s.drop.dev, s.tag.lines])).toEqual([["gw-01", ["eth0.10 192.168.10.1/24", "2001:db8:a::1/64"]]]);
    expect(bar.south.map((s) => [s.drop.dev, s.tag.lines])).toEqual([["sw-01", ["Port 2, Port 3, Port 4 and 1 more"]]]);
    // ELK puts the bar under the gateway's box, caption included, and over the switch
    const box = (id: string) => laid.children!.find((c) => c.id === id)!;
    expect(box("gw-01").y! + box("gw-01").height!).toBeLessThanOrEqual(box(bar.bar.id).y!);
    expect(box(bar.bar.id).y! + box(bar.bar.id).height!).toBeLessThanOrEqual(box("sw-01").y!);
    // a VLAN with nothing to drop to draws no bar
    expect(rowBars(MODEL, "l2", 20, null)).toEqual([]);
  });

  it("draws one bar per segment of the picked domain in L3, and none for a prefix no segment holds", async () => {
    const { row } = await rowOf("l3", null, "home");
    expect(row.bars.map((b) => b.bar.title)).toEqual(["VLAN 10 Office"]);
    expect(row.bars[0].north.map((s) => s.tag.lines[0])).toEqual(["eth0.10 192.168.10.1/24"]);
    // 192.168.2.0/24 and the /30 of the other domain are in no segment
    expect(rowBars(MODEL, "l3", null, "other")).toEqual([]);
    expect(rowBars(MODEL, "phys", 10, "home")).toEqual([]);
  });

  it("gives the same bars for the same model", async () => {
    const a = await rowOf("l3", null, "home");
    const b = await rowOf("l3", null, "home");
    expect(rowElements(b.row, b.laid)).toEqual(rowElements(a.row, a.laid));
  });
});

describe("the client badges", () => {
  it("draws one collapsed badge per attachment point with the count the layer shows", () => {
    const phys = nodes(clientElements(MODEL, "phys", null, null, AT, new Set()), "clientbadge");
    expect(phys.map((b) => b.data.label)).toEqual(["Home: 30 clients", "Port 2: 1 client"]);
    expect(phys.every((b) => b.classes === "clientbadge")).toBe(true);
    // in L2 only the clients of the picked VLAN count, and a group with none draws no badge
    const l2 = nodes(clientElements(MODEL, "l2", 10, null, AT, new Set()), "clientbadge");
    expect(l2.map((b) => b.data.label)).toEqual(["Home: 28 clients"]);
    // in L3 the clients of the segments on the domain's prefixes count
    expect(nodes(clientElements(MODEL, "l3", null, "home", AT, new Set()), "clientbadge")).toHaveLength(1);
    expect(nodes(clientElements(MODEL, "l3", null, "other", AT, new Set()), "clientbadge")).toHaveLength(0);
  });

  it("expands a badge into at most 24 glyphs with the name, the address and the vendor", () => {
    const key = groupKey(MODEL.clients![0]);
    const els = clientElements(MODEL, "l2", 10, null, AT, new Set([key]));
    const glyphs = nodes(els, "clientglyph");
    expect(glyphs).toHaveLength(GLYPHS);
    expect(glyphs[0].data.label).toBe("c0\n192.168.10.0\nSynology");
    expect(nodes(els, "clientbadge")[0].classes).toBe("clientbadge open");
    // the glyphs sit under the badge, in rows
    expect(glyphs.every((g) => g.position!.y > nodes(els, "clientbadge")[0].position!.y)).toBe(true);
  });

  it("writes a canonical MAC with colons", () => {
    expect(macText("112233445566")).toBe("11:22:33:44:55:66");
    expect(macText("not-a-mac")).toBe("not-a-mac");
    expect(macText(null)).toBe("");
  });
});
