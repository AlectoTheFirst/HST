import ELK from "elkjs/lib/elk.bundled.js";
import type { ElkNode } from "elkjs/lib/elk-api";
import { describe, expect, it } from "vitest";
import type { TopologyModel } from "../api/types";
import { DEMO_MADRID } from "./fixtures/demoMadrid";
import { DEMO_OFFICE } from "./fixtures/demoOffice";
import { crossings, dropLines as lines } from "./fixtures/geometry";
import { HOME_SITE } from "./fixtures/homeSite";
import { toElements, toFlatElkGraph, withPositions, type CyElement } from "./layout";
import type { Layer } from "./overlays";
import {
  behindRow,
  dropRoutes,
  GLUE,
  estimate,
  layoutRow,
  linkPrefixes,
  planRow,
  portsText,
  rowBars,
  segmentId,
  rowElements,
  jointId,
  shortAddress,
  vlanTitle,
  type Row,
} from "./segrow";

const elk = new ELK();
const run = (graph: ElkNode) => elk.layout(graph);

interface Rect {
  id: string;
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

const overlap = (a: Rect, b: Rect) =>
  a.x0 < b.x1 && b.x0 < a.x1 && a.y0 < b.y1 && b.y0 < a.y1;

async function view(
  model: TopologyModel,
  layer: Layer,
  vid: number | null,
  domain: string | null,
) {
  const bars = rowBars(model, layer, vid, domain);
  const planned = planRow(model, bars, estimate);
  const { laid, row } = await layoutRow(
    run,
    toFlatElkGraph(model),
    model,
    planned,
  );
  return { laid, row, elements: rowElements(row, laid) };
}

function rects(laid: ElkNode, ids: (id: string) => boolean): Rect[] {
  return (laid.children ?? [])
    .filter((c) => ids(c.id))
    .map((c) => ({
      id: c.id,
      x0: c.x!,
      y0: c.y!,
      x1: c.x! + c.width!,
      y1: c.y! + c.height!,
    }));
}

/** The drawn segments of a drop: its ELK route. */
function dropLines(
  laid: ElkNode,
): { id: string; pts: { x: number; y: number }[] }[] {
  return (laid.edges ?? [])
    .filter((e) => e.id.includes(":drop:"))
    .map((e) => {
      const s = e.sections![0];
      return {
        id: e.id,
        pts: [s.startPoint, ...(s.bendPoints ?? []), s.endPoint],
      };
    });
}

/** Whether two axis-parallel segments run along one line for more than a point. */
function collinear(
  a: [{ x: number; y: number }, { x: number; y: number }],
  b: [{ x: number; y: number }, { x: number; y: number }],
) {
  const eps = 0.5;
  const horiz = (s: typeof a) => Math.abs(s[0].y - s[1].y) < eps;
  const vert = (s: typeof a) => Math.abs(s[0].x - s[1].x) < eps;
  if (horiz(a) && horiz(b) && Math.abs(a[0].y - b[0].y) < eps) {
    const [a0, a1] = [Math.min(a[0].x, a[1].x), Math.max(a[0].x, a[1].x)];
    const [b0, b1] = [Math.min(b[0].x, b[1].x), Math.max(b[0].x, b[1].x)];
    return Math.min(a1, b1) - Math.max(a0, b0) > eps;
  }
  if (vert(a) && vert(b) && Math.abs(a[0].x - b[0].x) < eps) {
    const [a0, a1] = [Math.min(a[0].y, a[1].y), Math.max(a[0].y, a[1].y)];
    const [b0, b1] = [Math.min(b[0].y, b[1].y), Math.max(b[0].y, b[1].y)];
    return Math.min(a1, b1) - Math.max(a0, b0) > eps;
  }
  return false;
}

/** Whether a segment passes through the inside of a box. */
function crosses(
  p: { x: number; y: number },
  q: { x: number; y: number },
  r: Rect,
) {
  const inset = 1;
  const x0 = Math.min(p.x, q.x);
  const x1 = Math.max(p.x, q.x);
  const y0 = Math.min(p.y, q.y);
  const y1 = Math.max(p.y, q.y);
  return (
    x0 < r.x1 - inset &&
    x1 > r.x0 + inset &&
    y0 < r.y1 - inset &&
    y1 > r.y0 + inset
  );
}

function check(
  model: TopologyModel,
  laid: ElkNode,
  row: Row,
  elements: CyElement[],
) {
  const devices = new Set(
    model.nodes.filter((n) => n.kind === "device").map((n) => n.id),
  );
  const deviceBoxes = rects(laid, (id) => devices.has(id));
  const barBoxes = rects(laid, (id) => id.startsWith("seg:"));
  expect(barBoxes).toHaveLength(row.bars.length);
  // no bar crosses a device box, which holds the symbol and the caption, nor another bar
  for (const b of barBoxes) {
    for (const d of deviceBoxes)
      expect(overlap(b, d), `${b.id} over ${d.id}`).toBe(false);
    for (const o of barBoxes)
      if (o !== b) expect(overlap(b, o), `${b.id} over ${o.id}`).toBe(false);
  }
  // the row sits under every device above it and over every device under it
  for (const b of barBoxes) {
    for (const d of deviceBoxes) {
      if (row.upper.has(d.id))
        expect(d.y1, `${d.id} above ${b.id}`).toBeLessThanOrEqual(b.y0);
      else expect(d.y0, `${d.id} under ${b.id}`).toBeGreaterThanOrEqual(b.y1);
    }
  }
  // every label and every tag fits in its bar
  for (const b of row.bars) {
    expect(b.labelX + b.labelWidth, b.bar.id).toBeLessThanOrEqual(b.width);
    for (const s of [...b.north, ...b.south]) {
      expect(s.x - s.tag.width / 2, s.drop.key).toBeGreaterThanOrEqual(0);
      expect(s.x + s.tag.width / 2, s.drop.key).toBeLessThanOrEqual(b.width);
    }
    // a tag under the line keeps clear of the label
    for (const s of b.south)
      expect(s.x - s.tag.width / 2).toBeGreaterThanOrEqual(
        b.labelX + b.labelWidth,
      );
  }
  // no tag overlaps another tag or a device box
  const tags: Rect[] = elements
    .filter((e) => e.data.kind === "segtag")
    .map((e) => {
      const w = Number(e.data.width);
      const h = Number(e.data.height);
      return {
        id: String(e.data.id),
        x0: e.position!.x - w / 2,
        y0: e.position!.y - h / 2,
        x1: e.position!.x + w / 2,
        y1: e.position!.y + h / 2,
      };
    });
  for (const t of tags) {
    for (const o of tags)
      if (o !== t) expect(overlap(t, o), `${t.id} over ${o.id}`).toBe(false);
    for (const d of deviceBoxes)
      expect(overlap(t, d), `${t.id} over ${d.id}`).toBe(false);
  }
  // no two drops run along one line, and no drop passes through a device box or another bar
  const lines = dropLines(laid);
  const segs = lines.flatMap((l) =>
    l.pts
      .slice(1)
      .map((q, i) => ({
        id: l.id,
        seg: [l.pts[i], q] as [typeof q, typeof q],
      })),
  );
  for (const a of segs)
    for (const b of segs)
      if (a.id !== b.id)
        expect(collinear(a.seg, b.seg), `${a.id} along ${b.id}`).toBe(false);
  for (const l of lines) {
    const bar = l.id.slice(0, l.id.indexOf(":drop:"));
    for (let i = 1; i < l.pts.length; i++) {
      for (const d of deviceBoxes) {
        // a drop starts or ends at the edge of its own device's box
        if (crosses(l.pts[i - 1], l.pts[i], d))
          expect.fail(`${l.id} through ${d.id}`);
      }
      for (const o of barBoxes)
        if (o.id !== bar && crosses(l.pts[i - 1], l.pts[i], o))
          expect.fail(`${l.id} through ${o.id}`);
    }
  }
}

describe("the segment bars of the home site", () => {
  it("draws one bar per VLAN in L3, side by side in VLAN order under the router", async () => {
    const { laid, row, elements } = await view(
      HOME_SITE,
      "l3",
      null,
      "vrf:default",
    );
    expect(row.bars.map((b) => b.bar.title)).toEqual([
      "VLAN 1 Default",
      "VLAN 10 VL_10_HOME",
      "VLAN 20 VL_20_IOT",
      "VLAN 30 VL_30_GUEST",
      "VLAN 40 VL_40_CAMERAS",
      "VLAN 50 VL_50_LAB",
    ]);
    // dual stack: two prefixes under the label, and both addresses in the tag
    expect(row.bars[1].bar.prefixes).toEqual([
      "192.168.10.0/24",
      "2001:db8:10::/64",
    ]);
    expect(row.bars[1].north.map((s) => s.tag.lines)).toEqual([
      ["eth0.10 192.168.10.1/24", "2001:db8:10::1/64"],
    ]);
    // the untagged eth0 joins the default network
    expect(row.bars[0].north.map((s) => s.tag.lines[0])).toEqual([
      "eth0 192.168.2.1/24",
    ]);
    // one row: every bar at one height, in VLAN order from left to right
    const boxes = rects(laid, (id) => id.startsWith("seg:"));
    expect(new Set(boxes.map((b) => b.y0)).size).toBe(1);
    const xs = row.bars.map((b) => boxes.find((x) => x.id === b.bar.id)!.x0);
    expect(xs).toEqual([...xs].sort((a, b) => a - b));
    // only the router is above the row
    expect([...row.upper]).toEqual(["dev:gw-01"]);
    check(HOME_SITE, laid, row, elements);
  });

  it("draws no bar for a prefix that no segment holds", () => {
    const ids = rowBars(HOME_SITE, "l3", null, "vrf:default").flatMap(
      (b) => b.prefixes,
    );
    for (const cidr of ["203.0.113.0/24", "10.255.0.0/24", "10.0.0.1/32"])
      expect(ids).not.toContain(cidr);
  });

  it("draws the picked VLAN in L2 as one bar with a drop to every device that carries it", async () => {
    const { laid, row, elements } = await view(HOME_SITE, "l2", 10, null);
    expect(row.bars).toHaveLength(1);
    const [bar] = row.bars;
    expect(bar.north.map((s) => [s.drop.dev, s.tag.lines[0]])).toEqual([
      ["dev:gw-01", "eth0.10 192.168.10.1/24"],
    ]);
    expect(bar.south.map((s) => s.drop.dev).sort()).toEqual(
      [
        "dev:ap-garden",
        "dev:ap-hall",
        "dev:ap-office",
        "dev:sw-attic",
        "dev:sw-core",
        "dev:sw-office",
      ].sort(),
    );
    const office = bar.south.find((s) => s.drop.dev === "dev:sw-office")!;
    expect(office.tag.lines).toEqual(["Port 2, Port 3, Port 4 and 2 more"]);
    // a switch with no access port in the VLAN names its trunk ports
    expect(
      bar.south.find((s) => s.drop.dev === "dev:sw-core")!.tag.lines,
    ).toEqual(["Port 1, Port 2, Port 3 and 1 more"]);
    check(HOME_SITE, laid, row, elements);
  });

  it("draws every VLAN of the site in L2 within the row invariants", async () => {
    for (const vid of [1, 20, 30, 40, 50]) {
      const { laid, row, elements } = await view(HOME_SITE, "l2", vid, null);
      check(HOME_SITE, laid, row, elements);
    }
  });

  it("gives the same drawing for the same model", async () => {
    const a = await view(HOME_SITE, "l3", null, "vrf:default");
    const b = await view(HOME_SITE, "l3", null, "vrf:default");
    expect(b.elements).toEqual(a.elements);
    const plain = (n: ElkNode) =>
      JSON.stringify(n, (k, v) => (k === "$H" ? undefined : v));
    expect(plain(b.laid)).toEqual(plain(a.laid));
  });

  it("keeps the bars where they are when a device moves", async () => {
    const { elements } = await view(HOME_SITE, "l3", null, "vrf:default");
    const moved = withPositions(elements, {
      "dev:gw-01": { x: 5000, y: -300 },
    });
    const bars = (els: CyElement[]) =>
      els
        .filter((e) => e.data.kind === "segbar")
        .map((e) => [e.data.id, e.position]);
    expect(bars(moved)).toEqual(bars(elements));
  });
});

describe("the segment bars of the demo office", () => {
  it("draws the seven corp VLANs once each, with one drop from the HSRP pair of cores, in L3", async () => {
    const { laid, row, elements } = await view(DEMO_OFFICE, "l3", null, "corp");
    expect(row.bars.map((b) => b.bar.title)).toEqual([
      "VLAN 10 vie01-users",
      "VLAN 20 vie01-voice",
      "VLAN 30 vie01-printers",
      "VLAN 40 vie01-servers",
      "VLAN 99 vie01-mgmt",
      "VLAN 250 vie01-fw-transit",
    ]);
    // the two cores share a virtual address on each bar: one gateway, one drop from their joint
    const joint = jointId(["dev:vie01-core-01", "dev:vie01-core-02"]);
    for (const b of row.bars) {
      expect(b.north.map((s) => [s.drop.dev, s.drop.members])).toEqual([[joint, ["dev:vie01-core-01", "dev:vie01-core-02"]]]);
    }
    expect(row.bars[0].north[0].tag.lines).toEqual(["vlan10 10.11.10.1 (.2 .3)"]);
    // the joint sits between the two cores and under them
    const box = (id: string) => laid.children!.find((c) => c.id === id)!;
    const mid = (id: string) => box(id).x! + box(id).width! / 2;
    expect(mid(joint)).toBeGreaterThan(Math.min(mid("dev:vie01-core-01"), mid("dev:vie01-core-02")));
    expect(mid(joint)).toBeLessThan(Math.max(mid("dev:vie01-core-01"), mid("dev:vie01-core-02")));
    expect(box(joint).y!).toBeGreaterThan(box("dev:vie01-core-01").y! + box("dev:vie01-core-01").height!);
    check(DEMO_OFFICE, laid, row, elements);
  });

  it("draws each VLAN in L2 within the row invariants", async () => {
    for (const vid of [10, 20, 30, 40, 99, 250, 900]) {
      const { laid, row, elements } = await view(DEMO_OFFICE, "l2", vid, null);
      expect(row.bars, String(vid)).toHaveLength(1);
      check(DEMO_OFFICE, laid, row, elements);
    }
  });

  it("names a routed link on its cable", () => {
    const links = linkPrefixes(
      {
        ...DEMO_OFFICE,
        subnets: [
          ...(DEMO_OFFICE.subnets ?? []),
          {
            cidr: "10.11.252.0/31",
            af: 4,
            vrf: "corp",
            domain: "corp",
            members: [
              {
                dev: "dev:vie01-fgt-01",
                iface: "port3",
                ip: "10.11.252.0",
                fhrp: null,
              },
              {
                dev: "dev:vie01-vce-01",
                iface: "ge2",
                ip: "10.11.252.1",
                fhrp: null,
              },
            ],
          },
        ],
      },
      "corp",
    );
    expect([...links.values()]).toEqual(["10.11.252.0/31"]);
  });
});

describe("the row pieces", () => {
  it("names a segment by its VLAN and its name", () => {
    expect(vlanTitle({ vid: 10, name: "Office" })).toBe("VLAN 10 Office");
    expect(vlanTitle({ vid: null, name: "BD-Web" })).toBe("BD-Web");
  });

  it("routes the drops of a moved device with turns of their own", () => {
    const routes = dropRoutes([
      { id: "a", dev: "r", start: { x: 0, y: 0 }, end: { x: -300, y: 200 } },
      { id: "b", dev: "r", start: { x: 10, y: 0 }, end: { x: -100, y: 200 } },
      { id: "c", dev: "r", start: { x: 20, y: 0 }, end: { x: 300, y: 200 } },
      { id: "d", dev: "r", start: { x: 30, y: 0 }, end: { x: 500, y: 200 } },
    ]);
    const turn = (id: string) => routes.get(id)![0].y;
    // the outer drop turns first on each side, so none crosses another's turn
    expect(turn("a")).toBeLessThan(turn("b"));
    expect(turn("d")).toBeLessThan(turn("c"));
  });

  it("lays out a cable that crosses the row without a route, and keeps the device under it by a layout-only edge", async () => {
    const { laid, row } = await view(HOME_SITE, "l3", null, "vrf:default");
    const ids = (laid.edges ?? []).map((e) => e.id);
    const cable = HOME_SITE.cables.find((c) => c.from.dev === "dev:gw-01")!;
    expect(ids).not.toContain(cable.id);
    expect(ids).toContain(`${GLUE}${cable.id}`);
    // the core switch sits under the router's bars
    const pos = new Map((laid.children ?? []).map((c) => [c.id, c]));
    const first = pos.get(row.bars[0].bar.id)!;
    const last = pos.get(row.bars[row.bars.length - 1].bar.id)!;
    const core = pos.get("dev:sw-core")!;
    expect(core.x!).toBeGreaterThan(first.x!);
    expect(core.x! + core.width!).toBeLessThan(last.x! + last.width!);
  });

  it("puts a cable that crosses the row behind it", async () => {
    const { row } = await view(HOME_SITE, "l3", null, "vrf:default");
    const cable: CyElement = {
      group: "edges",
      data: { id: "c", source: "dev:gw-01", target: "dev:sw-core" },
      classes: "cable",
    };
    const under: CyElement = {
      group: "edges",
      data: { id: "d", source: "dev:sw-core", target: "dev:sw-office" },
      classes: "cable",
    };
    expect(behindRow([cable, under], row).map((e) => e.classes)).toEqual([
      "cable behind",
      "cable",
    ]);
  });

  it("writes long port names one per line", () => {
    expect(portsText(["Port 1", "Port 2"])).toEqual(["Port 1, Port 2"]);
    expect(
      portsText(["TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/2"]),
    ).toEqual(["TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/2"]);
    expect(
      portsText(["Gi1/0/11", "Gi1/0/12", "Gi1/0/13", "Gi1/0/14", "Gi1/0/15"]),
    ).toEqual(["Gi1/0/11", "Gi1/0/12", "Gi1/0/13", "and 2 more"]);
  });
});

/** Whether the segment from `p` to `q` passes through the inside of the box. */
function through(p: { x: number; y: number }, q: { x: number; y: number }, r: Rect): boolean {
  let t0 = 0;
  let t1 = 1;
  const d = { x: q.x - p.x, y: q.y - p.y };
  for (const [pc, dc, lo, hi] of [
    [p.x, d.x, r.x0 + 0.5, r.x1 - 0.5],
    [p.y, d.y, r.y0 + 0.5, r.y1 - 0.5],
  ] as const) {
    if (Math.abs(dc) < 1e-9) {
      if (pc <= lo || pc >= hi) return false;
      continue;
    }
    const a = (lo - pc) / dc;
    const b = (hi - pc) / dc;
    t0 = Math.max(t0, Math.min(a, b));
    t1 = Math.min(t1, Math.max(a, b));
  }
  return t0 < t1;
}

/** The drawn line of a cable: straight between the symbol centres, or bent where its data says. */
function cableLine(e: CyElement, at: Map<string, { x: number; y: number }>) {
  const a = at.get(String(e.data.source))!;
  const b = at.get(String(e.data.target))!;
  if (!/\bvia\b/.test(e.classes ?? "")) return [a, b];
  const ws = String(e.data.viaWeights).split(" ").map(Number);
  const ds = String(e.data.viaDistances).split(" ").map(Number);
  const l = Math.hypot(b.x - a.x, b.y - a.y);
  const n = { x: -(b.y - a.y) / l, y: (b.x - a.x) / l };
  return [a, ...ws.map((w, i) => ({ x: a.x + w * (b.x - a.x) + ds[i] * n.x, y: a.y + w * (b.y - a.y) + ds[i] * n.y })), b];
}

describe("the drops and the cables at the row", () => {
  const cases: [string, TopologyModel, Layer, number | null, string | null, number][] = [
    ["home L3", HOME_SITE, "l3", null, "vrf:default", 0],
    ["home L2 1", HOME_SITE, "l2", 1, null, 0],
    ["home L2 10", HOME_SITE, "l2", 10, null, 0],
    ["vie01 L2 10", DEMO_OFFICE, "l2", 10, null, 0],
    ["mad01 L2 30", DEMO_MADRID, "l2", 30, null, 0],
    // an HSRP pair on six bars: one drop per bar from the pair's joint
    ["vie01 L3", DEMO_OFFICE, "l3", null, "corp", 0],
    ["mad01 L3", DEMO_MADRID, "l3", null, "corp", 0],
    ["mad01 L2 10", DEMO_MADRID, "l2", 10, null, 0],
  ];

  it("never crosses two drops of one device, and crosses two devices' drops no more than the topology needs", async () => {
    for (const [name, model, layer, vid, domain, most] of cases) {
      const { laid, row } = await view(model, layer, vid, domain);
      const n = crossings(lines(laid, row));
      expect(n.same, name).toBe(0);
      expect(n.other, name).toBeLessThanOrEqual(most);
    }
  });

  it("runs a drop from a device under the bar straight up when nothing is in its way", async () => {
    const { laid, row } = await view(DEMO_MADRID, "l2", 30, null);
    for (const line of lines(laid, row)) {
      const xs = new Set(line.pts.map((p) => Math.round(p.x)));
      expect(xs.size, line.id).toBe(1);
    }
  });

  it("passes a cable across the row clear of every label, prefix line and tag", async () => {
    for (const [name, model, layer, vid, domain] of cases) {
      const { laid, row } = await view(model, layer, vid, domain);
      const drawn = toElements(model, laid);
      const elements = behindRow([...drawn, ...rowElements(row, laid)], row);
      const at = new Map(elements.filter((e) => e.data.kind === "device").map((e) => [String(e.data.id), e.position!]));
      const pos = new Map((laid.children ?? []).map((c) => [c.id, c]));
      const blocked: Rect[] = row.bars.flatMap((b) => {
        const box = pos.get(b.bar.id)!;
        const label = { id: `${b.bar.id} label`, x0: box.x! + b.labelX, x1: box.x! + b.labelX + b.labelWidth, y0: box.y! + b.lineY, y1: box.y! + b.height };
        const tags = [...b.north, ...b.south].map((s) => {
          const north = b.north.includes(s);
          const y0 = north ? box.y! + b.lineY - s.tag.height - 4 : box.y! + b.lineY + 4;
          return { id: `${b.bar.id} ${s.drop.key}`, x0: box.x! + s.x - s.tag.width / 2, x1: box.x! + s.x + s.tag.width / 2, y0, y1: y0 + s.tag.height };
        });
        return [label, ...tags];
      });
      for (const e of elements.filter((x) => /\bbehind\b/.test(x.classes ?? ""))) {
        const pts = cableLine(e, at);
        for (let i = 1; i < pts.length; i++) {
          for (const r of blocked) expect(through(pts[i - 1], pts[i], r), `${name}: ${e.data.id} through ${r.id}`).toBe(false);
        }
      }
    }
  });
});

describe("a first-hop pair", () => {
  it("writes the members' addresses in short form after the virtual address", () => {
    expect(shortAddress("10.15.30.3", "10.15.30.1")).toBe(".3");
    expect(shortAddress("10.15.31.3", "10.15.30.1")).toBe(".31.3");
    expect(shortAddress("2001:db8:30::3", "2001:db8:30::1")).toBe(":3");
  });

  it("keeps the own drop of a router that shares no virtual address on the bar", () => {
    const [bar] = rowBars(HOME_SITE, "l3", null, "vrf:default");
    expect(bar.drops.map((d) => [d.dev, d.members])).toEqual([["dev:gw-01", undefined]]);
  });
});

describe("segmentId", () => {
  it("keeps one element per bridge domain and site when the drawing holds a record per site", () => {
    expect(segmentId({ bd: "bd:vlan:default:10" })).toBe("seg:bd:vlan:default:10");
    expect(segmentId({ bd: "bd:vlan:default:10", site: "ham1" })).toBe("seg:bd:vlan:default:10@ham1");
    const [seg] = HOME_SITE.segments!.filter((g) => g.gateways.length > 0);
    const model = { ...HOME_SITE, segments: [{ ...seg, site: "ham1" }, { ...seg, site: "ham2" }] };
    const ids = rowBars(model, "l3", null, "vrf:default").map((b) => b.id);
    expect(ids).toContain(`seg:${seg.bd}@ham1`);
    expect(ids).toContain(`seg:${seg.bd}@ham2`);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
