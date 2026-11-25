import ELK from "elkjs/lib/elk.bundled.js";
import type { ElkNode } from "elkjs/lib/elk-api";
import { describe, expect, it } from "vitest";
import type { TopologyModel } from "../api/types";
import { DEMO_MADRID } from "./fixtures/demoMadrid";
import { DEMO_OFFICE } from "./fixtures/demoOffice";
import { HOME_SITE } from "./fixtures/homeSite";
import { toElements, toFlatElkGraph, type CyElement, type Point } from "./layout";
import { decorate } from "./look";
import type { Layer } from "./overlays";
import { behindRow, deviceBoxes, estimate, layoutRow, planRow, rowBars, rowElements, withBoxes } from "./segrow";
import { deviceRect, layoutBoxes, overlaps, placeTags, shortPort, type CableEnds, type Quad, type Rect, type TagLook } from "./tags";

const elk = new ELK();
const run = (graph: ElkNode) => elk.layout(graph);
const LOOK: TagLook = { ports: true, addresses: true, along: true };

/** The drawn elements of a model in a layer, as the page lays them out. */
async function drawn(model: TopologyModel, layer: Layer = "phys", vid: number | null = null, domain: string | null = null) {
  const bars = layer === "phys" ? [] : rowBars(model, layer, vid, domain);
  const boxes = layoutBoxes(model, deviceBoxes(model, estimate), estimate);
  if (!bars.length) return decorate(toElements(model, await run(withBoxes(toFlatElkGraph(model), boxes))), model);
  const { laid, row } = await layoutRow(run, toFlatElkGraph(model), model, planRow(model, bars, estimate, boxes));
  return decorate(behindRow([...toElements(model, laid), ...rowElements(row, laid)], row), model);
}

const rectOf = (e: CyElement, height: number): Rect => {
  const w = Number(e.data.width);
  return { x0: e.position!.x - w / 2, x1: e.position!.x + w / 2, y0: e.position!.y - height / 2, y1: e.position!.y + height / 2 };
};
const quadOf = (r: Rect): Quad => ({ c: { x: (r.x0 + r.x1) / 2, y: (r.y0 + r.y1) / 2 }, u: { x: 1, y: 0 }, hw: (r.x1 - r.x0) / 2, hh: (r.y1 - r.y0) / 2 });

/** The tags of the straight cables of a drawing, and the boxes they must keep clear of. */
function tagsOf(model: TopologyModel, elements: CyElement[], look = LOOK) {
  const at = new Map<string, Point>(elements.filter((e) => e.data.kind === "device").map((e) => [String(e.data.id), e.position!]));
  const boxes = deviceBoxes(model, estimate);
  const cables: CableEnds[] = elements
    .filter((e) => e.group === "edges" && /\bcable\b/.test(e.classes ?? "") && !/\bbehind\b/.test(e.classes ?? ""))
    .filter((e) => at.has(String(e.data.source)) && at.has(String(e.data.target)))
    .map((e) => ({
      id: String(e.data.id),
      source: String(e.data.source),
      target: String(e.data.target),
      sourcePort: String(e.data.sourcePort ?? ""),
      targetPort: String(e.data.targetPort ?? ""),
      sourceTag: String(e.data.sourceTag ?? ""),
      targetTag: String(e.data.targetTag ?? ""),
    }));
  // the bars with their labels, and their tags
  const obstacles: Rect[] = elements.flatMap((e) => {
    if (e.data.kind === "segtag") return [rectOf(e, Number(e.data.height))];
    if (e.data.kind === "segbar") {
      const r = rectOf(e, 3);
      const lines = String(e.data.label).split("\n").length;
      return [{ ...r, y1: r.y1 + 6 + lines * 13 }];
    }
    return [];
  });
  const places = placeTags(cables, at, boxes, estimate, look, obstacles);
  const devices = [...at].map(([id, p]) => ({ id, q: quadOf(deviceRect(p, boxes.get(id)!)) }));
  return { cables, places, devices, obstacles };
}

/** No tag overlaps another tag, a device box (the symbol and the caption) or a bar; every end has a tag. */
function checkTags(model: TopologyModel, elements: CyElement[], look = LOOK) {
  const { cables, places, devices, obstacles } = tagsOf(model, elements, look);
  const tags: { id: string; q: Quad }[] = [];
  for (const c of cables) {
    const p = places.get(c.id)!;
    expect(p.sourceLabel, `${c.id} source`).not.toBe("");
    expect(p.targetLabel, `${c.id} target`).not.toBe("");
    tags.push({ id: `${c.id} source`, q: p.sourceBox! }, { id: `${c.id} target`, q: p.targetBox! });
  }
  for (const t of tags) {
    for (const o of tags) if (o !== t) expect(overlaps(t.q, o.q), `${t.id} over ${o.id}`).toBe(false);
    for (const d of devices) expect(overlaps(t.q, d.q), `${t.id} over ${d.id}`).toBe(false);
    for (const r of obstacles) expect(overlaps(t.q, quadOf(r)), `${t.id} over a bar`).toBe(false);
  }
  return places;
}

describe("the port tags", () => {
  it("start outside the symbol and the caption, and clear each other, on the Madrid office", async () => {
    checkTags(DEMO_MADRID, await drawn(DEMO_MADRID));
    checkTags(DEMO_MADRID, await drawn(DEMO_MADRID), { ...LOOK, along: false });
    checkTags(DEMO_MADRID, await drawn(DEMO_MADRID), { ...LOOK, addresses: false });
  });

  it("stay clear of the segment bars and their tags in L2 and L3", async () => {
    checkTags(DEMO_MADRID, await drawn(DEMO_MADRID, "l2", 30));
    checkTags(DEMO_MADRID, await drawn(DEMO_MADRID, "l3", null, "corp"));
    checkTags(DEMO_OFFICE, await drawn(DEMO_OFFICE, "l2", 10));
    checkTags(HOME_SITE, await drawn(HOME_SITE, "l2", 10));
    checkTags(HOME_SITE, await drawn(HOME_SITE, "l3", null, "vrf:default"));
  });

  it("draw two cables between the same devices as parallel lines with tags of their own", async () => {
    const [peer] = DEMO_MADRID.cables.filter((c) => c.lateral);
    const second = { ...peer, id: `${peer.id}:2`, from: { ...peer.from, port: "TenGigabitEthernet1/0/2" }, to: { ...peer.to, port: "TenGigabitEthernet1/0/2" } };
    const model = { ...DEMO_MADRID, cables: [...DEMO_MADRID.cables, second] };
    const places = checkTags(model, await drawn(model));
    const a = places.get(peer.id)!;
    const b = places.get(second.id)!;
    expect(a.sourceEndpoint).not.toBeNull();
    expect(b.sourceEndpoint).not.toBeNull();
    expect(a.sourceEndpoint).not.toBe(b.sourceEndpoint);
  });

  it("keep both tags of a short cable readable", () => {
    const at = new Map([
      ["a", { x: 0, y: 0 }],
      ["b", { x: 0, y: 150 }],
    ]);
    const boxes = new Map([
      ["a", { width: 130, height: 78 }],
      ["b", { width: 130, height: 78 }],
    ]);
    const cable = {
      id: "c",
      source: "a",
      target: "b",
      sourcePort: "TenGigabitEthernet1/0/12",
      targetPort: "TenGigabitEthernet1/1/1",
      sourceTag: "TenGigabitEthernet1/0/12 10.0.0.1/30",
      targetTag: "TenGigabitEthernet1/1/1 10.0.0.2/30",
    };
    const p = placeTags([cable], at, boxes, estimate, LOOK).get("c")!;
    expect(p.sourceLabel).not.toBe("");
    expect(p.targetLabel).not.toBe("");
    expect(overlaps(p.sourceBox!, p.targetBox!)).toBe(false);
    for (const [id, pos] of at) {
      const r = deviceRect(pos, boxes.get(id)!);
      expect(overlaps(p.sourceBox!, quadOf(r))).toBe(false);
      expect(overlaps(p.targetBox!, quadOf(r))).toBe(false);
    }
  });

  it("give the same tags for the same drawing", async () => {
    const elements = await drawn(DEMO_MADRID);
    expect(tagsOf(DEMO_MADRID, elements).places).toEqual(tagsOf(DEMO_MADRID, elements).places);
  });

  it("shorten a long interface name the way the platform prints it", () => {
    expect(shortPort("TenGigabitEthernet1/0/12")).toBe("Te1/0/12");
    expect(shortPort("GigabitEthernet0/1")).toBe("Gi0/1");
    expect(shortPort("Port-channel10")).toBe("Po10");
    expect(shortPort("eth0")).toBe("eth0");
  });
});
