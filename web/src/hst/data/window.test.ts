import { describe, expect, it } from "vitest";
import { keyOf, type Row, type TableName } from "../render/types";
import { FakeSource, GONE, MOVED, REPLAN, history } from "../test/runs";
import { LayoutWindow, PREFETCH, RADIUS, REMOVED, ScrubWindow } from "./window";

const states = history(30);

function setup(name: TableName): { source: FakeSource; w: ScrubWindow } {
  const source = new FakeSource(states);
  const w = new ScrubWindow(name, source.keys, {
    tier: (run) => source.tier(name, run),
    delta: (run) => source.delta(name, run),
  });
  return { source, w };
}

function byKey(name: TableName, rows: Row[]): Record<string, Row> {
  return Object.fromEntries(rows.map((r) => [keyOf(name, r), r]));
}

function tierCalls(source: FakeSource): string[] {
  return source.calls.filter((c) => c.startsWith("tier"));
}

describe("the scrub window", () => {
  it("anchors at a run and loads the deltas five runs to each side", async () => {
    const { source, w } = setup("render_t1");
    await w.anchor(15);
    await w.idle();
    expect([...w.deltas.keys()].sort((a, b) => a - b)).toEqual([11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    expect(w.bounds()).toEqual([15 - RADIUS, 15 + RADIUS]);
    expect(tierCalls(source)).toEqual(["tier render_t1 15"]);
  });

  it("steps forward and back inside the window with deltas only", async () => {
    const { source, w } = setup("render_t1");
    await w.anchor(15);
    for (const target of [16, 18, 13, 10, 20, 15]) {
      const step = await w.seek(target);
      expect("changes" in step).toBe(true);
      expect(byKey("render_t1", w.table!.present())).toEqual(byKey("render_t1", states[target].render_t1));
    }
    expect(tierCalls(source)).toEqual(["tier render_t1 15"]);
  });

  it("slides the window within 10 runs of its edge and fetches a new anchor beyond", async () => {
    const { source, w } = setup("render_t1");
    await w.anchor(15);
    await w.idle();
    const slide = await w.seek(28);
    expect("changes" in slide).toBe(true);
    expect(byKey("render_t1", w.table!.present())).toEqual(byKey("render_t1", states[28].render_t1));
    await w.idle();
    const reset = await w.seek(2);
    expect("reset" in reset).toBe(true);
    expect(tierCalls(source)).toEqual(["tier render_t1 15", "tier render_t1 2"]);
    expect(byKey("render_t1", w.table!.present())).toEqual(byKey("render_t1", states[2].render_t1));
  });

  it("shows a removed device as a null change and brings it back when it returns", async () => {
    const { w } = setup("render_t1");
    await w.anchor(3);
    const removed = await w.seek(4);
    expect("changes" in removed && removed.changes).toContainEqual({ key: GONE, row: null });
    const back = await w.seek(7);
    expect("changes" in back && back.changes.find((c) => c.key === GONE)?.row).toMatchObject({ uid: GONE });
  });

  it("prefetches the next deltas after three steps in one direction", async () => {
    const { source, w } = setup("render_t1");
    await w.anchor(10);
    await w.idle();
    for (const target of [11, 12, 13]) await w.seek(target);
    await w.idle();
    const fetched = source.calls.filter((c) => c.startsWith("delta")).map((c) => Number(c.split(" ")[2]));
    expect(fetched).toContain(13 + RADIUS + PREFETCH);
    expect(Math.max(...[...w.deltas.keys()])).toBe(13 + RADIUS + PREFETCH);
  });
});

describe("the layout window", () => {
  function setupLayout(): { source: FakeSource; w: LayoutWindow } {
    const source = new FakeSource(states);
    return { source, w: new LayoutWindow(source.keys, source) };
  }

  function where(rows: Row[], uid: string): [unknown, unknown] {
    const r = rows.find((x) => x.uid === uid)!;
    return [r.u, r.v];
  }

  it("places every element at each run, across a move and a re-plan, both ways", async () => {
    const { w } = setupLayout();
    const placed = new Map<string, Row>((await w.anchor(12)).map((r) => [String(r.uid), r]));
    for (const target of [11, 10, 9, 8, 7, 5, 4, 6, 10, 14]) {
      const step = await w.seek(target);
      if ("reset" in step) {
        placed.clear();
        for (const r of step.reset) placed.set(String(r.uid), r);
      } else {
        for (const c of step.changes) {
          if (c.row) placed.set(c.key, c.row);
          else placed.delete(c.key);
        }
      }
      const expected = new FakeSource(states).rows("layout", target);
      expect(where([...placed.values()], MOVED), `run ${target}`).toEqual(where(expected, MOVED));
      expect(placed.size).toBe(expected.length);
    }
  });

  it("answers a step across the re-plan with the whole layout", async () => {
    const { w } = setupLayout();
    await w.anchor(REPLAN + 2);
    const step = await w.seek(REPLAN - 1);
    expect("reset" in step).toBe(true);
  });

  it("drops an element at the run of its removed row and places it again on the step back", async () => {
    const block: Row = {
      uid: "block:x",
      kind: "block",
      u: 1,
      v: 2,
      w: 6,
      h: 5,
      layout_version: 1,
      reason: "first-seen",
    };
    const gone: Row = { ...block, reason: REMOVED };
    const source = {
      layout: async (run: number): Promise<Row[]> => (run === 0 ? [block] : []),
      layoutDelta: async (run: number): Promise<Row[]> => (run === 1 ? [gone] : []),
    };
    const w = new LayoutWindow([0, 1], source);
    expect((await w.anchor(0)).map((r) => r.uid)).toEqual(["block:x"]);
    expect(await w.seek(1)).toEqual({ changes: [{ key: "block:x", row: null }] });
    expect(await w.seek(0)).toEqual({ changes: [{ key: "block:x", row: block }] });
  });
});
