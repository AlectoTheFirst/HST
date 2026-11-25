import { describe, expect, it } from "vitest";
import { createNullRenderer } from "../render/null";
import { keyOf, type Row, type TableName } from "../render/types";
import { FakeSource, GONE, diff, history } from "../test/runs";
import { MapData } from "./store";
import { LayoutWindow, ScrubWindow } from "./window";

/**
 * A run whose projection failed has no tables, and the delta of the run after it was folded against none:
 * every row is an add, and a removal is never written. The runs after it have a parent the chain left out.
 */
const states = history(10);
const gap = (i: number): boolean => i !== 4;

function byKey(name: TableName, rows: Row[]): Record<string, Row> {
  return Object.fromEntries(rows.map((r) => [keyOf(name, r), r]));
}

describe("a run whose parent is not the run before it, on the windows", () => {
  it("fetches no delta for it and answers a step across it with the whole table", async () => {
    const source = new FakeSource(states);
    const w = new ScrubWindow(
      "render_t1",
      source.keys,
      { tier: (run) => source.tier("render_t1", run), delta: (run) => source.delta("render_t1", run) },
      gap,
    );
    await w.anchor(3);
    await w.idle();
    expect(w.deltas.has(4)).toBe(false);
    const forward = await w.seek(5);
    expect("reset" in forward).toBe(true);
    expect(byKey("render_t1", w.table!.present())).toEqual(byKey("render_t1", states[5].render_t1));
    const back = await w.seek(3);
    expect("reset" in back).toBe(true);
    expect(byKey("render_t1", w.table!.present())).toEqual(byKey("render_t1", states[3].render_t1));
    expect(source.calls.filter((c) => c === "delta render_t1 4")).toEqual([]);
  });

  it("starts the layout base at the run and answers a step across it with the whole layout", async () => {
    const source = new FakeSource(states);
    const w = new LayoutWindow(source.keys, source, gap);
    await w.anchor(6);
    expect(w.base).toBe(4);
    const before = new LayoutWindow(source.keys, source, gap);
    await before.anchor(3);
    expect("reset" in (await before.seek(5))).toBe(true);
  });
});

describe("the map data across a run whose projection failed", () => {
  /** Run 4 names a parent the chain does not hold, and its delta was folded against no tables. */
  class Gapped extends FakeSource {
    async timeline() {
      const timeline = await super.timeline();
      return { ...timeline, runs: timeline.runs.map((r, i) => (i === 4 ? { ...r, parent: r.key - 1 } : r)) };
    }

    async delta(name: TableName, run: number, block?: string) {
      if (this.keys.indexOf(run) !== 4) return super.delta(name, run, block);
      return diff(name, [], this.rows(name, 4, block));
    }
  }

  async function open(index: number) {
    const source = new Gapped(states);
    const renderer = createNullRenderer();
    const data = new MapData(source, renderer);
    data.setTimeline(await source.timeline());
    await data.open(index);
    return { renderer, data };
  }

  const shown = (renderer: ReturnType<typeof createNullRenderer>) =>
    new Set([...renderer.scene.rows("render_t1")].map((r) => r.uid));

  it("marks the run as not contiguous", async () => {
    const { data } = await open(3);
    expect([4, 5].map((i) => data.contiguous(i))).toEqual([false, true]);
  });

  it("shows the table of the run after the gap when scrubbing forward", async () => {
    const { renderer, data } = await open(3);
    expect(shown(renderer).has(GONE)).toBe(true);
    await data.seek(5);
    expect(shown(renderer)).toEqual(new Set(states[5].render_t1.map((r) => r.uid)));
  });

  it("shows the table of the run before the gap when scrubbing back", async () => {
    const { renderer, data } = await open(6);
    await data.seek(3);
    expect(shown(renderer)).toEqual(new Set(states[3].render_t1.map((r) => r.uid)));
  });
});
