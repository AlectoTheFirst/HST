import { describe, expect, it } from "vitest";
import { createNullRenderer } from "../render/null";
import { keyOf } from "../render/types";
import { FakeSource, GONE, history } from "../test/runs";
import { MapData, TIER3_ENTRIES } from "./store";

describe("the map data", () => {
  const states = history(20);

  async function open(index: number) {
    const source = new FakeSource(states);
    const renderer = createNullRenderer();
    const data = new MapData(source, renderer);
    data.setTimeline(await source.timeline());
    await data.open(index);
    return { source, renderer, data };
  }

  it("loads Tier 0 and 1 and the layout without Tier 2", async () => {
    const { source, renderer } = await open(19);
    expect(source.calls.filter((c) => c.startsWith("tier")).map((c) => c.split(" ")[1]).sort()).toEqual([
      "context_identity",
      "render_t0",
      "render_t1",
      "render_t1_circuits",
      "render_t1_contexts",
      "render_t1_edges",
      "render_t1_fabric_ports",
    ]);
    expect([...renderer.scene.rows("render_t2_ports")]).toEqual([]);
    expect([...renderer.scene.layout.values()].some((p) => p.kind === "port")).toBe(false);
  });

  it("moves the renderer to each run the timeline seeks", async () => {
    const { renderer, data } = await open(10);
    for (const target of [9, 4, 3, 7, 12]) {
      await data.seek(target);
      const shown = new Map([...renderer.scene.rows("render_t1")].map((r) => [keyOf("render_t1", r), r]));
      expect(shown.size, `run ${target}`).toBe(states[target].render_t1.length);
      expect(shown.has(GONE)).toBe(target < 4 || target >= 7);
    }
  });

  it("folds seeks that arrive while one runs into the newest", async () => {
    const { data } = await open(10);
    await Promise.all([data.seek(11), data.seek(12), data.seek(13)]);
    expect(data.position).toBe(13);
  });

  it("loads a tile at the position and keeps it on the window", async () => {
    const { renderer, data } = await open(10);
    await data.loadTile("block:s0:campus");
    expect([...renderer.scene.rows("render_t2_ports")]).toHaveLength(24);
    await data.seek(12);
    const port = renderer.scene.row("render_t2_ports", "dev:s0d6/port/eth0");
    expect(port?.oper_status).toBe(states[12].render_t2_ports.find((r) => r.uid === "dev:s0d6/port/eth0")?.oper_status);
    data.dropTile("block:s0:campus");
    expect([...renderer.scene.rows("render_t2_ports")]).toEqual([]);
  });

  it("moves a tile that loads during a seek to the run of the seek", async () => {
    const source = new FakeSource(states);
    const renderer = createNullRenderer();
    const data = new MapData(source, renderer);
    data.setTimeline(await source.timeline());
    await data.open(2);
    // The reads of the seek wait. The reads of the tile, which name a block, do not.
    let release = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const tier = source.tier.bind(source);
    source.tier = async (name, run, block) => {
      if (!block) await gate;
      return tier(name, run, block);
    };
    const delta = source.delta.bind(source);
    source.delta = async (name, run, block) => {
      if (!block) await gate;
      return delta(name, run, block);
    };
    const layout = source.layout.bind(source);
    source.layout = async (run, block) => {
      if (!block) await gate;
      return layout(run, block);
    };
    const layoutDelta = source.layoutDelta.bind(source);
    source.layoutDelta = async (run, block) => {
      if (!block) await gate;
      return layoutDelta(run, block);
    };

    const seek = data.seek(18);
    const load = data.loadTile("block:s0:campus");
    await new Promise((resolve) => setTimeout(resolve, 0));
    release();
    await Promise.all([seek, load]);

    expect(data.position).toBe(18);
    const shown = new Map([...renderer.scene.rows("render_t2_ports")].map((r) => [r.uid, r.oper_status]));
    const stored = new Map(
      states[18].render_t2_ports.filter((r) => shown.has(r.uid)).map((r) => [r.uid, r.oper_status]),
    );
    expect(shown.size).toBe(24);
    expect(shown).toEqual(stored);
  });

  it("reads Tier 3 once per device and run and keeps the newest 200", async () => {
    const { source, data } = await open(5);
    await data.device("dev:s0d1");
    await data.device("dev:s0d1");
    expect(source.calls.filter((c) => c.startsWith("device"))).toHaveLength(1);
    for (let i = 0; i < TIER3_ENTRIES + 5; i++) await data.device(`dev:x${i}`);
    expect(data.tier3.size).toBe(TIER3_ENTRIES);
    expect(data.tier3.has("dev:s0d1@" + source.keys[5])).toBe(false);
  });
});
