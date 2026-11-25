import { describe, expect, it } from "vitest";
import type { TimelineRun } from "../data/api";
import { timelineModel } from "./model";

function run(i: number, changed: number, state = "warm"): TimelineRun {
  const key = 1_800_000_000_000 + i * 3_600_000;
  return {
    key,
    kind: "full",
    parent: i ? key - 3_600_000 : null,
    published_ts: key,
    state,
    tiers_ready: true,
    counts: { added: 0, removed: 0, changed },
    replan_recommended: false,
  };
}

describe("the timeline model", () => {
  const runs = [run(0, 400, "cold"), run(1, 2, "cold"), run(2, 0), run(3, 40), run(4, 9)];

  it("states Now at the live edge, History before it and Cold on a cold run", () => {
    expect(timelineModel(runs, 4, 4)).toMatchObject({ mode: "now", status: "Now" });
    expect(timelineModel(runs, 3, 4).mode).toBe("history");
    expect(timelineModel(runs, 3, 4).status).toMatch(/^History: /);
    expect(timelineModel(runs, 1, 4)).toMatchObject({ mode: "cold", status: "Cold" });
  });

  it("spreads the ticks over the scrubber, sized by the change count", () => {
    const m = timelineModel(runs, 4, 4);
    expect(m.ticks.map((t) => t.x)).toEqual([0, 0.25, 0.5, 0.75, 1]);
    expect(m.ticks[0].height).toBe(1);
    expect(m.ticks[3].height).toBeGreaterThan(m.ticks[4].height);
    expect(m.ticks[2].height).toBeGreaterThan(0);
    expect(m.ticks[4].label).toMatch(/full, 9 changes$/);
  });

  it("puts the cold runs in one muted band", () => {
    expect(timelineModel(runs, 4, 4).coldBands).toEqual([[0, 0.25]]);
  });

  it("marks one day tick per day in compacted history", () => {
    const old = [0, 1, 30, 31].map((i) => ({ ...run(i, 1, "compacted") }));
    expect(timelineModel([...old, run(60, 1)], 4, 4).dayTicks).toHaveLength(2);
  });

  it("counts the runs past the live edge for the new-run pill", () => {
    expect(timelineModel(runs, 2, 2).pending).toBe(2);
    expect(timelineModel(runs, 4, 4).pending).toBe(0);
  });
});
