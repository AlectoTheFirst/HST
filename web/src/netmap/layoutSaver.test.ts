import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { layoutSaver } from "./layoutSaver";

interface Flight {
  resolve: (revision: number) => void;
  reject: (error: Error) => void;
}

function harness() {
  const flights: Flight[] = [];
  const saved: number[] = [];
  const settled: unknown[] = [];
  const saver = layoutSaver<number>({
    send: () => new Promise<number>((resolve, reject) => flights.push({ resolve, reject })),
    onSaved: (revision) => saved.push(revision),
    onSettled: (error) => settled.push(error),
    delay: 300,
  });
  return { flights, saved, settled, saver };
}

const turn = () => vi.advanceTimersByTimeAsync(0);

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("layoutSaver", () => {
  it("sends once after the delay for a run of schedule calls", async () => {
    const { flights, saved, settled, saver } = harness();
    saver.schedule();
    await vi.advanceTimersByTimeAsync(200);
    saver.schedule();
    await vi.advanceTimersByTimeAsync(299);
    expect(flights).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(flights).toHaveLength(1);
    flights[0].resolve(6);
    await turn();
    expect(saved).toEqual([6]);
    expect(settled).toEqual([null]);
  });

  it("holds a send asked for during a flight until the flight ends", async () => {
    const { flights, saved, settled, saver } = harness();
    saver.schedule();
    await vi.advanceTimersByTimeAsync(300);
    saver.schedule();
    await vi.advanceTimersByTimeAsync(300);
    saver.schedule();
    await vi.advanceTimersByTimeAsync(300);
    expect(flights).toHaveLength(1);
    flights[0].resolve(6);
    await turn();
    expect(saved).toEqual([6]);
    expect(flights).toHaveLength(2);
    expect(settled).toEqual([]);
    flights[1].resolve(7);
    await turn();
    expect(saved).toEqual([6, 7]);
    expect(settled).toEqual([null]);
  });

  it("reports a failed send and sends again on the next schedule", async () => {
    const { flights, settled, saver } = harness();
    saver.schedule();
    await vi.advanceTimersByTimeAsync(300);
    const stale = new Error("stale");
    flights[0].reject(stale);
    await turn();
    expect(settled).toEqual([stale]);
    saver.schedule();
    await vi.advanceTimersByTimeAsync(300);
    expect(flights).toHaveLength(2);
  });

  it("sends a scheduled send on close and keeps its result from onSettled", async () => {
    const { flights, saved, settled, saver } = harness();
    saver.schedule();
    saver.close();
    await turn();
    expect(flights).toHaveLength(1);
    flights[0].resolve(6);
    await turn();
    expect(saved).toEqual([6]);
    expect(settled).toEqual([]);
  });

  it("keeps a failure after close from onSettled", async () => {
    const { flights, settled, saver } = harness();
    saver.schedule();
    await vi.advanceTimersByTimeAsync(300);
    saver.close();
    flights[0].reject(new Error("stale"));
    await turn();
    expect(settled).toEqual([]);
  });

  it("sends nothing on close without a scheduled send, and nothing after cancel", async () => {
    const { flights, saver } = harness();
    saver.schedule();
    saver.cancel();
    await vi.advanceTimersByTimeAsync(300);
    saver.close();
    await turn();
    expect(flights).toHaveLength(0);
  });
});
