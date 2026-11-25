import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen } from "@testing-library/react";
import type { TimelineRun } from "../data/api";
import Timeline from "./Timeline";
import { subscribe, type EventStream } from "./events";

const runs: TimelineRun[] = [0, 1, 2, 3].map((i) => ({
  key: 100 + i,
  kind: "full",
  parent: i ? 99 + i : null,
  published_ts: 1_800_000_000_000 + i * 3_600_000,
  state: "warm",
  tiers_ready: true,
  counts: { added: i, removed: 0, changed: 0 },
  replan_recommended: false,
}));

describe("the timeline bar", () => {
  it("steps, scrubs and returns to Now", () => {
    const onSeek = vi.fn();
    render(<Timeline runs={runs} position={2} live={3} onSeek={onSeek} onLive={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "Step back" }));
    fireEvent.click(screen.getByRole("button", { name: "Step forward" }));
    fireEvent.change(screen.getByRole("slider", { name: "Scrubber" }), { target: { value: "0" } });
    fireEvent.click(screen.getByRole("button", { name: "Now" }));
    expect(onSeek.mock.calls.map((c) => c[0])).toEqual([1, 3, 0, 3]);
  });

  it("plays forward to the live edge and stops", () => {
    vi.useFakeTimers();
    try {
      const seen: number[] = [];
      const { rerender } = render(<Timeline runs={runs} position={1} live={3} onSeek={(i) => seen.push(i)} onLive={() => {}} playMs={10} />);
      fireEvent.click(screen.getByRole("button", { name: "Play" }));
      act(() => vi.advanceTimersByTime(10));
      rerender(<Timeline runs={runs} position={2} live={3} onSeek={(i) => seen.push(i)} onLive={() => {}} playMs={10} />);
      act(() => vi.advanceTimersByTime(10));
      rerender(<Timeline runs={runs} position={3} live={3} onSeek={(i) => seen.push(i)} onLive={() => {}} playMs={10} />);
      act(() => vi.advanceTimersByTime(50));
      expect(seen).toEqual([2, 3]);
      expect(screen.getByRole("button", { name: "Pause" })).toBeDisabled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows the new-run pill when a run past the live edge is ready", () => {
    const onLive = vi.fn();
    const { rerender } = render(<Timeline runs={runs} position={3} live={3} onSeek={() => {}} onLive={onLive} />);
    expect(screen.queryByRole("button", { name: "New run ready" })).toBeNull();
    rerender(<Timeline runs={runs} position={2} live={2} onSeek={() => {}} onLive={onLive} />);
    fireEvent.click(screen.getByRole("button", { name: "New run ready" }));
    expect(onLive).toHaveBeenCalled();
  });
});

describe("the event subscription", () => {
  it("reports the run key of each tiers-ready event and closes", () => {
    const listeners: Record<string, (e: MessageEvent) => void> = {};
    const stream: EventStream = {
      addEventListener: (type, fn) => {
        listeners[type] = fn;
      },
      close: vi.fn(),
    };
    const ready: number[] = [];
    const stop = subscribe((k) => ready.push(k), (url) => {
      expect(url).toBe("/api/hst/events");
      return stream;
    });
    listeners["run.tiers_ready"](new MessageEvent("run.tiers_ready", { data: JSON.stringify({ run_key: 42, seq: 9 }) }));
    listeners["run.tiers_ready"](new MessageEvent("run.tiers_ready", { data: "not json" }));
    stop();
    expect(ready).toEqual([42]);
    expect(stream.close).toHaveBeenCalled();
  });
});
