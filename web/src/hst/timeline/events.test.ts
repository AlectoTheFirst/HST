import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EVENTS_URL, subscribe, type EventStream } from "./events";

class FakeStream implements EventStream {
  readyState = 1;
  closed = false;
  private listeners = new Map<string, (event: MessageEvent) => void>();

  addEventListener(type: string, listener: (event: MessageEvent) => void): void {
    this.listeners.set(type, listener);
  }

  close(): void {
    this.closed = true;
  }

  emit(type: string, data?: string): void {
    this.listeners.get(type)?.(new MessageEvent(type, { data }));
  }

  /** The stream ends as after a non-200 answer on reconnect. */
  fail(): void {
    this.readyState = 2;
    this.emit("error");
  }
}

function harness() {
  const streams: FakeStream[] = [];
  const urls: string[] = [];
  const ready: number[] = [];
  const reopened = vi.fn();
  const stop = subscribe(
    (key) => ready.push(key),
    (url) => {
      urls.push(url);
      const stream = new FakeStream();
      streams.push(stream);
      return stream;
    },
    reopened,
  );
  return { streams, urls, ready, reopened, stop };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("subscribe", () => {
  it("reports the run key of a run.tiers_ready event and skips a malformed one", () => {
    const { streams, urls, ready } = harness();
    expect(urls).toEqual([EVENTS_URL]);
    streams[0].emit("run.tiers_ready", JSON.stringify({ run_key: 7 }));
    streams[0].emit("run.tiers_ready", "{");
    streams[0].emit("run.tiers_ready", JSON.stringify({ run_key: "7" }));
    expect(ready).toEqual([7]);
  });

  it("leaves a stream alone while the browser reconnects it", () => {
    const { streams } = harness();
    streams[0].readyState = 0;
    streams[0].emit("error");
    vi.advanceTimersByTime(60_000);
    expect(streams).toHaveLength(1);
    expect(streams[0].closed).toBe(false);
  });

  it("opens a closed stream again after 1 s and reports its events", () => {
    const { streams, ready, reopened } = harness();
    streams[0].fail();
    vi.advanceTimersByTime(999);
    expect(streams).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(streams).toHaveLength(2);
    expect(reopened).not.toHaveBeenCalled();
    streams[1].emit("open");
    expect(reopened).toHaveBeenCalledTimes(1);
    streams[1].emit("run.tiers_ready", JSON.stringify({ run_key: 9 }));
    expect(ready).toEqual([9]);
  });

  it("doubles the wait up to 30 s and starts at 1 s again after an open stream", () => {
    const { streams } = harness();
    const waits: number[] = [];
    for (let attempt = 0; attempt < 7; attempt += 1) {
      streams[streams.length - 1].fail();
      let waited = 0;
      const before = streams.length;
      while (streams.length === before) {
        vi.advanceTimersByTime(1_000);
        waited += 1_000;
      }
      waits.push(waited);
    }
    expect(waits).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
    streams[streams.length - 1].emit("open");
    streams[streams.length - 1].fail();
    vi.advanceTimersByTime(1_000);
    expect(streams).toHaveLength(9);
  });

  it("opens no stream after the returned function ran", () => {
    const { streams, stop } = harness();
    streams[0].fail();
    stop();
    vi.advanceTimersByTime(60_000);
    expect(streams).toHaveLength(1);
  });
});
