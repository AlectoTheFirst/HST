/**
 * The loop caps the seconds since the last frame at 0.1 s.
 */

export interface LoopRuntime {
  dispose(): void;
}

export function createLoop(
  frame: (now: number, dt: number) => void,
  raf: (callback: FrameRequestCallback) => number = requestAnimationFrame,
  cancel: (handle: number) => void = cancelAnimationFrame,
  start: number = performance.now(),
): LoopRuntime {
  let last = start;
  let handle = 0;
  let stopped = false;
  function tick(now: number) {
    if (stopped) return;
    handle = raf(tick);
    const dt = Math.min((now - last) / 1000, 0.1);
    last = now;
    frame(now, dt);
  }
  handle = raf(tick);
  return {
    dispose() {
      stopped = true;
      cancel(handle);
    },
  };
}
