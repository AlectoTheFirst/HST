import { useEffect, useState } from "react";
import type { TimelineRun } from "../data/api";
import { timelineModel } from "./model";

interface Props {
  runs: TimelineRun[];
  position: number;
  /** The newest index shown as Now. */
  live: number;
  onSeek(index: number): void;
  /** Moves the live edge to the newest run. */
  onLive(): void;
  playMs?: number;
}

export default function Timeline({ runs, position, live, onSeek, onLive, playMs = 800 }: Props) {
  const m = timelineModel(runs, position, live);
  const [playing, setPlaying] = useState(false);
  const active = playing && position < live;

  useEffect(() => {
    if (!active) return;
    const id = setTimeout(() => {
      if (position + 1 >= live) setPlaying(false);
      onSeek(position + 1);
    }, playMs);
    return () => clearTimeout(id);
  }, [active, position, live, onSeek, playMs]);

  const last = runs.length - 1;
  return (
    <div className={`hst-timeline hst-mode-${m.mode}`} role="group" aria-label="Timeline">
      <button type="button" onClick={() => setPlaying(true)} disabled={active || position >= live}>
        Play
      </button>
      <button type="button" onClick={() => setPlaying(false)} disabled={!active}>
        Pause
      </button>
      <button type="button" onClick={() => onSeek(position - 1)} disabled={position <= 0}>
        Step back
      </button>
      <button type="button" onClick={() => onSeek(position + 1)} disabled={position >= last}>
        Step forward
      </button>
      <div className="hst-scrubber">
        <svg className="hst-ticks" viewBox="0 0 1000 24" preserveAspectRatio="none" aria-hidden="true">
          {m.coldBands.map(([a, b]) => (
            <rect key={a} className="hst-cold-band" x={a * 1000 - 4} y={0} width={(b - a) * 1000 + 8} height={24} />
          ))}
          {m.dayTicks.map((d) => (
            <line key={d.x} className="hst-day-tick" x1={d.x * 1000} x2={d.x * 1000} y1={0} y2={24} />
          ))}
          {m.ticks.map((t) => (
            <rect
              key={t.key}
              className={t.cold ? "hst-tick hst-tick-cold" : "hst-tick"}
              x={t.x * 1000 - 1}
              y={24 - t.height * 24}
              width={2}
              height={t.height * 24}
            />
          ))}
        </svg>
        <input
          type="range"
          aria-label="Scrubber"
          min={0}
          max={Math.max(0, last)}
          value={Math.max(0, position)}
          aria-valuetext={m.ticks[position]?.label ?? "no run"}
          onChange={(e) => onSeek(Number(e.target.value))}
          disabled={runs.length === 0}
        />
      </div>
      <button type="button" onClick={() => onSeek(live)} disabled={position === live}>
        Now
      </button>
      {m.pending > 0 && (
        <button type="button" className="hst-pill" onClick={onLive}>
          New run ready
        </button>
      )}
    </div>
  );
}
