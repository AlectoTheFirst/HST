import { formatSnapshotDate } from "../../flowdesk/SnapshotPicker";
import type { TimelineRun } from "../data/api";

export type Mode = "now" | "history" | "cold";

export interface Tick {
  key: number;
  /** The position on the scrubber, 0 to 1. */
  x: number;
  /** The tick height from the change count, 0 to 1. */
  height: number;
  cold: boolean;
  label: string;
}

export interface DayTick {
  x: number;
  label: string;
}

export interface TimelineModel {
  ticks: Tick[];
  /** Ranges of the scrubber, 0 to 1, that hold cold runs. */
  coldBands: [number, number][];
  /** A tick per day in compacted history. */
  dayTicks: DayTick[];
  mode: Mode;
  status: string;
  /** Runs newer than the live edge the user last saw. */
  pending: number;
}

const MIN_HEIGHT = 0.12;

function changes(run: TimelineRun): number {
  return run.counts.added + run.counts.removed + run.counts.changed;
}

export function runLabel(run: TimelineRun): string {
  const when = run.published_ts != null ? formatSnapshotDate(run.published_ts) : String(run.key);
  return `${when}, ${run.kind ?? "run"}, ${changes(run)} changes`;
}

/** The scrubber for `runs` (oldest first) at index `position`, with `live` the newest index shown as Now. */
export function timelineModel(runs: TimelineRun[], position: number, live: number): TimelineModel {
  const n = runs.length;
  const x = (i: number) => (n <= 1 ? 1 : i / (n - 1));
  const most = Math.max(1, ...runs.map(changes));
  const ticks = runs.map((run, i) => ({
    key: run.key,
    x: x(i),
    height: Math.max(MIN_HEIGHT, Math.log1p(changes(run)) / Math.log1p(most)),
    cold: run.state === "cold",
    label: runLabel(run),
  }));
  const coldBands: [number, number][] = [];
  ticks.forEach((t, i) => {
    if (!t.cold) return;
    const last = coldBands[coldBands.length - 1];
    if (last && i > 0 && ticks[i - 1].cold) last[1] = t.x;
    else coldBands.push([t.x, t.x]);
  });
  const dayTicks: DayTick[] = [];
  let day = "";
  runs.forEach((run, i) => {
    if (run.state !== "compacted" || run.published_ts == null) return;
    const d = new Date(run.published_ts).toDateString();
    if (d !== day) dayTicks.push({ x: x(i), label: d });
    day = d;
  });
  const run = runs[position];
  let mode: Mode = "history";
  if (run?.state === "cold") mode = "cold";
  else if (position === live) mode = "now";
  const status =
    mode === "now"
      ? "Now"
      : mode === "cold"
        ? "Cold"
        : `History: ${run?.published_ts != null ? formatSnapshotDate(run.published_ts) : "not known"}`;
  return { ticks, coldBands, dayTicks, mode, status, pending: Math.max(0, n - 1 - live) };
}
