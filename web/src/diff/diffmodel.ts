import type { DiffCounts, Snapshot } from "../api/types";

/** `snapshots` is newest first, as GET /api/snapshots returns it. */
export function defaultPair(snapshots: Snapshot[]): { a: string; b: string } | null {
  const complete = snapshots.filter((s) => !s.degraded);
  const pool = complete.length >= 2 ? complete : snapshots;
  if (pool.length < 2) return null;
  return { a: pool[1].id, b: pool[0].id };
}

export function isEmptyDiff(counts: DiffCounts): boolean {
  return (
    counts.nodes.added === 0 &&
    counts.nodes.removed === 0 &&
    counts.nodes.changed === 0 &&
    counts.rels.added === 0 &&
    counts.rels.removed === 0 &&
    counts.rels.changed === 0
  );
}

/** One property's before/after pair, keyed for a stable render list. */
interface ChangeRow {
  key: string;
  before: unknown;
  after: unknown;
}

/** A property stored as a JSON object string (`selector_json` and similar),
 *  parsed; null for any other value. */
function jsonObject(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "string" || !value.startsWith("{")) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function changeRows(changes: Record<string, [unknown, unknown]>): ChangeRow[] {
  return Object.keys(changes)
    .sort()
    .flatMap((key) => {
      const [before, after] = changes[key];
      const a = jsonObject(before);
      const b = jsonObject(after);
      if (a && b) {
        const inner = [...new Set([...Object.keys(a), ...Object.keys(b)])]
          .sort()
          .filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]))
          .map((k) => ({ key: `${key}.${k}`, before: a[k], after: b[k] }));
        if (inner.length > 0) return inner;
      }
      return [{ key, before, after }];
    });
}

export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "not set";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(formatValue).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
