import { keyOf, type ElementChange, type Row, type TableName } from "../render/types";
import type { DeltaRow } from "./api";

/** One tier table at a run, moved between runs by its deltas. A removed row stays, marked absent. */
export class TierTable {
  readonly rows = new Map<string, Row>();
  readonly absent = new Set<string>();

  constructor(
    readonly name: TableName,
    rows: Row[],
  ) {
    for (const row of rows) this.rows.set(keyOf(name, row), row);
  }

  present(): Row[] {
    return [...this.rows].filter(([k]) => !this.absent.has(k)).map(([, r]) => r);
  }

  private put(key: string, row: Row): ElementChange {
    this.rows.set(key, row);
    this.absent.delete(key);
    return { key, row };
  }

  private drop(key: string, fallback: Row | null): ElementChange {
    if (!this.rows.has(key) && fallback) this.rows.set(key, fallback);
    this.absent.add(key);
    return { key, row: null };
  }

  /** From the parent run to the run of `delta`. */
  apply(delta: DeltaRow[]): ElementChange[] {
    return delta.map((d) => {
      if (d.op === "add") return this.put(d.uid, { ...(d.after ?? {}) });
      if (d.op === "remove") return this.drop(d.uid, d.before);
      return this.put(d.uid, { ...(this.rows.get(d.uid) ?? {}), ...(d.after ?? {}) });
    });
  }

  /** From the run of `delta` back to its parent. */
  unapply(delta: DeltaRow[]): ElementChange[] {
    return [...delta].reverse().map((d) => {
      if (d.op === "add") return this.drop(d.uid, d.after);
      if (d.op === "remove") return this.put(d.uid, { ...(this.rows.get(d.uid) ?? {}), ...(d.before ?? {}) });
      return this.put(d.uid, { ...(this.rows.get(d.uid) ?? {}), ...(d.before ?? {}) });
    });
  }
}
