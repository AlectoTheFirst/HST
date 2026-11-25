import type { ElementChange, Row, TableName } from "../render/types";
import type { DeltaRow } from "./api";
import { TierTable } from "./table";

/** Runs of deltas kept loaded on each side of the position. */
export const RADIUS = 5;
/** The farthest a seek may leave the loaded deltas and still slide; beyond it the tier is fetched again. */
export const SLIDE = 10;
/** Deltas fetched ahead after `STREAK` single steps in one direction. */
export const PREFETCH = 5;
export const STREAK = 3;

/** The result of a seek: the whole table at the run, or the elements that changed. */
export type Step = { reset: Row[] } | { changes: ElementChange[] };

export interface TierSource {
  tier(run: number): Promise<Row[]>;
  delta(run: number): Promise<DeltaRow[]>;
}

/**
 * Whether the delta of index i is relative to index i - 1. It is not when the run's parent is a run the
 * chain left out.
 */
export type Contiguous = (index: number) => boolean;

const ALWAYS: Contiguous = () => true;

function crosses(contiguous: Contiguous, from: number, to: number): boolean {
  for (let i = Math.max(1, from); i <= to; i++) if (!contiguous(i)) return true;
  return false;
}

function dedupe(changes: ElementChange[]): ElementChange[] {
  const last = new Map<string, ElementChange>();
  for (const c of changes) {
    last.delete(c.key);
    last.set(c.key, c);
  }
  return [...last.values()];
}

/**
 * One tier table (and tile) on the scrub window. `chain` holds the run keys oldest first; the delta of
 * index i turns the table at i - 1 into the table at i.
 */
export class ScrubWindow {
  table: TierTable | null = null;
  position = -1;
  readonly deltas = new Map<number, DeltaRow[]>();
  private readonly inflight = new Map<number, Promise<DeltaRow[]>>();
  private streak = 0;
  private direction = 0;

  constructor(
    readonly name: TableName,
    readonly chain: readonly number[],
    private readonly source: TierSource,
    private readonly contiguous: Contiguous = ALWAYS,
  ) {}

  async anchor(index: number): Promise<Row[]> {
    const rows = await this.source.tier(this.chain[index]);
    this.table = new TierTable(this.name, rows);
    this.position = index;
    this.deltas.clear();
    this.streak = 0;
    this.direction = 0;
    this.fill(index - RADIUS + 1, index + RADIUS);
    return rows;
  }

  private load(i: number): Promise<DeltaRow[]> {
    const have = this.deltas.get(i);
    if (have) return Promise.resolve(have);
    let p = this.inflight.get(i);
    if (!p) {
      p = this.source.delta(this.chain[i]).then((rows) => {
        this.deltas.set(i, rows);
        return rows;
      });
      p.finally(() => this.inflight.delete(i)).catch(() => undefined);
      this.inflight.set(i, p);
    }
    return p;
  }

  private fill(from: number, to: number): void {
    for (let i = Math.max(1, from); i <= Math.min(this.chain.length - 1, to); i++) {
      if (!this.contiguous(i)) continue;
      if (!this.deltas.has(i)) this.load(i).catch(() => undefined);
    }
  }

  /** The indices reachable from the position with the deltas loaded now. */
  bounds(): [number, number] {
    let lo = this.position;
    while (lo > 0 && this.deltas.has(lo)) lo--;
    let hi = this.position;
    while (this.deltas.has(hi + 1)) hi++;
    return [lo, hi];
  }

  /** Resolves when no delta fetch is in flight. */
  async idle(): Promise<void> {
    while (this.inflight.size > 0) await Promise.allSettled([...this.inflight.values()]);
  }

  async seek(index: number): Promise<Step> {
    if (!this.table) return { reset: await this.anchor(index) };
    if (index === this.position) return { changes: [] };
    const [lo, hi] = this.bounds();
    const gap = index > hi ? index - hi : index < lo ? lo - index : 0;
    if (gap > SLIDE) return { reset: await this.anchor(index) };
    const from = Math.min(this.position, index) + 1;
    const to = Math.max(this.position, index);
    if (crosses(this.contiguous, from, to)) return { reset: await this.anchor(index) };
    const loads: Promise<DeltaRow[]>[] = [];
    for (let i = from; i <= to; i++) loads.push(this.load(i));
    await Promise.all(loads);
    const changes: ElementChange[] = [];
    if (index > this.position) {
      for (let i = this.position + 1; i <= index; i++) changes.push(...this.table.apply(this.deltas.get(i)!));
    } else {
      for (let i = this.position; i > index; i--) changes.push(...this.table.unapply(this.deltas.get(i)!));
    }
    const moved = index - this.position;
    const sign = Math.sign(moved);
    this.streak = Math.abs(moved) === 1 && sign === this.direction ? this.streak + 1 : Math.abs(moved) === 1 ? 1 : 0;
    this.direction = sign;
    this.position = index;
    this.evict();
    this.fill(index - RADIUS + 1, index + RADIUS);
    if (this.streak >= STREAK) {
      if (sign > 0) this.fill(index + RADIUS + 1, index + RADIUS + PREFETCH);
      else this.fill(index - RADIUS - PREFETCH + 1, index - RADIUS);
    }
    return { changes: dedupe(changes) };
  }

  private evict(): void {
    const keep = RADIUS + PREFETCH;
    for (const i of [...this.deltas.keys()]) {
      if (i <= this.position - keep || i > this.position + keep) this.deltas.delete(i);
    }
  }
}

export interface LayoutSource {
  layout(run: number): Promise<Row[]>;
  layoutDelta(run: number): Promise<Row[]>;
}

interface Entry {
  index: number;
  row: Row;
}

/** A table derived on read, with no deltas: every step reads it again at the target run. */
export class SnapshotWindow {
  constructor(
    readonly chain: readonly number[],
    private readonly read: (run: number) => Promise<Row[]>,
  ) {}

  anchor(index: number): Promise<Row[]> {
    return this.read(this.chain[index]);
  }

  async seek(index: number): Promise<Step> {
    return { reset: await this.anchor(index) };
  }

  async idle(): Promise<void> {}
}

/** The `reason` of the layout row of an element that leaves the layout at that run. */
export const REMOVED = "removed";

/**
 * The layout on the scrub window. The placement of a uid at index i is its newest row at or below i,
 * from the layout at the base index and the layout deltas after it. A delta with a greater
 * `layout_version` voids the rows before it. A newest row with `reason = removed`
 * means the element has no placement at i.
 */
export class LayoutWindow {
  position = -1;
  base = -1;
  private baseVersion = 0;
  private readonly entries = new Map<string, Entry[]>();
  private readonly versions = new Map<number, number>();
  private readonly loaded = new Set<number>();
  private readonly inflight = new Map<number, Promise<void>>();

  constructor(
    readonly chain: readonly number[],
    private readonly source: LayoutSource,
    private readonly contiguous: Contiguous = ALWAYS,
  ) {}

  async anchor(index: number): Promise<Row[]> {
    let base = Math.max(0, index - RADIUS);
    for (let i = base + 1; i <= index; i++) if (!this.contiguous(i)) base = i;
    const rows = await this.source.layout(this.chain[base]);
    this.entries.clear();
    this.versions.clear();
    this.loaded.clear();
    this.base = base;
    this.baseVersion = 0;
    for (const row of rows) {
      this.entries.set(String(row.uid), [{ index: base, row }]);
      this.baseVersion = Math.max(this.baseVersion, Number(row.layout_version ?? 0));
    }
    await Promise.all(this.range(base + 1, index).map((i) => this.load(i)));
    this.position = index;
    this.fill(index + 1, index + RADIUS);
    return this.placements(index);
  }

  private range(from: number, to: number): number[] {
    const out: number[] = [];
    for (let i = Math.max(1, from); i <= Math.min(this.chain.length - 1, to); i++) {
      if (this.contiguous(i)) out.push(i);
    }
    return out;
  }

  private load(i: number): Promise<void> {
    if (this.loaded.has(i)) return Promise.resolve();
    let p = this.inflight.get(i);
    if (!p) {
      const base = this.base;
      p = this.source.layoutDelta(this.chain[i]).then((rows) => {
        if (base !== this.base || this.loaded.has(i)) return;
        let version = 0;
        for (const row of rows) {
          const uid = String(row.uid);
          const list = this.entries.get(uid) ?? [];
          list.push({ index: i, row });
          list.sort((a, b) => a.index - b.index);
          this.entries.set(uid, list);
          version = Math.max(version, Number(row.layout_version ?? 0));
        }
        this.versions.set(i, version);
        this.loaded.add(i);
      });
      p.finally(() => this.inflight.delete(i)).catch(() => undefined);
      this.inflight.set(i, p);
    }
    return p;
  }

  private fill(from: number, to: number): void {
    for (const i of this.range(from, to)) this.load(i).catch(() => undefined);
  }

  async idle(): Promise<void> {
    while (this.inflight.size > 0) await Promise.allSettled([...this.inflight.values()]);
  }

  /** The index of the newest re-plan at or below `index`, or the base. */
  private barrier(index: number): number {
    let version = this.baseVersion;
    let barrier = this.base;
    for (let j = this.base + 1; j <= index; j++) {
      const v = this.versions.get(j) ?? 0;
      if (v > version) {
        version = v;
        barrier = j;
      }
    }
    return barrier;
  }

  at(uid: string, index: number): Row | null {
    const list = this.entries.get(uid);
    if (!list) return null;
    const floor = this.barrier(index);
    for (let k = list.length - 1; k >= 0; k--) {
      const e = list[k];
      if (e.index <= index) return e.index >= floor && e.row.reason !== REMOVED ? e.row : null;
    }
    return null;
  }

  private placements(index: number): Row[] {
    const out: Row[] = [];
    for (const uid of this.entries.keys()) {
      const row = this.at(uid, index);
      if (row) out.push(row);
    }
    return out;
  }

  async seek(index: number): Promise<Step> {
    if (this.position < 0 || index < this.base) return { reset: await this.anchor(index) };
    if (index === this.position) return { changes: [] };
    let hi = this.position;
    while (this.loaded.has(hi + 1)) hi++;
    if (index - hi > SLIDE || crosses(this.contiguous, this.position + 1, index)) {
      return { reset: await this.anchor(index) };
    }
    await Promise.all(this.range(this.position + 1, index).map((i) => this.load(i)));
    const from = Math.min(this.position, index);
    const to = Math.max(this.position, index);
    const crossed = this.barrier(from) !== this.barrier(to);
    this.position = index;
    this.fill(index + 1, index + RADIUS);
    if (crossed) return { reset: this.placements(index) };
    const touched = new Set<string>();
    for (const [uid, list] of this.entries) {
      if (list.some((e) => e.index > from && e.index <= to)) touched.add(uid);
    }
    return { changes: [...touched].map((uid) => ({ key: uid, row: this.at(uid, index) })) };
  }
}
