import type { ElementChange, Row, TableName } from "../render/types";
import type { Source, Tier3, Timeline, TimelineRun } from "./api";
import { Lru } from "./lru";
import { LayoutWindow, ScrubWindow, SnapshotWindow, type Step } from "./window";

export const BASE_TABLES: readonly TableName[] = [
  "render_t0",
  "render_t1",
  "render_t1_edges",
  "render_t1_circuits",
  "render_t1_fabric_ports",
  "render_t1_contexts",
  "context_identity",
];
export const TILE_TABLES: readonly TableName[] = [
  "render_t2_ports",
  "render_t2_cables",
  "render_t2_contexts",
  "render_t2_segments",
  "render_t2_port_groups",
];
/** The tile tables the server derives on read; they have no deltas. */
export const DERIVED_TABLES: ReadonlySet<TableName> = new Set(["render_t2_port_groups"]);
export const TIER3_ENTRIES = 200;

/** Where the map data goes: the renderer, in the page. */
export interface Sink {
  setTier(name: TableName, rows: Row[], tile?: string): void;
  applyDelta(name: TableName, changes: ElementChange[], tile?: string): void;
  dropTile(tile: string): void;
}

interface Track {
  name: TableName;
  tile?: string;
  window: ScrubWindow | LayoutWindow | SnapshotWindow;
}

/**
 * The map state in the browser: Tier 0 and 1 and the layout at the position, the deltas of the scrub
 * window, the Tier 2 tiles in view, and the Tier 3 entries most recently read.
 */
export class MapData {
  runs: TimelineRun[] = [];
  readonly chain: number[] = [];
  /** The parent run of each run in the chain, from the timeline. */
  readonly parents: (number | null)[] = [];
  position = -1;
  readonly tier3 = new Lru<string, Tier3>(TIER3_ENTRIES);
  private readonly tracks = new Map<string, Track>();
  private target = -1;
  private running: Promise<void> | null = null;
  /** the tile loads in flight */
  private loads = new Set<Promise<void>>();

  constructor(
    private readonly source: Source,
    private readonly sink: Sink,
  ) {}

  /** Takes the runs whose tiers are ready, oldest first. The chain only grows. */
  setTimeline(timeline: Timeline): void {
    this.runs = timeline.runs.filter((r) => r.tiers_ready);
    for (const run of this.runs.slice(this.chain.length)) {
      this.chain.push(run.key);
      this.parents.push(run.parent);
    }
  }

  /**
   * True when the delta of the run at `index` turns the run before it in the chain into this one. A run
   * whose parent is a run left out of the chain (its projection failed) has a delta against another base.
   */
  contiguous(index: number): boolean {
    return index <= 0 || this.parents[index] === this.chain[index - 1];
  }

  indexOf(run: number): number {
    return this.chain.indexOf(run);
  }

  get run(): number | undefined {
    return this.chain[this.position];
  }

  tiles(): string[] {
    return [...new Set([...this.tracks.values()].map((t) => t.tile).filter((t): t is string => Boolean(t)))];
  }

  private track(name: TableName, tile?: string): Track {
    const key = `${name}|${tile ?? ""}`;
    let t = this.tracks.get(key);
    if (!t) {
      const window =
        name === "layout"
          ? new LayoutWindow(
              this.chain,
              {
                layout: (run) => this.source.layout(run, tile),
                layoutDelta: (run) => this.source.layoutDelta(run, tile),
              },
              (i) => this.contiguous(i),
            )
          : DERIVED_TABLES.has(name)
            ? new SnapshotWindow(this.chain, (run) => this.source.tier(name, run, tile))
            : new ScrubWindow(
                name,
                this.chain,
                {
                  tier: (run) => this.source.tier(name, run, tile),
                  delta: (run) => this.source.delta(name, run, tile),
                },
                (i) => this.contiguous(i),
              );
      t = { name, tile, window };
      this.tracks.set(key, t);
    }
    return t;
  }

  private emit(t: Track, step: Step): void {
    if ("reset" in step) this.sink.setTier(t.name, step.reset, t.tile);
    else if (step.changes.length > 0) this.sink.applyDelta(t.name, step.changes, t.tile);
  }

  /** Loads the run at `index` as the new anchor of every loaded table. */
  async open(index: number): Promise<void> {
    this.target = index;
    const tracks = [this.track("layout"), ...BASE_TABLES.map((n) => this.track(n))];
    for (const tile of this.tiles()) tracks.push(this.track("layout", tile), ...TILE_TABLES.map((n) => this.track(n, tile)));
    const results = await Promise.all(tracks.map((t) => t.window.anchor(index)));
    tracks.forEach((t, i) => this.sink.setTier(t.name, results[i], t.tile));
    this.position = index;
  }

  /** Moves every loaded table to `index`. Seeks that arrive while one runs fold into the newest. */
  seek(index: number): Promise<void> {
    this.target = index;
    if (!this.running) {
      this.running = this.drain().finally(() => {
        this.running = null;
      });
    }
    return this.running;
  }

  private async drain(): Promise<void> {
    while (this.target !== this.position) {
      // A tile load in flight anchors at `position`. It ends before the tracks are read.
      await Promise.allSettled([...this.loads]);
      const index = this.target;
      const tracks = [...this.tracks.values()];
      const steps = await Promise.all(tracks.map((t) => t.window.seek(index)));
      tracks.forEach((t, i) => this.emit(t, steps[i]));
      this.position = index;
    }
  }

  async loadTile(tile: string): Promise<void> {
    // A seek in flight read the tracks before this tile had any.
    while (this.running) await this.running.catch(() => undefined);
    if (this.tiles().includes(tile) || this.position < 0) return;
    const tracks = [this.track("layout", tile), ...TILE_TABLES.map((n) => this.track(n, tile))];
    const index = this.position;
    const load = Promise.all(tracks.map((t) => t.window.anchor(index))).then((results) => {
      tracks.forEach((t, i) => this.sink.setTier(t.name, results[i], t.tile));
    });
    this.loads.add(load);
    try {
      await load;
    } finally {
      this.loads.delete(load);
    }
  }

  dropTile(tile: string): void {
    for (const [key, t] of this.tracks) if (t.tile === tile) this.tracks.delete(key);
    this.sink.dropTile(tile);
  }

  /** Tier 3 of `uid` at the position, from the cache when it holds it. */
  async device(uid: string): Promise<Tier3> {
    const run = this.chain[this.position];
    const key = `${uid}@${run}`;
    const hit = this.tier3.get(key);
    if (hit) return hit;
    const found = await this.source.device(uid, run);
    this.tier3.set(key, found);
    return found;
  }

  /** Resolves when no delta fetch of any table is in flight. */
  async idle(): Promise<void> {
    await Promise.all([...this.tracks.values()].map((t) => t.window.idle()));
  }
}
