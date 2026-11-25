import type { DeltaRow, InterfaceFacts, InterfaceText, Segment, SegmentClient, Source, Tier3, Timeline } from "../data/api";
import { keyOf, type Row, type TableName } from "../render/types";
import { base, estate, tile, type Tables } from "./estate";
import { portGroups } from "../data/portGroups";

export const RUN0 = 1_800_000_000_000;
export const HOUR = 3_600_000;

/** The delta from `before` to `after` in the shape of `tiers/delta.py` `changes`. */
export function diff(name: TableName, before: Row[], after: Row[]): DeltaRow[] {
  const a = new Map(before.map((r) => [keyOf(name, r), r]));
  const b = new Map(after.map((r) => [keyOf(name, r), r]));
  const out: DeltaRow[] = [];
  for (const [k, row] of b) {
    const old = a.get(k);
    if (!old) {
      out.push({ uid: k, op: "add", before: null, after: row });
      continue;
    }
    const cols = Object.keys({ ...old, ...row }).filter((c) => old[c] !== row[c]);
    if (cols.length > 0) {
      out.push({
        uid: k,
        op: "set",
        before: Object.fromEntries(cols.map((c) => [c, old[c] ?? null])),
        after: Object.fromEntries(cols.map((c) => [c, row[c] ?? null])),
      });
    }
  }
  for (const [k, row] of a) if (!b.has(k)) out.push({ uid: k, op: "remove", before: row, after: null });
  return out;
}

function clone(t: Tables): Tables {
  return Object.fromEntries(Object.entries(t).map(([k, rows]) => [k, rows.map((r) => ({ ...r }))])) as Tables;
}

export const MOVED = "dev:s0d2";
export const GONE = "dev:s1d3";
export const REPLAN = 9;

/** `n` runs of a 2-site estate. A status flips every third run, a port flips on even runs, `GONE` is
 * removed at run 4 and back at run 7, `MOVED` moves at run 5, and run `REPLAN` re-plans the layout. */
export function history(n: number): Tables[] {
  const first = estate({ sites: 2, devices: 12, ports: 2 });
  const states: Tables[] = [];
  let layoutVersion = 1;
  let prev = first;
  for (let k = 0; k < n; k++) {
    const t = clone(prev);
    if (k % 3 === 1) {
      const row = t.render_t1.find((r) => r.uid === `dev:s0d${k % 12}`)!;
      row.status = row.status === "observed" ? "carried" : "observed";
    }
    if (k % 2 === 0 && k > 0) {
      const port = t.render_t2_ports.find((r) => r.uid === `dev:s0d${(k / 2) % 12}/port/eth0`)!;
      port.oper_status = port.oper_status === "up" ? "down" : "up";
    }
    if (k === 4) {
      t.render_t1 = t.render_t1.filter((r) => r.uid !== GONE);
      t.render_t1_edges = t.render_t1_edges.filter((r) => r.a_uid !== GONE && r.b_uid !== GONE);
    }
    if (k === 7) {
      t.render_t1 = [...t.render_t1, first.render_t1.find((r) => r.uid === GONE)!];
      t.render_t1_edges = first.render_t1_edges.map((r) => ({ ...r }));
    }
    if (k === 5) t.layout.find((r) => r.uid === MOVED)!.u = Number(t.layout.find((r) => r.uid === MOVED)!.u) + 100;
    if (k === REPLAN) {
      layoutVersion = 2;
      for (const r of t.layout) r.v = Number(r.v) + 1;
    }
    for (const r of t.layout) r.layout_version = layoutVersion;
    states.push(t);
    prev = t;
  }
  return states;
}

/** A `Source` over `history` runs that counts its calls. */
export class FakeSource implements Source {
  readonly calls: string[] = [];
  readonly keys: number[];

  constructor(readonly states: Tables[]) {
    this.keys = states.map((_, i) => RUN0 + i * HOUR);
  }

  private at(run: number): number {
    const i = this.keys.indexOf(run);
    if (i < 0) throw new Error(`unknown run ${run}`);
    return i;
  }

  rows(name: TableName, i: number, block?: string): Row[] {
    const t = this.states[i];
    if (name === "layout") return block ? tile(t, "layout", block) : base(t);
    if (name === "render_t2_port_groups") return portGroups(tile(t, "render_t2_ports", block ?? ""), tile(t, "render_t2_cables", block ?? ""));
    return block ? tile(t, name, block) : t[name];
  }

  async timeline(): Promise<Timeline> {
    this.calls.push("timeline");
    return {
      current: this.keys[this.keys.length - 1],
      runs: this.keys.map((key, i) => ({
        key,
        kind: "full",
        parent: i > 0 ? this.keys[i - 1] : null,
        published_ts: key,
        state: "warm",
        tiers_ready: true,
        counts: { added: 0, removed: 0, changed: i },
        replan_recommended: false,
      })),
    };
  }

  async tier(name: TableName, run: number, block?: string): Promise<Row[]> {
    this.calls.push(`tier ${name} ${this.at(run)}${block ? ` ${block}` : ""}`);
    return this.rows(name, this.at(run), block);
  }

  async delta(name: TableName, run: number, block?: string): Promise<DeltaRow[]> {
    const i = this.at(run);
    this.calls.push(`delta ${name} ${i}${block ? ` ${block}` : ""}`);
    return i === 0 ? diff(name, [], this.rows(name, 0, block)) : diff(name, this.rows(name, i - 1, block), this.rows(name, i, block));
  }

  async layout(run: number, block?: string): Promise<Row[]> {
    this.calls.push(`layout ${this.at(run)}${block ? ` ${block}` : ""}`);
    return this.rows("layout", this.at(run), block);
  }

  async layoutDelta(run: number, block?: string): Promise<Row[]> {
    const i = this.at(run);
    this.calls.push(`layout-delta ${i}${block ? ` ${block}` : ""}`);
    if (i === 0) return this.rows("layout", 0, block);
    const before = new Map(this.rows("layout", i - 1, block).map((r) => [String(r.uid), r]));
    return this.rows("layout", i, block).filter((r) => {
      const old = before.get(String(r.uid));
      return !old || old.u !== r.u || old.v !== r.v || old.layout_version !== r.layout_version;
    });
  }

  async device(uid: string, run: number): Promise<Tier3> {
    this.calls.push(`device ${uid} ${this.at(run)}`);
    return { uid, snapshot: run, state: "warm", categories: {}, contexts: [] };
  }

  /** The segment's row from the tables and the clients `this.clients` holds for it. */
  clients = new Map<string, SegmentClient[]>();

  async segment(uid: string, run: number): Promise<Segment> {
    this.calls.push(`segment ${uid} ${this.at(run)}`);
    const row = this.states[this.at(run)].render_t2_segments.find((r) => r.uid === uid);
    if (!row) throw new Error(`unknown segment ${uid}`);
    return {
      uid,
      device_uid: String(row.device_uid),
      snapshot: run,
      state: "warm",
      prefix: (row.prefix as string | null) ?? null,
      vid: (row.vid as number | null) ?? null,
      name: (row.name as string | null) ?? null,
      clients: this.clients.get(uid) ?? [],
    };
  }

  private portAt(uid: string, run: number): Row {
    const port = this.states[this.at(run)].render_t2_ports.find((r) => r.uid === uid);
    if (!port) throw new Error(`unknown interface ${uid}`);
    return port;
  }

  async interface(uid: string, run: number): Promise<InterfaceFacts> {
    this.calls.push(`interface ${uid} ${this.at(run)}`);
    const port = this.portAt(uid, run);
    return {
      uid,
      snapshot: run,
      label: "Port",
      device_uid: String(port.device_uid),
      name: String(port.name),
      interface: { name: port.name, oper_status: port.oper_status },
      port: { name: port.name, admin_status: port.admin_status },
      contexts: [String(port.context_uid)],
      addresses: [],
      lags: [],
    };
  }

  async interfaceText(uid: string, run: number): Promise<InterfaceText> {
    this.calls.push(`interface-text ${uid} ${this.at(run)}`);
    const port = this.portAt(uid, run);
    const lines = [`interface ${port.name}`, " description uplink", port.oper_status === "up" ? " no shutdown" : " shutdown"];
    return { uid, command: "show running-config interface", fetched_ts: run, text: lines.join("\n") };
  }
}
