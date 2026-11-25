/** The same response gives the same layout. */

import type { Hop, Leg, PathResponse } from "../api/types";
import { isGate } from "./gate";
import { stationVerdict } from "./hopStyle";
import { allLegsBlocked, legOutcome, type GateVerdict } from "./verdict";

/** Which hops the graph and the tree keep (G2). */
export type HopDetail = "devices" | "all";

/** The direction of the graph: the path goes down, or to the right. */
export type GraphDirection = "tb" | "lr";

/** Hop kinds a Devices-mode link names between its 2 kept hops. */
const LINK_KINDS: ReadonlySet<string> = new Set(["Interface", "Port", "Tunnel", "WanLink"]);
const PORT_KINDS: ReadonlySet<string> = new Set(["Interface", "Port"]);

/** One lane's walk. `keys[i]` is the identity of `hops[i]`: the uid, or
 *  `uid#n` for its n-th visit in the same lane (a hairpin). */
export interface LaneWalk {
  lane: number;
  hops: Hop[];
  keys: string[];
}

export interface GraphBox {
  key: string;
  /** The hop a click on the box selects: the hop of the box's first lane. */
  hop: Hop;
  /** The hop object of each lane that crosses the box. */
  hopByLane: Map<number, Hop>;
  /** Lanes that cross the box, ascending. */
  lanes: number[];
  /** Per lane: the position of the box in that lane's kept hops. */
  at: Map<number, number>;
  /** Lanes whose walk starts or ends on the box. */
  starts: number[];
  ends: number[];
  /** Keys of the boxes the outgoing and incoming links lead to. */
  out: string[];
  in: string[];
  /** The step along the path. */
  col: number;
  /** The track across the path, on a grid of half tracks. */
  row: number;
  /** The gate's decision (`stationVerdict`), the worst over its lanes; null
   *  for a box that decides nothing. */
  verdict: GateVerdict | null;
  /** The worst outcome of the legs that end on the box; null when none does. */
  endOutcome: GateVerdict | null;
  /** A fork whose lanes all have the same source: an equal-cost split. */
  ecmp: boolean;
}

export interface GraphLink {
  key: string;
  from: string;
  to: string;
  lanes: number[];
  /** Per lane: the interfaces between the 2 kept hops, such as `eth49 > eth1`. */
  via: Map<number, string>;
}

export interface PathGraph {
  /** Lane numbers, ascending. */
  lanes: number[];
  walks: LaneWalk[];
  /** Per lane: the indexes of the kept hops of its walk. */
  kept: Map<number, number[]>;
  /** Per lane: the box key of each kept hop. */
  boxKeys: Map<number, string[]>;
  boxes: GraphBox[];
  links: GraphLink[];
  byKey: Map<string, GraphBox>;
  cols: number;
  rows: number;
}

type PathData = Pick<PathResponse, "hops" | "legs">;

const SEVERITY: Record<GateVerdict, number> = { ok: 0, warn: 1, bad: 2 };

/** The more severe of 2 outcomes: bad, then warn, then ok. */
export function worst(a: GateVerdict | null, b: GateVerdict | null): GateVerdict | null {
  if (a === null) return b;
  if (b === null) return a;
  return SEVERITY[b] > SEVERITY[a] ? b : a;
}

/** The lanes of a response: every leg's lane and every unshared hop's lane. */
export function laneNumbers({ hops, legs }: PathData): number[] {
  const set = new Set<number>([...legs.map((l) => l.lane), ...hops.filter((h) => !h.shared).map((h) => h.lane)]);
  if (set.size === 0 && hops.length > 0) set.add(hops[0].lane);
  return [...set].sort((a, b) => a - b);
}

/** 1 walk for each lane: the shared hops in rank order, then the lane's own. */
export function laneWalks(data: PathData): LaneWalk[] {
  const byRank = (a: Hop, b: Hop) => a.rank - b.rank;
  const shared = data.hops.filter((h) => h.shared).sort(byRank);
  return laneNumbers(data).map((lane) => {
    const hops = [...shared, ...data.hops.filter((h) => !h.shared && h.lane === lane).sort(byRank)];
    const seen = new Map<string, number>();
    const keys = hops.map((h) => {
      const n = (seen.get(h.uid) ?? 0) + 1;
      seen.set(h.uid, n);
      return n === 1 ? h.uid : `${h.uid}#${n}`;
    });
    return { lane, hops, keys };
  });
}

/** The device that owns hop `i` of a walk: an interface or port right before
 *  a device belongs to that device; any other hop to the last device before it. */
function hopOwner(hops: Hop[], i: number): string | null {
  if (PORT_KINDS.has(hops[i].kind) && hops[i + 1]?.kind === "Device") return hops[i + 1].uid;
  for (let j = i; j >= 0; j--) if (hops[j].kind === "Device") return hops[j].uid;
  return null;
}

/**
 * The indexes each lane keeps. All hops: every hop. Devices: the first and
 * the last hop, the devices and the gates, and the VRF and tunnel hops that
 * only some lanes of their device take. If 2 lanes still keep the same hops,
 * also their interfaces that the other lane does not cross.
 */
export function keptByLane(walks: LaneWalk[], detail: HopDetail): Map<number, number[]> {
  if (detail === "all") return new Map(walks.map((w) => [w.lane, w.hops.map((_, i) => i)]));
  const lanesOf = new Map<string, Set<number>>();
  for (const w of walks) {
    for (const h of w.hops) {
      if (!lanesOf.has(h.uid)) lanesOf.set(h.uid, new Set());
      lanesOf.get(h.uid)!.add(w.lane);
    }
  }
  const partial = (w: LaneWalk, i: number) => {
    const owner = hopOwner(w.hops, i);
    return owner !== null && lanesOf.get(w.hops[i].uid)!.size < (lanesOf.get(owner)?.size ?? 0);
  };
  const seqs = walks.map((w) =>
    w.hops
      .map((h, i) =>
        i === 0 ||
        i === w.hops.length - 1 ||
        h.kind === "Device" ||
        isGate(h) ||
        ((h.kind === "VrfInstance" || h.kind === "Tunnel") && partial(w, i))
          ? i
          : -1,
      )
      .filter((i) => i >= 0),
  );
  const sig = (k: number) => seqs[k].map((i) => walks[k].keys[i]).join(">");
  for (let a = 0; a < walks.length; a++) {
    for (let b = a + 1; b < walks.length; b++) {
      if (sig(a) !== sig(b)) continue;
      for (const [x, y] of [
        [a, b],
        [b, a],
      ]) {
        const other = new Set(walks[y].hops.map((h) => h.uid));
        walks[x].hops.forEach((h, i) => {
          if (PORT_KINDS.has(h.kind) && !other.has(h.uid) && !seqs[x].includes(i)) seqs[x].push(i);
        });
        seqs[x].sort((p, q) => p - q);
      }
    }
  }
  return new Map(walks.map((w, k) => [w.lane, seqs[k]]));
}

/** The identity of one hop object, as the selection compares it. */
export function hopId(hop: Pick<Hop, "uid" | "lane" | "rank">): string {
  return `${hop.uid}:${hop.lane}:${hop.rank}`;
}

export function buildPathGraph(data: PathData, detail: HopDetail): PathGraph {
  const walks = laneWalks(data);
  const lanes = walks.map((w) => w.lane);
  const legByLane = new Map<number, Leg>(data.legs.map((l) => [l.lane, l]));
  const allBlocked = allLegsBlocked(data.legs);
  const kept = keptByLane(walks, detail);

  // a box is shared on a common start, else on a common end, else it is the lane's own
  const ids = new Map(walks.map((w) => [w.lane, kept.get(w.lane)!.map((i) => w.keys[i])]));
  const count = new Map<string, number>();
  const bump = (k: string) => count.set(k, (count.get(k) ?? 0) + 1);
  for (const u of ids.values()) {
    u.forEach((_, j) => {
      bump("p:" + u.slice(0, j + 1).join(">"));
      bump("s:" + u.slice(j).join(">"));
    });
  }
  const boxKeys = new Map<number, string[]>();
  for (const w of walks) {
    const u = ids.get(w.lane)!;
    boxKeys.set(
      w.lane,
      u.map((_, j) => {
        const p = "p:" + u.slice(0, j + 1).join(">");
        const s = "s:" + u.slice(j).join(">");
        return count.get(p)! > 1 ? p : count.get(s)! > 1 ? s : `l${w.lane}:${j}`;
      }),
    );
  }

  const byKey = new Map<string, GraphBox>();
  const links = new Map<string, GraphLink>();
  for (const walk of walks) {
    const idx = kept.get(walk.lane)!;
    const keys = boxKeys.get(walk.lane)!;
    const leg = legByLane.get(walk.lane);
    idx.forEach((i, j) => {
      const key = keys[j];
      const hop = walk.hops[i];
      let box = byKey.get(key);
      if (!box) {
        box = {
          key,
          hop,
          hopByLane: new Map(),
          lanes: [],
          at: new Map(),
          starts: [],
          ends: [],
          out: [],
          in: [],
          col: 0,
          row: 0,
          verdict: null,
          endOutcome: null,
          ecmp: false,
        };
        byKey.set(key, box);
      }
      box.hopByLane.set(walk.lane, hop);
      box.lanes.push(walk.lane);
      box.at.set(walk.lane, j);
      if (isGate(hop)) box.verdict = worst(box.verdict, stationVerdict(hop, leg, allBlocked));
      if (j === 0) box.starts.push(walk.lane);
      if (j === idx.length - 1) {
        box.ends.push(walk.lane);
        if (leg) box.endOutcome = worst(box.endOutcome, legOutcome(leg));
      }
      if (j === 0) return;

      const from = keys[j - 1];
      const linkKey = `${from}>${key}`;
      let link = links.get(linkKey);
      if (!link) {
        link = { key: linkKey, from, to: key, lanes: [], via: new Map() };
        links.set(linkKey, link);
        byKey.get(from)!.out.push(key);
        box.in.push(from);
      }
      link.lanes.push(walk.lane);
      const between = walk.hops
        .slice(idx[j - 1] + 1, i)
        .filter((h) => LINK_KINDS.has(h.kind))
        .map((h) => h.label);
      if (between.length) link.via.set(walk.lane, between.join(" > "));
    });
  }

  const boxes = [...byKey.values()];
  for (const box of boxes) {
    box.lanes.sort((a, b) => a - b);
    const sources = new Set(box.lanes.map((l) => legByLane.get(l)?.src_label ?? ""));
    box.ecmp = box.out.length > 1 && sources.size === 1;
  }

  // Column: the longest path from a start box. The links only go from a
  // shorter common start to a longer one, or to a lane's own box, or to a
  // shorter common end, so the graph has no cycle.
  const indeg = new Map(boxes.map((b) => [b.key, b.in.length]));
  const queue = boxes.filter((b) => b.in.length === 0);
  const order: GraphBox[] = [];
  while (queue.length) {
    const box = queue.shift()!;
    order.push(box);
    for (const to of box.out) {
      const next = byKey.get(to)!;
      next.col = Math.max(next.col, box.col + 1);
      const left = indeg.get(to)! - 1;
      indeg.set(to, left);
      if (left === 0) queue.push(next);
    }
  }

  // Row: a track goes straight on, a fork spreads its targets around it, and
  // a join sits at the mean of its sources. Inside a column the boxes are at
  // least 1 track apart, and all rows stay on a grid of half tracks.
  const laneMean = (b: GraphBox) => b.lanes.reduce((s, l) => s + l, 0) / b.lanes.length;
  const columns = new Map<number, GraphBox[]>();
  for (const box of boxes) {
    const list = columns.get(box.col) ?? [];
    list.push(box);
    columns.set(box.col, list);
  }
  const want = new Map<string, number>();
  const cols = boxes.length ? Math.max(...boxes.map((b) => b.col)) + 1 : 0;
  for (let c = 0; c < cols; c++) {
    const list = columns.get(c) ?? [];
    for (const box of list) {
      const preds = box.in.map((k) => byKey.get(k)!);
      if (preds.length === 0) want.set(box.key, 0);
      else if (preds.length === 1) {
        const kids = preds[0].out.map((k) => byKey.get(k)!).sort((a, b) => laneMean(a) - laneMean(b));
        want.set(box.key, preds[0].row + kids.indexOf(box) - (kids.length - 1) / 2);
      } else want.set(box.key, preds.reduce((s, p) => s + p.row, 0) / preds.length);
    }
    list.sort((a, b) => want.get(a.key)! - want.get(b.key)! || laneMean(a) - laneMean(b));
    list.forEach((box, i) => {
      box.row = i ? Math.max(want.get(box.key)!, list[i - 1].row + 1) : want.get(box.key)!;
    });
    const shift = list.reduce((s, b) => s + want.get(b.key)! - b.row, 0) / (list.length || 1);
    for (const box of list) box.row = Math.round((box.row + shift) * 2) / 2;
  }
  const low = boxes.length ? Math.min(...boxes.map((b) => b.row)) : 0;
  for (const box of boxes) box.row -= low;

  const rows = boxes.length ? Math.max(...boxes.map((b) => b.row)) + 1 : 0;
  return { lanes, walks, kept, boxKeys, boxes: order, links: [...links.values()], byKey, cols, rows };
}

/** For the Paths list: the first box after each fork on a lane, gates left out. */
export function pathVia(graph: PathGraph, lane: number, count = 3): string[] {
  const keys = graph.boxKeys.get(lane) ?? [];
  const out: string[] = [];
  let open = false;
  keys.forEach((key, j) => {
    if (j > 0 && graph.byKey.get(keys[j - 1])!.out.length > 1) open = true;
    const box = graph.byKey.get(key)!;
    if (open && !isGate(box.hop)) {
      out.push(box.hop.label);
      open = false;
    }
  });
  return out.slice(0, count);
}

/** The box that holds a hop object, or undefined when the hop is not kept. */
export function boxOfHop(graph: PathGraph, hop: Pick<Hop, "uid" | "lane" | "rank">): GraphBox | undefined {
  const id = hopId(hop);
  return graph.boxes.find((b) => [...b.hopByLane.values()].some((h) => hopId(h) === id));
}

/** The lanes a selection lights up: a leg's own lane, or the lanes through the
 *  box of a selected hop. Null when nothing is selected or the hop has no box. */
export function selectedLanes(
  graph: PathGraph,
  selection: { type: "hop"; data: Hop } | { type: "leg"; data: Leg } | null,
): Set<number> | null {
  if (!selection) return null;
  if (selection.type === "leg") return new Set([selection.data.lane]);
  const box = boxOfHop(graph, selection.data);
  return box ? new Set(box.lanes) : null;
}
