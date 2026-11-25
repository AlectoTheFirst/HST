/** The items are the boxes of the Devices-mode path graph. */

import type { Hop, Leg, PathResponse } from "../api/types";
import { isGate } from "./gate";
import { stationVerdict } from "./hopStyle";
import { buildPathGraph, worst, type GraphBox, type LaneWalk } from "./pathGraph";
import { VERDICT_WORD, allLegsBlocked, legOutcome, legWord, type GateVerdict } from "./verdict";

export interface TreeNode {
  /** The box key (uid, or uid#n for a second visit in 1 lane). */
  key: string;
  box: GraphBox;
  /** The lanes of this branch that cross the item, ascending. */
  lanes: number[];
  hopByLane: Map<number, Hop>;
  /** Per lane: the hops of that lane on the item that the Devices filter left
   *  out (interfaces, VRFs, routes), in walk order. */
  owned: Map<number, Hop[]>;
  /** Lanes of this branch whose walk ends on the item. */
  ends: number[];
  kids: TreeNode[];
  /** The gate's decision over this branch's lanes; null when it decides nothing. */
  verdict: GateVerdict | null;
  /** A fork whose lanes all have the same source: an equal-cost split. */
  ecmp: boolean;
}

export type TreeRow =
  | { type: "item"; id: string; prefix: string; level: number; node: TreeNode; hasDetail: boolean }
  | { type: "hop"; id: string; parent: string; prefix: string; level: number; lane: number; hop: Hop; multi: boolean }
  | { type: "leg"; id: string; parent: string; prefix: string; level: number; lane: number; multi: boolean };

const ENTRY_KINDS: ReadonlySet<string> = new Set(["Interface", "Port"]);

/**
 * Which kept hop each left-out hop of a walk belongs to. A hop belongs to the
 * last kept hop before it that is not a gate (a gate is an item of its own),
 * except the interface right before a device, which is that device's way in.
 */
export function ownedHops(walk: LaneWalk, kept: number[]): Map<number, Hop[]> {
  const owned = new Map<number, Hop[]>(kept.map((i) => [i, []]));
  let owner = kept[0];
  for (let j = 0; j < kept.length - 1; j++) {
    const at = kept[j];
    if (!isGate(walk.hops[at])) owner = at;
    const next = kept[j + 1];
    for (let i = at + 1; i < next; i++) {
      const hop = walk.hops[i];
      const entry = i === next - 1 && walk.hops[next].kind === "Device" && ENTRY_KINDS.has(hop.kind);
      owned.get(entry ? next : owner)!.push(hop);
    }
  }
  return owned;
}

export interface PathTree {
  roots: TreeNode[];
  legByLane: Map<number, Leg>;
}

export function buildPathTree(data: Pick<PathResponse, "hops" | "legs">): PathTree {
  const graph = buildPathGraph(data, "devices");
  const legByLane = new Map(data.legs.map((l) => [l.lane, l]));
  const allBlocked = allLegsBlocked(data.legs);
  const root: TreeNode[] = [];

  for (const walk of graph.walks) {
    const kept = graph.kept.get(walk.lane)!;
    const boxKeys = graph.boxKeys.get(walk.lane)!;
    const owned = ownedHops(walk, kept);
    let level = root;
    kept.forEach((idx, j) => {
      const key = walk.keys[idx];
      let node = level.find((n) => n.key === key);
      if (!node) {
        node = {
          key,
          box: graph.byKey.get(boxKeys[j])!,
          lanes: [],
          hopByLane: new Map(),
          owned: new Map(),
          ends: [],
          kids: [],
          verdict: null,
          ecmp: false,
        };
        level.push(node);
      }
      const hop = walk.hops[idx];
      node.lanes.push(walk.lane);
      node.hopByLane.set(walk.lane, hop);
      node.owned.set(walk.lane, owned.get(idx) ?? []);
      if (isGate(hop)) node.verdict = worst(node.verdict, stationVerdict(hop, legByLane.get(walk.lane), allBlocked));
      if (j === kept.length - 1) node.ends.push(walk.lane);
      level = node.kids;
    });
  }
  const mark = (nodes: TreeNode[]) => {
    for (const node of nodes) {
      node.ecmp = node.kids.length > 1 && new Set(node.lanes.map((l) => legByLane.get(l)?.src_label ?? "")).size === 1;
      mark(node.kids);
    }
  };
  mark(root);
  return { roots: root, legByLane };
}

/** The hop a click on an item selects: the hop of its first lane. */
export function itemHop(node: TreeNode): Hop {
  return node.hopByLane.get(node.lanes[0])!;
}

/**
 * The rows of the tree. `open` holds the ids of the items whose hops show;
 * `legLine` says which lanes get a leg line at their last item (the MTU leg
 * summary).
 */
export function treeRows(tree: PathTree, open: ReadonlySet<string>, legLine?: (lane: number) => boolean): TreeRow[] {
  const out: TreeRow[] = [];

  function emit(node: TreeNode, prefix: string, cont: string, id: string, level: number) {
    const legLanes = legLine ? node.ends.filter(legLine) : [];
    const hasDetail = node.lanes.some((l) => (node.owned.get(l)?.length ?? 0) > 0) || legLanes.length > 0;
    out.push({ type: "item", id, prefix, level, node, hasDetail });
    if (hasDetail && open.has(id)) {
      const inner = cont + (node.kids.length ? "|   " : "    ");
      const multi = node.lanes.length > 1;
      for (const lane of node.lanes) {
        for (const [i, hop] of (node.owned.get(lane) ?? []).entries()) {
          out.push({ type: "hop", id: `${id}@${lane}.${i}`, parent: id, prefix: inner, level: level + 1, lane, hop, multi });
        }
        if (legLanes.includes(lane)) {
          out.push({ type: "leg", id: `${id}@${lane}.leg`, parent: id, prefix: inner, level: level + 1, lane, multi });
        }
      }
    }
    if (node.kids.length === 1) {
      emit(node.kids[0], cont, cont, `${id}/${node.kids[0].key}`, level);
      return;
    }
    node.kids.forEach((kid, i) => {
      const last = i === node.kids.length - 1;
      emit(kid, cont + (last ? "`-- " : "|-- "), cont + (last ? "    " : "|   "), `${id}/${kid.key}`, level + 1);
    });
  }

  for (const node of tree.roots) emit(node, "", "", node.key, 1);
  return out;
}

/** A row as plain text, without its guides. */
export function rowText(row: TreeRow, tree: PathTree): string {
  const pathName = (lane: number) => `Path ${lane + 1}`;
  if (row.type === "hop") {
    const h = row.hop;
    return [row.multi ? pathName(row.lane) : "", h.label, h.kind, h.note].filter(Boolean).join("  ");
  }
  if (row.type === "leg") {
    const leg = tree.legByLane.get(row.lane);
    return [row.multi ? pathName(row.lane) : "", leg ? legWord(leg) : ""].filter(Boolean).join("  ");
  }
  const { node } = row;
  const hop = itemHop(node);
  const parts = [hop.label];
  if (!isGate(hop)) parts.push(hop.kind);
  if (node.verdict) parts.push(VERDICT_WORD[node.verdict]);
  if (hop.note) parts.push(hop.note);
  if (node.ecmp) parts.push(`ECMP ${node.kids.length}`);
  for (const lane of node.ends) {
    const leg = tree.legByLane.get(lane);
    parts.push(leg ? `${pathName(lane)} ${legWord(leg)}` : pathName(lane));
  }
  return parts.join("  ");
}

/** The tree as plain text with the same guides, for "Copy as text". */
export function treeText(tree: PathTree, rows: TreeRow[]): string {
  return rows.map((r) => r.prefix + rowText(r, tree)).join("\n");
}

/** The outcome of a lane's leg, for its pill; ok when the response has no leg. */
export function laneOutcome(tree: PathTree, lane: number): GateVerdict {
  const leg = tree.legByLane.get(lane);
  return leg ? legOutcome(leg) : "ok";
}
