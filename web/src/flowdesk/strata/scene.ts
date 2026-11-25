/**
 * {hops, legs} (the /api/path response) to a scene description for Strata's
 * four-layer view.
 */

import type { Hop, Leg } from "../../api/types";
import { isGate } from "../gate";
import { allLegsBlocked, legOutcome, legWord, type GateVerdict } from "../verdict";
import { layerOf, STRATA_LAYERS } from "./layers";

export interface SceneCell {
  q: number;
  r: number;
}

export interface SceneNode {
  uid: string;
  kind: string;
  label: string;
  note: string;
  rank: number;
  lane: number;
  shared: boolean;
  /** Index into STRATA_LAYERS. */
  layer: number;
  /** q = hop.rank, r = hop.lane. */
  cell: SceneCell;
  /** true for every non-shared node in a blocked lane. */
  dimmed: boolean;
  verdict: "ok" | "bad" | "warn" | null;
}

/** `from`/`to` are station keys (`uid:lane:rank`). */
interface SceneEdge {
  from: string;
  to: string;
  /** true when this segment lies at or past the gate in a blocked lane. */
  dead: boolean;
}

/** A connector between two stations on different layers. */
interface SceneDrop {
  from: string;
  to: string;
  dead: boolean;
}

/** A lane that is not forwarded or not decided. */
export interface SceneLane {
  lane: number;
  src_label: string;
  outcome: GateVerdict;
  word: string;
  detail: string;
}

export interface SceneDescription {
  nodes: SceneNode[];
  edges: SceneEdge[];
  drops: SceneDrop[];
  layerCount: number;
}

// A hairpin path visits the same uid twice in one lane, so the key includes rank.
function stationKey(h: { uid: string; lane: number; rank: number }): string {
  return `${h.uid}:${h.lane}:${h.rank}`;
}

/** The lanes of a trace that are not forwarded or not decided, in lane order. */
export function sceneLanes(legs: readonly Leg[]): SceneLane[] {
  return [...legs]
    .sort((a, b) => a.lane - b.lane)
    .filter((leg) => legOutcome(leg) !== "ok")
    .map((leg) => ({
      lane: leg.lane,
      src_label: leg.src_label,
      outcome: legOutcome(leg),
      word: legWord(leg),
      detail: leg.detail,
    }));
}

export function buildScene({ hops, legs }: { hops: Hop[]; legs: Leg[] }): SceneDescription {
  const layerIndex = (h: Hop): number => (h.tier ? STRATA_LAYERS.indexOf(h.tier) : layerOf(h.kind));
  const legByLane = new Map(legs.map((leg) => [leg.lane, leg]));
  const allBlocked = allLegsBlocked(legs);

  // The gate that decides a lane is its highest-rank gate-kind hop.
  const gateRankByLane = new Map<number, number>();
  for (const h of hops) {
    if (h.shared || !isGate(h)) continue;
    const prev = gateRankByLane.get(h.lane);
    if (prev === undefined || h.rank > prev) gateRankByLane.set(h.lane, h.rank);
  }

  const nodes: SceneNode[] = hops.map((h) => {
    const leg = legByLane.get(h.lane);
    const blockedLane = !h.shared && !!leg && legOutcome(leg) === "bad";
    const dimmed = blockedLane;

    let verdict: "ok" | "bad" | "warn" | null = null;
    // `blocking_uid` names the deciding hop when it differs from `fw_uid`.
    if (leg && (leg.blocking_uid ?? leg.fw_uid) === h.uid) {
      verdict = leg.blocked ? "bad" : leg.indeterminate ? "warn" : "ok";
    } else if (leg?.fw_uids?.includes(h.uid)) {
      verdict = "ok";
    } else if (h.shared && isGate(h)) {
      verdict = allBlocked ? "bad" : null;
    }

    return {
      uid: h.uid,
      kind: h.kind,
      label: h.label,
      note: h.note ?? "",
      rank: h.rank,
      lane: h.lane,
      shared: h.shared,
      layer: layerIndex(h),
      cell: { q: h.rank, r: h.lane },
      dimmed,
      verdict,
    };
  });

  // A segment is dead once its source hop is at or past the gate in the destination lane's leg.
  function segmentDead(from: Hop, to: Hop): boolean {
    if (from.shared && to.shared) return false;
    const leg = legByLane.get(to.lane);
    if (!leg || legOutcome(leg) !== "bad") return false;
    const gateRank = gateRankByLane.get(to.lane);
    return gateRank !== undefined && from.rank >= gateRank;
  }

  const edges: SceneEdge[] = [];
  const drops: SceneDrop[] = [];
  function connect(from: Hop, to: Hop): void {
    const link = { from: stationKey(from), to: stationKey(to), dead: segmentDead(from, to) };
    if (layerIndex(from) === layerIndex(to)) edges.push(link);
    else drops.push(link);
  }

  const spine = hops.filter((h) => h.shared).sort((a, b) => a.rank - b.rank);
  for (let i = 1; i < spine.length; i++) connect(spine[i - 1], spine[i]);
  const spineEnd = spine.length ? spine[spine.length - 1] : null;

  for (const leg of [...legs].sort((a, b) => a.lane - b.lane)) {
    const laneHops = hops
      .filter((h) => !h.shared && h.lane === leg.lane)
      .sort((a, b) => a.rank - b.rank);
    let prev = spineEnd;
    for (const h of laneHops) {
      if (prev) connect(prev, h);
      prev = h;
    }
  }

  return { nodes, edges, drops, layerCount: STRATA_LAYERS.length };
}

// --- layer-toggle visibility -----------------------------------------------------

export function linkHiddenByLayers(
  fromLayer: number,
  toLayer: number,
  hiddenLayers: ReadonlySet<number>,
): boolean {
  return hiddenLayers.has(fromLayer) && hiddenLayers.has(toLayer);
}

/** `scene.edges`/`scene.drops`, filtered down to the links `linkHiddenByLayers` keeps. */
export function visibleLinks(
  scene: Pick<SceneDescription, "nodes" | "edges" | "drops">,
  hiddenLayers: ReadonlySet<number> = new Set(),
): { edges: SceneEdge[]; drops: SceneDrop[] } {
  if (hiddenLayers.size === 0) return { edges: scene.edges, drops: scene.drops };
  const layerByStation = new Map(scene.nodes.map((n) => [stationKey(n), n.layer]));
  const keep = (link: { from: string; to: string }): boolean => {
    const fromLayer = layerByStation.get(link.from);
    const toLayer = layerByStation.get(link.to);
    if (fromLayer === undefined || toLayer === undefined) return true;
    return !linkHiddenByLayers(fromLayer, toLayer, hiddenLayers);
  };
  return { edges: scene.edges.filter(keep), drops: scene.drops.filter(keep) };
}
