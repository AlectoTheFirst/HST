/**
 * Dir "row" places the children side by side, and dir "col" stacks them.
 */

import type { PaneView } from "./views";
export type { PaneView };
import type { AssessmentDraft } from "../assessments/types";
import type { ApplicationDraftRef } from "../applications/types";

export interface Pane {
  type: "leaf";
  id: string;
  view: PaneView;
  /** Explore panes remember which catalog query the rail sent them. */
  queryKey?: string;
  /** Parameter values the command palette collected for `queryKey`. */
  queryParams?: Record<string, string>;
  cypher?: boolean;
  /** Explore panes the command palette sent to the Search tab: the typed
   *  text, the object to open, and a send counter. */
  searchText?: string;
  nodeUid?: string;
  searchNonce?: number;
  /** A counter that changes on every open-query, so picking the query the pane
   *  already holds opens its form again. */
  queryNonce?: number;
  /** A site code, or `scope/<name>` for a routing scope. */
  mapScope?: string;
  assessmentId?: string;
  assessmentRunId?: string;
  assessmentDraft?: AssessmentDraft;
  applicationId?: string;
  /** The generated Business Application draft the applications view shows
   *  in place of the selected application. */
  applicationDraft?: ApplicationDraftRef;
  analysisSessionId?: string;
  analysisMode?: "connection" | "simulation";
  /** The Analysis section the pane shows (results, scope, history, verification). */
  analysisSection?: "results" | "scope" | "history" | "verification";
  /** The child run of the Analysis session the pane has selected. */
  analysisRunId?: string;
  /** The change-simulation conversation of the pane. It stays with the pane
   *  across view switches and the restore to an analysis pane. */
  conversationId?: string;
}

export interface Split {
  type: "split";
  id: string;
  dir: "row" | "col";
  /** Fraction of the axis given to `a`, clamped to [MIN_RATIO, 1-MIN_RATIO]. */
  ratio: number;
  a: Node;
  b: Node;
}

export type Node = Pane | Split;

export interface Workspace {
  root: Node;
  focus: string;
}

/** The smallest fraction of a split that either side gets. */
export const MIN_RATIO = 0.15;

/** A restored tree above the cap stays as it is. */
export const MAX_PANES = 4;

let counter = 0;
function nextId(prefix = "p"): string {
  counter += 1;
  return `${prefix}${counter}`;
}

function nodeIds(node: Node): string[] {
  return node.type === "leaf" ? [node.id] : [node.id, ...nodeIds(node.a), ...nodeIds(node.b)];
}

export function seedIds(node: Node): void {
  for (const id of nodeIds(node)) {
    const match = /^[ps](\d+)$/.exec(id);
    if (match) counter = Math.max(counter, Number(match[1]));
  }
}

/** The first bearer of a duplicate id keeps it. */
export function repairIds(node: Node): { node: Node; changed: boolean } {
  seedIds(node);
  const seen = new Set<string>();
  let changed = false;
  const walk = (n: Node): Node => {
    const id = seen.has(n.id) ? nextId(n.type === "leaf" ? "p" : "s") : n.id;
    if (id !== n.id) changed = true;
    seen.add(id);
    if (n.type === "leaf") return id === n.id ? n : { ...n, id };
    return { ...n, id, a: walk(n.a), b: walk(n.b) };
  };
  return { node: walk(node), changed };
}

function newPane(view: PaneView = "trace"): Pane {
  return { type: "leaf", id: nextId(), view };
}

export function initial(): Workspace {
  const pane = newPane("trace");
  return { root: pane, focus: pane.id };
}

export function panes(node: Node): Pane[] {
  return node.type === "leaf" ? [node] : [...panes(node.a), ...panes(node.b)];
}

function mapNode(node: Node, fn: (leaf: Pane) => Node): Node {
  if (node.type === "leaf") return fn(node);
  return { ...node, a: mapNode(node.a, fn), b: mapNode(node.b, fn) };
}

/** Remove a leaf, collapsing its parent split into the surviving sibling.
 *  Returns null when `node` *is* the pane being removed. */
function without(node: Node, id: string): Node | null {
  if (node.type === "leaf") return node.id === id ? null : node;
  const a = without(node.a, id);
  const b = without(node.b, id);
  if (a === null) return b;
  if (b === null) return a;
  return { ...node, a, b };
}

export type Action =
  | { type: "restore"; state: Workspace }
  | { type: "split"; id: string; dir: "row" | "col" }
  | { type: "close"; id: string }
  | { type: "focus"; id: string }
  | { type: "ratio"; id: string; ratio: number }
  | { type: "view"; id: string; view: PaneView }
  | {
      type: "open-query";
      id: string;
      queryKey?: string;
      cypher?: boolean;
      params?: Record<string, string>;
    }
  | { type: "open-search"; id: string; text?: string; uid?: string }
  | { type: "open-assessment"; id: string; assessmentId?: string; runId?: string; draft?: AssessmentDraft }
  | { type: "open-application"; id: string; applicationId?: string }
  | { type: "set-application-draft"; id: string; draft?: ApplicationDraftRef }
  | { type: "open-analysis"; id: string; sessionId?: string; mode?: "connection" | "simulation"; section?: Pane["analysisSection"]; runId?: string; restore?: boolean }
  | { type: "set-analysis-section"; id: string; section: NonNullable<Pane["analysisSection"]> }
  | { type: "set-analysis-run"; id: string; runId?: string }
  | { type: "open-analysis-assessment"; id: string; assessmentId?: string; runId?: string }
  | { type: "open-changesim"; id: string; conversationId?: string }
  | { type: "open-map"; id: string; scope?: string }
  | { type: "set-conversation"; id: string; conversationId?: string }
  | { type: "reset" };

export function reduce(state: Workspace, action: Action): Workspace {
  switch (action.type) {
    case "restore":
      return action.state;

    case "split": {
      if (panes(state.root).length >= MAX_PANES) return state;
      const source = panes(state.root).find((p) => p.id === action.id);
      if (!source) return state;
      const fresh = newPane(source.view);
      const root = mapNode(state.root, (leaf) =>
        leaf.id === action.id
          ? { type: "split", id: nextId("s"), dir: action.dir, ratio: 0.5, a: leaf, b: fresh }
          : leaf,
      );
      return { root, focus: fresh.id };
    }

    case "close": {
      const remaining = panes(state.root);
      if (remaining.length <= 1) return state;
      const root = without(state.root, action.id);
      if (!root) return state;
      const focus = panes(root).some((p) => p.id === state.focus)
        ? state.focus
        : panes(root)[0].id;
      return { root, focus };
    }

    case "focus":
      return panes(state.root).some((p) => p.id === action.id)
        ? { ...state, focus: action.id }
        : state;

    case "ratio": {
      const ratio = Math.min(1 - MIN_RATIO, Math.max(MIN_RATIO, action.ratio));
      const walk = (node: Node): Node =>
        node.type === "leaf"
          ? node
          : { ...node, ratio: node.id === action.id ? ratio : node.ratio,
              a: walk(node.a), b: walk(node.b) };
      return { ...state, root: walk(state.root) };
    }

    case "view":
      return {
        ...state,
        root: mapNode(state.root, (leaf) =>
          leaf.id === action.id ? { ...leaf, view: action.view } : leaf,
        ),
      };

    case "open-query":
      return {
        ...state,
        root: mapNode(state.root, (leaf) =>
          leaf.id === action.id
            ? {
                ...leaf,
                view: "explore",
                queryKey: action.queryKey,
                queryParams: action.params,
                cypher: action.cypher,
                queryNonce: (leaf.queryNonce ?? 0) + 1,
                searchText: undefined,
                nodeUid: undefined,
                searchNonce: undefined,
              }
            : leaf,
        ),
      };

    case "open-search":
      // the palette opens an object, or all of its matches, in Explore's Search tab
      return {
        ...state,
        root: mapNode(state.root, (leaf) =>
          leaf.id === action.id
            ? {
                ...leaf,
                view: "explore",
                queryKey: undefined,
                queryParams: undefined,
                cypher: undefined,
                searchText: action.text,
                nodeUid: action.uid,
                searchNonce: (leaf.searchNonce ?? 0) + 1,
              }
            : leaf,
        ),
      };

    case "open-map":
      // the site map hands a scope over; the rail's own map entry hands none
      return {
        ...state,
        root: mapNode(state.root, (leaf) =>
          leaf.id === action.id ? { ...leaf, view: "map", mapScope: action.scope } : leaf,
        ),
      };

    case "open-assessment":
      return {
        ...state,
        root: mapNode(state.root, (leaf) => leaf.id === action.id
          ? { ...leaf, view: "assessments", assessmentId: action.assessmentId, assessmentRunId: action.runId, assessmentDraft: action.draft }
          : leaf),
      };

    case "open-application":
      // opening another application closes the pane's draft
      return {
        ...state,
        root: mapNode(state.root, (leaf) => leaf.id === action.id
          ? {
              ...leaf,
              view: "applications",
              applicationId: action.applicationId,
              ...(action.applicationId && action.applicationId !== leaf.applicationId ? { applicationDraft: undefined } : {}),
            }
          : leaf),
      };

    case "set-application-draft":
      return {
        ...state,
        root: mapNode(state.root, (leaf) => leaf.id === action.id
          ? { ...leaf, view: "applications", applicationDraft: action.draft }
          : leaf),
      };

    case "open-analysis":
      // `restore` returns the pane to the Analysis state that it holds
      return {
        ...state,
        root: mapNode(state.root, (leaf) => leaf.id === action.id
          ? action.restore
            ? { ...leaf, view: "analysis" }
            : {
                ...leaf,
                view: "analysis",
                analysisSessionId: action.sessionId,
                analysisMode: action.mode,
                analysisSection: action.section,
                analysisRunId: action.runId,
                assessmentId: undefined,
                assessmentRunId: undefined,
              }
          : leaf),
      };

    case "set-analysis-section":
      return {
        ...state,
        root: mapNode(state.root, (leaf) => leaf.id === action.id ? { ...leaf, analysisSection: action.section } : leaf),
      };

    case "set-analysis-run":
      return {
        ...state,
        root: mapNode(state.root, (leaf) => leaf.id === action.id ? { ...leaf, analysisRunId: action.runId } : leaf),
      };

    case "open-analysis-assessment":
      return {
        ...state,
        root: mapNode(state.root, (leaf) => leaf.id === action.id
          ? {
              ...leaf,
              view: "analysis",
              analysisSessionId: undefined,
              analysisRunId: undefined,
              assessmentId: action.assessmentId,
              assessmentRunId: action.runId,
              analysisMode: "connection",
            }
          : leaf),
      };

    case "open-changesim":
      // a conversation from elsewhere (the drawer) replaces the pane's own;
      // without one the pane keeps its conversation
      return {
        ...state,
        root: mapNode(state.root, (leaf) =>
          leaf.id === action.id
            ? { ...leaf, view: "changesim", conversationId: action.conversationId ?? leaf.conversationId }
            : leaf,
        ),
      };

    case "set-conversation":
      return {
        ...state,
        root: mapNode(state.root, (leaf) =>
          leaf.id === action.id ? { ...leaf, conversationId: action.conversationId } : leaf,
        ),
      };

    case "reset":
      return initial();
  }
}

/** A pane or seam's place in the workspace, in percentages of it. */
export interface Rect {
  top: number;
  left: number;
  width: number;
  height: number;
}

interface TiledPane {
  pane: Pane;
  rect: Rect;
}

interface TiledDivider {
  id: string;
  dir: "row" | "col";
  /** The seam itself: zero-thickness along the axis it divides. */
  rect: Rect;
  /** The split's own box, which the drag ratio is measured against. */
  box: Rect;
}

interface Tiling {
  panes: TiledPane[];
  dividers: TiledDivider[];
}

const FULL: Rect = { top: 0, left: 0, width: 100, height: 100 };

/** Child `b` is the exact complement of child `a`. */
export function tile(node: Node, box: Rect = FULL): Tiling {
  if (node.type === "leaf") return { panes: [{ pane: node, rect: box }], dividers: [] };

  const row = node.dir === "row";
  const aSize = (row ? box.width : box.height) * node.ratio;
  const a: Rect = row
    ? { ...box, width: aSize }
    : { ...box, height: aSize };
  const b: Rect = row
    ? { ...box, left: box.left + aSize, width: box.width - aSize }
    : { ...box, top: box.top + aSize, height: box.height - aSize };

  const seam: Rect = row
    ? { top: box.top, left: box.left + aSize, width: 0, height: box.height }
    : { top: box.top + aSize, left: box.left, width: box.width, height: 0 };

  const first = tile(node.a, a);
  const second = tile(node.b, b);
  return {
    panes: [...first.panes, ...second.panes],
    dividers: [
      { id: node.id, dir: node.dir, rect: seam, box },
      ...first.dividers,
      ...second.dividers,
    ],
  };
}

/** The nearest pane in a direction, by geometry. */
export function neighbour(
  rects: Map<string, { x: number; y: number; w: number; h: number }>,
  from: string,
  dir: "left" | "right" | "up" | "down",
): string | null {
  const self = rects.get(from);
  if (!self) return null;
  const cx = self.x + self.w / 2;
  const cy = self.y + self.h / 2;

  let best: string | null = null;
  let bestDist = Infinity;
  for (const [id, r] of rects) {
    if (id === from) continue;
    const ox = r.x + r.w / 2;
    const oy = r.y + r.h / 2;
    const wrongWay =
      (dir === "left" && ox >= cx) ||
      (dir === "right" && ox <= cx) ||
      (dir === "up" && oy >= cy) ||
      (dir === "down" && oy <= cy);
    if (wrongWay) continue;
    // prefer the closest along the axis of travel, then the closest across it
    const along = dir === "left" || dir === "right" ? Math.abs(ox - cx) : Math.abs(oy - cy);
    const across = dir === "left" || dir === "right" ? Math.abs(oy - cy) : Math.abs(ox - cx);
    const dist = along + across * 2;
    if (dist < bestDist) {
      bestDist = dist;
      best = id;
    }
  }
  return best;
}
