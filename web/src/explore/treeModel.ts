/** A node that is already open above an item, or that is a root, shows as a reference item. */

import type { GraphNode, GraphRelationship, ResultGraph, ResultRow } from "../api/types";
import type { NeighborGroup } from "../api/explore";
import { captionFull, primaryLabel } from "./graphElements";

/** Result items one group shows before a "Show more" item. */
export const RESULT_PAGE = 20;
/** Snapshot items one page load adds. */
export const SNAPSHOT_PAGE = 50;
/** Node levels under each root that the filter searches. */
export const FILTER_DEPTH = 3;
/** The longest path, in relationships, that the reveal of a row follows. */
export const REVEAL_DEPTH = 6;

export interface Edge {
  rel: GraphRelationship;
  other: string;
  direction: "out" | "in";
}

export interface Adjacency {
  nodes: Map<string, GraphNode>;
  edges: Map<string, Edge[]>;
}

/** The view graph as a lookup. Build it once for each change of the graph. */
export function adjacency(graph: ResultGraph): Adjacency {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const edges = new Map<string, Edge[]>();
  const add = (id: string, edge: Edge) => {
    const list = edges.get(id);
    if (list) list.push(edge);
    else edges.set(id, [edge]);
  };
  for (const rel of graph.relationships) {
    if (!nodes.has(rel.start) || !nodes.has(rel.end)) continue;
    add(rel.start, { rel, other: rel.end, direction: "out" });
    if (rel.start !== rel.end) add(rel.end, { rel, other: rel.start, direction: "in" });
  }
  return { nodes, edges };
}

/** The roots of the tree: the first node of each row, once each, in row order.
 *  Without a row node index on any row, the payload nodes in payload order. */
export function rootsOf(rows: readonly ResultRow[], graph: ResultGraph): { roots: string[]; rowsOfRoot: Map<string, number[]> } {
  const present = new Set(graph.nodes.map((n) => n.id));
  const rowsOfRoot = new Map<string, number[]>();
  if (!rows.some((r) => r.nodes !== undefined)) return { roots: graph.nodes.map((n) => n.id), rowsOfRoot };
  const roots: string[] = [];
  rows.forEach((r, i) => {
    const first = r.nodes?.find((id) => present.has(id));
    if (first === undefined) return;
    const list = rowsOfRoot.get(first);
    if (list) list.push(i);
    else {
      rowsOfRoot.set(first, [i]);
      roots.push(first);
    }
  });
  return { roots, rowsOfRoot };
}

export type DetailState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ok"; groups: NeighborGroup[] };

export interface PageState {
  /** Snapshot items fetched so far: the offset of the next page. */
  offset: number;
  status: "idle" | "loading" | "error";
  message?: string;
}

export interface TreeInput {
  adj: Adjacency;
  roots: readonly string[];
  rowsOfRoot: ReadonlyMap<string, number[]>;
  /** The relationship ids of the query payload. An item reached by any other
   *  relationship came from the snapshot. */
  resultRels: ReadonlySet<string>;
  detail: (uid: string) => DetailState | undefined;
  page: (uid: string, gid: string) => PageState | undefined;
  open: ReadonlySet<string>;
  /** Result items shown for each group key, when the user asked for more. */
  limits: ReadonlyMap<string, number>;
  /** The view graph is at its node cap: no page load can add a node. */
  full: boolean;
}

export type ItemKind = "node" | "group" | "ref" | "more" | "loading" | "error";

export interface GroupInfo {
  /** `TYPE:dir:Label`, the same for the result and the snapshot side. */
  id: string;
  type: string;
  direction: "out" | "in";
  label: string | null;
  /** Items reached by a relationship of the query payload. */
  inResult: number;
  /** Items in the view graph, from the result and from loaded pages. */
  loaded: number;
  /** The count in the snapshot, once the node detail is loaded. */
  snapshot?: number;
}

export interface TreeItem {
  key: string;
  kind: ItemKind;
  level: number;
  parent: string | null;
  posinset: number;
  setsize: number;
  expandable: boolean;
  open: boolean;
  /** node and ref: the node. group: the node that owns the group. */
  nodeId?: string;
  /** The uid of `nodeId`, when it has one. */
  uid?: string;
  group?: GroupInfo;
  /** ref: the key of the item it points to. */
  target?: string;
  reason?: "above" | "root";
  /** node: reached by a relationship that the query did not return. */
  snapshot?: boolean;
  /** A root: the rows that start with it. */
  rows?: number[];
  more?: "result" | "snapshot";
  count?: number;
  /** more: the view graph is full and the load is off. */
  disabled?: boolean;
  message?: string;
  retry?: { kind: "detail"; uid: string } | { kind: "page"; uid: string; gid: string };
}

export const groupIdOf = (type: string, direction: string, label: string | null) => `${type}:${direction}:${label ?? ""}`;

function uidOf(node: GraphNode | undefined): string | undefined {
  const uid = node?.properties.uid;
  return typeof uid === "string" && uid ? uid : undefined;
}

/** Up to 3 key properties for each primary label. */
export const SUMMARY: Readonly<Record<string, readonly string[]>> = {
  Device: ["vendor", "model", "role"],
  Interface: ["kind", "mtu", "description"],
  Lag: ["protocol", "min_links"],
  Prefix: ["kind", "af"],
  IpAddress: ["af"],
  Site: ["code", "kind"],
  BgpSession: ["peer_ip", "peer_asn", "state"],
};

export function summary(node: GraphNode): string {
  const keys = SUMMARY[primaryLabel(node)] ?? [];
  return keys
    .map((k) => node.properties[k])
    .filter((v) => v !== null && v !== undefined && v !== "")
    .map((v) => (Array.isArray(v) ? v.join(" ") : String(v)))
    .join(", ");
}

export function countText(g: GroupInfo): string {
  if (g.snapshot === undefined || g.snapshot === g.inResult) return `${g.inResult}`;
  return `${g.inResult} in result, ${g.snapshot} in snapshot`;
}

export function groupText(g: GroupInfo): string {
  return `${g.type} ${g.direction === "out" ? "to" : "from"} ${g.label ?? "node"} (${countText(g)})`;
}

const PAGE_FULL = "Node limit reached";

/** The text of one item: what the tree shows, and what "Copy branch" writes. */
export function itemText(adj: Adjacency, item: TreeItem): string {
  switch (item.kind) {
    case "node": {
      const node = adj.nodes.get(item.nodeId!);
      if (!node) return item.nodeId!;
      return [captionFull(node), primaryLabel(node), summary(node)].filter(Boolean).join("  ");
    }
    case "group":
      return groupText(item.group!);
    case "ref": {
      const node = adj.nodes.get(item.nodeId!);
      const name = node ? captionFull(node) : item.nodeId!;
      return `${name}  (${item.reason === "above" ? "already open above" : "jump to its result branch"})`;
    }
    case "more":
      if (item.more === "result") return `Show ${item.count} more`;
      return item.disabled ? PAGE_FULL : `Load ${item.count} more from the snapshot`;
    case "loading":
      return "Loading";
    case "error":
      return item.message ?? "Request failed";
  }
}

type Partial = Omit<TreeItem, "level" | "parent" | "posinset" | "setsize" | "open"> & { open?: boolean };

interface PathStep {
  id: string;
  key: string;
}

/** The groups of one node: from the view graph, joined with the snapshot
 *  counts when the node detail is loaded. Sorted by type, then direction, then
 *  label. */
function groupsOf(input: TreeInput, nodeId: string): { info: GroupInfo; edges: Edge[] }[] {
  const byId = new Map<string, { info: GroupInfo; edges: Edge[]; seen: Set<string> }>();
  for (const edge of input.adj.edges.get(nodeId) ?? []) {
    const other = input.adj.nodes.get(edge.other);
    const label = other ? primaryLabel(other) : null;
    const id = groupIdOf(edge.rel.type, edge.direction, label);
    let g = byId.get(id);
    if (!g) {
      g = { info: { id, type: edge.rel.type, direction: edge.direction, label, inResult: 0, loaded: 0 }, edges: [], seen: new Set() };
      byId.set(id, g);
    }
    // parallel relationships to one node show the node once
    if (g.seen.has(edge.other)) continue;
    g.seen.add(edge.other);
    g.edges.push(edge);
  }
  const uid = uidOf(input.adj.nodes.get(nodeId));
  const detail = uid ? input.detail(uid) : undefined;
  if (detail?.status === "ok") {
    for (const ng of detail.groups) {
      const id = groupIdOf(ng.type, ng.direction, ng.label);
      const g = byId.get(id);
      if (g) g.info.snapshot = ng.count;
      else if (ng.count > 0)
        byId.set(id, {
          info: { id, type: ng.type, direction: ng.direction, label: ng.label, inResult: 0, loaded: 0, snapshot: ng.count },
          edges: [],
          seen: new Set(),
        });
    }
  }
  const out = [...byId.values()].map(({ info, edges }) => {
    // result items first, each side in view graph order
    const sorted = [...edges.filter((e) => input.resultRels.has(e.rel.id)), ...edges.filter((e) => !input.resultRels.has(e.rel.id))];
    return { info: { ...info, inResult: edges.filter((e) => input.resultRels.has(e.rel.id)).length, loaded: edges.length }, edges: sorted };
  });
  return out.sort(
    (a, b) =>
      a.info.type.localeCompare(b.info.type) ||
      a.info.direction.localeCompare(b.info.direction) ||
      (a.info.label ?? "").localeCompare(b.info.label ?? ""),
  );
}

function nodeExpandable(input: TreeInput, nodeId: string): boolean {
  if ((input.adj.edges.get(nodeId)?.length ?? 0) > 0) return true;
  const uid = uidOf(input.adj.nodes.get(nodeId));
  if (!uid) return false;
  const detail = input.detail(uid);
  return detail?.status !== "ok" || detail.groups.some((g) => g.count > 0);
}

function nodeItem(input: TreeInput, key: string, nodeId: string, extra: { snapshot?: boolean; rows?: number[] } = {}): Partial {
  return { key, kind: "node", nodeId, uid: uidOf(input.adj.nodes.get(nodeId)), ...extra, expandable: nodeExpandable(input, nodeId) };
}

/** All children of a node item: its groups, then a loading or error item for
 *  the node detail. */
function nodeChildren(input: TreeInput, item: TreeItem): Partial[] {
  const nodeId = item.nodeId!;
  const groups = groupsOf(input, nodeId).map(
    ({ info }): Partial => ({ key: `${item.key}|g:${info.id}`, kind: "group", nodeId, uid: item.uid, group: info, expandable: true }),
  );
  const detail = item.uid ? input.detail(item.uid) : undefined;
  // no item while the detail is not asked for
  if (item.uid && detail?.status === "loading")
    groups.push({ key: `${item.key}|loading`, kind: "loading", expandable: false });
  if (item.uid && detail?.status === "error")
    groups.push({
      key: `${item.key}|error`,
      kind: "error",
      message: detail.message,
      retry: { kind: "detail", uid: item.uid },
      expandable: false,
    });
  return groups;
}

/** All children of a group item, without the result page limit: its nodes or
 *  reference items, then the snapshot page item. */
function groupChildren(input: TreeInput, item: TreeItem, path: readonly PathStep[]): { items: Partial[]; tail: Partial[] } {
  const g = item.group!;
  const found = groupsOf(input, item.nodeId!).find((x) => x.info.id === g.id);
  const rootSet = new Set(input.roots);
  const items = (found?.edges ?? []).map((edge): Partial => {
    const key = `${item.key}|n:${edge.other}`;
    const above = path.find((p) => p.id === edge.other);
    if (above) return { key, kind: "ref", nodeId: edge.other, reason: "above", target: above.key, expandable: false };
    if (rootSet.has(edge.other)) return { key, kind: "ref", nodeId: edge.other, reason: "root", target: `n:${edge.other}`, expandable: false };
    return nodeItem(input, key, edge.other, { snapshot: !input.resultRels.has(edge.rel.id) });
  });
  const tail: Partial[] = [];
  const uid = item.uid;
  if (uid && g.snapshot !== undefined && g.loaded < g.snapshot) {
    const page = input.page(uid, g.id);
    const offset = page?.offset ?? 0;
    if (page?.status === "loading") tail.push({ key: `${item.key}|loading`, kind: "loading", expandable: false });
    else if (page?.status === "error")
      tail.push({
        key: `${item.key}|error`,
        kind: "error",
        message: page.message,
        retry: { kind: "page", uid, gid: g.id },
        expandable: false,
      });
    else if (offset < g.snapshot)
      tail.push({
        key: `${item.key}|load`,
        kind: "more",
        more: "snapshot",
        nodeId: item.nodeId,
        uid,
        group: g,
        count: Math.min(SNAPSHOT_PAGE, g.snapshot - offset),
        disabled: input.full,
        expandable: false,
      });
  }
  return { items, tail };
}

function finish(parts: Partial[], parent: TreeItem | null, open: (p: Partial) => boolean): TreeItem[] {
  return parts.map((p, i) => ({
    ...p,
    level: parent ? parent.level + 1 : 1,
    parent: parent?.key ?? null,
    posinset: i + 1,
    setsize: parts.length,
    open: p.expandable && open(p),
  }));
}

/**
 * The visible items, in order. `open` is the open set of the input plus any
 * keys a filter or a reveal opens. A key in `pinned` shows even past the
 * result page limit of its group.
 */
export function buildRows(input: TreeInput, extraOpen: ReadonlySet<string> = new Set(), pinned: ReadonlySet<string> = new Set()): TreeItem[] {
  const isOpen = (p: Partial) => input.open.has(p.key) || extraOpen.has(p.key);
  const out: TreeItem[] = [];
  const visit = (item: TreeItem, path: readonly PathStep[]) => {
    out.push(item);
    if (!item.open) return;
    if (item.kind === "node") {
      const next = [...path, { id: item.nodeId!, key: item.key }];
      for (const child of finish(nodeChildren(input, item), item, isOpen)) visit(child, next);
    } else if (item.kind === "group") {
      const { items, tail } = groupChildren(input, item, path);
      const limit = input.limits.get(item.key) ?? RESULT_PAGE;
      const shown = items.filter((p, i) => i < limit || pinned.has(p.key));
      const hidden = items.length - shown.length;
      const more: Partial[] =
        hidden > 0 ? [{ key: `${item.key}|more`, kind: "more", more: "result", count: Math.min(hidden, RESULT_PAGE), expandable: false }] : [];
      for (const child of finish([...shown, ...more, ...tail], item, isOpen)) visit(child, path);
    }
  };
  const roots = input.roots
    .filter((id) => input.adj.nodes.has(id))
    .map((id): Partial => nodeItem(input, `n:${id}`, id, { rows: input.rowsOfRoot.get(id) }));
  for (const root of finish(roots, null, isOpen)) visit(root, []);
  return out;
}

export interface FilterResult {
  matches: Set<string>;
  /** The matches and every item on a path from a root to a match. */
  onPath: Set<string>;
  /** The ancestors of the matches: the keys the filter opens. */
  open: Set<string>;
}

/** The filter matches every loaded item to `depth` node levels under each root, without case. */
export function filterTree(input: TreeInput, text: string, depth = FILTER_DEPTH): FilterResult {
  const needle = text.trim().toLowerCase();
  const result: FilterResult = { matches: new Set(), onPath: new Set(), open: new Set() };
  if (!needle) return result;
  const all = () => true;
  const visit = (item: TreeItem, path: readonly PathStep[], ancestors: readonly string[], nodeDepth: number) => {
    if (item.kind === "node" || item.kind === "group" || item.kind === "ref") {
      if (itemText(input.adj, item).toLowerCase().includes(needle)) {
        result.matches.add(item.key);
        result.onPath.add(item.key);
        for (const a of ancestors) {
          result.onPath.add(a);
          result.open.add(a);
        }
      }
    }
    const next = [...ancestors, item.key];
    if (item.kind === "node" && item.expandable && nodeDepth < depth) {
      const steps = [...path, { id: item.nodeId!, key: item.key }];
      for (const child of finish(nodeChildren(input, item), item, all)) visit(child, steps, next, nodeDepth);
    } else if (item.kind === "group") {
      const { items } = groupChildren(input, item, path);
      for (const child of finish(items, item, all)) visit(child, path, next, nodeDepth + 1);
    }
  };
  const roots = input.roots.filter((id) => input.adj.nodes.has(id)).map((id): Partial => nodeItem(input, `n:${id}`, id));
  for (const root of finish(roots, null, all)) visit(root, [], [], 0);
  return result;
}

/** Each kept item's position in its set is counted again among the kept siblings. */
export function keepFiltered(items: readonly TreeItem[], filtered: FilterResult): TreeItem[] {
  const kept: TreeItem[] = [];
  let under: number | null = null;
  for (const item of items) {
    if (under !== null && item.level <= under) under = null;
    if (under !== null || filtered.onPath.has(item.key)) kept.push(item);
    if (under === null && filtered.matches.has(item.key)) under = item.level;
  }
  const sizes = new Map<string | null, number>();
  for (const item of kept) sizes.set(item.parent, (sizes.get(item.parent) ?? 0) + 1);
  const seen = new Map<string | null, number>();
  return kept.map((item) => {
    const posinset = (seen.get(item.parent) ?? 0) + 1;
    seen.set(item.parent, posinset);
    return { ...item, posinset, setsize: sizes.get(item.parent)! };
  });
}

/**
 * "Copy branch": the item at `index` and its visible children as plain text.
 * Each level adds 4 characters.
 */
export function branchText(adj: Adjacency, items: readonly TreeItem[], index: number): string {
  const start = items[index];
  if (!start) return "";
  const lines = [itemText(adj, start)];
  const last: boolean[] = [];
  for (let i = index + 1; i < items.length && items[i].level > start.level; i++) {
    const item = items[i];
    const depth = item.level - start.level;
    const isLast = item.posinset === item.setsize;
    let prefix = "";
    for (let d = 1; d < depth; d++) prefix += last[d] ? "    " : "|   ";
    prefix += isLast ? "`-- " : "|-- ";
    last[depth] = isLast;
    lines.push(prefix + itemText(adj, item));
  }
  return lines.join("\n");
}

/** The search does not pass through another root. */
export function findPath(adj: Adjacency, roots: ReadonlySet<string>, from: string, to: string, depth = REVEAL_DEPTH): Edge[] | null {
  if (from === to) return [];
  const prev = new Map<string, { at: string; edge: Edge }>();
  const seen = new Set([from]);
  let frontier = [from];
  for (let d = 0; d < depth && frontier.length > 0; d++) {
    const next: string[] = [];
    for (const at of frontier) {
      if (at !== from && roots.has(at)) continue;
      for (const edge of adj.edges.get(at) ?? []) {
        if (seen.has(edge.other)) continue;
        seen.add(edge.other);
        prev.set(edge.other, { at, edge });
        if (edge.other === to) {
          const out: Edge[] = [];
          for (let cur = to; cur !== from; cur = prev.get(cur)!.at) out.unshift(prev.get(cur)!.edge);
          return out;
        }
        next.push(edge.other);
      }
    }
    frontier = next;
  }
  return null;
}

/** The item keys along a path from the root `from`: each group, then each node. */
export function pathKeys(adj: Adjacency, from: string, path: readonly Edge[]): string[] {
  let key = `n:${from}`;
  const keys = [key];
  for (const edge of path) {
    const other = adj.nodes.get(edge.other);
    key = `${key}|g:${groupIdOf(edge.rel.type, edge.direction, other ? primaryLabel(other) : null)}`;
    keys.push(key);
    key = `${key}|n:${edge.other}`;
    keys.push(key);
  }
  return keys;
}

export interface Reveal {
  /** The keys to open: every group and node on each path, but not the end nodes. */
  open: Set<string>;
  /** Every key on each path, so each shows past a group page limit. */
  pinned: Set<string>;
  /** For each node reached, the key of its item. */
  keyOf: Map<string, string>;
  /** The nodes with no path from the root. */
  missing: string[];
}

/** Open the paths from `root` to each of `targets` (S5, "Reveal a row"). */
export function reveal(adj: Adjacency, roots: readonly string[], root: string, targets: readonly string[]): Reveal {
  const rootSet = new Set(roots);
  const out: Reveal = { open: new Set(), pinned: new Set(), keyOf: new Map([[root, `n:${root}`]]), missing: [] };
  for (const target of targets) {
    if (target === root) continue;
    const path = findPath(adj, rootSet, root, target);
    if (!path) {
      out.missing.push(target);
      continue;
    }
    const keys = pathKeys(adj, root, path);
    keys.forEach((k, i) => {
      out.pinned.add(k);
      if (i < keys.length - 1) out.open.add(k);
    });
    out.keyOf.set(target, keys[keys.length - 1]);
  }
  return out;
}

/** The reveal of `target` from the root nearest to it. Of two roots at one
 *  distance, the first in row order. */
export function revealNode(adj: Adjacency, roots: readonly string[], target: string): Reveal | null {
  if (roots.includes(target)) return reveal(adj, roots, target, []);
  const rootSet = new Set(roots);
  let best: { root: string; length: number } | null = null;
  for (const root of roots) {
    const path = findPath(adj, rootSet, root, target, best ? Math.min(REVEAL_DEPTH, best.length - 1) : REVEAL_DEPTH);
    if (path && (!best || path.length < best.length)) best = { root, length: path.length };
  }
  return best ? reveal(adj, roots, best.root, [target]) : null;
}
