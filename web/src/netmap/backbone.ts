/**
 * The backbone of the estate, without a DOM: the hubs, data centers and
 * colocation sites as a small graph, and each branch as a count on the badge
 * of its primary major site.
 *
 * - The backbone ignores coordinates: a site with no place on the world map is
 *   still part of it.
 * - A branch belongs to one major site, its primary home: the major neighbor
 *   with the highest link count over the active kinds. A tie goes to the lower
 *   code in code point order. The other major neighbors are listed, not
 *   counted.
 * - A branch with no link to a major site over the active kinds goes to the
 *   "No hub" group (`orphans`).
 * - The backbone edges join major sites only, one per site pair, with the
 *   count per kind and a total.
 *
 * Pure and deterministic: the same payload and kinds give the same model.
 */

import type { SiteEdgeKind, SiteGraphPayload, SiteGraphSite } from "../api/types";
import type { Point } from "../diagram/projection";
import { byText, CLASS_ORDER, MAJOR, siteClass, type SiteClass } from "./estate";

export type MajorClass = Exclude<SiteClass, "branch">;

export interface MajorSite {
  code: string;
  cls: MajorClass;
  site: SiteGraphSite;
}

export interface Home {
  /** the branch code */
  code: string;
  /** the major site the branch counts under, null for the "No hub" group */
  primary: string | null;
  /** the other major neighbors, in code point order */
  others: string[];
  /** link count to each major neighbor, summed over the active kinds */
  counts: Record<string, number>;
  /** all links of the branch over the active kinds, to any site */
  total: number;
}

export interface BackboneEdge {
  /** the lower code of the pair in code point order */
  a: string;
  b: string;
  /** count per kind, only the active kinds */
  kinds: Partial<Record<SiteEdgeKind, number>>;
  total: number;
}

export interface Badge {
  /** the major site the badge sits beside */
  major: string;
  count: number;
  /** the branch codes, in code point order */
  branches: string[];
}

export interface Backbone {
  majors: MajorSite[];
  edges: BackboneEdge[];
  /** one per major site with at least one branch, in the order of `majors` */
  badges: Badge[];
  /** the branch codes with no major neighbor, in code point order */
  orphans: string[];
}

export interface BranchRow {
  code: string;
  name: string;
  /** the major neighbors other than the primary home */
  others: string[];
  /** all links of the branch over the active kinds */
  total: number;
}

/** The most branch positions one badge opens; the caller turns the last one
 *  into "and N more" when a badge holds more branches. */
export const RING_CAP = 120;
/** distance from a major site to its badge, in graph units */
export const BADGE_GAP = 44;
/** the smallest radius of the first branch ring, in graph units */
export const RING_INNER = 72;
/** the angle each ring spans, centered on the away direction */
const RING_ARC = Math.PI;
/** the space between two branch centers, as a multiple of the node size */
const SPACING = 1.5;

/** Hubs, data centers and colocation sites, by class and then by code. */
export function majorsOf(sites: SiteGraphSite[]): MajorSite[] {
  return sites
    .map((site) => ({ code: site.code, cls: siteClass(site), site }))
    .filter((m): m is MajorSite => MAJOR.has(m.cls))
    .sort((p, q) => CLASS_ORDER[p.cls] - CLASS_ORDER[q.cls] || byText(p.code, q.code));
}

/** The primary home of each branch, keyed by branch code in code point
 *  order. */
export function homes(payload: SiteGraphPayload, kinds: ReadonlySet<SiteEdgeKind>): Map<string, Home> {
  const major = new Set(majorsOf(payload.sites).map((m) => m.code));
  const branches = payload.sites
    .filter((s) => !major.has(s.code))
    .map((s) => s.code)
    .sort(byText);
  const work = new Map<string, Home>();
  for (const code of branches) work.set(code, { code, primary: null, others: [], counts: {}, total: 0 });
  for (const e of payload.edges) {
    if (!kinds.has(e.kind) || e.a === e.b) continue;
    for (const [near, far] of [
      [e.a, e.b],
      [e.b, e.a],
    ]) {
      const home = work.get(near);
      if (!home) continue;
      home.total += e.count;
      if (major.has(far)) home.counts[far] = (home.counts[far] ?? 0) + e.count;
    }
  }
  for (const home of work.values()) {
    const ranked = Object.entries(home.counts).sort(([p, n], [q, m]) => m - n || byText(p, q));
    if (ranked.length === 0) continue;
    home.primary = ranked[0][0];
    home.others = ranked
      .slice(1)
      .map(([code]) => code)
      .sort(byText);
  }
  return work;
}

/** The major sites, the edges between them, a badge per major site with
 *  branches, and the "No hub" group. */
export function backbone(payload: SiteGraphPayload, kinds: ReadonlySet<SiteEdgeKind>): Backbone {
  const majors = majorsOf(payload.sites);
  const major = new Set(majors.map((m) => m.code));
  const edges = combine(
    payload.edges.filter((e) => major.has(e.a) && major.has(e.b)),
    kinds,
  );
  const under = new Map<string, string[]>();
  const orphans: string[] = [];
  for (const home of homes(payload, kinds).values()) {
    if (home.primary === null) orphans.push(home.code);
    else under.set(home.primary, [...(under.get(home.primary) ?? []), home.code]);
  }
  const badges: Badge[] = [];
  for (const m of majors) {
    const branches = under.get(m.code);
    if (branches) badges.push({ major: m.code, count: branches.length, branches });
  }
  return { majors, edges, badges, orphans };
}

/** The rows of one badge: its branches, with their other major neighbors and
 *  link totals. `major` null gives the rows of the "No hub" group. */
export function branchRows(
  payload: SiteGraphPayload,
  kinds: ReadonlySet<SiteEdgeKind>,
  major: string | null,
): BranchRow[] {
  const names = new Map(payload.sites.map((s) => [s.code, s.name]));
  return [...homes(payload, kinds).values()]
    .filter((h) => h.primary === major)
    .map((h) => ({ code: h.code, name: names.get(h.code) ?? h.code, others: h.others, total: h.total }));
}

/** The links from the shown branches to the drawn nodes: the major sites and
 *  the other shown branches. `major` names the open badge, or several of
 *  them; null stands for the "No hub" group. */
export function branchLinks(
  payload: SiteGraphPayload,
  kinds: ReadonlySet<SiteEdgeKind>,
  major: string | null | ReadonlyArray<string | null>,
): BackboneEdge[] {
  const open = new Set<string | null>(Array.isArray(major) ? major : [major as string | null]);
  const shown = new Set(
    [...homes(payload, kinds).values()].filter((h) => open.has(h.primary)).map((h) => h.code),
  );
  const drawn = new Set([...majorsOf(payload.sites).map((m) => m.code), ...shown]);
  return combine(
    payload.edges.filter(
      (e) => (shown.has(e.a) && drawn.has(e.b)) || (shown.has(e.b) && drawn.has(e.a)),
    ),
    kinds,
  );
}

/** Positions for `n` branch nodes of diameter `size` on concentric arcs
 *  around `center`, opening toward `away`. Each ring spans a half circle
 *  centered on the away direction; the rings grow outward by the same step,
 *  and each holds as many nodes as its arc length allows. Two positions are
 *  never nearer than 1.5 node sizes. At most `RING_CAP` positions. */
export function ringPositions(center: Point, away: Point, n: number, size: number): Point[] {
  const count = Math.max(0, Math.min(Math.floor(n), RING_CAP));
  const gap = size * SPACING;
  const theta = Math.atan2(unit(away).y, unit(away).x);
  const out: Point[] = [];
  for (let ring = 0; out.length < count; ring++) {
    const r = Math.max(RING_INNER, 3 * size) + ring * gap;
    // the angle whose chord is one gap, so neighbors on a ring are one gap apart
    const step = 2 * Math.asin(Math.min(1, gap / (2 * r)));
    const capacity = Math.floor(RING_ARC / step) + 1;
    const m = Math.min(capacity, count - out.length);
    for (let i = 0; i < m; i++) {
      const a = theta + (i - (m - 1) / 2) * step;
      out.push({ x: center.x + r * Math.cos(a), y: center.y + r * Math.sin(a) });
    }
  }
  return out;
}

/** The badge position of a major site: a fixed distance on the away side. */
export function badgeOffset(center: Point, away: Point): Point {
  const u = unit(away);
  return { x: center.x + u.x * BADGE_GAP, y: center.y + u.y * BADGE_GAP };
}

/** The unit vector of `v`; a zero vector points right. */
function unit(v: Point): Point {
  const len = Math.hypot(v.x, v.y);
  return len === 0 ? { x: 1, y: 0 } : { x: v.x / len, y: v.y / len };
}

/** One edge per site pair, with the count per active kind and a total. */
function combine(edges: SiteGraphPayload["edges"], kinds: ReadonlySet<SiteEdgeKind>): BackboneEdge[] {
  const out = new Map<string, BackboneEdge>();
  for (const e of edges) {
    if (!kinds.has(e.kind) || e.a === e.b) continue;
    const [a, b] = byText(e.a, e.b) < 0 ? [e.a, e.b] : [e.b, e.a];
    const key = `${a}~${b}`;
    const line = out.get(key) ?? { a, b, kinds: {}, total: 0 };
    line.kinds[e.kind] = (line.kinds[e.kind] ?? 0) + e.count;
    line.total += e.count;
    out.set(key, line);
  }
  return [...out.values()].sort((p, q) => byText(p.a, q.a) || byText(p.b, q.b));
}
