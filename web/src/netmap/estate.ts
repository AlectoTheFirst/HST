/**
 * The estate level of the network map, without a DOM: the site classes, and
 * the geometry of the backbone on the world map. What the backbone holds (the
 * major sites, their lines, the badges, the "No hub" group, the rings) is
 * decided in backbone.ts.
 *
 * - A marker has a fixed size on the screen, so the page converts it to user
 *   units at each zoom; nothing here grows with the zoom.
 * - Major sites nearer than `SPREAD_PX` on the screen are spread on a small
 *   circle around their mean, in code point order.
 * - Labels are placed in priority order, and a label that would cover a
 *   marker, a badge or an earlier label is hidden.
 *
 * Pure and deterministic: the same sites and zoom give the same picture.
 */

import type { SiteEdgeKind, SiteGraphSite } from "../api/types";
import { WORLD_H, WORLD_W, type Point } from "../diagram/projection";
import type { View } from "../diagram/useCanvas";

export type SiteClass = "hub" | "dc" | "colo" | "branch";

export const DEFAULT_KINDS: ReadonlySet<SiteEdgeKind> = new Set(["cable", "circuit", "tunnel"]);

/** What a site is drawn as: a hub when it holds an SD-WAN hub, a data center
 *  when it holds a spine or a leaf, a colocation site when the graph says so. */
export function siteClass(site: Pick<SiteGraphSite, "kind" | "tiers">): SiteClass {
  const tiers = site.tiers ?? {};
  if (tiers["sdwan-hub"]) return "hub";
  if (tiers.spine || tiers.leaf || site.kind === "dc") return "dc";
  if (site.kind === "colo") return "colo";
  return "branch";
}

/** Code point order, independent of the locale. */
export const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export const MAJOR: ReadonlySet<SiteClass> = new Set(["hub", "dc", "colo"]);
export const CLASS_ORDER: Record<SiteClass, number> = { hub: 0, dc: 1, colo: 2, branch: 3 };

/** the radius of a major site's marker on the screen, in px */
export const MAJOR_PX = 7;
/** major sites nearer than this on the screen are spread apart: 2.5 marker
 *  diameters */
export const SPREAD_PX = 2.5 * 2 * MAJOR_PX;
/** the smallest width of the first view, in user units: 12 degrees of
 *  longitude */
export const MIN_FIT_W = 48;
/** the margin around the major sites in the first view, as a share of their
 *  extent on each side */
const FIT_PAD = 0.15;

/** The first view: the major sites with a margin, at least `MIN_FIT_W` wide,
 *  at 2:1 as the world is. With no placed site, the whole world. */
export function fitView(points: readonly Point[]): View {
  if (points.length === 0) return { x: 0, y: 0, w: WORLD_W, h: WORLD_H };
  const xs = points.map((p) => p.x);
  const ys = points.map((p) => p.y);
  const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
  let w = Math.max((x1 - x0) * (1 + 2 * FIT_PAD), MIN_FIT_W);
  let h = (y1 - y0) * (1 + 2 * FIT_PAD);
  if (w / 2 < h) w = h * 2;
  else h = w / 2;
  return { x: (x0 + x1) / 2 - w / 2, y: (y0 + y1) / 2 - h / 2, w, h };
}

export interface Spread {
  /** where each site is drawn */
  at: Map<string, Point>;
  /** the mean of each spread group, for its members only: a badge and a ring
   *  open away from it */
  around: Map<string, Point>;
}

/** The drawn positions of the major sites at a zoom of `pxPerUnit` screen px
 *  per user unit. Sites nearer than `SPREAD_PX`, directly or through a chain
 *  of near sites, form one group; a group of 2 or more is drawn on a circle
 *  around its mean, one `SPREAD_PX` from neighbor to neighbor, starting at the
 *  top and going clockwise in code point order. */
export function spread(sites: ReadonlyArray<{ code: string; at: Point }>, pxPerUnit: number): Spread {
  const reach = SPREAD_PX / pxPerUnit;
  const order = [...sites].sort((p, q) => byText(p.code, q.code));
  const parent = order.map((_, i) => i);
  const root = (i: number): number => (parent[i] === i ? i : (parent[i] = root(parent[i])));
  for (let i = 0; i < order.length; i++) {
    for (let j = i + 1; j < order.length; j++) {
      const d = Math.hypot(order[i].at.x - order[j].at.x, order[i].at.y - order[j].at.y);
      if (d < reach) parent[root(j)] = root(i);
    }
  }
  const groups = new Map<number, number[]>();
  order.forEach((_, i) => groups.set(root(i), [...(groups.get(root(i)) ?? []), i]));
  const at = new Map<string, Point>();
  const around = new Map<string, Point>();
  for (const members of groups.values()) {
    if (members.length === 1) {
      at.set(order[members[0]].code, order[members[0]].at);
      continue;
    }
    const n = members.length;
    const mean = {
      x: members.reduce((t, i) => t + order[i].at.x, 0) / n,
      y: members.reduce((t, i) => t + order[i].at.y, 0) / n,
    };
    // the radius whose chord between neighbors is one reach
    const r = reach / (2 * Math.sin(Math.PI / n));
    members.forEach((i, k) => {
      const a = -Math.PI / 2 + (2 * Math.PI * k) / n;
      at.set(order[i].code, { x: mean.x + r * Math.cos(a), y: mean.y + r * Math.sin(a) });
      around.set(order[i].code, mean);
    });
  }
  return { at, around };
}

/** A box on the screen, in px. `owner` names the marker a label belongs to,
 *  so a label never collides with its own marker. */
export interface Box {
  id: string;
  owner: string;
  x: number;
  y: number;
  w: number;
  h: number;
}

const overlaps = (p: Box, q: Box) => p.x < q.x + q.w && q.x < p.x + p.w && p.y < q.y + q.h && q.y < p.y + p.h;

/** The labels to show: in the order given, each label that covers no
 *  obstacle of another owner and no label shown before it. The first label
 *  is the most important one and always shows. */
export function visibleLabels(labels: readonly Box[], obstacles: readonly Box[]): Set<string> {
  const shown: Box[] = [];
  for (const [i, label] of labels.entries()) {
    const blocked =
      i > 0 &&
      (obstacles.some((o) => o.owner !== label.owner && overlaps(o, label)) || shown.some((s) => overlaps(s, label)));
    if (!blocked) shown.push(label);
  }
  return new Set(shown.map((s) => s.id));
}
