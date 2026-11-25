/**
 * The estate level of the network map: the backbone of hubs, data centers
 * and colocation sites drawn on a muted world map, with a branch count badge
 * on each.
 *
 * What is drawn is decided in pure modules and tested there: the major sites,
 * their lines, the badges, the "No hub" group and the ring positions in
 * backbone.ts; the first view, the spread of co-located sites and the label
 * collisions in estate.ts. This file is the SVG, the pan and zoom
 * (diagram/useCanvas.ts), the controls and the text alternative. A marker, a
 * badge, a ring and a label have a fixed size on the screen, so each is
 * stated in screen px times the user units per px at the current zoom.
 *
 * - A click on a major site or a shown branch selects it and fades the rest;
 *   a second click, or a double click, opens its diagram. A click on the
 *   background clears the selection.
 * - A click on a badge shows its branches on rings around the major site; a
 *   second click hides them. No major site moves. A ring that holds more than
 *   `RING_CAP` branches ends in an "and N more" pill, which lists them in the
 *   side panel.
 * - The "No hub" pill sits at the lower left corner of the view, and its ring
 *   opens upward from there.
 * - A major site with no coordinates is listed beside the map; it still
 *   counts in the model, and its lines are not drawn.
 *
 * The drawing is hidden from assistive technology; a list carries the same
 * actions, and it shows on the screen while it holds the keyboard focus.
 */

import { useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import type { SiteEdgeKind, SiteGraphPayload } from "../api/types";
import { project, WORLD_W, type Point } from "../diagram/projection";
import { KIND_LABEL, KIND_ORDER } from "../diagram/siteEdges";
import { useCanvas, type View } from "../diagram/useCanvas";
import { landPath } from "../diagram/world";
import {
  backbone,
  badgeOffset,
  branchLinks,
  majorsOf,
  ringPositions,
  RING_CAP,
  type BackboneEdge,
  type MajorClass,
} from "./backbone";
import { fitView, MAJOR_PX, spread, visibleLabels, type Box } from "./estate";

/** A badge's group: a major site code, or null for the "No hub" group. */
export type Group = string | null;

/** the narrowest view, in user units: a quarter degree, one metro */
const MIN_VIEW_W = 1;
/** the widest view: 1.25 times the world width */
const MAX_VIEW_W = WORLD_W * 1.25;
const ZOOM_STEP = 1.4;
/** the diameter of a shown branch, in screen px */
const BRANCH_PX = 9;
const LABEL_PX = 11;
const BRANCH_LABEL_PX = 9;
/** the estimated width of one character of a label, as a share of its size */
const CHAR_W = 0.6;
const PILL_H = 16;
/** where the "No hub" pill sits, from the lower left corner of the view */
const NOHUB_PX = { left: 96, bottom: 28 };
/** a pointer that moves farther than this between press and release panned */
const CLICK_SLOP = 4;
const UP: Point = { x: 0, y: -1 };

const CLASS_TEXT: Record<MajorClass, string> = { hub: "SD-WAN hub", dc: "data center", colo: "colocation" };

const pillWidth = (label: string) => 12 + label.length * LABEL_PX * CHAR_W;
const lineWidth = (total: number) => Math.min(1 + Math.log2(Math.max(total, 1)), 5);
const pairKey = (e: { a: string; b: string }) => `${e.a}~${e.b}`;

/** "4 cables, 2 fabric circuits": a line's count per kind. */
export function countText(kinds: BackboneEdge["kinds"]): string {
  return KIND_ORDER.filter((k) => kinds[k])
    .map((k) => `${kinds[k]} ${KIND_LABEL[k]}`)
    .join(", ");
}

interface Pill {
  id: string;
  label: string;
  at: Point;
  w: number;
}

interface Label {
  id: string;
  text: string;
  at: Point;
  anchor: "start" | "end" | "middle";
  size: number;
  box: Box;
}

export default function EstateMap({
  payload,
  kinds,
  selected,
  onSelect,
  onOpen,
  expanded,
  onExpanded,
  onList,
  initialView,
  onView,
}: {
  payload: SiteGraphPayload;
  kinds: ReadonlySet<SiteEdgeKind>;
  selected: string | null;
  onSelect: (code: string | null) => void;
  onOpen: (code: string) => void;
  /** the open badges: major site codes, and null for the "No hub" group */
  expanded: readonly Group[];
  onExpanded: (next: Group[]) => void;
  /** list a group's branches in the side panel; undefined closes the list */
  onList: (group: Group | undefined) => void;
  initialView?: View;
  onView: (view: View) => void;
}) {
  const model = useMemo(() => backbone(payload, kinds), [payload, kinds]);
  const placed = useMemo(
    () =>
      majorsOf(payload.sites)
        .filter((m) => m.site.lat !== null && m.site.lon !== null)
        .map((m) => ({ code: m.code, cls: m.cls, at: project(m.site.lat as number, m.site.lon as number) })),
    [payload],
  );
  const fit = useMemo(() => fitView(placed.map((p) => p.at)), [placed]);
  const { svg, view, viewBox, handlers, zoomBy, frameTo } = useCanvas(fit, {
    dragAttr: "data-none",
    passthrough: "[data-marker]",
    maxZoom: fit.w / MIN_VIEW_W,
    minZoom: fit.w / MAX_VIEW_W,
    initial: initialView,
  });
  const [size, setSize] = useState({ w: 1000, h: 500 });
  useEffect(() => {
    const el = svg.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => {
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) setSize({ w: rect.width, h: rect.height });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [svg]);
  useEffect(() => onView(view), [view, onView]);

  // the viewBox is drawn with "meet": the scale is that of the tighter side
  const ppu = Math.min(size.w / view.w, size.h / view.h);
  const u = 1 / ppu;
  const land = useMemo(() => landPath(), []);
  const names = useMemo(() => new Map(payload.sites.map((s) => [s.code, s.name || s.code])), [payload]);

  const { at, around } = useMemo(() => spread(placed, ppu), [placed, ppu]);
  const centroid = useMemo(() => {
    const points = [...at.values()];
    if (points.length === 0) return { x: 0, y: 0 };
    return {
      x: points.reduce((t, p) => t + p.x, 0) / points.length,
      y: points.reduce((t, p) => t + p.y, 0) / points.length,
    };
  }, [at]);
  /** the direction a site's badge and ring open: away from the mean of its
   *  spread group, or else from the mean of all major sites */
  const awayOf = (code: string): Point => {
    const p = at.get(code)!;
    const base = around.get(code) ?? centroid;
    return { x: p.x - base.x, y: p.y - base.y };
  };
  const toUnits = (center: Point, offsetPx: Point): Point => ({ x: center.x + offsetPx.x * u, y: center.y + offsetPx.y * u });

  const open = useMemo(
    () => expanded.filter((g) => (g === null ? model.orphans.length > 0 : model.badges.some((b) => b.major === g))),
    [expanded, model],
  );
  const links = useMemo(() => branchLinks(payload, kinds, open), [payload, kinds, open]);

  // the visible part of the view, for the "No hub" pill in its corner
  const visible = { w: size.w * u, h: size.h * u };
  const corner = { x: view.x + (view.w - visible.w) / 2, y: view.y + (view.h + visible.h) / 2 };
  const nohubAt = toUnits(corner, { x: NOHUB_PX.left, y: -NOHUB_PX.bottom });

  const badges: (Pill & { major: string })[] = model.badges
    .filter((b) => at.has(b.major))
    .map((b) => {
      const label = `+${b.count}`;
      return { id: b.major, major: b.major, label, w: pillWidth(label), at: toUnits(at.get(b.major)!, badgeOffset({ x: 0, y: 0 }, awayOf(b.major))) };
    });
  const nohubLabel = `No hub (${model.orphans.length})`;

  // the open rings: branch positions, and an "N more" pill per full ring
  const branchAt = new Map<string, Point>();
  const more: (Pill & { group: Group })[] = [];
  for (const group of open) {
    const branches = group === null ? model.orphans : model.badges.find((b) => b.major === group)?.branches;
    const center = group === null ? nohubAt : at.get(group);
    if (!branches || !center) continue;
    const capped = branches.length > RING_CAP;
    const ring = ringPositions({ x: 0, y: 0 }, group === null ? UP : awayOf(group), branches.length, BRANCH_PX);
    (capped ? branches.slice(0, RING_CAP - 1) : branches).forEach((code, i) => {
      if (!branchAt.has(code)) branchAt.set(code, toUnits(center, ring[i]));
    });
    if (capped) {
      const label = `${branches.length - (RING_CAP - 1)} more`;
      more.push({ id: group ?? "", group, label, w: pillWidth(label), at: toUnits(center, ring[RING_CAP - 1]) });
    }
  }
  const posOf = (code: string) => at.get(code) ?? branchAt.get(code);
  const lines = model.edges.filter((e) => at.has(e.a) && at.has(e.b));
  const dashed = links.filter((e) => posOf(e.a) && posOf(e.b));

  // what stays clear while a site is selected: the site and its neighbors
  const keep = new Set<string>();
  if (selected !== null) {
    keep.add(selected);
    for (const e of [...lines, ...dashed]) {
      if (e.a === selected) keep.add(e.b);
      if (e.b === selected) keep.add(e.a);
    }
  }
  const faded = (code: string) => selected !== null && !keep.has(code);
  const touches = (e: BackboneEdge) => e.a === selected || e.b === selected;
  const [hover, setHover] = useState<string | null>(null);

  // the labels, in priority order: the selection, the major sites, the branches
  const labels: Label[] = [];
  const obstacles: Box[] = [];
  const R = MAJOR_PX;
  for (const p of placed) {
    const q = at.get(p.code)!;
    obstacles.push({ id: p.code, owner: p.code, x: q.x * ppu - R, y: q.y * ppu - R, w: 2 * R, h: 2 * R });
  }
  for (const b of badges) {
    obstacles.push({ id: `badge:${b.id}`, owner: "", x: b.at.x * ppu - b.w / 2, y: b.at.y * ppu - PILL_H / 2, w: b.w, h: PILL_H });
  }
  for (const [code, q] of branchAt) {
    obstacles.push({ id: code, owner: code, x: q.x * ppu - BRANCH_PX / 2, y: q.y * ppu - BRANCH_PX / 2, w: BRANCH_PX, h: BRANCH_PX });
  }
  for (const p of placed) {
    const q = at.get(p.code)!;
    const hasBadge = badges.some((b) => b.major === p.code);
    // the label goes on the side away from the badge
    const left = hasBadge && awayOf(p.code).x > 0;
    const w = p.code.length * LABEL_PX * CHAR_W;
    const x = q.x * ppu + (left ? -(R + 4) - w : R + 4);
    labels.push({
      id: p.code,
      text: p.code,
      at: { x: q.x + (left ? -(R + 4) : R + 4) * u, y: q.y + 4 * u },
      anchor: left ? "end" : "start",
      size: LABEL_PX,
      box: { id: p.code, owner: p.code, x, y: q.y * ppu - LABEL_PX / 2 - 1, w, h: LABEL_PX + 2 },
    });
  }
  for (const [code, q] of branchAt) {
    const w = code.length * BRANCH_LABEL_PX * CHAR_W;
    const top = BRANCH_PX / 2 + 2;
    labels.push({
      id: code,
      text: code,
      at: { x: q.x, y: q.y + (top + BRANCH_LABEL_PX - 1) * u },
      anchor: "middle",
      size: BRANCH_LABEL_PX,
      box: { id: code, owner: code, x: q.x * ppu - w / 2, y: q.y * ppu + top, w, h: BRANCH_LABEL_PX + 2 },
    });
  }
  const first = labels.findIndex((l) => l.id === selected);
  if (first > 0) labels.unshift(...labels.splice(first, 1));
  const shownLabels = visibleLabels(
    labels.map((l) => l.box),
    obstacles,
  );

  const toggle = (group: Group) => {
    const opening = !open.includes(group);
    onExpanded(opening ? [...open, group] : open.filter((g) => g !== group));
    if (group === null) onList(opening ? null : undefined);
  };
  const pick = (code: string) => (selected === code ? onOpen(code) : onSelect(code));

  // a press that turns into a pan is not a click on the background
  const down = useRef<Point | null>(null);
  const target = (e: MouseEvent) => {
    const el = (e.target as Element).closest("[data-marker]");
    return el ? { kind: el.getAttribute("data-marker"), code: el.getAttribute("data-code") ?? "" } : null;
  };
  const onClick = (e: MouseEvent<SVGSVGElement>) => {
    const hit = target(e);
    if (!hit) {
      const start = down.current;
      if (!start || Math.hypot(e.clientX - start.x, e.clientY - start.y) <= CLICK_SLOP) onSelect(null);
      return;
    }
    if (hit.kind === "site") pick(hit.code);
    else if (hit.kind === "badge") toggle(hit.code);
    else if (hit.kind === "nohub") toggle(null);
    else if (hit.kind === "more") onList(hit.code === "" ? null : hit.code);
  };
  const onDoubleClick = (e: MouseEvent<SVGSVGElement>) => {
    const hit = target(e);
    if (hit?.kind === "site") onOpen(hit.code);
  };

  const marker = (code: string, cls: MajorClass, q: Point) => {
    const r = R * u;
    const d = r * 1.3;
    return (
      <g
        key={code}
        data-marker="site"
        data-code={code}
        className={`nm-major nm-major-${cls}` + (code === selected ? " selected" : "") + (faded(code) ? " faded" : "")}
        transform={`translate(${q.x} ${q.y})`}
      >
        {cls === "hub" && <circle r={r} />}
        {cls === "dc" && <rect x={-r} y={-r} width={2 * r} height={2 * r} rx={2.5 * u} />}
        {cls === "colo" && <polygon points={`0,${-d} ${d},0 0,${d} ${-d},0`} />}
      </g>
    );
  };
  const pill = (kind: string, code: string, p: Pill, className: string) => (
    <g key={`${kind}:${p.id}`} data-marker={kind} data-code={code} className={className} transform={`translate(${p.at.x} ${p.at.y})`}>
      <rect x={(-p.w / 2) * u} y={(-PILL_H / 2) * u} width={p.w * u} height={PILL_H * u} rx={(PILL_H / 2) * u} />
      <text fontSize={LABEL_PX * u} dy={4 * u} textAnchor="middle">
        {p.label}
      </text>
    </g>
  );

  const unplaced = model.majors.filter((m) => !at.has(m.code));
  const pickButton = (code: string, label: string) => (
    <button type="button" aria-pressed={selected === code} onClick={() => pick(code)}>
      {label}
    </button>
  );
  const ringList = (group: Group, branches: string[]) =>
    open.includes(group) && (
      <ul>
        {branches.slice(0, branches.length > RING_CAP ? RING_CAP - 1 : branches.length).map((code) => (
          <li key={code}>{pickButton(code, `${names.get(code) ?? code}, branch`)}</li>
        ))}
        {branches.length > RING_CAP && (
          <li>
            <button type="button" onClick={() => onList(group)}>
              {branches.length - (RING_CAP - 1)} more
            </button>
          </li>
        )}
      </ul>
    );
  const branchText = (n: number) => (n === 1 ? "1 branch" : `${n} branches`);

  return (
    <div className="nm-stage">
      <svg
        ref={svg}
        className="nm-estate"
        viewBox={viewBox}
        preserveAspectRatio="xMidYMid meet"
        aria-hidden="true"
        {...handlers}
        onPointerDown={(e) => {
          down.current = { x: e.clientX, y: e.clientY };
          handlers.onPointerDown(e);
        }}
        onPointerOver={(e) => setHover((e.target as Element).closest("[data-line]")?.getAttribute("data-line") ?? null)}
        onPointerOut={() => setHover(null)}
        onClick={onClick}
        onDoubleClick={onDoubleClick}
      >
        <path className="nm-land" d={land} />
        {lines.map((e) => {
          const a = at.get(e.a)!;
          const b = at.get(e.b)!;
          const key = pairKey(e);
          const cls = "nm-bb-line" + (touches(e) ? " selected" : selected !== null ? " faded" : "");
          return (
            <g key={key} data-line={key} className={cls}>
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} strokeWidth={lineWidth(e.total) * u} />
              <line className="nm-hit" x1={a.x} y1={a.y} x2={b.x} y2={b.y} strokeWidth={12 * u} />
            </g>
          );
        })}
        {dashed.map((e) => {
          const a = posOf(e.a)!;
          const b = posOf(e.b)!;
          return (
            <line
              key={pairKey(e)}
              className={"nm-branch-link" + (touches(e) ? " selected" : selected !== null ? " faded" : "")}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              strokeWidth={0.8 * u}
              strokeDasharray={`${3 * u} ${3 * u}`}
            />
          );
        })}
        {placed.map((p) => marker(p.code, p.cls, at.get(p.code)!))}
        {[...branchAt].map(([code, q]) => (
          <g
            key={code}
            data-marker="site"
            data-code={code}
            className={"nm-branch" + (code === selected ? " selected" : "") + (faded(code) ? " faded" : "")}
            transform={`translate(${q.x} ${q.y})`}
          >
            <circle r={(BRANCH_PX / 2) * u} />
          </g>
        ))}
        {badges.map((b) =>
          pill(
            "badge",
            b.major,
            b,
            "nm-badge" + (open.includes(b.major) ? " open" : "") + (selected !== null && b.major !== selected ? " faded" : ""),
          ),
        )}
        {model.orphans.length > 0 &&
          pill(
            "nohub",
            "",
            { id: "nohub", label: nohubLabel, w: pillWidth(nohubLabel), at: nohubAt },
            "nm-nohub" + (open.includes(null) ? " open" : "") + (selected !== null && !model.orphans.includes(selected) ? " faded" : ""),
          )}
        {more.map((m) => pill("more", m.group ?? "", m, "nm-badge nm-more"))}
        <g className="nm-labels">
          {labels
            .filter((l) => shownLabels.has(l.id))
            .map((l) => (
              <text
                key={l.id}
                className={"nm-label" + (faded(l.id) ? " faded" : "")}
                x={l.at.x}
                y={l.at.y}
                fontSize={l.size * u}
                textAnchor={l.anchor}
              >
                {l.text}
              </text>
            ))}
          {lines
            .filter((e) => hover === pairKey(e) || touches(e))
            .map((e) => {
              const a = at.get(e.a)!;
              const b = at.get(e.b)!;
              return (
                <text
                  key={pairKey(e)}
                  className="nm-line-label"
                  x={(a.x + b.x) / 2}
                  y={(a.y + b.y) / 2 - 4 * u}
                  fontSize={LABEL_PX * u}
                  textAnchor="middle"
                >
                  {countText(e.kinds)}
                </text>
              );
            })}
        </g>
      </svg>
      {unplaced.length > 0 && (
        <section className="nm-offmap" aria-label="Not on the map">
          <h3>Not on the map</h3>
          <ul>
            {unplaced.map((m) => {
              const badge = model.badges.find((b) => b.major === m.code);
              return (
                <li key={m.code}>
                  <button type="button" className="linkish" aria-pressed={selected === m.code} onClick={() => pick(m.code)}>
                    {m.code}
                  </button>
                  <span className="nm-branch-note">
                    {CLASS_TEXT[m.cls]}
                    {badge ? `, ${branchText(badge.count)}` : ""}
                  </span>
                </li>
              );
            })}
          </ul>
        </section>
      )}
      <div className="nm-zoom" role="group" aria-label="Zoom">
        <button type="button" onClick={() => zoomBy(ZOOM_STEP)} aria-label="Zoom in">+</button>
        <button type="button" onClick={() => zoomBy(1 / ZOOM_STEP)} aria-label="Zoom out">-</button>
        <button type="button" onClick={() => frameTo(fit)}>Fit</button>
      </div>
      <section className="nm-sr" aria-label="Estate list">
        <h3>Major sites</h3>
        <ul>
          {model.majors.map((m) => {
            const badge = model.badges.find((b) => b.major === m.code);
            return (
              <li key={m.code}>
                {pickButton(m.code, `${names.get(m.code) ?? m.code}, ${CLASS_TEXT[m.cls]}`)}
                {badge && (
                  <>
                    {" "}
                    <button type="button" aria-expanded={open.includes(m.code)} onClick={() => toggle(m.code)}>
                      Show {branchText(badge.count)} of {m.code}
                    </button>
                    {ringList(m.code, badge.branches)}
                  </>
                )}
              </li>
            );
          })}
        </ul>
        <h3>Backbone links</h3>
        <ul>
          {model.edges.map((e) => (
            <li key={pairKey(e)}>
              {e.a} to {e.b}: {countText(e.kinds)}
            </li>
          ))}
          {model.edges.length === 0 && <li>No backbone links</li>}
        </ul>
        {model.orphans.length > 0 && (
          <>
            <h3>No hub</h3>
            <button type="button" aria-expanded={open.includes(null)} onClick={() => toggle(null)}>
              Show {branchText(model.orphans.length)} with no hub
            </button>
            {ringList(null, model.orphans)}
          </>
        )}
      </section>
    </div>
  );
}
