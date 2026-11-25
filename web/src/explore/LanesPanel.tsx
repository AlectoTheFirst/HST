/** The boxes are one tab stop. */

import { useEffect, useId, useRef, useState } from "react";
import type { GraphNode } from "../api/types";
import { captionFull } from "./graphElements";
import { slotColor, type Palette } from "./graphStyle";
import { BOX_H2, BOX_W, CAPTION_CUT, cutMiddle, DEFAULT_WIDTH, laneStep, MEMBER_H, MEMBER_MAX, shapePath, sideStep, type Picture, type PictureDir } from "./lanes";
import { LabelChip } from "./slotMark";
import "./lanes.css";

const MARK = 12;

const DIRS: ReadonlyArray<readonly [PictureDir, string]> = [["tb", "Top down"], ["lr", "Left to right"]];

export function LanesPanel({ pic, nodes, focus, title, palette, onDir, onWidth, onToggleGroup, onFocus, onOpen }: {
  pic: Picture;
  nodes: ReadonlyMap<string, GraphNode>;
  focus: string | null;
  title: string;
  palette: Palette;
  onDir: (dir: PictureDir) => void;
  /** The width of the drawing area, for the top-down layout. */
  onWidth: (width: number) => void;
  onToggleGroup: (id: string) => void;
  onFocus: (id: string | null) => void;
  onOpen: (uid: string) => void;
}) {
  // ids from useId hold colons, which a url(#...) reference cannot carry
  const base = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const [cursor, setCursor] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const measure = () => onWidth(Math.floor(el.clientWidth) || DEFAULT_WIDTH);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [onWidth]);
  const focusBox = focus !== null ? (pic.itemOf.get(focus) ?? null) : null;
  const at = cursor !== null && pic.items.some((n) => n.id === cursor) ? cursor : (focusBox ?? pic.items[0]?.id ?? null);
  const domId = (id: string) => `${base}-n${pic.items.findIndex((n) => n.id === id)}`;
  const uidOf = (id: string) => {
    const uid = nodes.get(id)?.properties.uid;
    return typeof uid === "string" && uid ? uid : null;
  };
  const near = new Set<string>(focusBox ? [focusBox] : []);
  for (const e of pic.edges) {
    if (e.from === focusBox) near.add(e.to);
    if (e.to === focusBox) near.add(e.from);
  }


  function activate(id: string) {
    setCursor(id);
    if (pic.items.find((n) => n.id === id)?.kind === "group") onToggleGroup(id);
    else onFocus(focus === id ? null : id);
  }

  function onKeyDown(e: React.KeyboardEvent) {
    if (at === null) return;
    let next: string | null = null;
    // inside a line, and across the lines
    const [inPrev, inNext, acPrev, acNext] = pic.dir === "tb" ? ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"] : ["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"];
    if (e.key === inPrev) next = laneStep(pic, at, -1);
    else if (e.key === inNext) next = laneStep(pic, at, 1);
    else if (e.key === acPrev) next = sideStep(pic, at, -1);
    else if (e.key === acNext) next = sideStep(pic, at, 1);
    else if (e.key === " ") {
      e.preventDefault();
      activate(at);
      return;
    } else if (e.key === "Enter") {
      e.preventDefault();
      const uid = uidOf(at);
      if (uid) onOpen(uid);
      return;
    } else return;
    e.preventDefault();
    if (next !== null) setCursor(next);
  }

  const legend = [...new Map(pic.items.map((n) => [n.label, n.slot])).entries()].sort((a, b) => a[1] - b[1]);
  const labelled = new Set<string>();

  return (
    <section className="lanes" aria-label="Selection picture">
      <div className="lanes-head">
        <h3 className="eyebrow">Selection picture</h3>
        <span className="lanes-title">{title}</span>
      </div>
      <div className="lanes-bar">
        <div className="lanes-legend">
          {legend.map(([label, slot]) => (
            <LabelChip key={label} label={label} slot={slot} palette={palette} />
          ))}
        </div>
        <div className="segs" role="group" aria-label="Picture direction">
          {DIRS.map(([d, label]) => (
            <button key={d} type="button" aria-pressed={pic.dir === d} className={pic.dir === d ? "on" : ""} onClick={() => onDir(d)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="lanes-scroll" ref={scrollRef}>
        {pic.items.length > 0 && (
          <svg
            width={pic.width}
            height={pic.height}
            viewBox={`0 0 ${pic.width} ${pic.height}`}
            role="group"
            aria-label={`Selection picture: ${pic.items.length} boxes and ${pic.edges.length} links`}
            tabIndex={0}
            aria-activedescendant={at !== null ? domId(at) : undefined}
            onKeyDown={onKeyDown}
            className={focusBox ? "lanes-svg lanes-faded" : "lanes-svg"}
          >
            {pic.layers.map((layer) => (
              <text key={layer.name} x={layer.x} y={layer.y} textAnchor={layer.anchor} className="lanes-lane">
                {layer.name}
              </text>
            ))}
            {pic.edges.map((edge) => {
              const on = focusBox !== null && (edge.from === focusBox || edge.to === focusBox);
              const key = `${edge.type}|${on ? "on" : edge.count > 1 ? edge.id : ""}`;
              const label = (on || edge.count > 1) && !labelled.has(key);
              if (label) labelled.add(key);
              return (
                <g key={edge.id} className={on ? "lanes-edge on" : "lanes-edge"}>
                  <path d={edge.d} fill="none" stroke={on ? palette.accent : palette.line} strokeWidth={edge.count > 1 ? 2.4 : on ? 1.8 : 1.2}>
                    <title>{edge.count > 1 ? `${edge.type}, ${edge.count}` : edge.type}</title>
                  </path>
                  {label && (
                    <text x={edge.lx} y={edge.ly - 4} textAnchor="middle" className="lanes-edgelabel">
                      {edge.count > 1 ? `${edge.type} x${edge.count}` : edge.type}
                    </text>
                  )}
                </g>
              );
            })}
            {pic.items.map((n) => {
              const color = slotColor(palette, n.slot);
              const focused = n.id === focusBox;
              const other = n.slot >= 8;
              const className = ["lanes-node", n.id === at ? "cursor" : "", focused ? "focused" : "", near.has(n.id) ? "near" : ""].filter(Boolean).join(" ");
              if (n.kind === "group") {
                const members = n.members ?? [];
                return (
                  <g
                    key={n.id}
                    id={domId(n.id)}
                    role="button"
                    aria-expanded={n.open}
                    aria-label={`${n.caption}${n.seed ? ", selected" : ""}`}
                    transform={`translate(${n.x},${n.y})`}
                    className={className}
                    onClick={() => activate(n.id)}
                  >
                    <rect width={BOX_W} height={n.h} rx={5} fill={focused ? palette.panel2 : palette.panel} stroke={focused ? palette.accent : color} strokeWidth={focused ? 2.5 : 1.6} />
                    <path d={shapePath(n.slot, MARK)} transform="translate(8,8)" fill={other ? "none" : color} stroke={other ? palette.muted : "none"} />
                    <text x={26} y={19} className="lanes-count">{n.caption}</text>
                    <text x={26} y={33} className="lanes-owner">{n.open ? "[-]" : "[+]"}</text>
                    {n.open &&
                      members.slice(0, MEMBER_MAX).map((id, j) => {
                        const node = nodes.get(id);
                        const caption = node ? captionFull(node) : id;
                        const on = focus === id;
                        return (
                          <g
                            key={id}
                            className={on ? "lanes-member on" : "lanes-member"}
                            onClick={(e) => {
                              e.stopPropagation();
                              setCursor(n.id);
                              onFocus(on ? null : id);
                            }}
                          >
                            {on && <rect x={3} y={BOX_H2 + j * MEMBER_H} width={BOX_W - 6} height={MEMBER_H} rx={2} className="lanes-memberhit" />}
                            <text x={12} y={BOX_H2 + j * MEMBER_H + 12}>
                              <title>{caption}</title>
                              {cutMiddle(caption, CAPTION_CUT + 2)}
                            </text>
                          </g>
                        );
                      })}
                    {n.open && members.length > MEMBER_MAX && (
                      <text x={12} y={BOX_H2 + MEMBER_MAX * MEMBER_H + 12} className="lanes-owner">
                        {members.length - MEMBER_MAX} more
                      </text>
                    )}
                  </g>
                );
              }
              return (
                <g
                  key={n.id}
                  id={domId(n.id)}
                  role="button"
                  aria-pressed={focused}
                  aria-label={`${n.full}${n.second ? ` on ${n.second}` : ""}, ${n.label}, layer ${n.layer}${n.seed ? ", selected" : ""}`}
                  transform={`translate(${n.x},${n.y})`}
                  className={className}
                  onClick={() => activate(n.id)}
                  onDoubleClick={() => {
                    const uid = uidOf(n.id);
                    if (uid) onOpen(uid);
                  }}
                >
                  <rect
                    width={BOX_W}
                    height={n.h}
                    rx={5}
                    fill={focused ? palette.panel2 : palette.panel}
                    stroke={focused ? palette.accent : color}
                    strokeWidth={focused ? 2.5 : n.seed ? 1.6 : 1}
                    strokeDasharray={n.seed || focused ? undefined : "4 3"}
                  />
                  <path
                    d={shapePath(n.slot, MARK)}
                    transform={`translate(8,${n.second ? 7 : (n.h - MARK) / 2})`}
                    fill={other ? "none" : color}
                    stroke={other ? palette.muted : "none"}
                    strokeDasharray={other ? "2 2" : undefined}
                  />
                  <text x={26} y={n.second ? 18 : n.h / 2 + 4} className="lanes-caption">
                    <title>{n.full}</title>
                    {n.caption}
                  </text>
                  {n.second && (
                    <text x={26} y={33} className="lanes-owner">
                      {n.second}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        )}
      </div>
    </section>
  );
}
