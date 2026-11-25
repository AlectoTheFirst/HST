/** The SVG is 1 tab stop with a roving tabindex over the boxes. */

import { useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import type { Leg, PathResponse } from "../api/types";
import { hopMtuMark } from "./MtuPanel";
import { MONO_KINDS, kindColor, kindVar, truncate } from "./hopStyle";
import { isGate } from "./gate";
import {
  boxOfHop,
  buildPathGraph,
  pathVia,
  selectedLanes,
  type GraphBox,
  type GraphDirection,
  type HopDetail,
  type PathGraph,
} from "./pathGraph";
import type { Selection } from "./selection";
import { VERDICT_WORD, legOutcome, legWord } from "./verdict";

interface Metrics {
  boxW: number;
  boxH: number;
  /** The step from 1 box of a path to the next. */
  along: number;
  /** The step between 2 tracks. */
  across: number;
}

function metrics(detail: HopDetail, direction: GraphDirection): Metrics {
  if (direction === "tb") {
    return detail === "all"
      ? { boxW: 156, boxH: 30, along: 54, across: 182 }
      : { boxW: 176, boxH: 40, along: 74, across: 202 };
  }
  return detail === "all"
    ? { boxW: 124, boxH: 30, along: 158, across: 44 }
    : { boxW: 150, boxH: 40, along: 204, across: 60 };
}

/** Room for the ECMP badge above the top row and the frame inset. */
const PAD = 12;
/** Pointer movement in px before a press becomes a pan, not a click. */
const PAN_START = 4;

export function pathsText(lanes: readonly number[]): string {
  return `${lanes.length === 1 ? "path" : "paths"} ${lanes.map((l) => l + 1).join(", ")}`;
}

/** The word under the box of a lane's last hop: delivered, or the walk's word. */
function endWord(box: GraphBox, legByLane: Map<number, Leg>): string | null {
  const legs = box.ends.map((l) => legByLane.get(l)).filter((l): l is Leg => !!l);
  const leg = legs.find((l) => legOutcome(l) === box.endOutcome) ?? legs[0];
  if (!leg) return null;
  return legOutcome(leg) === "ok" && leg.delivered ? "delivered" : legWord(leg);
}

function SubLine({
  box,
  x,
  y,
  width,
  legByLane,
}: {
  box: GraphBox;
  x: number;
  y: number;
  width: number;
  legByLane: Map<number, Leg>;
}) {
  const hop = box.hop;
  if (box.verdict) {
    const word = VERDICT_WORD[box.verdict];
    const rest = hop.note ? truncate(hop.note, width - (word.length + 3) * 6.4) : "";
    return (
      <text className="pg-sub" x={x} y={y}>
        <tspan className={"pg-verdict " + box.verdict}>{word}</tspan>
        {rest && `, ${rest}`}
      </text>
    );
  }
  const end = box.endOutcome ? endWord(box, legByLane) : null;
  if (end) {
    return (
      <text className="pg-sub" x={x} y={y}>
        <tspan className={"pg-end " + box.endOutcome}>{truncate(end, width)}</tspan>
      </text>
    );
  }
  return (
    <text className="pg-sub" x={x} y={y}>
      {truncate(hop.note || hop.kind, width)}
    </text>
  );
}

function neighbour(graph: PathGraph, box: GraphBox, key: string, direction: GraphDirection): GraphBox | undefined {
  const near = (keys: string[]) =>
    keys
      .map((k) => graph.byKey.get(k)!)
      .sort((a, b) => Math.abs(a.row - box.row) - Math.abs(b.row - box.row))[0];
  const [fwd, back, next, prev] =
    direction === "tb"
      ? ["ArrowDown", "ArrowUp", "ArrowRight", "ArrowLeft"]
      : ["ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp"];
  if (key === fwd) return near(box.out);
  if (key === back) return near(box.in);
  const column = graph.boxes.filter((b) => b.col === box.col).sort((a, b) => a.row - b.row);
  const i = column.indexOf(box);
  if (key === next) return column[i + 1];
  if (key === prev) return column[i - 1];
  return undefined;
}

export function PathGraphView({
  result,
  selection,
  onSelect,
  onClear,
  detail = "devices",
  direction = "tb",
}: {
  result: PathResponse;
  selection: Selection | null;
  onSelect: (selection: Selection) => void;
  /** Clears the selection (Esc, or a second click on the selected item). */
  onClear?: () => void;
  detail?: HopDetail;
  direction?: GraphDirection;
}) {
  const graph = useMemo(() => buildPathGraph(result, detail), [result, detail]);
  const [cursor, setCursor] = useState<string | null>(null);
  const boxEls = useRef(new Map<string, SVGGElement>());
  const pan = useRef<{ x: number; y: number; left: number; top: number; moved: boolean } | null>(null);
  const panned = useRef(false);

  function onPointerDown(e: PointerEvent<HTMLDivElement>) {
    if (e.button !== 0) return;
    panned.current = false;
    const el = e.currentTarget;
    pan.current = { x: e.clientX, y: e.clientY, left: el.scrollLeft, top: el.scrollTop, moved: false };
  }

  function onPointerMove(e: PointerEvent<HTMLDivElement>) {
    const p = pan.current;
    if (!p) return;
    const dx = e.clientX - p.x;
    const dy = e.clientY - p.y;
    const el = e.currentTarget;
    if (!p.moved) {
      if (Math.hypot(dx, dy) < PAN_START) return;
      p.moved = true;
      el.classList.add("panning");
      el.setPointerCapture?.(e.pointerId);
    }
    el.scrollLeft = p.left - dx;
    el.scrollTop = p.top - dy;
  }

  function onPointerUp(e: PointerEvent<HTMLDivElement>) {
    if (!pan.current) return;
    panned.current = pan.current.moved;
    pan.current = null;
    e.currentTarget.classList.remove("panning");
  }

  if (!result.hops.length) {
    return (
      <div className="ribbon-outer">
        <div className="ribbon-empty">{result.detail || "no path to draw"}</div>
      </div>
    );
  }

  const tb = direction === "tb";
  const m = metrics(detail, direction);
  const legByLane = new Map(result.legs.map((l) => [l.lane, l]));
  const legs = [...result.legs].sort((a, b) => a.lane - b.lane);
  const sourcesDiffer = new Set(legs.map((l) => l.src_label)).size > 1;
  const lanesOn = selectedLanes(graph, selection);
  const selectedKey = selection?.type === "hop" ? boxOfHop(graph, selection.data)?.key : undefined;
  const focusKey = cursor && graph.byKey.has(cursor) ? cursor : graph.boxes[0]?.key;

  const steps = Math.max(0, graph.cols - 1);
  const tracks = Math.max(0, graph.rows - 1);
  const width = Math.ceil(PAD * 2 + (tb ? tracks * m.across : steps * m.along) + m.boxW);
  const height = Math.ceil(PAD * 2 + (tb ? steps * m.along : tracks * m.across) + m.boxH);
  const px = (b: GraphBox) => PAD + (tb ? b.row * m.across : b.col * m.along);
  const py = (b: GraphBox) => PAD + (tb ? b.col * m.along : b.row * m.across);

  // each link leaves and enters a box at its own point, in the order of the box at the other end
  const outsOf = new Map<string, string[]>();
  const insOf = new Map<string, string[]>();
  for (const link of graph.links) {
    if (!outsOf.has(link.from)) outsOf.set(link.from, []);
    if (!insOf.has(link.to)) insOf.set(link.to, []);
    outsOf.get(link.from)!.push(link.to);
    insOf.get(link.to)!.push(link.from);
  }
  const byRow = (a: string, b: string) => graph.byKey.get(a)!.row - graph.byKey.get(b)!.row;
  for (const list of [...outsOf.values(), ...insOf.values()]) list.sort(byRow);
  const side = tb ? m.boxW : m.boxH;
  const port = (list: string[], key: string) =>
    list.length < 2 ? 0 : (list.indexOf(key) - (list.length - 1) / 2) * Math.min(tb ? 28 : 9, side / (list.length + 1));
  const on = (lanes: readonly number[]) => !!lanesOn && lanes.some((l) => lanesOn.has(l));
  const outcome = (lane: number) => {
    const leg = legByLane.get(lane);
    return leg ? legOutcome(leg) : "ok";
  };

  function selectBox(box: GraphBox) {
    if (selectedKey === box.key && onClear) onClear();
    else onSelect({ type: "hop", data: box.hop });
  }

  function selectLeg(leg: Leg) {
    if (selection?.type === "leg" && selection.data.lane === leg.lane && onClear) onClear();
    else onSelect({ type: "leg", data: leg });
  }

  function onBoxKey(e: KeyboardEvent<SVGGElement>, box: GraphBox) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      selectBox(box);
      return;
    }
    if (e.key === "Escape") {
      onClear?.();
      return;
    }
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(e.key)) return;
    e.preventDefault();
    const next = neighbour(graph, box, e.key, direction);
    if (!next) return;
    setCursor(next.key);
    boxEls.current.get(next.key)?.focus();
  }

  const labels: { key: string; x: number; y: number; anchor: "start" | "middle"; text: string }[] = [];

  return (
    <div className="pg-outer">
      {legs.length > 0 && (
        <div className="pg-paths" role="group" aria-label="Paths">
          {legs.map((leg) => {
            const via = pathVia(graph, leg.lane);
            const pressed = selection?.type === "leg" && selection.data.lane === leg.lane;
            return (
              <button
                key={leg.lane}
                type="button"
                className="pg-path"
                aria-pressed={pressed}
                onClick={() => selectLeg(leg)}
              >
                <span className="pg-pn">Path {leg.lane + 1}</span>
                <span className="pg-via">
                  {sourcesDiffer && <span className="pg-src">{leg.src_label}</span>}
                  {via.length > 0 && <span>via {via.join(", ")}</span>}
                </span>
                <span className={"pg-pill " + legOutcome(leg)} title={leg.detail}>
                  {legWord(leg)}
                </span>
              </button>
            );
          })}
        </div>
      )}
      <div
        className="pg-scroll"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onClickCapture={(e) => {
          if (!panned.current) return;
          panned.current = false;
          e.stopPropagation();
        }}
      >
        <svg
          className={"pg-svg" + (lanesOn ? " faded" : "")}
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          role="group"
          aria-label="Path graph"
        >
          <g>
            {graph.links.map((link) => {
              const a = graph.byKey.get(link.from)!;
              const b = graph.byKey.get(link.to)!;
              const po = port(outsOf.get(a.key)!, b.key);
              const pi = port(insOf.get(b.key)!, a.key);
              const skip = b.col - a.col > 1;
              let d: string;
              let label: { x: number; y: number; anchor: "start" | "middle" };
              if (tb) {
                const x1 = px(a) + m.boxW / 2 + po;
                const y1 = py(a) + m.boxH;
                const x2 = px(b) + m.boxW / 2 + pi;
                const y2 = py(b);
                const my = (y1 + y2) / 2;
                // a link over empty steps runs straight on its track, then turns into the box
                d = skip
                  ? `M${x1} ${y1} L${x1} ${y2 - 30} C${x1} ${y2 - 10}, ${x2} ${y2 - 20}, ${x2} ${y2}`
                  : `M${x1} ${y1} C${x1} ${my}, ${x2} ${my}, ${x2} ${y2}`;
                label = { x: x1 + 6, y: y1 + (m.along - m.boxH) / 2 + 3, anchor: "start" };
              } else {
                const x1 = px(a) + m.boxW;
                const y1 = py(a) + m.boxH / 2 + po;
                const x2 = px(b);
                const y2 = py(b) + m.boxH / 2 + pi;
                const mx = (x1 + x2) / 2;
                d = skip
                  ? `M${x1} ${y1} L${x2 - 40} ${y1} C${x2 - 15} ${y1}, ${x2 - 25} ${y2}, ${x2} ${y2}`
                  : `M${x1} ${y1} C${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
                label = { x: x1 + (m.along - m.boxW) / 2, y: y1 - 5, anchor: "middle" };
              }
              const lit = on(link.lanes);
              const blocked = link.lanes.every((l) => outcome(l) === "bad");
              const warn = !blocked && link.lanes.every((l) => outcome(l) !== "ok");
              if (lit && detail === "devices") {
                const vias = [
                  ...new Set(link.lanes.filter((l) => lanesOn!.has(l)).map((l) => link.via.get(l)).filter(Boolean)),
                ] as string[];
                if (vias.length) labels.push({ key: link.key, ...label, text: vias.join(", ") });
              }
              const cls =
                "pg-link" + (lit ? " on" : "") + (blocked && !lit ? " blocked" : "") + (warn && !lit ? " warn" : "");
              return (
                <path
                  key={link.key}
                  className={cls}
                  d={d}
                  style={{ strokeWidth: Math.min(7, 1.5 + (link.lanes.length - 1)) }}
                >
                  <title>{`${a.hop.label} to ${b.hop.label}, ${pathsText(link.lanes)}`}</title>
                </path>
              );
            })}
          </g>
          <g>
            {graph.boxes.map((box) => {
              const hop = box.hop;
              const x = px(box);
              const y = py(box);
              const gate = isGate(hop);
              const solid = gate || hop.kind === "Device" || box.starts.length > 0 || box.ends.length > 0;
              const mtu = hopMtuMark(result.mtu, hop);
              const cls = [
                "pg-box",
                solid ? "solid" : "",
                gate ? "gate" : "",
                box.verdict ? `v-${box.verdict}` : "",
                selectedKey === box.key ? "focus" : "",
                !lanesOn || on(box.lanes) ? "near" : "",
              ]
                .filter(Boolean)
                .join(" ");
              const textX = x + 22;
              const labelY = detail === "all" ? y + m.boxH / 2 + 4 : y + 17;
              const title = [`${hop.label}: ${hop.note || hop.kind}`, mtu?.text, pathsText(box.lanes)]
                .filter(Boolean)
                .join(", ");
              return (
                <g
                  key={box.key}
                  ref={(el) => {
                    if (el) boxEls.current.set(box.key, el);
                    else boxEls.current.delete(box.key);
                  }}
                  className={cls}
                  style={kindVar(hop.kind)}
                  role="button"
                  tabIndex={box.key === focusKey ? 0 : -1}
                  aria-pressed={selectedKey === box.key}
                  aria-label={`${hop.label}, ${hop.kind}, ${pathsText(box.lanes)}`}
                  data-key={box.key}
                  onClick={() => {
                    setCursor(box.key);
                    selectBox(box);
                  }}
                  onFocus={() => setCursor(box.key)}
                  onKeyDown={(e) => onBoxKey(e, box)}
                >
                  <title>{title}</title>
                  <rect className="pg-rect" x={x} y={y} width={m.boxW} height={m.boxH} rx={gate ? 2 : 5} />
                  {gate ? (
                    <rect className="pg-mark" x={x + 7} y={y + (detail === "all" ? m.boxH / 2 : 13) - 4} width={8} height={8} />
                  ) : (
                    <circle
                      className="pg-mark"
                      cx={x + 11}
                      cy={detail === "all" ? y + m.boxH / 2 : y + 13}
                      r={4}
                      fill={kindColor(hop.kind)}
                    />
                  )}
                  <text className={"pg-label" + (MONO_KINDS.has(hop.kind) ? " mono" : "")} x={textX} y={labelY}>
                    {truncate(hop.label, m.boxW - 28, 7.2)}
                  </text>
                  {detail === "devices" && (
                    <SubLine box={box} x={textX} y={y + 32} width={m.boxW - 28} legByLane={legByLane} />
                  )}
                  {box.ecmp && (
                    <>
                      <rect className="pg-badge" x={x + m.boxW - 40} y={y - 7} width={48} height={14} rx={7} />
                      <text className="pg-badget" x={x + m.boxW - 16} y={y + 3} textAnchor="middle">
                        ECMP {box.out.length}
                      </text>
                    </>
                  )}
                </g>
              );
            })}
          </g>
          <g>
            {labels.map((l) => (
              <text key={l.key} className="pg-linklabel" x={l.x} y={l.y} textAnchor={l.anchor}>
                {l.text}
              </text>
            ))}
          </g>
        </svg>
      </div>
    </div>
  );
}
