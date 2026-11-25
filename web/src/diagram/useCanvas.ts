/** A new `fit` reframes the view and clears the pins during render. */

import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent } from "react";

export interface View {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface Point {
  x: number;
  y: number;
}

const MIN_ZOOM = 0.3;
const MAX_ZOOM = 6;
const WHEEL_STEP = 1.12;

function clamp(value: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, value));
}

/** The box the element's client rectangle has; a DOMRect satisfies it. */
export interface ClientBox {
  left: number;
  top: number;
  width: number;
  height: number;
}

/**
 * How the browser draws `view` into `box` under `xMidYMid meet`, the SVG
 * default every diagram here uses: one scale for both axes, the tighter side's,
 * and the picture centred, with empty bands on the looser side. `s` is screen
 * px per user unit; `ox` and `oy` are the band widths in px.
 */
export function meetScale(view: View, box: ClientBox): { s: number; ox: number; oy: number } {
  const s = Math.min(box.width / view.w, box.height / view.h);
  return { s, ox: (box.width - view.w * s) / 2, oy: (box.height - view.h * s) / 2 };
}

/** A client position in user units, under `xMidYMid meet`. */
export function clientToUser(view: View, box: ClientBox, clientX: number, clientY: number): Point {
  const { s, ox, oy } = meetScale(view, box);
  return { x: view.x + (clientX - box.left - ox) / s, y: view.y + (clientY - box.top - oy) / s };
}

export interface CanvasOptions {
  /** the attribute naming a draggable element and carrying its id */
  dragAttr: string;
  /** a selector for elements a pointer-down leaves alone (their own click handlers act) */
  passthrough?: string;
  /** how far in a wheel may zoom, as a multiple of `fit`; 6 by default */
  maxZoom?: number;
  /** how far out a wheel may zoom, as a multiple of `fit`; 0.3 by default */
  minZoom?: number;
  /** the view to open at; `fit` by default */
  initial?: View;
}

export function useCanvas(fit: View, { dragAttr, passthrough, maxZoom = MAX_ZOOM, minZoom = MIN_ZOOM, initial }: CanvasOptions) {
  const svg = useRef<SVGSVGElement | null>(null);
  const [view, setView] = useState<View>(initial ?? fit);
  const [pins, setPins] = useState<ReadonlyMap<string, Point>>(new Map());
  const pan = useRef<Point | null>(null);
  const drag = useRef<string | null>(null);

  const [framed, setFramed] = useState(fit);
  if (framed !== fit) {
    setFramed(fit);
    setView(fit);
    setPins(new Map());
  }

  /** the pointer's position in user units, or undefined before layout */
  const toUser = useCallback(
    (e: { clientX: number; clientY: number }): Point | undefined => {
      const rect = svg.current?.getBoundingClientRect();
      if (!rect || rect.width === 0 || rect.height === 0) return undefined;
      return clientToUser(view, rect, e.clientX, e.clientY);
    },
    [view],
  );

  const zoomBy = useCallback(
    (factor: number, clientX?: number, clientY?: number) => {
      setView((v) => {
        const nextW = clamp(v.w / factor, fit.w / maxZoom, fit.w / minZoom);
        const applied = v.w / nextW;
        const rect = svg.current?.getBoundingClientRect();
        const focus =
          rect && clientX !== undefined && clientY !== undefined && rect.width > 0 && rect.height > 0
            ? clientToUser(v, rect, clientX, clientY)
            : { x: v.x + v.w / 2, y: v.y + v.h / 2 };
        return {
          x: focus.x - (focus.x - v.x) / applied,
          y: focus.y - (focus.y - v.y) / applied,
          w: nextW,
          h: v.h / applied,
        };
      });
    },
    [fit, maxZoom, minZoom],
  );

  // React's onWheel is passive and ignores preventDefault.
  useEffect(() => {
    const el = svg.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      zoomBy(e.deltaY < 0 ? WHEEL_STEP : 1 / WHEEL_STEP, e.clientX, e.clientY);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomBy]);

  const handlers = useMemo(
    () => ({
      onPointerDown: (e: PointerEvent<SVGSVGElement>) => {
        if (passthrough && (e.target as Element).closest(passthrough)) return;
        (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
        const node = (e.target as Element).closest(`[${dragAttr}]`);
        if (node) drag.current = node.getAttribute(dragAttr);
        else pan.current = { x: e.clientX, y: e.clientY };
      },
      onPointerMove: (e: PointerEvent<SVGSVGElement>) => {
        if (drag.current) {
          const id = drag.current;
          const at = toUser(e);
          if (at) setPins((prev) => new Map(prev).set(id, at));
          return;
        }
        const p = pan.current;
        const rect = svg.current?.getBoundingClientRect();
        if (!p || !rect || rect.width === 0 || rect.height === 0) return;
        const dx = e.clientX - p.x;
        const dy = e.clientY - p.y;
        setView((v) => {
          const { s } = meetScale(v, rect);
          return { ...v, x: v.x - dx / s, y: v.y - dy / s };
        });
        pan.current = { x: e.clientX, y: e.clientY };
      },
      onPointerUp: () => {
        pan.current = null;
        drag.current = null;
      },
      onPointerCancel: () => {
        pan.current = null;
        drag.current = null;
      },
    }),
    [dragAttr, passthrough, toUser],
  );

  return {
    svg,
    view,
    viewBox: `${view.x} ${view.y} ${view.w} ${view.h}`,
    pins,
    handlers,
    zoomBy,
    /** frame a region, e.g. the fit the user returns to */
    frameTo: setView,
  };
}
