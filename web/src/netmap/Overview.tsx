/**
 * The overview of a site diagram: the whole drawing in small, with a
 * frame on the part the canvas shows. A press or a drag in the overview
 * centres the canvas on that point. It reads the canvas on each pan, zoom and
 * move, at most once per frame.
 */

import type cytoscape from "cytoscape";
import { useEffect, useRef, useState, type PointerEvent } from "react";
import { fitTransform } from "./look";

const WIDTH = 200;
const HEIGHT = 130;

/** One call per frame; a context with no frames (a test) runs it on a timer. */
const nextFrame = (fn: () => void): number =>
  typeof requestAnimationFrame === "function" ? requestAnimationFrame(fn) : window.setTimeout(fn, 16);
const cancelFrame = (id: number) =>
  typeof cancelAnimationFrame === "function" ? cancelAnimationFrame(id) : window.clearTimeout(id);

interface Picture {
  box: { x1: number; y1: number; w: number; h: number };
  dots: { id: string; x: number; y: number }[];
  lines: { id: string; x1: number; y1: number; x2: number; y2: number; color: string }[];
  view: { x1: number; y1: number; w: number; h: number };
}

function read(core: cytoscape.Core): Picture {
  const shown = core.elements(":visible");
  const bb = shown.boundingBox({ includeLabels: false });
  const ext = core.extent();
  return {
    box: { x1: bb.x1, y1: bb.y1, w: bb.w, h: bb.h },
    dots: shown.nodes(".device").map((n) => ({ id: n.id(), ...n.position() })),
    lines: shown.edges(".cable").map((e) => {
      const s = e.source().position();
      const t = e.target().position();
      return { id: e.id(), x1: s.x, y1: s.y, x2: t.x, y2: t.y, color: String(e.style("line-color")) };
    }),
    view: { x1: ext.x1, y1: ext.y1, w: ext.w, h: ext.h },
  };
}

export default function Overview({ core, version }: { core: cytoscape.Core | null; version: number }) {
  const [picture, setPicture] = useState<Picture | null>(null);
  const frame = useRef(0);

  useEffect(() => {
    if (!core) return;
    const update = () => {
      cancelFrame(frame.current);
      frame.current = nextFrame(() => {
        if (!core.destroyed()) setPicture(read(core));
      });
    };
    update();
    core.on("viewport position add remove style", update);
    return () => {
      cancelFrame(frame.current);
      if (!core.destroyed()) core.off("viewport position add remove style", update);
    };
  }, [core, version]);

  if (!core || !picture || picture.dots.length === 0) return null;
  const { scale, ox, oy } = fitTransform(picture.box, WIDTH, HEIGHT);
  const sx = (x: number) => x * scale + ox;
  const sy = (y: number) => y * scale + oy;

  const centreAt = (e: PointerEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - r.left - ox) / scale;
    const y = (e.clientY - r.top - oy) / scale;
    const zoom = core.zoom();
    core.pan({ x: core.width() / 2 - x * zoom, y: core.height() / 2 - y * zoom });
  };

  return (
    <div className="nm-overview" aria-hidden="true">
      <svg
        width={WIDTH}
        height={HEIGHT}
        onPointerDown={(e) => {
          e.currentTarget.setPointerCapture(e.pointerId);
          centreAt(e);
        }}
        onPointerMove={(e) => {
          if (e.currentTarget.hasPointerCapture(e.pointerId)) centreAt(e);
        }}
      >
        {picture.lines.map((l) => (
          <line key={l.id} x1={sx(l.x1)} y1={sy(l.y1)} x2={sx(l.x2)} y2={sy(l.y2)} stroke={l.color} strokeWidth={0.8} />
        ))}
        {picture.dots.map((d) => (
          <circle key={d.id} cx={sx(d.x)} cy={sy(d.y)} r={2} className="nm-overview-dot" />
        ))}
        <rect
          className="nm-overview-view"
          x={sx(picture.view.x1)}
          y={sy(picture.view.y1)}
          width={picture.view.w * scale}
          height={picture.view.h * scale}
        />
      </svg>
    </div>
  );
}
