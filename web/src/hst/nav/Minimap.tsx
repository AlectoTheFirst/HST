import { fit, minimapView, toPlane, toScreen } from "../render/camera";
import type { Placement } from "../render/scene";
import type { CameraState, Viewport } from "../render/types";

interface Props {
  plates: Placement[];
  /** The block areas, drawn in the tint of their kind. */
  areas?: { place: Placement; tint: number }[];
  camera: CameraState;
  viewport: Viewport;
  onJump(u: number, v: number): void;
}

const SIZE: Viewport = { width: 168, height: 120 };

/** The estate in the projection of the map, with the viewport as a rectangle. */
export default function Minimap({ plates, areas = [], camera, viewport, onJump }: Props) {
  if (plates.length === 0) return null;
  const bounds = {
    u0: Math.min(...plates.map((p) => p.u)),
    v0: Math.min(...plates.map((p) => p.v)),
    u1: Math.max(...plates.map((p) => p.u + p.w)),
    v1: Math.max(...plates.map((p) => p.v + p.h)),
  };
  const mini = fit(bounds, SIZE, camera.view);
  const view = minimapView(camera, viewport, mini, SIZE);
  const corners = (p: Placement) =>
    [
      [p.u, p.v],
      [p.u + p.w, p.v],
      [p.u + p.w, p.v + p.h],
      [p.u, p.v + p.h],
    ]
      .map(([u, v]) => toScreen(mini, SIZE, u, v).map((n) => n.toFixed(1)).join(","))
      .join(" ");
  return (
    <button
      type="button"
      className="hst-minimap"
      aria-label="Minimap"
      onClick={(e) => {
        const box = e.currentTarget.getBoundingClientRect();
        const x = box.width ? ((e.clientX - box.left) / box.width) * SIZE.width : SIZE.width / 2;
        const y = box.height ? ((e.clientY - box.top) / box.height) * SIZE.height : SIZE.height / 2;
        const [u, v] = toPlane(mini, SIZE, x, y);
        onJump(u, v);
      }}
    >
      <svg viewBox={`0 0 ${SIZE.width} ${SIZE.height}`} width={SIZE.width} height={SIZE.height} aria-hidden="true">
        {plates.map((p) => (
          <polygon key={p.uid} className="hst-minimap-plate" points={corners(p)} />
        ))}
        {areas.map(({ place, tint }) => (
          <polygon key={place.uid} className="hst-minimap-area" points={corners(place)} style={{ fill: `#${tint.toString(16).padStart(6, "0")}` }} />
        ))}
        <rect
          className="hst-minimap-view"
          x={view.x0}
          y={view.y0}
          width={Math.max(1, view.x1 - view.x0)}
          height={Math.max(1, view.y1 - view.y0)}
        />
      </svg>
    </button>
  );
}
