/**
 * The DOM label overlay over the canvas.
 */

import * as THREE from "three";
import type { Selection } from "../../selection";
import {
  badgeDisplay,
  labelPriority,
  planLabels,
  projectToScreen,
  type Box,
  type LabelRequest,
  type PlateOccluder,
  type ScreenSegment,
} from "../labels";
import type { SceneNode } from "../scene";
import {
  HEX_THICKNESS,
  clamp,
  isSelectedNode,
  levelOfDetail,
  sceneStationKey,
  type PositionedNode,
} from "../view-helpers";

/** Equal to `.st-badge`'s size and margin in theme.css. */
const BADGE_PX = 16;
const BADGE_RISE_PX = 24;
/** Label box, in px, for the first frame, before the overlay is measured. */
export const LABEL_FALLBACK = { width: 96, height: 20 };

interface Ref<T> {
  current: T;
}

/** The overlay's DOM, as the component's refs hold it. */
export interface OverlayElements {
  overlay: Ref<HTMLDivElement | null>;
  labels: Ref<Map<string, HTMLDivElement>>;
  badges: Ref<Map<string, HTMLDivElement>>;
  leaders: Ref<Map<string, HTMLDivElement>>;
  pivot: Ref<HTMLDivElement | null>;
}

/** What one overlay layout reads from the stage. */
export interface OverlayFrame {
  viewport: { width: number; height: number };
  slotPx: number;
  camera: THREE.PerspectiveCamera;
  positions: ReadonlyMap<string, PositionedNode>;
  contentScale: (layer: number) => number;
  selection: Selection | null;
  endpoints: ReadonlySet<string>;
  hovered: string | null;
  /** The drawn path, as world points per segment. */
  path: readonly (readonly THREE.Vector3[])[];
  occluders: PlateOccluder[];
  /** true while a gesture runs or settles: low-priority labels stay down. */
  suppressLowPriority: boolean;
  /** The orbit pivot while its crosshair shows, else null. */
  pivot: THREE.Vector3 | null;
}

export interface OverlayRuntime {
  update(frame: OverlayFrame): void;
  dispose(): void;
}

export function createOverlay(nodes: readonly SceneNode[], elements: OverlayElements): OverlayRuntime {
  const measured = new Map<string, { width: number; height: number }>();
  let measuredCaptions: boolean | null = null;

  function measureLabels(captions: boolean) {
    if (measuredCaptions === captions && measured.size > 0) return;
    for (const [nodeKey, el] of elements.labels.current) {
      if (el.classList.contains("dot") && measured.has(nodeKey)) continue;
      measured.set(nodeKey, {
        width: el.offsetWidth || LABEL_FALLBACK.width,
        height: el.offsetHeight || LABEL_FALLBACK.height,
      });
    }
    measuredCaptions = captions;
  }

  function update(frame: OverlayFrame) {
    const { viewport, camera } = frame;
    const lod = levelOfDetail(frame.slotPx);
    elements.overlay.current?.classList.toggle("no-caption", !lod.captions);
    measureLabels(lod.captions);

    const requests: LabelRequest[] = [];
    const anchors = new Map<string, THREE.Vector3>();
    for (const node of nodes) {
      const nodeKey = sceneStationKey(node);
      const position = frame.positions.get(nodeKey)?.position;
      if (!position) continue;
      // A plate on its way flat takes its labels with it.
      if (frame.contentScale(node.layer) < 0.5) continue;
      const anchor = new THREE.Vector3(position.x, position.y + HEX_THICKNESS + 0.05, position.z);
      anchors.set(nodeKey, anchor);
      const box = measured.get(nodeKey) ?? LABEL_FALLBACK;
      requests.push({
        key: nodeKey,
        world: anchor,
        width: box.width,
        height: box.height,
        rank: node.rank,
        priority: labelPriority(node, {
          selected: isSelectedNode(frame.selection, node),
          endpoint: frame.endpoints.has(nodeKey),
          hovered: frame.hovered === nodeKey,
        }),
      });
    }

    const pathSegments: ScreenSegment[] = [];
    for (const points of frame.path) {
      for (let i = 1; i < points.length; i++) {
        const a = projectToScreen(points[i - 1], camera, viewport.width, viewport.height);
        const b = projectToScreen(points[i], camera, viewport.width, viewport.height);
        if (!a.visible || !b.visible) continue;
        pathSegments.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y });
      }
    }

    const badgeBoxes: Box[] = [];
    for (const anchor of anchors.values()) {
      const p = projectToScreen(anchor, camera, viewport.width, viewport.height);
      if (!p.visible) continue;
      badgeBoxes.push({
        x: p.x - BADGE_PX / 2,
        y: p.y - BADGE_RISE_PX - BADGE_PX / 2,
        w: BADGE_PX,
        h: BADGE_PX,
      });
    }

    const placed = planLabels(requests, camera, viewport, {
      slotPx: frame.slotPx,
      navigating: frame.suppressLowPriority,
      occluders: frame.occluders,
      cameraPosition: camera.position,
      pathSegments,
      badges: badgeBoxes,
    });

    const asked = new Set(requests.map((r) => r.key));
    for (const [nodeKey, el] of elements.labels.current) {
      if (!asked.has(nodeKey)) el.style.visibility = "hidden";
    }
    for (const [nodeKey, el] of elements.leaders.current) {
      if (!asked.has(nodeKey)) el.style.visibility = "hidden";
    }

    const badgeMode = new Map<string, "chip" | "standalone" | "hidden">();
    for (const label of placed) {
      badgeMode.set(label.key, badgeDisplay(label.mode));
      const el = elements.labels.current.get(label.key);
      const leader = elements.leaders.current.get(label.key);
      if (el) {
        el.classList.toggle("dot", label.mode === "dot");
        el.classList.toggle("occluded", label.occluded);
        if (label.mode === "hidden") {
          el.style.visibility = "hidden";
        } else {
          el.style.visibility = "visible";
          el.style.transform = `translate3d(${Math.round(label.x)}px, ${Math.round(label.y)}px, 0)`;
        }
      }
      if (!leader) continue;
      const box = measured.get(label.key) ?? LABEL_FALLBACK;
      if (label.mode !== "full") {
        leader.style.visibility = "hidden";
        continue;
      }
      const fromX = clamp(label.anchorX, label.x, label.x + box.width);
      const fromY = label.side === "above" ? label.y + box.height : label.y;
      const dx = label.anchorX - fromX;
      const dy = label.anchorY - fromY;
      const length = Math.hypot(dx, dy);
      leader.style.visibility = length > 1 ? "visible" : "hidden";
      leader.style.width = `${Math.round(length)}px`;
      leader.style.transform =
        `translate3d(${Math.round(fromX)}px, ${Math.round(fromY)}px, 0) ` +
        `rotate(${Math.atan2(dy, dx).toFixed(4)}rad)`;
    }

    for (const [nodeKey, el] of elements.badges.current) {
      const anchor = anchors.get(nodeKey);
      if (!anchor || badgeMode.get(nodeKey) !== "standalone") {
        el.style.visibility = "hidden";
        continue;
      }
      const p = projectToScreen(anchor, camera, viewport.width, viewport.height);
      if (!p.visible) {
        el.style.visibility = "hidden";
        continue;
      }
      el.style.visibility = "visible";
      el.style.transform = `translate3d(${Math.round(p.x)}px, ${Math.round(p.y)}px, 0)`;
    }

    // The pivot crosshair.
    const pivotEl = elements.pivot.current;
    if (pivotEl) {
      if (frame.pivot) {
        const p = projectToScreen(frame.pivot, camera, viewport.width, viewport.height);
        pivotEl.style.transform = `translate3d(${Math.round(p.x)}px, ${Math.round(p.y)}px, 0)`;
        pivotEl.classList.add("on");
      } else {
        pivotEl.classList.remove("on");
      }
    }
  }

  return {
    update,
    dispose() {
      measured.clear();
    },
  };
}
