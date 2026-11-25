/**
 * The pointer, wheel and key handlers of the Strata canvas.
 */

import type * as THREE from "three";
import { TWEEN_MS, WHEEL_STEP, orbitBy, panBy, zoomToCursor, type OrbitState, type SnapName } from "../camera";

/** The pivot crosshair fades after half a second. */
export const PIVOT_HINT_MS = 500;
/** How close a double-click frames a node. */
const FRAME_NODE_RADIUS = 6;
/** Drag distance, in px, below which a pointer gesture is still a click. */
const DRAG_SLOP = 3;

export type DragMode = "orbit" | "pan";

export interface CameraController {
  orbit(): OrbitState;
  setOrbit(next: OrbitState): void;
  animateTo(target: OrbitState): void;
  viewport(): { width: number; height: number };
  /** The world point under the cursor, for zoom and pivot. */
  focusPoint(clientX: number, clientY: number): THREE.Vector3;
  nodeKeyAt(clientX: number, clientY: number): string | null;
  nodePosition(key: string): THREE.Vector3 | undefined;
  pick(clientX: number, clientY: number): void;
  hover(key: string | null): void;
  fit(): void;
  snap(name: SnapName): void;
  /** Called once per gesture. */
  beginGesture(): void;
  startNavigation(mode: DragMode): void;
  endNavigation(): void;
  /** Show the pivot crosshair for `ms`. */
  showPivot(ms: number): void;
}

export interface InputRuntime {
  dispose(): void;
}

export function createInput(container: HTMLElement, controller: CameraController): InputRuntime {
  let drag: { pointerId: number; mode: DragMode; x: number; y: number; moved: boolean; shift: boolean } | null =
    null;
  const touches = new Map<number, { x: number; y: number }>();
  let pinch: { distance: number; cx: number; cy: number } | null = null;

  function onPointerDown(e: PointerEvent) {
    container.focus?.();
    if (e.pointerType === "touch") {
      touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
      container.setPointerCapture?.(e.pointerId);
      if (touches.size === 2) {
        // Two fingers pan and pinch-zoom.
        drag = null;
        const [a, b] = [...touches.values()];
        pinch = { distance: Math.hypot(a.x - b.x, a.y - b.y), cx: (a.x + b.x) / 2, cy: (a.y + b.y) / 2 };
        controller.startNavigation("pan");
        return;
      }
      if (touches.size > 2) return;
    } else if (e.button !== 0 && e.button !== 1 && e.button !== 2) {
      return;
    }
    // Left-drag orbits. Right-drag or middle-drag pans.
    const mode: DragMode = e.pointerType !== "touch" && e.button !== 0 ? "pan" : "orbit";
    drag = { pointerId: e.pointerId, mode, x: e.clientX, y: e.clientY, moved: false, shift: e.shiftKey };
    container.setPointerCapture?.(e.pointerId);
  }

  function onPointerMove(e: PointerEvent) {
    if (e.pointerType === "touch" && touches.has(e.pointerId)) {
      touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
    }
    if (pinch && touches.size === 2) {
      const [a, b] = [...touches.values()];
      const next = { distance: Math.hypot(a.x - b.x, a.y - b.y), cx: (a.x + b.x) / 2, cy: (a.y + b.y) / 2 };
      if (pinch.distance > 0 && next.distance > 0) {
        controller.setOrbit(
          zoomToCursor(controller.orbit(), controller.focusPoint(next.cx, next.cy), next.distance / pinch.distance),
        );
      }
      controller.setOrbit(panBy(controller.orbit(), next.cx - pinch.cx, next.cy - pinch.cy, controller.viewport()));
      pinch = next;
      return;
    }
    if (!drag) {
      controller.hover(controller.nodeKeyAt(e.clientX, e.clientY));
      return;
    }
    if (drag.pointerId !== e.pointerId) return;
    const dx = e.clientX - drag.x;
    const dy = e.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) < DRAG_SLOP) return;
    if (!drag.moved) controller.startNavigation(drag.mode);
    drag.moved = true;
    if (drag.mode === "pan") controller.setOrbit(panBy(controller.orbit(), dx, dy, controller.viewport()));
    // Shift constrains the orbit to azimuth alone.
    else controller.setOrbit(orbitBy(controller.orbit(), dx, dy, { azimuthOnly: e.shiftKey || drag.shift }));
    drag.x = e.clientX;
    drag.y = e.clientY;
  }

  function onPointerUp(e: PointerEvent) {
    if (e.pointerType === "touch") {
      touches.delete(e.pointerId);
      if (touches.size < 2 && pinch) {
        pinch = null;
        controller.endNavigation();
      }
    }
    if (!drag) return;
    container.releasePointerCapture?.(e.pointerId);
    const wasMoving = drag.moved;
    const mode = drag.mode;
    drag = null;
    if (wasMoving) controller.endNavigation();
    else if (mode === "orbit" && e.button <= 0) controller.pick(e.clientX, e.clientY);
  }

  function onPointerLeave() {
    controller.hover(null);
  }

  // The listener is non-passive.
  function onWheel(e: WheelEvent) {
    e.preventDefault();
    controller.beginGesture();
    const factor = e.deltaY < 0 ? WHEEL_STEP : 1 / WHEEL_STEP;
    controller.setOrbit(zoomToCursor(controller.orbit(), controller.focusPoint(e.clientX, e.clientY), factor));
  }

  function onDoubleClick(e: MouseEvent) {
    e.preventDefault();
    const viewport = controller.viewport();
    const aspect = viewport.width / viewport.height;
    const nodeKey = controller.nodeKeyAt(e.clientX, e.clientY);
    if (nodeKey) {
      // The double-click pivots on the node and frames it.
      const position = controller.nodePosition(nodeKey);
      if (position) {
        controller.animateTo({
          ...controller.orbit(),
          pivot: position.clone(),
          radius: Math.max(FRAME_NODE_RADIUS / Math.max(aspect, 0.4), 4),
        });
      }
      return;
    }
    // Double-clicking empty plate space sets the pivot there.
    controller.animateTo({ ...controller.orbit(), pivot: controller.focusPoint(e.clientX, e.clientY) });
    controller.showPivot(TWEEN_MS + PIVOT_HINT_MS);
  }

  function onContextMenu(e: MouseEvent) {
    e.preventDefault();
  }

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "f" || e.key === "F") {
      e.preventDefault();
      controller.fit();
    } else if (e.key === "Home") {
      e.preventDefault();
      controller.snap("home");
    }
  }

  container.addEventListener("pointerdown", onPointerDown);
  container.addEventListener("pointermove", onPointerMove);
  container.addEventListener("pointerup", onPointerUp);
  container.addEventListener("pointercancel", onPointerUp);
  container.addEventListener("pointerleave", onPointerLeave);
  container.addEventListener("wheel", onWheel, { passive: false });
  container.addEventListener("dblclick", onDoubleClick);
  container.addEventListener("contextmenu", onContextMenu);
  container.addEventListener("keydown", onKeyDown);

  return {
    dispose() {
      container.removeEventListener("pointerdown", onPointerDown);
      container.removeEventListener("pointermove", onPointerMove);
      container.removeEventListener("pointerup", onPointerUp);
      container.removeEventListener("pointercancel", onPointerUp);
      container.removeEventListener("pointerleave", onPointerLeave);
      container.removeEventListener("wheel", onWheel);
      container.removeEventListener("dblclick", onDoubleClick);
      container.removeEventListener("contextmenu", onContextMenu);
      container.removeEventListener("keydown", onKeyDown);
    },
  };
}
