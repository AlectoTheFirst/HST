import { levelOf } from "./camera";
import { Scene } from "./scene";
import { drawsLine, type CameraState, type FrameStats, type Renderer, type Viewport } from "./types";

export interface NullRenderer extends Renderer {
  readonly scene: Scene;
  camera: CameraState;
  viewport: Viewport;
}

/** The renderer without a GPU: it keeps the scene and computes each frame's draw calls and labels. */
export function createNullRenderer(): NullRenderer {
  const scene = new Scene();
  const r: NullRenderer = {
    scene,
    camera: { u: 0, v: 0, zoom: 1 },
    viewport: { width: 800, height: 600 },
    setTier: (name, rows, tile) => scene.setTier(name, rows, tile),
    applyDelta: (name, changes, tile) => scene.applyDelta(name, changes, tile),
    dropTile: (tile) => scene.dropTile(tile),
    setRoutes: (routes) => scene.setRoutes(routes),
    setStyle: (style) => scene.setStyle(style),
    setCamera(camera, viewport) {
      r.camera = camera;
      r.viewport = viewport;
    },
    pick: (x, y) => scene.pick(r.camera, r.viewport, x, y, levelOf(r.camera.zoom)),
    frame: () => stats(scene, r.camera, r.viewport),
    dispose() {},
  };
  return r;
}

export function stats(scene: Scene, camera: CameraState, viewport: Viewport): FrameStats {
  const level = levelOf(camera.zoom);
  const { areas, boxes, lines, outlines, symbols, models } = scene.batches(level);
  const drawn = [areas, ...boxes.filter((b) => !b.proxy), ...lines, ...outlines, ...symbols, ...models].filter((b) => b.ids.length > 0);
  return {
    level,
    drawCalls: drawn.length + scene.routes.filter(drawsLine).length,
    instances: boxes.reduce((n, b) => n + b.ids.length, 0),
    labels: scene.labels(camera, viewport, level),
    markers: scene.markers(camera, viewport),
    animating: false,
  };
}
