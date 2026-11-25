import { describe, expect, it, vi } from "vitest";
import * as THREE from "three";
import { FIXTURE_PATH_SINGLE } from "../../../test/fixtures";
import { homeView } from "../camera";
import { buildPathGeometry, layerOffsets, sceneBounds, sceneFootprint } from "../path";
import { buildScene } from "../scene";
import { layerGap, platePalette, positionNodes, sceneStationKey, DENSITY_DEFAULT } from "../view-helpers";
import { HOVER_SCALE, PATH_WIDTH } from "./common";
import { createInput, type CameraController } from "./input";
import { createLoop } from "./loop";
import { createNodes } from "./nodes";
import { LABEL_FALLBACK, createOverlay } from "./overlay";
import { createPathLines } from "./pathLines";
import { createPlates } from "./plates";

function stage(fixture = FIXTURE_PATH_SINGLE) {
  const scene = buildScene(fixture);
  const offsets = layerOffsets(scene.layerCount, layerGap(DENSITY_DEFAULT), []);
  const positions = positionNodes(scene.nodes, offsets);
  return { scene, offsets, positions, three: new THREE.Scene() };
}

describe("createPlates", () => {
  it("makes one plate per layer, moves it to the layer's Y and fades it as it goes flat", () => {
    const { scene, three } = stage();
    const palettes = Array.from({ length: scene.layerCount }, (_, i) => platePalette("#eef1f5", "#1c2733", i));
    const plates = createPlates(three, sceneFootprint(scene.nodes), palettes);
    expect(plates.surfaces).toHaveLength(scene.layerCount);
    plates.update([0, 5, 10, 15], [0, 1, 0, 0.5]);
    expect(plates.surfaces.map((s) => s.position.y)).toEqual([0, 5, 10, 15]);
    const opacity = (i: number) => (plates.surfaces[i].material as THREE.MeshBasicMaterial).opacity;
    expect(opacity(0)).toBeCloseTo(palettes[0].opacity);
    expect(opacity(1)).toBe(0);
    expect(opacity(3)).toBeCloseTo(palettes[3].opacity / 2);
    plates.dispose();
    expect(three.children).toHaveLength(0);
  });
});

describe("createNodes", () => {
  it("maps a raycast hit back to its station and outlines the selected node", () => {
    const { scene, positions, three } = stage();
    const container = document.createElement("div");
    const nodes = createNodes(three, scene.nodes, container, new THREE.Color("#4a6fa8"));
    nodes.update(positions, () => 1, null);
    const first = scene.nodes[0];
    const hit = { object: nodes.pickTargets[0], instanceId: 0 } as unknown as THREE.Intersection;
    expect(nodes.keyForHit(hit)).toBe(sceneStationKey(first));
    expect(nodes.keyForHit({ object: new THREE.Object3D() } as THREE.Intersection)).toBeNull();
    expect(nodes.node(sceneStationKey(first))).toBe(first);

    const hop = FIXTURE_PATH_SINGLE.hops.find((h) => h.rank === first.rank)!;
    expect(nodes.select({ type: "hop", data: hop }, positions)).toBe(sceneStationKey(first));
    expect(nodes.select(null, positions)).toBeNull();
    nodes.dispose();
    expect(three.children).toHaveLength(0);
  });

  it("scales the hovered node and shrinks the nodes of a flattened plate", () => {
    const { scene, positions, three } = stage();
    const nodes = createNodes(three, scene.nodes, document.createElement("div"), new THREE.Color("#4a6fa8"));
    const mesh = nodes.pickTargets[0] as THREE.InstancedMesh;
    const scaleOf = (index: number) => {
      const m = new THREE.Matrix4();
      mesh.getMatrixAt(index, m);
      return new THREE.Vector3().setFromMatrixScale(m).x;
    };
    nodes.update(positions, () => 1, sceneStationKey(scene.nodes[0]));
    expect(scaleOf(0)).toBeCloseTo(HOVER_SCALE);
    nodes.update(positions, () => 0.25, null);
    expect(scaleOf(0)).toBeCloseTo(0.25);
    nodes.dispose();
  });
});

describe("createPathLines", () => {
  it("builds the segments once, then widens the selected node's segments and hides both-hidden ones", () => {
    const { scene, positions, three } = stage();
    const lines = createPathLines(three, new THREE.Color("#4a6fa8"), new THREE.Color("#8593a2"), false);
    const segments = buildPathGeometry(scene, positions).segments;
    lines.update(segments);
    const built = lines.segments.length;
    expect(built).toBe(segments.length);
    lines.update(segments);
    expect(lines.segments).toHaveLength(built);

    const first = lines.segments[0];
    lines.applyState(first.segment.from, new Set());
    expect(first.coreMaterial.linewidth).toBe(PATH_WIDTH + 2);
    lines.applyState(null, new Set([first.segment.fromLayer, first.segment.toLayer]));
    expect(first.coreMaterial.linewidth).toBe(PATH_WIDTH);
    expect(first.core.visible).toBe(false);

    lines.tick(0.5);
    expect(first.flowMaterial?.dashOffset).not.toBe(0);
    lines.dispose();
    expect(three.children).toHaveLength(0);
  });

  it("draws a chevron in place of the flow dash under reduced motion", () => {
    const { scene, positions, three } = stage();
    const lines = createPathLines(three, new THREE.Color("#4a6fa8"), new THREE.Color("#8593a2"), true);
    lines.update(buildPathGeometry(scene, positions).segments);
    const live = lines.segments.filter((o) => !o.segment.dead);
    expect(live.length).toBeGreaterThan(0);
    expect(live.every((o) => o.chevron && !o.flow)).toBe(true);
    lines.setChevronScale(2);
    expect(live[0].chevron?.scale.x).toBe(2);
    lines.dispose();
  });

  it("draws a dead segment muted, with no glow and no flow dash", () => {
    const { scene, positions, three } = stage();
    const lines = createPathLines(three, new THREE.Color("#4a6fa8"), new THREE.Color("#8593a2"), false);
    const segments = buildPathGeometry(scene, positions).segments.map((s, i) => ({ ...s, dead: i === 0 }));
    lines.update(segments);
    lines.applyState(null, new Set());
    const [dead, ...rest] = lines.segments;
    expect(dead.glow.visible).toBe(false);
    expect(dead.flow).toBeNull();
    expect(dead.coreMaterial.color.getHex()).toBe(new THREE.Color("#8593a2").getHex());
    expect(rest.every((o) => o.glow.visible && o.flow)).toBe(true);
    lines.dispose();
  });
});

describe("createOverlay", () => {
  it("places a label for each node and hides the labels of a flattened plate", () => {
    const { scene, offsets, positions } = stage();
    const labels = new Map<string, HTMLDivElement>();
    for (const node of scene.nodes) labels.set(sceneStationKey(node), document.createElement("div"));
    const pivot = document.createElement("div");
    const overlay = createOverlay(scene.nodes, {
      overlay: { current: document.createElement("div") },
      labels: { current: labels },
      badges: { current: new Map() },
      leaders: { current: new Map() },
      pivot: { current: pivot },
    });
    const viewport = { width: 800, height: 600 };
    const camera = new THREE.PerspectiveCamera(40, viewport.width / viewport.height, 0.1, 4000);
    const orbit = homeView(sceneBounds(scene.nodes, offsets), viewport.width / viewport.height);
    camera.position.copy(orbit.pivot).add(new THREE.Vector3(0, 0, orbit.radius));
    camera.lookAt(orbit.pivot);
    camera.updateMatrixWorld();
    const frame = {
      viewport,
      slotPx: 80,
      camera,
      positions,
      contentScale: () => 1,
      selection: null,
      endpoints: new Set<string>(),
      hovered: null,
      path: [],
      occluders: [],
      suppressLowPriority: false,
      pivot: orbit.pivot,
    };
    overlay.update(frame);
    expect([...labels.values()].some((el) => el.style.visibility === "visible")).toBe(true);
    expect(pivot.classList.contains("on")).toBe(true);

    overlay.update({ ...frame, contentScale: () => 0, pivot: null });
    expect([...labels.values()].every((el) => el.style.visibility === "hidden")).toBe(true);
    expect(pivot.classList.contains("on")).toBe(false);
    expect(LABEL_FALLBACK.width).toBeGreaterThan(0);
    overlay.dispose();
  });
});

function controller(): CameraController & { calls: string[] } {
  const calls: string[] = [];
  const orbit = homeView(sceneBounds(buildScene(FIXTURE_PATH_SINGLE).nodes, [0, 4, 8, 12]), 1);
  return {
    calls,
    orbit: () => orbit,
    setOrbit: () => calls.push("setOrbit"),
    animateTo: () => calls.push("animateTo"),
    viewport: () => ({ width: 800, height: 600 }),
    focusPoint: () => new THREE.Vector3(),
    nodeKeyAt: (x) => (x < 10 ? "node" : null),
    nodePosition: () => new THREE.Vector3(1, 2, 3),
    pick: () => calls.push("pick"),
    hover: (key) => calls.push(`hover:${key}`),
    fit: () => calls.push("fit"),
    snap: (name) => calls.push(`snap:${name}`),
    beginGesture: () => calls.push("beginGesture"),
    startNavigation: (mode) => calls.push(`start:${mode}`),
    endNavigation: () => calls.push("end"),
    showPivot: () => calls.push("showPivot"),
  };
}

function pointer(type: string, init: { x: number; y: number; button?: number; pointerId?: number }) {
  const e = new MouseEvent(type, { clientX: init.x, clientY: init.y, button: init.button ?? 0, bubbles: true });
  Object.assign(e, { pointerId: init.pointerId ?? 1, pointerType: "mouse" });
  return e;
}

describe("createInput", () => {
  it("picks on a click, orbits on a left drag and pans on a right drag", () => {
    const container = document.createElement("div");
    const c = controller();
    const input = createInput(container, c);

    container.dispatchEvent(pointer("pointerdown", { x: 5, y: 5 }));
    container.dispatchEvent(pointer("pointerup", { x: 5, y: 5 }));
    expect(c.calls).toEqual(["pick"]);

    c.calls.length = 0;
    container.dispatchEvent(pointer("pointerdown", { x: 50, y: 50 }));
    container.dispatchEvent(pointer("pointermove", { x: 80, y: 50 }));
    container.dispatchEvent(pointer("pointerup", { x: 80, y: 50 }));
    expect(c.calls).toEqual(["start:orbit", "setOrbit", "end"]);

    c.calls.length = 0;
    container.dispatchEvent(pointer("pointerdown", { x: 50, y: 50, button: 2 }));
    container.dispatchEvent(pointer("pointermove", { x: 50, y: 90, button: 2 }));
    container.dispatchEvent(pointer("pointerup", { x: 50, y: 90, button: 2 }));
    expect(c.calls).toEqual(["start:pan", "setOrbit", "end"]);
    input.dispose();
  });

  it("hovers on a move, zooms on the wheel, and fits and snaps from the keys", () => {
    const container = document.createElement("div");
    const c = controller();
    const input = createInput(container, c);
    container.dispatchEvent(pointer("pointermove", { x: 5, y: 5 }));
    container.dispatchEvent(new MouseEvent("pointerleave"));
    container.dispatchEvent(new WheelEvent("wheel", { deltaY: -1, cancelable: true }));
    container.dispatchEvent(new KeyboardEvent("keydown", { key: "f" }));
    container.dispatchEvent(new KeyboardEvent("keydown", { key: "Home" }));
    expect(c.calls).toEqual(["hover:node", "hover:null", "beginGesture", "setOrbit", "fit", "snap:home"]);

    c.calls.length = 0;
    container.dispatchEvent(new MouseEvent("dblclick", { clientX: 50, clientY: 50 }));
    expect(c.calls).toEqual(["animateTo", "showPivot"]);
    input.dispose();
    container.dispatchEvent(new KeyboardEvent("keydown", { key: "f" }));
    expect(c.calls).toEqual(["animateTo", "showPivot"]);
  });
});

describe("createLoop", () => {
  it("calls the frame with the capped time step until it is disposed", () => {
    const queue: FrameRequestCallback[] = [];
    const raf = vi.fn((cb: FrameRequestCallback) => queue.push(cb));
    const cancel = vi.fn();
    const frame = vi.fn();
    const loop = createLoop(frame, raf, cancel, 0);
    queue.shift()!(16);
    queue.shift()!(5000);
    expect(frame.mock.calls).toEqual([
      [16, 0.016],
      [5000, 0.1],
    ]);
    loop.dispose();
    expect(cancel).toHaveBeenCalled();
    queue.shift()!(5016);
    expect(frame).toHaveBeenCalledTimes(2);
  });
});
