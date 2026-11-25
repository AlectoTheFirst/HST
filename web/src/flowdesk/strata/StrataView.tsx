/** Every three.js object is created inside the build effect. */


import { VERDICT_WORD } from "../verdict";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";
import type { PathResponse } from "../../api/types";
import type { Selection } from "../selection";
import { buildScene, sceneLanes, type SceneDescription } from "./scene";
import { STRATA_LAYERS } from "./layers";
import { hopMtuMark } from "../MtuPanel";
import {
  FOV,
  TWEEN_MS,
  configureCamera,
  easeOut,
  fitView,
  flattenTargetsChanged,
  homeView,
  isSceneOffScreen,
  lerpOrbit,
  pointerNdc,
  slotPixels,
  snapTarget,
  viewCubeTransform,
  type OrbitState,
  type SnapName,
} from "./camera";
import type { PlateOccluder } from "./labels";
import {
  buildPathGeometry,
  flattenTargets,
  layerOffsets,
  pathCentroid,
  sceneBounds,
  sceneFootprint,
} from "./path";
import {
  DENSITY_DEFAULT,
  DENSITY_MAX,
  DENSITY_MIN,
  DENSITY_STEP,
  MONO_KINDS,
  clamp,
  findHopForNode,
  isSelectedNode,
  isolateLayer,
  layerGap,
  levelOfDetail,
  platePalette,
  positionNodes,
  resolveToken,
  sceneStationKey,
  toggleLayer,
  type FlatLayers,
} from "./view-helpers";
import { CHEVRON_PX } from "./runtime/common";
import { PIVOT_HINT_MS, createInput, type CameraController } from "./runtime/input";
import { createLoop } from "./runtime/loop";
import { createNodes } from "./runtime/nodes";
import { createOverlay } from "./runtime/overlay";
import { createPathLines } from "./runtime/pathLines";
import { createPlates } from "./runtime/plates";
import "./strata.css";

const AMBIENT_INTENSITY = 0.4;
const HEMISPHERE_INTENSITY = 0.34;
const KEY_INTENSITY = 0.95;
/** Low-priority labels come back this long after the gesture ends. */
const LABEL_SETTLE_MS = 150;
/** The scene is off-screen this long before Refocus shows. */
const REFOCUS_AFTER_MS = 2000;
/** A wheel notch this long after the previous one starts a new gesture. */
const GESTURE_IDLE_MS = 400;
/** No plate flattened: the state of every new trace. */
const NO_FLAT: FlatLayers = new Set();

const SNAP_BUTTONS: ReadonlyArray<{ name: SnapName; label: string }> = [
  { name: "front", label: "Front" },
  { name: "top", label: "Top" },
  { name: "left", label: "Left" },
  { name: "right", label: "Right" },
  { name: "home", label: "Home" },
];

function prefersReducedMotion(): boolean {
  try {
    return window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ?? false;
  } catch {
    return false;
  }
}

export function StrataView({
  result,
  selection,
  onSelect,
  onNavigate,
}: {
  result: PathResponse;
  selection: Selection | null;
  onSelect: (selection: Selection) => void;
  /** Called once at the start of every orbit, pan or zoom gesture. */
  onNavigate?: () => void;
}) {
  const [fallback, setFallback] = useState<string | null>(null);
  // A new scene has no plate flattened.
  const [flatState, setFlatState] = useState<{ scene: SceneDescription | null; flat: FlatLayers }>({
    scene: null,
    flat: NO_FLAT,
  });
  const [density, setDensity] = useState(DENSITY_DEFAULT);
  const [refocus, setRefocus] = useState(false);

  const scene: SceneDescription = useMemo(
    () => buildScene({ hops: result.hops, legs: result.legs }),
    [result],
  );
  const lanes = useMemo(() => sceneLanes(result.legs), [result]);

  /** The trace's two ends. Their labels outrank a plain hop's. */
  const endpointKeys = useMemo(() => {
    const keys = new Set<string>();
    if (scene.nodes.length === 0) return keys;
    let min = scene.nodes[0];
    let max = scene.nodes[0];
    for (const node of scene.nodes) {
      if (node.rank < min.rank) min = node;
      if (node.rank > max.rank) max = node;
    }
    keys.add(sceneStationKey(min));
    keys.add(sceneStationKey(max));
    return keys;
  }, [scene]);

  const flat = flatState.scene === scene ? flatState.flat : NO_FLAT;
  const setFlat = (update: (f: FlatLayers) => FlatLayers) =>
    setFlatState((s) => ({ scene, flat: update(s.scene === scene ? s.flat : NO_FLAT) }));

  const outerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const overlayRef = useRef<HTMLDivElement | null>(null);
  const labelRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const badgeRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const leaderRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const pivotRef = useRef<HTMLDivElement | null>(null);
  const cubeRef = useRef<HTMLDivElement | null>(null);

  // A layout effect updates these refs before the effects below run.
  const onSelectRef = useRef(onSelect);
  const onNavigateRef = useRef(onNavigate);
  const selectionRef = useRef(selection);
  const flatRef = useRef(flat);
  const densityRef = useRef(density);
  const endpointRef = useRef(endpointKeys);
  useLayoutEffect(() => {
    onSelectRef.current = onSelect;
    onNavigateRef.current = onNavigate;
    selectionRef.current = selection;
    flatRef.current = flat;
    densityRef.current = density;
    endpointRef.current = endpointKeys;
  });

  /** Null until the stage is built. */
  const stageRef = useRef<{
    fit: () => void;
    snap: (name: SnapName) => void;
    markLayoutDirty: () => void;
    onlyLayer: (layer: number) => void;
  } | null>(null);


  useEffect(() => {
    const container = canvasRef.current;
    if (!container || result.hops.length === 0) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    } catch {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setFallback("No WebGL context");
      return;
    }
    if (!renderer.getContext()) {
      renderer.dispose();
      setFallback("No WebGL context");
      return;
    }
    setFallback(null);

    const reducedMotion = prefersReducedMotion();
    const three = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(FOV, 1, 0.1, 4000);
    const layerCount = scene.layerCount;

    // --- theme -----------------------------------------------------------
    const bgToken = resolveToken("--bg", "#eef1f5", container);
    const textToken = resolveToken("--text", "#1c2733", container);
    const accent = new THREE.Color(resolveToken("--accent", "#4a6fa8", container));
    const muted = new THREE.Color(resolveToken("--muted", "#8593a2", container));
    const palettes = Array.from({ length: layerCount }, (_, i) => platePalette(bgToken, textToken, i));

    three.add(new THREE.AmbientLight(0xffffff, AMBIENT_INTENSITY));
    const hemisphere = new THREE.HemisphereLight(0xffffff, 0x2a2f38, HEMISPHERE_INTENSITY);
    hemisphere.position.set(0, 1, 0);
    three.add(hemisphere);
    const key = new THREE.DirectionalLight(0xffffff, KEY_INTENSITY);
    key.position.set(-60, 90, 70);
    three.add(key);

    // --- the runtime parts -----------------------------------------------
    const footprint = sceneFootprint(scene.nodes);
    const plates = createPlates(three, footprint, palettes);
    const nodes = createNodes(three, scene.nodes, container, accent);
    const lines = createPathLines(three, accent, muted, reducedMotion);
    const overlay = createOverlay(scene.nodes, {
      overlay: overlayRef,
      labels: labelRefs,
      badges: badgeRefs,
      leaders: leaderRefs,
      pivot: pivotRef,
    });

    let offsets = layerOffsets(layerCount, layerGap(densityRef.current), []);
    let positions = positionNodes(scene.nodes, offsets);
    let bounds = sceneBounds(scene.nodes, offsets);
    let occluders: PlateOccluder[] = [];
    const flattenNow: number[] = Array.from({ length: layerCount }, () => 0);
    let flattenFrom: number[] = [...flattenNow];
    let flattenTo: number[] = [...flattenNow];
    let flattenStart = 0;
    let flattenDuration = 0;
    let layoutDirty = true;
    let viewDirty = true;
    let hoveredKey: string | null = null;

    function contentScale(layer: number): number {
      return 1 - clamp(flattenNow[layer] ?? 0, 0, 1);
    }

    function rebuildLayout() {
      offsets = layerOffsets(layerCount, layerGap(densityRef.current), flattenNow);
      positions = positionNodes(scene.nodes, offsets);
      bounds = sceneBounds(scene.nodes, offsets);
      occluders = offsets.map((y) => ({
        y,
        minX: footprint.minX,
        maxX: footprint.maxX,
        minZ: footprint.minZ,
        maxZ: footprint.maxZ,
      }));
      plates.update(offsets, flattenNow);
      nodes.update(positions, contentScale, hoveredKey);
      lines.update(buildPathGeometry(scene, positions).segments);
      layoutDirty = false;
      viewDirty = true;
    }

    // --- camera state ----------------------------------------------------
    function viewportSize() {
      const rect = container!.getBoundingClientRect();
      return { width: Math.max(1, rect.width), height: Math.max(1, rect.height) };
    }

    let orbit: OrbitState = homeView(bounds, 1);
    let framed = false;
    let tween: { from: OrbitState; to: OrbitState; start: number; duration: number } | null = null;
    let navigating = false;
    let settleUntil = 0;
    let pivotHintUntil = 0;
    let lastGesture = -Infinity;
    let offScreenSince: number | null = null;
    let refocusShown = false;

    function setOrbit(next: OrbitState) {
      orbit = next;
      viewDirty = true;
    }

    function animateTo(target: OrbitState, duration = TWEEN_MS) {
      tween = { from: orbit, to: target, start: performance.now(), duration };
    }

    function beginGesture() {
      const now = performance.now();
      if (now - lastGesture > GESTURE_IDLE_MS) onNavigateRef.current?.();
      lastGesture = now;
    }

    function hideRefocus() {
      offScreenSince = null;
      if (refocusShown) {
        refocusShown = false;
        setRefocus(false);
      }
    }

    function doFit() {
      const viewport = viewportSize();
      const aspect = viewport.width / viewport.height;
      animateTo(fitView(orbit, bounds, pathCentroid(scene.nodes, positions), aspect));
      hideRefocus();
    }

    function doSnap(name: SnapName) {
      const viewport = viewportSize();
      animateTo(snapTarget(name, bounds, viewport.width / viewport.height));
      hideRefocus();
    }

    function layoutOverlay(viewport: { width: number; height: number }, slotPx: number) {
      const now = performance.now();
      overlay.update({
        viewport,
        slotPx,
        camera,
        positions,
        contentScale,
        selection: selectionRef.current,
        endpoints: endpointRef.current,
        hovered: hoveredKey,
        path: lines.segments.map((o) => o.segment.points),
        occluders,
        suppressLowPriority: navigating || now < settleUntil,
        pivot: now < pivotHintUntil ? orbit.pivot : null,
      });
    }

    // --- the frame -------------------------------------------------------
    function frame(now: number, dt: number) {
      const viewport = viewportSize();
      if (!framed && viewport.width > 1 && viewport.height > 1) {
        if (layoutDirty) rebuildLayout();
        orbit = homeView(bounds, viewport.width / viewport.height);
        framed = true;
        viewDirty = true;
      }

      if (flattenDuration > 0) {
        const t = easeOut(clamp((now - flattenStart) / flattenDuration, 0, 1));
        for (let i = 0; i < layerCount; i++) {
          flattenNow[i] = flattenFrom[i] + (flattenTo[i] - flattenFrom[i]) * t;
        }
        layoutDirty = true;
        if (t >= 1) flattenDuration = 0;
      }

      if (tween) {
        const t = easeOut(clamp((now - tween.start) / tween.duration, 0, 1));
        orbit = lerpOrbit(tween.from, tween.to, t);
        viewDirty = true;
        if (t >= 1) tween = null;
      }

      if (layoutDirty) rebuildLayout();

      configureCamera(camera, orbit, viewport);
      renderer.setSize(viewport.width, viewport.height, false);
      nodes.outlineMaterial.resolution.set(viewport.width, viewport.height);
      lines.setResolution(viewport.width, viewport.height);
      lines.tick(dt);

      const slotPx = slotPixels(orbit.radius, viewport.height);
      plates.setGridVisible(levelOfDetail(slotPx).grid);

      const chevronScale =
        (CHEVRON_PX * 2 * orbit.radius * Math.tan((FOV / 2) * (Math.PI / 180))) / Math.max(viewport.height, 1);
      lines.setChevronScale(chevronScale);

      // A segment whose two layers are both flattened is hidden.
      lines.applyState(nodes.select(selectionRef.current, positions), flatRef.current);
      renderer.render(three, camera);

      if (viewDirty) {
        layoutOverlay(viewport, slotPx);
        viewDirty = false;
      } else if (performance.now() < settleUntil + 32) {
        // Labels re-solve for LABEL_SETTLE_MS after a gesture.
        layoutOverlay(viewport, slotPx);
      }

      const lost = isSceneOffScreen(bounds, camera);
      if (!lost) {
        hideRefocus();
      } else {
        if (offScreenSince === null) offScreenSince = now;
        if (!refocusShown && now - offScreenSince > REFOCUS_AFTER_MS) {
          refocusShown = true;
          setRefocus(true);
        }
      }

      const cube = cubeRef.current;
      if (cube) cube.style.transform = viewCubeTransform(orbit);
    }

    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = "";
    container.appendChild(renderer.domElement);
    rebuildLayout();
    const loop = createLoop(frame);

    const resizeObserver = new ResizeObserver(() => {
      viewDirty = true;
    });
    resizeObserver.observe(container);

    // --- picking ---------------------------------------------------------
    const raycaster = new THREE.Raycaster();

    function ndcAt(clientX: number, clientY: number) {
      return pointerNdc(clientX, clientY, container!.getBoundingClientRect());
    }

    function nodeKeyAt(clientX: number, clientY: number): string | null {
      raycaster.setFromCamera(ndcAt(clientX, clientY), camera);
      for (const hit of raycaster.intersectObjects(nodes.pickTargets, false)) {
        const nodeKey = nodes.keyForHit(hit);
        if (nodeKey) return nodeKey;
      }
      return null;
    }

    /** The world point under the cursor: the first plate the ray meets, or
     *  the plane through the pivot. */
    function focusPoint(clientX: number, clientY: number): THREE.Vector3 {
      raycaster.setFromCamera(ndcAt(clientX, clientY), camera);
      const hits = raycaster.intersectObjects(plates.surfaces, false);
      if (hits.length > 0) return hits[0].point.clone();
      const plane = new THREE.Plane(new THREE.Vector3(0, 1, 0), -orbit.pivot.y);
      const hit = new THREE.Vector3();
      return raycaster.ray.intersectPlane(plane, hit) ?? orbit.pivot.clone();
    }

    const controller: CameraController = {
      orbit: () => orbit,
      setOrbit,
      animateTo: (target) => animateTo(target),
      viewport: viewportSize,
      focusPoint,
      nodeKeyAt,
      nodePosition: (nodeKey) => positions.get(nodeKey)?.position,
      pick(clientX, clientY) {
        const nodeKey = nodeKeyAt(clientX, clientY);
        const node = nodeKey ? nodes.node(nodeKey) : undefined;
        if (!node) return;
        const hop = findHopForNode(result.hops, node);
        if (hop) onSelectRef.current({ type: "hop", data: hop });
      },
      hover(nodeKey) {
        if (nodeKey === hoveredKey) return;
        hoveredKey = nodeKey;
        layoutDirty = true;
        viewDirty = true;
      },
      fit: doFit,
      snap: doSnap,
      beginGesture,
      startNavigation(mode) {
        navigating = true;
        beginGesture();
        if (mode === "orbit") pivotHintUntil = performance.now() + PIVOT_HINT_MS;
        viewDirty = true;
      },
      endNavigation() {
        navigating = false;
        settleUntil = performance.now() + LABEL_SETTLE_MS;
        viewDirty = true;
      },
      showPivot(ms) {
        pivotHintUntil = performance.now() + ms;
      },
    };
    const input = createInput(container, controller);

    stageRef.current = {
      fit: doFit,
      snap: doSnap,
      markLayoutDirty: () => {
        const targets = flattenTargets(flatRef.current, layerCount);
        if (flattenTargetsChanged(targets, flattenTo)) {
          flattenFrom = [...flattenNow];
          flattenTo = targets;
          flattenStart = performance.now();
          flattenDuration = TWEEN_MS;
        }
        layoutDirty = true;
        window.setTimeout(doFit, TWEEN_MS);
      },
      onlyLayer: () => {
        window.setTimeout(() => doSnap("top"), TWEEN_MS);
      },
    };

    return () => {
      stageRef.current = null;
      loop.dispose();
      resizeObserver.disconnect();
      input.dispose();
      overlay.dispose();
      lines.dispose();
      nodes.dispose();
      plates.dispose();
      // A disposed renderer holds its WebGL context until garbage collection.
      renderer.forceContextLoss();
      renderer.dispose();
      container.innerHTML = "";
    };
    // `flat`, `density`, `selection`, `onSelect` and `onNavigate` are read through refs.
  }, [scene, result]);

  useEffect(() => {
    stageRef.current?.markLayoutDirty();
  }, [flat, density]);

  if (result.hops.length === 0) {
    return (
      <div className="ribbon-outer">
        <div className="ribbon-empty">{result.detail || "No path"}</div>
      </div>
    );
  }

  if (fallback) {
    return (
      <div className="ribbon-outer">
        <div className="ribbon-empty">{fallback}</div>
      </div>
    );
  }

  return (
    <div className="ribbon-outer st-outer" ref={outerRef}>
      <div className="rb-controls st-controls" role="group" aria-label="Strata view controls">
        <div className="segs st-layer-segs">
          {STRATA_LAYERS.map((name, i) => (
            <button
              key={name}
              type="button"
              className={flat.has(i) ? "st-layer-chip" : "st-layer-chip on"}
              aria-pressed={!flat.has(i)}
              onClick={(e) => {
                if (e.shiftKey) {
                  setFlat((f) => isolateLayer(f, i, STRATA_LAYERS.length));
                  stageRef.current?.onlyLayer(i);
                } else {
                  setFlat((f) => toggleLayer(f, i));
                }
              }}
            >
              <span className={`st-layer-dot l${i}`} aria-hidden="true" />
              {name}
            </button>
          ))}
        </div>
        <button
          type="button"
          className="rb-fitbtn"
          onClick={() => stageRef.current?.fit()}
        >
          Fit
        </button>
        <button
          type="button"
          className="rb-fitbtn"
          onClick={() => stageRef.current?.snap("home")}
        >
          Home
        </button>
        <label className="st-density">
          Density
          <input
            type="range"
            min={DENSITY_MIN}
            max={DENSITY_MAX}
            step={DENSITY_STEP}
            value={density}
            onChange={(e) => setDensity(Number(e.target.value))}
            aria-label="Layer spacing"
          />
        </label>
      </div>
      {lanes.length > 0 && (
        <ul className="st-lanes" aria-label="Lanes not forwarded or not decided">
          {lanes.map((l) => (
            <li key={l.lane} className={"st-lane " + l.outcome} title={l.detail}>
              {l.src_label ? `${l.src_label}: ` : ""}
              {l.word}
            </li>
          ))}
        </ul>
      )}
      <div className="st-stage">
        {/* The lint rule's interactive-role allowlist does not include `role="application"`. */}
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
        <div className="st-canvas" ref={canvasRef} tabIndex={0} role="application" aria-label="Strata trace view" />
        <div className="st-overlay" ref={overlayRef}>
          <div className="st-pivot" ref={pivotRef} aria-hidden="true" />
          {scene.nodes.map((node) => {
            const nodeKey = sceneStationKey(node);
            return (
              <div
                key={`badge:${nodeKey}`}
                className={"st-badge" + (node.dimmed ? " off" : "")}
                ref={(el) => {
                  if (el) badgeRefs.current.set(nodeKey, el);
                  else badgeRefs.current.delete(nodeKey);
                }}
                aria-hidden="true"
              >
                {node.rank + 1}
              </div>
            );
          })}
          {scene.nodes.map((node) => {
            const nodeKey = sceneStationKey(node);
            return (
              <div
                key={`leader:${nodeKey}`}
                className={"st-leader" + (node.dimmed ? " off" : "")}
                ref={(el) => {
                  if (el) leaderRefs.current.set(nodeKey, el);
                  else leaderRefs.current.delete(nodeKey);
                }}
                aria-hidden="true"
              />
            );
          })}
          {scene.nodes.map((node) => {
            const nodeKey = sceneStationKey(node);
            const selected = isSelectedNode(selection, node);
            return (
              <div
                key={nodeKey}
                ref={(el) => {
                  if (el) labelRefs.current.set(nodeKey, el);
                  else labelRefs.current.delete(nodeKey);
                }}
                className={
                  "st-label" +
                  (MONO_KINDS.has(node.kind) ? " mono" : "") +
                  (selected ? " selected" : "") +
                  (node.dimmed ? " off" : "")
                }
              >
                {node.verdict ? (
                  <span className={`st-verdict ${node.verdict}`}>{VERDICT_WORD[node.verdict]}</span>
                ) : null}
                <span className="st-label-head">
                  <span className="st-label-num">{node.rank + 1}</span>
                  <span className="st-label-text">{node.label}</span>
                </span>
                <span className="st-label-kind">
                  <span
                    className="st-kind-dot"
                    style={{ background: `var(--kind-${node.kind}, var(--kind-fallback))` }}
                    aria-hidden="true"
                  />
                  {node.kind}
                </span>
                {(() => {
                  const mark = hopMtuMark(result.mtu, node);
                  return mark ? (
                    <span className="st-label-mtu" title={mark.title}>
                      {mark.text}
                    </span>
                  ) : null;
                })()}
              </div>
            );
          })}
        </div>
        <div className="st-cube" role="group" aria-label="View orientation">
          <div className="st-cube-body" aria-hidden="true">
            <div className="st-cube-inner" ref={cubeRef}>
              <span className="f front" />
              <span className="f back" />
              <span className="f left" />
              <span className="f right" />
              <span className="f top" />
              <span className="f bottom" />
            </div>
          </div>
          <div className="st-cube-snaps">
            {SNAP_BUTTONS.map((snap) => (
              <button
                key={snap.name}
                type="button"
                onClick={() => stageRef.current?.snap(snap.name)}
              >
                {snap.label}
              </button>
            ))}
          </div>
        </div>
        {refocus && (
          <div className="st-toast" role="status">
            <span>Scene off-screen</span>
            <button type="button" onClick={() => stageRef.current?.fit()}>
              Refocus
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
