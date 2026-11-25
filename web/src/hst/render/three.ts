import * as THREE from "three";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { Line2 } from "three/examples/jsm/lines/Line2.js";
import { LineGeometry } from "three/examples/jsm/lines/LineGeometry.js";
import { LineMaterial } from "three/examples/jsm/lines/LineMaterial.js";
import { LineSegments2 } from "three/examples/jsm/lines/LineSegments2.js";
import { LineSegmentsGeometry } from "three/examples/jsm/lines/LineSegmentsGeometry.js";
import { CSS2DObject, CSS2DRenderer } from "three/examples/jsm/renderers/CSS2DRenderer.js";
import { levelOf } from "./camera";
import { areaMaterial, brickTexture, groundMaterial, modelGeometry, nodeGeometry, rackTexture, shadowTexture, symbolTexture, tube } from "./materials";
import { areaIcon } from "./icons";
import { MODELS, type Shape } from "./models";
import { stats } from "./null";
import { Scene, Y, type Batches, type LineBatch } from "./scene";
import { GLOW_PX, LINE_PX, PALETTES, type Palette } from "./style";
import { SYMBOLS, svgOf, type SymbolName } from "./symbols";
import { drawsLine, type CameraState, type FrameStats, type Label, type Level, type Marker, type Renderer, type RouteState, type Viewport } from "./types";

const DISTANCE = 2000;
/** The cross-fade of a level change, in milliseconds. */
export const FADE_MS = 150;
const ROUTE_PX = 7;
/** The share of the route width the core takes; the rest is the halo. */
const ROUTE_CORE = 0.62;
/** The pixel width of an application flow route by state. */
const FLOW_PX: Record<Exclude<RouteState, "trace" | "unresolved">, number> = {
  passes: 5,
  fails: 5,
  decided: 3,
  open: 4,
  "not-evaluated": 3,
};
/** The dash and the gap, in grid units, of the dashed and the dotted flow states. */
const FLOW_DASH: Partial<Record<RouteState, [number, number]>> = {
  open: [0.8, 0.5],
  "not-evaluated": [0.12, 0.35],
};
const SYMBOL_PX = 128;
/** The contact shadow's margin around a model, as a share of the model's footprint. */
const SHADOW_SPREAD = 0.45;
/** The ground grid spacing in grid cells: the smallest power of 4 that is at least this many pixels on the screen. */
const GRID_PX = 36;
/** The sun direction: up and to the back left. */
const SUN = new THREE.Vector3(-0.55, 1, 0.15).normalize();

interface Build {
  objects: THREE.Object3D[];
  materials: THREE.Material[];
  geometries?: THREE.BufferGeometry[];
  /** The ground names, each with its zoom range in `userData.zoom`. */
  texts?: THREE.Mesh[];
}

/** The canvas height of a ground name, in pixels; the canvas width follows the text. */
const NAME_CANVAS_PX = 96;

/** The pixel width of a line batch, from its class and the speed suffix of a cable key. */
function widthOf(l: LineBatch): number {
  if (l.key === "glow:backbone") return GLOW_PX.backbone;
  if (l.key === "glow:selected") return GLOW_PX.selected;
  if (l.cls === "summary") {
    if (l.key.endsWith(":5")) return LINE_PX["summary-5"];
    if (l.key.endsWith(":2")) return LINE_PX["summary-2"];
  }
  if (l.cls === "cable") {
    if (l.key.endsWith(":40g")) return LINE_PX["cable-40g"];
    if (l.key.endsWith(":10g")) return LINE_PX["cable-10g"];
  }
  return LINE_PX[l.cls];
}

/** The line material of a route state: the trace with its halo, each flow state with its own pattern. */
function routeMaterial(state: RouteState, palette: Palette): LineMaterial {
  if (state === "trace") return haloMaterial(palette.route, palette.routeHalo, ROUTE_PX);
  const color =
    state === "passes"
      ? palette.route
      : state === "fails"
        ? palette.failed
        : state === "decided" || state === "open"
          ? palette.changed
          : palette.unknown;
  const m = new LineMaterial({ color, linewidth: state === "unresolved" ? 1 : FLOW_PX[state] });
  const dash = FLOW_DASH[state];
  if (dash) {
    m.dashed = true;
    m.dashSize = dash[0];
    m.gapSize = dash[1];
  }
  return m;
}

/** A line material whose outer band across the width draws in `halo`. */
function haloMaterial(core: number, halo: number, width: number): LineMaterial {
  const m = new LineMaterial({ color: core, linewidth: width });
  const haloColor = new THREE.Color(halo);
  m.onBeforeCompile = (shader) => {
    shader.uniforms.haloColor = { value: haloColor };
    shader.uniforms.coreShare = { value: ROUTE_CORE };
    shader.fragmentShader = shader.fragmentShader
      .replace("void main() {", "uniform vec3 haloColor;\nuniform float coreShare;\nvoid main() {")
      .replace(
        "gl_FragColor = vec4( diffuseColor.rgb, alpha );",
        [
          "float edge = abs( vUv.x );",
          "if ( abs( vUv.y ) > 1.0 ) { float cap = ( vUv.y > 0.0 ) ? vUv.y - 1.0 : vUv.y + 1.0; edge = sqrt( vUv.x * vUv.x + cap * cap ); }",
          "gl_FragColor = vec4( mix( diffuseColor.rgb, haloColor, step( coreShare, edge ) ), alpha );",
        ].join("\n"),
      );
  };
  m.userData.halo = haloColor;
  return m;
}

/** The WebGL backend: one instanced mesh per element class, one fat line buffer per line batch. */
export function createThreeRenderer(container: HTMLElement): Renderer {
  const scene = new Scene();
  const gl = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  gl.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  gl.toneMapping = THREE.NeutralToneMapping;
  gl.domElement.className = "hst-canvas-gl";
  container.appendChild(gl.domElement);
  const css = new CSS2DRenderer();
  css.domElement.className = "hst-labels";
  container.appendChild(css.domElement);

  const world = new THREE.Scene();
  const pickWorld = new THREE.Scene();
  const labelRoot = new THREE.Group();
  world.add(labelRoot);
  const pmrem = new THREE.PMREMGenerator(gl);
  const environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  pmrem.dispose();
  world.environment = environment;
  world.environmentIntensity = 0.7;
  world.add(new THREE.HemisphereLight(0xffffff, 0x9fb0c8, 0.8));
  const sun = new THREE.DirectionalLight(0xffffff, 1.3);
  world.add(sun);
  world.add(sun.target);
  const ground = new THREE.Mesh(new THREE.PlaneGeometry(1, 1).rotateX(-Math.PI / 2), groundMaterial());
  ground.renderOrder = -2;
  ground.frustumCulled = false;
  world.add(ground);
  const bricks = brickTexture();
  const racks = rackTexture();
  const shade = shadowTexture();
  let background = "";

  const camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 1, 4 * DISTANCE);
  const unit = new THREE.BoxGeometry(1, 1, 1).translate(0.5, 0.5, 0.5);
  const quad = new THREE.PlaneGeometry(1, 1).rotateX(-Math.PI / 2);
  const shapes = new Map<Shape, THREE.BufferGeometry>();
  const shapeOf = (shape: Shape) => {
    let g = shapes.get(shape);
    if (!g) shapes.set(shape, (g = modelGeometry(shape)));
    return g;
  };
  const dot = new THREE.SphereGeometry(0.5, 16, 10).translate(0.5, 0.5, 0.5);
  const flat = new THREE.MeshBasicMaterial();
  const target = new THREE.WebGLRenderTarget(1, 1);
  const pixel = new Uint8Array(4);
  const resolution = new THREE.Vector2(1, 1);

  const textures = new Map<SymbolName, THREE.Texture>();
  let pendingSymbols = 0;
  for (const name of Object.keys(SYMBOLS) as SymbolName[]) {
    if (typeof Image === "undefined") break;
    pendingSymbols += 1;
    const image = new Image(SYMBOL_PX, SYMBOL_PX);
    image.onload = () => {
      const texture = symbolTexture(image, SYMBOL_PX);
      texture.anisotropy = gl.capabilities.getMaxAnisotropy();
      textures.set(name, texture);
      pendingSymbols -= 1;
      built = null;
    };
    image.onerror = () => {
      pendingSymbols -= 1;
    };
    image.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svgOf(name, SYMBOL_PX))}`;
  }

  const names = new Map<string, { texture: THREE.CanvasTexture; aspect: number }>();
  /** The texture of a ground name and its width per unit of height, drawn once per theme and weight. */
  function nameTexture(text: string, strong: boolean): { texture: THREE.CanvasTexture; aspect: number } {
    const key = `${scene.style.theme}|${strong ? 1 : 0}|${text}`;
    let entry = names.get(key);
    if (entry) return entry;
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d")!;
    const font = `${strong ? 600 : 500} ${NAME_CANVAS_PX}px ${getComputedStyle(container).fontFamily || "sans-serif"}`;
    ctx.font = font;
    const pad = NAME_CANVAS_PX * 0.1;
    canvas.width = Math.ceil(ctx.measureText(text).width + 2 * pad);
    canvas.height = Math.ceil(NAME_CANVAS_PX * 1.25);
    ctx.font = font;
    ctx.fillStyle = `#${PALETTES[scene.style.theme].name.toString(16).padStart(6, "0")}`;
    ctx.textBaseline = "alphabetic";
    ctx.fillText(text, pad, NAME_CANVAS_PX);
    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    texture.anisotropy = gl.capabilities.getMaxAnisotropy();
    entry = { texture, aspect: canvas.width / canvas.height };
    names.set(key, entry);
    return entry;
  }

  let built: { version: number; level: Level } | null = null;
  let current: Build = { objects: [], materials: [] };
  let leaving: { build: Build; start: number } | null = null;
  let fadeStart = 0;
  let pickObjects: THREE.InstancedMesh[] = [];
  let pickIds: string[] = [];
  let routeLines: Line2[] = [];
  let routeMaterials = new Map<RouteState, LineMaterial>();
  let routeKey: unknown = null;
  let routeTheme = "";
  let cam: CameraState = { u: 0, v: 0, zoom: 1 };
  let vp: Viewport = { width: 1, height: 1 };
  const labelObjects = new Map<string, CSS2DObject>();
  const markerObjects = new Map<string, CSS2DObject>();

  const color = new THREE.Color();
  const matrix = new THREE.Matrix4();
  const position = new THREE.Vector3();
  const scale = new THREE.Vector3();
  const rotation = new THREE.Quaternion();

  function dispose(b: Build): void {
    for (const o of b.objects) {
      world.remove(o);
      if (o instanceof THREE.InstancedMesh) o.dispose();
      if (o instanceof LineSegments2) o.geometry.dispose();
    }
    for (const m of b.materials) m.dispose();
    for (const g of b.geometries ?? []) g.dispose();
  }

  function clearPick(): void {
    for (const o of pickObjects) {
      pickWorld.remove(o);
      o.dispose();
    }
    pickObjects = [];
    pickIds = [];
  }

  function lines(batches: LineBatch[], b: Build): void {
    for (const l of batches) {
      if (l.ids.length === 0) continue;
      const geometry = new LineSegmentsGeometry();
      geometry.setPositions(l.positions);
      const colors = new Float32Array(l.colors.length);
      for (let i = 0; i < l.colors.length; i += 3) {
        color.setRGB(l.colors[i], l.colors[i + 1], l.colors[i + 2], THREE.SRGBColorSpace);
        colors[i] = color.r;
        colors[i + 1] = color.g;
        colors[i + 2] = color.b;
      }
      geometry.setColors(colors);
      const material = tube(new LineMaterial({ vertexColors: true, linewidth: widthOf(l) }));
      material.resolution.copy(resolution);
      if (l.key === "glow:selected") {
        material.userData.base = 0.55;
        material.transparent = true;
        material.opacity = material.userData.base;
        material.depthWrite = false;
      }
      const segments = new LineSegments2(geometry, material);
      segments.frustumCulled = false;
      world.add(segments);
      b.objects.push(segments);
      b.materials.push(material);
    }
  }

  function build(batches: Batches): Build {
    clearPick();
    const b: Build = { objects: [], materials: [], geometries: [] };
    const solid = new THREE.MeshStandardMaterial({ roughness: 0.95, metalness: 0 });
    const gloss = { vertexColors: true, roughness: 0.34, metalness: 0, clearcoat: 0.8, clearcoatRoughness: 0.22 };
    const shiny = new THREE.MeshPhysicalMaterial(gloss);
    const brick = new THREE.MeshPhysicalMaterial({ ...gloss, map: bricks });
    const rack = new THREE.MeshPhysicalMaterial({ ...gloss, map: racks });
    const plain = new THREE.MeshPhysicalMaterial({ roughness: 0.4, metalness: 0, clearcoat: 0.5 });
    const nodeMaterial = new THREE.MeshStandardMaterial({ vertexColors: true, roughness: 0.3, metalness: 0 });
    const nodeShape = nodeGeometry(new THREE.Color(PALETTES[scene.style.theme].line));
    const shadows = new THREE.MeshBasicMaterial({ map: shade, transparent: true, depthWrite: false, color: 0x0a1a33 });
    const areas = areaMaterial();
    b.materials.push(solid, shiny, brick, rack, plain, nodeMaterial, shadows, areas);
    b.geometries = [nodeShape];
    const a = batches.areas;
    if (a.ids.length > 0) {
      const g = new THREE.InstancedBufferGeometry();
      g.setIndex(quad.index ? quad.index.clone() : null);
      g.setAttribute("position", quad.getAttribute("position").clone());
      g.translate(0.5, 0, 0.5);
      const tints = new Float32Array(a.colors.length);
      for (let i = 0; i < a.colors.length; i += 3) {
        color.setRGB(a.colors[i], a.colors[i + 1], a.colors[i + 2], THREE.SRGBColorSpace);
        tints.set([color.r, color.g, color.b], i);
      }
      g.setAttribute("aRect", new THREE.InstancedBufferAttribute(new Float32Array(a.data), 4));
      g.setAttribute("aTint", new THREE.InstancedBufferAttribute(tints, 3));
      g.setAttribute("aKind", new THREE.InstancedBufferAttribute(new Float32Array(a.kinds), 1));
      g.setAttribute("aSel", new THREE.InstancedBufferAttribute(new Float32Array(a.selected), 1));
      g.instanceCount = a.ids.length;
      const mesh = new THREE.Mesh(g, areas);
      mesh.position.y = Y.plateTop;
      mesh.renderOrder = -1;
      mesh.frustumCulled = false;
      world.add(mesh);
      b.objects.push(mesh);
      b.geometries.push(g);
    }
    for (const box of batches.boxes) {
      const n = box.ids.length;
      if (n === 0) continue;
      const geometry = box.cls === "node" ? nodeShape : box.cls === "dot" ? dot : unit;
      const unlit = box.cls === "dot" || box.cls === "port" || box.cls === "tier" || box.cls === "segment";
      const material = box.cls === "node" ? nodeMaterial : unlit ? plain : solid;
      const mesh = new THREE.InstancedMesh(geometry, material, n);
      const pick = new THREE.InstancedMesh(unit, flat, n);
      for (let i = 0; i < n; i++) {
        const o = i * 6;
        position.set(box.data[o], box.data[o + 1], box.data[o + 2]);
        scale.set(box.data[o + 3], Math.max(box.data[o + 4], 1e-3), box.data[o + 5]);
        matrix.compose(position, rotation, scale);
        mesh.setMatrixAt(i, matrix);
        if (box.cls === "node") mesh.setColorAt(i, color.setRGB(1, 1, 1));
        else mesh.setColorAt(i, color.setRGB(box.colors[i * 3], box.colors[i * 3 + 1], box.colors[i * 3 + 2], THREE.SRGBColorSpace));
        const id = pickIds.length + 1;
        pickIds.push(box.ids[i]);
        pick.setColorAt(i, color.setRGB(((id >> 16) & 255) / 255, ((id >> 8) & 255) / 255, (id & 255) / 255, THREE.LinearSRGBColorSpace));
      }
      pick.instanceMatrix = mesh.instanceMatrix;
      mesh.frustumCulled = false;
      pick.frustumCulled = false;
      if (box.proxy) {
        mesh.dispose();
        if (box.cls === "device" || box.cls === "context") {
          pick.dispose();
          pickIds.length -= n;
        } else {
          pickWorld.add(pick);
          pickObjects.push(pick);
        }
        continue;
      }
      pickWorld.add(pick);
      pickObjects.push(pick);
      world.add(mesh);
      b.objects.push(mesh);
    }
    for (const m of batches.models) {
      const n = m.ids.length;
      if (n === 0) continue;
      const material = m.name === "firewall" ? brick : m.name === "server" ? rack : shiny;
      const mesh = new THREE.InstancedMesh(shapeOf(MODELS[m.name].shape), material, n);
      const under = new THREE.InstancedMesh(quad, shadows, n);
      for (let i = 0; i < n; i++) {
        const o = i * 6;
        const spread = Math.max(m.data[o + 3], m.data[o + 5]) * SHADOW_SPREAD;
        position.set(m.data[o] + m.data[o + 3] / 2, Y.bandTop + 0.004, m.data[o + 2] + m.data[o + 5] / 2);
        scale.set(m.data[o + 3] + 2 * spread, 1, m.data[o + 5] + 2 * spread);
        matrix.compose(position, rotation, scale);
        under.setMatrixAt(i, matrix);
      }
      under.frustumCulled = false;
      world.add(under);
      b.objects.push(under);
      for (let i = 0; i < n; i++) {
        const o = i * 6;
        position.set(m.data[o], m.data[o + 1], m.data[o + 2]);
        scale.set(m.data[o + 3], m.data[o + 4], m.data[o + 5]);
        matrix.compose(position, rotation, scale);
        mesh.setMatrixAt(i, matrix);
        mesh.setColorAt(i, color.setRGB(m.colors[i * 3], m.colors[i * 3 + 1], m.colors[i * 3 + 2], THREE.SRGBColorSpace));
      }
      const pick = new THREE.InstancedMesh(mesh.geometry, flat, n);
      pick.instanceMatrix = mesh.instanceMatrix;
      for (let i = 0; i < n; i++) {
        const id = pickIds.length + 1;
        pickIds.push(m.ids[i]);
        pick.setColorAt(i, color.setRGB(((id >> 16) & 255) / 255, ((id >> 8) & 255) / 255, (id & 255) / 255, THREE.LinearSRGBColorSpace));
      }
      mesh.frustumCulled = false;
      pick.frustumCulled = false;
      world.add(mesh);
      pickWorld.add(pick);
      pickObjects.push(pick);
      b.objects.push(mesh);
    }
    lines(batches.outlines, b);
    lines(batches.lines, b);
    for (const s of batches.symbols) {
      const texture = textures.get(s.name);
      const n = s.ids.length;
      if (!texture || n === 0) continue;
      const material = new THREE.MeshBasicMaterial({ map: texture, transparent: true, alphaTest: 0.2, depthWrite: false });
      const mesh = new THREE.InstancedMesh(quad, material, n);
      for (let i = 0; i < n; i++) {
        const o = i * 4;
        position.set(s.data[o], s.data[o + 1], s.data[o + 2]);
        scale.set(s.data[o + 3], 1, s.data[o + 3]);
        matrix.compose(position, rotation, scale);
        mesh.setMatrixAt(i, matrix);
        mesh.setColorAt(i, color.setRGB(s.colors[i * 3], s.colors[i * 3 + 1], s.colors[i * 3 + 2], THREE.SRGBColorSpace));
      }
      mesh.frustumCulled = false;
      mesh.renderOrder = 1;
      world.add(mesh);
      b.objects.push(mesh);
      b.materials.push(material);
    }
    b.texts = [];
    for (const t of batches.texts) {
      const { texture, aspect } = nameTexture(t.text, t.strong);
      const material = new THREE.MeshBasicMaterial({ map: texture, transparent: true, depthWrite: false });
      material.userData.base = t.strong ? 0.9 : 0.5;
      const mesh = new THREE.Mesh(quad, material);
      const height = t.size * 1.25;
      const width = height * aspect;
      mesh.position.set(t.u + width / 2, Y.plateTop + 0.02, t.v - height / 2 + t.size * 0.25);
      mesh.scale.set(width, 1, height);
      mesh.userData.zoom = [t.minZoom, t.maxZoom];
      mesh.frustumCulled = false;
      world.add(mesh);
      b.objects.push(mesh);
      b.materials.push(material);
      b.texts.push(mesh);
    }
    return b;
  }

  /** A ground name shows in the zoom range where its letters read. */
  function showNames(b: Build): void {
    for (const mesh of b.texts ?? []) {
      const [lo, hi] = mesh.userData.zoom as [number, number];
      mesh.visible = cam.zoom >= lo && cam.zoom <= hi;
    }
  }

  /** Sets the opacity of a build's materials; 1 makes them opaque again. */
  function fade(b: Build, opacity: number): void {
    for (const m of b.materials) {
      const base = typeof m.userData.base === "number" ? m.userData.base : 1;
      const transparent = (m instanceof THREE.MeshBasicMaterial && m.map !== null) || m instanceof THREE.ShaderMaterial || base < 1 || opacity < 1;
      if (m.transparent !== transparent) {
        m.transparent = transparent;
        m.needsUpdate = true;
      }
      m.opacity = base * opacity;
      if (m instanceof THREE.ShaderMaterial && m.uniforms.uOpacity) m.uniforms.uOpacity.value = opacity;
    }
  }

  function clearRoutes(): void {
    for (const line of routeLines) {
      world.remove(line);
      line.geometry.dispose();
    }
    routeLines = [];
    for (const m of routeMaterials.values()) m.dispose();
    routeMaterials = new Map();
  }

  /** One line per route that draws one, sharing one material per state. */
  function updateRoutes(): void {
    const theme = scene.style.theme;
    if (routeKey === scene.routes && routeTheme === theme) return;
    routeKey = scene.routes;
    routeTheme = theme;
    clearRoutes();
    const palette = PALETTES[theme];
    for (const r of scene.routes) {
      if (!drawsLine(r)) continue;
      let material = routeMaterials.get(r.state);
      if (!material) {
        material = routeMaterial(r.state, palette);
        material.resolution.copy(resolution);
        routeMaterials.set(r.state, material);
      }
      const geometry = new LineGeometry();
      geometry.setPositions(r.points.flatMap((p) => [p.u, Math.max(Y.route, p.y ?? Y.route), p.v]));
      const line = new Line2(geometry, material);
      line.computeLineDistances();
      line.renderOrder = 2;
      world.add(line);
      routeLines.push(line);
    }
  }

  function place<T extends { at: [number, number, number] }>(
    items: T[],
    objects: Map<string, CSS2DObject>,
    keyOf: (item: T, i: number) => string,
    paint: (el: HTMLElement, item: T) => void,
  ): void {
    const seen = new Set<string>();
    items.forEach((item, i) => {
      const key = keyOf(item, i);
      seen.add(key);
      let o = objects.get(key);
      if (!o) {
        o = new CSS2DObject(document.createElement("div"));
        objects.set(key, o);
        labelRoot.add(o);
      }
      paint(o.element, item);
      o.position.set(item.at[0], item.at[1], item.at[2]);
    });
    for (const [key, o] of objects) {
      if (seen.has(key)) continue;
      labelRoot.remove(o);
      o.element.remove();
      objects.delete(key);
    }
  }

  function updateLabels(labels: Label[], markers: Marker[]): void {
    place(
      labels,
      labelObjects,
      (l) => `${l.kind}:${l.uid}`,
      (el, l) => {
        el.className = `hst-label hst-label-${l.kind}${l.sub !== undefined ? " hst-card" : ""}`;
        if (l.sub === undefined) {
          el.textContent = l.text;
          return;
        }
        const chip = document.createElement("span");
        chip.className = "hst-card-chip";
        if (l.tint !== undefined) chip.style.color = `#${l.tint.toString(16).padStart(6, "0")}`;
        chip.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">${areaIcon(l.icon)}</svg>`;
        const title = document.createElement("span");
        title.className = "hst-card-title";
        title.textContent = l.text;
        const sub = document.createElement("span");
        sub.className = "hst-card-sub";
        sub.textContent = l.sub;
        el.replaceChildren(chip, title, sub);
      },
    );
    place(
      markers,
      markerObjects,
      (_, i) => String(i),
      (el, m) => {
        el.className = `hst-marker hst-marker-${m.kind}`;
        el.textContent = m.text;
      },
    );
  }

  function placeCamera(): void {
    const w = vp.width / cam.zoom / 2;
    const h = vp.height / cam.zoom / 2;
    camera.left = -w;
    camera.right = w;
    camera.top = h;
    camera.bottom = -h;
    if (cam.view === "top") {
      camera.position.set(cam.u, DISTANCE, cam.v);
      camera.up.set(0, 0, -1);
    } else {
      camera.position.set(cam.u + DISTANCE, DISTANCE, cam.v + DISTANCE);
      camera.up.set(0, 1, 0);
    }
    camera.lookAt(cam.u, 0, cam.v);
    camera.updateProjectionMatrix();
    sun.target.position.set(cam.u, 0, cam.v);
    sun.position.set(cam.u + SUN.x * DISTANCE, SUN.y * DISTANCE, cam.v + SUN.z * DISTANCE);
    const reach = (1.5 * Math.max(vp.width, vp.height)) / cam.zoom;
    ground.position.set(cam.u, 0, cam.v);
    ground.scale.set(2 * reach, 1, 2 * reach);
    const g = ground.material as THREE.ShaderMaterial;
    let spacing = 1;
    while (spacing * cam.zoom < GRID_PX) spacing *= 4;
    g.uniforms.uSpacing.value = spacing;
    g.uniforms.uCenter.value.set(cam.u, cam.v);
    g.uniforms.uReach.value = reach;
  }

  /** Takes the page background and the grid colour of the theme in force. */
  function paintGround(): void {
    const bg = getComputedStyle(container).getPropertyValue("--bg").trim();
    const key = `${bg}|${scene.style.theme}`;
    if (key === background) return;
    background = key;
    world.background = bg ? new THREE.Color(bg) : null;
    (ground.material as THREE.ShaderMaterial).uniforms.uColor.value.set(PALETTES[scene.style.theme].grid);
  }

  return {
    setTier: (name, rows, tile) => scene.setTier(name, rows, tile),
    applyDelta: (name, changes, tile) => scene.applyDelta(name, changes, tile),
    dropTile: (tile) => scene.dropTile(tile),
    setRoutes: (routes) => scene.setRoutes(routes),
    setStyle: (style) => scene.setStyle(style),
    setCamera(next, viewport) {
      cam = next;
      if (viewport.width !== vp.width || viewport.height !== vp.height) {
        gl.setSize(viewport.width, viewport.height);
        css.setSize(viewport.width, viewport.height);
        resolution.set(viewport.width, viewport.height);
        for (const b of [current, leaving?.build]) {
          for (const m of b?.materials ?? []) if (m instanceof LineMaterial) m.resolution.copy(resolution);
        }
        for (const m of routeMaterials.values()) m.resolution.copy(resolution);
      }
      vp = viewport;
      placeCamera();
    },
    pick(x, y) {
      let hit: string | null = null;
      if (pickObjects.length > 0) {
        camera.setViewOffset(vp.width, vp.height, Math.floor(x), Math.floor(y), 1, 1);
        gl.setRenderTarget(target);
        gl.setClearColor(0x000000, 0);
        gl.clear();
        gl.render(pickWorld, camera);
        gl.setRenderTarget(null);
        camera.clearViewOffset();
        gl.readRenderTargetPixels(target, 0, 0, 1, 1, pixel);
        const id = (pixel[0] << 16) | (pixel[1] << 8) | pixel[2];
        hit = id > 0 ? (pickIds[id - 1] ?? null) : null;
      }
      const kind = hit ? scene.layout.get(hit)?.kind : undefined;
      if (kind === "device" || kind === "port" || (hit !== null && kind === undefined)) return hit;
      return scene.pickLine(cam, vp, x, y, levelOf(cam.zoom)) ?? hit;
    },
    frame(): FrameStats {
      const level = levelOf(cam.zoom);
      const now = performance.now();
      if (!built || built.version !== scene.version || built.level !== level) {
        const levelChange = built !== null && built.level !== level;
        if (leaving) dispose(leaving.build);
        leaving = null;
        if (levelChange) {
          leaving = { build: current, start: now };
        } else {
          dispose(current);
        }
        current = build(scene.batches(level));
        fadeStart = levelChange ? now : 0;
        built = { version: scene.version, level };
      }
      const t = fadeStart ? Math.min(1, (now - fadeStart) / FADE_MS) : 1;
      fade(current, t);
      showNames(current);
      if (leaving) showNames(leaving.build);
      if (leaving) {
        if (t >= 1) {
          dispose(leaving.build);
          leaving = null;
        } else {
          fade(leaving.build, 1 - t);
        }
      }
      updateRoutes();
      paintGround();
      const s = stats(scene, cam, vp);
      updateLabels(s.labels, s.markers);
      gl.render(world, camera);
      css.render(world, camera);
      return { ...s, animating: t < 1 || pendingSymbols > 0 };
    },
    dispose() {
      dispose(current);
      if (leaving) dispose(leaving.build);
      clearPick();
      for (const o of labelObjects.values()) o.element.remove();
      for (const o of markerObjects.values()) o.element.remove();
      for (const texture of textures.values()) texture.dispose();
      for (const { texture } of names.values()) texture.dispose();
      unit.dispose();
      quad.dispose();
      for (const g of shapes.values()) g.dispose();
      dot.dispose();
      for (const t of [bricks, racks, shade]) t.dispose();
      ground.geometry.dispose();
      (ground.material as THREE.Material).dispose();
      environment.dispose();
      flat.dispose();
      clearRoutes();
      target.dispose();
      // A disposed renderer holds its WebGL context until garbage collection.
      gl.forceContextLoss();
      gl.dispose();
      gl.domElement.remove();
      css.domElement.remove();
    },
  };
}

/** Whether the browser can create a WebGL context. */
export function webglAvailable(): boolean {
  try {
    const canvas = document.createElement("canvas");
    return Boolean(canvas.getContext("webgl2") ?? canvas.getContext("webgl"));
  } catch {
    return false;
  }
}
