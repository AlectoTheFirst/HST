/**
 * The hop prisms.
 */

import * as THREE from "three";
import { LineMaterial } from "three/examples/jsm/lines/LineMaterial.js";
import { LineSegments2 } from "three/examples/jsm/lines/LineSegments2.js";
import { LineSegmentsGeometry } from "three/examples/jsm/lines/LineSegmentsGeometry.js";
import type { Selection } from "../../selection";
import type { SceneNode } from "../scene";
import {
  CONTACT_SHADOW_OPACITY,
  CONTACT_SHADOW_RADIUS,
  HEX_RADIUS,
  HEX_THICKNESS,
  OFF_PATH_DESATURATION,
  OFF_PATH_OPACITY,
  desaturate,
  hexCorners,
  isSelectedNode,
  parseCssColor,
  resolveKindColor,
  sceneStationKey,
  toHexColor,
  type PositionedNode,
} from "../view-helpers";
import { HOVER_SCALE, ORDER, SELECT_OUTLINE_WIDTH, disposeBag, newBag } from "./common";

const SHADOW_TEXTURE_PX = 64;

interface NodeSlot {
  node: SceneNode;
  /** Which instanced mesh holds it, and where. */
  group: "path" | "offPath";
  index: number;
}

export function hexPrismGeometry(): THREE.ExtrudeGeometry {
  const shape = new THREE.Shape(hexCorners(HEX_RADIUS).map(([x, z]) => new THREE.Vector2(x, z)));
  const geometry = new THREE.ExtrudeGeometry(shape, { depth: HEX_THICKNESS, bevelEnabled: false });
  geometry.rotateX(-Math.PI / 2);
  geometry.computeBoundingBox();
  const minY = geometry.boundingBox?.min.y ?? 0;
  geometry.translate(0, -minY, 0); // base on y=0, extruding upward
  return geometry;
}

/** The rim of a path node: a flat hexagonal annulus laid
 *  on the node's top face, in the accent colour. */
function hexRimGeometry(): THREE.ShapeGeometry {
  const outer = new THREE.Shape(hexCorners(HEX_RADIUS * 1.16).map(([x, z]) => new THREE.Vector2(x, z)));
  outer.holes.push(new THREE.Path(hexCorners(HEX_RADIUS * 1.02).map(([x, z]) => new THREE.Vector2(x, z))));
  const geometry = new THREE.ShapeGeometry(outer);
  geometry.rotateX(-Math.PI / 2);
  return geometry;
}

/**
 * The contact-shadow sprite: a soft radial gradient, opaque at the centre
 * and transparent at the rim.
 *
 * Returns null where no 2D canvas context exists.
 */
function contactShadowTexture(): THREE.CanvasTexture | null {
  const canvas = document.createElement("canvas");
  canvas.width = SHADOW_TEXTURE_PX;
  canvas.height = SHADOW_TEXTURE_PX;
  const ctx = canvas.getContext("2d");
  if (!ctx) return null;
  const half = SHADOW_TEXTURE_PX / 2;
  const gradient = ctx.createRadialGradient(half, half, 0, half, half, half);
  gradient.addColorStop(0, "rgba(0,0,0,1)");
  gradient.addColorStop(0.45, "rgba(0,0,0,0.62)");
  gradient.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, SHADOW_TEXTURE_PX, SHADOW_TEXTURE_PX);
  return new THREE.CanvasTexture(canvas);
}

export interface NodesRuntime {
  /** The node at a raycast hit on one of `pickTargets`, by station key. */
  keyForHit(hit: THREE.Intersection): string | null;
  pickTargets: THREE.Object3D[];
  node(key: string): SceneNode | undefined;
  /** The selection outline's material, which needs the viewport resolution. */
  outlineMaterial: LineMaterial;
  /** Place every instance. `contentScale(layer)` shrinks the nodes of a
   *  plate on its way flat; `hovered` scales one node up. */
  update(
    positions: ReadonlyMap<string, PositionedNode>,
    contentScale: (layer: number) => number,
    hovered: string | null,
  ): void;
  select(selection: Selection | null, positions: ReadonlyMap<string, PositionedNode>): string | null;
  dispose(): void;
}

export function createNodes(
  three: THREE.Scene,
  nodes: readonly SceneNode[],
  container: HTMLElement,
  accent: THREE.Color,
): NodesRuntime {
  const bag = newBag();
  const prism = hexPrismGeometry();
  bag.geometries.push(prism);
  const pathNodes = nodes.filter((n) => !n.dimmed);
  const offPathNodes = nodes.filter((n) => n.dimmed);

  const nodeMaterial = new THREE.MeshLambertMaterial({});
  // Off-path nodes drop to 25% opacity.
  const offPathMaterial = new THREE.MeshLambertMaterial({
    transparent: true,
    opacity: OFF_PATH_OPACITY,
    depthWrite: false,
  });
  bag.materials.push(nodeMaterial, offPathMaterial);

  const pathMesh = new THREE.InstancedMesh(prism, nodeMaterial, Math.max(pathNodes.length, 1));
  const offPathMesh = new THREE.InstancedMesh(prism, offPathMaterial, Math.max(offPathNodes.length, 1));
  pathMesh.count = pathNodes.length;
  offPathMesh.count = offPathNodes.length;
  pathMesh.renderOrder = ORDER.node;
  offPathMesh.renderOrder = ORDER.node;
  pathMesh.frustumCulled = false;
  offPathMesh.frustumCulled = false;
  three.add(pathMesh);
  three.add(offPathMesh);

  // One soft contact shadow per node, laid flat on the plate it stands on.
  const shadowTexture = contactShadowTexture();
  const shadowGeometry = new THREE.PlaneGeometry(CONTACT_SHADOW_RADIUS * 2, CONTACT_SHADOW_RADIUS * 2);
  shadowGeometry.rotateX(-Math.PI / 2);
  bag.geometries.push(shadowGeometry);
  const shadowMaterial = new THREE.MeshBasicMaterial({
    color: 0x000000,
    map: shadowTexture ?? undefined,
    transparent: true,
    opacity: CONTACT_SHADOW_OPACITY,
    depthWrite: false,
  });
  bag.materials.push(shadowMaterial);
  const shadowMesh = new THREE.InstancedMesh(shadowGeometry, shadowMaterial, Math.max(nodes.length, 1));
  shadowMesh.count = shadowTexture ? nodes.length : 0;
  shadowMesh.renderOrder = ORDER.shadow;
  shadowMesh.frustumCulled = false;
  three.add(shadowMesh);

  const rimGeometry = hexRimGeometry();
  bag.geometries.push(rimGeometry);
  const rimMaterial = new THREE.MeshBasicMaterial({
    color: accent.clone(),
    transparent: true,
    opacity: 0.8,
    depthWrite: false,
    side: THREE.DoubleSide,
  });
  bag.materials.push(rimMaterial);
  const rimMesh = new THREE.InstancedMesh(rimGeometry, rimMaterial, Math.max(pathNodes.length, 1));
  rimMesh.count = pathNodes.length;
  rimMesh.renderOrder = ORDER.node;
  rimMesh.frustumCulled = false;
  three.add(rimMesh);

  const slots = new Map<string, NodeSlot>();
  const nodeByGroupIndex = new Map<string, SceneNode>();
  /** Each node's undimmed kind colour, kept for the hover restore below. */
  const fullColorByKey = new Map<string, THREE.Color>();
  function registerGroup(group: SceneNode[], name: "path" | "offPath", mesh: THREE.InstancedMesh) {
    group.forEach((node, index) => {
      const nodeKey = sceneStationKey(node);
      slots.set(nodeKey, { node, group: name, index });
      nodeByGroupIndex.set(`${name}:${index}`, node);
      const base = parseCssColor(resolveKindColor(node.kind, container)) ?? { r: 139, g: 143, b: 150 };
      fullColorByKey.set(nodeKey, new THREE.Color(toHexColor(base)));
      const shown = name === "offPath" ? desaturate(base, OFF_PATH_DESATURATION) : base;
      mesh.setColorAt(index, new THREE.Color(toHexColor(shown)));
    });
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
  }
  registerGroup(pathNodes, "path", pathMesh);
  registerGroup(offPathNodes, "offPath", offPathMesh);

  /** The shadow indices are in scene order. */
  const shadowIndexByKey = new Map<string, number>();
  nodes.forEach((node, i) => shadowIndexByKey.set(sceneStationKey(node), i));

  /** A hovered off-path node shows at full opacity. */
  const hoverMaterial = new THREE.MeshLambertMaterial({});
  bag.materials.push(hoverMaterial);
  const hoverMesh = new THREE.Mesh(prism, hoverMaterial);
  hoverMesh.renderOrder = ORDER.node;
  hoverMesh.visible = false;
  three.add(hoverMesh);

  const prismEdges = new THREE.EdgesGeometry(prism);
  bag.geometries.push(prismEdges);
  const outlineGeometry = new LineSegmentsGeometry().fromEdgesGeometry(prismEdges);
  const outlineMaterial = new LineMaterial({
    color: accent.getHex(),
    linewidth: SELECT_OUTLINE_WIDTH,
    transparent: true,
    depthTest: false,
  });
  bag.geometries.push(outlineGeometry);
  bag.materials.push(outlineMaterial);
  const outline = new LineSegments2(outlineGeometry, outlineMaterial);
  outline.renderOrder = ORDER.outline;
  outline.visible = false;
  three.add(outline);

  const dummy = new THREE.Object3D();

  return {
    pickTargets: [pathMesh, offPathMesh],
    keyForHit(hit) {
      const group = hit.object === pathMesh ? "path" : hit.object === offPathMesh ? "offPath" : null;
      if (!group) return null;
      const node = nodeByGroupIndex.get(`${group}:${hit.instanceId ?? -1}`);
      return node ? sceneStationKey(node) : null;
    },
    node: (key) => slots.get(key)?.node,
    outlineMaterial,
    update(positions, contentScale, hovered) {
      for (const [nodeKey, slot] of slots) {
        const position = positions.get(nodeKey)?.position;
        if (!position) continue;
        const mesh = slot.group === "path" ? pathMesh : offPathMesh;
        const scale = contentScale(slot.node.layer) * (hovered === nodeKey ? HOVER_SCALE : 1);
        dummy.position.copy(position);
        dummy.scale.setScalar(scale);
        dummy.rotation.set(0, 0, 0);
        dummy.updateMatrix();
        mesh.setMatrixAt(slot.index, dummy.matrix);
        if (slot.group === "path") {
          dummy.position.set(position.x, position.y + HEX_THICKNESS + 0.012, position.z);
          dummy.updateMatrix();
          rimMesh.setMatrixAt(slot.index, dummy.matrix);
        }
        const shadowIndex = shadowIndexByKey.get(nodeKey);
        if (shadowIndex !== undefined) {
          dummy.position.set(position.x, position.y + 0.006, position.z);
          dummy.scale.setScalar(contentScale(slot.node.layer));
          dummy.updateMatrix();
          shadowMesh.setMatrixAt(shadowIndex, dummy.matrix);
        }
      }
      pathMesh.instanceMatrix.needsUpdate = true;
      offPathMesh.instanceMatrix.needsUpdate = true;
      rimMesh.instanceMatrix.needsUpdate = true;
      shadowMesh.instanceMatrix.needsUpdate = true;
      pathMesh.computeBoundingSphere();
      offPathMesh.computeBoundingSphere();

      const hoveredSlot = hovered ? slots.get(hovered) : undefined;
      const hoveredAt = hovered ? positions.get(hovered)?.position : undefined;
      if (hoveredSlot && hoveredSlot.group === "offPath" && hovered && hoveredAt) {
        hoverMesh.position.copy(hoveredAt);
        hoverMesh.scale.setScalar(contentScale(hoveredSlot.node.layer) * HOVER_SCALE);
        hoverMaterial.color.copy(fullColorByKey.get(hovered) ?? hoverMaterial.color);
        hoverMesh.visible = true;
      } else {
        hoverMesh.visible = false;
      }
    },
    select(selection, positions) {
      let selected: SceneNode | null = null;
      for (const [, slot] of slots) {
        if (isSelectedNode(selection, slot.node)) selected = slot.node;
      }
      if (!selected) {
        outline.visible = false;
        return null;
      }
      const key = sceneStationKey(selected);
      const position = positions.get(key)?.position;
      if (position) {
        outline.position.copy(position);
        outline.visible = true;
      }
      return key;
    },
    dispose() {
      three.remove(pathMesh, offPathMesh, shadowMesh, rimMesh, hoverMesh, outline);
      pathMesh.dispose();
      offPathMesh.dispose();
      rimMesh.dispose();
      shadowMesh.dispose();
      shadowTexture?.dispose();
      disposeBag(bag);
    },
  };
}
