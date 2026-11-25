/**
 * The traced path.
 */

import * as THREE from "three";
import { Line2 } from "three/examples/jsm/lines/Line2.js";
import { LineGeometry } from "three/examples/jsm/lines/LineGeometry.js";
import { LineMaterial } from "three/examples/jsm/lines/LineMaterial.js";
import type { PathSegment } from "../path";
import { linkHiddenByLayers } from "../scene";
import { OFF_PATH_OPACITY } from "../view-helpers";
import {
  FLOW_DASH,
  FLOW_GAP,
  FLOW_SPEED,
  ORDER,
  PATH_GLOW_OPACITY,
  PATH_GLOW_WIDTH,
  PATH_WIDTH,
  disposeBag,
  newBag,
} from "./common";

export interface SegmentObjects {
  segment: PathSegment;
  core: Line2;
  coreGeometry: LineGeometry;
  coreMaterial: LineMaterial;
  glow: Line2;
  glowGeometry: LineGeometry;
  glowMaterial: LineMaterial;
  flow: Line2 | null;
  flowGeometry: LineGeometry | null;
  flowMaterial: LineMaterial | null;
  chevron: THREE.Mesh | null;
}

export interface PathLinesRuntime {
  segments: SegmentObjects[];
  update(segments: PathSegment[]): void;
  applyState(selectedKey: string | null, hiddenLayers: ReadonlySet<number>): void;
  /** Advances the flow dash by `dt` seconds. */
  tick(dt: number): void;
  setResolution(width: number, height: number): void;
  setChevronScale(scale: number): void;
  dispose(): void;
}

export function createPathLines(
  three: THREE.Scene,
  accent: THREE.Color,
  muted: THREE.Color,
  reducedMotion: boolean,
): PathLinesRuntime {
  const bag = newBag();
  const lineMaterials: LineMaterial[] = [];
  const objects: SegmentObjects[] = [];
  const added: THREE.Object3D[] = [];
  const chevronGeometry = new THREE.ConeGeometry(0.4, 1, 10);
  bag.geometries.push(chevronGeometry);
  let flowDistance = 0;

  function add(object: THREE.Object3D) {
    three.add(object);
    added.push(object);
  }

  function build(segments: PathSegment[]) {
    for (const segment of segments) {
      const flatPoints = segment.points.flatMap((p) => [p.x, p.y, p.z]);
      const glowGeometry = new LineGeometry().setPositions(flatPoints);
      const coreGeometry = new LineGeometry().setPositions(flatPoints);
      bag.geometries.push(glowGeometry, coreGeometry);

      const colour = segment.dead ? muted : accent;
      const opacity = segment.dead ? OFF_PATH_OPACITY : 1;
      const coreMaterial = new LineMaterial({
        color: colour.getHex(),
        linewidth: PATH_WIDTH,
        transparent: true,
        opacity,
        depthTest: false,
        depthWrite: false,
      });
      const glowMaterial = new LineMaterial({
        color: colour.getHex(),
        linewidth: PATH_GLOW_WIDTH,
        transparent: true,
        opacity: segment.dead ? 0 : PATH_GLOW_OPACITY,
        depthTest: false,
        depthWrite: false,
      });
      bag.materials.push(coreMaterial, glowMaterial);
      lineMaterials.push(coreMaterial, glowMaterial);

      const glow = new Line2(glowGeometry, glowMaterial);
      glow.computeLineDistances();
      glow.renderOrder = ORDER.glow;
      glow.frustumCulled = false;
      add(glow);

      const core = new Line2(coreGeometry, coreMaterial);
      core.computeLineDistances();
      core.renderOrder = ORDER.path;
      core.frustumCulled = false;
      add(core);

      let flow: Line2 | null = null;
      let flowGeometry: LineGeometry | null = null;
      let flowMaterial: LineMaterial | null = null;
      let chevron: THREE.Mesh | null = null;
      if (!segment.dead) {
        if (reducedMotion) {
          const chevronMaterial = new THREE.MeshBasicMaterial({
            color: accent.clone(),
            transparent: true,
            depthTest: false,
            depthWrite: false,
          });
          bag.materials.push(chevronMaterial);
          chevron = new THREE.Mesh(chevronGeometry, chevronMaterial);
          chevron.renderOrder = ORDER.flow;
          chevron.frustumCulled = false;
          add(chevron);
        } else {
          flowGeometry = new LineGeometry().setPositions(flatPoints);
          bag.geometries.push(flowGeometry);
          flowMaterial = new LineMaterial({
            color: 0xffffff,
            linewidth: PATH_WIDTH,
            transparent: true,
            opacity: 0.55,
            depthTest: false,
            depthWrite: false,
            dashed: true,
            dashSize: FLOW_DASH,
            gapSize: FLOW_GAP,
          });
          bag.materials.push(flowMaterial);
          lineMaterials.push(flowMaterial);
          flow = new Line2(flowGeometry, flowMaterial);
          flow.computeLineDistances();
          flow.renderOrder = ORDER.flow;
          flow.frustumCulled = false;
          add(flow);
        }
      }

      objects.push({
        segment,
        core,
        coreGeometry,
        coreMaterial,
        glow,
        glowGeometry,
        glowMaterial,
        flow,
        flowGeometry,
        flowMaterial,
        chevron,
      });
    }
  }

  return {
    segments: objects,
    update(segments) {
      if (objects.length === 0) {
        build(segments);
      } else {
        // The geometry is regenerated only when the trace or its layout changes.
        segments.forEach((segment, i) => {
          const o = objects[i];
          if (!o) return;
          o.segment.points = segment.points;
          o.segment.offset = segment.offset;
          const flatPoints = segment.points.flatMap((p) => [p.x, p.y, p.z]);
          o.coreGeometry.setPositions(flatPoints);
          o.glowGeometry.setPositions(flatPoints);
          o.flowGeometry?.setPositions(flatPoints);
          o.core.computeLineDistances();
          o.glow.computeLineDistances();
          o.flow?.computeLineDistances();
        });
      }
      for (const o of objects) {
        if (!o.chevron) continue;
        const points = o.segment.points;
        const a = points[points.length - 2];
        const b = points[points.length - 1];
        o.chevron.position.copy(a).add(b).multiplyScalar(0.5);
        const direction = b.clone().sub(a);
        if (direction.lengthSq() > 1e-12) {
          o.chevron.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction.normalize());
        }
      }
    },
    applyState(selectedKey, hiddenLayers) {
      for (const o of objects) {
        const incident = selectedKey !== null && (o.segment.from === selectedKey || o.segment.to === selectedKey);
        const hidden = linkHiddenByLayers(o.segment.fromLayer, o.segment.toLayer, hiddenLayers);
        o.coreMaterial.linewidth = incident ? PATH_WIDTH + 2 : PATH_WIDTH;
        o.core.visible = !hidden;
        o.glow.visible = !hidden && !o.segment.dead;
        o.glowMaterial.opacity = incident ? PATH_GLOW_OPACITY * 2.4 : PATH_GLOW_OPACITY;
        if (o.flow) o.flow.visible = !hidden;
        if (o.chevron) o.chevron.visible = !hidden;
      }
    },
    tick(dt) {
      if (reducedMotion) return;
      flowDistance = (flowDistance + dt * FLOW_SPEED) % (FLOW_DASH + FLOW_GAP);
      for (const o of objects) {
        if (!o.flowMaterial) continue;
        o.flowMaterial.dashOffset = -(flowDistance + o.segment.offset);
      }
    },
    setResolution(width, height) {
      for (const material of lineMaterials) material.resolution.set(width, height);
    },
    setChevronScale(scale) {
      for (const o of objects) o.chevron?.scale.setScalar(scale);
    },
    dispose() {
      for (const object of added) three.remove(object);
      disposeBag(bag);
    },
  };
}
