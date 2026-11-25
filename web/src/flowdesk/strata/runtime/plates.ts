/**
 * One translucent plate per layer over one shared footprint.
 */

import * as THREE from "three";
import { clipSegmentsToBounds, hexGridSegments, type PlateBounds } from "../path";
import {
  HEX_GRID_OPACITY,
  PLATE_EDGE_HEIGHT,
  PLATE_EDGE_OPACITY,
  PLATE_RIM_OPACITY,
  clamp,
  type PlatePalette,
} from "../view-helpers";
import { ORDER, disposeBag, newBag } from "./common";

interface Plate {
  surface: THREE.Mesh;
  edge: THREE.Mesh;
  rim: THREE.Line;
  grid: THREE.LineSegments;
  surfaceMaterial: THREE.MeshBasicMaterial;
  edgeMaterial: THREE.MeshBasicMaterial;
  rimMaterial: THREE.LineBasicMaterial;
  gridMaterial: THREE.LineBasicMaterial;
}

export interface PlatesRuntime {
  /** The plate surfaces, for the focus-point raycast. */
  surfaces: THREE.Mesh[];
  /** Move each plate to its layer's Y and fade it by its flatten amount. */
  update(offsets: readonly number[], flatten: readonly number[]): void;
  setGridVisible(visible: boolean): void;
  dispose(): void;
}

export function createPlates(
  three: THREE.Scene,
  footprint: PlateBounds,
  palettes: readonly PlatePalette[],
): PlatesRuntime {
  const bag = newBag();
  const plateWidth = footprint.maxX - footprint.minX;
  const plateDepth = footprint.maxZ - footprint.minZ;
  const plateCx = (footprint.minX + footprint.maxX) / 2;
  const plateCz = (footprint.minZ + footprint.maxZ) / 2;
  const gridPoints = clipSegmentsToBounds(hexGridSegments(footprint), footprint);

  const plateGeometry = new THREE.PlaneGeometry(plateWidth, plateDepth);
  plateGeometry.rotateX(-Math.PI / 2);
  bag.geometries.push(plateGeometry);
  // The slab is offset 0.002 below the surface.
  const edgeGeometry = new THREE.BoxGeometry(plateWidth, PLATE_EDGE_HEIGHT, plateDepth);
  edgeGeometry.translate(0, -PLATE_EDGE_HEIGHT / 2 - 0.002, 0);
  bag.geometries.push(edgeGeometry);
  const rimGeometry = new THREE.BufferGeometry().setFromPoints([
    new THREE.Vector3(footprint.minX, 0, footprint.minZ),
    new THREE.Vector3(footprint.maxX, 0, footprint.minZ),
    new THREE.Vector3(footprint.maxX, 0, footprint.maxZ),
    new THREE.Vector3(footprint.minX, 0, footprint.maxZ),
    new THREE.Vector3(footprint.minX, 0, footprint.minZ),
  ]);
  bag.geometries.push(rimGeometry);
  const gridPositions = new Float32Array((gridPoints.length / 2) * 3);
  for (let i = 0, j = 0; i < gridPoints.length; i += 2, j += 3) {
    gridPositions[j] = gridPoints[i];
    gridPositions[j + 1] = 0;
    gridPositions[j + 2] = gridPoints[i + 1];
  }

  const plates: Plate[] = palettes.map((palette, layer) => {
    const surfaceMaterial = new THREE.MeshBasicMaterial({
      color: new THREE.Color(palette.fill),
      transparent: true,
      opacity: palette.opacity,
      depthWrite: false,
      side: THREE.DoubleSide,
    });
    const edgeMaterial = new THREE.MeshBasicMaterial({
      color: new THREE.Color(palette.edge),
      transparent: true,
      opacity: PLATE_EDGE_OPACITY,
      depthWrite: false,
      side: THREE.DoubleSide,
    });
    const rimMaterial = new THREE.LineBasicMaterial({
      color: new THREE.Color(palette.rim),
      transparent: true,
      opacity: PLATE_RIM_OPACITY,
      depthWrite: false,
    });
    const gridMaterial = new THREE.LineBasicMaterial({
      color: new THREE.Color(palette.grid),
      transparent: true,
      opacity: HEX_GRID_OPACITY,
      depthWrite: false,
    });
    bag.materials.push(surfaceMaterial, edgeMaterial, rimMaterial, gridMaterial);

    const surface = new THREE.Mesh(plateGeometry, surfaceMaterial);
    surface.position.set(plateCx, 0, plateCz);
    surface.renderOrder = ORDER.plate;
    surface.userData.plateLayer = layer;
    three.add(surface);

    const edge = new THREE.Mesh(edgeGeometry, edgeMaterial);
    edge.position.set(plateCx, 0, plateCz);
    edge.renderOrder = ORDER.edge;
    three.add(edge);

    const rim = new THREE.Line(rimGeometry, rimMaterial);
    rim.renderOrder = ORDER.grid;
    three.add(rim);

    const gridGeometry = new THREE.BufferGeometry();
    gridGeometry.setAttribute("position", new THREE.BufferAttribute(gridPositions.slice(), 3));
    bag.geometries.push(gridGeometry);
    const grid = new THREE.LineSegments(gridGeometry, gridMaterial);
    grid.renderOrder = ORDER.grid;
    three.add(grid);

    return { surface, edge, rim, grid, surfaceMaterial, edgeMaterial, rimMaterial, gridMaterial };
  });

  return {
    surfaces: plates.map((p) => p.surface),
    update(offsets, flatten) {
      plates.forEach((plate, layer) => {
        const y = offsets[layer];
        plate.surface.position.y = y;
        plate.edge.position.y = y;
        plate.rim.position.y = y + 0.002;
        plate.grid.position.y = y + 0.004;
        const standing = 1 - clamp(flatten[layer] ?? 0, 0, 1);
        plate.edgeMaterial.opacity = PLATE_EDGE_OPACITY * standing;
        plate.surfaceMaterial.opacity = palettes[layer].opacity * standing;
        plate.rimMaterial.opacity = PLATE_RIM_OPACITY * standing;
        plate.gridMaterial.opacity = HEX_GRID_OPACITY * standing;
      });
    },
    setGridVisible(visible) {
      for (const plate of plates) plate.grid.visible = visible;
    },
    dispose() {
      for (const plate of plates) three.remove(plate.surface, plate.edge, plate.rim, plate.grid);
      disposeBag(bag);
    },
  };
}
