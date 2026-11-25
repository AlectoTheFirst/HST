/**
 * Shared parts of the Strata runtime factories.
 */

import type * as THREE from "three";

export const ORDER = {
  plate: 0,
  edge: 1,
  grid: 2,
  shadow: 3,
  node: 4,
  glow: 5,
  path: 6,
  flow: 7,
  outline: 8,
};

/** The path width in screen-space CSS pixels. */
export const PATH_WIDTH = 3;
export const PATH_GLOW_WIDTH = 10;
export const PATH_GLOW_OPACITY = 0.18;
/** The animated flow overlay drawn on top of the solid core. */
export const FLOW_DASH = 1.1;
export const FLOW_GAP = 2.1;
/** World units per second the dash pattern travels. */
export const FLOW_SPEED = 2.6;
export const CHEVRON_PX = 11;
export const SELECT_OUTLINE_WIDTH = 2;
/** The scale of a hovered node. */
export const HOVER_SCALE = 1.08;

/** The geometries and materials one factory created, disposed together. */
export interface Bag {
  geometries: THREE.BufferGeometry[];
  materials: THREE.Material[];
}

export function newBag(): Bag {
  return { geometries: [], materials: [] };
}

export function disposeBag(bag: Bag): void {
  for (const geometry of bag.geometries) geometry.dispose();
  for (const material of bag.materials) material.dispose();
  bag.geometries.length = 0;
  bag.materials.length = 0;
}
