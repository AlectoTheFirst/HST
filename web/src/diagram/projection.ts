/** The world map's projection is equirectangular. */

/** user units per degree; the world is 1440 by 720 */
export const SCALE = 4;
export const WORLD_W = 360 * SCALE;
export const WORLD_H = 180 * SCALE;

export interface Point {
  x: number;
  y: number;
}

export function project(lat: number, lon: number): Point {
  return { x: (lon + 180) * SCALE, y: (90 - lat) * SCALE };
}
