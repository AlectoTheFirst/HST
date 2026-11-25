/**
 * The world outline behind the network map's estate level: land polygons as rings of
 * [longitude, latitude] pairs, projected here into one SVG path.
 *
 * The rings are Natural Earth 110m land (public domain), rounded and
 * checked in as ./land.ts, which names its source and its generation step.
 * The dots and the lines between them do not depend on the outline.
 */

import { LAND_RINGS } from "./land";
import { project } from "./projection";

export type Ring = [number, number][];

export const LAND: readonly Ring[] = LAND_RINGS;

/** Every ring as one closed subpath. */
export function landPath(rings: readonly Ring[] = LAND): string {
  return rings
    .map((ring) =>
      ring
        .map(([lon, lat], i) => {
          const p = project(lat, lon);
          return `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`;
        })
        .join(" ") + " Z",
    )
    .join(" ");
}
