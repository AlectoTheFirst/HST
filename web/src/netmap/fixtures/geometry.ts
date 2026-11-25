/**
 * Geometry checks of a laid-out segment row for the tests: the crossings of
 * the drop lines.
 */

import type { ElkNode } from "elkjs/lib/elk-api";
import type { Point } from "../layout";
import type { Row } from "../segrow";

export interface DropLine {
  id: string;
  dev: string;
  pts: Point[];
}

/** Every drop of the row as the polyline ELK routed, with its device. */
export function dropLines(laid: ElkNode, row: Row): DropLine[] {
  const devOf = new Map<string, string>();
  for (const b of row.bars) for (const s of [...b.north, ...b.south]) devOf.set(`${b.bar.id}:drop:${s.drop.key}`, s.drop.dev);
  return (laid.edges ?? [])
    .filter((e) => devOf.has(e.id))
    .map((e) => {
      const s = e.sections![0];
      return { id: e.id, dev: devOf.get(e.id)!, pts: [s.startPoint, ...(s.bendPoints ?? []), s.endPoint] };
    });
}

/** Whether a horizontal and a vertical segment cross inside both. */
function cross(h: [Point, Point], v: [Point, Point]): boolean {
  const eps = 0.5;
  const [x0, x1] = [Math.min(h[0].x, h[1].x), Math.max(h[0].x, h[1].x)];
  const [y0, y1] = [Math.min(v[0].y, v[1].y), Math.max(v[0].y, v[1].y)];
  return v[0].x > x0 + eps && v[0].x < x1 - eps && h[0].y > y0 + eps && h[0].y < y1 - eps;
}

const legs = (pts: Point[]) => pts.slice(1).map((q, i) => [pts[i], q] as [Point, Point]);
const horizontal = (s: [Point, Point]) => Math.abs(s[0].y - s[1].y) < 0.5;
const vertical = (s: [Point, Point]) => Math.abs(s[0].x - s[1].x) < 0.5;

/** The crossings between the drops: of one device's drops, and of two devices' drops. */
export function crossings(lines: DropLine[]): { same: number; other: number } {
  let same = 0;
  let other = 0;
  for (let i = 0; i < lines.length; i++) {
    for (let j = i + 1; j < lines.length; j++) {
      let n = 0;
      for (const a of legs(lines[i].pts)) {
        for (const b of legs(lines[j].pts)) {
          if ((horizontal(a) && vertical(b) && cross(a, b)) || (vertical(a) && horizontal(b) && cross(b, a))) n++;
        }
      }
      if (lines[i].dev === lines[j].dev) same += n;
      else other += n;
    }
  }
  return { same, other };
}
