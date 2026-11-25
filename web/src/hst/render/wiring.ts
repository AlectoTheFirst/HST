/** The sockets of the ports on the walls of their device models, and the cable routes between them. */

export type Side = "n" | "s" | "e" | "w";

/** A device: its layout cell and the base of its model. */
export interface Footprint {
  uid: string;
  /** The layout cell. */
  u: number;
  v: number;
  w: number;
  h: number;
  /** The centre and half sizes of the model base; a round model has `hw` = `hh` = its radius. */
  cu: number;
  cv: number;
  hw: number;
  hh: number;
  round: boolean;
  /** The site whose devices a route of this device keeps clear of. */
  area: string | null;
}

export interface PortEnd {
  uid: string;
  device: string;
  side: string | null;
  slot: number | null;
}

export interface CableEnds {
  key: string;
  a: string;
  b: string;
}

/** A port socket: the point on the model wall, the outward normal and the socket edge length. */
export interface Socket {
  u: number;
  v: number;
  nu: number;
  nv: number;
  size: number;
  side: Side;
  /** The position of the socket on its wall, from the west or north end. */
  index: number;
}

export interface Wiring {
  sockets: Map<string, Socket>;
  routes: Map<string, [number, number][]>;
}

export const NORMAL: Readonly<Record<Side, [number, number]>> = {
  n: [0, -1],
  s: [0, 1],
  e: [1, 0],
  w: [-1, 0],
};
/** The share of a model side that holds its sockets. */
const SPAN = 0.8;
const SOCKET_MAX = 0.32;
const SOCKET_MIN = 0.06;
/** The distance between two parallel cables in one channel, in grid cells, and the part of the gap they leave free. */
export const LANE = 0.3;
const CHANNEL_SPARE = 0.6;
/** How far a cable leaves its own device before it turns, when it joins two ports of one device. */
const LOOP = 0.8;
/** The margin inside a layout cell that a route may cross. */
const CLEAR = 0.1;
const EPS = 1e-6;

type P = [number, number];

function side(s: string | null): Side {
  return s === "n" || s === "s" || s === "w" ? s : "e";
}

/** The edge of footprint `a` that faces footprint `b`: north or south when they share no row, else east or west. */
export function face(a: Footprint, b: Footprint): Side {
  if (b.v >= a.v + a.h) return "s";
  if (b.v + b.h <= a.v) return "n";
  return 2 * b.u + b.w > 2 * a.u + a.w ? "e" : "w";
}

/** The point at offset `t` along side `s` of the model of `f`, on its wall. */
export function wall(f: Footprint, s: Side, t: number): [number, number] {
  if (f.round) {
    const r = f.hw;
    const d = Math.sqrt(Math.max(0, r * r - t * t));
    if (s === "n") return [f.cu + t, f.cv - d];
    if (s === "s") return [f.cu + t, f.cv + d];
    if (s === "e") return [f.cu + d, f.cv + t];
    return [f.cu - d, f.cv + t];
  }
  if (s === "n") return [f.cu + t, f.cv - f.hh];
  if (s === "s") return [f.cu + t, f.cv + f.hh];
  if (s === "e") return [f.cu + f.hw, f.cv + t];
  return [f.cu - f.hw, f.cv + t];
}

/** The length of the part of side `s` of `f` that holds sockets and group segments. */
export function span(f: Footprint, s: Side): number {
  if (f.round) return 1.2 * f.hw;
  return SPAN * 2 * (s === "n" || s === "s" ? f.hw : f.hh);
}

function centre(f: Footprint): [number, number] {
  return [f.u + f.w / 2, f.v + f.h / 2];
}

function simplify(points: [number, number][]): [number, number][] {
  const out: [number, number][] = [];
  for (const p of points) {
    const last = out[out.length - 1];
    if (
      last &&
      Math.abs(last[0] - p[0]) < 1e-6 &&
      Math.abs(last[1] - p[1]) < 1e-6
    )
      continue;
    const prev = out[out.length - 2];
    if (
      prev &&
      last &&
      ((Math.abs(prev[0] - last[0]) < 1e-6 &&
        Math.abs(last[0] - p[0]) < 1e-6) ||
        (Math.abs(prev[1] - last[1]) < 1e-6 && Math.abs(last[1] - p[1]) < 1e-6))
    ) {
      out[out.length - 1] = p;
      continue;
    }
    out.push(p);
  }
  return out;
}

/** Whether the axis-parallel segment from `a` to `b` crosses the layout cell of `f`, inside its margin. */
function crosses(
  a: [number, number],
  b: [number, number],
  f: Footprint,
): boolean {
  const u0 = Math.min(a[0], b[0]);
  const u1 = Math.max(a[0], b[0]);
  const v0 = Math.min(a[1], b[1]);
  const v1 = Math.max(a[1], b[1]);
  return (
    u1 > f.u + CLEAR &&
    u0 < f.u + f.w - CLEAR &&
    v1 > f.v + CLEAR &&
    v0 < f.v + f.h - CLEAR
  );
}

function clear(points: [number, number][], others: Footprint[]): boolean {
  for (let i = 1; i < points.length; i++) {
    for (const f of others)
      if (crosses(points[i - 1], points[i], f)) return false;
  }
  return true;
}

/**
 * The sockets of `ports` and the routes of `cables` inside one site.
 *
 * A cabled port sits on the side of its model that faces the far device, an uncabled one on its layout side.
 * The sockets of one side spread over it in the order of their far devices.
 */
export function wire(
  devices: Map<string, Footprint>,
  ports: PortEnd[],
  cables: CableEnds[],
): Wiring {
  const portOf = new Map(ports.map((p) => [p.uid, p]));
  const far = new Map<string, string>();
  for (const c of cables) {
    const a = portOf.get(c.a);
    const b = portOf.get(c.b);
    if (!a || !b) continue;
    far.set(a.uid, b.device);
    far.set(b.uid, a.device);
  }
  // The planner sets the wall by the rank of the far device; the geometry is the fallback for a port without one.
  const sideOf = (p: PortEnd): Side => {
    if (p.side === "n" || p.side === "s" || p.side === "e" || p.side === "w") return p.side;
    const f = devices.get(p.device);
    const g = devices.get(far.get(p.uid) ?? "");
    if (f && g && f.uid !== g.uid) return face(f, g);
    return side(p.side);
  };

  const groups = new Map<
    string,
    { device: Footprint; side: Side; ports: PortEnd[] }
  >();
  for (const p of ports) {
    const f = devices.get(p.device);
    if (!f) continue;
    const s = sideOf(p);
    const key = `${p.device}\u0000${s}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { device: f, side: s, ports: [] }));
    g.ports.push(p);
  }
  const sockets = new Map<string, Socket>();
  for (const { device: f, side: s, ports: list } of groups.values()) {
    const along = (p: PortEnd): number => {
      const g = devices.get(far.get(p.uid) ?? "");
      if (!g) return Infinity;
      const [gu, gv] = centre(g);
      return s === "n" || s === "s" ? gu : gv;
    };
    list.sort(
      (a, b) =>
        along(a) - along(b) ||
        (a.slot ?? 0) - (b.slot ?? 0) ||
        a.uid.localeCompare(b.uid),
    );
    const length = span(f, s);
    const step = length / list.length;
    const size = Math.max(SOCKET_MIN, Math.min(SOCKET_MAX, step * 0.7));
    const [nu, nv] = NORMAL[s];
    list.forEach((p, i) => {
      const [u, v] = wall(f, s, -length / 2 + step * (i + 0.5));
      sockets.set(p.uid, { u, v, nu, nv, size, side: s, index: i });
    });
  }

  const byArea = new Map<string, Footprint[]>();
  for (const f of devices.values()) {
    const list = byArea.get(f.area ?? "") ?? [];
    list.push(f);
    byArea.set(f.area ?? "", list);
  }
  const half = channelHalf([...byArea.values()].map(gapOf));
  const routes = new Map<string, P[]>();
  const channels = { rows: new Set<number>(), cols: new Set<number>() };
  for (const c of cables) {
    const pa = portOf.get(c.a);
    const pb = portOf.get(c.b);
    const sa = sockets.get(c.a);
    const sb = sockets.get(c.b);
    const fa = pa && devices.get(pa.device);
    const fb = pb && devices.get(pb.device);
    if (!sa || !sb || !fa || !fb) continue;
    const a: P = [sa.u + sa.nu * sa.size, sa.v + sa.nv * sa.size];
    const b: P = [sb.u + sb.nu * sb.size, sb.v + sb.nv * sb.size];
    if (fa === fb) {
      routes.set(
        c.key,
        simplify([
          a,
          [a[0] + sa.nu * LOOP, a[1] + sa.nv * LOOP],
          [b[0] + sb.nu * LOOP, b[1] + sb.nv * LOOP],
          b,
        ]),
      );
      continue;
    }
    const field = [
      ...new Set([
        ...(byArea.get(fa.area ?? "") ?? []),
        ...(byArea.get(fb.area ?? "") ?? []),
      ]),
    ];
    const others = field.filter((f) => f !== fa && f !== fb);
    const points = route(a, sa.side, fa, b, sb.side, fb, field, others, half);
    // The first and the last leg are the socket stubs; the legs between run in channels.
    for (let i = 2; i < points.length - 1; i++) {
      const [p, q] = [points[i - 1], points[i]];
      if (Math.abs(p[1] - q[1]) < EPS) channels.rows.add(p[1]);
      else channels.cols.add(p[0]);
    }
    routes.set(c.key, points);
  }
  lanes(routes, channels, cables.map((c) => c.key), 2 * half - CHANNEL_SPARE);
  for (const [key, points] of routes) routes.set(key, simplify(points));
  return { sockets, routes };
}

function vertical(s: Side): boolean {
  return s === "n" || s === "s";
}

/** The smallest gap between two devices that face each other, or Infinity when none do. */
function gapOf(devices: Footprint[]): number {
  let gap = Infinity;
  for (const a of devices) {
    for (const b of devices) {
      if (b.u < a.u + a.w && a.u < b.u + b.w && b.v > a.v + a.h) gap = Math.min(gap, b.v - a.v - a.h);
      if (b.v < a.v + a.h && a.v < b.v + b.h && b.u > a.u + a.w) gap = Math.min(gap, b.u - a.u - a.w);
    }
  }
  return gap;
}

/** Half the smallest of the gaps, at least 1: the line of a channel. */
function channelHalf(found: number[]): number {
  const gap = found.reduce((least, g) => Math.min(least, g), Infinity);
  return Number.isFinite(gap) ? Math.max(1, gap / 2) : 1;
}

/** The channel a socket on side `s` of `f` leaves into: the middle of the row gap above or below, or of the column gap
 *  beside. */
function channelOf(f: Footprint, s: Side, half: number): number {
  if (s === "n") return f.v - half;
  if (s === "s") return f.v + f.h + half;
  if (s === "w") return f.u - half;
  return f.u + f.w + half;
}

/** The column gaps and row gaps of `field`, nearest to `mid` first, with the gaps outside the field last. */
function gaps(field: Footprint[], axis: 0 | 1, mid: number, half: number): number[] {
  const out = new Set<number>();
  let lo = Infinity;
  let hi = -Infinity;
  for (const f of field) {
    const start = axis === 0 ? f.u : f.v;
    const end = start + (axis === 0 ? f.w : f.h);
    out.add(start - half);
    out.add(end + half);
    lo = Math.min(lo, start);
    hi = Math.max(hi, end);
  }
  const inner = [...out].sort((x, y) => Math.abs(x - mid) - Math.abs(y - mid));
  return [...inner, lo - half, hi + half];
}

/**
 * The orthogonal route from `a` to `b` through the channels: along the channel of each socket, joined by
 * the nearest clear column or row. The last candidate runs outside the field and is clear by construction.
 */
function route(
  a: P,
  sa: Side,
  fa: Footprint,
  b: P,
  sb: Side,
  fb: Footprint,
  field: Footprint[],
  others: Footprint[],
  half: number,
): P[] {
  const candidates: P[][] = [];
  if (vertical(sa) && vertical(sb)) {
    const ya = channelOf(fa, sa, half);
    const yb = channelOf(fb, sb, half);
    if (Math.abs(ya - yb) < EPS) return simplify([a, [a[0], ya], [b[0], ya], b]);
    return staircase(a, ya, b, yb, field, others, half);
  } else if (!vertical(sa) && !vertical(sb)) {
    const xa = channelOf(fa, sa, half);
    const xb = channelOf(fb, sb, half);
    if (Math.abs(xa - xb) < EPS) candidates.push([a, [xa, a[1]], [xa, b[1]], b]);
    for (const y of gaps(field, 1, (a[1] + b[1]) / 2, half))
      candidates.push([a, [xa, a[1]], [xa, y], [xb, y], [xb, b[1]], b]);
  } else {
    const [p, sp, fp, q, sq, fq] = vertical(sa)
      ? [a, sa, fa, b, sb, fb]
      : [b, sb, fb, a, sa, fa];
    const yp = channelOf(fp, sp, half);
    const xq = channelOf(fq, sq, half);
    candidates.push([p, [p[0], yp], [xq, yp], [xq, q[1]], q]);
    const yq = channelOf(fq, q[1] < yp ? "s" : "n", half);
    for (const x of gaps(field, 0, (p[0] + q[0]) / 2, half))
      candidates.push([p, [p[0], yp], [x, yp], [x, yq], [xq, yq], [xq, q[1]], q]);
    if (!vertical(sa)) candidates.forEach((c) => c.reverse());
  }
  return simplify(candidates.find((c) => clear(c, others)) ?? candidates[candidates.length - 1]);
}

/**
 * The route of a cable that skips rows: in every row it passes, the column gap nearest to the straight line
 * between its sockets, joined in the row channels. Every vertical leg is clear of the devices of its row.
 */
function staircase(a: P, ya: number, b: P, yb: number, field: Footprint[], others: Footprint[], half: number): P[] {
  const down = yb > ya;
  const between = new Set<number>();
  for (const f of field) {
    for (const y of [f.v - half, f.v + f.h + half]) {
      if (y > Math.min(ya, yb) + EPS && y < Math.max(ya, yb) - EPS) between.add(y);
    }
  }
  const ys = [ya, ...[...between].sort((p, q) => (down ? p - q : q - p)), yb];
  const points: P[] = [a, [a[0], ya]];
  let x = a[0];
  for (let k = 1; k < ys.length; k++) {
    const [y0, y1] = [ys[k - 1], ys[k]];
    const t = ((y0 + y1) / 2 - ya) / (yb - ya);
    const ideal = a[0] + (b[0] - a[0]) * t;
    const column = gaps(field, 0, ideal, half).find((c) => clear([[c, y0], [c, y1]], others)) ?? ideal;
    points.push([x, y0], [column, y0], [column, y1]);
    x = column;
  }
  points.push([x, yb], [b[0], yb], b);
  return simplify(points);
}

interface Leg {
  cable: string;
  index: number;
  lo: number;
  hi: number;
  exit: number;
}

/**
 * The lanes of the channel legs: the legs that leave a channel to one side take lanes from that side, the
 * shortest span nearest.
 */
function lanes(
  routes: Map<string, P[]>,
  channels: { rows: Set<number>; cols: Set<number> },
  order: string[],
  width: number,
): void {
  for (const axis of [1, 0] as const) {
    const set = axis === 1 ? channels.rows : channels.cols;
    const byChannel = new Map<number, Leg[]>();
    for (const cable of order) {
      const points = routes.get(cable);
      if (!points) continue;
      for (let i = 2; i < points.length - 1; i++) {
        const [p, q] = [points[i - 1], points[i]];
        const fixed = axis === 1 ? 1 : 0;
        const along = axis === 1 ? 0 : 1;
        if (Math.abs(p[fixed] - q[fixed]) > EPS || !set.has(p[fixed])) continue;
        const next = points[i + 1];
        const exit = Math.sign(next[fixed] - q[fixed]) || Math.sign(points[i - 2][fixed] - q[fixed]) || 1;
        const list = byChannel.get(p[fixed]) ?? [];
        list.push({ cable, index: i, lo: Math.min(p[along], q[along]), hi: Math.max(p[along], q[along]), exit });
        byChannel.set(p[fixed], list);
      }
    }
    for (const [at, legs] of byChannel) {
      if (legs.length < 2) continue;
      const pack = (group: Leg[]): Leg[][] => {
        const out: Leg[][] = [];
        for (const leg of group.sort((x, y) => x.hi - x.lo - (y.hi - y.lo))) {
          let i = 0;
          while (out[i]?.some((o) => o.lo < leg.hi + LANE && leg.lo < o.hi + LANE)) i++;
          (out[i] ??= []).push(leg);
        }
        return out;
      };
      const minus = pack(legs.filter((l) => l.exit < 0));
      const plus = pack(legs.filter((l) => l.exit > 0));
      const ordered = [...minus, ...plus.reverse()];
      const n = ordered.length;
      if (n < 2) continue;
      const pitch = Math.min(LANE, width / (n - 1));
      ordered.forEach((lane, i) => {
        const shift = at + (i - (n - 1) / 2) * pitch;
        for (const leg of lane) {
          const points = routes.get(leg.cable)!;
          points[leg.index - 1][axis] = shift;
          points[leg.index][axis] = shift;
        }
      });
    }
  }
}
