import { parseQuery, rank } from "../../search/match";
import type { Scene } from "../render/scene";

export interface Hit {
  uid: string;
  kind: "site" | "block" | "device";
  label: string;
}

const KINDS: Record<string, Hit["kind"]> = { site: "site", block: "block" };

/** The sites, blocks and devices whose label or uid matches `query` by the
 *  shared search grammar (search/match.ts): exact matches first, then prefixes. */
export function search(scene: Scene, query: string, limit = 10): Hit[] {
  const q = parseQuery(query);
  if (!q.text) return [];
  const hits: (Hit & { rank: number })[] = [];
  const consider = (uid: string, kind: Hit["kind"], label: string) => {
    const r = rank(q, label, uid);
    if (r >= 0) hits.push({ uid, kind, label, rank: r });
  };
  for (const row of scene.rows("render_t0")) {
    const kind = KINDS[String(row.kind)];
    if (kind) consider(String(row.uid), kind, String(row.label ?? row.uid));
  }
  for (const row of scene.rows("render_t1")) consider(String(row.uid), "device", String(row.label ?? row.uid));
  hits.sort((a, b) => a.rank - b.rank || a.label.length - b.label.length || a.label.localeCompare(b.label));
  return hits.slice(0, limit).map(({ uid, kind, label }) => ({ uid, kind, label }));
}

/** The site, block or device of the scene with this uid, as a hit; null when
 *  the scene holds none. */
export function sceneHit(scene: Scene, uid: string): Hit | null {
  const device = scene.row("render_t1", uid);
  if (device) return { uid, kind: "device", label: String(device.label ?? uid) };
  const area = scene.row("render_t0", uid);
  const kind = area ? KINDS[String(area.kind)] : undefined;
  return area && kind ? { uid, kind, label: String(area.label ?? uid) } : null;
}
