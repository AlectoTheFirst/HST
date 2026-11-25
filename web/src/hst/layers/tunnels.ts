import type { Tier3 } from "../data/api";
import type { Row, Transport } from "../render/types";

/** The transports of each tunnel edge of `device`, keyed by `pair_id`, from its Tier 3 tunnel list. */
export function transports(device: string, tier3: Tier3, edges: Iterable<Row>): Map<string, Transport[]> {
  const byOther = new Map<string, Map<string, number>>();
  for (const t of tier3.tunnels ?? []) {
    if (!t.other) continue;
    const counts = byOther.get(t.other) ?? new Map<string, number>();
    const encap = t.encap ?? "unknown";
    counts.set(encap, (counts.get(encap) ?? 0) + 1);
    byOther.set(t.other, counts);
  }
  const out = new Map<string, Transport[]>();
  for (const e of edges) {
    if (Number(e.tunnel_count ?? 0) === 0) continue;
    const other = e.a_uid === device ? String(e.b_uid) : e.b_uid === device ? String(e.a_uid) : null;
    const counts = other ? byOther.get(other) : undefined;
    if (!counts) continue;
    out.set(
      String(e.pair_id),
      [...counts].map(([encap, count]) => ({ encap, count })).sort((a, b) => b.count - a.count || a.encap.localeCompare(b.encap)),
    );
  }
  return out;
}
