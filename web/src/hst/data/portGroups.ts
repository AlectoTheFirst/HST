import type { Row } from "../render/types";

/** The port name with its trailing number removed, as `group_key` in `hst/map/port_groups.py`. */
export function groupKey(name: string): string {
  return name.replace(/\d+$/, "");
}

/** A sort key that orders the numbers inside a name by value. */
export function natural(a: string, b: string): number {
  return a.localeCompare(b, undefined, { numeric: true });
}

function state(port: Row): "up" | "down" | "admin_down" | null {
  const admin = String(port.admin_status ?? "").toLowerCase();
  const oper = String(port.oper_status ?? "").toLowerCase();
  if (admin === "down" || oper.startsWith("admin")) return "admin_down";
  if (oper === "up") return "up";
  if (oper && oper !== "unknown") return "down";
  return null;
}

/** The rows of `render_t2_port_groups` for `ports` and `cables`, like `groups` in `hst/map/port_groups.py`. */
export function portGroups(ports: Row[], cables: Row[]): Row[] {
  const ends = new Set(cables.flatMap((c) => [c.a_port, c.b_port]).filter((p) => p != null).map(String));
  const found = new Map<string, Row>();
  for (const port of ports) {
    const name = String(port.name ?? "");
    const key = `${port.device_uid}|${groupKey(name)}`;
    let row = found.get(key);
    if (!row) {
      row = { device_uid: port.device_uid, tile: port.tile, group_key: groupKey(name), first_name: name, last_name: name, port_count: 0, up: 0, down: 0, admin_down: 0, connected: 0 };
      found.set(key, row);
    }
    row.port_count = Number(row.port_count) + 1;
    if (natural(name, String(row.first_name)) < 0) row.first_name = name;
    if (natural(name, String(row.last_name)) > 0) row.last_name = name;
    const s = state(port);
    if (s) row[s] = Number(row[s]) + 1;
    if (ends.has(String(port.uid))) row.connected = Number(row.connected) + 1;
  }
  return [...found.values()].sort((a, b) => String(a.device_uid).localeCompare(String(b.device_uid)) || natural(String(a.group_key), String(b.group_key)));
}
