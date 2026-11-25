/** The freshness badge states whether the pinned run observed a drawn device (FEAT-05 item 4). */

import type { MapDevice, TableFreshness } from "../api/types";

function when(tsMs: number): string {
  return new Date(tsMs).toLocaleString();
}

/**
 * The badge text for one device, or "" for a device this run collected.
 *
 * `carried_reason` names why the objects came forward (core/cycle.py
 * `CARRY_REASONS`):
 *
 *   failed          the poll did not land: the device is unknown from then on
 *   not-run         the run did not ask this device anything
 *   unchanged       the device answered and its configuration had not moved
 *   section-failed  the device answered and one section of it did not
 */
export function freshnessLabel(d: MapDevice): string {
  const seen = d.last_seen != null ? when(d.last_seen) : "";
  if (d.carried_reason === "failed") {
    return seen ? `unknown since ${seen}` : "unknown";
  }
  if (!d.carried) return "";
  const since = seen ? `, last seen ${seen}` : "";
  switch (d.carried_reason) {
    case "not-run":
      return `not collected in this run${since}`;
    case "unchanged":
      return `unchanged since the previous run${since}`;
    case "section-failed":
      return `part of this device was not collected${since}`;
    default:
      return `carried from an earlier run${since}`;
  }
}

/** The device's tables, oldest first, as "<table> <age>" strings. */
export function tableAges(d: MapDevice): string[] {
  const rows = Object.entries(d.tables ?? {}).filter(([, t]) => t.age_ms != null);
  rows.sort((a, b) => (b[1].age_ms as number) - (a[1].age_ms as number));
  return rows.map(([name, t]) => `${name} ${humanAge(t)}`);
}

/** An age in the largest whole unit, floored. */
function humanAge(t: TableFreshness): string {
  const ms = t.age_ms ?? 0;
  if (ms < 1000) return "0 s";
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h`;
  return `${Math.floor(hours / 24)} d`;
}
