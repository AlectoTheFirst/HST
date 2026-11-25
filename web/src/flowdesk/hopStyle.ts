/**
 * Hop helpers the trace views share: kind colours, the mono-font kinds, text
 * fitting for SVG, the selection identity of a hop, and which gate carries a
 * leg's verdict.
 */

import type { CSSProperties } from "react";
import type { Hop, Leg } from "../api/types";
import { isGate } from "./gate";
import type { Selection } from "./selection";
import type { GateVerdict } from "./verdict";

// the estimated character width of SVG text
export const CAPTION_CHAR_W = 6.4;

export function truncate(text: string, maxPx: number, charW = CAPTION_CHAR_W): string {
  const max = Math.max(4, Math.floor(maxPx / charW));
  return text.length <= max ? text : text.slice(0, max - 1) + "…";
}

// kinds whose labels are data (addresses, ports, uids), drawn in the mono font
export const MONO_KINDS: ReadonlySet<string> = new Set([
  "IpAddress",
  "Prefix",
  "Interface",
  "Tunnel",
  "WanLink",
  "VrfInstance",
  "Port",
  "Endpoint",
  "NextHop",
]);

export function kindColor(kind: string): string {
  return `var(--kind-${kind}, var(--kind-fallback))`;
}

/** A stylesheet rule (selection, focus) overrides the stroke by cascade. */
export function kindVar(kind: string): CSSProperties {
  return { "--kind-color": kindColor(kind) } as CSSProperties;
}

// a hairpin path visits the same node twice in one lane
export function isSelectedHop(selection: Selection | null, hop: Hop): boolean {
  return (
    selection?.type === "hop" &&
    selection.data.uid === hop.uid &&
    selection.data.lane === hop.lane &&
    selection.data.rank === hop.rank
  );
}

export type StationVerdict = GateVerdict | null;

/** `blocking_uid` names the hop that decided when it differs from `fw_uid`. */
export function stationVerdict(
  station: { uid: string; kind: string; shared: boolean; gate?: boolean },
  leg: Leg | undefined,
  allBlocked: boolean,
): StationVerdict {
  if (leg && (leg.blocking_uid ?? leg.fw_uid) === station.uid) {
    return leg.blocked ? "bad" : leg.indeterminate ? "warn" : "ok";
  }
  if (leg?.fw_uids?.includes(station.uid)) return "ok";
  if (station.shared && isGate(station)) return allBlocked ? "bad" : null;
  return null;
}
