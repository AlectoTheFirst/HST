import type { ReactNode } from "react";
import type { StateMap, Tone } from "./format";

export function Badge({ tone = "neutral", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`badge inv-badge ${tone}`}>{children}</span>;
}

/** A badge for a backend enum value. An unknown value shows as its raw string. */
export function StateBadge<K extends string>({ map, value }: { map: StateMap<K>; value: K }) {
  const entry = map[value];
  return <Badge tone={entry?.tone ?? "neutral"}>{entry?.label ?? value}</Badge>;
}
