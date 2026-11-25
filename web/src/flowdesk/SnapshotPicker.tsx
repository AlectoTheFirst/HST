/** Its styles do not depend on `.composer`. */

import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { Snapshot, SnapshotList } from "../api/types";

/** A snapshot id is the run's `ts_ms` as a string. */
export function formatSnapshotDate(tsMs: number): string {
  return new Date(tsMs).toLocaleString();
}

/** `all` resolves the parent's id to a date when the parent is in it. */
function optionLabel(s: Snapshot, all: Snapshot[]): string {
  const label = formatSnapshotDate(s.ts_ms) + (s.degraded ? " (degraded)" : "");
  if (s.kind === "full") return label;
  const parentId = s.parent;
  const parent = parentId != null ? all.find((p) => p.ts_ms === parentId) : undefined;
  const parentRef = parent ? formatSnapshotDate(parent.ts_ms) : parentId != null ? String(parentId) : "none";
  return `${label} [${s.kind}, parent ${parentRef}]`;
}

export function SnapshotPicker({
  value,
  onChange,
  label,
  allowCurrent,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  allowCurrent?: boolean;
}) {
  const snapshots = useQuery({
    queryKey: ["snapshots"],
    queryFn: () => api<SnapshotList>("/snapshots"),
  });

  const all = snapshots.data?.snapshots ?? [];

  return (
    <span className="snap-picker">
      <span className="snap-label">{label}</span>
      <select
        className="snap-select"
        aria-label={label}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {allowCurrent && <option value="">Current</option>}
        {snapshots.isError && <option disabled>Snapshots not loaded</option>}
        {all.map((s) => (
          <option key={s.id} value={s.id}>
            {optionLabel(s, all)}
          </option>
        ))}
      </select>
    </span>
  );
}
