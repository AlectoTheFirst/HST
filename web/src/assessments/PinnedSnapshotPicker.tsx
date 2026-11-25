import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { SnapshotList } from "../api/types";

export function PinnedSnapshotPicker({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  const snapshots = useQuery({ queryKey: ["snapshots"], queryFn: () => api<SnapshotList>("/snapshots") });
  const all = snapshots.data?.snapshots ?? [];
  return <label className="assessment-field"><span>{label}</span><select value={value} required onChange={(e) => onChange(e.target.value)}>
    <option value="">Select a recorded snapshot</option>
    {value && !all.some((s) => s.id === value) && <option value={value}>{value}</option>}
    {all.map((s) => <option key={s.id} value={s.id}>{new Date(s.ts_ms).toLocaleString()} [{s.kind}]{s.degraded ? " (degraded)" : ""}</option>)}
  </select>{snapshots.isError && <span role="alert">Could not load snapshots</span>}{snapshots.data?.truncated && <span>Older snapshots not listed</span>}</label>;
}
