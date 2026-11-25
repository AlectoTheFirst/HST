import type { Row } from "../render/types";

interface Props {
  identities: Row[];
  value: string | null;
  onChange(identity: string | null): void;
}

export function contextLabel(row: Row): string {
  const name = String(row.name ?? row.identity_uid);
  return row.rd ? `${name} (${String(row.rd)})` : name;
}

export default function ContextSelect({ identities, value, onChange }: Props) {
  const sorted = [...identities].sort((a, b) => contextLabel(a).localeCompare(contextLabel(b)));
  return (
    <label className="hst-context">
      Context
      <select value={value ?? ""} onChange={(e) => onChange(e.target.value || null)}>
        <option value="">All contexts</option>
        {sorted.map((row) => (
          <option key={String(row.identity_uid)} value={String(row.identity_uid)}>
            {contextLabel(row)}
          </option>
        ))}
      </select>
    </label>
  );
}
