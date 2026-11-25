import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { inventoryApi } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { ErrorNotice } from "./ErrorNotice";
import { flatten, formatValue, humanize } from "./format";
import { Facts } from "./Page";

/** The resolved collection settings of one target. Loaded only when opened. */
export function EffectiveSettings({ targetId }: { targetId: string }) {
  const [open, setOpen] = useState(false);
  const effective = useQuery({ queryKey: inventoryKeys.targets.effective(targetId), queryFn: () => inventoryApi.getEffective(targetId), enabled: open });
  const data = effective.data;
  return (
    <details onToggle={e => setOpen(e.currentTarget.open)}>
      <summary>Effective settings</summary>
      <div className="inv-review-section">
        <ErrorNotice error={effective.error} retry={() => void effective.refetch()} />
        {open && effective.isPending && <p className="hint">Loading effective settings</p>}
        {data && <>
          <Facts rows={[
            ["Profile", data.profile_id ? `${data.profile_id}, revision ${data.profile_revision ?? "none"}` : "None"],
            ["Credential revision", data.credential_revision ?? "None"],
            ["Configuration digest", <span className="mono">{data.configuration_digest}</span>],
          ]} />
          <div className="results inv-table">
            <table>
              <thead><tr><th>Setting</th><th>Value</th><th>Origin</th></tr></thead>
              <tbody>
                {flatten(data.values).map(([path, value]) => (
                  <tr key={path}>
                    <td className="mono">{path}</td>
                    <td>{formatValue(value)}</td>
                    <td>{data.origins[path] ? humanize(data.origins[path]) : "Not set"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>}
      </div>
    </details>
  );
}
