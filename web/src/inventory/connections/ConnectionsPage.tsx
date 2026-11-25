import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { inventoryApi, type ConnectionKind } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { useCapabilities, connectionLink } from "../shared";
import { Badge, StateBadge } from "../ui/Badge";
import { ErrorNotice } from "../ui/ErrorNotice";
import { PageHeader } from "../ui/Page";
import { COLLECTION_STATE, formatTime, humanize, plural } from "../ui/format";
import { Onboarding } from "./Onboarding";

const KINDS = [["", "All"], ["direct", "Direct"], ["controller", "Controller"]] as const;

export function ConnectionsPage() {
  const { read, write } = useCapabilities();
  const [params, setParams] = useSearchParams();
  const [onboard, setOnboard] = useState(false);
  const kind = params.get("kind"); const collector = params.get("collector_type");
  const filter = { ...(kind === "direct" || kind === "controller" ? { kind: kind as ConnectionKind } : {}), ...(collector ? { collector_type: collector } : {}) };
  const query = useQuery({ queryKey: inventoryKeys.connections.list(filter), queryFn: () => inventoryApi.listConnections(filter), enabled: read });
  const set = (key: string, value: string, replace = false) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    setParams(next, { replace });
  };
  if (!read) {
    return <section className="ops-page inv-page"><PageHeader title="Connections" /><p className="hint" role="status">No runs.manage permission</p></section>;
  }
  return (
    <section className="ops-page inv-page">
      <PageHeader title="Connections">
        {write && <Link className="secondary" to="/inventory/connections/profiles">Profiles and credentials</Link>}
        {write && !onboard && <button type="button" className="primary" onClick={() => setOnboard(true)}>Onboard connection or targets</button>}
      </PageHeader>
      {onboard && write && <Onboarding onCancel={() => setOnboard(false)} />}

      <div className="inv-listbar">
        <div className="tabs inv-views" role="group" aria-label="Connection kind">
          {KINDS.map(([value, label]) => (
            <button key={value} type="button" className={(kind ?? "") === value ? "on" : ""} aria-pressed={(kind ?? "") === value} onClick={() => set("kind", value)}>{label}</button>
          ))}
        </div>
        <label className="inv-field"><span>Collector</span>
          <input value={collector ?? ""} placeholder="Any collector" onChange={e => set("collector_type", e.target.value, true)} />
        </label>
      </div>

      <ErrorNotice error={query.error} retry={() => void query.refetch()} />
      {query.isPending && <p className="hint" role="status">Loading connections</p>}
      {query.data?.length === 0 && (
        <div className="results"><p className="tableempty">{kind || collector ? "No matching connections" : "No connections"}</p></div>
      )}
      {query.data && query.data.length > 0 && (
        <div className="results inv-table">
          <table>
            <thead>
              <tr><th>Connection</th><th>Collector</th><th>Collection</th><th>Targets</th><th>Devices</th><th>Last success</th><th>Last attempt</th></tr>
            </thead>
            <tbody>
              {query.data.map(c => (
                <tr key={c.id}>
                  <td>
                    <div className="inv-cell-stack">
                      <Link className="inv-row-name" to={connectionLink(c.id)}>{c.display_name}</Link>
                      <span className="inv-muted mono">{c.name}</span>
                      {!c.enabled && <Badge>Disabled</Badge>}
                    </div>
                  </td>
                  <td><div className="inv-cell-stack"><span>{c.collector_type}</span><span className="inv-muted">{humanize(c.kind)}</span></div></td>
                  <td>
                    <div className="inv-cell-stack">
                      <StateBadge map={COLLECTION_STATE} value={c.health.state} />
                      {c.health.failing_targets > 0 && <span className="inv-muted">{plural(c.health.failing_targets, "failing target")}</span>}
                    </div>
                  </td>
                  <td>{c.health.target_count.toLocaleString()}</td>
                  <td>{c.health.device_count.toLocaleString()}</td>
                  <td>{formatTime(c.health.last_success_at)}</td>
                  <td>{formatTime(c.health.last_attempt_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
