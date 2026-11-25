import { DeviceName } from "../../shell/deviceNames";
import { useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { ApiError } from "../../api/client";
import { deviceSelection, useAiContext, useAiPaneId } from "../../ai/context";
import { inventoryApi, type DeviceDetail as DeviceDetailView, type EventView } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { useCapabilities } from "../shared";
import { Badge, StateBadge } from "../ui/Badge";
import { EffectiveSettings } from "../ui/EffectiveSettings";
import { ErrorNotice } from "../ui/ErrorNotice";
import { Card, Facts } from "../ui/Page";
import {
  AUTHORITY, COLLECTION_STATE, LIFECYCLE, OBSERVATION, PLACEMENT_BASIS, PLACEMENT_MODE, PLACEMENT_STATE, PROFILE_ORIGIN,
  flatten, formatTime, formatValue, humanize,
} from "../ui/format";

const TABS = [["overview", "Overview"], ["collection", "Collection"], ["routing", "Routing"], ["history", "History"]] as const;
type Tab = typeof TABS[number][0];

export function DeviceDetail({ id }: { id: string }) {
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const tab: Tab = TABS.find(([key]) => key === params.get("tab"))?.[0] ?? "overview";
  const device = useQuery({ queryKey: inventoryKeys.devices.detail(id), queryFn: () => inventoryApi.getDevice(id) });
  // the inventory publishes the run's collection_ts as the snapshot key
  const snapshotKey = params.get("snapshot_key");
  const summary = device.data?.summary;
  useAiContext(useAiPaneId(), {
    selection: [deviceSelection(id, summary?.graph_uid, summary?.hostname, "url")],
    snapshot: snapshotKey ? { id: snapshotKey, origin: "pinned" } : undefined,
  });
  if (device.isPending) return <p className="hint" role="status">Loading device</p>;
  if (device.error && !device.data) {
    return <div className="inv-detail"><ErrorNotice error={device.error} retry={() => void device.refetch()} /><CachedObservedFacts error={device.error} /></div>;
  }
  const d = device.data!;
  const select = (next: Tab) => {
    const search = new URLSearchParams(params);
    search.set("tab", next);
    setParams(search, { replace: true, state: location.state });
  };
  return (
    <article className="inv-detail">
      <ErrorNotice error={device.error} retry={() => void device.refetch()} />
      <header className="inv-detail-head">
        <h2>{d.summary.hostname || d.summary.graph_uid}</h2>
        <div className="inv-head-meta">
          <StateBadge map={LIFECYCLE} value={d.summary.lifecycle} />
          <StateBadge map={COLLECTION_STATE} value={d.summary.collection_state} />
          <StateBadge map={PLACEMENT_STATE} value={d.summary.placement_state} />
          {d.generation.inventory_sync_pending && <Badge tone="warn">Snapshot publication pending</Badge>}
        </div>
        <div className="inv-head-meta">
          {d.summary.management_address && <span className="mono">{d.summary.management_address}</span>}
          {d.summary.platform && <span>{d.summary.platform}</span>}
        </div>
      </header>
      {d.summary.lifecycle === "archived" && d.observations.some(o => o.state === "current") && (
        <div className="banner warn"><p>Archived and still observed</p></div>
      )}
      <div className="tabs" role="tablist" aria-label="Device sections">
        {TABS.map(([key, label]) => (
          <button key={key} type="button" role="tab" id={`device-tab-${key}`} aria-selected={tab === key} aria-controls={`device-panel-${key}`}
            className={tab === key ? "on" : ""} onClick={() => select(key)}>{label}</button>
        ))}
      </div>
      <div className="inv-tabpanel" role="tabpanel" id={`device-panel-${tab}`} aria-labelledby={`device-tab-${tab}`}>
        {tab === "overview" && <Overview d={d} />}
        {tab === "collection" && <Collection d={d} />}
        {tab === "routing" && <Routing id={id} />}
        {tab === "history" && <History id={id} />}
      </div>
    </article>
  );
}

function Overview({ d }: { d: DeviceDetailView }) {
  const p = d.placement;
  return <>
    <div className="inv-grid-2">
      <Card title="Identity">
        <Facts rows={[
          ["Graph identity", <span className="mono">{d.summary.graph_uid}</span>],
          ["Platform", d.summary.platform || "Unknown"],
          ["Management address", d.summary.management_address ? <span className="mono">{d.summary.management_address}</span> : "None"],
          ["First seen", formatTime(d.summary.first_seen)],
          ["Last observed", formatTime(d.summary.last_seen)],
        ]} />
      </Card>
      <Card title="Placement">
        <Facts rows={[
          ["Current site", p.published_site_code ?? "Unplaced"],
          ["Intent", `${PLACEMENT_MODE[p.mode] ?? p.mode}${p.desired_site_code ? `: ${p.desired_site_code}` : ""}`],
          ["Basis", PLACEMENT_BASIS[p.basis] ?? p.basis],
          ["Publication", p.pending ? "Pending publication" : "Applied"],
          ["Resolution", p.conflict ? "Conflicting reported sites" : p.stale ? "Stale placement evidence" : "Resolved"],
        ]} />
        <details>
          <summary>Revisions</summary>
          <Facts rows={[
            ["Intent revision", p.desired_revision],
            ["Applied revision", p.applied_revision],
            ["Published snapshot", p.published_snapshot_key ? <span className="mono">{p.published_snapshot_key}</span> : "None"],
            ["Origin", humanize(p.origin)],
          ]} />
        </details>
      </Card>
    </div>
    <Card title="Reported placement">
      {p.contributing.length === 0 ? <p className="hint">No reported locations</p> : (
        <div className="results inv-table">
          <table>
            <thead><tr><th>Reported location</th><th>Site</th><th>State</th><th>Authority</th></tr></thead>
            <tbody>
              {p.contributing.map((o, n) => (
                <tr key={n}>
                  <td>{o.location_name || "No reported location"}</td>
                  <td>{o.bound ? o.site_code : <span className="inv-muted">Unmapped</span>}</td>
                  <td><StateBadge map={OBSERVATION} value={o.state} /></td>
                  <td><StateBadge map={AUTHORITY} value={o.authority} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
    <Card title="Related entities">
      {d.related.length === 0 ? <p className="hint">No related entities</p> : (
        <div className="results inv-table">
          <table>
            <thead><tr><th>Type</th><th>Name</th><th>Relation</th><th>Identity</th></tr></thead>
            <tbody>
              {d.related.map(r => (
                <tr key={`${r.relation}:${r.uid}`}>
                  <td>{r.label}</td><td>{r.name}</td><td>{humanize(r.relation.toLowerCase())}</td><td className="mono">{r.uid}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  </>;
}

function Collection({ d }: { d: DeviceDetailView }) {
  const { read } = useCapabilities();
  if (d.observations.length === 0) return <p className="hint">No observations</p>;
  return <>
    {d.observations.map(o => {
      const target = d.collection?.find(t => t.target_id === o.target_id);
      return (
        <Card key={o.target_id} title={<><span className="mono">{o.source_key}</span> {o.host || o.kind}</>}
          actions={read && <Link className="secondary" to={`/inventory/connections/${encodeURIComponent(o.connection_id)}?target_id=${encodeURIComponent(o.target_id)}`}>Manage target</Link>}>
          <div className="inv-head-meta">
            <StateBadge map={OBSERVATION} value={o.state} />
            <StateBadge map={AUTHORITY} value={o.authority} />
          </div>
          <Facts rows={[
            ["Last successful observation", formatTime(o.last_success_at)],
            ["Snapshot", o.last_seen_snapshot_key ? <span className="mono">{o.last_seen_snapshot_key}</span> : "None"],
            ...(read && target ? [
              ["Target", target.enabled ? "Enabled" : "Disabled"],
              ["Profile source", PROFILE_ORIGIN[target.profile_origin] ?? target.profile_origin],
              ["Last attempt", formatTime(target.last_attempt_at)],
              ["Consecutive failures", target.consecutive_failures],
            ] as Array<[string, string | number]> : []),
          ]} />
          {read && target?.last_error && <div className="banner err"><p className="sub">Last error: {target.last_error}</p></div>}
          {o.notes && Object.keys(o.notes).length > 0 && (
            <details>
              <summary>Collector notes</summary>
              <Facts rows={flatten(o.notes).map(([path, value]) => [humanize(path), formatValue(value)])} />
            </details>
          )}
          {read && <EffectiveSettings targetId={o.target_id} />}
        </Card>
      );
    })}
  </>;
}

function Routing({ id }: { id: string }) {
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const snapshotKey = params.get("snapshot_key");
  const [snapshot, setSnapshot] = useState(snapshotKey ?? "");
  const routing = useQuery({ queryKey: inventoryKeys.devices.routing(id, snapshotKey ?? undefined), queryFn: () => inventoryApi.getDeviceRouting(id, { snapshot_key: snapshotKey }) });
  return <>
    <form className="inv-inline-form" onSubmit={e => {
      e.preventDefault();
      const next = new URLSearchParams(params);
      if (snapshot) next.set("snapshot_key", snapshot); else next.delete("snapshot_key");
      setParams(next, { replace: true, state: location.state });
    }}>
      <label className="inv-field"><span>Snapshot key</span><input value={snapshot} placeholder="Current snapshot" onChange={e => setSnapshot(e.target.value)} /></label>
      <button type="submit" className="secondary">Load snapshot</button>
    </form>
    <ErrorNotice error={routing.error} retry={() => void routing.refetch()} />
    {routing.isPending && <p className="hint">Loading routing</p>}
    {routing.data && <>
      <p className="hint">
        Observed snapshot <span className="mono">{routing.data.snapshot_key}</span>, routing group annotations as of {formatTime(routing.data.annotations_as_of)}
      </p>
      {routing.data.contexts.length === 0 && <p className="hint">No routing contexts</p>}
      {routing.data.contexts.map(c => (
        <Card key={c.context_uid} title={`${c.kind}: ${c.identifier}`}
          actions={<Link className="secondary" to={`/inventory/routing-groups?context_uid=${encodeURIComponent(c.context_uid)}`}>View routing groups</Link>}>
          <Facts rows={[
            ["Context UID", <span className="mono">{c.context_uid}</span>],
            ["Owner", <DeviceName uid={c.owner_uid} />],
            ["Management domain", c.management_domain ?? "None"],
            ["Enterprise", c.enterprise_name ?? c.enterprise ?? "None"],
            ["Segment", c.segment ?? "None"],
            ["Virtual system", c.instance_uid ? `${c.instance_uid}${c.vsid != null ? `, VSID ${c.vsid}` : ""}` : "None"],
            ["Declared domain", c.declared_domain ?? "None"],
            ["Membership basis", `${humanize(c.membership_basis)}, ${c.authority ?? "observed"} authority`],
            ["Route targets", c.route_targets.length ? (
              <ul className="inv-list">{c.route_targets.map((r, n) => <li key={n}>{humanize(r.direction)}: {r.value}</li>)}</ul>
            ) : "None"],
            ["Routing groups", c.user_groups.length ? (
              <div className="inv-chips">{c.user_groups.map(g => <Badge key={g.group_id}>{g.display_name}</Badge>)}</div>
            ) : "None"],
          ]} />
        </Card>
      ))}
    </>}
  </>;
}

function History({ id }: { id: string }) {
  const history = useInfiniteQuery({
    queryKey: inventoryKeys.devices.history(id),
    queryFn: ({ pageParam }) => inventoryApi.getDeviceHistory(id, { cursor: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: p => p.next_cursor ?? undefined,
  });
  const events = history.data?.pages.flatMap(p => p.items) ?? [];
  return <>
    <ErrorNotice error={history.error} retry={() => void history.refetch()} />
    {history.isPending && <p className="hint">Loading history</p>}
    {history.data && events.length === 0 && <p className="hint">No history</p>}
    {events.length > 0 && <ol className="inv-timeline">{events.map(e => <HistoryEvent key={e.id} event={e} />)}</ol>}
    {history.hasNextPage && (
      <div><button type="button" className="secondary" disabled={history.isFetchingNextPage} onClick={() => void history.fetchNextPage()}>More history</button></div>
    )}
  </>;
}

function HistoryEvent({ event: e }: { event: EventView }) {
  const before = Object.fromEntries(flatten(e.before ?? {}));
  const after = Object.fromEntries(flatten(e.after ?? {}));
  const fields = [...new Set([...Object.keys(before), ...Object.keys(after)])];
  return (
    <li>
      <span className="mono">{e.action}</span>
      <div className="inv-head-meta">
        <span>{formatTime(e.at)}</span>
        <span>by {e.actor_name ?? e.actor_id ?? "system"}</span>
        <span>{e.snapshot_key ? <>snapshot <span className="mono">{e.snapshot_key}</span></> : "intent change"}</span>
      </div>
      {fields.length > 0 && (
        <details>
          <summary>Changes</summary>
          <div className="results inv-table">
            <table>
              <thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
              <tbody>
                {fields.map(field => (
                  <tr key={field}><td className="mono">{field}</td><td>{formatValue(before[field])}</td><td>{formatValue(after[field])}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </li>
  );
}

/** The cached device facts of a 503 response. */
export function CachedObservedFacts({ error }: { error: unknown }) {
  if (!(error instanceof ApiError) || error.status !== 503 || !("detail" in error)) return null;
  const record = (value: unknown): Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  const fallback = record(error.detail);
  const summary = record(fallback.summary);
  const placement = record(fallback.placement);
  if (!Object.keys(summary).length) return null;
  const label = (value: unknown) => typeof value === "string" && value ? value : "Unknown";
  const observations = Array.isArray(fallback.observations) ? fallback.observations.map(record) : [];
  return (
    <section className="inv-detail" aria-label="Cached device facts">
      <header className="inv-detail-head"><h2>{label(summary.hostname)}</h2></header>
      <div className="banner warn">
        <p>Cached inventory facts</p>
      </div>
      <Card title="Cached facts">
        <Facts rows={[
          ["Snapshot", <span className="mono">{label(fallback.snapshot_key)}</span>],
          ["Snapshot age", typeof fallback.snapshot_age_s === "number" ? `${fallback.snapshot_age_s} seconds` : "Unknown"],
          ["Graph identity", <span className="mono">{label(summary.graph_uid)}</span>],
          ["Platform", label(summary.platform)],
          ["Lifecycle", label(summary.lifecycle)],
          ["Collection state", label(summary.collection_state)],
          ["Placement intent", `${label(placement.mode)}: ${label(placement.desired_site_code)}`],
          ["Published placement", label(placement.published_site_code)],
          ["Publication", placement.pending === true ? "Pending publication" : "See published snapshot"],
        ]} />
      </Card>
      {observations.length > 0 && (
        <Card title="Cached observations">
          <div className="results inv-table">
            <table>
              <thead><tr><th>Source</th><th>Host</th><th>State</th><th>Authority</th></tr></thead>
              <tbody>
                {observations.map((o, index) => (
                  <tr key={index}><td className="mono">{label(o.source_key)}</td><td>{label(o.host)}</td><td>{label(o.state)}</td><td>{label(o.authority)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </section>
  );
}
