import { useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { JobHistory, RunHistory } from "../../api/types";
import { CollectionProgressView } from "../../settings/CollectionProgress";
import { inventoryApi, type ConnectionView, type PreviewRequest } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { useCapabilities, useAction, useCatalog, collectConnection } from "../shared";
import { Badge, StateBadge } from "../ui/Badge";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ImpactReview } from "../ui/ImpactReview";
import { SaveWarnings, type ConnectionSaveState } from "../ui/SaveWarnings";
import { LocationsBrowser } from "../sites/LocationsBrowser";
import { Card, Facts, PageHeader, Stat } from "../ui/Page";
import { COLLECTION_STATE, flatten, formatTime, formatValue, humanize } from "../ui/format";
import { MetadataFields, materialize } from "./MetadataFields";
import { TargetPanel } from "./TargetPanel";
import { AddTargets } from "./Onboarding";
import { ProfileEditor } from "../profiles/ProfileEditor";

const TABS = [["targets", "Targets"], ["locations", "Reported locations"], ["configuration", "Configuration"]] as const;
type Tab = typeof TABS[number][0];

export function ConnectionDetailPage() {
  const { id = "" } = useParams(); const { read } = useCapabilities();
  const query = useQuery({ queryKey: inventoryKeys.connections.detail(id), queryFn: () => inventoryApi.getConnection(id), enabled: read && !!id });
  return (
    <section className="ops-page inv-page">
      <Link className="inv-back" to="/inventory/connections">All connections</Link>
      {!read ? <p className="hint">No runs.manage permission</p> : <>
        <ErrorNotice error={query.error} retry={() => void query.refetch()} />
        {query.isPending && <p className="hint" role="status">Loading connection</p>}
        {query.data && <ConnectionDetail key={query.data.id} connection={query.data} />}
      </>}
    </section>
  );
}

function ConnectionDetail({ connection }: { connection: ConnectionView }) {
  const { write, sites: canMapSites } = useCapabilities();
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const focusedTarget = params.get("target_id");
  const action = useAction("connection");
  const [saveWarnings, setSaveWarnings] = useState<string[]>(() => (location.state as ConnectionSaveState | null)?.saveWarnings ?? []);
  const dismissWarnings = () => {
    setSaveWarnings([]);
    if ((location.state as ConnectionSaveState | null)?.saveWarnings) navigate({ pathname: location.pathname, search: location.search }, { replace: true, state: null });
  };
  const [tab, setTab] = useState<Tab>("targets");
  const [review, setReview] = useState<PreviewRequest | null>(null);
  const [adding, setAdding] = useState(false);
  const targets = useQuery({ queryKey: inventoryKeys.targets.list(connection.id), queryFn: () => inventoryApi.listTargets({ connection_id: connection.id }) });
  const activeTargets = targets.data?.filter(t => !t.archived_at) ?? [];
  const h = connection.health;
  return <>
    <PageHeader title={connection.display_name} meta={<>
      {connection.enabled ? <Badge tone="ok">Enabled</Badge> : <Badge>Disabled</Badge>}
      <StateBadge map={COLLECTION_STATE} value={h.state} />
      <span className="mono">{connection.name}</span>
      <span>{connection.collector_type}, {connection.kind}</span>
    </>}>
      <Link className="secondary" to={`/inventory/devices?connection_id=${encodeURIComponent(connection.id)}`}>Discovered devices</Link>
      {write && <>
        <button type="button" className="secondary" disabled={action.pending}
          onClick={() => action.run(() => inventoryApi.patchConnection(connection.id, { expected_revision: connection.revision, enabled: !connection.enabled }), saved => setSaveWarnings(saved.warnings ?? []))}>
          {connection.enabled ? "Disable connection" : "Enable connection"}
        </button>
        <button type="button" className="secondary inv-danger" onClick={() => setReview({ operation: "delete_connection", selection: { ids: [connection.id] }, change: {} })}>Delete connection</button>
      </>}
      <button type="button" className="primary" disabled={!connection.enabled || action.pending}
        onClick={() => action.run(() => collectConnection(connection.name), result => action.setMessage("job_id" in result ? `Collection job ${result.job_id} queued` : `Collection run ${result.id} ${result.status}`))}>
        Collect connection once
      </button>
    </PageHeader>

    <ErrorNotice error={action.error} />
    <SaveWarnings subject={connection.display_name} warnings={saveWarnings} onDismiss={dismissWarnings} />
    {action.message && <div className="banner ok" role="status"><p>{action.message}</p></div>}
    <div className="inv-stats">
      <Stat label="Targets" value={h.target_count.toLocaleString()} />
      <Stat label="Devices" value={h.device_count.toLocaleString()} />
      <Stat label="Failing targets" value={h.failing_targets.toLocaleString()} />
      <Stat label="Last success" value={formatTime(h.last_success_at)} />
      <Stat label="Last attempt" value={formatTime(h.last_attempt_at)} />
    </div>
    {connection.collector_type === "velocloud" && <ConnectionProgress source={connection.name} />}

    <div className="tabs" role="tablist" aria-label="Connection sections">
      {TABS.map(([key, label]) => (
        <button key={key} type="button" role="tab" id={`connection-tab-${key}`} aria-selected={tab === key} aria-controls={`connection-panel-${key}`}
          className={tab === key ? "on" : ""} onClick={() => setTab(key)}>{label}</button>
      ))}
    </div>
    <div className="inv-tabpanel" role="tabpanel" id={`connection-panel-${tab}`} aria-labelledby={`connection-tab-${tab}`}>
      {tab === "targets" && <>
        <div className="inv-listbar">
          <span className="hint">{activeTargets.length.toLocaleString()} active targets</span>
          <div className="inv-actions">
            <button type="button" className="secondary" onClick={() => void targets.refetch()}>Refresh</button>
            {write && connection.kind === "direct" && !adding && <button type="button" className="primary" onClick={() => setAdding(true)}>Add targets</button>}
          </div>
        </div>
        {adding && <AddTargets connection={connection} onClose={() => setAdding(false)} />}
        <ErrorNotice error={targets.error} retry={() => void targets.refetch()} />
        {targets.isPending && <p className="hint" role="status">Loading targets</p>}
        {targets.data && activeTargets.length === 0 && <div className="results"><p className="tableempty">No targets</p></div>}
        {activeTargets.map(t => <TargetPanel key={t.id} target={t} connection={connection} focused={t.id === focusedTarget} />)}
      </>}
      {tab === "locations" && <>
        <LocationsBrowser connectionId={connection.id} initialState="mapped" canEdit={canMapSites} />
      </>}
      {tab === "configuration" && <Configuration connection={connection} onSaved={saved => setSaveWarnings(saved.warnings ?? [])} />}
    </div>

    {review && <ImpactReview request={review} onCancel={() => setReview(null)} onDone={() => navigate("/inventory/connections")} />}
  </>;
}

function Configuration({ connection, onSaved }: { connection: ConnectionView; onSaved: (saved: ConnectionView) => void }) {
  const { write } = useCapabilities();
  const catalog = useCatalog();
  const [editing, setEditing] = useState(false);
  const config = flatten(connection.config);
  const fields = catalog.metadata.data?.find(m => m.collector_type === connection.collector_type)?.fields ?? [];
  const labelOf = (path: string) => fields.find(f => f.path === path)?.label || humanize(path);
  if (editing && write) return <ConnectionEditor connection={connection} onClose={() => setEditing(false)} onSaved={saved => { setEditing(false); onSaved(saved); }} />;
  return (
    <Card title="Endpoint and collector settings" actions={write && <button type="button" className="secondary" onClick={() => setEditing(true)}>Edit connection</button>}>
      <Facts rows={[
        ["Source key", <span className="mono">{connection.name}</span>],
        ["Collector", connection.collector_type],
        ["Kind", humanize(connection.kind)],
        ["Default profile", connection.profile_id ?? "None"],
        ["Revision", connection.revision],
        ...config.map(([path, value]) => [labelOf(path), formatValue(value)] as [string, string]),
      ]} />
    </Card>
  );
}

function ConnectionEditor({ connection, onClose, onSaved }: { connection: ConnectionView; onClose: () => void; onSaved: (saved: ConnectionView) => void }) {
  const catalog = useCatalog(); const action = useAction("connection");
  const profiles = useQuery({ queryKey: inventoryKeys.profiles.list(connection.collector_type), queryFn: () => inventoryApi.listProfiles({ collector_type: connection.collector_type }) });
  const [name, setName] = useState(connection.display_name);
  const [config, setConfig] = useState(connection.config);
  const [profile, setProfile] = useState(connection.profile_id ?? "");
  const [inline, setInline] = useState(false);
  const metadata = catalog.metadata.data?.find(m => m.collector_type === connection.collector_type);
  const schema = catalog.schemas.data?.types.find(s => s.type === connection.collector_type)?.schema;
  return (
    <Card title="Edit connection">
      <ErrorNotice error={action.error || profiles.error || catalog.metadata.error || catalog.schemas.error} />
      <form className="inv-form" onSubmit={e => {
        e.preventDefault();
        if (!schema || !metadata) return;
        void action.run(() => inventoryApi.patchConnection(connection.id, {
          expected_revision: connection.revision, display_name: name,
          config: { ...materialize(schema, metadata, "connection", config), ...(connection.kind === "controller" ? materialize(schema, metadata, "target", config) : {}) },
          profile_id: profile || null, clear_profile: !profile,
        }), onSaved);
      }}>
        <label className="inv-field"><span>Connection display name</span><input value={name} required onChange={e => setName(e.target.value)} /></label>
        {schema && metadata && <>
          <MetadataFields schema={schema} metadata={metadata} category="connection" value={config} onChange={setConfig} editing />
          {connection.kind === "controller" && <MetadataFields schema={schema} metadata={metadata} category="target" value={config} onChange={setConfig} editing />}
        </>}
        <label className="inv-field"><span>Connection default profile</span>
          <select value={profile} onChange={e => setProfile(e.target.value)}>
            <option value="">No default profile</option>
            {profiles.data?.filter(p => !p.archived_at).map(p => <option key={p.id} value={p.id}>{p.display_name}</option>)}
          </select>
        </label>
        <div className="inv-actions">
          <button type="submit" className="primary" disabled={action.pending || !schema || !metadata}>Save connection</button>
          <button type="button" className="secondary" onClick={() => setInline(true)}>Create profile inline</button>
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
        </div>
      </form>
      {inline && <ProfileEditor collectorType={connection.collector_type} onSaved={p => { setProfile(p.id); setInline(false); }} onCancel={() => setInline(false)} />}
    </Card>
  );
}

function ConnectionProgress({ source }: { source: string }) {
  const runs = useQuery({ queryKey: ["runs"], queryFn: () => api<RunHistory>("/runs"), refetchInterval: 5000 });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api<JobHistory>("/jobs"), refetchInterval: 5000 });
  const active = runs.data?.runs.filter(r => r.status === "running" && (r.source === source || r.source === "cycle")) ?? [];
  const activeJobs = jobs.data?.jobs.filter(j => j.source === source && (j.state === "running" || j.state === "queued")) ?? [];
  const queuedRuns = runs.data?.pending_runs?.filter(j => j.source === source) ?? [];
  const progress = [...new Map([...active, ...activeJobs].flatMap(r => r.progress ?? []).filter(p => p.source === source).map(p => [p.source, p])).values()];
  return <>
    {active.length + activeJobs.length + queuedRuns.length > 0 && progress.length === 0 && <p className="hint" role="status">Collection queued</p>}
    {progress.map(p => <CollectionProgressView key={p.source} progress={p} />)}
  </>;
}
