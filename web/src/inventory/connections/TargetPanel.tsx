import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { inventoryApi, type TargetView, type ConnectionView, type PreviewRequest, type ProbeResult } from "../../api/inventory";
import { useCapabilities, useAction, useCatalog, deviceLink } from "../shared";
import { Badge } from "../ui/Badge";
import { EffectiveSettings } from "../ui/EffectiveSettings";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ImpactReview } from "../ui/ImpactReview";
import { ConfirmDialog, Facts } from "../ui/Page";
import { SitePicker } from "../ui/SitePicker";
import { formatTime, plural } from "../ui/format";
import { MetadataFields, materialize } from "./MetadataFields";

export function TargetPanel({ target, connection, focused = false }: { target: TargetView; connection: ConnectionView; focused?: boolean }) {
  const { write } = useCapabilities();
  const action = useAction("target");
  const [probe, setProbe] = useState<ProbeResult | null>(null);
  const [review, setReview] = useState<PreviewRequest | null>(null);
  const [replace, setReplace] = useState(false);
  const [clearPin, setClearPin] = useState(false);
  const card = useRef<HTMLElement>(null);
  useEffect(() => { if (focused) card.current?.scrollIntoView?.({ block: "center" }); }, [focused]);
  const name = target.host || "Controller target";
  const devices = target.observed_device_ids;
  return (
    <article ref={card} className={`editorcard inv-card${focused ? " inv-focused" : ""}`} aria-label={`Target ${target.host || "controller"}`}>
      <div className="bar">
        <h3 className="card-title mono">{name}{target.port ? `:${target.port}` : ""}</h3>
        <div className="inv-head-meta">
          {target.enabled ? <Badge tone="ok">Enabled</Badge> : <Badge>Disabled</Badge>}
          {devices.length ? <Badge>{plural(devices.length, "observed device")}</Badge> : <Badge tone="warn">Pending</Badge>}
          {target.host_key_pinned && <Badge>Host key pinned</Badge>}
          {target.consecutive_failures > 0 && <Badge tone="bad">{plural(target.consecutive_failures, "failure")}</Badge>}
        </div>
      </div>
      <Facts rows={[
        ["Last attempt", formatTime(target.last_attempt_at)],
        ["Last success", formatTime(target.last_success_at)],
        ["Consecutive failures", target.consecutive_failures],
      ]} />
      {target.last_error && <div className="banner err" role="status"><p className="sub">Last collection error: {target.last_error}</p></div>}
      {devices.length > 0 && (
        <div className="inv-chips">
          {devices.map(id => <Link key={id} className="secondary" to={deviceLink(id)}>Observed device {id}</Link>)}
        </div>
      )}
      <ErrorNotice error={action.error} />
      {probe && (
        <div className={probe.ok ? "banner ok" : "banner err"} role="status">
          <p>Probe {probe.ok ? "succeeded" : "failed"}: {probe.message}</p>
          <p className="sub">Profile revision {probe.effective.profile_revision ?? "none"}, credential revision {probe.effective.credential_revision ?? "none"}, {probe.duration_ms} ms</p>
        </div>
      )}
      <div className="inv-actions">
        <button type="button" className="secondary" disabled={action.pending} onClick={() => action.run(() => inventoryApi.probeTarget(target.id), setProbe)}>Probe stored configuration</button>
        {write && <>
          <button type="button" className="secondary" disabled={action.pending}
            onClick={() => action.run(() => inventoryApi.patchTarget(target.id, { expected_revision: target.revision, enabled: !target.enabled }))}>
            {target.enabled ? "Disable target" : "Enable target"}
          </button>
          <Link className="secondary" to={`/inventory/connections/profiles?target_id=${encodeURIComponent(target.id)}`}>Assign target profile</Link>
          <button type="button" className="secondary" onClick={() => setReplace(!replace)} aria-expanded={replace}>Replace endpoint</button>
          {target.host_key_pinned && <button type="button" className="secondary" onClick={() => setClearPin(true)}>Reset host key pin</button>}
          <button type="button" className="secondary inv-danger" onClick={() => setReview({ operation: "delete_target", selection: { ids: [target.id] }, change: {} })}>Delete target</button>
        </>}
      </div>
      <EffectiveSettings targetId={target.id} />
      {write && <TargetSite target={target} />}
      {replace && <Replacement target={target} connection={connection} onCancel={() => setReplace(false)} onReview={request => { setReview(request); setReplace(false); }} />}
      {clearPin && (
        <ConfirmDialog label={`Reset host key pin for ${name}`} title="Reset host key pin" confirmLabel="Reset pin" danger pending={action.pending}
          onCancel={() => setClearPin(false)}
          onConfirm={() => void action.run(() => inventoryApi.patchTarget(target.id, { expected_revision: target.revision, clear_host_key: true }), () => setClearPin(false))}>
          <p>The stored host key for {name} is removed.</p>
          <ErrorNotice error={action.error} />
        </ConfirmDialog>
      )}
      {review && <ImpactReview request={review} onCancel={() => setReview(null)} onDone={() => setReview(null)} />}
    </article>
  );
}

function TargetSite({ target }: { target: TargetView }) {
  const [site, setSite] = useState(target.onboarding_site_id ?? ""); const action = useAction("target");
  return (
    <form className="inv-inline-form" onSubmit={e => {
      e.preventDefault();
      void action.run(() => inventoryApi.patchTarget(target.id, { expected_revision: target.revision, onboarding_site_id: site || null, clear_onboarding_site: !site }));
    }}>
      <SitePicker label="Initial site" value={site} emptyLabel="Automatic placement" onChange={id => setSite(id)} />
      <button type="submit" className="secondary" disabled={action.pending || site === (target.onboarding_site_id ?? "")}>Save initial site</button>
      <ErrorNotice error={action.error} />
    </form>
  );
}

function Replacement({ target, connection, onCancel, onReview }: { target: TargetView; connection: ConnectionView; onCancel: () => void; onReview: (request: PreviewRequest) => void }) {
  const catalog = useCatalog();
  const [host, setHost] = useState(target.host);
  const [port, setPort] = useState(target.port?.toString() ?? "");
  const [config, setConfig] = useState<Record<string, unknown>>(target.kind === "direct" ? {} : connection.config);
  const metadata = catalog.metadata.data?.find(m => m.collector_type === connection.collector_type);
  const schema = catalog.schemas.data?.types.find(s => s.type === connection.collector_type)?.schema;
  return (
    <form className="inv-form" onSubmit={e => {
      e.preventDefault();
      if (!schema || !metadata) return;
      onReview({ operation: "replace_target", selection: { ids: [target.id] }, change: {
        endpoint_config: target.kind === "direct"
          ? { ...materialize(schema, metadata, "target", config), host, ...(port ? { port: Number(port) } : {}) }
          : { ...materialize(schema, metadata, "connection", config), ...materialize(schema, metadata, "target", config) },
      } });
    }}>
      <fieldset>
        <legend>Replace {target.host || "controller endpoint"}</legend>
        <ErrorNotice error={catalog.metadata.error || catalog.schemas.error} />
        {target.kind === "direct" ? <>
          <div className="inv-form-grid">
            <label className="inv-field"><span>Replacement host</span><input required value={host} onChange={e => setHost(e.target.value)} /></label>
            <label className="inv-field"><span>Replacement port</span><input type="number" min={1} max={65535} value={port} onChange={e => setPort(e.target.value)} /></label>
          </div>
          {schema && metadata && <MetadataFields schema={schema} metadata={{ ...metadata, fields: metadata.fields.filter(f => !["host", "port"].includes(f.path)) }} category="target" value={config} onChange={setConfig} />}
        </> : schema && metadata && <>
          <MetadataFields schema={schema} metadata={metadata} category="connection" value={config} onChange={setConfig} markIdentity />
          <MetadataFields schema={schema} metadata={metadata} category="target" value={config} onChange={setConfig} markIdentity />
        </>}
        <div className="inv-actions">
          <button type="submit" className="primary" disabled={!schema || !metadata}>Preview replacement</button>
          <button type="button" className="secondary" onClick={onCancel}>Cancel replacement</button>
        </div>
      </fieldset>
    </form>
  );
}
