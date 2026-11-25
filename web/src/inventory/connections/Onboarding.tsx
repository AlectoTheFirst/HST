import { useState } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { inventoryApi, type ConnectionView, type TargetCreate } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { useAction, useCatalog, connectionLink } from "../shared";
import { Badge } from "../ui/Badge";
import { ErrorNotice } from "../ui/ErrorNotice";
import { Card, ConfirmDialog, Facts } from "../ui/Page";
import { flatten, formatValue, humanize, plural } from "../ui/format";
import { SitePicker } from "../ui/SitePicker";
import { MetadataFields, materialize } from "./MetadataFields";
import { ProfileEditor } from "../profiles/ProfileEditor";
import type { ConnectionSaveState } from "../ui/SaveWarnings";

export function parseTargets(text: string): Array<{ host: string; port?: number }> {
  const rows = text.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  if (!rows.length) throw new Error("No host");
  if (rows.length > 1000) throw new Error("More than 1000 targets");
  const seen = new Set<string>();
  return rows.map((row, i) => {
    const parts = row.split(/[\s,]+/);
    const host = parts[0];
    if (parts.length > 2 || !host || /[/?#@]/.test(host) || host.includes("://")) throw new Error(`Row ${i + 1}: not a hostname or IP address`);
    if (seen.has(host)) throw new Error(`Row ${i + 1}: duplicate host ${host}`);
    seen.add(host);
    const port = parts.length === 2 ? Number(parts[1]) : undefined;
    if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) throw new Error(`Row ${i + 1}: port outside 1 to 65535`);
    return { host, ...(port === undefined ? {} : { port }) };
  });
}

export function Onboarding({ onCancel }: { onCancel: () => void }) {
  const navigate = useNavigate();
  const catalog = useCatalog();
  const connections = useQuery({ queryKey: inventoryKeys.connections.list({ kind: "direct" }), queryFn: () => inventoryApi.listConnections({ kind: "direct" }) });
  const profiles = useQuery({ queryKey: inventoryKeys.profiles.list(), queryFn: () => inventoryApi.listProfiles() });
  const controllers = useQuery({ queryKey: inventoryKeys.connections.list({ kind: "controller" }), queryFn: () => inventoryApi.listConnections({ kind: "controller" }) });
  const [copyFrom, setCopyFrom] = useState("");
  const action = useAction("connection");
  const [kind, setKind] = useState<"direct" | "controller">("direct");
  const [existing, setExisting] = useState("");
  const [collector, setCollector] = useState("");
  const [name, setName] = useState("");
  const [display, setDisplay] = useState("");
  const [config, setConfig] = useState<Record<string, Record<string, unknown>>>({});
  const [profile, setProfile] = useState("");
  const [inlineProfile, setInlineProfile] = useState(false);
  const [hosts, setHosts] = useState("");
  const [site, setSite] = useState("");
  const [plan, setPlan] = useState<{ connection: Parameters<typeof inventoryApi.createConnection>[0] | null; targets: Array<{ host: string; port?: number; endpoint_config?: Record<string, unknown> }> } | null>(null);
  const [created, setCreated] = useState<ConnectionView | null>(null);
  const [savedHosts, setSavedHosts] = useState<string[]>([]);
  const [leaving, setLeaving] = useState(false);
  const selectedConnection = connections.data?.find(c => c.id === existing);
  const type = selectedConnection?.collector_type ?? collector;
  const metadata = catalog.metadata.data?.find(m => m.collector_type === type);
  const schema = catalog.schemas.data?.types.find(s => s.type === type)?.schema;
  const profileName = profiles.data?.find(p => p.id === profile)?.display_name;
  // ZIA and ZPA sign in with one OneAPI client: a new connection of either can
  // copy the vanity domain, the client ID and the credential of an existing one
  const zscaler = type === "zia" || type === "zpa";
  const zscalerConnections = (controllers.data ?? []).filter(c => c.collector_type === "zia" || c.collector_type === "zpa");
  const copied = zscalerConnections.find(c => c.id === copyFrom);
  const copiedProfile = profiles.data?.find(p => p.id === copied?.profile_id);
  const seed = copiedProfile
    ? { settings: { auth: { client_id: (copiedProfile.settings.auth as Record<string, unknown> | undefined)?.client_id } }, credentialId: copiedProfile.credential_id }
    : undefined;
  function copyZscaler(id: string) {
    setCopyFrom(id);
    const from = zscalerConnections.find(c => c.id === id);
    if (from && typeof from.config.vanity_domain === "string") {
      setConfig({ ...config, [type]: { ...(config[type] ?? {}), vanity_domain: from.config.vanity_domain } });
    }
  }
  async function save() {
    if (!plan) return;
    await action.run(async () => {
      let connection = created ?? selectedConnection;
      if (!connection && plan.connection) { connection = await inventoryApi.createConnection(plan.connection); setCreated(connection); }
      if (!connection) throw new Error("No connection selected");
      for (const target of plan.targets) {
        if (savedHosts.includes(target.host)) continue;
        await inventoryApi.createTarget({ ...target, connection_id: connection.id, profile_id: existing ? profile || null : null, onboarding_site_id: site || null });
        setSavedHosts(current => [...current, target.host]);
      }
      return connection;
    }, connection => {
      // the create response carries the save warnings; the detail page shows them
      const state: ConnectionSaveState = { saveWarnings: connection.warnings ?? [] };
      navigate(connectionLink(connection.id), { state });
    });
  }
  return (
    <Card label="Onboard connection" title="Onboard collection"
      actions={<button type="button" className="secondary" disabled={action.pending} onClick={() => setLeaving(true)}>Close onboarding</button>}>
      <ErrorNotice error={action.error || catalog.metadata.error || catalog.schemas.error || connections.error || profiles.error} />
      <form className="inv-form" onSubmit={e => {
        e.preventDefault();
        void action.run(async () => {
          if (!schema || !metadata) throw new Error("No collector type selected");
          if (!existing && !profile) throw new Error("No profile selected");
          return {
            connection: existing ? null : {
              name, display_name: display || name, collector_type: type, profile_id: profile,
              config: { ...materialize(schema, metadata, "connection", config[type] ?? {}), ...(kind === "controller" ? materialize(schema, metadata, "target", config[type] ?? {}) : {}) },
              enabled: false,
            },
            targets: kind === "direct" ? parseTargets(hosts) : [],
          };
        }, setPlan);
      }}>
        <fieldset disabled={!!plan || !!created || action.pending}>
          <legend>Connection</legend>
          <div className="inv-form-grid">
            <label className="inv-field"><span>Onboarding type</span>
              <select value={kind} onChange={e => { setKind(e.target.value as "direct" | "controller"); setExisting(""); setCollector(""); setProfile(""); }}>
                <option value="direct">Direct targets</option>
                <option value="controller">Controller discovery</option>
              </select>
            </label>
            {kind === "direct" && (
              <label className="inv-field"><span>Connection</span>
                <select value={existing} onChange={e => { setExisting(e.target.value); setProfile(""); }}>
                  <option value="">Create a new connection</option>
                  {connections.data?.filter(c => c.kind === "direct").map(c => <option key={c.id} value={c.id}>{c.display_name}</option>)}
                </select>
              </label>
            )}
            {!existing && <>
              <label className="inv-field"><span>Collector type</span>
                <select value={collector} required onChange={e => { setCollector(e.target.value); setProfile(""); }}>
                  <option value="">Choose collector</option>
                  {catalog.metadata.data?.filter(m => m.kind === kind).map(m => <option key={m.collector_type}>{m.collector_type}</option>)}
                </select>
              </label>
              <label className="inv-field"><span>Source key</span>
                <input required pattern="[a-z0-9-]{2,32}" minLength={2} maxLength={32} value={name} placeholder="lowercase-key" onChange={e => setName(e.target.value)} />
              </label>
              <label className="inv-field"><span>Display name</span><input value={display} onChange={e => setDisplay(e.target.value)} /></label>
            </>}
          </div>
          {!existing && zscaler && zscalerConnections.length > 0 && (
            <label className="inv-field"><span>Copy from a Zscaler connection</span>
              <select value={copyFrom} onChange={e => copyZscaler(e.target.value)}>
                <option value="">Enter the values</option>
                {zscalerConnections.map(c => <option key={c.id} value={c.id}>{c.display_name} ({c.collector_type})</option>)}
              </select>
            </label>
          )}
          {!existing && schema && metadata && <>
            <MetadataFields schema={schema} metadata={metadata} category="connection" value={config[type] ?? {}} onChange={next => setConfig({ ...config, [type]: next })} />
            {kind === "controller" && <MetadataFields schema={schema} metadata={metadata} category="target" value={config[type] ?? {}} onChange={next => setConfig({ ...config, [type]: next })} />}
          </>}
        </fieldset>
        <fieldset disabled={!!plan || !!created || action.pending}>
          <legend>Access profile</legend>
          <div className="inv-inline-form">
            <label className="inv-field"><span>Collection profile</span>
              <select required={!existing} value={profile} onChange={e => setProfile(e.target.value)}>
                <option value="">{existing ? "Follow connection profile" : "Choose a profile"}</option>
                {profiles.data?.filter(p => p.collector_type === type && !p.archived_at).map(p => <option key={p.id} value={p.id}>{p.display_name} (revision {p.current_revision})</option>)}
              </select>
            </label>
            <button type="button" className="secondary" disabled={!type} onClick={() => setInlineProfile(true)}>Create profile inline</button>
          </div>
        </fieldset>
        {kind === "direct" && (
          <fieldset disabled={!!plan || !!created || action.pending}>
            <legend>Targets</legend>
            <label className="inv-field"><span>Hosts and optional ports</span>
              <textarea required value={hosts} onChange={e => setHosts(e.target.value)} placeholder={"router.example 22\n192.0.2.10"} />
            </label>
            <SitePicker label="Initial site" value={site} emptyLabel="Automatic placement" onChange={id => setSite(id)} />
          </fieldset>
        )}
        {!plan && <div className="inv-actions"><button type="submit" className="primary" disabled={!schema || !metadata}>Preview onboarding</button></div>}
      </form>
      {inlineProfile && type && <ProfileEditor collectorType={type} seed={zscaler ? seed : undefined} onSaved={p => { setProfile(p.id); setInlineProfile(false); }} onCancel={() => setInlineProfile(false)} />}
      {plan && (
        <section className="inv-review-section" aria-label="Onboarding preview">
          <h3 className="card-title">Confirm onboarding</h3>
          <Facts rows={[
            ["Connection", plan.connection ? `New disabled connection ${plan.connection.display_name}` : selectedConnection?.display_name ?? "None"],
            ...(plan.connection ? [["Source key", <span className="mono">{plan.connection.name}</span>], ["Collector", type]] as Array<[string, React.ReactNode]> : []),
            ["Profile", profileName || "Connection profile"],
            ["New targets", plan.targets.length],
            ...(plan.connection ? flatten(plan.connection.config ?? {}).map(([path, value]) => [humanize(path), formatValue(value)] as [string, string]) : []),
          ]} />
          {plan.targets.length > 0 && (
            <ul className="inv-list">
              {plan.targets.map(t => (
                <li key={t.host}>
                  <span className="mono">{t.host}{t.port ? ` port ${t.port}` : ""}</span>{" "}
                  {savedHosts.includes(t.host) ? <Badge tone="ok">Saved</Badge> : <Badge>Pending</Badge>}
                  {!savedHosts.includes(t.host) && <TargetIdentityFields collectorType={type} value={t.endpoint_config ?? {}}
                    onChange={endpoint_config => setPlan({ ...plan, targets: plan.targets.map(target => target.host === t.host ? { ...target, endpoint_config } : target) })} />}
                </li>
              ))}
            </ul>
          )}
          {created && <p className="hint">Connection {created.display_name} saved</p>}
          {(created || savedHosts.length > 0) && plan.targets.some(t => !savedHosts.includes(t.host)) && (
            <RemainingTargets key={savedHosts.join(",")} targets={plan.targets} saved={savedHosts}
              onChange={remaining => setPlan({ ...plan, targets: [...plan.targets.filter(t => savedHosts.includes(t.host)), ...remaining] })} />
          )}
          <div className="inv-actions">
            <button type="button" className="primary" disabled={action.pending} onClick={() => void save()}>{action.pending ? "Saving" : "Save reviewed onboarding"}</button>
            <button type="button" className="secondary" disabled={action.pending || !!created || savedHosts.length > 0} onClick={() => setPlan(null)}>Edit draft</button>
          </div>
        </section>
      )}
      {leaving && (
        <ConfirmDialog label="Leave onboarding" title="Leave onboarding" confirmLabel="Leave onboarding" cancelLabel="Stay"
          onConfirm={() => { setLeaving(false); onCancel(); }} onCancel={() => setLeaving(false)}>
          <p>Unsaved form values are discarded.</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

export function AddTargets({ connection, onClose }: { connection: ConnectionView; onClose?: () => void }) {
  const profiles = useQuery({ queryKey: inventoryKeys.profiles.list(connection.collector_type), queryFn: () => inventoryApi.listProfiles({ collector_type: connection.collector_type }) });
  const [text, setText] = useState(""); const [profile, setProfile] = useState(""); const [site, setSite] = useState("");
  const [plan, setPlan] = useState<TargetCreate[] | null>(null); const [saved, setSaved] = useState<string[]>([]);
  const [inline, setInline] = useState(false);
  const action = useAction("target");
  const withDefaults = (t: { host: string; port?: number }) => ({ ...t, connection_id: connection.id, profile_id: profile || null, onboarding_site_id: site || null });
  return (
    <Card title="Add direct targets" actions={onClose && <button type="button" className="secondary" disabled={action.pending} onClick={onClose}>Close</button>}>
      <ErrorNotice error={action.error || profiles.error} />
      <form className="inv-form" onSubmit={e => { e.preventDefault(); void action.run(async () => parseTargets(text).map(withDefaults), setPlan); }}>
        <fieldset disabled={!!plan}>
          <legend>Targets</legend>
          <label className="inv-field"><span>Hosts and optional ports</span><textarea required value={text} onChange={e => setText(e.target.value)} /></label>
          <div className="inv-form-grid">
            <label className="inv-field"><span>Target profile</span>
              <select value={profile} onChange={e => setProfile(e.target.value)}>
                <option value="">Follow connection profile</option>
                {profiles.data?.filter(p => !p.archived_at).map(p => <option key={p.id} value={p.id}>{p.display_name}</option>)}
              </select>
            </label>
            <SitePicker label="Initial site" value={site} emptyLabel="Automatic placement" onChange={id => setSite(id)} />
          </div>
          <div className="inv-actions">
            <button type="submit" className="primary">Preview targets</button>
            <button type="button" className="secondary" onClick={() => setInline(true)}>Create profile inline</button>
          </div>
        </fieldset>
      </form>
      {inline && <ProfileEditor collectorType={connection.collector_type} onSaved={p => { setProfile(p.id); setInline(false); }} onCancel={() => setInline(false)} />}
      {plan && (
        <section className="inv-review-section" aria-label="Target preview">
          <p>Save {plural(plan.length, "pending target")}</p>
          <ul className="inv-list">
            {plan.map(t => (
              <li key={t.host}>
                <span className="mono">{t.host}{t.port ? ` port ${t.port}` : ""}</span>{" "}
                {saved.includes(t.host) && <Badge tone="ok">Saved</Badge>}
                {!saved.includes(t.host) && <TargetIdentityFields collectorType={connection.collector_type} value={t.endpoint_config ?? {}}
                  onChange={endpoint_config => setPlan(plan.map(target => target.host === t.host ? { ...target, endpoint_config } : target))} />}
              </li>
            ))}
          </ul>
          <div className="inv-actions">
            <button type="button" className="primary" disabled={action.pending} onClick={() => action.run(async () => {
              for (const target of plan) {
                if (saved.includes(target.host)) continue;
                await inventoryApi.createTarget(target);
                setSaved(s => [...s, target.host]);
              }
            }, () => { setPlan(null); setSaved([]); setText(""); })}>Save targets</button>
            <button type="button" className="secondary" disabled={action.pending || saved.length > 0} onClick={() => setPlan(null)}>Edit target draft</button>
          </div>
          {saved.length > 0 && (
            <RemainingTargets key={saved.join(",")} targets={plan} saved={saved}
              onChange={remaining => setPlan([...plan.filter(t => saved.includes(t.host)), ...remaining.map(withDefaults)])} />
          )}
        </section>
      )}
    </Card>
  );
}

function RemainingTargets({ targets, saved, onChange }: { targets: Array<{ host: string; port?: number | null }>; saved: string[]; onChange: (targets: Array<{ host: string; port?: number }>) => void }) {
  const [text, setText] = useState(() => targets.filter(t => !saved.includes(t.host)).map(t => `${t.host}${t.port ? ` ${t.port}` : ""}`).join("\n"));
  const [error, setError] = useState<unknown>(null);
  return (
    <form className="inv-form" onSubmit={e => {
      e.preventDefault();
      try {
        const rows = parseTargets(text);
        if (rows.some(t => saved.includes(t.host))) throw new Error("Host already saved");
        onChange(rows); setError(null);
      } catch (err) { setError(err); }
    }}>
      <ErrorNotice error={error} />
      <label className="inv-field"><span>Remaining target rows</span><textarea value={text} onChange={e => setText(e.target.value)} /></label>
      <div className="inv-actions"><button type="submit" className="secondary">Update remaining target draft</button></div>
    </form>
  );
}

function TargetIdentityFields({ collectorType, value, onChange }: {
  collectorType: string; value: Record<string, unknown>; onChange: (value: Record<string, unknown>) => void;
}) {
  const catalog = useCatalog();
  const original = catalog.metadata.data?.find(item => item.collector_type === collectorType);
  const schema = catalog.schemas.data?.types.find(item => item.type === collectorType)?.schema;
  const fields = original?.fields.filter(field => field.category === "target" && !["host", "port", "host_key"].includes(field.path));
  if (!original || !schema || !fields?.length) return null;
  return (
    <details>
      <summary>Target identity overrides</summary>
      <MetadataFields schema={schema} metadata={{ ...original, fields }} category="target" value={value} onChange={onChange} />
    </details>
  );
}
