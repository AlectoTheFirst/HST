import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { inventoryApi, type ProfileView, type CredentialView, type PreviewRequest } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { useCapabilities, useCatalog, useAction } from "../shared";
import { Badge } from "../ui/Badge";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ImpactReview } from "../ui/ImpactReview";
import { Card, ConfirmDialog, PageHeader } from "../ui/Page";
import { plural } from "../ui/format";
import { ProfileEditor } from "./ProfileEditor";
import { CredentialEditor } from "./CredentialEditor";

export function ProfilesPage() {
  const { write } = useCapabilities();
  return (
    <section className="ops-page inv-page">
      <Link className="inv-back" to="/inventory/connections">Connections</Link>
      <PageHeader title="Profiles and credentials" />
      {write ? <ProfilesWorkspace /> : <p className="hint" role="status">No sources.write permission</p>}
    </section>
  );
}

function ProfilesWorkspace() {
  const catalog = useCatalog();
  const profiles = useQuery({ queryKey: inventoryKeys.profiles.list(), queryFn: () => inventoryApi.listProfiles() });
  const credentials = useQuery({ queryKey: inventoryKeys.credentials.list(), queryFn: inventoryApi.listCredentials });
  const targets = useQuery({ queryKey: inventoryKeys.targets.list(), queryFn: () => inventoryApi.listTargets() });
  const connections = useQuery({ queryKey: inventoryKeys.connections.list({}), queryFn: () => inventoryApi.listConnections() });
  const [params] = useSearchParams();
  const [selected, setSelected] = useState<string[]>(() => params.getAll("target_id"));
  const [collector, setCollector] = useState("");
  const [edit, setEdit] = useState<ProfileView | "new" | null>(null);
  const [credentialEdit, setCredentialEdit] = useState<CredentialView | "new" | null>(null);
  const [assignment, setAssignment] = useState("");
  const [review, setReview] = useState<PreviewRequest | null>(null);
  const [remove, setRemove] = useState<{ kind: "profile" | "credential"; value: ProfileView | CredentialView } | null>(null);
  const action = useAction();
  const collectorTypes = new Set(targets.data?.filter(t => selected.includes(t.id)).map(t => connections.data?.find(c => c.id === t.connection_id)?.collector_type).filter(Boolean));
  const compatible = profiles.data?.filter(p => !p.archived_at && (collectorTypes.size === 0 || (collectorTypes.size === 1 && collectorTypes.has(p.collector_type))));
  const missing = selected.filter(id => !targets.data?.some(t => t.id === id));
  return <>
    <ErrorNotice error={profiles.error || credentials.error || targets.error || connections.error || catalog.metadata.error}
      retry={() => { void profiles.refetch(); void credentials.refetch(); void targets.refetch(); void connections.refetch(); }} />

    <Card title="Profiles" actions={!edit && <>
      <label className="inv-field"><span className="inv-sr">Collector for new profile</span>
        <select value={collector} onChange={e => setCollector(e.target.value)}>
          <option value="">Choose collector</option>
          {catalog.metadata.data?.map(m => <option key={m.collector_type}>{m.collector_type}</option>)}
        </select>
      </label>
      <button type="button" className="primary" disabled={!collector} onClick={() => setEdit("new")}>Create profile</button>
    </>}>
      {edit && <ProfileEditor key={edit === "new" ? `new-${collector}` : edit.id} collectorType={edit === "new" ? collector : edit.collector_type}
        profile={edit === "new" ? undefined : edit} onCancel={() => setEdit(null)} onSaved={() => setEdit(null)} />}
      {profiles.isPending && <p className="hint" role="status">Loading profiles</p>}
      {profiles.data?.length === 0 && <p className="tableempty">No profiles</p>}
      {!!profiles.data?.length && (
        <div className="results inv-table">
          <table>
            <thead><tr><th>Name</th><th>Collector</th><th>Revision</th><th>Used by</th><th className="inv-col-actions">Actions</th></tr></thead>
            <tbody>
              {profiles.data.map(p => (
                <tr key={p.id}>
                  <td>{p.display_name} {p.archived_at && <Badge>Archived</Badge>}</td>
                  <td>{p.collector_type}</td>
                  <td>{p.current_revision}</td>
                  <td>{plural(p.usage.connections, "connection")}, {plural(p.usage.targets, "target")}</td>
                  <td className="inv-col-actions">
                    {!p.archived_at && (
                      <div className="inv-actions">
                        <button type="button" className="secondary" aria-label={`Edit ${p.display_name}`} onClick={() => setEdit(p)}>Edit</button>
                        <button type="button" className="secondary inv-danger" aria-label={`Archive ${p.display_name}`} onClick={() => { action.reset(); setRemove({ kind: "profile", value: p }); }}>Archive</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>

    <Card title="Credentials" actions={!credentialEdit && <button type="button" className="primary" onClick={() => setCredentialEdit("new")}>Create credential</button>}>
      {credentialEdit && <CredentialEditor key={credentialEdit === "new" ? "new" : credentialEdit.id} collectorType={credentialEdit === "new" ? collector || undefined : undefined}
        credential={credentialEdit === "new" ? undefined : credentialEdit} onCancel={() => setCredentialEdit(null)} onSaved={() => setCredentialEdit(null)} />}
      {credentials.data?.length === 0 && <p className="tableempty">No credentials</p>}
      {!!credentials.data?.length && (
        <div className="results inv-table">
          <table>
            <thead><tr><th>Name</th><th>Revision</th><th>Stored secret fields</th><th>Profiles</th><th className="inv-col-actions">Actions</th></tr></thead>
            <tbody>
              {credentials.data.map(c => (
                <tr key={c.id}>
                  <td>{c.display_name} {c.archived_at && <Badge>Archived</Badge>}</td>
                  <td>{c.current_revision}</td>
                  <td className="mono">{c.secret_paths.join(", ") || "None"}</td>
                  <td>{c.profiles_using.toLocaleString()}</td>
                  <td className="inv-col-actions">
                    {!c.archived_at && (
                      <div className="inv-actions">
                        <button type="button" className="secondary" aria-label={`Rotate or repair ${c.display_name}`} onClick={() => setCredentialEdit(c)}>Rotate</button>
                        <button type="button" className="secondary inv-danger" aria-label={`Archive ${c.display_name}`} onClick={() => { action.reset(); setRemove({ kind: "credential", value: c }); }}>Archive</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>

    <Card title="Assign profiles to targets">
      <fieldset disabled={!!review}>
        <legend>Targets</legend>
        <div className="inv-target-list">
          {targets.data?.filter(t => !t.archived_at).map(t => (
            <label className="inv-check" key={t.id}>
              <input type="checkbox" checked={selected.includes(t.id)} onChange={e => setSelected(e.target.checked ? [...selected, t.id] : selected.filter(id => id !== t.id))} />
              <span className="mono">{t.source_key}</span> {t.host || "Controller"}
              <span className="inv-muted">{plural(t.observed_device_ids.length, "observed device")}</span>
            </label>
          ))}
        </div>
        {targets.data && missing.map(id => <p className="hint" key={id}>Target {id} not available</p>)}
        <div className="inv-inline-form">
          <label className="inv-field"><span>Assign profile</span>
            <select value={assignment} onChange={e => setAssignment(e.target.value)}>
              <option value="">Follow each connection's profile</option>
              {compatible?.map(p => <option key={p.id} value={p.id}>{p.display_name}</option>)}
            </select>
          </label>
          <button type="button" className="primary" disabled={!selected.length || selected.length > 1000 || missing.length > 0}
            onClick={() => setReview({ operation: "assign_target_profile", selection: { ids: selected }, change: { profile_id: assignment || null } })}>Preview target assignment</button>
        </div>
      </fieldset>
    </Card>

    {remove && (
      <ConfirmDialog label={`Archive ${remove.kind} ${remove.value.display_name}`} title={`Archive ${remove.value.display_name}`} confirmLabel="Confirm archive" cancelLabel="Cancel archive" danger
        pending={action.pending} onCancel={() => setRemove(null)}
        onConfirm={() => void action.run(() => remove.kind === "profile"
          ? inventoryApi.deleteProfile(remove.value.id, remove.value.current_revision)
          : inventoryApi.deleteCredential(remove.value.id, remove.value.current_revision), () => setRemove(null))}>
        <ErrorNotice error={action.error} />
      </ConfirmDialog>
    )}
    {review && <ImpactReview request={review} onCancel={() => setReview(null)} onDone={() => { setReview(null); setSelected([]); }} />}
  </>;
}
