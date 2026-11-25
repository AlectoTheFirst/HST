import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { inventoryApi, type ProfileView, type PreviewRequest } from "../../api/inventory";
import { inventoryKeys } from "../queryKeys";
import { useAction, useCatalog } from "../shared";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ImpactReview } from "../ui/ImpactReview";
import { Card } from "../ui/Page";
import { MetadataFields, materialize } from "../connections/MetadataFields";
import { CredentialEditor } from "./CredentialEditor";

export function ProfileEditor({ collectorType, profile, seed, onSaved, onCancel }: {
  collectorType: string; profile?: ProfileView;
  seed?: { settings: Record<string, unknown>; credentialId: string | null };
  onSaved: (profile: ProfileView) => void; onCancel: () => void;
}) {
  const catalog = useCatalog();
  const credentials = useQuery({ queryKey: inventoryKeys.credentials.list(), queryFn: inventoryApi.listCredentials });
  const action = useAction("profile");
  const [name, setName] = useState(profile?.display_name ?? "");
  const [settings, setSettings] = useState<Record<string, unknown>>(profile?.settings ?? seed?.settings ?? {});
  const [credential, setCredential] = useState(profile?.credential_id ?? seed?.credentialId ?? "");
  const [newCredential, setNewCredential] = useState(false);
  const [review, setReview] = useState<PreviewRequest | null>(null);
  const metadata = catalog.metadata.data?.find(m => m.collector_type === collectorType);
  const schema = catalog.schemas.data?.types.find(s => s.type === collectorType)?.schema;
  const selectedCredential = credentials.data?.find(c => c.id === credential);
  return (
    <Card label={profile ? "Edit profile" : "Create profile"} title={profile ? `Edit ${profile.display_name}` : `New ${collectorType} profile`}>
      <ErrorNotice error={action.error || credentials.error || catalog.metadata.error || catalog.schemas.error} />
      {schema && metadata ? (
        <form className="inv-form" onSubmit={e => {
          e.preventDefault();
          const change = { display_name: name, settings: materialize(schema, metadata, "profile", settings), credential_id: credential || null, ...(profile ? { expected_revision: profile.current_revision, clear_credential: !credential } : {}) };
          if (profile) setReview({ operation: "edit_profile", selection: { ids: [profile.id] }, change });
          else void action.run(() => inventoryApi.createProfile({ ...change, collector_type: collectorType }), onSaved);
        }}>
          <fieldset disabled={!!review || action.pending}>
            <legend>Settings</legend>
            <label className="inv-field"><span>Profile name</span><input required value={name} onChange={e => setName(e.target.value)} /></label>
            <p className="hint">Collector {collectorType}</p>
            <MetadataFields schema={schema} metadata={metadata} category="profile" value={settings} onChange={setSettings} editing={!!profile} />
          </fieldset>
          <fieldset disabled={!!review || action.pending}>
            <legend>Credential</legend>
            <div className="inv-inline-form">
              <label className="inv-field"><span>Credential</span>
                <select value={credential} onChange={e => setCredential(e.target.value)}>
                  <option value="">No credential</option>
                  {credentials.data?.filter(c => !c.archived_at).map(c => <option key={c.id} value={c.id}>{c.display_name} (revision {c.current_revision})</option>)}
                </select>
              </label>
              <button type="button" className="secondary" onClick={() => setNewCredential(true)}>Create credential inline</button>
            </div>
            {selectedCredential && <p className="hint">Stored secret fields: {selectedCredential.secret_paths.join(", ") || "None"}</p>}
          </fieldset>
          <div className="inv-actions">
            <button type="submit" className="primary" disabled={!!review || action.pending}>{profile ? "Preview profile changes" : "Save profile"}</button>
            <button type="button" className="secondary" onClick={onCancel}>Cancel profile</button>
          </div>
        </form>
      ) : <p className="hint" role="status">Loading collector fields</p>}
      {newCredential && <CredentialEditor collectorType={collectorType} onCancel={() => setNewCredential(false)} onSaved={c => { setCredential(c.id); setNewCredential(false); }} />}
      {review && <ImpactReview request={review} onCancel={() => setReview(null)}
        onDone={() => { setReview(null); void action.run(() => inventoryApi.getProfile(profile!.id), onSaved); }} />}
    </Card>
  );
}
