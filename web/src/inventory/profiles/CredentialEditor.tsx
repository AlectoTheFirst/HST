import { useState } from "react";
import { inventoryApi, type CredentialView, type PreviewRequest } from "../../api/inventory";
import { useAction, useCatalog } from "../shared";
import { ErrorNotice } from "../ui/ErrorNotice";
import { ImpactReview } from "../ui/ImpactReview";
import { Card } from "../ui/Page";

const isKey = (path: string) => path.endsWith(".private_key") || path === "tls.client_cert.key";

export function CredentialEditor({ collectorType, credential, onSaved, onCancel }: { collectorType?: string; credential?: CredentialView; onSaved: (credential: CredentialView) => void; onCancel: () => void }) {
  const catalog = useCatalog();
  const action = useAction("credential");
  const [name, setName] = useState(credential?.display_name ?? "");
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [review, setReview] = useState<PreviewRequest | null>(null);
  const fields = catalog.metadata.data?.filter(m => !collectorType || m.collector_type === collectorType).flatMap(m => m.fields.filter(f => f.category === "credential")) ?? [];
  const labels = new Map(fields.map(f => [f.path, f.label || f.path]));
  const paths = Array.from(new Set([...(credential?.secret_paths ?? []), ...fields.map(f => f.path)]));
  const set = (path: string, value: string) => setSecrets({ ...secrets, [path]: value });
  return (
    <Card label="Credential editor" title={credential ? `Rotate or repair ${credential.display_name}` : "New credential"}>
      <ErrorNotice error={action.error || catalog.metadata.error} />
      <form className="inv-form" onSubmit={e => {
        e.preventDefault();
        const values = Object.fromEntries(Object.entries(secrets).filter(([, v]) => v !== ""));
        if (credential) setReview({ operation: "rotate_credential", selection: { ids: [credential.id] }, change: { display_name: name, secrets: values, expected_revision: credential.current_revision } });
        else void action.run(() => inventoryApi.createCredential({ display_name: name, secrets: values }), c => { setSecrets({}); onSaved(c); });
      }}>
        <fieldset disabled={!!review || action.pending}>
          <legend>Credential</legend>
          <label className="inv-field"><span>Credential name</span><input value={name} required onChange={e => setName(e.target.value)} /></label>
          <div className="config-fields">
            {paths.map(path => (
              <label className="inv-field" key={path}><span>{labels.get(path) ?? path}</span>
                {isKey(path)
                  ? <textarea rows={7} autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="PEM private key" value={secrets[path] ?? ""} onChange={e => set(path, e.target.value)} />
                  : <input type="password" autoComplete="new-password" value={secrets[path] ?? ""} onChange={e => set(path, e.target.value)} />}
              </label>
            ))}
          </div>
          <div className="inv-actions">
            <button type="submit" className="primary" disabled={!paths.length}>{credential ? "Preview credential rotation" : "Save credential"}</button>
            <button type="button" className="secondary" onClick={onCancel}>Cancel credential</button>
          </div>
        </fieldset>
      </form>
      {review && <ImpactReview request={review} onCancel={() => setReview(null)}
        onDone={() => { setReview(null); setSecrets({}); void action.run(() => inventoryApi.getCredential(credential!.id), onSaved); }} />}
    </Card>
  );
}
