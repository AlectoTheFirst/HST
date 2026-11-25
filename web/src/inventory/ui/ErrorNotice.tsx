import { ApiError } from "../../api/client";

const MESSAGES: Record<string, string> = {
  inventory_changed: "Inventory changed after the selection",
  stale_revision: "Record changed after loading",
  preview_expired: "Preview expired",
  idempotency_conflict: "Request key used for another operation",
  normalization_migrated: "Normalization settings read-only",
  forbidden: "No permission for this action",
  not_found: "Inventory record not found",
  validation: "Request not valid",
  observed_store_unavailable: "Observed inventory store not available",
  conflict: "Conflict with the current inventory state",
};

function headline(error: unknown): string {
  if (!(error instanceof ApiError)) return "Request failed";
  if (error.code && MESSAGES[error.code]) return MESSAGES[error.code];
  if (error.status === 403) return MESSAGES.forbidden;
  if (error.status === 409) return "Inventory changed or preview expired";
  if (error.status === 503) return MESSAGES.observed_store_unavailable;
  return "Request failed";
}

export function ErrorNotice({ error, retry }: { error: unknown; retry?: () => void }) {
  if (!error) return null;
  const title = headline(error);
  const detail = error instanceof Error && error.message !== title ? error.message : "";
  const revision = error instanceof ApiError ? error.currentRevision : undefined;
  const references = error instanceof ApiError ? error.references : [];
  return (
    <div className="banner err inv-error" role="alert">
      <div className="inv-error-row">
        <div>
          <p className="inv-error-title">{title}</p>
          {detail && <p className="sub">{detail}</p>}
          {revision !== undefined && <p className="sub">Current server revision: {revision}</p>}
        </div>
        {retry && <button type="button" className="secondary" onClick={retry}>Retry</button>}
      </div>
      {references.length > 0 && (
        <ul className="inv-refs" aria-label="Conflict references">
          {references.map(reference => <li key={reference}>{reference}</li>)}
        </ul>
      )}
    </div>
  );
}
