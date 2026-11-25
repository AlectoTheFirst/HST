/** The warnings a source or connection save returned with a successful
 * response, such as another controller row that shares its routing scope
 * (src/hst/app/sources.py shared_routing_scope_warnings). The save has
 * committed; the banner stays until it is dismissed or the next save
 * replaces it. */
export function SaveWarnings({ subject, warnings, onDismiss }: { subject: string; warnings: readonly string[]; onDismiss: () => void }) {
  if (warnings.length === 0) return null;
  return (
    <div className="banner warn" role="status" aria-label={`Save warnings for ${subject}`}>
      <div className="sub save-warnings">
        <p>{subject} saved with {warnings.length === 1 ? "1 warning" : `${warnings.length} warnings`}</p>
        <ul>{warnings.map(w => <li key={w}>{w}</li>)}</ul>
      </div>
      <button type="button" className="secondary save-warnings-dismiss" onClick={onDismiss}>Dismiss</button>
    </div>
  );
}

/** Router state a save hands to the connection page when it navigates there,
 * such as Onboarding after it creates the connection. */
export interface ConnectionSaveState { saveWarnings?: string[] }
