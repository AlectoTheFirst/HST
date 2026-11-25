/** POST /api/cypher requires operator. */

import { useState, type FormEvent } from "react";
import { useAuth, atLeast } from "../auth";

// The server binds `$snap` for every query this endpoint runs (app/tables.py run_readonly).
const DEFAULT_QUERY =
  "MATCH (d:Device) WHERE coalesce(d.collection_ts, $snap) = $snap AND NOT d:Retired\n" +
  "RETURN d.hostname AS hostname, d.platform AS platform, d.role AS role ORDER BY hostname";

export function CypherEditor({
  onRun,
  pending,
  initial,
}: {
  onRun: (query: string) => void;
  pending: boolean;
  /** Starting text, for a starter query handed over from the schema view. */
  initial?: string;
}) {
  const { user } = useAuth();
  const [query, setQuery] = useState(initial ?? DEFAULT_QUERY);

  if (!user || !atLeast(user.role, "operator")) return null;

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const trimmed = query.trim();
    if (!trimmed) return;
    onRun(trimmed);
  }

  return (
    <form className="editorcard" onSubmit={handleSubmit} aria-label="Ad-hoc Cypher">
      <div className="bar">
        <span className="eyebrow">Cypher</span>
        <button className="primary" type="submit" disabled={pending}>
          {pending ? "Running" : "Run"}
        </button>
      </div>
      <textarea
        className="cypher-input"
        aria-label="Cypher query"
        spellCheck={false}
        rows={3}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
    </form>
  );
}
