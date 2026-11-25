/** The catalog queries of one object, as buttons that open the query form
 *  with the object's value filled in. Renders nothing when none matches. */
import type { CannedQuery } from "../api/types";
import { objectQueries } from "./objectQueries";

export function ObjectQueries({ catalog, labels, properties, onAsk }: {
  catalog: ReadonlyArray<CannedQuery>;
  labels: ReadonlyArray<string>;
  properties: Readonly<Record<string, unknown>>;
  onAsk: (queryKey: string, params: Record<string, string>) => void;
}) {
  const found = objectQueries(catalog, labels, properties);
  if (found.length === 0) return null;
  const lookups = found.filter((q) => q.lookup);
  const filters = found.filter((q) => !q.lookup);
  const button = (q: (typeof found)[number]) => (
    <li key={q.entry.key}>
      <button type="button" className="secondary" onClick={() => onAsk(q.entry.key, { [q.param]: q.value })}>
        {q.entry.title}
      </button>
    </li>
  );
  return (
    <section className="xb-object-queries" aria-label="Queries">
      <h3 className="eyebrow">Queries</h3>
      {lookups.length > 0 && <ul className="xb-object-query-list">{lookups.map(button)}</ul>}
      {filters.length > 0 && (
        <details>
          <summary>Filter queries ({filters.length})</summary>
          <ul className="xb-object-query-list">{filters.map(button)}</ul>
        </details>
      )}
    </section>
  );
}
