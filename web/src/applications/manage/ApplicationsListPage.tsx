import { useState } from "react";
import { Link } from "react-router";
import { atLeast, useAuth } from "../../auth";
import { Badge } from "../../inventory/ui/Badge";
import { PageHeader } from "../../inventory/ui/Page";
import { downloadApplication } from "../download";
import { formatTime, REASON_MAX, useCatalog, type CatalogEntry } from "./api";
import { useReviewActions } from "./reviewActions";

/** The applications table. `reviewOnly` shows the applications with an open review flag. */
export function ApplicationsListPage({ reviewOnly = false }: { reviewOnly?: boolean }) {
  const { user } = useAuth();
  const canEdit = !!user && atLeast(user.role, "operator");
  const canReview = !!user?.permissions.includes("changes.write");
  const catalog = useCatalog();
  const review = useReviewActions();
  const [search, setSearch] = useState("");
  const [state, setState] = useState<"" | "draft" | "ready">("");
  const [reviewFilter, setReviewFilter] = useState<"" | "open">("");
  const [selected, setSelected] = useState<string[]>([]);
  const [reason, setReason] = useState("");
  const [exportError, setExportError] = useState("");

  const text = search.trim().toLowerCase();
  const items = (catalog.data?.applications ?? []).filter(
    (item) =>
      (!text || item.name.toLowerCase().includes(text) || item.id.toLowerCase().includes(text)) &&
      (!state || item.definition.state === state) &&
      (!(reviewOnly || reviewFilter === "open") || item.review === "open"),
  );
  const filtered = !!text || !!state || reviewFilter !== "";
  const chosen = items.filter((item) => selected.includes(item.id));
  const toggle = (id: string, on: boolean) =>
    setSelected((current) => (on ? [...current, id] : current.filter((item) => item !== id)));

  async function exportSelected() {
    setExportError("");
    try {
      for (const item of chosen) await downloadApplication(item.id);
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : "Application not exported");
    }
  }

  return (
    <section className="ops-page inv-page apps-page" aria-label={reviewOnly ? "Review" : "Applications"}>
      <PageHeader title={reviewOnly ? "Review" : "Applications"}>
        <Link className="secondary" to="/applications/import">Import YAML</Link>
        {canEdit && <Link className="primary" to="/applications/new">New application</Link>}
      </PageHeader>

      <div className="inv-filters">
        <label className="inv-field">
          <span>Search</span>
          <input
            type="search"
            placeholder="Name or id"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        <label className="inv-field">
          <span>State</span>
          <select value={state} onChange={(event) => setState(event.target.value as typeof state)}>
            <option value="">All</option>
            <option value="ready">Ready</option>
            <option value="draft">Draft</option>
          </select>
        </label>
        {canReview && !reviewOnly && (
          <label className="inv-field">
            <span>Review</span>
            <select
              value={reviewFilter}
              onChange={(event) => setReviewFilter(event.target.value as typeof reviewFilter)}
            >
              <option value="">All</option>
              <option value="open">Needs review</option>
            </select>
          </label>
        )}
      </div>

      {catalog.isLoading && <p className="hint" role="status">Loading applications</p>}
      {catalog.isError && <p role="alert">Could not load applications</p>}
      {catalog.data && items.length === 0 && (
        <div className="results">
          <p className="tableempty">{filtered || reviewOnly ? "No matching applications" : "No applications"}</p>
        </div>
      )}
      {items.length > 0 && (
        <div className="results inv-table">
          <table>
            <thead>
              <tr>
                <th className="inv-col-check">
                  <input
                    type="checkbox"
                    aria-label="Select all"
                    checked={chosen.length === items.length}
                    onChange={(event) => setSelected(event.target.checked ? items.map((item) => item.id) : [])}
                  />
                </th>
                <th>Name</th>
                <th>Id</th>
                <th>Revision</th>
                <th>State</th>
                <th>Connections</th>
                <th>Analyses</th>
                {canReview && <th>Review</th>}
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <Row
                  key={item.id}
                  item={item}
                  canReview={canReview}
                  selected={selected.includes(item.id)}
                  onSelect={(on) => toggle(item.id, on)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {chosen.length > 0 && (
        <div className="apps-selection" role="group" aria-label="Selected application actions">
          <strong>{chosen.length} selected</strong>
          {canReview && (
            <>
              <label className="inv-field">
                <span>Reason</span>
                <input maxLength={REASON_MAX} value={reason} onChange={(event) => setReason(event.target.value)} />
              </label>
              <button
                type="button"
                className="secondary"
                disabled={review.busy || !reason.trim() || !chosen.some((item) => item.review !== "open")}
                onClick={() =>
                  void review
                    .flag(chosen.filter((item) => item.review !== "open").map((item) => item.id), reason.trim())
                    .then((done) => done && setReason(""))
                }
              >
                Flag for review
              </button>
              <button
                type="button"
                className="secondary"
                disabled={review.busy || !chosen.some((item) => item.review === "open")}
                onClick={() =>
                  void review.close(chosen.filter((item) => item.review === "open").map((item) => item.id))
                }
              >
                Mark reviewed
              </button>
            </>
          )}
          <button type="button" className="secondary" onClick={() => void exportSelected()}>
            Export YAML
          </button>
        </div>
      )}
      {review.error && <p role="alert">{review.error}</p>}
      {exportError && <p role="alert">{exportError}</p>}
    </section>
  );
}

function Row({
  item,
  canReview,
  selected,
  onSelect,
}: {
  item: CatalogEntry;
  canReview: boolean;
  selected: boolean;
  onSelect: (on: boolean) => void;
}) {
  return (
    <tr aria-selected={selected}>
      <td className="inv-col-check">
        <input
          type="checkbox"
          aria-label={`Select ${item.name}`}
          checked={selected}
          onChange={(event) => onSelect(event.target.checked)}
        />
      </td>
      <td>
        <Link to={`/applications/${encodeURIComponent(item.id)}`}>{item.name}</Link>
      </td>
      <td className="mono">{item.id}</td>
      <td>{item.revision}</td>
      <td>
        <Badge tone={item.definition.state === "ready" ? "ok" : "neutral"}>{item.definition.state}</Badge>
      </td>
      <td>{item.connections ?? item.definition.connections.length}</td>
      <td>{item.analyses ?? 0}</td>
      {canReview && <td>{item.review === "open" && <Badge tone="warn">needs review</Badge>}</td>}
      <td>{formatTime(item.created_at)}</td>
    </tr>
  );
}
