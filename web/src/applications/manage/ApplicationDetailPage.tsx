import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import { atLeast, useAuth } from "../../auth";
import { Badge } from "../../inventory/ui/Badge";
import { useOpenInWorkspace } from "../../workspace/WorkspaceContext";
import {
  ApplicationEditor,
  DraftConflict,
  MetadataFields,
  ServicesFields,
  newApplication,
} from "../ApplicationEditor";
import { ApplicationRevisions, describeOrigin, useRevisionHistory } from "../ApplicationRevisions";
import { downloadApplication } from "../download";
import type { ApplicationRevision } from "../types";
import { useApplicationDraft, type ApplicationDraft } from "../useApplicationDraft";
import {
  analysesKey,
  boundText,
  byText,
  catalogKey,
  REASON_MAX,
  formatTime,
  reviewKey,
  useAnalyses,
  useReview,
  type Review,
} from "./api";
import { ComponentsTab } from "./ComponentsTab";
import { ConnectionsTab } from "./ConnectionsTab";
import { useReviewActions } from "./reviewActions";

const TABS = [
  ["overview", "Overview"],
  ["components", "Components"],
  ["connections", "Connections"],
  ["services", "Services"],
  ["revisions", "Revisions"],
] as const;
type Tab = (typeof TABS)[number][0];

export function ApplicationDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canEdit = !!user && atLeast(user.role, "operator");
  const detail = useQuery({
    queryKey: ["business-application", id],
    queryFn: () => api<{ application: ApplicationRevision }>(`/business-applications/${encodeURIComponent(id)}`),
    enabled: id !== "new",
  });

  if (id === "new")
    return (
      <section className="ops-page inv-page apps-page" aria-label="New application">
        <Link className="inv-back" to="/applications">Applications</Link>
        <h1>New application</h1>
        <ApplicationEditor
          record={newApplication()}
          canEdit={canEdit}
          onSaved={(saved) => {
            queryClient.setQueryData(["business-application", saved.id], { application: saved });
            void queryClient.invalidateQueries({ queryKey: catalogKey });
            navigate(`/applications/${encodeURIComponent(saved.id)}`);
          }}
        />
      </section>
    );
  const record = detail.data?.application;
  return (
    <section className="ops-page inv-page apps-page" aria-label="Application">
      <Link className="inv-back" to="/applications">Applications</Link>
      {detail.isLoading && <p className="hint" role="status">Loading application</p>}
      {detail.isError && <p role="alert">Could not load this application</p>}
      {record && <DetailBody key={`${record.id}:${record.revision}`} record={record} canEdit={canEdit} />}
    </section>
  );
}

function DetailBody({ record, canEdit }: { record: ApplicationRevision; canEdit: boolean }) {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canReview = !!user?.permissions.includes("changes.write");
  const openInWorkspace = useOpenInWorkspace();
  const [params, setParams] = useSearchParams();
  const tab: Tab = TABS.find(([key]) => key === params.get("tab"))?.[0] ?? "overview";
  const [exportError, setExportError] = useState("");
  const editor = useApplicationDraft(record, (saved) => {
    queryClient.setQueryData(["business-application", saved.id], { application: saved });
    void queryClient.invalidateQueries({ queryKey: catalogKey });
    void queryClient.invalidateQueries({ queryKey: analysesKey(saved.id) });
    void queryClient.invalidateQueries({ queryKey: reviewKey(saved.id) });
    void queryClient.invalidateQueries({ queryKey: ["business-application-history", saved.id] });
  });
  const locked = !canEdit || editor.busy;

  async function exportRevision(revision?: number) {
    setExportError("");
    try {
      await downloadApplication(record.id, revision);
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : "Revision not exported");
    }
  }

  return (
    <>
      <header className="inv-head">
        <div className="inv-head-title">
          <span className="eyebrow">
            {editor.dirty ? `Revision ${record.revision}, draft changes` : `Revision ${record.revision}`}
          </span>
          <h1>{editor.draft.name || record.name}</h1>
          <span className="mono">{record.id}</span>
        </div>
        <div className="inv-actions">
          {editor.dirty ? (
            <>
              <button type="button" className="secondary" disabled={editor.busy} onClick={editor.discard}>
                Discard changes
              </button>
              <button type="button" className="primary" disabled={locked} onClick={() => void editor.save()}>
                {editor.busy ? "Saving" : `Save revision ${editor.base.revision + 1}`}
              </button>
            </>
          ) : (
            <>
              {openInWorkspace && (
                <button
                  type="button"
                  className="secondary"
                  onClick={() => openInWorkspace((workspace) => workspace.openApplications(record.id))}
                >
                  Open map
                </button>
              )}
              <button type="button" className="secondary" onClick={() => void exportRevision()}>
                Export YAML
              </button>
            </>
          )}
        </div>
      </header>
      {exportError && <p role="alert">{exportError}</p>}
      <DraftConflict editor={editor} />
      <div className="tabs" role="tablist" aria-label="Application sections">
        {TABS.map(([key, label]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={tab === key ? "on" : undefined}
            onClick={() =>
              setParams((current) => {
                const next = new URLSearchParams(current);
                if (key === "overview") next.delete("tab");
                else next.set("tab", key);
                return next;
              })
            }
          >
            {label}
          </button>
        ))}
      </div>
      {tab === "overview" && (
        <Overview
          record={record}
          editor={editor}
          locked={locked}
          canReview={canReview}
          onOpenSession={
            openInWorkspace
              ? (sessionId) => openInWorkspace((workspace) => workspace.openAnalysis(sessionId))
              : undefined
          }
        />
      )}
      {tab === "components" && <ComponentsTab record={record} editor={editor} locked={locked} />}
      {tab === "connections" && <ConnectionsTab editor={editor} locked={locked} />}
      {tab === "services" && <ServicesFields editor={editor} disabled={locked} />}
      {tab === "revisions" && (
        <ApplicationRevisions record={record} onExport={(revision) => void exportRevision(revision)} />
      )}
    </>
  );
}

function Overview({
  record,
  editor,
  locked,
  canReview,
  onOpenSession,
}: {
  record: ApplicationRevision;
  editor: ApplicationDraft;
  locked: boolean;
  canReview: boolean;
  onOpenSession?: (sessionId: string) => void;
}) {
  const analyses = useAnalyses(record.id);
  const history = useRevisionHistory(record.id);
  return (
    <div className="apps-overview">
      {canReview && <ReviewPanel id={record.id} />}
      <div className="apps-overview-grid">
        <section aria-label="Analyses">
          <h2>Analyses</h2>
          {analyses.isLoading && <p className="hint" role="status">Loading analyses</p>}
          {analyses.isError && <p role="alert">Could not load analyses</p>}
          {analyses.data?.analyses.length === 0 && <p>No analyses</p>}
          {!!analyses.data?.analyses.length && (
            <div className="results inv-table">
              <table>
                <thead>
                  <tr>
                    <th>Session</th>
                    <th>Bound revision</th>
                    <th>Run</th>
                    <th>
                      <span className="gv-sr">Open</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {analyses.data.analyses.map((item) => (
                    <tr key={item.session_id}>
                      <td>{item.title}</td>
                      <td>{item.stale ? <Badge tone="warn">{boundText(item)}</Badge> : boundText(item)}</td>
                      <td>{item.runs.length ? [...new Set(item.runs.map((run) => run.execution))].join(", ") : "no run"}</td>
                      <td>
                        {onOpenSession && (
                          <button
                            type="button"
                            className="secondary"
                            aria-label={`Open ${item.title}`}
                            onClick={() => onOpenSession(item.session_id)}
                          >
                            Open
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section aria-label="Revisions">
          <h2>Revisions</h2>
          {history.isLoading && <p className="hint" role="status">Loading revision history</p>}
          <ul className="apps-list">
            {history.data?.revisions.map((item) => (
              <li key={item.revision}>
                <strong>{item.revision}</strong>
                <span>{formatTime(item.created_at)}</span>
                <span>{describeOrigin(item.origin)}</span>
              </li>
            ))}
          </ul>
          {canReview && <ReviewHistory id={record.id} />}
        </section>
      </div>
      <MetadataFields editor={editor} disabled={locked} />
    </div>
  );
}

function ReviewPanel({ id }: { id: string }) {
  const review = useReview(id, true);
  const actions = useReviewActions();
  const [reason, setReason] = useState("");
  const current = review.data?.current;
  return (
    <section className="apps-review" aria-label="Review">
      {review.isLoading && <p className="hint" role="status">Loading review</p>}
      {review.isError && <p role="alert">Could not load the review</p>}
      {current?.state === "open" ? (
        <>
          <Badge tone="warn">needs review</Badge>
          <span>{current.reason}</span>
          <span>
            Opened {formatTime(current.opened_at)}
            {current.opened_by != null && ` by ${byText(current.opened_by)}`}
          </span>
          <button
            type="button"
            className="primary"
            disabled={actions.busy}
            onClick={() => void actions.close([id])}
          >
            Mark reviewed
          </button>
        </>
      ) : (
        review.data && (
          <>
            <label className="inv-field">
              <span>Reason</span>
              <input maxLength={REASON_MAX} value={reason} onChange={(event) => setReason(event.target.value)} />
            </label>
            <button
              type="button"
              className="secondary"
              disabled={actions.busy || !reason.trim()}
              onClick={() => void actions.flag([id], reason.trim()).then((done) => done && setReason(""))}
            >
              Flag for review
            </button>
          </>
        )
      )}
      {actions.error && <p role="alert">{actions.error}</p>}
    </section>
  );
}

function reviewEvents(history: Review[]) {
  return history
    .flatMap((item) => [
      { key: `${item.id}:opened`, time: item.opened_at, event: "opened", by: item.opened_by, reason: item.reason, revision: item.revision },
      ...(item.closed_at
        ? [{ key: `${item.id}:closed`, time: item.closed_at, event: "closed", by: item.closed_by, reason: "", revision: item.revision }]
        : []),
    ])
    .sort((left, right) => right.time.localeCompare(left.time));
}

function ReviewHistory({ id }: { id: string }) {
  const review = useReview(id, true);
  const events = reviewEvents(review.data?.history ?? []);
  return (
    <section aria-label="Review history">
      <h2>Review history</h2>
      {review.data && events.length === 0 && <p>No reviews</p>}
      {events.length > 0 && (
        <div className="results inv-table">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Revision</th>
                <th>By</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {events.map((item) => (
                <tr key={item.key}>
                  <td>{formatTime(item.time)}</td>
                  <td>{item.event}</td>
                  <td>{item.revision}</td>
                  <td>{item.event === "opened" || item.by != null ? byText(item.by) : ""}</td>
                  <td>{item.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
