import { lazy, Suspense, useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { atLeast, useAuth } from "../auth";
import { PinnedSnapshotPicker } from "../assessments/PinnedSnapshotPicker";
import { analyzeReadyConnections } from "./analysis";
import { ApplicationEditor, newApplication, toCondition } from "./ApplicationEditor";
import { conditionSentence } from "../assessments/types";
import { memberSource } from "./ApplicationStructure";
import { ApplicationDraftWorkspace } from "./ApplicationDraftWorkspace";
import { ApplicationImport } from "./ApplicationImport";
import { ApplicationRevisions } from "./ApplicationRevisions";
import { downloadApplication } from "./download";
import type {
  ApplicationDraftRef,
  ApplicationEditTarget,
  ApplicationConnection,
  ApplicationRevision,
  EndpointContext,
  ResolvedApplication,
} from "./types";
import { useAiContext, useAiPaneId } from "../ai/context";
import "./applications.css";

type Section = "components" | "connections" | "coverage" | "inventory" | "history" | "edit";
const SECTION_TEXT: Record<Section, string> = {
  components: "Components",
  connections: "Connections",
  coverage: "Coverage",
  inventory: "Expand to inventory",
  history: "History",
  edit: "Edit",
};

const ApplicationInventory = lazy(() => import("./ApplicationInventory"));

const CONTEXT_TEXT: Record<keyof EndpointContext, string> = {
  vrf: "VRF",
  device_uid: "device",
  identity_uid: "identity",
  segment_uid: "segment",
  ingress_interface_uid: "ingress interface",
};

function describeContext(context: EndpointContext | null | undefined): string {
  return (Object.keys(CONTEXT_TEXT) as Array<keyof EndpointContext>)
    .filter((key) => context?.[key])
    .map((key) => `${CONTEXT_TEXT[key]} ${context![key]}`)
    .join(", ");
}

const MTU_MODE_TEXT = {
  off: "off",
  inventory: "MTU evidence",
  unfragmented: "unfragmented packet size",
  packet: "packet behavior",
} as const;

function describeMtu(mtu: NonNullable<ApplicationConnection["mtu"]>): string {
  return [
    MTU_MODE_TEXT[mtu.mode ?? "off"],
    mtu.ip_packet_bytes != null ? `IP packet ${mtu.ip_packet_bytes} bytes` : "",
    mtu.reply_ip_packet_bytes != null ? `reply IP packet ${mtu.reply_ip_packet_bytes} bytes` : "",
    mtu.ipv4_df != null ? `IPv4 Don't Fragment ${mtu.ipv4_df ? "set" : "clear"}` : "",
    mtu.traffic_class ? `traffic class ${mtu.traffic_class}` : "",
  ]
    .filter(Boolean)
    .join(", ");
}

/** Without `onDraft` the page keeps the draft itself. */
export default function ApplicationsPage({
  applicationId,
  draft,
  onDraft,
  onNavigate,
  onOpenAnalysis,
}: {
  applicationId?: string;
  draft?: ApplicationDraftRef;
  onDraft?: (draft?: ApplicationDraftRef) => void;
  onNavigate: (id?: string) => void;
  onOpenAnalysis: (id: string) => void;
}) {
  const { user } = useAuth();
  const canEdit = !!user && atLeast(user.role, "operator");
  const canGenerate = !!user?.permissions.includes("agent.ask");
  const canCommit = !!user?.permissions.includes("changes.write");
  const queryClient = useQueryClient();
  const [localDraft, setLocalDraft] = useState<ApplicationDraftRef>();
  const openDraft = onDraft ? draft : localDraft;
  const setDraft = onDraft ?? setLocalDraft;
  // the description form is open before its generation exists; an edit
  // names the saved revision it starts from
  const [composing, setComposing] = useState<{ edit?: ApplicationEditTarget } | null>(null);
  const drafting = !!composing || !!openDraft;
  const closeDraft = () => {
    setComposing(null);
    setDraft(undefined);
  };
  const [creating, setCreating] = useState(false);
  const catalog = useQuery({
    queryKey: ["business-applications"],
    queryFn: () => api<{ applications: ApplicationRevision[] }>("/business-applications"),
  });
  const selected = applicationId;
  const [section, setSection] = useState<Section>("components");
  const [exportError, setExportError] = useState("");
  const [analysisError, setAnalysisError] = useState("");
  const [snapshot, setSnapshot] = useState("");
  const [connectionSelections, setConnectionSelections] = useState<Record<string, string[]>>({});
  const detail = useQuery({
    queryKey: ["business-application", selected],
    queryFn: () =>
      api<{ application: ApplicationRevision }>(
        `/business-applications/${encodeURIComponent(selected!)}`,
      ),
    enabled: !!selected,
  });
  const record = detail.data?.application;
  const selectedConnections = record
    ? (connectionSelections[record.id] ?? record.definition.connections.map((item) => item.id))
    : [];
  const setSelectedConnections = (values: string[]) =>
    record && setConnectionSelections((current) => ({ ...current, [record.id]: values }));
  // an open draft publishes its own context (ApplicationDraftWorkspace.tsx)
  useAiContext(
    useAiPaneId(),
    selected && !drafting
      ? {
          section,
          application: {
            application_id: selected,
            revision: record?.revision,
            connection_ids: record ? selectedConnections : undefined,
          },
          // the coverage snapshot
          snapshot: snapshot ? { id: snapshot, origin: "pinned" } : undefined,
        }
      : null,
  );
  const resolveBody =
    canEdit && selected && snapshot && selectedConnections.length > 0
      ? { snapshot, connection_ids: selectedConnections }
      : null;
  const coverage = useQuery({
    queryKey: ["business-application-resolution", selected, snapshot, selectedConnections],
    queryFn: () =>
      api<ResolvedApplication>(`/business-applications/${encodeURIComponent(selected!)}/resolve`, {
        method: "POST",
        body: resolveBody,
      }),
    enabled: !!resolveBody && section === "coverage",
  });

  async function exportRevision(revision?: number) {
    if (!selected) return;
    setExportError("");
    try {
      await downloadApplication(selected, revision);
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : "Revision not exported");
    }
  }

  async function analyze() {
    if (!record || !coverage.data) return;
    const names = new Map(
      record.definition.connections.map((connection) => [connection.id, connection.name] as const),
    );
    setAnalysisError("");
    let id: string;
    try {
      id = (await analyzeReadyConnections(record, coverage.data, names, selectedConnections)).id;
    } catch (cause) {
      setAnalysisError(cause instanceof Error ? cause.message : "Could not start the analysis");
      return;
    }
    onOpenAnalysis(id);
  }

  const servicesByConnection = useMemo(
    () =>
      new Map(
        record?.definition.services.flatMap((service) =>
          service.connection_ids.map((id) => [id, service.name] as const),
        ) ?? [],
      ),
    [record],
  );

  return (
    <div className="applications-page">
      <aside className="application-catalog" aria-label="Business applications">
        <div className="application-section-heading">
          <div>
            <span className="eyebrow">Catalog</span>
            <h2>Business applications</h2>
          </div>
          {canEdit && (
            <button
              type="button"
              onClick={() => {
                if (drafting) closeDraft();
                setCreating(true);
              }}
            >
              New application
            </button>
          )}
        </div>
        <Link to="/applications">Applications</Link>
        <details open={!catalog.data?.applications.length}>
          <summary>Import YAML</summary>
          {canGenerate && (
            <button
              type="button"
              onClick={() => {
                setCreating(false);
                setDraft(undefined);
                setComposing({});
              }}
            >
              Generate from a description
            </button>
          )}
          <ApplicationImport canEdit={canEdit} onCommitted={(id) => onNavigate(id)} />
        </details>
      </aside>
      <main className="application-detail">
        {drafting ? (
          <ApplicationDraftWorkspace
            generationId={openDraft?.generationId}
            edit={composing?.edit}
            canCommit={canCommit}
            onGenerated={(generationId) => {
              setComposing(null);
              setDraft({ generationId });
            }}
            onClose={closeDraft}
            onCommitted={(saved) => {
              closeDraft();
              onNavigate(saved.id);
              void queryClient.invalidateQueries({ queryKey: ["business-applications"] });
              void queryClient.invalidateQueries({ queryKey: ["business-application", saved.id] });
            }}
          />
        ) : creating ? (
          <ApplicationEditor
            key="new"
            record={newApplication()}
            canEdit={canEdit}
            onSaved={(saved) => {
              setCreating(false);
              queryClient.setQueryData(["business-application", saved.id], {
                application: saved,
              });
              void queryClient.invalidateQueries({ queryKey: ["business-applications"] });
              onNavigate(saved.id);
            }}
          />
        ) : (
          <>
            {!selected && (
              <div className="application-empty">
                <h2>No application selected</h2>
              </div>
            )}
            {detail.isLoading && <p role="status">Loading application</p>}
            {detail.isError && <p role="alert">Could not load this application</p>}
            {record && (
              <>
                <header>
                  <div>
                    <span className="eyebrow">Revision {record.revision}</span>
                    <h2>{record.name}</h2>
                    <p>{record.definition.description ?? "No description"}</p>
                  </div>
                  <div className="assessment-actions">
                    {canGenerate && (
                      <button
                        type="button"
                        onClick={() => {
                          setDraft(undefined);
                          setComposing({
                            edit: {
                              applicationId: record.id,
                              revision: record.revision,
                              name: record.name,
                            },
                          });
                        }}
                      >
                        Edit with AI
                      </button>
                    )}
                    <button type="button" onClick={() => void exportRevision()}>
                      Export this revision
                    </button>
                  </div>
                </header>
                {exportError && <p role="alert">{exportError}</p>}
                <div className="tabs" role="tablist" aria-label="Application sections">
                  {(
                    [
                      "components",
                      "connections",
                      "coverage",
                      "inventory",
                      "history",
                      "edit",
                    ] as Section[]
                  ).map((item) => (
                    <button
                      role="tab"
                      aria-selected={section === item}
                      className={section === item ? "on" : undefined}
                      key={item}
                      onClick={() => setSection(item)}
                    >
                      {SECTION_TEXT[item]}
                    </button>
                  ))}
                </div>
                {section === "components" && (
                  <section>
                    <h3>Services</h3>
                    {record.definition.services.length === 0 ? (
                      <p>No services</p>
                    ) : (
                      <div className="application-grid">
                        {record.definition.services.map((service) => (
                          <article key={service.id}>
                            <h4>{service.name}</h4>
                            <code>{service.id}</code>
                            <p>{service.description ?? "No description"}</p>
                            <p>
                              {service.connection_ids.length} connection
                              {service.connection_ids.length === 1 ? "" : "s"}
                            </p>
                            <ul>
                              {service.component_roles.map((role) => (
                                <li key={`${role.group_id}:${role.role}`}>
                                  {role.group_id}: {role.role}
                                </li>
                              ))}
                            </ul>
                          </article>
                        ))}
                      </div>
                    )}
                    <h3>Component groups</h3>
                    {record.definition.groups.map((group) => (
                      <article className="application-row" key={group.id}>
                        <div>
                          <strong>{group.name}</strong>
                          <code>{group.id}</code>
                        </div>
                        <ul>
                          {group.members.map((member) => (
                            <li key={member.id}>
                              <strong>{member.name ?? member.id}</strong>: {memberSource(member)}
                              {member.context || member.inventory?.context
                                ? ` in ${member.context ?? member.inventory?.context}`
                                : ""}
                            </li>
                          ))}
                        </ul>
                      </article>
                    ))}
                  </section>
                )}
                {section === "connections" && (
                  <section>
                    <h3>Connections</h3>
                    {record.definition.connections.length === 0 && <p>No connections</p>}
                    {record.definition.connections.map((connection) => (
                      <article className="application-row" key={connection.id}>
                        <label>
                          <input
                            type="checkbox"
                            checked={selectedConnections.includes(connection.id)}
                            onChange={(event) =>
                              setSelectedConnections(
                                event.target.checked
                                  ? [...selectedConnections, connection.id]
                                  : selectedConnections.filter((id) => id !== connection.id),
                              )
                            }
                          />
                          Select {connection.name}
                        </label>
                        <div>
                          <strong>{connection.source}</strong> to{" "}
                          <strong>{connection.destination}</strong>
                        </div>
                        <p>
                          {connection.protocol ?? "Protocol unspecified"}, destination ports{" "}
                          {(connection.destination_ports ?? ["unspecified"]).join(", ")},{" "}
                          {connection.success}
                        </p>
                        {connection.source_ports && (
                          <p>Source ports: {connection.source_ports.join(", ")}</p>
                        )}
                        <p>
                          Destination condition:{" "}
                          {conditionSentence(toCondition(connection.destination_condition))}
                        </p>
                        {describeContext(connection.source_context) && (
                          <p>Source context: {describeContext(connection.source_context)}</p>
                        )}
                        {describeContext(connection.destination_context) && (
                          <p>
                            Destination context: {describeContext(connection.destination_context)}
                          </p>
                        )}
                        {connection.mtu && <p>MTU: {describeMtu(connection.mtu)}</p>}
                        <p>Service: {servicesByConnection.get(connection.id) ?? "Unassigned"}</p>
                      </article>
                    ))}
                  </section>
                )}
                {section === "coverage" && (
                  <section>
                    <h3>Coverage</h3>
                    <PinnedSnapshotPicker
                      label="Coverage snapshot"
                      value={snapshot}
                      onChange={setSnapshot}
                    />
                    {snapshot && selectedConnections.length === 0 && (
                      <p role="alert">No connection selected</p>
                    )}
                    {coverage.isLoading && <p role="status">Resolving application scope</p>}
                    {coverage.isError && <p role="alert">Could not resolve coverage</p>}
                    {coverage.data && (
                      <>
                        <p role="status">
                          {coverage.data.ready
                            ? "All selected connections ready"
                            : "Not all selected connections ready"}
                        </p>
                        {coverage.data.connections.map((connection) => (
                          <article className="application-row" key={connection.id}>
                            <strong>
                              {connection.id}: {connection.readiness}
                            </strong>
                            {!connection.service_id && <p>No service</p>}
                            {connection.issues.map((issue) => (
                              <p key={`${issue.code}:${issue.path}`}>
                                {issue.path}: {issue.detail}
                              </p>
                            ))}
                          </article>
                        ))}
                        {coverage.data.issues.length > 0 && <h4>Resolution issues</h4>}
                        {coverage.data.issues.map((issue) => (
                          <p key={`${issue.code}:${issue.path}`}>
                            {issue.path}: {issue.detail}
                          </p>
                        ))}
                        <button
                          type="button"
                          disabled={
                            !canEdit ||
                            !coverage.data.connections.some(
                              (item) => item.readiness === "ready" && item.service_id,
                            )
                          }
                          onClick={() => void analyze()}
                        >
                          Analyze ready connections
                        </button>
                        {analysisError && <p role="alert">{analysisError}</p>}
                      </>
                    )}
                  </section>
                )}
                {section === "inventory" && (
                  <Suspense fallback={<p role="status">Loading the graph</p>}>
                    <ApplicationInventory key={`${record.id}:${record.revision}`} record={record} />
                  </Suspense>
                )}
                {section === "history" && (
                  <ApplicationRevisions
                    record={record}
                    onExport={(revision) => void exportRevision(revision)}
                  />
                )}
                {section === "edit" && (
                  <ApplicationEditor
                    key={`${record.id}:${record.revision}`}
                    record={record}
                    canEdit={canEdit}
                    onSaved={(saved) => {
                      queryClient.setQueryData(["business-application", saved.id], {
                        application: saved,
                      });
                      void queryClient.invalidateQueries({ queryKey: ["business-applications"] });
                    }}
                  />
                )}
              </>
            )}
          </>
        )}
      </main>
    </div>
  );
}
