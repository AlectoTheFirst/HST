import { lazy, Suspense, useId, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, apiDownload, ApiError } from "../api/client";
import { atLeast, useAuth } from "../auth";
import { PinnedSnapshotPicker } from "../assessments/PinnedSnapshotPicker";
import { analyzeReadyConnections } from "./analysis";
import { ApplicationEditor, changedAreas, newApplication, toCondition } from "./ApplicationEditor";
import { conditionSentence } from "../assessments/types";
import { ApplicationStructure, memberSource } from "./ApplicationStructure";
import { resultLabel } from "../results/text";
import { YamlEditor } from "./YamlEditor";
import { ApplicationDraftWorkspace, describeIssue } from "./ApplicationDraftWorkspace";
import type {
  ApplicationDraftRef,
  ApplicationEditTarget,
  ApplicationConnection,
  ApplicationRevision,
  EndpointContext,
  FlowCheck,
  ImportPreview,
  ResolvedApplication,
  RevisionOrigin,
  ValidationResult,
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

// The server evaluates at most this many ready connections per flow check.
const FLOW_CHECK_CAP = 20;
const NOT_CHECKED_TEXT: Record<NonNullable<FlowCheck["not_evaluated_reason"]>, string> = {
  "not-ready": "unresolved at this snapshot",
  "over-cap": `after the first ${FLOW_CHECK_CAP} ready connections`,
  deadline: "time limit passed",
  "capacity-busy": "no free analysis process slot",
  "evaluation-failed": "evaluation failed",
};

function describeFlow(flow: FlowCheck): string {
  if (flow.result) {
    const sources = [
      flow.fails.length > 0 ? `failing sources ${flow.fails.join(", ")}` : "",
      flow.open.length > 0 ? `sources not decided ${flow.open.join(", ")}` : "",
    ].filter(Boolean);
    return [`${flow.connection_id}: ${resultLabel(flow.result)}`, ...sources].join(", ");
  }
  const reason = flow.not_evaluated_reason
    ? NOT_CHECKED_TEXT[flow.not_evaluated_reason]
    : "reason not recorded";
  return `${flow.connection_id}: Not checked, ${reason}${flow.detail ? `: ${flow.detail}` : ""}`;
}

const ORIGIN_SOURCES: Record<RevisionOrigin["source"], string> = {
  import: "Imported from YAML",
  editor: "Saved in the visual editor",
  api: "Saved through the API",
  trace: "Added from a trace",
  generator: "Saved from a generated draft",
};

function describeOrigin(origin: RevisionOrigin | null | undefined): string {
  if (!origin) return "Origin not recorded";
  const source = ORIGIN_SOURCES[origin.source] ?? `Saved from ${origin.source}`;
  const validation = origin.validation;
  if (!validation) return `${source}, not validated`;
  const blocking = validation.blocking_count;
  const state =
    blocking === 0
      ? "nothing blocked the ready state"
      : `${blocking} ${blocking === 1 ? "path blocked" : "paths blocked"} the ready state`;
  return `${source}, validated at snapshot ${validation.snapshot.snapshot}, ${state}`;
}

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
  const [yaml, setYaml] = useState("");
  const [importMode, setImportMode] = useState<"merge" | "replace">("merge");
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [importError, setImportError] = useState("");
  const [exportError, setExportError] = useState("");
  const [analysisError, setAnalysisError] = useState("");
  const yamlId = useId();
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [validationSnapshot, setValidationSnapshot] = useState("");
  const [validationError, setValidationError] = useState("");
  const [snapshot, setSnapshot] = useState("");
  const [connectionSelections, setConnectionSelections] = useState<Record<string, string[]>>({});
  const [comparison, setComparison] = useState<ApplicationRevision | null>(null);
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
  const history = useQuery({
    queryKey: ["business-application-history", selected],
    queryFn: () =>
      api<{ revisions: ApplicationRevision[] }>(
        `/business-applications/${encodeURIComponent(selected!)}/history`,
      ),
    enabled: !!selected && section === "history",
  });
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

  const previewImport = useMutation({
    mutationFn: () =>
      api<ImportPreview>("/business-applications/import/preview", {
        method: "POST",
        body: { yaml, mode: importMode },
      }),
    onSuccess: (value) => {
      setPreview(value);
      setImportError("");
    },
    onError: (cause) =>
      setImportError(cause instanceof Error ? cause.message : "Could not preview the import"),
  });
  // Validate sends no `evaluate`; Check flows asks for the stage 4 results.
  const validateImport = useMutation({
    mutationFn: (evaluate: boolean) =>
      api<ValidationResult>("/business-applications/validate", {
        method: "POST",
        body: evaluate
          ? { yaml, mode: importMode, snapshot: validationSnapshot, evaluate: true }
          : { yaml, mode: importMode, snapshot: validationSnapshot },
      }),
    onSuccess: (value) => {
      setValidation(value);
      setValidationError("");
    },
    onError: (cause) => {
      setValidation(null);
      setValidationError(cause instanceof Error ? cause.message : "Could not validate the YAML");
    },
  });
  const errorLines = new Set(
    (validation?.errors ?? []).flatMap((issue) => (issue.line != null ? [issue.line] : [])),
  );
  const editYaml = (value: string) => {
    setYaml(value);
    setPreview(null);
    setValidation(null);
  };
  const commitImport = useMutation({
    mutationFn: () =>
      api<ApplicationRevision>("/business-applications/import/commit", {
        method: "POST",
        body: {
          yaml,
          mode: importMode,
          base_revision: preview!.base_revision,
          base_digest: preview!.base_digest,
          preview_digest: preview!.preview_digest,
        },
      }),
    onSuccess: async (value) => {
      setPreview(null);
      setYaml("");
      onNavigate(value.id);
      await queryClient.invalidateQueries({ queryKey: ["business-applications"] });
      await queryClient.invalidateQueries({ queryKey: ["business-application", value.id] });
    },
    onError: (cause) => {
      if (cause instanceof ApiError && cause.status === 409) setPreview(null);
      setImportError(
        cause instanceof ApiError && cause.status === 409
          ? "Application changed after this preview"
          : cause instanceof Error
            ? cause.message
            : "Could not commit the import",
      );
    },
  });

  async function exportRevision(revision?: number) {
    if (!selected) return;
    setExportError("");
    try {
      const download = await apiDownload(
        `/business-applications/${encodeURIComponent(selected)}/export${revision ? `?revision=${revision}` : ""}`,
      );
      const url = URL.createObjectURL(download.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = download.filename;
      link.click();
      URL.revokeObjectURL(url);
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
        {catalog.isLoading && <p role="status">Loading applications</p>}
        {catalog.isError && <p role="alert">Could not load applications</p>}
        {catalog.data?.applications.length === 0 && <p>No applications</p>}
        <ul>
          {catalog.data?.applications.map((item) => (
            <li key={item.id}>
              <button
                type="button"
                className={selected === item.id ? "on" : undefined}
                onClick={() => {
                  if (drafting) closeDraft();
                  setCreating(false);
                  onNavigate(item.id);
                }}
              >
                {item.name}
                <span>
                  {item.definition.environment ?? "No environment"}, revision {item.revision}
                </span>
              </button>
            </li>
          ))}
        </ul>
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
          <fieldset
            disabled={
              !canEdit ||
              previewImport.isPending ||
              commitImport.isPending ||
              validateImport.isPending
            }
          >
            <label htmlFor={yamlId}>Definition YAML</label>
            <YamlEditor id={yamlId} value={yaml} errorLines={errorLines} onChange={editYaml} />
            <label>
              Import mode
              <select
                value={importMode}
                onChange={(event) => {
                  setImportMode(event.target.value as "merge" | "replace");
                  setPreview(null);
                  setValidation(null);
                }}
              >
                <option value="merge">Merge</option>
                <option value="replace">Replace</option>
              </select>
            </label>
            <label className="application-file">
              Load YAML file
              <input
                type="file"
                accept=".yaml,.yml,text/yaml,application/yaml"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  if (file) void file.text().then(editYaml);
                }}
              />
            </label>
            {yaml.trim() !== "" && (
              <PinnedSnapshotPicker
                label="Validation snapshot"
                value={validationSnapshot}
                onChange={(value) => {
                  setValidationSnapshot(value);
                  setValidation(null);
                }}
              />
            )}
            <button
              type="button"
              disabled={!yaml.trim() || !validationSnapshot}
              onClick={() => validateImport.mutate(false)}
            >
              Validate
            </button>
            <button
              type="button"
              disabled={!yaml.trim() || !validationSnapshot}
              onClick={() => validateImport.mutate(true)}
            >
              Check flows
            </button>
            <button type="button" disabled={!yaml.trim()} onClick={() => previewImport.mutate()}>
              Preview import
            </button>
          </fieldset>
          {importError && <p role="alert">{importError}</p>}
          {validationError && <p role="alert">{validationError}</p>}
          {validateImport.isPending && validateImport.variables && (
            <p role="status">Checking flows</p>
          )}
          {validation && (
            <section aria-label="Validation result">
              <h3>Validation</h3>
              <p role="status">
                {validation.blocking.length === 0
                  ? "Nothing blocks the ready state"
                  : `${validation.blocking.length} ${validation.blocking.length === 1 ? "path blocks" : "paths block"} the ready state`}
              </p>
              {validation.errors.length > 0 && (
                <ul aria-label="Validation errors">
                  {validation.errors.map((issue, index) => (
                    <li key={index}>{describeIssue(issue)}</li>
                  ))}
                </ul>
              )}
              {validation.warnings.length > 0 && (
                <ul aria-label="Validation warnings">
                  {validation.warnings.map((warning) => (
                    <li key={`${warning.code}:${warning.path}`}>
                      {warning.path}: {warning.message}
                    </li>
                  ))}
                </ul>
              )}
              {validation.resolution && validation.resolution.issues.length > 0 && (
                <ul aria-label="Resolution issues">
                  {validation.resolution.issues.map((issue) => (
                    <li key={`${issue.code}:${issue.path}`}>
                      {issue.path}: {issue.detail}
                    </li>
                  ))}
                </ul>
              )}
              {validation.flows && (
                <section aria-label="Flow checks">
                  <h4>Flow checks</h4>
                  {validation.flows.length === 0 ? (
                    <p>No connections</p>
                  ) : (
                    <ul aria-label="Flow results">
                      {validation.flows.map((flow) => (
                        <li key={flow.connection_id}>{describeFlow(flow)}</li>
                      ))}
                    </ul>
                  )}
                </section>
              )}
              {validation.definition && (
                <ApplicationStructure
                  definition={validation.definition}
                  resolution={validation.resolution}
                  flows={validation.flows}
                />
              )}
            </section>
          )}
          {preview && (
            <section aria-label="Import preview">
              <h3>{preview.no_op ? "No semantic changes" : "Changes"}</h3>
              {Object.entries(preview.changes)
                .filter(([, values]) => values.length)
                .map(([kind, values]) => (
                  <p key={kind}>
                    <strong>{kind.replaceAll("_", " ")}:</strong> {values.join(", ")}
                  </p>
                ))}
              {preview.mapping_issues.map((issue) => (
                <p key={issue.path}>
                  {issue.path}: {issue.detail}
                </p>
              ))}
              <button type="button" disabled={preview.no_op} onClick={() => commitImport.mutate()}>
                Commit revision
              </button>
              <button type="button" onClick={() => setPreview(null)}>
                Cancel preview
              </button>
            </section>
          )}
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
                  <section>
                    <h3>Revisions</h3>
                    {history.isLoading && <p role="status">Loading revision history</p>}
                    {history.data?.revisions.map((item) => (
                      <article className="application-row" key={item.revision}>
                        <div>
                          <strong>Revision {item.revision}</strong>
                          <span>{new Date(item.created_at).toLocaleString()}</span>
                        </div>
                        <p>{describeOrigin(item.origin)}</p>
                        <code>{item.digest}</code>
                        <button type="button" onClick={() => setComparison(item)}>
                          Compare with current
                        </button>
                        <button type="button" onClick={() => void exportRevision(item.revision)}>
                          Export revision {item.revision}
                        </button>
                      </article>
                    ))}
                    {comparison && (
                      <section className="application-edit-card" aria-label="Revision differences">
                        <h4>
                          Revision {comparison.revision} compared with revision {record.revision}
                        </h4>
                        <p>
                          {changedAreas(comparison.definition, record.definition).join(", ") ||
                            "No definition changes"}
                        </p>
                        <details>
                          <summary>Inspect definitions</summary>
                          <h5>Revision {comparison.revision}</h5>
                          <pre>{JSON.stringify(comparison.definition, null, 2)}</pre>
                          <h5>Revision {record.revision}</h5>
                          <pre>{JSON.stringify(record.definition, null, 2)}</pre>
                        </details>
                        <button type="button" onClick={() => setComparison(null)}>
                          Close comparison
                        </button>
                      </section>
                    )}
                  </section>
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
