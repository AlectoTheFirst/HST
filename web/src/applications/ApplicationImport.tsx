import { useId, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { PinnedSnapshotPicker } from "../assessments/PinnedSnapshotPicker";
import { resultLabel } from "../results/text";
import { ApplicationStructure } from "./ApplicationStructure";
import { describeIssue } from "./ApplicationDraftWorkspace";
import { YamlEditor } from "./YamlEditor";
import type { ApplicationRevision, FlowCheck, ImportPreview, ValidationResult } from "./types";

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

/** The YAML import: validate, check flows, preview and commit a revision. */
export function ApplicationImport({
  canEdit,
  onCommitted,
}: {
  canEdit: boolean;
  onCommitted: (id: string) => void;
}) {
  const queryClient = useQueryClient();
  const [yaml, setYaml] = useState("");
  const [importMode, setImportMode] = useState<"merge" | "replace">("merge");
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [importError, setImportError] = useState("");
  const yamlId = useId();
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [validationSnapshot, setValidationSnapshot] = useState("");
  const [validationError, setValidationError] = useState("");

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
      onCommitted(value.id);
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

  return (
    <>
      <fieldset
        disabled={
          !canEdit || previewImport.isPending || commitImport.isPending || validateImport.isPending
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
      {validateImport.isPending && validateImport.variables && <p role="status">Checking flows</p>}
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
    </>
  );
}
