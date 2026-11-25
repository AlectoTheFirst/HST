import { useEffect, useId, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api/client";
import { useAiContext, useAiPaneId, type AiContextFragment } from "../ai/context";
import { ASK_MAX_ATTEMPTS, ASK_POLL_MS } from "../ai/useConversation";
import type { PageContextDraftMember } from "../api/types";
import { PinnedSnapshotPicker } from "../assessments/PinnedSnapshotPicker";
import { ApplicationStructure } from "./ApplicationStructure";
import { memberAt, ResolutionReport } from "./ResolutionReport";
import { YamlEditor } from "./YamlEditor";
import type {
  ApplicationEditTarget,
  ApplicationRevision,
  BusinessApplicationDefinition,
  EditSource,
  GenerationReport,
  GenerationResult,
  GenerationSource,
  ImportPreview,
  InventoryReference,
  ValidationIssue,
  ValidationResult,
} from "./types";

/** The generator's bound on a description (MAX_DESCRIPTION_CHARS in
 *  src/hst/app/routes/application_generator.py). */
export const MAX_DESCRIPTION_CHARS = 4000;
/** Validation runs this long after the last edit. */
export const VALIDATE_DELAY_MS = 500;

export function describeIssue(issue: ValidationIssue): string {
  const place =
    issue.line != null
      ? `Line ${issue.line}${issue.column != null ? `, column ${issue.column}` : ""}: `
      : "";
  return `${place}${issue.path}: ${issue.message}`;
}

/** The issues in their order, each once. */
function distinctIssues(issues: ValidationIssue[]): ValidationIssue[] {
  const seen = new Set<string>();
  return issues.filter((issue) => {
    const key = describeIssue(issue);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function errorText(cause: unknown, fallback: string): string {
  return cause instanceof Error && cause.message ? cause.message : fallback;
}

// --- Bind: a placeholder member becomes an inventory reference in the text ---

/** The indent of a line, or -1 for a blank line or a comment line. */
function indentOf(line: string): number {
  const body = line.trimStart();
  return body.trim() === "" || body.startsWith("#") ? -1 : line.length - body.length;
}

/** The text of an entry whose key starts at `column`: a line indented to the
 *  column, or the first entry of a list item whose dash is two columns before
 *  it. */
function entryAt(line: string, column: number): string | null {
  const indent = indentOf(line);
  if (indent === column) return line.slice(column);
  if (indent >= 0 && indent === column - 2 && line.startsWith("- ", indent))
    return line.slice(column);
  return null;
}

/** A plain, single-quoted or double-quoted scalar as its text. */
function scalar(value: string): string {
  const text = value.replace(/\s+#.*$/, "").trim();
  if (text.length >= 2 && text.startsWith("'") && text.endsWith("'"))
    return text.slice(1, -1).replaceAll("''", "'");
  if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
    try {
      return String(JSON.parse(text));
    } catch {
      return text.slice(1, -1);
    }
  }
  return text;
}

const KEY = /^([A-Za-z_][\w-]*):(?:\s+(.*))?$/;

/** The first entry with `key` at `column` in the lines [from, to). */
function findEntry(
  lines: string[],
  from: number,
  to: number,
  column: number,
  key: string,
): { line: number; value: string } | null {
  for (let index = from; index < to; index++) {
    const text = entryAt(lines[index], column);
    const match = text === null ? null : KEY.exec(text.trimEnd());
    if (match && match[1] === key) return { line: index, value: scalar(match[2] ?? "") };
  }
  return null;
}

/** The index after the last line of the entry at `start` whose key starts at
 *  `column`: its deeper lines and the items of a sequence written at the
 *  key's own indent. */
function entryEnd(lines: string[], start: number, column: number): number {
  let end = start + 1;
  for (let index = start + 1; index < lines.length; index++) {
    const indent = indentOf(lines[index]);
    if (indent === -1) continue;
    if (indent > column || (indent === column && lines[index].startsWith("- ", indent)))
      end = index + 1;
    else break;
  }
  return end;
}

interface Item {
  start: number;
  end: number;
  column: number;
}

/** The items of the block sequence under the entry at `start`, which ends at
 *  `end`. Each item carries the column of its keys. */
function sequenceItems(lines: string[], start: number, end: number): Item[] {
  const items: Item[] = [];
  let dash = -1;
  for (let index = start + 1; index < end; index++) {
    const indent = indentOf(lines[index]);
    if (indent === -1) continue;
    const isItem = lines[index].startsWith("- ", indent);
    if (dash === -1) {
      if (!isItem) return [];
      dash = indent;
    }
    if (indent === dash && isItem) {
      if (items.length > 0) items[items.length - 1].end = index;
      items.push({ start: index, end, column: dash + 2 });
    }
  }
  return items;
}

function itemWithId(lines: string[], items: Item[], id: string): Item | undefined {
  return items.find(
    (item) => findEntry(lines, item.start, item.end, item.column, "id")?.value === id,
  );
}

/**
 * Replace the placeholder of the member at `path`
 * (`groups.<group id>.members.<member id>`) with `inventory` in the YAML
 * text, and keep every other line as it is. The browser does not parse YAML:
 * the member is found by its keys and their indents, as block YAML writes
 * them, and the server validates the result. Returns null when the text
 * holds no such placeholder.
 */
export function bindPlaceholder(
  text: string,
  path: string,
  inventory: InventoryReference,
): string | null {
  const match = /^groups\.([^.]+)\.members\.([^.]+)$/.exec(path);
  if (!match) return null;
  const lines = text.split("\n");
  const groups = findEntry(lines, 0, lines.length, 0, "groups");
  if (!groups) return null;
  const group = itemWithId(
    lines,
    sequenceItems(lines, groups.line, entryEnd(lines, groups.line, 0)),
    match[1],
  );
  if (!group) return null;
  const members = findEntry(lines, group.start, group.end, group.column, "members");
  if (!members) return null;
  const member = itemWithId(
    lines,
    sequenceItems(lines, members.line, entryEnd(lines, members.line, group.column)),
    match[2],
  );
  if (!member) return null;
  const placeholder = findEntry(lines, member.start, member.end, member.column, "placeholder");
  if (!placeholder) return null;
  // the lead keeps the item's dash when the placeholder is its first entry
  const lead = lines[placeholder.line].slice(0, member.column);
  const pad = " ".repeat(member.column + 2);
  const block = [
    `${lead}inventory:`,
    `${pad}kind: ${inventory.kind}`,
    `${pad}uid: ${JSON.stringify(inventory.uid)}`,
    `${pad}role: ${inventory.role}`,
  ];
  return [
    ...lines.slice(0, placeholder.line),
    ...block,
    ...lines.slice(entryEnd(lines, placeholder.line, member.column)),
  ].join("\n");
}

// --- The page context of the open draft ---

const RUN = /^[0-9]{1,18}$/;

/** The report's members as the workspace shows them: the generator's decision
 *  per member, with the placeholder note `definition`, the server's reading of
 *  the text on screen, holds for the member. */
function draftMembers(
  report: GenerationReport | null | undefined,
  definition: BusinessApplicationDefinition | null,
): PageContextDraftMember[] {
  return (report?.references ?? []).map((reference) => ({
    path: reference.path,
    status: reference.status,
    phrase: reference.phrase || undefined,
    uid: reference.uid ?? undefined,
    candidates: reference.alternatives.length ? reference.alternatives : undefined,
    note:
      (definition ? memberAt(definition, reference.path)?.placeholder?.note : null) ?? undefined,
    issues: reference.issues.length
      ? reference.issues.map((issue) => `${issue.path}: ${issue.detail}`)
      : undefined,
  }));
}

/**
 * What the drawer reads about the open draft (ai/context.tsx): the generation,
 * its run, which the turn is pinned to, the YAML on screen, the YAML errors
 * and the report's members. ai/context.tsx cuts each part to the schema's caps
 * and marks a cut.
 */
export function draftContext(draft: {
  generationId: string;
  status: "running" | "done" | "error";
  snapshot?: string;
  yaml?: string;
  edited?: boolean;
  errors?: ValidationIssue[];
  report?: GenerationReport | null;
  definition?: BusinessApplicationDefinition | null;
}): AiContextFragment {
  const run = draft.snapshot && RUN.test(draft.snapshot) ? draft.snapshot : undefined;
  const members = draftMembers(draft.report, draft.definition ?? null);
  return {
    section: "draft",
    snapshot: run ? { id: run, origin: "pinned" } : undefined,
    application_draft: {
      generation_id: draft.generationId,
      status: draft.status,
      run_id: run,
      edited: draft.edited,
      yaml: draft.yaml,
      members: members.length ? members : undefined,
      errors: draft.errors?.length ? draft.errors.map(describeIssue) : undefined,
    },
  };
}

// --- The workspace ---

interface Props {
  /** The generation the workspace shows. Absent while the user writes the description. */
  generationId?: string;
  /** The saved revision the description form edits, for "Edit with AI". */
  edit?: ApplicationEditTarget;
  /** The user holds changes.write and may save a revision. */
  canCommit: boolean;
  onGenerated: (generationId: string) => void;
  onClose: () => void;
  onCommitted: (saved: ApplicationRevision) => void;
}

/**
 * The draft workspace of a generated Business Application.
 *
 * Without a generation it asks for a description and a pinned snapshot and
 * starts one (POST /business-applications/generations). A generation started
 * from a chat (POST /ai/service-drafts) opens here with its id. The workspace
 * polls the generation until it ends, then shows its YAML in the textarea
 * with a line gutter. A failed read ends the poll, and "Read again" reads the
 * generation once more and resumes the poll. YAML that did not parse is shown as the model wrote it,
 * with the error of each line. Every edit is validated at the generation's
 * snapshot VALIDATE_DELAY_MS after the last keystroke, in replace mode.
 *
 * The resolution report lists how each member was resolved, and Bind replaces
 * a placeholder with the chosen candidate in the text. Saving needs
 * changes.write: the import preview, then a replace commit that names the
 * generation and, for the text it was computed for, the recorded validation.
 *
 * With `edit`, the form asks for a change to that saved revision, and the
 * generator receives the revision's canonical export.
 * The commit of an edit states the base revision and digest the edit started
 * from, so a change saved in the meantime answers 409.
 */
export function ApplicationDraftWorkspace({
  generationId,
  edit,
  canCommit,
  onGenerated,
  onClose,
  onCommitted,
}: Props) {
  return generationId ? (
    <GeneratedDraft
      key={generationId}
      generationId={generationId}
      canCommit={canCommit}
      onClose={onClose}
      onCommitted={onCommitted}
    />
  ) : (
    <DescriptionForm
      edit={edit}
      canCommit={canCommit}
      onGenerated={onGenerated}
      onClose={onClose}
    />
  );
}

function DraftHeading({
  eyebrow,
  title,
  onClose,
}: {
  eyebrow: string;
  title: string;
  onClose: () => void;
}) {
  return (
    <div className="application-section-heading">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
      </div>
      <button type="button" onClick={onClose}>
        Close draft
      </button>
    </div>
  );
}

function DescriptionForm({
  edit,
  onGenerated,
  onClose,
}: {
  edit?: ApplicationEditTarget;
  canCommit: boolean;
  onGenerated: (generationId: string) => void;
  onClose: () => void;
}) {
  const [description, setDescription] = useState("");
  const [snapshot, setSnapshot] = useState("");
  const start = useMutation({
    mutationFn: () =>
      api<{ generation_id: string }>("/business-applications/generations", {
        method: "POST",
        body: {
          description: description.trim(),
          snapshot,
          ...(edit ? { application_id: edit.applicationId, base_revision: edit.revision } : {}),
        },
      }),
    onSuccess: (value) => onGenerated(value.generation_id),
  });
  return (
    <section className="application-draft" aria-label="Application draft">
      {edit ? (
        <>
          <DraftHeading
            eyebrow={`${edit.name} revision ${edit.revision}`}
            title="Edit with AI"
            onClose={onClose}
          />
        </>
      ) : (
        <>
          <DraftHeading
            eyebrow="Business application draft"
            title="Generate from a description"
            onClose={onClose}
          />
        </>
      )}
      <label className="application-field">
        {edit ? "Change" : "Description"}
        <textarea
          rows={6}
          maxLength={MAX_DESCRIPTION_CHARS}
          value={description}
          onChange={(event) => setDescription(event.target.value)}
        />
      </label>
      <PinnedSnapshotPicker label="Snapshot" value={snapshot} onChange={setSnapshot} />
      <div className="assessment-actions">
        <button
          type="button"
          disabled={!description.trim() || !snapshot || start.isPending}
          onClick={() => start.mutate()}
        >
          {edit ? "Generate the edit" : "Generate"}
        </button>
      </div>
      {start.isPending && <p role="status">Starting the generation</p>}
      {start.isError && (
        <p role="alert">{errorText(start.error, "The generation could not start")}</p>
      )}
    </section>
  );
}

/** A finished generation that holds its YAML. */
type Generated = GenerationResult & { yaml: string };

/** The saved revision an edit started from, or null for a new definition. */
function editBase(source: GenerationSource | null | undefined): EditSource | null {
  return source?.kind === "edit" ? source : null;
}

function finished(result: GenerationResult | undefined): boolean {
  return (
    !!result &&
    (result.status === "error" || (result.status === "done" && typeof result.yaml === "string"))
  );
}

/** The reads of a generation so far, answered or refused. */
function reads(state: { dataUpdateCount: number; errorUpdateCount: number } | undefined): number {
  return state ? state.dataUpdateCount + state.errorUpdateCount : 0;
}

function GeneratedDraft({
  generationId,
  canCommit,
  onClose,
  onCommitted,
}: {
  generationId: string;
  canCommit: boolean;
  onClose: () => void;
  onCommitted: (saved: ApplicationRevision) => void;
}) {
  const queryClient = useQueryClient();
  const queryKey = ["application-generation", generationId];
  const generation = useQuery({
    queryKey,
    queryFn: () =>
      api<GenerationResult>(
        `/business-applications/generations/${encodeURIComponent(generationId)}`,
      ),
    // a finished generation does not change
    staleTime: Infinity,
    // The bound counts every read.
    refetchInterval: (query) =>
      query.state.status !== "error" &&
      !finished(query.state.data) &&
      reads(query.state) < ASK_MAX_ATTEMPTS
        ? ASK_POLL_MS
        : false,
  });
  const result = generation.data;
  const done = result?.status === "done" && typeof result.yaml === "string";
  // the editor publishes a finished draft
  useAiContext(
    useAiPaneId(),
    done
      ? null
      : draftContext({
          generationId,
          status: result?.status === "error" ? "error" : "running",
          snapshot: result?.snapshot?.snapshot,
        }),
  );
  if (done) {
    return (
      <DraftEditor
        generationId={generationId}
        generated={result as Generated}
        canCommit={canCommit}
        onClose={onClose}
        onCommitted={onCommitted}
      />
    );
  }
  const polls = reads(queryClient.getQueryState(queryKey));
  return (
    <section className="application-draft" aria-label="Application draft">
      <DraftHeading
        eyebrow="Business application draft"
        title="Generated draft"
        onClose={onClose}
      />
      {generation.isError ? (
        <>
          <p role="alert">
            The draft could not be read: {errorText(generation.error, "the request failed")}
          </p>
          <button
            type="button"
            disabled={generation.isFetching}
            onClick={() => void generation.refetch()}
          >
            Read again
          </button>
        </>
      ) : result?.status === "error" ? (
        <p role="alert">{result.detail ?? "The generation failed"}</p>
      ) : polls >= ASK_MAX_ATTEMPTS ? (
        <p role="alert">The generation timed out</p>
      ) : (
        <p role="status">Generating the definition</p>
      )}
    </section>
  );
}

/** A validation result and the text it was computed for. `digest` names the
 *  recorded validation, when one was recorded. */
interface Checked {
  yaml: string;
  result: ValidationResult;
  digest: string | null;
}

function DraftEditor({
  generationId,
  generated,
  canCommit,
  onClose,
  onCommitted,
}: {
  generationId: string;
  generated: Generated;
  canCommit: boolean;
  onClose: () => void;
  onCommitted: (saved: ApplicationRevision) => void;
}) {
  const yamlId = useId();
  const snapshot = generated.snapshot?.snapshot ?? generated.report?.snapshot.snapshot ?? "";
  const base = editBase(generated.source);
  const [yaml, setYaml] = useState(generated.yaml);
  const [checked, setChecked] = useState<Checked | null>(null);
  const [previewed, setPreviewed] = useState<{ yaml: string; preview: ImportPreview } | null>(null);
  // the preview token a commit was refused with
  const [refused, setRefused] = useState("");
  const [bindError, setBindError] = useState("");
  const [saveError, setSaveError] = useState("");

  const unchanged = yaml === generated.yaml;
  // the validation of the text on screen: the last check of this text, or the
  // generation's own validation while the text is the generated one
  const current: Checked | null =
    checked && checked.yaml === yaml
      ? checked
      : unchanged && generated.validation
        ? { yaml, result: generated.validation, digest: generated.validation_digest ?? null }
        : null;
  const offered =
    previewed && previewed.yaml === yaml
      ? previewed.preview
      : unchanged
        ? (generated.validation?.preview ?? null)
        : null;
  const preview = offered && offered.preview_digest !== refused ? offered : null;
  // The post-processor's errors of the generated text. When the model's YAML
  // parsed, the validation of that text does not repeat them, so the list
  // shows both and the text is not previewed until it is edited.
  const generatorErrors = unchanged ? (generated.errors ?? []) : [];
  const errors = distinctIssues([...generatorErrors, ...(current?.result.errors ?? [])]);
  const errorLines = new Set(errors.flatMap((issue) => (issue.line != null ? [issue.line] : [])));
  const definition = current?.result.definition ?? null;
  useAiContext(
    useAiPaneId(),
    draftContext({
      generationId,
      status: "done",
      snapshot,
      yaml,
      edited: !unchanged,
      errors,
      report: generated.report,
      definition,
    }),
  );

  const validate = useMutation({
    mutationFn: (text: string) =>
      api<ValidationResult>("/business-applications/validate", {
        method: "POST",
        body: { yaml: text, snapshot, mode: "replace" },
      }),
    // a recorded check of the same text that finished first stays
    onSuccess: (result, text) =>
      setChecked((previous) =>
        previous && previous.yaml === text && previous.digest
          ? previous
          : { yaml: text, result, digest: null },
      ),
  });
  const validateText = validate.mutate;
  const needsCheck = !unchanged && checked?.yaml !== yaml && yaml.trim() !== "";
  useEffect(() => {
    if (!needsCheck) return;
    const timer = setTimeout(() => validateText(yaml), VALIDATE_DELAY_MS);
    return () => clearTimeout(timer);
  }, [needsCheck, yaml, validateText]);

  // The preview needs a recorded validation of the same text.
  const prepare = useMutation({
    mutationFn: async (text: string) => {
      let check: Checked;
      if (current && current.digest) check = current;
      else {
        const result = await api<ValidationResult>("/business-applications/validate", {
          method: "POST",
          body: { yaml: text, snapshot, mode: "replace", record: true },
        });
        check = { yaml: text, result, digest: result.validation_digest ?? null };
      }
      if (check.result.errors.length > 0) return { check, preview: null };
      // the recorded validation resolved the inventory members at the snapshot
      const next = await api<ImportPreview>("/business-applications/import/preview", {
        method: "POST",
        body: {
          yaml: text,
          mode: "replace",
          ...(check.digest ? { validation_digest: check.digest } : {}),
        },
      });
      return { check, preview: next };
    },
    onSuccess: ({ check, preview: next }, text) => {
      setChecked(check);
      if (next) setPreviewed({ yaml: text, preview: next });
      else setSaveError("The YAML has errors");
    },
    onError: (cause) => setSaveError(errorText(cause, "Could not preview the changes")),
  });
  const commit = useMutation({
    mutationFn: ({
      text,
      token,
      digest,
    }: {
      text: string;
      token: ImportPreview;
      digest: string | null;
    }) =>
      api<ApplicationRevision>("/business-applications/import/commit", {
        method: "POST",
        // an edit commits onto the revision it started from
        body: {
          yaml: text,
          mode: "replace",
          base_revision: base ? base.base_revision : token.base_revision,
          base_digest: base ? base.base_digest : token.base_digest,
          preview_digest: token.preview_digest,
          generation_id: generationId,
          ...(digest ? { validation_digest: digest } : {}),
        },
      }),
    onSuccess: (saved) => onCommitted(saved),
    onError: (cause, { token }) => {
      if (cause instanceof ApiError && cause.status === 409) {
        setRefused(token.preview_digest);
        setSaveError(
          base
            ? `The application changed after revision ${base.base_revision}`
            : "The application changed after this preview",
        );
      } else setSaveError(errorText(cause, "Could not save the revision"));
    },
  });
  const busy = prepare.isPending || commit.isPending;

  function edit(value: string) {
    setYaml(value);
    setBindError("");
    setSaveError("");
  }

  function bind(path: string, inventory: InventoryReference) {
    const next = bindPlaceholder(yaml, path, inventory);
    if (next === null) {
      setBindError(`No placeholder of ${path} in the YAML`);
      return;
    }
    edit(next);
  }

  const validation = current?.result ?? null;
  return (
    <section className="application-draft" aria-label="Application draft">
      <DraftHeading
        eyebrow={
          base
            ? `Edit of ${base.application_id} revision ${base.base_revision} at snapshot ${snapshot}`
            : `Generated draft at snapshot ${snapshot}`
        }
        title={definition?.name ?? "Business application draft"}
        onClose={onClose}
      />
      <label htmlFor={yamlId}>Draft YAML</label>
      <YamlEditor id={yamlId} value={yaml} errorLines={errorLines} onChange={edit} rows={18} />
      {errors.length > 0 && (
        <ul aria-label="YAML errors">
          {errors.map((issue, index) => (
            <li key={index}>{describeIssue(issue)}</li>
          ))}
        </ul>
      )}
      {validate.isPending && <p role="status">Validating</p>}
      {validate.isError && (
        <p role="alert">{errorText(validate.error, "Could not validate the YAML")}</p>
      )}
      {!validation && !validate.isPending && !unchanged && <p>Not validated</p>}
      {validation && (
        <section aria-label="Draft validation">
          <p role="status">
            {validation.blocking.length === 0
              ? "Nothing blocks the ready state"
              : `${validation.blocking.length} ${validation.blocking.length === 1 ? "path blocks" : "paths block"} the ready state`}
          </p>
          {validation.warnings.length > 0 && (
            <ul aria-label="Draft validation warnings">
              {validation.warnings.map((warning) => (
                <li key={`${warning.code}:${warning.path}`}>
                  {warning.path}: {warning.message}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
      {bindError && <p role="alert">{bindError}</p>}
      {generated.report && generated.report.references.length > 0 && (
        <ResolutionReport
          report={generated.report}
          definition={definition}
          disabled={busy}
          onBind={bind}
        />
      )}
      {validation?.definition && (
        <ApplicationStructure
          definition={validation.definition}
          resolution={validation.resolution}
          flows={validation.flows}
        />
      )}
      <section className="application-edit-card" aria-label="Save draft revision">
        <h4>Save as a draft revision</h4>
        {canCommit && !preview && (
          <button
            type="button"
            disabled={busy || !yaml.trim() || generatorErrors.length > 0}
            onClick={() => {
              setSaveError("");
              prepare.mutate(yaml);
            }}
          >
            Preview changes
          </button>
        )}
        {prepare.isPending && <p role="status">Preparing the import preview</p>}
        {preview && (
          <section aria-label="Save preview">
            <h5>{preview.no_op ? "No semantic changes" : "Changes"}</h5>
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
          </section>
        )}
        <button
          type="button"
          disabled={!canCommit || !preview || preview.no_op || busy}
          onClick={() => {
            setSaveError("");
            if (preview)
              commit.mutate({ text: yaml, token: preview, digest: current?.digest ?? null });
          }}
        >
          Save as draft revision
        </button>
        {saveError && <p role="alert">{saveError}</p>}
      </section>
    </section>
  );
}
