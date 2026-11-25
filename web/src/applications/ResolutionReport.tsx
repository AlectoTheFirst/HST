import { useState } from "react";
import type {
  ApplicationMember,
  BusinessApplicationDefinition,
  GenerationReference,
  GenerationReport,
  InventoryReference,
} from "./types";

/** The member a report path `groups.<group id>.members.<member id>` names. */
export function memberAt(
  definition: BusinessApplicationDefinition,
  path: string,
): ApplicationMember | undefined {
  const match = /^groups\.([^.]+)\.members\.([^.]+)$/.exec(path);
  if (!match) return undefined;
  return definition.groups
    .find((group) => group.id === match[1])
    ?.members.find((member) => member.id === match[2]);
}

function describeReference(reference: GenerationReference): string {
  if (reference.status === "ambiguous") return "Ambiguous placeholder";
  if (reference.status === "unresolved") return "Unresolved placeholder";
  return reference.selection === "model-choice" ? "Resolved by model choice" : "Resolved";
}

/**
 * The resolution report of a generated draft: one row per group member with
 * the decision of the post-processor, the lookup steps behind it and the
 * alternatives. The rows describe the generation. `definition` is the
 * server's reading of the current YAML text, so a member bound since the
 * generation shows as bound, and null while the text does not parse.
 *
 * Bind, on a member that still holds a placeholder with candidates, hands an
 * inventory reference of the expected kind to the chosen candidate to
 * `onBind`. The caller rewrites the YAML text.
 */
export function ResolutionReport({
  report,
  definition,
  disabled = false,
  onBind,
}: {
  report: GenerationReport;
  definition: BusinessApplicationDefinition | null;
  disabled?: boolean;
  onBind: (path: string, inventory: InventoryReference) => void;
}) {
  const omitted = report.related_omitted ?? 0;
  return (
    <section className="resolution-report" aria-label="Resolution report">
      <h4>Resolution report</h4>
      {report.references.length === 0 ? (
        <p>No members</p>
      ) : (
        report.references.map((reference) => (
          <ReferenceRow
            key={reference.path}
            reference={reference}
            definition={definition}
            disabled={disabled}
            onBind={onBind}
          />
        ))
      )}
      {(report.related.length > 0 || omitted > 0) && (
        <>
          <h5>Found and not written</h5>
          {report.related.length > 0 && (
            <ul aria-label="Related objects">
              {report.related.map((item) => (
                <li key={item.uid}>
                  {item.name ?? item.uid} <code>{item.uid}</code>
                  {item.label ? ` (${item.label})` : ""}, {item.relation}: {item.reason}
                </li>
              ))}
            </ul>
          )}
          {omitted > 0 && (
            <details aria-label="Other search results">
              <summary>
                {omitted} other {omitted === 1 ? "object" : "objects"} returned by searches
              </summary>
            </details>
          )}
        </>
      )}
    </section>
  );
}

function ReferenceRow({
  reference,
  definition,
  disabled,
  onBind,
}: {
  reference: GenerationReference;
  definition: BusinessApplicationDefinition | null;
  disabled: boolean;
  onBind: (path: string, inventory: InventoryReference) => void;
}) {
  const member = definition ? memberAt(definition, reference.path) : undefined;
  const placeholder = member?.placeholder ?? null;
  const candidates = placeholder?.candidates ?? [];
  const [candidate, setCandidate] = useState("");
  const chosen = candidates.includes(candidate) ? candidate : (candidates[0] ?? "");
  return (
    <article className="application-row" aria-label={`Reference ${reference.path}`}>
      <div>
        <strong>{reference.phrase}</strong>
        <code>{reference.path}</code>
      </div>
      <p>{describeReference(reference)}</p>
      {reference.uid && (
        <p>
          {reference.kind} <code>{reference.uid}</code>
        </p>
      )}
      {reference.bindings.length > 0 && (
        <p>
          Addresses:{" "}
          {reference.bindings
            .map((binding) =>
              binding.context ? `${binding.address} in ${binding.context}` : binding.address,
            )
            .join(", ")}
        </p>
      )}
      {reference.chain.length > 0 && (
        <p>
          Chain: {reference.chain.map((edge) => `${edge.from} ${edge.rel} ${edge.to}`).join(", ")}
        </p>
      )}
      {reference.alternatives.length > 0 && (
        <p>
          {reference.status === "resolved" ? "Alternatives" : "Candidates"}:{" "}
          {reference.alternatives.join(", ")}
        </p>
      )}
      {reference.evidence.length > 0 && (
        <p>
          Evidence: {reference.evidence.map((item) => `step ${item.step} ${item.tool}`).join(", ")}
        </p>
      )}
      {reference.issues.map((issue) => (
        <p key={`${issue.code}:${issue.path}`}>
          {issue.path}: {issue.detail}
        </p>
      ))}
      {placeholder?.note && <p>{placeholder.note}</p>}
      {definition && !member && <p>Member not in the draft</p>}
      {reference.status !== "resolved" && member?.inventory && (
        <p>
          Bound to <code>{member.inventory.uid}</code> in the draft
        </p>
      )}
      {placeholder &&
        (candidates.length > 0 ? (
          <div className="resolution-bind">
            <label>
              Candidate
              <select
                value={chosen}
                disabled={disabled}
                onChange={(event) => setCandidate(event.target.value)}
              >
                {candidates.map((uid) => (
                  <option key={uid} value={uid}>
                    {uid}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              disabled={disabled || !chosen}
              onClick={() =>
                onBind(reference.path, {
                  kind: placeholder.expected_kind ?? "interface",
                  uid: chosen,
                  role: "component",
                })
              }
            >
              Bind
            </button>
          </div>
        ) : (
          <p>No candidates</p>
        ))}
    </article>
  );
}
