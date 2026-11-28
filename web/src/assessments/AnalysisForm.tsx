import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { PinnedSnapshotPicker as SnapshotPicker } from "./PinnedSnapshotPicker";
import type { AnalysisKind, Assessment, Requirement } from "./types";
import { emptyRequirement, requirementError, conditionSentence } from "./types";
import { Field, ListField, RequirementComposer } from "./RequirementComposer";
import { InterfacePicker } from "./InterfacePicker";
import { ObjectPicker } from "./ObjectPicker";
import { ServicePicker } from "./ServicePicker";
import { analysisQuestions, objectDescription, optionsPath, scopeFromRequest } from "./guided";
import type { DiscoveryObject, DiscoveryResponse, ObjectKind, RepairScope } from "./guided";

const costDimensions = ["devices", "newly_permitted_scope", "rule_edits"];
const costLabels: Record<string, string> = {
  devices: "Devices changed",
  newly_permitted_scope: "Newly permitted flow scope",
  rule_edits: "Rule edits",
};
interface Protected {
  name: string;
  request: Requirement;
  desired: string;
}
interface RepairTarget {
  object: DiscoveryObject;
  device: string;
}
interface Props {
  assessment: Assessment;
  busy: boolean;
  onSubmit: (input: Record<string, unknown>) => void;
  initialKind?: AnalysisKind;
  initialInput?: Record<string, unknown>;
}
const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

async function resolveObject(
  snapshot: string,
  kind: string,
  uid: string,
): Promise<DiscoveryObject> {
  const response = await api<DiscoveryResponse>(optionsPath(snapshot, kind, "", undefined, uid));
  const item = response.items.find((entry) => entry.uid === uid && entry.kind === kind);
  if (!item?.selectable)
    throw new Error(item?.disabled_reason || "Proposed object not available at this snapshot");
  return item;
}
async function resolveDomain(
  snapshot: string,
  selected: DiscoveryObject,
): Promise<DiscoveryObject[]> {
  const found = new Map<string, DiscoveryObject>();
  async function visit(item: DiscoveryObject, ancestors: string[]) {
    if (ancestors.includes(item.uid) || ancestors.length > 8)
      throw new Error("Shared dependency membership has a cycle or more than 8 levels");
    if (found.has(item.uid)) return;
    found.set(item.uid, item);
    if (found.size > 100) throw new Error("Shared dependency has more than 100 objects");
    if (item.kind === "domain") {
      if (!item.members?.length)
        throw new Error("Shared dependency has no recorded failure members");
      for (const member of item.members)
        await visit(await resolveObject(snapshot, member.kind, member.uid), [
          ...ancestors,
          item.uid,
        ]);
    }
  }
  await visit(selected, []);
  return [...found.values()];
}

export function AnalysisForm(props: Props) {
  return (
    <GuidedAnalysisForm
      key={`${props.assessment.id}:${props.assessment.revision}:${props.initialKind}:${JSON.stringify(props.initialInput ?? {})}`}
      {...props}
    />
  );
}
function GuidedAnalysisForm({
  assessment,
  busy,
  onSubmit,
  initialKind = "evaluate",
  initialInput = {},
}: Props) {
  const draftSnapshot =
    typeof initialInput.snapshot === "string"
      ? initialInput.snapshot
      : assessment.definition.snapshot;
  const draftLimits = object(initialInput.limits);
  const [kind, setKind] = useState<AnalysisKind>(initialKind);
  const [step, setStep] = useState(0);
  const [snapshot, setSnapshot] = useState(draftSnapshot);
  const [beforeSnapshot, setBeforeSnapshot] = useState(
    typeof initialInput.before_snapshot === "string" ? initialInput.before_snapshot : "",
  );
  const [maxCandidates, setMaxCandidates] = useState(Number(draftLimits.max_candidates ?? 64));
  const [maxEvaluations, setMaxEvaluations] = useState(Number(draftLimits.max_evaluations ?? 256));
  const [maxCombination, setMaxCombination] = useState(
    Number(draftLimits.max_combination_size ?? 2),
  );
  const [maxSeconds, setMaxSeconds] = useState(Number(draftLimits.max_seconds ?? 30));
  const [allowedTargets, setAllowedTargets] = useState<RepairTarget[]>([]);
  const [costOrder, setCostOrder] = useState(
    strings(initialInput.cost_order).length === 3
      ? strings(initialInput.cost_order)
      : costDimensions,
  );
  const [allowedKinds, setAllowedKinds] = useState(
    initialInput.allowed_kinds ? strings(initialInput.allowed_kinds) : ["fw_rule.add"],
  );
  const [protectedRequests, setProtected] = useState<Protected[]>(() =>
    Array.isArray(initialInput.protected)
      ? (initialInput.protected.filter(
          (entry) => object(entry).request && typeof object(entry).desired === "string",
        ) as Protected[])
      : [],
  );
  const [scopeOverride, setScope] = useState<RepairScope | null>(() => {
    const draft = object(initialInput.scope);
    return Object.keys(draft).length
      ? {
          source: strings(draft.source),
          destination: strings(draft.destination),
          protocols: strings(draft.protocols),
          ports: strings(draft.ports),
          source_ports: strings(draft.source_ports),
        }
      : null;
  });
  const [failures, setFailures] = useState<DiscoveryObject[]>([]);
  const [failureKind, setFailureKind] = useState<ObjectKind>("device");
  const [resolving, setResolving] = useState(
    () =>
      !!Object.keys(object(initialInput.allowed_targets)).length ||
      !!(Array.isArray(initialInput.targets) && initialInput.targets.length) ||
      !!(Array.isArray(initialInput.domains) && initialInput.domains.length),
  );
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const search = ["regression", "repair", "resilience"].includes(kind);
  const graphService = useQuery({
    queryKey: ["assessment-service", snapshot, assessment.definition.requirement],
    queryFn: () => resolveObject(snapshot, "service", assessment.definition.requirement!),
    enabled: !!snapshot && !assessment.definition.request && !!assessment.definition.requirement,
  });
  const request = assessment.definition.request ?? graphService.data?.definition;
  const scope = scopeOverride ?? scopeFromRequest(request);
  const draftJson = JSON.stringify(initialInput);
  // Exact lookups resolve draft identities; display names are never used as identifiers.
  useEffect(() => {
    const draft = JSON.parse(draftJson) as Record<string, unknown>;
    if (snapshot !== draftSnapshot) return;
    const targets = object(draft.allowed_targets);
    const proposed = [
      ...(Array.isArray(draft.targets) ? draft.targets : []),
      ...(Array.isArray(draft.domains)
        ? draft.domains.map((entry) => ({ ...object(entry), kind: "domain" }))
        : []),
    ];
    if (!Object.keys(targets).length && !proposed.length) return;
    let current = true;
    Promise.all([
      Promise.all(
        Object.entries(targets).map(async ([uid, device]) => ({
          object: await resolveObject(snapshot, "rulebase", uid),
          device: String(device),
        })),
      ),
      Promise.all(
        proposed.map(async (entry) => {
          const candidate = object(entry);
          const selected = await resolveObject(
            snapshot,
            String(candidate.kind),
            String(candidate.uid),
          );
          return selected.kind === "domain" ? resolveDomain(snapshot, selected) : [selected];
        }),
      ),
    ])
      .then(([repair, failure]) => {
        if (!current) return;
        setAllowedTargets(repair);
        setFailures([...new Map(failure.flat().map((item) => [item.uid, item])).values()]);
        setNotice("Draft selections resolved at this snapshot");
      })
      .catch((cause: Error) => {
        if (current) setError(cause.message);
      })
      .finally(() => {
        if (current) setResolving(false);
      });
    return () => {
      current = false;
    };
  }, [draftJson, draftSnapshot, snapshot]);

  function changeSnapshot(next: string) {
    setSnapshot(next);
    setScope(null);
    setAllowedTargets([]);
    setFailures([]);
    setProtected([]);
    setResolving(false);
    setError("");
    setNotice("Selections cleared for the new snapshot");
  }
  async function addFailure(item: DiscoveryObject) {
    setError("");
    setResolving(true);
    const selectedSnapshot = snapshot;
    try {
      const additions = item.kind === "domain" ? await resolveDomain(snapshot, item) : [item];
      // This form cannot advance during membership loading; snapshot controls live on the previous stage.
      if (selectedSnapshot === snapshot)
        setFailures((previous) => [
          ...new Map([...previous, ...additions].map((entry) => [entry.uid, entry])).values(),
        ]);
      if (item.kind === "domain")
        setNotice(`${item.name}: ${additions.length - 1} recorded members`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not resolve recorded members");
    } finally {
      setResolving(false);
    }
  }
  function validation(): string | null {
    if (!snapshot) return "No snapshot selected";
    if (!request && assessment.definition.requirement)
      return graphService.isError
        ? "Recorded service not resolved at this snapshot"
        : "Loading the recorded service definition";
    if (kind === "regression" && (!beforeSnapshot || beforeSnapshot === snapshot))
      return "Regression needs two different snapshots";
    if (kind === "verify" && !assessment.definition.deployments?.length)
      return "No recorded deployment";
    if (kind === "repair") {
      if (
        !allowedTargets.length ||
        allowedTargets.some(
          (target) =>
            !target.device ||
            !(target.object.devices ?? (target.object.device ? [target.object.device] : [])).some(
              (owner) => owner.uid === target.device,
            ),
        ) ||
        !allowedKinds.length
      )
        return "Permitted change location, owner or allowed operation missing";
      if (protectedRequests.some((entry) => requirementError(entry.request)))
        return "Protected service definition incomplete";
      if (
        new Set(protectedRequests.map((entry) => entry.name || entry.request.name)).size !==
        protectedRequests.length
      )
        return "Protected service names not distinct";
      if (
        !scope.source.length ||
        !scope.destination.length ||
        !scope.protocols.length ||
        !scope.ports.length
      )
        return "Repair scope needs source, destination, protocol and ports";
      if (
        costOrder.length !== 3 ||
        new Set(costOrder).size !== 3 ||
        costOrder.some((value) => !costDimensions.includes(value))
      )
        return "Repeated repair cost dimension";
    }
    if (kind === "resilience" && !failures.some((item) => item.kind !== "domain"))
      return "No failure target selected";
    if (
      kind === "resilience" &&
      failures.some(
        (item) =>
          item.kind === "domain" &&
          item.members?.some((member) => !failures.some((other) => other.uid === member.uid)),
      )
    )
      return "Selected shared dependency missing members";
    if (search) {
      if (!Number.isInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > 256)
        return "Maximum candidates from 1 to 256";
      if (!Number.isInteger(maxEvaluations) || maxEvaluations < 1 || maxEvaluations > 10000)
        return "Maximum evaluations from 1 to 10000";
      if (!Number.isInteger(maxCombination) || maxCombination < 0 || maxCombination > 8)
        return "Maximum combination size from 0 to 8";
      if (!Number.isFinite(maxSeconds) || maxSeconds < 0.1 || maxSeconds > 300)
        return "Maximum seconds from 0.1 to 300";
    }
    return null;
  }
  function payload() {
    const ids = new Map(failures.map((item, index) => [item.uid, `${item.kind}-${index + 1}`]));
    return {
      kind,
      snapshot,
      ...(search
        ? {
            limits: {
              max_candidates: maxCandidates,
              max_evaluations: maxEvaluations,
              max_combination_size: maxCombination,
              max_seconds: maxSeconds,
              max_results: 50,
            },
          }
        : {}),
      ...(kind === "regression" ? { before_snapshot: beforeSnapshot } : {}),
      ...(kind === "repair"
        ? {
            allowed_targets: Object.fromEntries(
              allowedTargets.map((target) => [target.object.uid, target.device]),
            ),
            allowed_kinds: allowedKinds,
            cost_order: costOrder,
            scope: {
              source: scope.source,
              destination: scope.destination,
              protocols: scope.protocols,
              ports: scope.ports,
              ...(scope.source_ports.length ? { source_ports: scope.source_ports } : {}),
            },
            protected: protectedRequests.map((entry) => ({
              name: entry.name || entry.request.name,
              request: entry.request,
              desired: entry.desired,
            })),
          }
        : {}),
      ...(kind === "resilience"
        ? {
            targets: failures
              .filter((item) => item.kind !== "domain")
              .map((item) => ({
                id: ids.get(item.uid),
                kind: item.kind,
                uid: item.uid,
                interfaces: item.interfaces ?? [],
              })),
            domains: failures
              .filter((item) => item.kind === "domain")
              .map((item) => ({
                id: ids.get(item.uid),
                uid: item.uid,
                members: item.members?.map((member) => ids.get(member.uid)) ?? [],
                source: item.source || "unknown",
                evidence_status: item.evidence_status || "unknown",
                valid_from_ms: item.valid_from_ms ?? null,
                valid_until_ms: item.valid_until_ms ?? null,
                evidence_refs: item.evidence_refs ?? [],
              })),
          }
        : {}),
    };
  }
  function submit(event: React.FormEvent) {
    event.preventDefault();
    if (step === 0) {
      if (
        !snapshot ||
        (kind === "regression" && (!beforeSnapshot || beforeSnapshot === snapshot))
      ) {
        setError(snapshot ? "Regression needs two different snapshots" : "No snapshot selected");
        return;
      }
      setError("");
      setStep(1);
      return;
    }
    const invalid = validation();
    if (invalid) {
      setError(invalid);
      return;
    }
    setError("");
    if (step === 1) {
      setStep(2);
      return;
    }
    onSubmit(payload());
  }
  return (
    <form className="assessment-analysis-form" onSubmit={submit}>
      <h3>Run an analysis</h3>
      <ol className="assessment-guided-steps" aria-label="Analysis stages">
        {["Question", "Scope & assumptions", "Review & run"].map((label, index) => (
          <li key={label} aria-current={step === index ? "step" : undefined}>
            {label}
          </li>
        ))}
      </ol>
      {step === 0 && (
        <>
          <div className="assessment-fields">
            <label className="assessment-field">
              <span>Analysis</span>
              <select
                value={kind}
                onChange={(event) => {
                  setKind(event.target.value as AnalysisKind);
                  setError("");
                }}
              >
                {Object.entries(analysisQuestions).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            {kind === "regression" && (
              <SnapshotPicker
                label="Before snapshot A"
                value={beforeSnapshot}
                onChange={setBeforeSnapshot}
              />
            )}
            <SnapshotPicker
              label={
                kind === "regression"
                  ? "After snapshot B"
                  : kind === "verify"
                    ? "Post-deployment snapshot"
                    : "Analysis snapshot"
              }
              value={snapshot}
              onChange={changeSnapshot}
            />
          </div>
          <p>
            {request
              ? `${request.name}: ${request.sources.join(", ")} to ${request.destination}`
              : "Saved graph service"}
          </p>
        </>
      )}
      {step === 1 && (
        <>
          <h4>{analysisQuestions[kind]}</h4>
          {kind === "repair" && (
            <>
              <fieldset>
                <legend>Permitted change locations</legend>
                <ObjectPicker
                  snapshot={snapshot}
                  kind="rulebase"
                  label="Find a firewall policy"
                  assessmentId={assessment.id}
                  selectedUids={allowedTargets.map((target) => target.object.uid)}
                  onSelect={(item) => {
                    const owners = item.devices ?? (item.device ? [item.device] : []);
                    setAllowedTargets([
                      ...allowedTargets,
                      { object: item, device: owners.length === 1 ? owners[0].uid : "" },
                    ]);
                  }}
                />
                {allowedTargets.map((target, index) => (
                  <div key={target.object.uid} className="assessment-selection">
                    <strong>{target.object.name}</strong>
                    <p>{objectDescription(target.object)}</p>
                    <label className="assessment-field">
                      <span>Device for {target.object.name}</span>
                      <select
                        value={target.device}
                        onChange={(event) =>
                          setAllowedTargets(
                            allowedTargets.map((entry, i) =>
                              i === index ? { ...entry, device: event.target.value } : entry,
                            ),
                          )
                        }
                      >
                        <option value="">Choose its recorded owner</option>
                        {(
                          target.object.devices ??
                          (target.object.device ? [target.object.device] : [])
                        ).map((owner) => (
                          <option value={owner.uid} key={owner.uid}>
                            {owner.name}
                          </option>
                        ))}
                      </select>
                    </label>
                    <button
                      type="button"
                      onClick={() =>
                        setAllowedTargets(allowedTargets.filter((_, i) => i !== index))
                      }
                    >
                      Remove {target.object.name}
                    </button>
                  </div>
                ))}
              </fieldset>
              <fieldset>
                <legend>Protect other services</legend>
                <ServicePicker
                  snapshot={snapshot}
                  label="Find a service to protect"
                  onSelect={(item) => {
                    if (!protectedRequests.some((entry) => entry.name === item.request.name))
                      setProtected([
                        ...protectedRequests,
                        { name: item.request.name, request: item.request, desired: "holds" },
                      ]);
                    else setError("Service already protected");
                  }}
                />
                {protectedRequests.map((entry, index) => (
                  <fieldset key={index}>
                    <legend>{entry.request.name || `Protected service ${index + 1}`}</legend>
                    <label className="assessment-field">
                      <span>Protection for {entry.request.name || `service ${index + 1}`}</span>
                      <select
                        value={entry.desired}
                        onChange={(event) =>
                          setProtected(
                            protectedRequests.map((item, i) =>
                              i === index ? { ...item, desired: event.target.value } : item,
                            ),
                          )
                        }
                      >
                        <option value="holds">Must remain connected</option>
                        <option value="isolated">Must remain isolated</option>
                      </select>
                    </label>
                    <p>
                      {entry.request.sources.join(", ")} to {entry.request.destination},{" "}
                      {conditionSentence(entry.request.condition)}
                    </p>
                    <details open={!entry.request.name}>
                      <summary>Service definition</summary>
                      <RequirementComposer
                        value={entry.request}
                        onChange={(next) =>
                          setProtected(
                            protectedRequests.map((item, i) =>
                              i === index ? { ...item, name: next.name, request: next } : item,
                            ),
                          )
                        }
                      />
                    </details>
                    <button
                      type="button"
                      onClick={() => setProtected(protectedRequests.filter((_, i) => i !== index))}
                    >
                      Remove protection {index + 1}
                    </button>
                  </fieldset>
                ))}
                <details>
                  <summary>Define a custom protection</summary>
                  <button
                    type="button"
                    onClick={() =>
                      setProtected([
                        ...protectedRequests,
                        { name: "", request: emptyRequirement(), desired: "holds" },
                      ])
                    }
                  >
                    Add custom protected service
                  </button>
                </details>
              </fieldset>
              <fieldset>
                <legend>Repair scope</legend>
                <div className="assessment-fields">
                  {(["source", "destination", "protocols", "ports"] as const).map((key) => (
                    <ListField
                      key={key}
                      label={`Repair ${key}`}
                      value={scope[key]}
                      required
                      onChange={(next) => setScope({ ...scope, [key]: next })}
                    />
                  ))}
                </div>
                <ListField
                  label="Repair source ports"
                  value={scope.source_ports}
                  onChange={(next) => setScope({ ...scope, source_ports: next })}
                />
              </fieldset>
              <fieldset>
                <legend>Allowed operations</legend>
                {(
                  [
                    ["fw_rule.add", "Add firewall rule"],
                    ["fw_rule.modify", "Modify firewall rule"],
                    ["fw_rule.remove", "Remove firewall rule"],
                  ] as const
                ).map(([operation, operationName]) => (
                  <label className="assessment-check" key={operation}>
                    <input
                      type="checkbox"
                      checked={allowedKinds.includes(operation)}
                      onChange={(event) =>
                        setAllowedKinds(
                          event.target.checked
                            ? [...allowedKinds, operation]
                            : allowedKinds.filter((value) => value !== operation),
                        )
                      }
                    />
                    {operationName}
                  </label>
                ))}
              </fieldset>
              <fieldset>
                <legend>Repair cost priority</legend>
                <div className="assessment-fields">
                  {costOrder.map((dimension, index) => (
                    <label className="assessment-field" key={index}>
                      <span>Cost priority {index + 1}</span>
                      <select
                        value={dimension}
                        onChange={(event) => {
                          const next = [...costOrder];
                          const other = next.indexOf(event.target.value);
                          [next[index], next[other]] = [next[other], next[index]];
                          setCostOrder(next);
                        }}
                      >
                        {costDimensions.map((value) => (
                          <option key={value} value={value}>
                            {costLabels[value]}
                          </option>
                        ))}
                      </select>
                    </label>
                  ))}
                </div>
              </fieldset>
            </>
          )}
          {kind === "resilience" && (
            <>
              <label className="assessment-field">
                <span>Failure object type</span>
                <select
                  value={failureKind}
                  onChange={(event) => setFailureKind(event.target.value as ObjectKind)}
                >
                  {["device", "interface", "link", "tunnel", "domain"].map((value) => (
                    <option key={value} value={value}>
                      {value === "domain"
                        ? "Shared dependencies"
                        : `${value[0].toUpperCase()}${value.slice(1)}s`}
                    </option>
                  ))}
                </select>
              </label>
              {failureKind === "interface" ? (
                <InterfacePicker
                  snapshot={snapshot}
                  deviceLabel="Find a device"
                  interfaceLabel="Find a failure target"
                  assessmentId={assessment.id}
                  selectedUids={failures.map((item) => item.uid)}
                  onSelect={(item) => void addFailure(item)}
                />
              ) : (
                <ObjectPicker
                  snapshot={snapshot}
                  kind={failureKind}
                  label="Find a failure target"
                  assessmentId={assessment.id}
                  selectedUids={failures.map((item) => item.uid)}
                  onSelect={(item) => void addFailure(item)}
                />
              )}
              {resolving && <p role="status">Resolving recorded shared dependency members</p>}
              <ul className="assessment-selection-list">
                {failures.map((item) => (
                  <li key={item.uid}>
                    <strong>{item.name}</strong> (
                    {item.kind === "domain" ? "shared dependency" : item.kind})
                    <p>{objectDescription(item)}</p>
                    {item.kind === "domain" && (
                      <>
                        <p>
                          Recorded members: {item.members?.map((member) => member.name).join(", ")}
                        </p>
                        <p>Evidence: {item.evidence_status || "unknown"}</p>
                      </>
                    )}
                    {!!item.interfaces?.length && (
                      <p>{item.interfaces.length} recorded endpoint interfaces</p>
                    )}
                    <button
                      type="button"
                      onClick={() =>
                        setFailures(failures.filter((entry) => entry.uid !== item.uid))
                      }
                    >
                      Remove {item.name}
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
          <details>
            <summary>Assumptions and search limits</summary>
            <p>Evaluation mode: {assessment.definition.mode}</p>
            <p>Connectivity: {request?.success || "recorded service"}</p>
            {search && (
              <div className="assessment-fields">
                <Field
                  label="Maximum candidates"
                  type="number"
                  value={maxCandidates}
                  onChange={(value) => setMaxCandidates(Number(value))}
                />
                <Field
                  label="Maximum evaluations"
                  type="number"
                  value={maxEvaluations}
                  onChange={(value) => setMaxEvaluations(Number(value))}
                />
                <Field
                  label="Maximum combination size"
                  type="number"
                  value={maxCombination}
                  onChange={(value) => setMaxCombination(Number(value))}
                />
                <Field
                  label="Maximum seconds"
                  type="number"
                  value={maxSeconds}
                  onChange={(value) => setMaxSeconds(Number(value))}
                />
              </div>
            )}
          </details>
        </>
      )}
      {step === 2 && (
        <section className="assessment-review" aria-label="Analysis review">
          <h4>{analysisQuestions[kind]}</h4>
          <dl>
            <dt>Service</dt>
            <dd>{request?.name || assessment.title}</dd>
            <dt>Snapshot</dt>
            <dd>
              {snapshot}
              {kind === "regression" && ` compared with ${beforeSnapshot}`}
            </dd>
            <dt>Assumptions</dt>
            <dd>
              {assessment.definition.mode} evaluation, {request?.success || "recorded"} connectivity
            </dd>
          </dl>
          {request && (
            <p>
              {request.sources.join(", ")} to {request.destination},{" "}
              {conditionSentence(request.condition)}
            </p>
          )}
          {kind === "repair" && (
            <>
              <h5>Permitted changes</h5>
              <ul>
                {allowedTargets.map((target) => (
                  <li key={target.object.uid}>
                    {target.object.name} on{" "}
                    {
                      (target.object.devices ?? [target.object.device]).find(
                        (owner) => owner?.uid === target.device,
                      )?.name
                    }
                  </li>
                ))}
              </ul>
              <p>
                Operations: {allowedKinds.map((value) => value.replace("fw_rule.", "")).join(", ")}{" "}
                firewall rules
              </p>
              <p>Priority: {costOrder.map((value) => costLabels[value]).join(", then ")}</p>
              <p>
                Scope: {scope.source.join(", ")} to {scope.destination.join(", ")}
              </p>
              <p>Protocols: {scope.protocols.join(", ")}</p>
              <p>Destination ports: {scope.ports.join(", ")}</p>
              <p>Source ports: {scope.source_ports.join(", ") || "all"}</p>
              <h5>Protected services</h5>
              {protectedRequests.length ? (
                <ul>
                  {protectedRequests.map((entry, index) => (
                    <li key={index}>
                      {entry.request.name}: must remain{" "}
                      {entry.desired === "isolated" ? "isolated" : "connected"}
                    </li>
                  ))}
                </ul>
              ) : (
                <p>No protected services</p>
              )}
            </>
          )}
          {kind === "resilience" && (
            <>
              <h5>Declared failure universe</h5>
              <ul>
                {failures.map((item) => (
                  <li key={item.uid}>
                    {item.name} ({item.kind})
                    {item.kind === "domain"
                      ? `, members: ${item.members?.map((member) => member.name).join(", ")}`
                      : ""}
                  </li>
                ))}
              </ul>
            </>
          )}
          {search && (
            <p>
              Search bounds: {maxCandidates} candidates, {maxEvaluations} evaluations, combinations
              up to {maxCombination}, {maxSeconds} seconds
            </p>
          )}
          <details>
            <summary>Technical input</summary>
            <pre>{JSON.stringify(payload(), null, 2)}</pre>
          </details>
        </section>
      )}
      {resolving && step !== 1 && <p role="status">Resolving proposed objects</p>}
      {notice && <p role="status">{notice}</p>}
      {error && <p role="alert">{error}</p>}
      {graphService.isError && (
        <p role="alert">
          Recorded service not available at this snapshot{" "}
          <button type="button" onClick={() => void graphService.refetch()}>
            Retry service lookup
          </button>
        </p>
      )}
      <div className="assessment-actions">
        {step > 0 && (
          <button
            type="button"
            disabled={busy || resolving}
            onClick={() => {
              setStep(step - 1);
              setError("");
            }}
          >
            Back
          </button>
        )}
        <button type="submit" disabled={busy || resolving}>
          {step === 0 ? "Continue to scope" : step === 1 ? "Review analysis" : "Start analysis"}
        </button>
      </div>
    </form>
  );
}
