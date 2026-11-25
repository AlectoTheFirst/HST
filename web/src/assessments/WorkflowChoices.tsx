import type { AnalysisKind } from "./types";

export const workflows: { kind: AnalysisKind; title: string; description: string }[] = [
  { kind: "evaluate", title: "Check a service", description: "Traffic at a recorded snapshot" },
  {
    kind: "troubleshoot",
    title: "Troubleshoot a service",
    description: "Path end, missing evidence and next collection",
  },
  {
    kind: "regression",
    title: "Explain what changed",
    description: "Working snapshot against the service failure",
  },
  {
    kind: "repair",
    title: "Find a safe repair",
    description: "Service restored, other services and isolation protected",
  },
  {
    kind: "resilience",
    title: "Test service resilience",
    description: "Failures of devices, connections and shared dependencies",
  },
  {
    kind: "verify",
    title: "Verify a deployment",
    description: "Saved prediction against observations after deployment",
  },
];
export function workflowTitle(kind: AnalysisKind) {
  return workflows.find((item) => item.kind === kind)?.title ?? kind;
}
export function WorkflowChoices({
  onChoose,
  selected,
  allowVerify = true,
}: {
  onChoose: (kind: AnalysisKind) => void;
  selected?: AnalysisKind;
  allowVerify?: boolean;
}) {
  return (
    <div className="assessment-workflows" role="group" aria-label="Question">
      {workflows
        .filter((item) => allowVerify || item.kind !== "verify")
        .map((item) => (
          <button
            type="button"
            key={item.kind}
            aria-pressed={selected === item.kind}
            onClick={() => onChoose(item.kind)}
          >
            <strong>{item.title}</strong>
            <span>{item.description}</span>
          </button>
        ))}
    </div>
  );
}
