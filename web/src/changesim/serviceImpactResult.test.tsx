/** The tests cover the impact_evaluate_service result of tool version 3. */

import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { catalogueEnvelope } from "../test/fixtures";
import { parseImpactEvaluateService } from "./assessImpact";
import { ServiceImpactPane } from "./ServiceImpactPane";

function bucket(items: string[]) {
  return { count: items.length, items, truncated: false };
}

const FAILS = { kind: "result", statement: "condition-holds", answer: "false", word: "fails", quantifier: "every", condition: "forward", missing: [] };
const PASSES = { ...FAILS, answer: "true", word: "passes" };

const step = { device_uid: "dev:core1", stage: "filter", kind: "deny", detail: "rule 10 of fw:LAN denies the flow", unknown: [] };

const BODY = {
  mode: "guaranteed",
  intents: [],
  request: {
    name: "web",
    destination: "10.0.0.10",
    sources: bucket(["10.1.0.0/24"]),
    members: [{ name: "web", addresses: ["10.0.0.10"] }],
    condition: { kind: "member", member: "web" },
    requirement: null,
  },
  outcomes: {
    before: { result: PASSES, passes: ["10.1.0.0/24"], fails: [], open: [], isolated: false },
    after: { result: FAILS, passes: [], fails: ["10.1.0.0/24"], open: [], isolated: false },
  },
  decided_change: { loss: bucket(["10.1.0.0/24"]), gain: bucket([]) },
  open_change: { loss: bucket(["10.1.0.0/24"]), gain: bucket([]) },
  open: { before: bucket([]), after: bucket([]) },
  passes: { before: bucket(["10.1.0.0/24"]), after: bucket([]) },
  fails: { before: bucket([]), after: bucket(["10.1.0.0/24"]) },
  members: [],
  evidence: {
    count: 1,
    truncated: false,
    items: [{ side: "after", member: "web", result: FAILS, steps: [step], missing: [] }],
  },
  missing_evidence: [],
  gaps: [],
  model_errors: [],
};

const RAW = JSON.stringify(catalogueEnvelope("impact_evaluate_service", BODY));

describe("parseImpactEvaluateService on tool version 3", () => {
  it("reads the buckets into the pane's payload under their own names", () => {
    const parsed = parseImpactEvaluateService(RAW)!;
    expect(parsed).not.toBeNull();
    expect(parsed.decided_change.loss.items).toEqual(["10.1.0.0/24"]);
    expect(parsed.open_change.loss.items).toEqual(["10.1.0.0/24"]);
    expect(parsed.open.after.count).toBe(0);
    expect(parsed.passes.before.items).toEqual(["10.1.0.0/24"]);
    expect(parsed.fails.after.items).toEqual(["10.1.0.0/24"]);
    expect(parsed).not.toHaveProperty("proven");
    expect(parsed).not.toHaveProperty("condition_holds");
  });

  it("reads outcomes and evidence items that carry result and no verdict or outcome", () => {
    const parsed = parseImpactEvaluateService(RAW)!;
    expect(parsed.outcomes?.after?.result?.answer).toBe("false");
    expect(parsed.outcomes?.after).not.toHaveProperty("verdict");
    expect(parsed.evidence.items[0].result.word).toBe("fails");
    expect(parsed.evidence.items[0]).not.toHaveProperty("outcome");
  });

  it("does not read a body without the tool version 3 bucket names", () => {
    const { decided_change, open_change, open, passes, fails, ...rest } = BODY;
    const older = { ...rest, proven: decided_change, possible: open_change, not_established: open, condition_holds: passes, condition_fails: fails };
    expect(parseImpactEvaluateService(JSON.stringify(catalogueEnvelope("impact_evaluate_service", older)))).toBeNull();
  });
});

describe("ServiceImpactPane on a tool version 3 result", () => {
  it("states the outcome and each decision from result", () => {
    render(<ServiceImpactPane result={parseImpactEvaluateService(RAW)} />);
    const region = screen.getByRole("region", { name: "Application condition pane" });
    expect(within(region).getByRole("heading", { name: "Answer: Fails" })).toBeInTheDocument();
    expect(within(region).getByText("web fails, dev:core1 filter: rule 10 of fw:LAN denies the flow")).toBeInTheDocument();
    const fails = within(region).getByText("Fails").closest("section")!;
    expect(within(fails).getByText("10.1.0.0/24")).toBeInTheDocument();
  });
});
