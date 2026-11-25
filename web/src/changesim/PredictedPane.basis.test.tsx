/**
 * A flow whose comparison the API did not establish (`basis_uncertain`) is
 * never drawn as a changed or an unchanged result: the pane counts it apart,
 * states the reasons, and draws neither its rows nor its before-and-after line.
 */

import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { PredictedPane } from "./PredictedPane";
import { FIXTURE_SIMULATE_POLICY_CHANGE } from "../test/fixtures";
import {
  flowBasisReasons,
  flowNotEstablished,
  parseSimulatePolicyChange,
  resultsNotEstablished,
  type PredictedResult,
  type SimulatedFlow,
  type SimulatePolicyChangeResult,
} from "./assessImpact";

const BANNED_WORDS = /\b(reached|delivered|reachability|live|current|intended)\b/i;
const REASON = "a routing calculation that did not settle decides this flow";

const [FIRST, SECOND] = FIXTURE_SIMULATE_POLICY_CHANGE.flows;

function uncertain(flow: SimulatedFlow, extra: Partial<SimulatedFlow> = {}): SimulatedFlow {
  return {
    ...flow,
    basis_uncertain: true,
    basis_uncertain_reasons: [REASON],
    model_error: { kind: "flow-result-not-established", detail: REASON, subject: "a -> b" },
    ...extra,
  };
}

function policyWith(flows: SimulatedFlow[], extra: Partial<SimulatePolicyChangeResult> = {}) {
  return { ...FIXTURE_SIMULATE_POLICY_CHANGE, flows, ...extra };
}

function renderPane(policy: SimulatePolicyChangeResult) {
  const result: PredictedResult = { tool: "simulate_policy_change", policy };
  return render(<PredictedPane result={result} />);
}

function flowSection(text: RegExp): HTMLElement {
  const section = screen.getByText(text).closest("section");
  if (!section) throw new Error("no flow section");
  return section;
}

describe("the Predicted pane, a flow whose comparison is not established", () => {
  const policy = policyWith([uncertain(FIRST), SECOND], { results_changed: 0, results_not_established: 1 });

  it("counts it apart from the changed results", () => {
    renderPane(policy);
    const pane = screen.getByRole("region", { name: "Predicted pane" });
    expect(within(pane).getByText(/0 with a changed result/)).toBeInTheDocument();
    expect(within(pane).getByText(/1 with a comparison not established/)).toBeInTheDocument();
    expect(within(pane).getByText(/with the flow not established/)).toBeInTheDocument();
  });

  it("states the reasons and draws no rows and no before-and-after line for it", () => {
    renderPane(policy);
    const section = flowSection(/192\.168\.2\.35 to 10\.10\.10\.1\/32/);
    expect(within(section).getByText(`Comparison not established: ${REASON}`)).toBeInTheDocument();
    expect(within(section).getByText(/neither changed nor unchanged/)).toBeInTheDocument();
    expect(within(section).queryByRole("table")).not.toBeInTheDocument();
    expect(within(section).queryByText(/^before:/)).not.toBeInTheDocument();
    expect(within(section).queryByText(/result unchanged/)).not.toBeInTheDocument();
    expect(within(section).queryByText(/crosses none of the changed devices/)).not.toBeInTheDocument();
    expect(section.textContent).not.toMatch(BANNED_WORDS);
  });

  it("says so when the API stated no reason", () => {
    renderPane(policyWith([uncertain(FIRST, { basis_uncertain_reasons: undefined }), SECOND]));
    const section = flowSection(/192\.168\.2\.35 to 10\.10\.10\.1\/32/);
    expect(within(section).getByText("Comparison not established: no reason stated")).toBeInTheDocument();
  });

  it("keeps the rows of a flow whose comparison is established", () => {
    renderPane(policyWith([FIRST, SECOND]));
    const section = flowSection(/192\.168\.2\.35 to 10\.10\.10\.1\/32/);
    expect(within(section).getByRole("table")).toBeInTheDocument();
    expect(screen.queryByText(/not established/)).not.toBeInTheDocument();
  });

  it("states a flow that crosses none of the changed devices and one that is not established apart", () => {
    renderPane(policyWith([FIRST, uncertain(SECOND, { model_error: SECOND.model_error })]));
    const section = flowSection(/192\.168\.2\.10 to 192\.168\.2\.35/);
    expect(within(section).getByText(/crosses none of the changed devices/)).toBeInTheDocument();
    expect(within(section).getByText(`Comparison not established: ${REASON}`)).toBeInTheDocument();
  });

  it("shows the flow-result-not-established gap in the strip", () => {
    renderPane(
      policyWith([uncertain(FIRST), SECOND], {
        results_not_established: 1,
        model_errors: [
          ...FIXTURE_SIMULATE_POLICY_CHANGE.model_errors,
          { kind: "flow-result-not-established", detail: "1 of 2 flow(s) are not counted as changed or unchanged", subject: null },
        ],
      }),
    );
    const pane = screen.getByRole("region", { name: "Predicted pane" });
    expect(within(pane).getByText(/flow-result-not-established: 1 of 2 flow\(s\) are not counted/)).toBeInTheDocument();
  });
});

describe("the basis fields of a change simulation result", () => {
  it("are read from the payload", () => {
    const flows = [uncertain(FIRST), SECOND];
    const parsed = parseSimulatePolicyChange(JSON.stringify(policyWith(flows, { results_not_established: 1 })));
    expect(parsed).not.toBeNull();
    expect(flowNotEstablished(parsed!.flows[0])).toBe(true);
    expect(flowNotEstablished(parsed!.flows[1])).toBe(false);
    expect(flowBasisReasons(parsed!.flows[0])).toEqual([REASON]);
    expect(flowBasisReasons(parsed!.flows[1])).toEqual([]);
    expect(resultsNotEstablished(parsed!)).toBe(1);
  });

  it("count the flagged flows when the API states no count, and none without flags", () => {
    expect(resultsNotEstablished(policyWith([uncertain(FIRST), uncertain(SECOND)]))).toBe(2);
    expect(resultsNotEstablished(FIXTURE_SIMULATE_POLICY_CHANGE)).toBe(0);
  });

  it("take the API's count over the flags when it states one", () => {
    expect(resultsNotEstablished(policyWith([FIRST, SECOND], { results_not_established: 3 }))).toBe(3);
  });

  it("ignore reasons that are not text", () => {
    const flow = { ...FIRST, basis_uncertain: true, basis_uncertain_reasons: [REASON, 4, ""] } as unknown as SimulatedFlow;
    expect(flowBasisReasons(flow)).toEqual([REASON]);
  });
});
