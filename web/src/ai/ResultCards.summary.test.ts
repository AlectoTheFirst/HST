import { describe, expect, it } from "vitest";
import { FIXTURE_SIMULATE_POLICY_CHANGE } from "../test/fixtures";
import { simulationSummary } from "./ResultCards";

describe("the summary line of a change simulation card", () => {
  it("names no flows that are not established when the API counts none", () => {
    const line = simulationSummary(FIXTURE_SIMULATE_POLICY_CHANGE);
    expect(line).toContain("1 with a changed result");
    expect(line).not.toContain("not established");
  });

  it("counts the flows whose comparison is not established apart from the changed ones", () => {
    const line = simulationSummary({ ...FIXTURE_SIMULATE_POLICY_CHANGE, results_changed: 0, results_not_established: 2 });
    expect(line).toContain("0 with a changed result");
    expect(line).toContain("2 with a comparison not established");
  });

  it("counts them from the flags of the flows when the API states no count", () => {
    const [first, ...rest] = FIXTURE_SIMULATE_POLICY_CHANGE.flows;
    const line = simulationSummary({
      ...FIXTURE_SIMULATE_POLICY_CHANGE,
      flows: [{ ...first, basis_uncertain: true }, ...rest],
    });
    expect(line).toContain("1 with a comparison not established");
  });
});
