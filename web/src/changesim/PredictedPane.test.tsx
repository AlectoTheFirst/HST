/** The tests cover the routing-consequence section of the Predicted pane. */

import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { PredictedPane } from "./PredictedPane";
import { FIXTURE_SIMULATE_POLICY_CHANGE } from "../test/fixtures";
import type { PredictedResult, SimulatePolicyChangeResult } from "./assessImpact";

const BANNED_WORDS = /\b(reached|delivered|reachability|live|current|intended)\b/i;

function renderPane(policy: SimulatePolicyChangeResult) {
  const result: PredictedResult = { tool: "simulate_policy_change", policy };
  return render(<PredictedPane result={result} />);
}

describe("PredictedPane: a denied address that names a BGP session", () => {
  it("draws the session as a dependency, not a shutdown prediction", () => {
    renderPane(FIXTURE_SIMULATE_POLICY_CHANGE);
    const predicted = screen.getByRole("region", { name: "Predicted pane" });

    expect(within(predicted).getByText("BGP sessions to a denied address")).toBeInTheDocument();
    expect(
      within(predicted).getByText("192.168.2.35 in vrf:dev:x:vyos:core1:default"),
    ).toBeInTheDocument();
    expect(
      within(predicted).getByText(/needs a context-scoped control-plane evaluation/),
    ).toBeInTheDocument();
    // no section claims a BGP prediction was computed from this dependency
    expect(within(predicted).queryByText(/prefixes withdrawn/)).not.toBeInTheDocument();
    expect(within(predicted).queryByText(/prefixes added/)).not.toBeInTheDocument();
    expect(predicted.textContent).not.toMatch(BANNED_WORDS);
  });

  it("hides the dependency section and every prediction list when nothing is named", () => {
    const policy: SimulatePolicyChangeResult = {
      ...FIXTURE_SIMULATE_POLICY_CHANGE,
      routing_consequence: {
        ...FIXTURE_SIMULATE_POLICY_CHANGE.routing_consequence!,
        bgp_sessions_to_a_denied_address: [],
        bgp_sessions_to_a_denied_address_note: undefined,
      },
    };
    renderPane(policy);
    const predicted = screen.getByRole("region", { name: "Predicted pane" });

    expect(
      within(predicted).queryByText("BGP sessions to a denied address"),
    ).not.toBeInTheDocument();
    expect(within(predicted).queryByText(/prefixes withdrawn/)).not.toBeInTheDocument();
    expect(within(predicted).queryByText(/prefixes added/)).not.toBeInTheDocument();
    expect(within(predicted).queryByText(/best path changed/)).not.toBeInTheDocument();
  });
});

describe("PredictedPane: a group whose MTU verdict moved", () => {
  it("draws the before/after MTU line, with the ceiling only where the engine has one", () => {
    const [firstFlow, ...restFlows] = FIXTURE_SIMULATE_POLICY_CHANGE.flows;
    const [firstGroup, ...restGroups] = firstFlow.paths!.groups;
    const policy: SimulatePolicyChangeResult = {
      ...FIXTURE_SIMULATE_POLICY_CHANGE,
      flows: [
        {
          ...firstFlow,
          paths: {
            ...firstFlow.paths!,
            groups: [
              {
                ...firstGroup,
                mtu_before: {
                  outcome: "fail",
                  known_ceiling_bytes: 1492,
                  bottleneck: ["pppoe0"],
                  uncovered: [],
                },
                mtu_after: {
                  outcome: "fragmentation_required",
                  known_ceiling_bytes: null,
                  bottleneck: ["pppoe0"],
                  uncovered: [],
                },
              },
              ...restGroups,
            ],
          },
        },
        ...restFlows,
      ],
    };
    renderPane(policy);
    const predicted = screen.getByRole("region", { name: "Predicted pane" });

    expect(
      within(predicted).getByText("MTU fail at pppoe0 (1492 B) to MTU fragmentation required at pppoe0"),
    ).toBeInTheDocument();
    expect(predicted.textContent).not.toMatch(BANNED_WORDS);
  });

  it("draws no MTU line for a flow that never carried an mtu request", () => {
    renderPane(FIXTURE_SIMULATE_POLICY_CHANGE);
    const predicted = screen.getByRole("region", { name: "Predicted pane" });

    expect(within(predicted).queryByText(/^MTU /)).not.toBeInTheDocument();
  });
});
