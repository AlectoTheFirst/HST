import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AnalysisResult } from "./AnalysisResult";

// The answers a stored run records, as the server writes them.
const P = { kind: "result", statement: "condition-holds", answer: "true", word: "passes", quantifier: "some", condition: "forward", missing: [] };
const F = { ...P, answer: "false", word: "fails" };

describe("analysis result regression coverage", () => {
  it("keeps findings, gaps and failure domains independently accessible", () => {
    render(<AnalysisResult result={{
      kind: "resilience",
      findings: [{ id: "scenario", candidates: ["wan-a"], result: F, reason: "Checkout loses its only path" }],
      gaps: [{ id: "gap", code: "provider-evidence-missing", detail: "Provider observation expired" }],
      expanded_domains: { conduit: { evidence_complete: false, effects: [] } },
    }} />);

    expect(screen.getByRole("button", { name: /wan-a.*Checkout loses its only path.*Fails/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "conduit: Evidence incomplete" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "provider-evidence-missing: Evidence missing" })).toBeInTheDocument();
  });

  it("keeps arrow-key focus inside the result pane that received the key", async () => {
    render(<>
      <AnalysisResult result={{ kind: "repair", findings: [{ id: "left-a", candidates: ["left-a"], result: P }, { id: "left-b", candidates: ["left-b"], result: P }] }} />
      <AnalysisResult result={{ kind: "repair", findings: [{ id: "right-a", candidates: ["right-a"], result: P }, { id: "right-b", candidates: ["right-b"], result: P }] }} />
    </>);
    const panes = screen.getAllByLabelText("Findings");
    const leftSecond = within(panes[0]).getByRole("button", { name: /left-b/ });
    const rightFirst = within(panes[1]).getByRole("button", { name: /right-a/ });
    const rightSecond = within(panes[1]).getByRole("button", { name: /right-b/ });

    rightFirst.focus();
    await userEvent.keyboard("{ArrowDown}");
    expect(rightSecond).toHaveFocus();
    expect(leftSecond).not.toHaveFocus();
  });
});
