import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { AnalysisResult } from "./AnalysisResult";

// The answers a stored run records, as the server writes them.
const P = {
  kind: "result",
  statement: "condition-holds",
  answer: "true",
  word: "passes",
  quantifier: "some",
  condition: "forward",
  missing: [],
};
const F = { ...P, answer: "false", word: "fails" };
const O = {
  ...P,
  answer: "open",
  word: "not decided",
  missing: [{ code: "not-decided", subject: null, detail: "the evaluation is open" }],
};

describe("flat analysis findings", () => {
  it("keeps a stable selected finding when result order changes", async () => {
    const first = { id: "first", candidates: ["rule-a"], result: P, reason: "First evidence" };
    const second = { id: "second", candidates: ["rule-b"], result: F, reason: "Second evidence" };
    const view = render(<AnalysisResult result={{ kind: "repair", findings: [first, second] }} />);
    await userEvent.click(screen.getByRole("button", { name: /Inspect finding 2/ }));
    expect(
      within(screen.getByRole("region", { name: "Finding evidence inspector" })).getByRole(
        "heading",
        { name: "rule-b" },
      ),
    ).toBeInTheDocument();
    view.rerender(<AnalysisResult result={{ kind: "repair", findings: [second, first] }} />);
    expect(
      within(screen.getByRole("region", { name: "Finding evidence inspector" })).getByRole(
        "heading",
        { name: "rule-b" },
      ),
    ).toBeInTheDocument();
  });

  it("moves through the flat list with arrow keys and returns from detail", async () => {
    render(
      <AnalysisResult
        result={{
          kind: "regression",
          findings: [
            { id: "a", candidates: ["A"], result: P },
            { id: "b", candidates: ["B"], result: O },
          ],
        }}
      />,
    );
    const first = screen.getByRole("button", { name: /Inspect finding 1/ });
    const second = screen.getByRole("button", { name: /Inspect finding 2/ });
    first.focus();
    await userEvent.keyboard("{ArrowDown}");
    expect(second).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(screen.getByRole("region", { name: "Finding evidence inspector" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Back to findings" }));
    expect(
      screen.queryByRole("region", { name: "Finding evidence inspector" }),
    ).not.toBeInTheDocument();
  });

  it("adapts verification into one readable comparison", async () => {
    render(
      <AnalysisResult
        result={{
          kind: "verify",
          state: "deviation",
          configuration_realization: "partial",
          protected_comparison: { predicted: { checkout: P }, observed: { checkout: F } },
          observation_coverage: { qualifies: false, missing: ["new policy observation"] },
        }}
      />,
    );
    expect(
      screen.getByRole("heading", { name: "Prediction differs from collected model" }),
    ).toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: "Post-deployment comparison: Deviation" }),
    );
    expect(screen.getByText("new policy observation")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Predicted requirements" })).toBeInTheDocument();
  });

  it("loads unfamiliar large evidence only when the exact record is opened", async () => {
    const entries = Array.from({ length: 130 }, (_, index) => `evidence-${index}`);
    render(
      <AnalysisResult result={{ kind: "evaluate", result: P, unfamiliar_evidence: entries }} />,
    );
    expect(screen.queryByText("evidence-0")).not.toBeInTheDocument();
    await userEvent.click(screen.getByText("Exact analysis record"));
    expect(screen.getByText("evidence-0")).toBeInTheDocument();
    expect(screen.getByText("30 more entries in the exact export")).toBeInTheDocument();
  });
});

describe("asking HST AI about a finding", () => {
  it("sends the reference the server resolves: the finding's own id, or its position", async () => {
    const asked: string[] = [];
    const selected: (string | undefined)[] = [];
    render(
      <AnalysisResult
        result={{
          kind: "repair",
          findings: [
            { id: "first", candidates: ["rule-a"], result: P },
            { candidates: ["rule-b"], result: F },
          ],
        }}
        onAskAi={(finding) => asked.push(finding)}
        onSelectFinding={(_, finding) => selected.push(finding)}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: /Inspect finding 2/ }));
    let inspector = screen.getByRole("region", { name: "Finding evidence inspector" });
    expect(within(inspector).getByText("Finding ID: finding:@1")).toBeInTheDocument();
    await userEvent.click(
      within(inspector).getByRole("button", { name: "Ask HST AI about this finding" }),
    );

    await userEvent.click(screen.getByRole("button", { name: /Inspect finding 1/ }));
    inspector = screen.getByRole("region", { name: "Finding evidence inspector" });
    expect(within(inspector).getByText("Finding ID: finding:first")).toBeInTheDocument();
    await userEvent.click(
      within(inspector).getByRole("button", { name: "Ask HST AI about this finding" }),
    );

    expect(asked).toEqual(["finding:@1", "finding:first"]);
    expect(selected).toEqual(["finding:@1", "finding:first"]);
  });

  it("names a gap by its position and a failure domain by its name", async () => {
    const asked: string[] = [];
    render(
      <AnalysisResult
        result={{
          kind: "resilience",
          expanded_domains: { "rack-7": { evidence_complete: true } },
          gaps: [{ code: "rib-missing", detail: "No routing table" }],
        }}
        onAskAi={(finding) => asked.push(finding)}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: "rack-7: Evidence validated" }));
    await userEvent.click(screen.getByRole("button", { name: "Ask HST AI about this finding" }));
    await userEvent.click(screen.getByRole("button", { name: "rib-missing: Evidence missing" }));
    await userEvent.click(screen.getByRole("button", { name: "Ask HST AI about this finding" }));

    expect(asked).toEqual(["domain:rack-7", "gap:@0"]);
  });

  it("offers no chat when no drawer can open one", async () => {
    render(
      <AnalysisResult
        result={{ kind: "repair", findings: [{ id: "a", candidates: ["A"], result: P }] }}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: /Inspect finding 1/ }));

    expect(screen.getByRole("region", { name: "Finding evidence inspector" })).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Ask HST AI about this finding" }),
    ).not.toBeInTheDocument();
  });
});
