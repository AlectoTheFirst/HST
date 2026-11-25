import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { WorkspaceProvider, useWorkspace } from "./WorkspaceContext";
import { panes } from "./layout";
import { AnalysisSections } from "./AnalysisSections";
import { LISTED_VIEWS } from "./views";

function Probe() {
  const ws = useWorkspace();
  const focused = ws ? panes(ws.state.root).find((p) => p.id === ws.state.focus) : undefined;
  return (
    <>
      <AnalysisSections current={focused?.view ?? "trace"} />
      <div data-testid="pane-view">{focused?.view}</div>
    </>
  );
}

describe("AnalysisSections", () => {
  it("lists 9 views and opens Change simulation and Assessments as sections of Analysis", async () => {
    expect(LISTED_VIEWS).toHaveLength(9);
    expect(LISTED_VIEWS.map((v) => v.view)).not.toContain("changesim");
    const user = userEvent.setup();
    render(
      <WorkspaceProvider>
        <Probe />
      </WorkspaceProvider>,
    );
    const bar = screen.getByRole("navigation", { name: "Analysis tools" });
    expect(bar.textContent).toBe("AnalysisChange simulationAssessments");
    await user.click(screen.getByRole("button", { name: "Change simulation" }));
    expect(screen.getByTestId("pane-view")).toHaveTextContent("changesim");
    expect(screen.getByRole("button", { name: "Change simulation" })).toHaveAttribute("aria-current", "page");
    await user.click(screen.getByRole("button", { name: "Assessments" }));
    expect(screen.getByTestId("pane-view")).toHaveTextContent("assessments");
    await user.click(screen.getByRole("button", { name: "Analysis" }));
    expect(screen.getByTestId("pane-view")).toHaveTextContent("analysis");
  });
});
