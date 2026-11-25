import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CollectionProgressView } from "./CollectionProgress";
import type { CollectionProgress } from "../api/types";

function sample(overrides: Partial<CollectionProgress> = {}): CollectionProgress {
  return {
    source: "vco", state: "collecting", phase: "Collecting detailed paths",
    completed: 200, total: 1000, phase_eta_s: 120, updated_at_ms: Date.now(),
    enterprise: "Acme", enterprise_index: 2, enterprise_total: 3,
    cache_hits: 100, reverse_queries_saved: 300, ...overrides,
  };
}

describe("collection progress", () => {
  it("shows enterprise, phase progress, ETA, cache savings and avoided reverse requests", () => {
    render(<CollectionProgressView progress={sample()} />);
    expect(screen.getByText(/enterprise 2 of 3/)).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("value", "200");
    expect(screen.getByRole("progressbar")).toHaveAttribute("max", "1000");
    expect(screen.getByText("About 2 min remaining in this phase")).toBeInTheDocument();
    expect(screen.getByText("100 cached responses reused")).toBeInTheDocument();
    expect(screen.getByText("300 reverse-direction requests avoided")).toBeInTheDocument();
  });
  it("withholds an ETA until samples exist and pauses old estimates", () => {
    const view = render(<CollectionProgressView progress={sample({ phase_eta_s: null })} />);
    expect(screen.getByText(/Estimating remaining time/)).toBeInTheDocument();
    view.rerender(<CollectionProgressView progress={sample({ updated_at_ms: Date.now() - 60_000 })} />);
    expect(screen.getByText("Estimate paused")).toBeInTheDocument();
    expect(screen.queryByText(/About 2 min/)).not.toBeInTheDocument();
  });
  it("does not call a completed fetch a published run", () => {
    render(<CollectionProgressView progress={sample({ state: "collected" })} />);
    expect(screen.getByText("Preparing snapshot")).toBeInTheDocument();
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
  });
});
