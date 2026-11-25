import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import DiffPage from "./DiffPage";
import { mockApi } from "../test/fetchMock";
import { FIXTURE_DIFF, FIXTURE_SNAPSHOTS } from "../test/fixtures";

function renderDiffPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <DiffPage />
    </QueryClientProvider>,
  );
}

describe("DiffPage", () => {
  it("defaults A/B to the two newest snapshots and renders the counts and tables from the diff", async () => {
    mockApi({
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/diff": () => ({ status: 200, body: FIXTURE_DIFF }),
    });
    renderDiffPage();

    expect(await screen.findByText(`${FIXTURE_DIFF.counts.nodes.added} nodes added`)).toBeInTheDocument();
    expect(screen.getByText(`${FIXTURE_DIFF.counts.nodes.removed} nodes removed`)).toBeInTheDocument();
    expect(screen.getByText(`${FIXTURE_DIFF.counts.nodes.changed} nodes changed`)).toBeInTheDocument();
    expect(screen.getByText(`${FIXTURE_DIFF.counts.rels.added} rels added`)).toBeInTheDocument();
    expect(screen.getByText(`${FIXTURE_DIFF.counts.rels.removed} rels removed`)).toBeInTheDocument();
    expect(screen.getByText(`${FIXTURE_DIFF.counts.rels.changed} rels changed`)).toBeInTheDocument();

    const added = screen.getByText("Added").closest("section") as HTMLElement;
    expect(within(added).getByText("dev:x")).toBeInTheDocument();

    const changed = screen.getByText("Changed").closest("section") as HTMLElement;
    expect(within(changed).getByText("dev:y")).toBeInTheDocument();
    expect(within(changed).getByText("router to firewall")).toBeInTheDocument();

    // Removed rel
    const removed = screen.getByText("Removed").closest("section") as HTMLElement;
    expect(within(removed).getByText("ON")).toBeInTheDocument();
    expect(within(removed).getByText("if:a")).toBeInTheDocument();

    expect(screen.queryByText(/no differences/)).not.toBeInTheDocument();
    expect(screen.queryByText(/first 500 entries/)).not.toBeInTheDocument();
  });

  it("shows the truncation warning when the diff is truncated", async () => {
    mockApi({
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/diff": () => ({ status: 200, body: { ...FIXTURE_DIFF, truncated: true } }),
    });
    renderDiffPage();

    expect(await screen.findByText(/first 500 entries/)).toBeInTheDocument();
  });
});
