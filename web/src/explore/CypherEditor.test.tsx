import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { CypherEditor } from "./CypherEditor";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_VIEWER, ME_OPERATOR } from "../test/fixtures";
import type { Me } from "../api/types";

function renderEditor(me: Me, onRun = vi.fn()) {
  mockApi({ "GET /api/me": () => ({ status: 200, body: me }) });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <CypherEditor onRun={onRun} pending={false} />
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("CypherEditor operator gating", () => {
  it("renders nothing for a viewer", async () => {
    renderEditor(ME_VIEWER);
    await waitFor(() => expect(screen.queryByRole("button", { name: /run/i })).not.toBeInTheDocument());
    expect(screen.queryByRole("textbox", { name: /cypher query/i })).not.toBeInTheDocument();
  });

  it("seeds a query pinned to the run, not to a label", async () => {
    renderEditor(ME_OPERATOR);

    const textarea = await screen.findByRole<HTMLTextAreaElement>("textbox", {
      name: /cypher query/i,
    });
    expect(textarea.value).toContain("coalesce(d.collection_ts, $snap) = $snap");
    expect(textarea.value).not.toContain(":Latest");
  });

  it("renders the editor for an operator, and runs the typed query", async () => {
    const onRun = vi.fn();
    const user = userEvent.setup();
    renderEditor(ME_OPERATOR, onRun);

    const textarea = await screen.findByRole("textbox", { name: /cypher query/i });
    await user.clear(textarea);
    await user.type(textarea, "MATCH (n) RETURN n");
    await user.click(screen.getByRole("button", { name: /run/i }));

    expect(onRun).toHaveBeenCalledWith("MATCH (n) RETURN n");
  });
});
