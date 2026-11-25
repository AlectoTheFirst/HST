import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import TracePage from "../TracePage";
import { mockApi } from "../../test/fetchMock";
import { FIXTURE_PATH_SINGLE, FIXTURE_SNAPSHOTS } from "../../test/fixtures";

/**
 * This suite's jsdom runs on an opaque origin, where `window.localStorage`
 * is undefined.
 */
function installStorage(): void {
  const data = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
      clear: () => data.clear(),
    },
  });
}

function renderTracePage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <TracePage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function trace() {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /trace/i }));
  return user;
}

beforeEach(() => {
  installStorage();
  mockApi({
    "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
    "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }),
  });
});

describe("TracePage: Graph/Strata view toggle", () => {
  it("renders the toggle, defaulting to Graph", async () => {
    renderTracePage();
    const graphBtn = screen.getByRole("button", { name: "Graph" });
    const strataBtn = screen.getByRole("button", { name: "3D" });
    expect(graphBtn).toHaveAttribute("aria-pressed", "true");
    expect(strataBtn).toHaveAttribute("aria-pressed", "false");

    await trace();
    // the Graph renders its own <svg role="group" aria-label="Path graph">
    expect(await screen.findByRole("group", { name: "Path graph" })).toBeInTheDocument();
  });

  it("switching to Strata mounts the lazy view, which shows a message without WebGL", async () => {
    renderTracePage();
    await trace();
    await screen.findByRole("group", { name: "Path graph" });

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "3D" }));

    await waitFor(() => expect(screen.getByText("No WebGL context")).toBeInTheDocument());
    expect(screen.queryByRole("group", { name: "Path graph" })).not.toBeInTheDocument();
  });

  it("persists the choice in localStorage across a remount", async () => {
    const { unmount } = renderTracePage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "3D" }));
    expect(screen.getByRole("button", { name: "3D" })).toHaveAttribute("aria-pressed", "true");
    expect(window.localStorage.getItem("hst.trace.view")).toBe('"strata"');
    unmount();

    renderTracePage();
    expect(screen.getByRole("button", { name: "3D" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Graph" })).toHaveAttribute("aria-pressed", "false");
  });
});
