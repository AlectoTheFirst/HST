import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import EquinixPage from "./EquinixPage";
import { METRO, METROS } from "./fixture";

const { apiMock, openQuery } = vi.hoisted(() => ({ apiMock: vi.fn(), openQuery: vi.fn() }));
vi.mock("../api/client", () => ({ api: apiMock, ApiError: class extends Error {} }));
vi.mock("../workspace/WorkspaceContext", () => ({ useWorkspace: () => ({ openQuery }) }));

async function pickWith(metro: unknown) {
  apiMock.mockImplementation((path: string) => Promise.resolve(path === "/equinix/metros" ? METROS : metro));
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <EquinixPage />
    </QueryClientProvider>,
  );
  await screen.findByText("No metro picked");
  await userEvent.setup().click(screen.getByRole("radio", { name: "XX" }));
  await screen.findByRole("group", { name: "Equinix Fabric" });
}

beforeEach(() => {
  apiMock.mockReset();
  openQuery.mockReset();
});

describe("EquinixPage circuits that are not active", () => {
  it("counts them in the toolbar", async () => {
    await pickWith({ ...METRO, other_circuits: { PENDING: 2 } });
    expect(screen.getByText(", 2 not active", { exact: false })).toBeTruthy();
  });

  it("says nothing without the field", async () => {
    await pickWith(METRO);
    expect(screen.queryByText("not active", { exact: false })).toBeNull();
  });
});
