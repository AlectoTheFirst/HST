import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import EquinixPage from "./EquinixPage";
import { METROS } from "./fixture";
import { ApiError } from "../api/client";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));
// the real client module, with only `api` replaced: ApiError keeps its status
vi.mock("../api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/client")>()),
  api: apiMock,
}));
vi.mock("../workspace/WorkspaceContext", () => ({ useWorkspace: () => ({ openQuery: vi.fn() }) }));

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <EquinixPage />
    </QueryClientProvider>,
  );
}

async function pickWith(metroError: Error) {
  apiMock.mockImplementation((path: string) =>
    path === "/equinix/metros"
      ? Promise.resolve(METROS)
      : String(path ?? "").startsWith("/equinix/metro?")
        ? Promise.reject(metroError)
        : Promise.resolve({}),
  );
  const user = userEvent.setup();
  mount();
  await screen.findByText("No metro picked");
  await user.click(screen.getByRole("radio", { name: "XX" }));
}

beforeEach(() => apiMock.mockReset());

describe("EquinixPage errors", () => {
  it("states a metro that is not in the pinned run", async () => {
    await pickWith(new ApiError(404, "not found"));
    expect(await screen.findByText("Metro not in the pinned run")).toBeInTheDocument();
  });

  it("states a metro read that failed", async () => {
    await pickWith(new ApiError(500, "server error"));
    expect(await screen.findByText(/^Metro not loaded:/)).toBeInTheDocument();
  });

  it("states a metro list read that failed", async () => {
    apiMock.mockImplementation((path: string) =>
      path === "/equinix/metros" ? Promise.reject(new ApiError(500, "server error")) : Promise.resolve({}),
    );
    mount();
    expect(await screen.findByText(/^Metro list not loaded:/)).toBeInTheDocument();
  });
});
