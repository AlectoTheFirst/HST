import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ResultGraph } from "../api/types";
import ApplicationInventory from "./ApplicationInventory";
import type { ApplicationRevision } from "./types";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));
vi.mock("../api/client", () => ({ api: apiMock, ApiError: class ApiError extends Error {} }));
vi.mock("../explore/GraphView", () => ({
  default: ({ graph }: { graph: ResultGraph }) => (
    <ul aria-label="Drawn nodes">
      {graph.nodes.map((n) => (
        <li key={n.id}>{n.id}</li>
      ))}
    </ul>
  ),
}));

const RECORD = { id: "shop", revision: 2, name: "Shop", digest: "d", definition: { services: [], groups: [], connections: [] } } as unknown as ApplicationRevision;

const GRAPH = {
  application: { id: "shop", revision: 2, digest: "d", name: "Shop" },
  snapshot: { snapshot: "4000", manifest_sha256: "m", estate: "test" },
  resolution_digest: "r",
  issues: [{ code: "inventory-not-found", path: "groups.servers.members.web", detail: "ip:1 was not found at snapshot 4000", severity: "error" }],
  nodes: [
    { id: "app:shop", labels: ["BusinessApplication"], properties: { name: "Shop" } },
    { id: "ip:10.0.0.5", labels: ["IpAddress", "Obj"], properties: { uid: "ip:10.0.0.5" } },
  ],
  relationships: [],
  truncated: false,
  library_query: { key: "application-inventory", params: { uids: "ip:10.0.0.5" } },
};

describe("ApplicationInventory", () => {
  it("reads nothing until a snapshot is picked, then draws the revision joined to its inventory at it", async () => {
    apiMock.mockImplementation((path: string) => {
      if (path === "/snapshots") return Promise.resolve({ snapshots: [{ id: "4000", ts_ms: 0, kind: "full", degraded: false }], truncated: false });
      if (path === "/business-applications/shop/graph?snapshot=4000&revision=2") return Promise.resolve(GRAPH);
      return Promise.reject(new Error(`unexpected ${path}`));
    });
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ApplicationInventory record={RECORD} />
      </QueryClientProvider>,
    );
    expect(apiMock).not.toHaveBeenCalledWith(expect.stringContaining("/graph"));
    const picker = await screen.findByRole("combobox");
    await screen.findByRole("option", { name: /full/ });
    await user.selectOptions(picker, "4000");
    expect(await screen.findByRole("list", { name: "Drawn nodes" })).toHaveTextContent("app:shopip:10.0.0.5");
    expect(screen.getByText("groups.servers.members.web: ip:1 was not found at snapshot 4000")).toBeInTheDocument();
    expect(screen.getByText("application-inventory")).toBeInTheDocument();
  });
});
