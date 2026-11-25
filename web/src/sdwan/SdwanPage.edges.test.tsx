import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import SdwanPage, { edgeLabels } from "./SdwanPage";
import { TOPOLOGY } from "./fixture";

const { apiMock } = vi.hoisted(() => ({ apiMock: vi.fn() }));
vi.mock("../api/client", () => ({
  api: apiMock,
  ApiError: class extends Error {},
}));

const edge = (uid: string, name: string, site: string | null = null) => ({
  uid,
  name,
  role: null,
  location: null,
  country: null,
  site,
});

function mountWith(edges: ReturnType<typeof edge>[]) {
  apiMock.mockImplementation((path: string) =>
    Promise.resolve(path === "/sdwan/edges" ? { edges } : TOPOLOGY),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SdwanPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => apiMock.mockReset());

describe("SdwanPage edge list", () => {
  it("gives two edges with one name two labels", () => {
    const labels = edgeLabels([
      edge("a", "BRANCH-01", "FR2"),
      edge("b", "BRANCH-01", "PA3"),
      edge("c", "BRANCH-02"),
    ]);
    expect(labels.get("a")).toBe("BRANCH-01, FR2");
    expect(labels.get("b")).toBe("BRANCH-01, PA3");
    expect(labels.get("c")).toBe("BRANCH-02");
    const same = edgeLabels([edge("a", "BRANCH-01"), edge("b", "BRANCH-01")]);
    expect(new Set(same.values()).size).toBe(2);
  });

  it("states that the run has no edge", async () => {
    mountWith([]);
    expect(
      await screen.findByText("No SD-WAN edge"),
    ).toBeTruthy();
  });

  it("counts one edge in the singular", async () => {
    mountWith([edge("a", "BRANCH-01")]);
    expect(
      await screen.findByText("1 edge"),
    ).toBeTruthy();
  });
});
