import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { PathResponse } from "../../api/types";
import type { Selection } from "../selection";
import TracePage from "../TracePage";
import { mockApi } from "../../test/fetchMock";
import { FIXTURE_PATH_ECMP, FIXTURE_PATH_SINGLE, FIXTURE_SNAPSHOTS } from "../../test/fixtures";

const rendered = vi.hoisted(() => ({ results: [] as unknown[] }));

vi.mock("./StrataView", () => ({
  StrataView: ({
    result,
    onSelect,
    onNavigate,
  }: {
    result: PathResponse;
    selection: Selection | null;
    onSelect: (selection: Selection) => void;
    onNavigate?: () => void;
  }) => {
    rendered.results.push(result);
    return (
    <div>
      <button type="button" onClick={() => onSelect({ type: "hop", data: result.hops[0] })}>
        stub select
      </button>
      <button type="button" onClick={() => onNavigate?.()}>
        stub orbit
      </button>
    </div>
    );
  },
}));

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

beforeEach(() => {
  rendered.results.length = 0;
  installStorage();
  mockApi({
    "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
    "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
    "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }),
  });
});

describe("TracePage <-> StrataView", () => {
  it("passes onNavigate through, and a navigation gesture collapses the blocks below", async () => {
    renderTracePage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "3D" }));
    await user.click(screen.getByRole("button", { name: /trace/i }));

    // A node click fills the Inspector and opens its block.
    await user.click(await screen.findByRole("button", { name: "stub select" }));
    expect(window.localStorage.getItem("hst.trace.inspector.open")).toBe("true");

    await user.click(screen.getByRole("button", { name: "stub orbit" }));
    expect(window.localStorage.getItem("hst.trace.inspector.open")).toBe("false");
    expect(window.localStorage.getItem("hst.trace.info.open")).toBe("false");
  });

  it("gives each interpretation pane the same result object on every render", async () => {
    const [a, b] = FIXTURE_PATH_ECMP.legs;
    const split: PathResponse = {
      ...FIXTURE_PATH_ECMP,
      legs: [
        { ...a, interpretation: { anchor: "vrf:a", src_ip: "10.0.0.1", display: "VRF A" } },
        { ...b, interpretation: { anchor: "vrf:b", src_ip: "10.0.0.1", display: "VRF B" } },
      ] as PathResponse["legs"],
    };
    mockApi({
      "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
      "GET /api/snapshots": () => ({ status: 200, body: FIXTURE_SNAPSHOTS }),
      "GET /api/path": () => ({ status: 200, body: split }),
    });
    renderTracePage();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "3D" }));
    await user.click(screen.getByRole("button", { name: /trace/i }));

    const select = await screen.findAllByRole("button", { name: "stub select" });
    expect(select).toHaveLength(2);
    const before = new Set(rendered.results);
    expect(before.size).toBe(2);

    await user.click(select[0]);
    await user.click(screen.getAllByRole("button", { name: "stub orbit" })[0]);
    expect(rendered.results.length).toBeGreaterThan(2);
    expect(rendered.results.every((result) => before.has(result))).toBe(true);
  });
});
