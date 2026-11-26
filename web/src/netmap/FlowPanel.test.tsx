import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import type { FlowSelection, FlowsResponse } from "../applications/flows";
import FlowPanel, { EVALUATE_CAP, flowSelectionOf, useApplicationFlows } from "./FlowPanel";
import { connection, path, response } from "./flowFixture";

const { apiMock, user } = vi.hoisted(() => ({
  apiMock: vi.fn(),
  user: { current: { permissions: ["graph.read"] as string[] } },
}));
vi.mock("../api/client", () => ({ api: apiMock, ApiError: class ApiError extends Error {} }));
vi.mock("../auth", () => ({ useCurrentUser: () => user.current }));

const CATALOG = {
  applications: [
    {
      id: "shop",
      revision: 3,
      name: "Shop",
      digest: "d",
      definition: { services: [{ id: "front", name: "Front", connection_ids: ["web", "admin"], component_roles: [] }], connections: [], groups: [] },
    },
  ],
};

const failing = path({
  devices: ["a", "b"],
  answer: "fails",
  stop_device: "b",
  steps: [
    { device_uid: "a", stage: "entry", kind: "attach", detail: "", unknown: [], phase: "forward", gate: false },
    { device_uid: "b", stage: "filter", kind: "deny", detail: "rule 10", unknown: [], phase: "forward", gate: true },
  ],
});

function flows(over: Partial<FlowsResponse> = {}): FlowsResponse {
  return response(
    [
      connection({ id: "web", name: "Web", answer: "fails", paths: [failing], counts: { passes: 0, fails: 1, open: 0 }, more_paths: 2 }),
      connection({ id: "admin", name: "Admin", state: "not-evaluated" }),
      connection({ id: "backup", name: "Backup", service_id: null, state: "unresolved", readiness: "unresolved", issues: [{ code: "destination-empty", path: "connections.backup.destination", detail: "destination group resolved to no addresses" }] }),
    ],
    over,
  );
}

function Harness({ initial }: { initial: FlowSelection | null }) {
  const [selection, setSelection] = useState(initial);
  const data = useApplicationFlows(selection, 7);
  return (
    <>
      <FlowPanel snapshot={7} selection={selection} onSelection={setSelection} flows={data} nameOf={(id) => `dev-${id}`} drawn={new Set(["a", "b"])} note="" onClose={() => {}} />
      <output aria-label="selection">{JSON.stringify(selection)}</output>
    </>
  );
}

function renderPanel(initial: FlowSelection | null, body: FlowsResponse = flows()) {
  apiMock.mockImplementation((p: string) => {
    if (p === "/business-applications") return Promise.resolve(CATALOG);
    if (p === "/business-applications/shop/flows?snapshot=7") return Promise.resolve(body);
    return Promise.reject(new Error(`unexpected ${p}`));
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Harness initial={initial} />
    </QueryClientProvider>,
  );
}

const selection = () => JSON.parse(screen.getByLabelText("selection").textContent ?? "null");

beforeEach(() => {
  apiMock.mockReset();
  user.current = { permissions: ["graph.read"] };
});

describe("FlowPanel", () => {
  it("toggles nothing when an application is picked, then toggles by connection and by service", async () => {
    const u = userEvent.setup();
    renderPanel(null);
    await u.selectOptions(await screen.findByLabelText("Application"), "shop");
    expect(selection()).toEqual({ application: "shop", connections: [] });
    await u.click(await screen.findByRole("checkbox", { name: "Backup" }));
    expect(selection().connections).toEqual(["backup"]);
    await u.click(screen.getByRole("checkbox", { name: "Service Front" }));
    expect(selection().connections).toEqual(["web", "admin", "backup"]);
    await u.click(screen.getByRole("checkbox", { name: "Service Front" }));
    expect(selection().connections).toEqual(["backup"]);
    expect(apiMock).not.toHaveBeenCalledWith(expect.stringContaining("/analysis-sessions"), expect.anything());
  });

  it("states each toggled connection in words and lists the hops of a path with its stop", async () => {
    const u = userEvent.setup();
    renderPanel({ application: "shop", connections: ["web", "backup"] });
    expect(await screen.findByText("Fails")).toBeInTheDocument();
    expect(screen.getByText("Unresolved")).toBeInTheDocument();
    expect(screen.getByText(/3 paths, 1 failing, first 1 listed/)).toBeInTheDocument();
    expect(screen.getByText("connections.backup.destination: destination group resolved to no addresses")).toBeInTheDocument();
    await u.click(screen.getByText(/Path 1: fails, 1 part to db/));
    const hops = screen.getByRole("list", { name: "Hops of path 1 of Web" });
    expect(within(hops).getByText(/dev-b, stops here/)).toBeInTheDocument();
    expect(within(hops).getByText("filter deny: rule 10")).toBeInTheDocument();
  });

  it("shows the banner when an evaluation is of another run", async () => {
    const body = flows();
    body.connections[0].evaluation = { session_id: "s", run_id: "r", execution: "completed", snapshot: "6", revision: 3, finished_at: null, stale: { snapshot: true, revision: false } };
    renderPanel({ application: "shop", connections: ["web"] }, body);
    expect(await screen.findByRole("note")).toHaveTextContent("Evaluation of run 6, not run 7");
  });

  it("offers the evaluation of a connection with none at the run only to a user who may write", async () => {
    renderPanel({ application: "shop", connections: ["admin"] });
    expect(await screen.findByText("Admin")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Evaluate/ })).not.toBeInTheDocument();
  });

  it("evaluates through the Coverage resolution and the Analysis session", async () => {
    user.current = { permissions: ["graph.read", "changes.write"] };
    const u = userEvent.setup();
    renderPanel({ application: "shop", connections: ["admin"] });
    const calls: string[] = [];
    apiMock.mockImplementation((p: string) => {
      calls.push(p);
      if (p === "/business-applications") return Promise.resolve(CATALOG);
      if (p === "/business-applications/shop/flows?snapshot=7") return Promise.resolve(flows());
      if (p === "/business-applications/shop/resolve")
        return Promise.resolve({ snapshot: { snapshot: "7" }, digest: "r", connections: [{ id: "admin", service_id: "front", readiness: "ready", request: { name: "Admin" }, issues: [] }] });
      if (p === "/analysis-sessions") return Promise.resolve({ id: "s1", revision: 1, input_digest: "i" });
      if (p === "/analysis-sessions/s1/runs") return Promise.resolve({});
      return Promise.reject(new Error(`unexpected ${p}`));
    });
    await u.click(await screen.findByRole("button", { name: "Evaluate 1 connection at run 7" }));
    expect(await screen.findByText("Evaluation of 1 connection queued at run 7")).toBeInTheDocument();
    expect(calls).toEqual(expect.arrayContaining(["/business-applications/shop/resolve", "/analysis-sessions", "/analysis-sessions/s1/runs"]));
    const resolveCall = apiMock.mock.calls.find(([p]) => p === "/business-applications/shop/resolve")!;
    expect(resolveCall[1]).toEqual({ method: "POST", body: { snapshot: "7", revision: 3, connection_ids: ["admin"] } });
    await waitFor(() => expect(calls.filter((p) => p.includes("/flows")).length).toBeGreaterThan(0));
    expect(EVALUATE_CAP).toBe(20);
  });

  it("says which connections engine admission left out", async () => {
    user.current = { permissions: ["graph.read", "changes.write"] };
    const u = userEvent.setup();
    renderPanel({ application: "shop", connections: ["admin"] });
    apiMock.mockImplementation((p: string) => {
      if (p === "/business-applications") return Promise.resolve(CATALOG);
      if (p === "/business-applications/shop/flows?snapshot=7") return Promise.resolve(flows());
      if (p === "/business-applications/shop/resolve")
        return Promise.resolve({ snapshot: { snapshot: "7" }, digest: "r", connections: [{ id: "admin", service_id: "front", readiness: "ready", request: { name: "Admin" }, issues: [] }] });
      if (p === "/analysis-sessions") return Promise.resolve({ id: "s1", revision: 1, input_digest: "i" });
      if (p === "/analysis-sessions/s1/runs")
        return Promise.resolve({ results: { admission: { omitted: ["admin"], limit: 8, reason: "at most 8 unfinished analyses per actor" } } });
      return Promise.reject(new Error(`unexpected ${p}`));
    });
    await u.click(await screen.findByRole("button", { name: "Evaluate 1 connection at run 7" }));
    expect(await screen.findByText(/Evaluation of 0 connections queued at run 7, not submitted: .+ \(at most 8 unfinished analyses per actor\)$/)).toBeInTheDocument();
  });
});

describe("flowSelectionOf", () => {
  it("reads a saved selection and drops anything else", () => {
    expect(flowSelectionOf({ application: "shop", connections: ["web", 3] })).toEqual({ application: "shop", connections: ["web"] });
    expect(flowSelectionOf({ application: "" })).toBeNull();
    expect(flowSelectionOf(undefined)).toBeNull();
  });
});

describe("FlowPanel: an evaluation of an earlier application revision", () => {
  it("marks the evaluation with its revision and keeps its result", async () => {
    const body = flows();
    body.connections[0].evaluation = { session_id: "s", run_id: "r", execution: "completed", snapshot: "7", revision: 2, finished_at: null, stale: { snapshot: false, revision: true } };
    renderPanel({ application: "shop", connections: ["web"] }, body);
    expect(await screen.findByRole("note")).toHaveTextContent("Evaluation of revision 2, not revision 3");
    expect(screen.getByRole("note")).not.toHaveTextContent("run");
    expect(screen.getByText("Fails")).toBeInTheDocument();
  });
});
