import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { FlowConnection, FlowsResponse, ShownState } from "../../applications/flows";
import { conditionResult } from "../../netmap/flowFixture";
import type { ApplicationRevision } from "../../applications/types";
import HstMapPage, { type RendererFactory } from "../HstMapPage";
import { createNullRenderer, type NullRenderer } from "../render/null";
import { FakeSource, history } from "../test/runs";

function nullFactory(): { factory: RendererFactory; get: () => NullRenderer } {
  let r: NullRenderer | null = null;
  return { factory: async () => (r = createNullRenderer()), get: () => r! };
}

const APP = {
  id: "shop",
  revision: 3,
  name: "Shop",
  digest: "d",
  created_by: null,
  created_at: "2026-01-01T00:00:00Z",
  definition: {
    schema_version: 1,
    kind: "BusinessApplication",
    id: "shop",
    name: "Shop",
    state: "ready",
    groups: [],
    connections: [],
    services: [{ id: "front", name: "Front", connection_ids: ["web", "api"], component_roles: [] }],
  },
} as unknown as ApplicationRevision;

function conn(id: string, state: ShownState, extra: Partial<FlowConnection> = {}): FlowConnection {
  return {
    id,
    name: id.toUpperCase(),
    result: state === "unresolved" || state === "not-evaluated" ? null : conditionResult(state),
    service_id: "front",
    source: "clients",
    destination: "servers",
    protocol: "tcp",
    destination_ports: [443],
    success: "forward",
    readiness: "ready",
    state: state === "unresolved" || state === "not-evaluated" ? state : "evaluated",
    issues: [],
    endpoints: { source: [{ member: "a", inventory_uid: null, devices: ["dev:s0d0"], addresses: [] }], destination: [{ member: "b", inventory_uid: null, devices: ["dev:s0d2"], addresses: [] }] },
    evaluation: null,
    paths: [],
    more_paths: 0,
    counts: { passes: 0, fails: 0, open: 0 },
    missing: [],
    evidence_truncated: false,
    ...extra,
  };
}

function response(run: number): FlowsResponse {
  return {
    application: { id: "shop", revision: 3, digest: "d", name: "Shop" },
    snapshot: { snapshot: String(run), manifest_sha256: "m", estate: "e" },
    resolution_digest: "r",
    connections: [
      conn("web", "open", {
        missing: ["route table of dev:s0d1"],
        more_paths: 4,
        paths: [
          {
            id: "p1",
            result: conditionResult("open", ["route table of dev:s0d1"]),
            count: 2,
            members: ["b"],
            devices: ["dev:s0d0", "dev:s0d1", "dev:s0d2"],
            phases: ["forward", "forward", "forward"],
            segments: [
              { from: "dev:s0d0", to: "dev:s0d1", phase: "forward", state: "decided" },
              { from: "dev:s0d1", to: "dev:s0d2", phase: "forward", state: "open" },
            ],
            steps: [],
            stop_index: null,
            stop_device: null,
            unknown_index: 1,
            unknown_device: "dev:s0d1",
            missing: ["route table of dev:s0d1"],
          },
        ],
        counts: { passes: 0, fails: 0, open: 2 },
        evaluation: {
          session_id: "s",
          run_id: "x",
          execution: "completed",
          snapshot: "1",
          revision: 3,
          finished_at: null,
          stale: { snapshot: run !== 1, revision: false },
        },
      }),
      conn("api", "unresolved", { readiness: "unresolved", issues: [{ code: "inventory-not-found", path: "groups.servers.members.b", detail: "ip:b was not found" }] }),
    ],
    evaluated: { snapshots: ["1"], revisions: [3] },
    stale: { snapshot: run !== 1, revision: false },
    max_paths: 50,
  };
}

describe("the Applications section of the layers menu", () => {
  it("toggles nothing on pick, draws a toggled connection, and reads each run once", async () => {
    const calls: [string, number, number | undefined][] = [];
    const flows = async (app: string, run: number, revision?: number) => {
      calls.push([app, run, revision]);
      return response(run);
    };
    const r = nullFactory();
    render(
      <HstMapPage
        source={new FakeSource(history(3))}
        renderer={r.factory}
        events={null}
        trace={null}
        flows={flows}
        catalog={async () => ({ applications: [APP] })}
      />,
    );
    await screen.findByRole("status");
    expect(calls).toEqual([]);
    const section = document.querySelector<HTMLDetailsElement>(".hst-apps")!;
    section.open = true;
    fireEvent(section, new Event("toggle"));
    fireEvent.change(await screen.findByRole("combobox", { name: "Application" }), { target: { value: "shop" } });
    const web = await screen.findByRole("checkbox", { name: "WEB" });
    const last = calls[0][1];
    expect(calls).toEqual([["shop", last, 3]]);
    expect(web).not.toBeChecked();
    expect(r.get().scene.routes).toEqual([]);

    fireEvent.click(web);
    await waitFor(() => expect(r.get().scene.routes.filter((x) => x.line !== false).map((x) => x.state)).toEqual(["decided", "open"]));
    const item = web.closest("li")!;
    expect(within(item).getByText("Not decided")).toBeInTheDocument();
    expect(within(item).getByText("Missing evidence: route table of dev:s0d1")).toBeInTheDocument();
    expect(within(item).getByText("4 paths not drawn")).toBeInTheDocument();
    expect(r.get().scene.style.highlight).toEqual(new Set(["dev:s0d0", "dev:s0d1", "dev:s0d2"]));
    expect(screen.getByRole("note")).toHaveTextContent(`Evaluation of run 1, not run ${last}`);

    // the service toggles both of its connections; the unresolved one lists its issues
    fireEvent.click(screen.getByRole("checkbox", { name: "Service Front" }));
    await waitFor(() => expect(screen.getByRole("checkbox", { name: "API" })).toBeChecked());
    expect(screen.getByText("groups.servers.members.b: ip:b was not found")).toBeInTheDocument();

    // a scrub reads the run once; a scrub back reads nothing again
    fireEvent.click(screen.getByRole("button", { name: "Step back" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    fireEvent.click(screen.getByRole("button", { name: "Now" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Now"));
    expect(calls).toHaveLength(2);

    fireEvent.click(screen.getByRole("checkbox", { name: "Service Front" }));
    await waitFor(() => expect(r.get().scene.routes).toEqual([]));
    expect(r.get().scene.style.highlight).toBeNull();
  });
});
