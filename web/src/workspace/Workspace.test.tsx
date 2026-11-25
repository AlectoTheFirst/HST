import { act } from "react";
import { describe, it, expect, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Workspace } from "./Workspace";
import { WorkspaceProvider } from "./WorkspaceContext";
import { SideRail } from "../shell/SideRail";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_VIEWER, FIXTURE_PATH_SINGLE, FIXTURE_PATH_BLOCKED } from "../test/fixtures";

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

/** The rail is rendered by default: the split and close actions live in
 *  its foot and act on the focused pane. */
function renderWorkspace(withRail = true) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <WorkspaceProvider>
            {withRail && <SideRail />}
            <Workspace />
          </WorkspaceProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const HEALTHY = { path: true, neo4j: true, postgres: true, agent: false };

function mockBase(extra: Record<string, unknown> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
    "GET /api/health": () => ({ status: 200, body: HEALTHY }),
    "GET /api/queries": () => ({ status: 200, body: { queries: [] } }),
    ...extra,
  });
}

describe("Workspace", () => {
  beforeEach(installStorage);

  it("starts as one trace pane", async () => {
    mockBase();
    const { container } = renderWorkspace();
    expect(await screen.findByRole("region", { name: "Trace pane" })).toBeInTheDocument();
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(1);
    // nothing to close when it is the only pane
    expect(screen.getByRole("button", { name: "Close pane" })).toBeDisabled();
  });

  it("splits into two panes", async () => {
    mockBase();
    const user = userEvent.setup();
    renderWorkspace();

    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    expect(screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ })).toHaveLength(2);
    expect(screen.getByRole("separator", { name: "Resize panes" })).toBeInTheDocument();
  });

  it("holds two independent trace results at once", async () => {
    // each call answers differently, so a shared result would be visible
    let call = 0;
    mockBase({
      "GET /api/path": () => ({
        status: 200,
        body: ++call === 1 ? FIXTURE_PATH_SINGLE : FIXTURE_PATH_BLOCKED,
      }),
    });
    const user = userEvent.setup();
    renderWorkspace();

    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    const [paneA, paneB] = screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ });

    // A label can appear as a node and in the pane's inspector.
    await user.click(within(paneA).getByRole("button", { name: "Trace flow" }));
    expect((await within(paneA).findAllByText("host44")).length).toBeGreaterThan(0);

    await user.click(within(paneB).getByRole("button", { name: "Trace flow" }));
    expect((await within(paneB).findAllByText("IOT-LAN")).length).toBeGreaterThan(0);

    expect(within(paneA).queryAllByText("host44").length).toBeGreaterThan(0);
    expect(within(paneA).queryAllByText("IOT-LAN")).toHaveLength(0);
  });

  it("keeps a pane's trace result when the workspace is split", async () => {
    mockBase({ "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }) });
    const user = userEvent.setup();
    renderWorkspace();

    await user.click(await screen.findByRole("button", { name: "Trace flow" }));
    expect((await screen.findAllByText("host44")).length).toBeGreaterThan(0);

    await user.click(screen.getByRole("button", { name: "Split side by side" }));

    const [paneA] = screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ });
    expect(within(paneA).queryAllByText("host44").length).toBeGreaterThan(0);
  });

  it("keeps the survivor's trace result when its sibling closes", async () => {
    mockBase({ "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }) });
    const user = userEvent.setup();
    renderWorkspace();

    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    const [paneA, paneB] = screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ });
    await user.click(within(paneA).getByRole("button", { name: "Trace flow" }));
    expect((await within(paneA).findAllByText("host44")).length).toBeGreaterThan(0);

    await user.click(paneB);
    await user.click(screen.getByRole("button", { name: "Close pane" }));

    const survivor = screen.getByRole("region", { name: "Trace pane" });
    expect(within(survivor).queryAllByText("host44").length).toBeGreaterThan(0);
  });

  it("caps the workspace at four panes and greys the split buttons there", async () => {
    mockBase();
    const user = userEvent.setup();
    const { container } = renderWorkspace();

    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    await user.click(screen.getByRole("button", { name: "Split stacked" }));
    await user.click(screen.getByRole("button", { name: "Split side by side" }));
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(4);

    for (const b of screen.getAllByRole("button", { name: /^Split / })) expect(b).toBeDisabled();

    // and the keyboard chord is refused by the same reducer guard
    await user.keyboard("{Control>}{Shift>}\\{/Shift}{/Control}");
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(4);
  });

  it("reset returns the workspace to one fresh pane", async () => {
    mockBase({ "GET /api/path": () => ({ status: 200, body: FIXTURE_PATH_SINGLE }) });
    const user = userEvent.setup();
    const { container } = renderWorkspace(true);

    await user.click(await screen.findByRole("button", { name: "Trace flow" }));
    expect((await screen.findAllByText("host44")).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Split side by side" }));
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(2);

    await user.click(screen.getByRole("button", { name: "Reset workspace" }));

    // a hard reset: one pane, and the result is gone with the pane that held it
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Close pane" })).toBeDisabled();
    expect(screen.queryAllByText("host44")).toHaveLength(0);
  });

  it("closing a pane collapses the split", async () => {
    mockBase();
    const user = userEvent.setup();
    const { container } = renderWorkspace();

    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(2);

    const panes = screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ });
    await user.click(panes[1]);
    await user.click(screen.getByRole("button", { name: "Close pane" }));

    expect(container.querySelectorAll(".ws-pane")).toHaveLength(1);
    expect(container.querySelector(".ws-divider")).toBeNull();
  });

  it("switches one pane to Explore without touching the other", async () => {
    mockBase();
    const user = userEvent.setup();
    renderWorkspace(true);

    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    const panes = screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ });
    // the rail acts on the focused pane; a click inside a pane focuses it
    await user.click(panes[0]);
    await user.click(screen.getByRole("button", { name: "Explore" }));

    expect(screen.getAllByRole("region", { name: "Explore pane" })).toHaveLength(1);
    expect(screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ })).toHaveLength(1);
  });

  it("the rail loads a query into the focused pane only", async () => {
    mockBase({
      "GET /api/queries": () => ({
        status: 200,
        body: {
          queries: [{ key: "cabling", group: "topology", title: "Cabling",
                      cypher: "MATCH (a) RETURN a" }],
        },
      }),
    });
    const user = userEvent.setup();
    renderWorkspace(true);

    // split; the new pane takes focus
    await user.click(await screen.findByRole("button", { name: "Split side by side" }));

    await user.click(await screen.findByRole("button", { name: /topology/ }));
    await user.click(screen.getByRole("button", { name: "Cabling" }));

    expect(screen.getAllByRole("region", { name: "Explore pane" })).toHaveLength(1);
    expect(screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ })).toHaveLength(1);
  });

  it("restores the layout after a reload", async () => {
    mockBase();
    const user = userEvent.setup();
    const first = renderWorkspace();
    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    first.unmount();

    const { container } = renderWorkspace();
    expect(await screen.findAllByRole("region", { name: /^Trace pane( \d)?$/ })).toHaveLength(2);
    expect(container.querySelector(".ws-divider")).not.toBeNull();
  });

  it("repairs a stored layout whose panes share an id", async () => {
    window.localStorage.setItem(
      "hst-workspace",
      JSON.stringify({
        root: {
          type: "split", id: "s2", dir: "row", ratio: 0.5,
          a: { type: "leaf", id: "p1", view: "trace" },
          b: { type: "leaf", id: "p1", view: "trace" },
        },
        focus: "p1",
      }),
    );
    mockBase();
    const user = userEvent.setup();
    const { container } = renderWorkspace(true);

    const panes = await screen.findAllByRole("region", { name: /^Trace pane( \d)?$/ });
    expect(panes).toHaveLength(2);

    // one pane switches, the other keeps its view
    await user.click(panes[1]);
    await user.click(screen.getByRole("button", { name: "Explore" }));
    expect(screen.getAllByRole("region", { name: "Explore pane" })).toHaveLength(1);
    expect(screen.getAllByRole("region", { name: /^Trace pane( \d)?$/ })).toHaveLength(1);

    // the healed tree gave each pane its own id, persisted back to storage
    const stored = JSON.parse(window.localStorage.getItem("hst-workspace")!);
    const ids = [stored.root.id, stored.root.a.id, stored.root.b.id];
    expect(new Set(ids).size).toBe(ids.length);

    // and it closes back down to a single pane
    const explore = screen.getByRole("region", { name: "Explore pane" });
    await user.click(explore);
    await user.click(screen.getByRole("button", { name: "Close pane" }));
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Close pane" })).toBeDisabled();
  });

  it("resets a stored layout whose pane view this build does not know", async () => {
    window.localStorage.setItem(
      "hst-workspace",
      JSON.stringify({
        root: { type: "leaf", id: "p1", view: "dashboards" },
        focus: "p1",
      }),
    );
    mockBase();
    const { container } = renderWorkspace();
    expect(await screen.findByRole("region", { name: "Trace pane" })).toBeInTheDocument();
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(1);
  });

  it("opens a stored pane of a retired view as the Map, and keeps the other panes", async () => {
    window.localStorage.setItem(
      "hst-workspace",
      JSON.stringify({
        root: {
          type: "split", id: "s2", dir: "row", ratio: 0.5,
          a: { type: "leaf", id: "p1", view: "trace" },
          b: { type: "leaf", id: "p2", view: "sites" },
        },
        focus: "p2",
      }),
    );
    mockBase();
    renderWorkspace(true);
    expect(await screen.findByRole("region", { name: /^Trace pane/ })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: /^Map pane/ })).toBeInTheDocument();
  });

  it("ignores a corrupt stored layout", async () => {
    window.localStorage.setItem("hst-workspace", '{"root":"nonsense","focus":42}');
    mockBase();
    renderWorkspace();
    expect(await screen.findByRole("region", { name: "Trace pane" })).toBeInTheDocument();
  });

  it("restores a change-simulation pane with its conversation on the Scope tab", async () => {
    window.localStorage.setItem(
      "hst-workspace",
      JSON.stringify({
        root: { type: "leaf", id: "p1", view: "changesim", conversationId: "c1" },
        focus: "p1",
      }),
    );
    const base = {
      context: null, envelope: null, error: null, snapshot: null,
      created_at: null, finished_at: null, steps: [],
    };
    mockBase({
      "GET /api/analysis-sessions": () => ({ status: 200, body: { sessions: [] } }),
      "GET /api/ai/conversations/c1": () => ({
        status: 200,
        body: {
          id: "c1",
          surface: "changesim",
          message_count: 2,
          messages: [
            { ...base, id: "q1", seq: 1, role: "user", status: "done", content: "what if leaf101 reloads?" },
            { ...base, id: "m1", seq: 2, role: "assistant", status: "done", content: "Reloading leaf101 isolates one prefix." },
          ],
        },
      }),
    });
    const user = userEvent.setup();
    renderWorkspace(false);

    const pane = await screen.findByRole("region", { name: "Analysis pane" });
    await user.click(await within(pane).findByRole("tab", { name: "Scope" }));
    expect(await within(pane).findByText("Reloading leaf101 isolates one prefix.")).toBeInTheDocument();
    expect(within(pane).getByText("what if leaf101 reloads?")).toBeInTheDocument();

    // the translated pane keeps the conversation in storage
    const stored = JSON.parse(window.localStorage.getItem("hst-workspace")!);
    expect(stored.root).toMatchObject({ view: "analysis", analysisMode: "simulation", conversationId: "c1" });
  });

  it("closes the focused pane on Ctrl/Cmd+Shift+Backspace", async () => {
    mockBase();
    const user = userEvent.setup();
    const { container } = renderWorkspace();

    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(2);

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent("keydown", {
          key: "Backspace",
          ctrlKey: true,
          shiftKey: true,
          bubbles: true,
        }),
      );
    });

    expect(container.querySelectorAll(".ws-pane")).toHaveLength(1);
  });

  it("does not close a pane on Ctrl/Cmd+Shift+W", async () => {
    mockBase();
    const user = userEvent.setup();
    const { container } = renderWorkspace();

    await user.click(await screen.findByRole("button", { name: "Split side by side" }));
    expect(container.querySelectorAll(".ws-pane")).toHaveLength(2);

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent("keydown", { key: "w", ctrlKey: true, shiftKey: true, bubbles: true }),
      );
    });

    expect(container.querySelectorAll(".ws-pane")).toHaveLength(2);
  });

  // Standard layouts report Ctrl/Cmd+Shift+\ as key "|"
  it("splits side by side on the '|' alias for Ctrl/Cmd+Shift+\\", async () => {
    mockBase();
    const { container } = renderWorkspace();
    await screen.findByRole("region", { name: "Trace pane" });

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent("keydown", { key: "|", ctrlKey: true, shiftKey: true, bubbles: true }),
      );
    });

    expect(container.querySelectorAll(".ws-pane")).toHaveLength(2);
  });

  it("ignores chords when the event target is an editable element", async () => {
    mockBase();
    const { container } = renderWorkspace();
    await screen.findByRole("region", { name: "Trace pane" });

    const input = document.createElement("input");
    document.body.appendChild(input);
    try {
      act(() => {
        input.dispatchEvent(
          new KeyboardEvent("keydown", { key: "\\", ctrlKey: true, shiftKey: true, bubbles: true }),
        );
      });
      expect(container.querySelectorAll(".ws-pane")).toHaveLength(1);
    } finally {
      document.body.removeChild(input);
    }
  });
});
