import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthProvider } from "../auth";
import { mockApi } from "../test/fetchMock";
import { ME_OPERATOR } from "../test/fixtures";
import { clearUserStorage } from "../userStorage";
import { initial, panes, reduce, type Workspace } from "./layout";
import { useWorkspace, WorkspaceProvider } from "./WorkspaceContext";

/** Renders `node` in a WorkspaceProvider with ME_OPERATOR signed in. */
function renderSignedIn(node: React.ReactNode) {
  mockApi({ "GET /api/me": () => ({ body: ME_OPERATOR }) });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuthProvider>
          <WorkspaceProvider>{node}</WorkspaceProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The layout of the current history entry with the session "session-9" in the focused pane. */
function layoutWithSession9(): Workspace {
  const layout = window.history.state.hstWorkspace as Workspace;
  return reduce(layout, { type: "open-analysis", id: layout.focus, sessionId: "session-9" });
}

function Harness() {
  const workspace = useWorkspace()!;
  const focused = panes(workspace.state.root).find((pane) => pane.id === workspace.state.focus)!;
  return <>
    <output>{focused.view}:{focused.analysisSessionId ?? ""}</output>
    <button type="button" onClick={() => workspace.openAnalysis("session-2")}>Open session</button>
  </>;
}

it("adds durable Analysis navigation to browser history and restores prior workspace state", async () => {
  window.history.replaceState({}, "", "/");
  const user = userEvent.setup();
  renderSignedIn(<Harness />);
  const initialOutput = document.querySelector("output")?.textContent;
  await waitFor(() => expect(window.history.state.hstWorkspace).toBeDefined());
  const initialState = window.history.state;

  await user.click(screen.getByRole("button", { name: "Open session" }));
  await waitFor(() => expect(window.location.search).toBe("?analysis=session-2"));
  expect(screen.getByText("analysis:session-2")).toBeInTheDocument();

  window.dispatchEvent(new PopStateEvent("popstate", { state: initialState }));
  await waitFor(() => expect(document.querySelector("output")).toHaveTextContent(initialOutput ?? ""));
  expect(window.location.search).toBe("");
});

it("restores the layout of a popstate with the state of the same user", async () => {
  window.history.replaceState({}, "", "/");
  renderSignedIn(<Harness />);
  await waitFor(() => expect(window.history.state.hstWorkspaceUser).toBe(ME_OPERATOR.username));

  act(() => {
    const state = { hstWorkspace: layoutWithSession9(), hstWorkspaceUser: ME_OPERATOR.username };
    window.dispatchEvent(new PopStateEvent("popstate", { state }));
  });

  expect(screen.getByText("analysis:session-9")).toBeInTheDocument();
  expect(window.localStorage.getItem("hst-workspace")).toContain("session-9");
});

it.each([
  ["of another user", { hstWorkspaceUser: "viewer1" }],
  ["without a user", {}],
])("ignores a popstate with a state %s", async (_name, tag) => {
  window.history.replaceState({}, "", "/");
  renderSignedIn(<Harness />);
  await waitFor(() => expect(window.history.state.hstWorkspace).toBeDefined());
  const output = document.querySelector("output")?.textContent;
  const stored = window.localStorage.getItem("hst-workspace");

  act(() => {
    const state = { hstWorkspace: layoutWithSession9(), ...tag };
    window.dispatchEvent(new PopStateEvent("popstate", { state }));
  });

  expect(document.querySelector("output")?.textContent).toBe(output);
  expect(window.localStorage.getItem("hst-workspace")).toBe(stored);
  expect(stored).not.toContain("session-9");
});

it("keeps the layout out of the history state while no user is signed in", () => {
  window.history.replaceState({ idx: 1, hstWorkspace: initial(), hstWorkspaceUser: "viewer1" }, "", "/");

  render(<WorkspaceProvider><Harness /></WorkspaceProvider>);

  expect(window.history.state).toEqual({ idx: 1 });
});

it("clearUserStorage removes the layout from the current history entry", async () => {
  window.history.replaceState({ idx: 1 }, "", "/");
  renderSignedIn(<Harness />);
  await waitFor(() => expect(window.history.state.hstWorkspace).toBeDefined());

  clearUserStorage();

  expect(window.history.state).toEqual({ idx: 1 });
});

function ChangeSimHarness() {
  const workspace = useWorkspace()!;
  const focused = panes(workspace.state.root).find((pane) => pane.id === workspace.state.focus)!;
  return <>
    <output>{focused.view}:{focused.conversationId ?? ""}</output>
    <button type="button" onClick={() => workspace.openChangeSim("c7")}>Open the chat in Change simulation</button>
    <button type="button" onClick={() => workspace.openView("trace")}>Trace</button>
    <button type="button" onClick={() => workspace.openChangeSim()}>Change simulation</button>
  </>;
}

it("opens a conversation in the change simulation and keeps the drawer's URL param without a history entry", async () => {
  window.history.replaceState({}, "", "/");
  const user = userEvent.setup();
  renderSignedIn(<ChangeSimHarness />);
  await waitFor(() => expect(window.history.state.hstWorkspace).toBeDefined());
  // the drawer names its conversation in the URL with replaceState (ai/drawer.tsx)
  window.history.replaceState(window.history.state, "", "/?ai=c1");
  const entries = window.history.length;

  await user.click(screen.getByRole("button", { name: "Open the chat in Change simulation" }));
  expect(document.querySelector("output")).toHaveTextContent("changesim:c7");
  // a view switch and the rail's own entry keep the pane's conversation
  await user.click(screen.getByRole("button", { name: "Trace" }));
  expect(document.querySelector("output")).toHaveTextContent("trace:c7");
  await user.click(screen.getByRole("button", { name: "Change simulation" }));
  expect(document.querySelector("output")).toHaveTextContent("changesim:c7");

  expect(window.history.length).toBe(entries);
  expect(window.location.search).toBe("?ai=c1");
});
