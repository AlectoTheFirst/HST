/**
 * Logout clears the query cache and the stored data of the user.
 */

import { afterEach, describe, it, expect } from "vitest";
import type { ReactNode } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "../App";
import type { Me } from "../api/types";
import { TopBar } from "./TopBar";
import { THEME_KEY } from "./theme";
import { AuthProvider } from "../auth";
import { USER_KEYS } from "../userStorage";
import { mockApi, type MockHandler, type MockRequest } from "../test/fetchMock";
import { ME_ADMIN, ME_VIEWER } from "../test/fixtures";
import { AiContextProvider } from "../ai/context";
import { AiDrawerProvider, CONVERSATION_KEY, useOpenConversation } from "../ai/drawer";
import { WorkspaceProvider, useWorkspace } from "../workspace/WorkspaceContext";
import { panes } from "../workspace/layout";

const HEALTHY = { path: true, neo4j: true, postgres: true };

function renderTopBar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <Routes>
            <Route path="/" element={<AiDrawerProvider><TopBar /></AiDrawerProvider>} />
            <Route path="/login" element={<p>Login page</p>} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return queryClient;
}

function mockSession(logout: () => { status: number; body: unknown }) {
  let loggedIn = true;
  mockApi({
    "GET /api/me": () =>
      loggedIn
        ? { status: 200, body: ME_ADMIN }
        : { status: 401, body: { error: "unauthorized" } },
    "GET /api/health": () => ({ status: 200, body: HEALTHY }),
    "POST /api/logout": () => {
      loggedIn = false;
      return logout();
    },
  });
}

describe("TopBar: logout", () => {
  it("clears the entire query cache and lands on /login", async () => {
    mockSession(() => ({ status: 200, body: { ok: true } }));
    const user = userEvent.setup();
    const queryClient = renderTopBar();

    await user.click(await screen.findByRole("button", { name: ME_ADMIN.username }));
    queryClient.setQueryData(["sources"], { sources: [{ name: "home-unifi" }] });
    queryClient.setQueryData(["users"], { users: [{ username: "admin1" }] });

    await user.click(screen.getByRole("button", { name: "Log out" }));

    expect(await screen.findByText("Login page")).toBeInTheDocument();
    await waitFor(() => {
      expect(queryClient.getQueryData(["sources"])).toBeUndefined();
      expect(queryClient.getQueryData(["users"])).toBeUndefined();
      expect(queryClient.getQueryData(["me"])).toBeNull();
    });
  });

  it("still clears the cache and navigates when the POST fails", async () => {
    mockSession(() => ({ status: 500, body: { error: "session store unreachable" } }));
    const user = userEvent.setup();
    const queryClient = renderTopBar();

    await user.click(await screen.findByRole("button", { name: ME_ADMIN.username }));
    queryClient.setQueryData(["sources"], { sources: [{ name: "home-unifi" }] });

    await user.click(screen.getByRole("button", { name: "Log out" }));

    expect(await screen.findByText("Login page")).toBeInTheDocument();
    await waitFor(() => {
      expect(queryClient.getQueryData(["sources"])).toBeUndefined();
    });
  });

  it("removes the stored data of the user and keeps a display preference", async () => {
    mockSession(() => ({ status: 200, body: { ok: true } }));
    const userKeys = [...USER_KEYS, `hst.inventory.draft:${ME_ADMIN.username}:site:create`];
    const storages = [window.localStorage, window.sessionStorage];
    for (const storage of storages) {
      for (const key of userKeys) storage.setItem(key, "1");
    }
    window.localStorage.setItem(THEME_KEY, "dark");
    const user = userEvent.setup();
    renderTopBar();

    await user.click(await screen.findByRole("button", { name: ME_ADMIN.username }));
    await user.click(screen.getByRole("button", { name: "Log out" }));

    expect(await screen.findByText("Login page")).toBeInTheDocument();
    for (const storage of storages) {
      expect(userKeys.filter((key) => storage.getItem(key) !== null)).toEqual([]);
    }
    expect(window.localStorage.getItem(THEME_KEY)).toBe("dark");
    window.sessionStorage.clear();
  });
});

describe("TopBar: logout in the app", () => {
  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("opens the initial workspace for the next user", async () => {
    let session: Me | null = ME_ADMIN;
    mockApi({
      "GET /api/me": () =>
        session ? { status: 200, body: session } : { status: 401, body: { error: "unauthorized" } },
      "GET /api/health": () => ({ status: 200, body: HEALTHY }),
      "POST /api/logout": () => {
        session = null;
        return { status: 200, body: { ok: true } };
      },
      "POST /api/login": () => {
        session = ME_VIEWER;
        return { status: 200, body: ME_VIEWER };
      },
    });
    window.localStorage.setItem(
      "hst-workspace",
      JSON.stringify({
        root: { type: "leaf", id: "p1", view: "explore", searchText: "core-01", nodeUid: "device:core-01" },
        focus: "p1",
      }),
    );
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter initialEntries={["/"]}>
          <AuthProvider>
            <App />
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(await screen.findByRole("region", { name: "Explore pane" })).toBeInTheDocument();

    await user.click(await screen.findByRole("button", { name: ME_ADMIN.username }));
    await user.click(screen.getByRole("button", { name: "Log out" }));

    await user.type(await screen.findByLabelText("Username"), ME_VIEWER.username);
    expect(window.localStorage.getItem("hst-workspace")).toBeNull();
    await user.type(screen.getByLabelText("Password"), "secret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("region", { name: "Trace pane" })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Explore pane" })).not.toBeInTheDocument();
    expect(window.localStorage.getItem("hst-workspace")).not.toContain("core-01");
  });
});

describe("TopBar: API documentation", () => {
  it("links the server's Swagger UI from the user menu in a new tab", async () => {
    mockSession(() => ({ status: 200, body: { ok: true } }));
    const user = userEvent.setup();
    renderTopBar();

    await user.click(await screen.findByRole("button", { name: ME_ADMIN.username }));
    const link = screen.getByRole("link", { name: "API documentation" });
    expect(link).toHaveAttribute("href", "/api/docs");
    expect(link).toHaveAttribute("target", "_blank");
  });
});

const CONVERSATION = "4f0e9c2a-5b1d-4c3e-9a7f-1d2e3f4a5b6c";

/** The providers of the app shell (shell/AppShell.tsx) around the top bar. */
function renderShell(children?: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <WorkspaceProvider>
            <AiContextProvider>
              <AiDrawerProvider inUrl>
                <TopBar />
                {children}
              </AiDrawerProvider>
            </AiContextProvider>
          </WorkspaceProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function mockAgent(extra: Record<string, MockHandler>) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_ADMIN }),
    "GET /api/health": () => ({ status: 200, body: { ...HEALTHY, agent: true } }),
    ...extra,
  });
}

/** One message of GET /api/ai/conversations/{id}. */
function message(id: string, role: "user" | "assistant", content: string) {
  return {
    id, seq: 0, role, status: "done", content, context: null, envelope: null, error: null,
    snapshot: null, created_at: null, finished_at: null, steps: [],
  };
}

function stored(messages: unknown[]) {
  return () => ({
    status: 200,
    body: { id: CONVERSATION, surface: "assessment_qa", message_count: messages.length, messages },
  });
}

/** A page button that opens a chat about one finding. */
function AskAboutFinding() {
  const open = useOpenConversation();
  if (!open) return null;
  const fragment = {
    assessment: { assessment_id: "a-1", run_id: "run-1", finding_id: "finding:@1" },
    snapshot: { id: "1000", origin: "pinned" as const },
  };
  return <button type="button" onClick={() => void open("assessment_qa", fragment)}>Ask about the finding</button>;
}

/** The focused pane's view and the ids it opened. */
function FocusedPane() {
  const workspace = useWorkspace()!;
  const pane = panes(workspace.state.root).find((item) => item.id === workspace.state.focus)!;
  const ids = [
    `session=${pane.analysisSessionId ?? ""}`,
    `assessment=${pane.assessmentId ?? ""}`,
    `run=${pane.assessmentRunId ?? ""}`,
    `conversation=${pane.conversationId ?? ""}`,
  ];
  return <output aria-label="Focused pane">{[pane.view, ...ids].join(" ")}</output>;
}

/** Ask one question in the open drawer and wait for the answer. */
async function askInDrawer(user: ReturnType<typeof userEvent.setup>, answer: string) {
  await user.click(await screen.findByRole("button", { name: "HST AI" }));
  const drawer = screen.getByRole("complementary", { name: "HST AI" });
  await user.type(within(drawer).getByLabelText("Ask HST AI"), "does the finding hold?");
  await user.click(within(drawer).getByRole("button", { name: /Send/ }));
  await within(drawer).findByText(answer);
  return drawer;
}

describe("TopBar: the HST AI drawer", () => {
  afterEach(() => {
    window.history.replaceState({}, "", "/");
    try {
      window.localStorage.removeItem(CONVERSATION_KEY);
    } catch {
      // this origin keeps no storage
    }
  });

  it("reopens the drawer on the conversation the URL names, and names it only while open", async () => {
    window.history.replaceState({}, "", `/?ai=${CONVERSATION}`);
    mockAgent({
      [`GET /api/ai/conversations/${CONVERSATION}`]: stored([
        message("q1", "user", "what does this finding mean?"),
        message("m1", "assistant", "The routing table of fw1 was not collected."),
      ]),
    });
    const user = userEvent.setup();
    renderShell();

    const drawer = await screen.findByRole("complementary", { name: "HST AI" });
    expect(await within(drawer).findByText("The routing table of fw1 was not collected.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "HST AI" })).toHaveAttribute("aria-expanded", "true");

    await user.click(within(drawer).getByRole("button", { name: "Close HST AI" }));
    expect(window.location.search).toBe("");
    await user.click(screen.getByRole("button", { name: "HST AI" }));
    expect(window.location.search).toBe(`?ai=${CONVERSATION}`);
  });

  it("opens a conversation a page starts about its object, with the object as context", async () => {
    const created: unknown[] = [];
    const asked: MockRequest[] = [];
    mockAgent({
      "POST /api/ai/conversations": (req) => {
        created.push(req.body);
        return { status: 201, body: { id: CONVERSATION, surface: "assessment_qa", message_count: 0 } };
      },
      [`GET /api/ai/conversations/${CONVERSATION}`]: stored([]),
      [`POST /api/ai/conversations/${CONVERSATION}/messages`]: (req) => {
        asked.push(req);
        return { status: 202, body: { message_id: "m1" } };
      },
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: { status: "done", answer: "It is a gap in the evidence.", declined: false, steps: [] },
      }),
    });
    const user = userEvent.setup();
    renderShell(<AskAboutFinding />);

    await user.click(await screen.findByRole("button", { name: "Ask about the finding" }));

    const drawer = await screen.findByRole("complementary", { name: "HST AI" });
    expect(created).toEqual([
      {
        surface: "assessment_qa",
        context: {
          version: 1,
          route: { pathname: "/" },
          assessment: { assessment_id: "a-1", run_id: "run-1", finding_id: "finding:@1" },
          snapshot: { id: "1000", origin: "pinned" },
        },
      },
    ]);
    await waitFor(() => expect(window.location.search).toBe(`?ai=${CONVERSATION}`));

    // the drawer loads the new conversation before it takes a question
    await waitFor(() => expect(within(drawer).getByLabelText("Ask HST AI")).not.toBeDisabled());
    await user.type(within(drawer).getByLabelText("Ask HST AI"), "what does it mean?");
    await user.click(within(drawer).getByRole("button", { name: /Send/ }));
    expect(await within(drawer).findByText("It is a gap in the evidence.")).toBeInTheDocument();
    // the question goes to the conversation the page started
    expect(asked).toHaveLength(1);
    expect(created).toHaveLength(1);
  });

  it("shows the objects an answer read as chips that open them in the focused pane", async () => {
    const answer = "The finding holds.";
    const envelope = {
      version: 2,
      message_id: "m1",
      conversation_id: CONVERSATION,
      kind: "answer",
      snapshot: { id: "1000", origin: "pointer" },
      model: { provider: "anthropic", requested: "model" },
      prompt_hash: "f".repeat(64),
      tools_used: [],
      answer_markdown: answer,
      claims: [],
      grounding: { status: "no-evidence", cited: 0, uncited: 0, invalid: 0, cross_snapshot: 0 },
      links: [
        { kind: "step", ref_id: "st1", ref_revision: null, step: "s1" },
        { kind: "assessment", ref_id: "a-1", ref_revision: 3, step: "s1" },
        { kind: "assessment_run", ref_id: "run-1", ref_revision: null, step: "s1" },
        { kind: "finding", ref_id: "finding:@1", ref_revision: null, step: "s1" },
        { kind: "analysis_session", ref_id: "sess-1", ref_revision: 2, step: "s2" },
      ],
    };
    mockAgent({
      "POST /api/ai/conversations": () => ({ status: 201, body: { id: CONVERSATION, surface: "drawer", message_count: 0 } }),
      [`POST /api/ai/conversations/${CONVERSATION}/messages`]: () => ({ status: 202, body: { message_id: "m1" } }),
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: { status: "done", answer, declined: false, steps: [], envelope },
      }),
    });
    const user = userEvent.setup();
    renderShell(<FocusedPane />);

    const drawer = await askInDrawer(user, answer);

    const chips = within(drawer).getByRole("group", { name: "Objects this answer read" });
    expect(within(chips).getAllByRole("button").map((chip) => chip.textContent)).toEqual([
      "Assessment a-1",
      "Assessment run run-1",
      "Finding finding:@1",
      "Analysis session sess-1 revision 2",
    ]);

    const pane = screen.getByRole("status", { name: "Focused pane" });
    await user.click(within(chips).getByRole("button", { name: "Analysis session sess-1 revision 2" }));
    expect(pane).toHaveTextContent(/^analysis session=sess-1 /);
    await user.click(within(chips).getByRole("button", { name: "Finding finding:@1" }));
    expect(pane).toHaveTextContent(/^assessments .*assessment=a-1 run=run-1 /);
  });

  it("shows one chip per finding and per run an answer read, each opening its own run", async () => {
    const answer = "Both findings hold.";
    const link = (kind: string, ref_id: string, step: string) => ({
      kind, ref_id, ref_revision: kind === "assessment" ? 3 : null, step,
    });
    // the links the server lists when later steps read the same assessment or run
    const envelope = {
      version: 2,
      message_id: "m1",
      conversation_id: CONVERSATION,
      kind: "answer",
      snapshot: { id: "1000", origin: "pointer" },
      model: { provider: "anthropic", requested: "model" },
      prompt_hash: "f".repeat(64),
      tools_used: [],
      answer_markdown: answer,
      claims: [],
      grounding: { status: "no-evidence", cited: 0, uncited: 0, invalid: 0, cross_snapshot: 0 },
      links: [
        link("assessment", "a-1", "s1"),
        link("assessment_run", "run-1", "s1"),
        link("finding", "finding:@0", "s1"),
        link("assessment", "a-1", "s2"),
        link("assessment_run", "run-1", "s2"),
        link("finding", "finding:@1", "s2"),
        link("assessment", "a-1", "s3"),
        link("assessment_run", "run-2", "s3"),
        link("finding", "finding:@0", "s3"),
      ],
    };
    mockAgent({
      "POST /api/ai/conversations": () => ({ status: 201, body: { id: CONVERSATION, surface: "drawer", message_count: 0 } }),
      [`POST /api/ai/conversations/${CONVERSATION}/messages`]: () => ({ status: 202, body: { message_id: "m1" } }),
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: { status: "done", answer, declined: false, steps: [], envelope },
      }),
    });
    const user = userEvent.setup();
    renderShell(<FocusedPane />);

    const drawer = await askInDrawer(user, answer);

    const chips = within(drawer).getByRole("group", { name: "Objects this answer read" });
    expect(within(chips).getAllByRole("button").map((chip) => chip.textContent)).toEqual([
      "Assessment a-1",
      "Assessment run run-1",
      "Finding finding:@0",
      "Finding finding:@1",
      "Assessment run run-2",
      "Finding finding:@0",
    ]);

    const pane = screen.getByRole("status", { name: "Focused pane" });
    await user.click(within(chips).getByRole("button", { name: "Finding finding:@1" }));
    expect(pane).toHaveTextContent(/^assessments .*assessment=a-1 run=run-1 /);
    const [, secondRun] = within(chips).getAllByRole("button", { name: "Finding finding:@0" });
    await user.click(secondRun);
    expect(pane).toHaveTextContent(/^assessments .*assessment=a-1 run=run-2 /);
  });

  it("opens the conversation of a chat simulation in the change simulation", async () => {
    const answer = "Blocking it changes one verdict.";
    const step = { id: "st1", step: "s1", name: "change_simulate", arguments: {}, result: "{}", is_error: false };
    mockAgent({
      "POST /api/ai/conversations": () => ({ status: 201, body: { id: CONVERSATION, surface: "drawer", message_count: 0 } }),
      [`POST /api/ai/conversations/${CONVERSATION}/messages`]: () => ({ status: 202, body: { message_id: "m1" } }),
      "GET /api/ai/messages/m1": () => ({
        status: 200,
        body: { status: "done", answer, declined: false, steps: [step] },
      }),
    });
    const user = userEvent.setup();
    renderShell(<FocusedPane />);

    const drawer = await askInDrawer(user, answer);
    await user.click(within(drawer).getByRole("button", { name: "1 step" }));
    await user.click(within(drawer).getByRole("button", { name: "Open in Change simulation" }));

    expect(screen.getByRole("status", { name: "Focused pane" })).toHaveTextContent(
      new RegExp(`^changesim .*conversation=${CONVERSATION}$`),
    );
  });
});

describe("TopBar: user menu", () => {
  it("is a disclosure that Escape and an outside click close", async () => {
    mockSession(() => ({ status: 200, body: { ok: true } }));
    const user = userEvent.setup();
    renderTopBar();
    const button = await screen.findByRole("button", { name: ME_ADMIN.username });
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(screen.queryByRole("menu")).toBeNull();

    await user.click(button);
    expect(button.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByRole("link", { name: "Access tokens" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(button.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(button);

    await user.click(button);
    await user.click(document.body);
    expect(button.getAttribute("aria-expanded")).toBe("false");
  });
});
