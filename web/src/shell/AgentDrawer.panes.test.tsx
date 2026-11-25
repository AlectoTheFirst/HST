/**
 * The three parts of the HST AI drawer: the conversation list, the chat and
 * the evidence pane with its chain; one level at a time in a narrow drawer,
 * named by a breadcrumb, and side by side in a wide one.
 */

import { afterEach, describe, expect, it } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TopBar } from "./TopBar";
import { AuthProvider } from "../auth";
import { mockApi, type MockHandler } from "../test/fetchMock";
import { ME_VIEWER } from "../test/fixtures";
import { AiDrawerProvider } from "../ai/drawer";
import { CHAIN_ANSWER, CHAIN_ENVELOPE, EXPLAIN_STEP, RULE_UID, RULES_STEP } from "../test/chainFixture";

function renderBar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <AuthProvider>
          <AiDrawerProvider>
            <TopBar />
          </AiDrawerProvider>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function conversation(id: string, title: string, last: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    surface: "drawer",
    title,
    pin: null,
    pin_mode: "follow",
    message_count: 2,
    created_at: last,
    last_message_at: last,
    last_run: null,
    ...extra,
  };
}

function message(id: string, role: "user" | "assistant", content: string, steps: unknown[] = []) {
  return {
    id, seq: 0, role, status: "done", content, context: null, envelope: null, error: null,
    snapshot: null, created_at: null, finished_at: null, steps,
  };
}

/** A stored conversation: one question and an answer. An answer with steps
 *  is read again through its message. */
function stored(id: string, question: string, answer: string, steps: unknown[] = []) {
  return {
    status: 200,
    body: {
      ...conversation(id, "", "2026-10-01T10:00:00Z"),
      messages: [message(`q-${id}`, "user", question), message(`a-${id}`, "assistant", answer, steps)],
    },
  };
}

const LIST = [
  conversation("c2", "Which rules drop the flow?", "2026-10-02T09:00:00Z", { last_run: "1759" }),
  conversation("c1", "Which path does core1 take to the LAN?", "2026-10-01T10:00:00Z", { pin: "1760", pin_mode: "pinned" }),
];

/** The routes of a user with the two conversations of LIST: c2 holds the
 *  chain fixture answer, c1 a plain one. */
function mockConversations(extra: Record<string, MockHandler> = {}) {
  mockApi({
    "GET /api/me": () => ({ status: 200, body: ME_VIEWER }),
    "GET /api/health": () => ({ status: 200, body: { path: true, neo4j: true, postgres: true, agent: true } }),
    "GET /api/ai/conversations": () => ({ status: 200, body: { conversations: LIST } }),
    "GET /api/ai/conversations/c2": () =>
      stored("c2", "Which rules drop the flow?", CHAIN_ANSWER, [{ id: "st1" }, { id: "st2" }]),
    "GET /api/ai/messages/a-c2": () => ({
      status: 200,
      body: {
        status: "done",
        answer: CHAIN_ANSWER,
        declined: false,
        steps: [RULES_STEP, EXPLAIN_STEP],
        envelope: CHAIN_ENVELOPE,
      },
    }),
    "GET /api/ai/conversations/c1": () => stored("c1", "Which path does core1 take to the LAN?", "Through eth0."),
    ...extra,
  });
}

async function openDrawer() {
  const user = userEvent.setup();
  renderBar();
  await user.click(await screen.findByRole("button", { name: "HST AI" }));
  const drawer = screen.getByRole("complementary", { name: "HST AI" });
  return { user, drawer };
}

/** The breadcrumb of a narrow drawer. */
function crumbs(drawer: HTMLElement) {
  return within(drawer).getByRole("navigation", { name: "Breadcrumb" });
}

/** The levels the breadcrumb names, and the one on screen. */
function levels(drawer: HTMLElement) {
  const items = within(crumbs(drawer)).getAllByRole("listitem");
  return {
    names: items.map((item) => item.textContent),
    current: crumbs(drawer).querySelector("[aria-current]")?.textContent,
  };
}

/** Go up to the conversations from the breadcrumb. */
async function openChats(user: ReturnType<typeof userEvent.setup>, drawer: HTMLElement) {
  await user.click(within(crumbs(drawer)).getByRole("button", { name: "Chats" }));
}

/** Show the conversation titled `title` from the conversation list. */
async function switchTo(user: ReturnType<typeof userEvent.setup>, drawer: HTMLElement, title: string) {
  // a narrow drawer goes up to the list first; a wide one shows it beside the chat
  if (within(drawer).queryByRole("navigation", { name: "Breadcrumb" })) await openChats(user, drawer);
  const list = within(drawer).getByRole("list", { name: "Conversations" });
  await user.click(await within(list).findByRole("button", { name: new RegExp(`^${title}`) }));
}

const innerWidth = window.innerWidth;
afterEach(() => {
  Object.defineProperty(window, "innerWidth", { configurable: true, value: innerWidth });
});

describe("HST AI: the conversation list", () => {
  it("lists the conversations newest first with their runs, filters them by title and switches to one", async () => {
    mockConversations();
    const { user, drawer } = await openDrawer();
    await openChats(user, drawer);
    const list = within(drawer).getByRole("list", { name: "Conversations" });

    const entries = await within(list).findAllByRole("button", { name: /^Which/ });
    expect(entries.map((entry) => within(entry).getByText(/\?$/).textContent)).toEqual([
      "Which rules drop the flow?",
      "Which path does core1 take to the LAN?",
    ]);
    expect(within(entries[0]).getByText("Run 1759")).toBeInTheDocument();
    expect(within(entries[1]).getByText("Pinned to run 1760")).toBeInTheDocument();

    await user.type(within(drawer).getByRole("searchbox", { name: "Search conversations" }), "path");
    expect(within(list).queryByRole("button", { name: /^Which rules/ })).not.toBeInTheDocument();
    await user.click(within(list).getByRole("button", { name: /^Which path does core1/ }));

    // the chat shows the conversation picked, named in the breadcrumb under Chats
    expect(levels(drawer)).toEqual({
      names: ["Chats", "Which path does core1 take to the LAN?"],
      current: "Which path does core1 take to the LAN?",
    });
    expect(await within(drawer).findByText("Through eth0.")).toBeInTheDocument();
    expect(within(drawer).getByText("Which path does core1 take to the LAN?", { selector: "p" })).toBeInTheDocument();
    await openChats(user, drawer);
    expect(within(list).getByRole("button", { name: /^Which path does core1/ })).toHaveAttribute("aria-current", "true");
  });

  it("deletes a conversation only after confirmation; deleting the one on screen starts a new chat", async () => {
    const deleted: string[] = [];
    mockConversations({
      "GET /api/ai/conversations": () => ({
        status: 200,
        body: { conversations: LIST.filter((item) => !deleted.includes(item.id)) },
      }),
      // the server answers 204; the stub cannot send a 204 with its JSON body
      "DELETE /api/ai/conversations/c1": () => {
        deleted.push("c1");
        return { status: 200, body: {} };
      },
    });
    const { user, drawer } = await openDrawer();
    await switchTo(user, drawer, "Which path does core1");
    await within(drawer).findByText("Through eth0.");

    await openChats(user, drawer);
    await user.click(within(drawer).getByRole("button", { name: "Delete Which path does core1 take to the LAN?" }));
    const confirm = within(drawer).getByRole("group", { name: "Confirm delete Which path does core1 take to the LAN?" });
    await user.click(within(confirm).getByRole("button", { name: "Cancel" }));
    expect(deleted).toEqual([]);
    // the focus goes back to the button that asked
    expect(within(drawer).getByRole("button", { name: "Delete Which path does core1 take to the LAN?" })).toHaveFocus();

    await user.click(within(drawer).getByRole("button", { name: "Delete Which path does core1 take to the LAN?" }));
    await user.click(within(drawer).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(deleted).toEqual(["c1"]));
    const list = within(drawer).getByRole("list", { name: "Conversations" });
    await waitFor(() =>
      expect(within(list).queryByRole("button", { name: /^Which path does core1/ })).not.toBeInTheDocument(),
    );
    expect(within(drawer).queryByText("Through eth0.")).not.toBeInTheDocument();
    expect(within(drawer).getByRole("searchbox", { name: "Search conversations" })).toHaveFocus();
  });
});

describe("HST AI: the evidence pane", () => {
  it("opens a chip's evidence under its chat, with the chain of its statement", async () => {
    mockConversations();
    const { user, drawer } = await openDrawer();
    await switchTo(user, drawer, "Which rules");

    await user.click(await within(drawer).findByRole("button", { name: "Show evidence of s2" }));
    expect(levels(drawer)).toEqual({
      names: ["Chats", "Which rules drop the flow?", "Evidence"],
      current: "Evidence",
    });
    expect(within(drawer).getByRole("heading", { name: "Evidence" })).toHaveFocus();
    const evidence = within(drawer).getByRole("region", { name: "Evidence of s2" });
    expect(within(evidence).getByText(`Rule ${RULE_UID} on core1 at run 1759`)).toBeInTheDocument();
    // the supporting record, highlighted
    expect(evidence.querySelectorAll(".evidence-record.supporting")).toHaveLength(1);
    // s2 took the rule uid from s1
    expect(within(drawer).getByText(/^Takes/)).toHaveTextContent(`Takes ${RULE_UID} from s1`);

    // the chain of the statement, as a list of its nodes
    const chain = within(drawer).getByRole("region", { name: "Evidence chain" });
    expect(within(chain).getByText("Statement evidence chain")).toBeInTheDocument();
    const steps = within(chain).getByRole("group", { name: "Tool steps" });
    expect(within(steps).getAllByRole("button").map((button) => button.textContent)).toEqual([
      "s1 Graph query on Rulebase, Rule records...",
      `s2 Rule ${RULE_UID} on core1`,
    ]);
    expect(within(chain).getByRole("group", { name: "Objects" })).toHaveTextContent("Run 1759");
    expect(within(chain).getByText(`s2 Rule ${RULE_UID} on core1 takes ${RULE_UID} from s1 Graph query on Rulebase, Rule records...`)).toBeInTheDocument();

    // a node of the chain opens its step, and keeps the focus
    const node = within(steps).getByRole("button", { name: /^s1 / });
    await user.click(node);
    expect(within(drawer).getByRole("region", { name: "Evidence of s1" })).toBeInTheDocument();
    expect(node).toHaveFocus();
    // a step id opens that step
    await user.click(within(drawer).getByRole("button", { name: "Show step s2" }));
    expect(within(drawer).getByRole("region", { name: "Evidence of s2" })).toBeInTheDocument();

    await user.click(within(drawer).getByRole("button", { name: "Show whole answer" }));
    expect(within(drawer).getByText("Answer evidence chain")).toBeInTheDocument();
    expect(within(drawer).queryByRole("region", { name: "Evidence of s2" })).not.toBeInTheDocument();
  });

  it("enlarges the evidence chain in a dialog over the drawer; Escape closes only the dialog", async () => {
    mockConversations();
    const { user, drawer } = await openDrawer();
    await switchTo(user, drawer, "Which rules");
    await user.click(await within(drawer).findByRole("button", { name: "Show evidence of s2" }));

    const enlarge = within(drawer).getByRole("button", { name: "Enlarge evidence chain" });
    await user.click(enlarge);
    const dialog = screen.getByRole("dialog", { name: "Statement evidence chain" });
    // in document.body, not in the drawer, which a transform moves
    expect(drawer).not.toContainElement(dialog);
    expect(dialog).toHaveFocus();
    expect(dialog.querySelector(".chain-graph.large")).not.toBeNull();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("complementary", { name: "HST AI" })).toHaveAttribute("aria-hidden", "false");
    expect(enlarge).toHaveFocus();

    // Close closes it too
    await user.click(enlarge);
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("shows a statement's evidence when its text is clicked, and marks it in the answer", async () => {
    mockConversations();
    const { user, drawer } = await openDrawer();
    await switchTo(user, drawer, "Which rules");

    const statement = await within(drawer).findByText("LAN-WAN holds two rules.", { selector: ".claim-text" });
    await user.click(statement);
    expect(statement).toHaveClass("selected");
    const pane = within(drawer).getByRole("region", { name: "Evidence" });
    expect(within(pane).getByText("LAN-WAN holds two rules.", { selector: "blockquote *, blockquote" })).toBeInTheDocument();
    // a matched statement shows the step it is matched to
    expect(within(pane).getByRole("region", { name: "Evidence of s1" })).toBeInTheDocument();
  });

  it("opens the tool calls of an answer from the steps line", async () => {
    mockConversations();
    const { user, drawer } = await openDrawer();
    await switchTo(user, drawer, "Which rules");

    await user.click(await within(drawer).findByRole("button", { name: "2 steps" }));
    const pane = within(drawer).getByRole("region", { name: "Evidence" });
    expect(within(pane).getByText("2 tool calls").closest("details")).toHaveAttribute("open");
    expect(drawer.querySelector("#ai-step-st2")).not.toBeNull();
    // the chat itself holds no tool call
    const chat = drawer.querySelector<HTMLElement>(".drawer-chat")!;
    expect(within(chat).queryByText("2 tool calls")).not.toBeInTheDocument();
  });

  it("remembers the selection of each conversation", async () => {
    // expanded, so the evidence of each chat is in view beside it
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1600 });
    mockConversations();
    const { user, drawer } = await openDrawer();
    await user.click(within(drawer).getByRole("button", { name: "Expand HST AI" }));
    await switchTo(user, drawer, "Which rules");
    await user.click(await within(drawer).findByRole("button", { name: "Show evidence of s2" }));
    expect(within(drawer).getByRole("region", { name: "Evidence of s2" })).toBeInTheDocument();

    await switchTo(user, drawer, "Which path does core1");
    await within(drawer).findByText("Through eth0.");
    expect(within(drawer).queryByRole("region", { name: "Evidence of s2" })).not.toBeInTheDocument();

    await switchTo(user, drawer, "Which rules");
    await within(drawer).findByRole("button", { name: "Show evidence of s2" });
    expect(await within(drawer).findByRole("region", { name: "Evidence of s2" })).toBeInTheDocument();
  });
});

describe("HST AI: narrow and wide", () => {
  it("shows one level at a time in a narrow drawer: the chats, a chat and its evidence", async () => {
    mockConversations();
    const { user, drawer } = await openDrawer();
    expect(within(drawer).queryByRole("tablist")).not.toBeInTheDocument();
    // a new chat opens first, under Chats
    expect(levels(drawer)).toEqual({ names: ["Chats", "New chat"], current: "New chat" });
    expect(within(drawer).getByRole("region", { name: "Chat" })).toBeVisible();
    expect(within(drawer).queryByRole("region", { name: "Evidence" })).not.toBeInTheDocument();

    // up to the conversations; the focus goes to the level that opened
    await openChats(user, drawer);
    expect(levels(drawer)).toEqual({ names: ["Chats"], current: "Chats" });
    expect(crumbs(drawer).querySelector("[aria-current]")).toHaveFocus();
    expect(within(drawer).getByRole("searchbox", { name: "Search conversations" })).toBeVisible();
    expect(within(drawer).queryByRole("region", { name: "Chat" })).not.toBeInTheDocument();

    // down into a chat and the evidence of one of its statements
    const list = within(drawer).getByRole("list", { name: "Conversations" });
    await user.click(await within(list).findByRole("button", { name: /^Which rules/ }));
    await user.click(await within(drawer).findByRole("button", { name: "Show evidence of s2" }));
    expect(levels(drawer).names).toEqual(["Chats", "Which rules drop the flow?", "Evidence"]);
    expect(within(drawer).queryByRole("region", { name: "Chat" })).not.toBeInTheDocument();

    // back up to the chat the evidence belongs to
    await user.click(within(crumbs(drawer)).getByRole("button", { name: "Which rules drop the flow?" }));
    expect(levels(drawer)).toEqual({
      names: ["Chats", "Which rules drop the flow?"],
      current: "Which rules drop the flow?",
    });
    expect(crumbs(drawer).querySelector("[aria-current]")).toHaveFocus();
    expect(within(drawer).getByRole("region", { name: "Chat" })).toBeVisible();
    expect(within(drawer).queryByRole("region", { name: "Evidence" })).not.toBeInTheDocument();
  });

  it("shows the conversations, the chat and the evidence side by side once expanded", async () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1600 });
    mockConversations();
    const { user, drawer } = await openDrawer();

    await user.click(within(drawer).getByRole("button", { name: "Expand HST AI" }));
    expect(within(drawer).queryByRole("navigation", { name: "Breadcrumb" })).not.toBeInTheDocument();
    for (const name of ["Conversations", "Chat", "Evidence"]) {
      expect(within(drawer).getByRole("region", { name })).toBeVisible();
    }
    await user.click(
      await within(within(drawer).getByRole("region", { name: "Conversations" })).findByRole("button", {
        name: /^Which rules/,
      }),
    );
    await user.click(await within(drawer).findByRole("button", { name: "Show evidence of s2" }));
    // the chip stays where it is; the evidence shows beside it
    expect(within(drawer).getByRole("button", { name: "Show evidence of s2" })).toHaveFocus();
    const pane = within(drawer).getByRole("region", { name: "Evidence" });
    expect(within(pane).getByRole("region", { name: "Evidence of s2" })).toBeInTheDocument();

    await user.click(within(drawer).getByRole("button", { name: "Narrow HST AI" }));
    expect(crumbs(drawer)).toBeInTheDocument();
  });
});
