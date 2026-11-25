import { describe, expect, it } from "vitest";
import { useState } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { CHAIN_ANSWER, CHAIN_ENVELOPE, EXPLAIN_STEP, RULE_UID, RULES_STEP } from "../test/chainFixture";
import { EvidencePane, type EvidenceSelection } from "./EvidencePane";
import type { ConversationChat } from "./useConversation";

type PaneChat = Pick<ConversationChat, "turns" | "runningSteps" | "isPending" | "isLoading">;

const QUESTION = { role: "user" as const, content: "Which rules drop the flow?" };

function running(steps: PaneChat["runningSteps"]): PaneChat {
  return { turns: [QUESTION], runningSteps: steps, isPending: true, isLoading: false };
}

const DONE: PaneChat = {
  turns: [QUESTION, { role: "assistant", content: CHAIN_ANSWER, envelope: CHAIN_ENVELOPE, steps: [RULES_STEP, EXPLAIN_STEP] }],
  runningSteps: [],
  isPending: false,
  isLoading: false,
};

function Pane({ chat }: { chat: PaneChat }) {
  const [selection, setSelection] = useState<EvidenceSelection>();
  return <EvidencePane chat={chat} selection={selection} onSelect={setSelection} />;
}

function view(chat: PaneChat) {
  return <MemoryRouter><Pane chat={chat} /></MemoryRouter>;
}

function stepButtons(): string[] {
  const chain = screen.getByRole("region", { name: "Evidence chain" });
  return within(within(chain).getByRole("group", { name: "Tool steps" }))
    .getAllByRole("button")
    .map((button) => button.textContent ?? "");
}

describe("EvidencePane: the chain of a running turn", () => {
  it("grows by each step, with the steps it builds on, and takes the statements at the end", async () => {
    const { rerender, container } = render(view(running([RULES_STEP])));
    expect(stepButtons()).toEqual(["s1 Graph query on Rulebase, Rule records..."]);
    const chain = screen.getByRole("region", { name: "Evidence chain" });
    expect(within(chain).queryByRole("group", { name: "Statements" })).not.toBeInTheDocument();
    // the picture is loaded lazily; its host is kept from here to the answer
    await waitFor(() => expect(container.querySelector(".chain-graph canvas")).not.toBeNull());
    const picture = container.querySelector(".chain-graph");

    rerender(view(running([RULES_STEP, EXPLAIN_STEP])));
    expect(stepButtons()).toEqual(["s1 Graph query on Rulebase, Rule records...", `s2 Rule ${RULE_UID} on core1`]);
    expect(
      within(screen.getByRole("region", { name: "Evidence chain" })).getByText(
        `s2 Rule ${RULE_UID} on core1 takes ${RULE_UID} from s1 Graph query on Rulebase, Rule records...`,
      ),
    ).toBeInTheDocument();

    rerender(view(DONE));
    const done = screen.getByRole("region", { name: "Evidence chain" });
    expect(within(done).getByRole("group", { name: "Statements" })).toBeInTheDocument();
    expect(container.querySelector(".chain-graph")).toBe(picture);
  });

  it("opens a step's evidence from its node while the turn runs", async () => {
    const user = userEvent.setup();
    render(view(running([RULES_STEP, EXPLAIN_STEP])));
    const chain = screen.getByRole("region", { name: "Evidence chain" });
    await user.click(within(within(chain).getByRole("group", { name: "Tool steps" })).getByRole("button", { name: /^s2 / }));
    const evidence = screen.getByRole("region", { name: "Evidence of s2" });
    expect(within(evidence).getByText(`Rule ${RULE_UID} on core1 at run 1759`)).toBeInTheDocument();
    expect(screen.getByText(/^Takes/)).toHaveTextContent(`Takes ${RULE_UID} from s1`);
  });
});

describe("EvidencePane: the tool calls", () => {
  it("are collapsed while the turn runs", () => {
    render(view(running([RULES_STEP, EXPLAIN_STEP])));
    expect(screen.getByText("2 tool calls").closest("details")).not.toHaveAttribute("open");
  });

  it("are collapsed under a complete answer", () => {
    render(view(DONE));
    expect(screen.getByText("2 tool calls").closest("details")).not.toHaveAttribute("open");
  });
});
