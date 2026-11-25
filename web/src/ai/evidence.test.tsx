import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import type { AnswerClaim, AnswerEnvelope } from "../api/types";
import { citationView } from "./citations";
import { EvidenceView, lookupSentence, resolvePointer } from "./evidence";

function envelope(answer: string, claims: AnswerClaim[], steps: Record<string, string>): AnswerEnvelope {
  return {
    version: 2,
    message_id: "m1",
    conversation_id: "c1",
    kind: "answer",
    snapshot: { id: "1759", origin: "pointer", others_used: [] },
    model: { provider: "anthropic", requested: "claude-opus-5" },
    prompt_hash: "h",
    tools_used: [],
    answer_markdown: answer,
    claims,
    grounding: { status: "grounded", cited: 1, uncited: 0, invalid: 0, cross_snapshot: 0, matched: 1, process: 0 },
    links: Object.entries(steps).map(([step, id]) => ({ kind: "step", ref_id: id, step })),
  };
}

describe("lookupSentence", () => {
  it("names what a step looked up, with its run", () => {
    expect(
      lookupSentence("policy_evaluate", { mode: "explain_rule", rulebase: "LAN-WAN", rule: "10", device: "core1" }, "1759", {}),
    ).toBe("Rule 10 of rulebase LAN-WAN on core1 at run 1759");
    expect(lookupSentence("routing_routes", { mode: "lookup", address: "192.0.2.10", device: "core1" }, null, {})).toBe(
      "Route lookup for 192.0.2.10 on core1",
    );
    expect(
      lookupSentence("reach_trace", { mode: "path", flow: { src: "192.168.2.45", dst: "198.51.100.10" } }, "1759", {}),
    ).toBe("Path trace from 192.168.2.45 to 198.51.100.10 at run 1759");
    expect(lookupSentence("query_cypher", { query: "MATCH (d:Device) RETURN d.hostname" }, "1759", { columns: ["d.hostname"] })).toBe(
      "Graph query on Device records, returning d.hostname at run 1759",
    );
    expect(lookupSentence("some_new_tool", {}, null, {})).toBe("Tool some_new_tool");
  });
});

describe("resolvePointer", () => {
  it("reads an RFC 6901 pointer", () => {
    const root = { result: { data: [{ row: [1] }, { row: [2] }], "a/b": { "c~d": 3 } } };
    expect(resolvePointer(root, "/result/data/1")).toEqual({ row: [2] });
    expect(resolvePointer(root, "/result/a~1b/c~0d")).toBe(3);
    expect(resolvePointer(root, "/result/missing/0")).toBeUndefined();
    expect(resolvePointer(root, "")).toBe(root);
  });
});

describe("citationView", () => {
  it("tags each marker with its statement and gives a chip to a statement without one in its text", () => {
    const answer = "- Rules of LAN-WAN [s1]\n  - rule 10 drops\n\nrule 20 accepts.";
    const view = citationView(
      answer,
      envelope(
        answer,
        [
          { id: "c1", span: [2, 23], citations: ["s1"], citation_status: "cited" },
          // a nested item takes the markers of its parent
          { id: "c2", span: [28, 41], citations: ["s1"], citation_status: "cited" },
          {
            id: "c3",
            span: [43, 59],
            citations: [],
            citation_status: "matched",
            support: [
              { step: "s2", pointer: "/result/data/1" },
              { step: "s2", pointer: "/result/data/2" },
            ],
          },
        ],
        { s1: "st1", s2: "st2" },
      ),
    );
    expect(view.text).toBe(
      "- Rules of LAN-WAN c1[s1]\n  - rule 10 dropsc2[s1]\n\nrule 20 accepts.c3[s2]",
    );
    expect(view.unsupported).toEqual([]);
  });

  it("marks the unsupported statements only when asked, and reads no tag from the answer itself", () => {
    const answer = "fw1 denies it. sw2 forwards it.";
    const claims: AnswerClaim[] = [
      { id: "c1", span: [0, 14], citations: [], citation_status: "uncited" },
      { id: "c2", span: [16, 32], citations: [], citation_status: "process" },
    ];
    expect(citationView(answer, envelope(answer, claims, {})).text).toBe("fw1 denies it.� sw2 forwards it.");
    const marked = citationView(answer, envelope(answer, claims, {}), true);
    expect(marked.text).toBe("fw1 denies it.� sw2 forwards it.");
    expect(marked.unsupported.map((claim) => claim.id)).toEqual(["c1"]);
  });
});

describe("EvidenceView", () => {
  it("shows the summary of a compacted step as the record that supports the statement", () => {
    const claim: AnswerClaim = {
      id: "c1",
      span: [0, 24],
      citations: [],
      citation_status: "matched",
      support: [{ step: "s1", pointer: null }],
    };
    render(
      <MemoryRouter>
        <EvidenceView
        label="s1"
        stepId="st1"
        claim={claim}
        step={{ id: "st1", step: "s1", name: "reach_trace", arguments: { mode: "path" }, result: "verdict=deny; items: fw1", is_error: false }}
        envelope={envelope("fw1 would deny the flow.", [claim], { s1: "st1" })}
        onClose={() => undefined}
        />
      </MemoryRouter>,
    );
    const evidence = screen.getByRole("region", { name: "Evidence of s1" });
    expect(within(evidence).getByText("verdict=deny; items: fw1", { selector: "p" })).toHaveClass("evidence-record", "supporting");
    expect(within(evidence).getByText("Details").closest("details")).not.toHaveAttribute("open");
  });

  it("marks a step whose result is not loaded", () => {
    render(
      <MemoryRouter>
        <EvidenceView
        label="s1"
        stepId="st1"
        envelope={envelope("fw1 denies it [s1].", [], { s1: "st1" })}
        onClose={() => undefined}
        />
      </MemoryRouter>,
    );
    expect(screen.getByText("Result not loaded")).toBeInTheDocument();
    expect(screen.queryByText("Details")).not.toBeInTheDocument();
  });
});
