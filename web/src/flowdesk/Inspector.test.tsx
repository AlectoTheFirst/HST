import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { Inspector } from "./Inspector";
import { FIXTURE_PATH_BLOCKED } from "../test/fixtures";
import type { ResultValue } from "../results/text";

const FIRST_MATCH: ResultValue = { kind: "result", statement: "rule-first-match", answer: "true", word: "first match", quantifier: null, condition: null, missing: [] };
const NOT_DECIDED: ResultValue = {
  kind: "result", statement: "rule-first-match", answer: "open", word: "not decided", quantifier: null, condition: null,
  missing: [{ code: "match-not-decided", subject: "voice", detail: "DSCP not decided" }],
};

describe("Inspector SD-WAN rules", () => {
  it("shows the business policy rules of the selected leg as a table", () => {
    const leg = {
      ...FIXTURE_PATH_BLOCKED.legs[0],
      sdwan_rules: [
        { position: 1, name: "voice", result: NOT_DECIDED, undecided: "DSCP", action: "backhaul", candidates: 2 },
        { position: 2, name: "internet", result: FIRST_MATCH, undecided: "", action: "direct", candidates: 1 },
      ],
    };
    render(
      <Inspector
        selection={{ type: "leg", data: leg }}
        result={{ ...FIXTURE_PATH_BLOCKED, legs: [leg] }}
        open
        onToggle={() => {}}
      />,
    );
    const table = screen.getByRole("table", { name: "SD-WAN business policy rules" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.textContent)).toEqual(["1voicenot decidedDSCPbackhaul2", "2internetfirst matchdirect1"]);
  });
});
