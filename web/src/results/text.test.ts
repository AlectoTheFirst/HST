import { describe, expect, it } from "vitest";

import { missingText, modeText, resultText, testedText } from "./text";

describe("the result vocabulary on the pages", () => {
  it("prefers the server's result word and writes the tested and missing lines", () => {
    const result = {
      kind: "result" as const,
      statement: "condition-holds",
      answer: "open",
      word: "not decided",
      quantifier: "every" as const,
      condition: "forward" as const,
      missing: [{ code: "MODEL_SCOPE_INCOMPLETE", subject: "dev:leaf101", detail: "the fabric policy was not collected" }, { code: "capacity-not-modelled" }],
    };
    expect(resultText(result)).toBe("not decided");
    expect(testedText(result)).toBe("Tested: the forward flow, counts as passing only if every path and member works.");
    expect(missingText(result)).toBe("Not decided: dev:leaf101: the fabric policy was not collected; the capacity condition is declared, not calculated.");
    expect(missingText({ word: "passes", missing: [] })).toBeNull();
    expect(testedText(null)).toBeNull();
  });

  it("writes the mode as the strictness of the question", () => {
    expect(modeText("possible")).toBe("counts as passing if one path or member works");
    expect(modeText("guaranteed")).toBe("counts as passing only if every path and member works");
  });
});
