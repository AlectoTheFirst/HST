import { describe, expect, it } from "vitest";
import { connection, path } from "../netmap/flowFixture";
import type { ResultValue } from "../results/text";
import { outcomeOf, shownState, STATE_TEXT, type FlowConnection } from "./flows";

const result = (answer: string, word: string): ResultValue => ({
  kind: "result",
  statement: "condition-holds",
  answer,
  word,
  quantifier: "every",
  condition: "forward",
  missing: answer === "open" ? [{ code: "not-decided", subject: "dev:core1", detail: "the route table was not collected" }] : [],
});

describe("the flows body read from result", () => {
  it("keys a path on result.answer: true passes, false fails, open is not decided", () => {
    expect(outcomeOf(result("true", "passes"))).toBe("passes");
    expect(outcomeOf(result("false", "fails"))).toBe("fails");
    expect(outcomeOf(result("open", "not decided"))).toBe("open");
    expect(outcomeOf(null)).toBe("open");
  });

  it("shows an evaluated connection by the answer of its result", () => {
    const body: FlowConnection = { ...connection({ id: "web" }), state: "evaluated", result: result("false", "fails") };
    expect(body).not.toHaveProperty("outcome");
    expect(shownState(body)).toBe("fails");
    expect(STATE_TEXT[shownState(body)]).toBe("Fails");
    expect(STATE_TEXT[shownState({ ...body, result: result("open", "not decided") })]).toBe("Not decided");
    expect(STATE_TEXT[shownState({ ...body, result: result("true", "passes") })]).toBe("Passes");
  });

  it("shows an unresolved or not evaluated connection by its state, with a null result", () => {
    const unresolved = connection({ id: "api", state: "unresolved" });
    const waiting = connection({ id: "db", state: "not-evaluated" });
    expect(unresolved.result).toBeNull();
    expect(waiting.result).toBeNull();
    expect(shownState(unresolved)).toBe("unresolved");
    expect(STATE_TEXT[shownState(waiting)]).toBe("Not evaluated");
  });

  it("builds a path that carries result and no outcome", () => {
    const failing = path({ devices: ["a", "b"], answer: "fails" });
    expect(failing).not.toHaveProperty("outcome");
    expect(failing.result.answer).toBe("false");
    expect(outcomeOf(failing.result)).toBe("fails");
  });
});
