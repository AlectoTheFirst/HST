import { describe, expect, it } from "vitest";
import { buildsOn, evidenceChain } from "./chain";
import { CHAIN_ANSWER, CHAIN_ENVELOPE, EXPLAIN_STEP, RULE_UID, RULES_STEP } from "../test/chainFixture";

const ids = (items: { id: string }[]) => items.map((item) => item.id).sort();

describe("evidenceChain", () => {
  it("draws statements, steps, records and objects of the whole answer, and the step that builds on another", () => {
    const { chain, objects } = evidenceChain({
      content: CHAIN_ANSWER,
      envelope: CHAIN_ENVELOPE,
      steps: [RULES_STEP, EXPLAIN_STEP],
      turnSteps: ["s1", "s2"],
    });

    expect(ids(chain.nodes)).toEqual(
      [
        "statement:c1",
        "statement:c2",
        "step:s1",
        "step:s2",
        "record:s1:/result/data/0",
        "record:s2:/result/rule",
        // the rulebase and the rule the supporting row names
        "object:uid:vyos:core1:fw:LAN-WAN",
        `object:uid:${RULE_UID}`,
        "object:graph_node:dev:core1",
        "object:run:1759",
      ].sort(),
    );
    // the reading order: statements, steps, records, objects
    expect(chain.nodes.map((node) => node.kind)).toEqual([
      "statement",
      "statement",
      "step",
      "step",
      "record",
      "record",
      "object",
      "object",
      "object",
      "object",
    ]);
    expect(chain.nodes.find((node) => node.id === "statement:c1")?.label).toBe("Rule 10 on core1 drops the flow.");
    expect(chain.nodes.find((node) => node.id === "step:s2")?.label).toBe(`s2 Rule ${RULE_UID} on core1`);

    expect(chain.edges.map((edge) => [edge.source, edge.target, edge.kind]).sort()).toEqual(
      [
        ["statement:c1", "step:s2", "cites"],
        ["statement:c2", "step:s1", "cites"],
        ["step:s1", "step:s2", "builds-on"],
        ["step:s1", "record:s1:/result/data/0", "returned"],
        ["step:s2", "record:s2:/result/rule", "returned"],
        ["record:s1:/result/data/0", "object:uid:vyos:core1:fw:LAN-WAN", "names"],
        ["record:s1:/result/data/0", `object:uid:${RULE_UID}`, "names"],
        ["record:s2:/result/rule", `object:uid:${RULE_UID}`, "names"],
        ["step:s2", "object:graph_node:dev:core1", "names"],
        ["step:s1", "object:run:1759", "names"],
        ["step:s2", "object:run:1759", "names"],
      ].sort(),
    );
    expect(chain.edges.find((edge) => edge.kind === "builds-on")?.value).toBe(RULE_UID);
    expect(objects.get(`uid:${RULE_UID}`)?.uid).toBe(RULE_UID);
    expect(objects.get("graph_node:dev:core1")?.link?.label).toBe("Object dev:core1");
    expect(objects.get("run:1759")?.run).toBe("1759");
  });

  it("draws one statement with its steps and the steps they build on", () => {
    const { chain } = evidenceChain({
      content: CHAIN_ANSWER,
      envelope: CHAIN_ENVELOPE,
      steps: [RULES_STEP, EXPLAIN_STEP],
      turnSteps: ["s1", "s2"],
      claim: "c1",
    });

    expect(ids(chain.nodes)).toEqual(
      [
        "statement:c1",
        "step:s1",
        "step:s2",
        "record:s2:/result/rule",
        `object:uid:${RULE_UID}`,
        "object:graph_node:dev:core1",
        "object:run:1759",
      ].sort(),
    );
    expect(chain.nodes.find((node) => node.id === "record:s2:/result/rule")?.target).toEqual({
      step: "s2",
      pointer: "/result/rule",
    });
  });
});

describe("buildsOn", () => {
  it("links a step to the earlier step whose returned value its arguments use", () => {
    expect(buildsOn(RULES_STEP, EXPLAIN_STEP)).toBe(RULE_UID);
    expect(buildsOn(EXPLAIN_STEP, RULES_STEP)).toBeUndefined();
  });

  it("takes no value the earlier step was given, and no plain word", () => {
    const given = { ...EXPLAIN_STEP, id: "st3", step: "s3", arguments: { mode: "explain_rule", rule: "accept" } };
    expect(buildsOn(EXPLAIN_STEP, { ...given, arguments: { rule: RULE_UID } })).toBeUndefined();
    expect(buildsOn(RULES_STEP, given)).toBeUndefined();
  });
});
