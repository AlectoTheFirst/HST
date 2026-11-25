/**
 * A test fixture: an answer with two tool steps, where the second step takes
 * a rule uid the first one returned. Used by ai/chain.test.ts and
 * shell/AgentDrawer.panes.test.tsx.
 */

import type { AnswerEnvelope } from "../api/types";

export const RULE_UID = "vyos:core1:fw:LAN-WAN:10";

export const CHAIN_ANSWER = "Rule 10 on core1 drops the flow [s2]. LAN-WAN holds two rules.";

const QUERY =
  "MATCH (rb:Rulebase {name: 'LAN-WAN'})-[r:HAS_RULE]->(rule:Rule) RETURN rb.uid, type(r), rule.uid, rule.action";

export const RULES_STEP = {
  id: "st1",
  step: "s1",
  name: "query_cypher",
  arguments: { query: QUERY },
  result: JSON.stringify({
    snapshot: { id: "1759" },
    result: {
      columns: ["rb.uid", "type(r)", "rule.uid", "rule.action"],
      data: [
        { row: ["vyos:core1:fw:LAN-WAN", "HAS_RULE", RULE_UID, "drop"] },
        { row: ["vyos:core1:fw:LAN-WAN", "HAS_RULE", "vyos:core1:fw:LAN-WAN:20", "accept"] },
      ],
    },
  }),
  is_error: false,
};

export const EXPLAIN_STEP = {
  id: "st2",
  step: "s2",
  name: "policy_evaluate",
  arguments: { mode: "explain_rule", rule: RULE_UID, device: "core1" },
  result: JSON.stringify({ snapshot: { id: "1759" }, result: { rule: { uid: RULE_UID, action: "drop" } } }),
  is_error: false,
};

export const CHAIN_ENVELOPE: AnswerEnvelope = {
  version: 2,
  message_id: "m1",
  conversation_id: "c1",
  kind: "answer",
  snapshot: { id: "1759", origin: "pointer" },
  model: { provider: "anthropic", requested: "claude-opus-5" },
  prompt_hash: "h",
  tools_used: [
    { step: "s1", step_id: "st1", tool: "query_cypher", version: 1, is_error: false, snapshot: "1759" },
    { step: "s2", step_id: "st2", tool: "policy_evaluate", version: 1, is_error: false, snapshot: "1759" },
  ],
  answer_markdown: CHAIN_ANSWER,
  claims: [
    {
      id: "c1",
      span: [0, 37],
      citations: ["s2"],
      citation_status: "cited",
      support: [{ step: "s2", pointer: "/result/rule" }],
    },
    {
      id: "c2",
      span: [38, 62],
      citations: [],
      citation_status: "matched",
      support: [{ step: "s1", pointer: "/result/data/0" }],
    },
  ],
  grounding: { status: "grounded", cited: 1, uncited: 0, invalid: 0, cross_snapshot: 0, matched: 1 },
  links: [
    { kind: "step", ref_id: "st1", step: "s1" },
    { kind: "step", ref_id: "st2", step: "s2" },
    { kind: "graph_node", ref_id: "dev:core1", step: "s2" },
  ],
};
