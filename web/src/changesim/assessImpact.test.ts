import { describe, expect, it } from "vitest";

import type { AgentStep } from "../api/types";
import {
  FIXTURE_ASSESS_IMPACT,
  FIXTURE_ASSESS_IMPACT_JSON,
  FIXTURE_CHANGE_SIMULATE_JSON,
  FIXTURE_IMPACT_ASSESS_ENVELOPE,
  FIXTURE_IMPACT_ASSESS_JSON,
  FIXTURE_INVENTORY_RESOLVE_ENVELOPE,
  FIXTURE_INVENTORY_RESOLVE_JSON,
  FIXTURE_PREDICT_ROUTES,
  FIXTURE_PREDICT_ROUTES_JSON,
  FIXTURE_RESOLVE_ADDRESS,
  FIXTURE_RESOLVE_ADDRESS_JSON,
  FIXTURE_ROUTING_PREDICT_ROUTES_JSON,
  FIXTURE_SIMULATE_POLICY_CHANGE,
  FIXTURE_SIMULATE_POLICY_CHANGE_JSON,
  catalogueEnvelope,
} from "../test/fixtures";
import {
  baselineFromContext,
  latestBaseline,
  latestPredicted,
  latestServiceImpact,
  parseAssessImpact,
  parseChangeSimulate,
  parseImpactAssess,
  parseImpactEvaluateService,
  parseInventoryResolve,
  parsePredictRoutes,
  parseResolveAddress,
  parseRoutingPredictRoutes,
  parseSimulatePolicyChange,
  unreadablePredicted,
} from "./assessImpact";

/** A chat turn as the parsers see it: a user turn has no steps. */
type Turn = { role: "user" | "assistant"; content: string; steps?: AgentStep[] };

/** One assistant turn whose steps all succeeded. */
function turn(steps: [name: string, result: string][]): Turn {
  return {
    role: "assistant",
    content: "answered",
    steps: steps.map(([name, result]) => ({ name, arguments: {}, result, is_error: false })),
  };
}

// The routing_predict_routes envelope states no per-VRF cap, and the VRF rows
// are read from its page.
const { row_limit_per_vrf: _cap, ...PREDICTED_FROM_ENVELOPE } = FIXTURE_PREDICT_ROUTES;

// A service evaluation, as impact_evaluate_service returns it in `result`.
const SERVICE_RESULT = {
  mode: "possible",
  request: {
    name: "web",
    destination: "10.0.0.10",
    sources: { count: 1, items: ["10.1.0.0/24"], truncated: false },
    members: [{ name: "web", addresses: ["10.0.0.10"] }],
    condition: { kind: "member", member: "web" },
    requirement: null,
  },
  decided_change: {
    loss: { count: 1, items: ["10.1.0.0/24"], truncated: false },
    gain: { count: 0, items: [], truncated: false },
  },
  open_change: {
    loss: { count: 1, items: ["10.1.0.0/24"], truncated: false },
    gain: { count: 0, items: [], truncated: false },
  },
  open: {
    before: { count: 0, items: [], truncated: false },
    after: { count: 0, items: [], truncated: false },
  },
  passes: {
    before: { count: 1, items: ["10.1.0.0/24"], truncated: false },
    after: { count: 0, items: [], truncated: false },
  },
  members: [],
  evidence: { count: 0, items: [], truncated: false },
  missing_evidence: [],
  gaps: [],
  model_errors: [],
};

describe("parseImpactAssess", () => {
  it("reads the device and every bucket out of an impact_assess envelope", () => {
    expect(parseImpactAssess(FIXTURE_IMPACT_ASSESS_JSON)).toEqual(FIXTURE_ASSESS_IMPACT);
  });

  it("returns null for a truncated envelope", () => {
    expect(parseImpactAssess(FIXTURE_IMPACT_ASSESS_JSON.slice(0, 200))).toBeNull();
  });

  it("returns null for a link subject, which lists no device buckets", () => {
    const link = catalogueEnvelope("impact_assess", {
      subject: "link",
      device_uid: "dev:leaf101",
      link_uid: "wan:1",
      circuit: {},
      other_circuits: [],
      buckets: { single_homed_prefixes: { count: 0, items: [], truncated: false } },
    });
    expect(parseImpactAssess(JSON.stringify(link))).toBeNull();
  });

  it("returns null for the earlier assess_impact payload, which is no envelope", () => {
    expect(parseImpactAssess(FIXTURE_ASSESS_IMPACT_JSON)).toBeNull();
  });
});

describe("parseInventoryResolve", () => {
  it("reads the address and its five sections out of an inventory_resolve envelope", () => {
    expect(parseInventoryResolve(FIXTURE_INVENTORY_RESOLVE_JSON)).toEqual(FIXTURE_RESOLVE_ADDRESS);
  });

  it("returns null for a context resolution, which names no address", () => {
    const context = catalogueEnvelope("inventory_resolve", { kind: "context", items: [] });
    expect(parseInventoryResolve(JSON.stringify(context))).toBeNull();
  });

  it("returns null for an envelope missing a section", () => {
    const envelope = FIXTURE_INVENTORY_RESOLVE_ENVELOPE;
    const { bgp_sessions: _drop, ...sections } = envelope.result.sections as Record<string, unknown>;
    const broken = { ...envelope, result: { ...envelope.result, sections } };
    expect(parseInventoryResolve(JSON.stringify(broken))).toBeNull();
  });

  it("returns null for a truncated envelope", () => {
    expect(parseInventoryResolve(FIXTURE_INVENTORY_RESOLVE_JSON.slice(0, 120))).toBeNull();
  });
});

describe("parseRoutingPredictRoutes", () => {
  it("reads the predicted VRFs and the model errors out of a routing_predict_routes envelope", () => {
    expect(parseRoutingPredictRoutes(FIXTURE_ROUTING_PREDICT_ROUTES_JSON)).toEqual(PREDICTED_FROM_ENVELOPE);
  });

  it("marks a VRF whose rows were cut, and the whole prediction with it", () => {
    const envelope = JSON.parse(FIXTURE_ROUTING_PREDICT_ROUTES_JSON);
    envelope.result.vrfs[0].rows_truncated = true;
    const parsed = parseRoutingPredictRoutes(JSON.stringify(envelope));
    expect(parsed?.vrfs[0].truncated).toBe(true);
    expect(parsed?.truncated).toBe(true);
  });

  it("returns null when model_errors is missing", () => {
    const envelope = JSON.parse(FIXTURE_ROUTING_PREDICT_ROUTES_JSON);
    delete envelope.result.model_errors;
    expect(parseRoutingPredictRoutes(JSON.stringify(envelope))).toBeNull();
  });

  it("returns null for a truncated envelope", () => {
    expect(parseRoutingPredictRoutes(FIXTURE_ROUTING_PREDICT_ROUTES_JSON.slice(0, 150))).toBeNull();
  });
});

describe("parseChangeSimulate", () => {
  it("reads the simulation and the run out of a change_simulate envelope", () => {
    expect(parseChangeSimulate(FIXTURE_CHANGE_SIMULATE_JSON)).toEqual(FIXTURE_SIMULATE_POLICY_CHANGE);
  });

  it("keeps the before-and-after next hops of an affected prefix", () => {
    const vrf = parseChangeSimulate(FIXTURE_CHANGE_SIMULATE_JSON)?.routing_consequence?.next_hop_withdrawal
      ?.vrfs[0];
    expect(vrf?.prefixes[0].next_hops_before.map((n) => n.next_hop)).toEqual([
      "192.168.2.35",
      "192.168.2.36",
    ]);
    expect(vrf?.prefixes[0].no_next_hop_left).toBe(true);
  });

  it("returns null for a truncated envelope and for the earlier payload", () => {
    expect(parseChangeSimulate(FIXTURE_CHANGE_SIMULATE_JSON.slice(0, 300))).toBeNull();
    expect(parseChangeSimulate(FIXTURE_SIMULATE_POLICY_CHANGE_JSON)).toBeNull();
  });
});

describe("parseImpactEvaluateService", () => {
  it("reads the evaluation and the run out of an impact_evaluate_service envelope", () => {
    const parsed = parseImpactEvaluateService(
      JSON.stringify(catalogueEnvelope("impact_evaluate_service", SERVICE_RESULT)),
    );
    expect(parsed?.snapshot).toBe("1724236800000");
    expect(parsed?.decided_change.loss.items).toEqual(["10.1.0.0/24"]);
  });

  it("returns null for an unresolved application connection, which carries no evaluation", () => {
    const unresolved = catalogueEnvelope("impact_evaluate_service", {
      mode: "possible",
      application_connection: { readiness: "unresolved", issues: [] },
    });
    expect(parseImpactEvaluateService(JSON.stringify(unresolved))).toBeNull();
  });
});

describe("latestBaseline", () => {
  it("finds an inventory_resolve step", () => {
    const turns = [turn([["inventory_resolve", FIXTURE_INVENTORY_RESOLVE_JSON]])];
    expect(latestBaseline(turns)).toEqual({ tool: "resolve_address", address: FIXTURE_RESOLVE_ADDRESS });
  });

  it("finds an impact_assess step", () => {
    const turns = [turn([["impact_assess", FIXTURE_IMPACT_ASSESS_JSON]])];
    expect(latestBaseline(turns)).toEqual({ tool: "assess_impact", impact: FIXTURE_ASSESS_IMPACT });
  });

  it("takes the most recent call across the two tools", () => {
    const turns = [
      turn([["impact_assess", FIXTURE_IMPACT_ASSESS_JSON]]),
      turn([["inventory_resolve", FIXTURE_INVENTORY_RESOLVE_JSON]]),
    ];
    expect(latestBaseline(turns)).toEqual({ tool: "resolve_address", address: FIXTURE_RESOLVE_ADDRESS });
  });

  it("ignores a failed inventory_resolve call and falls back to the earlier result", () => {
    const turns = [
      turn([["impact_assess", FIXTURE_IMPACT_ASSESS_JSON]]),
      {
        role: "assistant" as const,
        content: "not an address",
        steps: [
          {
            name: "inventory_resolve",
            arguments: {},
            result: "ToolError: 'leaf101' is not an IP address",
            is_error: true,
          },
        ],
      },
    ];
    expect(latestBaseline(turns)).toEqual({ tool: "assess_impact", impact: FIXTURE_ASSESS_IMPACT });
  });

  it("ignores a routing_predict_routes step: it fills the other pane", () => {
    expect(latestBaseline([turn([["routing_predict_routes", FIXTURE_ROUTING_PREDICT_ROUTES_JSON]])])).toBeNull();
  });
});

describe("latestPredicted", () => {
  it("finds a routing_predict_routes step", () => {
    const turns = [turn([["routing_predict_routes", FIXTURE_ROUTING_PREDICT_ROUTES_JSON]])];
    expect(latestPredicted(turns)).toEqual({ tool: "predict_routes", routes: PREDICTED_FROM_ENVELOPE });
  });

  it("finds a change_simulate step", () => {
    const turns = [turn([["change_simulate", FIXTURE_CHANGE_SIMULATE_JSON]])];
    expect(latestPredicted(turns)).toEqual({
      tool: "simulate_policy_change",
      policy: FIXTURE_SIMULATE_POLICY_CHANGE,
    });
  });

  it("finds an impact_assess step", () => {
    const turns = [turn([["impact_assess", FIXTURE_IMPACT_ASSESS_JSON]])];
    expect(latestPredicted(turns)).toEqual({ tool: "assess_impact", impact: FIXTURE_ASSESS_IMPACT });
  });

  it("takes the most recent call across the tools", () => {
    const turns = [
      turn([["routing_predict_routes", FIXTURE_ROUTING_PREDICT_ROUTES_JSON]]),
      turn([["impact_assess", FIXTURE_IMPACT_ASSESS_JSON]]),
    ];
    expect(latestPredicted(turns)).toEqual({ tool: "assess_impact", impact: FIXTURE_ASSESS_IMPACT });
  });

  it("skips a truncated change_simulate result", () => {
    const turns = [turn([["change_simulate", FIXTURE_CHANGE_SIMULATE_JSON.slice(0, 120)]])];
    expect(latestPredicted(turns)).toBeNull();
  });

  it("ignores an inventory_resolve step: it fills the other pane", () => {
    expect(latestPredicted([turn([["inventory_resolve", FIXTURE_INVENTORY_RESOLVE_JSON]])])).toBeNull();
  });
});

describe("baselineFromContext", () => {
  it("reads an address the server resolved, with no pane step in the turn at all", () => {
    const turns = [
      {
        ...turn([["query_cypher", "{}"]]),
        context: [
          {
            kind: "address" as const,
            subject: "192.168.2.35",
            tool: "inventory_resolve" as const,
            result: FIXTURE_INVENTORY_RESOLVE_ENVELOPE,
          },
        ],
      },
    ];
    expect(baselineFromContext(turns)).toEqual({ tool: "resolve_address", address: FIXTURE_RESOLVE_ADDRESS });
  });

  it("reads a device the server assessed", () => {
    const turns = [
      {
        role: "assistant" as const,
        content: "here is what that device carries",
        context: [
          {
            kind: "device" as const,
            subject: "dev:leaf101",
            tool: "impact_assess" as const,
            result: FIXTURE_IMPACT_ASSESS_ENVELOPE,
          },
        ],
      },
    ];
    expect(baselineFromContext(turns)).toEqual({ tool: "assess_impact", impact: FIXTURE_ASSESS_IMPACT });
  });

  it("takes the most recent turn that carries any context", () => {
    const turns = [
      {
        role: "assistant" as const,
        content: "first",
        context: [
          {
            kind: "device" as const,
            subject: "dev:leaf101",
            tool: "impact_assess" as const,
            result: FIXTURE_IMPACT_ASSESS_ENVELOPE,
          },
        ],
      },
      { role: "assistant" as const, content: "second", context: [] },
      {
        role: "assistant" as const,
        content: "third",
        context: [
          {
            kind: "address" as const,
            subject: "192.168.2.35",
            tool: "inventory_resolve" as const,
            result: FIXTURE_INVENTORY_RESOLVE_ENVELOPE,
          },
        ],
      },
    ];
    expect(baselineFromContext(turns)).toEqual({ tool: "resolve_address", address: FIXTURE_RESOLVE_ADDRESS });
  });

  it("skips an entry whose payload is not the tool's envelope", () => {
    const turns = [
      {
        role: "assistant" as const,
        content: "two entities, one of them unreadable",
        context: [
          {
            kind: "address" as const,
            subject: "192.168.2.35",
            tool: "inventory_resolve" as const,
            result: { address: "192.168.2.35" },
          },
          {
            kind: "device" as const,
            subject: "dev:leaf101",
            tool: "impact_assess" as const,
            result: FIXTURE_IMPACT_ASSESS_ENVELOPE,
          },
        ],
      },
    ];
    expect(baselineFromContext(turns)).toEqual({ tool: "assess_impact", impact: FIXTURE_ASSESS_IMPACT });
  });

  it("is null for turns that carry no context", () => {
    const turns = [{ ...turn([["impact_assess", FIXTURE_IMPACT_ASSESS_JSON]]), context: [] }];
    expect(baselineFromContext(turns)).toBeNull();
    expect(latestBaseline(turns)).toEqual({ tool: "assess_impact", impact: FIXTURE_ASSESS_IMPACT });
  });
});

describe("latestServiceImpact", () => {
  it("finds an impact_evaluate_service step", () => {
    const envelope = JSON.stringify(catalogueEnvelope("impact_evaluate_service", SERVICE_RESULT));
    expect(latestServiceImpact([turn([["impact_evaluate_service", envelope]])])?.mode).toBe("possible");
  });
});

describe("unreadablePredicted", () => {
  it("names the tool whose newest result could not be read", () => {
    const turns = [turn([["change_simulate", FIXTURE_CHANGE_SIMULATE_JSON.slice(0, 120)]])];
    expect(unreadablePredicted(turns)).toBe("change_simulate");
  });

  it("names nothing when the newest result parses", () => {
    expect(unreadablePredicted([turn([["change_simulate", FIXTURE_CHANGE_SIMULATE_JSON]])])).toBeNull();
  });

  it("ignores steps no pane parses, and turns with no steps at all", () => {
    expect(unreadablePredicted([{}])).toBeNull();
    expect(unreadablePredicted([turn([["query_cypher", "not json"]])])).toBeNull();
  });

  it("does not throw on a result that is not JSON at all", () => {
    expect(unreadablePredicted([turn([["routing_predict_routes", "<html>gateway timeout"]])])).toBe(
      "routing_predict_routes",
    );
  });
});

describe("steps stored under the earlier tool names", () => {
  it("fill the panes from the payload each earlier tool returned", () => {
    expect(latestBaseline([turn([["resolve_address", FIXTURE_RESOLVE_ADDRESS_JSON]])])).toEqual({
      tool: "resolve_address",
      address: FIXTURE_RESOLVE_ADDRESS,
    });
    expect(latestPredicted([turn([["predict_routes", FIXTURE_PREDICT_ROUTES_JSON]])])).toEqual({
      tool: "predict_routes",
      routes: FIXTURE_PREDICT_ROUTES,
    });
    expect(latestPredicted([turn([["simulate_policy_change", FIXTURE_SIMULATE_POLICY_CHANGE_JSON]])])).toEqual({
      tool: "simulate_policy_change",
      policy: FIXTURE_SIMULATE_POLICY_CHANGE,
    });
    expect(latestBaseline([turn([["assess_impact", FIXTURE_ASSESS_IMPACT_JSON]])])).toEqual({
      tool: "assess_impact",
      impact: FIXTURE_ASSESS_IMPACT,
    });
  });

  it("read a stored context entry of the earlier tools", () => {
    const turns = [
      {
        role: "assistant" as const,
        content: "stored answer",
        context: [
          {
            kind: "device" as const,
            subject: "dev:leaf101",
            tool: "assess_impact" as const,
            result: FIXTURE_ASSESS_IMPACT,
          },
        ],
      },
    ];
    expect(baselineFromContext(turns)).toEqual({ tool: "assess_impact", impact: FIXTURE_ASSESS_IMPACT });
  });
});

describe("parseAssessImpact, the earlier payload", () => {
  it("parses a well-formed result", () => {
    expect(parseAssessImpact(FIXTURE_ASSESS_IMPACT_JSON)).toEqual(FIXTURE_ASSESS_IMPACT);
  });

  it("returns null for invalid JSON: a truncated tool result must not throw", () => {
    expect(parseAssessImpact(FIXTURE_ASSESS_IMPACT_JSON.slice(0, 200))).toBeNull();
  });

  it("returns null for JSON missing an expected bucket or the device", () => {
    const { fhrp_groups: _drop, ...withoutFhrp } = FIXTURE_ASSESS_IMPACT;
    expect(parseAssessImpact(JSON.stringify(withoutFhrp))).toBeNull();
    const { device: _device, ...withoutDevice } = FIXTURE_ASSESS_IMPACT;
    expect(parseAssessImpact(JSON.stringify(withoutDevice))).toBeNull();
    expect(parseAssessImpact("[]")).toBeNull();
  });
});

describe("parseResolveAddress, the earlier payload", () => {
  it("parses a well-formed result, and a result whose sections are all empty", () => {
    expect(parseResolveAddress(FIXTURE_RESOLVE_ADDRESS_JSON)).toEqual(FIXTURE_RESOLVE_ADDRESS);
    const empty = {
      ...FIXTURE_RESOLVE_ADDRESS,
      ip_nodes: [],
      endpoints: [],
      interfaces: [],
      bgp_sessions: [],
      next_hop_routes: [],
    };
    expect(parseResolveAddress(JSON.stringify(empty))).toEqual(empty);
  });

  it("returns null for a truncated result, a missing section and a device assessment", () => {
    expect(parseResolveAddress(FIXTURE_RESOLVE_ADDRESS_JSON.slice(0, 120))).toBeNull();
    const { bgp_sessions: _drop, ...withoutSessions } = FIXTURE_RESOLVE_ADDRESS;
    expect(parseResolveAddress(JSON.stringify(withoutSessions))).toBeNull();
    expect(parseResolveAddress(FIXTURE_ASSESS_IMPACT_JSON)).toBeNull();
  });
});

describe("parsePredictRoutes, the earlier payload", () => {
  it("parses a well-formed result", () => {
    expect(parsePredictRoutes(FIXTURE_PREDICT_ROUTES_JSON)).toEqual(FIXTURE_PREDICT_ROUTES);
  });

  it("returns null without model_errors, for a VRF without rows and for a truncated result", () => {
    const { model_errors: _drop, ...withoutErrors } = FIXTURE_PREDICT_ROUTES;
    expect(parsePredictRoutes(JSON.stringify(withoutErrors))).toBeNull();
    const broken = {
      ...FIXTURE_PREDICT_ROUTES,
      vrfs: [{ context_uid: "vrf:leaf101:default", row_count: 2, truncated: false }],
    };
    expect(parsePredictRoutes(JSON.stringify(broken))).toBeNull();
    expect(parsePredictRoutes(FIXTURE_PREDICT_ROUTES_JSON.slice(0, 150))).toBeNull();
  });
});

describe("parseSimulatePolicyChange, the payload a change simulation holds", () => {
  it("parses a well-formed result and rejects one of another shape", () => {
    expect(parseSimulatePolicyChange(FIXTURE_SIMULATE_POLICY_CHANGE_JSON)).toEqual(
      FIXTURE_SIMULATE_POLICY_CHANGE,
    );
    expect(parseSimulatePolicyChange(FIXTURE_SIMULATE_POLICY_CHANGE_JSON.slice(0, 300))).toBeNull();
    expect(parseSimulatePolicyChange("[]")).toBeNull();
    expect(parseSimulatePolicyChange('{"flows": []}')).toBeNull();
  });

  it("carries the paths as structure and the counts as numbers", () => {
    const parsed = parseSimulatePolicyChange(FIXTURE_SIMULATE_POLICY_CHANGE_JSON);
    expect(parsed?.paths_blocked_after).toBe(2);
    expect(parsed?.path_count_after).toBe(4);
    expect(parsed?.paths_changed).toBe(2);

    const paths = parsed?.flows[0].paths;
    expect(paths?.path_count_before).toBe(3);
    expect(paths?.blocked_after).toBe(2);
    // the equal-cost pair is one row standing for two paths, and the next hops
    // are what tells them apart
    expect(paths?.groups[0].path_count).toBe(2);
    expect(paths?.groups[0].next_hops).toEqual(["10.0.0.1", "10.0.0.2"]);
    expect(paths?.groups[0].after?.decided_by).toBe("LAN policy (LAN>WAN) drop by rule 10");
    // and a path the change does not decide says which rulebase did
    expect(paths?.groups[1].note).toBe("decided by fw:core1:INTRA, which this change does not alter");
  });

  it("reads a result that carries no paths", () => {
    const older = JSON.stringify({
      ...FIXTURE_SIMULATE_POLICY_CHANGE,
      flows: FIXTURE_SIMULATE_POLICY_CHANGE.flows.map((flow) => {
        const copy = { ...flow };
        delete copy.paths;
        return copy;
      }),
    });
    const parsed = parseSimulatePolicyChange(older);
    expect(parsed?.flows[0].paths).toBeUndefined();
    expect(parsed?.flow_count).toBe(2);
  });

  it("reads the per-level counts and the limit that stopped the withdrawal walk", () => {
    const parsed = parseSimulatePolicyChange(
      JSON.stringify({
        ...FIXTURE_SIMULATE_POLICY_CHANGE,
        routing_consequence: {
          ...FIXTURE_SIMULATE_POLICY_CHANGE.routing_consequence,
          walk: {
            depth_requested: 2,
            depth: 2,
            depth_cap: 8,
            depth_clamped: false,
            levels_walked: 2,
            level_count: 2,
            complete: false,
            limits: ["depth", "site_boundary"],
            prefixes_not_followed_at_the_depth_limit: 1,
            prefixes_not_followed_at_the_site_boundary: 3,
            levels: [
              {
                level: 1,
                prefix_count: 2,
                prefixes_with_no_next_hop_left: 1,
                withdrawn_route_edge_count: 3,
                vrf_count: 1,
                sample: ["10.10.10.1/32 in vrf:a"],
                sample_truncated: false,
              },
              {
                level: 2,
                prefix_count: 1,
                prefixes_with_no_next_hop_left: 1,
                withdrawn_route_edge_count: 1,
                vrf_count: 1,
                sample: ["172.16.0.0/16 in vrf:a"],
                sample_truncated: false,
              },
            ],
          },
          site_scope: {
            sites_requested: ["HQ"],
            sites_resolved: ["site:hq"],
            sites_not_found: [],
            stopped_the_walk: true,
            prefixes_not_followed: 3,
          },
        },
      }),
    );
    const walk = parsed?.routing_consequence?.walk;
    expect(walk?.complete).toBe(false);
    expect(walk?.limits).toEqual(["depth", "site_boundary"]);
    expect(walk?.levels?.map((l) => l.prefix_count)).toEqual([2, 1]);
    expect(parsed?.routing_consequence?.site_scope?.prefixes_not_followed).toBe(3);
  });

  it("reads a result that carries no walk", () => {
    const parsed = parseSimulatePolicyChange(FIXTURE_SIMULATE_POLICY_CHANGE_JSON);
    expect(parsed?.routing_consequence?.walk).toBeUndefined();
    expect(parsed?.routing_consequence?.site_scope).toBeUndefined();
    expect(parsed?.flow_count).toBe(2);
  });
});
