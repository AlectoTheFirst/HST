import { describe, expect, it } from "vitest";
import { reduce, initial, panes } from "../workspace/layout";
import { serviceDraft, traceDraft } from "./context";

const bucket = { count: 0, items: [], truncated: false };
const answer = {
  snapshot: "2000",
  mode: "guaranteed",
  request: { name: "Payment", sources: bucket, members: [], condition: {} },
  decided_change: { loss: bucket },
  open_change: { loss: bucket },
  open: { before: bucket, after: bucket },
  missing_evidence: [],
  members: [],
};
const request = {
  name: "Payment",
  destination: "app",
  sources: ["10.0.0.0/24"],
  members: [
    {
      name: "app",
      addresses: ["192.0.2.0/24"],
      proto: "tcp",
      port: "443",
      source_port: "1024-65535",
    },
  ],
  condition: { kind: "member", member: "app" },
  success: "session",
  identity_uid: "identity:alice",
  source_context: "vrf:blue",
};

describe("contextual assessments", () => {
  it("pins trace result identity and preserves unspecified destination port and reply semantics", () => {
    const draft = traceDraft(
      { src: "10.0.0.1", dst: "192.0.2.1", port: "", proto: "tcp", reply: true },
      "1234",
    )!;
    expect(draft.definition).toMatchObject({
      snapshot: "1234",
      request: { port: null, success: "session", sources: ["10.0.0.1"] },
    });
    expect(
      traceDraft({ src: "a", dst: "b", port: "", proto: "tcp", reply: false }, undefined),
    ).toBeNull();
  });
  it("preserves the full service request, context, ordered intents and exact snapshot independently of summary buckets", () => {
    const intents = [{ kind: "fw_rule.modify", params: { uid: "rule:7", action: "accept" } }];
    const draft = serviceDraft([
      {
        steps: [
          {
            name: "evaluate_service_impact",
            arguments: { request, intents },
            result: JSON.stringify(answer),
            is_error: false,
          },
        ],
      },
    ])!;
    expect(draft.definition).toMatchObject({
      request,
      intents,
      mode: "guaranteed",
      snapshot: "2000",
    });
    draft.definition.request!.members[0].port = "80";
    expect(request.members[0].port).toBe("443");
  });
  it("normalizes equivalent nested condition spellings for the editor", () => {
    const aliased = {
      ...request,
      condition: {
        kind: "every",
        parts: [{ kind: "n-of-m", n: 1, parts: [{ kind: "member", member: "app" }] }],
      },
    };
    const draft = serviceDraft([
      {
        steps: [
          {
            name: "evaluate_service_impact",
            arguments: { request: aliased },
            result: JSON.stringify(answer),
            is_error: false,
          },
        ],
      },
    ])!;
    expect(draft.definition.request!.condition).toEqual({
      kind: "and",
      parts: [{ kind: "threshold", n: 1, parts: [{ kind: "member", member: "app" }] }],
    });
  });
  it("refuses to invent a service request from a lossy result summary", () => {
    expect(
      serviceDraft([
        {
          steps: [
            {
              name: "evaluate_service_impact",
              arguments: {},
              result: JSON.stringify(answer),
              is_error: false,
            },
          ],
        },
      ]),
    ).toBeNull();
  });
  it("carries the draft into its pane and clears it when opening saved work", () => {
    const state = initial();
    const id = panes(state.root)[0].id;
    const draft = traceDraft(
      { src: "10.0.0.1", dst: "192.0.2.1", port: "443", proto: "tcp", reply: false },
      "1234",
    )!;
    const opened = reduce(state, { type: "open-assessment", id, draft });
    expect(panes(opened.root)[0].assessmentDraft).toEqual(draft);
    expect(
      panes(reduce(opened, { type: "open-assessment", id, assessmentId: "saved" }).root)[0]
        .assessmentDraft,
    ).toBeUndefined();
  });
});
