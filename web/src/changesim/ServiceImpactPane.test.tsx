/** The tests cover the application-condition pane. */

import { describe, it, expect } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { ServiceImpactPane, conditionText } from "./ServiceImpactPane";
import { parseEvaluateServiceImpact } from "./assessImpact";
import type { EvaluateServiceImpactResult } from "./assessImpact";

const BANNED_WORDS = /\b(reached|reachability|delivered|delivery|live|current|intended)\b/i;

function bucket(items: string[]) {
  return { count: items.length, items, truncated: false };
}

const PASSES = { kind: "result" as const, statement: "condition-holds", answer: "true", word: "passes", quantifier: "some" as const, condition: "forward" as const, missing: [] };
const FAILS = { ...PASSES, answer: "false", word: "fails" };

const RESULT: EvaluateServiceImpactResult = {
  snapshot: "2000",
  mode: "possible",
  request: {
    name: "checkout",
    destination: "checkout",
    sources: bucket(["10.0.0.0/24"]),
    members: [
      { name: "ip:app:203.0.113.10", addresses: ["203.0.113.10/32"] },
      { name: "ip:app:203.0.113.11", addresses: ["203.0.113.11/32"] },
    ],
    condition: {
      kind: "every",
      parts: [
        {
          kind: "n-of-m",
          n: 2,
          parts: [
            { kind: "member", member: "ip:app:203.0.113.10" },
            { kind: "member", member: "ip:app:203.0.113.11" },
          ],
        },
        { kind: "capacity", parts: [{ kind: "member", member: "ip:app:203.0.113.10" }] },
      ],
    },
    requirement: "svcreq:checkout",
  },
  decided_change: { loss: bucket(["10.0.0.0/25"]), gain: bucket([]) },
  open_change: { loss: bucket(["10.0.0.0/24"]), gain: bucket([]) },
  open: { before: bucket(["10.0.0.0/24"]), after: bucket(["10.0.0.128/25"]) },
  passes: { before: bucket([]), after: bucket([]) },
  fails: { before: bucket([]), after: bucket([]) },
  triage: {
    decided_loss: bucket(["10.0.0.0/25"]),
    passes_then_open: bucket(["10.0.0.128/25"]),
    open_then_fails: bucket([]),
    open_throughout: bucket([]),
    decided_gain: bucket([]),
    open_then_passes: bucket([]),
    fails_then_open: bucket([]),
  },
  members: [
    {
      name: "ip:app:203.0.113.10",
      triage: { decided_loss: true },
      before: { passes: 1, fails: 0, open: 0 },
      after: { passes: 0, fails: 1, open: 0 },
    },
  ],
  evidence: {
    count: 1,
    truncated: false,
    items: [
      {
        side: "after",
        member: "ip:app:203.0.113.10",
        result: FAILS,
        steps: [
          {
            device_uid: "dev:b",
            stage: "filter",
            kind: "deny",
            detail: "rule cp:deny denies the flow",
            unknown: [],
          },
        ],
        missing: [],
      },
    ],
  },
  missing_evidence: ["the paths of bgp:r1:b were not captured"],
  gaps: [{ kind: "unresolved-next-hop", prefix: "203.0.113.0/24", next_hop: "10.77.0.1" }],
  model_errors: [],
};

function pane() {
  return screen.getByRole("region", { name: "Application condition pane" });
}

describe("ServiceImpactPane", () => {
  it("draws each part of the change with its complete count", () => {
    render(<ServiceImpactPane result={RESULT} />);
    const region = pane();

    const loss = within(region).getByText("Passes before, fails after").closest("section")!;
    expect(within(loss).getByText("10.0.0.0/25")).toBeInTheDocument();

    const open = within(region).getByText("Passes before, not decided after").closest("section")!;
    expect(within(open).getByText("10.0.0.128/25")).toBeInTheDocument();

    const gain = within(region).getByText("Fails before, passes after").closest("section")!;
    expect(within(gain).getByText("none")).toBeInTheDocument();
  });

  it("writes the declared condition out as it was evaluated", () => {
    render(<ServiceImpactPane result={RESULT} />);
    expect(
      within(pane()).getByText(
        "every one of (at least 2 of (ip:app:203.0.113.10, ip:app:203.0.113.11), " +
          "capacity over (ip:app:203.0.113.10))",
      ),
    ).toBeInTheDocument();
  });

  it("names the evidence the answer is missing and the step that decided one", () => {
    render(<ServiceImpactPane result={RESULT} />);
    const region = pane();
    expect(
      within(region).getByText("the paths of bgp:r1:b were not captured"),
    ).toBeInTheDocument();
    expect(
      within(region).getByText(
        "after: ip:app:203.0.113.10 fails, dev:b filter: rule cp:deny denies the flow",
      ),
    ).toBeInTheDocument();
    expect(
      within(region).getByText(
        "unresolved-next-hop: prefix 203.0.113.0/24, next_hop 10.77.0.1",
      ),
    ).toBeInTheDocument();
  });

  it("uses no wording the correctness contract rules out", () => {
    render(<ServiceImpactPane result={RESULT} />);
    expect(pane().textContent).not.toMatch(BANNED_WORDS);
  });

  it("renders nothing at all when no evaluation is on the transcript", () => {
    const { container } = render(<ServiceImpactPane result={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("conditionText", () => {
  it("reads every group kind, nested", () => {
    expect(conditionText({ kind: "member", member: "dns" })).toBe("dns");
    expect(
      conditionText({
        kind: "any-one",
        parts: [
          { kind: "member", member: "a" },
          { kind: "member", member: "b" },
        ],
      }),
    ).toBe("any one of (a, b)");
    expect(conditionText({ kind: "capacity", parts: [{ kind: "member", member: "a" }] })).toBe(
      "capacity over (a)",
    );
  });
});

describe("parseEvaluateServiceImpact", () => {
  it("reads a whole result", () => {
    expect(parseEvaluateServiceImpact(JSON.stringify(RESULT))?.mode).toBe("possible");
  });

  it("returns null for a result cut off in transit", () => {
    const cut = JSON.stringify(RESULT).slice(0, 200);
    expect(parseEvaluateServiceImpact(cut)).toBeNull();
  });

  it("returns null for JSON that is not shaped like this tool's answer", () => {
    expect(parseEvaluateServiceImpact(JSON.stringify({ device: {}, interfaces: [] }))).toBeNull();
  });
});

describe("disjoint impact reporting", () => {
  it("renders every request in one triage bucket", () => {
    const triage = {
      decided_loss: bucket(["198.51.100.1/32"]),
      passes_then_open: bucket(["198.51.100.2/32"]),
      open_then_fails: bucket(["198.51.100.3/32"]),
      open_throughout: bucket(["198.51.100.4/32"]),
      decided_gain: bucket(["198.51.100.5/32"]),
      open_then_passes: bucket(["198.51.100.6/32"]),
      fails_then_open: bucket(["198.51.100.7/32"]),
    };
    render(<ServiceImpactPane result={{ ...RESULT, triage, members: [] }} />);
    for (const part of Object.values(triage)) {
      expect(within(pane()).getAllByText(part.items[0])).toHaveLength(1);
    }
  });

  it("shows the scope and assumptions that a conditional proof depends on", () => {
    render(<ServiceImpactPane result={{
      ...RESULT,
      assumptions: ["external advertisements remain fixed on session bgp:edge"],
    }} />);
    expect(pane()).toHaveTextContent("external advertisements remain fixed on session bgp:edge");
  });
});

describe("one recorded state", () => {
  const zero = bucket([]);
  const step = { device_uid: "dev:core1", stage: "filter", kind: "permit", detail: "permit by default-action in fw:LAN-IOT", unknown: [] };
  const SINGLE: EvaluateServiceImpactResult = {
    ...RESULT,
    intents: [],
    outcomes: {
      before: { result: PASSES, passes: ["10.0.0.0/24"], fails: [], open: [] },
      after: { result: PASSES, passes: ["10.0.0.0/24"], fails: [], open: [] },
    },
    decided_change: { loss: zero, gain: zero },
    open_change: { loss: zero, gain: zero },
    open: { before: zero, after: zero },
    passes: { before: bucket(["10.0.0.0/24"]), after: bucket(["10.0.0.0/24"]) },
    fails: { before: zero, after: zero },
    triage: {
      decided_loss: zero, passes_then_open: zero, open_then_fails: zero, open_throughout: zero,
      decided_gain: zero, open_then_passes: zero, fails_then_open: zero,
    },
    members: [{
      name: "ip:app:203.0.113.10", triage: {},
      before: { passes: 1, fails: 0, open: 0 }, after: { passes: 1, fails: 0, open: 0 },
    }],
    evidence: {
      count: 2, truncated: false,
      items: [
        { side: "before", member: "ip:app:203.0.113.10", result: PASSES, steps: [step], missing: [] },
        { side: "after", member: "ip:app:203.0.113.10", result: PASSES, steps: [step], missing: [] },
      ],
    },
    missing_evidence: [],
    gaps: [{ kind: "not-modeled", code: "MTU_PATH_COVERAGE_INCOMPLETE", detail: "MTU coverage is incomplete.", producer: { kind: "projection-incomplete", stage: "mtu" } }],
  };

  it("states the verdict once", () => {
    render(<ServiceImpactPane result={SINGLE} />);
    const region = pane();
    expect(within(region).getByRole("heading", { name: "Answer: Passes" })).toBeInTheDocument();
    const holds = within(region).getByText("Passes").closest("section")!;
    expect(within(holds).getByText("10.0.0.0/24")).toBeInTheDocument();
    expect(within(region).queryByText("Passes before, fails after")).not.toBeInTheDocument();
    expect(within(region).queryByText("Not decided before or after")).not.toBeInTheDocument();
    expect(region).toHaveTextContent("one recorded state");
  });

  it("writes each decision once, without a before and after side", () => {
    render(<ServiceImpactPane result={SINGLE} />);
    const region = pane();
    expect(within(region).getAllByText(/permit by default-action in fw:LAN-IOT/)).toHaveLength(1);
    expect(within(region).getByText("ip:app:203.0.113.10 passes, dev:core1 filter: permit by default-action in fw:LAN-IOT")).toBeInTheDocument();
    expect(within(region).getByText("ip:app:203.0.113.10: passes")).toBeInTheDocument();
  });

  it("writes a gap's nested producer out as fields", () => {
    render(<ServiceImpactPane result={SINGLE} />);
    expect(pane().textContent).not.toContain("[object Object]");
    expect(within(pane()).getByText(/producer kind projection-incomplete stage mtu/)).toBeInTheDocument();
  });

  it("uses no wording the correctness contract rules out", () => {
    render(<ServiceImpactPane result={SINGLE} />);
    expect(pane().textContent).not.toMatch(BANNED_WORDS);
  });
});

describe("one recorded state without saved outcomes", () => {
  // The shape a tool call on the transcript returns: the capped buckets
  // without `outcomes`. The three buckets partition the source population,
  // so the failing clients must be listed and the answer derived.
  const zero = bucket([]);
  const CAPPED: EvaluateServiceImpactResult = {
    ...RESULT,
    intents: [],
    decided_change: { loss: zero, gain: zero },
    open_change: { loss: zero, gain: zero },
    open: { before: zero, after: bucket(["10.0.0.128/25"]) },
    passes: { before: bucket(["10.0.0.0/24"]), after: zero },
    fails: { before: zero, after: bucket(["10.0.0.0/25"]) },
    members: [{
      name: "ip:app:203.0.113.10", triage: {},
      before: { passes: 1, fails: 0, open: 0 }, after: { passes: 0, fails: 1, open: 1 },
    }],
    evidence: { count: 0, truncated: false, items: [] },
    missing_evidence: [],
    gaps: [],
  };
  delete (CAPPED as { outcomes?: unknown }).outcomes;

  it("lists the clients for which the condition does not hold and derives the verdict", () => {
    render(<ServiceImpactPane result={CAPPED} />);
    const region = pane();
    expect(within(region).getByRole("heading", { name: "Answer: Fails" })).toBeInTheDocument();
    const fails = within(region).getByText("Fails").closest("section")!;
    expect(within(fails).getByText("10.0.0.0/25")).toBeInTheDocument();
    const open = within(region).getByText("Not decided").closest("section")!;
    expect(within(open).getByText("10.0.0.128/25")).toBeInTheDocument();
    expect(region).not.toHaveTextContent("see the client lists below");
  });

  it("reads Unknown when nothing fails and part of the population is open", () => {
    const result = { ...CAPPED, fails: { before: zero, after: zero } };
    render(<ServiceImpactPane result={result} />);
    expect(within(pane()).getByRole("heading", { name: "Answer: Not decided" })).toBeInTheDocument();
  });

  it("uses no wording the correctness contract rules out", () => {
    render(<ServiceImpactPane result={CAPPED} />);
    expect(pane().textContent).not.toMatch(BANNED_WORDS);
  });
});
