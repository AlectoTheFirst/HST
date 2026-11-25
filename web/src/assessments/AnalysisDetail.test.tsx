import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AnalysisResult } from "./AnalysisResult";
import { AnalysisForm } from "./AnalysisForm";
import { emptyRequirement, type Assessment } from "./types";
import { mockApi } from "../test/fetchMock";

// The answers a stored run records, as the server writes them.
const P = {
  kind: "result",
  statement: "condition-holds",
  answer: "true",
  word: "passes",
  quantifier: "some",
  condition: "forward",
  missing: [],
};
const F = { ...P, answer: "false", word: "fails" };
const O = {
  ...P,
  answer: "open",
  word: "not decided",
  missing: [{ code: "not-decided", subject: null, detail: "the evaluation is open" }],
};

describe("Structured analysis review", () => {
  it("shows a violated protection prominently even when the desired service succeeds", () => {
    render(
      <AnalysisResult
        result={{
          kind: "evaluate",
          result: F,
          constraints: {
            result: F,
            desired: P,
            protected: { "Payroll isolation": F },
            verified: false,
          },
        }}
      />,
    );
    expect(screen.getByRole("heading", { name: "Requirement constraints: Fails" })).toBeVisible();
    expect(screen.getByRole("row", { name: /^Payroll isolation Fails/ })).toBeVisible();
    expect(screen.getByRole("row", { name: /^Desired requirement Passes/ })).toBeVisible();
  });
  it("separates protected constraints and cost from exact verified proposal selection", async () => {
    const save = vi.fn();
    render(
      <AnalysisResult
        onSaveProposal={save}
        result={{
          kind: "repair",
          cost_order: ["devices", "newly_permitted_scope", "rule_edits"],
          findings: [
            {
              candidates: ["fix"],
              result: P,
              verified: true,
              desired: P,
              protected: { "Payroll isolation": { result: P, desired: "isolated" } },
              cost: [1, 32, 2],
              minimum_cost: true,
              intents: [{ kind: "fw_rule.modify", params: { rule: "r1" } }],
              diff: [{ rule: "r1", before: { action: "drop" }, after: { action: "accept" } }],
            },
          ],
        }}
      />,
    );
    await userEvent.click(screen.getByText("Inspect finding 1"));
    expect(screen.getByText("devices: 1")).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /^Payroll isolation Passes/ })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Before" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save proposal 1" }));
    expect(save).toHaveBeenCalledWith(0);
  });

  it("does not make an unproven protected constraint saveable", () => {
    render(
      <AnalysisResult
        onSaveProposal={vi.fn()}
        result={{
          kind: "repair",
          findings: [
            { result: P, verified: true, desired: P, protected: { payroll: O }, intents: [] },
          ],
        }}
      />,
    );
    expect(screen.queryByRole("button", { name: /Save proposal/ })).not.toBeInTheDocument();
  });

  it("preserves exact large flow cardinalities and discloses a capped diff", async () => {
    render(
      <AnalysisResult
        result={{
          kind: "repair",
          findings: [
            {
              candidates: ["ipv6"],
              result: P,
              cost: [1, 1e30, 1],
              cost_decimal: ["1", "1000000000000000000000000000001", "1"],
              diff: [],
              diff_count: 60,
              diff_truncated: true,
              diff_sha256: "full-diff-digest",
            },
          ],
        }}
      />,
    );
    await userEvent.click(screen.getByText("Inspect finding 1"));
    expect(
      screen.getByText("newly permitted scope: 1000000000000000000000000000001"),
    ).toBeInTheDocument();
    expect(screen.getByText(/Diff of 60 recorded edits incomplete/)).toBeInTheDocument();
  });

  it("shows forward reproduction independently from reverse recovery", async () => {
    render(
      <AnalysisResult
        result={{
          kind: "regression",
          edits: [
            {
              id: "route-change",
              before: { next_hop: "10.0.0.1" },
              after: { next_hop: "10.0.0.2" },
            },
          ],
          excluded: [{ reason: "Missing observed policy" }],
          findings: [
            {
              candidates: ["route-change"],
              result: P,
              forward_replay: {
                result: O,
                reproduces_failure: false,
                evaluation: { reason: "Missing peer supply" },
              },
            },
          ],
        }}
      />,
    );
    await userEvent.click(screen.getByText("Inspect finding 1"));
    expect(
      screen.getByRole("heading", { name: "Reverse recovery on snapshot B" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Reproduction not decided")).toBeInTheDocument();
    expect(screen.getByText("Changes excluded from counterfactual search")).toBeInTheDocument();
  });

  it("names MTU evidence inspection apart from a packet size requirement", () => {
    render(
      <AnalysisResult
        result={{ kind: "troubleshoot", evaluation: { request: { mtu: { mode: "inventory" } } } }}
      />,
    );
    expect(screen.getByRole("heading", { name: "MTU evidence" })).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Packet size requirement" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("No packet size requirement")).toBeInTheDocument();
  });

  it("lists evidence gaps as one readable line each with the record behind it", () => {
    render(
      <AnalysisResult
        result={{
          kind: "troubleshoot",
          gaps: [
            {
              id: "g1",
              code: "tunnel-decision-not-established",
              kind: "unclassified",
              dimension: "tunnel",
              detail: "missing graph identity: remote_device_uid",
              subject: "dev:core1",
              request_regions: [{ dst: ["8.8.8.8/32"] }],
            },
          ],
        }}
      />,
    );
    const item = screen.getAllByText("tunnel-decision-not-established")[0].closest("li")!;
    expect(item).toHaveTextContent(
      "tunnel-decision-not-established (unclassified, tunnel): missing graph identity: remote_device_uid, subject: dev:core1",
    );
    expect(within(item).getByText("Gap record 1")).toBeInTheDocument();
  });

  it("exposes nested domain dependencies and independently missing evidence", async () => {
    render(
      <AnalysisResult
        result={{
          kind: "resilience",
          expanded_domains: {
            conduit: {
              domains: ["conduit", "site"],
              effects: [{ kind: "link", uid: "wan:a", interfaces: ["if:a", "if:b"] }],
              evidence_complete: false,
              provenance_validated: false,
              evidence: {
                missing: ["Provider observation expired"],
                evidence_refs: [{ source: "inventory", reference: "raw/observed" }],
              },
            },
          },
        }}
      />,
    );
    await userEvent.click(screen.getByText("conduit: Evidence incomplete"));
    expect(screen.getByText("link: wan:a, interfaces if:a, if:b")).toBeInTheDocument();
    expect(screen.getByText("Provider observation expired")).toBeInTheDocument();
    expect(screen.getByText(/Independent physical diversity not known/)).toBeInTheDocument();
  });
});

it("reorders repair costs as a permutation and submits the chosen priority", async () => {
  mockApi({
    "GET /api/snapshots": () => ({
      body: {
        snapshots: [{ id: "1000", ts_ms: 1000, kind: "full" }],
        current: 1000,
        truncated: false,
      },
    }),
    "GET /api/assessment-options": () => ({
      body: {
        snapshot: "1000",
        truncated: false,
        items: [
          {
            uid: "rb:web",
            name: "Web policy",
            kind: "rulebase",
            selectable: true,
            devices: [{ uid: "dev:web", name: "Web gateway" }],
          },
        ],
      },
    }),
    "GET /api/requirements": () => ({ body: { requirements: [] } }),
  });
  const assessment: Assessment = {
    id: "a",
    title: "Service",
    revision: 1,
    created_at: "2026-09-08T12:00:00Z",
    updated_at: "2026-09-08T12:00:00Z",
    definition: {
      request: emptyRequirement(),
      snapshot: "1000",
      mode: "possible",
      freshness_s: 3600,
      intents: [],
    },
  };
  const submit = vi.fn();
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <AnalysisForm assessment={assessment} busy={false} onSubmit={submit} initialKind="repair" />
    </QueryClientProvider>,
  );
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Continue to scope" }));
  await user.selectOptions(screen.getByLabelText("Cost priority 1"), "rule_edits");
  expect(screen.getByLabelText("Cost priority 3")).toHaveValue("devices");
  await user.click(await screen.findByRole("button", { name: "Web policy" }));
  expect(screen.getByLabelText("Device for Web policy")).toHaveValue("dev:web");
  for (const [name, value] of [
    ["source", "10.0.0.0/24"],
    ["destination", "192.0.2.1"],
    ["protocols", "tcp"],
    ["ports", "443"],
  ])
    await user.type(screen.getByLabelText(`Repair ${name}`), value);
  expect(
    within(screen.getByRole("group", { name: "Repair cost priority" })).getAllByRole("combobox"),
  ).toHaveLength(3);
  await user.click(screen.getByRole("button", { name: "Review analysis" }));
  await user.click(screen.getByRole("button", { name: "Start analysis" }));
  expect(submit).toHaveBeenCalledWith(
    expect.objectContaining({ cost_order: ["rule_edits", "newly_permitted_scope", "devices"] }),
  );
});
