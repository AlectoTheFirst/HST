import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AnalysisForm } from "./AnalysisForm";
import { ObjectPicker } from "./ObjectPicker";
import { ServicePicker } from "./ServicePicker";
import { scopeFromRequest } from "./guided";
import type { DiscoveryObject, ServiceSelection } from "./guided";
import type { Assessment, Requirement } from "./types";

const request: Requirement = {
  name: "Checkout",
  destination: "API",
  sources: ["10.0.0.0/24"],
  members: [
    {
      name: "api",
      addresses: ["192.0.2.10"],
      proto: "tcp",
      port: "443",
      source_port: "1024-65535",
    },
  ],
  condition: { kind: "member", member: "api" },
  success: "session",
  source_context: "vrf:payments",
};
const assessment: Assessment = {
  id: "a1",
  title: "Checkout",
  revision: 1,
  created_at: "",
  updated_at: "",
  definition: { request, intents: [], snapshot: "1000", mode: "possible", freshness_s: 3600 },
};
const owner = { uid: "device:frankfurt", name: "Frankfurt gateway" };
const device: DiscoveryObject = {
  uid: owner.uid,
  name: owner.name,
  kind: "device",
  site: "Frankfurt",
  selectable: true,
};
const sharedPolicy: DiscoveryObject = {
  uid: "policy:edge",
  name: "Internet access",
  kind: "rulebase",
  devices: [owner, { uid: "device:berlin", name: "Berlin gateway" }],
  selectable: true,
};
const link: DiscoveryObject = {
  uid: "link:uplink",
  name: "Frankfurt uplink",
  kind: "link",
  interfaces: ["if:wan-a", "if:wan-b"],
  selectable: true,
};
const domain: DiscoveryObject = {
  uid: "domain:conduit",
  name: "Main conduit",
  kind: "domain",
  members: [
    { uid: link.uid, name: link.name, kind: "link" },
    { uid: device.uid, name: device.name, kind: "device" },
  ],
  source: "inventory",
  evidence_status: "observed",
  evidence_refs: ["sha256:evidence"],
  selectable: true,
};
function Wrapper({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } }),
  );
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
function setup(items: DiscoveryObject[] = []) {
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      const url = new URL(input, "http://localhost");
      calls.push(input);
      let body: unknown;
      if (url.pathname === "/api/snapshots")
        body = {
          snapshots: ["1000", "2000"].map((id) => ({ id, ts_ms: Number(id), kind: "full" })),
        };
      else if (url.pathname === "/api/requirements") body = { requirements: [] };
      else if (url.pathname === "/api/assessment-options")
        body = {
          snapshot: url.searchParams.get("snapshot"),
          truncated: false,
          items: items.filter(
            (item) =>
              item.kind === url.searchParams.get("kind") &&
              (!url.searchParams.get("uid") || item.uid === url.searchParams.get("uid")) &&
              (!url.searchParams.get("device") ||
                item.device_uid === url.searchParams.get("device")) &&
              (!url.searchParams.get("q") ||
                `${item.name} ${item.site || ""}`
                  .toLowerCase()
                  .includes(url.searchParams.get("q")!.toLowerCase())),
          ),
        };
      else throw new Error(`Unexpected request ${input}`);
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  return calls;
}

describe("Named guided assessment inputs", () => {
  it("lets the keyboard user distinguish identically named objects by site without preselecting suggestions", async () => {
    setup([
      {
        ...device,
        uid: "a",
        name: "Gateway",
        suggested: true,
        suggestion_reason: "Observed service path",
      },
      { ...device, uid: "b", name: "Gateway", site: "Berlin" },
    ]);
    const select = vi.fn();
    render(
      <Wrapper>
        <ObjectPicker snapshot="1000" kind="device" label="Find a device" onSelect={select} />
      </Wrapper>,
    );
    const user = userEvent.setup();
    const frankfurt = await screen.findByRole("button", { name: "Gateway Frankfurt" });
    expect(screen.getByRole("button", { name: "Gateway Berlin" })).toBeInTheDocument();
    expect(select).not.toHaveBeenCalled();
    frankfurt.focus();
    await user.keyboard("{Enter}");
    expect(select).toHaveBeenCalledWith(expect.objectContaining({ uid: "a" }));
  });

  it("never shows late results from a previous snapshot", async () => {
    let resolveOld!: (response: Response) => void;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: string) => {
        if (input.includes("snapshot=1000"))
          return new Promise<Response>((resolve) => {
            resolveOld = resolve;
          });
        return Promise.resolve(
          new Response(
            JSON.stringify({
              snapshot: "2000",
              items: [{ ...device, name: "Current gateway" }],
              truncated: false,
            }),
          ),
        );
      }),
    );
    const select = vi.fn();
    const { rerender } = render(
      <Wrapper>
        <ObjectPicker snapshot="1000" kind="device" label="Device" onSelect={select} />
      </Wrapper>,
    );
    rerender(
      <Wrapper>
        <ObjectPicker snapshot="2000" kind="device" label="Device" onSelect={select} />
      </Wrapper>,
    );
    expect(
      await screen.findByRole("button", { name: "Current gateway Frankfurt" }),
    ).toBeInTheDocument();
    resolveOld(
      new Response(
        JSON.stringify({
          snapshot: "1000",
          items: [{ ...device, name: "Stale gateway" }],
          truncated: false,
        }),
      ),
    );
    await waitFor(() => expect(screen.queryByText("Stale gateway")).not.toBeInTheDocument());
  });

  it("keeps a chosen service's member flow dimensions, condition and context exactly", async () => {
    setup([
      {
        uid: "service:checkout",
        name: "Checkout",
        kind: "service",
        selectable: true,
        definition: request,
      },
    ]);
    const select = vi.fn<(item: ServiceSelection) => void>();
    render(
      <Wrapper>
        <ServicePicker snapshot="1000" onSelect={select} />
      </Wrapper>,
    );
    await userEvent
      .setup()
      .click(await screen.findByRole("button", { name: /Checkout Recorded service/ }));
    expect(select.mock.calls[0][0]).toMatchObject({
      uid: "service:checkout",
      origin: "graph",
      request,
      definition: request,
    });
  });

  it("requires an owner for shared policies, preserves isolation, and submits only after review", async () => {
    setup([
      sharedPolicy,
      {
        uid: "service:private",
        name: "Private API",
        kind: "service",
        selectable: true,
        definition: { ...request, name: "Private API" },
      },
    ]);
    const submit = vi.fn();
    render(
      <Wrapper>
        <AnalysisForm assessment={assessment} initialKind="repair" busy={false} onSubmit={submit} />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.click(await screen.findByRole("button", { name: "Internet access" }));
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(screen.getByRole("alert")).toHaveTextContent("owner");
    expect(submit).not.toHaveBeenCalled();
    await user.selectOptions(screen.getByLabelText("Device for Internet access"), owner.uid);
    await user.click(screen.getByRole("button", { name: /Private API Recorded service/ }));
    await user.selectOptions(screen.getByLabelText("Protection for Private API"), "isolated");
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(screen.getByRole("region", { name: "Analysis review" })).toHaveTextContent(
      "Private API: must remain isolated",
    );
    expect(submit).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    expect(submit).toHaveBeenCalledWith(
      expect.objectContaining({
        allowed_targets: { "policy:edge": owner.uid },
        protected: [
          {
            name: "Private API",
            request: { ...request, name: "Private API" },
            desired: "isolated",
          },
        ],
        scope: {
          source: request.sources,
          destination: ["192.0.2.10"],
          protocols: ["tcp"],
          ports: ["443"],
          source_ports: ["1024-65535"],
        },
      }),
    );
  });

  it("offers Must remain connected and repeats it in the review", async () => {
    setup([
      sharedPolicy,
      {
        uid: "service:private",
        name: "Private API",
        kind: "service",
        selectable: true,
        definition: { ...request, name: "Private API" },
      },
    ]);
    render(
      <Wrapper>
        <AnalysisForm
          assessment={assessment}
          initialKind="repair"
          busy={false}
          onSubmit={vi.fn()}
        />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.click(await screen.findByRole("button", { name: "Internet access" }));
    await user.selectOptions(screen.getByLabelText("Device for Internet access"), owner.uid);
    await user.click(screen.getByRole("button", { name: /Private API Recorded service/ }));
    const select = screen.getByLabelText("Protection for Private API");
    expect(
      within(select).getByRole("option", { name: "Must remain connected" }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    const review = screen.getByRole("region", { name: "Analysis review" });
    expect(review).toHaveTextContent("Private API: must remain connected");
    expect(review.textContent?.toLowerCase()).not.toContain("reachab");
  });

  it("expands recorded shared-domain members and link endpoints for explicit review", async () => {
    setup([device, link, domain]);
    const submit = vi.fn();
    render(
      <Wrapper>
        <AnalysisForm
          assessment={assessment}
          initialKind="resilience"
          busy={false}
          onSubmit={submit}
        />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.selectOptions(screen.getByLabelText("Failure object type"), "domain");
    await user.click(await screen.findByRole("button", { name: "Main conduit inventory" }));
    await screen.findByRole("button", { name: "Remove Frankfurt uplink" });
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(screen.getByRole("region", { name: "Analysis review" })).toHaveTextContent(
      "Main conduit (domain), members: Frankfurt uplink, Frankfurt gateway",
    );
    expect(submit).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    const value = submit.mock.calls[0][0];
    expect(value.targets).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ uid: link.uid, interfaces: link.interfaces }),
      ]),
    );
    expect(value.domains[0]).toMatchObject({
      uid: domain.uid,
      source: "inventory",
      evidence_status: "observed",
      evidence_refs: domain.evidence_refs,
    });
    expect(new Set(value.domains[0].members)).toEqual(
      new Set(value.targets.map((item: { id: string }) => item.id)),
    );
  });

  it("finds an interface failure target among the interfaces of the selected device", async () => {
    const wan: DiscoveryObject = {
      uid: "if:wan-a",
      name: "wan-a",
      kind: "interface",
      device_uid: owner.uid,
      device_name: owner.name,
      selectable: true,
    };
    const calls = setup([device, wan]);
    const submit = vi.fn();
    render(
      <Wrapper>
        <AnalysisForm
          assessment={assessment}
          initialKind="resilience"
          busy={false}
          onSubmit={submit}
        />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.selectOptions(screen.getByLabelText("Failure object type"), "interface");
    expect(screen.queryByLabelText("Find a failure target")).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: /^Frankfurt gateway/ }));
    await user.click(await screen.findByRole("button", { name: /^wan-a/ }));
    expect(calls.some((call) => call.includes("kind=interface") && call.includes("device=device%3Afrankfurt"))).toBe(true);
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(screen.getByRole("region", { name: "Analysis review" })).toHaveTextContent("wan-a (interface)");
  });

  it("resolves AI draft identifiers and rejects claimed endpoints without starting anything", async () => {
    setup([link]);
    const submit = vi.fn();
    render(
      <Wrapper>
        <AnalysisForm
          assessment={assessment}
          initialKind="resilience"
          initialInput={{
            targets: [{ uid: link.uid, kind: "link", interfaces: ["invented-interface"] }],
          }}
          busy={false}
          onSubmit={submit}
        />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Continue to scope" })).toBeEnabled(),
    );
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await screen.findByRole("button", { name: "Remove Frankfurt uplink" });
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(submit).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    expect(submit.mock.calls[0][0].targets[0].interfaces).toEqual(link.interfaces);
  });

  it("invalidates selections on snapshot change", async () => {
    setup([device]);
    render(
      <Wrapper>
        <AnalysisForm
          assessment={assessment}
          initialKind="resilience"
          busy={false}
          onSubmit={vi.fn()}
        />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.click(await screen.findByRole("button", { name: "Frankfurt gateway Frankfurt" }));
    await user.click(screen.getByRole("button", { name: "Back" }));
    await user.selectOptions(screen.getByLabelText("Analysis snapshot"), "2000");
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    expect(
      screen.queryByRole("button", { name: "Remove Frankfurt gateway" }),
    ).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(screen.getByRole("alert")).toHaveTextContent("No failure target selected");
  });

  it("keeps unavailable recorded services visible with the missing-evidence reason", async () => {
    setup([
      {
        uid: "service:incomplete",
        name: "Legacy service",
        kind: "service",
        selectable: false,
        disabled_reason: "No observed destination members",
      },
    ]);
    render(
      <Wrapper>
        <ServicePicker snapshot="1000" onSelect={vi.fn()} />
      </Wrapper>,
    );
    expect(await screen.findByRole("button", { name: "Legacy service" })).toBeDisabled();
    expect(screen.getByText("No observed destination members")).toBeInTheDocument();
  });

  it("copies legacy graph-only saved references without claiming an immutable request revision", async () => {
    setup([
      {
        uid: "service:checkout",
        name: "Checkout",
        kind: "service",
        selectable: true,
        definition: request,
      },
    ]);
    const previousFetch = fetch;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: string) =>
        input === "/api/requirements"
          ? Promise.resolve(
              new Response(
                JSON.stringify({
                  requirements: [
                    {
                      id: "req:graph",
                      revision: 4,
                      title: "Saved checkout",
                      definition: { requirement: "service:checkout", intents: [], snapshot: "900" },
                    },
                  ],
                }),
              ),
            )
          : previousFetch(input),
      ),
    );
    const select = vi.fn();
    render(
      <Wrapper>
        <ServicePicker snapshot="1000" onSelect={select} />
      </Wrapper>,
    );
    await userEvent.setup().click(await screen.findByRole("button", { name: /Saved checkout/ }));
    await waitFor(() =>
      expect(select).toHaveBeenCalledWith(
        expect.objectContaining({
          origin: "saved",
          request,
          originRequirement: "service:checkout",
          originSnapshot: "1000",
        }),
      ),
    );
    expect(select.mock.calls[0][0]).not.toHaveProperty("requirementId");
    expect(select.mock.calls[0][0]).not.toHaveProperty("requirementRevision");
    expect(
      vi
        .mocked(fetch)
        .mock.calls.some(
          ([url]) =>
            String(url).includes("snapshot=1000") && String(url).includes("uid=service%3Acheckout"),
        ),
    ).toBe(true);
  });

  it("prefills the exact service scope for an existing graph-reference assessment", async () => {
    setup([
      {
        uid: "service:checkout",
        name: "Checkout",
        kind: "service",
        selectable: true,
        definition: request,
      },
    ]);
    render(
      <Wrapper>
        <AnalysisForm
          assessment={{
            ...assessment,
            definition: {
              ...assessment.definition,
              request: undefined,
              requirement: "service:checkout",
            },
          }}
          initialKind="repair"
          busy={false}
          onSubmit={vi.fn()}
        />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await screen.findByText("Checkout: 10.0.0.0/24 to API");
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    expect(screen.getByLabelText("Repair protocols")).toHaveValue("tcp");
    expect(screen.getByLabelText("Repair source ports")).toHaveValue("1024-65535");
  });

  it("does not apply a late saved-reference resolution after the snapshot changes", async () => {
    setup([
      {
        uid: "service:checkout",
        name: "Checkout",
        kind: "service",
        selectable: true,
        definition: request,
      },
    ]);
    const previousFetch = fetch;
    let resolveLookup!: (value: Response) => void;
    vi.stubGlobal(
      "fetch",
      vi.fn((input: string) => {
        if (input === "/api/requirements")
          return Promise.resolve(
            new Response(
              JSON.stringify({
                requirements: [
                  {
                    id: "req:graph",
                    revision: 4,
                    title: "Saved checkout",
                    definition: { requirement: "service:checkout" },
                  },
                ],
              }),
            ),
          );
        if (input.includes("uid="))
          return new Promise<Response>((resolve) => {
            resolveLookup = resolve;
          });
        return previousFetch(input);
      }),
    );
    const select = vi.fn();
    const { rerender } = render(
      <Wrapper>
        <ServicePicker snapshot="1000" onSelect={select} />
      </Wrapper>,
    );
    await userEvent.setup().click(await screen.findByRole("button", { name: /Saved checkout/ }));
    expect(screen.getByRole("button", { name: /Checkout Recorded service/ })).toBeDisabled();
    rerender(
      <Wrapper>
        <ServicePicker snapshot="2000" onSelect={select} />
      </Wrapper>,
    );
    await act(async () => {
      resolveLookup(
        new Response(
          JSON.stringify({
            snapshot: "1000",
            items: [
              { uid: "service:checkout", kind: "service", selectable: true, definition: request },
            ],
          }),
        ),
      );
    });
    expect(select).not.toHaveBeenCalled();
  });

  it("does not broaden an unspecified member protocol or destination port while prefilling scope", () => {
    expect(
      scopeFromRequest({
        ...request,
        members: [...request.members, { name: "other", addresses: ["192.0.2.11"] }],
      }),
    ).toMatchObject({ protocols: [], ports: [], destination: ["192.0.2.10", "192.0.2.11"] });
  });
});
