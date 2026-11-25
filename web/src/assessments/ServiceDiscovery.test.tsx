import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ServicePicker } from "./ServicePicker";
import { KnownTrafficForm } from "./KnownTrafficForm";
import { AssessmentEditor } from "./AssessmentEditor";
import { destinationClue, emptyServiceClues, literalAddress } from "./guided";
import type { DiscoveryResponse, ServiceClues, TrafficEndpoints } from "./guided";
import type { Requirement } from "./types";

const request: Requirement = {
  name: "Payments gateway",
  destination: "Checkout",
  sources: ["10.20.0.0/24"],
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
  source_context: "context:payments",
};
const candidate = {
  uid: "service:payments",
  name: "Payments gateway",
  kind: "service" as const,
  selectable: true,
  definition: request,
  locations: ["Frankfurt office"],
  applications: ["Payments"],
  match_reasons: [
    "Recorded DNS maps pay.example.test to 192.0.2.10",
    "Client belongs to 10.20.0.0/24",
  ],
};
function Wrapper({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } }),
  );
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
function setup(response: Partial<DiscoveryResponse> = { items: [candidate] }) {
  const calls: URL[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      const url = new URL(input, "http://localhost");
      calls.push(url);
      const body =
        url.pathname === "/api/snapshots"
          ? {
              snapshots: ["1000", "2000"].map((id) => ({ id, ts_ms: Number(id), kind: "full" })),
              current: 1000,
            }
          : url.pathname === "/api/requirements"
            ? { requirements: [] }
            : {
                snapshot: url.searchParams.get("snapshot"),
                items: [],
                facets: { locations: ["Frankfurt office"], applications: ["Payments"] },
                questions: [],
                truncated: false,
                ...response,
              };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  return calls;
}

describe("Finding a service without its name", () => {
  it("uses destination and client clues, explains matches, and waits for explicit candidate selection", async () => {
    const calls = setup();
    const select = vi.fn();
    render(
      <Wrapper>
        <ServicePicker snapshot="1000" onSelect={select} />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Search by clues" }));
    expect(
      await screen.findByRole("region", { name: "Location: Frankfurt office" }),
    ).toBeInTheDocument();
    await user.type(
      screen.getByLabelText("Destination URL, hostname or IP"),
      "https://pay.example.test",
    );
    await user.type(screen.getByLabelText("Client IP or subnet"), "10.20.0.42");
    await user.type(screen.getByLabelText("Client location"), "Frankfurt office");
    await user.type(screen.getByLabelText("Application"), "Payments");
    expect(
      screen.getByRole("button", { name: "Choose Payments gateway in Frankfurt office" }),
    ).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Find matching services" }));
    const choose = await screen.findByRole("button", {
      name: "Choose Payments gateway in Frankfurt office",
    });
    await waitFor(() => expect(choose).toBeEnabled());
    expect(screen.getByText(/Matches: Recorded DNS maps/)).toBeInTheDocument();
    expect(select).not.toHaveBeenCalled();
    expect(
      calls.some(
        (url) =>
          url.searchParams.get("destination") === "https://pay.example.test" &&
          url.searchParams.get("client") === "10.20.0.42" &&
          url.searchParams.get("location") === "Frankfurt office" &&
          url.searchParams.get("application") === "Payments",
      ),
    ).toBe(true);
    await user.selectOptions(screen.getByLabelText("Grouping"), "applications");
    await user.click(screen.getByRole("button", { name: "Choose Payments gateway in Payments" }));
    expect(select).toHaveBeenCalledWith(expect.objectContaining({ uid: candidate.uid, request }));
  });

  it("offers concrete next clues when the catalog is incomplete or a hostname is unrecorded", async () => {
    setup({
      items: [],
      questions: ["Which destination IP is observed for pay.example.test?"],
      catalog_complete: false,
    });
    const define = vi.fn();
    render(
      <Wrapper>
        <ServicePicker
          snapshot="1000"
          initialClues={{
            ...emptyServiceClues(),
            destination: "pay.example.test",
            location: "Frankfurt office",
          }}
          onSelect={vi.fn()}
          onDefineTraffic={define}
        />
      </Wrapper>,
    );
    expect(
      await screen.findByText("Which destination IP is observed for pay.example.test?"),
    ).toBeInTheDocument();
    expect(screen.getByText("Catalog search incomplete")).toBeInTheDocument();
    await userEvent
      .setup()
      .click(screen.getByRole("button", { name: "Define traffic from these clues" }));
    expect(define).toHaveBeenCalledWith(
      {
        destination: "pay.example.test",
        client: "",
        location: "Frankfurt office",
        application: "",
      },
      {},
    );
  });

  it("uses explicitly selected recorded endpoints without inferring device-originated traffic", async () => {
    setup({
      items: [],
      traffic_options: [
        {
          uid: "prefix:office",
          name: "Office clients",
          role: "client",
          addresses: ["10.20.0.0/24"],
          site: "Frankfurt office",
          device: { uid: "gateway:office", name: "Office gateway" },
          context: { uid: "context:payments", name: "Payments VRF" },
          selectable: true,
        },
        {
          uid: "ip:payment",
          name: "Payment API",
          role: "destination",
          addresses: ["192.0.2.10"],
          selectable: true,
        },
      ],
    });
    const apply = vi.fn();
    function Harness() {
      const [seed, setSeed] = useState<{
        clues: ServiceClues;
        endpoints?: TrafficEndpoints;
      } | null>(null);
      return seed ? (
        <KnownTrafficForm {...seed} onApply={apply} onCancel={() => setSeed(null)} />
      ) : (
        <ServicePicker
          snapshot="1000"
          initialClues={{
            ...emptyServiceClues(),
            destination: "pay.example.test",
            location: "Frankfurt office",
          }}
          onSelect={vi.fn()}
          onDefineTraffic={(clues, endpoints) => setSeed({ clues, endpoints })}
        />
      );
    }
    render(
      <Wrapper>
        <Harness />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: /Client: Office clients/ }));
    await user.click(screen.getByRole("button", { name: /Destination: Payment API/ }));
    await user.click(screen.getByRole("button", { name: "Define traffic from these clues" }));
    expect(screen.getByLabelText("Client IP addresses or subnets")).toHaveValue("10.20.0.0/24");
    expect(screen.getByLabelText("Destination IP addresses or subnets")).toHaveValue("192.0.2.10");
    expect(screen.getByLabelText("Traffic protocol")).toHaveValue("");
    await user.selectOptions(screen.getByLabelText("Traffic protocol"), "tcp");
    await user.type(screen.getByLabelText("Traffic destination port"), "443");
    await user.selectOptions(screen.getByLabelText("Connectivity to check"), "session");
    await user.click(screen.getByRole("button", { name: "Use this traffic definition" }));
    expect(apply).toHaveBeenCalledWith(
      expect.objectContaining({
        source_context: "context:payments",
        sources: ["10.20.0.0/24"],
        members: [
          expect.objectContaining({ addresses: ["192.0.2.10"], proto: "tcp", port: "443" }),
        ],
      }),
    );
    expect(apply.mock.calls[0][0]).not.toHaveProperty("source_device_uid");
  });

  it("lets an uncatalogued connection reach the same review flow without losing known clues", async () => {
    setup({ items: [] });
    const save = vi.fn();
    render(
      <Wrapper>
        <AssessmentEditor busy={false} onSave={save} onCancel={vi.fn()} />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getByLabelText("Pinned snapshot")).toHaveValue("1000"));
    await user.click(screen.getByRole("button", { name: "Search by clues" }));
    await user.type(
      screen.getByLabelText("Destination URL, hostname or IP"),
      "https://192.0.2.10:8443",
    );
    await user.type(screen.getByLabelText("Client IP or subnet"), "10.20.0.42");
    await user.click(screen.getByRole("button", { name: "Define traffic from these clues" }));
    expect(screen.getByLabelText("Traffic destination port")).toHaveValue(8443);
    expect(screen.getByLabelText("Destination IP addresses or subnets")).toHaveValue("192.0.2.10");
    await user.selectOptions(screen.getByLabelText("Traffic protocol"), "tcp");
    await user.selectOptions(screen.getByLabelText("Connectivity to check"), "session");
    await user.click(screen.getByRole("button", { name: "Use this traffic definition" }));
    expect(save).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Review analysis scope" }));
    await user.click(screen.getByRole("button", { name: "Continue to scope" }));
    await user.click(screen.getByRole("button", { name: "Review analysis" }));
    expect(save).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Start analysis" }));
    expect(save).toHaveBeenCalledWith(
      "Traffic to 192.0.2.10",
      expect.objectContaining({
        request: expect.objectContaining({
          sources: ["10.20.0.42"],
          members: [expect.objectContaining({ addresses: ["192.0.2.10"], port: "8443" })],
        }),
      }),
      expect.objectContaining({ kind: "troubleshoot", snapshot: "1000" }),
    );
  });

  it("clears recorded traffic choices and their source context when the editor snapshot changes", async () => {
    setup({
      items: [],
      traffic_options: [
        {
          uid: "prefix:office",
          name: "Office clients",
          role: "client",
          addresses: ["10.20.0.0/24"],
          context: { uid: "context:old", name: "Old VRF" },
          selectable: true,
        },
      ],
    });
    render(
      <Wrapper>
        <AssessmentEditor busy={false} onSave={vi.fn()} onCancel={vi.fn()} />
      </Wrapper>,
    );
    const user = userEvent.setup();
    await waitFor(() => expect(screen.getByLabelText("Pinned snapshot")).toHaveValue("1000"));
    await user.click(screen.getByRole("button", { name: "Search by clues" }));
    await user.click(await screen.findByRole("button", { name: /Client: Office clients/ }));
    await user.click(screen.getByRole("button", { name: "Define traffic from these clues" }));
    expect(screen.getByLabelText("Client IP addresses or subnets")).toHaveValue("10.20.0.0/24");
    expect(screen.getByText(/Selected client: Office clients, Old VRF/)).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Pinned snapshot"), "2000");
    expect(screen.queryByRole("group", { name: "Known traffic" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Define known traffic" }));
    expect(screen.getByLabelText("Client IP addresses or subnets")).toHaveValue("");
    expect(screen.queryByText(/Selected client:/)).not.toBeInTheDocument();
  });

  it("keeps hostnames out of traffic addresses and preserves explicitly supplied default URL ports", () => {
    expect(destinationClue("https://pay.example.test:443")).toEqual({
      address: "",
      label: "pay.example.test",
      port: "443",
    });
    expect(destinationClue("https://pay.example.test")).toEqual({
      address: "",
      label: "pay.example.test",
      port: "",
    });
    expect(destinationClue("https://[2001:db8::1]:443/path")).toEqual({
      address: "2001:db8::1",
      label: "2001:db8::1",
      port: "443",
    });
    expect(literalAddress("10.20.0.0/24")).toBe(true);
    expect(literalAddress("2001:db8::/64")).toBe(true);
    expect(literalAddress("office-vpn")).toBe(false);
    expect(literalAddress("10.20.0.999")).toBe(false);
  });
});
