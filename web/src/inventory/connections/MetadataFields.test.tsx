import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MetadataFields } from "./MetadataFields";
import type { CollectorFieldMetadata } from "../../api/inventory";
import type { SourceTypeSchema } from "../../api/types";

const SCHEMA = {
  type: "object",
  properties: {
    tenant: { type: "string", title: "Tenant" },
    vanity_domain: { type: "string", title: "Vanity domain" },
  },
  required: ["tenant", "vanity_domain"],
} as unknown as SourceTypeSchema;

const field = (path: string, label: string, identity_sensitivity: "identity" | "none") => ({
  path,
  variant: null,
  category: "connection" as const,
  secret: false,
  identity_sensitivity,
  profile_applicability: "n/a",
  label,
});

const METADATA = {
  collector_type: "zia",
  kind: "controller",
  fields: [field("tenant", "Tenant", "identity"), field("vanity_domain", "Vanity domain", "none")],
} as unknown as CollectorFieldMetadata;

describe("MetadataFields", () => {
  it("marks a field that keys the source identity when a connection is edited", () => {
    render(
      <MetadataFields schema={SCHEMA} metadata={METADATA} category="connection" value={{ tenant: "acme" }}
        onChange={() => {}} editing />,
    );
    const marks = screen.getAllByText("Source identity");
    expect(marks).toHaveLength(1);
    expect(marks[0].closest(".config-field")?.querySelector("label")?.textContent).toBe("Tenant");
  });

  it("marks nothing in a new connection", () => {
    render(<MetadataFields schema={SCHEMA} metadata={METADATA} category="connection" value={{}} onChange={() => {}} />);
    expect(screen.queryByText("Source identity")).toBeNull();
  });
});

describe("MetadataFields location_sites", () => {
  it("adds a line from a location and a picked site", async () => {
    const { mockApi } = await import("../../test/fetchMock");
    const { QueryClient, QueryClientProvider } = await import("@tanstack/react-query");
    const userEvent = (await import("@testing-library/user-event")).default;
    const site = { id: "s1", code: "vie01", name: "Vienna", location: "", devices: 0, targets: 0 };
    mockApi({
      "GET /api/inventory/sites/search": () => ({ body: { items: [site], total: 1, next_cursor: null } }),
      "GET /api/inventory/sites/s1": () => ({ body: site }),
    });
    const schema = {
      type: "object",
      properties: { location_sites: { type: "string", title: "Location to site", format: "multiline" } },
    } as unknown as SourceTypeSchema;
    const metadata = {
      collector_type: "zia",
      kind: "controller",
      fields: [{ ...field("location_sites", "Location to site", "none") }],
    } as unknown as CollectorFieldMetadata;
    const changes: Array<Record<string, unknown>> = [];
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MetadataFields schema={schema} metadata={metadata} category="connection" value={{ location_sites: "1001, hq" }}
          onChange={(v) => changes.push(v)} />
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Location id or name"), "Wien");
    await user.click(screen.getByRole("combobox", { name: "Site" }));
    await user.click(await screen.findByRole("option", { name: /vie01/ }));
    await user.click(screen.getByRole("button", { name: "Add line" }));
    expect(changes.at(-1)).toEqual({ location_sites: "1001, hq\nWien, vie01" });
  });
});

describe("MetadataFields profile form", () => {
  it("does not render a field the metadata classifies as internal, such as capture_bgp for zia", () => {
    const schema = {
      type: "object",
      properties: {
        interval_s: { type: "integer", title: "Collection interval (seconds)" },
        capture_bgp: { type: "string", title: "BGP observation capture", enum: ["all", "sessions", "none"] },
      },
    } as unknown as SourceTypeSchema;
    const metadata = {
      collector_type: "zia",
      kind: "controller",
      fields: [
        { ...field("interval_s", "Collection interval (seconds)", "none"), category: "profile" },
        { ...field("capture_bgp", "BGP observation capture", "none"), category: "internal" },
      ],
    } as unknown as CollectorFieldMetadata;
    render(<MetadataFields schema={schema} metadata={metadata} category="profile" value={{}} onChange={() => {}} />);
    expect(screen.getByLabelText("Collection interval (seconds)")).toBeInTheDocument();
    expect(screen.queryByLabelText("BGP observation capture")).toBeNull();
  });
});
