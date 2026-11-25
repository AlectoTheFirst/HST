import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { QueryForm } from "./QueryForm";
import type { CannedQuery } from "../api/types";

const FIREWALL: CannedQuery = {
  key: "firewall",
  group: "policy",
  title: "Firewall rules",
  cypher: "MATCH (rb:FwRulebase) WHERE $device = '' RETURN rb",
  params: [
    {
      name: "device",
      label: "Device",
      placeholder: "Any device",
      optional: true,
      picker: { label: "Device", property: "hostname" },
    },
  ],
} as CannedQuery;

describe("QueryForm device filter", () => {
  it("runs for any device when the device is left empty", async () => {
    const onRun = vi.fn();
    render(
      <QueryClientProvider client={new QueryClient()}>
        <QueryForm query={FIREWALL} onRun={onRun} pending={false} />
      </QueryClientProvider>,
    );
    expect(screen.getByPlaceholderText("Any device")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Run" }));
    expect(onRun).toHaveBeenCalledWith({ device: "" });
  });
});
