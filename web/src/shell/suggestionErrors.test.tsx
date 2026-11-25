/** A failed suggestion query shows a note in the list of its picker. */

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { ValuePicker } from "../explore/ValuePicker";
import { PlaceField } from "../inventory/ui/PlaceField";
import { SitePicker } from "../inventory/ui/SitePicker";
import { mockApi } from "../test/fetchMock";

const FAILED = () => ({ status: 500, body: { error: "store not reachable" } });

function renderWithClient(children: ReactNode) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={queryClient}>{children}</QueryClientProvider>);
}

describe("a failed suggestion query", () => {
  it("shows a note in the value picker", async () => {
    mockApi({ "GET /api/explore/values": FAILED });
    renderWithClient(<ValuePicker id="v" label="Device" property="hostname" value="" onChange={() => {}} />);
    await userEvent.setup().click(screen.getByRole("combobox"));
    expect(await screen.findByRole("option", { name: "Values not loaded" })).toHaveAttribute("aria-disabled", "true");
  });

  it("shows a note in the site picker", async () => {
    mockApi({ "GET /api/inventory/sites/search": FAILED });
    renderWithClient(<SitePicker label="Site" value="" onChange={() => {}} />);
    await userEvent.setup().click(screen.getByRole("combobox", { name: "Site" }));
    expect(await screen.findByRole("option", { name: "Sites not loaded" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Searching" })).not.toBeInTheDocument();
  });

  it("shows a note in the place field", async () => {
    mockApi({ "GET /api/geo-places": FAILED });
    function Field() {
      return <PlaceField label="Geography" value="Berlin" onChange={() => {}} point={null} onPoint={() => {}} />;
    }
    renderWithClient(<Field />);
    const input = screen.getByRole("combobox", { name: "Geography" });
    // The list opens on a change of the text.
    await userEvent.setup().type(input, "x{Backspace}");
    expect(await screen.findByRole("option", { name: "Places not loaded" })).toBeInTheDocument();
  });
});
