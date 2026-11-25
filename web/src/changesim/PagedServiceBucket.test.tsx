import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { PagedServiceBucket } from "./PagedServiceBucket";

it("pages exact results using decimal offsets and preserves the complete count", async () => {
  const first = {
    count: 2, count_decimal: "2", address_count_decimal: "18446744073709551616",
    items: ["2001:db8::/65"], truncated: true, offset_decimal: "0",
    next_offset_decimal: "9007199254740993",
  };
  const load = vi.fn().mockResolvedValue({
    ...first, items: ["2001:db8:0:0:8000::/65"], offset_decimal: "9007199254740993",
    next_offset_decimal: null,
  });
  render(<PagedServiceBucket title="Passes before the change, fails after" name="decided_change.loss" bucket={first} load={load} />);
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(screen.getByText("2001:db8:0:0:8000::/65")).toBeInTheDocument());
  expect(load).toHaveBeenCalledWith("decided_change.loss", "9007199254740993");
  expect(screen.getByText("18446744073709551616 addresses")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Previous" }));
  await waitFor(() => expect(load).toHaveBeenLastCalledWith("decided_change.loss", "0"));
});
