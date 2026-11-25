import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { RequirementComposer } from "./RequirementComposer";
import { emptyRequirement, requirementError, type Requirement } from "./types";

function Editor() {
  const [value, setValue] = useState<Requirement>({ ...emptyRequirement(), mtu: { mode: "packet", ip_packet_bytes: 9000, ipv4_df: true, reply_ip_packet_bytes: 1400 } });
  return <><RequirementComposer value={value} onChange={setValue} /><output data-testid="request">{JSON.stringify(value)}</output></>;
}

describe("MTU saved traffic requirement", () => {
  it("preserves a saved target and clears incompatible fields when changing mode", async () => {
    const user = userEvent.setup();
    render(<Editor />);
    expect(screen.getByLabelText("Complete IP packet bytes")).toHaveValue(9000);
    expect(screen.getByLabelText("Reply IP packet bytes")).toHaveValue(1400);
    await user.selectOptions(screen.getByLabelText("MTU assessment"), "inventory");
    expect(JSON.parse(screen.getByTestId("request").textContent!).mtu).toEqual({ mode: "inventory" });
    await user.selectOptions(screen.getByLabelText("MTU assessment"), "off");
    expect(JSON.parse(screen.getByTestId("request").textContent!).mtu).toBeUndefined();
  });
  it("rejects fractional sizes and IPv4 DF on IPv6 requirements", () => {
    expect(requirementError({ ...emptyRequirement(), mtu: { mode: "packet", ip_packet_bytes: 1500.5 } })).toMatch(/whole bytes/);
    expect(requirementError({ ...emptyRequirement(), sources: ["2001:db8::1"], mtu: { mode: "packet", ip_packet_bytes: 1500, ipv4_df: true } })).toMatch(/IPv6 requirement/);
  });
});
